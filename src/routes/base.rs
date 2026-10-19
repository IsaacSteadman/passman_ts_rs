use crate::server_policy::{PolicyParams, PolicyStorage};
use actix_web::{HttpRequest, HttpResponse, http::header, web};
use percent_encoding::percent_decode_str;
use rand::{TryRngCore, rngs::OsRng};
use serde_json::json;
use std::{
    collections::HashMap,
    fs::Metadata,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock},
};

pub use passman_crypto::{Argon2Params, HASH_SIZE};

// Credentials are sent in these headers rather than the query string so they
// stay out of URLs, proxy access logs and the request logging below.
pub const AUTH_KEY_HEADER: &str = "Passman-Auth-Key";
pub const NEW_AUTH_KEY_HEADER: &str = "Passman-New-Auth-Key";
/// percent-encoded (`encodeURIComponent`), since header values must be ASCII
pub const SERVER_PASS_HEADER: &str = "Passman-Server-Pass";

#[repr(packed)]
pub struct UserDataHeader {
    pub hash: [u8; HASH_SIZE],
    pub salt: [u8; HASH_SIZE],
}

impl UserDataHeader {
    pub const SIZE: usize = std::mem::size_of::<UserDataHeader>();
    pub async fn from_reader(f: &mut tokio::fs::File) -> anyhow::Result<Self> {
        let version = f.read_u32_le().await?;
        if version != 1 {
            anyhow::bail!("Expected exactly version 1");
        }
        let mut hash = [0; HASH_SIZE];
        f.read_exact(&mut hash).await?;
        let mut salt = [0; HASH_SIZE];
        f.read_exact(&mut salt).await?;
        Ok(Self { hash, salt })
    }
    pub async fn to_writer(&self, f: &mut tokio::fs::File) -> anyhow::Result<()> {
        f.write_u32_le(1).await?;
        f.write_all(&self.hash).await?;
        f.write_all(&self.salt).await?;
        Ok(())
    }
    pub async fn from_password(
        password: &[u8],
        argon2: &argon2::Argon2<'_>,
    ) -> anyhow::Result<Self> {
        let mut salt = [0; HASH_SIZE];
        let mut hash = [0; HASH_SIZE];
        OsRng.try_fill_bytes(&mut salt)?;
        if let Err(e) = argon2.hash_password_into(password, &salt, &mut hash) {
            anyhow::bail!("{e:?}")
        }
        Ok(Self { hash, salt })
    }
}

pub type UserT = ();

pub struct GetUser<'a> {
    pub user_path: PathBuf,
    pub read_guard: OwnedRwLockReadGuard<UserT>,
    pub read_file: tokio::fs::File,
    pub metadata: Metadata,
    pub udh: UserDataHeader,
    pub argon2: argon2::Argon2<'a>,
}

pub struct GetWillMutUser<'a> {
    pub base: GetUser<'a>,
    pub write_file_path: PathBuf,
}

pub struct AppState {
    pub policies_and_config: Arc<PolicyStorage>,
    pub server_data_dir: PathBuf,
    pub argon2_params: Argon2Params,
    pub user_locks: RwLock<HashMap<String, Arc<RwLock<UserT>>>>,
}

impl AppState {
    pub async fn get_user(
        &self,
        username: &str,
        password: &str,
        password_header_name: &str,
    ) -> Result<GetUser<'_>, HttpResponse> {
        validate_username(&username)?;
        let password = validate_password(password, password_header_name)?;
        let user_locks = self.user_locks.read().await;
        let user_path = self.server_data_dir.join(username);
        let user_lock = if let Some(x) = user_locks.get(username) {
            let user_lock = x.clone();
            drop(user_locks);
            user_lock
        } else {
            if user_path.is_file() {
                match self.user_locks.upgrade(user_locks).await {
                    Err(_) => {
                        return Err(HttpResponse::Conflict().json(json!({
                            "type": "E_AUTH_CONFLICT",
                            "params": ["username", password_header_name],
                            "message": "try again",
                        })));
                    }
                    Ok(mut user_locks) => {
                        let res = Arc::new(RwLock::new(()));
                        user_locks.insert(username.to_string(), res.clone());
                        res
                    }
                }
            } else {
                return Err(HttpResponse::BadRequest().json(json!({
                    "type": "E_AUTH",
                    "params": ["username", password_header_name],
                    "message": "username or password is incorrect",
                })));
            }
        };
        let read_guard = user_lock.read_owned().await;
        let mut read_file = match tokio::fs::File::open(&user_path).await {
            Err(e) => {
                eprintln!(
                    "Error occured attempting to open\n  e={e:?}\n  username={username:?}\n  path={user_path:?}"
                );
                return Err(HttpResponse::BadRequest().json(json!({
                    "type": "E_AUTH",
                    "params": ["username", password_header_name],
                    "message": "username or password is incorrect",
                })));
            }
            Ok(o) => o,
        };
        let udh = match UserDataHeader::from_reader(&mut read_file).await {
            Err(e) => {
                eprintln!(
                    "Error occured attempting to read\n  e={e:?}\n  username={username:?}\n  path={user_path:?}"
                );
                return Err(HttpResponse::BadRequest().json(json!({
                    "type": "E_AUTH",
                    "params": ["username", password_header_name],
                    "message": "username or password is incorrect",
                })));
            }
            Ok(o) => o,
        };
        let argon2 = self.argon2_params.make();
        let mut actual_hash = [0; HASH_SIZE];
        match argon2.hash_password_into(&password, &udh.salt, &mut actual_hash) {
            Err(e) => {
                eprintln!(
                    "Error occured attempting to hash password\n  e={e:?}\n  username={username:?}\n  path={user_path:?}"
                );
                return Err(HttpResponse::BadRequest().json(json!({
                    "type": "E_AUTH",
                    "params": ["username", password_header_name],
                    "message": "username or password is incorrect",
                })));
            }
            _ => {}
        }
        let expected: &[u8] = &udh.hash;
        let actual: &[u8] = &actual_hash;
        if !bool::from(ConstantTimeEq::ct_eq(expected, actual)) {
            return Err(HttpResponse::BadRequest().json(json!({
                "type": "E_AUTH",
                "params": ["username", password_header_name],
                "message": "username or password is incorrect",
            })));
        }
        let metadata = match read_file.metadata().await {
            Err(e) => {
                eprintln!(
                    "Error occured attempting to read metadata\n  e={e:?}\n  username={username:?}\n  path={user_path:?}"
                );
                return Err(HttpResponse::BadRequest().json(json!({
                    "type": "E_USER_READ",
                    "message": "Failed to read user file metadata"
                })));
            }
            Ok(o) => o,
        };
        Ok(GetUser {
            metadata,
            user_path,
            read_guard,
            read_file,
            udh,
            argon2,
        })
    }
    pub async fn get_will_mut_user(
        &self,
        username: &str,
        password: &str,
        password_header_name: &str,
    ) -> Result<GetWillMutUser<'_>, HttpResponse> {
        let base = self
            .get_user(username, password, password_header_name)
            .await?;
        let write_file_path = self.server_data_dir.join(format!(".{}.tmp", username));
        Ok(GetWillMutUser {
            base,
            write_file_path,
        })
    }
}

pub fn validate_username(username: &str) -> Result<(), HttpResponse> {
    let mut count = 0usize;
    let mut is_last_special = false;
    for ch in username.chars() {
        if ch.is_alphanumeric() {
            is_last_special = false;
        } else if ch == '-' || ch == '_' || ch == '.' || ch == '$' {
            if count == 0 {
                return Err(HttpResponse::BadRequest().json(json!({
                    "type": "E_AUTH",
                    "param": "username",
                    "message": "bad username characters, cannot start with '-_.$'",
                })));
            }
            is_last_special = true;
        } else {
            return Err(HttpResponse::BadRequest().json(json!({
                "type": "E_AUTH",
                "param": "username",
                "message": format!("bad username characters, cannot contain {:?}", ch),
            })));
        }
        count += 1
    }
    if is_last_special {
        return Err(HttpResponse::BadRequest().json(json!({
            "type": "E_AUTH",
            "param": "username",
            "message": "bad username characters, cannot end with '-_.$'",
        })));
    }
    if count == 0 {
        return Err(HttpResponse::BadRequest().json(json!({
            "type": "E_AUTH",
            "param": "username",
            "message": "must contain at least 1 character",
        })));
    } else if count > 64 {
        return Err(HttpResponse::BadRequest().json(json!({
            "type": "E_AUTH",
            "param": "username",
            "message": "must contain no more than 64 characters",
        })));
    }
    Ok(())
}

fn parse_b64_digit(ch: u8) -> anyhow::Result<u8> {
    Ok(match ch {
        b'A'..=b'Z' => ch - b'A',
        b'a'..=b'z' => ch - b'a' + 26,
        b'0'..=b'9' => ch - b'0' + 52,
        b'+' | b'-' => 62,
        b'/' | b'_' => 63,
        b'=' => 0,
        _ => anyhow::bail!("Invalid base64 digit {:?}", ch),
    })
}

pub fn parse_b64(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut res = Vec::with_capacity(data.len() * 3 / 4 + 3);
    for chunk in data.chunks(4) {
        let mut values = [0u8; 4];
        for (i, &v) in chunk.iter().enumerate() {
            values[i] = parse_b64_digit(v)?;
        }
        res.push((values[0] << 2) | (values[1] >> 4));
        if let Some(ch) = chunk.get(2) {
            if b'='.ne(ch) {
                res.push((values[1] << 4) | (values[2] >> 2));
            }
        }
        if let Some(ch) = chunk.get(3) {
            if b'='.ne(ch) {
                res.push((values[2] << 6) | values[3]);
            }
        }
    }
    Ok(res)
}

pub fn validate_password(password: &str, param_name: &str) -> Result<Vec<u8>, HttpResponse> {
    match parse_b64(password.as_bytes()) {
        Err(e) => Err(HttpResponse::BadRequest().json(json!({
            "type": "E_AUTH",
            "param": param_name,
            "message": format!("invalid base64 password: {}", e),
        }))),
        Ok(o) => Ok(o),
    }
}

/// HTTP dates have whole-second precision, so file mtimes are truncated to
/// match the `Last-Modified` value a client sends back as `If-Unmodified-Since`.
pub fn http_date(time: SystemTime) -> header::HttpDate {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    header::HttpDate::from(UNIX_EPOCH + Duration::from_secs(secs))
}

fn required_header<'a>(req: &'a HttpRequest, name: &'static str) -> Result<&'a str, HttpResponse> {
    match req.headers().get(name).map(|v| v.to_str()) {
        Some(Ok(s)) => Ok(s),
        _ => Err(HttpResponse::BadRequest().json(json!({
            "type": "E_BAD_REQUEST",
            "header_required": name,
            "message": "the header is required and must be ASCII"
        }))),
    }
}

/// Reads a base64 auth key header (`AUTH_KEY_HEADER` or `NEW_AUTH_KEY_HEADER`).
pub fn auth_key_header(req: &HttpRequest, name: &'static str) -> Result<String, HttpResponse> {
    required_header(req, name).map(str::to_string)
}

/// Builds the policy credentials from `SERVER_PASS_HEADER` and the
/// non-secret `server_ns` query parameter.
pub fn policy_params(
    req: &HttpRequest,
    server_ns: Option<String>,
) -> Result<PolicyParams, HttpResponse> {
    let encoded = required_header(req, SERVER_PASS_HEADER)?;
    match percent_decode_str(encoded).decode_utf8() {
        Ok(server_pass) => Ok(PolicyParams {
            server_pass: server_pass.into_owned(),
            server_ns,
        }),
        Err(_) => Err(HttpResponse::BadRequest().json(json!({
            "type": "E_BAD_REQUEST",
            "header": SERVER_PASS_HEADER,
            "message": "the header must be percent-encoded UTF-8"
        }))),
    }
}

pub fn get_content_length(req: &HttpRequest) -> Result<Option<u64>, HttpResponse> {
    let heads = req.headers();
    match (
        heads.get(header::CONTENT_LENGTH),
        heads.get(header::TRANSFER_ENCODING),
    ) {
        (Some(content_length), None) => match content_length.to_str() {
            Ok(s) => match s.parse::<u64>() {
                Ok(len) => Ok(Some(len)),
                _ => {
                    Err(HttpResponse::BadRequest().json(json!({
                        "type": "E_BAD_REQUEST",
                        "message": "invalid Content-Length header value"
                    })))
                }
            },
            _ => {
                Err(HttpResponse::BadRequest().json(json!({
                    "type": "E_BAD_REQUEST",
                    "message": "Content-Length header contains invalid characters"
                })))
            }
        },
        (None, Some(transfer_encoding)) => match transfer_encoding.to_str() {
            Ok(s) => {
                if s.eq_ignore_ascii_case("chunked") {
                    Ok(None)
                } else {
                    Err( HttpResponse::BadRequest().json(json!({
                            "type": "E_BAD_REQUEST",
                            "message": "unsupported Transfer-Encoding header value, only 'chunked' is supported"
                        })))
                }
            }
            _ => {
                Err(HttpResponse::BadRequest().json(json!({
                    "type": "E_BAD_REQUEST",
                    "message": "Transfer-Encoding header contains invalid characters"
                })))
            }
        },
        (Some(_), Some(_)) => {
            Err(HttpResponse::BadRequest().json(json!({
                "type": "E_BAD_REQUEST",
                "message": "only one of Content-Length or Transfer-Encoding headers can be specified, not both"
            })))
        }
        _ => {
            Err(HttpResponse::LengthRequired().json(json!({
                "type": "E_LENGTH_REQUIRED",
                "at_least_one_of_these_headers_required": ["Content-Length", "Transfer-Encoding"],
                "message": "the Content-Length header is recommended to be specified, alternatively a Transfer-Encoding header can be provided, but not both"
            })))
        }
    }
}

type CleanupTarget = (String, web::Data<AppState>);

struct WritingFileInner {
    wf: tokio::fs::File,
    write_file_path: PathBuf,
    guard: OwnedRwLockWriteGuard<UserT>,
    replace_target_path: PathBuf,
    cleanup_target: Option<CleanupTarget>,
}

pub struct WritingFile(Option<WritingFileInner>);

impl WritingFile {
    pub async fn new(
        username: &str,
        guard: OwnedRwLockWriteGuard<UserT>,
        write_file_path: PathBuf,
        replace_target_path: PathBuf,
        cleanup_target: Option<CleanupTarget>,
    ) -> Result<Self, HttpResponse> {
        let wf = match tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&write_file_path)
            .await
        {
            Err(e) => {
                eprintln!(
                    "Error occured attempting to create write file\n  e={e:?}\n  username={username:?}\n  path={write_file_path:?}"
                );
                return Err(HttpResponse::InternalServerError().json(json!({
                    "type": "E_USER_WRITE",
                    "message": "Failed to create user file for writing"
                })));
            }
            Ok(o) => o,
        };
        Ok(Self(Some(WritingFileInner {
            wf,
            guard,
            write_file_path,
            replace_target_path,
            cleanup_target,
        })))
    }

    pub fn close(&mut self) -> ReadyToReplace {
        ReadyToReplace(
            if let Some(WritingFileInner {
                wf,
                guard,
                replace_target_path,
                write_file_path,
                cleanup_target,
            }) = self.0.take()
            {
                Some(ReadyToReplaceInner {
                    wf,
                    write_file_path,
                    guard,
                    replace_target_path,
                    cleanup_target,
                })
            } else {
                None
            },
        )
    }

    pub async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), HttpResponse> {
        if let Some(WritingFileInner {
            wf,
            write_file_path,
            ..
        }) = &mut self.0
        {
            match wf.write_all(chunk).await {
                Err(e) => {
                    eprintln!(
                        "Error occured attempting to write chunk to write file\n  e={e:?}\n  path={:?}",
                        write_file_path
                    );
                    Err(HttpResponse::InternalServerError().json(json!({
                        "type": "E_USER_WRITE",
                        "message": "Failed to write data to user file"
                    })))
                }
                _ => Ok(()),
            }
        } else {
            Err(HttpResponse::InternalServerError().json(json!({
                "type": "E_USER_WRITE",
                "message": "Failed to write data to user file (already closed)"
            })))
        }
    }

    pub async fn write_udh(&mut self, udh: &UserDataHeader) -> Result<(), HttpResponse> {
        if let Some(WritingFileInner {
            wf,
            write_file_path,
            ..
        }) = &mut self.0
        {
            match udh.to_writer(wf).await {
                Err(e) => {
                    eprintln!(
                        "Error occured attempting to write UserDataHeader to write file\n  e={e:?}\n  path={:?}",
                        write_file_path
                    );
                    Err(HttpResponse::InternalServerError().json(json!({
                        "type": "E_USER_WRITE",
                        "message": "Failed to write data to user file"
                    })))
                }
                _ => Ok(()),
            }
        } else {
            Err(HttpResponse::InternalServerError().json(json!({
                "type": "E_USER_WRITE",
                "message": "Failed to write data to user file (already closed)"
            })))
        }
    }
}

impl Drop for WritingFile {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

struct ReadyToReplaceInner {
    wf: tokio::fs::File,
    write_file_path: PathBuf,
    guard: OwnedRwLockWriteGuard<UserT>,
    replace_target_path: PathBuf,
    cleanup_target: Option<CleanupTarget>,
}

pub struct ReadyToReplace(Option<ReadyToReplaceInner>);

impl ReadyToReplace {
    pub async fn replace(&mut self) -> Result<Replaced, HttpResponse> {
        if let Some(inner) = self.0.take() {
            // waits for tokio's in-flight background write, then flushes to
            // disk, so the renamed file is complete before the lock is released
            if let Err(e) = inner.wf.sync_all().await {
                eprintln!(
                    "Error occured attempting to sync write file\n  e={e:?}\n  path={:?}",
                    inner.write_file_path
                );
                // put it back so Drop removes the temporary file
                self.0 = Some(inner);
                return Err(HttpResponse::InternalServerError().json(json!({
                    "type": "E_USER_WRITE",
                    "message": "Failed to write data to user file"
                })));
            }
            let ReadyToReplaceInner {
                wf,
                guard,
                replace_target_path,
                write_file_path,
                ..
            } = inner;
            // read while still holding the write lock (rename keeps the mtime),
            // so this is the version this request wrote, not a later one
            let last_modified = match wf.metadata().await.and_then(|m| m.modified()) {
                Ok(o) => Some(http_date(o)),
                Err(e) => {
                    eprintln!(
                        "Error occured attempting to fetch modified of write file\n  e={e:?}\n  path={write_file_path:?}"
                    );
                    None
                }
            };
            drop(wf);
            match tokio::fs::rename(&write_file_path, &replace_target_path).await {
                Err(e) => {
                    eprintln!(
                        "Error occured attempting to replace target file with write file\n  e={e:?}\n  write_path={write_file_path:?}\n  target_path={replace_target_path:?}",
                    );
                    Err(HttpResponse::InternalServerError().json(json!({
                        "type": "E_USER_WRITE",
                        "message": "Failed to replace user file with written data"
                    })))
                }
                _ => Ok(Replaced {
                    guard,
                    replace_target_path,
                    last_modified,
                }),
            }
        } else {
            Err(HttpResponse::InternalServerError().json(json!({
                "type": "E_USER_WRITE_1",
                "message": "Failed to replace user file with written data since it was already replaced"
            })))
        }
    }
}

impl Drop for ReadyToReplace {
    fn drop(&mut self) {
        if let Some(ReadyToReplaceInner {
            guard,
            write_file_path,
            cleanup_target,
            ..
        }) = self.0.take()
        {
            tokio::spawn(async move {
                if let Err(e) = tokio::fs::remove_file(&write_file_path).await {
                    eprintln!(
                        "Error occured attempting to remove temporary write file after failed replace\n  e={e:?}\n  path={write_file_path:?}"
                    );
                }
                if let Some((username, app_state)) = cleanup_target {
                    app_state.user_locks.write().await.remove(&username);
                }
                drop(guard);
            });
        }
    }
}

pub struct Replaced {
    guard: OwnedRwLockWriteGuard<UserT>,
    replace_target_path: PathBuf,
    /// `None` if the mtime could not be read
    pub last_modified: Option<header::HttpDate>,
}

#[cfg(test)]
mod tests {
    use super::{parse_b64, parse_b64_digit};

    /// Every character in the standard 64-char base64 alphabet must decode to
    /// its correct 6-bit value (0–63).
    #[test]
    fn parse_b64_digit_full_alphabet() {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (expected, &ch) in ALPHABET.iter().enumerate() {
            let got = parse_b64_digit(ch)
                .unwrap_or_else(|e| panic!("parse_b64_digit('{}') failed: {e}", ch as char));
            assert_eq!(
                got, expected as u8,
                "wrong value for '{}': expected {expected} got {got}",
                ch as char,
            );
        }
    }

    /// URL-safe variants '-' and '_' must map to the same slots as '+' and '/'.
    #[test]
    fn parse_b64_digit_url_safe_variants() {
        assert_eq!(parse_b64_digit(b'-').unwrap(), 62);
        assert_eq!(parse_b64_digit(b'_').unwrap(), 63);
    }

    /// Encoding every byte value 0–255 and decoding it must round-trip.
    #[test]
    fn parse_b64_round_trip() {
        let original: Vec<u8> = (0u8..=255).collect();
        let encoded = b64url_encode(&original);
        let decoded = parse_b64(encoded.as_bytes()).expect("parse_b64 failed on round-trip input");
        assert_eq!(decoded, original, "round-trip mismatch");
    }

    /// A 64-byte all-zeros key encodes cleanly and decodes back.
    #[test]
    fn parse_b64_zero_key() {
        let key = vec![0u8; 64];
        let encoded = b64url_encode(&key);
        let decoded = parse_b64(encoded.as_bytes()).unwrap();
        assert_eq!(decoded, key);
    }

    /// Encodes bytes as URL-safe base64 without padding (matches the frontend).
    fn b64url_encode(bytes: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity((bytes.len() * 4 + 2) / 3);
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as usize;
            let b1 = if chunk.len() > 1 {
                chunk[1] as usize
            } else {
                0
            };
            let b2 = if chunk.len() > 2 {
                chunk[2] as usize
            } else {
                0
            };
            out.push(CHARS[b0 >> 2] as char);
            out.push(CHARS[((b0 & 3) << 4) | (b1 >> 4)] as char);
            if chunk.len() > 1 {
                out.push(CHARS[((b1 & 0xf) << 2) | (b2 >> 6)] as char);
            }
            if chunk.len() > 2 {
                out.push(CHARS[b2 & 0x3f] as char);
            }
        }
        // URL-safe, no padding (matches the frontend btoa → replace logic)
        out.replace('+', "-").replace('/', "_")
    }
}

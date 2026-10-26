use crate::{
    server_policy::{LenAccumChecker, PolicyParams, PolicyStorage},
    shared_vaults::SharedVaults,
};
use actix_web::{HttpRequest, HttpResponse, http::header, web};
use futures_util::StreamExt;
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
    sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock, mpsc},
    time::{Instant, timeout_at},
};

pub use passman_crypto::{Argon2Params, HASH_SIZE};

// Credentials are sent in these headers rather than the query string so they
// stay out of URLs, proxy access logs and the request logging below.
pub const AUTH_KEY_HEADER: &str = "Passman-Auth-Key";
pub const NEW_AUTH_KEY_HEADER: &str = "Passman-New-Auth-Key";
/// percent-encoded (`encodeURIComponent`), since header values must be ASCII
pub const SERVER_PASS_HEADER: &str = "Passman-Server-Pass";

#[repr(C, packed)]
pub struct UserDataHeader {
    pub hash: [u8; HASH_SIZE],
    pub salt: [u8; HASH_SIZE],
}

impl UserDataHeader {
    /// Size on disk: the u32 version written by `to_writer`, then hash and salt.
    pub const SIZE: usize = 4 + std::mem::size_of::<UserDataHeader>();
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
    pub shared_vaults: SharedVaults,
}

impl AppState {
    pub async fn get_user(
        &self,
        username: &str,
        password: &str,
        password_header_name: &str,
    ) -> Result<GetUser<'_>, HttpResponse> {
        validate_username(username)?;
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
        if let Err(e) = argon2.hash_password_into(&password, &udh.salt, &mut actual_hash) {
            eprintln!(
                "Error occured attempting to hash password\n  e={e:?}\n  username={username:?}\n  path={user_path:?}"
            );
            return Err(HttpResponse::BadRequest().json(json!({
                "type": "E_AUTH",
                "params": ["username", password_header_name],
                "message": "username or password is incorrect",
            })));
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
        if let Some(ch) = chunk.get(2)
            && b'='.ne(ch)
        {
            res.push((values[1] << 4) | (values[2] >> 2));
        }
        if let Some(ch) = chunk.get(3)
            && b'='.ne(ch)
        {
            res.push((values[2] << 6) | values[3]);
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

/// A vault's version: `Last-Modified` for display and a strong `ETag` for
/// conflict detection. The ETag uses the nanosecond mtime, which `finish_write`
/// makes strictly increase on every save.
pub fn vault_version(
    metadata: &Metadata,
) -> std::io::Result<(header::HttpDate, header::EntityTag)> {
    let modified = metadata.modified()?;
    let nanos = modified
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    Ok((
        http_date(modified),
        header::EntityTag::new_strong(format!("{nanos:x}-{:x}", metadata.len())),
    ))
}

/// Saves must say which version they replace (`If-Match` with the ETag the
/// client last loaded or saved); this checks it against the current one.
pub fn check_if_match(
    if_match: &header::IfMatch,
    current: &header::EntityTag,
) -> Result<(), HttpResponse> {
    let matches = match if_match {
        header::IfMatch::Any => true,
        header::IfMatch::Items(tags) => tags.iter().any(|tag| tag.strong_eq(current)),
    };
    if matches {
        Ok(())
    } else {
        Err(HttpResponse::PreconditionFailed().json(json!({
            "type": "E_PRECONDITION_FAILED",
            "header": "If-Match",
            "message": "the vault was changed by another session"
        })))
    }
}

/// actix parses an absent `If-Match` as an empty list, so both mean missing.
pub fn required_if_match(
    if_match: Option<web::Header<header::IfMatch>>,
) -> Result<header::IfMatch, HttpResponse> {
    match if_match.map(web::Header::into_inner) {
        Some(header::IfMatch::Items(tags)) if tags.is_empty() => {}
        Some(if_match) => return Ok(if_match),
        None => {}
    }
    Err(HttpResponse::PreconditionRequired().json(json!({
        "type": "E_PRECONDITION_REQUIRED",
        "header_required": "If-Match",
        "message": "the condition header is required to be specified"
    })))
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

/// Streams the rest of `file` (`remain_len` of its `file_len` bytes) as the
/// response body, holding `guard` meanwhile. `label` names the request in the
/// log line of a timed-out download.
///
/// The guard (a read lock) blocks saves, so a client that reads slowly or
/// stops reading must not keep it: a task owns the guard and the file and
/// hands chunks to the response through a one-chunk channel, and gives up
/// (releasing the guard) at the deadline even if the response stream is never
/// polled again.
pub fn streaming_download<G: Send + 'static>(
    guard: G,
    mut file: tokio::fs::File,
    file_len: u64,
    remain_len: u64,
    last_modified: header::HttpDate,
    etag: header::EntityTag,
    label: String,
) -> HttpResponse {
    let deadline = Instant::now() + download_timeout(file_len);
    let (tx, mut rx) = mpsc::channel::<std::io::Result<web::Bytes>>(1);
    tokio::spawn(async move {
        let _guard = guard;
        let mut buf = [0u8; 4096];
        loop {
            let chunk = match file.read(&mut buf).await {
                Ok(0) => return,
                Ok(len) => Ok(web::Bytes::copy_from_slice(&buf[..len])),
                Err(e) => Err(e),
            };
            let failed = chunk.is_err();
            // stops on timeout, on a read error, or when the client has gone
            match timeout_at(deadline, tx.send(chunk)).await {
                Ok(Ok(())) if !failed => {}
                _ => return,
            }
        }
    });

    HttpResponse::Ok()
        .content_type("application/octet-stream")
        .insert_header(header::CacheControl(vec![header::CacheDirective::NoCache]))
        .insert_header(header::LastModified(last_modified))
        .insert_header(header::ETag(etag))
        .no_chunking(remain_len)
        .streaming(async_stream::stream! {
            let mut sent = 0u64;
            while let Some(chunk) = rx.recv().await {
                let chunk: Result<web::Bytes, actix_web::Error> = chunk.map_err(Into::into);
                if let Ok(c) = &chunk {
                    sent += c.len() as u64;
                }
                yield chunk;
            }
            // the reader stopped before the end (it timed out): fail the
            // response rather than end it cleanly with a truncated vault
            if sent < remain_len {
                eprintln!("{label} timed out\n  sent={sent} of {remain_len}");
                let e: actix_web::Error = std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "vault download timed out",
                )
                .into();
                yield Err(e);
            }
        })
}

/// Downloads get at least `DOWNLOAD_MIN_TIMEOUT`, or long enough to finish at
/// `DOWNLOAD_MIN_RATE` bytes per second if that takes longer.
const DOWNLOAD_MIN_TIMEOUT: Duration = Duration::from_secs(5);
const DOWNLOAD_MIN_RATE: u64 = 128 * 1024;

fn download_timeout(len: u64) -> Duration {
    Duration::from_millis(len.saturating_mul(1000) / DOWNLOAD_MIN_RATE).max(DOWNLOAD_MIN_TIMEOUT)
}

/// Writes the request body to `wf`, checking it against the Content-Length
/// (when given rather than chunked) and the policy's size limit.
pub async fn write_payload(
    wf: &mut WritingFile,
    payload: &mut web::Payload,
    content_length: Option<u64>,
    len_checker: &mut LenAccumChecker,
) -> Result<(), HttpResponse> {
    if let Some(total_len) = content_length {
        len_checker.check_len(total_len).await?;
    }
    let mut accum_total_len = 0u64;
    while let Some(res) = payload.next().await {
        let chunk = match res {
            Ok(chunk) => chunk,
            Err(e) => {
                eprintln!("Error occured attempting to read payload\n  e={e:?}");
                return Err(HttpResponse::BadRequest().json(json!({
                    "type": "E_PAYLOAD_ERR",
                    "message": "Failed to read request payload"
                })));
            }
        };
        accum_total_len += chunk.len() as u64;
        match content_length {
            Some(total_len) if accum_total_len > total_len => {
                return Err(HttpResponse::BadRequest().json(json!({
                    "type": "E_PAYLOAD_TOO_LARGE",
                    "message": "request payload is larger than specified Content-Length"
                })));
            }
            Some(_) => {}
            None => len_checker.check_len(accum_total_len).await?,
        }
        wf.write_chunk(&chunk).await?;
    }
    match content_length {
        Some(total_len) if accum_total_len != total_len => {
            Err(HttpResponse::BadRequest().json(json!({
                "type": "E_PAYLOAD_TOO_SMALL",
                "message": "request payload is smaller than specified Content-Length"
            })))
        }
        _ => Ok(()),
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

/// Flushes the written file to disk (`sync_all` also waits for tokio's
/// in-flight background write, so the file is complete before the rename and
/// the lock release) and makes its mtime later than `previous`, the mtime of
/// the version it replaces, so the new version always gets a new ETag even
/// within one filesystem timestamp tick.
async fn finish_write(
    wf: &mut tokio::fs::File,
    previous: Option<SystemTime>,
) -> std::io::Result<Metadata> {
    wf.sync_all().await?;
    let metadata = wf.metadata().await?;
    let Some(previous) = previous else {
        return Ok(metadata);
    };
    if metadata.modified()? > previous {
        return Ok(metadata);
    }
    let file = wf.try_clone().await?.into_std().await;
    let bumped = previous + Duration::from_micros(1);
    tokio::task::spawn_blocking(move || {
        file.set_modified(bumped)?;
        file.sync_all()
    })
    .await??;
    let metadata = wf.metadata().await?;
    if metadata.modified()? > previous {
        Ok(metadata)
    } else {
        Err(std::io::Error::other(
            "filesystem mtime is too coarse to version the vault",
        ))
    }
}

impl ReadyToReplace {
    /// `previous_modified` is the mtime of the file being replaced (`None`
    /// when creating it).
    pub async fn replace(
        &mut self,
        previous_modified: Option<SystemTime>,
    ) -> Result<Replaced, HttpResponse> {
        if let Some(mut inner) = self.0.take() {
            // read while still holding the write lock (rename keeps the mtime),
            // so this is the version this request wrote, not a later one
            let version = finish_write(&mut inner.wf, previous_modified)
                .await
                .and_then(|metadata| vault_version(&metadata));
            let (last_modified, etag) = match version {
                Ok(o) => o,
                Err(e) => {
                    eprintln!(
                        "Error occured attempting to finish write file\n  e={e:?}\n  path={:?}",
                        inner.write_file_path
                    );
                    // put it back so Drop removes the temporary file
                    self.0 = Some(inner);
                    return Err(HttpResponse::InternalServerError().json(json!({
                        "type": "E_USER_WRITE",
                        "message": "Failed to write data to user file"
                    })));
                }
            };
            let ReadyToReplaceInner {
                wf,
                guard,
                replace_target_path,
                write_file_path,
                ..
            } = inner;
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
                    _guard: guard,
                    last_modified,
                    etag,
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
    /// Keeps the user locked until the response is built from this.
    _guard: OwnedRwLockWriteGuard<UserT>,
    pub last_modified: header::HttpDate,
    pub etag: header::EntityTag,
}

#[cfg(test)]
mod tests {
    use super::{download_timeout, finish_write, parse_b64, parse_b64_digit, vault_version};
    use std::time::{Duration, SystemTime};
    use tokio::io::AsyncWriteExt;

    /// A save in the same filesystem timestamp tick as the version it replaces
    /// (or after the clock stepped back) must still get a newer mtime, and so a
    /// different ETag.
    #[tokio::test]
    async fn finish_write_moves_mtime_past_previous() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = tokio::fs::File::create(dir.path().join("vault"))
            .await
            .unwrap();
        f.write_all(b"data").await.unwrap();
        f.sync_all().await.unwrap();
        let written = f.metadata().await.unwrap();
        for previous in [
            written.modified().unwrap(),
            SystemTime::now() + Duration::from_secs(5),
        ] {
            let metadata = finish_write(&mut f, Some(previous)).await.unwrap();
            assert!(metadata.modified().unwrap() > previous);
            assert_ne!(
                vault_version(&metadata).unwrap().1,
                vault_version(&written).unwrap().1
            );
        }
    }

    #[test]
    fn download_timeout_is_at_least_5s_or_128kib_per_s() {
        assert_eq!(download_timeout(0), Duration::from_secs(5));
        assert_eq!(download_timeout(5 * 128 * 1024), Duration::from_secs(5));
        assert_eq!(download_timeout(10 * 128 * 1024), Duration::from_secs(10));
        assert_eq!(download_timeout(64 * 1024 * 1024), Duration::from_secs(512));
    }

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
        let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
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

use crate::routes::base::{
    AUTH_KEY_HEADER, AppState, GetUser, UserDataHeader, auth_key_header, policy_params,
    vault_version,
};
use actix_web::{HttpRequest, HttpResponse, Responder, get, http::header, web};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;
use tokio::{
    io::AsyncReadExt,
    sync::mpsc,
    time::{Instant, timeout_at},
};

#[derive(Debug, Deserialize)]
struct GetPassTableParams {
    username: String,
    server_ns: Option<String>,
}

#[get("/pass-table")]
pub async fn route(
    app_state: web::Data<AppState>,
    query: web::Query<GetPassTableParams>,
    req: HttpRequest,
) -> impl Responder {
    eprintln!("GET /pass-table\n  query = {query:?}");
    let GetPassTableParams {
        username,
        server_ns,
    } = query.into_inner();
    let policy = match policy_params(&req, server_ns) {
        Err(e) => return e,
        Ok(o) => o,
    };
    let auth_key = match auth_key_header(&req, AUTH_KEY_HEADER) {
        Err(e) => return e,
        Ok(o) => o,
    };
    let len_checker = match app_state
        .policies_and_config
        .read_account_server_policy_auth(policy)
        .await
    {
        Err(e) => return e,
        Ok(o) => o,
    };
    let GetUser {
        user_path,
        read_guard,
        mut read_file,
        metadata,
        ..
    } = match app_state
        .get_user(&username, &auth_key, AUTH_KEY_HEADER)
        .await
    {
        Err(e) => return e,
        Ok(o) => o,
    };
    let remain_len = match metadata.len().checked_sub(UserDataHeader::SIZE as u64) {
        None => {
            eprintln!(
                "Error occured attempting to compare len of metadata\n  metadata={metadata:?}\n  username={username:?}\n  path={user_path:?}"
            );
            return HttpResponse::BadRequest().json(json!({
                "type": "E_USER_READ",
                "message": "Failed to read user file metadata len"
            }));
        }
        Some(s) => s,
    };
    let (last_modified, etag) = match vault_version(&metadata) {
        Ok(o) => o,
        Err(e) => {
            eprintln!(
                "Error occured attempting to fetch modified\n  metadata={metadata:?}\n  username={username:?}\n  path={user_path:?}\n  e={e:?}"
            );
            return HttpResponse::BadRequest().json(json!({
                "type": "E_USER_READ",
                "message": "Failed to read user file metadata last modified"
            }));
        }
    };
    if let Err(e) = len_checker.check_len(remain_len) {
        return e;
    }
    // The download holds the user's read lock, which blocks saves, so a client
    // that reads slowly or stops reading must not keep it: a task owns the
    // lock and the file and hands chunks to the response through a one-chunk
    // channel, and gives up (releasing the lock) at the deadline even if the
    // response stream is never polled again.
    let deadline = Instant::now() + download_timeout(metadata.len());
    let (tx, mut rx) = mpsc::channel::<std::io::Result<web::Bytes>>(1);
    tokio::spawn(async move {
        let _read_guard = read_guard;
        let mut buf = [0u8; 4096];
        loop {
            let chunk = match read_file.read(&mut buf).await {
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
                eprintln!("GET /pass-table timed out\n  username={username:?}\n  sent={sent} of {remain_len}");
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

#[cfg(test)]
mod tests {
    use super::download_timeout;
    use std::time::Duration;

    #[test]
    fn download_timeout_is_at_least_5s_or_128kib_per_s() {
        assert_eq!(download_timeout(0), Duration::from_secs(5));
        assert_eq!(download_timeout(5 * 128 * 1024), Duration::from_secs(5));
        assert_eq!(download_timeout(10 * 128 * 1024), Duration::from_secs(10));
        assert_eq!(download_timeout(64 * 1024 * 1024), Duration::from_secs(512));
    }
}

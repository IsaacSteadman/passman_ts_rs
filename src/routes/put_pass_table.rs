use crate::routes::base::{
    AUTH_KEY_HEADER, AppState, GetUser, GetWillMutUser, WritingFile, auth_key_header,
    get_content_length, policy_params,
};
use actix_web::{HttpRequest, HttpResponse, Responder, http::header, put, web};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::OwnedRwLockReadGuard;

#[derive(Debug, Deserialize)]
struct PutPassTableParams {
    username: String,
    server_ns: Option<String>,
}

#[put("/pass-table")]
pub async fn route(
    app_state: web::Data<AppState>,
    query: web::Query<PutPassTableParams>,
    if_unmodified_since: Option<web::Header<header::IfUnmodifiedSince>>,
    req: HttpRequest,
    mut payload: web::Payload,
) -> impl Responder {
    eprintln!(
        "PUT /pass-table\n  query = {query:?}\n  if_unmodified_since = {if_unmodified_since:?}"
    );
    let header::IfUnmodifiedSince(if_unmodified_since) = if let Some(s) = if_unmodified_since {
        s.into_inner()
    } else {
        return HttpResponse::PreconditionRequired().json(json!({
            "type": "E_PRECONDITION_REQUIRED",
            "header_required": "If-Unmodified-Since",
            "message": "the condition header is required to be specified"
        }));
    };
    let content_length = match get_content_length(&req) {
        Err(e) => return e,
        Ok(o) => o,
    };

    let PutPassTableParams {
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
    let mut len_checker = match app_state
        .policies_and_config
        .update_account_hook_accum_len(policy)
        .await
    {
        Err(e) => return e,
        Ok(o) => o,
    };
    let GetWillMutUser {
        base:
            GetUser {
                metadata,
                read_file,
                read_guard,
                user_path,
                udh,
                ..
            },
        write_file_path,
    } = match app_state
        .get_will_mut_user(&username, &auth_key, AUTH_KEY_HEADER)
        .await
    {
        Err(e) => return e,
        Ok(o) => o,
    };
    drop(read_file);
    let last_modified = {
        let sys_time = match metadata.modified() {
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
        // Truncate to second precision: HTTP dates have no sub-second resolution.
        // A raw SystemTime with nanoseconds compares as "newer" than the parsed
        // If-Unmodified-Since (which has only second precision), causing a
        // spurious 412 on every save even when nothing has changed.
        let secs = sys_time
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        header::HttpDate::from(
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs),
        )
    };
    if last_modified > if_unmodified_since {
        return HttpResponse::PreconditionFailed().json(json!({
            "type": "E_PRECONDITION_FAILED",
            "header": "If-Unmodified-Since",
            "message": "the resource has been modified since the specified time"
        }));
    }
    let write_guard = match OwnedRwLockReadGuard::upgrade(read_guard).await {
        Err(_) => {
            eprintln!(
                "another upgrade of the user lock was in progress when attempting to upgrade from read to write\n  username={username:?}"
            );
            return HttpResponse::Conflict().json(json!({
                "type": "E_AUTH_CONFLICT",
                "message": "failed to upgrade to exlusive lock",
            }));
        }
        Ok(o) => o,
    };
    let user_path_for_metadata = user_path.clone();
    let mut accum_total_len = 0u64;

    if let Some(total_len) = content_length {
        if let Err(e) = len_checker.check_len(total_len).await {
            return e;
        }

        let mut wf = match WritingFile::new(
            &username,
            write_guard,
            write_file_path,
            user_path,
            None,
        )
        .await
        {
            Err(e) => return e,
            Ok(o) => o,
        };

        if let Err(e) = wf.write_udh(&udh).await {
            return e;
        }

        while let Some(res) = payload.next().await {
            match res {
                Ok(chunk) => {
                    accum_total_len += chunk.len() as u64;
                    if accum_total_len > total_len {
                        return HttpResponse::BadRequest().json(json!({
                            "type": "E_PAYLOAD_TOO_LARGE",
                            "message": "request payload is larger than specified Content-Length"
                        }));
                    }
                    match wf.write_chunk(&chunk).await {
                        Err(e) => return e,
                        _ => {}
                    }
                }
                Err(e) => {
                    eprintln!("Error occured attempting to read payload\n  e={e:?}");
                    return HttpResponse::BadRequest().json(json!({
                        "type": "E_PAYLOAD_ERR",
                        "message": "Failed to read request payload"
                    }));
                }
            }
        }
        if accum_total_len != total_len {
            return HttpResponse::BadRequest().json(json!({
                "type": "E_PAYLOAD_TOO_SMALL",
                "message": "request payload is smaller than specified Content-Length"
            }));
        }
        if let Err(e) = wf.close().replace().await {
            return e;
        }
    } else {
        if let Err(e) = len_checker.check_len(accum_total_len).await {
            return e;
        }

        let mut wf = match WritingFile::new(
            &username,
            write_guard,
            write_file_path,
            user_path,
            None,
        )
        .await
        {
            Err(e) => return e,
            Ok(o) => o,
        };

        if let Err(e) = wf.write_udh(&udh).await {
            return e;
        }

        while let Some(res) = payload.next().await {
            match res {
                Ok(chunk) => {
                    accum_total_len += chunk.len() as u64;
                    if let Err(e) = len_checker.check_len(accum_total_len).await {
                        return e;
                    }
                    match wf.write_chunk(&chunk).await {
                        Err(e) => return e,
                        _ => {}
                    }
                }
                Err(e) => {
                    eprintln!("Error occured attempting to read payload\n  e={e:?}");
                    return HttpResponse::BadRequest().json(json!({
                        "type": "E_PAYLOAD_ERR",
                        "message": "Failed to read request payload"
                    }));
                }
            }
        }
        if let Err(e) = wf.close().replace().await {
            return e;
        }
    }
    // Re-read the written file's mtime (truncated to seconds) so the client
    // can use it as If-Unmodified-Since on the next save.
    let new_last_modified = tokio::fs::metadata(&user_path_for_metadata)
        .await
        .ok()
        .and_then(|m| m.modified().ok())
        .map(|t| {
            let secs = t
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            header::HttpDate::from(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs),
            )
        });
    let mut resp = HttpResponse::Ok();
    if let Some(lm) = new_last_modified {
        resp.insert_header(header::LastModified(lm));
    }
    resp.json(json!({
        "type": "SUCCESS",
        "message": "successfully saved password table"
    }))
}

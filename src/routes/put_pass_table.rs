use crate::routes::base::{
    AUTH_KEY_HEADER, AppState, GetUser, GetWillMutUser, WritingFile, auth_key_header,
    check_if_match, get_content_length, policy_params, required_if_match, vault_version,
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
    if_match: Option<web::Header<header::IfMatch>>,
    req: HttpRequest,
    mut payload: web::Payload,
) -> impl Responder {
    eprintln!("PUT /pass-table\n  query = {query:?}\n  if_match = {if_match:?}");
    let if_match = match required_if_match(if_match) {
        Err(e) => return e,
        Ok(o) => o,
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
    let current_etag = match vault_version(&metadata) {
        Ok((_, etag)) => etag,
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
    if let Err(e) = check_if_match(&if_match, &current_etag) {
        return e;
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
    let mut accum_total_len = 0u64;
    let replaced;

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
                    if let Err(e) = wf.write_chunk(&chunk).await {
                        return e;
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
        replaced = match wf.close().replace(metadata.modified().ok()).await {
            Err(e) => return e,
            Ok(o) => o,
        };
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
                    if let Err(e) = wf.write_chunk(&chunk).await {
                        return e;
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
        replaced = match wf.close().replace(metadata.modified().ok()).await {
            Err(e) => return e,
            Ok(o) => o,
        };
    }
    // the client sends the ETag back as If-Match on its next save
    let mut resp = HttpResponse::Ok();
    resp.insert_header(header::LastModified(replaced.last_modified));
    resp.insert_header(header::ETag(replaced.etag));
    resp.json(json!({
        "type": "SUCCESS",
        "message": "successfully saved password table"
    }))
}

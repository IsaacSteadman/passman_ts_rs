use crate::routes::base::{
    AUTH_KEY_HEADER, AppState, UserDataHeader, WritingFile, auth_key_header, get_content_length,
    is_reserved_username, policy_params, validate_password, validate_username,
};
use actix_web::{HttpRequest, HttpResponse, Responder, http::header, post, web};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Deserialize)]
struct PostPassTableParams {
    username: String,
    server_ns: Option<String>,
}

#[post("/pass-table")]
pub async fn route(
    app_state: web::Data<AppState>,
    query: web::Query<PostPassTableParams>,
    req: HttpRequest,
    mut payload: web::Payload,
) -> impl Responder {
    eprintln!("POST /pass-table\n  query = {query:?}");

    let content_length = match get_content_length(&req) {
        Err(e) => return e,
        Ok(o) => o,
    };

    let PostPassTableParams {
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

    if let Err(e) = validate_username(&username) {
        return e;
    }

    let password = match validate_password(&auth_key, AUTH_KEY_HEADER) {
        Err(e) => return e,
        Ok(o) => o,
    };

    let mut len_checker = match app_state
        .policies_and_config
        .clone()
        .create_account_hook_accum_len_auth(policy)
        .await
    {
        Err(e) => return e,
        Ok(o) => o,
    };

    let taken = || {
        HttpResponse::Conflict().json(json!({
            "type": "E_USER_EXISTS",
            "param": "username",
            "message": "user already exists"
        }))
    };
    if is_reserved_username(&username) {
        return taken();
    }
    let user_path = app_state.server_data_dir.join(&username);
    if tokio::fs::symlink_metadata(&user_path).await.is_ok() {
        return taken();
    }
    // the new account's lock, held until it's saved (or given up, which
    // removes it again)
    let new_lock = Arc::new(RwLock::new(()));
    let write_guard = match new_lock.clone().try_write_owned() {
        Ok(guard) => guard,
        Err(_) => unreachable!("nobody else has the new lock"),
    };
    {
        let mut user_locks = app_state.user_locks();
        if user_locks.contains_key(&username) {
            return taken();
        }
        user_locks.insert(username.clone(), new_lock);
    }

    let udh = UserDataHeader::from_auth_key(&password);

    let write_file_path = app_state.server_data_dir.join(format!(".{}.tmp", username));
    let mut accum_total_len = 0u64;

    let mut wf = match WritingFile::new(
        &username,
        write_guard,
        write_file_path,
        user_path,
        Some((username.clone(), app_state.clone())),
    )
    .await
    {
        Err(e) => return e,
        Ok(o) => o,
    };

    if let Some(total_len) = content_length {
        if let Err(e) = len_checker.check_len(total_len).await {
            return e;
        }
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
    } else {
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
    }
    let replaced = match wf.close().replace(None).await {
        Err(e) => return e,
        Ok(o) => o,
    };
    len_checker.commit();

    HttpResponse::Created()
        .insert_header(header::LastModified(replaced.last_modified))
        .insert_header(header::ETag(replaced.etag))
        .json(json!({
            "type": "SUCCESS",
            "message": "successfully created new account and saved password table"
        }))
}

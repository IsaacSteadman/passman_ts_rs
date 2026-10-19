use crate::{
    routes::base::{
        AppState, UserDataHeader, WritingFile, get_content_length, validate_password,
        validate_username,
    },
    server_policy::PolicyParams,
};
use actix_web::{HttpRequest, HttpResponse, Responder, post, web};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Deserialize)]
struct PostPassTableParams {
    #[serde(flatten)]
    policy: PolicyParams,
    username: String,
    auth_key: String,
}

#[post("/pass-table")]
pub async fn route(
    app_state: web::Data<AppState>,
    query: web::Query<PostPassTableParams>,
    req: HttpRequest,
    mut payload: web::Payload,
) -> impl Responder {
    eprintln!("POST /pass-table\n  query = {query:?}");

    let content_length = match get_content_length(req) {
        Err(e) => return e,
        Ok(o) => o,
    };

    let PostPassTableParams {
        auth_key,
        policy,
        username,
    } = query.into_inner();

    if let Err(e) = validate_username(&username) {
        return e;
    }

    let password = match validate_password(&auth_key, "auth_key") {
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

    let user_locks = app_state.user_locks.read().await;

    let user_path = app_state.server_data_dir.join(&username);
    if user_path.is_file() || user_locks.contains_key(&username) {
        return HttpResponse::Conflict().json(json!({
            "type": "E_USER_EXISTS",
            "query_param": "username",
            "message": "user already exists"
        }));
    }

    let mut user_locks = match app_state.user_locks.upgrade(user_locks).await {
        Ok(o) => o,
        Err(_) => {
            return HttpResponse::Conflict().json(json!({
                "type": "E_AUTH_CONFLICT",
                "message": "failed to upgrade to exlusive lock",
            }));
        }
    };
    let new_lock = Arc::new(RwLock::new(()));
    user_locks.insert(username.clone(), Arc::clone(&new_lock));
    let write_guard = new_lock.write_owned().await;
    drop(user_locks);

    let udh = match UserDataHeader::from_password(&password, &app_state.argon2_params.make()).await
    {
        Err(e) => {
            eprintln!(
                "Error occured attempting to create UserDataHeader from password\n  username={username:?}\n  e={e:?}"
            );
            return HttpResponse::InternalServerError().finish();
        }
        Ok(o) => o,
    };

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
    }
    if let Err(e) = wf.close().replace().await {
        return e;
    }
    len_checker.commit();

    HttpResponse::Created().json(json!({
        "type": "SUCCESS",
        "message": "successfully created new account and saved password table"
    }))
}

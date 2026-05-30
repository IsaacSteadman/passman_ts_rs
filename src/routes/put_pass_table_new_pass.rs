use crate::{
    routes::base::{
        AppState, GetUser, GetWillMutUser, UserDataHeader, WritingFile, get_content_length,
        validate_password,
    },
    server_policy::PolicyParams,
    ur_dw_lock::UpgradeError,
};
use actix_web::{HttpRequest, HttpResponse, Responder, http::header, put, web};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize)]
struct PutPassTableNewPassParams {
    #[serde(flatten)]
    policy: PolicyParams,
    username: String,
    old_auth_key: String,
    new_auth_key: String,
}

#[put("/pass-table-new-pass")]
pub async fn route(
    app_state: web::Data<AppState>,
    query: web::Query<PutPassTableNewPassParams>,
    if_unmodified_since: Option<web::Header<header::IfUnmodifiedSince>>,
    req: HttpRequest,
    mut payload: web::Payload,
) -> impl Responder {
    eprintln!(
        "PUT /pass-table-new-pass\n  query = {query:?}\n  if_unmodified_since = {if_unmodified_since:?}"
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
    let content_length = match get_content_length(req) {
        Err(e) => return e,
        Ok(o) => o,
    };

    let PutPassTableNewPassParams {
        old_auth_key,
        new_auth_key,
        policy,
        username,
    } = query.into_inner();
    let new_password = match validate_password(&new_auth_key, "new_auth_key") {
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
                argon2,
                ..
            },
        write_file_path,
    } = match app_state
        .get_will_mut_user(&username, &old_auth_key, "old_auth_key")
        .await
    {
        Err(e) => return e,
        Ok(o) => o,
    };
    drop(read_file);
    let last_modified = header::HttpDate::from(match metadata.modified() {
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
    });
    if last_modified > if_unmodified_since {
        return HttpResponse::PreconditionFailed().json(json!({
            "type": "E_PRECONDITION_FAILED",
            "header": "If-Unmodified-Since",
            "message": "the resource has been modified since the specified time"
        }));
    }
    let udh = match UserDataHeader::from_password(&new_password, &argon2).await {
        Err(e) => {
            eprintln!(
                "Error occured attempting to create new UserDataHeader from password\n  username={username:?}\n  e={e:?}"
            );
            return HttpResponse::InternalServerError().finish();
        }
        Ok(o) => o,
    };
    let write_guard = match read_guard.upgrade().await {
        Err((UpgradeError::AcquireError(ae), _)) => {
            eprintln!("AcquireError occured attempting to get user data {ae:?}");
            return HttpResponse::InternalServerError().finish();
        }
        Err((UpgradeError::AlreadyUpgrading, _)) => {
            eprintln!(
                "UpgradeError::AlreadyUpgrading occured attempting to upgrade user lock from read to write\n  username={username:?}"
            );
            return HttpResponse::Conflict().json(json!({
                "type": "E_AUTH_CONFLICT",
                "message": "failed to upgrade to exlusive lock",
            }));
        }
        Ok(o) => o,
    };
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
    HttpResponse::Ok().json(json!({
      "type": "SUCCESS",
      "message": "successfully saved password table"
    }))
}

use crate::{
    routes::base::{AppState, GetUser, UserDataHeader},
    server_policy::PolicyParams,
};
use actix_web::{HttpResponse, Responder, get, http::header, web};
use serde::Deserialize;
use serde_json::json;
use tokio::io::AsyncReadExt;

#[derive(Debug, Deserialize)]
struct GetPassTableParams {
    #[serde(flatten)]
    policy: PolicyParams,
    username: String,
    auth_key: String,
}

#[get("/pass-table")]
pub async fn route(
    app_state: web::Data<AppState>,
    query: web::Query<GetPassTableParams>,
) -> impl Responder {
    eprintln!("GET /pass-table\n  query = {query:?}");
    let GetPassTableParams {
        auth_key,
        policy,
        username,
    } = query.into_inner();
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
    } = match app_state.get_user(&username, &auth_key, "auth_key").await {
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
    if let Err(e) = len_checker.check_len(remain_len) {
        return e;
    }
    let mut buf = [0u8; 4096];

    HttpResponse::Ok()
        .content_type("application/octet-stream")
        .insert_header(header::CacheControl(vec![header::CacheDirective::NoCache]))
        .insert_header(header::LastModified(last_modified))
        .streaming(async_stream::stream! {
            loop {
                let r: Result<actix_web::web::Bytes, actix_web::Error> = match read_file.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(len) => Ok(actix_web::web::Bytes::copy_from_slice(&buf[0..len])),
                    Err(e) => Err(e.into()),
                };
                yield r;
            }
            drop(read_guard);
        })
}

//! Routes for shared vaults (see `crate::shared_vaults`). Every request is
//! made as a user, with the same credentials as their own vault's routes, and
//! only that user's memberships are visible: a vault they aren't a member of
//! is "not found", whether or not it exists.

use crate::{
    routes::base::{
        AUTH_KEY_HEADER, AppState, WritingFile, auth_key_header, check_if_match,
        get_content_length, parse_b64, policy_params, required_if_match, streaming_download,
        validate_username, vault_version, write_payload,
    },
    server_policy::{LenAccumChecker, SharedVaultLimits},
    shared_vaults::{
        MAX_SHARED_VAULT_MEMBERS, Member, Role, SharedVaultEntry, SharedVaultMeta, SharedVaults,
        valid_id,
    },
};
use actix_web::{
    HttpRequest, HttpResponse, Responder, delete, get, http::header, patch, post, put, web,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::RwLock;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(get_sharing_key)
        .service(put_sharing_key)
        .service(list)
        .service(create)
        .service(get_data)
        .service(put_data)
        .service(rename)
        .service(delete_vault)
        .service(put_member)
        .service(delete_member);
}

#[derive(Debug, Deserialize)]
struct UserParams {
    username: String,
    server_ns: Option<String>,
}

/// An X25519 public key is 32 bytes.
const SHARING_KEY_SIZE: usize = 32;
/// A sealed 32-byte vault key is 80 bytes; this leaves room for other sizes.
const MAX_WRAPPED_KEY_SIZE: usize = 256;
/// A vault name, encrypted (nonce, ciphertext and tag).
const MAX_ENCRYPTED_NAME_SIZE: usize = 1024;

fn bad_request(type_: &str, message: &str) -> HttpResponse {
    HttpResponse::BadRequest().json(json!({ "type": type_, "message": message }))
}

fn not_found() -> HttpResponse {
    HttpResponse::NotFound().json(json!({
        "type": "E_NOT_FOUND",
        "message": "no such shared vault"
    }))
}

fn forbidden(message: &str) -> HttpResponse {
    HttpResponse::Forbidden().json(json!({ "type": "E_FORBIDDEN", "message": message }))
}

fn conflict(type_: &str, message: &str) -> HttpResponse {
    HttpResponse::Conflict().json(json!({ "type": type_, "message": message }))
}

fn internal_error(context: &str, e: impl std::fmt::Debug) -> HttpResponse {
    eprintln!("Error occured attempting to {context}\n  e={e:?}");
    HttpResponse::InternalServerError().json(json!({
        "type": "E_SHARED_VAULT_IO",
        "message": format!("failed to {context}")
    }))
}

fn read_only_error() -> HttpResponse {
    HttpResponse::BadRequest().json(json!({
        "type": "E_POLICY",
        "action": "update_shared_vault",
        "message": "action was blocked by server policy",
        "policy_message": "the policy this shared vault was created under no longer allows changes"
    }))
}

/// Checks `value` is base64 of at most `max_len` bytes (exactly, if `exact`).
fn check_b64(value: &str, field: &str, max_len: usize, exact: bool) -> Result<(), HttpResponse> {
    let ok = match parse_b64(value.as_bytes()) {
        Ok(bytes) if exact => bytes.len() == max_len,
        Ok(bytes) => !bytes.is_empty() && bytes.len() <= max_len,
        Err(_) => false,
    };
    if ok {
        Ok(())
    } else {
        Err(HttpResponse::BadRequest().json(json!({
            "type": "E_BAD_REQUEST",
            "param": field,
            "message": format!("{field} must be base64 of {} {max_len} bytes", if exact { "exactly" } else { "at most" })
        })))
    }
}

/// Checks the server access credentials and the user's password.
async fn authenticate(
    app_state: &AppState,
    req: &HttpRequest,
    params: &UserParams,
) -> Result<(), HttpResponse> {
    let policy = policy_params(req, params.server_ns.clone())?;
    let auth_key = auth_key_header(req, AUTH_KEY_HEADER)?;
    app_state
        .policies_and_config
        .read_account_server_policy_auth(policy)
        .await?;
    app_state
        .get_user(&params.username, &auth_key, AUTH_KEY_HEADER)
        .await?;
    Ok(())
}

/// The vault `id` and `username`'s role in it, or "not found".
fn membership<'a>(
    vaults: &'a std::collections::HashMap<String, SharedVaultEntry>,
    id: &str,
    username: &str,
) -> Result<(&'a SharedVaultEntry, Role), HttpResponse> {
    let entry = vaults.get(id).ok_or_else(not_found)?;
    let member = entry.meta.members.get(username).ok_or_else(not_found)?;
    Ok((entry, member.role))
}

fn len_checker(limits: &SharedVaultLimits) -> LenAccumChecker {
    match limits.max_data_size {
        Some(max_data_size) => LenAccumChecker::Limited {
            action: "update_shared_vault".to_string(),
            max_data_size,
            rollback: None,
        },
        None => LenAccumChecker::AlwaysPass,
    }
}

fn max_members(limits: &SharedVaultLimits) -> usize {
    limits.max_members.map_or(MAX_SHARED_VAULT_MEMBERS, |max| {
        (max as usize).min(MAX_SHARED_VAULT_MEMBERS)
    })
}

// ── Sharing keys ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct GetSharingKeyParams {
    username: String,
    server_ns: Option<String>,
    /// Whose key to look up (the user's own when not given).
    user: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SharingKeyBody {
    public_key: String,
}

/// A user's sharing key, which vault keys are sealed to when adding them to a
/// shared vault.
#[get("/sharing-key")]
pub async fn get_sharing_key(
    app_state: web::Data<AppState>,
    query: web::Query<GetSharingKeyParams>,
    req: HttpRequest,
) -> impl Responder {
    eprintln!("GET /sharing-key\n  query = {query:?}");
    let GetSharingKeyParams {
        username,
        server_ns,
        user,
    } = query.into_inner();
    let user = user.unwrap_or_else(|| username.clone());
    if let Err(e) = authenticate(
        &app_state,
        &req,
        &UserParams {
            username,
            server_ns,
        },
    )
    .await
    {
        return e;
    }
    if let Err(e) = validate_username(&user) {
        return e;
    }
    match app_state.shared_vaults.read_sharing_key(&user).await {
        Ok(Some(public_key)) => HttpResponse::Ok().json(SharingKeyBody { public_key }),
        Ok(None) => HttpResponse::NotFound().json(json!({
            "type": "E_NO_SHARING_KEY",
            "message": "no user with this name has set up sharing"
        })),
        Err(e) => internal_error("read a sharing key", e),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutSharingKeyBody {
    public_key: String,
}

/// Publishes the user's sharing key. It can only be replaced while the user
/// isn't a member of any shared vault, since their vault keys are sealed to
/// it.
#[put("/sharing-key")]
pub async fn put_sharing_key(
    app_state: web::Data<AppState>,
    query: web::Query<UserParams>,
    body: web::Json<PutSharingKeyBody>,
    req: HttpRequest,
) -> impl Responder {
    eprintln!("PUT /sharing-key\n  query = {query:?}");
    let params = query.into_inner();
    if let Err(e) = authenticate(&app_state, &req, &params).await {
        return e;
    }
    let PutSharingKeyBody { public_key } = body.into_inner();
    if let Err(e) = check_b64(&public_key, "publicKey", SHARING_KEY_SIZE, true) {
        return e;
    }
    let shared = &app_state.shared_vaults;
    // held so no member can be added with the old key meanwhile
    let vaults = shared.vaults.write().await;
    match shared.read_sharing_key(&params.username).await {
        Ok(Some(current)) if current == public_key => {
            return HttpResponse::Ok().json(json!({ "type": "SUCCESS" }));
        }
        Ok(Some(_)) => {
            if vaults
                .values()
                .any(|v| v.meta.members.contains_key(&params.username))
            {
                return conflict(
                    "E_SHARING_KEY_IN_USE",
                    "the sharing key can't be replaced while you're a member of a shared vault",
                );
            }
        }
        Ok(None) => {}
        Err(e) => return internal_error("read a sharing key", e),
    }
    match shared
        .write_sharing_key(&params.username, &public_key)
        .await
    {
        Ok(()) => HttpResponse::Ok().json(json!({ "type": "SUCCESS" })),
        Err(e) => internal_error("save a sharing key", e),
    }
}

// ── Vaults ───────────────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MemberInfo {
    username: String,
    role: Role,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SharedVaultInfo {
    id: String,
    role: Role,
    wrapped_key: String,
    encrypted_name: String,
    members: Vec<MemberInfo>,
    /// Size of the encrypted data in bytes.
    size: u64,
    max_data_size: Option<u64>,
    max_members: usize,
    /// False once the vault's policy no longer allows changes.
    writable: bool,
}

/// The shared vaults the user is a member of, with their vault key sealed to
/// the user's sharing key.
#[get("/shared-vaults")]
pub async fn list(
    app_state: web::Data<AppState>,
    query: web::Query<UserParams>,
    req: HttpRequest,
) -> impl Responder {
    eprintln!("GET /shared-vaults\n  query = {query:?}");
    let params = query.into_inner();
    if let Err(e) = authenticate(&app_state, &req, &params).await {
        return e;
    }
    let shared = &app_state.shared_vaults;
    let mine: Vec<(String, Member, SharedVaultMeta)> = shared
        .vaults
        .read()
        .await
        .iter()
        .filter_map(|(id, entry)| {
            let member = entry.meta.members.get(&params.username)?;
            Some((id.clone(), member.clone(), entry.meta.clone()))
        })
        .collect();
    let mut infos = Vec::with_capacity(mine.len());
    for (id, member, meta) in mine {
        let limits = app_state
            .policies_and_config
            .shared_vault_limits(meta.policy_ns.as_deref())
            .await;
        let size = tokio::fs::metadata(shared.data_path(&id))
            .await
            .map_or(0, |m| m.len());
        infos.push(SharedVaultInfo {
            role: member.role,
            wrapped_key: member.wrapped_key,
            encrypted_name: meta.encrypted_name,
            members: meta
                .members
                .into_iter()
                .map(|(username, m)| MemberInfo {
                    username,
                    role: m.role,
                })
                .collect(),
            size,
            max_data_size: limits.max_data_size,
            max_members: max_members(&limits),
            writable: limits.writable,
            id,
        });
    }
    // oldest first would need a creation time; by id keeps the order stable
    infos.sort_by(|a, b| a.id.cmp(&b.id));
    HttpResponse::Ok().json(json!({ "vaults": infos }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateBody {
    encrypted_name: String,
    /// The new vault's key sealed to the creator's sharing key.
    wrapped_key: String,
    /// The sharing key it was sealed to, which must be the creator's current
    /// one.
    public_key: String,
}

/// Creates an empty shared vault with the user as its owner, counted against
/// the policy of the request's credentials (whose limits then apply to it).
#[post("/shared-vaults")]
pub async fn create(
    app_state: web::Data<AppState>,
    query: web::Query<UserParams>,
    body: web::Json<CreateBody>,
    req: HttpRequest,
) -> impl Responder {
    eprintln!("POST /shared-vaults\n  query = {query:?}");
    let params = query.into_inner();
    if let Err(e) = authenticate(&app_state, &req, &params).await {
        return e;
    }
    let CreateBody {
        encrypted_name,
        wrapped_key,
        public_key,
    } = body.into_inner();
    for (value, field, max_len) in [
        (&encrypted_name, "encryptedName", MAX_ENCRYPTED_NAME_SIZE),
        (&wrapped_key, "wrappedKey", MAX_WRAPPED_KEY_SIZE),
    ] {
        if let Err(e) = check_b64(value, field, max_len, false) {
            return e;
        }
    }
    let shared = &app_state.shared_vaults;
    match shared.read_sharing_key(&params.username).await {
        Ok(Some(current)) if current == public_key => {}
        Ok(_) => {
            return conflict(
                "E_SHARING_KEY_CHANGED",
                "the vault key must be sealed to your current sharing key",
            );
        }
        Err(e) => return internal_error("read a sharing key", e),
    }
    let policy = match policy_params(&req, params.server_ns.clone()) {
        Err(e) => return e,
        Ok(o) => o,
    };
    let mut slot = match app_state
        .policies_and_config
        .clone()
        .create_shared_vault_hook(policy)
        .await
    {
        Err(e) => return e,
        Ok(o) => o,
    };
    let id = match SharedVaults::new_id() {
        Ok(o) => o,
        Err(e) => return internal_error("generate a shared vault id", e),
    };
    let data_metadata = match shared.create_data(&id).await {
        Ok(o) => o,
        Err(e) => return internal_error("create a shared vault", e),
    };
    let meta = SharedVaultMeta {
        policy_ns: slot.policy_ns.clone(),
        encrypted_name,
        members: BTreeMap::from([(
            params.username.clone(),
            Member {
                role: Role::Owner,
                wrapped_key,
                added_by: params.username.clone(),
            },
        )]),
    };
    let mut vaults = shared.vaults.write().await;
    if let Err(e) = shared.save_meta(&id, &meta).await {
        let _ = shared.remove_data(&id).await;
        return internal_error("create a shared vault", e);
    }
    vaults.insert(
        id.clone(),
        SharedVaultEntry {
            meta,
            data_lock: Arc::new(RwLock::new(())),
        },
    );
    drop(vaults);
    slot.commit();
    let mut resp = HttpResponse::Created();
    if let Ok((last_modified, etag)) = vault_version(&data_metadata) {
        resp.insert_header(header::LastModified(last_modified));
        resp.insert_header(header::ETag(etag));
    }
    resp.json(json!({ "type": "SUCCESS", "id": id }))
}

/// Checks the id in the path, so it can be used in file names.
fn vault_id(path: web::Path<String>) -> Result<String, HttpResponse> {
    let id = path.into_inner();
    if valid_id(&id) {
        Ok(id)
    } else {
        Err(not_found())
    }
}

/// The vault's encrypted data. It is empty for a new vault.
#[get("/shared-vaults/{id}/data")]
pub async fn get_data(
    app_state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<UserParams>,
    req: HttpRequest,
) -> impl Responder {
    eprintln!("GET /shared-vaults/{path}/data\n  query = {query:?}");
    let params = query.into_inner();
    let id = match vault_id(path) {
        Err(e) => return e,
        Ok(o) => o,
    };
    if let Err(e) = authenticate(&app_state, &req, &params).await {
        return e;
    }
    let shared = &app_state.shared_vaults;
    let data_lock = match membership(&*shared.vaults.read().await, &id, &params.username) {
        Err(e) => return e,
        Ok((entry, _)) => entry.data_lock.clone(),
    };
    let guard = data_lock.read_owned().await;
    // removed (or the vault deleted) while waiting for the lock
    if let Err(e) = membership(&*shared.vaults.read().await, &id, &params.username) {
        return e;
    }
    let file = match tokio::fs::File::open(shared.data_path(&id)).await {
        Ok(o) => o,
        Err(e) => return internal_error("open a shared vault", e),
    };
    let version = file
        .metadata()
        .await
        .and_then(|metadata| Ok((metadata.len(), vault_version(&metadata)?)));
    let (len, (last_modified, etag)) = match version {
        Ok(o) => o,
        Err(e) => return internal_error("read a shared vault's metadata", e),
    };
    streaming_download(
        guard,
        file,
        len,
        len,
        last_modified,
        etag,
        format!(
            "GET /shared-vaults/{id}/data\n  username={:?}",
            params.username
        ),
    )
}

/// Replaces the vault's encrypted data; `If-Match` must hold the version it
/// replaces, as for the user's own vault.
#[put("/shared-vaults/{id}/data")]
pub async fn put_data(
    app_state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<UserParams>,
    if_match: Option<web::Header<header::IfMatch>>,
    req: HttpRequest,
    mut payload: web::Payload,
) -> impl Responder {
    eprintln!("PUT /shared-vaults/{path}/data\n  query = {query:?}\n  if_match = {if_match:?}");
    let params = query.into_inner();
    let id = match vault_id(path) {
        Err(e) => return e,
        Ok(o) => o,
    };
    let if_match = match required_if_match(if_match) {
        Err(e) => return e,
        Ok(o) => o,
    };
    let content_length = match get_content_length(&req) {
        Err(e) => return e,
        Ok(o) => o,
    };
    if let Err(e) = authenticate(&app_state, &req, &params).await {
        return e;
    }
    let shared = &app_state.shared_vaults;
    let (data_lock, policy_ns) =
        match membership(&*shared.vaults.read().await, &id, &params.username) {
            Err(e) => return e,
            Ok((_, role)) if !role.can_write() => {
                return forbidden("your role can't change this vault");
            }
            Ok((entry, _)) => (entry.data_lock.clone(), entry.meta.policy_ns.clone()),
        };
    let limits = app_state
        .policies_and_config
        .shared_vault_limits(policy_ns.as_deref())
        .await;
    if !limits.writable {
        return read_only_error();
    }
    let mut len_checker = len_checker(&limits);
    let guard = data_lock.write_owned().await;
    // removed (or the vault deleted) while waiting for the lock
    match membership(&*shared.vaults.read().await, &id, &params.username) {
        Err(e) => return e,
        Ok((_, role)) if !role.can_write() => {
            return forbidden("your role can't change this vault");
        }
        Ok(_) => {}
    }
    let data_path = shared.data_path(&id);
    let previous = match tokio::fs::metadata(&data_path).await {
        Ok(o) => o,
        Err(e) => return internal_error("read a shared vault's metadata", e),
    };
    match vault_version(&previous) {
        Ok((_, current_etag)) => {
            if let Err(e) = check_if_match(&if_match, &current_etag) {
                return e;
            }
        }
        Err(e) => return internal_error("read a shared vault's metadata", e),
    }
    let mut wf =
        match WritingFile::new(&id, guard, shared.write_data_path(&id), data_path, None).await {
            Err(e) => return e,
            Ok(o) => o,
        };
    if let Err(e) = write_payload(&mut wf, &mut payload, content_length, &mut len_checker).await {
        return e;
    }
    let replaced = match wf.close().replace(previous.modified().ok()).await {
        Err(e) => return e,
        Ok(o) => o,
    };
    HttpResponse::Ok()
        .insert_header(header::LastModified(replaced.last_modified))
        .insert_header(header::ETag(replaced.etag))
        .json(json!({
            "type": "SUCCESS",
            "message": "successfully saved shared vault"
        }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RenameBody {
    encrypted_name: String,
}

/// Renames the vault (the name is encrypted with the vault key).
#[patch("/shared-vaults/{id}")]
pub async fn rename(
    app_state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<UserParams>,
    body: web::Json<RenameBody>,
    req: HttpRequest,
) -> impl Responder {
    eprintln!("PATCH /shared-vaults/{path}\n  query = {query:?}");
    let params = query.into_inner();
    let id = match vault_id(path) {
        Err(e) => return e,
        Ok(o) => o,
    };
    if let Err(e) = authenticate(&app_state, &req, &params).await {
        return e;
    }
    let RenameBody { encrypted_name } = body.into_inner();
    if let Err(e) = check_b64(
        &encrypted_name,
        "encryptedName",
        MAX_ENCRYPTED_NAME_SIZE,
        false,
    ) {
        return e;
    }
    let shared = &app_state.shared_vaults;
    let mut vaults = shared.vaults.write().await;
    let mut meta = match membership(&vaults, &id, &params.username) {
        Err(e) => return e,
        Ok((_, role)) if !role.can_write() => {
            return forbidden("your role can't change this vault");
        }
        Ok((entry, _)) => entry.meta.clone(),
    };
    if !app_state
        .policies_and_config
        .shared_vault_limits(meta.policy_ns.as_deref())
        .await
        .writable
    {
        return read_only_error();
    }
    meta.encrypted_name = encrypted_name;
    if let Err(e) = shared.save_meta(&id, &meta).await {
        return internal_error("save a shared vault's details", e);
    }
    if let Some(entry) = vaults.get_mut(&id) {
        entry.meta = meta;
    }
    HttpResponse::Ok().json(json!({ "type": "SUCCESS" }))
}

/// Deletes the vault (owners only), giving its policy its count back.
#[delete("/shared-vaults/{id}")]
pub async fn delete_vault(
    app_state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<UserParams>,
    req: HttpRequest,
) -> impl Responder {
    eprintln!("DELETE /shared-vaults/{path}\n  query = {query:?}");
    let params = query.into_inner();
    let id = match vault_id(path) {
        Err(e) => return e,
        Ok(o) => o,
    };
    if let Err(e) = authenticate(&app_state, &req, &params).await {
        return e;
    }
    let shared = &app_state.shared_vaults;
    let mut vaults = shared.vaults.write().await;
    match membership(&vaults, &id, &params.username) {
        Err(e) => return e,
        Ok((_, Role::Owner)) => {}
        Ok(_) => return forbidden("only an owner can delete this vault"),
    }
    if let Err(e) = shared.remove_meta(&id).await {
        return internal_error("delete a shared vault", e);
    }
    let Some(entry) = vaults.remove(&id) else {
        return not_found();
    };
    drop(vaults);
    app_state
        .policies_and_config
        .release_shared_vault(entry.meta.policy_ns.as_deref())
        .await;
    // after any download or save in progress (which re-check that the vault
    // still exists once they hold the lock)
    let _guard = entry.data_lock.write().await;
    if let Err(e) = shared.remove_data(&id).await {
        eprintln!("Error occured attempting to remove a deleted shared vault's data\n  e={e:?}");
    }
    HttpResponse::Ok().json(json!({ "type": "SUCCESS" }))
}

// ── Members ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutMemberBody {
    role: Role,
    /// Required to add a member: the vault key sealed to their sharing key.
    wrapped_key: Option<String>,
    /// The sharing key `wrapped_key` was sealed to, which must still be the
    /// member's current one.
    public_key: Option<String>,
}

/// Adds a member or changes their role (owners only).
#[put("/shared-vaults/{id}/members/{member}")]
pub async fn put_member(
    app_state: web::Data<AppState>,
    path: web::Path<(String, String)>,
    query: web::Query<UserParams>,
    body: web::Json<PutMemberBody>,
    req: HttpRequest,
) -> impl Responder {
    let (id, member_name) = path.into_inner();
    eprintln!("PUT /shared-vaults/{id}/members/{member_name}\n  query = {query:?}");
    let params = query.into_inner();
    if !valid_id(&id) {
        return not_found();
    }
    if let Err(e) = authenticate(&app_state, &req, &params).await {
        return e;
    }
    if let Err(e) = validate_username(&member_name) {
        return e;
    }
    let PutMemberBody {
        role,
        wrapped_key,
        public_key,
    } = body.into_inner();
    let new_key = match (wrapped_key, public_key) {
        (Some(wrapped_key), Some(public_key)) => {
            if let Err(e) = check_b64(&wrapped_key, "wrappedKey", MAX_WRAPPED_KEY_SIZE, false) {
                return e;
            }
            Some((wrapped_key, public_key))
        }
        (None, None) => None,
        _ => {
            return bad_request(
                "E_BAD_REQUEST",
                "wrappedKey and publicKey must be given together",
            );
        }
    };
    let shared = &app_state.shared_vaults;
    let mut vaults = shared.vaults.write().await;
    let mut meta = match membership(&vaults, &id, &params.username) {
        Err(e) => return e,
        Ok((entry, Role::Owner)) => entry.meta.clone(),
        Ok(_) => return forbidden("only an owner can change this vault's members"),
    };
    let limits = app_state
        .policies_and_config
        .shared_vault_limits(meta.policy_ns.as_deref())
        .await;
    if !limits.writable {
        return read_only_error();
    }
    if let Some((_, public_key)) = &new_key {
        match shared.read_sharing_key(&member_name).await {
            Ok(Some(current)) if &current == public_key => {}
            Ok(Some(_)) => {
                return conflict(
                    "E_SHARING_KEY_CHANGED",
                    "the member's sharing key has changed; look it up again",
                );
            }
            Ok(None) => {
                return HttpResponse::NotFound().json(json!({
                    "type": "E_NO_SHARING_KEY",
                    "message": "no user with this name has set up sharing"
                }));
            }
            Err(e) => return internal_error("read a sharing key", e),
        }
    }
    let owner_count = meta.owner_count();
    match meta.members.get_mut(&member_name) {
        Some(member) => {
            if member.role == Role::Owner && role != Role::Owner && owner_count == 1 {
                return conflict(
                    "E_LAST_OWNER",
                    "a shared vault needs an owner; make someone else an owner first",
                );
            }
            member.role = role;
            if let Some((wrapped_key, _)) = new_key {
                member.wrapped_key = wrapped_key;
                member.added_by = params.username.clone();
            }
        }
        None => {
            let Some((wrapped_key, _)) = new_key else {
                return bad_request(
                    "E_BAD_REQUEST",
                    "wrappedKey and publicKey are required to add a member",
                );
            };
            let max = max_members(&limits);
            if meta.members.len() >= max {
                return HttpResponse::BadRequest().json(json!({
                    "type": "E_POLICY",
                    "action": "add_shared_vault_member",
                    "message": "action was blocked by server policy",
                    "policy_message": format!("this shared vault has reached the maximum of {max} members")
                }));
            }
            meta.members.insert(
                member_name,
                Member {
                    role,
                    wrapped_key,
                    added_by: params.username.clone(),
                },
            );
        }
    }
    if let Err(e) = shared.save_meta(&id, &meta).await {
        return internal_error("save a shared vault's members", e);
    }
    if let Some(entry) = vaults.get_mut(&id) {
        entry.meta = meta;
    }
    HttpResponse::Ok().json(json!({ "type": "SUCCESS" }))
}

/// Removes a member: an owner can remove anyone, and anyone can leave.
#[delete("/shared-vaults/{id}/members/{member}")]
pub async fn delete_member(
    app_state: web::Data<AppState>,
    path: web::Path<(String, String)>,
    query: web::Query<UserParams>,
    req: HttpRequest,
) -> impl Responder {
    let (id, member_name) = path.into_inner();
    eprintln!("DELETE /shared-vaults/{id}/members/{member_name}\n  query = {query:?}");
    let params = query.into_inner();
    if !valid_id(&id) {
        return not_found();
    }
    if let Err(e) = authenticate(&app_state, &req, &params).await {
        return e;
    }
    let shared = &app_state.shared_vaults;
    let mut vaults = shared.vaults.write().await;
    let mut meta = match membership(&vaults, &id, &params.username) {
        Err(e) => return e,
        Ok((entry, role)) if role == Role::Owner || member_name == params.username => {
            entry.meta.clone()
        }
        Ok(_) => return forbidden("only an owner can remove other members"),
    };
    let owner_count = meta.owner_count();
    match meta.members.get(&member_name) {
        None => {
            return HttpResponse::NotFound().json(json!({
                "type": "E_NOT_FOUND",
                "message": "no such member"
            }));
        }
        Some(member) if member.role == Role::Owner && owner_count == 1 => {
            return conflict(
                "E_LAST_OWNER",
                "a shared vault needs an owner; make someone else an owner first, or delete the vault",
            );
        }
        Some(_) => {}
    }
    meta.members.remove(&member_name);
    if let Err(e) = shared.save_meta(&id, &meta).await {
        return internal_error("save a shared vault's members", e);
    }
    if let Some(entry) = vaults.get_mut(&id) {
        entry.meta = meta;
    }
    HttpResponse::Ok().json(json!({ "type": "SUCCESS" }))
}

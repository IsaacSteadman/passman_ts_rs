//! Routes for shared vaults and sharing identities (see
//! `crate::shared_vaults`). Every request is made as a user, with the same
//! credentials as their own vault's routes, and only that user's vaults are
//! visible: one they aren't a member of is "not found", whether or not it
//! exists. Members' browsers check everything they download themselves; the
//! server checks it too before storing it.

use crate::{
    routes::base::{
        AUTH_KEY_HEADER, AppState, auth_key_header, check_if_match, get_content_length,
        policy_params, required_if_match, streaming_download, validate_username,
    },
    server_policy::SharedVaultLimits,
    shared_vaults::{VaultMeta, VaultState, valid_id},
};
use actix_web::{HttpRequest, HttpResponse, Responder, delete, get, http::header, post, put, web};
use futures_util::StreamExt;
use passman_crypto::sharing::{self, RecordBody, VersionBody};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(get_identity)
        .service(put_identity)
        .service(list)
        .service(create)
        .service(get_records)
        .service(post_record)
        .service(get_version)
        .service(put_version)
        .service(get_archive)
        .service(leave)
        .service(delete_vault);
}

#[derive(Debug, Deserialize)]
struct UserParams {
    username: String,
    server_ns: Option<String>,
}

/// The largest upload for a vault without a size limit.
const MAX_UPLOAD: u64 = 64 * 1024 * 1024;

fn error(status: actix_web::http::StatusCode, type_: &str, message: &str) -> HttpResponse {
    HttpResponse::build(status).json(json!({ "type": type_, "message": message }))
}

fn not_found() -> HttpResponse {
    error(
        actix_web::http::StatusCode::NOT_FOUND,
        "E_NOT_FOUND",
        "no such shared vault",
    )
}

fn forbidden(message: &str) -> HttpResponse {
    error(
        actix_web::http::StatusCode::FORBIDDEN,
        "E_FORBIDDEN",
        message,
    )
}

fn conflict(type_: &str, message: &str) -> HttpResponse {
    error(actix_web::http::StatusCode::CONFLICT, type_, message)
}

/// Something a member's browser would refuse too.
fn invalid(e: anyhow::Error) -> HttpResponse {
    HttpResponse::BadRequest().json(json!({
        "type": "E_INVALID",
        "message": format!("{e}")
    }))
}

fn internal_error(context: &str, e: impl std::fmt::Debug) -> HttpResponse {
    eprintln!("Error occured attempting to {context}\n  e={e:?}");
    HttpResponse::InternalServerError().json(json!({
        "type": "E_SHARED_VAULT_IO",
        "message": format!("failed to {context}")
    }))
}

fn policy_error(action: &str, policy_message: String) -> HttpResponse {
    HttpResponse::BadRequest().json(json!({
        "type": "E_POLICY",
        "action": action,
        "message": "action was blocked by server policy",
        "policy_message": policy_message
    }))
}

fn read_only_error() -> HttpResponse {
    policy_error(
        "update_shared_vault",
        "the policy this shared vault was created under no longer allows changes".to_string(),
    )
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

/// Reads the whole request body, refusing more than `max` bytes.
async fn read_body(
    req: &HttpRequest,
    payload: &mut web::Payload,
    max: u64,
) -> Result<Vec<u8>, HttpResponse> {
    let too_large = || {
        policy_error(
            "update_shared_vault",
            format!("the shared vault would be larger than its maximum size {max}"),
        )
    };
    let content_length = get_content_length(req)?;
    if content_length.is_some_and(|len| len > max) {
        return Err(too_large());
    }
    let mut body = Vec::with_capacity(content_length.unwrap_or(0) as usize);
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(|e| {
            eprintln!("Error occured attempting to read payload\n  e={e:?}");
            HttpResponse::BadRequest().json(json!({
                "type": "E_PAYLOAD_ERR",
                "message": "Failed to read request payload"
            }))
        })?;
        body.extend_from_slice(&chunk);
        if body.len() as u64 > max {
            return Err(too_large());
        }
    }
    if content_length.is_some_and(|len| len != body.len() as u64) {
        return Err(HttpResponse::BadRequest().json(json!({
            "type": "E_PAYLOAD_SIZE",
            "message": "request payload doesn't match the specified Content-Length"
        })));
    }
    Ok(body)
}

fn max_data_size(limits: &SharedVaultLimits) -> u64 {
    limits.max_data_size.unwrap_or(MAX_UPLOAD).min(MAX_UPLOAD)
}

fn max_members(limits: &SharedVaultLimits) -> usize {
    limits.max_members.map_or(sharing::MAX_MEMBERS, |max| {
        (max as usize).min(sharing::MAX_MEMBERS)
    })
}

/// The version's ETag: its epoch and number, which only ever increase.
fn version_etag(version: &VersionBody) -> header::EntityTag {
    header::EntityTag::new_strong(format!("{}-{}", version.epoch, version.version))
}

/// `username`'s published identity bundle, or why it can't be used.
async fn identity(app_state: &AppState, username: &str) -> Result<Vec<u8>, HttpResponse> {
    match app_state.shared_vaults.read_identity(username).await {
        Ok(Some(bundle)) => Ok(bundle),
        Ok(None) => Err(HttpResponse::NotFound().json(json!({
            "type": "E_NO_IDENTITY",
            "message": format!("{username} hasn't set up sharing")
        }))),
        Err(e) => Err(internal_error("read an identity", e)),
    }
}

/// Checks a record's members exist and were verified with their current
/// identity (a member whose fingerprint is unchanged since `prev` was checked
/// when they were added), and that the vault's policy allows that many.
async fn check_members(
    app_state: &AppState,
    record: &RecordBody,
    prev: Option<&RecordBody>,
    limits: &SharedVaultLimits,
) -> Result<(), HttpResponse> {
    let max = max_members(limits);
    if record.members.len() > max {
        return Err(policy_error(
            "add_shared_vault_member",
            format!("a shared vault can have at most {max} members"),
        ));
    }
    for member in &record.members {
        validate_username(&member.username)?;
        if prev
            .and_then(|p| p.member(&member.username))
            .is_some_and(|m| m.fingerprint == member.fingerprint)
        {
            continue;
        }
        let bundle = identity(app_state, &member.username).await?;
        if sharing::b64_encode(&sharing::fingerprint(&bundle)) != member.fingerprint {
            return Err(conflict(
                "E_IDENTITY_CHANGED",
                &format!(
                    "{}'s identity has changed; verify them again",
                    member.username
                ),
            ));
        }
    }
    Ok(())
}

/// The vault `id`, locked for reading, if `username` is a member.
async fn read_vault(
    app_state: &AppState,
    id: &str,
    username: &str,
) -> Result<tokio::sync::OwnedRwLockReadGuard<VaultState>, HttpResponse> {
    let vault = vault_arc(app_state, id).await?;
    let state = vault.read_owned().await;
    if state.is_member(username) && !deleted(&state) {
        Ok(state)
    } else {
        Err(not_found())
    }
}

/// The vault `id`, locked for changing, if `username` is a member.
async fn write_vault(
    app_state: &AppState,
    id: &str,
    username: &str,
) -> Result<tokio::sync::OwnedRwLockWriteGuard<VaultState>, HttpResponse> {
    let vault = vault_arc(app_state, id).await?;
    let state = vault.write_owned().await;
    if state.is_member(username) && !deleted(&state) {
        Ok(state)
    } else {
        Err(not_found())
    }
}

async fn vault_arc(
    app_state: &AppState,
    id: &str,
) -> Result<Arc<RwLock<VaultState>>, HttpResponse> {
    if !valid_id(id) {
        return Err(not_found());
    }
    app_state
        .shared_vaults
        .vaults
        .read()
        .await
        .get(id)
        .cloned()
        .ok_or_else(not_found)
}

/// A vault deleted while waiting for its lock has no members left.
fn deleted(state: &VaultState) -> bool {
    state.record.members.is_empty()
}

// ── Identities ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct GetIdentityParams {
    username: String,
    server_ns: Option<String>,
    /// Whose identity to look up (the user's own when not given).
    user: Option<String>,
    /// Or which identity: any bundle ever published, by its fingerprint (64
    /// hex digits), to check records and versions made with it.
    fingerprint: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityBody {
    /// The identity bundle (base64).
    bundle: String,
}

/// A user's public identity bundle, which members verify (by its
/// fingerprint) before adding them.
#[get("/identity")]
pub async fn get_identity(
    app_state: web::Data<AppState>,
    query: web::Query<GetIdentityParams>,
    req: HttpRequest,
) -> impl Responder {
    eprintln!("GET /identity\n  query = {query:?}");
    let GetIdentityParams {
        username,
        server_ns,
        user,
        fingerprint,
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
    if let Some(fingerprint) = fingerprint {
        return match app_state
            .shared_vaults
            .read_identity_by_fingerprint(&fingerprint)
            .await
        {
            Ok(Some(bundle)) => HttpResponse::Ok().json(IdentityBody {
                bundle: sharing::b64_encode(&bundle),
            }),
            Ok(None) => HttpResponse::NotFound().json(json!({
                "type": "E_NO_IDENTITY",
                "message": "no identity with this fingerprint"
            })),
            Err(e) => internal_error("read an identity", e),
        };
    }
    if let Err(e) = validate_username(&user) {
        return e;
    }
    match identity(&app_state, &user).await {
        Ok(bundle) => HttpResponse::Ok().json(IdentityBody {
            bundle: sharing::b64_encode(&bundle),
        }),
        Err(e) => e,
    }
}

/// Publishes the user's identity bundle. It can only be replaced while the
/// user isn't a member of any shared vault, since those pin its fingerprint.
#[put("/identity")]
pub async fn put_identity(
    app_state: web::Data<AppState>,
    query: web::Query<UserParams>,
    body: web::Json<IdentityBody>,
    req: HttpRequest,
) -> impl Responder {
    eprintln!("PUT /identity\n  query = {query:?}");
    let params = query.into_inner();
    if let Err(e) = authenticate(&app_state, &req, &params).await {
        return e;
    }
    let bundle = match base64_decode(&body.bundle) {
        Some(b) if sharing::check_bundle(&b).is_ok() => b,
        _ => {
            return HttpResponse::BadRequest().json(json!({
                "type": "E_BAD_REQUEST",
                "message": "bundle must be a base64 identity bundle"
            }));
        }
    };
    let shared = &app_state.shared_vaults;
    // held so no vault can add the user with the old identity meanwhile
    let vaults = shared.vaults.write().await;
    match shared.read_identity(&params.username).await {
        Ok(Some(current)) if current == bundle => {
            return HttpResponse::Ok().json(json!({ "type": "SUCCESS" }));
        }
        Ok(Some(_)) => {
            for vault in vaults.values() {
                if vault.read().await.record.member(&params.username).is_some() {
                    return conflict(
                        "E_IDENTITY_IN_USE",
                        "your identity can't be replaced while you're a member of a shared vault",
                    );
                }
            }
        }
        Ok(None) => {}
        Err(e) => return internal_error("read an identity", e),
    }
    match shared.write_identity(&params.username, &bundle).await {
        Ok(()) => HttpResponse::Ok().json(json!({ "type": "SUCCESS" })),
        Err(e) => internal_error("save an identity", e),
    }
}

fn base64_decode(value: &str) -> Option<Vec<u8>> {
    crate::routes::base::parse_b64(value.as_bytes()).ok()
}

// ── Vaults ───────────────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultInfo {
    id: String,
    /// The latest record's `seq` and the current version's ETag, to tell
    /// whether this device's copy is up to date.
    seq: u64,
    etag: String,
    /// Epochs whose history is archived.
    archives: Vec<u64>,
    /// Members who left and are still to be removed by a manager.
    leaving: Vec<String>,
    /// Bytes stored for the vault (its current version and archives).
    size: u64,
    max_data_size: Option<u64>,
    max_members: usize,
    /// False once the vault's policy no longer allows changes.
    writable: bool,
}

/// The shared vaults the user is a member of.
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
    let vaults: Vec<(String, Arc<RwLock<VaultState>>)> = app_state
        .shared_vaults
        .vaults
        .read()
        .await
        .iter()
        .map(|(id, v)| (id.clone(), v.clone()))
        .collect();
    let mut infos = Vec::new();
    for (id, vault) in vaults {
        let state = vault.read().await;
        if !state.is_member(&params.username) || deleted(&state) {
            continue;
        }
        let limits = app_state
            .policies_and_config
            .shared_vault_limits(state.meta.policy_ns.as_deref())
            .await;
        infos.push(VaultInfo {
            id,
            seq: state.record.seq,
            etag: version_etag(&state.version).to_string(),
            archives: state.archives.keys().copied().collect(),
            leaving: state.meta.leaving.iter().cloned().collect(),
            size: state.total_len(),
            max_data_size: limits.max_data_size,
            max_members: max_members(&limits),
            writable: limits.writable,
        });
    }
    infos.sort_by(|a, b| a.id.cmp(&b.id));
    HttpResponse::Ok().json(json!({ "vaults": infos }))
}

/// Splits a record and the version that goes with it.
fn record_and_version(body: &[u8]) -> Result<(&[u8], &[u8]), HttpResponse> {
    match sharing::decode_frames(body, 2) {
        Ok(frames) => Ok((frames[0], frames[1])),
        Err(e) => Err(invalid(e)),
    }
}

/// Creates a shared vault from its first record and version (frames, see
/// `sharing::encode_frames`), counted against the policy of the request's
/// credentials, whose limits then apply to it.
#[post("/shared-vaults")]
pub async fn create(
    app_state: web::Data<AppState>,
    query: web::Query<UserParams>,
    req: HttpRequest,
    mut payload: web::Payload,
) -> impl Responder {
    eprintln!("POST /shared-vaults\n  query = {query:?}");
    let params = query.into_inner();
    if let Err(e) = authenticate(&app_state, &req, &params).await {
        return e;
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
    let limits = app_state
        .policies_and_config
        .shared_vault_limits(slot.policy_ns.as_deref())
        .await;
    let body = match read_body(&req, &mut payload, max_data_size(&limits) + 512 * 1024).await {
        Err(e) => return e,
        Ok(o) => o,
    };
    let (record_wire, version_wire) = match record_and_version(&body) {
        Err(e) => return e,
        Ok(o) => o,
    };
    let bundle = match identity(&app_state, &params.username).await {
        Err(e) => return e,
        Ok(o) => o,
    };
    let record = match sharing::verify_record(None, record_wire, &bundle) {
        Err(e) => return invalid(e),
        Ok(o) => o,
    };
    if record.author != params.username || !valid_id(&record.vault_id) {
        return invalid(anyhow::anyhow!("the record must be yours, with a valid id"));
    }
    if let Err(e) = check_members(&app_state, &record, None, &limits).await {
        return e;
    }
    let version = match sharing::verify_version(&record, version_wire, &bundle) {
        Err(e) => return invalid(e),
        Ok(o) => o,
    };
    if version.version != 1 || version.author != params.username || version.rekey {
        return invalid(anyhow::anyhow!("not a first version"));
    }
    if version_wire.len() as u64 > max_data_size(&limits) {
        return policy_error(
            "update_shared_vault",
            format!(
                "the shared vault would be larger than its maximum size {}",
                max_data_size(&limits)
            ),
        );
    }
    let id = record.vault_id.clone();
    let shared = &app_state.shared_vaults;
    let mut vaults = shared.vaults.write().await;
    if vaults.contains_key(&id) {
        return conflict("E_EXISTS", "a shared vault with this id exists");
    }
    let meta = VaultMeta {
        policy_ns: slot.policy_ns.clone(),
        leaving: Default::default(),
    };
    if let Err(e) = shared.create(&id, &meta, record_wire, version_wire).await {
        let _ = shared.delete(&id).await;
        return internal_error("create a shared vault", e);
    }
    let etag = version_etag(&version);
    vaults.insert(
        id.clone(),
        Arc::new(RwLock::new(VaultState {
            meta,
            record,
            record_wire: record_wire.to_vec(),
            version,
            version_len: version_wire.len() as u64,
            archives: Default::default(),
        })),
    );
    drop(vaults);
    slot.commit();
    HttpResponse::Created()
        .insert_header(header::ETag(etag))
        .json(json!({ "type": "SUCCESS", "id": id }))
}

#[derive(Debug, Deserialize)]
struct RecordsParams {
    username: String,
    server_ns: Option<String>,
    /// The first record to return.
    from: Option<u64>,
}

/// The vault's records from `from` on (base64), so a member can check the
/// whole chain from its first record.
#[get("/shared-vaults/{id}/records")]
pub async fn get_records(
    app_state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<RecordsParams>,
    req: HttpRequest,
) -> impl Responder {
    eprintln!("GET /shared-vaults/{path}/records\n  query = {query:?}");
    let RecordsParams {
        username,
        server_ns,
        from,
    } = query.into_inner();
    let params = UserParams {
        username,
        server_ns,
    };
    if let Err(e) = authenticate(&app_state, &req, &params).await {
        return e;
    }
    let id = path.into_inner();
    let state = match read_vault(&app_state, &id, &params.username).await {
        Err(e) => return e,
        Ok(o) => o,
    };
    let mut records = Vec::new();
    for seq in from.unwrap_or(0)..=state.record.seq {
        match tokio::fs::read(app_state.shared_vaults.record_path(&id, seq)).await {
            Ok(wire) => records.push(sharing::b64_encode(&wire)),
            Err(e) => return internal_error("read a record", e),
        }
    }
    HttpResponse::Ok().json(json!({ "records": records }))
}

/// Starts a new epoch: a record changing the member list (made by a manager)
/// and the epoch's first version, which re-encrypts the vault with the new
/// key. `If-Match` must hold the current version's ETag.
#[post("/shared-vaults/{id}/records")]
pub async fn post_record(
    app_state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<UserParams>,
    if_match: Option<web::Header<header::IfMatch>>,
    req: HttpRequest,
    mut payload: web::Payload,
) -> impl Responder {
    eprintln!("POST /shared-vaults/{path}/records\n  query = {query:?}");
    let params = query.into_inner();
    let if_match = match required_if_match(if_match) {
        Err(e) => return e,
        Ok(o) => o,
    };
    if let Err(e) = authenticate(&app_state, &req, &params).await {
        return e;
    }
    let id = path.into_inner();
    let mut state = match write_vault(&app_state, &id, &params.username).await {
        Err(e) => return e,
        Ok(o) => o,
    };
    let limits = app_state
        .policies_and_config
        .shared_vault_limits(state.meta.policy_ns.as_deref())
        .await;
    if !limits.writable {
        return read_only_error();
    }
    let body = match read_body(&req, &mut payload, max_data_size(&limits) + 512 * 1024).await {
        Err(e) => return e,
        Ok(o) => o,
    };
    if let Err(e) = check_if_match(&if_match, &version_etag(&state.version)) {
        return e;
    }
    let (record_wire, version_wire) = match record_and_version(&body) {
        Err(e) => return e,
        Ok(o) => o,
    };
    let bundle = match identity(&app_state, &params.username).await {
        Err(e) => return e,
        Ok(o) => o,
    };
    let record = match sharing::verify_record(
        Some((&state.record, &state.record_wire)),
        record_wire,
        &bundle,
    ) {
        Err(e) => return invalid(e),
        Ok(o) => o,
    };
    if record.author != params.username {
        return invalid(anyhow::anyhow!("the record must be yours"));
    }
    if let Some(name) = state
        .meta
        .leaving
        .iter()
        .find(|name| record.member(name).is_some())
    {
        return conflict(
            "E_MEMBER_LEAVING",
            &format!("{name} left the vault and must be removed"),
        );
    }
    if let Err(e) = check_members(&app_state, &record, Some(&state.record), &limits).await {
        return e;
    }
    let version = match sharing::verify_version(&record, version_wire, &bundle) {
        Err(e) => return invalid(e),
        Ok(o) => o,
    };
    if version.version != state.version.version + 1 || version.author != params.username {
        return invalid(anyhow::anyhow!("not the next version"));
    }
    // older archives make room for the new one if needed
    let max = max_data_size(&limits);
    if version_wire.len() as u64 > max {
        return policy_error(
            "update_shared_vault",
            format!("the shared vault would be larger than its maximum size {max}"),
        );
    }
    let archived = match app_state
        .shared_vaults
        .start_epoch(&id, &state, record_wire, version_wire)
        .await
    {
        Err(e) => return internal_error("start an epoch", e),
        Ok(o) => o,
    };
    let old_epoch = state.version.epoch;
    state.archives.insert(old_epoch, archived);
    state.record = record;
    state.record_wire = record_wire.to_vec();
    state.version_len = version_wire.len() as u64;
    let etag = version_etag(&version);
    state.version = version;
    prune_archives(&app_state, &id, &mut state, max).await;
    HttpResponse::Ok()
        .insert_header(header::ETag(etag))
        .json(json!({ "type": "SUCCESS" }))
}

/// Drops the oldest archived history until the vault fits in `max`.
async fn prune_archives(app_state: &AppState, id: &str, state: &mut VaultState, max: u64) {
    while state.total_len() > max {
        let Some((&epoch, _)) = state.archives.iter().next() else {
            return;
        };
        if let Err(e) = app_state.shared_vaults.remove_archive(id, epoch).await {
            eprintln!("Error occured attempting to remove an archive\n  e={e:?}");
            return;
        }
        state.archives.remove(&epoch);
    }
}

/// The current version (frames, see `sharing::sign_version`).
#[get("/shared-vaults/{id}/version")]
pub async fn get_version(
    app_state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<UserParams>,
    req: HttpRequest,
) -> impl Responder {
    eprintln!("GET /shared-vaults/{path}/version\n  query = {query:?}");
    let params = query.into_inner();
    if let Err(e) = authenticate(&app_state, &req, &params).await {
        return e;
    }
    let id = path.into_inner();
    let state = match read_vault(&app_state, &id, &params.username).await {
        Err(e) => return e,
        Ok(o) => o,
    };
    let file = match tokio::fs::File::open(app_state.shared_vaults.current_path(&id)).await {
        Ok(o) => o,
        Err(e) => return internal_error("open a shared vault", e),
    };
    let etag = version_etag(&state.version);
    let len = state.version_len;
    let last_modified = header::HttpDate::from(
        std::time::UNIX_EPOCH + std::time::Duration::from_millis(state.version.time),
    );
    streaming_download(
        state,
        file,
        len,
        len,
        last_modified,
        etag,
        format!(
            "GET /shared-vaults/{id}/version\n  username={:?}",
            params.username
        ),
    )
}

/// Saves a new version in the current epoch. `If-Match` must hold the
/// current version's ETag; a version of an earlier epoch is refused with
/// `E_EPOCH_CHANGED` (re-encrypt it with the new key and try again).
#[put("/shared-vaults/{id}/version")]
pub async fn put_version(
    app_state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<UserParams>,
    if_match: Option<web::Header<header::IfMatch>>,
    req: HttpRequest,
    mut payload: web::Payload,
) -> impl Responder {
    eprintln!("PUT /shared-vaults/{path}/version\n  query = {query:?}");
    let params = query.into_inner();
    let if_match = match required_if_match(if_match) {
        Err(e) => return e,
        Ok(o) => o,
    };
    if let Err(e) = authenticate(&app_state, &req, &params).await {
        return e;
    }
    let id = path.into_inner();
    let mut state = match write_vault(&app_state, &id, &params.username).await {
        Err(e) => return e,
        Ok(o) => o,
    };
    let member = state.record.member(&params.username).cloned();
    if !member.is_some_and(|m| m.write) {
        return forbidden("you can't change this vault");
    }
    let limits = app_state
        .policies_and_config
        .shared_vault_limits(state.meta.policy_ns.as_deref())
        .await;
    if !limits.writable {
        return read_only_error();
    }
    let max = max_data_size(&limits);
    let body = match read_body(&req, &mut payload, max).await {
        Err(e) => return e,
        Ok(o) => o,
    };
    let bundle = match identity(&app_state, &params.username).await {
        Err(e) => return e,
        Ok(o) => o,
    };
    if let Ok(frames) = sharing::decode_frames(&body, 4)
        && let Ok(claimed) = serde_json::from_slice::<VersionBody>(frames[0])
        && claimed.epoch != state.record.seq
    {
        return HttpResponse::Conflict().json(json!({
            "type": "E_EPOCH_CHANGED",
            "message": "the member list changed; re-encrypt with the new key",
            "seq": state.record.seq
        }));
    }
    if let Err(e) = check_if_match(&if_match, &version_etag(&state.version)) {
        return e;
    }
    let version = match sharing::verify_version(&state.record, &body, &bundle) {
        Err(e) => return invalid(e),
        Ok(o) => o,
    };
    if version.version != state.version.version + 1
        || version.author != params.username
        || version.rekey
    {
        return invalid(anyhow::anyhow!("not the next version"));
    }
    if let Err(e) =
        crate::shared_vaults::write_atomic(&app_state.shared_vaults.current_path(&id), &body).await
    {
        return internal_error("save a shared vault", e);
    }
    state.version_len = body.len() as u64;
    let etag = version_etag(&version);
    state.version = version;
    prune_archives(&app_state, &id, &mut state, max).await;
    HttpResponse::Ok()
        .insert_header(header::ETag(etag))
        .json(json!({ "type": "SUCCESS" }))
}

/// The archived history of a past epoch the user was a member in.
#[get("/shared-vaults/{id}/archive/{epoch}")]
pub async fn get_archive(
    app_state: web::Data<AppState>,
    path: web::Path<(String, u64)>,
    query: web::Query<UserParams>,
    req: HttpRequest,
) -> impl Responder {
    let (id, epoch) = path.into_inner();
    eprintln!("GET /shared-vaults/{id}/archive/{epoch}\n  query = {query:?}");
    let params = query.into_inner();
    if let Err(e) = authenticate(&app_state, &req, &params).await {
        return e;
    }
    let state = match read_vault(&app_state, &id, &params.username).await {
        Err(e) => return e,
        Ok(o) => o,
    };
    if !state.archives.contains_key(&epoch) {
        return not_found();
    }
    let shared = &app_state.shared_vaults;
    // only for members of that epoch: later members may not read it
    let was_member = match tokio::fs::read(shared.record_path(&id, epoch)).await {
        Ok(wire) => sharing::parse_record(&wire)
            .is_ok_and(|record| record.member(&params.username).is_some()),
        Err(e) => return internal_error("read a record", e),
    };
    if !was_member {
        return not_found();
    }
    match tokio::fs::read(shared.archive_path(&id, epoch)).await {
        Ok(data) => HttpResponse::Ok()
            .content_type("application/octet-stream")
            .body(data),
        Err(e) => internal_error("read an archive", e),
    }
}

/// Leaves the vault: the user can no longer open it, and a manager's browser
/// removes them from the member list (with a new key) when it next can.
#[post("/shared-vaults/{id}/leave")]
pub async fn leave(
    app_state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<UserParams>,
    req: HttpRequest,
) -> impl Responder {
    eprintln!("POST /shared-vaults/{path}/leave\n  query = {query:?}");
    let params = query.into_inner();
    if let Err(e) = authenticate(&app_state, &req, &params).await {
        return e;
    }
    let id = path.into_inner();
    let mut state = match write_vault(&app_state, &id, &params.username).await {
        Err(e) => return e,
        Ok(o) => o,
    };
    let staying: Vec<_> = state
        .record
        .members
        .iter()
        .filter(|m| m.username != params.username && !state.meta.leaving.contains(&m.username))
        .collect();
    if staying.is_empty() {
        return conflict(
            "E_LAST_MEMBER",
            "you're the last member; delete the vault instead",
        );
    }
    if !staying.iter().any(|m| m.manage) {
        return conflict(
            "E_LAST_MANAGER",
            "a shared vault needs someone to manage it; let another member manage it first",
        );
    }
    let mut meta = state.meta.clone();
    meta.leaving.insert(params.username.clone());
    if let Err(e) = app_state.shared_vaults.save_meta(&id, &meta).await {
        return internal_error("leave a shared vault", e);
    }
    state.meta = meta;
    HttpResponse::Ok().json(json!({ "type": "SUCCESS" }))
}

/// Deletes the vault (managers only), giving its policy its count back.
#[delete("/shared-vaults/{id}")]
pub async fn delete_vault(
    app_state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<UserParams>,
    req: HttpRequest,
) -> impl Responder {
    eprintln!("DELETE /shared-vaults/{path}\n  query = {query:?}");
    let params = query.into_inner();
    if let Err(e) = authenticate(&app_state, &req, &params).await {
        return e;
    }
    let id = path.into_inner();
    if !valid_id(&id) {
        return not_found();
    }
    let shared = &app_state.shared_vaults;
    let mut vaults = shared.vaults.write().await;
    let Some(vault) = vaults.get(&id).cloned() else {
        return not_found();
    };
    // after any download or save in progress
    let mut state = vault.write().await;
    if !state.is_member(&params.username) {
        return not_found();
    }
    if !state
        .record
        .member(&params.username)
        .is_some_and(|m| m.manage)
    {
        return forbidden("only a manager can delete this vault");
    }
    if let Err(e) = shared.delete(&id).await {
        return internal_error("delete a shared vault", e);
    }
    vaults.remove(&id);
    drop(vaults);
    // anything still waiting for the lock sees it was deleted
    state.record.members.clear();
    let policy_ns = state.meta.policy_ns.clone();
    drop(state);
    app_state
        .policies_and_config
        .release_shared_vault(policy_ns.as_deref())
        .await;
    HttpResponse::Ok().json(json!({ "type": "SUCCESS" }))
}

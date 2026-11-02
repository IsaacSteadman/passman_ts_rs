//! Routes for shared vaults and sharing identities (see
//! `crate::shared_vaults`). Every request is made as a user, with the same
//! credentials as their own vault's routes, and only that user's vaults are
//! visible: one they aren't a member of is "not found", whether or not it
//! exists. Members' browsers check everything they download themselves; the
//! server checks it too before storing it.
//!
//! No lock is held while waiting for a client: uploads are read before the
//! vault is locked, downloads are opened under the lock and streamed after
//! it's released, and listing reads the registry rather than each vault.

use crate::{
    routes::base::{
        AUTH_KEY_HEADER, AppState, auth_key_header, check_if_match, get_content_length,
        http_date_from_millis, policy_params, required_if_match, streaming_download,
        validate_username,
    },
    server_policy::VaultLimits,
    shared_vaults::{
        ReserveError, Summary, VaultLock, VaultMeta, VaultState, valid_id, version_etag,
    },
};
use actix_web::{
    HttpRequest, HttpResponse, Responder, delete, get, http::StatusCode, http::header, post, put,
    web,
};
use futures_util::StreamExt;
use passman_crypto::sharing::{self, RecordBody, VersionBody};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, OwnedSemaphorePermit};

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

/// The most a version's signature, body and framing add to its encrypted
/// contents (about 3.7 KB; the body's fields are bounded and canonical).
const VERSION_OVERHEAD_MAX: u64 = 8 * 1024;
/// The largest leave statement.
const MAX_STATEMENT: u64 = 8 * 1024;
/// Signed times may be at most this far ahead of the server's clock.
const MAX_CLOCK_AHEAD_MS: u64 = 24 * 60 * 60 * 1000;

/// The largest record of a vault with at most `max_members` members: the
/// signature and body, and each member's entry and wrapped key.
fn record_max_len(max_members: u32) -> u64 {
    8 * 1024 + max_members as u64 * 3 * 1024
}

/// The largest version of a vault whose contents may be `max_data_size`.
fn version_max_len(limits: &VaultLimits) -> u64 {
    limits.max_data_size + VERSION_OVERHEAD_MAX
}

fn error(status: StatusCode, type_: &str, message: &str) -> HttpResponse {
    HttpResponse::build(status).json(json!({ "type": type_, "message": message }))
}

fn not_found() -> HttpResponse {
    error(StatusCode::NOT_FOUND, "E_NOT_FOUND", "no such shared vault")
}

fn forbidden(message: &str) -> HttpResponse {
    error(StatusCode::FORBIDDEN, "E_FORBIDDEN", message)
}

fn conflict(type_: &str, message: &str) -> HttpResponse {
    error(StatusCode::CONFLICT, type_, message)
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

fn too_large(max: u64) -> HttpResponse {
    policy_error(
        "update_shared_vault",
        format!("the shared vault's contents would be larger than its maximum size {max}"),
    )
}

/// Refuses a signed time too far in the future (it would also show
/// wrongly to everyone else).
fn check_time(millis: u64) -> Result<(), HttpResponse> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    if millis > now.saturating_add(MAX_CLOCK_AHEAD_MS) {
        return Err(invalid(anyhow::anyhow!(
            "the time it was made is in the future; check this device's clock"
        )));
    }
    Ok(())
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
        .get_user(req, &params.username, &auth_key, AUTH_KEY_HEADER)
        .await?;
    Ok(())
}

/// A request body held in memory, counted against the server's budget for
/// that until it's dropped.
struct Body {
    data: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}

/// Reads the whole request body, refusing more than `max` bytes. A
/// `Content-Length` is required, and memory for it is reserved up front:
/// when too many uploads are in progress, this one is refused (503).
async fn read_body(
    app_state: &AppState,
    req: &HttpRequest,
    payload: &mut web::Payload,
    max: u64,
) -> Result<Body, HttpResponse> {
    let Some(len) = get_content_length(req)? else {
        return Err(HttpResponse::LengthRequired().json(json!({
            "type": "E_LENGTH_REQUIRED",
            "message": "a Content-Length is required"
        })));
    };
    if len > max {
        return Err(too_large(max));
    }
    let kib = len.div_ceil(1024).max(1);
    let permit = u32::try_from(kib)
        .ok()
        .and_then(|kib| {
            app_state
                .upload_budget
                .clone()
                .try_acquire_many_owned(kib)
                .ok()
        })
        .ok_or_else(|| {
            HttpResponse::ServiceUnavailable()
                .insert_header((header::RETRY_AFTER, "5"))
                .json(json!({
                    "type": "E_BUSY",
                    "message": "the server is busy; try again shortly"
                }))
        })?;
    let mut data = Vec::with_capacity(len as usize);
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(|e| {
            eprintln!("Error occured attempting to read payload\n  e={e:?}");
            HttpResponse::BadRequest().json(json!({
                "type": "E_PAYLOAD_ERR",
                "message": "Failed to read request payload"
            }))
        })?;
        if (data.len() + chunk.len()) as u64 > len {
            break;
        }
        data.extend_from_slice(&chunk);
    }
    if data.len() as u64 != len {
        return Err(HttpResponse::BadRequest().json(json!({
            "type": "E_PAYLOAD_SIZE",
            "message": "request payload doesn't match the specified Content-Length"
        })));
    }
    Ok(Body {
        data,
        _permit: permit,
    })
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
/// when they were added), and that the vault's limits allow it. Call holding
/// `identity_lock`, until the record is stored.
async fn check_members(
    app_state: &AppState,
    record: &RecordBody,
    record_len: usize,
    prev: Option<&RecordBody>,
    limits: &VaultLimits,
) -> Result<(), HttpResponse> {
    let max = limits.max_members as usize;
    if record.members.len() > max {
        return Err(policy_error(
            "add_shared_vault_member",
            format!("this shared vault can have at most {max} members"),
        ));
    }
    if record_len as u64 > record_max_len(limits.max_members) {
        return Err(invalid(anyhow::anyhow!("the member list is too large")));
    }
    check_time(record.time)?;
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

/// The version's ETag (see `version_etag`).
fn entity_tag(version: &VersionBody) -> header::EntityTag {
    header::EntityTag::new_strong(format!("{}-{}", version.epoch, version.version))
}

/// Checks a version's contents fit the vault and its time is plausible.
fn check_version(
    version: &VersionBody,
    wire: &[u8],
    limits: &VaultLimits,
) -> Result<(), HttpResponse> {
    check_time(version.time)?;
    let content_len = sharing::version_content_len(wire).map_err(invalid)?;
    if content_len > limits.max_data_size {
        return Err(too_large(limits.max_data_size));
    }
    Ok(())
}

/// A vault the user is a member of, as known without its lock.
struct MemberVault {
    lock: VaultLock,
    summary: Arc<Summary>,
    write: bool,
    manage: bool,
}

/// The vault `id` and what's known about it without its lock, if `username`
/// is a member (and hasn't left).
fn member_vault(
    app_state: &AppState,
    id: &str,
    username: &str,
) -> Result<MemberVault, HttpResponse> {
    if !valid_id(id) {
        return Err(not_found());
    }
    let (lock, summary) = app_state.shared_vaults.lookup(id).ok_or_else(not_found)?;
    let (write, manage) = summary.member(username).ok_or_else(not_found)?;
    Ok(MemberVault {
        lock,
        summary,
        write,
        manage,
    })
}

/// The vault `id`, locked for reading, if `username` is a member.
async fn read_vault(
    app_state: &AppState,
    id: &str,
    username: &str,
) -> Result<OwnedRwLockReadGuard<VaultState>, HttpResponse> {
    let state = member_vault(app_state, id, username)?
        .lock
        .read_owned()
        .await;
    if state.is_member(username) {
        Ok(state)
    } else {
        Err(not_found())
    }
}

/// The vault `id`, locked for changing, if `username` is (still) a member.
async fn write_vault(
    lock: VaultLock,
    username: &str,
) -> Result<OwnedRwLockWriteGuard<VaultState>, HttpResponse> {
    let state = lock.write_owned().await;
    if state.is_member(username) {
        Ok(state)
    } else {
        Err(not_found())
    }
}

// ── Identities ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct GetIdentityParams {
    username: String,
    server_ns: Option<String>,
    /// Whose identity to look up (the user's own when not given).
    user: Option<String>,
    /// Or which identity: a bundle still in use (someone's current one, or
    /// one named in a record kept), by its fingerprint (64 hex digits), to
    /// check records and versions made with it.
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
/// user isn't a member of any shared vault, since those pin its fingerprint;
/// the replaced one is deleted unless a record kept still names it.
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
    // so no vault can add the user with the old identity meanwhile
    let _identities = shared.identity_lock.lock().await;
    match shared.read_identity(&params.username).await {
        Ok(Some(current)) if current == bundle => {
            return HttpResponse::Ok().json(json!({ "type": "SUCCESS" }));
        }
        Ok(Some(_)) if shared.in_any_vault(&params.username) => {
            return conflict(
                "E_IDENTITY_IN_USE",
                "your identity can't be replaced while you're a member of a shared vault",
            );
        }
        Ok(_) => {}
        Err(e) => return internal_error("read an identity", e),
    }
    match shared.write_identity(&params.username, &bundle).await {
        Ok(replaced) => {
            shared.forget_bundles(replaced).await;
            HttpResponse::Ok().json(json!({ "type": "SUCCESS" }))
        }
        Err(e) => internal_error("save an identity", e),
    }
}

fn base64_decode(value: &str) -> Option<Vec<u8>> {
    crate::routes::base::parse_b64(value.as_bytes()).ok()
}

// ── Vaults ───────────────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArchiveSize {
    epoch: u64,
    /// Its encrypted history's size (counted toward the vault's limit).
    size: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Leaving {
    username: String,
    /// The signed statement (base64), for managers' browsers to check
    /// before removing them.
    statement: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultInfo {
    id: String,
    /// The latest record's `seq` and the current version's ETag, to tell
    /// whether this device's copy is up to date.
    seq: u64,
    /// The oldest record kept.
    first_seq: u64,
    etag: String,
    /// Epochs whose history is archived.
    archives: Vec<ArchiveSize>,
    /// Members leaving, still to be removed by a manager.
    leaving: Vec<Leaving>,
    /// What counts toward the size limit: the encrypted contents of the
    /// current version and the archives.
    usage: u64,
    max_data_size: u64,
    max_members: u32,
    max_records: u32,
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
    let mut infos = Vec::new();
    for (id, summary) in app_state.shared_vaults.summaries_for(&params.username) {
        let writable = app_state
            .policies_and_config
            .shared_vault_writable(summary.policy_ns.as_deref())
            .await;
        infos.push(VaultInfo {
            id,
            seq: summary.seq,
            first_seq: summary.first_seq,
            etag: summary.etag.clone(),
            archives: summary
                .archives
                .iter()
                .map(|&(epoch, size)| ArchiveSize { epoch, size })
                .collect(),
            leaving: summary
                .leaving
                .iter()
                .map(|(username, statement)| Leaving {
                    username: username.clone(),
                    statement: statement.clone(),
                })
                .collect(),
            usage: summary.usage,
            max_data_size: summary.limits.max_data_size,
            max_members: summary.limits.max_members,
            max_records: summary.limits.max_records,
            writable,
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
/// `sharing::encode_frames`). Its limits come from the policy of the
/// request's credentials, which also counts it (as does its creator).
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
    let limits = slot.limits;
    let max = record_max_len(limits.max_members) + version_max_len(&limits) + 8;
    let body = match read_body(&app_state, &req, &mut payload, max).await {
        Err(e) => return e,
        Ok(o) => o,
    };
    let (record_wire, version_wire) = match record_and_version(&body.data) {
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
    let version = match sharing::verify_version(&record, version_wire, &bundle) {
        Err(e) => return invalid(e),
        Ok(o) => o,
    };
    if version.version != 1 || version.author != params.username || version.rekey {
        return invalid(anyhow::anyhow!("not a first version"));
    }
    if let Err(e) = check_version(&version, version_wire, &limits) {
        return e;
    }
    let shared = &app_state.shared_vaults;
    let id = record.vault_id.clone();
    let reservation = match shared.reserve_creation(&id, &params.username, slot.max_per_user) {
        Ok(o) => o,
        Err(ReserveError::Exists) => {
            return conflict("E_EXISTS", "a shared vault with this id exists");
        }
        Err(ReserveError::TooMany(max)) => {
            return policy_error(
                "create_shared_vault",
                format!("you can create at most {max} shared vaults"),
            );
        }
    };
    let _identities = shared.identity_lock.lock().await;
    if let Err(e) = check_members(&app_state, &record, record_wire.len(), None, &limits).await {
        return e;
    }
    let meta = VaultMeta {
        policy_ns: slot.policy_ns.clone(),
        creator: params.username.clone(),
        limits,
        leaving: Default::default(),
    };
    let etag = version_etag(&version);
    if let Err(e) = shared
        .create(
            reservation,
            meta,
            record,
            record_wire,
            version,
            version_wire,
        )
        .await
    {
        return internal_error("create a shared vault", e);
    }
    slot.commit();
    HttpResponse::Created()
        .insert_header((header::ETAG, etag))
        .json(json!({ "type": "SUCCESS", "id": id }))
}

#[derive(Debug, Deserialize)]
struct RecordsParams {
    username: String,
    server_ns: Option<String>,
    /// The first record wanted.
    from: Option<u64>,
}

/// The vault's records from `from` on (base64), or from the oldest kept if
/// that's later (`from` in the response says which), so a member can check
/// the whole chain the server keeps.
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
    let start = from.unwrap_or(0).max(state.first_seq);
    let mut records = Vec::new();
    for seq in start..=state.record.seq {
        match tokio::fs::read(app_state.shared_vaults.record_path(&id, seq)).await {
            Ok(wire) => records.push(sharing::b64_encode(&wire)),
            Err(e) => return internal_error("read a record", e),
        }
    }
    HttpResponse::Ok().json(json!({ "from": start, "records": records }))
}

/// Starts a new epoch: a record changing the member list (made by a manager)
/// and the epoch's first version, which re-encrypts the vault with the new
/// key. `If-Match` must hold the current version's ETag. Records beyond the
/// vault's limit are dropped (oldest first, with their epochs' history).
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
    let MemberVault {
        lock,
        summary,
        manage,
        ..
    } = match member_vault(&app_state, &id, &params.username) {
        Err(e) => return e,
        Ok(o) => o,
    };
    if !manage {
        return forbidden("only a manager can change the members");
    }
    let limits = summary.limits;
    let max = record_max_len(limits.max_members) + version_max_len(&limits) + 8;
    let body = match read_body(&app_state, &req, &mut payload, max).await {
        Err(e) => return e,
        Ok(o) => o,
    };
    let (record_wire, version_wire) = match record_and_version(&body.data) {
        Err(e) => return e,
        Ok(o) => o,
    };
    let bundle = match identity(&app_state, &params.username).await {
        Err(e) => return e,
        Ok(o) => o,
    };

    let mut state = match write_vault(lock, &params.username).await {
        Err(e) => return e,
        Ok(o) => o,
    };
    if !app_state
        .policies_and_config
        .shared_vault_writable(state.meta.policy_ns.as_deref())
        .await
    {
        return read_only_error();
    }
    if let Err(e) = check_if_match(&if_match, &entity_tag(&state.version)) {
        return e;
    }
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
        .keys()
        .find(|name| record.member(name).is_some())
    {
        return conflict(
            "E_MEMBER_LEAVING",
            &format!("{name} is leaving the vault and must be removed"),
        );
    }
    let version = match sharing::verify_version(&record, version_wire, &bundle) {
        Err(e) => return invalid(e),
        Ok(o) => o,
    };
    if version.version != state.version.version + 1 || version.author != params.username {
        return invalid(anyhow::anyhow!("not the next version"));
    }
    if let Err(e) = check_version(&version, version_wire, &limits) {
        return e;
    }

    let shared = &app_state.shared_vaults;
    let _identities = shared.identity_lock.lock().await;
    let prev = state.record.clone();
    if let Err(e) =
        check_members(&app_state, &record, record_wire.len(), Some(&prev), &limits).await
    {
        return e;
    }
    let etag = version_etag(&version);
    if let Err(e) = shared
        .start_epoch(&id, &mut state, record, record_wire, version, version_wire)
        .await
    {
        return internal_error("start an epoch", e);
    }
    // everyone leaving was removed
    if !state.meta.leaving.is_empty() {
        let mut meta = state.meta.clone();
        meta.leaving.clear();
        if let Err(e) = shared.save_meta(&id, &meta).await {
            eprintln!("Error occured attempting to save a vault's members leaving\n  e={e:?}");
        }
        state.meta = meta;
    }
    let dropped = shared.prune(&id, &mut state).await;
    shared.update_summary(&id, &state);
    drop(state);
    shared.forget_bundles(dropped).await;
    HttpResponse::Ok()
        .insert_header((header::ETAG, etag))
        .json(json!({ "type": "SUCCESS" }))
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
    let etag = entity_tag(&state.version);
    let len = state.version_len;
    let last_modified = http_date_from_millis(state.version.time);
    // the open file stays this version even if a save replaces it now
    drop(state);
    streaming_download(
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
/// `E_EPOCH_CHANGED` (re-encrypt it with the new key and try again). The
/// oldest archived history is dropped if needed to stay within the vault's
/// size.
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
    let MemberVault {
        lock,
        summary,
        write,
        ..
    } = match member_vault(&app_state, &id, &params.username) {
        Err(e) => return e,
        Ok(o) => o,
    };
    if !write {
        return forbidden("you can't change this vault");
    }
    let limits = summary.limits;
    let body = match read_body(&app_state, &req, &mut payload, version_max_len(&limits)).await {
        Err(e) => return e,
        Ok(o) => o,
    };
    let bundle = match identity(&app_state, &params.username).await {
        Err(e) => return e,
        Ok(o) => o,
    };

    let mut state = match write_vault(lock, &params.username).await {
        Err(e) => return e,
        Ok(o) => o,
    };
    if !state
        .record
        .member(&params.username)
        .is_some_and(|m| m.write)
    {
        return forbidden("you can't change this vault");
    }
    if !app_state
        .policies_and_config
        .shared_vault_writable(state.meta.policy_ns.as_deref())
        .await
    {
        return read_only_error();
    }
    if let Ok(frames) = sharing::decode_frames(&body.data, 4)
        && let Ok(claimed) = serde_json::from_slice::<VersionBody>(frames[0])
        && claimed.epoch != state.record.seq
    {
        return HttpResponse::Conflict().json(json!({
            "type": "E_EPOCH_CHANGED",
            "message": "the member list changed; re-encrypt with the new key",
            "seq": state.record.seq
        }));
    }
    if let Err(e) = check_if_match(&if_match, &entity_tag(&state.version)) {
        return e;
    }
    let version = match sharing::verify_version(&state.record, &body.data, &bundle) {
        Err(e) => return invalid(e),
        Ok(o) => o,
    };
    if version.version != state.version.version + 1
        || version.author != params.username
        || version.rekey
    {
        return invalid(anyhow::anyhow!("not the next version"));
    }
    if let Err(e) = check_version(&version, &body.data, &limits) {
        return e;
    }
    let shared = &app_state.shared_vaults;
    let etag = version_etag(&version);
    if let Err(e) = shared
        .save_version(&id, &mut state, version, &body.data)
        .await
    {
        return internal_error("save a shared vault", e);
    }
    shared.prune(&id, &mut state).await;
    shared.update_summary(&id, &state);
    HttpResponse::Ok()
        .insert_header((header::ETAG, etag))
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
    let Some(archive) = state.archives.get(&epoch).copied() else {
        return not_found();
    };
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
    let file = match tokio::fs::File::open(shared.archive_path(&id, epoch)).await {
        Ok(o) => o,
        Err(e) => return internal_error("read an archive", e),
    };
    drop(state);
    streaming_download(
        file,
        archive.len,
        archive.len,
        None,
        header::EntityTag::new_strong(format!("archive-{epoch}")),
        format!(
            "GET /shared-vaults/{id}/archive/{epoch}\n  username={:?}",
            params.username
        ),
    )
}

/// Records a signed statement (the body) that a member is leaving, made by
/// them or by a manager (the user making the request) in the current epoch.
/// The member can no longer open the vault, and a manager's browser removes
/// them (with a new key) when it next can, after checking the statement.
#[post("/shared-vaults/{id}/leave")]
pub async fn leave(
    app_state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<UserParams>,
    req: HttpRequest,
    mut payload: web::Payload,
) -> impl Responder {
    eprintln!("POST /shared-vaults/{path}/leave\n  query = {query:?}");
    let params = query.into_inner();
    if let Err(e) = authenticate(&app_state, &req, &params).await {
        return e;
    }
    let id = path.into_inner();
    let lock = match member_vault(&app_state, &id, &params.username) {
        Err(e) => return e,
        Ok(o) => o.lock,
    };
    let body = match read_body(&app_state, &req, &mut payload, MAX_STATEMENT).await {
        Err(e) => return e,
        Ok(o) => o,
    };
    let claimed = match sharing::parse_leave(&body.data) {
        Err(e) => return invalid(e),
        Ok(o) => o,
    };
    if claimed.author != params.username {
        return invalid(anyhow::anyhow!("the statement must be yours"));
    }
    let shared = &app_state.shared_vaults;
    let mut state = match write_vault(lock, &params.username).await {
        Err(e) => return e,
        Ok(o) => o,
    };
    let Some(author) = state.record.member(&params.username) else {
        return not_found();
    };
    let bundle = match shared.bundle_of(&author.fingerprint).await {
        Ok(Some(bundle)) => bundle,
        Ok(None) => return invalid(anyhow::anyhow!("your identity isn't known")),
        Err(e) => return internal_error("read an identity", e),
    };
    let statement = match sharing::verify_leave(&state.record, &body.data, &bundle) {
        Err(e) => return invalid(e),
        Ok(o) => o,
    };
    if let Err(e) = check_time(statement.time) {
        return e;
    }
    if state.meta.leaving.contains_key(&statement.member) {
        return HttpResponse::Ok().json(json!({ "type": "SUCCESS" }));
    }
    let staying: Vec<_> = state
        .record
        .members
        .iter()
        .filter(|m| m.username != statement.member && !state.meta.leaving.contains_key(&m.username))
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
    meta.leaving
        .insert(statement.member.clone(), sharing::b64_encode(&body.data));
    if let Err(e) = shared.save_meta(&id, &meta).await {
        return internal_error("leave a shared vault", e);
    }
    state.meta = meta;
    shared.update_summary(&id, &state);
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
    let lock = match member_vault(&app_state, &id, &params.username) {
        Err(e) => return e,
        Ok(o) => o.lock,
    };
    // after any save in progress (downloads don't hold it)
    let mut state = match write_vault(lock, &params.username).await {
        Err(e) => return e,
        Ok(o) => o,
    };
    if !state
        .record
        .member(&params.username)
        .is_some_and(|m| m.manage)
    {
        return forbidden("only a manager can delete this vault");
    }
    let shared = &app_state.shared_vaults;
    let fingerprints = match shared.delete(&id, &mut state).await {
        Err(e) => return internal_error("delete a shared vault", e),
        Ok(o) => o,
    };
    let policy_ns = state.meta.policy_ns.clone();
    drop(state);
    app_state
        .policies_and_config
        .release_shared_vault(policy_ns.as_deref())
        .await;
    let _identities = shared.identity_lock.lock().await;
    shared.forget_bundles(fingerprints).await;
    HttpResponse::Ok().json(json!({ "type": "SUCCESS" }))
}

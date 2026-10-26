use crate::{
    routes::{
        base::{AppState, Argon2Params},
        frontend::FrontendMode,
        get_pass_table, post_pass_table, put_pass_table, put_pass_table_new_pass,
    },
    server_policy::PolicyStorage,
    shared_vaults::SharedVaults,
};
use actix_web::{App, HttpServer, web};
use std::{collections::HashMap, os::unix::fs::PermissionsExt, path::PathBuf};
use tokio::sync::RwLock;

mod config;
mod routes;
mod server_policy;
mod shared_vaults;

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    let base_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let config_filename = base_dir.join("config.json");
    let config: crate::config::ServerConfig =
        match serde_json::from_slice(&match tokio::fs::read(&config_filename).await {
            Ok(o) => o,
            Err(e) => {
                anyhow::bail!("error reading {config_filename:?}: {e:?}");
            }
        }) {
            Ok(o) => o,
            Err(e) => {
                anyhow::bail!("error parsing {config_filename:?}: {e:?}");
            }
        };
    let (policies_and_config, join_handle) = PolicyStorage::new(&base_dir, config.clone()).await?;
    let policy_storage = policies_and_config.clone();
    // holds the vaults and password hashes, so only the service account may
    // list or open it (set_permissions also fixes a directory created earlier)
    let server_data_dir = base_dir.join("server_data");
    tokio::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&server_data_dir)
        .await?;
    tokio::fs::set_permissions(&server_data_dir, std::fs::Permissions::from_mode(0o700)).await?;
    let shared_vaults = SharedVaults::load(&server_data_dir.join(".shared")).await?;
    let app_state = web::Data::new(AppState {
        argon2_params: Argon2Params::new()?,
        policies_and_config,
        server_data_dir,
        user_locks: RwLock::new(HashMap::new()),
        shared_vaults,
    });
    let frontend_mode = web::Data::new(if let Ok(url) = std::env::var("FRONTEND_DEV_SERVER") {
        println!("Proxying frontend requests to {url}");
        FrontendMode::DevProxy(url)
    } else {
        let dist = base_dir.join("dist");
        println!("Serving static frontend from {dist:?}");
        FrontendMode::StaticFiles(dist)
    });
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .app_data(frontend_mode.clone())
            .service(get_pass_table::route)
            .service(post_pass_table::route)
            .service(put_pass_table::route)
            .service(put_pass_table_new_pass::route)
            .configure(routes::shared_vaults::configure)
            .default_service(web::to(routes::frontend::frontend_handler))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await?;
    join_handle.abort();
    let _ = join_handle.await;
    // persist any change the save task had not picked up yet
    policy_storage.save().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, http::header, test, web};
    use passman_crypto::HASH_SIZE;
    use sha2::{Digest, Sha512};
    use std::collections::HashMap;

    /// Replicates the frontend's `deriveUserKeys` function in Rust so that
    /// tests can compute the correct `auth_key` without a browser/WASM env.
    ///
    /// Steps (matching loginArea.ts):
    ///   1. saltAuth = SHA-512("auth:" + JSON.stringify(username))
    ///   2. authKey  = Argon2(password, saltAuth)   [64 bytes]
    ///   3. return base64url-no-padding(authKey)
    fn derive_client_auth_key(username: &str, password: &str) -> String {
        let json_username = serde_json::to_string(username).unwrap();
        let salt_auth = Sha512::digest(format!("auth:{json_username}").as_bytes());

        let params = Argon2Params::new().unwrap();
        let argon2 = params.make();
        let mut auth_key = [0u8; HASH_SIZE];
        argon2
            .hash_password_into(password.as_bytes(), &salt_auth, &mut auth_key)
            .expect("Argon2 key derivation failed");

        b64url_encode(&auth_key)
    }

    fn b64url_encode(bytes: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as usize;
            let b1 = if chunk.len() > 1 {
                chunk[1] as usize
            } else {
                0
            };
            let b2 = if chunk.len() > 2 {
                chunk[2] as usize
            } else {
                0
            };
            out.push(CHARS[b0 >> 2] as char);
            out.push(CHARS[((b0 & 3) << 4) | (b1 >> 4)] as char);
            if chunk.len() > 1 {
                out.push(CHARS[((b1 & 0xf) << 2) | (b2 >> 6)] as char);
            }
            if chunk.len() > 2 {
                out.push(CHARS[b2 & 0x3f] as char);
            }
        }
        out.replace('+', "-").replace('/', "_")
    }

    async fn make_test_app(tmpdir: &std::path::Path) -> web::Data<AppState> {
        make_test_app_with_policies(tmpdir, "{}").await
    }

    async fn make_test_app_with_policies(
        tmpdir: &std::path::Path,
        policies: &str,
    ) -> web::Data<AppState> {
        std::fs::create_dir_all(tmpdir.join("server_data")).unwrap();
        std::fs::write(tmpdir.join("policies.json"), policies).unwrap();

        let config = crate::config::ServerConfig {
            port: 8080,
            cors: false,
            debug: false,
            pretty_policies_json: None,
            server_access_password: "testpass".to_string(),
        };

        let (policies_and_config, _handle) = PolicyStorage::new(tmpdir, config).await.unwrap();

        web::Data::new(AppState {
            argon2_params: Argon2Params::new().unwrap(),
            policies_and_config,
            server_data_dir: tmpdir.join("server_data"),
            user_locks: RwLock::new(HashMap::new()),
            shared_vaults: SharedVaults::load(&tmpdir.join("server_data/.shared"))
                .await
                .unwrap(),
        })
    }

    /// Adds the credential headers the frontend sends.
    fn with_credentials(req: test::TestRequest, auth_key: &str) -> test::TestRequest {
        req.insert_header((routes::base::AUTH_KEY_HEADER, auth_key))
            .insert_header((routes::base::SERVER_PASS_HEADER, "testpass"))
    }

    macro_rules! init_app {
        ($state:expr) => {
            test::init_service(
                App::new()
                    .app_data($state.clone())
                    .service(routes::get_pass_table::route)
                    .service(routes::post_pass_table::route)
                    .service(routes::put_pass_table::route)
                    .service(routes::put_pass_table_new_pass::route)
                    .configure(routes::shared_vaults::configure),
            )
            .await
        };
    }

    /// Register a new user and then log in with the same credentials.
    /// This is the primary end-to-end regression test for the auth flow.
    #[actix_web::test]
    async fn e2e_register_then_login() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = make_test_app(tmpdir.path()).await;
        let app = init_app!(state);

        let username = "alice";
        let password = "hunter2";
        let auth_key = derive_client_auth_key(username, password);

        // --- Register ---
        // The body is a minimal dummy blob; the server stores it verbatim.
        let dummy_body = vec![0xffu8; 64];
        let uri = format!("/pass-table?username={username}");
        let req = with_credentials(test::TestRequest::post(), &auth_key)
            .uri(&uri)
            .insert_header(("Content-Type", "application/octet-stream"))
            .insert_header(("Content-Length", dummy_body.len().to_string()))
            .set_payload(dummy_body)
            .to_request();
        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(
            resp.status().as_u16(),
            201,
            "Registration failed with status {}",
            resp.status()
        );

        // --- Login ---
        let req = with_credentials(test::TestRequest::get(), &auth_key)
            .uri(&uri)
            .to_request();
        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(
            resp.status().as_u16(),
            200,
            "Login failed with status {}",
            resp.status()
        );
        // the stored blob comes back exactly, with a matching Content-Length
        assert_eq!(resp.headers().get("Content-Length").unwrap(), "64");
        assert_eq!(test::read_body(resp).await, vec![0xffu8; 64]);
    }

    /// A vault holds ciphertext plus the password hash, so it must not be
    /// readable by other local users whatever the umask is.
    #[actix_web::test]
    async fn registered_vault_file_is_private() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = make_test_app(tmpdir.path()).await;
        let app = init_app!(state);

        let auth_key = derive_client_auth_key("dave", "secret");
        let req = with_credentials(test::TestRequest::post(), &auth_key)
            .uri("/pass-table?username=dave")
            .insert_header(("Content-Length", "64"))
            .set_payload(vec![0u8; 64])
            .to_request();
        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 201);

        let mode = std::fs::metadata(tmpdir.path().join("server_data/dave"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// A password change must accept the `ETag` from a GET as its `If-Match`,
    /// and return a new `ETag` that the next save can use.
    #[actix_web::test]
    async fn change_password_then_save() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = make_test_app(tmpdir.path()).await;
        let app = init_app!(state);

        let old_key = derive_client_auth_key("frank", "old");
        let new_key = derive_client_auth_key("frank", "new");
        let uri = "/pass-table?username=frank";
        let req = with_credentials(test::TestRequest::post(), &old_key)
            .uri(uri)
            .insert_header(("Content-Length", "64"))
            .set_payload(vec![0u8; 64])
            .to_request();
        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 201);

        let req = with_credentials(test::TestRequest::get(), &old_key)
            .uri(uri)
            .to_request();
        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 200);
        let etag = resp.headers().get("ETag").unwrap().clone();
        // the body stream holds the user's read lock until it is consumed
        // (or the download times out)
        test::read_body(resp).await;

        let req = with_credentials(test::TestRequest::put(), &old_key)
            .uri("/pass-table-new-pass?username=frank")
            .insert_header((routes::base::NEW_AUTH_KEY_HEADER, new_key.as_str()))
            .insert_header(("If-Match", etag))
            .insert_header(("Content-Length", "64"))
            .set_payload(vec![1u8; 64])
            .to_request();
        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 200);
        let etag = resp.headers().get("ETag").unwrap().clone();

        let req = with_credentials(test::TestRequest::put(), &new_key)
            .uri(uri)
            .insert_header(("If-Match", etag))
            .insert_header(("Content-Length", "64"))
            .set_payload(vec![2u8; 64])
            .to_request();
        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 200);
        assert!(resp.headers().contains_key("ETag"));
    }

    /// A vault save for "gina" with the given `If-Match`.
    fn put_vault(auth_key: &str, if_match: Option<&header::HeaderValue>) -> test::TestRequest {
        let req = with_credentials(test::TestRequest::put(), auth_key)
            .uri("/pass-table?username=gina")
            .insert_header(("Content-Length", "64"))
            .set_payload(vec![3u8; 64]);
        match if_match {
            Some(etag) => req.insert_header(("If-Match", etag.clone())),
            None => req,
        }
    }

    /// Saves within the same second must get distinct ETags, so a client
    /// holding the older one is refused instead of overwriting the newer save.
    /// (Saves within one filesystem timestamp tick are covered by
    /// `finish_write_moves_mtime_past_previous`.)
    #[actix_web::test]
    async fn back_to_back_saves_get_distinct_etags() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = make_test_app(tmpdir.path()).await;
        let app = init_app!(state);

        let key = derive_client_auth_key("gina", "pw");
        let req = with_credentials(test::TestRequest::post(), &key)
            .uri("/pass-table?username=gina")
            .insert_header(("Content-Length", "64"))
            .set_payload(vec![0u8; 64])
            .to_request();
        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 201);
        let mut etag = resp.headers().get("ETag").unwrap().clone();

        let mut seen = vec![etag.clone()];
        for _ in 0..5 {
            let resp = test::call_service(&app, put_vault(&key, Some(&etag)).to_request()).await;
            assert_eq!(resp.status().as_u16(), 200);
            etag = resp.headers().get("ETag").unwrap().clone();
            assert!(!seen.contains(&etag), "ETag {etag:?} was reused");
            seen.push(etag.clone());
        }

        // a session still holding an older version is refused
        let resp = test::call_service(&app, put_vault(&key, Some(&seen[0])).to_request()).await;
        assert_eq!(resp.status().as_u16(), 412);
        // and a save without a version is refused too
        let resp = test::call_service(&app, put_vault(&key, None).to_request()).await;
        assert_eq!(resp.status().as_u16(), 428);
        // the current version still works
        let resp = test::call_service(&app, put_vault(&key, Some(&etag)).to_request()).await;
        assert_eq!(resp.status().as_u16(), 200);
    }

    /// A client that stops reading a download must block that user's saves
    /// only until the download times out (5s for a small vault), and must
    /// get an error rather than a silently truncated vault.
    #[actix_web::test]
    async fn stalled_download_times_out() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = make_test_app(tmpdir.path()).await;
        let app = init_app!(state);

        // larger than what the download hands over before blocking
        let vault_len = 64 * 1024;
        let key = derive_client_auth_key("hank", "pw");
        let req = with_credentials(test::TestRequest::post(), &key)
            .uri("/pass-table?username=hank")
            .insert_header(("Content-Length", vault_len.to_string()))
            .set_payload(vec![7u8; vault_len])
            .to_request();
        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 201);

        // start a download and never read it
        let req = with_credentials(test::TestRequest::get(), &key)
            .uri("/pass-table?username=hank")
            .to_request();
        let stalled: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(stalled.status().as_u16(), 200);
        let etag = stalled.headers().get("ETag").unwrap().clone();

        let started = std::time::Instant::now();
        let req = with_credentials(test::TestRequest::put(), &key)
            .uri("/pass-table?username=hank")
            .insert_header(("If-Match", etag))
            .insert_header(("Content-Length", "64"))
            .set_payload(vec![8u8; 64])
            .to_request();
        let resp: actix_web::dev::ServiceResponse = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            test::call_service(&app, req),
        )
        .await
        .expect("save still blocked by the stalled download");
        assert_eq!(resp.status().as_u16(), 200);
        // it did wait for the download's timeout
        assert!(started.elapsed() >= std::time::Duration::from_secs(4));

        assert!(test::try_read_body(stalled).await.is_err());
    }

    /// Registering the same username twice must return 409 Conflict.
    #[actix_web::test]
    async fn e2e_duplicate_register_is_conflict() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = make_test_app(tmpdir.path()).await;
        let app = init_app!(state);

        let auth_key = derive_client_auth_key("bob", "secret");
        let body = vec![0u8; 64];

        for expected_status in [201u16, 409] {
            let req = with_credentials(test::TestRequest::post(), &auth_key)
                .uri("/pass-table?username=bob")
                .insert_header(("Content-Type", "application/octet-stream"))
                .insert_header(("Content-Length", body.len().to_string()))
                .set_payload(body.clone())
                .to_request();
            let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
            assert_eq!(resp.status().as_u16(), expected_status);
        }
    }

    /// Credentials are only read from headers, never from the query string.
    #[actix_web::test]
    async fn credentials_in_query_are_not_accepted() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = make_test_app(tmpdir.path()).await;
        let app = init_app!(state);

        let auth_key = derive_client_auth_key("erin", "secret");
        let req = test::TestRequest::post()
            .uri(&format!(
                "/pass-table?username=erin&auth_key={auth_key}&server_pass=testpass"
            ))
            .insert_header(("Content-Length", "64"))
            .set_payload(vec![0u8; 64])
            .to_request();
        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 400);
        assert!(!tmpdir.path().join("server_data/erin").exists());
    }

    /// Logging in with a wrong password must return 400.
    #[actix_web::test]
    async fn e2e_wrong_password_is_rejected() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = make_test_app(tmpdir.path()).await;
        let app = init_app!(state);

        let right_key = derive_client_auth_key("carol", "rightpass");
        let wrong_key = derive_client_auth_key("carol", "wrongpass");

        // Register
        let req = with_credentials(test::TestRequest::post(), &right_key)
            .uri("/pass-table?username=carol")
            .insert_header(("Content-Type", "application/octet-stream"))
            .insert_header(("Content-Length", "64"))
            .set_payload(vec![0u8; 64])
            .to_request();
        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 201);

        // Login with wrong key
        let req = with_credentials(test::TestRequest::get(), &wrong_key)
            .uri("/pass-table?username=carol")
            .to_request();
        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 400);
    }

    // ── Shared vaults ────────────────────────────────────────────────────────

    use passman_crypto::sharing::{self, Member, RecordBody, VersionBody};
    use serde_json::json;

    /// A user registered on the test app with a published sharing identity.
    struct TestUser {
        name: &'static str,
        auth_key: String,
        /// `None` for the server access password, else this policy's
        /// namespace (whose password is "pw").
        server_ns: Option<&'static str>,
        secret: [u8; 32],
        bundle: Vec<u8>,
    }

    impl TestUser {
        fn new(name: &'static str, server_ns: Option<&'static str>) -> Self {
            let secret = sharing::generate_identity_secret();
            Self {
                name,
                auth_key: derive_client_auth_key(name, "pw"),
                server_ns,
                bundle: sharing::identity_bundle(&secret).unwrap(),
                secret,
            }
        }

        /// A request to `path` (with or without a query) as this user.
        fn req(&self, req: test::TestRequest, path: &str) -> test::TestRequest {
            let sep = if path.contains('?') { '&' } else { '?' };
            let mut uri = format!("{path}{sep}username={}", self.name);
            let server_pass = match self.server_ns {
                Some(ns) => {
                    uri.push_str(&format!("&server_ns={ns}"));
                    "pw"
                }
                None => "testpass",
            };
            req.uri(&uri)
                .insert_header((routes::base::AUTH_KEY_HEADER, self.auth_key.as_str()))
                .insert_header((routes::base::SERVER_PASS_HEADER, server_pass))
        }

        fn member(&self, write: bool, manage: bool) -> Member {
            Member {
                username: self.name.to_string(),
                fingerprint: sharing::b64_encode(&sharing::fingerprint(&self.bundle)),
                write,
                manage,
            }
        }
    }

    const VAULT_ID: &str = "0123456789abcdef0123456789abcdef";

    /// A signed record of `members` following `prev`.
    fn make_record(
        prev: Option<&[u8]>,
        author: &TestUser,
        members: &[(&TestUser, bool, bool)],
    ) -> Vec<u8> {
        let seq = prev.map_or(0, |p| sharing::parse_record(p).unwrap().seq + 1);
        let epoch_secret = sharing::generate_epoch_secret();
        let body = RecordBody {
            v: 1,
            vault_id: VAULT_ID.to_string(),
            seq,
            prev: prev.map(sharing::record_hash),
            author: author.name.to_string(),
            time: 0,
            members: members.iter().map(|(u, w, m)| u.member(*w, *m)).collect(),
            keys: members
                .iter()
                .map(|(u, ..)| {
                    let ctx = sharing::epoch_key_context(VAULT_ID, seq, u.name);
                    let wrapped = sharing::wrap_key(&u.bundle, &epoch_secret, &ctx).unwrap();
                    (u.name.to_string(), sharing::b64_encode(&wrapped))
                })
                .collect(),
        };
        sharing::sign_record(&author.secret, &body).unwrap()
    }

    /// A signed version whose (stand-in) ciphertexts are `len` bytes.
    fn make_version(
        author: &TestUser,
        epoch: u64,
        version: u64,
        rekey: bool,
        len: usize,
    ) -> Vec<u8> {
        let tables = vec![7u8; len];
        let history = b"history".to_vec();
        let hash = |d: &[u8]| {
            use sha2::Digest;
            sharing::b64_encode(&sha2::Sha256::digest(d))
        };
        let body = VersionBody {
            v: 1,
            vault_id: VAULT_ID.to_string(),
            epoch,
            version,
            author: author.name.to_string(),
            time: 0,
            tables_hash: hash(&tables),
            history_hash: hash(&history),
            rekey,
        };
        sharing::sign_version(&author.secret, &body, &tables, &history).unwrap()
    }

    fn frames(parts: &[&[u8]]) -> Vec<u8> {
        sharing::encode_frames(parts)
    }

    macro_rules! call {
        ($app:expr, $req:expr) => {{
            let resp: actix_web::dev::ServiceResponse =
                test::call_service(&$app, $req.to_request()).await;
            resp
        }};
    }

    /// Calls and returns the status and the JSON body (`null` if none).
    macro_rules! call_json {
        ($app:expr, $req:expr) => {{
            let resp = call!($app, $req);
            let status = resp.status().as_u16();
            let body = test::read_body(resp).await;
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            (status, json)
        }};
    }

    /// Registers the users and publishes their identities.
    macro_rules! setup_users {
        ($app:expr, $($user:expr),+) => {{
            for user in [$(&$user),+] {
                let req = user
                    .req(test::TestRequest::post(), "/pass-table")
                    .insert_header(("Content-Length", "64"))
                    .set_payload(vec![0u8; 64]);
                assert_eq!(call!($app, req).status().as_u16(), 201);
                let req = user
                    .req(test::TestRequest::put(), "/identity")
                    .set_json(json!({ "bundle": sharing::b64_encode(&user.bundle) }));
                assert_eq!(call!($app, req).status().as_u16(), 200);
            }
        }};
    }

    macro_rules! post_frames {
        ($app:expr, $user:expr, $path:expr, $body:expr, $etag:expr) => {{
            let body: Vec<u8> = $body;
            let mut req = $user
                .req(test::TestRequest::post(), $path)
                .insert_header(("Content-Length", body.len().to_string()))
                .set_payload(body);
            let etag: Option<&str> = $etag;
            if let Some(etag) = etag {
                req = req.insert_header(("If-Match", etag));
            }
            call_json!($app, req)
        }};
    }

    macro_rules! put_version {
        ($app:expr, $user:expr, $version:expr, $etag:expr) => {{
            let body: Vec<u8> = $version;
            let req = $user
                .req(
                    test::TestRequest::put(),
                    &format!("/shared-vaults/{VAULT_ID}/version"),
                )
                .insert_header(("If-Match", $etag))
                .insert_header(("Content-Length", body.len().to_string()))
                .set_payload(body);
            call_json!($app, req)
        }};
    }

    const ETAG_0_1: &str = "\"0-1\"";

    /// Managers change the member list, writers save, and everyone sees only
    /// the epochs they were in.
    #[actix_web::test]
    async fn shared_vault_lifecycle() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = make_test_app(tmpdir.path()).await;
        let app = init_app!(state);
        let alice = TestUser::new("alice", None);
        let bob = TestUser::new("bob", None);
        let carol = TestUser::new("carol", None);
        setup_users!(app, alice, bob, carol);
        let vault = format!("/shared-vaults/{VAULT_ID}");

        let r0 = make_record(None, &alice, &[(&alice, true, true)]);
        // a record claiming another author is refused
        let (status, body) = post_frames!(
            app,
            bob,
            "/shared-vaults",
            frames(&[&r0, &make_version(&alice, 0, 1, false, 10)]),
            None
        );
        assert_eq!((status, body["type"].as_str()), (400, Some("E_INVALID")));
        let (status, _) = post_frames!(
            app,
            alice,
            "/shared-vaults",
            frames(&[&r0, &make_version(&alice, 0, 1, false, 10)]),
            None
        );
        assert_eq!(status, 201);

        let (_, list) = call_json!(app, bob.req(test::TestRequest::get(), "/shared-vaults"));
        assert_eq!(list["vaults"], json!([]));
        let resp = call!(
            app,
            bob.req(test::TestRequest::get(), &format!("{vault}/version"))
        );
        assert_eq!(resp.status().as_u16(), 404);

        // alice adds bob (who can write) and carol (who can only read)
        let r1 = make_record(
            Some(&r0),
            &alice,
            &[
                (&alice, true, true),
                (&bob, true, false),
                (&carol, false, false),
            ],
        );
        let (status, _) = post_frames!(
            app,
            alice,
            &format!("{vault}/records"),
            frames(&[&r1, &make_version(&alice, 1, 2, true, 10)]),
            Some(ETAG_0_1)
        );
        assert_eq!(status, 200);

        let (_, list) = call_json!(app, bob.req(test::TestRequest::get(), "/shared-vaults"));
        assert_eq!(list["vaults"][0]["seq"], 1);
        assert_eq!(list["vaults"][0]["etag"], "\"1-2\"");
        assert_eq!(list["vaults"][0]["archives"], json!([0]));
        let (_, records) = call_json!(
            app,
            bob.req(test::TestRequest::get(), &format!("{vault}/records"))
        );
        assert_eq!(records["records"].as_array().unwrap().len(), 2);

        // bob saves; carol can't, nor can a version of the old epoch be saved
        let (status, _) = put_version!(app, bob, make_version(&bob, 1, 3, false, 20), "\"1-2\"");
        assert_eq!(status, 200);
        let (status, _) =
            put_version!(app, carol, make_version(&carol, 1, 4, false, 20), "\"1-3\"");
        assert_eq!(status, 403);
        let (status, body) =
            put_version!(app, alice, make_version(&alice, 0, 4, false, 20), "\"1-3\"");
        assert_eq!(
            (status, body["type"].as_str()),
            (409, Some("E_EPOCH_CHANGED"))
        );
        // a stale ETag is refused
        let (status, _) = put_version!(app, bob, make_version(&bob, 1, 4, false, 20), "\"1-2\"");
        assert_eq!(status, 412);
        let resp = call!(
            app,
            carol.req(test::TestRequest::get(), &format!("{vault}/version"))
        );
        assert_eq!(resp.headers().get("ETag").unwrap(), "\"1-3\"");
        let version = test::read_body(resp).await;
        let record = sharing::parse_record(&r1).unwrap();
        assert_eq!(
            sharing::verify_version(&record, &version, &bob.bundle)
                .unwrap()
                .version,
            3
        );

        // only members of epoch 0 can read its history
        let archive0 = format!("{vault}/archive/0");
        let resp = call!(app, bob.req(test::TestRequest::get(), &archive0));
        assert_eq!(resp.status().as_u16(), 404);
        let resp = call!(app, alice.req(test::TestRequest::get(), &archive0));
        let archive = test::read_body(resp).await;
        sharing::verify_archive(
            &sharing::parse_record(&r0).unwrap(),
            &archive,
            &alice.bundle,
        )
        .unwrap();

        // bob can't manage members
        let r2 = make_record(Some(&r1), &bob, &[(&alice, true, true), (&bob, true, true)]);
        let (status, _) = post_frames!(
            app,
            bob,
            &format!("{vault}/records"),
            frames(&[&r2, &make_version(&bob, 2, 4, true, 10)]),
            Some("\"1-3\"")
        );
        assert_eq!(status, 400);

        // carol leaves: she loses access at once, and the next record must
        // remove her
        let resp = call!(
            app,
            carol.req(test::TestRequest::post(), &format!("{vault}/leave"))
        );
        assert_eq!(resp.status().as_u16(), 200);
        let resp = call!(
            app,
            carol.req(test::TestRequest::get(), &format!("{vault}/version"))
        );
        assert_eq!(resp.status().as_u16(), 404);
        let (_, list) = call_json!(app, alice.req(test::TestRequest::get(), "/shared-vaults"));
        assert_eq!(list["vaults"][0]["leaving"], json!(["carol"]));
        let r2 = make_record(
            Some(&r1),
            &alice,
            &[
                (&alice, true, true),
                (&bob, true, false),
                (&carol, false, false),
            ],
        );
        let (status, body) = post_frames!(
            app,
            alice,
            &format!("{vault}/records"),
            frames(&[&r2, &make_version(&alice, 2, 4, true, 10)]),
            Some("\"1-3\"")
        );
        assert_eq!(
            (status, body["type"].as_str()),
            (409, Some("E_MEMBER_LEAVING"))
        );
        let r2 = make_record(
            Some(&r1),
            &alice,
            &[(&alice, true, true), (&bob, true, false)],
        );
        let (status, _) = post_frames!(
            app,
            alice,
            &format!("{vault}/records"),
            frames(&[&r2, &make_version(&alice, 2, 4, true, 10)]),
            Some("\"1-3\"")
        );
        assert_eq!(status, 200);

        // the last manager can't leave, and only managers can delete
        let (status, body) = call_json!(
            app,
            alice.req(test::TestRequest::post(), &format!("{vault}/leave"))
        );
        assert_eq!(
            (status, body["type"].as_str()),
            (409, Some("E_LAST_MANAGER"))
        );
        let resp = call!(app, bob.req(test::TestRequest::delete(), &vault));
        assert_eq!(resp.status().as_u16(), 403);

        // the vault survives a restart, and deleting it removes its files
        let state2 = make_test_app(tmpdir.path()).await;
        {
            let vaults = state2.shared_vaults.vaults.read().await;
            let reloaded = vaults[VAULT_ID].read().await;
            assert_eq!((reloaded.record.seq, reloaded.version.version), (2, 4));
            assert_eq!(
                reloaded.archives.keys().copied().collect::<Vec<_>>(),
                [0, 1]
            );
        }
        let resp = call!(app, alice.req(test::TestRequest::delete(), &vault));
        assert_eq!(resp.status().as_u16(), 200);
        let vaults_dir = tmpdir.path().join("server_data/.shared/vaults");
        assert_eq!(std::fs::read_dir(vaults_dir).unwrap().count(), 0);
    }

    /// An identity can be replaced until a vault pins its fingerprint, and a
    /// member must be added with their current identity.
    #[actix_web::test]
    async fn identities_are_pinned_by_vaults() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = make_test_app(tmpdir.path()).await;
        let app = init_app!(state);
        let alice = TestUser::new("alice", None);
        let mut bob = TestUser::new("bob", None);
        setup_users!(app, alice, bob);

        // bob replaces his identity; a record with the old one is refused
        let old_bob = TestUser::new("bob", None);
        let old_bob = TestUser {
            secret: bob.secret,
            bundle: bob.bundle.clone(),
            ..old_bob
        };
        bob.secret = sharing::generate_identity_secret();
        bob.bundle = sharing::identity_bundle(&bob.secret).unwrap();
        let req = bob
            .req(test::TestRequest::put(), "/identity")
            .set_json(json!({ "bundle": sharing::b64_encode(&bob.bundle) }));
        assert_eq!(call!(app, req).status().as_u16(), 200);
        let r0 = make_record(
            None,
            &alice,
            &[(&alice, true, true), (&old_bob, true, false)],
        );
        let (status, body) = post_frames!(
            app,
            alice,
            "/shared-vaults",
            frames(&[&r0, &make_version(&alice, 0, 1, false, 10)]),
            None
        );
        assert_eq!(
            (status, body["type"].as_str()),
            (409, Some("E_IDENTITY_CHANGED"))
        );

        let r0 = make_record(None, &alice, &[(&alice, true, true), (&bob, true, false)]);
        let (status, _) = post_frames!(
            app,
            alice,
            "/shared-vaults",
            frames(&[&r0, &make_version(&alice, 0, 1, false, 10)]),
            None
        );
        assert_eq!(status, 201);
        // now bob's identity is in use
        let req = bob
            .req(test::TestRequest::put(), "/identity")
            .set_json(json!({ "bundle": sharing::b64_encode(&old_bob.bundle) }));
        let (status, body) = call_json!(app, req);
        assert_eq!(
            (status, body["type"].as_str()),
            (409, Some("E_IDENTITY_IN_USE"))
        );

        let (status, body) = call_json!(
            app,
            alice.req(test::TestRequest::get(), "/identity?user=nobody")
        );
        assert_eq!(
            (status, body["type"].as_str()),
            (404, Some("E_NO_IDENTITY"))
        );
        let (status, body) = call_json!(
            app,
            alice.req(test::TestRequest::get(), "/identity?user=bob")
        );
        assert_eq!(status, 200);
        assert_eq!(body["bundle"], sharing::b64_encode(&bob.bundle));
        // bob's replaced identity can still be found by its fingerprint
        let hex: String = sharing::fingerprint(&old_bob.bundle)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let (status, body) = call_json!(
            app,
            alice.req(
                test::TestRequest::get(),
                &format!("/identity?fingerprint={hex}")
            )
        );
        assert_eq!(status, 200);
        assert_eq!(body["bundle"], sharing::b64_encode(&old_bob.bundle));
    }

    /// A limited policy caps how many shared vaults are created under it, and
    /// their size and members, separately from its accounts.
    #[actix_web::test]
    async fn shared_vault_policy_limits() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = make_test_app_with_policies(
            tmpdir.path(),
            r#"{
                "team": {"Password":"pw","PolicyType":"LIMITED_POLICY","MaxAccounts":4,"NumAccounts":0,"MaxDataSize":100000,
                         "MaxSharedVaults":1,"MaxSharedVaultDataSize":20000,"MaxSharedVaultMembers":2},
                "old": {"Password":"pw","PolicyType":"LIMITED_POLICY","MaxAccounts":4,"NumAccounts":0,"MaxDataSize":100000}
            }"#,
        )
        .await;
        let app = init_app!(state);
        let alice = TestUser::new("alice", Some("team"));
        let bob = TestUser::new("bob", Some("team"));
        let carol = TestUser::new("carol", Some("team"));
        let dave = TestUser::new("dave", Some("old"));
        setup_users!(app, alice, bob, carol, dave);
        let r0 = make_record(None, &alice, &[(&alice, true, true)]);
        let create = |user: &TestUser, record: &[u8], len: usize| {
            let body = frames(&[record, &make_version(user, 0, 1, false, len)]);
            user.req(test::TestRequest::post(), "/shared-vaults")
                .insert_header(("Content-Length", body.len().to_string()))
                .set_payload(body)
        };

        // policies without the shared vault fields don't allow any
        let d0 = make_record(None, &dave, &[(&dave, true, true)]);
        let (status, body) = call_json!(app, create(&dave, &d0, 10));
        assert_eq!((status, body["type"].as_str()), (400, Some("E_POLICY")));
        // the vault's own size limit applies, not the account one
        let (status, body) = call_json!(app, create(&alice, &r0, 30000));
        assert_eq!((status, body["type"].as_str()), (400, Some("E_POLICY")));
        let (status, _) = call_json!(app, create(&alice, &r0, 10));
        assert_eq!(status, 201);
        // only one vault under this policy (the failed attempts gave theirs back)
        let b0 = make_record(None, &bob, &[(&bob, true, true)]);
        let (status, body) = call_json!(app, create(&bob, &b0, 10));
        assert_eq!((status, body["type"].as_str()), (400, Some("E_POLICY")));

        let (_, list) = call_json!(app, alice.req(test::TestRequest::get(), "/shared-vaults"));
        assert_eq!(list["vaults"][0]["maxDataSize"], 20000);
        assert_eq!(list["vaults"][0]["maxMembers"], 2);

        // at most 2 members
        let vault = format!("/shared-vaults/{VAULT_ID}");
        let r1 = make_record(
            Some(&r0),
            &alice,
            &[
                (&alice, true, true),
                (&bob, true, false),
                (&carol, true, false),
            ],
        );
        let (status, body) = post_frames!(
            app,
            alice,
            &format!("{vault}/records"),
            frames(&[&r1, &make_version(&alice, 1, 2, true, 10)]),
            Some(ETAG_0_1)
        );
        assert_eq!((status, body["type"].as_str()), (400, Some("E_POLICY")));
        // members using other credentials still get the vault's limits
        let r1 = make_record(
            Some(&r0),
            &alice,
            &[(&alice, true, true), (&dave, true, false)],
        );
        let (status, _) = post_frames!(
            app,
            alice,
            &format!("{vault}/records"),
            frames(&[&r1, &make_version(&alice, 1, 2, true, 10)]),
            Some(ETAG_0_1)
        );
        assert_eq!(status, 200);
        let (status, body) = put_version!(
            app,
            dave,
            make_version(&dave, 1, 3, false, 30000),
            "\"1-2\""
        );
        assert_eq!((status, body["type"].as_str()), (400, Some("E_POLICY")));
        let (status, _) = put_version!(app, dave, make_version(&dave, 1, 3, false, 100), "\"1-2\"");
        assert_eq!(status, 200);

        // deleting the vault gives the policy its count back
        let resp = call!(app, alice.req(test::TestRequest::delete(), &vault));
        assert_eq!(resp.status().as_u16(), 200);
        let (status, _) = call_json!(app, create(&bob, &b0, 10));
        assert_eq!(status, 201);
    }

    /// A crash while starting an epoch is finished (if its first version was
    /// saved) or undone (if only the record was) on the next start.
    #[actix_web::test]
    async fn interrupted_epoch_change_is_recovered() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = make_test_app(tmpdir.path()).await;
        let app = init_app!(state);
        let alice = TestUser::new("alice", None);
        setup_users!(app, alice);
        let r0 = make_record(None, &alice, &[(&alice, true, true)]);
        let (status, _) = post_frames!(
            app,
            alice,
            "/shared-vaults",
            frames(&[&r0, &make_version(&alice, 0, 1, false, 10)]),
            None
        );
        assert_eq!(status, 201);
        let dir = tmpdir
            .path()
            .join(format!("server_data/.shared/vaults/{VAULT_ID}"));
        let r1 = make_record(Some(&r0), &alice, &[(&alice, true, true)]);

        // only the record was saved
        std::fs::write(dir.join("records/1"), &r1).unwrap();
        let reloaded = make_test_app(tmpdir.path()).await;
        {
            let vaults = reloaded.shared_vaults.vaults.read().await;
            assert_eq!(vaults[VAULT_ID].read().await.record.seq, 0);
        }
        assert!(!dir.join("records/1").exists());

        // the record and the epoch's first version were saved
        std::fs::write(dir.join("records/1"), &r1).unwrap();
        std::fs::write(dir.join("next"), make_version(&alice, 1, 2, true, 10)).unwrap();
        let reloaded = make_test_app(tmpdir.path()).await;
        let vaults = reloaded.shared_vaults.vaults.read().await;
        let vault = vaults[VAULT_ID].read().await;
        assert_eq!((vault.record.seq, vault.version.version), (1, 2));
        assert!(vault.archives.contains_key(&0));
        assert!(!dir.join("next").exists());
    }
}

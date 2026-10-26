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

    /// A user registered on the test app, with the credentials to act as them.
    struct TestUser {
        name: &'static str,
        auth_key: String,
        /// `None` for the server access password, else this policy's
        /// namespace (whose password is "pw").
        server_ns: Option<&'static str>,
    }

    impl TestUser {
        fn new(name: &'static str, server_ns: Option<&'static str>) -> Self {
            Self {
                name,
                auth_key: derive_client_auth_key(name, "pw"),
                server_ns,
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
    }

    /// Base64 of `len` copies of `byte`, standing in for keys and ciphertext.
    fn fake_b64(byte: u8, len: usize) -> String {
        b64url_encode(&vec![byte; len])
    }

    macro_rules! call {
        ($app:expr, $req:expr) => {{
            let resp: actix_web::dev::ServiceResponse =
                test::call_service(&$app, $req.to_request()).await;
            resp
        }};
    }

    /// Calls and returns the status and JSON body.
    macro_rules! call_json {
        ($app:expr, $req:expr) => {{
            let resp = call!($app, $req);
            let status = resp.status().as_u16();
            let body = test::read_body(resp).await;
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            (status, json)
        }};
    }

    /// Registers the users and publishes a sharing key for each (their key
    /// is 32 copies of their index + 1).
    macro_rules! setup_users {
        ($app:expr, $($user:expr),+) => {{
            for (i, user) in [$(&$user),+].into_iter().enumerate() {
                let req = user
                    .req(test::TestRequest::post(), "/pass-table")
                    .insert_header(("Content-Length", "64"))
                    .set_payload(vec![0u8; 64]);
                assert_eq!(call!($app, req).status().as_u16(), 201);
                let req = user
                    .req(test::TestRequest::put(), "/sharing-key")
                    .set_json(json!({ "publicKey": fake_b64(i as u8 + 1, 32) }));
                assert_eq!(call!($app, req).status().as_u16(), 200);
            }
        }};
    }

    macro_rules! create_vault {
        ($app:expr, $user:expr, $key_byte:expr) => {{
            let req = $user
                .req(test::TestRequest::post(), "/shared-vaults")
                .set_json(json!({
                    "encryptedName": fake_b64(9, 40),
                    "wrappedKey": fake_b64(7, 80),
                    "publicKey": fake_b64($key_byte, 32),
                }));
            call_json!($app, req)
        }};
    }

    use serde_json::json;

    /// Owners add members, members read and save, and non-members can't tell
    /// the vault exists.
    #[actix_web::test]
    async fn shared_vault_membership() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = make_test_app(tmpdir.path()).await;
        let app = init_app!(state);
        let alice = TestUser::new("alice", None);
        let bob = TestUser::new("bob", None);
        setup_users!(app, alice, bob);

        let (status, body) = create_vault!(app, alice, 1);
        assert_eq!(status, 201);
        let id = body["id"].as_str().unwrap().to_string();
        let data = format!("/shared-vaults/{id}/data");

        let (_, list) = call_json!(app, alice.req(test::TestRequest::get(), "/shared-vaults"));
        assert_eq!(list["vaults"][0]["id"], id.as_str());
        assert_eq!(list["vaults"][0]["role"], "Owner");
        assert_eq!(list["vaults"][0]["size"], 0);
        let (_, list) = call_json!(app, bob.req(test::TestRequest::get(), "/shared-vaults"));
        assert_eq!(list["vaults"], json!([]));
        let resp = call!(app, bob.req(test::TestRequest::get(), &data));
        assert_eq!(resp.status().as_u16(), 404);

        // the member's sharing key must be the one the vault key was sealed to
        let member = format!("/shared-vaults/{id}/members/bob");
        let add = |public_key: String| {
            alice
                .req(test::TestRequest::put(), &member)
                .set_json(json!({
                    "role": "Editor",
                    "wrappedKey": fake_b64(8, 80),
                    "publicKey": public_key,
                }))
        };
        let (status, body) = call_json!(app, add(fake_b64(1, 32)));
        assert_eq!(
            (status, body["type"].as_str()),
            (409, Some("E_SHARING_KEY_CHANGED"))
        );
        assert_eq!(call!(app, add(fake_b64(2, 32))).status().as_u16(), 200);

        let (_, list) = call_json!(app, bob.req(test::TestRequest::get(), "/shared-vaults"));
        assert_eq!(list["vaults"][0]["role"], "Editor");
        assert_eq!(list["vaults"][0]["wrappedKey"], fake_b64(8, 80));
        assert_eq!(list["vaults"][0]["members"].as_array().unwrap().len(), 2);

        // bob saves, alice reads it back
        let resp = call!(app, bob.req(test::TestRequest::get(), &data));
        let etag = resp.headers().get("ETag").unwrap().clone();
        assert!(test::read_body(resp).await.is_empty());
        let req = bob
            .req(test::TestRequest::put(), &data)
            .insert_header(("If-Match", etag.clone()))
            .insert_header(("Content-Length", "5"))
            .set_payload(b"hello".to_vec());
        assert_eq!(call!(app, req).status().as_u16(), 200);
        let resp = call!(app, alice.req(test::TestRequest::get(), &data));
        assert_eq!(test::read_body(resp).await, b"hello".to_vec());
        // a save based on the old version is refused
        let req = alice
            .req(test::TestRequest::put(), &data)
            .insert_header(("If-Match", etag))
            .insert_header(("Content-Length", "3"))
            .set_payload(b"old".to_vec());
        assert_eq!(call!(app, req).status().as_u16(), 412);

        // only owners manage the vault
        let resp = call!(
            app,
            bob.req(test::TestRequest::delete(), &format!("/shared-vaults/{id}"))
        );
        assert_eq!(resp.status().as_u16(), 403);
        let resp = call!(
            app,
            bob.req(
                test::TestRequest::delete(),
                &format!("/shared-vaults/{id}/members/alice")
            )
        );
        assert_eq!(resp.status().as_u16(), 403);
        // and the last owner can't leave
        let (status, body) = call_json!(
            app,
            alice.req(
                test::TestRequest::delete(),
                &format!("/shared-vaults/{id}/members/alice")
            )
        );
        assert_eq!((status, body["type"].as_str()), (409, Some("E_LAST_OWNER")));
        let (status, body) = call_json!(
            app,
            alice
                .req(
                    test::TestRequest::put(),
                    &format!("/shared-vaults/{id}/members/alice")
                )
                .set_json(json!({ "role": "Editor" }))
        );
        assert_eq!((status, body["type"].as_str()), (409, Some("E_LAST_OWNER")));

        // a removed member loses access
        assert_eq!(
            call!(app, alice.req(test::TestRequest::delete(), &member))
                .status()
                .as_u16(),
            200
        );
        let resp = call!(app, bob.req(test::TestRequest::get(), &data));
        assert_eq!(resp.status().as_u16(), 404);

        // deleting removes the files; the vault survives a restart until then
        let state2 = make_test_app_with_policies(tmpdir.path(), "{}").await;
        assert!(state2.shared_vaults.vaults.read().await.contains_key(&id));
        let resp = call!(
            app,
            alice.req(test::TestRequest::delete(), &format!("/shared-vaults/{id}"))
        );
        assert_eq!(resp.status().as_u16(), 200);
        let vaults_dir = tmpdir.path().join("server_data/.shared/vaults");
        assert_eq!(std::fs::read_dir(vaults_dir).unwrap().count(), 0);
    }

    /// A sharing key can be replaced until vault keys have been sealed to it.
    #[actix_web::test]
    async fn sharing_key_is_fixed_once_in_use() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = make_test_app(tmpdir.path()).await;
        let app = init_app!(state);
        let alice = TestUser::new("alice", None);
        setup_users!(app, alice);
        let put_key = |byte: u8| {
            alice
                .req(test::TestRequest::put(), "/sharing-key")
                .set_json(json!({ "publicKey": fake_b64(byte, 32) }))
        };
        assert_eq!(call!(app, put_key(5)).status().as_u16(), 200);
        let (status, _) = create_vault!(app, alice, 5);
        assert_eq!(status, 201);
        let (status, body) = call_json!(app, put_key(6));
        assert_eq!(
            (status, body["type"].as_str()),
            (409, Some("E_SHARING_KEY_IN_USE"))
        );
        // publishing the same key again is fine
        assert_eq!(call!(app, put_key(5)).status().as_u16(), 200);
        // keys must be 32 bytes
        let req = alice
            .req(test::TestRequest::put(), "/sharing-key")
            .set_json(json!({ "publicKey": fake_b64(5, 31) }));
        assert_eq!(call!(app, req).status().as_u16(), 400);

        let (status, body) = call_json!(
            app,
            alice.req(test::TestRequest::get(), "/sharing-key?user=nobody")
        );
        assert_eq!(
            (status, body["type"].as_str()),
            (404, Some("E_NO_SHARING_KEY"))
        );
        let (status, body) = call_json!(app, alice.req(test::TestRequest::get(), "/sharing-key"));
        assert_eq!(
            (status, body["publicKey"].clone()),
            (200, json!(fake_b64(5, 32)))
        );
    }

    /// A limited policy caps how many shared vaults are created under it, and
    /// their size and members, separately from its accounts.
    #[actix_web::test]
    async fn shared_vault_policy_limits() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = make_test_app_with_policies(
            tmpdir.path(),
            r#"{
                "team": {"Password":"pw","PolicyType":"LIMITED_POLICY","MaxAccounts":3,"NumAccounts":0,"MaxDataSize":1000,
                         "MaxSharedVaults":1,"MaxSharedVaultDataSize":10,"MaxSharedVaultMembers":2},
                "old": {"Password":"pw","PolicyType":"LIMITED_POLICY","MaxAccounts":3,"NumAccounts":0,"MaxDataSize":1000}
            }"#,
        )
        .await;
        let app = init_app!(state);
        let alice = TestUser::new("alice", Some("team"));
        let bob = TestUser::new("bob", Some("team"));
        let carol = TestUser::new("carol", Some("team"));
        let dave = TestUser::new("dave", Some("old"));
        setup_users!(app, alice, bob, carol, dave);

        // policies without the shared vault fields don't allow any
        let (status, body) = create_vault!(app, dave, 4);
        assert_eq!((status, body["type"].as_str()), (400, Some("E_POLICY")));

        let (status, body) = create_vault!(app, alice, 1);
        assert_eq!(status, 201);
        let id = body["id"].as_str().unwrap().to_string();
        let (status, body) = create_vault!(app, bob, 2);
        assert_eq!((status, body["type"].as_str()), (400, Some("E_POLICY")));

        let (_, list) = call_json!(app, alice.req(test::TestRequest::get(), "/shared-vaults"));
        assert_eq!(list["vaults"][0]["maxDataSize"], 10);
        assert_eq!(list["vaults"][0]["maxMembers"], 2);

        // the vault's own limit applies, not the account limit (1000)
        let data = format!("/shared-vaults/{id}/data");
        let resp = call!(app, alice.req(test::TestRequest::get(), &data));
        let etag = resp.headers().get("ETag").unwrap().clone();
        test::read_body(resp).await;
        let save = |len: usize| {
            alice
                .req(test::TestRequest::put(), &data)
                .insert_header(("If-Match", etag.clone()))
                .insert_header(("Content-Length", len.to_string()))
                .set_payload(vec![1u8; len])
        };
        let (status, body) = call_json!(app, save(11));
        assert_eq!((status, body["type"].as_str()), (400, Some("E_POLICY")));
        assert_eq!(call!(app, save(10)).status().as_u16(), 200);

        // and its member limit
        let add = |name: &str, key_byte: u8| {
            alice
                .req(
                    test::TestRequest::put(),
                    &format!("/shared-vaults/{id}/members/{name}"),
                )
                .set_json(json!({
                    "role": "Editor",
                    "wrappedKey": fake_b64(8, 80),
                    "publicKey": fake_b64(key_byte, 32),
                }))
        };
        assert_eq!(call!(app, add("bob", 2)).status().as_u16(), 200);
        let (status, body) = call_json!(app, add("carol", 3));
        assert_eq!((status, body["type"].as_str()), (400, Some("E_POLICY")));
        // members using other credentials still get the vault's limits:
        // dave's policy has none of its own
        assert_eq!(
            call!(
                app,
                alice.req(
                    test::TestRequest::delete(),
                    &format!("/shared-vaults/{id}/members/bob")
                )
            )
            .status()
            .as_u16(),
            200
        );
        assert_eq!(call!(app, add("dave", 4)).status().as_u16(), 200);
        let resp = call!(app, dave.req(test::TestRequest::get(), &data));
        let etag = resp.headers().get("ETag").unwrap().clone();
        test::read_body(resp).await;
        let req = dave
            .req(test::TestRequest::put(), &data)
            .insert_header(("If-Match", etag))
            .insert_header(("Content-Length", "11"))
            .set_payload(vec![1u8; 11]);
        assert_eq!(call!(app, req).status().as_u16(), 400);

        // deleting the vault gives the policy its count back
        let resp = call!(
            app,
            alice.req(test::TestRequest::delete(), &format!("/shared-vaults/{id}"))
        );
        assert_eq!(resp.status().as_u16(), 200);
        let (status, _) = create_vault!(app, bob, 2);
        assert_eq!(status, 201);
    }
}

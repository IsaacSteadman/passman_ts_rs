use crate::{
    rate_limit::RateLimiter,
    routes::{
        base::AppState, frontend::FrontendMode, get_pass_table, post_pass_table, put_pass_table,
        put_pass_table_new_pass,
    },
    server_policy::PolicyStorage,
    shared_vaults::SharedVaults,
};
use actix_web::{
    App, HttpServer,
    http::header::{REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS},
    middleware::{self, DefaultHeaders},
    web,
};
use std::{
    collections::HashMap,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::sync::Semaphore;

mod config;
mod rate_limit;
mod routes;
mod server_policy;
mod shared_vaults;

/// Builds the server's state from its config and the data in `base_dir`.
async fn app_state(
    base_dir: &std::path::Path,
    config: crate::config::ServerConfig,
) -> anyhow::Result<(
    web::Data<AppState>,
    Arc<PolicyStorage>,
    tokio::task::JoinHandle<()>,
)> {
    let rate_limiter = Arc::new(RateLimiter::new(config.rate_limit.clone()));
    let upload_kib = (config.max_buffered_upload_bytes / 1024).max(1) as usize;
    let (policies_and_config, join_handle) = PolicyStorage::new(base_dir, config).await?;
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
    let state = web::Data::new(AppState {
        policies_and_config: policies_and_config.clone(),
        server_data_dir,
        user_locks: Mutex::new(HashMap::new()),
        shared_vaults,
        rate_limiter,
        upload_budget: Arc::new(Semaphore::new(upload_kib.min(Semaphore::MAX_PERMITS))),
    });
    Ok((state, policies_and_config, join_handle))
}

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
    let port = config.listen_port()?;
    if !config.rate_limit.enabled {
        println!("Rate limiting is off (RateLimit.Enabled in config.json)");
    }
    let (app_state, policy_storage, join_handle) = app_state(&base_dir, config).await?;
    let frontend_mode = web::Data::new(if let Ok(url) = std::env::var("FRONTEND_DEV_SERVER") {
        println!("Proxying frontend requests to {url}");
        FrontendMode::DevProxy(url)
    } else {
        let dist = base_dir.join("dist");
        println!("Serving static frontend from {dist:?}");
        FrontendMode::StaticFiles(dist)
    });
    println!("Listening on 127.0.0.1:{port}");
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .app_data(frontend_mode.clone())
            .wrap(middleware::from_fn(rate_limit::middleware))
            .wrap(
                DefaultHeaders::new()
                    .add((X_CONTENT_TYPE_OPTIONS, "nosniff"))
                    .add((REFERRER_POLICY, "no-referrer")),
            )
            .service(get_pass_table::route)
            .service(post_pass_table::route)
            .service(put_pass_table::route)
            .service(put_pass_table_new_pass::route)
            .configure(routes::shared_vaults::configure)
            .default_service(web::to(routes::frontend::frontend_handler))
    })
    .bind(("127.0.0.1", port))?
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

    /// The auth key the frontend sends for this username and password
    /// (`passman_crypto::derive_account_keys`, as the browser runs it),
    /// remembered since deriving it is slow on purpose.
    fn derive_client_auth_key(username: &str, password: &str) -> String {
        static KEYS: Mutex<Vec<((String, String), String)>> = Mutex::new(Vec::new());
        let id = (username.to_string(), password.to_string());
        if let Some((_, key)) = KEYS.lock().unwrap().iter().find(|(k, _)| *k == id) {
            return key.clone();
        }
        let keys = passman_crypto::derive_account_keys(username, password).unwrap();
        let key = sharing::b64_encode(&keys.auth_key);
        KEYS.lock().unwrap().push((id, key.clone()));
        key
    }

    fn test_config() -> crate::config::ServerConfig {
        crate::config::ServerConfig {
            port: 8080,
            cors: false,
            debug: false,
            pretty_policies_json: None,
            server_access_password: "testpass".to_string(),
            rate_limit: Default::default(),
            max_buffered_upload_bytes: 64 * 1024 * 1024,
        }
    }

    async fn make_test_app(tmpdir: &std::path::Path) -> web::Data<AppState> {
        make_test_app_with_policies(tmpdir, "{}").await
    }

    async fn make_test_app_with_policies(
        tmpdir: &std::path::Path,
        policies: &str,
    ) -> web::Data<AppState> {
        make_test_app_with(tmpdir, policies, test_config()).await
    }

    async fn make_test_app_with(
        tmpdir: &std::path::Path,
        policies: &str,
        config: crate::config::ServerConfig,
    ) -> web::Data<AppState> {
        std::fs::create_dir_all(tmpdir.join("server_data")).unwrap();
        if !tmpdir.join("policies.json").exists() {
            std::fs::write(tmpdir.join("policies.json"), policies).unwrap();
        }
        app_state(tmpdir, config).await.unwrap().0
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

    /// A client that stops reading a download must not block that user's
    /// saves (downloads hold no lock), and must get an error rather than a
    /// silently truncated vault once the download times out (5s for a small
    /// vault).
    #[actix_web::test]
    async fn stalled_download_blocks_nothing_and_times_out() {
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

        let req = with_credentials(test::TestRequest::put(), &key)
            .uri("/pass-table?username=hank")
            .insert_header(("If-Match", etag))
            .insert_header(("Content-Length", "64"))
            .set_payload(vec![8u8; 64])
            .to_request();
        let resp: actix_web::dev::ServiceResponse = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            test::call_service(&app, req),
        )
        .await
        .expect("save blocked by the stalled download");
        assert_eq!(resp.status().as_u16(), 200);

        // the stalled download still gets the whole version it started
        // (renaming the new one over it doesn't change the open file)
        let body = test::try_read_body(stalled).await.unwrap();
        assert_eq!(body, vec![7u8; vault_len]);

        // one that never reads gives up at its deadline, with an error
        let req = with_credentials(
            test::TestRequest::post(),
            &derive_client_auth_key("ike", "pw"),
        )
        .uri("/pass-table?username=ike")
        .insert_header(("Content-Length", vault_len.to_string()))
        .set_payload(vec![9u8; vault_len])
        .to_request();
        assert_eq!(test::call_service(&app, req).await.status().as_u16(), 201);
        let req = with_credentials(
            test::TestRequest::get(),
            &derive_client_auth_key("ike", "pw"),
        )
        .uri("/pass-table?username=ike")
        .to_request();
        let stalled = test::call_service(&app, req).await;
        tokio::time::sleep(std::time::Duration::from_millis(5500)).await;
        assert!(test::try_read_body(stalled).await.is_err());
    }

    /// The auth key must be the size the frontend derives.
    #[actix_web::test]
    async fn auth_keys_of_the_wrong_size_are_refused() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = make_test_app(tmpdir.path()).await;
        let app = init_app!(state);
        let req = with_credentials(test::TestRequest::post(), "c2hvcnQ")
            .uri("/pass-table?username=ivy")
            .insert_header(("Content-Length", "64"))
            .set_payload(vec![0u8; 64])
            .to_request();
        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 400);
        assert!(!tmpdir.path().join("server_data/ivy").exists());
    }

    /// Reserved names are answered as taken, like an existing account.
    #[actix_web::test]
    async fn reserved_usernames_look_taken() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = make_test_app(tmpdir.path()).await;
        let app = init_app!(state);
        for name in ["by-fingerprint", "Identities"] {
            let req = with_credentials(
                test::TestRequest::post(),
                &derive_client_auth_key(name, "pw"),
            )
            .uri(&format!("/pass-table?username={name}"))
            .insert_header(("Content-Length", "64"))
            .set_payload(vec![0u8; 64])
            .to_request();
            let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
            assert_eq!(resp.status().as_u16(), 409);
            let body: serde_json::Value = test::read_body_json(resp).await;
            assert_eq!(body["type"], "E_USER_EXISTS");
        }
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
        make_record_in(VAULT_ID, prev, author, members)
    }

    fn make_record_in(
        vault_id: &str,
        prev: Option<&[u8]>,
        author: &TestUser,
        members: &[(&TestUser, bool, bool)],
    ) -> Vec<u8> {
        let seq = prev.map_or(0, |p| sharing::parse_record(p).unwrap().seq + 1);
        let epoch_secret = sharing::generate_epoch_secret();
        let body = RecordBody {
            v: 1,
            vault_id: vault_id.to_string(),
            seq,
            prev: prev.map(sharing::record_hash),
            author: author.name.to_string(),
            time: 0,
            members: members.iter().map(|(u, w, m)| u.member(*w, *m)).collect(),
            keys: members
                .iter()
                .map(|(u, ..)| {
                    let ctx = sharing::epoch_key_context(vault_id, seq, u.name);
                    let wrapped = sharing::wrap_key(&u.bundle, &epoch_secret, &ctx).unwrap();
                    (u.name.to_string(), sharing::b64_encode(&wrapped))
                })
                .collect(),
        };
        sharing::sign_record(&author.secret, &body).unwrap()
    }

    /// A signed version whose (stand-in) tables ciphertext is `len` bytes
    /// (and history 7).
    fn make_version(
        author: &TestUser,
        epoch: u64,
        version: u64,
        rekey: bool,
        len: usize,
    ) -> Vec<u8> {
        make_version_in(VAULT_ID, author, epoch, version, rekey, len, 0)
    }

    fn make_version_in(
        vault_id: &str,
        author: &TestUser,
        epoch: u64,
        version: u64,
        rekey: bool,
        len: usize,
        time: u64,
    ) -> Vec<u8> {
        let tables = vec![7u8; len];
        let history = b"history".to_vec();
        let hash = |d: &[u8]| {
            use sha2::Digest;
            sharing::b64_encode(&sha2::Sha256::digest(d))
        };
        let body = VersionBody {
            v: 1,
            vault_id: vault_id.to_string(),
            epoch,
            version,
            author: author.name.to_string(),
            time,
            tables_hash: hash(&tables),
            history_hash: hash(&history),
            rekey,
        };
        sharing::sign_version(&author.secret, &body, &tables, &history).unwrap()
    }

    fn frames(parts: &[&[u8]]) -> Vec<u8> {
        sharing::encode_frames(parts)
    }

    /// `author`'s signed statement that `member` is leaving in epoch `seq`.
    fn leave_statement(author: &TestUser, member: &str, seq: u64) -> Vec<u8> {
        let body = sharing::LeaveBody {
            v: 1,
            vault_id: VAULT_ID.to_string(),
            seq,
            member: member.to_string(),
            author: author.name.to_string(),
            time: 0,
        };
        sharing::sign_leave(&author.secret, &body).unwrap()
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
        // the archive's history ciphertext ("history") counts toward its size
        assert_eq!(
            list["vaults"][0]["archives"],
            json!([{"epoch": 0, "size": 7}])
        );
        assert_eq!(list["vaults"][0]["usage"], 10 + 7 + 7);
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
        assert_eq!(status, 403);

        // carol leaves: she loses access at once, and the next record must
        // remove her
        // her statement must be signed by her (or a manager), not another member
        let (status, _) = post_frames!(
            app,
            bob,
            &format!("{vault}/leave"),
            leave_statement(&bob, "carol", 1),
            None
        );
        assert_eq!(status, 400);
        let (status, _) = post_frames!(
            app,
            carol,
            &format!("{vault}/leave"),
            leave_statement(&carol, "carol", 1),
            None
        );
        assert_eq!(status, 200);
        let resp = call!(
            app,
            carol.req(test::TestRequest::get(), &format!("{vault}/version"))
        );
        assert_eq!(resp.status().as_u16(), 404);
        let (_, list) = call_json!(app, alice.req(test::TestRequest::get(), "/shared-vaults"));
        assert_eq!(list["vaults"][0]["leaving"][0]["username"], "carol");
        let statement = routes::base::parse_b64(
            list["vaults"][0]["leaving"][0]["statement"]
                .as_str()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        let record = sharing::parse_record(&r1).unwrap();
        sharing::verify_leave(&record, &statement, &carol.bundle).unwrap();
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
        let (status, body) = post_frames!(
            app,
            alice,
            &format!("{vault}/leave"),
            leave_statement(&alice, "alice", 2),
            None
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
            let (lock, _) = state2.shared_vaults.lookup(VAULT_ID).unwrap();
            let reloaded = lock.read().await;
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
        // bob's replaced identity wasn't in any record, so it isn't kept;
        // his current one (named in r0) can be found by its fingerprint
        let by_fingerprint = |bundle: &[u8]| {
            let hex: String = sharing::fingerprint(bundle)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            alice.req(
                test::TestRequest::get(),
                &format!("/identity?fingerprint={hex}"),
            )
        };
        let (status, _) = call_json!(app, by_fingerprint(&old_bob.bundle));
        assert_eq!(status, 404);
        let (status, body) = call_json!(app, by_fingerprint(&bob.bundle));
        assert_eq!(status, 200);
        assert_eq!(body["bundle"], sharing::b64_encode(&bob.bundle));
    }

    /// A limited policy caps how many shared vaults each user creates under
    /// it, and their size, members and records kept, separately from its
    /// accounts (with defaults when it doesn't say).
    #[actix_web::test]
    async fn shared_vault_policy_limits() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = make_test_app_with_policies(
            tmpdir.path(),
            r#"{
                "team": {"Password":"pw","PolicyType":"LIMITED_POLICY","MaxAccounts":4,"NumAccounts":0,"MaxDataSize":100000,
                         "MaxSharedVaultsPerUser":1,"MaxSharedVaultDataSize":20000,"MaxSharedVaultMembers":2,
                         "MaxSharedVaultRecords":2},
                "old": {"Password":"pw","PolicyType":"LIMITED_POLICY","MaxAccounts":4,"NumAccounts":0,"MaxDataSize":100000},
                "gone": {"Password":"pw","PolicyType":"NULL_POLICY"}
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

        // the defaults: 16 KiB of contents (signatures not counted)
        let d0 = make_record(None, &dave, &[(&dave, true, true)]);
        let (status, body) = call_json!(app, create(&dave, &d0, 16 * 1024));
        assert_eq!((status, body["type"].as_str()), (400, Some("E_POLICY")));
        let (_, d_list) = call_json!(app, dave.req(test::TestRequest::get(), "/shared-vaults"));
        assert_eq!(d_list["vaults"], json!([]));
        // the vault's own size limit applies, not the account one
        let (status, body) = call_json!(app, create(&alice, &r0, 30000));
        assert_eq!((status, body["type"].as_str()), (400, Some("E_POLICY")));
        let (status, _) = call_json!(app, create(&alice, &r0, 10));
        assert_eq!(status, 201);
        // only one vault per user under this policy
        let other_id = "f".repeat(32);
        let second = || {
            let body = frames(&[
                &make_record_in(&other_id, None, &alice, &[(&alice, true, true)]),
                &make_version_in(&other_id, &alice, 0, 1, false, 10, 0),
            ]);
            alice
                .req(test::TestRequest::post(), "/shared-vaults")
                .insert_header(("Content-Length", body.len().to_string()))
                .set_payload(body)
        };
        let (status, body) = call_json!(app, second());
        assert_eq!((status, body["type"].as_str()), (400, Some("E_POLICY")));
        assert!(
            body["policy_message"]
                .as_str()
                .unwrap()
                .contains("at most 1")
        );

        let (_, list) = call_json!(app, alice.req(test::TestRequest::get(), "/shared-vaults"));
        assert_eq!(list["vaults"][0]["maxDataSize"], 20000);
        assert_eq!(list["vaults"][0]["maxMembers"], 2);
        assert_eq!(list["vaults"][0]["maxRecords"], 2);

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

        // only the latest 2 records are kept, with their epochs' history
        let r2 = make_record(Some(&r1), &alice, &[(&alice, true, true)]);
        let (status, _) = post_frames!(
            app,
            alice,
            &format!("{vault}/records"),
            frames(&[&r2, &make_version(&alice, 2, 4, true, 10)]),
            Some("\"1-3\"")
        );
        assert_eq!(status, 200);
        let (_, list) = call_json!(app, alice.req(test::TestRequest::get(), "/shared-vaults"));
        assert_eq!(list["vaults"][0]["firstSeq"], 1);
        assert_eq!(
            list["vaults"][0]["archives"],
            json!([{"epoch": 1, "size": 7}])
        );
        let (_, records) = call_json!(
            app,
            alice.req(test::TestRequest::get(), &format!("{vault}/records"))
        );
        assert_eq!(records["from"], 1);
        assert_eq!(records["records"].as_array().unwrap().len(), 2);
        let dir = tmpdir
            .path()
            .join(format!("server_data/.shared/vaults/{VAULT_ID}"));
        assert!(!dir.join("records/0").exists());
        assert!(!dir.join("archive/0").exists());
        // dave left with r2: his identity is only named in r1, still kept
        let hex: String = sharing::fingerprint(&dave.bundle)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(
            tmpdir
                .path()
                .join(format!("server_data/.shared/identities/bundles/{hex}"))
                .exists()
        );

        // archived history counts toward the size: a version that leaves
        // too little room drops the oldest archive
        let (status, _) = put_version!(
            app,
            alice,
            make_version(&alice, 2, 5, false, 20000 - 7 - 5),
            "\"2-4\""
        );
        assert_eq!(status, 200);
        let (_, list) = call_json!(app, alice.req(test::TestRequest::get(), "/shared-vaults"));
        assert_eq!(list["vaults"][0]["archives"], json!([]));
        assert_eq!(list["vaults"][0]["usage"], 20000 - 5);

        // deleting the vault gives alice her count back
        let resp = call!(app, alice.req(test::TestRequest::delete(), &vault));
        assert_eq!(resp.status().as_u16(), 200);
        let (status, _) = call_json!(app, second());
        assert_eq!(status, 201);
        // dave's identity is still his current one, so it's kept
        assert!(
            tmpdir
                .path()
                .join(format!("server_data/.shared/identities/bundles/{hex}"))
                .exists()
        );
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
            let (lock, _) = reloaded.shared_vaults.lookup(VAULT_ID).unwrap();
            assert_eq!(lock.read().await.record.seq, 0);
        }
        assert!(!dir.join("records/1").exists());

        // the record and the epoch's first version were saved
        std::fs::write(dir.join("records/1"), &r1).unwrap();
        std::fs::write(dir.join("next"), make_version(&alice, 1, 2, true, 10)).unwrap();
        let reloaded = make_test_app(tmpdir.path()).await;
        let (lock, _) = reloaded.shared_vaults.lookup(VAULT_ID).unwrap();
        let vault = lock.read().await;
        assert_eq!((vault.record.seq, vault.version.version), (1, 2));
        assert!(vault.archives.contains_key(&0));
        assert!(!dir.join("next").exists());
    }

    /// Signed times far in the future are refused (they'd also break the
    /// `Last-Modified` header, which ends at the year 9999).
    #[actix_web::test]
    async fn far_future_times_are_refused() {
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
        let future = make_version_in(VAULT_ID, &alice, 0, 2, false, 10, 253_402_300_800_000);
        let (status, body) = put_version!(app, alice, future, ETAG_0_1);
        assert_eq!((status, body["type"].as_str()), (400, Some("E_INVALID")));
        let resp = call!(
            app,
            alice.req(
                test::TestRequest::get(),
                &format!("/shared-vaults/{VAULT_ID}/version")
            )
        );
        assert_eq!(resp.status().as_u16(), 200);
    }

    /// Listing vaults and publishing identities don't wait for a vault
    /// someone is changing (or holding locked).
    #[actix_web::test]
    async fn a_locked_vault_blocks_only_itself() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = make_test_app(tmpdir.path()).await;
        let app = init_app!(state);
        let alice = TestUser::new("alice", None);
        let bob = TestUser::new("bob", None);
        setup_users!(app, alice, bob);
        let r0 = make_record(None, &alice, &[(&alice, true, true)]);
        let (status, _) = post_frames!(
            app,
            alice,
            "/shared-vaults",
            frames(&[&r0, &make_version(&alice, 0, 1, false, 10)]),
            None
        );
        assert_eq!(status, 201);

        let (lock, _) = state.shared_vaults.lookup(VAULT_ID).unwrap();
        let held = lock.write_owned().await;
        let quick = std::time::Duration::from_secs(5);
        let (status, list) = tokio::time::timeout(quick, async {
            call_json!(app, alice.req(test::TestRequest::get(), "/shared-vaults"))
        })
        .await
        .expect("listing waited for the locked vault");
        assert_eq!(
            (status, list["vaults"][0]["id"].as_str()),
            (200, Some(VAULT_ID))
        );
        let new_bob = sharing::identity_bundle(&sharing::generate_identity_secret()).unwrap();
        let req = bob
            .req(test::TestRequest::put(), "/identity")
            .set_json(json!({ "bundle": sharing::b64_encode(&new_bob) }));
        let resp = tokio::time::timeout(quick, async { call!(app, req) })
            .await
            .expect("publishing an identity waited for the locked vault");
        assert_eq!(resp.status().as_u16(), 200);
        drop(held);
    }

    /// A leave statement is only good in the epoch it was made in, so it
    /// can't be replayed to remove someone again after they're added back;
    /// a manager can make one for another member.
    #[actix_web::test]
    async fn leave_statements_are_bound_to_their_epoch() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = make_test_app(tmpdir.path()).await;
        let app = init_app!(state);
        let alice = TestUser::new("alice", None);
        let bob = TestUser::new("bob", None);
        let carol = TestUser::new("carol", None);
        setup_users!(app, alice, bob, carol);
        let vault = format!("/shared-vaults/{VAULT_ID}");
        let all = [
            (&alice, true, true),
            (&bob, true, false),
            (&carol, true, false),
        ];
        let r0 = make_record(None, &alice, &all);
        let (status, _) = post_frames!(
            app,
            alice,
            "/shared-vaults",
            frames(&[&r0, &make_version(&alice, 0, 1, false, 10)]),
            None
        );
        assert_eq!(status, 201);

        // carol leaves in epoch 0, is removed, then added back
        let statement = leave_statement(&carol, "carol", 0);
        let (status, _) = post_frames!(
            app,
            carol,
            &format!("{vault}/leave"),
            statement.clone(),
            None
        );
        assert_eq!(status, 200);
        let r1 = make_record(Some(&r0), &alice, &all[..2]);
        let (status, _) = post_frames!(
            app,
            alice,
            &format!("{vault}/records"),
            frames(&[&r1, &make_version(&alice, 1, 2, true, 10)]),
            Some(ETAG_0_1)
        );
        assert_eq!(status, 200);
        let r2 = make_record(Some(&r1), &alice, &all);
        let (status, _) = post_frames!(
            app,
            alice,
            &format!("{vault}/records"),
            frames(&[&r2, &make_version(&alice, 2, 3, true, 10)]),
            Some("\"1-2\"")
        );
        assert_eq!(status, 200);
        // the old statement no longer works
        let (status, body) = post_frames!(app, carol, &format!("{vault}/leave"), statement, None);
        assert_eq!((status, body["type"].as_str()), (400, Some("E_INVALID")));
        let resp = call!(
            app,
            carol.req(test::TestRequest::get(), &format!("{vault}/version"))
        );
        assert_eq!(resp.status().as_u16(), 200);

        // alice (a manager) says bob is leaving: he loses access at once
        let (status, _) = post_frames!(
            app,
            alice,
            &format!("{vault}/leave"),
            leave_statement(&alice, "bob", 2),
            None
        );
        assert_eq!(status, 200);
        let resp = call!(
            app,
            bob.req(test::TestRequest::get(), &format!("{vault}/version"))
        );
        assert_eq!(resp.status().as_u16(), 404);
        // carol can't say alice is leaving
        let (status, _) = post_frames!(
            app,
            carol,
            &format!("{vault}/leave"),
            leave_statement(&carol, "alice", 2),
            None
        );
        assert_eq!(status, 400);
    }

    /// Requests are rate limited per IP, failed logins ban an IP, and an
    /// account with many failures makes new IPs wait (but not where its
    /// owner logged in from).
    #[actix_web::test]
    async fn failed_logins_are_limited() {
        let tmpdir = tempfile::tempdir().unwrap();
        let mut config = test_config();
        config.rate_limit.request_burst = 1000.0;
        let state = make_test_app_with(tmpdir.path(), "{}", config).await;
        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .wrap(middleware::from_fn(rate_limit::middleware))
                .service(routes::get_pass_table::route)
                .service(routes::post_pass_table::route),
        )
        .await;
        let right = derive_client_auth_key("judy", "pw");
        let wrong = derive_client_auth_key("judy", "wrong");
        let get = |key: &str, ip: &str| {
            with_credentials(test::TestRequest::get(), key)
                .uri("/pass-table?username=judy")
                .peer_addr(format!("{ip}:1234").parse().unwrap())
                .to_request()
        };
        let req = with_credentials(test::TestRequest::post(), &right)
            .uri("/pass-table?username=judy")
            .peer_addr("10.0.0.1:1234".parse().unwrap())
            .insert_header(("Content-Length", "64"))
            .set_payload(vec![0u8; 64])
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status().as_u16(), 201);
        // judy logs in from 10.0.0.1
        let resp = test::call_service(&app, get(&right, "10.0.0.1")).await;
        assert_eq!(resp.status().as_u16(), 200);
        test::read_body(resp).await;

        // 5 failures from 5 IPs throttle judy's account
        for n in 10..15 {
            let resp = test::call_service(&app, get(&wrong, &format!("10.0.1.{n}"))).await;
            assert_eq!(resp.status().as_u16(), 400);
        }
        // a new IP must wait, even with the right password
        let resp = test::call_service(&app, get(&right, "10.0.2.1")).await;
        assert_eq!(resp.status().as_u16(), 429);
        assert_eq!(resp.headers().get("Retry-After").unwrap(), "1");
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["type"], "E_THROTTLED");
        // but not where judy logged in from
        let resp = test::call_service(&app, get(&right, "10.0.0.1")).await;
        assert_eq!(resp.status().as_u16(), 200);
        test::read_body(resp).await;
        // after the wait the right password works there too
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let resp = test::call_service(&app, get(&right, "10.0.2.1")).await;
        assert_eq!(resp.status().as_u16(), 200);
        test::read_body(resp).await;

        // wrong server passwords ban an IP behind the proxy (X-Real-IP)
        for _ in 0..10 {
            let req = test::TestRequest::get()
                .uri("/pass-table?username=nobody")
                .insert_header((routes::base::AUTH_KEY_HEADER, right.as_str()))
                .insert_header((routes::base::SERVER_PASS_HEADER, "nope"))
                .insert_header(("X-Real-IP", "203.0.113.9"))
                .peer_addr("127.0.0.1:5555".parse().unwrap())
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status().as_u16(), 400);
        }
        let req = test::TestRequest::get()
            .uri("/pass-table?username=judy")
            .insert_header(("X-Real-IP", "203.0.113.9"))
            .peer_addr("127.0.0.1:5555".parse().unwrap())
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 429);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["type"], "E_BANNED");
        // the proxy's own address isn't what's banned (it's only throttled
        // for judy, like any IP she hasn't logged in from)
        let resp = test::call_service(&app, get(&right, "127.0.0.1")).await;
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["type"], "E_THROTTLED");
    }
}

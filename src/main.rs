use crate::{
    routes::{
        base::{AppState, Argon2Params},
        frontend::FrontendMode,
        get_pass_table, post_pass_table, put_pass_table, put_pass_table_new_pass,
    },
    server_policy::PolicyStorage,
};
use actix_web::{App, HttpServer, web};
use std::{collections::HashMap, path::PathBuf};
use tokio::sync::RwLock;

mod config;
mod routes;
mod server_policy;

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
    tokio::fs::create_dir_all(base_dir.join("server_data")).await?;
    let app_state = web::Data::new(AppState {
        argon2_params: Argon2Params::new()?,
        policies_and_config,
        server_data_dir: base_dir.join("server_data"),
        user_locks: RwLock::new(HashMap::new()),
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
            .default_service(web::to(routes::frontend::frontend_handler))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await?;
    join_handle.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, test, web};
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
        let mut out = String::with_capacity((bytes.len() * 4 + 2) / 3);
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
        std::fs::create_dir_all(tmpdir.join("server_data")).unwrap();
        std::fs::write(tmpdir.join("policies.json"), b"{}").unwrap();

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
        })
    }

    macro_rules! init_app {
        ($state:expr) => {
            test::init_service(
                App::new()
                    .app_data($state.clone())
                    .service(routes::get_pass_table::route)
                    .service(routes::post_pass_table::route)
                    .service(routes::put_pass_table::route),
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
        let server_pass = "testpass";
        let auth_key = derive_client_auth_key(username, password);

        // --- Register ---
        // The body is a minimal dummy blob; the server stores it verbatim.
        let dummy_body = vec![0xffu8; 64];
        let register_uri = format!(
            "/pass-table?username={username}&auth_key={auth_key}&server_pass={server_pass}"
        );
        let req = test::TestRequest::post()
            .uri(&register_uri)
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
        let req = test::TestRequest::get().uri(&register_uri).to_request();
        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(
            resp.status().as_u16(),
            200,
            "Login failed with status {}",
            resp.status()
        );
    }

    /// Registering the same username twice must return 409 Conflict.
    #[actix_web::test]
    async fn e2e_duplicate_register_is_conflict() {
        let tmpdir = tempfile::tempdir().unwrap();
        let state = make_test_app(tmpdir.path()).await;
        let app = init_app!(state);

        let auth_key = derive_client_auth_key("bob", "secret");
        let uri = format!("/pass-table?username=bob&auth_key={auth_key}&server_pass=testpass");
        let body = vec![0u8; 64];

        for expected_status in [201u16, 409] {
            let req = test::TestRequest::post()
                .uri(&uri)
                .insert_header(("Content-Type", "application/octet-stream"))
                .insert_header(("Content-Length", body.len().to_string()))
                .set_payload(body.clone())
                .to_request();
            let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
            assert_eq!(resp.status().as_u16(), expected_status);
        }
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
        let reg_uri =
            format!("/pass-table?username=carol&auth_key={right_key}&server_pass=testpass");
        let req = test::TestRequest::post()
            .uri(&reg_uri)
            .insert_header(("Content-Type", "application/octet-stream"))
            .insert_header(("Content-Length", "64"))
            .set_payload(vec![0u8; 64])
            .to_request();
        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 201);

        // Login with wrong key
        let bad_uri =
            format!("/pass-table?username=carol&auth_key={wrong_key}&server_pass=testpass");
        let req = test::TestRequest::get().uri(&bad_uri).to_request();
        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 400);
    }
}

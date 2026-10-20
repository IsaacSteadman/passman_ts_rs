use actix_web::{
    HttpRequest, HttpResponse, Responder as _,
    http::header::{CACHE_CONTROL, CONNECTION, HOST, HeaderValue, TRANSFER_ENCODING},
    web,
};
use std::path::PathBuf;

pub enum FrontendMode {
    /// Proxy all unmatched requests to a frontend dev server (e.g. parcel serve).
    DevProxy(String),
    /// Serve static files from a built dist directory, falling back to index.html
    /// for unknown paths (SPA routing).
    StaticFiles(PathBuf),
}

pub async fn frontend_handler(
    req: HttpRequest,
    body: web::Bytes,
    mode: web::Data<FrontendMode>,
) -> HttpResponse {
    match mode.as_ref() {
        FrontendMode::DevProxy(base_url) => dev_proxy(&req, body, base_url).await,
        FrontendMode::StaticFiles(dir) => serve_static(&req, dir),
    }
}

async fn dev_proxy(req: &HttpRequest, body: web::Bytes, base_url: &str) -> HttpResponse {
    let client = awc::Client::default();
    let target = format!("{}{}", base_url.trim_end_matches('/'), req.uri());

    let mut fwd = client.request(req.method().clone(), target.as_str());
    for (name, value) in req.headers() {
        if name != HOST {
            fwd = fwd.insert_header((name.clone(), value.clone()));
        }
    }

    let mut res = match fwd.send_body(body).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Dev proxy request error: {e:?}");
            return HttpResponse::BadGateway().finish();
        }
    };

    let mut builder = HttpResponse::build(res.status());
    for (name, value) in res.headers() {
        // Strip hop-by-hop headers — we already collected the full body.
        if name != TRANSFER_ENCODING && name != CONNECTION {
            builder.insert_header((name.clone(), value.clone()));
        }
    }

    match res.body().limit(20_000_000).await {
        Ok(bytes) => builder.body(bytes),
        Err(e) => {
            eprintln!("Dev proxy body error: {e:?}");
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// Files whose names stay the same from one build to the next. Browsers must
/// check these with the server on every load, or they could keep using an old
/// index.html (and so the old app) after a deploy. Parcel puts a content hash
/// in every other file name.
const UNHASHED_FILES: &[&str] = &["index.html", "manifest.webmanifest"];

fn serve_static(req: &HttpRequest, dir: &PathBuf) -> HttpResponse {
    let rel = req.path().trim_start_matches('/');
    let candidate = if rel.is_empty() {
        dir.join("index.html")
    } else {
        dir.join(rel)
    };

    // Path traversal protection: ensure the resolved path stays inside dist/.
    let canonical_dir = match dir.canonicalize() {
        Ok(p) => p,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let path = match candidate.canonicalize() {
        Ok(p) if p.starts_with(&canonical_dir) && p.is_file() => p,
        // File not found or traversal attempt → SPA fallback.
        _ => dir.join("index.html"),
    };

    match actix_files::NamedFile::open(&path) {
        Ok(f) => {
            let mut resp = f.respond_to(req);
            let name = path.file_name().and_then(|name| name.to_str());
            if name.is_some_and(|name| UNHASHED_FILES.contains(&name)) {
                resp.headers_mut()
                    .insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            }
            resp
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("{e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, test};

    #[actix_web::test]
    async fn unhashed_files_must_be_revalidated() {
        let dist = tempfile::tempdir().unwrap();
        for name in ["index.html", "manifest.webmanifest", "main.1a2b3c4d.js"] {
            std::fs::write(dist.path().join(name), "x").unwrap();
        }
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(FrontendMode::StaticFiles(
                    dist.path().to_path_buf(),
                )))
                .default_service(web::to(frontend_handler)),
        )
        .await;
        let cache_control = |resp: &actix_web::dev::ServiceResponse| {
            resp.headers()
                .get(CACHE_CONTROL)
                .map(|v| v.to_str().unwrap().to_owned())
        };

        for path in ["/", "/index.html", "/some/app/route"] {
            let resp =
                test::call_service(&app, test::TestRequest::get().uri(path).to_request()).await;
            assert_eq!(cache_control(&resp).as_deref(), Some("no-cache"), "{path}");
        }

        let req = test::TestRequest::get()
            .uri("/manifest.webmanifest")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(cache_control(&resp).as_deref(), Some("no-cache"));
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/manifest+json"
        );

        let req = test::TestRequest::get()
            .uri("/main.1a2b3c4d.js")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(cache_control(&resp), None);
    }
}

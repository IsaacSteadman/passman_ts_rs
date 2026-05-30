use actix_web::{
    HttpRequest, HttpResponse, Responder as _,
    http::header::{CONNECTION, HOST, TRANSFER_ENCODING},
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
        Ok(f) => f.respond_to(req),
        Err(e) => HttpResponse::InternalServerError().body(format!("{e}")),
    }
}

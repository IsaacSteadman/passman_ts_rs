use actix_web::{
    HttpRequest, HttpResponse, Responder as _,
    http::header::{
        CACHE_CONTROL, CONNECTION, CONTENT_SECURITY_POLICY, HOST, HeaderValue, TRANSFER_ENCODING,
        X_FRAME_OPTIONS,
    },
    web,
};
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
};

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
const UNHASHED_FILES: &[&str] = &["index.html", "manifest.webmanifest", "sw.js"];

fn serve_static(req: &HttpRequest, dir: &Path) -> HttpResponse {
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
            if path.extension().is_some_and(|ext| ext == "html") {
                match page_policy(&path) {
                    Ok(policy) => {
                        let headers = resp.headers_mut();
                        headers.insert(CONTENT_SECURITY_POLICY, policy);
                        headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
                    }
                    Err(e) => {
                        eprintln!("Error occured attempting to read {path:?}\n  e={e:?}");
                        return HttpResponse::InternalServerError().finish();
                    }
                }
            }
            resp
        }
        Err(e) => {
            eprintln!("Error occured attempting to open {path:?}\n  e={e:?}");
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// The Content Security Policy of a page: scripts and styles only from the
/// app itself, except the page's own inline ones (Parcel's import map, the
/// theme script, `style` attributes), allowed by their hashes; no framing.
/// Cached until the file changes.
fn page_policy(path: &Path) -> std::io::Result<HeaderValue> {
    type Cached = (PathBuf, std::time::SystemTime, u64, HeaderValue);
    static CACHE: Mutex<Vec<Cached>> = Mutex::new(Vec::new());
    let metadata = std::fs::metadata(path)?;
    let (modified, len) = (metadata.modified()?, metadata.len());
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((.., value)) = cache
        .iter()
        .find(|(p, m, l, _)| p == path && *m == modified && *l == len)
    {
        return Ok(value.clone());
    }
    let html = std::fs::read_to_string(path)?;
    let policy = content_security_policy(&html);
    let value = HeaderValue::from_str(&policy).map_err(std::io::Error::other)?;
    cache.retain(|(p, ..)| p != path);
    cache.push((path.to_path_buf(), modified, len, value.clone()));
    Ok(value)
}

fn sha256_source(text: &str) -> String {
    use base64::Engine;
    use sha2::Digest;
    let digest = sha2::Sha256::digest(text.as_bytes());
    format!(
        "'sha256-{}'",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

/// Builds the policy for `html` (see `page_policy`).
pub fn content_security_policy(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let mut scripts = Vec::new();
    let mut at = 0;
    while let Some(start) = lower[at..].find("<script").map(|i| at + i) {
        let Some(tag_end) = lower[start..].find('>').map(|i| start + i) else {
            break;
        };
        let Some(close) = lower[tag_end..].find("</script").map(|i| tag_end + i) else {
            break;
        };
        let tag = &lower[start..tag_end];
        if !tag.contains(" src=") {
            scripts.push(sha256_source(&html[tag_end + 1..close]));
        }
        at = close;
    }
    let mut styles = Vec::new();
    for (i, _) in lower.match_indices("style=") {
        // an attribute (inside a tag, after a space), not text that
        // happens to contain it
        let before = &lower[..i];
        let in_tag = before.rfind('<') > before.rfind('>');
        if !in_tag || !before.ends_with(|c: char| c.is_ascii_whitespace()) {
            continue;
        }
        let rest = &html[i + "style=".len()..];
        let value = match rest.chars().next() {
            Some(q @ ('"' | '\'')) => rest[1..].split(q).next(),
            _ => rest
                .split(|c: char| c.is_ascii_whitespace() || c == '>')
                .next(),
        };
        if let Some(value) = value {
            styles.push(sha256_source(value));
        }
    }
    scripts.dedup();
    styles.sort();
    styles.dedup();
    let style_src = if styles.is_empty() {
        "'self'".to_string()
    } else {
        format!("'self' 'unsafe-hashes' {}", styles.join(" "))
    };
    format!(
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval' {}; style-src {style_src}; \
         img-src 'self' data:; connect-src 'self'; worker-src 'self'; manifest-src 'self'; \
         object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        scripts.join(" ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, test};

    #[actix_web::test]
    async fn unhashed_files_must_be_revalidated() {
        let dist = tempfile::tempdir().unwrap();
        for name in [
            "index.html",
            "manifest.webmanifest",
            "sw.js",
            "main.1a2b3c4d.js",
        ] {
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

        for path in ["/", "/index.html", "/some/app/route", "/sw.js"] {
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
        assert!(resp.headers().get(CONTENT_SECURITY_POLICY).is_none());
    }

    /// Pages may only run their own inline scripts and style attributes.
    #[actix_web::test]
    async fn page_policy_allows_only_the_pages_inline_code() {
        let html = r#"<html><head><script type=importmap>{"imports":{}}</script>
            <script>var theme = 1;</script><script type=module src=/main.js></script></head>
            <body><div id=a style=display:none></div><p style="color: red">x style=no</p></body></html>"#;
        let policy = content_security_policy(html);
        assert!(policy.contains(&sha256_source(r#"{"imports":{}}"#)));
        assert!(policy.contains(&sha256_source("var theme = 1;")));
        assert!(policy.contains(&sha256_source("display:none")));
        assert!(policy.contains(&sha256_source("color: red")));
        assert!(!policy.contains(&sha256_source("no")));
        assert!(policy.contains("frame-ancestors 'none'"));
        assert!(policy.contains("object-src 'none'"));
        // the external script isn't hashed
        assert_eq!(policy.matches("'sha256-").count(), 4);
    }
}

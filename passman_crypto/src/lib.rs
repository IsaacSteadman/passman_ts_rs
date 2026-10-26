pub mod sharing;

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use wasm_bindgen::prelude::*;

/// The size in bytes of both the hash output and the salt used with Argon2.
/// This is the value the configured [`Argon2Params`] instance expects.
pub const HASH_SIZE: usize = 64;

/// Returns `HASH_SIZE` — the expected salt length and output key length in
/// bytes.  Exposed to JS/TS so callers can allocate the right buffer without
/// hard-coding the constant.
#[wasm_bindgen]
pub fn hash_size() -> usize {
    HASH_SIZE
}

/// A cloneable snapshot of the Argon2 parameters used by passman.
/// Call [`Argon2Params::make`] to produce a ready-to-use [`argon2::Argon2`]
/// instance.
#[derive(Clone)]
pub struct Argon2Params {
    pub algo: argon2::Algorithm,
    pub ver: argon2::Version,
    pub params: argon2::Params,
}

impl Argon2Params {
    /// Constructs the default Argon2id v1.3 parameters (19 MiB, 4 passes,
    /// 1 lane, [`HASH_SIZE`]-byte output).
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            algo: argon2::Algorithm::Argon2id,
            ver: argon2::Version::V0x13,
            params: match argon2::Params::new(19 * 1024, 4, 1, Some(HASH_SIZE)) {
                Err(e) => anyhow::bail!("params construct error {:?}", e),
                Ok(o) => o,
            },
        })
    }

    /// Creates a fresh [`argon2::Argon2`] hasher bound to these parameters.
    pub fn make(&self) -> argon2::Argon2<'_> {
        argon2::Argon2::new(self.algo, self.ver, self.params.clone())
    }
}

/// Key length in bytes required by XChaCha20-Poly1305 (32).
pub const XCHACHA20_KEY_SIZE: usize = 32;
/// Nonce length in bytes required by XChaCha20-Poly1305 (24).
pub const XCHACHA20_NONCE_SIZE: usize = 24;

/// Returns the XChaCha20-Poly1305 key size in bytes (32).
#[wasm_bindgen]
pub fn xchacha20_key_size() -> usize {
    XCHACHA20_KEY_SIZE
}

/// Returns the XChaCha20-Poly1305 nonce size in bytes (24).
#[wasm_bindgen]
pub fn xchacha20_nonce_size() -> usize {
    XCHACHA20_NONCE_SIZE
}

/// Generates a random 24-byte nonce suitable for use with
/// [`xchacha20_encrypt`].  Uses the OS CSPRNG (or `window.crypto` on wasm32).
#[wasm_bindgen]
pub fn xchacha20_generate_nonce() -> Vec<u8> {
    XChaCha20Poly1305::generate_nonce(&mut OsRng).to_vec()
}

/// Encrypts `plaintext` with XChaCha20-Poly1305.
///
/// - `key` must be exactly 32 bytes.
/// - `nonce` must be exactly 24 bytes (use [`xchacha20_generate_nonce`]).
///
/// Returns the ciphertext with the 16-byte Poly1305 authentication tag
/// appended (i.e. `ciphertext.length == plaintext.length + 16`).
#[wasm_bindgen]
pub fn xchacha20_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    let key: &[u8; XCHACHA20_KEY_SIZE] = key.try_into().map_err(|_| {
        JsError::new(&format!(
            "key must be {XCHACHA20_KEY_SIZE} bytes, got {}",
            key.len()
        ))
    })?;
    let nonce: &[u8; XCHACHA20_NONCE_SIZE] = nonce.try_into().map_err(|_| {
        JsError::new(&format!(
            "nonce must be {XCHACHA20_NONCE_SIZE} bytes, got {}",
            nonce.len()
        ))
    })?;
    let nonce = XNonce::from_slice(nonce);
    XChaCha20Poly1305::new(key.into())
        .encrypt(nonce, plaintext)
        .map_err(|e| JsError::new(&format!("encrypt error: {e}")))
}

/// Decrypts `ciphertext` (with appended 16-byte Poly1305 tag) using
/// XChaCha20-Poly1305.
///
/// - `key` must be exactly 32 bytes.
/// - `nonce` must be exactly 24 bytes.
///
/// Throws if authentication fails or inputs are malformed.
#[wasm_bindgen]
pub fn xchacha20_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
    let key: &[u8; XCHACHA20_KEY_SIZE] = key.try_into().map_err(|_| {
        JsError::new(&format!(
            "key must be {XCHACHA20_KEY_SIZE} bytes, got {}",
            key.len()
        ))
    })?;
    let nonce: &[u8; XCHACHA20_NONCE_SIZE] = nonce.try_into().map_err(|_| {
        JsError::new(&format!(
            "nonce must be {XCHACHA20_NONCE_SIZE} bytes, got {}",
            nonce.len()
        ))
    })?;
    let nonce = XNonce::from_slice(nonce);
    XChaCha20Poly1305::new(key.into())
        .decrypt(nonce, ciphertext)
        .map_err(|_| JsError::new("decryption failed: authentication tag mismatch or corrupt data"))
}

/// the provided `salt` (must be exactly `hash_size()` = 64 bytes).
///
/// Returns the raw key bytes as a `Uint8Array`.  Throws a JS `Error` if the
/// salt length is wrong or the Argon2 operation fails.
///
/// Because Argon2 is CPU-intensive, consider calling this from a Web Worker to
/// avoid blocking the main thread.
#[wasm_bindgen]
pub fn derive_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, JsError> {
    if salt.len() != HASH_SIZE {
        return Err(JsError::new(&format!(
            "salt must be exactly {HASH_SIZE} bytes, got {}",
            salt.len()
        )));
    }
    let salt_arr: &[u8; HASH_SIZE] = salt.try_into().unwrap();
    let params = Argon2Params::new().map_err(|e| JsError::new(&e.to_string()))?;
    let argon2 = params.make();
    let mut output = [0u8; HASH_SIZE];
    argon2
        .hash_password_into(password.as_bytes(), salt_arr, &mut output)
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    Ok(output.to_vec())
}

// ── Sharing (see `sharing`) ─────────────────────────────────────────────────
// Thin wrappers turning errors into JS exceptions; records and versions are
// passed as their signed bytes, and their bodies returned as JSON.

fn js_err(e: anyhow::Error) -> JsError {
    JsError::new(&e.to_string())
}

/// Generates the secret of a new sharing identity (32 bytes).
#[wasm_bindgen]
pub fn identity_generate() -> Vec<u8> {
    sharing::generate_identity_secret().to_vec()
}

/// The public bundle of an identity secret.
#[wasm_bindgen]
pub fn identity_bundle(secret: &[u8]) -> Result<Vec<u8>, JsError> {
    sharing::identity_bundle(secret).map_err(js_err)
}

#[wasm_bindgen]
pub fn identity_fingerprint(bundle: &[u8]) -> Vec<u8> {
    sharing::fingerprint(bundle).to_vec()
}

#[wasm_bindgen]
pub fn safety_number(
    user_a: &str,
    fingerprint_a: &[u8],
    user_b: &str,
    fingerprint_b: &[u8],
) -> String {
    sharing::safety_number(user_a, fingerprint_a, user_b, fingerprint_b)
}

#[wasm_bindgen]
pub fn epoch_secret_generate() -> Vec<u8> {
    sharing::generate_epoch_secret().to_vec()
}

#[wasm_bindgen]
pub fn epoch_subkey(epoch_secret: &[u8], label: &str) -> Vec<u8> {
    sharing::epoch_subkey(epoch_secret, label).to_vec()
}

#[wasm_bindgen]
pub fn epoch_key_context(vault_id: &str, seq: f64, username: &str) -> Vec<u8> {
    sharing::epoch_key_context(vault_id, seq as u64, username)
}

#[wasm_bindgen]
pub fn wrap_key(bundle: &[u8], key: &[u8], context: &[u8]) -> Result<Vec<u8>, JsError> {
    sharing::wrap_key(bundle, key, context).map_err(js_err)
}

#[wasm_bindgen]
pub fn unwrap_key(secret: &[u8], wrapped: &[u8], context: &[u8]) -> Result<Vec<u8>, JsError> {
    sharing::unwrap_key(secret, wrapped, context)
        .map(|k| k.to_vec())
        .map_err(js_err)
}

/// Signs a record body (JSON of `sharing::RecordBody`).
#[wasm_bindgen]
pub fn record_sign(secret: &[u8], body_json: &str) -> Result<Vec<u8>, JsError> {
    let body: sharing::RecordBody =
        serde_json::from_str(body_json).map_err(|e| js_err(e.into()))?;
    sharing::sign_record(secret, &body).map_err(js_err)
}

#[wasm_bindgen]
pub fn record_hash(wire: &[u8]) -> String {
    sharing::record_hash(wire)
}

/// Checks a record follows `prev` (empty for the first) and returns its body
/// as JSON.
#[wasm_bindgen]
pub fn record_verify(prev: &[u8], wire: &[u8], author_bundle: &[u8]) -> Result<String, JsError> {
    let prev_body = if prev.is_empty() {
        None
    } else {
        Some(sharing::parse_record(prev).map_err(js_err)?)
    };
    let body = sharing::verify_record(prev_body.as_ref().map(|b| (b, prev)), wire, author_bundle)
        .map_err(js_err)?;
    serde_json::to_string(&body).map_err(|e| js_err(e.into()))
}

/// The body of a record already checked, as JSON.
#[wasm_bindgen]
pub fn record_body(wire: &[u8]) -> Result<String, JsError> {
    let body = sharing::parse_record(wire).map_err(js_err)?;
    serde_json::to_string(&body).map_err(|e| js_err(e.into()))
}

/// Signs a version body (JSON of `sharing::VersionBody`) with its contents.
#[wasm_bindgen]
pub fn version_sign(
    secret: &[u8],
    body_json: &str,
    tables: &[u8],
    history: &[u8],
) -> Result<Vec<u8>, JsError> {
    let body: sharing::VersionBody =
        serde_json::from_str(body_json).map_err(|e| js_err(e.into()))?;
    sharing::sign_version(secret, &body, tables, history).map_err(js_err)
}

/// Checks a version (or, if `archived`, an archived version) of the epoch
/// started by `record`, and returns its body as JSON.
#[wasm_bindgen]
pub fn version_verify(
    record: &[u8],
    wire: &[u8],
    author_bundle: &[u8],
    archived: bool,
) -> Result<String, JsError> {
    let record = sharing::parse_record(record).map_err(js_err)?;
    let body = if archived {
        sharing::verify_archive(&record, wire, author_bundle)
    } else {
        sharing::verify_version(&record, wire, author_bundle)
    }
    .map_err(js_err)?;
    serde_json::to_string(&body).map_err(|e| js_err(e.into()))
}

/// SHA-256 (base64) of `data`, as used in version bodies.
#[wasm_bindgen]
pub fn content_hash(data: &[u8]) -> String {
    use sha2::Digest;
    sharing::b64_encode(&sha2::Sha256::digest(data))
}

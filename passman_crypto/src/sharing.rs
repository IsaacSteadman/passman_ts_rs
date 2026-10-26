//! Cryptography for shared vaults, used by the browser (through the wasm
//! exports in `lib.rs`) and by the server, which checks everything it stores
//! the same way the members' browsers do.
//!
//! - Each user has an *identity*: one 32-byte secret, kept in their own
//!   vault, from which three key pairs are derived: Ed25519 and ML-DSA-65
//!   (both must sign) and X-Wing (X25519 + ML-KEM-768) for wrapping keys. The
//!   public halves form a *bundle*, published on the server; its SHA-256
//!   *fingerprint* is what members verify in person.
//! - A shared vault's member list is a chain of signed *records*. Each record
//!   is signed by a member who could manage members in the previous one, and
//!   starts a new epoch with a fresh random *epoch secret*, wrapped for every
//!   member. So a member removed from the list can't read later versions, and
//!   one added can't read earlier ones.
//! - Each *version* of a vault's contents is signed by its author, who must be
//!   allowed to write in that epoch. Its tables and its history are separate
//!   ciphertexts, so the server can keep each past epoch's history without its
//!   tables.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit as _, OsRng, Payload, rand_core::RngCore},
};
use ed25519_dalek::Signer as _;
use hkdf::Hkdf;
use hybrid_array::Array;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{BTreeMap, BTreeSet};
use x_wing::{Decapsulate, Decapsulator, KeyExport};

pub type Result<T> = anyhow::Result<T>;

pub const IDENTITY_SECRET_SIZE: usize = 32;
const ED25519_PUBLIC_SIZE: usize = 32;
const ED25519_SIGNATURE_SIZE: usize = 64;
const ML_DSA_PUBLIC_SIZE: usize = 1952;
const ML_DSA_SIGNATURE_SIZE: usize = 3309;
const X_WING_PUBLIC_SIZE: usize = x_wing::ENCAPSULATION_KEY_SIZE;
const X_WING_CIPHERTEXT_SIZE: usize = x_wing::CIPHERTEXT_SIZE;
const BUNDLE_VERSION: u8 = 1;
/// version byte, Ed25519, ML-DSA-65 and X-Wing public keys
pub const BUNDLE_SIZE: usize = 1 + ED25519_PUBLIC_SIZE + ML_DSA_PUBLIC_SIZE + X_WING_PUBLIC_SIZE;
pub const SIGNATURE_SIZE: usize = ED25519_SIGNATURE_SIZE + ML_DSA_SIGNATURE_SIZE;
pub const FINGERPRINT_SIZE: usize = 32;
/// A 32-byte key wrapped for a bundle: X-Wing ciphertext, nonce, then the
/// key encrypted with its tag.
pub const WRAPPED_KEY_SIZE: usize = X_WING_CIPHERTEXT_SIZE + 24 + 32 + 16;
pub const EPOCH_SECRET_SIZE: usize = 32;
/// The most members a shared vault can have.
pub const MAX_MEMBERS: usize = 256;

const DOMAIN: &[u8] = b"passman-sharing-v1";

fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

pub fn generate_identity_secret() -> [u8; IDENTITY_SECRET_SIZE] {
    random()
}

/// A random epoch secret for a new record.
pub fn generate_epoch_secret() -> [u8; EPOCH_SECRET_SIZE] {
    random()
}

// ── Identities ───────────────────────────────────────────────────────────────

struct Identity {
    ed25519: ed25519_dalek::SigningKey,
    ml_dsa: ml_dsa::ExpandedSigningKey<MlDsa65>,
    x_wing: x_wing::DecapsulationKey,
}

impl Identity {
    fn new(secret: &[u8]) -> Result<Self> {
        anyhow::ensure!(
            secret.len() == IDENTITY_SECRET_SIZE,
            "identity secret must be {IDENTITY_SECRET_SIZE} bytes"
        );
        let seed = |label: &[u8]| hkdf32(secret, b"passman identity v1", label);
        Ok(Self {
            ed25519: ed25519_dalek::SigningKey::from_bytes(&seed(b"ed25519")),
            ml_dsa: ml_dsa::ExpandedSigningKey::from_seed(&Array(seed(b"ml-dsa-65"))),
            x_wing: x_wing::DecapsulationKey::from(seed(b"x-wing")),
        })
    }

    fn bundle(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BUNDLE_SIZE);
        out.push(BUNDLE_VERSION);
        out.extend_from_slice(self.ed25519.verifying_key().as_bytes());
        out.extend_from_slice(&self.ml_dsa.verifying_key().encode());
        out.extend_from_slice(&self.x_wing.encapsulation_key().to_bytes());
        out
    }
}

/// The public keys of an identity.
struct Bundle {
    ed25519: ed25519_dalek::VerifyingKey,
    ml_dsa: ml_dsa::VerifyingKey<MlDsa65>,
    x_wing: x_wing::EncapsulationKey,
}

impl Bundle {
    fn parse(bundle: &[u8]) -> Result<Self> {
        anyhow::ensure!(
            bundle.len() == BUNDLE_SIZE && bundle[0] == BUNDLE_VERSION,
            "not an identity bundle"
        );
        let (ed, rest) = bundle[1..].split_at(ED25519_PUBLIC_SIZE);
        let (dsa, xw) = rest.split_at(ML_DSA_PUBLIC_SIZE);
        let dsa = EncodedVerifyingKey::<MlDsa65>::try_from(dsa)
            .map_err(|_| anyhow::anyhow!("bad ML-DSA key"))?;
        Ok(Self {
            ed25519: ed25519_dalek::VerifyingKey::from_bytes(ed.try_into()?)
                .map_err(|_| anyhow::anyhow!("bad Ed25519 key"))?,
            ml_dsa: ml_dsa::VerifyingKey::decode(&dsa),
            x_wing: x_wing::EncapsulationKey::try_from(xw)
                .map_err(|_| anyhow::anyhow!("bad X-Wing key"))?,
        })
    }
}

/// Checks `bundle` is a well-formed identity bundle.
pub fn check_bundle(bundle: &[u8]) -> Result<()> {
    Bundle::parse(bundle).map(|_| ())
}

/// The public identity bundle of `secret`.
pub fn identity_bundle(secret: &[u8]) -> Result<Vec<u8>> {
    Ok(Identity::new(secret)?.bundle())
}

/// What members compare to check they have each other's real bundle.
pub fn fingerprint(bundle: &[u8]) -> [u8; FINGERPRINT_SIZE] {
    Sha256::new()
        .chain_update(b"passman identity fingerprint v1\0")
        .chain_update(bundle)
        .finalize()
        .into()
}

/// A number two users can read to each other to verify both fingerprints at
/// once (like Signal's safety numbers): 60 digits, the same for both.
pub fn safety_number(
    user_a: &str,
    fingerprint_a: &[u8],
    user_b: &str,
    fingerprint_b: &[u8],
) -> String {
    let mut sides = [(user_a, fingerprint_a), (user_b, fingerprint_b)];
    sides.sort();
    let mut hasher = Sha512::new().chain_update(b"passman safety number v1\0");
    for (user, fp) in sides {
        hasher.update((user.len() as u32).to_le_bytes());
        hasher.update(user.as_bytes());
        hasher.update(fp);
    }
    let digest = hasher.finalize();
    // 12 groups of 5 digits, each from its own 5 bytes (as Signal does)
    digest[..60]
        .chunks(5)
        .map(|chunk| {
            let n = chunk.iter().fold(0u64, |n, b| (n << 8) | *b as u64);
            format!("{:05}", n % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn signed_message(context: &str, msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN.len() + context.len() + msg.len() + 2);
    out.extend_from_slice(DOMAIN);
    out.push(0);
    out.extend_from_slice(context.as_bytes());
    out.push(0);
    out.extend_from_slice(msg);
    out
}

/// Signs with both Ed25519 and ML-DSA-65; `context` says what is signed.
pub fn sign(secret: &[u8], context: &str, msg: &[u8]) -> Result<Vec<u8>> {
    let identity = Identity::new(secret)?;
    let m = signed_message(context, msg);
    let mut out = Vec::with_capacity(SIGNATURE_SIZE);
    out.extend_from_slice(&identity.ed25519.sign(&m).to_bytes());
    let dsa = identity
        .ml_dsa
        .sign_deterministic(&m, DOMAIN)
        .map_err(|_| anyhow::anyhow!("ML-DSA signing failed"))?;
    out.extend_from_slice(&dsa.encode());
    Ok(out)
}

/// Checks both signatures made by `sign`.
pub fn verify(bundle: &[u8], context: &str, msg: &[u8], signature: &[u8]) -> Result<()> {
    let bundle = Bundle::parse(bundle)?;
    anyhow::ensure!(signature.len() == SIGNATURE_SIZE, "bad signature length");
    let (ed, dsa) = signature.split_at(ED25519_SIGNATURE_SIZE);
    let m = signed_message(context, msg);
    let ed = ed25519_dalek::Signature::from_bytes(ed.try_into()?);
    bundle
        .ed25519
        .verify_strict(&m, &ed)
        .map_err(|_| anyhow::anyhow!("bad Ed25519 signature"))?;
    let dsa = EncodedSignature::<MlDsa65>::try_from(dsa)
        .ok()
        .and_then(|enc| ml_dsa::Signature::decode(&enc))
        .ok_or_else(|| anyhow::anyhow!("bad ML-DSA signature"))?;
    anyhow::ensure!(
        bundle.ml_dsa.verify_with_context(&m, DOMAIN, &dsa),
        "bad ML-DSA signature"
    );
    Ok(())
}

// ── Wrapping keys ────────────────────────────────────────────────────────────

/// Encrypts a 32-byte key so only `bundle`'s owner can read it. `context`
/// binds it to where it is used (so it can't be moved elsewhere).
pub fn wrap_key(bundle: &[u8], key: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    anyhow::ensure!(key.len() == 32, "key must be 32 bytes");
    let bundle = Bundle::parse(bundle)?;
    let randomness = Array(random::<{ x_wing::ENCAPSULATION_RANDOMNESS_SIZE }>());
    let (ct, shared) = bundle.x_wing.encapsulate_deterministic(&randomness);
    let kek = hkdf32(&shared, b"passman wrap v1", context);
    let nonce = random::<24>();
    let sealed = XChaCha20Poly1305::new(&kek.into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: key,
                aad: context,
            },
        )
        .map_err(|_| anyhow::anyhow!("wrapping failed"))?;
    let mut out = Vec::with_capacity(WRAPPED_KEY_SIZE);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

pub fn unwrap_key(secret: &[u8], wrapped: &[u8], context: &[u8]) -> Result<[u8; 32]> {
    anyhow::ensure!(wrapped.len() == WRAPPED_KEY_SIZE, "bad wrapped key length");
    let identity = Identity::new(secret)?;
    let (ct, rest) = wrapped.split_at(X_WING_CIPHERTEXT_SIZE);
    let (nonce, sealed) = rest.split_at(24);
    let ct = x_wing::Ciphertext::try_from(ct).map_err(|_| anyhow::anyhow!("bad ciphertext"))?;
    let shared = identity.x_wing.decapsulate(&ct);
    let kek = hkdf32(&shared, b"passman wrap v1", context);
    let key = XChaCha20Poly1305::new(&kek.into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: sealed,
                aad: context,
            },
        )
        .map_err(|_| anyhow::anyhow!("the key was wrapped for another identity"))?;
    key.try_into().map_err(|_| anyhow::anyhow!("bad key"))
}

// ── Frames ───────────────────────────────────────────────────────────────────

/// Joins byte strings, each preceded by its length (u32 little-endian).
pub fn encode_frames(frames: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(frames.iter().map(|f| f.len() + 4).sum());
    for frame in frames {
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(frame);
    }
    out
}

/// Splits what `encode_frames` made; there must be exactly `count`.
pub fn decode_frames(mut data: &[u8], count: usize) -> Result<Vec<&[u8]>> {
    let mut frames = Vec::with_capacity(count);
    while !data.is_empty() {
        anyhow::ensure!(data.len() >= 4, "truncated frame");
        let (len, rest) = data.split_at(4);
        let len = u32::from_le_bytes(len.try_into()?) as usize;
        anyhow::ensure!(rest.len() >= len, "truncated frame");
        let (frame, rest) = rest.split_at(len);
        frames.push(frame);
        data = rest;
    }
    anyhow::ensure!(frames.len() == count, "expected {count} frames");
    Ok(frames)
}

fn b64_decode(value: &str, what: &str) -> Result<Vec<u8>> {
    B64.decode(value)
        .map_err(|_| anyhow::anyhow!("{what} is not base64"))
}

pub fn b64_encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

// ── Records ──────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Member {
    pub username: String,
    /// The fingerprint of the bundle this member was verified with (base64).
    pub fingerprint: String,
    /// May change the vault's contents.
    pub write: bool,
    /// May change the member list.
    pub manage: bool,
}

/// A version of a shared vault's member list (an epoch).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordBody {
    pub v: u32,
    pub vault_id: String,
    pub seq: u64,
    /// SHA-256 of the previous record (base64), `None` for the first.
    pub prev: Option<String>,
    pub author: String,
    /// Milliseconds since the Unix epoch, as the author's clock said.
    pub time: u64,
    pub members: Vec<Member>,
    /// This epoch's secret wrapped for each member (base64).
    pub keys: BTreeMap<String, String>,
}

impl RecordBody {
    pub fn member(&self, username: &str) -> Option<&Member> {
        self.members.iter().find(|m| m.username == username)
    }
}

/// Where a member's wrapped epoch secret may be unwrapped.
pub fn epoch_key_context(vault_id: &str, seq: u64, username: &str) -> Vec<u8> {
    format!("passman epoch key v1\0{vault_id}\0{seq}\0{username}").into_bytes()
}

/// Derives a purpose's key (e.g. "tables", "history") from an epoch secret.
pub fn epoch_subkey(epoch_secret: &[u8], label: &str) -> [u8; 32] {
    hkdf32(epoch_secret, b"passman epoch v1", label.as_bytes())
}

pub fn sign_record(secret: &[u8], body: &RecordBody) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(body)?;
    let signature = sign(secret, "record", &body)?;
    Ok(encode_frames(&[&body, &signature]))
}

pub fn parse_record(wire: &[u8]) -> Result<RecordBody> {
    let frames = decode_frames(wire, 2)?;
    Ok(serde_json::from_slice(frames[0])?)
}

/// SHA-256 of a record, which the next one names as its `prev`.
pub fn record_hash(wire: &[u8]) -> String {
    b64_encode(&sha256(wire))
}

/// Checks a username has the shape the server allows (it checks the details).
fn plausible_username(username: &str) -> bool {
    !username.is_empty() && username.chars().count() <= 64
}

/// Checks `wire` is a valid next record after `prev` (`None` for a vault's
/// first record), signed by its author whose bundle is `author_bundle`, and
/// returns it. `prev` must have been checked already.
pub fn verify_record(
    prev: Option<(&RecordBody, &[u8])>,
    wire: &[u8],
    author_bundle: &[u8],
) -> Result<RecordBody> {
    let frames = decode_frames(wire, 2)?;
    let body: RecordBody = serde_json::from_slice(frames[0])?;
    anyhow::ensure!(body.v == 1, "unsupported record version");
    let signer = match prev {
        None => {
            anyhow::ensure!(body.seq == 0 && body.prev.is_none(), "not a first record");
            body.member(&body.author)
        }
        Some((prev, prev_wire)) => {
            anyhow::ensure!(body.vault_id == prev.vault_id, "record of another vault");
            anyhow::ensure!(body.seq == prev.seq + 1, "records out of order");
            anyhow::ensure!(
                body.prev.as_deref() == Some(record_hash(prev_wire).as_str()),
                "record doesn't follow the previous one"
            );
            prev.member(&body.author)
        }
    };
    let signer = signer.ok_or_else(|| anyhow::anyhow!("the author isn't a member"))?;
    anyhow::ensure!(signer.manage, "the author can't manage members");
    anyhow::ensure!(
        b64_decode(&signer.fingerprint, "fingerprint")? == fingerprint(author_bundle),
        "the author's identity doesn't match their verified fingerprint"
    );
    verify(author_bundle, "record", frames[0], frames[1])?;

    anyhow::ensure!(
        (1..=MAX_MEMBERS).contains(&body.members.len()),
        "a vault has 1 to {MAX_MEMBERS} members"
    );
    let mut names = BTreeSet::new();
    for member in &body.members {
        anyhow::ensure!(plausible_username(&member.username), "bad username");
        anyhow::ensure!(names.insert(member.username.as_str()), "duplicate member");
        anyhow::ensure!(
            b64_decode(&member.fingerprint, "fingerprint")?.len() == FINGERPRINT_SIZE,
            "bad fingerprint"
        );
    }
    anyhow::ensure!(
        body.members.iter().any(|m| m.manage),
        "a vault needs a manager"
    );
    anyhow::ensure!(
        body.keys
            .keys()
            .map(String::as_str)
            .eq(names.iter().copied()),
        "every member, and only they, must have the epoch key"
    );
    for wrapped in body.keys.values() {
        anyhow::ensure!(
            b64_decode(wrapped, "wrapped key")?.len() == WRAPPED_KEY_SIZE,
            "bad wrapped key"
        );
    }
    Ok(body)
}

// ── Versions ─────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VersionBody {
    pub v: u32,
    pub vault_id: String,
    /// The `seq` of the record whose epoch key encrypts this version.
    pub epoch: u64,
    /// Counts up across the vault's lifetime.
    pub version: u64,
    pub author: String,
    pub time: u64,
    /// SHA-256 (base64) of the tables and history ciphertexts.
    pub tables_hash: String,
    pub history_hash: String,
    /// The version a manager made when starting an epoch, re-encrypting the
    /// previous tables with the new key. A manager who can't write may only
    /// make these, and members check the tables didn't change.
    pub rekey: bool,
}

pub fn sign_version(
    secret: &[u8],
    body: &VersionBody,
    tables: &[u8],
    history: &[u8],
) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(body)?;
    let signature = sign(secret, "version", &body)?;
    Ok(encode_frames(&[&body, &signature, tables, history]))
}

/// A version without its tables, kept to read its epoch's history.
pub fn archive_of_version(version_wire: &[u8]) -> Result<Vec<u8>> {
    let f = decode_frames(version_wire, 4)?;
    Ok(encode_frames(&[f[0], f[1], f[3]]))
}

fn verify_version_frames(
    record: &RecordBody,
    body_bytes: &[u8],
    signature: &[u8],
    tables: Option<&[u8]>,
    history: &[u8],
    author_bundle: &[u8],
) -> Result<VersionBody> {
    let body: VersionBody = serde_json::from_slice(body_bytes)?;
    anyhow::ensure!(body.v == 1, "unsupported version format");
    anyhow::ensure!(body.vault_id == record.vault_id, "version of another vault");
    anyhow::ensure!(body.epoch == record.seq, "version of another epoch");
    let author = record
        .member(&body.author)
        .ok_or_else(|| anyhow::anyhow!("the author isn't a member"))?;
    anyhow::ensure!(
        if body.rekey {
            author.manage
        } else {
            author.write
        },
        "the author can't change this vault"
    );
    anyhow::ensure!(
        b64_decode(&author.fingerprint, "fingerprint")? == fingerprint(author_bundle),
        "the author's identity doesn't match their verified fingerprint"
    );
    verify(author_bundle, "version", body_bytes, signature)?;
    if let Some(tables) = tables {
        anyhow::ensure!(
            b64_encode(&sha256(tables)) == body.tables_hash,
            "tables don't match the signed hash"
        );
    }
    anyhow::ensure!(
        b64_encode(&sha256(history)) == body.history_hash,
        "history doesn't match the signed hash"
    );
    Ok(body)
}

/// Checks a version of the epoch started by `record` (already checked).
pub fn verify_version(
    record: &RecordBody,
    wire: &[u8],
    author_bundle: &[u8],
) -> Result<VersionBody> {
    let f = decode_frames(wire, 4)?;
    verify_version_frames(record, f[0], f[1], Some(f[2]), f[3], author_bundle)
}

/// Checks an archived version (see `archive_of_version`).
pub fn verify_archive(
    record: &RecordBody,
    wire: &[u8],
    author_bundle: &[u8],
) -> Result<VersionBody> {
    let f = decode_frames(wire, 3)?;
    verify_version_frames(record, f[0], f[1], None, f[2], author_bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct User {
        name: &'static str,
        secret: [u8; 32],
        bundle: Vec<u8>,
    }

    fn user(name: &'static str) -> User {
        let secret = generate_identity_secret();
        User {
            name,
            bundle: identity_bundle(&secret).unwrap(),
            secret,
        }
    }

    fn member(u: &User, write: bool, manage: bool) -> Member {
        Member {
            username: u.name.to_string(),
            fingerprint: b64_encode(&fingerprint(&u.bundle)),
            write,
            manage,
        }
    }

    fn record(
        prev: Option<&[u8]>,
        seq: u64,
        author: &User,
        members: &[(&User, bool, bool)],
    ) -> (Vec<u8>, [u8; 32]) {
        let epoch_secret = generate_epoch_secret();
        let body = RecordBody {
            v: 1,
            vault_id: "v".repeat(32),
            seq,
            prev: prev.map(record_hash),
            author: author.name.to_string(),
            time: 0,
            members: members.iter().map(|(u, w, m)| member(u, *w, *m)).collect(),
            keys: members
                .iter()
                .map(|(u, ..)| {
                    let ctx = epoch_key_context(&"v".repeat(32), seq, u.name);
                    let wrapped = wrap_key(&u.bundle, &epoch_secret, &ctx).unwrap();
                    (u.name.to_string(), b64_encode(&wrapped))
                })
                .collect(),
        };
        (sign_record(&author.secret, &body).unwrap(), epoch_secret)
    }

    #[test]
    fn identity_is_derived_from_its_secret() {
        let a = user("a");
        assert_eq!(a.bundle.len(), BUNDLE_SIZE);
        assert_eq!(identity_bundle(&a.secret).unwrap(), a.bundle);
        assert_ne!(user("b").bundle, a.bundle);
    }

    #[test]
    fn signatures_need_both_halves_and_the_right_context() {
        let a = user("a");
        let sig = sign(&a.secret, "record", b"msg").unwrap();
        assert_eq!(sig.len(), SIGNATURE_SIZE);
        verify(&a.bundle, "record", b"msg", &sig).unwrap();
        assert!(verify(&a.bundle, "version", b"msg", &sig).is_err());
        assert!(verify(&a.bundle, "record", b"msh", &sig).is_err());
        assert!(verify(&user("b").bundle, "record", b"msg", &sig).is_err());
        for i in [0, ED25519_SIGNATURE_SIZE + 10] {
            let mut bad = sig.clone();
            bad[i] ^= 1;
            assert!(verify(&a.bundle, "record", b"msg", &bad).is_err());
        }
    }

    #[test]
    fn wrapped_keys_open_only_for_their_owner_and_context() {
        let a = user("a");
        let key = random::<32>();
        let wrapped = wrap_key(&a.bundle, &key, b"ctx").unwrap();
        assert_eq!(wrapped.len(), WRAPPED_KEY_SIZE);
        assert_eq!(unwrap_key(&a.secret, &wrapped, b"ctx").unwrap(), key);
        assert!(unwrap_key(&a.secret, &wrapped, b"other").is_err());
        assert!(unwrap_key(&user("b").secret, &wrapped, b"ctx").is_err());
    }

    #[test]
    fn safety_numbers_match_on_both_sides() {
        let (a, b) = (user("a"), user("b"));
        let (fa, fb) = (fingerprint(&a.bundle), fingerprint(&b.bundle));
        let n = safety_number("a", &fa, "b", &fb);
        assert_eq!(n, safety_number("b", &fb, "a", &fa));
        assert_eq!(n.len(), 12 * 5 + 11);
        assert_ne!(
            n,
            safety_number("a", &fa, "b", &fingerprint(&user("c").bundle))
        );
    }

    #[test]
    fn record_chain_rules() {
        let (a, b, c) = (user("a"), user("b"), user("c"));
        let (r0, _) = record(None, 0, &a, &[(&a, true, true)]);
        let b0 = verify_record(None, &r0, &a.bundle).unwrap();
        // the first record must be signed by a manager in it
        let (bad, _) = record(None, 0, &b, &[(&a, true, true)]);
        assert!(verify_record(None, &bad, &b.bundle).is_err());

        let (r1, secret1) = record(Some(&r0), 1, &a, &[(&a, true, true), (&b, true, false)]);
        let b1 = verify_record(Some((&b0, &r0)), &r1, &a.bundle).unwrap();
        // each member can unwrap the epoch key, in this vault and epoch only
        let wrapped = B64.decode(&b1.keys["b"]).unwrap();
        assert_eq!(
            unwrap_key(
                &b.secret,
                &wrapped,
                &epoch_key_context(&b1.vault_id, 1, "b")
            )
            .unwrap(),
            secret1
        );
        assert!(
            unwrap_key(
                &b.secret,
                &wrapped,
                &epoch_key_context(&b1.vault_id, 2, "b")
            )
            .is_err()
        );

        // b can't manage, so can't add c
        let (r2, _) = record(
            Some(&r1),
            2,
            &b,
            &[(&a, true, true), (&b, true, true), (&c, true, true)],
        );
        assert!(verify_record(Some((&b1, &r1)), &r2, &b.bundle).is_err());
        // nor can a record skip ahead or claim another predecessor
        let (r2, _) = record(Some(&r0), 2, &a, &[(&a, true, true)]);
        assert!(verify_record(Some((&b1, &r1)), &r2, &a.bundle).is_err());
        // a signature from a key other than the verified one is refused
        let (r2, _) = record(Some(&r1), 2, &a, &[(&a, true, true)]);
        assert!(verify_record(Some((&b1, &r1)), &r2, &c.bundle).is_err());
        verify_record(Some((&b1, &r1)), &r2, &a.bundle).unwrap();
    }

    #[test]
    fn versions_need_write_permission_unless_rekeying() {
        let (a, b) = (user("a"), user("b"));
        let (r0, _) = record(None, 0, &a, &[(&a, false, true), (&b, true, false)]);
        let rec = verify_record(None, &r0, &a.bundle).unwrap();
        let body = |author: &str, rekey: bool, tables: &[u8], history: &[u8]| VersionBody {
            v: 1,
            vault_id: rec.vault_id.clone(),
            epoch: 0,
            version: 1,
            author: author.to_string(),
            time: 0,
            tables_hash: b64_encode(&sha256(tables)),
            history_hash: b64_encode(&sha256(history)),
            rekey,
        };
        let v = sign_version(&b.secret, &body("b", false, b"t", b"h"), b"t", b"h").unwrap();
        assert_eq!(verify_version(&rec, &v, &b.bundle).unwrap().author, "b");
        // the archive keeps the history and the signature checks without the tables
        let archive = archive_of_version(&v).unwrap();
        verify_archive(&rec, &archive, &b.bundle).unwrap();
        // tampered contents
        let tampered = encode_frames(&{
            let f = decode_frames(&v, 4).unwrap();
            [f[0], f[1], b"T".as_slice(), f[3]]
        });
        assert!(verify_version(&rec, &tampered, &b.bundle).is_err());
        // a can't write, but may rekey
        let v = sign_version(&a.secret, &body("a", false, b"t", b"h"), b"t", b"h").unwrap();
        assert!(verify_version(&rec, &v, &a.bundle).is_err());
        let v = sign_version(&a.secret, &body("a", true, b"t", b"h"), b"t", b"h").unwrap();
        verify_version(&rec, &v, &a.bundle).unwrap();
        // b can write but not rekey
        let v = sign_version(&b.secret, &body("b", true, b"t", b"h"), b"t", b"h").unwrap();
        assert!(verify_version(&rec, &v, &b.bundle).is_err());
    }
}

import init, {
  derive_key,
  hash_size,
  seal,
  unseal,
  x25519_generate_secret_key,
  x25519_public_key,
  xchacha20_decrypt,
  xchacha20_encrypt,
  xchacha20_generate_nonce,
  xchacha20_key_size,
  xchacha20_nonce_size,
} from "passman_crypto";

// These are set by initWasm() before any function is called.
export let SALT_LEN: number;
export let XCHACHA20_KEY_SIZE: number;
export let XCHACHA20_NONCE_SIZE: number;

/**
 * Must be awaited once (e.g. via top-level await in main.ts) before calling
 * any other export from this module.  Using --target web means the wasm
 * module is fetched/instantiated asynchronously; Parcel rewrites the
 * `new URL(...)` inside init() to point at the hashed emitted asset.
 */
export async function initWasm(): Promise<void> {
  await init();
  SALT_LEN = hash_size();
  XCHACHA20_KEY_SIZE = xchacha20_key_size();
  XCHACHA20_NONCE_SIZE = xchacha20_nonce_size();
}

/** Derives a SALT_LEN-byte key from a password string and a SALT_LEN-byte salt. */
export function deriveKey(password: string, salt: Uint8Array): Uint8Array {
  if (salt.byteLength !== SALT_LEN) {
    throw new Error(`salt must be ${SALT_LEN} bytes, got ${salt.byteLength}`);
  }
  return derive_key(password, salt);
}

/**
 * Encrypts `plaintext` with XChaCha20-Poly1305.  The returned blob has the
 * layout expected by the server and `decryptBlob`:
 *   nonce (XCHACHA20_NONCE_SIZE bytes) || ciphertext+tag
 *
 * The encryptionKey may be longer than XCHACHA20_KEY_SIZE; only the first
 * XCHACHA20_KEY_SIZE bytes are used (matching `decryptBlob`'s behaviour).
 */
export function encryptBlob(
  encryptionKey: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array<ArrayBuffer> {
  const nonce = xchacha20_generate_nonce();
  const key = encryptionKey.slice(0, XCHACHA20_KEY_SIZE);
  const ciphertext = xchacha20_encrypt(key, nonce, plaintext);
  const blob = new Uint8Array(nonce.byteLength + ciphertext.byteLength);
  blob.set(nonce, 0);
  blob.set(ciphertext, nonce.byteLength);
  return blob;
}

/**
 * Decrypts a blob produced by xchacha20_encrypt where the layout is:
 *   nonce (XCHACHA20_NONCE_SIZE bytes) || ciphertext+tag
 *
 * The encryptionKey may be longer than XCHACHA20_KEY_SIZE (e.g. 64 bytes from
 * Argon2); only the first XCHACHA20_KEY_SIZE bytes are used.
 */
export function decryptBlob(
  encryptionKey: Uint8Array,
  blob: Uint8Array,
): Uint8Array {
  if (blob.byteLength < XCHACHA20_NONCE_SIZE) {
    throw new Error(
      `blob too short: ${blob.byteLength} < ${XCHACHA20_NONCE_SIZE}`,
    );
  }
  const nonce = blob.slice(0, XCHACHA20_NONCE_SIZE);
  const ciphertext = blob.slice(XCHACHA20_NONCE_SIZE);
  const key = encryptionKey.slice(0, XCHACHA20_KEY_SIZE);
  return xchacha20_decrypt(key, nonce, ciphertext);
}

/** Generates a key pair for sharing vaults: others seal vault keys to the
 *  public key, and only the secret key opens them. */
export function generateSharingKeyPair(): {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
} {
  const secretKey = x25519_generate_secret_key();
  return { publicKey: x25519_public_key(secretKey), secretKey };
}

/** Encrypts `plaintext` so only the holder of `publicKey`'s secret key can
 *  read it (a sealed box). */
export function sealTo(
  publicKey: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  return seal(publicKey, plaintext);
}

/** Opens a box from `sealTo` (throws if it was sealed to another key). */
export function unsealWith(
  secretKey: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  return unseal(secretKey, ciphertext);
}

/** URL-safe base64 without padding, as the server expects. */
export function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function fromBase64Url(text: string): Uint8Array<ArrayBuffer> {
  const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
}

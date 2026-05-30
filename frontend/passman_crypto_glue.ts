import init, {
  derive_key,
  hash_size,
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

// Biometric unlock. An account's keys (what its password would derive) are
// stored on the device encrypted twice:
//
//  - inner layer: an AES-GCM key derived (HKDF) from a passkey's PRF output.
//    Getting that output takes the device's biometrics, or its passcode: a web
//    page can require that the user is verified, but not how.
//  - outer layer: a non-extractable AES-GCM key created on this device, kept
//    only in its IndexedDB. Apple and Google sync passkeys to the user's other
//    devices; with this layer the passkey alone can't decrypt anything.
//
// Both layers are bound to the account id (additional authenticated data).
// The rest of the app only uses the KeyProtector interface, so a native app
// could keep the keys in the Secure Enclave / Android Keystore instead.

import {
  deleteUnlockKey,
  getUnlockKey,
  putUnlockKey,
  type StoredUnlockKey,
} from "./deviceStore";

/** What the password would otherwise derive. */
export interface UnlockSecrets {
  authKeyB64: string;
  encryptionKey: Uint8Array;
}

export interface ProtectionStatus {
  /** False after the password changed (or an interrupted setup), until
   *  `protect` runs again. */
  current: boolean;
  /** Whether the key that biometrics release is synced to the user's other
   *  devices; null if unknown. */
  synced: boolean | null;
}

export interface KeyProtector {
  /** Whether this device may support it (setting it up can still fail). */
  isSupported(): Promise<boolean>;
  /** Biometric unlock's state for the account, or null when it's off. */
  status(accountId: string): Promise<ProtectionStatus | null>;
  /** Protects the account's keys, reusing its existing setup if there is
   *  one. Asks for biometrics. */
  protect(
    accountId: string,
    label: string,
    secrets: UnlockSecrets,
  ): Promise<void>;
  /** Recovers the account's keys. Asks for biometrics. */
  unlock(accountId: string): Promise<UnlockSecrets>;
  /** Marks the stored keys out of date, e.g. after a password change. */
  invalidate(accountId: string): Promise<void>;
  /** Turns biometric unlock off for the account. */
  remove(accountId: string): Promise<void>;
}

/** An error whose message can be shown to the user as is. */
export class UnlockError extends Error {}

/** A message for an error from a KeyProtector. */
export function unlockErrorMessage(e: unknown): string {
  if (e instanceof UnlockError) return e.message;
  if (e instanceof DOMException && e.name === "NotAllowedError")
    return "Biometric check cancelled or timed out.";
  return `Biometric unlock failed: ${e}`;
}

// ── WebAuthn PRF implementation ─────────────────────────────────────────────

interface PasskeyUnlockKey extends StoredUnlockKey {
  credentialId: Uint8Array<ArrayBuffer>;
  /** Input to the passkey's PRF; random per account. */
  prfSalt: Uint8Array<ArrayBuffer>;
  /** The outer layer's key (non-extractable). */
  deviceKey: CryptoKey;
  synced: boolean | null;
  /** The encrypted keys; null when out of date. */
  wrapped: {
    innerIv: Uint8Array<ArrayBuffer>;
    outerIv: Uint8Array<ArrayBuffer>;
    ciphertext: ArrayBuffer;
  } | null;
}

const HKDF_INFO = new TextEncoder().encode("passman biometric unlock v1");
const TIMEOUT_MS = 120_000;
/** Authenticator data flag: the credential may be backed up (synced). */
const FLAG_BACKUP_ELIGIBLE = 0x08;

function random(length: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(length));
}

function toBytes(source: BufferSource): Uint8Array<ArrayBuffer> {
  const view = ArrayBuffer.isView(source)
    ? new Uint8Array(source.buffer, source.byteOffset, source.byteLength)
    : new Uint8Array(source);
  return new Uint8Array(view);
}

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function prfOutput(
  credential: PublicKeyCredential,
): Uint8Array<ArrayBuffer> | null {
  const first = credential.getClientExtensionResults().prf?.results?.first;
  return first ? toBytes(first) : null;
}

/** Whether the authenticator data says the credential may sync. */
function backupEligible(authenticatorData: ArrayBuffer | undefined) {
  if (authenticatorData == null || authenticatorData.byteLength < 33)
    return null;
  return (new Uint8Array(authenticatorData)[32] & FLAG_BACKUP_ELIGIBLE) !== 0;
}

async function innerKey(prf: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey("raw", prf, "HKDF", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: HKDF_INFO },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function encodeSecrets(secrets: UnlockSecrets): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(
    JSON.stringify({
      authKeyB64: secrets.authKeyB64,
      encryptionKey: Array.from(secrets.encryptionKey),
    }),
  );
}

function decodeSecrets(plaintext: ArrayBuffer): UnlockSecrets {
  const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as {
    authKeyB64: string;
    encryptionKey: number[];
  };
  return {
    authKeyB64: parsed.authKeyB64,
    encryptionKey: new Uint8Array(parsed.encryptionKey),
  };
}

async function wrap(
  record: PasskeyUnlockKey,
  prf: Uint8Array<ArrayBuffer>,
  secrets: UnlockSecrets,
): Promise<NonNullable<PasskeyUnlockKey["wrapped"]>> {
  const additionalData = new TextEncoder().encode(record.id);
  const innerIv = random(12);
  const outerIv = random(12);
  const inner = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: innerIv, additionalData },
    await innerKey(prf),
    encodeSecrets(secrets),
  );
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: outerIv, additionalData },
    record.deviceKey,
    inner,
  );
  return { innerIv, outerIv, ciphertext };
}

async function unwrap(
  record: PasskeyUnlockKey,
  prf: Uint8Array<ArrayBuffer>,
): Promise<UnlockSecrets> {
  const { wrapped } = record;
  if (wrapped == null)
    throw new UnlockError(
      "Biometric unlock needs to be confirmed again; unlock with the password.",
    );
  const additionalData = new TextEncoder().encode(record.id);
  try {
    const inner = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: wrapped.outerIv, additionalData },
      record.deviceKey,
      wrapped.ciphertext,
    );
    return decodeSecrets(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: wrapped.innerIv, additionalData },
        await innerKey(prf),
        inner,
      ),
    );
  } catch {
    throw new UnlockError(
      "The keys stored for biometric unlock couldn't be decrypted; unlock with the password.",
    );
  }
}

/** Asks the passkey for its PRF output (biometrics). */
async function evaluate(
  record: PasskeyUnlockKey,
): Promise<Uint8Array<ArrayBuffer>> {
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: random(32),
      allowCredentials: [{ type: "public-key", id: record.credentialId }],
      userVerification: "required",
      timeout: TIMEOUT_MS,
      extensions: { prf: { eval: { first: record.prfSalt } } },
    },
  })) as PublicKeyCredential | null;
  const output = assertion && prfOutput(assertion);
  if (output == null)
    throw new UnlockError(
      "The passkey didn't return the secret biometric unlock needs.",
    );
  return output;
}

/** Tells the passkey provider (if it supports it) that a passkey is no longer
 *  used, so it can delete it. */
async function discardPasskey(credentialId: Uint8Array): Promise<void> {
  const signal = (
    PublicKeyCredential as unknown as {
      signalUnknownCredential?: (options: {
        rpId: string;
        credentialId: string;
      }) => Promise<void>;
    }
  ).signalUnknownCredential;
  try {
    await signal?.call(PublicKeyCredential, {
      rpId: location.hostname,
      credentialId: base64url(credentialId),
    });
  } catch {
    // best effort
  }
}

/** Records read so far. Once `status` has read an account's record, `unlock`
 *  and `protect` start the passkey prompt without waiting for IndexedDB, so it
 *  directly follows the click (Safari requires that). */
const records = new Map<string, PasskeyUnlockKey | null>();

async function load(accountId: string): Promise<PasskeyUnlockKey | null> {
  if (!records.has(accountId))
    records.set(
      accountId,
      (await getUnlockKey<PasskeyUnlockKey>(accountId)) ?? null,
    );
  return records.get(accountId)!;
}

async function store(record: PasskeyUnlockKey): Promise<void> {
  await putUnlockKey(record);
  records.set(record.id, record);
}

const passkeyProtector: KeyProtector = {
  async isSupported() {
    if (typeof PublicKeyCredential === "undefined" || !isSecureContext)
      return false;
    try {
      if (typeof PublicKeyCredential.getClientCapabilities === "function") {
        const capabilities = await PublicKeyCredential.getClientCapabilities();
        if (capabilities["extension:prf"] === false) return false;
      }
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch {
      return false;
    }
  },

  async status(accountId) {
    const record = await load(accountId);
    return record && { current: record.wrapped != null, synced: record.synced };
  },

  async protect(accountId, label, secrets) {
    let record = await load(accountId);
    let prf: Uint8Array<ArrayBuffer> | null = null;
    if (record == null) {
      const prfSalt = random(32);
      const credential = (await navigator.credentials.create({
        publicKey: {
          rp: { name: "Passman" },
          user: { id: random(16), name: label, displayName: label },
          challenge: random(32),
          pubKeyCredParams: [
            { type: "public-key", alg: -7 },
            { type: "public-key", alg: -257 },
          ],
          authenticatorSelection: {
            authenticatorAttachment: "platform",
            residentKey: "required",
            userVerification: "required",
          },
          attestation: "none",
          timeout: TIMEOUT_MS,
          extensions: { prf: { eval: { first: prfSalt } } },
        },
      })) as PublicKeyCredential | null;
      if (credential == null) throw new UnlockError("No passkey was created.");
      const credentialId = toBytes(credential.rawId);
      const prfResult = credential.getClientExtensionResults().prf;
      if (!prfResult?.enabled && !prfResult?.results) {
        await discardPasskey(credentialId);
        throw new UnlockError(
          "This device's passkeys don't support the PRF extension that biometric unlock needs.",
        );
      }
      const response = credential.response as AuthenticatorAttestationResponse;
      record = {
        id: accountId,
        credentialId,
        prfSalt,
        deviceKey: await crypto.subtle.generateKey(
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"],
        ),
        synced: backupEligible(
          typeof response.getAuthenticatorData === "function"
            ? response.getAuthenticatorData()
            : undefined,
        ),
        wrapped: null,
      };
      // stored before asking for the PRF output separately (below), so if
      // that is cancelled, finishing later reuses this passkey
      await store(record);
      prf = prfOutput(credential);
    }
    // some platforms only return the PRF output when the passkey is used
    prf ??= await evaluate(record);
    await store({ ...record, wrapped: await wrap(record, prf, secrets) });
  },

  async unlock(accountId) {
    const record = await load(accountId);
    if (record?.wrapped == null)
      throw new UnlockError(
        "Biometric unlock isn't set up for this account; unlock with the password.",
      );
    return unwrap(record, await evaluate(record));
  },

  async invalidate(accountId) {
    const record = await load(accountId);
    if (record?.wrapped != null) await store({ ...record, wrapped: null });
  },

  async remove(accountId) {
    const record = await load(accountId);
    await deleteUnlockKey(accountId);
    records.set(accountId, null);
    if (record) await discardPasskey(record.credentialId);
  },
};

export const keyProtector: KeyProtector = passkeyProtector;

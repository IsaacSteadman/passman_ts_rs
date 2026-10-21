// Time-based one-time passwords (TOTP, RFC 6238) from a Base32 MFA key, with
// the usual authenticator app settings: HMAC-SHA1, 6 digits, a new code
// every 30 seconds.

export const OTP_PERIOD_SECONDS = 30;
const OTP_DIGITS = 6;

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** Decodes a Base32 key, ignoring case, spaces and "=" padding. */
export function decodeBase32(key: string): Uint8Array<ArrayBuffer> {
  const chars = key.replace(/[\s=]/g, "").toUpperCase();
  const bytes = new Uint8Array(Math.floor((chars.length * 5) / 8));
  let buffer = 0;
  let bits = 0;
  let length = 0;
  for (const char of chars) {
    const value = BASE32_ALPHABET.indexOf(char);
    if (value < 0) throw new Error(`"${char}" isn't a Base32 character`);
    buffer = ((buffer << 5) | value) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes[length++] = buffer >> bits;
    }
  }
  return bytes;
}

/** The code for `mfaKey` at the time `now` (milliseconds since the epoch). */
export async function generateOtp(
  mfaKey: string,
  now: number = Date.now(),
): Promise<string> {
  const counter = Math.floor(now / 1000 / OTP_PERIOD_SECONDS);
  const message = new Uint8Array(8);
  new DataView(message.buffer).setBigUint64(0, BigInt(counter));

  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase32(mfaKey),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const hmac = new DataView(await crypto.subtle.sign("HMAC", key, message));
  // dynamic truncation (RFC 4226 section 5.3)
  const offset = hmac.getUint8(hmac.byteLength - 1) & 0xf;
  const binary = hmac.getUint32(offset) & 0x7fffffff;
  return String(binary % 10 ** OTP_DIGITS).padStart(OTP_DIGITS, "0");
}

/** Seconds until the code changes, from `OTP_PERIOD_SECONDS` down to 1. */
export function otpSecondsRemaining(now: number = Date.now()): number {
  return OTP_PERIOD_SECONDS - (Math.floor(now / 1000) % OTP_PERIOD_SECONDS);
}

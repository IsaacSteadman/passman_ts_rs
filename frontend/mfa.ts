export const subtle: SubtleCrypto = crypto.subtle || crypto["webkitSubtle"];
const CODE_0 = "0".charCodeAt(0);
const CODE_A = "A".charCodeAt(0) - 10;
const CODE_a = "a".charCodeAt(0) - 10;

export function hexStringToUint8Array(str: string): Uint8Array {
  if (str.length & 1) throw new Error("expected even length");
  const arr = new Uint8Array(str.length >> 1);
  for (let i = 0, j = 0; i < str.length; i += 2, ++j) {
    const msd = str.charCodeAt(i);
    let msv = msd - CODE_0;
    if (msv >= 10) {
      msv = msd - CODE_A;
      if (msv >= 16) {
        msv = msd - CODE_a;
      } else if (msv < 10) {
        msv = -1;
      }
    }
    if (msv < 0 || msv >= 16) {
      throw new Error(`bad char at pos str.charAt(${i}) = '${str.charAt(i)}'`);
    }
    const lsd = str.charCodeAt(i + 1);
    let lsv = lsd - CODE_0;
    if (lsv >= 10) {
      lsv = lsd - CODE_A;
      if (lsv >= 16) {
        lsv = lsd - CODE_a;
      } else if (lsv < 10) {
        lsv = -1;
      }
    }
    if (lsv < 0 || lsv >= 16) {
      throw new Error(
        `bad char at pos str.charAt(${i + 1}) = '${str.charAt(i + 1)}'`,
      );
    }
    arr[j] = (msv << 4) | lsv;
  }
  return arr;
}
const digits = "0123456789abcdef";
export function arrayBufferToHexString(buf: ArrayBuffer): string {
  const arr = new Uint8Array(buf);
  let str = "";
  for (let i = 0; i < arr.length; ++i) {
    str += digits.charAt(arr[i] >> 4) + digits.charAt(arr[i] & 0xf);
  }
  return str;
}

function dec2hex(s: number): string {
  return (s < 15.5 ? "0" : "") + Math.round(s).toString(16);
}
function hex2dec(s: string): number {
  return parseInt(s, 16);
}

const base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32tohex(base32: string) {
  let bits = "";
  let hex = "";

  for (let i = 0; i < base32.length; i++) {
    const val = base32chars.indexOf(base32.charAt(i).toUpperCase());
    bits += leftpad(val.toString(2), 5, "0");
  }

  for (let i = 0; i + 4 <= bits.length; i += 4) {
    const chunk = bits.substring(i, i + 4);
    hex = hex + parseInt(chunk, 2).toString(16);
  }
  return hex;
}

function leftpad(str: string, len: number, pad: string) {
  if (len + 1 >= str.length) {
    str = Array(len + 1 - str.length).join(pad) + str;
  }
  return str;
}

export async function generateOtp(mfaKey: string) {
  const key = base32tohex(mfaKey);
  const epoch = Math.round(new Date().getTime() / 1000.0);
  const time = leftpad(dec2hex(Math.floor(epoch / 30)), 16, "0");

  const importedKey = await subtle.importKey(
    "raw",
    hexStringToUint8Array(key),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );

  const hmacArr = await subtle.sign(
    "HMAC",
    importedKey,
    hexStringToUint8Array(time),
  );
  const hmac = arrayBufferToHexString(hmacArr);

  var offset = hex2dec(hmac.substring(hmac.length - 1));

  var otp =
    (hex2dec(hmac.substring(offset * 2, offset * 2 + 8)) &
      hex2dec("7fffffff")) +
    "";
  otp = otp.substring(otp.length - 6, otp.length);

  return otp;
}

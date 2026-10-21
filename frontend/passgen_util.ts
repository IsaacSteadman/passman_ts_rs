const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER = "abcdefghijklmnopqrstuvwxyz";
const DIGITS = "0123456789";

export interface PassgenOptions {
  symbols: string; // extra symbol characters allowed
  lettersAllowed: "all" | "only-lower" | "only-upper";
  mustUpper: boolean;
  mustLower: boolean;
  mustDigit: boolean;
  mustSymbol: boolean;
  canSpaces: boolean;
}

export type PassgenLength =
  { type: "nchars"; nChars: number } | { type: "bits"; nBits: number };

export function estimateBits(nChars: number, options: PassgenOptions): number {
  let nBits = 0;
  if (nChars <= 0) {
    return nBits;
  } else if (options.mustUpper) {
    nBits += Math.log2(26);
    --nChars;
  }
  if (nChars <= 0) {
    return nBits;
  } else if (options.mustLower) {
    nBits += Math.log2(26);
    --nChars;
  }
  if (nChars <= 0) {
    return nBits;
  } else if (options.mustDigit) {
    nBits += Math.log2(10);
    --nChars;
  }
  if (nChars <= 0) {
    return nBits;
  } else if (options.mustSymbol) {
    nBits += Math.log2(options.symbols.length);
    --nChars;
  }

  const charSetSize =
    10 +
    (options.lettersAllowed === "all" ? 52 : 26) +
    (options.canSpaces ? 1 : 0) +
    options.symbols.length;
  nBits += nChars * Math.log2(charSetSize);
  return nBits;
}

export function estimateChars(bits: number, options: PassgenOptions): number {
  let nChars = 0;
  if (options.mustUpper) {
    bits -= Math.log2(26);
    ++nChars;
  }
  if (options.mustLower) {
    bits -= Math.log2(26);
    ++nChars;
  }
  if (options.mustDigit) {
    bits -= Math.log2(10);
    ++nChars;
  }
  if (options.mustSymbol) {
    bits -= Math.log2(options.symbols.length);
    ++nChars;
  }
  const charSetSize =
    10 +
    (options.lettersAllowed === "all" ? 52 : 26) +
    (options.canSpaces ? 1 : 0) +
    options.symbols.length;
  nChars += bits / Math.log2(charSetSize);
  return nChars;
}

function randomBits(nBits: number): bigint {
  const nBytes = Math.ceil(nBits / 8);
  const randomBytes = new Uint8Array(nBytes);
  crypto.getRandomValues(randomBytes);
  let result = 0n;
  for (let i = 0; i < nBytes; i++) {
    result = (result << 8n) | BigInt(randomBytes[i]);
  }
  // Mask off any excess bits in the most significant byte
  const excessBits = nBytes * 8 - nBits;
  if (excessBits > 0) {
    result = result & ((1n << BigInt(nBits)) - 1n);
  }
  return result;
}

function divmodpick(
  n: bigint,
  from: string,
  push: string[],
  idx: number,
): bigint {
  const divisor = BigInt(from.length);
  push[idx] = from[Number(n % divisor)];
  return n / divisor;
}

export function passgen(
  options: PassgenOptions,
  length: PassgenLength,
): string {
  const [nBits, nChars] =
    length.type === "nchars"
      ? [Math.ceil(estimateBits(length.nChars, options)), length.nChars]
      : [length.nBits, Math.ceil(estimateChars(length.nBits, options))];
  let n = randomBits(nBits);
  const chars: string[] = Array(nChars).fill(" ");
  let i = 0;
  if (options.mustUpper && i < chars.length) {
    n = divmodpick(n, UPPER, chars, i++);
  }
  if (options.mustLower && i < chars.length) {
    n = divmodpick(n, LOWER, chars, i++);
  }
  if (options.mustDigit && i < chars.length) {
    n = divmodpick(n, DIGITS, chars, i++);
  }
  if (options.mustSymbol && i < chars.length) {
    n = divmodpick(n, options.symbols, chars, i++);
  }
  const remainingCharSet =
    { all: UPPER + LOWER, "only-upper": UPPER, "only-lower": LOWER }[
      options.lettersAllowed
    ] +
    DIGITS +
    options.symbols +
    (options.canSpaces ? " " : "");
  while (i < chars.length) {
    n = divmodpick(n, remainingCharSet, chars, i++);
  }
  return chars.join("");
}

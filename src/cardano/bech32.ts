/**
 * bech32 (BIP-173) DECODE — inline, no deps, for Cardano Shelley addresses
 * (`addr1…`, `stake1…`, and their `addr_test1…` / `stake_test1…` testnet
 * forms). Cardano uses plain bech32 (constant 1), but its addresses exceed the
 * 90-char BIP-173 limit, so this decoder does NOT enforce that bound (Cardano's
 * CIP-19 explicitly relaxes it). Verification-only: we decode the claimed
 * address to its raw bytes and compare the embedded key credential against
 * blake2b-224(pubkey). Fail closed — any malformation returns null.
 *
 * Mirrors go/walletconnect/cardano_bech32.go byte-for-byte.
 */

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32_CONST = 1;

function polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((top >>> i) & 1) chk ^= GEN[i]!;
    }
  }
  return chk >>> 0;
}

function hrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >>> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
  return out;
}

/** 5-bit groups → 8-bit bytes (frombits=5, tobits=8, pad=false), strict. */
function convert5to8(data: number[]): Uint8Array | null {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  for (const value of data) {
    if (value < 0 || value >>> 5 !== 0) return null;
    acc = ((acc << 5) | value) & 0xffffffff;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      out.push((acc >>> bits) & 0xff);
    }
  }
  // Per BIP-173: leftover bits must be < 5 and the pad bits must be zero.
  if (bits >= 5) return null;
  if ((acc << (8 - bits)) & 0xff) return null;
  return Uint8Array.from(out);
}

/** 8-bit bytes → 5-bit groups (frombits=8, tobits=5, pad=true). */
function convert8to5(data: Uint8Array): number[] | null {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  for (const value of data) {
    if (value < 0 || value >>> 8 !== 0) return null;
    acc = ((acc << 8) | value) & 0xffffffff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out.push((acc >>> bits) & 31);
    }
  }
  if (bits > 0) out.push((acc << (5 - bits)) & 31);
  return out;
}

function createChecksum(hrp: string, data5: number[]): number[] {
  const mod = polymod(hrpExpand(hrp).concat(data5).concat([0, 0, 0, 0, 0, 0])) ^ BECH32_CONST;
  const out: number[] = [];
  for (let i = 0; i < 6; i++) out.push((mod >>> (5 * (5 - i))) & 31);
  return out;
}

/**
 * Encode raw address bytes to a bech32 string under `hrp` (plain bech32; no
 * length limit, per CIP-19). Returns null on invalid input. Browser-side: the
 * connector uses it to render a CIP-30 hex address as `addr1…`/`stake1…`.
 */
export function bech32Encode(hrp: string, data: Uint8Array): string | null {
  const data5 = convert8to5(data);
  if (data5 === null) return null;
  const combined = data5.concat(createChecksum(hrp, data5));
  let out = hrp + '1';
  for (const d of combined) {
    if (d < 0 || d > 31) return null;
    out += CHARSET[d];
  }
  return out;
}

/** A decoded bech32 string: human-readable part + the 8-bit data payload. */
export interface Bech32Decoded {
  hrp: string;
  data: Uint8Array;
}

/**
 * Decode a bech32 string into its hrp and 8-bit payload, validating the
 * checksum. Returns null on any malformation (bad case, bad char, bad
 * separator, bad checksum, bad padding) — fail closed.
 */
export function bech32Decode(addr: string): Bech32Decoded | null {
  // Mixed case is invalid; normalize to lower after the case check.
  const lower = addr.toLowerCase();
  const upper = addr.toUpperCase();
  if (addr !== lower && addr !== upper) return null;
  const s = lower;

  const sep = s.lastIndexOf('1');
  if (sep < 1 || sep + 7 > s.length) return null; // hrp >=1, checksum 6 chars
  const hrp = s.slice(0, sep);
  const dataPart = s.slice(sep + 1);

  for (let i = 0; i < hrp.length; i++) {
    const c = hrp.charCodeAt(i);
    if (c < 33 || c > 126) return null;
  }

  const data5: number[] = [];
  for (let i = 0; i < dataPart.length; i++) {
    const idx = CHARSET.indexOf(dataPart[i]!);
    if (idx === -1) return null;
    data5.push(idx);
  }

  // Verify checksum (plain bech32; Cardano never uses bech32m).
  if (polymod(hrpExpand(hrp).concat(data5)) !== BECH32_CONST) return null;

  // Strip the 6-symbol checksum, convert the rest 5→8.
  const payload5 = data5.slice(0, data5.length - 6);
  const bytes = convert5to8(payload5);
  if (bytes === null) return null;
  return { hrp, data: bytes };
}

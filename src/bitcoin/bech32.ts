/**
 * bech32 (BIP-173) and bech32m (BIP-350) segwit address encoding — inline, no
 * deps. Encode-only: we derive an address from a recovered pubkey and compare
 * it against the claimed `proof.address` string, so we never need to decode.
 *
 * A SegWit v0 address (P2WPKH) uses the bech32 constant; v1+ (P2TR) uses
 * bech32m. The two differ only in the final XOR constant of the checksum —
 * the source of the 2017-era "bech32 is malleable for v1" fix.
 */

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

const BECH32_CONST = 1;
const BECH32M_CONST = 0x2bc830a3;

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

/** Convert a byte array (8-bit) to 5-bit groups (frombits=8, tobits=5, pad=true). */
function convert8to5(data: Uint8Array): number[] | null {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  const maxv = 31;
  for (const value of data) {
    if (value < 0 || value >> 8 !== 0) return null;
    acc = ((acc << 8) | value) & 0xffffffff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out.push((acc >>> bits) & maxv);
    }
  }
  if (bits > 0) out.push((acc << (5 - bits)) & maxv);
  return out;
}

function createChecksum(hrp: string, data5: number[], constant: number): number[] {
  const values = hrpExpand(hrp).concat(data5);
  const mod = polymod(values.concat([0, 0, 0, 0, 0, 0])) ^ constant;
  const out: number[] = [];
  for (let i = 0; i < 6; i++) out.push((mod >>> (5 * (5 - i))) & 31);
  return out;
}

/**
 * Encode a SegWit address. witver 0 → bech32 (P2WPKH); witver 1 → bech32m
 * (P2TR). Returns null on any invalid input (fail closed; never throws).
 */
export function encodeSegwitAddress(
  hrp: string,
  witver: number,
  program: Uint8Array,
): string | null {
  if (witver < 0 || witver > 16) return null;
  // BIP-141 program length bounds: 2..40 bytes; v0 must be 20 or 32.
  if (program.length < 2 || program.length > 40) return null;
  if (witver === 0 && program.length !== 20 && program.length !== 32) return null;

  const data5 = convert8to5(program);
  if (data5 === null) return null;
  const payload = [witver, ...data5];
  const constant = witver === 0 ? BECH32_CONST : BECH32M_CONST;
  const checksum = createChecksum(hrp, payload, constant);
  const combined = payload.concat(checksum);

  let out = hrp + '1';
  for (const d of combined) {
    if (d < 0 || d > 31) return null;
    out += CHARSET[d];
  }
  return out;
}

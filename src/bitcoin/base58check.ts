/**
 * Base58Check (Bitcoin alphabet) — inline, no deps. Encode-only: we build a
 * P2PKH address from a recovered pubkey-hash and compare it byte-for-byte
 * against `proof.address`. Checksum = first 4 bytes of sha256d(payload).
 */
import { sha256 } from '@noble/hashes/sha2';
import { concatBytes } from '../bytes.js';

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/** Plain base58 (big-endian) encode. */
function base58encode(bytes: Uint8Array): string {
  // Count leading zero bytes → leading '1's.
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  // Convert base-256 → base-58 via repeated division on a digit buffer.
  const digits: number[] = [0];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i]!;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let out = '';
  for (let i = 0; i < zeros; i++) out += '1';
  for (let i = digits.length - 1; i >= 0; i--) out += ALPHABET[digits[i]!];
  return out;
}

/** version-byte || payload, append sha256d checksum, base58-encode. */
export function base58checkEncode(version: number, payload: Uint8Array): string {
  const data = concatBytes(new Uint8Array([version & 0xff]), payload);
  const checksum = sha256(sha256(data)).slice(0, 4);
  return base58encode(concatBytes(data, checksum));
}

import { describe, it, expect } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { verifyXrp } from '../xrp/verify.js';
import { buildSiwxMessage } from '../caip122.js';
import { newChallenge } from '../nonce.js';
import { bytesToHex, concatBytes, utf8ToBytes } from '../bytes.js';
import type { SignedProof } from '../types.js';

// --- Reproduce the XRPL signing + r-address derivation (the wallet side). ---
// This is an INDEPENDENT implementation of the same spec the verifier uses; if
// the two ever drift, the round-trip "accepts a valid proof" test fails. That
// is the whole point of mirroring rather than importing verifier internals.

const XRPL_ALPHABET = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';

/** Independent XRPL base58check (account/version-prefixed payload in). */
function base58CheckXrpl(payload: Uint8Array): string {
  const checksum = sha256(sha256(payload)).slice(0, 4);
  const full = concatBytes(payload, checksum);
  let acc = 0n;
  for (const b of full) acc = (acc << 8n) | BigInt(b);
  let out = '';
  while (acc > 0n) {
    out = XRPL_ALPHABET[Number(acc % 58n)] + out;
    acc /= 58n;
  }
  for (let i = 0; i < full.length && full[i] === 0; i++) out = XRPL_ALPHABET[0] + out;
  return out;
}

/** r-address from a full 33-byte XRPL public key. */
function rAddressFromPubkey(pubkey33: Uint8Array): string {
  const accountId = ripemd160(sha256(pubkey33));
  return base58CheckXrpl(concatBytes(Uint8Array.of(0x00), accountId));
}

function sha512Half(d: Uint8Array): Uint8Array {
  return sha512(d).slice(0, 32);
}

interface Minted {
  proof: SignedProof;
  address: string;
}

/** Mint a self-consistent ed25519-xrpl proof: key → r-address → SIWx → raw sig. */
function mintEd25519(now = 1_700_000_000_000): Minted {
  const seed = ed25519.utils.randomPrivateKey();
  const raw32 = ed25519.getPublicKey(seed);
  // XRPL ed25519 public key = 0xED || 32-byte Edwards key.
  const pubkey33 = concatBytes(Uint8Array.of(0xed), raw32);
  const address = rAddressFromPubkey(pubkey33);

  const challenge = newChallenge({ domain: 'hanzo.id', uri: 'https://hanzo.id/login', now });
  const message = buildSiwxMessage({ challenge, address, chain: 'xrp' });

  // ed25519-xrpl signs the raw UTF-8 message bytes.
  const sig = ed25519.sign(utf8ToBytes(message), seed);

  return {
    address,
    proof: {
      chain: 'xrp',
      scheme: 'ed25519-xrpl',
      address,
      publicKey: bytesToHex(pubkey33),
      message,
      signature: bytesToHex(sig),
    },
  };
}

/** Mint a self-consistent secp256k1-xrpl proof: key → r-address → SIWx → DER sig. */
function mintSecp256k1(now = 1_700_000_000_000): Minted {
  // Reject keys whose compressed form is not the usual length (defensive).
  const priv = secp256k1.utils.randomPrivateKey();
  const pubkey33 = secp256k1.getPublicKey(priv, true); // compressed: 0x02/0x03 || 32
  const address = rAddressFromPubkey(pubkey33);

  const challenge = newChallenge({ domain: 'hanzo.id', uri: 'https://hanzo.id/login', now });
  const message = buildSiwxMessage({ challenge, address, chain: 'xrp' });

  // secp256k1-xrpl signs the sha512half of the message, DER-encoded.
  const digest = sha512Half(utf8ToBytes(message));
  const sig = secp256k1.sign(digest, priv, { prehash: false, lowS: true });
  const der = bytesToHex(sig.toBytes('der'));

  return {
    address,
    proof: {
      chain: 'xrp',
      scheme: 'secp256k1-xrpl',
      address,
      publicKey: bytesToHex(pubkey33),
      message,
      signature: der,
    },
  };
}

describe('XRPL base58check (known-answer vector)', () => {
  it('encodes the canonical xrpl.org AccountID example', () => {
    // From https://xrpl.org/addresses.html (Address Encoding worked example):
    //   AccountID  = BA8E78626EE42C41B46D46C3048DF3A1C3C87072
    //   r-address  = rJrRMgiRgrU6hDF4pgu5DXQdWyPbY35ErN
    const accountId = Uint8Array.from(
      'BA8E78626EE42C41B46D46C3048DF3A1C3C87072'.match(/../g)!.map((h) => parseInt(h, 16)),
    );
    const addr = base58CheckXrpl(concatBytes(Uint8Array.of(0x00), accountId));
    expect(addr).toBe('rJrRMgiRgrU6hDF4pgu5DXQdWyPbY35ErN');
  });
});

describe('verifyXrp — ed25519-xrpl', () => {
  it('accepts a valid proof (full round-trip)', () => {
    const { proof } = mintEd25519();
    expect(verifyXrp(proof)).toBe(true);
  });

  it('rejects a tampered message (signature no longer matches)', () => {
    const { proof } = mintEd25519();
    const bad: SignedProof = { ...proof, message: proof.message + ' ' };
    expect(verifyXrp(bad)).toBe(false);
  });

  it('rejects a flipped signature bit', () => {
    const { proof } = mintEd25519();
    const sig = Uint8Array.from(proof.signature.match(/../g)!.map((h) => parseInt(h, 16)));
    sig[0] = (sig[0]! ^ 0x01) & 0xff;
    expect(verifyXrp({ ...proof, signature: bytesToHex(sig) })).toBe(false);
  });

  it('rejects a wrong address (binding failure, key/sig still valid)', () => {
    const { proof } = mintEd25519();
    const other = mintEd25519();
    expect(verifyXrp({ ...proof, address: other.address })).toBe(false);
  });

  it('rejects a mismatched public key', () => {
    const { proof } = mintEd25519();
    const other = mintEd25519();
    // Valid 0xED-prefixed key but not the signer → sig verify fails.
    expect(verifyXrp({ ...proof, publicKey: other.proof.publicKey })).toBe(false);
  });

  it('rejects a missing 0xED prefix on the public key', () => {
    const { proof } = mintEd25519();
    const bytes = Uint8Array.from(proof.publicKey!.match(/../g)!.map((h) => parseInt(h, 16)));
    bytes[0] = 0xee; // wrong family tag
    expect(verifyXrp({ ...proof, publicKey: bytesToHex(bytes) })).toBe(false);
  });

  it('fails closed on a missing public key', () => {
    const { proof } = mintEd25519();
    expect(verifyXrp({ ...proof, publicKey: undefined })).toBe(false);
  });
});

describe('verifyXrp — secp256k1-xrpl', () => {
  it('accepts a valid proof (full round-trip)', () => {
    const { proof } = mintSecp256k1();
    expect(verifyXrp(proof)).toBe(true);
  });

  it('rejects a tampered message (signature no longer matches)', () => {
    const { proof } = mintSecp256k1();
    const bad: SignedProof = { ...proof, message: proof.message + ' ' };
    expect(verifyXrp(bad)).toBe(false);
  });

  it('rejects a corrupted DER signature', () => {
    const { proof } = mintSecp256k1();
    const der = Uint8Array.from(proof.signature.match(/../g)!.map((h) => parseInt(h, 16)));
    const last = der.length - 1;
    der[last] = (der[last]! ^ 0x01) & 0xff; // mangle last byte of s
    expect(verifyXrp({ ...proof, signature: bytesToHex(der) })).toBe(false);
  });

  it('rejects a wrong address (binding failure, key/sig still valid)', () => {
    const { proof } = mintSecp256k1();
    const other = mintSecp256k1();
    expect(verifyXrp({ ...proof, address: other.address })).toBe(false);
  });

  it('rejects a mismatched public key', () => {
    const { proof } = mintSecp256k1();
    const other = mintSecp256k1();
    expect(verifyXrp({ ...proof, publicKey: other.proof.publicKey })).toBe(false);
  });

  it('rejects an ed25519-tagged key under the secp256k1 scheme', () => {
    const { proof } = mintSecp256k1();
    const bytes = Uint8Array.from(proof.publicKey!.match(/../g)!.map((h) => parseInt(h, 16)));
    bytes[0] = 0xed; // not a valid compressed-point tag
    expect(verifyXrp({ ...proof, publicKey: bytesToHex(bytes) })).toBe(false);
  });

  it('fails closed on a missing public key', () => {
    const { proof } = mintSecp256k1();
    expect(verifyXrp({ ...proof, publicKey: undefined })).toBe(false);
  });
});

describe('verifyXrp — fail-closed hardening', () => {
  it('rejects an unknown scheme via this verifier', () => {
    const { proof } = mintEd25519();
    expect(verifyXrp({ ...proof, scheme: 'ed25519' as SignedProof['scheme'] })).toBe(false);
  });

  it('does not throw on garbage input', () => {
    const garbage = {
      chain: 'xrp',
      scheme: 'ed25519-xrpl',
      address: 'x',
      publicKey: 'nothex',
      message: 'not a siwx message',
      signature: '!!!!',
    } as unknown as SignedProof;
    expect(() => verifyXrp(garbage)).not.toThrow();
    expect(verifyXrp(garbage)).toBe(false);
  });

  it('rejects a wrong-length public key', () => {
    const { proof } = mintEd25519();
    expect(verifyXrp({ ...proof, publicKey: bytesToHex(new Uint8Array(31)) })).toBe(false);
  });
});

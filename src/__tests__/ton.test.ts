import { describe, it, expect } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { verifyTon } from '../ton/verify.js';
import { buildSiwxMessage } from '../caip122.js';
import { newChallenge } from '../nonce.js';
import { bytesToHex, bytesToBase64, utf8ToBytes, concatBytes } from '../bytes.js';
import type { SignedProof } from '../types.js';

// --- Reproduce the TON Connect ton_proof signing algorithm (the wallet side). ---
// This MUST mirror src/ton/verify.ts byte-for-byte; if they ever drift, the
// round-trip "accepts a valid proof" test fails — which is the whole point.

interface ProofEnvelope {
  timestamp: number;
  domain: string;
  payload: string;
  workchain: number;
  addressHashHex: string;
}

function tonProofDigest(env: ProofEnvelope): Uint8Array {
  const addressHash = hexFix(env.addressHashHex);

  const wc = new Uint8Array(4);
  new DataView(wc.buffer).setInt32(0, env.workchain, false); // big-endian, signed

  const domainBytes = utf8ToBytes(env.domain);
  const dlen = new Uint8Array(4);
  new DataView(dlen.buffer).setUint32(0, domainBytes.length, true); // little-endian

  const ts = new Uint8Array(8);
  new DataView(ts.buffer).setBigUint64(0, BigInt(env.timestamp), true); // little-endian

  const message = concatBytes(
    utf8ToBytes('ton-proof-item-v2/'),
    wc,
    addressHash,
    dlen,
    domainBytes,
    ts,
    utf8ToBytes(env.payload),
  );

  const fullMsg = concatBytes(Uint8Array.of(0xff, 0xff), utf8ToBytes('ton-connect'), sha256(message));
  return sha256(fullMsg);
}

/** Local hex→bytes (no 0x) so the test does not depend on verifier internals. */
function hexFix(hex: string): Uint8Array {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * Mint a fresh, self-consistent TON proof: random ed25519 key, a CAIP-122
 * message whose Nonce equals the ton_proof payload, and a real signature over
 * the reconstructed digest.
 */
function mintProof(overrides?: {
  workchain?: number;
  domain?: string;
  now?: number;
}): { proof: SignedProof; env: ProofEnvelope; priv: Uint8Array; pub: Uint8Array } {
  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);

  // A TON address-hash (account state-init hash). For the verifier it is just
  // 32 opaque bytes; use a deterministic-but-arbitrary value here.
  const addressHash = sha256(pub); // 32 bytes
  const addressHashHex = bytesToHex(addressHash);

  const workchain = overrides?.workchain ?? 0;
  const domain = overrides?.domain ?? 'hanzo.id';
  const now = overrides?.now ?? 1_700_000_000_000;
  const timestamp = Math.floor(now / 1000);

  // Server mints the nonce; the connector reuses it as the ton_proof payload.
  const challenge = newChallenge({ domain, uri: `https://${domain}/login`, now });
  const payload = challenge.nonce;

  // The on-chain "address" we use for binding: friendly form would be base64url,
  // but for verifier purposes the address must simply equal the SIWx address
  // line. Use "<workchain>:<addressHashHex>" (raw TON address form).
  const address = `${workchain}:${addressHashHex}`;

  const message = buildSiwxMessage({ challenge, address, chain: 'ton' });

  const env: ProofEnvelope = { timestamp, domain, payload, workchain, addressHashHex };
  const digest = tonProofDigest(env);
  const signature = bytesToBase64(ed25519.sign(digest, priv));

  const proof: SignedProof = {
    chain: 'ton',
    scheme: 'ton-proof',
    address,
    publicKey: bytesToHex(pub),
    message,
    signature,
    extra: { ...env },
  };
  return { proof, env, priv, pub };
}

describe('TON ton_proof verify', () => {
  it('accepts a valid proof (full round-trip)', () => {
    const { proof } = mintProof();
    expect(verifyTon(proof)).toBe(true);
  });

  it('accepts a valid proof on the masterchain (workchain = -1)', () => {
    // Exercises signed int32BE encoding: -1 must serialize as 0xFFFFFFFF on
    // both the signing and verifying sides.
    const { proof } = mintProof({ workchain: -1 });
    expect(verifyTon(proof)).toBe(true);
  });

  it('rejects a tampered timestamp', () => {
    const { proof } = mintProof();
    const bad: SignedProof = {
      ...proof,
      extra: { ...(proof.extra as object), timestamp: (proof.extra as any).timestamp + 1 },
    };
    expect(verifyTon(bad)).toBe(false);
  });

  it('rejects a tampered domain', () => {
    const { proof } = mintProof();
    const bad: SignedProof = {
      ...proof,
      extra: { ...(proof.extra as object), domain: 'evil.com' },
    };
    expect(verifyTon(bad)).toBe(false);
  });

  it('rejects a tampered payload (signature no longer matches)', () => {
    const { proof } = mintProof();
    // Mutate BOTH the SIWx nonce and the envelope payload so the binding check
    // passes and we isolate the cryptographic rejection.
    const tamperedPayload = (proof.extra as any).payload + 'X';
    const bad: SignedProof = {
      ...proof,
      message: proof.message.replace(/Nonce: .*/, `Nonce: ${tamperedPayload}`),
      address: proof.address,
      extra: { ...(proof.extra as object), payload: tamperedPayload },
    };
    expect(verifyTon(bad)).toBe(false);
  });

  it('rejects a wrong public key', () => {
    const { proof } = mintProof();
    const otherPub = ed25519.getPublicKey(ed25519.utils.randomPrivateKey());
    const bad: SignedProof = { ...proof, publicKey: bytesToHex(otherPub) };
    expect(verifyTon(bad)).toBe(false);
  });

  it('rejects a nonce/payload mismatch (binding failure, before crypto)', () => {
    const { proof } = mintProof();
    // Envelope payload no longer equals the SIWx Nonce → binding rejects it
    // even though the (still-valid-for-old-payload) signature is untouched.
    const bad: SignedProof = {
      ...proof,
      extra: { ...(proof.extra as object), payload: 'a-different-nonce' },
    };
    expect(verifyTon(bad)).toBe(false);
  });

  it('rejects an address that does not match the SIWx message', () => {
    const { proof } = mintProof();
    const bad: SignedProof = { ...proof, address: '0:deadbeef' };
    expect(verifyTon(bad)).toBe(false);
  });

  it('rejects a malformed signature (wrong length)', () => {
    const { proof } = mintProof();
    const bad: SignedProof = { ...proof, signature: bytesToBase64(new Uint8Array(63)) };
    expect(verifyTon(bad)).toBe(false);
  });

  it('rejects a malformed public key (wrong length)', () => {
    const { proof } = mintProof();
    const bad: SignedProof = { ...proof, publicKey: bytesToHex(new Uint8Array(31)) };
    expect(verifyTon(bad)).toBe(false);
  });

  it('rejects a malformed address hash (wrong length)', () => {
    const { proof } = mintProof();
    const bad: SignedProof = {
      ...proof,
      extra: { ...(proof.extra as object), addressHashHex: 'dead' },
    };
    expect(verifyTon(bad)).toBe(false);
  });

  it('fails closed on a missing envelope', () => {
    const { proof } = mintProof();
    const bad: SignedProof = { ...proof, extra: undefined };
    expect(verifyTon(bad)).toBe(false);
  });

  it('fails closed on a missing public key', () => {
    const { proof } = mintProof();
    const bad = { ...proof, publicKey: undefined } as SignedProof;
    expect(verifyTon(bad)).toBe(false);
  });

  it('does not throw on garbage input', () => {
    const garbage = {
      chain: 'ton',
      scheme: 'ton-proof',
      address: 'x',
      publicKey: 'nothex',
      message: 'not a siwx message',
      signature: '!!!!',
      extra: { timestamp: 'soon', domain: 1, payload: null, workchain: 0.5, addressHashHex: 7 },
    } as unknown as SignedProof;
    expect(() => verifyTon(garbage)).not.toThrow();
    expect(verifyTon(garbage)).toBe(false);
  });
});

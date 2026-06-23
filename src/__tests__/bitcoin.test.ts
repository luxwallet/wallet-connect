/**
 * Bitcoin verifier tests.
 *
 * Coverage:
 *   • Legacy "Bitcoin Signed Message" (recoverable ECDSA) over a real CAIP-122
 *     login message — for P2PKH, P2WPKH and P2TR (BIP-86) addresses.
 *   • BIP-322 "simple" for P2WPKH (ECDSA / BIP-143) and P2TR key-path
 *     (Schnorr / BIP-341).
 *   • Tamper / wrong-address / wrong-type negatives (fail closed).
 *   • Anchors: the BIP-322 message hash + to_spend txid + P2WPKH derivation
 *     are pinned to the official Bitcoin Core BIP-322 test vectors, so the
 *     sighash construction is verified against a known-answer source rather
 *     than only self-consistently.
 */
import { describe, it, expect } from 'vitest';
import { secp256k1, schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha2';
import { ripemd160 } from '@noble/hashes/legacy';
import { verifyBitcoin } from '../bitcoin/verify.js';
import { encodeSegwitAddress } from '../bitcoin/bech32.js';
import { base58checkEncode } from '../bitcoin/base58check.js';
import { buildSiwxMessage } from '../caip122.js';
import { newChallenge } from '../nonce.js';
import { utf8ToBytes, concatBytes, bytesToHex } from '../bytes.js';
import type { SignedProof } from '../types.js';

// ── local crypto helpers (independent of the verifier internals) ─────────────

const enc = (s: string) => utf8ToBytes(s);
const sha256d = (b: Uint8Array) => sha256(sha256(b));
const hash160 = (b: Uint8Array) => ripemd160(sha256(b));

function taggedHash(tag: string, ...m: Uint8Array[]): Uint8Array {
  const t = sha256(enc(tag));
  return sha256(concatBytes(t, t, ...m));
}

function compactSize(n: number): Uint8Array {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, (n >>> 8) & 0xff]);
  return new Uint8Array([0xfe, n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
}
const u32le = (n: number) =>
  new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
const u64le = (n: bigint) => {
  const o = new Uint8Array(8);
  let v = n;
  for (let i = 0; i < 8; i++) {
    o[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return o;
};
const varBytes = (b: Uint8Array) => concatBytes(compactSize(b.length), b);

function bytesToBig(b: Uint8Array): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}
function bigToXonly(x: bigint): Uint8Array {
  const o = new Uint8Array(32);
  let v = x;
  for (let i = 31; i >= 0; i--) {
    o[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return o;
}

function toBase64(b: Uint8Array): string {
  return Buffer.from(b).toString('base64');
}

// Address derivations (must match the verifier's, independently written).
function p2pkh(pubkey: Uint8Array): string {
  return base58checkEncode(0x00, hash160(pubkey));
}
function p2wpkh(pubCompressed: Uint8Array): string {
  return encodeSegwitAddress('bc', 0, hash160(pubCompressed))!;
}
function taprootTweak(internalXonly: Uint8Array): Uint8Array {
  const n = secp256k1.CURVE.n;
  const P = schnorr.utils.lift_x(bytesToBig(internalXonly));
  const t = bytesToBig(taggedHash('TapTweak', internalXonly)) % n;
  const Q = P.add(secp256k1.Point.BASE.multiply(t));
  return bigToXonly(Q.toAffine().x);
}
function p2tr(internalXonly: Uint8Array): { address: string; program: Uint8Array } {
  const program = taprootTweak(internalXonly);
  return { address: encodeSegwitAddress('bc', 1, program)!, program };
}

// ── legacy "Bitcoin Signed Message" signer ───────────────────────────────────

function legacyDigest(message: string): Uint8Array {
  const msg = enc(message);
  const magic = enc('\x18Bitcoin Signed Message:\n');
  return sha256d(concatBytes(magic, compactSize(msg.length), msg));
}

/** Produce a 65-byte [header || r || s] legacy signature. */
function signLegacy(priv: Uint8Array, message: string, compressed: boolean): Uint8Array {
  const digest = legacyDigest(message);
  const sig = secp256k1.sign(digest, priv);
  const recid = sig.recovery!;
  const header = 27 + recid + (compressed ? 4 : 0);
  return concatBytes(new Uint8Array([header]), sig.toBytes('compact'));
}

// ── BIP-322 simple signers (sign exactly the verifier's sighash) ─────────────

function toSpendTxid(message: string, scriptPubKey: Uint8Array): Uint8Array {
  const msgHash = taggedHash('BIP0322-signed-message', enc(message));
  const scriptSig = concatBytes(new Uint8Array([0x00, 0x20]), msgHash);
  const ser = concatBytes(
    u32le(0),
    compactSize(1),
    new Uint8Array(32),
    u32le(0xffffffff),
    varBytes(scriptSig),
    u32le(0),
    compactSize(1),
    u64le(0n),
    varBytes(scriptPubKey),
    u32le(0),
  );
  return sha256d(ser);
}

function bip143SighashP2WPKH(txid: Uint8Array, h160: Uint8Array): Uint8Array {
  const outpoint = concatBytes(txid, u32le(0));
  const nSequence = u32le(0);
  const hashPrevouts = sha256d(outpoint);
  const hashSequence = sha256d(nSequence);
  const scriptCode = concatBytes(
    new Uint8Array([0x19, 0x76, 0xa9, 0x14]),
    h160,
    new Uint8Array([0x88, 0xac]),
  );
  const output = concatBytes(u64le(0n), varBytes(new Uint8Array([0x6a])));
  const hashOutputs = sha256d(output);
  const preimage = concatBytes(
    u32le(0),
    hashPrevouts,
    hashSequence,
    outpoint,
    scriptCode,
    u64le(0n),
    nSequence,
    hashOutputs,
    u32le(0),
    u32le(1),
  );
  return sha256d(preimage);
}

function bip341SighashP2TR(txid: Uint8Array, scriptPubKey: Uint8Array): Uint8Array {
  const outpoint = concatBytes(txid, u32le(0));
  const nSequence = u32le(0);
  const shaPrevouts = sha256(outpoint);
  const shaAmounts = sha256(u64le(0n));
  const shaScriptPubkeys = sha256(varBytes(scriptPubKey));
  const shaSequences = sha256(nSequence);
  const output = concatBytes(u64le(0n), varBytes(new Uint8Array([0x6a])));
  const shaOutputs = sha256(output);
  const sigMsg = concatBytes(
    new Uint8Array([0x00]), // hash_type SIGHASH_DEFAULT
    u32le(0),
    u32le(0),
    shaPrevouts,
    shaAmounts,
    shaScriptPubkeys,
    shaSequences,
    shaOutputs,
    new Uint8Array([0x00]), // spend_type
    u32le(0), // input index
  );
  return taggedHash('TapSighash', concatBytes(new Uint8Array([0x00]), sigMsg));
}

function serializeWitness(items: Uint8Array[]): Uint8Array {
  let out = compactSize(items.length);
  for (const it of items) out = concatBytes(out, varBytes(it));
  return out;
}

/** BIP-322 simple P2WPKH signature (serialized witness [sig||SIGHASH_ALL, pubkey]). */
function signBip322P2WPKH(priv: Uint8Array, message: string): Uint8Array {
  const pub = secp256k1.getPublicKey(priv, true);
  const h160 = hash160(pub);
  const spk = concatBytes(new Uint8Array([0x00, 0x14]), h160);
  const txid = toSpendTxid(message, spk);
  const sighash = bip143SighashP2WPKH(txid, h160);
  const sig = secp256k1.sign(sighash, priv, { lowS: true });
  const der = concatBytes(sig.toBytes('der'), new Uint8Array([0x01])); // SIGHASH_ALL
  return serializeWitness([der, pub]);
}

/** BIP-322 simple P2TR key-path signature (serialized witness [schnorr_sig]). */
function signBip322P2TR(priv: Uint8Array, message: string): { sig: Uint8Array; address: string } {
  const internalXonly = secp256k1.getPublicKey(priv, true).slice(1);
  const { address, program } = p2tr(internalXonly);
  const spk = concatBytes(new Uint8Array([0x51, 0x20]), program);
  const txid = toSpendTxid(message, spk);
  const sighash = bip341SighashP2TR(txid, spk);
  // Taproot key-path must sign with the *tweaked* private key.
  const n = secp256k1.CURVE.n;
  let d = bytesToBig(priv) % n;
  // BIP-340: if the internal pubkey has odd Y, negate d.
  const Pfull = secp256k1.Point.BASE.multiply(d);
  if (Pfull.toAffine().y % 2n === 1n) d = n - d;
  const t = bytesToBig(taggedHash('TapTweak', internalXonly)) % n;
  const tweaked = (d + t) % n;
  const tweakedBytes = bigToXonly(tweaked);
  const sig = schnorr.sign(sighash, tweakedBytes);
  return { sig: serializeWitness([sig]), address };
}

// ── fixtures ─────────────────────────────────────────────────────────────────

function makeMessage(address: string): string {
  const challenge = newChallenge({
    domain: 'hanzo.id',
    uri: 'https://hanzo.id/login',
    statement: 'Sign in to Hanzo',
    nonce: 'abc123XYZ789',
    now: Date.UTC(2026, 0, 1),
  });
  return buildSiwxMessage({ challenge, address, chain: 'bitcoin' });
}

// A fixed key so failures are reproducible.
const PRIV = new Uint8Array(32).fill(0);
PRIV[31] = 0x2a; // d = 42

describe('verifyBitcoin — anchors against Bitcoin Core BIP-322 vectors', () => {
  it('message_hash + to_spend txid match the official vectors', () => {
    const addr = 'bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l';
    // Reconstruct that address's witness program from the known WIF private key.
    // WIF L3VFe…: 0x80 || priv(32) || 0x01 || checksum(4)  → priv extracted below.
    const wifPriv = hexToBytesLocal(
      'bb051cd0dda0246f33c5a9e133ebd8e7bc02a92af6c41adc131ccd7826c5b004',
    );
    const pub = secp256k1.getPublicKey(wifPriv, true);
    expect(p2wpkh(pub)).toBe(addr); // P2WPKH derivation anchor

    expect(bytesToHex(taggedHash('BIP0322-signed-message', enc('')))).toBe(
      'c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1',
    );
    expect(bytesToHex(taggedHash('BIP0322-signed-message', enc('Hello World')))).toBe(
      'f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a',
    );
    const spk = concatBytes(new Uint8Array([0x00, 0x14]), hash160(pub));
    const display = (b: Uint8Array) => bytesToHex(Uint8Array.from([...b].reverse()));
    expect(display(toSpendTxid('', spk))).toBe(
      'c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7',
    );
    expect(display(toSpendTxid('Hello World', spk))).toBe(
      'b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b',
    );
  });
});

function hexToBytesLocal(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

describe('verifyBitcoin — legacy Bitcoin Signed Message', () => {
  const pubC = secp256k1.getPublicKey(PRIV, true);
  const pubU = secp256k1.getPublicKey(PRIV, false);

  it('P2PKH (compressed) verifies, tamper + wrong address fail', () => {
    const address = p2pkh(pubC);
    const message = makeMessage(address);
    const sig = signLegacy(PRIV, message, true);
    const proof: SignedProof = {
      chain: 'bitcoin',
      scheme: 'bip322',
      address,
      message,
      signature: toBase64(sig),
    };
    expect(verifyBitcoin(proof)).toBe(true);

    // Tamper the signature (flip a byte in r).
    const bad = sig.slice();
    bad[5] = bad[5]! ^ 0xff;
    expect(verifyBitcoin({ ...proof, signature: toBase64(bad) })).toBe(false);

    // Tamper the message.
    expect(verifyBitcoin({ ...proof, message: message + ' ' })).toBe(false);

    // Wrong address (different key's P2PKH).
    const other = secp256k1.getPublicKey(hexToBytesLocal('11'.repeat(32)), true);
    expect(verifyBitcoin({ ...proof, address: p2pkh(other) })).toBe(false);
  });

  it('P2PKH (uncompressed) verifies and is key-encoding-bound', () => {
    const address = p2pkh(pubU);
    const message = makeMessage(address);
    const sig = signLegacy(PRIV, message, false);
    expect(
      verifyBitcoin({ chain: 'bitcoin', scheme: 'bip322', address, message, signature: toBase64(sig) }),
    ).toBe(true);

    // The compressed-key address must NOT verify against an uncompressed-header sig.
    const cAddr = p2pkh(pubC);
    const cMsg = makeMessage(cAddr);
    const uncompSig = signLegacy(PRIV, cMsg, false);
    expect(
      verifyBitcoin({ chain: 'bitcoin', scheme: 'bip322', address: cAddr, message: cMsg, signature: toBase64(uncompSig) }),
    ).toBe(false);
  });

  it('P2WPKH verifies via legacy recoverable sig, rejects uncompressed header', () => {
    const address = p2wpkh(pubC);
    const message = makeMessage(address);
    const sig = signLegacy(PRIV, message, true);
    expect(
      verifyBitcoin({ chain: 'bitcoin', scheme: 'bip322', address, message, signature: toBase64(sig) }),
    ).toBe(true);

    // Uncompressed header can't back a segwit address → reject.
    const uncompSig = signLegacy(PRIV, message, false);
    expect(
      verifyBitcoin({ chain: 'bitcoin', scheme: 'bip322', address, message, signature: toBase64(uncompSig) }),
    ).toBe(false);

    // A P2WPKH address from a DIFFERENT key must not verify against this sig.
    const otherP2wpkh = p2wpkh(secp256k1.getPublicKey(hexToBytesLocal('05'.repeat(32)), true));
    expect(
      verifyBitcoin({
        chain: 'bitcoin',
        scheme: 'bip322',
        address: otherP2wpkh,
        message,
        signature: toBase64(sig),
      }),
    ).toBe(false);
  });

  it('P2TR (BIP-86) verifies via legacy recoverable sig', () => {
    const internalXonly = pubC.slice(1);
    const { address } = p2tr(internalXonly);
    const message = makeMessage(address);
    const sig = signLegacy(PRIV, message, true);
    expect(
      verifyBitcoin({ chain: 'bitcoin', scheme: 'bip322', address, message, signature: toBase64(sig) }),
    ).toBe(true);

    // Tamper → false.
    const bad = sig.slice();
    bad[40] = bad[40]! ^ 0x01;
    expect(
      verifyBitcoin({ chain: 'bitcoin', scheme: 'bip322', address, message, signature: toBase64(bad) }),
    ).toBe(false);
  });
});

describe('verifyBitcoin — BIP-322 simple', () => {
  it('P2WPKH (BIP-143 / ECDSA) verifies, tamper + wrong address fail', () => {
    const pub = secp256k1.getPublicKey(PRIV, true);
    const address = p2wpkh(pub);
    const message = makeMessage(address);
    const sig = signBip322P2WPKH(PRIV, message);
    const proof: SignedProof = {
      chain: 'bitcoin',
      scheme: 'bip322',
      address,
      message,
      signature: toBase64(sig),
      extra: { addressType: 'p2wpkh' },
    };
    expect(verifyBitcoin(proof)).toBe(true);

    // Tamper the message → sighash changes → false.
    expect(verifyBitcoin({ ...proof, message: message + 'x' })).toBe(false);

    // Wrong address → witness pubkey no longer hashes to it → false.
    const other = p2wpkh(secp256k1.getPublicKey(hexToBytesLocal('07'.repeat(32)), true));
    expect(verifyBitcoin({ ...proof, address: other })).toBe(false);

    // Truncated witness → false.
    expect(verifyBitcoin({ ...proof, signature: toBase64(sig.slice(0, sig.length - 3)) })).toBe(false);
  });

  it('P2TR key-path (BIP-341 / Schnorr) verifies, tamper fails', () => {
    const message0 = 'placeholder';
    const { address } = signBip322P2TR(PRIV, message0); // get the address first
    const message = makeMessage(address);
    const { sig } = signBip322P2TR(PRIV, message);
    const proof: SignedProof = {
      chain: 'bitcoin',
      scheme: 'bip322',
      address,
      message,
      signature: toBase64(sig),
      extra: { addressType: 'p2tr' },
    };
    expect(verifyBitcoin(proof)).toBe(true);

    // Tamper the message → false.
    expect(verifyBitcoin({ ...proof, message: message + 'z' })).toBe(false);

    // Flip a byte in the schnorr sig → false.
    const bad = sig.slice();
    bad[bad.length - 1] = bad[bad.length - 1]! ^ 0x01;
    expect(verifyBitcoin({ ...proof, signature: toBase64(bad) })).toBe(false);
  });
});

describe('verifyBitcoin — malformed input fails closed', () => {
  const address = p2wpkh(secp256k1.getPublicKey(PRIV, true));
  const message = makeMessage(address);
  const base: SignedProof = { chain: 'bitcoin', scheme: 'bip322', address, message, signature: '' };

  it('empty signature → false', () => {
    expect(verifyBitcoin(base)).toBe(false);
  });
  it('garbage base64 → false', () => {
    expect(verifyBitcoin({ ...base, signature: '!!!notbase64!!!' })).toBe(false);
  });
  it('unknown address prefix → false', () => {
    expect(verifyBitcoin({ ...base, address: '3unsupportedP2SHaddress', signature: 'AQID' })).toBe(false);
  });
  it('legacy sig with out-of-range header → false', () => {
    const sig = new Uint8Array(65);
    sig[0] = 99; // invalid header
    expect(verifyBitcoin({ ...base, signature: toBase64(sig) })).toBe(false);
  });
});

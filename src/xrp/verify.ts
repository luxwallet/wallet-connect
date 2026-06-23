/**
 * XRP (XRP Ledger) verifier — wallet message signatures. [skeleton — being implemented]
 *
 * XRPL accounts use secp256k1 or ed25519 keypairs. The connector carries the
 * public key in `proof.publicKey`; this verifier checks the signature over the
 * CAIP-122 message and that the public key derives the claimed r-address.
 */
import type { SignedProof } from '../types.js';

export function verifyXrp(_proof: SignedProof): boolean {
  return false; // TODO: implement XRPL secp256k1/ed25519 verification
}

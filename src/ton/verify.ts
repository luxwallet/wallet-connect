/**
 * TON verifier — TON Connect `ton_proof` (ed25519). [skeleton — being implemented]
 *
 * Unlike text-signing chains, TON signs a structured `ton_proof` envelope, not
 * the CAIP-122 string. The connector carries the envelope in `proof.extra` and
 * the wallet public key in `proof.publicKey`; this verifier reconstructs the
 * ton_proof signing message and checks the ed25519 signature, plus that the
 * envelope's payload carries the login nonce.
 */
import type { SignedProof } from '../types.js';

export function verifyTon(_proof: SignedProof): boolean {
  return false; // TODO: implement ton_proof ed25519 verification
}

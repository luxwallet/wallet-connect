/**
 * Bitcoin verifier — BIP-322 message signatures (and legacy "Bitcoin Signed
 * Message"). [skeleton — being implemented]
 *
 * Verifies a signature over the CAIP-122 message against a BTC address
 * (P2WPKH / P2TR / P2PKH). The connector may carry the address type / script
 * hints in `proof.extra`.
 */
import type { SignedProof } from '../types.js';

export function verifyBitcoin(_proof: SignedProof): boolean {
  return false; // TODO: implement BIP-322 (+ legacy) verification
}

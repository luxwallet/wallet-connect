package walletconnect

// Per-chain verifier stubs. These fail closed (return false) until the full
// ports land, so VerifyProof reports bad-signature rather than ever accepting an
// unverified proof. The TS reference implementations these mirror:
//
//   - VerifyTon     — src/ton/verify.ts     (TON Connect ton_proof, ed25519)
//   - VerifyBitcoin — src/bitcoin/verify.ts (BIP-322; itself still a TS stub)
//   - VerifyXrp     — src/xrp/verify.ts     (XRPL secp256k1 / ed25519 + AccountID)
//
// Each takes the full Proof because these schemes carry material outside the
// CAIP-122 message body (ton_proof envelope in Extra, public keys, address
// type hints).

// VerifyTon verifies a TON Connect ton_proof login proof. Stub: fails closed.
func VerifyTon(_ Proof) bool { return false }

// VerifyBitcoin verifies a BIP-322 (or legacy) Bitcoin message signature.
// Stub: fails closed.
func VerifyBitcoin(_ Proof) bool { return false }

// VerifyXrp verifies an XRP Ledger login-message signature. Stub: fails closed.
func VerifyXrp(_ Proof) bool { return false }

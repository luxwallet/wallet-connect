# wallet-connect (Go)

Go port of the `@luxwallet/connect` login verifier. Mirrors the TypeScript
`src/` byte-for-byte so Hanzo IAM (Casdoor, Go) verifies wallet logins
identically to `verifyProof`: same CAIP-122 message parse, same
domain/nonce/time checks, same EIP-191 digest, same ed25519 check.

Module: `github.com/luxwallet/connect/go`
Package: `walletconnect`

## API

- `ParseSiwxMessage` / `BuildSiwxMessage` — CAIP-122 message (mirrors `caip122.ts`).
- `VerifyProof(Proof, Expectation) Result` — the one server-side entry point
  (mirrors `verify.ts`). Fails closed; never panics.
- `VerifyEVM` — EIP-191 `personal_sign`, secp256k1 ecrecover (mirrors `evm/verify.ts`).
- `VerifySolana` — ed25519 over the message, base58 pubkey address (mirrors `solana/verify.ts`).
- `VerifyTon` / `VerifyBitcoin` / `VerifyXrp` — fail-closed stubs; full ports later.

`Result.Reason` strings match the TS union exactly: `bad-signature`,
`address-mismatch`, `domain-mismatch`, `nonce-mismatch`, `expired`,
`not-yet-valid`, `malformed-message`, `unsupported-scheme`, `missing-public-key`.

## Crypto

EVM secp256k1 + keccak256 come from `github.com/luxfi/crypto` (the luxfi
package — NOT go-ethereum, NOT ava-labs). ed25519 is stdlib `crypto/ed25519`;
base58 is `github.com/mr-tron/base58`.

The verifier path uses pure-Go secp256k1 (`luxfi/crypto`'s `!cgo` build), so it
needs no C toolchain.

## Test

```sh
CGO_ENABLED=0 go test ./...
```

CGO-free is the portable, one-and-only-one-way invocation (no libsecp256k1 C
build required). A bare `go test ./...` also works on a machine with a healthy
C toolchain.

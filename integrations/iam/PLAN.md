# Hanzo IAM ⇄ `@luxwallet/connect` — multi-chain wallet login

Integration design for replacing IAM's EVM-only `@web3-onboard` path with the
MIT `@luxwallet/connect` SDK (`/Users/z/work/lux/wallet-connect`), so `hanzo.id`
supports wallet login for **EVM, Solana, Bitcoin, TON, XRP** through one
canonical, signature-verifying flow.

- IAM repo: `/Users/z/work/hanzo/iam` (Casdoor fork; brand login `hanzo.id`, API `iam.hanzo.ai`).
- SDK: `github.com/luxwallet/wallet-connect` — TS `src/` + Go port `go/walletconnect`.
- Auth law: **HIP-0111** — canonical paths under `/v1/iam/...` only; never `/api/`, never `/oauth`.

Draft artifacts in this directory (NOT applied to IAM):
- `web3_auth.go.draft`  → `controllers/web3_auth.go`
- `web3_store.go.draft` → `object/web3_store.go`
- `WalletConnect.tsx.draft` → `web/src/auth/WalletConnect.tsx`

---

## 0. Headline finding — the current path verifies NOTHING

IAM's existing web3 sign-in **never checks the signature**. The address is taken
on faith, so impersonating any wallet address is trivial today. This integration
is therefore not "swap one verifier for another" — it is **introduce real
verification (and a real nonce) where there is none**, using the SDK's
`VerifyProof` so Go and TS verify identically.

---

## 1. Current web3 sign-in flow (file:line)

### Frontend — `web/src/auth/Web3Auth.tsx`
- `authViaMetaMask` (`:157`) → `signEthereumTypedData` (`:97`) signs an **EIP-712
  typed-data** `AuthRequest{prompt,nonce,createAt}` with a **client-generated
  uuid nonce** (`generateNonce`, `:44`). Builds a `Web3AuthToken
  {address,createAt,typedData,signature}`, stashes it in `localStorage`
  (`setWeb3AuthToken`, `:53`), then redirects to `getAuthUrl(...) +
  "&web3AuthTokenKey=..."` (`:170`).
- `authViaWeb3Onboard` (`:374`) connects via `@web3-onboard`, but builds a token
  with **only `{address, walletType, createAt}` — no `signature` at all**
  (`:382`), stashes + redirects (`:388`).
- `checkEthereumSignedTypedData` (`:140`) does an `ecrecover` **client-side
  only** — never trusted by the server.

### Provider dispatch — `idp/provider.go`
- `:127` `case "MetaMask": return NewMetaMaskIdProvider()`
- `:129` `case "Web3Onboard": return NewWeb3OnboardIdProvider()`

### "Verification" (there is none) — `idp/metamask.go`, `idp/web3onboard.go`
- `idp/web3onboard.go:30` `Web3AuthToken {Address,Nonce,CreateAt,TypedData,Signature,WalletType}`.
- `idp/metamask.go:40` `GetToken(code)` = `json.Unmarshal(code → Web3AuthToken)`;
  `AccessToken = web3AuthToken.Signature` (carried, **never recovered**).
- `idp/metamask.go:57` `GetUserInfo` returns `Id = web3AuthToken.Address` — the
  **claimed** address becomes the identity, unverified. `:58` has a literal
  `// TODO use go-ethereum to check` — the check was never written.
- `idp/web3onboard.go:69` same, `Id = "<WalletType>_<Address>"`.

### Claimed address → casdoor user + JWT — `controllers/auth.go`
- `:821` Web3 shares the OAuth branch: `idProvider.GetToken(authForm.Code)`
  (`:849`) → `token.Valid()` (`:855`) → `idProvider.GetUserInfo(token)` (`:860`).
  `authForm.Code` is the `Web3AuthToken` JSON.
- signup branch: `GetUserByField(application.Organization, provider.Type,
  userInfo.Id)` (`:888`); auto-provision `AddUser` (`:1048`); link with
  `LinkUserAccount(user, provider.Type, userInfo.Id)` (`:1079`, `:1128`).
- `object/user_util.go:35` `GetUserByField` → `WHERE <field>=?` on the User
  table (`field` = the provider's lowercased column, e.g. `web3onboard`).
- `object/user.go:1377` `LinkUserAccount` → `object/user_util.go:198`
  `SetUserField` → single-column `UPDATE`. **One address, one varchar column** —
  cannot hold N wallets across chains.
- JWT/session minted by `c.HandleLoggedIn(application, user, &authForm)` (`:908`).

### Nonce / challenge — **does not exist server-side**
- Repo grep for a web3 nonce store returns nothing. The `nonce` at
  `controllers/auth.go:144` / `:1319` is the **OIDC `id_token` nonce**, unrelated.
- `Web3AuthToken.Nonce` is client-minted (`Web3Auth.tsx:44`) and **never stored
  or validated** → replay is unbounded.

### Routing / the SPA gotcha
- `routers/router.go:33` `web.NSNamespace("/v1/iam", ...)` + explicit
  `web.Router("/v1/iam/<x>", &controllers.ApiController{}, "<METHOD>:<Fn>")`
  lines (`:46`–`:105`+).
- `routers/path_rewrite_filter.go` collapses `/api/*` → `/v1/iam/*` and
  `/oauth/*`/aliases → `/v1/iam/oauth/*`.
- `routers/static_filter.go:43` serves the SPA `index.html` as a catch-all → an
  **unregistered `/v1/iam/...` path returns `200 text/html`, not `404`**
  (HIP-0111 gotcha). A typo in a route is silent breakage.

---

## 2. Server-side design — canonical endpoints

Two endpoints, both under `/v1/iam` (HIP-0111). They replace the OAuth-shaped
`code`-smuggling entirely.

### `GET /v1/iam/web3/nonce`
Mint + store a single-use CAIP-122 challenge.

Query: `?chain=<evm|solana|bitcoin|ton|xrp>&address=<addr>`
(advisory; the authoritative binding is the *signed* message.)

Response (`Web3NonceResponse`, shaped as `LoginChallenge`):
```json
{
  "status": "ok",
  "data": {
    "domain": "hanzo.id",
    "uri": "https://hanzo.id/login",
    "statement": "Sign in to Hanzo. This request will not trigger a blockchain transaction or cost any gas.",
    "nonce": "a1b2c3d4e5f6...",
    "issuedAt": "2026-06-22T00:00:00Z",
    "expirationTime": "2026-06-22T00:10:00Z",
    "version": "1"
  }
}
```
`domain` is derived from the **request host**, never the client.

### `POST /v1/iam/web3/verify`
Verify a `SignedProof`, burn the nonce, log in.

Request (a `SignedProof` + routing fields):
```json
{
  "organization": "hanzo",
  "application": "app-hanzo",
  "method": "signup",            // "signup" (default) | "login"
  "chain": "evm",
  "scheme": "secp256k1-eip191",
  "address": "0xbd54...76de",
  "publicKey": "",               // required for solana/ton/xrp
  "message": "hanzo.id wants you to sign in with your Ethereum account:\n0x...\n\n...\nNonce: a1b2...\nIssued At: ...",
  "signature": "0x...",
  "extra": {}                     // ton_proof envelope / btc address-type hints
}
```
Response on success — identical shape to `Login()` (`HandleLoggedIn` result):
```json
{ "status": "ok", "data": { /* redirect target or logged-in payload */ } }
```
Failure: `{ "status": "error", "msg": "web3: verification failed: bad-signature" }`
(reason is the stable `walletconnect.Reason` code).

### Nonce: mint → store → burn
- **Mint** in the GET handler: random nonce (≥ 8 alnum; draft uses 36-hex),
  `expireTime = now + 10m`, persisted via `object.AddWeb3Nonce`.
- **Burn** in the POST handler **before crypto**: `object.BurnWeb3Nonce(nonce)`
  is a **conditional single-row `UPDATE used=false → true`**. `affected==0`
  (already used / unknown / expired) → reject. Atomicity is the replay guard —
  never "read then write". (`web3_store.go.draft`.)
- The nonce comes out of the **signed** message (`ParseSiwxMessage(proof.message)`),
  not a separate body field, so a forged body can't desync nonce from signature.

### `(chain,address)` → casdoor user (one user, many wallets)
New side table `WalletLink {owner,user,chain,address,scheme,publicKey,createdTime}`
with PK/unique on `(owner,user,chain,address)` and a unique `(chain,address)`
(global) so a wallet binds to **at most one** identity.

`VerifyWeb3` resolution order:
1. `GetWalletLink(org, chain, verifiedAddress)` → if found, load that user → login.
2. Not found + an **authenticated session** present → link the new wallet to the
   session's user (this is how a user adds a 2nd/3rd chain).
3. Not found + no session + `method=="signup"` + `app.EnableSignUp` →
   `provisionWalletUser` (username `"<chain>_<address>"`, no password) → insert link.
4. Not found + `method=="login"` → error "no account linked to this wallet".

We **never** link by address alone across identities — that would let a wallet
hijack a social/password account (see risk 4).

EVM addresses are canonicalized lowercase by the verifier; store + look up
lowercased so EVM stays case-insensitive.

---

## 3. Go handler — uses `walletconnect.VerifyProof`

Full draft: `web3_auth.go.draft`. The load-bearing call:

```go
import wc "github.com/luxwallet/wallet-connect/go/walletconnect"

res := wc.VerifyProof(wc.Proof{
    Chain:     wc.Chain(form.Chain),
    Scheme:    wc.SignatureScheme(form.Scheme),
    Address:   form.Address,
    PublicKey: form.PublicKey,
    Message:   form.Message,
    Signature: form.Signature,
    Extra:     form.Extra,
}, wc.Expectation{
    Domain:    rec.Domain,        // from the burned nonce row, host-derived at mint
    Nonce:     parsed.Nonce,      // parsed from the SIGNED message
    ClockSkew: wc.DefaultClockSkew,
})
if !res.OK {
    c.ResponseError(fmt.Sprintf("web3: verification failed: %s", res.Reason))
    return
}
verifiedAddress := res.Address   // canonicalized
```

**Confirmed Go API** (`go/walletconnect/verify.go`, `stubs.go`, `caip122.go`):
- `func VerifyProof(proof Proof, expected Expectation) Result`
- `type Proof struct { Chain Chain; Scheme SignatureScheme; Address, PublicKey, Message, Signature string; Extra map[string]any }`
- `type Expectation struct { Domain, Nonce, Address string; Now time.Time; ClockSkew time.Duration }`
- `type Result struct { OK bool; Reason Reason; Address string; Chain Chain }`
- `func ParseSiwxMessage(string) (ParsedSiwx, error)`
- Chains: `ChainEVM/Solana/Bitcoin/TON/XRP`; `DefaultClockSkew = 5*time.Minute`.

> Note the Go names: it's `walletconnect.Proof` / `Expectation` / `Result`
> (the TS names are `SignedProof` / `VerifyExpectation` / `VerifyResult`).

### go.mod diff (SPECIFY ONLY — do not apply; would break the build until published)

IAM `go.mod` today already has `github.com/luxfi/crypto v1.19.0` (`:51`) and
`github.com/mr-tron/base58 v1.2.0 // indirect` (`:195`). The SDK's `go/go.mod`
requires `luxfi/crypto v1.19.21` and `base58 v1.3.0` — **patch bumps within
v1.x, allowed**. **No `go-ethereum` needed** (the verifier uses `luxfi/crypto`).

```diff
 require (
     ...
-    github.com/luxfi/crypto v1.19.0
+    github.com/luxfi/crypto v1.19.21
+    github.com/luxwallet/wallet-connect/go v0.1.0
     ...
 )

 require (
     ...
-    github.com/mr-tron/base58 v1.2.0 // indirect
+    github.com/mr-tron/base58 v1.3.0 // (now a direct dep via walletconnect)
     ...
 )

+// Local dev until luxwallet/wallet-connect/go is tagged + published:
+replace github.com/luxwallet/wallet-connect/go => /Users/z/work/lux/wallet-connect/go
```
Then `go mod tidy`. Remove the `replace` once the module is tagged.

### routers/router.go diff (SPECIFY ONLY)
```go
web.Router("/v1/iam/web3/nonce",  &controllers.ApiController{}, "GET:GetWeb3Nonce")
web.Router("/v1/iam/web3/verify", &controllers.ApiController{}, "POST:VerifyWeb3")
```
Add an explicit-route test (mirror `routers/v1_iam_login_route_test.go`) asserting
both return JSON (not the SPA `text/html`) — closes the catch-all gotcha (risk 1).
Register `Web3Nonce` + `WalletLink` in the ormer table-sync list.

---

## 4. Frontend design

Full draft: `WalletConnect.tsx.draft` (→ `web/src/auth/WalletConnect.tsx`),
replacing `Web3Auth.tsx`'s `@web3-onboard` machinery.

Per-chain flow (orthogonal: connect is browser-side, verify is server-side):
1. `connector.connect()` → `Account {chain,address,publicKey?,walletId}`
2. `GET /v1/iam/web3/nonce` → `LoginChallenge`
3. `connector.signLogin(account, challenge)` → `SignedProof`
   (the connector renders the canonical CAIP-122 message; TON uses its
   `ton_proof` envelope internally and returns `scheme:"ton-proof"`)
4. `POST /v1/iam/web3/verify` → on `ok`, redirect / reload like the OAuth path.

The picker renders one button per **enabled** chain. EVM's signing scheme changes
from the old **EIP-712 typed-data** to the SDK's **EIP-191 `personal_sign` over
CAIP-122** — the legacy typed-data path is dropped (one way only).

### npm deps for the connectors (all MIT / Apache / ISC — zero GPL)

| Chain | Library | License | Notes |
|-------|---------|---------|-------|
| EVM | `viem` (+ `wagmi`) | **MIT** | injected + WalletConnect v2; `personal_sign` |
| Solana | `@solana/wallet-adapter-base` / `-react` | **Apache-2.0** | Phantom/Solflare; `signMessage` (ed25519) |
| Bitcoin | `sats-connect` | **ISC** | Xverse/Leather; BIP-322 message signing |
| TON | `@tonconnect/ui` (`@tonconnect/sdk`) | **Apache-2.0** | TON Connect `ton_proof` |
| XRP | `@gemwallet/api` *(MIT)* or `xrpl` *(ISC)* | **MIT / ISC** | GemWallet `signMessage`; `xrpl` for keys/derivation |
| shared | `@noble/curves`, `@noble/hashes`, `bs58` | **MIT** | already the SDK's verify-core deps |

Remove from `web/package.json`: `@web3-onboard/*` and `@metamask/eth-sig-util`
(typed-data recovery no longer used). The connectors themselves are
`@luxwallet/connect/connectors` — **currently TODO in the SDK** (the verifiers
are done; the browser connectors are the next SDK milestone). Until they exist,
the frontend can call the chain libs directly behind the same `WalletConnector`
interface.

---

## 5. Risks

1. **SPA catch-all 200 (HIP-0111).** Unregistered `/v1/iam/web3/*` returns
   `200 text/html` (`static_filter.go:43`), so a route typo looks like a broken
   wallet, not a 404. *Mitigation:* explicit `web.Router` lines + a routes test
   asserting JSON content-type/`status` field.

2. **Nonce replay.** The current path has **no server nonce** at all. *Mitigation:*
   single-use store + **atomic conditional burn** (`BurnWeb3Nonce`, `UPDATE
   used=false→true`, `affected==0`⇒reject), 10-min TTL, nonce read from the
   *signed* message, domain bound to the request host. `VerifyProof` re-checks
   nonce + time independently.

3. **Address spoofing.** Today the claimed address is trusted verbatim
   (`metamask.go:65`, `web3onboard.go` carries no signature). *Mitigation:*
   `VerifyProof` enforces `message.address == proof.address` **and** the crypto
   recovery/verification per scheme; identity = the *verified* address only.

4. **Multi-wallet vs existing social/password identities.** A wallet must not be
   able to seize an email/password or OAuth account. *Mitigation:* `(chain,address)`
   is globally unique in `WalletLink`; a wallet links to an existing identity
   **only** via an authenticated session (or, if added, a verified-email
   challenge) — **never** silently by address. Fresh wallets provision a distinct
   `"<chain>_<address>"` user.

5. **Backend coverage gap (fail-closed).** Go ports for **TON, Bitcoin, XRP are
   stubs** (`go/walletconnect/stubs.go` → `false`); only **EVM + Solana** verify
   today. TS has EVM/Solana/TON/XRP done, **Bitcoin still a stub**. So those
   chains *fail closed* (`reason: bad-signature`) until each port lands.
   *Mitigation:* `ENABLED_CHAINS = ["evm","solana"]` in the picker; enable each
   chain only when **both** its TS and Go verifiers are green. (Tracking matrix
   below.)

6. **EVM signing-scheme switch.** Old path = EIP-712 typed data; new path = EIP-191
   `personal_sign` over CAIP-122. *Mitigation:* delete the typed-data path
   (`signEthereumTypedData`, `checkEthereumSignedTypedData`) — one canonical way;
   no dual-scheme verifier.

7. **Casdoor provider rows.** The old `MetaMask` / `Web3Onboard` provider entries
   and `idp/{metamask,web3onboard}.go` become dead. *Mitigation:* leave them
   inert initially (no provider configured ⇒ unreachable), delete in a follow-up
   once the new path is in production. New flow does **not** route through
   `idp.GetIdProvider` at all.

### Chain readiness matrix (gate the picker on this)

| Chain | Scheme | TS verifier | Go verifier | Enable now? |
|-------|--------|-------------|-------------|-------------|
| EVM | `secp256k1-eip191` | done | **done** (`evm.go`) | **yes** |
| Solana | `ed25519` | done | **done** (`solana.go`) | **yes** |
| TON | `ton-proof` | done | stub (`stubs.go`) | no — port Go |
| XRP | `secp256k1-xrpl` / `ed25519-xrpl` | done | stub | no — port Go |
| Bitcoin | `bip322` | **stub** | stub | no — port both |

---

## Sequencing
1. Land Go ports for TON/XRP (mirror the done TS); implement BIP-322 in TS then Go.
2. Build `@luxwallet/connect/connectors` (browser side).
3. Tag + publish `github.com/luxwallet/wallet-connect/go`; drop the `replace`.
4. Apply the IAM diffs (controller, store, router, go.mod, ormer sync, frontend).
5. Add routes test (anti-catch-all) + an e2e (Playwright) per enabled chain:
   connect → nonce → sign → verify → session.
6. Remove `@web3-onboard/*`, `@metamask/eth-sig-util`, and the dead idp providers.

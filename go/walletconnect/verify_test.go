package walletconnect

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	luxcrypto "github.com/luxfi/crypto"
	"github.com/mr-tron/base58"
)

func nowTime() time.Time { return time.UnixMilli(fixedNow) }

func baseChallenge() LoginChallenge {
	return newChallenge(challengeOpts{
		domain: "hanzo.id",
		uri:    "https://hanzo.id/login",
		nonce:  "abc12345",
		nowMs:  fixedNow,
	})
}

func TestVerifyProof_AcceptsFreshEVM(t *testing.T) {
	c := baseChallenge()
	priv, err := luxcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	address := AddressFromPublicKey(luxcrypto.FromECDSAPub(&priv.PublicKey))
	msg := mustBuild(t, BuildParams{Challenge: c, Address: address, Chain: ChainEVM})
	sig, err := luxcrypto.Sign(EIP191Digest(msg), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sig[64] += 27
	proof := Proof{
		Chain:     ChainEVM,
		Scheme:    SchemeSecp256k1EIP191,
		Address:   address,
		Message:   msg,
		Signature: "0x" + hex.EncodeToString(sig),
	}
	res := VerifyProof(proof, Expectation{Domain: "hanzo.id", Nonce: "abc12345", Now: nowTime()})
	if !res.OK {
		t.Fatalf("expected OK, got reason %q", res.Reason)
	}
	if res.Address != address {
		t.Errorf("address = %q want %q", res.Address, address)
	}
	if res.Chain != ChainEVM {
		t.Errorf("chain = %q", res.Chain)
	}
}

func freshSolanaProof(t *testing.T, c LoginChallenge) (Proof, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	address := base58.Encode(pub)
	msg := mustBuild(t, BuildParams{Challenge: c, Address: address, Chain: ChainSolana})
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(msg)))
	return Proof{Chain: ChainSolana, Scheme: SchemeEd25519, Address: address, Message: msg, Signature: sig}, address
}

func TestVerifyProof_AcceptsFreshSolana(t *testing.T) {
	proof, _ := freshSolanaProof(t, baseChallenge())
	res := VerifyProof(proof, Expectation{Domain: "hanzo.id", Nonce: "abc12345", Now: nowTime()})
	if !res.OK {
		t.Fatalf("expected OK, got reason %q", res.Reason)
	}
}

func TestVerifyProof_RejectsWrongNonceAndDomain(t *testing.T) {
	// Address must match the message; signature need not verify because the
	// nonce/domain checks run before crypto. Build a real signer to satisfy the
	// address binding, then assert the pre-crypto reason.
	proof, _ := freshSolanaProof(t, baseChallenge())

	if r := VerifyProof(proof, Expectation{Domain: "hanzo.id", Nonce: "WRONG", Now: nowTime()}).Reason; r != ReasonNonceMismatch {
		t.Errorf("nonce: reason = %q want %q", r, ReasonNonceMismatch)
	}
	if r := VerifyProof(proof, Expectation{Domain: "evil.com", Nonce: "abc12345", Now: nowTime()}).Reason; r != ReasonDomainMismatch {
		t.Errorf("domain: reason = %q want %q", r, ReasonDomainMismatch)
	}
}

func TestVerifyProof_RejectsExpired(t *testing.T) {
	c := newChallenge(challengeOpts{
		domain:     "hanzo.id",
		uri:        "https://hanzo.id/login",
		nonce:      "abc12345",
		nowMs:      fixedNow,
		ttlSeconds: 60,
	})
	proof, _ := freshSolanaProof(t, c)
	// now is 1h after issuance, well past 60s ttl + default 5m skew.
	res := VerifyProof(proof, Expectation{
		Domain: "hanzo.id",
		Nonce:  "abc12345",
		Now:    time.UnixMilli(fixedNow + 3_600_000),
	})
	if res.Reason != ReasonExpired {
		t.Fatalf("reason = %q want %q", res.Reason, ReasonExpired)
	}
}

func TestVerifyProof_RejectsNotYetValid(t *testing.T) {
	// notBefore far in the future => not-yet-valid.
	c := baseChallenge()
	nbf := isoFromEpochMs(fixedNow + 3_600_000)
	c.NotBefore = &nbf
	proof, _ := freshSolanaProof(t, c)
	res := VerifyProof(proof, Expectation{Domain: "hanzo.id", Nonce: "abc12345", Now: nowTime()})
	if res.Reason != ReasonNotYetValid {
		t.Fatalf("reason = %q want %q", res.Reason, ReasonNotYetValid)
	}
}

func TestVerifyProof_RejectsAddressMismatch(t *testing.T) {
	// Message embeds a different address than the proof claims.
	proof, _ := freshSolanaProof(t, baseChallenge())
	proof.Address = randSolanaAddress(t)
	res := VerifyProof(proof, Expectation{Domain: "hanzo.id", Nonce: "abc12345", Now: nowTime()})
	if res.Reason != ReasonAddressMismatch {
		t.Fatalf("reason = %q want %q", res.Reason, ReasonAddressMismatch)
	}
}

func TestVerifyProof_MalformedMessage(t *testing.T) {
	proof := Proof{Chain: ChainEVM, Scheme: SchemeSecp256k1EIP191, Address: "0xabc", Message: "garbage", Signature: "0x00"}
	res := VerifyProof(proof, Expectation{Domain: "hanzo.id", Nonce: "abc12345", Now: nowTime()})
	if res.Reason != ReasonMalformedMessage {
		t.Fatalf("reason = %q want %q", res.Reason, ReasonMalformedMessage)
	}
}

func TestVerifyProof_FailsClosedUnknownScheme(t *testing.T) {
	c := baseChallenge()
	msg := mustBuild(t, BuildParams{Challenge: c, Address: "rXYZ", Chain: ChainXRP})
	proof := Proof{Chain: ChainXRP, Scheme: SignatureScheme("totally-unknown"), Address: "rXYZ", Message: msg, Signature: "00"}
	res := VerifyProof(proof, Expectation{Domain: "hanzo.id", Nonce: "abc12345", Now: nowTime()})
	if res.Reason != ReasonUnsupportedScheme {
		t.Fatalf("reason = %q want %q", res.Reason, ReasonUnsupportedScheme)
	}
}

func TestVerifyProof_FailsClosedWiredButUnverifiable(t *testing.T) {
	// A known-but-stubbed scheme (XRPL) wired with junk: passes parse/domain/
	// nonce/time, then the crypto stub returns false => bad-signature.
	c := baseChallenge()
	msg := mustBuild(t, BuildParams{Challenge: c, Address: "rXYZ", Chain: ChainXRP})
	proof := Proof{Chain: ChainXRP, Scheme: SchemeSecp256k1XRPL, Address: "rXYZ", Message: msg, Signature: "00"}
	res := VerifyProof(proof, Expectation{Domain: "hanzo.id", Nonce: "abc12345", Now: nowTime()})
	if res.OK {
		t.Fatal("expected fail-closed")
	}
	if res.Reason != ReasonBadSignature {
		t.Fatalf("reason = %q want %q", res.Reason, ReasonBadSignature)
	}
}

func TestVerifyProof_ExpectedAddressMismatch(t *testing.T) {
	// Proof verifies, but Expectation.Address pins a different address (EVM
	// case-insensitive path).
	c := baseChallenge()
	priv, err := luxcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	address := AddressFromPublicKey(luxcrypto.FromECDSAPub(&priv.PublicKey))
	msg := mustBuild(t, BuildParams{Challenge: c, Address: address, Chain: ChainEVM})
	sig, err := luxcrypto.Sign(EIP191Digest(msg), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sig[64] += 27
	proof := Proof{Chain: ChainEVM, Scheme: SchemeSecp256k1EIP191, Address: address, Message: msg, Signature: "0x" + hex.EncodeToString(sig)}
	res := VerifyProof(proof, Expectation{
		Domain:  "hanzo.id",
		Nonce:   "abc12345",
		Address: "0x0000000000000000000000000000000000000000",
		Now:     nowTime(),
	})
	if res.Reason != ReasonAddressMismatch {
		t.Fatalf("reason = %q want %q", res.Reason, ReasonAddressMismatch)
	}
}

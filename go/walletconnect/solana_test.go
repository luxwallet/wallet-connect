package walletconnect

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/mr-tron/base58"
)

// solanaSign produces a real ed25519 proof (base64 signature, base58 address)
// the verifier must accept. Mirrors the TS solanaSign test helper.
func solanaSign(t *testing.T, message string) (address, signature string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	address = base58.Encode(pub)
	signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(message)))
	return address, signature
}

func randSolanaAddress(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return base58.Encode(pub)
}

func TestVerifySolana_AcceptsValidSignature(t *testing.T) {
	message := "hello solana"
	address, signature := solanaSign(t, message)
	if !VerifySolana(message, signature, address) {
		t.Fatal("expected valid signature to verify")
	}
}

func TestVerifySolana_RejectsTamperedMessage(t *testing.T) {
	address, signature := solanaSign(t, "original")
	if VerifySolana("tampered", signature, address) {
		t.Fatal("expected tampered message to be rejected")
	}
}

func TestVerifySolana_RejectsWrongAddress(t *testing.T) {
	_, signature := solanaSign(t, "m")
	other := randSolanaAddress(t)
	if VerifySolana("m", signature, other) {
		t.Fatal("expected wrong address to be rejected")
	}
}

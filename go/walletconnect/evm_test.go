package walletconnect

import (
	"encoding/hex"
	"strings"
	"testing"

	luxcrypto "github.com/luxfi/crypto"
)

// evmSign produces a real EIP-191 proof (65-byte [R||S||V], V in 27/28) the
// verifier must accept. Mirrors the TS evmSign test helper.
func evmSign(t *testing.T, message string) (address, signature string) {
	t.Helper()
	priv, err := luxcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	address = AddressFromPublicKey(luxcrypto.FromECDSAPub(&priv.PublicKey))
	sig, err := luxcrypto.Sign(EIP191Digest(message), priv) // [R||S||V], V=0/1
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sig[64] += 27 // wallets emit V as 27/28; verifier must normalise it back
	return address, "0x" + hex.EncodeToString(sig)
}

func TestVerifyEVM_AcceptsValidSignature(t *testing.T) {
	message := "hello hanzo"
	address, signature := evmSign(t, message)
	if !VerifyEVM(message, signature, address) {
		t.Fatal("expected valid signature to verify")
	}
}

func TestVerifyEVM_CaseInsensitiveAddress(t *testing.T) {
	message := "hello"
	address, signature := evmSign(t, message)
	upper := strings.Replace(strings.ToUpper(address), "0X", "0x", 1)
	if !VerifyEVM(message, signature, upper) {
		t.Fatal("expected case-insensitive address match")
	}
}

func TestVerifyEVM_RejectsTamperedMessage(t *testing.T) {
	address, signature := evmSign(t, "original")
	if VerifyEVM("tampered", signature, address) {
		t.Fatal("expected tampered message to be rejected")
	}
}

func TestVerifyEVM_RejectsWrongAddress(t *testing.T) {
	_, signature := evmSign(t, "m")
	if VerifyEVM("m", signature, "0x0000000000000000000000000000000000000000") {
		t.Fatal("expected wrong address to be rejected")
	}
}

func TestVerifyEVM_RejectsMalformedSignature(t *testing.T) {
	// Not 65 bytes => unrecoverable => false (fail closed).
	if VerifyEVM("m", "0xdeadbeef", "0x0000000000000000000000000000000000000000") {
		t.Fatal("expected malformed signature to be rejected")
	}
}

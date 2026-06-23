package walletconnect

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
)

// Byte helpers shared by every verifier. Mirror src/bytes.ts.

// hexToBytes decodes hex, tolerant of a leading 0x/0X. Mirrors the TS
// hexToBytes.
func hexToBytes(s string) ([]byte, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	return hex.DecodeString(s)
}

// base64ToBytes decodes standard, padded base64. Mirrors the TS base64ToBytes.
func base64ToBytes(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

var pureHexRE = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// decodeSignature decodes a signature that may be hex (0x…) or base64 into raw
// bytes. The heuristic mirrors the TS decodeSignature exactly:
//   - leading 0x/0X => hex
//   - pure hex of even length => hex
//   - otherwise => base64
func decodeSignature(sig string) ([]byte, error) {
	s := strings.TrimSpace(sig)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return hexToBytes(s)
	}
	if pureHexRE.MatchString(s) && len(s)%2 == 0 {
		return hexToBytes(s)
	}
	return base64ToBytes(s)
}

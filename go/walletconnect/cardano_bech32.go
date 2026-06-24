package walletconnect

// bech32 (BIP-173) DECODE — inline, no deps, for Cardano Shelley addresses
// (addr1…/stake1… and their *_test1… testnet forms). Cardano uses plain bech32
// (constant 1) but its addresses exceed the 90-char BIP-173 limit, so this
// decoder does NOT enforce that bound (CIP-19 relaxes it). Verification-only:
// decode the claimed address to raw bytes and compare the embedded key
// credential against blake2b-224(pubkey). Fail closed — any malformation
// returns ok=false. Mirrors src/cardano/bech32.ts byte-for-byte.
//
// Every identifier is cardanoBech32-prefixed: this flat package is shared by
// all chains (btc* already owns the SegWit bech32 encoder).

import "strings"

const cardanoBech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

const cardanoBech32Const = 1

func cardanoBech32Polymod(values []int) uint32 {
	gen := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = ((chk & 0x1ffffff) << 5) ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func cardanoBech32HrpExpand(hrp string) []int {
	out := make([]int, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, int(hrp[i])>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, int(hrp[i])&31)
	}
	return out
}

// cardanoConvert5to8 converts 5-bit groups to 8-bit bytes (pad=false), strict
// per BIP-173. Returns nil on invalid input or non-zero pad.
func cardanoConvert5to8(data []int) []byte {
	var acc uint32
	var bits int
	out := make([]byte, 0, len(data)*5/8+1)
	for _, value := range data {
		if value < 0 || value>>5 != 0 {
			return nil
		}
		acc = ((acc << 5) | uint32(value)) & 0xffffffff
		bits += 5
		for bits >= 8 {
			bits -= 8
			out = append(out, byte((acc>>uint(bits))&0xff))
		}
	}
	if bits >= 5 {
		return nil
	}
	if (acc<<uint(8-bits))&0xff != 0 {
		return nil
	}
	return out
}

// cardanoBech32Decode decodes a bech32 string into its hrp and 8-bit payload,
// validating the checksum. Returns ("", nil, false) on any malformation. Mirrors
// the TS bech32Decode.
func cardanoBech32Decode(addr string) (hrp string, data []byte, ok bool) {
	lower := strings.ToLower(addr)
	upper := strings.ToUpper(addr)
	if addr != lower && addr != upper {
		return "", nil, false
	}
	s := lower

	sep := strings.LastIndex(s, "1")
	if sep < 1 || sep+7 > len(s) {
		return "", nil, false
	}
	hrp = s[:sep]
	dataPart := s[sep+1:]

	for i := 0; i < len(hrp); i++ {
		c := hrp[i]
		if c < 33 || c > 126 {
			return "", nil, false
		}
	}

	data5 := make([]int, 0, len(dataPart))
	for i := 0; i < len(dataPart); i++ {
		idx := strings.IndexByte(cardanoBech32Charset, dataPart[i])
		if idx == -1 {
			return "", nil, false
		}
		data5 = append(data5, idx)
	}

	if cardanoBech32Polymod(append(cardanoBech32HrpExpand(hrp), data5...)) != cardanoBech32Const {
		return "", nil, false
	}

	payload5 := data5[:len(data5)-6]
	bytes := cardanoConvert5to8(payload5)
	if bytes == nil {
		return "", nil, false
	}
	return hrp, bytes, true
}

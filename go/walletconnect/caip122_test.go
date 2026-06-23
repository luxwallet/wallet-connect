package walletconnect

import (
	"strings"
	"testing"
	"time"
)

// isoFromEpochMs renders an epoch-millisecond instant the way JS
// `new Date(ms).toISOString()` does: RFC3339 in UTC with millisecond precision
// and a 'Z' zone (e.g. "2023-11-14T22:13:20.000Z"). The CAIP-122 message embeds
// timestamps in exactly this shape, so the Go port must round-trip it.
func isoFromEpochMs(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z07:00")
}

type challengeOpts struct {
	domain     string
	uri        string
	statement  *string
	nonce      string
	nowMs      int64
	ttlSeconds int64 // 0 => 600
	requestID  *string
	resources  []string
}

// newChallenge mirrors the TS nonce.ts newChallenge defaults for tests.
func newChallenge(o challengeOpts) LoginChallenge {
	ttl := o.ttlSeconds
	if ttl == 0 {
		ttl = 600
	}
	issuedAt := isoFromEpochMs(o.nowMs)
	exp := isoFromEpochMs(o.nowMs + ttl*1000)
	version := "1"
	return LoginChallenge{
		Domain:         o.domain,
		URI:            o.uri,
		Statement:      o.statement,
		Nonce:          o.nonce,
		IssuedAt:       issuedAt,
		ExpirationTime: &exp,
		Version:        &version,
		RequestID:      o.requestID,
		Resources:      o.resources,
	}
}

func mustBuild(t *testing.T, p BuildParams) string {
	t.Helper()
	s, err := BuildSiwxMessage(p)
	if err != nil {
		t.Fatalf("BuildSiwxMessage: %v", err)
	}
	return s
}

const fixedNow int64 = 1_700_000_000_000

func TestCaip122_BuildParseRoundTrip(t *testing.T) {
	stmt := "Sign in to Hanzo."
	reqID := "req-1"
	c := newChallenge(challengeOpts{
		domain:     "hanzo.id",
		uri:        "https://hanzo.id/login",
		statement:  &stmt,
		nonce:      "abc12345",
		nowMs:      fixedNow,
		ttlSeconds: 600,
		requestID:  &reqID,
		resources:  []string{"https://hanzo.ai/api", "https://hanzo.chat"},
	})
	chainID := "eip155:1"
	msg := mustBuild(t, BuildParams{
		Challenge: c,
		Address:   "0x1111111111111111111111111111111111111111",
		Chain:     ChainEVM,
		ChainID:   &chainID,
	})

	p, err := ParseSiwxMessage(msg)
	if err != nil {
		t.Fatalf("ParseSiwxMessage: %v", err)
	}
	if p.Domain != "hanzo.id" {
		t.Errorf("domain = %q", p.Domain)
	}
	if p.Address != "0x1111111111111111111111111111111111111111" {
		t.Errorf("address = %q", p.Address)
	}
	if p.Statement == nil || *p.Statement != "Sign in to Hanzo." {
		t.Errorf("statement = %v", p.Statement)
	}
	if p.URI != "https://hanzo.id/login" {
		t.Errorf("uri = %q", p.URI)
	}
	if p.Version == nil || *p.Version != "1" {
		t.Errorf("version = %v", p.Version)
	}
	if p.ChainID == nil || *p.ChainID != "eip155:1" {
		t.Errorf("chainId = %v", p.ChainID)
	}
	if p.Nonce != "abc12345" {
		t.Errorf("nonce = %q", p.Nonce)
	}
	if p.IssuedAt != isoFromEpochMs(fixedNow) {
		t.Errorf("issuedAt = %q want %q", p.IssuedAt, isoFromEpochMs(fixedNow))
	}
	if p.ExpirationTime == nil || *p.ExpirationTime != isoFromEpochMs(fixedNow+600_000) {
		t.Errorf("expirationTime = %v", p.ExpirationTime)
	}
	if p.RequestID == nil || *p.RequestID != "req-1" {
		t.Errorf("requestId = %v", p.RequestID)
	}
	if len(p.Resources) != 2 || p.Resources[0] != "https://hanzo.ai/api" || p.Resources[1] != "https://hanzo.chat" {
		t.Errorf("resources = %v", p.Resources)
	}
}

func TestCaip122_ChainLabelOnHeader(t *testing.T) {
	c := newChallenge(challengeOpts{domain: "hanzo.id", uri: "https://hanzo.id", nonce: "nonce123", nowMs: fixedNow})
	cases := []struct {
		chain Chain
		want  string
	}{
		{ChainSolana, "wants you to sign in with your Solana account:"},
		{ChainBitcoin, "with your Bitcoin account:"},
		{ChainTON, "with your TON account:"},
		{ChainXRP, "with your XRP Ledger account:"},
	}
	for _, tc := range cases {
		msg := mustBuild(t, BuildParams{Challenge: c, Address: "addr", Chain: tc.chain})
		if !strings.Contains(msg, tc.want) {
			t.Errorf("chain %s: message missing %q\n%s", tc.chain, tc.want, msg)
		}
	}
}

func TestCaip122_OmitsOptionalFields(t *testing.T) {
	c := newChallenge(challengeOpts{domain: "d", uri: "https://d", nonce: "nonce123", nowMs: fixedNow})
	c.ExpirationTime = nil
	msg := mustBuild(t, BuildParams{Challenge: c, Address: "a", Chain: ChainEVM})
	if strings.Contains(msg, "Chain ID:") {
		t.Error("should omit Chain ID")
	}
	if strings.Contains(msg, "Request ID:") {
		t.Error("should omit Request ID")
	}
	if strings.Contains(msg, "Resources:") {
		t.Error("should omit Resources")
	}
	if strings.Contains(msg, "Expiration Time:") {
		t.Error("should omit Expiration Time")
	}
}

func TestCaip122_RejectsMultiLineStatement(t *testing.T) {
	bad := "a\nb"
	c := newChallenge(challengeOpts{domain: "d", uri: "https://d", nonce: "nonce123", nowMs: fixedNow, statement: &bad})
	if _, err := BuildSiwxMessage(BuildParams{Challenge: c, Address: "a", Chain: ChainEVM}); err == nil {
		t.Fatal("expected error on multi-line statement")
	}
}

func TestCaip122_ThrowsOnMalformedMessage(t *testing.T) {
	if _, err := ParseSiwxMessage("not a siwx message"); err == nil {
		t.Fatal("expected error on malformed message")
	}
}

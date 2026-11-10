// Boundary rows for pfb_unbound_idn.go that pfb_unbound_idn_test.go's Python-pinned rows do not reach: the whole of the
// punycode adaptation (checked against x/net's independent encoder), the U+10FFFF limit, the severity order, and the
// "xn--" shape of is_idn_domain.
package decider

import (
	"math/rand/v2"
	"strings"
	"testing"

	"golang.org/x/net/idna"
)

// Every string decodeIdnLabel decodes after x/net's raw punycode encoder wrote it (RFC 3492 is deterministic, so Python's
// codec agrees too): each adaptation step, the bias update and the insertion order are on this path.
func TestDecodeIdnLabelRoundTripsXNetPunycode(t *testing.T) {
	rng := rand.New(rand.NewPCG(3779, 8))
	alphabets := [][]rune{
		[]rune("abcdefghijklmnopqrstuvwxyz0123456789-ABCXYZ"),
		[]rune("\u00e4\u00f6\u00fc\u00df\u0430\u0431\u0432\u03b1\u03b2\u03b3\u05d0\u05d1\u0627\u0628"),
		[]rune("\u4e2d\u6587\u65e5\u672c\u8a9e\ud55c\uae00\u3072\u3089\u30ab\u30bf\u0e01\u0e02\u0915\u0916"),
		{0x1F4A9, 0x1F600, 0x10FFFF, 0x1D400, 0x20000, 0x2EBF0, 0x80, 0xFFFF, 0x7FF, 0x800},
	}
	for range 3000 {
		var s []rune
		for range 1 + rng.IntN(24) {
			alphabet := alphabets[0]
			if rng.IntN(3) > 0 {
				alphabet = alphabets[rng.IntN(len(alphabets))]
			}
			s = append(s, alphabet[rng.IntN(len(alphabet))])
		}
		encoded, err := idna.Punycode.ToASCII(string(s))
		if err != nil || !strings.HasPrefix(encoded, "xn--") {
			continue // all-ASCII input is no A-label
		}
		if got, err := decodeIdnLabel(encoded); err != nil || got != string(s) {
			t.Fatalf("decodeIdnLabel(%q) = (%+q, %v), want %+q", encoded, got, err, string(s))
		}
	}
}

// The limit is the code point, not the code point plus one: U+10FFFF decodes, U+110000 is Python's "Invalid character".
func TestDecodeIdnLabelCodePointLimit(t *testing.T) {
	if got, err := decodeIdnLabel("xn--dn32g"); err != nil || got != "\U0010FFFF" {
		t.Errorf("decodeIdnLabel(xn--dn32g) = (%+q, %v), want U+10FFFF", got, err)
	}
	for _, label := range []string{"xn--en32g", "xn--fn32g"} {
		if got, err := decodeIdnLabel(label); err == nil || idnErrClass(err) != "UnicodeError" || !strings.Contains(err.Error(), "Invalid character U+11") {
			t.Errorf("decodeIdnLabel(%q) = (%+q, %v), want a UnicodeError: Invalid character U+11....", label, got, err)
		}
	}
}

// _SEV_ORDER: legit < flagged < suspicious < malicious, so the most severe label names the whole, in either label order.
func TestClassifyIdnSeverityOrder(t *testing.T) {
	byTier := map[string]string{
		SEV_LEGIT: "xn--mnchen-3ya", SEV_FLAGGED: "xn--zz", SEV_SUSPICIOUS: "xn--bnk-1ce", SEV_MALICIOUS: "xn--pple-43d",
	}
	tiers := []string{SEV_LEGIT, SEV_FLAGGED, SEV_SUSPICIOUS, SEV_MALICIOUS}
	for i, low := range tiers {
		for _, high := range tiers[i+1:] {
			for _, name := range []string{byTier[low] + "." + byTier[high], byTier[high] + "." + byTier[low]} {
				if got := classifyIdn(name).severity; got != high {
					t.Errorf("classifyIdn(%q).severity = %q, want %q", name, got, high)
				}
			}
		}
	}
	for _, tier := range tiers {
		if got := classifyIdn(byTier[tier]).severity; got != tier {
			t.Errorf("classifyIdn(%q).severity = %q, want %q: the fixture label is not its tier", byTier[tier], got, tier)
		}
	}
}

func TestIsIdnDomainNeedsTheWholePrefix(t *testing.T) {
	for _, q := range []string{"xn-a.com", "a.xn-b", "xn.com", "xn-.com", "a.xn.b"} {
		if isIdnDomain(q) {
			t.Errorf("isIdnDomain(%q) = true, want false: only xn-- starts an A-label", q)
		}
	}
}

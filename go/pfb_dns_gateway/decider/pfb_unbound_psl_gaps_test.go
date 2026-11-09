// Rows for branches of pfb_unbound_psl.go that a mutation sweep of pfb_unbound_psl_test.go left unpinned: an uppercase
// invalid ACE label (the xn-- test is case-insensitive), the whole-name length gate applied to the ACE form, and the
// lenient query path's lowercased raw fallback. Expectations produced by running pfb_unbound.py under CPython 3.11.
package decider

import (
	"strings"
	"testing"
)

func TestPslNormalizeNameGapsMatchPython(t *testing.T) {
	repeat := func(label, sep string, count int) string {
		return strings.TrimSuffix(strings.Repeat(label+sep, count), sep)
	}
	for _, c := range []struct{ name, strict, query string }{
		{"XN--BAD.com", "err:invalid IDNA label", "ok:xn--bad|com"},
		{"XN--ABC.com", "err:invalid IDNA label", "ok:xn--abc|com"},
		{"Xn--a-.com", "err:invalid IDNA label", "ok:xn--a-|com"},
		// 25 labels of "aü" are 99 bytes and 249 as ACE; 26 are 103 bytes and 259 as ACE, past the 253 octet limit.
		{repeat("a\u00fc", ".", 25), "ok:" + repeat("xn--a-eha", ".", 25), "ok:" + repeat("xn--a-eha", "|", 25)},
		{repeat("a\u00fc", ".", 26), "err:invalid DNS name", "ok:" + repeat("xn--a-eha", "|", 26)},
	} {
		if got := pslNormalizeNameResult(c.name); got != c.strict {
			t.Errorf("pslNormalizeName(%.40q) = %.80s, want %.80s", c.name, got, c.strict)
		}
		if got := pslNormalizeQueryResult(c.name); got != c.query {
			t.Errorf("pslNormalizeQuery(%.40q) = %.80s, want %.80s", c.name, got, c.query)
		}
	}
}

func TestPslNormalizeQueryRawFallbackIsLowercasedUnlikePython(t *testing.T) {
	// U+0378 is unassigned: UTS #46 refuses the label, so the lenient path keeps it raw and lowercased. Python's
	// codec encodes it ("ok:xn--ab-g4b|com"); the strict path refuses it in both.
	if got, want := pslNormalizeQueryResult("A\u0378B.com"), "ok:a\u0378b|com"; got != want {
		t.Errorf("pslNormalizeQuery(\"A\\u0378B.com\") = %s, want %s (Python: ok:xn--ab-g4b|com)", got, want)
	}
	if got, want := pslNormalizeNameResult("A\u0378B.com"), "err:invalid DNS label"; got != want {
		t.Errorf("pslNormalizeName(\"A\\u0378B.com\") = %s, want %s (Python agrees)", got, want)
	}
}

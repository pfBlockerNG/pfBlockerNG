package decider

import "testing"

// The digits/hyphen carve-out of severityOf is ASCII only (ADR-08 Section 2, #720, #745): a label of ASCII digits and
// hyphens is legitimate, and every other label that resolves to no letter script stays flagged, including non-ASCII
// decimal digits (Arabic-Indic digits are category Nd and would pass a unicode digit test).
func TestSeverityOfDigitHyphenCarveOut(t *testing.T) {
	for _, tc := range []struct {
		label string
		want  string
	}{
		{"24", SEV_LEGIT},
		{"123-45", SEV_LEGIT},
		{"", SEV_FLAGGED},
		{"\U0001f4a9", SEV_FLAGGED},
		{"\u0660\u0661\u0662", SEV_FLAGGED},
	} {
		if got := severityOf(tc.label); got != tc.want {
			t.Errorf("severityOf(%q) = %q, want %q", tc.label, got, tc.want)
		}
	}
}

// A digit label under a punycode label (is_idn_domain gates on the whole name) is untouched whether or not the
// escalate-suspicious opt-in is on: the carve-out, not "escalation happens to be off", is why it stays legitimate.
func TestIdnConfusableActionLeavesADigitLabelUntouchedWithAndWithoutEscalation(t *testing.T) {
	const name = "24.xn--mnchen-3ya.com"
	for _, escalate := range []bool{false, true} {
		if got, _ := idnConfusableAction(name, true, escalate); got != IDN_ACT_NONE {
			t.Errorf("idnConfusableAction(%q, block, escalate=%v) = %q, want %q", name, escalate, got, IDN_ACT_NONE)
		}
	}
}

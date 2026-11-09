// Go translation of src/usr/local/pkg/pfblockerng/pfb_unbound.py lines 2346-2517 (is_idn_domain, idn_mode_decision and the ADR-08
// TR39 homoglyph analyzer; IdnMode and idn_mode_from_legacy are in pfb_unbound.go) and 2600-2651 (_idn_dual_form,
// idn_confusable_action).
//
// Python reads a code point's class from unicodedata.category() and its script from the first word of unicodedata.name(), both
// Unicode 14.0.0 in Python 3.11. scriptOf reads them from Go's unicode tables and x/text's rune names, which are the toolchain's
// Unicode version (17.0.0 under Go 1.27): a code point assigned after 14.0.0 is a letter here where Python sees an unassigned one,
// and the script vocabulary is Python's by construction. pfb_unbound_idn_test.go pins the rows where the two differ.
package decider

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/runenames"
)

func isIdnDomain(qName string) bool {
	return strings.HasPrefix(qName, "xn--") || strings.Contains(qName, ".xn--")
}

func idnModeDecision(qName string, idnMode IdnMode) bool {
	return idnMode == IdnModeAll && isIdnDomain(qName)
}

const (
	SEV_LEGIT      = "legit"
	SEV_SUSPICIOUS = "suspicious"
	SEV_MALICIOUS  = "malicious"
	SEV_FLAGGED    = "flagged"

	LEVEL_ASCII              = "ascii_only"
	LEVEL_SINGLE             = "single_script"
	LEVEL_HIGHLY_RESTRICTIVE = "highly_restrictive"
	LEVEL_NON_RESTRICTIVE    = "non_restrictive"
)

// scriptSet is Python's set[str] / frozenset[str] of script names.
type scriptSet map[string]struct{}

var (
	// >=2 of the mutually-confusable trio in ONE label -> malicious (incl. Cyrillic+Greek).
	CONFUSABLE_SET = scriptSet{"Latin": {}, "Cyrillic": {}, "Greek": {}}
	// UTS#39 Highly Restrictive allow-set: single script, OR Latin + a CJK companion.
	HIGHLY_RESTRICTIVE_SET = scriptSet{"Latin": {}, "Han": {}, "Hiragana": {}, "Katakana": {}, "Hangul": {}, "Bopomofo": {}}
	SEV_ORDER              = map[string]int{SEV_LEGIT: 0, SEV_FLAGGED: 1, SEV_SUSPICIOUS: 2, SEV_MALICIOUS: 3}
	// unicodedata.name() leading token -> script; CJK ideographs name themselves "CJK".
	NAME_PREFIX_TO_SCRIPT = map[string]string{"CJK": "Han"}
	// Common ideographic Lo marks name() would misattribute (Lm marks drop out by category).
	COMMON_LO_MARKS = map[rune]struct{}{0x3006: {}, 0x303C: {}}
)

// digits + hyphen are the EURid-exempt, letter-less "Common-only mix": legitimate, never touched in Confusable mode.
const DIGIT_HYPHEN_CHARS = "0123456789-"

// pyCodecError is the exception Python's punycode decode raises; classify_label logs type(exc).__name__, i.e. class.
// The names are Python 3.11's: 3.13+ raises UnicodeDecodeError where 3.11 raises the base UnicodeError.
type pyCodecError struct{ class, message string }

func (e *pyCodecError) Error() string { return e.class + ": " + e.message }

func decodeIdnLabel(label string) (string, error) {
	if !strings.HasPrefix(label, "xn--") {
		return label, nil
	}
	payload := label[4:]
	position := 0
	for _, r := range payload {
		if r >= 0x80 {
			return "", &pyCodecError{"UnicodeEncodeError", fmt.Sprintf("'ascii' codec can't encode character %+q in position %d: ordinal not in range(128)", r, position)}
		}
		position++
	}
	return punycodeDecode(payload)
}

// punycodeDecode is Python's Lib/encodings/punycode.py decode in strict mode: RFC 3492 without the IDNA checks.
func punycodeDecode(text string) (string, error) {
	var base []rune
	extended := text
	if pos := strings.LastIndexByte(text, '-'); pos != -1 {
		base = []rune(text[:pos])
		extended = text[pos+1:]
	}
	decoded, err := punycodeInsertionSort(base, strings.ToUpper(extended))
	if err != nil {
		return "", err
	}
	// A lone surrogate Python keeps in its str becomes U+FFFD in a Go string: both are no letter, so the verdict is the same.
	return string(decoded), nil
}

func punycodeInsertionSort(base []rune, extended string) ([]rune, error) {
	char, pos, bias := int64(0x80), int64(-1), int64(72)
	extpos := 0
	for extpos < len(extended) {
		newpos, delta, err := punycodeDecodeGeneralizedNumber(extended, extpos, bias)
		if err != nil {
			return nil, err
		}
		pos += delta + 1
		char += pos / int64(len(base)+1)
		if char > 0x10FFFF {
			return nil, &pyCodecError{"UnicodeError", fmt.Sprintf("Invalid character U+%x", char)}
		}
		pos %= int64(len(base) + 1)
		base = slices.Insert(base, int(pos), rune(char))
		bias = punycodeAdapt(delta, extpos == 0, len(base))
		extpos = newpos
	}
	return base, nil
}

// punycodeSaturation caps the numbers Python holds unbounded: a delta past it puts char above U+10FFFF for any label
// shorter than 2**31 code points, so the cap changes no outcome, and neither the products nor the sums can overflow.
const punycodeSaturation = 1 << 56

func punycodeDecodeGeneralizedNumber(extended string, extpos int, bias int64) (int, int64, error) {
	result, w := int64(0), int64(1)
	for j := int64(0); ; j++ {
		if extpos >= len(extended) {
			return 0, 0, &pyCodecError{"UnicodeError", "incomplete punicode string"}
		}
		char := extended[extpos]
		extpos++
		var digit int64
		switch {
		case 'A' <= char && char <= 'Z':
			digit = int64(char - 'A')
		case '0' <= char && char <= '9':
			digit = int64(char) - 22
		default:
			return 0, 0, &pyCodecError{"UnicodeError", fmt.Sprintf("Invalid extended code point '%c'", char)}
		}
		t := punycodeT(j, bias)
		result = min(result+digit*w, punycodeSaturation)
		if digit < t {
			return extpos, result, nil
		}
		w = min(w*(36-t), punycodeSaturation)
	}
}

// punycodeT is Python's T: tmin = 1, tmax = 26, base = 36.
func punycodeT(j, bias int64) int64 {
	return min(max(36*(j+1)-bias, 1), 26)
}

func punycodeAdapt(delta int64, first bool, numchars int) int64 {
	if first {
		delta /= 700
	} else {
		delta /= 2
	}
	delta += delta / int64(numchars)
	divisions := int64(0)
	// ((base - tmin) * tmax) // 2 == 455
	for delta > 455 {
		delta /= 35
		divisions += 36
	}
	return divisions + 36*delta/(delta+38)
}

// charName is unicodedata.name(ch, ""), cut to what scriptOf reads (the first word). x/text names a range of UnicodeData.txt
// "<CJK Ideograph Extension A>" where Python expands only the CJK unified ideograph and Hangul syllable ranges; every other
// range (TANGUT IDEOGRAPH-17000 ..) is unnamed there.
func charName(r rune) string {
	name := runenames.Name(r)
	switch {
	case strings.HasPrefix(name, "<CJK Ideograph"):
		return "CJK UNIFIED IDEOGRAPH"
	case name == "<Hangul Syllable>":
		return "HANGUL SYLLABLE"
	case strings.HasPrefix(name, "<"):
		return ""
	}
	return name
}

// scriptOf is Python's script_of: its result is a tuple of zero or one script, ok false being the empty tuple of a transparent
// point (non-letter, Lm modifier mark, Common Lo mark, or unnamed -- contributes no script).
func scriptOf(codepoint rune) (script string, ok bool) {
	if !unicode.IsLetter(codepoint) || unicode.Is(unicode.Lm, codepoint) {
		return "", false
	}
	if _, common := COMMON_LO_MARKS[codepoint]; common {
		return "", false
	}
	name := charName(codepoint)
	if name == "" {
		return "", false
	}
	token, _, _ := strings.Cut(name, " ")
	if mapped, ok := NAME_PREFIX_TO_SCRIPT[token]; ok {
		return mapped, true
	}
	return strings.ToUpper(token[:1]) + strings.ToLower(token[1:]), true
}

func resolvedScriptSet(text string) scriptSet {
	out := scriptSet{}
	for _, ch := range text {
		if script, ok := scriptOf(ch); ok {
			out[script] = struct{}{}
		}
	}
	return out
}

func scriptIntersection(a, b scriptSet) scriptSet {
	out := scriptSet{}
	for script := range a {
		if _, ok := b[script]; ok {
			out[script] = struct{}{}
		}
	}
	return out
}

func restrictionLevel(scripts scriptSet, asciiOnly bool) string {
	if asciiOnly {
		return LEVEL_ASCII
	}
	if len(scripts) == 1 {
		return LEVEL_SINGLE
	}
	if len(scripts) >= 2 && len(scriptIntersection(scripts, HIGHLY_RESTRICTIVE_SET)) == len(scripts) {
		return LEVEL_HIGHLY_RESTRICTIVE
	}
	return LEVEL_NON_RESTRICTIVE
}

func severityOf(text string) string {
	scripts := resolvedScriptSet(text)
	if len(scriptIntersection(scripts, CONFUSABLE_SET)) >= 2 {
		return SEV_MALICIOUS
	}
	if len(scripts) == 0 {
		// A digits/hyphen-only label is the ADR-08 Section 2 Common-only carve-out -- legit, not flagged. Every OTHER scriptless
		// label (empty, control-char, emoji, combining-marks-alone) stays flagged.
		if text != "" && strings.IndexFunc(text, func(r rune) bool { return !strings.ContainsRune(DIGIT_HYPHEN_CHARS, r) }) < 0 {
			return SEV_LEGIT
		}
		return SEV_FLAGGED
	}
	if level := restrictionLevel(scripts, false); level == LEVEL_SINGLE || level == LEVEL_HIGHLY_RESTRICTIVE {
		return SEV_LEGIT
	}
	return SEV_SUSPICIOUS
}

// labelVerdict is the decode-safe analysis of ONE label; offending = the scripts to surface in the log.
type labelVerdict struct {
	aLabel      string
	decoded     *string // nil = Python None
	scripts     scriptSet
	severity    string
	offending   scriptSet
	decodeError string // type(exc).__name__ of a caught decode error, "" = Python None
}

// nameVerdict is the per-label analysis of a whole name; the most severe label wins.
type nameVerdict struct {
	aName     string
	labels    []labelVerdict
	severity  string
	offending scriptSet
}

func offendingScripts(scripts scriptSet, severity string) scriptSet {
	if severity == SEV_MALICIOUS {
		return scriptIntersection(scripts, CONFUSABLE_SET)
	}
	if severity == SEV_SUSPICIOUS {
		return scripts
	}
	return scriptSet{}
}

func classifyLabel(aLabel string) labelVerdict {
	decoded, err := decodeIdnLabel(aLabel)
	if err != nil {
		// decodeIdnLabel fails only with a *pyCodecError.
		return labelVerdict{aLabel: aLabel, scripts: scriptSet{}, severity: SEV_FLAGGED, offending: scriptSet{}, decodeError: err.(*pyCodecError).class}
	}
	scripts := resolvedScriptSet(decoded)
	sev := severityOf(decoded)
	return labelVerdict{aLabel: aLabel, decoded: &decoded, scripts: scripts, severity: sev, offending: offendingScripts(scripts, sev)}
}

func classifyIdn(qName string) nameVerdict {
	parts := strings.Split(qName, ".")
	verdicts := make([]labelVerdict, len(parts))
	for i, part := range parts {
		verdicts[i] = classifyLabel(part)
	}
	worst := verdicts[0]
	for _, v := range verdicts[1:] {
		if SEV_ORDER[v.severity] > SEV_ORDER[worst.severity] {
			worst = v
		}
	}
	return nameVerdict{aName: qName, labels: verdicts, severity: worst.severity, offending: worst.offending}
}

// The Confusable tier: distinct feed/group labels so a homoglyph block is attributed apart from the blunt All-IDN feed
// ("IDN"/"DNSBL_IDN"). Malicious -> the Homoglyph feed; the suspicious/flagged tier -> the Suspect feed.
const (
	IDN_FEED_MALICIOUS  = "Homoglyph"
	IDN_GROUP_MALICIOUS = "DNSBL_Homoglyph"
	IDN_FEED_SUSPECT    = "Homoglyph_Suspect"
	IDN_GROUP_SUSPECT   = "DNSBL_Homoglyph_Suspect"
)

// The three matcher actions the analyzer's severity maps to.
const (
	IDN_ACT_NONE  = "none"
	IDN_ACT_ALERT = "alert"
	IDN_ACT_BLOCK = "block"
)

func idnDualForm(verdict *nameVerdict) string {
	worstIdx := slices.IndexFunc(verdict.labels, func(lbl labelVerdict) bool { return lbl.severity == verdict.severity })
	if worstIdx < 0 {
		return verdict.aName
	}
	worst := verdict.labels[worstIdx]
	scripts := strings.Join(slices.Sorted(maps.Keys(verdict.offending)), " ")
	if worst.decoded == nil {
		detail := worst.decodeError
		if detail == "" {
			detail = "unknown"
		}
		return worst.aLabel + " [decode-error:" + detail + "]"
	}
	if scripts != "" {
		return worst.aLabel + " [" + *worst.decoded + "] " + scripts
	}
	return worst.aLabel + " [" + *worst.decoded + "]"
}

func idnConfusableAction(qName string, blockMalicious, escalateSuspicious bool) (string, *nameVerdict) {
	if !isIdnDomain(qName) {
		return IDN_ACT_NONE, nil
	}
	verdict := classifyIdn(qName)
	sev := verdict.severity
	if sev == SEV_LEGIT {
		return IDN_ACT_NONE, &verdict
	}
	if sev == SEV_MALICIOUS {
		if blockMalicious {
			return IDN_ACT_BLOCK, &verdict
		}
		return IDN_ACT_ALERT, &verdict
	}
	// SUSPICIOUS or FLAGGED: alert by default, escalatable to block via the opt-in.
	if escalateSuspicious {
		return IDN_ACT_BLOCK, &verdict
	}
	return IDN_ACT_ALERT, &verdict
}

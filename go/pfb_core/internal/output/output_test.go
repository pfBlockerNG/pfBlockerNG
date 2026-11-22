package output

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

// capture runs Capture over a program that writes text, and returns what reached the main log and the transcript.
func capture(t *testing.T, text string) (log, transcript string) {
	t.Helper()
	var l, tr bytes.Buffer
	if !Capture("pfb-output-test-", Sinks{Log: &l, Transcript: &tr}, func(out *os.File) {
		if _, err := out.WriteString(text); err != nil {
			t.Error(err)
		}
	}) {
		t.Fatal("no output file could be made")
	}
	return l.String(), tr.String()
}

// Output that ends inside a UTF-8 sequence is flushed by the final read, each byte escaped as malformed UTF-8.
func TestTheFinalReadFlushesAnIncompleteCharacterAsEscapedBytes(t *testing.T) {
	log, transcript := capture(t, "a\xE2\x82")
	if want := `a\xE2\x82`; log != want || transcript != want {
		t.Errorf("log %q, transcript %q; want both %q", log, transcript, want)
	}
}

// An escape unit that straddles the transcript allowance is not cut: the transcript ends at the last whole unit, with the
// notice, and the main log gets everything.
func TestAnEscapeUnitAtTheAllowanceIsNotCut(t *testing.T) {
	head := strings.Repeat("a", allowance-1)
	log, transcript := capture(t, head+"\x01b")
	if want := head + `\x01b`; log != want {
		t.Errorf("log: %d bytes ending %q; want %d bytes ending %q", len(log), log[max(0, len(log)-8):], len(want), `\x01b`)
	}
	if want := head + notice; transcript != want {
		t.Errorf("transcript: %d bytes ending %q; want %d bytes ending %q", len(transcript),
			transcript[max(0, len(transcript)-len(notice)-4):], len(want), notice)
	}
}

// OneLine escapes what could break a line, cuts at the bound without splitting an escape or a character, and returns a
// clean string as it is.
func TestOneLine(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		max      int
		want     string
	}{
		{"clean", "plain text 123", 100, "plain text 123"},
		{"clean at the bound", "abcd", 4, "abcd"},
		{"TAB and LF", "a\tb\nc", 100, `a\x09b\x0Ac`},
		{"line separator", "a b", 100, `a\u{2028}b`},
		{"paragraph separator", "a b", 100, `a\u{2029}b`},
		{"multi-byte character kept", "aéb", 100, "aéb"},
		{"escape straddling the cut", "aa\x01b", 4, "aa"},
		{"escape ending at the cut", "aa\x01b", 6, `aa\x01`},
		{"multi-byte character straddling the cut", "aaé", 3, "aa"},
		{"separator straddling the cut", "aa ", 5, "aa"},
		{"TAB straddling the cut", "aa\tb", 3, "aa"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := OneLine(tc.in, tc.max)
			if got != tc.want {
				t.Errorf("OneLine(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
			}
			if len(got) > tc.max || !utf8.ValidString(got) || strings.ContainsAny(got, "  \n\t") {
				t.Errorf("OneLine(%q, %d) = %q: want at most %d bytes of valid UTF-8 without a line break", tc.in, tc.max, got, tc.max)
			}
		})
	}
}

// A cut never leaves half an escape: every output of every bound ends on a whole unit.
func TestOneLineNeverEndsInsideAnEscapeOrACharacter(t *testing.T) {
	in := "a\x01é \tb\xff€"
	whole := OneLine(in, 1000)
	for max := 0; max <= len(whole)+2; max++ {
		got := OneLine(in, max)
		if len(got) > max || !utf8.ValidString(got) || !strings.HasPrefix(whole, got) || strings.HasSuffix(got, `\`) ||
			strings.HasSuffix(got, `\x`) || strings.HasSuffix(got, `\x0`) || strings.HasSuffix(got, `\u`) || strings.HasSuffix(got, `\u{`) {
			t.Errorf("OneLine(_, %d) = %q, want a whole-unit prefix of %q within the bound", max, got, whole)
		}
	}
}

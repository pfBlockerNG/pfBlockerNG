package output

import (
	"bytes"
	"os"
	"strings"
	"testing"
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

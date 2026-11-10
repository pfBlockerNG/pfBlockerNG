// The control channel reads a lone surrogate escape as U+FFFD, a documented shortcut (parsePyJSON): Python keeps the
// surrogate. The observer's reports keep it (parsePyJSONSurrogates), because it reaches their rows. These tests pin both
// sides, so that neither reader is changed into the other's.
package decider

import (
	"os"
	"path/filepath"
	"testing"
)

func TestControlJSONReadsALoneSurrogateEscapeAsTheReplacementCharacter(t *testing.T) {
	cases := []struct {
		name, text, control, observer string
	}{
		{"a lone high surrogate", `"\ud800"`, "\uFFFD", "\xed\xa0\x80"},
		{"a lone low surrogate", `"\udfff"`, "\uFFFD", "\xed\xbf\xbf"},
		{"a high one before a plain escape", `"\ud800\u0041"`, "\uFFFDA", "\xed\xa0\x80A"},
		{"a low one before a high one", `"\udc00\ud800"`, "\uFFFD\uFFFD", "\xed\xb0\x80\xed\xa0\x80"},
		{"a pair is one character in both", `"\ud83d\ude00"`, "\U0001F600", "\U0001F600"},
		{"text with none is the same in both", `"é\u00e9"`, "éé", "éé"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := parsePyJSON(tc.text); !ok || got != tc.control {
				t.Errorf("parsePyJSON(%s) = %q, %v, want %q: the control channel reads a lone surrogate as U+FFFD", tc.text, got, ok, tc.control)
			}
			if got, ok := parsePyJSONSurrogates(tc.text); !ok || got != tc.observer {
				t.Errorf("parsePyJSONSurrogates(%s) = %q, %v, want %q: an observer report keeps it as Python does", tc.text, got, ok, tc.observer)
			}
		})
	}
}

// A control record names its IP and duration as text; a lone surrogate in either is U+FFFD by the time the command's
// message is built. Python's message holds the surrogate, which the shim's print to stderr writes as \ud800.
func TestAControlRecordWithALoneSurrogateReachesItsCommandAsTheReplacementCharacter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.json")
	if err := os.WriteFile(path, []byte(`{"seq":1,"cmd":"addbypass","ip":"192.0.2.1\ud800","duration":"\ud8005"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	record := controlReadRecord(path)
	if record == nil {
		t.Fatal("the record was not read")
	}
	want := []string{"python_control", "addbypass", "192.0.2.1\uFFFD", "\uFFFD5"}
	if got := controlRecordToCommand(record); !equalStrings(got, want) {
		t.Errorf("command = %q, want %q", got, want)
	}
}

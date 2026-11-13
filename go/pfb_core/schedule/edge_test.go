package schedule

import (
	"reflect"
	"testing"
	"time"
)

// Behaviours of the old path that testdata/schedule.json does not pin. Every verdict below was taken from PHP 8.4
// (pfb_schedule_state_valid(json_decode($text, true)), is_numeric(), pfb_quiet_hours_in_window()), not from this port.

func stateWith(key string) string {
	return `{"schema":1,"items":{"` + key + `":{"pending_occurrence":1}}}`
}

func TestParseStateTextMatchesPHP(t *testing.T) {
	for _, c := range []struct {
		name  string
		text  string
		valid bool
	}{
		{"utf8 key", stateWith("a\xc3\xa9"), true},
		{"utf8 four-byte key", stateWith("a\xf0\x9f\x98\x80"), true},
		{"invalid utf8 key", stateWith("a\xff"), false},
		{"truncated utf8 key", stateWith("a\xc3"), false},
		{"encoded surrogate key", stateWith("a\xed\xa0\x80"), false},
		{"invalid utf8 after the document", stateWith("a") + "\xff", false},
		{"surrogate pair escape", stateWith(`\ud83d\ude00`), true},
		{"escaped backslash is no surrogate", stateWith(`\\ud83d`), true},
		{"lone high surrogate escape", stateWith(`\ud83d`), false},
		{"high surrogate then text", stateWith(`\ud83dx`), false},
		{"high surrogate then other escape", stateWith(`\ud83d\u0041`), false},
		{"lone low surrogate escape", stateWith(`\ude00`), false},
		{"reversed pair", stateWith(`\ude00\ud83d`), false},
		{"escaped numeric key", stateWith(`\u0031`), false},
		{"trailing newlines", stateWith("a") + "\n\n", true},
		{"trailing NUL", stateWith("a") + "\x00", false},
		{"trailing vertical tab", stateWith("a") + "\v", false},
		{"trailing second document", stateWith("a") + " {}", false},
		{"leading no-break space", "\xc2\xa0" + `{"schema":1,"items":{}}`, false},
		{"minus zero is an integer", `{"schema":1,"items":{"a":{"pending_occurrence":-0}}}`, true},
		{"exponent is a float", `{"schema":1,"items":{"a":{"pending_occurrence":1e0}}}`, false},
		{"int64 maximum", `{"schema":1,"items":{"a":{"pending_occurrence":9223372036854775807}}}`, true},
		{"last duplicate key wins, valid", `{"schema":1,"items":{"a":{"pending_occurrence":-1,"pending_occurrence":1}}}`, true},
		{"last duplicate key wins, invalid", `{"schema":1,"items":{"a":{"pending_occurrence":1},"a":5}}`, false},
		{"field names are case sensitive", `{"schema":1,"items":{"a":{"PENDING_OCCURRENCE":1}}}`, false},
		{"upper-case literal", `{"schema":1,"items":{"a":{"pending_occurrence":1,"pending_attempted":TRUE}}}`, false},
	} {
		if _, err := ParseState([]byte(c.text)); (err == nil) != c.valid {
			t.Errorf("%s: %q: valid=%v, PHP says %v", c.name, c.text, err == nil, c.valid)
		}
	}
}

func TestNumericItemKeysMatchPHP(t *testing.T) {
	for key, numeric := range map[string]bool{
		"1.": true, ".5": true, "1.e3": true, "+.5e-3": true, " \t\n\r\v\f1": true, "1 \v": true,
		"1e": false, ".": false, "-": false, "1e+": false, "0x1A": false, "1_0": false, "inf": false, "a1": false,
		"1\u00a0": false, "\u0661": false,
	} {
		if got := !validID(key); got != numeric {
			t.Errorf("%q: numeric=%v, PHP is_numeric says %v", key, got, numeric)
		}
	}
}

func TestStateUpdatesLeaveTheInputAlone(t *testing.T) {
	const text = `{"schema":1,"items":{"ipv4:a_v4":{"pending_occurrence":10,"pending_attempted":true},"dnsbl:b":{"last_successful_check":5}}}`
	st, err := ParseState([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	pending, err := SetPending(st, map[string]int64{"dnsbl:b": 20, "ipv6:c_v6": 30})
	if err != nil {
		t.Fatal(err)
	}
	done, err := RecordOutcome(st, "ipv4:a_v4", Success, 99, nil)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := ParseState([]byte(text))
	if !reflect.DeepEqual(st, want) {
		t.Errorf("the input state changed: %#v", st)
	}
	if len(pending) != 3 || len(done) != 2 || done["ipv4:a_v4"].PendingOccurrence != nil {
		t.Errorf("updates not applied: %#v %#v", pending, done)
	}
}

func TestInApplyWindowTrailingNewline(t *testing.T) {
	noon := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC).Unix()
	for window, want := range map[string]bool{
		"02:00-06:00":     false, // outside the window: defer
		"02:00-06:00\n":   false, // PHP's $ without the D flag still matches before one final newline
		"02:00-06:00\n\n": true,  // malformed: apply now
		" 02:00-06:00":    true,
	} {
		if got := InApplyWindow(noon, window, time.UTC); got != want {
			t.Errorf("%q: %v, want %v", window, got, want)
		}
	}
}

// A state file may hold any non-negative int64; near the top of the range PHP's DateTimeImmutable('@'.$t) throws, so such a
// cursor must never come back as a due (wrapped, negative) occurrence.
func TestHostileCursorIsNeverDue(t *testing.T) {
	const top = int64(9223372036854775807)
	if _, ok, err := NextOccurrence("01hour", Schedule{Weekday: 1}, top, time.UTC); err == nil || ok {
		t.Errorf("NextOccurrence at the int64 maximum: ok=%v err=%v, want an error", ok, err)
	}
	last := top
	got := Plan([]Group{{Entry: Entry{ID: "ipv4:a_v4", Cadence: "01hour", Enabled: true}, LastCompleted: &last}}, Schedule{Weekday: 1}, 1714557600, time.UTC)
	if len(got.Due) != 0 || len(got.Occurrences) != 0 {
		t.Errorf("a cursor at the int64 maximum came back due: %v %v", got.Due, got.Occurrences)
	}
}

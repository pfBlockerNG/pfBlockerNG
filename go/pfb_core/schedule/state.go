package schedule

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"regexp"
	"strconv"
	"unicode/utf8"
)

// Outcome is how a scheduled run ended.
type Outcome string

const (
	Success         Outcome = "success"
	RetryCapReached Outcome = "retry-cap-reached"
)

// Item is one entry of the state file; a nil pointer is an absent field.
type Item struct {
	LastSuccessfulCheck, LastCompletedOccurrence, PendingOccurrence *int64
	CompletionOutcome                                               Outcome
	PendingAttempted                                                bool
}

// State holds the items of pfb_schedule_state.json by feed id. The updates return a copy and share the *int64 values with
// their input, which nothing writes through.
type State map[string]Item

var (
	errState = errors.New("schedule state is invalid")
	// PHP 8 is_numeric: optional surrounding whitespace, sign, digits[.digits] or .digits, exponent; never hex.
	numericRe = regexp.MustCompile(`^[ \t\n\r\v\f]*[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?[ \t\n\r\v\f]*$`)
	feedIDRe  = regexp.MustCompile(`^(?:ipv4:[A-Za-z0-9_]+_v4|ipv6:[A-Za-z0-9_]+_v6|dnsbl:[A-Za-z0-9_]+|extra:(?:dcc|bl))$`)
)

func validOutcome(o Outcome) bool { return o == Success || o == RetryCapReached }

// validID is the rule for an item key: not empty and not numeric (PHP would turn a numeric key into an integer).
func validID(id string) bool { return id != "" && !numericRe.MatchString(id) }

func (it Item) valid() bool {
	for _, p := range []*int64{it.LastSuccessfulCheck, it.LastCompletedOccurrence, it.PendingOccurrence} {
		if p != nil && *p < 0 {
			return false
		}
	}
	switch {
	case it == Item{}, it.PendingAttempted && it.PendingOccurrence == nil:
		return false
	case (it.LastCompletedOccurrence == nil) != (it.CompletionOutcome == ""):
		return false
	case it.CompletionOutcome != "" && !validOutcome(it.CompletionOutcome):
		return false
	}
	return it.LastCompletedOccurrence == nil || it.PendingOccurrence == nil || *it.PendingOccurrence > *it.LastCompletedOccurrence
}

func (st State) validate() error {
	for id, it := range st {
		if !validID(id) || !it.valid() {
			return errState
		}
	}
	return nil
}

// phpInt reads a non-negative integer the way PHP's json_decode makes one: no '.', 'e' or 'E', and it fits an int64.
func phpInt(v any) (*int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return nil, false
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	return &i, err == nil && i >= 0
}

func parseItem(v any) (Item, bool) {
	obj, ok := v.(map[string]any)
	var it Item
	for key, raw := range obj {
		switch key {
		case "last_successful_check":
			it.LastSuccessfulCheck, ok = phpInt(raw)
		case "last_completed_occurrence":
			it.LastCompletedOccurrence, ok = phpInt(raw)
		case "pending_occurrence":
			it.PendingOccurrence, ok = phpInt(raw)
		case "completion_outcome":
			s, isString := raw.(string)
			it.CompletionOutcome, ok = Outcome(s), isString && validOutcome(Outcome(s))
		case "pending_attempted":
			b, isBool := raw.(bool)
			it.PendingAttempted, ok = b, isBool && b
		default:
			ok = false
		}
		if !ok {
			return it, false
		}
	}
	return it, ok
}

// loneSurrogate reports an unpaired UTF-16 surrogate in a \u escape of well-formed JSON text: PHP refuses it, Go's decoder
// silently replaces it.
func loneSurrogate(b []byte) bool {
	hex := func(at int) uint64 {
		r, _ := strconv.ParseUint(string(b[at:at+4]), 16, 32)
		return r
	}
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		i++
		if b[i] != 'u' {
			continue
		}
		r := hex(i + 1)
		i += 4
		switch {
		case r >= 0xDC00 && r <= 0xDFFF:
			return true
		case r >= 0xD800 && r < 0xDC00:
			if !bytes.HasPrefix(b[i+1:], []byte(`\u`)) {
				return true
			}
			if lo := hex(i + 3); lo < 0xDC00 || lo > 0xDFFF {
				return true
			}
			i += 6
		}
	}
	return false
}

// ParseState reads the whole text of the state file, {"schema":1,"items":{...}}, with PHP json_decode semantics: an integer
// is a number without '.', 'e' or 'E' that fits an int64 (so {"schema":1.0} is invalid), and text that is not valid UTF-8
// does not decode. It returns an error exactly when pfb_schedule_state_valid() would refuse the file.
func ParseState(data []byte) (State, error) {
	if !utf8.Valid(data) {
		return nil, errState
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc any
	if dec.Decode(&doc) != nil {
		return nil, errState
	}
	if _, err := dec.Token(); err != io.EOF || loneSurrogate(data) {
		return nil, errState
	}
	top, _ := doc.(map[string]any)
	if schema, _ := top["schema"].(json.Number); len(top) != 2 || schema != "1" {
		return nil, errState
	}
	st := State{}
	switch items := top["items"].(type) {
	case []any: // PHP's empty array is a JSON list; a non-empty list has integer keys
		if len(items) > 0 {
			return nil, errState
		}
	case map[string]any:
		for id, raw := range items {
			it, ok := parseItem(raw)
			if !ok {
				return nil, errState
			}
			st[id] = it
		}
	default:
		return nil, errState
	}
	if err := st.validate(); err != nil {
		return nil, err
	}
	return st, nil
}

// update applies fn to a copy of st, as pfb_schedule_state_update does: the input and the result must both be valid.
func update(st State, fn func(State)) (State, error) {
	if err := st.validate(); err != nil {
		return nil, err
	}
	out := make(State, len(st))
	maps.Copy(out, st)
	fn(out)
	if err := out.validate(); err != nil {
		return nil, err
	}
	return out, nil
}

// SetPending reserves each occurrence as the item's pending one, unless the item already has a pending occurrence or has
// completed this or a later one. An empty map changes nothing; a bad id or a negative occurrence rejects the whole call.
func SetPending(st State, occurrences map[string]int64) (State, error) {
	for id, o := range occurrences {
		if !validID(id) || o < 0 {
			return nil, errors.New("schedule pending occurrence rejected")
		}
	}
	if len(occurrences) == 0 {
		out := make(State, len(st))
		maps.Copy(out, st)
		return out, nil
	}
	return update(st, func(s State) {
		for id, o := range occurrences {
			it := s[id]
			if it.PendingOccurrence == nil && (it.LastCompletedOccurrence == nil || o > *it.LastCompletedOccurrence) {
				it.PendingOccurrence = &o
			}
			s[id] = it
		}
	})
}

// Reserve is the tick's reservation: SetPending, then an item whose pending occurrence is absent or older takes the planned
// one and loses its attempted flag. An occurrence not after the item's completed one fails the validation, so the call
// is rejected as a whole. An empty map returns a copy.
func Reserve(st State, occurrences map[string]int64) (State, error) {
	out, err := SetPending(st, occurrences)
	if err != nil || len(occurrences) == 0 {
		return out, err
	}
	return update(out, func(s State) {
		for id, o := range occurrences {
			if it := s[id]; it.PendingOccurrence == nil || *it.PendingOccurrence < o {
				it.PendingOccurrence, it.PendingAttempted = &o, false
				s[id] = it
			}
		}
	})
}

// RecordOutcome records a terminal source check. Without a pending occurrence a success only stamps the check and a
// retry-cap outcome changes nothing; expected, when set, must equal the pending occurrence or nothing changes.
func RecordOutcome(st State, id string, outcome Outcome, now int64, expected *int64) (State, error) {
	if !feedIDRe.MatchString(id) || !validOutcome(outcome) {
		return nil, errors.New("schedule outcome rejected")
	}
	return update(st, func(s State) {
		it := s[id]
		if expected != nil && (it.PendingOccurrence == nil || *it.PendingOccurrence != *expected) {
			return
		}
		if outcome == RetryCapReached && it.PendingOccurrence == nil {
			return
		}
		if outcome == Success {
			it.LastSuccessfulCheck = &now
		}
		if it.PendingOccurrence != nil {
			it.LastCompletedOccurrence, it.CompletionOutcome = it.PendingOccurrence, outcome
			it.PendingOccurrence, it.PendingAttempted = nil, false
		}
		s[id] = it
	})
}

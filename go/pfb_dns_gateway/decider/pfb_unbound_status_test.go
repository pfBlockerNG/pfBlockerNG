// Tests for the Go translation of pfb_unbound.py's parse-stage status ledger (683-790: _pfb_py_status_read_all,
// _pfb_py_status_write_all, pfb_py_status_open, pfb_py_status_close). They mirror tests/test_adr61_py_status.py
// (TestPfbPyStatusOpenClose, TestPfbPyStatusReadDegradation); the expectations are the Python source's.
package decider

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// statusModule is a module whose ledger lives in a fresh directory and whose clock the test sets.
func statusModule(t *testing.T) (*pfbUnbound, string) {
	t.Helper()
	m := modMust(t, t.TempDir())
	path := filepath.Join(t.TempDir(), "pfb_py_status.json")
	m.pfb.pfbPyStatus = path
	return m, path
}

func statusRead(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the ledger %s: %v", path, err)
	}
	var entries []map[string]any
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("ledger %s = %q is not a JSON array of objects: %v", path, data, err)
	}
	return entries
}

func TestPfbPyStatusOpenCreatesOneEntry(t *testing.T) {
	m, path := statusModule(t)
	m.statusClock = func() int64 { return 1000 }

	m.pfbPyStatusOpen("dnsbl", "pfb_py_zone.txt", "parse", "boom")

	entries := statusRead(t, path)
	if len(entries) != 1 {
		t.Fatalf("entries = %v, want exactly one", entries)
	}
	want := map[string]any{
		"facility": "dnsbl", "item": "pfb_py_zone.txt", "stage": "parse", "message": "boom",
		"first_seen": float64(1000), "last_seen": float64(1000),
	}
	for key, value := range want {
		if entries[0][key] != value {
			t.Errorf("entry[%q] = %v, want %v", key, entries[0][key], value)
		}
	}
	if len(entries[0]) != len(want) {
		t.Errorf("entry = %v, want exactly the keys %v", entries[0], want)
	}
}

func TestPfbPyStatusReopeningARefreshesWithoutDuplicating(t *testing.T) {
	m, path := statusModule(t)
	now := int64(1000)
	m.statusClock = func() int64 { return now }

	m.pfbPyStatusOpen("dnsbl", "pfb_py_zone.txt", "parse", "first")
	now = 2000
	m.pfbPyStatusOpen("dnsbl", "pfb_py_zone.txt", "parse", "second")

	entries := statusRead(t, path)
	if len(entries) != 1 {
		t.Fatalf("entries = %v, want one: reopening the same key refreshes, never duplicates", entries)
	}
	if entries[0]["message"] != "second" || entries[0]["first_seen"] != float64(1000) || entries[0]["last_seen"] != float64(2000) {
		t.Errorf("entry = %v, want message second, first_seen 1000 (kept from the first open), last_seen 2000", entries[0])
	}

	// A key differing in any one of facility, item or stage is another entry.
	m.pfbPyStatusOpen("dnsbl", "pfb_py_zone.txt", "apply", "other stage")
	m.pfbPyStatusOpen("dnsbl", "pfb_py_data.txt", "parse", "other item")
	m.pfbPyStatusOpen("other", "pfb_py_zone.txt", "parse", "other facility")
	if got := len(statusRead(t, path)); got != 4 {
		t.Errorf("entries after three distinct keys = %d, want 4", got)
	}
}

func TestPfbPyStatusOpenDefaultsToTheRealClock(t *testing.T) {
	m, path := statusModule(t)

	before := time.Now().Unix()
	m.pfbPyStatusOpen("dnsbl", "x", "parse", "boom")
	after := time.Now().Unix()

	first, _ := statusRead(t, path)[0]["first_seen"].(float64)
	if int64(first) < before || int64(first) > after {
		t.Errorf("first_seen = %v, want within [%d, %d]", first, before, after)
	}
}

func TestPfbPyStatusCloseRemovesOnlyItsKey(t *testing.T) {
	m, path := statusModule(t)
	m.statusClock = func() int64 { return 1000 }
	m.pfbPyStatusOpen("dnsbl", "pfb_py_zone.txt", "parse", "boom")
	if got := len(statusRead(t, path)); got != 1 { // before-state: the entry is open, so the close is a real transition
		t.Fatalf("entries before the close = %d, want 1", got)
	}

	m.pfbPyStatusClose("dnsbl", "pfb_py_data.txt", "parse") // an unrelated key
	entries := statusRead(t, path)
	if len(entries) != 1 || entries[0]["item"] != "pfb_py_zone.txt" {
		t.Errorf("entries after closing an unrelated key = %v, want the zone entry kept", entries)
	}

	m.pfbPyStatusClose("dnsbl", "pfb_py_zone.txt", "parse")
	if entries := statusRead(t, path); len(entries) != 0 {
		t.Errorf("entries after the close = %v, want none (an empty array, not a missing file)", entries)
	}
}

func TestPfbPyStatusClosingAnAbsentKeyWritesNothing(t *testing.T) {
	m, path := statusModule(t)

	m.pfbPyStatusClose("dnsbl", "never_opened", "parse")

	if _, err := os.Stat(path); err == nil {
		t.Errorf("%s exists after closing an absent key, want no file written", path)
	}
}

func TestPfbPyStatusReadDegradesToEmpty(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	m := modMust(t, t.TempDir())
	for _, tc := range []struct{ name, path string }{
		{"no ledger path configured", ""},
		{"absent file", filepath.Join(dir, "does_not_exist.json")},
		{"corrupt JSON", write("corrupt.json", "this is not json{{{")},
		{"an object, not a list", write("object.json", `{"facility": "dnsbl"}`)},
	} {
		m.pfb.pfbPyStatus = tc.path
		if got := m.pfbPyStatusReadAll(); len(got) != 0 {
			t.Errorf("%s: read = %v, want empty", tc.name, got)
		}
	}

	// Entries that are not objects are dropped, the objects kept.
	m.pfb.pfbPyStatus = write("mixed.json", `[1, {"facility": "dnsbl", "item": "a"}, "x", null, {"item": "b"}]`)
	if got := m.pfbPyStatusReadAll(); len(got) != 2 || got[0]["item"] != "a" || got[1]["item"] != "b" {
		t.Errorf("read of a list with non-object entries = %v, want the two objects", got)
	}
}

func TestPfbPyStatusOpenSelfHealsACorruptFile(t *testing.T) {
	m, path := statusModule(t)
	if err := os.WriteFile(path, []byte("{{{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	m.statusClock = func() int64 { return 1000 }

	m.pfbPyStatusOpen("dnsbl", "x", "parse", "boom")

	if entries := statusRead(t, path); len(entries) != 1 || entries[0]["item"] != "x" {
		t.Errorf("entries = %v, want the corrupt content replaced by the one new entry", entries)
	}
}

func TestPfbPyStatusWriteFailureIsSilentAndLeavesNoTempFile(t *testing.T) {
	m := modMust(t, t.TempDir())
	dir := t.TempDir()
	m.pfb.pfbPyStatus = filepath.Join(dir, "missing-dir", "pfb_py_status.json") // the temp file cannot be created
	logs := modCaptureLog(t)

	m.pfbPyStatusOpen("dnsbl", "x", "parse", "boom")

	if logs.Len() != 0 {
		t.Errorf("log = %q, want nothing: the ledger is display-only, a write failure is a silent no-op", logs.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "missing-dir")); err == nil {
		t.Errorf("a directory appeared, want the write to fail cleanly")
	}
}

// Python holds _pfb_py_status_lock across a whole read-modify-write: two opens for different keys must both survive.
func TestPfbPyStatusConcurrentOpensLoseNoUpdate(t *testing.T) {
	m, path := statusModule(t)
	m.statusClock = func() int64 { return 1000 }
	const writers = 16
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.pfbPyStatusOpen("dnsbl", string(rune('a'+i)), "parse", "boom")
		}()
	}
	wg.Wait()
	if got := len(statusRead(t, path)); got != writers {
		t.Errorf("entries after %d concurrent opens of different keys = %d, want %d", writers, got, writers)
	}
}

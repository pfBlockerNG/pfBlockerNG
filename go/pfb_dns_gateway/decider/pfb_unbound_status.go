// Go translation of src/usr/local/pkg/pfblockerng/pfb_unbound.py 683-790, ADR-61: Python's own structured status
// ledger, pfb_py_status.json. The module writes it and PHP only reads it. Every entry is
// {facility, item, stage, message, first_seen, last_seen}; the module only ever opens facility "dnsbl", stage "parse".
//
// The file is JSON that PHP decodes, so key order and whitespace are free: Go writes the keys sorted and compact where
// json.dump writes them in insertion order with ", " separators, and escapes no non-ASCII.
package decider

import (
	"encoding/json"
	"os"
	"slices"
	"time"
)

// pfbPyStatusReadAll reads the full ledger. An absent or unreadable file, corrupt JSON and JSON that is no list all
// degrade to an empty list (fail-open); an entry that is no object is dropped.
func (m *pfbUnbound) pfbPyStatusReadAll() []map[string]any {
	path := m.pfb.pfbPyStatus
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var decoded []any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil
	}
	var entries []map[string]any
	for _, entry := range decoded {
		if object, ok := entry.(map[string]any); ok {
			entries = append(entries, object)
		}
	}
	return entries
}

// pfbPyStatusWriteAll atomically persists the full ledger (temp write, fsync, rename). A write failure is a silent
// no-op: the ledger is a display-only signal, never worth failing over.
func (m *pfbUnbound) pfbPyStatusWriteAll(entries []map[string]any) {
	path := m.pfb.pfbPyStatus
	if path == "" {
		return
	}
	if entries == nil {
		entries = []map[string]any{} // json.dump([]) is "[]", not "null"
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := writeFileSynced(tmp, data); err != nil {
		os.Remove(tmp)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
	}
}

func writeFileSynced(path string, data []byte) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}

// pfbPyStatusOpen opens, or refreshes, one {facility, item, stage} entry. Reopening an open key updates message and
// last_seen in place and keeps first_seen: it never duplicates the entry. Python holds _pfb_py_status_lock across the
// whole read-modify-write so two threads' opens cannot lose an update; statusMu is that lock.
func (m *pfbUnbound) pfbPyStatusOpen(facility, item, stage, message string) {
	now := time.Now().Unix()
	if m.statusClock != nil {
		now = m.statusClock()
	}
	m.statusMu.Lock()
	defer m.statusMu.Unlock()
	if m.retired.Load() {
		return
	}
	entries := m.pfbPyStatusReadAll()
	for _, entry := range entries {
		if entry["facility"] == facility && entry["item"] == item && entry["stage"] == stage {
			entry["message"] = message
			entry["last_seen"] = now
			m.pfbPyStatusWriteAll(entries)
			return
		}
	}
	m.pfbPyStatusWriteAll(append(entries, map[string]any{
		"facility": facility, "item": item, "stage": stage, "message": message, "first_seen": now, "last_seen": now,
	}))
}

// pfbPyStatusClose clears one {facility, item, stage} entry. Closing an absent key is a no-op that writes nothing.
func (m *pfbUnbound) pfbPyStatusClose(facility, item, stage string) {
	m.statusMu.Lock()
	defer m.statusMu.Unlock()
	if m.retired.Load() {
		return
	}
	entries := m.pfbPyStatusReadAll()
	filtered := slices.DeleteFunc(slices.Clone(entries), func(entry map[string]any) bool {
		return entry["facility"] == facility && entry["item"] == item && entry["stage"] == stage
	})
	if len(filtered) == len(entries) {
		return
	}
	m.pfbPyStatusWriteAll(filtered)
}

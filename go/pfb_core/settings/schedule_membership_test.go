package settings

import (
	"errors"
	"strings"
	"testing"
)

// membershipBackend is a refreshBackend with the settings adapter's two rules about the schedule's groups (issue #3941):
// a write may list only groups the configuration holds now (a group it does not hold is refused), and what the configuration
// stores lists only the groups its feeds projections hold, so deleting a feed group takes its schedule item along.
type membershipBackend struct{ *refreshBackend }

func (m membershipBackend) Write(expected uint64, values map[string]map[string]any) (uint64, error) {
	held := map[string]bool{}
	for _, g := range m.values["schedule"]["groups"].([]any) {
		held[g.(map[string]any)["id"].(string)] = true
	}
	for _, g := range values["schedule"]["groups"].([]any) {
		if id := g.(map[string]any)["id"].(string); !held[id] {
			return 0, &BackendError{Err: errors.New("schedule.groups: the configuration holds no group " + id)}
		}
	}
	revision, err := m.refreshBackend.Write(expected, values)
	if err != nil {
		return revision, err
	}
	kept := []any{}
	for _, g := range m.values["schedule"]["groups"].([]any) {
		family, name, _ := strings.Cut(g.(map[string]any)["id"].(string), "/")
		for _, feed := range m.values["feeds/"+family]["groups"].([]any) {
			if feed.(map[string]any)["name"] == name {
				kept = append(kept, g)
			}
		}
	}
	m.values["schedule"]["groups"] = kept
	return revision, nil
}

func scheduleGroupIDs(t *testing.T, st *Store) []string {
	t.Helper()
	ids := []string{}
	for _, g := range projection(t, get(t, st, "schedule"), "schedule").Value["groups"].([]any) {
		ids = append(ids, g.(map[string]any)["id"].(string))
	}
	return ids
}

// Deleting a feed group while schedule.groups still lists it is accepted, and Core then holds what the configuration stored:
// the schedule without that group. Core's next save, which sends the schedule it holds, is accepted too, where the
// adapter would refuse a group that is gone.
func TestAFeedGroupDeletedWhileTheScheduleListsItLeavesNoGroupBehindAndTheNextSaveIsAccepted(t *testing.T) {
	b := newRefreshBackend(1, map[string]map[string]any{
		"feeds/ipv4": {"groups": []any{map[string]any{"name": "A", "action": "Disabled"}}},
		"schedule":   {"groups": []any{map[string]any{"id": "ipv4/A", "override": true, "weekday": int64(5), "hour": int64(13), "minute": int64(45)}}},
	})
	st, err := Load(membershipBackend{b}, testSchema())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if ids := scheduleGroupIDs(t, st); len(ids) != 1 || ids[0] != "ipv4/A" {
		t.Fatalf("before the save: schedule.groups %v, want [ipv4/A]", ids)
	}

	if _, err := st.Save(1, changes(t, `{"feeds/ipv4": {"groups": []}}`)); err != nil {
		t.Fatalf("Save deleting feed group A while schedule.groups lists ipv4/A = %v, want it accepted", err)
	}
	if ids := scheduleGroupIDs(t, st); len(ids) != 0 {
		t.Errorf("after the save: schedule.groups %v, want none: Core holds what the configuration stored", ids)
	}

	snap := get(t, st)
	if _, err := st.Save(snap.Revision, changes(t, `{"dns": {"idnMode": "on"}}`)); err != nil {
		t.Fatalf("Save of dns.idnMode after it = %v, want it accepted", err)
	}
	if got := projection(t, get(t, st, "dns"), "dns").Value["idnMode"]; got != "on" {
		t.Errorf("dns.idnMode = %v, want on", got)
	}
}

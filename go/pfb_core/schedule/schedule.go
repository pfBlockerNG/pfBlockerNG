package schedule

import (
	"errors"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Schedule is a weekly quarter-hour slot; Weekday is ISO (1 Monday to 7 Sunday).
type Schedule struct {
	Weekday int `json:"weekday"`
	Hour    int `json:"hour"`
	Minute  int `json:"minute"`
}

// Entry is one schedulable feed (or Extras job); Override nil means the default schedule.
type Entry struct {
	ID, Cadence string
	Enabled     bool
	Override    *Schedule
}

// Group is an Entry with the occurrence it last completed (nil: never).
type Group struct {
	Entry
	LastCompleted *int64
}

// PlanResult is what Plan decides: due ids in group order, the earliest next occurrence of an eligible group, and each
// due id's latest occurrence.
type PlanResult struct {
	Due         []string
	NextDue     *int64
	Occurrences map[string]int64
}

// LedgerEntry is one entry of the due ledger.
type LedgerEntry struct{ LastRun, NextDue, Jitter int64 }

const (
	extraPrefix = "extra:"
	day         = 86400 // seconds; the scan horizon is 15 of them
)

// cadenceHours maps every cadence to its hour step (0: not an N-hour cadence).
var cadenceHours = map[string]int{
	"Never": 0, "01hour": 1, "02hours": 2, "03hours": 3, "04hours": 4, "06hours": 6, "08hours": 8, "12hours": 12,
	"EveryDay": 0, "Weekly": 0,
}

// NextOccurrence returns the first occurrence strictly after reference; ok is false for Never or when none falls within
// 15 days. It scans real instants, so skipped local slots never occur and repeated ones occur twice.
func NextOccurrence(cadence string, s Schedule, reference int64, loc *time.Location) (next int64, ok bool, err error) {
	hours, known := cadenceHours[cadence]
	switch {
	case !known:
		return 0, false, errors.New("unsupported schedule cadence")
	case s.Weekday < 1 || s.Weekday > 7:
		return 0, false, errors.New("schedule weekday must be 1..7")
	case s.Hour < 0 || s.Hour > 23:
		return 0, false, errors.New("schedule hour must be 0..23")
	case s.Minute < 0 || s.Minute > 45 || s.Minute%15 != 0:
		return 0, false, errors.New("schedule minute must be 0, 15, 30, or 45")
	case cadence == "Never":
		return 0, false, nil
	case reference > math.MaxInt64-16*day: // the 15-day scan would wrap; PHP's DateTimeImmutable throws there
		return 0, false, errors.New("schedule reference out of range")
	}
	interval := max(1, hours)
	limit := reference + 15*day
	candidate := reference + 1
	local := time.Unix(candidate, 0).In(loc)
	if into := local.Minute()%15*60 + local.Second(); into != 0 {
		candidate += int64(900 - into)
	}
	// Historical offsets can carry seconds, so the quarter-hour alignment may need a bounded second-by-second scan.
	for alignLimit := min(limit, candidate+900); candidate <= alignLimit; candidate++ {
		if l := time.Unix(candidate, 0).In(loc); l.Second() == 0 && l.Minute()%15 == 0 {
			break
		}
	}
	for ; candidate <= limit; candidate += 900 {
		l := time.Unix(candidate, 0).In(loc)
		weekday := int(l.Weekday())
		if weekday == 0 {
			weekday = 7
		}
		hour, minute := l.Hour(), l.Minute()
		var match bool
		switch cadence {
		case "01hour":
			match = minute == s.Minute
		case "EveryDay":
			match = hour == s.Hour && minute == s.Minute
		case "Weekly":
			match = weekday == s.Weekday && hour == s.Hour && minute == s.Minute
		default: // the 02hours..12hours cadences; Go's % truncates like PHP's
			match = minute == s.Minute && (hour-s.Hour)%interval == 0
		}
		if match {
			return candidate, true, nil
		}
	}
	return 0, false, nil
}

// latestOccurrence is the last occurrence after start and not after now; ok is false when there is none.
func latestOccurrence(cadence string, s Schedule, start, now int64, loc *time.Location) (latest int64, ok bool) {
	for ref := start; ; {
		next, found, err := NextOccurrence(cadence, s, ref, loc)
		if err != nil || !found || next > now {
			return latest, ok
		}
		latest, ok, ref = next, true, next
	}
}

type slot struct {
	cadence string
	s       Schedule
}

type dueKey struct {
	slot
	start int64
}

type found struct {
	at int64
	ok bool
}

// Plan selects the groups with an occurrence due at now and the earliest future wake. An ineligible group (disabled or
// Never) never wakes. shortcut: PHP throws on a malformed schedule or cadence; Plan has no error, so such a group yields no
// occurrence, which cannot happen for a model RuntimeModel built.
func Plan(groups []Group, def Schedule, now int64, loc *time.Location) PlanResult {
	res := PlanResult{Occurrences: map[string]int64{}}
	nexts := map[slot]found{}
	dues := map[dueKey]found{}
	for _, g := range groups {
		if !g.Enabled || g.Cadence == "Never" {
			continue
		}
		s := def
		if g.Override != nil {
			s = *g.Override
		}
		k := slot{g.Cadence, s}
		next, seen := nexts[k]
		if !seen {
			at, ok, err := NextOccurrence(g.Cadence, s, now, loc)
			next = found{at, ok && err == nil}
			nexts[k] = next
		}
		// The search reaches back 15 days at most, from the completed occurrence when it is newer.
		start := now - 15*day - 1
		if g.LastCompleted != nil {
			start = max(*g.LastCompleted, start)
		}
		dk := dueKey{k, start}
		due, seen := dues[dk]
		if !seen {
			at, ok := latestOccurrence(g.Cadence, s, start, now, loc)
			due = found{at, ok}
			dues[dk] = due
		}
		if due.ok {
			res.Due = append(res.Due, g.ID)
			res.Occurrences[g.ID] = due.at
		}
		if next.ok && (res.NextDue == nil || next.at < *res.NextDue) {
			v := next.at
			res.NextDue = &v
		}
	}
	return res
}

// lastRun is the ledger's last_run of an item.
func lastRun(it Item) int64 {
	switch {
	case it.LastSuccessfulCheck != nil:
		return *it.LastSuccessfulCheck
	case it.LastCompletedOccurrence != nil:
		return *it.LastCompletedOccurrence
	}
	return 0
}

// cursor is the occurrence an item has completed; adoptPending also counts a newer pending one as completed.
func cursor(it Item, adoptPending bool) *int64 {
	c := it.LastCompletedOccurrence
	if adoptPending && it.PendingOccurrence != nil && (c == nil || *it.PendingOccurrence > *c) {
		c = it.PendingOccurrence
	}
	return c
}

// ExtraPlan returns the Extras ids due at now, in PHP's insertion order, and their occurrences. cache (id to next_due) nil
// means no cache; a GeoIP generation mid-swap forces an enabled extra:dcc due.
func ExtraPlan(m Model, st State, now int64, loc *time.Location, cache map[string]int64, geoipReady bool) (due []string, occurrences map[string]int64) {
	var groups []Group
	for _, e := range m.Entries {
		if strings.HasPrefix(e.ID, extraPrefix) {
			groups = append(groups, Group{Entry: e, LastCompleted: cursor(st[e.ID], false)})
		}
	}
	plan := Plan(groups, m.Default, now, loc)
	add := func(id string) {
		if !slices.Contains(due, id) {
			due = append(due, id)
		}
	}
	if cache == nil {
		due = plan.Due
	} else {
		for _, g := range groups {
			it := st[g.ID]
			unattempted := it.PendingOccurrence != nil && !it.PendingAttempted
			if next, cached := cache[g.ID]; cached && next <= now && (unattempted || slices.Contains(plan.Due, g.ID)) {
				add(g.ID)
			}
		}
	}
	for _, g := range groups {
		if g.ID == extraPrefix+"dcc" && g.Enabled && !geoipReady {
			add(g.ID)
		}
	}
	return due, plan.Occurrences
}

// FeedPlan is the tick's plan over the feeds (every entry but the Extras): nothing unless scheduled updates are on, and
// what a feed completed is its only cursor, so a pending occurrence, attempted or not, never counts as done.
func FeedPlan(m Model, st State, now int64, loc *time.Location) PlanResult {
	if !m.Scheduled {
		return PlanResult{Occurrences: map[string]int64{}}
	}
	var groups []Group
	for _, e := range m.Entries {
		if !strings.HasPrefix(e.ID, extraPrefix) {
			groups = append(groups, Group{Entry: e, LastCompleted: cursor(st[e.ID], false)})
		}
	}
	return Plan(groups, m.Default, now, loc)
}

// CacheEntries returns the ledger entries a refresh computes for an empty ledger: "cron" when scheduled and something is
// or will be due, and "extra:dcc" / "extra:bl" when enabled and they have a next due. shortcut: the model's hash/validity
// check and the merge with an existing ledger stay in PHP; a malformed schedule (PHP throws) yields no entry.
func CacheEntries(m Model, st State, now int64, loc *time.Location) map[string]LedgerEntry {
	var groups, extras []Group
	for _, e := range m.Entries {
		it := st[e.ID]
		if strings.HasPrefix(e.ID, extraPrefix) {
			extras = append(extras, Group{Entry: e, LastCompleted: cursor(it, true)})
		} else {
			groups = append(groups, Group{Entry: e, LastCompleted: cursor(it, it.PendingAttempted)})
		}
	}
	plan := Plan(groups, m.Default, now, loc)
	extraDue := Plan(extras, m.Default, now, loc).Due
	out := map[string]LedgerEntry{}
	for _, g := range extras {
		if !g.Enabled {
			continue
		}
		it := st[g.ID]
		reference := now
		if it.PendingAttempted && it.PendingOccurrence != nil {
			reference = max(now, *it.PendingOccurrence)
		}
		next, ok := now, true
		if !(it.PendingOccurrence != nil && !it.PendingAttempted) && !slices.Contains(extraDue, g.ID) {
			var err error
			next, ok, err = NextOccurrence(g.Cadence, m.Default, reference, loc)
			ok = ok && err == nil
		}
		if ok {
			out[g.ID] = LedgerEntry{LastRun: lastRun(it), NextDue: next}
		}
	}
	var cronLastRun int64
	pending := false
	for _, g := range groups {
		if g.Enabled {
			it := st[g.ID]
			cronLastRun = max(cronLastRun, lastRun(it))
			pending = pending || it.PendingOccurrence != nil
		}
	}
	next := plan.NextDue
	if pending || len(plan.Due) > 0 {
		next = &now
	}
	if m.Scheduled && next != nil {
		out["cron"] = LedgerEntry{LastRun: cronLastRun, NextDue: *next}
	}
	return out
}

// The regexp has no D flag in PHP, so one trailing newline still matches.
var windowRe = regexp.MustCompile(`^(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})\n?$`)

// InApplyWindow reports whether an update may apply at now given a "HH:MM-HH:MM" quiet-hours window read in loc: start is
// inclusive, end exclusive, and a window across midnight wraps. An empty, malformed, out-of-range or zero-width window
// answers true (apply now) so an update can never be deferred forever.
func InApplyWindow(now int64, window string, loc *time.Location) bool {
	m := windowRe.FindStringSubmatch(window)
	if m == nil {
		return true
	}
	var n [4]int
	for i := range n {
		n[i], _ = strconv.Atoi(m[i+1])
	}
	if n[0] > 23 || n[1] > 59 || n[2] > 23 || n[3] > 59 {
		return true
	}
	start, end := n[0]*60+n[1], n[2]*60+n[3]
	t := time.Unix(now, 0).In(loc)
	cur := t.Hour()*60 + t.Minute()
	switch {
	case start == end:
		return true
	case start < end:
		return cur >= start && cur < end
	}
	return cur >= start || cur < end
}

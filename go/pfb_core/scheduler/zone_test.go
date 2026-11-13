package scheduler

import (
	"sync/atomic"
	"testing"
	"time"
)

// zoned is a Scheduler over the fixture whose zone is whatever *zone holds when the scheduler asks for it.
func zoned(f *fixture, zone *atomic.Pointer[time.Location]) *Scheduler {
	cfg := f.config()
	cfg.Zone = zone.Load
	s := New(cfg)
	s.Bind(f.start)
	return s
}

func at(offsetHours int) *time.Location { return time.FixedZone("test", offsetHours*3600) }

// The tests run on Friday 2026-11-13 10:20 UTC with every item completed at today's 03:00 UTC slot (the quiet state). The
// default slot is Friday 03:00 local, so the daily dcc and the weekly bl are due again once that slot, in the zone asked for,
// falls between 03:00 UTC and now: at UTC-4 it is 07:00 UTC; at UTC and at UTC+5 it is not.
func TestTheZoneIsResolvedAtEveryTick(t *testing.T) {
	f := newFixture(t, allEntries(), quiet)
	var zone atomic.Pointer[time.Location]
	zone.Store(at(0))
	s := zoned(f, &zone)

	if err := s.Tick(); err != nil {
		t.Fatal(err)
	}
	if n := len(f.requests()); n != 0 {
		t.Fatalf("%d Updates requested at UTC, want 0", n)
	}
	zone.Store(at(-4))
	if err := s.Tick(); err != nil {
		t.Fatal(err)
	}
	wantRequest(t, f.last(), "scheduled", nil, []string{dcc, bl})
}

func TestTheZoneIsResolvedAtEveryView(t *testing.T) {
	f := newFixture(t, allEntries(), quiet)
	var zone atomic.Pointer[time.Location]
	zone.Store(at(0))
	s := zoned(f, &zone)

	for _, z := range []*time.Location{at(0), at(5), at(-8), at(0)} {
		zone.Store(z)
		v, err := s.View()
		if err != nil {
			t.Fatal(err)
		}
		want := next03(z).Unix()
		if got := v.Extras[dcc].NextDue; got != want {
			t.Errorf("at UTC%+d the daily Extra is next due at %s, want %s", offsetOf(z), time.Unix(got, 0).UTC(), time.Unix(want, 0).UTC())
		}
	}
}

func TestAZoneThatIsNilFallsBackToTheConfiguredLocation(t *testing.T) {
	f := newFixture(t, allEntries(), quiet)
	var zone atomic.Pointer[time.Location] // nothing stored: Zone returns nil
	s := zoned(f, &zone)

	v, err := s.View()
	if err != nil {
		t.Fatal(err)
	}
	if got := v.Extras[dcc].NextDue; got != nextDCC { // the fixture's Loc is UTC
		t.Errorf("the daily Extra is next due at %d, want %d (UTC, the configured location)", got, nextDCC)
	}
}

// next03 is the first 03:00 in z after nowT: what a daily Extra whose last slot has completed is next due.
func next03(z *time.Location) time.Time {
	d := nowT.In(z)
	next := time.Date(d.Year(), d.Month(), d.Day(), 3, 0, 0, 0, z)
	if !next.After(nowT) {
		next = next.AddDate(0, 0, 1)
	}
	return next
}

func offsetOf(l *time.Location) int {
	_, off := time.Unix(nowT.Unix(), 0).In(l).Zone()
	return off / 3600
}

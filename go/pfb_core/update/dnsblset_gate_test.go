package update

// Sub-slice 9g (issue #4038), the pfB-DNS switch and the second review: DNSBL is active only while DNSBL and pfB-DNS are on
// (pfb_dnsbl_active()); a feed's identity fields of the wrong type refuse the build; the removed-list cleanup removes a
// feed's parsed rows last, so a failed removal leaves the feed to the next Update.

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/apply"
)

// WHEN DNSBL is on but pfB-DNS is off THEN DNSBL is not active: every dnsbl/* leaves the store, no DNSBL object is given to
// the apply, and DNSBLIP is empty (not nil) with its lists removed, though it has an action and side lists are there.
func TestDNSBLIsNotActiveWhilePfbDNSIsOff(t *testing.T) {
	s, settings := sideListTree(t)
	if held, _ := s.Store.IDs("dnsbl/"); len(held) == 0 {
		t.Fatal("before-state: nothing published")
	}
	settings["dns"]["pfbDnsEnabled"] = false
	out, err := s.Build(context.Background(), DNSBLInput{Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	if held, _ := s.Store.IDs("dnsbl/"); len(held) != 0 || out.DNSBL != nil {
		t.Errorf("pfB-DNS off: store holds %q, DNSBL %+v; want nothing", held, out.DNSBL)
	}
	if out.DNSBLIP == nil || len(out.DNSBLIP) != 0 {
		t.Errorf("DNSBLIP with pfB-DNS off = %#v, want empty and not nil", out.DNSBLIP)
	}
	for _, v := range []string{"v4", "v6"} {
		if _, err := os.Stat(filepath.Join(s.ListDir, "DNSBLIP_"+v+".txt")); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("DNSBLIP_%s.txt with pfB-DNS off: %v, want removed", v, err)
		}
	}

	settings["dns"]["pfbDnsEnabled"] = true
	out, err = s.Build(context.Background(), DNSBLInput{Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	if out.DNSBL == nil || len(out.DNSBLIP) != 2 {
		t.Errorf("both on again: DNSBL %+v, DNSBLIP %+v; want the build and both lists", out.DNSBL, out.DNSBLIP)
	}
}

// WHEN a field that decides which feeds are configured, or DNSBL's activity, has the wrong type THEN the build is refused
// before any change.
func TestAFeedIdentityFieldOfTheWrongTypeRefusesTheBuild(t *testing.T) {
	group := func(m map[string]map[string]any) map[string]any {
		return m["feeds/dnsbl"]["groups"].([]any)[0].(map[string]any)
	}
	row := func(m map[string]map[string]any) map[string]any { return group(m)["feeds"].([]any)[0].(map[string]any) }
	provider := func(m map[string]map[string]any) map[string]any {
		p := map[string]any{"id": "ut1", "selected": true, "categories": "x", "title": "UT1"}
		m["schedule"]["categoryProviders"] = []any{p}
		return p
	}
	for name, spoil := range map[string]func(map[string]map[string]any){
		"no pfbDnsEnabled":         func(m map[string]map[string]any) { delete(m["dns"], "pfbDnsEnabled") },
		"pfbDnsEnabled not a bool": func(m map[string]map[string]any) { m["dns"]["pfbDnsEnabled"] = "on" },
		"a group's action":         func(m map[string]map[string]any) { group(m)["action"] = 1 },
		"a group's name":           func(m map[string]map[string]any) { group(m)["name"] = 1 },
		"a row's header":           func(m map[string]map[string]any) { row(m)["header"] = 1 },
		"a row's state":            func(m map[string]map[string]any) { row(m)["state"] = 1 },
		"a row's url":              func(m map[string]map[string]any) { row(m)["url"] = 1 },
		"a provider's title":       func(m map[string]map[string]any) { provider(m)["title"] = 1 },
		"a provider's selected":    func(m map[string]map[string]any) { provider(m)["selected"] = "yes" },
		"a provider's categories":  func(m map[string]map[string]any) { provider(m)["categories"] = []any{"x"} },
		"dnsblIpAction":            func(m map[string]map[string]any) { m["policy/dnsbl"]["dnsblIpAction"] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			s, settings := sideListTree(t)
			spoil(settings)
			before := dnsblState(t, s)
			if _, err := s.Build(context.Background(), DNSBLInput{Settings: settings}); err == nil {
				t.Error("no error")
			}
			if after := dnsblState(t, s); after != before {
				t.Errorf("the refused build changed the disk\nbefore %s\nafter  %s", before, after)
			}
		})
	}
}

// WHEN removing a stale feed's file fails THEN its parsed rows stay, removed last, so the next Update finds the feed again,
// removes the rest and raises the issue.
func TestAFailedCleanupLeavesTheFeedToTheNextUpdate(t *testing.T) {
	s, settings := sideListTree(t) // Old is staged and no longer configured
	touch(t, filepath.Join(s.FeedDir, "Old.parsed.v4.ip"), "192.0.2.7\n")
	failing := filepath.Join(s.FeedDir, "Old.parsed.v4.ip")
	dnsblRemove = func(name string) error {
		if name == failing {
			return errors.New("injected removal failure")
		}
		return os.Remove(name)
	}
	t.Cleanup(func() { dnsblRemove = os.Remove })
	if _, err := s.Build(context.Background(), DNSBLInput{Settings: settings}); err == nil {
		t.Fatal("the removal failed: no error")
	}
	if _, err := os.Stat(filepath.Join(s.FeedDir, "Old.parsed.ndjson")); err != nil {
		t.Fatalf("Old's parsed rows after a failed cleanup: %v, want kept", err)
	}

	dnsblRemove = os.Remove
	out, err := s.Build(context.Background(), DNSBLInput{Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	if left, _ := filepath.Glob(filepath.Join(s.FeedDir, "Old.*")); len(left) != 0 {
		t.Errorf("Old's files after the next Update: %q, want none", left)
	}
	want := []apply.Issue{{Resource: "feed/dnsbl:Old", Stage: "parse", Code: "feed_files_removed",
		Message: "no configured feed names it, so its files are removed (a row the settings do not project counts as removed)"}}
	if !reflect.DeepEqual(out.Issues, want) {
		t.Errorf("issues = %+v, want %+v", out.Issues, want)
	}
}

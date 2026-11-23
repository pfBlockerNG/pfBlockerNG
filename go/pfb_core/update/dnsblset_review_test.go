package update

// The review round of sub-slice 9g (issue #4038): DNSBLIP only while DNSBL is on, no disk change before every step that
// can fail has passed, a cancelled Update publishes nothing, a TOP1M read error is the build's error, and settings that are
// absent or of the wrong shape refuse the build before anything is deleted.

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/dnsbl"
)

// dnsblState is what a build may change on disk: the store's dnsbl/* ids with their generations, the feed folder's file
// names and the DNSBLIP lists' contents.
func dnsblState(t *testing.T, s DNSBLSet) string {
	t.Helper()
	var b strings.Builder
	ids, err := s.Store.IDs("dnsbl/")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		reply, err := s.Store.Get(id, nil)
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString(id + "@" + strings.Repeat("|", int(reply.Generation)) + "\n")
	}
	files, _ := filepath.Glob(filepath.Join(s.FeedDir, "*"))
	for _, f := range files {
		b.WriteString(filepath.Base(f) + "\n")
	}
	for _, v := range []string{"v4", "v6"} {
		text, err := os.ReadFile(filepath.Join(s.ListDir, "DNSBLIP_"+v+".txt"))
		b.WriteString("DNSBLIP_" + v + "=" + string(text) + "(" + errString(err) + ")\n")
	}
	return b.String()
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return "absent"
}

// sideListTree has a published DNSBL build with DNSBLIP Deny_Both over feed A's side lists, and a stale feed Old that is no
// longer configured.
func sideListTree(t *testing.T) (DNSBLSet, map[string]map[string]any) {
	t.Helper()
	s := dnsblTree(t)
	staged(t, s, "A", "a.example")
	touch(t, filepath.Join(s.FeedDir, "A.parsed.v4.ip"), "192.0.2.1\n")
	touch(t, filepath.Join(s.FeedDir, "A.parsed.v6.ip"), "2001:db8::1\n")
	settings := dnsblSettings([]any{dnsblGroup("G", "unbound", "", dnsblFeed("A", "enabled", "deny"))},
		dnsblPolicy(map[string]any{"dnsblIpAction": "Deny_Both"}))
	if _, err := s.Build(context.Background(), DNSBLInput{Settings: settings}); err != nil {
		t.Fatal(err)
	}
	staged(t, s, "Old", "old.example")
	return s, settings
}

// WHEN DNSBL is off THEN DNSBLIP is empty (not nil) and its lists are removed, though DNSBLIP has an action and stale side
// lists are in the feed folder: today the DNSBLIP alias exists only while pfb_dnsbl_active() holds.
func TestDNSBLIPIsEmptyAndItsListsRemovedWhileDNSBLIsOff(t *testing.T) {
	s, settings := sideListTree(t)
	settings["policy/dnsbl"]["enabled"] = false
	out, err := s.Build(context.Background(), DNSBLInput{Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	if out.DNSBLIP == nil || len(out.DNSBLIP) != 0 {
		t.Errorf("DNSBLIP with DNSBL off = %#v, want empty and not nil", out.DNSBLIP)
	}
	for _, v := range []string{"v4", "v6"} {
		if _, err := os.Stat(filepath.Join(s.ListDir, "DNSBLIP_"+v+".txt")); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("DNSBLIP_%s.txt with DNSBL off: %v, want removed", v, err)
		}
	}
}

// WHEN a step that can fail fails (the PSL cannot be read) THEN nothing on disk changed: no publication, no cleanup of a
// removed feed, no new DNSBLIP list, though a side list changed.
func TestAFailingStepLeavesTheDiskAsItWas(t *testing.T) {
	s, settings := sideListTree(t)
	touch(t, filepath.Join(s.FeedDir, "A.parsed.v4.ip"), "192.0.2.99\n")
	staged(t, s, "A", "changed.example")
	if err := os.Remove(s.PSL); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.PSL, 0o755); err != nil { // a folder where the PSL file should be: the read fails
		t.Fatal(err)
	}
	before := dnsblState(t, s)
	if _, err := s.Build(context.Background(), DNSBLInput{Settings: settings}); err == nil {
		t.Fatal("the PSL cannot be read: no error")
	}
	if after := dnsblState(t, s); after != before {
		t.Errorf("a failed build changed the disk\nbefore %s\nafter  %s", before, after)
	}
}

// WHEN the Update is cancelled THEN the build publishes nothing and changes nothing.
func TestACancelledUpdatePublishesNothing(t *testing.T) {
	s, settings := sideListTree(t)
	touch(t, filepath.Join(s.FeedDir, "A.parsed.v4.ip"), "192.0.2.99\n")
	staged(t, s, "A", "changed.example")
	before := dnsblState(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Build(ctx, DNSBLInput{Settings: settings}); !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled build: %v, want context.Canceled", err)
	}
	if after := dnsblState(t, s); after != before {
		t.Errorf("a cancelled build changed the disk\nbefore %s\nafter  %s", before, after)
	}
}

// WHEN TOP1M is on and its list cannot be read for another reason than its absence THEN that error is the build's.
func TestATop1mReadErrorIsTheBuildsError(t *testing.T) {
	s := dnsblTree(t)
	if err := os.Mkdir(s.Top1m, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := s.Build(context.Background(), DNSBLInput{Settings: dnsblSettings([]any{}, dnsblPolicy(map[string]any{"top1m": true}))})
	if err == nil || !strings.Contains(err.Error(), s.Top1m) {
		t.Errorf("TOP1M list unreadable: %v, want the read error naming %s", err, s.Top1m)
	}
	if _, err := s.Store.Get(dnsbl.ManifestID, nil); err == nil {
		t.Error("TOP1M list unreadable: the manifest was published")
	}
}

// WHEN a projection the build reads is absent, or a list in it has the wrong shape THEN the build is refused before any
// change: a configured feed is never taken for a removed one (today's $config_complete guard).
func TestAbsentOrMisshapenSettingsRefuseTheBuildAndDeleteNothing(t *testing.T) {
	for name, spoil := range map[string]func(map[string]map[string]any){
		"no feeds/dnsbl":        func(m map[string]map[string]any) { delete(m, "feeds/dnsbl") },
		"no policy/dnsbl":       func(m map[string]map[string]any) { delete(m, "policy/dnsbl") },
		"no schedule":           func(m map[string]map[string]any) { delete(m, "schedule") },
		"no dns":                func(m map[string]map[string]any) { delete(m, "dns") },
		"groups not a list":     func(m map[string]map[string]any) { m["feeds/dnsbl"]["groups"] = "G" },
		"a group not an object": func(m map[string]map[string]any) { m["feeds/dnsbl"]["groups"] = []any{"G"} },
		"a group's feeds not a list": func(m map[string]map[string]any) {
			m["feeds/dnsbl"]["groups"] = []any{map[string]any{"name": "G", "action": "unbound", "feeds": "A"}}
		},
		"policy groups not a list": func(m map[string]map[string]any) { m["policy/dnsbl"]["groups"] = 1 },
		"providers not a list":     func(m map[string]map[string]any) { m["schedule"]["categoryProviders"] = map[string]any{} },
		"enabled not a bool":       func(m map[string]map[string]any) { m["policy/dnsbl"]["enabled"] = "on" },
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

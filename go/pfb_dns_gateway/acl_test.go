package main

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type capturedLog struct {
	mu    sync.Mutex
	lines []string
}

func (c *capturedLog) logf(format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, fmt.Sprintf(format, args...))
}

func (c *capturedLog) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.lines)
}

func (c *capturedLog) joined() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.lines, "\n")
}

func writeACLFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "access_lists.conf")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func newACL(t *testing.T, content string) *ACL {
	t.Helper()
	return NewACL(writeACLFile(t, content), t.Logf)
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("bad test address %q: %v", s, err)
	}
	return a
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi
}

func checkLookup(t *testing.T, a *ACL, client string, want ACLAction) {
	t.Helper()
	if got := a.Lookup(mustAddr(t, client)); got != want {
		t.Errorf("Lookup(%s): got %v, want %v", client, got, want)
	}
}

// aclText renders rows the way pfSense writes custom ACL rows.
func aclText(rows ...string) string {
	var b strings.Builder
	for _, r := range rows {
		b.WriteString("access-control: " + r + "\n")
	}
	return b.String()
}

func reverseLines(s string) string {
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
	return strings.Join(lines, "\n") + "\n"
}

// A1-A9: only deny and refuse act; every other known action forwards, and an unknown one is a line that names nobody.
func TestACLActionMapping(t *testing.T) {
	cases := []struct {
		action string
		alone  ACLAction // the only line in the file
		nested ACLAction // more specific than a 0.0.0.0/0 deny
	}{
		{"deny", ACLDrop, ACLDrop},
		{"refuse", ACLRefuse, ACLRefuse},
		{"allow", ACLForward, ACLForward},
		{"allow_snoop", ACLForward, ACLForward},
		{"allow_setrd", ACLForward, ACLForward},
		{"allow_cookie", ACLForward, ACLForward},
		{"deny_non_local", ACLForward, ACLForward},
		{"refuse_non_local", ACLForward, ACLForward},
		// An unknown action is a line Unbound would reject: ignored, so alone the client matches no row (Refuse) and
		// behind a 0.0.0.0/0 deny the outer deny still applies.
		{"DENY", ACLRefuse, ACLDrop},
		{"block", ACLRefuse, ACLDrop},
	}
	for _, c := range cases {
		t.Run(c.action, func(t *testing.T) {
			checkLookup(t, newACL(t, aclText("10.0.0.0/8 "+c.action)), "10.1.2.3", c.alone)
			checkLookup(t, newACL(t, aclText("0.0.0.0/0 deny", "10.0.0.0/8 "+c.action)), "10.1.2.3", c.nested)
		})
	}
}

// P1: neighbouring levels carry different actions so every level is individually visible.
func TestACLPrefixLengthsIPv4MostSpecificWins(t *testing.T) {
	text := aclText("0.0.0.0/0 refuse", "10.0.0.0/8 deny", "10.1.0.0/16 allow", "10.1.2.0/24 refuse", "10.1.2.3/32 deny")
	for name, content := range map[string]string{"as written": text, "reversed": reverseLines(text)} {
		t.Run(name, func(t *testing.T) {
			a := newACL(t, content)
			checkLookup(t, a, "8.8.8.8", ACLRefuse)
			checkLookup(t, a, "10.9.9.9", ACLDrop)
			checkLookup(t, a, "10.1.9.9", ACLForward)
			checkLookup(t, a, "10.1.2.9", ACLRefuse)
			checkLookup(t, a, "10.1.2.3", ACLDrop)
			checkLookup(t, a, "10.1.2.4", ACLRefuse)
		})
	}
}

// P2 including a bare ::1, which must act as a /128.
func TestACLPrefixLengthsIPv6MostSpecificWins(t *testing.T) {
	text := aclText("::/0 refuse", "2001:db8::/32 deny", "2001:db8:1::/48 allow", "2001:db8:1:2::/64 refuse",
		"2001:db8:1:2::5/128 deny", "::1 allow")
	for name, content := range map[string]string{"as written": text, "reversed": reverseLines(text)} {
		t.Run(name, func(t *testing.T) {
			a := newACL(t, content)
			checkLookup(t, a, "2606:4700::1111", ACLRefuse)
			checkLookup(t, a, "2001:db8:9::1", ACLDrop)
			checkLookup(t, a, "2001:db8:1:9::1", ACLForward)
			checkLookup(t, a, "2001:db8:1:2::9", ACLRefuse)
			checkLookup(t, a, "2001:db8:1:2::5", ACLDrop)
			checkLookup(t, a, "::1", ACLForward)
			checkLookup(t, a, "::2", ACLRefuse)
		})
	}
}

func TestACLNestedBlocksResolvePerClientInnermost(t *testing.T) {
	a := newACL(t, aclText("10.0.0.0/8 deny", "10.1.0.0/16 allow", "10.1.2.0/24 refuse", "10.1.2.3/32 allow_snoop"))
	checkLookup(t, a, "10.9.9.9", ACLDrop)
	checkLookup(t, a, "10.1.9.9", ACLForward)
	checkLookup(t, a, "10.1.2.9", ACLRefuse)
	checkLookup(t, a, "10.1.2.3", ACLForward)
}

func TestACLHostBitsAreMasked(t *testing.T) {
	a := newACL(t, aclText("198.51.100.7/24 refuse", "2001:db8:2::7/64 deny"))
	checkLookup(t, a, "198.51.100.0", ACLRefuse)
	checkLookup(t, a, "198.51.100.7", ACLRefuse)
	checkLookup(t, a, "198.51.100.255", ACLRefuse)
	checkLookup(t, a, "198.51.99.255", ACLRefuse)
	checkLookup(t, a, "198.51.101.0", ACLRefuse)
	checkLookup(t, a, "2001:db8:2::1", ACLDrop)
	checkLookup(t, a, "2001:db8:2:1::1", ACLRefuse)
}

// Unbound lets the LAST of identical prefixes win: the config list is built by prepending and the first tree insert sticks.
func TestACLDuplicatePrefixLastLineWins(t *testing.T) {
	checkLookup(t, newACL(t, aclText("192.0.2.0/24 deny", "192.0.2.0/24 allow")), "192.0.2.1", ACLForward)
	checkLookup(t, newACL(t, aclText("192.0.2.0/24 allow", "192.0.2.0/24 deny")), "192.0.2.1", ACLDrop)
	checkLookup(t, newACL(t, aclText("192.0.2.0/24 deny", "10.0.0.0/8 allow", "192.0.2.0/24 allow")), "192.0.2.1", ACLForward)
	// Identical after masking host bits, and the IPv6 spelling of the same rule.
	checkLookup(t, newACL(t, aclText("192.0.2.0/24 deny", "192.0.2.77/24 allow")), "192.0.2.1", ACLForward)
	checkLookup(t, newACL(t, aclText("2001:db8:3::/48 deny", "2001:db8:3::/48 allow")), "2001:db8:3::1", ACLForward)
}

// Unbound inserts 127.0.0.0/8 and ::1 as `allow` beneath the file's rows, so a broader deny or refuse
// never reaches localhost; the gateway being stricter than that would cut off local clients.
func TestACLLocalhostDefaultsBeatBroaderRules(t *testing.T) {
	a := newACL(t, aclText("0.0.0.0/0 refuse", "::/0 deny"))
	checkLookup(t, a, "8.8.8.8", ACLRefuse) // before-state: the broad rules do act elsewhere
	checkLookup(t, a, "2606:4700::1111", ACLDrop)
	checkLookup(t, a, "::2", ACLDrop)
	checkLookup(t, a, "127.0.0.2", ACLForward)
	checkLookup(t, a, "127.255.255.255", ACLForward)
	checkLookup(t, a, "::ffff:127.0.0.5", ACLForward)
	checkLookup(t, a, "::1", ACLForward)
}

// The defaults lose to the file: an identical prefix overrides them, and a more specific row sits inside.
func TestACLLocalhostDefaultsYieldToExplicitRows(t *testing.T) {
	a := newACL(t, aclText("127.0.0.0/8 deny", "::1 refuse"))
	checkLookup(t, a, "127.0.0.2", ACLDrop)
	checkLookup(t, a, "::1", ACLRefuse)
	b := newACL(t, aclText("0.0.0.0/0 refuse", "127.0.0.9/32 deny"))
	checkLookup(t, b, "127.0.0.9", ACLDrop)
	checkLookup(t, b, "127.0.0.8", ACLForward)
}

func TestACLBareAddressIsHostPrefix(t *testing.T) {
	a := newACL(t, aclText("203.0.113.9 deny"))
	checkLookup(t, a, "203.0.113.9", ACLDrop)
	checkLookup(t, a, "203.0.113.8", ACLRefuse)
	checkLookup(t, a, "203.0.113.10", ACLRefuse)
}

// C1: the gateway puts the unmapped address in the PROXYv2 header, so lookups must unmap too.
func TestACLIPv4MappedClientMatchesAsIPv4(t *testing.T) {
	a := newACL(t, aclText("10.0.0.0/8 deny"))
	checkLookup(t, a, "::ffff:10.0.0.1", ACLDrop)
	checkLookup(t, a, "::ffff:11.0.0.1", ACLRefuse)
}

func TestACLZoneIsDroppedBeforeLookup(t *testing.T) {
	a := newACL(t, aclText("fe80::/10 deny", "fe80::1 allow"))
	checkLookup(t, a, "fe80::2%em0", ACLDrop)
	checkLookup(t, a, "fe80::1%em0", ACLForward)
}

// Unbound refuses a client that matches no row; a v4 /0 never captures a v6 client nor a v6 /0 a v4 one.
func TestACLUnmatchedAndForeignFamilyClientsAreRefused(t *testing.T) {
	a := newACL(t, aclText("10.0.0.0/8 deny", "2001:db8::/32 refuse"))
	checkLookup(t, a, "192.0.2.1", ACLRefuse)
	checkLookup(t, a, "2606:4700::1111", ACLRefuse)
	if got := a.Lookup(netip.Addr{}); got != ACLForward {
		t.Errorf("Lookup(zero Addr): got %v, want %v", got, ACLForward)
	}
	checkLookup(t, newACL(t, aclText("0.0.0.0/0 deny")), "2001:db8::1", ACLRefuse)
	checkLookup(t, newACL(t, aclText("::/0 deny")), "192.0.2.1", ACLRefuse)
}

// The file exactly as pfSense unbound_acls_config() writes it, trailing space and comment lines included.
func TestACLPfSenseShapedFile(t *testing.T) {
	a := newACL(t, "access-control: 127.0.0.1/32 allow_snoop\n"+
		"access-control: ::1 allow_snoop\n"+
		"access-control: 192.168.1.0/24 allow \n"+
		"#Guests\n"+
		"access-control: 10.9.0.0/16 deny\n"+
		"access-control: 10.9.1.0/24 refuse_non_local\n")
	checkLookup(t, a, "127.0.0.1", ACLForward)
	checkLookup(t, a, "::1", ACLForward)
	checkLookup(t, a, "192.168.1.50", ACLForward)
	checkLookup(t, a, "10.9.7.7", ACLDrop)
	checkLookup(t, a, "10.9.1.7", ACLForward)
}

func TestACLMissingFileForwardsEverythingAndLogsOnce(t *testing.T) {
	var log capturedLog
	a := NewACL(filepath.Join(t.TempDir(), "absent.conf"), log.logf)
	checkLookup(t, a, "10.1.2.3", ACLForward)
	checkLookup(t, a, "2001:db8::1", ACLForward)
	if log.count() == 0 {
		t.Error("a missing ACL file must be logged")
	}
	logged := log.count()
	if a.Refresh() {
		t.Error("Refresh() on a still-missing file: got changed=true, want false")
	}
	if log.count() != logged {
		t.Errorf("a still-missing file must not log again each Refresh; log:\n%s", log.joined())
	}
}

// A config with no `access-control` row is a valid Unbound config: only localhost is served.
func TestACLEmptyFileRefusesEveryoneButLocalhost(t *testing.T) {
	a := newACL(t, "")
	checkLookup(t, a, "10.1.2.3", ACLRefuse)
	checkLookup(t, a, "2001:db8::1", ACLRefuse)
	checkLookup(t, a, "127.0.0.1", ACLForward)
	checkLookup(t, a, "::1", ACLForward)
}

// F3: file_put_contents truncates then writes; a cut `refuse_non_local` reads as `refuse` and must not act.
func TestACLUnterminatedLastLineIsIgnored(t *testing.T) {
	a := newACL(t, "access-control: 10.0.0.0/8 allow\naccess-control: 10.1.0.0/16 refuse")
	checkLookup(t, a, "10.9.9.9", ACLForward)
	checkLookup(t, a, "10.1.1.1", ACLForward)
}

func TestACLRefreshUnchangedReportsFalseAndKeepsRules(t *testing.T) {
	path := writeACLFile(t, aclText("10.0.0.0/8 deny"))
	a := NewACL(path, t.Logf)
	if a.Refresh() {
		t.Error("Refresh() with nothing changed: got changed=true, want false")
	}
	checkLookup(t, a, "10.1.2.3", ACLDrop)
}

// F4, size arm: mtime is restored so only the size says the content moved.
func TestACLRewriteInPlaceIsReloadedBySize(t *testing.T) {
	path := writeACLFile(t, aclText("10.0.0.0/8 deny"))
	a := NewACL(path, t.Logf)
	checkLookup(t, a, "10.1.2.3", ACLDrop) // before-state
	before := mustStat(t, path)
	if err := os.WriteFile(path, []byte(aclText("10.0.0.0/8 refuse", "11.0.0.0/8 deny")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	after := mustStat(t, path)
	if !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) || before.Size() == after.Size() {
		t.Fatalf("test premise: want same inode and mtime, different size; before %v/%d after %v/%d",
			before.ModTime(), before.Size(), after.ModTime(), after.Size())
	}
	if !a.Refresh() {
		t.Error("Refresh() after an in-place rewrite: got changed=false, want true")
	}
	checkLookup(t, a, "10.1.2.3", ACLRefuse)
	checkLookup(t, a, "11.1.1.1", ACLDrop)
}

// F4, mtime arm: same inode, same size, only the modification time moved.
func TestACLRewriteInPlaceIsReloadedByMtime(t *testing.T) {
	path := writeACLFile(t, aclText("10.0.0.0/8 deny"))
	a := NewACL(path, t.Logf)
	checkLookup(t, a, "10.1.2.3", ACLDrop)
	before := mustStat(t, path)
	if err := os.WriteFile(path, []byte(aclText("11.0.0.0/8 deny")), 0o644); err != nil {
		t.Fatal(err)
	}
	later := before.ModTime().Add(2 * time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	after := mustStat(t, path)
	if !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("test premise: want same inode and size, different mtime")
	}
	if !a.Refresh() {
		t.Error("Refresh() after an mtime-only change: got changed=false, want true")
	}
	checkLookup(t, a, "10.1.2.3", ACLRefuse)
	checkLookup(t, a, "11.1.1.1", ACLDrop)
}

// F6, inode arm: same size and mtime, only the file identity changed (rename over the path).
func TestACLReplacedByRenameIsReloadedByInode(t *testing.T) {
	path := writeACLFile(t, aclText("10.0.0.0/8 deny"))
	a := NewACL(path, t.Logf)
	checkLookup(t, a, "10.1.2.3", ACLDrop)
	before := mustStat(t, path)
	fresh := path + ".new"
	if err := os.WriteFile(fresh, []byte(aclText("11.0.0.0/8 deny")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(fresh, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(fresh, path); err != nil {
		t.Fatal(err)
	}
	after := mustStat(t, path)
	if os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("test premise: want a new inode with the same size and mtime")
	}
	if !a.Refresh() {
		t.Error("Refresh() after a rename replacement: got changed=false, want true")
	}
	checkLookup(t, a, "10.1.2.3", ACLRefuse)
	checkLookup(t, a, "11.1.1.1", ACLDrop)
}

// F7: a stale deny must never survive its file.
func TestACLDeletedFileForwardsEverythingAndRecovers(t *testing.T) {
	path := writeACLFile(t, aclText("10.0.0.0/8 deny"))
	var log capturedLog
	a := NewACL(path, log.logf)
	checkLookup(t, a, "10.1.2.3", ACLDrop)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if !a.Refresh() {
		t.Error("Refresh() after the file was deleted: got changed=false, want true")
	}
	checkLookup(t, a, "10.1.2.3", ACLForward)
	if a.Refresh() {
		t.Error("second Refresh() on a still-deleted file: got changed=true, want false")
	}
	if err := os.WriteFile(path, []byte(aclText("10.0.0.0/8 refuse")), 0o644); err != nil {
		t.Fatal(err)
	}
	if !a.Refresh() {
		t.Error("Refresh() after the file came back: got changed=false, want true")
	}
	checkLookup(t, a, "10.1.2.3", ACLRefuse)
}

type lookupCheck struct {
	client string
	want   ACLAction
}

func TestACLHostileInput(t *testing.T) {
	// A line the parser must skip, followed by a good deny that proves parsing carried on.
	ignored := func(bad string) string { return bad + "\n" + aclText("12.0.0.0/8 deny") }
	skipped := []lookupCheck{{"10.1.1.1", ACLRefuse}, {"12.1.1.1", ACLDrop}}
	cases := []struct {
		name    string
		content string
		checks  []lookupCheck
	}{
		{"CRLF line endings", "access-control: 10.0.0.0/8 deny\r\naccess-control: 11.0.0.0/8 refuse\r\n",
			[]lookupCheck{{"10.1.1.1", ACLDrop}, {"11.1.1.1", ACLRefuse}}},
		{"tabs and repeated spaces", "access-control:\t10.0.0.0/8   \t deny\n",
			[]lookupCheck{{"10.1.1.1", ACLDrop}}},
		{"quoted netblock", "access-control: \"10.0.0.0/8\" deny\n",
			[]lookupCheck{{"10.1.1.1", ACLDrop}}},
		{"quoted action", "access-control: 10.0.0.0/8 \"deny\"\n", []lookupCheck{{"10.1.1.1", ACLDrop}}},
		{"single-quoted netblock", "access-control: '10.0.0.0/8' deny\n", []lookupCheck{{"10.1.1.1", ACLDrop}}},
		{"trailing comment", "access-control: 10.0.0.0/8 deny # x\n",
			[]lookupCheck{{"10.1.1.1", ACLDrop}}},
		{"commented-out rule", ignored("#access-control: 10.0.0.0/8 deny"), skipped},
		{"access-control-view names an implicit allow", ignored("access-control-view: 10.0.0.0/8 v1"),
			[]lookupCheck{{"10.1.1.1", ACLForward}, {"12.1.1.1", ACLDrop}}},
		{"prefix /33", ignored("access-control: 10.0.0.0/33 deny"), skipped},
		{"prefix /-1", ignored("access-control: 10.0.0.0/-1 deny"), skipped},
		{"prefix /abc", ignored("access-control: 10.0.0.0/abc deny"), skipped},
		{"prefix missing digits", ignored("access-control: 10.0.0.0/ deny"), skipped},
		{"IPv6 prefix /129", ignored("access-control: 2001:db8::/129 deny"),
			[]lookupCheck{{"2001:db8::1", ACLRefuse}, {"12.1.1.1", ACLDrop}}},
		{"zone id in prefix", ignored("access-control: fe80::1%em0/64 deny"),
			[]lookupCheck{{"fe80::2", ACLRefuse}, {"12.1.1.1", ACLDrop}}},
		{"zone id in bare address", ignored("access-control: fe80::1%em0 deny"),
			[]lookupCheck{{"fe80::1", ACLRefuse}, {"12.1.1.1", ACLDrop}}},
		{"extra trailing token", ignored("access-control: 10.0.0.0/8 deny extra"), skipped},
		{"empty quoted netblock", ignored("access-control: \"\" deny"), skipped},
		{"missing netblock", ignored("access-control: deny"), skipped},
		{"missing action", ignored("access-control: 10.0.0.0/8"), skipped},
		{"non-UTF-8 byte in the netblock", ignored("access-control: 10.0.0.0/8\xff deny"), skipped},
		{"non-UTF-8 byte in a trailing comment", "access-control: 10.0.0.0/8 deny # caf\xe9\n", []lookupCheck{{"10.1.1.1", ACLDrop}}},
		// Unbound's lexer splits on space and tab only; a Unicode space must not make a rule stricter.
		{"non-breaking space separator", ignored("access-control: 10.0.0.0/8\u00a0deny"), skipped},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := newACL(t, c.content)
			for _, ch := range c.checks {
				checkLookup(t, a, ch.client, ch.want)
			}
		})
	}
}

// A glued access-control netblock must retain its action instead of becoming an unmatched-client refusal.
// TestACLOracleGluedKeyRows checks the same spellings against a running Unbound.
func TestACLGluedKeyRowsAreApplied(t *testing.T) {
	cases := []struct{ name, row, client string }{
		{"no space after the colon", "access-control:10.0.0.0/8 deny", "10.1.1.1"},
		{"no space, trailing comment", "access-control:10.0.0.0/8 deny # x", "10.1.1.1"},
		{"no space, tab before the action", "access-control:10.0.0.0/8\tdeny", "10.1.1.1"},
		{"no space, double-quoted netblock", "access-control:\"10.0.0.0/8\" deny", "10.1.1.1"},
		{"no space, single-quoted netblock", "access-control:'10.0.0.0/8' deny", "10.1.1.1"},
		{"no space, IPv6 netblock", "access-control:2001:db8::/32 deny", "2001:db8::1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := newACL(t, c.row+"\n")
			checkLookup(t, a, c.client, ACLDrop)
			checkLookup(t, a, "12.1.1.1", ACLRefuse)
		})
	}
}

// Unbound 1.26.1 allows a netblock named by an implicit-allow keyword whether the netblock is glued to the keyword or not,
// quoted or not, IPv4 or IPv6; TestACLOracleGluedImplicitRows checks these spellings against a running Unbound.
func TestACLGluedImplicitRowsAreAllowedLikeUnbound(t *testing.T) {
	keywords := []struct{ name, args string }{
		{"access-control-view", "v1"},
		{"access-control-tag", `"t1"`},
		{"access-control-tag-action", `"t1" deny`},
		{"access-control-tag-data", `"t1" "A 192.0.2.1"`},
	}
	families := []struct{ name, netblock, in, out string }{
		{"IPv4", "10.5.0.0/16", "10.5.1.1", "10.9.1.1"},
		{"IPv6", "2001:db8:5::/48", "2001:db8:5::1", "2001:db8:9::1"},
	}
	quotes := []struct {
		name string
		wrap func(string) string
	}{
		{"unquoted", func(s string) string { return s }},
		{"double-quoted", func(s string) string { return `"` + s + `"` }},
		{"single-quoted", func(s string) string { return "'" + s + "'" }},
	}
	for _, k := range keywords {
		for _, glued := range []bool{false, true} {
			for _, f := range families {
				for _, q := range quotes {
					head, spelling := k.name+": ", "standard"
					if glued {
						head, spelling = k.name+":", "glued"
					}
					row := head + q.wrap(f.netblock) + " " + k.args + "\n"
					t.Run(k.name+" "+spelling+" "+f.name+" "+q.name, func(t *testing.T) {
						a := newACL(t, row)
						checkLookup(t, a, f.in, ACLForward)
						checkLookup(t, a, f.out, ACLRefuse)
					})
				}
			}
		}
	}
}

// The implicit rows keep their meaning beyond the glued spelling: an identical explicit row still wins, a glued row allows
// its own netblock only, unknown keywords and unparsable netblocks are skipped, and a keyword without its colon is not a row.
func TestACLImplicitRowGuards(t *testing.T) {
	t.Run("an identical explicit deny wins over an implicit allow in either order and spelling", func(t *testing.T) {
		for _, content := range []string{
			"access-control: 10.5.0.0/16 deny\naccess-control-view:10.5.0.0/16 v1\n",
			"access-control-view:10.5.0.0/16 v1\naccess-control: 10.5.0.0/16 deny\n",
			"access-control:10.5.0.0/16 deny\naccess-control-view: 10.5.0.0/16 v1\n",
			"access-control-view: 10.5.0.0/16 v1\naccess-control:10.5.0.0/16 deny\n",
		} {
			a := newACL(t, content)
			checkLookup(t, a, "10.5.1.1", ACLDrop)
			checkLookup(t, a, "10.9.1.1", ACLRefuse)
		}
	})
	t.Run("a standard implicit row allows its own netblock only", func(t *testing.T) {
		a := newACL(t, "access-control-view: 10.5.0.0/16 v1\n")
		checkLookup(t, a, "10.5.1.1", ACLForward)
		checkLookup(t, a, "10.6.1.1", ACLRefuse)
		checkLookup(t, a, "192.0.2.7", ACLRefuse)
	})
	for _, bad := range []string{
		"access-control-viewer:10.1.0.0/16 v1",
		"access-control-viewer: 10.1.0.0/16 v1",
		"access-control-view:10.1.0.0/33 v1",
		"access-control-view: 10.1.0.0/33 v1",
		"access-control-view:10.1.0.0/abc v1",
	} {
		t.Run("skipped "+bad, func(t *testing.T) {
			a := newACL(t, bad+"\naccess-control-view: 12.0.0.0/8 v1\n")
			checkLookup(t, a, "10.1.1.1", ACLRefuse)
			checkLookup(t, a, "12.1.1.1", ACLForward)
			checkLookup(t, a, "192.0.2.7", ACLRefuse)
		})
	}
	t.Run("a keyword without its colon is not a row", func(t *testing.T) {
		a := newACL(t, "access-control-view 10.1.0.0/16 v1\naccess-control-view: 12.0.0.0/8 v1\n")
		checkLookup(t, a, "10.1.1.1", ACLRefuse)
		checkLookup(t, a, "12.1.1.1", ACLForward)
	})
}

// The oversized line would parse as `10.0.0.0/8 deny` if the line cap were missing.
func TestACLOversizedLineIsIgnoredWithoutExtraAllocation(t *testing.T) {
	content := "access-control: 10.0.0.0/8 deny" + strings.Repeat(" ", 1<<20) + "# x\n" + aclText("11.0.0.0/8 deny")
	path := writeACLFile(t, content)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	a := NewACL(path, t.Logf)
	runtime.ReadMemStats(&after)
	if got, limit := after.TotalAlloc-before.TotalAlloc, uint64(2*len(content)); got > limit {
		t.Errorf("NewACL allocated %d bytes for a %d-byte file; want at most %d", got, len(content), limit)
	}
	checkLookup(t, a, "10.1.1.1", ACLRefuse)
	checkLookup(t, a, "11.1.1.1", ACLDrop)
}

func TestACLTwentyThousandLinesAllResolve(t *testing.T) {
	const n = 20000
	var b strings.Builder
	for i := range n {
		action := "deny"
		if i%2 == 1 {
			action = "refuse"
		}
		fmt.Fprintf(&b, "access-control: 10.%d.%d.0/24 %s\n", i/256, i%256, action)
	}
	a := newACL(t, b.String())
	for i := range n {
		want := ACLDrop
		if i%2 == 1 {
			want = ACLRefuse
		}
		client := fmt.Sprintf("10.%d.%d.1", i/256, i%256)
		if got := a.Lookup(mustAddr(t, client)); got != want {
			t.Fatalf("Lookup(%s): got %v, want %v", client, got, want)
		}
	}
	checkLookup(t, a, "10.200.0.1", ACLRefuse)
	checkLookup(t, a, "11.0.0.1", ACLRefuse)
}

// The assertion is the race detector (go test -race) plus a deterministic end state.
func TestACLConcurrentLookupDuringRefresh(t *testing.T) {
	path := writeACLFile(t, aclText("10.0.0.0/8 deny"))
	a := NewACL(path, t.Logf)
	contents := []string{aclText("10.0.0.0/8 refuse", "11.0.0.0/8 deny"), aclText("10.0.0.0/8 deny")}
	client := mustAddr(t, "10.1.2.3")
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					a.Lookup(client)
				}
			}
		}()
	}
	for i := range 200 {
		if err := os.WriteFile(path, []byte(contents[i%2]), 0o644); err != nil {
			t.Fatal(err)
		}
		later := time.Unix(1_700_000_000+int64(i), 0)
		if err := os.Chtimes(path, later, later); err != nil {
			t.Fatal(err)
		}
		a.Refresh()
	}
	close(stop)
	readers.Wait()
	// Iteration 199 wrote contents[1]: a lone 10/8 deny.
	checkLookup(t, a, "10.1.2.3", ACLDrop)
	checkLookup(t, a, "11.1.1.1", ACLRefuse)
}

// F1: access-control-view, -tag, -tag-action and -tag-data name a netblock Unbound allows when no access-control row
// names the same netblock. An identical row keeps its action, and a more specific view sits under a refuse row.
func TestACLViewAndTagNetblocksWithoutARowAreAllowed(t *testing.T) {
	a := newACL(t, "access-control: 10.7.0.0/16 refuse\n"+
		"access-control-view: 10.7.1.0/24 v1\n"+
		"access-control-view: 10.7.0.0/16 v1\n"+
		"access-control-tag: 10.8.0.0/16 \"t1\"\n"+
		"access-control-tag-action: 10.9.0.0/16 t1 deny\n"+
		"access-control-tag-data: 10.10.0.0/16 t1 \"x\"\n")
	checkAll(t, a, map[string]ACLAction{
		"10.7.1.5":  ACLForward, // view under the refuse row
		"10.7.0.5":  ACLRefuse,  // identical netblock: the explicit row stands
		"10.8.0.5":  ACLForward, // tag only
		"10.9.0.5":  ACLForward, // tag action only
		"10.10.0.5": ACLForward, // tag data only
		"10.11.0.5": ACLRefuse,  // no row names it
	})
}

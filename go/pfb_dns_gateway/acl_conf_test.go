package main

// The gateway's ACL is Unbound's effective `access-control` set: the rows of unbound.conf and of every file it
// pulls in with `include:` (globs too), most specific prefix first, the last row of identical prefixes winning,
// and a client no row names refused.

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// confTree writes files (relative name -> content, "{dir}" standing for the tree's directory) and returns the
// directory; unbound.conf is the ACL's path.
func confTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(strings.ReplaceAll(content, "{dir}", dir)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func newACLTree(t *testing.T, files map[string]string) (*ACL, string, *capturedLog) {
	t.Helper()
	dir := confTree(t, files)
	log := &capturedLog{}
	return NewACL(filepath.Join(dir, "unbound.conf"), log.logf), dir, log
}

func checkAll(t *testing.T, a *ACL, want map[string]ACLAction) {
	t.Helper()
	for client, action := range want {
		checkLookup(t, a, client, action)
	}
}

// rewriteFile replaces path's content and moves its mtime on, so Refresh cannot mistake it for the old file.
func rewriteFile(t *testing.T, path, content string) {
	t.Helper()
	before := mustStat(t, path)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	later := before.ModTime().Add(2 * time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
}

// pfSense writes access_lists.conf and includes it; pfBlockerNG's marked clause (the IPv6 LAN grant pfSense no
// longer writes with the Resolver on loopback) and an admin's custom row sit in unbound.conf itself.
func TestACLFollowsIncludesAndReadsTheMarkedClauseAndCustomRows(t *testing.T) {
	a, _, log := newACLTree(t, map[string]string{
		"unbound.conf": "server:\n    chroot: \"/var/unbound\"\n    include: {dir}/access_lists.conf\n    include: {dir}/host_entries.conf\n" +
			"server:\n# pfBlockerNG DNS proxy\nport: 5354\naccess-control: 2001:db8:51:1::/64 allow\n# end\n" +
			"access-control: 198.51.100.0/24 deny\n",
		"access_lists.conf": "#LAN\naccess-control: 127.0.0.1/32 allow_snoop\naccess-control: 192.168.1.0/24 allow \n",
		"host_entries.conf": "local-data: \"a.example. A 192.0.2.1\"\naccess-control-view: 10.0.0.0/8 ignored\n",
	})
	checkAll(t, a, map[string]ACLAction{
		"192.168.1.50":        ACLForward, // a row of the included access_lists.conf
		"2001:db8:51:1::1234": ACLForward, // the marked clause's IPv6 grant: in no included file
		"198.51.100.9":        ACLDrop,    // an admin's custom row in unbound.conf
		"127.0.0.1":           ACLForward,
		"10.1.1.1":            ACLForward, // access-control-view with no access-control row: Unbound allows it
		"2001:db8:ffff::1":    ACLRefuse,
	})
	if !strings.Contains(log.joined(), "3 files") {
		t.Errorf("the log should say how many files were read (3); log:\n%s", log.joined())
	}
}

// Unbound reads an include where it stands: of identical prefixes the row read last wins, whichever file it is in.
func TestACLLastRowWinsAcrossFilesAndSpecificityStillBeatsOrder(t *testing.T) {
	a, _, _ := newACLTree(t, map[string]string{
		"unbound.conf": "access-control: 10.0.0.0/8 deny\ninclude: {dir}/a.conf\naccess-control: 10.2.0.0/16 deny\n",
		"a.conf":       "access-control: 10.0.0.0/8 allow\naccess-control: 10.2.0.0/16 refuse\naccess-control: 10.3.0.0/16 refuse\n",
	})
	checkAll(t, a, map[string]ACLAction{
		"10.9.9.9": ACLForward, // the include's allow came after unbound.conf's deny
		"10.2.0.1": ACLDrop,    // unbound.conf's deny came after the include's refuse
		"10.3.0.1": ACLRefuse,  // the /16 is more specific than the /8 allow whatever the order
	})
}

func TestACLGlobIncludeReadsEveryMatchAndNothingElse(t *testing.T) {
	a, _, log := newACLTree(t, map[string]string{
		"unbound.conf":    "server:\ninclude: \"{dir}/acl.d/*.conf\"\ninclude: {dir}/none.d/*.conf\n",
		"acl.d/10-a.conf": "access-control: 10.1.0.0/16 deny\n",
		"acl.d/20-b.conf": "access-control: 10.2.0.0/16 refuse\n",
		"acl.d/30-c.txt":  "access-control: 10.3.0.0/16 deny\n", // not matched by *.conf
		"none.d/x.txt":    "",                                   // a directory with no match for none.d/*.conf
	})
	checkAll(t, a, map[string]ACLAction{
		"10.1.0.1": ACLDrop,
		"10.2.0.1": ACLRefuse,
		"10.3.0.1": ACLRefuse, // no row: Drop if the .txt had been read
	})
	// A glob that matches nothing is not an error (Unbound agrees): the other rows stay in force.
	if strings.Contains(log.joined(), "forwarding every query") {
		t.Errorf("a glob without matches must not break the config; log:\n%s", log.joined())
	}
}

func TestACLIncludeSpellings(t *testing.T) {
	const row = "access-control: 10.0.0.0/8 deny\n"
	cases := []struct {
		name string
		line string
		want ACLAction
	}{
		{"unquoted", "include: {dir}/inc.conf", ACLDrop},
		{"double quoted", "include: \"{dir}/inc.conf\"", ACLDrop},
		{"indented, tabs, trailing comment", "\t  include:\t{dir}/inc.conf   # the rows", ACLDrop},
		{"include-toplevel", "include-toplevel: {dir}/inc.conf", ACLDrop},
		{"commented out", "# include: {dir}/inc.conf", ACLRefuse},
		{"another keyword", "include-else: {dir}/inc.conf", ACLRefuse},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _, _ := newACLTree(t, map[string]string{"unbound.conf": "server:\n" + c.line + "\n", "inc.conf": row})
			checkLookup(t, a, "10.1.1.1", c.want)
		})
	}
}

func TestACLNestedIncludesAreFollowed(t *testing.T) {
	a, _, _ := newACLTree(t, map[string]string{
		"unbound.conf": "include: {dir}/a.conf\n",
		"a.conf":       "include: {dir}/sub/b.conf\n",
		"sub/b.conf":   "access-control: 10.0.0.0/8 deny\n",
	})
	checkLookup(t, a, "10.1.1.1", ACLDrop)
}

// Unbound will not start on any of these; the gateway then forwards everything (it is never stricter than Unbound)
// and says why once. The rows before the broken include must not linger as a half-read ACL.
func TestACLConfigUnboundCannotLoadForwardsEverythingAndLogsOnce(t *testing.T) {
	const head = "access-control: 10.0.0.0/8 deny\n"
	cases := map[string]map[string]string{
		"missing include":        {"unbound.conf": head + "include: {dir}/absent.conf\n"},
		"include is a directory": {"unbound.conf": head + "include: {dir}/d\n", "d/x.conf": ""},
		"include cycle":          {"unbound.conf": head + "include: {dir}/unbound.conf\n"},
		"unterminated quote":     {"unbound.conf": head + "include: \"{dir}/a.conf\n", "a.conf": ""},
		"brace pattern":          {"unbound.conf": head + "include: {dir}/{a,b}.conf\n", "a.conf": "", "b.conf": ""},
		"include without a path": {"unbound.conf": head + "include:\n"},
		"malformed glob":         {"unbound.conf": head + "include: {dir}/[.conf\n"},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			a, _, log := newACLTree(t, files)
			checkAll(t, a, map[string]ACLAction{"10.1.1.1": ACLForward, "192.0.2.1": ACLForward, "::1": ACLForward})
			if got := strings.Count(log.joined(), "forwarding every query"); got != 1 {
				t.Errorf("want the reason logged once, got %d times; log:\n%s", got, log.joined())
			}
			if a.Refresh() {
				t.Error("Refresh() with nothing changed on a config that cannot load: got changed=true, want false")
			}
			if got := strings.Count(log.joined(), "forwarding every query"); got != 1 {
				t.Errorf("an unchanged broken config must not log again each Refresh; log:\n%s", log.joined())
			}
		})
	}
}

func TestACLMissingIncludeIsPickedUpWhenItAppears(t *testing.T) {
	a, dir, _ := newACLTree(t, map[string]string{"unbound.conf": "include: {dir}/late.conf\n"})
	checkLookup(t, a, "10.1.1.1", ACLForward) // before-state: the config cannot load
	if err := os.WriteFile(filepath.Join(dir, "late.conf"), []byte("access-control: 10.0.0.0/8 deny\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !a.Refresh() {
		t.Error("Refresh() after the missing include appeared: got changed=false, want true")
	}
	checkLookup(t, a, "10.1.1.1", ACLDrop)
	checkLookup(t, a, "192.0.2.1", ACLRefuse)
}

// runAsModeUser runs testName in a child that drops to a user the mode bits apply to. The Go gate runs the
// suite as root, and root opens a mode 000 file, so this failure would never happen in-process. The child
// starts as root because the test binary sits in a build directory only root may enter.
func runAsModeUser(t *testing.T, testName string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+testName+"$", "-test.count=1", "-test.timeout=2m")
	cmd.Env = append(os.Environ(), "PFB_ACL_MODE_USER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("mode-bits run as nobody failed: %v\n%s", err, out)
	}
}

// becomeModeUser is runAsModeUser's child giving up root before the test body runs.
func becomeModeUser(t *testing.T) {
	t.Helper()
	nobody, err := lookupAccount("nobody")
	if err != nil {
		t.Fatalf("root ignores mode 000 and user nobody is unavailable: %v", err)
	}
	if err := nobody.drop(); err != nil {
		t.Fatal(err)
	}
}

// An include made mode 000 is a failed reload, not a missing file. The last good rules stay, the same
// permission error is logged once across two Refreshes, and chmod 0644 alone loads the include again.
func TestACLUnreadableIncludeKeepsLastGoodRulesUntilTheModeReturns(t *testing.T) {
	if os.Getuid() == 0 {
		if os.Getenv("PFB_ACL_MODE_USER") == "" {
			runAsModeUser(t, "TestACLUnreadableIncludeKeepsLastGoodRulesUntilTheModeReturns")
			return
		}
		becomeModeUser(t)
	}
	a, dir, log := newACLTree(t, map[string]string{
		"unbound.conf":      "include: {dir}/access_lists.conf\n",
		"access_lists.conf": "access-control: 10.0.0.0/8 deny\n",
	})
	checkLookup(t, a, "10.1.2.3", ACLDrop)
	checkLookup(t, a, "192.0.2.1", ACLRefuse)
	checkLookup(t, a, "127.0.0.1", ACLForward)

	inc := filepath.Join(dir, "access_lists.conf")
	before := mustStat(t, inc)
	if err := os.Chmod(inc, 0); err != nil {
		t.Fatal(err)
	}
	after := mustStat(t, inc)
	if !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() || before.Mode() == after.Mode() {
		t.Fatalf("test premise: chmod 000 must keep inode, mtime and size and change mode; before mode %v mtime %v size %d, after mode %v mtime %v size %d",
			before.Mode(), before.ModTime(), before.Size(), after.Mode(), after.ModTime(), after.Size())
	}
	// chmod leaves mtime and size alone, so touch the main file to reach the open failure.
	main := filepath.Join(dir, "unbound.conf")
	later := mustStat(t, main).ModTime().Add(2 * time.Second)
	if err := os.Chtimes(main, later, later); err != nil {
		t.Fatal(err)
	}

	if !a.Refresh() {
		t.Error("Refresh() after the include became unreadable: got changed=false, want true")
	}
	checkLookup(t, a, "10.1.2.3", ACLDrop)
	checkLookup(t, a, "192.0.2.1", ACLRefuse)
	checkLookup(t, a, "127.0.0.1", ACLForward)
	if strings.Contains(log.joined(), "forwarding every query") {
		t.Errorf("an unreadable include after a good load must not forward every client; log:\n%s", log.joined())
	}
	if got := strings.Count(log.joined(), "keeping the last good rules"); got != 1 {
		t.Errorf("the unreadable include should be logged once so far, got %d; log:\n%s", got, log.joined())
	}
	if a.Refresh() {
		t.Error("second Refresh() on an unchanged unreadable include: got changed=true, want false")
	}
	if got := strings.Count(log.joined(), "keeping the last good rules"); got != 1 {
		t.Errorf("an unchanged permission error must not log again, got %d; log:\n%s", got, log.joined())
	}
	checkLookup(t, a, "10.1.2.3", ACLDrop)
	checkLookup(t, a, "192.0.2.1", ACLRefuse)
	checkLookup(t, a, "127.0.0.1", ACLForward)

	if err := os.Chmod(inc, 0o644); err != nil {
		t.Fatal(err)
	}
	restored := mustStat(t, inc)
	if !os.SameFile(after, restored) || !restored.ModTime().Equal(after.ModTime()) || restored.Size() != after.Size() || restored.Mode() == after.Mode() {
		t.Fatalf("test premise: chmod 0644 must change mode only; unreadable mode %v mtime %v size %d, restored mode %v mtime %v size %d",
			after.Mode(), after.ModTime(), after.Size(), restored.Mode(), restored.ModTime(), restored.Size())
	}
	if !a.Refresh() {
		t.Error("Refresh() after chmod 0644 and no other edit: got changed=false, want true")
	}
	if got := strings.Count(log.joined(), "acl: loaded "); got != 2 {
		t.Errorf("restoring the mode must load the include again, loaded-lines=%d; log:\n%s", got, log.joined())
	}
	if got := strings.Count(log.joined(), "keeping the last good rules"); got != 1 {
		t.Errorf("restoring the mode must not be another failed reload, keeping-lines=%d; log:\n%s", got, log.joined())
	}
	checkLookup(t, a, "10.1.2.3", ACLDrop) // the include's deny, not a forward-all fallback
	checkLookup(t, a, "192.0.2.1", ACLRefuse)
	checkLookup(t, a, "127.0.0.1", ACLForward)
}

// An include glob whose directory cannot be opened fails the reload, so a deny that lives in the glob stays
// denied over the broader allow. A readable directory with no matches is an empty include and does not fail
// the load; a directory that is not there is an empty include too.
func TestACLUnreadableGlobDirectoryKeepsTheDeniedAddress(t *testing.T) {
	if os.Getuid() == 0 {
		if os.Getenv("PFB_ACL_MODE_USER") == "" {
			runAsModeUser(t, "TestACLUnreadableGlobDirectoryKeepsTheDeniedAddress")
			return
		}
		becomeModeUser(t)
	}

	dir := confTree(t, map[string]string{
		"unbound.conf": "access-control: 10.0.0.0/8 allow\n" +
			"include: {dir}/acl.d/*.conf\n" +
			"include: {dir}/empty.d/*.conf\n" +
			"include: {dir}/missing.d/*.conf\n",
		"acl.d/deny.conf": "access-control: 10.1.2.3/32 deny\n",
	})
	emptyDir := filepath.Join(dir, "empty.d")
	if err := os.Mkdir(emptyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	log := &capturedLog{}
	a := NewACL(filepath.Join(dir, "unbound.conf"), log.logf)

	entries, readErr := os.ReadDir(emptyDir)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("test premise: empty.d must be readable and empty, got %d entries, err %v", len(entries), readErr)
	}
	if _, err := os.Stat(filepath.Join(dir, "missing.d")); !os.IsNotExist(err) {
		t.Fatalf("test premise: missing.d must be absent, stat err %v", err)
	}
	checkAll(t, a, map[string]ACLAction{
		"10.1.2.3":  ACLDrop,    // the glob's deny, more specific than the allow
		"10.9.9.9":  ACLForward, // the broader allow
		"192.0.2.1": ACLRefuse,  // no row names it: Refuse, not a failed load's forward-all
	})
	loaded := log.joined()
	if !strings.Contains(loaded, "acl: loaded 2 entries from 2 files") ||
		strings.Contains(loaded, "forwarding every query") ||
		strings.Contains(loaded, "keeping the last good rules") {
		t.Errorf("a readable empty include directory must not fail the load; log:\n%s", loaded)
	}

	aclDir := filepath.Join(dir, "acl.d")
	t.Cleanup(func() { _ = os.Chmod(aclDir, 0o755) })
	if err := os.Chmod(aclDir, 0); err != nil {
		t.Fatal(err)
	}
	if f, err := os.Open(aclDir); err == nil {
		f.Close()
		t.Fatal("test premise: mode 000 directory opened; mode bits are not in force")
	}
	if !a.Refresh() {
		t.Error("Refresh() after the glob directory became unreadable: got changed=false, want true")
	}
	checkLookup(t, a, "10.1.2.3", ACLDrop) // still denied; the broader allow must not take over
	checkLookup(t, a, "10.9.9.9", ACLForward)
	checkLookup(t, a, "192.0.2.1", ACLRefuse)
	if strings.Contains(log.joined(), "forwarding every query") {
		t.Errorf("an unlistable glob after a good load must not forward every client; log:\n%s", log.joined())
	}
	if got := strings.Count(log.joined(), "keeping the last good rules"); got != 1 {
		t.Errorf("the unlistable glob should keep the last good rules once, got %d; log:\n%s", got, log.joined())
	}
}

// Only a permission error is a failure that waits for the file to change. Any other open error (here a socket,
// standing in for a transient EMFILE or EIO) is retried on every Refresh, so the edit it hid is not lost.
func TestACLOpenErrorThatIsNotPermissionIsRetriedOnEveryRefresh(t *testing.T) {
	sockDir, err := os.MkdirTemp("", "pfbacl") // short: a socket path is limited to about 100 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	inc := filepath.Join(sockDir, "inc.conf")
	if err := os.WriteFile(inc, []byte("access-control: 10.0.0.0/8 deny\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, _, log := newACLTree(t, map[string]string{"unbound.conf": "include: " + inc + "\n"})
	checkLookup(t, a, "10.1.2.3", ACLDrop)

	if err := os.Remove(inc); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", inc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if !a.Refresh() {
		t.Error("Refresh() after the include became a socket: got changed=false, want true")
	}
	checkLookup(t, a, "10.1.2.3", ACLDrop)
	if strings.Contains(log.joined(), "forwarding every query") {
		t.Errorf("an open error after a good load must not forward every client; log:\n%s", log.joined())
	}
	if !a.Refresh() {
		t.Error("second Refresh() on a non-permission open error: got changed=false, want true (it must be retried)")
	}
	checkLookup(t, a, "10.1.2.3", ACLDrop)
}

// A config that has never loaded forwards every client. An edit that still names the missing include must keep
// forwarding the denied address, localhost and an address no row names; that broken snapshot is not rules to keep.
func TestACLEditThatStillCannotLoadKeepsForwardingEveryone(t *testing.T) {
	a, dir, log := newACLTree(t, map[string]string{
		"unbound.conf": "access-control: 10.0.0.0/8 deny\ninclude: {dir}/absent.conf\n",
	})
	checkLookup(t, a, "10.1.2.3", ACLForward) // before-state: the deny row is not in force
	checkLookup(t, a, "127.0.0.1", ACLForward)
	checkLookup(t, a, "198.51.100.1", ACLForward) // no row names it
	if strings.Contains(log.joined(), "keeping the last good rules") {
		t.Errorf("startup with a missing include has no rules to keep; log:\n%s", log.joined())
	}

	rewriteFile(t, filepath.Join(dir, "unbound.conf"),
		"access-control: 10.0.0.0/8 deny\ninclude: "+filepath.Join(dir, "absent.conf")+"\n# edited\n")
	if !a.Refresh() {
		t.Error("Refresh() after an edit that still cannot load: got changed=false, want true")
	}
	checkLookup(t, a, "10.1.2.3", ACLForward)
	checkLookup(t, a, "127.0.0.1", ACLForward)
	checkLookup(t, a, "198.51.100.1", ACLForward)
	if strings.Contains(log.joined(), "keeping the last good rules") {
		t.Errorf("a config that has never loaded must not be kept as rules; log:\n%s", log.joined())
	}
}

// Every file the rules came from is watched: a change to any of them reloads, nothing else does.
func TestACLRefreshWatchesEveryIncludedFileAndGlob(t *testing.T) {
	a, dir, _ := newACLTree(t, map[string]string{
		"unbound.conf":      "include: {dir}/access_lists.conf\ninclude: {dir}/acl.d/*.conf\n",
		"access_lists.conf": "access-control: 10.1.0.0/16 deny\n",
		"acl.d/a.conf":      "access-control: 10.2.0.0/16 deny\n",
	})
	checkAll(t, a, map[string]ACLAction{"10.1.0.1": ACLDrop, "10.2.0.1": ACLDrop, "10.3.0.1": ACLRefuse})
	if a.Refresh() {
		t.Error("Refresh() with nothing changed: got changed=true, want false")
	}

	rewriteFile(t, filepath.Join(dir, "access_lists.conf"), "access-control: 10.1.0.0/16 refuse\n")
	if !a.Refresh() {
		t.Error("Refresh() after an included file changed: got changed=false, want true")
	}
	checkLookup(t, a, "10.1.0.1", ACLRefuse)

	if err := os.WriteFile(filepath.Join(dir, "acl.d", "b.conf"), []byte("access-control: 10.3.0.0/16 deny\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !a.Refresh() {
		t.Error("Refresh() after a file appeared that the glob matches: got changed=false, want true")
	}
	checkLookup(t, a, "10.3.0.1", ACLDrop)

	rewriteFile(t, filepath.Join(dir, "acl.d", "a.conf"), "access-control: 10.2.0.0/16 refuse\n")
	if !a.Refresh() {
		t.Error("Refresh() after a glob match changed: got changed=false, want true")
	}
	checkLookup(t, a, "10.2.0.1", ACLRefuse)

	if err := os.Remove(filepath.Join(dir, "acl.d", "b.conf")); err != nil {
		t.Fatal(err)
	}
	if !a.Refresh() {
		t.Error("Refresh() after a glob match was removed: got changed=false, want true")
	}
	checkLookup(t, a, "10.3.0.1", ACLRefuse)

	rewriteFile(t, filepath.Join(dir, "unbound.conf"), "include: "+filepath.Join(dir, "access_lists.conf")+"\n")
	if !a.Refresh() {
		t.Error("Refresh() after unbound.conf stopped including the glob: got changed=false, want true")
	}
	checkAll(t, a, map[string]ACLAction{"10.1.0.1": ACLRefuse, "10.2.0.1": ACLRefuse})
}

// A real Resolver's config pulls in files that are not ACLs and can be huge (DNSBL's local-zone lists): they are
// read as a stream, not slurped, and never refuse the config.
func TestACLLargeUnrelatedIncludeIsStreamedAndRowsAfterItApply(t *testing.T) {
	line := "local-zone: \"example.test.\" static\n"
	big := strings.Repeat(line, (24<<20)/len(line)) // 24 MiB, over the 16 MiB the whole-file reader used to refuse
	dir := confTree(t, map[string]string{
		"unbound.conf":   "access-control: 10.1.0.0/16 deny\ninclude: {dir}/pfb_dnsbl.conf\naccess-control: 10.2.0.0/16 refuse\n",
		"pfb_dnsbl.conf": big + "access-control: 10.3.0.0/16 deny\n",
	})
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	a := NewACL(filepath.Join(dir, "unbound.conf"), t.Logf)
	runtime.ReadMemStats(&after)
	if got, limit := after.TotalAlloc-before.TotalAlloc, uint64(4<<20); got > limit {
		t.Errorf("NewACL allocated %d bytes for a %d-byte include; a stream needs at most %d", got, len(big), limit)
	}
	checkAll(t, a, map[string]ACLAction{"10.1.0.1": ACLDrop, "10.2.0.1": ACLRefuse, "10.3.0.1": ACLDrop, "10.4.0.1": ACLRefuse})
}

// Every include is a file Unbound opens; a gateway that opens thousands of them for one config stops and forwards.
func TestACLIncludeFanOutIsBounded(t *testing.T) {
	files := map[string]string{"unbound.conf": "include: {dir}/loop.d/*.conf\n"}
	for i := range 3 {
		files[fmt.Sprintf("loop.d/%d.conf", i)] = "include: {dir}/loop.d/*.conf\n" // every file includes all three again
	}
	a, _, log := newACLTree(t, files)
	checkLookup(t, a, "10.1.1.1", ACLForward)
	if !strings.Contains(log.joined(), "forwarding every query") {
		t.Errorf("a config that fans out without end must be reported; log:\n%s", log.joined())
	}
}

// F3: Unbound reads `[!` as glob(3) negation; filepath.Match reads it as a set of '!' and 'a'.
func TestACLGlobBracketNegationMatchesGlob3(t *testing.T) {
	a, _, _ := newACLTree(t, map[string]string{
		"unbound.conf":  "include: {dir}/acl.d/[!a]*.conf\n",
		"acl.d/a1.conf": "access-control: 10.1.0.0/16 deny\n",
		"acl.d/b1.conf": "access-control: 10.2.0.0/16 deny\n",
	})
	checkLookup(t, a, "10.1.0.1", ACLRefuse) // a1.conf is not matched, so no row names the client
	checkLookup(t, a, "10.2.0.1", ACLDrop)
}

// F3: a wildcard does not match a leading dot (glob(3)); a dot the pattern spells out still matches.
func TestACLGlobWildcardDoesNotMatchDotFiles(t *testing.T) {
	a, _, _ := newACLTree(t, map[string]string{
		"unbound.conf":       "include: {dir}/acl.d/*.conf\ninclude: {dir}/.hid/*.conf\n",
		"acl.d/a.conf":       "access-control: 10.1.0.0/16 deny\n",
		"acl.d/.hidden.conf": "access-control: 10.2.0.0/16 deny\n",
		".hid/b.conf":        "access-control: 10.3.0.0/16 deny\n",
	})
	checkLookup(t, a, "10.1.0.1", ACLDrop)
	checkLookup(t, a, "10.2.0.1", ACLRefuse) // .hidden.conf is not matched by *.conf
	checkLookup(t, a, "10.3.0.1", ACLDrop)   // a literal dot in the pattern does match
}

// F3: Unbound's unquoted include path runs to a space, tab or CR, so a '#' is part of the name; a quoted one is too.
func TestACLIncludePathWithHashIsOneName(t *testing.T) {
	a, _, _ := newACLTree(t, map[string]string{
		"unbound.conf": "include: {dir}/inc#1.conf\ninclude: \"{dir}/inc#2.conf\"\n",
		"inc#1.conf":   "access-control: 10.1.0.0/16 deny\n",
		"inc#2.conf":   "access-control: 10.2.0.0/16 deny\n",
		"inc":          "access-control: 10.3.0.0/16 deny\n",
	})
	checkLookup(t, a, "10.1.0.1", ACLDrop)
	checkLookup(t, a, "10.2.0.1", ACLDrop)
	checkLookup(t, a, "10.3.0.1", ACLRefuse) // the file named inc is not included
}

// F4: an include on a CRLF line reads its path without the CR, quoted or not.
func TestACLIncludeOnCRLFLine(t *testing.T) {
	for name, line := range map[string]string{"unquoted": "include: {dir}/inc.conf\r\n", "quoted": "include: \"{dir}/inc.conf\"\r\n"} {
		t.Run(name, func(t *testing.T) {
			a, _, _ := newACLTree(t, map[string]string{"unbound.conf": "server:\r\n" + line, "inc.conf": "access-control: 10.0.0.0/8 deny\r\n"})
			checkLookup(t, a, "10.1.1.1", ACLDrop)
		})
	}
}

// F4: every file an include opens counts toward maxACLFiles, shared or not: 64 mids each including the same 64
// leaves is 4161 opens, over the cap; 8 by 8 is well under it.
func TestACLWideIncludeDAGHitsTheFileCap(t *testing.T) {
	dag := func(width int) map[string]string {
		files := map[string]string{}
		var root strings.Builder
		for m := range width {
			fmt.Fprintf(&root, "include: {dir}/mid%d.conf\n", m)
			var mid strings.Builder
			for l := range width {
				fmt.Fprintf(&mid, "include: {dir}/leaf%d.conf\n", l)
			}
			files[fmt.Sprintf("mid%d.conf", m)] = mid.String()
		}
		for l := range width {
			files[fmt.Sprintf("leaf%d.conf", l)] = "access-control: 10.0.0.0/8 deny\n"
		}
		files["unbound.conf"] = root.String()
		return files
	}
	t.Run("8 by 8 loads", func(t *testing.T) {
		a, _, log := newACLTree(t, dag(8))
		checkLookup(t, a, "10.1.1.1", ACLDrop)
		if strings.Contains(log.joined(), "forwarding every query") {
			t.Errorf("a shallow DAG under the cap must load; log:\n%s", log.joined())
		}
	})
	t.Run("64 by 64 is over the cap", func(t *testing.T) {
		a, _, log := newACLTree(t, dag(64))
		checkLookup(t, a, "10.1.1.1", ACLForward)
		want := fmt.Sprintf("more than %d files included", maxACLFiles)
		if !strings.Contains(log.joined(), want) {
			t.Errorf("want %q in the log; log:\n%s", want, log.joined())
		}
	})
}

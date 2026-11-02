package main

// An `include:` glob is read the way glob(3) reads it, with one difference the gateway needs: a directory it cannot
// list is a failed load (the last good rules stay, a first load forwards everything), never an empty include, and
// that failed glob stays a dependency, so the ACL reloads once the directory can be listed again (issue #3654).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A directory component of an include glob may itself be a pattern; it is expanded, and each directory it names is
// listed, not looked up as a literal path.
func TestACLGlobWildcardDirectoryComponentIsExpanded(t *testing.T) {
	cases := []struct {
		name, include, deny, decoy string
	}{
		{"star", "{dir}/acl.*/*.conf", "acl.1/deny.conf", "acl.f"},
		{"question mark", "{dir}/acl.?/*.conf", "acl.1/deny.conf", "acl.f"},
		{"bracket set", "{dir}/acl.[0-9]/*.conf", "acl.1/deny.conf", "acl.7"},
		{"negated bracket set", "{dir}/acl.[!x]/*.conf", "acl.1/deny.conf", "acl.f"},
		{"nested wildcard directories", "{dir}/a*/b*/*.conf", "a1/b1/deny.conf", "a1/b9"},
		{"quoted path with a space", "\"{dir}/acl d.*/*.conf\"", "acl d.1/deny.conf", "acl d.f"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _, log := newACLTree(t, map[string]string{
				"unbound.conf": "access-control: 10.0.0.0/8 allow\ninclude: " + c.include + "\n",
				c.deny:         "access-control: 10.1.2.3/32 deny\n",
				// A regular file the wildcard directory component also matches: not a directory, so nothing to read
				// and not a failure either.
				c.decoy: "access-control: 10.9.9.9/32 deny\n",
			})
			checkAll(t, a, map[string]ACLAction{
				"10.1.2.3":  ACLDrop,    // the glob's deny, more specific than the allow
				"10.9.9.9":  ACLForward, // the decoy file is not an include
				"192.0.2.1": ACLRefuse,  // no row names it: Refuse, not a failed load's forward-all
			})
			if strings.Contains(log.joined(), "forwarding every query") || strings.Contains(log.joined(), "keeping the last good rules") {
				t.Errorf("a wildcard directory component must load, not fail; log:\n%s", log.joined())
			}
		})
	}
}

// A malformed pattern fails the load wherever the bad bracket is, a directory component included.
func TestACLGlobMalformedDirectoryComponentFailsTheLoad(t *testing.T) {
	a, _, log := newACLTree(t, map[string]string{
		"unbound.conf": "access-control: 10.0.0.0/8 deny\ninclude: {dir}/acl.[/*.conf\n",
	})
	checkAll(t, a, map[string]ACLAction{"10.1.1.1": ACLForward, "192.0.2.1": ACLForward})
	if got := strings.Count(log.joined(), "forwarding every query"); got != 1 {
		t.Errorf("want the malformed pattern logged once as a failed load, got %d; log:\n%s", got, log.joined())
	}
	if a.Refresh() {
		t.Error("Refresh() with nothing changed on a malformed glob: got changed=true, want false")
	}
	if got := strings.Count(log.joined(), "forwarding every query"); got != 1 {
		t.Errorf("an unchanged malformed glob must not log again each Refresh; log:\n%s", log.joined())
	}
}

// A glob directory that is a regular file, or sits below one, is not there: an empty include, as for glob(3). Putting
// a real directory in its place is picked up by the next Refresh.
func TestACLGlobDirectoryThatIsNotADirectoryIsEmptyUntilReplaced(t *testing.T) {
	a, dir, log := newACLTree(t, map[string]string{
		"unbound.conf": "access-control: 10.0.0.0/8 allow\ninclude: {dir}/acl.d/*.conf\ninclude: {dir}/under/sub/*.conf\n",
		"acl.d":        "a file, not a directory\n",
		"under":        "a file, not a directory\n",
	})
	checkAll(t, a, map[string]ACLAction{"10.1.2.3": ACLForward, "10.4.4.4": ACLForward, "192.0.2.1": ACLRefuse})
	if !strings.Contains(log.joined(), "acl: loaded 1 entries from 1 files") || strings.Contains(log.joined(), "forwarding every query") {
		t.Errorf("a glob directory that is a file is an empty include, not a failed load; log:\n%s", log.joined())
	}

	for _, c := range []struct{ file, deny, client string }{
		{"acl.d", "acl.d/deny.conf", "10.1.2.3"},
		{"under", "under/sub/deny.conf", "10.4.4.4"},
	} {
		if err := os.Remove(filepath.Join(dir, c.file)); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, c.deny)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, c.deny), []byte("access-control: "+c.client+"/32 deny\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if !a.Refresh() {
			t.Errorf("Refresh() after %s became a directory: got changed=false, want true", c.file)
		}
		checkLookup(t, a, c.client, ACLDrop)
	}
	checkLookup(t, a, "192.0.2.1", ACLRefuse)
}

// A glob directory that cannot be listed on the first load forwards every client, and says so once. The failed glob
// is still a dependency, so the ACL loads the moment the mode returns, with no other edit to prompt it.
func TestACLGlobDirectoryUnreadableAtStartLoadsOnceTheModeReturns(t *testing.T) {
	if os.Getuid() == 0 {
		if os.Getenv("PFB_ACL_MODE_USER") == "" {
			runAsModeUser(t, "TestACLGlobDirectoryUnreadableAtStartLoadsOnceTheModeReturns")
			return
		}
		becomeModeUser(t)
	}

	dir := confTree(t, map[string]string{
		"unbound.conf":    "access-control: 10.0.0.0/8 allow\ninclude: {dir}/acl.d/*.conf\n",
		"acl.d/deny.conf": "access-control: 10.1.2.3/32 deny\n",
	})
	aclDir := filepath.Join(dir, "acl.d")
	t.Cleanup(func() { _ = os.Chmod(aclDir, 0o755) })
	if err := os.Chmod(aclDir, 0); err != nil {
		t.Fatal(err)
	}
	if f, err := os.Open(aclDir); err == nil {
		f.Close()
		t.Fatal("test premise: mode 000 directory opened; mode bits are not in force")
	}
	log := &capturedLog{}
	a := NewACL(filepath.Join(dir, "unbound.conf"), log.logf)

	checkAll(t, a, map[string]ACLAction{"10.1.2.3": ACLForward, "192.0.2.1": ACLForward}) // before-state: no good load yet
	if a.Refresh() {
		t.Error("Refresh() on a glob directory still unreadable: got changed=true, want false")
	}
	if got := strings.Count(log.joined(), "forwarding every query"); got != 1 {
		t.Errorf("an unchanged permission error must be logged once, got %d; log:\n%s", got, log.joined())
	}

	if err := os.Chmod(aclDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if !a.Refresh() {
		t.Error("Refresh() after the glob directory became readable: got changed=false, want true")
	}
	checkAll(t, a, map[string]ACLAction{
		"10.1.2.3":  ACLDrop,    // the glob's deny, not a forward-all fallback
		"10.9.9.9":  ACLForward, // the broader allow
		"192.0.2.1": ACLRefuse,
	})
}

// After a good load a glob directory that stops being listable keeps the last good rules. Its mode returning alone
// reloads them, and so does a new deny that arrives with it.
func TestACLGlobDirectoryUnreadableAfterGoodLoadReloadsWhenTheModeReturns(t *testing.T) {
	if os.Getuid() == 0 {
		if os.Getenv("PFB_ACL_MODE_USER") == "" {
			runAsModeUser(t, "TestACLGlobDirectoryUnreadableAfterGoodLoadReloadsWhenTheModeReturns")
			return
		}
		becomeModeUser(t)
	}

	a, dir, log := newACLTree(t, map[string]string{
		"unbound.conf":    "access-control: 10.0.0.0/8 allow\ninclude: {dir}/acl.d/*.conf\n",
		"acl.d/deny.conf": "access-control: 10.1.2.3/32 deny\n",
	})
	aclDir := filepath.Join(dir, "acl.d")
	t.Cleanup(func() { _ = os.Chmod(aclDir, 0o755) })
	checkAll(t, a, map[string]ACLAction{"10.1.2.3": ACLDrop, "10.5.5.5": ACLForward, "192.0.2.1": ACLRefuse})

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
	checkAll(t, a, map[string]ACLAction{"10.1.2.3": ACLDrop, "10.5.5.5": ACLForward, "192.0.2.1": ACLRefuse})
	if a.Refresh() {
		t.Error("second Refresh() on an unchanged unreadable glob directory: got changed=true, want false")
	}
	if got := strings.Count(log.joined(), "keeping the last good rules"); got != 1 {
		t.Errorf("an unchanged permission error must be logged once, got %d; log:\n%s", got, log.joined())
	}
	if strings.Contains(log.joined(), "forwarding every query") {
		t.Errorf("an unlistable glob after a good load must not forward every client; log:\n%s", log.joined())
	}

	if err := os.Chmod(aclDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if !a.Refresh() {
		t.Error("Refresh() after chmod 0755 and no other edit: got changed=false, want true")
	}
	if got := strings.Count(log.joined(), "acl: loaded "); got != 2 {
		t.Errorf("restoring the mode must load the glob again, loaded-lines=%d; log:\n%s", got, log.joined())
	}
	checkAll(t, a, map[string]ACLAction{"10.1.2.3": ACLDrop, "10.5.5.5": ACLForward, "192.0.2.1": ACLRefuse})

	if err := os.Chmod(aclDir, 0); err != nil {
		t.Fatal(err)
	}
	if !a.Refresh() {
		t.Error("Refresh() after the glob directory became unreadable again: got changed=false, want true")
	}
	if err := os.Chmod(aclDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aclDir, "more.conf"), []byte("access-control: 10.5.5.5/32 deny\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !a.Refresh() {
		t.Error("Refresh() after the mode returned with a new deny: got changed=false, want true")
	}
	checkAll(t, a, map[string]ACLAction{"10.1.2.3": ACLDrop, "10.5.5.5": ACLDrop, "192.0.2.1": ACLRefuse})
}

// While its directory cannot be listed, a glob is still waited on, so a new directory put in its place is read.
func TestACLGlobDirectoryReplacedWhileUnreadableIsReloaded(t *testing.T) {
	if os.Getuid() == 0 {
		if os.Getenv("PFB_ACL_MODE_USER") == "" {
			runAsModeUser(t, "TestACLGlobDirectoryReplacedWhileUnreadableIsReloaded")
			return
		}
		becomeModeUser(t)
	}

	a, dir, _ := newACLTree(t, map[string]string{
		"unbound.conf":    "access-control: 10.0.0.0/8 allow\ninclude: {dir}/acl.d/*.conf\n",
		"acl.d/deny.conf": "access-control: 10.1.2.3/32 deny\n",
	})
	aclDir := filepath.Join(dir, "acl.d")
	t.Cleanup(func() { _ = os.Chmod(aclDir, 0o755) })
	if err := os.Chmod(aclDir, 0); err != nil {
		t.Fatal(err)
	}
	if f, err := os.Open(aclDir); err == nil {
		f.Close()
		t.Fatal("test premise: mode 000 directory opened; mode bits are not in force")
	}
	a.Refresh()
	checkLookup(t, a, "10.1.2.3", ACLDrop) // before-state: the last good rules

	oldDir := filepath.Join(dir, "acl.old")
	t.Cleanup(func() { _ = os.Chmod(oldDir, 0o755) })
	if err := os.Rename(aclDir, oldDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(aclDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aclDir, "new.conf"), []byte("access-control: 10.2.2.3/32 deny\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !a.Refresh() {
		t.Error("Refresh() after a readable directory replaced the unreadable one: got changed=false, want true")
	}
	checkAll(t, a, map[string]ACLAction{
		"10.2.2.3":  ACLDrop,    // the replacement's deny
		"10.1.2.3":  ACLForward, // the old deny left with the old directory
		"10.5.5.5":  ACLForward,
		"192.0.2.1": ACLRefuse,
	})
}

// An unreadable directory a wildcard directory component names fails the load like any other glob directory, so a
// wildcard does not hide it. A dot directory the wildcard cannot match is never listed, so it never fails anything.
func TestACLGlobUnreadableWildcardMatchedDirectoryKeepsTheLastGoodRules(t *testing.T) {
	if os.Getuid() == 0 {
		if os.Getenv("PFB_ACL_MODE_USER") == "" {
			runAsModeUser(t, "TestACLGlobUnreadableWildcardMatchedDirectoryKeepsTheLastGoodRules")
			return
		}
		becomeModeUser(t)
	}

	// The first * also matches unbound.conf, a regular file.
	a, dir, log := newACLTree(t, map[string]string{
		"unbound.conf":      "access-control: 10.0.0.0/8 allow\ninclude: {dir}/*/*.conf\n",
		"acl.one/deny.conf": "access-control: 10.1.2.3/32 deny\n",
		"acl.two/deny.conf": "access-control: 10.2.2.3/32 deny\n",
		".hid/deny.conf":    "access-control: 10.7.7.7/32 deny\n",
	})
	hidDir, twoDir := filepath.Join(dir, ".hid"), filepath.Join(dir, "acl.two")
	t.Cleanup(func() { _ = os.Chmod(hidDir, 0o755); _ = os.Chmod(twoDir, 0o755) })
	want := map[string]ACLAction{"10.1.2.3": ACLDrop, "10.2.2.3": ACLDrop, "10.7.7.7": ACLForward, "192.0.2.1": ACLRefuse}
	checkAll(t, a, want) // .hid's deny is not read: no wildcard matches a leading dot

	for _, d := range []string{hidDir, twoDir} {
		if err := os.Chmod(d, 0); err != nil {
			t.Fatal(err)
		}
		if f, err := os.Open(d); err == nil {
			f.Close()
			t.Fatal("test premise: mode 000 directory opened; mode bits are not in force")
		}
	}
	if !a.Refresh() {
		t.Error("Refresh() after acl.two became unreadable: got changed=false, want true")
	}
	checkAll(t, a, want) // acl.two's deny stays; a swallowed error would load without it
	if got := strings.Count(log.joined(), "keeping the last good rules"); got != 1 {
		t.Errorf("the unreadable wildcard directory should keep the last good rules once, got %d; log:\n%s", got, log.joined())
	}
	if strings.Contains(log.joined(), ".hid") {
		t.Errorf("a dot directory no wildcard matches must not be listed; log:\n%s", log.joined())
	}

	if err := os.Chmod(twoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if !a.Refresh() {
		t.Error("Refresh() after acl.two became readable: got changed=false, want true")
	}
	if got := strings.Count(log.joined(), "acl: loaded "); got != 2 {
		t.Errorf("restoring the mode must load the glob again, loaded-lines=%d; log:\n%s", got, log.joined())
	}
	checkAll(t, a, want)
}

// A glob directory that can be listed again but now holds nothing is an empty include: the ACL reloads without the
// rows it kept while the directory was unreadable, and does not stay on them for good.
func TestACLGlobDirectoryRestoredWithoutMatchesDropsTheKeptRows(t *testing.T) {
	if os.Getuid() == 0 {
		if os.Getenv("PFB_ACL_MODE_USER") == "" {
			runAsModeUser(t, "TestACLGlobDirectoryRestoredWithoutMatchesDropsTheKeptRows")
			return
		}
		becomeModeUser(t)
	}

	a, dir, log := newACLTree(t, map[string]string{
		"unbound.conf":    "access-control: 10.0.0.0/8 allow\ninclude: {dir}/acl.d/*.conf\n",
		"acl.d/deny.conf": "access-control: 10.1.2.3/32 deny\n",
	})
	aclDir := filepath.Join(dir, "acl.d")
	t.Cleanup(func() { _ = os.Chmod(aclDir, 0o755) })
	if err := os.Chmod(aclDir, 0); err != nil {
		t.Fatal(err)
	}
	if f, err := os.Open(aclDir); err == nil {
		f.Close()
		t.Fatal("test premise: mode 000 directory opened; mode bits are not in force")
	}
	a.Refresh()
	checkLookup(t, a, "10.1.2.3", ACLDrop) // before-state: the last good rules, kept while the directory is unreadable

	if err := os.Chmod(aclDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(aclDir, "deny.conf")); err != nil {
		t.Fatal(err)
	}
	if !a.Refresh() {
		t.Error("Refresh() after the directory became readable and empty: got changed=false, want true")
	}
	checkAll(t, a, map[string]ACLAction{
		"10.1.2.3":  ACLForward, // the deny is gone with its file: the broader allow
		"192.0.2.1": ACLRefuse,
	})
	if got := strings.Count(log.joined(), "acl: loaded "); got != 2 {
		t.Errorf("a readable empty directory must load again, loaded-lines=%d; log:\n%s", got, log.joined())
	}
}

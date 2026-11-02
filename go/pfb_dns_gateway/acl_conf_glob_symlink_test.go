package main

// A symlink loop (a link that names itself, or two that name each other) cannot be listed, but it is no I/O fault: glob(3)
// and the include read before issue #3654 skip it, so the rows that sit beside it stay in force. Failing the load
// instead forwards every client, denied ones included, because a stray link sits in a directory a `*` names.

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestACLGlobSymlinkLoopIsSkippedNotAFailedLoad(t *testing.T) {
	cases := []struct {
		name    string
		include string               // the include under test, read after the anchor include
		files   map[string]string    // extra files below the tree
		links   map[string]string    // link name -> link target, below the tree
		want    map[string]ACLAction // on top of the anchor's deny and the refused stranger
		more    string               // a deny file added later in a directory the include lists; "" when it lists none
	}{
		{
			name:    "self-referencing link beside the wildcard directory level",
			include: "{dir}/*/*.conf",
			files:   map[string]string{"acl.one/deny.conf": "access-control: 10.1.2.3/32 deny\n"},
			links:   map[string]string{"loop": "loop"},
			want:    map[string]ACLAction{"10.1.2.3": ACLDrop},
			more:    "acl.one/more.conf",
		},
		{
			name:    "two links naming each other beside the wildcard directory level",
			include: "{dir}/*/*.conf",
			files:   map[string]string{"acl.one/deny.conf": "access-control: 10.1.2.3/32 deny\n"},
			links:   map[string]string{"a": "b", "b": "a"},
			want:    map[string]ACLAction{"10.1.2.3": ACLDrop},
			more:    "acl.one/more.conf",
		},
		{
			name:    "a loop under each of two wildcard directory levels",
			include: "{dir}/a*/b*/*.conf",
			files:   map[string]string{"a1/b1/deny.conf": "access-control: 10.1.2.3/32 deny\n"},
			links:   map[string]string{"aloop": "aloop", "a1/bloop": "bloop"},
			want:    map[string]ACLAction{"10.1.2.3": ACLDrop},
			more:    "a1/b1/more.conf",
		},
		{
			name:    "glob directory spelled out is a self-referencing link",
			include: "{dir}/loop/*.conf",
			links:   map[string]string{"loop": "loop"},
			want:    map[string]ACLAction{"10.1.2.3": ACLForward}, // an empty include: only the broader allow names it
		},
		{
			name:    "glob directory sits below a self-referencing link",
			include: "{dir}/loop/sub/*.conf",
			links:   map[string]string{"loop": "loop"},
			want:    map[string]ACLAction{"10.1.2.3": ACLForward},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{
				"unbound.conf": "access-control: 10.0.0.0/8 allow\ninclude: {dir}/anchor.conf\ninclude: " + c.include + "\n",
				"anchor.conf":  "access-control: 10.2.2.3/32 deny\n",
			}
			maps.Copy(files, c.files)
			dir := confTree(t, files)
			for name, target := range c.links {
				if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
			}
			for name := range c.links { // checked once every link exists: a pair is a loop only when both are there
				if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, syscall.ELOOP) {
					t.Fatalf("test premise: %s must be a symlink loop, stat err %v", name, err)
				}
			}
			log := &capturedLog{}
			a := NewACL(filepath.Join(dir, "unbound.conf"), log.logf)

			want := map[string]ACLAction{"10.2.2.3": ACLDrop, "192.0.2.1": ACLRefuse}
			maps.Copy(want, c.want)
			loads := 1
			stillServing := func(when string) {
				t.Helper()
				checkAll(t, a, want)
				for _, failure := range []string{"forwarding every query", "keeping the last good rules"} {
					if strings.Contains(log.joined(), failure) {
						t.Errorf("%s: a symlink loop must not fail the load (%q in the log):\n%s", when, failure, log.joined())
					}
				}
				if got := strings.Count(log.joined(), "acl: loaded "); got != loads {
					t.Errorf("%s: loaded-lines=%d, want %d; log:\n%s", when, got, loads, log.joined())
				}
			}
			stillServing("first load")
			if a.Refresh() {
				t.Error("Refresh() with nothing changed beside a symlink loop: got changed=true, want false")
			}
			stillServing("unchanged refresh")

			if c.more != "" { // a new match of the glob is still noticed with the loop in place
				if err := os.WriteFile(filepath.Join(dir, c.more), []byte("access-control: 10.5.5.5/32 deny\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				if !a.Refresh() {
					t.Error("Refresh() after a new file appeared in a listed directory: got changed=false, want true")
				}
				want["10.5.5.5"] = ACLDrop
				loads++
				stillServing("new match")
			}

			rewriteFile(t, filepath.Join(dir, "anchor.conf"), "access-control: 10.2.2.3/32 deny\naccess-control: 10.4.4.4/32 deny\n")
			if !a.Refresh() {
				t.Error("Refresh() after the anchor include changed: got changed=false, want true")
			}
			want["10.4.4.4"] = ACLDrop
			loads++
			stillServing("reload beside the loop") // the rules read before the reload are still there
		})
	}
}

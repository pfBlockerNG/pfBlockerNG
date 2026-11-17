package resources

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

const emfileDirEnv = "PFB_RESOURCES_EMFILE_DIR"

// TestEMFILEChild is the child of TestWriterReadErrorDeletesNothing: with no file descriptor left to open files, every
// writer call must fail with EMFILE. It reports each outcome on the stdout it already holds.
func TestEMFILEChild(t *testing.T) {
	dir := os.Getenv(emfileDirEnv)
	if dir == "" {
		return
	}
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	lim.Cur = 0
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	s := Open(dir)
	_, perr := s.Publish(crashID, []string{"changed"}, nil)
	for name, err := range map[string]error{
		"Publish": perr, "Applied": s.Applied(crashID, 2), "Remove": s.Remove(crashID), "RemovalApplied": s.RemovalApplied(crashID),
	} {
		fmt.Printf("%s %v\n", name, errors.Is(err, syscall.EMFILE))
	}
	os.Exit(0)
}

func TestWriterReadErrorDeletesNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	s := Open(dir)
	if _, err := s.Publish(crashID, []string{"1"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Applied(crashID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(crashID, []string{"2"}, nil); err != nil {
		t.Fatal(err)
	}
	snap := func() map[string]string {
		out := map[string]string{}
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			out[e.Name()] = string(b)
		}
		return out
	}
	before := snap()
	if len(before) != 3 {
		t.Fatalf("setup holds %d files; want the index and two bodies", len(before))
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestEMFILEChild$")
	cmd.Env = append(os.Environ(), emfileDirEnv+"="+dir)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	got := strings.Fields(string(out))
	for _, name := range []string{"Publish", "Applied", "Remove", "RemovalApplied"} {
		if i := slices.Index(got, name); i < 0 || got[i+1] != "true" {
			t.Errorf("%s did not fail with EMFILE; child said %q", name, out)
		}
	}
	if after := snap(); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("a read error changed the store:\n before %v\n after  %v", before, after)
	}
	if r, err := s.Get(crashID, nil); err != nil || !slices.Equal(r.Members, []string{"2"}) {
		t.Fatalf("Get = %+v, %v; want the current body", r, err)
	}
}

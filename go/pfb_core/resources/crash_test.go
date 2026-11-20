package resources

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	crashStepEnv = "PFB_RESOURCES_CRASH_STEP"
	crashDirEnv  = "PFB_RESOURCES_CRASH_DIR"
	reached      = "STEP-REACHED"
	crashID      = "dnsbl/x"
)

var (
	oldBody = []string{"1.1.1.1", "2.2.2.2"}
	newBody = []string{"2.2.2.2", "3.3.3.3"}
)

// bodyLines is the members the store serves for id's generation g.
func bodyLines(t *testing.T, s *Store, id string, g uint64) []string {
	t.Helper()
	f, _, err := s.Body(id, g, PartMembers, 0)
	if err != nil {
		t.Fatalf("Body(%s, %d): %v", id, g, err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		return []string{}
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

// TestCrashChild is the child of TestKilledPublishLeavesAWholeBody: it publishes newBody and blocks at the named step
// until its stdin closes, which is when the parent kills it or dies.
func TestCrashChild(t *testing.T) {
	want := os.Getenv(crashStepEnv)
	if want == "" {
		return
	}
	step = func(name string) {
		if name == want {
			os.Stdout.WriteString(reached + "\n")
			bufio.NewReader(os.Stdin).ReadByte()
		}
	}
	if _, err := Open(os.Getenv(crashDirEnv)).Publish(crashID, slices.Clone(newBody), nil); err != nil {
		t.Fatal(err)
	}
}

func TestKilledPublishLeavesAWholeBody(t *testing.T) {
	for _, tc := range []struct {
		step    string
		want    []string
		gen     uint64
		applied bool // generation 1 is the applied baseline, so the publish writes a delta
	}{
		{"body-written", oldBody, 1, false}, {"body-renamed", oldBody, 1, false}, {"index-renamed", newBody, 2, false},
		{"pruned", newBody, 2, false},
		{"body-renamed", oldBody, 1, true}, {"delta-renamed", oldBody, 1, true}, {"index-renamed", newBody, 2, true},
	} {
		t.Run(fmt.Sprintf("%s applied %v", tc.step, tc.applied), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "store")
			s := Open(dir)
			if _, err := s.Publish(crashID, slices.Clone(oldBody), nil); err != nil {
				t.Fatal(err)
			}
			want := []string{"dnsbl~x.2.body", "index.json"}
			if tc.applied {
				if err := s.Applied(crashID, 1); err != nil {
					t.Fatal(err)
				}
				want = []string{"dnsbl~x.1.body", "dnsbl~x.2.1.add", "dnsbl~x.2.1.remove", "dnsbl~x.2.body", "index.json"}
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$")
			cmd.Env = append(os.Environ(), crashStepEnv+"="+tc.step, crashDirEnv+"="+dir)
			in, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			out, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer in.Close()
			sc, ok := bufio.NewScanner(out), false
			for !ok && sc.Scan() {
				ok = strings.TrimSpace(sc.Text()) == reached
			}
			if !ok {
				t.Fatalf("child never reached %s", tc.step)
			}
			cmd.Process.Kill()
			cmd.Wait()

			r, err := s.Get(crashID, nil)
			if err != nil || r.Generation != tc.gen || !slices.Equal(bodyLines(t, s, crashID, r.Generation), tc.want) {
				t.Fatalf("after kill at %s: Get = gen %d, %v; want gen %d members %v", tc.step, r.Generation, err, tc.gen, tc.want)
			}
			if g, err := s.Publish(crashID, slices.Clone(newBody), nil); err != nil || g != 2 {
				t.Fatalf("Publish after kill = %d, %v; want 2", g, err)
			}
			r, err = s.Get(crashID, nil)
			if err != nil || r.Generation != 2 || !slices.Equal(bodyLines(t, s, crashID, 2), newBody) {
				t.Fatalf("Get after republish = %+v, %v", r, err)
			}
			ents, _ := os.ReadDir(dir)
			var got []string
			for _, e := range ents {
				got = append(got, e.Name())
			}
			slices.Sort(got)
			if !slices.Equal(got, want) {
				t.Fatalf("files = %v; want %v", got, want)
			}
		})
	}
}

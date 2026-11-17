package resources

import (
	"bufio"
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

// TestCrashChild is the child of TestKilledPublishLeavesAWholeBody: it publishes newBody and blocks at the named step
// until its stdin closes, which is when the parent kills it or dies.
func TestCrashChild(t *testing.T) {
	want := os.Getenv(crashStepEnv)
	if want == "" {
		t.Skip("child of TestKilledPublishLeavesAWholeBody")
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
		step string
		want []string
		gen  uint64
	}{
		{"body-written", oldBody, 1}, {"body-renamed", oldBody, 1}, {"index-renamed", newBody, 2}, {"pruned", newBody, 2},
	} {
		t.Run(tc.step, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "store")
			s := Open(dir)
			if _, err := s.Publish(crashID, slices.Clone(oldBody), nil); err != nil {
				t.Fatal(err)
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
			if err != nil || r.Generation != tc.gen || !slices.Equal(r.Members, tc.want) {
				t.Fatalf("after kill at %s: Get = gen %d members %v, %v; want gen %d members %v", tc.step, r.Generation, r.Members, err, tc.gen, tc.want)
			}
			if g, err := s.Publish(crashID, slices.Clone(newBody), nil); err != nil || g != 2 {
				t.Fatalf("Publish after kill = %d, %v; want 2", g, err)
			}
			r, err = s.Get(crashID, nil)
			if err != nil || r.Generation != 2 || !slices.Equal(r.Members, newBody) {
				t.Fatalf("Get after republish = %+v, %v", r, err)
			}
			ents, _ := os.ReadDir(dir)
			var got []string
			for _, e := range ents {
				got = append(got, e.Name())
			}
			slices.Sort(got)
			if want := []string{"dnsbl~x.2.body", "index.json"}; !slices.Equal(got, want) {
				t.Fatalf("files = %v; want %v", got, want)
			}
		})
	}
}

// The Go corpus runner: every scenario in tests/dns_proxy/fixtures/parity against the Go decider, as
// tests/dns_proxy/test_parity_corpus.py runs the Python one.
package decider

import (
	"bytes"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/paritycorpus"
)

// translated lists the families whose decisions the Go decider makes; the others are reported, never passed.
var translated = map[string]bool{"relay": true}

type tally struct{ passed, failed, notImplemented int }

func TestParityCorpus(t *testing.T) {
	fixtures := paritycorpus.Fixtures()
	names, source, err := paritycorpus.LoadFamilies(filepath.Join(fixtures, "families.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name := range translated {
		if _, ok := source[name]; !ok {
			t.Fatalf("translated family %q is not in families.json", name)
		}
	}
	files, err := filepath.Glob(filepath.Join(fixtures, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(files)
	counts := map[string]*tally{}
	for _, name := range names {
		counts[name] = &tally{}
	}
	for _, file := range files {
		if filepath.Base(file) == "families.json" {
			continue
		}
		t.Run(strings.TrimSuffix(filepath.Base(file), ".json"), func(t *testing.T) {
			runScenario(t, file, source, counts)
		})
	}
	for _, name := range names {
		if translated[name] {
			t.Logf("%s: %d passed, %d failed", name, counts[name].passed, counts[name].failed)
		} else {
			t.Logf("%s: %d not implemented", name, counts[name].notImplemented)
		}
	}
}

func runScenario(t *testing.T, file string, families map[string]string, counts map[string]*tally) {
	s, err := paritycorpus.LoadScenario(file, families)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := paritycorpus.WriteModule(dir, s.Module); err != nil {
		t.Fatal(err)
	}
	module, err := boot(dir)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	f := newFrontend(module)
	for i := range s.Cases {
		c := &s.Cases[i]
		skipped := false
		ok := t.Run(c.ID, func(t *testing.T) {
			u := paritycorpus.NewFakeUnbound(s.Upstream)
			// Every case is resolved, translated or not: the decider's per-name memo carries across the cases in file order.
			// The decider gets its own copy of the wire: Python's bytes cannot change under the comparison with the FORWARD.
			answer := f.resolve(bytes.Clone(c.Query.Wire), c.Query.Client, func(w []byte) []byte {
				reply, err := u.Answer(w)
				if err != nil {
					t.Errorf("FakeUnbound: %v", err)
				}
				return reply
			}, c.Query.Transport, "", "")
			if !translated[c.Family] {
				skipped = true
				t.Skipf("family %s: not implemented in Go yet", c.Family)
			}
			for _, line := range paritycorpus.Mismatches(s, c, c.Query.Wire, u, answer) {
				t.Error(line)
			}
		})
		switch {
		case skipped:
			counts[c.Family].notImplemented++
		case ok:
			counts[c.Family].passed++
		default:
			counts[c.Family].failed++
		}
	}
}

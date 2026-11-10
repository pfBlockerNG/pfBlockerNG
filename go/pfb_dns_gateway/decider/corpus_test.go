// The corpus runner, the only one: every scenario in tests/dns_proxy/fixtures/parity against the Go decider.
package decider

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/paritycorpus"
)

func TestParityCorpus(t *testing.T) {
	fixtures := paritycorpus.Fixtures()
	_, source, err := paritycorpus.LoadFamilies(filepath.Join(fixtures, "families.json"))
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(fixtures, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(files)
	for _, file := range files {
		if filepath.Base(file) == "families.json" {
			continue
		}
		t.Run(strings.TrimSuffix(filepath.Base(file), ".json"), func(t *testing.T) {
			runScenario(t, file, source)
		})
	}
	if statsCounted == 0 {
		t.Error("no corpus query was counted in a resolver database: the corpus must run with the statistics on")
	}
}

func runScenario(t *testing.T, file string, families map[string]string) {
	s, err := paritycorpus.LoadScenario(file, families)
	if err != nil {
		t.Fatal(err)
	}
	module, f := bootScenario(t, s)
	for i := range s.Cases {
		c := &s.Cases[i]
		t.Run(c.ID, func(t *testing.T) {
			for _, line := range resolveCase(f, s, c) {
				t.Error(line)
			}
		})
	}
	module.stopDbWorker() // the stop flushes what the worker holds
	if module.sqlite3ResolverCon.Load() {
		checkResolverStats(t, module)
	}
}

// bootScenario boots the decider on the scenario's module directory.
func bootScenario(t *testing.T, s *paritycorpus.Scenario) (*pfbUnbound, *Frontend) {
	t.Helper()
	dir := t.TempDir()
	if err := paritycorpus.WriteModule(dir, s.Module); err != nil {
		t.Fatal(err)
	}
	module, err := boot(dir)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	stopModule(t, module)
	return module, newFrontend(module)
}

// resolveCase resolves the case's query and returns what differs from its expect, one line each. Cases run in file
// order: the decider's per-name memo carries across them.
func resolveCase(f *Frontend, s *paritycorpus.Scenario, c *paritycorpus.Case) []string {
	u := paritycorpus.NewFakeUnbound(s.Upstream)
	var lines []string
	// The decider gets its own copy of the wire: it cannot change under the comparison with the FORWARD.
	answer := f.resolve(bytes.Clone(c.Query.Wire), c.Query.Client, func(w []byte) []byte {
		reply, err := u.Answer(w)
		if err != nil {
			lines = append(lines, "FakeUnbound: "+err.Error())
		}
		return reply
	}, c.Query.Transport, "", "")
	return append(lines, paritycorpus.Mismatches(s, c, c.Query.Wire, u, answer)...)
}

// scratchScenario loads a one-case scenario whose case, in a family no runner list names, relays an unlisted name; expect
// is the case's expect object as JSON.
func scratchScenario(t *testing.T, expect string) *paritycorpus.Scenario {
	t.Helper()
	doc := `{"schema": 4, "description": "scratch",
	"module": {"ini": {"MAIN": {"python_enable": "true"}}, "manifest": {"version": 1, "config": {}, "feeds": []},
		"files": {"pfb_py_raw/feed.txt": ["listed.example"]}},
	"upstream": {"allowed.example. A": ["allowed.example. 300 IN A 192.0.2.77"]},
	"cases": [{"id": "scratch", "family": "never_heard_of", "description": "a relay",
		"query": {"name": "allowed.example.", "type": "A"}, "expect": ` + expect + `}]}`
	path := filepath.Join(t.TempDir(), "scratch.json")
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := paritycorpus.LoadScenario(path, map[string]string{"never_heard_of": "no branch"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestACaseIsComparedWhateverItsFamily(t *testing.T) {
	const relay = `{"decision": "relay", "forwards": ["allowed.example. A"], "rcode": "NOERROR",
		"answer": ["allowed.example. 300 IN A 192.0.2.77"], "authority": []}`
	const wrong = `{"decision": "drop", "forwards": []}`
	for _, row := range []struct {
		name, expect string
		mismatch     bool
	}{{"a right expect passes", relay, false}, {"a wrong expect fails", wrong, true}} {
		t.Run(row.name, func(t *testing.T) {
			s := scratchScenario(t, row.expect)
			_, f := bootScenario(t, s)
			lines := resolveCase(f, s, &s.Cases[0])
			if got := len(lines) > 0; got != row.mismatch {
				t.Errorf("mismatch lines %q: reported %v, want %v", lines, got, row.mismatch)
			}
		})
	}
}

// statsCounted is the queries the corpus's resolver databases counted: the corpus runs with the statistics on.
var statsCounted int64

// checkResolverStats holds the invariant of a database born under the module: the total and the detail rows count the
// same queries.
func checkResolverStats(t *testing.T, m *pfbUnbound) {
	t.Helper()
	total := sqlValue(t, m.pfb.pfbPyResolver, "SELECT totalqueries FROM resolver WHERE row = 0")
	detail := sqlValue(t, m.pfb.pfbPyResolver, "SELECT COALESCE(SUM(count), 0) FROM dns_metric_queries")
	if total != detail {
		t.Errorf("resolver stats: totalqueries = %v, dns_metric_queries sums to %v", total, detail)
	}
	statsCounted += total.(int64)
}

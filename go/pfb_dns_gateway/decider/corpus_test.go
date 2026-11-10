// The corpus runner, the only one: every scenario in tests/dns_proxy/fixtures/parity against the Go decider.
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
var translated = map[string]bool{
	"relay": true, "zone_exact": true, "zone_wildcard": true, "tld_block": true, "tld_allow": true, "psl": true,
	"idn": true, "regex": true, "abp": true, "allow": true, "allow_band": true, "hsts": true, "response": true,
	"qtype": true, "in_addr_arpa": true, "group_policy": true, "cname": true, "noaaaa": true, "safesearch": true,
	"top1m": true, "safesearch_cname": true, "frontend": true, "control": true,
}

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
	if statsCounted == 0 {
		t.Error("no corpus query was counted in a resolver database: the corpus must run with the statistics on")
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
	stopModule(t, module)
	f := newFrontend(module)
	for i := range s.Cases {
		c := s.Cases[i]
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
			for _, line := range paritycorpus.Mismatches(s, &c, c.Query.Wire, u, answer) {
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
	module.stopDbWorker() // the stop flushes what the worker holds
	if module.sqlite3ResolverCon.Load() {
		checkResolverStats(t, module)
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

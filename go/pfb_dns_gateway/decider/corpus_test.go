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
var translated = map[string]bool{
	"relay": true, "zone_exact": true, "zone_wildcard": true, "tld_block": true, "tld_allow": true, "psl": true,
	"idn": true, "regex": true, "abp": true, "allow": true, "allow_band": true, "hsts": true, "response": true,
	"qtype": true, "in_addr_arpa": true, "group_policy": true, "cname": true, "noaaaa": true, "safesearch": true,
	"top1m": true, "safesearch_cname": true, "frontend": true, "control": true,
}

// divergent lists the cases of translated families where the Go decider differs from the Python oracle and the owner
// has not yet signed off a go_expect for them, as "<scenario file stem>/<case id>" -> the #3511 comment that tables the
// row. Such a case is reported as divergent, never as a pass and never skipped, and it must still differ: one that
// starts to match fails until it is taken off this list. A signed-off case carries a go_expect and is never listed.
var divergent = map[string]string{}

type tally struct{ passed, failed, divergent, notImplemented int }

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
			t.Logf("%s: %d passed, %d failed, %d divergent", name, counts[name].passed, counts[name].failed, counts[name].divergent)
		} else {
			t.Logf("%s: %d not implemented", name, counts[name].notImplemented)
		}
	}
	stems := map[string]bool{}
	for _, file := range files {
		stems[strings.TrimSuffix(filepath.Base(file), ".json")] = true
	}
	for key := range divergent {
		if !stems[strings.SplitN(key, "/", 2)[0]] {
			t.Errorf("divergent case %q names no scenario file", key)
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
	stopModule(t, module)
	f := newFrontend(module)
	stem := strings.TrimSuffix(filepath.Base(file), ".json")
	for i := range s.Cases {
		c := s.Cases[i]
		if c.GoExpect != nil { // the owner signed off a Go-specific decision for this case: compare that one
			c.Expect = *c.GoExpect
		}
		skipped := false
		reason, isDivergent := divergent[stem+"/"+c.ID]
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
			lines := paritycorpus.Mismatches(s, &c, c.Query.Wire, u, answer)
			if isDivergent {
				if len(lines) == 0 {
					t.Errorf("listed as divergent (%s) but the Go decider now matches the oracle: take it off the list", reason)
				}
				for _, line := range lines {
					t.Logf("divergent (%s): %s", reason, line)
				}
				return
			}
			for _, line := range lines {
				t.Error(line)
			}
		})
		switch {
		case skipped:
			counts[c.Family].notImplemented++
		case ok && isDivergent:
			counts[c.Family].divergent++
		case ok:
			counts[c.Family].passed++
		default:
			counts[c.Family].failed++
		}
	}
}

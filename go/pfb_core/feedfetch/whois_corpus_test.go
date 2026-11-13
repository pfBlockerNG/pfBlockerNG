package feedfetch_test

// The whois/asn source-resolution corpus (#3974), schema 1: language-neutral JSON cases in
// tests/feedfetch/fixtures/whois that today's shell passes (tests/shell/pfblockerng_whoisconvert_corpus_spec.sh runs the
// real whoisconvert() on each) and Fetcher.Whois passes. Expectations are frozen literals read from whoisconvert() and
// confirmed by the shell run. The feed's name is always CorpusList. A case (unknown keys are refused):
//
//	schema, description   1, and what the case pins.
//	vtype                 "_v4" or "_v6".
//	list                  the comma-separated list whoisconvert() receives.
//	whoisbatchtimeout     optional string: the override as written, valid or not.
//	hosts                 {name: value}, what the host(1) stand-in and the fake lookup answer; a name not listed fails the
//	                      run. A value is [addresses] (answers of both families; a lookup returns its family's), a failure
//	                      kind - "nxdomain" (the lookup fails), "nxdomain-exit0" (the shell stand-in prints the failure
//	                      text and exits 0; the lookup fails), "blocks" (never returns on its own: only the batch deadline
//	                      ends it) - or {addresses, takes}: answers after taking that many seconds of the batch clock.
//	asn_csv               optional string: the file's content (absent: the file does not exist).
//	asn_csv_after_download optional string: what the first-use download writes (absent: it writes nothing).
//	seed, seed_bk         optional strings: the published copy ".orig" and an earlier backup ".bk" before the run.
//	expect                orig (the published bytes), found (at least one entry resolved), fail (".fail" present),
//	                      lookups ["A name" | "AAAA name"] in order, error_log [lines], and optionally
//	                      first_lookup_timeout [lo, hi] (whole seconds the first lookup was bounded by), downloads (the
//	                      first-use downloads attempted; default 0), log_includes [substrings of the update log].
//
// The batch clock is injected, so no case waits and no duration is asserted.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

const whoisCorpusDir = "../../../tests/feedfetch/fixtures/whois"

type whoisExpect struct {
	Orig               string   `json:"orig"`
	Found              bool     `json:"found"`
	Fail               bool     `json:"fail"`
	Lookups            []string `json:"lookups"`
	ErrorLog           []string `json:"error_log"`
	FirstLookupTimeout []int    `json:"first_lookup_timeout"`
	Downloads          int      `json:"downloads"`
	LogIncludes        []string `json:"log_includes"`
}

type whoisCase struct {
	Schema              int                        `json:"schema"`
	Description         string                     `json:"description"`
	VType               string                     `json:"vtype"`
	List                string                     `json:"list"`
	WhoisBatchTimeout   *string                    `json:"whoisbatchtimeout"`
	Hosts               map[string]json.RawMessage `json:"hosts"`
	ASNCSV              *string                    `json:"asn_csv"`
	ASNCSVAfterDownload *string                    `json:"asn_csv_after_download"`
	Seed                *string                    `json:"seed"`
	SeedBk              *string                    `json:"seed_bk"`
	Expect              whoisExpect                `json:"expect"`
}

// whoisHost is one hosts value, decoded.
type whoisHost struct {
	kind  string // "answers", "nxdomain", "nxdomain-exit0" or "blocks"
	addrs []netip.Addr
	takes time.Duration
}

func decodeStrict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func parseWhoisHost(t *testing.T, name string, raw json.RawMessage) whoisHost {
	t.Helper()
	var h whoisHost
	var list []string
	var kind string
	var obj struct {
		Addresses []string `json:"addresses"`
		Takes     int      `json:"takes"`
	}
	switch {
	case decodeStrict(raw, &list) == nil:
		h.kind = "answers"
	case decodeStrict(raw, &kind) == nil:
		h.kind = kind
	case decodeStrict(raw, &obj) == nil:
		h.kind, list, h.takes = "answers", obj.Addresses, time.Duration(obj.Takes)*time.Second
	default:
		t.Fatalf("host %q: unreadable value %s", name, raw)
	}
	for _, a := range list {
		h.addrs = append(h.addrs, netip.MustParseAddr(a))
	}
	return h
}

func TestWhoisCorpus(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(whoisCorpusDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus case under %s (%v)", whoisCorpusDir, err)
	}
	for _, file := range files {
		t.Run(strings.TrimSuffix(filepath.Base(file), ".json"), func(t *testing.T) { runWhoisCase(t, file) })
	}
}

// The coverage matrix of #3974: every row has a case, so a deleted file cannot shrink the corpus unseen.
func TestWhoisCorpusCoversTheMatrix(t *testing.T) {
	for _, name := range []string{
		"domain-v4", "domain-v6", "domain-unresolvable-no-seed", "domain-unresolvable-seed-restored", "as-v4", "as-v6",
		"as-spellings", "as-invalid", "as-no-rows", "asn-csv-missing", "mixed-partial-success", "blank-entries-skipped",
		"budget-expiry-after-first-entry", "budget-override-abc", "budget-override-zero", "budget-override-padded",
		"domain-nxdomain-text-exit-zero", "hostile-shell-metacharacters", "hostile-as-regex-metacharacters",
		"hostile-long-list", "hostile-unicode-domain",
	} {
		if _, err := os.Stat(filepath.Join(whoisCorpusDir, name+".json")); err != nil {
			t.Errorf("the corpus lacks case %s: %v", name, err)
		}
	}
}

func runWhoisCase(t *testing.T, file string) {
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var sc whoisCase
	if err := decodeStrict(raw, &sc); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	if sc.Schema != 1 || sc.Description == "" || (sc.VType != "_v4" && sc.VType != "_v6") {
		t.Fatalf("%s: schema 1 with a description and a vtype required", file)
	}

	const name = "CorpusList"
	base := t.TempDir()
	dir := filepath.Join(base, "feeds")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	asnPath := filepath.Join(base, "asn.csv")
	write := func(path string, content *string) {
		if content == nil {
			return
		}
		if err := os.WriteFile(path, []byte(*content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, name+".orig"), sc.Seed)
	write(filepath.Join(dir, name+".bk"), sc.SeedBk)
	write(asnPath, sc.ASNCSV)

	hosts := map[string]whoisHost{}
	for host, rawHost := range sc.Hosts {
		hosts[host] = parseWhoisHost(t, host, rawHost)
	}
	clock := time.Unix(1_000_000, 0)
	var lookups []string
	first := -1
	downloads := 0
	f := &feedfetch.Fetcher{
		Now:    func() time.Time { return clock },
		ASNCSV: asnPath,
		EnsureASN: func(context.Context) {
			downloads++
			write(asnPath, sc.ASNCSVAfterDownload)
		},
		Lookup: func(ctx context.Context, network, host string) ([]netip.Addr, error) {
			kind := map[string]string{"ip4": "A", "ip6": "AAAA"}[network]
			if kind == "" {
				t.Errorf("lookup on network %q", network)
				return nil, errors.New("unexpected network")
			}
			lookups = append(lookups, kind+" "+host)
			deadline, bounded := ctx.Deadline()
			if !bounded {
				t.Errorf("lookup of %q has no deadline", host)
			} else if first < 0 {
				first = int(math.Round(time.Until(deadline).Seconds()))
			}
			h, ok := hosts[host]
			if !ok {
				t.Errorf("lookup of %q, which the case does not list", host)
				return nil, fmt.Errorf("unlisted host %q", host)
			}
			clock = clock.Add(h.takes)
			switch h.kind {
			case "answers":
				var out []netip.Addr
				for _, a := range h.addrs {
					if (network == "ip4" && a.Is4()) || (network == "ip6" && a.Is6()) {
						out = append(out, a)
					}
				}
				return out, nil
			case "blocks":
				if bounded { // killed at its deadline, so the batch clock reaches it
					clock = clock.Add(time.Until(deadline).Round(time.Second))
				}
				return nil, context.DeadlineExceeded
			}
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		},
	}
	override := ""
	if sc.WhoisBatchTimeout != nil {
		override = *sc.WhoisBatchTimeout
	}
	res := f.Whois(context.Background(), feedfetch.Feed{Dir: dir, Name: name},
		feedfetch.WhoisRequest{List: sc.List, IPv6: sc.VType == "_v6", Budget: feedfetch.WhoisBudget(override)})

	exp := sc.Expect
	if res.Reason != "" {
		t.Errorf("run abandoned: %s", res.Reason)
	}
	if res.Found != exp.Found {
		t.Errorf("Found = %v, want %v", res.Found, exp.Found)
	}
	if res.Failed != exp.Fail {
		t.Errorf("Failed = %v, want %v", res.Failed, exp.Fail)
	}
	got, err := os.ReadFile(filepath.Join(dir, name+".orig"))
	if err != nil {
		t.Errorf("published copy: %v", err)
	} else if string(got) != exp.Orig {
		t.Errorf("published copy\n got %q\nwant %q", got, exp.Orig)
	}
	wantFiles := []string{name + ".orig"}
	if exp.Fail {
		wantFiles = []string{name + ".fail", name + ".orig"}
	}
	var gotFiles []string
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		gotFiles = append(gotFiles, e.Name())
	}
	if !slices.Equal(gotFiles, wantFiles) {
		t.Errorf("files in the feed directory = %q, want %q", gotFiles, wantFiles)
	}
	if !slices.Equal(lookups, exp.Lookups) {
		t.Errorf("lookups\n got %q\nwant %q", lookups, exp.Lookups)
	}
	if downloads != exp.Downloads {
		t.Errorf("asn.csv downloads = %d, want %d", downloads, exp.Downloads)
	}
	if !slices.Equal(res.ErrorLog, exp.ErrorLog) {
		t.Errorf("error log\n got %q\nwant %q", res.ErrorLog, exp.ErrorLog)
	}
	if w := exp.FirstLookupTimeout; len(w) == 2 && (first < w[0] || first > w[1]) {
		t.Errorf("first lookup bounded by %d s, want %d..%d", first, w[0], w[1])
	}
	for _, s := range exp.LogIncludes {
		if !strings.Contains(res.Log, s) {
			t.Errorf("the log lacks %q:\n%s", s, res.Log)
		}
	}
}

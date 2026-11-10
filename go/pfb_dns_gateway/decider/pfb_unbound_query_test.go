// Tests for the Go translation of pfb_unbound.py's ADR-65 query channel (pfb_query_watcher and what it answers with).
// The expected bytes are testdata/pfb_unbound_query_oracle.json, which gen_pfb_unbound_query_oracle.py records from the
// shipped Python watcher: its fixtures (the strata of a snapshot and the settings it is read with) are built here the
// way that script builds them, so a reply that differs by one byte fails.
package decider

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"
)

type queryEntry struct {
	Log       string `json:"log"`
	Index     int    `json:"index"`
	Important bool   `json:"important"`
	Band      int    `json:"band"`
}

type queryFixture struct {
	Settings struct {
		PythonBlocking              bool     `json:"python_blocking"`
		TldAllow                    bool     `json:"tld_allow"`
		TldAllowList                []string `json:"tld_allow_list"`
		DnsblIpv4                   string   `json:"dnsbl_ipv4"`
		DnsblIpv6                   string   `json:"dnsbl_ipv6"`
		PythonIdn                   bool     `json:"python_idn"`
		IdnMode                     string   `json:"idn_mode"`
		PythonIdnBlockMalicious     bool     `json:"python_idn_block_malicious"`
		PythonIdnEscalateSuspicious bool     `json:"python_idn_escalate_suspicious"`
		RegexWarnMs                 float64  `json:"regex_warn_ms"`
		PythonTldSeg                int64    `json:"python_tld_seg"`
		HstsTlds                    []string `json:"hsts_tlds"`
	} `json:"settings"`
	ImportantRules bool                  `json:"important_rules"`
	FeedGroupIndex map[string][2]string  `json:"feed_group_index"`
	Data           map[string]queryEntry `json:"data"`
	Zone           map[string]queryEntry `json:"zone"`
	// White is a JSON true (Python's legacy {name: True}) or an object with wildcard, important and band.
	White          map[string]json.RawMessage `json:"white"`
	Regex          [][]any                    `json:"regex"` // [name, pattern, band, important, group_owner, group_origin]
	AllowRegex     [][]any                    `json:"allow_regex"`
	UserRegex      [][]any                    `json:"user_regex"`
	UserAllowRegex [][]any                    `json:"user_allow_regex"`
	Hsts           []string                   `json:"hsts"`
	GroupEpochs    [][3]string                `json:"group_epochs"`
}

type queryStep struct {
	Op     string  `json:"op"`
	Text   string  `json:"text"`
	B64    string  `json:"b64"`
	Reply  *string `json:"reply"`
	Mode   *string `json:"mode"`
	Stderr string  `json:"stderr"`
}

type queryScenario struct {
	Name      string      `json:"name"`
	Fixture   string      `json:"fixture"`
	ReplyMode string      `json:"reply_mode"`
	Steps     []queryStep `json:"steps"`
}

type queryOracle struct {
	Fixtures  map[string]*queryFixture `json:"fixtures"`
	Scenarios []queryScenario          `json:"scenarios"`
}

func loadQueryOracle(t *testing.T) *queryOracle {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "pfb_unbound_query_oracle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var oracle queryOracle
	if err := json.Unmarshal(data, &oracle); err != nil {
		t.Fatal(err)
	}
	return &oracle
}

func (o *queryOracle) scenario(t *testing.T, name string) *queryScenario {
	t.Helper()
	for i := range o.Scenarios {
		if o.Scenarios[i].Name == name {
			return &o.Scenarios[i]
		}
	}
	t.Fatalf("no oracle scenario %q", name)
	return nil
}

func queryBlock(e queryEntry) *blockEntry {
	return &blockEntry{log: e.Log, index: e.Index, important: e.Important, band: e.Band}
}

func queryRegexDB(t *testing.T, rows [][]any) *regexDB {
	t.Helper()
	db := &regexDB{}
	for _, row := range rows {
		name, pattern := row[0].(string), row[1].(string)
		db.set(name, &regexEntry{
			re: regexp.MustCompile(pattern), band: int(row[2].(float64)), important: row[3].(bool),
			groupOwner: row[4].(string), groupOrigin: row[5].(string),
		})
	}
	return db
}

// snapshot is install() of the generator: the fixture's strata and settings as one snapshot.
func (f *queryFixture) snapshot(t *testing.T) *snapshot {
	t.Helper()
	s := newSnapshot()
	s.settings = &pfbSettings{
		pythonBlocking: f.Settings.PythonBlocking, tldAllow: f.Settings.TldAllow, tldAllowList: f.Settings.TldAllowList,
		dnsblIpv4: f.Settings.DnsblIpv4, dnsblIpv6: f.Settings.DnsblIpv6, pythonIdn: f.Settings.PythonIdn,
		idnMode: IdnMode(f.Settings.IdnMode), pythonIdnBlockMalicious: f.Settings.PythonIdnBlockMalicious,
		pythonIdnEscalateSuspicious: f.Settings.PythonIdnEscalateSuspicious, regexWarnMs: f.Settings.RegexWarnMs,
		pythonTldSeg: f.Settings.PythonTldSeg, hstsTlds: f.Settings.HstsTlds,
	}
	s.importantRules = f.ImportantRules
	for index, fg := range f.FeedGroupIndex {
		n, err := strconv.Atoi(index)
		if err != nil {
			t.Fatal(err)
		}
		s.feedGroupIndexDB[n] = feedGroup{feed: fg[0], group: fg[1]}
	}
	for name, e := range f.Data {
		s.dataDB[name] = queryBlock(e)
	}
	for name, e := range f.Zone {
		s.zoneDB[name] = queryBlock(e)
	}
	for name, raw := range f.White {
		if string(raw) == "true" {
			s.whiteDB[name] = evLegacyWhite(false)
			continue
		}
		var w struct {
			Wildcard, Important bool
			Band                int
		}
		if err := json.Unmarshal(raw, &w); err != nil {
			t.Fatal(err)
		}
		s.whiteDB[name] = evWhite(w.Wildcard, w.Important, w.Band)
	}
	s.regexDB = queryRegexDB(t, f.Regex)
	s.allowRegexDB = queryRegexDB(t, f.AllowRegex)
	s.userRegexDB = queryRegexDB(t, f.UserRegex)
	s.userAllowRegexDB = queryRegexDB(t, f.UserAllowRegex)
	for _, name := range f.Hsts {
		s.hstsDB[name] = struct{}{}
	}
	for _, g := range f.GroupEpochs {
		s.groupEpochs[[2]string{g[0], g[1]}] = g[2]
	}
	return s
}

// A booted module answers a request written to its query channel, whatever python_enable says and with or without an
// ini: Python starts pfb_query_watcher unconditionally. The wait is bounded; the reply is the shipped Python's bytes.
func TestQueryChannelAnswersABootedModule(t *testing.T) {
	oracle := loadQueryOracle(t)
	step := oracle.scenario(t, "verdicts").Steps[0]
	if step.Reply == nil {
		t.Fatal("oracle scenario verdicts has no reply for its first step")
	}
	for _, tc := range []struct{ name, ini string }{
		{"python_enable on", "[MAIN]\npython_enable = true\n"},
		{"python_enable off", "[MAIN]\npython_enable = false\n"},
		{"no ini", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.ini != "" {
				dir = modIniDir(t, tc.ini)
			}
			m := modMust(t, dir)
			m.snapshot.Store(oracle.Fixtures["plain"].snapshot(t))
			channel := filepath.Join(dir, "pfb_py_query")
			if err := os.WriteFile(channel, []byte(step.Text), 0o660); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(3 * RELOAD_POLL_INTERVAL)
			for {
				got, err := os.ReadFile(filepath.Join(dir, "pfb_py_query.reply"))
				if err == nil {
					if string(got) != *step.Reply {
						t.Fatalf("reply = %s, want %s", got, *step.Reply)
					}
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("no reply to %s within %v: %v", step.Text, 3*RELOAD_POLL_INTERVAL, err)
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
}

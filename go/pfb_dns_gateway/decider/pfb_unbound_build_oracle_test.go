// Differential tests of pfb_unbound_build.go against CPython 3.11.
//
// testdata/pfb_unbound_build_oracle.json holds what pfb_unbound.py returned for the inputs below, each row recorded by
// calling the Python function itself (testdata/gen_pfb_unbound_build_oracle.py):
//   - build: a staged module directory (manifest, raw feeds, TOP1M sidecar, PSL authority) and the pfb settings its ini
//     gives, run through dnsbl_build_from_manifest: the golden and manifest-v1 fixtures, every manifest/v1 contract
//     violation, the issue #3648 Group/TOP1M matrix, the issue #2371 feed-at-suffix policy matrix, the ADR-07 corpus
//     and regex fixtures as feed and as Custom_List, the manifest of every parity-corpus module, the TOP1M sidecar and
//     the retired inline top1m_list;
//   - user_regex_entries, compile, reader, top1m, stats: _load_user_regex_entries, the two regex compilers, the feed
//     line reader, the TOP1M sidecar reader and dnsbl_emit_reject_stats;
//   - decode, b64, realpath: the stdlib behaviours those emulate (bytes.decode("utf-8", "replace"),
//     base64.b64decode(validate=True), os.path.realpath and _dnsbl_path_within_base over a tree of links).
//
// Divergences recorded here are deliberate: the text of a JSON, UTF-8 or PSL error is the language's own, so the
// comparison cuts those messages after the path they name.
package decider

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
)

type bldEntry struct {
	Log         string    `json:"log"`
	Index       int       `json:"index"`
	Important   bool      `json:"important"`
	Band        int       `json:"band"`
	GroupOwner  *string   `json:"group_owner"`
	GroupOrigin *string   `json:"group_origin"`
	Top1m       *[]string `json:"top1m"`
	Fallback    *bldEntry `json:"top1m_fallback"`
}

type bldWhite struct {
	Wildcard  bool `json:"wildcard"`
	Important bool `json:"important"`
	Band      int  `json:"band"`
	Index     *int `json:"index"`
}

type bldWant struct {
	DataDB           map[string]bldEntry          `json:"data_db"`
	ZoneDB           map[string]bldEntry          `json:"zone_db"`
	FeedGroupIndexDB map[string]map[string]string `json:"feed_group_index_db"`
	WhiteDB          map[string]bldWhite          `json:"white_db"`
	Counts           int                          `json:"counts"`
	RegexDB          [][2]json.RawMessage         `json:"regex_db"`
	AllowRegexDB     [][2]json.RawMessage         `json:"allow_regex_db"`
	UserRegexDB      [][2]json.RawMessage         `json:"user_regex_db"`
	UserAllowRegexDB [][2]json.RawMessage         `json:"user_allow_regex_db"`
	ImportantRules   bool                         `json:"important_rules"`
	RegexCount       int                          `json:"regex_count"`
	Rejects          [][3]json.RawMessage         `json:"rejects"`
	PslRules         map[string][]string          `json:"psl_rules"`
	BuiltinLogFlag   string                       `json:"builtin_log_flag"`
}

type bldBuildRow struct {
	Name        string            `json:"name"`
	Files       map[string]string `json:"files"`
	Manifest    any               `json:"manifest"`
	ManifestB64 *string           `json:"manifest_b64"`
	Pfb         map[string]any    `json:"pfb"`
	SidecarMode *string           `json:"sidecar_mode"`
	Want        *bldWant          `json:"want"`
	Ledger      []string          `json:"ledger"`
	Stderr      string            `json:"stderr"`
}

type bldRegexWant struct {
	Pattern     string  `json:"pattern"`
	Important   bool    `json:"important"`
	Band        int     `json:"band"`
	GroupOwner  *string `json:"group_owner"`
	GroupOrigin *string `json:"group_origin"`
}

type bldRuleSpec struct {
	Pattern   string `json:"pattern"`
	Kind      string `json:"kind"`
	Feed      string `json:"feed"`
	Group     string `json:"group"`
	Band      int    `json:"band"`
	Important bool   `json:"important"`
}

type bldOracleFile struct {
	Build            []bldBuildRow `json:"build"`
	UserRegexEntries []struct {
		Name   string      `json:"name"`
		Ini    string      `json:"ini"`
		Want   [][2]string `json:"want"`
		Stderr string      `json:"stderr"`
	} `json:"user_regex_entries"`
	Decode []struct {
		Hex  string `json:"hex"`
		Want []rune `json:"want"`
	} `json:"decode"`
	B64 []struct {
		S   string `json:"s"`
		Ok  bool   `json:"ok"`
		Hex string `json:"hex"`
	} `json:"b64"`
	Compile []struct {
		Name      string               `json:"name"`
		Kind      string               `json:"kind"`
		Rules     []bldRuleSpec        `json:"rules"`
		Entries   [][2]string          `json:"entries"`
		StaticCap bool                 `json:"static_cap"`
		RegexCap  bool                 `json:"regex_cap"`
		WantDB    [][2]json.RawMessage `json:"want_db"`
		Admitted  int                  `json:"admitted"`
		Stderr    string               `json:"stderr"`
	} `json:"compile"`
	Reader []struct {
		Name string   `json:"name"`
		Hex  string   `json:"hex"`
		Want []string `json:"want"`
	} `json:"reader"`
	Top1m []struct {
		Name  string   `json:"name"`
		Hex   string   `json:"hex"`
		Want  []string `json:"want"`
		Error *string  `json:"error"`
	} `json:"top1m"`
	Stats []struct {
		Name  string               `json:"name"`
		Tally [][3]json.RawMessage `json:"tally"`
		Ok    bool                 `json:"ok"`
		Want  []map[string]any     `json:"want"`
	} `json:"stats"`
	Realpath []struct {
		Probe  string `json:"probe"`
		Want   string `json:"want"`
		Base   string `json:"base"`
		Within *bool  `json:"within"`
	} `json:"realpath"`
	Tree [][3]*string `json:"tree"`
}

var (
	bldOracleOnce sync.Once
	bldOracleData bldOracleFile
	bldOracleErr  error
)

func bldOracle(t *testing.T) *bldOracleFile {
	t.Helper()
	bldOracleOnce.Do(func() {
		var data []byte
		if data, bldOracleErr = os.ReadFile(filepath.Join("testdata", "pfb_unbound_build_oracle.json")); bldOracleErr == nil {
			bldOracleErr = json.Unmarshal(data, &bldOracleData)
		}
	})
	if bldOracleErr != nil {
		t.Fatal(bldOracleErr)
	}
	return &bldOracleData
}

func bldHex(t *testing.T, s string) []byte {
	t.Helper()
	data, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// bldCut shortens a message whose tail is the language's own error text to the part Python and Go share.
func bldCut(line string) string {
	for _, marker := range []string{
		"Failed to load DNSBL manifest '", // ... '<path>': <json / utf-8 error>
		"PSL authority '",                 // ... '<path>': <os / utf-8 error>
		"Failed to decode MAIN.regex_list: ",
	} {
		if i := strings.Index(line, marker); i >= 0 {
			rest := line[i+len(marker):]
			switch marker {
			case "Failed to decode MAIN.regex_list: ":
				if strings.HasPrefix(rest, "'") { // 'utf-8' / 'ascii' codec errors: the language's own text
					return line[:i+len(marker)]
				}
			default:
				if j := strings.Index(rest, "': "); j >= 0 {
					return line[:i+len(marker)+j+3]
				}
			}
		}
	}
	return line
}

// bldPyLines splits Python's stderr into the lines of its writes (some end without a newline).
func bldPyLines(stderr string) []string {
	var lines []string
	for _, piece := range strings.Split(strings.ReplaceAll(stderr, "[pfBlockerNG]: ", "\n[pfBlockerNG]: "), "\n") {
		if piece != "" {
			lines = append(lines, bldCut(piece))
		}
	}
	return lines
}

// bldGoLines is what the Go side logged, one entry per log call, with the shim's "pfb_dns_proxy <level>: " dropped.
func bldGoLines(out *bytes.Buffer, dir string) []string {
	var lines []string
	for _, line := range strings.Split(out.String(), "\n") {
		if line == "" {
			continue
		}
		if i := strings.Index(line, ": "); i >= 0 && strings.HasPrefix(line, "pfb_dns_proxy ") {
			line = line[i+2:]
		}
		if dir != "" {
			line = strings.ReplaceAll(line, dir, "<DIR>")
		}
		lines = append(lines, bldCut(line))
	}
	return lines
}

func bldCaptureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var out bytes.Buffer
	previous := logOutput
	logOutput = &out
	t.Cleanup(func() { logOutput = previous })
	return &out
}

// bldStage writes the row's module directory, the way the generator staged it.
func bldStage(t *testing.T, row *bldBuildRow) (dir, manifestPath string) {
	t.Helper()
	dir = t.TempDir()
	for rel, encoded := range row.Files {
		data, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if row.SidecarMode != nil {
		sidecar := filepath.Join(dir, "pfb_py_top1m.txt")
		switch *row.SidecarMode {
		case "symlink":
			if err := os.Rename(sidecar, filepath.Join(dir, "elsewhere.txt")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(dir, "elsewhere.txt"), sidecar); err != nil {
				t.Fatal(err)
			}
		case "directory":
			if err := os.Remove(sidecar); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(sidecar, 0o755); err != nil {
				t.Fatal(err)
			}
		case "absent":
			if err := os.Remove(sidecar); err != nil {
				t.Fatal(err)
			}
		}
	}
	manifestPath = filepath.Join(dir, "pfb_py_sources.json")
	switch {
	case row.ManifestB64 != nil:
		data, err := base64.StdEncoding.DecodeString(*row.ManifestB64)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manifestPath, data, 0o644); err != nil {
			t.Fatal(err)
		}
	case row.Manifest != nil:
		data, err := json.Marshal(row.Manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manifestPath, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir, manifestPath
}

// bldModule is the module the row's pfb settings describe; its ledger lives in the module directory.
func bldModule(dir string, pfb map[string]any) *pfbUnbound {
	flag := func(key string) bool { value, _ := pfb[key].(bool); return value }
	text := func(key string) string { value, _ := pfb[key].(string); return value }
	m := &pfbUnbound{}
	m.pfb.pythonTldWildcard = flag("python_tld_wildcard")
	m.pfb.tldAllow = flag("tld_allow")
	m.pfb.pslIncludePrivate = flag("psl_include_private")
	m.pfb.pslFeedPrivatePolicy = text("psl_feed_private_policy")
	m.pfb.pslFeedIcannPolicy = text("psl_feed_icann_policy")
	m.pfb.regexCap = flag("regex_cap")
	if psl := text("pfb_py_psl"); psl != "" {
		m.pfb.pfbPyPsl = filepath.Join(dir, psl)
	}
	m.pfb.pfbPyStatus = filepath.Join(dir, "pfb_py_status.json")
	return m
}

func bldLedger(t *testing.T, dir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "pfb_py_status.json"))
	if err != nil {
		return nil
	}
	var entries []struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("the ledger %q is not JSON: %v", data, err)
	}
	var messages []string
	for _, entry := range entries {
		messages = append(messages, bldCut(strings.ReplaceAll(entry.Message, dir, "<DIR>")))
	}
	return messages
}

func bldEntryDiff(got *blockEntry, want bldEntry) string {
	var problems []string
	if got.log != want.Log || got.index != want.Index || got.important != want.Important || got.band != want.Band {
		problems = append(problems, fmt.Sprintf("log/index/important/band = %q/%d/%v/%d, want %q/%d/%v/%d",
			got.log, got.index, got.important, got.band, want.Log, want.Index, want.Important, want.Band))
	}
	if got.hasGroupOwner != (want.GroupOwner != nil) || want.GroupOwner != nil && got.groupOwner != *want.GroupOwner {
		problems = append(problems, fmt.Sprintf("group_owner = (%v, %q), want %v", got.hasGroupOwner, got.groupOwner, want.GroupOwner))
	}
	if got.hasGroupOrigin != (want.GroupOrigin != nil) || want.GroupOrigin != nil && got.groupOrigin != *want.GroupOrigin {
		problems = append(problems, fmt.Sprintf("group_origin = (%v, %q), want %v", got.hasGroupOrigin, got.groupOrigin, want.GroupOrigin))
	}
	if got.hasTop1m != (want.Top1m != nil) {
		problems = append(problems, fmt.Sprintf("top1m present = %v, want %v", got.hasTop1m, want.Top1m != nil))
	} else if want.Top1m != nil {
		names := make([]string, 0, len(got.top1m))
		for name := range got.top1m {
			names = append(names, name)
		}
		slices.Sort(names)
		if !slices.Equal(names, *want.Top1m) {
			problems = append(problems, fmt.Sprintf("top1m = %q, want %q", names, *want.Top1m))
		}
	}
	switch {
	case (got.top1mFallback != nil) != (want.Fallback != nil):
		problems = append(problems, fmt.Sprintf("top1m_fallback present = %v, want %v", got.top1mFallback != nil, want.Fallback != nil))
	case want.Fallback != nil:
		if diff := bldEntryDiff(got.top1mFallback, *want.Fallback); diff != "" {
			problems = append(problems, "top1m_fallback: "+diff)
		}
	}
	return strings.Join(problems, "; ")
}

func bldRegexDiff(label string, got *regexDB, want [][2]json.RawMessage) string {
	if got.len() != len(want) {
		return fmt.Sprintf("%s has %d rules, want %d", label, got.len(), len(want))
	}
	i := 0
	for name, entry := range got.items() {
		var wantName string
		var wantEntry bldRegexWant
		if err := json.Unmarshal(want[i][0], &wantName); err != nil {
			return err.Error()
		}
		if err := json.Unmarshal(want[i][1], &wantEntry); err != nil {
			return err.Error()
		}
		i++
		pattern := strings.TrimPrefix(entry.re.String(), "(?i)")
		if name != wantName || pattern != wantEntry.Pattern || entry.important != wantEntry.Important || entry.band != wantEntry.Band ||
			wantEntry.GroupOwner == nil || entry.groupOwner != *wantEntry.GroupOwner || wantEntry.GroupOrigin == nil || entry.groupOrigin != *wantEntry.GroupOrigin {
			return fmt.Sprintf("%s rule #%d = %q %q important=%v band=%d owner=%q origin=%q, want %q %q important=%v band=%d owner=%v origin=%v",
				label, i, name, pattern, entry.important, entry.band, entry.groupOwner, entry.groupOrigin,
				wantName, wantEntry.Pattern, wantEntry.Important, wantEntry.Band, wantEntry.GroupOwner, wantEntry.GroupOrigin)
		}
	}
	return ""
}

// bldResultDiff is every way the build result differs from what Python built, "" for none.
func bldResultDiff(got *buildResult, want *bldWant) string {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	for label, pair := range map[string]struct {
		got  map[string]*blockEntry
		want map[string]bldEntry
	}{"data_db": {got.dataDB, want.DataDB}, "zone_db": {got.zoneDB, want.ZoneDB}} {
		if len(pair.got) != len(pair.want) {
			add("%s has %d entries, want %d", label, len(pair.got), len(pair.want))
		}
		for key, wantEntry := range pair.want {
			gotEntry, ok := pair.got[key]
			if !ok {
				add("%s lacks %q", label, key)
			} else if diff := bldEntryDiff(gotEntry, wantEntry); diff != "" {
				add("%s[%q]: %s", label, key, diff)
			}
		}
	}
	if len(got.feedGroupIndexDB) != len(want.FeedGroupIndexDB) {
		add("feed_group_index_db has %d entries, want %d", len(got.feedGroupIndexDB), len(want.FeedGroupIndexDB))
	}
	for key, wantRow := range want.FeedGroupIndexDB {
		var idx int
		fmt.Sscanf(key, "%d", &idx)
		if row, ok := got.feedGroupIndexDB[idx]; !ok || row.feed != wantRow["feed"] || row.group != wantRow["group"] {
			add("feed_group_index_db[%s] = %+v, want %v", key, row, wantRow)
		}
	}
	if len(got.whiteDB) != len(want.WhiteDB) {
		add("white_db has %d entries, want %d", len(got.whiteDB), len(want.WhiteDB))
	}
	for key, wantRow := range want.WhiteDB {
		row, ok := got.whiteDB[key]
		if !ok || row.legacy || row.wildcard != wantRow.Wildcard || row.important != wantRow.Important || !row.hasBand || row.band != wantRow.Band ||
			row.hasIndex != (wantRow.Index != nil) || wantRow.Index != nil && row.index != *wantRow.Index {
			add("white_db[%q] = %+v, want %+v", key, row, wantRow)
		}
	}
	if got.counts != want.Counts {
		add("counts = %d, want %d", got.counts, want.Counts)
	}
	for label, pair := range map[string]struct {
		got  *regexDB
		want [][2]json.RawMessage
	}{"regex_db": {got.regexDB, want.RegexDB}, "allow_regex_db": {got.allowRegexDB, want.AllowRegexDB},
		"user_regex_db": {got.userRegexDB, want.UserRegexDB}, "user_allow_regex_db": {got.userAllowRegexDB, want.UserAllowRegexDB}} {
		if diff := bldRegexDiff(label, pair.got, pair.want); diff != "" {
			add("%s", diff)
		}
	}
	if got.importantRules != want.ImportantRules {
		add("important_rules = %v, want %v", got.importantRules, want.ImportantRules)
	}
	if got.regexCount != want.RegexCount {
		add("regex_count = %d, want %d", got.regexCount, want.RegexCount)
	}
	if got.builtinLogFlag != want.BuiltinLogFlag {
		add("builtin_log_flag = %q, want %q", got.builtinLogFlag, want.BuiltinLogFlag)
	}
	wantRejects := map[[2]string]map[string]int{}
	for _, row := range want.Rejects {
		var feed, group string
		var counts map[string]int
		_ = json.Unmarshal(row[0], &feed)
		_ = json.Unmarshal(row[1], &group)
		_ = json.Unmarshal(row[2], &counts)
		wantRejects[[2]string{feed, group}] = counts
	}
	if !reflect.DeepEqual(map[[2]string]map[string]int(got.rejects), wantRejects) && !(len(got.rejects) == 0 && len(wantRejects) == 0) {
		add("rejects = %v, want %v", got.rejects, wantRejects)
	}
	if want.PslRules != nil {
		gotRules := map[string][]string{
			"icann_exact": got.pslRules.icannExact, "icann_wildcard": got.pslRules.icannWildcard, "icann_exception": got.pslRules.icannException,
			"private_exact": got.pslRules.privateExact, "private_wildcard": got.pslRules.privateWildcard, "private_exception": got.pslRules.privateException,
		}
		for name, wantList := range want.PslRules {
			if !slices.Equal(gotRules[name], wantList) {
				add("psl_rules.%s = %q, want %q", name, gotRules[name], wantList)
			}
		}
	}
	return strings.Join(problems, "\n")
}

func TestDnsblBuildFromManifestMatchesPython(t *testing.T) {
	rows := bldOracle(t).Build
	if len(rows) < 400 {
		t.Fatalf("the oracle holds %d build rows, want the full matrix", len(rows))
	}
	for i := range rows {
		row := &rows[i]
		t.Run(row.Name, func(t *testing.T) {
			dir, manifestPath := bldStage(t, row)
			out := bldCaptureLog(t)
			m := bldModule(dir, row.Pfb)

			got := m.dnsblBuildFromManifest(manifestPath)

			if (got == nil) != (row.Want == nil) {
				t.Fatalf("dnsblBuildFromManifest returned %v, want nil = %v; ledger %q, log %q", got, row.Want == nil, bldLedger(t, dir), bldGoLines(out, dir))
			}
			if got != nil {
				if diff := bldResultDiff(got, row.Want); diff != "" {
					t.Errorf("the build differs from Python's:\n%s", diff)
				}
			}
			var wantLedger []string
			for _, message := range row.Ledger {
				wantLedger = append(wantLedger, bldCut(message))
			}
			if gotLedger := bldLedger(t, dir); !slices.Equal(gotLedger, wantLedger) {
				t.Errorf("ledger = %q, want %q", gotLedger, wantLedger)
			}
			wantLog := bldPyLines(row.Stderr)
			if gotLog := bldGoLines(out, dir); !slices.Equal(gotLog, wantLog) && !(len(gotLog) == 0 && len(wantLog) == 0) {
				t.Errorf("log lines =\n%q\nwant\n%q", gotLog, wantLog)
			}
		})
	}
}

func TestDecodeReplaceMatchesPython(t *testing.T) {
	rows := bldOracle(t).Decode
	for _, row := range rows {
		data := bldHex(t, row.Hex)
		if got := []rune(decodeReplace(data)); !slices.Equal(got, row.Want) {
			t.Fatalf("decodeReplace(% x) = %U, want %U", data, got, row.Want)
		}
	}
	if len(rows) < 2000 {
		t.Fatalf("only %d decode rows", len(rows))
	}
}

func TestB64DecodeValidateMatchesPython(t *testing.T) {
	for _, row := range bldOracle(t).B64 {
		got, err := b64decodeValidate(row.S)
		if (err == nil) != row.Ok {
			t.Fatalf("b64decodeValidate(%q) = (%x, %v), want ok = %v", row.S, got, err, row.Ok)
		}
		if row.Ok && hex.EncodeToString(got) != row.Hex {
			t.Fatalf("b64decodeValidate(%q) = %x, want %s", row.S, got, row.Hex)
		}
	}
}

func TestLoadUserRegexEntriesMatchesPython(t *testing.T) {
	for _, row := range bldOracle(t).UserRegexEntries {
		t.Run(row.Name, func(t *testing.T) {
			config := newConfigParser()
			if err := config.readString(row.Ini, "<ini>"); err != nil {
				t.Fatal(err)
			}
			out := bldCaptureLog(t)

			got := loadUserRegexEntries(config)

			var gotRows [][2]string
			for _, entry := range got {
				gotRows = append(gotRows, [2]string{entry.name, entry.pattern})
			}
			if !reflect.DeepEqual(gotRows, row.Want) && !(len(gotRows) == 0 && len(row.Want) == 0) {
				t.Errorf("entries = %q, want %q", gotRows, row.Want)
			}
			if gotLog, wantLog := bldGoLines(out, ""), bldPyLines(row.Stderr); !slices.Equal(gotLog, wantLog) && !(len(gotLog) == 0 && len(wantLog) == 0) {
				t.Errorf("log lines = %q, want %q", gotLog, wantLog)
			}
		})
	}
}

func TestRegexCompilersMatchPython(t *testing.T) {
	for _, row := range bldOracle(t).Compile {
		t.Run(row.Name, func(t *testing.T) {
			out := bldCaptureLog(t)
			var db *regexDB
			if row.Kind == "feed" {
				rules := make([]regexRule, len(row.Rules))
				for i, spec := range row.Rules {
					rules[i] = regexRule{pattern: spec.Pattern, kind: spec.Kind, band: spec.Band, important: spec.Important,
						provenance: RULE_PROV_FEED, feed: spec.Feed, group: spec.Group, log: "1"}
				}
				var admitted int
				db, admitted = dnsblCompileRegexRules(rules, row.StaticCap)
				if admitted != row.Admitted {
					t.Errorf("admitted = %d, want %d", admitted, row.Admitted)
				}
			} else {
				entries := make([]userRegexEntry, len(row.Entries))
				for i, pair := range row.Entries {
					entries[i] = userRegexEntry{pair[0], pair[1]}
				}
				db = dnsblCompileUserRegex(entries, row.RegexCap)
			}
			if diff := bldRegexDiff("db", db, row.WantDB); diff != "" {
				t.Error(diff)
			}
			if gotLog, wantLog := bldGoLines(out, ""), bldPyLines(row.Stderr); !slices.Equal(gotLog, wantLog) && !(len(gotLog) == 0 && len(wantLog) == 0) {
				t.Errorf("log lines =\n%q\nwant\n%q", gotLog, wantLog)
			}
		})
	}
}

func TestDnsblFileLineReaderMatchesPython(t *testing.T) {
	for _, row := range bldOracle(t).Reader {
		t.Run(row.Name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "feed.raw"), bldHex(t, row.Hex), 0o644); err != nil {
				t.Fatal(err)
			}
			var got []string
			for line, err := range dnsblFileLineReader(dir, true)("feed.raw") {
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, line)
			}
			if !slices.Equal(got, row.Want) && !(len(got) == 0 && len(row.Want) == 0) {
				t.Errorf("lines = %q, want %q", got, row.Want)
			}
		})
	}
}

func TestDnsblFixedTop1mLinesMatchesPython(t *testing.T) {
	for _, row := range bldOracle(t).Top1m {
		t.Run(row.Name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "pfb_py_top1m.txt"), bldHex(t, row.Hex), 0o644); err != nil {
				t.Fatal(err)
			}
			var got []string
			var gotErr error
			for line, err := range dnsblFixedTop1mLines(dir) {
				if err != nil {
					gotErr = err
					break
				}
				got = append(got, line)
			}
			if row.Error != nil {
				want := strings.ReplaceAll(*row.Error, "<DIR>", dir)
				if gotErr == nil || gotErr.Error() != want {
					t.Errorf("error = %v, want %q", gotErr, want)
				}
				return
			}
			if gotErr != nil {
				t.Fatal(gotErr)
			}
			if !slices.Equal(got, row.Want) && !(len(got) == 0 && len(row.Want) == 0) {
				t.Errorf("lines = %q, want %q", got, row.Want)
			}
		})
	}
}

func TestDnsblEmitRejectStatsMatchesPython(t *testing.T) {
	for _, row := range bldOracle(t).Stats {
		t.Run(row.Name, func(t *testing.T) {
			tally := rejectTally{}
			for _, pair := range row.Tally {
				var feed, group string
				var counts map[string]int
				_ = json.Unmarshal(pair[0], &feed)
				_ = json.Unmarshal(pair[1], &group)
				_ = json.Unmarshal(pair[2], &counts)
				tally[[2]string{feed, group}] = counts
			}
			path := filepath.Join(t.TempDir(), "stats.json")
			if ok := dnsblEmitRejectStats(path, tally); ok != row.Ok {
				t.Fatalf("dnsblEmitRejectStats = %v, want %v", ok, row.Ok)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var got []map[string]any
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("%q is not a JSON array: %v", data, err)
			}
			if !reflect.DeepEqual(got, row.Want) {
				t.Errorf("rows = %v, want %v", got, row.Want)
			}
			if _, err := os.Stat(path + ".tmp"); err == nil {
				t.Error("the temp file was left behind")
			}
		})
	}
}

// bldTree makes the oracle's tree of files, directories and links in a fresh directory.
func bldTree(t *testing.T, tree [][3]*string) (dir, realDir string) {
	t.Helper()
	dir = t.TempDir()
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range tree {
		kind, rel := *row[0], *row[1]
		path := filepath.Join(dir, rel)
		var err error
		switch kind {
		case "dir":
			err = os.MkdirAll(path, 0o755)
		case "file":
			err = os.WriteFile(path, []byte("x"), 0o644)
		default:
			err = os.Symlink(strings.ReplaceAll(*row[2], "@TMP@", dir), path)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return dir, realDir
}

func bldResolveProbe(dir, spec string) string {
	if strings.HasPrefix(spec, "@TMP@") || strings.HasPrefix(spec, "/") {
		return strings.ReplaceAll(spec, "@TMP@", dir)
	}
	return pyJoin(dir, spec)
}

func TestPyRealpathAndPathWithinBaseMatchPython(t *testing.T) {
	oracle := bldOracle(t)
	dir, realDir := bldTree(t, oracle.Tree)
	checked := 0
	for _, row := range oracle.Realpath {
		if row.Within == nil {
			got := strings.ReplaceAll(strings.ReplaceAll(pyRealpath(bldResolveProbe(dir, row.Probe)), realDir, "<DIR>"), dir, "<DIR>")
			if got != row.Want {
				t.Errorf("pyRealpath(%q) = %q, want %q", row.Probe, got, row.Want)
			}
		} else if got := dnsblPathWithinBase(bldResolveProbe(dir, row.Probe), bldResolveProbe(dir, row.Base)); got != *row.Within {
			t.Errorf("dnsblPathWithinBase(%q, base %q) = %v, want %v", row.Probe, row.Base, got, *row.Within)
		}
		checked++
	}
	if checked < 300 {
		t.Fatalf("only %d path rows", checked)
	}
}

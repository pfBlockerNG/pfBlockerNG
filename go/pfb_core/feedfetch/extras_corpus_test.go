package feedfetch_test

// The Extras parity corpus (#3978), schema 1: JSON scenarios in tests/extras/fixtures/parity that today's PHP passes
// (tests/php/ExtrasParityCorpusTest.php drives pfblockerng_download_extras()) and this package passes. A scenario
// (unknown keys are refused):
//
//	schema       1.
//	description  what the scenario pins.
//	hosts        {name: [addresses]}: the vetting resolver; every connection goes to 127.0.0.1.
//	servers      [name]: HTTP servers on 127.0.0.1; "{port:<name>}" expands to a server's port.
//	settings     {maxmind_account, maxmind_key, asn_token, sanity, top1m_source, top1m_token, top1m_inclusions,
//	             top1m_count}: what the extras and DNSBL projections hold (top1m_source is the provider the TOP1M row
//	             names; top1m_inclusions the TLD inclusions, comma-separated and passed as given; top1m_count defaults to 1000).
//	ledger       the open message of the TOP1M download ledger entry before the first step; absent when none is open.
//	seed         {"db/<path>" or "share/<path>": content or {"b64": bytes}}: files before the first step.
//	routes       {server: {path: route}}: what each server answers (the feed-transfer corpus's route keys).
//	steps        [step]: run in order on the same directories.
//
// A step: run ("download"; "dcc": the cron verb whose TOP1M row runs the change detector first; or "bls": the verb that
// prints the Blacklist report), extras ([{url, file_dwn, file, folder ("db" or "share"), type, provider on a top1m row,
// and name, username and password on a blacklist row}]), routes and seed (replacing or
// adding before the step), expect and, where Core deliberately differs (an owner decision), old_expect (today's PHP answer,
// which only the PHP runner reads): ok, maxmind_error, replaced (paths that must hold a new file afterwards, even when its
// bytes are the same), files ({path: content, {"b64": bytes}, or null when nothing is there; any other entry reads
// "<not a regular file>"}: only the paths named), and requests (what the servers recorded; host and query only where
// named), top1m_changed (TOP1M changed under dcc), and ledger (the TOP1M download ledger's open message after the step, or
// null when none is open; checked only where named), report (the Blacklist report the bls verb prints, a line per
// blacklist row; checked only where named), and reason, stage and detected (the refusal of the step's last refused row,
// checked only where named: on the PHP side the last "pfb_validate: REJECT" line's reason code, stage and detected, else
// the last "— skipped" text or failed transfer status of the Extras log, with stage "fetch"). Every refused row
// carries a reason and a stage, and after every step no configured secret appears in a row's reason or detail, or in
// the name or content of any file the run left (the servers' request log aside). `pfblockerng.sh asn_table`, the ASN conversion's step (#4034), is
// recorded as a line in db/script.calls.
//
// A "whitelist" step (no extras) runs the TOP1M whitelist build, pfblockerng_top1m(); its ok is whether a new
// db/pfbalexawhitelist.txt was published.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

const extrasCorpusDir = "../../../tests/extras/fixtures/parity"

type extrasExtra struct {
	URL      string `json:"url"`
	FileDwn  string `json:"file_dwn"`
	File     string `json:"file"`
	Folder   string `json:"folder"`
	Type     string `json:"type"`
	Provider string `json:"provider"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type extrasExpect struct {
	OK           bool                `json:"ok"`
	MaxmindError bool                `json:"maxmind_error"`
	Top1MChanged bool                `json:"top1m_changed"`
	Ledger       json.RawMessage     `json:"ledger"`
	Report       *string             `json:"report"`
	Reason       *string             `json:"reason"`
	Stage        *string             `json:"stage"`
	Detected     *string             `json:"detected"`
	Replaced     []string            `json:"replaced"`
	Files        map[string]any      `json:"files"`
	Requests     []map[string]string `json:"requests"`
}

type extrasStep struct {
	Run       string         `json:"run"`
	Extras    []extrasExtra  `json:"extras"`
	Routes    routes         `json:"routes"`
	Seed      map[string]any `json:"seed"`
	Expect    extrasExpect   `json:"expect"`
	OldExpect *extrasExpect  `json:"old_expect"`
}

type extrasScenario struct {
	Schema      int                 `json:"schema"`
	Description string              `json:"description"`
	Hosts       map[string][]string `json:"hosts"`
	Servers     []string            `json:"servers"`
	Settings    struct {
		MaxMindAccount string `json:"maxmind_account"`
		MaxMindKey     string `json:"maxmind_key"`
		ASNToken       string `json:"asn_token"`
		Sanity         bool   `json:"sanity"`
		Top1MSource    string `json:"top1m_source"`
		Top1MToken     string `json:"top1m_token"`
		Top1MInc       string `json:"top1m_inclusions"`
		Top1MCount     *int   `json:"top1m_count"`
	} `json:"settings"`
	Ledger *string        `json:"ledger"`
	Seed   map[string]any `json:"seed"`
	Routes routes         `json:"routes"`
	Steps  []extrasStep   `json:"steps"`
}

func TestExtrasParityCorpus(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(extrasCorpusDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus scenario under %s (%v)", extrasCorpusDir, err)
	}
	for _, file := range files {
		t.Run(strings.TrimSuffix(filepath.Base(file), ".json"), func(t *testing.T) { runExtrasScenario(t, file) })
	}
}

func runExtrasScenario(t *testing.T, file string) {
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var sc extrasScenario
	if err := dec.Decode(&sc); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	if sc.Schema != 1 || sc.Description == "" || len(sc.Steps) == 0 {
		t.Fatalf("%s: schema 1 with a description and steps required", file)
	}
	// A typo in body_b64 would serve a short body that a refusal row still accepts.
	checkRoutes := func(rs routes) {
		for server, paths := range rs {
			for path, rt := range paths {
				if _, err := base64.StdEncoding.DecodeString(rt.BodyB64); err != nil {
					t.Fatalf("%s: route %s %s: body_b64: %v", file, server, path, err)
				}
			}
		}
	}
	checkRoutes(sc.Routes)
	for _, st := range sc.Steps {
		checkRoutes(st.Routes)
	}

	root := t.TempDir()
	for _, d := range []string{"db", "share"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	tab := sc.Routes
	log := &requestLog{path: filepath.Join(root, "requests.log")}
	ports := map[string]string{}
	for _, name := range sc.Servers {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: corpusServer{t: t, name: name, mu: &mu, log: log, tab: &tab, query: true}}
		go srv.Serve(ln)
		t.Cleanup(func() { srv.Close() })
		ports[name] = strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	}
	portRe := regexp.MustCompile(`\{port:([a-z]+)\}`)
	expand := func(s string) string {
		return portRe.ReplaceAllStringFunc(s, func(m string) string {
			p, ok := ports[portRe.FindStringSubmatch(m)[1]]
			if !ok {
				t.Fatalf("no server %s", m)
			}
			return p
		})
	}
	seed := func(files map[string]any) {
		for rel, content := range files {
			p := filepath.Join(root, rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, contentBytes(t, content, expand), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	seed(sc.Seed)

	f := &feedfetch.Fetcher{RetryDelay: 1}
	f.Sanity = sc.Settings.Sanity
	f.Resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
		var out []netip.Addr
		for _, a := range sc.Hosts[host] {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
	calls := filepath.Join(root, "db", "script.calls")
	cfg := feedfetch.ExtrasConfig{
		DBDir:          filepath.Join(root, "db"),
		MaxMindAccount: sc.Settings.MaxMindAccount,
		MaxMindKey:     sc.Settings.MaxMindKey,
		ASNToken:       sc.Settings.ASNToken,
		Top1MToken:     sc.Settings.Top1MToken,
		ASNTable: func(context.Context) {
			out, err := os.OpenFile(calls, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
			if err != nil {
				t.Fatal(err)
			}
			out.WriteString("asn_table\n")
			out.Close()
		},
	}

	ledger := sc.Ledger // the TOP1M download ledger's open message, nil when none is open
	for i, st := range sc.Steps {
		label := filepath.Base(file) + " step " + strconv.Itoa(i)
		mu.Lock()
		if st.Routes != nil {
			tab = st.Routes
		}
		expanded := routes{}
		for server, paths := range tab {
			expanded[server] = map[string]route{}
			for p, rt := range paths {
				rt.Location, rt.Body = expand(rt.Location), expand(rt.Body)
				expanded[server][p] = rt
			}
		}
		tab = expanded
		mu.Unlock()
		log.reset(t)
		seed(st.Seed)
		if st.Run != "download" && st.Run != "dcc" && st.Run != "bls" && st.Run != "whitelist" {
			t.Fatalf("%s: unknown run %q", label, st.Run)
		}
		cfg.Detect = st.Run == "dcc"

		inodes := map[string]uint64{}
		for _, rel := range st.Expect.Replaced {
			inodes[rel] = inode(filepath.Join(root, rel))
		}
		var extras []feedfetch.Extra
		for _, e := range st.Extras {
			if e.Provider != "" && e.Provider != sc.Settings.Top1MSource {
				t.Fatalf("%s: the TOP1M row names %s, the settings %s", label, e.Provider, sc.Settings.Top1MSource)
			}
			extras = append(extras, feedfetch.Extra{
				Kind: e.Type, URL: expand(e.URL), Dir: filepath.Join(root, e.Folder), Download: e.FileDwn, File: e.File,
				Provider: e.Provider, Name: e.Name, Username: e.Username, Password: e.Password,
			})
		}
		var res feedfetch.ExtrasResult
		if st.Run == "whitelist" {
			wl := feedfetch.Top1MWhitelistConfig{DBDir: cfg.DBDir, Provider: sc.Settings.Top1MSource, Count: 1000}
			if sc.Settings.Top1MInc != "" {
				wl.Inclusions = strings.Split(sc.Settings.Top1MInc, ",")
			}
			if sc.Settings.Top1MCount != nil {
				wl.Count = *sc.Settings.Top1MCount
			}
			res.OK = feedfetch.Top1MWhitelist(wl).Published
		} else {
			res = f.DownloadExtras(context.Background(), cfg, extras)
		}
		if res.Top1MLedger != nil { // "" closes the entry; any other text opens it with that message
			if ledger = nil; *res.Top1MLedger != "" {
				ledger = res.Top1MLedger
			}
		}
		actual := map[string]any{"ok": res.OK, "maxmind_error": res.MaxMindError, "top1m_changed": res.Top1MChanged}
		if st.Expect.Ledger != nil {
			actual["ledger"] = nil
			if ledger != nil {
				actual["ledger"] = *ledger
			}
		}
		if st.Expect.Report != nil {
			actual["report"] = res.Report
		}
		var refused *feedfetch.ExtrasRow
		for n := range res.Rows {
			row := &res.Rows[n]
			if !row.OK {
				if row.Reason == "" || row.Stage == "" {
					t.Errorf("%s: refused row %s carries no reason or stage: %+v", label, row.Download, *row)
				}
				refused = row
			}
		}
		got := map[string]any{"reason": nil, "stage": nil, "detected": nil}
		if refused != nil {
			got = map[string]any{"reason": refused.Reason, "stage": refused.Stage, "detected": refused.Detected}
		}
		for key, want := range map[string]*string{"reason": st.Expect.Reason, "stage": st.Expect.Stage, "detected": st.Expect.Detected} {
			if want != nil {
				actual[key] = got[key]
			}
		}
		checkSecrets(t, label, root, res.Rows,
			secrets(sc.Settings.MaxMindAccount, sc.Settings.MaxMindKey, sc.Settings.ASNToken, sc.Settings.Top1MToken, st.Extras))
		files := map[string]any{}
		for rel := range st.Expect.Files {
			files[rel] = observe(t, filepath.Join(root, rel))
		}
		actual["files"] = files
		if st.Expect.Replaced != nil {
			replaced := []string{}
			for _, rel := range st.Expect.Replaced {
				if inode(filepath.Join(root, rel)) != inodes[rel] {
					replaced = append(replaced, rel)
				}
			}
			actual["replaced"] = replaced
		}
		reqs := log.read(t)
		for n, rec := range reqs {
			for _, optional := range []string{"host", "query"} {
				named := false
				if n < len(st.Expect.Requests) {
					_, named = st.Expect.Requests[n][optional]
				}
				if !named {
					delete(rec, optional)
				}
			}
		}
		actual["requests"] = reqs

		want := st.Expect
		wantFiles := map[string]any{}
		for rel, content := range want.Files {
			if content == nil {
				wantFiles[rel] = nil
			} else {
				wantFiles[rel] = string(contentBytes(t, content, expand))
			}
		}
		wantReqs := []map[string]string{}
		for _, r := range want.Requests {
			rec := map[string]string{}
			for k, v := range r {
				rec[k] = expand(v)
			}
			wantReqs = append(wantReqs, rec)
		}
		wantMap := map[string]any{"ok": want.OK, "maxmind_error": want.MaxmindError, "top1m_changed": want.Top1MChanged,
			"files": wantFiles, "requests": wantReqs}
		if want.Ledger != nil {
			var msg *string
			if err := json.Unmarshal(want.Ledger, &msg); err != nil {
				t.Fatalf("%s: ledger: %v", label, err)
			}
			wantMap["ledger"] = nil
			if msg != nil {
				wantMap["ledger"] = *msg
			}
		}
		if want.Replaced != nil {
			wantMap["replaced"] = want.Replaced
		}
		if want.Report != nil {
			wantMap["report"] = *want.Report
		}
		for key, v := range map[string]*string{"reason": want.Reason, "stage": want.Stage, "detected": want.Detected} {
			if v != nil {
				wantMap[key] = *v
			}
		}
		if !reflect.DeepEqual(wantMap, actual) {
			t.Errorf("%s: %s\nwant %#v\n got %#v", label, sc.Description, wantMap, actual)
		}
	}
}

// secrets are the configured secrets of a step, each as it is configured and as it travels: the MaxMind key, the ASN and
// TOP1M tokens and the blacklist rows' passwords, raw, URL-encoded (query and path escaping) and inside the Basic
// authorization they make with their account or user.
func secrets(maxMindAccount, maxMindKey, asnToken, top1mToken string, extras []extrasExtra) []string {
	var out []string
	add := func(s string) {
		if s != "" {
			out = append(out, s, url.QueryEscape(s), url.PathEscape(s))
		}
	}
	basic := func(user, pass string) {
		if pass != "" {
			out = append(out, base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
		}
	}
	add(maxMindKey)
	add(asnToken)
	add(top1mToken)
	basic(maxMindAccount, maxMindKey)
	for _, e := range extras {
		add(e.Password)
		basic(e.Username, e.Password)
	}
	return out
}

// checkSecrets fails when a secret appears in a row's reason or detail, or in the name or content of a file under root
// (the servers' request log aside: the servers record what they were sent).
func checkSecrets(t *testing.T, label, root string, rows []feedfetch.ExtrasRow, secrets []string) {
	t.Helper()
	if len(secrets) == 0 {
		return
	}
	for _, row := range rows {
		for _, s := range secrets {
			if strings.Contains(row.Reason, s) || strings.Contains(row.Detected, s) {
				t.Errorf("%s: a secret reaches the refusal of %s: %q %q", label, row.Download, row.Reason, row.Detected)
			}
		}
	}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == filepath.Join(root, "requests.log") {
			return nil
		}
		var content []byte
		if d.Type().IsRegular() {
			if content, err = os.ReadFile(p); err != nil {
				return err
			}
		}
		for _, s := range secrets {
			if strings.Contains(d.Name(), s) || bytes.Contains(content, []byte(s)) {
				t.Errorf("%s: a secret reaches %s", label, strings.TrimPrefix(p, root))
			}
		}
		return nil
	})
	if err != nil {
		t.Errorf("%s: the run root was not read whole for secrets: %v", label, err)
	}
}

// contentBytes is a seeded or expected file: text (ports expanded) or {"b64": bytes}.
func contentBytes(t *testing.T, content any, expand func(string) string) []byte {
	t.Helper()
	switch c := content.(type) {
	case string:
		return []byte(expand(c))
	case map[string]any:
		b, err := base64.StdEncoding.DecodeString(c["b64"].(string))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	t.Fatalf("content %#v is neither text nor {b64}", content)
	return nil
}

// observe is what a path holds: its content, nil when nothing is there, or a marker for an entry that is not a regular
// file (a directory left where a file was expected to be gone must not read as absent). A share entry Core publishes as
// a link through its archive's link (.<archive>/<entry>, #4142) reads as the file it names, as today's path names it.
func observe(t *testing.T, path string) any {
	t.Helper()
	info, err := os.Lstat(path)
	if to, lerr := os.Readlink(path); lerr == nil && feedfetch.EntryLink(filepath.Dir(path), to, filepath.Base(path)) {
		info, err = os.Stat(path)
	}
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		return "<not a regular file>"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// inode is the file's inode number, 0 when nothing is there: a publication by rename gives the path a new one.
func inode(path string) uint64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Sys().(*syscall.Stat_t).Ino
}

// The negative control of a null expectation: a directory where nothing is expected must not read as absent.
func TestObserveTellsADirectoryFromNothing(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "asn.update"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]any{"asn.update": "<not a regular file>", "missing": nil, "f": "x"} {
		if got := observe(t, filepath.Join(root, path)); got != want {
			t.Errorf("observe(%s) = %#v, want %#v", path, got, want)
		}
	}
}

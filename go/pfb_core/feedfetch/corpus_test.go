package feedfetch_test

// The feed-transfer parity corpus (#3905), schema 1: language-neutral JSON scenarios in tests/feedfetch/fixtures/parity
// that today's PHP passes (tests/php/FeedFetchParityCorpusTest.php drives pfb_download() and pfb_update_check()) and
// this package passes. Expectations are frozen literals read from the PHP source and confirmed by the PHP run.
//
// A scenario (unknown keys are refused):
//
//	schema       1.
//	description  what the scenario pins.
//	hosts        {name: [addresses]}: the resolver used for vetting and self-hosted classification (a name that is not
//	             listed fails the run). With the filter off, connections resolve names through the system resolver.
//	filter       optional, default true: the feed-host internal-address filter.
//	allowlist    optional [IP or CIDR]: internal-address exemptions.
//	self         optional [IP]: the box's own configured addresses (127.0.0.1 and ::1 always are).
//	servers      optional [name]: HTTP servers on 127.0.0.1; "{port:<name>}" expands to a server's port and
//	             "{port:closed}" to a port nothing listens on. "{local}" is the feed directory, which is also the one
//	             directory local file sources may sit in (a URL "{local}/x" is the local path; Core reads it as file://).
//	routes       optional {server: {path: route}}, a step may replace it (the replacement stays for later steps).
//	             route: status (default 200), location, body, etag, last_modified (Unix seconds), declared_length.
//	             An unknown path is a 404 "missing\n". With etag the server answers 304 when If-None-Match equals it;
//	             otherwise with last_modified, when If-Modified-Since is not older. declared_length is the Content-Length
//	             sent; the server then closes after the body.
//	seed         optional {published, etag, lastmod, digest}: the feed's published copy, stored validators and content
//	             digest (the xxh128 sidecar ".orig.xxhash128", as PHP's pfb_hash_write() leaves it) before step 0.
//	local_files  optional {relative path: content}; local_symlinks optional {relative path: target}. A step may write
//	             local_files again before it runs.
//	steps        [step], run in order against one feed:
//	  op         "ingest" (download and publish) or "probe" (change detection).
//	  url, format ("rsync" or absent), username, password, headers ["Name: value"], ceiling (bytes),
//	  rsync      {exit, body}: the stand-in rsync (tests/feedfetch/fixtures/fake-rsync.sh) for this step.
//	  expect     ok; decision (probe: changed|unchanged|failed); published (string or null); etag, lastmod, digest
//	             (absent: unchanged by the step); requests [{server, path, and only the headers sent among authorization,
//	             if_none_match, if_modified_since, x_feed_probe, accept_encoding}] in order, plus host (the Host header as
//	             received, "name:port"), which is checked only when the expectation names it; reason (optional: the
//	             refusal reason); rsync_source (absent: rsync never started). No non-empty staged body may survive a step.
//	  old_expect optional, the shape of expect: present only where Core differs from the old path on purpose. This runner
//	             asserts expect and refuses an old_expect equal to it; the PHP runner asserts old_expect instead.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

const corpusDir = "../../../tests/feedfetch/fixtures/parity"

type route struct {
	Status         int     `json:"status"`
	Location       string  `json:"location"`
	Body           string  `json:"body"`
	ETag           *string `json:"etag"`
	LastModified   *int64  `json:"last_modified"`
	DeclaredLength *int    `json:"declared_length"`
}

type routes map[string]map[string]route

type expect struct {
	OK          bool                `json:"ok"`
	Decision    *string             `json:"decision"`
	Published   *string             `json:"published"`
	ETag        json.RawMessage     `json:"etag"`
	LastMod     json.RawMessage     `json:"lastmod"`
	Digest      json.RawMessage     `json:"digest"`
	Requests    []map[string]string `json:"requests"`
	Reason      *string             `json:"reason"`
	RsyncSource *string             `json:"rsync_source"`
}

type step struct {
	Op         string            `json:"op"`
	URL        string            `json:"url"`
	Format     string            `json:"format"`
	Username   string            `json:"username"`
	Password   string            `json:"password"`
	Headers    []string          `json:"headers"`
	Ceiling    int64             `json:"ceiling"`
	Routes     routes            `json:"routes"`
	LocalFiles map[string]string `json:"local_files"`
	Rsync      *struct {
		Exit int    `json:"exit"`
		Body string `json:"body"`
	} `json:"rsync"`
	Expect    expect  `json:"expect"`
	OldExpect *expect `json:"old_expect"`
}

type scenario struct {
	Schema      int                 `json:"schema"`
	Description string              `json:"description"`
	Hosts       map[string][]string `json:"hosts"`
	Filter      *bool               `json:"filter"`
	Allowlist   []string            `json:"allowlist"`
	Self        []string            `json:"self"`
	Servers     []string            `json:"servers"`
	Routes      routes              `json:"routes"`
	Seed        *struct {
		Published *string `json:"published"`
		ETag      *string `json:"etag"`
		LastMod   *int64  `json:"lastmod"`
		Digest    *string `json:"digest"`
	} `json:"seed"`
	LocalFiles    map[string]string `json:"local_files"`
	LocalSymlinks map[string]string `json:"local_symlinks"`
	Steps         []step            `json:"steps"`
}

// corpusServer mirrors tests/php/support/FeedFetchCorpusRouter.php.
type corpusServer struct {
	name string
	mu   *sync.Mutex
	log  *[]map[string]string
	tab  *routes
}

func (s corpusServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := map[string]string{"server": s.name, "path": r.URL.Path, "host": r.Host}
	for key, header := range map[string]string{
		"authorization": "Authorization", "if_none_match": "If-None-Match", "if_modified_since": "If-Modified-Since",
		"x_feed_probe": "X-Feed-Probe", "accept_encoding": "Accept-Encoding",
	} {
		if v, ok := r.Header[header]; ok {
			rec[key] = v[0]
		}
	}
	s.mu.Lock()
	*s.log = append(*s.log, rec)
	rt, ok := (*s.tab)[s.name][r.URL.Path]
	s.mu.Unlock()
	if !ok {
		w.Header().Set("Content-Length", "8")
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, "missing\n")
		return
	}
	if rt.ETag != nil {
		w.Header().Set("ETag", *rt.ETag)
	}
	if rt.LastModified != nil {
		w.Header().Set("Last-Modified", time.Unix(*rt.LastModified, 0).UTC().Format(http.TimeFormat))
	}
	notModified := false
	if rt.ETag != nil {
		notModified = r.Header.Get("If-None-Match") == *rt.ETag
	} else if ims := r.Header.Get("If-Modified-Since"); rt.LastModified != nil && ims != "" {
		t, err := http.ParseTime(ims)
		notModified = err == nil && t.Unix() >= *rt.LastModified
	}
	if notModified {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if rt.Location != "" {
		w.Header().Set("Location", rt.Location)
	}
	n := len(rt.Body)
	if rt.DeclaredLength != nil {
		n = *rt.DeclaredLength
	}
	w.Header().Set("Content-Length", strconv.Itoa(n))
	status := rt.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	io.WriteString(w, rt.Body)
}

func TestParityCorpus(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(corpusDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus scenario under %s (%v)", corpusDir, err)
	}
	for _, file := range files {
		t.Run(strings.TrimSuffix(filepath.Base(file), ".json"), func(t *testing.T) { runScenario(t, file) })
	}
}

func loadScenario(t *testing.T, file string) scenario {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var sc scenario
	if err := dec.Decode(&sc); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	if sc.Schema != 1 || sc.Description == "" || len(sc.Steps) == 0 {
		t.Fatalf("%s: schema 1 with a description and steps required", file)
	}
	return sc
}

func runScenario(t *testing.T, file string) {
	sc := loadScenario(t, file)
	base := t.TempDir()
	dir := filepath.Join(base, "feeds")
	tools := filepath.Join(base, "tools")
	for _, d := range []string{dir, tools} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	script, err := os.ReadFile("../../../tests/feedfetch/fixtures/fake-rsync.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tools, "rsync"), script, 0o700); err != nil {
		t.Fatal(err)
	}

	ports := map[string]string{}
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ports["closed"] = strconv.Itoa(closed.Addr().(*net.TCPAddr).Port)
	closed.Close()

	var mu sync.Mutex
	var requests []map[string]string
	table := routes{}
	for _, name := range sc.Servers {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: corpusServer{name: name, mu: &mu, log: &requests, tab: &table}}
		go srv.Serve(ln)
		t.Cleanup(func() { srv.Close() })
		ports[name] = strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	}
	placeholder := regexp.MustCompile(`\{port:([a-z]+)\}`)
	expand := func(s string) string {
		return placeholder.ReplaceAllStringFunc(s, func(m string) string {
			p, ok := ports[placeholder.FindStringSubmatch(m)[1]]
			if !ok {
				t.Fatalf("no server for %s", m)
			}
			return p
		})
	}
	setRoutes := func(rs routes) {
		mu.Lock()
		defer mu.Unlock()
		table = routes{}
		for server, paths := range rs {
			table[server] = map[string]route{}
			for p, rt := range paths {
				rt.Location = expand(rt.Location)
				table[server][p] = rt
			}
		}
	}

	writeLocal := func(files map[string]string) {
		for rel, content := range files {
			p := filepath.Join(dir, rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	writeLocal(sc.LocalFiles)
	for rel, target := range sc.LocalSymlinks {
		if err := os.Symlink(target, filepath.Join(dir, rel)); err != nil {
			t.Fatal(err)
		}
	}

	const name = "FEED"
	feed := feedfetch.Feed{Dir: dir, Name: name}
	orig := filepath.Join(dir, name+".orig")
	var prevETag, prevLastMod, prevDigest any
	if sc.Seed != nil {
		if sc.Seed.Published != nil {
			os.WriteFile(orig, []byte(*sc.Seed.Published), 0o600)
		}
		if sc.Seed.ETag != nil {
			os.WriteFile(orig+".etag", []byte(*sc.Seed.ETag), 0o600)
			prevETag = *sc.Seed.ETag
		}
		if sc.Seed.LastMod != nil {
			os.WriteFile(orig+".lastmod", []byte(strconv.FormatInt(*sc.Seed.LastMod, 10)), 0o600)
			prevLastMod = float64(*sc.Seed.LastMod)
		}
		if sc.Seed.Digest != nil {
			os.WriteFile(orig+".xxhash128", []byte(*sc.Seed.Digest), 0o600)
			prevDigest = *sc.Seed.Digest
		}
	}

	f := &feedfetch.Fetcher{
		Policy: feedfetch.Policy{
			NoFilter:  sc.Filter != nil && !*sc.Filter,
			LocalDirs: []string{dir},
			Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
				addrs, ok := sc.Hosts[host]
				if !ok {
					t.Errorf("resolver asked for %q, which the scenario does not list", host)
					return nil, fmt.Errorf("unlisted host %q", host)
				}
				var out []netip.Addr
				for _, a := range addrs {
					out = append(out, netip.MustParseAddr(a))
				}
				return out, nil
			},
		},
		RsyncBin:   filepath.Join(tools, "rsync"),
		RetryDelay: time.Millisecond, // the PHP side runs with curl_retry_sleep 0
	}
	for _, a := range sc.Allowlist {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			addr := netip.MustParseAddr(a)
			p = netip.PrefixFrom(addr, addr.BitLen())
		}
		f.Allow = append(f.Allow, p)
	}
	for _, a := range sc.Self {
		f.Self = append(f.Self, netip.MustParseAddr(a))
	}

	current := sc.Routes
	for i, st := range sc.Steps {
		label := fmt.Sprintf("step %d (%s): %s", i, st.Op, sc.Description)
		if st.OldExpect != nil && reflect.DeepEqual(*st.OldExpect, st.Expect) {
			t.Fatalf("%s: old_expect equals expect; drop it", label)
		}
		if st.Routes != nil {
			current = st.Routes
		}
		setRoutes(current)
		writeLocal(st.LocalFiles)
		mu.Lock()
		requests = nil
		mu.Unlock()
		os.Remove(filepath.Join(tools, "rsync.argv"))
		var body string
		exit := 0
		if st.Rsync != nil {
			body, exit = st.Rsync.Body, st.Rsync.Exit
		}
		os.WriteFile(filepath.Join(tools, "rsync.body"), []byte(body), 0o600)
		os.WriteFile(filepath.Join(tools, "rsync.exit"), []byte(strconv.Itoa(exit)), 0o600)

		url := expand(st.URL)
		if strings.HasPrefix(url, "{local}") {
			url = "file://" + dir + strings.TrimPrefix(url, "{local}")
		}
		req := feedfetch.Request{
			URL: url, Rsync: st.Format == "rsync", Username: st.Username, Password: st.Password,
			Headers: st.Headers, Timeout: 30 * time.Second, MaxBytes: st.Ceiling,
		}
		var res feedfetch.Result
		switch st.Op {
		case "ingest":
			res = f.Ingest(context.Background(), feed, req)
		case "probe":
			res = f.Probe(context.Background(), feed, req)
		default:
			t.Fatalf("%s: unknown op %q", label, st.Op)
		}

		got := map[string]any{"ok": res.OK}
		want := map[string]any{"ok": st.Expect.OK}
		if st.Expect.Decision != nil {
			got["decision"] = res.Decision.String()
			want["decision"] = *st.Expect.Decision
		}
		got["published"] = readOrNil(orig)
		want["published"] = nilOr(st.Expect.Published)
		got["etag"] = readOrNil(orig + ".etag")
		got["lastmod"] = nil
		if lm := readOrNil(orig + ".lastmod"); lm != nil {
			n, _ := strconv.ParseInt(lm.(string), 10, 64)
			got["lastmod"] = float64(n)
		}
		want["etag"] = rawOr(st.Expect.ETag, prevETag)
		want["lastmod"] = rawOr(st.Expect.LastMod, prevLastMod)
		got["digest"], want["digest"] = readOrNil(orig+".xxhash128"), rawOr(st.Expect.Digest, prevDigest)
		mu.Lock()
		gotReq := append([]map[string]string{}, requests...)
		mu.Unlock()
		if gotReq == nil {
			gotReq = []map[string]string{}
		}
		wantReq := []map[string]string{}
		for _, r := range st.Expect.Requests {
			e := map[string]string{}
			for k, v := range r {
				e[k] = expand(v)
			}
			wantReq = append(wantReq, e)
		}
		for i := range gotReq {
			if i >= len(wantReq) || wantReq[i]["host"] == "" {
				delete(gotReq[i], "host") // recorded for every request, compared only where an expectation names it
			}
		}
		got["requests"], want["requests"] = gotReq, wantReq
		got["rsync_source"], want["rsync_source"] = nil, nilOr(st.Expect.RsyncSource)
		if argv, err := os.ReadFile(filepath.Join(tools, "rsync.argv")); err == nil {
			args := strings.Split(strings.TrimSuffix(string(argv), "\n"), "\n")
			if len(args) >= 2 {
				got["rsync_source"] = args[len(args)-2]
			}
		}
		if st.Expect.Reason != nil {
			got["reason"], want["reason"] = res.Reason, *st.Expect.Reason
		}
		got["staged"], want["staged"] = stagedLeftover(t, dir, name), ""
		if !reflect.DeepEqual(got, want) {
			gj, _ := json.MarshalIndent(got, "", " ")
			wj, _ := json.MarshalIndent(want, "", " ")
			t.Fatalf("%s\nwant %s\n got %s\n(result %+v)", label, wj, gj, res)
		}
		prevETag, prevLastMod, prevDigest = got["etag"], got["lastmod"], got["digest"]
	}
}

// stagedLeftover names a non-empty file of the feed that is neither published state nor the pending probe body and
// its validators.
func stagedLeftover(t *testing.T, dir, name string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	keep := map[string]bool{}
	for _, s := range []string{".orig", ".orig.etag", ".orig.lastmod", ".orig.xxhash128", ".probe", ".probe.etag", ".probe.lastmod"} {
		keep[name+s] = true
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || keep[e.Name()] {
			continue
		}
		if strings.Contains(e.Name(), name) {
			return e.Name()
		}
	}
	return ""
}

func readOrNil(p string) any {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	return string(b)
}

func nilOr(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// rawOr decodes an expectation that may be absent (then the value before the step), null, a string or a number.
func rawOr(raw json.RawMessage, prev any) any {
	if raw == nil {
		return prev
	}
	var v any
	json.Unmarshal(raw, &v)
	return v
}

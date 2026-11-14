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
//	sanity       optional, default false: the opt-in plain-text sanity scan (ADR-49, gen/pfb_feed_sanity).
//	allowlist    optional [IP or CIDR]: internal-address exemptions.
//	self         optional [IP]: the box's own configured addresses (127.0.0.1 and ::1 always are).
//	servers      optional [server]: HTTP servers on 127.0.0.1; "{port:<name>}" expands to a server's port and
//	             "{port:closed}" to a port nothing listens on. "{local}" is the feed directory, which is also the one
//	             directory local file sources may sit in (a URL "{local}/x" is the local path; Core reads it as file://).
//	             A server is a name or {name, tls: true, cert: "trusted"|"untrusted", plain_too}: HTTPS with a
//	             certificate from a test CA made at test time (the feed fetcher trusts that CA, Fetcher.RootCAs);
//	             "untrusted" is self-signed, not signed by it. Each TLS connection a server accepts is recorded, before
//	             its handshake, as {server, tls: "connect"}: the attempts the fetcher made, whether or not the handshake
//	             held. With plain_too the same port also serves plain http (the first byte decides, 0x16 being a TLS
//	             handshake), so a redirect can change the scheme and nothing else.
//	             {name, kind: "ftp", users, epsv, pasv_host, replies, quirk} is an ftp server instead: the Python server
//	             tests/feedfetch/fixtures/ftp_server.py, whose header documents the options. It records into the shared
//	             request order {server, command} per command and {server, data_to} per data connection.
//	proxy        optional {server, auth: {user, password}, requires: {user, password}}: the system proxy. server names
//	             a forward proxy the runner starts (tests/feedfetch/fixtures/net_fixture.py, run by both runners: an
//	             absolute-form GET for http, CONNECT for https, to 127.0.0.1 at the target's port; "closed" is nothing
//	             listening), auth the user and password the system proxy holds (Fetcher.Proxy's userinfo), requires the
//	             Basic credentials the proxy demands (407 otherwise). The proxy records each request as {server: the
//	             proxy's name, method, target, and proxy_authorization when one was sent} in the shared request order.
//	routes       optional {server: {path: route}}, a step may replace it (the replacement stays for later steps).
//	             route: status (default 200), location, body (text) or body_b64 (the bytes, base64, for a body that is
//	             not text), etag, last_modified (Unix seconds), declared_length.
//	             An unknown path is a 404 "missing\n". With etag the server answers 304 when If-None-Match equals it;
//	             otherwise with last_modified, when If-Modified-Since is not older. declared_length is the Content-Length
//	             sent; the server then closes after the body.
//	files        optional {server: {absolute path: {body, size, mdtm, cut}}}: an ftp server's files (the header of
//	             ftp_server.py says what each field does); a step may replace it, as it may replace routes.
//	seed         optional {published, etag, lastmod, digest}: the feed's published copy, stored validators and content
//	             digest (the xxh128 sidecar ".orig.xxhash128", as PHP's pfb_hash_write() leaves it) before step 0.
//	local_files  optional {relative path: content}; local_symlinks optional {relative path: target}. A step may write
//	             local_files again before it runs.
//	steps        [step], run in order against one feed:
//	  op         "ingest" (download and publish) or "probe" (change detection).
//	  url, format ("rsync" or absent), username, password, headers ["Name: value"], ceiling (bytes), flex (the feed's
//	  Flex flag, default false),
//	  rsync      {exit, body}: the stand-in rsync (tests/feedfetch/fixtures/fake-rsync.sh) for this step.
//	  expect     ok; decision (probe: changed|unchanged|failed); published (string or null); etag, lastmod, digest
//	             (absent: unchanged by the step); mtime (the published copy's modification time, Unix seconds; checked
//	             only where named); requests [{server, path, and only the headers sent among authorization,
//	             if_none_match, if_modified_since, x_feed_probe, accept_encoding}] in order, plus host (the Host header as
//	             received, "name:port"), which is checked only when the expectation names it; reason (optional: the
//	             refusal reason; a null in an old_expect pins "no reason" for the PHP runner, this one ignores it);
//	             rsync_source (absent: rsync never started). Content gates (#3973): stage and detected (optional: those
//	             of a validation refusal's "stage=.. reason=.. detected=.." line); raw_retained (default false: a
//	             non-empty staged ".raw" survives the step, as an archive success leaves it); published_b64 or
//	             published_size in place of published, for bytes that are not text or are too large to inline. Apart
//	             from raw_retained, no non-empty staged body may survive a step.
//	  old_expect optional, the shape of expect: present only where Core differs from the old path on purpose. This runner
//	             asserts expect and refuses an old_expect equal to it; the PHP runner asserts old_expect instead.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
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
	BodyB64        string  `json:"body_b64"`
	ETag           *string `json:"etag"`
	LastModified   *int64  `json:"last_modified"`
	DeclaredLength *int    `json:"declared_length"`
}

type routes map[string]map[string]route

// expect, beyond the transfer keys of the header: stage and detected (optional: the validation stage and detail of the
// refusal, as pfb_validate_log() writes them: "stage=<stage> reason=<reason> detected=<detail>"); raw_retained (default
// false: a non-empty staged ".raw" survives the step, as an archive success leaves it); published_b64 (published, for
// bytes that are not text) or published_size (the size of the published copy, for a body too large to inline) in
// place of published.
type expect struct {
	OK            bool                `json:"ok"`
	Decision      *string             `json:"decision"`
	Published     *string             `json:"published"`
	ETag          json.RawMessage     `json:"etag"`
	LastMod       json.RawMessage     `json:"lastmod"`
	Digest        json.RawMessage     `json:"digest"`
	Requests      []map[string]string `json:"requests"`
	Mtime         *int64              `json:"mtime"`
	Reason        *string             `json:"reason"`
	RsyncSource   *string             `json:"rsync_source"`
	Stage         *string             `json:"stage"`
	Detected      *string             `json:"detected"`
	RawRetained   bool                `json:"raw_retained"`
	PublishedB64  *string             `json:"published_b64"`
	PublishedSize *int64              `json:"published_size"`
}

type ftpFile struct {
	Body string          `json:"body"`
	Size json.RawMessage `json:"size,omitempty"`
	Mdtm *int64          `json:"mdtm,omitempty"`
	Cut  *int            `json:"cut,omitempty"`
}

type ftpFiles map[string]map[string]ftpFile

type step struct {
	Op         string            `json:"op"`
	URL        string            `json:"url"`
	Format     string            `json:"format"`
	Username   string            `json:"username"`
	Password   string            `json:"password"`
	Headers    []string          `json:"headers"`
	Ceiling    int64             `json:"ceiling"`
	Routes     routes            `json:"routes"`
	Files      ftpFiles          `json:"files"`
	LocalFiles map[string]string `json:"local_files"`
	Rsync      *struct {
		Exit int    `json:"exit"`
		Body string `json:"body"`
	} `json:"rsync"`
	Flex      bool    `json:"flex"`
	Expect    expect  `json:"expect"`
	OldExpect *expect `json:"old_expect"`
}

type scenario struct {
	Schema      int                 `json:"schema"`
	Description string              `json:"description"`
	Hosts       map[string][]string `json:"hosts"`
	Filter      *bool               `json:"filter"`
	Sanity      bool                `json:"sanity"`
	Allowlist   []string            `json:"allowlist"`
	Self        []string            `json:"self"`
	Servers     []serverSpec        `json:"servers"`
	Proxy       *proxySpec          `json:"proxy"`
	Routes      routes              `json:"routes"`
	Files       ftpFiles            `json:"files"`
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
	t    testing.TB
	name string
	mu   *sync.Mutex // guards tab
	log  *requestLog
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
	s.log.add(s.t, rec)
	s.mu.Lock()
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
	body := []byte(rt.Body)
	if rt.BodyB64 != "" {
		body, _ = base64.StdEncoding.DecodeString(rt.BodyB64) // validated by loadScenario
	}
	n := len(body)
	if rt.DeclaredLength != nil {
		n = *rt.DeclaredLength
	}
	w.Header().Set("Content-Length", strconv.Itoa(n))
	status := rt.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	w.Write(body)
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
	checkRoutes := func(rs routes) {
		for p, paths := range rs {
			for path, rt := range paths {
				if _, err := base64.StdEncoding.DecodeString(rt.BodyB64); err != nil {
					t.Fatalf("%s: route %s %s: body_b64: %v", file, p, path, err)
				}
			}
		}
	}
	checkRoutes(sc.Routes)
	for _, st := range sc.Steps {
		checkRoutes(st.Routes)
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
	reqLog := &requestLog{path: filepath.Join(tools, "requests.log")}
	table := routes{}
	var pki *corpusPKI
	var ftpServers []serverSpec
	for _, spec := range sc.Servers {
		spec := spec
		if spec.Kind == "ftp" {
			ftpServers = append(ftpServers, spec)
			ports[spec.Name] = startFTP(t, tools, spec, reqLog.path)
			continue
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{
			Handler:  corpusServer{t: t, name: spec.Name, mu: &mu, log: reqLog, tab: &table},
			ErrorLog: log.New(io.Discard, "", 0), // a handshake the client aborts is the expected outcome of some scenarios
		}
		if spec.TLS {
			if pki == nil {
				made := newCorpusPKI(t)
				pki = &made
			}
			cert, ok := pki.certs[spec.Cert]
			if !ok {
				t.Fatalf("server %s: cert must be trusted or untrusted, got %q", spec.Name, spec.Cert)
			}
			ln = tlsListener{
				Listener: ln, cfg: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
				plainToo: spec.PlainToo,
				connected: func() {
					reqLog.add(t, map[string]string{"server": spec.Name, "tls": "connect"})
				},
			}
		}
		go srv.Serve(ln)
		t.Cleanup(func() { srv.Close() })
		ports[spec.Name] = strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	}
	var systemProxy *url.URL
	if sc.Proxy != nil {
		port := ports["closed"]
		if sc.Proxy.Server != "closed" {
			args := []string{"proxy", "--name", sc.Proxy.Server, "--log", reqLog.path}
			if r := sc.Proxy.Requires; r != nil {
				args = append(args, "--user", r.User, "--password", r.Password)
			}
			port = startNetFixture(t, args...)
			ports[sc.Proxy.Server] = port
		}
		systemProxy = &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", port)}
		if a := sc.Proxy.Auth; a != nil {
			systemProxy.User = url.UserPassword(a.User, a.Password)
		}
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

	// writeFTP gives every ftp server its files; the server reads its config afresh for each connection.
	writeFTP := func(files ftpFiles) {
		for _, decl := range ftpServers {
			writeFTPConfig(t, tools, decl, files[decl.Name])
		}
	}
	writeFTP(sc.Files)

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
		Proxy:      systemProxy,
		RsyncBin:   filepath.Join(tools, "rsync"),
		RetryDelay: time.Millisecond, // the PHP side runs with curl_retry_sleep 0
		Sanity:     sc.Sanity,
	}
	if pki != nil {
		f.RootCAs = pki.pool
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

	current, currentFiles := sc.Routes, sc.Files
	for i, st := range sc.Steps {
		label := fmt.Sprintf("step %d (%s): %s", i, st.Op, sc.Description)
		if st.OldExpect != nil && reflect.DeepEqual(*st.OldExpect, st.Expect) {
			t.Fatalf("%s: old_expect equals expect; drop it", label)
		}
		exp := st.Expect
		if st.Routes != nil {
			current = st.Routes
		}
		if st.Files != nil {
			currentFiles = st.Files
		}
		setRoutes(current)
		writeFTP(currentFiles)
		writeLocal(st.LocalFiles)
		reqLog.reset(t)
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
			Headers: st.Headers, Timeout: 30 * time.Second, MaxBytes: st.Ceiling, Flex: st.Flex,
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
		want := map[string]any{"ok": exp.OK}
		if exp.Decision != nil {
			got["decision"] = res.Decision.String()
			want["decision"] = *exp.Decision
		}
		got["published"], want["published"] = readOrNil(orig), nilOr(exp.Published)
		switch {
		case exp.PublishedSize != nil:
			delete(got, "published")
			delete(want, "published")
			got["published_size"], want["published_size"] = sizeOrNil(orig), *exp.PublishedSize
		case exp.PublishedB64 != nil:
			b, err := base64.StdEncoding.DecodeString(*exp.PublishedB64)
			if err != nil {
				t.Fatalf("%s: published_b64: %v", label, err)
			}
			want["published"] = string(b) // inline in a scenario, so under readCap: readOrNil reads it whole
		}
		got["raw_retained"], want["raw_retained"] = rawKept(filepath.Join(dir, name+".raw")), exp.RawRetained
		got["etag"] = readOrNil(orig + ".etag")
		got["lastmod"] = nil
		if lm := readOrNil(orig + ".lastmod"); lm != nil {
			n, _ := strconv.ParseInt(lm.(string), 10, 64)
			got["lastmod"] = float64(n)
		}
		want["etag"] = rawOr(exp.ETag, prevETag)
		want["lastmod"] = rawOr(exp.LastMod, prevLastMod)
		got["digest"], want["digest"] = readOrNil(orig+".xxhash128"), rawOr(exp.Digest, prevDigest)
		gotReq := reqLog.read(t)
		wantReq := []map[string]string{}
		for _, r := range exp.Requests {
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
		got["rsync_source"], want["rsync_source"] = nil, nilOr(exp.RsyncSource)
		if argv, err := os.ReadFile(filepath.Join(tools, "rsync.argv")); err == nil {
			args := strings.Split(strings.TrimSuffix(string(argv), "\n"), "\n")
			if len(args) >= 2 {
				got["rsync_source"] = args[len(args)-2]
			}
		}
		if exp.Reason != nil {
			got["reason"], want["reason"] = res.Reason, *exp.Reason
		}
		if exp.Mtime != nil {
			got["mtime"], want["mtime"] = nil, *exp.Mtime
			if info, err := os.Stat(orig); err == nil {
				got["mtime"] = info.ModTime().Unix()
			}
		}
		if st.Expect.Stage != nil {
			got["stage"], want["stage"] = res.Stage, *st.Expect.Stage
		}
		if st.Expect.Detected != nil {
			got["detected"], want["detected"] = res.Detected, *st.Expect.Detected
		}
		got["staged"], want["staged"] = stagedLeftover(t, dir, name), ""
		if !reflect.DeepEqual(got, want) {
			gj, _ := json.MarshalIndent(got, "", " ")
			wj, _ := json.MarshalIndent(want, "", " ")
			t.Fatalf("%s\nwant %s\n got %s\n(result %+v)", label, wj[:min(len(wj), readCap)], gj[:min(len(gj), readCap)], res)
		}
		prevETag, prevLastMod, prevDigest = got["etag"], got["lastmod"], got["digest"]
	}
}

// startFTP runs the ftp server of a scenario and returns its port: the server prints "PORT <n>" once it listens, and
// ends when its stdin closes.
func startFTP(t *testing.T, tools string, decl serverSpec, logPath string) string {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("the ftp corpus servers need python3: %v", err)
	}
	writeFTPConfig(t, tools, decl, nil)
	cmd := exec.Command(python, "../../../tests/feedfetch/fixtures/ftp_server.py", ftpConfigPath(tools, decl.Name), logPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stdin.Close()
		cmd.Process.Kill()
		cmd.Wait()
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	n, ok := strings.CutPrefix(strings.TrimSpace(line), "PORT ")
	if _, convErr := strconv.Atoi(n); err != nil || !ok || convErr != nil {
		t.Fatalf("ftp server %s did not announce its port: %q (%v) %s", decl.Name, line, err, stderr.String())
	}
	return n
}

func ftpConfigPath(tools, name string) string { return filepath.Join(tools, name+".ftp.json") }

func writeFTPConfig(t *testing.T, tools string, decl serverSpec, files map[string]ftpFile) {
	t.Helper()
	cfg := struct {
		serverSpec
		Files map[string]ftpFile `json:"files"`
	}{decl, files}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ftpConfigPath(tools, decl.Name), raw, 0o600); err != nil {
		t.Fatal(err)
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
	for _, s := range []string{".orig", ".orig.etag", ".orig.lastmod", ".orig.xxhash128", ".probe", ".probe.etag", ".probe.lastmod", ".raw"} {
		keep[name+s] = true
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".pfbstage_") { // an extraction's staging file, whatever its size
			return e.Name()
		}
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

// readCap bounds what a step reads back (#3989): a larger file becomes its size and SHA-256, so a ceiling regression
// still fails the comparison without holding the file.
const readCap = 1 << 20

// sizeOrNil is the size of the file at p, or nil when there is none.
func sizeOrNil(p string) any {
	info, err := os.Stat(p)
	if err != nil {
		return nil
	}
	return info.Size()
}

// rawKept reports whether p is a non-empty file: the staged body an archive success leaves behind.
func rawKept(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.Size() > 0
}

func readOrNil(p string) any {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, readCap+1))
	if err != nil {
		return fmt.Sprintf("<read error: %v>", err)
	}
	if len(b) <= readCap {
		return string(b)
	}
	h := sha256.New()
	h.Write(b)
	n, err := io.Copy(h, f)
	if err != nil {
		return fmt.Sprintf("<read error: %v>", err)
	}
	return fmt.Sprintf("<%d bytes, sha256 %x>", int64(len(b))+n, h.Sum(nil))
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

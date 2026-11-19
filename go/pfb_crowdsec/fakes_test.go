package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// pfCall is one pfctl invocation the fake saw: its argument vector, and for `-f <file>` (not /dev/null) the file's
// path, mode and content at the time of the call.
type pfCall struct {
	args    []string
	file    string
	mode    os.FileMode
	content string
}

func (c pfCall) String() string { return strings.Join(c.args, " ") }

// fakePF stands in for /sbin/pfctl: it keeps the tables pf would hold and answers the commands the daemon runs.
type fakePF struct {
	mu     sync.Mutex
	tables map[string][]string // table -> addresses, in insertion order
	states string              // `pfctl -s states` output
	rules  string              // `pfctl -v -s rules` output
	calls  []pfCall
	failOn func(args []string) error
}

func newFakePF() *fakePF { return &fakePF{tables: map[string][]string{}} }

func (f *fakePF) run(_ context.Context, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := pfCall{args: slices.Clone(args)}
	if i := slices.Index(args, "-f"); i >= 0 && i+1 < len(args) && args[i+1] != "/dev/null" {
		call.file = args[i+1]
		info, err := os.Stat(call.file)
		if err != nil {
			return nil, fmt.Errorf("fake pfctl: %w", err)
		}
		call.mode = info.Mode().Perm()
		data, err := os.ReadFile(call.file)
		if err != nil {
			return nil, fmt.Errorf("fake pfctl: %w", err)
		}
		call.content = string(data)
	}
	f.calls = append(f.calls, call)
	if f.failOn != nil {
		if err := f.failOn(args); err != nil {
			return nil, err
		}
	}
	switch {
	case len(args) == 6 && args[0] == "-t" && args[2] == "-T" && args[4] == "-f":
		return nil, f.tableOp(args[1], args[3], call.content)
	case len(args) == 4 && args[0] == "-t" && args[2] == "-T" && args[3] == "flush":
		if _, ok := f.tables[args[1]]; !ok {
			return nil, errors.New("pfctl: Table does not exist.")
		}
		f.tables[args[1]] = nil
		return nil, nil
	case slices.Equal(args, []string{"-vvs", "Tables"}):
		return []byte(f.tablesOutput()), nil
	case slices.Equal(args, []string{"-s", "states"}):
		return []byte(f.states), nil
	case slices.Equal(args, []string{"-v", "-s", "rules"}):
		return []byte(f.rules), nil
	case len(args) >= 2 && args[0] == "-k":
		return nil, nil
	}
	return nil, fmt.Errorf("fake pfctl: unexpected command %q", args)
}

func (f *fakePF) tableOp(table, op, content string) error {
	lines := strings.Fields(content)
	have, exists := f.tables[table]
	switch op {
	case "add":
		for _, line := range lines {
			if !slices.Contains(have, line) {
				have = append(have, line)
			}
		}
		f.tables[table] = have
	case "replace":
		f.tables[table] = lines
	case "delete":
		if !exists {
			return errors.New("pfctl: Table does not exist.")
		}
		f.tables[table] = slices.DeleteFunc(have, func(a string) bool { return slices.Contains(lines, a) })
	default:
		return fmt.Errorf("fake pfctl: unexpected table op %q", op)
	}
	return nil
}

// tablesOutput renders `pfctl -vvs Tables` the way FreeBSD's pfctl prints it.
func (f *fakePF) tablesOutput() string {
	var b strings.Builder
	names := make([]string, 0, len(f.tables))
	for name := range f.tables {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		fmt.Fprintf(&b, "-pa-r--\t%s\n", name)
		fmt.Fprintf(&b, "\tAddresses:   %d\n", len(f.tables[name]))
		b.WriteString("\tCleared:     Thu Nov 19 08:00:00 2026\n")
		b.WriteString("\tReferences:  [ Anchors: 0                  Rules: 2                  ]\n")
		b.WriteString("\tEvaluations: [ NoMatch: 0                  Match: 0                  ]\n")
		b.WriteString("\tIn/Block:    [ Packets: 0                  Bytes: 0                  ]\n")
	}
	return b.String()
}

// table returns a sorted copy of a table's addresses, and whether it exists.
func (f *fakePF) table(name string) ([]string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	have, ok := f.tables[name]
	out := slices.Clone(have)
	slices.Sort(out)
	return out, ok
}

func (f *fakePF) setTable(name string, addrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tables[name] = slices.Clone(addrs)
}

func (f *fakePF) killTable(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.tables, name)
}

// takeCalls returns the calls since the last takeCalls and forgets them.
func (f *fakePF) takeCalls() []pfCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	calls := f.calls
	f.calls = nil
	return calls
}

func callStrings(calls []pfCall) []string {
	out := make([]string, 0, len(calls))
	for _, c := range calls {
		out = append(out, c.String())
	}
	return out
}

// lapiReply is one scripted answer of the stub LAPI's stream endpoint.
type lapiReply struct {
	status int
	body   string
}

// stubLAPI serves /v1/decisions/stream from a script of replies (the last one repeats) and records every request.
type stubLAPI struct {
	t       *testing.T
	mu      sync.Mutex
	replies []lapiReply
	reqs    []*http.Request
	bodies  []string
	usage   int // status for POST /v1/usage-metrics
	srv     *httptest.Server
}

func newStubLAPI(t *testing.T, replies ...lapiReply) *stubLAPI {
	t.Helper()
	s := &stubLAPI{t: t, replies: replies, usage: http.StatusCreated}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stubLAPI) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.reqs = append(s.reqs, r.Clone(context.Background()))
	s.bodies = append(s.bodies, string(body))
	var reply lapiReply
	switch r.URL.Path {
	case "/v1/decisions/stream":
		if len(s.replies) == 0 {
			reply = lapiReply{http.StatusOK, `{"new":[],"deleted":[]}`}
		} else {
			reply = s.replies[0]
			if len(s.replies) > 1 {
				s.replies = s.replies[1:]
			}
		}
	case "/v1/usage-metrics":
		reply = lapiReply{s.usage, `{}`}
	default:
		reply = lapiReply{http.StatusNotFound, `{"message":"not found"}`}
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(reply.status)
	_, _ = io.WriteString(w, reply.body)
}

func (s *stubLAPI) push(replies ...lapiReply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replies = replies
}

func (s *stubLAPI) requests() ([]*http.Request, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.reqs), slices.Clone(s.bodies)
}

func ok(body string) lapiReply { return lapiReply{http.StatusOK, body} }

const testKey = "s3cretBouncerKey-1234567890"

// testConfig is a valid config pointing at the stub LAPI, with its status file in a fresh directory.
func testConfig(t *testing.T, apiURL string) *config {
	t.Helper()
	raw := fmt.Sprintf(`{"api_url": %q, "api_key": %q, "update_frequency": "10s", "table_v4": "crowdsec_v4",
		"table_v6": "crowdsec_v6", "log_level": "debug", "status_file": %q}`,
		apiURL, testKey, filepath.Join(t.TempDir(), "pfb_crowdsec.json"))
	cfg, err := parseConfig([]byte(raw))
	if err != nil {
		t.Fatalf("parseConfig(valid test config) = %v", err)
	}
	return cfg
}

// harness wires a daemon to a fake pfctl, a stub LAPI and a log buffer, with a fixed clock.
type harness struct {
	d    *daemon
	pf   *fakePF
	lapi *stubLAPI
	logs *bytes.Buffer
	cfg  *config
	now  time.Time
}

var testEpoch = time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)

func newHarness(t *testing.T, replies ...lapiReply) *harness {
	t.Helper()
	h := &harness{pf: newFakePF(), lapi: newStubLAPI(t, replies...), logs: &bytes.Buffer{}, now: testEpoch}
	h.cfg = testConfig(t, h.lapi.srv.URL+"/")
	log := newLogger(&lockedWriter{w: h.logs}, levelDebug)
	log.setSecret(h.cfg.APIKey)
	api, err := newLAPIClient(h.cfg)
	if err != nil {
		t.Fatalf("newLAPIClient = %v", err)
	}
	h.d = newDaemon(h.cfg, log, &pfctl{r: h.pf, tmpDir: t.TempDir()}, api, func() time.Time { return h.now })
	return h
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func assertTable(t *testing.T, pf *fakePF, name string, want ...string) {
	t.Helper()
	got, exists := pf.table(name)
	if !exists {
		t.Fatalf("table %s does not exist; want %v", name, want)
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("table %s = %v; want %v", name, got, want)
	}
}

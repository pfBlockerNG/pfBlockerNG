// Package coretest is a Core API that serves fixed dnsbl/* resources over a Unix socket, as Core's GetResources and
// GetResourceBody answer them (docs/misc/core-api-protocol.md "Resources"), for the tests of pfB-DNS's Core input.
package coretest

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/zeebo/xxh3"
)

// Resource is one body the server holds: its current generation and its bytes, each line ending in a newline.
type Resource struct {
	Generation string
	Body       []byte
}

// Lines is a body of lines, each ending in a newline.
func Lines(lines []string) []byte {
	if len(lines) == 0 {
		return []byte{}
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// Digest is a body's digest as Core writes it: the xxh128 in lower-case hexadecimal.
func Digest(body []byte) string {
	h := xxh3.New128()
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// Cursor is a generation and digest as a ReportApplied request names them.
type Cursor struct{ Generation, Digest string }

// Server answers GetResources and GetResourceBody from Resources, GetSettings from the settings SetSettings gave (an
// uninitialized Core until then), and records each ReportApplied; every other method is not_found. Like Core's store it
// keeps one baseline per resource besides the current body, the body Set replaced, and answers a cursor at the baseline
// with the delta from it.
type Server struct {
	Socket string

	mu        sync.Mutex
	resources map[string]Resource
	baselines map[string]Resource
	body      func(id string, w http.ResponseWriter) bool
	part      func(id, part string, w http.ResponseWriter) bool
	calls     []string
	applied   []map[string]Cursor
	settings  map[string]map[string]any // projection id → value; nil: uninitialized
	revision  int
}

// New is a Server of resources that a test serves itself, on a listener of its own.
func New(resources map[string]Resource) *Server { return &Server{resources: resources} }

// Start serves resources on a socket in a fresh short directory until the test ends.
func Start(t testing.TB, resources map[string]Resource) *Server {
	t.Helper()
	dir, err := os.MkdirTemp("", "core")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	s := New(resources)
	s.Socket = filepath.Join(dir, "api.sock")
	ln, err := net.Listen("unix", s.Socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: s}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return s
}

// Set replaces the resources served; a body it replaces becomes that resource's baseline.
func (s *Server) Set(resources map[string]Resource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	baselines := map[string]Resource{}
	for id, r := range resources {
		if old, ok := s.resources[id]; ok && old.Generation != r.Generation {
			baselines[id] = old
		} else if old, ok := s.baselines[id]; ok {
			baselines[id] = old
		}
	}
	s.resources, s.baselines = resources, baselines
}

// SetPart has reply answer a GetResourceBody for a delta part ("add" or "remove") first, a test's hostile part: when it
// reports true it has answered.
func (s *Server) SetPart(reply func(id, part string, w http.ResponseWriter) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.part = reply
}

// delta is what turns base into cur: the lines cur has that base has not, and those base has that cur has not, each in
// byte order.
func delta(base, cur []byte) (add, remove []string) {
	in := func(body []byte) map[string]bool {
		set := map[string]bool{}
		for _, line := range strings.Split(strings.TrimSuffix(string(body), "\n"), "\n") {
			if line != "" {
				set[line] = true
			}
		}
		return set
	}
	b, c := in(base), in(cur)
	for line := range c {
		if !b[line] {
			add = append(add, line)
		}
	}
	for line := range b {
		if !c[line] {
			remove = append(remove, line)
		}
	}
	slices.Sort(add)
	slices.Sort(remove)
	return add, remove
}

// SetBody has reply answer a GetResourceBody first, a test's hostile body: when it reports true it has answered.
func (s *Server) SetBody(reply func(id string, w http.ResponseWriter) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body = reply
}

// Settings is the dns and policy/dnsbl values of a Core that holds the defaults, with the fields pfB-DNS reads.
func Settings() (dns, policy map[string]any) {
	dns = map[string]any{
		"replyLogging": true, "pslIncludePrivate": true, "idnBlockMalicious": true, "tldWildcard": false, "pslAllowPrivate": false,
		"idnEscalateSuspicious": false, "cnameValidation": false, "control": false, "controlLegacy": false, "regexCap": false,
		"metricsClientIp": false, "pslFeedPrivatePolicy": "honor", "pslFeedIcannPolicy": "honor", "idnMode": "off",
		"decisionCacheMax": 10000, "noAaaa": false, "noAaaaList": []any{}, "groupPolicy": false, "groupPolicyBypassList": []any{},
		"pfbDnsEnabled": true,
	}
	policy = map[string]any{
		"enabled": true, "tldAllow": false, "tldAllowGtld": []any{}, "tldAllowCctld": []any{}, "tldAllowItld": []any{},
		"tldAllowBgtld": []any{}, "regex": false, "regexList": []any{},
	}
	return dns, policy
}

// SetSettings has GetSettings answer dns and policy as the dns and policy/dnsbl projections, at a new revision; nil
// dns: an uninitialized Core.
func (s *Server) SetSettings(dns, policy map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revision++
	s.settings = nil
	if dns != nil {
		s.settings = map[string]map[string]any{"dns": dns, "policy/dnsbl": policy}
	}
}

// Calls is every call served so far, "<method> <id>" each.
func (s *Server) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

// Applied is every report ReportApplied recorded so far, in order.
func (s *Server) Applied() []map[string]Cursor {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]map[string]Cursor(nil), s.applied...)
}

func fail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": code}})
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	resources, baselines, body, part := s.resources, s.baselines, s.body, s.part
	s.mu.Unlock()
	switch r.URL.Path {
	case "/v1/GetResources":
		var req struct {
			Resources map[string]struct{ Generation, Digest string } `json:"resources"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			fail(w, 400, "invalid_argument")
			return
		}
		items := map[string]any{}
		for id, cur := range req.Resources {
			s.record("GetResources " + id)
			res, ok := resources[id]
			digest := Digest(res.Body)
			switch {
			case !ok:
				items[id] = map[string]any{"error": map[string]string{"code": "not_found", "message": "not found"}}
			case cur.Generation == res.Generation && cur.Digest == digest:
				items[id] = map[string]any{"kind": "unchanged", "generation": res.Generation}
			case cur.Generation == baselines[id].Generation && cur.Digest == Digest(baselines[id].Body):
				add, remove := delta(baselines[id].Body, res.Body)
				items[id] = map[string]any{"kind": "delta", "generation": res.Generation, "from": cur.Generation, "digest": digest,
					"entries": strings.Count(string(res.Body), "\n"), "addEntries": len(add), "removeEntries": len(remove),
					"metadata": map[string]any{}}
			default:
				items[id] = map[string]any{"kind": "full", "generation": res.Generation, "digest": digest,
					"entries": strings.Count(string(res.Body), "\n"), "metadata": map[string]any{}}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"resources": items})
	case "/v1/GetResourceBody":
		var req struct{ ID, Generation, Part, From string }
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.Part != "members" && req.Part != "add" && req.Part != "remove" {
			fail(w, 400, "invalid_argument")
			return
		}
		s.record("GetResourceBody " + req.ID + " " + req.Part)
		if req.Part != "members" {
			if part != nil && part(req.ID, req.Part, w) {
				return
			}
			res, base := resources[req.ID], baselines[req.ID]
			if res.Generation != req.Generation || base.Generation == "" || base.Generation != req.From {
				fail(w, 404, "not_found")
				return
			}
			add, remove := delta(base.Body, res.Body)
			lines := Lines(add)
			if req.Part == "remove" {
				lines = Lines(remove)
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Write(lines)
			return
		}
		if body != nil && body(req.ID, w) {
			return
		}
		res, ok := resources[req.ID]
		if !ok || res.Generation != req.Generation {
			fail(w, 404, "not_found")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(res.Body)))
		w.Write(res.Body)
	case "/v1/GetSettings":
		var req struct {
			ProjectionIDs []string `json:"projectionIds"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			fail(w, 400, "invalid_argument")
			return
		}
		s.record("GetSettings")
		s.mu.Lock()
		reply := map[string]any{"initialized": s.settings != nil, "revision": s.revision, "projections": []any{}}
		if s.settings != nil {
			var projections []any
			for _, id := range req.ProjectionIDs {
				projections = append(projections, map[string]any{"resourceId": "settings/" + id, "generation": strconv.Itoa(s.revision),
					"value": s.settings[id]})
			}
			reply["projections"] = projections
		}
		data, err := json.Marshal(reply)
		s.mu.Unlock()
		if err != nil {
			fail(w, 500, "internal")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	case "/v1/ReportApplied":
		// Core refuses a request without its requestId, with an unknown parameter, or with resources missing or null.
		var req struct {
			RequestID string            `json:"requestId"`
			Resources map[string]Cursor `json:"resources"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if dec.Decode(&req) != nil || req.RequestID == "" || req.Resources == nil {
			fail(w, 400, "invalid_argument")
			return
		}
		s.record("ReportApplied")
		s.mu.Lock()
		s.applied = append(s.applied, req.Resources)
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
	default:
		fail(w, 404, "not_found")
	}
}

func (s *Server) record(call string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, call)
}

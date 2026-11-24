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
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/pfBlockerNG/xxh3"
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

// Server answers GetResources and GetResourceBody from Resources; every other method is not_found.
type Server struct {
	Socket string

	mu        sync.Mutex
	resources map[string]Resource
	// Body, when set, replaces the reply to a GetResourceBody of id: a test's hostile body.
	Body  func(id string, w http.ResponseWriter) bool
	calls []string
}

// Start serves resources on a socket in a fresh short directory until the test ends.
func Start(t testing.TB, resources map[string]Resource) *Server {
	t.Helper()
	dir, err := os.MkdirTemp("", "core")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	s := &Server{Socket: filepath.Join(dir, "api.sock"), resources: resources}
	ln, err := net.Listen("unix", s.Socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: s}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return s
}

// Set replaces the resources served.
func (s *Server) Set(resources map[string]Resource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resources = resources
}

// Calls is every call served so far, "<method> <id>" each.
func (s *Server) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func fail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": code}})
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	resources := s.resources
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
			switch {
			case !ok:
				items[id] = map[string]any{"error": map[string]string{"code": "not_found", "message": "not found"}}
			case cur.Generation == res.Generation && cur.Digest == Digest(res.Body):
				items[id] = map[string]any{"kind": "unchanged", "generation": res.Generation}
			default:
				items[id] = map[string]any{"kind": "full", "generation": res.Generation, "digest": Digest(res.Body),
					"entries": strings.Count(string(res.Body), "\n"), "metadata": map[string]any{}}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"resources": items})
	case "/v1/GetResourceBody":
		var req struct{ ID, Generation, Part string }
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.Part != "members" {
			fail(w, 400, "invalid_argument")
			return
		}
		s.record("GetResourceBody " + req.ID)
		if s.Body != nil && s.Body(req.ID, w) {
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
	default:
		fail(w, 404, "not_found")
	}
}

func (s *Server) record(call string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, call)
}

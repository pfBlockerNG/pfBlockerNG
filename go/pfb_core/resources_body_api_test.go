package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/digest"
)

// GetResourceBody streams one resource part as plain text (docs/misc/core-api-protocol.md, "Resources").

func bodyParams(id, g, part, from string) string {
	if from == "" {
		return fmt.Sprintf(`{"id":%q,"generation":%q,"part":%q}`, id, g, part)
	}
	return fmt.Sprintf(`{"id":%q,"generation":%q,"part":%q,"from":%q}`, id, g, part, from)
}

// body is the lines GetResourceBody serves for a part; the reply must be a plain-text 200 of exactly its bytes.
func (r *resRig) body(id, g, part, from string) []string {
	r.t.Helper()
	rep := r.core.post("GetResourceBody", bodyParams(id, g, part, from))
	if rep.status != 200 {
		r.t.Fatalf("GetResourceBody(%s, %s, %s, %s) status = %d (body %s)", id, g, part, from, rep.status, rep.body)
	}
	for k, want := range map[string]string{"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store",
		"Content-Length": fmt.Sprint(len(rep.body))} {
		if got := rep.header.Get(k); got != want {
			r.t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if len(rep.body) == 0 {
		return []string{}
	}
	if rep.body[len(rep.body)-1] != '\n' {
		r.t.Fatalf("body does not end in a newline: %q", rep.body)
	}
	return strings.Split(strings.TrimSuffix(string(rep.body), "\n"), "\n")
}

func wantLines(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if !slices.Equal(got, want) {
		t.Errorf("%s = %q, want %q", what, got, want)
	}
}

func TestGetResourceBodyServesTheCanonicalBytes(t *testing.T) {
	r := newResRig(t)
	const id = "ip-set/B/ipv4"
	r.pub(id, nil, "10.0.0.3", "10.0.0.1", "10.0.0.2")
	r.applied(id, 1)
	r.pub(id, nil, "10.0.0.2", "10.0.0.3", "10.0.0.4")
	rep := r.core.post("GetResourceBody", bodyParams(id, "2", "members", ""))
	canonical, err := os.ReadFile(filepath.Join(r.dir, "ip-set~B~ipv4.2.body"))
	if err != nil || string(rep.body) != string(canonical) || digest.Bytes(rep.body) != r.digest(id) {
		t.Fatalf("body %q (digest %s); want the canonical file %q (digest %s): %v", rep.body, digest.Bytes(rep.body), canonical, r.digest(id), err)
	}
	wantLines(t, "members of 2", r.body(id, "2", "members", ""), "10.0.0.2", "10.0.0.3", "10.0.0.4")
	wantLines(t, "members of the applied 1", r.body(id, "1", "members", ""), "10.0.0.1", "10.0.0.2", "10.0.0.3")
	wantLines(t, "add from 1", r.body(id, "2", "add", "1"), "10.0.0.4")
	wantLines(t, "remove from 1", r.body(id, "2", "remove", "1"), "10.0.0.1")
	wantLines(t, "add from 1, generation as 0-padded digits", r.body(id, "002", "add", "01"), "10.0.0.4")
}

func TestGetResourceBodyAnswersNotFoundForWhatTheStoreNoLongerHolds(t *testing.T) {
	r := newResRig(t)
	const id = "dnsbl/main"
	r.pub(id, nil, "a.example")
	r.applied(id, 1)
	r.pub(id, nil, "b.example")
	r.applied(id, 2)
	r.pub(id, nil, "c.example")
	for _, p := range [][4]string{
		{id, "1", "members", ""}, {id, "2", "add", "1"}, {id, "3", "add", "1"}, {id, "4", "members", ""},
		{"dnsbl/never", "1", "members", ""},
	} {
		wantError(t, r.core.post("GetResourceBody", bodyParams(p[0], p[1], p[2], p[3])), 404, "not_found")
	}
	wantLines(t, "add from 2", r.body(id, "3", "add", "2"), "c.example")
	resJSONEqual(t, r.call(map[string]string{id: cur(1, digest.Bytes([]byte("a.example\n")))}),
		map[string]any{id: full("3", r.digest(id), 1, map[string]any{})})
}

func TestGetResourceBodyNeverServesADamagedBody(t *testing.T) {
	r := newResRig(t)
	const id = "dnsbl/main"
	r.pub(id, nil, "a.example", "b.example")
	p := filepath.Join(r.dir, "dnsbl~main.1.body")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b[0] ^= 1
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	wantError(t, r.core.post("GetResourceBody", bodyParams(id, "1", "members", "")), 503, "unavailable")
}

func TestGetResourceBodyRefusesABadRequestNamingTheField(t *testing.T) {
	r := newResRig(t)
	r.pub("dnsbl/main", nil, "a.example")
	for name, tc := range map[string]struct{ body, field string }{
		"no id":                  {`{"generation":"1","part":"members"}`, "id"},
		"an invalid id":          {`{"id":"settings/dns","generation":"1","part":"members"}`, "id"},
		"an id that is a number": {`{"id":5,"generation":"1","part":"members"}`, "id"},
		"no generation":          {`{"id":"dnsbl/main","part":"members"}`, "generation"},
		"a negative generation":  {`{"id":"dnsbl/main","generation":"-1","part":"members"}`, "generation"},
		"a numeric generation":   {`{"id":"dnsbl/main","generation":1,"part":"members"}`, "generation"},
		"no part":                {`{"id":"dnsbl/main","generation":"1"}`, "part"},
		"an unknown part":        {`{"id":"dnsbl/main","generation":"1","part":"body"}`, "part"},
		"add without from":       {`{"id":"dnsbl/main","generation":"1","part":"add"}`, "from"},
		"remove without from":    {`{"id":"dnsbl/main","generation":"1","part":"remove"}`, "from"},
		"members with from":      {`{"id":"dnsbl/main","generation":"1","part":"members","from":"1"}`, "from"},
		"a from too large":       {`{"id":"dnsbl/main","generation":"1","part":"add","from":"18446744073709551616"}`, "from"},
		"an unknown parameter":   {`{"id":"dnsbl/main","generation":"1","part":"members","x":1}`, "x"},
	} {
		t.Run(name, func(t *testing.T) {
			wantError(t, r.core.post("GetResourceBody", tc.body), 400, "invalid_argument", tc.field)
		})
	}
}

func TestGetResourceBodyWithoutAStoreIsUnavailable(t *testing.T) {
	c := startCore(t, scratchDir(t))
	wantError(t, c.post("GetResourceBody", bodyParams("dnsbl/main", "1", "members", "")), 503, "unavailable")
}

// Neither call holds a body in memory: GetResources over 16 large resources, and a body read of one, allocate a small
// constant, far below the bodies' size.
func TestResourceCallsAllocateAConstant(t *testing.T) {
	const n, budget = 40_000, 2 << 20 // 16 bodies of about 600 kB each
	r := newResRig(t)
	members := make([]string, n)
	req := map[string]string{}
	for i := range 16 {
		for j := range members {
			members[j] = fmt.Sprintf("10.%d.%d.%d", i, j/256, j%256)
		}
		id := fmt.Sprintf("ip-set/G%d/ipv4", i)
		r.pub(id, nil, members...)
		req[id] = `{}`
	}
	members = nil
	discard := func(method, body string) {
		resp, err := r.core.client.Post("http://pfb-core/v1/"+method, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if n, err := io.Copy(io.Discard, resp.Body); err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: status %d after %d bytes: %v", method, resp.StatusCode, n, err)
		}
	}
	for what, call := range map[string]func(){
		"GetResources of 16": func() { r.call(req) },
		"GetResourceBody":    func() { discard("GetResourceBody", bodyParams("ip-set/G0/ipv4", "1", "members", "")) },
	} {
		call() // warm the connection
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		call()
		runtime.ReadMemStats(&after)
		if got := after.TotalAlloc - before.TotalAlloc; got > budget {
			t.Errorf("%s allocated %d bytes; want at most %d", what, got, budget)
		}
	}
}

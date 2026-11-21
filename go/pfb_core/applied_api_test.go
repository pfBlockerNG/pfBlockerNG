package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
)

// A further local client (--client-uid, pfb-dns's user) reads what a dnsbl/* consumer needs and reports what it serves
// (issue #4036); it may change nothing else. The privileged uid (root: PHP) keeps every method.

// clientMethods is what a further local client is served: the health check, the settings it builds from, the resources
// it fetches, and its report of what it applied. Every other method of the table, one added later included, is refused.
var clientMethods = []string{"GetResourceBody", "GetResources", "GetSettings", "GetVersion", "ReportApplied"}

const (
	privilegedUID = 0
	clientUID     = 1001
	strangerUID   = 1002
)

// startAs serves Core's real method table over a state directory to a caller the kernel names uid.
func startAs(t *testing.T, uid uint32, state string) *harness {
	t.Helper()
	st, err := settings.Open(state, settings.Production())
	if err != nil {
		t.Fatal(err)
	}
	return start(t, func(o *options) {
		o.methods = coreMethods(state, st, nil, nil, nil)
		o.allowUID = privilegedUID
		o.clientUIDs = []uint32{clientUID}
		o.peerUID = func(*net.UnixConn) (uint32, error) { return uid, nil }
	}, nil)
}

// errorCode is the code of an error reply, or "" for a success.
func errorCode(t *testing.T, r reply) string {
	t.Helper()
	var env struct {
		Error *struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if r.status == http.StatusOK {
		return ""
	}
	if err := json.Unmarshal(r.body, &env); err != nil || env.Error == nil {
		t.Fatalf("status %d without the error envelope: %s", r.status, r.body)
	}
	return env.Error.Code
}

func TestEachCallerIsServedItsMethodsOnly(t *testing.T) {
	state := t.TempDir()
	st, err := settings.Open(state, settings.Production())
	if err != nil {
		t.Fatal(err)
	}
	table := coreMethods(state, st, nil, nil, nil)
	names := slices.Sorted(maps.Keys(table))
	for _, name := range clientMethods {
		if _, ok := table[name]; !ok {
			t.Errorf("the method table has no %s, which a client is to be served; table %v", name, names)
		}
	}
	callers := []struct {
		who    string
		uid    uint32
		served func(name string) bool
	}{
		{"the privileged uid", privilegedUID, func(string) bool { return true }},
		{"a listed client uid", clientUID, func(name string) bool { return slices.Contains(clientMethods, name) }},
		{"an unlisted uid", strangerUID, func(string) bool { return false }},
	}
	for _, c := range callers {
		h := startAs(t, c.uid, state)
		for _, name := range names {
			// An empty body reaches every method's own checks: any answer but unauthenticated means it was served
			got := h.post("/v1/"+name, `{}`)
			code := errorCode(t, got)
			if c.served(name) && code == codeUnauthenticated {
				t.Errorf("%s calling %s: refused as unauthenticated, want it served (body %.200s)", c.who, name, got.body)
			}
			if !c.served(name) && code != codeUnauthenticated {
				t.Errorf("%s calling %s: answered %d %.200s, want 401 unauthenticated", c.who, name, got.status, got.body)
			}
		}
		h.stop()
	}
	// A client learns nothing of methods it may not call: an unknown one is refused the same way
	h := startAs(t, clientUID, state)
	wantError(t, h.post("/v1/NoSuchMethod", `{}`), http.StatusUnauthorized, codeUnauthenticated)
}

const (
	digestA = "0123456789abcdef0123456789abcdef"
	digestB = "fedcba9876543210fedcba9876543210"
)

func appliedReport(requestID string, entries ...string) string {
	return `{"requestId":"` + requestID + `","resources":{` + strings.Join(entries, ",") + `}}`
}

func appliedEntry(id, generation, digest string) string {
	return `"` + id + `":{"generation":"` + generation + `","digest":"` + digest + `"}`
}

// recorded is the resources object the state directory's applied.json holds, as compact JSON, or "" without the file.
func recorded(t *testing.T, state string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(state, "applied.json"))
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Format    int            `json:"format"`
		Resources map[string]any `json:"resources"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil || doc.Format != 1 || doc.Resources == nil {
		t.Fatalf("applied.json is not a format 1 report (%v): %s", err, raw)
	}
	out, _ := json.Marshal(doc.Resources)
	return string(out)
}

// compact is the resources object of a report body as recorded compares it.
func compact(t *testing.T, body string) string {
	t.Helper()
	var p struct {
		Resources map[string]any `json:"resources"`
	}
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(p.Resources)
	return string(out)
}

// asClient are startCore's flags that make the test's own uid a further local client, as pfb-dns's user is, not the
// privileged one: a later --allow-uid overrides coreArgs' own.
func asClient() []string {
	return []string{"--allow-uid", strconv.Itoa(os.Getuid() + 1), "--client-uid", strconv.Itoa(os.Getuid())}
}

func TestAReportIsRecordedAndSurvivesARestart(t *testing.T) {
	dir := scratchDir(t)
	state := filepath.Join(dir, "state")
	body := appliedReport("r1", appliedEntry("dnsbl/manifest", "7", digestA), appliedEntry("dnsbl/feed-a", "18446744073709551615", digestB))

	// Given a Core that serves the test as a further local client
	c := startCore(t, dir, asClient()...)
	// When the client reports the generations it serves
	wantJSON(t, c.post("ReportApplied", body), http.StatusOK, `{}`)
	if code := c.stop(); code != 0 {
		t.Fatalf("run = %d, want 0; its log:\n%s", code, c.stderr.String())
	}
	if got, want := recorded(t, state), compact(t, body); got != want {
		t.Fatalf("recorded after the report:\n have %s\n want %s", got, want)
	}

	// Then a restarted Core finds the report as it was left, and says so at start
	again := startCore(t, dir, asClient()...)
	if code := again.stop(); code != 0 {
		t.Fatalf("run = %d, want 0; its log:\n%s", code, again.stderr.String())
	}
	if got, want := recorded(t, state), compact(t, body); got != want {
		t.Errorf("recorded after a restart:\n have %s\n want %s", got, want)
	}
	if log := again.stderr.String(); !strings.Contains(log, "applied report: 2 resources") {
		t.Errorf("the restarted Core does not report what it found:\n%s", log)
	}
}

func TestARepeatedReportReplaysAndAnotherBodyConflicts(t *testing.T) {
	state := t.TempDir()
	h := startAs(t, clientUID, state)
	first := appliedReport("r1", appliedEntry("dnsbl/manifest", "3", digestA))
	other := appliedReport("r1", appliedEntry("dnsbl/manifest", "4", digestB))

	got := h.post("/v1/ReportApplied", first)
	wantJSON(t, got, http.StatusOK, `{}`)
	// The same requestId and body: the first answer, byte for byte
	if again := h.post("/v1/ReportApplied", first); again.status != got.status || !bytes.Equal(again.body, got.body) {
		t.Errorf("a repeat answered %d %s, want the first answer %d %s", again.status, again.body, got.status, got.body)
	}
	// The same requestId with another body: conflict, and the first report stays recorded
	wantError(t, h.post("/v1/ReportApplied", other), http.StatusConflict, codeConflict, "requestId")
	if have, want := recorded(t, state), compact(t, first); have != want {
		t.Errorf("recorded after a conflicting repeat:\n have %s\n want %s", have, want)
	}
	// A later report replaces the earlier one whole: an id it no longer lists is no longer recorded
	later := appliedReport("r2", appliedEntry("dnsbl/feed-b", "1", digestB))
	wantJSON(t, h.post("/v1/ReportApplied", later), http.StatusOK, `{}`)
	if have, want := recorded(t, state), compact(t, later); have != want {
		t.Errorf("recorded after a later report:\n have %s\n want %s", have, want)
	}
}

// manyEntries is n report entries for distinct dnsbl/* ids.
func manyEntries(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = appliedEntry(fmt.Sprintf("dnsbl/feed-%05d", i), "1", digestA)
	}
	return out
}

func TestAHostileReportIsRefusedAndNothingIsRecorded(t *testing.T) {
	m := `"dnsbl/manifest"`
	cases := map[string]struct{ body, field string }{
		"no resources":               {`{"requestId":"r"}`, "resources"},
		"resources null":             {`{"requestId":"r","resources":null}`, "resources"},
		"an IP set":                  {appliedReport("r", appliedEntry("ip-set/g/ipv4", "1", digestA)), "resources"},
		"the geo catalog":            {appliedReport("r", appliedEntry("geo-catalog", "1", digestA)), "resources"},
		"a settings resource":        {appliedReport("r", appliedEntry("settings/dns", "1", digestA)), "resources"},
		"a dnsbl id with a dot":      {appliedReport("r", appliedEntry("dnsbl/a.b", "1", digestA)), "resources"},
		"a dnsbl id with two levels": {appliedReport("r", appliedEntry("dnsbl/a/b", "1", digestA)), "resources"},
		"generation with a point":    {appliedReport("r", appliedEntry("dnsbl/manifest", "1.5", digestA)), "resources.dnsbl/manifest.generation"},
		"generation negative":        {appliedReport("r", appliedEntry("dnsbl/manifest", "-1", digestA)), "resources.dnsbl/manifest.generation"},
		"generation empty":           {appliedReport("r", appliedEntry("dnsbl/manifest", "", digestA)), "resources.dnsbl/manifest.generation"},
		"generation over 64 bits":    {appliedReport("r", appliedEntry("dnsbl/manifest", "18446744073709551616", digestA)), "resources.dnsbl/manifest.generation"},
		"generation a number":        {`{"requestId":"r","resources":{` + m + `:{"generation":7,"digest":"` + digestA + `"}}}`, "resources.dnsbl/manifest.generation"},
		"digest 31 characters":       {appliedReport("r", appliedEntry("dnsbl/manifest", "1", digestA[:31])), "resources.dnsbl/manifest.digest"},
		"digest upper case":          {appliedReport("r", appliedEntry("dnsbl/manifest", "1", strings.ToUpper(digestA))), "resources.dnsbl/manifest.digest"},
		"digest not hexadecimal":     {appliedReport("r", appliedEntry("dnsbl/manifest", "1", digestA[:31]+"g")), "resources.dnsbl/manifest.digest"},
		"no digest":                  {`{"requestId":"r","resources":{` + m + `:{"generation":"1"}}}`, "resources.dnsbl/manifest.digest"},
		"no generation":              {`{"requestId":"r","resources":{` + m + `:{"digest":"` + digestA + `"}}}`, "resources.dnsbl/manifest.generation"},
		"an entry a string":          {`{"requestId":"r","resources":{` + m + `:"7"}}`, "resources.dnsbl/manifest"},
		"more ids than the bound":    {appliedReport("r", manyEntries(4097)...), "resources"},
	}
	for _, name := range slices.Sorted(maps.Keys(cases)) {
		t.Run(name, func(t *testing.T) {
			state := t.TempDir()
			h := startAs(t, clientUID, state)
			wantError(t, h.post("/v1/ReportApplied", cases[name].body), http.StatusBadRequest, codeInvalidArgument, cases[name].field)
			if have := recorded(t, state); have != "" {
				t.Errorf("a refused report was recorded: %s", have)
			}
		})
	}
	t.Run("an entry with neither field names both", func(t *testing.T) {
		state := t.TempDir()
		h := startAs(t, clientUID, state)
		wantError(t, h.post("/v1/ReportApplied", `{"requestId":"r","resources":{`+m+`:{}}}`), http.StatusBadRequest,
			codeInvalidArgument, "resources.dnsbl/manifest.generation", "resources.dnsbl/manifest.digest")
	})
}

func TestTheReportBoundsAndAnUnknownResourceAreAccepted(t *testing.T) {
	for name, body := range map[string]string{
		// The store changes between a report and its fold, so the fold, not the report, decides what an id still means
		"a resource the store never had": appliedReport("r", appliedEntry("dnsbl/never-published", "1", digestA)),
		"as many ids as the bound":       appliedReport("r", manyEntries(4096)...),
		"no resources at all":            appliedReport("r"),
	} {
		t.Run(name, func(t *testing.T) {
			state := t.TempDir()
			h := startAs(t, clientUID, state)
			wantJSON(t, h.post("/v1/ReportApplied", body), http.StatusOK, `{}`)
			if have, want := recorded(t, state), compact(t, body); have != want {
				t.Errorf("recorded:\n have %.200s\n want %.200s", have, want)
			}
		})
	}
}

func TestADamagedRecordIsIgnoredAndReportedAtStart(t *testing.T) {
	valid := `{"format":1,"resources":{` + appliedEntry("dnsbl/manifest", "7", digestA) + `}}`
	cases := map[string]func(t *testing.T, path, elsewhere string){
		"truncated": func(t *testing.T, path, _ string) {
			if err := os.WriteFile(path, []byte(valid[:len(valid)/2]), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"a symlink to a valid report": func(t *testing.T, path, elsewhere string) {
			if err := os.WriteFile(elsewhere, []byte(valid), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(elsewhere, path); err != nil {
				t.Fatal(err)
			}
		},
		"over its size bound": func(t *testing.T, path, _ string) {
			// Valid JSON once the padding is skipped: the bound, not the parse, refuses it
			if err := os.WriteFile(path, []byte(valid+strings.Repeat(" ", 1<<20)), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"naming an id a client could not report": func(t *testing.T, path, _ string) {
			bad := `{"format":1,"resources":{` + appliedEntry("ip-set/g/ipv4", "7", digestA) + `}}`
			if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"of another format": func(t *testing.T, path, _ string) {
			if err := os.WriteFile(path, []byte(strings.Replace(valid, `"format":1`, `"format":2`, 1)), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, plant := range cases {
		t.Run(name, func(t *testing.T) {
			dir := scratchDir(t)
			state, elsewhere := filepath.Join(dir, "state"), filepath.Join(dir, "elsewhere.json")
			if err := os.Mkdir(state, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(state, "applied.json")
			plant(t, path, elsewhere)

			// Given a damaged record, Core still starts and says it ignored it
			c := startCore(t, dir, asClient()...)
			wantJSON(t, c.post("GetVersion", `{}`), http.StatusOK, versionReply)
			log := c.stderr.String()
			if !strings.Contains(log, "ignored applied.json") || strings.Contains(log, "applied report:") {
				t.Errorf("the start does not report the damaged record as ignored:\n%s", log)
			}

			// When the client reports again, the new report replaces the record and never writes through a link
			body := appliedReport("r1", appliedEntry("dnsbl/feed-a", "2", digestB))
			wantJSON(t, c.post("ReportApplied", body), http.StatusOK, `{}`)
			if code := c.stop(); code != 0 {
				t.Fatalf("run = %d, want 0; its log:\n%s", code, c.stderr.String())
			}
			if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
				t.Fatalf("applied.json after a report = %v, %v; want a regular file", info, err)
			}
			if have, want := recorded(t, state), compact(t, body); have != want {
				t.Errorf("recorded:\n have %s\n want %s", have, want)
			}
			if raw, err := os.ReadFile(elsewhere); err == nil && string(raw) != valid {
				t.Errorf("the link's target was written: %s", raw)
			}
		})
	}
}

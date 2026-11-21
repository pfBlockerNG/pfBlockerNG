package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
)

// What a further local client (pfb-dns's user) may reach beyond the method table: its own replay memory, the settings and
// resources pfb-dns builds from, and nothing the privileged uid keeps (issue #4036).

// clientProjectionIDs are the settings projections a client may read; clientResourcePrefix the resources.
var clientProjectionIDs = []string{"dns", "policy/dnsbl"}

const clientResourcePrefix = "dnsbl/"

// startSwitchable serves Core's real method table over state to a caller whose uid is the returned value's when each request
// connects: every request opens its own connection, so a test changes callers between two requests.
func startSwitchable(t *testing.T, state string, allow uint32, clients ...uint32) (*harness, *atomic.Uint32) {
	t.Helper()
	st, err := settings.Open(state, settings.Production())
	if err != nil {
		t.Fatal(err)
	}
	var uid atomic.Uint32
	h := start(t, func(o *options) {
		o.methods = coreMethods(state, st, nil, nil, nil)
		o.allowUID = allow
		o.clientUIDs = clients
		o.peerUID = func(*net.UnixConn) (uint32, error) { return uid.Load(), nil }
	}, nil)
	h.client.Transport.(*http.Transport).DisableKeepAlives = true
	return h, &uid
}

func TestAClientCannotEvictThePrivilegedCallersReplay(t *testing.T) {
	h, uid := startSwitchable(t, t.TempDir(), privilegedUID, clientUID)

	// Given the privileged uid initialized the settings under requestId R
	uid.Store(privilegedUID)
	const init = `{"requestId":"R","settings":{"dns":{"control":true}}}`
	first := h.post("/v1/InitializeSettings", init)
	if first.status != http.StatusOK {
		t.Fatalf("InitializeSettings = %d %s", first.status, first.body)
	}

	// When a client sends as many reports, each with its own requestId, as the replay memory holds. A refused report is
	// remembered like a recorded one, and writes no file: the flood costs no disk sync.
	uid.Store(clientUID)
	var last reply
	for i := range replayEntries {
		last = h.post("/v1/ReportApplied", fmt.Sprintf(`{"requestId":"c%d"}`, i))
		if last.status != http.StatusBadRequest {
			t.Fatalf("report c%d = %d %s, want the 400 of a report without resources", i, last.status, last.body)
		}
	}

	// Then the privileged uid's repeat of R still gets its first answer, not a second run's conflict
	uid.Store(privilegedUID)
	if again := h.post("/v1/InitializeSettings", init); again.status != first.status || !bytes.Equal(again.body, first.body) {
		t.Errorf("the privileged repeat of R after a client's flood got %d %s, want the first answer %d %s",
			again.status, again.body, first.status, first.body)
	}
	// And the client's own replay still works: its latest report is answered from its memory
	uid.Store(clientUID)
	id := replayEntries - 1
	if again := h.post("/v1/ReportApplied", fmt.Sprintf(`{"requestId":"c%d"}`, id)); again.status != last.status ||
		!bytes.Equal(again.body, last.body) {
		t.Errorf("the client's repeat of c%d got %d %s, want its first answer %d %s", id, again.status, again.body, last.status,
			last.body)
	}
	wantError(t, h.post("/v1/ReportApplied", fmt.Sprintf(`{"requestId":"c%d","resources":{}}`, id)), http.StatusConflict,
		codeConflict, "requestId")
}

// projectionIDs are the ids of a GetSettings reply's projections, in order.
func projectionIDs(t *testing.T, r reply) []string {
	t.Helper()
	if r.status != http.StatusOK {
		t.Fatalf("GetSettings = %d %s, want 200", r.status, r.body)
	}
	var snap struct {
		Projections []struct {
			ResourceID string `json:"resourceId"`
		} `json:"projections"`
	}
	if err := json.Unmarshal(r.body, &snap); err != nil {
		t.Fatalf("GetSettings reply: %v\n%s", err, r.body)
	}
	ids := make([]string, len(snap.Projections))
	for i, p := range snap.Projections {
		ids[i] = strings.TrimPrefix(p.ResourceID, "settings/")
	}
	return ids
}

func TestEachCallerReadsItsSettingsProjectionsOnly(t *testing.T) {
	var all []string
	for _, p := range settings.Production().Projections {
		all = append(all, p.ID)
	}
	for _, id := range clientProjectionIDs {
		if !slices.Contains(all, id) {
			t.Fatalf("the schema has no projection %q, which a client reads; schema %v", id, all)
		}
	}
	h, uid := startSwitchable(t, t.TempDir(), privilegedUID, clientUID)
	uid.Store(privilegedUID)
	if r := h.post("/v1/InitializeSettings", `{"requestId":"i","settings":{"dns":{"control":true}}}`); r.status != http.StatusOK {
		t.Fatalf("InitializeSettings = %d %s", r.status, r.body)
	}

	// The privileged uid reads every projection, alone or all at once
	if got := projectionIDs(t, h.post("/v1/GetSettings", `{}`)); !slices.Equal(got, all) {
		t.Errorf("the privileged uid asking for every projection got %v, want %v", got, all)
	}
	for _, id := range all {
		if got := projectionIDs(t, h.post("/v1/GetSettings", `{"projectionIds":["`+id+`"]}`)); !slices.Equal(got, []string{id}) {
			t.Errorf("the privileged uid asking for %s got %v", id, got)
		}
	}

	// A client asking for every projection is given its own; one it may not read is to it no such projection
	uid.Store(clientUID)
	if got := projectionIDs(t, h.post("/v1/GetSettings", `{}`)); !slices.Equal(got, clientProjectionIDs) {
		t.Errorf("a client asking for every projection got %v, want %v", got, clientProjectionIDs)
	}
	if got := projectionIDs(t, h.post("/v1/GetSettings", `{"projectionIds":[]}`)); !slices.Equal(got, clientProjectionIDs) {
		t.Errorf("a client asking with an empty list got %v, want %v", got, clientProjectionIDs)
	}
	for _, id := range all {
		got := h.post("/v1/GetSettings", `{"projectionIds":["`+id+`"]}`)
		if slices.Contains(clientProjectionIDs, id) {
			if ids := projectionIDs(t, got); !slices.Equal(ids, []string{id}) {
				t.Errorf("a client asking for %s got %v", id, ids)
			}
			continue
		}
		wantError(t, got, http.StatusBadRequest, codeInvalidArgument, "projectionIds[0]")
		if want := `"no such projection"`; !bytes.Contains(got.body, []byte(want)) {
			t.Errorf("a client asking for %s: %s, want the refusal of a projection that does not exist (%s)", id, got.body, want)
		}
	}
	// One it may not read among its own refuses the call, naming that one
	wantError(t, h.post("/v1/GetSettings", `{"projectionIds":["dns","policy/ip"]}`), http.StatusBadRequest,
		codeInvalidArgument, "projectionIds[1]")
}

func TestEachCallerReadsItsResourcesOnly(t *testing.T) {
	ids := []string{"dnsbl/main", "geo-catalog", "ip-aggregate/deny/ipv4", "ip-set/Abuse/ipv4"}
	for _, c := range []struct {
		who   string
		flags []string
		reads func(id string) bool
	}{
		{"the privileged uid", nil, func(string) bool { return true }},
		{"a client", asClient(), func(id string) bool { return strings.HasPrefix(id, clientResourcePrefix) }},
	} {
		t.Run(c.who, func(t *testing.T) {
			dir := scratchDir(t)
			store := filepath.Join(dir, "store")
			if err := os.Mkdir(store, 0o700); err != nil {
				t.Fatal(err)
			}
			r := &resRig{t: t, dir: store, store: resources.Open(store)}
			req, want := map[string]string{}, map[string]any{}
			for _, id := range ids {
				r.pub(id, nil, "member")
				req[id] = `{}`
				want[id] = errItem("not_found")
				if c.reads(id) {
					want[id] = full("1", r.digest(id), 1, map[string]any{})
				}
			}
			r.core = startCore(t, dir, append([]string{"--resource-dir", store}, c.flags...)...)

			// GetResources answers an id the caller may not read as one the store does not hold
			resJSONEqual(t, r.call(req), want)
			// And GetResourceBody refuses its body the same way
			for _, id := range ids {
				if c.reads(id) {
					wantLines(t, id, r.body(id, "1", "members", ""), "member")
					continue
				}
				wantError(t, r.core.post("GetResourceBody", bodyParams(id, "1", "members", "")), http.StatusNotFound, codeNotFound)
			}
		})
	}
}

func TestAUIDThatIsBothPrivilegedAndAClientIsServedEverything(t *testing.T) {
	state := t.TempDir()
	h, uid := startSwitchable(t, state, privilegedUID, privilegedUID, clientUID)
	uid.Store(privilegedUID)
	table := coreMethods(state, nil, nil, nil, nil)
	for _, name := range slices.Sorted(maps.Keys(table)) {
		if got := h.post("/v1/"+name, `{}`); errorCode(t, got) == codeUnauthenticated {
			t.Errorf("%s: refused as unauthenticated, want it served (body %.200s)", name, got.body)
		}
	}
	if r := h.post("/v1/InitializeSettings", `{"requestId":"i","settings":{"dns":{"control":true}}}`); r.status != http.StatusOK {
		t.Fatalf("InitializeSettings = %d %s", r.status, r.body)
	}
	if got := projectionIDs(t, h.post("/v1/GetSettings", `{}`)); len(got) != len(settings.Production().Projections) {
		t.Errorf("GetSettings gave %v, want every projection", got)
	}
}

func TestConcurrentReportsLeaveOneOfThemRecorded(t *testing.T) {
	state := t.TempDir()
	h := startAs(t, clientUID, state)
	for round := range 20 {
		bodies := [2]string{
			appliedReport(fmt.Sprintf("a%d", round), appliedEntry("dnsbl/feed-a", fmt.Sprint(round+1), digestA)),
			appliedReport(fmt.Sprintf("b%d", round), appliedEntry("dnsbl/feed-b", fmt.Sprint(round+1), digestB)),
		}
		var wg sync.WaitGroup
		var errs [2]error
		begin := make(chan struct{})
		for i, body := range bodies {
			wg.Go(func() {
				<-begin
				resp, err := h.client.Post("http://pfb-core/v1/ReportApplied", "application/json", strings.NewReader(body))
				if err != nil {
					errs[i] = err
					return
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					errs[i] = fmt.Errorf("status %d", resp.StatusCode)
				}
			})
		}
		close(begin)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d: report %d failed: %v", round, i, err)
			}
		}
		if have := recorded(t, state); have != compact(t, bodies[0]) && have != compact(t, bodies[1]) {
			t.Fatalf("round %d: recorded %s, want one of the two reports", round, have)
		}
		entries, err := os.ReadDir(state)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "applied") && e.Name() != "applied.json" {
				t.Fatalf("round %d: a temporary file is left in the state directory: %s", round, e.Name())
			}
		}
	}
}

// refusalBound is the most a refusal to a client may weigh: whatever it sent, so that the replay memory's answers to it
// stay small however many it sends.
const refusalBound = 4 << 10

// startClientWithStore serves Core's real method table, with a resource store, to a further local client.
func startClientWithStore(t *testing.T) *harness {
	t.Helper()
	state, store := t.TempDir(), t.TempDir()
	st, err := settings.Open(state, settings.Production())
	if err != nil {
		t.Fatal(err)
	}
	return start(t, func(o *options) {
		o.methods = coreMethods(state, st, resources.Open(store), nil, nil)
		o.allowUID = privilegedUID
		o.clientUIDs = []uint32{clientUID}
		o.peerUID = func(*net.UnixConn) (uint32, error) { return clientUID, nil }
	}, nil)
}

func TestARefusalToAClientIsSmallWhateverItSent(t *testing.T) {
	big := strings.Repeat("a", 1<<20-512) // with the rest of the request, just under the body limit
	var shortBadIDs, emptyProjections []string
	for i := range maxAppliedResources {
		shortBadIDs = append(shortBadIDs, fmt.Sprintf(`"x%d":{}`, i))
	}
	for range 300000 {
		emptyProjections = append(emptyProjections, `""`)
	}
	cases := map[string]struct{ method, body string }{
		"a report with a 1 MiB id":                     {"ReportApplied", appliedReport("r1", appliedEntry(big, "1", digestA))},
		"a report with a 1 MiB dnsbl id":               {"ReportApplied", appliedReport("r2", appliedEntry("dnsbl/"+big, "1", digestA))},
		"a report with a 1 MiB parameter name":         {"ReportApplied", `{"requestId":"r3","resources":{},"` + big + `":1}`},
		"a report with a mistyped entry of a 1 MiB id": {"ReportApplied", `{"requestId":"r4","resources":{"` + big + `":5}}`},
		"a report of as many bad ids as the bound":     {"ReportApplied", appliedReport("r5", shortBadIDs...)},
		"GetVersion with a 1 MiB parameter name":       {"GetVersion", `{"` + big + `":1}`},
		"GetSettings with a 1 MiB parameter name":      {"GetSettings", `{"` + big + `":1}`},
		"GetSettings naming 300000 projections":        {"GetSettings", `{"projectionIds":[` + strings.Join(emptyProjections, ",") + `]}`},
		"GetResources with a 1 MiB id":                 {"GetResources", `{"resources":{"` + big + `":{}}}`},
		"GetResources with a mistyped 1 MiB id":        {"GetResources", `{"resources":{"` + big + `":5}}`},
		"GetResources with a 1 MiB parameter name":     {"GetResources", `{"resources":{},"` + big + `":1}`},
		"GetResourceBody with a 1 MiB id":              {"GetResourceBody", `{"id":"` + big + `","generation":"1","part":"members"}`},
		"GetResourceBody with a 1 MiB parameter":       {"GetResourceBody", `{"id":"dnsbl/a","generation":"1","part":"members","` + big + `":1}`},
	}
	h := startClientWithStore(t)
	for _, name := range slices.Sorted(maps.Keys(cases)) {
		t.Run(name, func(t *testing.T) {
			got := h.post("/v1/"+cases[name].method, cases[name].body)
			if code := errorCode(t, got); code != codeInvalidArgument {
				t.Errorf("answered %d %.200s, want invalid_argument", got.status, got.body)
			}
			if len(got.body) >= refusalBound {
				t.Errorf("the refusal is %d bytes, want under %d: %.300s", len(got.body), refusalBound, got.body)
			}
		})
	}
}

// otherClientUID is a second further local client.
const otherClientUID = 1003

func TestEachClientUIDHasItsOwnReplayMemory(t *testing.T) {
	state := t.TempDir()
	h, uid := startSwitchable(t, state, privilegedUID, clientUID, otherClientUID)
	recordedReport := appliedReport("same", appliedEntry("dnsbl/manifest", "3", digestA))
	refusedReport := appliedReport("same", appliedEntry("ip-set/g/ipv4", "3", digestA))

	// Given one client recorded a report under requestId "same"
	uid.Store(clientUID)
	first := h.post("/v1/ReportApplied", recordedReport)
	wantJSON(t, first, http.StatusOK, `{}`)

	// When another client sends another body under the same requestId, it is its own request: run, not a conflict
	uid.Store(otherClientUID)
	other := h.post("/v1/ReportApplied", refusedReport)
	wantError(t, other, http.StatusBadRequest, codeInvalidArgument, "resources")

	// Then each one's repeat gets its own first answer
	uid.Store(clientUID)
	if again := h.post("/v1/ReportApplied", recordedReport); again.status != first.status || !bytes.Equal(again.body, first.body) {
		t.Errorf("the first client's repeat got %d %s, want its first answer %d %s", again.status, again.body, first.status, first.body)
	}
	uid.Store(otherClientUID)
	if again := h.post("/v1/ReportApplied", refusedReport); again.status != other.status || !bytes.Equal(again.body, other.body) {
		t.Errorf("the other client's repeat got %d %s, want its first answer %d %s", again.status, again.body, other.status, other.body)
	}
	if have, want := recorded(t, state), compact(t, recordedReport); have != want {
		t.Errorf("recorded:\n have %s\n want %s", have, want)
	}
}

func TestAMethodCalledWithoutACallersMarkServesOnlyWhatAClientMayRead(t *testing.T) {
	state, storeDir := t.TempDir(), t.TempDir()
	st, err := settings.Open(state, settings.Production())
	if err != nil {
		t.Fatal(err)
	}
	r := &resRig{t: t, dir: storeDir, store: resources.Open(storeDir)}
	r.pub("dnsbl/main", nil, "member")
	r.pub("ip-set/Abuse/ipv4", nil, "member")
	table := coreMethods(state, st, r.store, nil, nil)
	unmarked := context.Background() // no path through the server: no mark says who calls
	if _, err := table["InitializeSettings"].call(unmarked, []byte(`{"requestId":"i","settings":{"dns":{"control":true}}}`)); err != nil {
		t.Fatalf("InitializeSettings: %v", err)
	}

	// GetSettings gives a client's projections only
	snap, err := table["GetSettings"].call(unmarked, []byte(`{}`))
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	raw, _ := json.Marshal(snap)
	if got := projectionIDs(t, reply{status: http.StatusOK, body: raw}); !slices.Equal(got, clientProjectionIDs) {
		t.Errorf("GetSettings without a mark gave %v, want a client's %v", got, clientProjectionIDs)
	}

	// GetResources and GetResourceBody hold no resource outside dnsbl/*
	res, err := table["GetResources"].call(unmarked, []byte(`{"resources":{"dnsbl/main":{},"ip-set/Abuse/ipv4":{}}}`))
	if err != nil {
		t.Fatalf("GetResources: %v", err)
	}
	items := res.(map[string]any)["resources"].(map[string]resourceItem)
	if e := items["ip-set/Abuse/ipv4"].Error; e == nil || e.Code != codeNotFound {
		t.Errorf("GetResources without a mark served ip-set/Abuse/ipv4: %+v, want not_found", items["ip-set/Abuse/ipv4"])
	}
	if items["dnsbl/main"].Error != nil {
		t.Errorf("GetResources without a mark refused dnsbl/main: %+v", items["dnsbl/main"])
	}
	body, err := table["GetResourceBody"].call(unmarked, []byte(`{"id":"ip-set/Abuse/ipv4","generation":"1","part":"members"}`))
	if b, ok := body.(*bodyStream); ok {
		_ = b.f.Close()
	}
	if e, ok := err.(*apiError); !ok || e.Code != codeNotFound {
		t.Errorf("GetResourceBody without a mark = %v, %v; want not_found", body, err)
	}
}

// A key that is not a resource id is one field error however many such keys a request holds.
func TestBadKeysGetOneFieldError(t *testing.T) {
	h := startClientWithStore(t)
	wantError(t, h.post("/v1/ReportApplied", `{"requestId":"b1","resources":{"x1":{},"x2":{},"x3":{}}}`),
		http.StatusBadRequest, codeInvalidArgument, "resources")
	wantError(t, h.post("/v1/GetResources", `{"resources":{"x1":{},"x2":{},"x3":{}}}`),
		http.StatusBadRequest, codeInvalidArgument, "resources")
}

// The 4 KiB cap on a refusal is the client's only: the privileged caller keeps every field error.
func TestAPrivilegedRefusalKeepsItsFieldErrorsAboveTheClientCap(t *testing.T) {
	var entries []string
	for i := range 200 {
		entries = append(entries, appliedEntry(fmt.Sprintf("dnsbl/r%d", i), "z", digestA))
	}
	got := startAs(t, privilegedUID, t.TempDir()).post("/v1/ReportApplied", appliedReport("p1", entries...))
	if code := errorCode(t, got); code != codeInvalidArgument {
		t.Fatalf("answered %d %.200s, want invalid_argument", got.status, got.body)
	}
	if len(got.body) < refusalBound {
		t.Fatalf("the refusal is %d bytes, want %d or more to cross the client cap", len(got.body), refusalBound)
	}
	var env struct {
		Error struct {
			FieldErrors []json.RawMessage `json:"fieldErrors"`
		} `json:"error"`
	}
	if err := json.Unmarshal(got.body, &env); err != nil || len(env.Error.FieldErrors) != len(entries) {
		t.Errorf("fieldErrors = %d, %v; want %d", len(env.Error.FieldErrors), err, len(entries))
	}
}

package main

import (
	"bytes"
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

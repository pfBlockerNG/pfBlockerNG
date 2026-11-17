package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
)

// The projections of the whole Update loop (issue #4031) over the API: the schema lists them in the protocol's order, a read
// shows the three secrets of extras as their presence only, a change set that names a read-only projection is refused whole,
// and a writable one saves and reads back.

const extrasSecret = "SECRET-value-never-shown"

// startProjections serves the settings methods over a file backend that holds the three extras secrets and a MaxMind account.
func startProjections(t *testing.T, secret string) (*harness, *settings.Store) {
	t.Helper()
	dir := t.TempDir()
	values := `{"maxmindAccount":"424242"}`
	if secret != "" {
		values = `{"maxmindAccount":"424242","maxmindKey":"Key_` + "SECRET" + `","ipinfoToken":"` + secret + `","top1mToken":"` + secret + `.2"}`
	}
	doc := `{"format":1,"revision":1,"projections":{"extras":{"values":` + values + `}}}`
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := settings.Open(dir, settings.Production())
	if err != nil {
		t.Fatal(err)
	}
	return start(t, func(o *options) {
		for name, m := range settingsMethods(st) {
			o.methods[name] = m
		}
	}, nil), st
}

func TestGetSettingsSchemaListsTheProjectionsOfTheUpdateLoopInProtocolOrderWithTheirSecrets(t *testing.T) {
	h := startSettings(t)
	got := h.post("/v1/GetSettingsSchema", `{}`)
	var schema struct {
		Projections []struct {
			ID     string `json:"id"`
			Fields []struct {
				Name   string `json:"name"`
				Secret bool   `json:"secret"`
			} `json:"fields"`
		} `json:"projections"`
	}
	if err := json.Unmarshal(got.body, &schema); err != nil || got.status != http.StatusOK {
		t.Fatalf("GetSettingsSchema = %d %s: %v", got.status, got.body, err)
	}
	var ids, secrets []string
	for _, p := range schema.Projections {
		ids = append(ids, p.ID)
		for _, f := range p.Fields {
			if f.Secret {
				secrets = append(secrets, p.ID+"."+f.Name)
			}
		}
	}
	if want := []string{"dns", "feeds/ipv4", "feeds/ipv6", "feeds/dnsbl", "schedule", "ingest", "policy/ip", "feeds/geoip", "policy/dnsbl", "extras", "hooks", "maintenance"}; !slices.Equal(ids, want) {
		t.Errorf("projections = %v, want %v", ids, want)
	}
	if want := []string{"ingest.proxyPassword", "extras.maxmindKey", "extras.ipinfoToken", "extras.top1mToken"}; !slices.Equal(secrets, want) {
		t.Errorf("top-level secret fields = %v, want %v", secrets, want)
	}
}

func TestGetSettingsShowsEachExtrasSecretAsItsPresenceAndNeverItsValue(t *testing.T) {
	for name, secret := range map[string]string{"set": extrasSecret, "empty": ""} {
		t.Run(name, func(t *testing.T) {
			h, st := startProjections(t, secret)
			present := map[bool]string{true: "true", false: "false"}[secret != ""]
			for _, body := range []string{`{}`, `{"projectionIds":["extras"]}`} {
				got := h.post("/v1/GetSettings", body)
				if got.status != http.StatusOK || bytes.Contains(got.body, []byte("SECRET")) {
					t.Errorf("GetSettings %s = %d %s, want 200 without a secret's value", body, got.status, got.body)
				}
				for _, field := range []string{"maxmindKey", "ipinfoToken", "top1mToken"} {
					if want := `"` + field + `":{"present":` + present + `}`; !bytes.Contains(got.body, []byte(want)) {
						t.Errorf("GetSettings %s does not show %s:\n%s", body, want, got.body)
					}
				}
				if !bytes.Contains(got.body, []byte(`"maxmindAccount":"424242"`)) {
					t.Errorf("GetSettings %s = %s, want the account, which is no secret", body, got.body)
				}
			}
			if clear, err := st.GetClear("extras"); err != nil || clear["ipinfoToken"] != secret {
				t.Errorf("GetClear ipinfoToken = %v, %v, want the value for code in the process", clear["ipinfoToken"], err)
			}
		})
	}
}

func TestSaveSettingsRefusesAChangeSetThatNamesHooksOrABoxFactAndWritesNothing(t *testing.T) {
	h, _ := startProjections(t, extrasSecret)
	n := 0
	for name, changes := range map[string]struct{ body, field string }{
		"hooks with a row":              {`{"hooks":{"rows":[{"id":"0","when":"pre","script":"hook_pre_a.sh","description":"","timeout":60,"enabled":true}]}}`, "changes.hooks"},
		"hooks empty":                   {`{"hooks":{}}`, "changes.hooks"},
		"hooks null":                    {`{"hooks":null}`, "changes.hooks"},
		"scheduled work disabled":       {`{"ingest":{"scheduledWorkDisabled":true}}`, "changes.ingest"},
		"a sinkhole address":            {`{"ingest":{"sinkholeV4":"10.10.10.1"}}`, "changes.ingest"},
		"hooks beside a writable field": {`{"policy/ip":{"dedup":true},"hooks":{"rows":[]}}`, "changes.hooks"},
	} {
		t.Run(name, func(t *testing.T) {
			n++
			wantError(t, h.post("/v1/SaveSettings", `{"requestId":"r`+strconv.Itoa(n)+`","expectedRevision":1,"changes":`+changes.body+`}`),
				http.StatusBadRequest, codeInvalidArgument, changes.field)
			wantError(t, h.post("/v1/ValidateSettings", `{"changes":`+changes.body+`}`), http.StatusBadRequest, codeInvalidArgument, changes.field)
			got := h.post("/v1/GetSettings", `{"projectionIds":["policy/ip","ingest","hooks"]}`)
			for _, want := range []string{`"revision":1`, `"dedup":false`, `"scheduledWorkDisabled":false`, `"sinkholeV4":""`, `"rows":[]`} {
				if !bytes.Contains(got.body, []byte(want)) {
					t.Errorf("after the refused change GetSettings lacks %s: nothing may have changed\n%s", want, got.body)
				}
			}
		})
	}
}

func TestSaveSettingsStoresAChangeToAWritableProjectionOfTheUpdateLoop(t *testing.T) {
	h, _ := startProjections(t, extrasSecret)
	if got := h.post("/v1/GetSettings", `{"projectionIds":["policy/ip"]}`); !bytes.Contains(got.body, []byte(`"dedup":false`)) {
		t.Fatalf("before-state: dedup is off, got %s", got.body)
	}

	got := h.post("/v1/SaveSettings", `{"requestId":"s1","expectedRevision":1,"changes":{"policy/ip":{"dedup":true,"suppressionV4":[{"cidr":"10.0.0.0/8"}]},"extras":{"maxmindLocale":"de"}}}`)
	if got.status != http.StatusOK || !bytes.Contains(got.body, []byte(`"revision":2`)) {
		t.Fatalf("SaveSettings = %d %s, want revision 2", got.status, got.body)
	}

	read := h.post("/v1/GetSettings", `{"projectionIds":["policy/ip","extras"]}`)
	for _, want := range []string{`"dedup":true`, `"suppressionV4":[{"cidr":"10.0.0.0/8"}]`, `"maxmindLocale":"de"`, `"ipinfoToken":{"present":true}`} {
		if !bytes.Contains(read.body, []byte(want)) {
			t.Errorf("GetSettings after the save lacks %s (a secret Core was not given again stays set):\n%s", want, read.body)
		}
	}
	if bytes.Contains(read.body, []byte("SECRET")) {
		t.Errorf("GetSettings after the save shows a secret's value:\n%s", read.body)
	}
}

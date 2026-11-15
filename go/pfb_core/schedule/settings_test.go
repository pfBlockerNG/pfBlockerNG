package schedule

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The schedule projection's parity fixture (issue #3941), tests/core/fixtures/settings_schedule_parity.json, frozen against
// today's PHP by tests/php/CoreSettingsScheduleParityTest.php. A case holds the config.xml sections, the projection values
// the adapter reads from them, and the model PHP's pfb_schedule_runtime_config() computes from them (null: PHP rejects the
// config). Core builds its model from the projections: it must be PHP's, config_hash included.
type settingsFixtureCase struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Config      struct {
		Gen       map[string]any `json:"gen"`
		IPv4      []any          `json:"ipv4"`
		IPv6      []any          `json:"ipv6"`
		DNSBL     []any          `json:"dnsbl"`
		Blacklist map[string]any `json:"blacklist"`
	} `json:"config"`
	Schedule map[string]any            `json:"schedule"`
	Feeds    map[string]map[string]any `json:"feeds"`
	Model    *struct {
		ConfigHash string   `json:"config_hash"`
		Scheduled  bool     `json:"scheduled"`
		Default    Schedule `json:"default"`
		Entries    []Entry  `json:"entries"` // an Entry's fields read from id, cadence, enabled and override
	} `json:"model"`
}

func loadSettingsFixture(t *testing.T) []settingsFixtureCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "core", "fixtures", "settings_schedule_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema int                   `json:"schema"`
		Cases  []settingsFixtureCase `json:"cases"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("the fixture does not read: %v", err)
	}
	if doc.Schema != 1 || len(doc.Cases) == 0 {
		t.Fatalf("fixture schema %d with %d cases", doc.Schema, len(doc.Cases))
	}
	return doc.Cases
}

// runtimeModelOfConfig is RuntimeModel and BlacklistExtra over the case's config.xml sections, with the registry's defaults
// (on, Sunday 00:00) for the General keys it leaves out, as pfb_schedule_runtime_config() reads them.
func (c settingsFixtureCase) runtimeModelOfConfig(t *testing.T) (Model, error) {
	t.Helper()
	general := map[string]any{"pfb_scheduled_feed_updates": "on", "pfb_schedule_weekday": "7", "pfb_schedule_hour": "0", "pfb_schedule_minute": "0"}
	for k, v := range c.Config.Gen {
		general[k] = v
	}
	list := func(groups []any) any {
		if groups == nil {
			return []any{}
		}
		return groups
	}
	sections := map[string]any{"ipv4": list(c.Config.IPv4), "ipv6": list(c.Config.IPv6), "dnsbl": list(c.Config.DNSBL)}
	bl, err := BlacklistExtra(c.Config.Blacklist)
	if err != nil {
		t.Fatalf("%s: %v", c.ID, err)
	}
	return RuntimeModel(general, sections, &Extras{DCC: true, BL: bl})
}

func TestModelFromSettingsIsTodaysModelOnEveryFixtureCase(t *testing.T) {
	for _, c := range loadSettingsFixture(t) {
		t.Run(c.ID, func(t *testing.T) {
			viaConfig, configErr := c.runtimeModelOfConfig(t)
			got, err := ModelFromSettings(c.Schedule, c.Feeds)
			if err != nil {
				t.Fatalf("%s\nModelFromSettings: %v", c.Description, err)
			}
			if c.Model == nil {
				// PHP rejects the whole config; the projections carry what the adapter reads, so Core has a model of them
				if configErr == nil {
					t.Fatalf("%s\nRuntimeModel accepts a config PHP rejects", c.Description)
				}
				slot := Schedule{Weekday: int(c.Schedule["weekday"].(float64)), Hour: int(c.Schedule["hour"].(float64)), Minute: int(c.Schedule["minute"].(float64))}
				if got.Default != slot {
					t.Errorf("%s\ndefault slot %+v, want what the projection reads: %+v", c.Description, got.Default, slot)
				}
				return
			}
			if configErr != nil {
				t.Fatalf("%s\nRuntimeModel rejects the config: %v", c.Description, configErr)
			}
			want := Model{ConfigHash: c.Model.ConfigHash, Scheduled: c.Model.Scheduled, Default: c.Model.Default, Entries: c.Model.Entries}
			if !reflect.DeepEqual(viaConfig, want) {
				t.Errorf("%s\nRuntimeModel of the config\n %+v\nPHP\n %+v", c.Description, viaConfig, want)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s\nModelFromSettings\n %+v\nPHP\n %+v", c.Description, got, want)
			}
		})
	}
}

// What Core's store serves has Go integers where a decoded document has float64: both build the same model.
func TestModelFromSettingsTakesIntegersAsTheStoreHoldsThem(t *testing.T) {
	sched := map[string]any{"scheduledUpdates": true, "weekday": int64(3), "hour": int64(2), "minute": int64(15), "groups": []any{
		map[string]any{"id": "ipv4/A", "override": true, "weekday": int64(5), "hour": int64(13), "minute": int64(45)}},
		"categoryUpdates": false, "categoryFrequency": "Never", "categoryProviders": []any{}}
	feeds := map[string]map[string]any{
		"feeds/ipv4": {"groups": []any{map[string]any{"name": "A", "action": "Deny_Inbound", "updateFrequency": "EveryDay", "feeds": []any{
			map[string]any{"header": "F", "state": "enabled", "url": "https://example.org/f"}}}}},
		"feeds/ipv6":  {"groups": []any{}},
		"feeds/dnsbl": {"groups": []any{}},
	}
	got, err := ModelFromSettings(sched, feeds)
	if err != nil {
		t.Fatal(err)
	}
	want := Entry{ID: "ipv4:F_v4", Cadence: "EveryDay", Enabled: true, Override: &Schedule{Weekday: 5, Hour: 13, Minute: 45}}
	if got.Default != (Schedule{Weekday: 3, Hour: 2, Minute: 15}) || len(got.Entries) != 3 || !reflect.DeepEqual(got.Entries[0], want) {
		t.Errorf("ModelFromSettings = %+v, want the default 3/2/15 and %+v first", got, want)
	}
}

// A value the settings store never serves is an error, not a model and not a panic.
func TestModelFromSettingsRefusesWhatTheStoreNeverServes(t *testing.T) {
	good := func() (map[string]any, map[string]map[string]any) {
		return map[string]any{"scheduledUpdates": true, "weekday": 7.0, "hour": 0.0, "minute": 0.0, "groups": []any{},
				"categoryUpdates": false, "categoryFrequency": "Never", "categoryProviders": []any{}},
			map[string]map[string]any{"feeds/ipv4": {"groups": []any{}}, "feeds/ipv6": {"groups": []any{}}, "feeds/dnsbl": {"groups": []any{}}}
	}
	sched, feeds := good()
	if _, err := ModelFromSettings(sched, feeds); err != nil {
		t.Fatalf("the control is refused: %v", err)
	}
	for name, spoil := range map[string]func(sched map[string]any, feeds map[string]map[string]any){
		"scheduledUpdates a string":  func(s map[string]any, _ map[string]map[string]any) { s["scheduledUpdates"] = "on" },
		"weekday a string":           func(s map[string]any, _ map[string]map[string]any) { s["weekday"] = "7" },
		"weekday 8":                  func(s map[string]any, _ map[string]map[string]any) { s["weekday"] = 8.0 },
		"minute 20":                  func(s map[string]any, _ map[string]map[string]any) { s["minute"] = 20.0 },
		"hour a fraction":            func(s map[string]any, _ map[string]map[string]any) { s["hour"] = 1.5 },
		"groups not a list":          func(s map[string]any, _ map[string]map[string]any) { s["groups"] = "x" },
		"a group not an object":      func(s map[string]any, _ map[string]map[string]any) { s["groups"] = []any{"x"} },
		"categoryFrequency unknown":  func(s map[string]any, _ map[string]map[string]any) { s["categoryFrequency"] = "Daily" },
		"a provider not an object":   func(s map[string]any, _ map[string]map[string]any) { s["categoryProviders"] = []any{1.0} },
		"a feeds projection missing": func(_ map[string]any, f map[string]map[string]any) { delete(f, "feeds/dnsbl") },
		"a feeds groups missing":     func(_ map[string]any, f map[string]map[string]any) { f["feeds/ipv4"] = map[string]any{} },
		"a feed state unknown": func(_ map[string]any, f map[string]map[string]any) {
			f["feeds/ipv4"] = map[string]any{"groups": []any{map[string]any{"name": "A", "action": "Disabled", "updateFrequency": "Never",
				"feeds": []any{map[string]any{"header": "F", "state": "on", "url": "u"}}}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			sched, feeds := good()
			spoil(sched, feeds)
			if m, err := ModelFromSettings(sched, feeds); err == nil {
				t.Errorf("ModelFromSettings accepted it: %+v", m)
			}
		})
	}
	if _, err := ModelFromSettings(nil, nil); err == nil {
		t.Error("ModelFromSettings(nil, nil) accepted it")
	}
}

// Which fault ModelFromSettings reports does not depend on map order: with several bad slot fields it names the first of
// weekday, hour and minute, so a log line and a test see the same one every time.
func TestModelFromSettingsNamesTheFirstBadSlotFieldEveryTime(t *testing.T) {
	feeds := map[string]map[string]any{"feeds/ipv4": {"groups": []any{}}, "feeds/ipv6": {"groups": []any{}}, "feeds/dnsbl": {"groups": []any{}}}
	for i := 0; i < 50; i++ {
		general := map[string]any{"scheduledUpdates": true, "weekday": "x", "hour": "y", "minute": "z", "groups": []any{},
			"categoryUpdates": false, "categoryFrequency": "Never", "categoryProviders": []any{}}
		if _, err := ModelFromSettings(general, feeds); err == nil || err.Error() != "schedule: weekday is not a whole number" {
			t.Fatalf("run %d: the default slot's fault = %v, want the weekday's", i, err)
		}
		group := map[string]any{"id": "ipv4/A", "override": true, "weekday": "x", "hour": "y", "minute": "z"}
		sched := map[string]any{"scheduledUpdates": true, "weekday": 7.0, "hour": 0.0, "minute": 0.0, "groups": []any{group},
			"categoryUpdates": false, "categoryFrequency": "Never", "categoryProviders": []any{}}
		if _, err := ModelFromSettings(sched, feeds); err == nil || err.Error() != "schedule: groups[0].weekday is not a whole number" {
			t.Fatalf("run %d: the group slot's fault = %v, want the weekday's", i, err)
		}
	}
}

func TestCustomParentCadenceModelAndPlan(t *testing.T) {
	now := time.Date(2026, 11, 13, 10, 20, 0, 0, time.UTC).Unix()
	occ := now - 20*60
	for _, family := range families {
		for _, regular := range []bool{false, true} {
			for _, mode := range []string{"due", "Never", "notdue", "disabled", "updates-off", "empty", "zero", "blank", "override"} {
				t.Run(family+"/"+mode+map[bool]string{false: "/custom-only", true: "/mixed"}[regular], func(t *testing.T) {
					action := "Deny_Inbound"
					if family == "dnsbl" {
						action = "unbound"
					}
					sched := map[string]any{"scheduledUpdates": mode != "updates-off", "weekday": 5, "hour": 3, "minute": 0,
						"groups": []any{}, "categoryUpdates": false, "categoryFrequency": "Never", "categoryProviders": []any{}}
					group := map[string]any{"name": "A", "action": action, "updateFrequency": "01hour", "customList": "example.org\n", "feeds": []any{}}
					if mode == "Never" {
						group["updateFrequency"] = "Never"
					}
					if mode == "disabled" {
						group["action"] = "Disabled"
					}
					switch mode {
					case "empty":
						group["customList"] = ""
					case "zero":
						group["customList"] = "0"
					case "blank":
						group["customList"] = " \n\t"
					}
					if mode == "override" {
						sched["groups"] = []any{map[string]any{"id": family + "/A", "override": true, "weekday": 5, "hour": 3, "minute": 15}}
					}
					suffix := map[string]string{"ipv4": "_v4", "ipv6": "_v6"}[family]
					if regular {
						group["feeds"] = []any{map[string]any{"header": "F", "state": "enabled", "url": "https://example.org/f"}}
					}
					feeds := map[string]map[string]any{"feeds/ipv4": {"groups": []any{}}, "feeds/ipv6": {"groups": []any{}}, "feeds/dnsbl": {"groups": []any{}}}
					feeds["feeds/"+family]["groups"] = []any{group}
					m, err := ModelFromSettings(sched, feeds)
					if err != nil {
						t.Fatal(err)
					}
					custom := mode != "empty" && mode != "blank"
					enabled := mode != "Never" && mode != "disabled" && mode != "updates-off"
					var override *Schedule
					if mode == "override" {
						override = &Schedule{5, 3, 15}
					}
					want := []Entry{}
					if regular {
						want = append(want, Entry{ID: family + ":F" + suffix, Cadence: group["updateFrequency"].(string), Enabled: enabled, Override: override})
					}
					id := "custom:" + family + ":A"
					if custom {
						want = append(want, Entry{ID: id, Cadence: group["updateFrequency"].(string), Enabled: enabled, Override: override})
					}
					want = append(want, Entry{ID: "extra:dcc", Cadence: "EveryDay", Enabled: true}, Entry{ID: "extra:bl", Cadence: "EveryDay"})
					if !reflect.DeepEqual(m.Entries, want) {
						t.Fatalf("entries=%+v want=%+v", m.Entries, want)
					}
					st := State{}
					if mode == "notdue" {
						for _, e := range m.Entries {
							st[e.ID] = Item{LastCompletedOccurrence: &occ, CompletionOutcome: Success}
						}
					}
					plan := FeedPlan(m, st, now, time.UTC)
					var due []string
					if enabled && mode != "notdue" {
						if regular {
							due = append(due, family+":F"+suffix)
						}
						if custom {
							due = append(due, id)
						}
					}
					if !reflect.DeepEqual(plan.Due, due) {
						t.Fatalf("due=%v want=%v", plan.Due, due)
					}
					if custom && enabled && mode != "notdue" {
						wantOcc := occ
						if override != nil {
							wantOcc += 15 * 60
						}
						if plan.Occurrences[id] != wantOcc {
							t.Fatalf("custom occurrence=%d want=%d", plan.Occurrences[id], wantOcc)
						}
						reserved, err := Reserve(st, plan.Occurrences)
						if err != nil {
							t.Fatal(err)
						}
						if retry := FeedPlan(m, reserved, now, time.UTC); !reflect.DeepEqual(retry.Due, due) {
							t.Fatalf("pending custom dropped from retry: %+v", retry)
						}
					}
					t.Logf("model IDs=%v due=%v", m.Entries, plan.Due)
				})
			}
		}
	}
}

func TestCustomRuntimeModelIdentityBoundary(t *testing.T) {
	for _, family := range families {
		limit := 64 - len("custom:"+family+":")
		for _, name := range []string{"A", strings.Repeat("A", limit), "", "bad-name", "bad:name", "bad/name", "bad\n", strings.Repeat("A", limit+1)} {
			t.Run(family+"/"+name, func(t *testing.T) {
				action := "Deny_Inbound"
				if family == "dnsbl" {
					action = "unbound"
				}
				general := map[string]any{"pfb_scheduled_feed_updates": "on", "pfb_schedule_weekday": "5", "pfb_schedule_hour": "3", "pfb_schedule_minute": "0"}
				group := map[string]any{"aliasname": name, "action": action, "cron": "01hour", "custom": "x"}
				sections := map[string]any{"ipv4": []any{}, "ipv6": []any{}, "dnsbl": []any{}}
				sections[family] = []any{group}
				m, err := RuntimeModel(general, sections, nil)
				valid := name == "A" || len(name) == limit
				if !valid {
					if err == nil {
						t.Fatalf("invalid custom name accepted: %+v", m)
					}
					return
				}
				if err != nil || len(m.Entries) != 1 || m.Entries[0].ID != "custom:"+family+":"+name {
					t.Fatalf("custom entry=%+v err=%v", m, err)
				}
				sections[family] = []any{group, group}
				if _, err := RuntimeModel(general, sections, nil); err == nil {
					t.Fatal("duplicate custom ID accepted")
				}
			})
		}
	}
	for _, family := range families {
		general := map[string]any{"pfb_scheduled_feed_updates": "on", "pfb_schedule_weekday": "5", "pfb_schedule_hour": "3", "pfb_schedule_minute": "0"}
		sections := map[string]any{"ipv4": []any{}, "ipv6": []any{}, "dnsbl": []any{}}
		sections[family] = []any{map[string]any{"aliasname": "A", "action": "Disabled", "cron": "01hour", "custom": "0"}}
		m, err := RuntimeModel(general, sections, nil)
		if err != nil || len(m.Entries) != 0 {
			t.Fatalf("raw config PHP-empty zero became custom: %+v err=%v", m, err)
		}
	}
	// Identical names in different families occupy distinct namespaces; regular IDs remain distinct too.
	general := map[string]any{"pfb_scheduled_feed_updates": "on", "pfb_schedule_weekday": "5", "pfb_schedule_hour": "3", "pfb_schedule_minute": "0"}
	sections := map[string]any{}
	for _, family := range families {
		action := "Deny_Inbound"
		if family == "dnsbl" {
			action = "unbound"
		}
		sections[family] = []any{map[string]any{"aliasname": "A", "action": action, "cron": "01hour", "custom": "x",
			"row": []any{map[string]any{"header": "A", "url": "u", "state": "Enabled"}}}}
	}
	m, err := RuntimeModel(general, sections, nil)
	if err != nil || len(m.Entries) != 6 {
		t.Fatalf("namespace collision: %+v err=%v", m, err)
	}
}

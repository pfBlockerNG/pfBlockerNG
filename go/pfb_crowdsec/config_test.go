package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validConfigMap() map[string]any {
	return map[string]any{
		"api_url":          "https://lapi.example.test:8080/",
		"api_key":          testKey,
		"update_frequency": "10s",
		"table_v4":         "crowdsec_v4",
		"table_v6":         "crowdsec_v6",
		"log_level":        "info",
		"status_file":      "/var/run/pfb_crowdsec.json",
		"decisions_dir":    "/var/run/pfb_crowdsec",
	}
}

func configJSON(t *testing.T, m map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseConfigReadsTheD3File(t *testing.T) {
	cfg, err := parseConfig(configJSON(t, validConfigMap()))
	if err != nil {
		t.Fatalf("parseConfig(valid) = %v", err)
	}
	if cfg.APIURL != "https://lapi.example.test:8080/" || cfg.APIKey != testKey || cfg.TableV4 != "crowdsec_v4" ||
		cfg.TableV6 != "crowdsec_v6" || cfg.StatusFile != "/var/run/pfb_crowdsec.json" {
		t.Fatalf("parsed config = %+v; want the file's values", cfg)
	}
	if cfg.interval != 10*time.Second || cfg.level != levelInfo {
		t.Fatalf("interval, level = %v, %d; want 10s, info", cfg.interval, cfg.level)
	}
}

func TestParseConfigDefaultsTheOptionalValues(t *testing.T) {
	m := validConfigMap()
	for _, key := range []string{"update_frequency", "table_v4", "table_v6", "log_level", "status_file", "decisions_dir"} {
		delete(m, key)
	}
	cfg, err := parseConfig(configJSON(t, m))
	if err != nil {
		t.Fatalf("parseConfig(minimal) = %v", err)
	}
	if cfg.interval != 10*time.Second || cfg.TableV4 != "crowdsec_v4" || cfg.TableV6 != "crowdsec_v6" ||
		cfg.level != levelInfo || cfg.StatusFile != "/var/run/pfb_crowdsec.json" || cfg.DecisionsDir != "/var/run/pfb_crowdsec" {
		t.Fatalf("defaults = %+v (interval %v, level %d); want the D3 values", cfg, cfg.interval, cfg.level)
	}
}

func TestParseConfigAcceptsALongerUpdateFrequency(t *testing.T) {
	m := validConfigMap()
	m["update_frequency"] = "1m"
	cfg, err := parseConfig(configJSON(t, m))
	if err != nil || cfg.interval != time.Minute {
		t.Fatalf("parseConfig(1m) = %+v, %v; want interval 1m", cfg, err)
	}
}

// Every rejected value is an error, and no error message repeats the key.
func TestParseConfigRejectsHostileValues(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		value any
	}{
		{"url ftp scheme", "api_url", "ftp://lapi.example.test/"},
		{"url no host", "api_url", "http://"},
		{"url relative", "api_url", "lapi.example.test:8080"},
		{"url userinfo", "api_url", "https://user:pw@lapi.example.test/"},
		{"url query", "api_url", "https://lapi.example.test/?x=1"},
		{"url fragment", "api_url", "https://lapi.example.test/#x"},
		{"url space", "api_url", "https://lapi example.test/"},
		{"url leading space", "api_url", " https://lapi.example.test/"},
		{"url javascript", "api_url", "javascript:alert(1)"},
		{"url empty", "api_url", ""},
		{"key empty", "api_key", ""},
		{"key too long", "api_key", strings.Repeat("k", 257)},
		{"key space", "api_key", "abc def"},
		{"key tab", "api_key", "abc\tdef"},
		{"key newline", "api_key", "abc\ndef"},
		{"key non-ascii", "api_key", "abcdé"},
		{"key control", "api_key", "abc\x7fdef"},
		{"key number", "api_key", 12345},
		{"frequency below minimum", "update_frequency", "5s"},
		{"frequency negative", "update_frequency", "-10s"},
		{"frequency garbage", "update_frequency", "ten seconds"},
		{"frequency number", "update_frequency", 10},
		{"table v4 empty", "table_v4", ""},
		{"table v4 dash", "table_v4", "-f"},
		{"table v4 space", "table_v4", "crowdsec v4"},
		{"table v4 metachar", "table_v4", "crowdsec_v4;rm"},
		{"table v4 too long", "table_v4", strings.Repeat("t", 32)},
		{"table v6 same as v4", "table_v6", "crowdsec_v4"},
		{"log level unknown", "log_level", "verbose"},
		{"status relative", "status_file", "pfb_crowdsec.json"},
		{"status nul", "status_file", "/var/run/pfb\x00crowdsec.json"},
		{"status empty", "status_file", ""},
		{"decisions relative", "decisions_dir", "pfb_crowdsec"},
		{"decisions nul", "decisions_dir", "/var/run/pfb\x00crowdsec"},
		{"decisions empty", "decisions_dir", ""},
		{"decisions root", "decisions_dir", "/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validConfigMap()
			m[tc.key] = tc.value
			cfg, err := parseConfig(configJSON(t, m))
			if err == nil {
				t.Fatalf("parseConfig accepted %s = %#v (config %+v)", tc.key, tc.value, cfg)
			}
			if s, isString := tc.value.(string); isString && tc.key == "api_key" && s != "" &&
				strings.Contains(err.Error(), s) {
				t.Fatalf("error %q repeats the key", err)
			}
			if strings.Contains(err.Error(), testKey) {
				t.Fatalf("error %q contains the configured key", err)
			}
		})
	}
}

func TestParseConfigRejectsStructuralProblems(t *testing.T) {
	cases := map[string]string{
		"unknown key":   `{"api_url":"https://l.test/","api_key":"k","anchor":"x"}`,
		"trailing data": `{"api_url":"https://l.test/","api_key":"k"} {}`,
		"not an object": `["https://l.test/"]`,
		"truncated":     `{"api_url":"https://l.test/","api_key":"k"`,
		"empty":         ``,
		"null":          `null`,
	}
	for name, raw := range cases {
		if cfg, err := parseConfig([]byte(raw)); err == nil {
			t.Errorf("%s: parseConfig(%q) = %+v, nil; want an error", name, raw, cfg)
		}
	}
}

func TestLoadConfigReadsAFileAndRefusesAMissingOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pfb_crowdsec.json")
	if err := os.WriteFile(path, configJSON(t, validConfigMap()), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil || cfg.APIKey != testKey {
		t.Fatalf("loadConfig(valid file) = %+v, %v", cfg, err)
	}
	if _, err := loadConfig(path + ".missing"); err == nil {
		t.Fatal("loadConfig(missing file) = nil error")
	}
}

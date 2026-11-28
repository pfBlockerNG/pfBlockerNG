package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_crowdsec/spoa"
)

const (
	minInterval          = 10 * time.Second
	minAppSecTimeout     = 50 * time.Millisecond
	maxAppSecTimeout     = 30 * time.Second
	defaultAppSecTimeout = 500 * time.Millisecond
	maxConfigBytes       = 64 << 10
)

// config is the JSON file the settings page writes (spec D3). Unknown keys are an error.
type config struct {
	APIURL              string `json:"api_url"`
	APIKey              string `json:"api_key"`
	UpdateFrequency     string `json:"update_frequency"`
	TableV4             string `json:"table_v4"`
	TableV6             string `json:"table_v6"`
	LogLevel            string `json:"log_level"`
	StatusFile          string `json:"status_file"`
	SPOAListen          string `json:"spoa_listen"`
	SPOASocketGroup     *int   `json:"spoa_socket_group"`
	AppSecURL           string `json:"appsec_url"`
	AppSecTimeout       string `json:"appsec_timeout"`
	AppSecFailureAction string `json:"appsec_failure_action"`

	interval      time.Duration
	appSecTimeout time.Duration
	level         logLevel
}

func loadConfig(path string) (*config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxConfigBytes)
	}
	return parseConfig(data)
}

// parseConfig decodes and validates the file. Its errors name the field, never the key's value.
func parseConfig(data []byte) (*config, error) {
	cfg := &config{
		UpdateFrequency:     "10s",
		TableV4:             "crowdsec_v4",
		TableV6:             "crowdsec_v6",
		LogLevel:            "info",
		StatusFile:          "/var/run/pfb_crowdsec.json",
		AppSecTimeout:       "500ms",
		AppSecFailureAction: "passthrough",
	}
	if err := checkConfigKeys(data); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("config: trailing data after the JSON object")
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

var configKeys = []string{
	"api_url", "api_key", "update_frequency", "table_v4", "table_v6", "log_level", "status_file",
	"spoa_listen", "spoa_socket_group", "appsec_url", "appsec_timeout", "appsec_failure_action",
}

// checkConfigKeys requires one JSON object whose keys are configKeys, spelled exactly and each at most once (encoding/json
// alone matches keys case-insensitively and lets a repeated key win).
func checkConfigKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return errors.New("not a JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := tok.(string)
		if !slices.Contains(configKeys, key) {
			return fmt.Errorf("unknown key %q", key)
		}
		if seen[key] {
			return fmt.Errorf("key %q appears twice", key)
		}
		seen[key] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return err
		}
	}
	return nil
}

func (c *config) validate() error {
	u, err := url.Parse(c.APIURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Hostname() == "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(c.APIURL, " \t\r\n") {
		return errors.New("api_url must be an http:// or https:// URL with a host, and no credentials, query or fragment")
	}
	if n := len(c.APIKey); n == 0 || n > 256 {
		return errors.New("api_key must be 1 to 256 characters")
	}
	for i := 0; i < len(c.APIKey); i++ {
		if c.APIKey[i] <= ' ' || c.APIKey[i] >= 0x7f {
			return errors.New("api_key must be printable ASCII without whitespace")
		}
	}
	c.interval, err = time.ParseDuration(c.UpdateFrequency)
	if err != nil || c.interval < minInterval {
		return fmt.Errorf("update_frequency %q must be a duration of at least %s", c.UpdateFrequency, minInterval)
	}
	for _, t := range []struct{ key, name string }{{"table_v4", c.TableV4}, {"table_v6", c.TableV6}} {
		if !validTableName(t.name) {
			return fmt.Errorf("%s %q must be 1 to 31 of A-Z a-z 0-9 _ -, starting with a letter or _", t.key, t.name)
		}
	}
	if c.TableV4 == c.TableV6 {
		return errors.New("table_v4 and table_v6 must differ")
	}
	if c.level, err = parseLogLevel(c.LogLevel); err != nil {
		return err
	}
	if !filepath.IsAbs(c.StatusFile) || strings.ContainsRune(c.StatusFile, 0) {
		return errors.New("status_file must be an absolute path")
	}
	if c.SPOAListen != "" {
		if _, _, err := spoa.ParseListen(c.SPOAListen); err != nil {
			return fmt.Errorf("spoa_listen: %w", err)
		}
	}
	if c.SPOASocketGroup != nil && (*c.SPOASocketGroup < 0 || *c.SPOASocketGroup > math.MaxInt32) {
		return errors.New("spoa_socket_group must be a valid non-negative gid")
	}
	if c.AppSecURL != "" {
		au, err := url.Parse(c.AppSecURL)
		if err != nil || (au.Scheme != "http" && au.Scheme != "https") || au.Host == "" || au.Hostname() == "" ||
			au.User != nil || au.RawQuery != "" || au.ForceQuery || au.Fragment != "" || strings.ContainsAny(c.AppSecURL, " \t\r\n") {
			return errors.New("appsec_url must be an http:// or https:// URL with a host, and no credentials, query or fragment")
		}
	}
	if c.AppSecTimeout == "" {
		c.appSecTimeout = defaultAppSecTimeout
	} else {
		c.appSecTimeout, err = time.ParseDuration(c.AppSecTimeout)
		if err != nil || c.appSecTimeout < minAppSecTimeout || c.appSecTimeout > maxAppSecTimeout {
			return fmt.Errorf("appsec_timeout %q must be a duration between %s and %s", c.AppSecTimeout, minAppSecTimeout, maxAppSecTimeout)
		}
	}
	if c.AppSecFailureAction != "passthrough" && c.AppSecFailureAction != "deny" {
		return fmt.Errorf("appsec_failure_action %q must be passthrough or deny", c.AppSecFailureAction)
	}
	return nil
}

// validTableName: pf table names are at most 31 bytes; a leading letter or _ keeps pfctl from reading a flag.
func validTableName(s string) bool {
	if len(s) == 0 || len(s) > 31 {
		return false
	}
	for i, r := range s {
		letter := r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !letter && (i == 0 || !(r == '-' || (r >= '0' && r <= '9'))) {
			return false
		}
	}
	return true
}

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type familyBans struct {
	Total   int            `json:"total"`
	Origins map[string]int `json:"origins"`
}

// status is the status file the Status page and the metrics export read. Times are Unix seconds, 0 for never;
// maps are keyed "ipv4" and "ipv6". It never holds the key.
type status struct {
	Version                string                `json:"version"`
	StartTime              int64                 `json:"start_time"`
	UpdateFrequencySeconds int64                 `json:"update_frequency_seconds"`
	UpdatedAt              int64                 `json:"updated_at"`
	LastPull               int64                 `json:"last_pull"`
	LastErrorTime          int64                 `json:"last_error_time"`
	LastError              string                `json:"last_error"`
	LAPIRequests           uint64                `json:"lapi_requests"`
	LAPIErrors             uint64                `json:"lapi_errors"`
	Banned                 map[string]familyBans `json:"banned"`
	Dropped                map[string]counter    `json:"dropped"`
}

// writeStatus replaces path atomically: a temp file in the same directory, mode 0644, renamed over it.
func writeStatus(path string, st *status) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".pfb_crowdsec-status-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // a no-op once renamed
	_, err = f.Write(append(data, '\n'))
	if err == nil {
		err = f.Chmod(0o644)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

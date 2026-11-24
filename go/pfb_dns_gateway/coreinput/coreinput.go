// Package coreinput is pfB-DNS's DNSBL input from the Core API (issue #4036, sub-slice 7d): it fetches the dnsbl/*
// resources the Core Updater publishes and writes them into the module directory in the shapes the decider reads there
// today (pfb_py_sources.json, its raw feed files, pfb_py_top1m.txt, pfb_py_ss.txt and dnsbl_psl), so that boot and
// reload build from them unchanged. The module directory is pfB-DNS's private cache: nothing else writes or reads it.
package coreinput

import (
	"context"
	"errors"
)

// Cursor is the generation and digest of a body, the strings GetResources gave.
type Cursor struct {
	Generation string `json:"generation,omitempty"`
	Digest     string `json:"digest,omitempty"`
}

// State is what the module directory holds from Core: the manifest's cursor, and every dnsbl/* body it serves (the
// manifest included), as ReportApplied takes them.
type State struct {
	Manifest  Cursor            `json:"manifest"`
	Resources map[string]Cursor `json:"resources"`
}

var (
	// ErrNoData: Core publishes no dnsbl/manifest (DNSBL is off, or no Update has run yet).
	ErrNoData = errors.New("core publishes no DNSBL data")
	// ErrMoved: a body the manifest names moved on before it was fetched; the module directory is unchanged.
	ErrMoved = errors.New("a DNSBL body moved on while it was fetched")
)

// Client calls the Core API on its Unix socket.
type Client struct{ socket string }

// New is a client of the Core API listening on socket.
func New(socket string) *Client { return &Client{socket} }

// Load is the State the last Sync left in dir; the zero State when there is none.
func Load(dir string) State { return State{} }

// Sync brings dir to the dnsbl/* data Core publishes. It reports whether dir changed.
func Sync(ctx context.Context, c *Client, dir string, prev State) (State, bool, error) {
	return prev, false, errors.New("not implemented")
}

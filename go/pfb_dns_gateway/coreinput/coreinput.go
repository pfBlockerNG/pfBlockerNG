// Package coreinput is pfB-DNS's DNSBL input from the Core API (issue #4036, sub-slice 7d): it fetches the dnsbl/*
// resources the Core Updater publishes and writes them into the module directory in the shapes the decider reads there
// today (pfb_py_sources.json, its raw feed files, pfb_py_top1m.txt, pfb_py_ss.txt and dnsbl_psl), so that boot and
// reload build from them unchanged. The module directory is pfB-DNS's private cache: nothing else writes or reads it.
//
// A Sync verifies every body against the digest and line count its manifest row names before it changes anything, then
// writes the feed bodies into a folder of their own generation, the TOP1M, SafeSearch and PSL files, and the manifest
// last: the manifest names the feed folder, so a build that reads it reads one generation's feeds.
package coreinput

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/pfBlockerNG/xxh3"
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

const (
	manifestID = "dnsbl/manifest"
	top1mID    = "dnsbl/top1m"
	ssID       = "dnsbl/safesearch"
	pslID      = "dnsbl/psl"
	feedPrefix = "dnsbl/feed-"

	maxMember = 1 << 20 // the longest member a body may hold (docs/misc/core-api-protocol.md "Body and digest")
	rawDir    = "pfb_py_raw"
	stateFile = "pfb_py_core.json"
)

// Client calls the Core API on its Unix socket.
type Client struct{ http *http.Client }

// New is a client of the Core API listening on socket.
func New(socket string) *Client {
	return &Client{&http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}}}
}

// APIError is a refusal in the Core API's error envelope.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *APIError) Error() string { return e.Code + ": " + e.Message }

func (c *Client) post(ctx context.Context, method string, req any) (*http.Response, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://core/v1/"+method, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(r)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusOK {
		return resp, nil
	}
	defer resp.Body.Close()
	var env struct{ Error *APIError }
	if json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&env) != nil || env.Error == nil {
		return nil, fmt.Errorf("%s: HTTP %d", method, resp.StatusCode)
	}
	return nil, fmt.Errorf("%s: %w", method, env.Error)
}

// item is a GetResources item.
type item struct {
	Kind       string    `json:"kind"`
	Generation string    `json:"generation"`
	Digest     string    `json:"digest"`
	Entries    int       `json:"entries"`
	Error      *APIError `json:"error"`
}

func (c *Client) resource(ctx context.Context, id string, cur Cursor) (item, error) {
	resp, err := c.post(ctx, "GetResources", map[string]any{"resources": map[string]Cursor{id: cur}})
	if err != nil {
		return item{}, err
	}
	defer resp.Body.Close()
	var reply struct{ Resources map[string]item }
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&reply); err != nil {
		return item{}, fmt.Errorf("GetResources: %w", err)
	}
	it, ok := reply.Resources[id]
	switch {
	case !ok:
		return item{}, fmt.Errorf("GetResources: no item for %s", id)
	case it.Error != nil && it.Error.Code == "not_found":
		return item{}, ErrNoData
	case it.Error != nil:
		return item{}, fmt.Errorf("GetResources %s: %w", id, it.Error)
	case it.Kind == "unchanged":
		return it, nil
	case it.Kind != "full" && it.Kind != "delta" || !cursorOK(Cursor{it.Generation, it.Digest}) || it.Entries < 0:
		return item{}, fmt.Errorf("GetResources %s: a malformed item", id)
	}
	return it, nil
}

// body writes the members of id at cur to w, and refuses them unless they are entries lines whose digest is cur's.
func (c *Client) body(ctx context.Context, id string, cur Cursor, entries int, w io.Writer) error {
	resp, err := c.post(ctx, "GetResourceBody", map[string]string{"id": id, "generation": cur.Generation, "part": "members"})
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Code == "not_found" {
		return ErrMoved
	}
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	bound := int64(entries) * (maxMember + 1)
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") || resp.ContentLength > bound {
		return fmt.Errorf("%s: the body is not plain text within %d bytes", id, bound)
	}
	h, lines := xxh3.New128(), lineCount(0)
	n, err := io.Copy(io.MultiWriter(w, h, &lines), io.LimitReader(resp.Body, bound+1))
	switch {
	case err != nil:
		return fmt.Errorf("%s: %w", id, err)
	case n > bound:
		return fmt.Errorf("%s: the body runs past %d bytes", id, bound)
	case int(lines) != entries || hex.EncodeToString(h.Sum(nil)) != cur.Digest:
		return fmt.Errorf("%s: the body is not the one its manifest row names", id)
	}
	return nil
}

type lineCount int

func (l *lineCount) Write(p []byte) (int, error) {
	*l += lineCount(bytes.Count(p, []byte{'\n'}))
	return len(p), nil
}

func cursorOK(c Cursor) bool {
	if _, err := strconv.ParseUint(c.Generation, 10, 64); err != nil || strings.Trim(c.Generation, "0123456789") != "" {
		return false
	}
	return len(c.Digest) == 32 && strings.Trim(c.Digest, "0123456789abcdef") == ""
}

// Load is the State the last Sync left in dir; the zero State when there is none or its manifest is gone.
func Load(dir string) State {
	var s State
	data, err := os.ReadFile(filepath.Join(dir, stateFile))
	if err != nil || json.Unmarshal(data, &s) != nil || !cursorOK(s.Manifest) {
		return State{}
	}
	if info, err := os.Stat(filepath.Join(dir, "pfb_py_sources.json")); err != nil || !info.Mode().IsRegular() {
		return State{}
	}
	return s
}

// row is one manifest row, every kind's fields together.
type row struct {
	Kind           string `json:"kind"`
	BuiltinLogFlag string `json:"builtinLogFlag"`
	Top1mEnabled   bool   `json:"top1mEnabled"`
	Domain         string `json:"domain"`
	TLD            string `json:"tld"`
	Position       int    `json:"position"`
	Feed           string `json:"feed"`
	Group          string `json:"group"`
	LogFlag        string `json:"logFlag"`
	Provenance     string `json:"provenance"`
	Mode           string `json:"mode"`
	Top1m          bool   `json:"top1m"`
	Resource       string `json:"resource"`
	Generation     string `json:"generation"`
	Digest         string `json:"digest"`
	Entries        int    `json:"entries"`
}

// manifest is a checked dnsbl/manifest: the file manifest's config, the feeds in position order, and each body it names.
type manifest struct {
	config map[string]any
	feeds  []row
	bodies map[string]row // resource id: the row naming it
}

func parseManifest(data []byte) (manifest, error) {
	m := manifest{bodies: map[string]row{}}
	lists := map[string][]string{"user_whitelist": {}, "user_unlock": {}, "tld_wildcard_blacklist": {}, "tld_wildcard_exclusion": {}}
	configs := 0
	for _, line := range strings.SplitAfter(string(data), "\n") {
		if line == "" {
			continue
		}
		var r row
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return m, fmt.Errorf("a manifest row is not a JSON object: %w", err)
		}
		bad := func(why string) error { return fmt.Errorf("a %q manifest row %s", r.Kind, why) }
		switch r.Kind {
		case "config":
			if configs++; configs > 1 || !slices.Contains([]string{"0", "1", "2", "3", "4", "5", "6"}, r.BuiltinLogFlag) {
				return m, bad("is repeated or has a builtinLogFlag outside 0 to 6")
			}
			m.config = map[string]any{"builtin_log_flag": r.BuiltinLogFlag, "top1m_enabled": r.Top1mEnabled}
		case "whitelist", "unlock", "tld_exclusion", "tld_blacklist":
			value := r.Domain // as today's manifest lists it, an empty entry included
			if r.Kind == "tld_blacklist" {
				value = r.TLD
			}
			key := map[string]string{"whitelist": "user_whitelist", "unlock": "user_unlock", "tld_exclusion": "tld_wildcard_exclusion",
				"tld_blacklist": "tld_wildcard_blacklist"}[r.Kind]
			lists[key] = append(lists[key], value)
		case "feed":
			if !word(r.Feed) || r.Resource != feedPrefix+r.Feed || r.Mode != "deny" && r.Mode != "permit" ||
				r.Provenance != "feed" && r.Provenance != "user" {
				return m, bad(fmt.Sprintf("for feed %q has a bad name, resource, mode or provenance", r.Feed))
			}
			m.feeds = append(m.feeds, r)
		case "member":
			if r.Resource != top1mID && r.Resource != ssID && r.Resource != pslID {
				return m, bad(fmt.Sprintf("names %q", r.Resource))
			}
		default:
			return m, bad("is of an unknown kind")
		}
		if r.Kind == "feed" || r.Kind == "member" {
			if !cursorOK(Cursor{r.Generation, r.Digest}) || r.Entries < 0 {
				return m, bad(fmt.Sprintf("for %q has a bad generation, digest or count", r.Resource))
			}
			if seen, ok := m.bodies[r.Resource]; ok && (r.Kind == "member" || seen.Generation != r.Generation ||
				seen.Digest != r.Digest || seen.Entries != r.Entries) {
				return m, bad(fmt.Sprintf("names %q again", r.Resource))
			}
			m.bodies[r.Resource] = r
		}
	}
	if configs != 1 {
		return m, errors.New("the manifest has no config row")
	}
	if _, ok := m.bodies[top1mID]; m.config["top1m_enabled"] == true && !ok {
		return m, errors.New("the manifest turns TOP1M on without a TOP1M body")
	}
	slices.SortFunc(m.feeds, func(a, b row) int { return a.Position - b.Position })
	for i, f := range m.feeds {
		if f.Position != i+1 {
			return m, fmt.Errorf("the manifest's feed positions are not 1 to %d", len(m.feeds))
		}
	}
	for key, values := range lists {
		m.config[key] = values
	}
	return m, nil
}

// word is PFB_FILTER_WORD: letters, digits and underscores, not empty.
func word(s string) bool {
	return s != "" && strings.Trim(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") == ""
}

// Sync brings dir to the dnsbl/* data Core publishes, starting from prev (Load(dir)). It reports whether dir changed.
// On an error before the first change dir is as it was; the next Sync removes a feed folder no manifest names.
func Sync(ctx context.Context, c *Client, dir string, prev State) (State, bool, error) {
	it, err := c.resource(ctx, manifestID, prev.Manifest)
	if err != nil {
		return prev, false, err
	}
	if it.Kind == "unchanged" {
		return prev, false, nil
	}
	cur := Cursor{it.Generation, it.Digest}
	var data bytes.Buffer
	if err := c.body(ctx, manifestID, cur, it.Entries, &data); err != nil {
		return prev, false, err
	}
	m, err := parseManifest(data.Bytes())
	if err != nil {
		return prev, false, fmt.Errorf("%s %s: %w", manifestID, cur.Generation, err)
	}

	raw := filepath.Join(dir, rawDir)
	if err := os.MkdirAll(raw, 0o700); err != nil {
		return prev, false, err
	}
	stage, err := os.MkdirTemp(raw, ".g"+cur.Generation+".")
	if err != nil {
		return prev, false, err
	}
	defer os.RemoveAll(stage)
	state := State{Manifest: cur, Resources: map[string]Cursor{manifestID: cur}}
	small := map[string][]byte{}
	for _, id := range slices.Sorted(maps.Keys(m.bodies)) {
		r := m.bodies[id]
		at := Cursor{r.Generation, r.Digest}
		state.Resources[id] = at
		if id == ssID || id == pslID {
			var b bytes.Buffer
			if err := c.body(ctx, id, at, r.Entries, &b); err != nil {
				return prev, false, err
			}
			small[id] = b.Bytes()
			continue
		}
		if err := fetchFile(ctx, c, id, at, r.Entries, filepath.Join(stage, strings.TrimPrefix(id, "dnsbl/")+".txt")); err != nil {
			return prev, false, err
		}
	}
	files := map[string][]byte{"pfb_py_ss.txt": nil, "dnsbl_psl": nil}
	if b, ok := small[ssID]; ok {
		if files["pfb_py_ss.txt"], err = safeSearchCSV(b); err != nil {
			return prev, false, err
		}
	}
	if b, ok := small[pslID]; ok {
		if files["dnsbl_psl"], err = pslText(b); err != nil {
			return prev, false, err
		}
	}
	gen := "g" + cur.Generation
	feeds := []map[string]any{}
	for _, f := range m.feeds {
		feeds = append(feeds, map[string]any{"raw": rawDir + "/" + gen + "/" + strings.TrimPrefix(f.Resource, "dnsbl/") + ".txt",
			"feed": f.Feed, "group": f.Group, "log_flag": f.LogFlag, "provenance": f.Provenance, "mode": f.Mode, "top1m": f.Top1m})
	}
	doc, err := json.Marshal(map[string]any{"version": 1, "config": m.config, "feeds": feeds})
	if err != nil {
		return prev, false, err
	}
	st, err := json.Marshal(state)
	if err != nil {
		return prev, false, err
	}

	// Everything is fetched and checked: from here on dir changes.
	final := filepath.Join(raw, gen)
	if err := os.RemoveAll(final); err != nil {
		return prev, false, err
	}
	if err := os.Rename(stage, final); err != nil {
		return prev, false, err
	}
	top1m := filepath.Join(dir, "pfb_py_top1m.txt")
	if _, ok := m.bodies[top1mID]; ok {
		err = os.Rename(filepath.Join(final, "top1m.txt"), top1m)
	} else {
		err = removeFile(top1m)
	}
	if err != nil {
		return prev, true, err
	}
	for _, name := range []string{"pfb_py_ss.txt", "dnsbl_psl"} {
		if files[name] == nil {
			err = removeFile(filepath.Join(dir, name))
		} else {
			err = writeFile(filepath.Join(dir, name), files[name])
		}
		if err != nil {
			return prev, true, err
		}
	}
	if err := writeFile(filepath.Join(dir, "pfb_py_sources.json"), doc); err != nil {
		return prev, true, err
	}
	if err := writeFile(filepath.Join(dir, stateFile), st); err != nil {
		return state, true, err
	}
	// ponytail: every feed body is fetched again whenever the manifest moves; link an unchanged digest from the previous
	// folder if the transfer of a large DNSBL set on each Update matters.
	entries, _ := os.ReadDir(raw)
	for _, e := range entries {
		if n := e.Name(); n != gen && (strings.HasPrefix(n, ".g") || n[0] == 'g' && strings.Trim(n[1:], "0123456789") == "") {
			os.RemoveAll(filepath.Join(raw, n))
		}
	}
	return state, true, nil
}

// fetchFile writes the body of id at cur to a new file at path and syncs it.
func fetchFile(ctx context.Context, c *Client, id string, cur Cursor, entries int, path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := c.body(ctx, id, cur, entries, f); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// writeFile replaces path with data through a synced file beside it.
func writeFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".")
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		os.Remove(f.Name())
	}
	return err
}

func removeFile(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// safeSearchCSV is dnsbl/safesearch as pfb_py_ss.txt: one CSV row per host, host,a,aaaa and v4,v6 when Core gives them.
func safeSearchCSV(body []byte) ([]byte, error) {
	var out bytes.Buffer
	w := csv.NewWriter(&out)
	for _, line := range strings.SplitAfter(string(body), "\n") {
		if line == "" {
			continue
		}
		var r struct{ Host, A, AAAA, V4, V6 string }
		if err := json.Unmarshal([]byte(line), &r); err != nil || r.Host == "" {
			return nil, fmt.Errorf("%s: a row is not a SafeSearch host", ssID)
		}
		fields := []string{r.Host, r.A, r.AAAA}
		if r.V4 != "" || r.V6 != "" {
			fields = append(fields, r.V4, r.V6)
		}
		w.Write(fields)
	}
	w.Flush()
	return out.Bytes(), w.Error()
}

// pslText is dnsbl/psl as the PSL authority file: each section's rules between its two markers.
func pslText(body []byte) ([]byte, error) {
	rules := map[string][]string{}
	for _, line := range strings.SplitAfter(string(body), "\n") {
		if line == "" {
			continue
		}
		var r struct{ Section, Rule string }
		if err := json.Unmarshal([]byte(line), &r); err != nil || r.Section != "icann" && r.Section != "private" || r.Rule == "" ||
			strings.ContainsAny(r.Rule, "\n\r\v\f\x1c\x1d\x1e\u0085  ") {
			return nil, fmt.Errorf("%s: a row is not a PSL rule of a section", pslID)
		}
		rules[r.Section] = append(rules[r.Section], r.Rule)
	}
	var out strings.Builder
	for _, s := range []struct{ name, title string }{{"icann", "ICANN"}, {"private", "PRIVATE"}} {
		out.WriteString("// ===BEGIN " + s.title + " DOMAINS===\n")
		for _, rule := range rules[s.name] {
			out.WriteString(rule + "\n")
		}
		out.WriteString("// ===END " + s.title + " DOMAINS===\n")
	}
	return []byte(out.String()), nil
}

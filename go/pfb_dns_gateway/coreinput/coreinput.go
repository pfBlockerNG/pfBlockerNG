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
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
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
	"syscall"
	"unicode"

	"github.com/zeebo/xxh3"
)

// Cursor is the generation and digest of a body, the strings GetResources gave.
type Cursor struct {
	Generation string `json:"generation,omitempty"`
	Digest     string `json:"digest,omitempty"`
}

// State is what the module directory holds from Core: the manifest's cursor, and every dnsbl/* body it serves (the
// manifest included), as ReportApplied takes them.
type State struct {
	Version   int               `json:"version"` // stateVersion; a state of another version is not trusted
	Manifest  Cursor            `json:"manifest"`
	Resources map[string]Cursor `json:"resources"`
	Folder    string            `json:"folder"` // the folder of pfb_py_raw that holds the feeds
	// Files is the digest of each file written converted (SafeSearch, PSL), which Core's digest does not describe.
	Files map[string]string `json:"files,omitempty"`
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

	stateVersion = 1
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

// ReportApplied tells Core the dnsbl/* resources pfB-DNS serves, each at the cursor of the body it applied: Core makes
// them the applied baseline. A report replaces the last one whole; nil reports that it serves none.
func (c *Client) ReportApplied(ctx context.Context, served map[string]Cursor) error {
	if served == nil {
		served = map[string]Cursor{}
	}
	resp, err := c.post(ctx, "ReportApplied", map[string]any{"requestId": rand.Text(), "resources": served})
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// item is a GetResources item.
type item struct {
	Kind       string `json:"kind"`
	Generation string `json:"generation"`
	Digest     string `json:"digest"`
	Entries    int    `json:"entries"`
	// From, AddEntries and RemoveEntries describe a delta: the cursor's generation, and the line counts of its parts.
	From          string    `json:"from"`
	AddEntries    int       `json:"addEntries"`
	RemoveEntries int       `json:"removeEntries"`
	Error         *APIError `json:"error"`
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
	case it.Kind != "full" && it.Kind != "delta" || !cursorOK(Cursor{it.Generation, it.Digest}):
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
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
		return fmt.Errorf("%s: the body is not plain text", id)
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
	if _, err := strconv.ParseUint(c.Generation, 10, 64); err != nil { // decimal digits only: no sign, space or prefix
		return false
	}
	return len(c.Digest) == 32 && strings.Trim(c.Digest, "0123456789abcdef") == ""
}

// Load is the State the last Sync left in dir, once every file it wrote is still there, is pfB-DNS's own (a regular file
// of this user that no other user may write), and each body written as Core sent it (the feeds, TOP1M) still has its
// digest; the zero State otherwise, so that the next Sync fetches everything.
func Load(dir string) State {
	var s State
	if !own(filepath.Join(dir, stateFile)) || !own(filepath.Join(dir, "pfb_py_sources.json")) {
		return State{}
	}
	data, err := os.ReadFile(filepath.Join(dir, stateFile))
	if err != nil || json.Unmarshal(data, &s) != nil || s.Version != stateVersion || !cursorOK(s.Manifest) {
		return State{}
	}
	for id, cur := range s.Resources {
		if id == manifestID {
			continue
		}
		path := cachedPath(dir, s, id)
		if path == "" || !own(path) {
			return State{}
		}
		want := cur.Digest
		if id == ssID || id == pslID {
			want = s.Files[memberFile[id]]
		}
		if digest, err := fileDigest(path); err != nil || digest != want {
			return State{}
		}
	}
	return s
}

// cachedPath is where s keeps the body of id in dir; "" for an id it cannot keep.
func cachedPath(dir string, s State, id string) string {
	if strings.HasPrefix(id, feedPrefix) {
		return filepath.Join(dir, rawDir, s.Folder, rawName(id))
	}
	if memberFile[id] == "" {
		return ""
	}
	return filepath.Join(dir, memberFile[id])
}

// own is whether path is a regular file of this user that neither its group nor others may write: a symbolic link is not
// followed.
func own(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
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

// memberFile is the module file of each member body.
var memberFile = map[string]string{top1mID: "pfb_py_top1m.txt", ssID: "pfb_py_ss.txt", pslID: "dnsbl_psl"}

// rawName is the name of a body's file in a Sync's folder.
func rawName(id string) string { return strings.TrimPrefix(id, "dnsbl/") + ".txt" }

// listKey is the file manifest's config key of each list row kind.
var listKey = map[string]string{"whitelist": "user_whitelist", "unlock": "user_unlock", "tld_exclusion": "tld_wildcard_exclusion",
	"tld_blacklist": "tld_wildcard_blacklist"}

// manifest is a checked dnsbl/manifest: the file manifest's config, the feeds in position order, and each body it names.
type manifest struct {
	config map[string]any
	feeds  []row
	bodies map[string]row // resource id: the row naming it
}

func parseManifest(data []byte) (manifest, error) {
	m := manifest{bodies: map[string]row{}}
	lists := map[string][]string{}
	for _, key := range listKey {
		lists[key] = []string{}
	}
	configs, top1m := 0, false
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
			m.config, top1m = map[string]any{"builtin_log_flag": r.BuiltinLogFlag, "top1m_enabled": r.Top1mEnabled}, r.Top1mEnabled
		case "whitelist", "unlock", "tld_exclusion", "tld_blacklist":
			value := r.Domain // as today's manifest lists it, an empty entry included
			if r.Kind == "tld_blacklist" {
				value = r.TLD
			}
			lists[listKey[r.Kind]] = append(lists[listKey[r.Kind]], value)
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
			if !cursorOK(Cursor{r.Generation, r.Digest}) {
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
	if _, ok := m.bodies[top1mID]; top1m && !ok {
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
//
// Every body is fetched into a new folder of the manifest's generation and checked before dir changes. The state file goes
// first, so that a Sync interrupted from there on leaves Load nothing to trust and the next Sync fetches everything; then
// TOP1M, SafeSearch and the PSL are replaced, the manifest naming the new folder, and the state last. The folder the
// manifest on disk named stays, for a build that may still read it, until the next Sync. TOP1M, SafeSearch and the PSL
// keep their fixed names, so a caller never builds while a Sync runs, builds only from a dir whose Load is not the zero
// State, and does not build after a Sync that returned an error, whatever it reports changed. When Core publishes no
// DNSBL data, which is also a store not rebuilt yet, Sync answers ErrNoData and keeps every file: DNSBL switched off reaches
// pfB-DNS through its settings.
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
	folder, err := os.MkdirTemp(raw, "g"+cur.Generation+".")
	if err != nil {
		return prev, false, err
	}
	committed := false
	defer func() {
		if !committed {
			os.RemoveAll(folder)
		}
	}()
	state := State{Version: stateVersion, Manifest: cur, Resources: map[string]Cursor{manifestID: cur}, Folder: filepath.Base(folder),
		Files: map[string]string{}}
	files := map[string][]byte{} // the SafeSearch and PSL files this generation has, empty ones included
	kept := map[string]bool{}    // the SafeSearch and PSL files that stay as they are
	for _, id := range slices.Sorted(maps.Keys(m.bodies)) {
		r := m.bodies[id]
		at := Cursor{r.Generation, r.Digest}
		state.Resources[id] = at
		have := prev.Resources[id]
		if id != ssID && id != pslID {
			if err := fetchBody(ctx, c, id, at, r.Entries, have, cachedPath(dir, prev, id), filepath.Join(folder, rawName(id))); err != nil {
				return prev, false, err
			}
			continue
		}
		if have == at {
			kept[memberFile[id]] = true
			state.Files[memberFile[id]] = prev.Files[memberFile[id]]
			continue
		}
		var b bytes.Buffer
		if err := c.body(ctx, id, at, r.Entries, &b); err != nil {
			return prev, false, err
		}
		if id == ssID {
			files[memberFile[id]], err = safeSearchCSV(b.Bytes())
		} else {
			files[memberFile[id]], err = pslText(b.Bytes())
		}
		if err != nil {
			return prev, false, err
		}
		state.Files[memberFile[id]] = digestOf(files[memberFile[id]])
	}
	feeds := []map[string]any{}
	for _, f := range m.feeds {
		feeds = append(feeds, map[string]any{"raw": rawDir + "/" + state.Folder + "/" + rawName(f.Resource),
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
	if err := syncDir(folder); err != nil {
		return prev, false, err
	}
	onDisk := manifestFolder(dir)

	// Everything is fetched and checked: from here on dir changes, and an error leaves no state.
	committed = true
	fail := func(err error) (State, bool, error) { return State{}, true, err }
	if err := removeFile(filepath.Join(dir, stateFile)); err != nil {
		return fail(err)
	}
	if err := syncDir(dir); err != nil {
		return fail(err)
	}
	top1m := filepath.Join(dir, memberFile[top1mID])
	if _, ok := m.bodies[top1mID]; ok {
		err = os.Rename(filepath.Join(folder, rawName(top1mID)), top1m)
		os.Remove(filepath.Join(folder, rawName(top1mID))) // left by a rename onto the link it came from, or by a failed one
	} else {
		err = removeFile(top1m)
	}
	if err != nil {
		return fail(err)
	}
	for _, name := range []string{memberFile[ssID], memberFile[pslID]} {
		if kept[name] {
			continue
		}
		if body, ok := files[name]; ok {
			err = writeFile(filepath.Join(dir, name), body)
		} else {
			err = removeFile(filepath.Join(dir, name))
		}
		if err != nil {
			return fail(err)
		}
	}
	if err := writeFile(filepath.Join(dir, "pfb_py_sources.json"), doc); err != nil {
		return fail(err)
	}
	for _, d := range []string{folder, raw, dir} {
		if err := syncDir(d); err != nil {
			return fail(err)
		}
	}
	if err := writeFile(filepath.Join(dir, stateFile), st); err != nil {
		return fail(err)
	}
	if err := syncDir(dir); err != nil {
		return fail(err)
	}
	entries, _ := os.ReadDir(raw)
	for _, e := range entries {
		if n := e.Name(); n != state.Folder && n != onDisk && strings.HasPrefix(n, "g") {
			os.RemoveAll(filepath.Join(raw, n))
		}
	}
	// The temporary files a writeFile cut short left.
	entries, _ = os.ReadDir(dir)
	for _, e := range entries {
		for _, name := range []string{memberFile[ssID], memberFile[pslID], "pfb_py_sources.json", stateFile} {
			if strings.HasPrefix(e.Name(), "."+name+".") {
				os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}
	return state, true, nil
}

// manifestFolder is the folder of pfb_py_raw the manifest in dir names, "" when there is none.
func manifestFolder(dir string) string {
	var doc struct{ Feeds []struct{ Raw string } }
	data, err := os.ReadFile(filepath.Join(dir, "pfb_py_sources.json"))
	if err != nil || json.Unmarshal(data, &doc) != nil {
		return ""
	}
	for _, f := range doc.Feeds {
		if folder, _, ok := strings.Cut(strings.TrimPrefix(f.Raw, rawDir+"/"), "/"); ok && folder != "" {
			return folder
		}
	}
	return ""
}

// errDelta is a delta that does not turn the cached body into the current one: the full body is fetched instead.
var errDelta = errors.New("the delta does not apply")

// fetchBody writes the body of id at want to a new file at path, from the body at have cached at cached: linked when it is
// the same body, merged with Core's delta from have when Core holds one that applies, fetched whole otherwise. have is a
// body the last Sync wrote and Load trusts, never one changed since.
func fetchBody(ctx context.Context, c *Client, id string, want Cursor, entries int, have Cursor, cached, path string) error {
	if have == want {
		if os.Link(cached, path) == nil {
			return nil
		}
	} else if have != (Cursor{}) && cached != "" {
		it, err := c.resource(ctx, id, have)
		switch {
		case errors.Is(err, ErrNoData):
			return ErrMoved
		case err != nil:
			return err
		case Cursor{it.Generation, it.Digest} != want:
			return ErrMoved
		case it.Kind == "delta" && it.From == have.Generation:
			err := merge(ctx, c, id, it, cached, path)
			if !errors.Is(err, errDelta) {
				return err
			}
			os.Remove(path)
		}
	}
	return fetchFile(ctx, c, id, want, entries, path)
}

// merge writes the body at it to a new file at path: the cached body with Core's delta applied, line by line in byte
// order. It is errDelta unless the result has the digest and entries it names: that check alone stands for every
// other, a part out of order, a member added twice or removed though absent.
// ponytail: each part is held in memory while it merges; stream the parts from files if a delta reaches the size of a body.
func merge(ctx context.Context, c *Client, id string, it item, cached, path string) error {
	add, err := c.part(ctx, id, it, "add", it.AddEntries)
	if err != nil {
		return err
	}
	remove, err := c.part(ctx, id, it, "remove", it.RemoveEntries)
	if err != nil {
		return err
	}
	old, err := os.Open(cached)
	if err != nil {
		return errDelta
	}
	defer old.Close()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	h, n := xxh3.New128(), 0
	w := bufio.NewWriter(io.MultiWriter(f, h))
	emit := func(line string) {
		w.WriteString(line)
		w.WriteByte('\n')
		n++
	}
	sc := bufio.NewScanner(old)
	sc.Buffer(make([]byte, 64<<10), maxMember+1)
	for sc.Scan() {
		line := sc.Text()
		for len(add) > 0 && add[0] < line {
			emit(add[0])
			add = add[1:]
		}
		if len(remove) > 0 && remove[0] == line {
			remove = remove[1:]
		} else {
			emit(line)
		}
	}
	if sc.Err() != nil {
		return errDelta
	}
	for _, line := range add {
		emit(line)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if n != it.Entries || hex.EncodeToString(h.Sum(nil)) != it.Digest {
		return errDelta
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}

// part is the lines of a delta part of id, errDelta when it runs past count lines' bound or is not plain text, or when Core
// no longer holds the delta. merge checks what the lines make.
func (c *Client) part(ctx context.Context, id string, it item, part string, count int) ([]string, error) {
	resp, err := c.post(ctx, "GetResourceBody", map[string]string{"id": id, "generation": it.Generation, "part": part, "from": it.From})
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Code == "not_found" {
		return nil, errDelta
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
		return nil, errDelta
	}
	bound := int64(count) * (maxMember + 1)
	data, err := io.ReadAll(io.LimitReader(resp.Body, bound+1))
	switch {
	case err != nil:
		return nil, fmt.Errorf("%s %s: %w", id, part, err)
	case int64(len(data)) > bound:
		return nil, errDelta
	case len(data) == 0:
		return nil, nil
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n"), nil
}

// fetchFile writes the body of id at cur to a new file at path and syncs it.
func fetchFile(ctx context.Context, c *Client, id string, cur Cursor, entries int, path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	err = c.body(ctx, id, cur, entries, f)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// syncDir makes the renames and removals in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

// digestOf is the digest of data, as Core writes a body's.
func digestOf(data []byte) string {
	sum := xxh3.Hash128(data).Bytes()
	return hex.EncodeToString(sum[:])
}

// fileDigest is the digest of the file at path, as Core writes a body's.
func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := xxh3.New128()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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

// safeSearchCSV is dnsbl/safesearch as pfb_py_ss.txt: one row per host, host,a,aaaa and v4,v6 when Core gives them, unquoted
// as PHP writes the file (loadSafesearchDb relies on that), so a value that would need quoting is refused.
func safeSearchCSV(body []byte) ([]byte, error) {
	var out bytes.Buffer
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
		for _, f := range fields {
			if strings.ContainsAny(f, ",\"\r\n") || strings.TrimSpace(f) != f {
				return nil, fmt.Errorf("%s: a row holds a value that is not one plain field", ssID)
			}
		}
		out.WriteString(strings.Join(fields, ",") + "\n")
	}
	return out.Bytes(), nil
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
			strings.ContainsAny(r.Rule, "\n\r\v\f\x1c\x1d\x1e\u0085\u2028\u2029") || strings.TrimFunc(r.Rule, pySpace) != r.Rule ||
			strings.HasPrefix(r.Rule, "//") || strings.HasPrefix(r.Rule, "#") {
			return nil, fmt.Errorf("%s: a row is not a PSL rule of a section", pslID)
		}
		rules[r.Section] = append(rules[r.Section], r.Rule)
	}
	var out bytes.Buffer
	for _, s := range []struct{ name, title string }{{"icann", "ICANN"}, {"private", "PRIVATE"}} {
		out.WriteString("// ===BEGIN " + s.title + " DOMAINS===\n")
		for _, rule := range rules[s.name] {
			out.WriteString(rule + "\n")
		}
		out.WriteString("// ===END " + s.title + " DOMAINS===\n")
	}
	return out.Bytes(), nil
}

// pySpace is str.isspace(), what the decider strips from a PSL line.
func pySpace(r rune) bool { return unicode.IsSpace(r) || 0x1C <= r && r <= 0x1F }

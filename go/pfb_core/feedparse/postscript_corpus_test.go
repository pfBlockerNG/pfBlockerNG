package feedparse

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Replays testdata/postscript.json (schema: testdata/README.md): a list's post-script through PostScript, DNSBL on a staged
// copy of the download, IP on the download with a restore point. The PHP runner (tests/php/FeedParsePostScriptCorpusTest.php)
// replays the same file through the two call sites of sync_package_pfblockerng(), verbatim; where Core differs on purpose
// the case holds today's answer in old_expect, which only that runner asserts.
//
// A script that blocks reports through a fifo that it is running, and the runner then ends the context as the 300-second
// limit does (limitOnEvent): the kill is driven by that event. A child the case expects gone holds a fifo open, and its
// end is the fifo's end of file.

type psDoc struct {
	Schema *int            `json:"schema"`
	Prefix *string         `json:"prefix"`
	Env    *string         `json:"env"`
	Header *string         `json:"header"`
	Cases  []psPostCaseRaw `json:"cases"`
}

type psEntry struct {
	Body    *string `json:"body"`
	Mode    *string `json:"mode"`
	Shebang *bool   `json:"shebang"`
	Link    *string `json:"link"`
	Dir     *bool   `json:"dir"`
}

type psExpect struct {
	Files      map[string]json.RawMessage `json:"files"`
	Between    map[string]json.RawMessage `json:"between"`
	Seen       json.RawMessage            `json:"seen"`
	Log        json.RawMessage            `json:"log"`
	Errors     json.RawMessage            `json:"errors"`
	Transcript json.RawMessage            `json:"transcript"`
	Failed     *bool                      `json:"failed"`
	Reason     *string                    `json:"reason"` // Go only: PostScriptResult.Reason
	Status     *int                       `json:"status"` // Go only: PostScriptResult.Status
	Alive      json.RawMessage            `json:"alive"`
}

type psPostCaseRaw struct {
	ID          *string                    `json:"id"`
	Description *string                    `json:"description"`
	ListType    *string                    `json:"list_type"`
	Name        *string                    `json:"name"`
	Tree        map[string]psEntry         `json:"tree"`
	Feed        map[string]json.RawMessage `json:"feed"`
	Blocks      *bool                      `json:"blocks"`
	Expect      *psExpect                  `json:"expect"`
	OldExpect   *psExpect                  `json:"old_expect"`
	Departure   *string                    `json:"departure"`
}

func loadPostScript(data []byte) (psDoc, error) {
	var doc psDoc
	if err := decodeCorpus(data, &doc); err != nil {
		return doc, err
	}
	if doc.Schema == nil || *doc.Schema != 1 || doc.Prefix == nil || doc.Env == nil || doc.Header == nil || len(doc.Cases) == 0 {
		return doc, errors.New(`postscript.json must be {"schema": 1, "prefix", "env", "header", "cases": [non-empty list]}`)
	}
	ids := corpusIDs{}
	for i, c := range doc.Cases {
		if err := ids.add(c.ID, c.Description); err != nil {
			return doc, fmt.Errorf("case #%d: %w", i, err)
		}
		e := c.Expect
		if c.ListType == nil || c.Name == nil || c.Tree == nil || c.Feed == nil || c.Blocks == nil || e == nil || e.Files == nil ||
			e.Seen == nil || e.Log == nil || e.Errors == nil || e.Transcript == nil || e.Failed == nil || e.Reason == nil ||
			e.Status == nil || e.Alive == nil {
			return doc, fmt.Errorf("case %s: every key is required", *c.ID)
		}
		if !slices.Contains([]string{"", PreScriptStage, PreScriptExit, PreScriptTimeout}, *e.Reason) ||
			(*e.Reason != "") != *e.Failed || (*e.Status != 0) != (*e.Reason == PreScriptExit) {
			return doc, fmt.Errorf("case %s: reason \"\", stage, exit or timeout, set exactly when failed; status exactly "+
				"for exit", *c.ID)
		}
		if !slices.Contains([]string{"dnsbl", "_v4", "_v6"}, *c.ListType) || (*c.ListType == "dnsbl") != (e.Between == nil) {
			return doc, fmt.Errorf("case %s: list_type dnsbl, _v4 or _v6, and between exactly for an IP list", *c.ID)
		}
		if (c.OldExpect == nil) != (c.Departure == nil) || (c.Departure != nil && *c.Departure == "") {
			return doc, fmt.Errorf("case %s: old_expect and a departure that says why come together", *c.ID)
		}
		for path, entry := range c.Tree {
			dir, name, _ := strings.Cut(path, "/")
			kinds := 0
			for _, set := range []bool{entry.Body != nil, entry.Link != nil, entry.Dir != nil} {
				if set {
					kinds++
				}
			}
			if !slices.Contains([]string{"list", "pkg", "outside"}, dir) || name == "" || strings.Contains(name, "/") || kinds != 1 ||
				(entry.Body != nil && (entry.Mode == nil || (*entry.Mode != "exec" && *entry.Mode != "noexec"))) ||
				(entry.Shebang != nil && (*entry.Shebang || entry.Body == nil)) {
				return doc, fmt.Errorf("case %s tree %s: list/, pkg/ or outside/ and a name; a body with mode exec or noexec "+
					"(shebang only ever false), a link or a dir", *c.ID, path)
			}
		}
	}
	return doc, nil
}

func TestPostScriptCorpus(t *testing.T) {
	data, err := os.ReadFile("testdata/postscript.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := loadPostScript(data)
	if err != nil {
		t.Fatalf("postscript.json: %v", err)
	}
	for _, c := range doc.Cases {
		t.Run(*c.ID, func(t *testing.T) { replayPostScript(t, doc, c) })
	}
}

// psState renders a corpus listing of the feed folder: "=content", "-> target", "<dir>" or "<fifo>" per entry.
func psState(t *testing.T, raw map[string]json.RawMessage) map[string]string {
	t.Helper()
	out := map[string]string{}
	for name, v := range raw {
		var content string
		var node struct {
			Link *string `json:"link"`
			Type *string `json:"type"`
		}
		switch {
		case json.Unmarshal(v, &content) == nil:
			out[name] = "=" + content
		case decodeCorpus(v, &node) == nil && node.Link != nil && node.Type == nil:
			out[name] = "-> " + *node.Link
		case node.Type != nil && node.Link == nil && (*node.Type == "dir" || *node.Type == "fifo"):
			out[name] = "<" + *node.Type + ">"
		default:
			t.Fatalf("listing entry %s: a string, {link} or {type: dir|fifo}", name)
		}
	}
	return out
}

func listFeed(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		switch mode := e.Type(); {
		case mode&os.ModeSymlink != 0:
			target, _ := os.Readlink(path)
			out[e.Name()] = "-> " + target
		case mode.IsDir():
			out[e.Name()] = "<dir>"
		case mode&os.ModeNamedPipe != 0:
			out[e.Name()] = "<fifo>"
		default:
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			out[e.Name()] = "=" + string(b)
		}
	}
	return out
}

// psText is an expected text: a string, or {prefix, repeat, times, suffix}.
func psText(t *testing.T, raw json.RawMessage, expand func(string) string) string {
	t.Helper()
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return expand(s)
	}
	var r struct {
		Prefix *string `json:"prefix"`
		Repeat *string `json:"repeat"`
		Times  *int    `json:"times"`
		Suffix *string `json:"suffix"`
	}
	if err := decodeCorpus(raw, &r); err != nil || r.Prefix == nil || r.Repeat == nil || r.Times == nil || r.Suffix == nil {
		t.Fatalf("text: a string or {prefix, repeat, times, suffix}: %v", err)
	}
	return expand(*r.Prefix) + strings.Repeat(*r.Repeat, *r.Times) + expand(*r.Suffix)
}

func replayPostScript(t *testing.T, doc psDoc, c psPostCaseRaw) {
	root := t.TempDir()
	for _, d := range []string{"list", "pkg", "outside", "feed", "test"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cwd, err := os.Getwd()
	if err == nil {
		cwd, err = filepath.EvalSymlinks(cwd)
	}
	if err != nil {
		t.Fatal(err)
	}
	expand := strings.NewReplacer("{root}", root, "{cwd}", cwd).Replace
	for path, e := range c.Tree {
		file := filepath.Join(root, path)
		switch {
		case e.Link != nil:
			err = os.Symlink(*e.Link, file)
		case e.Dir != nil:
			err = os.Mkdir(file, 0o700)
		default:
			text := *doc.Prefix + *e.Body + "\n"
			if e.Shebang == nil {
				text = "#!/bin/sh\n" + text
			}
			perm := os.FileMode(0o755)
			if *e.Mode == "noexec" {
				perm = 0o644
			}
			if err = os.WriteFile(file, []byte(text), perm); err == nil {
				err = os.Chmod(file, perm) // the umask does not apply to the mode asked for
			}
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	feed := filepath.Join(root, "feed")
	for name, entry := range psState(t, c.Feed) {
		file := filepath.Join(feed, name)
		switch {
		case strings.HasPrefix(entry, "="):
			err = os.WriteFile(file, []byte(entry[1:]), 0o644)
		case strings.HasPrefix(entry, "-> "):
			err = os.Symlink(entry[3:], file)
		case entry == "<dir>":
			err = os.Mkdir(file, 0o700)
		default:
			t.Fatalf("feed %s: a string, {link} or {type: dir}", name)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	test := filepath.Join(root, "test")
	for _, f := range []string{"child", "alive"} {
		if err := syscall.Mkfifo(filepath.Join(test, f), 0o600); err != nil {
			t.Skipf("no fifos on this host: %v", err)
		}
	}
	for k, v := range map[string]string{"SEEN": "seen", "CHILD": "child", "ALIVE": "alive", "PID": "pid"} {
		t.Setenv("PFB_TEST_"+k, filepath.Join(test, v))
	}
	t.Setenv("PFB_TEST_ENV", *doc.Env)
	t.Setenv("PFB_TEST_ALARM", "")

	ctx, cancel, limit := limitOnEvent()
	defer cancel()
	reported, release := blockOnFifo(t, test, limit)
	defer release()
	var log, errs, transcript bytes.Buffer
	p := PostScript{Name: expand(*c.Name), Dirs: []string{filepath.Join(root, "list"), filepath.Join(root, "pkg")},
		Header: *doc.Header, Log: &log, Errors: &errs, Transcript: &transcript}
	orig := filepath.Join(feed, "feed.orig")
	var got PostScriptResult
	var between map[string]string
	if *c.ListType == "dnsbl" {
		got = p.RunDNSBL(ctx, orig, filepath.Join(feed, "feed.post"))
	} else {
		got = p.RunIP(ctx, orig, filepath.Join(feed, "feed.orig.post"), *c.ListType)
		between = listFeed(t, feed) // what the caller's empty-feed check reads
		got.Restore()
	}
	select {
	case <-reported:
		if !*c.Blocks {
			t.Error("the script blocked in a case that does not block")
		}
	default:
		if *c.Blocks {
			t.Fatal("the script never reported it was running: the kill was not the event under test")
		}
	}

	e := c.Expect
	if want, have := psState(t, e.Files), listFeed(t, feed); !maps.Equal(want, have) {
		t.Errorf("feed folder\n  expected: %q\n  actual:   %q", want, have)
	}
	if e.Between != nil {
		if want := psState(t, e.Between); !maps.Equal(want, between) {
			t.Errorf("feed folder before the restore\n  expected: %q\n  actual:   %q", want, between)
		}
	}
	var wantSeen *string
	if err := json.Unmarshal(e.Seen, &wantSeen); err != nil {
		t.Fatalf("seen: a string or null: %v", err)
	}
	seen, err := os.ReadFile(filepath.Join(test, "seen"))
	switch {
	case wantSeen == nil && err == nil:
		t.Errorf("the script ran and saw %q; want it never run", seen)
	case wantSeen != nil && err != nil:
		t.Errorf("the script never ran (%v); want it to see %q", err, expand(*wantSeen))
	case wantSeen != nil && string(seen) != expand(*wantSeen):
		t.Errorf("what the script saw\n  expected: %q\n  actual:   %q", expand(*wantSeen), seen)
	}
	for _, w := range []struct {
		what string
		raw  json.RawMessage
		got  string
	}{{"main log", e.Log, log.String()}, {"error log", e.Errors, errs.String()}, {"transcript", e.Transcript, transcript.String()}} {
		if want := psText(t, w.raw, expand); w.got != want {
			t.Errorf("%s\n  expected: %s\n  actual:   %s", w.what, clipVisible(want), clipVisible(w.got))
		}
	}
	wantLog := psText(t, e.Log, expand)
	if got.Reason != *e.Reason || got.Status != *e.Status || got.Skipped != !strings.Contains(wantLog, "\nExecuting post-script: ") {
		t.Errorf("Skipped, Reason, Status = %v, %q, %d; want %q, %d, skipped exactly when nothing is executed",
			got.Skipped, got.Reason, got.Status, *e.Reason, *e.Status)
	}
	var wantAlive *bool
	if err := json.Unmarshal(e.Alive, &wantAlive); err != nil {
		t.Fatalf("alive: a bool or null: %v", err)
	}
	if wantAlive != nil {
		if alive := childAlive(t, test, *wantAlive); alive != *wantAlive {
			t.Errorf("the script's child alive after the run = %v; want %v", alive, *wantAlive)
		}
	}
}

// childAlive reports whether the child the script started still holds the alive fifo, which it opened before it reported
// ready: a child expected gone is given until the watchdog to close it, one expected alive must hold it now. A child left
// alive is killed when the test ends.
func childAlive(t *testing.T, test string, want bool) bool {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(test, "alive"), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	deadline := time.Now()
	if !want {
		deadline = deadline.Add(watchdog)
	}
	if err := f.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	_, err = f.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		return false
	}
	if b, err := os.ReadFile(filepath.Join(test, "pid")); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 0 {
			t.Cleanup(func() { syscall.Kill(pid, syscall.SIGKILL) })
		}
	}
	return true
}

// clipVisible keeps a failure message readable when a text runs to mebibytes.
func clipVisible(s string) string {
	if len(s) > 400 {
		return fmt.Sprintf("%s ... (%d bytes) ... %s", visible(s[:200]), len(s), visible(s[len(s)-200:]))
	}
	return visible(s)
}

func TestPostScriptCorpusLoaderIsStrict(t *testing.T) {
	const ok = `{"id": "a", "description": "d", "list_type": "dnsbl", "name": "s.sh", "tree": {"list/s.sh": {"body": "true", ` +
		`"mode": "exec"}}, "feed": {}, "blocks": false, "expect": {"files": {}, "seen": null, "log": "", "errors": "", ` +
		`"transcript": "", "failed": false, "reason": "", "status": 0, "alive": null}}`
	doc := func(c string) string {
		return `{"schema": 1, "prefix": "", "env": "", "header": "h", "cases": [` + c + `]}`
	}
	if _, err := loadPostScript([]byte(doc(ok))); err != nil {
		t.Fatalf("the well-formed document is refused: %v", err)
	}
	rep := func(old, new string) string { return doc(replaceOnce(t, ok, old, new)) }
	bad := map[string]string{
		"unknown top key":          replaceOnce(t, doc(ok), `"schema": 1`, `"schema": 1, "x": 1`),
		"no prefix":                replaceOnce(t, doc(ok), `"prefix": "", `, ``),
		"unknown case key":         rep(`"description": "d",`, `"description": "d", "x": 1,`),
		"unknown expect key":       rep(`"alive": null}`, `"alive": null, "x": 1}`),
		"missing seen":             rep(`"seen": null, `, ``),
		"missing reason":           rep(`"reason": "", `, ``),
		"missing status":           rep(`"status": 0, `, ``),
		"reason without failed":    rep(`"reason": ""`, `"reason": "stage"`),
		"failed without reason":    rep(`"failed": false`, `"failed": true`),
		"unknown reason":           rep(`"failed": false, "reason": ""`, `"failed": true, "reason": "x"`),
		"status without exit":      rep(`"status": 0`, `"status": 3`),
		"exit without status":      rep(`"failed": false, "reason": ""`, `"failed": true, "reason": "exit"`),
		"bad list type":            rep(`"list_type": "dnsbl"`, `"list_type": "x"`),
		"between for dnsbl":        rep(`"files": {},`, `"files": {}, "between": {},`),
		"no between for ip":        rep(`"list_type": "dnsbl"`, `"list_type": "_v4"`),
		"tree outside the folders": rep(`"list/s.sh"`, `"etc/s.sh"`),
		"tree entry of two kinds":  rep(`"mode": "exec"}`, `"mode": "exec", "dir": true}`),
		"bad mode":                 rep(`"mode": "exec"`, `"mode": "x"`),
		"shebang true":             rep(`"mode": "exec"}`, `"mode": "exec", "shebang": true}`),
		"old_expect without why":   rep(`"alive": null}}`, `"alive": null}, "old_expect": {"log": ""}}`),
		"duplicate id":             doc(ok + `,` + ok),
		"empty cases":              `{"schema": 1, "prefix": "", "env": "", "header": "h", "cases": []}`,
	}
	for name, text := range bad {
		if _, err := loadPostScript([]byte(text)); err == nil {
			t.Errorf("%s: the malformed document is accepted", name)
		}
	}
}

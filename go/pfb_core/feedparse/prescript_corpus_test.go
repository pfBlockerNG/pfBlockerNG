package feedparse

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Replays testdata/prescript.json (schema: testdata/README.md): a list's pre-script on a staged copy of the normalized feed,
// through RunPreScript and Cleanup. The PHP runner (tests/php/FeedParsePreScriptCorpusTest.php) replays the same file through the
// production functions, which go through sh where Core runs the script itself: the hostile script names pin that both agree.
//
// A script that blocks reads a fifo nobody writes. It first tells the runner it is running through a second fifo, and the runner
// then cancels the context: the kill is driven by that event, never by a sleep or a measured duration. The watchdog below only
// frees a run that is stuck, and the test then fails because the script never reported.

type psFilesJSON struct {
	Norm      *string `json:"norm"`
	NormHex   *string `json:"norm_hex"`
	Staged    *string `json:"staged"`
	StagedHex *string `json:"staged_hex"`
}

type psCaseJSON struct {
	ID          *string      `json:"id"`
	Description *string      `json:"description"`
	Setup       *psFilesJSON `json:"setup"`
	Script      *struct {
		Name    *string `json:"name"`
		Body    *string `json:"body"`
		Mode    *string `json:"mode"`
		Shebang *bool   `json:"shebang"`
	} `json:"script"`
	ListType *string `json:"list_type"`
	Blocks   *bool   `json:"blocks"`
	Expect   *struct {
		OK     *bool        `json:"ok"`
		Reason *string      `json:"reason"`
		Status *int         `json:"status"`
		Files  *psFilesJSON `json:"files"`
	} `json:"expect"`
}

type psCase struct {
	id                      string
	setup, files            map[string]string
	name, body, mode, vtype string
	shebang, blocks, ok     bool
	reason                  string
	status                  int
}

func (f *psFilesJSON) state(id string) (map[string]string, error) {
	out := map[string]string{}
	for key, pair := range map[string][2]*string{"norm": {f.Norm, f.NormHex}, "staged": {f.Staged, f.StagedHex}} {
		b, err := corpusBytes(id, key, pair[0], pair[1], false)
		if err != nil {
			return nil, err
		}
		if pair[0] != nil || pair[1] != nil {
			out[key] = string(b)
		}
	}
	return out, nil
}

func loadPreScript(data []byte) ([]psCase, error) {
	var file struct {
		Schema *int         `json:"schema"`
		Cases  []psCaseJSON `json:"cases"`
	}
	if err := decodeCorpus(data, &file); err != nil {
		return nil, err
	}
	if file.Schema == nil || *file.Schema != 1 || len(file.Cases) == 0 {
		return nil, errors.New(`prescript.json must be {"schema": 1, "cases": [non-empty list]}`)
	}
	ids := corpusIDs{}
	var out []psCase
	for i, c := range file.Cases {
		if err := ids.add(c.ID, c.Description); err != nil {
			return nil, fmt.Errorf("case #%d: %w", i, err)
		}
		s, e := c.Script, c.Expect
		if c.Setup == nil || s == nil || e == nil || s.Name == nil || s.Body == nil || s.Mode == nil || c.ListType == nil || c.Blocks == nil ||
			e.OK == nil || e.Reason == nil || e.Status == nil || e.Files == nil {
			return nil, fmt.Errorf("case %s: every key is required", *c.ID)
		}
		if *s.Name == "" || strings.ContainsAny(*s.Name, "/\x00") || (*s.Mode != "exec" && *s.Mode != "noexec" && *s.Mode != "absent") ||
			(*c.ListType != "_v4" && *c.ListType != "_v6" && *c.ListType != "dnsbl") {
			return nil, fmt.Errorf("case %s: script name without / or NUL, mode exec, noexec or absent, list_type _v4, _v6 or dnsbl", *c.ID)
		}
		if s.Shebang != nil && *s.Shebang {
			return nil, fmt.Errorf("case %s: shebang is only ever false (a script has its #! line unless the case says otherwise)", *c.ID)
		}
		switch *e.Reason {
		case "", PreScriptStage, PreScriptExit, PreScriptTimeout, PreScriptDeleted:
		default:
			return nil, fmt.Errorf("case %s: unknown reason %q", *c.ID, *e.Reason)
		}
		if *e.OK != (*e.Reason == "") || (*e.Reason == PreScriptExit) != (*e.Status != 0) {
			return nil, fmt.Errorf("case %s: ok is true exactly when reason is empty, and status is non-zero exactly when reason is exit", *c.ID)
		}
		want := psCase{id: *c.ID, name: *s.Name, body: *s.Body, mode: *s.Mode, shebang: s.Shebang == nil, vtype: *c.ListType, blocks: *c.Blocks, ok: *e.OK, reason: *e.Reason, status: *e.Status}
		var err error
		if want.setup, err = c.Setup.state(want.id); err != nil {
			return nil, err
		}
		if want.files, err = e.Files.state(want.id); err != nil {
			return nil, err
		}
		out = append(out, want)
	}
	return out, nil
}

// watchdog frees a stuck run: it ends the context the script runs under, and the test then fails on the missing report.
const watchdog = time.Minute

func TestPreScriptCorpus(t *testing.T) {
	data, err := os.ReadFile("testdata/prescript.json")
	if err != nil {
		t.Fatal(err)
	}
	cases, err := loadPreScript(data)
	if err != nil {
		t.Fatalf("prescript.json: %v", err)
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) { replayPreScript(t, c) })
	}
}

func replayPreScript(t *testing.T, c psCase) {
	dir := t.TempDir()
	norm, staged := filepath.Join(dir, "feed.norm"), filepath.Join(dir, "feed.pre")
	for key, content := range c.setup {
		path := norm
		if key == "staged" {
			path = staged
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "bin", c.name)
	if c.mode != "absent" {
		perm := os.FileMode(0o755)
		if c.mode == "noexec" {
			perm = 0o644
		}
		text := c.body + "\n"
		if c.shebang {
			text = "#!/bin/sh\n" + text
		}
		if err := os.WriteFile(script, []byte(text), perm); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(script, perm); err != nil { // the umask does not apply to the mode asked for
			t.Fatal(err)
		}
	}
	canary := filepath.Join(dir, "canary")
	t.Setenv("PFB_TEST_CANARY", canary)

	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()
	var reported <-chan struct{}
	if c.blocks {
		var release func()
		reported, release = blockOnFifo(t, dir, cancel)
		defer release()
	}
	got := RunPreScript(ctx, script, norm, staged, io.Discard, c.vtype)
	if c.blocks {
		select {
		case <-reported:
		default:
			t.Fatal("the script never reported it was running: the kill was not the event under test")
		}
	}

	wantPath := norm
	if c.ok {
		wantPath = staged
	}
	if got.OK != c.ok || got.Reason != c.reason || got.Status != c.status || got.Path != wantPath {
		t.Errorf("OK, Reason, Status, Path = %v, %q, %d, %s; want %v, %q, %d, %s", got.OK, got.Reason, got.Status, filepath.Base(got.Path), c.ok, c.reason, c.status, filepath.Base(wantPath))
	}
	for key, path := range map[string]string{"norm": norm, "staged": staged} {
		b, err := os.ReadFile(path)
		want, wantOK := c.files[key]
		switch {
		case err != nil && wantOK:
			t.Errorf("%s: expected %s, got no file (%v)", key, visible(want), err)
		case err == nil && !wantOK:
			t.Errorf("%s should not exist, holds %s", key, visible(string(b)))
		case err == nil && string(b) != want:
			t.Errorf("%s\n  expected: %s\n  actual:   %s", key, visible(want), visible(string(b)))
		}
	}
	if _, err := os.Stat(canary); err == nil {
		t.Error("the script name reached a shell as code")
	}
	got.Cleanup()
	if _, err := os.Stat(staged); err == nil {
		t.Error("the staged copy outlives the parse")
	}
}

// blockOnFifo makes the fifos a blocking script uses (PFB_TEST_BLOCK is read and never written, PFB_TEST_READY is where the
// script reports it is running) and cancels the run once it has. reported is closed by that report; release frees the reader
// when the script never came, and waits for it.
func blockOnFifo(t *testing.T, dir string, cancel context.CancelFunc) (reported <-chan struct{}, release func()) {
	t.Helper()
	block, ready := filepath.Join(dir, "block.fifo"), filepath.Join(dir, "ready.fifo")
	for _, f := range []string{block, ready} {
		if err := syscall.Mkfifo(f, 0o600); err != nil {
			t.Skipf("no fifos on this host: %v", err)
		}
	}
	t.Setenv("PFB_TEST_BLOCK", block)
	t.Setenv("PFB_TEST_READY", ready)
	// Read-write, so that opening it waits for no one and no writer's exit ends the read: the read ends with the script's report.
	r, err := os.OpenFile(ready, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		if n, _ := r.Read(make([]byte, 1)); n == 1 {
			close(got)
			cancel()
		}
	}()
	return got, func() {
		r.Close() // frees a read the script never answered
		<-done
	}
}

func TestPreScriptCorpusLoaderIsStrict(t *testing.T) {
	const ok = `{"id": "a", "description": "d", "setup": {"norm": "a.example\n"}, "script": {"name": "s.sh", "body": "true", "mode": "exec"}, "list_type": "_v4", "blocks": false, "expect": {"ok": true, "reason": "", "status": 0, "files": {"norm": "a.example\n", "staged": "a.example\n"}}}`
	doc := func(c string) string { return `{"schema": 1, "cases": [` + c + `]}` }
	if _, err := loadPreScript([]byte(doc(ok))); err != nil {
		t.Fatalf("the well-formed document is refused: %v", err)
	}
	rep := func(old, new string) string { return doc(replaceOnce(t, ok, old, new)) }
	bad := map[string]string{
		"unknown top key":     replaceOnce(t, doc(ok), `"schema": 1`, `"schema": 1, "x": 1`),
		"unknown case key":    rep(`"description": "d",`, `"description": "d", "x": 1,`),
		"unknown setup key":   rep(`"setup": {"norm"`, `"setup": {"x": "y", "norm"`),
		"norm and norm_hex":   rep(`"setup": {"norm": "a.example\n"}`, `"setup": {"norm": "a", "norm_hex": "ff"}`),
		"unknown script key":  rep(`"mode": "exec"}`, `"mode": "exec", "x": 1}`),
		"script name with /":  rep(`"name": "s.sh"`, `"name": "a/b"`),
		"bad mode":            rep(`"mode": "exec"`, `"mode": "x"`),
		"shebang true":        rep(`"mode": "exec"}`, `"mode": "exec", "shebang": true}`),
		"shebang not a bool":  rep(`"mode": "exec"}`, `"mode": "exec", "shebang": 0}`),
		"bad list type":       rep(`"list_type": "_v4"`, `"list_type": "x"`),
		"blocks not a bool":   rep(`"blocks": false`, `"blocks": 0`),
		"ok with a reason":    rep(`"reason": ""`, `"reason": "exit"`),
		"exit without status": rep(`"ok": true, "reason": ""`, `"ok": false, "reason": "exit"`),
		"status without exit": rep(`"status": 0`, `"status": 3`),
		"unknown reason":      rep(`"ok": true, "reason": ""`, `"ok": false, "reason": "x"`),
		"unknown files key":   rep(`"staged": "a.example\n"}}}`, `"staged": "a.example\n", "x": "y"}}}`),
		"duplicate id":        `{"schema": 1, "cases": [` + ok + `,` + ok + `]}`,
		"empty cases":         `{"schema": 1, "cases": []}`,
	}
	for name, text := range bad {
		if _, err := loadPreScript([]byte(text)); err == nil {
			t.Errorf("%s: the malformed document is accepted", name)
		}
	}
}

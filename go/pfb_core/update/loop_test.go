package update

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
)

// adapterEnv makes this test binary, run with no argument, stand in for the Outpost's settings adapter
// (settings.AdapterBackend): it reads the request, appends "run" to the file runs, opens the FIFO started for writing
// and then the FIFO proceed for reading when they exist (each open waits for the test), and then answers by the files
// of its folder: block (it never answers), fail (its text on stderr, exit status 1), else reply on stdout.
const adapterEnv = "PFB_TEST_SETTINGS_ADAPTER"

func init() {
	dir := os.Getenv(adapterEnv)
	if dir == "" || len(os.Args) != 1 {
		return
	}
	_, _ = io.ReadAll(os.Stdin)
	appendFile(filepath.Join(dir, "runs"), "run\n")
	for _, fifo := range []struct {
		name string
		flag int
	}{{"started", os.O_WRONLY}, {"proceed", os.O_RDONLY}} {
		if f, err := os.OpenFile(filepath.Join(dir, fifo.name), fifo.flag, 0); err == nil {
			f.Close()
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "block")); err == nil {
		time.Sleep(time.Hour) // never answers: the backend's read timeout ends it
	}
	if msg, err := os.ReadFile(filepath.Join(dir, "fail")); err == nil {
		os.Stderr.Write(msg)
		os.Exit(1)
	}
	reply, _ := os.ReadFile(filepath.Join(dir, "reply"))
	os.Stdout.Write(reply)
	os.Exit(0)
}

func appendFile(path, s string) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err == nil {
		_, _ = f.WriteString(s)
		f.Close()
	}
}

// settingsAdapter is the test binary as the settings adapter, answering reply; its folder is returned for the other files.
func settingsAdapter(t *testing.T, reply string) (path, dir string) {
	t.Helper()
	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "reply"), []byte(reply), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(adapterEnv, dir)
	return os.Args[0], dir
}

func adapterRuns(t *testing.T, dir string) int {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "runs"))
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(b), "run\n")
}

func touch(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// plainReply is a read reply at revision 7 with every projection at its defaults and a pending token.
const plainReply = `{"version":1,"revision":7,"settings":{},"platform":{"pendingToken":"tok-of-the-snapshot"}}`

// disabledReply is plainReply with scheduled work switched off (the .pfb_cron_disable marker).
const disabledReply = `{"version":1,"revision":7,"settings":{"ingest":{"scheduledWorkDisabled":true}},"platform":{"pendingToken":"t"}}`

// secretReply sets every secret field of the production schema, each to a value that appears nowhere else.
const secretReply = `{"version":1,"revision":9,"settings":{
"extras":{"maxmindKey":"MMKEYsecret01","ipinfoToken":"IPINFOsecret02","top1mToken":"TOP1Msecret03"},
"ingest":{"proxyPassword":"PROXYsecret04"},
"feeds/ipv4":{"groups":[{"name":"Alpha","action":"Deny_Inbound","feeds":[{"header":"FourA","url":"https://example.org/a","credentials":"u:FEEDFOURsecret05"}]}]},
"feeds/ipv6":{"groups":[{"name":"Beta","action":"Deny_Inbound","feeds":[{"header":"SixB","url":"https://example.org/b","credentials":"u:FEEDSIXsecret06"}]}]},
"feeds/dnsbl":{"groups":[{"name":"Ads","action":"unbound","feeds":[{"header":"DnsC","url":"https://example.org/c","credentials":"u:DNSBLsecret07"}]}]},
"schedule":{"categoryProviders":[{"id":"prov","selected":true,"categories":"cat1","password":"PROVIDERsecret08"}]}},
"platform":{"pendingToken":"TOKENsecret09"}}`

var plantedSecrets = []string{"MMKEYsecret01", "IPINFOsecret02", "TOP1Msecret03", "PROXYsecret04", "u:FEEDFOURsecret05",
	"u:FEEDSIXsecret06", "u:DNSBLsecret07", "PROVIDERsecret08"}

// recordBoundaries records every stage boundary the loop reaches while the test runs.
func recordBoundaries(t *testing.T) *[]string {
	t.Helper()
	var seen []string
	prev := boundary
	boundary = func(name string) { seen = append(seen, name) }
	t.Cleanup(func() { boundary = prev })
	return &seen
}

// loopCommand is a Command whose program records each run in its folder and whose state carries loop.
func loopCommand(t *testing.T, loop *Loop) (*Command, string) {
	t.Helper()
	c, dir := program(t, `echo run >> "$D/runs"`)
	c.Loop = loop
	return c, dir
}

// The stage boundaries of spec section 3 from the snapshot on, in order (stage 17, the outcomes, is written as each feed
// finishes and has no boundary of its own), then the end of the loop.
var wantBoundaries = []string{"snapshot", "work-list", "pre-hook", "extras", "change-detection", "apply-window", "dnsbl",
	"dnsblip", "publish-dnsbl", "geoip-sets", "ip", "recompute", "suppression", "uber", "publish-ip", "apply", "post-hook",
	"settle", "end"}

// WHEN the loop takes its snapshot THEN it reads the adapter once, holds that revision's settings and keeps the pending
// token as the adapter wrote it, in memory.
func TestTheSnapshotReadsTheAdapterOnceAndKeepsTheTokenInMemory(t *testing.T) {
	adapter, dir := settingsAdapter(t, plainReply)
	u := &updater{loop: Loop{SettingsCmd: adapter}, req: Request{Trigger: "manual", Scope: "both", Force: "none"}, stateDir: t.TempDir()}
	if err := u.run(); err != nil {
		t.Fatalf("run = %v, want nil", err)
	}
	if n := adapterRuns(t, dir); n != 1 {
		t.Errorf("the adapter ran %d times, want once", n)
	}
	if u.settings == nil {
		t.Fatal("the loop holds no snapshot")
	}
	if snap, _ := u.settings.Get(nil); !snap.Initialized || snap.Revision != 7 {
		t.Errorf("snapshot = initialized %t revision %d, want initialized at revision 7", snap.Initialized, snap.Revision)
	}
	if string(u.token) != `"tok-of-the-snapshot"` {
		t.Errorf("token = %s, want the adapter's JSON value \"tok-of-the-snapshot\"", u.token)
	}
}

// WHEN Core keeps its settings in its state directory (no adapter) THEN the snapshot reads them from there.
func TestWithoutAnAdapterTheSnapshotReadsTheStateDirectorysSettings(t *testing.T) {
	stateDir := t.TempDir()
	st, err := settings.Open(stateDir, settings.Production())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Initialize(t.Context(), map[string]map[string]json.RawMessage{}); err != nil {
		t.Fatal(err)
	}
	u := &updater{req: Request{Trigger: "manual"}, stateDir: stateDir}
	if err := u.run(); err != nil {
		t.Fatalf("run = %v, want nil", err)
	}
	if snap, _ := u.settings.Get(nil); !snap.Initialized || snap.Revision != 1 {
		t.Errorf("snapshot = initialized %t revision %d, want the state directory's revision 1", snap.Initialized, snap.Revision)
	}
}

// WHEN scheduled work is switched off THEN a scheduled Update ends skipped after the snapshot, and the other triggers run.
func TestOnlyAScheduledUpdateIsSkippedWhenScheduledWorkIsDisabled(t *testing.T) {
	for _, tc := range []struct {
		trigger string
		want    error
		reached []string
	}{
		{"scheduled", ErrDeferred, []string{"snapshot"}},
		{"retry", nil, wantBoundaries},
		{"manual", nil, wantBoundaries},
		{"apply", nil, wantBoundaries},
	} {
		t.Run(tc.trigger, func(t *testing.T) {
			seen := recordBoundaries(t)
			adapter, _ := settingsAdapter(t, disabledReply)
			u := &updater{loop: Loop{SettingsCmd: adapter}, req: Request{Trigger: tc.trigger}, stateDir: t.TempDir()}
			if err := u.run(); !errors.Is(err, tc.want) || tc.want == nil && err != nil {
				t.Fatalf("run = %v, want %v", err, tc.want)
			}
			if !slices.Equal(*seen, tc.reached) {
				t.Errorf("boundaries:\n have %q\n want %q", *seen, tc.reached)
			}
		})
	}
	t.Run("scheduled with scheduled work on", func(t *testing.T) {
		adapter, _ := settingsAdapter(t, plainReply)
		u := &updater{loop: Loop{SettingsCmd: adapter}, req: Request{Trigger: "scheduled"}, stateDir: t.TempDir()}
		if err := u.run(); err != nil {
			t.Fatalf("run = %v, want nil", err)
		}
	})
}

// WHEN the settings cannot be read at the snapshot (the adapter fails, runs past its timeout, answers revision 0, or the
// state directory holds no settings) THEN the Update fails and no stage after the snapshot is reached: nothing is published.
func TestASnapshotThatCannotBeReadFailsTheUpdateBeforeAnyLaterStage(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T) *updater
	}{
		{"adapter fails", func(t *testing.T) *updater {
			adapter, dir := settingsAdapter(t, plainReply)
			touch(t, filepath.Join(dir, "fail"), "config.xml is locked")
			return &updater{loop: Loop{SettingsCmd: adapter}, req: Request{Trigger: "manual"}, stateDir: t.TempDir()}
		}},
		{"adapter runs past its timeout", func(t *testing.T) *updater {
			adapter, dir := settingsAdapter(t, plainReply)
			touch(t, filepath.Join(dir, "block"), "")
			return &updater{loop: Loop{SettingsCmd: adapter}, req: Request{Trigger: "manual"}, stateDir: t.TempDir(),
				readTimeout: 50 * time.Millisecond}
		}},
		{"adapter answers revision 0", func(t *testing.T) *updater {
			adapter, _ := settingsAdapter(t, `{"version":1,"revision":0,"settings":{}}`)
			return &updater{loop: Loop{SettingsCmd: adapter}, req: Request{Trigger: "manual"}, stateDir: t.TempDir()}
		}},
		{"no settings in the state directory", func(t *testing.T) *updater {
			return &updater{req: Request{Trigger: "manual"}, stateDir: t.TempDir()}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := tc.prepare(t)
			seen := recordBoundaries(t)
			err := u.run()
			if err == nil || errors.Is(err, ErrDeferred) {
				t.Fatalf("run = %v, want a failure", err)
			}
			if !slices.Equal(*seen, []string{"snapshot"}) {
				t.Errorf("boundaries:\n have %q\n want only the snapshot's", *seen)
			}
		})
	}
}

// WHEN Core admits an Update whose state carries the loop THEN the worker runs the loop, and the Update program is not
// started; the loop reaches the worker in its request only, and the status the worker publishes has no loop member, so
// that a Core that does not know the member can still read it.
func TestTheWorkerRunsTheLoopInsteadOfTheProgram(t *testing.T) {
	adapter, _ := settingsAdapter(t, plainReply)
	log := independentLog(t)
	c, pdir := loopCommand(t, &Loop{SettingsCmd: adapter})
	if _, err := runCmd(t, c, Request{Trigger: "manual", Scope: "both", Force: "none"}, log); err != nil {
		t.Fatalf("Run = %v, want success", err)
	}
	if _, err := os.Stat(filepath.Join(pdir, "runs")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the Update program ran (%v); the loop replaces it", err)
	}
	if text := logText(t, log); !strings.Contains(text, "settings revision 7") {
		t.Errorf("transcript = %q, want the snapshot's revision line", text)
	}
	state, err := readWorkerState(log.Name() + ".status")
	if err != nil || state.ExitCode == nil || *state.ExitCode != 0 || state.Failure != "" {
		t.Errorf("terminal status = %+v, %v; want exit 0 without failure", state, err)
	}
	if loop, ok := fileMembers(t, log.Name()+".status")["loop"]; ok {
		t.Errorf("the published status carries the loop %s, want none", loop)
	}
	var loop Loop
	if err := json.Unmarshal(fileMembers(t, log.Name()+".request")["loop"], &loop); err != nil || loop.SettingsCmd != adapter {
		t.Errorf("the request's loop = %+v, %v; want the adapter %q", loop, err, adapter)
	}
}

// fileMembers is the JSON object in path, member by member.
func fileMembers(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	var members map[string]json.RawMessage
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &members) != nil {
		t.Fatalf("%s = %q, %v", path, b, err)
	}
	return members
}

// waitUnlocked waits until no process holds the lock file at path: the worker holds it until it has ended.
func waitUnlocked(t *testing.T, path string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	locked := make(chan error, 1)
	go func() { locked <- syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }()
	select {
	case err := <-locked:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(stuck):
		t.Fatalf("STUCK: the worker did not end within %v", stuck)
	}
}

// WHEN the worker runs the loop THEN the settings adapter starts only after the worker has completed its ownership
// handshake with Launch: a controller that stops observing once the adapter has started ends with its own cancellation,
// because Launch has already handed the Update over, never with a worker that did not acknowledge ownership.
func TestTheSnapshotIsTakenOnlyAfterTheOwnershipHandshake(t *testing.T) {
	adapter, adir := settingsAdapter(t, plainReply)
	started, proceed := filepath.Join(adir, "started"), filepath.Join(adir, "proceed")
	for _, fifo := range []string{started, proceed} {
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	log := independentLog(t)
	c, _ := loopCommand(t, &Loop{SettingsCmd: adapter})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := make(chan error, 1)
	go func() { _, err := c.Run(ctx, Request{Trigger: "manual"}, log); ran <- err }()
	opened := awaitFIFOWriter(t, started) // returns once the adapter has opened it: the adapter runs
	select {
	case err := <-opened:
		if err != nil {
			t.Fatal(err)
		}
	case err := <-ran:
		t.Fatalf("Run = %v before the adapter started", err)
	case <-time.After(stuck):
		t.Fatalf("STUCK: the adapter did not start within %v", stuck)
	}
	cancel()
	select {
	case err := <-ran:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run = %v, want context.Canceled: the adapter ran before the worker completed its handshake", err)
		}
	case <-time.After(stuck):
		t.Fatalf("STUCK: Run did not return within %v", stuck)
	}
	releaseFIFO(t, proceed) // lets the adapter answer
	waitUnlocked(t, log.Name()+".lock")
}

// awaitFIFOWriter opens path for reading in a goroutine and sends the open's error once a writer holds the FIFO. When
// no writer came by the end of the test, a writer of its own lets the blocked open return, so no goroutine outlives
// the test.
func awaitFIFOWriter(t *testing.T, path string) <-chan error {
	t.Helper()
	opened, done := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(done)
		f, err := os.OpenFile(path, os.O_RDONLY, 0)
		if err == nil {
			f.Close()
		}
		opened <- err
	}()
	t.Cleanup(func() {
		// Without a blocked reader this open fails with ENXIO: the goroutine has ended already.
		if w, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			<-done
			w.Close()
		}
	})
	return opened
}

// releaseFIFO opens path for writing, which returns once a reader holds it. When no reader comes (an adapter that died
// or timed out) it fails the test and leaves no goroutine blocked, instead of blocking until the suite's timeout.
func releaseFIFO(t *testing.T, path string) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err == nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(stuck):
		// A reader of our own lets the blocked open return, so the goroutine ends with the test.
		if r, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
			<-done
			r.Close()
		}
		t.Fatalf("STUCK: nothing read %s within %v", path, stuck)
	}
}

// WHEN the settings adapter fails with a line break, an escape sequence and kilobytes of text on its stderr THEN the
// transcript, the main log and the receipt's failure text each hold one bounded line without a control character.
func TestAFailedSnapshotWritesOneBoundedSanitizedLine(t *testing.T) {
	adapter, adir := settingsAdapter(t, plainReply)
	touch(t, filepath.Join(adir, "fail"), "MARK locked\tA\nsecond line \x1b[31mred "+strings.Repeat("x", 4000))
	mainLog := filepath.Join(t.TempDir(), "pfblockerng.log")
	log := independentLog(t)
	c, _ := loopCommand(t, &Loop{SettingsCmd: adapter, MainLog: mainLog})
	if _, err := runCmd(t, c, Request{Trigger: "manual"}, log); err == nil {
		t.Fatal("Run = nil, want the snapshot's failure")
	}
	const bound = 512
	state, err := readWorkerState(log.Name() + ".status")
	if err != nil {
		t.Fatal(err)
	}
	main, err := os.ReadFile(mainLog)
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"transcript": logText(t, log), "main log": string(main), "failure": state.Failure + "\n"} {
		var marked []string
		for _, line := range strings.SplitAfter(text, "\n") {
			if strings.Contains(line, "MARK") || strings.Contains(line, "second line") || strings.Contains(line, "xxxx") {
				marked = append(marked, line)
			}
		}
		if len(marked) != 1 {
			t.Errorf("%s holds %d lines of the adapter's text, want one; the second starts %.40q", name, len(marked), marked[min(1, len(marked)-1)])
			continue
		}
		line := strings.TrimSuffix(marked[0], "\n")
		if !strings.Contains(line, "MARK locked") || len(line) > bound || strings.IndexFunc(line, unicode.IsControl) >= 0 {
			t.Errorf("%s line = %.600q (%d bytes), want the adapter's reason in at most %d bytes without a control character",
				name, line, len(line), bound)
		}
	}
}

// WHEN the main log is missing THEN the loop creates it with the mode the package's PHP logger gives a new log
// (file_put_contents: 0666 less the umask); a FIFO, with or without a reader, a directory, a file with a second hard
// link and a symbolic link are refused, and opening a FIFO never waits for a reader.
func TestTheMainLogIsCreatedAsThePackageCreatesItAndOnlyAPlainFileIsTaken(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		old := syscall.Umask(0o022)
		defer syscall.Umask(old)
		path := filepath.Join(t.TempDir(), "pfblockerng.log")
		f, err := openMainLog(path)
		if err != nil {
			t.Fatalf("openMainLog = %v, want the log created", err)
		}
		f.Close()
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o644 {
			t.Errorf("the created main log = %v, %v; want mode 0644 under umask 022", info.Mode(), err)
		}
	})
	refused := func(t *testing.T, path string) {
		t.Helper()
		opened := make(chan error, 1)
		go func() {
			f, err := openMainLog(path)
			if err == nil {
				f.Close()
			}
			opened <- err
		}()
		select {
		case err := <-opened:
			if err == nil {
				t.Errorf("openMainLog(%s) = nil, want a refusal", path)
			}
		case <-time.After(stuck):
			if r, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil { // frees an open that waits
				defer r.Close()
				<-opened
			}
			t.Fatalf("STUCK: openMainLog(%s) waited %v for a reader", path, stuck)
		}
	}
	fifo := func(t *testing.T) string {
		path := filepath.Join(t.TempDir(), "pfblockerng.log")
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	t.Run("FIFO without a reader", func(t *testing.T) { refused(t, fifo(t)) })
	t.Run("FIFO with a reader", func(t *testing.T) {
		path := fifo(t)
		r, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		refused(t, path)
	})
	t.Run("directory", func(t *testing.T) { refused(t, t.TempDir()) })
	t.Run("second hard link", func(t *testing.T) {
		dir := t.TempDir()
		touch(t, filepath.Join(dir, "other"), "kept")
		if err := os.Link(filepath.Join(dir, "other"), filepath.Join(dir, "pfblockerng.log")); err != nil {
			t.Fatal(err)
		}
		refused(t, filepath.Join(dir, "pfblockerng.log"))
		if b, _ := os.ReadFile(filepath.Join(dir, "other")); string(b) != "kept" {
			t.Errorf("the other link = %q, want it untouched", b)
		}
	})
	t.Run("symbolic link", func(t *testing.T) {
		dir := t.TempDir()
		touch(t, filepath.Join(dir, "target"), "")
		if err := os.Symlink(filepath.Join(dir, "target"), filepath.Join(dir, "pfblockerng.log")); err != nil {
			t.Fatal(err)
		}
		refused(t, filepath.Join(dir, "pfblockerng.log"))
	})
}

// WHEN the loop skips a scheduled Update THEN Core sees it deferred (the result "skipped"), as for exit status 75.
func TestAScheduledUpdateTheLoopSkipsIsDeferred(t *testing.T) {
	adapter, _ := settingsAdapter(t, disabledReply)
	log := independentLog(t)
	c, _ := loopCommand(t, &Loop{SettingsCmd: adapter})
	if _, err := runCmd(t, c, Request{Trigger: "scheduled", Feeds: []string{"ipv4:a_v4"}}, log); !errors.Is(err, ErrDeferred) {
		t.Fatalf("Run = %v, want ErrDeferred", err)
	}
	if text := logText(t, log); !strings.Contains(text, "skipped") {
		t.Errorf("transcript = %q, want the skip said", text)
	}
}

// WHEN the worker's snapshot fails THEN the Update fails with the reason in the transcript, reports no result and
// publishes nothing into the resource store.
func TestAFailedSnapshotFailsTheUpdateAndPublishesNothing(t *testing.T) {
	adapter, adir := settingsAdapter(t, plainReply)
	touch(t, filepath.Join(adir, "fail"), "config.xml is locked")
	resources := t.TempDir()
	log := independentLog(t)
	c, _ := loopCommand(t, &Loop{SettingsCmd: adapter, ResourceDir: resources})
	res, err := runCmd(t, c, Request{Trigger: "manual"}, log)
	if err == nil || errors.Is(err, ErrDeferred) {
		t.Fatalf("Run = %v, want a failure", err)
	}
	if !reflect.DeepEqual(res, Result{}) {
		t.Errorf("result = %+v, want none", res)
	}
	if text := logText(t, log); !strings.Contains(text, "config.xml is locked") {
		t.Errorf("transcript = %q, want the adapter's reason", text)
	}
	if entries, _ := os.ReadDir(resources); len(entries) != 0 {
		t.Errorf("the resource store holds %d entries, want none", len(entries))
	}
	if b, _ := os.ReadFile(log.Name() + ".result"); len(b) != 0 {
		t.Errorf("result file = %q, want empty", b)
	}
}

// WHEN the loop runs with a main log THEN its lines go to the transcript and are appended to the main log as well.
func TestTheLoopsLinesGoToTheTranscriptAndTheMainLog(t *testing.T) {
	adapter, _ := settingsAdapter(t, plainReply)
	mainLog := filepath.Join(t.TempDir(), "pfblockerng.log")
	touch(t, mainLog, "earlier line\n")
	log := independentLog(t)
	c, _ := loopCommand(t, &Loop{SettingsCmd: adapter, MainLog: mainLog})
	if _, err := runCmd(t, c, Request{Trigger: "manual"}, log); err != nil {
		t.Fatalf("Run = %v, want success", err)
	}
	main, err := os.ReadFile(mainLog)
	if err != nil || !strings.HasPrefix(string(main), "earlier line\n") || !strings.Contains(string(main), "settings revision 7") {
		t.Errorf("main log = %q, %v; want its earlier line kept and the revision line appended", main, err)
	}
	if text := logText(t, log); !strings.Contains(text, "settings revision 7") {
		t.Errorf("transcript = %q, want the revision line", text)
	}
}

// WHEN the main log is a symbolic link THEN the Update fails before the snapshot and the link's target is untouched.
func TestAMainLogThatIsALinkFailsTheUpdateAndLeavesItsTargetAlone(t *testing.T) {
	adapter, adir := settingsAdapter(t, plainReply)
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	touch(t, target, "untouched")
	mainLog := filepath.Join(dir, "pfblockerng.log")
	if err := os.Symlink(target, mainLog); err != nil {
		t.Fatal(err)
	}
	log := independentLog(t)
	c, _ := loopCommand(t, &Loop{SettingsCmd: adapter, MainLog: mainLog})
	if _, err := runCmd(t, c, Request{Trigger: "manual"}, log); err == nil {
		t.Fatal("Run = nil, want a failure for a main log that is a link")
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "untouched" {
		t.Errorf("link target = %q, %v; want untouched", b, err)
	}
	if n := adapterRuns(t, adir); n != 0 {
		t.Errorf("the adapter ran %d times, want none: the sinks are opened before the snapshot", n)
	}
}

// secretsOf adds to found every secret value in value, the fields of one projection or list item, and marks each secret
// field's path in covered when it holds one.
func secretsOf(path string, fields []settings.Field, value map[string]any, found, covered map[string]bool) {
	for _, f := range fields {
		switch {
		case f.Secret:
			covered[path+"."+f.Name] = covered[path+"."+f.Name] || value[f.Name] != ""
			if s, ok := value[f.Name].(string); ok && s != "" {
				found[s] = true
			}
		case f.Type == settings.TypeList:
			items, _ := value[f.Name].([]any)
			for _, item := range items {
				if m, ok := item.(map[string]any); ok {
					secretsOf(path+"."+f.Name, f.Items, m, found, covered)
				}
			}
		}
	}
}

// secretFields is the path of every secret field of the schema.
func secretFields(path string, fields []settings.Field, into map[string]bool) {
	for _, f := range fields {
		if f.Secret {
			into[path+"."+f.Name] = true
		}
		secretFields(path+"."+f.Name, f.Items, into)
	}
}

// WHEN a snapshot holds a secret in every secret field of the schema THEN no secret, and not the pending token, appears in
// the worker's state files, its transcript, its result file, the main log or any other file of the state directory.
func TestNoSecretOfTheSnapshotIsWrittenAnywhere(t *testing.T) {
	adapter, _ := settingsAdapter(t, secretReply)
	u := &updater{loop: Loop{SettingsCmd: adapter}, req: Request{Trigger: "manual"}, stateDir: t.TempDir()}
	if err := u.run(); err != nil {
		t.Fatalf("run = %v, want nil", err)
	}
	found, covered, want := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, p := range settings.Production().Projections {
		secretFields(p.ID, p.Fields, want)
		value, err := u.settings.GetClear(p.ID)
		if err != nil {
			t.Fatal(err)
		}
		secretsOf(p.ID, p.Fields, value, found, covered)
	}
	for field := range want {
		if !covered[field] {
			t.Errorf("the fixture sets no value for the secret field %s: the scan would miss it", field)
		}
	}
	for _, s := range plantedSecrets {
		if !found[s] {
			t.Errorf("the snapshot does not hold the secret %q", s)
		}
	}

	mainDir := t.TempDir()
	log := independentLog(t)
	c, _ := loopCommand(t, &Loop{SettingsCmd: adapter, MainLog: filepath.Join(mainDir, "pfblockerng.log")})
	if _, err := runCmd(t, c, Request{Trigger: "manual"}, log); err != nil {
		t.Fatalf("Run = %v, want success", err)
	}
	scanned := 0
	for _, dir := range []string{filepath.Dir(log.Name()), mainDir} {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			scanned++
			for _, s := range append(slices.Clone(plantedSecrets), "TOKENsecret09") {
				if strings.Contains(string(body), s) {
					t.Errorf("%s holds the secret %q", path, s)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{log.Name(), log.Name() + ".request", log.Name() + ".status", log.Name() + ".result"} {
		if _, err := os.Stat(name); err != nil {
			t.Errorf("%s was not scanned: %v", name, err)
		}
	}
	if scanned < 6 { // the transcript, its request, status, result and lock, and the main log
		t.Errorf("scanned %d files, want at least 6", scanned)
	}
}

// WHEN a worker state carries a loop THEN only paths that are absolute, clean and free of control characters are taken,
// an empty list item is refused (empty means none only for a single path), and an unknown field refuses the state.
func TestAWorkerStateWithAHostileLoopIsRefused(t *testing.T) {
	base := workerState{Version: 1, Nonce: strings.Repeat("a", 64), Path: "/bin/true", Request: Request{Trigger: "apply"}, StartedAt: 100}
	encode := func(loop *Loop) string {
		s := base
		s.Loop = loop
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	valid := encode(&Loop{SettingsCmd: "/usr/local/bin/adapter", ResourceDir: "/var/db/store", FeedLocalDirs: []string{"/a", "/b"},
		ScriptDirs: []string{"/s"}, RsyncBin: "/usr/bin/rsync", HookDir: "/h", PythonWrapper: "/p.sh", MainLog: "/var/log/x.log"})
	if _, err := decodeWorkerState(strings.NewReader(valid)); err != nil {
		t.Fatalf("a valid loop is refused: %v", err)
	}
	if _, err := decodeWorkerState(strings.NewReader(encode(&Loop{}))); err != nil {
		t.Fatalf("a loop over the file backend with no other path is refused: %v", err)
	}
	for _, tc := range []struct{ name, body string }{
		{"unknown field in the loop", strings.Replace(valid, `"loop":{`, `"loop":{"stateDir":"/elsewhere",`, 1)},
		{"relative path", encode(&Loop{ResourceDir: "store"})},
		{"path climbing out", encode(&Loop{ResourceDir: "/var/db/../../etc"})},
		{"unclean path", encode(&Loop{HookDir: "/h/"})},
		{"relative folder in a list", encode(&Loop{FeedLocalDirs: []string{"/a", "b"}})},
		{"control character", encode(&Loop{MainLog: "/var/log/x\n.log"})},
		{"relative settings program", encode(&Loop{SettingsCmd: "adapter.sh"})},
		{"empty feed folder", encode(&Loop{FeedLocalDirs: []string{"/a", ""}})},
		{"empty script folder", encode(&Loop{ScriptDirs: []string{""}})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeWorkerState(strings.NewReader(tc.body)); err == nil {
				t.Fatalf("accepted a worker state with %s", tc.name)
			}
		})
	}
}

// WHEN Core is given a loop with a path the worker would refuse THEN nothing is admitted: no receipt is written and
// neither the program nor the adapter runs.
func TestALoopWithABadPathIsRefusedBeforeAnyReceipt(t *testing.T) {
	adapter, adir := settingsAdapter(t, plainReply)
	log := independentLog(t)
	c, pdir := loopCommand(t, &Loop{SettingsCmd: adapter, ResourceDir: "relative/store"})
	if _, err := runCmd(t, c, Request{Trigger: "manual"}, log); err == nil {
		t.Fatal("Run = nil, want the bad loop refused")
	}
	for _, suffix := range []string{".request", ".status"} {
		if _, err := os.Stat(log.Name() + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s exists (%v), want no receipt", suffix, err)
		}
	}
	if _, err := os.Stat(filepath.Join(pdir, "runs")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the program ran (%v)", err)
	}
	if n := adapterRuns(t, adir); n != 0 {
		t.Errorf("the adapter ran %d times, want none", n)
	}
}

// WHEN the Command carries no loop (the switch off) THEN the worker's state has no loop member, as before the loop existed,
// and the program runs.
func TestWithoutALoopTheStateHasNoLoopMemberAndTheProgramRuns(t *testing.T) {
	log := independentLog(t)
	c, pdir := loopCommand(t, nil)
	if _, err := runCmd(t, c, Request{Trigger: "apply"}, log); err != nil {
		t.Fatalf("Run = %v, want success", err)
	}
	for _, suffix := range []string{".request", ".status"} {
		var members map[string]json.RawMessage
		b, err := os.ReadFile(log.Name() + suffix)
		if err != nil || json.Unmarshal(b, &members) != nil {
			t.Fatalf("%s = %q, %v", suffix, b, err)
		}
		if _, ok := members["loop"]; ok {
			t.Errorf("%s = %s, want no loop member", suffix, b)
		}
	}
	if b, err := os.ReadFile(filepath.Join(pdir, "runs")); err != nil || string(b) != "run\n" {
		t.Errorf("program runs = %q, %v; want one", b, err)
	}
}

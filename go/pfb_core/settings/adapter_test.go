package settings

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// slow bounds a call that must come back at once: far below the 30 s of the hung programs, far above a loaded host's jitter.
const slow = 5 * time.Second

// fakeAdapter is a #!/bin/sh program standing in for the adapter: it keeps the last request and one line per call in its
// directory and answers the file "reply", which a test rewrites between calls (or the whole script, to make it misbehave).
type fakeAdapter struct {
	t    *testing.T
	dir  string
	path string
}

func newFakeAdapter(t *testing.T, reply string) *fakeAdapter {
	t.Helper()
	f := &fakeAdapter{t: t, dir: t.TempDir()}
	f.path = filepath.Join(f.dir, "adapter.sh")
	f.script(`cat > "$D/req"; echo run >> "$D/runs"; cat "$D/reply"`)
	f.reply(reply)
	return f
}

// script replaces the program with body; $D is the fake's directory.
func (f *fakeAdapter) script(body string) {
	f.t.Helper()
	text := "#!/bin/sh\nD='" + f.dir + "'\n" + body + "\n"
	if err := os.WriteFile(f.path, []byte(text), 0o755); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeAdapter) reply(s string) { f.t.Helper(); f.replyBytes([]byte(s + "\n")) }

func (f *fakeAdapter) replyBytes(b []byte) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, "reply"), b, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

// request is the last request the program read.
func (f *fakeAdapter) request() string {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, "req"))
	if err != nil {
		f.t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// runs is how many times the program was run.
func (f *fakeAdapter) runs() int {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, "runs"))
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return strings.Count(string(b), "\n")
}

// readReply is the adapter's answer to a read: the production defaults with over laid on them.
func readReply(t *testing.T, revision uint64, over map[string]any) string {
	t.Helper()
	values := defaults(Production().Projections[0])
	maps.Copy(values, over)
	return jsonOf(t, map[string]any{"version": 1, "revision": revision, "settings": map[string]any{"dns": values}})
}

// loadFake loads the production schema from f; timeout 0 keeps the backend's defaults.
func loadFake(t *testing.T, f *fakeAdapter, timeout time.Duration) *Store {
	t.Helper()
	st, err := Load(&AdapterBackend{Path: f.path, ReadTimeout: timeout, WriteTimeout: timeout}, Production())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return st
}

func isBackendError(err error) *BackendError {
	var b *BackendError
	if errors.As(err, &b) {
		return b
	}
	return nil
}

func TestLoadReadsTheAdapterAtStart(t *testing.T) {
	f := newFakeAdapter(t, readReply(t, 7, map[string]any{"control": true, "decisionCacheMax": 500}))
	st := loadFake(t, f, 0)
	snap := get(t, st)
	dns := projection(t, snap, "dns")
	if !snap.Initialized || snap.Revision != 7 || dns.Value["control"] != true || dns.Value["decisionCacheMax"] != int64(500) ||
		dns.Value["replyLogging"] != true {
		t.Errorf("Get = %s, want initialized at revision 7 with control on, cap 500 and the defaults", jsonOf(t, snap))
	}
	if got := f.request(); got != `{"version":1,"op":"read"}` {
		t.Errorf("the adapter was sent %s, want the version 1 read request", got)
	}
	if f.runs() != 1 {
		t.Errorf("the adapter ran %d times for a Load, want 1", f.runs())
	}
}

func TestReloadPicksUpTheAdaptersNewValuesAndRevision(t *testing.T) {
	f := newFakeAdapter(t, readReply(t, 7, nil))
	st := loadFake(t, f, 0)
	f.reply(readReply(t, 8, map[string]any{"idnMode": "on", "control": true}))
	snap, err := st.Reload()
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	dns := projection(t, snap, "dns")
	if snap.Revision != 8 || dns.Value["idnMode"] != "on" || dns.Value["control"] != true {
		t.Errorf("Reload = %s, want revision 8 with idnMode on and control on", jsonOf(t, snap))
	}
	if now := get(t, st); jsonOf(t, now) != jsonOf(t, snap) {
		t.Errorf("Get after Reload = %s, want what Reload answered: %s", jsonOf(t, now), jsonOf(t, snap))
	}
}

// beat starts, in the fake's program, a background loop that touches its heartbeat file until the fake's directory is
// gone; heartbeat is the file's size, which stops growing once the loop is killed.
const beat = `(while [ -d "$D" ]; do echo x >> "$D/beat"; sleep 0.05; done) &`

func (f *fakeAdapter) heartbeat() int64 {
	f.t.Helper()
	info, err := os.Stat(filepath.Join(f.dir, "beat"))
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return info.Size()
}

func TestAHungAdapterFailsTheCallAndItsWholeProcessGroupDies(t *testing.T) {
	f := newFakeAdapter(t, readReply(t, 7, nil))
	st, err := Load(&AdapterBackend{Path: f.path, ReadTimeout: 300 * time.Millisecond}, Production())
	if err != nil {
		t.Fatal(err)
	}
	before := jsonOf(t, get(t, st))
	f.script(beat + "\nsleep 30")
	start := time.Now()
	_, err = st.Reload()
	if elapsed := time.Since(start); elapsed > slow {
		t.Errorf("Reload of a hung adapter took %v, want it cut at the 300ms deadline", elapsed)
	}
	if b := isBackendError(err); b == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("Reload = %v, want a *BackendError saying it timed out", err)
	}
	if after := jsonOf(t, get(t, st)); after != before {
		t.Errorf("a failed Reload changed the values:\n before %s\n after  %s", before, after)
	}
	if f.heartbeat() == 0 {
		t.Fatal("the program's background loop never ran: the process group check below proves nothing")
	}
	time.Sleep(200 * time.Millisecond) // a kill that missed the loop would let it beat again
	size := f.heartbeat()
	time.Sleep(300 * time.Millisecond)
	if f.heartbeat() != size {
		t.Error("the adapter's background child kept running after the deadline: only the adapter itself was killed, not its process group")
	}
}

func TestAGrandchildHoldingStdoutDoesNotHangTheCall(t *testing.T) {
	t.Run("no reply", func(t *testing.T) {
		f := newFakeAdapter(t, readReply(t, 7, nil))
		st, err := Load(&AdapterBackend{Path: f.path, ReadTimeout: 300 * time.Millisecond}, Production())
		if err != nil {
			t.Fatal(err)
		}
		f.script(beat) // exits 0 at once; the background loop keeps the stdout pipe open
		start := time.Now()
		_, err = st.Reload()
		if elapsed := time.Since(start); elapsed > slow {
			t.Errorf("Reload took %v with a grandchild holding stdout, want it back within %v", elapsed, slow)
		}
		if isBackendError(err) == nil {
			t.Errorf("Reload = %v, want a *BackendError: the adapter printed no reply", err)
		}
	})
	t.Run("with a reply", func(t *testing.T) {
		f := newFakeAdapter(t, readReply(t, 7, nil))
		st := loadFake(t, f, 10*time.Second)
		f.script(`cat > "$D/req"; cat "$D/reply"; ` + beat) // the reply is whole; the background child outlives the adapter
		f.reply(readReply(t, 8, map[string]any{"control": true}))
		start := time.Now()
		snap, err := st.Reload()
		if elapsed := time.Since(start); elapsed > slow {
			t.Errorf("Reload took %v with a grandchild holding stdout, want it back within %v", elapsed, slow)
		}
		if err != nil || snap.Revision != 8 {
			t.Errorf("Reload = %s, %v: the adapter exited 0 with a whole reply, want it taken (revision 8)", jsonOf(t, snap), err)
		}
	})
}

func TestAFailingAdapterFailsTheCallAndKeepsTheLastValues(t *testing.T) {
	good := readReply(t, 7, map[string]any{"control": true})
	huge := `{"version":1,"revision":8,"settings":{},"pad":"` + strings.Repeat("x", 2<<20) + `"}`
	cases := []struct {
		name   string
		script string // "": the plain fake, answering reply
		reply  string
		bytes  []byte // non-nil: the reply file's exact content
		want   string // what the error says
	}{
		{name: "exit 1 with stderr", script: `cat > "$D/req"; echo 'boom: config locked' >&2; exit 1`, want: "exit status 1: boom: config locked"},
		{name: "exit 1 after a whole reply", script: `cat > "$D/req"; cat "$D/reply"; exit 1`, reply: good, want: "exit status 1"},
		{name: "empty stdout", bytes: []byte{}, want: "not one JSON object"},
		{name: "not JSON", reply: "Warning: something", want: "not one JSON object"},
		{name: "null", reply: "null", want: "version"},
		{name: "an array", reply: "[]", want: "not one JSON object"},
		{name: "two objects", reply: good + good, want: "not one JSON object"},
		{name: "trailing garbage", reply: good + " junk", want: "not one JSON object"},
		{name: "version as a string", reply: `{"version":"1"}`, want: "version"},
		{name: "version 2", reply: `{"version":2,"revision":8,"settings":{}}`, want: "version"},
		{name: "revision 0", reply: `{"version":1,"revision":0,"settings":{}}`, want: "revision"},
		{name: "revision missing", reply: `{"version":1,"settings":{}}`, want: "revision"},
		{name: "revision a float", reply: `{"version":1,"revision":1.5,"settings":{}}`, want: "revision"},
		{name: "revision negative", reply: `{"version":1,"revision":-3,"settings":{}}`, want: "revision"},
		{name: "revision a string", reply: `{"version":1,"revision":"3","settings":{}}`, want: "revision"},
		{name: "settings missing", reply: `{"version":1,"revision":8}`, want: "settings"},
		{name: "an unknown key", reply: `{"version":1,"revision":8,"settings":{},"extra":1}`, want: "not one JSON object"},
		{name: "an invalid value", reply: `{"version":1,"revision":8,"settings":{"dns":{"decisionCacheMax":-1}}}`, want: "dns.decisionCacheMax"},
		{name: "an unknown projection", reply: `{"version":1,"revision":8,"settings":{"nosuch":{}}}`, want: "nosuch"},
		{name: "an unknown field", reply: `{"version":1,"revision":8,"settings":{"dns":{"nosuch":1}}}`, want: "dns.nosuch"},
		{name: "a projection that is not an object", reply: `{"version":1,"revision":8,"settings":{"dns":[]}}`, want: "not one JSON object"},
		{name: "stdout over 1 MiB", reply: huge, want: "1 MiB"},
		{name: "stdout that never ends", script: `cat > "$D/req"; yes xxxxxxxxxxxxxxxx`, want: "1 MiB"},
		{name: "non-UTF-8 stdout", bytes: []byte{0xff, 0xfe, '{', '}', '\n'}, want: "not one JSON object"},
		{name: "non-UTF-8 inside an enum", bytes: []byte(`{"version":1,"revision":8,"settings":{"dns":{"idnMode":"` + "\xff" + `"}}}`), want: "dns.idnMode"},
		{name: "the adapter is unavailable", reply: `{"version":1,"error":{"code":"unavailable","message":"the config lock stayed taken"}}`,
			want: "the config lock stayed taken"},
		{name: "an error code nobody defined", reply: `{"version":1,"error":{"code":"teapot","message":"short and stout"}}`, want: "short and stout"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeAdapter(t, good)
			st := loadFake(t, f, 10*time.Second)
			before := jsonOf(t, get(t, st))
			if c.script != "" {
				f.script(c.script)
			}
			switch {
			case c.bytes != nil:
				f.replyBytes(c.bytes)
			default:
				f.reply(c.reply)
			}
			start := time.Now()
			_, err := st.Reload()
			if elapsed := time.Since(start); elapsed > slow {
				t.Errorf("Reload took %v, want a failure at once", elapsed)
			}
			if isBackendError(err) == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("Reload = %v, want a *BackendError saying %q", err, c.want)
			}
			if after := jsonOf(t, get(t, st)); after != before {
				t.Errorf("a failed Reload changed the values:\n before %s\n after  %s", before, after)
			}
		})
	}
}

func TestLoadFailsWhenTheAdapterDoes(t *testing.T) {
	f := newFakeAdapter(t, `{"version":1,"revision":8,"settings":{"dns":{"decisionCacheMax":-1}}}`)
	if st, err := Load(&AdapterBackend{Path: f.path}, Production()); err == nil || st != nil ||
		!strings.Contains(err.Error(), "dns.decisionCacheMax") {
		t.Errorf("Load over a reply with an invalid value = %v, %v, want no store and an error naming dns.decisionCacheMax", st, err)
	}
	f.script(`cat > "$D/req"; echo 'config.xml is locked' >&2; exit 1`)
	if st, err := Load(&AdapterBackend{Path: f.path}, Production()); err == nil || st != nil ||
		!strings.Contains(err.Error(), "config.xml is locked") {
		t.Errorf("Load over a failing adapter = %v, %v, want no store and the adapter's stderr in the error", st, err)
	}
	missing := filepath.Join(f.dir, "no-such-adapter")
	if st, err := Load(&AdapterBackend{Path: missing}, Production()); err == nil || st != nil || !strings.Contains(err.Error(), missing) {
		t.Errorf("Load over a program that is not there = %v, %v, want no store and an error naming %s", st, err, missing)
	}
}

const allDnsFields = `{"cnameValidation":false,"control":true,"controlLegacy":false,"decisionCacheMax":10000,"hstsNullBlocking":true,` +
	`"idnBlockMalicious":true,"idnEscalateSuspicious":false,"idnMode":"off","logViaWebserver":false,"metricsClientIp":false,` +
	`"pslAllowPrivate":false,"pslFeedIcannPolicy":"honor","pslFeedPrivatePolicy":"honor","pslIncludePrivate":true,"regexCap":false,` +
	`"replyLogging":true,"tldWildcard":false}`

func TestSaveWritesThroughTheAdapter(t *testing.T) {
	f := newFakeAdapter(t, readReply(t, 7, nil))
	st := loadFake(t, f, 0)
	f.reply(`{"version":1,"revision":9}`)
	res, err := st.Save(7, changes(t, `{"dns": {"control": true}}`))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if want := `{"version":1,"op":"write","expectedRevision":7,"settings":{"dns":` + allDnsFields + `}}`; f.request() != want {
		t.Errorf("the adapter was sent\n %s\n want\n %s", f.request(), want)
	}
	if res.Revision != 9 || len(res.Projections) != 1 || res.Projections[0].Value["control"] != true {
		t.Errorf("Save = %s, want the adapter's revision 9 and settings/dns with control on", jsonOf(t, res))
	}
	if snap := get(t, st); snap.Revision != 9 || projection(t, snap, "dns").Value["control"] != true {
		t.Errorf("Get after Save = %s, want revision 9 with control on", jsonOf(t, snap))
	}
}

func TestAnAdapterThatRefusesAWriteLeavesTheValuesAsTheyWere(t *testing.T) {
	good := readReply(t, 7, nil)
	save := func(st *Store) error {
		_, err := st.Save(7, changes(t, `{"dns": {"control": true}}`))
		return err
	}
	t.Run("a stale expectedRevision never reaches the adapter", func(t *testing.T) {
		f := newFakeAdapter(t, good)
		st := loadFake(t, f, 0)
		before := jsonOf(t, get(t, st))
		_, err := st.Save(3, changes(t, `{"dns": {"control": true}}`))
		var c *ConflictError
		if !errors.As(err, &c) || c.Field != "expectedRevision" {
			t.Errorf("Save at revision 3 over 7 = %v, want a *ConflictError on expectedRevision", err)
		}
		if f.runs() != 1 {
			t.Errorf("the adapter ran %d times, want only the Load's: a stale save is refused by Core", f.runs())
		}
		if jsonOf(t, get(t, st)) != before {
			t.Error("the refused save changed the values")
		}
	})
	cases := []struct {
		name  string
		reply string
		check func(t *testing.T, err error)
	}{
		{"conflict", `{"version":1,"error":{"code":"conflict","message":"config.xml is at revision 8"}}`, func(t *testing.T, err error) {
			var c *ConflictError
			if !errors.As(err, &c) || c.Field != "expectedRevision" || !strings.Contains(c.Message, "revision 8") {
				t.Errorf("err = %v, want a *ConflictError on expectedRevision carrying the adapter's message", err)
			}
		}},
		{"invalid_argument with fieldErrors", `{"version":1,"error":{"code":"invalid_argument","message":"bad",` +
			`"fieldErrors":[{"field":"dns.decisionCacheMax","message":"too big"},{"field":"dns.idnMode","message":"unknown"}]}}`,
			func(t *testing.T, err error) {
				if got := strings.Join(validationFields(err), ","); got != "dns.decisionCacheMax,dns.idnMode" {
					t.Errorf("err = %v, want a *ValidationError keeping the adapter's two fields, got %q", err, got)
				}
			}},
		{"invalid_argument without fieldErrors", `{"version":1,"error":{"code":"invalid_argument","message":"bad request"}}`,
			func(t *testing.T, err error) {
				var v *ValidationError
				if !errors.As(err, &v) || len(v.Fields) == 0 || !strings.Contains(err.Error(), "bad request") {
					t.Errorf("err = %v, want a *ValidationError with a field and the adapter's message (Error() must not panic)", err)
				}
			}},
		{"unavailable", `{"version":1,"error":{"code":"unavailable","message":"write_config refused"}}`, func(t *testing.T, err error) {
			if isBackendError(err) == nil || !strings.Contains(err.Error(), "write_config refused") {
				t.Errorf("err = %v, want a *BackendError naming the adapter's message", err)
			}
		}},
		{"a reply that is not JSON", `config saved`, func(t *testing.T, err error) {
			if isBackendError(err) == nil {
				t.Errorf("err = %v, want a *BackendError", err)
			}
		}},
		{"a write reply without a revision", `{"version":1}`, func(t *testing.T, err error) {
			if isBackendError(err) == nil || !strings.Contains(err.Error(), "revision") {
				t.Errorf("err = %v, want a *BackendError about the missing revision", err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeAdapter(t, good)
			st := loadFake(t, f, 0)
			before := jsonOf(t, get(t, st))
			f.reply(c.reply)
			err := save(st)
			if err == nil {
				t.Fatal("Save took the adapter's refusal")
			}
			c.check(t, err)
			if f.runs() != 2 {
				t.Errorf("the adapter ran %d times, want the Load and the one write", f.runs())
			}
			if after := jsonOf(t, get(t, st)); after != before {
				t.Errorf("a refused write changed the values:\n before %s\n after  %s", before, after)
			}
		})
	}
	t.Run("a write that times out", func(t *testing.T) {
		f := newFakeAdapter(t, good)
		st, err := Load(&AdapterBackend{Path: f.path, WriteTimeout: 300 * time.Millisecond}, Production())
		if err != nil {
			t.Fatal(err)
		}
		before := jsonOf(t, get(t, st))
		f.script(beat + "\nsleep 30")
		start := time.Now()
		err = save(st)
		if elapsed := time.Since(start); elapsed > slow {
			t.Errorf("Save took %v, want it cut at the 300ms write deadline", elapsed)
		}
		if isBackendError(err) == nil || !strings.Contains(err.Error(), "timed out") {
			t.Errorf("Save = %v, want a *BackendError saying it timed out", err)
		}
		if after := jsonOf(t, get(t, st)); after != before {
			t.Errorf("a timed-out write changed the values:\n before %s\n after  %s", before, after)
		}
	})
}

func TestTheAdapterBackendRefusesInitializeAndNeverAsksTheAdapterToWrite(t *testing.T) {
	f := newFakeAdapter(t, readReply(t, 7, nil))
	st := loadFake(t, f, 0)
	_, err := st.Initialize(changes(t, `{"dns": {"control": true}}`))
	if !isConflict(err) {
		t.Errorf("Initialize over an adapter = %v, want a *ConflictError: its settings always exist", err)
	}
	if f.runs() != 1 || strings.Contains(f.request(), `"write"`) {
		t.Errorf("the adapter ran %d times, last asked %s: want only the Load's read", f.runs(), f.request())
	}
}

// A slow adapter call holds the writers' lock only: a read of the settings or a validation answers meanwhile.
func TestASlowAdapterWriteDoesNotBlockReadsOrValidation(t *testing.T) {
	f := newFakeAdapter(t, readReply(t, 7, nil))
	st := loadFake(t, f, 0)
	f.script(`cat > "$D/req"; touch "$D/started"; sleep 2; cat "$D/reply"`)
	f.reply(`{"version":1,"revision":9}`)
	saved := make(chan error, 1)
	go func() {
		_, err := st.Save(7, changes(t, `{"dns": {"control": true}}`))
		saved <- err
	}()
	for deadline := time.Now().Add(slow); ; time.Sleep(5 * time.Millisecond) {
		if _, err := os.Stat(filepath.Join(f.dir, "started")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the slow write never started")
		}
	}
	start := time.Now()
	snap := get(t, st)
	if err := st.Validate(changes(t, `{"dns": {"idnMode": "on"}}`)); err != nil {
		t.Errorf("Validate during a write: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Get and Validate took %v behind a 2s adapter write, want them to answer at once", elapsed)
	}
	if snap.Revision != 7 {
		t.Errorf("Get during the write = revision %d, want the last whole revision 7", snap.Revision)
	}
	if err := <-saved; err != nil {
		t.Errorf("Save: %v", err)
	}
	if got := get(t, st).Revision; got != 9 {
		t.Errorf("revision after the write = %d, want 9", got)
	}
}

// A lone surrogate in an observer report's name survives into the row Python builds, and Python's log writers then cannot
// encode that row as UTF-8: the direct append fails four times and reports it, the pipeline's handler logs the error and
// goes on, and neither writes the row. The counter has counted the block already. The decider carries the surrogate as its
// three-byte WTF-8 encoding and its writers refuse the row the same way.
package decider

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestRowEncodeErrorNamesTheSurrogatesAsPythonsUTF8CodecDoes(t *testing.T) {
	cases := []struct {
		name string
		row  string
		want string // "" is a row the codec encodes
	}{
		{"a plain row", "ok", ""},
		{"a character above the BMP is one character", "\U0001f600é", ""},
		{"one surrogate", "x\xed\xa0\x80y", "'utf-8' codec can't encode character '\\ud800' in position 1: surrogates not allowed"},
		{"a surrogate first", "\xed\xa0\x80", "'utf-8' codec can't encode character '\\ud800' in position 0: surrogates not allowed"},
		{"a low surrogate", "a\xed\xbf\xbfz", "'utf-8' codec can't encode character '\\udfff' in position 1: surrogates not allowed"},
		{"a pair is two unencodable characters in a run", "ab\xed\xa0\x80\xed\xb0\x80cd", "'utf-8' codec can't encode characters in position 2-3: surrogates not allowed"},
		{"a run of three", "\xed\xa0\x80\xed\xa0\x80\xed\xa0\x80", "'utf-8' codec can't encode characters in position 0-2: surrogates not allowed"},
		{"the first run is the one named", "a\xed\xa0\x80b\xed\xb0\x80", "'utf-8' codec can't encode character '\\ud800' in position 1: surrogates not allowed"},
		{"positions count characters, not bytes", "\U0001f600é\xed\xa0\x80", "'utf-8' codec can't encode character '\\ud800' in position 2: surrogates not allowed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := rowEncodeError(tc.row)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("rowEncodeError(%q) = %v, want none", tc.row, err)
			case tc.want != "" && (err == nil || err.Error() != tc.want):
				t.Errorf("rowEncodeError(%q) = %v, want %q", tc.row, err, tc.want)
			}
		})
	}
}

// forwardingModuleWithLogs boots a forwarding module whose logs go to dir, and returns the directory of its stats databases.
func forwardingModuleWithLogs(t *testing.T, dir string) (*pfbUnbound, *Frontend, string) {
	t.Helper()
	withLogDir(t, dir)
	moduleDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(moduleDir, "pfb_unbound.ini"), []byte("[MAIN]\npython_enable = true\nforwarding = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := boot(moduleDir, testLogDir)
	if err != nil {
		t.Fatal(err)
	}
	stopModule(t, m)
	return m, newFrontend(m), moduleDir
}

func upstreamCounter(t *testing.T, m *pfbUnbound, moduleDir string) any {
	t.Helper()
	m.stopDbWorker() // the stop flushes what the worker holds; later counters are written at once
	return sqlValue(t, filepath.Join(moduleDir, "pfb_py_dnsbl.sqlite"), "SELECT counter FROM dnsbl WHERE groupname='Upstream'")
}

func TestPipelineLosesARowWithASurrogateAndKeepsTheRowsAroundIt(t *testing.T) {
	logs := modCaptureLog(t)
	dir := t.TempDir()
	m, f, moduleDir := forwardingModuleWithLogs(t, dir)
	f.relayUpstreamResponse(observerReport(t, map[string]any{"qname": "good1.example.", "flags": 33027, "opts": [][2]any{}}))
	f.relayUpstreamResponse(rawReport(`"192.0.2.7"`, `"bad\ud800row.example."`, "1", "33027", "[]"))
	f.relayUpstreamResponse(observerReport(t, map[string]any{"qname": "good2.example.", "flags": 33027, "opts": [][2]any{}}))
	m.stopLogging() // flushes
	got := readLog(t, filepath.Join(dir, "dnsbl.log"))
	if strings.Count(got, "\n") != 2 || !strings.Contains(got, ",good1.example,") || !strings.Contains(got, ",good2.example,") || strings.Contains(got, "bad") {
		t.Errorf("dnsbl.log = %q, want the two good rows and not the one that cannot be encoded", got)
	}
	want := regexp.MustCompile(`pfb_dns_proxy error: \[pfBlockerNG\]: Failed to write .*dnsbl\.log: 'utf-8' codec can't encode character '\\ud800' in position 36: surrogates not allowed\n`)
	if !want.MatchString(logs.String()) {
		t.Errorf("log = %q, want the write failure named, once", logs.String())
	}
	if got := upstreamCounter(t, m, moduleDir); got != int64(3) {
		t.Errorf("Upstream counter = %v, want 3: the block is counted whether or not its row can be written", got)
	}
}

func TestDirectAppendLosesARowWithASurrogateAfterFourAttempts(t *testing.T) {
	_ = modCaptureLog(t)
	dir := t.TempDir()
	m, f, moduleDir := forwardingModuleWithLogs(t, dir)
	m.stopLogging()
	var slept int
	previous := logRetrySleep
	logRetrySleep = func(time.Duration) { slept++ }
	t.Cleanup(func() { logRetrySleep = previous })
	f.relayUpstreamResponse(rawReport(`"192.0.2.7"`, `"a\ud800b.example."`, "1", "33027", "[]"))
	f.relayUpstreamResponse(observerReport(t, map[string]any{"qname": "good.example.", "flags": 33027, "opts": [][2]any{}}))
	got := readLog(t, filepath.Join(dir, "dnsbl.log"))
	if strings.Count(got, "\n") != 1 || !strings.Contains(got, ",good.example,") {
		t.Errorf("dnsbl.log = %q, want only the good row: the file is opened and the write fails, as Python's open().write() does", got)
	}
	if slept != 4 {
		t.Errorf("slept %d times, want 4: the encoding error is retried like any other", slept)
	}
	want := "[pfBlockerNG]: log_entry: 4: 'utf-8' codec can't encode character '\\ud800' in position 34: surrogates not allowed\n"
	if got := drainPyError(); got != want {
		t.Errorf("py_error.log = %q, want %q", got, want)
	}
	if got := upstreamCounter(t, m, moduleDir); got != int64(2) {
		t.Errorf("Upstream counter = %v, want 2", got)
	}
}

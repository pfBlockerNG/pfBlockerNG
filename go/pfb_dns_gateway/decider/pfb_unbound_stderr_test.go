package decider

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The module's sys.stderr is a logger that appends "<asctime>|ERROR| <message stripped>" rows to py_error.log in the log
// directory, and does not repeat a message equal to the one before it (init_standard, pfb_unbound.py log_stderr). The Log
// Browser reads that file. The shim's log_err, log_warn and log_info are another channel: they print to sys.__stderr__.

// rowTime is the asctime of a row: "YYYY-MM-DD HH:MM:SS,mmm" in local time.
const rowTime = `\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}`

// bootWithLogDir boots a module from an ini that holds ini, its logs in a directory of its own.
func bootWithLogDir(t *testing.T, ini string) (module *pfbUnbound, logDir string) {
	t.Helper()
	logDir = t.TempDir()
	module, err := initStandard(MODULE_ID, modIniDir(t, ini), logDir)
	if err != nil || module == nil {
		t.Fatalf("initStandard = (%v, %v), want a module", module, err)
	}
	stopModule(t, module)
	return module, logDir
}

func readPyError(t *testing.T, logDir string) string {
	t.Helper()
	text, err := os.ReadFile(filepath.Join(logDir, "py_error.log"))
	if err != nil {
		t.Fatalf("py_error.log: %v", err)
	}
	return string(text)
}

// A module error is one py_error.log row of exactly the shape Python writes, and not a line on the process stderr.
func TestAModuleErrorIsOnePyErrorLogRowInPythonsFormat(t *testing.T) {
	out := captureLog(t)
	_, logDir := bootWithLogDir(t, "[MAIN]\npython_enable = true\n[GP_Bypass_List]\nrow1 = not-an-ip\n")

	want := regexp.MustCompile(`^` + rowTime + `\|ERROR\| \[pfBlockerNG\]: Failed to parse: GP_Bypass_List: row:row1 line:not-an-ip\n$`)
	if got := readPyError(t, logDir); !want.MatchString(got) {
		t.Fatalf("py_error.log is %q, want one row matching %s", got, want)
	}
	if strings.Contains(out.String(), "GP_Bypass_List") {
		t.Fatalf("the module error also went to the process stderr: %q (Python's redirect sent it to py_error.log only)", out)
	}
}

// A message equal to the one before it is written once; a different one, then the first again, is written again.
func TestARepeatedModuleErrorIsWrittenOnce(t *testing.T) {
	_ = captureLog(t)
	_, logDir := bootWithLogDir(t, "[MAIN]\npython_enable = true\n")
	for _, path := range []string{"/no/such/dir/one", "/no/such/dir/one", "/no/such/dir/one", "/no/such/dir/two", "/no/such/dir/one"} {
		dnsblEmitCount(path, 1)
	}

	var want bytes.Buffer
	for _, path := range []string{"one", "two", "one"} {
		want.WriteString("ROW Failed to write DNSBL count '/no/such/dir/" + path + "': [Errno 2] No such file or directory: '/no/such/dir/" + path + "'\n")
	}
	got := regexp.MustCompile(`(?m)^`+rowTime+`\|ERROR\| \[pfBlockerNG\]: `).ReplaceAllString(readPyError(t, logDir), "ROW ")
	if got != want.String() {
		t.Fatalf("py_error.log rows:\n%s\nwant:\n%s", got, want.String())
	}
}

// redirected is a module of its own whose sys.stderr is py_error.log in a directory of its own.
func redirected(t *testing.T) (logDir string) {
	t.Helper()
	logDir = t.TempDir()
	m := &pfbUnbound{logDir: logDir}
	m.redirectStderr()
	t.Cleanup(m.restoreStderr)
	return logDir
}

// The writes of testdata/gen_pfb_unbound_stderr_oracle.py leave in py_error.log what the shipped log_stderr left there:
// a repeat is not written, a message that differs only by its newline is, trailing whitespace is stripped, several lines
// stay several lines.
func TestPyErrorLogHoldsWhatTheShippedLoggerWrote(t *testing.T) {
	raw, err := os.ReadFile("testdata/pfb_unbound_stderr_oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Writes []string `json:"writes"`
		File   string   `json:"file"`
	}
	if err := json.Unmarshal(raw, &oracle); err != nil {
		t.Fatal(err)
	}
	logDir := redirected(t)
	for _, msg := range oracle.Writes {
		pyStderr(msg)
	}
	got := regexp.MustCompile(`(?m)^`+rowTime+`\|`).ReplaceAllString(readPyError(t, logDir), "<ASCTIME>|")
	if got != oracle.File {
		t.Fatalf("py_error.log is\n%q\nthe shipped logger wrote\n%q", got, oracle.File)
	}
}

// asctime is "%Y-%m-%d %H:%M:%S,mmm", the milliseconds cut, not rounded.
func TestPyErrorLogRowCarriesPythonsAsctime(t *testing.T) {
	logDir := redirected(t)
	previous := stderrNow
	stderrNow = func() time.Time { return time.Date(2026, 11, 10, 17, 8, 47, 987_999_999, time.Local) }
	t.Cleanup(func() { stderrNow = previous })
	pyStderr("[pfBlockerNG]: x")
	if got, want := readPyError(t, logDir), "2026-11-10 17:08:47,987|ERROR| [pfBlockerNG]: x\n"; got != want {
		t.Fatalf("py_error.log is %q, want %q", got, want)
	}
}

// The shim's log_err, log_warn and log_info are sys.__stderr__ in Python: they stay on the process stderr and never reach
// py_error.log.
func TestShimLogLinesStayOnTheProcessStderr(t *testing.T) {
	out := captureLog(t)
	logDir := redirected(t)
	logErr("shim error")
	logWarn("shim warning")
	logInfo("shim info")
	if got := readPyError(t, logDir); got != "" {
		t.Fatalf("py_error.log holds %q, want nothing: those lines are not sys.stderr", got)
	}
	if want := "pfb_dns_proxy error: shim error\npfb_dns_proxy warning: shim warning\npfb_dns_proxy info: shim info\n"; out.String() != want {
		t.Fatalf("process stderr is %q, want %q", out, want)
	}
}

// A py_error.log that cannot be written does not lose the error: it goes to the process stderr, and the failure is said once.
func TestAnUnwritablePyErrorLogFallsBackToTheProcessStderrWithOneLine(t *testing.T) {
	logDir := redirected(t)
	out := captureLog(t)
	path := filepath.Join(logDir, "py_error.log")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil { // a directory where the file was: opening it for append fails (EISDIR) for every user, root included
		t.Fatal(err)
	}
	pyStderr("[pfBlockerNG]: one")
	pyStderr("[pfBlockerNG]: two")
	text := out.String()
	if n := strings.Count(text, "cannot write"); n != 1 {
		t.Fatalf("the failure was said %d times, want once:\n%s", n, text)
	}
	for _, msg := range []string{"[pfBlockerNG]: one", "[pfBlockerNG]: two"} {
		if !strings.Contains(text, "pfb_dns_proxy error: "+msg+"\n") {
			t.Fatalf("the process stderr lacks %q:\n%s", msg, text)
		}
	}
}

// takePyError is what the modules of these tests (they all log to testLogDir) wrote to py_error.log since the last take,
// each row without its asctime and level. It empties the file and leaves the message before as it is: a module that
// writes the same message again writes no second row, as in Python.
func takePyError() string {
	path := filepath.Join(testLogDir, pyErrorLogName)
	raw, _ := os.ReadFile(path)
	_ = os.Truncate(path, 0)
	return regexp.MustCompile(`(?m)^`+rowTime+`\|ERROR\| `).ReplaceAllString(string(raw), "")
}

// drainPyError is takePyError, and forgets the message before as a freshly booted module has it, so that the same message
// written again is written again.
func drainPyError() string {
	rows := takePyError()
	stderrRedirect.mu.Lock()
	stderrRedirect.last = ""
	stderrRedirect.mu.Unlock()
	return rows
}

package update

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unicode"
)

// WHEN a path is not valid UTF-8 THEN CheckPath refuses it: the request is JSON, which writes each invalid byte as U+FFFD,
// so the worker would be given another path than Core checked.
func TestCheckPathRefusesAPathThatIsNotValidUTF8(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		ok         bool
	}{
		{"plain", "/var/log/pfblockerng.log", true},
		{"multi-byte character", "/var/log/été.log", true},
		{"lone Latin-1 byte", "/var/log/\xe9.log", false},
		{"truncated sequence", "/var/log/\xe2\x82", false},
		{"control character", "/var/log/a\x01.log", false},
		{"relative", "var/log", false},
		{"unclean", "/var/../log", false},
	} {
		if err := CheckPath(tc.path); (err == nil) != tc.ok {
			t.Errorf("%s: CheckPath(%q) = %v, want ok %t", tc.name, tc.path, err, tc.ok)
		}
	}
}

// WHEN the main log cannot be opened and its path is 1,000 bytes THEN the transcript line and the receipt's failure hold
// the reason as one bounded line, as a stage failure does.
func TestAMainLogFailureIsOneBoundedLine(t *testing.T) {
	adapter, _ := settingsAdapter(t, plainReply)
	dir := t.TempDir()
	for len(dir) < 900 {
		dir = filepath.Join(dir, strings.Repeat("d", 100))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	mainLog := filepath.Join(dir, strings.Repeat("m", 1000-len(dir)-1))
	if err := syscall.Mkfifo(mainLog, 0o600); err != nil { // a FIFO without a reader is refused at once
		t.Fatal(err)
	}
	if len(mainLog) != 1000 {
		t.Fatalf("test setup: the main log path is %d bytes, want 1000", len(mainLog))
	}
	log := independentLog(t)
	c, _ := loopCommand(t, &Loop{SettingsCmd: adapter, MainLog: mainLog})
	if _, err := runCmd(t, c, Request{Trigger: "manual"}, log); err == nil {
		t.Fatal("Run = nil, want a failure for a main log that cannot be opened")
	}
	state, err := readWorkerState(log.Name() + ".status")
	if err != nil {
		t.Fatal(err)
	}
	const bound = 512
	transcript := strings.TrimSuffix(logText(t, log), "\n")
	if !strings.Contains(transcript, "the main log cannot be used") {
		t.Errorf("transcript = %.200q, want the main log's refusal", transcript)
	}
	for name, line := range map[string]string{"transcript": transcript, "failure": state.Failure} {
		if line == "" || len(line) > bound || strings.IndexFunc(line, unicode.IsControl) >= 0 {
			t.Errorf("%s = %.600q (%d bytes), want one line of at most %d bytes", name, line, len(line), bound)
		}
	}
}

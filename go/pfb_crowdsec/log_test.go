package main

import (
	"bytes"
	"log/syslog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Each configured level lets through its own level and the ones above it, and nothing below.
func TestLogLevelFiltersLowerLevels(t *testing.T) {
	cases := map[logLevel][]string{
		levelDebug:   {"level=debug msg=d", "level=info msg=i", "level=warning msg=w", "level=error msg=e"},
		levelInfo:    {"level=info msg=i", "level=warning msg=w", "level=error msg=e"},
		levelWarning: {"level=warning msg=w", "level=error msg=e"},
		levelError:   {"level=error msg=e"},
	}
	for min, want := range cases {
		var buf bytes.Buffer
		l := newLogger(&buf, min)
		l.debugf("d")
		l.infof("i")
		l.warnf("w")
		l.errorf("e")
		got := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("level %d: lines = %q; want %q", min, got, want)
		}
	}
}

func TestParseLogLevelAcceptsOnlyTheSettingsValues(t *testing.T) {
	want := map[string]logLevel{"debug": levelDebug, "info": levelInfo, "warning": levelWarning, "error": levelError}
	for text, lvl := range want {
		got, err := parseLogLevel(text)
		if err != nil || got != lvl {
			t.Errorf("parseLogLevel(%q) = %d, %v; want %d, nil", text, got, err, lvl)
		}
	}
	for _, text := range []string{"", "warn", "INFO", "trace", "fatal", " info"} {
		if _, err := parseLogLevel(text); err == nil {
			t.Errorf("parseLogLevel(%q) accepted a value the settings never write", text)
		}
	}
}

// A message carrying LAPI-supplied text cannot forge a second log line or hide control bytes.
func TestLogMessageStaysOnOneLine(t *testing.T) {
	var buf bytes.Buffer
	l := newLogger(&buf, levelDebug)
	l.warnf("invalid value %s", "1.2.3.4\nlevel=error msg=forged\x1b[2J")
	got := buf.String()
	if strings.Count(got, "\n") != 1 || !strings.HasSuffix(got, "\n") {
		t.Fatalf("output = %q; want exactly one line", got)
	}
	if strings.ContainsAny(strings.TrimSuffix(got, "\n"), "\n\r\x1b") {
		t.Fatalf("output = %q; control characters reached the log", got)
	}
	if !strings.HasPrefix(got, "level=warning msg=invalid value 1.2.3.4") {
		t.Fatalf("output = %q; want the message text kept", got)
	}
}

func TestLoggerRedactsTheSecret(t *testing.T) {
	var buf bytes.Buffer
	l := newLogger(&buf, levelDebug)
	l.setSecret(testKey)
	l.errorf("LAPI said: bad key %s (%s)", testKey, "x")
	if strings.Contains(buf.String(), testKey) {
		t.Fatalf("output = %q; the key reached the log", buf.String())
	}
	if !strings.Contains(buf.String(), "LAPI said: bad key") {
		t.Fatalf("output = %q; want the rest of the message kept", buf.String())
	}
}

// fakeSyslogd stands in for syslogd's /var/run/log: a datagram socket in a temporary directory. It returns the socket's
// path and the listener; the logger reaches it through dialSyslogAt(path).
func fakeSyslogd(t *testing.T) (string, *net.UnixConn) {
	t.Helper()
	dir, err := os.MkdirTemp("", "pfbcs") // short: a socket path has a length limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "log")
	return path, listenSyslog(t, path)
}

func listenSyslog(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func dialSyslogAt(path string) func() (*syslog.Writer, error) {
	return func() (*syslog.Writer, error) {
		return syslog.Dial("unixgram", path, syslog.LOG_DAEMON, "pfb_crowdsec")
	}
}

// readSyslog returns the next datagram, or "" when none comes within a second.
func readSyslog(t *testing.T, conn *net.UnixConn) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}
	return string(buf[:n])
}

// Each level reaches syslog at its own severity, facility daemon, tag pfb_crowdsec, with the line's text unchanged
// (#4158): debug 7, info 6, warning 4, error 3, so <24+severity>.
func TestSyslogLineCarriesItsLevelsSeverity(t *testing.T) {
	path, conn := fakeSyslogd(t)
	var out bytes.Buffer
	l := newLogger(&out, levelDebug)
	l.toSyslog(dialSyslogAt(path))
	l.debugf("d")
	l.infof("i")
	l.warnf("w")
	l.errorf("e")
	for _, want := range []struct{ pri, body string }{
		{"<31>", "level=debug msg=d"}, {"<30>", "level=info msg=i"}, {"<28>", "level=warning msg=w"}, {"<27>", "level=error msg=e"},
	} {
		got := readSyslog(t, conn)
		if !strings.HasPrefix(got, want.pri) || !strings.Contains(got, " pfb_crowdsec[") ||
			!strings.HasSuffix(strings.TrimSuffix(got, "\n"), ": "+want.body) {
			t.Errorf("datagram = %q; want priority %s, tag pfb_crowdsec and text %q", got, want.pri, want.body)
		}
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q; want nothing while syslog takes the lines", out.String())
	}
}

// The level filter still applies before syslog.
func TestSyslogGetsNothingBelowTheConfiguredLevel(t *testing.T) {
	path, conn := fakeSyslogd(t)
	l := newLogger(&bytes.Buffer{}, levelWarning)
	l.toSyslog(dialSyslogAt(path))
	l.infof("i")
	l.warnf("w")
	if got := readSyslog(t, conn); !strings.HasPrefix(got, "<28>") {
		t.Fatalf("first datagram = %q; want the warning, not the info line", got)
	}
}

// Syslog not up yet (pfSense's boot order) or gone (syslogd restarting): the line goes to stdout as before, and the
// logger dials again on the next line, so syslog takes the lines once it is back.
func TestSyslogUnavailableFallsBackToStdoutUntilItIsBack(t *testing.T) {
	dir, err := os.MkdirTemp("", "pfbcs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "log")
	var out bytes.Buffer
	l := newLogger(&out, levelDebug)
	l.toSyslog(dialSyslogAt(path))

	l.errorf("before")
	if out.String() != "level=error msg=before\n" {
		t.Fatalf("stdout = %q; want the line there while syslog is down", out.String())
	}

	conn := listenSyslog(t, path)
	out.Reset()
	l.infof("after")
	if got := readSyslog(t, conn); !strings.HasPrefix(got, "<30>") || !strings.Contains(got, "level=info msg=after") {
		t.Fatalf("datagram = %q; want the line in syslog once it is up", got)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q; want nothing once syslog is up", out.String())
	}

	_ = conn.Close()
	_ = os.Remove(path)
	l.warnf("gone")
	if out.String() != "level=warning msg=gone\n" {
		t.Fatalf("stdout = %q; want the line there once syslog went away", out.String())
	}
}

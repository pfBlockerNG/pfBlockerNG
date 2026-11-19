package main

import (
	"bytes"
	"strings"
	"testing"
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

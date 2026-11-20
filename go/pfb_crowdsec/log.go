package main

import (
	"fmt"
	"io"
	"log/syslog"
	"strings"
	"sync"
)

type logLevel int

const (
	levelDebug logLevel = iota
	levelInfo
	levelWarning
	levelError
)

const minRedacted = 8

var levelNames = [...]string{"debug", "info", "warning", "error"}

// toSeverity sends a line at each level's syslog severity: debug, info, warning, err.
var toSeverity = [...]func(*syslog.Writer, string) error{
	(*syslog.Writer).Debug, (*syslog.Writer).Info, (*syslog.Writer).Warning, (*syslog.Writer).Err,
}

// parseLogLevel accepts exactly the values the settings page writes.
func parseLogLevel(s string) (logLevel, error) {
	for i, name := range levelNames {
		if s == name {
			return logLevel(i), nil
		}
	}
	return levelInfo, fmt.Errorf("log_level %q is not one of debug, info, warning, error", s)
}

// logger writes `level=<lvl> msg=<text>` lines. Control characters in the text are escaped so that values from the
// LAPI cannot start a second line, and the API key, once set, is replaced wherever it appears.
//
// With toSyslog, each line goes to syslog at its level's severity instead; a line syslog does not take (not up yet at
// boot, or restarting) goes to out, and the next line dials again.
type logger struct {
	mu     sync.Mutex
	out    io.Writer
	min    logLevel
	secret string
	dial   func() (*syslog.Writer, error)
	sys    *syslog.Writer
}

func newLogger(out io.Writer, min logLevel) *logger { return &logger{out: out, min: min} }

func (l *logger) toSyslog(dial func() (*syslog.Writer, error)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.dial = dial
}

func (l *logger) setSecret(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.secret = s
}

func (l *logger) logf(lvl logLevel, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if lvl < l.min {
		return
	}
	line := "level=" + levelNames[lvl] + " msg=" + escapeControls(redact(fmt.Sprintf(format, args...), l.secret))
	if l.dial != nil && l.sys == nil {
		l.sys, _ = l.dial()
	}
	// The writer redials by itself after a failed write; an error means this line did not reach syslog
	if l.sys != nil && toSeverity[lvl](l.sys, line) == nil {
		return
	}
	_, _ = fmt.Fprintln(l.out, line)
}

func (l *logger) debugf(format string, args ...any) { l.logf(levelDebug, format, args...) }
func (l *logger) infof(format string, args ...any)  { l.logf(levelInfo, format, args...) }
func (l *logger) warnf(format string, args ...any)  { l.logf(levelWarning, format, args...) }
func (l *logger) errorf(format string, args ...any) { l.logf(levelError, format, args...) }

// redact hides secret in text. A key shorter than minRedacted is left alone: replacing every occurrence of a one- or
// two-letter key would garble the log and spell the key out; the LAPI client drops any reply that echoes the key.
func redact(text, secret string) string {
	if len(secret) < minRedacted {
		return text
	}
	return strings.ReplaceAll(text, secret, "[redacted]")
}

func escapeControls(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			fmt.Fprintf(&b, `\x%02x`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

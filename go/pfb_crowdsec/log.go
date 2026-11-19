package main

import (
	"fmt"
	"io"
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

var levelNames = [...]string{"debug", "info", "warning", "error"}

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
type logger struct {
	mu     sync.Mutex
	out    io.Writer
	min    logLevel
	secret string
}

func newLogger(out io.Writer, min logLevel) *logger { return &logger{out: out, min: min} }

func (l *logger) setLevel(min logLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.min = min
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
	msg := redact(fmt.Sprintf(format, args...), l.secret)
	_, _ = fmt.Fprintf(l.out, "level=%s msg=%s\n", levelNames[lvl], escapeControls(msg))
}

func (l *logger) debugf(format string, args ...any) { l.logf(levelDebug, format, args...) }
func (l *logger) infof(format string, args ...any)  { l.logf(levelInfo, format, args...) }
func (l *logger) warnf(format string, args ...any)  { l.logf(levelWarning, format, args...) }
func (l *logger) errorf(format string, args ...any) { l.logf(levelError, format, args...) }

func redact(text, secret string) string {
	if secret == "" {
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

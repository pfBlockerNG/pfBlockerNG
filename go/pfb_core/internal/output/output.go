// Package output captures the output of a hook or a list script as pfb_script_output_exec() does: the program writes to a
// fresh regular file, never a pipe a daemon could hold open, which is sanitized into the logs on a 200 ms tick while it
// runs. All of it reaches the main log; the first 1,048,576 bytes reach the transcript, then one notice
// (core-api-protocol.md "Update command").
package output

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	allowance = 1 << 20 // core-api-protocol.md "Update command"
	drainTick = 200 * time.Millisecond
	notice    = "\n[ pfBlockerNG ] Script output limit (1,048,576 bytes) reached; remaining output is in the main log.\n"
)

// BeforeTickSize runs once a drain tick is taken, before the size it reads up to is decided: a test seam that widens that
// gap.
var BeforeTickSize = func() {}

// Sinks are where the output goes; a nil writer discards.
type Sinks struct {
	Log        io.Writer // all of it
	Transcript io.Writer // the first 1,048,576 bytes, then one notice
	Errors     io.Writer // one line for each of the two that fails a write
}

// Line writes one runner line to Log and Transcript, and a failure's to Errors too.
func (s Sinks) Line(failure bool, format string, args ...any) {
	text := fmt.Sprintf(format, args...)
	io.WriteString(orDiscard(s.Log), text)
	io.WriteString(orDiscard(s.Transcript), text)
	if failure {
		io.WriteString(orDiscard(s.Errors), text)
	}
}

// Capture makes a fresh file in the temporary folder, its name starting with prefix, and calls run with a descriptor of
// it opened write-only in append mode, as PHP's 'a', for the program's stdout and stderr. run starts the program and
// returns when its caller's lifetime policy says it has exited. While run runs, Capture sanitizes the file into s, and
// then the rest of it up to its size sampled after run returned, not at the instant the program exited: what a process
// the program left running writes in between is included, and what it writes later is not waited for. The file's name
// is removed once that size is fixed. Capture returns false, and does not call run, when no file can be made.
func Capture(prefix string, s Sinks, run func(out *os.File)) bool {
	capture, err := os.CreateTemp("", prefix)
	if err != nil {
		return false
	}
	defer capture.Close()
	name := capture.Name()
	// as PHP's 'a': a seek by the program leaves no hole; O_NOFOLLOW refuses a link planted at that name
	out, err := os.OpenFile(name, os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0)
	if err != nil {
		os.Remove(name)
		return false
	}
	defer out.Close()
	var (
		mu     sync.Mutex // a tick checks the exit and takes its size, or the exit fixes the cutoff: never interleaved
		done   bool
		cutoff int64 // the output's size, sampled after run returned
	)
	exited := make(chan struct{})
	go func() {
		run(out)
		mu.Lock()
		if info, err := capture.Stat(); err == nil {
			cutoff = info.Size()
		}
		done = true
		mu.Unlock()
		os.Remove(name) // both descriptors are open; tests take the name's absence as the sign that the cutoff is fixed
		close(exited)
	}()
	d := newDrain(capture, s)
	tick := time.NewTicker(drainTick)
	defer tick.Stop()
	for {
		select {
		case <-exited:
			d.feed(cutoff, true)
			return true
		case <-tick.C:
			BeforeTickSize()
			mu.Lock()
			info, err := capture.Stat()
			read := !done && err == nil // the file only grows: a size taken before the exit is within the cutoff
			mu.Unlock()
			if read {
				d.feed(info.Size(), false)
			}
		}
	}
}

// drain sanitizes an output file into the main log, all of it, and into the transcript up to the allowance, then one
// notice.
type drain struct {
	limit                       *io.LimitedReader
	size                        int64 // the most of the file it may read
	in                          *bufio.Reader
	log, transcript             *bufio.Writer
	errs                        io.Writer
	left                        int
	noticed                     bool
	logFailed, transcriptFailed bool
}

func newDrain(f *os.File, s Sinks) *drain {
	limit := &io.LimitedReader{R: f}
	return &drain{limit: limit, in: bufio.NewReaderSize(limit, 64<<10), log: bufio.NewWriter(orDiscard(s.Log)),
		transcript: bufio.NewWriter(orDiscard(s.Transcript)), errs: orDiscard(s.Errors), left: allowance}
}

// feed sanitizes the file up to size, a size it had, and flushes both logs: a failed log does not stop the other.
func (d *drain) feed(size int64, final bool) {
	if size > d.size {
		d.limit.N += size - d.size
		d.size = size
	}
	sanitize(d.in, final, func(text string, atomic bool) {
		d.log.WriteString(text)
		switch {
		case d.noticed:
		case len(text) <= d.left:
			d.transcript.WriteString(text)
			d.left -= len(text)
		default:
			if !atomic { // a run of printable ASCII: cut at the allowance
				d.transcript.WriteString(text[:d.left])
			}
			d.transcript.WriteString(notice)
			d.noticed = true
		}
	})
	d.flush(d.log, &d.logFailed, "main log")
	d.flush(d.transcript, &d.transcriptFailed, "transcript")
}

// flush flushes one log; its first failure is one line in the error log. A bufio.Writer keeps its error, so a failed
// log takes no more.
func (d *drain) flush(w *bufio.Writer, failed *bool, name string) {
	if err := w.Flush(); err != nil && !*failed {
		*failed = true
		fmt.Fprintf(d.errs, "[ pfB Script Output ] Failed to write script output to %s; child status is preserved\n", name)
	}
}

// sanitize is pfb_script_output_sanitize_chunk() over what in holds: printable ASCII, TAB and LF stay; other ASCII
// controls, DEL and each byte of malformed UTF-8 become \xNN; Unicode Cc and Cf become \u{HEX}; other characters stay.
// emit gets runs of printable ASCII (atomic false) and single units that must not be cut (atomic true). Unless final, a
// character whose bytes in has not all read yet stays there for the next call.
func sanitize(in *bufio.Reader, final bool, emit func(text string, atomic bool)) {
	for {
		b, err := in.Peek(utf8.UTFMax)
		switch {
		case len(b) == 0:
			return
		case printable(b[0]):
			b, _ = in.Peek(in.Buffered())
			n := 1
			for n < len(b) && printable(b[n]) {
				n++
			}
			emit(string(b[:n]), false)
			in.Discard(n)
			continue
		case b[0] < utf8.RuneSelf:
			emit(fmt.Sprintf(`\x%02X`, b[0]), true)
			in.Discard(1)
			continue
		case err != nil && !final && !utf8.FullRune(b):
			return
		}
		ch, size := utf8.DecodeRune(b)
		switch {
		case ch == utf8.RuneError && size == 1:
			emit(fmt.Sprintf(`\x%02X`, b[0]), true)
		case unicode.In(ch, unicode.Cc, unicode.Cf):
			emit(fmt.Sprintf(`\u{%X}`, ch), true)
		default:
			emit(string(b[:size]), true)
		}
		in.Discard(size)
	}
}

// OneLine is text sanitized as program output is, with TAB and LF escaped as well, cut to at most max bytes without
// splitting an escape or a character: one line for a log or a receipt.
func OneLine(text string, max int) string {
	var b strings.Builder
	full := false
	add := func(s string, atomic bool) bool { // false once the line is full
		if b.Len()+len(s) <= max {
			b.WriteString(s)
			return true
		}
		if !atomic {
			b.WriteString(s[:max-b.Len()])
		}
		return false
	}
	sanitize(bufio.NewReader(strings.NewReader(text)), true, func(s string, atomic bool) {
		for !full && s != "" {
			i := strings.IndexAny(s, "\t\n")
			if atomic || i < 0 {
				full = !add(s, atomic)
				return
			}
			full = !add(s[:i], false) || !add(fmt.Sprintf(`\x%02X`, s[i]), true)
			s = s[i+1:]
		}
	})
	return b.String()
}

func printable(b byte) bool { return b >= 0x20 && b <= 0x7e || b == '\t' || b == '\n' }

func orDiscard(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}

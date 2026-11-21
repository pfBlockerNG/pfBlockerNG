// Package hooks runs the ADR-12 update hooks (pfb_run_hooks(), docs/specs/go-updater-pipeline.md §5): the vetted
// hook_<when>_*.sh and .py files of the hook directory that the settings/hooks rows name, one after another, under the
// survivor policy. tests/hooks/fixtures/runner is the parity corpus.
package hooks

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/process"
)

const (
	defaultTimeout = 60 // seconds
	defaultGrace   = 5 * time.Second
	allowance      = 1 << 20 // core-api-protocol.md "Update command"
	drainTick      = 200 * time.Millisecond
	bourneShell    = "/bin/sh"
	notice         = "\n[ pfBlockerNG ] Script output limit (1,048,576 bytes) reached; remaining output is in the main log.\n"
)

var errTimedOut = errors.New("hook timed out")

// beforeTickSize runs once a drain tick is taken, before the size it reads up to is decided; tests widen that gap.
var beforeTickSize = func() {}

// end is how a hook ended as far as the run goes on.
type end int

const (
	ran         end = iota // it exited or was skipped: the next hook runs
	timedOut               // its own timeout ended it: the next hook runs
	cancelled              // the run's context ended before it started
	interrupted            // the run's context ended while it ran
)

// Hook is one stored hook row.
type Hook struct {
	When        string // pre or post
	Script      string // a file name of the hook directory; vetted when the hook runs
	Description string
	Timeout     int64 // seconds; below 1 is the default 60
	Enabled     bool
}

// Rows are the hook rows of the settings/hooks projection's value (Store.GetClear("hooks")), in list order.
func Rows(value map[string]any) []Hook {
	list, _ := value["rows"].([]any)
	rows := make([]Hook, 0, len(list))
	for _, item := range list {
		row, _ := item.(map[string]any)
		str := func(key string) string { s, _ := row[key].(string); return s }
		timeout, _ := row["timeout"].(int64)
		enabled, _ := row["enabled"].(bool)
		rows = append(rows, Hook{When: str("when"), Script: str("script"), Description: str("description"), Timeout: timeout,
			Enabled: enabled})
	}
	return rows
}

// Context is what a fire point tells its hooks, each set on the child only as a PFB_* environment entry.
type Context struct {
	Lifecycle string            // install: PFB_POST_INSTALL=1; uninstall: PFB_PRE_UNINSTALL=1; otherwise both 0
	PkgOp     string            // PFB_PKG_OP: install, upgrade, reinstall, delete or ""
	Vars      map[string]string // the rest (TRIGGER, IP_CHANGED, ...): a name is upper-cased and exported as PFB_<NAME>
}

// Runner runs the hooks of one fire point.
type Runner struct {
	Dir        string        // the hook directory
	Python     string        // the Python wrapper (pfb_python.sh): a .py hook runs only through it
	Log        io.Writer     // the main log: every line and all of each hook's output (nil: none)
	Errors     io.Writer     // the error log: the lines of a hook that was skipped or failed (nil: none)
	Transcript io.Writer     // the Update transcript: every line and the first 1,048,576 bytes of each hook's output (nil: none)
	Grace      time.Duration // between TERM and KILL; 0 is 5 s
}

// Run runs the enabled hooks of when (pre or post) among rows, one after another in list order, and returns when the
// last has exited. A hook's script is vetted on every run: a bare hook_<when>_*.sh or .py file name of a regular file
// in the hook directory, else it is logged and never run. Each hook's own process gets TERM at its timeout and KILL
// after the grace; what it started is left alone. A hook that is skipped, times out or exits non-zero is logged and the
// next one runs: the caller never fails because of a hook. When ctx ends, a running hook gets TERM and KILL the same
// way, no further hook starts, and one line says the run was cancelled and how many enabled hooks did not run. Output
// goes to a fresh regular file, sanitized into the logs while the hook runs, and read up to its size when the hook
// exited.
func (r Runner) Run(ctx context.Context, when string, rows []Hook, c Context) {
	if when != "pre" && when != "post" {
		return
	}
	var selected []Hook
	for _, h := range rows {
		if h.Enabled && h.When == when && !blank(h.Script) {
			selected = append(selected, h)
		}
	}
	if len(selected) == 0 {
		return
	}
	env := environ(when, c)
	python := sync.OnceValue(func() bool { return r.interpreter(ctx) })
	for i, h := range selected {
		e := r.run(ctx, when, i, h, env, python)
		if e != cancelled && e != interrupted {
			continue
		}
		left, plural := len(selected)-i, "s"
		if e == interrupted {
			left--
		}
		if left == 1 {
			plural = ""
		}
		r.line(true, "[ pfB Hook ] %s run cancelled; %d enabled hook%s did not run\n", when, left, plural)
		return
	}
}

func (r Runner) run(ctx context.Context, when string, index int, h Hook, env []string, python func() bool) end {
	if ctx.Err() != nil {
		return cancelled
	}
	label := strings.Trim(h.Description, " \t\n\r\x00\x0B")
	if label == "" {
		label = fmt.Sprintf("#%d", index)
	}
	path := r.vetted(h.Script, when)
	if path == "" {
		missing := ""
		if h.Script != "" {
			missing = "'" + h.Script + "' "
		}
		r.line(true, "[ pfB Hook ] %s %s script %snot a valid file in %s; skipping\n", when, label, missing, r.Dir)
		return ran
	}
	argv := []string{path}
	if strings.HasSuffix(h.Script, ".py") {
		ok := python()
		if ctx.Err() != nil {
			return cancelled
		}
		if !ok {
			r.line(true, "[ pfB Hook ] %s %s script '%s' has no usable launcher; skipping\n", when, label, h.Script)
			return ran
		}
		argv = []string{r.Python, path}
	}
	timeout := h.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	r.line(false, "\n[ pfB Hook ] %s %s (%s, timeout %ds)\n", when, label, h.Script, timeout)
	status, e := r.exec(ctx, argv, env, time.Duration(min(timeout, math.MaxInt64/int64(time.Second)))*time.Second)
	switch {
	case e == timedOut:
		r.line(true, "[ pfB Hook ] %s %s TIMED OUT after %ds (killed); continuing\n", when, label, timeout)
	case e != ran:
		return e
	case status != 0:
		r.line(true, "[ pfB Hook ] %s %s exited non-zero [ %d ]; continuing\n", when, label, status)
	default:
		r.line(false, "[ pfB Hook ] %s %s completed\n", when, label)
	}
	return ran
}

// vetted is pfb_hook_script_valid(): the absolute path of script when it is a bare hook_<when>_*.sh or .py name and the
// file it names resolves to a regular file directly in the hook directory (a symlink to a file there counts; one
// leading out does not), else "". The runner executes that path: a name without a slash would be looked up in PATH.
func (r Runner) vetted(script, when string) string {
	if strings.Contains(script, "/") || !strings.HasPrefix(script, "hook_"+when+"_") ||
		!strings.HasSuffix(script, ".sh") && !strings.HasSuffix(script, ".py") {
		return ""
	}
	base, err := filepath.Abs(r.Dir)
	if err != nil {
		return ""
	}
	dir, err := filepath.EvalSymlinks(base)
	if err != nil {
		return ""
	}
	path := filepath.Join(base, script)
	real, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Dir(real) != dir {
		return ""
	}
	if info, err := os.Stat(real); err != nil || !info.Mode().IsRegular() {
		return ""
	}
	return path
}

func (r Runner) interpreter(ctx context.Context) bool {
	if !filepath.IsAbs(r.Python) { // a relative wrapper would be looked up in PATH
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.Python, "--print-interpreter")
	cmd.WaitDelay = r.grace()
	out, err := cmd.Output()
	first, _, _ := strings.Cut(string(out), "\n")
	return err == nil && strings.TrimSpace(first) != ""
}

func (r Runner) grace() time.Duration {
	if r.Grace > 0 {
		return r.Grace
	}
	return defaultGrace
}

// exec runs argv under the survivor policy with its output in a fresh regular file, which it sanitizes into the logs
// while the hook runs and up to the size the file had when the hook's own process exited: a descendant may keep writing
// to it, and is not waited for. status is the exit status: 128+n for signal n, 126 when the file cannot be run, 127
// when it cannot be started at all, as timeout(1) reports them, and -1 when no output file can be made.
func (r Runner) exec(ctx context.Context, argv, env []string, timeout time.Duration) (status int, e end) {
	capture, err := os.CreateTemp("", "pfb-hook-output-")
	if err != nil {
		return -1, ran
	}
	defer capture.Close()
	name := capture.Name()
	output, err := os.Open(name)
	if err != nil {
		os.Remove(name)
		return -1, ran
	}
	defer output.Close()
	ctx, cancel := context.WithTimeoutCause(ctx, timeout, errTimedOut)
	defer cancel()
	type result struct {
		process.Outcome
		size int64 // of the output when the hook's own process exited
	}
	exited := make(chan result, 1)
	go func() {
		start := func(argv []string) process.Outcome {
			cmd := exec.Command(argv[0], argv[1:]...)
			cmd.Env, cmd.Stdout, cmd.Stderr = env, capture, capture
			return process.RunSurvivor(ctx, cmd, r.grace())
		}
		out := start(argv)
		if len(argv) == 1 && errors.Is(out.CommandErr, syscall.ENOEXEC) { // no #! line: sh runs it, as execvp() does
			out = start([]string{bourneShell, argv[0]})
		}
		var size int64
		if info, err := capture.Stat(); err == nil {
			size = info.Size()
		}
		exited <- result{out, size}
		os.Remove(name) // only once the size is posted: the name's absence tells that the cutoff is fixed
	}()
	d := r.newDrain(output)
	tick := time.NewTicker(drainTick)
	defer tick.Stop()
	var res result
	for waiting := true; waiting; {
		select {
		case res = <-exited:
			waiting = false
		case <-tick.C:
			select {
			case res = <-exited: // an exit posted during the last read wins over the tick: never read past the cutoff
				waiting = false
			default:
				beforeTickSize()
				if info, err := output.Stat(); err == nil {
					d.feed(info.Size(), false)
				}
			}
		}
	}
	d.feed(res.size, true)
	out := res.Outcome
	notStarted := ctx.Err() != nil && errors.Is(out.CommandErr, context.Cause(ctx))
	var exit *exec.ExitError
	switch {
	case (out.Interrupted != nil || notStarted) && errors.Is(context.Cause(ctx), errTimedOut):
		return 0, timedOut
	case out.Interrupted != nil:
		return 0, interrupted
	case notStarted:
		return 0, cancelled
	case out.CommandErr == nil:
		return 0, ran
	case errors.As(out.CommandErr, &exit):
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), ran
		}
		return exit.ExitCode(), ran
	case errors.Is(out.CommandErr, fs.ErrPermission) || errors.Is(out.CommandErr, syscall.ENOEXEC):
		return 126, ran
	}
	return 127, ran
}

// drain sanitizes a hook's output file into the main log, all of it, and into the transcript up to the allowance, then
// one notice.
type drain struct {
	limit           *io.LimitedReader
	size            int64 // the most of the file it may read
	in              *bufio.Reader
	log, transcript *bufio.Writer
	left            int
	noticed         bool
}

func (r Runner) newDrain(f *os.File) *drain {
	limit := &io.LimitedReader{R: f}
	return &drain{limit: limit, in: bufio.NewReaderSize(limit, 64<<10), log: bufio.NewWriter(orDiscard(r.Log)),
		transcript: bufio.NewWriter(orDiscard(r.Transcript)), left: allowance}
}

// feed sanitizes the file up to size, a size it had, and flushes both logs.
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
	d.log.Flush()
	d.transcript.Flush()
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

func printable(b byte) bool { return b >= 0x20 && b <= 0x7e || b == '\t' || b == '\n' }

// line writes one runner line to the main log and the transcript, and a failure's to the error log too.
func (r Runner) line(failure bool, format string, args ...any) {
	text := fmt.Sprintf(format, args...)
	for _, w := range []io.Writer{r.Log, r.Transcript} {
		if w != nil {
			io.WriteString(w, text)
		}
	}
	if failure && r.Errors != nil {
		io.WriteString(r.Errors, text)
	}
}

// environ is the hooks' environment: the runner's own, then PFB_<NAME> for each context value whose upper-cased name is
// [A-Z0-9_]+ and that holds no NUL, then PFB_WHEN and the lifecycle entries, which no context name replaces. A PkgOp
// holding a NUL is no operation: PFB_PKG_OP is set empty, as hooks expect it always set.
func environ(when string, c Context) []string {
	vars := map[string]string{}
	for _, name := range slices.Sorted(maps.Keys(c.Vars)) {
		upper := strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' {
				return r - 'a' + 'A'
			}
			return r
		}, name)
		value := c.Vars[name]
		if upper != "" && strings.Trim(upper, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") == "" && !strings.Contains(value, "\x00") {
			vars[upper] = value
		}
	}
	flag := func(on bool) string {
		if on {
			return "1"
		}
		return "0"
	}
	pkgOp := c.PkgOp
	if strings.Contains(pkgOp, "\x00") {
		pkgOp = ""
	}
	vars["WHEN"], vars["PKG_OP"] = when, pkgOp
	vars["POST_INSTALL"], vars["PRE_UNINSTALL"] = flag(c.Lifecycle == "install"), flag(c.Lifecycle == "uninstall")
	env := os.Environ()
	for _, name := range slices.Sorted(maps.Keys(vars)) {
		env = append(env, "PFB_"+name+"="+vars[name])
	}
	return env
}

// blank is pfb_is_blank(): nothing but white space, separators, BOMs and NULs.
func blank(s string) bool {
	return strings.TrimFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.In(r, unicode.Z) || r == 0xFEFF || r == 0
	}) == ""
}

func orDiscard(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}

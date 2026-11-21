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
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/process"
)

const (
	defaultTimeout = 60              // seconds: PFB_HOOK_TIMEOUT_DEFAULT
	defaultGrace   = 5 * time.Second // PFB_HOOK_KILL_GRACE
	allowance      = 1 << 20         // output bytes per hook the transcript holds (core-api-protocol.md "Update command")
	bourneShell    = "/bin/sh"       // runs a .sh hook that is no executable format, as execvp() does
	notice         = "\n[ pfBlockerNG ] Script output limit (1,048,576 bytes) reached; remaining output is in the main log.\n"
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

// Run runs the enabled hooks of when (pre or post) among rows, one after another in list order, and returns when the last
// has exited; it stops before the next hook once ctx ends. A hook's script is vetted on every run: a bare hook_<when>_*.sh
// or .py file name of a regular file in the hook directory, else it is logged and never run. Each hook's own process gets
// TERM at its timeout and KILL after the grace; what it started is left alone. A hook that is skipped, times out or exits
// non-zero is logged and the next one runs: the caller never fails because of a hook. Output goes to a fresh regular file
// and is sanitized, then read up to its size when the hook exited.
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
	var python *bool // the wrapper's answer, asked once, at the first .py hook
	for i, h := range selected {
		if ctx.Err() != nil {
			return
		}
		r.run(ctx, when, i, h, env, &python)
	}
}

func (r Runner) run(ctx context.Context, when string, index int, h Hook, env []string, python **bool) {
	label := strings.Trim(h.Description, " \t\n\r\x00\x0B")
	if label == "" {
		label = fmt.Sprintf("#%d", index)
	}
	if !r.vetted(h.Script, when) {
		missing := ""
		if h.Script != "" {
			missing = "'" + h.Script + "' "
		}
		r.line(true, "[ pfB Hook ] %s %s script %snot a valid file in %s; skipping\n", when, label, missing, r.Dir)
		return
	}
	path := filepath.Join(r.Dir, h.Script)
	argv := []string{path}
	if strings.HasSuffix(h.Script, ".py") {
		if *python == nil {
			ok := r.interpreter(ctx)
			*python = &ok
		}
		if !**python {
			r.line(true, "[ pfB Hook ] %s %s script '%s' has no usable launcher; skipping\n", when, label, h.Script)
			return
		}
		argv = []string{r.Python, path}
	}
	timeout := h.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	r.line(false, "\n[ pfB Hook ] %s %s (%s, timeout %ds)\n", when, label, h.Script, timeout)
	status, timedOut := r.exec(ctx, argv, env, time.Duration(min(timeout, math.MaxInt64/int64(time.Second)))*time.Second)
	switch {
	case timedOut:
		r.line(true, "[ pfB Hook ] %s %s TIMED OUT after %ds (killed); continuing\n", when, label, timeout)
	case status != 0:
		r.line(true, "[ pfB Hook ] %s %s exited non-zero [ %d ]; continuing\n", when, label, status)
	default:
		r.line(false, "[ pfB Hook ] %s %s completed\n", when, label)
	}
}

// vetted is pfb_hook_script_valid(): script is a bare hook_<when>_*.sh or .py name, and the file it names resolves to a
// regular file directly in the hook directory (a symlink to a file there counts; one leading out does not).
func (r Runner) vetted(script, when string) bool {
	if strings.Contains(script, "/") || !strings.HasPrefix(script, "hook_"+when+"_") ||
		!strings.HasSuffix(script, ".sh") && !strings.HasSuffix(script, ".py") {
		return false
	}
	dir, err := filepath.EvalSymlinks(r.Dir)
	if err != nil {
		return false
	}
	real, err := filepath.EvalSymlinks(filepath.Join(r.Dir, script))
	if err != nil || filepath.Dir(real) != dir {
		return false
	}
	info, err := os.Stat(real)
	return err == nil && info.Mode().IsRegular()
}

// interpreter asks the wrapper whether it has an interpreter (pfb_python_interpreter()).
func (r Runner) interpreter(ctx context.Context) bool {
	if r.Python == "" {
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

// exec runs argv under the survivor policy with its output in a fresh regular file, then sanitizes what the file held when
// the hook exited. status is the exit status: 128+n for signal n, 126 when the file cannot be run, 127 when it cannot be
// started at all, as timeout(1) reports them, and -1 when no output file can be made.
func (r Runner) exec(ctx context.Context, argv, env []string, timeout time.Duration) (status int, timedOut bool) {
	capture, err := os.CreateTemp("", "pfb-hook-output-")
	if err != nil {
		return -1, false
	}
	defer os.Remove(capture.Name())
	defer capture.Close()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := func(argv []string) process.Outcome {
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Env, cmd.Stdout, cmd.Stderr = env, capture, capture
		return process.RunSurvivor(ctx, cmd, r.grace())
	}
	out := start(argv)
	if len(argv) == 1 && errors.Is(out.CommandErr, syscall.ENOEXEC) {
		out = start([]string{bourneShell, argv[0]})
	}
	r.drain(capture)
	var exit *exec.ExitError
	switch {
	case out.Interrupted != nil:
		return 0, true
	case out.CommandErr == nil:
		return 0, false
	case errors.As(out.CommandErr, &exit):
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), false
		}
		return exit.ExitCode(), false
	case errors.Is(out.CommandErr, fs.ErrPermission) || errors.Is(out.CommandErr, syscall.ENOEXEC):
		return 126, false
	}
	return 127, false
}

// drain sanitizes the capture up to its size now: a descendant may keep writing to it, and is not waited for.
func (r Runner) drain(capture *os.File) {
	info, err := capture.Stat()
	if err != nil {
		return
	}
	f, err := os.Open(capture.Name())
	if err != nil {
		return
	}
	defer f.Close()
	log, transcript := bufio.NewWriter(orDiscard(r.Log)), bufio.NewWriter(orDiscard(r.Transcript))
	left, noticed := allowance, false
	sanitize(io.LimitReader(f, info.Size()), func(text string, atomic bool) {
		log.WriteString(text)
		switch {
		case noticed:
		case len(text) <= left:
			transcript.WriteString(text)
			left -= len(text)
		default:
			if !atomic { // a run of printable ASCII: cut at the allowance
				transcript.WriteString(text[:left])
			}
			transcript.WriteString(notice)
			noticed = true
		}
	})
	log.Flush()
	transcript.Flush()
}

// sanitize is pfb_script_output_sanitize_chunk() over all of r: printable ASCII, TAB and LF stay; other ASCII controls,
// DEL and each byte of malformed UTF-8 become \xNN; Unicode Cc and Cf become \u{HEX}; other characters stay. emit gets
// runs of printable ASCII (atomic false) and single units that must not be cut (atomic true).
func sanitize(r io.Reader, emit func(text string, atomic bool)) {
	buf := make([]byte, 64<<10)
	var carry []byte
	for {
		n, err := io.ReadFull(r, buf[len(carry):])
		copy(buf, carry)
		data, final := buf[:len(carry)+n], err != nil
		carry = nil
		for i := 0; i < len(data); {
			b := data[i]
			switch {
			case printable(b):
				j := i + 1
				for j < len(data) && printable(data[j]) {
					j++
				}
				emit(string(data[i:j]), false)
				i = j
				continue
			case b < utf8.RuneSelf:
				emit(fmt.Sprintf(`\x%02X`, b), true)
				i++
				continue
			case !final && !utf8.FullRune(data[i:]):
				carry = append([]byte(nil), data[i:]...)
			}
			if carry != nil {
				break
			}
			ch, size := utf8.DecodeRune(data[i:])
			switch {
			case ch == utf8.RuneError && size == 1:
				emit(fmt.Sprintf(`\x%02X`, b), true)
			case unicode.In(ch, unicode.Cc, unicode.Cf):
				emit(fmt.Sprintf(`\u{%X}`, ch), true)
			default:
				emit(string(data[i:i+size]), true)
			}
			i += size
		}
		if final {
			return
		}
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
// [A-Z0-9_]+ and that holds no NUL, then PFB_WHEN and the lifecycle entries, which no context name replaces.
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
	vars["WHEN"], vars["PKG_OP"] = when, c.PkgOp
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

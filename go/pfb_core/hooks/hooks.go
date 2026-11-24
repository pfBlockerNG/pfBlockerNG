// Package hooks runs the ADR-12 update hooks (pfb_run_hooks(), docs/specs/go-updater-pipeline.md §5): the vetted
// hook_<when>_*.sh and .py files of the hook directory that the settings/hooks rows name, one after another, under the
// survivor policy. tests/hooks/fixtures/runner is the parity corpus.
package hooks

import (
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

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/output"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/process"
)

const (
	defaultTimeout = 60 // seconds
	defaultGrace   = 5 * time.Second
	bourneShell    = "/bin/sh"
)

var errTimedOut = errors.New("hook timed out")

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

// PkgOps are the package operations a Context's PkgOp may name; "" is none.
var PkgOps = []string{"install", "upgrade", "reinstall", "delete"}

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
	Errors     io.Writer     // the error log: skipped or failed hooks, failed output writes, a cancelled run (nil: none)
	Transcript io.Writer     // the Update transcript: every line and the first 1,048,576 bytes of each hook's output (nil: none)
	Grace      time.Duration // between TERM and KILL; 0 is 5 s
	// SignalLag is how long a hook that ends with a status above 128 waits for the run to be cancelled before it counts
	// as failed rather than cut short: a signal sent to the whole process group can end the hook before its handler has
	// cancelled ctx. 0 waits not at all: only whether ctx has ended when the hook does counts.
	SignalLag time.Duration
	// Hold, when set, is a lock each hook's holder keeps until the hook's own process exits, so that a caller killed
	// while a hook runs does not free it early; the hook and what it starts never get it (issue #4225).
	Hold *os.File
}

// Run runs the enabled hooks of when (pre or post) among rows, one after another in list order, and returns when the
// last has exited. A hook's script is vetted on every run: a bare hook_<when>_*.sh or .py file name of a regular file
// in the hook directory, else it is logged and never run. Each hook's own process gets TERM at its timeout and KILL
// after the grace; what it started is left alone. A hook that is skipped, times out or exits non-zero is logged and the
// next one runs: the caller never fails because of a hook. When ctx ends, a running hook gets TERM and KILL the same
// way, no further hook starts, and one line says the run was cancelled and how many enabled hooks did not run. Output
// goes to a fresh regular file, sanitized into the logs while the hook runs, and read up to its size sampled after the
// hook exited (output.Capture). cut is whether ctx ended the run with an enabled hook unrun or cut short.
func (r Runner) Run(ctx context.Context, when string, rows []Hook, c Context) (cut bool) {
	if when != "pre" && when != "post" {
		return false
	}
	var selected []Hook
	for _, h := range rows {
		if h.Enabled && h.When == when && !blank(h.Script) {
			selected = append(selected, h)
		}
	}
	if len(selected) == 0 {
		return false
	}
	env := environ(when, c)
	python := sync.OnceValue(func() bool { return r.interpreter(ctx, env) })
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
		r.sinks().Line(true, "[ pfB Hook ] %s run cancelled; %d enabled hook%s did not run\n", when, left, plural)
		return true
	}
	return false
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
		r.sinks().Line(true, "[ pfB Hook ] %s %s script %snot a valid file in %s; skipping\n", when, label, missing, r.Dir)
		return ran
	}
	argv := []string{path}
	if strings.HasSuffix(h.Script, ".py") {
		ok := python()
		if ctx.Err() != nil {
			return cancelled
		}
		if !ok {
			r.sinks().Line(true, "[ pfB Hook ] %s %s script '%s' has no usable launcher; skipping\n", when, label, h.Script)
			return ran
		}
		argv = []string{r.Python, path}
	}
	timeout := h.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	r.sinks().Line(false, "\n[ pfB Hook ] %s %s (%s, timeout %ds)\n", when, label, h.Script, timeout)
	status, e := r.exec(ctx, argv, env, time.Duration(min(timeout, math.MaxInt64/int64(time.Second)))*time.Second)
	// decided before any line is written, so that a slow log never widens the window in which a cancel still counts
	cut := status > 128 && (ctx.Err() != nil || r.SignalLag > 0 && cancelledWithin(ctx, r.SignalLag))
	switch {
	case e == timedOut:
		r.sinks().Line(true, "[ pfB Hook ] %s %s TIMED OUT after %ds (killed); continuing\n", when, label, timeout)
	case e != ran:
		return e
	case status != 0:
		r.sinks().Line(true, "[ pfB Hook ] %s %s exited non-zero [ %d ]; continuing\n", when, label, status)
		if cut {
			return interrupted // its status is logged; it still counts as cut short
		}
	default:
		r.sinks().Line(false, "[ pfB Hook ] %s %s completed\n", when, label)
	}
	return ran
}

// cancelledWithin is whether ctx is cancelled now or within lag (Runner.SignalLag). A variable for the tests alone.
var cancelledWithin = func(ctx context.Context, lag time.Duration) bool {
	timer := time.NewTimer(lag)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return true
	case <-timer.C:
		return false
	}
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

// interpreter is whether the Python wrapper names an interpreter, asked with env, the environment the hook would get, so
// that the wrapper's own PFB_* overrides reach neither the probe nor the launch.
func (r Runner) interpreter(ctx context.Context, env []string) bool {
	if !filepath.IsAbs(r.Python) { // a relative wrapper would be looked up in PATH
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.Python, "--print-interpreter")
	cmd.Env, cmd.WaitDelay = env, r.grace()
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

// exec runs argv under the survivor policy with its output captured (output.Capture): sanitized into the logs while the
// hook runs, and up to its size sampled once the hook's own process has exited and been reaped, so that what a service
// the hook left running writes in between is included. status is the exit status: 128+n for signal n; as timeout(1)
// reports a failure to start, 127 when the program does not exist and 126 when it exists but cannot be started; and -1
// when no output file can be made.
func (r Runner) exec(ctx context.Context, argv, env []string, timeout time.Duration) (status int, e end) {
	ctx, cancel := context.WithTimeoutCause(ctx, timeout, errTimedOut)
	defer cancel()
	var out process.Outcome
	captured := output.Capture("pfb-hook-output-", r.sinks(),
		func(hook *os.File) {
			start := func(argv []string) process.Outcome {
				cmd := exec.Command(argv[0], argv[1:]...)
				if r.Hold != nil {
					self, err := os.Executable()
					if err != nil {
						return process.Outcome{CommandErr: err}
					}
					cmd = exec.Command(self, append([]string{holdArg}, argv...)...)
					cmd.ExtraFiles = []*os.File{r.Hold}
				}
				cmd.Env, cmd.Stdout, cmd.Stderr = env, hook, hook
				return process.RunSurvivor(ctx, cmd, r.grace())
			}
			out = start(argv)
			if len(argv) == 1 && errors.Is(out.CommandErr, syscall.ENOEXEC) { // no #! line: sh runs it, as execvp() does
				out = start([]string{bourneShell, argv[0]})
			}
		})
	if !captured {
		return -1, ran
	}
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
	case errors.Is(out.CommandErr, fs.ErrNotExist):
		return 127, ran
	}
	return 126, ran
}

func (r Runner) sinks() output.Sinks {
	return output.Sinks{Log: r.Log, Transcript: r.Transcript, Errors: r.Errors}
}

// environ is the hooks' environment: the runner's own without any PFB_* entry, then PFB_<NAME> for each context value
// whose upper-cased name is [A-Z0-9_]+ and that holds no NUL, then PFB_WHEN and the lifecycle entries, which no context
// name replaces. A PkgOp holding a NUL is no operation: PFB_PKG_OP is set empty, as hooks expect it always set.
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
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool { return strings.HasPrefix(kv, "PFB_") })
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

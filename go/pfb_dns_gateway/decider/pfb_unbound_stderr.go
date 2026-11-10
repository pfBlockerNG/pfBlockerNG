package decider

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/pysem"
)

// The module's sys.stderr. init_standard() points it at a logger (log_stderr in pfb_unbound.py): every write is appended to
// py_error.log in the log directory as "<asctime>|ERROR| <message stripped of trailing whitespace>", and a message equal to
// the one written just before it is not logged again (pfb["p_err"]). Users read that file in the Log Browser.
//
// The shim's log_err, log_warn and log_info are not this channel: they print to sys.__stderr__, which is the process
// stderr, and stay on it (logErr, logWarn, logInfo). Only what the module wrote through sys.stderr goes through pyStderr.

const pyErrorLogName = "py_error.log"

// stderrRedirect is sys.stderr of the one module of the process. Before a module redirects it (and in the standalone reply
// log, which Python never redirects) a write goes to the process stderr.
var stderrRedirect struct {
	mu      sync.Mutex
	owner   *pfbUnbound // the module that redirected it, nil when nothing has
	path    string      // py_error.log
	last    string      // pfb["p_err"]: the raw message written last
	failing bool        // the file could not be written: said once, until a write works again
}

// stderrNow is the clock of a row's asctime; a test sets it.
var stderrNow = time.Now

// redirectStderr is the redirect of init_standard: it creates py_error.log (logging.basicConfig opens it at once) and
// resets pfb["p_err"]. A file it cannot open is removed once and opened again, as Python does for one that unbound does not
// own; one that still cannot be opened is said once on the process stderr, and the module's errors stay there.
func (m *pfbUnbound) redirectStderr() {
	path := m.logPath(pyErrorLogName)
	err := touch(path)
	if err != nil {
		if info, statErr := os.Stat(path); statErr == nil && info.Mode().IsRegular() {
			_ = os.Remove(path)
		}
		err = touch(path)
	}
	stderrRedirect.mu.Lock()
	defer stderrRedirect.mu.Unlock()
	stderrRedirect.last, stderrRedirect.failing = "", false
	if err != nil {
		stderrRedirect.owner, stderrRedirect.path = nil, ""
		logErr(fmt.Sprintf("[pfBlockerNG]: cannot open %s, module errors stay on this log: %v", path, err))
		return
	}
	stderrRedirect.owner, stderrRedirect.path = m, path
}

// restoreStderr gives sys.stderr back to the process when m is the module that redirected it.
func (m *pfbUnbound) restoreStderr() {
	stderrRedirect.mu.Lock()
	defer stderrRedirect.mu.Unlock()
	if stderrRedirect.owner == m {
		stderrRedirect.owner, stderrRedirect.path = nil, ""
	}
}

func touch(path string) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o666)
	if err != nil {
		return err
	}
	return file.Close()
}

// pyStderr is sys.stderr.write(msg): msg is exactly what Python writes, with its trailing newline where it has one (it
// takes part in the comparison with the message before). Without a redirect it is a line of the process stderr, as
// logErr writes it: the standalone reply log, which Python never redirects, and a module that is not booted yet.
// The mutex is held across the file write on purpose: the comparison with the message before, the update of it and the append
// are one step, so concurrent writers cannot reorder rows against it or log a repeat (Python's logging handler lock covers the
// same write). A repeat returns before any I/O, and the callers are the module's error paths.
func pyStderr(msg string) {
	stderrRedirect.mu.Lock()
	defer stderrRedirect.mu.Unlock()
	if stderrRedirect.path == "" {
		logErr(strings.TrimRight(msg, "\n"))
		return
	}
	if msg == stderrRedirect.last {
		return
	}
	stderrRedirect.last = msg
	now := stderrNow()
	row := fmt.Sprintf("%s,%03d|ERROR| %s\n", now.Format("2006-01-02 15:04:05"), now.Nanosecond()/int(time.Millisecond),
		strings.TrimRightFunc(msg, pysem.IsSpace))
	file, err := os.OpenFile(stderrRedirect.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o666)
	if err == nil {
		_, err = file.WriteString(row)
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
	}
	if err == nil {
		stderrRedirect.failing = false
		return
	}
	if !stderrRedirect.failing {
		stderrRedirect.failing = true
		logErr(fmt.Sprintf("[pfBlockerNG]: cannot write %s, module errors go to this log meanwhile: %v", stderrRedirect.path, err))
	}
	logErr(strings.TrimRightFunc(msg, pysem.IsSpace))
}

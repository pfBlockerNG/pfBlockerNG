//go:build unix

package feedfetch

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// fetchRsync runs rsync (no rsync client exists in the standard library, and the protocol is far larger than this
// feature) the way pfb_download() does: pinned to the vetted address, under `ulimit -f` at twice the ceiling with a
// named refusal over it (#2667), and under the request's wall deadline, which ends the whole process group (#2876).
func (f *Fetcher) fetchRsync(ctx context.Context, src *source, req Request, dst string) transfer {
	from := src.path
	if f.Filter {
		pin, reason := f.vet(ctx, src.host)
		if reason != "" {
			return transfer{reason: reason}
		}
		if from = pinRsync(src.path, pin); from == "" {
			return transfer{reason: "feed host could not be pinned"}
		}
	}
	limit := req.maxBytes()
	ctx, cancel := context.WithTimeout(ctx, req.timeout())
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", `ulimit -f "$1" || exit 1; shift; exec "$@"`, "sh",
		strconv.FormatInt(limit/256, 10), f.RsyncBin, "--timeout=5", from, dst)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		pgid := -cmd.Process.Pid
		time.AfterFunc(killGrace, func() { syscall.Kill(pgid, syscall.SIGKILL) })
		return syscall.Kill(pgid, syscall.SIGTERM)
	}
	cmd.WaitDelay = killGrace + time.Second
	out, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		os.Remove(dst)
		return transfer{reason: "rsync transfer timed out"}
	}
	if err != nil {
		os.Remove(dst)
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return transfer{reason: "rsync exit " + strconv.Itoa(exit.ExitCode()) + ": " + string(out)}
		}
		return transfer{reason: "rsync could not run: " + err.Error()}
	}
	if info, err := os.Stat(dst); err != nil || info.Size() > limit {
		os.Remove(dst)
		return transfer{reason: "rsync_too_large"}
	}
	return transfer{status: 200}
}

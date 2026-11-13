//go:build unix

package feedfetch

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// fetchRsync runs rsync (no rsync client exists in the standard library, and the protocol is far larger than this
// feature) the way pfb_download() does: pinned to the vetted address, under `ulimit -f` at twice the ceiling with a
// named refusal over it (#2667), and under the request's wall deadline, which ends the whole process group (#2876).
func (f *Fetcher) fetchRsync(ctx context.Context, src *source, req Request, dst string) transfer {
	from := src.path
	if !f.NoFilter {
		pin, _, reason := f.vet(ctx, src.host)
		if reason != "" {
			return transfer{reason: reason}
		}
		if from = pinRsync(src.path, pin); from == "" {
			return transfer{reason: "feed host could not be pinned"}
		}
	}
	// rsync's temporary file (".NAME.XXXXXX" beside dst) outlives a kill, this run's or an earlier one's (#3911).
	temps := filepath.Join(filepath.Dir(dst), "."+filepath.Base(dst)+".*")
	removeAll(temps)
	defer removeAll(temps)
	limit := req.maxBytes()
	ctx, cancel := context.WithTimeout(ctx, req.timeout())
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", `ulimit -f "$1" || exit 1; shift; exec "$@"`, "sh",
		strconv.FormatInt(limit/256, 10), f.RsyncBin, "--timeout=5", from, dst)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var kill *time.Timer
	cmd.Cancel = func() error {
		pgid := -cmd.Process.Pid
		kill = time.AfterFunc(killGrace, func() { syscall.Kill(pgid, syscall.SIGKILL) })
		return syscall.Kill(pgid, syscall.SIGTERM)
	}
	cmd.WaitDelay = killGrace + time.Second
	var out bytes.Buffer
	cmd.Stdout = &capped{&out, 4096}
	cmd.Stderr = cmd.Stdout
	err := cmd.Run()
	if kill != nil {
		kill.Stop() // the group is gone; never signal a reused pgid
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		os.Remove(dst)
		return transfer{reason: "rsync transfer timed out"}
	}
	if err != nil {
		os.Remove(dst)
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return transfer{reason: "rsync exit " + strconv.Itoa(exit.ExitCode()) + ": " + out.String()}
		}
		return transfer{reason: "rsync could not run: " + err.Error()}
	}
	if info, err := os.Stat(dst); err != nil || info.Size() > limit {
		os.Remove(dst)
		return transfer{reason: "rsync_too_large"}
	}
	return transfer{status: 200}
}

func removeAll(pattern string) {
	matches, _ := filepath.Glob(pattern)
	for _, m := range matches {
		os.Remove(m)
	}
}

// capped keeps the first n bytes of rsync's output (a daemon's message can be arbitrarily long) and drops the rest.
type capped struct {
	b *bytes.Buffer
	n int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.n - c.b.Len(); room > 0 {
		c.b.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

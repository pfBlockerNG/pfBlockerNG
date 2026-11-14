//go:build linux || freebsd

package update

import (
	"context"
	"testing"
)

func TestEveryTerminalProgramResultCommitsCompletionWithoutKillingItsDaemon(t *testing.T) {
	for _, end := range []string{"exit 0", "exit 7", "exit 75", "kill -TERM $$"} {
		t.Run(end, func(t *testing.T) {
			c, dir := program(t, `sleep 60 >/dev/null 2>&1 </dev/null &
echo $! > "$D/child"
`+end)
			_, err := c.Run(context.Background(), Request{}, newLog(t))
			if (end == "exit 0") != (err == nil) {
				t.Errorf("Run(%s) = %v; want success only for exit 0", end, err)
			}
			child := recordedPid(t, dir)
			if exited(child) {
				t.Errorf("daemon %d was killed after terminal program result %s", child, end)
			}
		})
	}
}

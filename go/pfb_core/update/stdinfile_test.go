package update

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestTheProgramsStdinIsARegularFileNeverAPipe(t *testing.T) {
	p, dir := program(t, `echo ran > "$D/ran"; [ -f /dev/fd/0 ] || echo "fd 0" > "$D/notfile"`)
	if _, err := runCmd(t, p, Request{Trigger: "manual"}, newLog(t)); err != nil {
		t.Fatalf("Run = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ran")); err != nil {
		t.Fatalf("the program did not run to its check: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "notfile")); err == nil {
		t.Error("the program's stdin is not a regular file: a pipe makes Run wait for a descendant that keeps it open")
	}
}

// reaped is true once pid is no longer a process at all: a zombie still counts as there, which is what Run's own wait ends.
func reaped(pid int) bool { return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) }

// A context that ends once the program has exited and been reaped must not reach the descendants it left running, whatever
// holds the program's stdin: a reload it started in the background has to survive.
func TestAContextEndingAfterTheProgramExitedLeavesItsDescendantsAndTheSuccess(t *testing.T) {
	var feeds []string
	for i := range 20000 { // about 450 KB: far over a pipe buffer
		feeds = append(feeds, fmt.Sprintf("ipv4:feed_%05d_v4", i))
	}
	p, dir := program(t, `exec 4<&0
sleep 60 <&4 &
echo $! > "$D/child"
echo $$ > "$D/leader"
echo up > "$D/up"
exit 0`)
	log := newLog(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	type ended struct {
		res Result
		err error
	}
	got := make(chan ended, 1)
	go func() {
		res, err := p.Run(ctx, Request{Trigger: "apply", Feeds: feeds}, log)
		got <- ended{res, err}
	}()
	awaitFile(t, filepath.Join(dir, "up"))
	child := recordedPid(t, dir)
	raw, err := os.ReadFile(filepath.Join(dir, "leader"))
	if err != nil {
		t.Fatalf("ENVIRONMENT: the program never recorded its pid: %v", err)
	}
	leader, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("ENVIRONMENT: the program's pid file holds %q: %v", raw, err)
	}
	for deadline := time.Now().Add(stuck); !reaped(leader); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("STUCK: the program %d was never reaped", leader)
		}
	}
	cancel()
	e := recv(t, got, "Run never returned")
	if e.err != nil || !reflect.DeepEqual(e.res, Result{}) {
		t.Errorf("Run = (%s, %v), want its success and no result: the program had exited before the context ended", jsonOf(t, e.res), e.err)
	}
	if exited(child) {
		t.Errorf("the descendant %d was killed by a context that ended after the program had exited", child)
	}
}

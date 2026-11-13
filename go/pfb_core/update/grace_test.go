package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The leader dies on TERM at once; a child of its group traps TERM and needs a moment to finish. The group, not the leader,
// is what the TERM grace waits for: a KILL sent when the leader is gone would end the child before its marker.
func TestAGroupMemberHandlingTermGetsItsGraceAfterTheLeaderDies(t *testing.T) {
	p, dir := program(t, `export D
cat > "$D/child.sh" <<'EOF'
trap 'sleep 0.3; echo handled > "$D/marker"; exit 0' TERM
echo $$ > "$D/child"
echo up > "$D/up"
sleep 60 &
wait
EOF
sh "$D/child.sh" &
sleep 60`)
	log := newLog(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ended := make(chan error, 1)
	go func() { _, err := p.Run(ctx, Request{Trigger: "manual"}, log); ended <- err }()
	awaitFile(t, filepath.Join(dir, "up"))
	pid := recordedPid(t, dir)
	cancel()
	err := recv(t, ended, "Run never returned after its context was canceled")
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "killed") {
		t.Errorf("Run = %v, want an error saying the program was killed, wrapping context.Canceled", err)
	}
	marker, rerr := os.ReadFile(filepath.Join(dir, "marker"))
	if rerr != nil || string(marker) != "handled\n" {
		t.Errorf("the group member's marker = %q (%v), want it written: the group was killed when its leader died instead of being given its TERM grace", marker, rerr)
	}
	if !exited(pid) {
		t.Errorf("the group member %d still runs after Run returned, want Run to wait until the group is gone", pid)
	}
}

// The cap is a pin on the value and on Cap 0 meaning it; Run's own use of it is the cap test of command_test.go.
func TestTheDefaultCapIsFourHoursAndACapSetIsKept(t *testing.T) {
	for _, c := range []struct{ set, want time.Duration }{
		{0, 4 * time.Hour},
		{time.Minute, time.Minute},
		{5 * time.Hour, 5 * time.Hour},
	} {
		if got := (&Command{Cap: c.set}).limit(); got != c.want {
			t.Errorf("Command{Cap: %v} runs for at most %v, want %v", c.set, got, c.want)
		}
	}
}

func TestACanceledContextStartsNothingEvenWhenThePathIsMissing(t *testing.T) {
	c := &Command{Path: filepath.Join(t.TempDir(), "absent")}
	log := newLog(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := c.Run(ctx, Request{Trigger: "manual"}, log)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Run with a canceled context and a missing program = %v, want context.Canceled, not the error of starting it", err)
	}
	if !reflect.DeepEqual(res, Result{}) {
		t.Errorf("Run returned %s, want an empty Result", jsonOf(t, res))
	}
	entries, rerr := os.ReadDir(filepath.Dir(log.Name()))
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(entries) != 1 {
		t.Errorf("the log's directory holds %d entries after a canceled Run, want only the log", len(entries))
	}
}

package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)


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
	lock, err := operationLock(log.Name())
	if err != nil {
		t.Fatalf("lifetime lock after canceled observer = %v; want reacquirable", err)
	}
	if err := lock.Close(); err != nil {
		t.Errorf("release reacquired lifetime lock: %v", err)
	}
	entries, rerr := os.ReadDir(filepath.Dir(log.Name()))
	if rerr != nil {
		t.Fatal(rerr)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if !reflect.DeepEqual(names, []string{"update.log", "update.log.lock"}) {
		t.Errorf("the log directory holds %v after a canceled Run; want only the log and its lifetime lock", names)
	}
}

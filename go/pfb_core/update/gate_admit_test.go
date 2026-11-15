package update

import (
	"context"
	"os"
	"testing"
)

func TestGateStartAdmitsBeforeTruncatingTheLog(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := dir + "/update.log"
	if err := os.WriteFile(logPath, []byte("previous-update\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(logPath+".status", 0o700); err != nil {
		t.Fatal(err)
	}
	g := New(logPath, func(ctx context.Context, req Request, log *os.File) (Result, error) {
		t.Error("the program ran after admission failed")
		return Result{}, nil
	}, nil)
	g.Admit = (&Command{Path: "/bin/true"}).Admit
	t.Cleanup(g.Stop)
	if err := g.Start(Request{Trigger: "apply"}); err == nil {
		t.Fatal("hostile worker state admitted a new Update")
	}
	body, err := os.ReadFile(logPath)
	if err != nil || string(body) != "previous-update\n" {
		t.Fatalf("log = %q, %v; want the previous Update untouched", body, err)
	}
}

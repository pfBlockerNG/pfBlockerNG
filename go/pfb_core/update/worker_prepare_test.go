package update

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestWorkerPreparationFailureNeverPairsOldResultsWithNewAdmission(t *testing.T) {
	log := independentLog(t)
	prior := strings.Replace(validWorkerJSON(t), `"trigger":"apply"`, `"trigger":"manual"`, 1)
	if err := os.WriteFile(log.Name()+".status", []byte(prior), 0o600); err != nil {
		t.Fatal(err)
	}
	oldResult := []byte("{\"version\":1,\"outcomes\":{\"ipv4:old_v4\":\"success\"}}\n")
	if err := os.WriteFile(log.Name()+".result", oldResult, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(log.Name()+".request", 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Command{Path: "/bin/true"}).Run(context.Background(), Request{Trigger: "apply"}, log); err == nil {
		t.Fatal("request preparation unexpectedly succeeded")
	}
	state, err := readWorkerState(log.Name() + ".status")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(log.Name() + ".result")
	if err != nil {
		t.Fatal(err)
	}
	if state.Nonce != strings.Repeat("a", 64) && len(raw) != 0 {
		t.Fatalf("new admission %s retained previous worker's fd3 records %q", state.Nonce, raw)
	}
}

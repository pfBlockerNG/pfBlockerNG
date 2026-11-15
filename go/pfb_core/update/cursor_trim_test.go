package update

import (
	"os"
	"strings"
	"testing"
)

func TestObserverCursorRestartsAfterWorkerTrim(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := dir + "/update.log"
	old := strings.Repeat("old-line\n", 100)
	if err := os.WriteFile(logPath, []byte(old+"kept-tail\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	g := New(logPath, nil, nil)
	g.status = &Status{Trigger: "apply", StartedAt: 1}
	first := mustView(t, g, 0, len(old))
	if !strings.HasPrefix(first.Log, "old-line\n") || first.Next == 0 {
		t.Fatalf("first view = %q next %d", first.Log, first.Next)
	}
	// The worker keeps a tail whose length is still above the observer's old offset.
	if err := os.WriteFile(logPath+".status", []byte(`{"version":1,"nonce":"`+strings.Repeat("a", 64)+`","path":"/bin/true","request":{"trigger":"apply"},"startedAt":1,"logGen":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, []byte("newest\n"+strings.Repeat("x", len(old))), 0o600); err != nil {
		t.Fatal(err)
	}
	second := mustView(t, g, first.Next, len(old))
	if strings.Contains(second.Log, "newest") {
		return
	}
	t.Fatalf("cursor %d read %q after trim; size still covers the old offset, so the observer skipped the new start", first.Next, second.Log)
}

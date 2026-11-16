package update

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func workerStateWithLogGen(logGen int64) workerState {
	finished, exit := int64(101), 0
	return workerState{
		Version: workerVersion, Nonce: strings.Repeat("0", 64), Path: "/bin/true",
		Request: Request{Trigger: "manual"}, StartedAt: 100, LogGen: logGen, Settled: true,
		FinishedAt: &finished, ExitCode: &exit,
	}
}

func TestAdmissionCursorGenerationWrapsAtMask(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "update.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeWorkerState(logPath+".status", workerStateWithLogGen(genMask)); err != nil {
		t.Fatal(err)
	}
	admission, err := (&Command{Path: "/bin/true"}).Admit(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer admission.Close()
	if admission.logGen != 0 {
		t.Errorf("next admission LogGen = %d; want wrapped generation 0", admission.logGen)
	}
}

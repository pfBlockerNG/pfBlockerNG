package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func maintenanceTestProgram(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "program.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMaintenanceDeferralIsBenignAndOtherFailuresRemainVisible(t *testing.T) {
	for _, kind := range []string{"deferred", "exit", "start", "logIO"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := maintenanceTestProgram(t, dir, "exit 0")
			logPath := filepath.Join(dir, "maintenance.log")
			if kind == "deferred" {
				path = maintenanceTestProgram(t, dir, "printf 'deferred marker\\n'\nexit 75")
			}
			if kind == "exit" {
				path = maintenanceTestProgram(t, dir, "printf 'failure marker\\n'\nexit 42")
			}
			if kind == "start" {
				path = filepath.Join(dir, "missing-program")
			}
			if kind == "logIO" {
				if err := os.Mkdir(logPath, 0o700); err != nil {
					t.Fatal(err)
				}
			}

			err := maintenance(path, dir)(context.Background())
			if kind == "deferred" {
				if err != nil {
					t.Fatalf("actual exit 75 returned %v, want benign nil", err)
				}
			} else if err == nil {
				t.Fatalf("%s failure was hidden", kind)
			}
			if kind == "exit" && !strings.Contains(err.Error(), "exit status 42") {
				t.Errorf("nonzero exit result = %v, want actual status 42", err)
			}
			if kind == "start" && !strings.Contains(err.Error(), "missing-program") {
				t.Errorf("start error = %v, want missing program path", err)
			}
			if kind == "logIO" {
				var pathErr *os.PathError
				if !errors.As(err, &pathErr) || pathErr.Op != "open" || pathErr.Path != logPath {
					t.Errorf("log open error = %v, want open %s", err, logPath)
				}
			}
		})
	}
}

func TestMaintenanceEmptyCommandIsDisabled(t *testing.T) {
	if callback := maintenance("", t.TempDir()); callback != nil {
		t.Fatal("an empty maintenance command enabled a callback")
	}
}

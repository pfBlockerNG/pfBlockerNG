package feedparse

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeFileDoesNotSweepAnotherFeedsActiveTemp(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "feedA.orig"), []byte("a.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct {
		path string
		err  error
	}, 1)
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		tmp, err := os.CreateTemp(dir, ".pfbnorm_*")
		if err != nil {
			started <- struct {
				path string
				err  error
			}{err: err}
			done <- err
			return
		}
		started <- struct {
			path string
			err  error
		}{path: tmp.Name()}
		<-release
		_, writeErr := tmp.Write([]byte("still active"))
		closeErr := tmp.Close()
		if writeErr != nil {
			done <- writeErr
		} else {
			done <- closeErr
		}
	}()

	active := <-started
	if active.err != nil {
		t.Fatal(active.err)
	}
	released, waited := false, false
	defer func() {
		if !released {
			close(release)
		}
		if !waited {
			<-done
		}
	}()
	if got := NormalizeFile(dir, "feedA"); !got.Normalized {
		t.Fatalf("NormalizeFile = %+v, want a normalized feed", got)
	}
	if _, err := os.Stat(active.path); err != nil {
		t.Errorf("another feed's active temp stat error = %v, want it preserved", err)
	}
	close(release)
	released = true
	if err := <-done; err != nil {
		t.Errorf("active temp writer: %v", err)
	}
	waited = true
}

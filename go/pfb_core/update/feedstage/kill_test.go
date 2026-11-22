package feedstage

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// A KILL test runs its feed in a child process, this test binary re-run for that one test with these variables set.
const (
	killAtEnv   = "PFB_FEEDSTAGE_KILL_AT"   // the step boundary the child announces, then waits at for the KILL
	killRootEnv = "PFB_FEEDSTAGE_KILL_ROOT" // the root of the folders killStage uses
)

// killRoot makes the folders killStage uses below a fresh root and publishes baseline as the feed's list.
func killRoot(t *testing.T, baseline string) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"orig", "db", "scripts"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(root, "db", "feed.txt"), baseline)
	stage, feed := killStage(root)
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the baseline run = %+v", r)
	}
	return root
}

// killScript writes the list script name of root with body; killChildAt sets every script it finds on the feed.
func killScript(t *testing.T, root, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "scripts", name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// killChildAt runs the feed of root in the child: at the step boundary it announces on fd 3, then waits on stdin for the
// KILL. It never returns.
func killChildAt(root, boundary string) {
	step = func(name string) {
		if name != boundary {
			return
		}
		event := os.NewFile(3, "event")
		_, _ = event.Write([]byte("ready"))
		_ = event.Close()
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(3) // the parent went away without the KILL
	}
	stage, feed := killStage(root)
	if regularExists(filepath.Join(root, "scripts", "pre.sh")) {
		feed.PreScript = "pre.sh"
	}
	if regularExists(filepath.Join(root, "scripts", "post.sh")) {
		feed.PostScript = "post.sh"
	}
	run(stage, feed, "none")
	os.Exit(2) // the boundary was never reached
}

// killAt runs the feed of root in a child process of the test named test and KILLs it at the step boundary.
func killAt(t *testing.T, test, root, boundary string) {
	t.Helper()
	events, eventWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	hold, holdWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer holdWriter.Close()
	// The cap only fails a hung run: on expiry the child is killed, which ends the read below with EOF.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+test+"$", "-test.count=1")
	child.Env = append(os.Environ(), killAtEnv+"="+boundary, killRootEnv+"="+root)
	child.ExtraFiles = []*os.File{eventWriter}
	child.Stdin = hold
	child.Stdout, child.Stderr = os.Stderr, os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	eventWriter.Close()
	hold.Close()
	buf := make([]byte, len("ready"))
	if _, err := io.ReadFull(events, buf); err != nil {
		werr := child.Wait()
		t.Fatalf("the child never reached the boundary %q: %v (child: %v)", boundary, err, werr)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
}

// noLeftovers fails for any run folder, staged file or restore point left in the feed folder dir.
func noLeftovers(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".orig.post") || strings.Contains(e.Name(), ".pfb") {
			t.Errorf("recovery left %s", e.Name())
		}
	}
}

// Scenario: KILL after a failed feed's run is dropped.
// Given a published baseline and a changed source whose pre-script fails after the new download was normalized, when the
// Updater is killed right after the failed run is dropped, then the feed folder is the baseline byte for byte: neither the
// abandoned download nor its normalization reached it. The next run ingests that download again and must parse it, never
// reuse the baseline's list for it.
func TestKillAfterRestoreLeavesNoStaleReuse(t *testing.T) {
	if boundary := os.Getenv(killAtEnv); boundary != "" {
		killChildAt(os.Getenv(killRootEnv), boundary)
	}
	root := killRoot(t, "198.51.100.1\n")
	dir := filepath.Join(root, "orig")
	baseline := publishedState(t, dir)
	writeFile(t, filepath.Join(root, "db", "feed.txt"), "198.51.100.2\n")
	killScript(t, root, "pre.sh", "exit 1")
	killAt(t, "TestKillAfterRestoreLeavesNoStaleReuse", root, "restored")
	if got := publishedState(t, dir); !reflect.DeepEqual(got, baseline) {
		t.Fatalf("at the KILL the feed folder is\n %q\nwant the baseline byte for byte\n %q", got, baseline)
	}
	if err := Recover(dir); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	noLeftovers(t, dir)
	if err := os.Remove(filepath.Join(root, "scripts", "pre.sh")); err != nil {
		t.Fatal(err)
	}
	stage, feed := killStage(root)
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the run after the KILL = %+v, want the change parsed, not the baseline's list reused", r)
	}
	if got := readFile(t, filepath.Join(dir, "Feed_v4.parsed.ip")); got != "198.51.100.2\n" {
		t.Fatalf("the run after the KILL published %q, want the changed source", got)
	}
}

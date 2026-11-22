package feedfetch

import (
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/digest"
)

// The TOP1M publication's KILL matrix (#4198): the list, its raw baseline and the baseline's digest are published by
// renames alone, with no copy set aside and nothing put back. A process killed before any rename, between two of them, or
// after the last leaves a folder that the next run's recovery and publication bring to exactly what an uninterrupted run
// leaves; the list is never absent; and while the list is still the old one, the change detector never reads the new
// source as unchanged.

const (
	top1mKillOldList = "1,old.example\n"
	top1mKillNewList = "1,new.example\n"
	top1mKillOldRaw  = "old raw body"
	top1mKillNewRaw  = "new raw body"
)

// top1mKillRenames is how many renames a publication makes; a kill point past it falls after the last one.
const top1mKillRenames = 3

// seedTop1MKill lays out a folder as an earlier publication left it, with that version's validators, plus this run's list
// staged under stageName (a TOP1M stage's own prefix) and its raw download.
func seedTop1MKill(t *testing.T, dir, stageName string) (stage, target, base, raw string) {
	t.Helper()
	target, base = filepath.Join(dir, "top-1m.csv"), filepath.Join(dir, "top-1m.csv.zip")
	stage, raw = filepath.Join(dir, stageName), filepath.Join(dir, "top-1m.csv.zip.raw")
	for path, content := range map[string]string{
		target: top1mKillOldList, base + ".orig": top1mKillOldRaw, base + ".xxhash128": digest.Bytes([]byte(top1mKillOldRaw)), base + ".md5": "legacy", base + ".orig.etag": `"v1"`, base + ".orig.lastmod": "1700000000",
		stage: top1mKillNewList, raw: top1mKillNewRaw,
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return stage, target, base, raw
}

// folderOf is every file of dir by name, with its content.
func folderOf(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && p != dir {
			rel, _ := filepath.Rel(dir, p)
			if d.IsDir() {
				files[rel+"/"] = ""
			} else {
				b, _ := os.ReadFile(p)
				files[rel] = string(b)
			}
		}
		return nil
	})
	return files
}

// publishedFiles drops the files a run stages on the way (and the caller's own stage and raw download) from a folder listing.
func publishedFiles(files map[string]string) map[string]string {
	out := map[string]string{}
	for name, content := range files {
		if !strings.HasPrefix(name, ".pfbtop1m_") && !strings.HasSuffix(name, ".raw") {
			out[name] = content
		}
	}
	return out
}

// TestTop1MKillChild is the child of the KILL matrix: it publishes and sends itself SIGKILL at the kill point.
func TestTop1MKillChild(t *testing.T) {
	dir, point := os.Getenv("PFB_TOP1M_KILL_DIR"), os.Getenv("PFB_TOP1M_KILL_POINT")
	if dir == "" {
		t.Skip("run by TestTop1MPublicationSurvivesAKillAtEveryStep")
	}
	at, _ := strconv.Atoi(point)
	real, n := rename, 0
	rename = func(from, to string) error {
		n++
		if n == at {
			syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
		err := real(from, to)
		if at > top1mKillRenames && n == top1mKillRenames {
			syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
		return err
	}
	target, base := filepath.Join(dir, "top-1m.csv"), filepath.Join(dir, "top-1m.csv.zip")
	top1mCommit(filepath.Join(dir, os.Getenv("PFB_TOP1M_KILL_STAGE")), target, base, filepath.Join(dir, "top-1m.csv.zip.raw"))
	t.Fatal("the publication ran to its end without reaching its kill point")
}

func TestTop1MPublicationSurvivesAKillAtEveryStep(t *testing.T) {
	// The uninterrupted run, which every killed one must end like.
	clean := t.TempDir()
	stage, target, base, raw := seedTop1MKill(t, clean, top1mStaging+"clean")
	if !top1mCommit(stage, target, base, raw) {
		t.Fatal("the uninterrupted publication failed")
	}
	want := folderOf(t, clean)
	if want["top-1m.csv"] != top1mKillNewList || want["top-1m.csv.zip.orig"] != top1mKillNewRaw {
		t.Fatalf("the uninterrupted publication left %v", want)
	}

	for at := 1; at <= top1mKillRenames+1; at++ {
		t.Run("kill before rename "+strconv.Itoa(at), func(t *testing.T) {
			dir := t.TempDir()
			_, target, base, raw := seedTop1MKill(t, dir, top1mStaging+"killed")
			before := publishedFiles(folderOf(t, dir))

			cmd := exec.Command(os.Args[0], "-test.run=^TestTop1MKillChild$", "-test.count=1")
			cmd.Env = append(os.Environ(), "PFB_TOP1M_KILL_DIR="+dir, "PFB_TOP1M_KILL_POINT="+strconv.Itoa(at), "PFB_TOP1M_KILL_STAGE="+top1mStaging+"killed")
			out, err := cmd.CombinedOutput()
			if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
				t.Fatalf("the child was not killed at its kill point: %v\n%s", err, out)
			}
			killed := folderOf(t, dir)

			if at == 1 {
				// The old version's validators and the baseline's digest may already be gone (a missing digest reads as
				// changed): the list and the baseline may not change.
				for _, name := range []string{"top-1m.csv", "top-1m.csv.zip.orig", "top-1m.csv.zip.md5"} {
					if killed[name] != before[name] {
						t.Errorf("before the first rename %s changed: %q, was %q", name, killed[name], before[name])
					}
				}
				if d, ok := killed["top-1m.csv.zip.xxhash128"]; ok && d != before["top-1m.csv.zip.xxhash128"] {
					t.Errorf("before the first rename the digest changed: %q", d)
				}
			}
			list, present := killed["top-1m.csv"]
			if !present {
				t.Errorf("the list is absent after the kill: %v", killed)
			}
			if list != top1mKillNewList {
				probeBody := filepath.Join(t.TempDir(), "probe")
				os.WriteFile(probeBody, []byte(top1mKillNewRaw), 0o644)
				x := Extra{Dir: dir, File: "top-1m.csv", Download: "top-1m.csv.zip"}
				if d := top1mDecision(transfer{status: 200}, probeBody, base, x, true); d == Unchanged {
					t.Errorf("the old list is live while the detector reads the new source as unchanged: %v", killed)
				}
			}

			if killed["top-1m.csv.zip.orig"] == top1mKillNewRaw {
				if _, ok := killed["top-1m.csv.zip.orig.etag"]; ok {
					t.Errorf("the old version's validators sit beside the new baseline, so a server back on it answers 304: %v", killed)
				}
			}

			// Recovery and a new run of the same download, staged afresh as a run stages it: the next publication.
			stage := filepath.Join(dir, top1mStaging+"rerun")
			for path, content := range map[string]string{stage: top1mKillNewList, raw: top1mKillNewRaw} {
				if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if !top1mCommit(stage, target, base, raw) {
				t.Fatalf("the publication after the kill failed: %v", folderOf(t, dir))
			}
			if got := folderOf(t, dir); !maps.Equal(got, want) {
				t.Errorf("after the kill and a new run:\n got %v\nwant %v", got, want)
			}
		})
	}
}

// A rename that fails at any step leaves the list whole and, unless the new list is live, a baseline that does not vouch for
// the new source; nothing a run staged for the baseline or its digest is left behind (#4198).
func TestTop1MPublicationWithARenameThatFailsAtEachStep(t *testing.T) {
	for at := 1; at <= top1mKillRenames; at++ {
		t.Run("rename "+strconv.Itoa(at)+" fails", func(t *testing.T) {
			dir := t.TempDir()
			stage, target, base, raw := seedTop1MKill(t, dir, top1mStaging+"run")
			real, n := rename, 0
			rename = func(from, to string) error {
				if n++; n == at {
					return os.ErrPermission
				}
				return real(from, to)
			}
			t.Cleanup(func() { rename = real })

			ok := top1mCommit(stage, target, base, raw)

			files := folderOf(t, dir)
			list := files["top-1m.csv"]
			if list != top1mKillOldList && list != top1mKillNewList {
				t.Fatalf("the list is not whole after a failed rename %d: %v", at, files)
			}
			if ok != (list == top1mKillNewList) {
				t.Errorf("the commit reported %v while the live list is %q: it reports whether the new list was published", ok, list)
			}
			if list != top1mKillNewList {
				probeBody := filepath.Join(t.TempDir(), "probe")
				os.WriteFile(probeBody, []byte(top1mKillNewRaw), 0o644)
				x := Extra{Dir: dir, File: "top-1m.csv", Download: "top-1m.csv.zip"}
				if top1mDecision(transfer{status: 200}, probeBody, base, x, true) == Unchanged {
					t.Errorf("the old list is live while the detector reads the new source as unchanged: %v", files)
				}
			}
			for name := range files {
				if strings.HasPrefix(name, top1mStaging) && name != filepath.Base(stage) {
					t.Errorf("a staged file is left behind: %s", name)
				}
			}
		})
	}
}

// A list that today's PHP set aside (".pfbtop1m_active_") while no list is published is the only copy of the live list: the
// commit puts it back first, so a publication that then fails still leaves a list in place.
func TestTop1MPublicationPutsBackAListPHPSetAside(t *testing.T) {
	dir := t.TempDir()
	stage, target, base, raw := seedTop1MKill(t, dir, top1mStaging+"run")
	if err := os.Rename(target, filepath.Join(dir, ".pfbtop1m_active_1234567890")); err != nil {
		t.Fatal(err)
	}
	real := rename
	rename = func(from, to string) error {
		if to == target && from == stage {
			return os.ErrPermission
		}
		return real(from, to)
	}
	t.Cleanup(func() { rename = real })

	top1mCommit(stage, target, base, raw)

	if got, err := os.ReadFile(target); err != nil || string(got) != top1mKillOldList {
		t.Errorf("the list PHP set aside is not back in place: %q, %v", got, err)
	}
}

// The published list is readable by the readers of the database folder, whatever mode its stage was created with.
func TestTop1MPublicationPublishesTheListReadable(t *testing.T) {
	dir := t.TempDir()
	stage, target, base, raw := seedTop1MKill(t, dir, top1mStaging+"run")
	if err := os.Chmod(stage, 0o600); err != nil {
		t.Fatal(err)
	}

	if !top1mCommit(stage, target, base, raw) {
		t.Fatal("the publication failed")
	}

	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("the list is published with mode %v (%v), want 0644", info.Mode().Perm(), err)
	}
}

// The copies of the old list and baseline that today's PHP sets aside are swept by the next commit, a folder as well as a
// file: they are stale once a list is published, and nothing restores them.
func TestTop1MPublicationSweepsThePHPSetAsideCopies(t *testing.T) {
	dir := t.TempDir()
	stage, target, base, raw := seedTop1MKill(t, dir, top1mStaging+"run")
	if err := os.WriteFile(filepath.Join(dir, ".pfbtop1m_active_1234567890"), []byte(top1mKillOldList), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".pfbtop1m_base_1234567890"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".pfbtop1m_base_1234567890", "top-1m.csv.zip.orig"), []byte(top1mKillOldRaw), 0o644); err != nil {
		t.Fatal(err)
	}

	if !top1mCommit(stage, target, base, raw) {
		t.Fatal("the publication failed")
	}

	for name := range folderOf(t, dir) {
		if strings.HasPrefix(name, ".pfbtop1m_") {
			t.Errorf("%s is left after the publication", name)
		}
	}
}

// Of the lists today's PHP set aside, the newest one with content is put back: PHP's tempnam() leaves an empty file under
// the same prefix when it is killed before its unlink, and that file is newer than the list a rename set aside.
func TestTop1MPublicationPutsBackTheNewestNonEmptyCopy(t *testing.T) {
	dir := t.TempDir()
	stage, target, base, raw := seedTop1MKill(t, dir, top1mStaging+"run")
	os.Remove(target)
	now := time.Now()
	for name, copy := range map[string]struct {
		content string
		age     time.Duration
	}{
		".pfbtop1m_active_older": {"1,older.example\n", 2 * time.Hour},
		".pfbtop1m_active_newer": {top1mKillOldList, time.Hour},
		".pfbtop1m_active_empty": {"", 0},
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(copy.content), 0o644); err != nil {
			t.Fatal(err)
		}
		os.Chtimes(p, now.Add(-copy.age), now.Add(-copy.age))
	}
	real := rename
	rename = func(from, to string) error {
		if from == raw {
			return os.ErrPermission // the publication fails before its list goes live
		}
		return real(from, to)
	}
	t.Cleanup(func() { rename = real })

	top1mCommit(stage, target, base, raw)

	if got, err := os.ReadFile(target); err != nil || string(got) != top1mKillOldList {
		t.Errorf("the list put back is %q (%v), want the newest copy with content", got, err)
	}
}

// The raw download becomes the baseline readable by the database folder's readers, whatever mode it was written with.
func TestTop1MPublicationPublishesTheBaselineReadable(t *testing.T) {
	dir := t.TempDir()
	stage, target, base, raw := seedTop1MKill(t, dir, top1mStaging+"run")
	if err := os.Chmod(raw, 0o600); err != nil {
		t.Fatal(err)
	}

	if !top1mCommit(stage, target, base, raw) {
		t.Fatal("the publication failed")
	}

	if info, err := os.Stat(base + ".orig"); err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("the baseline is published with mode %v (%v), want 0644", info.Mode().Perm(), err)
	}
}

// Two publications interrupted in turn never leave a baseline and digest that vouch for a source while another list is
// live: B stops before its digest, then a return to A stops before its list. A baseline and digest of A beside list B would
// read A as unchanged and keep B live (#4198).
func TestTop1MTwoInterruptedPublicationsNeverVouchForAListThatIsNotLive(t *testing.T) {
	dir := t.TempDir()
	stage, target, base, raw := seedTop1MKill(t, dir, top1mStaging+"b")
	failAt := func(at int) {
		real, n := rename, 0
		rename = func(from, to string) error {
			if n++; n == at {
				return os.ErrPermission
			}
			return real(from, to)
		}
		t.Cleanup(func() { rename = real })
	}
	failAt(3)
	top1mCommit(stage, target, base, raw)
	stage = filepath.Join(dir, top1mStaging+"a")
	for path, content := range map[string]string{stage: top1mKillOldList, raw: top1mKillOldRaw} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	failAt(2)
	top1mCommit(stage, target, base, raw)

	files := folderOf(t, dir)
	if files["top-1m.csv"] != top1mKillNewList {
		t.Fatalf("setup: list B is live after both interruptions: %v", files)
	}
	probeBody := filepath.Join(t.TempDir(), "probe")
	os.WriteFile(probeBody, []byte(top1mKillOldRaw), 0o644)
	x := Extra{Dir: dir, File: "top-1m.csv", Download: "top-1m.csv.zip"}
	if top1mDecision(transfer{status: 200}, probeBody, base, x, true) == Unchanged {
		t.Errorf("list B is live while the detector reads source A as unchanged: %v", files)
	}
}

// A list PHP set aside that cannot be put back stays where it is: the commit stops before its sweep, which would remove the
// only copy of the live list.
func TestTop1MPublicationKeepsAPHPCopyItCannotPutBack(t *testing.T) {
	dir := t.TempDir()
	stage, target, base, raw := seedTop1MKill(t, dir, top1mStaging+"run")
	copied := filepath.Join(dir, ".pfbtop1m_active_1234567890")
	if err := os.Rename(target, copied); err != nil {
		t.Fatal(err)
	}
	real := rename
	rename = func(from, to string) error {
		if from == copied {
			return os.ErrPermission
		}
		return real(from, to)
	}
	t.Cleanup(func() { rename = real })

	top1mCommit(stage, target, base, raw)

	if got, err := os.ReadFile(copied); err != nil || string(got) != top1mKillOldList {
		t.Errorf("the only copy of the live list is gone: %q, %v; folder %v", got, err, folderOf(t, dir))
	}
}

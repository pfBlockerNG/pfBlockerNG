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

// seedTop1MKill lays out a folder as an earlier publication left it, plus this run's staged list and raw download.
func seedTop1MKill(t *testing.T, dir string) (stage, target, base, raw string) {
	t.Helper()
	target, base = filepath.Join(dir, "top-1m.csv"), filepath.Join(dir, "top-1m.csv.zip")
	stage, raw = filepath.Join(dir, ".pfbtop1m_123456"), filepath.Join(dir, "top-1m.csv.zip.raw")
	oldDigest, err := digestOf(top1mKillOldRaw)
	if err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{
		target: top1mKillOldList, base + ".orig": top1mKillOldRaw, base + ".xxhash128": oldDigest, base + ".md5": "legacy",
		stage: top1mKillNewList, raw: top1mKillNewRaw,
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return stage, target, base, raw
}

func digestOf(content string) (string, error) {
	f, err := os.CreateTemp("", "digest")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()
	return digest.File(f.Name())
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
	top1mCommit(filepath.Join(dir, ".pfbtop1m_123456"), target, base, filepath.Join(dir, "top-1m.csv.zip.raw"))
	t.Fatal("the publication ran to its end without reaching its kill point")
}

func TestTop1MPublicationSurvivesAKillAtEveryStep(t *testing.T) {
	// The uninterrupted run, which every killed one must end like.
	clean := t.TempDir()
	stage, target, base, raw := seedTop1MKill(t, clean)
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
			stage, target, base, raw := seedTop1MKill(t, dir)
			before := publishedFiles(folderOf(t, dir))

			cmd := exec.Command(os.Args[0], "-test.run=^TestTop1MKillChild$", "-test.count=1")
			cmd.Env = append(os.Environ(), "PFB_TOP1M_KILL_DIR="+dir, "PFB_TOP1M_KILL_POINT="+strconv.Itoa(at))
			out, err := cmd.CombinedOutput()
			if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
				t.Fatalf("the child was not killed at its kill point: %v\n%s", err, out)
			}
			killed := folderOf(t, dir)

			if at == 1 && !maps.Equal(publishedFiles(killed), before) {
				t.Errorf("before the first rename the published files changed:\n got %v\nwant %v", publishedFiles(killed), before)
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

			// Recovery and a new run of the same download: the next publication of the same body.
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

package geoip

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
)

var generationName = regexp.MustCompile(`^\.cc\.[0-9]+\.[0-9a-f]{8}$`)

// current is the generation the country folder links to.
func current(t *testing.T, c Conversion) string {
	t.Helper()
	to, err := os.Readlink(c.CCDir)
	if err != nil {
		t.Fatalf("cc is not a link: %v", err)
	}
	if !generationName.MatchString(to) {
		t.Fatalf("cc links to %q, not a generation beside it", to)
	}
	return to
}

// A generation goes live in one step (#4140): the only rename is a link to it taking the country folder's name, so a
// reader sees the previous generation or the new one whole, and a run killed at any point leaves one of them.
func TestAGenerationIsPublishedByOneLinkRename(t *testing.T) {
	c, log := conversionRoot(t, testBlocks)
	var renames []string
	rename = func(from, to string) error {
		renames = append(renames, to)
		return os.Rename(from, to)
	}
	defer func() { rename = os.Rename }()
	if !c.Run(context.Background()) {
		t.Fatalf("conversion failed:\n%s", log)
	}
	if !slices.Equal(renames, []string{c.CCDir}) {
		t.Errorf("renames onto %v, want one onto %s", renames, c.CCDir)
	}
	gen := current(t, c)
	if b, _ := os.ReadFile(filepath.Join(c.CCDir, "US_v4.txt")); string(b) != "3.0.0.0/15\n" {
		t.Errorf("US_v4.txt = %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(c.CCDir, ".geoip_isos")); !strings.Contains(string(b), "US [ United States ]") {
		t.Errorf(".geoip_isos = %.200q, want the ISO list", b)
	}
	if _, err := os.Stat(filepath.Join(c.CCDir, ".pfb_generation_swapping")); err == nil {
		t.Error("a swap marker in the generation")
	}
	assertBeside(t, c, previousGeneration, gen)
}

// Only the current generation and the one before it remain.
func TestOnlyTwoGenerationsRemain(t *testing.T) {
	c, log := conversionRoot(t, testBlocks)
	var gens []string
	for range 3 {
		if !c.Run(context.Background()) {
			t.Fatalf("conversion failed:\n%s", log)
		}
		gens = append(gens, current(t, c))
	}
	if gens[0] == gens[1] || gens[1] == gens[2] {
		t.Fatalf("a run reused a generation: %v", gens)
	}
	assertBeside(t, c, gens[1], gens[2])
}

// A failed link rename leaves the previous generation live and removes the new one.
func TestAFailedLinkRenameKeepsThePreviousGeneration(t *testing.T) {
	c, _ := conversionRoot(t, testBlocks)
	rename = func(string, string) error { return syscall.EIO }
	defer func() { rename = os.Rename }()
	if c.Run(context.Background()) {
		t.Fatal("published without its rename")
	}
	assertPrevious(t, c)
}

// A country folder that is still a real folder (an install from before #4140) is set aside once, as the previous
// generation, and the link takes its place; a failed rename puts it back.
func TestARealCountryFolderIsSetAsideOnce(t *testing.T) {
	realFolder := func(t *testing.T) Conversion {
		c, _ := conversionRoot(t, testBlocks)
		for _, step := range []error{os.Remove(c.CCDir), os.Mkdir(c.CCDir, 0o755),
			os.WriteFile(filepath.Join(c.CCDir, "US_v4.txt"), []byte("198.51.100.0/24\n"), 0o644),
			os.RemoveAll(filepath.Join(filepath.Dir(c.CCDir), previousGeneration))} {
			if step != nil {
				t.Fatal(step)
			}
		}
		return c
	}
	t.Run("published", func(t *testing.T) {
		c := realFolder(t)
		if !c.Run(context.Background()) {
			t.Fatal("conversion failed")
		}
		gen := current(t, c)
		entries, _ := filepath.Glob(filepath.Join(filepath.Dir(c.CCDir), ".cc.*"))
		var aside string
		for _, e := range entries {
			if name := filepath.Base(e); name != gen && name != ".cc.lock" {
				aside = name
			}
		}
		if !generationName.MatchString(aside) {
			t.Fatalf("the real folder was not set aside as a generation: %v", entries)
		}
		if b, _ := os.ReadFile(filepath.Join(filepath.Dir(c.CCDir), aside, "US_v4.txt")); string(b) != "198.51.100.0/24\n" {
			t.Errorf("the folder set aside holds %q", b)
		}
		assertBeside(t, c, aside, gen)
	})
	t.Run("rename fails", func(t *testing.T) {
		c := realFolder(t)
		rename = func(string, string) error { return syscall.EIO }
		defer func() { rename = os.Rename }()
		if c.Run(context.Background()) {
			t.Fatal("published without its rename")
		}
		if info, err := os.Lstat(c.CCDir); err != nil || !info.IsDir() {
			t.Fatalf("the real folder is not back: %v", err)
		}
		if b, _ := os.ReadFile(filepath.Join(c.CCDir, "US_v4.txt")); string(b) != "198.51.100.0/24\n" {
			t.Errorf("US_v4.txt = %q", b)
		}
		assertBeside(t, c)
	})
}

// A publication removes what earlier interrupted ones left by the names they use: stale generations and their links,
// and the cc.new.* and cc.old.* folders of today's PHP publication (#4131). Any other name stays.
func TestStaleSiblingsAreRemovedByName(t *testing.T) {
	c, log := conversionRoot(t, testBlocks)
	parent := filepath.Dir(c.CCDir)
	stale := []string{".cc.7.0badcafe", "cc.new.7.0badcafe", "cc.old.7.0badcafe"}
	kept := []string{"cc.backup", ".cc.notes", "cc.new.x", ".cc.7.0BADCAFE", "cc.old.7.0badcafe.d", "cc.old.x.0badcafe",
		".cc.7.0badcafe0"}
	for _, name := range append(append([]string{}, stale...), kept...) {
		if err := os.MkdirAll(filepath.Join(parent, name, "inside"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(".cc.7.0badcafe", filepath.Join(parent, ".cc.7.0badcafe.link")); err != nil {
		t.Fatal(err)
	}
	if !c.Run(context.Background()) {
		t.Fatalf("conversion failed:\n%s", log)
	}
	assertBeside(t, c, append([]string{previousGeneration, current(t, c)}, kept...)...)
}

// A forged "# ISO Code: *" header removes nothing: today's PHP hands it to unlink_if_exists(), which globs, and loses
// almost every staged list while still succeeding (#4127).
func TestAForgedGlobHeaderRemovesNothing(t *testing.T) {
	c, log := conversionRoot(t, testBlocks+"\"4.0.0.0/8\n# ISO Code: *\",6252001,6252001,,0,0,\n")
	if !c.Run(context.Background()) {
		t.Fatalf("conversion failed:\n%s", log)
	}
	for _, name := range []string{"Africa_v4.txt", "Asia_v4.txt", "US_v4.txt", "CN_v6.txt", "AD_v4.txt"} {
		if _, err := os.Stat(filepath.Join(c.CCDir, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A MaxMind CSV path that is a directory reads as a failed read: nothing is converted. Today's PHP opens it, reads
// nothing, and publishes a generation without MaxMind's data.
func TestADirectoryForACSVConvertsNothing(t *testing.T) {
	for _, name := range []string{"GeoLite2-Country-Locations-en.csv", "GeoLite2-Country-Blocks-IPv4.csv"} {
		t.Run(name, func(t *testing.T) {
			c, _ := conversionRoot(t, testBlocks)
			path := filepath.Join(c.Share, name)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			if c.Run(context.Background()) {
				t.Fatal("converted from a directory")
			}
			assertPrevious(t, c)
		})
	}
}

// A generation is created and filled only under the publication lock beside the link, so another publication's cleanup
// never meets one half written: held there, a publication creates nothing and gives up when its context ends.
func TestAGenerationIsWrittenUnderTheLockBesideTheLink(t *testing.T) {
	c, _ := conversionRoot(t, testBlocks)
	held, err := os.OpenFile(filepath.Join(filepath.Dir(c.CCDir), ".cc.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c.publish(ctx, stage{"US_v4.txt": []byte("3.0.0.0/15\n")}) {
		t.Fatal("published under a reader's lock")
	}
	assertPrevious(t, c)
}

// A country folder that is missing (a run killed while setting a real folder aside) leaves no previous generation to
// tell apart, so a publication removes no generation: the folder set aside may hold the only copy of the old lists.
func TestAMissingCountryFolderKeepsEveryGeneration(t *testing.T) {
	c, log := conversionRoot(t, testBlocks)
	if err := os.Remove(c.CCDir); err != nil {
		t.Fatal(err)
	}
	if !c.Run(context.Background()) {
		t.Fatalf("conversion failed:\n%s", log)
	}
	assertBeside(t, c, previousGeneration, current(t, c))
}

// Concurrent conversions each link a whole generation: one publication's cleanup never removes part of another's
// generation while it is being written.
func TestConcurrentConversionsLinkWholeGenerations(t *testing.T) {
	c, log := conversionRoot(t, testBlocks)
	if !c.Run(context.Background()) {
		t.Fatalf("conversion failed:\n%s", log)
	}
	entries, err := os.ReadDir(c.CCDir)
	if err != nil {
		t.Fatal(err)
	}
	whole := len(entries)
	var mu sync.Mutex
	var partial []int
	rename = func(from, to string) error {
		to2, _ := os.Readlink(from)
		if got, _ := os.ReadDir(filepath.Join(filepath.Dir(from), to2)); len(got) != whole {
			mu.Lock()
			partial = append(partial, len(got))
			mu.Unlock()
		}
		return os.Rename(from, to)
	}
	defer func() { rename = os.Rename }()
	var wg sync.WaitGroup
	var published atomic.Int32
	for range 4 {
		wg.Add(1)
		run := c
		run.Log = io.Discard // each run its own writer
		go func() {
			defer wg.Done()
			for range 8 {
				if run.Run(context.Background()) {
					published.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if n := published.Load(); n != 32 {
		t.Errorf("%d of 32 concurrent conversions published", n)
	}
	if len(partial) != 0 {
		t.Errorf("%d generations linked with fewer than %d files: %v", len(partial), whole, partial)
	}
	if got, _ := os.ReadDir(c.CCDir); len(got) != whole {
		t.Errorf("the live generation holds %d files, want %d", len(got), whole)
	}
}

// A country folder named with a trailing slash is the same folder: the generations and the lock go beside it, not into
// the live generation.
func TestATrailingSlashOnTheCountryFolderPublishesBesideIt(t *testing.T) {
	c, log := conversionRoot(t, testBlocks)
	c.CCDir += "/"
	if !c.Run(context.Background()) {
		t.Fatalf("conversion failed:\n%s", log)
	}
	c.CCDir = filepath.Clean(c.CCDir)
	assertBeside(t, c, previousGeneration, current(t, c))
	if _, err := os.Stat(filepath.Join(filepath.Dir(c.CCDir), previousGeneration, ".cc.lock")); err == nil {
		t.Error("a lock inside the previous generation")
	}
}

// A link to the previous generation spelt as a path (absolute, or with a ./ prefix) still names it: the cleanup keeps it.
func TestAPreviousGenerationLinkedByPathIsKept(t *testing.T) {
	for _, spelling := range []string{"abs", "./"} {
		t.Run(spelling, func(t *testing.T) {
			c, log := conversionRoot(t, testBlocks)
			to := "./" + previousGeneration
			if spelling == "abs" {
				to = filepath.Join(filepath.Dir(c.CCDir), previousGeneration)
			}
			if err := os.Remove(c.CCDir); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(to, c.CCDir); err != nil {
				t.Fatal(err)
			}
			if !c.Run(context.Background()) {
				t.Fatalf("conversion failed:\n%s", log)
			}
			assertBeside(t, c, previousGeneration, current(t, c))
		})
	}
}

// A generation that cannot be written whole is removed: the previous generation stays live and nothing is left beside
// it.
func TestAGenerationThatCannotBeWrittenIsRemoved(t *testing.T) {
	c, _ := conversionRoot(t, testBlocks)
	if c.publish(context.Background(), stage{"US_v4.txt": []byte("3.0.0.0/15\n"), "missing/US_v6.txt": nil}) {
		t.Fatal("published a generation that could not be written")
	}
	assertPrevious(t, c)
}

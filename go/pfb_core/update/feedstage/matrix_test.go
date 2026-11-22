package feedstage

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// matrixEnv carries a matrixCall to the child process, this test binary re-run for TestKillAtEveryFileOperation.
const matrixEnv = "PFB_FEEDSTAGE_MATRIX"

// matrixScenario is a feed kind (ip, dnsbl or custom) and a variant: none, post (a post-script that rewrites its file),
// parse or both (the force of the killed run), or legacy (no script, no force, a baseline with only the legacy .orig.md5).
type matrixScenario struct {
	Kind, Variant string
}

func (sc matrixScenario) name() string { return sc.Kind + "-" + sc.Variant }

func (sc matrixScenario) force() string {
	if sc.Variant == "parse" || sc.Variant == "both" {
		return sc.Variant
	}
	return "none"
}

// contents are the source the baseline was published from and the source of the killed run.
func (sc matrixScenario) contents() (old, changed string) {
	if sc.Kind == "dnsbl" {
		return "old.example\n198.51.100.1\n2001:db8::1\n", "new.example\n198.51.100.2\n2001:db8::2\n"
	}
	return "198.51.100.1\n", "198.51.100.2\n"
}

func (sc matrixScenario) lists() []string {
	if sc.Kind == "dnsbl" {
		return []string{"Feed.parsed.ndjson", "Feed.parsed.v4.ip", "Feed.parsed.v6.ip"}
	}
	return []string{"Feed_v4.parsed.ip"}
}

// matrixStage is the stage and feed both sides use over the folders below root. The source is root/db/feed.txt, which a
// custom feed takes as its text.
func matrixStage(root string, sc matrixScenario) (*Stage, Feed) {
	stage, feed := killStage(root)
	switch sc.Kind {
	case "dnsbl":
		feed.ID, feed.Kind, feed.Name = "dnsbl:Feed", "dnsbl", "Feed"
		stage.Config.DNSBLIP = true
	case "custom":
		text, _ := os.ReadFile(filepath.Join(root, "db", "feed.txt"))
		feed.ID, feed.Custom, feed.CustomText, feed.Source = "custom:ipv4:Feed_v4", true, string(text), ""
	}
	if sc.Variant == "post" {
		feed.PostScript = "post.sh"
	}
	return stage, feed
}

// matrixRoot makes fresh folders for sc with the baseline published from the old source and the changed source in place.
func matrixRoot(t *testing.T, sc matrixScenario) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"orig", "db", "scripts"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if sc.Variant == "post" {
		killScript(t, root, "post.sh", `printf '10.9.9.9\n' > "$1"`)
	}
	old, changed := sc.contents()
	writeFile(t, filepath.Join(root, "db", "feed.txt"), old)
	stage, feed := matrixStage(root, sc)
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the baseline run of %s = %+v", sc.name(), r)
	}
	if sc.Variant == "legacy" {
		dir := filepath.Join(root, "orig")
		sum := md5.Sum([]byte(readFile(t, filepath.Join(dir, feed.Name+".orig"))))
		writeFile(t, filepath.Join(dir, feed.Name+".orig.md5"), hex.EncodeToString(sum[:]))
		if err := os.Remove(filepath.Join(dir, feed.Name+".orig.xxhash128")); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(root, "db", "feed.txt"), changed)
	return root
}

// readLists reads the parsed lists of sc in the feed folder dir; a missing one reads as "<missing>".
func readLists(dir string, sc matrixScenario) map[string]string {
	got := map[string]string{}
	for _, name := range sc.lists() {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			got[name] = "<missing>"
			continue
		}
		got[name] = string(data)
	}
	return got
}

// matrixOracle is what each source parses to for sc, published by a run in fresh folders.
func matrixOracle(t *testing.T, sc matrixScenario) map[string]map[string]string {
	t.Helper()
	oracle := map[string]map[string]string{}
	old, changed := sc.contents()
	for _, content := range []string{old, changed} {
		root := t.TempDir()
		for _, d := range []string{"orig", "db", "scripts"} {
			if err := os.Mkdir(filepath.Join(root, d), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		writeFile(t, filepath.Join(root, "db", "feed.txt"), content)
		stage, feed := matrixStage(root, sc)
		if r := run(stage, feed, "none"); r.Disposition != "changed" {
			t.Fatalf("the oracle run of %s = %+v", sc.name(), r)
		}
		oracle[content] = readLists(filepath.Join(root, "orig"), sc)
	}
	return oracle
}

// matrixCall is one child: Mode run (the scenario's run of its changed source) or recover (Recover on its feed folder),
// stopped by a KILL at its file operation KillAt (counted from 1; 0 never stops).
type matrixCall struct {
	Mode     string
	KillAt   int
	Root     string
	Scenario matrixScenario
}

// matrixChild runs the call in the child: at the operation it announces "ready <op>" on fd 3, with " after COMMIT" once
// the run's COMMIT stands, and waits on stdin for the KILL; a call that ends first announces "done <operations>". It never
// returns.
func matrixChild(spec string) {
	var c matrixCall
	if err := json.Unmarshal([]byte(spec), &c); err != nil {
		os.Exit(4)
	}
	event := os.NewFile(3, "event")
	count, phase := 0, ""
	step = func(name string) {
		if name == "committed" { // COMMIT stands: from here the run rolls forward
			phase = " after COMMIT"
		}
		if !strings.HasPrefix(name, "op:") {
			return
		}
		count++
		if count != c.KillAt {
			return
		}
		fmt.Fprintf(event, "ready %s%s\n", name, phase)
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(3) // the parent went away without the KILL
	}
	if c.Mode == "recover" {
		_ = Recover(filepath.Join(c.Root, "orig"))
	} else {
		stage, feed := matrixStage(c.Root, c.Scenario)
		run(stage, feed, c.Scenario.force())
	}
	fmt.Fprintf(event, "done %d\n", count)
	os.Exit(0)
}

// runMatrixCall runs c in a child process and KILLs it at its operation. It returns the name of the operation it was
// killed at, or "" and the number of operations of a call that ended first.
func runMatrixCall(t *testing.T, c matrixCall) (killedAt string, ops int) {
	t.Helper()
	spec, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
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
	// The cap only fails a hung child: on expiry it is killed, which ends the read below with EOF.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestKillAtEveryFileOperation$", "-test.count=1")
	child.Env = append(os.Environ(), matrixEnv+"="+string(spec))
	child.ExtraFiles = []*os.File{eventWriter}
	child.Stdin = hold
	child.Stdout, child.Stderr = os.Stderr, os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	eventWriter.Close()
	hold.Close()
	line, err := bufio.NewReader(events).ReadString('\n')
	if err != nil {
		werr := child.Wait()
		t.Fatalf("the %s child (operation %d) announced nothing: %v (child: %v)", c.Mode, c.KillAt, err, werr)
	}
	word, rest, _ := strings.Cut(strings.TrimSpace(line), " ")
	if word == "ready" {
		if err := child.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		_ = child.Wait()
		return rest, 0
	}
	if err := child.Wait(); err != nil || word != "done" {
		t.Fatalf("the %s child announced %q and ended with %v", c.Mode, line, err)
	}
	ops, err = strconv.Atoi(rest)
	if err != nil {
		t.Fatal(err)
	}
	return "", ops
}

// copyRoot copies the folders below src to a fresh root, keeping each file's mode and modification time, the subfolders a
// run leaves in the feed folder, and the hard links between the files of a folder and its subfolders: a KILL leaves a run
// folder whose files are linked to the published ones, and a Recover over the copy must take the steps it takes over the
// KILLed folders.
func copyRoot(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	for _, d := range []string{"orig", "db", "scripts"} {
		copied := map[string]os.FileInfo{} // each copy, by the source it was copied from
		err := filepath.WalkDir(filepath.Join(src, d), func(from string, e fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(src, from)
			if err != nil {
				return err
			}
			to := filepath.Join(dst, rel)
			info, err := e.Info()
			if err != nil {
				return err
			}
			switch {
			case e.IsDir():
				return os.Mkdir(to, 0o700)
			case !info.Mode().IsRegular():
				return fmt.Errorf("%s is left a %v", from, info.Mode().Type())
			}
			for made, source := range copied {
				if os.SameFile(source, info) {
					return os.Link(made, to)
				}
			}
			copied[to] = info
			data, err := os.ReadFile(from)
			if err != nil {
				return err
			}
			if err := os.WriteFile(to, data, info.Mode().Perm()); err != nil {
				return err
			}
			return os.Chtimes(to, info.ModTime(), info.ModTime())
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// publishedState is the name, mode and content of each file in the feed folder dir, a run folder left out: what readers of
// the feed folder see.
func publishedState(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	state := map[string]string{}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".pfbrun-") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() {
			state[e.Name()] = info.Mode().String()
			continue
		}
		state[e.Name()] = info.Mode().String() + " " + readFile(t, filepath.Join(dir, e.Name()))
	}
	return state
}

// committed reports whether a run folder in the feed folder dir holds its COMMIT, which Recover finishes.
func committed(dir string) bool {
	found, _ := filepath.Glob(filepath.Join(dir, ".pfbrun-*", "COMMIT"))
	return len(found) > 0
}

// runLeftovers fails for any run folder, staged file or temporary left in the feed folder.
func runLeftovers(t *testing.T, dir, when string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".pfb") || strings.HasSuffix(e.Name(), ".orig.post") || strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("%s: %s is left", when, e.Name())
		}
	}
}

// followUps runs the stage over the recovered folders of root once with the changed source and once with the source back
// at the old content, each on its own copy, through stage 6: the published lists must be what that source parses to.
func followUps(t *testing.T, root string, sc matrixScenario, oracle map[string]map[string]string, where string) {
	t.Helper()
	runLeftovers(t, filepath.Join(root, "orig"), where+", after Recover")
	old, changed := sc.contents()
	for _, content := range []string{changed, old} {
		copied := copyRoot(t, root)
		dir := filepath.Join(copied, "orig")
		writeFile(t, filepath.Join(copied, "db", "feed.txt"), content)
		stage, feed := matrixStage(copied, sc)
		before := readLists(dir, sc)
		r := run(stage, feed, "none")
		got, want := readLists(dir, sc), oracle[content]
		if r.Disposition == "failed" {
			t.Errorf("%s, source %q: the next run = %+v, want it to publish the source", where, content, r)
			want = before
		}
		for _, name := range sc.lists() {
			if got[name] != want[name] {
				t.Errorf("%s, source %q: the next run (%s) left %s = %q, want %q (the lists before it: %q)", where, content,
					r.Disposition, name, got[name], want[name], before)
			}
		}
		runLeftovers(t, dir, where+", after the next run")
	}
}

// Scenario: an Update is killed at any file operation of a feed, and its recovery is killed too.
// Given a published baseline and a changed source, for each kind (IP, DNSBL with v4, v6 and rows, custom list) and each
// variant (no script, a post-script that rewrites its file, force parse, force both, a legacy digest), when the run is
// KILLed before each of its file operations, then until its run folder holds COMMIT the feed folder is the baseline byte
// for byte: no published file is new, changed or gone. When the folder is then recovered (for one variant per kind,
// Recover itself KILLed before each of its operations and run again), and the stage run again with the changed source and
// with the old one, then the published lists are always what that source parses to: never a list of the other download,
// as unchanged or reparsed; and no run folder, staged file or temporary is left. A Recover KILLed and run again must leave
// the folder an uninterrupted Recover leaves, so the next runs checked on that folder hold for it as well.
//
// The KILL points are the stage's own file operations (the op: steps of rename, remove, link, create, mkdir and
// truncate). feedfetch's transfer and whois, and feedparse's NormalizeFile and post-scripts, call os directly and are no
// KILL point here: they write only in the run folder, which a KILL before COMMIT leaves to be deleted, and never through a
// file the run folder shares with the feed folder.
func TestKillAtEveryFileOperation(t *testing.T) {
	if spec := os.Getenv(matrixEnv); spec != "" {
		matrixChild(spec)
	}
	var scenarios []matrixScenario
	for _, kind := range []string{"ip", "dnsbl", "custom"} {
		for _, variant := range []string{"none", "post", "parse", "both"} {
			scenarios = append(scenarios, matrixScenario{kind, variant})
		}
	}
	scenarios = append(scenarios, matrixScenario{"ip", "legacy"}, matrixScenario{"dnsbl", "legacy"})
	for _, sc := range scenarios {
		oracle := matrixOracle(t, sc)
		// The count of the run's operations, from a run that is never stopped; that run is checked as well.
		root := matrixRoot(t, sc)
		_, total := runMatrixCall(t, matrixCall{Mode: "run", Root: root, Scenario: sc})
		if total == 0 {
			t.Fatalf("%s: the run performed no file operation", sc.name())
		}
		if err := Recover(filepath.Join(root, "orig")); err != nil {
			t.Fatalf("%s: Recover after a whole run: %v", sc.name(), err)
		}
		followUps(t, root, sc, oracle, sc.name()+" without a KILL")
		for n := 1; n <= total; n++ {
			t.Run(fmt.Sprintf("%s/op%03d", sc.name(), n), func(t *testing.T) {
				t.Parallel()
				root := matrixRoot(t, sc)
				baseline := publishedState(t, filepath.Join(root, "orig"))
				op, _ := runMatrixCall(t, matrixCall{Mode: "run", KillAt: n, Root: root, Scenario: sc})
				if op == "" {
					t.Fatalf("the run ended before its operation %d of %d", n, total)
				}
				where := fmt.Sprintf("%s KILLed at operation %d (%s)", sc.name(), n, op)
				if dir := filepath.Join(root, "orig"); !strings.HasSuffix(op, " after COMMIT") {
					if got := publishedState(t, dir); !reflect.DeepEqual(got, baseline) {
						t.Errorf("%s, before COMMIT: the feed folder is\n %q\nwant the baseline\n %q", where, got, baseline)
					}
				}
				killed := root
				if sc.Variant == "none" {
					killed = copyRoot(t, root)
				}
				if err := Recover(filepath.Join(root, "orig")); err != nil {
					t.Fatalf("%s: Recover: %v", where, err)
				}
				followUps(t, root, sc, oracle, where)
				if sc.Variant == "none" {
					killRecoverAtEveryOperation(t, killed, folderState(t, filepath.Join(root, "orig")), where)
				}
			})
		}
	}
}

// folderState is the name, mode and content of each file in dir.
func folderState(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	state := map[string]string{}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		state[e.Name()] = info.Mode().String() + " " + readFile(t, filepath.Join(dir, e.Name()))
	}
	return state
}

// killRecoverAtEveryOperation KILLs Recover over a copy of the killed folders before each of its operations and runs it
// again whole: the folder must be the one an uninterrupted Recover leaves (recovered), whose next runs followUps checked.
func killRecoverAtEveryOperation(t *testing.T, killed string, recovered map[string]string, where string) {
	t.Helper()
	_, total := runMatrixCall(t, matrixCall{Mode: "recover", Root: copyRoot(t, killed)})
	for m := 1; m <= total; m++ {
		copied := copyRoot(t, killed)
		op, _ := runMatrixCall(t, matrixCall{Mode: "recover", KillAt: m, Root: copied})
		if op == "" {
			t.Fatalf("%s: Recover ended before its operation %d of %d", where, m, total)
		}
		dir := filepath.Join(copied, "orig")
		if err := Recover(dir); err != nil {
			t.Fatalf("%s, Recover KILLed at operation %d (%s): Recover again: %v", where, m, op, err)
		}
		if got := folderState(t, dir); !reflect.DeepEqual(got, recovered) {
			t.Errorf("%s, Recover KILLed at operation %d (%s) and run again left\n %q\nwant what Recover leaves whole\n %q",
				where, m, op, got, recovered)
		}
	}
}

package feedstage

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Scenario: a COMMIT is cut short, names a file twice, or removes what it may not.
// Given a run folder whose COMMIT names a file twice, removes a file it also renames, ends without its last line feed,
// removes a published list (only a file the run is seeded with may be removed), or names a bare suffix without the feed's
// stem, when Recover reads it, then Recover fails and touches nothing: the feed folder and COMMIT stay as they were.
func TestRecoverRefusesACommitThatIsNoWholeListOfDistinctNames(t *testing.T) {
	for _, commit := range []string{
		"rename a_v4.orig\nrename a_v4.orig\n",
		"remove a_v4.orig\nrename a_v4.orig\n",
		"rename a_v4.orig\nremove a_v4.orig\n",
		"rename a_v4.orig",
		"remove a_v4.parsed.ip\n",
		"rename .orig\n",
	} {
		dir := t.TempDir()
		published := map[string]string{"a_v4.orig": "download of a\n", "a_v4.parsed.ip": "list of a\n"}
		for name, body := range published {
			writeFile(t, filepath.Join(dir, name), body)
		}
		run := runFolder(t, dir, "a_v4", commit, map[string]string{"a_v4.orig": "new download of a\n", ".orig": "stray\n"})
		if err := Recover(dir); err == nil {
			t.Errorf("COMMIT %q: Recover succeeded, want it refused", commit)
		}
		want := map[string]string{"a_v4.orig": "-rw------- download of a\n", "a_v4.parsed.ip": "-rw------- list of a\n"}
		if got := publishedState(t, dir); !reflect.DeepEqual(got, want) {
			t.Errorf("COMMIT %q: the feed folder is %q, want %q untouched", commit, got, want)
		}
		if got, err := os.ReadFile(filepath.Join(run, "COMMIT")); err != nil || string(got) != commit {
			t.Errorf("COMMIT %q: Recover changed it to %q (%v)", commit, got, err)
		}
	}
}

package main

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The feed phase's flags (issue #3975): Core is told the folders a file:// feed may sit in, the folders of the list scripts, the
// rsync program and the user agent, as it is told every path: by a flag. Core refuses what it could not use safely at start.

func parseFeedFlags(args ...string) (*feedFlags, string, error) {
	var out bytes.Buffer
	fl := flag.NewFlagSet("pfb-core", flag.ContinueOnError)
	fl.SetOutput(&out)
	ff := addFeedFlags(fl)
	err := fl.Parse(args)
	return ff, out.String(), err
}

func TestTheFeedFlagsAreTakenAsGivenRepeatedOnesInOrder(t *testing.T) {
	ff, out, err := parseFeedFlags(
		"--feed-local-dir", "/data/one", "--script-dir", "/scripts/first", "--feed-local-dir", "/data/two",
		"--script-dir", "/scripts/second", "--rsync-bin", "/tools/rsync", "--user-agent", "an agent/1.0 (with spaces)")
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if !slices.Equal(ff.LocalDirs, []string{"/data/one", "/data/two"}) || !slices.Equal(ff.ScriptDirs, []string{"/scripts/first", "/scripts/second"}) {
		t.Errorf("local dirs %q, script dirs %q, want each in the order given", ff.LocalDirs, ff.ScriptDirs)
	}
	if ff.RsyncBin != "/tools/rsync" || ff.UserAgent != "an agent/1.0 (with spaces)" {
		t.Errorf("rsync %q, user agent %q, want them as given", ff.RsyncBin, ff.UserAgent)
	}
}

func TestTheFeedFlagsWithNoneGivenAreEmpty(t *testing.T) {
	ff, out, err := parseFeedFlags()
	if err != nil || len(ff.LocalDirs) != 0 || len(ff.ScriptDirs) != 0 || ff.RsyncBin != "" || ff.UserAgent != "" {
		t.Errorf("no flags gave %+v, %v %s, want nothing set", ff, err, out)
	}
}

// A folder is compared with the folder of a file's real path: a trailing slash or a dot segment must not make it match nothing.
func TestAFeedFolderIsCleaned(t *testing.T) {
	ff, out, err := parseFeedFlags("--feed-local-dir", "/data/one/", "--feed-local-dir", "/data//two/./sub/..", "--script-dir", "/scripts/")
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if !slices.Equal(ff.LocalDirs, []string{"/data/one", "/data/two"}) || !slices.Equal(ff.ScriptDirs, []string{"/scripts"}) {
		t.Errorf("local dirs %q, script dirs %q, want them cleaned", ff.LocalDirs, ff.ScriptDirs)
	}
}

func TestAFeedPathThatIsNotAbsoluteIsRefusedNamingTheFlag(t *testing.T) {
	for _, flagName := range []string{"feed-local-dir", "script-dir", "rsync-bin"} {
		for _, value := range []string{"relative/dir", "./here", "../up", "", "~/home", "rsync"} {
			ff, out, err := parseFeedFlags("--"+flagName, value)
			if err == nil {
				t.Errorf("--%s %q was accepted as %+v, want a refusal", flagName, value, ff)
				continue
			}
			if !strings.Contains(out, flagName) || !strings.Contains(out, "absolute") {
				t.Errorf("--%s %q refused with %q, want the message to name the flag and say the path must be absolute", flagName, value, out)
			}
		}
	}
}

func TestAUserAgentWithAControlCharacterIsRefusedAndOtherTextIsNot(t *testing.T) {
	for name, value := range map[string]string{"CR LF": "agent\r\nX-Evil: 1", "LF": "agent\nX", "CR": "agent\rX", "NUL": "agent\x00X", "tab": "agent\tX", "DEL": "agent\x7fX", "ESC": "agent\x1b[0m"} {
		ff, out, err := parseFeedFlags("--user-agent", value)
		if err == nil {
			t.Errorf("a user agent with %s was accepted as %q, want a refusal", name, ff.UserAgent)
			continue
		}
		if !strings.Contains(out, "user-agent") || !strings.Contains(out, "control") {
			t.Errorf("a user agent with %s refused with %q, want the message to name the flag and the control character", name, out)
		}
	}
	for _, value := range []string{"pfSense/pfBlockerNG cURL download agent-0123456789abcdef", "agent é ü 日本", "x"} {
		if ff, out, err := parseFeedFlags("--user-agent", value); err != nil || ff.UserAgent != value {
			t.Errorf("--user-agent %q = %q, %v %s, want it accepted as given", value, ff.UserAgent, err, out)
		}
	}
}

// run refuses a bad feed flag as a usage error before it touches the state directory.
func TestRunRefusesABadFeedFlagWithAUsageErrorBeforeItStarts(t *testing.T) {
	for name, extra := range map[string][]string{
		"a relative local folder":  {"--feed-local-dir", "relative"},
		"a relative script folder": {"--script-dir", "scripts"},
		"a relative rsync":         {"--rsync-bin", "rsync"},
		"a user agent with CR LF":  {"--user-agent", "agent\r\nX-Evil: 1"},
	} {
		t.Run(name, func(t *testing.T) {
			stopped, cancel := context.WithCancel(context.Background())
			cancel()
			dir := scratchDir(t)
			var stderr bytes.Buffer
			args := coreArgs(dir, "run", extra...)
			if code := run(stopped, args, &stderr); code != 2 {
				t.Errorf("run %v = %d, want 2; stderr %q", extra, code, stderr.String())
			}
			if _, err := os.Stat(filepath.Join(dir, "state")); err == nil {
				t.Errorf("run %v made the state directory before it refused the flag", extra)
			}
			if !strings.Contains(stderr.String(), extra[0][2:]) {
				t.Errorf("run %v said %q, want it to name the flag", extra, stderr.String())
			}
		})
	}
}

func TestRunServesWithTheFeedFlagsGiven(t *testing.T) {
	stopped, cancel := context.WithCancel(context.Background())
	cancel()
	dir := scratchDir(t)
	var stderr bytes.Buffer
	args := coreArgs(dir, "run", "--feed-local-dir", "/data/one", "--feed-local-dir", "/data/two", "--script-dir", "/scripts/a", "--script-dir", "/scripts/b",
		"--rsync-bin", "/tools/rsync", "--user-agent", "an agent/1.0")
	if code := run(stopped, args, &stderr); code != 0 {
		t.Errorf("run with the feed flags = %d, want 0; stderr %q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "serving API") {
		t.Errorf("Core did not serve with the feed flags: %q", stderr.String())
	}
}

func TestUsageNamesTheFeedFlags(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(context.Background(), nil, &stderr); code != 2 {
		t.Fatalf("run without flags = %d, want 2", code)
	}
	for _, want := range []string{"--feed-local-dir PATH", "--script-dir PATH", "--rsync-bin PATH", "--user-agent STRING"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("the usage text does not name %s: %q", want, stderr.String())
		}
	}
}

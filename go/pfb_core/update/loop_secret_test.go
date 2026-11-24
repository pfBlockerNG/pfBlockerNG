package update

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoFileOfAnUpdateHoldsAFeedsCredentials runs one Update whose remote feeds carry credentials, one of them failing
// (404), and reads back every file the run wrote: the store's bodies and index, the feed and log folders, the main log,
// the Update log and its state files, the apply request. The feed server listens on 127.0.0.2: a feed on the box's own
// address (127.0.0.1) is read as a local one, without its credentials, as today. None holds the password or the userinfo in any form the run
// could write it in (raw, percent-encoded, or as the Basic authorization the feed server was sent) (issue #4038, 9j-2).
func TestNoFileOfAnUpdateHoldsAFeedsCredentials(t *testing.T) {
	const user, password = "e2e-feed-user", "Hunter2-Secret.9q"
	userinfo := user + ":" + password
	basic := base64.StdEncoding.EncodeToString([]byte(userinfo))
	c := e2eCaseNamed(t, "both_first_run_then_unchanged_then_changed")
	var snap bytes.Buffer
	if err := json.Compact(&snap, c.Expect[0].Snapshot); err != nil {
		t.Fatal(err)
	}
	withCreds := strings.ReplaceAll(snap.String(), `"credentials":""`, `"credentials":"`+userinfo+`"`)
	withCreds = strings.ReplaceAll(withCreds, `{{FEEDS}}/e2e1_v4b"`, `{{FEEDS}}/e2e1_missing"`)
	if strings.Count(withCreds, userinfo) != 4 || !strings.Contains(withCreds, "e2e1_missing") {
		t.Fatalf("the corpus snapshot no longer has four feeds with empty credentials and E2E1B: %s", snap.String())
	}
	c.Expect[0].Snapshot = json.RawMessage(withCreds)

	sb := newE2ESandbox(t, c, "127.0.0.2")
	sb.loop.LogDir = filepath.Join(sb.root, "var/log/pfblockerng") // the error and parse-error logs are written
	if err := sb.run(t, c, 0); err != nil {
		t.Fatalf("the Update: %v\n%s", err, logText(t, sb.log))
	}
	sb.mu.Lock()
	sent := strings.Join(sb.auth, "\n")
	sb.mu.Unlock()
	if !strings.Contains(sent, "Basic "+basic) {
		t.Fatalf("the run proves nothing: the feed server was not sent the credentials: %q", sent)
	}

	forms := []string{password, userinfo, strings.ReplaceAll(userinfo, ":", "%3A"), basic}
	scanned := map[string]bool{}
	for _, root := range []string{sb.root, sb.dir, filepath.Dir(sb.log.Name())} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			// reply is the settings adapter's answer this test wrote; the Update did not.
			if !d.Type().IsRegular() || path == filepath.Join(sb.dir, "reply") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			scanned[filepath.Base(path)] = true
			for _, form := range forms {
				if bytes.Contains(b, []byte(form)) {
					t.Errorf("%s holds the feed's credentials (%q)", path, form)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// The failed feed left its marker, and the apply request carries its failure as an issue.
	if !strings.Contains(readOr(t, filepath.Join(sb.dir, "requests")), "404") {
		t.Errorf("the apply request records no failed fetch of E2E1B: the failure path did not run:\n%s", readOr(t, filepath.Join(sb.dir, "requests")))
	}
	for _, name := range []string{"index.json", "pfblockerng.log", "error.log", "E2E1B_v4.fail", filepath.Base(sb.log.Name()),
		filepath.Base(sb.log.Name()) + ".status", filepath.Base(sb.log.Name()) + ".result", "requests"} {
		if !scanned[name] {
			t.Errorf("the scan never read %s: the run's files are not where the test looks", name)
		}
	}
}

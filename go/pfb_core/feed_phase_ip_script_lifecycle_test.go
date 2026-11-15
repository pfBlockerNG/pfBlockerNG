package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
)

type applyLifecycleCase struct {
	family string
	mode   string
	passes int
}

type applyLifecycleRequest struct {
	Phase string   `json:"phase"`
	Feeds []string `json:"feeds"`
	Force string   `json:"force"`
	Rows  []FeedPhaseResult
}

type applyLifecycleState struct {
	Artifacts map[string]string `json:"artifacts"`
	Ledger    []struct {
		Facility string `json:"facility"`
		Item     string `json:"item"`
		Stage    string `json:"stage"`
		Message  string `json:"message"`
	} `json:"ledger"`
	Outcomes map[string]string `json:"outcomes"`
	Log      string            `json:"log"`
}

type applyLifecycleObservation struct {
	root     string
	orig     string
	trace    string
	events   string
	requests []applyLifecycleRequest
	states   []applyLifecycleState
}

func TestFeedPhaseIPScriptLifecycleThroughPHPApply(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, row := range []struct {
			mode  string
			trace string
			pass  int
		}{
			{"same-group", "pre1\npost1\npre2\npost2\n", 1},
			{"across-groups", "pre1\npost1\npre2\npost2\n", 1},
			{"script-free-tail", "post1\n", 1},
			{"pre-only", "pre1\npre2\n", 1},
			{"unchanged-pre-post", "pre1\npost1\n", 2},
			{"unchanged-post", "post1\n", 2},
			{"pre-failure", "pre1\n", 2},
			{"post-failure", "post1\n", 2},
		} {
			t.Run(family+"/"+row.mode, func(t *testing.T) {
				got := runApplyLifecycleBoundary(t, applyLifecycleCase{family, row.mode, row.pass})
				if got.trace != row.trace {
					t.Errorf("actual IP script order=%q, want %q", got.trace, row.trace)
				}
				suffix, current := "v4", "192.0.2.2\n"
				if family == "ipv6" {
					suffix, current = "v6", "2001:db8::2\n"
				}
				if row.pass == 1 {
					want := []string{family + ":one_" + suffix, family + ":two_" + suffix}
					if row.mode == "script-free-tail" {
						want = append(want, family+":three_"+suffix)
					}
					var order []string
					for _, request := range got.requests {
						if request.Phase != "ip" || len(request.Feeds) != 1 {
							t.Errorf("script-observable IP phase must be lazy for every feed: %+v", got.requests)
						}
						order = append(order, request.Feeds...)
					}
					if !reflect.DeepEqual(order, want) {
						t.Errorf("IP transport order=%v, want %v", order, want)
					}
					for _, id := range want[1:] {
						header := strings.TrimPrefix(id, family+":")
						parsed, err := os.ReadFile(filepath.Join(got.orig, header+".parsed.ip"))
						if err != nil || string(parsed) != current {
							t.Errorf("%s parsed=%q (%v), want predecessor-visible %q", id, parsed, err, current)
						}
						if got.states[0].Artifacts[header+".txt"] != current {
							t.Errorf("%s action=%q, want %q", id, got.states[0].Artifacts[header+".txt"], current)
						}
					}
				} else {
					if len(got.requests) != 2 || got.requests[1].Force != "parse" {
						t.Errorf("unchanged selected script requests=%+v, want two single-feed passes ending in local parse", got.requests)
					}
					orig, err := os.ReadFile(filepath.Join(got.orig, "one_"+suffix+".orig"))
					if err != nil || string(orig) != current {
						t.Errorf("original after script=%q (%v), want %q", orig, err, current)
					}
					for pass, state := range got.states {
						if state.Artifacts["one_"+suffix+".txt"] != current {
							t.Errorf("pass%d action=%q, want preserved %q", pass, state.Artifacts["one_"+suffix+".txt"], current)
						}
					}
					failed := strings.Contains(row.mode, "failure")
					var scriptEntries int
					for _, entry := range got.states[1].Ledger {
						if entry.Facility == "ip" && entry.Item == "pfB_First_"+suffix && entry.Stage == "script" {
							scriptEntries++
						}
					}
					if failed && scriptEntries != 1 {
						t.Errorf("failed script must retain exactly one real IP script-stage entry: %+v", got.states[1].Ledger)
					}
					if !failed && len(got.states[1].Ledger) != 0 {
						t.Errorf("successful unchanged scripts left a failure ledger: %+v", got.states[1].Ledger)
					}
					if row.mode == "pre-failure" && len(got.states[0].Ledger) != 0 {
						t.Errorf("pre-failure transition lacks clean successful before-state: %+v", got.states[0].Ledger)
					}
					if row.mode == "pre-failure" {
						if _, success := got.states[1].Outcomes[family+":one_"+suffix]; success {
							t.Errorf("failed pre-script emitted a successful refresh outcome: %+v", got.states[1].Outcomes)
						}
					}
				}
			})
		}
	}
}

func TestFeedPhaseIPSelectionValidatesBeforeASNPrerequisite(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, mode := range []string{"invalid-duplicate", "invalid-late-force", "valid-asn-control"} {
			t.Run(family+"/"+mode, func(t *testing.T) {
				got := runApplyLifecycleBoundary(t, applyLifecycleCase{family, mode, 1})
				if mode == "valid-asn-control" {
					if !strings.HasPrefix(got.events, "reentry|asn_shell|scheduled\nphase|") || len(got.requests) == 0 {
						t.Fatalf("valid selection must actually reach recorded ASN prerequisite BEFORE Core transport: events=%q requests=%+v", got.events, got.requests)
					}
					// The recorder returns failure and supplies no CSV; no successful ASN expansion is claimed.
					return
				}
				if len(got.requests) != 0 || got.trace != "" || got.events != "" {
					t.Errorf("known-invalid complete selection performed work: requests=%+v scripts=%q side-effects=%q", got.requests, got.trace, got.events)
				}
				if _, err := os.Stat(filepath.Join(got.root, "geoip", "asn.csv")); !os.IsNotExist(err) {
					t.Errorf("invalid phase created ASN prerequisite output: %v", err)
				}
			})
		}
	}
}

func TestFeedPhaseDNSBLFinalPublicationRollbackThroughRealPostScript(t *testing.T) {
	for _, mode := range []string{"txt-refusal", "restore-refusal"} {
		t.Run(mode, func(t *testing.T) {
			got := runApplyLifecycleBoundary(t, applyLifecycleCase{"dnsbl", mode, 2})
			before, after := got.states[0], got.states[1]
			if _, err := os.Stat(filepath.Join(got.root, "obstruction-ready")); err != nil {
				t.Fatalf("fixture did not create the real private mount obstruction: %v; log=%s", err, after.Log)
			}
			if !strings.Contains(before.Artifacts["one.txt"], "kept.example") || before.Artifacts["one_v4.ip"] != "192.0.2.1\n" || before.Artifacts["one_v6.ip"] != "2001:db8::1\n" {
				t.Fatalf("successful old-generation before-state missing: %+v", before.Artifacts)
			}
			if before.Outcomes["dnsbl:one"] != "success" || len(before.Ledger) != 0 {
				t.Fatalf("initial publication did not settle cleanly: %+v", before)
			}
			if !strings.Contains(after.Artifacts["one.txt"], "kept.example") || strings.Contains(after.Artifacts["one.txt"], "recovered.example") {
				t.Errorf("refused TXT publication must keep readable last-good action: %q", after.Artifacts["one.txt"])
			}
			parsed, err := os.ReadFile(filepath.Join(got.orig, "one.parsed.ndjson"))
			if err != nil || !strings.Contains(string(parsed), "recovered.example") {
				t.Errorf("failure was not after a real new Core generation: parsed=%q (%v)", parsed, err)
			}
			for _, marker := range []string{"one.fail", "one.update"} {
				if _, exists := after.Artifacts[marker]; !exists {
					t.Errorf("failed final publication cleared %s: %+v", marker, after.Artifacts)
				}
			}
			if _, exists := after.Outcomes["dnsbl:one"]; exists {
				t.Errorf("refused final publication emitted success: %+v", after.Outcomes)
			}
			if len(after.Ledger) != 1 || after.Ledger[0].Stage != "download" || after.Ledger[0].Item != "DNSBL_First" {
				t.Errorf("refused publication must stay visible in real ledger: %+v", after.Ledger)
			}
			if _, exists := after.Artifacts["one.bk"]; exists {
				t.Errorf("failed final rename left mixed new staging instead of restoring absent old .bk: %+v", after.Artifacts)
			}
			if after.Artifacts["one_v6.ip"] != before.Artifacts["one_v6.ip"] {
				t.Errorf("IPv6 sidecar failed to restore: %q", after.Artifacts["one_v6.ip"])
			}
			if mode == "txt-refusal" {
				if after.Artifacts["one_v4.ip"] != before.Artifacts["one_v4.ip"] {
					t.Errorf("IPv4 sidecar failed to restore: %q", after.Artifacts["one_v4.ip"])
				}
			} else {
				if after.Artifacts["one_v4.ip"] != "192.0.2.2\n" {
					t.Errorf("restore-refusal witness did not retain the new committed IPv4 sidecar: %q", after.Artifacts["one_v4.ip"])
				}
				var backups []string
				for name, body := range after.Artifacts {
					if strings.HasPrefix(name, "one_v4.ip.restore.") && body == before.Artifacts["one_v4.ip"] {
						backups = append(backups, name)
					}
				}
				if len(backups) != 1 || !strings.Contains(after.Log, "rollback failed") {
					t.Errorf("refused rollback lost old restore artifact or visibility: backups=%v log=%s", backups, after.Log)
				}
			}
		})
	}
}

// The original PHP driver owns setup, warning policy, sync passes and teardown. Only fixture
// configuration and observations are adapted; no test-authored fetch/pre/parse/post ordering.
func runApplyLifecycleBoundary(t *testing.T, tc applyLifecycleCase) applyLifecycleObservation {
	t.Helper()
	root, err := os.MkdirTemp("", "pfb-boundary-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	local := filepath.Join(root, "local")
	scripts := filepath.Join(local, "pkg", "pfblockerng", "list_scripts")
	hooks := filepath.Join(local, "pkg", "pfblockerng", "hooks")
	orig := filepath.Join(root, "orig")
	for _, dir := range []string{
		scripts, hooks, orig, filepath.Join(root, "original-local"), filepath.Join(root, "action"),
		filepath.Join(root, "geoip"), filepath.Join(root, "dns-action"), filepath.Join(root, "dns-orig"),
	} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(name, []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "trace"), "")
	write(filepath.Join(root, "events"), "")
	suffix, current, previous := "v4", "192.0.2.2\n", "192.0.2.1\n"
	if tc.family == "ipv6" {
		suffix, current, previous = "v6", "2001:db8::2\n", "2001:db8::1\n"
	}
	write(filepath.Join(root, "first.txt"), current)
	write(filepath.Join(root, "derived.txt"), previous)
	pre := "#!/bin/sh\n[ \"$#\" -eq 2 ] && [ -f \"$1\" ] && [ \"$2\" = _" + suffix + " ] || exit 91\nif [ -s \"$LIFECYCLE_ROOT/trace\" ]; then n=2; else n=1; fi\nprintf 'pre%s\\n' \"$n\" >> \"$LIFECYCLE_ROOT/trace\"\n"
	post := "#!/bin/sh\n[ \"$#\" -eq 2 ] && [ -f \"$1\" ] && [ \"$2\" = _" + suffix + " ] || exit 92\ncase \"$1\" in */one_*.orig) n=1;; *) n=2;; esac\nprintf 'post%s\\n' \"$n\" >> \"$LIFECYCLE_ROOT/trace\"\n[ \"$n\" != 1 ] || printf '%s' '" + current + "' > \"$LIFECYCLE_ROOT/derived.txt\"\n"
	if tc.mode == "pre-only" {
		pre += "if [ \"$n\" = 2 ] && grep -q '" + strings.TrimSpace(current) + "' \"$LIFECYCLE_ROOT/action/one_" + suffix + ".txt\"; then printf '%s' '" + current + "' > \"$1\"; fi\n"
	}
	if tc.mode == "pre-failure" {
		pre += "if [ -f \"$LIFECYCLE_ROOT/fail-pre\" ]; then printf '%s' '" + previous + "' > \"$1\"; exit 7; fi\n"
		post += "touch \"$LIFECYCLE_ROOT/fail-pre\"\n"
	}
	if tc.mode == "post-failure" {
		post += "printf '%s' '" + previous + "' > \"$1\"\nexit 7\n"
	}
	if tc.family == "dnsbl" {
		write(filepath.Join(root, "first.txt"), "kept.example\n192.0.2.1\n2001:db8::1\n")
		write(filepath.Join(root, "next.txt"), "recovered.example\n192.0.2.2\n2001:db8::2\n")
		post = "#!/bin/sh\n[ \"$#\" -eq 2 ] && [ -f \"$1\" ] && [ \"$2\" = dnsbl ] || exit 92\nprintf 'post1\\n' >> \"$LIFECYCLE_ROOT/trace\"\nif [ -f \"$LIFECYCLE_ROOT/armed\" ]; then\n cp \"$LIFECYCLE_ROOT/action/one.txt\" \"$LIFECYCLE_ROOT/busy-txt\" || exit 93\n mount --bind \"$LIFECYCLE_ROOT/busy-txt\" \"$LIFECYCLE_ROOT/action/one.txt\" || exit 94\n"
		if tc.mode == "restore-refusal" {
			post += " cp \"$LIFECYCLE_ROOT/action/one_v4.ip\" \"$LIFECYCLE_ROOT/busy-v4\" || exit 95\n mount --bind \"$LIFECYCLE_ROOT/busy-v4\" \"$LIFECYCLE_ROOT/action/one_v4.ip\" || exit 96\n"
		}
		post += " touch \"$LIFECYCLE_ROOT/obstruction-ready\" || exit 97\nelse\n touch \"$LIFECYCLE_ROOT/armed\"\nfi\n"
	}
	write(filepath.Join(scripts, "ip_pre_boundary.sh"), pre)
	write(filepath.Join(scripts, "ip_post_boundary.sh"), post)
	write(filepath.Join(hooks, "hook_pre_lifecycle.sh"), "#!/bin/sh\nexit 0\n")
	write(filepath.Join(hooks, "hook_post_lifecycle.sh"), "#!/bin/sh\nexit 0\n")
	write(filepath.Join(root, "reentry.php"), "<?php file_put_contents(getenv('LIFECYCLE_ROOT') . '/events', 'reentry|' . implode('|', array_slice($argv, 1)) . \"\\n\", FILE_APPEND); exit(9);\n")
	row := func(header, file string) map[string]any {
		return map[string]any{"header": header, "state": "enabled", "format": "auto", "url": "file://" + filepath.Join(root, file)}
	}
	group := func(name string, feeds []any, hasPre, hasPost bool) map[string]any {
		action := "Alias_Native"
		if tc.family == "dnsbl" {
			action = "unbound"
		}
		g := map[string]any{"name": name, "action": action, "feeds": feeds}
		if hasPre {
			g["preScript"] = "ip_pre_boundary.sh"
		}
		if hasPost {
			g["postScript"] = "ip_post_boundary.sh"
		}
		return g
	}
	var groups []any
	switch tc.mode {
	case "same-group":
		groups = []any{group("First", []any{row("one", "first.txt"), row("two", "derived.txt")}, true, true)}
	case "across-groups":
		groups = []any{group("First", []any{row("one", "first.txt")}, true, true), group("Second", []any{row("two", "derived.txt")}, true, true)}
	case "script-free-tail":
		groups = []any{group("First", []any{row("one", "first.txt")}, false, true), group("Second", []any{row("two", "derived.txt"), row("three", "derived.txt")}, false, false)}
	case "pre-only":
		groups = []any{group("First", []any{row("one", "first.txt")}, true, false), group("Second", []any{row("two", "derived.txt")}, true, false)}
	case "unchanged-pre-post", "pre-failure":
		groups = []any{group("First", []any{row("one", "first.txt")}, true, true)}
	case "invalid-duplicate", "invalid-late-force", "valid-asn-control":
		asn := map[string]any{"header": "two", "state": "enabled", "format": "asn", "url": "AS64512"}
		groups = []any{group("First", []any{row("one", "first.txt")}, true, true), group("Second", []any{asn}, false, false)}
	default:
		groups = []any{group("First", []any{row("one", "first.txt")}, false, true)}
	}
	encoded, err := json.Marshal(groups)
	if err != nil {
		t.Fatal(err)
	}
	store, err := settings.Load(&feedPhaseTestBackend{stored: settings.Stored{
		Initialized: true, Revision: 1,
		Projections: map[string]map[string]json.RawMessage{
			"feeds/" + tc.family: {"groups": encoded},
			"ingest":             {"dnsblIp": json.RawMessage("true"), "suppression": json.RawMessage("false")},
		},
	}}, settings.Production())
	if err != nil {
		t.Fatal(err)
	}
	runner := feedPhaseTestRunner(t, tc.family, "enabled", "auto", "file://"+filepath.Join(root, "first.txt"), "")
	runner.store = store
	runner.flags.LocalDirs = []string{root}
	runner.flags.ScriptDirs = []string{scripts}
	runner.flags.OrigDir = orig
	runner.flags.DNSBLOrigDir = orig
	runner.flags.ASNCSV = filepath.Join(root, "geoip", "asn.csv")
	t.Setenv("LIFECYCLE_ROOT", root)
	var phpGroups []any
	var ids []string
	for _, item := range groups {
		g := item.(map[string]any)
		p := map[string]any{"aliasname": g["name"], "action": g["action"], "order": "default", "cron": "EveryDay"}
		if tc.family == "dnsbl" {
			p["logging"] = "disabled_log"
		} else {
			p["aliaslog"] = "enabled"
		}
		p["script_pre"], p["script_post"] = g["preScript"], g["postScript"]
		var feeds []any
		for _, item := range g["feeds"].([]any) {
			r := item.(map[string]any)
			feeds = append(feeds, map[string]any{"header": r["header"], "state": "Enabled", "format": r["format"], "url": r["url"]})
			id := tc.family + ":" + r["header"].(string)
			if tc.family != "dnsbl" {
				id += "_" + suffix
			}
			ids = append(ids, id)
		}
		if tc.mode == "invalid-duplicate" && g["name"] == "Second" {
			feeds = append(feeds, map[string]any{"header": "one", "state": "Enabled", "format": "auto", "url": "file://" + filepath.Join(root, "first.txt")})
		}
		p["row"] = feeds
		phpGroups = append(phpGroups, p)
	}
	config := map[string]any{"family": tc.family, "suffix": suffix, "mode": tc.mode, "ids": ids, "groups": phpGroups}
	rawConfig, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(root, "boundary.json"), string(rawConfig))
	// The frozen driver still reads groups.json; the checked adapter replaces only that setup statement.
	write(filepath.Join(root, "groups.json"), "[]")
	driver := feedLifecyclePHP
	replace := func(old, replacement string) {
		t.Helper()
		if strings.Count(driver, old) != 1 {
			t.Fatalf("shared PHP driver fixture anchor changed: %q", old)
		}
		driver = strings.Replace(driver, old, replacement, 1)
	}
	replace("    config_set_path('installedpackages/pfblockerngdnsbl/config', json_decode(file_get_contents($args[2] . '/groups.json'), TRUE, 512, JSON_THROW_ON_ERROR));", applyLifecycleFixturePHP)
	replace("            file_put_contents($args[2] . '/trace', '');", "            $GLOBALS['pfb']['scheduled_outcomes'] = [];\n"+applyLifecycleNextPassPHP+"\n            file_put_contents($args[2] . '/trace', '');")
	replace("            if (!sync_package_pfblockerng()) { throw new RuntimeException('actual sync returned false'); }", "            if (!sync_package_pfblockerng()) { throw new RuntimeException('actual sync returned false'); }\n"+applyLifecycleObservePHP)
	driver = "define('PFB_REENTRY_SCRIPT', getenv('LIFECYCLE_ROOT') . '/reentry.php');\n" + driver
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	listener, err := net.Listen("unix", filepath.Join(root, "core.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var requests []applyLifecycleRequest
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var params struct {
			Token string `json:"token"`
			applyLifecycleRequest
		}
		if request.URL.Path != "/v1/FeedPhase" || json.NewDecoder(request.Body).Decode(&params) != nil || params.Token != strings.Repeat("a", 64) {
			http.Error(w, "unexpected phase request", 400)
			return
		}
		file, err := os.OpenFile(filepath.Join(root, "events"), os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_, writeErr := fmt.Fprintln(file, "phase|"+strings.Join(params.Feeds, ","))
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			http.Error(w, "phase event could not be recorded", 500)
			return
		}
		rows, err := runner.run(ctx, params.Phase, params.Feeds, params.Force, nil)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		params.Rows = rows
		mu.Lock()
		requests = append(requests, params.applyLifecycleRequest)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"results": rows})
	})}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	defer func() { _ = server.Close(); <-served }()
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	php, err := exec.LookPath("php")
	if err != nil {
		t.Fatal(err)
	}
	beforeNS, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/usr/local/pkg/pfblockerng"); !os.IsNotExist(err) {
		t.Fatal("fixture requires absent host resolver target")
	}
	mountScript := `mount --make-rprivate /
mount --bind /usr/local "$1/original-local"
mount -o remount,bind,ro "$1/original-local"
mount --bind "$1/local" /usr/local
export PATH="$1/original-local/bin:$1/original-local/sbin:$PATH"
shift
exec "$@"`
	cmd := exec.CommandContext(ctx, "unshare", "-m", "sh", "-eu", "-c", mountScript, "sh", root, php, "-r", driver, repo, root, filepath.Join(root, "core.sock"), orig, fmt.Sprint(tc.passes))
	out, runErr := cmd.CombinedOutput()
	afterNS, nsErr := os.Readlink("/proc/self/ns/mnt")
	_, targetErr := os.Stat("/usr/local/pkg/pfblockerng")
	if nsErr != nil || beforeNS != afterNS || !os.IsNotExist(targetErr) {
		t.Fatalf("host namespace/target changed: before=%s after=%s ns=%v target=%v", beforeNS, afterNS, nsErr, targetErr)
	}
	t.Logf("parent namespace before/after=%s; host resolver target absent before/after", beforeNS)
	if runErr != nil {
		t.Fatalf("real PHP apply boundary failed: %v\n%s", runErr, out)
	}
	trace, err := os.ReadFile(filepath.Join(root, "trace"))
	if err != nil {
		t.Fatal(err)
	}
	events, err := os.ReadFile(filepath.Join(root, "events"))
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := applyLifecycleObservation{root: root, orig: orig, trace: string(trace), events: string(events), requests: append([]applyLifecycleRequest(nil), requests...)}
	mu.Unlock()
	for pass := range tc.passes {
		body, err := os.ReadFile(filepath.Join(root, fmt.Sprintf("state-%d.json", pass)))
		if err != nil {
			t.Fatal(err)
		}
		var state applyLifecycleState
		if err := json.Unmarshal(body, &state); err != nil {
			t.Fatal(err)
		}
		got.states = append(got.states, state)
	}
	return got
}

const applyLifecycleFixturePHP = `
    $boundary = json_decode(file_get_contents($args[2] . '/boundary.json'), TRUE, 512, JSON_THROW_ON_ERROR);
    config_set_path('installedpackages/pfblockerngdnsbl/config', []);
    $GLOBALS['pfb']['geoipshare'] = $args[2] . '/geoip';
    $GLOBALS['pfb']['scheduled_runtime_cron'] = TRUE;
    $GLOBALS['pfb']['scheduled_selected_ids'] = array_fill_keys($boundary['ids'], TRUE);
    if ($boundary['family'] === 'dnsbl') {
        config_set_path('installedpackages/pfblockerngdnsbl/config', $boundary['groups']);
        $GLOBALS['pfb']['feed_phase_scope'] = 'dnsbl';
    } else {
        $GLOBALS['pfb']['dnsdir'] = $args[2] . '/dns-action';
        $GLOBALS['pfb']['dnsorigdir'] = $args[2] . '/dns-orig';
        $GLOBALS['pfb']['origdir'] = $args[4];
        $GLOBALS['pfb']['nativedir'] = $args[2] . '/action';
        config_set_path('installedpackages/pfblockernglists' . $boundary['suffix'] . '/config', $boundary['groups']);
        $GLOBALS['pfb']['feed_phase_scope'] = 'ip';
    }
    if ($boundary['mode'] === 'invalid-late-force') {
        file_put_contents($args[2] . '/action/one_' . $boundary['suffix'] . '.txt', file_get_contents($args[2] . '/first.txt'));
        file_put_contents($args[4] . '/one_' . $boundary['suffix'] . '.orig', file_get_contents($args[2] . '/first.txt'));
        $GLOBALS['pfb']['feed_phase_force'] = 'invalid';
    }
`

const applyLifecycleNextPassPHP = `
            if ($i === 1 && $boundary['family'] === 'dnsbl') {
                if (!copy($args[2] . '/next.txt', $args[2] . '/first.txt')) { throw new RuntimeException('could not advance real local source'); }
                touch($args[2] . '/action/one.update');
            }
`

const applyLifecycleObservePHP = `
            $artifacts = [];
            foreach (glob($args[2] . '/action/*') ?: [] as $path) {
                $artifacts[basename($path)] = is_file($path) ? file_get_contents($path) : 'DIRECTORY';
            }
            $state = ['artifacts' => (object) $artifacts,
                'ledger' => pfb_sync_status_list_open($GLOBALS['pfb']['dbdir'], $boundary['family'] === 'dnsbl' ? 'dnsbl' : 'ip'),
                'outcomes' => (object) ($GLOBALS['pfb']['scheduled_outcomes'] ?? []),
                'log' => file_get_contents($GLOBALS['pfb']['log'])];
            file_put_contents($args[2] . '/state-' . $i . '.json', json_encode($state, JSON_THROW_ON_ERROR));
`

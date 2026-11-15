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

// This runs the actual PHP sync collector, resolver and post consumer against the real Go
// fetch/pre/parse runner; the test never chooses feed/post order.
func TestFeedPhaseScriptLifecycleThroughPHPApply(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      string
		passes    int
		wantTrace string
	}{
		{"pre and post in one group", "same-group", 1, "pre1\npost1\npre2\npost2\n"},
		{"pre and post across groups", "across-groups", 1, "pre1\npost1\npre2\npost2\n"},
		{"post with script-free successors", "script-free-tail", 1, "post1\n"},
		{"pre-only observes prior published action", "pre-only", 1, "pre1\npre2\n"},
		{"post-only unchanged local orig", "post-only-retry", 2, "post1\n"},
		{"post failure stays visible", "post-failure", 2, "post1\n"},
		{"global no-op hooks still run", "no-op-hooks", 2, ""},
		{"lazy selection validates duplicates before transport", "duplicate", 1, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, err := os.MkdirTemp("", "pfb-script-")
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
			for _, dir := range []string{scripts, hooks, filepath.Join(root, "original-local"), filepath.Join(root, "action")} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			write := func(path, body string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(root, "first.txt"), "current.example\n")
			write(filepath.Join(root, "derived.txt"), "previous.example\n")
			trace := filepath.Join(root, "trace")
			write(trace, "")
			// Go pre and PHP post retain the production staged-path, family and log arguments.
			pre := "#!/bin/sh\n[ \"$#\" -eq 2 ] && [ -f \"$1\" ] && [ \"$2\" = dnsbl ] || exit 91\nif [ -s \"$LIFECYCLE_ROOT/trace\" ]; then n=2; else n=1; fi\nprintf 'pre%s\\n' \"$n\" >> \"$LIFECYCLE_ROOT/trace\"\n"
			post := "#!/bin/sh\n[ \"$#\" -eq 2 ] && [ -f \"$1\" ] && [ \"$2\" = dnsbl ] || exit 92\ncase \"$1\" in */one.post) n=1;; *) n=2;; esac\nprintf 'post%s\\n' \"$n\" >> \"$LIFECYCLE_ROOT/trace\"\n[ \"$n\" != 1 ] || printf 'current.example\\n' > \"$LIFECYCLE_ROOT/derived.txt\"\n"
			if tc.mode == "pre-only" {
				pre += "if [ \"$n\" = 2 ] && grep -q current.example \"$LIFECYCLE_ROOT/action/one.txt\"; then printf 'current.example\\n' > \"$1\"; fi\n"
			}
			if tc.mode == "post-failure" {
				post += "exit 7\n"
			}
			write(filepath.Join(scripts, "dnsbl_pre_lifecycle.sh"), pre)
			write(filepath.Join(scripts, "dnsbl_post_lifecycle.sh"), post)
			write(filepath.Join(hooks, "hook_pre_lifecycle.sh"), "#!/bin/sh\nprintf 'pre\\n' >> \"$LIFECYCLE_ROOT/hooks.trace\"\n")
			write(filepath.Join(hooks, "hook_post_lifecycle.sh"), "#!/bin/sh\nprintf 'post|%s|%s|%s|%s\\n' \"${PFB_IP_CHANGED-unset}\" \"${PFB_DNSBL_CHANGED-unset}\" \"${PFB_CHANGED_IP_ALIASES-unset}\" \"${PFB_CHANGED_DNSBL_GROUPS-unset}\" >> \"$LIFECYCLE_ROOT/hooks.trace\"\n")

			row := func(header, source string) map[string]any {
				return map[string]any{"header": header, "state": "enabled", "format": "auto", "url": "file://" + filepath.Join(root, source)}
			}
			group := func(name string, rows []any, hasPre, hasPost bool) map[string]any {
				g := map[string]any{"name": name, "action": "unbound", "feeds": rows}
				if hasPre {
					g["preScript"] = "dnsbl_pre_lifecycle.sh"
				}
				if hasPost {
					g["postScript"] = "dnsbl_post_lifecycle.sh"
				}
				return g
			}
			var groups []any
			switch tc.mode {
			case "same-group", "duplicate":
				groups = []any{group("First", []any{row("one", "first.txt"), row("two", "derived.txt")}, true, true)}
			case "across-groups":
				groups = []any{group("First", []any{row("one", "first.txt")}, true, true), group("Second", []any{row("two", "derived.txt")}, true, true)}
			case "script-free-tail":
				groups = []any{group("First", []any{row("one", "first.txt")}, false, true), group("Second", []any{row("two", "derived.txt"), row("three", "derived.txt")}, false, false)}
			case "pre-only":
				groups = []any{group("First", []any{row("one", "first.txt")}, true, false), group("Second", []any{row("two", "derived.txt")}, true, false)}
			case "no-op-hooks":
				groups = []any{group("First", []any{row("one", "first.txt")}, false, false)}
			default:
				groups = []any{group("First", []any{row("one", "first.txt")}, false, true)}
			}
			raw, err := json.Marshal(groups)
			if err != nil {
				t.Fatal(err)
			}
			store, err := settings.Load(&feedPhaseTestBackend{stored: settings.Stored{
				Initialized: true, Revision: 1,
				Projections: map[string]map[string]json.RawMessage{"feeds/dnsbl": {"groups": raw}},
			}}, settings.Production())
			if err != nil {
				t.Fatal(err)
			}
			runner := feedPhaseTestRunner(t, "dnsbl", "enabled", "auto", "file://"+filepath.Join(root, "first.txt"), "")
			runner.store = store
			runner.flags.LocalDirs = []string{root}
			runner.flags.ScriptDirs = []string{scripts}
			t.Setenv("LIFECYCLE_ROOT", root)
			var phpGroups []any
			for _, item := range groups {
				g := item.(map[string]any)
				p := map[string]any{"aliasname": g["name"], "action": "unbound", "order": "default", "logging": "disabled_log"}
				p["script_pre"], p["script_post"] = g["preScript"], g["postScript"]
				var rows []any
				for _, item := range g["feeds"].([]any) {
					r := item.(map[string]any)
					rows = append(rows, map[string]any{"header": r["header"], "state": "Enabled", "format": r["format"], "url": r["url"]})
				}
				if tc.mode == "duplicate" {
					rows = append(rows, rows[0])
				}
				p["row"] = rows
				phpGroups = append(phpGroups, p)
			}
			fixture, err := json.Marshal(phpGroups)
			if err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(root, "groups.json"), string(fixture))

			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			socket := filepath.Join(root, "core.sock")
			listener, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var requests []struct {
				Feeds []string
				Force string
			}
			server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				var params struct {
					Token string   `json:"token"`
					Phase string   `json:"phase"`
					Feeds []string `json:"feeds"`
					Force string   `json:"force"`
				}
				if request.URL.Path != "/v1/FeedPhase" || json.NewDecoder(request.Body).Decode(&params) != nil || params.Token != strings.Repeat("a", 64) {
					http.Error(w, "unexpected phase request", 400)
					return
				}
				mu.Lock()
				requests = append(requests, struct {
					Feeds []string
					Force string
				}{params.Feeds, params.Force})
				mu.Unlock()
				results, err := runner.run(ctx, params.Phase, params.Feeds, params.Force, nil)
				if err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
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
			// The inherited BSD-unzip bind remains in place. All resolver-path changes are private,
			// propagation is disabled first, and the original /usr/local tools stay read-only.
			mountScript := `mount --make-rprivate /
mount --bind /usr/local "$1/original-local"
mount -o remount,bind,ro "$1/original-local"
mount --bind "$1/local" /usr/local
export PATH="$1/original-local/bin:$1/original-local/sbin:$PATH"
shift
exec "$@"`
			beforeNS, err := os.Readlink("/proc/self/ns/mnt")
			if err != nil {
				t.Fatal(err)
			}
			_, beforeTarget := os.Stat("/usr/local/pkg/pfblockerng")
			if !os.IsNotExist(beforeTarget) {
				t.Fatal("fixture requires absent host resolver target; refusing to shadow an existing installation")
			}
			cmd := exec.CommandContext(ctx, "unshare", "-m", "sh", "-eu", "-c", mountScript, "sh", root, php, "-r", feedLifecyclePHP, repo, root, socket, runner.flags.DNSBLOrigDir, fmt.Sprint(tc.passes))
			out, runErr := cmd.CombinedOutput()
			afterNS, nsErr := os.Readlink("/proc/self/ns/mnt")
			_, afterTarget := os.Stat("/usr/local/pkg/pfblockerng")
			if nsErr != nil || beforeNS != afterNS || !os.IsNotExist(afterTarget) {
				t.Fatalf("host mount state changed: before=%s after=%s error=%v target=%v", beforeNS, afterNS, nsErr, afterTarget)
			}
			t.Logf("parent namespace before/after=%s; host resolver target absent before/after", beforeNS)
			if runErr != nil {
				t.Fatalf("actual PHP sync failed: %v\n%s", runErr, out)
			}
			gotTrace, err := os.ReadFile(trace)
			if err != nil {
				t.Fatal(err)
			}
			if string(gotTrace) != tc.wantTrace {
				t.Errorf("script order=%q, want %q\nPHP: %s", gotTrace, tc.wantTrace, out)
			}
			mu.Lock()
			gotRequests := append([]struct {
				Feeds []string
				Force string
			}(nil), requests...)
			mu.Unlock()
			if tc.mode == "duplicate" {
				if len(gotRequests) != 0 {
					t.Fatalf("invalid complete selection partially executed: %+v", gotRequests)
				}
				return
			}
			if tc.passes == 2 {
				wantForce := "parse"
				if tc.mode == "no-op-hooks" {
					wantForce = "none"
				}
				if len(gotRequests) != 2 || gotRequests[1].Force != wantForce {
					t.Errorf("unchanged retry requests=%+v; want one request per pass, final force %s", gotRequests, wantForce)
				}
				orig, err := os.ReadFile(filepath.Join(runner.flags.DNSBLOrigDir, "one.orig"))
				if err != nil || string(orig) != "current.example\n" {
					t.Errorf("post mutated original: %q (%v)", orig, err)
				}
			} else {
				var order []string
				for _, request := range gotRequests {
					if len(request.Feeds) != 1 {
						t.Errorf("script-observable phase must dispatch lazily per feed: %+v", gotRequests)
						break
					}
					order = append(order, request.Feeds...)
				}
				want := []string{"dnsbl:one", "dnsbl:two"}
				if tc.mode == "script-free-tail" {
					want = append(want, "dnsbl:three")
				}
				if !reflect.DeepEqual(order, want) {
					t.Errorf("phase order=%v, want %v", order, want)
				}
				for _, id := range want[1:] {
					name := strings.TrimPrefix(id, "dnsbl:")
					parsed, err := os.ReadFile(filepath.Join(runner.flags.DNSBLOrigDir, name+".parsed.ndjson"))
					if err != nil || !strings.Contains(string(parsed), "current.example") || strings.Contains(string(parsed), "previous.example") {
						t.Errorf("%s parsed=%q (%v); must observe prior feed's completed PHP side effects", id, parsed, err)
					}
				}
			}
			if tc.mode == "post-failure" && !strings.Contains(string(out), "SCRIPT_FAILURE_OPEN") {
				t.Errorf("post exit 7 silently closed script ledger: %s", out)
			}
			if tc.mode == "post-only-retry" || tc.mode == "no-op-hooks" {
				hookTrace, err := os.ReadFile(filepath.Join(root, "hooks.trace"))
				if err != nil || string(hookTrace) != "pre\npost|0|0||\n" {
					t.Errorf("no-op must run global hooks once with unchanged context: got %q (%v)", hookTrace, err)
				}
			}
		})
	}
}

const feedLifecyclePHP = `
$args = $argv;
require $args[1] . '/vendor/autoload.php';
require $args[1] . '/tests/php/bootstrap.php';
require $args[1] . '/tests/php/DnsblVipApplyLifecycleTest.php';
$test = new DnsblVipApplyLifecycleTest('testSelectedScriptsReparseLocalOrigWithoutForcingDownload');
$call = static function (string $method, mixed ...$values) use ($test): mixed {
    return (new ReflectionMethod($test, $method))->invoke($test, ...$values);
};
$call('setUp');
try {
    $call('arrange', ['save' => FALSE]);
    $call('modelMountedModule');
    $call('publishTo', TRUE);
    $GLOBALS['pfb']['dnsdir'] = $args[2] . '/action';
    $GLOBALS['pfb']['dnsorigdir'] = $args[4];
    $GLOBALS['pfb']['core_socket'] = $args[3];
    $GLOBALS['pfb']['feed_phase_token'] = str_repeat('a', 64);
    $GLOBALS['pfb']['feed_phase_force'] = 'none';
    config_set_path('installedpackages/pfblockerngdnsbl/config', json_decode(file_get_contents($args[2] . '/groups.json'), TRUE, 512, JSON_THROW_ON_ERROR));
    config_set_path('installedpackages/pfblockerng/config/0/hooks/row', [
        ['enabled' => 'on', 'when' => 'pre', 'script' => 'hook_pre_lifecycle.sh'],
        ['enabled' => 'on', 'when' => 'post', 'script' => 'hook_post_lifecycle.sh'],
    ]);
    set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
        if ((error_reporting() & $severity) === 0) { return TRUE; }
        if ($severity === E_WARNING || $severity === E_USER_WARNING) {
            throw new ErrorException($message, 0, $severity, $file, $line);
        }
        return FALSE;
    });
    try {
        for ($i = 0; $i < (int) $args[5]; $i++) {
            file_put_contents($args[2] . '/trace', '');
            file_put_contents($args[2] . '/hooks.trace', '');
            if (!sync_package_pfblockerng()) { throw new RuntimeException('actual sync returned false'); }
        }
    } finally { restore_error_handler(); }
    foreach (pfb_sync_status_list_open($GLOBALS['pfb']['dbdir'], 'dnsbl') as $entry) {
        if ($entry['stage'] === 'script' && $entry['item'] === 'DNSBL_First'
            && str_contains($entry['message'], 'Post-script FAIL')) { echo "SCRIPT_FAILURE_OPEN\n"; }
    }
} finally { $call('tearDown'); }
`

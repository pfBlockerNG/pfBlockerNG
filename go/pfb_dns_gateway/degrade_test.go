package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider"
)

// issue #3848: pfB-DNS never fails to start. What the gateway can serve without, it serves without, and its control-socket
// status lists every part it serves without in `degraded`, in a fixed order, each part once.

// lostRow is one row of the status's degraded list.
type lostRow struct {
	Part   string `json:"part"`
	Reason string `json:"reason"`
}

// statusLost is the degraded list of the control socket's status, and the field as it was sent ("" when the status has none).
func statusLost(t *testing.T, sock string) (rows []lostRow, raw string) {
	t.Helper()
	wire := statusWire(t, sock, nil, -1)
	var got struct {
		Degraded json.RawMessage `json:"degraded"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSuffix(wire, "\nok\n")), &got); err != nil {
		t.Fatalf("status %q: %v", wire, err)
	}
	if got.Degraded == nil {
		return nil, ""
	}
	if err := json.Unmarshal(got.Degraded, &rows); err != nil {
		t.Fatalf("degraded %s: %v", got.Degraded, err)
	}
	return rows, string(got.Degraded)
}

func lostParts(rows []lostRow) []string {
	parts := []string{}
	for _, row := range rows {
		parts = append(parts, row.Part)
	}
	return parts
}

// requireLost fails unless the status lists exactly the parts in want, in that order, each reason holding the text with it.
func requireLost(t *testing.T, sock, when string, want map[string]string, order ...string) []lostRow {
	t.Helper()
	rows, _ := statusLost(t, sock)
	if got := lostParts(rows); !slices.Equal(got, append([]string{}, order...)) {
		t.Fatalf("%s: degraded parts %q, want %q; rows %+v", when, got, order, rows)
	}
	for _, row := range rows {
		if !strings.Contains(row.Reason, want[row.Part]) {
			t.Errorf("%s: reason of %s is %q, want it to hold %q", when, row.Part, row.Reason, want[row.Part])
		}
	}
	return rows
}

// validUnboundConf is a config Unbound's ACL loads, so that a test's ACL is not what it reports.
func validUnboundConf(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "unbound.conf")
	if err := os.WriteFile(path, []byte("server:\n\taccess-control: 127.0.0.0/8 allow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// healthyConfig is lifecycleConfig with a loadable Resolver config and a private control socket.
func healthyConfig(t *testing.T) (config, *capture, string) {
	t.Helper()
	cfg, logs := lifecycleConfig(t)
	cfg.unboundConf = validUnboundConf(t)
	cfg.ctlSocket = filepath.Join(shortTempDir(t), "run", "ctl.sock")
	return cfg, logs, cfg.ctlSocket
}

func echoOpen(decider.Options) (frontend, error) { return echoFrontend{}, nil }

// startFromFlags starts the gateway as the command line does it: parseConfig, validation included, then start. open nil boots
// the real decider.
func startFromFlags(t *testing.T, open func(decider.Options) (frontend, error), flags ...string) (*server, *capture, string) {
	t.Helper()
	_, logs, sock := healthyConfig(t)
	args := append([]string{"--listen", "127.0.0.1", "--port", "0", "--ctl-socket", sock, "--unbound-conf", validUnboundConf(t)}, flags...)
	cfg, err := parseConfig(args, io.Discard)
	if err != nil {
		t.Fatalf("parseConfig(%q) = %v, want the flags accepted", args, err)
	}
	cfg.open = open
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatalf("start(%q) = %v, want the gateway to serve; log:\n%s", flags, err, logs.text())
	}
	t.Cleanup(srv.shutdown)
	return srv, logs, sock
}

// requirePlainDNS fails unless the gateway answers one plain UDP query: what it has lost is never its plain DNS.
func requirePlainDNS(t *testing.T, logs *capture) {
	t.Helper()
	query := buildQuery(t, 0x3848, "example.", true)
	to := listenAddr(t, firstLine(logs.text(), "listening udp+tcp "))
	if got, want := udpQuery(t, to, query), echoWithQR(seenQuery{wire: query})[0]; !bytes.Equal(got, want) {
		t.Fatalf("plain DNS answered %x, want %x", got, want)
	}
}

// forwardingFrontend is the decider with no module: every query goes to Unbound as it came.
type forwardingFrontend struct{}

func (forwardingFrontend) Resolve(wire []byte, _ string, fwd func([]byte) []byte, _, _, _ string) []byte {
	return fwd(wire)
}

func (forwardingFrontend) Close() {}

// bootScript is the decider boot of a test: a boot with the module fails with moduleErr, one without gives fe. It keeps the
// options of every boot.
type bootScript struct {
	moduleErr error
	fe        frontend
	mu        sync.Mutex
	boots     []decider.Options
}

func (b *bootScript) open(o decider.Options) (frontend, error) {
	b.mu.Lock()
	b.boots = append(b.boots, o)
	b.mu.Unlock()
	if !o.NoModule {
		return nil, b.moduleErr
	}
	return b.fe, nil
}

func (b *bootScript) seen() []decider.Options {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.boots)
}

// requireForwarded fails unless a query sent to the gateway reaches the fake Unbound as the client sent it.
func requireForwarded(t *testing.T, logs *capture, up *fakeUpstream) {
	t.Helper()
	query := buildQuery(t, 0x3849, "forwarded.example.", true)
	to := listenAddr(t, firstLine(logs.text(), "listening udp+tcp "))
	if got, want := udpQuery(t, to, query), echoWithQR(seenQuery{wire: query})[0]; !bytes.Equal(got, want) {
		t.Fatalf("the reply through the gateway is %x, want Unbound's %x", got, want)
	}
	if seen := up.next(); !bytes.Equal(seen.wire, query) {
		t.Fatalf("Unbound saw %x, want the client's query %x", seen.wire, query)
	}
}

// pushPEM sends a certificate to the control socket and returns the reply line.
func pushPEM(t *testing.T, sock string, pem []byte) string {
	t.Helper()
	c := dialCtl(t, sock)
	_, _ = c.Write(ctlFrame(pem))
	return ctlReply(t, c)
}

// A1: a DNS name or DDR flag that cannot be built is served without. The gateway starts, answers plain DNS, and the status
// says which part is gone; what still works (a valid name beside a bad --ddr-doh-443) keeps working.
func TestADNSNameOrDDRFlagThatCannotBeBuiltStartsTheGatewayWithoutIt(t *testing.T) {
	cases := []struct {
		name    string
		flags   []string
		dnsName string // the status's applied name
		order   []string
		reasons map[string]string
	}{
		{"an invalid --dns-name", []string{"--dns-name", "fw..lan"}, "", []string{"dns_name"}, map[string]string{"dns_name": `--dns-name "fw..lan"`}},
		{"an invalid --dns-name-answer", []string{"--dns-name", "fw.example.lan", "--dns-name-answer", "10.0.0.1=bad"}, "", []string{"dns_name"}, map[string]string{"dns_name": "--dns-name-answer"}},
		{"--dns-name-answer without --dns-name", []string{"--dns-name-answer", "10.0.0.1=10.0.0.1"}, "", []string{"dns_name"}, map[string]string{"dns_name": "--dns-name-answer needs --dns-name"}},
		{"--ddr without --dns-name", []string{"--ddr"}, "", []string{"ddr"}, map[string]string{"ddr": "--ddr needs --dns-name"}},
		{"an invalid --ddr-doh-443", []string{"--dns-name", "fw.example.lan", "--ddr", "--ddr-doh-443", "192.0.2.1:443"}, "fw.example.lan", []string{"ddr"}, map[string]string{"ddr": `--ddr-doh-443 "192.0.2.1:443"`}},
		{"--ddr-doh-443 without --ddr", []string{"--dns-name", "fw.example.lan", "--ddr-doh-443", "192.0.2.1"}, "fw.example.lan", []string{"ddr"}, map[string]string{"ddr": "--ddr-doh-443 needs --ddr"}},
		{"an invalid --dns-name with --ddr", []string{"--dns-name", "fw..lan", "--ddr"}, "", []string{"dns_name", "ddr"}, map[string]string{"dns_name": `--dns-name "fw..lan"`, "ddr": "--ddr needs"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, logs, sock := startFromFlags(t, echoOpen, c.flags...)
			requirePlainDNS(t, logs)
			status := statusObject(t, sock)
			if status["dns_name"] != c.dnsName || status["ddr"] != false || len(status["name_answers"].(map[string]any)) != 0 {
				t.Errorf("applied dns_name=%v ddr=%v name_answers=%v, want %q, no DDR and no name answers", status["dns_name"], status["ddr"], status["name_answers"], c.dnsName)
			}
			requireLost(t, sock, c.name, c.reasons, c.order...)
		})
	}
}

// A2: every other flag rule is an invariant of the rc script PHP writes; a break there is a bug in that script and stays a
// usage error (exit 2), whatever else the gateway could serve.
func TestEveryOtherFlagRuleStillStopsTheGatewayWithExitTwo(t *testing.T) {
	for name, args := range map[string][]string{
		"a port out of range":              {"--listen", "127.0.0.1", "--port", "70000"},
		"an empty --listen":                {"--listen", ""},
		"an upstream that is no HOST:PORT": {"--listen", "127.0.0.1", "--upstream", "nonsense"},
		"--observer with --no-module":      {"--listen", "127.0.0.1", "--observer", "--no-module"},
	} {
		t.Run(name, func(t *testing.T) {
			var log bytes.Buffer
			if code := run(args, &log, nil); code != 2 {
				t.Fatalf("run(%q) = %d, want 2; log:\n%s", args, code, log.String())
			}
		})
	}
}

// A5: a decider that cannot boot does not stop the gateway: it boots again with no module (every query forwarded), and the
// status says the DNSBL is not blocking, with the first error.
func TestADeciderThatCannotBootIsReplacedByOneWithNoModuleAndTheGatewayServesAndForwards(t *testing.T) {
	up := newFakeUpstream(t)
	cfg, logs, sock := healthyConfig(t)
	cfg.upstream, cfg.moduleDir, cfg.logDir = up.addr, "/some/module/dir", "/some/log/dir"
	script := &bootScript{moduleErr: errors.New("init_standard: [MAIN] python_enable: not a boolean"), fe: forwardingFrontend{}}
	cfg.open = script.open
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatalf("start = %v, want the gateway to serve without the module", err)
	}
	t.Cleanup(srv.shutdown)
	want := []decider.Options{{ModuleDir: "/some/module/dir", LogDir: "/some/log/dir"}, {ModuleDir: "/some/module/dir", LogDir: "/some/log/dir", NoModule: true}}
	if got := script.seen(); !slices.Equal(got, want) {
		t.Fatalf("boots %+v, want %+v", got, want)
	}
	requireForwarded(t, logs, up)
	rows := requireLost(t, sock, "after the module failed to boot", map[string]string{}, "dnsbl")
	if rows[0].Reason != "decider: init_standard: [MAIN] python_enable: not a boolean" {
		t.Errorf("reason %q, want the first boot's error", rows[0].Reason)
	}
}

// The same with the real decider and real files: a [MAIN] value that is no boolean makes init_standard raise.
func TestARealDeciderWhoseIniHoldsANonBooleanMainValueIsReplacedByOneWithNoModule(t *testing.T) {
	up := newFakeUpstream(t)
	moduleDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(moduleDir, "pfb_unbound.ini"), []byte("[MAIN]\npython_enable = banana\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, logs, sock := startFromFlags(t, nil, "--upstream", up.addr, "--module-dir", moduleDir, "--log-dir", t.TempDir())
	requireForwarded(t, logs, up)
	requireLost(t, sock, "real decider, bad ini", map[string]string{"dnsbl": "python_enable"}, "dnsbl")
}

// A5e: the observer belongs to the module; the boot without the module does not ask for it.
func TestTheBootWithNoModuleAsksForNoObserver(t *testing.T) {
	up := newFakeUpstream(t)
	cfg, logs, _ := healthyConfig(t)
	cfg.upstream, cfg.observer = up.addr, true
	script := &bootScript{moduleErr: errors.New("module refused"), fe: forwardingFrontend{}}
	cfg.open = script.open
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatalf("start = %v, want the gateway to serve without the module", err)
	}
	t.Cleanup(srv.shutdown)
	if got, want := script.seen(), []decider.Options{{ModuleDir: cfg.moduleDir, LogDir: cfg.logDir, Observer: true}, {ModuleDir: cfg.moduleDir, LogDir: cfg.logDir, NoModule: true}}; !slices.Equal(got, want) {
		t.Fatalf("boots %+v, want %+v", got, want)
	}
	requireForwarded(t, logs, up)
}

// A5c: with no decider of either kind there is nothing to serve with: the start fails with the second error and nothing stays
// bound.
func TestWhenTheDeciderWithNoModuleCannotBootEitherTheStartFailsWithThatErrorAndFreesThePort(t *testing.T) {
	cfg, logs, _ := healthyConfig(t)
	cfg.port = freePort(t)
	cfg.open = func(o decider.Options) (frontend, error) {
		if o.NoModule {
			return nil, errors.New("the boot with no module refused")
		}
		return nil, errors.New("the boot with the module refused")
	}
	srv, err := start(cfg, logs.logf)
	if err == nil || err.Error() != "decider: the boot with no module refused" {
		t.Fatalf("start: got srv=%v err=%v, want the second boot's error", srv, err)
	}
	l, err := bindPlain("127.0.0.1", cfg.port)
	if err != nil {
		t.Fatalf("the port is still held after a failed start: %v", err)
	}
	l.close()
	if strings.Contains(logs.text(), "listening") {
		t.Fatalf("no readiness line without a decider:\n%s", logs.text())
	}
}

// With no module asked for there is nothing to boot without: a boot error then is the start's, as before, after one boot.
func TestABootErrorWhenNoModuleWasAskedForIsNotRetried(t *testing.T) {
	cfg, logs, _ := healthyConfig(t)
	cfg.noModule = true
	script := &bootScript{}
	cfg.open = func(o decider.Options) (frontend, error) { script.open(o); return nil, errors.New("no reply log") }
	srv, err := start(cfg, logs.logf)
	if err == nil || err.Error() != "decider: no reply log" {
		t.Fatalf("start: got srv=%v err=%v, want the boot error", srv, err)
	}
	if n := len(script.seen()); n != 1 {
		t.Fatalf("the decider was booted %d times, want once", n)
	}
}

// B1: a certificate that cannot be loaded leaves the TLS listeners bound and every handshake failing: the status says so until
// a certificate is pushed on the control socket.
func TestAnUnusableCertificateFileIsReportedUntilACertificateIsPushed(t *testing.T) {
	absent := filepath.Join(shortTempDir(t), "absent.pem")
	_, _, sock := startFromFlags(t, echoOpen, "--dot-listen", "127.0.0.1", "--dot-port", strconv.Itoa(freePort(t)), "--tls-pem", absent)
	requireLost(t, sock, "no certificate loaded", map[string]string{"tls_certificate": absent}, "tls_certificate")
	listed := false
	for _, row := range statusObject(t, sock)["listeners"].([]any) {
		if r := row.(map[string]any); r["kind"] == "dot" && r["state"] == "listening" {
			listed = true
		}
	}
	if !listed {
		t.Errorf("the DoT listener is not listed as listening: %#v", statusObject(t, sock)["listeners"])
	}
	path, _ := goodPEM(t)
	pem, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := pushPEM(t, sock, pem); got != "ok" {
		t.Fatalf("push reply %q, want ok", got)
	}
	requireLost(t, sock, "after a certificate was pushed", nil)
}

// B5: a Resolver config that cannot be loaded makes the gateway forward every client; the status says so until the file loads.
func TestAnUnloadableResolverConfigIsReportedUntilItLoads(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "unbound.conf")
	srv, _, sock := startFromFlags(t, echoOpen, "--unbound-conf", conf)
	requireLost(t, sock, "no config", map[string]string{"acl": conf}, "acl")
	if err := os.WriteFile(conf, []byte("server:\n\taccess-control: 127.0.0.0/8 allow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv.g.acl.Refresh() // the gateway's own tick does the same every second
	requireLost(t, sock, "after the config loaded", nil)
}

// S1: the list is always there, empty when nothing is lost; a consumer reads an absent field as an older gateway.
func TestAHealthyStartReportsAnEmptyDegradedList(t *testing.T) {
	path, _ := goodPEM(t)
	_, _, sock := startFromFlags(t, echoOpen, "--dns-name", "fw.example.lan", "--ddr",
		"--dot-listen", "127.0.0.1", "--dot-port", strconv.Itoa(freePort(t)), "--tls-pem", path)
	if rows, raw := statusLost(t, sock); raw != "[]" || len(rows) != 0 {
		t.Fatalf("degraded %q (%+v), want []", raw, rows)
	}
}

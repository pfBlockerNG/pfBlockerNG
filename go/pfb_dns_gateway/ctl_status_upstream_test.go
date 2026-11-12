package main

import (
	"fmt"
	"io"
	"path/filepath"
	"testing"
)

// cliStatusObject starts the gateway with --upstream as the command line gives it: parseConfig, validate included, is the
// only source of the upstream. The test harness sets its own fields (control socket, TLS, frontend, Unbound config) only.
func cliStatusObject(t *testing.T, upstream string) map[string]any {
	t.Helper()
	base, logs := lifecycleConfig(t)
	path, _ := goodPEM(t)
	sock := filepath.Join(shortTempDir(t), "run", "ctl.sock")
	cfg, err := parseConfig([]string{"--listen", "127.0.0.1", "--port", "0", "--upstream", upstream,
		"--dot-listen", "127.0.0.1", "--dot-port", fmt.Sprint(freePort(t)), "--tls-pem", path, "--ctl-socket", sock}, io.Discard)
	if err != nil {
		t.Fatalf("the CLI must accept --upstream %q: %v", upstream, err)
	}
	cfg.unboundConf, cfg.open = base.unboundConf, base.open
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.shutdown)
	return statusObject(t, sock)
}

// requireSnapshot fails unless the status carries every field the consumers read; upstream is optional and checked by callers.
func requireSnapshot(t *testing.T, got map[string]any) {
	t.Helper()
	for _, field := range []string{"version", "pid", "executable", "ready", "dns_name", "listeners", "name_answers", "ddr", "advertisements", "degraded"} {
		if _, ok := got[field]; !ok {
			t.Fatalf("snapshot lacks %q: %#v", field, got)
		}
	}
}

func TestStatusWireReportsBracketedIPv4UpstreamAsApplied(t *testing.T) {
	if got := cliStatusObject(t, "[127.0.0.1]:5353"); got["upstream"] != "127.0.0.1:5353" {
		t.Fatalf("applied upstream %v want 127.0.0.1:5353", got["upstream"])
	}
}

// Supported: the package's own 127.0.0.1 and ::1 spellings, and every numeric literal the readiness check accepts (bracketed or
// plain IPv4, bracketed IPv6, IPv4-mapped IPv6), with a port of digits, leading zeros normalized, 1 to 65535.
func TestStatusWireCanonicalizesSupportedUpstreamSpellings(t *testing.T) {
	for upstream, applied := range map[string]string{
		"127.0.0.1:5353":          "127.0.0.1:5353",
		"[127.0.0.1]:5353":        "127.0.0.1:5353",
		"127.0.0.1:05353":         "127.0.0.1:5353",
		"[::1]:5353":              "[::1]:5353",
		"[::1]:65535":             "[::1]:65535",
		"[2001:0db8:0:0::1]:5353": "[2001:db8::1]:5353",
		"[::ffff:192.0.2.1]:5353": "192.0.2.1:5353",
		"[::ffff:c000:201]:5353":  "192.0.2.1:5353",
	} {
		t.Run(upstream, func(t *testing.T) {
			got := cliStatusObject(t, upstream)
			requireSnapshot(t, got)
			if got["upstream"] != applied {
				t.Fatalf("applied upstream %v want %s", got["upstream"], applied)
			}
		})
	}
}

// Accepted by the CLI but with no numeric canonical form (a hostname, a scoped address, a sign or non-numeric port): the upstream
// is omitted and the rest of the snapshot is still served.
func TestStatusWireOmitsUnsupportedCLIUpstream(t *testing.T) {
	for _, upstream := range []string{
		"localhost:5353", "[localhost]:5353", "ns.example:5353", "127.1:5353", "127.000.000.001:5353", "0x7f.0.0.1:5353",
		"[fe80::1%eth0]:5353", "[127.0.0.1%eth0]:5353", "[ 127.0.0.1 ]:5353", "127.0.0.1:+5353",
	} {
		t.Run(upstream, func(t *testing.T) {
			got := cliStatusObject(t, upstream)
			requireSnapshot(t, got)
			if v, ok := got["upstream"]; ok {
				t.Fatalf("upstream %v must be absent", v)
			}
			if got["ready"] != true {
				t.Fatalf("ready %v, want the started gateway served", got["ready"])
			}
		})
	}
}

// Ports the CLI rejects never reach start; the emitter still omits them rather than failing the snapshot.
func TestStatusWireOmitsOutOfRangeUpstreamPort(t *testing.T) {
	for _, upstream := range []string{"127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:", "[::1]:99999"} {
		t.Run(upstream, func(t *testing.T) {
			k := newCtlRig(t, func(c *ctlServer) {
				c.listeners = &listenerSet{cfg: config{upstream: upstream}}
			})
			got := statusObject(t, k.path)
			requireSnapshot(t, got)
			if v, ok := got["upstream"]; ok {
				t.Fatalf("upstream %v must be absent", v)
			}
		})
	}
}

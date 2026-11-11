package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func statusWire(t *testing.T, path string, tail []byte, fd int) string {
	t.Helper()
	c := dialCtl(t, path)
	frame := append(binary.BigEndian.AppendUint32(nil, 0xfffffffa), tail...)
	if fd >= 0 {
		_, _, _ = c.WriteMsgUnix(frame, syscall.UnixRights(fd), nil)
	} else {
		_, _ = c.Write(frame)
	}
	_ = c.SetReadDeadline(time.Now().Add(watchdog))
	b, err := io.ReadAll(c)
	if err != nil && !isClosed(err) {
		t.Fatalf("status read: %v (%q)", err, b)
	}
	return string(b)
}

func statusObject(t *testing.T, path string) map[string]any {
	t.Helper()
	wire := statusWire(t, path, nil, -1)
	if len(wire) > 65536 || !strings.HasSuffix(wire, "\nok\n") || strings.Count(wire, "\n") != 2 {
		t.Fatalf("want bounded JSON line + ok + EOF, got %q", wire)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSuffix(wire, "\nok\n")), &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestStatusWireReportsAppliedLongConfiguration(t *testing.T) {
	cfg, logs, sock := ctlConfig(t)
	cfg.dnsName, cfg.ddr = "DNS.example.", true
	cfg.nameAnswers = []string{"127.0.0.1=192.0.2.1,2001:db8::1", "::1=", "192.0.2.2=192.0.2.3", "2001:db8::2=2001:db8::3"}
	for i := 1; i <= 100; i++ {
		cfg.nameAnswers = append(cfg.nameAnswers, fmt.Sprintf("198.51.100.%d=192.0.2.1", i))
	}
	if len(strings.Join(cfg.nameAnswers, " --dns-name-answer ")) <= 2048 {
		t.Fatal("fixture must exceed ps limit")
	}
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.shutdown()
	got := statusObject(t, sock)
	exe, _ := os.Executable()
	if got["version"] != float64(1) || got["pid"] != float64(os.Getpid()) || got["executable"] != exe || got["ready"] != true || got["upstream"] != netip.MustParseAddrPort(cfg.upstream).String() || got["dns_name"] != "dns.example" || got["ddr"] != true {
		t.Fatalf("runtime/applied fields: %#v", got)
	}
	names := got["name_answers"].(map[string]any)
	for local, want := range map[string]string{"127.0.0.1": `{"a":["192.0.2.1"],"aaaa":["2001:db8::1"]}`, "::1": `{"a":[],"aaaa":[]}`, "192.0.2.2": `{"a":["192.0.2.3"],"aaaa":[]}`, "2001:db8::2": `{"a":[],"aaaa":["2001:db8::3"]}`} {
		var expected any
		_ = json.Unmarshal([]byte(want), &expected)
		if !reflect.DeepEqual(names[local], expected) {
			t.Fatalf("name answer %s: %#v want %s", local, names[local], want)
		}
	}
	if len(names) != 104 || names["203.0.113.1"] != nil {
		t.Fatalf("owned/unowned names: %#v", names)
	}
	if len(got["listeners"].([]any)) != 2 {
		t.Fatalf("listener inventory: %#v", got["listeners"])
	}
	ads := got["advertisements"].(map[string]any)
	if len(ads) != 104 {
		t.Fatalf("advertisement locals %d want 104", len(ads))
	}
	ad := ads["127.0.0.1"].(map[string]any)
	recs := ad["records"].([]any)
	if len(recs) != 1 {
		t.Fatalf("DoT designation: %#v", ad)
	}
	rec := recs[0].(map[string]any)
	if rec["alpn"] != "dot" || rec["target"] != "DNS.example" || rec["hint"] != "127.0.0.1" || rec["priority"] != float64(2) || rec["port"] != float64(cfg.dotPort) || rec["path"] != "" {
		t.Fatalf("DoT record: %#v", rec)
	}
}

func TestStatusWireEmptyRefusedAndBounded(t *testing.T) {
	for _, oversized := range []bool{false, true} {
		t.Run(fmt.Sprint(oversized), func(t *testing.T) {
			k := newCtlRig(t, func(c *ctlServer) {
				c.listeners = &listenerSet{cfg: config{upstream: "[::1]:5353"}, served: map[string]func(){"udp+tcp 0.0.0.0:53": nil}, refused: map[string]string{"dot [::1]:853": "bind refused"}}
				if oversized {
					c.listeners.refused["dot [::1]:853"] = strings.Repeat("x", 65536)
				}
			})
			if oversized {
				if got := statusWire(t, k.path, nil, -1); got != "error: status exceeds response limit\n" {
					t.Fatalf("oversized response: %q", got)
				}
				return
			}
			got := statusObject(t, k.path)
			if got["ready"] != false || got["dns_name"] != "" || got["ddr"] != false || got["upstream"] != "[::1]:5353" {
				t.Fatalf("uninitialized fields: %#v", got)
			}
			if !reflect.DeepEqual(got["name_answers"], map[string]any{}) {
				t.Fatalf("empty names: %#v", got)
			}
			rows := got["listeners"].([]any)
			if len(rows) != 2 || rows[0].(map[string]any)["state"] != "refused" || rows[0].(map[string]any)["reason"] != "bind refused" || rows[1].(map[string]any)["reason"] != "" {
				t.Fatalf("sorted refusal/listening: %#v", rows)
			}
			for _, v := range got["advertisements"].(map[string]any) {
				a := v.(map[string]any)
				if !reflect.DeepEqual(a["records"], []any{}) || !reflect.DeepEqual(a["additional"], []any{}) {
					t.Fatalf("empty ad: %#v", a)
				}
			}
		})
	}
}

func TestStatusWireRejectsUntrustedPeersAndBodies(t *testing.T) {
	for _, mode := range []string{"uid", "credential", "body", "rights"} {
		t.Run(mode, func(t *testing.T) {
			k := newCtlRig(t)
			var tail []byte
			fd := -1
			switch mode {
			case "uid":
				k.peer.Store(ctlUID + 1)
			case "credential":
				k.peerErr.Store(true)
			case "body":
				tail = []byte("unexpected")
			case "rights":
				f, err := os.Open(os.DevNull)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				fd = int(f.Fd())
			}
			got := statusWire(t, k.path, tail, fd)
			if mode == "uid" || mode == "credential" {
				if got != "" {
					t.Fatalf("untrusted response %q", got)
				}
			} else if !strings.HasPrefix(got, "error: status takes no body or descriptors") {
				t.Fatalf("body/rights response %q", got)
			}
		})
	}
}

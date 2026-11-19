package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A failed pfctl add is repaired by the same pull's reconcile; the new address's states are still killed.
func TestAStateKillIsNotLostWhenTheAddFails(t *testing.T) {
	h := synced(t, ok(`{"new":[{"id":70,"origin":"crowdsec","type":"ban","scope":"Ip","value":"198.51.100.70"}],"deleted":[]}`))
	h.pf.states = "vtnet0 tcp 192.168.1.1:22 <- 198.51.100.70:50122       ESTABLISHED:ESTABLISHED\n"
	h.pf.failOn = func(args []string) error {
		if len(args) == 6 && args[3] == "add" && args[5] != "/dev/null" {
			return errors.New("pfctl: Cannot allocate memory")
		}
		return nil
	}
	if err := h.d.pull(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertTable(t, h.pf, "crowdsec_v4", append(slices.Clone(startupV4), "198.51.100.70")...)
	got := callStrings(h.pf.takeCalls())
	replaced := slices.IndexFunc(got, func(c string) bool { return strings.HasPrefix(c, "-t crowdsec_v4 -T replace") })
	killed := slices.Index(got, "-k 198.51.100.70")
	if replaced < 0 || killed < replaced || !slices.Contains(got, "-k 0.0.0.0/0 -k 198.51.100.70") {
		t.Fatalf("calls = %q; want the table replaced, then both state kills", got)
	}
}

// An origin that repeats the key is not written to the status file or sent as a usage label.
func TestAnOriginRepeatingTheKeyIsNotPublished(t *testing.T) {
	h := newHarness(t, ok(`{"new":[{"id":1,"origin":"`+testKey+`","type":"ban","scope":"Ip","value":"198.51.100.10"},
		{"id":2,"origin":"cscli","type":"ban","scope":"Ip","value":"198.51.100.11"}],"deleted":[]}`))
	ctx := context.Background()
	if err := h.d.setup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.d.pull(ctx); err != nil {
		t.Fatal(err)
	}
	h.d.sendUsage(ctx)
	written, _ := os.ReadFile(h.cfg.StatusFile)
	_, bodies := h.lapi.requests()
	for what, text := range map[string]string{"status file": string(written), "usage post": bodies[len(bodies)-1]} {
		if strings.Contains(text, testKey) {
			t.Fatalf("%s carries the key: %s", what, text)
		}
	}
	var st status
	if err := json.Unmarshal(written, &st); err != nil {
		t.Fatal(err)
	}
	if b := st.Banned["ipv4"]; b.Total != 2 || b.Origins["cscli"] != 1 || len(b.Origins) != 2 {
		t.Fatalf("banned ipv4 = %+v; want both values counted, cscli kept as is", b)
	}
}

// A status line whose reason phrase repeats a short key does not carry it into the error text.
func TestAShortKeyInTheStatusLineDoesNotReachTheError(t *testing.T) {
	const key = "abc1234"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 4096)
			_, _ = conn.Read(buf)
			_, _ = conn.Write([]byte("HTTP/1.1 403 " + key + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			conn.Close()
		}
	}()
	cfg, err := parseConfig([]byte(fmt.Sprintf(`{"api_url":"http://%s/","api_key":%q}`, ln.Addr(), key)))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := newLAPIClient(cfg)
	_, err = c.pull(context.Background(), true)
	if err == nil || strings.Contains(err.Error(), key) {
		t.Fatalf("pull error = %v; want an error without the key", err)
	}
}

// Scenario: SIGTERM arrives while start-up is still flushing the tables. Both tables end flushed and serve exits 0.
func TestSIGTERMDuringSetupStillFlushesBothTables(t *testing.T) {
	dir := t.TempDir()
	argsLog := filepath.Join(dir, "pfctl.log")
	once := filepath.Join(dir, "signalled")
	script := "#!/bin/sh\necho \"$*\" >> " + argsLog + "\n" +
		"if [ \"$*\" = '-t crowdsec_v4 -T flush' ] && [ ! -e " + once + " ]; then : > " + once +
		"; kill -TERM $PPID; exec sleep 60; fi\n"
	pfctlBin := filepath.Join(dir, "pfctl")
	if err := os.WriteFile(pfctlBin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	device := filepath.Join(dir, "pf")
	if err := os.WriteFile(device, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t, newStubLAPI(t).srv.URL+"/")
	out := &lockedWriter{w: &bytes.Buffer{}}
	if code := serve(cfg, out, pfctlBin, device); code != 0 {
		t.Fatalf("serve returned %d; want 0 for a stop during start-up", code)
	}
	data, _ := os.ReadFile(argsLog)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if n := len(lines); n < 2 || lines[n-2] != "-t crowdsec_v4 -T flush" || lines[n-1] != "-t crowdsec_v6 -T flush" {
		t.Fatalf("pfctl calls = %q; want both tables flushed last", lines)
	}
}

// Usage labels respect the LAPI schema's 255-character limit.
func TestUsageLabelsStayWithinTheSchemaLimit(t *testing.T) {
	long := strings.Repeat("o", 300)
	data, err := usagePayload(usageInput{origins: [2]map[string]int{{long: 1, "cscli": 2}, {}}})
	if err != nil {
		t.Fatal(err)
	}
	var top allMetrics
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatal(err)
	}
	counts := map[string]float64{}
	for _, item := range top.RemediationComponents[0].Metrics[0].Items {
		for k, v := range item.Labels {
			if len(v) > 255 {
				t.Fatalf("label %s is %d characters long", k, len(v))
			}
		}
		if item.Name == "active_decisions" {
			counts[item.Labels["origin"]] += item.Value
		}
	}
	if len(counts) != 2 || counts["cscli"] != 2 {
		t.Fatalf("active_decisions per origin = %v; want the long origin and cscli kept apart", counts)
	}
}

func droppedPosted(t *testing.T, h *harness) []string {
	t.Helper()
	reqs, bodies := h.lapi.requests()
	var got []string
	for i, r := range reqs {
		if r.URL.Path != "/v1/usage-metrics" {
			continue
		}
		var top allMetrics
		if err := json.Unmarshal([]byte(bodies[i]), &top); err != nil {
			t.Fatal(err)
		}
		for _, item := range top.RemediationComponents[0].Metrics[0].Items {
			if item.Name == "dropped" && item.Unit == "packet" && item.Labels["ip_type"] == "ipv4" {
				got = append(got, fmt.Sprint(item.Value))
			}
		}
	}
	return got
}

func setRules(h *harness, packets int) {
	h.pf.mu.Lock()
	defer h.pf.mu.Unlock()
	h.pf.rules = fmt.Sprintf("block drop in quick inet from <crowdsec_v4> to any label \"CrowdSec IPv4\"\n"+
		"  [ Evaluations: 1 Packets: %d Bytes: %d States: 0 ]\n", packets, packets*100)
}

// Scenario: dropped counts are measured when the window closes, and a reset seen between two posts is kept.
// Given 20 packets at the first post, a filter reload that resets the counter to 3, and 25 at the next post,
// the second post reports the 25 counted since the reset; packets counted after the last pull are in the window too.
func TestDroppedCountsFollowEveryPullAndTheWindowEnd(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.d.setup(ctx); err != nil {
		t.Fatal(err)
	}
	setRules(h, 20)
	_ = h.d.pull(ctx)
	h.d.sendUsage(ctx)
	setRules(h, 3)
	_ = h.d.pull(ctx)
	setRules(h, 25)
	_ = h.d.pull(ctx)
	h.d.sendUsage(ctx)
	setRules(h, 30) // no pull before the window closes
	h.d.sendUsage(ctx)
	if got, want := droppedPosted(t, h), []string{"20", "25", "5"}; !slices.Equal(got, want) {
		t.Fatalf("dropped ipv4 packets per post = %v; want %v", got, want)
	}
}

// A failed usage post drops its window: the next post reports only what came after it.
func TestAFailedPostDropsItsWindow(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.d.setup(ctx); err != nil {
		t.Fatal(err)
	}
	h.lapi.mu.Lock()
	h.lapi.usage = http.StatusInternalServerError
	h.lapi.mu.Unlock()
	setRules(h, 20)
	h.d.sendUsage(ctx)
	h.lapi.mu.Lock()
	h.lapi.usage = http.StatusCreated
	h.lapi.mu.Unlock()
	setRules(h, 25)
	h.d.sendUsage(ctx)
	if got := droppedPosted(t, h); len(got) != 2 || got[1] != "5" {
		t.Fatalf("dropped ipv4 packets per post = %v; want the second post to report 5", got)
	}
}

package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestStatusWireUsesEffectiveStandardPorts(t *testing.T) {
	k := newCtlRig(t, func(c *ctlServer) {
		c.listeners = &listenerSet{cfg: config{upstream: "127.0.0.1:5353"}, served: map[string]func(){"udp+tcp 192.0.2.1:53": nil}}
		c.ddr = mustDDR(t, ddrTarget, ddrLoaded(t), ddrAt("192.0.2.1", 853), ddrAt("192.0.2.1", 4443), ddrAt("192.0.2.1", 853))
		c.ddr.setDoH443(addrSet("192.0.2.1"))
	})
	ads := statusObject(t, k.path)["advertisements"].(map[string]any)
	records := ads["192.0.2.1"].(map[string]any)["records"].([]any)
	if len(records) != 3 {
		t.Fatalf("records %#v want three transports", records)
	}
	for _, value := range records {
		r := value.(map[string]any)
		want := float64(853)
		if r["alpn"] == "h2" {
			want = 443
		}
		if r["port"] != want {
			t.Fatalf("effective port for %s: %v want %v", r["alpn"], r["port"], want)
		}
	}
}

func TestStatusWireExactResponseBoundary(t *testing.T) {
	for _, size := range []int{65536, 65537} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			k := newCtlRig(t, func(c *ctlServer) {
				c.listeners = &listenerSet{cfg: config{upstream: "127.0.0.1:5353"}, refused: map[string]string{"dot 192.0.2.1:853": ""}}
				wire, err := c.status()
				if err != nil {
					t.Fatal(err)
				}
				c.listeners.refused["dot 192.0.2.1:853"] = strings.Repeat("x", size-len(wire))
			})
			wire := statusWire(t, k.path, nil, -1)
			if size == 65536 {
				if len(wire) != size || !strings.HasSuffix(wire, "\nok\n") {
					t.Fatalf("exact cap: length %d suffix %q", len(wire), wire[len(wire)-4:])
				}
			} else if wire != "error: status exceeds response limit\n" {
				t.Fatalf("cap+1 reply %q", wire)
			}
		})
	}
}

func TestStatusWireReadinessFollowsCancellation(t *testing.T) {
	k := newCtlRig(t, func(c *ctlServer) {
		c.listeners = &listenerSet{cfg: config{upstream: "127.0.0.1:5353"}}
		c.ready.Store(true)
	})
	if got := statusObject(t, k.path)["ready"]; got != true {
		t.Fatalf("initialized ready %v want true", got)
	}
	k.r.g.cancel()
	if got := statusObject(t, k.path)["ready"]; got != false {
		t.Fatalf("stopping ready %v want false", got)
	}
}

func TestStatusWireTracksRealLiveListeners(t *testing.T) {
	r := newLiveRig(t, liveDDR)
	const added = "127.0.0.2"
	check := func(want bool) {
		t.Helper()
		got := statusObject(t, r.sock)
		found := false
		for _, value := range got["listeners"].([]any) {
			row := value.(map[string]any)
			if row["kind"] == "dot" && row["address"] == r.at("dot", added).String() {
				found = row["state"] == "listening"
			}
		}
		if found != want {
			t.Fatalf("live DoT inventory %v want %v: %#v", found, want, got["listeners"])
		}
		ad, exists := got["advertisements"].(map[string]any)[added]
		if want {
			if !exists || len(ad.(map[string]any)["records"].([]any)) != 1 {
				t.Fatalf("live DoT advertisement %#v", ad)
			}
		} else if exists {
			t.Fatalf("removed local still advertised: %#v", ad)
		}
	}
	check(false)
	r.add("dot", r.at("dot", added))
	check(true)
	r.remove("dot", r.at("dot", added))
	check(false)
}

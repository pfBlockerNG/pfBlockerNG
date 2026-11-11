package main

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestStatusWireDesignationMatchesDNSAcrossCertificateAndTableUpdates(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			var d *ddr
			k := newCtlRig(t, func(c *ctlServer) {
				c.names = mustNames(t, ddrTarget, "192.0.2.1=", "2001:db8::1=", "0.0.0.0=")
				c.listeners = &listenerSet{cfg: config{upstream: "127.0.0.1:5353"}, served: map[string]func(){"dot 192.0.2.1:853": nil, "doh [2001:db8::1]:4443": nil, "doq 192.0.2.1:8853": nil, "udp+tcp 0.0.0.0:53": nil}}
				if enabled {
					d = mustDDR(t, ddrTarget, c.certs, ddrAt("192.0.2.1", 853), ddrAt("2001:db8::1", 4443), ddrAt("192.0.2.1", 8853))
					c.ddr = d
				}
			})
			check := func(loaded, advertised bool) {
				t.Helper()
				got := statusObject(t, k.path)
				ads := got["advertisements"].(map[string]any)
				for _, local := range []string{"192.0.2.1", "2001:db8::1", "0.0.0.0"} {
					ad := ads[local].(map[string]any)
					records := ad["records"].([]any)
					additional := ad["additional"].([]any)
					if !enabled || !loaded || local == "0.0.0.0" {
						if len(records) != 0 || len(additional) != 0 {
							t.Fatalf("no designation on %s: %#v", local, ad)
						}
						continue
					}
					answers, extra := d.designate(dnsmessage.MustNewName(ddrAsk), netip.MustParseAddr(local))
					if len(records) != len(answers) || len(additional) != len(extra) {
						t.Fatalf("DNS/status count mismatch on %s: %#v vs %v %v", local, ad, answers, extra)
					}
					for i, rr := range answers {
						r := ddrDecode(t, rr, ddrAsk)
						if r.port == 0 {
							r.port = 853
							if r.alpn == "h2" {
								r.port = 443
							}
						}
						want := map[string]any{"priority": float64(r.prio), "target": strings.TrimSuffix(r.target, "."), "alpn": r.alpn, "port": float64(r.port), "hint": r.hint, "path": r.dohpath}
						if !reflect.DeepEqual(records[i], want) {
							t.Fatalf("DNS/status record mismatch: %#v want %#v", records[i], want)
						}
					}
					if !reflect.DeepEqual(additional, []any{local}) {
						t.Fatalf("additional on %s: %#v", local, additional)
					}
					if local == "2001:db8::1" {
						wantPort := float64(4443)
						if advertised {
							wantPort = 443
						}
						if records[0].(map[string]any)["port"] != wantPort {
							t.Fatalf("advertised DoH port: %#v want %v", records, wantPort)
						}
					}
				}
			}
			check(false, false)
			if got := k.push(t, chainPEM(t, k.leaf(t))); got != "ok" {
				t.Fatalf("certificate push: %s", got)
			}
			check(true, false)
			body := "dns-name-answer 192.0.2.1=192.0.2.9\ndns-name-answer 2001:db8::1=\ndns-name-answer 0.0.0.0=\n"
			if enabled {
				body += "ddr-doh-443 2001:db8::1\n"
			}
			if got := k.send(t, addressTableFrame(strings.TrimSuffix(body, "\n"))); got != "ok" {
				t.Fatalf("table push: %s", got)
			}
			check(true, enabled)
			got := statusObject(t, k.path)["name_answers"].(map[string]any)["192.0.2.1"]
			var want any
			_ = json.Unmarshal([]byte(`{"a":["192.0.2.9"],"aaaa":[]}`), &want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("updated name snapshot: %#v want %#v", got, want)
			}
		})
	}
}

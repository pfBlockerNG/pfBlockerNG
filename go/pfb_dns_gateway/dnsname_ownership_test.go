package main

import (
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func requireNameNODATA(t *testing.T, query, reply []byte) {
	t.Helper()
	q := parseReply(t, query).Questions[0]
	requireDDR(t, query, reply, ddrWant{authority: []string{q.Name.String() + " 300 IN SOA localhost. nobody.invalid. 1 3600 1200 604800 300"}})
}

// The controlled decider deliberately has public answers: forwarding is observable, never an Internet lookup.
func publicNameAnswer(q decidedQuery) []byte {
	var request dnsmessage.Message
	if err := request.Unpack(q.wire); err != nil {
		panic(err)
	}
	ask := request.Questions[0]
	msg := replyTo(request.Header, ask)
	rr := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: ask.Name, Class: dnsmessage.ClassINET, TTL: 60}}
	if ask.Type == dnsmessage.TypeA {
		rr.Body = &dnsmessage.AResource{A: [4]byte{9, 9, 9, 9}}
	} else {
		rr.Body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2606:4700:4700::1111").As16()}
	}
	msg.Answers = []dnsmessage.Resource{rr}
	wire, err := msg.Pack()
	if err != nil {
		panic(err)
	}
	return wire
}

func TestNameOwnershipMissingFamiliesNeverEscapeOnWire(t *testing.T) {
	for _, row := range []struct {
		label, value, positiveIP string
		missing, positive        dnsmessage.Type
	}{
		{"v4-only", "127.0.0.1=172.16.53.53", "172.16.53.53", dnsmessage.TypeAAAA, dnsmessage.TypeA},
		{"v6-only", "127.0.0.1=fd00:53::1", "fd00:53::1", dnsmessage.TypeA, dnsmessage.TypeAAAA},
		{"all-unavailable-A", "127.0.0.1=", "", dnsmessage.TypeA, 0},
		{"all-unavailable-AAAA", "127.0.0.1=", "", dnsmessage.TypeAAAA, 0},
	} {
		for _, tr := range transports {
			t.Run(row.label+"/"+tr.name, func(t *testing.T) {
				names := mustNames(t, "fw.example.lan", row.value)
				r := newRig(t, rigConfig{acl: aclMixed, beforeServe: func(g *gateway) { g.names = names }})
				r.autoAnswer(publicNameAnswer)
				if row.positive != 0 {
					q := nameQuery(t, nameFQDN, row.positive)
					requireNameAnswer(t, q, r.roundTrip(tr, clientAllowed, q), nameFQDN, row.positiveIP)
				}
				q := nameQuery(t, nameFQDN, row.missing)
				requireNameNODATA(t, q, r.roundTrip(tr, clientAllowed, q))
				r.requireDeciderSawOnlyTheBarrier()
			})
		}
	}
	for _, tr := range transports {
		t.Run("unknown-local/"+tr.name, func(t *testing.T) {
			r := newRig(t, rigConfig{acl: aclMixed, beforeServe: func(g *gateway) {
				g.names = mustNames(t, "fw.example.lan", "127.0.0.2=")
			}})
			r.autoAnswer(publicNameAnswer)
			q := nameQuery(t, nameFQDN, dnsmessage.TypeA)
			got := parseReply(t, r.roundTrip(tr, clientAllowed, q))
			if len(got.Answers) != 1 || got.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{9, 9, 9, 9} {
				t.Fatalf("unknown LOCAL must receive controlled public decider answer, got %+v", got)
			}
			if seen := r.nextQuery(); string(seen.wire) != string(q) {
				t.Fatalf("decider query %x, want %x", seen.wire, q)
			}
		})
	}
}

func TestNameOwnershipScreenKeepsQuestionHeadersEDNSAndACL(t *testing.T) {
	for _, value := range []string{"10.0.0.1=10.0.0.1", "10.0.0.1=2001:db8::1", "10.0.0.1="} {
		for _, path := range screenPaths {
			t.Run(value+"/"+path.name, func(t *testing.T) {
				n := mustNames(t, "fw.example.lan", value)
				r := newNameRig(t, n)
				for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
					if (typ == dnsmessage.TypeA && strings.Contains(value, "=10.")) || (typ == dnsmessage.TypeAAAA && strings.Contains(value, "=2001:")) {
						continue
					}
					q := ddrQuery(t, 19, "Fw.EXAMPLE.lan.", typ, 1232)
					disp, reply := screenAs(r.g, "10.0.0.1", path.plain, path.udp, q)
					if disp != replyNow {
						t.Fatalf("known LOCAL disposition %v, want local reply", disp)
					}
					requireNameNODATA(t, q, reply)
					for _, mutate := range []func(*dnsmessage.Message){
						func(m *dnsmessage.Message) { m.Questions = append(m.Questions, m.Questions[0]) },
						func(m *dnsmessage.Message) { m.Questions[0].Class = dnsmessage.ClassCHAOS },
						func(m *dnsmessage.Message) { m.OpCode = 2 },
						func(m *dnsmessage.Message) { m.Response = true },
						func(m *dnsmessage.Message) { m.Questions[0].Type = dnsmessage.TypeMX },
						func(m *dnsmessage.Message) { m.Questions[0].Name = dnsmessage.MustNewName("other.example.lan.") },
					} {
						var m dnsmessage.Message
						if err := m.Unpack(q); err != nil {
							t.Fatal(err)
						}
						mutate(&m)
						wire, err := m.Pack()
						if err != nil {
							t.Fatal(err)
						}
						if got := n.answer(wire, netip.MustParseAddr("10.0.0.1"), path.udp); got != nil {
							t.Fatalf("invalid question got a local reply: %x", got)
						}
					}
					disp, reply = r.g.screen(netip.MustParseAddr(clientRefused), netip.MustParseAddr("10.0.0.1"), path.plain, path.udp, q)
					if disp != replyNow {
						t.Fatalf("refused disposition %v", disp)
					}
					requireRefused(t, q, reply)
				}
			})
		}
	}
}

func TestNameOwnershipEmptyCLIAndAtomicControlTransitions(t *testing.T) {
	for _, value := range []string{"127.0.0.1=", "::1=", "::ffff:127.0.0.1="} {
		if _, err := parse(t, "--dns-name", "fw.example.lan", "--dns-name-answer", value, "--", "decider"); err != nil {
			t.Errorf("owned-empty CLI %q: %v", value, err)
		}
	}
	k := newNamesCtlRig(t, "fw.example.lan", "10.0.0.1=192.0.2.7,2001:db8::7")
	for _, step := range []struct {
		body, a, aaaa string
		owned         bool
	}{
		{tableLine("10.0.0.1=192.0.2.7,2001:db8::7"), nameV4, nameV6, true},
		{tableLine("10.0.0.1=192.0.2.7"), nameV4, "", true},
		{tableLine("10.0.0.1="), "", "", true},
		{"", "", "", false},
	} {
		if got := k.send(t, addressTableFrame(step.body)); got != "ok" {
			t.Fatalf("push %q: %s", step.body, got)
		}
		check := func() {
			for _, row := range []struct {
				typ dnsmessage.Type
				ip  string
			}{{dnsmessage.TypeA, step.a}, {dnsmessage.TypeAAAA, step.aaaa}} {
				q := nameQuery(t, nameFQDN, row.typ)
				disp, reply := screenAs(k.r.g, "10.0.0.1", true, true, q)
				if !step.owned {
					requireDeciders(t, disp, reply, "empty table")
					continue
				}
				if disp != replyNow {
					t.Fatalf("owned LOCAL delegated after %q", step.body)
				}
				if row.ip == "" {
					requireNameNODATA(t, q, reply)
				} else {
					requireNameAnswer(t, q, reply, nameFQDN, row.ip)
				}
			}
		}
		check()
		for _, bad := range []string{"=", " 10.0.0.1=", "10.0.0.1= ", "10.0.0.1=,", "10.0.0.1=1.2.3.4,5.6.7.8", "10.0.0.1=2001:db8::1,2001:db8::2"} {
			body := tableLine("10.0.0.1=9.9.9.9") + "\n" + tableLine(bad)
			if got := k.send(t, addressTableFrame(body)); !strings.HasPrefix(got, "error:") {
				t.Fatalf("malformed %q accepted: %q", body, got)
			}
			check()
		}
		for _, body := range []string{tableLine("10.0.0.1=") + "\n" + tableLine("::ffff:10.0.0.1="), "unknown 10.0.0.1="} {
			if got := k.send(t, addressTableFrame(body)); !strings.HasPrefix(got, "error:") {
				t.Fatalf("bad body %q accepted: %q", body, got)
			}
			check()
		}
	}
}

// A seeded mutation loop over the decider's wire code (issue #3517, maintainer fuzz note; ported from
// tests/dns_proxy/test_seeded_fuzz.py (removed in #3791) when the Python decider went, issue #3791). Every input is a mutation of a
// well-formed message and the seed is fixed, so a failure reproduces exactly: each message names the seed and the step.
// Two properties: dnswire.Parse fails only with a *WireError, and a message it accepts encodes and parses again;
// Frontend.Resolve never panics, and its reply is nil or a message dnswire.Parse accepts. In Python "never raises" was an
// assertion; here a panic is the failure, and `go test` reports it with the step in the log line before it.
package decider

import (
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/dnswire"
)

const (
	seededSeed       = 3517
	seededIterations = 3000
	seededBlocked    = "blocked.example."
)

func seededSeedWires(t *testing.T) [][]byte {
	t.Helper()
	rr := func(text string) dnswire.RR {
		r, err := dnswire.RRFromText(text)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	reply := &dnswire.Message{
		ID: 0x1234, Flags: dnswire.QR | dnswire.RD | dnswire.RA,
		Questions:  []dnswire.Question{{Name: allowed, Qtype: dnswire.TYPE_A, Qclass: dnswire.CLASS_IN}},
		Answers:    []dnswire.RR{rr(allowed + " 300 IN CNAME target.example."), rr("target.example. 60 IN A 192.0.2.1")},
		Authority:  []dnswire.RR{rr("example. 60 IN SOA ns.example. hostmaster.example. 1 2 3 4 60")},
		Additional: []dnswire.RR{dnswire.MakeOpt(1232, true, nil)},
	}
	ede := []byte{0, 15, 0, 3, 'a', 'b', 'c'}
	return [][]byte{
		queryWire(t, seededBlocked, dnswire.RD),
		queryWire(t, allowed, dnswire.RD, dnswire.MakeOpt(512, false, nil)),
		queryWire(t, allowed, dnswire.RD|dnswire.CD, dnswire.MakeOpt(1232, true, nil)),
		queryWire(t, "long.label.example.", dnswire.RD, dnswire.MakeOpt(1232, false, ede)),
		encode(t, reply),
	}
}

// seededMutate makes between one and four random edits: bit and byte changes, truncation, insertion, header counts and
// compression pointers.
func seededMutate(rng *rand.Rand, wire []byte) []byte {
	data := append([]byte(nil), wire...)
	for range 1 + rng.IntN(4) {
		switch edit := rng.IntN(6); {
		case edit == 0 && len(data) > 0:
			data[rng.IntN(len(data))] ^= 1 << rng.IntN(8)
		case edit == 1 && len(data) > 0:
			data[rng.IntN(len(data))] = byte(rng.IntN(256))
		case edit == 2:
			data = data[:rng.IntN(len(data)+1)]
		case edit == 3:
			at := rng.IntN(len(data) + 1)
			insert := make([]byte, 1+rng.IntN(8))
			for i := range insert {
				insert[i] = byte(rng.IntN(256))
			}
			data = append(data[:at], append(insert, data[at:]...)...)
		case edit == 4 && len(data) >= 12:
			count := 4 + 2*rng.IntN(4) // QDCOUNT, ANCOUNT, NSCOUNT or ARCOUNT
			choices := []uint16{0, 1, 2, 8, 9, 0xFFFF, uint16(rng.IntN(0x10000))}
			binary.BigEndian.PutUint16(data[count:], choices[rng.IntN(len(choices))])
		default:
			at := rng.IntN(len(data) + 1)
			data = append(data[:at], append([]byte{0xC0, byte(rng.IntN(256))}, data[at:]...)...) // a pointer, maybe forward or looping
		}
	}
	return data
}

func TestSeededMutationParseFailsOnlyWithAWireErrorAndWhatItAcceptsEncodesAndParsesAgain(t *testing.T) {
	rng := rand.New(rand.NewPCG(seededSeed, seededSeed))
	seeds := seededSeedWires(t)
	accepted := 0
	for step := range seededIterations {
		wire := seededMutate(rng, seeds[rng.IntN(len(seeds))])
		message, err := dnswire.Parse(wire)
		if err != nil {
			var wireErr *dnswire.WireError
			if !errors.As(err, &wireErr) {
				t.Fatalf("seed %d step %d: Parse returned %T %v, want a *WireError, on %x", seededSeed, step, err, err, wire)
			}
			continue
		}
		accepted++
		again, err := dnswire.Encode(message)
		if err != nil {
			t.Fatalf("seed %d step %d: re-encoding an accepted message failed: %v, for %x", seededSeed, step, err, wire)
		}
		if _, err := dnswire.Parse(again); err != nil {
			t.Fatalf("seed %d step %d: the re-encoded message does not parse: %v, for %x", seededSeed, step, err, wire)
		}
	}
	if minimum := seededIterations / 10; accepted < minimum {
		t.Fatalf("%d of %d mutations parsed, at least %d needed: the property is not being tried", accepted, seededIterations, minimum)
	}
}

func TestSeededMutationResolveNeverPanicsAndItsReplyIsNilOrAMessage(t *testing.T) {
	rlQuietLog(t)
	dir := opManifestModule(t, []string{"python_blocking = true", "python_cname = true", "dnsbl_ipv4 = 10.10.10.1", "dnsbl_ipv6 = fd00::1"},
		map[string][]string{"feed.txt": {"blocked.example"}})
	f := openOK(t, Options{LogDir: testLogDir, ModuleDir: dir})
	rng := rand.New(rand.NewPCG(seededSeed, seededSeed))
	seeds := seededSeedWires(t)
	upstream := unboundAnswering192_0_2_77(t)
	// the gateway's forward gives no reply to a query Unbound cannot read; the stand-in does the same
	forward := func(wire []byte) []byte {
		if query, err := dnswire.Parse(wire); err != nil || len(query.Questions) == 0 {
			return nil
		}
		return upstream(wire)
	}
	transports := []string{"TCP", "UDP", "DoT", "DoH", "DoQ"}
	replies := 0
	for step := range seededIterations {
		wire := seededMutate(rng, seeds[rng.IntN(len(seeds))])
		t.Logf("seed %d step %d: %x", seededSeed, step, wire) // only shown with -v or on failure: the input a panic would name
		reply := f.Resolve(wire, testClient, forward, transports[rng.IntN(len(transports))], "", "")
		if reply == nil {
			continue
		}
		if _, err := dnswire.Parse(reply); err != nil {
			t.Fatalf("seed %d step %d: Resolve answered %x, which does not parse: %v, for %x", seededSeed, step, reply, err, wire)
		}
		replies++
	}
	if minimum := seededIterations / 10; replies < minimum {
		t.Fatalf("%d of %d mutations got a reply, at least %d needed: the property is not being tried", replies, seededIterations, minimum)
	}
}

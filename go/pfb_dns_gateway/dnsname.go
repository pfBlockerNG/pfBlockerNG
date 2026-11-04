package main

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"

	"golang.org/x/net/dns/dnsmessage"
)

// issue #3694: the DNS name (--dns-name) is DDR's target and the one name the gateway answers itself: A and AAAA, from the
// address the query reached, after the ACL and DDR and before the decider. Every other name, type and query shape is the
// decider's, and so is a query that reached an address the table has no answer of that family for.

const nameTTL = ddrTTL

// nameAddrs is what a listen address answers for the name; the zero Addr is no answer of that family.
type nameAddrs struct{ v4, v6 netip.Addr }

// nameAnswers is what answers for the DNS name; built once at start. Only the table changes afterwards (the address table verb).
type nameAnswers struct {
	key   string                                   // the name as an absolute name in ASCII lower case, which a query's name folds to
	table atomic.Pointer[map[netip.Addr]nameAddrs] // by the address a query reached; replaced whole, never edited
}

// dnsName is the --dns-name value as an absolute name; one trailing dot is optional.
func dnsName(s string) (dnsmessage.Name, error) {
	bad := func(why string) error { return fmt.Errorf("--dns-name %q: %s", s, why) }
	host := strings.TrimSuffix(s, ".")
	if host == "" {
		return dnsmessage.Name{}, bad("empty name")
	}
	if len(host) > 253 {
		return dnsmessage.Name{}, bad("longer than 253 characters")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return dnsmessage.Name{}, bad("every label must be 1 to 63 bytes")
		}
	}
	return dnsmessage.NewName(host + ".")
}

// newNameAnswers is the answerer for name with the table the --dns-name-answer values make.
func newNameAnswers(name string, values []string) (*nameAnswers, error) {
	abs, err := dnsName(name)
	if err != nil {
		return nil, err
	}
	table, err := nameTable(values)
	if err != nil {
		return nil, fmt.Errorf("--dns-name-answer %w", err)
	}
	n := &nameAnswers{key: asciiLower(abs.String())}
	n.table.Store(&table)
	return n, nil
}

// asciiLower folds ASCII only: strings.ToLower would fold the Kelvin sign into a "k", which a query's name never does.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// nameTable is the table the values make; a value is `LOCAL=ADDR[,ADDR]`, as a flag and as a line of the address table verb.
// The first bad value is the error.
func nameTable(values []string) (map[netip.Addr]nameAddrs, error) {
	table := make(map[netip.Addr]nameAddrs, len(values))
	for _, v := range values {
		local, addrs, err := parseNameAnswer(v)
		if err != nil {
			return nil, fmt.Errorf("%.64q: %w", v, err)
		}
		if _, twice := table[local]; twice {
			return nil, fmt.Errorf("%.64q: %s is named twice", v, local)
		}
		table[local] = addrs
	}
	return table, nil
}

// parseNameAnswer reads LOCAL=ADDR[,ADDR]: IP addresses with no zone, IPv4-mapped ones unmapped, at most one of each family.
// LOCAL need not be among the ADDRs.
func parseNameAnswer(v string) (local netip.Addr, addrs nameAddrs, err error) {
	lhs, rhs, ok := strings.Cut(v, "=")
	if !ok {
		return local, addrs, errors.New("want LOCAL=ADDR[,ADDR]")
	}
	if local, err = parseNameIP(lhs); err != nil {
		return local, addrs, err
	}
	if rhs == "" {
		return local, addrs, errors.New("no address to answer with")
	}
	for _, s := range strings.Split(rhs, ",") {
		ip, err := parseNameIP(s)
		if err != nil {
			return local, addrs, err
		}
		slot := &addrs.v6
		if ip.Is4() {
			slot = &addrs.v4
		}
		if slot.IsValid() {
			return local, addrs, errors.New("two addresses of one family")
		}
		*slot = ip
	}
	return local, addrs, nil
}

func parseNameIP(s string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return ip, err
	}
	if ip.Zone() != "" {
		return ip, fmt.Errorf("%q has a zone", s)
	}
	return ip.Unmap(), nil
}

// parseAddressTable reads the body of the address table verb: lines separated by \n, no line empty, each led by the word
// that says what it is. The only word is dns-name-answer, whose value is a flag's.
func parseAddressTable(body []byte) (map[netip.Addr]nameAddrs, error) {
	var values []string
	if len(body) > 0 {
		for i, line := range strings.Split(string(body), "\n") {
			word, value, _ := strings.Cut(line, " ")
			if word != "dns-name-answer" {
				return nil, fmt.Errorf("line %d: %.64q does not start with dns-name-answer", i+1, line)
			}
			values = append(values, value)
		}
	}
	return nameTable(values)
}

// answer is the reply to wire when it is a query for the DNS name, A or AAAA, that reached local and the table has an
// address of that family for, and nil when it is not (it does not parse, is not opcode QUERY, has not exactly one question,
// is not class IN, or asks about another name). udp limits the size of the reply.
func (n *nameAnswers) answer(wire []byte, local netip.Addr, udp bool) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(wire)
	if err != nil || h.Response || h.OpCode != 0 {
		return nil
	}
	q, err := p.Question()
	if err != nil || q.Class != dnsmessage.ClassINET || (q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeAAAA) ||
		!asciiEqualFold(q.Name.Data[:q.Name.Length], n.key) {
		return nil
	}
	addrs := (*n.table.Load())[local.Unmap().WithZone("")]
	ip := addrs.v4
	if q.Type == dnsmessage.TypeAAAA {
		ip = addrs.v6
	}
	if !ip.IsValid() {
		return nil
	}
	if _, err := p.Question(); err != dnsmessage.ErrSectionDone {
		return nil
	}
	size, edns := clientOPT(&p)

	rr := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: nameTTL}}
	if ip.Is4() {
		rr.Body = &dnsmessage.AResource{A: ip.As4()}
	} else {
		rr.Body = &dnsmessage.AAAAResource{AAAA: ip.As16()}
	}
	msg := replyTo(h, q)
	msg.Answers = []dnsmessage.Resource{rr}
	return packReply(wire, msg, size, edns, udp)
}

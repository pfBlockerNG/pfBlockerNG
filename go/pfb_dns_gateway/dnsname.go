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
// decider's, and so is a query that reached an address without a table entry. An owned entry's absent family gets NODATA.

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
// LOCAL= owns the name with no addresses. The first bad value is the error.
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
// LOCAL need not be among the ADDRs; an empty RHS owns both families with NODATA.
func parseNameAnswer(v string) (local netip.Addr, addrs nameAddrs, err error) {
	lhs, rhs, ok := strings.Cut(v, "=")
	if !ok {
		return local, addrs, errors.New("want LOCAL=ADDR[,ADDR]")
	}
	if local, err = parseNameIP(lhs); err != nil {
		return local, addrs, err
	}
	if rhs == "" {
		return local, addrs, nil
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

// addressTable is what the address table verb's body holds: the name answers by the address a query reached, and the addresses
// DDR advertises DoH on without a port.
type addressTable struct {
	names  map[netip.Addr]nameAddrs
	doh443 map[netip.Addr]struct{}
}

// parseAddressTable reads the body of the address table verb: lines separated by \n, no line empty, each led by the word that
// says what it is. `dns-name-answer` carries a flag's value of --dns-name-answer, `ddr-doh-443` an address as --ddr-doh-443
// takes it. The first bad line is the error, and no table is made of a body that has one.
func parseAddressTable(body []byte) (addressTable, error) {
	var answers []string
	doh443 := map[netip.Addr]struct{}{}
	if len(body) > 0 {
		for i, line := range strings.Split(string(body), "\n") {
			word, value, _ := strings.Cut(line, " ")
			switch word {
			case "dns-name-answer":
				answers = append(answers, value)
			case "ddr-doh-443":
				ip, err := parseNameIP(value)
				if err != nil {
					return addressTable{}, fmt.Errorf("line %d: %.64q: %w", i+1, line, err)
				}
				doh443[ip] = struct{}{}
			default:
				return addressTable{}, fmt.Errorf("line %d: %.64q does not start with dns-name-answer or ddr-doh-443", i+1, line)
			}
		}
	}
	names, err := nameTable(answers)
	if err != nil {
		return addressTable{}, err
	}
	return addressTable{names: names, doh443: doh443}, nil
}

// answer replies to exactly one IN QUERY for the DNS name, A or AAAA, at an owned local address; an absent family gets
// NOERROR/NODATA with an SOA for negative caching. Other names, types, query shapes and unknown locals return nil.
// udp limits the size of the reply.
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
	addrs, owned := (*n.table.Load())[local.Unmap().WithZone("")]
	if !owned {
		return nil
	}
	ip := addrs.v4
	if q.Type == dnsmessage.TypeAAAA {
		ip = addrs.v6
	}
	if _, err := p.Question(); err != dnsmessage.ErrSectionDone {
		return nil
	}
	size, edns := clientOPT(&p)
	msg := replyTo(h, q)
	if !ip.IsValid() {
		msg.Authorities = []dnsmessage.Resource{soaRecord(q.Name)}
		return packReply(wire, msg, size, edns, udp)
	}

	rr := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: nameTTL}}
	if ip.Is4() {
		rr.Body = &dnsmessage.AResource{A: ip.As4()}
	} else {
		rr.Body = &dnsmessage.AAAAResource{AAAA: ip.As16()}
	}
	msg.Answers = []dnsmessage.Resource{rr}
	return packReply(wire, msg, size, edns, udp)
}

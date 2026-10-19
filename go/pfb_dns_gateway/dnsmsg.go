package main

import "golang.org/x/net/dns/dnsmessage"

// optTCPKeepalive is the option code of edns-tcp-keepalive (RFC 7828), which RFC 9250 5.5.2 forbids in DoQ.
const optTCPKeepalive = 11

// hasTCPKeepalive reports whether wire has an OPT record with the edns-tcp-keepalive option. A message that does not
// parse says no: the decider has its own checks for those.
func hasTCPKeepalive(wire []byte) bool {
	var p dnsmessage.Parser
	if _, err := p.Start(wire); err != nil || p.SkipAllQuestions() != nil || p.SkipAllAnswers() != nil || p.SkipAllAuthorities() != nil {
		return false
	}
	for {
		h, err := p.AdditionalHeader()
		if err != nil {
			return false
		}
		if h.Type != dnsmessage.TypeOPT {
			if p.SkipAdditional() != nil {
				return false
			}
			continue
		}
		opt, err := p.OPTResource()
		if err != nil {
			return false
		}
		for _, o := range opt.Options {
			if o.Code == optTCPKeepalive {
				return true
			}
		}
	}
}

// buildRefused answers a client the gateway refuses itself (Resolver ACL `refuse`), as Unbound would.
func buildRefused(query []byte) []byte { return buildError(query, dnsmessage.RCodeRefused) }

// buildServfail answers a client when no decision arrived in time.
func buildServfail(query []byte) []byte { return buildError(query, dnsmessage.RCodeServerFailure) }

// buildError keeps the id, opcode, RD and CD of the query, sets QR and RA, and echoes the first question; a
// question that does not parse leaves the reply header-only. A packet without a header gets no reply (nil).
func buildError(query []byte, rcode dnsmessage.RCode) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return nil
	}
	msg := dnsmessage.Message{Header: dnsmessage.Header{
		ID: h.ID, Response: true, OpCode: h.OpCode, RecursionDesired: h.RecursionDesired,
		RecursionAvailable: true, CheckingDisabled: h.CheckingDisabled, RCode: rcode,
	}}
	if q, err := p.Question(); err == nil {
		msg.Questions = []dnsmessage.Question{q}
	}
	out, err := msg.Pack()
	if err != nil { // a question the packer rejects: say nothing about it
		msg.Questions = nil
		out, _ = msg.Pack()
	}
	return out
}

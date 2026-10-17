package main

import "golang.org/x/net/dns/dnsmessage"

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

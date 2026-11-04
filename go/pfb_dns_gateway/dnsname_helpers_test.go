package main

import (
	"encoding/binary"
	"slices"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// The wire side of the issue #3694 tests: queries, the check of a name answer, and the address-table verb's frame. Nothing
// here names a symbol of the gateway, so it reads the same against any build of it.

const (
	nameFQDN = "fw.example.lan."
	nameV4   = "192.0.2.7" // documentation addresses: never an address the rig is on
	nameV6   = "2001:db8::7"
)

func nameQuery(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	return ddrQuery(t, 0x3694, name, typ, 0)
}

// requireNameAnswer requires the reply to be a name answer: header, question and sections as the contract has them (NOERROR,
// AA, RA, RD and CD copied, the question as asked), one record of owner and addr with a TTL of 300, nothing else.
func requireNameAnswer(t *testing.T, query, reply []byte, owner, addr string) {
	t.Helper()
	requireDDR(t, query, reply, ddrWant{answers: []string{ddrAddrRR(owner, addr)}})
}

// The address-table verb: FF FF FF FB, a 4-byte big-endian length (0 to 64 KiB) and that many bytes of
// `dns-name-answer LOCAL=ADDR[,ADDR]` lines separated by \n.
var addressTableVerb = []byte{0xff, 0xff, 0xff, 0xfb}

func addressTableFrame(body string) []byte {
	return append(binary.BigEndian.AppendUint32(slices.Clone(addressTableVerb), uint32(len(body))), body...)
}

func tableLine(value string) string { return "dns-name-answer " + value }

package geoip

import "testing"

// Where glibc's C.UTF-8 and FreeBSD's differ, the reader takes FreeBSD's (the appliance's libc, RFC 3629): a four-byte
// sequence past U+10FFFF is not a character, so the line ending before it is what PHP finds there; a valid four-byte
// character after the "\r" makes the "\r" no line ending. The PHP-held table cannot carry these rows, glibc PHP reads
// them the other way.
func TestTheLineEndingFollowsFreeBSDsUTF8(t *testing.T) {
	for in, want := range map[string]string{
		"a\r\xf4\x90\x80\x80": "a\r\xf4\x90\x80", // past U+10FFFF: the "\r" ends the line, one byte comes off
		"a\r\xf5\x80\x80\x80": "a\r\xf5\x80\x80",
		"a\r\xf4\x8f\xbf\xbf": "a\r\xf4\x8f\xbf\xbf", // U+10FFFF is a character: no line ending
		"a\r\xf0\x9f\x98\x80": "a\r\xf0\x9f\x98\x80",
	} {
		if got := in[:lineEnd(in)]; got != want {
			t.Errorf("%q: line %q, want %q", in, got, want)
		}
	}
}

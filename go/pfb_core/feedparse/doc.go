// Package feedparse is Core's feed content stage (issue #3906, map #3813): it turns the bytes of a downloaded feed into
// the IP entries or DNSBL rows today's PHP and Python produce, line for line. The parity corpus in testdata/ pins every
// result; the PHP runners under tests/php replay the same corpus against the old path until the cutover removes it.
//
// The per-line functions (Normalize, ParseIPLine, DNSBLParser.Line) are the stage's core. Around them sit the per-feed
// pieces the PHP download loops keep (issue #3976), in the order a feed passes through them: NormalizeFile builds and caches
// the .norm of a downloaded .orig, RunPreScript runs a list's script on a staged copy of it, and ParseIPFeed or
// ParseDNSBLFeed reads the result to the files the next stage reads, handing what the old loops log to a Sink as it goes; the
// empty-feed probe ParseIPFeed needs is the caller's, CountContent of the raw .orig. Nothing in Core calls them yet.
package feedparse

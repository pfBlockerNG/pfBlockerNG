package feedparse

import (
	"io"
)

// FailRecord is one parse-error record of a feed (pfb_parse_fail_log()): the line number, the line as the parser shows it
// ("null" when it has none) and the raw line without its trailing CR and LF.
type FailRecord struct {
	LineNo    int
	Line, Raw string
}

// Placeholder outcomes of ParseIPFeed.
const (
	PlaceholderEmpty      = "empty"      // the feed had no content line and yielded no entry
	PlaceholderSuppressed = "suppressed" // Suppression dropped every IPv6 entry
)

// IPFeed is what the IP loop keeps of one feed: the entry count, the failed lines, whether Suppression dropped valid IPv6
// entries, the placeholder written instead of an empty result ("" for none), the parse-error records and the parser's notices.
type IPFeed struct {
	Entries, ParseFail int
	Suppressed         bool
	Placeholder        string
	Details            []FailRecord
	Messages           []string
}

// ParseIPFeed is pfb_ip_parse_feed() and the empty-feed block after it, over the whole feed r: every entry goes to out, one
// per line, and so does the placeholder when there is no entry (ph is the Placeholder IP Address setting).
func ParseIPFeed(r io.Reader, cfg IPConfig, ph string, out io.Writer) (IPFeed, error) {
	return IPFeed{}, nil
}

// DNSBLFeed is what the DNSBL loop keeps of one feed: the rows written, the IPs found per family (de-duplicated, in the order
// first seen), whether any was found, the strict-scheme skips, whether the feed ended at the hpHosts marker and the
// parse-error records.
type DNSBLFeed struct {
	Rows          int
	IP4, IP6      []string
	UpdateIP      bool
	SchemeSkipped int
	Stopped       bool
	Details       []FailRecord
}

// ParseDNSBLFeed is pfb_dnsbl_parse_feed() and the IP de-duplication after it, over the whole feed r: every row goes to out as
// an NDJSON line.
func ParseDNSBLFeed(r io.Reader, cfg DNSBLConfig, out io.Writer) (DNSBLFeed, error) {
	return DNSBLFeed{}, nil
}

package feedparse

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
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
// per line, and so does the placeholder when there is no entry (ph is the Placeholder IP Address setting). Lines are read as
// fgets() reads them. A feed that cannot be read to its end or written whole is an error and no placeholder: the caller keeps
// its last known-good list.
//
// The placeholder is written when the feed has bytes but no content line (see isContentLine) and no entry, unless the list is
// custom, or, for an IPv6 list, when Suppression dropped every entry. The old path probes the raw .orig for content, or the
// staged copy after a pre-script; this counts the text it parses.
func ParseIPFeed(r io.Reader, cfg IPConfig, ph string, out io.Writer) (IPFeed, error) {
	var feed IPFeed
	var size int64
	content, lineNo := 0, 0
	w := bufio.NewWriter(out)
	err := eachLine(r, func(line string) error {
		lineNo++
		size += int64(len(line))
		if isContentLine(line) {
			content++
		}
		l := ParseIPLine(line, cfg)
		for _, entry := range l.Entries {
			w.WriteString(entry)
			if err := w.WriteByte('\n'); err != nil {
				return err
			}
			feed.Entries++
		}
		feed.Suppressed = feed.Suppressed || l.Suppressed
		feed.ParseFail += l.ParseFail
		feed.Messages = append(feed.Messages, l.Messages...)
		if l.DetailedParseFail {
			feed.Details = append(feed.Details, FailRecord{LineNo: lineNo, Line: nullIfEmpty(l.Line), Raw: rawLine(line)})
		}
		return nil
	})
	if err != nil {
		return feed, err
	}
	switch {
	case feed.Entries > 0:
	case !cfg.Custom && size > 0 && content == 0:
		feed.Placeholder = PlaceholderEmpty
	case feed.Suppressed && cfg.VType == "_v6":
		feed.Placeholder = PlaceholderSuppressed
	}
	if feed.Placeholder != "" {
		if cfg.VType == "_v6" {
			w.WriteString("::")
		}
		w.WriteString(ph)
		w.WriteByte('\n')
	}
	return feed, w.Flush()
}

// isContentLine is the empty-feed probe's line test (pfb_ip_feed_content_count()): a line that is not blank and does not start,
// after any whitespace, with '#', ';', '!' or '//'. Whitespace is ASCII, as in grep's C locale.
func isContentLine(line string) bool {
	line = strings.TrimLeft(line, " \t\n\v\f\r")
	return line != "" && !strings.ContainsRune("#;!", rune(line[0])) && !strings.HasPrefix(line, "//")
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

var errFeedEnd = errors.New("end of feed")

// ParseDNSBLFeed is pfb_dnsbl_parse_feed() and the IP de-duplication after it, over the whole feed r: every row goes to out as
// an NDJSON line (pfb_dnsbl_ndjson_emit_row()), and the hpHosts end marker ends the feed.
func ParseDNSBLFeed(r io.Reader, cfg DNSBLConfig, out io.Writer) (DNSBLFeed, error) {
	var feed DNSBLFeed
	p := NewDNSBLParser(cfg)
	seen := map[string]bool{}
	w := bufio.NewWriter(out)
	var row []byte
	lineNo := 0
	// array_unique(): the first of equal strings stays, in order; the two families cannot share a string.
	collect := func(dst *[]string, ips []string) {
		for _, ip := range ips {
			if !seen[ip] {
				seen[ip] = true
				*dst = append(*dst, ip)
			}
		}
	}
	err := eachLine(r, func(line string) error {
		lineNo++
		l := p.Line(line)
		if l.Stop {
			feed.Stopped = true
			return errFeedEnd
		}
		for _, f := range l.Fail {
			feed.Details = append(feed.Details, FailRecord{LineNo: lineNo, Line: f, Raw: rawLine(line)})
		}
		collect(&feed.IP4, l.IP4)
		collect(&feed.IP6, l.IP6)
		feed.UpdateIP = feed.UpdateIP || len(l.IP4) > 0 || len(l.IP6) > 0
		feed.SchemeSkipped += l.SchemeSkipped
		for _, r := range l.Rows {
			row = appendRow(row[:0], r)
			if _, err := w.Write(row); err != nil {
				return err
			}
			feed.Rows++
		}
		return nil
	})
	if err != nil && !errors.Is(err, errFeedEnd) {
		return feed, err
	}
	return feed, w.Flush()
}

// appendRow appends the NDJSON line of a row, byte for byte what json_encode() writes with JSON_UNESCAPED_SLASHES and
// JSON_UNESCAPED_UNICODE: ["d","text"] or ["a","text"] and a newline. The text is valid UTF-8 (see rowText).
func appendRow(b []byte, r DNSBLRow) []byte {
	kind := byte('d')
	if r.ABP {
		kind = 'a'
	}
	b = append(b, '[', '"', kind, '"', ',', '"')
	for _, c := range r.Text {
		switch {
		case c == '"' || c == '\\':
			b = append(b, '\\', byte(c))
		case c == '\b':
			b = append(b, '\\', 'b')
		case c == '\f':
			b = append(b, '\\', 'f')
		case c == '\n':
			b = append(b, '\\', 'n')
		case c == '\r':
			b = append(b, '\\', 'r')
		case c == '\t':
			b = append(b, '\\', 't')
		case c < 0x20 || c == 0x2028 || c == 0x2029: // U+2028 and U+2029 stay escaped under JSON_UNESCAPED_UNICODE
			b = append(b, '\\', 'u', hexDigits[c>>12&0xf], hexDigits[c>>8&0xf], hexDigits[c>>4&0xf], hexDigits[c&0xf])
		default:
			b = utf8.AppendRune(b, c)
		}
	}
	return append(b, '"', ']', '\n')
}

const hexDigits = "0123456789abcdef"

// eachLine calls f with every line of r as fgets() reads it: split at LF only (a lone CR is no line end), the LF kept, a last
// line without one kept, whatever the length. A read error ends the read before the unfinished line is used.
func eachLine(r io.Reader, f func(line string) error) error {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return err
		}
		if line != "" {
			if ferr := f(line); ferr != nil {
				return ferr
			}
		}
		if err == io.EOF {
			return nil
		}
	}
}

// rawLine is a line as pfb_parse_fail_log() shows it: without its trailing CR and LF characters.
func rawLine(line string) string { return strings.TrimRight(line, "\r\n") }

// nullIfEmpty is pfb_parse_fail_log()'s line field for the IP loop: only the empty string becomes "null" ("0" stays).
func nullIfEmpty(line string) string {
	if line == "" {
		return "null"
	}
	return line
}

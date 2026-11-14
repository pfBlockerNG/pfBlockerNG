package feedparse

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"strings"
)

// FailRecord is one parse-error record of a feed (pfb_parse_fail_log()): the line number, the line as the parser shows it
// ("null" when it has none) and the raw line without its trailing CR and LF.
type FailRecord struct {
	LineNo    int
	Line, Raw string
}

// Sink receives what the feed loops log, as the feed is read: the parser's notices (pfb_logger()) in order, and each parse-error
// record (pfb_parse_fail_log()). The PHP loops write both to log files as they go, and so nothing is kept for the result to
// carry: a hostile feed of failing lines costs the callbacks, not memory. Either callback may be nil.
type Sink struct {
	Message func(msg string)
	Fail    func(rec FailRecord)
}

func (s Sink) message(msg string) {
	if s.Message != nil {
		s.Message(msg)
	}
}

func (s Sink) fail(rec FailRecord) {
	if s.Fail != nil {
		s.Fail(rec)
	}
}

// Placeholder outcomes of ParseIPFeed.
const (
	PlaceholderEmpty      = "empty"      // the feed had no content line and yielded no entry
	PlaceholderSuppressed = "suppressed" // Suppression dropped every IPv6 entry
)

// NoProbe is the content argument of ParseIPFeed when there was nothing to count: no file to probe, or one of zero bytes.
const NoProbe = -1

// IPFeed is what the IP loop keeps of one feed: the entry count, the failed lines, whether Suppression dropped valid IPv6
// entries and the placeholder written instead of an empty result ("" for none).
type IPFeed struct {
	Entries, ParseFail int
	Suppressed         bool
	Placeholder        string
}

// ParseIPFeed is pfb_ip_parse_feed() and the empty-feed block after it, over the whole feed r: every entry goes to out, one
// per line, and so does the placeholder when there is no entry (ph is the Placeholder IP Address setting). Lines up to 1 MiB follow
// fgets(); a longer one is skipped to its newline and recorded as a parse failure. Notices and parse-error records go to the sink as read.
// A feed that cannot be read to its end or written whole is an error and no placeholder: the caller keeps its last known-good list, and what out received
// until then is partial, so the caller writes to a temporary file and renames it once there is no error.
//
// content is the empty-feed probe, the caller's: CountContent of the file the old path probes, the raw .orig, or the staged
// copy after a pre-script. What r holds says nothing about it (a .norm has lost its BOM and control characters, which are
// content to the probe). The placeholder is written when content is 0 and there is no entry, unless the list is custom, or, for
// an IPv6 list, when Suppression dropped every entry.
func ParseIPFeed(r io.Reader, cfg IPConfig, ph string, content int, out io.Writer, sink Sink) (IPFeed, error) {
	var feed IPFeed
	lineNo := 0
	w := bufio.NewWriter(out)
	err := eachLine(r, func(line string, overlong, _ bool) error {
		lineNo++
		if overlong {
			feed.ParseFail++
			sink.fail(FailRecord{LineNo: lineNo, Line: "line over 1 MiB", Raw: "line over 1 MiB"})
			return nil
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
		for _, msg := range l.Messages {
			sink.message(msg)
		}
		if l.DetailedParseFail {
			sink.fail(FailRecord{LineNo: lineNo, Line: nullIfEmpty(l.Line), Raw: rawLine(line)})
		}
		return nil
	})
	if err != nil {
		return feed, err
	}
	switch {
	case feed.Entries > 0:
	case !cfg.Custom && content == 0:
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

// CountContent is the empty-feed probe, pfb_ip_feed_content_count() behind the old path's file_exists() and filesize() > 0 gate:
// the number of content lines (see isContentLine) of the file at path, or NoProbe when it is missing, empty or cannot be read to
// its end, which is no placeholder.
func CountContent(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return NoProbe
	}
	defer f.Close()
	n, hasBytes := 0, false
	err = eachLine(f, func(line string, overlong, content bool) error {
		if overlong {
			hasBytes = true
			if content {
				n++
			}
			return nil
		}
		hasBytes = hasBytes || len(line) > 0
		if isContentLine(line) {
			n++
		}
		return nil
	})
	if err != nil || !hasBytes {
		return NoProbe
	}
	return n
}

// isContentLine is the empty-feed probe's line test (pfb_ip_feed_content_count()): a line that is not blank and does not start,
// after any whitespace, with '#', ';', '!' or '//'. Whitespace is ASCII, as in grep's C locale.
func isContentLine(line string) bool {
	line = strings.TrimLeft(line, " \t\n\v\f\r")
	return line != "" && !strings.ContainsRune("#;!", rune(line[0])) && !strings.HasPrefix(line, "//")
}

// DNSBLFeed is what the DNSBL loop keeps of one feed: the rows written, the IPs found per family (de-duplicated, in the order
// first seen), whether any was found, the strict-scheme skips and whether the feed ended at the hpHosts marker.
type DNSBLFeed struct {
	Rows          int
	IP4, IP6      []string
	UpdateIP      bool
	SchemeSkipped int
	Stopped       bool
}

var errFeedEnd = errors.New("end of feed")

// ParseDNSBLFeed is pfb_dnsbl_parse_feed() and the IP de-duplication after it, over the whole feed r: every row goes to out as
// an NDJSON line (pfb_dnsbl_ndjson_emit_row()), the hpHosts end marker ends the feed, and the parser's notices and the
// parse-error records go to the sink as they come. A line over 1 MiB is skipped and recorded as a parse failure. A feed that cannot
// be read to its end or written whole is an error, and what out received until then is partial.

// The notices are those the old path logs from its line parser: an IP literal decoded, an IDN converted and a /0 CIDR clamped to
// its single host. Its ABP IPv4 regex expansion has a fourth, for a thrown Throwable that only its test seam can raise; Core's
// expansion cannot throw, so has none.
func ParseDNSBLFeed(r io.Reader, cfg DNSBLConfig, out io.Writer, sink Sink) (DNSBLFeed, error) {
	var feed DNSBLFeed
	p := NewDNSBLParser(cfg)
	seen4 := make(map[[5]byte]struct{})
	seen6 := make(map[[17]byte]struct{})
	seenZone := make(map[netip.Prefix]struct{})
	w := bufio.NewWriter(out)
	emit := newRowEncoder(w)
	lineNo := 0
	// Compact keys keep array_unique()'s first-seen order without retaining address strings in the index.
	collect := func(dst *[]string, ips []string) error {
		for _, ip := range ips {
			var prefix netip.Prefix
			var err error
			if strings.IndexByte(ip, '/') >= 0 {
				prefix, err = netip.ParsePrefix(ip)
			} else {
				var addr netip.Addr
				addr, err = netip.ParseAddr(ip)
				if err == nil {
					prefix = netip.PrefixFrom(addr, addr.BitLen())
				}
			}
			if err != nil {
				return err
			}
			addr := prefix.Addr()
			switch {
			case addr.Zone() != "":
				if _, exists := seenZone[prefix]; exists {
					continue
				}
				seenZone[prefix] = struct{}{}
			case addr.Is4():
				bytes := addr.As4()
				key := [5]byte{byte(prefix.Bits()), bytes[0], bytes[1], bytes[2], bytes[3]}
				if _, exists := seen4[key]; exists {
					continue
				}
				seen4[key] = struct{}{}
			default:
				bytes := addr.As16()
				key := [17]byte{byte(prefix.Bits())}
				copy(key[1:], bytes[:])
				if _, exists := seen6[key]; exists {
					continue
				}
				seen6[key] = struct{}{}
			}
			*dst = append(*dst, ip)
		}
		return nil
	}
	err := eachLine(r, func(line string, overlong, _ bool) error {
		lineNo++
		if overlong {
			sink.fail(FailRecord{LineNo: lineNo, Line: "line over 1 MiB", Raw: "line over 1 MiB"})
			return nil
		}
		l := p.Line(line)
		for _, msg := range l.Messages {
			sink.message(msg)
		}
		if l.Stop {
			feed.Stopped = true
			return errFeedEnd
		}
		for _, f := range l.Fail {
			sink.fail(FailRecord{LineNo: lineNo, Line: f, Raw: rawLine(line)})
		}
		if err := collect(&feed.IP4, l.IP4); err != nil {
			return err
		}
		if err := collect(&feed.IP6, l.IP6); err != nil {
			return err
		}
		feed.UpdateIP = feed.UpdateIP || len(l.IP4) > 0 || len(l.IP6) > 0
		feed.SchemeSkipped += l.SchemeSkipped
		for _, row := range l.Rows {
			if err := emit(row); err != nil {
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

// newRowEncoder returns the writer of a row as pfb_dnsbl_ndjson_emit_row() writes it, json_encode() with JSON_UNESCAPED_SLASHES
// and JSON_UNESCAPED_UNICODE: an NDJSON line ["d","text"] or ["a","text"]. The text is valid UTF-8 (see rowText). Like PHP under
// JSON_UNESCAPED_UNICODE, encoding/json still escapes U+2028 and U+2029; only its HTML escaping has to go.
func newRowEncoder(w io.Writer) func(DNSBLRow) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return func(r DNSBLRow) error {
		kind := "d"
		if r.ABP {
			kind = "a"
		}
		return enc.Encode([2]string{kind, r.Text})
	}
}

const maxFeedLineBytes = 1 << 20

// eachLine bounds stored lines at 1 MiB including LF, drains longer lines, and calls f once per line. A read error discards the
// unfinished line, as fgets()'s caller does.
func eachLine(r io.Reader, f func(line string, overlong, content bool) error) error {
	br := bufio.NewReaderSize(r, 64<<10)
	line := make([]byte, 0, 64<<10)
	var first, second byte
	haveFirst, haveSecond, overlong := false, false, false
	for {
		part, err := br.ReadSlice('\n')
		if err != nil && err != io.EOF && err != bufio.ErrBufferFull {
			return err
		}
		for _, c := range part {
			if c == '\n' {
				break
			}
			if !haveFirst {
				if c == ' ' || c == '\t' || c == '\v' || c == '\f' || c == '\r' {
					continue
				}
				first, haveFirst = c, true
				if c != '/' {
					break
				}
			} else if first == '/' && !haveSecond {
				second, haveSecond = c, true
				break
			}
		}
		if !overlong {
			if len(part) > maxFeedLineBytes-len(line) {
				overlong, line = true, nil
			} else {
				line = append(line, part...)
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if len(line) > 0 || overlong {
			content := haveFirst && first != '#' && first != ';' && first != '!' && !(first == '/' && haveSecond && second == '/')
			if ferr := f(string(line), overlong, content); ferr != nil {
				return ferr
			}
		}
		if err == io.EOF {
			return nil
		}
		line = line[:0]
		first, second = 0, 0
		haveFirst, haveSecond, overlong = false, false, false
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

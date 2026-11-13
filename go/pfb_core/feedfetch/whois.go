package feedfetch

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	whoisBudget = 1800 * time.Second // the whole batch, whoisbatchtimeout's default
	whoisLookup = 30 * time.Second   // one lookup at most
	asnMissing  = "Database ASN [ asn.csv ] not found. Register for IPinfo Token."
)

// WhoisRequest is one Domain/AS list as whoisconvert() receives it.
type WhoisRequest struct {
	List   string        // entries separated by a comma or a newline: a domain (it has a dot) or an AS number; blank entries are skipped
	IPv6   bool          // the list's family (vtype _v6): AAAA lookups and IPv6 ranges, else A and IPv4
	Budget time.Duration // the whole batch; zero is 1800 s (see WhoisBudget)
}

// WhoisResult is the outcome of Whois.
type WhoisResult struct {
	Found    bool     // at least one entry resolved: the published copy holds this run's entries
	Failed   bool     // the ".fail" marker was left: an entry failed or the batch ran out of time
	Log      string   // what whoisconvert() prints to the update log
	ErrorLog []string // the lines it also appends to error.log
	Reason   string   // set when the run was abandoned or a file could not be written; the published copy is not half-written
}

// WhoisBudget is the whoisbatchtimeout override as whoisconvert() reads it: whole seconds, digits only (leading zeros
// allowed) and above zero. Anything else is the default: empty, signed, spaced, zero, or past the largest integer the
// shell's test reads.
func WhoisBudget(override string) time.Duration {
	n, err := strconv.ParseInt(override, 10, 64)
	if err != nil || n <= 0 || !allIn(override, "0123456789") {
		return whoisBudget
	}
	if n > math.MaxInt64/int64(time.Second) {
		return math.MaxInt64
	}
	return time.Duration(n) * time.Second
}

// Whois is whoisconvert() in Core: it resolves a feed's Domain/AS list into the published copy ".orig". Every entry that
// resolves is kept, in order, whatever fails around it; a copy is never left half-built. Nothing resolving keeps the
// previous copy, or writes an empty one (one newline) when there is none. A failed entry, or a batch that ran out of
// time, leaves the ".fail" marker. A cancelled ctx abandons the run with every file untouched.
func (f *Fetcher) Whois(ctx context.Context, feed Feed, req WhoisRequest) WhoisResult {
	if !feed.valid() {
		return WhoisResult{Reason: "invalid feed name"}
	}
	now := f.Now
	if now == nil {
		now = time.Now
	}
	budget := req.Budget
	if budget <= 0 {
		budget = whoisBudget
	}
	start := now()
	b := &whoisBatch{f: f, ctx: ctx, ipv6: req.IPv6, started: start}
	b.log.WriteString("\n")
	expired := false
	// whoisconvert() turns the commas into newlines and reads a line per entry: both separate.
	for _, entry := range strings.FieldsFunc(req.List, func(r rune) bool { return r == ',' || r == '\n' }) {
		if ctx.Err() != nil {
			break
		}
		left := budget - now().Sub(start)
		if left <= 0 {
			expired = true
			break
		}
		if strings.Contains(entry, ".") {
			b.domain(entry, min(left, whoisLookup))
		} else {
			b.asn(entry)
		}
	}
	if err := ctx.Err(); err != nil {
		return WhoisResult{Reason: err.Error()}
	}
	if expired {
		b.errorLine(fmt.Sprintf("WHOIS batch [ %s ] TIMED OUT after %ds total; remaining Domain/AS entries skipped",
			feed.Name, int64(budget/time.Second)))
		b.failed = true
	}
	return b.publish(feed)
}

// whoisBatch is one Whois run's state.
type whoisBatch struct {
	f             *Fetcher
	ctx           context.Context
	ipv6          bool
	started       time.Time
	collected     bytes.Buffer // the new published copy
	log           strings.Builder
	errorLog      []string
	found, failed bool
}

// errorLine is a line for both the update log and error.log.
func (b *whoisBatch) errorLine(line string) {
	b.errorLog = append(b.errorLog, line)
	b.log.WriteString(line + "\n")
}

// domain looks the host up for the batch's family; only addresses of that family are kept.
func (b *whoisBatch) domain(host string, limit time.Duration) {
	network := "ip4"
	if b.ipv6 {
		network = "ip6"
	}
	fmt.Fprintf(&b.log, "  Collecting host IP: %s", host)
	ctx, cancel := context.WithTimeout(b.ctx, limit)
	addrs, err := b.f.lookup(ctx, network, host)
	cancel()
	var lines strings.Builder
	if err == nil {
		for _, a := range addrs {
			if (b.ipv6 && a.Is6()) || (!b.ipv6 && a.Is4()) {
				lines.WriteString(a.String() + "\n")
			}
		}
	}
	if lines.Len() == 0 {
		fmt.Fprintf(&b.log, "... Failed to resolve host [ %s ]", host)
		b.failed = true
		return
	}
	b.found = true
	fmt.Fprintf(&b.collected, "### Domain: %s ###\n%s", host, lines.String())
	b.log.WriteString("... completed\n")
}

// asn reads the AS's ranges of the batch's family from asn.csv, trying the first-use download when it is missing.
func (b *whoisBatch) asn(entry string) {
	ok := false
	if !regularFile(b.f.ASNCSV) && b.f.EnsureASN != nil {
		fmt.Fprintf(&b.log, "Downloading [ IPinfo databases ] [ %s ]", b.started.Format("2006-01-02 15:04:05"))
		b.f.EnsureASN(b.ctx)
		b.log.WriteString("... completed")
	}
	if !regularFile(b.f.ASNCSV) {
		b.errorLine(asnMissing)
	} else {
		// whoisconvert() deletes every A and S, wherever they stand (tr -d), before it asks for digits.
		number := strings.Map(func(r rune) rune {
			if strings.ContainsRune("AaSs", r) {
				return -1
			}
			return r
		}, entry)
		fmt.Fprintf(&b.log, "  Collecting ASN: AS%s", number)
		if number == "" || !allIn(number, "0123456789") {
			fmt.Fprintf(&b.log, "... Invalid ASN [ %s ]", entry)
			b.failed = true
			return
		}
		ranges := asnRanges(b.f.ASNCSV, number, b.ipv6)
		for _, r := range ranges {
			b.collected.WriteString(r + "\n")
		}
		ok = len(ranges) > 0
	}
	if !ok {
		b.log.WriteString("... Failed to collect ASN")
		b.failed = true
		return
	}
	b.found = true
}

// asnRanges is grep -F ",AS<n>," | cut -f1-2 | tr ',' '-', then the family filter: a line holding the pattern anywhere
// gives its first two fields as "start-end"; IPv4 keeps those without a colon, IPv6 those without a dot.
func asnRanges(path, number string, ipv6 bool) []string {
	in, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer in.Close()
	needle := []byte(",AS" + number + ",")
	var out []string
	// The real file has hundreds of thousands of rows: scan them as bytes and build a string only for a match.
	// shortcut: a row past 16 MiB ends the scan with no ranges, where grep reads any length; nothing asn.csv holds is near.
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if !bytes.Contains(line, needle) {
			continue
		}
		first := bytes.IndexByte(line, ',')
		second := first + 1 + bytes.IndexByte(line[first+1:], ',')
		span := strings.ReplaceAll(string(line[:second]), ",", "-")
		if (ipv6 && !strings.Contains(span, ".")) || (!ipv6 && !strings.Contains(span, ":")) {
			out = append(out, span)
		}
	}
	if sc.Err() != nil {
		return nil
	}
	return out
}

// publish writes the batch's outcome: the failure marker, then the published copy (or the previous one back).
func (b *whoisBatch) publish(feed Feed) WhoisResult {
	res := WhoisResult{Found: b.found, Failed: b.failed, ErrorLog: b.errorLog}
	orig, bk := feed.path(".orig"), feed.path(".bk")
	fail := func(reason string, err error) {
		if res.Reason == "" {
			res.Reason = reason + ": " + err.Error()
		}
	}
	if b.failed {
		if err := touch(feed.path(".fail")); err != nil {
			fail("failure marker could not be written", err)
		}
	}
	switch {
	case b.found:
		if err := writeAtomic(orig, b.collected.Bytes()); err != nil {
			res.Found = false
			fail("published copy could not be written", err) // the previous copy, or its backup, stays
		} else {
			os.Remove(bk)
		}
	case regularFile(orig):
		b.log.WriteString("... Restoring previous data\n")
		os.Remove(bk)
	case regularFile(bk):
		b.log.WriteString("... Restoring previous data\n")
		if err := os.Rename(bk, orig); err != nil {
			fail("previous copy could not be restored", err)
		}
	default:
		b.log.WriteString("... Creating empty file\n")
		if err := writeAtomic(orig, []byte("\n")); err != nil {
			fail("empty copy could not be written", err)
		}
	}
	res.Log = b.log.String()
	return res
}

func (f *Fetcher) lookup(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if f.Lookup != nil {
		return f.Lookup(ctx, network, host)
	}
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// touch creates the file or refreshes its time, as touch(1) does.
func touch(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	now := time.Now()
	return os.Chtimes(path, now, now)
}

// writeAtomic replaces path whole: the bytes are synced under a temporary name first, so a crash leaves the old copy or
// the new one, never part of one.
func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	if err := errors.Join(werr, serr, f.Close()); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

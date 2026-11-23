package ipset

import (
	"maps"
	"net/netip"
	"slices"
	"strings"
)

// PrepIn is the per-feed preprocess setting of a v4 feed: the three switches of pfb_ip_preprocess_args, DRep (the dedup token
// the per-feed reputation reads) and the reputation setting.
type PrepIn struct {
	Dup, Agg, Rep, DRep bool
	Reputation
}

// Stages is which per-feed stages ran: the /24 collapse of a full /24 (_255), the CIDR aggregation (_agg) and the reputation
// (_rep).
type Stages struct{ Full24, Aggregate, Rep bool }

// Prepped is a preprocessed feed: its rows, the reputation match list it wrote (nil for none) and the stages that ran.
type Prepped struct {
	Members, Match []string
	Ran            Stages
}

// Preprocess is pfb_ip_preprocess_args and the per-feed verb it names, in the order _255, _agg, _rep: _255 runs when Dup or Agg
// is on, _agg when Agg is, _rep when Rep is. With no stage selected the rows are the lines of members unchanged.
func Preprocess(members string, in PrepIn) Prepped {
	out := Prepped{Members: textRows(members), Ran: Stages{Full24: in.Dup || in.Agg, Aggregate: in.Agg, Rep: in.Rep}}
	if out.Ran.Full24 {
		out.Members = full24(out.Members)
	}
	if out.Ran.Aggregate {
		out.Members = CIDRAggregate(strings.Join(out.Members, "\n"))
	}
	if out.Ran.Rep {
		out.Members, out.Match = feedReputation(out.Members, in)
	}
	return out
}

// cut3 is cut -d '.' -f 1-3: the first three dot-separated fields of a row, fewer when it has fewer.
func cut3(row string) string {
	f := strings.SplitN(row, ".", 4)
	return strings.Join(f[:min(len(f), 3)], ".")
}

// isOctetPrefix reports whether s is digits and dots only, the shape a /24 key must have to be acted on.
func isOctetPrefix(s string) bool {
	return s != "" && strings.Trim(s, "0123456789.") == ""
}

// over is the /24 keys held by more than max rows that are octet prefixes, in byte order. any is whether a key of any shape is
// over max, which is what makes the shell act at all.
func over(count map[string]int, max int) (keys []string, any bool) {
	for k, n := range count {
		if n > max && k != "" {
			if any = true; isOctetPrefix(k) {
				keys = append(keys, k)
			}
		}
	}
	slices.Sort(keys)
	return keys, any
}

func sortUniq(rows []string) []string {
	rows = slices.Clone(rows)
	slices.Sort(rows)
	return slices.Compact(rows)
}

// in24 reports whether row is written under one of the /24 keys: the key, then a ".".
func in24(row string, keys map[string]bool) bool {
	k := cut3(row)
	return keys[k] && len(row) > len(k)
}

func keySet(keys []string) map[string]bool {
	set := make(map[string]bool, len(keys))
	for _, k := range keys {
		set[k] = true
	}
	return set
}

func cidr24(keys []string) []string {
	rows := make([]string, len(keys))
	for i, k := range keys {
		rows[i] = k + ".0/24"
	}
	return rows
}

// minus is rows without the ones remove selects, as the shell's awk filter leaves them: when nothing is selected the filter
// reads its empty first file as the second and prints nothing at all.
func minus(rows []string, remove func(string) bool) []string {
	kept := slices.DeleteFunc(slices.Clone(rows), remove)
	if len(kept) == len(rows) {
		return rows[:0:0]
	}
	return kept
}

// full24 is the _255 stage: a /24 key held by more than 253 rows becomes the one row "key.0/24".
func full24(rows []string) []string {
	count := map[string]int{}
	for _, r := range rows {
		count[cut3(r)]++
	}
	keys, any := over(count, 253)
	if !any {
		return rows
	}
	set := keySet(keys)
	return append(minus(rows, func(r string) bool { return in24(r, set) }), cidr24(keys)...)
}

// feedReputation is the _rep stage (reputation_max). An offender /24 outside the country list, or of unknown country, is
// blocked: with CCBlack "block" its rows become "key.0/24". The match list is written only for CCWhite "match" with DRep off.
func feedReputation(rows []string, in PrepIn) (members, match []string) {
	sorted := sortUniq(rows)
	count := map[string]int{}
	for _, r := range sorted {
		count[cut3(r)]++
	}
	white, black := strings.ToLower(in.CCWhite), strings.ToLower(in.CCBlack)
	var blocked, exempt []string
	keys, _ := over(count, in.Max)
	for _, key := range keys {
		cc := ""
		if in.Geo != nil {
			cc = in.Geo(key)
		}
		switch {
		case cc == "" || !listed(in.CC, cc):
			blocked = append(blocked, key)
		case white == "match" || black == "match":
			exempt = append(exempt, key)
		}
	}
	if len(exempt) > 0 && !in.DRep && white == "match" {
		match = cidr24(exempt)
		set := keySet(exempt)
		for _, r := range sorted {
			if in24(r, set) {
				match = append(match, "!"+r)
			}
		}
	}
	switch {
	case len(blocked) == 0:
		return rows, match
	case black == "block":
		set := keySet(blocked)
		rows = append(slices.DeleteFunc(sorted, func(r string) bool { return in24(r, set) }), cidr24(blocked)...)
	}
	return sortUniq(rows), match
}

// listed is whether cc is an entry of the comma-separated country list. Today's shell matches a substring, so an entry
// such as "A1_US" exempts US too (#4149).
func listed(list, cc string) bool { return slices.Contains(strings.Split(list, ","), cc) }

// RecomputeIn is one family's batch recompute. Feeds are the pristine per-feed snapshots in priority order, highest first (the
// caller resolves a missing snapshot); the first feed to list a row owns it. Master is the masterfile as it stands, both
// families. With Dedup off the feeds are copied and Master is returned unchanged. Placeholder keeps its /24 out of the offender
// count.
type RecomputeIn struct {
	Family      Family
	Feeds       []Feed
	Master      []string
	Dedup       bool
	Mode        RepMode
	Rep         Reputation
	Placeholder string
}

// RecomputeOut is the pass result. Lists are the surviving rows per feed, in Feeds order. Master is the new masterfile. The
// match lists are the reputation artifacts the pass writes (MatchExempt nil for none); DropRep and DropExempt name the previous
// ones it supersedes (none when GeoIP is unavailable, which keeps them).
type RecomputeOut struct {
	Lists       []List
	Master      []string
	MatchRep    []List
	MatchExempt []string
	DropRep     []string
	DropExempt  bool
}

// field1 is awk's $1: the first run of non-blank characters.
func field1(row string) string {
	row = strings.TrimLeft(row, " \t")
	if i := strings.IndexAny(row, " \t"); i >= 0 {
		return row[:i]
	}
	return row
}

// scanNum is sscanf's %u or %d at s[i:]: blanks skipped, an optional sign, then digits, kept to 32 bits as C stores them.
func scanNum(s string, i int) (v uint32, next int, ok bool) {
	for i < len(s) && (isSpace(s[i]) || s[i] == '\n') {
		i++
	}
	neg := false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	start := i
	var n uint64
	for ; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		if n = n*10 + uint64(s[i]-'0'); n > 1<<59 {
			n = 1<<60 | 0xffffffff // strtoul saturates: the stored 32 bits are all ones
		}
	}
	if i == start {
		return 0, i, false
	}
	if v = uint32(n); neg && n < 1<<59 {
		v = -v
	}
	return v, i, true
}

// scanQuad is sscanf's "%u.%u.%u.%u" at s[i:]; ok needs four numbers, valid that each is under 256.
func scanQuad(s string, i int) (ip uint32, next int, ok, valid bool) {
	valid = true
	for part := 0; part < 4; part++ {
		if part > 0 {
			if i >= len(s) || s[i] != '.' {
				return 0, i, false, false
			}
			i++
		}
		v, j, found := scanNum(s, i)
		if !found {
			return 0, i, false, false
		}
		valid = valid && v < 256
		ip, i = ip<<8|v&0xff, j
	}
	return ip, i, true, valid
}

// grepPattern reads a row as grepcidr 2.0 reads a pattern line: an IPv4 "a.b.c.d/len" (host bits cleared), "a.b.c.d - e.f.g.h"
// or "a.b.c.d", each number plain decimal and any text after it ignored; else an IPv6 address with an optional "/len". ok is
// false for a line it skips ("#" lines) or cannot read.
func grepPattern(line string) (r span, ok bool) {
	if line == "" || line[0] == '#' || line[0] == '\r' {
		return span{}, false
	}
	ip, i, found, valid := scanQuad(line, 0)
	if found && valid && i < len(line) && line[i] == '/' {
		if bits, _, ok := scanNum(line, i+1); ok {
			switch b := int32(bits); {
			case b == 0:
				return span{addrOf(0), addrOf(^uint32(0))}, true
			case b < 0 || b > 32:
				return span{}, false
			default:
				host := uint32(1)<<(32-b) - 1
				return span{addrOf(ip &^ host), addrOf(ip | host)}, true
			}
		}
	}
	if found && valid && strings.Contains(line, "-") {
		j := i
		for j < len(line) && (isSpace(line[j]) || line[j] == '\n') {
			j++
		}
		if j < len(line) && line[j] == '-' {
			if hi, _, found2, valid2 := scanQuad(line, j+1); found2 && valid2 {
				if hi < ip {
					return span{}, false
				}
				return span{addrOf(ip), addrOf(hi)}, true
			}
		}
	}
	if found {
		if valid {
			return span{addrOf(ip), addrOf(ip)}, true
		}
		return span{}, false
	}
	n := 0
	for n < len(line) && isV6Field(line[n]) {
		n++
	}
	a, err := netip.ParseAddr(line[:n])
	if err != nil || !a.Is6() || n > 45 {
		return span{}, false
	}
	bits := 128
	if n < len(line) && line[n] == '/' {
		if b, _, ok := scanNum(line, n+1); ok {
			if bits = int(int32(b)); bits < 0 || bits > 128 {
				return span{}, false
			}
		}
	}
	return prefixSpan(netip.PrefixFrom(a, bits)), true
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isV6Field(c byte) bool { return isAlnum(c) || c == '.' || c == ':' }

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// at is s[i], 0 past the end.
func at(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

// eachAddr calls f with every address grepcidr 2.0 finds on a row, wherever it stands: an IPv4 one where a digit has a "." within
// three characters and the run of letters, digits and dots there is an address; an IPv6 one where "::" and a hex digit, or one
// to four hex digits and a ":", start a run that is one. It looks for a family only when asked. f returning true ends the scan.
func eachAddr(row string, v4, v6 bool, f func(netip.Addr) bool) {
	for i := 0; i < len(row); i++ {
		c := row[i]
		var want6 bool
		switch {
		case v4 && c >= '0' && c <= '9' && (at(row, i+1) == '.' || at(row, i+2) == '.' || at(row, i+3) == '.'):
		case !v6:
			continue
		case c == ':' && at(row, i+1) == ':' && isHex(at(row, i+2)), isHex(c) && (at(row, i+1) == ':' ||
			isHex(at(row, i+1)) && (at(row, i+2) == ':' || isHex(at(row, i+2)) && (at(row, i+3) == ':' ||
				isHex(at(row, i+3)) && at(row, i+4) == ':'))):
			want6 = true
		default:
			continue
		}
		n := i
		for n < len(row) && (isAlnum(row[n]) || row[n] == '.' || want6 && row[n] == ':') {
			n++
		}
		if a, err := netip.ParseAddr(row[i:n]); err == nil && a.Is6() == want6 && f(a) {
			return
		}
		i = n - 1
	}
}

// awkClass is how pfb_cidr_dedup files a row: IPv6 when it holds a ":", and the digits after its first "/digits" as the prefix
// length, capped at the family's; a row without one is a host.
func awkClass(row string) (v6 int, bits int) {
	bits = 32
	if strings.Contains(row, ":") {
		v6, bits = 1, 128
	}
	for i := 0; i+1 < len(row); i++ {
		if row[i] == '/' && row[i+1] >= '0' && row[i+1] <= '9' {
			n := 0
			for i++; i < len(row) && row[i] >= '0' && row[i] <= '9' && n <= bits; i++ {
				n = n*10 + int(row[i]-'0')
			}
			return v6, min(n, bits)
		}
	}
	return v6, bits
}

// cover is the rows the earlier feeds own, as the patterns the dedup tests a later row against (pfb_cidr_dedup over grepcidr
// 2.0, issue #3606). A row is tested only against earlier rows of its family at least as wide as itself: two halves never
// cover their whole.
type cover struct {
	rows  int
	all   [2]addrSet                // every pattern, by address family (v4, v6)
	have  [2]int                    // patterns read, by address family
	count [2][129]int               // earlier rows by awk family and prefix length
	wide  [2][129]int               // count summed up to each prefix length, as freeze left it
	part  [2][129][2]int            // patterns narrower than a host, by awk family, prefix length and address family
	nets  map[netip.Prefix]struct{} // those of part that are the network awk filed them as
	odd   []oddPattern              // the rest of part
}

type oddPattern struct {
	v6, bits int
	span
}

func famIndex(a netip.Addr) int {
	if a.Is4() {
		return 0
	}
	return 1
}

func (c *cover) add(row string) {
	row = strings.TrimSuffix(row, "\r")
	// A total-range row would cover every later feed, so it stays in its own feed only.
	if f := field1(row); f == "" || f == "0.0.0.0/0" || f == "::/0" {
		return
	}
	c.rows++
	v6, bits := awkClass(row)
	c.count[v6][bits]++
	r, ok := grepPattern(row)
	if !ok {
		return
	}
	fam := famIndex(r.lo)
	c.all[fam].add(r.lo, r.hi)
	c.have[fam]++
	if bits == 32+96*v6 {
		return
	}
	c.part[v6][bits][fam]++
	if p := netip.PrefixFrom(r.lo, bits); fam == v6 && prefixSpan(p) == r {
		if c.nets == nil {
			c.nets = map[netip.Prefix]struct{}{}
		}
		c.nets[p] = struct{}{}
		return
	}
	c.odd = append(c.odd, oddPattern{v6, bits, r})
}

// freeze fixes the patterns for the next feed.
func (c *cover) freeze() {
	for v6 := range c.all {
		c.all[v6].freeze()
		n := 0
		for b, k := range c.count[v6] {
			n += k
			c.wide[v6][b] = n
		}
	}
}

// drops reports whether the dedup removes a later feed's row.
func (c *cover) drops(row string) bool {
	v6, bits := awkClass(row)
	seen, hit := false, false
	switch wide := c.wide[v6][bits]; {
	case wide == c.wide[v6][128]:
		// Every earlier row of the family is wide enough (or there is none): grepcidr gets all the patterns, and prints a row
		// only when it reads an address of a family it has patterns for and no pattern holds it.
		eachAddr(row, c.have[0] > 0, c.have[1] > 0, func(a netip.Addr) bool {
			seen, hit = true, c.all[famIndex(a)].contains(a)
			return hit
		})
	case wide == 0:
		return false // no earlier row is wide enough: the row never reaches grepcidr
	default:
		// Only the earlier rows at least as wide are patterns.
		var have [2]bool
		for b := 0; b <= bits; b++ {
			have[0], have[1] = have[0] || c.part[v6][b][0] > 0, have[1] || c.part[v6][b][1] > 0
		}
		eachAddr(row, have[0], have[1], func(a netip.Addr) bool {
			seen = true
			for b := 0; b <= bits && !hit && famIndex(a) == v6; b++ {
				if c.part[v6][b][v6] > 0 {
					_, hit = c.nets[netip.PrefixFrom(a, b).Masked()]
				}
			}
			hit = hit || slices.ContainsFunc(c.odd, func(o oddPattern) bool {
				return o.v6 == v6 && o.bits <= bits && o.lo.BitLen() == a.BitLen() && o.lo.Compare(a) <= 0 && a.Compare(o.hi) <= 0
			})
			return hit
		})
	}
	return hit || !seen
}

// cleanRows is the rows as the emit reads them: a trailing CR dropped, blank rows dropped.
func cleanRows(rows []string) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if r = strings.TrimSuffix(r, "\r"); field1(r) != "" {
			out = append(out, r)
		}
	}
	return out
}

// octets3 is the /24 key of a row for the recompute's offender scan: the first three dot-separated parts of its first field.
func octets3(row string) (string, bool) {
	f := strings.Split(field1(row), ".")
	if len(f) < 3 {
		return "", false
	}
	return strings.Join(f[:3], "."), true
}

// Recompute is the recompute verb for one family.
func Recompute(in RecomputeIn) RecomputeOut {
	out := RecomputeOut{Lists: make([]List, len(in.Feeds)), Master: in.Master}
	owned := make([][]string, len(in.Feeds))
	var earlier cover
	for i, f := range in.Feeds {
		rows := textRows(f.Text)
		if in.Dedup {
			if earlier.rows > 0 {
				earlier.freeze()
				rows = slices.DeleteFunc(rows, earlier.drops)
			}
			for _, r := range rows {
				earlier.add(r)
			}
		}
		owned[i] = rows
	}

	// Reputation is v4 only. The action of an offender /24: "block", "matchdup", "matchexempt", or none.
	action := map[string]string{}
	dmax := in.Family == V4 && in.Mode == RepDMax
	geoOK := true
	if dmax || in.Family == V4 && in.Mode == RepPMax {
		count := map[string]int{}
		ph := cut3(in.Placeholder)
		for i, f := range in.Feeds {
			if strings.HasPrefix(f.Name, "pfB") {
				continue
			}
			for _, r := range owned[i] {
				if key, ok := octets3(r); ok && key != ph {
					count[key]++
				}
			}
		}
		offenders, _ := over(count, in.Rep.Max)
		white, black := strings.ToLower(in.Rep.CCWhite), strings.ToLower(in.Rep.CCBlack)
		outside := map[string]string{"block": "block", "match": "matchdup"}[black]
		switch {
		case !dmax:
			for _, key := range offenders {
				action[key] = "block"
			}
		case in.Rep.Geo == nil:
			geoOK = len(offenders) == 0
		default:
			for _, key := range offenders {
				switch cc := in.Rep.Geo(key); {
				case cc == "" || !listed(in.Rep.CC, cc):
					action[key] = outside
				case white == "match" || black == "match":
					action[key] = "matchexempt"
				}
			}
		}
		maps.DeleteFunc(action, func(_, a string) bool { return a == "" })
		if dmax && geoOK {
			out.DropExempt = white == "match"
		}
	}

	// Offender rows leave their feeds: a blocked /24 becomes one row owned by its highest-priority feed, a matched one keeps
	// its rows (first field only) and is listed in the match artifacts.
	type diverted struct {
		ip   string
		feed int
	}
	windows := map[string][]diverted{}
	keep := make([][]string, len(in.Feeds))
	for i, f := range in.Feeds {
		keep[i] = cleanRows(owned[i])
		if len(action) == 0 || strings.HasPrefix(f.Name, "pfB") {
			continue
		}
		keep[i] = slices.DeleteFunc(keep[i], func(r string) bool {
			key, ok := octets3(r)
			if _, hit := action[key]; !ok || !hit {
				return false
			}
			windows[key] = append(windows[key], diverted{field1(r), i})
			return true
		})
	}
	matchRep := make([][]string, len(in.Feeds))
	var exemptNets, exemptRows []string
	for _, key := range slices.Sorted(maps.Keys(windows)) {
		w := windows[key]
		if action[key] == "block" {
			keep[w[0].feed] = append(keep[w[0].feed], key+".0/24")
			continue
		}
		seen := map[int]bool{}
		for _, d := range w {
			keep[d.feed] = append(keep[d.feed], d.ip)
			switch {
			case action[key] == "matchexempt":
				exemptRows = append(exemptRows, "!"+d.ip)
			case !seen[d.feed]:
				matchRep[d.feed] = append(matchRep[d.feed], key+".0/24")
				fallthrough
			default:
				matchRep[d.feed] = append(matchRep[d.feed], "!"+d.ip)
			}
			seen[d.feed] = true
		}
		if action[key] == "matchexempt" {
			exemptNets = append(exemptNets, key+".0/24")
		}
	}

	if in.Dedup {
		suffix := "_" + string(in.Family)
		out.Master = slices.DeleteFunc(slices.Clone(in.Master), func(r string) bool { return strings.HasSuffix(field1(r), suffix) })
	}
	for i, f := range in.Feeds {
		out.Lists[i] = List{f.Name, sortUniq(keep[i])}
		if in.Dedup {
			for _, r := range out.Lists[i].Lines {
				out.Master = append(out.Master, f.Name+" "+r)
			}
		}
		switch {
		case matchRep[i] != nil:
			out.MatchRep = append(out.MatchRep, List{f.Name, matchRep[i]})
		case dmax && geoOK:
			out.DropRep = append(out.DropRep, f.Name)
		}
	}
	if dmax && strings.ToLower(in.Rep.CCWhite) == "match" && len(exemptNets) > 0 {
		out.MatchExempt = append(exemptNets, exemptRows...)
	}
	return out
}

// PMaxOut is the deny folder and masterfile after the legacy pMax pass. Lists has every input feed, in input order. Applied is
// whether any /24 was over the threshold: only then are the masterfile and its category file rewritten and empty feeds refilled.
type PMaxOut struct {
	Lists   []List
	Master  []string
	Applied bool
}

// PMax is the pmax verb: every /24 holding more than max rows across the deny feeds (none named "pfB..." or ending "_v6")
// becomes one "x.y.z.0/24" row in the first feed, in byte order of name, that held it. A feed left empty gets the placeholder,
// unless placeholder is "" (none: Core's, #4038).
// The masterfile loses the rows of those /24s and gains the new ones; when it held none of them it is emptied first.
func PMax(deny []Feed, master []string, max int, placeholder string) PMaxOut {
	out := PMaxOut{Lists: make([]List, len(deny)), Master: slices.Clone(master)}
	var scanned []int
	for i, f := range deny {
		out.Lists[i] = List{f.Name, textRows(f.Text)}
		if !strings.HasPrefix(f.Name, "pfB") && !strings.HasSuffix(f.Name, "_v6") {
			scanned = append(scanned, i)
		}
	}
	// The verb walks the folder in the byte order of the file names.
	slices.SortFunc(scanned, func(a, b int) int { return strings.Compare(deny[a].Name+".", deny[b].Name+".") })
	count := map[string]int{}
	for _, i := range scanned {
		for _, r := range out.Lists[i].Lines {
			count[cut3(r)]++
		}
	}
	delete(count, cut3(placeholder))
	offenders, any := over(count, max)
	if out.Applied = any; !any {
		return out
	}
	var held []string // "feed key." of every feed an offender /24 was taken from
	var added []string
	for _, key := range offenders {
		owner, set := true, map[string]bool{key: true}
		for _, i := range scanned {
			l := &out.Lists[i]
			n := len(l.Lines)
			if l.Lines = slices.DeleteFunc(l.Lines, func(r string) bool { return in24(r, set) }); len(l.Lines) == n {
				continue
			}
			held = append(held, l.Name+" "+key+".")
			if owner {
				l.Lines = append(l.Lines, key+".0/24")
				added = append(added, l.Name+" "+key+".0/24")
				owner = false
			}
		}
	}
	out.Master = append(minus(out.Master, func(r string) bool {
		return slices.ContainsFunc(held, func(h string) bool { return strings.HasPrefix(r, h) })
	}), added...)
	for i := range out.Lists {
		if len(out.Lists[i].Lines) == 0 && placeholder != "" {
			out.Lists[i].Lines = []string{placeholder}
		}
	}
	return out
}

package ipset

import (
	"maps"
	"net/netip"
	"slices"
	"strconv"
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

// over is the /24 keys held by more than max rows that are octet prefixes, in byte order.
func over(count map[string]int, max int) []string {
	var keys []string
	for k, n := range count {
		if n > max && isOctetPrefix(k) {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys
}

func sortUniq(rows []string) []string {
	rows = slices.Clone(rows)
	slices.Sort(rows)
	return slices.Compact(rows)
}

// in24 reports whether row is written under one of the /24 keys.
func in24(row string, keys []string) bool {
	for _, k := range keys {
		if strings.HasPrefix(row, k) && len(row) > len(k) && row[len(k)] == '.' {
			return true
		}
	}
	return false
}

func cidr24(keys []string) []string {
	rows := make([]string, len(keys))
	for i, k := range keys {
		rows[i] = k + ".0/24"
	}
	return rows
}

// full24 is the _255 stage: a /24 key held by more than 253 rows becomes the one row "key.0/24".
func full24(rows []string) []string {
	count := map[string]int{}
	for _, r := range rows {
		count[cut3(r)]++
	}
	keys := over(count, 253)
	if len(keys) == 0 {
		return rows
	}
	return append(slices.DeleteFunc(slices.Clone(rows), func(r string) bool { return in24(r, keys) }), cidr24(keys)...)
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
	countries := strings.ReplaceAll(in.CC, ",", ", ")
	var blocked, exempt []string
	for _, key := range over(count, in.Max) {
		cc := ""
		if in.Geo != nil {
			cc = in.Geo(key)
		}
		switch {
		case cc == "" || !strings.Contains(countries, cc):
			blocked = append(blocked, key)
		case white == "match" || black == "match":
			exempt = append(exempt, key)
		}
	}
	if len(exempt) > 0 && !in.DRep && white == "match" {
		match = cidr24(exempt)
		for _, key := range exempt {
			for _, r := range sorted {
				if in24(r, []string{key}) {
					match = append(match, "!"+r)
				}
			}
		}
	}
	switch {
	case len(blocked) == 0:
		return rows, match
	case black == "block":
		rows = append(slices.DeleteFunc(sorted, func(r string) bool { return in24(r, blocked) }), cidr24(blocked)...)
	}
	return sortUniq(rows), match
}

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

// rowNet reads a row as grepcidr and pfb_cidr_dedup do: the address before any "/", and the prefix length after the first "/"
// capped at the family's (a bare address is a host). ok is false for a row that holds no address.
func rowNet(row string) (p netip.Prefix, ok bool) {
	tok := strings.TrimSuffix(field1(row), "\r")
	addr, bitsText, _ := strings.Cut(tok, "/")
	a, err := netip.ParseAddr(addr)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, false
	}
	bits := a.BitLen()
	if n := len(bitsText) - len(strings.TrimLeft(bitsText, "0123456789")); n > 0 {
		if b, err := strconv.Atoi(bitsText[:n]); err == nil && b < bits {
			bits = b
		}
	}
	return netip.PrefixFrom(a, bits), true
}

// cover is the rows the earlier feeds own, as networks by prefix length. A row is covered only by ONE network at least as wide
// as itself that holds it: two halves do not cover their whole (grepcidr tests the row's address alone, issue #3606).
type cover struct {
	nets   map[netip.Prefix]struct{}
	bits   [2][]int // the prefix lengths present, v4 and v6
	ranges []span   // "a-b" rows, which grepcidr reads as patterns; they cover hosts only
	rows   int
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
	p, ok := rowNet(row)
	if !ok {
		if lo, hi, cut := strings.Cut(field1(row), "-"); cut {
			a, errA := netip.ParseAddr(lo)
			b, errB := netip.ParseAddr(hi)
			if errA == nil && errB == nil && a.BitLen() == b.BitLen() {
				c.ranges = append(c.ranges, span{a, b})
			}
		}
		return
	}
	if c.nets == nil {
		c.nets = map[netip.Prefix]struct{}{}
	}
	c.nets[p.Masked()] = struct{}{}
	if b := &c.bits[famIndex(p.Addr())]; !slices.Contains(*b, p.Bits()) {
		*b = append(*b, p.Bits())
	}
}

func (c *cover) covers(row string) bool {
	p, ok := rowNet(row)
	if !ok {
		return false
	}
	for _, b := range c.bits[famIndex(p.Addr())] {
		if b <= p.Bits() {
			if _, hit := c.nets[netip.PrefixFrom(p.Addr(), b).Masked()]; hit {
				return true
			}
		}
	}
	return p.IsSingleIP() && slices.ContainsFunc(c.ranges, func(r span) bool {
		return r.lo.BitLen() == p.Addr().BitLen() && r.lo.Compare(p.Addr()) <= 0 && p.Addr().Compare(r.hi) <= 0
	})
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
				rows = slices.DeleteFunc(rows, earlier.covers)
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
		offenders := over(count, in.Rep.Max)
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
				case cc == "" || !strings.Contains(in.Rep.CC, cc):
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

// PMaxOut is the deny folder and masterfile after the legacy pMax pass. Lists has every input feed, in input order.
type PMaxOut struct {
	Lists  []List
	Master []string
}

// PMax is the pmax verb: every /24 holding more than max rows across the deny feeds (none named "pfB..." or ending "_v6")
// becomes one "x.y.z.0/24" row in the first feed, in byte order of name, that held it. A feed left empty gets the placeholder.
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
	offenders := over(count, max)
	if len(offenders) == 0 {
		return out
	}
	for _, key := range offenders {
		owner := true
		for _, i := range scanned {
			l := &out.Lists[i]
			n := len(l.Lines)
			if l.Lines = slices.DeleteFunc(l.Lines, func(r string) bool { return in24(r, []string{key}) }); len(l.Lines) == n {
				continue
			}
			held := l.Name + " " + key + "."
			out.Master = slices.DeleteFunc(out.Master, func(r string) bool { return strings.HasPrefix(r, held) })
			if owner {
				l.Lines = append(l.Lines, key+".0/24")
				out.Master = append(out.Master, l.Name+" "+key+".0/24")
				owner = false
			}
		}
	}
	for i := range out.Lists {
		if len(out.Lists[i].Lines) == 0 {
			out.Lists[i].Lines = []string{placeholder}
		}
	}
	return out
}

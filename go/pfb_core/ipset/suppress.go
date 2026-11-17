package ipset

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// SuppressIn is one feed's suppression. Holes is the suppression list as text, nil when there is no list. Master and Dedup
// matter for v4 only: with Dedup on and Alias in Master, the Alias rows of Master are replaced by the surviving rows.
type SuppressIn struct {
	Family  Family
	Alias   string
	Members string
	Holes   *string
	Master  []string
	Dedup   bool
}

// Suppressed is the result. Applied is false when there is no list, or a v4 list names no entry: Members and Master are then as
// they were (a v6 list, even an empty one, is always applied). BadHoles are the hole entries dropped as malformed and BadMembers the member rows dropped: v4 drops
// them before the subtraction and reads a CRLF row as malformed, v6 while normalising the rows it keeps.
type Suppressed struct {
	Members, Master      []string
	Applied              bool
	BadHoles, BadMembers []string
}

// Suppress is the suppress verb (v4: exact CIDR subtraction, the minimal covering CIDRs of the remainder) and
// pfb_suppress_file_v6 (v6: every kept row rewritten as a CIDR, a bare host as /128, duplicates kept). A fully suppressed set
// is an empty list, not the placeholder.
func Suppress(in SuppressIn) Suppressed {
	if in.Family == V6 {
		return suppressV6(in)
	}
	return suppressV4(in)
}

// isDigits reports whether s is one or more decimal digits.
func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// isNetToken is the suppress verb's shape test: digits and dots, then, when mask is true, exactly one "/" and a digit mask;
// when it is false the "/mask" is optional.
func isNetToken(s string, mask bool) bool {
	addr, bits, cut := strings.Cut(s, "/")
	if cut && !isDigits(bits) || !cut && mask || addr == "" {
		return false
	}
	for i := 0; i < len(addr); i++ {
		if addr[i] != '.' && (addr[i] < '0' || addr[i] > '9') {
			return false
		}
	}
	return true
}

func suppressV4(in SuppressIn) Suppressed {
	out := Suppressed{Members: textRows(in.Members), Master: slices.Clone(in.Master)}
	if in.Holes == nil {
		return out
	}
	holes := sortUniq(textRows(*in.Holes))
	for _, h := range holes {
		out.Applied = out.Applied || h != ""
	}
	if !out.Applied {
		return out
	}
	var set addrSet
	for _, row := range out.Members {
		if isNetToken(row, false) {
			if lo, hi, ok := parseRangeLine(row); ok {
				set.add(addrOf(lo), addrOf(hi))
			}
		} else {
			out.BadMembers = append(out.BadMembers, row)
		}
	}
	for _, h := range holes {
		switch {
		case isNetToken(h, true):
			if lo, hi, ok := parseRangeLine(h); ok {
				set.remove(addrOf(lo), addrOf(hi))
			}
		case h != "":
			out.BadHoles = append(out.BadHoles, h)
		}
	}
	out.Members = v4Rows(set.prefixes())
	if !in.Dedup || !slices.ContainsFunc(in.Master, func(r string) bool { return strings.Contains(r, in.Alias) }) {
		return out
	}
	// The masterfile rows of the alias are the ones starting with "alias" and a blank; the survivors replace them. An alias
	// named only inside another's rows has none, and the masterfile is then emptied first.
	out.Master = minus(in.Master, func(r string) bool {
		rest, ok := strings.CutPrefix(r, in.Alias)
		return ok && rest != "" && isSpace(rest[0])
	})
	for _, r := range out.Members {
		out.Master = append(out.Master, in.Alias+" "+r)
	}
	return out
}

// v6Range reads one v6 member or hole token as pfb_v6_cidr_to_range does: trimmed, a bare address its own /128, otherwise
// "address/bits" with 1 to 3 digit bits up to 128. A blank or "#" token is no entry and no error.
func v6Range(tok string) (r span, bits int, entry, valid bool) {
	t := strings.Trim(tok, " \t\n\r\x00\x0b")
	if t == "" || t[0] == '#' {
		return span{}, 0, false, true
	}
	addr, bitsText, cut := strings.Cut(t, "/")
	bits = 128
	if cut {
		if len(bitsText) > 3 || !isDigits(bitsText) {
			return span{}, 0, false, false
		}
		bits, _ = strconv.Atoi(bitsText)
		if bits > 128 {
			return span{}, 0, false, false
		}
	}
	a, err := netip.ParseAddr(addr)
	if err != nil || !a.Is6() || a.Zone() != "" {
		return span{}, 0, false, false
	}
	lo, hi := a.As16(), a.As16()
	for i := bits; i < 128; i++ {
		lo[i/8] &^= 1 << (7 - i%8)
		hi[i/8] |= 1 << (7 - i%8)
	}
	return span{netip.AddrFrom16(lo), netip.AddrFrom16(hi)}, bits, true, true
}

func v6Row(dst []string, a netip.Addr, bits int) []string {
	return append(dst, string(strconv.AppendUint(append(appendV6(nil, a), '/'), uint64(bits), 10)))
}

// suppressV6 carves each entry on its own, so entries are never merged and a duplicate stays.
func suppressV6(in SuppressIn) Suppressed {
	if in.Holes == nil {
		return Suppressed{Members: textRows(in.Members), Master: in.Master}
	}
	out := Suppressed{Applied: true, Members: []string{}, Master: in.Master}
	type entry struct {
		span
		bits int
	}
	var entries []entry
	// PHP's file() drops a CRLF line end whole, so a dropped token is named without its CR.
	for _, row := range textRows(in.Members) {
		row = strings.TrimSuffix(row, "\r")
		switch r, bits, ok, valid := v6Range(row); {
		case !valid:
			out.BadMembers = append(out.BadMembers, row)
		case ok:
			entries = append(entries, entry{r, bits})
		}
	}
	var holes addrSet
	for _, row := range textRows(*in.Holes) {
		row = strings.TrimSuffix(row, "\r")
		switch r, _, ok, valid := v6Range(row); {
		case !valid:
			out.BadHoles = append(out.BadHoles, row)
		case ok:
			holes.add(r.lo, r.hi)
		}
	}
	merged := holes.spans()
	for _, e := range entries {
		// merged is sorted and disjoint, so the first hole ending at or after the entry is the only one that can start it.
		i, _ := slices.BinarySearchFunc(merged, e.lo, func(h span, a netip.Addr) int { return h.hi.Compare(a) })
		if i == len(merged) || merged[i].lo.Compare(e.hi) > 0 {
			out.Members = v6Row(out.Members, e.lo, e.bits)
			continue
		}
		var carve addrSet
		carve.add(e.lo, e.hi)
		for ; i < len(merged) && merged[i].lo.Compare(e.hi) <= 0; i++ {
			carve.remove(merged[i].lo, merged[i].hi)
		}
		for _, p := range carve.prefixes() {
			out.Members = v6Row(out.Members, p.Addr(), p.Bits())
		}
	}
	return out
}

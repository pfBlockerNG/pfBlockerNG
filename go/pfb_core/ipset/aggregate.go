package ipset

import (
	"slices"
	"strings"
)

// Canonical is pfb_canonical_alias_set: the concatenated member text without empty and "#" rows, deduplicated, in byte order.
func Canonical(content string) []string {
	rows := make([]string, 0, strings.Count(content, "\n")+1)
	eachLine(content, func(l string) {
		if l != "" && l[0] != '#' {
			rows = append(rows, l)
		}
	})
	slices.Sort(rows)
	return slices.Compact(rows)
}

// UnionOut is one Uber union. Kept names the members that were unioned, Aggregate is the aggregate file and Consumer the
// never-empty consumer file ("#" alone for an empty union). Before is the row count of the deduplicated union before any CIDR
// collapse.
type UnionOut struct {
	Kept, Aggregate, Consumer []string
	Before                    int
}

// Union is pfb_aggregate_member_list and the aggregate verb. members are the member files of one class folder, named by alias,
// in any order. Union keeps those of family, in byte order of name, drops any holding only the placeholder (v4 spelling,
// "::"-prefixed for v6) or comments (an empty one stays), and unions the rest. collapsed is CIDR Aggregation: on, the union is
// the rows deduplicated; off, v4 goes through iprange and v6 stays deduplicated rows.
func Union(family Family, collapsed bool, placeholder string, members []Feed) UnionOut {
	if family == V6 && placeholder != "" {
		placeholder = "::" + placeholder
	}
	var out UnionOut
	var rows []string
	for _, m := range familyFeeds(family, members) {
		if placeholder != "" && placeholderOnly(m.Text, placeholder) {
			continue
		}
		out.Kept = append(out.Kept, m.Name)
		eachLine(m.Text, func(l string) { rows = append(rows, l) })
	}
	rows = sortUniq(rows)
	out.Before = len(rows)
	switch {
	case len(rows) == 0:
	case family == V6 || collapsed:
		out.Aggregate = rows
	default:
		out.Aggregate = CIDRAggregate(strings.Join(rows, "\n"))
	}
	if out.Consumer = slices.Clone(out.Aggregate); len(out.Aggregate) == 0 {
		out.Consumer = []string{"#"}
	}
	return out
}

// placeholderOnly reports whether every row of text that is not a comment is the placeholder, in either spelling. A text with no
// row at all is not.
func placeholderOnly(text, placeholder string) bool {
	bare := strings.TrimPrefix(placeholder, "::")
	spellings := []string{placeholder, bare}
	if bare == placeholder {
		spellings[1] = "::" + bare
	}
	rows := 0
	for _, l := range textRows(text) {
		if l == "" {
			continue
		}
		rows++
		if t := strings.Trim(l, " \t\n\r\x00\x0b"); t != "" && t[0] != '#' && !slices.Contains(spellings, t) {
			return false
		}
	}
	return rows > 0
}

// familyFeeds is the feeds named for family, in byte order of name.
func familyFeeds(family Family, feeds []Feed) []Feed {
	var out []Feed
	for _, f := range feeds {
		if strings.HasSuffix(f.Name, "_"+string(family)) {
			out = append(out, f)
		}
	}
	slices.SortFunc(out, func(a, b Feed) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// DNSBLIPOut is the DNSBLIP file of one family: Content is its raw text and Sources the names concatenated into it.
type DNSBLIPOut struct {
	Content string
	Sources []string
}

// DNSBLIP is the DNSBLIP assembly: the files of family concatenated in byte order of name with no record terminator added, or
// the placeholder row ("::"-prefixed for v6) when there is none. placeholder is the v4 spelling.
func DNSBLIP(family Family, placeholder string, files []Feed) DNSBLIPOut {
	var out DNSBLIPOut
	var b strings.Builder
	for _, f := range familyFeeds(family, files) {
		out.Sources = append(out.Sources, f.Name)
		b.WriteString(f.Text)
	}
	if out.Content = b.String(); out.Sources == nil {
		if family == V6 {
			placeholder = "::" + placeholder
		}
		out.Content = placeholder + "\n"
	}
	return out
}

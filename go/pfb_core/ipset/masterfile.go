package ipset

import (
	"slices"
	"strconv"
	"strings"
)

// MasterCat is the category column of a masterfile: the second space-separated field of every "alias member" row.
func MasterCat(master []string) []string {
	cat := make([]string, len(master))
	for i, r := range master {
		cat[i] = r
		if _, rest, ok := strings.Cut(r, " "); ok {
			cat[i], _, _ = strings.Cut(rest, " ")
		}
	}
	return cat
}

// RemoveOut is the result of removing feeds. Master is the masterfile left (empty means the file is deleted), Removed the
// headers removed and Invalid the headers refused for holding "/" or "..". Kept is, per directory handed in, the names left.
type RemoveOut struct {
	Master, Removed, Invalid []string
	Kept                     [][]string
}

// Remove is the remove verb: for each non-empty header it drops the header's rows from master (anchored at the row start), and
// deletes every file name of dirs that begins with the header, so a sibling whose name starts with it goes too. dirs hold one
// list of file names per directory the verb cleans.
func Remove(headers, master []string, dirs [][]string) RemoveOut {
	var out RemoveOut
	// The verb word-splits the comma list, so a header holding blanks is several; a trailing comma is dropped.
	for _, w := range strings.Fields(strings.ReplaceAll(strings.Join(headers, ","), ",", ", ")) {
		h := strings.TrimSuffix(w, ",")
		switch {
		case strings.Contains(h, "/") || strings.Contains(h, ".."):
			out.Invalid = append(out.Invalid, h)
		case h != "":
			out.Removed = append(out.Removed, h)
		}
	}
	// A row belongs to a header when it starts with it and a blank; "BadAds_v4" is not "Ads_v4".
	out.Master = slices.DeleteFunc(slices.Clone(master), func(r string) bool {
		return slices.ContainsFunc(out.Removed, func(h string) bool {
			rest, ok := strings.CutPrefix(r, h)
			return ok && rest != "" && isSpace(rest[0])
		})
	})
	out.Kept = make([][]string, len(dirs))
	for i, names := range dirs {
		out.Kept[i] = []string{}
		for _, n := range names {
			// The files go by prefix, so a sibling whose name starts with the header goes too.
			if !slices.ContainsFunc(out.Removed, func(h string) bool { return strings.HasPrefix(n, h) }) {
				out.Kept[i] = append(out.Kept[i], n)
			}
		}
	}
	return out
}

// ClosingIn is the closing report's input. Deny is the deny folder by alias. AggCounts are the texts of the v4 aggregation
// count files and Origs those of the v4 original feeds, which stand in when the counts sum to 0. Dedup on adds the masterfile
// check. Placeholder is the v4 spelling; "" is none (Core's, #4038): an empty list stays empty.
type ClosingIn struct {
	Deny        []Feed
	Master      []string
	AggCounts   []string
	Origs       []string
	Dedup       bool
	Placeholder string
}

// Sanity is the closing report's verdict. Original counts the rows before processing. With Dedup on, Final counts the masterfile
// rows, MasterCat and Deny the categories and deny rows without the placeholder, Passed is that they are equal, and DupMaster
// and DupDeny are the repeated rows (the last 30). Empty names the lists holding the placeholder row.
type Sanity struct {
	Original, Final    int
	MasterCat, Deny    int
	Passed             bool
	DupMaster, DupDeny []string
	Empty              []string
}

// ClosingOut is the deny folder after the placeholder refill, the masterfile (byte order) and the verdict.
type ClosingOut struct {
	Lists  []List
	Master []string
	Sanity Sanity
}

// Closing is the closing verb: an empty deny file gets the placeholder, then, with Dedup on, the masterfile and the deny folder
// are checked against each other.
func Closing(in ClosingIn) ClosingOut {
	out := ClosingOut{Lists: make([]List, len(in.Deny)), Master: slices.Clone(in.Master)}
	var denyRows []string
	for i, f := range in.Deny {
		// A deny file of size 0 gets the placeholder, written as the v4 spelling for either family.
		out.Lists[i] = List{f.Name, textRows(f.Text)}
		if f.Text == "" && in.Placeholder != "" {
			out.Lists[i].Lines = []string{in.Placeholder}
		}
		denyRows = append(denyRows, out.Lists[i].Lines...)
		for _, l := range out.Lists[i].Lines {
			if in.Placeholder != "" && l == in.Placeholder {
				out.Sanity.Empty = append(out.Sanity.Empty, f.Name)
			}
		}
	}
	out.Sanity.Original = originalCount(in.AggCounts, in.Origs)
	if !in.Dedup {
		return out
	}
	slices.Sort(out.Master)
	cat := MasterCat(out.Master)
	slices.Sort(cat)
	slices.Sort(denyRows)
	out.Sanity.Final = len(out.Master)
	out.Sanity.MasterCat = countNot(cat, in.Placeholder)
	out.Sanity.Deny = countNot(denyRows, in.Placeholder)
	out.Sanity.Passed = out.Sanity.MasterCat == out.Sanity.Deny
	out.Sanity.DupMaster = lastDuplicates(cat)
	// The deny duplicates are cut to the last 30 before the placeholder is filtered out of them.
	out.Sanity.DupDeny = slices.DeleteFunc(lastDuplicates(denyRows), func(r string) bool { return r == in.Placeholder })
	return out
}

// originalCount is the rows before processing: the first fields of the aggregation count files added up, else the rows of the
// original feeds that are neither empty nor comments.
func originalCount(aggCounts, origs []string) int {
	var sum float64
	for _, t := range aggCounts {
		eachLine(t, func(l string) {
			if f := strings.Fields(strings.Trim(l, "\n")); len(f) > 0 {
				sum += leadingNumber(f[0])
			}
		})
	}
	if n := int(sum); n != 0 {
		return n
	}
	n := 0
	for _, t := range origs {
		eachLine(t, func(l string) {
			if l != "" && l[0] != '#' {
				n++
			}
		})
	}
	return n
}

// leadingNumber is awk's number read from the start of s, 0 when there is none.
func leadingNumber(s string) float64 {
	end := 0
	for end < len(s) && (s[end] >= '0' && s[end] <= '9' || s[end] == '.' || end == 0 && (s[end] == '-' || s[end] == '+')) {
		end++
	}
	for ; end > 0; end-- {
		if v, err := strconv.ParseFloat(s[:end], 64); err == nil {
			return v
		}
	}
	return 0
}

func countNot(rows []string, not string) int {
	n := 0
	for _, r := range rows {
		if r != not {
			n++
		}
	}
	return n
}

// lastDuplicates is uniq -d | tail -30 of sorted rows: each repeated row once, the last 30.
func lastDuplicates(sorted []string) []string {
	var dups []string
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] && (len(dups) == 0 || dups[len(dups)-1] != sorted[i]) {
			dups = append(dups, sorted[i])
		}
	}
	return dups[max(0, len(dups)-30):]
}

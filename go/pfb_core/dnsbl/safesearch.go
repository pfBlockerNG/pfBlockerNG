package dnsbl

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// SafeSearchPolicy is policy/dnsbl's SafeSearch fields.
type SafeSearchPolicy struct {
	Enable  bool     // safeSearch
	YouTube string   // safeSearchYoutube: Disable, Moderate or Strict
	DoH     bool     // safeSearchDoh
	DoHList []string // safeSearchDohList: a line of the DoH list that names one of them stays blocked
}

// ssHost is one host of today's $safesearch_hosts: a later line sets one field and leaves the others.
type ssHost struct {
	name, a, aaaa string
	nxdomain      bool
}

// SafeSearchTable is today's SafeSearch stage (pfblockerng_apply.inc, "Loading DNSBL SafeSearch", then pfb_ss_csv()): the
// rows of the package's lists pfb_dnsbl.<name>.conf in dir that the policy turns on, a host and its www. variant (an
// nxdomain host once). A CNAME row carries its target and no fallback address: today's stage resolves the target's
// addresses (pfb_ss_resolve_target()); Core leaves that to pfB-DNS (owner, 2026-11-23). nil when no host is listed: no body
// is published. A host with a row the decider's CSV would not read back as written (a comma in a field, or an empty
// host) is left out and named in refused. Unlike today, the DoH list file is not rewritten: its lines are commented out in
// memory, which reads as today's pass over the same file.
func SafeSearchTable(dir string, p SafeSearchPolicy) (rows []SafeSearch, refused []string) {
	var hosts []*ssHost
	byName := map[string]*ssHost{}
	for _, list := range []struct {
		on   bool
		name string
	}{{p.Enable, "safesearch"}, {p.YouTube == "Strict", "youtube_restrict"}, {p.YouTube == "Moderate", "youtube_restrictmoderate"},
		{p.DoH, "doh"}} {
		if !list.on {
			continue
		}
		b, _ := os.ReadFile(filepath.Join(dir, "pfb_dnsbl."+list.name+".conf")) // file(): a list it cannot read is empty
		text := string(b)
		if list.name == "doh" && text != "" {
			text = dohLines(text, p.DoHList)
		}
		for _, line := range fileLines(text) {
			if strings.HasPrefix(line, "#") {
				continue
			}
			_, rest, quoted := strings.Cut(line, `"`)
			line = strings.ReplaceAll(rest, `"`, "")
			if !quoted {
				line = ""
			}
			ip := ""
			if i := strings.Index(line, "A "); i >= 0 {
				ip = phpTrim(strings.ReplaceAll(line[i:], "A ", ""))
			}
			domain, _, spaced := strings.Cut(line, " ")
			if !spaced { // strstr() answers false: no host
				domain = ""
			}
			domain = strings.TrimPrefix(domain, "www.")
			h := byName[domain]
			if h == nil {
				h = &ssHost{name: domain}
			}
			switch {
			case strings.Contains(line, " A "):
				h.a = ip
			case strings.Contains(line, " AAAA "):
				h.aaaa = ip
			case strings.Contains(line, " CNAME "):
				h.a, h.aaaa = "cname", phpTrim(strings.ReplaceAll(line[strings.Index(line, "CNAME"):], "CNAME ", ""))
			case strings.Contains(line, "always_nxdomain"):
				h.nxdomain = true
			default:
				continue
			}
			if byName[domain] == nil {
				byName[domain] = h
				hosts = append(hosts, h)
			}
		}
	}
	for _, h := range hosts {
		if h.name == "" || strings.Contains(h.name+h.a+h.aaaa, ",") {
			refused = append(refused, h.name)
			continue
		}
		switch {
		case h.nxdomain:
			rows = append(rows, SafeSearch{Host: h.name, A: "nxdomain", AAAA: "nxdomain"})
		case h.a == "cname":
			rows = append(rows, SafeSearch{Host: h.name, A: "cname", AAAA: h.aaaa}, SafeSearch{Host: "www." + h.name, A: "cname", AAAA: h.aaaa})
		default:
			rows = append(rows, SafeSearch{Host: h.name, A: h.a, AAAA: h.aaaa}, SafeSearch{Host: "www." + h.name, A: h.a, AAAA: h.aaaa})
		}
	}
	return rows, refused
}

// dohLines is the DoH list as today's stage rewrites it before reading it: a line's every "#" removed and the line
// left-trimmed, then kept when it names a selected server, else commented out with "# "; a line left empty loses its
// newline, so its comment runs into the next line.
func dohLines(text string, servers []string) string {
	var b strings.Builder
	for _, line := range fileLines(text) {
		if strings.Contains(line, "#") {
			line = strings.TrimLeft(strings.ReplaceAll(line, "#", ""), " \t\n\r\x00\x0b")
		}
		if !slices.ContainsFunc(servers, func(s string) bool { return strings.Contains(line, s) }) {
			b.WriteString("# ")
		}
		b.WriteString(line)
	}
	return b.String()
}

// fileLines is file(): the lines of text, each with its newline.
func fileLines(text string) []string {
	lines := strings.SplitAfter(text, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// phpTrim is PHP's trim().
func phpTrim(s string) string { return strings.Trim(s, " \t\n\r\x00\x0b") }

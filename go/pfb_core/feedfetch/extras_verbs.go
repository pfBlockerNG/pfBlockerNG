package feedfetch

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// The Extras verbs of pfblockerng.php (:338-449): dc, dcc, bu, al, asn, asn_shell, bl and bls, each a row selection over
// the Extras table, a DownloadExtras run, its log and its exit code. The Core Updater runs them under its own lock, so
// pfb_extras_process_begin() has no counterpart here. uc, gc and ugc are the conversion's (#4034).

// ExtrasSettings is what the verbs read of Core's settings: the extras projection, policy/dnsbl's TOP1M switch and
// schedule's Blacklist providers. The secrets are held in memory only.
type ExtrasSettings struct {
	MaxMindAccount, MaxMindKey string
	MaxMindCSVDisabled         bool // the IP tab's "skip the MaxMind CSV" ($pfb['cc'])
	ASNToken                   string
	Top1M                      bool // policy/dnsbl top1m
	Top1MProvider, Top1MToken  string
	Providers                  []BlacklistProvider // schedule's categoryProviders, in their order
}

// BlacklistProvider is one of schedule's categoryProviders: Selected is its membership of blacklist_selected.
type BlacklistProvider struct {
	ID, Title, Feed, Username, Password string
	Selected                            bool
}

// ExtrasVerb is one run of a verb.
type ExtrasVerb struct {
	Name string   // dc, dcc, bu, al, asn, asn_shell, bl or bls
	Args []string // what follows the verb on PHP's command line: "scheduled", then bl's comma-separated provider ids
	// GeoIPShare and DBDir are $pfb['geoipshare'] and $pfb['dbdir'], from the Core's flags.
	GeoIPShare, DBDir string
	Settings          ExtrasSettings
	Log               io.Writer // what PHP's pfb_logger() writes to extraslog, whatever its log type; nil discards it
	ASNTable          func(ctx context.Context)
	// Convert is pfblockerng_uc_countries(), which dc and dcc run after their download (#4034); nil converts nothing.
	Convert func(ctx context.Context) bool
}

// RunExtras runs the verb as pfblockerng.php does and returns its exit code with the run's result. A name that is not an
// Extras verb exits 1 without a download. A dcc that changed the TOP1M list reports it in the result (Top1MChanged); the
// caller starts the DNSBL update, which PHP's pfb_top1m_dispatch_if_changed() does for a dcc run by hand.
func (f *Fetcher) RunExtras(ctx context.Context, v ExtrasVerb) (int, ExtrasResult) {
	log := func(m string) {
		if v.Log != nil {
			io.WriteString(v.Log, m)
		}
	}
	if !slices.Contains([]string{"dc", "dcc", "bu", "al", "asn", "asn_shell", "bl", "bls"}, v.Name) {
		log("\nUnknown Extras verb [ " + v.Name + " ]\n")
		return 1, ExtrasResult{OK: false}
	}
	extras := v.plan(log)
	if len(extras) == 0 && v.Name != "dc" && v.Name != "dcc" { // dc and dcc download an empty table, then convert
		return 0, ExtrasResult{OK: true}
	}
	s := v.Settings
	log("\nDownload Process Starting\n")
	res := f.DownloadExtras(ctx, ExtrasConfig{DBDir: v.DBDir, MaxMindAccount: s.MaxMindAccount, MaxMindKey: s.MaxMindKey,
		ASNToken: s.ASNToken, Top1MToken: s.Top1MToken, ASNTable: v.ASNTable, Detect: v.Name == "dcc"}, extras)
	for i, r := range res.Rows {
		if !r.OK {
			log(fmt.Sprintf("\nFailed to Download %s [ stage=%s reason=%s detected=%s ]\n",
				cmp.Or(extras[i].File, extras[i].Download), r.Stage, r.Reason, r.Detected))
		}
	}
	log("Download Process Ended\n\n")
	if v.Name == "bls" {
		log(res.Report)
	}
	return v.exit(ctx, res), res
}

// plan is the verb's rows of the Extras table (pfblockerng.php:166-260 and its case), logging why a verb downloads
// nothing or a provider is skipped.
func (v ExtrasVerb) plan(log func(string)) []Extra {
	s := v.Settings
	table := []Extra{
		{Kind: "geoip", URL: "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz",
			Dir: v.GeoIPShare, Download: "GeoLite2-Country.tar.gz", File: "GeoLite2-Country.mmdb"},
		{Kind: "geoip", URL: "https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip",
			Dir: v.GeoIPShare, Download: "GeoLite2-Country-CSV.zip"},
		{Kind: "top1m", URL: top1mProviderOf(s.Top1MProvider).url, Dir: v.DBDir, Download: "top-1m.csv.zip",
			File: "top-1m.csv", Provider: s.Top1MProvider},
		{Kind: "asn", URL: "https://ipinfo.io/data/free/asn.mmdb?token=", Dir: v.GeoIPShare, Download: "asn.mmdb",
			File: "asn.mmdb"},
		{Kind: "asn", URL: "https://ipinfo.io/data/free/asn.csv.gz?token=", Dir: v.GeoIPShare, Download: "asn.csv.gz",
			File: "asn.csv"},
	}
	maxmind := s.MaxMindAccount != "" && s.MaxMindKey != ""
	csv := !s.MaxMindCSVDisabled // the IP tab skips the GeoIP CSV (:371-373)
	var keep []bool
	switch v.Name {
	case "dc":
		keep = []bool{true, csv}
	case "dcc":
		keep = []bool{maxmind, maxmind && csv, s.Top1M, s.ASNToken != "", s.ASNToken != ""}
	case "bu":
		if !maxmind {
			log("\nTerminating MaxMind download due to invalid Account or Key")
			return nil
		}
		return table[:1]
	case "al":
		return table[2:3]
	case "asn", "asn_shell":
		if s.ASNToken == "" {
			log("\n  ASN Token not defined. Terminating Download. ")
			return nil
		}
		return table[3:5]
	case "bl", "bls":
		return v.blacklist(log)
	}
	var rows []Extra
	for i, k := range keep {
		if k {
			rows = append(rows, table[i])
		}
	}
	return rows
}

// csvArgument is PFB_FILTER_CSV (pfblockerng.inc:2331-2335).
var csvArgument = regexp.MustCompile(`^[a-zA-Z0-9,_-]+$`)

// blacklist is the Blacklist rows of pfblockerng.php:217-260: the providers bl's argument names, in the settings' order,
// on a box with a provider selected.
func (v ExtrasVerb) blacklist(log func(string)) []Extra {
	args := v.Args
	if len(args) > 0 && args[0] == "scheduled" {
		args = args[1:]
	}
	if len(args) == 0 || !csvArgument.MatchString(args[0]) ||
		!slices.ContainsFunc(v.Settings.Providers, func(p BlacklistProvider) bool { return p.Selected }) {
		return nil
	}
	ids := strings.Split(args[0], ",")
	var rows []Extra
	for _, p := range v.Settings.Providers {
		if !slices.Contains(ids, p.ID) {
			continue
		}
		// The base of the feed's path: PHP's pathinfo() keeps a query, which can carry a key, in a name written to disk.
		name := ""
		if u, err := url.Parse(p.Feed); err == nil {
			name = path.Base(u.EscapedPath()) // as written, as pathinfo() takes it
		}
		if p.ID == "ut1" { // keyed on the id, never the feed: the name decides the category folder (issue #2636)
			name = "ut1.tar.gz"
		}
		if name == "." || name == "/" || name == ".." || name == "" {
			log("\nBlacklist provider [ " + p.ID + " ] skipped: its feed names no file\n")
			continue
		}
		rows = append(rows, Extra{Kind: "blacklist", URL: p.Feed, Dir: v.DBDir, Download: name, File: name, Name: p.Title,
			Username: p.Username, Password: p.Password})
	}
	var logged []string
	for _, id := range ids {
		known := slices.ContainsFunc(v.Settings.Providers, func(p BlacklistProvider) bool { return p.ID == id })
		if id != "" && !known && !slices.Contains(logged, id) {
			logged = append(logged, id)
			log("\nBlacklist provider [ " + id + " ] skipped: the settings hold no valid provider of that id\n")
		}
	}
	return rows
}

// exit is the verb's exit code (pfblockerng.php:374-386, :380-449), after dc and dcc's country conversion.
func (v ExtrasVerb) exit(ctx context.Context, res ExtrasResult) int {
	s := v.Settings
	switch v.Name {
	case "dc", "dcc":
		ok := res.OK
		// A run whose context ended converts nothing: its geoip rows read aborted, not MaxMind errors, but are not new.
		if !res.MaxMindError && ctx.Err() == nil && (!s.MaxMindCSVDisabled || s.MaxMindKey != "" || s.MaxMindAccount != "") && v.Convert != nil {
			ok = v.Convert(ctx) && ok
		}
		_, err := os.Stat(filepath.Join(v.DBDir, "geoip.update"))
		changed := len(v.Args) > 0 && v.Args[0] == "scheduled" && (res.Top1MChanged || err == nil)
		switch {
		case !ok && changed:
			return 3
		case !ok:
			return 1
		case changed:
			return 2
		}
	case "bl", "bls":
		if !res.OK {
			return 1
		}
	}
	return 0
}

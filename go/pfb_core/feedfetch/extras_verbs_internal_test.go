package feedfetch

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The Extras table of pfblockerng.php:166-212, rows 0 to 4, with the GeoIP share /share and the database folder /db.
var (
	verbGeoIP = Extra{Kind: "geoip", URL: "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz",
		Dir: "/share", Download: "GeoLite2-Country.tar.gz", File: "GeoLite2-Country.mmdb"}
	verbGeoIPCSV = Extra{Kind: "geoip", URL: "https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip",
		Dir: "/share", Download: "GeoLite2-Country-CSV.zip"}
	verbTop1M = Extra{Kind: "top1m", URL: "https://tranco-list.eu/top-1m.csv.zip", Dir: "/db", Download: "top-1m.csv.zip",
		File: "top-1m.csv", Provider: "tranco"}
	verbASNDB  = Extra{Kind: "asn", URL: "https://ipinfo.io/data/free/asn.mmdb?token=", Dir: "/share", Download: "asn.mmdb", File: "asn.mmdb"}
	verbASNCSV = Extra{Kind: "asn", URL: "https://ipinfo.io/data/free/asn.csv.gz?token=", Dir: "/share", Download: "asn.csv.gz", File: "asn.csv"}
)

// verbSettings is a box with every Extra configured: a MaxMind account and key, an IPinfo token, TOP1M on, and three
// Blacklist providers, two of them selected.
func verbSettings() ExtrasSettings {
	return ExtrasSettings{MaxMindAccount: "1", MaxMindKey: "mk", ASNToken: "it", Top1M: true, Top1MProvider: "tranco",
		Providers: []BlacklistProvider{
			{ID: "ut1", Title: "UT1", Feed: "https://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz", Selected: true},
			{ID: "ex", Title: "Example", Feed: "https://lists.example/cat/ex.tar.gz?key=k", Username: "u", Password: "p", Selected: true},
			{ID: "other", Title: "Other", Feed: "https://other.example/other.tar.gz"},
		}}
}

// Each verb's rows are pfblockerng.php's (the line each case cites), from the same settings.
func TestTheExtrasVerbsSelectTheirRows(t *testing.T) {
	ut1 := Extra{Kind: "blacklist", URL: "https://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz", Dir: "/db",
		Download: "ut1.tar.gz", File: "ut1.tar.gz", Name: "UT1"}
	ex := Extra{Kind: "blacklist", URL: "https://lists.example/cat/ex.tar.gz?key=k", Dir: "/db", Download: "ex.tar.gz",
		File: "ex.tar.gz", Name: "Example", Username: "u", Password: "p"}
	other := Extra{Kind: "blacklist", URL: "https://other.example/other.tar.gz", Dir: "/db", Download: "other.tar.gz",
		File: "other.tar.gz", Name: "Other"}
	for _, tc := range []struct {
		name, verb string
		args       []string
		edit       func(*ExtrasSettings)
		want       []Extra
		log        string // a line the verb logs before any download
	}{
		// dcc (:346-363, :371-373): every row, less MaxMind without both its account and key, TOP1M when it is off, ASN
		// without a token, and the GeoIP CSV when the IP tab skips it.
		{name: "dcc", verb: "dcc", want: []Extra{verbGeoIP, verbGeoIPCSV, verbTop1M, verbASNDB, verbASNCSV}},
		{name: "dcc scheduled", verb: "dcc", args: []string{"scheduled"},
			want: []Extra{verbGeoIP, verbGeoIPCSV, verbTop1M, verbASNDB, verbASNCSV}},
		{name: "dcc without a MaxMind key", verb: "dcc", edit: func(s *ExtrasSettings) { s.MaxMindKey = "" },
			want: []Extra{verbTop1M, verbASNDB, verbASNCSV}},
		{name: "dcc without a MaxMind account", verb: "dcc", edit: func(s *ExtrasSettings) { s.MaxMindAccount = "" },
			want: []Extra{verbTop1M, verbASNDB, verbASNCSV}},
		{name: "dcc with TOP1M off", verb: "dcc", edit: func(s *ExtrasSettings) { s.Top1M = false },
			want: []Extra{verbGeoIP, verbGeoIPCSV, verbASNDB, verbASNCSV}},
		{name: "dcc without an IPinfo token", verb: "dcc", edit: func(s *ExtrasSettings) { s.ASNToken = "" },
			want: []Extra{verbGeoIP, verbGeoIPCSV, verbTop1M}},
		{name: "dcc with the GeoIP CSV skipped", verb: "dcc", edit: func(s *ExtrasSettings) { s.MaxMindCSVDisabled = true },
			want: []Extra{verbGeoIP, verbTop1M, verbASNDB, verbASNCSV}},
		// dc (:365-368, :371-373): the MaxMind rows only, kept without a key, less the CSV the IP tab skips.
		{name: "dc", verb: "dc", want: []Extra{verbGeoIP, verbGeoIPCSV}},
		{name: "dc without a MaxMind key", verb: "dc", edit: func(s *ExtrasSettings) { s.MaxMindKey = "" },
			want: []Extra{verbGeoIP, verbGeoIPCSV}},
		{name: "dc with the GeoIP CSV skipped", verb: "dc", edit: func(s *ExtrasSettings) { s.MaxMindCSVDisabled = true },
			want: []Extra{verbGeoIP}},
		// bu (:381-388): the MaxMind database only; nothing without the account and key.
		{name: "bu", verb: "bu", want: []Extra{verbGeoIP}},
		{name: "bu with the GeoIP CSV skipped", verb: "bu", edit: func(s *ExtrasSettings) { s.MaxMindCSVDisabled = true },
			want: []Extra{verbGeoIP}},
		{name: "bu without a MaxMind account", verb: "bu", edit: func(s *ExtrasSettings) { s.MaxMindAccount = "" },
			log: "\nTerminating MaxMind download due to invalid Account or Key"},
		// al (:390-396): the TOP1M row only, whether TOP1M is on or not.
		{name: "al", verb: "al", want: []Extra{verbTop1M}},
		{name: "al with TOP1M off", verb: "al", edit: func(s *ExtrasSettings) { s.Top1M = false }, want: []Extra{verbTop1M}},
		// asn and asn_shell (:397-414): the ASN rows only; nothing without a token.
		{name: "asn", verb: "asn", want: []Extra{verbASNDB, verbASNCSV}},
		{name: "asn_shell", verb: "asn_shell", want: []Extra{verbASNDB, verbASNCSV}},
		{name: "asn without a token", verb: "asn", edit: func(s *ExtrasSettings) { s.ASNToken = "" },
			log: "\n  ASN Token not defined. Terminating Download. "},
		{name: "asn_shell without a token", verb: "asn_shell", edit: func(s *ExtrasSettings) { s.ASNToken = "" },
			log: "\n  ASN Token not defined. Terminating Download. "},
		// bl and bls (:217-260, :430-449): the providers the argument names, after "scheduled" when it is there, in the
		// settings' order. The ut1 archive is renamed ut1.tar.gz; a provider's credentials go with its row.
		{name: "bl", verb: "bl", args: []string{"ex,ut1"}, want: []Extra{ut1, ex}},
		{name: "bl scheduled", verb: "bl", args: []string{"scheduled", "ut1"}, want: []Extra{ut1}},
		{name: "bls scheduled", verb: "bls", args: []string{"scheduled", "ut1,ex"}, want: []Extra{ut1, ex}},
		{name: "bl of a provider not selected", verb: "bl", args: []string{"other"}, want: []Extra{other}},
		{name: "bl names a provider twice", verb: "bl", args: []string{"ex,ex"}, want: []Extra{ex}},
		// The argument must pass PFB_FILTER_CSV (pfblockerng.inc:2331-2335); and a box with no provider selected gets none.
		{name: "bl without an argument", verb: "bl"},
		{name: "bl scheduled without an argument", verb: "bl", args: []string{"scheduled"}},
		{name: "bl of an argument that is not a list", verb: "bl", args: []string{"ut1;ex"}},
		{name: "bl with no provider selected", verb: "bl", args: []string{"ut1"}, edit: func(s *ExtrasSettings) {
			for i := range s.Providers {
				s.Providers[i].Selected = false
			}
		}},
		// Departures. A provider the settings do not hold is skipped and logged: Core's projection leaves out an invalid
		// provider, which PHP would still download (pfb_core_schedule_providers, pfblockerng.inc:5877). Shallalist is one
		// of them, so the "Terminating Shallalist" line of :228-231 becomes this one.
		{name: "bl of a provider the settings do not hold", verb: "bl", args: []string{"gone,ut1"}, want: []Extra{ut1},
			log: "\nBlacklist provider [ gone ] skipped: the settings hold no valid provider of that id\n"},
		// The file name is the base of the feed's path, without its query: PHP's pathinfo() keeps the query, which can
		// carry a key, in a name written to disk (issue #3978: no secret in a file name).
		{name: "bl of a feed that names no file", verb: "bl", args: []string{"ex"}, edit: func(s *ExtrasSettings) {
			s.Providers[1].Feed = "https://lists.example/?key=k"
		}, log: "\nBlacklist provider [ ex ] skipped: its feed names no file\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := verbSettings()
			if tc.edit != nil {
				tc.edit(&s)
			}
			var log strings.Builder
			got := ExtrasVerb{Name: tc.verb, Args: tc.args, GeoIPShare: "/share", DBDir: "/db", Settings: s}.plan(func(m string) {
				log.WriteString(m)
			})
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("rows =\n%+v\nwant\n%+v", got, tc.want)
			}
			if log.String() != tc.log {
				t.Errorf("log = %q, want %q", log.String(), tc.log)
			}
		})
	}
}

// The TOP1M row's URL is its provider's, from pfb_top1m_providers() (pfblockerng_extra.inc:262-336).
func TestTheTOP1MRowTakesItsProvidersURL(t *testing.T) {
	for provider, url := range map[string]string{
		"tranco":       "https://tranco-list.eu/top-1m.csv.zip",
		"cisco":        "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip",
		"openpagerank": "https://openpagerank.keywordseverywhere.com/downloads/top10milliondomains.csv.zip",
		"majestic":     "https://downloads.majestic.com/majestic_million.csv",
		"cloudflare":   "https://api.cloudflare.com/client/v4/radar/datasets/ranking_top_1000000",
	} {
		s := verbSettings()
		s.Top1MProvider = provider
		got := ExtrasVerb{Name: "al", GeoIPShare: "/share", DBDir: "/db", Settings: s}.plan(func(string) {})
		if len(got) != 1 || got[0].URL != url || got[0].Provider != provider {
			t.Errorf("%s: rows %+v, want the one TOP1M row of %s", provider, got, url)
		}
	}
}

// Each verb's exit code (pfblockerng.php:374-386 for dc and dcc, :380-449 for the others). A scheduled dc or dcc that
// changed something exits 2, or 3 when it also failed; a change is a changed TOP1M list or a geoip.update marker. The
// country conversion runs after a download without a MaxMind failure, unless the IP tab skips the CSV and no MaxMind
// credential is set, and its failure fails the verb. bu, al and asn exit 0 whatever their download did: PHP's switch
// falls off its end without an exit.
func TestTheExtrasVerbsExitCodes(t *testing.T) {
	for _, tc := range []struct {
		name, verb string
		scheduled  bool
		res        ExtrasResult
		geoip      bool // the geoip.update marker is there
		edit       func(*ExtrasSettings)
		convert    *bool // nil: no conversion is set
		want       int
		converted  bool
	}{
		{name: "dcc ok", verb: "dcc", res: ExtrasResult{OK: true}, want: 0},
		{name: "dcc failed", verb: "dcc", want: 1},
		{name: "dcc changed, not scheduled", verb: "dcc", res: ExtrasResult{OK: true, Top1MChanged: true}, geoip: true, want: 0},
		{name: "dcc scheduled ok", verb: "dcc", scheduled: true, res: ExtrasResult{OK: true}, want: 0},
		{name: "dcc scheduled, TOP1M changed", verb: "dcc", scheduled: true, res: ExtrasResult{OK: true, Top1MChanged: true}, want: 2},
		{name: "dcc scheduled, GeoIP changed", verb: "dcc", scheduled: true, res: ExtrasResult{OK: true}, geoip: true, want: 2},
		{name: "dcc scheduled, failed and changed", verb: "dcc", scheduled: true, res: ExtrasResult{Top1MChanged: true}, want: 3},
		{name: "dcc scheduled, failed", verb: "dcc", scheduled: true, want: 1},
		{name: "dc scheduled, GeoIP changed", verb: "dc", scheduled: true, res: ExtrasResult{OK: true}, geoip: true, want: 2},
		{name: "dcc converts", verb: "dcc", res: ExtrasResult{OK: true}, convert: new(true), want: 0, converted: true},
		{name: "dcc conversion fails", verb: "dcc", res: ExtrasResult{OK: true}, convert: new(false), want: 1, converted: true},
		{name: "dc conversion fails", verb: "dc", res: ExtrasResult{OK: true}, convert: new(false), want: 1, converted: true},
		{name: "no conversion after a MaxMind failure", verb: "dcc", res: ExtrasResult{MaxMindError: true}, convert: new(true),
			want: 1},
		{name: "no conversion with the CSV skipped and no credential", verb: "dcc", res: ExtrasResult{OK: true},
			edit:    func(s *ExtrasSettings) { s.MaxMindCSVDisabled, s.MaxMindAccount, s.MaxMindKey = true, "", "" },
			convert: new(false), want: 0},
		{name: "conversion with the CSV skipped and an account", verb: "dcc", res: ExtrasResult{OK: true},
			edit: func(s *ExtrasSettings) { s.MaxMindCSVDisabled, s.MaxMindKey = true, "" }, convert: new(false), want: 1,
			converted: true},
		{name: "bu failed", verb: "bu", scheduled: true, geoip: true, want: 0},
		{name: "al failed", verb: "al", want: 0},
		{name: "asn failed", verb: "asn", want: 0},
		{name: "asn_shell failed", verb: "asn_shell", want: 0},
		{name: "bl ok", verb: "bl", res: ExtrasResult{OK: true}, want: 0},
		{name: "bl failed", verb: "bl", want: 1},
		{name: "bls failed", verb: "bls", scheduled: true, want: 1},
		{name: "bu converts nothing", verb: "bu", res: ExtrasResult{OK: true}, convert: new(false), want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := t.TempDir()
			if tc.geoip {
				if err := os.WriteFile(filepath.Join(db, "geoip.update"), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			s := verbSettings()
			if tc.edit != nil {
				tc.edit(&s)
			}
			v := ExtrasVerb{Name: tc.verb, DBDir: db, Settings: s}
			if tc.scheduled {
				v.Args = []string{"scheduled"}
			}
			converted := false
			if tc.convert != nil {
				v.Convert = func(context.Context) bool { converted = true; return *tc.convert }
			}
			if got := v.exit(context.Background(), tc.res); got != tc.want || converted != tc.converted {
				t.Errorf("(exit, converted) = (%d, %v), want (%d, %v)", got, converted, tc.want, tc.converted)
			}
		})
	}
}

// A GeoIP merge whose rollback could not finish names what it left: the backup it could not put back, or an entry it
// published and could not remove (#4059 review). The verb's failure line logs it.
func TestAnIncompleteMergeRollbackNamesWhatItLeft(t *testing.T) {
	write := func(dir string) error {
		for name, content := range map[string]string{"a.csv": "new a\n", "b.csv": "new b\n", "c.csv": "new c\n"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
				return err
			}
		}
		return nil
	}
	failC := func(t *testing.T, share string, alsoBackup bool) {
		realRename, realRemove := rename, removeAll
		rename = func(from, to string) error {
			if strings.Contains(from, ".pfbstagedir_") && filepath.Base(to) == "c.csv" {
				return os.ErrPermission // the publication fails part-way
			}
			if alsoBackup && strings.Contains(from, ".pfbbackup_") {
				return os.ErrPermission // and so does putting a.csv back
			}
			return realRename(from, to)
		}
		removeAll = func(path string) error {
			if path == filepath.Join(share, "b.csv") {
				return os.ErrPermission // the new b.csv cannot be taken out
			}
			return realRemove(path)
		}
		t.Cleanup(func() { rename, removeAll = realRename, realRemove })
	}
	t.Run("a backup not put back", func(t *testing.T) {
		share := t.TempDir()
		if err := os.WriteFile(filepath.Join(share, "a.csv"), []byte("old a\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		failC(t, share, true)
		ok, left := (&Fetcher{}).mergeIntoDir(share, write)
		backups, _ := filepath.Glob(filepath.Join(share, ".pfbbackup_*"))
		if ok || len(backups) != 1 || left != backups[0]+" "+filepath.Join(share, "b.csv") {
			t.Errorf("(merged, left) = (%v, %q), want a failure naming the backup %v and b.csv", ok, left, backups)
		}
	})
	t.Run("a new entry not removed", func(t *testing.T) {
		share := t.TempDir()
		failC(t, share, false)
		ok, left := (&Fetcher{}).mergeIntoDir(share, write)
		if ok || left != filepath.Join(share, "b.csv") {
			t.Errorf("(merged, left) = (%v, %q), want a failure naming b.csv", ok, left)
		}
	})
	t.Run("a complete rollback leaves nothing", func(t *testing.T) {
		share := t.TempDir()
		realRename := rename
		rename = func(from, to string) error {
			if strings.Contains(from, ".pfbstagedir_") && filepath.Base(to) == "c.csv" {
				return os.ErrPermission
			}
			return realRename(from, to)
		}
		t.Cleanup(func() { rename = realRename })
		if ok, left := (&Fetcher{}).mergeIntoDir(share, write); ok || left != "" {
			t.Errorf("(merged, left) = (%v, %q), want a failure that left nothing", ok, left)
		}
	})
	t.Run("the row's refusal", func(t *testing.T) {
		r := published(func(string, func(string) error) (bool, string) { return false, "/share/.pfbbackup_1" }, "/share",
			"geoip", "GeoLite2-Country.tar.gz", func(string) error { return nil })
		if want := refused("publish", "rollback_incomplete", "/share/.pfbbackup_1"); r != want {
			t.Errorf("refusal = %+v, want %+v", r, want)
		}
	})
}

// A dcc with no row to download still runs pfblockerng_download_extras() over an empty table, then the conversion and
// the exit formula (pfblockerng.php:374-386): a pending geoip.update makes a scheduled run exit 2 (#4119 review).
func TestADccWithNoRowStillConvertsAndReportsTheGeoIPChange(t *testing.T) {
	db := t.TempDir()
	if err := os.WriteFile(filepath.Join(db, "geoip.update"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	f := &Fetcher{RetryDelay: 1}
	f.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		t.Error("a dcc with no row resolved a host")
		return nil, errors.New("no such host")
	}
	converted := false
	var log strings.Builder
	code, _ := f.RunExtras(context.Background(), ExtrasVerb{Name: "dcc", Args: []string{"scheduled"}, GeoIPShare: t.TempDir(),
		DBDir: db, Settings: ExtrasSettings{Top1MProvider: "tranco"}, Log: &log,
		Convert: func(context.Context) bool { converted = true; return true }})
	if code != 2 || !converted || !strings.Contains(log.String(), "Download Process Starting") {
		t.Errorf("(exit, converted) = (%d, %v), log %q; want (2, true) and the download's start", code, converted, log.String())
	}
}

// A run's configuration carries every setting the transfers need: the MaxMind credentials, the IPinfo and TOP1M tokens,
// the database folder for the update markers, the ASN table hook, and the change detector for dcc alone (#4119 review).
func TestAVerbsConfigurationCarriesItsSettings(t *testing.T) {
	s := verbSettings()
	s.Top1MToken = "tt"
	for verb, detect := range map[string]bool{"dcc": true, "dc": false, "al": false, "bl": false} {
		ran := false
		c := ExtrasVerb{Name: verb, GeoIPShare: "/share", DBDir: "/db", Settings: s,
			ASNTable: func(context.Context) { ran = true }}.config()
		if c.DBDir != "/db" || c.MaxMindAccount != "1" || c.MaxMindKey != "mk" || c.ASNToken != "it" || c.Top1MToken != "tt" ||
			c.Detect != detect || c.ASNTable == nil {
			t.Errorf("%s: config = %+v, want every setting and detect %v", verb, c, detect)
			continue
		}
		if c.ASNTable(context.Background()); !ran {
			t.Errorf("%s: the ASN table hook is not the verb's", verb)
		}
	}
}

// A feed path ending in "." or ".." names no file: the row would download beside the database folder (#4119 review).
func TestAFeedEndingInADotNamesNoFile(t *testing.T) {
	for _, feed := range []string{"https://lists.example/a/..", "https://lists.example/a/.", "https://lists.example/.."} {
		s := verbSettings()
		s.Providers[1].Feed = feed
		var log strings.Builder
		rows := ExtrasVerb{Name: "bl", Args: []string{"ex"}, DBDir: "/db", Settings: s}.plan(func(m string) { log.WriteString(m) })
		if len(rows) != 0 || log.String() != "\nBlacklist provider [ ex ] skipped: its feed names no file\n" {
			t.Errorf("%s: rows %+v, log %q; want none and the skip", feed, rows, log.String())
		}
	}
}

// bl logs no Blacklist report (only bls prints it, pfblockerng.php:442-448); an unknown id is logged once, an empty one
// never (#4119 review).
func TestTheBlacklistVerbsLogs(t *testing.T) {
	f := &Fetcher{RetryDelay: 1}
	f.Resolve = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no such host") }
	var log strings.Builder
	f.RunExtras(context.Background(), ExtrasVerb{Name: "bl", Args: []string{",gone,ex,gone,"}, GeoIPShare: t.TempDir(),
		DBDir: t.TempDir(), Settings: verbSettings(), Log: &log})
	if strings.Contains(log.String(), "... Failed") {
		t.Errorf("bl logged the Blacklist report:\n%s", log.String())
	}
	if n := strings.Count(log.String(), "skipped"); n != 1 || !strings.Contains(log.String(), "[ gone ] skipped") {
		t.Errorf("skip lines = %d, want one for gone:\n%s", n, log.String())
	}
}

// A geoip row the run's end cut short blocks the conversion, as PHP's maxmind_feed_error does for any geoip failure: its
// data is not new. The rows decide, not the context's state when the exit code is worked out (#4119 review, round 2).
func TestAnAbortedGeoIPRowBlocksTheConversion(t *testing.T) {
	converted := false
	v := ExtrasVerb{Name: "dcc", DBDir: t.TempDir(), Settings: verbSettings(),
		Convert: func(context.Context) bool { converted = true; return true }}
	res := ExtrasResult{Rows: []ExtrasRow{{Kind: "geoip", Download: "GeoLite2-Country.tar.gz",
		Result: refused("aborted", context.Canceled.Error(), "")}}}
	if code := v.exit(context.Background(), res); code != 1 || converted {
		t.Errorf("(exit, converted) = (%d, %v), want (1, false)", code, converted)
	}
}

// A run whose context ended never reports success and starts no conversion, whatever its rows did: an ended scheduled
// dcc over a pending geoip.update exits 3, not 2 (#4119 review, round 3).
func TestAnEndedRunNeverSucceedsNorConverts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, convert := range []bool{true, false} {
		db := t.TempDir()
		if err := os.WriteFile(filepath.Join(db, "geoip.update"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		converted := false
		v := ExtrasVerb{Name: "dcc", Args: []string{"scheduled"}, DBDir: db, Settings: verbSettings()}
		if convert {
			v.Convert = func(context.Context) bool { converted = true; return true }
		}
		if code := v.exit(ctx, ExtrasResult{OK: true}); code != 3 || converted {
			t.Errorf("convert set %v: (exit, converted) = (%d, %v), want (3, false)", convert, code, converted)
		}
	}
}

// Any failed geoip row blocks the conversion, whatever its stage, as PHP's maxmind_feed_error does (#4119 review,
// round 3).
func TestAnyFailedGeoIPRowBlocksTheConversion(t *testing.T) {
	for _, stage := range []string{"fetch", "aborted", "publish"} {
		converted := false
		v := ExtrasVerb{Name: "dcc", DBDir: t.TempDir(), Settings: verbSettings(),
			Convert: func(context.Context) bool { converted = true; return true }}
		res := ExtrasResult{Rows: []ExtrasRow{{Kind: "geoip", Result: refused(stage, "r", "")}}}
		if code := v.exit(context.Background(), res); code != 1 || converted {
			t.Errorf("%s: (exit, converted) = (%d, %v), want (1, false)", stage, code, converted)
		}
	}
}

// The archive's name is the last segment of the feed's path as written, without the query or fragment: a space, a
// non-ASCII letter or a malformed escape stays as pathinfo() keeps it. A feed with no path names no file, so userinfo
// never becomes a name.
func TestABlacklistArchiveNameIsThePathAsWritten(t *testing.T) {
	for feed, want := range map[string]string{
		"https://lists.example/cat/my list.tar.gz":       "my list.tar.gz",
		"https://lists.example/catégories.tar.gz":        "catégories.tar.gz",
		"https://lists.example/a%zz.tar.gz?key=k#frag":   "a%zz.tar.gz",
		"https://lists.example/cat/my%20list.tar.gz#x?y": "my%20list.tar.gz",
		"https://user:pw@lists.example":                  "",
		"https://user:pw@lists.example?x=/a.tar.gz":      "",
	} {
		s := verbSettings()
		s.Providers[1].Feed = feed
		rows := ExtrasVerb{Name: "bl", Args: []string{"ex"}, DBDir: "/db", Settings: s}.plan(func(string) {})
		got := ""
		if len(rows) == 1 {
			got = rows[0].Download
		}
		if got != want || (len(rows) == 1 && rows[0].File != want) {
			t.Errorf("%s: rows %+v, want the name %q", feed, rows, want)
		}
	}
}

// A feed with no path is skipped, never downloaded under an empty name: Dir joined with "" is the database folder
// itself. A URL inside a scheme-less feed's query does not name the file (#4119 review, round 3).
func TestAFeedWithNoPathIsSkipped(t *testing.T) {
	for feed, want := range map[string]string{
		"https://user:pw@lists.example":             "",
		"https://user:pw@lists.example?x=/a.tar.gz": "",
		"lists.example/a.tar.gz?u=http://x/y":       "a.tar.gz",
	} {
		s := verbSettings()
		s.Providers[1].Feed = feed
		var log strings.Builder
		rows := ExtrasVerb{Name: "bl", Args: []string{"ex"}, DBDir: "/db", Settings: s}.plan(func(m string) { log.WriteString(m) })
		switch {
		case want == "" && (len(rows) != 0 || log.String() != "\nBlacklist provider [ ex ] skipped: its feed names no file\n"):
			t.Errorf("%s: rows %+v, log %q; want none and the skip", feed, rows, log.String())
		case want != "" && (len(rows) != 1 || rows[0].Download != want):
			t.Errorf("%s: rows %+v, want the name %q", feed, rows, want)
		}
	}
}

// Only a failed geoip row blocks the conversion: an aborted TOP1M or ASN row does not (pfblockerng.php:668-670).
func TestAnAbortedNonGeoIPRowDoesNotBlockTheConversion(t *testing.T) {
	converted := false
	v := ExtrasVerb{Name: "dcc", DBDir: t.TempDir(), Settings: verbSettings(),
		Convert: func(context.Context) bool { converted = true; return true }}
	res := ExtrasResult{Rows: []ExtrasRow{{Kind: "geoip", Result: accepted},
		{Kind: "top1m", Result: refused("aborted", context.Canceled.Error(), "")}}}
	if code := v.exit(context.Background(), res); code != 1 || !converted {
		t.Errorf("(exit, converted) = (%d, %v), want (1, true)", code, converted)
	}
}

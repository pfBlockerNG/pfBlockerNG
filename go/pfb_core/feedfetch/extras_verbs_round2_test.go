package feedfetch

import (
	"context"
	"testing"
)

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

// A run whose rows all succeeded converts even when its context ends after them: the conversion's own failure, not a
// skipped conversion, decides the exit, so the verb never exits 0 or 2 over data it did not convert.
func TestAConversionAfterTheRunEndedStillDecidesTheExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	converted := false
	v := ExtrasVerb{Name: "dcc", DBDir: t.TempDir(), Settings: verbSettings(),
		Convert: func(ctx context.Context) bool { converted = true; return ctx.Err() == nil }}
	if code := v.exit(ctx, ExtrasResult{OK: true}); code != 1 || !converted {
		t.Errorf("(exit, converted) = (%d, %v), want (1, true)", code, converted)
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

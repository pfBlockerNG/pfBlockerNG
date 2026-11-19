package feedfetch_test

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// The secrets of a box with every Extra configured; none may reach what a verb logs.
var verbSecrets = []string{"mmkey-secret", "ipinfo-secret", "top1m-secret", "bl-password-secret", "bl-query-secret"}

func verbBox() feedfetch.ExtrasSettings {
	return feedfetch.ExtrasSettings{MaxMindAccount: "123456", MaxMindKey: "mmkey-secret", ASNToken: "ipinfo-secret", Top1M: true,
		Top1MProvider: "cloudflare", Top1MToken: "top1m-secret", Providers: []feedfetch.BlacklistProvider{{ID: "ex", Title: "Example",
			Feed: "https://lists.example/cat/ex.tar.gz?key=bl-query-secret", Username: "user", Password: "bl-password-secret",
			Selected: true}}}
}

// A verb logs its run as pfblockerng_download_extras() does (pfblockerng.php:547-694): the start, a line for each Extra that
// failed, with why (its stage, reason and what was detected: PHP logs only the file name), and the end; bls then logs the
// Blacklist report. No secret reaches the log (issue #3978).
func TestAnExtrasVerbLogsEachFailureWithoutASecret(t *testing.T) {
	f := &feedfetch.Fetcher{RetryDelay: 1}
	f.Resolve = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no such host") }
	for _, tc := range []struct {
		verb  string
		args  []string
		lines []string
	}{
		{"dcc", nil, []string{
			"\nDownload Process Starting\n",
			"\nFailed to Download GeoLite2-Country.mmdb [ stage=fetch ",
			"\nFailed to Download GeoLite2-Country-CSV.zip [ stage=fetch ",
			"\nFailed to Download top-1m.csv [ stage=fetch ",
			"\nFailed to Download asn.mmdb [ stage=fetch ",
			"\nFailed to Download asn.csv [ stage=fetch ",
			"Download Process Ended\n\n",
		}},
		{"bls", []string{"scheduled", "ex"}, []string{
			"\nDownload Process Starting\n",
			"\nFailed to Download ex.tar.gz [ stage=fetch ",
			"Download Process Ended\n\n\tExample ... Failed\n",
		}},
	} {
		t.Run(tc.verb, func(t *testing.T) {
			var log strings.Builder
			code, res := f.RunExtras(context.Background(), feedfetch.ExtrasVerb{Name: tc.verb, Args: tc.args,
				GeoIPShare: t.TempDir(), DBDir: t.TempDir(), Settings: verbBox(), Log: &log})
			if code != 1 || res.OK {
				t.Errorf("(exit, ok) = (%d, %v), want (1, false)", code, res.OK)
			}
			at := 0
			for _, line := range tc.lines {
				i := strings.Index(log.String()[at:], line)
				if i < 0 {
					t.Errorf("log lacks %q after offset %d:\n%s", line, at, log.String())
					break // the secret check below still runs
				}
				at += i + len(line)
			}
			for _, secret := range verbSecrets {
				if strings.Contains(log.String(), secret) {
					t.Errorf("the log carries the secret %q:\n%s", secret, log.String())
				}
			}
		})
	}
}

// A verb before its download: bu and asn without their credentials, bl naming no provider, end with exit 0 and no
// download, as PHP's return and break do (pfblockerng.php:381-384, :402-410, :437-439). A verb that is not an Extras verb
// exits 1.
func TestAnExtrasVerbWithNothingToDownloadExitsZero(t *testing.T) {
	f := &feedfetch.Fetcher{RetryDelay: 1}
	f.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		t.Error("a verb with nothing to download resolved a host")
		return nil, errors.New("no such host")
	}
	for _, tc := range []struct {
		verb string
		args []string
		edit func(*feedfetch.ExtrasSettings)
		want int
	}{
		{"bu", nil, func(s *feedfetch.ExtrasSettings) { s.MaxMindKey = "" }, 0},
		{"asn", nil, func(s *feedfetch.ExtrasSettings) { s.ASNToken = "" }, 0},
		{"bl", []string{"scheduled", "gone"}, nil, 0},
		{"uc", nil, nil, 1},
	} {
		s := verbBox()
		if tc.edit != nil {
			tc.edit(&s)
		}
		var log strings.Builder
		code, res := f.RunExtras(context.Background(), feedfetch.ExtrasVerb{Name: tc.verb, Args: tc.args,
			GeoIPShare: t.TempDir(), DBDir: t.TempDir(), Settings: s, Log: &log})
		if code != tc.want || len(res.Rows) != 0 || strings.Contains(log.String(), "Download Process") {
			t.Errorf("%s: (exit, rows) = (%d, %d), log %q; want (%d, 0) and no download", tc.verb, code, len(res.Rows),
				log.String(), tc.want)
		}
	}
}

// A TOP1M row that reads aborted leaves the ledger alone: the run ended, so neither the probe nor the download failed
// (#4085 review). PHP opens the entry with "TOP1M probe failed" or "TOP1M download failed".
func TestAnAbortedTOP1MRowLeavesTheLedger(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, detect := range []bool{true, false} {
		dir := t.TempDir()
		res := extrasFetcher().DownloadExtras(ctx, feedfetch.ExtrasConfig{DBDir: dir, Detect: detect},
			[]feedfetch.Extra{{Kind: "top1m", URL: "http://tranco-list.eu:9/top-1m.csv.zip", Dir: dir,
				Download: "top-1m.csv.zip", File: "top-1m.csv", Provider: "tranco"}})
		if r := res.Rows[0]; r.Stage != "aborted" || res.Top1MLedger != nil {
			t.Errorf("detect %v: (stage, ledger) = (%q, %v), want (aborted, nil)", detect, r.Stage, res.Top1MLedger)
		}
	}
}

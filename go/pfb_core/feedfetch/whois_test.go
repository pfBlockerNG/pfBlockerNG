package feedfetch_test

// What the corpus cannot say about Fetcher.Whois: it is Core's own, so there is no shell to hold it to.

import (
	"context"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

func TestWhoisBudgetReadsTheOverrideAsTheShellDoes(t *testing.T) {
	const def = 1800 * time.Second
	for override, want := range map[string]time.Duration{
		"":                     def,
		"abc":                  def,
		"0":                    def,
		"000":                  def,
		"+5":                   def,
		"-5":                   def,
		" 5":                   def,
		"5 ":                   def,
		"1e3":                  def,
		"５":                    def, // fullwidth digit: not 0-9
		"99999999999999999999": def, // beyond the integer range
		"1":                    time.Second,
		"007":                  7 * time.Second,
		"12":                   12 * time.Second,
		"9223372036854775808":  def,                          // one past the largest integer dash's [ -gt ] reads
		"9223372036854775807":  time.Duration(math.MaxInt64), // the largest it reads: longer than any batch, capped not wrapped
	} {
		if got := feedfetch.WhoisBudget(override); got != want {
			t.Errorf("WhoisBudget(%q) = %v, want %v", override, got, want)
		}
	}
}

// whoisFixture is a Fetcher whose lookup answers one address per family for any name.
func whoisFixture(t *testing.T) (*feedfetch.Fetcher, feedfetch.Feed, string) {
	t.Helper()
	dir := t.TempDir()
	f := &feedfetch.Fetcher{
		ASNCSV: filepath.Join(t.TempDir(), "asn.csv"),
		Lookup: func(_ context.Context, network, _ string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("2001:db8::5")}, nil
		},
	}
	return f, feedfetch.Feed{Dir: dir, Name: "CorpusList"}, filepath.Join(dir, "CorpusList.orig")
}

func TestWhoisCancelledRunKeepsThePublishedCopyAndLeavesNoMarker(t *testing.T) {
	f, feed, orig := whoisFixture(t)
	if err := os.WriteFile(orig, []byte("198.51.100.7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.Lookup = func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		cancel() // Core shutting down mid-lookup
		return nil, ctx.Err()
	}
	res := f.Whois(ctx, feed, feedfetch.WhoisRequest{List: "a.example,b.example"})
	if res.Reason == "" {
		t.Error("a cancelled run reports no reason")
	}
	if res.Found || res.Failed {
		t.Errorf("cancelled run reports Found=%v Failed=%v, want neither", res.Found, res.Failed)
	}
	if got, _ := os.ReadFile(orig); string(got) != "198.51.100.7\n" {
		t.Errorf("published copy = %q, want it untouched", got)
	}
	if entries, _ := os.ReadDir(feed.Dir); len(entries) != 1 {
		t.Errorf("feed directory holds %d files, want only the published copy", len(entries))
	}
}

func TestWhoisRefusesAFeedNameThatIsNotAWord(t *testing.T) {
	f, feed, _ := whoisFixture(t)
	for _, name := range []string{"", "../escape", "a/b", "a b", "a.b"} {
		feed.Name = name
		if res := f.Whois(context.Background(), feed, feedfetch.WhoisRequest{List: "a.example"}); res.Reason == "" {
			t.Errorf("feed name %q accepted", name)
		}
	}
	if entries, _ := os.ReadDir(filepath.Dir(feed.Dir)); len(entries) != 2 { // the feed and asn.csv directories only
		t.Errorf("a refused name left files behind: %v", entries)
	}
	if entries, _ := os.ReadDir(feed.Dir); len(entries) != 0 {
		t.Errorf("a refused name left files in the feed directory: %v", entries)
	}
}

func TestWhoisWithoutADownloadHookLeavesASNCSVMissing(t *testing.T) {
	f, feed, orig := whoisFixture(t)
	if err := os.WriteFile(orig, []byte("198.51.100.7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := f.Whois(context.Background(), feed, feedfetch.WhoisRequest{List: "AS64500"})
	want := []string{"Database ASN [ asn.csv ] not found. Register for IPinfo Token."}
	if !reflect.DeepEqual(res.ErrorLog, want) {
		t.Errorf("error log = %q, want %q", res.ErrorLog, want)
	}
	if strings.Contains(res.Log, "Downloading") {
		t.Errorf("a download was announced with no hook:\n%s", res.Log)
	}
	if !res.Failed || res.Found {
		t.Errorf("Failed=%v Found=%v, want the entry failed and nothing found", res.Failed, res.Found)
	}
	if got, _ := os.ReadFile(orig); string(got) != "198.51.100.7\n" {
		t.Errorf("published copy = %q, want the previous one", got)
	}
}

func TestWhoisKeepsOnlyTheRequestedFamilyWhateverTheLookupReturns(t *testing.T) {
	for _, tc := range []struct {
		ipv6 bool
		want string
	}{
		{false, "### Domain: a.example ###\n203.0.113.5\n"},
		{true, "### Domain: a.example ###\n2001:db8::5\n"},
	} {
		f, feed, orig := whoisFixture(t)
		res := f.Whois(context.Background(), feed, feedfetch.WhoisRequest{List: "a.example", IPv6: tc.ipv6})
		if got, _ := os.ReadFile(orig); string(got) != tc.want || !res.Found {
			t.Errorf("ipv6=%v: published %q (found %v), want %q", tc.ipv6, got, res.Found, tc.want)
		}
	}
}

func TestWhoisWithNoBudgetBoundsEachLookupAtThirtySeconds(t *testing.T) {
	f, feed, _ := whoisFixture(t)
	bound := -1
	f.Lookup = func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		if deadline, ok := ctx.Deadline(); ok {
			bound = int(math.Round(time.Until(deadline).Seconds()))
		}
		return nil, context.DeadlineExceeded
	}
	f.Whois(context.Background(), feed, feedfetch.WhoisRequest{List: "a.example"})
	if bound != 30 {
		t.Errorf("lookup bounded at %d s, want 30", bound)
	}
}

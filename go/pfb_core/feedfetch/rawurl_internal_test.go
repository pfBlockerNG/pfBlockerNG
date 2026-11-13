package feedfetch

import (
	"context"
	"net/netip"
	"testing"
)

// A URL on a non-ASCII host is requested on the mapped host with every other part as written, as
// pfb_feed_redirect_target rebuilds it: an empty userinfo or query keeps its delimiter, the fragment goes.
var mappedHostURLs = []struct{ name, in, want string }{
	{"plain", "http://ＢÜCHER.example/p", "http://xn--bcher-kva.example/p"},
	{"userinfo port query", "http://u:p%40ss@ＢÜCHER.example:8080/p/q?a=b&c=d%20e",
		"http://u:p%40ss@xn--bcher-kva.example:8080/p/q?a=b&c=d%20e"},
	{"empty query", "http://ＢÜCHER.example/p?", "http://xn--bcher-kva.example/p?"},
	{"empty userinfo", "http://@ＢÜCHER.example/p", "http://@xn--bcher-kva.example/p"},
	{"empty password", "http://u:@ＢÜCHER.example/p", "http://u:@xn--bcher-kva.example/p"},
	{"fragment", "http://ＢÜCHER.example/p?a=b#frag", "http://xn--bcher-kva.example/p?a=b"},
}

func TestAFeedURLOnANonASCIIHostIsRequestedOnTheMappedHostOtherwiseAsWritten(t *testing.T) {
	f := &Fetcher{Policy: Policy{Resolve: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.5")}, nil
	}}}
	for _, c := range mappedHostURLs {
		t.Run(c.name, func(t *testing.T) {
			src, reason := f.entry(context.Background(), Request{URL: c.in})
			if src == nil {
				t.Fatalf("entry refused %q: %q", c.in, reason)
			}
			if src.path != c.want || src.host != "xn--bcher-kva.example" {
				t.Errorf("entry %q\n want %q on xn--bcher-kva.example\n  got %q on %q", c.in, c.want, src.path, src.host)
			}
		})
	}
}

func TestARedirectToANonASCIIHostIsRequestedOnTheMappedHostOtherwiseAsWritten(t *testing.T) {
	f := &Fetcher{Policy: Policy{Resolve: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.5")}, nil
	}}}
	for _, c := range mappedHostURLs {
		t.Run(c.name, func(t *testing.T) {
			target, next, _, reason := f.redirectTarget(context.Background(), c.in, "http://feed.example/start")
			if reason != "" {
				t.Fatalf("redirect to %q refused: %q", c.in, reason)
			}
			if target != c.want || next.host != "xn--bcher-kva.example" {
				t.Errorf("redirect to %q\n want %q on xn--bcher-kva.example\n  got %q on %q", c.in, c.want, target, next.host)
			}
		})
	}
}

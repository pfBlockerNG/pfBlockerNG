package feedparse

import (
	"bytes"
	"strings"
	"testing"
)

func parseDNSBLReview(input string) (DNSBLFeed, []byte, []FailRecord, error) {
	var out bytes.Buffer
	var fails []FailRecord
	feed, err := ParseDNSBLFeed(strings.NewReader(input), DNSBLConfig{DNSBLIP: true, ParseMode: ParseLenient}, &out, Sink{
		Fail: func(rec FailRecord) { fails = append(fails, rec) },
	})
	return feed, out.Bytes(), fails, err
}

func TestDNSBLFeedContinuesAfterNoncanonicalIPv6(t *testing.T) {
	for _, address := range []string{
		"::ffff:01.2.3.4",
		"::1.2.3.04",
		"ffff::01.2.3.4",
		"fe80::1%",
		"2001:db8::1.2.3.04",
	} {
		t.Run(address, func(t *testing.T) {
			input := "before.example.com\n" + address + "\nafter.example.com\n"
			feed, out, fails, err := parseDNSBLReview(input)
			if err != nil {
				t.Fatalf("one accepted IPv6 spelling failed the feed: %v", err)
			}
			want := []byte("[\"d\",\"before.example.com\"]\n[\"d\",\"after.example.com\"]\n")
			if feed.Rows != 2 || !bytes.Equal(out, want) {
				t.Errorf("feed lost rows around %q: rows=%d output=%q", address, feed.Rows, out)
			}
			if !feed.UpdateIP || len(feed.IP4)+len(feed.IP6) != 1 || len(fails) != 0 {
				t.Errorf("accepted IP result = %+v, v4=%q v6=%q failures=%+v", feed, feed.IP4, feed.IP6, fails)
			}
		})
	}
}

func TestDNSBLDeduplicatesOnlyIdenticalIPv6Spellings(t *testing.T) {
	lines := []string{"2001:db8::1", "2001:DB8::1", "2001:db8:0:0:0:0:0:1"}
	feed, _, _, err := parseDNSBLReview(strings.Join(lines, "\n") + "\n")
	if err != nil {
		t.Fatalf("ParseDNSBLFeed: %v", err)
	}
	if !sameStrings(feed.IP6, lines) {
		t.Errorf("IPv6 spellings = %q, want array_unique's exact-string order %q", feed.IP6, lines)
	}
}

func TestDNSBLKeepsSameBaseWithDifferentPrefixLengths(t *testing.T) {
	want := []string{"10.0.0.0/24", "10.0.0.0/8"}
	feed, _, _, err := parseDNSBLReview(strings.Join(want, "\n") + "\n")
	if err != nil {
		t.Fatalf("ParseDNSBLFeed: %v", err)
	}
	if !sameStrings(feed.IP4, want) {
		t.Errorf("IPv4 prefixes = %q, want both masks %q", feed.IP4, want)
	}
}

func TestDNSBLKeepsIPv6ZonesAndPrefixLengthsDistinct(t *testing.T) {
	want := []string{"fe80::1%eth0", "fe80::1%eth1", "2001:db8::/32", "2001:db8::/48"}
	feed, _, _, err := parseDNSBLReview(strings.Join(want, "\n") + "\n")
	if err != nil {
		t.Fatalf("ParseDNSBLFeed: %v", err)
	}
	if !sameStrings(feed.IP6, want) {
		t.Errorf("IPv6 entries = %q, want every zone and mask kept %q", feed.IP6, want)
	}
}

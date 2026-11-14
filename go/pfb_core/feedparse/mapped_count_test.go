package feedparse

import (
	"strings"
	"testing"
)

func TestParseIPFeedCountsIPv4MappedDropsSeparately(t *testing.T) {
	var out strings.Builder
	got, err := ParseIPFeed(strings.NewReader("::ffff:192.0.2.1\n"), IPConfig{VType: "_v6"}, "", NoProbe, &out, Sink{})
	if err != nil {
		t.Fatal(err)
	}
	if got.MappedDrops != 1 || got.ParseFail != 1 || got.Entries != 0 {
		t.Fatalf("ParseIPFeed = %+v, want one separately counted mapped drop and one parse failure", got)
	}
}

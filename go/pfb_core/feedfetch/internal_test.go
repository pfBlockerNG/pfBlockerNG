package feedfetch

// Unexported helpers the black-box tests cannot reach: the internal-address table and the validator sidecars.

import (
	"encoding/json"
	"net/netip"
	"os"
	"testing"
	"time"
)

// The shared range table (tests/feedfetch/fixtures/internal_ranges.json) is also run against PHP's
// pfb_ip_is_internal() by tests/php/FeedFetchInternalRangesTest.php: both sides must agree on every boundary.
func TestInternalMatchesTheSharedRangeTable(t *testing.T) {
	raw, err := os.ReadFile("../../../tests/feedfetch/fixtures/internal_ranges.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		IP       string `json:"ip"`
		Internal bool   `json:"internal"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil || len(rows) == 0 {
		t.Fatalf("range table unreadable: %v (%d rows)", err, len(rows))
	}
	for _, row := range rows {
		a, err := netip.ParseAddr(row.IP)
		if err != nil {
			t.Fatalf("table row %q: %v", row.IP, err)
		}
		if got := internal(a); got != row.Internal {
			t.Errorf("internal(%s) = %v, want %v", row.IP, got, row.Internal)
		}
	}
}

// A stored ETag is sent back as a header value, so a CR or LF in it must never reach the sidecar.
func TestWriteValidatorsStripsLineBreaksFromTheETag(t *testing.T) {
	feed := Feed{Dir: t.TempDir(), Name: "FEED"}
	writeValidators(feed, "\"a\rb\nc\"", time.Time{})
	if b, err := os.ReadFile(feed.path(".orig.etag")); err != nil || string(b) != `"abc"` {
		t.Fatalf("stored ETag %q (%v), want %q with CR and LF removed", b, err, `"abc"`)
	}

	// Nothing but line breaks is no ETag at all: an empty sidecar must not be written.
	bare := Feed{Dir: t.TempDir(), Name: "FEED"}
	writeValidators(bare, "\r\n", time.Time{})
	if _, err := os.Stat(bare.path(".orig.etag")); !os.IsNotExist(err) {
		t.Fatalf("an ETag of line breaks only left a sidecar behind: %v", err)
	}
}

// A PASV reply is read as libcurl reads it: from the first digit at which six comma-separated numbers of at most 255
// start, wherever that is in the text; a reply with no such run names no port.
func TestPasvPortReadsTheFirstRunOfSixNumbers(t *testing.T) {
	for msg, want := range map[string]int{
		"Entering Passive Mode (127,0,0,1,4,1)": 4<<8 | 1,
		"Mode 2 127,0,0,1,4,1":                  4<<8 | 1,
		"(1) 127,0,0,1,4,1":                     4<<8 | 1,
		"x 1,2 y 127,0,0,1,4,1":                 4<<8 | 1,
		"(1127,0,0,1,4,1)":                      4<<8 | 1, // from inside a number, as libcurl tries every digit
		"(127,000,0,1,4,1)":                     4<<8 | 1,
		"(127,0,0,1,4)":                         -1,
		"(127,0,0,1,256,1)":                     -1,
		"(127,0,0,1,4,256)":                     -1,
		"(127,0,0,1,ab,cd)":                     -1,
		"Entering Passive Mode":                 -1,
	} {
		port, ok := pasvPort(msg)
		if !ok {
			port = -1
		}
		if port != want {
			t.Errorf("pasvPort(%q) = %d, %v; want %d", msg, port, ok, want)
		}
	}
}

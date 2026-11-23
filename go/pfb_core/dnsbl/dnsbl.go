// Package dnsbl assembles the DNSBL data pfB-DNS builds from into dnsbl/* resources (issue #4036, spec section 9): the
// data today's pfb_unbound_python_sources() writes as the manifest pfb_py_sources.json and its raw feed files, the TOP1M
// sidecar, the SafeSearch table and the PSL authority. Publish writes them into the resource store, the members first
// and dnsbl/manifest last, so the manifest is the one commit point: a consumer that reads it finds every body it names.
//
//	dnsbl/manifest     JSON Lines: one config row; one whitelist, unlock, tld_blacklist or tld_exclusion row per entry;
//	                   one feed row per feed (position, attributes, and its body's resource, generation, digest and
//	                   entries); one member row per other body. Metadata: the per-group entry counts.
//	dnsbl/feed-<name>  plain text: the feed's rows, each a domain or a verbatim ABP rule, as a .raw file holds them.
//	dnsbl/top1m        plain text: the TOP1M whitelist, one domain per line.
//	dnsbl/safesearch   JSON Lines: {"host", "a", "aaaa", "v4", "v6"}, v4 and v6 only on a CNAME row.
//	dnsbl/psl          JSON Lines: {"section": "icann" or "private", "rule"}.
//
// A body is a sorted set (owner, 2026-11-23): a feed's rows lose their order and repeats, which changes no block or
// allow decision; the departures are pinned in tests/core/fixtures/dnsbl_resources_parity.json.
package dnsbl

import (
	"errors"
	"io"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

// The resource ids. A feed's is FeedPrefix followed by its name.
const (
	ManifestID   = "dnsbl/manifest"
	Top1mID      = "dnsbl/top1m"
	SafeSearchID = "dnsbl/safesearch"
	PSLID        = "dnsbl/psl"
	FeedPrefix   = "dnsbl/feed-"
)

// Feed is one feed, in the order the build reads the feeds: the order decides which feed a domain listed twice belongs to.
type Feed struct {
	Name       string // the feed header: letters, digits and underscores (PFB_FILTER_WORD)
	Group      string
	LogFlag    string
	Provenance string   // "user" for a Custom_List; anything else is "feed"
	Mode       string   // "permit" for a permit feed; anything else is "deny"
	Top1m      bool     // the group's "TOP1M Whitelist" box
	Rows       []string // domains and verbatim ABP rules, in any order; Publish sorts them in place
}

// SafeSearch is one row of the SafeSearch table: an A and AAAA rewrite, or a CNAME redirect with its baked addresses.
type SafeSearch struct {
	Host string `json:"host"`
	A    string `json:"a"`
	AAAA string `json:"aaaa"`
	V4   string `json:"v4,omitempty"`
	V6   string `json:"v6,omitempty"`
}

// Set is everything Publish writes. A nil Top1m, SafeSearch or PSL publishes no body for it.
type Set struct {
	BuiltinLogFlag string
	Top1mEnabled   bool
	Whitelist      []string
	Unlock         []string
	TLDBlacklist   []string // published by the caller only while dns.tldWildcard is on, as today
	TLDExclusions  []string
	Feeds          []Feed
	Top1m          []string
	SafeSearch     []SafeSearch // a host listed twice keeps its last row
	PSL            []byte       // the PSL text with its four section markers
}

// Result is what Publish did.
type Result struct {
	Generation uint64         // dnsbl/manifest's: the apply request's dnsbl.generation
	Dropped    map[string]int // resource id: rows left out because the store cannot hold them
	Refused    []string       // feeds left out because their name is not letters, digits and underscores
}

var errNotImplemented = errors.New("dnsbl: not implemented")

// ReadStaged is not implemented yet.
func ReadStaged(r io.Reader) (rows []string, invalid int, err error) {
	return nil, 0, errNotImplemented
}

// Publish is not implemented yet.
func Publish(store *resources.Store, set Set) (Result, error) { return Result{}, errNotImplemented }

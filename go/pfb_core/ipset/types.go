package ipset

// Family is the address family of a list; a feed or logical-set name carries it as the suffix "_v4" or "_v6".
type Family string

const (
	V4 Family = "v4"
	V6 Family = "v6"
)

// Feed is one named member list as the raw text of its file. CRLF, a missing final newline, blank lines and order are
// significant.
type Feed struct{ Name, Text string }

// List is one named member list as the lines of its file: the text split at "\n", a final unterminated line counted, "\r"
// kept in its line.
type List struct {
	Name  string
	Lines []string
}

// GeoLookup maps the first three octets of an IPv4 address ("203.0.113") to an ISO country code, "" for an unknown address.
// A nil GeoLookup means there is no GeoIP tool at all.
type GeoLookup func(octets string) string

// RepMode is the reputation stage of a recompute pass; only v4 passes honour it.
type RepMode string

const (
	RepOff  RepMode = "off"
	RepDMax RepMode = "dmax"
	RepPMax RepMode = "pmax"
)

// Reputation is the dMax and pMax setting. Max is the member count per /24 that a /24 must exceed to be an offender. The rest
// is dMax only: CC is a comma separated country list (no spaces) matched entry by entry, CCWhite and CCBlack are "match",
// "block" or any other value, and Geo classifies each offender /24.
type Reputation struct {
	Max              int
	CC               string
	CCWhite, CCBlack string
	Geo              GeoLookup
}

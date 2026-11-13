// Package settings is Core's native settings (issues #3842, #3924; map #3813): a schema of typed projections, held in
// memory and loaded from a Backend (a file in the state directory, or the Outpost's adapter command).
// docs/misc/core-api-protocol.md documents the API methods over it.
package settings

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Type is a field's native JSON type.
type Type string

const (
	TypeBool   Type = "bool"
	TypeInt    Type = "int"
	TypeEnum   Type = "enum"
	TypeString Type = "string"
	TypeList   Type = "list" // a JSON array of objects, each with the fields Items; Key names the field that identifies one
)

// Field is one setting. A secret is write-only: a read shows only whether it is set. Requires names a bool field of the
// same projection: while that one is false, this bool is held false. A string matches Pattern (when set) and is none of
// Reserved. A list's items are objects of the fields Items, its Key field unique and non-empty across them; Check and
// CheckList (not published) refuse an item whose fields, or a list whose items, do not hold together. Check also refuses a
// scalar field's decoded value, which it gets as {Name: value}.
type Field struct {
	Name     string   `json:"name"`
	Type     Type     `json:"type"`
	Default  any      `json:"default"`
	Enum     []string `json:"enum,omitempty"`
	Min      *int64   `json:"min,omitempty"`
	Max      *int64   `json:"max,omitempty"`
	Secret   bool     `json:"secret,omitempty"`
	Requires string   `json:"requires,omitempty"`
	Pattern  string   `json:"pattern,omitempty"`
	Reserved []string `json:"reserved,omitempty"`
	Key      string   `json:"key,omitempty"`
	Items    []Field  `json:"items,omitempty"`

	Check     func(item map[string]any) []FieldError `json:"-"`
	CheckList func(list []any) []FieldError          `json:"-"` // field names relative to the list: "[i].…"
}

// Projection is a group of fields read and versioned together, published as the resource settings/<ID>.
type Projection struct {
	ID     string  `json:"id"`
	Fields []Field `json:"fields"`
}

// Schema is what GetSettingsSchema answers.
type Schema struct {
	Version     int          `json:"schemaVersion"`
	Projections []Projection `json:"projections"`
}

// Production is Core's schema. dns: the DNSBL resolver settings pfb-dns reads from pfb_unbound.ini today, each with
// the default and range today's PHP gives (tests/core/fixtures/settings_dns_parity.json). feeds/<type>: the IP and
// DNSBL groups and their feeds, as far as downloading and parsing them needs (tests/core/fixtures/settings_feeds_parity.json).
func Production() Schema {
	return Schema{Version: 1, Projections: []Projection{dnsProjection(), feeds("ipv4"), feeds("ipv6"), feeds("dnsbl"), scheduleProjection()}}
}

func dnsProjection() Projection {
	policy := []string{"ignore", "apex", "honor"}
	return Projection{ID: "dns", Fields: []Field{
		{Name: "replyLogging", Type: TypeBool, Default: true},
		{Name: "hstsNullBlocking", Type: TypeBool, Default: true},
		{Name: "tldWildcard", Type: TypeBool, Default: false},
		{Name: "pslIncludePrivate", Type: TypeBool, Default: true},
		{Name: "pslAllowPrivate", Type: TypeBool, Default: false},
		{Name: "pslFeedPrivatePolicy", Type: TypeEnum, Default: "honor", Enum: policy},
		{Name: "pslFeedIcannPolicy", Type: TypeEnum, Default: "honor", Enum: policy},
		{Name: "idnMode", Type: TypeEnum, Default: "off", Enum: []string{"off", "confusable", "on"}},
		{Name: "idnBlockMalicious", Type: TypeBool, Default: true},
		{Name: "idnEscalateSuspicious", Type: TypeBool, Default: false},
		{Name: "decisionCacheMax", Type: TypeInt, Default: int64(10000), Min: new(int64(0)), Max: new(int64(5000000))}, // 0: unlimited
		{Name: "logViaWebserver", Type: TypeBool, Default: false},
		{Name: "cnameValidation", Type: TypeBool, Default: false},
		{Name: "control", Type: TypeBool, Default: false},
		{Name: "controlLegacy", Type: TypeBool, Default: false, Requires: "control"},
		{Name: "regexCap", Type: TypeBool, Default: false},
		{Name: "metricsClientIp", Type: TypeBool, Default: false},
	}}
}

const (
	word      = `^[A-Za-z0-9_]+$`
	printable = `^[^\p{C}<>"]*$` // the Groups editor refuses control characters and < > " in a source
)

// reservedHeaders are the alias names pfBlockerNG builds itself: DNSBL-IP and the GeoIP continents (pfb_header_reserved_error).
var reservedHeaders = []string{"DNSBLIP", "pfB_Top", "pfB_Africa", "pfB_Antarctica", "pfB_Asia", "pfB_Europe", "pfB_NAmerica",
	"pfB_Oceania", "pfB_SAmerica", "pfB_PS"}

// feeds is the projection feeds/<kind>: the groups of one Groups editor tab (IPv4, IPv6, DNSBL) with their feeds. The
// Outpost translates what is local to it: the source interface is the address to bind, a local file a file:// URL, and a
// URL's userinfo the write-only credentials.
func feeds(kind string) Projection {
	ip := kind != "dnsbl"
	name, actions, formats := word, []string{"Disabled", "unbound"}, []string{"auto", "rsync"}
	if ip {
		name = `^[A-Za-z0-9_]{1,24}$` // pfB_<name>_v4 within PF's 31 characters
		actions = []string{"Disabled", "Deny_Inbound", "Deny_Outbound", "Deny_Both", "Permit_Inbound", "Permit_Outbound",
			"Permit_Both", "Match_Inbound", "Match_Outbound", "Match_Both", "Alias_Deny", "Alias_Permit", "Alias_Match", "Alias_Native"}
		formats = []string{"auto", "geoip", "regex", "whois", "asn", "rsync"}
	}
	feed := []Field{
		{Name: "header", Type: TypeString, Default: "", Pattern: word, Reserved: reservedHeaders},
		{Name: "state", Type: TypeEnum, Default: "enabled", Enum: []string{"enabled", "disabled", "hold", "flex"}},
		{Name: "format", Type: TypeEnum, Default: "auto", Enum: formats},
		{Name: "url", Type: TypeString, Default: "", Pattern: printable},
		{Name: "credentials", Type: TypeString, Default: "", Pattern: `^[^\p{C}<>"/?#]*$`, Secret: true}, // / ? # end a userinfo
	}
	if !ip {
		feed = append(feed, Field{Name: "action", Type: TypeEnum, Default: "deny", Enum: []string{"deny", "permit"}})
	}
	group := []Field{
		{Name: "name", Type: TypeString, Default: "", Pattern: name},
		{Name: "action", Type: TypeEnum, Default: "Disabled", Enum: actions},
		{Name: "updateFrequency", Type: TypeEnum, Default: "Never",
			Enum: []string{"Never", "01hour", "02hours", "03hours", "04hours", "06hours", "08hours", "12hours", "EveryDay", "Weekly"}},
		{Name: "bindAddress", Type: TypeString, Default: ""},
		{Name: "preScript", Type: TypeString, Default: "", Pattern: `^[^/\p{C}]*$`},
		{Name: "postScript", Type: TypeString, Default: "", Pattern: `^[^/\p{C}]*$`},
		{Name: "customList", Type: TypeString, Default: ""},
	}
	if kind == "ipv4" {
		group = append(group, Field{Name: "suppressionCidr", Type: TypeInt, Default: int64(0), Min: new(int64(0)), Max: new(int64(32))}) // 0: Disabled
	}
	if ip {
		group = append(group, Field{Name: "whoisConvert", Type: TypeBool, Default: false})
	}
	group = append(group, Field{Name: "feeds", Type: TypeList, Default: []any{}, Key: "header", Items: feed, Check: checkFeed})
	return Projection{ID: "feeds/" + kind, Fields: []Field{
		{Name: "groups", Type: TypeList, Default: []any{}, Key: "name", Items: group, Check: checkGroup, CheckList: uniqueHeaders},
	}}
}

var (
	schemeURL   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)
	userinfoURL = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://[^/?#]*@`)
)

// checkFeed refuses a source the Outpost could not store as given (credentials go into a scheme:// URL's userinfo, a
// local file is a file:// URL), then applies the Groups editor's rule for a feed that is not disabled: it needs a
// source, and not the placeholder of an API key the user has not filled in.
func checkFeed(item map[string]any) []FieldError {
	url := item["url"].(string)
	switch {
	case item["credentials"] != "" && !schemeURL.MatchString(url):
		return []FieldError{{Field: "credentials", Message: "need a scheme:// url"}}
	case userinfoURL.MatchString(url):
		return []FieldError{{Field: "url", Message: "holds credentials: put them in credentials"}}
	case strings.HasPrefix(url, "/"):
		return []FieldError{{Field: "url", Message: "a local file is a file:// url"}}
	case item["state"] == "disabled":
	case url == "":
		return []FieldError{{Field: "url", Message: "required unless the feed is disabled"}}
	case strings.Contains(url, "_API_KEY_"):
		return []FieldError{{Field: "url", Message: "holds the _API_KEY_ placeholder: add the API key or disable the feed"}}
	}
	return nil
}

// uniqueHeaders holds a feed header to one group of the type: it names one file in the type's directory.
func uniqueHeaders(groups []any) []FieldError {
	seen := map[any]bool{}
	var errs []FieldError
	for i, g := range groups {
		for j, f := range g.(map[string]any)["feeds"].([]any) {
			header := f.(map[string]any)["header"]
			if seen[header] {
				errs = append(errs, FieldError{Field: fmt.Sprintf("[%d].feeds[%d].header", i, j), Message: "repeats a header of another group: it names one file of the type"})
			}
			seen[header] = true
		}
	}
	return errs
}

// checkGroup holds bindAddress to an IP address or none.
func checkGroup(item map[string]any) []FieldError {
	if a := item["bindAddress"].(string); a != "" {
		if ip, err := netip.ParseAddr(a); err != nil || ip.Zone() != "" {
			return []FieldError{{Field: "bindAddress", Message: "must be an IP address or empty"}}
		}
	}
	return nil
}

package settings

import (
	"fmt"
	"net/netip"
	"strings"
)

// policyIPProjection is settings/policy/ip (issue #4031): the IP policy the Update loop applies after the feeds are downloaded, as the
// Outpost reads it from its configuration: deduplication and aggregation, the three Reputation passes with their limits, what
// to do with the country lists, and the two suppression lists. The Outpost lists each list entry once and only the ones below; Core
// still refuses the rest, as it does not trust a backend. tests/core/fixtures/settings_policy_ip_parity.json is the parity fixture.
func policyIPProjection() Projection {
	limit := func(name string) Field {
		return Field{Name: name, Type: TypeInt, Default: int64(0), Min: new(int64(0)), Max: new(int64(50))} // 0: no limit set
	}
	cidrs := func(name string, v6 bool) Field {
		return Field{Name: name, Type: TypeList, Default: []any{}, Key: "cidr", Check: checkSuppressionEntry(v6),
			Items: []Field{{Name: "cidr", Type: TypeString, Default: ""}}}
	}
	return Projection{ID: "policy/ip", Fields: []Field{
		{Name: "dedup", Type: TypeBool, Default: false},
		{Name: "aggregate", Type: TypeBool, Default: false},
		{Name: "max", Type: TypeBool, Default: false},
		limit("maxLimit"),
		{Name: "pMax", Type: TypeBool, Default: false},
		limit("pMaxLimit"),
		{Name: "dMax", Type: TypeBool, Default: false},
		limit("dMaxLimit"),
		{Name: "countryWhitelistAction", Type: TypeEnum, Default: "ignore", Enum: []string{"ignore", "match"}},
		{Name: "countryBlacklistAction", Type: TypeEnum, Default: "none", Enum: []string{"none", "block", "match"}},
		stringList("countryWhitelist", "code", `^[A-Z][A-Z0-9]$`),
		stringList("etBlock", "category", `^ET_[A-Za-z0-9_]+$`),
		stringList("etMatch", "category", `^ET_[A-Za-z0-9_]+$`),
		cidrs("suppressionV4", false),
		cidrs("suppressionV6", true),
	}}
}

// checkSuppressionEntry holds a suppression entry to a CIDR of its family with no zone, a prefix length the IP page accepts (/8 to /32
// for IPv4, /32 to /128 for IPv6) and no upper-case letter: the Outpost lower-cases what it reads.
func checkSuppressionEntry(v6 bool) func(map[string]any) []FieldError {
	family, lowest, highest := "IPv4", 8, 32
	if v6 {
		family, lowest, highest = "IPv6", 32, 128
	}
	return func(item map[string]any) []FieldError {
		entry := item["cidr"].(string)
		p, err := netip.ParsePrefix(entry)
		if err != nil || p.Addr().Is6() != v6 || p.Bits() < lowest || p.Bits() > highest || entry != strings.ToLower(entry) {
			return []FieldError{{Field: "cidr", Message: fmt.Sprintf("must be a lower-case %s CIDR with a prefix length from %d to %d", family, lowest, highest)}}
		}
		return nil
	}
}

// stringList is a list field of objects holding one string, listed once, that matches pattern.
func stringList(name, item, pattern string) Field {
	return Field{Name: name, Type: TypeList, Default: []any{}, Key: item,
		Items: []Field{{Name: item, Type: TypeString, Default: "", Pattern: pattern}}}
}

// dnsblMechanisms are the logging mechanisms of the Outpost's DNSBL, the first being the VIP response it deprecates.
var dnsblMechanisms = []string{"enabled", "disabled_log", "disabled", "nxdomain_log", "nxdomain", "nodata_log", "nodata"}

// policyDNSBLProjection is settings/policy/dnsbl (issue #4031): the DNSBL build policy the Update loop applies, as the Outpost reads it
// from its configuration: the switch, the whitelist, TOP1M, the TLD wildcard lists, TLD Allow, the Regex list, SafeSearch and the DNSBL-IP
// action, and the logging the Outpost derives from them and from its groups. A list holds each entry once, lower case where the Outpost
// lowers it, and only entries the Outpost can store in one line; Core still refuses the rest, as it does not trust a backend. The last
// three fields are derived: the Outpost answers them and ignores what a client sends back. The Regex list is the lines pfB-DNS loads.
// tests/core/fixtures/settings_policy_dnsbl_parity.json is the parity fixture.
func policyDNSBLProjection() Projection {
	const (
		lowerToken = `^[^\p{C}\p{Z}A-Z#]+$` // the Outpost's text area cuts a line at #
		listToken  = `^[^\p{C}\p{Z},]+$`
	)
	logging := func(name string) Field {
		return Field{Name: name, Type: TypeEnum, Default: "disabled_log", Enum: dnsblMechanisms}
	}
	whitelist := stringList("whitelist", "domain", `^[a-z0-9_.-]{1,254}$`)
	whitelist.Check = checkWhitelistDomain
	return Projection{ID: "policy/dnsbl", Fields: []Field{
		{Name: "enabled", Type: TypeBool, Default: false},
		whitelist,
		{Name: "top1m", Type: TypeBool, Default: false},
		{Name: "top1mCount", Type: TypeInt, Default: int64(1000), Min: new(int64(1)), Max: new(int64(1000000))},
		stringList("top1mInclusions", "tld", `^[A-Za-z0-9_-]+$`),
		stringList("tldBlacklist", "tld", lowerToken),
		stringList("tldExclusions", "domain", lowerToken),
		{Name: "tldAllow", Type: TypeBool, Default: false},
		stringList("tldAllowGtld", "tld", listToken),
		stringList("tldAllowCctld", "tld", listToken),
		stringList("tldAllowItld", "tld", listToken),
		stringList("tldAllowBgtld", "tld", listToken),
		{Name: "regex", Type: TypeBool, Default: false},
		stringList("regexList", "pattern", `^[^\p{C}\p{Z}#](?:[^\p{C}]*[^\p{C}\p{Z}])?$`),
		{Name: "safeSearch", Type: TypeBool, Default: false},
		{Name: "safeSearchYoutube", Type: TypeEnum, Default: "Disable", Enum: []string{"Disable", "Moderate", "Strict"}},
		{Name: "safeSearchDoh", Type: TypeBool, Default: false},
		stringList("safeSearchDohList", "host", listToken),
		{Name: "dnsblIpAction", Type: TypeEnum, Default: "Disabled", Enum: ipActions},
		logging("logging"),
		logging("blacklistLogging"),
		{Name: "groups", Type: TypeList, Default: []any{}, Key: "name", Items: []Field{
			{Name: "name", Type: TypeString, Default: "", Pattern: word},
			logging("logging"),
			{Name: "primary", Type: TypeBool, Default: false},
			{Name: "top1mFilter", Type: TypeBool, Default: false},
		}},
	}}
}

// checkWhitelistDomain holds a whitelist entry to the shape the Outpost's domain filter accepts: a dot inside, no label empty
// or over 63 characters.
func checkWhitelistDomain(item map[string]any) []FieldError {
	d := item["domain"].(string)
	fault := !strings.Contains(d, ".") || strings.Contains(d, "..")
	for label := range strings.SplitSeq(d, ".") {
		fault = fault || len(label) > 63
	}
	if fault {
		return []FieldError{{Field: "domain", Message: "must be a domain: labels of at most 63 characters joined by dots, none empty"}}
	}
	return nil
}

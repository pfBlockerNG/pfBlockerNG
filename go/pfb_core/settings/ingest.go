package settings

import (
	"net/netip"
	"net/url"
	"strconv"
)

// ingestProjection is settings/ingest (issue #3975): what the feed phase reads of the package settings and of the platform it
// runs on, as the Outpost reads them from its configuration and the box. It is read-only: Core never changes any of it, so a
// change set that names it is refused. Where a value is a list of addresses, the Outpost lists each once and only the ones the
// lists below hold (no zone, nothing the box could not own); Core still refuses the rest, as it does not trust a backend.
// tests/core/fixtures/settings_ingest_parity.json is the parity fixture.
func ingestProjection() Projection {
	return Projection{ID: "ingest", ReadOnly: true, Fields: []Field{
		{Name: "suppression", Type: TypeBool, Default: true},
		{Name: "suppressionCidrV4", Type: TypeInt, Default: int64(0), Min: new(int64(0)), Max: new(int64(17))}, // 0: Disabled
		{Name: "suppressionCidrV6", Type: TypeInt, Default: int64(0), Min: new(int64(0)), Max: new(int64(64))}, // 0: Disabled
		{Name: "dnsblIp", Type: TypeBool, Default: false},
		{Name: "dnsblLenient", Type: TypeBool, Default: false},
		{Name: "feedHostFilter", Type: TypeBool, Default: true},
		{Name: "feedHostAllowlist", Type: TypeList, Default: []any{}, Key: "cidr", Check: checkAllowEntry,
			Items: []Field{{Name: "cidr", Type: TypeString, Default: ""}}},
		{Name: "selfAddresses", Type: TypeList, Default: []any{}, Key: "address", Check: checkSelfAddress,
			Items: []Field{{Name: "address", Type: TypeString, Default: ""}}},
		{Name: "proxyUrl", Type: TypeString, Default: "", Check: checkProxyURL},
		{Name: "proxyUser", Type: TypeString, Default: ""},
		{Name: "proxyPassword", Type: TypeString, Default: "", Secret: true},
	}}
}

// checkAllowEntry holds an allowlist entry to an IP address or a CIDR: the forms the feed policy parses, with no zone.
func checkAllowEntry(item map[string]any) []FieldError {
	entry := item["cidr"].(string)
	if _, err := netip.ParsePrefix(entry); err == nil {
		return nil
	}
	if a, err := netip.ParseAddr(entry); err == nil && a.Zone() == "" {
		return nil
	}
	return []FieldError{{Field: "cidr", Message: "must be an IP address or a CIDR"}}
}

// checkSelfAddress holds a listed address of the box to an IP address that is none of: with a zone, unspecified, link-local, or
// an IPv4-mapped IPv6 one (which would exempt the IPv4 address under another spelling).
func checkSelfAddress(item map[string]any) []FieldError {
	a, err := netip.ParseAddr(item["address"].(string))
	switch {
	case err != nil || a.Zone() != "":
		return []FieldError{{Field: "address", Message: "must be an IP address without a zone"}}
	case a.IsUnspecified() || a.IsLinkLocalUnicast() || a.Is4In6():
		return []FieldError{{Field: "address", Message: "must be an address of the box: not unspecified, link-local or IPv4-mapped"}}
	}
	return nil
}

// checkProxyURL holds the proxy to none or to http://host:port, a port of 1 to 65535: no userinfo (the credentials are their own
// fields), path, query or control character.
func checkProxyURL(v map[string]any) []FieldError {
	proxy := v["proxyUrl"].(string)
	if proxy == "" {
		return nil
	}
	if u, err := url.Parse(proxy); err == nil && u.Scheme == "http" && u.Hostname() != "" && u.User == nil && u.Path == "" &&
		u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" {
		if port, err := strconv.Atoi(u.Port()); err == nil && port >= 1 && port <= 65535 {
			return nil
		}
	}
	return []FieldError{{Field: "proxyUrl", Message: "must be http://host:port, a port from 1 to 65535, with no credentials, path or query"}}
}

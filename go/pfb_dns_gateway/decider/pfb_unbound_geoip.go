// Go translation of the GeoIP half of get_details_reply and of init_standard's MaxMind open: the country code a reply
// row shows for an address in its answer.
package decider

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/pysem"
)

// maxmindDBPath is pfb["maxminddb"]; a variable so that tests never read the host's database.
var maxmindDBPath = "/usr/local/share/GeoIP/GeoLite2-Country.mmdb"

// openMaxmind is init_standard's open of the reader for DNS Reply GeoIP logging: only when DNS Reply Logging is on and
// the database is installed. A database that does not open is reported and the module runs without GeoIP.
func (m *pfbUnbound) openMaxmind() {
	if !m.pfb.pythonReply || !isFile(maxmindDBPath) {
		return
	}
	reader, err := maxminddb.Open(maxmindDBPath)
	if err != nil {
		logErr("[pfBlockerNG]: Failed to open MaxMind DB: " + err.Error())
		return
	}
	m.maxmind = reader
	m.pfb.pythonMaxmind = true
}

// closeMaxmind is deinit's close of the reader.
func (m *pfbUnbound) closeMaxmind() {
	if m.maxmind != nil {
		m.maxmind.Close()
		m.maxmind = nil
	}
}

// geoIPCode is the country (else the continent) of the address in the reply column: prv for a private one, l.b. for a
// loopback one, unk for anything that is not an address, is not in the database or fails to look up (a scope id the
// reader refuses is such a failure).
func (m *pfbUnbound) geoIPCode(settings *pfbSettings, rAddr string) string {
	const unknown = "unk"
	if !settings.pythonMaxmind || m.maxmind == nil {
		return unknown
	}
	switch rAddr {
	case "", "Unknown", "NXDOMAIN", "NODATA", "DNSSEC", "SOA", "NS":
		return unknown
	}
	packed, err := pysem.IPAddress(rAddr)
	if err != nil {
		return unknown
	}
	switch {
	case pysem.IsPrivate(packed):
		return "prv"
	case pysem.IsLoopback(packed):
		return "l.b."
	}
	// maxminddb's get() takes the text, and libmaxminddb refuses a scope id that is not a decimal number up to 2**32-1
	// (what an interface name is), as a ValueError: unk. pysem drops the scope from the packed address.
	if _, scope, scoped := strings.Cut(rAddr, "%"); scoped {
		if _, err := strconv.ParseUint(scope, 10, 32); err != nil {
			logErr(fmt.Sprintf("[pfBlockerNG]: MaxMind Reader failed: %s does not appear to be an IPv4 or IPv6 address.: IP: %s", pysem.Repr(rAddr), rAddr))
			return unknown
		}
	}
	addr, _ := netip.AddrFromSlice(packed)
	var record geoRecord
	if err := m.maxmind.Lookup(addr).Decode(&record); err != nil {
		logErr(fmt.Sprintf("[pfBlockerNG]: MaxMind Reader failed: %v: IP: %s", err, rAddr))
		return unknown
	}
	return record.code()
}

// geoRecord is the part of a GeoLite2 Country record the reply row reads; a nil member is a key the record lacks.
type geoRecord struct {
	Country *struct {
		IsoCode *string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Continent *struct {
		Code *string `maxminddb:"code"`
	} `maxminddb:"continent"`
}

// code is the country's ISO code; a record with a country but no code is unk, not its continent's, which answers only
// for a record with no country at all. A record that is neither (or not found: the zero record) is unk.
func (r *geoRecord) code() string {
	switch {
	case r.Country != nil && r.Country.IsoCode != nil:
		return *r.Country.IsoCode
	case r.Country == nil && r.Continent != nil && r.Continent.Code != nil:
		return *r.Continent.Code
	}
	return "unk"
}

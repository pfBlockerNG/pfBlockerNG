// Package geoip converts the MaxMind GeoLite2 Country CSVs into the country and continent lists pfBlockerNG's GeoIP
// aliases read (#4034). Nothing calls it yet (slice 9, #4038).
package geoip

import (
	"context"
	"io"
	"time"
)

// Conversion is pfblockerng_uc_countries() as the dcc verb runs it, without the pages.
type Conversion struct {
	Share  string    // the MaxMind CSVs ($pfb['geoipshare'])
	CCDir  string    // the country folder ($pfb['ccdir'])
	ISOs   string    // the GeoIP ISO list ($pfb['geoip_isos'])
	LogDir string    // where maxmind_ver goes ($pfb['logdir'])
	Locale string    // the MaxMind locale (extras.maxmindLocale)
	Now    time.Time // the continent files' "Generated" stamp
	Log    io.Writer // the Extras log
}

// Run converts the CSVs and publishes the new generation whole; false leaves the previous one in place.
func (c Conversion) Run(ctx context.Context) bool {
	return false
}

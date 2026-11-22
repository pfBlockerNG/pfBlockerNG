package update

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// Extras is stage 5 of the Update loop (docs/specs/go-updater-pipeline.md §3): extra:dcc, then extra:bl, as today's
// pfb_core_update_scheduled() runs them (pfblockerng_extra.inc), each as the scheduled Extras verb. An Extra whose data
// is missing is due though the schedule did not name it, which folds in today's on-demand fetches: MaxMind
// (pfblockerng_apply.inc:3434-3439), TOP1M (pfb_top1m_refresh_needed()) and a Blacklist category never downloaded. The
// country conversion runs only when its source changed: after a new MaxMind download (the geoip.update marker the
// download leaves) or when the country folder lacks its data.
//
// Departure from today: the ISO list MaxMind's check reads is the country folder's .geoip_isos, not geoip.txt in the
// database folder (#4038, cutover row 2).
type Extras struct {
	// RunVerb runs one Extras verb: Fetcher.RunExtras.
	RunVerb func(ctx context.Context, v feedfetch.ExtrasVerb) (int, feedfetch.ExtrasResult)
	// GeoIPShare and DBDir are $pfb['geoipshare'] and $pfb['dbdir']; CCDir is the country folder ($pfb['ccdir']).
	GeoIPShare, DBDir, CCDir string
	Settings                 feedfetch.ExtrasSettings
	Enabled                  bool                       // pfBlockerNG is on ($pfb['enable']); off, extra:bl runs nothing
	Convert                  func(context.Context) bool // the country conversion: geoip.Conversion.Run
	ASNTable                 func(context.Context)      // the ASN conversion the download runs after a new asn.csv: geoip.ASNTable.Run
	Log                      io.Writer                  // the Extras log
}

// ExtrasOutcome is what stage 5 did.
type ExtrasOutcome struct {
	// Succeeded and Attempted are the Extras ids that ran to success and those that failed or had nothing to run, in run
	// order: the feed outcomes of the Update.
	Succeeded, Attempted []string
	// GeoIPChanged: the country conversion published new country lists (worklist.Input.GeoIPChanged, GeoSets.GeoIPChanged).
	GeoIPChanged bool
	// Changed: extra:dcc changed Extras data (today's $dcc_changed, worklist.Input.ExtrasChanged).
	Changed bool
}

// Stage runs the Extras of due (schedule.ExtraPlan's ids) and those whose data is missing, extra:dcc first. A failed
// Extra is attempted, keeps its previous data and does not stop the stage.
func (x Extras) Stage(ctx context.Context, due []string) ExtrasOutcome {
	var out ExtrasOutcome
	marker := filepath.Join(x.DBDir, "geoip.update")
	for _, id := range []string{"extra:dcc", "extra:bl"} {
		if !slices.Contains(due, id) && !(id == "extra:dcc" && x.dccMissing()) && !(id == "extra:bl" && x.blMissing()) {
			continue
		}
		v := feedfetch.ExtrasVerb{Name: strings.TrimPrefix(id, "extra:"), Args: []string{"scheduled"}, GeoIPShare: x.GeoIPShare,
			DBDir: x.DBDir, Settings: x.Settings, Log: x.Log, ASNTable: x.ASNTable}
		converted := false
		if id == "extra:bl" {
			ids := x.selected()
			if !x.Enabled || len(ids) == 0 {
				out.Attempted = append(out.Attempted, id) // reported, or Core would ask again every quarter hour
				continue
			}
			v.Args = append(v.Args, strings.Join(ids, ","))
		} else {
			v.Convert = func(ctx context.Context) bool {
				if !exists(marker) && !x.countriesMissing() {
					return true
				}
				converted = x.Convert != nil && x.Convert(ctx)
				return converted
			}
		}
		code, _ := x.RunVerb(ctx, v)
		if converted {
			// After the verb's exit code read it: a conversion that failed keeps it, so the next Update converts again.
			os.Remove(marker)
			out.GeoIPChanged = true
		}
		out.Changed = out.Changed || id == "extra:dcc" && (code == 2 || code == 3)
		if code == 0 || code == 2 {
			out.Succeeded = append(out.Succeeded, id)
		} else {
			out.Attempted = append(out.Attempted, id)
		}
	}
	return out
}

// countriesMissing: the country folder lacks the ISO list or the Top Spammers list the conversion publishes.
func (x Extras) countriesMissing() bool {
	return !exists(filepath.Join(x.CCDir, ".geoip_isos")) || !exists(filepath.Join(x.CCDir, "Top_Spammers_v4.info"))
}

// dccMissing: MaxMind is configured and its data is missing, or TOP1M is on and its list or baseline is missing.
func (x Extras) dccMissing() bool {
	s := x.Settings
	maxmind := s.MaxMindAccount != "" && s.MaxMindKey != "" && (x.countriesMissing() ||
		!exists(filepath.Join(x.GeoIPShare, "GeoLite2-Country.mmdb")) ||
		!exists(filepath.Join(x.GeoIPShare, "GeoLite2-Country-Blocks-IPv4.csv")))
	top1m := s.Top1M && (!exists(filepath.Join(x.DBDir, "top-1m.csv")) || !exists(filepath.Join(x.DBDir, "top-1m.csv.zip.orig")))
	return maxmind || top1m
}

// blMissing: a selected Blacklist provider's category folder is missing or empty.
func (x Extras) blMissing() bool {
	for _, id := range x.selected() {
		if entries, err := os.ReadDir(filepath.Join(x.DBDir, id)); err != nil || len(entries) == 0 {
			return true
		}
	}
	return false
}

// selected is the ids of the selected Blacklist providers, in settings order.
func (x Extras) selected() []string {
	var ids []string
	for _, p := range x.Settings.Providers {
		if p.Selected {
			ids = append(ids, p.ID)
		}
	}
	return ids
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

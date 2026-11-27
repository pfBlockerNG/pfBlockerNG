package update

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The MaxMind locale (#3977, owner decision 2026-11-27): the country lists record the locale they were built with, and
// the next Update converts them again from the local CSVs, with no download, when the configured locale differs. The IP
// page only saves the setting.
func TestTheCountryListsAreConvertedAgainWhenTheLocaleChanged(t *testing.T) {
	for _, tc := range []struct {
		name, recorded, locale string
		noMaxMind, convertOK   bool
		wantConvert            bool
	}{
		{name: "the locale changed", recorded: "en", locale: "fr", convertOK: true, wantConvert: true},
		{name: "lists built before the locale was recorded", locale: "en", convertOK: true, wantConvert: true},
		{name: "a conversion that fails", recorded: "en", locale: "fr", wantConvert: true},
		{name: "the same locale", recorded: "fr", locale: "fr", convertOK: true},
		{name: "MaxMind not configured", recorded: "en", locale: "fr", noMaxMind: true, convertOK: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := extrasBox(t)
			x.Locale = tc.locale
			if tc.noMaxMind {
				x.Settings.MaxMindAccount, x.Settings.MaxMindKey = "", ""
			}
			if tc.recorded != "" {
				if err := os.WriteFile(filepath.Join(x.CCDir, ".geoip_locale"), []byte(tc.recorded+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			converted := false
			x.Convert = func(context.Context) bool { converted = true; return tc.convertOK }
			calls := stand(&x, nil)
			out := x.Stage(context.Background(), nil)
			if converted != tc.wantConvert {
				t.Errorf("converted = %v, want %v", converted, tc.wantConvert)
			}
			if want := tc.wantConvert && tc.convertOK; out.GeoIPChanged != want {
				t.Errorf("GeoIPChanged = %v, want %v", out.GeoIPChanged, want)
			}
			if len(*calls) != 0 {
				t.Errorf("verbs run = %v, want none: a locale change downloads nothing", *calls)
			}
		})
	}
}

// A dcc that converted in the same Update recorded the new locale: the lists are not converted twice.
func TestADownloadThatConvertedIsNotConvertedAgainForTheLocale(t *testing.T) {
	x := extrasBox(t)
	x.Locale = "fr"
	touchFile(t, filepath.Join(x.DBDir, "geoip.update"))
	n := 0
	x.Convert = func(context.Context) bool {
		n++
		return os.WriteFile(filepath.Join(x.CCDir, ".geoip_locale"), []byte("fr\n"), 0o644) == nil
	}
	stand(&x, nil)
	x.Stage(context.Background(), []string{"extra:dcc"})
	if n != 1 {
		t.Errorf("converted %d times, want once", n)
	}
}

// The loop gives stage 5 the locale the snapshot configures.
func TestTheLoopGivesTheExtrasTheConfiguredLocale(t *testing.T) {
	fx := newLoopFixture(t)
	fx.settings["extras"] = map[string]any{"maxmindLocale": "pt-BR"}
	fx.reply(t)
	u := fx.updater(t, manual())
	if err := u.snapshot(); err != nil {
		t.Fatal(err)
	}
	if err := u.workList(); err != nil {
		t.Fatal(err)
	}
	if u.extras.Locale != "pt-BR" {
		t.Errorf("Extras.Locale = %q, want the configured pt-BR", u.extras.Locale)
	}
}

package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
)

// feedFlags is what the feed phase reads from the command line, as Core is told every path by a flag.
type feedFlags struct {
	LocalDirs    []string // --feed-local-dir, repeatable: a file:// feed may sit directly in one of these
	ScriptDirs   []string // --script-dir, repeatable, in search order
	OrigDir      string   // --feed-orig-dir: IPv4 and IPv6 feed baselines and parsed artifacts
	DNSBLOrigDir string   // --dnsbl-orig-dir: DNSBL feed baselines and parsed artifacts
	DBDir        string   // --feed-db-dir: the package database folder used by synthetic DNSBLIP feeds
	GeoIPDir     string   // --feed-geoip-dir: local GeoIP country feed sources
	ASNCSV       string   // --feed-asn-csv: IPinfo ASN ranges used by `asn` feeds
	RsyncBin     string   // --rsync-bin: the rsync program
	UserAgent    string   // --user-agent: what a feed host is told Core is
}

// addFeedFlags registers the feed phase's flags on fl and returns what a parse fills. A flag that is not valid refuses the
// parse with a usage error: a path must be absolute (it is cleaned), a user agent holds no control character (a line break
// would end the header it is sent in).
func addFeedFlags(fl *flag.FlagSet) *feedFlags {
	ff := &feedFlags{}
	absolute := func(v string) (string, error) {
		if !filepath.IsAbs(v) {
			return "", fmt.Errorf("%q is not an absolute path", v)
		}
		return filepath.Clean(v), nil
	}
	repeated := func(name, usage string, into *[]string) {
		fl.Func(name, usage, func(v string) error {
			dir, err := absolute(v)
			if err == nil {
				*into = append(*into, dir)
			}
			return err
		})
	}
	single := func(name, usage string, into *string) {
		fl.Func(name, usage, func(v string) error {
			path, err := absolute(v)
			if err == nil {
				*into = path
			}
			return err
		})
	}
	repeated("feed-local-dir", "a folder a file:// feed may sit directly in (repeatable)", &ff.LocalDirs)
	repeated("script-dir", "a folder of list scripts, searched in the order given (repeatable)", &ff.ScriptDirs)
	single("feed-orig-dir", "the IPv4 and IPv6 feed baselines", &ff.OrigDir)
	single("dnsbl-orig-dir", "the DNSBL feed baselines", &ff.DNSBLOrigDir)
	single("feed-db-dir", "the package database directory", &ff.DBDir)
	single("feed-geoip-dir", "the local GeoIP country-feed directory", &ff.GeoIPDir)
	single("feed-asn-csv", "the local IPinfo ASN ranges file", &ff.ASNCSV)
	fl.Func("rsync-bin", "the rsync program", func(v string) error {
		bin, err := absolute(v)
		if err == nil {
			ff.RsyncBin = bin
		}
		return err
	})
	fl.Func("user-agent", "the user agent feed hosts are told", func(v string) error {
		if i := strings.IndexFunc(v, unicode.IsControl); i >= 0 {
			return fmt.Errorf("holds a control character at byte %d", i)
		}
		ff.UserAgent = v
		return nil
	})
	return ff
}

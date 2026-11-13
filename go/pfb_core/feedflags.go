package main

import "flag"

// feedFlags holds what the feed phase reads from the command line (issue #3975): stub.
type feedFlags struct {
	LocalDirs  []string
	ScriptDirs []string
	RsyncBin   string
	UserAgent  string
}

// addFeedFlags registers the feed phase's flags on fl: stub.
func addFeedFlags(fl *flag.FlagSet) *feedFlags { return &feedFlags{} }

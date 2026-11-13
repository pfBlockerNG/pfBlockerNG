package feedfetch

import (
	"context"
	"time"
)

// WhoisRequest is one Domain/AS list as whoisconvert() receives it.
type WhoisRequest struct {
	List   string        // comma-separated entries: a domain (it has a dot) or an AS number; blank entries are skipped
	IPv6   bool          // the list's family (vtype _v6): AAAA lookups and IPv6 ranges, else A and IPv4
	Budget time.Duration // the whole batch; zero is 1800 s (see WhoisBudget)
}

// WhoisResult is the outcome of Whois.
type WhoisResult struct {
	Found    bool     // at least one entry resolved: the published copy holds this run's entries
	Failed   bool     // the ".fail" marker was left: an entry failed or the batch ran out of time
	Log      string   // what whoisconvert() prints to the update log
	ErrorLog []string // the lines it also appends to error.log
	Reason   string   // set when the run was abandoned; the published copy is then untouched
}

// WhoisBudget is the whoisbatchtimeout override.
func WhoisBudget(override string) time.Duration { return 0 }

// Whois resolves a Domain/AS list into the feed's published copy.
func (f *Fetcher) Whois(ctx context.Context, feed Feed, req WhoisRequest) WhoisResult {
	return WhoisResult{}
}

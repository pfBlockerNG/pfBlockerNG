package feedfetch

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Top1MWhitelistConfig is what pfblockerng_top1m() reads: the database folder holding top-1m.csv, the provider the list
// came from, the TLD inclusions and the count of domains to write.
type Top1MWhitelistConfig struct {
	DBDir      string
	Provider   string
	Inclusions []string
	Count      int
}

// Top1MWhitelistResult is what a whitelist build did: Parsed valid rows read and Found domains written, Published
// whether a new pfbalexawhitelist.txt stands, and Reason why none was published.
type Top1MWhitelistResult struct {
	Parsed, Found int
	Published     bool
	Reason        string
}

// top1mWhitelistWriter is where the build writes its staging file, a test seam for a write that fails.
var top1mWhitelistWriter = func(f *os.File) io.Writer { return f }

// Top1MWhitelist is pfblockerng_top1m(): it derives pfbalexawhitelist.txt from top-1m.csv. Each valid row whose TLD is an
// inclusion is written as its domain, lowercased and without a leading "www.", until Count domains are written. A list
// without one valid row, or a build that cannot be written or published, keeps the previous whitelist. The update
// marker top-1m.update is removed whatever the outcome, unless there are no inclusions.
func Top1MWhitelist(cfg Top1MWhitelistConfig) Top1MWhitelistResult {
	if len(cfg.Inclusions) == 0 {
		return Top1MWhitelistResult{Reason: "no TLD inclusions"}
	}
	defer os.Remove(filepath.Join(cfg.DBDir, "top-1m.update"))
	include := map[string]bool{}
	for _, tld := range cfg.Inclusions {
		include[tld] = true
	}
	p := top1mProviderOf(cfg.Provider)

	src, err := os.Open(filepath.Join(cfg.DBDir, "top-1m.csv"))
	if err != nil {
		return Top1MWhitelistResult{Reason: "top-1m.csv not found"}
	}
	defer src.Close()
	whitelist := filepath.Join(cfg.DBDir, "pfbalexawhitelist.txt")
	tmp, err := os.CreateTemp(cfg.DBDir, ".pfbtop1m_")
	if err != nil {
		return Top1MWhitelistResult{Reason: "could not create the staging file"}
	}
	defer os.Remove(tmp.Name()) // gone already once published
	out := bufio.NewWriter(top1mWhitelistWriter(tmp))

	var res Top1MWhitelistResult
	var werr error
	rd := bufio.NewReader(src)
	header := p.header
	for res.Found < cfg.Count && werr == nil {
		line, err := rd.ReadString('\n')
		if line != "" {
			if header {
				header = false
			} else if domain, ok := top1mRow(line, p); ok {
				res.Parsed++
				if include[domain[strings.LastIndexByte(domain, '.')+1:]] {
					res.Found++
					_, werr = out.WriteString(strings.TrimPrefix(domain, "www.") + "\n")
				}
			}
		}
		if err != nil {
			break
		}
	}
	if werr == nil {
		werr = out.Flush()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	switch {
	case werr != nil:
		res.Reason = "could not write the new whitelist"
	case res.Parsed == 0:
		res.Reason = "top-1m.csv holds no valid row"
	case rename(tmp.Name(), whitelist) != nil:
		res.Reason = "could not publish the new whitelist"
	default:
		res.Published = true
	}
	return res
}

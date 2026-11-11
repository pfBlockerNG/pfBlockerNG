package decider

import "testing"

// issue #3805: with python_hsts on, a VIP block of a name under a built-in HSTS TLD is a null block whatever
// pfb_py_hsts.txt holds, because the browser refuses the block page's certificate there; the preload file only adds its
// own names. With python_hsts off, and for a name outside the HSTS TLDs, the block keeps the VIP.
func TestBuiltInHstsTldNullBlocksWhateverThePreloadFileHolds(t *testing.T) {
	file := func(content string) *string { return &content }
	for _, tc := range []struct {
		name       string
		pythonHsts bool
		preload    *string // nil: no pfb_py_hsts.txt
		query, tld string
		wantNull   bool
		wantPType  string
	}{
		{"python_hsts off", false, file("bank.example\n"), "blocked.dev", "dev", false, "Python"},
		{"no file", true, nil, "blocked.dev", "dev", true, "HSTS_TLD"},
		{"zero-byte file", true, file(""), "blocked.dev", "dev", true, "HSTS_TLD"},
		{"comment-only file", true, file("# header\n\n"), "blocked.dev", "dev", true, "HSTS_TLD"},
		{"unrelated file", true, file("bank.example\n"), "blocked.dev", "dev", true, "HSTS_TLD"},
		{"no file, a name outside the HSTS TLDs", true, nil, "blocked.example", "example", false, "Python"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := opHstsModule(t, tc.pythonHsts, tc.preload)
			m.pfb.pythonBlocking = true
			snap := evSnapshot(&m.pfb)
			snap.dataDB[tc.query] = evBlk("1", 0, PRIO_FEED_BLOCK)
			m.loadHstsDb(snap.hstsDB)

			got := evaluateDomain(tc.query, tc.query, tc.tld, false, m.evaluateCfg(snap), snap.containers())

			if !got.isFound || got.logType != "1" {
				t.Fatalf("(isFound, logType) = (%v, %q), want the VIP-flagged block (true, \"1\")", got.isFound, got.logType)
			}
			if got.nullBlocking != tc.wantNull || got.inHsts != tc.wantNull || got.pType != tc.wantPType {
				t.Errorf("(nullBlocking, inHsts, pType) = (%v, %v, %q), want (%v, %v, %q)",
					got.nullBlocking, got.inHsts, got.pType, tc.wantNull, tc.wantNull, tc.wantPType)
			}
		})
	}
}

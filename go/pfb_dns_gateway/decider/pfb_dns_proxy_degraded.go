// issue #3848: what the decider serves without. DNS never goes down with a part of the decider, so each loss is kept, with the
// message the decider logged for it, for the gateway's control-socket status to list (the part names are that status's).
package decider

import (
	"cmp"
	"sync/atomic"
)

// DegradedPart is one part of the decider's work that it serves without, and why.
type DegradedPart struct{ Part, Reason string }

const (
	partDNSBL         = "dnsbl"          // no DNSBL build: nothing is blocked
	partDNSBLSettings = "dnsbl_settings" // pfb_unbound.ini could not be parsed
	partStatistics    = "statistics"     // a stats database could not be opened
	partObserver      = "observer"       // the upstream observer's socket could not be bound
)

// lossReason is why one part of the module does not work: empty while it does. The databases open again after init, so it is atomic.
type lossReason struct{ why atomic.Pointer[string] }

func (f *lossReason) set(reason string) { f.why.Store(&reason) }
func (f *lossReason) clear()            { f.why.Store(nil) }

func (f *lossReason) reason() string {
	if why := f.why.Load(); why != nil {
		return *why
	}
	return ""
}

// Degraded lists what the decider serves without now, in the order dnsbl, dnsbl_settings, statistics, observer. dnsbl is while
// the live snapshot has no DNSBL build; a reload that fails after a good build leaves the last good snapshot, so it is not
// reported. Safe for any goroutine, also after Close.
func (f *Frontend) Degraded() []DegradedPart {
	var parts []DegradedPart
	if m := f.module; m != nil {
		if snap := m.snapshot.Load(); snap != nil && snap.dnsblUnbuilt != "" {
			parts = append(parts, DegradedPart{partDNSBL, snap.dnsblUnbuilt})
		}
		if why := m.iniFailure.reason(); why != "" {
			parts = append(parts, DegradedPart{partDNSBLSettings, why})
		}
		if why := cmp.Or(m.resolverDbFailure.reason(), m.dnsblDbFailure.reason()); why != "" {
			parts = append(parts, DegradedPart{partStatistics, why})
		}
	}
	if f.observerLost != "" {
		parts = append(parts, DegradedPart{partObserver, f.observerLost})
	}
	return parts
}

// logUpstreamBlock called on its own, as Python's tests call _log_upstream_block: it normalises the transport and the
// listener it is given, whatever its caller already did, and counts under the metric type, not the row's.
package decider

import (
	"reflect"
	"testing"
)

func TestLogUpstreamBlockNormalisesWhatItIsGiven(t *testing.T) {
	r := newObserverRig(t, "forwarding = true\n")
	drain, epoch := counterEvents(t, r)
	r.m.logUpstreamBlock("n.example", "Unknown", upstreamBlock{"NXRA", "NXRA", ""}, "Unknown", "bogus", "TYPE9", epoch, "::ffff:192.0.2.53", "L\x01N")
	wantRow := "DNSBL-python," + observerStamp + ",n.example,127.0.0.1,Python,Upstream_Block,Upstream,NXRA,External,+,Unknown,Unknown,192.0.2.53,"
	if !reflect.DeepEqual(r.rows, []string{wantRow}) {
		t.Errorf("rows = %q, want %q: the row has the type name, the transport Unknown and the listener cleaned", r.rows, wantRow)
	}
	wantEvent := dbEvent{dnsbl: true, group: "Upstream", owner: "Upstream", origin: "builtin", epoch: epoch, qtype: "TYPE9", listenerIP: "192.0.2.53"}
	if got := drain(); !reflect.DeepEqual(got, []dbEvent{wantEvent}) {
		t.Errorf("enqueued %+v, want %+v: the counter has the metric type and no transport", got, []dbEvent{wantEvent})
	}
}

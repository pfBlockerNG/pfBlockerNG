// Go translation of the upstream-block half of pfb_unbound.py (issue #267): classify_upstream_block, _parse_ede_options,
// inplace_cb_query_response and _log_upstream_block with its Upstream counter, and the shim's fire_query_response that
// calls the callback. _upstream_edns_opts and _client_ip_from_qstate are a field read and isUnknown here: a typed qstate
// has no failure for them to swallow. The callback only observes and logs: it returns no answer and changes none.
package decider

import (
	"encoding/binary"
	"fmt"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/dnswire"
)

const (
	edeBlocked  = 15 // RFC 8914 INFO-CODE 15: Blocked
	edeFiltered = 17 // RFC 8914 INFO-CODE 17: Filtered
	// ednsOptCodeEDE is the EDNS option that carries an Extended DNS Error, distinct from the INFO-codes above.
	ednsOptCodeEDE = 15
)

// ednsOpt is one entry of the upstream's EDNS options (qstate.edns_opts_back_in_iter).
type ednsOpt struct {
	code uint16
	data []byte
}

// edeEntry is a parsed RFC 8914 option: its INFO-CODE and its EXTRA-TEXT.
type edeEntry struct {
	infoCode  uint16
	extraText string
}

// upstreamBlock is a forwarded reply classified as an upstream block: its signal, the label the row's b_eval takes, and the
// provider text of its EDE, empty when it carried none.
type upstreamBlock struct{ signal, label, provider string }

// classifyUpstreamBlock decides whether a forwarded reply is an upstream block. The first EDE 15 (Blocked) wins, then the
// first EDE 17 (Filtered), each carrying its text as the provider; else NXRA: NXDOMAIN with RA clear and AA clear. A
// natural NXDOMAIN (RA), an authoritative one (AA) and any other reply without a recognised EDE are no block, nil.
func classifyUpstreamBlock(rcode int, raAvailable, aaAuthoritative bool, ede []edeEntry) *upstreamBlock {
	var ede15, ede17 *string
	for i := range ede {
		switch {
		case ede[i].infoCode == edeBlocked && ede15 == nil:
			ede15 = &ede[i].extraText
		case ede[i].infoCode == edeFiltered && ede17 == nil:
			ede17 = &ede[i].extraText
		}
	}
	switch {
	case ede15 != nil:
		return &upstreamBlock{"EDE15", "EDE15 (Blocked)", pyStrip(*ede15)}
	case ede17 != nil:
		return &upstreamBlock{"EDE17", "EDE17 (Filtered)", pyStrip(*ede17)}
	case rcode == RCODE_NXDOMAIN && !raAvailable && !aaAuthoritative:
		return &upstreamBlock{"NXRA", "NXRA", ""}
	}
	return nil
}

// parseEdeOptions keeps the EDNS options that are an EDE with an INFO-CODE: code 15 and at least two data bytes. The
// INFO-CODE is the first two bytes, big-endian, and the EXTRA-TEXT the rest, UTF-8 with replacement characters.
func parseEdeOptions(opts []ednsOpt) []edeEntry {
	var result []edeEntry
	for _, opt := range opts {
		if opt.code == ednsOptCodeEDE && len(opt.data) >= 2 {
			result = append(result, edeEntry{binary.BigEndian.Uint16(opt.data), decodeReplace(opt.data[2:])})
		}
	}
	return result
}

// inplaceCbQueryResponse classifies the RAW upstream response of one forwarded query (its RA and AA bits and its EDE
// survive here, unlike in the reply callbacks) and logs and counts a block. Only while forwarding; the gate is read from
// the live snapshot, which is also where the Upstream counter's epoch comes from. Any panic is printed as Python prints
// its exception, and the callback returns True whatever happens.
func (m *pfbUnbound) inplaceCbQueryResponse(qstate *moduleQstate, response *dnsMsg) (observed bool) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Fprintf(logOutput, "[pfBlockerNG] inplace_cb_query_response: %v\n", err)
		}
		observed = true
	}()
	snap := m.snapshot.Load()
	if !snap.settings.forwarding || response == nil || response.rep == nil {
		return true
	}
	flags := response.rep.flags
	// The wire header's RA and AA bits and the rcode in its low four bits, not the runtime's PKT_RA.
	result := classifyUpstreamBlock(int(flags&0x000F), flags&dnswire.RA != 0, flags&dnswire.AA != 0, parseEdeOptions(qstate.ednsOptsBackInIter))
	if result == nil {
		return true
	}
	qType := getQType(qstate, nil)
	listenerIP, listenerInterface := getQListener(qstate, nil)
	m.logUpstreamBlock(
		getQNameQstate(qstate), isUnknown(qstate.clientIP), *result, qType, getQTransport(qstate, nil), metricQtype(qstate, nil, qType),
		snap.groupEpochs[[2]string{"Upstream", "builtin"}], listenerIP, listenerInterface,
	)
	return true
}

// fireQueryResponse is the shim's fire_query_response: it calls the module's query_response callback with the qstate and the
// raw upstream response and no keyword arguments, so the row's transport and listener are the qstate's. A callback that fails
// is logged and swallowed, as pythonmod does.
func (m *pfbUnbound) fireQueryResponse(qstate *moduleQstate, response *dnsMsg) {
	defer func() {
		if err := recover(); err != nil {
			logErr(fmt.Sprintf("inplace callback query_response failed: %v", err))
		}
	}()
	m.inplaceCbQueryResponse(qstate, response)
}

// logUpstreamBlock logs an upstream block in a DNSBL block's shape, b_type Upstream_Block, b_eval the classifier's label and
// feed the provider or External. No python_nolog or log-type gate and no duplicate check: the duplicate column is always +.
// The row is always written; the group counter is enqueued only with the DNSBL connection up and an Upstream epoch, and
// counts the client as it came (Unknown stays Unknown), where the row says 127.0.0.1.
func (m *pfbUnbound) logUpstreamBlock(qName, qIP string, result upstreamBlock, qType, transport, mQtype, groupEpoch, listenerIP, listenerInterface string) {
	listenerIP, listenerInterface = getQListener(nil, &logKwargs{listenerIP: listenerIP, listenerInterface: listenerInterface})
	logIP := qIP
	if logIP == "Unknown" {
		logIP = "127.0.0.1"
	}
	transport = getQTransport(nil, &logKwargs{transport: transport})
	provider := logText(result.provider)
	if provider == "" {
		provider = "External"
	}
	m.pfbLog(dnsblLogName, csvRow([]string{
		"DNSBL-python", m.makeTimestamp(), logText(qName), logIP, "Python", "Upstream_Block", "Upstream", logText(result.label), provider,
		"+", qType, transport, listenerIP, listenerInterface,
	}))
	if m.sqlite3DnsblCon.Load() && groupEpoch != "" {
		client, clientEpoch := m.metricClient(dbDnsbl, qIP)
		m.dbEnqueue(dbEvent{
			dnsbl: true, group: "Upstream", owner: "Upstream", origin: "builtin", epoch: groupEpoch,
			qtype: mQtype, transport: metricTransport(transport), listenerIP: listenerIP, listenerInterface: listenerInterface,
			client: client, clientEpoch: clientEpoch,
		})
	}
}

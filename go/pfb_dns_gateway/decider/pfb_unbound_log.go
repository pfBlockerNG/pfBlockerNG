// Go translation of the log-row half of pfb_unbound.py: get_details_dnsbl, _log_idn_alert and get_details_reply with the
// helpers their rows are built from (_log_text, _csv_row, make_timestamp, get_q_*, convert_ipv4/ipv6) and the reply
// callbacks. The rows go out through pfbLog (pfb_unbound_logfile.go), and the counters the same functions enqueue go to
// the stats databases (pfb_unbound_sqlite.go). _log_upstream_block is in pfb_unbound_upstream.go.
package decider

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/pysem"
)

const (
	dnsblLogName    = "dnsbl.log"
	dnsReplyLogName = "dns_reply.log"
)

// logKwargs is the kwargs dict the row writers read: pfb_addr from operate(), repinfo (the client's address) and the
// listener from a reply callback, pfb_transport and the listener from a caller that has no qstate. nil is Python's None.
type logKwargs struct {
	pfbAddr           *string
	repinfo           *string
	transport         string
	listenerIP        string
	listenerInterface string
}

var errIndexOutOfRange = errors.New("index out of range")

// now is the module's clock: the local time, unless a test fixed it.
func (m *pfbUnbound) now() time.Time {
	if m.clock != nil {
		return m.clock()
	}
	return time.Now()
}

func (m *pfbUnbound) makeTimestamp() string {
	return m.now().Format("2006-01-02 15:04:05")
}

// snapshotOf is the snapshot a query decides on, else the live one (a callback whose query never reached operate()).
func (m *pfbUnbound) snapshotOf(qstate *moduleQstate) *snapshot {
	if qstate != nil && qstate.snap != nil {
		return qstate.snap
	}
	return m.snapshot.Load()
}

// logTextEscaped reports whether _LOG_TEXT_ESCAPE rewrites r: C0 controls but CR and LF (left to csvRow), the HTML
// metacharacters, backslash, DEL, C1 controls, and the separators and bidi controls pfb_hsc() strips.
func logTextEscaped(r rune) bool {
	switch {
	case r == '\n' || r == '\r':
		return false
	case r < 0x20, r == '"', r == '&', r == '\'', r == '<', r == '>', r == '\\', r == 0x7f:
		return true
	case 0x80 <= r && r < 0xa0:
		return true
	}
	switch r {
	case 0x061c, 0x200b, 0x200e, 0x200f, 0x2028, 0x2029:
		return true
	}
	return 0x202a <= r && r <= 0x202e || 0x2066 <= r && r <= 0x2069
}

// logText escapes one attacker-controlled field before it is written (_log_text): a code point up to U+00FF becomes one
// \DDD of its value, anything above the \DDD of each UTF-8 octet. Apply it to what comes off the wire or from third
// parties, never to admin-set names like feed or group.
func logText(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); {
		r, size := utf8.DecodeRuneInString(v[i:])
		switch {
		case !logTextEscaped(r):
			b.WriteString(v[i : i+size])
		case r < 0x100:
			fmt.Fprintf(&b, "\\%03d", r)
		default:
			for j := i; j < i+size; j++ {
				fmt.Fprintf(&b, "\\%03d", v[j])
			}
		}
		i += size
	}
	return b.String()
}

var crlfToSpace = strings.NewReplacer("\r\n", " ", "\r", " ", "\n", " ")

// csvRow is _csv_row: one RFC 4180 line without its newline, as the csv module's "excel" dialect writes it (QUOTE_MINIMAL,
// quotes doubled, no escape character), CR and LF folded to a space first so a row is always one physical line. A field
// is quoted only when it holds a comma or a quote, and a row of one empty field is `""`; encoding/csv differs on both
// (it quotes a leading space and `\.`), so the writer is the dialect's own.
func csvRow(fields []string) string {
	var b strings.Builder
	for i, field := range fields {
		if i > 0 {
			b.WriteByte(',')
		}
		field = crlfToSpace.Replace(field)
		switch {
		case field == "" && len(fields) == 1:
			b.WriteString(`""`)
		case strings.ContainsAny(field, `,"`):
			b.WriteByte('"')
			b.WriteString(strings.ReplaceAll(field, `"`, `""`))
			b.WriteByte('"')
		default:
			b.WriteString(field)
		}
	}
	return b.String()
}

// getQTransport is the original listener transport, never inferred from upstream sockets or client ports: a qstate
// carries it, a caller without one passes it in kwargs.
func getQTransport(qstate *moduleQstate, kwargs *logKwargs) string {
	value := ""
	switch {
	case qstate != nil:
		value = qstate.pfbTransport
	case kwargs != nil:
		value = kwargs.transport
	}
	switch value {
	case "TCP", "UDP", "DoT", "DoH", "DoQ":
		return value
	}
	return "Unknown"
}

// metricIp is _metric_ip: the address as the ipaddress module prints it, an IPv4-mapped one as its IPv4 address, or "" for
// anything that is not an address, carries a %scope or is unspecified.
func metricIp(value string) string {
	if value == "" || strings.Contains(value, "%") {
		return ""
	}
	packed, err := pysem.IPAddress(value)
	if err != nil {
		return ""
	}
	if mapped := pysem.IPv4Mapped(packed); mapped != nil {
		packed = mapped
	}
	if pysem.IsUnspecified(packed) {
		return ""
	}
	return pysem.Compressed(packed)
}

// getQListener is the listener address and interface label of the query; a label with a control, format, surrogate or
// line-separator character is dropped.
// shortcut: the categories are Go's Unicode tables (17), Python 3.11's are Unicode 14: a code point assigned between the two
// as a format character is dropped here and kept there. Port the 14 tables if an interface label can be one.
func getQListener(qstate *moduleQstate, kwargs *logKwargs) (string, string) {
	ip, label := "", ""
	switch {
	case qstate != nil:
		ip, label = qstate.pfbListenerIP, qstate.pfbListenerInterface
	case kwargs != nil:
		ip, label = kwargs.listenerIP, kwargs.listenerInterface
	}
	listenerIP := metricIp(ip)
	if listenerIP == "" {
		return "", ""
	}
	if !utf8.ValidString(label) || strings.IndexFunc(label, func(r rune) bool {
		return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Cs, unicode.Zl, unicode.Zp)
	}) >= 0 {
		return listenerIP, ""
	}
	return listenerIP, label
}

func getQNameQinfo(qinfo *queryInfo) string {
	qName := ""
	if qinfo != nil && pyStrip(qinfo.qnameStr) != "" {
		qName = strings.TrimRight(qinfo.qnameStr, ".")
	}
	return isUnknown(qName)
}

// getQIpComm is the client address of a callback: the pfb_addr operate() passes, else the repinfo's.
func getQIpComm(kwargs *logKwargs) string {
	qIP := ""
	switch {
	case kwargs == nil:
	case kwargs.pfbAddr != nil:
		qIP = *kwargs.pfbAddr
	case kwargs.repinfo != nil:
		qIP = *kwargs.repinfo
	}
	return isUnknown(qIP)
}

func getQType(qstate *moduleQstate, qinfo *queryInfo) string {
	qType := ""
	switch {
	case qstate != nil && qstate.qinfo.qtypeStr() != "":
		qType = qstate.qinfo.qtypeStr()
	case qinfo != nil && qinfo.qtypeStr() != "":
		qType = qinfo.qtypeStr()
	}
	return isUnknown(qType)
}

// getOType is the type of the first rrset of the message being returned, else the query's type.
func getOType(qstate *moduleQstate, rep *replyInfo) string {
	oType := ""
	if qstate != nil {
		switch {
		case qstate.returnMsg != nil && qstate.returnMsg.rep != nil && len(qstate.returnMsg.rep.rrsets) > 0 && qstate.returnMsg.rep.rrsets[0] != nil:
			oType = qstate.returnMsg.rep.rrsets[0].rk.typeStr
		case qstate.qinfo.qtypeStr() != "":
			oType = qstate.qinfo.qtypeStr()
		case rep != nil && len(rep.rrsets) > 0 && rep.rrsets[0] != nil:
			oType = rep.rrsets[0].rk.typeStr
		}
	}
	return isUnknown(oType)
}

// getRepTtl: a TTL of 0 is a value (RFC 2181 s8), only a missing reply is "Unk" (#723).
func getRepTtl(rep *replyInfo) string {
	if rep == nil {
		return "Unk"
	}
	return strconv.FormatUint(uint64(rep.ttl), 10)
}

// convertIpv4 is the dotted address of an rr_data payload (a 2-byte length, then the 4 octets); a payload too short for it
// is the IndexError Python raises.
func convertIpv4(x []byte) (string, error) {
	ipv4 := ""
	if len(x) > 0 {
		if len(x) < 6 {
			return "", errIndexOutOfRange
		}
		ipv4 = fmt.Sprintf("%d.%d.%d.%d", x[2], x[3], x[4], x[5])
	}
	return isUnknown(ipv4), nil
}

func convertIpv6(x []byte) (string, error) {
	ipv6 := ""
	if len(x) > 0 {
		if len(x) < 18 {
			return "", errIndexOutOfRange
		}
		var b strings.Builder
		for i := 2; i < 18; i += 2 {
			if i > 2 {
				b.WriteByte(':')
			}
			fmt.Fprintf(&b, "%02x%02x", x[i], x[i+1])
		}
		ipv6 = b.String()
	}
	return isUnknown(ipv6), nil
}

// dnsblEvent is what get_details_dnsbl compares to the previous block to mark a duplicate: Python compares
// str((name, qtype, decision, transport, client, listener, interface)), the decision's dataclass repr showing every field.
type dnsblEvent struct {
	qName, qType, transport, qIP, listenerIP, listenerInterface string

	isFound, inWhitelist, inHsts, nullBlocking, nxdomain bool
	logType, bType, pType, feed, group, bEval            string
	idnAlert                                             idnAlert
	hasIdnAlert                                          bool
	groupOwner, groupOrigin                              string
}

// seen records the event as the last one and reports whether it equals the previous.
func (m *pfbUnbound) seen(event dnsblEvent) bool {
	m.dnsblLastMu.Lock()
	defer m.dnsblLastMu.Unlock()
	duplicate := m.dnsblLast != nil && *m.dnsblLast == event
	m.dnsblLast = &event
	return duplicate
}

// getDetailsDnsbl logs the block `dnsbl` that operate() served for the query, unless the block is silent (python_nolog
// for a VIP block, log type 2, 4 or 6). A nil dnsbl is UNSET, a defensive no-op. groupEpoch is the group's counter
// authority from the query's snapshot: the group counter is enqueued, silent or not, only under it.
func (m *pfbUnbound) getDetailsDnsbl(mType string, qinfo *queryInfo, qstate *moduleQstate, kwargs *logKwargs, dnsbl *dnsblDecision, groupEpoch string) bool {
	var qName string
	switch {
	case qstate != nil:
		qName = getQNameQstate(qstate)
	case qinfo != nil:
		qName = getQNameQinfo(qinfo)
	default:
		return true
	}

	qType := getQType(qstate, qinfo)
	transport := getQTransport(qstate, kwargs)
	listenerIP, listenerInterface := getQListener(qstate, kwargs)
	qIP := getQIpComm(kwargs)

	// Increment the totalqueries counter.
	if m.sqlite3ResolverCon.Load() {
		client, clientEpoch := m.metricClient(dbResolver, qIP)
		m.dbEnqueue(dbEvent{
			qtype: metricQtype(qstate, qinfo, qType), transport: metricTransport(transport), listenerIP: listenerIP, listenerInterface: listenerInterface,
			client: client, clientEpoch: clientEpoch,
		})
	}

	// The served verdict rides in by value from operate(): never re-read the shared decisionDB memo (issue #1094).
	if dnsbl == nil || !dnsbl.isFound || dnsbl.inWhitelist {
		return true
	}
	// If logging is disabled, do not log blocked DNSBL events (Utilize DNSBL Webserver) except for Python nullblock events.
	if m.snapshotOf(qstate).settings.pythonNolog && !dnsbl.nullBlocking {
		return true
	}

	// Increment the dnsblgroup counter.
	if m.sqlite3DnsblCon.Load() && dnsbl.group != "" && groupEpoch != "" {
		client, clientEpoch := m.metricClient(dbDnsbl, qIP)
		m.dbEnqueue(dbEvent{
			dnsbl: true, group: dnsbl.group, owner: dnsbl.groupOwner, origin: dnsbl.groupOrigin, epoch: groupEpoch,
			qtype: metricQtype(qstate, qinfo, qType), transport: metricTransport(transport), listenerIP: listenerIP, listenerInterface: listenerInterface,
			client: client, clientEpoch: clientEpoch,
		})
	}

	// The decision is name- and qtype-independent for some block kinds, so the name and q_type are part of the event.
	event := dnsblEvent{
		qName: pysem.Lower(qName), qType: qType, transport: transport, qIP: qIP, listenerIP: listenerIP, listenerInterface: listenerInterface,
		isFound: dnsbl.isFound, inWhitelist: dnsbl.inWhitelist, inHsts: dnsbl.inHsts, nullBlocking: dnsbl.nullBlocking,
		nxdomain: dnsbl.nxdomain, logType: dnsbl.logType, bType: dnsbl.bType, pType: dnsbl.pType, feed: dnsbl.feed,
		group: dnsbl.group, bEval: dnsbl.bEval, groupOwner: dnsbl.groupOwner, groupOrigin: dnsbl.groupOrigin,
	}
	if dnsbl.idnAlert != nil {
		event.idnAlert, event.hasIdnAlert = *dnsbl.idnAlert, true
	}
	dupEntry := "+"
	if m.seen(event) {
		dupEntry = "-"
	}
	// Silent modes still increment the per-group counter above.
	if dnsbl.logType == "2" || dnsbl.logType == "4" || dnsbl.logType == "6" {
		return true
	}

	if qIP == "Unknown" {
		qIP = "127.0.0.1"
	}

	m.pfbLog(dnsblLogName, csvRow([]string{
		"DNSBL-python", m.makeTimestamp(), logText(qName), qIP, dnsbl.pType, dnsbl.bType, dnsbl.group, logText(dnsbl.bEval),
		dnsbl.feed, dupEntry, qType, transport, listenerIP, listenerInterface,
	}))
	return true
}

// logIdnAlert logs an ADR-08 Confusable-mode ALERT (the name still resolves) in a block's shape, b_type Homoglyph_Alert
// and b_eval the dual form. No python_nolog or log-type gate, and no duplicate check.
func (m *pfbUnbound) logIdnAlert(qName, qIP string, alert idnAlert, qType, transport, listenerIP, listenerInterface string) {
	listenerIP, listenerInterface = getQListener(nil, &logKwargs{listenerIP: listenerIP, listenerInterface: listenerInterface})
	if qIP == "Unknown" {
		qIP = "127.0.0.1"
	}
	m.pfbLog(dnsblLogName, csvRow([]string{
		"DNSBL-python", m.makeTimestamp(), logText(qName), qIP, "Python", "Homoglyph_Alert", alert.group, logText(alert.bEval),
		alert.feed, "+", qType, getQTransport(nil, &logKwargs{transport: transport}), listenerIP, listenerInterface,
	}))
}

// getDetailsReply logs the reply the client is about to get as a dns_reply.log row. mType is reply (the module's own
// MODDONE), or the callback that fired: reply-x (only python_control names and noAAAA AAAA queries pass), cache, local,
// servfail. The error is the IndexError Python raises on a record too short for its type.
func (m *pfbUnbound) getDetailsReply(mType string, qinfo *queryInfo, qstate *moduleQstate, rep *replyInfo, kwargs *logKwargs) error {
	var qName string
	switch {
	case qstate != nil:
		qName = getQNameQstate(qstate)
	case qinfo != nil:
		qName = getQNameQinfo(qinfo)
	default:
		return nil
	}

	qIP := getQIpComm(kwargs)
	if qIP == "Unknown" || qIP == "127.0.0.1" {
		qIP = "127.0.0.1"
		mType = "resolver"
	}

	oType := getQType(qstate, qinfo)
	transport := getQTransport(qstate, kwargs)
	listenerIP, listenerInterface := getQListener(qstate, kwargs)
	qType := oType
	if mType != "cache" && oType != "PTR" {
		qType = getOType(qstate, rep)
	}

	snap := m.snapshotOf(qstate)
	// Collect 'python_control' and 'noAAAA' events from inplace_cb_reply.
	if mType == "reply-x" {
		isReply := strings.HasPrefix(qName, "python_control.") || qType == "AAAA" && evaluateNoaaaa(qName, snap.noAAAADB)
		if !isReply {
			return nil
		}
		mType = "reply"
	}

	// Increment the totalqueries counter (the Resolver's own DNS requests are not included).
	if m.sqlite3ResolverCon.Load() && qIP != "127.0.0.1" {
		client, clientEpoch := m.metricClient(dbResolver, qIP)
		m.dbEnqueue(dbEvent{
			qtype: metricQtype(qstate, qinfo, oType), transport: metricTransport(transport), listenerIP: listenerIP, listenerInterface: listenerInterface,
			client: client, clientEpoch: clientEpoch,
		})
	}

	// Do not log Replies, if disabled.
	if !snap.settings.pythonReply {
		return nil
	}

	rAddr, err := replyAddress(rep)
	if err != nil {
		return err
	}

	// Collect RCODE for non-NOError codes.
	if qstate != nil && qstate.returnRcode != 0 {
		if name, ok := m.rcodeDB[qstate.returnRcode]; ok {
			rAddr = name
		}
	}

	rAddr = isUnknown(rAddr)
	if qType == "SOA" && rAddr == "NXDOMAIN" {
		rAddr = "SOA"
	}
	if qType == "NSEC3" && rAddr == "NXDOMAIN" {
		rAddr = "NSEC3"
	}
	if qType == "NS" && qName == "Unknown" {
		qName = "NS"
	}
	// Determine if domain was noAAAA blocked.
	if rAddr == "NXDOMAIN" && qType == "AAAA" && evaluateNoaaaa(qName, snap.noAAAADB) {
		rAddr = "noAAAA"
	}

	ttl := getRepTtl(rep)
	// Cached TTLs are in unix timestamp (time remaining).
	if mType == "cache" {
		ttl = cacheTtl(ttl, m.now().Unix())
	}

	m.pfbLog(dnsReplyLogName, csvRow([]string{
		"DNS-reply", m.makeTimestamp(), mType, oType, qType, ttl, logText(qName), qIP, logText(rAddr), m.geoIPCode(snap.settings, rAddr),
		transport, listenerIP, listenerInterface,
	}))
	return nil
}

// cacheTtl turns the unix expiry a cached reply carries into the seconds left; a TTL that is not a ten-digit timestamp is "".
func cacheTtl(ttl string, now int64) string {
	if len(ttl) != 10 || !pysem.IsASCIIDigits(ttl) {
		return ""
	}
	expiry, err := strconv.ParseInt(ttl, 10, 64)
	if err != nil {
		return ""
	}
	return strconv.FormatInt(expiry-now, 10)
}

// replyAddress is the reply column before the RCODE and the noAAAA/SOA rewrites: the answer records walked in order. A
// and AAAA give an address (the first record's) and the next rrset overwrites it; DNSKEY and DS give DNSSEC; every other
// type is its records' names, "|"-joined onto what is there. No answer section is NXDOMAIN.
func replyAddress(rep *replyInfo) (string, error) {
	rAddr := ""
	if rep == nil {
		return rAddr, nil
	}
	if rep.anNumrrsets <= 0 {
		return "NXDOMAIN", nil
	}
	for i := range rep.anNumrrsets {
		if i >= len(rep.rrsets) {
			return "", errIndexOutOfRange
		}
		set := rep.rrsets[i]
		if set.entry.data == nil || set.rk.typeStr == "" {
			continue
		}
		data := set.entry.data
		if set.rk.typeStr == "CNAME" && data.count > 1 {
			continue
		}
		for j := range data.count {
			if j >= len(data.rrData) {
				return "", errIndexOutOfRange
			}
			x := data.rrData[j]
			switch set.rk.typeStr {
			case "A":
				address, err := convertIpv4(x)
				if err != nil {
					return "", err
				}
				rAddr = address
			case "AAAA":
				address, err := convertIpv6(x)
				if err != nil {
					return "", err
				}
				rAddr = address
				if packed, err := pysem.IPAddress(address); err != nil {
					pyStderr(fmt.Sprintf("[pfBlockerNG]: Failed to compress IPv6: %s, %s", address, err))
				} else {
					rAddr = pysem.Compressed(packed)
				}
			case "DNSKEY", "DS":
				rAddr = "DNSSEC"
			default:
				rAddr = strings.Trim(rAddr+"|"+convertOther(x), "|")
				if rAddr == "" {
					rAddr = "NXDOMAIN"
				}
				continue
			}
			break // an address or DNSSEC ends the rrset
		}
	}
	return rAddr, nil
}

// replyCallbackTypes are the reply callbacks Unbound registers (inplace_cb_reply, _cache, _local, _servfail) by the kind
// the shim fires, and the m_type each logs: the filter of reply-x is get_details_reply's.
var replyCallbackTypes = map[string]string{"reply": "reply-x", "reply_cache": "cache", "reply_local": "local", "reply_servfail": "servfail"}

// fireReplyCallback is the shim's fire_reply_callback: the registered callback of this kind gets the query's state and
// the reply, the client in repinfo. A callback that fails is logged and the reply is still sent.
func (m *pfbUnbound) fireReplyCallback(kind string, qstate *moduleQstate, rep *replyInfo) {
	mType, ok := replyCallbackTypes[kind]
	if !ok {
		return
	}
	client := qstate.clientIP
	kwargs := &logKwargs{repinfo: &client, listenerIP: qstate.pfbListenerIP, listenerInterface: qstate.pfbListenerInterface}
	if err := m.getDetailsReply(mType, &qstate.qinfo, qstate, rep, kwargs); err != nil {
		logErr(fmt.Sprintf("inplace callback %s failed: %v", kind, err))
	}
}

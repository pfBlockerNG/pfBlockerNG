// Go translation of src/usr/local/pkg/pfblockerng/dns_proxy/unbound_shim.py: the constants, reply objects and query
// state of the Unbound API that pythonmod gives pfb_unbound.py. The callback registry, install/uninstall and the
// observer's EDNS options come with the rows that need them.
package decider

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/dnswire"
)

const MODULE_ID = 0

const (
	RR_TYPE_A     uint16 = 1
	RR_TYPE_NS    uint16 = 2
	RR_TYPE_CNAME uint16 = 5
	RR_TYPE_PTR   uint16 = 12
	RR_TYPE_MX    uint16 = 15
	RR_TYPE_TXT   uint16 = 16
	RR_TYPE_SIG   uint16 = 24
	RR_TYPE_AAAA  uint16 = 28
	RR_TYPE_SRV   uint16 = 33
	RR_TYPE_DNAME uint16 = 39
	RR_TYPE_ANY   uint16 = 255
	RR_CLASS_IN   uint16 = 1
)

// pythonmod's runtime constants (interface.i), NOT wire header bits.
const (
	PKT_QR = 1
	PKT_AA = 2
	PKT_TC = 4
	PKT_RD = 8
	PKT_CD = 16
	PKT_RA = 32
	PKT_AD = 64
)

var pktWire = [...]struct {
	pkt  int
	wire uint16
}{
	{PKT_QR, dnswire.QR}, {PKT_AA, dnswire.AA}, {PKT_TC, dnswire.TC}, {PKT_RD, dnswire.RD},
	{PKT_CD, dnswire.CD}, {PKT_RA, dnswire.RA}, {PKT_AD, 0x0020},
}

const (
	RCODE_NOERROR  = 0
	RCODE_NXDOMAIN = 3
)

// util/module.h enum positions
const (
	MODULE_EVENT_NEW     = 0
	MODULE_EVENT_PASS    = 1
	MODULE_EVENT_MODDONE = 5
	MODULE_WAIT_MODULE   = 2
	MODULE_RESTART_NEXT  = 3
	MODULE_WAIT_SUBQUERY = 4
	MODULE_ERROR         = 5
	MODULE_FINISHED      = 6
)

const (
	secStatusUnchecked     = 0
	secStatusIndeterminate = 2
	secStatusInsecure      = 3
)

const moduleCount = 16

// logOutput is where the log lines go: Python's sys.__stderr__. Tests swap it.
var logOutput io.Writer = os.Stderr

// logLine is Python's _log; named so that no declaration of ours takes the standard `log` package's name.
func logLine(level, msg string) {
	fmt.Fprintf(logOutput, "pfb_dns_proxy %s: %s\n", level, msg)
}

func logInfo(msg string) { logLine("info", msg) }

func logWarn(msg string) { logLine("warning", msg) }

func logErr(msg string) { logLine("error", msg) }

// --- reply objects -------------------------------------------------------------------------------

type rrSetKey struct{ typeStr string }

type rrSetData struct {
	count      int // RRs, RRSIGs excluded
	rrsigCount int
	rrData     [][]byte // 2-byte rdlength + uncompressed rdata, the RRs first, then their RRSIGs
	rrTTL      []uint32
}

type rrSetEntry struct{ data *rrSetData }

type rrSet struct {
	rk    rrSetKey
	entry rrSetEntry
}

// shortcut: Python's RRSets reads an index past the end as None (the pythonmod wrapper); rrsets here is a plain slice
// until the first decision that indexes past the end, which comes with its family.
type replyInfo struct {
	flags         uint16 // wire header flags (rcode in the low 4 bits)
	ttl           uint32
	security      int // createResponse never stamps it; the module does
	anNumrrsets   int
	nsNumrrsets   int
	arNumrrsets   int
	rrsets        []*rrSet
	authoritative int
}

type queryInfo struct {
	qnameStr string
	qtype    uint16
	qclass   uint16
}

// qnameList is the labels INCLUDING the root label, so the TLD is [-2]; an error on a non-UTF-8 label, where the real
// property raises.
func (q *queryInfo) qnameList() ([]string, error) {
	labels, err := dnswire.NameToLabels(q.qnameStr)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(labels)+1)
	for _, label := range labels {
		if !utf8.Valid(label) {
			return nil, fmt.Errorf("label %q is not valid UTF-8", label)
		}
		names = append(names, string(label))
	}
	return append(names, ""), nil
}

func (q *queryInfo) qtypeStr() string {
	return dnswire.TypeStr(q.qtype)
}

// rrDataBytes is Python's _rr_data.
func rrDataBytes(rdata []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(rdata))), rdata...)
}

type rrsetIndex struct {
	owner         string
	rtype, rclass uint16
}

// buildRrsets groups each section's RRs into rrsets the way parse_create_msg does: one per (owner, type, class),
// RRSIGs attached to the set they cover, EDNS dropped. Returns (rrsets, per-section rrset counts, minimum TTL).
func buildRrsets(sections [3][]dnswire.RR) ([]*rrSet, [3]int, uint32) {
	var rrsets []*rrSet
	var counts [3]int
	var ttls []uint32
	for i, section := range sections {
		before := len(rrsets)
		byKey := map[rrsetIndex]*rrSet{}
		for _, rr := range section {
			if rr.Rtype == dnswire.TYPE_OPT {
				continue
			}
			ttls = append(ttls, rr.TTL)
			owner := strings.ToLower(rr.Name)
			if rr.Rtype == dnswire.TYPE_RRSIG && len(rr.Rdata) >= 2 {
				covered := byKey[rrsetIndex{owner, binary.BigEndian.Uint16(rr.Rdata[:2]), rr.Rclass}]
				if covered != nil {
					covered.entry.data.rrData = append(covered.entry.data.rrData, rrDataBytes(rr.Rdata))
					covered.entry.data.rrTTL = append(covered.entry.data.rrTTL, rr.TTL)
					covered.entry.data.rrsigCount++
					continue
				}
			}
			rrset := byKey[rrsetIndex{owner, rr.Rtype, rr.Rclass}]
			if rrset == nil {
				rrset = &rrSet{rrSetKey{dnswire.TypeStr(rr.Rtype)}, rrSetEntry{&rrSetData{}}}
				byKey[rrsetIndex{owner, rr.Rtype, rr.Rclass}] = rrset
				rrsets = append(rrsets, rrset)
			}
			data := rrset.entry.data
			data.rrData = slices.Insert(data.rrData, data.count, rrDataBytes(rr.Rdata))
			data.rrTTL = slices.Insert(data.rrTTL, data.count, rr.TTL)
			data.count++
		}
		counts[i] = len(rrsets) - before
	}
	var minTTL uint32
	if len(ttls) > 0 {
		minTTL = slices.Min(ttls)
	}
	return rrsets, counts, minTTL
}

// dnsMsg is Unbound's dns_msg (`qinfo`, `rep`) plus the RR sections the proxy serialises when it answers itself.
type dnsMsg struct {
	qinfo                         queryInfo
	rep                           *replyInfo
	answer, authority, additional []dnswire.RR
}

func newDnsMsg(qinfo queryInfo, flags uint16, answer, authority, additional []dnswire.RR) *dnsMsg {
	rrsets, counts, ttl := buildRrsets([3][]dnswire.RR{answer, authority, additional})
	rep := &replyInfo{
		flags: flags, ttl: ttl, security: secStatusUnchecked,
		anNumrrsets: counts[0], nsNumrrsets: counts[1], arNumrrsets: counts[2], rrsets: rrsets,
	}
	if flags&dnswire.AA != 0 {
		rep.authoritative = 1
	}
	return &dnsMsg{qinfo, rep, answer, authority, additional}
}

// dnsMsgFromMessage is what createResponse makes of a reply from Unbound: EDNS removed, CD cleared. `fallback` stands
// in for a question section the reply lacks (Unbound's access-control REFUSED has none).
func dnsMsgFromMessage(message *dnswire.Message, fallback *dnswire.Question) (*dnsMsg, error) {
	question := fallback
	if len(message.Questions) > 0 {
		question = &message.Questions[0]
	}
	if question == nil {
		return nil, errors.New("reply carries no question")
	}
	qinfo := queryInfo{question.Name, question.Qtype, question.Qclass}
	var additional []dnswire.RR
	for _, rr := range message.Additional {
		if rr.Rtype != dnswire.TYPE_OPT {
			additional = append(additional, rr)
		}
	}
	return newDnsMsg(qinfo, message.Flags&^dnswire.CD, message.Answers, message.Authority, additional), nil
}

type DNSMessage struct {
	rrName                        string
	rrType, rrClass               uint16
	queryFlags                    int
	answer, authority, additional []string
}

func newDNSMessage(rrName string, rrType, rrClass uint16, queryFlags int) *DNSMessage {
	return &DNSMessage{rrName: rrName, rrType: rrType, rrClass: rrClass, queryFlags: queryFlags}
}

// setReturnMsg replaces qstate.returnMsg with a fresh message built from the text RRs; false if one cannot be encoded.
func (m *DNSMessage) setReturnMsg(qstate *moduleQstate) bool {
	if _, err := dnswire.NameToLabels(m.rrName); err != nil {
		return false
	}
	var sections [3][]dnswire.RR
	for i, texts := range [3][]string{m.answer, m.authority, m.additional} {
		for _, text := range texts {
			rr, err := dnswire.RRFromText(text)
			if err != nil {
				return false
			}
			sections[i] = append(sections[i], rr)
		}
	}
	var flags uint16
	for _, p := range pktWire {
		if m.queryFlags&p.pkt != 0 {
			flags += p.wire
		}
	}
	qstate.returnMsg = newDnsMsg(queryInfo{m.rrName, m.rrType, m.rrClass}, flags, sections[0], sections[1], sections[2])
	return true
}

// --- query state ---------------------------------------------------------------------------------

// moduleQstate flattens mesh_info.reply_list.query_reply to clientIP and clientPort.
type moduleQstate struct {
	qinfo                queryInfo
	queryFlags           uint16
	pfbTransport         string
	pfbListenerIP        string
	pfbListenerInterface string
	returnMsg            *dnsMsg
	returnRcode          int
	extState             [moduleCount]int
	noCacheStore         int
	clientIP             string
	clientPort           int
}

func newModuleQstate(qinfo queryInfo, clientIP string, clientPort int, queryFlags uint16, transport, listenerIP, listenerInterface string) *moduleQstate {
	return &moduleQstate{
		qinfo:                qinfo,
		queryFlags:           queryFlags,
		pfbTransport:         transport,
		pfbListenerIP:        listenerIP,
		pfbListenerInterface: listenerInterface,
		returnRcode:          RCODE_NOERROR,
		clientIP:             clientIP,
		clientPort:           clientPort,
	}
}

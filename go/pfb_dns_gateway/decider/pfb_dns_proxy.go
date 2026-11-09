// Go translation of src/usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_proxy.py: the Frontend that decides one client
// query, and the replies it builds itself. The observer, CLI, privilege-drop and code-record code, and the module-less
// path (a Go boot always yields a module or an error), are not part of it.
package decider

import (
	"encoding/binary"
	"fmt"
	"slices"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/dnswire"
)

const (
	RCODE_FORMERR        = 1
	RCODE_SERVFAIL       = 2
	SILENCE_LOG_INTERVAL = 30 * time.Second // between two "no reply from Unbound" lines, whatever Unbound answers in between
	MAX_DNS_MESSAGE      = 65535            // one DNS message; a longer ANSWER is a protocol error at the gateway
)

// forward has the gateway send the client's own bytes to Unbound as that client and returns Unbound's reply bytes,
// nil if there is none.
type forward func(wire []byte) []byte

// boot loads the module from moduleDir and runs its init_standard.
func boot(moduleDir string) (*pfbUnbound, error) {
	return initStandard(MODULE_ID, moduleDir)
}

func optOf(query *dnswire.Message) *dnswire.RR {
	for i := range query.Additional {
		if query.Additional[i].Rtype == dnswire.TYPE_OPT {
			return &query.Additional[i]
		}
	}
	return nil
}

// ednsFor is the OPT record for a message this proxy sends: none when the client sent none, else the proxy's UDP size,
// the client's DO bit and, with `options` (the SafeSearch chase), the client's EDNS options such as ECS.
func ednsFor(query *dnswire.Message, options bool) []dnswire.RR {
	opt := optOf(query)
	if opt == nil {
		return nil
	}
	var data []byte
	if options {
		data = opt.Rdata
	}
	return []dnswire.RR{dnswire.MakeOpt(dnswire.EDNS_UDP_SIZE, opt.TTL&0x8000 != 0, data)}
}

// udpLimit is the bytes a UDP reply to `query` may have: 512 without EDNS, else the client's size, at least 512 and at
// most the size this proxy advertises.
func udpLimit(query *dnswire.Message) int {
	opt := optOf(query)
	if opt == nil {
		return 512
	}
	return min(max(int(opt.Rclass), 512), int(dnswire.EDNS_UDP_SIZE))
}

// errorReply is a bare error reply as Unbound's error_encode builds it: question echoed, RD and CD copied, opcode
// kept, EDNS echoed.
func errorReply(query *dnswire.Message, rcode int) []byte {
	flags := dnswire.QR | dnswire.RA | (query.Flags & (dnswire.RD | dnswire.CD | dnswire.OPCODE_MASK)) | uint16(rcode)
	wire, err := dnswire.Encode(&dnswire.Message{ID: query.ID, Flags: flags, Questions: query.Questions, Additional: ednsFor(query, false)})
	if err != nil {
		// A parsed query's own question and an OPT without options always encode; Python lets the ValueError escape.
		logErr(err.Error())
		return nil
	}
	return wire
}

// rendered is the module's replacement message, addressed to this client, with its rcode, and whether it was replaced
// by a bare SERVFAIL. AD is not kept: the data is no longer the one Unbound validated. Over `limit` bytes (a UDP
// client's) it becomes the question alone with TC set, so the client asks again over TCP; that keeps the module rcode,
// so the callback stays reply. With no limit (a stream client, nil), a message over MAX_DNS_MESSAGE bytes cannot be
// sent whole and is not truncated: it is the bare SERVFAIL.
func rendered(query *dnswire.Message, msg *dnsMsg, limit *int) ([]byte, bool, error) {
	flags := dnswire.QR | dnswire.RA |
		(msg.rep.flags & (dnswire.AA | dnswire.TC | 0xF)) | // 0xF: the rcode, NXDOMAIN included
		(query.Flags & (dnswire.RD | dnswire.CD))
	additional := slices.Concat(msg.additional, ednsFor(query, false))
	wire, err := dnswire.Encode(&dnswire.Message{ID: query.ID, Flags: flags, Questions: query.Questions, Answers: msg.answer, Authority: msg.authority, Additional: additional})
	if err != nil {
		return nil, false, err
	}
	if limit == nil && len(wire) > MAX_DNS_MESSAGE {
		return errorReply(query, RCODE_SERVFAIL), true, nil
	}
	if limit == nil || len(wire) <= *limit {
		return wire, false, nil
	}
	truncated, err := dnswire.Encode(&dnswire.Message{ID: query.ID, Flags: flags | dnswire.TC, Questions: query.Questions, Additional: ednsFor(query, false)})
	return truncated, false, err
}

// moduleDecides is whether the module decides this query. Unbound answers a class other than IN or ANY itself, and an
// additional record that is not one root OPT of EDNS version 0, so those go to it unchanged.
func moduleDecides(query *dnswire.Message) bool {
	for _, question := range query.Questions {
		if question.Qclass != dnswire.CLASS_IN && question.Qclass != dnswire.CLASS_ANY {
			return false
		}
	}
	for _, rr := range query.Additional {
		// EDNS version: TTL bits 16-23
		if rr.Name != "." || rr.Rtype != dnswire.TYPE_OPT || (rr.TTL>>16)&0xFF != 0 {
			return false
		}
	}
	return true
}

// Frontend decides one client query at a time: the module answers it, or Unbound does through the gateway's forward.
// A Frontend is not safe for concurrent use: Python ran it on one asyncio loop, so the wiring PR must serialize or lock.
type Frontend struct {
	module        *pfbUnbound
	silenceLogged time.Duration // when "no reply from Unbound" was last logged, on the monotonic clock
	silenceSeen   bool          // Python starts silenceLogged at -inf; a Duration has no such value
	monotonic     func() time.Duration
}

func newFrontend(module *pfbUnbound) *Frontend {
	start := time.Now()
	return &Frontend{module: module, monotonic: func() time.Duration { return time.Since(start) }}
}

func (f *Frontend) operate(qstate *moduleQstate, event int) int {
	f.module.operate(MODULE_ID, event, qstate, nil)
	return qstate.extState[MODULE_ID]
}

// ask is Unbound's reply to the client's query, or nil. A reply too short to have a DNS header (a zero-length TCP
// frame) is no reply. Silence is logged at most once per SILENCE_LOG_INTERVAL, whatever Unbound answers in between: a
// flood of queries it never answers would otherwise fill the unrotated log, and so would one that it answers a few of.
func (f *Frontend) ask(fwd forward, wire []byte, question dnswire.Question) []byte {
	reply := fwd(wire)
	if len(reply) < 12 {
		reply = nil
	}
	if reply == nil {
		if now := f.monotonic(); !f.silenceSeen || now-f.silenceLogged >= SILENCE_LOG_INTERVAL {
			f.silenceLogged, f.silenceSeen = now, true
			logWarn(fmt.Sprintf("no reply from Unbound for %s %s", question.Name, dnswire.TypeStr(question.Qtype)))
		}
	}
	return reply
}

// unchanged is Unbound's reply to a query it answers itself, relayed as it is; SERVFAIL when it gives none, as the
// module path does for a query Unbound does not answer.
func (f *Frontend) unchanged(wire []byte, query *dnswire.Message, fwd forward) []byte {
	reply := fwd(wire)
	if reply == nil {
		return errorReply(query, RCODE_SERVFAIL)
	}
	return reply
}

// resolve answers one client query: parse it, let the module decide, forward to Unbound when it defers.
//
// nil means the packet is dropped. The header is checked before anything is parsed, so a hostile packet costs a
// constant, and every FORMERR is header-only. Only `transport == "UDP"` holds a built reply to the client's advertised
// size (a relayed reply already is: Unbound saw that size). A query Unbound answers itself (see moduleDecides) is
// forwarded unchanged: its reply is the client's answer.
func (f *Frontend) resolve(wire []byte, clientIP string, fwd forward, transport, listenerIP, listenerInterface string) []byte {
	if len(wire) < 12 || wire[2]&0x80 != 0 { // no header, or a response: never answered (no reflection loops)
		return nil
	}
	msgID, flags := binary.BigEndian.Uint16(wire[0:]), binary.BigEndian.Uint16(wire[2:])
	qdcount, ancount, nscount, arcount := binary.BigEndian.Uint16(wire[4:]), binary.BigEndian.Uint16(wire[6:]), binary.BigEndian.Uint16(wire[8:]), binary.BigEndian.Uint16(wire[10:])
	if (flags>>11)&0xF != 0 {
		return f.unchanged(wire, &dnswire.Message{ID: msgID, Flags: flags}, fwd)
	}
	if qdcount != 1 {
		return errorReply(&dnswire.Message{ID: msgID, Flags: flags}, RCODE_FORMERR)
	}
	if flags&dnswire.TC != 0 || ancount != 0 || nscount != 0 || arcount > 1 {
		return f.unchanged(wire, &dnswire.Message{ID: msgID, Flags: flags}, fwd) // refused before it is read
	}
	query, err := dnswire.Parse(wire)
	if err != nil {
		return errorReply(&dnswire.Message{ID: msgID, Flags: flags}, RCODE_FORMERR)
	}
	if !moduleDecides(query) {
		return f.unchanged(wire, query, fwd)
	}

	question := query.Questions[0]
	qstate := newModuleQstate(
		queryInfo{question.Name, question.Qtype, question.Qclass},
		clientIP,
		0,
		query.Flags,
		transport,
		listenerIP,
		listenerInterface,
	)
	var relay []byte
	state := f.operate(qstate, MODULE_EVENT_NEW)
	if state == MODULE_WAIT_MODULE {
		upstreamReply := f.ask(fwd, wire, question)
		if upstreamReply == nil {
			state = MODULE_ERROR
		} else {
			reply, err := dnswire.Parse(upstreamReply)
			var msg *dnsMsg
			if err == nil {
				msg, err = dnsMsgFromMessage(reply, &question)
			}
			if err != nil {
				logErr(err.Error())
				state = MODULE_ERROR
			} else {
				// An error rcode from Unbound (SERVFAIL, REFUSED...) is the module's returnRcode; NXDOMAIN stays in
				// the reply flags, as Unbound's iterator leaves it.
				baseRcode := reply.Rcode()
				if baseRcode == RCODE_NOERROR || baseRcode == RCODE_NXDOMAIN {
					baseRcode = 0
				}
				qstate.returnMsg = msg
				qstate.returnRcode = baseRcode
				state = f.operate(qstate, MODULE_EVENT_MODDONE)
				if qstate.returnMsg == msg && qstate.returnRcode == baseRcode {
					relay = upstreamReply // the module left Unbound's answer alone: pass its bytes through
				}
			}
		}
	}
	// MODULE_RESTART_NEXT (Python's _chase_cname) comes with the safesearch_cname family: until then it is "not
	// FINISHED", a SERVFAIL, like every other state but the one below.
	if state != MODULE_FINISHED {
		qstate.returnMsg, qstate.returnRcode, relay = nil, RCODE_SERVFAIL, nil
	}
	var limit *int
	if transport == "UDP" {
		limit = new(udpLimit(query))
	}
	reply, err := f.send(query, qstate, relay, limit)
	if err != nil {
		logErr(err.Error())
		return nil
	}
	return reply
}

// send replies to the client the way mesh_send_reply does: rcode != 0 is a bare error, no message is SERVFAIL. A
// stream answer over MAX_DNS_MESSAGE is that same bare SERVFAIL, so the callback is reply_servfail.
func (f *Frontend) send(query *dnswire.Message, qstate *moduleQstate, relay []byte, limit *int) ([]byte, error) {
	msg, rcode := qstate.returnMsg, qstate.returnRcode
	if msg == nil && rcode == RCODE_NOERROR {
		rcode = RCODE_SERVFAIL
	}
	var wire []byte
	if relay == nil && msg != nil && rcode == RCODE_NOERROR {
		var replaced bool
		var err error
		if wire, replaced, err = rendered(query, msg, limit); err != nil {
			return nil, err
		}
		if replaced {
			rcode = RCODE_SERVFAIL // fire_reply_callback picks reply_servfail by it; that call comes with the DNS Reply rows
		}
	}
	if relay != nil {
		return relay, nil
	}
	if wire != nil {
		return wire, nil
	}
	return errorReply(query, rcode), nil
}

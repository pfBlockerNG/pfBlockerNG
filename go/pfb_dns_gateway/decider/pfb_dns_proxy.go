// Go translation of src/usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_proxy.py: the Frontend that decides one client
// query, and the replies it builds itself. The observer's reports come in through relayUpstreamResponse
// (pfb_dns_proxy_observer.go); its socket, the CLI, privilege-drop and code-record code, and the module-less path (a Go
// boot always yields a module or an error), are not part of it.
package decider

import (
	"crypto/rand"
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
	// when an oversized SafeSearch chase was last logged, likewise
	oversizedChaseLogged time.Duration
	oversizedChaseSeen   bool
	monotonic            func() time.Duration
	// malformedReported is the latch of the first malformed observer report: warned about once, never reset.
	malformedReported bool
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
// forwarded unchanged: its reply is the client's answer. The gateway asks Unbound again over TCP for a truncated reply
// to a SafeSearch chase.
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
	if state == MODULE_RESTART_NEXT {
		state = f.chaseCname(query, qstate, fwd)
	}
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

// chaseId is secrets.randbits(16): the 16 bits of a chase's id come from crypto/rand, not math/rand/v2. The id is all an
// off-path sender of a forged answer to the chase has to guess, and Python's `secrets` is the CSPRNG for that; one
// two-byte read per chase costs nothing next to the round trip it starts, and since Go 1.24 Read never fails.
func chaseId() uint16 {
	var id [2]byte
	_, _ = rand.Read(id[:])
	return binary.BigEndian.Uint16(id[:])
}

// chaseCname emulates MODULE_RESTART_NEXT as the SafeSearch CNAME redirect uses it (safesearchCnameRedirect).
//
// The module planted orig -> CNAME -> target and expects Unbound's iterator to chase the target, then runs its
// post-resolution pass on the combined answer. Unbound will not chase a CNAME a module hands it, so this plays the
// iterator: ask Unbound for the target as the same client, give the module the planted CNAME plus the target's answer
// records, and run that pass once. A chase that finds nothing leaves the CNAME alone in the message, which is what makes
// the module answer with its baked address. The chase carries the client's CD bit and EDNS options. A chase over
// MAX_DNS_MESSAGE bytes is never forwarded: the state is MODULE_ERROR, a SERVFAIL. Returns the module's state.
//
// A failure Python raises through resolve's `except Exception` (an unreadable target, a chase that cannot be encoded,
// a reply that is not a DNS message) is logged here and is MODULE_ERROR, as there.
func (f *Frontend) chaseCname(query *dnswire.Message, qstate *moduleQstate, fwd forward) int {
	planted := qstate.returnMsg
	if planted == nil || len(planted.answer) != 1 || planted.answer[0].Rtype != dnswire.TYPE_CNAME {
		logErr("MODULE_RESTART_NEXT without a planted CNAME referral")
		return MODULE_ERROR
	}
	cname := planted.answer[0]
	name, err := dnswire.NameFromRdata(cname.Rdata)
	if err != nil {
		logErr(err.Error())
		return MODULE_ERROR
	}
	target := dnswire.Question{Name: name, Qtype: planted.qinfo.qtype, Qclass: planted.qinfo.qclass}
	chase := &dnswire.Message{
		ID:         chaseId(),
		Flags:      dnswire.RD | (query.Flags & dnswire.CD),
		Questions:  []dnswire.Question{target},
		Additional: ednsFor(query, true),
	}
	wire, err := dnswire.Encode(chase)
	if err != nil {
		logErr(err.Error())
		return MODULE_ERROR
	}
	if len(wire) > MAX_DNS_MESSAGE {
		if now := f.monotonic(); !f.oversizedChaseSeen || now-f.oversizedChaseLogged >= SILENCE_LOG_INTERVAL { // a client can repeat it
			f.oversizedChaseLogged, f.oversizedChaseSeen = now, true
			logErr(fmt.Sprintf("SafeSearch chase for %s is %d bytes, over one DNS message; SERVFAIL", target.Name, len(wire)))
		}
		return MODULE_ERROR
	}
	var answers []dnswire.RR
	if reply := fwd(wire); reply != nil {
		message, err := dnswire.Parse(reply) // an unparseable reply is a SERVFAIL, as above
		if err != nil {
			logErr(err.Error())
			return MODULE_ERROR
		}
		answers = message.Answers
	}
	qstate.returnMsg = newDnsMsg(planted.qinfo, planted.rep.flags, slices.Concat([]dnswire.RR{cname}, answers), nil, nil)
	// A module that asks for yet another restart is not obeyed: the chased answer is final, so that is a SERVFAIL.
	return f.operate(qstate, MODULE_EVENT_MODDONE)
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
			rcode = RCODE_SERVFAIL
		}
	}
	// fire_reply_callback: reply_servfail for a SERVFAIL, else reply; the module logs the row there.
	kind := "reply"
	if rcode == RCODE_SERVFAIL {
		kind = "reply_servfail"
	}
	var rep *replyInfo
	if msg != nil {
		rep = msg.rep
	}
	f.module.fireReplyCallback(kind, qstate, rep)
	if relay != nil {
		return relay, nil
	}
	if wire != nil {
		return wire, nil
	}
	return errorReply(query, rcode), nil
}

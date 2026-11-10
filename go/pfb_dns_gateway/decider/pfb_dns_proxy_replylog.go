// Go translation of src/usr/local/pkg/pfblockerng/dns_proxy/dns_reply_log.py: the DNS Reply log of a decider with no module
// (--no-module --reply-log, issue #3515). Each reply the decider relays fills the row the module fills in module mode (the
// same getDetailsReply, so the same columns, escaping and r_addr values) and goes through the same log pipeline to the same
// file. The rows are the module mode's, call for call: the pass after Unbound's reply (MODDONE) logs a "reply" row, and a
// SERVFAIL (Unbound's, or the proxy's own when Unbound stays silent) goes through the servfail callback as it does in module
// mode, which makes a SERVFAIL Unbound sent two rows there and here.
//
// What init_standard would have set up for that one function is all that is set up: the DNS Reply Logging switch, the
// RCODE names, an empty noAAAA table, the GeoIP reader (as the module opens it, when its database is installed) and the log
// pipeline. No feed is read, no query is decided, none of the module's lifecycle runs.
package decider

import (
	"fmt"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/dnswire"
)

// openReplyLog is ReplyLog.__init__: the module state of the row writer, and its log pipeline.
// shortcut: Python's ReplyLog can fail to start (the module import, the log listener) and the proxy then serves without
// it, with "DNS Reply logging is off, serving without it: ..."; here nothing in the setup can fail: the log files open at
// their first row, so an unwritable log directory is the pipeline's one "Failed to write" line, and the answers go on.
// Upgrade if the setup gains a step that can.
func openReplyLog() *pfbUnbound {
	m := &pfbUnbound{rcodeDB: rcodeNames(), regexRuntime: newRegexRuntime(), decisionDB: newLruCache[*decision](1)}
	m.pfb.pythonReply = true
	m.openMaxmind() // python_maxmind: on when the database is installed and opens
	// no noAAAA, no lists: the row writer reads the switch and the GeoIP flag of the one snapshot
	m.rebuildAndSwap(func() (*snapshot, error) { return newSnapshot(), nil }, false)
	m.pfbSetupLogging()
	logInfo("DNS Reply logging is on: pfb_unbound.py is loaded for its row writer only, no DNSBL runs")
	return m
}

// closeReplyLog is ReplyLog.close: the writer writes what is still queued, then the GeoIP reader closes.
func (m *pfbUnbound) closeReplyLog() {
	m.stopLogging()
	m.closeMaxmind()
}

// logReply is ReplyLog.__call__: it logs one answered query and never fails the answer: a row that cannot be made costs
// that row and one error line.
func (f *Frontend) logReply(query *dnswire.Message, clientIP string, reply []byte, transport, listenerIP, listenerInterface string) {
	if err := f.replyRow(query, clientIP, reply, transport, listenerIP, listenerInterface); err != nil {
		f.replyLogFailed.Do(func() {
			logErr(fmt.Sprintf("DNS Reply logging failed, further failures are silent: %v", err))
		})
	}
}

// replyRow is ReplyLog._log; reply is nil when Unbound did not answer.
func (f *Frontend) replyRow(query *dnswire.Message, clientIP string, reply []byte, transport, listenerIP, listenerInterface string) error {
	m := f.replyLog
	question := query.Questions[0]
	qstate := newModuleQstate(queryInfo{question.Name, question.Qtype, question.Qclass}, clientIP, 0, query.Flags, transport, listenerIP, listenerInterface)
	if reply == nil { // Unbound did not answer: the proxy sends the client a SERVFAIL
		qstate.returnRcode = RCODE_SERVFAIL
		m.fireReplyCallback("reply_servfail", qstate, nil)
		return nil
	}
	parsed, err := dnswire.Parse(reply) // a reply that does not parse is relayed as it is and logs nothing
	if err != nil {
		return err
	}
	message, err := dnsMsgFromMessage(parsed, &question)
	if err != nil {
		return err
	}
	// As the proxy's module mode: an error rcode is the returnRcode, NXDOMAIN stays in the reply flags.
	rcode := parsed.Rcode()
	if rcode == RCODE_NOERROR || rcode == RCODE_NXDOMAIN {
		rcode = 0
	}
	qstate.returnMsg, qstate.returnRcode = message, rcode
	if err := m.getDetailsReply("reply", nil, qstate, message.rep, &logKwargs{pfbAddr: &clientIP, listenerIP: listenerIP, listenerInterface: listenerInterface}); err != nil {
		return err
	}
	if rcode == RCODE_SERVFAIL {
		m.fireReplyCallback("reply_servfail", qstate, message.rep)
	}
	return nil
}

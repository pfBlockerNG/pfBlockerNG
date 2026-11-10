// Go translation of the ADR-65 read-only DNSBL decision query channel of src/usr/local/pkg/pfblockerng/pfb_unbound.py:
// pfb_query_watcher, _pfb_answer_query_request, _pfb_write_query_reply and dnsbl_query_answer. A local consumer (PHP's
// pfb_dnsbl_query) writes a JSON request to pfb_py_query and reads the verdict from pfb_py_query.reply; the verdict is the
// live matcher's, with no counter, log or cache side effect but the decision memo.
//
// It is the control watcher's shape (pfb_unbound_control.go) without a sequence: stateless, so a request already on disk
// when the module starts is answered. The one thing it remembers is the last record it read, so that the reply's own
// directory event in Python (and its next tick here) does not answer an unchanged request twice.
package decider

import (
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/pysem"
)

// queryField is one key of a reply: value is a bool or a string. A reply is written in the order Python builds its dict
// in, which json.dumps keeps.
type queryField struct {
	key   string
	value any
}

// pyJSONString is json.dumps(s) with ensure_ascii: a character outside printable ASCII (DEL included) is a \u escape,
// a character above U+FFFF a surrogate pair, and a lone surrogate (pysem's encoding of one) its own escape.
func pyJSONString(s string) string {
	var out strings.Builder
	out.WriteByte('"')
	for len(s) > 0 {
		r, size := pysem.DecodeRune(s)
		s = s[size:]
		switch {
		case r == '"' || r == '\\':
			out.WriteByte('\\')
			out.WriteRune(r)
		case r == '\n':
			out.WriteString(`\n`)
		case r == '\r':
			out.WriteString(`\r`)
		case r == '\t':
			out.WriteString(`\t`)
		case r == '\b':
			out.WriteString(`\b`)
		case r == '\f':
			out.WriteString(`\f`)
		case ' ' <= r && r <= '~':
			out.WriteRune(r)
		case r >= 0x10000:
			r -= 0x10000
			fmt.Fprintf(&out, `\u%04x\u%04x`, 0xd800|r>>10, 0xdc00|r&0x3ff)
		default:
			fmt.Fprintf(&out, `\u%04x`, r)
		}
	}
	out.WriteByte('"')
	return out.String()
}

// pyJSONDumps is json.dumps of a dict of bools and strings.
func pyJSONDumps(fields []queryField) string {
	var out strings.Builder
	out.WriteByte('{')
	for i, f := range fields {
		if i > 0 {
			out.WriteString(", ")
		}
		out.WriteString(pyJSONString(f.key))
		out.WriteString(": ")
		switch v := f.value.(type) {
		case bool:
			if v {
				out.WriteString("true")
			} else {
				out.WriteString("false")
			}
		case string:
			out.WriteString(pyJSONString(v))
		}
	}
	out.WriteByte('}')
	return out.String()
}

// pyEqual is Python's == of two parsed JSON values, as comparing the two records does: a bool is the int 0 or 1, an int
// equals the float of the same value, dicts compare by content and not by order, and a NaN equals itself because
// json.loads hands out one NaN object, which a container's comparison finds identical.
func pyEqual(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case string:
		y, ok := b.(string)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !pyEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	case *jsonObject:
		y, ok := b.(*jsonObject)
		if !ok || len(x.vals) != len(y.vals) {
			return false
		}
		for key, value := range x.vals {
			other, ok := y.vals[key]
			if !ok || !pyEqual(value, other) {
				return false
			}
		}
		return true
	}
	return pyNumberEqual(a, b)
}

// pyNumberEqual compares two of bool, *big.Int and float64 as Python does; anything else is not a number and not equal.
func pyNumberEqual(a, b any) bool {
	ai, af := pyNumber(a)
	bi, bf := pyNumber(b)
	switch {
	case ai == nil && af == nil, bi == nil && bf == nil:
		return false
	case ai != nil && bi != nil:
		return ai.Cmp(bi) == 0
	case af != nil && bf != nil:
		return *af == *bf || math.IsNaN(*af) && math.IsNaN(*bf)
	}
	i, f := ai, bf
	if i == nil {
		i, f = bi, af
	}
	if math.IsNaN(*f) || math.IsInf(*f, 0) {
		return false
	}
	return new(big.Float).SetInt(i).Cmp(big.NewFloat(*f)) == 0
}

// pyNumber is v as the Python int (an integer) or float (a float) it is; both nil for a value that is neither.
func pyNumber(v any) (*big.Int, *float64) {
	switch x := v.(type) {
	case bool:
		if x {
			return big.NewInt(1), nil
		}
		return new(big.Int), nil
	case *big.Int:
		return x, nil
	case float64:
		return nil, &x
	}
	return nil, nil
}

// queryWriteReply is _pfb_write_query_reply: reply is published as the channel's reply (temp file, fsync, chmod 0o640, rename:
// Go owns this file, unlike the request, which is the writer's to create and permit). A write failure is logged and the
// watcher stays alive. Nothing is written once deinit has begun.
func (m *pfbUnbound) queryWriteReply(reply []queryField) {
	path := m.pfb.pfbPyQueryReply
	if path == "" {
		return
	}
	m.whileNotRetired(func() {
		if failure := writeMarker(path, pyJSONDumps(reply), 0o640); failure != "" {
			fmt.Fprintf(logOutput, "[pfBlockerNG]: failed to write query reply [ %s ]: %s\n", path, failure)
		}
	})
}

// queryMiss is the miss-shaped answer: blocked false and every attribution field empty.
func queryMiss() []queryField {
	return []queryField{
		{"blocked", false}, {"b_type", ""}, {"group", ""}, {"b_eval", ""}, {"feed", ""}, {"p_type", ""},
		{"group_owner", ""}, {"group_origin", ""}, {"group_epoch", ""},
	}
}

// dnsblQueryAnswer is dnsbl_query_answer: the pure, read-only DNSBL verdict for the query channel, without the id. It is
// the matcher operate() uses, with none of its side effects but the decision memo (the one allowed write, as operate()'s
// own memoize call). Python's qtype is accepted and ignored: evaluate_domain has no qtype axis.
func (m *pfbUnbound) dnsblQueryAnswer(domain string) []queryField {
	snap := m.snapshot.Load()
	// Parity with operate(): get_q_name_qstate strips the root dot before lowering; there is no CNAME chain on the channel,
	// so the original name is the name and is_cname is false.
	qName := pysem.Lower(strings.TrimRight(domain, "."))
	dnsbl := evaluateDomain(qName, qName, getTldFromName(qName), false, m.evaluateCfg(snap), snap.containers())
	decisionFor(m.decisionDB, qName, snap.gen).setDnsbl(dnsbl)
	if !(dnsbl.isFound && !dnsbl.inWhitelist) {
		return queryMiss()
	}
	return []queryField{
		{"blocked", true}, {"b_type", dnsbl.bType}, {"group", dnsbl.group},
		{"group_owner", dnsbl.groupOwner}, {"group_origin", dnsbl.groupOrigin},
		{"group_epoch", snap.groupEpochs[[2]string{dnsbl.groupOwner, dnsbl.groupOrigin}]},
		{"b_eval", dnsbl.bEval}, {"feed", dnsbl.feed}, {"p_type", dnsbl.pType},
	}
}

// answerQueryRequest is _pfb_answer_query_request: id must be a non-empty string, else there is nothing to correlate a
// reply to and none is written. domain must be a non-empty string once the trailing root dot is stripped and the rest
// is stripped of whitespace, else the miss-shaped reply is written.
func (m *pfbUnbound) answerQueryRequest(record *jsonObject) {
	id, _ := record.vals["id"].(string)
	if id == "" {
		return
	}
	domain, _ := record.vals["domain"].(string)
	if strings.TrimFunc(strings.TrimRight(domain, "."), pysem.IsSpace) == "" {
		m.queryWriteReply(append([]queryField{{"id", id}}, queryMiss()...))
		return
	}
	m.queryWriteReply(append(m.dnsblQueryAnswer(domain), queryField{"id", id}))
}

// queryWatcher is the state of pfb_query_watcher: the channel and the last record it read.
type queryWatcher struct {
	m       *pfbUnbound
	channel string
	last    *jsonObject
}

func (m *pfbUnbound) newQueryWatcher() *queryWatcher {
	return &queryWatcher{m: m, channel: m.pfb.pfbPyQuery}
}

// answer isolates one request's failure: evaluate_domain over an externally supplied domain is a far larger surface than
// the control or reload watchers, and one request that fails must not end the answering goroutine for the rest of the
// process, which nothing restarts.
// shortcut: Python catches Exception and prints its str(e); a recovered panic's value is printed with %v instead.
func (w *queryWatcher) answer(record *jsonObject) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Fprintf(logOutput, "[pfBlockerNG]: query watcher failed to answer a request: %v\n", err)
		}
	}()
	w.m.answerQueryRequest(record)
}

// drainAndAnswer reads the record and answers it iff it differs from the last one read: a changed record is answered
// again, even with the same id, an identical one (the writer's rewrite, the next tick) is not. A record that is not
// readable is not "the last record": the next good one is compared with the one before it.
func (w *queryWatcher) drainAndAnswer(stop <-chan struct{}) {
	for !stopped(stop) {
		record := channelReadRecord(w.channel, parsePyJSONSurrogates)
		// a record read after Close is not answered
		if record == nil || w.m.retired.Load() || w.last != nil && pyEqual(record, w.last) {
			return
		}
		w.last = record
		w.answer(record)
	}
}

// run is the daemon body: drain, then wait for the next tick, until stop is closed.
// shortcut: Python waits on a kqueue (EVFILT_VNODE on the channel's directory) on FreeBSD and polls elsewhere; Go polls
// on every queryPollInterval tick, which only adds up to that much latency to a reply. Upgrade if that latency matters.
func (w *queryWatcher) run(stop <-chan struct{}, tick <-chan time.Time) {
	drain := w.drainAndAnswer
	if done := w.m.queryDrained; done != nil { // a test's hook: production pays one nil check when the watcher starts
		drain = func(stop <-chan struct{}) {
			w.drainAndAnswer(stop)
			done()
		}
	}
	pollLoop(stop, tick, drain)
}

// queryPollInterval is how often the query watcher looks at the channel. Python wakes on the directory's kqueue event, so
// a reply follows its request within milliseconds; PHP's pfb_dnsbl_query() waits 5 s for it and shares that budget with
// its lock wait, so two parsers polled at RELOAD_POLL_INTERVAL (2 s) would time each other out. A look at an absent or
// unchanged channel is one open and one read.
const queryPollInterval = 50 * time.Millisecond

// startQueryWatcher starts the watcher (queryStop is set, and nil again once it stops) unless it already runs.
func (m *pfbUnbound) startQueryWatcher() {
	if m.queryStop != nil {
		return
	}
	tickFor := m.queryTick
	if tickFor == nil {
		newTicker := m.queryNewTicker
		if newTicker == nil {
			newTicker = time.NewTicker
		}
		tickFor = func() (<-chan time.Time, func()) {
			ticker := newTicker(queryPollInterval)
			return ticker.C, ticker.Stop
		}
	}
	m.queryStop = startPoller("query", tickFor, m.newQueryWatcher().run)
}

// stopQueryWatcher is deinit's stop of the watcher: it returns once the watcher has ended, or after watcherStopWait.
func (m *pfbUnbound) stopQueryWatcher() {
	if m.queryStop != nil {
		m.queryStop()
		m.queryStop = nil
	}
}

package main

import (
	"cmp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// issue #3848: pfB-DNS never fails to start. What the gateway can serve without, it serves without, and the control-socket status
// lists each part it serves without (docs/misc/dns-gateway-transports.md, "Applied status").

// degradedParts is the closed set of parts the status lists, in the order it lists them, each at most once.
var degradedParts = []string{"dnsbl", "dnsbl_settings", "dns_name", "ddr", "tls_certificate", "acl", "statistics", "observer"}

const degradedReasonMax = 300 // bytes

// degradedReasonNone is the reason of a part with nothing printable left in its reason: the status rejects an empty one.
const degradedReasonNone = "no reason given"

// statusDegraded is one part the gateway serves without, and why in one line.
type statusDegraded struct {
	Part   string `json:"part"`
	Reason string `json:"reason"`
}

// nameAndDDR builds the DNS name's answerer and DDR from the flags. What they cannot make is served without, logged, and
// returned in lost by part: a name or an answer table that is no good leaves no name answers, and DDR with it (DDR names the
// name); a --ddr that cannot be built, or --ddr-doh-443 without --ddr, leaves DDR off.
func nameAndDDR(cfg config, secure *tlsListeners, logf func(format string, args ...any)) (names *nameAnswers, d *ddr, lost map[string]string) {
	lost = map[string]string{}
	lose := func(part, what, reason string) {
		logf("%s not served: %s", what, reason)
		lost[part] = reason
	}
	var err error
	switch {
	case cfg.dnsName != "":
		if names, err = newNameAnswers(cfg.dnsName, cfg.nameAnswers); err != nil {
			lose("dns_name", "DNS name", err.Error())
		}
	case len(cfg.nameAnswers) > 0:
		lose("dns_name", "DNS name", "--dns-name-answer needs --dns-name")
	}
	switch {
	case !cfg.ddr:
		if len(cfg.ddrDoH443) > 0 {
			lose("ddr", "DDR", "--ddr-doh-443 needs --ddr")
		}
	case cfg.dnsName == "":
		lose("ddr", "DDR", "--ddr needs --dns-name")
	case names == nil:
		lose("ddr", "DDR", "--ddr needs a --dns-name that can be served")
	default:
		if d, err = ddrOnListeners(cfg, secure); err != nil {
			lose("ddr", "DDR", err.Error())
		}
	}
	return names, d, lost
}

// degraded is what the gateway serves without now: its own start-time losses, the decider's, the certificate store's and the
// ACL's, each part once (the first to name it wins: the gateway's dnsbl is the first boot's error), in degradedParts' order.
func (c *ctlServer) degraded() []statusDegraded {
	reasons := map[string]string{}
	lose := func(part, reason string) {
		if _, listed := reasons[part]; !listed {
			reasons[part] = reason
		}
	}
	for part, reason := range c.lost {
		lose(part, reason)
	}
	if c.frontend != nil {
		for _, p := range c.frontend.Degraded() {
			lose(p.Part, p.Reason)
		}
	}
	if c.certs != nil && c.certs.cert.Load() == nil {
		lose("tls_certificate", cmp.Or(c.certs.missing, noCertificate))
	}
	if c.g != nil && c.g.acl != nil {
		if why := c.g.acl.lost(); why != "" {
			lose("acl", why)
		}
	}
	rows := []statusDegraded{}
	for _, part := range degradedParts {
		if reason, listed := reasons[part]; listed {
			rows = append(rows, statusDegraded{part, degradedReason(reason)})
		}
	}
	return rows
}

// degradedReason is reason as the status carries it: one line, with every character of Unicode category C (control, format,
// private use, surrogate, unassigned) dropped, as PHP's `\p{C}` check of a status reason rejects them, and no bytes that are no
// UTF-8, which JSON would widen; cut to degradedReasonMax bytes where a character ends, and degradedReasonNone if nothing is left.
func degradedReason(reason string) string {
	reason = strings.Map(func(r rune) rune {
		if unicode.Is(unicode.C, r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(reason, ""))
	if len(reason) > degradedReasonMax {
		cut := degradedReasonMax
		for !utf8.RuneStart(reason[cut]) {
			cut--
		}
		reason = reason[:cut]
	}
	if reason == "" {
		return degradedReasonNone
	}
	return reason
}

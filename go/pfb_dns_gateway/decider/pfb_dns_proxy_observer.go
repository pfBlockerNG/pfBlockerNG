// Go translation of the observer's receiving half of dns_proxy/pfb_dns_proxy.py: _upstream_report, which validates one
// datagram from pfb_upstream_observer.py, and Frontend.relay_upstream_response, which fires the module's query_response
// callback on it. The socket the datagrams arrive on (serve_observer: its 0600 mode, the stale-socket unlink, the receive
// buffer) is not part of it: a datagram's bytes come in through relayUpstreamResponse.
package decider

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unicode/utf8"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/pysem"
)

// The limits of one report, which the sender (pfb_upstream_observer.py) keeps its own copies of, except the qname's.
const (
	maxReportBytes     = 2048
	maxReportOptions   = 8
	maxReportOptionHex = 1024
	maxReportQname     = 1024
)

// jsonU16 is _is_u16: an int, never a bool, in 0..65535. A parsed JSON int is a *big.Int and a bool is a bool.
func jsonU16(value any) (uint16, bool) {
	n, ok := value.(*big.Int)
	if !ok || !n.IsUint64() || n.Uint64() > 0xFFFF {
		return 0, false
	}
	return uint16(n.Uint64()), true
}

// reportText is json.loads(bytes)'s decoding of a datagram: UTF-8 with or without a BOM, UTF-16 or UTF-32 with a BOM, or
// without one when the first bytes' NUL pattern says so (json.detect_encoding), the BOM a codec of that name takes off.
// Python decodes with "surrogatepass", so a lone surrogate (an encoded one in UTF-8, an unpaired UTF-16 unit, a UTF-32
// unit in the surrogate range) is a character of the str, not an error: here it is pysem's three-byte encoding of it, which
// the name, the row and the counter then carry as Python does. Anything else invalid is not text.
func reportText(b []byte) (string, bool) {
	switch {
	case bytes.HasPrefix(b, []byte{0xff, 0xfe, 0, 0}):
		return utf32Text(b[4:], binary.LittleEndian)
	case bytes.HasPrefix(b, []byte{0, 0, 0xfe, 0xff}):
		return utf32Text(b[4:], binary.BigEndian)
	case bytes.HasPrefix(b, []byte{0xff, 0xfe}):
		return utf16Text(b[2:], binary.LittleEndian)
	case bytes.HasPrefix(b, []byte{0xfe, 0xff}):
		return utf16Text(b[2:], binary.BigEndian)
	case bytes.HasPrefix(b, []byte{0xef, 0xbb, 0xbf}):
		b = b[3:]
	case len(b) >= 4 && b[0] == 0 && b[1] != 0:
		return utf16Text(b, binary.BigEndian)
	case len(b) >= 4 && b[0] == 0:
		return utf32Text(b, binary.BigEndian)
	case len(b) >= 4 && b[1] == 0 && (b[2] != 0 || b[3] != 0):
		return utf16Text(b, binary.LittleEndian)
	case len(b) >= 4 && b[1] == 0:
		return utf32Text(b, binary.LittleEndian)
	case len(b) == 2 && b[0] == 0:
		return utf16Text(b, binary.BigEndian)
	case len(b) == 2 && b[1] == 0:
		return utf16Text(b, binary.LittleEndian)
	}
	text := string(b)
	for rest := text; len(rest) > 0; {
		r, size := pysem.DecodeRune(rest)
		if r == utf8.RuneError && size == 1 {
			return "", false
		}
		rest = rest[size:]
	}
	return text, true
}

// utf16Text decodes UTF-16 as the codec does: a high unit followed by a low one is one character, any other surrogate unit
// stands alone.
func utf16Text(b []byte, order binary.ByteOrder) (string, bool) {
	if len(b)%2 != 0 {
		return "", false
	}
	var out strings.Builder
	for i := 0; i < len(b); i += 2 {
		unit := rune(order.Uint16(b[i:]))
		if 0xD800 <= unit && unit < 0xDC00 && i+3 < len(b) {
			if low := rune(order.Uint16(b[i+2:])); 0xDC00 <= low && low < 0xE000 {
				out.WriteRune(0x10000 + (unit-0xD800)<<10 + (low - 0xDC00))
				i += 2
				continue
			}
		}
		pysem.WriteRune(&out, unit)
	}
	return out.String(), true
}

// utf32Text decodes UTF-32 as the codec does: a surrogate unit is a lone surrogate, a unit above U+10FFFF is an error.
func utf32Text(b []byte, order binary.ByteOrder) (string, bool) {
	if len(b)%4 != 0 {
		return "", false
	}
	var out strings.Builder
	for i := 0; i < len(b); i += 4 {
		unit := order.Uint32(b[i:])
		if unit > utf8.MaxRune {
			return "", false
		}
		pysem.WriteRune(&out, rune(unit))
	}
	return out.String(), true
}

// notSubscriptable is the TypeError Python's report[key] raises on a parsed JSON value that is not an object.
func notSubscriptable(value any) string {
	switch value.(type) {
	case string:
		return `TypeError("string indices must be integers, not 'str'")`
	case []any:
		return `TypeError('list indices must be integers or slices, not str')`
	case bool:
		return `TypeError("'bool' object is not subscriptable")`
	case *big.Int:
		return `TypeError("'int' object is not subscriptable")`
	case float64:
		return `TypeError("'float' object is not subscriptable")`
	}
	return `TypeError("'NoneType' object is not subscriptable")`
}

// hexDigit is the value of an ASCII hex digit.
func hexDigit(r rune) (byte, bool) {
	switch {
	case '0' <= r && r <= '9':
		return byte(r - '0'), true
	case 'a' <= r && r <= 'f':
		return byte(r-'a') + 10, true
	case 'A' <= r && r <= 'F':
		return byte(r-'A') + 10, true
	}
	return 0, false
}

// pyFromHex is bytes.fromhex: byte pairs of hex digits, with ASCII whitespace allowed between pairs. The error names the
// position, in characters, of the first digit that is missing or is not one.
func pyFromHex(text string) ([]byte, error) {
	chars := pysem.Runes(text)
	out := make([]byte, 0, len(chars)/2)
	for i := 0; i < len(chars); {
		switch chars[i] {
		case ' ', '\t', '\n', '\v', '\f', '\r':
			i++
			continue
		}
		bad := i
		if top, ok := hexDigit(chars[i]); ok {
			bad = i + 1
			if bad < len(chars) {
				if bot, ok := hexDigit(chars[bad]); ok {
					out = append(out, top<<4|bot)
					i += 2
					continue
				}
			}
		}
		return nil, fmt.Errorf("non-hexadecimal number found in fromhex() arg at position %d", bad)
	}
	return out, nil
}

// upstreamReport is what pythonmod would give inplace_cb_query_response for one observer report: the qstate carrying the
// upstream's EDNS options, and the raw response. The error is Python's ValueError: the datagram is not a well-formed
// report. The checks run in Python's order, so that the one refusal reported is the same.
// shortcut: where the refusal is a Python library's exception text (JSONDecodeError, UnicodeDecodeError, RecursionError),
// whose message carries a position or a codec's detail, the reason here is the fixed "invalid JSON" or "not text in UTF-8,
// UTF-16 or UTF-32"; every refusal's cause is the same. Upgrade if a log reader needs the position.
func upstreamReport(data []byte) (*moduleQstate, *dnsMsg, error) {
	if len(data) > maxReportBytes {
		return nil, nil, fmt.Errorf("%d bytes: a report is one datagram of at most %d", len(data), maxReportBytes)
	}
	text, ok := reportText(data)
	if !ok {
		return nil, nil, errors.New("not a report: not text in UTF-8, UTF-16 or UTF-32")
	}
	parsed, ok := parsePyJSONSurrogates(text)
	if !ok {
		return nil, nil, errors.New("not a report: invalid JSON")
	}
	report, ok := parsed.(*jsonObject)
	if !ok {
		return nil, nil, errors.New("not a report: " + notSubscriptable(parsed))
	}
	for _, key := range []string{"client", "qname", "qtype", "flags", "opts"} {
		if _, ok := report.vals[key]; !ok {
			return nil, nil, fmt.Errorf("not a report: KeyError('%s')", key)
		}
	}
	qname, qnameOK := report.vals["qname"].(string)
	qtype, qtypeOK := jsonU16(report.vals["qtype"])
	flags, flagsOK := jsonU16(report.vals["flags"])
	if length := pysem.Len(qname); !(qnameOK && 0 < length && length <= maxReportQname && qtypeOK && flagsOK) {
		return nil, nil, errors.New("qname, qtype or flags is not valid")
	}
	client, clientOK := report.vals["client"].(string)
	opts, optsOK := report.vals["opts"].([]any)
	if !(clientOK && optsOK && len(opts) <= maxReportOptions) {
		return nil, nil, errors.New("client or opts is not valid")
	}
	if client != "" {
		if _, err := pysem.IPAddress(client); err != nil {
			return nil, nil, fmt.Errorf("%s does not appear to be an IPv4 or IPv6 address", pysem.Repr(client))
		}
	}
	options := make([]ednsOpt, 0, len(opts))
	for _, item := range opts {
		pair, ok := item.([]any)
		if !ok || len(pair) != 2 {
			return nil, nil, errors.New("option is not [code, hex data]")
		}
		code, ok := jsonU16(pair[0])
		if !ok {
			return nil, nil, errors.New("option is not [code, hex data]")
		}
		digits, ok := pair[1].(string)
		if !ok || pysem.Len(digits) > maxReportOptionHex {
			return nil, nil, errors.New("option data is not hex of a sane size")
		}
		optionData, err := pyFromHex(digits)
		if err != nil {
			return nil, nil, err
		}
		options = append(options, ednsOpt{code, optionData})
	}
	qinfo := queryInfo{qnameStr: qname, qtype: qtype, qclass: 1}
	qstate := newModuleQstate(qinfo, client, 0, 0, "Unknown", "", "")
	qstate.ednsOptsBackInIter = options
	return qstate, newDnsMsg(qinfo, flags, nil, nil, nil), nil
}

// relayUpstreamResponse handles one datagram from pfb_upstream_observer.py: it fires the module's query_response callback
// on the raw upstream response the datagram reports, so the module logs an upstream block, and counts it, exactly as inside
// Unbound. A malformed or oversize datagram is dropped; the first one of the process is warned about, not every one. No
// answer is built or changed on this path.
func (f *Frontend) relayUpstreamResponse(data []byte) {
	qstate, response, err := upstreamReport(data)
	if err != nil {
		if !f.malformedReported {
			f.malformedReported = true
			logWarn("malformed upstream report from the observer, ignored (further ones silently): " + err.Error())
		}
		return
	}
	f.module.fireQueryResponse(qstate, response)
}

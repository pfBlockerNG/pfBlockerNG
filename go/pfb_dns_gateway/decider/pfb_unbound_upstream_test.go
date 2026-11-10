// The upstream-block half of the module and the observer's receiver: the classifier and the EDE parser, the validation of
// a report in the order Python's _upstream_report applies it, the row and the counter an upstream block writes, and the
// guarantee that no report, however it fails, reaches an answer. Datagram-for-datagram agreement with the shipped Python
// is pfb_unbound_observer_oracle_test.go's; these tests name the rules.
package decider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

const observerStamp = "2026-10-18 12:00:00"

var edeBlockedOption = [2]any{15, fmt.Sprintf("%x", append([]byte{0x00, 0x0f}, "Blocked by Quad9"...))}

// observerReport is a report as the sender's json.dumps writes it, `overrides` replacing fields.
func observerReport(t testing.TB, overrides map[string]any) []byte {
	t.Helper()
	fields := map[string]any{
		"client": "192.0.2.7", "qname": "blocked.example.", "qtype": 1, "flags": 0x8183, "opts": [][2]any{edeBlockedOption},
	}
	for key, value := range overrides {
		fields[key] = value
	}
	out, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// rawReport is a report from JSON tokens written by hand, for the spellings json.Marshal never writes.
func rawReport(client, qname, qtype, flags, opts string) []byte {
	return fmt.Appendf(nil, `{"client":%s,"qname":%s,"qtype":%s,"flags":%s,"opts":%s}`, client, qname, qtype, flags, opts)
}

// goodRaw is rawReport with every field good and `opts` as given.
func goodRaw(opts string) []byte {
	return rawReport(`"192.0.2.7"`, `"blocked.example."`, "1", "33027", opts)
}

type observerRig struct {
	*sqlRig
	rows     []string
	frontend *Frontend
}

// newObserverRig is a module with the dnsbl.log rows collected and the clock fixed; `main` is the ini's [MAIN] body after
// python_enable, so forwarding = true opens the DNSBL database and puts the Upstream counter's epoch in the snapshot.
func newObserverRig(t *testing.T, main string) *observerRig {
	t.Helper()
	r := &observerRig{sqlRig: newSqlRig(t, main, nil)}
	r.m.clock = func() time.Time { return time.Unix(1792324800, 0).UTC() }
	r.m.logSink = func(name, line string) {
		if name == dnsblLogName {
			r.rows = append(r.rows, line)
		}
	}
	r.frontend = newFrontend(r.m)
	return r
}

func (r *observerRig) relay(t testing.TB, data []byte) {
	t.Helper()
	r.frontend.relayUpstreamResponse(data)
}

// --- a: the classifier ---

func TestClassifyUpstreamBlock(t *testing.T) {
	nxra := &upstreamBlock{"NXRA", "NXRA", ""}
	ede := func(info uint16, text string) edeEntry { return edeEntry{info, text} }
	cases := []struct {
		name   string
		rcode  int
		ra, aa bool
		ede    []edeEntry
		want   *upstreamBlock
	}{
		{"NXDOMAIN with RA clear and no EDE is NXRA", RCODE_NXDOMAIN, false, false, nil, nxra},
		{"an empty EDE list leaves NXRA", RCODE_NXDOMAIN, false, false, []edeEntry{}, nxra},
		{"a natural NXDOMAIN (RA set) is no block", RCODE_NXDOMAIN, true, false, nil, nil},
		{"an authoritative NXDOMAIN (AA set) is no block", RCODE_NXDOMAIN, false, true, nil, nil},
		{"an authoritative NXDOMAIN with RA is no block", RCODE_NXDOMAIN, true, true, nil, nil},
		{"NOERROR with RA clear is no block: only NXDOMAIN is NXRA", RCODE_NOERROR, false, false, nil, nil},
		{"SERVFAIL with RA clear is no block", 2, false, false, nil, nil},
		{"EDE15 carries its text as the provider", RCODE_NOERROR, true, false, []edeEntry{ede(15, "Quad9")}, &upstreamBlock{"EDE15", "EDE15 (Blocked)", "Quad9"}},
		{"EDE17 carries its text as the provider", RCODE_NOERROR, true, false, []edeEntry{ede(17, "Quad9")}, &upstreamBlock{"EDE17", "EDE17 (Filtered)", "Quad9"}},
		{"EDE15 with no text has no provider", RCODE_NOERROR, true, false, []edeEntry{ede(15, "")}, &upstreamBlock{"EDE15", "EDE15 (Blocked)", ""}},
		{"EDE15 wins over EDE17 listed before it", RCODE_NOERROR, true, false, []edeEntry{ede(17, "filtered"), ede(15, "blocked")}, &upstreamBlock{"EDE15", "EDE15 (Blocked)", "blocked"}},
		{"EDE15 wins over EDE17 listed after it", RCODE_NOERROR, true, false, []edeEntry{ede(15, "blocked"), ede(17, "filtered")}, &upstreamBlock{"EDE15", "EDE15 (Blocked)", "blocked"}},
		{"only the first EDE15 counts", RCODE_NOERROR, true, false, []edeEntry{ede(15, "one"), ede(15, "two")}, &upstreamBlock{"EDE15", "EDE15 (Blocked)", "one"}},
		{"only the first EDE17 counts", RCODE_NOERROR, true, false, []edeEntry{ede(17, "one"), ede(17, "two")}, &upstreamBlock{"EDE17", "EDE17 (Filtered)", "one"}},
		{"an EDE15 after an unrecognised code still counts", RCODE_NOERROR, true, false, []edeEntry{ede(5, "x"), ede(15, "late")}, &upstreamBlock{"EDE15", "EDE15 (Blocked)", "late"}},
		{"an EDE beats NXRA", RCODE_NXDOMAIN, false, false, []edeEntry{ede(17, "filtered")}, &upstreamBlock{"EDE17", "EDE17 (Filtered)", "filtered"}},
		{"an EDE beats the AA and RA exclusions", RCODE_NXDOMAIN, true, true, []edeEntry{ede(15, "blocked")}, &upstreamBlock{"EDE15", "EDE15 (Blocked)", "blocked"}},
		{"an unrecognised EDE code leaves NXRA", RCODE_NXDOMAIN, false, false, []edeEntry{ede(5, "other")}, nxra},
		{"an unrecognised EDE code on NOERROR is no block", RCODE_NOERROR, false, false, []edeEntry{ede(5, "other")}, nil},
		{"info code 271 is not 15", RCODE_NOERROR, true, false, []edeEntry{ede(271, "x")}, nil},
		{"the provider is stripped of Python whitespace", RCODE_NOERROR, true, false, []edeEntry{ede(15, " \t\u00a0Quad9\u3000\n")}, &upstreamBlock{"EDE15", "EDE15 (Blocked)", "Quad9"}},
		{"a provider of only whitespace is empty", RCODE_NOERROR, true, false, []edeEntry{ede(15, " \u00a0 ")}, &upstreamBlock{"EDE15", "EDE15 (Blocked)", ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyUpstreamBlock(tc.rcode, tc.ra, tc.aa, tc.ede)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("classifyUpstreamBlock(%d, ra=%v, aa=%v, %v) = %+v, want %+v", tc.rcode, tc.ra, tc.aa, tc.ede, got, tc.want)
			}
		})
	}
}

// --- b: the EDE parser ---

func TestParseEdeOptions(t *testing.T) {
	cases := []struct {
		name string
		opts []ednsOpt
		want []edeEntry
	}{
		{"nothing in, nothing out", nil, nil},
		{"code 15 with its two info bytes and no text", []ednsOpt{{15, []byte{0x00, 0x0f}}}, []edeEntry{{15, ""}}},
		{"the info code is big-endian: 0x010F is 271", []ednsOpt{{15, []byte{0x01, 0x0f}}}, []edeEntry{{271, ""}}},
		{"the info code is big-endian: 0x0F01 is 3841", []ednsOpt{{15, []byte{0x0f, 0x01}}}, []edeEntry{{3841, ""}}},
		{"the text is what follows the two bytes", []ednsOpt{{15, append([]byte{0x00, 0x11}, "Filtered"...)}}, []edeEntry{{17, "Filtered"}}},
		{"another option code is skipped", []ednsOpt{{10, []byte{0x00, 0x0f}}, {14, []byte{0x00, 0x0f}}, {16, []byte{0x00, 0x0f}}}, nil},
		{"code 0 and 65535 are skipped", []ednsOpt{{0, []byte{0x00, 0x0f}}, {65535, []byte{0x00, 0x0f}}}, nil},
		{"data of one byte is skipped", []ednsOpt{{15, []byte{0x0f}}}, nil},
		{"data of no bytes is skipped", []ednsOpt{{15, nil}}, nil},
		{"every EDE comes back, in order, around what is skipped", []ednsOpt{{15, []byte{0, 15, 'a'}}, {3, []byte{0, 1}}, {15, []byte{0}}, {15, []byte{0, 17, 'b'}}}, []edeEntry{{15, "a"}, {17, "b"}}},
		{"text that is not UTF-8 gets replacement characters", []ednsOpt{{15, []byte{0, 15, 'b', 'a', 'd', 0xff, 0xfe, 'x'}}}, []edeEntry{{15, "bad\ufffd\ufffdx"}}},
		{"text cut inside a character is one replacement character", []ednsOpt{{15, []byte{0, 15, 'c', 0xe2, 0x82}}}, []edeEntry{{15, "c\ufffd"}}},
		{"an encoded surrogate is three replacement characters", []ednsOpt{{15, []byte{0, 15, 0xed, 0xa0, 0x80}}}, []edeEntry{{15, "\ufffd\ufffd\ufffd"}}},
		{"text of valid multibyte characters is kept", []ednsOpt{{15, append([]byte{0, 15}, "é中😀"...)}}, []edeEntry{{15, "é中😀"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseEdeOptions(tc.opts); !reflect.DeepEqual(got, tc.want) && !(len(got) == 0 && len(tc.want) == 0) {
				t.Errorf("parseEdeOptions(%v) = %v, want %v", tc.opts, got, tc.want)
			}
		})
	}
}

// --- c: report validation, in Python's order ---

// paddedReport is a valid report of exactly `size` bytes: an unknown key, which the receiver ignores, takes up the rest.
func paddedReport(t *testing.T, size int) []byte {
	t.Helper()
	base := len(observerReport(t, map[string]any{"pad": ""}))
	return observerReport(t, map[string]any{"pad": strings.Repeat("a", size-base)})
}

func TestUpstreamReportRefusesWhatPythonRefuses(t *testing.T) {
	const (
		notValid = "qname, qtype or flags is not valid"
		noClient = "client or opts is not valid"
		noOption = "option is not [code, hex data]"
		noData   = "option data is not hex of a sane size"
		notJSON  = "not a report: invalid JSON"
		notText  = "not a report: not text in UTF-8, UTF-16 or UTF-32"
	)
	fromhex := func(pos int) string {
		return fmt.Sprintf("non-hexadecimal number found in fromhex() arg at position %d", pos)
	}
	over := func(size int) string {
		return fmt.Sprintf("%d bytes: a report is one datagram of at most 2048", size)
	}
	nine := "[" + strings.TrimSuffix(strings.Repeat(`[10,"0102"],`, 9), ",") + "]"
	r := func(overrides map[string]any) []byte { return observerReport(t, overrides) }
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"2049 bytes that are not JSON are refused for their size", bytes.Repeat([]byte("x"), 2049), over(2049)},
		{"5000 bytes that are not JSON are refused for their size", bytes.Repeat([]byte("x"), 5000), over(5000)},
		{"a valid report of 2049 bytes is refused before it is read", paddedReport(t, 2049), over(2049)},
		{"not JSON", []byte("not json"), notJSON},
		{"empty", nil, notJSON},
		{"only whitespace", []byte(" \n"), notJSON},
		{"text after the report", append(r(nil), " x"...), notJSON},
		{"a trailing comma", []byte(`{"client":"",}`), notJSON},
		{"single quotes", []byte(`{'client':''}`), notJSON},
		{"a raw control character in a string", []byte("{\"client\":\"a\x01\"}"), notJSON},
		{"nested deeper than the parser recurses", bytes.Repeat([]byte("["), 2000), notJSON},
		{"a BOM twice", append([]byte("\xef\xbb\xbf\xef\xbb\xbf"), r(nil)...), notJSON},
		{"not UTF-8", []byte{0xff, 0xfe, 0x00}, notText},
		{"Latin-1 text", []byte("{\"client\":\"\",\"qname\":\"\xe9\"}"), notText},
		{"UTF-16 cut in a code unit", append([]byte{0xff, 0xfe}, []byte("{\x00}")...), notText},
		{"an array", []byte("[1, 2]"), "not a report: TypeError('list indices must be integers or slices, not str')"},
		{"null", []byte("null"), `not a report: TypeError("'NoneType' object is not subscriptable")`},
		{"a number", []byte("1"), `not a report: TypeError("'int' object is not subscriptable")`},
		{"a float", []byte("1.5"), `not a report: TypeError("'float' object is not subscriptable")`},
		{"NaN is a float", []byte("NaN"), `not a report: TypeError("'float' object is not subscriptable")`},
		{"a boolean", []byte("true"), `not a report: TypeError("'bool' object is not subscriptable")`},
		{"a string", []byte(`"x"`), `not a report: TypeError("string indices must be integers, not 'str'")`},
		{"no fields: the first missing key is client", []byte("{}"), "not a report: KeyError('client')"},
		{"no qname", []byte(`{"client":""}`), "not a report: KeyError('qname')"},
		{"no qtype", []byte(`{"client":"","qname":"a"}`), "not a report: KeyError('qtype')"},
		{"no flags", []byte(`{"client":"","qname":"a","qtype":1}`), "not a report: KeyError('flags')"},
		{"no opts", []byte(`{"client":"","qname":"a","qtype":1,"flags":1}`), "not a report: KeyError('opts')"},
		{"a missing key is reported before a bad value", []byte(`{"client":5}`), "not a report: KeyError('qname')"},
		{"qname not a string", r(map[string]any{"qname": 7}), notValid},
		{"qname empty", r(map[string]any{"qname": ""}), notValid},
		{"qname of 1025 characters", r(map[string]any{"qname": strings.Repeat("a", 1025)}), notValid},
		{"qtype a string", r(map[string]any{"qtype": "A"}), notValid},
		{"qtype a boolean", rawReport(`""`, `"a"`, "true", "1", "[]"), notValid},
		{"qtype out of range", r(map[string]any{"qtype": 70000}), notValid},
		{"qtype 65536", r(map[string]any{"qtype": 65536}), notValid},
		{"qtype negative", r(map[string]any{"qtype": -1}), notValid},
		{"qtype fractional", r(map[string]any{"qtype": 1.5}), notValid},
		{"qtype a float written 1.0", rawReport(`""`, `"a"`, "1.0", "1", "[]"), notValid},
		{"qtype a float written 1e0", rawReport(`""`, `"a"`, "1e0", "1", "[]"), notValid},
		{"qtype null", rawReport(`""`, `"a"`, "null", "1", "[]"), notValid},
		{"qtype beyond 64 bits", rawReport(`""`, `"a"`, "99999999999999999999999", "1", "[]"), notValid},
		{"flags a boolean", rawReport(`""`, `"a"`, "1", "false", "[]"), notValid},
		{"flags NaN", rawReport(`""`, `"a"`, "1", "NaN", "[]"), notValid},
		{"flags Infinity", rawReport(`""`, `"a"`, "1", "Infinity", "[]"), notValid},
		{"flags a string", r(map[string]any{"flags": "x"}), notValid},
		{"flags negative", r(map[string]any{"flags": -1}), notValid},
		{"flags out of range", r(map[string]any{"flags": 70000}), notValid},
		{"qname is checked before client and opts", rawReport("5", "7", "1", "1", "7"), notValid},
		{"client not a string", r(map[string]any{"client": 5}), noClient},
		{"client null", rawReport("null", `"a"`, "1", "1", "[]"), noClient},
		{"opts not a list", r(map[string]any{"opts": "x"}), noClient},
		{"opts null", rawReport(`""`, `"a"`, "1", "1", "null"), noClient},
		{"opts an object", rawReport(`""`, `"a"`, "1", "1", "{}"), noClient},
		{"nine options", rawReport(`""`, `"a"`, "1", "1", nine), noClient},
		{"nine options are counted before the client is read", rawReport(`"not-an-ip"`, `"a"`, "1", "1", nine), noClient},
		{"nine options are counted before any is read", rawReport(`""`, `"a"`, "1", "1", strings.Replace(nine, `[10,"0102"]`, `[15]`, 1)), noClient},
		{"client not an address", r(map[string]any{"client": "not-an-ip"}), "'not-an-ip' does not appear to be an IPv4 or IPv6 address"},
		{"the word Unknown is not an address", r(map[string]any{"client": "Unknown"}), "'Unknown' does not appear to be an IPv4 or IPv6 address"},
		{"a client with a space", r(map[string]any{"client": "192.0.2.7 "}), "'192.0.2.7 ' does not appear to be an IPv4 or IPv6 address"},
		{"a client with a leading zero", r(map[string]any{"client": "192.0.2.07"}), "'192.0.2.07' does not appear to be an IPv4 or IPv6 address"},
		{"a client with an empty zone id", r(map[string]any{"client": "fe80::1%"}), "'fe80::1%' does not appear to be an IPv4 or IPv6 address"},
		{"a client with a slash in its zone id", r(map[string]any{"client": "::1%a/b"}), "'::1%a/b' does not appear to be an IPv4 or IPv6 address"},
		{"a client written with quotes in it is quoted as Python's repr does", r(map[string]any{"client": `a'b`}), `"a'b" does not appear to be an IPv4 or IPv6 address`},
		{"the client is read before any option", rawReport(`"bad"`, `"a"`, "1", "1", `[[15]]`), "'bad' does not appear to be an IPv4 or IPv6 address"},
		{"an option of one item", goodRaw(`[[15]]`), noOption},
		{"an option of no items", goodRaw(`[[]]`), noOption},
		{"an option of three items", goodRaw(`[[15,"00",1]]`), noOption},
		{"an option that is an object", goodRaw(`[{}]`), noOption},
		{"an option code a string", goodRaw(`[["a","00"]]`), noOption},
		{"an option code out of range", goodRaw(`[[70000,"00"]]`), noOption},
		{"an option code negative", goodRaw(`[[-1,"00"]]`), noOption},
		{"an option code a float", goodRaw(`[[1.0,"00"]]`), noOption},
		{"an option code a boolean", goodRaw(`[[true,"00"]]`), noOption},
		{"option data a number", goodRaw(`[[15,5]]`), noData},
		{"option data null", goodRaw(`[[15,null]]`), noData},
		{"option data of 1026 digits", goodRaw(`[[15,"` + strings.Repeat("00", 513) + `"]]`), noData},
		{"option data of 1025 characters, one of them two bytes", goodRaw(`[[15,"` + strings.Repeat("00", 511) + "00é" + `"]]`), noData},
		{"option data not hex", goodRaw(`[[15,"zz"]]`), fromhex(0)},
		{"option data of an odd number of digits", goodRaw(`[[15,"0"]]`), fromhex(1)},
		{"option data with a space inside a byte", goodRaw(`[[15,"0 0"]]`), fromhex(1)},
		{"option data with a digit left after a space", goodRaw(`[[15,"00 0"]]`), fromhex(4)},
		{"option data with a 0x prefix", goodRaw(`[[15,"0x00"]]`), fromhex(1)},
		{"option data with a sign", goodRaw(`[[15,"-100"]]`), fromhex(0)},
		{"option data with a non-ASCII digit first", goodRaw(`[[15,"é00"]]`), fromhex(0)},
		{"the first non-ASCII character is named ahead of an earlier bad digit", goodRaw(`[[15,"zzé"]]`), fromhex(2)},
		{"the first non-ASCII character is named ahead of an earlier space", goodRaw(`[[15,"0 é"]]`), fromhex(2)},
		{"the first non-ASCII character is named ahead of a digit left over", goodRaw(`[[15,"0zé"]]`), fromhex(2)},
		{"option data with a non-ASCII character last", goodRaw(`[[15,"00é"]]`), fromhex(2)},
		{"option data with a no-break space", goodRaw(`[[15,"\u00a000"]]`), fromhex(0)},
		{"the position of a bad character counts characters, not bytes", goodRaw(`[[15,"` + strings.Repeat("00", 511) + `0é"]]`), fromhex(1023)},
		{"the first bad option is the one reported (structure first)", goodRaw(`[[15],[15,"zz"]]`), noOption},
		{"the first bad option is the one reported (hex first)", goodRaw(`[[15,"zz"],[15]]`), fromhex(0)},
		{"a good option, then a bad one", goodRaw(`[[15,"00"],["a","00"]]`), noOption},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			qstate, response, err := upstreamReport(tc.data)
			if err == nil {
				t.Fatalf("upstreamReport accepted %q (qstate %+v), want the refusal %q", tc.data, qstate, tc.want)
			}
			if qstate != nil || response != nil {
				t.Errorf("a refusal returned a qstate and a response: %v %v", qstate, response)
			}
			if err.Error() != tc.want {
				t.Errorf("upstreamReport(%q): refusal %q, want %q", tc.data, err, tc.want)
			}
		})
	}
}

func TestUpstreamReportBuildsWhatTheCallbackReads(t *testing.T) {
	data := rawReport(`"fe80::1%em0"`, `"Blocked.Example."`, "28", "33027", `[[3,"ab"],[15,"00 0f 42"],[65535,""]]`)
	qstate, response, err := upstreamReport(data)
	if err != nil {
		t.Fatal(err)
	}
	if qstate.clientIP != "fe80::1%em0" || qstate.clientPort != 0 {
		t.Errorf("client = %q port %d, want the client as sent and port 0", qstate.clientIP, qstate.clientPort)
	}
	wantInfo := queryInfo{qnameStr: "Blocked.Example.", qtype: 28, qclass: 1}
	if qstate.qinfo != wantInfo || response.qinfo != wantInfo {
		t.Errorf("qinfo = %+v / response %+v, want %+v on both", qstate.qinfo, response.qinfo, wantInfo)
	}
	wantOpts := []ednsOpt{{3, []byte{0xab}}, {15, []byte{0x00, 0x0f, 0x42}}, {65535, []byte{}}}
	if !reflect.DeepEqual(qstate.ednsOptsBackInIter, wantOpts) {
		t.Errorf("EDNS options = %v, want %v: the option data is hex with the whitespace between byte pairs dropped", qstate.ednsOptsBackInIter, wantOpts)
	}
	if response.rep == nil || response.rep.flags != 33027 {
		t.Errorf("response flags = %+v, want 33027: the raw upstream flags", response.rep)
	}
	if qstate.pfbTransport != "Unknown" || qstate.pfbListenerIP != "" || qstate.pfbListenerInterface != "" {
		t.Errorf("transport %q listener %q/%q: the observer path has none of them", qstate.pfbTransport, qstate.pfbListenerIP, qstate.pfbListenerInterface)
	}
	if qstate.returnMsg != nil || qstate.snap != nil {
		t.Errorf("returnMsg %v snap %v: a report's qstate never reached operate()", qstate.returnMsg, qstate.snap)
	}
}

func TestUpstreamReportAcceptsWhatPythonAccepts(t *testing.T) {
	r := func(overrides map[string]any) []byte { return observerReport(t, overrides) }
	cases := []struct {
		name   string
		data   []byte
		client string
		qname  string
		qtype  uint16
		flags  uint16
	}{
		{"an empty client", r(map[string]any{"client": ""}), "", "blocked.example.", 1, 0x8183},
		{"a report of exactly 2048 bytes", paddedReport(t, 2048), "192.0.2.7", "blocked.example.", 1, 0x8183},
		{"qtype -0 is the int 0", rawReport(`""`, `"a."`, "-0", "-0", "[]"), "", "a.", 0, 0},
		{"qtype and flags 65535", rawReport(`""`, `"a."`, "65535", "65535", "[]"), "", "a.", 65535, 65535},
		{"a repeated key: the last wins", []byte(`{"client":"bad","client":"192.0.2.9","qname":"a.","qtype":1,"flags":1,"opts":[],"qname":"b."}`), "192.0.2.9", "b.", 1, 1},
		{"an extra key", []byte(`{"client":"","qname":"a.","qtype":1,"flags":1,"opts":[],"x":[1,{"a":null}]}`), "", "a.", 1, 1},
		{"whitespace around the object", []byte(" \t\r\n{\"client\":\"\",\"qname\":\"a.\",\"qtype\":1,\"flags\":1,\"opts\":[]}\n "), "", "a.", 1, 1},
		{"an escaped slash and a unicode escape", []byte(`{"client":"","qname":"s\/\u0062.","qtype":1,"flags":1,"opts":[]}`), "", "s/b.", 1, 1},
		{"an escaped surrogate pair is one character", []byte(`{"client":"","qname":"\ud83d\ude00.","qtype":1,"flags":1,"opts":[]}`), "", "😀.", 1, 1},
		{"UTF-8 with a BOM", append([]byte("\xef\xbb\xbf"), r(nil)...), "192.0.2.7", "blocked.example.", 1, 0x8183},
		{"UTF-16 little endian with a BOM", utf16Bytes(string(r(nil)), true, true), "192.0.2.7", "blocked.example.", 1, 0x8183},
		{"UTF-16 big endian with a BOM", utf16Bytes(string(r(nil)), false, true), "192.0.2.7", "blocked.example.", 1, 0x8183},
		{"UTF-16 little endian with no BOM", utf16Bytes(string(r(nil)), true, false), "192.0.2.7", "blocked.example.", 1, 0x8183},
		{"UTF-16 big endian with no BOM", utf16Bytes(string(r(nil)), false, false), "192.0.2.7", "blocked.example.", 1, 0x8183},
		{"UTF-32 little endian with a BOM", utf32Bytes(string(r(nil)), true, true), "192.0.2.7", "blocked.example.", 1, 0x8183},
		{"UTF-32 big endian with a BOM", utf32Bytes(string(r(nil)), false, true), "192.0.2.7", "blocked.example.", 1, 0x8183},
		{"UTF-32 little endian with no BOM", utf32Bytes(string(r(nil)), true, false), "192.0.2.7", "blocked.example.", 1, 0x8183},
		{"UTF-32 big endian with no BOM", utf32Bytes(string(r(nil)), false, false), "192.0.2.7", "blocked.example.", 1, 0x8183},
		{"UTF-16 with a pair", utf16Bytes(string(r(map[string]any{"qname": "é😀."})), true, true), "192.0.2.7", "é😀.", 1, 0x8183},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			qstate, response, err := upstreamReport(tc.data)
			if err != nil {
				t.Fatalf("upstreamReport refused a report Python accepts: %v", err)
			}
			if qstate.clientIP != tc.client || qstate.qinfo.qnameStr != tc.qname || qstate.qinfo.qtype != tc.qtype || response.rep.flags != tc.flags {
				t.Errorf("got client %q qname %q qtype %d flags %d, want %q %q %d %d",
					qstate.clientIP, qstate.qinfo.qnameStr, qstate.qinfo.qtype, response.rep.flags, tc.client, tc.qname, tc.qtype, tc.flags)
			}
		})
	}
}

// utf16Bytes is the text in UTF-16 the way Python's codecs write it: a BOM only when asked (the "utf-16" codec's).
func utf16Bytes(text string, little, bom bool) []byte {
	var out []byte
	put := func(unit uint16) {
		if little {
			out = append(out, byte(unit), byte(unit>>8))
		} else {
			out = append(out, byte(unit>>8), byte(unit))
		}
	}
	if bom {
		put(0xfeff)
	}
	for _, r := range text {
		if r >= 0x10000 {
			r -= 0x10000
			put(uint16(0xd800 + r>>10))
			put(uint16(0xdc00 + r&0x3ff))
			continue
		}
		put(uint16(r))
	}
	return out
}

func utf32Bytes(text string, little, bom bool) []byte {
	var out []byte
	put := func(unit uint32) {
		if little {
			out = append(out, byte(unit), byte(unit>>8), byte(unit>>16), byte(unit>>24))
		} else {
			out = append(out, byte(unit>>24), byte(unit>>16), byte(unit>>8), byte(unit))
		}
	}
	if bom {
		put(0xfeff)
	}
	for _, r := range text {
		put(uint32(r))
	}
	return out
}

// The qname limit counts code points, as len() of a Python str does, and not bytes.
func TestUpstreamReportQnameLimitCountsCodePointsNotBytes(t *testing.T) {
	cases := []struct {
		name   string
		qname  string
		accept bool
	}{
		{"1024 ASCII characters", strings.Repeat("a", 1024), true},
		{"1025 ASCII characters", strings.Repeat("a", 1025), false},
		{"1024 code points in 1025 bytes", strings.Repeat("a", 1023) + "é", true},
		{"1024 code points in 1028 bytes", strings.Repeat("a", 1022) + "中中", true},
		{"1024 code points in 1036 bytes", strings.Repeat("a", 1020) + strings.Repeat("😀", 4), true},
		{"1000 code points in 1600 bytes", strings.Repeat("é", 600) + strings.Repeat("a", 400), true},
		{"1025 code points in 1026 bytes", strings.Repeat("a", 1024) + "é", false},
		{"one character", "a", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A report with its non-ASCII characters written as themselves, so that a long name fits a datagram.
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(map[string]any{"client": "", "qname": tc.qname, "qtype": 1, "flags": 1, "opts": []any{}}); err != nil {
				t.Fatal(err)
			}
			_, _, err := upstreamReport(buf.Bytes())
			switch {
			case tc.accept && err != nil:
				t.Errorf("a qname of %d code points (%d bytes) was refused: %v", len([]rune(tc.qname)), len(tc.qname), err)
			case !tc.accept && err == nil:
				t.Errorf("a qname of %d code points (%d bytes) was accepted, want it refused", len([]rune(tc.qname)), len(tc.qname))
			case !tc.accept && err.Error() != "qname, qtype or flags is not valid":
				t.Errorf("refusal %q, want the qname/qtype/flags one", err)
			}
		})
	}
}

// The first malformed report of the process is warned about, whatever it is, and no later one is.
func TestMalformedReportsAreWarnedAboutOnceForTheLifetime(t *testing.T) {
	r := newObserverRig(t, "forwarding = true\n")
	const warning = "pfb_dns_proxy warning: malformed upstream report from the observer, ignored (further ones silently): "
	r.log.Reset()
	r.relay(t, []byte("not json"))
	if got, want := r.log.String(), warning+"not a report: invalid JSON\n"; got != want {
		t.Fatalf("first malformed report logged %q, want %q", got, want)
	}
	r.log.Reset()
	for _, data := range [][]byte{[]byte("not json"), []byte("[1]"), bytes.Repeat([]byte("x"), 3000), paddedReport(t, 2049), nil} {
		r.relay(t, data)
	}
	r.relay(t, observerReport(t, nil))
	r.relay(t, []byte("{}"))
	if r.log.Len() != 0 {
		t.Errorf("later malformed reports logged %q, want nothing", r.log.String())
	}
	if len(r.rows) != 1 {
		t.Errorf("%d rows, want the one good report's", len(r.rows))
	}
	r.frontend = newFrontend(r.m)
	r.relay(t, []byte("{}"))
	if got, want := r.log.String(), warning+"not a report: KeyError('client')\n"; got != want {
		t.Errorf("a new Frontend logged %q, want its own first warning %q", got, want)
	}
}

func TestAnOversizeFirstReportSpendsTheWarning(t *testing.T) {
	r := newObserverRig(t, "forwarding = true\n")
	r.log.Reset()
	r.relay(t, bytes.Repeat([]byte("x"), 2049))
	want := "pfb_dns_proxy warning: malformed upstream report from the observer, ignored (further ones silently): 2049 bytes: a report is one datagram of at most 2048\n"
	if got := r.log.String(); got != want {
		t.Fatalf("logged %q, want %q", got, want)
	}
	r.log.Reset()
	r.relay(t, []byte("not json"))
	if r.log.Len() != 0 {
		t.Errorf("a malformed report after the oversize one logged %q: the one warning was spent", r.log.String())
	}
}

// --- d: the row ---

func TestUpstreamBlockRowIsTheFourteenFieldsPythonWrites(t *testing.T) {
	r := newObserverRig(t, "forwarding = true\n")
	r.relay(t, observerReport(t, nil))
	want := "DNSBL-python," + observerStamp + ",blocked.example,192.0.2.7,Python,Upstream_Block,Upstream,EDE15 (Blocked),Blocked by Quad9,+,A,Unknown,,"
	if !reflect.DeepEqual(r.rows, []string{want}) {
		t.Errorf("rows = %q, want %q", r.rows, want)
	}
}

func TestUpstreamBlockRowCases(t *testing.T) {
	const head = "DNSBL-python," + observerStamp + ","
	const tail = ",Python,Upstream_Block,Upstream,"
	opt := func(info byte, text string) [][2]any {
		return [][2]any{{15, fmt.Sprintf("%x", append([]byte{0, info}, text...))}}
	}
	cases := []struct {
		name string
		over map[string]any
		want string
	}{
		{"NXRA with no provider is External", map[string]any{"flags": 0x8103, "opts": [][2]any{}}, head + "blocked.example,192.0.2.7" + tail + "NXRA,External,+,A,Unknown,,"},
		{"EDE17 names its label", map[string]any{"flags": 0x8180, "opts": opt(17, "Filtered by Quad9")}, head + "blocked.example,192.0.2.7" + tail + "EDE17 (Filtered),Filtered by Quad9,+,A,Unknown,,"},
		{"EDE15 with no text is External", map[string]any{"opts": opt(15, "")}, head + "blocked.example,192.0.2.7" + tail + "EDE15 (Blocked),External,+,A,Unknown,,"},
		{"a provider of only whitespace is External", map[string]any{"opts": opt(15, " \t ")}, head + "blocked.example,192.0.2.7" + tail + "EDE15 (Blocked),External,+,A,Unknown,,"},
		{"no client is logged against 127.0.0.1", map[string]any{"client": ""}, head + "blocked.example,127.0.0.1" + tail + "EDE15 (Blocked),Blocked by Quad9,+,A,Unknown,,"},
		{"a real loopback client is logged as itself", map[string]any{"client": "127.0.0.1"}, head + "blocked.example,127.0.0.1" + tail + "EDE15 (Blocked),Blocked by Quad9,+,A,Unknown,,"},
		{"the client is logged as sent, not normalised", map[string]any{"client": "2001:0DB8::0053"}, head + "blocked.example,2001:0DB8::0053" + tail + "EDE15 (Blocked),Blocked by Quad9,+,A,Unknown,,"},
		{"a zone id with a comma and a quote is quoted", map[string]any{"client": `fe80::1%a,b"c`}, head + `blocked.example,"fe80::1%a,b""c"` + tail + "EDE15 (Blocked),Blocked by Quad9,+,A,Unknown,,"},
		{"the trailing dot of the name is dropped", map[string]any{"qname": "x.y."}, head + "x.y,192.0.2.7" + tail + "EDE15 (Blocked),Blocked by Quad9,+,A,Unknown,,"},
		{"a name with no trailing dot is kept in its case", map[string]any{"qname": "X.Y"}, head + "X.Y,192.0.2.7" + tail + "EDE15 (Blocked),Blocked by Quad9,+,A,Unknown,,"},
		{"a root name is Unknown", map[string]any{"qname": "."}, head + "Unknown,192.0.2.7" + tail + "EDE15 (Blocked),Blocked by Quad9,+,A,Unknown,,"},
		{"the type is its name", map[string]any{"qtype": 28}, head + "blocked.example,192.0.2.7" + tail + "EDE15 (Blocked),Blocked by Quad9,+,AAAA,Unknown,,"},
		{"a private-use type is Unknown in the log", map[string]any{"qtype": 65280}, head + "blocked.example,192.0.2.7" + tail + "EDE15 (Blocked),Blocked by Quad9,+,TYPE65280,Unknown,,"},
		{"a hostile name is escaped and quoted", map[string]any{"qname": `<b>"a"&'c'</b>,x\.example.`}, head + `"\060b\062\034a\034\038\039c\039\060/b\062,x\092.example",192.0.2.7` + tail + "EDE15 (Blocked),Blocked by Quad9,+,A,Unknown,,"},
		{"a hostile provider is escaped and quoted", map[string]any{"opts": opt(15, `<i>"x"</i>, a\`)}, head + "blocked.example,192.0.2.7" + tail + `EDE15 (Blocked),"\060i\062\034x\034\060/i\062, a\092",+,A,Unknown,,`},
		{"a provider ending in a backslash", map[string]any{"opts": opt(15, `end\`)}, head + "blocked.example,192.0.2.7" + tail + `EDE15 (Blocked),end\092,+,A,Unknown,,`},
		{"a line feed in the name is a space", map[string]any{"qname": "a\nb\rc"}, head + "a b c,192.0.2.7" + tail + "EDE15 (Blocked),Blocked by Quad9,+,A,Unknown,,"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newObserverRig(t, "forwarding = true\n")
			r.relay(t, observerReport(t, tc.over))
			if !reflect.DeepEqual(r.rows, []string{tc.want}) {
				t.Errorf("rows = %q\n want   %q", r.rows, tc.want)
			}
		})
	}
}

// An Upstream row has no python_nolog gate and no duplicate mark: it is written each time, "+" each time.
func TestUpstreamBlockRowIgnoresPythonNologAndTheDuplicateMark(t *testing.T) {
	r := newObserverRig(t, "forwarding = true\npython_nolog = true\n")
	if !r.m.snapshot.Load().settings.pythonNolog {
		t.Fatal("python_nolog is off: the test does not exercise the gate")
	}
	r.relay(t, observerReport(t, nil))
	r.relay(t, observerReport(t, nil))
	if len(r.rows) != 2 {
		t.Fatalf("%d rows, want 2: the Upstream row has no python_nolog gate", len(r.rows))
	}
	for i, row := range r.rows {
		if !strings.Contains(row, ",EDE15 (Blocked),Blocked by Quad9,+,A,") {
			t.Errorf("row %d = %q, want the duplicate column to be + each time", i, row)
		}
	}
}

// A qstate of the test's own making carries a transport and a listener the observer path never has: the callback reads
// them from the qstate, since the shim fires it with no keyword arguments.
func TestUpstreamBlockRowTakesTransportAndListenerFromTheQstate(t *testing.T) {
	r := newObserverRig(t, "forwarding = true\n")
	qstate := newModuleQstate(queryInfo{"q.example.", 1, 1}, "192.0.2.7", 0, 0, "DoT", "2001:db8::53", "WAN")
	r.m.fireQueryResponse(qstate, newDnsMsg(qstate.qinfo, 0x8103, nil, nil, nil))
	want := "DNSBL-python," + observerStamp + ",q.example,192.0.2.7,Python,Upstream_Block,Upstream,NXRA,External,+,A,DoT,2001:db8::53,WAN"
	if !reflect.DeepEqual(r.rows, []string{want}) {
		t.Errorf("rows = %q, want %q", r.rows, want)
	}
}

// --- e: the counter ---

// counterEvents is every task the callback enqueued, the worker's queue standing in for the stats database.
func counterEvents(t *testing.T, r *observerRig) (func() []dbEvent, string) {
	t.Helper()
	queue := make(chan dbTask, 16)
	r.m.dbWorker.Store(newDbWorker(r.m, queue))
	t.Cleanup(func() { r.m.dbWorker.Store(nil) })
	drain := func() []dbEvent {
		var events []dbEvent
		for {
			select {
			case task := <-queue:
				events = append(events, task.event)
			default:
				return events
			}
		}
	}
	return drain, r.groupEpoch(t, "Upstream")
}

func TestUpstreamBlockEnqueuesTheUpstreamCounterTask(t *testing.T) {
	cases := []struct {
		name    string
		over    map[string]any
		privacy bool
		want    func(epoch string) dbEvent
	}{
		{"a block counts under the Upstream group, qtype A, no transport, no client", map[string]any{}, false,
			func(epoch string) dbEvent {
				return dbEvent{dnsbl: true, group: "Upstream", owner: "Upstream", origin: "builtin", epoch: epoch, qtype: "A"}
			}},
		{"with the client policy on the client rides with its epoch", map[string]any{}, true,
			func(epoch string) dbEvent {
				return dbEvent{dnsbl: true, group: "Upstream", owner: "Upstream", origin: "builtin", epoch: epoch, qtype: "A", client: "192.0.2.7", clientEpoch: "privacy"}
			}},
		{"no client is counted as no client, not as loopback", map[string]any{"client": ""}, true,
			func(epoch string) dbEvent {
				return dbEvent{dnsbl: true, group: "Upstream", owner: "Upstream", origin: "builtin", epoch: epoch, qtype: "A", clientEpoch: "privacy"}
			}},
		{"a real loopback client is counted as loopback", map[string]any{"client": "127.0.0.1"}, true,
			func(epoch string) dbEvent {
				return dbEvent{dnsbl: true, group: "Upstream", owner: "Upstream", origin: "builtin", epoch: epoch, qtype: "A", client: "127.0.0.1", clientEpoch: "privacy"}
			}},
		{"an IPv4-mapped client is counted as its IPv4 address", map[string]any{"client": "::ffff:192.0.2.7"}, true,
			func(epoch string) dbEvent {
				return dbEvent{dnsbl: true, group: "Upstream", owner: "Upstream", origin: "builtin", epoch: epoch, qtype: "A", client: "192.0.2.7", clientEpoch: "privacy"}
			}},
		{"a client with a zone id is not counted by address", map[string]any{"client": "fe80::1%em0"}, true,
			func(epoch string) dbEvent {
				return dbEvent{dnsbl: true, group: "Upstream", owner: "Upstream", origin: "builtin", epoch: epoch, qtype: "A", clientEpoch: "privacy"}
			}},
		{"a private-use type is counted by its number, the row says Unknown", map[string]any{"qtype": 65280}, false,
			func(epoch string) dbEvent {
				return dbEvent{dnsbl: true, group: "Upstream", owner: "Upstream", origin: "builtin", epoch: epoch, qtype: "TYPE65280"}
			}},
		{"a named type is counted by its name", map[string]any{"qtype": 28}, false,
			func(epoch string) dbEvent {
				return dbEvent{dnsbl: true, group: "Upstream", owner: "Upstream", origin: "builtin", epoch: epoch, qtype: "AAAA"}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newObserverRig(t, "forwarding = true\n")
			drain, epoch := counterEvents(t, r)
			if tc.privacy {
				r.m.metricsPrivacyEpochs = map[int]string{dbDnsbl: "privacy"}
			}
			r.relay(t, observerReport(t, tc.over))
			if got, want := drain(), []dbEvent{tc.want(epoch)}; !reflect.DeepEqual(got, want) {
				t.Errorf("enqueued %+v, want %+v", got, want)
			}
			if len(r.rows) != 1 {
				t.Errorf("%d rows, want the block's one", len(r.rows))
			}
		})
	}
}

// The observer never carries a transport or a listener on a report, but a qstate that does has them counted: the
// counter's transport is blank for Unknown and the listener is the normalised one.
func TestUpstreamBlockCounterCarriesTheQstatesTransportAndListener(t *testing.T) {
	r := newObserverRig(t, "forwarding = true\n")
	drain, epoch := counterEvents(t, r)
	for _, transport := range []string{"UDP", "TCP", "DoT", "DoH", "DoQ", "other"} {
		qstate := newModuleQstate(queryInfo{"q.example.", 1, 1}, "192.0.2.7", 0, 0, transport, "::ffff:192.0.2.53", "LAN")
		r.m.fireQueryResponse(qstate, newDnsMsg(qstate.qinfo, 0x8103, nil, nil, nil))
		want := transport
		if transport == "other" {
			want = ""
		}
		wantEvent := dbEvent{dnsbl: true, group: "Upstream", owner: "Upstream", origin: "builtin", epoch: epoch, qtype: "A", transport: want, listenerIP: "192.0.2.53", listenerInterface: "LAN"}
		if got := drain(); !reflect.DeepEqual(got, []dbEvent{wantEvent}) {
			t.Errorf("transport %q: enqueued %+v, want %+v", transport, got, wantEvent)
		}
	}
}

func TestUpstreamCounterIsGatedOnTheConnectionAndTheEpochButTheRowIsNot(t *testing.T) {
	cases := []struct {
		name     string
		disarm   func(r *observerRig)
		counted  bool
		rowCount int
	}{
		{"connection up and the epoch known: counted", func(*observerRig) {}, true, 1},
		{"the DNSBL connection is down: not counted", func(r *observerRig) { r.m.sqlite3DnsblCon.Store(false) }, false, 1},
		{"the snapshot has no Upstream epoch: not counted", func(r *observerRig) {
			delete(r.m.snapshot.Load().groupEpochs, [2]string{"Upstream", "builtin"})
		}, false, 1},
		{"the snapshot's Upstream epoch is empty: not counted", func(r *observerRig) {
			r.m.snapshot.Load().groupEpochs[[2]string{"Upstream", "builtin"}] = ""
		}, false, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newObserverRig(t, "forwarding = true\n")
			drain, _ := counterEvents(t, r)
			tc.disarm(r)
			r.relay(t, observerReport(t, nil))
			if got := len(drain()); (got == 1) != tc.counted || got > 1 {
				t.Errorf("%d counter events, counted = %v wanted", got, tc.counted)
			}
			if len(r.rows) != tc.rowCount {
				t.Errorf("%d rows, want %d: the row is written whatever the counter does", len(r.rows), tc.rowCount)
			}
		})
	}
}

// The flush lands on the Upstream row init seeded, and only a block counts: a report that classifies as no block, a
// malformed one and one while the resolver is not forwarding leave it alone.
func TestUpstreamCounterLandsOnTheSeededUpstreamRow(t *testing.T) {
	r := newObserverRig(t, "forwarding = true\n")
	counter := func() any {
		return sqlValue(t, r.path(dbDnsbl), "SELECT counter FROM dnsbl WHERE groupname='Upstream'")
	}
	if got := counter(); got != int64(0) {
		t.Fatalf("seeded Upstream counter = %v, want 0", got)
	}
	r.relay(t, observerReport(t, nil))
	r.relay(t, observerReport(t, map[string]any{"flags": 0x8103, "opts": [][2]any{}}))
	r.relay(t, observerReport(t, map[string]any{"flags": 0x8183, "opts": [][2]any{}})) // a natural NXDOMAIN
	r.relay(t, []byte("not json"))
	if got := counter(); got != int64(2) {
		t.Errorf("Upstream counter = %v, want 2: the two blocks", got)
	}
	if got := sqlValue(t, r.path(dbDnsbl), "SELECT count FROM dns_metric_totals WHERE groupname='Upstream' AND owner='Upstream' AND origin='builtin'"); got != int64(2) {
		t.Errorf("dns_metric_totals = %v, want 2", got)
	}
	if len(r.rows) != 2 {
		t.Errorf("%d rows, want 2", len(r.rows))
	}
}

// The forwarding gate is read from the snapshot the callback loads: a swap that turns it off is seen at once, as a
// block reported after it writes nothing.
func TestForwardingGateIsReadFromTheCallbacksSnapshot(t *testing.T) {
	r := newObserverRig(t, "forwarding = true\n")
	r.relay(t, observerReport(t, nil))
	if len(r.rows) != 1 {
		t.Fatalf("%d rows before the gate is closed, want 1", len(r.rows))
	}
	next := *r.m.snapshot.Load()
	settings := *next.settings
	settings.forwarding = false
	next.settings = &settings
	r.m.snapshot.Store(&next)
	r.relay(t, observerReport(t, nil))
	r.relay(t, observerReport(t, map[string]any{"flags": 0x8103, "opts": [][2]any{}}))
	if len(r.rows) != 1 {
		t.Errorf("%d rows after the gate is closed, want still 1", len(r.rows))
	}
}

func TestNoRowAndNoCounterWhileTheResolverIsNotForwarding(t *testing.T) {
	r := newObserverRig(t, "forwarding = false\npython_blocking = true\n")
	r.relay(t, observerReport(t, nil))
	if len(r.rows) != 0 {
		t.Errorf("rows = %q, want none: no forwarding, no upstream to blame", r.rows)
	}
}

// --- f: no answer change ---

// A callback that panics is logged the way Python's try/except prints it, and the report is dropped: nothing reaches the
// caller, no row and no counter are written.
func TestAPanickingCallbackIsSwallowedAndPrintedLikePythons(t *testing.T) {
	r := newObserverRig(t, "forwarding = true\n")
	drain, _ := counterEvents(t, r)
	r.m.logSink = func(string, string) { panic("boom") }
	qstate, response, err := upstreamReport(observerReport(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	r.log.Reset()
	if !r.m.inplaceCbQueryResponse(qstate, response) {
		t.Error("the callback returned False: Python's always returns True")
	}
	if got, want := r.log.String(), "[pfBlockerNG] inplace_cb_query_response: boom\n"; got != want {
		t.Errorf("printed %q, want %q", got, want)
	}
	r.log.Reset()
	r.relay(t, observerReport(t, nil)) // through the Frontend: it must return
	if got, want := r.log.String(), "[pfBlockerNG] inplace_cb_query_response: boom\n"; got != want {
		t.Errorf("through the Frontend printed %q, want %q", got, want)
	}
	if events := drain(); len(events) != 0 {
		t.Errorf("%d counter events after a failed row, want none: the counter follows the row", len(events))
	}
}

// failingWriter panics on the first write containing `trigger`.
type failingWriter struct {
	trigger string
	failed  bool
	out     bytes.Buffer
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if !w.failed && strings.Contains(string(p), w.trigger) {
		w.failed = true
		panic("writer boom")
	}
	return w.out.Write(p)
}

// fireQueryResponse is the shim's last line: whatever the callback's own handler lets out is logged as an error and
// swallowed, as Python's fire_query_response does. The line's reason is the panic value as %v says it, where Python's is
// the exception's repr (Exception('writer boom')): the module's callback catches every Exception itself, so no report
// reaches this line, and the test pins the Go text only to show that the swallow works.
func TestFireQueryResponseSwallowsWhatTheCallbackLetsOut(t *testing.T) {
	r := newObserverRig(t, "forwarding = true\n")
	r.m.logSink = func(string, string) { panic("boom") }
	w := &failingWriter{trigger: "inplace_cb_query_response"}
	previous := logOutput
	logOutput = w
	t.Cleanup(func() { logOutput = previous })
	qstate, response, err := upstreamReport(observerReport(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	r.m.fireQueryResponse(qstate, response)
	if got, want := w.out.String(), "pfb_dns_proxy error: inplace callback query_response failed: writer boom\n"; got != want {
		t.Errorf("logged %q, want %q", got, want)
	}
}

func TestACallbackWithNoResponseFlagsLogsNothing(t *testing.T) {
	r := newObserverRig(t, "forwarding = true\n")
	qstate := newModuleQstate(queryInfo{"q.example.", 1, 1}, "192.0.2.7", 0, 0, "Unknown", "", "")
	for name, response := range map[string]*dnsMsg{"no response": nil, "no reply info": {qinfo: qstate.qinfo}} {
		r.log.Reset()
		if !r.m.inplaceCbQueryResponse(qstate, response) {
			t.Errorf("%s: the callback returned False", name)
		}
		if len(r.rows) != 0 || r.log.Len() != 0 {
			t.Errorf("%s: rows %q log %q, want nothing", name, r.rows, r.log.String())
		}
	}
}

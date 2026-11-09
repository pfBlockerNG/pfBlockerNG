// Port of tests/dns_proxy/test_dnswire.py: packets are hand-built so the codec is not graded against itself.
// Tests after the "Python stdlib behaviour" banner cover what the Go port had to reimplement from the Python
// standard library (shlex, ipaddress, int, repr, str.split); their expectations were produced by running Python 3.13.

package dnswire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var www = []byte("\x03www\x07example\x03com\x00")

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func u16(values ...uint16) []byte {
	var out []byte
	for _, v := range values {
		out = binary.BigEndian.AppendUint16(out, v)
	}
	return out
}

func u32(values ...uint32) []byte {
	var out []byte
	for _, v := range values {
		out = binary.BigEndian.AppendUint32(out, v)
	}
	return out
}

// hdrFlags is Python's _hdr(qd, an, ns, ar, flags=...): counts left out are 0, the id is 0xABCD.
func hdrFlags(flags uint16, counts ...int) []byte {
	var c [4]uint16
	for i, n := range counts {
		c[i] = uint16(n)
	}
	return u16(0xABCD, flags, c[0], c[1], c[2], c[3])
}

func hdr(counts ...int) []byte { return hdrFlags(0x8180, counts...) }

func rr(owner []byte, rtype uint16, rdata []byte) []byte {
	return cat(owner, u16(rtype, CLASS_IN), u32(60), u16(uint16(len(rdata))), rdata)
}

func mustRR(t *testing.T, text string) RR {
	t.Helper()
	got, err := RRFromText(text)
	if err != nil {
		t.Fatalf("RRFromText(%q): %v", text, err)
	}
	return got
}

func mustEncode(t *testing.T, m *Message) []byte {
	t.Helper()
	wire, err := Encode(m)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return wire
}

func mustParse(t *testing.T, packet []byte) *Message {
	t.Helper()
	m, err := Parse(packet)
	if err != nil {
		t.Fatalf("Parse(%x): %v", packet, err)
	}
	return m
}

func wantBytes(t *testing.T, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("got  %x\nwant %x", got, want)
	}
}

func equalRR(a, b RR) bool {
	return a.Name == b.Name && a.Rtype == b.Rtype && a.Rclass == b.Rclass && a.TTL == b.TTL && bytes.Equal(a.Rdata, b.Rdata)
}

// wantWireError is pytest.raises(WireError, match=match): a *WireError whose text contains match.
func wantWireError(t *testing.T, err error, match string) {
	t.Helper()
	var wireErr *WireError
	if !errors.As(err, &wireErr) {
		t.Fatalf("error = %T %v, want *WireError containing %q", err, err, match)
	}
	if !strings.Contains(err.Error(), match) {
		t.Fatalf("error %q does not contain %q", err, match)
	}
}

// wantError is pytest.raises(ValueError, match=match): any error whose text contains match.
func wantError(t *testing.T, err error, match string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want one containing %q", match)
	}
	if !strings.Contains(err.Error(), match) {
		t.Fatalf("error %q does not contain %q", err, match)
	}
}

func response(t *testing.T) []byte {
	t.Helper()
	owner := "www.example.com."
	message := &Message{
		ID:        0xABCD,
		Flags:     QR | RD | RA,
		Questions: []Question{{owner, TYPE_A, CLASS_IN}},
		Answers: []RR{
			mustRR(t, owner+" 300 IN A 192.0.2.1"),
			mustRR(t, owner+" 300 IN AAAA 2001:db8::1"),
			mustRR(t, owner+" 300 IN CNAME target.example.com."),
			mustRR(t, owner+` 300 IN TXT "hello world"`),
		},
		Authority: []RR{mustRR(t, "example.com. 300 IN SOA ns.example.com. admin.example.com. 1 2 3 4 5")},
	}
	return mustEncode(t, message)
}

// --- happy path ----------------------------------------------------------------------------------

func TestEncodeQueryMatchesHandBuiltBytes(t *testing.T) {
	message := &Message{ID: 0xABCD, Flags: RD, Questions: []Question{{"www.example.com.", TYPE_A, CLASS_IN}}}
	wantBytes(t, mustEncode(t, message), cat(hdrFlags(0x0100, 1), www, []byte("\x00\x01\x00\x01")))
}

func TestParseHandBuiltQuery(t *testing.T) {
	message := mustParse(t, cat(hdrFlags(0x0100, 1), www, []byte("\x00\x1c\x00\x01")))
	if message.ID != 0xABCD || message.Flags != 0x0100 || message.Rcode() != 0 {
		t.Fatalf("(id, flags, rcode) = (%#x, %#x, %d), want (0xabcd, 0x100, 0)", message.ID, message.Flags, message.Rcode())
	}
	wantQuestions := []Question{{"www.example.com.", TYPE_AAAA, CLASS_IN}}
	if !reflect.DeepEqual(message.Questions, wantQuestions) {
		t.Fatalf("questions = %v, want %v", message.Questions, wantQuestions)
	}
	if len(message.Answers) != 0 || len(message.Authority) != 0 || len(message.Additional) != 0 {
		t.Fatalf("records = %v %v %v, want none", message.Answers, message.Authority, message.Additional)
	}
}

func TestResponseRoundTripsAndCompressesOwnerNames(t *testing.T) {
	wire := response(t)
	// owner == question name -> pointer to offset 12; the SOA owner example.com. -> pointer into the question
	if n := bytes.Count(wire, []byte("\xc0\x0c")); n != 4 {
		t.Fatalf("pointers to offset 12 = %d, want 4 (wire %x)", n, wire)
	}
	if !bytes.Contains(wire, []byte("\xc0\x10")) {
		t.Fatalf("no pointer to offset 16 in %x", wire)
	}
	message := mustParse(t, wire)
	var types []uint16
	for _, answer := range message.Answers {
		types = append(types, answer.Rtype)
	}
	if want := []uint16{TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_TXT}; !slices.Equal(types, want) {
		t.Fatalf("answer types = %v, want %v", types, want)
	}
	wantA := RR{"www.example.com.", TYPE_A, CLASS_IN, 300, []byte{192, 0, 2, 1}}
	if !equalRR(message.Answers[0], wantA) {
		t.Fatalf("answer 0 = %+v, want %+v", message.Answers[0], wantA)
	}
	wantBytes(t, message.Answers[2].Rdata, []byte("\x06target\x07example\x03com\x00"))
	wantBytes(t, message.Answers[3].Rdata, []byte("\x0bhello world"))
	if message.Authority[0].Rtype != TYPE_SOA {
		t.Fatalf("authority type = %d, want SOA", message.Authority[0].Rtype)
	}
	wantBytes(t, mustEncode(t, message), wire) // re-encoding the parsed message is stable
}

func TestParseExpandsCompressionPointersInsideRdata(t *testing.T) {
	question := cat([]byte("\x01a\x07example\x00"), u16(TYPE_CNAME, CLASS_IN)) // "example." label at offset 14
	owner := []byte("\xc0\x0c")
	cname := rr(owner, TYPE_CNAME, []byte("\x03www\xc0\x0e"))
	mx := rr(owner, TYPE_MX, cat(u16(10), []byte("\x04mail\xc0\x0e")))
	soa := rr(owner, TYPE_SOA, cat([]byte("\x02ns\xc0\x0e\x05admin\xc0\x0e"), u32(1, 2, 3, 4, 5)))
	message := mustParse(t, cat(hdr(1, 3), question, cname, mx, soa))
	want := [][]byte{
		[]byte("\x03www\x07example\x00"),
		cat(u16(10), []byte("\x04mail\x07example\x00")),
		cat([]byte("\x02ns\x07example\x00\x05admin\x07example\x00"), u32(1, 2, 3, 4, 5)),
	}
	if len(message.Answers) != len(want) {
		t.Fatalf("answers = %d, want %d", len(message.Answers), len(want))
	}
	for i, answer := range message.Answers {
		wantBytes(t, answer.Rdata, want[i])
	}
}

func TestParseKeepsRdataOfTypesThatMayNotBeCompressed(t *testing.T) {
	srv := cat(u16(1, 2, 3), []byte("\x03srv\x07example\x00"))
	message := mustParse(t, cat(hdr(1, 1), www, []byte("\x00\x01\x00\x01"), rr([]byte("\xc0\x0c"), 33, srv))) // 33: SRV
	wantBytes(t, message.Answers[0].Rdata, srv)
}

func TestParseIgnoresBytesAfterTheLastRecord(t *testing.T) {
	message := mustParse(t, cat(hdrFlags(0x0100, 1), www, []byte("\x00\x01\x00\x01"), []byte("trailing")))
	if len(message.Questions) != 1 {
		t.Fatalf("questions = %d, want 1", len(message.Questions))
	}
}

func TestNamesRoundTripEscapedLabels(t *testing.T) {
	wire := []byte("\x03a.b\x07example\x00")
	got, err := EncodeName("a\\.b.example.")
	if err != nil {
		t.Fatal(err)
	}
	wantBytes(t, got, wire)
	message := mustParse(t, cat(hdr(1), wire, []byte("\x00\x01\x00\x01")))
	if name := message.Questions[0].Name; name != "a\\.b.example." {
		t.Fatalf("name = %q", name)
	}
	nonprintable := mustParse(t, cat(hdr(1), []byte("\x01\x01\x00"), []byte("\x00\x01\x00\x01")))
	if name := nonprintable.Questions[0].Name; name != "\\001." {
		t.Fatalf("name = %q", name)
	}
}

func TestOptRecordMarksEdnsAndCarriesTheDoBit(t *testing.T) {
	opt := MakeOpt(1232, true, nil)
	if opt.Name != "." || opt.Rtype != TYPE_OPT || opt.Rclass != 1232 || opt.TTL != 0x8000 || len(opt.Rdata) != 0 {
		t.Fatalf("opt = %+v", opt)
	}
	wire := mustEncode(t, &Message{ID: 1, Flags: 0, Questions: []Question{{"example.", TYPE_A, CLASS_IN}}, Additional: []RR{opt}})
	parsed := mustParse(t, wire).Additional
	if len(parsed) != 1 || !equalRR(parsed[0], opt) {
		t.Fatalf("parsed additional = %+v, want [%+v]", parsed, opt)
	}
}

// --- text RRs as written by pfb_unbound.py (DNSMessage.answer/authority) -------------------------

func TestRRFromTextBuildsTheWireRdata(t *testing.T) {
	cases := []struct {
		text  string
		rtype uint16
		rdata []byte
	}{
		{"x.example. 3600 IN A 10.10.10.1", TYPE_A, []byte{10, 10, 10, 1}},
		{"x.example. 3600 IN AAAA ::1", TYPE_AAAA, append(make([]byte, 15), 1)},
		{"x.example. 3600 IN CNAME y.example.", TYPE_CNAME, []byte("\x01y\x07example\x00")},
		{"x.example. 3600 IN CNAME y.example.  ", TYPE_CNAME, []byte("\x01y\x07example\x00")},
		{`python_control. 0 IN TXT "Not authorized! [ a b ]"`, TYPE_TXT, []byte("\x17Not authorized! [ a b ]")},
		{
			"blocked.example. 3600 IN SOA pfb.invalid. nobody.invalid. 1 3600 1200 604800 3600",
			TYPE_SOA,
			cat([]byte("\x03pfb\x07invalid\x00\x06nobody\x07invalid\x00"), u32(1, 3600, 1200, 604800, 3600)),
		},
	}
	for _, c := range cases {
		t.Run(c.text, func(t *testing.T) {
			got := mustRR(t, c.text)
			fields := strings.Fields(c.text)
			ttl, err := strconv.ParseUint(fields[1], 10, 32)
			if err != nil {
				t.Fatal(err)
			}
			want := RR{fields[0], c.rtype, CLASS_IN, uint32(ttl), c.rdata}
			if !equalRR(got, want) {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
	}
}

func TestRRFromTextRejectsWhatItCannotEncode(t *testing.T) {
	for _, text := range []string{
		"x.example. 60 IN MX 10 mail.example.", // type the module never writes
		"x.example. 60 IN A",                   // rdata missing
		"x.example. 60 IN A 999.1.1.1",
		"x.example. 60 IN AAAA 10.0.0.1",
		"x.example. 60 CH A 10.0.0.1",
		"x.example. sixty IN A 10.0.0.1",
		`x.example. 60 IN TXT "unterminated`,
		"x.example. 60 IN TXT " + `"` + strings.Repeat("a", 256) + `"`,
		"x.example. 60 IN SOA only.three. fields.here.",
		"x.example. 60 IN CNAME y.example. junk",
	} {
		t.Run(text, func(t *testing.T) {
			if got, err := RRFromText(text); err == nil {
				t.Fatalf("RRFromText(%q) = %+v, want an error", text, got)
			}
		})
	}
}

// --- hostile input -------------------------------------------------------------------------------

func TestEveryTruncationOfAValidResponseIsRejected(t *testing.T) {
	wire := response(t)
	for cut := range len(wire) {
		t.Run(strconv.Itoa(cut), func(t *testing.T) {
			_, err := Parse(wire[:cut])
			wantWireError(t, err, "")
		})
	}
}

func TestPointerToItselfIsRejected(t *testing.T) {
	_, err := Parse(cat(hdr(1), []byte("\xc0\x0c"), []byte("\x00\x01\x00\x01")))
	wantWireError(t, err, "backwards")
}

func TestForwardPointerIsRejected(t *testing.T) {
	_, err := Parse(cat(hdr(1), []byte("\xc0\x14"), []byte("\x00\x01\x00\x01"), www))
	wantWireError(t, err, "backwards")
}

func TestTwoPointersAimedAtEachOtherAreRejected(t *testing.T) {
	// offset 12 points at 16 and offset 16 points back at 12: a cycle needs one non-backward hop
	packet := cat(hdr(1), []byte("\xc0\x10"), []byte("\x00\x01"), []byte("\xc0\x0c"), []byte("\x00\x01"))
	_, err := Parse(packet)
	wantWireError(t, err, "")
}

func TestTruncatedPointerIsRejected(t *testing.T) {
	_, err := Parse(cat(hdr(1), []byte("\xc0")))
	wantWireError(t, err, "")
}

func TestLabelLongerThan63OrReservedTypeIsRejected(t *testing.T) {
	for _, lengthOctet := range []int{0x40, 0x41, 0x80, 0xBF} {
		t.Run(fmt.Sprintf("%#x", lengthOctet), func(t *testing.T) {
			// The label fits the packet, so only the reserved-type rule can reject it (not "truncated label").
			packet := cat(hdr(1), []byte{byte(lengthOctet)}, bytes.Repeat([]byte("a"), lengthOctet), []byte("\x00\x00\x01\x00\x01"))
			_, err := Parse(packet)
			wantWireError(t, err, "reserved")
		})
	}
}

func TestEncodingALabelLongerThan63IsRejected(t *testing.T) {
	_, err := EncodeName(strings.Repeat("a", 64) + ".example.")
	wantError(t, err, "label")
}

func TestNameOf255OctetsIsAcceptedAndOf256IsNot(t *testing.T) {
	longest := cat(bytes.Repeat([]byte("\x01a"), 127), []byte("\x00")) // 255 octets on the wire
	message := mustParse(t, cat(hdr(1), longest, []byte("\x00\x01\x00\x01")))
	if name := message.Questions[0].Name; name != strings.Repeat("a.", 127) {
		t.Fatalf("name = %q", name)
	}
	_, err := Parse(cat(hdr(1), bytes.Repeat([]byte("\x01a"), 128), []byte("\x00\x00\x01\x00\x01")))
	wantWireError(t, err, "255")
	_, err = EncodeName(strings.Repeat("a.", 128))
	wantError(t, err, "255")
}

func TestEmptyLabelInTheMiddleOfANameIsRejected(t *testing.T) {
	_, err := EncodeName("a..example.")
	wantError(t, err, "")
}

func TestQuestionCountZeroParsesToNoQuestions(t *testing.T) {
	message := mustParse(t, hdrFlags(0x0100, 0))
	if len(message.Questions) != 0 {
		t.Fatalf("questions = %v, want none", message.Questions)
	}
}

func TestHeaderCountsLargerThanThePacketAreRejectedBeforeParsing(t *testing.T) {
	_, err := Parse(hdr(65535, 65535, 65535, 65535))
	wantWireError(t, err, "count")
}

func TestHeaderShorterThanTwelveBytesIsRejected(t *testing.T) {
	_, err := Parse([]byte("\x12\x34\x01"))
	wantWireError(t, err, "header")
}

func TestRdlengthBeyondThePacketIsRejected(t *testing.T) {
	packet := cat(hdr(1, 1), www, []byte("\x00\x01\x00\x01"), []byte("\xc0\x0c"), u16(1, CLASS_IN), u32(60), u16(4), []byte("\x01\x02"))
	_, err := Parse(packet)
	wantWireError(t, err, "rdata")
}

func TestNameInsideRdataThatRunsPastRdlengthIsRejected(t *testing.T) {
	// CNAME rdlength 2 covers "\x01a" only; the name's root octet sits OUTSIDE the declared rdata
	packet := cat(hdr(1, 1), www, []byte("\x00\x05\x00\x01"), []byte("\xc0\x0c"), u16(5, CLASS_IN), u32(60), u16(2), []byte("\x01a\x00"))
	_, err := Parse(packet)
	wantWireError(t, err, "rdata")
}

func TestNameInRdataFollowedByAStrayOctetIsRejected(t *testing.T) {
	// rdlength covers the name "a." and one octet more: the record says more than its type holds.
	for _, rtype := range []uint16{TYPE_CNAME, TYPE_PTR} {
		t.Run(TypeStr(rtype), func(t *testing.T) {
			packet := cat(hdr(1, 1), www, []byte("\x00\x05\x00\x01"), rr([]byte("\xc0\x0c"), rtype, []byte("\x01a\x00\xff")))
			_, err := Parse(packet)
			wantWireError(t, err, "rdata length mismatch")
		})
	}
}

// --- Go-only checks of what the translation adds ------------------------------------------------

func TestTypeStr(t *testing.T) {
	for _, c := range typeNameCases {
		if got := TypeStr(c.rtype); got != c.want {
			t.Errorf("TypeStr(%d) = %q, want %q", c.rtype, got, c.want)
		}
	}
}

func TestRcodeIsTheLowFourFlagBits(t *testing.T) {
	if got := (&Message{Flags: QR | RA | 0x0003}).Rcode(); got != 3 {
		t.Fatalf("Rcode = %d, want 3", got)
	}
	if got := (&Message{Flags: 0xFFF0}).Rcode(); got != 0 {
		t.Fatalf("Rcode = %d, want 0", got)
	}
}

func TestMakeOptWithoutDoAndWithOptions(t *testing.T) {
	opt := MakeOpt(512, false, []byte{1, 2})
	if want := (RR{".", TYPE_OPT, 512, 0, []byte{1, 2}}); !equalRR(opt, want) {
		t.Fatalf("opt = %+v, want %+v", opt, want)
	}
}

func TestLabelsToTextEscapesAndRoot(t *testing.T) {
	if got := LabelsToText(nil); got != "." {
		t.Fatalf("root = %q", got)
	}
	if got := LabelsToText([][]byte{[]byte("a.b"), {0x01}, []byte(`c\d`), {0x7f}, []byte("é")}); got != `a\.b.\001.c\\d.\127.\195\169.` {
		t.Fatalf("got %q", got)
	}
}

func TestNameFromRdata(t *testing.T) {
	got, err := NameFromRdata([]byte("\x03www\x07example\x00"))
	if err != nil || got != "www.example." {
		t.Fatalf("got %q, %v", got, err)
	}
	if got, err = NameFromRdata([]byte{0}); err != nil || got != "." {
		t.Fatalf("root: got %q, %v", got, err)
	}
	_, err = NameFromRdata([]byte("\x03www"))
	wantWireError(t, err, "truncated")
}

func TestEncodeCompressesOwnersCaseBlind(t *testing.T) {
	// the client's spelling of the question wins: an answer owner equal to it (or to a suffix of it) is a pointer into it
	message := &Message{
		ID:        0xABCD,
		Flags:     0x8180,
		Questions: []Question{{"WWW.Example.COM.", TYPE_A, CLASS_IN}},
		Answers: []RR{
			mustRR(t, "www.example.com. 60 IN A 1.2.3.4"),
			mustRR(t, "Ns.EXAMPLE.com. 60 IN A 1.2.3.5"),
			mustRR(t, "Other.Example.COM. 60 IN CNAME www.example.com."),
		},
	}
	want, err := hex.DecodeString("abcd8180000100030000000003575757074578616d706c6503434f4d0000010001c00c000100010000003c000401020304" +
		"024e73c010000100010000003c000401020305054f74686572c010000500010000003c001103777777076578616d706c6503636f6d00")
	if err != nil {
		t.Fatal(err)
	}
	wantBytes(t, mustEncode(t, message), want)
}

func TestEncodeStopsRecordingNamesPastThe0x4000Offset(t *testing.T) {
	message := &Message{ID: 1, Flags: 0x8180, Questions: []Question{{"q.example.", TYPE_A, CLASS_IN}}}
	for i := range 1500 {
		message.Answers = append(message.Answers, RR{fmt.Sprintf("n%d.example.", i), TYPE_A, CLASS_IN, 60, make([]byte, 4)})
	}
	for _, name := range []string{"late.example.", "late.example.", "LATE.example."} {
		message.Answers = append(message.Answers, RR{name, TYPE_A, CLASS_IN, 60, make([]byte, 4)})
	}
	wire := mustEncode(t, message)
	// Python 3.13 produced this length and digest for the same message
	if got := fmt.Sprintf("%d %x", len(wire), sha256.Sum256(wire)); got != "31980 d778114b7d43349726793cb2a3ae3308072f9f83c66c1ed1521b747cfcf3d8cf" {
		t.Fatalf("len and sha256 = %s", got)
	}
	if n := bytes.Count(wire, []byte("\x04late")); n != 2 { // both lower-case owners written in full: the first sits past 0x4000
		t.Fatalf("full \\x04late owners = %d, want 2", n)
	}
}

func TestEncodeRejectsWhatDoesNotFitTheWireFields(t *testing.T) {
	_, err := Encode(&Message{Answers: []RR{{".", TYPE_A, CLASS_IN, 0, make([]byte, 65536)}}})
	wantError(t, err, "'H' format requires 0 <= number <= 65535")
	_, err = Encode(&Message{Questions: make([]Question, 65536)})
	wantError(t, err, "'H' format requires 0 <= number <= 65535")
	_, err = Encode(&Message{Questions: []Question{{"bad..name.", TYPE_A, CLASS_IN}}})
	wantError(t, err, "empty label")
}

func TestParseReturnsRdataThatDoesNotAliasThePacket(t *testing.T) {
	packet := cat(hdr(1, 1), www, []byte("\x00\x01\x00\x01"), rr([]byte("\xc0\x0c"), TYPE_A, []byte{1, 2, 3, 4}))
	message := mustParse(t, packet)
	for i := range packet {
		packet[i] = 0xEE
	}
	wantBytes(t, message.Answers[0].Rdata, []byte{1, 2, 3, 4})
}

// parseOneRR parses a packet holding one question and one answer of rtype with the given rdata.
func parseOneRR(rtype uint16, rdata []byte) ([]byte, error) {
	packet := cat(hdr(1, 1), []byte("\x01a\x07example\x00"), u16(TYPE_A, CLASS_IN), []byte("\xc0\x0c"), rr(nil, rtype, rdata))
	message, err := Parse(packet)
	if err != nil {
		return nil, err
	}
	return message.Answers[0].Rdata, nil
}

func TestParseExpandsEveryTypeWithNameRdata(t *testing.T) {
	// "\xc0\x0e" points at the "example." label of the question
	for _, rtype := range []uint16{2, 3, 4, 5, 7, 8, 9, 12} { // NS MD MF CNAME MB MG MR PTR
		got, err := parseOneRR(rtype, []byte("\x03www\xc0\x0e"))
		if err != nil {
			t.Fatalf("type %d: %v", rtype, err)
		}
		wantBytes(t, got, []byte("\x03www\x07example\x00"))
	}
	got, err := parseOneRR(14, []byte("\x03www\xc0\x0e\x04mail\xc0\x0e")) // MINFO: two names
	if err != nil {
		t.Fatal(err)
	}
	wantBytes(t, got, []byte("\x03www\x07example\x00\x04mail\x07example\x00"))
	got, err = parseOneRR(13, []byte("\x03www\xc0\x0e")) // HINFO is not a name type: kept verbatim
	if err != nil {
		t.Fatal(err)
	}
	wantBytes(t, got, []byte("\x03www\xc0\x0e"))
	_, err = parseOneRR(TYPE_MX, []byte("\x00"))
	wantWireError(t, err, "fixed rdata field overruns rdata")
	_, err = parseOneRR(TYPE_SOA, cat([]byte("\x00\x00"), make([]byte, 19)))
	wantWireError(t, err, "fixed rdata field overruns rdata")
	_, err = parseOneRR(TYPE_NS, []byte("\x03www\xc0\x0e\x00"))
	wantWireError(t, err, "rdata length mismatch")
}

func TestParseFollowsAtMost127PointersPerName(t *testing.T) {
	// answer k's owner is a pointer to answer k-1's owner (answer 1's to the question's root name): k hops
	chain := func(n int) []byte {
		packet := cat(hdr(1, n), []byte{0}, u16(TYPE_A, CLASS_IN))
		prev := 12
		for range n {
			packet = cat(packet, u16(0xC000|uint16(prev)), u16(99, CLASS_IN), u32(0), u16(0))
			prev = len(packet) - 12
		}
		return packet
	}
	mustParse(t, chain(127))
	_, err := Parse(chain(128))
	wantWireError(t, err, "more than 127 compression pointers in one name")
}

// --- Python stdlib behaviour the Go port reimplements (expectations: Python 3.13 output) ----------

var shlexCases = []struct {
	in   string
	want []string
	err  string
}{
	{"a b", []string{"a", "b"}, ""},
	{"\"hello world\"", []string{"hello world"}, ""},
	{"'single quoted'", []string{"single quoted"}, ""},
	{"a\"b c\"d", []string{"ab cd"}, ""},
	{"\"\"", []string{""}, ""},
	{"''", []string{""}, ""},
	{"a\\ b", []string{"a b"}, ""},
	{"\"a\\\"b\"", []string{"a\"b"}, ""},
	{"\"a\\\\b\"", []string{"a\\b"}, ""},
	{"\"a\\xb\"", []string{"a\\xb"}, ""},
	{"'a\\b'", []string{"a\\b"}, ""},
	{"  lead  trail  ", []string{"lead", "trail"}, ""},
	{"x \"a b\" y", []string{"x", "a b", "y"}, ""},
	{"\"unterminated", nil, "No closing quotation"},
	{"'unterminated", nil, "No closing quotation"},
	{"dangling\\", nil, "No escaped character"},
	{"\"a\" \"b\"", []string{"a", "b"}, ""},
	{"a\u0009b\u000ac", []string{"a", "b", "c"}, ""},
	{"\\\"q", []string{"\"q"}, ""},
	{"\"\u00e9 \u00fc\"", []string{"\u00e9 \u00fc"}, ""},
	{"a\"\"b", []string{"ab"}, ""},
	{"\"a\\", nil, "No escaped character"},
	{"", []string{}, ""},
	{"   ", []string{}, ""},
	{"\\", nil, "No escaped character"},
	{"a'b'c", []string{"abc"}, ""},
	{"'a\"b'", []string{"a\"b"}, ""},
	{"a\\\u000ab", []string{"a\u000ab"}, ""},
}

var reprCases = []struct{ in, want string }{
	{"abc", "'abc'"},
	{"", "''"},
	{"a'b", "\"a'b\""},
	{"a\"b", "'a\"b'"},
	{"a'\"b", "'a\\'\"b'"},
	{"a\\b", "'a\\\\b'"},
	{"tab\u0009", "'tab\\t'"},
	{"nl\u000a\u000d", "'nl\\n\\r'"},
	{"\u0000\u0001", "'\\x00\\x01'"},
	{"\u007f\u00ad\u0085\u00e9", "'\\x7f\\xad\\x85\u00e9'"},
	{"\U0001f600", "'\U0001f600'"},
	{"\ue000", "'\\ue000'"},
	{"\U000e0001", "'\\U000e0001'"},
	{"\u00a0", "'\\xa0'"},
	{"\u2028", "'\\u2028'"},
	{"\u0007\u000b\u000c\u001b", "'\\x07\\x0b\\x0c\\x1b'"},
	{"\u00ff\u00ff\u0100", "'\u00ff\u00ff\u0100'"},
}

var rrFromTextErrCases = []struct{ line, want string }{
	{"x.example. 60 IN A 999.1.1.1", "Octet 999 (> 255) not permitted in '999.1.1.1'"},
	{"x.example. 60 IN A 1.2.3", "Expected 4 octets in '1.2.3'"},
	{"x.example. 60 IN A 01.2.3.4", "Leading zeros are not permitted in '01' in '01.2.3.4'"},
	{"x.example. 60 IN A 1.2.3.x", "Only decimal digits permitted in 'x' in '1.2.3.x'"},
	{"x.example. 60 IN A 1..3.4", "Empty octet not permitted in '1..3.4'"},
	{"x.example. 60 IN A 1.2.3.4/8", "Unexpected '/' in '1.2.3.4/8'"},
	{"x.example. 60 IN A 1.2.3.1234", "At most 3 characters permitted in '1234' in '1.2.3.1234'"},
	{"x.example. 60 IN A \u0661.2.3.4", "Only decimal digits permitted in '\u0661' in '\u0661.2.3.4'"},
	{"x.example. 60 IN A 1.2.3.4.5", "Expected 4 octets in '1.2.3.4.5'"},
	{"x.example. 60 IN AAAA 10.0.0.1", "At least 3 parts expected in '10.0.0.1'"},
	{"x.example. 60 IN AAAA ::1::", "At most one '::' permitted in '::1::'"},
	{"x.example. 60 IN AAAA 1:2:3:4:5:6:7:8:9", "Exactly 8 parts expected without '::' in '1:2:3:4:5:6:7:8:9'"},
	{"x.example. 60 IN AAAA 12345::", "At most 4 characters permitted in '12345' in '12345::'"},
	{"x.example. 60 IN AAAA fe80::1%", "Invalid IPv6 address: \"'fe80::1%'\""},
	{"x.example. 60 IN AAAA fe80::1%a%b", "Invalid IPv6 address: \"'fe80::1%a%b'\""},
	{"x.example. 60 IN AAAA ::1.2.3", "Expected 4 octets in '1.2.3' in '::1.2.3'"},
	{"x.example. 60 IN AAAA :1:2:3:4:5:6:7", "Leading ':' only permitted as part of '::' in ':1:2:3:4:5:6:7'"},
	{"x.example. 60 IN AAAA 1:2:3:4:5:6:7:", "Trailing ':' only permitted as part of '::' in '1:2:3:4:5:6:7:'"},
	{"x.example. 60 IN AAAA 1:2:3:4:5:6:7", "Exactly 8 parts expected without '::' in '1:2:3:4:5:6:7'"},
	{"x.example. 60 IN AAAA 1:2:3:4:5:6::7:8", "Expected at most 7 other parts with '::' in '1:2:3:4:5:6::7:8'"},
	{"x.example. 60 IN AAAA 1:g::", "Only hex digits permitted in 'g' in '1:g::'"},
	{"x.example. 60 IN AAAA 1::2::3", "At most one '::' permitted in '1::2::3'"},
	{"x.example. 60 IN AAAA 1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1", "At most 45 characters expected in '1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1'"},
	{"x.example. 60 IN AAAA 1:2:3:4:5:6:7:8/64", "Unexpected '/' in '1:2:3:4:5:6:7:8/64'"},
	{"x.example. 60 IN AAAA 1:2", "At least 3 parts expected in '1:2'"},
	{"x.example. 60 IN AAAA 1:2:3:4:5:6:7:8:9:1:2:3", "At most 8 colons permitted in '1:2:3:4:5:6:7:8:9:1:2:3'"},
	{"x.example. 60 IN AAAA ::1:2:3:4:5:6:7:8", "At most 8 colons permitted in '::1:2:3:4:5:6:7:8'"},
	{"x.example. 60 IN A", "expected 'name ttl IN type rdata': 'x.example. 60 IN A'"},
	{"x.example. 60 CH A 10.0.0.1", "unsupported class 'CH'"},
	{"x.example. sixty IN A 10.0.0.1", "bad ttl 'sixty'"},
	{"x.example. 4294967296 IN A 10.0.0.1", "bad ttl '4294967296'"},
	{"x.example. +60 IN A 10.0.0.1", "bad ttl '+60'"},
	{"x.example. 60 IN MX 10 mail.example.", "unsupported RR type 'MX'"},
	{"x.example. 60 IN TXT \"unterminated", "No closing quotation"},
	{"x.example. 60 IN SOA only.three. fields.here.", "SOA rdata is: mname rname serial refresh retry expire minimum"},
	{"x.example. 60 IN SOA a. b. 1 2 3 4 x", "invalid literal for int() with base 10: 'x'"},
	{"x.example. 60 IN SOA a. b. 1 2 3 4 -1", "SOA counter out of range"},
	{"x.example. 60 IN SOA a. b. 1 2 3 4 4294967296", "SOA counter out of range"},
	{"x.example. 60 IN SOA a. b. 1 2 3 4 1_", "invalid literal for int() with base 10: '1_'"},
	{"x.example. 60 IN SOA a. b. 1 2 x 4 -1", "invalid literal for int() with base 10: 'x'"},
	{"x.example. 60 IN SOA a. b. 1 2 3 4 _1", "invalid literal for int() with base 10: '_1'"},
	{"x.example. 60 IN SOA a. b. 1 2 3 4 1__0", "invalid literal for int() with base 10: '1__0'"},
	{"x.example. 60 IN SOA a. b. 1 2 3 4 +", "invalid literal for int() with base 10: '+'"},
	{"x.example. 60 IN SOA a. b. 1 2 3 4 0x10", "invalid literal for int() with base 10: '0x10'"},
	{"x.example. 60 IN SOA a. b. 1 2 3 4 99999999999999999999999", "SOA counter out of range"},
	{"x.example. 60 IN CNAME y.example. junk", "CNAME rdata is one target name"},
	{"x.example. 60 IN CNAME", "expected 'name ttl IN type rdata': 'x.example. 60 IN CNAME'"},
	{"bad..name. 60 IN A 1.2.3.4", "empty label in 'bad..name.'"},
	{"x\\ 60 IN A 1.2.3.4", "dangling escape in 'x\\\\'"},
	{"x\\9 60 IN A 1.2.3.4", "bad \\DDD escape in 'x\\\\9'"},
	{"x\\256 60 IN A 1.2.3.4", "bad \\DDD escape in 'x\\\\256'"},
	{"x\\\u0661 60 IN A 1.2.3.4", "bad \\DDD escape in 'x\\\\\u0661'"},
	{"x.example. 60 IN SOA a..b. c. 1 2 3 4 5", "empty label in 'a..b.'"},
	{"x.example. 60 IN TXT   ", "expected 'name ttl IN type rdata': 'x.example. 60 IN TXT   '"},
	{"x.example. 60 IN TXT \\", "No escaped character"},
	{"x.example. 60 IN A 1.2.3.4\u0085z", "Only decimal digits permitted in '4\\x85z' in '1.2.3.4\\x85z'"},
}

var rrFromTextOkCases = []struct {
	line, name string
	rtype      uint16
	ttl        uint32
	rdata      string
}{
	{"x. 60 IN A 1.2.3.4", "x.", 1, 60, "01020304"},
	{"x. 60 IN a 1.2.3.4  ", "x.", 1, 60, "01020304"},
	{"x. 60 in A  \u00091.2.3.4", "x.", 1, 60, "01020304"},
	{"x. 60 IN AAAA 2001:db8::1", "x.", 28, 60, "20010db8000000000000000000000001"},
	{"x. 60 IN AAAA ::ffff:1.2.3.4", "x.", 28, 60, "00000000000000000000ffff01020304"},
	{"x. 60 IN AAAA fe80::1%eth0", "x.", 28, 60, "fe800000000000000000000000000001"},
	{"x. 60 IN AAAA 1:2:3:4:5:6:7:8", "x.", 28, 60, "00010002000300040005000600070008"},
	{"x. 60 IN AAAA ::", "x.", 28, 60, "00000000000000000000000000000000"},
	{"x. 60 IN AAAA 1::", "x.", 28, 60, "00010000000000000000000000000000"},
	{"x. 60 IN AAAA 0001:0002:0003:0004:0005:0006:1.2.3.4", "x.", 28, 60, "00010002000300040005000601020304"},
	{"x. 60 IN AAAA ABCD::EF", "x.", 28, 60, "abcd00000000000000000000000000ef"},
	{"x. 60 IN AAAA 1:2:3:4:5:6:7::", "x.", 28, 60, "00010002000300040005000600070000"},
	{"x. 60 IN AAAA ::2:3:4:5:6:7:8", "x.", 28, 60, "00000002000300040005000600070008"},
	{"x. 60 IN AAAA 1:2:3:4:5:6:7:8%z", "x.", 28, 60, "00010002000300040005000600070008"},
	{"x. 60 IN TXT a b", "x.", 16, 60, "01610162"},
	{"x. 60 IN TXT 'a b' \"c d\" e\\ f", "x.", 16, 60, "036120620363206403652066"},
	{"x. 60 IN TXT \"a\\\"b\" \"a\\\\b\" \"a\\xb\"", "x.", 16, 60, "0361226203615c6204615c7862"},
	{"x. 60 IN TXT \"\"", "x.", 16, 60, "00"},
	{"x. 60 IN TXT \"\u00e9 \u00fc\"", "x.", 16, 60, "05c3a920c3bc"},
	{"x. 60 IN TXT a'b c'd", "x.", 16, 60, "056162206364"},
	{"x. 60 IN TXT \"a\" b", "x.", 16, 60, "01610162"},
	{"x. 4294967295 IN A 1.2.3.4", "x.", 1, 4294967295, "01020304"},
	{"x. 0007 IN A 1.2.3.4", "x.", 1, 7, "01020304"},
	{"x. 60 IN SOA a. b. +1 1_0 003 4 -0", "x.", 6, 60, "016100016200000000010000000a000000030000000400000000"},
	{"x. 60 IN SOA a. b. 4294967295 0 0 0 0", "x.", 6, 60, "016100016200ffffffff00000000000000000000000000000000"},
	{"a\\.b\\046c. 60 IN CNAME \\255\\001.", "a\\.b\\046c.", 5, 60, "02ff0100"},
	{"x. 60 IN CNAME \u00e9.", "x.", 5, 60, "02c3a900"},
	{"a\\\\b. 60 IN A 1.2.3.4", "a\\\\b.", 1, 60, "01020304"},
	{"A.B. 60 IN A 1.2.3.4", "A.B.", 1, 60, "01020304"},
}

var nameToLabelsCases = []struct{ in, labels, err string }{
	{".", "", ""},
	{"", "", "empty name"},
	{"a.b", "61,62", ""},
	{"a.b.", "61,62", ""},
	{"a\\.b.c", "612e62,63", ""},
	{"a\\\\b.", "615c62", ""},
	{"\\046.", "2e", ""},
	{"\\000a.", "0061", ""},
	{"a\\", "", "dangling escape in 'a\\\\'"},
	{"a\\1", "", "bad \\DDD escape in 'a\\\\1'"},
	{"a\\12", "", "bad \\DDD escape in 'a\\\\12'"},
	{"a\\256", "", "bad \\DDD escape in 'a\\\\256'"},
	{"a\\12x", "", "bad \\DDD escape in 'a\\\\12x'"},
	{"\\x.", "78", ""},
	{"a..b", "", "empty label in 'a..b'"},
	{".a", "", "empty label in '.a'"},
	{"..", "", "empty label in '..'"},
	{"\u00e9.\u00e9.", "c3a9,c3a9", ""},
	{"a\\\u0661", "", "bad \\DDD escape in 'a\\\\\u0661'"},
	{"\\", "", "dangling escape in '\\\\'"},
	{"x\\0", "", "bad \\DDD escape in 'x\\\\0'"},
	{"a\\255", "61ff", ""},
	{"\\2556.", "ff36", ""},
	{"a.\\", "", "dangling escape in 'a.\\\\'"},
	{"\u2603.", "e29883", ""},
	{"a b.", "612062", ""},
}

var splitCases = []struct {
	in   string
	want []string
}{
	{"a b c d e", []string{"a", "b", "c", "d", "e"}},
	{"a b c d e  f  ", []string{"a", "b", "c", "d", "e  f  "}},
	{"  a  b  ", []string{"a", "b"}},
	{"a b c d   ", []string{"a", "b", "c", "d"}},
	{"a b c d  e f g ", []string{"a", "b", "c", "d", "e f g "}},
	{"a\u001cb c d e f", []string{"a", "b", "c", "d", "e f"}},
	{"a\u00a0b c d e f", []string{"a", "b", "c", "d", "e f"}},
	{"", []string{}},
	{"   ", []string{}},
	{"a", []string{"a"}},
	{"a b c d e\u0009f\u000a", []string{"a", "b", "c", "d", "e\u0009f\u000a"}},
}

var typeNameCases = []struct {
	rtype uint16
	want  string
}{
	{1, "A"},
	{2, "NS"},
	{5, "CNAME"},
	{6, "SOA"},
	{12, "PTR"},
	{15, "MX"},
	{16, "TXT"},
	{24, "SIG"},
	{28, "AAAA"},
	{33, "SRV"},
	{39, "DNAME"},
	{41, "OPT"},
	{43, "DS"},
	{46, "RRSIG"},
	{47, "NSEC"},
	{48, "DNSKEY"},
	{50, "NSEC3"},
	{51, "NSEC3PARAM"},
	{64, "SVCB"},
	{65, "HTTPS"},
	{255, "ANY"},
	{0, "TYPE0"},
	{99, "TYPE99"},
	{65535, "TYPE65535"},
}

func TestShlexSplitMatchesPython(t *testing.T) {
	for _, c := range shlexCases {
		got, err := shlexSplit(c.in)
		if c.err != "" {
			if err == nil || err.Error() != c.err {
				t.Errorf("shlexSplit(%q): err = %v, want %q", c.in, err, c.err)
			}
			continue
		}
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("shlexSplit(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

func TestPyReprMatchesPython(t *testing.T) {
	for _, c := range reprCases {
		if got := pyRepr(c.in); got != c.want {
			t.Errorf("pyRepr(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestSplitWhitespaceMatchesPython(t *testing.T) {
	for _, c := range splitCases {
		if got := splitWhitespace(c.in, 4); !slices.Equal(got, c.want) {
			t.Errorf("splitWhitespace(%q, 4) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRRFromTextErrorTextMatchesPython(t *testing.T) {
	for _, c := range rrFromTextErrCases {
		got, err := RRFromText(c.line)
		if err == nil || err.Error() != c.want {
			t.Errorf("RRFromText(%q) = %+v, %v; want error %q", c.line, got, err, c.want)
		}
	}
}

func TestRRFromTextRdataMatchesPython(t *testing.T) {
	for _, c := range rrFromTextOkCases {
		got, err := RRFromText(c.line)
		if err != nil {
			t.Errorf("RRFromText(%q): %v", c.line, err)
			continue
		}
		if hexRdata := hex.EncodeToString(got.Rdata); got.Name != c.name || got.Rtype != c.rtype || got.Rclass != CLASS_IN || got.TTL != c.ttl || hexRdata != c.rdata {
			t.Errorf("RRFromText(%q) = (%q, %d, %d, %d, %s), want (%q, %d, %d, %d, %s)",
				c.line, got.Name, got.Rtype, got.Rclass, got.TTL, hexRdata, c.name, c.rtype, CLASS_IN, c.ttl, c.rdata)
		}
	}
}

func TestRRFromTextAcceptsATxtStringOf255Octets(t *testing.T) {
	got := mustRR(t, `x. 60 IN TXT "`+strings.Repeat("a", 255)+`"`)
	wantBytes(t, got.Rdata, append([]byte{255}, bytes.Repeat([]byte("a"), 255)...))
}

func TestNameToLabelsMatchesPython(t *testing.T) {
	for _, c := range nameToLabelsCases {
		labels, err := NameToLabels(c.in)
		if c.err != "" {
			if err == nil || err.Error() != c.err {
				t.Errorf("NameToLabels(%q): err = %v, want %q", c.in, err, c.err)
			}
			continue
		}
		var hexLabels []string
		for _, label := range labels {
			hexLabels = append(hexLabels, hex.EncodeToString(label))
		}
		if got := strings.Join(hexLabels, ","); err != nil || got != c.labels {
			t.Errorf("NameToLabels(%q) = %q, %v; want %q", c.in, got, err, c.labels)
		}
	}
}

func TestNameToLabelsLabelLengthMessage(t *testing.T) {
	name := strings.Repeat("a", 64) + "."
	_, err := NameToLabels(name)
	wantError(t, err, "label longer than 63 octets in '"+name+"'")
	labels, err := NameToLabels(strings.Repeat("a", 63) + ".")
	if err != nil || len(labels) != 1 || len(labels[0]) != 63 {
		t.Fatalf("63-octet label: %q, %v", labels, err)
	}
}

func TestEncodeNameAcceptsAName255OctetsLongOnTheWire(t *testing.T) {
	got, err := EncodeName(strings.Repeat("a.", 127))
	if err != nil {
		t.Fatal(err)
	}
	wantBytes(t, got, append(bytes.Repeat([]byte("\x01a"), 127), 0))
	if len(got) != 255 {
		t.Fatalf("wire length = %d, want 255", len(got))
	}
}

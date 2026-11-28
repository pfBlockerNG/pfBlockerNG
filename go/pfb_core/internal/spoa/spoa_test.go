package spoa

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestVarintRoundTripAndHostile(t *testing.T) {
	values := []uint64{0, 1, 239, 240, 241, 255, 256, 2287, 2288, 2289, 4336, 65535, 1 << 20, 1 << 32, math.MaxUint64}
	for _, want := range values {
		enc := EncodeVarint(nil, want)
		got, n, err := DecodeVarint(enc)
		if err != nil {
			t.Fatalf("DecodeVarint(%d) error: %v", want, err)
		}
		if got != want || n != len(enc) {
			t.Fatalf("varint %d: got (%d, %d), want (%d, %d)", want, got, n, want, len(enc))
		}
	}
	// Truncated varint
	if _, _, err := DecodeVarint([]byte{240}); !errors.Is(err, ErrTruncated) {
		t.Fatalf("truncated varint err = %v, want ErrTruncated", err)
	}
	// Overflow varint (10 continuation bytes)
	if _, _, err := DecodeVarint([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}); !errors.Is(err, ErrVarint) {
		t.Fatalf("overflow varint err = %v, want ErrVarint", err)
	}
}

func TestValueRoundTripAndParseIP(t *testing.T) {
	vals := []Value{
		NullValue(),
		BoolValue(false),
		BoolValue(true),
		{Type: DataTypeInt32, Int: -42},
		Uint32Value(16384),
		Int64Value(-123456789),
		{Type: DataTypeUint64, Uint: 1 << 40},
		IPValue(netip.MustParseAddr("198.51.100.1")),
		IPValue(netip.MustParseAddr("2001:db8::1")),
		StringValue("hello"),
		BinaryValue([]byte{0xde, 0xad, 0xbe, 0xef}),
	}
	for _, want := range vals {
		enc, err := EncodeValue(nil, want)
		if err != nil {
			t.Fatalf("EncodeValue(%+v): %v", want, err)
		}
		got, n, err := DecodeValue(enc)
		if err != nil {
			t.Fatalf("DecodeValue(%+v): %v", want, err)
		}
		if n != len(enc) || got.Type != want.Type {
			t.Fatalf("DecodeValue mismatch: got (%+v, %d), want (%+v, %d)", got, n, want, len(enc))
		}
		if want.Type == DataTypeBinary && !bytes.Equal(got.Bytes, want.Bytes) {
			t.Fatalf("binary mismatch: got %x, want %x", got.Bytes, want.Bytes)
		}
	}
	if addr, ok := StringValue(" 203.0.113.5 ").ParseIP(); !ok || addr.String() != "203.0.113.5" {
		t.Fatalf("ParseIP string = (%v, %v)", addr, ok)
	}
	if _, ok := StringValue("fe80::1%em0").ParseIP(); ok {
		t.Fatal("zoned IP must be rejected")
	}
}

func TestParseListen(t *testing.T) {
	okCases := []struct {
		spec, net, addr string
	}{
		{"127.0.0.1:10090", "tcp", "127.0.0.1:10090"},
		{"[::1]:10091", "tcp", "[::1]:10091"},
		{"unix:/var/run/pfb_core/spoa.sock", "unix", "/var/run/pfb_core/spoa.sock"},
	}
	for _, tc := range okCases {
		n, a, err := ParseListen(tc.spec)
		if err != nil || n != tc.net || a != tc.addr {
			t.Fatalf("ParseListen(%q) = (%q, %q, %v), want (%q, %q, nil)", tc.spec, n, a, err, tc.net, tc.addr)
		}
	}
	badCases := []string{
		"",
		"0.0.0.0:10090",
		"192.168.1.1:10090",
		"[::]:10090",
		"unix:relative.sock",
		"unix:/var/run/../spoa.sock",
		"127.0.0.1:99999",
	}
	for _, spec := range badCases {
		if _, _, err := ParseListen(spec); err == nil {
			t.Errorf("ParseListen(%q) succeeded, want error", spec)
		}
	}
}

func encodeNotifyPayload(name string, args []KV) []byte {
	var out []byte
	out = EncodeString(out, name)
	out = append(out, byte(len(args)))
	for _, a := range args {
		out = EncodeString(out, a.Key)
		var err error
		out, err = EncodeValue(out, a.Value)
		if err != nil {
			panic(err)
		}
	}
	return out
}

func decodeActionsForTest(t *testing.T, payload []byte) []Action {
	t.Helper()
	var out []Action
	for off := 0; off < len(payload); {
		typ := payload[off]
		nbArgs := payload[off+1]
		scope := payload[off+2]
		off += 3
		name, n, err := DecodeString(payload[off:])
		if err != nil {
			t.Fatalf("DecodeString action name: %v", err)
		}
		off += n
		var val Value
		if typ == ActionSetVar {
			if nbArgs != 3 {
				t.Fatalf("SET-VAR nbArgs = %d, want 3", nbArgs)
			}
			var m int
			val, m, err = DecodeValue(payload[off:])
			if err != nil {
				t.Fatalf("DecodeValue action val: %v", err)
			}
			off += m
		}
		out = append(out, Action{Type: typ, Scope: scope, Name: name, Value: val})
	}
	return out
}

func runEndToEndSuite(t *testing.T, listenSpec string) {
	t.Helper()
	srv, err := Listen(ServerConfig{
		Listen: listenSpec,
		Handler: func(_ context.Context, msgs []Message) ([]Action, bool, error) {
			for _, m := range msgs {
				if m.Name == "panic-msg" {
					panic("boom")
				}
				v, ok := m.Arg("src-ip")
				if !ok {
					continue
				}
				ip, ok := v.ParseIP()
				if !ok {
					continue
				}
				if ip == netip.MustParseAddr("198.51.100.99") {
					return []Action{
						SetTxnVar("blocked", BoolValue(true)),
						SetTxnVar("alias", StringValue("pfB_Test_v4")),
					}, true, nil
				}
			}
			return []Action{SetTxnVar("blocked", BoolValue(false))}, false, nil
		},
	})
	if err != nil {
		t.Fatalf("Listen(%q): %v", listenSpec, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve returned: %v", err)
		}
	})

	dial := func() net.Conn {
		t.Helper()
		network := "tcp"
		addr := srv.Addr()
		if len(listenSpec) > 5 && listenSpec[:5] == "unix:" {
			network = "unix"
		}
		c, err := net.DialTimeout(network, addr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial %s %s: %v", network, addr, err)
		}
		return c
	}

	// 1. Healthcheck connection: AGENT-HELLO then immediate close.
	hc := dial()
	hcPayload, _ := EncodeKVList([]KV{
		{Key: "supported-versions", Value: StringValue("2.0")},
		{Key: "max-frame-size", Value: Uint32Value(16384)},
		{Key: "capabilities", Value: StringValue("pipelining,fragmentation")},
		{Key: "healthcheck", Value: BoolValue(true)},
	})
	if err := WriteFrame(hc, Frame{Type: FrameTypeHaproxyHello, Flags: FrameFlagFin, Payload: hcPayload}); err != nil {
		t.Fatalf("write healthcheck hello: %v", err)
	}
	f, err := ReadFrame(hc, 16384)
	if err != nil || f.Type != FrameTypeAgentHello {
		t.Fatalf("healthcheck reply = (%+v, %v), want AGENT-HELLO", f, err)
	}
	hc.Close()

	// 2. Normal pipelined + fragmented + panic-recovery session.
	conn := dial()
	defer conn.Close()
	helloPayload, _ := EncodeKVList([]KV{
		{Key: "supported-versions", Value: StringValue("1.0,2.0")},
		{Key: "max-frame-size", Value: Uint32Value(4096)},
		{Key: "capabilities", Value: StringValue("pipelining,fragmentation")},
	})
	if err := WriteFrame(conn, Frame{Type: FrameTypeHaproxyHello, Flags: FrameFlagFin, Payload: helloPayload}); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	helloResp, err := ReadFrame(conn, 4096)
	if err != nil || helloResp.Type != FrameTypeAgentHello {
		t.Fatalf("hello resp = (%+v, %v)", helloResp, err)
	}

	// Pipeline two NOTIFY frames (one blocked, one clean).
	n1 := encodeNotifyPayload("pfb-check", []KV{{Key: "src-ip", Value: IPValue(netip.MustParseAddr("198.51.100.99"))}})
	n2 := encodeNotifyPayload("pfb-check", []KV{{Key: "src-ip", Value: IPValue(netip.MustParseAddr("203.0.113.1"))}})
	if err := WriteFrame(conn, Frame{Type: FrameTypeNotify, Flags: FrameFlagFin, StreamID: 1, FrameID: 1, Payload: n1}); err != nil {
		t.Fatalf("write n1: %v", err)
	}
	if err := WriteFrame(conn, Frame{Type: FrameTypeNotify, Flags: FrameFlagFin, StreamID: 2, FrameID: 1, Payload: n2}); err != nil {
		t.Fatalf("write n2: %v", err)
	}

	ack1, err := ReadFrame(conn, 4096)
	if err != nil || ack1.Type != FrameTypeAck || ack1.StreamID != 1 {
		t.Fatalf("ack1 = (%+v, %v)", ack1, err)
	}
	acts1 := decodeActionsForTest(t, ack1.Payload)
	if len(acts1) != 2 || acts1[0].Name != "blocked" || !acts1[0].Value.Bool || acts1[1].Name != "alias" || acts1[1].Value.String != "pfB_Test_v4" {
		t.Fatalf("ack1 actions = %+v", acts1)
	}

	ack2, err := ReadFrame(conn, 4096)
	if err != nil || ack2.Type != FrameTypeAck || ack2.StreamID != 2 {
		t.Fatalf("ack2 = (%+v, %v)", ack2, err)
	}
	acts2 := decodeActionsForTest(t, ack2.Payload)
	if len(acts2) != 1 || acts2[0].Name != "blocked" || acts2[0].Value.Bool {
		t.Fatalf("ack2 actions = %+v", acts2)
	}

	// Fragmented NOTIFY frame (split across two frames).
	split := len(n1) / 2
	if err := WriteFrame(conn, Frame{Type: FrameTypeNotify, Flags: 0, StreamID: 3, FrameID: 1, Payload: n1[:split]}); err != nil {
		t.Fatalf("write frag1: %v", err)
	}
	if err := WriteFrame(conn, Frame{Type: FrameTypeUnset, Flags: FrameFlagFin, StreamID: 3, FrameID: 1, Payload: n1[split:]}); err != nil {
		t.Fatalf("write frag2: %v", err)
	}
	ack3, err := ReadFrame(conn, 4096)
	if err != nil || ack3.Type != FrameTypeAck || ack3.StreamID != 3 {
		t.Fatalf("ack3 = (%+v, %v)", ack3, err)
	}
	acts3 := decodeActionsForTest(t, ack3.Payload)
	if len(acts3) != 2 || !acts3[0].Value.Bool {
		t.Fatalf("ack3 actions = %+v", acts3)
	}

	// Panic recovery in handler still returns empty ACK and increments errors.
	nPanic := encodeNotifyPayload("panic-msg", nil)
	if err := WriteFrame(conn, Frame{Type: FrameTypeNotify, Flags: FrameFlagFin, StreamID: 4, FrameID: 1, Payload: nPanic}); err != nil {
		t.Fatalf("write panic notify: %v", err)
	}
	ack4, err := ReadFrame(conn, 4096)
	if err != nil || ack4.Type != FrameTypeAck || ack4.StreamID != 4 || len(ack4.Payload) != 0 {
		t.Fatalf("ack4 = (%+v, %v), want empty ACK", ack4, err)
	}

	// Graceful HAPROXY-DISCONNECT -> AGENT-DISCONNECT.
	discPayload, _ := EncodeKVList([]KV{{Key: "status-code", Value: Uint32Value(0)}, {Key: "message", Value: StringValue("bye")}})
	if err := WriteFrame(conn, Frame{Type: FrameTypeHaproxyDisconn, Flags: FrameFlagFin, Payload: discPayload}); err != nil {
		t.Fatalf("write disconnect: %v", err)
	}
	discResp, err := ReadFrame(conn, 4096)
	if err != nil || discResp.Type != FrameTypeAgentDisconnect {
		t.Fatalf("disconnect resp = (%+v, %v), want AGENT-DISCONNECT", discResp, err)
	}

	m := srv.Metrics()
	if m.Lookups != 4 || m.Blocked != 2 || m.Errors != 1 {
		t.Fatalf("Metrics() = %+v, want Lookups=4 Blocked=2 Errors=1", m)
	}
}

func TestServerLoopbackTCP(t *testing.T) {
	runEndToEndSuite(t, "127.0.0.1:0")
}

func TestServerUnixSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "spoa.sock")
	runEndToEndSuite(t, "unix:"+sock)
}

func TestServerRejectsUnsupportedVersionAndOversizedFrame(t *testing.T) {
	srv, err := Listen(ServerConfig{
		Listen:       "127.0.0.1:0",
		MaxFrameSize: 512,
		Handler:      func(_ context.Context, _ []Message) ([]Action, bool, error) { return nil, false, nil },
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	defer func() { cancel(); <-done }()

	// Unsupported version -> AGENT-DISCONNECT
	c1, err := net.DialTimeout("tcp", srv.Addr(), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	badHello, _ := EncodeKVList([]KV{
		{Key: "supported-versions", Value: StringValue("1.0")},
		{Key: "max-frame-size", Value: Uint32Value(512)},
		{Key: "capabilities", Value: StringValue("")},
	})
	_ = WriteFrame(c1, Frame{Type: FrameTypeHaproxyHello, Flags: FrameFlagFin, Payload: badHello})
	resp, err := ReadFrame(c1, 512)
	c1.Close()
	if err != nil || resp.Type != FrameTypeAgentDisconnect {
		t.Fatalf("bad version resp = (%+v, %v), want AGENT-DISCONNECT", resp, err)
	}

	// Oversized frame length prefix -> closed cleanly
	c2, err := net.DialTimeout("tcp", srv.Addr(), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 999999)
	_, _ = c2.Write(hdr[:])
	_ = c2.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 16)
	_, rerr := c2.Read(buf)
	c2.Close()
	if rerr == nil {
		t.Fatal("expected read error / EOF after oversized frame")
	}
}

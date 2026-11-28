// Package spoa implements a stdlib-only HAProxy SPOP v2.0 server and an immutable IPv4/IPv6 radix tree.
//
// Wire specification: HAProxy SPOE documentation (doc/SPOE.txt, SPOP version 2.0).
package spoa

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
)

// SPOP v2.0 frame types.
const (
	FrameTypeUnset           byte = 0
	FrameTypeHaproxyHello    byte = 1
	FrameTypeHaproxyDisconn  byte = 2
	FrameTypeNotify          byte = 3
	FrameTypeAgentHello      byte = 101
	FrameTypeAgentDisconnect byte = 102
	FrameTypeAck             byte = 103
)

// SPOP frame flags.
const (
	FrameFlagFin   uint32 = 0x00000001
	FrameFlagAbort uint32 = 0x00000002
)

// SPOP typed data kinds (low 4 bits of the type byte).
const (
	DataTypeNull   byte = 0
	DataTypeBool   byte = 1
	DataTypeInt32  byte = 2
	DataTypeUint32 byte = 3
	DataTypeInt64  byte = 4
	DataTypeUint64 byte = 5
	DataTypeIPv4   byte = 6
	DataTypeIPv6   byte = 7
	DataTypeString byte = 8
	DataTypeBinary byte = 9

	dataTypeMask byte = 0x0f
	dataFlagTrue byte = 0x10
)

// SPOP action types and variable scopes.
const (
	ActionSetVar   byte = 1
	ActionUnsetVar byte = 2

	ScopeProcess     byte = 0
	ScopeSession     byte = 1
	ScopeTransaction byte = 2
	ScopeRequest     byte = 3
	ScopeResponse    byte = 4
)

// SPOP status codes for AGENT-DISCONNECT.
const (
	StatusNormal           uint32 = 0
	StatusIOError          uint32 = 1
	StatusTimeout          uint32 = 2
	StatusFrameTooBig      uint32 = 3
	StatusInvalidFrame     uint32 = 4
	StatusNoVersion        uint32 = 5
	StatusNoMaxFrameSize   uint32 = 6
	StatusNoCapabilities   uint32 = 7
	StatusUnsupportedVer   uint32 = 8
	StatusMaxFrameTooSmall uint32 = 9
	StatusMaxFrameTooBig   uint32 = 10
	StatusBadFragmentation uint32 = 11
	StatusUnknownError     uint32 = 99
)

const (
	ProtocolVersion    = "2.0"
	MinMaxFrameSize    = 256
	DefaultMaxFrame    = 16384
	HardMaxFrameCap    = 1 << 20 // 1 MiB absolute safety cap on inbound frames
	maxVarintBytes     = 10
	maxArgsPerMessage  = 255
	maxMessagesPerList = 256
)

var (
	ErrFrameTooLarge = errors.New("spoa: frame exceeds max-frame-size")
	ErrFrameTooSmall = errors.New("spoa: frame too short")
	ErrTruncated     = errors.New("spoa: truncated data")
	ErrVarint        = errors.New("spoa: invalid varint")
	ErrUnknownType   = errors.New("spoa: unknown typed data kind")
)

// Frame is one SPOP wire frame (after the 4-byte length prefix).
type Frame struct {
	Type     byte
	Flags    uint32
	StreamID uint64
	FrameID  uint64
	Payload  []byte
}

// Value is a SPOP typed value.
type Value struct {
	Type   byte
	Bool   bool
	Int    int64
	Uint   uint64
	Addr   netip.Addr
	String string
	Bytes  []byte
}

func NullValue() Value           { return Value{Type: DataTypeNull} }
func BoolValue(v bool) Value     { return Value{Type: DataTypeBool, Bool: v} }
func Uint32Value(v uint32) Value { return Value{Type: DataTypeUint32, Uint: uint64(v)} }
func Int64Value(v int64) Value   { return Value{Type: DataTypeInt64, Int: v} }
func StringValue(v string) Value { return Value{Type: DataTypeString, String: v} }
func BinaryValue(v []byte) Value { return Value{Type: DataTypeBinary, Bytes: v} }
func IPValue(addr netip.Addr) Value {
	addr = addr.Unmap()
	if addr.Is4() {
		return Value{Type: DataTypeIPv4, Addr: addr}
	}
	return Value{Type: DataTypeIPv6, Addr: addr}
}

// ParseIP extracts a netip.Addr from an IPv4, IPv6, or String/Binary SPOP value.
func (v Value) ParseIP() (netip.Addr, bool) {
	switch v.Type {
	case DataTypeIPv4, DataTypeIPv6:
		if !v.Addr.IsValid() {
			return netip.Addr{}, false
		}
		return v.Addr.Unmap(), true
	case DataTypeString:
		addr, err := netip.ParseAddr(strings.TrimSpace(v.String))
		if err != nil || addr.Zone() != "" {
			return netip.Addr{}, false
		}
		return addr.Unmap(), true
	case DataTypeBinary:
		addr, err := netip.ParseAddr(strings.TrimSpace(string(v.Bytes)))
		if err != nil || addr.Zone() != "" {
			return netip.Addr{}, false
		}
		return addr.Unmap(), true
	default:
		return netip.Addr{}, false
	}
}

// AsString returns the string representation of a String or Binary value.
func (v Value) AsString() (string, bool) {
	switch v.Type {
	case DataTypeString:
		return v.String, true
	case DataTypeBinary:
		return string(v.Bytes), true
	default:
		return "", false
	}
}

// KV is one key-value pair in a HELLO or DISCONNECT payload.
type KV struct {
	Key   string
	Value Value
}

// Message is one SPOE message inside a NOTIFY frame.
type Message struct {
	Name string
	Args []KV
}

// Arg returns the first argument with the given name.
func (m Message) Arg(name string) (Value, bool) {
	for _, a := range m.Args {
		if a.Key == name {
			return a.Value, true
		}
	}
	return Value{}, false
}

// Action is one SPOE action inside an ACK frame.
type Action struct {
	Type  byte // ActionSetVar or ActionUnsetVar
	Scope byte
	Name  string
	Value Value
}

// SetTxnVar builds a SET-VAR action in Transaction scope.
func SetTxnVar(name string, val Value) Action {
	return Action{Type: ActionSetVar, Scope: ScopeTransaction, Name: name, Value: val}
}

// EncodeVarint appends an SPOP variable-length integer to dst.
func EncodeVarint(dst []byte, v uint64) []byte {
	if v < 240 {
		return append(dst, byte(v))
	}
	dst = append(dst, byte(240+(v&0x0f)))
	v = (v - 240) >> 4
	for v >= 128 {
		dst = append(dst, byte(128+(v&0x7f)))
		v = (v - 128) >> 7
	}
	return append(dst, byte(v))
}

// DecodeVarint reads an SPOP variable-length integer from src.
func DecodeVarint(src []byte) (uint64, int, error) {
	if len(src) == 0 {
		return 0, 0, ErrTruncated
	}
	b := src[0]
	if b < 240 {
		return uint64(b), 1, nil
	}
	val := uint64(b)
	shift := uint(4)
	for i := 1; i < len(src) && i < maxVarintBytes; i++ {
		c := src[i]
		if shift >= 64 {
			return 0, 0, ErrVarint
		}
		add := uint64(c) << shift
		if add>>shift != uint64(c) || val+add < val {
			return 0, 0, ErrVarint
		}
		val += add
		if c < 128 {
			return val, i + 1, nil
		}
		shift += 7
	}
	if len(src) < maxVarintBytes {
		return 0, 0, ErrTruncated
	}
	return 0, 0, ErrVarint
}

// EncodeString appends a varint-length-prefixed string to dst.
func EncodeString(dst []byte, s string) []byte {
	dst = EncodeVarint(dst, uint64(len(s)))
	return append(dst, s...)
}

// DecodeString reads a varint-length-prefixed string from src.
func DecodeString(src []byte) (string, int, error) {
	n, off, err := DecodeVarint(src)
	if err != nil {
		return "", 0, err
	}
	if n > uint64(len(src)-off) {
		return "", 0, ErrTruncated
	}
	end := off + int(n)
	return string(src[off:end]), end, nil
}

// EncodeValue appends a SPOP typed value to dst.
func EncodeValue(dst []byte, v Value) ([]byte, error) {
	switch v.Type {
	case DataTypeNull:
		return append(dst, DataTypeNull), nil
	case DataTypeBool:
		b := DataTypeBool
		if v.Bool {
			b |= dataFlagTrue
		}
		return append(dst, b), nil
	case DataTypeInt32:
		dst = append(dst, DataTypeInt32)
		return EncodeVarint(dst, uint64(uint32(v.Int))), nil
	case DataTypeUint32:
		dst = append(dst, DataTypeUint32)
		return EncodeVarint(dst, uint64(uint32(v.Uint))), nil
	case DataTypeInt64:
		dst = append(dst, DataTypeInt64)
		return EncodeVarint(dst, uint64(v.Int)), nil
	case DataTypeUint64:
		dst = append(dst, DataTypeUint64)
		return EncodeVarint(dst, v.Uint), nil
	case DataTypeIPv4:
		a := v.Addr.Unmap()
		if !a.Is4() {
			return nil, errors.New("spoa: expected IPv4 address")
		}
		b4 := a.As4()
		dst = append(dst, DataTypeIPv4)
		return append(dst, b4[:]...), nil
	case DataTypeIPv6:
		a := v.Addr
		if !a.IsValid() {
			return nil, errors.New("spoa: expected IPv6 address")
		}
		b16 := a.As16()
		dst = append(dst, DataTypeIPv6)
		return append(dst, b16[:]...), nil
	case DataTypeString:
		dst = append(dst, DataTypeString)
		return EncodeString(dst, v.String), nil
	case DataTypeBinary:
		dst = append(dst, DataTypeBinary)
		dst = EncodeVarint(dst, uint64(len(v.Bytes)))
		return append(dst, v.Bytes...), nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownType, v.Type)
	}
}

// DecodeValue reads one SPOP typed value from src.
func DecodeValue(src []byte) (Value, int, error) {
	if len(src) == 0 {
		return Value{}, 0, ErrTruncated
	}
	tb := src[0]
	kind := tb & dataTypeMask
	off := 1
	switch kind {
	case DataTypeNull:
		return Value{Type: DataTypeNull}, off, nil
	case DataTypeBool:
		return Value{Type: DataTypeBool, Bool: tb&dataFlagTrue != 0}, off, nil
	case DataTypeInt32:
		v, n, err := DecodeVarint(src[off:])
		if err != nil {
			return Value{}, 0, err
		}
		return Value{Type: DataTypeInt32, Int: int64(int32(v))}, off + n, nil
	case DataTypeUint32:
		v, n, err := DecodeVarint(src[off:])
		if err != nil {
			return Value{}, 0, err
		}
		return Value{Type: DataTypeUint32, Uint: uint64(uint32(v))}, off + n, nil
	case DataTypeInt64:
		v, n, err := DecodeVarint(src[off:])
		if err != nil {
			return Value{}, 0, err
		}
		return Value{Type: DataTypeInt64, Int: int64(v)}, off + n, nil
	case DataTypeUint64:
		v, n, err := DecodeVarint(src[off:])
		if err != nil {
			return Value{}, 0, err
		}
		return Value{Type: DataTypeUint64, Uint: v}, off + n, nil
	case DataTypeIPv4:
		if len(src)-off < 4 {
			return Value{}, 0, ErrTruncated
		}
		var b4 [4]byte
		copy(b4[:], src[off:off+4])
		return Value{Type: DataTypeIPv4, Addr: netip.AddrFrom4(b4)}, off + 4, nil
	case DataTypeIPv6:
		if len(src)-off < 16 {
			return Value{}, 0, ErrTruncated
		}
		var b16 [16]byte
		copy(b16[:], src[off:off+16])
		return Value{Type: DataTypeIPv6, Addr: netip.AddrFrom16(b16).Unmap()}, off + 16, nil
	case DataTypeString:
		s, n, err := DecodeString(src[off:])
		if err != nil {
			return Value{}, 0, err
		}
		return Value{Type: DataTypeString, String: s}, off + n, nil
	case DataTypeBinary:
		l, n, err := DecodeVarint(src[off:])
		if err != nil {
			return Value{}, 0, err
		}
		off += n
		if l > uint64(len(src)-off) {
			return Value{}, 0, ErrTruncated
		}
		cp := make([]byte, int(l))
		copy(cp, src[off:off+int(l)])
		return Value{Type: DataTypeBinary, Bytes: cp}, off + int(l), nil
	default:
		return Value{}, 0, fmt.Errorf("%w: %d", ErrUnknownType, kind)
	}
}

// EncodeKVList encodes key-value pairs into a payload slice.
func EncodeKVList(kvs []KV) ([]byte, error) {
	var out []byte
	for _, kv := range kvs {
		out = EncodeString(out, kv.Key)
		var err error
		out, err = EncodeValue(out, kv.Value)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// DecodeKVList decodes key-value pairs until the end of payload.
func DecodeKVList(payload []byte) ([]KV, error) {
	var out []KV
	for off := 0; off < len(payload); {
		k, n, err := DecodeString(payload[off:])
		if err != nil {
			return nil, err
		}
		off += n
		v, m, err := DecodeValue(payload[off:])
		if err != nil {
			return nil, err
		}
		off += m
		out = append(out, KV{Key: k, Value: v})
	}
	return out, nil
}

// DecodeMessages decodes a NOTIFY payload's LIST-OF-MESSAGES.
func DecodeMessages(payload []byte) ([]Message, error) {
	var msgs []Message
	for off := 0; off < len(payload); {
		if len(msgs) >= maxMessagesPerList {
			return nil, errors.New("spoa: too many messages in NOTIFY frame")
		}
		name, n, err := DecodeString(payload[off:])
		if err != nil {
			return nil, err
		}
		off += n
		if off >= len(payload) {
			return nil, ErrTruncated
		}
		nbArgs := int(payload[off])
		off++
		args := make([]KV, 0, nbArgs)
		for range nbArgs {
			ak, an, err := DecodeString(payload[off:])
			if err != nil {
				return nil, err
			}
			off += an
			av, vn, err := DecodeValue(payload[off:])
			if err != nil {
				return nil, err
			}
			off += vn
			args = append(args, KV{Key: ak, Value: av})
		}
		msgs = append(msgs, Message{Name: name, Args: args})
	}
	return msgs, nil
}

// EncodeActions encodes a list of ACK actions.
func EncodeActions(actions []Action) ([]byte, error) {
	var out []byte
	for _, a := range actions {
		switch a.Type {
		case ActionSetVar:
			out = append(out, ActionSetVar, 3, a.Scope)
			out = EncodeString(out, a.Name)
			var err error
			out, err = EncodeValue(out, a.Value)
			if err != nil {
				return nil, err
			}
		case ActionUnsetVar:
			out = append(out, ActionUnsetVar, 2, a.Scope)
			out = EncodeString(out, a.Name)
		default:
			return nil, fmt.Errorf("spoa: unknown action type %d", a.Type)
		}
	}
	return out, nil
}

// ReadFrame reads one length-prefixed SPOP frame from r, enforcing maxFrameSize.
func ReadFrame(r io.Reader, maxFrameSize uint32) (Frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrameSize || n > HardMaxFrameCap {
		return Frame{}, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, n, maxFrameSize)
	}
	if n < 7 { // 1 type + 4 flags + >=1 stream-id + >=1 frame-id
		return Frame{}, ErrFrameTooSmall
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Frame{}, err
	}
	f := Frame{
		Type:  buf[0],
		Flags: binary.BigEndian.Uint32(buf[1:5]),
	}
	off := 5
	sid, sn, err := DecodeVarint(buf[off:])
	if err != nil {
		return Frame{}, err
	}
	off += sn
	fid, fn, err := DecodeVarint(buf[off:])
	if err != nil {
		return Frame{}, err
	}
	off += fn
	f.StreamID = sid
	f.FrameID = fid
	f.Payload = buf[off:]
	return f, nil
}

// WriteFrame writes one length-prefixed SPOP frame to w.
func WriteFrame(w io.Writer, f Frame) error {
	body := make([]byte, 0, 5+2*maxVarintBytes+len(f.Payload))
	body = append(body, f.Type)
	body = binary.BigEndian.AppendUint32(body, f.Flags)
	body = EncodeVarint(body, f.StreamID)
	body = EncodeVarint(body, f.FrameID)
	body = append(body, f.Payload...)
	if len(body) > HardMaxFrameCap {
		return ErrFrameTooLarge
	}
	var out []byte
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)))
	out = append(out, body...)
	_, err := w.Write(out)
	return err
}

// supportsVersion reports whether a comma-separated SPOP supported-versions string includes want.
func supportsVersion(versions, want string) bool {
	for v := range strings.SplitSeq(versions, ",") {
		if strings.TrimSpace(v) == want {
			return true
		}
	}
	return false
}

// negotiateCapabilities returns the intersection of clientCaps and agentCaps, preserving agentCaps order.
func negotiateCapabilities(clientCaps string, agentCaps []string) string {
	var clientList []string
	for c := range strings.SplitSeq(clientCaps, ",") {
		if t := strings.TrimSpace(c); t != "" {
			clientList = append(clientList, t)
		}
	}
	var agreed []string
	for _, capName := range agentCaps {
		if slices.Contains(clientList, capName) {
			agreed = append(agreed, capName)
		}
	}
	return strings.Join(agreed, ",")
}

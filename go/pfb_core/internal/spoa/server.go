package spoa

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultReadTimeout  = 30 * time.Second
	defaultWriteTimeout = 10 * time.Second
	maxConnsDefault     = 256
)

// Handler evaluates one NOTIFY frame's messages and returns ACK actions plus whether the request was blocked.
type Handler func(ctx context.Context, msgs []Message) (actions []Action, blocked bool, err error)

// ServerConfig configures a SPOP v2.0 server.
type ServerConfig struct {
	// Listen is either "127.0.0.1:<port>", "[::1]:<port>", or "unix:/abs/path/to/spoa.sock".
	Listen       string
	SocketGroup  int // optional gid for unix sockets (when GroupSet is true)
	GroupSet     bool
	SocketMode   os.FileMode // default 0660 when GroupSet, else 0660 for unix sockets
	MaxFrameSize uint32      // default DefaultMaxFrame
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	MaxConns     int
	Logf         func(format string, args ...any)
	Handler      Handler
}

// Metrics is a snapshot of the SPOP server's runtime counters.
type Metrics struct {
	Lookups     uint64
	Blocked     uint64
	Errors      uint64
	ActiveConns int64
}

// ParseListen validates a SPOA listen address: loopback TCP ("127.0.0.1:<port>", "[::1]:<port>") or
// Unix domain socket ("unix:/abs/path"). Returns network ("tcp" or "unix") and address.
func ParseListen(spec string) (network, addr string, err error) {
	if spec == "" {
		return "", "", errors.New("spoa listen address is empty")
	}
	if len(spec) > 5 && spec[:5] == "unix:" {
		p := spec[5:]
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return "", "", fmt.Errorf("unix socket path %q must be a clean absolute path", p)
		}
		return "unix", p, nil
	}
	host, portStr, err := net.SplitHostPort(spec)
	if err != nil {
		return "", "", fmt.Errorf("invalid listen address %q: %w", spec, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return "", "", fmt.Errorf("listen address %q must be a loopback IP (127.0.0.1 or [::1]) or unix:/path", spec)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return "", "", fmt.Errorf("invalid port in %q", spec)
	}
	return "tcp", spec, nil
}

// Server serves HAProxy SPOP v2.0 connections over loopback TCP or a Unix domain socket.
type Server struct {
	cfg      ServerConfig
	network  string
	addr     string
	ln       net.Listener
	unixPath string

	lookups     atomic.Uint64
	blocked     atomic.Uint64
	errors      atomic.Uint64
	activeConns atomic.Int64

	wg sync.WaitGroup
}

// Listen validates cfg, binds the TCP or Unix listener, and returns a ready Server.
func Listen(cfg ServerConfig) (*Server, error) {
	if cfg.Handler == nil {
		return nil, errors.New("spoa: handler is required")
	}
	network, addr, err := ParseListen(cfg.Listen)
	if err != nil {
		return nil, err
	}
	if cfg.MaxFrameSize == 0 {
		cfg.MaxFrameSize = DefaultMaxFrame
	}
	if cfg.MaxFrameSize < MinMaxFrameSize || cfg.MaxFrameSize > HardMaxFrameCap {
		return nil, fmt.Errorf("spoa: max frame size %d out of range [%d, %d]", cfg.MaxFrameSize, MinMaxFrameSize, HardMaxFrameCap)
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = defaultReadTimeout
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = defaultWriteTimeout
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = maxConnsDefault
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	s := &Server{cfg: cfg, network: network, addr: addr}
	if network == "unix" {
		ln, err := listenUnix(addr, cfg.SocketGroup, cfg.GroupSet, cfg.SocketMode)
		if err != nil {
			return nil, err
		}
		s.ln = ln
		s.unixPath = addr
	} else {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		s.ln = ln
	}
	return s, nil
}

func listenUnix(path string, gid int, groupSet bool, mode os.FileMode) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&fs.ModeSocket == 0 {
			return nil, fmt.Errorf("spoa: %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("spoa: removing stale socket %s: %w", path, err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if mode == 0 {
		mode = 0o660
	}
	if groupSet {
		if err := os.Chown(path, -1, gid); err != nil {
			_ = ln.Close()
			_ = os.Remove(path)
			return nil, fmt.Errorf("spoa: chown socket %s: %w", path, err)
		}
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("spoa: chmod socket %s: %w", path, err)
	}
	return ln, nil
}

// Addr returns the bound listener address (useful when binding port 0 in tests).
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Metrics returns a point-in-time snapshot of server counters.
func (s *Server) Metrics() Metrics {
	return Metrics{
		Lookups:     s.lookups.Load(),
		Blocked:     s.blocked.Load(),
		Errors:      s.errors.Load(),
		ActiveConns: s.activeConns.Load(),
	}
}

// Serve accepts connections until ctx is cancelled or the listener fails.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
	}()
	defer func() {
		s.wg.Wait()
		if s.unixPath != "" {
			_ = os.Remove(s.unixPath)
		}
	}()
	sem := make(chan struct{}, s.cfg.MaxConns)
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			s.errors.Add(1)
			_ = conn.Close()
			continue
		}
		s.activeConns.Add(1)
		s.wg.Add(1)
		go func(c net.Conn) {
			defer func() {
				_ = c.Close()
				<-sem
				s.activeConns.Add(-1)
				s.wg.Done()
			}()
			s.handleConn(ctx, c)
		}(conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-connCtx.Done()
		_ = conn.SetDeadline(time.Now())
	}()

	// 1. Expect HAPROXY-HELLO.
	_ = conn.SetReadDeadline(time.Now().Add(s.cfg.ReadTimeout))
	hello, err := ReadFrame(conn, s.cfg.MaxFrameSize)
	if err != nil {
		if !errors.Is(err, io.EOF) && connCtx.Err() == nil {
			s.errors.Add(1)
		}
		return
	}
	if hello.Type != FrameTypeHaproxyHello {
		s.errors.Add(1)
		s.sendDisconnect(conn, StatusInvalidFrame, "expected HAPROXY-HELLO")
		return
	}
	kvs, err := DecodeKVList(hello.Payload)
	if err != nil {
		s.errors.Add(1)
		s.sendDisconnect(conn, StatusInvalidFrame, "malformed HAPROXY-HELLO")
		return
	}
	var (
		versions    string
		hasVer      bool
		clientMax   uint32
		hasMax      bool
		clientCaps  string
		hasCaps     bool
		healthcheck bool
	)
	for _, kv := range kvs {
		switch kv.Key {
		case "supported-versions":
			if v, ok := kv.Value.AsString(); ok {
				versions, hasVer = v, true
			}
		case "max-frame-size":
			if kv.Value.Type == DataTypeUint32 || kv.Value.Type == DataTypeUint64 {
				clientMax, hasMax = uint32(kv.Value.Uint), true
			}
		case "capabilities":
			if v, ok := kv.Value.AsString(); ok {
				clientCaps, hasCaps = v, true
			}
		case "healthcheck":
			if kv.Value.Type == DataTypeBool {
				healthcheck = kv.Value.Bool
			}
		}
	}
	if !hasVer {
		s.sendDisconnect(conn, StatusNoVersion, "missing supported-versions")
		return
	}
	if !supportsVersion(versions, ProtocolVersion) {
		s.sendDisconnect(conn, StatusUnsupportedVer, "unsupported SPOP version")
		return
	}
	if !hasMax {
		s.sendDisconnect(conn, StatusNoMaxFrameSize, "missing max-frame-size")
		return
	}
	if clientMax < MinMaxFrameSize {
		s.sendDisconnect(conn, StatusMaxFrameTooSmall, "max-frame-size too small")
		return
	}
	if !hasCaps {
		s.sendDisconnect(conn, StatusNoCapabilities, "missing capabilities")
		return
	}
	negMax := min(clientMax, s.cfg.MaxFrameSize)
	negCaps := negotiateCapabilities(clientCaps, []string{"pipelining", "fragmentation"})

	respPayload, err := EncodeKVList([]KV{
		{Key: "version", Value: StringValue(ProtocolVersion)},
		{Key: "max-frame-size", Value: Uint32Value(negMax)},
		{Key: "capabilities", Value: StringValue(negCaps)},
	})
	if err != nil {
		s.errors.Add(1)
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout))
	if err := WriteFrame(conn, Frame{
		Type:    FrameTypeAgentHello,
		Flags:   FrameFlagFin,
		Payload: respPayload,
	}); err != nil {
		s.errors.Add(1)
		return
	}
	if healthcheck {
		return
	}

	// 2. Main NOTIFY / HAPROXY-DISCONNECT loop with fragmentation reassembly.
	var fragBuf []byte
	var fragStream, fragFrame uint64
	inFrag := false

	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.cfg.ReadTimeout))
		f, err := ReadFrame(conn, negMax)
		if err != nil {
			if connCtx.Err() != nil {
				s.sendDisconnect(conn, StatusNormal, "shutting down")
				return
			}
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			s.errors.Add(1)
			if errors.Is(err, ErrFrameTooLarge) {
				s.sendDisconnect(conn, StatusFrameTooBig, "frame too large")
			} else {
				s.sendDisconnect(conn, StatusIOError, "read error")
			}
			return
		}

		switch f.Type {
		case FrameTypeHaproxyDisconn:
			s.sendDisconnect(conn, StatusNormal, "normal")
			return

		case FrameTypeNotify:
			if inFrag {
				s.errors.Add(1)
				s.sendDisconnect(conn, StatusBadFragmentation, "unexpected NOTIFY during fragmentation")
				return
			}
			if f.Flags&FrameFlagFin == 0 {
				inFrag = true
				fragStream, fragFrame = f.StreamID, f.FrameID
				fragBuf = append(fragBuf[:0], f.Payload...)
				continue
			}
			if !s.dispatchNotify(connCtx, conn, f.StreamID, f.FrameID, f.Payload, negMax) {
				return
			}

		case FrameTypeUnset:
			if !inFrag || f.StreamID != fragStream || f.FrameID != fragFrame {
				s.errors.Add(1)
				s.sendDisconnect(conn, StatusBadFragmentation, "unexpected fragment")
				return
			}
			if f.Flags&FrameFlagAbort != 0 {
				inFrag = false
				fragBuf = fragBuf[:0]
				continue
			}
			if len(fragBuf)+len(f.Payload) > HardMaxFrameCap {
				s.errors.Add(1)
				s.sendDisconnect(conn, StatusFrameTooBig, "reassembled frame too large")
				return
			}
			fragBuf = append(fragBuf, f.Payload...)
			if f.Flags&FrameFlagFin != 0 {
				inFrag = false
				payload := fragBuf
				fragBuf = nil
				if !s.dispatchNotify(connCtx, conn, fragStream, fragFrame, payload, negMax) {
					return
				}
			}

		default:
			s.errors.Add(1)
			s.sendDisconnect(conn, StatusInvalidFrame, fmt.Sprintf("unexpected frame type %d", f.Type))
			return
		}
	}
}

func (s *Server) dispatchNotify(ctx context.Context, conn net.Conn, streamID, frameID uint64, payload []byte, maxFrame uint32) bool {
	msgs, err := DecodeMessages(payload)
	if err != nil {
		s.errors.Add(1)
		s.sendDisconnect(conn, StatusInvalidFrame, "malformed NOTIFY payload")
		return false
	}
	s.lookups.Add(1)
	actions, blocked, err := s.safeHandle(ctx, msgs)
	if err != nil {
		s.errors.Add(1)
		s.cfg.Logf("spoa handler error: %v", err)
		actions = nil
	} else if blocked {
		s.blocked.Add(1)
	}
	ackPayload, err := EncodeActions(actions)
	if err != nil || uint32(len(ackPayload)+32) > maxFrame {
		s.errors.Add(1)
		ackPayload = nil
	}
	_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout))
	if err := WriteFrame(conn, Frame{
		Type:     FrameTypeAck,
		Flags:    FrameFlagFin,
		StreamID: streamID,
		FrameID:  frameID,
		Payload:  ackPayload,
	}); err != nil {
		s.errors.Add(1)
		return false
	}
	return true
}

func (s *Server) safeHandle(ctx context.Context, msgs []Message) (actions []Action, blocked bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in handler: %v", r)
		}
	}()
	return s.cfg.Handler(ctx, msgs)
}

func (s *Server) sendDisconnect(conn net.Conn, code uint32, msg string) {
	payload, err := EncodeKVList([]KV{
		{Key: "status-code", Value: Uint32Value(code)},
		{Key: "message", Value: StringValue(msg)},
	})
	if err != nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout))
	_ = WriteFrame(conn, Frame{
		Type:    FrameTypeAgentDisconnect,
		Flags:   FrameFlagFin,
		Payload: payload,
	})
}

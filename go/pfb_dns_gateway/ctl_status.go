package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/net/dns/dnsmessage"
)

type statusListener struct {
	Kind    string `json:"kind"`
	Address string `json:"address"`
	State   string `json:"state"`
	Reason  string `json:"reason"`
}

type statusNameAnswers struct {
	A    []string `json:"a"`
	AAAA []string `json:"aaaa"`
}

type statusRecord struct {
	Priority uint16 `json:"priority"`
	Target   string `json:"target"`
	ALPN     string `json:"alpn"`
	Port     uint16 `json:"port"`
	Hint     string `json:"hint"`
	Path     string `json:"path"`
}

type statusAdvertisement struct {
	Records    []statusRecord `json:"records"`
	Additional []string       `json:"additional"`
}

type appliedStatus struct {
	Version        int                            `json:"version"`
	PID            int                            `json:"pid"`
	Executable     string                         `json:"executable"`
	Ready          bool                           `json:"ready"`
	Upstream       string                         `json:"upstream,omitempty"`
	DNSName        string                         `json:"dns_name"`
	Listeners      []statusListener               `json:"listeners"`
	NameAnswers    map[string]statusNameAnswers   `json:"name_answers"`
	DDR            bool                           `json:"ddr"`
	Advertisements map[string]statusAdvertisement `json:"advertisements"`
	Degraded       []statusDegraded               `json:"degraded"`
}

// canonicalUpstream is the applied upstream in its numeric spelling, or "" for a spelling that has none: a hostname, a scoped
// address, or a port that is not 1 to 65535 in at most five digits (devel's readiness bound). The status then omits the field.
func canonicalUpstream(upstream string) string {
	host, port, err := net.SplitHostPort(upstream)
	if err != nil {
		return ""
	}
	addr, err := netip.ParseAddr(host)
	p, perr := strconv.ParseUint(port, 10, 16)
	if err != nil || addr.Zone() != "" || perr != nil || p == 0 || len(port) > 5 {
		return ""
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(p)).String()
}

// The file this process was started from, read at start: a package upgrade replaces it under a running gateway, and FreeBSD then
// reports no path for the process (issue #3857).
var startExecutable, startExecutableErr = os.Executable()

// status runs only on the control goroutine, which owns listener and address-table updates.
func (c *ctlServer) status() ([]byte, error) {
	if startExecutableErr != nil {
		return nil, startExecutableErr
	}
	s := appliedStatus{
		Version: 1, PID: os.Getpid(), Executable: startExecutable,
		Ready:     c.ready.Load() && c.g != nil && c.g.ctx.Err() == nil,
		Listeners: []statusListener{}, NameAnswers: map[string]statusNameAnswers{},
		DDR: c.ddr != nil, Advertisements: map[string]statusAdvertisement{}, Degraded: c.degraded(),
	}
	locals := map[netip.Addr]struct{}{}
	if c.names != nil {
		s.DNSName = strings.TrimSuffix(c.names.key, ".")
		for local, addrs := range *c.names.table.Load() {
			answer := statusNameAnswers{A: []string{}, AAAA: []string{}}
			if addrs.v4.IsValid() {
				answer.A = append(answer.A, addrs.v4.String())
			}
			if addrs.v6.IsValid() {
				answer.AAAA = append(answer.AAAA, addrs.v6.String())
			}
			s.NameAnswers[local.String()] = answer
			locals[local] = struct{}{}
		}
	}
	if c.listeners != nil {
		s.Upstream = canonicalUpstream(c.listeners.cfg.upstream)
		rows := map[string]statusListener{}
		add := func(key, state, reason string) error {
			kind, address, _ := strings.Cut(key, " ")
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return err
			}
			if ap.Port() == 0 {
				return nil // a failed port-0 bind has no applied endpoint
			}
			local := ap.Addr().Unmap().WithZone("")
			address = netip.AddrPortFrom(local, ap.Port()).String()
			rows[kind+" "+address] = statusListener{Kind: kind, Address: address, State: state, Reason: reason}
			if state == "listening" {
				locals[local] = struct{}{}
			}
			return nil
		}
		for key, reason := range c.listeners.refused {
			if err := add(key, "refused", reason); err != nil {
				return nil, err
			}
		}
		for key := range c.listeners.served {
			if err := add(key, "listening", ""); err != nil {
				return nil, err
			}
		}
		for _, key := range slices.Sorted(maps.Keys(rows)) {
			s.Listeners = append(s.Listeners, rows[key])
		}
	}
	for local := range locals {
		ad := statusAdvertisement{Records: []statusRecord{}, Additional: []string{}}
		if c.ddr != nil {
			answers, additional := c.ddr.designate(dnsmessage.MustNewName(ddrDesignated), local)
			for _, answer := range answers {
				r := answer.Body.(*dnsmessage.SVCBResource)
				record := statusRecord{Priority: r.Priority, Target: strings.TrimSuffix(r.Target.String(), ".")}
				for _, param := range r.Params {
					switch param.Key {
					case dnsmessage.SVCParamALPN:
						record.ALPN = string(param.Value[1:])
					case dnsmessage.SVCParamPort:
						record.Port = binary.BigEndian.Uint16(param.Value)
					case dnsmessage.SVCParamIPv4Hint, dnsmessage.SVCParamIPv6Hint:
						hint, _ := netip.AddrFromSlice(param.Value)
						record.Hint = hint.String()
					case dnsmessage.SVCParamDOHPath:
						record.Path = string(param.Value)
					}
				}
				if record.Port == 0 {
					switch record.ALPN {
					case "h2":
						record.Port = ddrDoHPort
					case "dot":
						record.Port = defaultDoTPort
					case "doq":
						record.Port = ddrDoQPort
					}
				}
				ad.Records = append(ad.Records, record)
			}
			for _, extra := range additional {
				switch r := extra.Body.(type) {
				case *dnsmessage.AResource:
					ad.Additional = append(ad.Additional, netip.AddrFrom4(r.A).String())
				case *dnsmessage.AAAAResource:
					ad.Additional = append(ad.Additional, netip.AddrFrom16(r.AAAA).String())
				}
			}
		}
		s.Advertisements[local.String()] = ad
	}
	wire, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	if len(wire)+4 > 65536 {
		return nil, errors.New("status exceeds response limit")
	}
	return append(wire, '\n', 'o', 'k', '\n'), nil
}

// Peek only at bytes already queued: callers need not half-close to obtain a status reply.
func (in *ctlInput) emptyStatusRequest() bool {
	if in.cut || len(in.fds) != 0 {
		return false
	}
	raw, err := in.conn.SyscallConn()
	if err != nil {
		return false
	}
	var n, oobn, flags int
	var readErr error
	var one [1]byte
	err = raw.Control(func(fd uintptr) {
		n, oobn, flags, _, readErr = syscall.Recvmsg(int(fd), one[:], in.oob, syscall.MSG_DONTWAIT)
	})
	msgs, parseErr := syscall.ParseSocketControlMessage(in.oob[:max(oobn, 0)])
	for _, msg := range msgs {
		if fds, err := syscall.ParseUnixRights(&msg); err == nil {
			in.fds = append(in.fds, fds...)
		}
	}
	return err == nil && parseErr == nil && n <= 0 && oobn == 0 && flags&syscall.MSG_CTRUNC == 0 && (readErr == nil || errors.Is(readErr, syscall.EAGAIN) || errors.Is(readErr, syscall.EWOULDBLOCK))
}

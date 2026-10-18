package main

import (
	"net"

	"github.com/quic-go/quic-go"
)

// tlsListeners are the DoT, DoH and DoQ sockets, bound while the gateway is still root; serving starts later.
type tlsListeners struct {
	settings tlsSettings
	dot, doh []*net.TCPListener
	doq      []*quic.Listener
}

// bindTLS binds every requested TLS transport. When one is requested but the certificate is unusable the reason is
// logged once and nothing is bound (nil): plain DNS keeps serving, as a broken certificate must not take :53 down.
// An address that cannot be bound is logged and skipped. config.xml is not looked at unless a transport is requested.
func bindTLS(cfg config, logf func(format string, args ...any)) *tlsListeners {
	if !cfg.dot && len(cfg.dohListen) == 0 && len(cfg.doqListen) == 0 {
		return nil
	}
	settings, err := readTLSSettings(cfg.pfsenseConfig)
	if err != nil {
		logf("TLS transports disabled: %v", err)
		return nil
	}
	t := &tlsListeners{settings: settings}
	if cfg.dot {
		for _, host := range cfg.listen {
			if ln, err := bindTCP(host, settings.port); err != nil {
				logf("%v", err)
			} else {
				t.dot = append(t.dot, ln)
			}
		}
	}
	for _, host := range cfg.dohListen {
		if ln, err := bindTCP(host, cfg.dohPort); err != nil {
			logf("%v", err)
		} else {
			t.doh = append(t.doh, ln)
		}
	}
	for _, host := range cfg.doqListen {
		if ln, err := listenDoQ(host, cfg.doqPort, settings.doq()); err != nil {
			logf("%v", err)
		} else {
			t.doq = append(t.doq, ln)
		}
	}
	return t
}

func (t *tlsListeners) close() {
	if t == nil {
		return
	}
	for _, ln := range t.dot {
		_ = ln.Close()
	}
	for _, ln := range t.doh {
		_ = ln.Close()
	}
	for _, ln := range t.doq {
		_ = ln.Close()
	}
}

// report logs one readiness line per bound listener: `listening dot|doh|doq <host>:<port>`.
func (t *tlsListeners) report(logf func(format string, args ...any)) {
	if t == nil {
		return
	}
	for _, ln := range t.dot {
		logf("listening dot %s", ln.Addr())
	}
	for _, ln := range t.doh {
		logf("listening doh %s", ln.Addr())
	}
	for _, ln := range t.doq {
		logf("listening doq %s", ln.Addr())
	}
}

// serve starts answering on every bound TLS listener.
func (t *tlsListeners) serve(g *gateway, trusted []string) {
	if t == nil {
		return
	}
	for _, ln := range t.dot {
		g.serveDoT(ln, t.settings.dot())
	}
	if len(t.doh) > 0 {
		prefixes := parseTrusted(trusted, g.logf)
		for _, ln := range t.doh {
			g.serveDoH(ln, t.settings.doh(), prefixes)
		}
	}
	for _, ln := range t.doq {
		g.serveDoQ(ln)
	}
}

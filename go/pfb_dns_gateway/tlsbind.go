package main

import "net"

// tlsListeners are the DoT, DoH and DoQ sockets and the control socket, bound while the gateway is still root; serving
// starts later.
type tlsListeners struct {
	certs    *certStore
	ctl      *ctlServer
	dot, doh []*net.TCPListener
	doq      []*net.UDPConn
}

// bindTLS binds every requested TLS transport and the control socket that renews their certificate. The certificate file
// is read here, as root; when it is unusable the reason is logged once and the store starts empty: the listeners are bound,
// handshakes fail, and the first certificate pushed on the control socket is served with no restart (plain DNS is
// unaffected either way: a broken certificate must not take :53 down). An address that cannot be bound is logged and
// skipped, and so is a control socket that cannot be made: the certificate read at start is then served until a restart.
// The file is not looked at, and no socket is made, unless a transport is requested.
func bindTLS(cfg config, logf func(format string, args ...any)) *tlsListeners {
	if !cfg.dot && len(cfg.dohListen) == 0 && len(cfg.doqListen) == 0 {
		return nil
	}
	certs, err := newCertStore(cfg.tlsPEM, logf)
	if err != nil {
		logf("TLS certificate not loaded: %v; DoT, DoH and DoQ handshakes fail until one is pushed", err)
		certs = newEmptyCertStore(logf)
	}
	t := &tlsListeners{certs: certs}
	if cfg.ctlSocket != "" {
		if ctl, err := bindCtl(cfg.ctlSocket, certs, logf); err != nil {
			logf("control socket: %v; the certificate cannot be renewed without a restart", err)
		} else {
			t.ctl = ctl
		}
	}
	if cfg.dot {
		for _, host := range cfg.listen {
			if ln, err := bindTCP(host, cfg.dotPort); err != nil {
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
		if ln, err := bindUDP(host, cfg.doqPort); err != nil {
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
	if t.ctl != nil {
		_ = t.ctl.ln.Close()
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
		logf("listening doq %s", ln.LocalAddr())
	}
	if t.ctl != nil {
		logf("control socket %s", t.ctl.path)
	}
}

// serve starts answering on every bound TLS listener.
func (t *tlsListeners) serve(g *gateway, trusted []string) {
	if t == nil {
		return
	}
	for _, ln := range t.dot {
		g.serveDoT(ln, t.certs.dot())
	}
	if len(t.doh) > 0 {
		prefixes := parseTrusted(trusted, g.logf)
		for _, ln := range t.doh {
			g.serveDoH(ln, t.certs.doh(), prefixes)
		}
	}
	for _, ln := range t.doq {
		g.serveDoQ(ln, t.certs.doq())
	}
	if t.ctl != nil {
		t.ctl.serve(g)
	}
}

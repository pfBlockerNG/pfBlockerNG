package main

import "net"

// tlsListeners are the DoT, DoH and DoQ sockets, bound while the gateway is still root; serving starts later.
type tlsListeners struct {
	certs    *certStore
	dot, doh []*net.TCPListener
	doq      []*net.UDPConn
}

// bindTLS binds every requested TLS transport. The certificate file is read here, as root; when it is unusable the reason
// is logged once and the store starts empty: the listeners are bound, handshakes fail, and the first certificate pushed on
// the control socket (bound by start() in every mode) is served with no restart (plain DNS is unaffected either way: a
// broken certificate must not take :53 down). An address that cannot be bound is logged and skipped. The file is not
// looked at unless a transport is requested.
func bindTLS(cfg config, logf func(format string, args ...any)) *tlsListeners {
	if len(cfg.dotListen) == 0 && len(cfg.dohListen) == 0 && len(cfg.doqListen) == 0 {
		return nil
	}
	certs, err := newCertStore(cfg.tlsPEM, logf)
	if err != nil {
		logf("TLS certificate not loaded: %v; DoT, DoH and DoQ handshakes fail until one is pushed", err)
		certs = newEmptyCertStore(logf)
	}
	t := &tlsListeners{certs: certs}
	for _, host := range cfg.dotListen {
		if ln, err := bindTCP(host, cfg.dotPort); err != nil {
			logf("%v", err)
		} else {
			t.dot = append(t.dot, ln)
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
}

// serve starts answering on every bound TLS listener and records each in set, where the control socket's remove finds it.
func (t *tlsListeners) serve(set *listenerSet) {
	if t == nil {
		return
	}
	for _, ln := range t.dot {
		set.track("dot", ln.Addr().(*net.TCPAddr).AddrPort(), set.g.serveDoT(ln, t.certs.dot()))
	}
	for _, ln := range t.doh {
		set.track("doh", ln.Addr().(*net.TCPAddr).AddrPort(), set.g.serveDoH(ln, t.certs.doh(), set.trusted))
	}
	for _, ln := range t.doq {
		if closeNow, err := set.g.serveDoQ(ln, t.certs.doq()); err == nil { // serveDoQ has logged what failed
			set.track("doq", ln.LocalAddr().(*net.UDPAddr).AddrPort(), closeNow)
		}
	}
}

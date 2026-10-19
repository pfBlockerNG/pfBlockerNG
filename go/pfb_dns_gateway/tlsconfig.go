package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"
)

// What DoT, DoH and DoQ serve is one PEM file: the DNS Resolver's certificate, the CAs after it nearest first, then its
// private key, written by pfBlockerNG (pfb_dns_proxy_certificate_export(), docs/misc/dns-gateway-transports.md) for the
// user the gateway runs as. The gateway hands it out through tls.Config.GetCertificate and looks at it again at most
// once a second. A new content that parses, key included, replaces the certificate for the handshakes that follow; one
// that does not is reported once and the previous certificate stays. A connection that is open keeps the certificate
// it was set up with. So a renewal needs no restart and fails no handshake.

const (
	defaultDoTPort = 853
	certRecheck    = time.Second // how often the file is looked at, at most
)

// certStore is the certificate the transports serve and the file it is read from.
type certStore struct {
	path string
	logf func(format string, args ...any)
	now  func() time.Time // the clock; a test replaces it

	mu      sync.Mutex
	cert    *tls.Certificate
	seen    []byte    // the content last read, whether it parsed or not: the same content is neither parsed nor reported again
	readErr string    // why the file could not be read, while it cannot
	checked time.Time // when the file was last looked at
}

// newCertStore loads the file; every error names it and the reason. A gateway that cannot load its certificate at
// start serves no TLS (bindTLS): there is no previous certificate to keep.
func newCertStore(path string, logf func(format string, args ...any)) (*certStore, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot read: %w", path, reason(err))
	}
	cert, err := tls.X509KeyPair(raw, raw)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot load the certificate and key: %w", path, err)
	}
	return &certStore{path: path, logf: logf, now: time.Now, cert: &cert, seen: raw, checked: time.Now()}, nil
}

// reason is the cause of a file error without the operation and the path, which the caller names.
func reason(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// getCertificate is tls.Config.GetCertificate.
func (s *certStore) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now := s.now(); now.Sub(s.checked) >= certRecheck {
		s.checked = now
		s.reload()
	}
	return s.cert, nil
}

// reload looks at the file once; the caller holds mu.
func (s *certStore) reload() {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if msg := reason(err).Error(); msg != s.readErr {
			s.readErr = msg
			s.logf("TLS certificate not reloaded: %s: cannot read: %s; keeping the previous certificate", s.path, msg)
		}
		return
	}
	s.readErr = ""
	if bytes.Equal(raw, s.seen) {
		return
	}
	s.seen = raw
	cert, err := tls.X509KeyPair(raw, raw)
	if err != nil {
		s.logf("TLS certificate not reloaded: %s: cannot load the certificate and key: %v; keeping the previous certificate", s.path, err)
		return
	}
	s.cert = &cert
	s.logf("TLS certificate reloaded: %s", s.path)
}

// dot is the TLS 1.2+ configuration of DoT.
func (s *certStore) dot() *tls.Config {
	return &tls.Config{GetCertificate: s.getCertificate, MinVersion: tls.VersionTLS12}
}

// doh is the TLS 1.2+ configuration of DoH, HTTP/2 preferred.
func (s *certStore) doh() *tls.Config {
	return &tls.Config{GetCertificate: s.getCertificate, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
}

// doq is the TLS 1.3 configuration of DoQ (RFC 9250 4.1: ALPN "doq").
func (s *certStore) doq() *tls.Config {
	return &tls.Config{GetCertificate: s.getCertificate, MinVersion: tls.VersionTLS13, NextProtos: []string{"doq"}}
}

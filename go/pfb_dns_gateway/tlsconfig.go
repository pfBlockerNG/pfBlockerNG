package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync/atomic"
)

// What DoT, DoH and DoQ serve is one certificate chain and its private key. The gateway reads the PEM file pfBlockerNG
// writes (pfb_dns_proxy_certificate_export(), docs/misc/dns-gateway-transports.md) once, at start, while it is still root,
// and never looks at it again: a renewal arrives as a push on the control socket (ctl.go), from root, and replaces the
// certificate for the handshakes that follow. A push that does not parse, key included, is reported and the previous
// certificate stays. A connection that is open keeps the certificate it was set up with. So a renewal needs no restart,
// fails no handshake, and the key never has to be readable by the user the gateway runs as.

const defaultDoTPort = 853

// certStore is the certificate the transports serve.
type certStore struct {
	logf func(format string, args ...any)
	cert atomic.Pointer[tls.Certificate] // nil until the file at start or a push provides one
}

// newCertStore loads the file; every error names it and the reason. bindTLS starts an empty store when it fails.
func newCertStore(path string, logf func(format string, args ...any)) (*certStore, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot read: %w", path, reason(err))
	}
	cert, err := tls.X509KeyPair(raw, raw)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot load the certificate and key: %w", path, err)
	}
	s := &certStore{logf: logf}
	s.cert.Store(&cert)
	return s, nil
}

// newEmptyCertStore is a store with no certificate: every handshake fails until one is pushed.
func newEmptyCertStore(logf func(format string, args ...any)) *certStore {
	return &certStore{logf: logf}
}

// parseCertPEM is the certificate chain and key of one PEM text, the certificate first and its key somewhere in it. The key
// has to belong to the certificate, and an encrypted key is refused (a daemon cannot be asked for a passphrase).
func parseCertPEM(raw []byte) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(raw, raw)
	if err != nil {
		return nil, fmt.Errorf("cannot load the certificate and key: %w", err)
	}
	return &cert, nil
}

// push replaces the served certificate by the chain and key in pem; one that does not parse, or whose key is not the
// certificate's, changes nothing. New handshakes get the new certificate, connections that are open keep theirs.
func (s *certStore) push(pem []byte) error {
	cert, err := parseCertPEM(pem)
	if err != nil {
		s.logf("TLS certificate not replaced: %v; keeping the previous one", err)
		return err
	}
	s.cert.Store(cert)
	s.logf("TLS certificate replaced by a push")
	return nil
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
	if cert := s.cert.Load(); cert != nil {
		return cert, nil
	}
	return nil, errors.New("no TLS certificate is loaded")
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

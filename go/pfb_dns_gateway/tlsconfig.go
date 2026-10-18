package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
)

// The DNS Resolver's certificate, read from config.xml exactly as dns_proxy/pfsense_dot.py reads it (issue #3513):
// unbound/sslcertref names a top-level <cert> whose crt and prv are base64 PEM; the CAs its caref leads to follow
// it, nearest first, as Unbound is given them. unbound/enablessl is not read: the gateway's flags decide.

const defaultDoTPort = 853

// tlsSettings is what DoT, DoH and DoQ serve: the DoT port and the certificate chain with its key.
type tlsSettings struct {
	port int
	cert tls.Certificate
}

// pfsenseConfig is the slice of config.xml that is read; encoding/xml ignores the rest.
type pfsenseConfig struct {
	Unbound struct {
		SSLCertRef string `xml:"sslcertref"`
		TLSPort    string `xml:"tlsport"`
	} `xml:"unbound"`
	Certs []xmlCert `xml:"cert"`
	CAs   []xmlCert `xml:"ca"`
}

type xmlCert struct {
	RefID string `xml:"refid"`
	CARef string `xml:"caref"`
	CRT   string `xml:"crt"`
	PRV   string `xml:"prv"`
}

// readTLSSettings is the Resolver's certificate and DoT port in the config.xml at path; every error names the
// file and the reason.
func readTLSSettings(path string) (tlsSettings, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return tlsSettings{}, fmt.Errorf("%s: cannot read: %w", path, err)
	}
	var cfg pfsenseConfig
	if err := xml.Unmarshal(raw, &cfg); err != nil {
		return tlsSettings{}, fmt.Errorf("%s: not well-formed XML: %w", path, err)
	}

	ref := strings.TrimSpace(cfg.Unbound.SSLCertRef)
	if ref == "" {
		return tlsSettings{}, fmt.Errorf("%s: unbound/sslcertref is empty; pick the SSL/TLS Certificate of the DNS Resolver", path)
	}
	var cert *xmlCert
	for i := range cfg.Certs {
		if strings.TrimSpace(cfg.Certs[i].RefID) == ref {
			cert = &cfg.Certs[i]
			break
		}
	}
	if cert == nil {
		return tlsSettings{}, fmt.Errorf("%s: no <cert> with refid %q (unbound/sslcertref)", path, ref)
	}

	leaf, err := decodePEM(path, "cert", cert, "crt", cert.CRT)
	if err != nil {
		return tlsSettings{}, err
	}
	chain := [][]byte{leaf}
	// each CA the certificate's caref leads to, nearest first; a missing CA or a loop ends the chain
	authorities := map[string]*xmlCert{}
	for i := range cfg.CAs {
		authorities[strings.TrimSpace(cfg.CAs[i].RefID)] = &cfg.CAs[i]
	}
	seen := map[string]bool{}
	for caref := strings.TrimSpace(cert.CARef); caref != "" && !seen[caref] && authorities[caref] != nil; {
		seen[caref] = true
		ca := authorities[caref]
		pemBytes, err := decodePEM(path, "ca", ca, "crt", ca.CRT)
		if err != nil {
			return tlsSettings{}, err
		}
		chain = append(chain, pemBytes)
		caref = strings.TrimSpace(ca.CARef)
	}
	key, err := decodePEM(path, "cert", cert, "prv", cert.PRV)
	if err != nil {
		return tlsSettings{}, err
	}
	if encryptedKey(key) {
		return tlsSettings{}, fmt.Errorf("%s: the private key of the DNS Resolver's certificate is encrypted with a passphrase; use a key without one", path)
	}
	pair, err := tls.X509KeyPair(bytes.Join(chain, []byte("\n")), key)
	if err != nil {
		return tlsSettings{}, fmt.Errorf("%s: cannot load the DNS Resolver's certificate and key: %w", path, err)
	}

	port := defaultDoTPort
	if p, err := strconv.ParseUint(strings.TrimSpace(cfg.Unbound.TLSPort), 10, 16); err == nil && p > 0 {
		port = int(p)
	}
	return tlsSettings{port: port, cert: pair}, nil
}

// decodePEM is the base64 text of an element (whitespace ignored) as bytes.
func decodePEM(path, kind string, entry *xmlCert, field, text string) ([]byte, error) {
	label := fmt.Sprintf("<%s> %q", kind, strings.TrimSpace(entry.RefID))
	compact := strings.Join(strings.Fields(text), "")
	if compact == "" {
		return nil, fmt.Errorf("%s: %s has no %s", path, label, field)
	}
	decoded, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		return nil, fmt.Errorf("%s: %s of %s is not valid base64", path, field, label)
	}
	return decoded, nil
}

// encryptedKey reports a PEM key that needs a passphrase: a daemon cannot be asked for one.
func encryptedKey(keyPEM []byte) bool {
	for rest := keyPEM; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			return false
		}
		if block.Type == "ENCRYPTED PRIVATE KEY" || strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
			return true
		}
	}
}

// dot is the TLS 1.2+ configuration of DoT.
func (s tlsSettings) dot() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12}
}

// doh is the TLS 1.2+ configuration of DoH, HTTP/2 preferred.
func (s tlsSettings) doh() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
}

// doq is the TLS 1.3 configuration of DoQ (RFC 9250 4.1: ALPN "doq").
func (s tlsSettings) doq() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"doq"}}
}

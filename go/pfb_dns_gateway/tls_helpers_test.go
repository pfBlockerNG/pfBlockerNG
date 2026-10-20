package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// pki is a test certificate: a CA, an intermediate or a leaf valid for localhost, 127.0.0.1 and ::1.
type pki struct {
	cert *x509.Certificate
	key  any // *ecdsa.PrivateKey, or *rsa.PrivateKey for the PKCS#1 rows
	der  []byte
}

// newPKI issues a certificate signed by parent (self-signed when nil).
func newPKI(t *testing.T, parent *pki, cn string, isCA bool) *pki {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return issue(t, parent, cn, isCA, key, &key.PublicKey)
}

func issue(t *testing.T, parent *pki, cn string, isCA bool, key any, pub any) *pki {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		BasicConstraintsValid: true, IsCA: isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, pub, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &pki{cert: cert, key: key, der: der}
}

func (p *pki) certPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.der})
}

// keyPEM is the key as PKCS#8 (the format openssl and pfSense write).
func (p *pki) keyPEM(t *testing.T) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(p.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func (p *pki) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.cert)
	return pool
}

// tlsMaterial is what a TLS listener of a rig serves and what its clients trust.
type tlsMaterial struct {
	certs *certStore
	pool  *x509.CertPool
}

func newTLSMaterial(t *testing.T) tlsMaterial {
	t.Helper()
	_, m := goodPEM(t)
	return m
}

func (m tlsMaterial) clientConfig(protos ...string) *tls.Config {
	return &tls.Config{RootCAs: m.pool, ServerName: "localhost", NextProtos: protos}
}

// goodPEM is a certificate file (a fresh leaf, then its key) alone in its directory and the store loaded from it;
// clients trust the returned pool.
func goodPEM(t *testing.T) (path string, m tlsMaterial) {
	t.Helper()
	root := newPKI(t, nil, "test root", true)
	path = filepath.Join(t.TempDir(), "pfb_dns_cert.pem")
	if err := os.WriteFile(path, chainPEM(t, newPKI(t, root, "localhost", false)), 0o600); err != nil {
		t.Fatal(err)
	}
	certs, err := newCertStore(path, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	return path, tlsMaterial{certs: certs, pool: root.pool()}
}

// rsaPKCS1PEM and ecSEC1PEM are the legacy key encodings (PKCS#1 and SEC1) that openssl also writes.
func rsaPKCS1PEM(t *testing.T) (leaf *pki, keyPEM []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf = issue(t, nil, "localhost", false, key, &key.PublicKey)
	return leaf, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func ecSEC1PEM(t *testing.T) (leaf *pki, keyPEM []byte) {
	t.Helper()
	leaf = newPKI(t, nil, "localhost", false)
	der, err := x509.MarshalECPrivateKey(leaf.key.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	return leaf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// distinctPorts returns n TCP ports that are free and differ from each other: a gateway given one for DoT and port 0
// for plain DNS could otherwise be handed the same number twice by the kernel.
func distinctPorts(t *testing.T, n int) []int {
	t.Helper()
	held := make([]net.Listener, n)
	ports := make([]int, n)
	for i := range held {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		held[i], ports[i] = l, l.Addr().(*net.TCPAddr).Port
	}
	for _, l := range held {
		_ = l.Close()
	}
	return ports
}

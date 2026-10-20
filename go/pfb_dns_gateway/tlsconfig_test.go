package main

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// chainStore is a store loaded from a file as pfBlockerNG writes it for a certificate below an intermediate CA below
// a root CA: the certificate, the intermediate, the root (nearest first), then the key.
func chainStore(t *testing.T) (store *certStore, leaf, mid, root *pki) {
	t.Helper()
	root = newPKI(t, nil, "chain root", true)
	mid = newPKI(t, root, "chain intermediate", true)
	leaf = newPKI(t, mid, "localhost", false)
	store, _ = storeAt(t, chainPEM(t, leaf, mid, root))
	return store, leaf, mid, root
}

// storeAt loads a store from a file of its own holding content.
func storeAt(t *testing.T, content []byte) (*certStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pfb_dns_cert.pem")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newCertStore(path, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	return store, path
}

// The certificate, then each CA up its chain, exactly as the file holds them (pfBlockerNG writes nearest first).
func TestCertificateChainIsServedAsTheFileHoldsIt(t *testing.T) {
	store, leaf, mid, root := chainStore(t)
	want := [][]byte{leaf.der, mid.der, root.der}
	got := store.cert.Load().Certificate
	if len(got) != len(want) {
		t.Fatalf("chain length: got %d certificates, want %d (leaf, intermediate, root)", len(got), len(want))
	}
	for i, der := range want {
		if !bytes.Equal(got[i], der) {
			t.Fatalf("certificate %d of the chain is not the expected one (want order leaf, intermediate, root)", i)
		}
	}
}

// Every way the file can be unusable at start names its reason and the file.
func TestUnusableCertificateFileIsRefusedAtStartWithTheReason(t *testing.T) {
	leaf, other := newPKI(t, nil, "localhost", false), newPKI(t, nil, "localhost", false)
	legacyEncrypted := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,00112233445566778899AABBCCDDEEFF"},
		Bytes: bytes.Repeat([]byte{7}, 32),
	})
	pkcs8Encrypted := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: bytes.Repeat([]byte{7}, 64)})
	whole := chainPEM(t, leaf)
	cases := []struct {
		name    string
		content []byte
		want    string
	}{
		{"empty file", nil, "cannot load the certificate and key"},
		{"no PEM text", []byte("hello\n"), "cannot load the certificate and key"},
		{"certificate without a key", leaf.certPEM(), "cannot load the certificate and key"},
		{"key without a certificate", leaf.keyPEM(t), "cannot load the certificate and key"},
		{"key of another certificate", append(leaf.certPEM(), other.keyPEM(t)...), "does not match"},
		{"truncated file", whole[:len(whole)/2], "cannot load the certificate and key"},
		{"key encrypted (traditional PEM)", append(leaf.certPEM(), legacyEncrypted...), "cannot load the certificate and key"},
		{"key encrypted (PKCS#8)", append(leaf.certPEM(), pkcs8Encrypted...), "cannot load the certificate and key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pfb_dns_cert.pem")
			if err := os.WriteFile(path, c.content, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := newCertStore(path, func(string, ...any) {})
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), path) {
				t.Fatalf("got %v, want an error naming %s and containing %q", err, path, c.want)
			}
		})
	}
	dir := t.TempDir()
	for name, path := range map[string]string{"absent file": filepath.Join(dir, "absent.pem"), "a directory": dir} {
		if _, err := newCertStore(path, func(string, ...any) {}); err == nil || !strings.Contains(err.Error(), "cannot read") {
			t.Fatalf("%s: got %v, want a cannot-read error", name, err)
		}
	}
}

// PKCS#8, PKCS#1 and SEC1 private keys all load.
func TestPrivateKeyEncodingsLoad(t *testing.T) {
	pkcs8 := newPKI(t, nil, "localhost", false)
	rsaLeaf, rsaPEM := rsaPKCS1PEM(t)
	ecLeaf, ecPEM := ecSEC1PEM(t)
	cases := []struct {
		name string
		leaf *pki
		key  []byte
	}{{"PKCS#8", pkcs8, pkcs8.keyPEM(t)}, {"PKCS#1 RSA", rsaLeaf, rsaPEM}, {"SEC1 EC", ecLeaf, ecPEM}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store, _ := storeAt(t, append(c.leaf.certPEM(), c.key...))
			if got := store.cert.Load().Certificate; len(got) != 1 || !bytes.Equal(got[0], c.leaf.der) {
				t.Fatalf("the loaded certificate is not the one in the file")
			}
		})
	}
}

// DoT and DoH speak TLS 1.2 or later; DoQ is TLS 1.3 with ALPN doq; DoH offers HTTP/2 first. All three take the
// certificate from the store at each handshake, not once.
func TestTLSConfigsPerTransport(t *testing.T) {
	m := newTLSMaterial(t)
	dot, doh, doq := m.certs.dot(), m.certs.doh(), m.certs.doq()
	if dot.MinVersion != tls.VersionTLS12 || doh.MinVersion != tls.VersionTLS12 {
		t.Fatalf("DoT/DoH minimum TLS version: got %#x/%#x, want %#x", dot.MinVersion, doh.MinVersion, tls.VersionTLS12)
	}
	if doq.MinVersion != tls.VersionTLS13 {
		t.Fatalf("DoQ minimum TLS version: got %#x, want %#x", doq.MinVersion, tls.VersionTLS13)
	}
	if got := strings.Join(doh.NextProtos, ","); got != "h2,http/1.1" {
		t.Fatalf("DoH ALPN: got %q, want h2,http/1.1", got)
	}
	if got := strings.Join(doq.NextProtos, ","); got != "doq" {
		t.Fatalf("DoQ ALPN: got %q, want doq", got)
	}
	for name, c := range map[string]*tls.Config{"DoT": dot, "DoH": doh, "DoQ": doq} {
		if c.GetCertificate == nil || len(c.Certificates) != 0 {
			t.Fatalf("%s must serve through GetCertificate alone, so that a renewal reaches the next handshake", name)
		}
	}
}

// --- one certificate at start, the rest pushed ---

// The file is read once, at start, as root: what happens to it afterwards is none of the gateway's business. A new content
// in it, or its removal, changes nothing that is served; a renewal reaches the gateway by a push and by nothing else.
func TestTheFileIsReadOnceAtStartAndNeverAgain(t *testing.T) {
	root := newPKI(t, nil, "once root", true)
	first, second := newPKI(t, root, "localhost", false), newPKI(t, root, "localhost", false)
	store, path := storeAt(t, chainPEM(t, first))
	served := func(when string) {
		t.Helper()
		for range 20 { // every call is a handshake's: a store that looked at the file would see it change on one of them
			cert, err := store.getCertificate(nil)
			if err != nil || !bytes.Equal(cert.Certificate[0], first.der) {
				t.Fatalf("%s: the store serves %v (err %v), want the certificate read at start", when, cert, err)
			}
		}
	}
	served("untouched")
	if err := os.WriteFile(path, chainPEM(t, second), 0o600); err != nil {
		t.Fatal(err)
	}
	served("with another certificate in the file")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	served("with the file gone")
}

// A store with no certificate fails every handshake and says why.
func TestAnEmptyStoreFailsEveryHandshakeWithAReason(t *testing.T) {
	store := newEmptyCertStore(func(string, ...any) {})
	cert, err := store.getCertificate(nil)
	if cert != nil || err == nil || !strings.Contains(err.Error(), "no TLS certificate") {
		t.Fatalf("got %v, %v; want no certificate and the reason", cert, err)
	}
}

// Handshakes on every transport share one store: a push while they run never hands out nothing or a mixture.
func TestHandshakesDuringPushesGetOneCertificateOrTheOther(t *testing.T) {
	root := newPKI(t, nil, "race root", true)
	first, second := newPKI(t, root, "localhost", false), newPKI(t, root, "localhost", false)
	store, _ := storeAt(t, chainPEM(t, first))
	firstPEM, secondPEM := chainPEM(t, first), chainPEM(t, second)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var bad atomic.Int64
	for range 8 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				cert, err := store.getCertificate(nil)
				if err != nil || cert == nil || len(cert.Certificate) != 1 ||
					(!bytes.Equal(cert.Certificate[0], first.der) && !bytes.Equal(cert.Certificate[0], second.der)) {
					bad.Add(1)
				}
			}
		})
	}
	for i := range 200 {
		pem := firstPEM
		if i%2 == 0 {
			pem = secondPEM
		}
		if err := store.push(pem); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	if n := bad.Load(); n != 0 {
		t.Fatalf("%d handshakes got no certificate or one that was never pushed", n)
	}
}

// With no certificate every transport refuses the handshake; once one is pushed the very next handshake is served, on the
// listeners that were there all along.
func TestAnEmptyStoreRefusesTheHandshakeOnEveryTransportUntilACertificateIsPushed(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	r.autoAnswer(echoAnswer)
	root := newPKI(t, nil, "empty root", true)
	m := tlsMaterial{certs: newEmptyCertStore(r.logs.logf), pool: root.pool()}
	dot, doh, doq := r.serveDoT(m), r.serveDoH(m), r.serveDoQ(m)
	handshakes := func() (dotErr, dohErr, doqErr error) {
		for _, c := range []struct {
			addr netip.AddrPort
			err  *error
		}{{dot, &dotErr}, {doh, &dohErr}} {
			raw, err := net.DialTimeout("tcp4", c.addr.String(), watchdog)
			if err != nil {
				t.Fatal(err)
			}
			*c.err = tlsClientHandshake(raw, m)
			_ = raw.Close()
		}
		conn, err := tryDialDoQ(t, doq, doqConfig(m), "")
		if err == nil {
			_ = conn.CloseWithError(0, "")
		}
		return dotErr, dohErr, err
	}
	if a, b, c := handshakes(); a == nil || b == nil || c == nil {
		t.Fatalf("a handshake with no certificate loaded was accepted: DoT %v, DoH %v, DoQ %v", a, b, c)
	}
	if err := m.certs.push(chainPEM(t, newPKI(t, root, "localhost", false))); err != nil {
		t.Fatal(err)
	}
	if a, b, c := handshakes(); a != nil || b != nil || c != nil {
		t.Fatalf("the first handshake after a push failed: DoT %v, DoH %v, DoQ %v", a, b, c)
	}
}

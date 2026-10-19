package main

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
	got := store.cert.Certificate
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
			if got := store.cert.Certificate; len(got) != 1 || !bytes.Equal(got[0], c.leaf.der) {
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

// --- the reload, on a clock the test drives ---

// reloadClock is the store's clock: the tests move it, a recheck is never waited for.
type reloadClock struct{ nanos atomic.Int64 }

func (c *reloadClock) now() time.Time          { return time.Unix(0, c.nanos.Load()) }
func (c *reloadClock) advance(d time.Duration) { c.nanos.Add(int64(d)) }

type clockedStore struct {
	*certStore
	clock *reloadClock
	path  string
	logs  *capturedLog
	root  *pki
}

func newClockedStore(t *testing.T) (*clockedStore, *pki) {
	t.Helper()
	root := newPKI(t, nil, "clocked root", true)
	first := newPKI(t, root, "localhost", false)
	path := filepath.Join(t.TempDir(), "pfb_dns_cert.pem")
	write(t, path, chainPEM(t, first))
	logs := &capturedLog{}
	store, err := newCertStore(path, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	clock := &reloadClock{}
	clock.nanos.Store(time.Now().UnixNano())
	store.now, store.checked = clock.now, clock.now()
	return &clockedStore{certStore: store, clock: clock, path: path, logs: logs, root: root}, first
}

func write(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

// served is the leaf the next handshake would present.
func (s *clockedStore) served(t *testing.T) []byte {
	t.Helper()
	cert, err := s.getCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	return cert.Certificate[0]
}

func (s *clockedStore) requireServed(t *testing.T, want *pki, when string) {
	t.Helper()
	if got := s.served(t); !bytes.Equal(got, want.der) {
		t.Fatalf("%s: a handshake got another certificate than serial %v", when, want.cert.SerialNumber)
	}
}

// A new content is served from the first handshake after a second has gone by since the file was last looked at;
// until then the previous one is, and the same content is never read as a new one.
func TestCertificateFileIsLookedAtOnceASecondAtMost(t *testing.T) {
	s, first := newClockedStore(t)
	second, third := newPKI(t, s.root, "localhost", false), newPKI(t, s.root, "localhost", false)

	s.clock.advance(10 * time.Second)
	s.requireServed(t, first, "unchanged file")
	if n := s.logs.count(); n != 0 {
		t.Fatalf("an unchanged file must log nothing, got:\n%s", s.logs.joined())
	}
	write(t, s.path, chainPEM(t, second))
	s.clock.advance(time.Second - time.Nanosecond)
	s.requireServed(t, first, "just under a second after the last look")
	s.clock.advance(time.Nanosecond)
	s.requireServed(t, second, "a second after the last look")
	write(t, s.path, chainPEM(t, third))
	s.clock.advance(500 * time.Millisecond)
	s.requireServed(t, second, "half a second after a look that found a change")
	s.clock.advance(500 * time.Millisecond)
	s.requireServed(t, third, "a second after it")
	if got := strings.Count(s.logs.joined(), "TLS certificate reloaded: "+s.path); got != 2 {
		t.Fatalf("each reload is logged once, got %d in:\n%s", got, s.logs.joined())
	}
}

// A file that does not parse, or whose key is another certificate's, leaves the previous certificate in place and is
// reported once for as long as its content stays; another bad content, or the same one coming back after a good file,
// is a new report.
func TestUnusableReplacementKeepsThePreviousCertificateAndIsReportedOnce(t *testing.T) {
	s, first := newClockedStore(t)
	other := newPKI(t, s.root, "localhost", false)
	good := chainPEM(t, first)
	half, mismatch := good[:len(good)/2], append(first.certPEM(), other.keyPEM(t)...)
	reports := func() int { return strings.Count(s.logs.joined(), "TLS certificate not reloaded: "+s.path) }
	tick := func(when string) {
		t.Helper()
		s.clock.advance(time.Second)
		s.requireServed(t, first, when)
	}

	write(t, s.path, half)
	for i := range 5 {
		tick("half-written file, look " + string(rune('1'+i)))
	}
	if reports() != 1 {
		t.Fatalf("the same bad content is reported once, got:\n%s", s.logs.joined())
	}
	write(t, s.path, mismatch)
	tick("key of another certificate")
	tick("key of another certificate, again")
	if reports() != 2 || !strings.Contains(s.logs.joined(), "does not match") {
		t.Fatalf("another bad content is a report of its own, naming the mismatch; got:\n%s", s.logs.joined())
	}

	second := newPKI(t, s.root, "localhost", false)
	write(t, s.path, chainPEM(t, second))
	s.clock.advance(time.Second)
	s.requireServed(t, second, "the good file")
	write(t, s.path, half)
	s.clock.advance(time.Second)
	s.requireServed(t, second, "the bad content again")
	if reports() != 3 {
		t.Fatalf("a condition that returns is reported again, got:\n%s", s.logs.joined())
	}
}

// A file that cannot be read for a while leaves the previous certificate in place and is reported once; its return
// with the content the store already serves is not a reload.
func TestUnreadableCertificateFileKeepsThePreviousCertificateAndIsReportedOnce(t *testing.T) {
	s, first := newClockedStore(t)
	if err := os.Remove(s.path); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		s.clock.advance(time.Second)
		s.requireServed(t, first, "file gone")
	}
	if got := strings.Count(s.logs.joined(), "cannot read"); got != 1 {
		t.Fatalf("an unreadable file is reported once, got %d in:\n%s", got, s.logs.joined())
	}
	write(t, s.path, chainPEM(t, first))
	s.clock.advance(time.Second)
	s.requireServed(t, first, "file back with the same content")
	if strings.Contains(s.logs.joined(), "TLS certificate reloaded") {
		t.Fatalf("the same certificate is not a reload:\n%s", s.logs.joined())
	}
}

// Handshakes on every transport share one store: a replacement while they run never hands out nothing or a mixture.
func TestHandshakesDuringAReplacementGetOneCertificateOrTheOther(t *testing.T) {
	s, first := newClockedStore(t)
	second := newPKI(t, s.root, "localhost", false)
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
				cert, err := s.getCertificate(nil)
				if err != nil || cert == nil || len(cert.Certificate) != 1 ||
					(!bytes.Equal(cert.Certificate[0], first.der) && !bytes.Equal(cert.Certificate[0], second.der)) {
					bad.Add(1)
				}
			}
		})
	}
	for i := range 40 {
		content := chainPEM(t, first)
		if i%2 == 0 {
			content = chainPEM(t, second)
		}
		write(t, s.path, content)
		s.clock.advance(time.Second)
	}
	close(stop)
	wg.Wait()
	if n := bad.Load(); n != 0 {
		t.Fatalf("%d handshakes got no certificate or one that was never in the file", n)
	}
}

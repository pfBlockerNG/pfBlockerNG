package feedfetch_test

// Network stand-ins of the parity corpus beyond plain HTTP servers (the schema is documented in corpus_test.go): the
// request log shared with the Python fixture, the test PKI, and the forward proxy, which is the same script the PHP
// runner starts (tests/feedfetch/fixtures/net_fixture.py).

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

const netFixture = "../../../tests/feedfetch/fixtures/net_fixture.py"

// serverSpec is a scenario's "servers" entry: a name, or {name, tls: true, cert: "trusted"|"untrusted", plain_too}, or
// {name, kind: "ftp", ...}: an ftp server (tests/feedfetch/fixtures/ftp_server.py) with the options it reads.
type serverSpec struct {
	Name     string            `json:"name"`
	TLS      bool              `json:"tls"`
	Cert     string            `json:"cert"`
	PlainToo bool              `json:"plain_too"`
	Kind     string            `json:"kind,omitempty"`
	Users    map[string]string `json:"users,omitempty"`
	Epsv     *bool             `json:"epsv,omitempty"`
	PasvHost string            `json:"pasv_host,omitempty"`
	Replies  map[string]string `json:"replies,omitempty"`
	Quirk    string            `json:"quirk,omitempty"`
}

func (s *serverSpec) UnmarshalJSON(b []byte) error {
	var name string
	if json.Unmarshal(b, &name) == nil {
		*s = serverSpec{Name: name}
		return nil
	}
	type plain serverSpec
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields() // a custom unmarshaler does not inherit the scenario decoder's strictness
	return dec.Decode((*plain)(s))
}

type credentials struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

// proxySpec is a scenario's system proxy: Server names the forward proxy (or "closed": nothing listening), Auth is the
// user and password the system proxy holds, Requires the Basic credentials the proxy demands.
type proxySpec struct {
	Server   string       `json:"server"`
	Auth     *credentials `json:"auth"`
	Requires *credentials `json:"requires"`
}

// requestLog is the file the Go servers and the Python fixture both append one JSON record per line to, so a request's
// order across them is what happened.
type requestLog struct {
	mu   sync.Mutex
	path string
}

func (l *requestLog) add(t testing.TB, rec map[string]string) {
	t.Helper()
	line, err := json.Marshal(rec)
	if err != nil {
		t.Error(err)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		t.Error(err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		t.Error(err)
	}
}

func (l *requestLog) reset(t testing.TB) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.WriteFile(l.path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (l *requestLog) read(t testing.TB) []map[string]string {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	raw, err := os.ReadFile(l.path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	out := []map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		rec := map[string]string{}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("request log line %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

// tlsListener serves TLS on ln and calls connected for each TLS connection once its first byte has arrived, before the
// handshake starts: the fetcher's attempt, whatever it makes of the certificate. With plainToo that first byte decides
// (0x16 is a TLS handshake) and any other connection is served as plain http on the same port, unrecorded.
type tlsListener struct {
	net.Listener
	cfg       *tls.Config
	plainToo  bool
	connected func()
}

func (l tlsListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &sniffConn{Conn: c, l: l}, nil
}

// sniffConn decides at its first Read or Write which protocol the connection speaks.
type sniffConn struct {
	net.Conn
	l    tlsListener
	once sync.Once
	rw   net.Conn
}

// replayConn reads through the buffer that peeked at the first byte.
type replayConn struct {
	net.Conn
	r *bufio.Reader
}

func (c replayConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *sniffConn) decide() {
	br := bufio.NewReader(c.Conn)
	first, err := br.Peek(1)
	conn := replayConn{Conn: c.Conn, r: br}
	if !c.l.plainToo || (err == nil && first[0] == 0x16) {
		c.l.connected()
		c.rw = tls.Server(conn, c.l.cfg)
		return
	}
	c.rw = conn
}

func (c *sniffConn) Read(p []byte) (int, error) {
	c.once.Do(c.decide)
	return c.rw.Read(p)
}

func (c *sniffConn) Write(p []byte) (int, error) {
	c.once.Do(c.decide)
	return c.rw.Write(p)
}

// corpusPKI is the corpus's test PKI, made when a scenario needs it: a CA, a leaf it signed ("trusted") and a
// self-signed leaf it did not sign ("untrusted"). Both leaves name feed.example and rdr.example only, never an IP address.
type corpusPKI struct {
	pool  *x509.CertPool
	certs map[string]tls.Certificate
}

func newCorpusPKI(t testing.TB) corpusPKI {
	t.Helper()
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	now := time.Now()
	sign := func(tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	caKey := key()
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pfb corpus test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	ca := sign(caTmpl, caTmpl, &caKey.PublicKey, caKey)
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	leaf := func(serial int64, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) tls.Certificate {
		k := key()
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "feed.example"},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(48 * time.Hour),
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:    []string{"feed.example", "rdr.example"},
		}
		if parent == nil {
			parent, parentKey = tmpl, k
		}
		cert := sign(tmpl, parent, &k.PublicKey, parentKey)
		return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: k}
	}
	return corpusPKI{pool: pool, certs: map[string]tls.Certificate{
		"trusted":   leaf(2, ca, caKey),
		"untrusted": leaf(3, nil, nil),
	}}
}

// startNetFixture starts net_fixture.py with args and returns the port it reports once it listens. The 10 s cap is a
// watchdog for a hung start, never the readiness signal; the process dies with the test.
func startNetFixture(t testing.TB, args ...string) string {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("the corpus's forward-proxy fixture needs python3 on PATH: %v", err)
	}
	cmd := exec.Command(python, append([]string{netFixture}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	ready := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(out).ReadString('\n')
		ready <- strings.TrimSpace(line)
	}()
	select {
	case line := <-ready:
		if port, ok := strings.CutPrefix(line, "ready "); ok {
			return port
		}
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatalf("net_fixture.py %v did not report ready: %q\n%s", args, line, stderr.String())
	case <-time.After(10 * time.Second):
		t.Fatalf("net_fixture.py %v did not start within 10 s", args)
	}
	return ""
}

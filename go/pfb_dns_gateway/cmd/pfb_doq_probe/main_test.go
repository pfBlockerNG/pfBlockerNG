package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/dns/dnsmessage"
)

// fakeDoQ is a DoQ server of the test's own: ALPN doq, one framed query per stream.
type fakeDoQ struct {
	t       *testing.T
	port    int
	caPath  string // the server certificate as a PEM file: it is its own trust anchor
	queries chan dnsmessage.Message
	names   chan string // the SNI of each handshake
	release chan struct{}
}

// respond builds the reply to a query; nil resets the stream, and a handler that returns after <-release sends nothing.
type respondFunc func(f *fakeDoQ, q dnsmessage.Message) []byte

func newCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, path
}

func startFakeDoQ(t *testing.T, respond respondFunc) *fakeDoQ {
	t.Helper()
	cert, caPath := newCert(t)
	f := &fakeDoQ{t: t, caPath: caPath, queries: make(chan dnsmessage.Message, 16), names: make(chan string, 16), release: make(chan struct{})}
	conf := &tls.Config{
		Certificates: []tls.Certificate{cert}, NextProtos: []string{"doq"}, MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) { f.names <- h.ServerName; return nil, nil },
	}
	ln, err := quic.ListenAddr("127.0.0.1:0", conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.port = ln.Addr().(*net.UDPAddr).Port
	t.Cleanup(func() { close(f.release); _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				for {
					s, err := conn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go f.serve(s, respond)
				}
			}()
		}
	}()
	return f
}

func (f *fakeDoQ) serve(s *quic.Stream, respond respondFunc) {
	data, err := io.ReadAll(s)
	if err != nil || len(data) < 2 {
		return
	}
	var q dnsmessage.Message
	if q.Unpack(data[2:]) != nil {
		return
	}
	f.queries <- q
	reply := respond(f, q)
	if reply == nil {
		s.CancelWrite(2)
		return
	}
	_, _ = s.Write(binary.BigEndian.AppendUint16(nil, uint16(len(reply))))
	_, _ = s.Write(reply)
	_ = s.Close()
}

func (f *fakeDoQ) server() string { return "127.0.0.1:" + strconv.Itoa(f.port) }

// answer packs the reply to q: the question echoed, the given rcode and records.
func answer(q dnsmessage.Message, rcode dnsmessage.RCode, rrs ...dnsmessage.Resource) []byte {
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: true, RecursionAvailable: true, RCode: rcode},
		Questions: q.Questions, Answers: rrs,
	}
	out, err := m.Pack()
	if err != nil {
		panic(err)
	}
	return out
}

func rr(name string, body dnsmessage.ResourceBody, typ dnsmessage.Type) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET, TTL: 30}, Body: body}
}

func runProbe(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- run(args, &out, &errOut) }()
	select {
	case code = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("STUCK/ENVIRONMENT: the probe did not return")
	}
	return code, out.String(), errOut.String()
}

func nextQuery(t *testing.T, f *fakeDoQ) dnsmessage.Message {
	t.Helper()
	select {
	case q := <-f.queries:
		return q
	case <-time.After(10 * time.Second):
		t.Fatal("STUCK/ENVIRONMENT: the server never saw a query")
		return dnsmessage.Message{}
	}
}

func a(ip [4]byte) dnsmessage.ResourceBody     { return &dnsmessage.AResource{A: ip} }
func aaaa(ip [16]byte) dnsmessage.ResourceBody { return &dnsmessage.AAAAResource{AAAA: ip} }

// T19: the answer section is printed one RR per line after the rcode, exit 0.
func TestProbePrintsTheRcodeAndEveryAnswer(t *testing.T) {
	cases := []struct {
		name    string
		qtype   string
		respond respondFunc
		want    string
	}{
		{"A", "A", func(_ *fakeDoQ, q dnsmessage.Message) []byte {
			return answer(q, dnsmessage.RCodeSuccess, rr("www.example.", a([4]byte{192, 0, 2, 1}), dnsmessage.TypeA))
		}, "rcode NOERROR\nanswer www.example. A 192.0.2.1\n"},
		{"AAAA", "AAAA", func(_ *fakeDoQ, q dnsmessage.Message) []byte {
			ip := [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}
			return answer(q, dnsmessage.RCodeSuccess, rr("www.example.", aaaa(ip), dnsmessage.TypeAAAA))
		}, "rcode NOERROR\nanswer www.example. AAAA 2001:db8::1\n"},
		{"a CNAME chain", "A", func(_ *fakeDoQ, q dnsmessage.Message) []byte {
			return answer(q, dnsmessage.RCodeSuccess,
				rr("www.example.", &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("edge.example.")}, dnsmessage.TypeCNAME),
				rr("edge.example.", a([4]byte{192, 0, 2, 9}), dnsmessage.TypeA))
		}, "rcode NOERROR\nanswer www.example. CNAME edge.example.\nanswer edge.example. A 192.0.2.9\n"},
		{"TXT", "TXT", func(_ *fakeDoQ, q dnsmessage.Message) []byte {
			return answer(q, dnsmessage.RCodeSuccess, rr("www.example.", &dnsmessage.TXTResource{TXT: []string{"hello world", "two"}}, dnsmessage.TypeTXT))
		}, "rcode NOERROR\nanswer www.example. TXT \"hello world\" \"two\"\n"},
		{"MX", "MX", func(_ *fakeDoQ, q dnsmessage.Message) []byte {
			return answer(q, dnsmessage.RCodeSuccess, rr("www.example.", &dnsmessage.MXResource{Pref: 10, MX: dnsmessage.MustNewName("mail.example.")}, dnsmessage.TypeMX))
		}, "rcode NOERROR\nanswer www.example. MX 10 mail.example.\n"},
		{"a type with no name", "65280", func(_ *fakeDoQ, q dnsmessage.Message) []byte {
			return answer(q, dnsmessage.RCodeSuccess, rr("www.example.", &dnsmessage.UnknownResource{Type: 65280, Data: []byte{0x0a, 0x0b, 0x0c}}, dnsmessage.Type(65280)))
		}, "rcode NOERROR\nanswer www.example. 65280 \\# 3 0a0b0c\n"},
		{"NXDOMAIN", "A", func(_ *fakeDoQ, q dnsmessage.Message) []byte { return answer(q, dnsmessage.RCodeNameError) }, "rcode NXDOMAIN\n"},
		{"REFUSED", "A", func(_ *fakeDoQ, q dnsmessage.Message) []byte { return answer(q, dnsmessage.RCodeRefused) }, "rcode REFUSED\n"},
		{"SERVFAIL", "A", func(_ *fakeDoQ, q dnsmessage.Message) []byte { return answer(q, dnsmessage.RCodeServerFailure) }, "rcode SERVFAIL\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := startFakeDoQ(t, c.respond)
			code, stdout, stderr := runProbe(t, "-server", f.server(), "-name", "www.example", "-type", c.qtype, "-ca", f.caPath)
			if code != 0 || stdout != c.want {
				t.Fatalf("exit %d (stderr %q)\n got stdout  %q\n want stdout %q", code, stderr, stdout, c.want)
			}
		})
	}
}

// The query on the wire: Message ID 0 (RFC 9250 4.2.1), recursion desired, one question of the asked type, the
// name made absolute.
func TestProbeSendsOneQuestionWithMessageIDZero(t *testing.T) {
	f := startFakeDoQ(t, func(_ *fakeDoQ, q dnsmessage.Message) []byte { return answer(q, dnsmessage.RCodeSuccess) })
	if code, _, stderr := runProbe(t, "-server", f.server(), "-name", "WWW.Example", "-type", "aaaa", "-ca", f.caPath); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	q := nextQuery(t, f)
	if q.ID != 0 || !q.RecursionDesired || q.Response || len(q.Questions) != 1 ||
		q.Questions[0].Name.String() != "WWW.Example." || q.Questions[0].Type != dnsmessage.TypeAAAA || q.Questions[0].Class != dnsmessage.ClassINET {
		t.Fatalf("query on the wire: %+v", q)
	}
}

// Without -type the probe asks for A.
func TestProbeDefaultTypeIsA(t *testing.T) {
	f := startFakeDoQ(t, func(_ *fakeDoQ, q dnsmessage.Message) []byte { return answer(q, dnsmessage.RCodeSuccess) })
	if code, _, stderr := runProbe(t, "-server", f.server(), "-name", "example.", "-ca", f.caPath); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if q := nextQuery(t, f); q.Questions[0].Type != dnsmessage.TypeA {
		t.Fatalf("default type: got %v, want A", q.Questions[0].Type)
	}
}

// -sni is what the server sees as the server name; by default it is the host of -server.
func TestProbeSNI(t *testing.T) {
	f := startFakeDoQ(t, func(_ *fakeDoQ, q dnsmessage.Message) []byte { return answer(q, dnsmessage.RCodeSuccess) })
	if code, _, stderr := runProbe(t, "-server", "localhost:"+strconv.Itoa(f.port), "-name", "example.", "-ca", f.caPath); code != 0 {
		t.Fatalf("default SNI: exit %d: %s", code, stderr)
	}
	if got := <-f.names; got != "localhost" {
		t.Fatalf("default SNI %q, want the host of -server", got)
	}
	if code, _, stderr := runProbe(t, "-server", f.server(), "-name", "example.", "-insecure", "-sni", "dns.example.net"); code != 0 {
		t.Fatalf("-sni: exit %d: %s", code, stderr)
	}
	if got := <-f.names; got != "dns.example.net" {
		t.Fatalf("-sni: the server saw %q, want dns.example.net", got)
	}
}

// Certificate checking: -ca trusts exactly that file; no flag trusts the system roots (which do not know the test
// certificate); -insecure skips the check.
func TestProbeCertificateVerification(t *testing.T) {
	respond := func(_ *fakeDoQ, q dnsmessage.Message) []byte { return answer(q, dnsmessage.RCodeSuccess) }
	f := startFakeDoQ(t, respond)
	other := startFakeDoQ(t, respond)
	if code, _, _ := runProbe(t, "-server", f.server(), "-name", "example.", "-timeout", "5s"); code != 1 {
		t.Fatalf("system roots must not accept the test certificate: exit %d, want 1", code)
	}
	if code, out, _ := runProbe(t, "-server", f.server(), "-name", "example.", "-ca", other.caPath); code != 1 || out != "" {
		t.Fatalf("the CA of another server must not verify this one: exit %d stdout %q, want 1 and nothing", code, out)
	}
	if code, _, stderr := runProbe(t, "-server", f.server(), "-name", "example.", "-insecure"); code != 0 {
		t.Fatalf("-insecure: exit %d: %s", code, stderr)
	}
}

// Exit 1 whenever no DNS response arrived: and nothing on stdout.
func TestProbeExitsOneWhenNoResponseArrives(t *testing.T) {
	reset := startFakeDoQ(t, func(*fakeDoQ, dnsmessage.Message) []byte { return nil })
	silent := startFakeDoQ(t, func(f *fakeDoQ, _ dnsmessage.Message) []byte { <-f.release; return nil })
	garbage := startFakeDoQ(t, func(*fakeDoQ, dnsmessage.Message) []byte { return []byte{1, 2, 3} })
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() }) // a UDP port that never answers a QUIC handshake
	cases := []struct {
		name   string
		server string
		ca     string
	}{
		{"the stream is reset", reset.server(), reset.caPath},
		{"no answer before the timeout", silent.server(), silent.caPath},
		{"an answer that is not a DNS message", garbage.server(), garbage.caPath},
		{"nothing listens", udp.LocalAddr().String(), reset.caPath},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, stdout, stderr := runProbe(t, "-server", c.server, "-name", "example.", "-ca", c.ca, "-timeout", "700ms")
			if code != 1 || stdout != "" || stderr == "" {
				t.Fatalf("exit %d stdout %q stderr %q; want exit 1, no stdout, a reason on stderr", code, stdout, stderr)
			}
		})
	}
}

func TestProbeCAFileProblemsAreRuntimeErrors(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"absent": filepath.Join(t.TempDir(), "absent.pem"), "no certificate in it": empty} {
		if code, _, stderr := runProbe(t, "-server", "127.0.0.1:1", "-name", "example.", "-ca", path); code != 1 || stderr == "" {
			t.Fatalf("-ca file %s: exit %d stderr %q, want exit 1 and a reason", name, code, stderr)
		}
	}
}

// Exit 2: anything wrong with the command line, before any network use.
func TestProbeUsageErrorsExitTwo(t *testing.T) {
	cases := map[string][]string{
		"no arguments":                {},
		"no -name":                    {"-server", "127.0.0.1:853"},
		"no -server":                  {"-name", "example."},
		"empty -name":                 {"-server", "127.0.0.1:853", "-name", ""},
		"-server without a port":      {"-server", "127.0.0.1", "-name", "example."},
		"-server with port 0":         {"-server", "127.0.0.1:0", "-name", "example."},
		"-ca and -insecure together":  {"-server", "127.0.0.1:853", "-name", "example.", "-ca", "x.pem", "-insecure"},
		"unknown -type":               {"-server", "127.0.0.1:853", "-name", "example.", "-type", "NOPE"},
		"-type out of range":          {"-server", "127.0.0.1:853", "-name", "example.", "-type", "70000"},
		"-timeout zero":               {"-server", "127.0.0.1:853", "-name", "example.", "-timeout", "0s"},
		"-timeout negative":           {"-server", "127.0.0.1:853", "-name", "example.", "-timeout", "-1s"},
		"-timeout not a duration":     {"-server", "127.0.0.1:853", "-name", "example.", "-timeout", "soon"},
		"unknown flag":                {"-server", "127.0.0.1:853", "-name", "example.", "-bogus"},
		"an argument that is no flag": {"-server", "127.0.0.1:853", "-name", "example.", "extra"},
		"a name label over 63 bytes":  {"-server", "127.0.0.1:853", "-name", strings.Repeat("a", 64) + ".example."},
		"a name over 255 bytes":       {"-server", "127.0.0.1:853", "-name", strings.Repeat("abcdefgh.", 32)},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runProbe(t, args...)
			if code != 2 || stdout != "" || stderr == "" {
				t.Fatalf("exit %d stdout %q stderr %q; want exit 2, no stdout, a usage message on stderr", code, stdout, stderr)
			}
		})
	}
}

func TestProbeHelpExitsZero(t *testing.T) {
	if code, _, stderr := runProbe(t, "-h"); code != 0 || !strings.Contains(stderr, "-server") {
		t.Fatalf("-h: exit %d, stderr %q; want 0 and the flag list", code, stderr)
	}
}

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// chainConfig is a config.xml whose certificate hangs below an intermediate CA below a root CA.
func chainConfig(t *testing.T, extra ...string) (path string, leaf, mid, root *pki) {
	t.Helper()
	root = newPKI(t, nil, "chain root", true)
	mid = newPKI(t, root, "chain intermediate", true)
	leaf = newPKI(t, mid, "localhost", false)
	sections := []string{
		unboundEl(el("sslcertref", testRefid)),
		certEl(testRefid, el("caref", "mid"), el("crt", b64(leaf.certPEM())), el("prv", b64(leaf.keyPEM(t)))),
		caEl("mid", el("caref", "root"), el("crt", b64(mid.certPEM()))),
		caEl("root", el("crt", b64(root.certPEM()))),
	}
	return writeConfig(t, configXML(append(sections, extra...)...)), leaf, mid, root
}

// T1: the certificate, then each CA up its chain, exactly what Unbound is given.
func TestCertificateChainIsServedLeafFirstThenTheCAs(t *testing.T) {
	path, leaf, mid, root := chainConfig(t)
	s, err := readTLSSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]byte{leaf.der, mid.der, root.der}
	if len(s.cert.Certificate) != len(want) {
		t.Fatalf("chain length: got %d certificates, want %d (leaf, intermediate, root)", len(s.cert.Certificate), len(want))
	}
	for i, der := range want {
		if !bytes.Equal(s.cert.Certificate[i], der) {
			t.Fatalf("certificate %d of the chain is not the expected one (want order leaf, intermediate, root)", i)
		}
	}
}

// A CA that is missing or a caref loop ends the chain instead of failing or looping.
func TestCAChainStopsAtAMissingCAAndAtALoop(t *testing.T) {
	root := newPKI(t, nil, "root", true)
	a := newPKI(t, root, "a", true)
	b := newPKI(t, a, "b", true)
	leaf := newPKI(t, b, "localhost", false)
	cert := certEl(testRefid, el("caref", "a"), el("crt", b64(leaf.certPEM())), el("prv", b64(leaf.keyPEM(t))))
	cases := []struct {
		name string
		cas  []string
		want [][]byte
	}{
		{"missing CA", []string{caEl("a", el("caref", "gone"), el("crt", b64(a.certPEM())))}, [][]byte{leaf.der, a.der}},
		{"caref loop", []string{
			caEl("a", el("caref", "b"), el("crt", b64(a.certPEM()))),
			caEl("b", el("caref", "a"), el("crt", b64(b.certPEM()))),
		}, [][]byte{leaf.der, a.der, b.der}},
		{"no CA at all", nil, [][]byte{leaf.der}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := writeConfig(t, configXML(append([]string{unboundEl(el("sslcertref", testRefid)), cert}, c.cas...)...))
			s, err := readTLSSettings(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(s.cert.Certificate) != len(c.want) {
				t.Fatalf("got %d certificates, want %d", len(s.cert.Certificate), len(c.want))
			}
			for i := range c.want {
				if !bytes.Equal(s.cert.Certificate[i], c.want[i]) {
					t.Fatalf("certificate %d differs from the expected chain", i)
				}
			}
		})
	}
}

// T2: every way the certificate can be unusable names its reason; the error mentions the file.
func TestUnusableCertificateIsReportedWithTheReason(t *testing.T) {
	leaf := newPKI(t, nil, "localhost", false)
	crt, prv := b64(leaf.certPEM()), b64(leaf.keyPEM(t))
	other := newPKI(t, nil, "localhost", false)
	legacyEncrypted := pem.EncodeToMemory(&pem.Block{ // the Proc-Type header openssl writes for traditional encrypted keys
		Type: "EC PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00112233445566778899AABBCCDDEEFF"},
		Bytes: bytes.Repeat([]byte{7}, 32),
	})
	pkcs8Encrypted := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: bytes.Repeat([]byte{7}, 64)})
	notWellFormed := `<?xml version="1.0"?><pfsense><unbound><sslcertref>x</unbound></pfsense>`

	cases := []struct {
		name string
		xml  string
		want string
	}{
		{"sslcertref empty", configXML(unboundEl(el("sslcertref", "")), certEl(testRefid, el("crt", crt), el("prv", prv))), "unbound/sslcertref is empty"},
		{"sslcertref element missing", configXML(unboundEl(el("enable", "")), certEl(testRefid, el("crt", crt), el("prv", prv))), "unbound/sslcertref is empty"},
		{"no unbound section", configXML(certEl(testRefid, el("crt", crt), el("prv", prv))), "unbound/sslcertref is empty"},
		{"unknown refid", configXML(unboundEl(el("sslcertref", "nope")), certEl(testRefid, el("crt", crt), el("prv", prv))), `no <cert> with refid "nope"`},
		{"cert element without refid", configXML(unboundEl(el("sslcertref", testRefid)), "<cert>"+el("crt", crt)+el("prv", prv)+"</cert>"), "no <cert> with refid"},
		{"crt is not base64", configXML(unboundEl(el("sslcertref", testRefid)), certEl(testRefid, el("crt", "!!not base64!!"), el("prv", prv))), "crt of <cert>"},
		{"prv is not base64", configXML(unboundEl(el("sslcertref", testRefid)), certEl(testRefid, el("crt", crt), el("prv", "%%%"))), "prv of <cert>"},
		{"crt element empty", configXML(unboundEl(el("sslcertref", testRefid)), certEl(testRefid, el("crt", ""), el("prv", prv))), "has no crt"},
		{"crt element missing", configXML(unboundEl(el("sslcertref", testRefid)), certEl(testRefid, el("prv", prv))), "has no crt"},
		{"prv element empty", configXML(unboundEl(el("sslcertref", testRefid)), certEl(testRefid, el("crt", crt), el("prv", ""))), "has no prv"},
		{"prv element missing", configXML(unboundEl(el("sslcertref", testRefid)), certEl(testRefid, el("crt", crt))), "has no prv"},
		{"crt is base64 of something that is not PEM", configXML(unboundEl(el("sslcertref", testRefid)), certEl(testRefid, el("crt", b64([]byte("hello"))), el("prv", prv))), "cannot load the DNS Resolver's certificate and key"},
		{"key does not belong to the certificate", configXML(unboundEl(el("sslcertref", testRefid)), certEl(testRefid, el("crt", crt), el("prv", b64(other.keyPEM(t))))), "cannot load the DNS Resolver's certificate and key"},
		{"key encrypted (traditional PEM)", configXML(unboundEl(el("sslcertref", testRefid)), certEl(testRefid, el("crt", crt), el("prv", b64(legacyEncrypted)))), "encrypted with a passphrase"},
		{"key encrypted (PKCS#8)", configXML(unboundEl(el("sslcertref", testRefid)), certEl(testRefid, el("crt", crt), el("prv", b64(pkcs8Encrypted)))), "encrypted with a passphrase"},
		{"CA with invalid base64 crt", configXML(unboundEl(el("sslcertref", testRefid)), certEl(testRefid, el("caref", "ca"), el("crt", crt), el("prv", prv)), caEl("ca", el("crt", "$$$"))), "crt of <ca>"},
		{"config.xml not well-formed", notWellFormed, "not well-formed XML"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := writeConfig(t, c.xml)
			_, err := readTLSSettings(path)
			if err == nil {
				t.Fatalf("an unusable certificate (%s) was accepted", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error:\n got  %v\n want it to contain %q", err, c.want)
			}
			if !strings.Contains(err.Error(), path) {
				t.Fatalf("the error must name the file %s, got: %v", path, err)
			}
		})
	}
	t.Run("config.xml absent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "absent.xml")
		_, err := readTLSSettings(path)
		if err == nil || !strings.Contains(err.Error(), "cannot read") || !strings.Contains(err.Error(), path) {
			t.Fatalf("want a cannot-read error naming %s, got %v", path, err)
		}
	})
}

// T3: tlsport is the DoT port when it is a port, 853 otherwise.
func TestDoTPortComesFromTlsportAnd853WhenItIsNotAPort(t *testing.T) {
	leaf := newPKI(t, nil, "localhost", false)
	cert := certEl(testRefid, el("crt", b64(leaf.certPEM())), el("prv", b64(leaf.keyPEM(t))))
	cases := []struct {
		name    string
		tlsport string // "-" leaves the element out
		want    int
	}{
		{"unset", "-", 853}, {"empty", "", 853}, {"letters", "abc", 853}, {"above 65535", "70000", 853},
		{"zero", "0", 853}, {"negative", "-5", 853}, {"huge", "99999999999999999999", 853}, {"padded with spaces", " 8853 ", 8853},
		{"8853", "8853", 8853}, {"65535", "65535", 65535}, {"1", "1", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			children := []string{el("sslcertref", testRefid)}
			if c.tlsport != "-" {
				children = append(children, el("tlsport", c.tlsport))
			}
			s, err := readTLSSettings(writeConfig(t, configXML(unboundEl(children...), cert)))
			if err != nil {
				t.Fatal(err)
			}
			if s.port != c.want {
				t.Fatalf("tlsport %q: got DoT port %d, want %d", c.tlsport, s.port, c.want)
			}
		})
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
			xml := configXML(unboundEl(el("sslcertref", testRefid)), certEl(testRefid, el("crt", b64(c.leaf.certPEM())), el("prv", b64(c.key))))
			s, err := readTLSSettings(writeConfig(t, xml))
			if err != nil {
				t.Fatalf("a %s key must load: %v", c.name, err)
			}
			if len(s.cert.Certificate) != 1 || !bytes.Equal(s.cert.Certificate[0], c.leaf.der) {
				t.Fatalf("the loaded certificate is not the configured one")
			}
		})
	}
}

// Whitespace inside the base64 text (pfSense wraps nothing, but an editor might) is ignored, as in the Python reader.
func TestBase64TextWithWhitespaceLoads(t *testing.T) {
	leaf := newPKI(t, nil, "localhost", false)
	wrap := func(s string) string { return "\n  " + s[:20] + "\r\n\t" + s[20:] + "\n" }
	xml := configXML(unboundEl(el("sslcertref", testRefid)), certEl(testRefid, el("crt", wrap(b64(leaf.certPEM()))), el("prv", wrap(b64(leaf.keyPEM(t))))))
	if _, err := readTLSSettings(writeConfig(t, xml)); err != nil {
		t.Fatalf("whitespace inside base64 must be ignored: %v", err)
	}
}

// DoT and DoH speak TLS 1.2 or later; DoQ is TLS 1.3 with ALPN doq; DoH offers HTTP/2 first.
func TestTLSConfigsPerTransport(t *testing.T) {
	m := newTLSMaterial(t)
	dot, doh, doq := m.settings.dot(), m.settings.doh(), m.settings.doq()
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
		if len(c.Certificates) != 1 {
			t.Fatalf("%s serves %d certificates, want the Resolver's one", name, len(c.Certificates))
		}
	}
}

// The files read here are unaffected by who runs the test: a config.xml that is not readable is a reason, not a crash.
func TestUnreadableConfigIsAReason(t *testing.T) {
	dir := t.TempDir()
	_, err := readTLSSettings(dir) // a directory
	if err == nil || !strings.Contains(err.Error(), "cannot read") {
		t.Fatalf("want a cannot-read error for a directory, got %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "empty.xml"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = readTLSSettings(filepath.Join(dir, "empty.xml"))
	if err == nil {
		t.Fatal("an empty config.xml has no certificate")
	}
}

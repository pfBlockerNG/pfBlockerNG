package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

// Fuzz targets for what the gateway parses from outside: the decider's frames, Unbound's config rows and the DoH
// request. `go test` runs each over the corpus committed in testdata/fuzz/<target>/ (the run-gates Go step does that,
// at no cost to speak of); `go test -fuzz=<target> -fuzztime=30s` explores from it. A crasher the fuzzer finds is
// minimised into the same directory and stays a regression test.

// A frame the decoder accepts is one the encoder writes back byte for byte, whatever bytes came in; one it refuses is
// refused with the error kind its callers act on (a clean end, a torn frame, a protocol violation), never a panic.
func FuzzReadFrame(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		typ, id, payload, err := readFrame(bytes.NewReader(data))
		if len(data) >= 4 { // a length outside 5..maxFrameLen is refused before any payload is read
			if n := binary.BigEndian.Uint32(data); n < 5 || n > maxFrameLen {
				var pe protocolError
				if !errors.As(err, &pe) {
					t.Fatalf("readFrame(%x…) with the length %d returned err %v, want a protocolError", data[:4], n, err)
				}
			}
		}
		if err != nil {
			var pe protocolError
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.As(err, &pe) {
				t.Fatalf("readFrame(%x) failed with %T %v, want EOF, an unexpected EOF or a protocolError", data, err, err)
			}
			return
		}
		if typ < frameQuery || typ > frameReady || len(payload) > maxFrameLen-5 {
			t.Fatalf("readFrame(%x) returned type %d with %d payload bytes, outside the protocol", data, typ, len(payload))
		}
		var back bytes.Buffer
		if err := writeFrame(&back, typ, id, payload); err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(data, back.Bytes()) {
			t.Fatalf("the frame read from %x writes back as %x, not the bytes it came from", data, back.Bytes())
		}
	})
}

// An access-control or implicit-allow row either parses to a netblock with no host bits and no zone, and to an action
// the matcher knows, or it is ignored; and a matcher built from what parsed answers every address with a known action.
func FuzzACLRow(f *testing.F) {
	f.Fuzz(func(t *testing.T, row string) {
		var rows = map[netip.Prefix]ACLAction{}
		if prefix, action, ok := parseACLLine(row); ok {
			requireNetblock(t, row, prefix)
			requireNoZone(t, row)
			if action.String() == "" {
				t.Fatalf("%q parsed to an action with no name: %d", row, action)
			}
			rows[prefix] = action
		}
		if prefix, ok := parseImplicitRow(row); ok {
			requireNetblock(t, row, prefix)
			requireNoZone(t, row)
			rows[prefix] = ACLForward
		}
		rules := newACLRules(rows)
		for _, client := range []string{"127.0.0.1", "::1", "192.0.2.7", "2001:db8::7", "0.0.0.0", "::"} {
			if action := rules.lookup(netip.MustParseAddr(client)); action.String() == "" {
				t.Fatalf("the matcher built from %q answered %s with action %d, which has no name", row, client, action)
			}
		}
	})
}

// A netblock with a zone (fe80::1%eth0) names an interface of the gateway's host, not a client: a Prefix cannot even
// carry the zone, so it shows only as a row that parsed at all.
func requireNoZone(t *testing.T, row string) {
	t.Helper()
	if words, _ := aclWords(row); len(words) > 1 && strings.Contains(unquote(words[1]), "%") {
		t.Fatalf("%q parsed although its netblock has a zone", row)
	}
}

func requireNetblock(t *testing.T, row string, p netip.Prefix) {
	t.Helper()
	if !p.IsValid() || p != p.Masked() || p.Addr().Zone() != "" {
		t.Fatalf("%q parsed to %v: not a masked, zoneless, valid netblock", row, p)
	}
}

// What the GET parameter makes of a request is a query, or one of the three refusals RFC 8484 allows for it; a query
// is never longer than a DNS message.
func FuzzDoHGet(f *testing.F) {
	f.Add(strings.Repeat("A", maxDoHParam)) // the limits are seeds in code: written out, they would be most of the corpus
	f.Add(strings.Repeat("A", maxDoHParam+1))
	f.Fuzz(func(t *testing.T, param string) {
		r := &http.Request{Method: http.MethodGet, URL: &url.URL{Path: dohPath, RawQuery: "dns=" + url.QueryEscape(param)}, Header: http.Header{}}
		wire, status := dohWire(httptest.NewRecorder(), r)
		trimmed := strings.TrimRight(param, "=")
		switch status {
		case 0:
			if want, err := base64.RawURLEncoding.DecodeString(trimmed); err != nil || trimmed == "" || !bytes.Equal(wire, want) || len(wire) > maxWire {
				t.Fatalf("GET dns=%q was taken as %x (err %v)", param, wire, err)
			}
		case http.StatusBadRequest, http.StatusRequestEntityTooLarge:
			if wire != nil {
				t.Fatalf("GET dns=%q was refused with %d and still returned %x", param, status, wire)
			}
			if _, err := base64.RawURLEncoding.DecodeString(trimmed); status == http.StatusBadRequest && trimmed != "" && err == nil {
				t.Fatalf("GET dns=%q is valid base64url and was refused as a bad request", param)
			}
			if status == http.StatusRequestEntityTooLarge && len(trimmed) <= maxDoHParam {
				t.Fatalf("GET dns= of %d characters was refused as too large, the limit is %d", len(trimmed), maxDoHParam)
			}
		default:
			t.Fatalf("GET dns=%q got status %d", param, status)
		}
	})
}

// A POST body is the query itself when the content type says so and is at most 65535 bytes, else it is refused with
// the status RFC 8484 names for that: 415 for the type, 413 for the size.
func FuzzDoHPost(f *testing.F) {
	f.Add(dohMediaType, make([]byte, maxWire))
	f.Add(dohMediaType, make([]byte, maxWire+1))
	f.Add("text/plain", make([]byte, maxWire+1))
	f.Fuzz(func(t *testing.T, contentType string, body []byte) {
		header := http.Header{}
		header.Set("Content-Type", contentType)
		r := &http.Request{Method: http.MethodPost, URL: &url.URL{Path: dohPath}, Header: header, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}
		wire, status := dohWire(httptest.NewRecorder(), r)
		switch status {
		case 0:
			if !bytes.Equal(wire, body) || len(body) > maxWire {
				t.Fatalf("POST of %d bytes as %q was taken as %d bytes", len(body), contentType, len(wire))
			}
			if mt, _, err := mime.ParseMediaType(contentType); err != nil || mt != dohMediaType {
				t.Fatalf("a body of type %q was taken as a query: only %s is one", contentType, dohMediaType)
			}
		case http.StatusUnsupportedMediaType, http.StatusRequestEntityTooLarge:
			if wire != nil {
				t.Fatalf("POST was refused with %d and still returned %x", status, wire)
			}
			if status == http.StatusRequestEntityTooLarge && len(body) <= maxWire {
				t.Fatalf("a body of %d bytes was refused as too large, the limit is %d", len(body), maxWire)
			}
		default:
			t.Fatalf("POST of %d bytes as %q got status %d", len(body), contentType, status)
		}
	})
}

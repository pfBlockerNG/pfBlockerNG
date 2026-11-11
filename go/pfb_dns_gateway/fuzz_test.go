package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

// Fuzz targets for what the gateway parses from outside: Unbound's config rows and the DoH request. `go test` runs each
// over the corpus committed in testdata/fuzz/<target>/ (the run-gates Go step does that, at no cost to speak of); `go test
// -fuzz=<target> -fuzztime=30s` explores from it. A crasher the fuzzer finds is minimised into the same directory and stays
// a regression test.

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

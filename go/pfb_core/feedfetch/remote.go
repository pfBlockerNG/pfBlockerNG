package feedfetch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"
)

var errTooLarge = errors.New("download_too_large")

// fetchHTTP is pfb_download()'s cURL path: the connection is pinned to the vetted address, redirects are followed by
// hand with every hop re-vetted and re-pinned (at most maxRedirects), credentials and an Authorization header reach the
// feed's origin only (scheme, host and port: #1919, #1953), and each hop gets three attempts with the body reset between
// them. Only the final hop's body is kept in dst.
func (f *Fetcher) fetchHTTP(ctx context.Context, src *source, req Request, dst string, cond *validators) transfer {
	out, err := os.Create(dst)
	if err != nil {
		return transfer{reason: "download file could not be created"}
	}
	defer out.Close()

	var pin netip.Addr
	if f.Filter {
		var reason string
		if pin, reason = f.vet(ctx, src.host); reason != "" {
			return transfer{reason: reason}
		}
	}
	extra, offOrigin := splitHeaders(req.Headers)
	if cond != nil {
		if cond.etag != "" {
			extra = append([][2]string{{"If-None-Match", cond.etag}}, extra...)
			offOrigin = append([][2]string{{"If-None-Match", cond.etag}}, offOrigin...)
		} else if !cond.lastMod.IsZero() {
			ims := [2]string{"If-Modified-Since", cond.lastMod.UTC().Format(http.TimeFormat)}
			extra, offOrigin = append([][2]string{ims}, extra...), append([][2]string{ims}, offOrigin...)
		}
	}

	var t transfer
	current, scheme, host, port := strings.TrimSpace(req.URL), src.scheme, src.host, src.port
	flex := false
	for hop := 0; ; hop++ {
		onOrigin := strings.EqualFold(host, src.host) && scheme == src.scheme && port == src.port
		headers := extra
		if !onOrigin {
			headers = offOrigin
		}
		var resp *http.Response
		var lastErr error
		for attempt := 1; attempt <= attempts; attempt++ {
			if err := out.Truncate(0); err != nil {
				return transfer{reason: "download file could not be reset"}
			}
			out.Seek(0, io.SeekStart)
			resp, lastErr = f.attempt(ctx, req, current, pin, flex, onOrigin, headers, out)
			if lastErr == nil {
				break
			}
			if errors.Is(lastErr, errTooLarge) {
				return transfer{reason: "download_too_large"}
			}
			if attempt == 1 && req.Flex && tlsFailure(lastErr) {
				flex = true
				continue
			}
			if attempt < attempts && f.RetryDelay > 0 {
				select {
				case <-time.After(f.RetryDelay):
				case <-ctx.Done():
				}
			}
		}
		if lastErr != nil {
			return transfer{reason: "curl_incomplete"}
		}
		t.status = resp.StatusCode
		if v := resp.Header.Get("ETag"); v != "" {
			t.etag = v
		}
		location := strings.TrimSpace(resp.Header.Get("Location"))
		if t.status < 300 || t.status >= 400 || location == "" {
			t.lastMod, _ = http.ParseTime(resp.Header.Get("Last-Modified"))
			return t
		}
		if hop >= maxRedirects {
			return transfer{status: t.status, reason: "too many redirects"}
		}
		target, next, nextPin, reason := f.redirectTarget(ctx, location, current)
		if reason != "" {
			return transfer{status: t.status, reason: reason}
		}
		current, scheme, host, port, pin = target, next.scheme, next.host, next.portNum(), nextPin
	}
}

// attempt makes one request and, for a final answer, copies its body to out under the ceiling.
func (f *Fetcher) attempt(ctx context.Context, req Request, target string, pin netip.Addr, flex,
	onOrigin bool, headers [][2]string, out *os.File) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, req.timeout())
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Accept", "*/*")
	if f.UserAgent != "" {
		r.Header.Set("User-Agent", f.UserAgent)
	}
	hasAuth := false
	for _, h := range headers {
		r.Header.Add(h[0], h[1])
		hasAuth = hasAuth || strings.EqualFold(h[0], "Authorization")
	}
	if onOrigin && !hasAuth && (req.Username != "" || req.Password != "") {
		r.SetBasicAuth(req.Username, req.Password)
	}

	tr := f.transport(req, pin, flex)
	defer tr.CloseIdleConnections()
	resp, err := tr.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 && resp.Header.Get("Location") != "" {
		return resp, nil // a redirect page's body is never kept
	}
	limit := req.maxBytes()
	if resp.ContentLength > limit {
		return nil, errTooLarge
	}
	n, err := io.Copy(out, io.LimitReader(resp.Body, limit+1))
	if n > limit {
		return nil, errTooLarge
	}
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// transport dials host:port at the pinned address (SNI and Host stay the URL's), through the proxy when one is set,
// with a fresh connection per request and no Accept-Encoding offered (#2634: the digest is of the raw bytes).
func (f *Fetcher) transport(req Request, pin netip.Addr, flex bool) *http.Transport {
	dialer := &net.Dialer{Timeout: connectTimeout}
	if req.BindAddr.IsValid() {
		dialer.LocalAddr = &net.TCPAddr{IP: req.BindAddr.AsSlice()}
	}
	tlsConf := &tls.Config{RootCAs: f.RootCAs, MinVersion: tls.VersionTLS12}
	if flex {
		tlsConf.InsecureSkipVerify, tlsConf.MinVersion = true, tls.VersionTLS10
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Only the feed's own host is ever dialled here, except the proxy, which is not pinned.
			if _, p, err := net.SplitHostPort(addr); err == nil && pin.IsValid() && f.Proxy == nil {
				addr = net.JoinHostPort(pin.String(), p)
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:     tlsConf,
		TLSHandshakeTimeout: connectTimeout,
		DisableKeepAlives:   true,
		DisableCompression:  true,
		ForceAttemptHTTP2:   true,
	}
	if f.Proxy != nil {
		tr.Proxy = http.ProxyURL(f.Proxy)
	}
	return tr
}

// tlsFailure is what cURL reports as 35, 51 or 60: a failed handshake or certificate check.
func tlsFailure(err error) bool {
	var cert *tls.CertificateVerificationError
	var host x509.HostnameError
	var authority x509.UnknownAuthorityError
	var alert tls.AlertError
	var record tls.RecordHeaderError
	return errors.As(err, &cert) || errors.As(err, &host) || errors.As(err, &authority) ||
		errors.As(err, &alert) || errors.As(err, &record)
}

// splitHeaders parses "Name: value" headers into the list sent to the origin and the one sent off it (no Authorization).
func splitHeaders(raw []string) (all, offOrigin [][2]string) {
	for _, h := range raw {
		name, value, ok := strings.Cut(h, ":")
		if !ok || strings.TrimSpace(name) == "" {
			continue
		}
		kv := [2]string{strings.TrimSpace(name), strings.TrimSpace(value)}
		all = append(all, kv)
		if !strings.EqualFold(kv[0], "Authorization") {
			offOrigin = append(offOrigin, kv)
		}
	}
	return all, offOrigin
}

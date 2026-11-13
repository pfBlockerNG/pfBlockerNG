package feedfetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
)

// fetchFile copies a local source under the ceiling (pfb_download()'s local branch for a path).
func fetchFile(src *source, req Request, dst string) transfer {
	in, err := os.Open(src.path)
	if err != nil {
		return transfer{reason: err.Error()}
	}
	defer in.Close()
	// The file opened must be the file checked: a leaf swapped (say for a symlink) since is refused (#3911).
	if info, err := in.Stat(); err != nil || !os.SameFile(info, src.file) {
		return transfer{reason: "local feed changed during the check"}
	}
	return copyLocal(in, -1, req.maxBytes(), dst)
}

// fetchSelfHosted reads a URL served by the host itself (issues #3362, #3368): no proxy, dialled at the address it was
// classified self at, no redirect (a 3xx is refused on its status), only 200/221/226, the request's timeout over the
// whole read, the ceiling, and a body shorter than its Content-Length refused.
func fetchSelfHosted(ctx context.Context, src *source, req Request, dst string) transfer {
	ctx, cancel := context.WithTimeout(ctx, req.timeout())
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, src.url.String(), nil)
	if err != nil {
		return transfer{reason: err.Error()}
	}
	var dialer net.Dialer
	dial := func(ctx context.Context, network, addr string) (conn net.Conn, err error) {
		_, p, _ := net.SplitHostPort(addr)
		for _, a := range src.self { // each in turn, as PHP's stream wrapper tries them
			if conn, err = dialer.DialContext(ctx, network, net.JoinHostPort(a.String(), p)); err == nil {
				break
			}
		}
		return conn, err
	}
	client := &http.Client{
		Transport:     &http.Transport{DialContext: dial, DisableKeepAlives: true, DisableCompression: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(r)
	if err != nil {
		return transfer{reason: err.Error()}
	}
	defer resp.Body.Close()
	if s := resp.StatusCode; s != 200 && s != 221 && s != 226 {
		return transfer{status: s, reason: "local feed answered with " + resp.Proto + " " + resp.Status}
	}
	t := copyLocal(resp.Body, resp.ContentLength, req.maxBytes(), dst)
	if t.reason == "" && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.reason = "local feed read timed out"
	}
	return t
}

func copyLocal(in io.Reader, declared, limit int64, dst string) transfer {
	if declared > limit {
		return transfer{reason: "local_too_large"}
	}
	out, err := os.Create(dst)
	if err != nil {
		return transfer{reason: "local feed could not be saved"}
	}
	defer out.Close()
	want := limit + 1
	if declared >= 0 {
		want = declared
	}
	n, err := io.Copy(out, io.LimitReader(in, want))
	switch {
	case n > limit:
		return transfer{reason: "local_too_large"}
	case errors.Is(err, context.DeadlineExceeded):
		return transfer{reason: "local feed read timed out"}
	case declared >= 0 && n < declared:
		return transfer{reason: fmt.Sprintf("local feed body incomplete (%d of %d bytes)", n, declared)}
	case err != nil:
		return transfer{reason: "local feed could not be saved"}
	}
	return transfer{status: 200}
}

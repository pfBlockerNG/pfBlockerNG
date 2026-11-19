package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultMaxBody = 256 << 20
	requestTimeout = 30 * time.Second
)

// lapiClient talks to the CrowdSec Local API with the bouncer key. One keep-alive client, a 30 s limit per request,
// the system trust store, and no redirects (a redirect would carry X-Api-Key to wherever it points).
type lapiClient struct {
	streamURL  string
	metricsURL string
	key        string
	http       *http.Client
	maxBody    int64
	requests   uint64
	errors     uint64
}

func newLAPIClient(cfg *config) (*lapiClient, error) {
	base, err := url.Parse(cfg.APIURL)
	if err != nil {
		return nil, err
	}
	stream := base.JoinPath("v1", "decisions", "stream")
	return &lapiClient{
		streamURL:  stream.String(),
		metricsURL: base.JoinPath("v1", "usage-metrics").String(),
		key:        cfg.APIKey,
		maxBody:    defaultMaxBody,
		http: &http.Client{
			Timeout:   requestTimeout,
			Transport: http.DefaultTransport.(*http.Transport).Clone(),
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// pull fetches the decision stream: the full set when startup is true, else the changes since the last pull.
func (c *lapiClient) pull(ctx context.Context, startup bool) (*streamResponse, error) {
	q := url.Values{"scopes": {"ip,range"}}
	if startup {
		q.Set("startup", "true")
	}
	var resp *streamResponse
	err := c.do(ctx, http.MethodGet, c.streamURL+"?"+q.Encode(), nil, func(body io.Reader) error {
		var err error
		resp, err = decodeStream(body)
		return err
	})
	return resp, err
}

// postUsage sends one AllMetrics body to /v1/usage-metrics.
func (c *lapiClient) postUsage(ctx context.Context, body []byte) error {
	return c.do(ctx, http.MethodPost, c.metricsURL, body, nil)
}

func (c *lapiClient) do(ctx context.Context, method, target string, body []byte, read func(io.Reader) error) error {
	c.requests++
	status, err := c.roundTrip(ctx, method, target, body, read)
	if err != nil {
		c.errors++
		if strings.Contains(err.Error(), c.key) {
			shown := ""
			if status != 0 {
				shown = fmt.Sprintf(" (HTTP %d)", status)
			}
			err = fmt.Errorf("%s %s failed%s; the details repeat the key and are omitted", method, c.path(target), shown)
		}
	}
	return err
}

// path is target's path for messages; target is one of the client's own URLs.
func (c *lapiClient) path(target string) string {
	if u, err := url.Parse(target); err == nil {
		return u.Path
	}
	return ""
}

// roundTrip makes one request; status is the reply's HTTP status, 0 when there was none.
func (c *lapiClient) roundTrip(ctx context.Context, method, target string, body []byte, read func(io.Reader) error) (status int, err error) {
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reqBody)
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-Api-Key", c.key)
	req.Header.Set("User-Agent", "pfb_crowdsec/"+version)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		excerpt, _ := io.ReadAll(io.LimitReader(resp.Body, int64(200+len(c.key))))
		if bytes.Contains(excerpt, []byte(c.key)) {
			excerpt = []byte("(reply omitted: it repeats the key)")
		} else if len(excerpt) > 200 {
			excerpt = excerpt[:200] // a cut-off key prefix cannot reach the log: the whole reply was checked
		}
		return resp.StatusCode, fmt.Errorf("%s %s: HTTP %s: %s", method, req.URL.Path, resp.Status, bytes.TrimSpace(excerpt))
	}
	if read == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, nil
	}
	if err := read(http.MaxBytesReader(nil, resp.Body, c.maxBody)); err != nil {
		if tooLarge := (*http.MaxBytesError)(nil); errors.As(err, &tooLarge) {
			return resp.StatusCode, fmt.Errorf("%s %s: response body larger than the %d-byte limit", method, req.URL.Path, c.maxBody)
		}
		return resp.StatusCode, err
	}
	return resp.StatusCode, nil
}

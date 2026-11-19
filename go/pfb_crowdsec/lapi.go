package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

var errTooLarge = errors.New("response body larger than the limit")

func (c *lapiClient) do(ctx context.Context, method, target string, body []byte, read func(io.Reader) error) error {
	c.requests++
	err := c.roundTrip(ctx, method, target, body, read)
	if err != nil {
		c.errors++
		err = errors.New(redact(err.Error(), c.key))
	}
	return err
}

func (c *lapiClient) roundTrip(ctx context.Context, method, target string, body []byte, read func(io.Reader) error) error {
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reqBody)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", c.key)
	req.Header.Set("User-Agent", "pfb_crowdsec/"+version)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	limited := &cappedReader{r: resp.Body, left: c.maxBody}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		excerpt, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("%s %s: HTTP %s: %s", method, req.URL.Path, resp.Status, bytes.TrimSpace(excerpt))
	}
	if read == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	if err := read(limited); err != nil {
		if limited.over {
			return fmt.Errorf("%s %s: %w (%d bytes)", method, req.URL.Path, errTooLarge, c.maxBody)
		}
		return err
	}
	return nil
}

// cappedReader fails once more than left bytes would be read.
type cappedReader struct {
	r    io.Reader
	left int64
	over bool
}

func (c *cappedReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		var one [1]byte
		if n, err := io.ReadFull(c.r, one[:]); n > 0 {
			c.over = true
			return 0, errTooLarge
		} else if err != io.EOF {
			return 0, err
		}
		return 0, io.EOF
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

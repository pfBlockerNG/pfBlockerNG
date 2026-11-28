package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_crowdsec/spoa"
)

const (
	maxAppSecBodyRead  = 16 << 10
	maxAppSecReqBody   = 64 << 10
	appSecErrLogWindow = 30 * time.Second
)

// spoaState holds the atomically swapped decision radix tree, optional AppSec client, and SPOA metrics.
type spoaState struct {
	tree   atomic.Pointer[spoa.RadixTree[spoaDecision]]
	appSec *appSecClient

	appsecLookups atomic.Uint64
	appsecBlocked atomic.Uint64
	appsecErrors  atomic.Uint64
}

func newSPOAState(cfg *config, log *logger) *spoaState {
	st := &spoaState{}
	st.tree.Store(spoa.NewRadixBuilder[spoaDecision]().Build())
	if cfg != nil && cfg.AppSecURL != "" {
		st.appSec = newAppSecClient(cfg.AppSecURL, cfg.APIKey, cfg.appSecTimeout, cfg.AppSecFailureAction, log)
	}
	return st
}

// swap replaces the active decision tree atomically without disrupting live SPOA connections.
func (s *spoaState) swap(tree *spoa.RadixTree[spoaDecision]) {
	if tree == nil {
		tree = spoa.NewRadixBuilder[spoaDecision]().Build()
	}
	s.tree.Store(tree)
}

func (s *spoaState) counts() (v4, v6 int) {
	return s.tree.Load().Counts()
}

// Handle evaluates one SPOP NOTIFY frame against the local cached LAPI decisions (and optional AppSec).
func (s *spoaState) Handle(ctx context.Context, msgs []spoa.Message) ([]spoa.Action, bool, error) {
	var msg spoa.Message
	var ip netip.Addr
	foundIP := false
	for _, m := range msgs {
		if v, ok := m.Arg("src-ip"); ok {
			if addr, ok := v.ParseIP(); ok {
				msg, ip, foundIP = m, addr, true
				break
			}
		}
		if v, ok := m.Arg("ip"); ok {
			if addr, ok := v.ParseIP(); ok {
				msg, ip, foundIP = m, addr, true
				break
			}
		}
	}
	if !foundIP {
		return []spoa.Action{
			spoa.SetTxnVar("remediation", spoa.StringValue("bypass")),
		}, false, nil
	}

	if dec, ok := s.tree.Load().Lookup(ip); ok {
		actions := []spoa.Action{
			spoa.SetTxnVar("remediation", spoa.StringValue(dec.Remediation)),
			spoa.SetTxnVar("origin", spoa.StringValue(dec.Origin)),
			spoa.SetTxnVar("scenario", spoa.StringValue(dec.Scenario)),
		}
		return actions, dec.Remediation != "" && dec.Remediation != "bypass", nil
	}

	if s.appSec != nil && hasAppSecArgs(msg) {
		s.appsecLookups.Add(1)
		dec, blocked, err := s.appSec.evaluate(ctx, ip, msg)
		if err != nil {
			s.appsecErrors.Add(1)
		}
		if blocked {
			s.appsecBlocked.Add(1)
		}
		actions := []spoa.Action{
			spoa.SetTxnVar("remediation", spoa.StringValue(dec.Remediation)),
		}
		if dec.Origin != "" {
			actions = append(actions, spoa.SetTxnVar("origin", spoa.StringValue(dec.Origin)))
		}
		if dec.Scenario != "" {
			actions = append(actions, spoa.SetTxnVar("scenario", spoa.StringValue(dec.Scenario)))
		}
		return actions, blocked, nil
	}

	return []spoa.Action{
		spoa.SetTxnVar("remediation", spoa.StringValue("bypass")),
	}, false, nil
}

func hasAppSecArgs(m spoa.Message) bool {
	for _, k := range []string{"method", "uri", "host"} {
		if _, ok := m.Arg(k); ok {
			return true
		}
	}
	return false
}

// appSecClient forwards non-blocked HTTP metadata to CrowdSec's Security Engine AppSec endpoint.
type appSecClient struct {
	endpoint      string
	apiKey        string
	timeout       time.Duration
	failureAction string // "passthrough" or "deny"
	client        *http.Client
	log           *logger
	lastErrLog    atomic.Int64
}

func newAppSecClient(endpoint, apiKey string, timeout time.Duration, failureAction string, log *logger) *appSecClient {
	if timeout <= 0 {
		timeout = defaultAppSecTimeout
	}
	if failureAction != "deny" {
		failureAction = "passthrough"
	}
	return &appSecClient{
		endpoint:      endpoint,
		apiKey:        apiKey,
		timeout:       timeout,
		failureAction: failureAction,
		client: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        64,
				MaxIdleConnsPerHost: 64,
				IdleConnTimeout:     60 * time.Second,
			},
		},
		log: log,
	}
}

type appSecResponse struct {
	Action     string `json:"action"`
	HTTPStatus int    `json:"http_status"`
	Scenario   string `json:"scenario"`
}

func (c *appSecClient) evaluate(ctx context.Context, ip netip.Addr, msg spoa.Message) (spoaDecision, bool, error) {
	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var bodyReader io.Reader
	httpMethod := http.MethodGet
	if bv, ok := msg.Arg("body"); ok {
		var raw []byte
		if bv.Type == spoa.DataTypeBinary {
			raw = bv.Bytes
		} else if bv.Type == spoa.DataTypeString {
			raw = []byte(bv.String)
		}
		if len(raw) > maxAppSecReqBody {
			raw = raw[:maxAppSecReqBody]
		}
		if len(raw) > 0 {
			bodyReader = bytes.NewReader(raw)
			httpMethod = http.MethodPost
		}
	}

	req, err := http.NewRequestWithContext(reqCtx, httpMethod, c.endpoint, bodyReader)
	if err != nil {
		return c.onFailure(err)
	}
	req.Header.Set("X-Crowdsec-Appsec-Api-Key", c.apiKey)
	req.Header.Set("X-Crowdsec-Appsec-Ip", ip.String())
	if v, ok := msg.Arg("host"); ok {
		if s, ok := v.AsString(); ok && s != "" {
			req.Header.Set("X-Crowdsec-Appsec-Host", sanitizeHeaderValue(s))
		}
	}
	if v, ok := msg.Arg("uri"); ok {
		if s, ok := v.AsString(); ok && s != "" {
			req.Header.Set("X-Crowdsec-Appsec-Uri", sanitizeHeaderValue(s))
		}
	}
	if v, ok := msg.Arg("method"); ok {
		if s, ok := v.AsString(); ok && s != "" {
			req.Header.Set("X-Crowdsec-Appsec-Verb", sanitizeHeaderValue(s))
		}
	}
	if v, ok := msg.Arg("version"); ok {
		if s, ok := v.AsString(); ok && s != "" {
			req.Header.Set("X-Crowdsec-Appsec-Http-Version", sanitizeHeaderValue(s))
		}
	}
	if v, ok := msg.Arg("user-agent"); ok {
		if s, ok := v.AsString(); ok && s != "" {
			req.Header.Set("X-Crowdsec-Appsec-User-Agent", sanitizeHeaderValue(s))
		}
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return c.onFailure(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxAppSecBodyRead))

	if resp.StatusCode == http.StatusOK {
		return spoaDecision{Remediation: "bypass"}, false, nil
	}
	if resp.StatusCode >= 500 {
		return c.onFailure(&httpStatusError{code: resp.StatusCode})
	}
	var parsed appSecResponse
	_ = json.Unmarshal(body, &parsed)
	action := strings.ToLower(strings.TrimSpace(parsed.Action))
	if action == "" || action == "allow" {
		if resp.StatusCode == http.StatusForbidden {
			action = "ban"
		} else {
			return spoaDecision{Remediation: "bypass"}, false, nil
		}
	}
	if action == "bypass" {
		return spoaDecision{Remediation: "bypass"}, false, nil
	}
	return spoaDecision{
		Remediation: action,
		Origin:      "appsec",
		Scenario:    parsed.Scenario,
	}, true, nil
}

type httpStatusError struct{ code int }

func (e *httpStatusError) Error() string { return "appsec returned HTTP " + http.StatusText(e.code) }

func (c *appSecClient) onFailure(err error) (spoaDecision, bool, error) {
	now := time.Now().UnixNano()
	prev := c.lastErrLog.Load()
	if c.log != nil && (prev == 0 || now-prev >= int64(appSecErrLogWindow)) && c.lastErrLog.CompareAndSwap(prev, now) {
		c.log.warnf("appsec evaluation failed (%s): %v", c.failureAction, err)
	}
	if c.failureAction == "deny" {
		return spoaDecision{Remediation: "ban", Origin: "appsec-error"}, true, err
	}
	return spoaDecision{Remediation: "bypass"}, false, err
}

func sanitizeHeaderValue(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

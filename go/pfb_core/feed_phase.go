package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

const (
	maxFeedPhaseFeeds    = 1024
	maxFeedPhaseIDLength = 64
	feedPhaseTimeout     = 4 * time.Hour
)

type FeedPhaseResponse struct {
	Results []FeedPhaseResult `json:"results"`
}

type FeedPhaseResult struct {
	ID                string `json:"id"`
	Disposition       string `json:"disposition"`
	Stage             string `json:"stage"`
	Reason            string `json:"reason"`
	Entries           int    `json:"entries"`
	ParseFailures     int    `json:"parseFailures"`
	Suppressed        bool   `json:"suppressed"`
	MappedDrops       int    `json:"mappedDrops"`
	DNSBLRows         int    `json:"dnsblRows"`
	IPv4Count         int    `json:"ipv4Count"`
	IPv6Count         int    `json:"ipv6Count"`
	UpdateIP          bool   `json:"updateIP"`
	SchemeSkipped     int    `json:"schemeSkipped"`
	HPHostsStop       bool   `json:"hpHostsStop"`
	Placeholder       string `json:"placeholder"`
	PreScriptFailed   bool   `json:"preScriptFailed"`
	SourceChanged     bool   `json:"sourceChanged"`
	NormalizedChanged bool   `json:"normalizedChanged"`
}

type feedPhaseRunner struct {
	store   *settings.Store
	flags   feedFlags
	fetcher *feedfetch.Fetcher
}

func newFeedPhaseRunner(store *settings.Store, flags feedFlags) *feedPhaseRunner {
	return &feedPhaseRunner{store: store, flags: flags, fetcher: &feedfetch.Fetcher{}}
}

type feedPhaseID struct {
	kind, header string
	custom       bool
	synthetic    bool
}

func validFeedPhaseToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	for i := range token {
		c := token[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validFeedPhaseID(phase, id string) bool {
	parsed, err := parseFeedPhaseID(id)
	if err != nil {
		return false
	}
	if phase == "dnsbl" {
		return parsed.kind == "dnsbl"
	}
	return phase == "ip" && parsed.kind != "dnsbl"
}

func parseFeedPhaseID(id string) (feedPhaseID, error) {
	family, value, ok := strings.Cut(id, ":")
	if !ok {
		return feedPhaseID{}, errors.New("invalid feed id")
	}
	switch family {
	case "dnsbl":
		if validFeedWord(value) {
			return feedPhaseID{kind: family, header: value}, nil
		}
	case "ipv4", "ipv6":
		suffix := "_v4"
		if family == "ipv6" {
			suffix = "_v6"
		}
		if strings.HasSuffix(value, suffix) && validFeedWord(strings.TrimSuffix(value, suffix)) {
			return feedPhaseID{kind: family, header: strings.TrimSuffix(value, suffix)}, nil
		}
	case "custom":
		kind, group, ok := strings.Cut(value, ":")
		if ok && validFeedWord(group) && (kind == "dnsbl" || kind == "ipv4" || kind == "ipv6") {
			return feedPhaseID{kind: kind, header: group, custom: true}, nil
		}
	case "synthetic":
		kind, header, ok := strings.Cut(value, ":")
		if ok && ((kind == "ipv4" && header == "DNSBLIP_v4") || (kind == "ipv6" && header == "DNSBLIP_v6")) {
			return feedPhaseID{kind: kind, header: header, synthetic: true}, nil
		}
	}
	return feedPhaseID{}, errors.New("invalid feed id")
}

func validFeedWord(value string) bool {
	if value == "" {
		return false
	}
	for i := range value {
		c := value[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

func updatePhaseAllowed(req update.Request, phase string) bool {
	if req.Trigger == "apply" {
		return false
	}
	if req.Trigger != "manual" || req.Scope == "both" {
		return true
	}
	return req.Scope == phase
}

func (p *feedPhaseRunner) run(ctx context.Context, phase string, ids []string, force string, log io.Writer) ([]FeedPhaseResult, error) {
	if len(ids) == 0 {
		return []FeedPhaseResult{}, nil
	}
	if len(ids) > maxFeedPhaseFeeds {
		return nil, errors.New("too many feeds")
	}
	ingest, err := p.store.GetClear("ingest")
	if err != nil {
		return nil, err
	}
	fetcher, err := p.fetcherFor(ingest)
	if err != nil {
		return nil, err
	}
	projections := make(map[string]map[string]any)
	results := make([]FeedPhaseResult, 0, len(ids))
	for _, id := range ids {
		parsed, err := parseFeedPhaseID(id)
		if err != nil || !validFeedPhaseID(phase, id) || len(id) > maxFeedPhaseIDLength {
			return nil, errors.New("invalid feed id")
		}
		projectionID := "feeds/" + parsed.kind
		projection, ok := projections[projectionID]
		if !ok && !parsed.synthetic {
			projection, err = p.store.GetClear(projectionID)
			if err != nil {
				return nil, err
			}
			projections[projectionID] = projection
		}
		spec, found := p.feedFor(parsed, id, projection, ingest)
		var result FeedPhaseResult
		if !found {
			result = failedFeed(id, "settings", "feed_not_found")
		} else {
			result = p.runFeed(ctx, spec, force, fetcher, ingest, log)
		}
		if log != nil {
			_, _ = fmt.Fprintf(log, "feed %s: %s\n", result.ID, result.Disposition)
		}
		results = append(results, result)
	}
	return results, nil
}

func (p *feedPhaseRunner) fetcherFor(ingest map[string]any) (*feedfetch.Fetcher, error) {
	fetcher := *p.fetcher
	policy := feedfetch.Policy{NoFilter: !boolSetting(ingest, "feedHostFilter"), LocalDirs: p.flags.LocalDirs, Resolve: p.fetcher.Policy.Resolve}
	for _, row := range listSetting(ingest, "feedHostAllowlist") {
		entry := stringSetting(row, "cidr")
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			policy.Allow = append(policy.Allow, prefix)
		} else if address, err := netip.ParseAddr(entry); err == nil {
			policy.Allow = append(policy.Allow, netip.PrefixFrom(address, address.BitLen()))
		}
	}
	for _, row := range listSetting(ingest, "selfAddresses") {
		if address, err := netip.ParseAddr(stringSetting(row, "address")); err == nil {
			policy.Self = append(policy.Self, address)
		}
	}
	fetcher.Policy = policy
	fetcher.UserAgent, fetcher.RsyncBin = p.flags.UserAgent, p.flags.RsyncBin
	proxyText := stringSetting(ingest, "proxyUrl")
	if proxyText == "" {
		fetcher.Proxy = nil
	} else {
		proxy, err := url.Parse(proxyText)
		if err != nil {
			return nil, errors.New("invalid configured proxy")
		}
		user, password := stringSetting(ingest, "proxyUser"), stringSetting(ingest, "proxyPassword")
		if user != "" || password != "" {
			proxy.User = url.UserPassword(user, password)
		}
		fetcher.Proxy = proxy
	}
	fetcher.ASNCSV = p.flags.ASNCSV
	return &fetcher, nil
}

type phaseFeed struct {
	id, kind, name, header                    string
	state, format, source                     string
	credentials, bindAddress, preScript       string
	groupAction, customText                   string
	custom, synthetic, disabled, whoisConvert bool
	suppressionCidr                           int
}

func (p *feedPhaseRunner) feedFor(parsed feedPhaseID, id string, projection, ingest map[string]any) (phaseFeed, bool) {
	kind, name := parsed.kind, parsed.header
	suffix := ""
	if kind == "ipv4" {
		suffix = "_v4"
	} else if kind == "ipv6" {
		suffix = "_v6"
	}
	if parsed.synthetic {
		return phaseFeed{id: id, kind: kind, name: name, header: name, state: "enabled", format: "auto", synthetic: true,
			disabled: !boolSetting(ingest, "dnsblIp")}, p.flags.DBDir != ""
	}
	for _, group := range listSetting(projection, "groups") {
		groupName := stringSetting(group, "name")
		if parsed.custom {
			if groupName != parsed.header {
				continue
			}
			customText := stringSetting(group, "customList")
			if customText == "" || customText == "0" {
				return phaseFeed{}, false
			}
			return phaseFeed{
				id: id, kind: kind, name: groupName + "_custom" + suffix, header: groupName + "_custom" + suffix,
				state: "enabled", format: "auto", preScript: stringSetting(group, "preScript"),
				groupAction: stringSetting(group, "action"), customText: customText, custom: true,
				disabled:     stringSetting(group, "action") == "Disabled",
				whoisConvert: boolSetting(group, "whoisConvert"), suppressionCidr: intSetting(group, "suppressionCidr"),
			}, true
		}
		for _, row := range listSetting(group, "feeds") {
			if stringSetting(row, "header") != parsed.header {
				continue
			}
			return phaseFeed{
				id: id, kind: kind, name: parsed.header + suffix, header: parsed.header + suffix,
				state: stringSetting(row, "state"), format: stringSetting(row, "format"), source: stringSetting(row, "url"),
				credentials: stringSetting(row, "credentials"), bindAddress: stringSetting(group, "bindAddress"),
				preScript: stringSetting(group, "preScript"), groupAction: stringSetting(group, "action"),
				disabled:        stringSetting(group, "action") == "Disabled" || stringSetting(row, "state") == "disabled",
				suppressionCidr: intSetting(group, "suppressionCidr"),
			}, true
		}
	}
	return phaseFeed{}, false
}

func failedFeed(id, stage, reason string) FeedPhaseResult {
	return FeedPhaseResult{ID: id, Disposition: "failed", Stage: stage, Reason: reason}
}

func boolSetting(m map[string]any, key string) bool {
	value, _ := m[key].(bool)
	return value
}

func intSetting(m map[string]any, key string) int {
	switch value := m[key].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case json.Number:
		n, _ := strconv.Atoi(string(value))
		return n
	}
	return 0
}

func stringSetting(m map[string]any, key string) string {
	value, _ := m[key].(string)
	return value
}

func listSetting(m map[string]any, key string) []map[string]any {
	values, _ := m[key].([]any)
	out := make([]map[string]any, 0, len(values))
	for _, value := range values {
		if row, ok := value.(map[string]any); ok {
			out = append(out, row)
		}
	}
	return out
}

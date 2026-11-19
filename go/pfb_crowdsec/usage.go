package main

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"slices"
	"strings"
	"time"
)

// usageInterval is go-cs-bouncer's default for POST /v1/usage-metrics.
const usageInterval = 15 * time.Minute

const maxLabel = 255

// usageInput is one window's worth of figures: dropped counts for the window, active decisions now.
type usageInput struct {
	start, now time.Time
	window     time.Duration
	dropped    [2]counter
	origins    [2]map[string]int
}

// The LAPI swagger's AllMetrics, RemediationComponentsMetrics, DetailedMetrics, MetricsMeta and MetricsDetailItem.
type (
	allMetrics struct {
		RemediationComponents []remediationComponent `json:"remediation_components"`
	}
	remediationComponent struct {
		Type                string            `json:"type"`
		Version             string            `json:"version"`
		UTCStartupTimestamp int64             `json:"utc_startup_timestamp"`
		FeatureFlags        []string          `json:"feature_flags"`
		Metrics             []detailedMetrics `json:"metrics"`
	}
	detailedMetrics struct {
		Meta  metricsMeta  `json:"meta"`
		Items []metricItem `json:"items"`
	}
	metricsMeta struct {
		WindowSizeSeconds int64 `json:"window_size_seconds"`
		UTCNowTimestamp   int64 `json:"utc_now_timestamp"`
	}
	metricItem struct {
		Name   string            `json:"name"`
		Value  float64           `json:"value"`
		Unit   string            `json:"unit"`
		Labels map[string]string `json:"labels"`
	}
)

// usagePayload renders the window under the official bouncer's metric names and units.
func usagePayload(in usageInput) ([]byte, error) {
	var items []metricItem
	for f := range 2 {
		ipType := map[string]string{"ip_type": ipTypes[f]}
		items = append(items,
			metricItem{Name: "dropped", Value: float64(in.dropped[f].Packets), Unit: "packet", Labels: ipType},
			metricItem{Name: "dropped", Value: float64(in.dropped[f].Bytes), Unit: "byte", Labels: ipType},
		)
		origins := make([]string, 0, len(in.origins[f]))
		for origin := range in.origins[f] {
			origins = append(origins, origin)
		}
		slices.Sort(origins)
		for _, origin := range origins {
			label := origin
			if len(label) > maxLabel { // the LAPI schema's MetricsLabels limit; the digest keeps long origins apart
				h := fnv.New32a()
				h.Write([]byte(origin))
				label = fmt.Sprintf("%s~%08x", strings.ToValidUTF8(label[:maxLabel-9], ""), h.Sum32())
			}
			items = append(items, metricItem{Name: "active_decisions", Value: float64(in.origins[f][origin]), Unit: "ip",
				Labels: map[string]string{"origin": label, "ip_type": ipTypes[f]}})
		}
	}
	return json.Marshal(allMetrics{RemediationComponents: []remediationComponent{{
		Type:                "pfb_crowdsec",
		Version:             version,
		UTCStartupTimestamp: in.start.Unix(),
		FeatureFlags:        []string{},
		Metrics: []detailedMetrics{{
			Meta:  metricsMeta{WindowSizeSeconds: int64(in.window / time.Second), UTCNowTimestamp: in.now.Unix()},
			Items: items,
		}},
	}}})
}

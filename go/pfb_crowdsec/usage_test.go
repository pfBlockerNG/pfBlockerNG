package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

// checkKeys fails unless obj has every required key and no key outside allowed (the LAPI swagger definitions).
func checkKeys(t *testing.T, what string, obj map[string]any, required, allowed []string) {
	t.Helper()
	for _, k := range required {
		if _, ok := obj[k]; !ok {
			t.Errorf("%s: required %q missing in %v", what, k, obj)
		}
	}
	for k := range obj {
		if !slices.Contains(allowed, k) {
			t.Errorf("%s: %q is not in the LAPI schema (allowed %v)", what, k, allowed)
		}
	}
}

func asObject(t *testing.T, what string, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v; want an object", what, v)
	}
	return m
}

func asList(t *testing.T, what string, v any) []any {
	t.Helper()
	l, ok := v.([]any)
	if !ok {
		t.Fatalf("%s = %#v; want a list", what, v)
	}
	return l
}

// The payload is an AllMetrics body with one RemediationComponentsMetrics entry, per the LAPI swagger
// (BaseMetrics, DetailedMetrics, MetricsMeta, MetricsDetailItem), with no OS block.
func TestUsagePayloadMatchesTheLAPISchema(t *testing.T) {
	start := time.Unix(1_795_000_000, 0)
	now := start.Add(20 * time.Minute)
	data, err := usagePayload(usageInput{
		start:   start,
		now:     now,
		window:  15 * time.Minute,
		dropped: [2]counter{{Packets: 10, Bytes: 1000}, {Packets: 0, Bytes: 0}},
		origins: [2]map[string]int{{"crowdsec": 2, "cscli": 1}, {}},
	})
	if err != nil {
		t.Fatalf("usagePayload = %v", err)
	}
	var top map[string]any
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatalf("payload is not JSON: %v (%s)", err, data)
	}
	checkKeys(t, "AllMetrics", top, []string{"remediation_components"},
		[]string{"remediation_components", "log_processors", "lapi"})
	rcs := asList(t, "remediation_components", top["remediation_components"])
	if len(rcs) != 1 {
		t.Fatalf("remediation_components has %d entries; want 1", len(rcs))
	}
	rc := asObject(t, "remediation_components[0]", rcs[0])
	checkKeys(t, "RemediationComponentsMetrics", rc, []string{"version", "utc_startup_timestamp", "type"},
		[]string{"version", "os", "metrics", "feature_flags", "utc_startup_timestamp", "type", "name", "last_pull"})
	if _, has := rc["os"]; has {
		t.Errorf("payload carries an os block: host and OS probing is left out")
	}
	if rc["type"] != "pfb_crowdsec" || rc["version"] != version || rc["utc_startup_timestamp"] != float64(start.Unix()) {
		t.Errorf("type, version, startup = %v, %v, %v", rc["type"], rc["version"], rc["utc_startup_timestamp"])
	}
	metrics := asList(t, "metrics", rc["metrics"])
	if len(metrics) != 1 {
		t.Fatalf("metrics has %d entries; want 1", len(metrics))
	}
	dm := asObject(t, "metrics[0]", metrics[0])
	checkKeys(t, "DetailedMetrics", dm, []string{"meta", "items"}, []string{"meta", "items"})
	meta := asObject(t, "meta", dm["meta"])
	checkKeys(t, "MetricsMeta", meta, []string{"window_size_seconds", "utc_now_timestamp"},
		[]string{"window_size_seconds", "utc_now_timestamp"})
	if meta["window_size_seconds"] != float64(900) || meta["utc_now_timestamp"] != float64(now.Unix()) {
		t.Errorf("meta = %v; want window 900 and now %d", meta, now.Unix())
	}
	var items []string
	for i, raw := range asList(t, "items", dm["items"]) {
		item := asObject(t, fmt.Sprintf("items[%d]", i), raw)
		checkKeys(t, "MetricsDetailItem", item, []string{"name", "value", "unit"}, []string{"name", "value", "unit", "labels"})
		labels := asObject(t, "labels", item["labels"])
		var pairs []string
		for k, v := range labels {
			s, isString := v.(string)
			if !isString {
				t.Errorf("label %s = %#v; MetricsLabels values are strings", k, v)
			}
			pairs = append(pairs, k+"="+s)
		}
		slices.Sort(pairs)
		value, isNumber := item["value"].(float64)
		if !isNumber {
			t.Errorf("value = %#v; want a number", item["value"])
		}
		items = append(items, fmt.Sprintf("%v/%v %g {%s}", item["name"], item["unit"], value, strings.Join(pairs, ",")))
	}
	slices.Sort(items)
	want := []string{
		"active_decisions/ip 1 {ip_type=ipv4,origin=cscli}",
		"active_decisions/ip 2 {ip_type=ipv4,origin=crowdsec}",
		"dropped/byte 0 {ip_type=ipv6}",
		"dropped/byte 1000 {ip_type=ipv4}",
		"dropped/packet 0 {ip_type=ipv6}",
		"dropped/packet 10 {ip_type=ipv4}",
	}
	if !slices.Equal(items, want) {
		t.Errorf("items =\n  %s\nwant\n  %s", strings.Join(items, "\n  "), strings.Join(want, "\n  "))
	}
}

// Scenario: dropped counts are per window. Given the inbound rules counted 20 packets at the first post and 25 at
// the second, the second post reports 5; when a filter reload resets the counter to 3, the next post reports 3.
func TestSendUsageReportsDroppedPerWindowAndSurvivesACounterReset(t *testing.T) {
	h := newHarness(t, ok(`{"new":[],"deleted":[]}`))
	ctx := context.Background()
	if err := h.d.setup(ctx); err != nil {
		t.Fatal(err)
	}
	post := func(packets int) {
		t.Helper()
		h.pf.mu.Lock()
		h.pf.rules = fmt.Sprintf("block drop in quick inet from <crowdsec_v4> to any label \"CrowdSec IPv4\"\n"+
			"  [ Evaluations: 1 Packets: %d Bytes: %d States: 0 ]\n", packets, packets*100)
		h.pf.mu.Unlock()
		if err := h.d.pull(ctx); err != nil {
			t.Fatal(err)
		}
		h.d.sendUsage(ctx)
	}
	post(20)
	post(25)
	post(3)
	reqs, bodies := h.lapi.requests()
	var got []string
	for i, r := range reqs {
		if r.URL.Path != "/v1/usage-metrics" {
			continue
		}
		var top struct {
			RC []struct {
				Metrics []struct {
					Items []struct {
						Name   string            `json:"name"`
						Unit   string            `json:"unit"`
						Value  float64           `json:"value"`
						Labels map[string]string `json:"labels"`
					} `json:"items"`
				} `json:"metrics"`
			} `json:"remediation_components"`
		}
		if err := json.Unmarshal([]byte(bodies[i]), &top); err != nil {
			t.Fatalf("usage body %d: %v", i, err)
		}
		for _, item := range top.RC[0].Metrics[0].Items {
			if item.Name == "dropped" && item.Unit == "packet" && item.Labels["ip_type"] == "ipv4" {
				got = append(got, fmt.Sprint(item.Value))
			}
		}
	}
	if want := []string{"20", "5", "3"}; !slices.Equal(got, want) {
		t.Fatalf("dropped ipv4 packets per post = %v; want %v", got, want)
	}
}

func TestAFailedUsagePostIsLoggedAndDropped(t *testing.T) {
	h := newHarness(t)
	h.lapi.mu.Lock()
	h.lapi.usage = http.StatusInternalServerError
	h.lapi.mu.Unlock()
	h.d.sendUsage(context.Background())
	if !strings.Contains(h.logs.String(), "level=warning msg=usage metrics") {
		t.Fatalf("logs = %q; want a warning about the failed post", h.logs.String())
	}
	reqs, _ := h.lapi.requests()
	if len(reqs) != 1 {
		t.Fatalf("LAPI saw %d requests; want the one failed post and no retry", len(reqs))
	}
	if h.d.requests != 1 || h.d.errors != 1 {
		t.Fatalf("lapi requests, errors = %d, %d; want the failed post counted: 1, 1", h.d.requests, h.d.errors)
	}
}

// Two origins that share their first 255 characters still get two distinct labels within the schema limit.
func TestLongOriginsKeepDistinctLabels(t *testing.T) {
	prefix := strings.Repeat("o", 300)
	data, err := usagePayload(usageInput{origins: [2]map[string]int{{prefix + "-a": 1, prefix + "-b": 2}, {}}})
	if err != nil {
		t.Fatal(err)
	}
	var top allMetrics
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatal(err)
	}
	labels := map[string]float64{}
	for _, item := range top.RemediationComponents[0].Metrics[0].Items {
		if item.Name != "active_decisions" {
			continue
		}
		label := item.Labels["origin"]
		if len(label) > 255 {
			t.Fatalf("origin label is %d characters long", len(label))
		}
		labels[label] += item.Value
	}
	if len(labels) != 2 {
		t.Fatalf("active_decisions labels = %v; want two distinct labels for two origins", labels)
	}
}

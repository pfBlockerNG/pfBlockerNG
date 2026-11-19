package main

import (
	"encoding/json"
	"strings"
	"testing"
)

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

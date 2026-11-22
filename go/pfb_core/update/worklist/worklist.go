// Package worklist decides the Core Updater's work (spec §3, stages 3, 6 and the decision of stage 7).
package worklist

import (
	"context"
	"errors"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/feedstage"
)

// Decision is stage 7's answer.
type Decision string

const (
	Now     Decision = "now"
	Pending Decision = "pending"
	Nothing Decision = "nothing"
)

// Request is the Update's request.
type Request struct {
	Trigger, Scope, Force string
	Feeds                 []string
}

// Input is what Build reads.
type Input struct {
	Request       Request
	Settings      map[string]map[string]any
	Stages        map[string]*feedstage.Stage
	InWindow      bool
	ExtrasChanged bool
	PendingApply  bool
	SkipFeed      int
	Failures      map[string]int
}

// Item is one feed of the work list.
type Item struct {
	Feed    feedstage.Feed
	Change  feedstage.Change
	Checked bool
	Outcome string
	Stopped string
}

// Plan is the work list and stage 7's decision.
type Plan struct {
	Items    []Item
	Decision Decision
}

// Build decides the work list.
func Build(ctx context.Context, in Input) (Plan, error) {
	return Plan{}, errors.New("not written yet")
}

// ClearUpdate removes a feed's update marker.
func ClearUpdate(dir, name string) error { return errors.New("not written yet") }

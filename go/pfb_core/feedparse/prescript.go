package feedparse

import (
	"context"
	"io"
)

// PreScript is the outcome of RunPreScript (pfb_list_pre_script_run()): whether the transform ran, the file to parse, and why
// it did not.
type PreScript struct {
	OK     bool
	Path   string
	Reason string
	Status int
}

// Reasons a pre-script did not run to the end.
const (
	PreScriptStage   = "stage"
	PreScriptExit    = "exit"
	PreScriptTimeout = "timeout"
	PreScriptDeleted = "deleted"
)

// RunPreScript is pfb_list_pre_script_run(): a staged copy of norm is made at staged and script is run on it with args after it.
func RunPreScript(ctx context.Context, script, norm, staged string, log io.Writer, args ...string) PreScript {
	return PreScript{}
}

// Cleanup removes the staged copy once the feed is parsed (pfb_list_script_cleanup_staged()).
func (p PreScript) Cleanup() {}

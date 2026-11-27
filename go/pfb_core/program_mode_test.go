package main

import "testing"

// The test binary keeps the program mode: the API, gate, scheduler and restart tests drive Core through a fake Update program.
func init() { programMode = true }

// #3977: after the cutover an Update is the Core Updater loop. Without --update-loop, Core would run the PHP program with a
// version 1 request, which the Outpost no longer serves, so a production pfb-core refuses --update-cmd without the switch.
func TestAnUpdateProgramWithoutTheLoopIsRefusedOutsideTheTestBinary(t *testing.T) {
	if got := updateModeReason(false, "/usr/local/pkg/pfblockerng/pfb_core_update.sh", false); got != "--update-cmd needs --update-loop" {
		t.Errorf("updateModeReason without the loop = %q, want the refusal", got)
	}
	if got := updateModeReason(true, "/usr/local/pkg/pfblockerng/pfb_core_update.sh", false); got != "" {
		t.Errorf("updateModeReason with the loop = %q, want none", got)
	}
	if got := updateModeReason(false, "", false); got != "" {
		t.Errorf("updateModeReason without an Update program = %q, want none", got)
	}
	if got := updateModeReason(false, "/bin/true", true); got != "" {
		t.Errorf("updateModeReason in the test binary = %q, want none", got)
	}
}

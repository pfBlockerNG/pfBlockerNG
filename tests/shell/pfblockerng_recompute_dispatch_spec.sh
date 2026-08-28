#shellcheck shell=sh
# issue #1084: pins the `recompute` dispatch arm's rc propagation. The script
# tail's bare `exitnow` (no argument, defaults to 0) discarded pfb_recompute()'s
# own return status, so a keep-previous abort exited 0 at the process boundary
# even though the pass failed internally -- unlike the sibling `dnsbl-control`
# arm, which already threads its exec's rc through `exitnow "$?"`. Runs the
# REAL script entrypoint (not the sourced function): the bug lives in the
# dispatch/exit wiring, not inside pfb_recompute() itself.

Describe 'pfblockerng.sh recompute dispatch (issue #1084 review: rc propagation)'
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/recdispatch.XXXXXX")"
		true > "${work}/memberlist"
		true > "${work}/countsfile"
	}
	cleanup() { rm -rf "$work"; }
	Before 'setup'
	After 'cleanup'

	It 'exits non-zero when a dedup=on recompute pass fails (grepcidr missing at its hardcoded appliance path)'
		# The top-level init's hardcoded /usr/local/bin/grepcidr does not exist
		# off-appliance (dev box / CI runner alike) -- dedup=on hits that check
		# FIRST, before any /var/db write, so pfb_recompute() genuinely fails here
		# even though the rest of the unsourced top-level init has no writable
		# pfSense paths on this machine.
		When run sh "${PFB_PKGDIR}/pfblockerng.sh" recompute v4 "${work}/memberlist" "${work}/countsfile" on
		The status should be failure
		The stdout should include 'Application [ grepcidr ] Not found'
		# The top-level init also spews unrelated stderr noise off-appliance
		# (missing /usr/local/sbin/read_xml_tag.sh, /cf/conf/config.xml, etc.) --
		# real but incidental to this test's purpose, so only asserted as present.
		The stderr should not equal ''
	End
End

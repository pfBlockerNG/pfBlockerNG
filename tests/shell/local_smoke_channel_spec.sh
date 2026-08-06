#shellcheck shell=sh
# local_smoke_channel_spec.sh — issue #2206: the pkg channel the local smoke run builds.
#
# WHY THIS EXISTS: smoke-on-box.sh called build-leg.sh with no --channel, so a local run
# took build-leg.sh's own default while CI passed its own value into build-pkg-linux.yml.
# The two build sites therefore produced DIFFERENTLY NAMED packages
# (pfSense-pkg-pfBlockerNG-<channel>), and a local "green" said nothing about the artifact
# CI ships. local-smoke.sh now carries the channel end to end, so a verification run can
# name the exact channel under test.
#
# TOPOLOGY: the same hermetic fake select-box.sh seam the sibling local_smoke_spec.sh uses
# (PFB_SELECT_BOX) — the bootstrap string is recorded, never executed, so no ssh, no box,
# no build.
#
# RED→GREEN: before the change, `--channel` falls through local-smoke.sh's
# `-*) unknown flag; exit 2` arm, so the explicit-channel examples exit 2 with zero calls
# recorded, and the default example records a bootstrap carrying no --channel at all.

Describe 'local-smoke.sh --channel'
  SCRIPT="${PFB_ROOT}/scripts/local-smoke.sh"

  setup() {
    scrub_git_env
    unset PFB_REF
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/localsmokechannel.XXXXXX")"
    CALLS_DIR="${WORK}/calls"
    mkdir -p "$CALLS_DIR"

    FAKE_SELECT_BOX="${WORK}/fake-select-box.sh"
    cat > "$FAKE_SELECT_BOX" <<'FAKEEOF'
#!/bin/sh
_call_file="$(mktemp "${CALLS_DIR}/call.XXXXXX")"
printf '%s\n' "$*" > "$_call_file"
exit 0
FAKEEOF
    chmod +x "$FAKE_SELECT_BOX"

    TMPDIR="$WORK"
    PFB_SELECT_BOX="$FAKE_SELECT_BOX"
    PFB_BOXES="dummy@dummy"
    export PFB_SELECT_BOX PFB_BOXES WORK CALLS_DIR TMPDIR
  }

  teardown() {
    rm -rf "$WORK"
  }

  BeforeEach 'setup'
  AfterEach  'teardown'

  call_count() { find "$CALLS_DIR" -type f 2>/dev/null | wc -l | tr -d ' '; }

  run_and_diag() {
    _out="$(sh "$SCRIPT" "$@" 2>&1)"
    _rc=$?
    printf 'exit=%s\n' "$_rc"
    printf 'calls=%s\n' "$(call_count)"
    printf '%s\n' "$_out"
    cat "$CALLS_DIR"/* 2>/dev/null
    return 0
  }

  It 'forwards an explicit --channel to smoke-on-box.sh'
    When call run_and_diag --ref dummy --channel testing
    The line 1 of output should equal 'exit=0'
    The line 2 of output should equal 'calls=1'
    The output should include "--channel 'testing'"
  End

  It 'falls back to the devel branch release line when no --channel is given'
    When call run_and_diag --ref dummy
    The line 1 of output should equal 'exit=0'
    The line 2 of output should equal 'calls=1'
    The output should include "--channel 'edge'"
  End

  It 'rejects a channel the portable builder would reject, before leasing a box'
    When call run_and_diag --ref dummy --channel devel
    The line 1 of output should equal 'exit=2'
    The line 2 of output should equal 'calls=0'
    The output should include 'devel'
  End

  # Scoped deliberately: this pins that VALIDATION rejects a hostile channel before the value
  # is ever interpolated into the remote bootstrap string — not that the interpolation itself
  # is quote-safe (it is never reached with such a value). Widening the whitelist would need
  # its own coverage, and `_sq()` around the value.
  It 'refuses a channel carrying shell metacharacters before it can reach the remote shell'
    When call run_and_diag --ref dummy --channel "edge; touch ${WORK}/pwned"
    The line 1 of output should equal 'exit=2'
    The line 2 of output should equal 'calls=0'
    The path "${WORK}/pwned" should not be exist
  End
End

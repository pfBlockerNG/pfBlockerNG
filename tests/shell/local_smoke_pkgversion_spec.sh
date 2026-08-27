#shellcheck shell=sh
# local_smoke_pkgversion_spec.sh — issue #2754: nightly --pkgversion on the bootstrap argv.
#
# WHY THIS EXISTS: a substring pin on comments stayed green after the nightly
# pkgversion block was deleted. This spec records the bootstrap argv through
# the PFB_SELECT_BOX seam (no ssh, no box, no build).
#
# IDENTITY RULE (M1): local-smoke.sh must NOT derive the nightly SHA from the
# orchestrator clone. The box fetches --ref from --git-remote and checks that
# out; smoke-on-box.sh derives from that HEAD. Deriving here stamps a package
# with a commit the box did not build when the two repos diverge, and hard-fails
# before contacting the box when the ref exists only on the remote.
#
# RED→GREEN: --channel nightly without --pkgversion must not put --pkgversion on
# the argv (smoke-on-box.sh derives after checkout). An override must appear
# verbatim. --channel edge must not grow a --pkgversion. A --ref that does not
# exist in the orchestrator clone plus --git-remote must still reach select-box
# (today local-smoke.sh dies in rev-parse before any call).

Describe 'local-smoke.sh --pkgversion (issue #2754)'
  SCRIPT="${PFB_ROOT}/scripts/local-smoke.sh"

  setup() {
    scrub_git_env
    unset PFB_REF PFB_NIGHTLY_PKGVERSION
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/localsmokepkgver.XXXXXX")"
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

    HEAD_SHA="$(git_fixture -C "$PFB_ROOT" rev-parse HEAD)"
    HEAD_SHORT="$(printf '%.7s' "$HEAD_SHA")"

    TMPDIR="$WORK"
    PFB_SELECT_BOX="$FAKE_SELECT_BOX"
    PFB_BOXES="dummy@dummy"
    export PFB_SELECT_BOX PFB_BOXES WORK CALLS_DIR TMPDIR HEAD_SHA HEAD_SHORT
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

  It 'does not put a derived --pkgversion on --channel nightly'
    When call run_and_diag --ref HEAD --channel nightly
    The line 1 of output should equal 'exit=0'
    The line 2 of output should equal 'calls=1'
    The output should include "--channel 'nightly'"
    The output should not include "--pkgversion"
  End

  It 'forwards an explicit --pkgversion verbatim on --channel nightly'
    When call run_and_diag --ref HEAD --channel nightly --pkgversion 20260101120000.abcdef0
    The line 1 of output should equal 'exit=0'
    The line 2 of output should equal 'calls=1'
    The output should include "--pkgversion '20260101120000.abcdef0'"
    The output should not include ".${HEAD_SHORT}'"
  End

  It 'does not put --pkgversion on --channel edge'
    When call run_and_diag --ref HEAD --channel edge --pkgversion 20260101120000.abcdef0
    The line 1 of output should equal 'exit=0'
    The line 2 of output should equal 'calls=1'
    The output should include "--channel 'edge'"
    The output should not include "--pkgversion"
  End

  It 'does not resolve --ref against the orchestrator clone for nightly identity'
    When call run_and_diag --ref dummy --channel nightly --git-remote https://example.invalid/fork.git
    The line 1 of output should equal 'exit=0'
    The line 2 of output should equal 'calls=1'
    The output should include "--channel 'nightly'"
    The output should include "--ref 'dummy'"
    The output should not include "--pkgversion"
    The output should not include "cannot resolve"
  End
End

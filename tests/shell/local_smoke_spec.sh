#shellcheck shell=sh
# local_smoke_spec.sh — shellspec suite for scripts/local-smoke.sh --shards N
# (issue #797, work item 3): concurrent multi-box module sharding.
#
# TOPOLOGY UNDER TEST:
#   A fake select-box.sh (PFB_SELECT_BOX testability seam) records the full
#   "-- <bootstrap>" string of every invocation to its own file under a shared
#   CALLS_DIR, then exits 0 unless a per-shard fail marker file is present —
#   letting each example assert both WHICH invocations happened and HOW MANY,
#   with no real ssh/box/pytest involved (fully hermetic, per sibling specs).
#
# RED→GREEN evidence: before local-smoke.sh parses --shards, the flag falls
# through the `-*) unknown flag; exit 2` arm — EVERY example below that
# expects N invocations, per-shard --shard/--shard-total tagging, or a
# passing multi-shard exit 0 FAILS pre-change (0 calls recorded, exit 2
# instead of the expected exit code). The N=1-default and the flag-validation
# guards (--filter, non-smoke --marker, non-integer/zero --shards) also fail
# pre-change for the same reason (any --shards flag at all is "unknown").
# After implementation those flip to green; the N=1-compat examples
# independently confirm --shards changes nothing when N=1 or absent.

Describe 'local-smoke.sh --shards'
  SCRIPT="${PFB_ROOT}/scripts/local-smoke.sh"

  setup() {
    scrub_git_env
    unset PFB_REF
    unset PFB_GIT_REMOTE
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/localsmokespec.XXXXXX")"
    CALLS_DIR="${WORK}/calls"
    mkdir -p "$CALLS_DIR"

    # Fake select-box.sh: records "-- <bootstrap>" to a unique file under
    # CALLS_DIR, then fails iff a fail-<shard-index> marker exists under WORK.
    # Never touches ssh/PFB_BOXES — local-smoke.sh still requires PFB_BOXES
    # set (a dummy value), but this fake never reads it.
    FAKE_SELECT_BOX="${WORK}/fake-select-box.sh"
    cat > "$FAKE_SELECT_BOX" <<'FAKEEOF'
#!/bin/sh
_call_file="$(mktemp "${CALLS_DIR}/call.XXXXXX")"
printf '%s\n' "$*" > "$_call_file"
_shard_idx="$(printf '%s' "$*" | sed -n "s/.*--shard '\([0-9]*\)'.*/\1/p")"
if [ -n "$_shard_idx" ] && [ -f "${WORK}/fail-${_shard_idx}" ]; then
    exit 1
fi
exit 0
FAKEEOF
    chmod +x "$FAKE_SELECT_BOX"

    # Keep the "kept" shard-logs mktemp dir INSIDE WORK (hermetic: teardown's
    # rm -rf "$WORK" cleans it up instead of leaving debris under real /tmp).
    TMPDIR="$WORK"

    PFB_SELECT_BOX="$FAKE_SELECT_BOX"
    PFB_BOXES="dummy@dummy"
    # issue #2780: existing --ref dummy rows are not on any remote; skip the
    # ls-remote preflight. SHA expansion still runs (dummy is not hex).
    PFB_REF_PREFLIGHT=0
    unset PFB_LS_REMOTE
    export PFB_SELECT_BOX PFB_BOXES WORK CALLS_DIR TMPDIR PFB_REF_PREFLIGHT
  }

  teardown() {
    rm -rf "$WORK"
  }

  BeforeEach 'setup'
  AfterEach  'teardown'

  # ── Helpers ────────────────────────────────────────────────────────────── #
  call_count() { find "$CALLS_DIR" -type f 2>/dev/null | wc -l | tr -d ' '; }

  # Run local-smoke.sh with the given args and print three diagnostic blocks:
  # line 1 = exit=<rc>, line 2 = calls=<N recorded select-box invocations>,
  # remaining lines = the combined stdout+stderr (for substring/"include"
  # checks) followed by every recorded call's bootstrap string (for
  # --shard/--shard-total tagging checks).
  run_and_diag() {
    _out="$(sh "$SCRIPT" "$@" 2>&1)"
    _rc=$?
    printf 'exit=%s\n' "$_rc"
    printf 'calls=%s\n' "$(call_count)"
    printf '%s\n' "$_out"
    cat "$CALLS_DIR"/* 2>/dev/null
    return 0   # diagnostics-only function; assertions read the printed lines, not $?
  }

  # ── --shards 3: three concurrent invocations, each correctly shard-tagged ── #
  Describe '--shards 3'
    It 'launches exactly 3 select-box invocations, each tagged with its shard index and total'
      When call run_and_diag --ref dummy --shards 3
      The line 1 of output should equal 'exit=0'
      The line 2 of output should equal 'calls=3'
      The output should include "--shard '0'"
      The output should include "--shard '1'"
      The output should include "--shard '2'"
      The output should include "--shard-total '3'"
      # every shard still carries the usual ref/abi/marker flags
      The output should include "--ref 'dummy'"
      The output should include "--marker 'smoke'"
    End
  End

  # ── N=1 compat pin: no --shards flag ─ byte-identical to pre-#797 ────────── #
  Describe 'no --shards flag (default N=1)'
    It 'makes a single select-box invocation with no --shard tagging at all'
      When call run_and_diag --ref dummy
      The line 1 of output should equal 'exit=0'
      The line 2 of output should equal 'calls=1'
      The output should not include "--shard "
    End
  End

  # ── N=1 compat pin: explicit --shards 1 ─ same as no flag ────────────────── #
  Describe '--shards 1 (explicit)'
    It 'behaves exactly like no flag: a single untagged select-box invocation'
      When call run_and_diag --ref dummy --shards 1
      The line 1 of output should equal 'exit=0'
      The line 2 of output should equal 'calls=1'
      The output should not include "--shard "
    End
  End

  # ── --shards 2, all shards pass → exit 0 ──────────────────────────────────── #
  Describe '--shards 2, both shards pass'
    It 'aggregates to exit 0 with both shards launched'
      When call run_and_diag --ref dummy --shards 2
      The line 1 of output should equal 'exit=0'
      The line 2 of output should equal 'calls=2'
    End
  End

  # ── --shards 2, one shard fails → non-zero exit, but BOTH shards ran ─────── #
  # Assert-the-before-state discipline: the all-pass example above already
  # proves exit=0 when nothing fails, so THIS example genuinely proves the
  # failure path flips the aggregate result rather than always reporting 0.
  run_shards2_one_fails() {
    true > "${WORK}/fail-1"   # shard index 1 fails; shard 0 must still run
    run_and_diag --ref dummy --shards 2
  }

  Describe '--shards 2, shard 1 fails'
    It 'exits non-zero AND still ran the passing shard (both invocations recorded)'
      When call run_shards2_one_fails
      The line 1 of output should not equal 'exit=0'
      The line 2 of output should equal 'calls=2'
    End
  End

  # ── --shards N>1 + --filter: refused before any invocation ────────────────── #
  Describe '--shards 2 --filter x'
    It 'exits 2 and never invokes select-box.sh (empty-slice hazard)'
      When call run_and_diag --ref dummy --shards 2 --filter x
      The line 1 of output should equal 'exit=2'
      The line 2 of output should equal 'calls=0'
      The output should include 'filter'
    End
  End

  # ── --shards N>1 + non-smoke --marker: refused before any invocation ─────── #
  Describe '--shards 2 --marker repo'
    It 'exits 2 and never invokes select-box.sh (non-default markers select few tests)'
      When call run_and_diag --ref dummy --shards 2 --marker repo
      The line 1 of output should equal 'exit=2'
      The line 2 of output should equal 'calls=0'
      The output should include 'marker'
    End
  End

  # ── --shards garbage: rejected by the case guard ──────────────────────────── #
  Describe '--shards abc'
    It 'exits 2 (non-integer) and never invokes select-box.sh'
      When call run_and_diag --ref dummy --shards abc
      The line 1 of output should equal 'exit=2'
      The line 2 of output should equal 'calls=0'
      The output should include 'positive integer'
    End
  End

  # ── --shards 0: passes the digit check, fails the >=1 check ──────────────── #
  Describe '--shards 0'
    It 'exits 2 (zero is not a positive integer) and never invokes select-box.sh'
      When call run_and_diag --ref dummy --shards 0
      The line 1 of output should equal 'exit=2'
      The line 2 of output should equal 'calls=0'
      The output should include '>= 1'
    End
  End

  # ── the bootstrap runs the suite with the box's own tools ─────────────────── #
  Describe 'on-box invocation'
    It 'lowers the unprivileged port floor before handing off to smoke-on-box.sh'
      # smoke-on-box.sh refuses to run while the floor is above 53 (the non-root mock DNS
      # binds :53), and it is the caller that holds the privilege to lower it -- so the
      # bootstrap must do it, and must do it BEFORE the handoff.
      When call run_and_diag --ref dummy
      The line 1 of output should equal 'exit=0'
      The line 2 of output should equal 'calls=1'
      The output should include 'sysctl -w net.ipv4.ip_unprivileged_port_start=53'
      The output should include 'sh scripts/smoke-on-box.sh'
      The output should not include 'docker run'
    End

    It 'checks out only the paths a smoke leg reads'
      # src/ builds the .pkg; scripts/ holds the harness and installer client input;
      # stubs/python supports root conftest; tests/smoke/ is the suite.
      When call run_and_diag --ref dummy
      The line 1 of output should equal 'exit=0'
      The output should include 'git sparse-checkout set src scripts stubs/python tests/smoke'
      The output should not include 'pkg-site'
    End

    It 'keeps a space-bearing filter as ONE argument through the exec env handoff'
      # --channel cannot carry metacharacters: local-smoke.sh whitelists it to
      # stable|testing|edge|nightly and rejects anything else, which is stronger than
      # quoting. --filter is the free-form value (a pytest -k expression), so it is the one
      # that must survive the remote shell's word-splitting unsplit -- the bootstrap is
      # re-parsed by ssh, so the _sq single-quoting is what holds it together.
      When call run_and_diag --ref dummy --filter 'a and not b'
      The line 1 of output should equal 'exit=0'
      The line 2 of output should equal 'calls=1'
      The output should include "--filter 'a and not b'"
    End

    It 'passes caller smoke values across SSH into the exec env prefix'
      # These reach the leg ONLY through the bootstrap's `exec env VAR='...'` prefix: ssh
      # carries no environment of its own, so a dropped assignment does not fail, it makes
      # the leg silently grade against its own defaults.
      smoke_values() {
        SMOKE_REPO_LIVE_URL='https://example.test/pkg/docs/edge'
        SMOKE_NIGHTLY_LIVE_URL='https://example.test/pkg/docs/nightly'
        SMOKE_REPO_EXPECTED_SOURCE_SHA='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        SMOKE_REPO_EXPECTED_VERSION='4.0.0.a21'
        SMOKE_REPO_EXPECTED_CHANNEL='edge'
        SMOKE_NIGHTLY_EXPECTED_SOURCE_SHA='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
        SMOKE_NIGHTLY_EXPECTED_VERSION='20260810_2'
        SMOKE_PFSENSE_REF='ghcr.io/example/pfsense-plus:26.03'
        CIVM_REF='ghcr.io/example/civm:v2'
        export SMOKE_REPO_LIVE_URL SMOKE_NIGHTLY_LIVE_URL
        export SMOKE_REPO_EXPECTED_SOURCE_SHA SMOKE_REPO_EXPECTED_VERSION SMOKE_REPO_EXPECTED_CHANNEL
        export SMOKE_NIGHTLY_EXPECTED_SOURCE_SHA SMOKE_NIGHTLY_EXPECTED_VERSION
        export SMOKE_PFSENSE_REF CIVM_REF
      }
      BeforeCall 'smoke_values'
      When call run_and_diag --ref dummy
      The line 1 of output should equal 'exit=0'
      The output should include 'exec env'
      The output should include "SMOKE_PFSENSE_REF='ghcr.io/example/pfsense-plus:26.03'"
      The output should include "CIVM_REF='ghcr.io/example/civm:v2'"
      The output should include "SMOKE_REPO_LIVE_URL='https://example.test/pkg/docs/edge'"
      The output should include "SMOKE_NIGHTLY_LIVE_URL='https://example.test/pkg/docs/nightly'"
      The output should include "SMOKE_REPO_EXPECTED_SOURCE_SHA='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"
      The output should include "SMOKE_REPO_EXPECTED_VERSION='4.0.0.a21'"
      The output should include "SMOKE_REPO_EXPECTED_CHANNEL='edge'"
      The output should include "SMOKE_NIGHTLY_EXPECTED_SOURCE_SHA='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'"
      The output should include "SMOKE_NIGHTLY_EXPECTED_VERSION='20260810_2'"
    End
  End

  # ── --git-remote (issue #2497): per-run git source, default origin ────────── #
  Describe '--git-remote'
    It 'substitutes the given remote into BOTH bootstrap fetches (ref + ci-metadata)'
      When call run_and_diag --ref dummy --git-remote 'git://10.20.41.1/pfBlockerNG.git'
      The line 1 of output should equal 'exit=0'
      The line 2 of output should equal 'calls=1'
      The output should include "git fetch --quiet 'git://10.20.41.1/pfBlockerNG.git' 'dummy'"
      The output should include "git fetch --quiet --no-tags 'git://10.20.41.1/pfBlockerNG.git' '+ci-metadata:refs/pfb/ci-metadata'"
      # the substituted bootstrap must not still fetch from origin
      The output should not include "git fetch --quiet origin"
    End

    It 'defaults to origin when neither flag nor env is given'
      When call run_and_diag --ref dummy
      The line 1 of output should equal 'exit=0'
      The line 2 of output should equal 'calls=1'
      The output should include "git fetch --quiet 'origin' 'dummy'"
      The output should include "git fetch --quiet --no-tags 'origin' 'ci-metadata:refs/remotes/origin/ci-metadata'"
    End

    It 'honours PFB_GIT_REMOTE from the environment, with the flag taking precedence'
      preserve_env() { PFB_GIT_REMOTE='env-remote'; export PFB_GIT_REMOTE; }
      BeforeCall 'preserve_env'
      When call run_and_diag --ref dummy --git-remote flag-remote
      The line 1 of output should equal 'exit=0'
      The output should include "git fetch --quiet 'flag-remote' 'dummy'"
      The output should not include "env-remote"
    End

    It 'rejects an empty value before leasing anything'
      When call run_and_diag --ref dummy --git-remote ''
      The line 1 of output should equal 'exit=2'
      The line 2 of output should equal 'calls=0'
      The output should include 'non-empty'
    End

    It 'honours PFB_GIT_REMOTE alone (no flag) — review B2: env support must be failable'
      env_only() { PFB_GIT_REMOTE='env-remote'; export PFB_GIT_REMOTE; }
      BeforeCall 'env_only'
      When call run_and_diag --ref dummy
      The line 1 of output should equal 'exit=0'
      The line 2 of output should equal 'calls=1'
      The output should include "git fetch --quiet 'env-remote' 'dummy'"
    End

    It 'seeds a NEUTRAL ci-metadata ref for a non-origin remote and exports MATRIX_REF (review B3)'
      When call run_and_diag --ref dummy --git-remote mirror-remote
      The line 1 of output should equal 'exit=0'
      # the box-side read-version-matrix.sh must be pointed at the seeded ref, so its
      # own tolerated `git fetch origin ci-metadata` cannot clobber the seed
      The output should include "'+ci-metadata:refs/pfb/ci-metadata'"
      The output should include "MATRIX_REF='refs/pfb/ci-metadata'"
      The output should not include "ci-metadata:refs/remotes/origin/ci-metadata"
    End

    It 'prints the WHOLE --git-remote help block (usage truncated twice with fixed ranges)'
      When call run_and_diag --help
      The line 1 of output should equal 'exit=0'
      # the last line of the flag block — a fixed sed range silently drops it
      The output should include "only an explicit --git-remote '' is rejected."
      The output should not include 'Test-only (env):'
    End

    It 'keeps the default origin path on the classic refspec with MATRIX_REF empty'
      When call run_and_diag --ref dummy
      The line 1 of output should equal 'exit=0'
      The output should include "'ci-metadata:refs/remotes/origin/ci-metadata'"
      The output should include "MATRIX_REF=''"
      The output should not include "refs/pfb/ci-metadata"
    End
  End

End

# issue #2780: a missing or abbreviated ref used to lease a box, then git fetch
# died rc=128 in ~2s with zero tests run. Fail before select-box.sh instead.
Describe 'local-smoke.sh ref preflight (issue #2780)'
  SCRIPT="${PFB_ROOT}/scripts/local-smoke.sh"

  setup() {
    scrub_git_env
    unset PFB_REF
    unset PFB_GIT_REMOTE
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/localsmokeref.XXXXXX")"
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

    # Stub git ls-remote: records argv, exits 0 iff WORK/ls-remote-ok exists.
    # Default is miss (exit 2) so a forgotten marker cannot leak a lease.
    FAKE_LS_REMOTE="${WORK}/fake-ls-remote.sh"
    cat > "$FAKE_LS_REMOTE" <<'FAKEEOF'
#!/bin/sh
printf '%s\n' "$*" >> "${WORK}/ls-remote.args"
if [ -f "${WORK}/ls-remote-ok" ]; then
    exit 0
fi
exit 2
FAKEEOF
    chmod +x "$FAKE_LS_REMOTE"

    TMPDIR="$WORK"
    PFB_SELECT_BOX="$FAKE_SELECT_BOX"
    PFB_BOXES="dummy@dummy"
    PFB_LS_REMOTE="$FAKE_LS_REMOTE"
    PFB_REF_PREFLIGHT=1
    export PFB_SELECT_BOX PFB_BOXES WORK CALLS_DIR TMPDIR PFB_LS_REMOTE PFB_REF_PREFLIGHT
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
    if [ -f "${WORK}/ls-remote.args" ]; then
      printf 'LS_REMOTE_CALLED=1\n'
    else
      printf 'LS_REMOTE_CALLED=0\n'
    fi
    printf '%s\n' "$_out"
    cat "$CALLS_DIR"/* 2>/dev/null
    cat "${WORK}/ls-remote.args" 2>/dev/null
    return 0
  }

  Describe 'abbreviated SHA not in this clone'
    It 'exits 2 and never leases a box'
      When call run_and_diag --ref e1e1e1e1e1e1e1e1
      The line 1 of output should equal 'exit=2'
      The line 2 of output should equal 'calls=0'
      The output should include 'abbreviated SHA'
      The output should include '40-character'
    End
  End

  Describe 'abbreviated SHA that resolves locally'
    run_short_head() {
      _full="$(git_fixture -C "${PFB_ROOT}" rev-parse HEAD)"
      _short="$(printf '%.7s' "$_full")"
      run_and_diag --ref "$_short"
      _boot="$(cat "$CALLS_DIR"/* 2>/dev/null)"
      case "$_boot" in
        *"git fetch --quiet 'origin' '${_full}'"*) printf 'EXPANDED=1\n' ;;
        *) printf 'EXPANDED=0\n' ;;
      esac
    }
    It 'expands to the full 40-character SHA in the bootstrap fetch before leasing'
      When call run_short_head
      The line 1 of output should equal 'exit=0'
      The line 2 of output should equal 'calls=1'
      The output should include 'EXPANDED=1'
    End
  End

  Describe 'branch missing from the box remote'
    It 'exits 2, names the ref, and never leases a box'
      When call run_and_diag --ref issue/not-on-remote
      The line 1 of output should equal 'exit=2'
      The line 2 of output should equal 'calls=0'
      The output should include 'issue/not-on-remote'
      The output should include 'not leasing'
    End

    It 'does not lease N boxes when --shards is set'
      When call run_and_diag --ref issue/not-on-remote --shards 2
      The line 1 of output should equal 'exit=2'
      The line 2 of output should equal 'calls=0'
    End
  End

  Describe 'branch present on the box remote'
    present_branch() {
      true > "${WORK}/ls-remote-ok"
      run_and_diag --ref dummy
    }
    It 'leases once after a successful ls-remote'
      When call present_branch
      The line 1 of output should equal 'exit=0'
      The line 2 of output should equal 'calls=1'
      The output should include 'LS_REMOTE_CALLED=1'
      The output should include "git fetch --quiet 'origin' 'dummy'"
    End
  End
End

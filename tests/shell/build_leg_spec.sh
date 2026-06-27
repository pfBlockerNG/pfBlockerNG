#shellcheck shell=sh
# build_leg_spec.sh — test suite for scripts/build-leg.sh
#
# Layer (a): argv-assembly parity (fast; no real build).
#   Fake sparse-clone-ports.sh and build-pkg-portable.py via SCRIPT_DIR override
#   (symlink real build-leg.sh into a temp scripts dir; put fakes alongside it).
#   Assert each build-site's old direct args are reproduced; prove the amendment-1
#   stdout contract (git chatter does not leak); prove run-keying.
#
# Layer (b): real-build byte/manifest parity (heavier; needs a real ports tree +
#   zstd).  Scaffolded below and explicitly marked skip — not run in the fast PR
#   suite.  See handoff (RESULTS/03_Results.txt) for the gating rationale.

Describe 'build-leg.sh'
  SCRIPT="${PFB_ROOT}/scripts/build-leg.sh"

  # ── Shared setup: fake scripts dir + stubs ───────────────────────────────
  # Symlink the real build-leg.sh into FAKE_SCRIPTS so that SCRIPT_DIR resolves
  # to FAKE_SCRIPTS when called as sh "$FAKE_SCRIPTS/build-leg.sh".  The fakes for
  # sparse-clone-ports.sh and build-pkg-portable.py sit alongside it, so the script's
  # own "${SCRIPT_DIR}/..." calls hit the stubs.
  setup() {
    # Scrub inherited git context (same guard as in the script itself and the exemplar).
    unset GIT_DIR GIT_INDEX_FILE GIT_WORK_TREE GIT_PREFIX GIT_OBJECT_DIRECTORY GIT_COMMON_DIR
    # Ensure CI vars are absent so run-id minting is local (deterministic for tests).
    unset GITHUB_RUN_ID GITHUB_RUN_ATTEMPT LEG RUN_ID PFB_RUN_DIR

    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/buildleg.XXXXXX")"
    FAKE_SCRIPTS="${WORK}/scripts"
    FAKE_LIB="${FAKE_SCRIPTS}/lib"
    mkdir -p "$FAKE_LIB"

    BUILDER_ARGV="${WORK}/builder_argv"
    CLONE_ARGV="${WORK}/clone_argv"
    FAKE_PKG="${WORK}/pfBlockerNG-devel-4.0.0.pkg"
    touch "$FAKE_PKG"

    # Fake build-pkg-portable.py: records argv (one per line) and prints FAKE_PKG_PATH.
    # Called as `python3 "$SCRIPT_DIR/build-pkg-portable.py" ...` by build-leg.sh.
    cat > "${FAKE_SCRIPTS}/build-pkg-portable.py" << 'PYEOF'
#!/usr/bin/env python3
import os, sys
with open(os.environ['BUILDER_ARGV_FILE'], 'w') as f:
    for arg in sys.argv[1:]:
        f.write(arg + '\n')
print(os.environ['FAKE_PKG_PATH'])
PYEOF
    chmod +x "${FAKE_SCRIPTS}/build-pkg-portable.py"

    # Fake sparse-clone-ports.sh: records argv and prints git-checkout chatter to stdout.
    # AMENDMENT 1: build-leg.sh MUST redirect this stdout to stderr; if it does not, the
    # chatter line appears on build-leg's own stdout and the amendment-1 assertion fails.
    cat > "${FAKE_SCRIPTS}/sparse-clone-ports.sh" << 'SHEOF'
#!/bin/sh
printf '%s\n' "$@" > "$CLONE_ARGV_FILE_PATH"
# Simulate git checkout stdout chatter — must NOT reach build-leg stdout.
printf 'Your branch is up to date with origin/pfblockerng/use-github.\n'
SHEOF
    chmod +x "${FAKE_SCRIPTS}/sparse-clone-ports.sh"

    # Symlink the real build-leg.sh and lib/run-id.sh into FAKE_SCRIPTS so SCRIPT_DIR
    # resolves to FAKE_SCRIPTS and the helper includes resolve correctly.
    ln -s "${SCRIPT}" "${FAKE_SCRIPTS}/build-leg.sh"
    ln -s "${PFB_ROOT}/scripts/lib/run-id.sh" "${FAKE_LIB}/run-id.sh"

    # Export paths/vars consumed by the fake stubs and by build-leg.sh.
    export BUILDER_ARGV_FILE="${BUILDER_ARGV}"
    export CLONE_ARGV_FILE_PATH="${CLONE_ARGV}"
    export FAKE_PKG_PATH="${FAKE_PKG}"
    # Pin the run dir under WORK so build-leg.sh never writes to /var/tmp.
    export PFB_RUN_ROOT="${WORK}/pfb-runs"
    # Pre-set RUN_ID so minting is skipped (deterministic in tests).
    export RUN_ID="test-run-buildleg-001"
  }

  cleanup() { rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  # arg_after: extract the value following FLAG in FILE (one-arg-per-line format).
  arg_after() { awk -v f="$1" '$0==f{found=1;next} found{print;exit}' "$2"; }

  # ── Layer (a): argv-assembly parity ──────────────────────────────────────

  # ── Amendment-1: stdout contract ─────────────────────────────────────────
  #
  # The sparse-clone fake prints "Your branch is up to date with ..." to stdout.
  # build-leg.sh redirects sparse-clone's stdout to stderr (1>&2) so that NONE of
  # it reaches build-leg's own stdout.  The caller captures build-leg stdout as the
  # .pkg path; any extra line corrupts that variable.
  #
  # RED→GREEN: against a build-leg that DOES NOT redirect (the naive implementation),
  # the stdout would be two lines — the git chatter + the .pkg path — and the
  # `The output should equal "$FAKE_PKG"` assertion below FAILS.  With the 1>&2
  # redirect it is exactly one line and PASSES.  The red output was recorded manually:
  #   Your branch is up to date with origin/pfblockerng/use-github.
  #   /tmp/buildleg.XXXXXX/pfBlockerNG-devel-4.0.0.pkg
  # (see RESULTS/03_Results.txt for the full red evidence).
  Describe 'amendment-1: stdout contract'
    run_default() {
      sh "${FAKE_SCRIPTS}/build-leg.sh" 2>/dev/null
    }

    It 'stdout is exactly the .pkg path — sparse-clone chatter does not leak (amendment 1)'
      # Scenario: the sparse-clone fake prints git chatter to stdout.
      # Given: build-leg.sh redirects sparse-clone stdout to stderr.
      # When: build-leg.sh is invoked (all defaults).
      # Then: stdout is exactly one line equal to the fake .pkg path.
      When call run_default
      The output should equal "${FAKE_PKG}"
      The lines of output should equal 1
    End
  End

  # ── build-pkg-linux leg: NO --pkgversion, NO --annotate ──────────────────
  Describe 'build-pkg-linux leg'
    check_linux_leg() {
      sh "${FAKE_SCRIPTS}/build-leg.sh" \
        --ports-repo 'pfBlockerNG/FreeBSD-ports' \
        --ports-ref 'pfblockerng/use-github' \
        --channel 'devel' \
        --abi 'FreeBSD:15:amd64' \
        --py-flavor 'py311' \
        --php '8.3' \
        2>/dev/null
      # Assert ABSENCE of --pkgversion (the ADR "neither" — build-pkg-linux omits it).
      if grep -qF -- '--pkgversion' "$BUILDER_ARGV_FILE" 2>/dev/null; then
        echo "pkgversion=present"
      else
        echo "pkgversion=absent"
      fi
      # Assert ABSENCE of --annotate.
      if grep -qF -- '--annotate' "$BUILDER_ARGV_FILE" 2>/dev/null; then
        echo "annotate=present"
      else
        echo "annotate=absent"
      fi
      # Confirm core args are present (proves args went through, not just absent by chance).
      echo "channel=$(arg_after '--channel' "$BUILDER_ARGV_FILE")"
      echo "php=$(arg_after '--php' "$BUILDER_ARGV_FILE")"
    }

    It 'records no --pkgversion and no --annotate in builder argv (the linux-leg neither case)'
      # Scenario: build-pkg-linux leg passes no version override and no annotations.
      # Given: build-leg.sh called without --pkgversion or --annotate.
      # When: builder argv is recorded by the fake.
      # Then: --pkgversion is absent, --annotate is absent, --channel/--php are present.
      When call check_linux_leg
      The output should include 'pkgversion=absent'
      The output should include 'annotate=absent'
      The output should include 'channel=devel'
      The output should include 'php=8.3'
    End
  End

  # ── release leg: --pkgversion + --annotate created + --annotate commit ───
  Describe 'release leg'
    check_release_leg() {
      sh "${FAKE_SCRIPTS}/build-leg.sh" \
        --channel 'devel' \
        --abi 'FreeBSD:15:amd64' \
        --py-flavor 'py311' \
        --php '8.3' \
        --pkgversion '4.0.0.rc.1' \
        --annotate 'created=1750000000' \
        --annotate 'commit=abc1234567890abcdef' \
        2>/dev/null
      echo "pkgversion=$(arg_after '--pkgversion' "$BUILDER_ARGV_FILE")"
      # Annotations are recorded as the VALUE after --annotate (one K=V per record).
      if grep -qF 'created=1750000000' "$BUILDER_ARGV_FILE" 2>/dev/null; then
        echo "annotate_created=present"
      else
        echo "annotate_created=absent"
      fi
      if grep -qF 'commit=abc1234567890abcdef' "$BUILDER_ARGV_FILE" 2>/dev/null; then
        echo "annotate_commit=present"
      else
        echo "annotate_commit=absent"
      fi
    }

    It 'records --pkgversion and --annotate created + commit in builder argv'
      # Scenario: release leg passes a pinned portversion and build-stamp annotations.
      # Given: build-leg.sh called with --pkgversion, --annotate created=, --annotate commit=.
      # When: builder argv is recorded.
      # Then: all three flags and their values appear in the recorded argv.
      When call check_release_leg
      The output should include 'pkgversion=4.0.0.rc.1'
      The output should include 'annotate_created=present'
      The output should include 'annotate_commit=present'
    End
  End

  # ── Branch coverage: absence vs presence of --pkgversion ─────────────────
  # Proves the two paths are genuinely distinct — not always-absent or always-present.
  Describe 'branch coverage: --pkgversion absence vs presence'
    linux_then_release() {
      # linux leg: no --pkgversion
      sh "${FAKE_SCRIPTS}/build-leg.sh" --channel devel 2>/dev/null
      if grep -qF -- '--pkgversion' "$BUILDER_ARGV_FILE" 2>/dev/null; then
        echo "linux_pv=present"
      else
        echo "linux_pv=absent"
      fi
      # release leg: with --pkgversion (different argv file)
      export BUILDER_ARGV_FILE="${WORK}/argv_release"
      sh "${FAKE_SCRIPTS}/build-leg.sh" --channel devel --pkgversion '4.0.0.rc.1' 2>/dev/null
      if grep -qF -- '--pkgversion' "${WORK}/argv_release" 2>/dev/null; then
        echo "release_pv=present"
      else
        echo "release_pv=absent"
      fi
    }

    It 'linux leg has pkgversion=absent; release leg has pkgversion=present — real branch not always-absent'
      # Scenario: the two call paths produce genuinely different argv.
      # Given: first a linux-leg call (no --pkgversion), then a release-leg call (with one).
      # When: both recorded argv files are checked.
      # Then: linux is absent, release is present — the branch is real.
      When call linux_then_release
      The output should include 'linux_pv=absent'
      The output should include 'release_pv=present'
    End
  End

  # ── smoke leg: nightly channel + --pkgversion + --annotate commit ─────────
  Describe 'smoke leg'
    check_smoke_leg() {
      sh "${FAKE_SCRIPTS}/build-leg.sh" \
        --channel 'nightly' \
        --abi 'FreeBSD:15:amd64' \
        --py-flavor 'py311' \
        --php '8.3' \
        --pkgversion '3.2.16.20260606.2' \
        --annotate 'commit=deadbeef00000000cafebabe' \
        2>/dev/null
      echo "channel=$(arg_after '--channel' "$BUILDER_ARGV_FILE")"
      echo "pkgversion=$(arg_after '--pkgversion' "$BUILDER_ARGV_FILE")"
      if grep -qF 'commit=deadbeef00000000cafebabe' "$BUILDER_ARGV_FILE" 2>/dev/null; then
        echo "annotate_commit=present"
      else
        echo "annotate_commit=absent"
      fi
    }

    It 'records channel nightly, --pkgversion 3.2.16.20260606.2, and --annotate commit in builder argv'
      # Scenario: smoke repo-leg builds a nightly .pkg with a pinned version + commit annotation.
      # Given: build-leg.sh called with nightly channel, hard-coded pkgversion, annotate commit.
      # When: builder argv is recorded.
      # Then: channel=nightly, pkgversion and annotate commit match the inputs.
      When call check_smoke_leg
      The output should include 'channel=nightly'
      The output should include 'pkgversion=3.2.16.20260606.2'
      The output should include 'annotate_commit=present'
    End
  End

  # ── Run-keying: different RUN_IDs → different --out dirs ─────────────────
  Describe 'run-keying'
    run_keying_check() {
      # First invocation with RUN_ID=run-key-001
      BUILDER_ARGV_FILE="${WORK}/argv_key1"
      export BUILDER_ARGV_FILE
      RUN_ID="run-key-001" sh "${FAKE_SCRIPTS}/build-leg.sh" --channel devel >/dev/null 2>/dev/null
      out1="$(arg_after '--out' "${WORK}/argv_key1")"

      # Second invocation with a different RUN_ID
      BUILDER_ARGV_FILE="${WORK}/argv_key2"
      export BUILDER_ARGV_FILE
      RUN_ID="run-key-002" sh "${FAKE_SCRIPTS}/build-leg.sh" --channel devel >/dev/null 2>/dev/null
      out2="$(arg_after '--out' "${WORK}/argv_key2")"

      if [ "$out1" != "$out2" ]; then
        echo "keyed=distinct"
        echo "out1=${out1}"
        echo "out2=${out2}"
      else
        # Print actual values for debugging on failure
        printf 'expected distinct OUT dirs, both got: %s\n' "$out1"
        echo "keyed=same"
      fi
    }

    It 'two invocations with different RUN_IDs receive different --out directories'
      # Scenario: run-keyed OUT dirs prevent artifact collision between concurrent legs.
      # Given: build-leg.sh called twice with RUN_ID=run-key-001 and RUN_ID=run-key-002.
      # When: the --out values in each recorded builder argv are compared.
      # Then: they are distinct (keyed by RUN_ID).
      When call run_keying_check
      The output should include 'keyed=distinct'
      The output should match pattern '*run-key-001*'
      The output should match pattern '*run-key-002*'
    End
  End

  # ── Layer (b): real-build byte/manifest parity ───────────────────────────
  #
  # Requires: a real FreeBSD-ports clone at a fixed commit + python3 + zstd.
  # Not run in the fast PR suite (too slow; network dependency).
  # To run manually on a box with the ports tree available:
  #   REAL_PORTS_DIR=<path-to-ports> shellspec tests/shell/build_leg_spec.sh \
  #     --example "real-build parity"
  #
  # SMOKE leg (no created= annotation → reproducible):
  #   Build OLD way (verbatim pre-rewire commands) → PKG_OLD
  #   Build NEW way (build-leg.sh, same inputs)    → PKG_NEW
  #   cmp -s PKG_OLD PKG_NEW  (byte-for-byte identical)
  #
  # RELEASE leg (created= is nondeterministic):
  #   Build OLD way → PKG_OLD; build NEW way → PKG_NEW
  #   Extract +MANIFEST from both via: zstd -dc "$PKG" | tar -xO +MANIFEST
  #   Normalize with jq: del(.annotations.created) + strip created= from comment
  #   Assert normalized manifests identical (name, version, arch, ABI, files,
  #   RUN_DEPENDS, commit= annotation all match).
  Describe 'real-build parity (layer b — heavier, skipped in fast suite)'
    Skip "requires a real ports tree and zstd; run manually with REAL_PORTS_DIR set"

    It 'smoke leg: build-leg.sh produces a byte-identical .pkg to the pre-rewire direct call'
      pending
    End

    It 'release leg: build-leg.sh manifest is identical to pre-rewire modulo created= annotation'
      pending
    End
  End
End

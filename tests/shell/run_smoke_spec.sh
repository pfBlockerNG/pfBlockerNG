#shellcheck shell=sh
# run_smoke_spec.sh — shellspec suite for scripts/run-smoke.sh
#
# Verifies the canonical pytest argv emitted by run-smoke.sh across all three
# caller shapes (local default, UI, CI smoke 'repo'), the single-arg --filter, the
# -m passthrough guard (default -m NOT added when caller's passthrough has one),
# the bare-path REPLACE amendment (positional path in passthrough replaces the
# default tests/smoke), and PYTHON resolution.
#
# RED→GREEN evidence:
#   - Before run-smoke.sh exists (or while any caller inlines its own argv), the
#     "argv is canonical" assertions FAIL because the fake python is never invoked
#     or receives a different argv.
#   - After run-smoke.sh emits the canonical argv, all assertions PASS.
#
# Uses fake python + pytest stubs that record their argv to a file, so no real
# pytest or VM is needed (fully hermetic).

Describe 'run-smoke.sh'
  SCRIPT="${PFB_ROOT}/scripts/run-smoke.sh"

  setup() {
    # Scrub inherited git context (shared-bare-repo rule).
    scrub_git_env
    unset PYTHON GITHUB_ACTIONS
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/runsmokespec.XXXXXX")"
    ARGV_FILE="${WORK}/argv"
    FAKE_BIN="${WORK}/bin"
    mkdir -p "$FAKE_BIN"

    # Fake python: records its argv (one arg per line) to $ARGV_FILE.
    # run-smoke.sh calls: exec $PYTHON -m pytest <args>; the fake captures them.
    cat > "${FAKE_BIN}/python" << 'PYEOF'
#!/bin/sh
printf '%s\n' "$@" > "$ARGV_FILE"
PYEOF
    chmod +x "${FAKE_BIN}/python"

    # Fake python3 for the PYTHON-resolution fallback test.
    cat > "${FAKE_BIN}/python3" << 'PY3EOF'
#!/bin/sh
printf '%s\n' "$@" > "$ARGV_FILE"
PY3EOF
    chmod +x "${FAKE_BIN}/python3"

    # Prepend fake bin so run-smoke.sh's python3 fallback hits our stub.
    PATH="${FAKE_BIN}:${PATH}"
    export PATH ARGV_FILE WORK FAKE_BIN
  }

  teardown() {
    rm -rf "$WORK"
  }

  BeforeEach 'setup'
  AfterEach  'teardown'

  # Helper: read the captured argv (one arg per line) and join with '|' for substring
  # matching. Called AFTER run-smoke.sh has executed the fake python.
  argv_joined() { tr '\n' '|' < "$ARGV_FILE" | sed 's/|$//'; }

  # ── Canonical argv: local default (no args) ──────────────────────────────── #
  # Expected: -m pytest tests/smoke -m smoke --override-ini=addopts= ...
  run_local_default() {
    PYTHON="${FAKE_BIN}/python"
    export PYTHON
    sh "$SCRIPT"
    argv_joined
  }

  Describe 'local default (no args)'
    It 'emits the canonical smoke argv with tests/smoke and -m smoke'
      When call run_local_default
      The output should include "-m|pytest|tests/smoke|-m|smoke"
      The output should include "--override-ini=addopts="
      The output should include "--override-ini=timeout_func_only=true"
      The output should include "--timeout=30"
      The output should include "--timeout-method=signal"
      The output should include "-v"
    End
  End

  # ── Canonical argv: UI call ───────────────────────────────────────────────── #
  run_ui_call() {
    PYTHON="${FAKE_BIN}/python"
    export PYTHON
    sh "$SCRIPT" --paths tests/smoke/ui -m ui_render --timeout 300
    argv_joined
  }

  Describe 'UI call (--paths tests/smoke/ui -m ui_render --timeout 300)'
    It 'uses tests/smoke/ui, ui_render marker, timeout 300'
      When call run_ui_call
      The output should include "tests/smoke/ui|-m|ui_render"
      The output should include "--timeout=300"
      The output should not include "tests/smoke|-m|smoke"
    End
  End

  # ── Canonical argv: CI smoke 'repo' marker ────────────────────────────────── #
  run_ci_repo() {
    PYTHON="${FAKE_BIN}/python"
    export PYTHON
    sh "$SCRIPT" --paths tests/smoke -m repo --timeout 30
    argv_joined
  }

  Describe 'CI smoke repo (--paths tests/smoke -m repo --timeout 30)'
    It 'uses repo marker, timeout 30'
      When call run_ci_repo
      The output should include "tests/smoke|-m|repo"
      The output should include "--timeout=30"
      The output should not include "-m|smoke"
    End
  End

  # ── --filter as a single arg → pytest -k (no word-split) ─────────────────── #
  # The caller flag is --filter (translated to pytest's -k); the expression
  # "a and not b" must ride as one arg. If word-split, it becomes three separate
  # args and the assertion "-k|a and not b" would NOT match.
  run_filter_expr() {
    PYTHON="${FAKE_BIN}/python"
    export PYTHON
    sh "$SCRIPT" --filter "a and not b"
    argv_joined
  }

  Describe '--filter "a and not b" → pytest -k as ONE arg'
    It 'passes the expression to pytest as a single -k argument (no word-split)'
      When call run_filter_expr
      The output should include "-k|a and not b"
    End
  End

  # ── -m passthrough guard: default NOT injected when passthrough has -m ────── #
  # When run-smoke.sh is called as:
  #   run-smoke.sh --timeout 30 tests/smoke -m ui_render
  # The '--timeout 30' is consumed as a structured flag; 'tests/smoke' stops the
  # loop and starts the passthrough ['tests/smoke', '-m', 'ui_render']. The guard
  # detects bare '-m' in the passthrough → does NOT inject the default '-m smoke'.
  # Result: only ui_render rides in; smoke marker is absent.
  run_m_guard() {
    PYTHON="${FAKE_BIN}/python"
    export PYTHON
    sh "$SCRIPT" --timeout 30 tests/smoke -m ui_render
    argv_joined
  }

  Describe '-m guard (passthrough carries its own -m)'
    It 'does NOT inject the default -m smoke when passthrough has bare -m'
      When call run_m_guard
      The output should include "-m|ui_render"
      The output should not include "-m|smoke"
    End
  End

  # ── bare-path REPLACE: positional in passthrough replaces --paths ─────────── #
  # When the passthrough has a positional arg (no --paths given), the default
  # 'tests/smoke' path is SUPPRESSED and only the passthrough path reaches pytest.
  # Assertion: tests/smoke/ui appears; the default 'tests/smoke|-m' sequence does not.
  run_bare_path() {
    PYTHON="${FAKE_BIN}/python"
    export PYTHON
    sh "$SCRIPT" tests/smoke/ui
    argv_joined
  }

  Describe 'bare-path REPLACE amendment'
    It 'positional path in passthrough replaces the default tests/smoke'
      When call run_bare_path
      The output should include "tests/smoke/ui"
      # In glob patterns `|` is alternation (POSIX sh case), not literal.
      # Use should-not-include for a literal substring check instead.
      # Bug shape (if default injected): "...|pytest|tests/smoke|-m|smoke|..." —
      # that literal sequence IS present; correct shape: absent (replaced by passthrough).
      The output should not include "pytest|tests/smoke|-m"
    End
  End

  # ── PYTHON resolution: explicit PYTHON env wins ───────────────────────────── #
  # FAKE_BIN/python is the only python on the fake PATH; if PYTHON is set to it,
  # $ARGV_FILE is written by our fake. If resolution falls through to something else,
  # the test fails (ARGV_FILE won't contain the expected argv).
  run_python_explicit() {
    PYTHON="${FAKE_BIN}/python"
    export PYTHON
    sh "$SCRIPT"
    argv_joined
  }

  Describe 'PYTHON resolution: explicit PYTHON env'
    It 'uses the PYTHON env var when set'
      When call run_python_explicit
      The output should include "-m|pytest"
    End
  End

  # ── PYTHON resolution: fallback to python3 when no .venv ─────────────────── #
  # Unset PYTHON, use a fakerepo root with NO .venv → run-smoke.sh falls back to
  # python3 (our fake python3 on PATH). CI parity: CI runners have no .venv and no
  # PYTHON override; the fallback is the same python3 that CI uses.
  run_python_fallback() {
    unset PYTHON
    WORK_ROOT="${WORK}/fakerepo"
    mkdir -p "$WORK_ROOT/scripts"
    ln -s "$SCRIPT" "${WORK_ROOT}/scripts/run-smoke.sh"
    sh "${WORK_ROOT}/scripts/run-smoke.sh"
    argv_joined
  }

  Describe 'PYTHON resolution: fallback to python3 when no .venv'
    It 'falls back to python3 (CI parity: CI runners have no .venv)'
      When call run_python_fallback
      The output should include "-m|pytest"
    End
  End

  # ── argv injection guard: passthrough metachar reaches pytest literally ────── #
  # When run-smoke.sh receives an arg containing a shell substitution pattern,
  # that string must reach pytest verbatim — no eval, so the subshell is never
  # executed. If the arg were eval'd, the file /tmp/pfb_pwn_test would be created.
  # RED→GREEN: old eval-based passthrough → subshell fires → file created → FAILS.
  # After: successive set -- prepends → file never created → PASSES.
  # Per-test marker under ${WORK} (not a shared /tmp path) so leftovers / a parallel
  # run cannot taint this assertion. The arg uses "\$(...)" — a LITERAL $( in the spec
  # shell (never command-substituted here), with ${WORK} expanded — so run-smoke.sh
  # receives the literal string; only an eval inside run-smoke.sh could fire it.
  run_injection_guard() {
    PYTHON="${FAKE_BIN}/python"
    export PYTHON
    rm -f "${WORK}/pfb_pwn_test"
    sh "$SCRIPT" "\$(touch ${WORK}/pfb_pwn_test)"
    argv_joined
  }

  Describe 'argv injection guard: passthrough metachar is never evaluated'
    It 'passes $(touch ...) as a literal string, never executes it'
      When call run_injection_guard
      The output should include "\$(touch ${WORK}/pfb_pwn_test)"
      The path "${WORK}/pfb_pwn_test" should not be exist
    End
  End

  # ── bare-path fix: a caller PATH is detected by SHAPE (has /, .py, or ::) ──── #
  # '--maxfail 1' passes --maxfail as a flag and '1' as its value. '1' has no path
  # shape, so it is NOT a caller path and the default tests/smoke is still injected.
  # RED→GREEN: old code (any non-'-' token → _CALLER_GAVE_PATH=1) suppressed
  # tests/smoke → FAILS. After (shape match): '1' is not a path → PASSES.
  run_maxfail_not_a_path() {
    PYTHON="${FAKE_BIN}/python"
    export PYTHON
    sh "$SCRIPT" --maxfail 1
    argv_joined
  }

  Describe '--maxfail 1: numeric value is not a positional path'
    It 'still injects the default tests/smoke path (1 is an option value, not a path)'
      When call run_maxfail_not_a_path
      The output should include "tests/smoke"
      The output should include "--maxfail|1"
    End
  End

  # ── bare-path fix: a path AFTER a leading option still replaces the default ── #
  # 'run-smoke.sh --lf tests/smoke/ui' — the path comes after an option. The
  # shape match (tests/smoke/ui has '/') catches it regardless of position, so the
  # default tests/smoke is NOT injected. RED→GREEN: the old position-based
  # (_pt_first reset every token) logic left _pt_first=0 by the path → default
  # wrongly injected → FAILS. After (shape match): path replaces default → PASSES.
  run_path_after_option() {
    PYTHON="${FAKE_BIN}/python"
    export PYTHON
    sh "$SCRIPT" --lf tests/smoke/ui
    argv_joined
  }

  Describe '--lf tests/smoke/ui: a path after a leading option replaces the default'
    It 'uses the caller path (no default tests/smoke injected)'
      When call run_path_after_option
      The output should include "tests/smoke/ui"
      # The default 'tests/smoke' (injected leftmost when no caller path) would join as
      # 'tests/smoke|' — absent here. 'tests/smoke/ui' joins as 'tests/smoke/ui|', which
      # does NOT contain 'tests/smoke|', so this catches a wrongly-injected default.
      The output should not include "tests/smoke|"
    End
  End

  # ── PYTHON/CI parity: GITHUB_ACTIONS=1 uses python3 even when .venv exists ─── #
  # A .venv/bin/python exists in the fake repo root; when GITHUB_ACTIONS is set,
  # run-smoke.sh must skip it and use python3 (CI runners have no .venv, so the
  # .venv gate must be OFF in CI to prevent a stray future .venv from drifting).
  # The .venv/bin/python creates a marker file if invoked — absent = it was skipped.
  # RED→GREEN: old code (no GITHUB_ACTIONS gate) → .venv used → marker created → FAILS.
  # After: GITHUB_ACTIONS gate → python3 used → marker absent → PASSES.
  run_ci_python_resolution() {
    unset PYTHON
    GITHUB_ACTIONS=true
    export GITHUB_ACTIONS
    WORK_ROOT="${WORK}/fakerepo_ci"
    mkdir -p "$WORK_ROOT/scripts" "${WORK_ROOT}/.venv/bin"
    VENV_MARKER="${WORK}/venv_was_called"
    # Write the VENV_MARKER path into the venv python at creation time (heredoc expands it).
    cat > "${WORK_ROOT}/.venv/bin/python" << VENVEOF
#!/bin/sh
touch "$VENV_MARKER"
printf '%s\n' "\$@" > "\$ARGV_FILE"
VENVEOF
    chmod +x "${WORK_ROOT}/.venv/bin/python"
    ln -s "$SCRIPT" "${WORK_ROOT}/scripts/run-smoke.sh"
    sh "${WORK_ROOT}/scripts/run-smoke.sh"
    argv_joined
  }

  Describe 'GITHUB_ACTIONS=true: uses python3 even when .venv exists (CI parity)'
    It 'skips the .venv and falls back to python3 when GITHUB_ACTIONS is set'
      When call run_ci_python_resolution
      The output should include "-m|pytest"
      The path "${WORK}/venv_was_called" should not be exist
    End
  End

  # ── shard slicing (issue #797): --shard/--shard-total teach run-smoke.sh to
  # run a MODULE-level slice of a --paths dir via scripts/shard-modules.sh ──── #
  #
  # RED→GREEN evidence: before run-smoke.sh parses --shard/--shard-total, both
  # flags fall through the Phase-1 loop's default case and STOP it (the `*)
  # break` arm), so they land verbatim in the pytest passthrough instead of
  # driving a splitter call — the round-robin assertions below see the whole
  # --paths dir (not a module slice) and the error-path assertions see exit 0
  # with the bogus flags forwarded to pytest. After implementation, the flags
  # are consumed, the splitter runs, and the assertions flip to green.
  make_shard_fixture() {
    mkdir -p "${WORK}/mods"
    for m in a b c d e; do
      : > "${WORK}/mods/test_${m}.py"
    done
  }

  run_shard0_of2() {
    PYTHON="${FAKE_BIN}/python"
    export PYTHON
    make_shard_fixture
    sh "$SCRIPT" --paths "${WORK}/mods" --shard 0 --shard-total 2
    argv_joined
  }

  Describe 'N=2 shard 0: round-robin even-indexed modules (a, c, e)'
    It 'replaces --paths with exactly the shard-0 module slice, in order, leftmost'
      When call run_shard0_of2
      The output should include "-m|pytest|${WORK}/mods/test_a.py|${WORK}/mods/test_c.py|${WORK}/mods/test_e.py|-m|smoke"
    End
  End

  run_shard1_of2() {
    PYTHON="${FAKE_BIN}/python"
    export PYTHON
    make_shard_fixture
    sh "$SCRIPT" --paths "${WORK}/mods" --shard 1 --shard-total 2
    argv_joined
  }

  Describe 'N=2 shard 1: round-robin odd-indexed modules (b, d)'
    It 'replaces --paths with exactly the shard-1 module slice, in order, leftmost'
      When call run_shard1_of2
      The output should include "-m|pytest|${WORK}/mods/test_b.py|${WORK}/mods/test_d.py|-m|smoke"
    End
  End

  # ── N=1 (default): backwards-compat pin — byte-identical to pre-#797 ──────── #
  run_shard_default_over_paths_dir() {
    PYTHON="${FAKE_BIN}/python"
    export PYTHON
    make_shard_fixture
    sh "$SCRIPT" --paths "${WORK}/mods"
    argv_joined
  }

  Describe 'N=1 (default) over a --paths dir: unchanged single-path argv'
    It 'never calls the splitter -- the whole dir rides as ONE pytest path arg'
      When call run_shard_default_over_paths_dir
      The output should include "-m|pytest|${WORK}/mods|-m|smoke"
    End
  End

  # ── N>1 + an explicit passthrough path: conflicting intents, loud error ──── #
  run_shard_conflict_bare_path() {
    PYTHON="${FAKE_BIN}/python"
    export PYTHON
    make_shard_fixture
    sh "$SCRIPT" --shard-total 2 "${WORK}/mods/test_a.py"
  }

  Describe 'N>1 together with an explicit passthrough path'
    It 'errors loudly and never invokes python (no argv file written)'
      When run run_shard_conflict_bare_path
      The status should be failure
      The stderr should include 'conflict'
      The path "$ARGV_FILE" should not be exist
    End
  End

  # ── N > module count: the requested shard is empty; splitter error propagates ── #
  run_shard_empty_slice() {
    PYTHON="${FAKE_BIN}/python"
    export PYTHON
    make_shard_fixture
    sh "$SCRIPT" --paths "${WORK}/mods" --shard 5 --shard-total 6
  }

  Describe 'shard-total large enough to leave the requested shard EMPTY'
    It 'propagates the splitter error and never invokes python'
      When run run_shard_empty_slice
      The status should be failure
      The stderr should include 'empty'
      The path "$ARGV_FILE" should not be exist
    End
  End

  # ── non-numeric --shard-total: rejected before the splitter ever runs ────── #
  run_shard_total_non_numeric() {
    PYTHON="${FAKE_BIN}/python"
    export PYTHON
    sh "$SCRIPT" --shard-total notanumber
  }

  Describe 'non-numeric --shard-total'
    It 'is rejected with a non-zero exit and never invokes python'
      When run run_shard_total_non_numeric
      The status should be failure
      The stderr should include 'shard-total'
      The path "$ARGV_FILE" should not be exist
    End
  End

  # ── pytest exit 5 under sharding: a partition artifact, not a failure ─────── #
  # A shard's module slice can legitimately select ZERO tests for the requested
  # marker (e.g. a slice of only repo/reboot-marked modules under -m smoke) —
  # pytest then exits 5 ("no tests ran"). Sharded runs must treat that as a pass
  # (the union of all shards is still the whole run); every other rc stays fatal,
  # and an UNSHARDED run keeps exit 5 fatal (there it means a wrong invocation).
  #
  # RED→GREEN: before run-smoke.sh mapped rc 5 under N>1, the first example
  # failed (run-smoke propagated 5); after the mapping it passes.
  make_rc_fake() {
    # Fake python exiting with $1 after recording argv — drives the rc mapping.
    cat > "${FAKE_BIN}/python-rc" << RCEOF
#!/bin/sh
printf '%s\n' "\$@" > "$ARGV_FILE"
exit $1
RCEOF
    chmod +x "${FAKE_BIN}/python-rc"
  }

  run_sharded_pytest_exit5() {
    make_shard_fixture
    make_rc_fake 5
    PYTHON="${FAKE_BIN}/python-rc" sh "$SCRIPT" --paths "${WORK}/mods" --shard 0 --shard-total 2
  }

  Describe 'sharded run whose slice selects no tests (pytest exit 5)'
    It 'treats the empty slice as a pass -- a partition artifact, not a failure'
      When run run_sharded_pytest_exit5
      The status should be success
      The stderr should include 'partition artifact'
      The path "$ARGV_FILE" should be exist
    End
  End

  run_sharded_pytest_exit1() {
    make_shard_fixture
    make_rc_fake 1
    PYTHON="${FAKE_BIN}/python-rc" sh "$SCRIPT" --paths "${WORK}/mods" --shard 0 --shard-total 2
  }

  Describe 'sharded run with real test failures (pytest exit 1)'
    It 'stays fatal -- only exit 5 is mapped, never a genuine failure'
      When run run_sharded_pytest_exit1
      The status should equal 1
    End
  End

  run_unsharded_pytest_exit5() {
    make_shard_fixture
    make_rc_fake 5
    PYTHON="${FAKE_BIN}/python-rc" sh "$SCRIPT" --paths "${WORK}/mods"
  }

  Describe 'unsharded run with pytest exit 5'
    It 'keeps exit 5 fatal -- zero-selected without sharding means a wrong invocation'
      When run run_unsharded_pytest_exit5
      The status should equal 5
    End
  End

End

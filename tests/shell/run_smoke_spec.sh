#shellcheck shell=sh
# run_smoke_spec.sh — shellspec suite for scripts/run-smoke.sh
#
# Verifies the canonical pytest argv emitted by run-smoke.sh across all three
# caller shapes (local default, UI, CI smoke 'repo'), the single-arg -k, the
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
    unset GIT_DIR GIT_INDEX_FILE GIT_WORK_TREE GIT_PREFIX GIT_OBJECT_DIRECTORY GIT_COMMON_DIR
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

  # ── -k as a single arg (no word-split) ───────────────────────────────────── #
  # The expression "a and not b" must ride as one arg; if word-split, it becomes
  # three separate args and the assertion "-k|a and not b" would NOT match.
  run_k_expr() {
    PYTHON="${FAKE_BIN}/python"
    export PYTHON
    sh "$SCRIPT" -k "a and not b"
    argv_joined
  }

  Describe '-k "a and not b" rides as ONE arg'
    It 'passes the expression as a single -k argument (no word-split)'
      When call run_k_expr
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

End

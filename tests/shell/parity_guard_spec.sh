#shellcheck shell=sh
# parity_guard_spec.sh — tests for scripts/parity-guard.sh
#
# Creates minimal fixture workflow YAML snippets in a temp dir and verifies:
#   - A conforming workflow (uses build-leg.sh) exits 0 with no output.
#   - A workflow with a direct build-pkg-portable.py call exits 1 and reports a violation.
#   - A workflow with a direct sparse-clone-ports.sh call exits 1 and reports a violation.
#   - Comment lines mentioning the tools are NOT flagged (allowed mentions in YAML comments).

Describe 'parity-guard.sh'
  GUARD="${PFB_ROOT}/scripts/parity-guard.sh"

  setup() {
    scrub_git_env
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/parity_guard.XXXXXX")"
    WFDIR="${WORK}/workflows"
    mkdir -p "$WFDIR"
  }

  cleanup() { rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  # ── Fixture helpers ───────────────────────────────────────────────────────

  # conforming_workflow: uses build-leg.sh — parity-guard must pass.
  write_conforming() {
    cat > "${WFDIR}/build-pkg.yml" << 'EOF'
name: Build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build .pkg
        run: |
          set -eu
          PKG="$(sh scripts/build-leg.sh --channel devel --abi 'FreeBSD:15:amd64')"
          echo "pkg=$PKG"
EOF
  }

  # violating_builder: directly calls build-pkg-portable.py — violation class 1.
  write_violating_builder() {
    cat > "${WFDIR}/bad-builder.yml" << 'EOF'
name: Bad Build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build .pkg (direct — violation)
        run: |
          python3 scripts/build-pkg-portable.py \
            --ports "${{ runner.temp }}/ports" \
            --channel devel
EOF
  }

  # violating_clone: directly calls sparse-clone-ports.sh — violation class 2.
  write_violating_clone() {
    cat > "${WFDIR}/bad-clone.yml" << 'EOF'
name: Bad Clone
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Clone ports (direct — violation)
        run: |
          sh scripts/sparse-clone-ports.sh \
            https://github.com/pfBlockerNG/FreeBSD-ports \
            pfblockerng/use-github \
            "${{ runner.temp }}/ports" devel 8.3 py311
EOF
  }

  # inline_derived_arg: feeds build-leg.sh a $(...)-derived arg — Rule 3 violation.
  # The $( comes AFTER the build-leg.sh token (the evasion); the capture wrapper's
  # own $( precedes the token and is legit.
  write_inline_derived_arg() {
    cat > "${WFDIR}/inline-derived.yml" << 'EOF'
name: Inline Derived
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build with inline-derived version (violation)
        run: |
          PKG="$(sh scripts/build-leg.sh --pkgversion "$(sh scripts/release-version.sh devel)")"
          echo "$PKG"
EOF
  }

  # env_sourced_arg: feeds build-leg.sh a $PORTVERSION from an env: block — the
  # documented residual, NOT flagged (no $( or backtick after the token).
  write_env_sourced_arg() {
    cat > "${WFDIR}/env-sourced.yml" << 'EOF'
name: Env Sourced
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      PORTVERSION: 4.0.0.rc.1
    steps:
      - uses: actions/checkout@v4
      - name: Build with env-sourced version (legit)
        run: |
          PKG="$(sh scripts/build-leg.sh --pkgversion "$PORTVERSION")"
          echo "$PKG"
EOF
  }

  # comment_mentions: mentions the tool names in YAML comments only — NOT violations.
  write_comment_mentions() {
    cat > "${WFDIR}/comment-ok.yml" << 'EOF'
name: Comment Only
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: |
          # Previously called build-pkg-portable.py and sparse-clone-ports.sh directly.
          # Now uses build-leg.sh instead.
          sh scripts/build-leg.sh --channel devel
EOF
  }

  # ── Tests ─────────────────────────────────────────────────────────────────

  Describe 'conforming workflow (uses build-leg.sh)'
    conforming_run() {
      write_conforming
      sh "$GUARD" "$WFDIR"
    }

    It 'exits 0 and produces no stderr output'
      # Scenario: workflow calls build-leg.sh — the indirection layer.
      # Given: a workflow YAML that invokes only build-leg.sh.
      # When: parity-guard scans the workflows dir.
      # Then: exit 0, no violation output.
      When call conforming_run
      The status should be success
      The stderr should equal ''
    End
  End

  Describe 'direct build-pkg-portable.py call (violation class 1)'
    builder_violation_run() {
      write_violating_builder
      sh "$GUARD" "$WFDIR" 2>&1
    }

    It 'exits 1 and reports a violation on stderr'
      # Scenario: workflow calls build-pkg-portable.py directly.
      # Given: a workflow YAML with a direct python3 build-pkg-portable.py invocation.
      # When: parity-guard scans it.
      # Then: exit 1, violation line printed to stderr containing the filename.
      When run builder_violation_run
      The status should be failure
      The output should include 'build-pkg-portable.py'
      The output should include 'build-leg.sh'
    End
  End

  Describe 'direct sparse-clone-ports.sh call (violation class 2)'
    clone_violation_run() {
      write_violating_clone
      sh "$GUARD" "$WFDIR" 2>&1
    }

    It 'exits 1 and reports a violation on stderr'
      # Scenario: workflow calls sparse-clone-ports.sh directly.
      # Given: a workflow YAML with a direct sh sparse-clone-ports.sh invocation.
      # When: parity-guard scans it.
      # Then: exit 1, violation line printed to stderr containing the filename.
      When run clone_violation_run
      The status should be failure
      The output should include 'sparse-clone-ports.sh'
      The output should include 'build-leg.sh'
    End
  End

  Describe 'tool names in YAML comments only (branch coverage: allowed)'
    comment_run() {
      write_comment_mentions
      sh "$GUARD" "$WFDIR"
    }

    It 'exits 0 — comment mentions are not violations'
      # Scenario: the workflow mentions the old tools only in YAML comment lines.
      # Given: comment lines starting with # reference build-pkg-portable.py and sparse-clone-ports.sh.
      # When: parity-guard scans it.
      # Then: exit 0 (comments are not executable invocations).
      When call comment_run
      The status should be success
      The stderr should equal ''
    End
  End

  Describe 'mixed: conforming + violating in same dir'
    mixed_run() {
      write_conforming
      write_violating_builder
      sh "$GUARD" "$WFDIR" 2>&1
    }

    It 'exits 1 — one violating file is enough to fail'
      # Scenario: a workflows dir contains both a good and a bad file.
      # Given: one conforming file and one with a direct build-pkg-portable.py call.
      # When: parity-guard scans all files in the dir.
      # Then: exit 1 (the violation is detected even alongside clean files).
      When run mixed_run
      The status should be failure
      The output should include 'bad-builder.yml'
    End
  End

  # ── Rule 3: inline-derived arg to build-leg.sh ───────────────────────────
  # The teeth of amendment 4/5 — CI-only step logic must not survive by living
  # one line above (inside) the build-leg.sh call. red→green for Rule 3.
  Describe 'Rule 3: inline-derived arg to build-leg.sh (violation class 3)'
    inline_derived_run() {
      write_inline_derived_arg
      sh "$GUARD" "$WFDIR" 2>&1
    }

    It 'exits 1 — a command-substitution-derived arg after the build-leg.sh token is flagged'
      # Scenario: a build-leg.sh call derives its --pkgversion inline via $(...).
      # Given: build-leg.sh --pkgversion "$(sh scripts/release-version.sh devel)".
      # When: parity-guard scans the workflows dir.
      # Then: exit 1; the inline-derived-arg violation is reported.
      #   This is RED against a guard with only Rules 1-2 (the $() is not a direct
      #   build-pkg-portable.py/sparse-clone-ports.sh call), GREEN with Rule 3.
      When run inline_derived_run
      The status should be failure
      The output should include 'inline-derived.yml'
      The output should include 'inline-derived arg'
    End
  End

  Describe 'Rule 3 branch coverage: env-sourced arg is the allowed residual'
    env_sourced_run() {
      write_env_sourced_arg
      sh "$GUARD" "$WFDIR"
    }

    It 'exits 0 — a build-leg.sh call with an env-sourced variable is NOT flagged'
      # Scenario: build-leg.sh --pkgversion "$PORTVERSION" where PORTVERSION comes
      #   from an env: block (the documented residual, not an inline derivation).
      # Given: the only $ after the token is $PORTVERSION (no $( or backtick).
      # When: parity-guard scans the workflows dir.
      # Then: exit 0 — proves Rule 3 is the AFTER-token-$() branch, not "any $ flags".
      When call env_sourced_run
      The status should be success
      The stderr should equal ''
    End
  End

  # ── Rule 4: direct smoke pytest bypass ─────────────────────────────────────

  # write_smoke_pytest_direct: python -m pytest tests/smoke — Rule 4 violation.
  write_smoke_pytest_direct() {
    cat > "${WFDIR}/smoke-pytest-direct.yml" << 'EOF'
name: Smoke Direct
on: [push]
jobs:
  smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run (violation)
        run: |
          python -m pytest tests/smoke -m smoke
EOF
  }

  # write_unit_pytest_nopath: bare python -m pytest (no tests/smoke path) — NOT a violation.
  # This is the unit runner form used in test.yml; the false-positive guard must keep it green.
  write_unit_pytest_nopath() {
    cat > "${WFDIR}/unit-tests.yml" << 'EOF'
name: Unit Tests
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run unit tests
        run: python -m pytest
EOF
  }

  # write_blessed_smoke_run: run-smoke.sh "$@" — the correct form; no $( after token.
  write_blessed_smoke_run() {
    cat > "${WFDIR}/blessed-smoke.yml" << 'EOF'
name: Blessed Smoke
on: [push]
jobs:
  smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run (blessed — no violation)
        env:
          PYTEST_MARKER: smoke
        run: |
          set -- --paths tests/smoke -m "${PYTEST_MARKER}" --timeout 30
          sh scripts/run-smoke.sh "$@"
EOF
  }

  # write_smoke_pytest3_direct: python3 -m pytest tests/smoke — also a Rule 4 violation.
  write_smoke_pytest3_direct() {
    cat > "${WFDIR}/smoke-pytest3-direct.yml" << 'EOF'
name: Smoke Direct (python3)
on: [push]
jobs:
  smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run (violation)
        run: |
          python3 -m pytest tests/smoke/ui -m ui_render
EOF
  }

  Describe 'Rule 4: direct smoke pytest bypass (violation)'
    smoke_pytest_direct_run() {
      write_smoke_pytest_direct
      sh "$GUARD" "$WFDIR" 2>&1
    }

    It 'exits 1 — python -m pytest tests/smoke is flagged'
      # Scenario: workflow calls python -m pytest tests/smoke directly.
      # Given: a `python -m pytest tests/smoke` line in a workflow run block.
      # When: parity-guard scans it.
      # Then: exit 1 (Rule 4 violation — use run-smoke.sh instead).
      #   RED on a guard with only Rules 1-3; GREEN after Rule 4 is added.
      When run smoke_pytest_direct_run
      The status should be failure
      The output should include 'smoke-pytest-direct.yml'
      The output should include 'run-smoke.sh'
    End
  End

  Describe 'Rule 4: python3 -m pytest tests/smoke/ui also flagged'
    smoke_pytest3_run() {
      write_smoke_pytest3_direct
      sh "$GUARD" "$WFDIR" 2>&1
    }

    It 'exits 1 — python3 -m pytest tests/smoke/ui is a Rule 4 violation'
      When run smoke_pytest3_run
      The status should be failure
      The output should include 'direct smoke pytest call'
    End
  End

  Describe 'Rule 4 false-positive guard: bare python -m pytest (no tests/smoke path)'
    unit_pytest_nopath_run() {
      write_unit_pytest_nopath
      sh "$GUARD" "$WFDIR"
    }

    It 'exits 0 — bare python -m pytest without tests/smoke is NOT flagged'
      # Scenario: the unit runner in test.yml — bare `python -m pytest` (no path).
      # Given: a workflow with `python -m pytest` and no tests/smoke on the same line.
      # When: parity-guard scans it.
      # Then: exit 0 (this is the unit runner, not a smoke bypass).
      When call unit_pytest_nopath_run
      The status should be success
      The stderr should equal ''
    End
  End

  Describe 'Rule 4 false-positive guard: -m "${PYTEST_MARKER}" + run-smoke.sh is blessed'
    blessed_smoke_run() {
      write_blessed_smoke_run
      sh "$GUARD" "$WFDIR"
    }

    It 'exits 0 — set -- ... run-smoke.sh "$@" form is the blessed pattern'
      # Scenario: the correct smoke run pattern — build argv via set --, then
      #   pass to run-smoke.sh (no inline $( on the run-smoke.sh line).
      # Given: a workflow step using run-smoke.sh "$@" (no $( after the token).
      # When: parity-guard scans it.
      # Then: exit 0 — the blessed argv-via-set form is not a Rule 4 or 5 violation.
      When call blessed_smoke_run
      The status should be success
      The stderr should equal ''
    End
  End

  # ── Rule 5: inline-derived arg to run-smoke.sh ──────────────────────────────

  # write_inline_derived_runsmoke: run-smoke.sh with $(...) after it — Rule 5 violation.
  write_inline_derived_runsmoke() {
    cat > "${WFDIR}/inline-runsmoke.yml" << 'EOF'
name: Inline Derived RunSmoke
on: [push]
jobs:
  smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run (violation)
        run: |
          sh scripts/run-smoke.sh -k "$(sh scripts/impacted-tests.sh origin/devel tests/smoke)"
EOF
  }

  # write_blessed_runsmoke: prior-line capture + run-smoke.sh "$@" — NOT a violation.
  write_blessed_runsmoke() {
    cat > "${WFDIR}/blessed-runsmoke.yml" << 'EOF'
name: Blessed RunSmoke
on: [push]
jobs:
  smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run (blessed — no violation)
        run: |
          RUN_ID="$(sh scripts/select-box.sh --print-id)"
          export RUN_ID
          set -- --paths tests/smoke -m smoke --timeout 30
          sh scripts/run-smoke.sh "$@"
EOF
  }

  Describe 'Rule 5: inline-derived arg to run-smoke.sh (violation)'
    inline_runsmoke_run() {
      write_inline_derived_runsmoke
      sh "$GUARD" "$WFDIR" 2>&1
    }

    It 'exits 1 — run-smoke.sh with $(...) after the token is flagged'
      # Scenario: run-smoke.sh receives an inline-derived -k expression.
      # Given: sh scripts/run-smoke.sh -k "$(sh scripts/impacted-tests.sh ...)".
      # When: parity-guard scans it.
      # Then: exit 1 (Rule 5 violation — derive -k in a prior step, not inline).
      #   RED on a guard with only Rules 1-4; GREEN after Rule 5 is added.
      When run inline_runsmoke_run
      The status should be failure
      The output should include 'inline-runsmoke.yml'
      The output should include 'inline-derived arg'
    End
  End

  Describe 'Rule 5 branch coverage: blessed run-smoke.sh form is not flagged'
    blessed_runsmoke_run() {
      write_blessed_runsmoke
      sh "$GUARD" "$WFDIR"
    }

    It 'exits 0 — run-smoke.sh "$@" with no inline $( is not a Rule 5 violation'
      # Scenario: the $(...) is on the RUN_ID= PRIOR line (select-box.sh, not run-smoke.sh).
      # Given: RUN_ID="$(...)" on one line; sh scripts/run-smoke.sh "$@" on a later line.
      # When: parity-guard scans it.
      # Then: exit 0 — the $( is not after the run-smoke.sh token.
      When call blessed_runsmoke_run
      The status should be success
      The stderr should equal ''
    End
  End
End

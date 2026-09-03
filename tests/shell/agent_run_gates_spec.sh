#shellcheck shell=sh
# run-gates.sh gates_for(): the touched-file-type -> canonical-gate-command mapping
# (CLAUDE.md "Canonical gates" table). Pins per-file gates (php -l / sh -n / shellcheck
# emit one command per file), whole-suite gates firing once, and empty input -> no gates.

Describe 'run-gates.sh gates_for()'
  # shellcheck disable=SC2034 # consumed by the Included script's source-only guard
  AGENT_SOURCE_ONLY=1
  Include scripts/agent/run-gates.sh

  # issue #2016: the re-entry-bounds gate is emitted for a .php/.inc OR .sh diff, and
  # exactly ONCE when both are touched -- a duplicated gate is the defect this counts.
  count_reentry_gate() { gates_for | grep -c 'scripts/check_reentry_bounds.py --self-test'; }

  It 'maps a Python file to the four Python gates'
    Data "tests/test_x.py"
    When call gates_for
    The line 1 of output should equal 'uv run --locked pytest'
    The line 2 of output should equal 'uv run --locked ruff check .'
    The line 3 of output should equal 'uv run --locked ruff format --check .'
    The line 4 of output should equal 'uv run --locked mypy tests/'
    The lines of output should equal 4
  End

  It 'maps PHP files to per-file lint, the toggle-registry and re-entry-bounds gates, and the three suite gates'
    Data
      #|src/a.inc
      #|src/b.php
    End
    When call gates_for
    The line 1 of output should equal 'uv run --locked python scripts/check_composer_vendor.py'
    # issue #2123: the red canary runs first in the same command, so a rotted matcher
    # fails the gate instead of greening the real scan.
    The line 2 of output should equal 'uv run --locked python scripts/check_toggle_registry.py --self-test && uv run --locked python scripts/check_toggle_registry.py'
    # issue #2016: nested pfblockerng.php re-entries must stay bounded at the seam. Same
    # red-canary-first shape, emitted directly after the toggle-registry gate.
    The line 3 of output should equal 'uv run --locked python scripts/check_reentry_bounds.py --self-test && uv run --locked python scripts/check_reentry_bounds.py'
    The line 4 of output should equal 'php -l src/a.inc'
    The line 5 of output should equal 'php -l src/b.php'
    The line 6 of output should equal 'vendor/bin/phpunit'
    The line 7 of output should equal 'composer phpstan'
    The line 8 of output should equal 'composer phpcs -- --standard=phpcs.xml.dist src/'
    The lines of output should equal 8
  End

  It 'emits the re-entry-bounds gate exactly once for a PHP-only diff'
    Data
      #|src/a.inc
      #|src/b.php
    End
    When call count_reentry_gate
    The output should equal '1'
  End

  It 'maps shell files to the re-entry-bounds gate, per-file sh -n + shellcheck, and the dash-pinned shellspec'
    Data "scripts/agent/x.sh"
    When call gates_for
    # issue #2016: pfblockerng.sh owns four of the eight blocking re-entry sites, so a
    # shell-only diff carries the gate too -- first line of the shell bucket.
    The line 1 of output should equal 'uv run --locked python scripts/check_reentry_bounds.py --self-test && uv run --locked python scripts/check_reentry_bounds.py'
    The line 2 of output should equal 'sh -n scripts/agent/x.sh'
    The line 3 of output should equal 'shellcheck scripts/agent/x.sh'
    # shellcheck disable=SC2016 # the literal $( ) is the pinned command text
    The line 4 of output should equal 'shellspec --shell $(command -v dash || command -v sh)'
    The lines of output should equal 4
  End

  It 'emits the re-entry-bounds gate exactly once for a shell-only diff'
    Data "scripts/agent/x.sh"
    When call count_reentry_gate
    The output should equal '1'
  End

  It 'emits the re-entry-bounds gate exactly once for a mixed PHP + shell diff'
    # Both buckets want the gate; emitting it twice would run the same scan twice and
    # report two verdicts for one question.
    Data
      #|src/a.php
      #|scripts/b.sh
    End
    When call count_reentry_gate
    The output should equal '1'
  End

  It 'keeps the re-entry-bounds gate in its PHP-bucket position for a mixed PHP + shell diff'
    Data
      #|src/a.php
      #|scripts/b.sh
    End
    When call gates_for
    The line 1 of output should equal 'uv run --locked python scripts/check_composer_vendor.py'
    The line 2 of output should equal 'uv run --locked python scripts/check_toggle_registry.py --self-test && uv run --locked python scripts/check_toggle_registry.py'
    The line 3 of output should equal 'uv run --locked python scripts/check_reentry_bounds.py --self-test && uv run --locked python scripts/check_reentry_bounds.py'
    The line 4 of output should equal 'php -l src/a.php'
    The line 5 of output should equal 'vendor/bin/phpunit'
    The line 6 of output should equal 'composer phpstan'
    The line 7 of output should equal 'composer phpcs -- --standard=phpcs.xml.dist src/'
    The line 8 of output should equal 'sh -n scripts/b.sh'
    The line 9 of output should equal 'shellcheck scripts/b.sh'
    # shellcheck disable=SC2016 # the literal $( ) is the pinned command text
    The line 10 of output should equal 'shellspec --shell $(command -v dash || command -v sh)'
    The lines of output should equal 10
  End

  It 'wraps the selected pytest gate with JUnit, canary, and real check'
    When call gate_command 'uv run --locked pytest'
    The output should include '--junitxml="$PFB_SKIP_REPORT_DIR/pytest.xml"'
    The output should include '--suite pytest'
    The output should include 'skip-allowlist-canary.xml'
  End

  It 'wraps the selected PHPUnit gate with JUnit, canary, and real check'
    When call gate_command 'vendor/bin/phpunit'
    The output should include '--log-junit "$PFB_SKIP_REPORT_DIR/phpunit.xml"'
    The output should include '--suite phpunit'
    The output should include 'skip-allowlist-canary.xml'
  End

  It 'wraps the selected ShellSpec gate with JUnit, canary, and real check'
    # shellcheck disable=SC2016 # the literal $( ) is the pinned command text
    When call gate_command 'shellspec --shell $(command -v dash || command -v sh)'
    The output should include '-o junit --reportdir "$PFB_SKIP_REPORT_DIR/shellspec"'
    The output should include '--suite shellspec'
    The output should include 'skip-allowlist-canary.xml'
  End

  It 'syntax-checks an out-of-scope shell file but does not shellcheck it'
    # The hook + CI shellcheck only src/, scripts/ and .claude/hooks/; tests/ specs and
    # skill helpers are outside that production-tooling scope.
    Data
      #|tests/shell/agent_work_branch_spec.sh
      #|.agents/skills/release/helper.sh
    End
    When call gates_for
    The line 1 of output should equal 'uv run --locked python scripts/check_reentry_bounds.py --self-test && uv run --locked python scripts/check_reentry_bounds.py'
    The line 2 of output should equal 'sh -n tests/shell/agent_work_branch_spec.sh'
    The line 3 of output should equal 'sh -n .agents/skills/release/helper.sh'
    # shellcheck disable=SC2016 # the literal $( ) is the pinned command text
    The line 4 of output should equal 'shellspec --shell $(command -v dash || command -v sh)'
    The lines of output should equal 4
    The output should not include 'shellcheck'
  End

  It 'shellchecks only the in-scope files of a mixed in/out-of-scope shell diff'
    Data
      #|src/usr/local/pkg/pfblockerng/pfblockerng.sh
      #|.claude/hooks/x.sh
      #|tests/shell/y_spec.sh
    End
    When call gates_for
    The line 1 of output should equal 'uv run --locked python scripts/check_reentry_bounds.py --self-test && uv run --locked python scripts/check_reentry_bounds.py'
    The line 2 of output should equal 'sh -n src/usr/local/pkg/pfblockerng/pfblockerng.sh'
    The line 3 of output should equal 'shellcheck src/usr/local/pkg/pfblockerng/pfblockerng.sh'
    The line 4 of output should equal 'sh -n .claude/hooks/x.sh'
    The line 5 of output should equal 'shellcheck .claude/hooks/x.sh'
    The line 6 of output should equal 'sh -n tests/shell/y_spec.sh'
    # shellcheck disable=SC2016 # the literal $( ) is the pinned command text
    The line 7 of output should equal 'shellspec --shell $(command -v dash || command -v sh)'
    The lines of output should equal 7
  End

  It 'maps Markdown to markdownlint'
    Data "docs/misc/notes.md"
    When call gates_for
    The output should equal 'npx markdownlint-cli2'
  End

  It 'ignores every legacy file type'
    Data
      #|legacy/old.py
      #|legacy/old.sh
      #|legacy/old.md
    End
    When call gates_for
    The output should equal ''
  End

  It 'combines gate families for a mixed diff'
    Data
      #|a.py
      #|scripts/b.sh
    End
    When call gates_for
    The output should include 'uv run --locked pytest'
    The output should include 'shellcheck scripts/b.sh'
  End

  It 'refuses to build a command from an unsafe path that feeds a per-file gate'
    Data "evil\$(touch pwned).sh"
    When call gates_for
    The line 1 of output should equal "printf 'unsafe filename in diff\\n' >&2; false"
  End

  It 'keeps aggregate gates for an unsafe-named Python file (no per-file interpolation)'
    Data "my file.py"
    When call gates_for
    The line 1 of output should equal 'uv run --locked pytest'
    The lines of output should equal 4
  End

  It 'ignores an unsafe-named file that has no gates at all'
    Data
      #|legacy/ADRs/ADR_04/07_Unbound_(next_only).txt
      #|scripts/ok.py
    End
    When call gates_for
    The line 1 of output should equal 'uv run --locked pytest'
    The output should not include 'unsafe filename'
  End

  It 'emits nothing for file types with no gates'
    Data "src/usr/local/pkg/pfblockerng/info.xml"
    When call gates_for
    The output should equal ''
  End
End

Describe 'run-gates.sh Composer vendor guard'
  gitc() { git_fixture -C "$repo" -c user.email=t@t -c user.name=t "$@"; }
  make_repo() {
    scrub_git_env
    repo="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/rungatesphp.XXXXXX")"
    git_fixture -C "$repo" init -q
    gitc config commit.gpgsign false
    mkdir -p "$repo/src" "$repo/vendor/bin" "$repo/scripts/agent"
    printf 'base\n' > "$repo/README"
    # issue #3139: the always-on graph-freshness gate runs the checkout's own script;
    # a fresh-graph stand-in keeps these rows about the Composer checker.
    printf '#!/bin/sh\nexit 0\n' > "$repo/scripts/agent/check-graph-fresh.sh"
    gitc add -A; gitc commit -qm base
    base_sha=$(gitc rev-parse HEAD)
    printf '<?php echo 1;\n' > "$repo/src/a.php"
    gitc add -A; gitc commit -qm php

    stubdir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/rungatesphpstub.XXXXXX")"
    checker_marker="$stubdir/checker-ran"
    php_marker="$stubdir/php-ran"
    composer_marker="$stubdir/composer-ran"
    phpunit_marker="$stubdir/phpunit-ran"
    # The vendor checker runs through the locked uv environment, so `uv` is the tool
    # run_gate resolves for that gate; the stub stands in for the whole invocation.
    pairing_marker="$stubdir/pairing-ran"
    {
      printf '%s\n' '#!/bin/sh' \
        'if [ "$1" = scripts/check_skip_allowlist.py ]; then' \
        '  case "$*" in *skip-allowlist-canary.xml*) exit 1 ;; esac' \
        '  for report do :; done' \
        '  [ -f "$report" ] || exit 2' \
        '  exit 0' \
        'fi' \
        'cat >/dev/null'
      printf 'touch "%s"\nexit 0\n' "$pairing_marker"
    } > "$stubdir/python3"
    printf '#!/bin/sh\ntouch "%s"\nprintf "version mismatch: phpstan/phpstan (locked 2.2.5; installed 2.2.1)\\nremediation: composer install --no-interaction\\n"\nexit 1\n' "$checker_marker" > "$stubdir/uv"
    printf '#!/bin/sh\ntouch "%s"\nexit 0\n' "$php_marker" > "$stubdir/php"
    printf '#!/bin/sh\ntouch "%s"\nexit 0\n' "$composer_marker" > "$stubdir/composer"
    {
      printf '%s\n' '#!/bin/sh' 'report=' \
        'while [ "$#" -gt 0 ]; do' \
        '  if [ "$1" = --log-junit ]; then shift; report=$1; fi' \
        '  shift' \
        'done' \
        'printf "<testsuites/>\\n" > "$report"'
      printf 'touch "%s"\nexit 0\n' "$phpunit_marker"
    } > "$repo/vendor/bin/phpunit"
    chmod +x "$stubdir/python3" "$stubdir/uv" "$stubdir/php" "$stubdir/composer" "$repo/vendor/bin/phpunit"
    ln -s "$(command -v git)" "$stubdir/git"
    # The minimal-PATH contract uses only POSIX utilities. The report directory
    # adds mkdir; rm reaps it and the NUL-separated path/status files.
    for tool in cat dirname grep mkdir rm sh sort tr; do
      ln -s "$(command -v "$tool")" "$stubdir/$tool"
    done
    PATH="$stubdir:$PATH"
  }
  cleanup() { rm -rf "$repo" "$stubdir"; }
  Before 'make_repo'
  After 'cleanup'
  script="scripts/agent/run-gates.sh"

  It 'stops before PHP analysis when the Composer vendor checker fails'
    When run sh "$script" --worktree "$repo" --diff "$base_sha"
    The status should equal 1
    The line 1 of output should equal 'GATE PASS: python3 scripts/check_coverage_pairing.py --name-status-z'
    The line 2 of output should equal 'GATE PASS: sh scripts/agent/check-graph-fresh.sh'
    The line 3 of output should equal 'version mismatch: phpstan/phpstan (locked 2.2.5; installed 2.2.1)'
    The line 4 of output should equal 'remediation: composer install --no-interaction'
    The output should include 'GATE FAIL: uv run --locked python scripts/check_composer_vendor.py'
    The output should not include 'GATE PASS: php -l src/a.php'
    The output should not include 'GATE PASS: vendor/bin/phpunit'
    The output should not include 'GATE PASS: composer phpstan'
    The output should not include 'GATE PASS: composer phpcs -- --standard=phpcs.xml.dist src/'
    The lines of output should equal 6
    Assert [ -e "$pairing_marker" ]
    Assert [ -e "$checker_marker" ]
    Assert [ ! -e "$php_marker" ]
    Assert [ ! -e "$composer_marker" ]
    Assert [ ! -e "$phpunit_marker" ]
  End

  It 'keeps a checker OVERALL=0 diagnostic from passing the final verdict'
    printf '#!/bin/sh\nprintf "checker diagnostic OVERALL=0\\n"\nexit 1\n' > "$stubdir/uv"
    chmod +x "$stubdir/uv"
    When run sh "$script" --worktree "$repo" --diff "$base_sha"
    The status should equal 1
    The output should include 'checker diagnostic OVERALL=0'
    The output should include 'GATE FAIL: uv run --locked python scripts/check_composer_vendor.py'
    The output should include 'GATES: FAIL'
    The output should not include 'GATES: PASS'
  End

  It 'fails closed under --allow-missing when the checker interpreter is unavailable'
    # The vendor guard is the one gate a missing tool may never soften into a SKIP: every
    # Composer-backed gate downstream of it is unsafe against an unverified vendor tree.
    rm -f "$stubdir/uv"
    When run sh -c "PATH='$stubdir' sh '$script' --worktree '$repo' --diff '$base_sha' --allow-missing"
    The status should equal 1
    The output should include 'GATE FAIL: uv run --locked python scripts/check_composer_vendor.py (TOOL-MISSING: uv)'
    The output should not include 'GATE SKIP: uv run --locked python scripts/check_composer_vendor.py'
    The output should not include 'GATE PASS: php -l src/a.php'
    The output should not include 'GATE PASS: vendor/bin/phpunit'
    The output should not include 'GATE PASS: composer phpstan'
    The output should not include 'GATE PASS: composer phpcs -- --standard=phpcs.xml.dist src/'
    Assert [ ! -e "$php_marker" ]
    Assert [ ! -e "$composer_marker" ]
    Assert [ ! -e "$phpunit_marker" ]
  End

  It 'suppresses successful Composer checker diagnostics while running PHP gates'
    printf '#!/bin/sh\ntouch "%s"\nprintf "checker stdout\\n"\nprintf "checker stderr\\n" >&2\nexit 0\n' "$checker_marker" > "$stubdir/uv"
    chmod +x "$stubdir/uv"
    When run sh "$script" --worktree "$repo" --diff "$base_sha"
    The status should equal 0
    The output should not include 'checker stdout'
    The output should not include 'checker stderr'
    The stderr should equal ''
    The output should include 'GATE PASS: uv run --locked python scripts/check_composer_vendor.py'
    The output should include 'GATE PASS: php -l src/a.php'
    The output should include 'GATE PASS: vendor/bin/phpunit'
    The output should include 'GATE PASS: composer phpstan'
    The output should include 'GATE PASS: composer phpcs -- --standard=phpcs.xml.dist src/'
    The output should include 'GATES: PASS'
    Assert [ -e "$checker_marker" ]
    Assert [ -e "$php_marker" ]
    Assert [ -e "$composer_marker" ]
    Assert [ -e "$phpunit_marker" ]
  End
End

Describe 'run-gates.sh main (fixture repo, stubbed tools)'
  gitc() { git_fixture -C "$repo" -c user.email=t@t -c user.name=t "$@"; }
  make_repo() {
    scrub_git_env
    # Controlled stubs isolate run-gates wiring from the real checker/tool suites.
    stubdir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gatestub.XXXXXX")"
    # issue #3139: the always-on graph-freshness gate runs the checkout's own
    # scripts/agent/check-graph-fresh.sh. The tracked copy only defers to this
    # out-of-repo file, so an example can change the verdict without touching a
    # tracked .sh and thereby planning extra per-file gates.
    graph_check="$stubdir/check-graph-fresh"
    printf '#!/bin/sh\nexit 0\n' > "$graph_check"
    repo="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/rungates.XXXXXX")"
    git_fixture -C "$repo" init -q
    # Under scripts/ so the files are in shellcheck's scope (src, scripts, .claude/hooks).
    mkdir -p "$repo/scripts/agent" "$repo/tests"
    printf '#!/bin/sh\n# gone-marker: content distinct from kept.sh so git reports a\n# genuine deletion (identical content collapses to an R100 rename)\ntrue\n' > "$repo/scripts/gone.sh"
    printf '#!/bin/sh\nexec sh "%s"\n' "$graph_check" > "$repo/scripts/agent/check-graph-fresh.sh"
    gitc add -A; gitc commit -qm base
    base_sha=$(gitc rev-parse HEAD)
    gitc rm -q scripts/gone.sh
    mkdir -p "$repo/scripts"
    printf '#!/bin/sh\ntrue\n' > "$repo/scripts/kept.sh"
    printf 'paired\n' > "$repo/tests/coverage-pairing.fixture"
    gitc add -A; gitc commit -qm head
    marker="$stubdir/last-gate-ran"
    pairing_raw="$stubdir/pairing.raw"
    pairing_lines="$stubdir/pairing.lines"
    require_pair="$stubdir/require-pair"
    {
      printf '%s\n' '#!/bin/sh' \
        'if [ "$1" = scripts/check_skip_allowlist.py ]; then' \
        '  case "$*" in *skip-allowlist-canary.xml*) exit 1 ;; esac' \
        '  for report do :; done' \
        '  [ -f "$report" ] || exit 2' \
        '  exit 0' \
        'fi'
      printf 'cat > "%s"\ntr "\\0" "\\n" < "%s" > "%s"\nif [ -e "%s" ]; then grep -q "^tests/" "%s"; fi\n' \
        "$pairing_raw" "$pairing_raw" "$pairing_lines" "$require_pair" "$pairing_lines"
    } > "$stubdir/python3"
    {
      printf '%s\n' '#!/bin/sh' 'reportdir=' \
        'while [ "$#" -gt 0 ]; do' \
        '  if [ "$1" = --reportdir ]; then shift; reportdir=$1; fi' \
        '  shift' \
        'done' \
        'printf "<testsuites/>\\n" > "$reportdir/results_junit.xml"'
      printf 'touch "%s"\n' "$marker"
    } > "$stubdir/shellspec"
    printf '#!/bin/sh\nexit 0\n' > "$stubdir/shellcheck"
    # issue #2016: a .sh diff now plans the re-entry-bounds gate, which runs through uv.
    printf '#!/bin/sh\nexit 0\n' > "$stubdir/uv"
    chmod +x "$stubdir/python3" "$stubdir/shellspec" "$stubdir/shellcheck" "$stubdir/uv"
    PATH="$stubdir:$PATH"
  }
  cleanup() { rm -rf "$repo" "$stubdir"; }
  Before 'make_repo'
  After 'cleanup'
  script="scripts/agent/run-gates.sh"

  It 'executes EVERY planned gate including the last one, and passes'
    When run sh -c "TMPDIR='$stubdir' sh '$script' --worktree '$repo' --diff '$base_sha'"
    The status should equal 0
    The line 1 of output should equal 'GATE PASS: python3 scripts/check_coverage_pairing.py --name-status-z'
    # issue #3139: the graph-freshness gate is always-on and follows pairing directly.
    The line 2 of output should equal 'GATE PASS: sh scripts/agent/check-graph-fresh.sh'
    # issue #2016: the re-entry-bounds gate leads the shell bucket, so it is gate 3 here.
    The line 3 of output should equal 'GATE PASS: uv run --locked python scripts/check_reentry_bounds.py --self-test && uv run --locked python scripts/check_reentry_bounds.py'
    The output should include 'GATE PASS: sh -n scripts/kept.sh'
    The output should include 'GATE PASS: shellspec'
    The line 7 of output should equal 'GATES: PASS'
    Assert [ -e "$marker" ]
    Assert [ ! -e "$stubdir"/pfb-run-gates-skip-reports.* ]
  End

  # issue #3139: a stale graphify-out/graph.json is a property of the whole tree, not of
  # a touched file type, so the gate is planned on every run -- right after pairing and
  # before any file-type bucket.
  It 'plans the graph-freshness gate second, ahead of every file-type gate'
    When run sh "$script" --worktree "$repo" --diff "$base_sha" --plan
    The status should equal 0
    The line 1 of output should equal 'python3 scripts/check_coverage_pairing.py --name-status-z'
    The line 2 of output should equal 'sh scripts/agent/check-graph-fresh.sh'
    The line 3 of output should equal 'uv run --locked python scripts/check_reentry_bounds.py --self-test && uv run --locked python scripts/check_reentry_bounds.py'
  End

  It 'fails the run on a stale graph, printing the checker diagnostic first, and still runs the later gates'
    printf '#!/bin/sh\nprintf "check-graph-fresh.sh: STALE: graphify-out/graph.json differs from a rebuild of this tree\\n" >&2\nexit 1\n' > "$graph_check"
    When run sh "$script" --worktree "$repo" --diff "$base_sha"
    The status should equal 1
    The line 1 of output should equal 'GATE PASS: python3 scripts/check_coverage_pairing.py --name-status-z'
    The line 2 of output should equal 'check-graph-fresh.sh: STALE: graphify-out/graph.json differs from a rebuild of this tree'
    The line 3 of output should equal 'GATE FAIL: sh scripts/agent/check-graph-fresh.sh'
    The output should include 'GATE PASS: shellspec'
    The output should include 'GATES: FAIL'
    The stderr should equal ''
    Assert [ -e "$marker" ]
  End

  # A missing Graphify is a mandatory-tool failure for this gate: the runner resolves
  # `sh`, never graphify, so --allow-missing cannot soften the checker's exit 4 into a SKIP.
  It 'fails the run (never SKIP) when the graph checker reports Graphify missing, even under --allow-missing'
    printf '#!/bin/sh\nprintf "resolve-graphify.sh: Graphify is not installed; run %s first\\n" >&2\nexit 4\n' "'uv tool install --upgrade graphifyy'" > "$graph_check"
    When run sh "$script" --worktree "$repo" --diff "$base_sha" --allow-missing
    The status should equal 1
    The line 2 of output should equal "resolve-graphify.sh: Graphify is not installed; run 'uv tool install --upgrade graphifyy' first"
    The line 3 of output should equal 'GATE FAIL: sh scripts/agent/check-graph-fresh.sh'
    The output should not include 'GATE SKIP: sh scripts/agent/check-graph-fresh.sh'
    The output should include 'GATES: FAIL'
  End

  It 'preserves a selected suite failure and cleans its report directory'
    printf '#!/bin/sh\nexit 37\n' > "$stubdir/shellspec"
    chmod +x "$stubdir/shellspec"
    When run sh -c "TMPDIR='$stubdir' sh '$script' --worktree '$repo' --diff '$base_sha'"
    The status should equal 1
    The output should include 'GATE FAIL: shellspec --shell $(command -v dash || command -v sh)'
    The output should include 'GATES: FAIL'
    The output should not include 'red canary failed'
    Assert [ ! -e "$stubdir"/pfb-run-gates-skip-reports.* ]
  End

  It 'fails when the checker accepts the known-skip canary'
    {
      printf '%s\n' '#!/bin/sh' \
        'if [ "$1" = scripts/check_skip_allowlist.py ]; then exit 0; fi'
      printf 'cat > "%s"\ntr "\\0" "\\n" < "%s" > "%s"\n' \
        "$pairing_raw" "$pairing_raw" "$pairing_lines"
    } > "$stubdir/python3"
    chmod +x "$stubdir/python3"
    When run sh "$script" --worktree "$repo" --diff "$base_sha"
    The status should equal 1
    The output should include 'red canary failed: an unlisted skip did not fail the gate'
    The output should include 'GATE FAIL: shellspec --shell $(command -v dash || command -v sh)'
    The output should include 'GATES: FAIL'
  End

  It 'feeds exact NUL status records to the first checker gate'
    expected=$(printf 'D\nscripts/gone.sh\nA\nscripts/kept.sh\nA\ntests/coverage-pairing.fixture')
    When run sh "$script" --worktree "$repo" --diff "$base_sha"
    The status should equal 0
    The output should include 'GATE PASS: python3 scripts/check_coverage_pairing.py --name-status-z'
    The contents of file "$pairing_lines" should equal "$expected"
  End

  It 'propagates an unpaired release-only checker failure outside plan mode'
    unpaired_base=$(gitc rev-parse HEAD)
    printf '#!/bin/sh\n# unpaired release edit\ntrue\n' > "$repo/scripts/kept.sh"
    gitc add scripts/kept.sh
    gitc commit -qm unpaired
    touch "$require_pair"
    expected=$(printf 'M\nscripts/kept.sh')
    When run sh "$script" --worktree "$repo" --diff "$unpaired_base"
    The status should equal 1
    The line 1 of output should equal 'GATE FAIL: python3 scripts/check_coverage_pairing.py --name-status-z'
    The output should include 'GATES: FAIL'
    The contents of file "$pairing_lines" should equal "$expected"
  End

  It 'runs later gates after an ordinary failure and keeps the final failure verdict'
    printf '#!/bin/sh\nexit 1\n' > "$stubdir/shellcheck"
    chmod +x "$stubdir/shellcheck"
    When run sh "$script" --worktree "$repo" --diff "$base_sha"
    The status should equal 1
    The output should include 'GATE FAIL: shellcheck scripts/kept.sh'
    The output should include 'GATE PASS: shellspec'
    The output should include 'GATES: FAIL'
    Assert [ -e "$marker" ]
  End

  # issue #1865: a failing gate previously discarded its own stdout/stderr, so
  # `GATE FAIL: <cmd>` alone carried no diagnostic content.
  It 'prints a failing generic gate stdout before its own GATE FAIL line'
    printf '#!/bin/sh\nprintf "shellcheck stdout diagnostic\\n"\nexit 1\n' > "$stubdir/shellcheck"
    chmod +x "$stubdir/shellcheck"
    When run sh "$script" --worktree "$repo" --diff "$base_sha"
    The status should equal 1
    The line 1 of output should equal 'GATE PASS: python3 scripts/check_coverage_pairing.py --name-status-z'
    The line 4 of output should equal 'GATE PASS: sh -n scripts/kept.sh'
    The line 5 of output should equal 'shellcheck stdout diagnostic'
    The line 6 of output should equal 'GATE FAIL: shellcheck scripts/kept.sh'
    The output should include 'GATE PASS: shellspec'
    The output should include 'GATES: FAIL'
    Assert [ -e "$marker" ]
  End

  It 'prints a failing generic gate stderr before its own GATE FAIL line (combined capture)'
    printf '#!/bin/sh\nprintf "shellcheck stderr diagnostic\\n" >&2\nexit 1\n' > "$stubdir/shellcheck"
    chmod +x "$stubdir/shellcheck"
    When run sh "$script" --worktree "$repo" --diff "$base_sha"
    The status should equal 1
    The line 1 of output should equal 'GATE PASS: python3 scripts/check_coverage_pairing.py --name-status-z'
    The line 4 of output should equal 'GATE PASS: sh -n scripts/kept.sh'
    The line 5 of output should equal 'shellcheck stderr diagnostic'
    The line 6 of output should equal 'GATE FAIL: shellcheck scripts/kept.sh'
    The stderr should equal ''
  End

  It 'preserves every line, in order, for a multi-line failing gate'
    printf '#!/bin/sh\nprintf "line one\\nline two\\nline three\\n"\nexit 1\n' > "$stubdir/shellcheck"
    chmod +x "$stubdir/shellcheck"
    When run sh "$script" --worktree "$repo" --diff "$base_sha"
    The status should equal 1
    The line 1 of output should equal 'GATE PASS: python3 scripts/check_coverage_pairing.py --name-status-z'
    The line 4 of output should equal 'GATE PASS: sh -n scripts/kept.sh'
    The line 5 of output should equal 'line one'
    The line 6 of output should equal 'line two'
    The line 7 of output should equal 'line three'
    The line 8 of output should equal 'GATE FAIL: shellcheck scripts/kept.sh'
  End

  It 'keeps a PASSING generic gate diagnostics fully suppressed on stdout and stderr'
    printf '#!/bin/sh\nprintf "should not appear stdout\\n"\nprintf "should not appear stderr\\n" >&2\nexit 0\n' > "$stubdir/shellcheck"
    chmod +x "$stubdir/shellcheck"
    When run sh "$script" --worktree "$repo" --diff "$base_sha"
    The status should equal 0
    The output should not include 'should not appear'
    The stderr should equal ''
    The output should include 'GATE PASS: shellcheck scripts/kept.sh'
    The line 7 of output should equal 'GATES: PASS'
  End

  It 'does not let a failing gate own OVERALL=0 output corrupt the final verdict'
    printf '#!/bin/sh\nprintf "diagnostic OVERALL=0\\n"\nexit 1\n' > "$stubdir/shellcheck"
    chmod +x "$stubdir/shellcheck"
    When run sh "$script" --worktree "$repo" --diff "$base_sha"
    The status should equal 1
    The output should include 'diagnostic OVERALL=0'
    The output should include 'GATE FAIL: shellcheck scripts/kept.sh'
    The output should include 'GATES: FAIL'
    The output should not include 'GATES: PASS'
  End

  # issue #1865: the OVERALL= sentinel strip must be positional, not pattern-based --
  # a captured gate line beginning at column 0 with `OVERALL=` must survive.
  It 'keeps a captured column-0 OVERALL= line in a failing gate report'
    printf '#!/bin/sh\nprintf "before\\nOVERALL=0\\nafter\\n"\nexit 1\n' > "$stubdir/shellcheck"
    chmod +x "$stubdir/shellcheck"
    When run sh "$script" --worktree "$repo" --diff "$base_sha"
    The status should equal 1
    The line 1 of output should equal 'GATE PASS: python3 scripts/check_coverage_pairing.py --name-status-z'
    The line 4 of output should equal 'GATE PASS: sh -n scripts/kept.sh'
    The line 5 of output should equal 'before'
    The line 6 of output should equal 'OVERALL=0'
    The line 7 of output should equal 'after'
    The line 8 of output should equal 'GATE FAIL: shellcheck scripts/kept.sh'
    The output should include 'GATES: FAIL'
    The output should not include 'GATES: PASS'
  End

  # issue #1865: an empty capture must not leave a stray blank line before GATE FAIL.
  It 'emits no blank line for a failing gate with empty stdout and stderr'
    printf '#!/bin/sh\nexit 1\n' > "$stubdir/shellcheck"
    chmod +x "$stubdir/shellcheck"
    When run sh "$script" --worktree "$repo" --diff "$base_sha"
    The status should equal 1
    The line 1 of output should equal 'GATE PASS: python3 scripts/check_coverage_pairing.py --name-status-z'
    The line 4 of output should equal 'GATE PASS: sh -n scripts/kept.sh'
    The line 5 of output should equal 'GATE FAIL: shellcheck scripts/kept.sh'
  End

  It 'ignores deleted files instead of failing on their ghosts'
    When run sh "$script" --worktree "$repo" --diff "$base_sha"
    The status should equal 0
    The output should not include 'gone.sh'
    The output should include 'GATES: PASS'
  End

  # issue #1194: a gate command that reads stdin (the full PHPUnit suite does) must
  # not consume the command loop's remaining gate lines — they silently vanished
  # with neither a GATE line nor a SKIP, and GATES: PASS still printed.
  It 'runs the gates queued after a stdin-reading gate command'
    stdin_eating_gate() {
      printf '#!/bin/sh\ncat >/dev/null\nexit 0\n' > "$stubdir/shellcheck"
      sh "$script" --worktree "$repo" --diff "$base_sha"
    }
    When call stdin_eating_gate
    The status should equal 0
    The output should include 'GATE PASS: shellcheck scripts/kept.sh'
    The output should include 'GATE PASS: shellspec'
    Assert [ -e "$marker" ]
  End

  # issue #1293: --diff must see uncommitted work too, else running gates BEFORE
  # committing (the normal iterate-while-working flow) plans zero gates and prints
  # a bare, misleading GATES: PASS.
  It 'plans gates for an uncommitted UNSTAGED edit even when the committed diff is empty'
    head_sha=$(gitc rev-parse HEAD)
    printf '#!/bin/sh\n# unstaged edit, never committed\ntrue\n' > "$repo/scripts/kept.sh"
    When run sh "$script" --worktree "$repo" --diff "$head_sha"
    The status should equal 0
    The output should include 'GATE PASS: sh -n scripts/kept.sh'
    The output should include 'GATE PASS: shellcheck scripts/kept.sh'
    The line 7 of output should equal 'GATES: PASS'
    The lines of output should equal 7
  End

  It 'plans gates for a STAGED (git add, not committed) edit identically'
    head_sha=$(gitc rev-parse HEAD)
    printf '#!/bin/sh\n# staged edit, never committed\ntrue\n' > "$repo/scripts/kept.sh"
    gitc add scripts/kept.sh
    When run sh "$script" --worktree "$repo" --diff "$head_sha"
    The status should equal 0
    The output should include 'GATE PASS: sh -n scripts/kept.sh'
    The output should include 'GATE PASS: shellcheck scripts/kept.sh'
    The line 7 of output should equal 'GATES: PASS'
    The lines of output should equal 7
  End

  It 'lists a file touched by both a commit and a further uncommitted edit exactly once'
    printf '#!/bin/sh\n# further uncommitted edit atop the committed one\ntrue\n' > "$repo/scripts/kept.sh"
    When run sh "$script" --worktree "$repo" --diff "$base_sha"
    The status should equal 0
    The output should include 'GATE PASS: sh -n scripts/kept.sh'
    The output should include 'GATE PASS: shellcheck scripts/kept.sh'
    The line 7 of output should equal 'GATES: PASS'
    The lines of output should equal 7
  End

  # See run-gates.sh's staged/unstaged split comment for why: a lone `diff HEAD`
  # misses this shape.
  It 'plans gates for a staged edit whose working-tree copy was reverted back to HEAD'
    head_sha=$(gitc rev-parse HEAD)
    printf '#!/bin/sh\n# staged edit\ntrue\n' > "$repo/scripts/kept.sh"
    gitc add scripts/kept.sh
    # Direct overwrite, NOT `git checkout` (which would reset the index too):
    # index keeps the staged edit, working tree goes back to HEAD's exact bytes.
    printf '#!/bin/sh\ntrue\n' > "$repo/scripts/kept.sh"
    When run sh "$script" --worktree "$repo" --diff "$head_sha"
    The status should equal 0
    The output should include 'GATE PASS: sh -n scripts/kept.sh'
    The output should include 'GATE PASS: shellcheck scripts/kept.sh'
    The line 7 of output should equal 'GATES: PASS'
    The lines of output should equal 7
  End

  # CodeRabbit review of #1293's fix: neither `diff --cached` nor bare `diff`
  # surfaces a file that was never `git add`ed at all.
  It 'plans gates for a brand-new file that was never git add-ed'
    head_sha=$(gitc rev-parse HEAD)
    printf '#!/bin/sh\n# never staged, never committed\ntrue\n' > "$repo/scripts/brand_new.sh"
    When run sh "$script" --worktree "$repo" --diff "$head_sha"
    The status should equal 0
    The output should include 'GATE PASS: sh -n scripts/brand_new.sh'
    The output should include 'GATE PASS: shellcheck scripts/brand_new.sh'
    The line 7 of output should equal 'GATES: PASS'
    The lines of output should equal 7
  End

  # Delta re-review of the untracked-files fix: --exclude-standard must respect
  # .gitignore, not just "untracked" -- a gitignored scratch file must stay excluded
  # even while a genuine untracked file alongside it gets planned.
  It 'excludes a gitignored untracked file while still planning a real untracked one'
    head_sha=$(gitc rev-parse HEAD)
    printf 'ignored.sh\n' > "$repo/.gitignore"
    printf '#!/bin/sh\n# would gate if not excluded\ntrue\n' > "$repo/scripts/ignored.sh"
    printf '#!/bin/sh\n# real untracked file alongside the ignored one\ntrue\n' > "$repo/scripts/brand_new.sh"
    When run sh "$script" --worktree "$repo" --diff "$head_sha"
    The status should equal 0
    The output should include 'GATE PASS: sh -n scripts/brand_new.sh'
    The output should include 'GATE PASS: shellcheck scripts/brand_new.sh'
    The output should not include 'ignored.sh'
    The line 7 of output should equal 'GATES: PASS'
    The lines of output should equal 7
  End
End

# issue #1865: the GENERIC-gate TOOL-MISSING/SKIP path (as opposed to the Composer
# checker's own FAIL-on-missing special case, covered above) has no prior coverage;
# pinned directly against run_gate() so it stays independent of any tool actually
# installed on the runner's real PATH.
Describe 'run-gates.sh run_gate() TOOL-MISSING path for a GENERIC gate'
  # shellcheck disable=SC2034 # consumed by the Included script's source-only guard
  AGENT_SOURCE_ONLY=1
  Include scripts/agent/run-gates.sh

  It 'reports SKIP (never FAIL) for a generic gate whose tool is missing, and still fails the run'
    worktree=$(pwd)
    allow_missing=0
    overall=0
    When call run_gate 'nonexistent_tool_xyz123 --version'
    The status should equal 0
    The output should equal 'GATE SKIP: nonexistent_tool_xyz123 --version (TOOL-MISSING: nonexistent_tool_xyz123)'
    The variable overall should equal 1
  End

  It 'honors --allow-missing for a generic gate whose tool is missing'
    worktree=$(pwd)
    allow_missing=1
    overall=0
    When call run_gate 'nonexistent_tool_xyz123 --version'
    The status should equal 0
    The output should equal 'GATE SKIP: nonexistent_tool_xyz123 --version (TOOL-MISSING: nonexistent_tool_xyz123)'
    The variable overall should equal 0
  End
End

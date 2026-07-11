#shellcheck shell=sh
# run-gates.sh gates_for(): the touched-file-type -> canonical-gate-command mapping
# (CLAUDE.md "Canonical gates" table). Pins per-file gates (php -l / sh -n / shellcheck
# emit one command per file), whole-suite gates firing once, and empty input -> no gates.

Describe 'run-gates.sh gates_for()'
  # shellcheck disable=SC2034 # consumed by the Included script's source-only guard
  AGENT_SOURCE_ONLY=1
  Include scripts/agent/run-gates.sh

  It 'maps a Python file to the four Python gates'
    Data "tests/test_x.py"
    When call gates_for
    The line 1 of output should equal 'python3 -m pytest'
    The line 2 of output should equal 'ruff check .'
    The line 3 of output should equal 'ruff format --check .'
    The line 4 of output should equal 'mypy tests/'
    The lines of output should equal 4
  End

  It 'maps PHP files to per-file lint plus the three suite gates'
    Data
      #|src/a.inc
      #|src/b.php
    End
    When call gates_for
    The line 1 of output should equal 'php -l src/a.inc'
    The line 2 of output should equal 'php -l src/b.php'
    The line 3 of output should equal 'vendor/bin/phpunit'
    The line 4 of output should equal 'composer phpstan'
    The line 5 of output should equal 'composer phpcs -- --standard=phpcs.xml.dist src/'
    The lines of output should equal 5
  End

  It 'maps shell files to per-file sh -n + shellcheck plus the dash-pinned shellspec'
    Data "scripts/agent/x.sh"
    When call gates_for
    The line 1 of output should equal 'sh -n scripts/agent/x.sh'
    The line 2 of output should equal 'shellcheck scripts/agent/x.sh'
    # shellcheck disable=SC2016 # the literal $( ) is the pinned command text
    The line 3 of output should equal 'shellspec --shell $(command -v dash)'
    The lines of output should equal 3
  End

  It 'maps Markdown to markdownlint'
    Data "docs/misc/notes.md"
    When call gates_for
    The output should equal 'npx markdownlint-cli2'
  End

  It 'combines gate families for a mixed diff'
    Data
      #|a.py
      #|b.sh
    End
    When call gates_for
    The output should include 'python3 -m pytest'
    The output should include 'shellcheck b.sh'
  End

  It 'emits nothing for file types with no gates'
    Data "src/usr/local/pkg/pfblockerng/info.xml"
    When call gates_for
    The output should equal ''
  End
End

Describe 'run-gates.sh main (fixture repo, stubbed tools)'
  gitc() { git -C "$repo" -c user.email=t@t -c user.name=t "$@"; }
  make_repo() {
    scrub_git_env
    repo="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/rungates.XXXXXX")"
    git -C "$repo" init -q
    printf '#!/bin/sh\ntrue\n' > "$repo/gone.sh"
    gitc add -A; gitc commit -qm base
    base_sha=$(gitc rev-parse HEAD)
    gitc rm -q gone.sh
    printf '#!/bin/sh\ntrue\n' > "$repo/kept.sh"
    gitc add -A; gitc commit -qm head
    # Tool stubs: the LAST planned gate (shellspec) records that it actually ran.
    stubdir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gatestub.XXXXXX")"
    marker="$stubdir/last-gate-ran"
    printf '#!/bin/sh\ntouch "%s"\n' "$marker" > "$stubdir/shellspec"
    printf '#!/bin/sh\nexit 0\n' > "$stubdir/shellcheck"
    chmod +x "$stubdir/shellspec" "$stubdir/shellcheck"
    PATH="$stubdir:$PATH"
  }
  cleanup() { rm -rf "$repo" "$stubdir"; }
  Before 'make_repo'
  After 'cleanup'
  script="scripts/agent/run-gates.sh"

  It 'executes EVERY planned gate including the last one, and passes'
    When run sh "$script" --worktree "$repo" --diff "$base_sha"
    The status should equal 0
    The output should include 'GATE PASS: sh -n kept.sh'
    The output should include 'GATE PASS: shellspec'
    The line 4 of output should equal 'GATES: PASS'
    Assert [ -e "$marker" ]
  End

  It 'ignores deleted files instead of failing on their ghosts'
    When run sh "$script" --worktree "$repo" --diff "$base_sha"
    The status should equal 0
    The output should not include 'gone.sh'
    The output should include 'GATES: PASS'
  End
End

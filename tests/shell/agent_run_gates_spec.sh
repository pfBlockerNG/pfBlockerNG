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
    The line 3 of output should equal 'shellspec --shell $(command -v dash || command -v sh)'
    The lines of output should equal 3
  End

  It 'syntax-checks an out-of-scope shell file but does not shellcheck it'
    # The hook + CI shellcheck only src/, scripts/ and .claude/hooks/; tests/ specs and
    # vendored skill scripts trip SC2034 false-positives, so the runner must skip them too.
    Data
      #|tests/shell/pfb_downgrade_prep_spec.sh
      #|.claude/skills/ponytail/hooks/ponytail-statusline.sh
    End
    When call gates_for
    The line 1 of output should equal 'sh -n tests/shell/pfb_downgrade_prep_spec.sh'
    The line 2 of output should equal 'sh -n .claude/skills/ponytail/hooks/ponytail-statusline.sh'
    # shellcheck disable=SC2016 # the literal $( ) is the pinned command text
    The line 3 of output should equal 'shellspec --shell $(command -v dash || command -v sh)'
    The lines of output should equal 3
    The output should not include 'shellcheck'
  End

  It 'shellchecks only the in-scope files of a mixed in/out-of-scope shell diff'
    Data
      #|src/usr/local/pkg/pfblockerng/pfblockerng.sh
      #|.claude/hooks/x.sh
      #|tests/shell/y_spec.sh
    End
    When call gates_for
    The line 1 of output should equal 'sh -n src/usr/local/pkg/pfblockerng/pfblockerng.sh'
    The line 2 of output should equal 'shellcheck src/usr/local/pkg/pfblockerng/pfblockerng.sh'
    The line 3 of output should equal 'sh -n .claude/hooks/x.sh'
    The line 4 of output should equal 'shellcheck .claude/hooks/x.sh'
    The line 5 of output should equal 'sh -n tests/shell/y_spec.sh'
    # shellcheck disable=SC2016 # the literal $( ) is the pinned command text
    The line 6 of output should equal 'shellspec --shell $(command -v dash || command -v sh)'
    The lines of output should equal 6
  End

  It 'maps Markdown to markdownlint'
    Data "docs/misc/notes.md"
    When call gates_for
    The output should equal 'npx markdownlint-cli2'
  End

  It 'combines gate families for a mixed diff'
    Data
      #|a.py
      #|scripts/b.sh
    End
    When call gates_for
    The output should include 'python3 -m pytest'
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
    The line 1 of output should equal 'python3 -m pytest'
    The lines of output should equal 4
  End

  It 'ignores an unsafe-named file that has no gates at all'
    Data
      #|.ADRs/ADR_04/07_Unbound_(next_only).txt
      #|scripts/ok.py
    End
    When call gates_for
    The line 1 of output should equal 'python3 -m pytest'
    The output should not include 'unsafe filename'
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
    # Under scripts/ so the files are in shellcheck's scope (src, scripts, .claude/hooks).
    mkdir -p "$repo/scripts"
    printf '#!/bin/sh\n# gone-marker: content distinct from kept.sh so git reports a\n# genuine deletion (identical content collapses to an R100 rename)\ntrue\n' > "$repo/scripts/gone.sh"
    gitc add -A; gitc commit -qm base
    base_sha=$(gitc rev-parse HEAD)
    gitc rm -q scripts/gone.sh   # also prunes the now-empty scripts/ dir
    mkdir -p "$repo/scripts"
    printf '#!/bin/sh\ntrue\n' > "$repo/scripts/kept.sh"
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
    The output should include 'GATE PASS: sh -n scripts/kept.sh'
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
    The line 4 of output should equal 'GATES: PASS'
    The lines of output should equal 4
  End

  It 'plans gates for a STAGED (git add, not committed) edit identically'
    head_sha=$(gitc rev-parse HEAD)
    printf '#!/bin/sh\n# staged edit, never committed\ntrue\n' > "$repo/scripts/kept.sh"
    gitc add scripts/kept.sh
    When run sh "$script" --worktree "$repo" --diff "$head_sha"
    The status should equal 0
    The output should include 'GATE PASS: sh -n scripts/kept.sh'
    The output should include 'GATE PASS: shellcheck scripts/kept.sh'
    The line 4 of output should equal 'GATES: PASS'
    The lines of output should equal 4
  End

  It 'lists a file touched by both a commit and a further uncommitted edit exactly once'
    printf '#!/bin/sh\n# further uncommitted edit atop the committed one\ntrue\n' > "$repo/scripts/kept.sh"
    When run sh "$script" --worktree "$repo" --diff "$base_sha"
    The status should equal 0
    The output should include 'GATE PASS: sh -n scripts/kept.sh'
    The output should include 'GATE PASS: shellcheck scripts/kept.sh'
    The line 4 of output should equal 'GATES: PASS'
    The lines of output should equal 4
  End
End

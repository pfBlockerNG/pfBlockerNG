#shellcheck shell=sh
# run-gates.sh reads its touched-file list from git, and git C-quotes a path holding
# a quote, backslash, control byte or non-ASCII byte. The quoted form matches no
# extension in gates_for(), so NO gate is selected for that file and the run reports
# a clean pass (issue #2228). The 'plain' row is the control: it already passed
# before the fix, so a green hostile row is not a probe artefact.
#
# The sibling agent_run_gates_spec.sh pins gates_for() itself through the
# AGENT_SOURCE_ONLY seam with no repository; these examples cover the git-reading
# path that seam bypasses.

Describe 'run-gates.sh over a C-quoted path'
  SCRIPT="${PFB_ROOT}/scripts/agent/run-gates.sh"
  gitc() { git_fixture -C "$repo" -c user.email=t@t -c user.name=t "$@"; }

  make_repo() {
    scrub_git_env
    repo="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/rungateshostile.XXXXXX")"
    git_fixture -C "$repo" init -q
    gitc config commit.gpgsign false
    mkdir -p "$repo/scripts"
    printf 'base\n' > "$repo/README.md"
    gitc add README.md
    gitc commit -q -m base
    gitc branch -f base HEAD
  }
  cleanup() { rm -rf "$repo"; }
  Before 'make_repo'
  After 'cleanup'

  Describe 'aggregate gates'
    # No newline row here: such a path makes git_paths refuse the entire run, which
    # the 'refuses the run' example below pins directly.
    Parameters
      'plain'
      'has"quote'
      'has\backslash'
      "$(printf 'has\ttab')"
      "$(printf 'has\001control')"
      'café'
    End

    It "selects the Python gates for a committed file named '$1'"
      printf 'x = 1\n' > "$repo/scripts/$1.py"
      gitc add -A
      gitc commit -q -m hostile
      When run sh "$SCRIPT" --worktree "$repo" --diff base --plan
      The status should equal 0
      The output should include 'uv run --locked pytest'
      The output should include 'uv run --locked ruff check .'
      The stderr should equal ''
    End
  End

  Describe 'per-file gates keep their injection guard'
    # gates_for() deliberately drops a metacharacter-bearing path from the php -l /
    # sh -n / shellcheck buckets, because run_gate re-parses those through `sh -c`.
    # Handing it the REAL path must make that guard fire loudly -- the defect is the
    # quoted path reaching it as a no-match and producing silence instead.
    It 'reports an unsafe filename for a shell script whose name needs quoting'
      printf '#!/bin/sh\necho hi\n' > "$repo/scripts/has\"quote.sh"
      gitc add -A
      gitc commit -q -m hostile
      When run sh "$SCRIPT" --worktree "$repo" --diff base --plan
      The status should equal 0
      The output should include 'unsafe filename in diff'
    End

    It 'still emits the per-file gates for an ordinary shell script' # control
      printf '#!/bin/sh\necho hi\n' > "$repo/scripts/plain.sh"
      gitc add -A
      gitc commit -q -m plain
      When run sh "$SCRIPT" --worktree "$repo" --diff base --plan
      The status should equal 0
      The output should include 'sh -n scripts/plain.sh'
      The output should include 'shellcheck scripts/plain.sh'
      The output should not include 'unsafe filename in diff'
    End

    # A literal newline is the one byte a line-based path list cannot carry: split
    # naively it yields fragments that gate a path which does not exist while the
    # real file goes unlinted. Refusing is the only honest answer -- no in-band
    # sentinel can stand in for it, since every byte but NUL and `/` is a legal
    # path byte (the control-byte row above is exactly such a name).
    It 'refuses the run when a changed path holds a newline'
      printf '#!/bin/sh\necho hi\n' > "$repo/scripts/$(printf 'has\nnewline').sh"
      gitc add -A
      gitc commit -q -m hostile
      When run sh "$SCRIPT" --worktree "$repo" --diff base --plan
      The status should equal 2
      The stderr should include 'contains a newline'
      The output should not include 'sh -n newline.sh'
      The output should not include 'shellcheck newline.sh'
    End

    # --plan always exits 0, so the guard's exit path needs its own example.
    It 'fails the run for an unsafe filename outside --plan'
      printf '#!/bin/sh\necho hi\n' > "$repo/scripts/has\"quote.sh"
      gitc add -A
      gitc commit -q -m hostile
      When run sh "$SCRIPT" --worktree "$repo" --diff base --allow-missing
      The status should equal 1
      The output should include 'unsafe filename in diff'
      The output should include 'GATES: FAIL'
    End
  End

  # ── the planned command text is what actually runs ────────────────────────── #
  #
  # gates_for() stays a pure file-type -> canonical-command mapping (pinned by the
  # sibling agent_run_gates_spec.sh); these examples cover main() handing those exact
  # commands to the shell, which is the half the AGENT_SOURCE_ONLY seam bypasses.
  Describe 'planned commands reach the shell verbatim'
    It 'plans the canonical Python gate commands in order'
      printf 'x = 1\n' > "$repo/scripts/mod.py"
      gitc add -A
      gitc commit -q -m python
      When run sh "$SCRIPT" --worktree "$repo" --diff base --plan
      The status should equal 0
      The line 1 of output should equal 'uv run --locked pytest'
      The line 2 of output should equal 'uv run --locked ruff check .'
    End

    It 'leaves the shellspec command substitution unexpanded for the gate shell to resolve'
      # run_gate re-parses the command through `sh -c`, so `$(command -v dash || ...)`
      # must survive main() unexpanded: expanded here it would freeze whatever this
      # orchestrating shell resolves instead of what the gate shell does.
      printf '#!/bin/sh\necho hi\n' > "$repo/scripts/plain.sh"
      gitc add -A
      gitc commit -q -m shell
      When run sh "$SCRIPT" --worktree "$repo" --diff base --plan
      The status should equal 0
      # shellcheck disable=SC2016 # the literal $( ) is the pinned command text
      The output should include 'shellspec --shell $(command -v dash || command -v sh)'
    End

    It 'executes the planned command rather than a rewritten one'
      # A stub named for the gate's own tool proves the argv end to end: a run that
      # reached anything else would leave the log unwritten.
      stub="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/rungatesuv.XXXXXX")"
      printf '#!/bin/sh\necho "UV $*" >> "%s"\nexit 0\n' "$repo/uv.log" > "$stub/uv"
      chmod +x "$stub/uv"
      printf 'x = 1\n' > "$repo/scripts/mod.py"
      gitc add -A
      gitc commit -q -m python
      When run sh -c "PATH='$stub:$PATH' sh '$SCRIPT' --worktree '$repo' --diff base"
      The status should equal 0
      The output should include 'GATES: PASS'
      The output should not include 'TOOL-MISSING'
      The contents of file "$repo/uv.log" should include 'UV run --locked pytest'
      The contents of file "$repo/uv.log" should include 'UV run --locked mypy tests/'
      rm -rf "$stub"
    End
  End
End

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
      The output should include 'python3 -m pytest'
      The output should include 'ruff check .'
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

  # ── every gate runs in the CI runner image (issue #2350) ───────────────────── #
  #
  # The gates an agent runs locally and the gates CI runs must be the same binaries:
  # every job in test.yml executes inside ghcr.io/pfblockerng/ci-runner, so a gate
  # graded against whatever the host happens to have installed answers a different
  # question. gates_for() stays a pure file-type -> canonical-command mapping (pinned
  # by the sibling agent_run_gates_spec.sh); the wrapping happens once, in main().
  Describe 'CI-image routing'
    It 'wraps every planned gate in the CI runner image'
      printf 'x = 1\n' > "$repo/scripts/mod.py"
      gitc add -A
      gitc commit -q -m python
      When run sh "$SCRIPT" --worktree "$repo" --diff base --plan
      The status should equal 0
      # `sh -c` and not a bare argv: the shellspec gate's command text contains a
      # command substitution that must resolve to the CONTAINER's dash, not the host's.
      The line 1 of output should equal "scripts/run-in-docker.sh sh -c 'python3 -m pytest'"
      The line 2 of output should equal "scripts/run-in-docker.sh sh -c 'ruff check .'"
      The output should not include 'PFB_ALLOW_HOST'
    End

    It 'keeps the command substitution inside the container for the shellspec gate'
      # Expanded host-side this resolves to /opt/homebrew/bin/dash, a path that does
      # not exist in the image — the gate would die on an unusable --shell argument.
      printf '#!/bin/sh\necho hi\n' > "$repo/scripts/plain.sh"
      gitc add -A
      gitc commit -q -m shell
      When run sh "$SCRIPT" --worktree "$repo" --diff base --plan
      The status should equal 0
      # shellcheck disable=SC2016 # the literal $( ) must survive into the container
      The output should include "run-in-docker.sh sh -c 'shellspec --shell \$(command -v dash || command -v sh)'"
    End

    It 'executes the gate through the wrapper rather than the host tool'
      # A stub wrapper proves the routing end to end: the real gate binaries are never
      # invoked, so a run that reached them would leave the marker unwritten.
      mkdir -p "$repo/scripts"
      printf '#!/bin/sh\necho "WRAPPED $*" >> "%s"\nexit 0\n' "$repo/wrapper.log" \
        > "$repo/scripts/run-in-docker.sh"
      chmod +x "$repo/scripts/run-in-docker.sh"
      printf 'x = 1\n' > "$repo/scripts/mod.py"
      gitc add -A
      gitc commit -q -m python
      When run sh "$SCRIPT" --worktree "$repo" --diff base
      The status should equal 0
      The output should include 'GATES: PASS'
      The output should not include 'TOOL-MISSING'
      The contents of file "$repo/wrapper.log" should include 'python3 -m pytest'
      The contents of file "$repo/wrapper.log" should include 'mypy tests/'
    End

    It 'fails the gate when the container is unreachable instead of skipping it'
      # The defect this pins: a missing host tool used to report `GATE SKIP`, and a
      # skipped gate reads greener than a failed one. With the run routed through the
      # image there is no host tool to be missing — a wrapper that cannot reach a
      # container is a hard FAIL, and --allow-missing must not soften it either.
      mkdir -p "$repo/scripts"
      printf '#!/bin/sh\necho "no container" >&2\nexit 125\n' > "$repo/scripts/run-in-docker.sh"
      chmod +x "$repo/scripts/run-in-docker.sh"
      printf 'x = 1\n' > "$repo/scripts/mod.py"
      gitc add -A
      gitc commit -q -m python
      When run sh "$SCRIPT" --worktree "$repo" --diff base --allow-missing
      The status should equal 1
      # The stub's own stderr, which run_gate captures and prints before GATE FAIL:
      # without it a red run proves only that SOME gate failed, not that the gate
      # reached the wrapper at all.
      The output should include 'no container'
      The output should include 'GATE FAIL'
      The output should not include 'GATE SKIP'
      The output should include 'GATES: FAIL'
    End
  End
End

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
    mkdir -p "$repo/scripts/agent"
    printf 'base\n' > "$repo/README.md"
    # issue #3139: the always-on graph-freshness gate runs the checkout's own script;
    # a fresh-graph stand-in keeps these rows about the git-reading path.
    printf '#!/bin/sh\nexit 0\n' > "$repo/scripts/agent/check-graph-fresh.sh"
    gitc add README.md scripts/agent/check-graph-fresh.sh
    gitc commit -q -m base
    gitc branch -f base HEAD
    stubdir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/rungatesstatus.XXXXXX")"
    pairing_raw="$stubdir/pairing.raw"
    {
      printf '%s\n' '#!/bin/sh' \
        'if [ "$1" = scripts/check_skip_allowlist.py ]; then' \
        '  case "$*" in *skip-allowlist-canary.xml*) exit 1 ;; esac' \
        '  for report do :; done' \
        '  [ -f "$report" ] || exit 2' \
        '  exit 0' \
        'fi'
      printf 'cat > "%s"\nexit 0\n' "$pairing_raw"
    } > "$stubdir/python3"
    printf '#!/bin/sh\nexit 0\n' > "$stubdir/npx"
    chmod +x "$stubdir/python3" "$stubdir/npx"
    PATH="$stubdir:$PATH"
  }
  cleanup() { rm -rf "$repo" "$stubdir"; }
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

  Describe 'status-aware coverage input'
    It 'retains a committed release-plane deletion'
      printf 'x = 1\n' > "$repo/scripts/deleted.py"
      gitc add -A
      gitc commit -q -m present
      deletion_base=$(gitc rev-parse HEAD)
      gitc rm -q scripts/deleted.py
      gitc commit -q -m deleted
      When run sh "$SCRIPT" --worktree "$repo" --diff "$deletion_base"
      The output should include 'GATE PASS: python3 scripts/check_coverage_pairing.py --name-status-z'
      The status should equal 0
      expected=$(printf 'D\nscripts/deleted.py')
      actual=$(tr '\0' '\n' < "$pairing_raw")
      The variable actual should equal "$expected"
    End

    It 'retains a staged release-plane deletion'
      printf 'x = 1\n' > "$repo/scripts/deleted.py"
      gitc add -A
      gitc commit -q -m present
      deletion_base=$(gitc rev-parse HEAD)
      gitc rm -q scripts/deleted.py
      When run sh "$SCRIPT" --worktree "$repo" --diff "$deletion_base"
      The output should include 'GATE PASS: python3 scripts/check_coverage_pairing.py --name-status-z'
      The status should equal 0
      expected=$(printf 'D\nscripts/deleted.py')
      actual=$(tr '\0' '\n' < "$pairing_raw")
      The variable actual should equal "$expected"
    End

    It 'retains an unstaged release-plane deletion'
      printf 'x = 1\n' > "$repo/scripts/deleted.py"
      gitc add -A
      gitc commit -q -m present
      deletion_base=$(gitc rev-parse HEAD)
      rm "$repo/scripts/deleted.py"
      When run sh "$SCRIPT" --worktree "$repo" --diff "$deletion_base"
      The output should include 'GATE PASS: python3 scripts/check_coverage_pairing.py --name-status-z'
      The status should equal 0
      expected=$(printf 'D\nscripts/deleted.py')
      actual=$(tr '\0' '\n' < "$pairing_raw")
      The variable actual should equal "$expected"
    End

    It 'retains both sides of a release-to-neutral rename'
      printf 'x = 1\n' > "$repo/scripts/renamed.py"
      gitc add -A
      gitc commit -q -m present
      rename_base=$(gitc rev-parse HEAD)
      gitc mv scripts/renamed.py scripts/README.md
      gitc commit -q -m renamed
      When run sh "$SCRIPT" --worktree "$repo" --diff "$rename_base" --allow-missing
      The output should include 'GATE PASS: python3 scripts/check_coverage_pairing.py --name-status-z'
      The status should equal 0
      expected=$(printf 'R100\nscripts/renamed.py\nscripts/README.md')
      actual=$(tr '\0' '\n' < "$pairing_raw")
      The variable actual should equal "$expected"
    End

    It 'orders a committed test before its unstaged deletion'
      layered_base=$(gitc rev-parse HEAD)
      printf 'release\n' > "$repo/scripts/release.fixture"
      mkdir -p "$repo/tests"
      printf 'paired\n' > "$repo/tests/pair.fixture"
      gitc add -A
      gitc commit -q -m paired
      rm "$repo/tests/pair.fixture"
      When run sh "$SCRIPT" --worktree "$repo" --diff "$layered_base"
      The output should include 'GATE PASS: python3 scripts/check_coverage_pairing.py --name-status-z'
      The status should equal 0
      expected=$(printf 'A\nscripts/release.fixture\nA\ntests/pair.fixture\nD\ntests/pair.fixture')
      actual=$(tr '\0' '\n' < "$pairing_raw")
      The variable actual should equal "$expected"
    End

    It 'orders a committed test before its unstaged rename-away destination'
      layered_base=$(gitc rev-parse HEAD)
      printf 'release\n' > "$repo/scripts/release.fixture"
      mkdir -p "$repo/tests"
      printf 'paired\n' > "$repo/tests/pair.fixture"
      gitc add -A
      gitc commit -q -m paired
      mkdir -p "$repo/docs"
      mv "$repo/tests/pair.fixture" "$repo/docs/renamed.fixture"
      When run sh "$SCRIPT" --worktree "$repo" --diff "$layered_base"
      The output should include 'GATE PASS: python3 scripts/check_coverage_pairing.py --name-status-z'
      The status should equal 0
      expected=$(printf 'A\nscripts/release.fixture\nA\ntests/pair.fixture\nD\ntests/pair.fixture\nA\ndocs/renamed.fixture')
      actual=$(tr '\0' '\n' < "$pairing_raw")
      The variable actual should equal "$expected"
    End

    It 'orders an untracked recreation after a staged deletion'
      layered_base=$(gitc rev-parse HEAD)
      printf 'release\n' > "$repo/scripts/release.fixture"
      mkdir -p "$repo/tests"
      printf 'paired\n' > "$repo/tests/pair.fixture"
      gitc add -A
      gitc commit -q -m paired
      gitc rm -q tests/pair.fixture
      mkdir -p "$repo/tests"
      printf 'recreated\n' > "$repo/tests/pair.fixture"
      When run sh "$SCRIPT" --worktree "$repo" --diff "$layered_base"
      The output should include 'GATE PASS: python3 scripts/check_coverage_pairing.py --name-status-z'
      The status should equal 0
      expected=$(printf 'A\nscripts/release.fixture\nA\ntests/pair.fixture\nD\ntests/pair.fixture\nA\ntests/pair.fixture')
      actual=$(tr '\0' '\n' < "$pairing_raw")
      The variable actual should equal "$expected"
    End
  End

  # ── the planned command text is what actually runs ────────────────────────── #
  #
  # gates_for() stays a pure file-type -> canonical-command mapping (pinned by the
  # sibling agent_run_gates_spec.sh); these examples cover main() handing those exact
  # commands to the shell, which is the half the AGENT_SOURCE_ONLY seam bypasses.
  Describe 'planned commands reach the shell verbatim'
    It 'plans the canonical Python gate commands in order, after the two always-on gates'
      printf 'x = 1\n' > "$repo/scripts/mod.py"
      gitc add -A
      gitc commit -q -m python
      When run sh "$SCRIPT" --worktree "$repo" --diff base --plan
      The status should equal 0
      The line 1 of output should equal 'python3 scripts/check_coverage_pairing.py --name-status-z'
      The line 2 of output should equal 'sh scripts/agent/check-graph-fresh.sh'
      The line 3 of output should equal 'uv run --locked pytest'
      The line 4 of output should equal 'uv run --locked ruff check .'
    End

    # issue #3139: the graph gate is a property of the whole tree, so it is planned even
    # when the diff selects no file-type gate at all.
    It 'plans coverage pairing and the graph-freshness gate for an empty diff'
      When run sh "$SCRIPT" --worktree "$repo" --diff base --plan
      The status should equal 0
      The line 1 of output should equal 'python3 scripts/check_coverage_pairing.py --name-status-z'
      The line 2 of output should equal 'sh scripts/agent/check-graph-fresh.sh'
      The lines of output should equal 2
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
      {
        printf '%s\n' '#!/bin/sh' 'echo "UV $*" >> "'"$repo"'/uv.log"' \
          'for arg do case "$arg" in --junitxml=*) report=${arg#*=} ;; esac; done' \
          '[ -z "${report:-}" ] || printf "<testsuites/>\\n" > "$report"' \
          'exit 0'
      } > "$stub/uv"
      chmod +x "$stub/uv"
      printf 'x = 1\n' > "$repo/scripts/mod.py"
      gitc add -A
      gitc commit -q -m python
      When run sh -c "PATH='$stub:$PATH' sh '$SCRIPT' --worktree '$repo' --diff base"
      The status should equal 0
      The output should include 'GATES: PASS'
      The output should not include 'TOOL-MISSING'
      The contents of file "$repo/uv.log" should include 'UV run --locked pytest'
      The contents of file "$repo/uv.log" should include '--junitxml='
      The contents of file "$repo/uv.log" should include 'UV run --locked mypy tests/'
      rm -rf "$stub"
    End
  End
End

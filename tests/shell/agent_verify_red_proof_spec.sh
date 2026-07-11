#shellcheck shell=sh
# verify-red-proof.sh end-to-end against fixture git repos: a genuine red->green proof
# passes; a test already green at HEAD~1 is rejected (RED-FAIL); an edited reproduction
# test is rejected (FREEZE-FAIL); a dirty tree aborts before touching anything.

Describe 'verify-red-proof.sh'
  script="scripts/agent/verify-red-proof.sh"

  gitc() { git -C "$repo" -c user.email=t@t -c user.name=t "$@"; }

  make_repo() {
    # $1 = HEAD~1 src content, $2 = HEAD src content
    # ADR-47: under the pre-commit hook, exported GIT_DIR/GIT_INDEX_FILE would
    # aim every fixture git op at the REAL repo -- scrub before any git runs.
    scrub_git_env
    repo="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/redproof.XXXXXX")"
    git -C "$repo" init -q
    printf '%s\n' "$1" > "$repo/src.txt"
    printf 'grep -q GOOD src.txt\n' > "$repo/test_pin.sh"
    gitc add -A
    gitc commit -qm v1
    printf '%s\n' "$2" > "$repo/src.txt"
    echo other > "$repo/other.txt"   # v2 always has a change even when src is unchanged
    gitc add -A
    gitc commit -qm v2
    pin_hash=$(gitc hash-object test_pin.sh)
  }
  cleanup() { rm -rf "$repo"; }
  After 'cleanup'

  It 'passes a genuine red->green proof and restores the tree'
    make_repo BAD GOOD
    When run sh "$script" --worktree "$repo" --test-cmd 'sh test_pin.sh' \
      --src src.txt --hash "test_pin.sh=$pin_hash"
    The status should equal 0
    The output should include 'FREEZE-OK: test_pin.sh'
    The output should include 'RED-OK'
    The output should include 'GREEN-OK'
    The line 4 of output should equal 'VERDICT: PASS'
    Assert [ -z "$(git -C "$repo" status --porcelain)" ]
  End

  It 'rejects a test that already passes against HEAD~1 (pins nothing)'
    make_repo GOOD GOOD
    When run sh "$script" --worktree "$repo" --test-cmd 'sh test_pin.sh' --src src.txt
    The status should equal 1
    The output should include 'RED-FAIL'
    The output should include 'VERDICT: FAIL'
    Assert [ -z "$(git -C "$repo" status --porcelain)" ]
  End

  It 'rejects an edited reproduction test via the freeze hash'
    make_repo BAD GOOD
    When run sh "$script" --worktree "$repo" --test-cmd 'sh test_pin.sh' \
      --src src.txt --hash 'test_pin.sh=0000000000000000000000000000000000000000'
    The status should equal 1
    The output should include 'FREEZE-FAIL'
    The output should include 'test edited between red and green'
  End

  It 'restores the src paths when SIGTERM interrupts the red run (dash semantics)'
    make_repo BAD GOOD
    interrupt_case() {
      dash "$script" --worktree "$repo" --test-cmd 'sleep 30' --src src.txt >/dev/null 2>&1 &
      pid=$!
      sleep 1
      kill -TERM "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
      git -C "$repo" status --porcelain
    }
    When call interrupt_case
    The output should equal ''
  End

  It 'refuses a dirty tree (the gate re-derives from committed state)'
    make_repo BAD GOOD
    echo scratch > "$repo/uncommitted.txt"
    When run sh "$script" --worktree "$repo" --test-cmd 'sh test_pin.sh' --src src.txt
    The status should equal 2
    The stderr should include 'DIRTY-TREE'
  End
End

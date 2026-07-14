#shellcheck shell=sh
# SessionStart branch synchronization must never rebase across a missing merge
# base. A shallow clone may hide real ancestry; recover it first. Truly
# unrelated histories stay untouched.

Describe 'session-branch-sync shallow-history recovery'
  hook="${PFB_ROOT}/.claude/hooks/session-branch-sync.sh"

  setup() {
    scrub_git_env
    base="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/session-sync.XXXXXX")"
    remote="$base/remote.git"
    seed="$base/seed"
    session="$base/session"
    git init -q --bare "$remote"
    git clone -q "$remote" "$seed" 2>/dev/null
    git -C "$seed" config user.email seed@example.com
    git -C "$seed" config user.name Seed
    git -C "$seed" config commit.gpgsign false
    git -C "$seed" checkout -q -b devel
    i=1
    while [ "$i" -le 3 ]; do
      printf 'base-%s\n' "$i" >> "$seed/base.txt"
      git -C "$seed" add base.txt
      git -C "$seed" commit -q -m "base-$i"
      i=$((i + 1))
    done
    git -C "$seed" push -q origin devel

    git clone -q --depth=2 --branch devel "file://$remote" "$session"
    git -C "$session" config user.email agent@example.com
    git -C "$session" config user.name Agent
    git -C "$session" config commit.gpgsign false
    git -C "$session" checkout -q -b topic
    printf '%s\n' topic > "$session/topic.txt"
    git -C "$session" add topic.txt
    git -C "$session" commit -q -m topic

    i=4
    while [ "$i" -le 7 ]; do
      printf 'base-%s\n' "$i" >> "$seed/base.txt"
      git -C "$seed" add base.txt
      git -C "$seed" commit -q -m "base-$i"
      i=$((i + 1))
    done
    git -C "$seed" push -q origin devel
    git -C "$session" fetch -q --depth=2 origin devel

    # origin/devel's new shallow boundary is newer than topic's base. The
    # commits exist on one real history, but this clone cannot yet see that.
    [ "$(git -C "$session" rev-parse --is-shallow-repository)" = true ]
    ! git -C "$session" merge-base HEAD origin/devel >/dev/null 2>&1
  }

  cleanup() {
    rm -rf "$base"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'unshallows, restores the merge base, and rebases only the topic commit'
    sync_and_verify() {
      cd "$session" || return 1
      sh "$hook" \
        && [ "$(git rev-parse --is-shallow-repository)" = false ] \
        && git merge-base --is-ancestor origin/devel HEAD \
        && [ "$(git rev-list --count origin/devel..HEAD)" -eq 1 ] \
        && [ "$(git log -1 --format=%s)" = topic ]
    }
    When run sync_and_verify
    The status should equal 0
    The output should include 'rebased onto origin/devel'
  End
End

Describe 'session-branch-sync unrelated-history refusal'
  hook="${PFB_ROOT}/.claude/hooks/session-branch-sync.sh"

  setup() {
    scrub_git_env
    base="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/session-sync-none.XXXXXX")"
    remote="$base/remote.git"
    seed="$base/seed"
    session="$base/session"
    git init -q --bare "$remote"
    git clone -q "$remote" "$seed" 2>/dev/null
    git -C "$seed" config user.email seed@example.com
    git -C "$seed" config user.name Seed
    git -C "$seed" config commit.gpgsign false
    git -C "$seed" checkout -q -b devel
    printf '%s\n' base > "$seed/base.txt"
    git -C "$seed" add base.txt
    git -C "$seed" commit -q -m base
    git -C "$seed" push -q origin devel

    git init -q -b topic "$session"
    git -C "$session" config user.email agent@example.com
    git -C "$session" config user.name Agent
    git -C "$session" config commit.gpgsign false
    printf '%s\n' topic > "$session/topic.txt"
    git -C "$session" add topic.txt
    git -C "$session" commit -q -m topic
    git -C "$session" remote add origin "$remote"
    git -C "$session" fetch -q origin devel
    tip="$(git -C "$session" rev-parse HEAD)"
  }

  cleanup() {
    rm -rf "$base"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'reports the missing merge base and leaves the branch untouched'
    sync_and_verify() {
      cd "$session" || return 1
      sh "$hook" \
        && [ "$(git rev-parse HEAD)" = "$tip" ] \
        && [ "$(git rev-parse --is-shallow-repository)" = false ]
    }
    When run sync_and_verify
    The status should equal 0
    The output should include 'NO VISIBLE MERGE BASE'
    The output should include 'branch left untouched'
  End
End

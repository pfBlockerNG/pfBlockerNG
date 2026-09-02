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
    git_fixture init -q --bare "$remote"
    git_fixture clone -q "$remote" "$seed" 2>/dev/null
    git_fixture -C "$seed" config user.email seed@example.com
    git_fixture -C "$seed" config user.name Seed
    git_fixture -C "$seed" config commit.gpgsign false
    git_fixture -C "$seed" checkout -q -b devel
    i=1
    while [ "$i" -le 3 ]; do
      printf 'base-%s\n' "$i" >> "$seed/base.txt"
      git_fixture -C "$seed" add base.txt
      git_fixture -C "$seed" commit -q -m "base-$i"
      i=$((i + 1))
    done
    git_fixture -C "$seed" push -q origin devel

    git_fixture clone -q --depth=2 --branch devel "file://$remote" "$session"
    git_fixture -C "$session" config user.email agent@example.com
    git_fixture -C "$session" config user.name Agent
    git_fixture -C "$session" config commit.gpgsign false
    git_fixture -C "$session" checkout -q -b topic
    printf '%s\n' topic > "$session/topic.txt"
    git_fixture -C "$session" add topic.txt
    git_fixture -C "$session" commit -q -m topic

    i=4
    while [ "$i" -le 7 ]; do
      printf 'base-%s\n' "$i" >> "$seed/base.txt"
      git_fixture -C "$seed" add base.txt
      git_fixture -C "$seed" commit -q -m "base-$i"
      i=$((i + 1))
    done
    git_fixture -C "$seed" push -q origin devel
    git_fixture -C "$session" fetch -q --depth=2 origin devel

    # origin/devel's new shallow boundary is newer than topic's base. The
    # commits exist on one real history, but this clone cannot yet see that.
    [ "$(git_fixture -C "$session" rev-parse --is-shallow-repository)" = true ]
    ! git_fixture -C "$session" merge-base HEAD origin/devel >/dev/null 2>&1
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
        && [ "$(git_fixture rev-parse --is-shallow-repository)" = false ] \
        && git_fixture merge-base --is-ancestor origin/devel HEAD \
        && [ "$(git_fixture rev-list --count origin/devel..HEAD)" -eq 1 ] \
        && [ "$(git_fixture log -1 --format=%s)" = topic ]
    }
    When run sync_and_verify
    The status should equal 0
    The output should include 'rebased onto origin/devel'
    The output should include 'patch-equivalent'
  End

  It 'explains dirty divergent history in squash-landing terms'
    sync_dirty() {
      printf '%s\n' dirty >> "$session/topic.txt"
      cd "$session" || return 1
      sh "$hook"
    }
    When run sync_dirty
    The status should equal 0
    The output should include 'squash commit'
    The output should not include 'rebase-merge'
  End
End

# Untracked files never conflict with a fast-forward or rebase unless the incoming
# commits write the same path, so they must not count as tree dirt: a session that
# only queried Graphify leaves untracked graphify-out/memory/ records behind, and a
# hook that refused to sync over them would stall every later session on that clone.
Describe 'session-branch-sync base branch with untracked files'
  hook="${PFB_ROOT}/.claude/hooks/session-branch-sync.sh"

  setup() {
    scrub_git_env
    base="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/session-sync.XXXXXX")"
    remote="$base/remote.git"
    seed="$base/seed"
    session="$base/session"
    git_fixture init -q --bare "$remote"
    git_fixture clone -q "$remote" "$seed" 2>/dev/null
    git_fixture -C "$seed" config user.email seed@example.com
    git_fixture -C "$seed" config user.name Seed
    git_fixture -C "$seed" config commit.gpgsign false
    git_fixture -C "$seed" checkout -q -b devel
    printf 'base-1\n' > "$seed/base.txt"
    git_fixture -C "$seed" add base.txt
    git_fixture -C "$seed" commit -q -m base-1
    git_fixture -C "$seed" push -q origin devel

    git_fixture clone -q --branch devel "file://$remote" "$session"

    printf 'base-2\n' >> "$seed/base.txt"
    mkdir -p "$seed/graphify-out/memory"
    printf 'upstream\n' > "$seed/graphify-out/memory/collide.md"
    git_fixture -C "$seed" add base.txt graphify-out/memory/collide.md
    git_fixture -C "$seed" commit -q -m base-2
    git_fixture -C "$seed" push -q origin devel
    git_fixture -C "$session" fetch -q origin devel
  }

  cleanup() {
    rm -rf "$base"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'fast-forwards over an untracked memory record'
    sync_untracked() {
      mkdir -p "$session/graphify-out/memory"
      printf 'local\n' > "$session/graphify-out/memory/query_local.md"
      cd "$session" || return 1
      sh "$hook" \
        && [ "$(git_fixture rev-parse HEAD)" = "$(git_fixture rev-parse origin/devel)" ] \
        && [ "$(cat graphify-out/memory/query_local.md)" = local ]
    }
    When run sync_untracked
    The status should equal 0
    The output should include 'fast-forwarded 1 commit'
  End

  It 'still refuses over a modified tracked file'
    sync_modified() {
      printf 'local\n' >> "$session/base.txt"
      cd "$session" || return 1
      sh "$hook" \
        && [ "$(git_fixture rev-list --count HEAD..origin/devel)" -eq 1 ]
    }
    When run sync_modified
    The status should equal 0
    The output should include 'DIRTY'
  End

  It 'reports a fast-forward blocked by a colliding untracked file'
    sync_collide() {
      mkdir -p "$session/graphify-out/memory"
      printf 'local\n' > "$session/graphify-out/memory/collide.md"
      cd "$session" || return 1
      sh "$hook" \
        && [ "$(git_fixture rev-list --count HEAD..origin/devel)" -eq 1 ] \
        && [ "$(cat graphify-out/memory/collide.md)" = local ]
    }
    When run sync_collide
    The status should equal 0
    The output should include 'fast-forward'
    The output should include 'FAILED'
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
    git_fixture init -q --bare "$remote"
    git_fixture clone -q "$remote" "$seed" 2>/dev/null
    git_fixture -C "$seed" config user.email seed@example.com
    git_fixture -C "$seed" config user.name Seed
    git_fixture -C "$seed" config commit.gpgsign false
    git_fixture -C "$seed" checkout -q -b devel
    printf '%s\n' base > "$seed/base.txt"
    git_fixture -C "$seed" add base.txt
    git_fixture -C "$seed" commit -q -m base
    git_fixture -C "$seed" push -q origin devel

    git_fixture init -q -b topic "$session"
    git_fixture -C "$session" config user.email agent@example.com
    git_fixture -C "$session" config user.name Agent
    git_fixture -C "$session" config commit.gpgsign false
    printf '%s\n' topic > "$session/topic.txt"
    git_fixture -C "$session" add topic.txt
    git_fixture -C "$session" commit -q -m topic
    git_fixture -C "$session" remote add origin "$remote"
    git_fixture -C "$session" fetch -q origin devel
    tip="$(git_fixture -C "$session" rev-parse HEAD)"
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
        && [ "$(git_fixture rev-parse HEAD)" = "$tip" ] \
        && [ "$(git_fixture rev-parse --is-shallow-repository)" = false ]
    }
    When run sync_and_verify
    The status should equal 0
    The output should include 'NO VISIBLE MERGE BASE'
    The output should include 'branch left untouched'
  End
End

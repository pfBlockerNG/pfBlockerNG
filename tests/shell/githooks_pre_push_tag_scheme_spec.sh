#shellcheck shell=sh
# .githooks/pre-push tag-scheme oracle: pins that the release-tag validation
# loop still consumes the per-ref update list after the capture-once stdin
# refactor (issue #1307) — a silently empty feed would disable tag enforcement
# with no other test noticing. Behaviour-preserving pin: green before and after.

Describe 'pre-push tag-scheme loop still consumes the update list (issue #1307)'
  hook="${PFB_ROOT}/.githooks/pre-push"

  setup() {
    scrub_git_env
    base="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/prepushtag.XXXXXX")"
    git init -q -b devel "${base}/repo"
    git -C "${base}/repo" config user.email t@example.com
    git -C "${base}/repo" config user.name T
    ( cd "${base}/repo" && echo one > f && git add f && git commit -q -m c1 )
    sha="$(git -C "${base}/repo" rev-parse HEAD)"
  }

  cleanup() {
    rm -rf "$base"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'still rejects a versioned tag unreachable from origin/main and origin/devel'
    push_tag() {
      # No origin/main or origin/devel exists here, so a versioned tag must
      # hit the reachability error — proving the loop actually read the line.
      cd "${base}/repo" && printf '%s\n' "refs/tags/v9.9.9 $sha refs/tags/v9.9.9 0000000000000000000000000000000000000000" \
        | env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL sh "$hook" origin "${base}/repo"
    }
    When run push_tag
    The status should equal 1
    The stderr should include 'reachable'
  End
End

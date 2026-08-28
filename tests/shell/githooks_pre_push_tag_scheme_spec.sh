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
    git_fixture init -q -b devel "${base}/repo"
    git_fixture -C "${base}/repo" config user.email t@example.com
    git_fixture -C "${base}/repo" config user.name T
    git_fixture -C "${base}/repo" config commit.gpgsign false
    ( cd "${base}/repo" && echo one > f && git_fixture add f && git_fixture commit -q -m c1 )
    sha="$(git_fixture -C "${base}/repo" rev-parse HEAD)"
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
      cd "${base}/repo" || return
      git_fixture tag -a v9.9.9.r1 -m v9.9.9.r1 -m 'pfBlockerNG-Release-Channel: testing' "$sha"
      tag_object="$(git_fixture rev-parse refs/tags/v9.9.9.r1)"
      printf '%s\n' "refs/tags/v9.9.9.r1 $tag_object refs/tags/v9.9.9.r1 0000000000000000000000000000000000000000" \
        | env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID -u COPILOT_AGENT_PROMPT \
          -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          sh "$hook" origin "${base}/repo"
    }
    When run push_tag
    The status should equal 1
    The stderr should include 'reachable'
  End

  It 'accepts an annotated tag with one matching channel trailer on the exact release line'
    push_tag() {
      cd "${base}/repo" || return
      git_fixture update-ref refs/remotes/origin/release/9.9 "$sha"
      git_fixture tag -a v9.9.9.r1 -m v9.9.9.r1 -m 'pfBlockerNG-Release-Channel: testing' "$sha"
      tag_object="$(git_fixture rev-parse refs/tags/v9.9.9.r1)"
      printf '%s\n' "refs/tags/v9.9.9.r1 $tag_object refs/tags/v9.9.9.r1 0000000000000000000000000000000000000000" \
        | env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID -u COPILOT_AGENT_PROMPT \
          -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          sh "$hook" origin "${base}/repo"
    }
    When run push_tag
    The status should equal 0
  End

  It 'rejects a non-tag source ref targeting a versioned remote tag'
    push_tag() {
      cd "${base}/repo" || return
      git_fixture update-ref refs/remotes/origin/release/9.9 "$sha"
      git_fixture tag -a v9.9.9.r1 -m v9.9.9.r1 -m 'pfBlockerNG-Release-Channel: testing' "$sha"
      printf '%s\n' "HEAD $sha refs/tags/v9.9.9.r1 0000000000000000000000000000000000000000" \
        | env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID -u COPILOT_AGENT_PROMPT \
          -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          sh "$hook" origin "${base}/repo"
    }
    When run push_tag
    The status should equal 1
    The stderr should include 'source ref'
  End

  It 'accepts a header-shaped body line plus one terminal channel trailer'
    push_tag() {
      cd "${base}/repo" || return
      git_fixture update-ref refs/remotes/origin/release/9.9 "$sha"
      git_fixture tag -a v9.9.9.r1 -m 'body mentions
pfBlockerNG-Release-Channel: edge' -m 'pfBlockerNG-Release-Channel: testing' "$sha"
      tag_object="$(git_fixture rev-parse refs/tags/v9.9.9.r1)"
      printf '%s\n' "refs/tags/v9.9.9.r1 $tag_object refs/tags/v9.9.9.r1 0000000000000000000000000000000000000000" \
        | env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID -u COPILOT_AGENT_PROMPT \
          -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          sh "$hook" origin "${base}/repo"
    }
    When run push_tag
    The status should equal 0
  End

  It 'rejects a lightweight versioned tag before push'
    push_tag() {
      cd "${base}/repo" || return
      git_fixture update-ref refs/remotes/origin/release/9.9 "$sha"
      git_fixture tag v9.9.9.r1 "$sha"
      printf '%s\n' "refs/tags/v9.9.9.r1 $sha refs/tags/v9.9.9.r1 0000000000000000000000000000000000000000" \
        | env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID -u COPILOT_AGENT_PROMPT \
          -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          sh "$hook" origin "${base}/repo"
    }
    When run push_tag
    The status should equal 1
    The stderr should include 'annotated'
  End

  It 'rejects duplicate channel trailers during recovery'
    push_tag() {
      cd "${base}/repo" || return
      git_fixture update-ref refs/remotes/origin/release/9.9 "$sha"
      git_fixture tag -a v9.9.9.r1 -m v9.9.9.r1 -m 'pfBlockerNG-Release-Channel: testing
pfBlockerNG-Release-Channel: testing' "$sha"
      tag_object="$(git_fixture rev-parse refs/tags/v9.9.9.r1)"
      printf '%s\n' "refs/tags/v9.9.9.r1 $tag_object refs/tags/v9.9.9.r1 0000000000000000000000000000000000000000" \
        | env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID -u COPILOT_AGENT_PROMPT \
          -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          sh "$hook" origin "${base}/repo"
    }
    When run push_tag
    The status should equal 1
    The stderr should include 'trailer'
  End

  It 'rejects a conflicting case-variant channel trailer'
    push_tag() {
      cd "${base}/repo" || return
      git_fixture update-ref refs/remotes/origin/release/9.9 "$sha"
      git_fixture tag -a v9.9.9.r1 -m v9.9.9.r1 -m 'pfBlockerNG-Release-Channel: testing
pfblockerng-release-channel: edge' "$sha"
      tag_object="$(git_fixture rev-parse refs/tags/v9.9.9.r1)"
      printf '%s\n' "refs/tags/v9.9.9.r1 $tag_object refs/tags/v9.9.9.r1 0000000000000000000000000000000000000000" \
        | env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID -u COPILOT_AGENT_PROMPT \
          -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          sh "$hook" origin "${base}/repo"
    }
    When run push_tag
    The status should equal 1
    The stderr should include 'trailer'
  End

  It 'rejects hidden no-space and tab channel trailers'
    push_tag() {
      cd "${base}/repo" || return
      git_fixture update-ref refs/remotes/origin/release/9.9 "$sha"
      git_fixture tag -a v9.9.9.r1 -m v9.9.9.r1 -m 'pfBlockerNG-Release-Channel: testing
pfblockerng-release-channel:edge
PFBLOCKERNG-RELEASE-CHANNEL:	edge' "$sha"
      tag_object="$(git_fixture rev-parse refs/tags/v9.9.9.r1)"
      printf '%s\n' "refs/tags/v9.9.9.r1 $tag_object refs/tags/v9.9.9.r1 0000000000000000000000000000000000000000" \
        | env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID -u COPILOT_AGENT_PROMPT \
          -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          sh "$hook" origin "${base}/repo"
    }
    When run push_tag
    The status should equal 1
    The stderr should include 'trailer'
  End
End

#shellcheck shell=sh
# Copilot session lifecycle wiring (issue #2177).
#
# copilot-session-hook.sh is called from BOTH the repo-level hook file and the
# user-level install, and the user-level copy is GLOBAL — Copilot runs it for
# every session in every repository on the machine. So the scope guard is the
# load-bearing row here, and the fixture that matters is the HOSTILE one: a
# checkout that satisfies whatever the guard looks for. An earlier revision
# tested for an `AGENTS.md` plus an executable marker script and then executed
# both from the session's repo, so any repo could create those two paths and get
# this repo's capsule plus arbitrary code execution. The guard is now identity
# (same common git dir as the dispatcher's own checkout), and the rows below
# forge the old signal to prove it no longer opens anything.
#
# The capsule row asserts parseable JSON carrying additionalContext, because
# sessionStart is the one Copilot event whose stdout is parsed, and malformed
# output is dropped silently.

Describe 'Copilot session lifecycle (issue #2177)'
  hook="${PFB_ROOT}/scripts/agent/copilot-session-hook.sh"
  installer="${PFB_ROOT}/scripts/agent/install-copilot-hooks.sh"

  setup() {
    scrub_git_env
    base="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/copilothook.XXXXXX")"
    repo="${base}/repo"
    stranger="${base}/stranger"
    for tree in "$repo" "$stranger"; do
      git_fixture init -q -b devel "$tree"
      git_fixture -C "$tree" config user.email human@example.com
      git_fixture -C "$tree" config user.name Human
    done
    # The checkout the dispatcher belongs to: it runs from here, so this is the
    # one repository whose sessions it may act on.
    printf '%s\n' '# bootstrap' > "${repo}/AGENTS.md"
    mkdir -p "${repo}/scripts/agent" "${repo}/.claude/hooks"
    cp "${PFB_ROOT}/scripts/agent/copilot-session-marker.sh" \
      "${PFB_ROOT}/scripts/agent/copilot-session-hook.sh" "${repo}/scripts/agent/"
    chmod +x "${repo}/scripts/agent/copilot-session-marker.sh" \
      "${repo}/scripts/agent/copilot-session-hook.sh"
    hook="${repo}/scripts/agent/copilot-session-hook.sh"
    sessions="${repo}/.git/pfb-copilot-sessions"

    # The hostile checkout: everything the RETIRED presence guard looked for,
    # with payloads in place of the real scripts.
    printf '%s\n' '# bootstrap' > "${stranger}/AGENTS.md"
    mkdir -p "${stranger}/scripts/agent" "${stranger}/.claude/hooks"
    payload="${base}/payload.log"
    printf '#!/bin/sh\necho marker >> "%s"\n' "$payload" \
      > "${stranger}/scripts/agent/copilot-session-marker.sh"
    printf '#!/bin/sh\necho sync >> "%s"\n' "$payload" \
      > "${stranger}/.claude/hooks/session-branch-sync.sh"
    chmod +x "${stranger}/scripts/agent/copilot-session-marker.sh" \
      "${stranger}/.claude/hooks/session-branch-sync.sh"
  }

  cleanup() {
    rm -rf "$base"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  # PFB_COPILOT_PID is the marker script's documented seam: outside a real CLI
  # session the ancestor walk finds no `copilot` process, and injecting a pid here
  # is what lets the row assert on a record that names a LIVE process.
  hook_in() {
    cd "$1" && PFB_COPILOT_PID="${3:-$$}" sh "$hook" "$2"
  }

  It 'records the session pid on start'
    When run hook_in "$repo" start
    The status should equal 0
    The stdout should include 'additionalContext'
    The path "${sessions}/$$" should be exist
  End

  It 'emits a capsule that parses as JSON with the modes'
    capsule() {
      cd "$repo" && PFB_COPILOT_PID=$$ sh "$hook" start | python3 -c 'import json,sys; d=json.load(sys.stdin); c=d["additionalContext"]; print("PONYTAIL" in c and "CAVEMAN" in c and "AGENTS.md" in c)'
    }
    When run capsule
    The status should equal 0
    The stdout should include 'True'
  End

  It 'removes the record on end'
    hook_in "$repo" start > /dev/null
    When run hook_in "$repo" end
    The status should equal 0
    The path "${sessions}/$$" should not be exist
  End

  It 'no-ops in a foreign checkout that forges every signal the guard once used'
    When run hook_in "$stranger" start
    The status should equal 0
    The stdout should equal ''
    The path "${stranger}/.git/pfb-copilot-sessions" should not be exist
    The path "$payload" should not be exist
  End

  It 'acts in a linked worktree of its own checkout'
    git_fixture -C "$repo" worktree add -q "${base}/wt" -b hook-spec
    in_worktree() {
      cd "${base}/wt" && PFB_COPILOT_PID=$$ sh "$hook" start
    }
    When run in_worktree
    The status should equal 0
    The stdout should include 'additionalContext'
    The path "${sessions}/$$" should be exist
  End

  It 'rejects an unknown action'
    When run hook_in "$repo" sideways
    The status should equal 2
    The stderr should include 'usage:'
  End

  Describe 'install-copilot-hooks.sh'
    install_setup() {
      copilot_home="${base}/copilot-home"
    }
    BeforeEach 'install_setup'

    install() {
      cd "$repo" && COPILOT_HOME="$copilot_home" sh "$installer" --root "$repo" "$@"
    }

    It 'writes a user-level hook file pointing at the dispatcher'
      When run install
      The status should equal 0
      The stdout should include 'pfblockerng.json'
      The contents of file "${copilot_home}/hooks/pfblockerng.json" should include \
        "${repo}/scripts/agent/copilot-session-hook.sh"
      The contents of file "${copilot_home}/hooks/pfblockerng.json" should include 'sessionEnd'
    End

    It 'writes a hook file Copilot can parse'
      install > /dev/null
      valid_json() {
        python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(sorted(d["hooks"]))' \
          "${copilot_home}/hooks/pfblockerng.json"
      }
      When run valid_json
      The status should equal 0
      The stdout should include "['sessionEnd', 'sessionStart', 'subagentStart']"
    End

    It 'is idempotent'
      install > /dev/null
      When run install
      The status should equal 0
      The stdout should include 'pfblockerng.json'
    End

    It 'refuses a checkout path that cannot be embedded in JSON'
      quoted_root() {
        weird="${base}/we\"ird"
        mkdir -p "${weird}/scripts/agent"
        cp "${repo}/scripts/agent/copilot-session-hook.sh" "${weird}/scripts/agent/"
        cd "$repo" && COPILOT_HOME="$copilot_home" sh "$installer" --root "$weird"
      }
      When run quoted_root
      The status should equal 1
      The stderr should include 'cannot be embedded in JSON'
      The path "${copilot_home}/hooks/pfblockerng.json" should not be exist
    End

    It 'installs the same events the repo-level hook file defines'
      install > /dev/null
      same_events() {
        python3 -c 'import json,sys; a,b=(json.load(open(p))["hooks"] for p in sys.argv[1:3]); print(sorted(a)==sorted(b))' \
          "${copilot_home}/hooks/pfblockerng.json" "${PFB_ROOT}/.github/hooks/pfblockerng.json"
      }
      When run same_events
      The status should equal 0
      The stdout should include 'True'
    End

    It 'rejects --root with no directory argument'
      bare_root() {
        cd "$repo" && COPILOT_HOME="$copilot_home" sh "$installer" --root
      }
      When run bare_root
      The status should equal 2
      The stderr should include 'needs a directory'
      The path "${copilot_home}/hooks/pfblockerng.json" should not be exist
    End

    It 'removes the hook file on --uninstall'
      install > /dev/null
      When run install --uninstall
      The status should equal 0
      The stdout should include 'removed'
      The path "${copilot_home}/hooks/pfblockerng.json" should not be exist
    End
  End
End

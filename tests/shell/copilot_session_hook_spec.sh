#shellcheck shell=sh
# Copilot session lifecycle wiring (issue #2177).
#
# copilot-session-hook.sh is called from BOTH the repo-level hook file and the
# user-level install, and the user-level copy is global — so the repo guard is
# the load-bearing row here: a Copilot session in an unrelated checkout must get
# neither this repo's capsule nor a stray marker file.
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
    # A checkout this hook may act on: the bootstrap plus this repo's own marker
    # script. The stranger gets neither.
    printf '%s\n' '# bootstrap' > "${repo}/AGENTS.md"
    mkdir -p "${repo}/scripts/agent" "${repo}/.claude/hooks"
    cp "${PFB_ROOT}/scripts/agent/copilot-session-marker.sh" \
      "${PFB_ROOT}/scripts/agent/copilot-session-hook.sh" "${repo}/scripts/agent/"
    chmod +x "${repo}/scripts/agent/copilot-session-marker.sh" \
      "${repo}/scripts/agent/copilot-session-hook.sh"
    marker="${repo}/.git/pfb-copilot-session"
  }

  cleanup() {
    rm -rf "$base"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  hook_in() {
    cd "$1" && sh "$hook" "$2"
  }

  It 'writes a live pid marker on start'
    When run hook_in "$repo" start
    The status should equal 0
    The stdout should include 'additionalContext'
    The contents of file "$marker" should match pattern '[0-9]*'
  End

  It 'emits a capsule that parses as JSON with the modes'
    capsule() {
      cd "$repo" && sh "$hook" start | python3 -c 'import json,sys; d=json.load(sys.stdin); c=d["additionalContext"]; print("PONYTAIL" in c and "CAVEMAN" in c and "AGENTS.md" in c)'
    }
    When run capsule
    The status should equal 0
    The stdout should include 'True'
  End

  It 'removes the marker on end'
    hook_in "$repo" start > /dev/null
    When run hook_in "$repo" end
    The status should equal 0
    The path "$marker" should not be exist
  End

  It 'no-ops in a checkout that is not a pfBlockerNG-org repository'
    When run hook_in "$stranger" start
    The status should equal 0
    The stdout should equal ''
    The path "${stranger}/.git/pfb-copilot-session" should not be exist
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
      The stdout should include "['sessionEnd', 'sessionStart']"
    End

    It 'is idempotent'
      install > /dev/null
      When run install
      The status should equal 0
      The stdout should include 'pfblockerng.json'
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

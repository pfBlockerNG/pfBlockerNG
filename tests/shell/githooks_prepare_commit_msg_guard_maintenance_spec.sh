#shellcheck shell=sh

Describe 'prepare-commit-msg fixture maintenance isolation (issue #2055)'
  subject_spec="${PFB_ROOT}/tests/shell/githooks_prepare_commit_msg_guard_spec.sh"

  setup() {
    scrub_git_env
    trace="$(mktemp "${SHELLSPEC_TMPBASE:-/tmp}/pcmguard-trace.XXXXXX")"
  }

  cleanup() {
    rm "$trace"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  run_subject() {
    cd "$PFB_ROOT" || return
    env -u SHELLSPEC_MODE -u COPILOT_AGENT_PROMPT GIT_TRACE2_EVENT="$trace" shellspec --no-quick --fail-no-examples \
      --shell "$(command -v dash)" "$subject_spec"
  }

  It 'proves successful fixture commits do not launch detached maintenance'
    When run run_subject
    The status should equal 0
    The stdout should include '0 failures'
    The stderr should equal ''
    The contents of file "$trace" should include '"name":"commit"'
    The contents of file "$trace" should not include '"--detach"'
  End
End

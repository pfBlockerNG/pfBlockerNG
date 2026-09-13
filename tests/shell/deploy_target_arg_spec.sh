#!/bin/sh
#shellcheck shell=sh
# deploy_target_arg_spec.sh — issue #3277 review follow-up: deploy.sh must
# reject an EMPTY ssh-target, not just a missing one. `[ $# -eq 1 ]` alone
# accepts `deploy.sh ""`, which leaves the rsync destination as `:/usr/local/`
# (no host). Real rsync fails closed, but the script must refuse before it
# touches the network.
#
# TOPOLOGY: `ssh` and `rsync` are shims that exit 0, so a regression is caught
# by the assertions here instead of by an external command failing.

Describe 'deploy.sh ssh-target validation (issue #3277)'
  setup() {
    scrub_git_env
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/deployarg.XXXXXX")"
    mkdir -p "${WORK}/bin"
    for stub in ssh rsync; do
      printf '#!/bin/sh\nexit 0\n' > "${WORK}/bin/${stub}"
      chmod +x "${WORK}/bin/${stub}"
    done
  }

  cleanup() {
    [ -z "${WORK:-}" ] || rm -rf "${WORK}"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  deploy() {
    PATH="${WORK}/bin:${PATH}" sh "${PFB_ROOT}/scripts/deploy.sh" "$@"
  }

  It 'rejects an empty ssh-target'
    When call deploy ''
    The status should equal 1
    The stderr should include 'Usage:'
    The stdout should not include 'Deploying pfBlockerNG'
  End

  It 'still rejects a missing ssh-target'
    When call deploy
    The status should equal 1
    The stderr should include 'Usage:'
  End

  It 'still rejects an option-shaped argument'
    When call deploy --channel
    The status should equal 1
    The stderr should include 'Unknown option: --channel'
  End
End

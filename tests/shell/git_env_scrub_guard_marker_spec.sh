#shellcheck shell=sh

Describe 'git-env-scrub-guard marker comments'
  GUARD="${PFB_ROOT}/scripts/git-env-scrub-guard.sh"

  setup_root() {
    root="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/guardmarker.XXXXXX")"
    mkdir -p "${root}/scripts/lib" "${root}/tests/shell"
    printf '#!/bin/sh\npfb_scrub_git_env() { :; }\n' > "${root}/scripts/lib/git-env-scrub.sh"
  }
  cleanup_root() { rm -rf "$root"; }

  BeforeEach 'setup_root'
  AfterEach 'cleanup_root'

  It 'does not accept marker text inside an inert quoted string'
    printf '%s\n' 'scrub_git_env' \
      "printf '%s' '# git-env-scrub-guard: fake'; git status" \
      > "${root}/tests/shell/quoted_marker_spec.sh"
    When run sh "$GUARD" "$root"
    The status should be failure
    The error should include 'quoted_marker_spec.sh'
  End
End

#shellcheck shell=sh
# Focused lexical guard coverage: each command form gets its own fixture so a
# dropped scanner branch cannot hide behind another positive case.

Describe 'git-env-scrub-guard raw Git command scanner'
  GUARD="${PFB_ROOT}/scripts/git-env-scrub-guard.sh"

  setup_root() {
    root="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/guardsupp.XXXXXX")"
    mkdir -p "${root}/scripts/lib" "${root}/tests/shell"
    printf '#!/bin/sh\npfb_scrub_git_env() { :; }\n' > "${root}/scripts/lib/git-env-scrub.sh"
  }
  cleanup_root() { rm -rf "$root"; }
  write_case() {
    case_name="$1"
    case_body="$2"
    printf '%s\n%s\n' 'scrub_git_env' "$case_body" > "${root}/tests/shell/${case_name}_spec.sh"
  }
  raw_case() {
    write_case "$1" "$2"
    sh "$GUARD" "$root"
  }
  marker_case() {
    write_case "$1" "$2"
    sh "$GUARD" "$root"
  }

  BeforeEach 'setup_root'
  AfterEach 'cleanup_root'

  It 'detects a raw Git command at the start of a line'
    When call raw_case start 'git status'
    The status should be failure
    The error should include 'start_spec.sh'
  End

  It 'detects a raw Git command after indentation'
    When call raw_case indent '  git status'
    The status should be failure
    The error should include 'indent_spec.sh'
  End

  It 'detects a raw Git command after &&'
    When call raw_case and 'true && git status'
    The status should be failure
    The error should include 'and_spec.sh'
  End

  It 'detects a raw Git command after ;'
    When call raw_case semicolon 'true; git status'
    The status should be failure
    The error should include 'semicolon_spec.sh'
  End

  It 'detects a raw Git command after !'
    When call raw_case bang '! git status'
    The status should be failure
    The error should include 'bang_spec.sh'
  End

  It 'detects an unquoted command substitution'
    When call raw_case substitution 'value=$(git status)'
    The status should be failure
    The error should include 'substitution_spec.sh'
  End

  It 'detects an active command substitution inside double quotes'
    When call raw_case quoted_substitution 'value="$(git status)"'
    The status should be failure
    The error should include 'quoted_substitution_spec.sh'
  End

  It 'detects an env-prefixed raw Git command'
    When call raw_case env_prefix 'env -u FOO git status'
    The status should be failure
    The error should include 'env_prefix_spec.sh'
  End

  It 'detects an assignment-prefixed raw Git command'
    When call raw_case assignment_prefix 'FOO=bar git status'
    The status should be failure
    The error should include 'assignment_prefix_spec.sh'
  End

  It 'detects a literal tab between Git and its subcommand'
    tab_case="$(printf 'git\tstatus')"
    When call raw_case literal_tab "$tab_case"
    The status should be failure
    The error should include 'literal_tab_spec.sh'
  End

  It 'detects repeated spaces between Git and its subcommand'
    When call raw_case repeated_spaces 'git  status'
    The status should be failure
    The error should include 'repeated_spaces_spec.sh'
  End

  It 'does not classify gitc as the Git command'
    When call raw_case gitc 'gitc status'
    The status should be success
    The output should include 'git-env-scrub-guard: clean'
  End

  It 'does not classify comments'
    When call raw_case comments '# git status'
    The status should be success
    The output should include 'git-env-scrub-guard: clean'
  End

  It 'does not classify prose or titles'
    When call raw_case prose "printf '%s' 'a title mentions git status'"
    The status should be success
    The output should include 'git-env-scrub-guard: clean'
  End

  It 'does not classify quoted inert fixture text'
    When call raw_case inert "printf '%s' '{\"command\":\"git status\"}'"
    The status should be success
    The output should include 'git-env-scrub-guard: clean'
  End

  It 'accepts a same-line marker with a non-empty reason'
    When call marker_case good_marker 'git status # git-env-scrub-guard: hook under test'
    The status should be success
    The output should include 'git-env-scrub-guard: clean'
  End

  It 'rejects an empty same-line marker'
    When call marker_case empty_marker 'git status # git-env-scrub-guard:'
    The status should be failure
    The error should include 'empty_marker_spec.sh'
  End

  It 'rejects a marker placed on the prior line'
    prior_marker="$(printf '%s\n%s' '# git-env-scrub-guard: prior reason' 'git status')"
    When call marker_case prior_marker "$prior_marker"
    The status should be failure
    The error should include 'prior_marker_spec.sh'
  End

  It 'detects a raw Git command after a 10k-character prefix'
    oversized="$(awk 'BEGIN { for (i = 0; i < 10000; i++) printf "x" }')"
    When call raw_case oversized "$oversized; git status"
    The status should be failure
    The error should include 'oversized_spec.sh'
  End
End

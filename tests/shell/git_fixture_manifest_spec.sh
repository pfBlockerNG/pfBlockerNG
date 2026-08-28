#!/bin/sh
# shellcheck shell=sh

Describe 'git fixture sweep manifest'
  GUARD="${PFB_ROOT}/scripts/git-env-scrub-guard.sh"
  SWEPT_SPECS='agent_run_gates_git_spec.sh
agent_run_gates_spec.sh
agent_work_branch_spec.sh
composer_cloud_install_spec.sh
git_no_docs_spec.sh
githooks_pre_push_lease_spec.sh
githooks_pre_push_tag_scheme_spec.sh
githooks_prepare_commit_msg_guard_spec.sh
impacted_tests_spec.sh
pfblockerng_truncate_survival_spec.sh
precommit_composer_vendor_spec.sh
read_version_matrix_test_spec.sh
release_ci_gate_spec.sh
session_branch_sync_spec.sh
sparse_clone_ports_spec.sh'

  setup_root() {
    root="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/guardmanifest.XXXXXX")"
    mkdir -p "${root}/scripts/lib" "${root}/tests/shell"
    cp "${PFB_ROOT}/scripts/lib/git-env-scrub.sh" "${root}/scripts/lib/"
    for spec in $SWEPT_SPECS; do
      cp "${PFB_ROOT}/tests/shell/${spec}" "${root}/tests/shell/"
    done
  }
  cleanup_root() { rm -rf "$root"; }

  assert_each_fixture_pin_is_required() {
    sh "$GUARD" "$root" >/dev/null 2>&1 || return 1
    for spec in $SWEPT_SPECS; do
      path="${root}/tests/shell/${spec}"
      awk '
        !changed && /git_fixture/ {
          sub(/git_fixture/, "git")
          changed=1
        }
        { print }
      ' "$path" > "${path}.tmp" || return 1
      mv "${path}.tmp" "$path"
      if sh "$GUARD" "$root" >/dev/null 2>&1; then
        printf 'guard missed removed fixture pin: %s\n' "$spec" >&2
        return 1
      fi
      cp "${PFB_ROOT}/tests/shell/${spec}" "$path"
    done
  }

  BeforeEach 'setup_root'
  AfterEach 'cleanup_root'

  It 'fails after the first fixture helper is removed from every swept spec'
    When call assert_each_fixture_pin_is_required
    The status should be success
  End
End

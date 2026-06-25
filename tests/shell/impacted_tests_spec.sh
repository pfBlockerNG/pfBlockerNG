#shellcheck shell=sh
# impacted-tests.sh — derive a pytest `-k` from the test modules changed on a
# branch, so a default smoke/UI dispatch runs "only the tests you created or
# touched" without a coverage map. The PFB_IMPACTED_CHANGED_FILES seam feeds the
# changed-file list directly, so these specs pin the pure filtering with no git
# fixture. Mirrors the smoke/UI fan-out's auto-derive step.

Describe 'impacted-tests.sh'
  SCRIPT="${PFB_ROOT}/scripts/impacted-tests.sh"

  # Run the resolver with a fixed changed-file list (one path per line).
  run_with() {
    PFB_IMPACTED_CHANGED_FILES="$1" sh "$SCRIPT" origin/devel "$2"
  }

  Describe 'smoke dir (tests/smoke)'
    It 'ORs the changed top-level smoke test modules'
      changed="tests/smoke/test_dns_redirect.py
tests/smoke/test_killstates.py"
      When call run_with "$changed" tests/smoke
      The output should equal 'test_dns_redirect or test_killstates'
    End

    It 'excludes the ui/ subtree, src, and non-test infra (owned elsewhere / unmappable)'
      changed="tests/smoke/test_dns_redirect.py
tests/smoke/ui/test_render.py
src/usr/local/pkg/pfblockerng/pfb_unbound.py
tests/smoke/conftest.py"
      When call run_with "$changed" tests/smoke
      The output should equal 'test_dns_redirect'
    End

    It 'emits nothing when only non-test code changed (caller runs the full marker)'
      When call run_with "src/usr/local/pkg/pfblockerng/pfb_unbound.py" tests/smoke
      The output should equal ''
    End
  End

  Describe 'ui dir (tests/smoke/ui)'
    It 'picks only the changed UI test modules, not the smoke-root ones'
      changed="tests/smoke/test_dns_redirect.py
tests/smoke/ui/test_render.py"
      When call run_with "$changed" tests/smoke/ui
      The output should equal 'test_render'
    End
  End
End

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

    It 'excludes subtrees, src, and non-test infra (owned elsewhere / unmappable)'
      changed="tests/smoke/test_dns_redirect.py
tests/smoke/test_group/helper.py
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
    It 'picks only direct changed UI test modules, not smoke-root modules or subtrees'
      changed="tests/smoke/test_dns_redirect.py
tests/smoke/ui/test_render.py
tests/smoke/ui/test_group/helper.py"
      When call run_with "$changed" tests/smoke/ui
      The output should equal 'test_render'
    End
  End

  # The PFB_IMPACTED_CHANGED_FILES seam above bypasses git entirely, so these
  # examples cover the git-reading branch. git C-quotes a path holding a quote,
  # backslash, control byte or non-ASCII byte, and the quoted form matches neither
  # the "$dir"/test_*.py prefix nor the .py suffix -- the module drops out of the
  # derived -k expression and simply never runs (issue #2228). The 'plain' row is
  # the control.
  Describe 'changed-file list read from git'
    gitc() { git_fixture -C "$repo" -c user.email=t@t -c user.name=t "$@"; }

    make_repo() {
      scrub_git_env
      repo="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/impactedhostile.XXXXXX")"
      git_fixture -C "$repo" init -q
      gitc config commit.gpgsign false
      mkdir -p "$repo/tests/smoke"
      printf 'base\n' > "$repo/README.md"
      gitc add README.md
      gitc commit -q -m base
      gitc branch -f base HEAD
    }
    cleanup_repo() { rm -rf "$repo"; }
    Before 'make_repo'
    After 'cleanup_repo'

    Describe 'each escape class git quotes'
      Parameters
        'plain'
        'has\backslash'
        "$(printf 'has\ttab')"
        "$(printf 'has\001control')"
        'café'
      End

      It "selects a changed test module named 'test_$1.py'"
        printf 'def test_x():\n    pass\n' > "$repo/tests/smoke/test_$1.py"
        gitc add -A
        gitc commit -q -m hostile
        When run sh -c "cd '$repo' && sh '$SCRIPT' base tests/smoke"
        The status should equal 0
        The output should equal "test_$1"
      End
    End

    # A literal newline cannot be expressed as a -k stem at all, so the module must
    # NOT be quietly dropped from a narrowed expression: emitting nothing routes the
    # caller to its full-marker path, which runs everything. The sibling module is
    # what makes this failable -- without it the expression would be empty anyway.
    It 'emits nothing when a changed path holds a newline, so the caller runs it all'
      printf 'def test_x():\n    pass\n' > "$repo/tests/smoke/test_$(printf 'has\nnewline').py"
      printf 'def test_y():\n    pass\n' > "$repo/tests/smoke/test_sibling.py"
      gitc add -A
      gitc commit -q -m hostile
      When run sh -c "cd '$repo' && sh '$SCRIPT' base tests/smoke"
      The status should equal 0
      The output should equal ''
    End
  End
End

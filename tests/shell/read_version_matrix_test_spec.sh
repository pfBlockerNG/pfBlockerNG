#shellcheck shell=sh
# read-version-matrix.sh derived test matrices (python_versions / php_versions) —
# locks the test.yml matrix-derivation: pytest fans out over the DISTINCT pythons
# mapped from each entry's py_flavor, the PHP jobs over the DISTINCT php_version,
# both deduped + sorted. Strict supported-only derive (no hardcoded version list).
#
# The reader reads its JSON via `git show <ref>:<file>`, so the fixture matrix is
# committed to a throwaway git repo and addressed with --ref HEAD --file. Each
# fixture includes a ci:true CE entry so the reader's CI-empty guard is satisfied
# and the UNFILTERED (CE + Plus) derive path — the one test.yml uses — is exercised.

Describe 'read-version-matrix.sh derived test matrices'
  READER="${PFB_ROOT}/scripts/read-version-matrix.sh"

  # Build a self-contained git repo holding $1 as supported-versions.json on HEAD,
  # and echo the repo path. The reader's `git fetch origin ...` is a harmless no-op
  # there (no remote); `git show HEAD:file` reads the commit. Commit signing is
  # disabled (-c commit.gpgsign=false) so the spec runs in any environment.
  make_matrix_repo() {
    _mm_json="$1"
    _mm_repo="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/vermx.XXXXXX")"
    (
      cd "$_mm_repo" || exit 1
      git init -q
      git config user.email ci@example.invalid
      git config user.name CI
      printf '%s\n' "$_mm_json" > supported-versions.json
      git add supported-versions.json
      git -c commit.gpgsign=false commit -qm fixture
    )
    printf '%s' "$_mm_repo"
  }

  # Run the reader's --print-test against a fixture-matrix repo, from inside it.
  # Preserve the reader's exit status across the cleanup so a fail-closed exit is
  # observable to the caller.
  run_print_test() {
    _rt_repo="$(make_matrix_repo "$1")"
    ( cd "$_rt_repo" && sh "$READER" --ref HEAD --file supported-versions.json --print-test )
    _rt_status=$?
    rm -rf "$_rt_repo"
    return "$_rt_status"
  }

  Describe 'python_versions derivation (py_flavor -> N.MM)'
    It 'derives, dedups, and sorts py311,py312,py311 into ["3.11","3.12"]'
      # Given three entries whose py_flavor is py311, py312, py311 (a duplicate)
      # When the reader derives python_versions
      # Then the result is the deduped, sorted distinct set ["3.11","3.12"]
      #      (3.11 once, despite appearing twice in the input).
      json='{"versions":[
        {"channel":"CE","ci":true,"php_version":"8.3","py_flavor":"py311"},
        {"channel":"CE","ci":true,"php_version":"8.3","py_flavor":"py312"},
        {"channel":"Plus","ci":false,"php_version":"8.5","py_flavor":"py311"}
      ]}'
      When call run_print_test "$json"
      The status should be success
      # --print-test prints python_versions first (jq-pretty, one element/line):
      #   1 python_versions:  2 [  3   "3.11",  4   "3.12"  5 ]
      The line 3 of output should equal '  "3.11",'
      The line 4 of output should equal '  "3.12"'
    End

    It 'maps a single-digit minor flavor py39 to 3.9'
      # Given an entry whose py_flavor is py39 (single major, single minor digit)
      # Then it maps to "3.9" (not "3.39" nor "39") — the documented N.MM transform.
      json='{"versions":[{"channel":"CE","ci":true,"php_version":"8.3","py_flavor":"py39"}]}'
      When call run_print_test "$json"
      The status should be success
      The line 3 of output should equal '  "3.9"'
    End
  End

  Describe 'php_versions derivation'
    It 'dedups and sorts 8.3,8.5,8.3 into ["8.3","8.5"]'
      # Given entries with php_version 8.3, 8.5, 8.3 (a duplicate)
      # Then php_versions is the deduped, sorted set ["8.3","8.5"] (8.3 once).
      json='{"versions":[
        {"channel":"CE","ci":true,"php_version":"8.3","py_flavor":"py311"},
        {"channel":"Plus","ci":false,"php_version":"8.5","py_flavor":"py311"},
        {"channel":"CE","ci":true,"php_version":"8.3","py_flavor":"py312"}
      ]}'
      When call run_print_test "$json"
      The status should be success
      # python_versions block is lines 1-5 (two distinct pythons), then a blank
      # line 6, 'php_versions:' line 7, '[' line 8, then the php elements:
      The line 9 of output should equal '  "8.3",'
      The line 10 of output should equal '  "8.5"'
    End
  End

  Describe 'fail-closed on a malformed py_flavor'
    It 'exits non-zero when no python version can be derived'
      # Given a non-empty matrix whose only entry has an unparseable py_flavor
      # Then the derive fails closed (non-zero) rather than emitting [] silently.
      json='{"versions":[{"channel":"CE","ci":true,"php_version":"8.3","py_flavor":"python3"}]}'
      When call run_print_test "$json"
      The status should be failure
      The stderr should include 'no python versions derived'
    End
  End
End

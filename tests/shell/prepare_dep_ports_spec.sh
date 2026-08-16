#shellcheck shell=sh
# prepare-dep-ports.sh — the dependency flow's OWN "prepare the ports tree" step
# (issue #2454 step 3b), sibling to sparse-clone-ports.sh: a blobless sparse
# checkout of FreeBSD-ports at a pinned full-SHA commit, materializing only the
# origins the given ROUTE matrix's rows declare as extra_pkgs.
#
# Behavioural contracts pinned here:
#   declared-only  — only the origins a matrix row's extra_pkgs names are
#                    materialised; an unrelated port dir in the same tree stays
#                    absent, and HEAD lands exactly on the pinned SHA.
#   zero-origins   — a matrix with no extra_pkgs anywhere is a NOOP: DEST is
#                    created empty and NO network call happens at all (the
#                    fixture URL can be a bogus, unreachable path).
#   bad-sha        — a REF that is not a full 40-hex commit SHA (branch name,
#                    short abbreviation, tag, ...) is a usage error, exit 1.
#   existing-empty-dest — an existing but EMPTY DEST is accepted.
#   non-empty-dest — an existing, non-empty DEST is refused, never silently
#                    reused or overwritten.
#
# Local file:// remote + uploadpack.allowFilter, same idiom as
# sparse_clone_ports_spec.sh -- no real FreeBSD-ports checkout needed.

Describe 'prepare-dep-ports.sh'
  SCRIPT="${PFB_ROOT}/scripts/prepare-dep-ports.sh"
  DECLARED_PORT_A="textproc/py-a"
  DECLARED_PORT_B="www/py-b"
  UNDECLARED_PORT="net/x"

  # Build a local git 'remote' with the two declared origins' Makefiles plus one
  # UNRELATED port dir that must never be materialised.
  setup() {
    # Scrub inherited git context -- same rationale as sparse_clone_ports_spec.sh:
    # under the pre-commit hook git exports GIT_DIR/GIT_INDEX_FILE/GIT_WORK_TREE
    # pointing at the REAL repo; without this the fixture's git init AND the
    # script-under-test's `git -C` would hit it, not the file:// fixture.
    scrub_git_env
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/depports.XXXXXX")"
    REMOTE="${WORK}/remote"
    DEST="${WORK}/dest"
    URL="file://${REMOTE}"
    mkdir -p "${REMOTE}/${DECLARED_PORT_A}" "${REMOTE}/${DECLARED_PORT_B}" "${REMOTE}/${UNDECLARED_PORT}"
    (
      cd "$REMOTE" || exit 1
      git_fixture init -q
      git_fixture config user.email ci@example.invalid
      git_fixture config user.name CI
      git_fixture config uploadpack.allowFilter true
      printf 'PORTNAME=py-a\n' > "${DECLARED_PORT_A}/Makefile"
      printf 'PORTNAME=py-b\n' > "${DECLARED_PORT_B}/Makefile"
      printf 'PORTNAME=x\n' > "${UNDECLARED_PORT}/Makefile"
      git_fixture add -A && git_fixture -c commit.gpgsign=false commit -qm ports
    ) >/dev/null 2>&1
    SHA="$(cd "$REMOTE" && git_fixture rev-parse HEAD)"
    ROUTE_MATRIX="$(printf '[{"extra_pkgs":["%s"]},{"extra_pkgs":["%s"]},{"extra_pkgs":[]}]' "$DECLARED_PORT_A" "$DECLARED_PORT_B")"
  }
  cleanup() { rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  run_prepare() { sh "$SCRIPT" "$URL" "$SHA" "$DEST" "$ROUTE_MATRIX"; }

  declared_result() {
    run_prepare >/dev/null 2>&1 || { echo "script-failed=$?"; return 1; }
    [ -f "${DEST}/${DECLARED_PORT_A}/Makefile" ] && echo 'a=present' || echo 'a=absent'
    [ -f "${DEST}/${DECLARED_PORT_B}/Makefile" ] && echo 'b=present' || echo 'b=absent'
    [ -e "${DEST}/${UNDECLARED_PORT}" ] && echo 'x=present' || echo 'x=absent'
    echo "head=$(git_fixture -C "$DEST" rev-parse HEAD)"
  }
  It 'declared-only: materialises exactly the extra_pkgs origins, HEAD == SHA'
    When call declared_result
    The status should be success
    The line 1 of output should equal 'a=present'
    The line 2 of output should equal 'b=present'
    The line 3 of output should equal 'x=absent'
    The line 4 of output should equal "head=${SHA}"
  End

  # A bogus, unreachable URL: the zero-origins path must never dial out, so this
  # must still succeed (proves no git fetch/clone ran).
  zero_origins_result() {
    URL='file:///nonexistent/does-not-exist'
    ROUTE_MATRIX='[{"extra_pkgs":[]},{}]'
    run_prepare >/dev/null 2>&1 || { echo "script-failed=$?"; return 1; }
    [ -d "$DEST" ] && echo 'dest=dir' || echo 'dest=missing'
    [ -e "${DEST}/.git" ] && echo 'git=present' || echo 'git=absent'
    find "$DEST" -mindepth 1 | wc -l | tr -d ' '
  }
  It 'zero-origins: creates DEST empty and exits 0 without any network call'
    When call zero_origins_result
    The status should be success
    The line 1 of output should equal 'dest=dir'
    The line 2 of output should equal 'git=absent'
    The line 3 of output should equal '0'
  End

  bad_sha_result() {
    SHA='not-a-real-sha'
    run_prepare 2>&1
  }
  It 'bad-sha: a non-40-hex SHA is a usage error, exit 1'
    When call bad_sha_result
    The status should be failure
    The output should include 'full 40-hex commit SHA'
  End

  short_sha_result() {
    SHA="$(printf '%.7s' "$SHA")"
    run_prepare 2>&1
  }
  It 'bad-sha: a short 7-hex abbreviation is rejected the same way'
    When call short_sha_result
    The status should be failure
    The output should include 'full 40-hex commit SHA'
  End

  empty_existing_dest_result() {
    mkdir -p "$DEST"
    run_prepare >/dev/null 2>&1 || { echo "script-failed=$?"; return 1; }
    [ -f "${DEST}/${DECLARED_PORT_A}/Makefile" ] && echo 'a=present' || echo 'a=absent'
  }
  It 'existing-empty-dest: a pre-existing but EMPTY DEST is accepted, not refused'
    When call empty_existing_dest_result
    The status should be success
    The line 1 of output should equal 'a=present'
  End

  non_empty_dest_result() {
    mkdir -p "$DEST"
    true > "${DEST}/leftover"
    run_prepare 2>&1
  }
  It 'non-empty-dest: an existing non-empty DEST is refused, never overwritten'
    When call non_empty_dest_result
    The status should be failure
    The output should include 'exists and is not empty'
    The path "${DEST}/leftover" should be exist
  End
End

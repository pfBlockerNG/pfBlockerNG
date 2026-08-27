#shellcheck shell=sh
# sparse-clone-ports.sh — the SINGLE 'prepare the FreeBSD-ports tree at REF' step shared by
# BOTH CI (fresh clone on an empty runner dir) and local/repeat builds (reuse a persistent
# clone). One script, two callers; CI is just the fresh-clone special case of the local flow.
#
# Behavioural contracts pinned here:
#   fresh-clone    — DEST absent -> blobless clone of REF; the materialised port Makefile is
#                    the REF variant (USE_GITHUB=yes).
#   reuse-fixes    — DEST is a git clone left on the WRONG branch (devel — whose port installs
#                    an EMPTY pfblockerng_extra.inc stub, the silently-broken .pkg) -> the
#                    script FETCHES + checks out REF. before: NOT the build-input variant;
#                    after: USE_GITHUB=yes — green proves the switch CAUSED the fix (red on the
#                    old script, whose `git clone` into an existing DEST aborts).
#   refuse-foreign — DEST exists but is NOT a git work-tree -> exit nonzero, nothing overwritten.
#
# Why it matters: a build that trusts whatever branch a stale local clone happens to be on
# silently ships a broken .pkg. Sharing this one branch-ensuring step between CI and local
# removes that divergence — the bug that cost a long debugging session.
#
# The real build-pkg-portable.py query interface (--print-port-origin / --print-build-origins)
# is stubbed by a fake python3 on PATH, so the spec needs no real ports tree or dep Makefiles;
# only the git acquisition logic under test runs, against a local file:// remote.

Describe 'sparse-clone-ports.sh'
  SCRIPT="${PFB_ROOT}/scripts/sparse-clone-ports.sh"
  PORT_SUB="net/pfSense-pkg-pfBlockerNG-testing"

  # Build a local git 'remote' with two branches at the port Makefile (devel = stub; the
  # use-github branch = USE_GITHUB=yes) and a fake python3 covering the builder's two query
  # subcommands. file:// + uploadpack.allowFilter so the blobless clone/fetch work locally.
  setup() {
    # Scrub inherited git context. Under the pre-commit hook git exports GIT_DIR /
    # GIT_INDEX_FILE / GIT_WORK_TREE / ... pointing at the REAL repo; without this the
    # fixture's git init/clone AND the script-under-test's `git -C` would hit it, not the
    # file:// fixture. (BeforeEach runs in-context, so the unset reaches the When too.)
    scrub_git_env
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/sparseclone.XXXXXX")"
    REMOTE="${WORK}/remote"
    DEST="${WORK}/dest"
    URL="file://${REMOTE}"
    MAKEFILE="${DEST}/${PORT_SUB}/Makefile"
    mkdir -p "${REMOTE}/${PORT_SUB}"
    (
      cd "$REMOTE" || exit 1
      git_fixture init -q
      git_fixture config user.email ci@example.invalid
      git_fixture config user.name CI
      git_fixture config uploadpack.allowFilter true
      git_fixture checkout -q -b devel
      printf 'PORTNAME=pfSense-pkg-pfBlockerNG-testing\n# classic: pfblockerng_extra.inc from FILESDIR (stub)\n' > "${PORT_SUB}/Makefile"
      git_fixture add -A && git_fixture -c commit.gpgsign=false commit -qm devel
      git_fixture checkout -q -b pfblockerng/use-github
      printf 'PORTNAME=pfSense-pkg-pfBlockerNG-testing\nUSE_GITHUB=yes\n' > "${PORT_SUB}/Makefile"
      git_fixture add -A && git_fixture -c commit.gpgsign=false commit -qm use-github
      git_fixture tag use-github-tag
      git_fixture checkout -q devel
    ) >/dev/null 2>&1
    USE_GITHUB_SHA="$(cd "$REMOTE" && git_fixture rev-parse pfblockerng/use-github)"
    BIN="${WORK}/bin"
    mkdir -p "$BIN"
    cat > "${BIN}/python3" <<'PYEOF'
#!/bin/sh
# stand-in for `python3 build-pkg-portable.py ...` — only the clone script's two query
# subcommands; echo the testing port dir for both, ignore everything else.
for _a in "$@"; do
	case "$_a" in
		--print-port-origin|--print-build-origins) echo "net/pfSense-pkg-pfBlockerNG-testing"; exit 0 ;;
	esac
done
exit 0
PYEOF
    chmod +x "${BIN}/python3"
    PATH="${BIN}:${PATH}"
  }
  cleanup() { rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  # Discard git's incidental clone/checkout chatter and echo only the meaningful outcome, so
  # the assertions pin behaviour (which branch variant materialised) not volatile git wording.
  run_clone() { sh "$SCRIPT" "$URL" pfblockerng/use-github "$DEST" testing 8.3 py311; }
  is_build_input_variant() { grep -q '^USE_GITHUB=yes' "$MAKEFILE"; }

  fresh_result() {
    run_clone >/dev/null 2>&1 || { echo "script-failed=$?"; return 1; }
    if is_build_input_variant; then echo 'variant=usegithub'; else echo 'variant=stub'; fi
  }
  It 'fresh-clone: clones REF into an absent DEST as the build-input variant'
    When call fresh_result
    The status should be success
    The output should equal 'variant=usegithub'
  End

  # issue #1676: `git clone -b REF` only accepts a branch/tag NAME — a bare 40-hex
  # commit SHA fails ("fatal: Remote branch <sha> not found in upstream origin").
  # Fresh clone with a full-SHA REF must still land on that commit.
  run_clone_sha() { sh "$SCRIPT" "$URL" "$USE_GITHUB_SHA" "$DEST" testing 8.3 py311; }

  fresh_sha_result() {
    run_clone_sha >/dev/null 2>&1 || { echo "script-failed=$?"; return 1; }
    if is_build_input_variant; then echo 'variant=usegithub'; else echo 'variant=stub'; fi
    echo "head=$(git_fixture -C "$DEST" rev-parse HEAD)"
  }
  It 'fresh-clone-by-sha: DEST absent, REF a full 40-hex commit SHA -> clones + checks out that commit'
    When call fresh_sha_result
    The status should be success
    The line 1 of output should equal 'variant=usegithub'
    The line 2 of output should equal "head=${USE_GITHUB_SHA}"
  End

  run_clone_tag() { sh "$SCRIPT" "$URL" use-github-tag "$DEST" testing 8.3 py311; }
  fresh_tag_result() {
    run_clone_tag >/dev/null 2>&1 || { echo "script-failed=$?"; return 1; }
    if is_build_input_variant; then echo 'variant=usegithub'; else echo 'variant=stub'; fi
  }
  It 'fresh-clone-by-tag: DEST absent, REF a tag name -> clones + checks out the tag commit'
    When call fresh_tag_result
    The status should be success
    The output should equal 'variant=usegithub'
  End

  # REF is 40 chars but not hex ("z" is outside [0-9a-f]) -> not a SHA -> unchanged
  # branch/tag fast path -> fails exactly as before (no branch named this).
  run_clone_zzz() { sh "$SCRIPT" "$URL" 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz' "$DEST" testing 8.3 py311 2>&1; }
  It 'fresh-clone: a 40-char non-hex REF (40 zs) is not a SHA -> branch path, fails as before'
    When call run_clone_zzz
    The status should be failure
    The output should include 'Remote branch'
  End

  # A short abbreviation of a real commit SHA is not a FULL SHA -> unchanged branch/tag
  # fast path (git's fetch-by-oid needs the full oid, not an abbreviation) -> fails.
  run_clone_short_sha() {
    _short="$(printf '%.7s' "$USE_GITHUB_SHA")"
    sh "$SCRIPT" "$URL" "$_short" "$DEST" testing 8.3 py311 2>&1
  }
  It 'fresh-clone: a short 7-hex SHA abbreviation is not a full SHA -> branch path, fails as before'
    When call run_clone_short_sha
    The status should be failure
    The output should include 'Remote branch'
  End

  # GIVEN an existing clone parked on the wrong branch (devel, the stub), WHEN the shared
  # prepare step runs, THEN the tree ends on REF (use-github). before/after both asserted so
  # green proves the switch caused it — and the old `git clone`-into-existing-DEST path is red.
  reuse_before_after() {
    git_fixture clone -q "$URL" "$DEST" >/dev/null 2>&1            # full clone, checks out devel
    if is_build_input_variant; then echo 'before=usegithub'; else echo 'before=stub'; fi
    run_clone >/dev/null 2>&1 || { echo "script-failed=$?"; return 1; }
    if is_build_input_variant; then echo 'after=usegithub'; else echo 'after=stub'; fi
  }
  It 'reuse-fixes: switches an existing clone off the wrong branch onto REF'
    When call reuse_before_after
    The status should be success
    The line 1 of output should equal 'before=stub'
    The line 2 of output should equal 'after=usegithub'
  End

  # Regression guard: the reuse branch already fetches a full-SHA REF (fetch + FETCH_HEAD,
  # not `-b`) — this must keep working unchanged by the fresh-clone REF-shape guard above.
  reuse_sha_result() {
    git_fixture clone -q "$URL" "$DEST" >/dev/null 2>&1            # full clone, checks out devel
    run_clone_sha >/dev/null 2>&1 || { echo "script-failed=$?"; return 1; }
    echo "head=$(git_fixture -C "$DEST" rev-parse HEAD)"
  }
  It 'reuse-by-sha: an existing work-tree fetches + checks out a full-SHA REF'
    When call reuse_sha_result
    The status should be success
    The output should equal "head=${USE_GITHUB_SHA}"
  End

  refuse_result() {
    mkdir -p "$DEST" && true > "${DEST}/not-a-clone"
    run_clone 2>&1  # merge the refusal (stderr) into output for a single clean assertion
  }
  It 'refuse-foreign: a non-git DEST is refused, not overwritten'
    When call refuse_result
    The status should be failure
    The output should include 'not a git work-tree'
  End

  # issue #2490: an EMPTY pre-created DEST (historically Docker's bind-mount side effect,
  # generally any `mkdir` that beat the first run) carries nothing to protect — it must take
  # the fresh-clone path, not the refuse-foreign one, or a fresh box can never self-bootstrap.
  empty_dir_result() {
    mkdir -p "$DEST"
    run_clone >/dev/null 2>&1 || { echo "script-failed=$?"; return 1; }
    if is_build_input_variant; then echo 'variant=usegithub'; else echo 'variant=stub'; fi
  }
  It 'fresh-clone-into-empty: an empty pre-created DEST clones as if absent (issue #2490)'
    When call empty_dir_result
    The status should be success
    The output should equal 'variant=usegithub'
  End

  # ── REF-shape hostile inputs (issue #1676) ────────────────────────────────
  #
  # None of these REF values may be misclassified as a full 40-hex SHA — each must take
  # the pre-existing `git clone -b REF` fast path unchanged (not the new fetch-by-oid
  # path) and fail exactly as it always did. `git clone -b` prints "Remote branch ...
  # not found" only on that fast path (the fetch-by-oid path, when reachable, prints a
  # different message) — asserting that phrase proves the REF was NOT treated as a SHA.
  run_clone_hostile() { sh "$SCRIPT" "$URL" "$1" "$DEST" testing 8.3 py311 2>&1; }

  It 'empty REF is not a SHA -> branch path (not fetch-by-oid)'
    When call run_clone_hostile ''
    The status should be failure
    The output should include 'Remote branch'
  End

  It '39-hex (one short) REF is not a SHA -> branch path'
    When call run_clone_hostile '0123456789012345678901234567890123456'
    The status should be failure
    The output should include 'Remote branch'
  End

  It '41-hex (one long) REF is not a SHA -> branch path'
    When call run_clone_hostile '012345678901234567890123456789012345678'
    The status should be failure
    The output should include 'Remote branch'
  End

  It '40 chars with one non-hex char is not a SHA -> branch path'
    When call run_clone_hostile '012345678901234567890123456789012345678g'
    The status should be failure
    The output should include 'Remote branch'
  End

  # Decision (pinned): git object ids are lowercase hex only — an UPPERCASE 40-char
  # hex string is deliberately NOT treated as a SHA and takes the branch/tag path.
  It 'UPPERCASE 40-hex REF is not treated as a SHA (git object ids are lowercase) -> branch path'
    When call run_clone_hostile 'ABCDEF0123456789ABCDEF0123456789ABCDEF01'
    The status should be failure
    The output should include 'Remote branch'
  End

  It "REF containing '/' is not a SHA -> branch path"
    When call run_clone_hostile 'origin/main'
    The status should be failure
    The output should include 'Remote branch'
  End

  It 'REF containing whitespace is not a SHA -> branch path'
    When call run_clone_hostile 'abc def'
    The status should be failure
    The output should include 'Remote branch'
  End

  It 'REF with a leading dash is never taken as a git option -> branch path, treated as literal data'
    # Absolute payload path on purpose: a bare 'touch INJECTED' would land in the
    # shellspec CWD, so asserting on ${WORK} would pass even if the option were honoured.
    When call run_clone_hostile "--upload-pack=touch ${WORK}/INJECTED"
    The status should be failure
    The output should include 'Remote branch'
    The path "${WORK}/INJECTED" should not be exist
  End

  It "REF containing '..' is not a SHA -> branch path"
    When call run_clone_hostile 'abc..def'
    The status should be failure
    The output should include 'Remote branch'
  End

  It 'REF containing shell metacharacters is treated as literal data, never interpolated/executed'
    # The $( and backticks are escaped so THIS shell leaves them literal, while ${WORK}
    # expands to an absolute path — so if anything downstream did evaluate the REF, the
    # files below would really appear and these assertions would really fail.
    When call run_clone_hostile "\$(touch ${WORK}/INJECTED); \`touch ${WORK}/INJECTED2\`"
    The status should be failure
    The output should include 'Remote branch'
    The path "${WORK}/INJECTED" should not be exist
    The path "${WORK}/INJECTED2" should not be exist
  End
End

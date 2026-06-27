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
  PORT_SUB="net/pfSense-pkg-pfBlockerNG-devel"

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
      git init -q
      git config user.email ci@example.invalid
      git config user.name CI
      git config uploadpack.allowFilter true
      git checkout -q -b devel
      printf 'PORTNAME=pfBlockerNG-devel\n# classic: pfblockerng_extra.inc from FILESDIR (stub)\n' > "${PORT_SUB}/Makefile"
      git add -A && git -c commit.gpgsign=false commit -qm devel
      git checkout -q -b pfblockerng/use-github
      printf 'PORTNAME=pfBlockerNG-devel\nUSE_GITHUB=yes\n' > "${PORT_SUB}/Makefile"
      git add -A && git -c commit.gpgsign=false commit -qm use-github
      git checkout -q devel
    ) >/dev/null 2>&1
    BIN="${WORK}/bin"
    mkdir -p "$BIN"
    cat > "${BIN}/python3" <<'PYEOF'
#!/bin/sh
# stand-in for `python3 build-pkg-portable.py ...` — only the clone script's two query
# subcommands; echo the devel port dir for both, ignore everything else.
for _a in "$@"; do
	case "$_a" in
		--print-port-origin|--print-build-origins) echo "net/pfSense-pkg-pfBlockerNG-devel"; exit 0 ;;
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
  run_clone() { sh "$SCRIPT" "$URL" pfblockerng/use-github "$DEST" devel 8.3 py311; }
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

  # GIVEN an existing clone parked on the wrong branch (devel, the stub), WHEN the shared
  # prepare step runs, THEN the tree ends on REF (use-github). before/after both asserted so
  # green proves the switch caused it — and the old `git clone`-into-existing-DEST path is red.
  reuse_before_after() {
    git clone -q "$URL" "$DEST" >/dev/null 2>&1            # full clone, checks out devel
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

  refuse_result() {
    mkdir -p "$DEST" && : > "${DEST}/not-a-clone"
    run_clone 2>&1  # merge the refusal (stderr) into output for a single clean assertion
  }
  It 'refuse-foreign: a non-git DEST is refused, not overwritten'
    When call refuse_result
    The status should be failure
    The output should include 'not a git work-tree'
  End
End

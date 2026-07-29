#shellcheck shell=sh
# install_pkg_spec.sh — shellspec suite for scripts/install-pkg.sh
#
# Net-new (nothing covered install-pkg.sh before issue #1806). Pins:
#   (a) SMOKE_DEP_PKGS unset -> single scp+pkg add (current behaviour, regression pin).
#   (b) two dep paths set -> deps scp'd + pkg add'd BEFORE the branch pkg, in order.
#   (c) a dep pkg-add failure -> nonzero exit, branch pkg never installed (not even copied).
#
# Hermetic: stubs ssh + scp via a PATH-prepended fake bin dir (same pattern as
# run_smoke_spec.sh's fake python). The ssh stub answers the unbound-control
# readiness poll immediately (exit 0) so the script never enters the sleep loop,
# and fails any `pkg add` whose wrapped remote command matches $FAIL_PKG_ADD_MATCH
# (unset -> never matches, i.e. every pkg add succeeds). The scp stub just logs
# its source file. Both stubs record the FULL invocation so ORDER is assertable.

Describe 'install-pkg.sh'
  SCRIPT="${PFB_ROOT}/scripts/install-pkg.sh"

  setup() {
    scrub_git_env
    unset SMOKE_DEP_PKGS FAIL_PKG_ADD_MATCH
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/instpkgspec.XXXXXX")"
    FAKE_BIN="${WORK}/bin"
    mkdir -p "$FAKE_BIN"
    SSH_LOG="${WORK}/ssh.log"
    SCP_LOG="${WORK}/scp.log"
    true > "$SSH_LOG"
    true > "$SCP_LOG"

    PKGFILE="${WORK}/pfBlockerNG-devel.pkg"
    DEP1="${WORK}/py311-charset-normalizer-1.pkg"
    DEP2="${WORK}/py311-idna-2.pkg"
    true > "$PKGFILE"
    true > "$DEP1"
    true > "$DEP2"

    # Fake ssh: records the LAST arg (the wrapped `/bin/sh -c '<remote cmd>'`
    # string install-pkg.sh's ssh_t() builds) to $SSH_LOG, one per line.
    # unbound-control status -> always "ready" (exit 0), so the readiness loop
    # never sleeps. A pkg-add line matching $FAIL_PKG_ADD_MATCH -> exit 1.
    cat > "${FAKE_BIN}/ssh" << 'SSHEOF'
#!/bin/sh
for _a in "$@"; do :; done
printf '%s\n' "$_a" >> "$SSH_LOG"
case "$_a" in
    *unbound-control*) exit 0 ;;
esac
case "$_a" in
    *"${FAIL_PKG_ADD_MATCH:-__pfb_never_match__}"*) exit 1 ;;
esac
exit 0
SSHEOF
    chmod +x "${FAKE_BIN}/ssh"

    # Fake scp: records its SRC (second-to-last positional arg; last is
    # "$SSH_TARGET:$REMOTE") to $SCP_LOG, one per line.
    cat > "${FAKE_BIN}/scp" << 'SCPEOF'
#!/bin/sh
_src=""
_prev=""
for _a in "$@"; do
    _src="$_prev"
    _prev="$_a"
done
printf '%s\n' "$_src" >> "$SCP_LOG"
exit 0
SCPEOF
    chmod +x "${FAKE_BIN}/scp"

    PATH="${FAKE_BIN}:${PATH}"
    export PATH WORK FAKE_BIN SSH_LOG SCP_LOG PKGFILE DEP1 DEP2
  }

  teardown() { rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach 'teardown'

  # Count lines in $SSH_LOG whose wrapped remote command contains `pkg add`.
  pkg_add_count() { grep -c 'pkg add' "$SSH_LOG"; }

  It 'SMOKE_DEP_PKGS unset -> exactly one scp + one pkg add (regression pin)'
    When run sh "$SCRIPT" root@dummy --pkg "$PKGFILE" --port 2222
    The status should be success
    The contents of file "$SCP_LOG" should equal "$PKGFILE"
    The result of function pkg_add_count should equal 1
    The contents of file "$SSH_LOG" should include "$(basename "$PKGFILE")"
  End

  It 'two SMOKE_DEP_PKGS entries: deps scp'"'"'d + pkg add'"'"'d before the branch pkg, in order'
    SMOKE_DEP_PKGS="${DEP1} ${DEP2}"
    export SMOKE_DEP_PKGS
    When run sh "$SCRIPT" root@dummy --pkg "$PKGFILE" --port 2222
    The status should be success
    # scp order: dep1, dep2, branch pkg -- exactly 3 copies, that order.
    The line 1 of contents of file "$SCP_LOG" should equal "$DEP1"
    The line 2 of contents of file "$SCP_LOG" should equal "$DEP2"
    The line 3 of contents of file "$SCP_LOG" should equal "$PKGFILE"
    The result of function pkg_add_count should equal 3
    # pkg-add order in the raw ssh log mirrors the scp order (dep1, dep2, branch);
    # the only other ssh_t call (unbound-control) always comes after all three.
    The line 1 of contents of file "$SSH_LOG" should include "$(basename "$DEP1")"
    The line 2 of contents of file "$SSH_LOG" should include "$(basename "$DEP2")"
    The line 3 of contents of file "$SSH_LOG" should include "$(basename "$PKGFILE")"
  End

  It 'a dep pkg-add failure aborts before the branch pkg is even copied'
    SMOKE_DEP_PKGS="${DEP1} ${DEP2}"
    FAIL_PKG_ADD_MATCH="$(basename "$DEP1")"
    export SMOKE_DEP_PKGS FAIL_PKG_ADD_MATCH
    When run sh "$SCRIPT" root@dummy --pkg "$PKGFILE" --port 2222
    The status should be failure
    # dep1 was copied (its pkg add is what fails); dep2 and the branch pkg never are.
    The contents of file "$SCP_LOG" should include "$DEP1"
    The contents of file "$SCP_LOG" should not include "$DEP2"
    The contents of file "$SCP_LOG" should not include "$PKGFILE"
    The result of function pkg_add_count should equal 1
  End
End

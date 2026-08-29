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
    unset SMOKE_DEP_PKGS SMOKE_ABI FAIL_PKG_ADD_MATCH EXEC_REMOTE_PKG_CONTEXT PFB_FAKE_PS_OUTPUT POSTINSTALL_FAIL
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
if [ "${EXEC_REMOTE_PKG_CONTEXT:-0}" -eq 1 ]; then
    case "$_a" in
        *PFB_PKG_CONTEXT*) eval "/bin/sh -c $_a"; exit $? ;;
    esac
fi
case "$_a" in
    *unbound-control*) exit 0 ;;
esac
# Lock mode (issue #2237): while $WORK/lock.remaining holds N > 0, each pkg add
# decrements it and fails with the REAL guest lock signature (observed verbatim
# in run 31229687348) -- the transient/persistent lock cases drive this.
case "$_a" in
    *"pkg add"* | *"pkg -o ABI="*)
        if [ -f "${WORK}/lock.remaining" ]; then
            _n=$(cat "${WORK}/lock.remaining")
            if [ "$_n" -gt 0 ]; then
                echo $((_n - 1)) > "${WORK}/lock.remaining"
                echo "pkg: Package database is busy while closing!" >&2
                echo "pkg: Cannot get an exclusive lock on a database, it is locked by another process" >&2
                exit 1
            fi
        fi
        ;;
esac
# pkg(8) can exit 0 after POST-INSTALL fails (files already extracted).
# The stub reproduces that: rc=0 plus the pkg: * script failed line.
case "$_a" in
    *"pkg add"*)
        if [ -n "${POSTINSTALL_FAIL:-}" ]; then
            case "$POSTINSTALL_FAIL" in
                glued) printf '%s\n' 'thrown</pre>pkg: POST-INSTALL script failed' ;;
                noise) printf '%s\n' 'the POST-INSTALL script failed to mention foo' ;;
                *) printf '%s\n' 'pkg: POST-INSTALL script failed' ;;
            esac
            exit 0
        fi
        ;;
esac
case "$_a" in
    *"${FAIL_PKG_ADD_MATCH:-__pfb_never_match__}"*) exit 1 ;;
esac
exit 0
SSHEOF
    chmod +x "${FAKE_BIN}/ssh"

    cat > "${FAKE_BIN}/pkg" <<'PKGEOF'
#!/bin/sh
case "$1" in
    config) printf '%s\n' 'FreeBSD:15:amd64' ;;
    add) printf 'Installing %s...\n' "${2##*/}" ;;
esac
PKGEOF
    chmod +x "${FAKE_BIN}/pkg"

    cat > "${FAKE_BIN}/ps" <<'PSEOF'
#!/bin/sh
[ -z "${PFB_FAKE_PS_OUTPUT:-}" ] || printf '%s\n' "$PFB_FAKE_PS_OUTPUT"
PSEOF
    chmod +x "${FAKE_BIN}/ps"

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

  It 'SMOKE_ABI set -> pkg add forces that ABI quoted (issue #2730)'
    SMOKE_ABI=FreeBSD:15:amd64
    export SMOKE_ABI
    When run sh "$SCRIPT" root@dummy --pkg "$PKGFILE" --port 2222
    The status should be success
    The stdout should be present
    # ssh_t single-quotes the remote blob, so inner ABI quotes log as '\''.
    The line 1 of contents of file "$SSH_LOG" should include "pkg -o ABI='\''FreeBSD:15:amd64'\'' add"
  End

  It 'SMOKE_ABI with a single quote is dash-escaped (issue #2730)'
    SMOKE_ABI="FreeBSD:15:am'd64"
    export SMOKE_ABI
    When run sh "$SCRIPT" root@dummy --pkg "$PKGFILE" --port 2222
    The status should be success
    The stdout should be present
    # sed-escape then ssh_t: an ABI quote becomes '\''\'\'''\'' in SSH_LOG.
    The line 1 of contents of file "$SSH_LOG" should include "pkg -o ABI='\''FreeBSD:15:am'\''\\'\\'''\\''d64'\'' add"
  End

  It 'SMOKE_ABI unset -> pkg add has no -o ABI (issue #2730)'
    When run sh "$SCRIPT" root@dummy --pkg "$PKGFILE" --port 2222
    The status should be success
    The stdout should be present
    The line 1 of contents of file "$SSH_LOG" should include 'pkg add'
    The line 1 of contents of file "$SSH_LOG" should not include 'pkg -o ABI='
  End

  It 'SMOKE_ABI empty -> treated as unset (issue #2730)'
    SMOKE_ABI=
    export SMOKE_ABI
    When run sh "$SCRIPT" root@dummy --pkg "$PKGFILE" --port 2222
    The status should be success
    The stdout should be present
    The line 1 of contents of file "$SSH_LOG" should include 'pkg add'
    The line 1 of contents of file "$SSH_LOG" should not include 'pkg -o ABI='
  End

  It 'logs pkg identity in the same remote shell immediately before pkg add'
    When run sh "$SCRIPT" root@dummy --pkg "$PKGFILE" --port 2222
    The status should be success
    The stdout should be present
    The line 1 of contents of file "$SSH_LOG" should include 'PFB_PKG_CONTEXT'
    The line 1 of contents of file "$SSH_LOG" should include '/usr/local/sbin/pkg config ABI'
    The line 1 of contents of file "$SSH_LOG" should include "awk"
    The line 1 of contents of file "$SSH_LOG" should include 'pkg-static'
    The line 1 of contents of file "$SSH_LOG" should not include 'grep -E'
    The line 1 of contents of file "$SSH_LOG" should include 'pkg add'
  End

  It 'terminates an empty boot-process list before pkg output'
    EXEC_REMOTE_PKG_CONTEXT=1
    export EXEC_REMOTE_PKG_CONTEXT
    When run sh "$SCRIPT" root@dummy --pkg "$PKGFILE" --port 2222
    The status should be success
    The stdout should include 'PFB_PKG_CONTEXT boot_pkg_processes=none'
    The stdout should include 'none
Installing pfBlockerNG-devel.pkg...'
  End

  It 'logs every boot pkg process class and excludes observer decoys'
    EXEC_REMOTE_PKG_CONTEXT=1
    PFB_FAKE_PS_OUTPUT='42 sh /bin/sh /etc/rc.update_pkg_metadata now
43 sh /bin/sh /usr/local/sbin/pfSense-upgrade -uf
44 sh /bin/sh /usr/local/libexec/pfSense-upgrade -uf
45 lockf /usr/bin/lockf -s -t 5 /tmp/pfSense-upgrade.lock /usr/local/libexec/pfSense-upgrade -uf
46 pkg pkg add /tmp/package.pkg
47 pkg-static /usr/local/sbin/pkg-static rquery %v pkg
98 sh /bin/sh -c printf /bin/sh /etc/rc.update_pkg_metadata now
99 awk awk /bin/sh /usr/local/sbin/pfSense-upgrade'
    export EXEC_REMOTE_PKG_CONTEXT PFB_FAKE_PS_OUTPUT
    When run sh "$SCRIPT" root@dummy --pkg "$PKGFILE" --port 2222
    The status should be success
    The stdout should include 'PFB_PKG_CONTEXT boot_pkg_processes=42 sh /bin/sh /etc/rc.update_pkg_metadata now'
    The stdout should include '43 sh /bin/sh /usr/local/sbin/pfSense-upgrade -uf'
    The stdout should include '44 sh /bin/sh /usr/local/libexec/pfSense-upgrade -uf'
    The stdout should include '45 lockf /usr/bin/lockf -s -t 5 /tmp/pfSense-upgrade.lock'
    The stdout should include '46 pkg pkg add /tmp/package.pkg'
    The stdout should include '47 pkg-static /usr/local/sbin/pkg-static rquery %v pkg'
    The stdout should not include '98 sh /bin/sh -c'
    The stdout should not include '99 awk awk'
    The stdout should not include 'boot_pkg_processes=none'
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

  # ── issue #2237: the guest pkg database can be locked by first-boot pkg activity ── #

  It 'retries through a transient guest pkg-database lock and installs'
    # The defect: one boot-time lock collision failed the whole deploy (run
    # 31229687348). Two locked attempts then a free database must succeed.
    echo 2 > "${WORK}/lock.remaining"
    PFB_INSTALL_PKG_RETRY_DELAY=0
    export PFB_INSTALL_PKG_RETRY_DELAY
    When run sh "$SCRIPT" root@dummy --pkg "$PKGFILE" --port 2222
    The status should be success
    # 2 locked attempts + the succeeding one, all for the same branch pkg.
    The result of function pkg_add_count should equal 3
    The stderr should include 'retry 1/'
    The stderr should include 'retry 2/'
  End

  It 'gives up loudly after the bounded retry cap when the lock never clears'
    echo 99 > "${WORK}/lock.remaining"
    PFB_INSTALL_PKG_RETRY_DELAY=0
    PFB_INSTALL_PKG_RETRY_MAX=3
    export PFB_INSTALL_PKG_RETRY_DELAY PFB_INSTALL_PKG_RETRY_MAX
    When run sh "$SCRIPT" root@dummy --pkg "$PKGFILE" --port 2222
    The status should be failure
    The result of function pkg_add_count should equal 3
    # The give-up is DISTINCT from an ordinary pkg-add failure and names the cap.
    The stderr should include 'still locked after 3 attempts'
    The stderr should include 'issue #2237'
    The stdout should include 'Cannot get an exclusive lock'
  End

  It 'rejects a non-integer retry cap before touching the guest'
    # A bad cap would make the -ge comparison silently false and the retry
    # loop unbounded — refuse it up front, before any scp/ssh runs.
    PFB_INSTALL_PKG_RETRY_MAX=abc
    export PFB_INSTALL_PKG_RETRY_MAX
    When run sh "$SCRIPT" root@dummy --pkg "$PKGFILE" --port 2222
    The status should be failure
    The stderr should include 'PFB_INSTALL_PKG_RETRY_MAX must be a positive integer'
    The contents of file "$SCP_LOG" should equal ''
  End

  It 'rejects a non-integer retry delay before touching the guest'
    PFB_INSTALL_PKG_RETRY_DELAY=1.5
    export PFB_INSTALL_PKG_RETRY_DELAY
    When run sh "$SCRIPT" root@dummy --pkg "$PKGFILE" --port 2222
    The status should be failure
    The stderr should include 'PFB_INSTALL_PKG_RETRY_DELAY must be a non-negative integer'
    The contents of file "$SCP_LOG" should equal ''
  End

  It 'honours the minimum cap of one attempt'
    echo 99 > "${WORK}/lock.remaining"
    PFB_INSTALL_PKG_RETRY_DELAY=0
    PFB_INSTALL_PKG_RETRY_MAX=1
    export PFB_INSTALL_PKG_RETRY_DELAY PFB_INSTALL_PKG_RETRY_MAX
    When run sh "$SCRIPT" root@dummy --pkg "$PKGFILE" --port 2222
    The status should be failure
    The result of function pkg_add_count should equal 1
    The stderr should include 'still locked after 1 attempts'
  End

  It 'never retries a non-lock pkg-add failure'
    FAIL_PKG_ADD_MATCH="$(basename "$PKGFILE")"
    PFB_INSTALL_PKG_RETRY_DELAY=0
    export FAIL_PKG_ADD_MATCH PFB_INSTALL_PKG_RETRY_DELAY
    When run sh "$SCRIPT" root@dummy --pkg "$PKGFILE" --port 2222
    The status should be failure
    # A missing-dependency-style failure is not a lock: exactly one attempt.
    The result of function pkg_add_count should equal 1
  End

  # pkg(8) can exit 0 after POST-INSTALL still failed (issue #2575 class).
  # 20260827T005125Z-smoke shard-0.log:144-147 printed "Installed" and
  # helpers.deploy treated rc=0 as PASSED. Fail closed; do not print Installed.

  It 'fails closed when pkg add exits 0 after POST-INSTALL script failed'
    POSTINSTALL_FAIL=1
    export POSTINSTALL_FAIL
    When run sh "$SCRIPT" root@dummy --pkg "$PKGFILE" --port 2222
    The status should be failure
    The stdout should include 'pkg: POST-INSTALL script failed'
    The stdout should not include '==> Installed'
    The stderr should include 'package-script failure'
    The result of function pkg_add_count should equal 1
  End

  It 'fails closed when POST-INSTALL failed is glued to hook stdout'
    POSTINSTALL_FAIL=glued
    export POSTINSTALL_FAIL
    When run sh "$SCRIPT" root@dummy --pkg "$PKGFILE" --port 2222
    The status should be failure
    The stdout should include 'pkg: POST-INSTALL script failed'
    The stdout should not include '==> Installed'
    The result of function pkg_add_count should equal 1
  End

  It 'does not treat a coincidental script-failed substring as a hook failure'
    POSTINSTALL_FAIL=noise
    export POSTINSTALL_FAIL
    When run sh "$SCRIPT" root@dummy --pkg "$PKGFILE" --port 2222
    The status should be success
    The stdout should include 'the POST-INSTALL script failed to mention foo'
    The stdout should include '==> Installed'
  End
End

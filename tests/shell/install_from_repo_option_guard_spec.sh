#!/bin/sh
#shellcheck shell=sh
# install_from_repo_option_guard_spec.sh — issue #3279 finding 1:
# install-from-repo.sh's --port/--ssh-key without a trailing value must fail
# with a clear usage diagnostic instead of dash's raw "shift: can't shift
# that many" — and must fail BEFORE any ssh/rsync call reaches the network.
# Mirrors build-leg.sh's existing "${1?...}"-style missing-value guard.
#
# TOPOLOGY: `ssh` and `rsync` are shims that would answer any call; their
# invocation log staying empty on the missing-value cases is itself the
# "fails before any network call" proof.

Describe 'install-from-repo.sh missing option value guard (issue #3279)'
  setup() {
    scrub_git_env
    unset SMOKE_PHP_VERSION SMOKE_PY_FLAVOR
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/optguard.XXXXXX")"
    FAKE_ROOT="${WORK}/repo"
    LOG="${WORK}/calls.log"
    mkdir -p "${FAKE_ROOT}/scripts" "${FAKE_ROOT}/src/usr/local/share/pfSense-pkg-pfBlockerNG" "${FAKE_ROOT}/src/etc"
    cp "${PFB_ROOT}/scripts/install-from-repo.sh" "${FAKE_ROOT}/scripts/"
    cp "${PFB_ROOT}/src/usr/local/share/pfSense-pkg-pfBlockerNG/info.xml" \
      "${FAKE_ROOT}/src/usr/local/share/pfSense-pkg-pfBlockerNG/info.xml"

    # One BUILD row for the box's major, so a run that gets past option
    # parsing resolves py_flavor without touching the network for it.
    printf '#!/bin/sh\nprintf %%s\\\\n '"'"'[{"freebsd_major":"15","extra_pkgs":[],"py_flavor":"py311","php_version":"8.3"}]'"'"'\n' \
      > "${FAKE_ROOT}/scripts/read-version-matrix.sh"
    chmod +x "${FAKE_ROOT}/scripts/read-version-matrix.sh"

    mkdir -p "${WORK}/bin"
    cat > "${WORK}/bin/ssh" <<'STUBEOF'
#!/bin/sh
printf 'ssh: %s\n' "$*" >> "$GUARD_LOG"
case "$*" in
    *"pkg config ABI"*) printf 'FreeBSD:15:amd64\n' ;;
    *"-sqlite3"*)       printf 'py311-sqlite3\n' ;;
esac
exit 0
STUBEOF
    cat > "${WORK}/bin/rsync" <<'STUBEOF'
#!/bin/sh
printf 'rsync: %s\n' "$*" >> "$GUARD_LOG"
exit 0
STUBEOF
    chmod +x "${WORK}/bin/ssh" "${WORK}/bin/rsync"
    GUARD_LOG="$LOG"
    export GUARD_LOG
    PATH="${WORK}/bin:${PATH}"
    export PATH
  }

  teardown() { rm -rf "$WORK"; }

  BeforeEach 'setup'
  AfterEach 'teardown'

  calls() { cat "$LOG" 2>/dev/null; }

  install() { sh "${FAKE_ROOT}/scripts/install-from-repo.sh" "$@"; }

  It 'rejects a trailing --port with no value, before any ssh/rsync call'
    When run install root@target --port
    The status should not equal 0
    The stderr should include '--port requires an argument'
    The path "$LOG" should not be exist
  End

  It 'rejects a trailing --ssh-key with no value, before any ssh/rsync call'
    When run install root@target --ssh-key
    The status should not equal 0
    The stderr should include '--ssh-key requires an argument'
    The path "$LOG" should not be exist
  End

  It 'still accepts an explicit --ssh-key value and threads it into the ssh/rsync calls'
    When run install root@target --ssh-key /tmp/does-not-need-to-exist
    The status should equal 0
    The result of function calls should include '-i /tmp/does-not-need-to-exist'
  End
End

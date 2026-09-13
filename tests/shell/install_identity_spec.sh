#!/bin/sh
#shellcheck shell=sh
# install_identity_spec.sh — issue #3277: deploy.sh and install-from-repo.sh
# must register the CANONICAL package identity. Since #2148 every channel
# publishes `pfSense-pkg-pfBlockerNG` and the channel comes from the installed
# repo, never from a name suffix; `-devel` is a retired port. The port renders
# `info.xml <name>` as the prefix-stripped `pfBlockerNG` (the full name makes
# rc.packages abort — tests/smoke/test_install_hook.py) while the share
# directory and the rc.packages argument carry the full canonical name.
#
# TOPOLOGY: `ssh` and `rsync` are shims that log their arguments; the rsync shim
# copies the templated info.xml aside so its <name> can be read back. Nothing
# reaches a box.

Describe 'canonical package identity (issue #3277)'
  setup() {
    scrub_git_env
    unset SMOKE_PHP_VERSION SMOKE_PY_FLAVOR
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/identspec.XXXXXX")"
    FAKE_ROOT="${WORK}/repo"
    LOG="${WORK}/calls.log"
    CAPTURE="${WORK}/info.xml"
    mkdir -p "${FAKE_ROOT}/scripts" "${FAKE_ROOT}/src/usr/local/share/pfSense-pkg-pfBlockerNG" "${FAKE_ROOT}/src/etc"
    cp "${PFB_ROOT}/scripts/deploy.sh" "${PFB_ROOT}/scripts/install-from-repo.sh" "${FAKE_ROOT}/scripts/"
    cp "${PFB_ROOT}/src/usr/local/share/pfSense-pkg-pfBlockerNG/info.xml" \
      "${FAKE_ROOT}/src/usr/local/share/pfSense-pkg-pfBlockerNG/info.xml"

    # One BUILD row for the box's major, so install-from-repo.sh resolves py_flavor.
    printf '#!/bin/sh\nprintf %%s\\\\n '"'"'[{"freebsd_major":"15","extra_pkgs":[],"py_flavor":"py311","php_version":"8.3"}]'"'"'\n' \
      > "${FAKE_ROOT}/scripts/read-version-matrix.sh"
    chmod +x "${FAKE_ROOT}/scripts/read-version-matrix.sh"

    mkdir -p "${WORK}/bin"
    cat > "${WORK}/bin/ssh" <<'STUBEOF'
#!/bin/sh
# Log the remote command (last argument) and answer the probes the scripts make.
cmd=""
for arg in "$@"; do cmd="$arg"; done
printf 'ssh: %s\n' "$*" >> "$IDENT_LOG"
case "$cmd" in
    *"pkg config ABI"*) printf 'FreeBSD:15:amd64\n' ;;
    *"-sqlite3"*)       printf 'py311-sqlite3\n' ;;
esac
exit 0
STUBEOF
    cat > "${WORK}/bin/rsync" <<'STUBEOF'
#!/bin/sh
# Log the transfer; keep a copy of the templated info.xml for the assertions.
printf 'rsync: %s\n' "$*" >> "$IDENT_LOG"
src=""
for arg in "$@"; do
    case "$arg" in
        -*) ;;
        *.info.xml.tmp) src="$arg" ;;
    esac
done
[ -n "$src" ] && cp "$src" "$IDENT_CAPTURE"
exit 0
STUBEOF
    chmod +x "${WORK}/bin/ssh" "${WORK}/bin/rsync"
    IDENT_LOG="$LOG" IDENT_CAPTURE="$CAPTURE"
    export IDENT_LOG IDENT_CAPTURE
    PATH="${WORK}/bin:${PATH}"
    export PATH
  }

  teardown() { rm -rf "$WORK"; }

  BeforeEach 'setup'
  AfterEach 'teardown'

  calls() { cat "$LOG"; }
  info_xml() { cat "$CAPTURE"; }

  Describe 'install-from-repo.sh'
    It 'registers the canonical identity: full name for the share dir and rc.packages, short <name>'
      When run sh "${FAKE_ROOT}/scripts/install-from-repo.sh" root@target --port 2222
      The status should equal 0
      The stdout should include 'Done. pfBlockerNG'
      The result of function calls should include 'mkdir -p /usr/local/share/pfSense-pkg-pfBlockerNG'
      The result of function calls should include '/etc/rc.packages pfSense-pkg-pfBlockerNG POST-INSTALL'
      The result of function calls should include 'root@target:/usr/local/share/pfSense-pkg-pfBlockerNG/info.xml'
      The result of function calls should not include 'pfBlockerNG-devel'
      The result of function info_xml should include '<name>pfBlockerNG</name>'
      The result of function info_xml should not include '<name>pfSense-pkg-'
    End

    It 'rejects --channel: the package name is not a channel any more'
      When run sh "${FAKE_ROOT}/scripts/install-from-repo.sh" root@target --channel devel
      The status should equal 1
      The stderr should include 'Unknown option: --channel'
      The path "$LOG" should not be exist
    End
  End

  Describe 'deploy.sh'
    It 'writes the short <name> into the canonical share directory'
      When run sh "${FAKE_ROOT}/scripts/deploy.sh" root@target
      The status should equal 0
      The stdout should include 'Done. pfBlockerNG'
      The result of function calls should include 'mkdir -p /usr/local/share/pfSense-pkg-pfBlockerNG'
      The result of function calls should include 'root@target:/usr/local/share/pfSense-pkg-pfBlockerNG/info.xml'
      The result of function calls should not include 'pfBlockerNG-devel'
      The result of function info_xml should include '<name>pfBlockerNG</name>'
      The result of function info_xml should not include '<name>pfSense-pkg-'
    End

    It 'rejects --channel: the package name is not a channel any more'
      When run sh "${FAKE_ROOT}/scripts/deploy.sh" root@target --channel stable
      The status should equal 1
      The stderr should include 'Unknown option: --channel'
      The path "$LOG" should not be exist
    End
  End
End

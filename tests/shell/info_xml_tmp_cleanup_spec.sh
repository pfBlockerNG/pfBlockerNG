#!/bin/sh
#shellcheck shell=sh
# info_xml_tmp_cleanup_spec.sh — issue #3279 finding 2: deploy.sh and
# install-from-repo.sh must not leave a stray info.xml temp file behind
# after a later step fails. Both scripts now render the templated info.xml
# into a mktemp-created file with an EXIT/INT/TERM trap, so a `set -e`
# abort after the render still reaps it, TMPDIR spaces included, and a
# failing mktemp itself aborts before any ssh/rsync call for info.xml runs.
#
# TOPOLOGY: `ssh` and `rsync` are shims. The first Context force-fails the
# ssh `mkdir -p .../share/...` call that immediately follows the info.xml
# render (opt-in via a flag file, so the second Context can leave ssh/rsync
# succeeding and isolate mktemp's own failure) — checked both at the fixed
# checkout-local `.info.xml.tmp` path the pre-fix scripts wrote (issue
# #3279's own reproduction) and across TMPDIR. The second Context replaces
# `mktemp` itself with a stub that always fails, simulating an
# unwritable/full TMPDIR, with ssh/rsync left free to succeed so a
# pre-fix script (which never calls mktemp) runs to completion instead of
# failing closed.

Describe 'info.xml temp file lifecycle (issue #3279)'
  setup() {
    scrub_git_env
    unset SMOKE_PHP_VERSION SMOKE_PY_FLAVOR
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/infoxmltmp.XXXXXX")"
    FAKE_ROOT="${WORK}/repo"
    LOG="${WORK}/calls.log"
    TMPHOME="${WORK}/tmp home"
    mkdir -p "${FAKE_ROOT}/scripts" "${FAKE_ROOT}/src/usr/local/share/pfSense-pkg-pfBlockerNG" \
      "${FAKE_ROOT}/src/etc" "${TMPHOME}"
    cp "${PFB_ROOT}/scripts/deploy.sh" "${PFB_ROOT}/scripts/install-from-repo.sh" "${FAKE_ROOT}/scripts/"
    cp "${PFB_ROOT}/src/usr/local/share/pfSense-pkg-pfBlockerNG/info.xml" \
      "${FAKE_ROOT}/src/usr/local/share/pfSense-pkg-pfBlockerNG/info.xml"

    printf '#!/bin/sh\nprintf %%s\\\\n '"'"'[{"freebsd_major":"15","extra_pkgs":[],"py_flavor":"py311","php_version":"8.3"}]'"'"'\n' \
      > "${FAKE_ROOT}/scripts/read-version-matrix.sh"
    chmod +x "${FAKE_ROOT}/scripts/read-version-matrix.sh"

    mkdir -p "${WORK}/bin"
    cat > "${WORK}/bin/ssh" <<'STUBEOF'
#!/bin/sh
printf 'ssh: %s\n' "$*" >> "$CLEANUP_LOG"
case "$*" in
    *"mkdir -p"*"share"*)
        [ ! -f "$CLEANUP_FAIL_MKDIR" ] || exit 1
        [ -z "${CLEANUP_SEND_SIGNAL:-}" ] || kill "-${CLEANUP_SEND_SIGNAL}" "$PPID"
        ;;
esac
case "$*" in
    *"pkg config ABI"*) printf 'FreeBSD:15:amd64\n' ;;
    *"-sqlite3"*)       printf 'py311-sqlite3\n' ;;
esac
exit 0
STUBEOF
    cat > "${WORK}/bin/rsync" <<'STUBEOF'
#!/bin/sh
printf 'rsync: %s\n' "$*" >> "$CLEANUP_LOG"
prev=""
for arg in "$@"; do
    case "$arg" in
        -*) ;;
        */info.xml) [ -z "$CLEANUP_MODE_CAPTURE" ] || ls -ld "$prev" | cut -c1-10 > "$CLEANUP_MODE_CAPTURE" ;;
        *) prev="$arg" ;;
    esac
done
exit 0
STUBEOF
    chmod +x "${WORK}/bin/ssh" "${WORK}/bin/rsync"
    CLEANUP_LOG="$LOG"
    CLEANUP_FAIL_MKDIR="${WORK}/fail-mkdir"
    CLEANUP_MODE_CAPTURE="${WORK}/info-mode.txt"
    export CLEANUP_LOG CLEANUP_FAIL_MKDIR CLEANUP_MODE_CAPTURE
    PATH="${WORK}/bin:${PATH}"
    export PATH
  }

  teardown() { rm -rf "$WORK"; }

  BeforeEach 'setup'
  AfterEach 'teardown'

  calls() { cat "$LOG" 2>/dev/null; }

  leftover_tmp_count() {
    find "$TMPHOME" -type f | wc -l | tr -d ' '
  }

  Context 'when a later ssh/rsync call fails'
    force_ssh_mkdir_failure() { true > "$CLEANUP_FAIL_MKDIR"; }
    BeforeEach 'force_ssh_mkdir_failure'

    It 'install-from-repo.sh: leaves no temp file in the checkout or in TMPDIR (spaces included)'
      When run env TMPDIR="$TMPHOME" sh "${FAKE_ROOT}/scripts/install-from-repo.sh" root@target --port 2222
      The status should not equal 0
      The path "${FAKE_ROOT}/.info.xml.tmp" should not be exist
      The result of function leftover_tmp_count should equal "0"
    End

    It 'deploy.sh: leaves no temp file in the checkout or in TMPDIR (spaces included)'
      When run env TMPDIR="$TMPHOME" sh "${FAKE_ROOT}/scripts/deploy.sh" root@target
      The status should not equal 0
      The path "${FAKE_ROOT}/.info.xml.tmp" should not be exist
      The result of function leftover_tmp_count should equal "0"
    End
  End

  Context 'when mktemp itself fails (e.g. a full/unwritable TMPDIR)'
    add_failing_mktemp_stub() {
      cat > "${WORK}/bin/mktemp" <<'STUBEOF'
#!/bin/sh
echo "mktemp: no space left on device" >&2
exit 1
STUBEOF
      chmod +x "${WORK}/bin/mktemp"
    }
    BeforeEach 'add_failing_mktemp_stub'

    It 'install-from-repo.sh: aborts before any info.xml ssh/rsync call'
      When run sh "${FAKE_ROOT}/scripts/install-from-repo.sh" root@target --port 2222
      The status should not equal 0
      The result of function calls should not include 'info.xml'
    End

    It 'deploy.sh: aborts before any info.xml ssh/rsync call'
      When run sh "${FAKE_ROOT}/scripts/deploy.sh" root@target
      The status should not equal 0
      The result of function calls should not include 'info.xml'
    End
  End

  info_mode() { cat "$CLEANUP_MODE_CAPTURE" 2>/dev/null; }

  It 'install-from-repo.sh: uploads info.xml with mode 0644 despite mktemp defaulting to 0600'
    When run sh "${FAKE_ROOT}/scripts/install-from-repo.sh" root@target --port 2222
    The status should equal 0
    The result of function info_mode should equal "-rw-r--r--"
  End

  Context 'when a signal arrives during the network step'
    send_sigint() { CLEANUP_SEND_SIGNAL=INT; export CLEANUP_SEND_SIGNAL; }
    BeforeEach 'send_sigint'

    It 'install-from-repo.sh: exits 130 and does not continue past cleanup'
      When run sh "${FAKE_ROOT}/scripts/install-from-repo.sh" root@target --port 2222
      The status should equal 130
      The result of function calls should not include 'info.xml'
    End

    It 'deploy.sh: exits 130 and does not continue past cleanup'
      When run sh "${FAKE_ROOT}/scripts/deploy.sh" root@target
      The status should equal 130
      The result of function calls should not include 'info.xml'
    End
  End
End

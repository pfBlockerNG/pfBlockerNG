#shellcheck shell=sh
# beta_repo_probe_spec.sh — shellspec suite for scripts/beta-repo-probe.sh
# (issue #1820: the version tracker's public-beta detection).
#
# Pins the verdict contract: yes (+ repo-name capture, annotations stripped),
# no, and the unknown degradations (Plus identity absent — with NO boot attempt,
# oras pull failure, guest SSH never up). Hermetic: stubs oras, ssh, and the
# boot helper — no image pulls, no VM boots.

Describe 'beta-repo-probe.sh'
  SCRIPT="${PFB_ROOT}/scripts/beta-repo-probe.sh"

  setup() {
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/betaprobe.XXXXXX")"
    BIN="${WORK}/bin"; mkdir -p "$BIN"
    BOOT_ARGV="${WORK}/boot-argv"
    SSH_LOG="${WORK}/ssh-log"
    KEY="${WORK}/key"; : > "$KEY"

    # Stub oras: succeed and drop a qcow2 into the --output dir (unless
    # ORAS_FAIL=1). Mirrors `oras pull REF --output DIR`.
    cat > "${BIN}/oras" << 'OEOF'
#!/bin/sh
[ "${ORAS_FAIL:-0}" = "1" ] && exit 1
_out=""
while [ "$#" -gt 0 ]; do
  [ "$1" = "--output" ] && _out="$2"
  shift
done
[ -n "$_out" ] && : > "${_out}/pfSense-CE_2.8.qcow2"
exit 0
OEOF
    chmod +x "${BIN}/oras"

    # Stub ssh: log the remote command; `true` (the liveness poll) succeeds,
    # pfSense-repoc prints the live-probed repo listing (tab-delimited),
    # shutdown succeeds. SSH_DOWN=1 fails everything (boot-timeout path).
    cat > "${BIN}/ssh" << 'SEOF'
#!/bin/sh
[ "${SSH_DOWN:-0}" = "1" ] && exit 255
_cmd=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -p|-i|-o) shift 2 ;;
    root@*) shift ;;
    *) _cmd="$_cmd $1"; shift ;;
  esac
done
printf '%s\n' "$_cmd" >> "$SSH_LOG"
case "$_cmd" in
  *pfSense-repoc*)
    printf '26.07\t\tBeta Version (26.07)\n'
    printf '26_03_1 (release) (default)\t\tCurrent Stable Version (26.03.1)\n'
    ;;
esac
exit 0
SEOF
    chmod +x "${BIN}/ssh"

    # Stub boot helper: record argv, stay up until killed (the probe reaps it).
    cat > "${WORK}/boot_vm" << 'BEOF'
#!/bin/sh
printf '%s\n' "$@" > "$BOOT_ARGV"
# exec: the probe kills THIS pid; without exec the sleep child would linger
# holding the captured fds and stall the spec runner.
exec sleep 60 < /dev/null > /dev/null 2>&1
BEOF
    chmod +x "${WORK}/boot_vm"

    export WORK BIN BOOT_ARGV SSH_LOG KEY
    export PFB_BOOT_VM="${WORK}/boot_vm" PFB_POLL_INTERVAL=1 PFB_SHUTDOWN_WAIT=1
  }
  teardown() { rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach 'teardown'

  probe() {  # extra env prefixes come via the caller's environment
    PATH="${BIN}:${PATH}" sh "$SCRIPT" \
      --variant "${1:-ce}" --expect "${2:-26.07}" \
      --image ghcr.io/example/pfsense-ce --tag 2.8 \
      --ssh-key "$KEY" --boot-timeout 2 --out "${WORK}/verdict.json"
  }

  It 'reports yes with the repo name when the expected version is listed'
    When call probe ce 26.07
    The status should be success
    The stderr should include 'booting'
    The contents of file "${WORK}/verdict.json" should include '"verdict":"yes"'
    The contents of file "${WORK}/verdict.json" should include '"branch":"26.07"'
  End

  It 'strips release/default annotations from the captured repo name'
    When call probe ce 26.03.1
    The status should be success
    The stderr should include 'booting'
    The contents of file "${WORK}/verdict.json" should include '"verdict":"yes"'
    # "26_03_1 (release) (default)" → the pkg_list_repos() name alone
    The contents of file "${WORK}/verdict.json" should include '"branch":"26_03_1"'
  End

  It 'reports no when the guest answers but the version is absent'
    When call probe ce 27.99
    The status should be success
    The stderr should include 'booting'
    The contents of file "${WORK}/verdict.json" should include '"verdict":"no"'
  End

  It 'reports unknown without booting when Plus identity is absent'
    unset SMOKE_VM_MAC SMOKE_VM_SMBIOS_UUID
    When call probe plus 26.07
    The status should be success
    The stderr should include 'Plus identity absent'
    The contents of file "${WORK}/verdict.json" should include '"verdict":"unknown"'
    The file "$BOOT_ARGV" should not be exist
  End

  It 'boots Plus when the full identity is present'
    SMOKE_VM_MAC="$(printf 'AA:BB:CC:00:00:0%d\n' 1 2 3 4 5 6 7 8)"
    SMOKE_VM_SMBIOS_UUID="58fd7964-c40c-4f47-bf02-3fdad18f8b00"
    export SMOKE_VM_MAC SMOKE_VM_SMBIOS_UUID
    When call probe plus 26.07
    The status should be success
    The stderr should include 'booting'
    The contents of file "${WORK}/verdict.json" should include '"verdict":"yes"'
    The file "$BOOT_ARGV" should be exist
  End

  It 'reports unknown when the image pull fails'
    export ORAS_FAIL=1
    When call probe ce 26.07
    The status should be success
    The stderr should include 'oras pull'
    The contents of file "${WORK}/verdict.json" should include '"verdict":"unknown"'
    The file "$BOOT_ARGV" should not be exist
  End

  It 'reports unknown when guest SSH never comes up'
    export SSH_DOWN=1
    When call probe ce 26.07
    The status should be success
    The stderr should include 'SSH not up'
    The contents of file "${WORK}/verdict.json" should include '"verdict":"unknown"'
  End
End

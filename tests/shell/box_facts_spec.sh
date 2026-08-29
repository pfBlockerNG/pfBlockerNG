#shellcheck shell=sh
# box_facts_spec.sh — shellspec suite for scripts/box-facts.sh (issue #1823:
# the image-reconcile fact gatherer).
#
# Pins the contract: raw facts written verbatim (etc-version, repoc.txt,
# upgrade-check.txt) + status ok, and the unavailable degradations (Plus
# identity absent — with NO boot attempt, pull failure, guest SSH never up,
# a guest command failing). Hermetic: stubs oras, ssh, and the boot helper.

Describe 'box-facts.sh'
  SCRIPT="${PFB_ROOT}/scripts/box-facts.sh"

  setup() {
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/boxfacts.XXXXXX")"
    BIN="${WORK}/bin"; mkdir -p "$BIN"
    BOOT_ARGV="${WORK}/boot-argv"
    OUT="${WORK}/facts"
    KEY="${WORK}/key"; true > "$KEY"
    SSH_CMDS_LOG="${WORK}/ssh-cmds"

    # Stub oras: succeed and drop a qcow2 into the --output dir (unless ORAS_FAIL=1).
    cat > "${BIN}/oras" << 'OEOF'
#!/bin/sh
[ "${ORAS_FAIL:-0}" = "1" ] && exit 1
_out=""
while [ "$#" -gt 0 ]; do
  [ "$1" = "--output" ] && _out="$2"
  shift
done
[ -n "$_out" ] && true > "${_out}/pfSense-Plus_26.03.qcow2"
exit 0
OEOF
    chmod +x "${BIN}/oras"

    # Stub ssh: answer the three fact commands with live-probed shapes;
    # SSH_DOWN=1 fails everything, FAIL_REPOC=1 fails only the repoc command.
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
printf '%s\n' "$_cmd" >> "$SSH_CMDS_LOG"
case "$_cmd" in
  *pfSense-repoc*)
    [ "${FAIL_REPOC:-0}" = "1" ] && exit 1
    printf '26.07\t\tBeta Version (26.07)\n'
    printf '26_03_1 (release) (default)\t\tCurrent Stable Version (26.03.1)\n'
    ;;
  */etc/version*)
    [ "${FAIL_VERSION:-0}" = "1" ] && exit 1
    printf '26.03.1-RELEASE\n'
    ;;
  *pfSense-upgrade*)
    # LOCKED_UNTIL=N: the first N attempts hit pfSense's lock refusal (issue
    # #1844) — the gatherer must retry, not record the refusal.
    if [ "${LOCKED_UNTIL:-0}" -gt 0 ]; then
      _n=$(cat "$WORK/upg-count" 2>/dev/null || printf '0')
      _n=$((_n + 1)); printf '%s\n' "$_n" > "$WORK/upg-count"
      if [ "$_n" -le "$LOCKED_UNTIL" ]; then
        printf 'Another instance is already running... Aborting!\n'
        exit 75
      fi
    fi
    # TIMEOUT_UPGRADE=1 emulates the guest-side `timeout` expiring: the remote
    # shell yields exit 124 — unless the command string swallows it with a bare
    # `|| true`, which is exactly the defect this pin exists for (CR2)
    if [ "${TIMEOUT_UPGRADE:-0}" = "1" ]; then
      case "$_cmd" in
        *"|| true"*) exit 0 ;;
        *) exit 124 ;;
      esac
    fi
    [ "${FAIL_UPGRADE:-0}" = "1" ] && exit 1
    # UPGRADE_RC models what pfSense-upgrade -c itself returns: 0 current,
    # 2 update available, 1 a real check error. ssh propagates it.
    case "${UPGRADE_RC:-0}" in
      2) printf '26.07.b.20260727.1443 version of pfSense is available\n'; exit 2 ;;
      1) printf 'Unable to check for updates.\n'; exit 1 ;;
      *) printf 'Your system is up to date\n' ;;
    esac
    ;;
esac
exit 0
SEOF
    chmod +x "${BIN}/ssh"

    # Stub boot helper: record argv, stay up until killed.
    cat > "${WORK}/boot_vm" << 'BEOF'
#!/bin/sh
printf '%s\n' "$@" > "$BOOT_ARGV"
# exec: the gatherer kills THIS pid; a lingering child would stall the runner.
exec sleep 60 < /dev/null > /dev/null 2>&1
BEOF
    chmod +x "${WORK}/boot_vm"

    export WORK BIN BOOT_ARGV OUT KEY SSH_CMDS_LOG
    export PFB_BOOT_VM="${WORK}/boot_vm" PFB_POLL_INTERVAL=1 PFB_SHUTDOWN_WAIT=1
  }
  teardown() { rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach 'teardown'

  facts() {  # $1 = variant (default ce)
    PATH="${BIN}:${PATH}" sh "$SCRIPT" \
      --variant "${1:-ce}" \
      --image ghcr.io/example/pfsense-plus --tag 26.03 \
      --ssh-key "$KEY" --out-dir "$OUT" --boot-timeout 2
  }

  It 'gathers the three facts verbatim and reports ok'
    When call facts ce
    The status should be success
    The stderr should include 'booting'
    The contents of file "${OUT}/status" should equal 'ok'
    The contents of file "${OUT}/etc-version" should equal '26.03.1-RELEASE'
    The contents of file "${OUT}/repoc.txt" should include 'Beta Version (26.07)'
    The contents of file "${OUT}/upgrade-check.txt" should include 'up to date'
    # Review F2: both network-fetching guest commands run under a hard cap;
    # delta-review: every fact command is wrapped in /bin/sh -c so a stock
    # tcsh root shell can never misparse 2>&1 (docs/misc/local-smoke-debian.md)
    The contents of file "$SSH_CMDS_LOG" should include "/bin/sh -c 'timeout 120 /usr/local/sbin/pfSense-repoc -p'"
    The contents of file "$SSH_CMDS_LOG" should include "/bin/sh -c 'timeout 240 /usr/local/sbin/pfSense-upgrade"
    The contents of file "$SSH_CMDS_LOG" should include "/bin/sh -c 'cat /etc/version'"
  End

  It 'reports unavailable without booting when Plus identity is absent'
    unset SMOKE_VM_MAC SMOKE_VM_SMBIOS_UUID
    When call facts plus
    The status should be success
    The stderr should include 'Plus identity absent'
    The contents of file "${OUT}/status" should equal 'unavailable'
    The file "$BOOT_ARGV" should not be exist
  End

  It 'boots Plus when the full identity is present'
    SMOKE_VM_MAC="$(printf 'AA:BB:CC:00:00:0%d\n' 1 2 3 4 5 6 7 8)"
    SMOKE_VM_SMBIOS_UUID="58fd7964-c40c-4f47-bf02-3fdad18f8b00"
    export SMOKE_VM_MAC SMOKE_VM_SMBIOS_UUID
    When call facts plus
    The status should be success
    The stderr should include 'booting'
    The contents of file "${OUT}/status" should equal 'ok'
    The file "$BOOT_ARGV" should be exist
  End

  It 'reports unavailable when the image pull fails'
    export ORAS_FAIL=1
    When call facts ce
    The status should be success
    The stderr should include 'oras pull'
    The contents of file "${OUT}/status" should equal 'unavailable'
    The file "$BOOT_ARGV" should not be exist
  End

  It 'reports unavailable when guest SSH never comes up'
    export SSH_DOWN=1
    When call facts ce
    The status should be success
    The stderr should include 'SSH not up'
    The contents of file "${OUT}/status" should equal 'unavailable'
  End

  # issue #1848: the -c check is the planner's OPTIONAL second source. Losing
  # it must not discard the branch list — the fact the whole reconcile turns on.
  It 'keeps the boot usable when only the optional upgrade check fails'
    export FAIL_UPGRADE=1
    When call facts ce
    The status should be success
    The stderr should include 'upgrade-check'
    The contents of file "${OUT}/status" should equal 'ok'
    The contents of file "${OUT}/repoc.txt" should include 'Beta Version (26.07)'
  End

  It 'names the failing fact, its command and its status in the log'
    export FAIL_REPOC=1
    When call facts ce
    The status should be success
    The stderr should include 'repoc'
    The stderr should include 'pfSense-repoc -p'
    The stderr should include 'status 1'
    The contents of file "${OUT}/status" should equal 'unavailable'
  End

  It 'gives up on a lock that never clears instead of retrying forever'
    # Review: removing the PFB_LOCK_RETRIES bound killed no test — the only
    # locked case released well inside the default cap.
    export LOCKED_UNTIL=99 PFB_LOCK_RETRIES=3
    When call facts ce
    The status should be success
    The stderr should include 'attempt 2'
    The stderr should not include 'attempt 3'
    The contents of file "${OUT}/status" should equal 'ok'
    The contents of file "${OUT}/upgrade-check.txt" should equal ''
  End

  It 'still fails the boot when the version fact is lost'
    export FAIL_VERSION=1
    When call facts ce
    The status should be success
    The stderr should include 'etc-version'
    The contents of file "${OUT}/status" should equal 'unavailable'
  End

  It 'reports unavailable when a REQUIRED guest fact command fails'
    export FAIL_REPOC=1
    When call facts ce
    The status should be success
    The stderr should include 'required facts incomplete'
    The contents of file "${OUT}/status" should equal 'unavailable'
  End

  It 'retries a locked upgrade check instead of recording the refusal'
    export LOCKED_UNTIL=2
    When call facts ce
    The status should be success
    The stderr should include 'upgrade check locked'
    The contents of file "${OUT}/status" should equal 'ok'
    The contents of file "${OUT}/upgrade-check.txt" should include 'up to date'
    The contents of file "${OUT}/upgrade-check.txt" should not include 'Another instance'
  End

  It 'treats a failing upgrade check (rc 1) as an absent optional fact'
    # CodeRabbit: `-le 2` accepted rc 1, so a real check ERROR would have been
    # recorded as the planner's second source.
    export UPGRADE_RC=1
    When call facts ce
    The status should be success
    The stderr should include 'optional'
    The contents of file "${OUT}/status" should equal 'ok'
    The contents of file "${OUT}/upgrade-check.txt" should equal ''
  End

  It 'keeps a real available-update answer (rc 2)'
    export UPGRADE_RC=2
    When call facts ce
    The status should be success
    The stderr should include 'booting'
    The contents of file "${OUT}/status" should equal 'ok'
    The contents of file "${OUT}/upgrade-check.txt" should include 'version of pfSense is available'
  End

  It 'records a timed-out upgrade check as absent, never as up to date'
    # CR2: timeout(1)'s 124 must never be swallowed into a clean-looking fact.
    # issue #1848: it is the OPTIONAL source, so the boot stays usable — the
    # file is left EMPTY, which the planner reads as "no signal".
    export TIMEOUT_UPGRADE=1
    When call facts ce
    The status should be success
    The stderr should include 'optional'
    The contents of file "${OUT}/status" should equal 'ok'
    The contents of file "${OUT}/upgrade-check.txt" should equal ''
  End
End

#shellcheck shell=sh
# image_upgrade_lock_spec.sh — pins image-upgrade.sh's handling of pfSense's
# "Another instance is already running... Aborting!" refusal (issue #1844).
#
# `--branch` applies the switch via pkg_switch_repo(), whose pkg refresh still
# holds the pfSense-upgrade lock when the script fires `-c` seconds later. The
# refusal is NOT a verdict: it must be retried, and an unclearable lock must
# die loudly instead of falling through into the version-change poll (which
# turned a ~30 s lock into a 20-minute misleading timeout on run 30397807774).
#
# Hermetic: sources the two helpers out of the script and drives them with a
# stub guest runner — no VM, no ssh.

Describe 'image-upgrade.sh upgrade-lock retry'
  SCRIPT="${PFB_ROOT}/scripts/image-upgrade.sh"

  setup() {
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/upglock.XXXXXX")"
    COUNT="${WORK}/count"
    SLEEP_ARG="${WORK}/sleep-arg"
    printf '0\n' > "$COUNT"
    true > "$SLEEP_ARG"
    export WORK COUNT SLEEP_ARG
  }
  teardown() { rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach 'teardown'

  # run_helper MODE — extract the lock helper from the script and drive it with
  # a stub ssh_guest. MODE controls how many times the guest answers "locked":
  #   clears-after-2 — two refusals, then the real output
  #   always-locked  — every attempt refused
  run_helper() {
    _mode="$1" _retries="${2-3}" _interval="${3-0}" timeout 10 sh -c '
      log()  { printf "==> %s\n" "$*"; }
      warn() { printf "WARNING: %s\n" "$*" >&2; }
      die()  { printf "ERROR: %s\n" "$*" >&2; exit 1; }
      # The helper under test, lifted verbatim from the script.
      eval "$(sed -n "/^# pfb_upgrade_run BEGIN/,/^# pfb_upgrade_run END/p" "$1")"
      LOCK_RETRIES="$_retries"
      LOCK_INTERVAL="$_interval"
      sleep() { printf "%s\n" "$1" > "$SLEEP_ARG"; }
      ssh_guest() {
        _n=$(cat "$COUNT"); _n=$((_n + 1)); printf "%s\n" "$_n" > "$COUNT"
        case "$_mode" in
          always-locked) printf "Another instance is already running... Aborting!\n" ;;
          clears-after-2)
            if [ "$_n" -le 2 ]; then
              printf "Another instance is already running... Aborting!\n"
            else
              printf "26.07.b.20260727.1443 version of pfSense is available\n"
            fi
            ;;
        esac
      }
      pfb_upgrade_run "pfSense-upgrade -c" "upgrade check"
    ' _ "$SCRIPT"
    _status=$?
    if [ "$_status" -eq 124 ]; then
      printf 'stuck/environment: pfb_upgrade_run exceeded salvage cap\n' >&2
      return 125
    fi
    return "$_status"
  }

  It 'retries until the lock clears and returns the real output'
    When call run_helper clears-after-2
    The status should be success
    The stderr should include 'lock held'
    The output should include 'version of pfSense is available'
    The contents of file "$COUNT" should equal '3'
  End

  It 'dies loudly when the lock never clears'
    When call run_helper always-locked
    The status should be failure
    The stderr should include 'lock'
  End

  It 'uses the documented lock retry defaults when both knobs are empty'
    When call run_helper always-locked '' ''
    The status should be failure
    The stderr should include 'after 20 attempts'
    The contents of file "$COUNT" should equal '20'
    The contents of file "$SLEEP_ARG" should equal '15'
  End

  It 'falls back to 20 retries when LOCK_RETRIES is nonnumeric'
    When call run_helper always-locked not-a-number 0
    The status should be failure
    The stderr should include 'after 20 attempts'
    The contents of file "$COUNT" should equal '20'
  End

  It 'falls back to 20 retries when LOCK_RETRIES is zero'
    When call run_helper always-locked 0 0
    The status should be failure
    The stderr should include 'after 20 attempts'
    The contents of file "$COUNT" should equal '20'
  End

  It 'falls back to 20 retries when LOCK_RETRIES has a leading zero'
    When call run_helper always-locked 03 0
    The status should be failure
    The stderr should include 'after 20 attempts'
    The contents of file "$COUNT" should equal '20'
  End

  It 'falls back to 20 retries when LOCK_RETRIES is above 20'
    When call run_helper always-locked 21 0
    The status should be failure
    The stderr should include 'after 20 attempts'
    The contents of file "$COUNT" should equal '20'
  End

  It 'falls back when LOCK_RETRIES exceeds shell integer range'
    When call run_helper always-locked 99999999999999999999999999 0
    The status should be failure
    The stderr should include 'after 20 attempts'
    The contents of file "$COUNT" should equal '20'
  End

  It 'falls back to 15s when LOCK_INTERVAL is nonnumeric'
    When call run_helper always-locked 2 not-a-number
    The status should be failure
    The stderr should include 'after 2 attempts'
    The contents of file "$COUNT" should equal '2'
    The contents of file "$SLEEP_ARG" should equal '15'
  End

  It 'preserves zero as a finite lock retry interval'
    When call run_helper always-locked 2 0
    The status should be failure
    The stderr should include 'after 2 attempts'
    The contents of file "$COUNT" should equal '2'
    The contents of file "$SLEEP_ARG" should equal '0'
  End

  It 'falls back to 15s when LOCK_INTERVAL has a leading zero'
    When call run_helper always-locked 2 09
    The status should be failure
    The stderr should include 'after 2 attempts'
    The contents of file "$COUNT" should equal '2'
    The contents of file "$SLEEP_ARG" should equal '15'
  End

  It 'falls back to 15s when LOCK_INTERVAL is above 15'
    When call run_helper always-locked 2 16
    The status should be failure
    The stderr should include 'after 2 attempts'
    The contents of file "$COUNT" should equal '2'
    The contents of file "$SLEEP_ARG" should equal '15'
  End

  It 'falls back when LOCK_INTERVAL exceeds shell integer range'
    When call run_helper always-locked 2 99999999999999999999999999
    The status should be failure
    The stderr should include 'after 2 attempts'
    The contents of file "$COUNT" should equal '2'
    The contents of file "$SLEEP_ARG" should equal '15'
  End

  It 'preserves valid positive lock retry values'
    When call run_helper always-locked 4 7
    The status should be failure
    The stderr should include 'after 4 attempts'
    The contents of file "$COUNT" should equal '4'
    The contents of file "$SLEEP_ARG" should equal '7'
  End

  # run_call_site MODE — drive the helper through the REAL call-site shape.
  # A shell function on the left of a pipe runs in a subshell, so its `die`
  # cannot abort the script and `set -e` only sees the pipeline's last command
  # (issue #1844). The shipped call sites must
  # therefore never pipe the helper.
  run_call_site() {
    _func="${2:-pfb_call_site_check}" _seed="${3:-}" _mode="$1" sh -c '
      set -e
      log()  { printf "==> %s\n" "$*"; }
      warn() { printf "WARNING: %s\n" "$*" >&2; }
      die()  { printf "ERROR: %s\n" "$*" >&2; exit 1; }
      eval "$(sed -n "/^# pfb_upgrade_run BEGIN/,/^# pfb_upgrade_run END/p" "$1")"
      LOCK_RETRIES=2
      LOCK_INTERVAL=0
      ssh_guest() { printf "Another instance is already running... Aborting!\n"; }
      # The shape the script actually uses, whatever it is today.
      eval "$(sed -n "/^# pfb_call_site BEGIN/,/^# pfb_call_site END/p" "$1")"
      UPGRADE_CMD="yes | pfSense-upgrade -d"
      [ -n "$_seed" ] && printf "%s\n" "$_seed" > "$2/check.log"
      "$_func" "$2/check.log"
      printf "REACHED-AFTER-CHECK\n"
    ' _ "$SCRIPT" "$WORK"
  }

  It 'aborts the script when the lock never clears at the real call site'
    When call run_call_site always-locked
    The status should be failure
    The stderr should include 'lock'
    The output should not include 'REACHED-AFTER-CHECK'
  End

  It 'persists the refusal diagnostics in the log file'
    When call run_call_site always-locked
    The status should be failure
    The stderr should include 'lock held'
    The contents of file "${WORK}/check.log" should include 'Another instance is already running'
  End

  It 'aborts the script at the UPGRADE call site too'
    # The call site that actually triggers the reboot must fail the same way —
    # it was the untested half of the pair.
    When call run_call_site always-locked pfb_call_site_upgrade
    The status should be failure
    The stderr should include 'lock held'
    The output should not include 'REACHED-AFTER-CHECK'
    The contents of file "${WORK}/check.log" should include 'Another instance is already running'
  End

  It 'starts each run with a fresh log instead of appending to a stale one'
    When call run_call_site always-locked pfb_call_site_check STALE-FROM-A-PREVIOUS-RUN
    The status should be failure
    The stderr should include 'lock held'
    The contents of file "${WORK}/check.log" should not include 'STALE-FROM-A-PREVIOUS-RUN'
  End

  It 'never returns the refusal text as if it were a verdict'
    When call run_helper always-locked
    The status should be failure
    The stderr should include 'lock held'
    The output should not include 'Another instance is already running'
  End
End

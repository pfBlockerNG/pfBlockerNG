#shellcheck shell=sh
# image_upgrade_metadata_wait_spec.sh — issue #2458.
#
# image-upgrade.sh reads `pkg config ABI`, runs `pkg upgrade`, samples the
# exported artifact's ABI and powers the verify VM off, each one immediately
# after wait_guest_ssh returns. SSH answering is not a settled box: pfSense
# clears its boot flag before rc.update_pkg_metadata starts, and that job
# rewrites pkg's effective ABI while it runs (#2242 measured ABI 15 with no
# metadata process at 10:16:37Z and ABI 16 with the job active 26s later).
#
# So wait_guest_ssh also waits for the metadata job, using the same three-word
# predicate tests/smoke/helpers.py uses: `gone` before any `running` means the
# job has not started, `gone` after one means it died without publishing the
# sentinel, and only `present` is done.
#
# Hermetic: lifts the helpers out of the script and drives them with a stub
# guest runner — no VM, no ssh.

Describe 'image-upgrade.sh package-metadata wait'
  SCRIPT="${PFB_ROOT}/scripts/image-upgrade.sh"

  setup() {
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/upgmeta.XXXXXX")"
    COUNT="${WORK}/count"
    printf '0\n' > "$COUNT"
    export WORK COUNT
  }
  teardown() { rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach 'teardown'

  # run_wait WORDS — drive pfb_wait_pkg_metadata with a stub ssh_guest that
  # answers the space-separated WORDS in order, repeating the last one forever.
  run_wait() {
    _words="$1" sh -c '
      set -e
      log()  { printf "==> %s\n" "$*"; }
      warn() { printf "WARNING: %s\n" "$*" >&2; }
      die()  { printf "ERROR: %s\n" "$*" >&2; exit 1; }
      eval "$(sed -n "/^# pfb_wait_pkg_metadata BEGIN/,/^# pfb_wait_pkg_metadata END/p" "$1")"
      METADATA_INTERVAL=1
      sleep() { :; }
      ssh_guest() {
        _n=$(cat "$COUNT"); _n=$((_n + 1)); printf "%s\n" "$_n" > "$COUNT"
        _i=0
        _pick=
        for _w in $_words; do
          _i=$((_i + 1))
          if [ -z "$_pick" ] && [ "$_i" -ge "$_n" ]; then
            _pick=$_w
          fi
        done
        [ -n "$_pick" ] || _pick=$_w
        printf "%s\r\n" "$_pick"
      }
      pfb_wait_pkg_metadata "${METADATA_TIMEOUT:-4}"
    ' _ "$SCRIPT"
  }

  It 'keeps polling when the first probe finds no metadata job yet'
    # `gone` on the first probe is the normal boot (#2242's 10:16:37Z sample),
    # not a finished job — so the wait must not stop there.
    When call run_wait 'gone gone running present'
    The status should be success
    The contents of file "$COUNT" should equal '4'
    The stdout should include 'waiting for the pfSense package metadata refresh'
  End

  It 'returns as soon as the sentinel is present'
    When call run_wait 'running present'
    The status should be success
    The contents of file "$COUNT" should equal '2'
    The stdout should include 'waiting for the pfSense package metadata refresh'
  End

  It 'dies when the job is seen running and then disappears with no sentinel'
    When call run_wait 'running gone'
    The status should be failure
    The stderr should include 'pfSense_version.rc'
    The stdout should include 'waiting for the pfSense package metadata refresh'
  End

  It 'dies when the job never stops running before the deadline'
    # The stuck-job row. `running` forever is not success and not a reason to
    # return; the wait ends through the deadline, loudly.
    When call run_wait 'running'
    The status should be failure
    The stderr should include 'did not settle'
    The stdout should include 'waiting for the pfSense package metadata refresh'
  End

  It 'dies when the job never appears before the deadline'
    # A box where the metadata job never runs must not be handed to `pkg add`
    # or powered off silently: the wait ends by dying, never by returning.
    When call run_wait 'gone'
    The status should be failure
    The stderr should include 'did not settle'
    The stdout should include 'waiting for the pfSense package metadata refresh'
  End

  # run_wait_zero_interval — METADATA_INTERVAL=0 would leave the elapsed counter
  # pinned at 0 and the deadline unreachable, i.e. an unbounded wait. `timeout`
  # bounds the example so a regression fails the row instead of hanging the suite.
  run_wait_zero_interval() {
    timeout 10 sh -c '
      set -e
      log()  { printf "==> %s\n" "$*"; }
      die()  { printf "ERROR: %s\n" "$*" >&2; exit 1; }
      eval "$(sed -n "/^# pfb_wait_pkg_metadata BEGIN/,/^# pfb_wait_pkg_metadata END/p" "$1")"
      METADATA_INTERVAL=0
      sleep() { :; }
      ssh_guest() { printf "gone\r\n"; }
      pfb_wait_pkg_metadata 4
    ' _ "$SCRIPT"
  }

  It 'stays bounded when the poll interval is zero'
    When call run_wait_zero_interval
    The status should be failure
    The stderr should include 'did not settle'
    The stdout should include 'waiting for the pfSense package metadata refresh'
  End

  # run_ssh_wait — drive the REAL wait_guest_ssh with SSH answering
  # immediately, and record whether it waits for package metadata too.
  run_ssh_wait() {
    sh -c '
      set -e
      log()  { printf "==> %s\n" "$*"; }
      die()  { printf "ERROR: %s\n" "$*" >&2; exit 1; }
      eval "$(sed -n "/^# wait_guest_ssh BEGIN/,/^# wait_guest_ssh END/p" "$1")"
      sleep() { :; }
      ssh_guest() { :; }
      pfb_wait_pkg_metadata() { printf "metadata-waited\n"; }
      wait_guest_ssh 30
    ' _ "$SCRIPT"
  }

  It 'waits for package metadata before any caller reads pkg state'
    When call run_ssh_wait
    The status should be success
    The output should include 'metadata-waited'
  End

  # The OS-upgrade path never calls wait_guest_ssh: after pfSense-upgrade reboots
  # the box it polls /etc/version itself and breaks the moment the version
  # differs. /etc/version is written by the installer BEFORE
  # rc.update_pkg_metadata runs, so that poll answers while pkg's effective ABI
  # is still being rewritten -- and everything after it reads or writes the pkg
  # database (dependency reconcile, health gate) and then powers the disk off for
  # export. It needs the same settle gate (issue #2458).
  #
  # run_upgraded_wait VERSIONS — drive pfb_wait_upgraded_box with a stub guest
  # answering the space-separated VERSIONS in order, repeating the last forever.
  run_upgraded_wait() {
    _words="$1" sh -c '
      set -e
      log()  { printf "==> %s\n" "$*"; }
      die()  { printf "ERROR: %s\n" "$*" >&2; exit 1; }
      eval "$(sed -n "/^# pfb_wait_upgraded_box BEGIN/,/^# pfb_wait_upgraded_box END/p" "$1")"
      UPGRADE_TIMEOUT=45
      sleep() { :; }
      pfb_wait_pkg_metadata() { printf "metadata-waited\n"; }
      ssh_guest() {
        _n=$(cat "$COUNT"); _n=$((_n + 1)); printf "%s\n" "$_n" > "$COUNT"
        _i=0
        _pick=
        for _w in $_words; do
          _i=$((_i + 1))
          if [ -z "$_pick" ] && [ "$_i" -ge "$_n" ]; then
            _pick=$_w
          fi
        done
        [ -n "$_pick" ] || _pick=$_w
        printf "%s\r\n" "$_pick"
      }
      pfb_wait_upgraded_box 2.8.0-RELEASE /tmp/upgrade.log
      printf "NEW_VER=%s\n" "$NEW_VER"
    ' _ "$SCRIPT"
  }

  It 'waits for package metadata after the upgraded box reports its new version'
    When call run_upgraded_wait '2.8.0-RELEASE 2.8.0-RELEASE 2.9.0-RELEASE'
    The status should be success
    The output should include 'NEW_VER=2.9.0-RELEASE'
    The output should include 'metadata-waited'
  End

  It 'dies when the upgraded box never reports a new version'
    When call run_upgraded_wait '2.8.0-RELEASE'
    The status should be failure
    The stderr should include 'version did not change'
    The output should not include 'metadata-waited'
  End
End

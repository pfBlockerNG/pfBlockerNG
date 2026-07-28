#shellcheck shell=sh
# image_lib_facts_spec.sh — shellspec suite for image_gather_facts()
# (issue #1837: the box-verified activation PR's fact source).
#
# Pins: key=value output from live-probed command shapes, /bin/sh -c wrapping
# of every guest command, best-effort key omission, and the nothing-gathered
# failure. Hermetic: a fake runner function answers the guest commands.

Describe 'image-lib.sh image_gather_facts'
  LIB="${PFB_ROOT}/scripts/image-lib.sh"

  setup() {
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/imgfacts.XXXXXX")"
    OUT="${WORK}/facts.env"
    export WORK OUT
  }
  teardown() { rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach 'teardown'

  # gather MODE — source the lib with a fake runner and call the function.
  gather() {
    _mode="${1:-full}" sh -c '
      log() { :; }; warn() { :; }; die() { printf "%s\n" "$*" >&2; exit 1; }
      . "$1" || exit 1
      # Fake guest runner: answers the live-probed command shapes
      # (Plus 26.03.1, probed 2026-07-28). Logs every command string.
      fake_run() {
        printf "%s\n" "$2" >> "$WORK/run-log"
        case "$2" in
          *"cat /etc/version"*) printf "26.03.1-RELEASE\n" ;;
          *"php -v"*)
            [ "$_mode" = "no-php" ] && return 1
            printf "PHP 8.5.2 (cli) (built: May 15 2026 23:13:28) (NTS)\n"
            printf "Copyright (c) The PHP Group\n"
            ;;
          *"ls /usr/local/bin"*)
            printf "python3.11\npython3.11-config\nphp\n"
            ;;
          *freebsd-version*) printf "16.0-CURRENT\n" ;;
          *) return 1 ;;
        esac
      }
      # POSIX runner-by-name: image_gather_facts calls "$_run" "cmd"; our
      # runner needs a first arg slot, so wrap it.
      runner() { fake_run runner "$1"; }
      if [ "$_mode" = "dead-box" ]; then
        dead() { return 255; }
        image_gather_facts "$2" dead
      else
        image_gather_facts "$2" runner
      fi
    ' _ "$LIB" "$OUT"
  }

  It 'writes all five facts from the live-probed shapes'
    When call gather full
    The status should be success
    The contents of file "$OUT" should include 'etc_version=26.03.1-RELEASE'
    The contents of file "$OUT" should include 'php_version=8.5'
    The contents of file "$OUT" should include 'py_flavor=py311'
    The contents of file "$OUT" should include 'freebsd_version=16.0-CURRENT'
    The contents of file "$OUT" should include 'freebsd_major=16'
  End

  It 'wraps every guest command in /bin/sh -c'
    When call gather full
    The status should be success
    The contents of file "${WORK}/run-log" should include "/bin/sh -c 'cat /etc/version'"
    The contents of file "${WORK}/run-log" should include "/bin/sh -c '/usr/local/bin/php -v'"
    The contents of file "${WORK}/run-log" should include "/bin/sh -c '/bin/freebsd-version'"
  End

  It 'omits keys for absent tools without failing'
    When call gather no-php
    The status should be success
    The contents of file "$OUT" should include 'etc_version='
    The contents of file "$OUT" should not include 'php_version='
  End

  It 'fails only when nothing at all was gathered'
    When call gather dead-box
    The status should be failure
  End
End

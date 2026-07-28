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
          *"cat /etc/version"*)
            case "$_mode" in
              hostile-multiline) printf "26.03.1-RELEASE\ntouch %s/PWNED\n" "$WORK" ;;
              hostile-subst)     printf "26.03.1-RELEASE\$(touch %s/PWNED)\n" "$WORK" ;;
              *)                 printf "26.03.1-RELEASE\n" ;;
            esac
            ;;
          *"php -v"*)
            [ "$_mode" = "no-php" ] && return 1
            printf "PHP 8.5.2 (cli) (built: May 15 2026 23:13:28) (NTS)\n"
            printf "Copyright (c) The PHP Group\n"
            ;;
          *"ls /usr/local/bin"*)
            case "$_mode" in
              # A mid-upgrade box can carry two interpreters; lexical order puts
              # python3.11 first, but 3.9 -> 3.11 must resolve to the HIGHEST.
              multi-python) printf "python3.9\npython3.11\nphp\n" ;;
              *) printf "python3.11\npython3.11-config\nphp\n" ;;
            esac
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

  # Review B1: the facts file is consumed by CI; a box value that is multi-line
  # or carries shell metacharacters must NEVER reach it (an anomalous
  # /etc/version would otherwise corrupt — or inject into — the consumer).
  It 'drops a multi-line version value instead of writing extra lines'
    When call gather hostile-multiline
    The status should be success
    The contents of file "$OUT" should not include 'touch '
    The contents of file "$OUT" should not include 'etc_version=26.03.1-RELEASE'
  End

  It 'drops a version value carrying command substitution'
    When call gather hostile-subst
    The status should be success
    The contents of file "$OUT" should not include 'touch '
    The contents of file "$OUT" should not include '$('
  End

  # unsafe_lines — every fact line must match key=<charset-safe token>; prints
  # the offending lines (expected: none).
  unsafe_lines() {
    gather "${1:-full}" >/dev/null 2>&1
    grep -vE '^[a-z_]+=[0-9A-Za-z._:@-]+$' "$OUT" || true
  }

  It 'writes only key=<charset-safe value> lines'
    When call unsafe_lines full
    The status should be success
    The output should equal ""
  End

  It 'picks the highest python3.X when several are installed'
    When call gather multi-python
    The status should be success
    The contents of file "$OUT" should include 'py_flavor=py311'
  End

  It 'writes no unsafe line even when the box answers hostile'
    When call unsafe_lines hostile-multiline
    The status should be success
    The output should equal ""
  End
End

#shellcheck shell=sh
# image_upgrade_be_spec.sh — pins the two guards that keep image-upgrade.sh from
# publishing a disk other than the one it verified (issue #1858).
#
# pfSense-upgrade renames the running BE to `default_<ts>`, installs the new
# release as `default`, activates it FOR THE NEXT BOOT ONLY (`bectl activate
# -t`) and reboots. Nothing on disk is permanent yet: the promotion happens at
# the END of the next boot, where /etc/pfSense-rc's bootonce_verify_start()
# runs `be_activate "$(be_active_name)"` ("Performing automatic boot
# verification"). That is why a GUI upgrade needs no extra step.
#
# The image job never got that far. It shut the box down 4 seconds after its
# first SSH answer (health gate satisfied by pfctl rules, which are up long
# before pfSense-rc finishes), so the exported disk still booted the archived
# pre-upgrade BE — which is how ghcr.io/pfblockerng/pfsense-plus:26.07 came to
# hold a 26.03.1 system (published run 30419584790, 03:31:44 -> 03:31:48).
#
# Two layers, both pinned here:
#   1. before shutdown, WAIT for that automatic promotion, fall back to an
#      explicit `bectl activate` if it never comes, and refuse to continue
#      unless `bectl list` then shows the running BE active-on-reboot;
#   2. before the push, boot the EXPORTED artifact and refuse to publish it
#      under a tag whose family it does not actually come up with — the guard
#      that catches this whole class, not just the boot-environment case.
#
# Hermetic: drives the shipped helper with a stub guest — no VM.

Describe 'image-upgrade.sh pre-push artifact verification'
  SCRIPT="${PFB_ROOT}/scripts/image-upgrade.sh"

  setup() {
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/upgver.XXXXXX")"
    export WORK
  }
  teardown() { rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach 'teardown'

  # run_verify BOOTED TAG [ABI] [KERNEL] [EXPECT] — drive the shipped verifier:
  # it re-boots the EXPORTED artifact and compares the family it actually boots
  # against the publish tag, then (issue #2242) the artifact's own pkg ABI
  # against its kernel and, when EXPECT is given, against EXPECT. ABI/KERNEL
  # default to an internally-consistent FreeBSD 16 pair so callers testing only
  # the version/family guard don't have to spell them out.
  # This is the guard that catches the whole class, not just the one-shot-BE
  # case: whatever makes the disk differ from the box we observed, the artifact
  # itself is the last word before a push (issue #1858).
  run_verify() {
    _booted="$1" _tag="$2" _abi="${3-FreeBSD:16:amd64}" _kern="${4-16.0-CURRENT}" _expect="${5-}" sh -c '
      set -e
      log()  { printf "==> %s\n" "$*"; }
      warn() { printf "WARNING: %s\n" "$*" >&2; }
      die()  { printf "ERROR: %s\n" "$*" >&2; exit 1; }
      LOCAL_DIR="$2"
      EXPECT_FREEBSD_MAJOR="$_expect"
      # the real tag rule, not a stub — the family comparison IS the guard
      . "$(dirname "$1")/image-lib.sh"
      eval "$(sed -n "/^# pfb_verify_artifact BEGIN/,/^# pfb_verify_artifact END/p" "$1")"
      # stub the boot: report the version/abi/kernel the exported disk comes up with
      pfb_boot_artifact_version() { printf "%s\n%s\n%s\n" "$_booted" "$_abi" "$_kern"; }
      pfb_verify_artifact "$2/out.qcow2" "$_tag"
      printf "REACHED-AFTER-VERIFY\n"
    ' _ "$SCRIPT" "$WORK"
  }

  # run_verify_glob BOOTED TAG ABI KERNEL — like run_verify, but first CDs into a
  # scratch dir containing a file literally named "16": an unguarded
  # `IFS=: set -- $_pva_abi` word-split lets an unquoted `*` field GLOB against real
  # filenames in cwd instead of staying the literal text "*" (issue #2242).
  run_verify_glob() {
    _booted="$1" _tag="$2" _abi="$3" _kern="$4" sh -c '
      set -e
      log()  { printf "==> %s\n" "$*"; }
      warn() { printf "WARNING: %s\n" "$*" >&2; }
      die()  { printf "ERROR: %s\n" "$*" >&2; exit 1; }
      LOCAL_DIR="$2"
      EXPECT_FREEBSD_MAJOR=
      . "$(dirname "$1")/image-lib.sh"
      eval "$(sed -n "/^# pfb_verify_artifact BEGIN/,/^# pfb_verify_artifact END/p" "$1")"
      pfb_boot_artifact_version() { printf "%s\n%s\n%s\n" "$_booted" "$_abi" "$_kern"; }
      mkdir -p "$2/globdir"
      true > "$2/globdir/16"
      cd "$2/globdir"
      pfb_verify_artifact "$2/out.qcow2" "$_tag"
      printf "REACHED-AFTER-VERIFY\n"
    ' _ "$SCRIPT" "$WORK"
  }

  # run_verify_reap — drive the REAL boot helper (not the stub) into a wedged
  # boot and show where the verify VM pid ends up. cleanup() reaps $QPID from
  # the top-level shell: if the boot runs in a subshell/pipeline, the pid never
  # reaches it and a wedged verification QEMU is unreapable (and die() cannot
  # abort from the left side of a pipe — the #1844 rule in the script header).
  run_verify_reap() {
    sh -c '
      set -e
      log()  { printf "==> %s\n" "$*"; }
      warn() { printf "WARNING: %s\n" "$*" >&2; }
      die()  { printf "ERROR: %s\n" "$*" >&2; exit 1; }
      sleep() { true; }
      REMOTE_DIR=/r
      LOCAL_DIR="$2"
      QPID=""
      at_exit() { printf "QPID-AT-EXIT=%s\n" "$QPID" >&2; }
      trap at_exit EXIT
      QEMU_CMD="qemu-kvm -drive file=/r/work.qcow2,if=none -display none -serial file:/r/console.log -pidfile /r/qemu.pid -daemonize"
      . "$(dirname "$1")/image-lib.sh"
      eval "$(sed -n "/^# pfb_verify_artifact BEGIN/,/^# pfb_verify_artifact END/p" "$1")"
      eval "$(sed -n "/^pfb_boot_artifact_version()/,/^}/p" "$1")"
      px() {
        case "$1" in
          "cat "*) printf "4242\n" ;;
        esac
      }
      wait_guest_ssh() { die "SSH never answered"; }
      ssh_guest() { true; }
      pfb_verify_artifact "$2/out.qcow2" 26.07
      printf "REACHED-AFTER-VERIFY\n"
    ' _ "$SCRIPT" "$WORK"
  }

  It 'keeps the verify VM pid where cleanup can reap it when the boot wedges'
    When call run_verify_reap
    The status should be failure
    The stderr should include 'SSH never answered'
    The stderr should include 'QPID-AT-EXIT=4242'
    The output should not include 'REACHED-AFTER-VERIFY'
  End

  It 'keeps both #1858 guards wired into the main flow'
    # a guard nobody calls is not a guard: the bare call lines must exist —
    # deleting either wiring line must turn a test red, not silently drop a layer
    When call sh -c 'grep -cE "^pfb_promote_be$|^pfb_verify_artifact " "$1"' _ "$SCRIPT"
    The output should equal 2
  End

  It 'passes when the exported disk boots the family being published'
    When call run_verify 26.07-BETA 26.07
    The status should be success
    The output should include 'REACHED-AFTER-VERIFY'
  End

  It 'refuses to push a disk that boots a different family'
    # exactly what shipped: tag 26.07, disk boots 26.03.1
    When call run_verify 26.03.1-RELEASE 26.07
    The status should be failure
    The stderr should include '26.03.1'
    The output should not include 'REACHED-AFTER-VERIFY'
  End

  It 'refuses to push when the artifact never reports a version'
    # a boot that dies inside the command substitution surfaces here as empty;
    # it must be named as such, not reported as a bogus family mismatch
    When call run_verify '' 26.07
    The status should be failure
    The stderr should include 'could not read a version'
    The output should not include 'REACHED-AFTER-VERIFY'
  End

  It 'accepts a patch-level difference inside the family'
    When call run_verify 26.07.1-RELEASE 26.07
    The status should be success
    The output should include 'REACHED-AFTER-VERIFY'
  End

  It 'passes when the artifact ABI and kernel major agree, no expectation given'
    When call run_verify 26.07-BETA 26.07 'FreeBSD:16:amd64' '16.0-CURRENT'
    The status should be success
    The output should include 'REACHED-AFTER-VERIFY'
  End

  It 'refuses to publish when the artifact ABI disagrees with its own kernel'
    When call run_verify 26.07-BETA 26.07 'FreeBSD:16:amd64' '15.0-CURRENT'
    The status should be failure
    The stderr should include 'disagrees with its kernel'
    The output should not include 'REACHED-AFTER-VERIFY'
  End

  It 'refuses to publish when the artifact ABI major does not match --expect-freebsd-major'
    When call run_verify 26.07-BETA 26.07 'FreeBSD:16:amd64' '16.0-CURRENT' 15
    The status should be failure
    The stderr should include 'expected 15'
    The output should not include 'REACHED-AFTER-VERIFY'
  End

  It 'passes when the artifact ABI major matches --expect-freebsd-major'
    When call run_verify 26.07-BETA 26.07 'FreeBSD:16:amd64' '16.0-CURRENT' 16
    The status should be success
    The output should include 'REACHED-AFTER-VERIFY'
  End

  It 'refuses to publish when the artifact never reports a pkg ABI'
    When call run_verify 26.07-BETA 26.07 '' '16.0-CURRENT'
    The status should be failure
    The stderr should include 'could not read pkg ABI'
    The output should not include 'REACHED-AFTER-VERIFY'
  End

  It 'refuses to publish when the artifact never reports a kernel release'
    When call run_verify 26.07-BETA 26.07 'FreeBSD:16:amd64' ''
    The status should be failure
    The stderr should include 'could not read kernel release'
    The output should not include 'REACHED-AFTER-VERIFY'
  End

  It 'refuses to publish when the pkg ABI split would glob-match a real filename (issue #2242)'
    When call run_verify_glob 26.07-BETA 26.07 'FreeBSD:*:amd64' '16.0-CURRENT'
    The status should be failure
    The stderr should include 'could not read pkg ABI'
    The output should not include 'REACHED-AFTER-VERIFY'
  End
End

Describe 'image-upgrade.sh option parsing'
  SCRIPT="${PFB_ROOT}/scripts/image-upgrade.sh"

  # run_optparse ARGS... — drive the shipped option-parsing loop in isolation
  # (extracted verbatim, real execution — not a stub), so the digit guard is
  # proven against the actual case arm, not a grep proxy.
  run_optparse() {
    sh -c '
      set -e
      die() { printf "ERROR: %s\n" "$*" >&2; exit 1; }
      _self="$1"; shift
      eval "$(sed -n "/^while \[ \$# -gt 0 \]; do\$/,/^done\$/p" "$_self")"
      printf "UPGRADE_TIMEOUT=%s\n" "${UPGRADE_TIMEOUT:-<unset>}"
      printf "REACHED-AFTER-PARSE\n"
    ' _ "$SCRIPT" "$@"
  }

  It 'rejects a non-numeric --expect-freebsd-major'
    When call run_optparse --expect-freebsd-major abc
    The status should be failure
    The stderr should include 'digits only'
    The output should not include 'REACHED-AFTER-PARSE'
  End

  It 'accepts a numeric --expect-freebsd-major'
    When call run_optparse --expect-freebsd-major 16
    The status should be success
    The output should include 'REACHED-AFTER-PARSE'
  End

  It 'rejects a nonnumeric --upgrade-timeout before starting the upgrade'
    When call run_optparse --upgrade-timeout not-a-number
    The status should be failure
    The stderr should include '--upgrade-timeout must be a decimal integer from 0 to 86400'
    The output should not include 'REACHED-AFTER-PARSE'
  End

  It 'rejects an overflowing --upgrade-timeout before starting the upgrade'
    When call run_optparse --upgrade-timeout 99999999999999999999999999
    The status should be failure
    The stderr should include '--upgrade-timeout must be a decimal integer from 0 to 86400'
    The output should not include 'REACHED-AFTER-PARSE'
  End

  It 'rejects an --upgrade-timeout above 86400 before starting the upgrade'
    When call run_optparse --upgrade-timeout 86401
    The status should be failure
    The stderr should include '--upgrade-timeout must be a decimal integer from 0 to 86400'
    The output should not include 'REACHED-AFTER-PARSE'
  End

  It 'accepts zero as an immediate --upgrade-timeout boundary'
    When call run_optparse --upgrade-timeout 0
    The status should be success
    The output should include 'UPGRADE_TIMEOUT=0'
    The output should include 'REACHED-AFTER-PARSE'
  End

  It 'accepts the 86400 upper --upgrade-timeout boundary'
    When call run_optparse --upgrade-timeout 86400
    The status should be success
    The output should include 'UPGRADE_TIMEOUT=86400'
    The output should include 'REACHED-AFTER-PARSE'
  End

  It 'preserves a valid positive --upgrade-timeout'
    When call run_optparse --upgrade-timeout 45
    The status should be success
    The output should include 'UPGRADE_TIMEOUT=45'
    The output should include 'REACHED-AFTER-PARSE'
  End

  It '--help prints the whole header, past the old truncation point (issue #2242)'
    # this option's own usage-doc line sits below the old sed cutoff -- a bare
    # `--expect-freebsd-major` substring check would pass even truncated (the
    # earlier flow narrative mentions the flag too), so assert the option-doc
    # line itself, which exists only past the cutoff
    When run script "$SCRIPT" --help
    The status should be success
    The output should include "require the EXPORTED artifact's pkg ABI major"
    # the header's LAST lines: a numeric sed range drifts as options are added
    The output should include '--force          overwrite the target tag'
    The output should include 'Auth: as in image-publish.sh'
  End
End

Describe 'image-upgrade.sh boot-environment promotion'
  SCRIPT="${PFB_ROOT}/scripts/image-upgrade.sh"

  setup() {
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/upgbe.XXXXXX")"
    CMDS="${WORK}/guest-cmds"
    POLLS="${WORK}/polls"
    SLEEP_ARG="${WORK}/sleep-arg"
    SLEEP_COUNT="${WORK}/sleep-count"
    true > "$SLEEP_ARG"
    printf '0\n' > "$SLEEP_COUNT"
    export WORK CMDS POLLS SLEEP_ARG SLEEP_COUNT
  }
  teardown() { rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach 'teardown'

  # run_promote MODE — extract the shipped helper and drive it with a stub
  # guest. MODE shapes how `bectl list` evolves across polls:
  #   auto  — pfSense's own boot verification promotes on the 3rd poll
  #   slow  — never promotes on its own; the fallback activate makes it stick
  #   stuck — never promotes, not even after the fallback activate
  run_promote() {
    _mode="$1" _timeout="${2-30}" _interval="${3-10}" timeout 10 sh -c '
      set -e
      log()  { printf "==> %s\n" "$*"; }
      warn() { printf "WARNING: %s\n" "$*" >&2; }
      die()  { printf "ERROR: %s\n" "$*" >&2; exit 1; }
      sleep() {
        _sleep_n=$(cat "$SLEEP_COUNT")
        _sleep_n=$((_sleep_n + 1))
        printf "%s\n" "$_sleep_n" > "$SLEEP_COUNT"
        printf "%s\n" "$1" > "$SLEEP_ARG"
      }
      PROMOTE_TIMEOUT="$_timeout"
      PROMOTE_INTERVAL="$_interval"
      eval "$(sed -n "/^# pfb_promote_be BEGIN/,/^# pfb_promote_be END/p" "$1")"
      ssh_guest() {
        printf "%s\n" "$*" >> "$CMDS"
        case "$*" in
          *"bectl activate"*) printf "activated\n" >> "$WORK/activated" ;;
          *"bectl list"*)
            # garbled — the list never parses (ssh flake, unexpected output):
            # there is nothing trustworthy to promote or verify against
            [ "$_mode" = garbled ] && return 0
            if [ "$_mode" = named ]; then
              if [ -f "$WORK/activated" ]; then
                printf "pfSense_2603           NR     /          1.76G 2026-07-29 03:30\n"
                printf "default                -      -          826M  2026-06-12 22:03\n"
              else
                # hostile shape: an old BE literally named `default` still owns
                # the permanent bootfs while the running BE carries another
                # name — promoting a guessed `default` would pass here
                printf "pfSense_2603           N      /          1.76G 2026-07-29 03:30\n"
                printf "default                R      -          826M  2026-06-12 22:03\n"
              fi
              return 0
            fi
            _n=$(( $(cat "$POLLS" 2>/dev/null || echo 0) + 1 ))
            printf "%s" "$_n" > "$POLLS"
            _promoted=0
            [ "$_mode" = auto ] && [ "$_n" -ge 3 ] && _promoted=1
            [ "$_mode" = slow ] && [ -f "$WORK/activated" ] && _promoted=1
            if [ "$_promoted" -eq 1 ]; then
              printf "default                NR     /          1.76G 2026-07-29 03:30\n"
              printf "default_20260729033017 -      -          826M  2026-06-12 22:03\n"
            else
              # the shape between the upgrade reboot and pfSense-rc finishing:
              # the new BE is running (N) but the archived pre-upgrade BE still
              # owns the permanent bootfs (R) — publish that disk and every
              # later boot is the old system (the shape the :26.07 tag shipped)
              printf "default                N      /          1.76G 2026-07-29 03:30\n"
              printf "default_20260729033017 R      -          826M  2026-06-12 22:03\n"
            fi
            ;;
        esac
      }
      pfb_promote_be
      printf "REACHED-AFTER-PROMOTE\n"
    ' _ "$SCRIPT"
    _status=$?
    if [ "$_status" -eq 124 ]; then
      printf 'stuck/environment: pfb_promote_be exceeded salvage cap\n' >&2
      return 125
    fi
    return "$_status"
  }

  It 'uses the documented promotion defaults when both knobs are empty'
    When call run_promote slow '' ''
    The status should be success
    The output should include 'REACHED-AFTER-PROMOTE'
    The stderr should include 'after 300s'
    The contents of file "$SLEEP_ARG" should equal '10'
    The contents of file "$SLEEP_COUNT" should equal '30'
    The contents of file "$POLLS" should equal '32'
  End

  It 'falls back to 300s when the promotion timeout is nonnumeric'
    When call run_promote slow not-a-number 10
    The status should be success
    The output should include 'REACHED-AFTER-PROMOTE'
    The stderr should include 'after 300s'
    The contents of file "$SLEEP_ARG" should equal '10'
    The contents of file "$SLEEP_COUNT" should equal '30'
    The contents of file "$POLLS" should equal '32'
  End

  It 'falls back to 10s when the promotion interval is nonnumeric'
    When call run_promote slow 30 not-a-number
    The status should be success
    The output should include 'REACHED-AFTER-PROMOTE'
    The stderr should include 'after 30s'
    The contents of file "$SLEEP_ARG" should equal '10'
    The contents of file "$SLEEP_COUNT" should equal '3'
    The contents of file "$POLLS" should equal '5'
  End

  It 'falls back to 10s when the promotion interval is zero'
    When call run_promote slow 30 0
    The status should be success
    The output should include 'REACHED-AFTER-PROMOTE'
    The stderr should include 'after 30s'
    The contents of file "$SLEEP_ARG" should equal '10'
    The contents of file "$SLEEP_COUNT" should equal '3'
    The contents of file "$POLLS" should equal '5'
  End

  It 'falls back to 10s when the promotion interval is zero-padded zero'
    When call run_promote slow 30 00
    The status should be success
    The output should include 'REACHED-AFTER-PROMOTE'
    The stderr should include 'after 30s'
    The contents of file "$SLEEP_ARG" should equal '10'
    The contents of file "$SLEEP_COUNT" should equal '3'
    The contents of file "$POLLS" should equal '5'
  End

  It 'falls back to 10s when the promotion interval is zero-padded 09'
    When call run_promote slow 30 09
    The status should be success
    The output should include 'REACHED-AFTER-PROMOTE'
    The stderr should include 'after 30s'
    The contents of file "$SLEEP_ARG" should equal '10'
    The contents of file "$SLEEP_COUNT" should equal '3'
    The contents of file "$POLLS" should equal '5'
  End

  It 'falls back to 10s when the promotion interval is octal-shaped 010'
    When call run_promote slow 30 010
    The status should be success
    The output should include 'REACHED-AFTER-PROMOTE'
    The stderr should include 'after 30s'
    The contents of file "$SLEEP_ARG" should equal '10'
    The contents of file "$SLEEP_COUNT" should equal '3'
    The contents of file "$POLLS" should equal '5'
  End

  It 'preserves the upper promotion timeout and interval boundaries'
    When call run_promote slow 86400 3600
    The status should be success
    The output should include 'REACHED-AFTER-PROMOTE'
    The stderr should include 'after 86400s'
    The contents of file "$SLEEP_ARG" should equal '3600'
    The contents of file "$SLEEP_COUNT" should equal '24'
    The contents of file "$POLLS" should equal '26'
  End

  It 'falls back when the promotion timeout is above 86400'
    When call run_promote slow 86401 10
    The status should be success
    The output should include 'REACHED-AFTER-PROMOTE'
    The stderr should include 'after 300s'
    The contents of file "$SLEEP_COUNT" should equal '30'
    The contents of file "$POLLS" should equal '32'
  End

  It 'falls back when the promotion interval is above 3600'
    When call run_promote slow 30 3601
    The status should be success
    The output should include 'REACHED-AFTER-PROMOTE'
    The stderr should include 'after 30s'
    The contents of file "$SLEEP_ARG" should equal '10'
    The contents of file "$SLEEP_COUNT" should equal '3'
    The contents of file "$POLLS" should equal '5'
  End

  It 'falls back when the promotion timeout exceeds shell integer range'
    When call run_promote slow 99999999999999999999999999 10
    The status should be success
    The output should include 'REACHED-AFTER-PROMOTE'
    The stderr should include 'after 300s'
    The contents of file "$SLEEP_COUNT" should equal '30'
    The contents of file "$POLLS" should equal '32'
  End

  It 'falls back when the promotion interval exceeds shell integer range'
    When call run_promote slow 30 99999999999999999999999999
    The status should be success
    The output should include 'REACHED-AFTER-PROMOTE'
    The stderr should include 'after 30s'
    The contents of file "$SLEEP_ARG" should equal '10'
    The contents of file "$SLEEP_COUNT" should equal '3'
    The contents of file "$POLLS" should equal '5'
  End

  It 'treats a zero promotion timeout as immediate explicit fallback'
    When call run_promote slow 0 10
    The status should be success
    The output should include 'REACHED-AFTER-PROMOTE'
    The stderr should include 'after 0s'
    The contents of file "$SLEEP_ARG" should equal ''
    The contents of file "$SLEEP_COUNT" should equal '0'
    The contents of file "$POLLS" should equal '2'
  End

  It 'preserves valid positive promotion values'
    When call run_promote slow 30 15
    The status should be success
    The output should include 'REACHED-AFTER-PROMOTE'
    The stderr should include 'after 30s'
    The contents of file "$SLEEP_ARG" should equal '15'
    The contents of file "$SLEEP_COUNT" should equal '2'
    The contents of file "$POLLS" should equal '4'
  End

  It 'waits for pfSense to promote the BE itself and does not touch bectl activate'
    # the box promotes its own running BE at the end of pfSense-rc; forcing an
    # activate would mask a boot that never actually completed
    When call run_promote auto
    The status should be success
    The output should include 'REACHED-AFTER-PROMOTE'
    The contents of file "$CMDS" should not include 'bectl activate'
  End

  It 'falls back to an explicit activate when the promotion never comes'
    When call run_promote slow
    The status should be success
    The output should include 'REACHED-AFTER-PROMOTE'
    The stderr should include 'no automatic boot verification'
    The contents of file "$CMDS" should include 'bectl activate'
  End

  It 'refuses to publish when the BE stays activated for one boot only'
    When call run_promote stuck
    The status should be failure
    The stderr should include 'boot environment'
    The output should not include 'REACHED-AFTER-PROMOTE'
  End

  It 'promotes the BE it detected, not a well-known name'
    When call run_promote named
    The status should be success
    The stderr should include 'no automatic boot verification'
    The output should include 'REACHED-AFTER-PROMOTE'
    The contents of file "$CMDS" should include "bectl activate 'pfSense_2603'"
    The contents of file "$CMDS" should not include "bectl activate 'default'"
  End

  It 'refuses to guess when the running BE cannot be identified'
    # an empty/garbled `bectl list` must not degrade into activating a guessed
    # name: on a lineage whose permanent BE happens to carry that name, the
    # guess passes the permanence check and publishes a disk nobody verified
    When call run_promote garbled
    The status should be failure
    The stderr should include 'could not identify the running boot environment'
    The output should not include 'REACHED-AFTER-PROMOTE'
    The contents of file "$CMDS" should not include 'bectl activate'
  End
End

Describe 'image-upgrade.sh verification boot command'
  SCRIPT="${PFB_ROOT}/scripts/image-upgrade.sh"

  setup() {
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/upgcmd.XXXXXX")"
    PXCMDS="${WORK}/px-cmds"
    export WORK PXCMDS
  }
  teardown() { rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach 'teardown'

  # run_bootcmd DRIVE — drive the shipped pfb_boot_artifact_version with a stub
  # KVM host (px) and guest. DRIVE is the `-drive file=` the upgrade's QEMU_CMD
  # carries: the real work.qcow2 in the good case, something else to model the
  # command's shape having drifted from what the sed seams expect.
  run_bootcmd() {
    _drive="$1" sh -c '
      set -e
      log()  { printf "==> %s\n" "$*"; }
      warn() { printf "WARNING: %s\n" "$*" >&2; }
      die()  { printf "ERROR: %s\n" "$*" >&2; exit 1; }
      sleep() { true; }
      REMOTE_DIR=/r
      QEMU_CMD="qemu-kvm -drive file=${_drive},if=none,id=drive-scsi0 -display none -serial file:/r/console.log -pidfile /r/qemu.pid -daemonize"
      eval "$(sed -n "/^pfb_boot_artifact_version()/,/^}/p" "$1")"
      px() {
        printf "%s\n" "$1" >> "$PXCMDS"
        case "$1" in
          "cat "*) printf "4242\n" ;;
          "kill -0 "*) return 1 ;;   # the verify VM is already gone
        esac
      }
      wait_guest_ssh() { true; }
      ssh_guest() {
        case "$*" in
          *"/etc/version"*)     printf "26.07-BETA\n" ;;
          *"pkg config ABI"*)   printf "FreeBSD:16:amd64\n" ;;
          *"uname -r"*)         printf "16.0-CURRENT\n" ;;
        esac
      }
      pfb_boot_artifact_version /r/out.qcow2
    ' _ "$SCRIPT"
  }

  It 'boots the exported artifact on the upgrade topology, swapping only the seams'
    When call run_bootcmd /r/work.qcow2
    The status should be success
    The stderr should include 'booting the exported artifact'
    The output should include '26.07-BETA'
    The contents of file "$PXCMDS" should include '/r/out.qcow2'
    The contents of file "$PXCMDS" should include '/r/verify.pid'
    The contents of file "$PXCMDS" should include '/r/verify-console.log'
    The contents of file "$PXCMDS" should not include 'work.qcow2'
    The contents of file "$PXCMDS" should not include '/r/qemu.pid'
    The contents of file "$PXCMDS" should not include '/r/console.log'
  End

  It 'prints exactly three lines: version, pkg ABI, kernel release (issue #2242)'
    When call run_bootcmd /r/work.qcow2
    The status should be success
    The stderr should include 'booting the exported artifact'
    The lines of output should equal 3
    The line 1 of output should equal '26.07-BETA'
    The line 2 of output should equal 'FreeBSD:16:amd64'
    The line 3 of output should equal '16.0-CURRENT'
  End

  It 'refuses to boot when the substitutions do not take'
    # QEMU_CMD drifted (no work.qcow2 seam): the old sed silently no-opped and
    # re-booted the disk we already observed — the exact fail-open of #1858
    When call run_bootcmd /r/box.qcow2
    The status should be failure
    The stderr should include 'refusing to boot'
    The path "$PXCMDS" should not be exist
  End
End

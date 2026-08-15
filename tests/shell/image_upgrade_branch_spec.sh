#shellcheck shell=sh
# image_upgrade_branch_spec.sh — branch discovery must use pfSense-repoc's
# available-branch catalogue, not pkg_list_repos()'s installed-repo view.

Describe 'image-upgrade.sh update-branch selection'
  SCRIPT="${PFB_ROOT}/scripts/image-upgrade.sh"

  setup() {
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/upgbranch.XXXXXX")"
    CALLS="${WORK}/calls"
    PAYLOAD="${WORK}/payload"
    COUNT="${WORK}/count"
    printf '0\n' > "$COUNT"
    export WORK CALLS PAYLOAD COUNT
  }
  teardown() { rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach 'teardown'

  run_branch_block() {
    _mode="$1" _requested="$2" sh -c '
      set -e
      log()  { printf "==> %s\n" "$*"; }
      warn() { printf "WARNING: %s\n" "$*" >&2; }
      die()  { printf "ERROR: %s\n" "$*" >&2; exit 1; }
      ssh_guest() {
        printf "%s\n" "$1" >> "$CALLS"
        case "$1" in
          "/usr/local/sbin/pfSense-repoc -p")
            [ "$_mode" = catalogue-error ] && return 7
            printf "2_9_0\t\tBeta Version (2.9.0)\n"
            printf "2_8_1 (release) (default)\t\tCurrent Stable Version (2.8.1)\n"
            ;;
          pfSsh.php)
            cat > "$PAYLOAD"
            if grep -q pkg_list_repos "$PAYLOAD"; then
              printf "PFB_BRANCH_NOT_FOUND available=2_8_1\n"
            else
              printf "PFB_BRANCH_OK\n"
            fi
            ;;
          "pkg update -f")
            _n=$(cat "$COUNT"); _n=$((_n + 1)); printf "%s\n" "$_n" > "$COUNT"
            case "$_mode" in
              transient-lock)
                if [ "$_n" -eq 1 ]; then
                  printf "%s\n" "pkg: Cannot get an exclusive lock on a database, it is locked by another process"
                  return 1
                fi
                ;;
              permanent-lock)
                printf "%s\n" "pkg: Package database is busy while closing!"
                return 1
                ;;
              refresh-error)
                printf "%s\n" "REFRESH FAILED"
                return 9
                ;;
            esac
            printf "catalogue refreshed\n"
            ;;
        esac
      }
      # New code exposes its helper between these markers. On the old code the
      # extraction is empty and the unchanged main-flow block still executes,
      # giving a genuine RED against its pkg_list_repos() behavior.
      eval "$(sed -n "/^# pfb_pkg_update_retry BEGIN/,/^# pfb_pkg_update_retry END/p" "$1")"
      eval "$(sed -n "/^# pfb_switch_branch BEGIN/,/^# pfb_switch_branch END/p" "$1")"
      PKG_LOCK_RETRIES=2
      PKG_LOCK_INTERVAL=0
      BRANCH="$_requested"
      LOCAL_DIR="$2"
      eval "$(sed -n "/^# --- optional: switch the pfSense update branch/,/^# --- check whether an OS upgrade is available/p" "$1")"
      printf "REACHED-AFTER-BRANCH\n"
    ' _ "$SCRIPT" "$WORK"
  }

  run_newline_branch() {
    run_branch_block available "$(printf 'bad\n2_9_0')"
  }

  It 'accepts a live branch absent from pkg_list_repos'
    When call run_branch_block available 2_9_0
    The status should be success
    The output should include 'REACHED-AFTER-BRANCH'
    The contents of file "$CALLS" should include '/usr/local/sbin/pfSense-repoc -p'
    The contents of file "$PAYLOAD" should include "config_set_path('system/pkg_repo_conf_path', '2_9_0')"
    The contents of file "$PAYLOAD" should include 'pkg_switch_repo()'
    The contents of file "${WORK}/pkg-update-branch.log" should include 'catalogue refreshed'
    The contents of file "$COUNT" should equal '1'
  End

  It 'retries a transient pkg database lock and preserves every attempt'
    When call run_branch_block transient-lock 2_9_0
    The status should be success
    The stderr should include 'pkg database locked'
    The output should include 'REACHED-AFTER-BRANCH'
    The contents of file "${WORK}/pkg-update-branch.log" should include 'Cannot get an exclusive lock'
    The contents of file "${WORK}/pkg-update-branch.log" should include 'catalogue refreshed'
    The contents of file "$COUNT" should equal '2'
  End

  It 'fails closed when the pkg database lock never clears'
    When call run_branch_block permanent-lock 2_9_0
    The status should be failure
    The stderr should include 'still locked after 2 attempts'
    The output should not include 'REACHED-AFTER-BRANCH'
    The contents of file "${WORK}/pkg-update-branch.log" should include 'Package database is busy'
    The contents of file "$COUNT" should equal '2'
  End

  It 'fails closed without retrying a non-lock catalogue refresh error'
    When call run_branch_block refresh-error 2_9_0
    The status should be failure
    The stderr should include 'pkg catalogue refresh failed'
    The output should not include 'REACHED-AFTER-BRANCH'
    The contents of file "${WORK}/pkg-update-branch.log" should include 'REFRESH FAILED'
    The contents of file "$COUNT" should equal '1'
  End

  It 'rejects an unknown branch before changing pfSense configuration'
    When call run_branch_block available 2_10_0
    The status should be failure
    The stderr should include "branch '2_10_0' not found"
    The stderr should include '2_9_0 2_8_1'
    The contents of file "$CALLS" should not include 'pfSsh.php'
    The output should not include 'REACHED-AFTER-BRANCH'
  End

  It 'fails closed when the authoritative catalogue cannot be read'
    When call run_branch_block catalogue-error 2_9_0
    The status should be failure
    The stderr should include 'could not list available pfSense update branches'
    The contents of file "$CALLS" should not include 'pfSsh.php'
    The output should not include 'REACHED-AFTER-BRANCH'
  End

  It 'rejects a quote before querying the catalogue'
    When call run_branch_block available "2_9_0'"
    The status should be failure
    The stderr should include 'must not contain a single quote'
    The contents of file "$CALLS" should not include 'pfSense-repoc'
  End

  It 'rejects a newline before querying the catalogue'
    When call run_newline_branch
    The status should be failure
    The stderr should include 'invalid update branch name'
    The contents of file "$CALLS" should not include 'pfSense-repoc'
    The contents of file "$CALLS" should not include 'pfSsh.php'
  End
End

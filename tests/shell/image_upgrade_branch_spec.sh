#shellcheck shell=sh
# image_upgrade_branch_spec.sh — branch discovery must use pfSense-repoc's
# available-branch catalogue, not pkg_list_repos()'s installed-repo view.

Describe 'image-upgrade.sh update-branch selection'
  SCRIPT="${PFB_ROOT}/scripts/image-upgrade.sh"

  setup() {
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/upgbranch.XXXXXX")"
    CALLS="${WORK}/calls"
    PAYLOAD="${WORK}/payload"
    export WORK CALLS PAYLOAD
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
          "pkg update -f") printf "catalogue refreshed\n" ;;
        esac
      }
      # New code exposes its helper between these markers. On the old code the
      # extraction is empty and the unchanged main-flow block still executes,
      # giving a genuine RED against its pkg_list_repos() behavior.
      eval "$(sed -n "/^# pfb_switch_branch BEGIN/,/^# pfb_switch_branch END/p" "$1")"
      BRANCH="$_requested"
      LOCAL_DIR="$2"
      eval "$(sed -n "/^# --- optional: switch the pfSense update branch/,/^# --- check whether an OS upgrade is available/p" "$1")"
      printf "REACHED-AFTER-BRANCH\n"
    ' _ "$SCRIPT" "$WORK"
  }

  It 'accepts a live branch absent from pkg_list_repos'
    When call run_branch_block available 2_9_0
    The status should be success
    The output should include 'REACHED-AFTER-BRANCH'
    The contents of file "$CALLS" should include '/usr/local/sbin/pfSense-repoc -p'
    The contents of file "$PAYLOAD" should include "config_set_path('system/pkg_repo_conf_path', '2_9_0')"
    The contents of file "$PAYLOAD" should include 'pkg_switch_repo()'
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
End

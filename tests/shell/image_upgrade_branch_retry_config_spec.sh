#shellcheck shell=sh

Describe 'image-upgrade.sh branch refresh retry configuration'
  SCRIPT="${PFB_ROOT}/scripts/image-upgrade.sh"

  run_with_config() {
    _retries="$1" _interval="$2" sh -c '
      log()  { :; }
      warn() { :; }
      die()  { printf "ERROR: %s\n" "$*" >&2; exit 1; }
      ssh_guest() {
        case "$1" in
          "/usr/local/sbin/pfSense-repoc -p") printf "2_9_0\n" ;;
          pfSsh.php) cat >/dev/null; printf "PFB_BRANCH_OK\n" ;;
          "pkg update -f") printf "catalogue refreshed\n" ;;
        esac
      }
      eval "$(sed -n "/^# pfb_switch_branch BEGIN/,/^# pfb_switch_branch END/p" "$1")"
      PKG_LOCK_RETRIES="$_retries"
      PKG_LOCK_INTERVAL="$_interval"
      pfb_switch_branch 2_9_0 "$2"
    ' _ "$SCRIPT" "${SHELLSPEC_TMPBASE:-/tmp}"
  }

  It 'rejects a non-integer retry cap before refreshing'
    When call run_with_config invalid 0
    The status should be failure
    The stderr should include 'PKG_LOCK_RETRIES must be a positive integer'
  End

  It 'rejects a non-integer retry interval before refreshing'
    When call run_with_config 2 invalid
    The status should be failure
    The stderr should include 'PKG_LOCK_INTERVAL must be a non-negative integer'
  End
End

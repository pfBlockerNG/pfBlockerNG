#shellcheck shell=sh

Describe 'image-upgrade.sh branch refresh retry configuration'
  SCRIPT="${PFB_ROOT}/scripts/image-upgrade.sh"

  setup() {
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/upgbranch-config.XXXXXX")"
    CALLS="${WORK}/calls"
    export WORK CALLS
  }
  teardown() { rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach 'teardown'

  run_with_config() {
    _retries="$1" _interval="$2" sh -c '
      log()  { :; }
      warn() { :; }
      die()  { printf "ERROR: %s\n" "$*" >&2; exit 1; }
      ssh_guest() {
        printf "%s\n" "$1" >> "$CALLS"
        case "$1" in
          "/usr/local/sbin/pfSense-repoc -p") printf "2_9_0\n" ;;
          pfSsh.php) cat >/dev/null; printf "PFB_BRANCH_OK\n" ;;
          "pkg update -f") printf "catalogue refreshed\n" ;;
        esac
      }
      eval "$(sed -n "/^# pfb_pkg_update_retry BEGIN/,/^# pfb_pkg_update_retry END/p" "$1")"
      eval "$(sed -n "/^# pfb_switch_branch BEGIN/,/^# pfb_switch_branch END/p" "$1")"
      PKG_LOCK_RETRIES="$_retries"
      PKG_LOCK_INTERVAL="$_interval"
      pfb_switch_branch 2_9_0 "$2"
    ' _ "$SCRIPT" "$WORK"
  }

  It 'rejects a non-integer retry cap before refreshing'
    When call run_with_config invalid 0
    The status should be failure
    The stderr should include 'PKG_LOCK_RETRIES must be a positive integer'
    The contents of file "$CALLS" should not include 'pkg update -f'
  End

  It 'rejects a non-integer retry interval before refreshing'
    When call run_with_config 2 invalid
    The status should be failure
    The stderr should include 'PKG_LOCK_INTERVAL must be a non-negative integer'
    The contents of file "$CALLS" should not include 'pkg update -f'
  End

  It 'rejects a retry cap above the production maximum before refreshing'
    When call run_with_config 13 0
    The status should be failure
    The stderr should include 'PKG_LOCK_RETRIES must be between 1 and 12'
    The contents of file "$CALLS" should not include 'pkg update -f'
  End

  It 'rejects a retry interval above the production maximum before refreshing'
    When call run_with_config 2 6
    The status should be failure
    The stderr should include 'PKG_LOCK_INTERVAL must be between 0 and 5'
    The contents of file "$CALLS" should not include 'pkg update -f'
  End
End

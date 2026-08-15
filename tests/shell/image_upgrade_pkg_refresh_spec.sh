#shellcheck shell=sh
# image_upgrade_pkg_refresh_spec.sh — pins --upgrade-pkgs publish decisions.
#
# A same-family pkg refresh must not fall into the OS version-change poll
# (20 minute timeout) and must not treat a failed or unclear pkg apply as
# a publish signal.

Describe 'image-upgrade.sh package-refresh verdict'
  SCRIPT="${PFB_ROOT}/scripts/image-upgrade.sh"

  run_verdict() {
    _dry="$1" sh -c '
      eval "$(sed -n "/^# pfb_pkg_refresh_verdict BEGIN/,/^# pfb_pkg_refresh_verdict END/p" "$1")"
      pfb_pkg_refresh_verdict "$_dry"
    ' _ "$SCRIPT"
  }

  It 'reports up-to-date when pkg says so'
    When call run_verdict 'Your packages are up to date.'
    The status should be success
    The output should equal 'up-to-date'
  End

  It 'reports pending only when pkg printed a plan'
    When call run_verdict 'Number of packages to be upgraded: 3'
    The status should be success
    The output should equal 'pending'
  End

  It 'fail-closes on a fetch error with no plan'
    When call run_verdict 'pkg: http://example.test: Not Found'
    The status should be success
    The output should equal 'fail-closed'
  End

  It 'fail-closes on empty dry-run output'
    When call run_verdict ''
    The status should be success
    The output should equal 'fail-closed'
  End
End

Describe 'image-upgrade.sh skips the OS poll after a verified package apply'
  SCRIPT="${PFB_ROOT}/scripts/image-upgrade.sh"

  It 'does not call pfb_call_site_upgrade when SKIP_OS_UPGRADE is set by the pkg path'
    When call grep -n 'SKIP_OS_UPGRADE' "$SCRIPT"
    The status should be success
    The output should include 'SKIP_OS_UPGRADE=1'
  End

  It 'does not pipe pkg upgrade -y into tee'
    When call grep -n "pkg upgrade -y" "$SCRIPT"
    The status should be success
    The output should not include 'pkg upgrade -y'"'"' 2>&1 | tee'
  End
End

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

  It 'treats a removal-only plan as pending'
    When call run_verdict 'Number of packages to be REMOVED: 1'
    The status should be success
    The output should equal 'pending'
  End

  It 'treats a downgrade plan as pending'
    When call run_verdict 'Number of packages to be downgraded: 2'
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

Describe 'image-upgrade.sh publish decision after a package apply'
  SCRIPT="${PFB_ROOT}/scripts/image-upgrade.sh"

  run_decision() {
    _pkg="$1" _old="$2" _post="$3" _cur="$4" sh -c '
      eval "$(sed -n "/^# pfb_publish_decision BEGIN/,/^# pfb_publish_decision END/p" "$1")"
      pfb_publish_decision "$_pkg" "$_old" "$_post" "$_cur"
    ' _ "$SCRIPT"
  }

  It 'skips the OS poll when pkg already moved /etc/version'
    When call run_decision 1 26.07-BETA 26.07-RC 0
    The status should be success
    The output should equal 'skip-os'
  End

  It 'skips the OS poll when -c is current after a verified apply'
    When call run_decision 1 26.07 26.07 1
    The status should be success
    The output should equal 'skip-os'
  End

  It 'exits with nothing to publish when current and no apply'
    When call run_decision 0 26.07 26.07 1
    The status should be success
    The output should equal 'nothing-to-publish'
  End

  It 'runs the OS upgrade when -c is not current'
    When call run_decision 0 26.07 26.07 0
    The status should be success
    The output should equal 'run-os'
  End

  It 'fail-closes when apply succeeded but the version probe is empty'
    When call run_decision 1 26.07 '' 1
    The status should be success
    The output should equal 'fail-closed'
  End
End

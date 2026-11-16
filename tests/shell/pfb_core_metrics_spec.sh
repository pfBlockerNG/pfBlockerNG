#shellcheck shell=sh
Describe 'Core metrics wrapper'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbmetricslane.XXXXXX")"
    for tool in timeout php; do
      cat > "$work/$tool" <<'STUB'
#!/bin/sh
printf '%s\n' "$0" "$@"
exit 7
STUB
      chmod +x "$work/$tool"
    done
  }
  cleanup() { rm -rf "$work"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  # Redirects only the platform paths (the sentinel, timeout, php); every other shipped byte runs under dash.
  run_wrapper() {
    wrapper="$PFB_PKGDIR/pfb_core_metrics.sh"
    if [ ! -f "$wrapper" ]; then
      printf '%s\n' 'missing production metrics wrapper' >&2
      return 1
    fi
    sed -e "s|/usr/local/etc/pfb_metrics_enabled|$work/sentinel|" -e "s|/usr/bin/timeout|$work/timeout|" "$wrapper" > "$work/wrapper.sh"
    dash "$work/wrapper.sh" ignored-argument
  }

  It 'does nothing and succeeds while the export is off'
    When call run_wrapper
    The status should equal 0
    The output should equal ''
    The stderr should equal ''
  End

  It 'runs the metrics verb under the 50 s timeout while the export is on'
    : > "$work/sentinel"
    When call run_wrapper
    The status should equal 7
    The output should equal "$(printf '%s\n' "$work/timeout" '-s' 'TERM' '-k' '5' '50' '/usr/local/bin/php' '/usr/local/www/pfblockerng/pfblockerng.php' 'metrics')"
    The stderr should equal ''
  End

  It 'is executable and passes the syntax check'
    When call sh -n "$PFB_PKGDIR/pfb_core_metrics.sh"
    The status should equal 0
    The path "$PFB_PKGDIR/pfb_core_metrics.sh" should be executable
  End
End

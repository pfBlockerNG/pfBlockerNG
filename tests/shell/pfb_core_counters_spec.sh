#shellcheck shell=sh
Describe 'Core counters wrapper'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbcounters.XXXXXX")"
    cat > "$work/php" <<'PHP'
#!/bin/sh
printf '%s\n' "$@"
exit 3
PHP
    chmod +x "$work/php"
  }
  cleanup() { rm -rf "$work"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  run_wrapper() {
    wrapper="$PFB_PKGDIR/pfb_core_counters.sh"
    if [ ! -f "$wrapper" ]; then
      printf '%s\n' 'missing production counters wrapper' >&2
      return 1
    fi
    # Replace only the platform interpreter; execute every other shipped byte under dash.
    sed "s|/usr/local/bin/php|$work/php|" "$wrapper" > "$work/wrapper.sh"
    dash "$work/wrapper.sh" "$@"
  }

  It 'execs the counters verb with one cadence verbatim'
    When call run_wrapper daily
    The status should equal 3
    The output should equal "$(printf '%s\n' '-d' 'display_errors=stderr' '-f' '/usr/local/pkg/pfblockerng/pfblockerng.inc' 'core_counters' 'daily')"
    The stderr should equal ''
  End

  It 'forwards two cadences verbatim and in order'
    When call run_wrapper daily weekly
    The status should equal 3
    The output should equal "$(printf '%s\n' '-d' 'display_errors=stderr' '-f' '/usr/local/pkg/pfblockerng/pfblockerng.inc' 'core_counters' 'daily' 'weekly')"
  End

  It 'does not split or reinterpret a hostile argument'
    When call run_wrapper 'daily;rm -rf /' ''
    The status should equal 3
    The output should equal "$(printf '%s\n' '-d' 'display_errors=stderr' '-f' '/usr/local/pkg/pfblockerng/pfblockerng.inc' 'core_counters' 'daily;rm -rf /' '')"
  End

  It 'is executable and passes the syntax check'
    When call sh -n "$PFB_PKGDIR/pfb_core_counters.sh"
    The status should equal 0
    The path "$PFB_PKGDIR/pfb_core_counters.sh" should be executable
  End
End

#shellcheck shell=sh
Describe 'Core maintenance wrapper'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbmaintenance.XXXXXX")"
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
    wrapper="$PFB_PKGDIR/pfb_core_maintenance.sh"
    if [ ! -f "$wrapper" ]; then
      printf '%s\n' 'missing production maintenance wrapper' >&2
      return 1
    fi
    # Replace only the platform interpreter; execute every other shipped byte under dash.
    sed "s|/usr/local/bin/php|$work/php|" "$wrapper" > "$work/wrapper.sh"
    printf '%s\n' 'hostile stdin is not a request' | dash "$work/wrapper.sh" ignored-argument 3> "$work/fd3"
  }

  It 'execs the real maintenance verb and propagates its exit status without Update outcomes'
    When call run_wrapper
    The status should equal 3
    The output should equal "$(printf '%s\n' '-d' 'display_errors=stderr' '-f' '/usr/local/pkg/pfblockerng/pfblockerng.inc' 'core_maintenance')"
    The stderr should equal ''
    The contents of file "$work/fd3" should equal ''
  End
End

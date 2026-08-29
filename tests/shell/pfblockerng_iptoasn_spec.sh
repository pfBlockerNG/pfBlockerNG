#shellcheck shell=sh
# iptoasn() result handling — locks the issue #28 fix (the pre-fix code ran the
# file-exists test -s against $asn, a string variable, instead of -n).

Describe 'iptoasn() result test (issue #28)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/iptoasn.XXXXXX")"
    pathgeoip="${work}/mmdblookup"
    pathasndat="${work}/asn.mmdb"
    touch "$pathasndat"            # skip the on-first-use download branch
    errorlog="${work}/error.log"
    extraslog="${work}/extras.log"
    now="now"
    alias="203.0.113.1"
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'echoes the ASN string when the lookup is non-empty'
    make_geoip_stub "$pathgeoip" 'AS64500 Example'
    When call iptoasn
    The output should include "AS64500"
  End

  It 'echoes nothing when the lookup is empty'
    make_geoip_stub "$pathgeoip" ''
    When call iptoasn
    The output should equal ""
  End

  It 'echoes a result that is also an existing filename (proves -n, not -s)'
    # Pre-fix, -s "${asn}" treats the result as a path: an existing non-empty
    # file makes -s true and the function wrongly echoes "". -n tests contents.
    # The pipeline appends a trailing '|' (grep re-terminates the line, then
    # tr '\n' '|'), so the result — and the file we create to match it — is
    # "<stub output>|".
    expected="${work}/asnentry|"
    printf 'data\n' > "${expected}"
    make_geoip_stub "$pathgeoip" "${work}/asnentry"
    When call iptoasn
    The output should equal "${expected}"
  End
End

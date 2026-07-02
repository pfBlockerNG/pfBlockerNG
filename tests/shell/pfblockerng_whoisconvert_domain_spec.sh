#shellcheck shell=sh
# whoisconvert() domain branch (issue #714): a failed `host` lookup used to be
# treated as success -- found=true was set unconditionally and the lookup's
# output was piped straight into the .orig sink with no exit-code check, so a
# failed DNS lookup landed as DATA (e.g. the literal "3(NXDOMAIN)" tail of
# "Host x not found: 3(NXDOMAIN)"). The sibling ASN branch already checks its
# result and falls back to the previous .orig (.bk) on failure; the domain
# branch now mirrors it: on a failed lookup it touches an alias.fail marker
# and leaves `found=false`, so the existing .bk-restore logic preserves the
# last-good data instead of being clobbered with garbage.

Describe 'whoisconvert() domain branch checks the host(1) result (issue #714)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/whoisdom.XXXXXX")"
    pfborig="${work}/orig/"; mkdir -p "$pfborig"
    alias="TestDomainList"
    max="_v4"
    dedup="a-failing-domain.com"

    # host(1) stand-in: a failed lookup prints the classic NXDOMAIN message to
    # stdout and exits 1 -- exactly what a real `host -t A <name>` does for a
    # name that doesn't resolve.
    pathhost="${work}/host"
    cat > "$pathhost" <<'EOF'
#!/bin/sh
echo "Host $3 not found: 3(NXDOMAIN)"
exit 1
EOF
    chmod +x "$pathhost"

    # Last-good data already on disk before this run -- whoisconvert() must
    # preserve it (via its .bk backup/restore) when the lookup fails.
    printf '203.0.113.9\n' > "${pfborig}${alias}.orig"
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'touches .fail and restores the last-good .orig instead of capturing the NXDOMAIN error text'
    When call whoisconvert
    The status should be success
    The stdout should include 'Restoring previous data'
    # Then a failure marker is left for the caller to notice...
    The path "${pfborig}${alias}.fail" should be exist
    # ...the previously-good data is restored, not clobbered...
    The contents of file "${pfborig}${alias}.orig" should equal '203.0.113.9'
    # ...and the raw host(1) error text never lands in .orig as if it were an IP.
    The contents of file "${pfborig}${alias}.orig" should not include '3(NXDOMAIN)'
  End
End

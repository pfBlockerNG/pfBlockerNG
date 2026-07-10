#shellcheck shell=sh
# whoisconvert() ASN branch accumulation (issue #1075).
#
# The ASN branch used to write its collected prefixes with `>` (truncate) while
# the domain branch appends with `>>`. In a mixed or multi-ASN comma list every
# ASN entry therefore clobbered EVERYTHING collected before it -- a
# "domain,ASN" list kept only the ASN prefixes, and an "ASN,ASN" list kept only
# the last ASN. The branch now captures the entry's prefixes in a variable and
# appends, with per-entry success detected on the variable (the old `[ -s
# .orig ]` check only worked because of the truncation).
#
# The asn.csv rows mirror IPinfo's layout: start_ip,end_ip,ASN,name -- the
# collector greps `,AS<n>,` and emits "start-end" ranges via cut -f1-2 + tr.

Describe 'whoisconvert() ASN branch appends instead of truncating (issue #1075)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/whoisasn.XXXXXX")"
    pfborig="${work}/orig/"; mkdir -p "$pfborig"
    alias="MixedList"
    max="_v4"
    # Domain FIRST, ASN second -- before the fix the ASN entry's `>` write
    # dropped the domain IP collected in the first iteration.
    dedup="good-one.example,AS64500"

    pathhost="${work}/host"
    cat > "$pathhost" <<'EOF'
#!/bin/sh
echo "$3 has address 203.0.113.5"
exit 0
EOF
    chmod +x "$pathhost"

    pathasncsv="${work}/asn.csv"
    cat > "$pathasncsv" <<'EOF'
203.0.113.64,203.0.113.127,AS64500,ExampleNet
2001:db8::,2001:db8::ffff,AS64500,ExampleNet
198.51.100.0,198.51.100.63,AS64501,OtherNet
EOF

    # A prior .orig so a .bk is created; on success it must be removed, and its
    # stale contents must not reappear in the fresh .orig.
    printf '198.51.100.7\n' > "${pfborig}${alias}.orig"
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'keeps BOTH the resolved domain IP and the ASN v4 range in .orig'
    When call whoisconvert
    The status should be success
    The stdout should include 'completed'
    # The domain entry's IP survives the later ASN entry...
    The contents of file "${pfborig}${alias}.orig" should include '203.0.113.5'
    # ...the ASN's v4 range is appended after it...
    The contents of file "${pfborig}${alias}.orig" should include '203.0.113.64-203.0.113.127'
    # ...the v6 row is filtered out in a _v4 run...
    The contents of file "${pfborig}${alias}.orig" should not include '2001:db8'
    # ...and the run is a clean success: no stale .bk data, no failure marker.
    The contents of file "${pfborig}${alias}.orig" should not include '198.51.100.7'
    The path "${pfborig}${alias}.fail" should not be exist
    The path "${pfborig}${alias}.bk" should not be exist
  End
End

Describe 'whoisconvert() accumulates prefixes across a multi-ASN list (issue #1075)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/whoisasn2.XXXXXX")"
    pfborig="${work}/orig/"; mkdir -p "$pfborig"
    alias="TwoAsnList"
    max="_v4"
    dedup="AS64500,AS64501"

    # No domain entries, but whoisconvert() references ${pathhost} only in the
    # domain branch -- still define it so an accidental call fails loudly.
    pathhost="${work}/host"
    printf '#!/bin/sh\nexit 1\n' > "$pathhost"
    chmod +x "$pathhost"

    pathasncsv="${work}/asn.csv"
    cat > "$pathasncsv" <<'EOF'
203.0.113.64,203.0.113.127,AS64500,ExampleNet
198.51.100.0,198.51.100.63,AS64501,OtherNet
EOF
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'keeps the FIRST ASN range when a second ASN entry follows'
    When call whoisconvert
    The status should be success
    The stdout should include 'Collecting ASN: AS64501'
    The contents of file "${pfborig}${alias}.orig" should include '203.0.113.64-203.0.113.127'
    The contents of file "${pfborig}${alias}.orig" should include '198.51.100.0-198.51.100.63'
    The path "${pfborig}${alias}.fail" should not be exist
  End
End

Describe 'whoisconvert() ASN branch keeps only v6 ranges in a _v6 run (issue #1075)'
  # Behaviour-preserving oracle for the vtype filter axis: a single-ASN v6 run
  # collected correctly even before the append fix -- pin it so the rework of
  # the collect/append block cannot regress the v6 side.
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/whoisasn6.XXXXXX")"
    pfborig="${work}/orig/"; mkdir -p "$pfborig"
    alias="V6List"
    max="_v6"
    dedup="AS64500"

    pathhost="${work}/host"
    printf '#!/bin/sh\nexit 1\n' > "$pathhost"
    chmod +x "$pathhost"

    pathasncsv="${work}/asn.csv"
    cat > "$pathasncsv" <<'EOF'
203.0.113.64,203.0.113.127,AS64500,ExampleNet
2001:db8::,2001:db8::ffff,AS64500,ExampleNet
EOF
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'lands the v6 range and filters the v4 row'
    When call whoisconvert
    The status should be success
    The stdout should include 'Collecting ASN: AS64500'
    The contents of file "${pfborig}${alias}.orig" should include '2001:db8::-2001:db8::ffff'
    The contents of file "${pfborig}${alias}.orig" should not include '203.0.113.64'
    The path "${pfborig}${alias}.fail" should not be exist
  End
End

Describe 'whoisconvert() ASN entry with no matching rows fails and restores (issue #1075)'
  # Failure-path pin: the per-entry success check moved from `[ -s .orig ]` to
  # the captured variable -- an ASN with no rows in asn.csv must still touch
  # .fail and, with nothing collected, restore the previous .orig from .bk.
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/whoisasnf.XXXXXX")"
    pfborig="${work}/orig/"; mkdir -p "$pfborig"
    alias="FailList"
    max="_v4"
    dedup="AS64599"

    pathhost="${work}/host"
    printf '#!/bin/sh\nexit 1\n' > "$pathhost"
    chmod +x "$pathhost"

    pathasncsv="${work}/asn.csv"
    cat > "$pathasncsv" <<'EOF'
203.0.113.64,203.0.113.127,AS64500,ExampleNet
EOF

    printf '198.51.100.7\n' > "${pfborig}${alias}.orig"
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'touches .fail and restores the last-good .orig'
    When call whoisconvert
    The status should be success
    The stdout should include 'Failed to collect ASN'
    The stdout should include 'Restoring previous data'
    The path "${pfborig}${alias}.fail" should be exist
    The contents of file "${pfborig}${alias}.orig" should equal '198.51.100.7'
  End
End

#shellcheck shell=sh
# whoisconvert() domain branch + found-accumulation (issue #714).
#
# Two coupled fixes are pinned here:
#
#   1) A failed `host` lookup used to be treated as success -- found=true was set
#      unconditionally and the lookup output piped straight into the .orig sink
#      with no exit-code check, so a failed DNS lookup landed as DATA (e.g. the
#      literal "3(NXDOMAIN)" tail of "Host x not found: 3(NXDOMAIN)"). The domain
#      branch now checks host(1)'s exit code and keeps only "has (IPv6) address"
#      lines; on failure it touches an alias.fail marker and collects nothing.
#
#   2) ${found} ACCUMULATES across the comma-list loop: it is initialised false
#      ONCE before the loop and only ever set true on a successful entry, never
#      reset false inside the loop. So found=true iff AT LEAST ONE entry resolved
#      (keep the collected data) and false iff nothing did (restore the .bk).
#      Previously each iteration overwrote found, so a multi-entry list whose LAST
#      entry failed discarded the good data collected from earlier entries.

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
    # ...the previously-good data is restored (nothing resolved -> found stays false)...
    The contents of file "${pfborig}${alias}.orig" should equal '203.0.113.9'
    # ...and the raw host(1) error text never lands in .orig as if it were an IP.
    The contents of file "${pfborig}${alias}.orig" should not include '3(NXDOMAIN)'
  End
End

Describe 'whoisconvert() accumulates found across a multi-entry list (issue #714)'
  # RED→GREEN oracle for the found-accumulation fix: a comma list whose FIRST
  # entry resolves and LAST entry fails must KEEP the first entry's IP, not
  # discard it by restoring the .bk (which the per-iteration found=false reset
  # caused, since found ended up reflecting only the failing last entry).
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/whoismulti.XXXXXX")"
    pfborig="${work}/orig/"; mkdir -p "$pfborig"
    alias="MultiList"
    max="_v4"
    # good FIRST, failing entry LAST -- the ordering that exposes the bug.
    dedup="good-one.example,bad-two.example"

    # host(1) stand-in that branches on the queried name ($3 = the host arg):
    # a name containing "good" resolves, anything else NXDOMAINs.
    pathhost="${work}/host"
    cat > "$pathhost" <<'EOF'
#!/bin/sh
name="$3"
case "$name" in
	*good*) echo "$name has address 203.0.113.5"; exit 0 ;;
	*)      echo "Host $name not found: 3(NXDOMAIN)"; exit 1 ;;
esac
EOF
    chmod +x "$pathhost"

    # An OLD .orig so a .bk is created at the top of whoisconvert(); if found
    # wrongly ended false, the restore would bring this back.
    printf '198.51.100.7\n' > "${pfborig}${alias}.orig"
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'keeps the resolved entry IP when a later entry fails (does not restore the .bk)'
    When call whoisconvert
    The status should be success
    The stdout should include 'completed'
    # The good entry's IP is kept...
    The contents of file "${pfborig}${alias}.orig" should include '203.0.113.5'
    # ...the stale .bk is NOT restored over it (found stayed true via the good entry)...
    The contents of file "${pfborig}${alias}.orig" should not include '198.51.100.7'
    # ...and the failing entry is still noted with a .fail marker.
    The path "${pfborig}${alias}.fail" should be exist
  End
End

Describe 'whoisconvert() success path keeps the resolved IP with no failure marker (issue #714)'
  # Green regression pin for a fully-resolving lookup: the valid "has address"
  # line must survive the exit-code check + the grep filter (a filter that wrongly
  # dropped it would leave .orig empty -> found false -> a .fail marker, failing
  # these assertions).
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/whoisok.XXXXXX")"
    pfborig="${work}/orig/"; mkdir -p "$pfborig"
    alias="OkList"
    max="_v4"
    dedup="good-solo.example"

    pathhost="${work}/host"
    cat > "$pathhost" <<'EOF'
#!/bin/sh
echo "$3 has address 203.0.113.5"
exit 0
EOF
    chmod +x "$pathhost"

    # A prior .orig so a .bk is created; on success it must be removed.
    printf '198.51.100.7\n' > "${pfborig}${alias}.orig"
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'lands the resolved IP in .orig, leaves no .fail, and removes the .bk'
    When call whoisconvert
    The status should be success
    The stdout should include 'completed'
    The contents of file "${pfborig}${alias}.orig" should include '203.0.113.5'
    The path "${pfborig}${alias}.fail" should not be exist
    The path "${pfborig}${alias}.bk" should not be exist
  End
End

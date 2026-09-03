#shellcheck shell=sh
# issue #1263: cat concatenates BYTES, not records. When a multi-file `cat`
# pipeline's non-final input lacks a trailing newline, its last line welds
# onto the next file's first line -- corrupting a record and undercounting.
# closingprocess()/processet() switched every multi-file `cat` to `awk 1`
# (a drop-in that supplies the missing terminator at no extra fork).
#
# Fixtures below use files that ALL lack a trailing newline (not just the
# first) so the weld reproduces deterministically regardless of `find`'s
# filesystem enumeration order between same-directory files -- with only ONE
# file unterminated, whether IT lands first or last in `find`'s listing (and
# therefore whether a weld occurs at all) depends on that order.

Describe 'closingprocess() Original IP count: aggcount sum never welds digits together (issue #1263 site 3)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/aggweld.XXXXXX")"
    pfborig="${work}/orig/"; pfbdeny="${work}/deny/"
    pfbpermit="${work}/permit/"; pfbmatch="${work}/match/"; pfbnative="${work}/native/"
    mkdir -p "$pfborig" "$pfbdeny" "$pfbpermit" "$pfbmatch" "$pfbnative"
    masterfile="${work}/masterfile"; mastercat="${work}/mastercat"
    tempfile="${work}/t1"; errorlog="${work}/err.log"; now="now"
    ip_placeholder2="127.0.0.1"
    pathpfctl="${work}/pfctl"; printf '#!/bin/sh\n' > "$pathpfctl"; chmod +x "$pathpfctl"
    alias="off"
    # Three sidecars, ALL unterminated -- true sum is 600; a cat weld glues
    # at least two of them into one bogus number (e.g. the nine-character
    # concatenation of "100"+"200"+"300" in whatever order `find` returns
    # them), never 600.
    printf '100' > "${pfborig}FeedA_v4.aggcount"
    printf '200' > "${pfborig}FeedB_v4.aggcount"
    printf '300' > "${pfborig}FeedC_v4.aggcount"
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'sums 100+200+300=600, never a digit-welded number'
    When call closingprocess
    The status should be success
    The stdout should include '[ Original IP count   ]  [ 600 ]'
  End
End

Describe 'closingprocess() Original IP count: whitespace sidecar names stay whole (issue #3176)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/aggspace.XXXXXX")"
    pfborig="${work}/orig/"; pfbdeny="${work}/deny/"
    pfbpermit="${work}/permit/"; pfbmatch="${work}/match/"; pfbnative="${work}/native/"
    mkdir -p "$pfborig" "$pfbdeny" "$pfbpermit" "$pfbmatch" "$pfbnative"
    masterfile="${work}/masterfile"; mastercat="${work}/mastercat"
    tempfile="${work}/t1"; errorlog="${work}/err.log"; now="now"
    ip_placeholder2="127.0.0.1"
    pathpfctl="${work}/pfctl"; printf '#!/bin/sh\n' > "$pathpfctl"; chmod +x "$pathpfctl"
    alias='off'
    printf '10' > "${pfborig}Feed A_v4.aggcount"
    printf '5'  > "${pfborig}FeedB_v4.aggcount"
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'sums sidecars without splitting a whitespace-bearing pathname'
    When call closingprocess
    The status should be success
    The stdout should include '[ Original IP count   ]  [ 15 ]'
  End

  It 'marks the original count incomplete when its producer fails (issue #3176)'
    mkdir -p "${work}/bin"
    real_awk="$(command -v awk)"
    cat > "${work}/bin/awk" <<EOF
#!/bin/sh
case " \$* " in
  *aggcount*) printf '10\n'; exit 2 ;;
  *) exec "${real_awk}" "\$@" ;;
esac
EOF
    chmod +x "${work}/bin/awk"
    PATH="${work}/bin:${PATH}"

    When call closingprocess
    The status should be success
    The stdout should include '[ Original IP count   ]  [ incomplete ]'
    The stdout should include 'original count'
  End
End

Describe 'closingprocess() Original IP count: raw *_v4.orig fallback never welds lines together (issue #1263 site 4)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/origweld.XXXXXX")"
    pfborig="${work}/orig/"; pfbdeny="${work}/deny/"
    pfbpermit="${work}/permit/"; pfbmatch="${work}/match/"; pfbnative="${work}/native/"
    mkdir -p "$pfborig" "$pfbdeny" "$pfbpermit" "$pfbmatch" "$pfbnative"
    masterfile="${work}/masterfile"; mastercat="${work}/mastercat"
    tempfile="${work}/t1"; errorlog="${work}/err.log"; now="now"
    ip_placeholder2="127.0.0.1"
    pathpfctl="${work}/pfctl"; printf '#!/bin/sh\n' > "$pathpfctl"; chmod +x "$pathpfctl"
    alias="off"
    # No .aggcount sidecars -> counto's first pass sums to 0 -> the raw
    # *_v4.orig fallback runs. Three feeds, ALL unterminated (one IP each);
    # true count is 3. A cat weld fuses all three into ONE line (there is no
    # newline anywhere in the concatenated stream), reporting 1.
    printf '1.1.1.1' > "${pfborig}FeedA_v4.orig"
    printf '2.2.2.2' > "${pfborig}FeedB_v4.orig"
    printf '3.3.3.3' > "${pfborig}FeedC_v4.orig"
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'counts the true 3 records, never the welded 1'
    When call closingprocess
    The status should be success
    The stdout should include '[ Original IP count   ]  [ 3 ]'
    The stdout should not include '[ Original IP count   ]  [ 1 ]'
  End
End

Describe 'closingprocess() Database Sanity check: deny-folder re-scan never welds records together (issue #1263 sites 5/6)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/denyweld.XXXXXX")"
    pfborig="${work}/orig/"; pfbdeny="${work}/deny/"
    pfbpermit="${work}/permit/"; pfbmatch="${work}/match/"; pfbnative="${work}/native/"
    mkdir -p "$pfborig" "$pfbdeny" "$pfbpermit" "$pfbmatch" "$pfbnative"
    masterfile="${work}/masterfile"; mastercat="${work}/mastercat"
    tempfile="${work}/t1"; errorlog="${work}/err.log"; now="now"
    ip_placeholder2="127.0.0.1"
    pathpfctl="${work}/pfctl"; printf '#!/bin/sh\n' > "$pathpfctl"; chmod +x "$pathpfctl"
    alias="on"
    # mastercat (s1's source) is a clean, properly-terminated 3-row file --
    # the true membership the deny folder must match.
    printf 'FeedA_v4 192.0.2.1\nFeedB_v4 192.0.2.2\nFeedC_v4 192.0.2.3\n' > "$masterfile"
    printf '192.0.2.1\n192.0.2.2\n192.0.2.3\n' > "$mastercat"
    # The deny folder re-scan (s2/s4) -- 3 files, ALL unterminated. A cat
    # weld fuses all three IPs into ONE bogus record (no true IP survives
    # verbatim), so s2 undercounts to 1 and the sanity check spuriously FAILS
    # even though the real membership matches.
    printf '192.0.2.1' > "${pfbdeny}FeedA_v4.txt"
    printf '192.0.2.2' > "${pfbdeny}FeedB_v4.txt"
    printf '192.0.2.3' > "${pfbdeny}FeedC_v4.txt"
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'passes the sanity check -- s2 counts the true 3 deny records, no fused garbage record'
    When call closingprocess
    The status should be success
    The stdout should include 'Database Sanity check [  PASSED  ]'
    The stdout should not include 'FAILED'
  End
End

# A2 (data-producing site): the s4 "Deny folder/Masterfile uniq check" cross-file
# duplicate detector (sort | uniq -d) is itself a real regression channel for the
# weld -- a fused garbage line is unique (it appears once), so a genuine
# cross-file duplicate that gets welded away is SILENTLY MISSED, not merely
# miscounted. Both deny files hold the identical IP so the weld's output is
# deterministic regardless of find's enumeration order between them (same glued
# string either way): the true duplicate is invisible pre-fix, caught post-fix.
Describe 'closingprocess() deny-folder duplicate detection: a real cross-file duplicate is never hidden by a weld (issue #1263 site 6)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/denydup.XXXXXX")"
    pfborig="${work}/orig/"; pfbdeny="${work}/deny/"
    pfbpermit="${work}/permit/"; pfbmatch="${work}/match/"; pfbnative="${work}/native/"
    mkdir -p "$pfborig" "$pfbdeny" "$pfbpermit" "$pfbmatch" "$pfbnative"
    masterfile="${work}/masterfile"; mastercat="${work}/mastercat"
    tempfile="${work}/t1"; errorlog="${work}/err.log"; now="now"
    ip_placeholder2="127.0.0.1"
    pathpfctl="${work}/pfctl"; printf '#!/bin/sh\n' > "$pathpfctl"; chmod +x "$pathpfctl"
    alias="on"
    printf 'x 1.1.1.1\n' > "$masterfile"
    printf '1.1.1.1\n' > "$mastercat"
    # The SAME IP in both deny files, unterminated -- a real cross-file
    # duplicate that `sort | uniq -d` must report.
    printf '192.0.2.5' > "${pfbdeny}FeedA_v4.txt"
    printf '192.0.2.5' > "${pfbdeny}FeedB_v4.txt"
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'reports the real duplicate IP -- the weld cannot hide it inside a fused record'
    When call closingprocess
    The status should be success
    The stdout should include 'Deny folder/Masterfile uniq check'
    The stdout should include '192.0.2.5'
  End
End

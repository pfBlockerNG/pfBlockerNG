#shellcheck shell=sh
# "Original" metric reflects the CIDR-aggregated feed, not the raw download.
#
# duplicate() prints the per-feed "Original / Master / Final" table and closingprocess()
# prints the aggregate "Original IP count". Both used to report the RAW .orig size, so with
# CIDR aggregation enabled they over-reported the input (the table read raw -> master -> final,
# folding the aggregation collapse into the apparent dedup delta). The fix sources "Original"
# from the size ENTERING de-duplication (the aggregated .txt), persisted per feed as a
# {alias}.aggcount sidecar that closingprocess() sums.

Describe 'duplicate() Original = de-dup input (aggregated), not raw .orig'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/origcount.XXXXXX")"
    pfbdeny="${work}/deny/"; pfborig="${work}/orig/"
    mkdir -p "$pfbdeny" "$pfborig"
    masterfile="${work}/masterfile"; mastercat="${work}/mastercat"
    tempfile="${work}/t1"; tempfile2="${work}/t2"
    errorlog="${work}/err.log"
    # grepcidr stub: -vf <file> <target> -> target lines not present (literal) in <file>.
    pathgrepcidr="${work}/grepcidr"
    printf '#!/bin/sh\ngrep -vxF -f "$2" "$3"\n' > "$pathgrepcidr"; chmod +x "$pathgrepcidr"
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'reports the aggregated input size and persists it to {alias}.aggcount'
    alias="MYLIST"
    # The aggregated feed entering de-duplication: 4 entries.
    printf '1.2.3.4\n5.6.7.8\n9.9.9.9\n10.0.0.1\n' > "${pfbdeny}${alias}.txt"
    # The RAW download (77 lines) -- what the pre-fix "Original" wrongly reported.
    i=1; while [ "$i" -le 77 ]; do printf 'raw-%s\n' "$i" >> "${pfborig}${alias}.orig"; i=$((i + 1)); done
    # A different alias keeps masterfile non-empty (so the cross-feed grepcidr prune runs);
    # mastercat lists 9.9.9.9, so the prune drops it -> Final (3) differs from Original (4).
    printf 'OTHER 8.8.8.8\n' > "$masterfile"
    printf '9.9.9.9\n' > "$mastercat"

    When call duplicate
    The status should be success
    # Original is the aggregated input (4), NOT the raw .orig count (77).
    The contents of file "${pfborig}${alias}.aggcount" should equal "4"
    The stdout should include 'Final'
    The stdout should not include '77'
  End
End

Describe 'closingprocess() aggregate Original = sum of per-feed aggregated counts'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/origclose.XXXXXX")"
    pfborig="${work}/orig/"; pfbdeny="${work}/deny/"
    pfbpermit="${work}/permit/"; pfbmatch="${work}/match/"; pfbnative="${work}/native/"
    mkdir -p "$pfborig" "$pfbdeny" "$pfbpermit" "$pfbmatch" "$pfbnative"
    masterfile="${work}/masterfile"; mastercat="${work}/mastercat"
    tempfile="${work}/t1"; errorlog="${work}/err.log"; now="now"
    ip_placeholder2="127.0.0.1"
    pathpfctl="${work}/pfctl"; printf '#!/bin/sh\n' > "$pathpfctl"; chmod +x "$pathpfctl"
    printf 'a 1.1.1.1\nb 2.2.2.2\n' > "$masterfile"
    printf '1.1.1.1\n2.2.2.2\n' > "$mastercat"
    # Raw originals (large) -- what the pre-fix aggregate "Original" summed.
    i=1; while [ "$i" -le 99 ]; do printf 'r%s\n' "$i" >> "${pfborig}FeedA_v4.orig"; i=$((i + 1)); done
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'sums the .aggcount sidecars (aggregated), not the raw *_v4.orig total'
    alias="on"
    printf '10\n' > "${pfborig}FeedA_v4.aggcount"
    printf '5\n'  > "${pfborig}FeedB_v4.aggcount"
    When call closingprocess
    The status should be success
    The stdout should include '[ Original IP count   ]  [ 15 ]'
    The stdout should not include '[ 99 ]'
  End

  It 'falls back to the raw *_v4.orig total when no sidecars exist (de-dup ran no feeds)'
    alias="on"
    # No .aggcount sidecars -> duplicate() never ran -> report the raw total (99).
    When call closingprocess
    The status should be success
    The stdout should include '[ Original IP count   ]  [ 99 ]'
  End
End

#shellcheck shell=sh
# "Original" metric reflects the CIDR-aggregated feed, not the raw download.
#
# closingprocess() prints the aggregate "Original IP count", sourced from the size ENTERING
# de-duplication (the aggregated .txt) rather than the raw .orig download -- persisted per
# feed as a {alias}.aggcount sidecar (written today by pfb_ip_recompute_write_snapshot(),
# pfblockerng.inc) that closingprocess() sums. Pre-fix, both this and the now-retired
# duplicate()'s own per-feed "Original / Master / Final" table read the raw .orig size, so
# with CIDR aggregation enabled they over-reported the input.

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
    # No .aggcount sidecars -> no snapshot was ever written -> report the raw total (99).
    When call closingprocess
    The status should be success
    The stdout should include '[ Original IP count   ]  [ 99 ]'
  End
End

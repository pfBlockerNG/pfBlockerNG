#shellcheck shell=sh
# duplicate() strips an alias's own prior masterfile rows before re-adding its
# current data. The grep that finds those rows used to be unanchored
# (`grep "${alias}[[:space:]]"`), so a shorter alias that is a SUFFIX of
# another over-matches: alias "Ads_v4" also matches the row for a sibling
# alias "BadAds_v4" (its row ends "...Ads_v4 20.0.0.0/24" once the leading
# "Bad" is skipped by an unanchored search), so the sibling's masterfile row
# was pulled into the removal set and silently dropped (issue #714). Anchoring
# the grep to the start of the line (masterfile rows always begin with the
# alias at column 0) fixes it; the same bug + fix applies to the two sibling
# sites in remove() and suppress().

Describe 'duplicate() masterfile grep is anchored (issue #714 suffix over-match)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/mfanchor.XXXXXX")"
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

  It 'never strips a sibling masterfile row whose alias is a suffix of the current one'
    alias="Ads_v4"
    # Ads_v4's own prior row, plus an UNRELATED sibling "BadAds_v4" whose row
    # tail ("Ads_v4 20.0.0.0/24") is what an unanchored grep for "Ads_v4"
    # wrongly matches too.
    printf 'Ads_v4 10.0.0.0/24\nBadAds_v4 20.0.0.0/24\n' > "$masterfile"
    printf '10.0.0.0/24\n' > "${pfbdeny}${alias}.txt"

    When call duplicate
    The status should be success
    # duplicate() also prints an Original/Master/Final sanity table; not under
    # test here, just consumed so shellspec doesn't flag it as unexpected output.
    The stdout should include 'Master'
    # Then BadAds_v4's row must survive untouched -- it was never Ads_v4's to remove.
    The contents of file "$masterfile" should include 'BadAds_v4 20.0.0.0/24'
  End
End

#shellcheck shell=sh
# pfblockerng.sh fail-open feed-list redirects (issue #713 bug 8, family of 12
# sites in two producer classes -- the original 9 plus 3 the initial fix missed:
# suppress()'s dedup='on' masterfile block, process255(), and reputation_max()'s
# ccblack='block' arm). A producer (grepcidr / awk dedup, or -- since ADR-53
# Phase 3 -- iprange for suppress() specifically) was redirected into a file
# consumed downstream with NO exit-status gating, so a producer error
# truncated/overwrote the live list to empty/partial:
#
#   Class A (grepcidr, or iprange for suppress() post-ADR-53): rc 0 = success
#   (for iprange, INCLUDING a legitimately-empty result -- no grepcidr-style
#   "rc 1 = empty" quirk); any other rc = a real engine error (must keep the
#   previous target untouched). suppress() held the worst case -- a direct
#   "<producer> ... > livelist" redirect with no temp at all, truncating the
#   live list before the producer even ran.
#
#   Class B (awk dedup): awk has no "empty output = error" quirk -- rc 0 is
#   always a legitimate result (including a genuinely empty dedup), non-zero is
#   always a real error. The unconditional "awk ... > tmp; mv -f tmp target"
#   became "awk ... > tmp && mv -f tmp target".
#
# Each scenario asserts the BEFORE state (prior content) so a pass proves the
# fix caused the preservation, not an accidental empty-target coincidence.
#
# suppress()'s OWN producer switched from grepcidr to iprange in ADR-53 Phase
# 3 (tests/shell/pfblockerng_suppress_spec.sh is the dedicated, comprehensive
# oracle for that engine swap) -- its Class A/B Describe blocks below follow
# suit (pathaggregate/IPRANGE_MODE), staying deliberately redundant with that
# file's own rc-gating cases, not duplicative (each proves the contract from
# its own file's self-contained narrative).

Describe 'pfblockerng.sh fail-open feed-list redirects (issue #713 bug 8)'
  BeforeAll 'pfb_source; SHELLSPEC_REAL_AWK="$(command -v awk)"; export SHELLSPEC_REAL_AWK'

  # ---- iprange shim (suppress()'s producer post-ADR-53): exit code/output
  # selected via IPRANGE_MODE ----
  #   success -> two matches on stdout, rc 0
  #   error   -> a real iprange error (e.g. a missing/unloadable ipset), rc 1
  #              (unlike grepcidr, iprange has no separate "rc 1 = legitimate
  #              empty" case to simulate -- rc 0 covers an empty result too)
  write_pathaggregate_shim() {
    cat > "$1" <<'SHIM'
#!/bin/sh
case "${IPRANGE_MODE:-}" in
	success) printf '192.0.2.1\n192.0.2.2\n'; exit 0 ;;
	error) echo 'iprange: simulated error (missing/unloadable ipset)' >&2; exit 1 ;;
	*) exit 1 ;;
esac
SHIM
    chmod +x "$1"
  }

  # ---- awk shim: awk is invoked bare (base utility, per repo convention), so
  # its exit status is controlled by prepending a shim dir to PATH rather than
  # a path* variable. AWK_MODE=error forces a real non-zero exit with no
  # stdout; anything else delegates to the real awk.
  setup_awk_shim() {
    mkdir -p "$1"
    cat > "$1/awk" <<SHIM
#!/bin/sh
if [ "\${AWK_MODE:-real}" = 'error' ]; then
	echo 'awk: simulated failure' >&2
	exit 2
fi
exec "${SHELLSPEC_REAL_AWK}" "\$@"
SHIM
    chmod +x "$1/awk"
  }

  # Like setup_awk_shim but fails ONLY the dedup pass (awk program text holds
  # FNR==NR) under AWK_MODE=error. process255()/reputation_max() compute their
  # /24 offender set with an EARLIER, unrelated awk; a blanket shim would fail
  # that first and no-op the whole function, so the test would prove nothing.
  setup_awk_shim_dedup() {
    mkdir -p "$1"
    cat > "$1/awk" <<SHIM
#!/bin/sh
for _a in "\$@"; do
	case "\${_a}" in *FNR==NR*) _dedup=1 ;; esac
done
if [ "\${AWK_MODE:-real}" = 'error' ] && [ "\${_dedup:-0}" = '1' ]; then
	echo 'awk: simulated dedup failure' >&2
	exit 2
fi
exec "${SHELLSPEC_REAL_AWK}" "\$@"
SHIM
    chmod +x "$1/awk"
  }

  Describe 'suppress() -- Class A worst case (direct redirect into the LIVE published list)'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbsupp.XXXXXX")"
      max="${work}"
      alias='TestList_v4'
      pfbsuppression="${work}/suppression.txt"
      printf '198.51.100.0/24\n' > "${pfbsuppression}"
      tmpdir="${work}"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      true > "${masterfile}"
      dedup='off'
      errorlog="${work}/error.log"; true > "${errorlog}"
      pathaggregate="${work}/iprange"
      write_pathaggregate_shim "${pathaggregate}"
      livelist="${work}/${alias}.txt"
      printf 'PRIOR-1\nPRIOR-2\n' > "${livelist}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'keeps the live list UNCHANGED when iprange errors (rc!=0) -- pre-fix this truncated it to empty'
      # When: iprange errors.
      IPRANGE_MODE='error'; export IPRANGE_MODE
      When call silently suppress
      # Then: the prior content survives -- and the error is logged, not swallowed.
      The status should be success
      The contents of file "${livelist}" should equal "$(printf 'PRIOR-1\nPRIOR-2')"
      The contents of file "${errorlog}" should include 'iprange error'
    End

    It 'publishes the new content on iprange success'
      IPRANGE_MODE='success'; export IPRANGE_MODE
      When call silently suppress
      The status should be success
      The contents of file "${livelist}" should equal "$(printf '192.0.2.1\n192.0.2.2')"
    End
  End

  Describe 'suppress() -- Class B (dedup="on" masterfile block, the site the initial bug-8 fix missed)'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbsuppdd.XXXXXX")"
      max="${work}"
      alias='DedupList_v4'
      pfbsuppression="${work}/suppression.txt"
      printf '198.51.100.0/24\n' > "${pfbsuppression}"
      tmpdir="${work}"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      printf 'DedupList_v4 PRIOR-1\nDedupList_v4 PRIOR-2\nOtherList_v4 203.0.113.5\n' > "${masterfile}"
      dedup='on'
      errorlog="${work}/error.log"; true > "${errorlog}"
      pathaggregate="${work}/iprange"
      write_pathaggregate_shim "${pathaggregate}"
      livelist="${work}/${alias}.txt"
      printf 'PRIOR-1\nPRIOR-2\n' > "${livelist}"
      awkshim="${work}/bin"
      setup_awk_shim "${awkshim}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'keeps the PRIOR masterfile rows when awk errors -- pre-fix this truncated masterfile, losing them all (incl. the unrelated OtherList_v4 row)'
      IPRANGE_MODE='success'; AWK_MODE='error'; export IPRANGE_MODE AWK_MODE
      PATH="${awkshim}:${PATH}"
      When call silently suppress
      The status should be success
      # suppress()'s trailing sed always re-appends the (here: iprange-succeeded)
      # fresh list content regardless of the dedup outcome -- pre-existing,
      # unrelated to this fix -- so the fix's proof is that NONE of the prior
      # rows are lost, not that the file is byte-identical to its pre-call state.
      The contents of file "${masterfile}" should include 'DedupList_v4 PRIOR-1'
      The contents of file "${masterfile}" should include 'DedupList_v4 PRIOR-2'
      The contents of file "${masterfile}" should include 'OtherList_v4 203.0.113.5'
    End

    It 'dedups masterfile (drops the stale alias rows, keeps the unrelated one, appends the fresh list) on awk success'
      IPRANGE_MODE='success'; AWK_MODE='real'; export IPRANGE_MODE AWK_MODE
      PATH="${awkshim}:${PATH}"
      When call silently suppress
      The status should be success
      The contents of file "${masterfile}" should include 'OtherList_v4 203.0.113.5'
      The contents of file "${masterfile}" should not include 'PRIOR-1'
      The contents of file "${masterfile}" should include 'DedupList_v4 192.0.2.1'
      The contents of file "${masterfile}" should include 'DedupList_v4 192.0.2.2'
    End
  End

  Describe 'remove() -- Class B (awk masterfile dedup, no grepcidr involved)'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbrmfo.XXXXXX")"
      alias='Benign'
      cc='RmList_v4,'
      pfborig="${work}/orig/"; pfbdeny="${work}/deny/"; pfbmatch="${work}/match/"
      pfbpermit="${work}/permit/"; pfbnative="${work}/native/"
      mkdir -p "${pfborig}" "${pfbdeny}" "${pfbmatch}" "${pfbpermit}" "${pfbnative}"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      tempfile="${work}/t1"; tempfile2="${work}/t2"
      awkshim="${work}/bin"
      setup_awk_shim "${awkshim}"
      printf 'RmList_v4 192.0.2.20\nOtherList_v4 203.0.113.9\n' > "${masterfile}"
      true > "${pfborig}RmList_v4.txt"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'keeps masterfile UNCHANGED when awk errors -- pre-fix this truncated masterfile (remove() then deletes an empty masterfile entirely)'
      AWK_MODE='error'; export AWK_MODE
      PATH="${awkshim}:${PATH}"
      When call silently remove
      The status should be success
      The contents of file "${masterfile}" should equal "$(printf 'RmList_v4 192.0.2.20\nOtherList_v4 203.0.113.9')"
    End

    It 'dedups masterfile (drops the removed alias row, keeps the unrelated one) on awk success'
      AWK_MODE='real'; export AWK_MODE
      PATH="${awkshim}:${PATH}"
      When call silently remove
      The status should be success
      The contents of file "${masterfile}" should equal 'OtherList_v4 203.0.113.9'
    End
  End

  Describe 'process255() -- Class B (dedup awk redirected straight into the LIVE deny list)'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbp255.XXXXXX")"
      alias='P255List_v4'
      pfbdeny="${work}/deny/"; mkdir -p "${pfbdeny}"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dedupfile="${work}/t3"
      # >253 hosts inside 10.0.0.0/24 trips process255()'s collapse path; a
      # PRIOR-MARKER row (outside that /24) stands in for unrelated live content.
      { i=1; while [ "${i}" -le 254 ]; do echo "10.0.0.${i}"; i=$((i + 1)); done; echo 'PRIOR-MARKER'; } > "${pfbdeny}${alias}.txt"
      awkshim="${work}/bin"
      setup_awk_shim_dedup "${awkshim}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'keeps the live deny list UNCHANGED when the dedup awk errors -- pre-fix the direct redirect truncated it before the awk even ran, losing every prior host'
      AWK_MODE='error'; export AWK_MODE
      PATH="${awkshim}:${PATH}"
      When call silently process255
      The status should be success
      # Then: the prior hosts survive the failed collapse (only the /24 summary is appended).
      The contents of file "${pfbdeny}${alias}.txt" should include '10.0.0.5'
      The contents of file "${pfbdeny}${alias}.txt" should include 'PRIOR-MARKER'
    End

    It 'collapses the /24 (drops the individual hosts, appends the summary) on awk success -- proves the error branch is a real fail-safe, not an always-preserve no-op'
      AWK_MODE='real'; export AWK_MODE
      PATH="${awkshim}:${PATH}"
      When call silently process255
      The status should be success
      The contents of file "${pfbdeny}${alias}.txt" should not include '10.0.0.5'
      The contents of file "${pfbdeny}${alias}.txt" should include '10.0.0.0/24'
      The contents of file "${pfbdeny}${alias}.txt" should include 'PRIOR-MARKER'
    End
  End

  Describe 'reputation_max() -- Class B (ccblack="block" dedup awk redirected into the LIVE deny list)'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbrmax.XXXXXX")"
      alias='RMaxList_v4'
      pfbdeny="${work}/deny/"; pfbmatch="${work}/match/"; mkdir -p "${pfbdeny}" "${pfbmatch}"
      tempfile="${work}/r1"; tempfile2="${work}/r2"; dupfile="${work}/r3"
      matchfile="${work}/r4"; tempmatchfile="${work}/r5"
      true > "${dupfile}"; true > "${matchfile}"; true > "${tempmatchfile}"
      max=253; cc='ZZ,'; ccwhite='block'; ccblack='block'; dedup='off'; count=0; countr=0
      # An empty GeoIP answer routes every repeat offender down the block/dupfile
      # path (the unknown-country branch), reaching the ccblack='block' dedup awk.
      pathgeoip="${work}/mmdblookup"; pathgeoipdat="${work}/geo.mmdb"; true > "${pathgeoipdat}"
      make_geoip_stub "${pathgeoip}" ''
      { i=1; while [ "${i}" -le 254 ]; do echo "10.0.0.${i}"; i=$((i + 1)); done; echo 'PRIOR-MARKER'; } > "${pfbdeny}${alias}.txt"
      awkshim="${work}/bin"
      setup_awk_shim_dedup "${awkshim}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'keeps the live deny list UNCHANGED when the ccblack="block" dedup awk errors -- pre-fix the direct redirect truncated it, losing every prior host'
      AWK_MODE='error'; export AWK_MODE
      PATH="${awkshim}:${PATH}"
      When call silently reputation_max
      The status should be success
      The contents of file "${pfbdeny}${alias}.txt" should include '10.0.0.5'
      The contents of file "${pfbdeny}${alias}.txt" should include 'PRIOR-MARKER'
    End

    It 'removes the country-classified hosts and appends the /24 summary on awk success -- proves the error branch is a real fail-safe, not an always-preserve no-op'
      AWK_MODE='real'; export AWK_MODE
      PATH="${awkshim}:${PATH}"
      When call silently reputation_max
      The status should be success
      The contents of file "${pfbdeny}${alias}.txt" should not include '10.0.0.5'
      The contents of file "${pfbdeny}${alias}.txt" should include '10.0.0.0/24'
      The contents of file "${pfbdeny}${alias}.txt" should include 'PRIOR-MARKER'
    End
  End
End

#shellcheck shell=sh
# suppress() oracle (ADR-53 Phase 1) -- pins TODAY's IP-suppression semantics,
# including its known containing-entry defect, as a regression baseline for
# Phase 3's iprange --except rewrite. This spec is BEHAVIOUR-PRESERVING: it
# adds no src/ change and must stay green before and after this phase; Phase 3
# flips exactly the "containing-entry silent no-op" assertion below (§2) from
# a no-op pin to a real-carve assertion, red on pre-Phase-3 code, green after.
#
# suppress() (pfblockerng.sh) carves suppression-list entries out of a deny
# member file (${max}/${alias}.txt), gated on a non-empty ${pfbsuppression}
# file. Per suppression entry (always a /32 or /24 today -- pfblockerng_ip.php
# validation): a bare-host member token is removed by the trailing
# `grepcidr -vf` whole-token pass; a member token that is the EXACT containing
# /24 of a /32 suppression entry is exploded into 255 individual hosts (a
# literal grep -F string match against "<prefix>.0/24", entirely independent
# of grepcidr) minus the suppressed octet, deduped via ${dupfile} so a second
# /32 inside the same /24 does not re-explode; but a member token WIDER than
# /24 (a /16, say) containing the suppressed host is a SILENT NO-OP -- ADR-53
# §1.2 proved live that grepcidr does not split/pierce a containing CIDR, so
# the suppressed host stays blocked with no warning. That defect is pinned
# below as today's oracle, not fixed here.
#
# Note: tests/shell/pfblockerng_fail_open_redirect_spec.sh already pins
# suppress()'s #713 fail-open rc-gating (grepcidr rc>=2 keep-previous; the
# dedup="on" masterfile awk redirect) as part of a cross-function "fail-open
# redirect" family (it also covers duplicate()/remove()/process255()/
# reputation_max()). This file is the dedicated, comprehensive suppress()
# semantics pin (bare-token removal, the /24 explode + dupfile dedup guard,
# the containing-entry defect, absent/empty gating, the stats table) and
# re-asserts the #713 rc gating here too so it is self-contained -- the two
# files' fail-safe cases are deliberately redundant, not duplicative (each
# proves it from its own file's narrative).

Describe 'suppress() (ADR-53 Phase 1 oracle)'
  BeforeAll 'pfb_source'

  # ---- grepcidr shim ----
  # Fake grepcidr -vf <filter> <target> for the suppress() oracle.
  #
  # Default mode performs plain ADDRESS-EQUALITY filtering with the mask
  # stripped from both sides: every suppression entry the UI accepts today is
  # a /32 host (mask enforcement at pfblockerng_ip.php:159), so real
  # grepcidr's CIDR-containment test ("is this target line's range a subset
  # of a filter CIDR") collapses to "is this target line's address exactly
  # the suppressed host". A bare host, or a target line written as that exact
  # /32, is REMOVED -- grepcidr's proven whole-token/host removal (ADR-53
  # §1.2, both address families). Any WIDER target CIDR (a /16 or /24 line)
  # can never equal a single suppressed host address, so it survives
  # completely untouched -- the exact containing-entry silent no-op ADR-53
  # §1.2 proved live and this suite pins as today's oracle.
  #
  # GREPCIDR_MODE overrides the default for the #713 fail-safe rc-gating
  # cases: empty -> a LEGITIMATE "everything suppressed" empty result, rc 1;
  # error -> a real grepcidr error (e.g. malformed filter file), rc 2.
  write_grepcidr_shim() {
    cat > "$1" <<'SHIM'
#!/bin/sh
case "${GREPCIDR_MODE:-}" in
	empty) exit 1 ;;
	error) echo 'grepcidr: simulated malformed filter' >&2; exit 2 ;;
esac

filter="$2"
target="$3"
faddrs="$(sed 's#/.*##' "${filter}")"
while IFS= read -r line; do
	[ -z "${line}" ] && continue
	addr="${line%%/*}"
	if ! printf '%s\n' "${faddrs}" | grep -qxF "${addr}"; then
		printf '%s\n' "${line}"
	fi
done < "${target}"
SHIM
    chmod +x "$1"
  }

  Describe 'a — suppression file absent or empty: early return, member file untouched'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbsuppa.XXXXXX")"
      max="${work}"
      alias='TestList_v4'
      pfbsuppression="${work}/suppression.txt"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      : > "${masterfile}"
      dedup='off'
      errorlog="${work}/error.log"; : > "${errorlog}"
      pathgrepcidr="${work}/grepcidr"
      write_grepcidr_shim "${pathgrepcidr}"
      member="${work}/${alias}.txt"
      printf '203.0.113.5\n' > "${member}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'leaves the member file byte-identical when the suppression file does not exist'
      # Given: no pfbsuppression file was ever created (the "-e" leg of the gate).
      When call silently suppress
      The status should be success
      The contents of file "${member}" should equal '203.0.113.5'
    End

    It 'leaves the member file byte-identical when the suppression file exists but is empty'
      # Given: the file exists but is zero-length (the "-s" leg of the gate).
      : > "${pfbsuppression}"
      When call silently suppress
      The status should be success
      The contents of file "${member}" should equal '203.0.113.5'
    End
  End

  Describe 'b — bare-host token + matching /32 suppression: token removed (the working case)'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbsuppb.XXXXXX")"
      max="${work}"
      alias='TestList_v4'
      pfbsuppression="${work}/suppression.txt"
      printf '203.0.113.7/32\n' > "${pfbsuppression}"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      : > "${masterfile}"
      dedup='off'
      errorlog="${work}/error.log"; : > "${errorlog}"
      pathgrepcidr="${work}/grepcidr"
      write_grepcidr_shim "${pathgrepcidr}"
      member="${work}/${alias}.txt"
      printf '203.0.113.5\n203.0.113.7\n203.0.113.9\n' > "${member}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'removes the exact suppressed host, keeping its siblings'
      When call silently suppress
      The status should be success
      The contents of file "${member}" should equal "$(printf '203.0.113.5\n203.0.113.9')"
    End
  End

  Describe 'c — exact-/24 explode: a /32 suppression inside a containing /24 member entry'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbsuppc.XXXXXX")"
      max="${work}"
      alias='TestList_v4'
      pfbsuppression="${work}/suppression.txt"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      : > "${masterfile}"
      dedup='off'
      errorlog="${work}/error.log"; : > "${errorlog}"
      pathgrepcidr="${work}/grepcidr"
      write_grepcidr_shim "${pathgrepcidr}"
      member="${work}/${alias}.txt"
      printf '10.9.8.0/24\n' > "${member}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'explodes the /24 line into its 254 non-suppressed host lines (the /24 line itself is gone)'
      printf '10.9.8.4/32\n' > "${pfbsuppression}"
      When call silently suppress
      The status should be success
      The contents of file "${member}" should not include '10.9.8.0/24'
      # Exact-line greps (never substring "include") -- '10.9.8.4' as a
      # substring would false-positive-match '10.9.8.40'..'10.9.8.49'. `|| true`
      # so a legitimate zero-match (grep rc=1) doesn't abort the example.
      has4="$(grep -c '^10\.9\.8\.4$' "${member}" || true)"
      The variable has4 should equal 0
      has1="$(grep -c '^10\.9\.8\.1$' "${member}" || true)"
      The variable has1 should equal 1
      has255="$(grep -c '^10\.9\.8\.255$' "${member}" || true)"
      The variable has255 should equal 1
      # seq 255 walks octets 1..255 (255 values); excluding the one suppressed
      # octet (.4) leaves 254 -- verified empirically against the real function.
      hostcount="$(grep -c ^ "${member}")"
      The variable hostcount should equal 254
    End

    It 'a SECOND /32 suppression inside the same containing /24 does not re-explode (dupfile dedup): both hosts gone, no duplicate lines'
      # Given: two DIFFERENT /32 holes that both map to the same containing
      # /24 -- the dupfile guard (suppress()'s "dcheck" check) must fire only
      # once, or the explode loop would run twice and duplicate all 254 hosts.
      printf '10.9.8.4/32\n10.9.8.55/32\n' > "${pfbsuppression}"
      When call silently suppress
      The status should be success
      The contents of file "${member}" should not include '10.9.8.0/24'
      has4="$(grep -c '^10\.9\.8\.4$' "${member}" || true)"
      The variable has4 should equal 0
      has55="$(grep -c '^10\.9\.8\.55$' "${member}" || true)"
      The variable has55 should equal 0
      # 254 - the second suppressed host (.55, removed by the trailing
      # grepcidr pass since the single explode run already included it).
      hostcount="$(grep -c ^ "${member}")"
      The variable hostcount should equal 253
      # Then: no line was doubled by a second explode pass -- a real double
      # explode would leave every non-suppressed host appearing twice.
      dupcount="$(sort "${member}" | uniq -d | grep -c ^ || true)"
      The variable dupcount should equal 0
    End
  End

  Describe 'd — containing-entry silent no-op: the DEFECT, pinned as todays oracle (Phase 3 flips this)'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbsuppd.XXXXXX")"
      max="${work}"
      alias='TestList_v4'
      pfbsuppression="${work}/suppression.txt"
      printf '10.0.3.4/32\n' > "${pfbsuppression}"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      : > "${masterfile}"
      dedup='off'
      errorlog="${work}/error.log"; : > "${errorlog}"
      pathgrepcidr="${work}/grepcidr"
      write_grepcidr_shim "${pathgrepcidr}"
      member="${work}/${alias}.txt"
      # A /16 member entry containing the suppressed /32 host, but NOT the
      # exact /24 the explode branch's literal grep -F match requires.
      printf '10.0.0.0/16\n' > "${member}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'SURVIVES the containing /16 line unchanged -- the suppressed host stays blocked, ADR-53 §1.2 (Phase 3 flips this to a carve)'
      When call silently suppress
      The status should be success
      The contents of file "${member}" should equal '10.0.0.0/16'
    End
  End

  Describe 'e — grepcidr fail-safe publish gating (#713), re-asserted here for a self-contained oracle'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbsuppe.XXXXXX")"
      max="${work}"
      alias='TestList_v4'
      pfbsuppression="${work}/suppression.txt"
      printf '203.0.113.7/32\n' > "${pfbsuppression}"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      : > "${masterfile}"
      dedup='off'
      errorlog="${work}/error.log"; : > "${errorlog}"
      pathgrepcidr="${work}/grepcidr"
      write_grepcidr_shim "${pathgrepcidr}"
      member="${work}/${alias}.txt"
      printf '203.0.113.5\n203.0.113.7\n203.0.113.9\n' > "${member}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'keeps the PRIOR member list unchanged when grepcidr errors (rc>=2), and logs the error'
      GREPCIDR_MODE='error'; export GREPCIDR_MODE
      When call silently suppress
      The status should be success
      The contents of file "${member}" should equal "$(printf '203.0.113.5\n203.0.113.7\n203.0.113.9')"
      The contents of file "${errorlog}" should include 'grepcidr error'
    End

    It 'publishes an EMPTY member list on grepcidr rc=1 (a legitimate "everything suppressed" outcome)'
      GREPCIDR_MODE='empty'; export GREPCIDR_MODE
      When call silently suppress
      The status should be success
      The contents of file "${member}" should equal ''
    End
  End

  Describe 'f — masterfile resync under dedup="on" mirrors the post-suppression list'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbsuppf.XXXXXX")"
      max="${work}"
      alias='DedupList_v4'
      pfbsuppression="${work}/suppression.txt"
      printf '203.0.113.7/32\n' > "${pfbsuppression}"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      # A stale pair of rows for THIS alias, plus one unrelated alias's row
      # that must survive the resync untouched.
      printf 'DedupList_v4 PRIOR-1\nDedupList_v4 PRIOR-2\nOtherList_v4 198.51.100.5\n' > "${masterfile}"
      dedup='on'
      errorlog="${work}/error.log"; : > "${errorlog}"
      pathgrepcidr="${work}/grepcidr"
      write_grepcidr_shim "${pathgrepcidr}"
      member="${work}/${alias}.txt"
      printf '203.0.113.5\n203.0.113.7\n203.0.113.9\n' > "${member}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'drops the stale alias rows, keeps the unrelated row, and appends the post-suppression list'
      When call silently suppress
      The status should be success
      The contents of file "${masterfile}" should include 'OtherList_v4 198.51.100.5'
      The contents of file "${masterfile}" should not include 'PRIOR-1'
      The contents of file "${masterfile}" should not include 'PRIOR-2'
      The contents of file "${masterfile}" should include 'DedupList_v4 203.0.113.5'
      The contents of file "${masterfile}" should include 'DedupList_v4 203.0.113.9'
      The contents of file "${masterfile}" should not include 'DedupList_v4 203.0.113.7'
    End
  End

  Describe 'g — the Suppression Stats table'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbsuppg.XXXXXX")"
      max="${work}"
      pfbsuppression="${work}/suppression.txt"
      printf '203.0.113.7/32\n' > "${pfbsuppression}"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      : > "${masterfile}"
      dedup='off'
      errorlog="${work}/error.log"; : > "${errorlog}"
      pathgrepcidr="${work}/grepcidr"
      write_grepcidr_shim "${pathgrepcidr}"
      alias='StatsList_v4'
      member="${work}/${alias}.txt"
      printf '203.0.113.5\n203.0.113.7\n203.0.113.9\n' > "${member}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'prints the header block when alias="suppressheader"'
      alias='suppressheader'
      When call suppress
      The status should be success
      The stdout should include '===[ Suppression Stats ]==================================='
      The stdout should include 'List'
      The stdout should include 'Pre'
      The stdout should include 'Suppress'
      The stdout should include 'Master'
    End

    It 'prints the per-alias Pre/Suppress/Master row shape on a normal call'
      When call suppress
      The status should be success
      The stdout should include 'StatsList_v4'
      # Pre = 3 (member file before this call); Suppress = 2 (one host removed).
      The stdout should match pattern "*StatsList_v4*3*2*0*"
    End
  End
End

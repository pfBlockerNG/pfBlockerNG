#shellcheck shell=sh
# Legacy ": >" truncate-create sites (issue #1172).
#
# ":" is a POSIX special built-in (XCU 2.8.1): a redirection error on it exits a
# non-interactive strict-POSIX shell (ash/dash) ENTIRELY, skipping every abort/cleanup
# path below it. "true" is a regular built-in -- the same redirection error just fails
# that one command; the script continues. pfb_recompute() already made this swap (see
# its rationale comment); this spec pins the class fix for every remaining site.
#
# Probed this session (dash -c 'CMD > <directory>; echo rc=$?'):
#   ': >' on a directory  -> shell exits before the echo runs at all (no "rc=" line)
#   'true >' on a directory -> "rc=2" prints; the shell survives
#
# Because the pre-fix failure is a real shell exit, the two behavioural examples below
# run their target function via `When run` (a forked subshell, per the exitnow spec in
# pfblockerng_tempfile_spec.sh) -- never `When call`, which would take the whole
# shellspec process down with it.

# Structural guard: the exact class of legacy site, scoped to shipped shell sources
# (never tests/, which uses ": >" for ordinary fixture setup and is not part of this
# retirement). Scoped to the whole of src/ (not just pfblockerng/) so the guard also
# covers any future shell source elsewhere under src/.
_trunc_legacy_hits() {
	git -C "${PFB_ROOT}" grep -nE '(^|[;&|({[:space:]]):[[:space:]]*>' -- \
		src scripts
}

# process255(): truncate the dedupfile, then signal survival. `silently` swallows
# process255's own (irrelevant) stdout so only the marker is asserted.
_trunc255_run() {
	silently process255
	echo 'SURVIVED_255'
}

# pfb_aggregate(): union+swap into agg_tmp, then signal survival.
_truncagg_run() {
	silently pfb_aggregate agg v6 "${memberlist}" "${aggout}" "${consumer}"
	echo 'SURVIVED_AGG'
}

# issue #1172 review: the sites above only proved the process SURVIVES a redirection
# failure. Surviving is not enough -- the functions below must also ABORT loudly
# (log + return) instead of falling through into the #713 publish gate with a
# corrupted scratch file, which (via the FNR==NR-on-an-empty-first-file awk
# degeneracy) silently publishes an EMPTY or truncated artifact over a live one.
_truncA_run() {
	silently process255
	echo 'SURVIVED_A'
}
_truncB_run() {
	silently suppress
	echo 'SURVIVED_B'
}
_truncC_run() {
	silently pfb_aggregate agg v6 "${memberlist}" "${aggout}" "${consumer}"
	echo 'SURVIVED_C'
}
_truncD_run() {
	silently reputation_max
	echo 'SURVIVED_D'
}
_truncE_run() {
	silently reputation_pmax
	echo 'SURVIVED_E'
}
_truncF_run() {
	silently processet
	echo 'SURVIVED_F'
}

Describe 'legacy special-builtin truncate sites survive redirection failure (issue #1172)'
  BeforeAll 'pfb_source'

  Describe 'process255(): directory debris at its dedupfile truncate site'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/trunc255.XXXXXX")"
      pfbdeny="${work}/deny_"
      alias='Empty_v4'
      dedupfile="${work}/dedup"
      tempfile="${work}/t1"
      # Empty deny file -> data255 stays empty -> process255 never runs past the
      # truncate site under test into the octet-collapse body.
      : > "${pfbdeny}${alias}.txt"
      # Crash-leftover DIRECTORY at the dedupfile truncate target.
      mkdir "${dedupfile}"
    }
    cleanup() { rm -rf "$work"; }
    Before 'setup'
    After 'cleanup'

    It 'runs process255 to completion instead of exiting the shell on the truncate error'
      When run _trunc255_run
      The status should be success
      The output should include 'SURVIVED_255'
    End
  End

  Describe 'pfb_aggregate(): directory debris at its agg_tmp truncate site'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/truncagg.XXXXXX")"
      tempfile="${work}/t1"
      dedupfile="${work}/dedup"
      errorlog="${work}/err.log"
      memberlist="${work}/members"
      aggout="${work}/agg.txt"
      consumer="${work}/agg.lst"
      # No members -> the empty-union branch fires, which is the one guarded by
      # the agg_tmp truncate site under test.
      : > "${memberlist}"
      printf 'stale\n' > "${aggout}"
      # Crash-leftover DIRECTORY at agg_tmp ("${aggout}.tmp").
      mkdir "${aggout}.tmp"
    }
    cleanup() { rm -rf "$work"; }
    Before 'setup'
    After 'cleanup'

    It 'runs pfb_aggregate to completion (existing "keeping existing" abort path) instead of exiting the shell'
      When run _truncagg_run
      The status should be success
      The output should include 'SURVIVED_AGG'
      The contents of file "${errorlog}" should include 'failed; keeping existing'
      The contents of file "${aggout}" should equal 'stale'
    End
  End
End

Describe 'guarded truncate sites abort loudly on create failure, protecting the live artifact (issue #1172)'
  BeforeAll 'pfb_source'

  Describe 'process255(): dedupfile debris collapses a 255-line deny file to 1 line via the awk degeneracy'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/truncA.XXXXXX")"
      pfbdeny="${work}/deny_"
      alias='WipeA'
      dedupfile="${work}/dedup"
      tempfile="${work}/t1"
      errorlog="${work}/err.log"
      # 254 hosts sharing the '10.0.0' prefix (> process255's hardcoded 253
      # threshold) plus one unrelated marker row -- 255 lines total.
      i=1
      while [ "$i" -le 254 ]; do
        echo "10.0.0.${i}"
        i=$((i + 1))
      done > "${pfbdeny}${alias}.txt"
      echo 'PRIOR-MARKER' >> "${pfbdeny}${alias}.txt"
      before_count="$(grep -c ^ "${pfbdeny}${alias}.txt")"
      [ "${before_count}" -eq 255 ] || { echo "FIXTURE BUG: pre-run count ${before_count}" >&2; exit 1; }
      # Crash-leftover DIRECTORY at the dedupfile truncate target.
      mkdir "${dedupfile}"
    }
    cleanup() { rm -rf "$work"; }
    Before 'setup'
    After 'cleanup'

    It 'aborts before the #713 publish gate, leaving the deny file byte-unchanged'
      When run _truncA_run
      The status should be success
      The output should include 'SURVIVED_A'
      The contents of file "${errorlog}" should include 'cannot create'
      The lines of contents of file "${pfbdeny}${alias}.txt" should equal 255
      The contents of file "${pfbdeny}${alias}.txt" should include 'PRIOR-MARKER'
      The contents of file "${pfbdeny}${alias}.txt" should not include '10.0.0.0/24'
    End
  End

  Describe 'suppress(): dupfile debris lets execution reach iprange instead of aborting'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/truncB.XXXXXX")"
      max="${work}/deny"
      mkdir -p "${max}"
      alias='WipeB'
      member_file="${max}/${alias}.txt"
      printf '192.0.2.0/24\n198.51.100.0/24\n' > "${member_file}"
      expected_member="$(printf '%s\n' '192.0.2.0/24' '198.51.100.0/24')"
      pfbsuppression="${work}/suppression.txt"
      printf '192.0.2.0/24\n' > "${pfbsuppression}"
      dedup='off'
      dupfile="${work}/dup"
      dedupfile="${work}/dedup"
      tempfile="${work}/t1"
      tempfile2="${work}/t2"
      errorlog="${work}/err.log"
      marker="${work}/iprange_called"
      # Neutral iprange stand-in: proves whether it ran at all (the marker) --
      # real subtraction semantics are irrelevant to the truncate-guard under test.
      pathaggregate="${work}/iprange"
      cat > "${pathaggregate}" <<STUB
#!/bin/sh
touch "${marker}"
sort -u "\$1"
STUB
      chmod +x "${pathaggregate}"
      # Crash-leftover DIRECTORY at the dupfile truncate target.
      mkdir "${dupfile}"
    }
    cleanup() { rm -rf "$work"; }
    Before 'setup'
    After 'cleanup'

    It 'aborts before iprange runs, instead of silently proceeding past the broken dupfile'
      When run _truncB_run
      The status should be success
      The output should include 'SURVIVED_B'
      The contents of file "${errorlog}" should include 'cannot create'
      The path "${marker}" should not be exist
      The contents of file "${member_file}" should equal "${expected_member}"
    End
  End

  Describe 'pfb_aggregate(): tempfile debris wipes the union, publishing an EMPTY aggregate'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/truncC.XXXXXX")"
      tempfile="${work}/t1"
      dedupfile="${work}/dedup"
      errorlog="${work}/err.log"
      memberlist="${work}/members"
      aggout="${work}/agg.txt"
      consumer="${work}/agg.lst"
      agg_setsnap="${aggout}.members"
      printf '192.0.2.0/24\n198.51.100.0/24\n' > "${work}/m1"
      printf '%s\n' "${work}/m1" > "${memberlist}"
      printf 'stale\n' > "${aggout}"
      # Crash-leftover DIRECTORY at the union scratch (tempfile) truncate target.
      mkdir "${tempfile}"
    }
    cleanup() { rm -rf "$work"; }
    Before 'setup'
    After 'cleanup'

    It 'aborts the union pass, keeping the existing aggregate and never marking the pass successful'
      When run _truncC_run
      The status should be success
      The output should include 'SURVIVED_C'
      The contents of file "${errorlog}" should include 'keeping existing'
      The contents of file "${aggout}" should equal 'stale'
      The path "${agg_setsnap}" should not be exist
    End
  End

  Describe 'reputation_max(): tempfile2 debris collapses a 255-line deny file to 1 line (ccblack=block)'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/truncD.XXXXXX")"
      pfbdeny="${work}/deny/"; pfbmatch="${work}/match/"
      mkdir -p "${pfbdeny}" "${pfbmatch}"
      alias='WipeD'
      max=253
      tempfile="${work}/t1"; tempfile2="${work}/t2"
      dupfile="${work}/dup"; matchfile="${work}/matchf"; tempmatchfile="${work}/tmatchf"
      pathgeoip="${work}/mmdblookup"
      pathgeoipdat="${work}/geo.mmdb"; touch "${pathgeoipdat}"
      # A country that never matches ${cc} -> every repeat offender takes the
      # default (block) branch.
      make_geoip_stub "${pathgeoip}" 'xx iso_code: "FR" xx'
      now="now"
      count=0; countb=0; counts=0; countr=0
      dedup="off"; ccwhite="off"; ccblack="block"; cc="US"
      errorlog="${work}/err.log"
      i=1
      while [ "$i" -le 254 ]; do
        echo "10.0.0.${i}"
        i=$((i + 1))
      done > "${pfbdeny}${alias}.txt"
      echo 'PRIOR-MARKER' >> "${pfbdeny}${alias}.txt"
      before_count="$(grep -c ^ "${pfbdeny}${alias}.txt")"
      [ "${before_count}" -eq 255 ] || { echo "FIXTURE BUG: pre-run count ${before_count}" >&2; exit 1; }
      # Crash-leftover DIRECTORY at the tempfile2 truncate target.
      mkdir "${tempfile2}"
    }
    cleanup() { rm -rf "$work"; }
    Before 'setup'
    After 'cleanup'

    It 'aborts before the ccblack publish, leaving the deny file byte-unchanged'
      When run _truncD_run
      The status should be success
      The output should include 'SURVIVED_D'
      The contents of file "${errorlog}" should include 'cannot create'
      The lines of contents of file "${pfbdeny}${alias}.txt" should equal 255
      The contents of file "${pfbdeny}${alias}.txt" should include 'PRIOR-MARKER'
      The contents of file "${pfbdeny}${alias}.txt" should not include '10.0.0.0/24'
    End
  End

  Describe 'reputation_pmax(): tempfile debris wipes the masterfile via the FNR==NR degenerate awk'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/truncE.XXXXXX")"
      pfbdeny="${work}/deny/"
      mkdir -p "${pfbdeny}"
      alias='WipeE'
      max=253
      now='now'
      ip_placeholder3=''
      masterfile="${work}/masterfile"
      mastercat="${work}/mastercat"
      tempfile="${work}/t1"; tempfile2="${work}/t2"
      dedupfile="${work}/dedup"; addfile="${work}/add"
      : > "${dedupfile}"; : > "${addfile}"
      errorlog="${work}/err.log"
      i=1
      while [ "$i" -le 254 ]; do
        echo "10.0.0.${i}"
        i=$((i + 1))
      done > "${pfbdeny}${alias}.txt"
      expected_master="$(printf '%s\n' 'SentinelAlias 203.0.113.10' 'SentinelAlias 203.0.113.11' 'SentinelAlias 203.0.113.12')"
      expected_cat="$(printf '%s\n' '203.0.113.10' '203.0.113.11' '203.0.113.12')"
      printf '%s\n' "${expected_master}" > "${masterfile}"
      printf '%s\n' "${expected_cat}" > "${mastercat}"
      # Crash-leftover DIRECTORY at the masterfile-removal-pass tempfile truncate target.
      mkdir "${tempfile}"
    }
    cleanup() { rm -rf "$work"; }
    Before 'setup'
    After 'cleanup'

    It 'aborts before masterfile surgery, leaving masterfile and mastercat byte-unchanged'
      When run _truncE_run
      The status should be success
      The output should include 'SURVIVED_E'
      The contents of file "${errorlog}" should include 'cannot create'
      The contents of file "${masterfile}" should equal "${expected_master}"
      The contents of file "${mastercat}" should equal "${expected_cat}"
    End
  End

  Describe 'processet(): tempfile2 debris corrupts pfB_Match_ET_v4.txt into a directory'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/truncF.XXXXXX")"
      pfborig="${work}/orig/"; pfbmatch="${work}/match/"; etdir="${work}/ET"
      pfbmatchgen="${work}/match/generated/"
      mkdir -p "${pfborig}" "${pfbmatch}" "${pfbmatchgen}" "${etdir}"
      alias='WipeF'
      ip_placeholder2=''
      now='now'
      tempfile="${work}/t1"
      tempfile2="${work}/t2"
      errorlog="${work}/err.log"
      etblock='ET_Cnc'
      etmatch='ET_Bot'
      expected_orig="$(printf '%s\n' '192.0.2.10,1,90' '198.51.100.20,2,80')"
      printf '%s\n' "${expected_orig}" > "${pfborig}${alias}.orig"
      # Crash-leftover DIRECTORY at the tempfile2 (match-category scratch) truncate target.
      mkdir "${tempfile2}"
    }
    cleanup() { rm -rf "$work"; }
    Before 'setup'
    After 'cleanup'

    It 'aborts ET processing, leaving the .orig file unchanged and never creating pfB_Match_ET_v4.txt'
      When run _truncF_run
      The status should be success
      The output should include 'SURVIVED_F'
      The contents of file "${errorlog}" should include 'cannot create'
      The contents of file "${pfborig}${alias}.orig" should equal "${expected_orig}"
      The path "${pfbmatchgen}/pfB_Match_ET_v4.txt" should not be exist
    End
  End
End

Describe 'structural retirement guard: no legacy ": >" truncate sites remain in shipped shell sources (issue #1172)'
  # ADR-47 P5: scrub inherited GIT_* before the real `git grep` below -- an
  # inherited GIT_DIR (e.g. from the pre-commit hook) can override `-C` and
  # silently target the wrong repo.
  BeforeAll 'scrub_git_env'

  It 'has zero hits for the legacy special-builtin truncate pattern'
    When call _trunc_legacy_hits
    The status should be failure
    The output should equal ""
  End
End

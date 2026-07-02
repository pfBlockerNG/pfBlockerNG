#shellcheck shell=sh
# pfblockerng.sh fail-open feed-list redirects (issue #713 bug 8, family of 9
# sites in two producer classes). A producer (grepcidr / awk dedup) was
# redirected into a file consumed downstream with NO exit-status gating, so a
# producer error truncated/overwrote the live list to empty/partial:
#
#   Class A (grepcidr): rc 0 = matches removed, rc 1 = a LEGITIMATE "everything
#   suppressed" empty result (must still replace the target), rc >= 2 = a real
#   grepcidr error (must keep the previous target untouched). suppress() held
#   the worst case -- a direct "grepcidr ... > livelist" redirect with no temp
#   at all, truncating the live list before grepcidr even ran.
#
#   Class B (awk dedup): awk has no "empty output = error" quirk -- rc 0 is
#   always a legitimate result (including a genuinely empty dedup), non-zero is
#   always a real error. The unconditional "awk ... > tmp; mv -f tmp target"
#   became "awk ... > tmp && mv -f tmp target".
#
# Each scenario asserts the BEFORE state (prior content) so a pass proves the
# fix caused the preservation, not an accidental empty-target coincidence.

Describe 'pfblockerng.sh fail-open feed-list redirects (issue #713 bug 8)'
  BeforeAll 'pfb_source; SHELLSPEC_REAL_AWK="$(command -v awk)"; export SHELLSPEC_REAL_AWK'

  # ---- grepcidr shim: exit code/output selected via GREPCIDR_MODE ----
  #   success -> two matches on stdout, rc 0
  #   empty   -> a LEGITIMATE "everything suppressed" empty result, rc 1
  #   error   -> a real grepcidr error (e.g. malformed filter file), rc 2
  write_grepcidr_shim() {
    cat > "$1" <<'SHIM'
#!/bin/sh
case "${GREPCIDR_MODE:-}" in
	success) printf '192.0.2.1\n192.0.2.2\n'; exit 0 ;;
	empty) exit 1 ;;
	error) echo 'grepcidr: malformed CIDR in filter file' >&2; exit 2 ;;
	*) exit 2 ;;
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

  Describe 'suppress() -- Class A worst case (direct redirect into the LIVE published list)'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbsupp.XXXXXX")"
      max="${work}"
      alias='TestList_v4'
      pfbsuppression="${work}/suppression.txt"
      # A plain /24 (not /32) suppression entry stays out of the awk/dupfile
      # branch entirely, isolating the grepcidr producer for this test.
      printf '198.51.100.0/24\n' > "${pfbsuppression}"
      tmpdir="${work}"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      : > "${masterfile}"
      dedup='off'
      errorlog="${work}/error.log"; : > "${errorlog}"
      pathgrepcidr="${work}/grepcidr"
      write_grepcidr_shim "${pathgrepcidr}"
      livelist="${work}/${alias}.txt"
      printf 'PRIOR-1\nPRIOR-2\n' > "${livelist}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'keeps the live list UNCHANGED when grepcidr errors (rc>=2) -- pre-fix this truncated it to empty'
      # Given: the live list holds prior, real content.
      The contents of file "${livelist}" should equal "$(printf 'PRIOR-1\nPRIOR-2')"
      # When: grepcidr errors.
      GREPCIDR_MODE='error'; export GREPCIDR_MODE
      When call suppress
      # Then: the prior content survives -- and the error is logged, not swallowed.
      The status should be success
      The contents of file "${livelist}" should equal "$(printf 'PRIOR-1\nPRIOR-2')"
      The contents of file "${errorlog}" should include 'grepcidr error'
    End

    It 'replaces the live list with an EMPTY result on grepcidr rc=1 (a legitimate "everything suppressed" outcome)'
      GREPCIDR_MODE='empty'; export GREPCIDR_MODE
      When call suppress
      The status should be success
      The contents of file "${livelist}" should equal ''
    End

    It 'publishes the new content on grepcidr success'
      GREPCIDR_MODE='success'; export GREPCIDR_MODE
      When call suppress
      The status should be success
      The contents of file "${livelist}" should equal "$(printf '192.0.2.1\n192.0.2.2')"
    End
  End

  Describe 'duplicate() -- Class A (temp+mv grepcidr variant) + Class B (awk masterfile dedup)'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbdup.XXXXXX")"
      alias='DupList_v4'
      pfbdeny="${work}/deny/"; mkdir -p "${pfbdeny}"
      pfborig="${work}/orig/"; mkdir -p "${pfborig}"
      tmpdir="${work}"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      errorlog="${work}/error.log"; : > "${errorlog}"
      pathgrepcidr="${work}/grepcidr"
      write_grepcidr_shim "${pathgrepcidr}"
      # shellcheck disable=SC2034  # read by the sourced emptyfiles(), called at duplicate()'s tail
      ip_placeholder='240.0.0.0'
      awkshim="${work}/bin"
      setup_awk_shim "${awkshim}"
      denyfile="${pfbdeny}${alias}.txt"
      printf 'DupList_v4 192.0.2.10\nDupList_v4 192.0.2.11\nOtherList_v4 203.0.113.5\n' > "${masterfile}"
      printf '192.0.2.10\n192.0.2.11\n' > "${denyfile}"
      : > "${mastercat}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'keeps masterfile rows from the dedup step UNCHANGED when awk errors -- pre-fix this truncated masterfile, losing the unrelated OtherList_v4 row'
      GREPCIDR_MODE='success'; AWK_MODE='error'; export GREPCIDR_MODE AWK_MODE
      PATH="${awkshim}:${PATH}"
      When call duplicate
      The status should be success
      # duplicate()'s own trailing append always re-adds the (here: grepcidr-
      # succeeded) pfbdeny content -- pre-existing, unrelated to this fix -- so
      # the fix's proof is that the unrelated OtherList_v4 row is NOT lost, not
      # that the file is byte-identical to its pre-call state.
      The contents of file "${masterfile}" should include 'OtherList_v4 203.0.113.5'
      The contents of file "${masterfile}" should include 'DupList_v4 192.0.2.10'
    End

    It 'keeps the pfbdeny list UNCHANGED when grepcidr errors (rc>=2) -- Class A temp+mv variant'
      GREPCIDR_MODE='error'; export GREPCIDR_MODE
      # Given: the deny list holds prior, real content.
      The contents of file "${denyfile}" should equal "$(printf '192.0.2.10\n192.0.2.11')"
      When call duplicate
      The status should be success
      The contents of file "${denyfile}" should equal "$(printf '192.0.2.10\n192.0.2.11')"
      The contents of file "${errorlog}" should include 'grepcidr error'
    End

    It 'dedups masterfile and publishes the new pfbdeny content on full success'
      GREPCIDR_MODE='success'; export GREPCIDR_MODE
      When call duplicate
      The status should be success
      # DupList_v4's original rows are dedup'd out of masterfile; only the
      # unrelated OtherList_v4 row plus the freshly-published pfbdeny content
      # (re-appended by duplicate()'s own trailing step) remain.
      The contents of file "${masterfile}" should include 'OtherList_v4 203.0.113.5'
      The contents of file "${masterfile}" should not include '192.0.2.10'
      The contents of file "${denyfile}" should equal "$(printf '192.0.2.1\n192.0.2.2')"
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
      : > "${pfborig}RmList_v4.txt"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'keeps masterfile UNCHANGED when awk errors -- pre-fix this truncated masterfile (remove() then deletes an empty masterfile entirely)'
      AWK_MODE='error'; export AWK_MODE
      # Given: masterfile holds both the removed alias's row and an unrelated one.
      The contents of file "${masterfile}" should equal "$(printf 'RmList_v4 192.0.2.20\nOtherList_v4 203.0.113.9')"
      PATH="${awkshim}:${PATH}"
      When call remove
      The status should be success
      The contents of file "${masterfile}" should equal "$(printf 'RmList_v4 192.0.2.20\nOtherList_v4 203.0.113.9')"
    End

    It 'dedups masterfile (drops the removed alias row, keeps the unrelated one) on awk success'
      AWK_MODE='real'; export AWK_MODE
      PATH="${awkshim}:${PATH}"
      When call remove
      The status should be success
      The contents of file "${masterfile}" should equal 'OtherList_v4 203.0.113.9'
    End
  End
End

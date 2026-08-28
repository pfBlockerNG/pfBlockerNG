#shellcheck shell=sh
# issue #1263: a tree-wide re-enumeration found further bare multi-file/append
# `cat` concat sites in pfblockerng.sh. Same drop-in fix as the rest of the
# file: `awk 1` (a record terminator is guaranteed on every emitted line, even
# when the source lacked one). Each statement is extracted verbatim from the
# committed file (never a hand-retyped copy) and exercised directly, mirroring
# the technique already used by pfblockerng_processet_weld_spec.sh and
# bench_cat_weld_spec.sh for concat statements embedded in functions too heavy
# to invoke wholesale.
#
# pfb_recompute_finish()'s matchexempt concat is deliberately NOT covered here:
# both its inputs are written exclusively by awk `print ... >> file`, which
# terminates every record, so it cannot weld.

extract_stmt() {
  # $1 = file  $2 = literal anchor substring
  line="$(grep -Fn "$2" "$1" | head -n 1 | cut -d: -f1)"
  [ -n "$line" ] || return 1
  sed -n "${line}p" "$1" | sed 's/^[[:space:]]*//'
}

Describe 'reputation_pmax() masterfile append: addfile concat always leaves masterfile newline-terminated (issue #1263)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/addfileweld.XXXXXX")"
    addfile="${work}/add.txt"
    masterfile="${work}/masterfile"
    # masterfile mirrors the real upstream invariant: it was just rebuilt by the
    # preceding `awk ... > tempfile2 && mv -f tempfile2 masterfile` (awk always
    # terminates its own last emitted record), so it enters this append terminated.
    printf 'x 192.0.2.10\n' > "${masterfile}"
    # addfile is the adversarial input: no trailing newline.
    printf 'y 192.0.2.20' > "${addfile}"
    stmt="$(extract_stmt "${PFB_PKGDIR}/pfblockerng.sh" '"${addfile}" >> "${masterfile}"')"
  }
  cleanup() { rm -rf "$work"; }
  Before 'setup'
  After 'cleanup'

  It 'the committed line is extractable (vacuity guard)'
    When call test -n "${stmt}"
    The status should be success
  End

  It 'masterfile stays newline-terminated, never inheriting addfile bare tail'
    eval "$stmt"
    The contents of file "${masterfile}" should include 'x 192.0.2.10'
    The contents of file "${masterfile}" should include 'y 192.0.2.20'
    tail_byte="$(tail -c1 "${masterfile}" | od -An -tx1 | tr -d ' ')"
    The variable tail_byte should equal '0a'
  End
End

Describe 'processet() etblock/etmatch tempfile accumulation: multi-category concat never welds records (issue #1263)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/etaccum.XXXXXX")"
    etdir="${work}/ET"; mkdir -p "$etdir"
    tempfile="${work}/t1"
    tempfile2="${work}/t2"
    true > "$tempfile"
    true > "$tempfile2"
    # Two selected categories, the first unterminated -- deterministic single-line
    # weld pre-fix regardless of iteration order (both accumulators are seeded
    # identically so the same fixture drives both the block and match statements).
    printf '1.2.3.4' > "${etdir}/ET_Cnc.txt"
    printf '5.6.7.8\n' > "${etdir}/ET_Bot.txt"
    blockstmt="$(extract_stmt "${PFB_PKGDIR}/pfblockerng.sh" '"${etdir}/${list}.txt" >> "${tempfile}"')"
    matchstmt="$(extract_stmt "${PFB_PKGDIR}/pfblockerng.sh" '"${etdir}/${list}.txt" >> "${tempfile2}"')"
  }
  cleanup() { rm -rf "$work"; }
  Before 'setup'
  After 'cleanup'

  It 'both committed lines are extractable (vacuity guard)'
    When call test -n "${blockstmt}" -a -n "${matchstmt}"
    The status should be success
  End

  It 'etblock accumulation holds both real category files as TWO lines, never a fused record'
    for list in ET_Cnc ET_Bot; do
      eval "$blockstmt"
    done
    The contents of file "${tempfile}" should include '1.2.3.4'
    The contents of file "${tempfile}" should include '5.6.7.8'
    The contents of file "${tempfile}" should not include '1.2.3.45.6.7.8'
    linecount="$(grep -c ^ "${tempfile}")"
    The variable linecount should equal 2
  End

  It 'etmatch accumulation holds both real category files as TWO lines, never a fused record'
    for list in ET_Cnc ET_Bot; do
      eval "$matchstmt"
    done
    The contents of file "${tempfile2}" should include '1.2.3.4'
    The contents of file "${tempfile2}" should include '5.6.7.8'
    The contents of file "${tempfile2}" should not include '1.2.3.45.6.7.8'
    linecount="$(grep -c ^ "${tempfile2}")"
    The variable linecount should equal 2
  End
End

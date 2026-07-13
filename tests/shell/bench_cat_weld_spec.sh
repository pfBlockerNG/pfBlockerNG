#shellcheck shell=sh
# issue #1263, sites 7-9: dev-only benchmark tooling (scripts/bench_ip_recompute.sh,
# scripts/misc/bench_aggregate_union.sh) hit the identical multi-file `cat` weld as
# the production sites -- fixed with the same `awk 1` drop-in. Both scripts have
# zero pre-existing test harness (heavy synthetic-data generation, `bench_aggregate_union.sh`
# runs under `set -eu`) and are never invoked by CI, so a full-script run is out of
# scope; each spec below extracts the exact COMMITTED text (never a hand-retyped
# copy) of the isolable unit under test and exercises it directly against a
# real weld fixture.

Describe 'bench_ip_recompute.sh union_cksum(): the committed function never welds member records (issue #1263 site 7)'
  extract_union_cksum() {
    sed -n '/^union_cksum() {/,/^}/p' "$1"
  }

  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/ipru.XXXXXX")"
    memberdir="${work}/members"; mkdir -p "$memberdir"
    # All three unterminated -- deterministic single-line weld regardless of glob order.
    printf '10.0.0.1' > "${memberdir}/a.txt"
    printf '10.0.0.2' > "${memberdir}/b.txt"
    printf '10.0.0.3' > "${memberdir}/c.txt"
    funcsrc="$(extract_union_cksum "${PFB_ROOT}/scripts/bench_ip_recompute.sh")"
    expected="$(printf '10.0.0.1\n10.0.0.2\n10.0.0.3\n' | LC_ALL=C sort -u | cksum)"
  }
  cleanup() { rm -rf "$work"; }
  Before 'setup'
  After 'cleanup'

  It 'the committed function is extractable (vacuity guard)'
    When call test -n "${funcsrc}"
    The status should be success
  End

  It 'checksums the true 3-member set, never a welded/fused record'
    eval "$funcsrc"
    got="$(union_cksum "$memberdir")"
    When call test "$got" = "$expected"
    The status should be success
  End
End

Describe 'bench_aggregate_union.sh member concat: the committed lines never weld member records (issue #1263 sites 8/9)'
  extract_stmt() {
    # $1 = file  $2 = anchor grep pattern
    line="$(grep -n "$2" "$1" | head -n 1 | cut -d: -f1)"
    [ -n "$line" ] || return 1
    sed -n "${line}p" "$1"
  }

  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/aggu.XXXXXX")"
    memberdir="${work}/members"; mkdir -p "$memberdir"
    workdir="${work}/wd"; mkdir -p "$workdir"
    union_sorted="${workdir}/union.sorted"
    printf '10.0.0.1' > "${memberdir}/deny_a.txt"
    printf '10.0.0.2' > "${memberdir}/deny_b.txt"
    printf '10.0.0.3' > "${memberdir}/deny_c.txt"
    countstmt="$(extract_stmt "${PFB_ROOT}/scripts/misc/bench_aggregate_union.sh" 'input_count="\$(')"
    unionstmt="$(extract_stmt "${PFB_ROOT}/scripts/misc/bench_aggregate_union.sh" 'run_timed sh -c')"
  }
  cleanup() { rm -rf "$work"; }
  Before 'setup'
  After 'cleanup'

  It 'both committed lines are extractable (vacuity guard)'
    When call test -n "${countstmt}" -a -n "${unionstmt}"
    The status should be success
  End

  It 'site 8: input_count is the true 3 lines, never a welded 1'
    eval "$countstmt"
    When call test "$input_count" = 3
    The status should be success
  End

  It 'site 9: the written union file holds the true 3 unique members, never a fused record'
    # run_timed isn't defined here (it just wraps timing) -- strip the
    # wrapper and eval the inner `sh -c "..."` payload directly. The payload
    # was written escaped for ITS OWN enclosing double quotes (\"...\"); undo
    # that escaping now that those enclosing quotes are gone.
    inner="$(printf '%s\n' "$unionstmt" | sed -e 's/^run_timed sh -c "//' -e 's/"$//' -e 's/\\"/"/g')"
    eval "$inner"
    The path "${union_sorted}" should be file
    The contents of file "${union_sorted}" should include '10.0.0.1'
    The contents of file "${union_sorted}" should include '10.0.0.2'
    The contents of file "${union_sorted}" should include '10.0.0.3'
    The contents of file "${union_sorted}" should not include '10.0.0.110.0.0.2'
    linecount="$(grep -c ^ "${union_sorted}")"
    The variable linecount should equal 3
  End
End

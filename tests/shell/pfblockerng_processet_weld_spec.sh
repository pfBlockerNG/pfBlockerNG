#shellcheck shell=sh
# issue #1263, site 2: processet()'s `counto="$(cat "${etdir}"/ET_* | grep -cv ...)"`
# welds an unterminated ET_*.txt onto its neighbour, same as the other 8
# `cat`-of-a-multi-file-glob sites. processet() itself REGENERATES etdir/ET_*.txt
# from '.orig' via grep+cut at every call, so a fixture can't durably plant an
# unterminated derived file through the public processet() entry point.
# Extracting the counto assignment's literal, currently-committed text (never a
# hand-retyped copy -- avoids testing a stale/wrong shape) and eval'ing it
# against a directly-crafted etdir proves the exact shipped pipeline, order-
# independent (both fixture files lack a trailing newline, so the weld -- one
# fused line, zero internal newlines -- is deterministic regardless of which
# file `awk`/`cat` reads first).

Describe 'processet() ET_* count line: the exact committed pipeline never welds records (issue #1263 site 2)'
  extract_counto_assignment() {
    # $1 = path to pfblockerng.sh
    line="$(grep -n 'ET_\* | grep -cv' "$1" | head -n 1 | cut -d: -f1)"
    [ -n "$line" ] || return 1
    sed -n "${line}p" "$1" | sed 's/;.*//'
  }

  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/etweld.XXXXXX")"
    etdir="${work}/ET"
    mkdir -p "$etdir"
    # Both unterminated -- deterministic single-line weld regardless of glob order.
    printf '1.2.3.4' > "${etdir}/ET_A.txt"
    printf '5.6.7.8' > "${etdir}/ET_B.txt"
    stmt="$(extract_counto_assignment "${PFB_PKGDIR}/pfblockerng.sh")"
  }
  cleanup() { rm -rf "$work"; }
  Before 'setup'
  After 'cleanup'

  It 'the committed counto line exists and is extractable (vacuity guard)'
    When call test -n "${stmt}"
    The status should be success
  End

  It 'counts the true 2 ET records, never the welded 1'
    When call eval "${stmt}"
    The status should be success
    The variable counto should equal '2'
  End
End

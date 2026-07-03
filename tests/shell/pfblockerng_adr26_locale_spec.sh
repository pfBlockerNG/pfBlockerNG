#shellcheck shell=sh
# ADR-26 — locale policy + cross-platform shell portability: off-appliance coverage.
#
# The runtime EFFECT of the inline `LC_ALL=C` prefixes (Phase 1) is only observable
# under a non-C collation locale with collation-merging input; on the C-locale pfSense
# VM with ASCII (IP/punycode) data it is a deliberate no-op, so the ADR-04 smoke cannot
# distinguish it. This spec supplies the coverage that IS deterministic off-box:
#
#   * Phase 3 — `pfb_list_orig_by_mtime()` is exercised as a real function (GNU branch,
#     the shellspec CI runtime) and its oldest-first / column-exact output is pinned.
#     The BSD branch runs live in the ADR-04 smoke (every update's closingprocess).
#   * Phase 1/2 — the source invariants the ADR decided are pinned structurally (every
#     load-bearing sink carries `LC_ALL=C`; nothing exports LC_ALL/LANG; the ls-column
#     parse + hardcoded jot are gone), so a regression that drops a prefix or reverts a
#     construct fails CI deterministically.
#   * §2.1 byte-exact property — that `LC_ALL=C sort -u` keeps collation-equivalent but
#     byte-distinct lines (the guarantee the blocklist relies on), with a best-effort,
#     never-flaky demonstration that a language UTF-8 locale would merge them.

Describe 'ADR-26 — pfb_list_orig_by_mtime() diagnostic listing (Phase 3)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/a26mtime.XXXXXX")"
    export TZ=UTC   # make the GNU date(1) formatting reproducible regardless of runner TZ
  }
  cleanup() { rm -rf "$work"; unset TZ; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  # The exact-format assertions need GNU `touch -d` + GNU `date`; the shellspec CI runs
  # on GNU coreutils. Elsewhere (a BSD dev box) skip them — that branch is covered live.
  # The probe writes ${work}/.gnuprobe (a dotfile, never matched by the *.orig glob;
  # removed with the rest of ${work} by After 'cleanup').
  is_gnu() { stat --version >/dev/null 2>&1 && date --version >/dev/null 2>&1 && touch -d '2026-01-01 00:00:00' "${work}/.gnuprobe" 2>/dev/null; }
  # `Skip if` runs its condition as a simple command — a leading `!` is not a command
  # in POSIX sh, so wrap the negation in a function (where `!` is a valid pipeline op).
  not_gnu() { ! is_gnu; }

  It 'lists *.orig oldest-first as "<YYYY-MM-DD> <HH:MM><TAB><name>" (ISO date, path + .orig stripped)'
    Skip if 'needs GNU stat/date/touch (the BSD branch is covered live by ADR-04 smoke)' not_gnu
    # Created out of mtime order; the helper must emit them oldest-first (the old `ls -lahtr`).
    touch -d '2026-01-15 23:59:00' "${work}/pfB_Charlie.orig"
    touch -d '2026-01-10 08:05:00' "${work}/pfB_Alpha.orig"
    touch -d '2026-01-12 14:30:00' "${work}/pfB_Bravo.orig"
    touch "${work}/ignore.txt"   # a non-.orig file must NOT appear
    expected="$(printf '2026-01-10 08:05\tpfB_Alpha\n2026-01-12 14:30\tpfB_Bravo\n2026-01-15 23:59\tpfB_Charlie')"
    When call pfb_list_orig_by_mtime "${work}/"
    The status should be success
    The output should equal "$expected"
  End

  It 'emits nothing for a directory with no .orig files (the unmatched-glob guard holds)'
    When call pfb_list_orig_by_mtime "${work}/"
    The status should be success
    The output should equal ""
  End
End

Describe 'ADR-26 — pfblockerng.sh locale/portability source invariants (Phases 1,2,4)'
  src() { echo "${PFB_PKGDIR}/pfblockerng.sh"; }
  has() { grep -qF "$1" "$(src)"; }       # fixed-string present
  lacks() { ! grep -qF "$1" "$(src)"; }   # fixed-string absent

  # Gate 1 — every HIGH/MEDIUM collation sink from ADR §1.3 carries an inline LC_ALL=C.
  It 'prefixes the suppression dedup sink with LC_ALL=C'
    When call has 'data="$(LC_ALL=C sort -u "${pfbsuppression}")"'
    The status should be success
  End
  It 'prefixes the deny-list sort -u sink with LC_ALL=C'
    When call has 'LC_ALL=C sort -u "${pfbdeny}${alias}.txt"'
    The status should be success
  End
  It 'prefixes the alias-list compare (cut | sort -u) with LC_ALL=C'
    When call has 'cut -d '"'"' '"'"' -f1 "${masterfile}" | LC_ALL=C sort -u'
    The status should be success
  End
  It 'prefixes the extracted-IP .orig sink with LC_ALL=C'
    When call has 'LC_ALL=C sort -u > "${pfborig}${alias}.orig"'
    The status should be success
  End
  It 'prefixes the masterfile order (sort -o) with LC_ALL=C'
    When call has 'LC_ALL=C sort -o "${masterfile}" "${masterfile}"'
    The status should be success
  End
  It 'keeps LC_ALL=C on the aggregate dedup sink (ADR §1.3 reference idiom)'
    When call has 'LC_ALL=C sort -u "${tempfile}" > "${dedupfile}"'
    The status should be success
  End

  # Gate 2 — locale is per-command, NEVER exported process-wide.
  It 'never exports LC_ALL process-wide'
    When call lacks 'export LC_ALL'
    The status should be success
  End
  It 'never exports LANG process-wide'
    When call lacks 'export LANG'
    The status should be success
  End

  # Gate 4 — the FreeBSD-only / locale-fragile constructs are gone.
  It 'defines the pfb_list_orig_by_mtime() helper (replacing the ls -l column parse)'
    When call has 'pfb_list_orig_by_mtime()'
    The status should be success
  End
  It 'no longer parses ls -l output by awk column position'
    When call lacks '{print $6" "$7,$8,$9}'
    The status should be success
  End
  It 'no longer hardcodes /usr/bin/jot'
    When call lacks '/usr/bin/jot'
    The status should be success
  End
  # The portable `seq 255` this gate once pinned lived ONLY in suppress()'s
  # /24-host-explode loop -- ADR-53 Phase 3 deleted that loop entirely
  # (replaced by `iprange --except` set-subtraction), so the call site the
  # jot->seq portability fix protected is gone, not reverted. `seq` no longer
  # appears anywhere in the script; nothing left to pin here.
End

Describe 'ADR-26 — LC_ALL=C dedup is byte-exact (§2.1 guarantee)'
  # A collation-IGNORABLE soft hyphen (U+00AD = 0xC2 0xAD) makes "ab" and "a<SH>b"
  # byte-distinct but collation-EQUAL under a language UTF-8 locale. LC_ALL=C compares
  # bytes, so it keeps BOTH — the property a blocklist relies on (no silently dropped row).
  c_count() { printf 'ab\na\302\255b\n' | LC_ALL=C sort -u | wc -l | tr -d ' '; }

  # A *.UTF-8 locale that is NOT C/POSIX (those use codepoint order, so never merge).
  utf8_lang_locale() { locale -a 2>/dev/null | grep -iE '\.utf-?8$' | grep -ivE '^(C|POSIX)([.@]|$)' | head -n 1; }

  It 'keeps both byte-distinct lines under LC_ALL=C (byte-exact uniqueness)'
    When call c_count
    The output should equal 2
  End

  It 'is load-bearing: a language UTF-8 locale collation-merges what LC_ALL=C keeps'
    loc="$(utf8_lang_locale)"
    Skip if 'no language *.UTF-8 locale installed to demonstrate the merge' [ -z "$loc" ]
    merged="$(printf 'ab\na\302\255b\n' | LC_ALL="$loc" sort -u | wc -l | tr -d ' ')"
    # Never-flaky: only assert the contrast when this libc's locale actually merges the
    # sample (it dropped a line LC_ALL=C kept); otherwise skip (libc-collation-dependent).
    Skip if "locale ${loc} does not collation-merge the sample on this libc" [ "$merged" -ge 2 ]
    # No `When` needed: `merged` is set by the assignment above, not by a called command.
    The variable merged should equal 1
  End
End

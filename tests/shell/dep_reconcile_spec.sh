#shellcheck shell=sh
# dep_reconcile_spec.sh — shellspec suite for scripts/lib/dep-reconcile.sh
# (issue #1806 final step: post-upgrade dependency reconcile + shed).
#
# Pins the pure needed-set derivation + install/shed diff that
# scripts/image-upgrade.sh's post-upgrade phase drives: a py_flavor flip
# (py311 -> py312) must install the new-flavor CORE pkgs and shed the
# old-flavor ones; a missing package surfaces in the install list; a healthy
# (already-reconciled) set produces two empty lists; a same-row call (the
# "no matrix row for the new version yet" shape) never sheds and only
# reports genuinely missing packages.
#
# CONTRACT (corrected — a matrix row's extra_pkgs, e.g. CE's
# textproc/py-charset-normalizer, NEVER enter needed/install/verify: that
# package is deliberately NOT baked into the image — the per-leg smoke
# harness ships+installs it, and a real install resolves it from our
# self-hosted repo as an ordinary RUN_DEPENDS. Baking/demanding it here would
# (a) violate that dep-free-image decision and (b) fail-close every CE image
# upgrade on a healthy, correctly dep-free image. extra_pkgs participate ONLY
# in shed, and only for a basename NEW_EXTRA has genuinely dropped — never
# merely because its flavor changed):
#   (a) a CE-shaped row's extra_pkgs NEVER put that package in install (or, by
#       construction, verify — verify walks the same core-only set as install).
#   (b) an extra-derived stray already on the box gets shed once the NEW row's
#       extra_pkgs drops its origin.
#   (c) a Plus-shaped pair (extra_pkgs=[] on BOTH rows) never recognises its
#       baked (Netgate-provided) charset-normalizer as extra-derived at all —
#       neither installed nor shed; untouched end to end.
#
# RED->GREEN: before scripts/lib/dep-reconcile.sh exists, every `.` (source)
# below fails (ENOENT) and every function call is "command not found" —
# these assertions FAIL. After the helper lands they PASS. Pure functions;
# no ssh, no pkg(8), no VM — fully hermetic.

Describe 'dep-reconcile.sh'
  setup() {
    scrub_git_env
    # shellcheck source=scripts/lib/dep-reconcile.sh
    . "${PFB_ROOT}/scripts/lib/dep-reconcile.sh"
  }
  BeforeEach 'setup'

  Describe 'pfb_dep_core_pkgs'
    It 'lists the 7 flavor-independent + 2 flavor-tracking RUN_DEPENDS packages for py311'
      # Scenario: docs/misc/pfSense_versions.md's 9-row table (minus the
      # extra_pkgs-derived charset-normalizer, which is NOT core). This IS the
      # image's full needed/install/verify set — extra_pkgs never add to it.
      When call pfb_dep_core_pkgs py311
      The lines of output should equal 9
      The output should include 'libmaxminddb'
      The output should include 'lighttpd'
      The output should include 'jq'
      The output should include 'rsync'
      The output should include 'grepcidr'
      The output should include 'iprange'
      The output should include 'gnugrep'
      The output should include 'py311-maxminddb'
      The output should include 'py311-sqlite3'
    End

    It 'tracks a different flavor (py312) on the two python packages'
      # Branch coverage: the flavor prefix must actually vary, not be hardcoded.
      When call pfb_dep_core_pkgs py312
      The output should include 'py312-maxminddb'
      The output should include 'py312-sqlite3'
      The output should not include 'py311-maxminddb'
    End

    It 'rejects a malformed py_flavor (fail-closed, never a silent default)'
      When call pfb_dep_core_pkgs python3
      The status should be failure
      The stderr should include 'invalid py_flavor'
    End
  End

  Describe 'pfb_dep_python_dotted'
    It 'maps py311 -> 3.11'
      When call pfb_dep_python_dotted py311
      The output should equal '3.11'
    End

    It 'maps py39 -> 3.9 (single-digit minor)'
      When call pfb_dep_python_dotted py39
      The output should equal '3.9'
    End

    It 'maps py312 -> 3.12'
      When call pfb_dep_python_dotted py312
      The output should equal '3.12'
    End

    It 'rejects a malformed flavor'
      When call pfb_dep_python_dotted notaflavor
      The status should be failure
      The stderr should include 'invalid py_flavor'
    End
  End

  Describe 'pfb_dep_extra_basename'
    # SHED-recognition only (see file header) — never feeds needed/install/verify.
    It 'strips the py- PKGNAMEPREFIX'
      # Scenario: the one currently-known extra_pkgs entry (CE's charset-normalizer).
      When call pfb_dep_extra_basename 'textproc/py-charset-normalizer'
      The output should equal 'charset-normalizer'
    End

    It 'passes a non-py- basename through unchanged (branch coverage)'
      When call pfb_dep_extra_basename 'net/foo-bar'
      The output should equal 'foo-bar'
    End
  End

  Describe 'pfb_dep_plan'
    # installed_of FLAVOR [EXTRA_PKG_NAME] — FLAVOR's core needed set, an
    # already-reconciled box, plus an optional literal extra-derived package
    # name (simulating a stray/baked extra actually present on the box —
    # never derived via the production needed-set logic, since extra_pkgs
    # deliberately never feed that).
    installed_of() {
      _flavor="$1"; _extra_pkg="${2:-}"
      pfb_dep_core_pkgs "$_flavor"
      [ -z "$_extra_pkg" ] || printf '%s\n' "$_extra_pkg"
    }

    It 'a py311->py312 flip: installs every py312-* core pkg, sheds every py311-* one'
      # Scenario: the box was baked/left on py311 (old row); the new version
      # flipped to py312 (new row). Given the box has the full OLD needed set
      # installed; When planned against py311->py312; Then every NEW-flavor
      # python package is queued to install and every OLD-flavor one to shed —
      # the non-flavored core packages (already shared) appear in neither list.
      flip() {
        old_installed="$(installed_of py311)"
        pfb_dep_plan py311 '' py312 '' "$old_installed"
      }
      When call flip
      The output should include 'install py312-maxminddb'
      The output should include 'install py312-sqlite3'
      The output should include 'shed py311-maxminddb'
      The output should include 'shed py311-sqlite3'
      The output should not include 'install libmaxminddb'
      The output should not include 'shed libmaxminddb'
      The output should not include 'install lighttpd'
      The output should not include 'shed lighttpd'
    End

    It 'a genuinely missing package surfaces only in the install list'
      # Given an installed set missing py311-sqlite3 (everything else present,
      # same row old==new); Then install lists exactly the missing package and
      # shed is empty (nothing is stale — the row did not change).
      missing_one() {
        full="$(installed_of py311)"
        partial="$(printf '%s\n' "$full" | grep -vxF 'py311-sqlite3')"
        pfb_dep_plan py311 '' py311 '' "$partial"
      }
      When call missing_one
      The output should equal 'install py311-sqlite3'
    End

    It 'a healthy (already-reconciled) set produces two empty lists'
      # Given the installed set is EXACTLY the needed set (old==new, nothing
      # missing, nothing stale); Then the plan is empty end to end.
      healthy() {
        full="$(installed_of py311)"
        pfb_dep_plan py311 '' py311 '' "$full"
      }
      When call healthy
      The output should equal ''
    End

    It 'a same-row call (unknown-new-version verify shape) never sheds'
      # Scenario: image-upgrade.sh's "no matrix row for the new version yet"
      # path calls pfb_dep_plan with the SAME row on both sides (verify-only).
      # Given the box is missing one package; Then shed is empty regardless
      # (old_needed - new_needed is empty when old==new) and install lists
      # exactly the gap — this is the "warn + skip reconcile, still verify"
      # semantics pinned at the pure-function level (the warn message itself
      # and the exit-code routing in image-upgrade.sh are live-proof-only).
      verify_only_missing() {
        full="$(installed_of py311)"
        partial="$(printf '%s\n' "$full" | grep -vxF 'jq')"
        pfb_dep_plan py311 '' py311 '' "$partial"
      }
      When call verify_only_missing
      The output should equal 'install jq'
    End

    It 'CONTRACT (a): a CE-shaped extra_pkgs entry never enters install (only the per-leg harness installs it)'
      # DISCRIMINATING RED: the pre-correction implementation put the
      # extra_pkgs-derived name straight into the install list here (it folded
      # extra_pkgs into the "needed" set). Given a healthy, correctly
      # dep-free CE image (installed = core only) and a NEW row that carries
      # extra_pkgs; Then the plan is EMPTY — nothing is installed and nothing
      # verifies-missing for it (verify walks this same core-only set).
      ce_extra_never_installed() {
        core_only_installed="$(installed_of py311)"
        pfb_dep_plan py311 '' py311 'textproc/py-charset-normalizer' "$core_only_installed"
      }
      When call ce_extra_never_installed
      The output should equal ''
    End

    It 'CONTRACT (b): an extra-derived stray is shed once the NEW row drops its origin'
      # Given the OLD row needed the extra pkg (and a stray is actually
      # installed) but the NEW row's extra_pkgs dropped it (e.g. upstream now
      # covers it); Then it moves to the shed list, and nothing else changes.
      extra_dropped() {
        old_installed="$(installed_of py311 'py311-charset-normalizer')"
        pfb_dep_plan py311 'textproc/py-charset-normalizer' py311 '' "$old_installed"
      }
      When call extra_dropped
      The output should equal 'shed py311-charset-normalizer'
    End

    It 'excludes a still-needed extra_pkgs entry from shed (same flavor, unchanged extra)'
      # Given a stray is installed and BOTH rows still carry its origin; Then
      # it is in neither list (never installed — extra_pkgs never is; never
      # shed — its basename was not dropped).
      extra_kept() {
        old_installed="$(installed_of py311 'py311-charset-normalizer')"
        pfb_dep_plan py311 'textproc/py-charset-normalizer' \
                     py311 'textproc/py-charset-normalizer' \
                     "$old_installed"
      }
      When call extra_kept
      The output should equal ''
    End

    It 'CONTRACT (c): a Plus-shaped pair (extra_pkgs=[] both sides) leaves its baked charset-normalizer untouched'
      # Scenario: Plus's own pfSense repo already carries charset-normalizer
      # (Netgate-provided, a real RUN_DEPENDS resolution) — the matrix's
      # extra_pkgs is [] on BOTH rows (docs/misc/pfSense_versions.md). Given
      # it is installed; Then it is recognised as neither core nor
      # extra-derived (no basename in either row's extra_pkgs to match) —
      # neither installed (redundant — already there) nor shed.
      plus_baked_charset_untouched() {
        installed="$(installed_of py311 'py311-charset-normalizer')"
        pfb_dep_plan py311 '' py311 '' "$installed"
      }
      When call plus_baked_charset_untouched
      The output should equal ''
    End

    It 'CR-3: a dropped extra_pkgs basename never sheds a same-named CORE package (net/py-maxminddb collision)'
      # DISCRIMINATING RED: the extra-derived shed loop matched by BASENAME
      # alone (py[0-9][0-9]*-<basename> against $_planp_installed), with no
      # check against the NEW core needed set -- a dropped extra_pkgs origin
      # whose basename collides with a CORE package (net/py-maxminddb's
      # basename "maxminddb" collides with the CORE py<flavor>-maxminddb
      # dependency every row needs) would shed the STILL-NEEDED core pkg.
      # Given the OLD row carried net/py-maxminddb as an extra_pkgs entry and
      # the box has the full core set installed (incl. py311-maxminddb, which
      # is core-needed regardless), but the NEW row (same flavor) dropped that
      # extra origin; Then py311-maxminddb must NOT be shed -- the plan is
      # empty (nothing to install, already-core-satisfied; nothing genuinely
      # stale to shed).
      core_collision() {
          old_installed="$(installed_of py311)"
          pfb_dep_plan py311 'net/py-maxminddb' py311 '' "$old_installed"
      }
      When call core_collision
      The output should equal ''
    End

    It 'a newly-added extra_pkgs entry is untouched (never installed — the per-leg harness handles it)'
      # Given the OLD row carried no extra pkg (not installed) and the NEW row
      # adds one; Then the plan is EMPTY — extra_pkgs never enters install.
      extra_added() {
        old_installed="$(installed_of py311)"
        pfb_dep_plan py311 '' py311 'textproc/py-charset-normalizer' "$old_installed"
      }
      When call extra_added
      The output should equal ''
    End
  End
End

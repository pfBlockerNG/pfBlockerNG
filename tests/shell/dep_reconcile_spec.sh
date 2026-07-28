#shellcheck shell=sh
# dep_reconcile_spec.sh — shellspec suite for scripts/lib/dep-reconcile.sh
# (issue #1806 final step: post-upgrade dependency reconcile + shed).
#
# Pins the pure needed-set derivation + install/shed diff that
# scripts/image-upgrade.sh's post-upgrade phase drives: a py_flavor flip
# (py311 -> py312) must install the new-flavor core pkgs and shed the
# old-flavor ones; a missing package surfaces in the install list; a healthy
# (already-reconciled) set produces two empty lists; a same-row call (the
# "no matrix row for the new version yet" shape) never sheds and only
# reports genuinely missing packages; and a matrix row's extra_pkgs is
# excluded from shed while still needed, included once dropped.
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
      # extra_pkgs-derived charset-normalizer, which is NOT core).
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

  Describe 'pfb_dep_extra_pkg_name'
    It 'strips the py- PKGNAMEPREFIX and applies the target flavor'
      # Scenario: the one currently-known extra_pkgs entry (CE's charset-normalizer).
      When call pfb_dep_extra_pkg_name 'textproc/py-charset-normalizer' py311
      The output should equal 'py311-charset-normalizer'
    End

    It 'applies a different flavor to the same origin'
      When call pfb_dep_extra_pkg_name 'textproc/py-charset-normalizer' py312
      The output should equal 'py312-charset-normalizer'
    End
  End

  Describe 'pfb_dep_needed_pkgs'
    It 'is exactly the core set when EXTRA_ORIGINS is empty'
      When call pfb_dep_needed_pkgs py311 ''
      The lines of output should equal 9
      The output should not include 'charset-normalizer'
    End

    It 'appends the extra_pkgs-derived name when EXTRA_ORIGINS is non-empty'
      When call pfb_dep_needed_pkgs py311 'textproc/py-charset-normalizer'
      The lines of output should equal 10
      The output should include 'py311-charset-normalizer'
    End
  End

  Describe 'pfb_dep_python_modules'
    It 'is maxminddb + sqlite3 with no extras'
      When call pfb_dep_python_modules py311 ''
      The lines of output should equal 2
      The output should include 'maxminddb'
      The output should include 'sqlite3'
    End

    It 'turns an extra package name dash into the python import underscore'
      When call pfb_dep_python_modules py311 'textproc/py-charset-normalizer'
      The lines of output should equal 3
      The output should include 'charset_normalizer'
      The output should not include 'charset-normalizer'
    End
  End

  Describe 'pfb_dep_plan'
    # installed_of <flavor> [extra] — the exact needed set for FLAVOR (+ optional
    # extra origin), i.e. a box that is FULLY reconciled for that row already.
    installed_of() {
      pfb_dep_needed_pkgs "$1" "${2:-}"
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

    It 'excludes a still-needed extra_pkgs entry from shed (same flavor, unchanged extra)'
      # Given the box has the extra pkg installed and BOTH rows still carry it;
      # Then it is in neither list (still needed -> never shed; already
      # installed -> never queued to install).
      extra_kept() {
        old_installed="$(installed_of py311 'textproc/py-charset-normalizer')"
        pfb_dep_plan py311 'textproc/py-charset-normalizer' \
                     py311 'textproc/py-charset-normalizer' \
                     "$old_installed"
      }
      When call extra_kept
      The output should equal ''
    End

    It 'sheds an extra_pkgs entry the NEW row no longer carries'
      # Given the OLD row needed the extra pkg (and it is installed) but the
      # NEW row's extra_pkgs dropped it (e.g. upstream now covers it); Then it
      # moves to the shed list, and nothing else changes.
      extra_dropped() {
        old_installed="$(installed_of py311 'textproc/py-charset-normalizer')"
        pfb_dep_plan py311 'textproc/py-charset-normalizer' py311 '' "$old_installed"
      }
      When call extra_dropped
      The output should equal 'shed py311-charset-normalizer'
    End

    It 'queues a NEWLY-added extra_pkgs entry for install, never shed'
      # Given the OLD row carried no extra pkg (not installed) and the NEW row
      # adds one; Then it is queued to install, and the shed list stays empty.
      extra_added() {
        old_installed="$(installed_of py311)"
        pfb_dep_plan py311 '' py311 'textproc/py-charset-normalizer' "$old_installed"
      }
      When call extra_added
      The output should equal 'install py311-charset-normalizer'
    End
  End
End

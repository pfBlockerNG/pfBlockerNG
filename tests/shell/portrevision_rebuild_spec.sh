#shellcheck shell=sh
# portrevision-rebuild.sh — pins the compare-and-bump arithmetic.
#
# pkg orders: 4.0.0 < 4.0.0_1 < 4.0.0_2 < 4.0.1
# Rule: same PORTVERSION → old_rev + 1; different PORTVERSION → 0.
# old_portrevision absent/empty is treated as 0.

Describe 'portrevision-rebuild.sh'
  SCRIPT="${PFB_ROOT}/scripts/portrevision-rebuild.sh"

  # Invoke the script with the given three arguments and capture stdout.
  rebuild_rev() {
    sh "${SCRIPT}" "$1" "$2" "$3"
  }

  Describe 'same PORTVERSION (rebuild bump)'
    It 'absent old revision + same version -> 1 (first rebuild)'
      # Given old_portrevision is absent (empty string)
      # When the new PORTVERSION equals the old one
      # Then the result is 1 (the first rebuild increment).
      When call rebuild_rev '4.0.0' '' '4.0.0'
      The status should be success
      The output should equal '1'
    End

    It 'old revision 1 + same version -> 2'
      # Given the port was already rebuilt once (PORTREVISION=1)
      # When the PORTVERSION is still the same
      # Then it bumps to 2.
      When call rebuild_rev '4.0.0' '1' '4.0.0'
      The status should be success
      The output should equal '2'
    End

    It 'old revision 2 + same version -> 3'
      # Consecutive rebuilds continue incrementing.
      When call rebuild_rev '4.0.0' '2' '4.0.0'
      The status should be success
      The output should equal '3'
    End

    It 'works for a prerelease PORTVERSION (alpha/rc) rebuild'
      # Prerelease versions (e.g. 4.0.0.alpha.1) follow the same rule.
      When call rebuild_rev '4.0.0.alpha.1' '1' '4.0.0.alpha.1'
      The status should be success
      The output should equal '2'
    End
  End

  Describe 'different PORTVERSION (version change → reset to 0)'
    It 'any old revision + different version -> 0'
      # Given the PORTVERSION changed (e.g. a new release tag)
      # When the new version differs from the old one
      # Then PORTREVISION resets to 0 (no _N suffix on the new version).
      When call rebuild_rev '4.0.0' '1' '4.0.1'
      The status should be success
      The output should equal '0'
    End

    It 'absent old revision + different version -> 0'
      # No prior revision, fresh version bump — still resets to 0.
      When call rebuild_rev '4.0.0' '' '4.0.1'
      The status should be success
      The output should equal '0'
    End

    It 'resets across a prerelease-to-stable promotion'
      # e.g. rc.1 -> stable release: PORTREVISION must reset.
      When call rebuild_rev '4.0.0.rc.1' '3' '4.0.0'
      The status should be success
      The output should equal '0'
    End

    It 'resets from stable to the next prerelease series'
      # e.g. 4.0.0 -> 4.1.0.alpha.1: PORTREVISION resets.
      When call rebuild_rev '4.0.0' '2' '4.1.0.alpha.1'
      The status should be success
      The output should equal '0'
    End
  End

  Describe 'argument validation'
    It 'exits 2 when called with fewer than 3 arguments'
      When run sh "${SCRIPT}" '4.0.0' '1'
      The status should equal 2
      The stderr should include 'usage:'
    End
  End
End

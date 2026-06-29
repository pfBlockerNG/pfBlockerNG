#shellcheck shell=sh
# smoke_tier_spec.sh — shellspec suite for scripts/lib/smoke-tier.sh
#
# Pins the marker → (paths, timeout, browser?) mapping that lets a bare
# `local-smoke.sh -m ui_render` run the ADR-14 Web-UI tiers locally with the same
# --paths/--timeout the CI ui-tests.yml uses, plus the Chromium-needed predicate.
#
# RED→GREEN: before scripts/lib/smoke-tier.sh exists (and before smoke-on-box.sh
# derives paths/timeout from the marker), a UI marker resolved to the default
# tests/smoke + 30s and never installed Chromium — these assertions FAIL. After
# the helper lands they PASS. Pure functions; no VM, fully hermetic.

Describe 'smoke-tier.sh'
  setup() {
    scrub_git_env
    # shellcheck source=scripts/lib/smoke-tier.sh
    . "${PFB_ROOT}/scripts/lib/smoke-tier.sh"
  }
  BeforeEach 'setup'

  Describe 'pfb_smoke_tier_paths'
    It 'scopes ui_render to tests/smoke/ui'
      # Scenario: the render tier's target path.
      # Given the ui_render marker; When mapped; Then the UI subtree is used.
      When call pfb_smoke_tier_paths ui_render
      The output should equal 'tests/smoke/ui'
    End

    It 'scopes ui_e2e to tests/smoke/ui'
      When call pfb_smoke_tier_paths ui_e2e
      The output should equal 'tests/smoke/ui'
    End

    It 'scopes ui_browser to tests/smoke/ui'
      When call pfb_smoke_tier_paths ui_browser
      The output should equal 'tests/smoke/ui'
    End

    It 'resolves a compound UI marker to tests/smoke/ui'
      # Scenario: a `-m "ui_render or ui_browser"` expression still scopes to ui.
      When call pfb_smoke_tier_paths 'ui_render or ui_browser'
      The output should equal 'tests/smoke/ui'
    End

    It 'leaves the default smoke marker on tests/smoke'
      # Branch coverage: the non-UI side must keep the whole-suite path.
      When call pfb_smoke_tier_paths smoke
      The output should equal 'tests/smoke'
    End

    It 'leaves the repo marker on tests/smoke'
      When call pfb_smoke_tier_paths repo
      The output should equal 'tests/smoke'
    End
  End

  Describe 'pfb_smoke_tier_timeout'
    It 'gives the UI tiers the 300s ceiling (ui_render)'
      # Scenario: UI flows need the longer per-test ceiling (matches ui-tests.yml).
      When call pfb_smoke_tier_timeout ui_render
      The output should equal '300'
    End

    It 'gives the UI tiers the 300s ceiling (ui_e2e)'
      When call pfb_smoke_tier_timeout ui_e2e
      The output should equal '300'
    End

    It 'gives the UI tiers the 300s ceiling (ui_browser)'
      When call pfb_smoke_tier_timeout ui_browser
      The output should equal '300'
    End

    It 'keeps the default smoke 30s ceiling'
      # Branch coverage: the non-UI side keeps the tight default.
      When call pfb_smoke_tier_timeout smoke
      The output should equal '30'
    End
  End

  Describe 'pfb_smoke_tier_needs_browser'
    It 'is true for ui_browser (needs Chromium)'
      # Scenario: only the browser tier downloads the Chromium binary.
      When call pfb_smoke_tier_needs_browser ui_browser
      The status should be success
    End

    It 'is true for a compound marker containing ui_browser'
      When call pfb_smoke_tier_needs_browser 'ui_render or ui_browser'
      The status should be success
    End

    It 'is false for ui_render (bindings suffice)'
      # Branch coverage: the HTTP render tier must NOT trigger the browser install.
      When call pfb_smoke_tier_needs_browser ui_render
      The status should be failure
    End

    It 'is false for ui_e2e (no browser)'
      When call pfb_smoke_tier_needs_browser ui_e2e
      The status should be failure
    End

    It 'is false for the default smoke marker'
      When call pfb_smoke_tier_needs_browser smoke
      The status should be failure
    End
  End
End

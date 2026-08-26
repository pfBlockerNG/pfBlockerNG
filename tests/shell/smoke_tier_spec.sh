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

  # `playwright install --with-deps` shells out to apt-get on EVERY run, even when the
  # browser is already cached and nothing needs installing -- so an unrelated broken
  # package on the leased box failed runs that needed no packages at all (#1226). The
  # OS-dependency half is therefore reserved for a box that genuinely lacks the browser.
  Describe 'pfb_chromium_cached'
    # NOT named setup()/cleanup(): those are the OUTER Describe's hooks, which source the
    # library under test -- redefining them here would silently unload it.
    cache_setup() { CACHE="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pwcache.XXXXXX")"; }
    cache_cleanup() { rm -rf "$CACHE"; }
    Before 'cache_setup'
    After 'cache_cleanup'

    It 'is true when a chromium build is already cached'
      # Scenario: the real layout on a provisioned box -- ~/.cache/ms-playwright/chromium-<rev>.
      mkdir_build() { mkdir -p "${CACHE}/chromium-1223"; pfb_chromium_cached "$CACHE"; }
      When call mkdir_build
      The status should be success
    End

    It 'is false for an EMPTY cache directory (browser absent, deps needed)'
      # Branch coverage: the directory existing is not enough -- a build must be in it.
      When call pfb_chromium_cached "$CACHE"
      The status should be failure
    End

    It 'is false when the cache directory does not exist at all'
      When call pfb_chromium_cached "${CACHE}/nope"
      The status should be failure
    End

    It 'ignores a NON-chromium build in the cache (e.g. ffmpeg only)'
      # A cache holding only ffmpeg/firefox must still install chromium + its deps.
      mkdir_other() { mkdir -p "${CACHE}/ffmpeg-1011"; pfb_chromium_cached "$CACHE"; }
      When call mkdir_other
      The status should be failure
    End
  End

  # smoke-on-box.sh runs under `set -eu`, where a bare ${HOME} aborts the whole script if
  # HOME is unset (as it can be in a non-login execution context). Resolving the cache root
  # here keeps that expansion out of the caller and lets the fallbacks be pinned.
  # The provisioning order is the load-bearing bit (#1226): --with-deps runs FIRST so a
  # healthy box keeps its OS libs current, and the cache is consulted ONLY to judge whether
  # an apt failure is survivable. Each branch is stubbed here -- the real playwright would
  # need a box.
  Describe 'pfb_chromium_provision'
    prov_setup() {
      CACHE="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pwprov.XXXXXX")"
      LOG="${CACHE}/calls"
      true > "$LOG"
      unset _pfb_cp_cache   # the leak probe below must measure THIS call, not a sibling's
    }
    prov_cleanup() { rm -rf "$CACHE"; }
    Before 'prov_setup'
    After 'prov_cleanup'

    # Stand-in for the venv python: records its argv, and fails --with-deps iff APT_BROKEN.
    fake_pw() {
      printf '%s\n' "$*" >> "$LOG"
      case "$*" in
          *--with-deps*) [ "${APT_BROKEN:-0}" = 1 ] && return 100 ;;
          *)             [ "${RETRY_BROKEN:-0}" = 1 ] && return 42 ;;
      esac
      return 0
    }

    It 'installs with OS deps on a healthy box, and does not retry'
      healthy() { APT_BROKEN=0 pfb_chromium_provision "$CACHE" fake_pw; }
      When call healthy
      The status should be success
      The contents of file "$LOG" should include 'install --with-deps chromium'
      The lines of contents of file "$LOG" should equal 1
    End

    It 'survives a broken apt when a build is cached: retries WITHOUT the OS deps'
      # Scenario: the #1226 incident -- unrelated dpkg breakage, browser already there.
      recovers() {
        mkdir -p "${CACHE}/chromium-1223"
        APT_BROKEN=1 pfb_chromium_provision "$CACHE" fake_pw
      }
      When call recovers
      The status should be success
      The stderr should include 'retrying without the OS-dependency half'
      The contents of file "$LOG" should include 'install chromium'
      The lines of contents of file "$LOG" should equal 2
    End

    It 'FAILS LOUDLY when apt breaks and no build is cached (box unprovisionable)'
      # Branch coverage: without a cached browser the box genuinely cannot run the tier --
      # never a silent skip, which would surface later as a confusing Tier-B failure.
      unprovisionable() { APT_BROKEN=1 pfb_chromium_provision "$CACHE" fake_pw; }
      When call unprovisionable
      The status should be failure
      The stderr should include 'cannot be provisioned'
      The lines of contents of file "$LOG" should equal 1
    End

    It 'propagates the retry failure rather than swallowing it'
      # The fallback must not turn a genuinely failed install into a green provision.
      retry_dies() {
        mkdir -p "${CACHE}/chromium-1223"
        APT_BROKEN=1 RETRY_BROKEN=1 pfb_chromium_provision "$CACHE" fake_pw
      }
      When call retry_dies
      The status should equal 42
      The stderr should include 'retrying without the OS-dependency half'
    End
    It 'leaves no temp var behind in the caller on ANY exit path'
      # POSIX sh has no function scope: a leaked var would be visible to the whole harness.
      # The success path is the easy one to forget -- it returns before any cleanup.
      leak_probe() {
        APT_BROKEN=0 pfb_chromium_provision "$CACHE" fake_pw >/dev/null 2>&1
        printf 'leftover=[%s]\n' "${_pfb_cp_cache+set}"
      }
      When call leak_probe
      The output should equal 'leftover=[]'
    End
  End

  Describe 'pfb_playwright_cache_root'
    It 'honours PLAYWRIGHT_BROWSERS_PATH when set'
      env_override() { PLAYWRIGHT_BROWSERS_PATH=/opt/pw pfb_playwright_cache_root; }
      When call env_override
      The output should equal '/opt/pw'
    End

    It 'falls back to the HOME cache when the override is unset'
      home_default() { unset PLAYWRIGHT_BROWSERS_PATH; HOME=/home/tester pfb_playwright_cache_root; }
      When call home_default
      The output should equal '/home/tester/.cache/ms-playwright'
    End

    It 'falls back to root when HOME is unset too (never trips set -u)'
      # Branch coverage: the box runs the harness as root; an unset HOME must not abort it.
      no_home() { unset PLAYWRIGHT_BROWSERS_PATH; unset HOME; pfb_playwright_cache_root; }
      When call no_home
      The output should equal '/root/.cache/ms-playwright'
    End
  End
End

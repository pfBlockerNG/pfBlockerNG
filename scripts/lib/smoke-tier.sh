#!/bin/sh
# scripts/lib/smoke-tier.sh — map a pytest marker to the smoke run's target path,
# per-test timeout, and whether it needs the headless-browser binary.
#
# Sourced by smoke-on-box.sh (local lease runs) so a bare `local-smoke.sh -m
# ui_render` Just Works: the ADR-14 Web-UI tiers live under tests/smoke/ui and
# want a longer per-test ceiling than the default smoke tier, and the browser
# tier additionally needs Chromium (the pip `playwright` wheel ships bindings
# only). The CI path (ui-tests.yml) sets these explicitly; this keeps the local
# path in parity without the caller having to remember the right --paths/--timeout.
#
# The mapping is the testable bit — pinned by tests/shell/smoke_tier_spec.sh.
# POSIX sh; no side effects (function definitions only).

# pfb_smoke_tier_paths <marker> — echo the pytest target path for that marker.
# A UI-tier marker scopes to tests/smoke/ui; anything else uses tests/smoke.
# Glob-matched so a compound marker ("ui_render or ui_browser") still resolves.
pfb_smoke_tier_paths() {
    case "$1" in
        *ui_render*|*ui_e2e*|*ui_browser*) printf 'tests/smoke/ui\n' ;;
        *)                                 printf 'tests/smoke\n' ;;
    esac
}

# pfb_smoke_tier_timeout <marker> — echo the per-test timeout (seconds). UI tiers
# run multi-step CSRF/browser flows (300s, matching ui-tests.yml); the default
# smoke tier keeps the 30s ceiling.
pfb_smoke_tier_timeout() {
    case "$1" in
        *ui_render*|*ui_e2e*|*ui_browser*) printf '300\n' ;;
        *)                                 printf '30\n' ;;
    esac
}

# pfb_smoke_tier_needs_browser <marker> — exit 0 iff the marker runs the Tier-B
# browser tier (needs `playwright install chromium`); non-zero otherwise.
pfb_smoke_tier_needs_browser() {
    case "$1" in
        *ui_browser*) return 0 ;;
        *)            return 1 ;;
    esac
}

# pfb_playwright_cache_root — echo the playwright browser cache directory: the
# PLAYWRIGHT_BROWSERS_PATH override, else `$HOME/.cache/ms-playwright` (playwright's own
# default), else `/root/…` — the box runs the harness as root, and the caller runs under
# `set -eu`, where a bare ${HOME} aborts the whole script when HOME is unset.
pfb_playwright_cache_root() {
    printf '%s\n' "${PLAYWRIGHT_BROWSERS_PATH:-${HOME:-/root}/.cache/ms-playwright}"
}

# pfb_chromium_cached <cache_root> — exit 0 iff a Chromium build is already in the
# playwright cache (`<cache_root>/chromium-<rev>`); non-zero otherwise.
#
# The caller uses this to skip `playwright install --with-deps`, whose OS-dependency
# half shells out to apt-get on EVERY run — so a broken package on the box fails a run
# that needed no packages at all (#1226). The browser download half is a genuine no-op
# when cached; only --with-deps is not.
pfb_chromium_cached() {
    for _pfb_cc_build in "$1"/chromium-*; do
        [ -d "$_pfb_cc_build" ] && return 0
    done
    return 1
}

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

# pfb_chromium_provision <cache_root> <playwright_cmd...> — install the Tier-B browser.
#
# `--with-deps` FIRST, so a healthy box always gets whatever OS libs the current Chromium
# revision wants. Its apt-get half runs even when nothing needs installing, though, so
# unrelated package breakage on the box used to fail a run that needed no packages at all
# (#1226) — survivable IFF a build is already cached, since the libs then came from an
# earlier --with-deps on this box: retry without that half. With nothing cached the box
# genuinely cannot run the tier, so say so and fail rather than skip silently.
pfb_chromium_provision() {
    _pfb_cp_cache="$1"
    shift
    if "$@" install --with-deps chromium; then
        unset _pfb_cp_cache   # POSIX sh has no function scope; do not leak it on ANY exit
        return 0
    fi

    if ! pfb_chromium_cached "$_pfb_cp_cache"; then
        printf 'smoke-on-box: playwright install --with-deps failed and no Chromium is cached in %s — this box cannot be provisioned (apt/dpkg state? no cached build to fall back on)\n' \
            "$_pfb_cp_cache" >&2
        unset _pfb_cp_cache
        return 1
    fi

    printf 'smoke-on-box: --with-deps failed (apt/dpkg state?) but Chromium is cached in %s — retrying without the OS-dependency half\n' \
        "$_pfb_cp_cache" >&2
    unset _pfb_cp_cache
    "$@" install chromium
}

# pfb_chromium_cached <cache_root> — exit 0 iff a Chromium build is present in the
# playwright cache (`<cache_root>/chromium-<rev>`); non-zero otherwise.
#
# Consulted only after a --with-deps failure, to judge whether it is survivable: a build
# being there is TAKEN to mean an earlier --with-deps on this box already put its OS libs
# in place (the pool's boxes are long-lived and leased, not reprovisioned per run). It
# deliberately does NOT match the revision the pinned playwright wants, nor validate the
# build: a stale or partial one is simply re-downloaded by the retry.
pfb_chromium_cached() {
    for _pfb_cc_build in "$1"/chromium-*; do
        if [ -d "$_pfb_cc_build" ]; then
            unset _pfb_cc_build   # POSIX sh has no function scope; do not leak the iterator
            return 0
        fi
    done
    unset _pfb_cc_build
    return 1
}

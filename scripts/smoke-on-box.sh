#!/bin/sh
# scripts/smoke-on-box.sh — on-box smoke entrypoint (local runs only).
#
# Runs ON the leased LXC box (invoked by local-smoke.sh via select-box.sh -- <cmd>).
# Single-writer per lease; no other smoke runs share this box concurrently.
#
# USAGE (always via select-box.sh -- "... sh /root/pfBlockerNG/scripts/smoke-on-box.sh <flags>"):
#   smoke-on-box.sh [--ref REF] [--abi ABI] [--channel C] [--marker M] [--filter EXPR]
#                   [--no-two-vm]
#                   [--shard I] [--shard-total N]
#
# FLAGS:
#   --ref REF        git ref to check out (default: current HEAD)
#   --abi ABI        build ABI string (default: FreeBSD:15:amd64)
#   --channel C      pkg channel to build: stable|testing|edge|nightly (default: edge).
#                    The channel selects the port, and the port names the package, so this
#                    decides WHICH artifact the suite installs (issue #2206).
#   --marker M       pytest -m marker (default: smoke)
#   --filter EXPR    pytest -k filter expr (default: none)
#   --no-two-vm      skip civm image pull and set NO_TWO_VM=1
#   --shard I        0-based shard index, forwarded to run-smoke.sh (default: 0;
#                     issue #797)
#   --shard-total N  shard count, forwarded to run-smoke.sh (default: 1). N>1 is
#                     REJECTED when the marker resolves to the UI tier
#                     (tests/smoke/ui) — the UI suite always runs as one unit.
#
# ENV (set by the select-box.sh lease or inherited):
#   SMOKE_LANE        lane index for port-striding (default 0; always 0 for local runs)
#   PFB_DIAG_DIR      diagnostics dir; defaults to "smoke-diag" relative in REPO_ROOT
#   SMOKE_SSH_KEY     path to pfSense guest SSH key (default /root/smoke-ssh-key)
#   SMOKE_GHCR_TOKEN  optional; used for `oras login ghcr.io` before image pull
#   SMOKE_PFSENSE_REF pfSense image ref (default ghcr.io/pfblockerng/pfsense-ce:2.8)
#   CIVM_REF          civm image ref (default ghcr.io/pfblockerng/civm:v1)
#   PFB_LAN_REGISTRY  issue #2247: when set (box's own /etc/environment), rewrite a
#                     leading ghcr.io/ in PFSENSE_REF/CIVM_REF to
#                     "${PFB_LAN_REGISTRY}/", add --plain-http to every oras call,
#                     and skip the token-based ghcr.io login (anonymous LAN cache).
#
# Test-only (env):
#   PFB_ONBOX_REPO_ROOT  override the repo path (default /root/pfBlockerNG). Points the
#                        script at a fixture repo; never set on a box.
#   PFB_ONBOX_PORTS_DIR  override the ports checkout (default /root/FreeBSD-ports); same
#                        purpose, never set on a box.
#
# RESPONSIBILITIES (in order):
#   1. (the caller resolved the ref before invoking this script)
#   2. Ensure /root/FreeBSD-ports is current on pfblockerng/use-github.
#   3. Refresh /root/images/{pfsense,civm} via oras (digest-compare; pull when absent).
#   4. Host prep: ip_unprivileged_port_start sysctl + pkill stale qemu.
#   5. Build .pkg via build-leg.sh → SMOKE_PKG.
#   6. Build this leg's extra_pkgs (per the CURRENT ref's version matrix) via
#      build-dep-pkg-portable.py → SMOKE_DEP_PKGS (issue #1806 D2; empty when
#      the leg's extra_pkgs is empty).
#   7. Run: run-smoke.sh with the configured lane/marker/-k.
#
# POSIX sh; shellcheck clean; all expansions quoted.

set -eu

# ── Defaults ──────────────────────────────────────────────────────────────── #
_REF=""        # resolved below (HEAD) if not given
_ABI="FreeBSD:15:amd64"  # version-literal-ok: local-dev default; overridden by --abi
_CHANNEL="edge"          # the devel branch's release line; overridden by --channel
_MARKER="smoke"
_FILTER=""
_NO_TWO_VM=0
_SHARD=0       # 0-based shard index, forwarded to run-smoke.sh (issue #797)
_SHARD_TOTAL=1 # N=1 = no sharding (default)

# Testability seam (mirrors local-smoke.sh's PFB_SELECT_BOX): the box always has the repo at
# the fixed path, but tests/shell/smoke_on_box_spec.sh points this at a fixture repo so the
# arg-parse can be exercised without a box.
REPO_ROOT="${PFB_ONBOX_REPO_ROOT:-/root/pfBlockerNG}"

# ── Scrub inherited GIT_* context (via shared lib — ADR-47 chokepoint) ─── #
# Inherited from the pre-commit hook or the orchestrator's env; scrub once
# before any git operations in this script.
# shellcheck source=scripts/lib/git-env-scrub.sh
. "${REPO_ROOT}/scripts/lib/git-env-scrub.sh"
pfb_scrub_git_env
# Marker → (paths, timeout, browser?) mapping for the ADR-14 UI tiers.
# shellcheck source=scripts/lib/smoke-tier.sh
. "${REPO_ROOT}/scripts/lib/smoke-tier.sh"
# Shared-image-store-safe refresh (issue #2218): staging + rename publish, per-ref digests.
# shellcheck source=scripts/lib/oras-refresh.sh
. "${REPO_ROOT}/scripts/lib/oras-refresh.sh"
# Seam (test-only, mirroring PFB_ONBOX_REPO_ROOT): lets the spec reach the port-floor
# precondition without writing to /root. Never set on a box.
PORTS_DIR="${PFB_ONBOX_PORTS_DIR:-/root/FreeBSD-ports}"
IMAGES_DIR="/root/images"

PFSENSE_REF="${SMOKE_PFSENSE_REF:-ghcr.io/pfblockerng/pfsense-ce:2.8}"
CIVM_REF="${CIVM_REF:-ghcr.io/pfblockerng/civm:v1}"

# ── LAN registry override (issue #2247) ─────────────────────────────────────── #
# Single choke point: covers this script's own ghcr.io/... defaults above AND a
# caller-injected full ghcr.io/... ref alike (pfb_rewrite_lan_registry only
# touches a LEADING ghcr.io/, so a ref that already points elsewhere is a no-op).
PFSENSE_REF="$(pfb_rewrite_lan_registry "$PFSENSE_REF")"
CIVM_REF="$(pfb_rewrite_lan_registry "$CIVM_REF")"

# oras-refresh.sh's four oras invocations consume this (default empty -> unquoted
# expansion is zero words, i.e. no flag); set once here rather than repeating the
# flag at each call site. Exported: SC1091 is disabled repo-wide (.shellcheckrc),
# so shellcheck never follows the `.` of oras-refresh.sh from this file and reads
# this var as dead without it.
PFB_ORAS_FLAGS=""
if pfb_lan_registry_active; then
    PFB_ORAS_FLAGS="--plain-http"
fi
export PFB_ORAS_FLAGS

# ── Arg parsing ───────────────────────────────────────────────────────────── #
while [ "$#" -gt 0 ]; do
    case "$1" in
        --ref)      shift; _REF="$1";    shift ;;
        --abi)      shift; _ABI="$1";    shift ;;
        --channel)  shift; _CHANNEL="$1"; shift ;;
        --marker)   shift; _MARKER="$1"; shift ;;
        --filter)   shift; _FILTER="$1";      shift ;;
        --no-two-vm) _NO_TWO_VM=1;       shift ;;
        --shard)       shift; _SHARD="$1";       shift ;;
        --shard-total) shift; _SHARD_TOTAL="$1"; shift ;;
        *) printf 'smoke-on-box: unknown argument: %s\n' "$1" >&2; exit 1 ;;
    esac
done

# ── Step 1: the ref is already resolved ────────────────────────────────────── #
# The caller (local-smoke.sh's bootstrap, via select-box.sh) fetches the requested ref and
# checks out its FETCHED TIP before invoking this script, so there is nothing to resolve
# here. This script used to re-fetch and re-exec itself at the same ref, which duplicated
# the caller's work and put the choice of WHICH code runs inside the container.
[ -n "$_REF" ] || _REF="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
printf 'smoke-on-box: running at ref %s\n' "$_REF" >&2
# Echo the whole resolved configuration, not just the ref: a flag that silently
# failed to parse otherwise shows up only as a leg that quietly ran the default.
# pfsense_ref/civm_ref are echoed AFTER their LAN-registry rewrite (issue #2247), so
# a wrong rewrite is visible here rather than only three steps later, mid pull.
printf 'smoke-on-box: config abi=%s channel=%s marker=%s filter=%s shard=%s/%s two-vm=%s pfsense_ref=%s civm_ref=%s\n' \
    "$_ABI" "$_CHANNEL" "$_MARKER" "${_FILTER:-<none>}" "$_SHARD" "$_SHARD_TOTAL" \
    "$([ "$_NO_TWO_VM" -eq 1 ] && echo no || echo yes)" "$PFSENSE_REF" "$CIVM_REF" >&2

# Checked FIRST: this is a property of how we were INVOKED, so failing here costs
# nothing, while discovering it after the ports refresh and the image pull wastes minutes
# and reports as a mock-DNS failure rather than a missing docker flag.
# The unprivileged-port floor (so the non-root mock DNS can bind :53) is set by the
# caller's `docker run --sysctl net.ipv4.ip_unprivileged_port_start=53`: the sysctl is
# namespaced, and a container cannot set it on the host. Fail loudly rather than let the
# mock DNS fail to bind halfway through a run.
# Seam: the spec pins this at a fixture file so the gate fires deterministically. Without
# it the examples depend on the AMBIENT floor, and on a host that already has it lowered --
# which is exactly what this script's own container is -- the run would sail past the gate
# and reach the real host prep, whose `pkill -9 -f qemu-system-x86_64` would kill a
# concurrent leg's VMs on a shared box.
_floor_file="${PFB_ONBOX_PORT_FLOOR_FILE:-/proc/sys/net/ipv4/ip_unprivileged_port_start}"
_floor="$(cat "$_floor_file" 2>/dev/null || echo 1024)"
if [ "$_floor" -gt 53 ]; then
    printf 'smoke-on-box: ip_unprivileged_port_start is %s; the caller must pass\n' "$_floor" >&2
    printf 'smoke-on-box:   --sysctl net.ipv4.ip_unprivileged_port_start=53\n' >&2
    exit 1
fi

cd "$REPO_ROOT"

# ── Derive build params from the ABI ─────────────────────────────────────── #
# Extract FreeBSD major to pick the matching PHP version.
# FreeBSD 15 = CE 2.8 (php 8.3); FreeBSD 16 = Plus 26.03 (php 8.5).
# py_flavor is py311 for all current legs.
_freebsd_major="${_ABI#FreeBSD:}"
_freebsd_major="${_freebsd_major%%:*}"
case "$_freebsd_major" in
    15) _php_ver="8.3" ;;
    16) _php_ver="8.5" ;;
    *)
        printf 'smoke-on-box: unknown FreeBSD major %s in ABI %s; defaulting to 8.3\n' \
            "$_freebsd_major" "$_ABI" >&2
        _php_ver="8.3"
        ;;
esac
# ponytail: all current legs use py311; extend the case above when this changes.
_py_flavor="py311"  # version-literal-ok: all current legs are py311 (see comment above)

# ── Step 2: ports tree — bring to pfblockerng/use-github ───────────────────── #
printf 'smoke-on-box: updating FreeBSD-ports at %s (php=%s %s)\n' \
    "$PORTS_DIR" "$_php_ver" "$_py_flavor" >&2
sh scripts/sparse-clone-ports.sh \
    "https://github.com/pfBlockerNG/FreeBSD-ports" \
    "pfblockerng/use-github" \
    "$PORTS_DIR" \
    "$_CHANNEL" "$_php_ver" "$_py_flavor" >&2

# ── Step 3: oras images (refresh when stale; pull when absent) ─────────────── #
_oras_login_done=0
# issue #2247: the LAN registry is anonymous read-only -- when it is active, leave
# oras-refresh.sh's own no-op pfb_oras_login stub in effect (sourced above) rather
# than defining the real token-based ghcr.io login here.
if ! pfb_lan_registry_active; then
    pfb_oras_login() {
        if [ "$_oras_login_done" -eq 0 ] && [ -n "${SMOKE_GHCR_TOKEN:-}" ]; then
            printf '%s\n' "$SMOKE_GHCR_TOKEN" | \
                oras login ghcr.io --username pfBlockerNG --password-stdin >/dev/null 2>&1 \
                || true
            _oras_login_done=1
        fi
    }
fi

pfb_oras_refresh "$PFSENSE_REF" "${IMAGES_DIR}/pfsense" "pfSense"
if [ "$_NO_TWO_VM" -eq 0 ]; then
    pfb_oras_refresh "$CIVM_REF" "${IMAGES_DIR}/civm" "civm"
fi

_IMAGE_VIEW_ROOT="${REPO_ROOT}/out/smoke-images"
SMOKE_IMAGE_DIR="${_IMAGE_VIEW_ROOT}/pfsense"
pfb_oras_ref_view "$PFSENSE_REF" "${IMAGES_DIR}/pfsense" "$SMOKE_IMAGE_DIR"
export SMOKE_IMAGE_DIR
if [ "$_NO_TWO_VM" -eq 0 ]; then
    SMOKE_CLIENT_IMAGE_DIR="${_IMAGE_VIEW_ROOT}/civm"
    pfb_oras_ref_view "$CIVM_REF" "${IMAGES_DIR}/civm" "$SMOKE_CLIENT_IMAGE_DIR"
    export SMOKE_CLIENT_IMAGE_DIR
    export NO_TWO_VM=0
else
    export NO_TWO_VM=1
fi

# ── Step 4: host prep (this box only — single-writer per lease) ─────────────── #
export SMOKE_STUB_DNS_ADDR="${SMOKE_STUB_DNS_ADDR:-127.0.0.1}"
export SMOKE_STUB_DNS_PORT="${SMOKE_STUB_DNS_PORT:-53}"

# Kill any stale qemu from a previous run on this box (lease guarantees we are
# the only writer; pkill -9 never touches another box's VMs).
pkill -9 -f qemu-system-x86_64 2>/dev/null || true

# ── Step 5: build .pkg ─────────────────────────────────────────────────────── #
printf 'smoke-on-box: building .pkg (abi=%s channel=%s)...\n' "$_ABI" "$_CHANNEL" >&2
SMOKE_PKG="$(sh scripts/build-leg.sh \
    --ports-dir  "$PORTS_DIR" \
    --channel    "$_CHANNEL" \
    --abi        "$_ABI" \
    --php        "$_php_ver" \
    --py-flavor  "$_py_flavor" \
    --local-src  "$REPO_ROOT")"
export SMOKE_PKG
printf 'smoke-on-box: pkg built: %s\n' "$SMOKE_PKG" >&2

# ── Step 5b: this leg's dep pkgs (issue #1806 D2) ──────────────────────────── #
# Look up this leg's freebsd_major row in the CURRENT ref's BUILD matrix
# (read-version-matrix.sh --print-build is deduped one row per major) for its
# extra_pkgs (port origins pfSense's own repo doesn't carry, e.g.
# textproc/py-charset-normalizer for CE) and build each as a dep .pkg, from the
# SAME ports tree build-leg.sh above just prepared/reused (no second clone).
_BUILD_ROW="$(sh scripts/read-version-matrix.sh --print-build)" \
    || { printf 'smoke-on-box: could not read the version matrix for extra_pkgs\n' >&2; exit 1; }
_EXTRA_PKGS_JSON="$(printf '%s' "$_BUILD_ROW" | jq -c --arg maj "$_freebsd_major" \
    '([.[] | select(.freebsd_major == $maj)][0].extra_pkgs) // []')"
_EXTRA_PKGS_COUNT="$(printf '%s' "$_EXTRA_PKGS_JSON" | jq 'length')"
# This leg's OWN py_flavor from the SAME matrix row (already read above for
# extra_pkgs) -- never the top-level hardcoded default: a dep .pkg's
# python<NNN> RUN_DEPENDS must match the box's REAL flavor, which the matrix
# already knows precisely, even while the branch-.pkg build above still uses
# the hardcoded ceiling (see its own comment).
_dep_py_flavor="$(printf '%s' "$_BUILD_ROW" | jq -r --arg maj "$_freebsd_major" \
    '([.[] | select(.freebsd_major == $maj)][0].py_flavor) // ""')"
[ -n "$_dep_py_flavor" ] || _dep_py_flavor="$_py_flavor"
SMOKE_DEP_PKGS=""
if [ "$_EXTRA_PKGS_COUNT" -gt 0 ]; then
    _DEP_PKG_DIR="${REPO_ROOT}/out/deppkgs"
    mkdir -p "$_DEP_PKG_DIR"
    _i=0
    while [ "$_i" -lt "$_EXTRA_PKGS_COUNT" ]; do
        _origin="$(printf '%s' "$_EXTRA_PKGS_JSON" | jq -r ".[$_i]")"
        # sparse-clone-ports.sh's checkout only includes the pfBlockerNG port's
        # OWN RUN_DEPENDS -- extra_pkgs is a matrix-level concept it doesn't
        # know about, so this origin's dir was never materialized. Add it
        # explicitly (idempotent; cone mode already set by sparse-clone-ports.sh).
        git -C "$PORTS_DIR" sparse-checkout add "$_origin"
        printf 'smoke-on-box: building dep pkg %s...\n' "$_origin" >&2
        # Capture WITHOUT a pipe first -- a pipe inside `$(...)` would take the
        # PIPELINE's exit status (tail's, always 0) instead of the builder's,
        # masking a real build failure under `set -e`. Then tail -n 1 as
        # belt-and-braces on top of the script's own stdout=path-only contract
        # (take only the LAST line no matter what).
        _dep_pkg_out="$(python3 scripts/build-dep-pkg-portable.py \
            --ports "$PORTS_DIR" \
            --port "$_origin" \
            --py-flavor "$_dep_py_flavor" \
            --freebsd-major "$_freebsd_major" \
            --out-dir "$_DEP_PKG_DIR")"
        _dep_pkg="$(printf '%s\n' "$_dep_pkg_out" | tail -n 1)"
        SMOKE_DEP_PKGS="${SMOKE_DEP_PKGS:+$SMOKE_DEP_PKGS }${_dep_pkg}"
        _i=$((_i + 1))
    done
    printf 'smoke-on-box: dep pkgs built: %s\n' "$SMOKE_DEP_PKGS" >&2
fi
export SMOKE_DEP_PKGS

# SSH key for the pfSense guest (baked into the image).
export SMOKE_SSH_KEY="${SMOKE_SSH_KEY:-/root/smoke-ssh-key}"
if [ ! -f "$SMOKE_SSH_KEY" ]; then
    printf 'smoke-on-box: SMOKE_SSH_KEY not a file: %s\n' "$SMOKE_SSH_KEY" >&2
    printf 'smoke-on-box: set SMOKE_SSH_KEY or place the key at /root/smoke-ssh-key\n' >&2
    exit 2
fi

# ── Step 5c: provision the Python test deps into a repo-root venv ──────────── #
# The box ships python3 but not pytest; install the harness deps (version-pinned
# by the checked-out ref's tests/smoke/requirements.txt, + pytest explicitly, the
# same set CI installs) into ${REPO_ROOT}/.venv so run-smoke.sh's non-CI .venv
# preference uses it. Idempotent: reuse an existing venv; pip is a no-op when the
# pinned deps are already satisfied.
printf 'smoke-on-box: provisioning test venv (.venv)...\n' >&2
_VENV_DIR="${REPO_ROOT}/.venv"
# `venv --clear` follows a directory symlink and erases its target before failing.
if [ -L "$_VENV_DIR" ] || { [ -e "$_VENV_DIR" ] && [ ! -d "$_VENV_DIR" ]; }; then
    printf 'smoke-on-box: refusing unsafe venv path: %s\n' "$_VENV_DIR" >&2
    exit 2
fi
[ -x "${_VENV_DIR}/bin/python" ] || python3 -m venv --clear "$_VENV_DIR"
"${REPO_ROOT}/.venv/bin/python" -m pip install --quiet --upgrade pip
"${REPO_ROOT}/.venv/bin/python" -m pip install --quiet -r "${REPO_ROOT}/tests/smoke/requirements.txt" pytest

# The Tier-B browser marker needs the Chromium BINARY (the pip wheel above ships the
# bindings only); mirrors ui-tests.yml. The install order and its apt-failure fallback are
# the testable bit — they live in the lib, pinned by tests/shell/smoke_tier_spec.sh.
if pfb_smoke_tier_needs_browser "$_MARKER"; then
    printf 'smoke-on-box: provisioning headless Chromium (browser tier)...\n' >&2
    pfb_chromium_provision "$(pfb_playwright_cache_root)" "${REPO_ROOT}/.venv/bin/python" -m playwright
fi

# ── Step 7: run smoke ─────────────────────────────────────────────────────── #
# Paths + per-test timeout follow the marker: a UI tier scopes to tests/smoke/ui
# with the 300s ceiling (matching ui-tests.yml); everything else keeps the
# whole-suite tests/smoke + 30s default.
_PATHS="$(pfb_smoke_tier_paths "$_MARKER")"
_TIMEOUT="$(pfb_smoke_tier_timeout "$_MARKER")"

# Sharding is only supported for the default full-suite marker (issue #797):
# the UI tier (ADR-14) always runs as a single unit (small, non-module-fungible
# suite), and a non-smoke marker (repo/reboot/...) selects too few modules for
# a slice to be meaningful — local-smoke.sh enforces the same policy at its own
# entry point; this is the on-box defence-in-depth layer for direct invocations.
if [ "$_SHARD_TOTAL" != "1" ] && { [ "$_PATHS" != "tests/smoke" ] || [ "$_MARKER" != "smoke" ]; }; then
    printf 'smoke-on-box: --shard-total %s is only supported with marker=smoke on tests/smoke (got marker=%s paths=%s)\n' \
        "$_SHARD_TOTAL" "$_MARKER" "$_PATHS" >&2
    exit 1
fi

printf 'smoke-on-box: running smoke (marker=%s paths=%s timeout=%s%s)\n' \
    "$_MARKER" "$_PATHS" "$_TIMEOUT" "${_FILTER:+ filter=$_FILTER}" >&2

set -- --paths "$_PATHS" --marker "$_MARKER" --timeout "$_TIMEOUT"
[ -n "$_FILTER" ] && set -- "$@" --filter "$_FILTER"
[ "$_SHARD" != "0" ] && set -- "$@" --shard "$_SHARD"
[ "$_SHARD_TOTAL" != "1" ] && set -- "$@" --shard-total "$_SHARD_TOTAL"
exec sh scripts/run-smoke.sh "$@"

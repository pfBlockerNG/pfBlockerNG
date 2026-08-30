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
#   --pkgversion V   nightly identity YYYYMMDDHHMMSS.<7-sha>. When omitted on
#                    --channel nightly, derived from scripts/nightly-pkgversion.sh
#                    using the just-checked-out HEAD (the commit this script
#                    builds, issue #2754). An explicit flag or
#                    PFB_NIGHTLY_PKGVERSION is the documented exception: the
#                    operator may stamp any identity. Ignored on other channels.
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
#   SMOKE_PFSENSE_VERSION expected guest version; default is the image tag, or `?`
#                         when SMOKE_PFSENSE_REF is digest-only
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
#   PFB_ONBOX_IMAGES_DIR override the image root (default /root/images); test-only seam,
#                        never set on a box.
#
# RESPONSIBILITIES (in order):
#   1. (the caller resolved the ref before invoking this script)
#   2. Ensure /root/FreeBSD-ports is current on pfblockerng/use-github.
#   3. Pull /root/images/{pfsense,civm} directly via oras into this workload's filesystem.
#   4. Host prep: ip_unprivileged_port_start sysctl + pkill stale qemu.
#   5. Build .pkg via build-leg.sh → SMOKE_PKG.
#   6. Sync the locked smoke + dependency-builder environment.
#   7. Build this leg's extra_pkgs (per the CURRENT ref's version matrix) via
#      build-dep-pkg-portable.py → SMOKE_DEP_PKGS (issue #1806 D2; empty when
#      the leg's extra_pkgs is empty).
#   8. Run: run-smoke.sh with the configured lane/marker/-k.
#
# POSIX sh; shellcheck clean; all expansions quoted.

set -eu

# ── Defaults ──────────────────────────────────────────────────────────────── #
_REF=""        # resolved below (HEAD) if not given
_ABI="FreeBSD:15:amd64"  # version-literal-ok: local-dev default; overridden by --abi
_CHANNEL="edge"          # the devel branch's release line; overridden by --channel
_PKGVERSION="${PFB_NIGHTLY_PKGVERSION:-}"
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
# LAN registry ref rewrite and mode detection (issue #2247).
# shellcheck source=scripts/lib/lan-registry.sh
. "${REPO_ROOT}/scripts/lib/lan-registry.sh"
# Seam (test-only, mirroring PFB_ONBOX_REPO_ROOT): lets the spec reach the port-floor
# precondition without writing to /root. Never set on a box.
PORTS_DIR="${PFB_ONBOX_PORTS_DIR:-/root/FreeBSD-ports}"
IMAGES_DIR="${PFB_ONBOX_IMAGES_DIR:-/root/images}"

PFSENSE_REF="${SMOKE_PFSENSE_REF:-ghcr.io/pfblockerng/pfsense-ce:2.8}"
CIVM_REF="${CIVM_REF:-ghcr.io/pfblockerng/civm:v1}"

# ── LAN registry override (issue #2247) ─────────────────────────────────────── #
# Single choke point: covers this script's own ghcr.io/... defaults above AND a
# caller-injected full ghcr.io/... ref alike (pfb_rewrite_lan_registry only
# touches a LEADING ghcr.io/, so a ref that already points elsewhere is a no-op).
PFSENSE_REF="$(pfb_rewrite_lan_registry "$PFSENSE_REF")"
CIVM_REF="$(pfb_rewrite_lan_registry "$CIVM_REF")"

# Direct oras pulls consume this (default empty -> unquoted expansion is zero words,
# i.e. no flag); set once here rather than repeating the flag at each call site.
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
        --pkgversion) shift; _PKGVERSION="$1"; shift ;;
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
# the caller's work and moved the choice of WHICH code runs away from the caller.
[ -n "$_REF" ] || _REF="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
printf 'smoke-on-box: running at ref %s\n' "$_REF" >&2

# One preflight for every tool the leg shells out to, before anything expensive. Reported
# as a single list: a box missing three tools should say so once, not fail three runs.
_missing=''
for _tool in git jq curl uv oras python3 ssh qemu-system-x86_64 qemu-img dig iptables zstd tar unzip pkill; do
	command -v "$_tool" >/dev/null 2>&1 || _missing="${_missing} ${_tool}"
done
if [ -n "$_missing" ]; then
	printf 'smoke-on-box: missing required tools on this box:%s\n' "$_missing" >&2
	printf 'smoke-on-box: see docs/misc/local-smoke-debian.md for what a box carries\n' >&2
	exit 2
fi
# Echo the whole resolved configuration, not just the ref: a flag that silently
# failed to parse otherwise shows up only as a leg that quietly ran the default.
# pfsense_ref/civm_ref are echoed AFTER their LAN-registry rewrite (issue #2247), so
# a wrong rewrite is visible here rather than only three steps later, mid pull.
printf 'smoke-on-box: config abi=%s channel=%s marker=%s filter=%s shard=%s/%s two-vm=%s pfsense_ref=%s civm_ref=%s\n' \
    "$_ABI" "$_CHANNEL" "$_MARKER" "${_FILTER:-<none>}" "$_SHARD" "$_SHARD_TOTAL" \
    "$([ "$_NO_TWO_VM" -eq 1 ] && echo no || echo yes)" "$PFSENSE_REF" "$CIVM_REF" >&2

# Checked FIRST: this is a property of how we were INVOKED, so failing here costs
# nothing, while discovering it after the ports refresh and the image pull wastes minutes
# and reports as a mock-DNS failure rather than as unprepared host state.
# The unprivileged-port floor (so the non-root mock DNS can bind :53) is lowered by the
# caller, which is the side that has the privilege to write it. Fail loudly rather than
# let the mock DNS fail to bind halfway through a run.
# Seam: the spec pins this at a fixture file so the gate fires deterministically. Without
# it the examples depend on the AMBIENT floor, and on a host that already has it lowered
# the run would sail past the gate and reach the real host prep, whose
# `pkill -9 -f qemu-system-x86_64` would kill a concurrent leg's VMs on a shared box.
_floor_file="${PFB_ONBOX_PORT_FLOOR_FILE:-/proc/sys/net/ipv4/ip_unprivileged_port_start}"
_floor="$(cat "$_floor_file" 2>/dev/null || echo 1024)"
if [ "$_floor" -gt 53 ]; then
    printf 'smoke-on-box: ip_unprivileged_port_start is %s; the caller must run\n' "$_floor" >&2
    printf 'smoke-on-box:   sysctl -w net.ipv4.ip_unprivileged_port_start=53\n' >&2
    exit 1
fi

cd "$REPO_ROOT"

# ── Derive build params from the ABI ─────────────────────────────────────── #
# The exact runtime tuple (freebsd_major, php_version, py_flavor) picks the
# matrix row; the row supplies php_version, py_flavor, and extra_pkgs. NEVER a
# major -> php table (issue #2464): "FreeBSD 15 means php 8.3" was the current
# row set written down as a rule, so a new major silently built the wrong php.
# issue #2926: --print-build is deduped to one row per runtime TUPLE, so
# major-only [0] selection would silently pick the wrong runtime when two
# tuples share a major (e.g. FreeBSD 16 / PHP 8.4 and 8.5). This box's ABI
# carries only the major, so when a major holds more than one tuple this
# launcher CANNOT know which one the image needs — it refuses rather than
# guesses; a leg targeting one of them sets SMOKE_PHP_VERSION (+ optionally
# SMOKE_PY_FLAVOR) to name its tuple, as smoke-single.yml already exports.
_freebsd_major="${_ABI#FreeBSD:}"
_freebsd_major="${_freebsd_major%%:*}"
_BUILD_ROW="$(sh scripts/read-version-matrix.sh --print-build)" \
    || { printf 'smoke-on-box: could not read the version matrix\n' >&2; exit 1; }
_ROW_MATCHES="$(printf '%s' "$_BUILD_ROW" | jq -c --arg maj "$_freebsd_major" --arg php "${SMOKE_PHP_VERSION:-}" --arg py "${SMOKE_PY_FLAVOR:-}" '
    [.[] | select(.freebsd_major == $maj) | select($php == "" or .php_version == $php)
          | select($py == "" or .py_flavor == $py)]' 2>/dev/null)"
_ROW_COUNT="$(printf '%s' "$_ROW_MATCHES" | jq 'length' 2>/dev/null || echo 0)"
if [ -z "$_ROW_MATCHES" ] || [ "$_ROW_COUNT" -eq 0 ]; then
    printf 'smoke-on-box: no matrix row for FreeBSD major %s (ABI %s; selectors php=%s py=%s) — refusing to guess php/py\n' \
        "$_freebsd_major" "$_ABI" "${SMOKE_PHP_VERSION:-unset}" "${SMOKE_PY_FLAVOR:-unset}" >&2
    exit 1
fi
if [ "$_ROW_COUNT" -gt 1 ]; then
    printf 'smoke-on-box: FreeBSD major %s matches more than one BUILD row for runtime tuple selection (ABI %s) — refusing to silently pick one; set SMOKE_PHP_VERSION/SMOKE_PY_FLAVOR\n' \
        "$_freebsd_major" "$_ABI" >&2
    exit 1
fi
_SELECTED_ROW="$_ROW_MATCHES"
_php_ver="$(printf '%s' "$_SELECTED_ROW" | jq -r '.[0].php_version')"
_py_flavor="$(printf '%s' "$_SELECTED_ROW" | jq -r '.[0].py_flavor')"

# ── Step 2: ports tree — bring to pfblockerng/use-github ───────────────────── #
printf 'smoke-on-box: updating FreeBSD-ports at %s (php=%s %s)\n' \
    "$PORTS_DIR" "$_php_ver" "$_py_flavor" >&2
sh scripts/sparse-clone-ports.sh \
    "https://github.com/pfBlockerNG/FreeBSD-ports" \
    "pfblockerng/use-github" \
    "$PORTS_DIR" \
    "$_CHANNEL" "$_php_ver" "$_py_flavor" >&2

# ── Step 3: oras images (direct pull into this workload) ───────────────────── #
_oras_login_done=0
# issue #2247: the LAN registry is anonymous read-only, so skip token-based login there.
_oras_login() {
    if [ "$_oras_login_done" -eq 0 ] && [ -n "${SMOKE_GHCR_TOKEN:-}" ]; then
        printf '%s\n' "$SMOKE_GHCR_TOKEN" | \
            oras login ghcr.io --username pfBlockerNG --password-stdin >/dev/null 2>&1 \
            || true
        _oras_login_done=1
    fi
}

_oras_pull() {
    _op_ref="$1"
    _op_dir="$2"
    _op_tag="$3"
    # Empty the target first. tests/smoke/conftest.py requires EXACTLY ONE *.qcow2 per
    # image dir, and the names carry the variant and version (pfSense-CE_2.8.qcow2,
    # pfSense-Plus_26.03.qcow2, civm_v1.qcow2), so a run against a different variant or
    # version would leave two behind and strand the box for every later run -- including
    # ones that would otherwise pass. Re-pulling the same tag overwrites in place, which
    # is why only a switch exposes it.
    rm -rf "$_op_dir"
    mkdir -p "$_op_dir"
    if ! pfb_lan_registry_active; then
        case "$_op_ref" in
            ghcr.io/*) _oras_login ;;
        esac
    fi
    printf 'smoke-on-box: pulling %s image (%s) -> %s\n' \
        "$_op_tag" "$_op_ref" "$_op_dir" >&2
    # Resolve once, then fetch annotations and pull by that immutable digest.
    # This prevents a moving tag from making the log describe different bytes.
    # shellcheck disable=SC2086  # intentional: empty flags expand to zero words
    _op_digest="$(oras resolve ${PFB_ORAS_FLAGS:-} "$_op_ref" 2>/dev/null || true)"
    _op_descriptor=""
    if [ -z "$_op_digest" ]; then
        # shellcheck disable=SC2086  # intentional: empty flags expand to zero words
        _op_descriptor="$(oras manifest fetch ${PFB_ORAS_FLAGS:-} "$_op_ref" --descriptor)"
        _op_digest="$(printf '%s\n' "$_op_descriptor" | jq -r '.digest')"
    fi
    case "$_op_digest" in
        sha256:*) ;;
        *) printf 'smoke-on-box: invalid %s image digest: %s\n' "$_op_tag" "$_op_digest" >&2; exit 1 ;;
    esac
    if [ -z "$_op_descriptor" ]; then
        # shellcheck disable=SC2086  # intentional: empty flags expand to zero words
        _op_descriptor="$(oras manifest fetch ${PFB_ORAS_FLAGS:-} "${_op_ref%@*}@${_op_digest}" --descriptor)"
    fi
    _op_descriptor_digest="$(printf '%s\n' "$_op_descriptor" | jq -r '.digest')"
    [ "$_op_descriptor_digest" = "$_op_digest" ] || {
        printf 'smoke-on-box: %s descriptor digest %s disagrees with resolved digest %s\n' \
            "$_op_tag" "$_op_descriptor_digest" "$_op_digest" >&2
        exit 1
    }
    # Annotations live in the manifest body; digest-addressed descriptors may
    # omit them. Read the body by the exact digest that the pull uses below.
    # shellcheck disable=SC2086  # intentional: empty flags expand to zero words
    _op_manifest="$(oras manifest fetch ${PFB_ORAS_FLAGS:-} "${_op_ref%@*}@${_op_digest}")"
    printf 'smoke-on-box: %s image identity %s\n' "$_op_tag" \
        "$(printf '%s\n' "$_op_manifest" | jq -c --arg digest "$_op_digest" \
            '{digest:$digest, pfsense_version:(.annotations["io.github.pfblockerng.pfsense-version"] // null), image_version:(.annotations["org.opencontainers.image.version"] // null), created:(.annotations["org.opencontainers.image.created"] // null)}')" >&2
    # shellcheck disable=SC2086  # intentional: empty flags expand to zero words
    ( cd "$_op_dir" && oras pull ${PFB_ORAS_FLAGS:-} "${_op_ref%@*}@${_op_digest}" ) >&2
}

_oras_pull "$PFSENSE_REF" "${IMAGES_DIR}/pfsense" "pfSense"
if [ "$_NO_TWO_VM" -eq 0 ]; then
    _oras_pull "$CIVM_REF" "${IMAGES_DIR}/civm" "civm"
fi

SMOKE_IMAGE_DIR="${IMAGES_DIR}/pfsense"
export SMOKE_IMAGE_DIR
# Give the in-guest identity probe the same resolved expectations this launcher
# used to pull and build. CI already exports both; local pfb-box runs must too.
SMOKE_IMAGE_REF="$PFSENSE_REF"
_pfsense_ref_without_digest="${PFSENSE_REF%@*}"
_pfsense_ref_leaf="${_pfsense_ref_without_digest##*/}"
case "$_pfsense_ref_leaf" in
    *:*) _pfsense_ref_version="${_pfsense_ref_leaf##*:}" ;;
    *) _pfsense_ref_version="?" ;;
esac
SMOKE_PFSENSE_VERSION="${SMOKE_PFSENSE_VERSION:-$_pfsense_ref_version}"
SMOKE_ABI="$_ABI"
export SMOKE_IMAGE_REF SMOKE_PFSENSE_VERSION SMOKE_ABI
if [ "$_NO_TWO_VM" -eq 0 ]; then
    SMOKE_CLIENT_IMAGE_DIR="${IMAGES_DIR}/civm"
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
# Nightly builds require explicit --pkgversion (YYYYMMDDHHMMSS.<7-sha>).
# Derive from the just-checked-out HEAD so the identity matches what this
# run builds (issue #2754). An explicit --pkgversion / PFB_NIGHTLY_PKGVERSION
# is the operator override and is not re-derived.
printf 'smoke-on-box: building .pkg (abi=%s channel=%s)...\n' "$_ABI" "$_CHANNEL" >&2
set -- \
    --ports-dir  "$PORTS_DIR" \
    --channel    "$_CHANNEL" \
    --abi        "$_ABI" \
    --php        "$_php_ver" \
    --py-flavor  "$_py_flavor" \
    --local-src  "$REPO_ROOT"
if [ "$_CHANNEL" = nightly ]; then
    if [ -z "$_PKGVERSION" ]; then
        _PKGVERSION="$(sh scripts/nightly-pkgversion.sh "$(git -C "$REPO_ROOT" rev-parse HEAD)")"
    fi
    set -- "$@" --pkgversion "$_PKGVERSION"
    printf 'smoke-on-box: nightly pkgversion %s\n' "$_PKGVERSION" >&2
fi
SMOKE_PKG="$(sh scripts/build-leg.sh "$@")"
export SMOKE_PKG
printf 'smoke-on-box: pkg built: %s\n' "$SMOKE_PKG" >&2

# ── Step 5b: provision the locked smoke + dep-builder venv ─────────────────── #
# Both the extra_pkgs builder below and run-smoke.sh use this exact repo-root
# environment. Idempotent: an already-synced venv is a no-op.
printf 'smoke-on-box: provisioning test venv (.venv)...\n' >&2
_VENV_DIR="${REPO_ROOT}/.venv"
# `uv sync` recreates an unusable environment in place, which would follow a directory
# symlink and erase its target.
if [ -L "$_VENV_DIR" ] || { [ -e "$_VENV_DIR" ] && [ ! -d "$_VENV_DIR" ]; }; then
    printf 'smoke-on-box: refusing unsafe venv path: %s\n' "$_VENV_DIR" >&2
    exit 2
fi
uv sync --locked --group smoke --group dep-pkg-build

# ── Step 5c: this leg's dep pkgs (issue #1806 D2) ──────────────────────────── #
# Read the SELECTED row's extra_pkgs (port origins pfSense's own repo doesn't
# carry, e.g. textproc/py-charset-normalizer for CE) from the CURRENT ref's
# BUILD matrix and build each as a dep .pkg, from the SAME ports tree
# build-leg.sh above just prepared/reused (no second clone). The exact-tuple
# selection above already narrowed _BUILD_ROW to this leg's one row — reuse it
# rather than re-matching by major (issue #2926: major-only [0] would read a
# sibling tuple's extra_pkgs).
_EXTRA_PKGS_JSON="$(printf '%s' "$_SELECTED_ROW" | jq -c '.[0].extra_pkgs // []')"
_EXTRA_PKGS_COUNT="$(printf '%s' "$_EXTRA_PKGS_JSON" | jq 'length')"
# The dep .pkgs use the SAME row-derived flavor as the branch .pkg above.
_dep_py_flavor="$_py_flavor"
SMOKE_DEP_PKGS=""
if [ "$_EXTRA_PKGS_COUNT" -gt 0 ]; then
    _DEP_PKG_DIR="${REPO_ROOT}/out/deppkgs"
    mkdir -p "$_DEP_PKG_DIR"
    _dep_ports_sha="$(git -C "$PORTS_DIR" rev-parse HEAD)"
    _dep_source_epoch="$(git -C "$REPO_ROOT" show -s --format=%ct HEAD)"
    _dep_python="${REPO_ROOT}/.venv/bin/python"
    [ -x "$_dep_python" ] || {
        printf 'smoke-on-box: missing locked dependency toolchain after uv sync\n' >&2
        exit 1
    }
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
        _dep_pkg_out="$("$_dep_python" scripts/build-dep-pkg-portable.py \
            --ports "$PORTS_DIR" \
            --ports-sha "$_dep_ports_sha" \
            --port "$_origin" \
            --py-flavor "$_dep_py_flavor" \
            --freebsd-major "$_freebsd_major" \
            --source-date-epoch "$_dep_source_epoch" \
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


# The Tier-B browser marker needs the Chromium BINARY (the playwright wheel ships the
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

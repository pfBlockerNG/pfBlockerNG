#!/bin/sh
# scripts/resolve-legs.sh — shared leg-resolution + per-leg helpers (ADR-47).
#
# Six subcommands covering the inline blocks previously repeated across
# smoke.yml / smoke-single.yml / ui-tests.yml:
#
#   legs        [--test-dir DIR] [--label LABEL]
#                 Resolve scope ladder + THREE-WAY jq + -k derivation, then
#                 expand each leg into its shards (issue #797): reads
#                 SHARDS_INPUT (script default 1 — the workflow's policy
#                 default of 3 lives in the caller's input, not here) and
#                 MARKER_INPUT (default smoke). Shard count collapses to 1
#                 unless the derived -k is EMPTY and the marker is exactly
#                 "smoke", and is clamped to the --test-dir's direct-child
#                 test_*.py module count. Every FILTERED entry gets `shard` /
#                 `shard_label` / `shard_total` STRING fields (0..S-1 / S,
#                 label = shard+1 for display). One S drives every channel —
#                 Plus shards exactly like CE (issue #856 validated
#                 same-identity parallel Plus boots).
#                 Prints the filtered legs JSON to stdout.
#                 Writes scope= / ci_matrix= / leg_matrix= / pytest_filter= to
#                 $GITHUB_OUTPUT. leg_matrix is the UNSHARDED per-leg set (one
#                 entry per version leg, no shard fields) — smoke.yml's
#                 build-pkg job matrixes over it so each version leg builds
#                 its .pkg once, shared by every shard (issue #857).
#
#   image-ref   Compose the pfSense/civm image ref from env vars.
#               Reads: INPUT_REF, INPUT_VERSION, INPUT_IMAGE_NAME,
#                      SMOKE_IMAGE_REPO, SMOKE_IMAGE_NAME, SMOKE_IMAGE_TAG.
#               Writes ref= to $GITHUB_OUTPUT; prints ref to stdout.
#
#   digest      <ref>
#               Resolve the GHCR manifest digest via oras.
#               Reads: SMOKE_GHCR_USER, SMOKE_GHCR_TOKEN.
#               Writes digest= k= to $GITHUB_OUTPUT.
#
#   exact-image-name
#               Derive IMG_NAME from IMAGE_REF + INPUT_IMAGE_NAME.
#               Prints the exact name (e.g. pfsense-ce, pfsense-plus) to stdout.
#
#   vm-identity [--civm-mac MAC]
#               Resolve VM identity; mask secrets; write RESOLVED_* to $GITHUB_ENV.
#               Reads: IMAGE_REF, INPUT_IMAGE_NAME, PLUS_MAC, PLUS_UUID, PLUS_NDI.
#               --civm-mac MAC: civm data-NIC MAC; defaults EMPTY (deny-by-default).
#
#   scrub       [--root DIR ...] [--keep PATTERN]
#               Drop console screenshots, value-redact text files.
#               Reads: IMAGE_REF, INPUT_IMAGE_NAME, SMOKE_REDACT_VALUES.
#               --root: space-separated dirs to scrub (default: smoke-diag).
#               --keep: path glob pattern to preserve from text-scrub (e.g. ui-screenshots).
#
# Top-level set -eu; subcommands run as functions under it.
# POSIX sh; shellcheck clean; no bash-isms.

set -eu

# ── Self-dir (for lib + sibling scripts) ─────────────────────────────────── #
_RL_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── GIT_* scrub (ADR-47 chokepoint) ───────────────────────────────────── #
# shellcheck source=scripts/lib/git-env-scrub.sh
. "${_RL_DIR}/lib/git-env-scrub.sh"
pfb_scrub_git_env

# ── _rl_legs ─────────────────────────────────────────────────────────────── #
_rl_legs() {
    _l_test_dir="tests/smoke"
    _l_label="marker"
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --test-dir) shift; _l_test_dir="$1"; shift ;;
            --label)    shift; _l_label="$1";    shift ;;
            *) printf 'resolve-legs legs: unknown arg: %s\n' "$1" >&2; exit 1 ;;
        esac
    done

    # ── SCOPE ladder ───────────────────────────────────────────────────────── #
    # schedule → full; explicit SCOPE_INPUT wins; anything else → impacted (the
    # lean default). Deliberately NO workflow_call rung: inside a reusable-
    # workflow callee `github.event_name` is always the CALLER's event (never
    # "workflow_call"), so such a rung is unreachable — a workflow_call gate
    # that wants the full fan-out must pass `scope: full` explicitly
    # (issue #906; test.yml's ui-suite does).
    if [ "${EVENT_NAME:-}" = "schedule" ]; then
        SCOPE="full"
    elif [ -n "${SCOPE_INPUT:-}" ]; then
        SCOPE="$SCOPE_INPUT"
    else
        SCOPE="impacted"
    fi
    case "$SCOPE" in
        impacted|full) ;;
        *) printf '::error::unknown scope '\''%s'\'' (impacted|full)\n' "$SCOPE" >&2; exit 1 ;;
    esac

    # ── THREE-WAY jq ───────────────────────────────────────────────────────── #
    # version-exact: explicit VERSION_INPUT wins (exact match).
    # full: keep all ci:true legs (matrix already pre-filtered).
    # impacted: min-CE numeric sort (2.8 < 2.10, not lexical).
    if [ -n "${VERSION_INPUT:-}" ]; then
        FILTERED="$(printf '%s\n' "$CI_MATRIX" | jq -c --arg v "$VERSION_INPUT" \
            '[ .[] | select(.pfsense_version == $v) ]')"
        [ "$(printf '%s' "$FILTERED" | jq 'length')" -ne 0 ] \
            || { printf '::error::version filter '\''%s'\'' matched no ci:true leg\n' "$VERSION_INPUT" >&2; exit 1; }
    elif [ "$SCOPE" = "full" ]; then
        FILTERED="$(printf '%s\n' "$CI_MATRIX" | jq -c '.')"
    else
        FILTERED="$(printf '%s\n' "$CI_MATRIX" | jq -c \
            '[ .[] | select(.channel == "CE") ] | sort_by(.pfsense_version | split(".") | map(tonumber)) | .[0:1]')"
        [ "$(printf '%s' "$FILTERED" | jq 'length')" -ne 0 ] \
            || { printf '::error::impacted scope found no CE leg in the CI matrix\n' >&2; exit 1; }
    fi

    # ── -k derivation ─────────────────────────────────────────────────────── #
    # Explicit PYTEST_FILTER_INPUT always wins. In impacted scope without a -k,
    # auto-derive from changed test modules. full never auto-derives.
    K=""
    if [ -n "${PYTEST_FILTER_INPUT:-}" ]; then
        K="$PYTEST_FILTER_INPUT"
    elif [ "$SCOPE" = "impacted" ]; then
        # BASE_REF is origin/devel (the merge-base branch); allow override.
        _l_base="${PFB_BASE_REF:-origin/devel}"
        git fetch --no-tags --depth=200 origin "${_l_base#origin/}:refs/remotes/${_l_base}" 2>/dev/null || true
        K="$(sh "${_RL_DIR}/impacted-tests.sh" "$_l_base" "$_l_test_dir" 2>/dev/null || true)"
        if [ -n "$K" ]; then
            printf 'impacted: auto-derived -k from changed %s modules: %s\n' "$_l_label" "$K" >&2
        else
            printf 'impacted: no changed %s modules vs %s — running the whole %s on the min CE leg. Pass -f pytest_filter=... to narrow.\n' \
                "$_l_label" "$_l_base" "$_l_label" >&2
        fi
    fi

    # ── SHARD expansion (issue #797) ──────────────────────────────────────── #
    # S from SHARDS_INPUT: empty/unset/non-numeric or <1 -> 1. This SCRIPT's
    # default is 1 (conservative standalone behaviour); the policy default of
    # 3 lives in the WORKFLOW input (smoke.yml), not here.
    case "${SHARDS_INPUT:-}" in
        '' | *[!0-9]*) S=1 ;;
        *) S="$SHARDS_INPUT" ;;
    esac
    [ "$S" -ge 1 ] || S=1

    # Collapse to 1 unless BOTH hold: the effective -k (K) is EMPTY (a
    # filtered/impacted run must never fan out to shards that may not contain
    # the selected tests) AND the marker is exactly "smoke" (a narrow marker
    # like repo/reboot selects few tests — a shard slice can collect zero and
    # pytest exit-5-fails the leg).
    _l_marker="${MARKER_INPUT:-smoke}"
    if [ -n "$K" ] || [ "$_l_marker" != "smoke" ]; then
        S=1
    fi

    # Clamp to the direct-child test_*.py module count under --test-dir (same
    # non-recursive glob as shard-modules.sh); an empty dir can't be sharded.
    _l_mod_count=0
    for _l_mod in "${_l_test_dir%/}"/test_*.py; do
        [ -e "$_l_mod" ] || continue
        _l_mod_count=$((_l_mod_count + 1))
    done
    if [ "$_l_mod_count" -eq 0 ]; then
        S=1
    elif [ "$S" -gt "$_l_mod_count" ]; then
        S="$_l_mod_count"
    fi

    # Snapshot the UNSHARDED per-leg set (one entry per version leg, no shard
    # fields) before the expansion below fans it out to legs x shards. This
    # feeds smoke.yml's build-pkg job (issue #857): one .pkg build per version
    # leg, shared by every shard of that leg — not one build per shard.
    _l_leg_matrix="$FILTERED"

    # Expand ALWAYS (even at S=1) so every matrix entry uniformly carries
    # shard/shard_total as STRINGS (workflow_call inputs are typed string;
    # avoid number/string coercion surprises). Every leg gets S copies —
    # Plus shards exactly like CE, same count and defaults (issue #856
    # validated same-identity parallel Plus boots; the #797 1-shard cap and
    # its #856 opt-in are gone).
    # shard_label is the 1-based DISPLAY counterpart of the 0-based shard index —
    # job names read "shard 1/2".."2/2" instead of the off-by-one-looking "0/2"
    # (and "shard 1/1" for an unsharded leg instead of "0/1"). Scripts keep the
    # 0-based `shard` field; the label exists for naming only.
    FILTERED="$(printf '%s\n' "$FILTERED" | jq -c --argjson s "$S" \
        '[ .[] | range(0; $s) as $i
           | . + {shard: ($i | tostring), shard_label: (($i + 1) | tostring), shard_total: ($s | tostring)} ]')"

    printf 'scope=%s  legs=%s  -k=[%s]\n' "$SCOPE" \
        "$(printf '%s' "$FILTERED" | jq 'length')" "$K" >&2

    # ── $GITHUB_OUTPUT writes ─────────────────────────────────────────────── #
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
        {
            printf 'scope=%s\n' "$SCOPE"
            printf 'ci_matrix<<__EOF__\n%s\n__EOF__\n' "$FILTERED"
            printf 'leg_matrix<<__EOF__\n%s\n__EOF__\n' "$_l_leg_matrix"
            printf 'pytest_filter<<__EOF__\n%s\n__EOF__\n' "$K"
        } >> "$GITHUB_OUTPUT"
    fi

    # ── stdout: the resolved legs JSON (for same-step capture) ───────────── #
    printf '%s\n' "$FILTERED"
}

# ── _rl_image_ref ────────────────────────────────────────────────────────── #
# Compose the pfSense/civm image ref.
# INPUT_REF wins; else compose: REPO/NAME:TAG with fallbacks.
_rl_image_ref() {
    if [ -n "${INPUT_REF:-}" ]; then
        REF="$INPUT_REF"
    else
        REPO="${SMOKE_IMAGE_REPO:-ghcr.io/$(printf '%s' "${GITHUB_REPOSITORY_OWNER:-pfblockerng}" | tr '[:upper:]' '[:lower:]')}"
        NAME="${INPUT_IMAGE_NAME:-${SMOKE_IMAGE_NAME:-pfsense-ce}}"
        TAG="${INPUT_VERSION:-${SMOKE_IMAGE_TAG:-2.8}}"
        REF="${REPO%/}/${NAME}:${TAG}"
    fi
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
        printf 'ref=%s\n' "$REF" >> "$GITHUB_OUTPUT"
    fi
    printf 'resolved image ref: %s\n' "$REF" >&2
    printf '%s\n' "$REF"
}

# ── _rl_digest ───────────────────────────────────────────────────────────── #
# Resolve the GHCR manifest digest for a given ref via oras.
_rl_digest() {
    _ref="${1:?resolve-legs digest: <ref> required}"
    printf '%s\n' "${SMOKE_GHCR_TOKEN:-}" | oras login ghcr.io \
        --username "${SMOKE_GHCR_USER:-}" --password-stdin
    DIGEST="$(oras resolve "$_ref" 2>/dev/null || true)"
    if [ -z "$DIGEST" ]; then
        DIGEST="$(oras manifest fetch "$_ref" --descriptor | jq -r '.digest')"
    fi
    case "$DIGEST" in
        sha256:*) ;;
        *) printf '::error::could not resolve a sha256 digest for %s (got '\''%s'\'')\n' "$_ref" "$DIGEST" >&2; exit 1 ;;
    esac
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
        {
            printf 'digest=%s\n' "$DIGEST"
            printf 'k=%s\n' "${DIGEST#sha256:}"
        } >> "$GITHUB_OUTPUT"
    fi
    printf 'resolved %s -> %s\n' "$_ref" "$DIGEST"
}

# ── _rl_exact_image_name ─────────────────────────────────────────────────── #
# Strip ghcr path, @digest, :tag from IMAGE_REF; fall back to INPUT_IMAGE_NAME.
_rl_exact_image_name() {
    IMG_NAME="${INPUT_IMAGE_NAME:-pfsense-ce}"
    if [ -n "${IMAGE_REF:-}" ]; then
        _ref_no_digest="${IMAGE_REF%@*}"
        IMG_NAME="${_ref_no_digest##*/}"
        IMG_NAME="${IMG_NAME%%:*}"
    fi
    printf '%s\n' "$IMG_NAME"
}

# ── _rl_vm_identity ──────────────────────────────────────────────────────── #
# Resolve VM identity, mask secrets, write RESOLVED_* to $GITHUB_ENV.
_rl_vm_identity() {
    _civm_mac=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --civm-mac) shift; _civm_mac="$1"; shift ;;
            *) printf 'resolve-legs vm-identity: unknown arg: %s\n' "$1" >&2; exit 1 ;;
        esac
    done

    IMG_NAME="$(_rl_exact_image_name)"

    # civm data MAC is secret in every edition (deny-by-default: empty unless --civm-mac set).
    REDACT_EXTRA=""
    if [ -n "${_civm_mac:-}" ]; then
        printf '::add-mask::%s\n' "$_civm_mac"
        REDACT_EXTRA="$_civm_mac"
    fi

    case "$IMG_NAME" in
        pfsense-ce)
            # CE identity is don't-care: empty MAC → QEMU assigns per-NIC defaults.
            {
                printf 'RESOLVED_VM_MAC=\n'
                printf 'RESOLVED_VM_SMBIOS_UUID=58fd7964-c40c-4f47-bf02-3fdad18f8b00\n'
                printf 'RESOLVED_REDACT<<__EOF__\n'
                [ -n "$REDACT_EXTRA" ] && printf '%s\n' "$REDACT_EXTRA"
                printf '__EOF__\n'
            } >> "${GITHUB_ENV:?GITHUB_ENV required}"
            ;;
        *)
            # Non-CE (Plus): license/NDI-keyed identity from secrets — fail closed.
            if [ -z "${PLUS_MAC:-}" ] || [ -z "${PLUS_UUID:-}" ]; then
                printf '::error::non-CE image '\''%s'\'' requires SMOKE_PLUS_MAC and SMOKE_PLUS_SMBIOS_UUID secrets; one or both are empty.\n' "$IMG_NAME" >&2
                exit 1
            fi
            # Mask each MAC line individually (multiline mask doesn't match per-line).
            printf '%s\n' "$PLUS_MAC" | while IFS= read -r _m; do
                [ -n "$_m" ] && printf '::add-mask::%s\n' "$_m"
            done
            printf '::add-mask::%s\n' "$PLUS_UUID"
            if [ -n "${PLUS_NDI:-}" ]; then printf '::add-mask::%s\n' "$PLUS_NDI"; fi
            {
                printf 'RESOLVED_VM_MAC<<__MAC_EOF__\n%s\n__MAC_EOF__\n' "$PLUS_MAC"
                printf 'RESOLVED_VM_SMBIOS_UUID=%s\n' "$PLUS_UUID"
                printf 'RESOLVED_REDACT<<__EOF__\n%s\n%s\n' "$PLUS_MAC" "$PLUS_UUID"
                [ -n "${PLUS_NDI:-}" ] && printf '%s\n' "$PLUS_NDI"
                [ -n "$REDACT_EXTRA" ] && printf '%s\n' "$REDACT_EXTRA"
                printf '__EOF__\n'
            } >> "${GITHUB_ENV:?GITHUB_ENV required}"
            ;;
    esac
}

# ── _rl_scrub ────────────────────────────────────────────────────────────── #
# Drop console screenshots; value-redact text files (Plus only).
_rl_scrub() {
    # ponytail: --root defaults to smoke-diag; UI passes "smoke-diag test-results" + --keep
    _roots="smoke-diag"
    _keep=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --root) shift; _roots="$1"; shift ;;
            --keep) shift; _keep="$1";  shift ;;
            *) printf 'resolve-legs scrub: unknown arg: %s\n' "$1" >&2; exit 1 ;;
        esac
    done

    IMG_NAME="$(_rl_exact_image_name)"

    # Non-CE: drop console screenshots (banner pixels can leak NDI/serial).
    # KEEP Playwright UI shots (ui-screenshots/) — they are DOM-masked at capture.
    case "$IMG_NAME" in
        pfsense-ce) : ;;
        *)
            # shellcheck disable=SC2086
            find . -type f \( -name 'screen-*.png' -o -name 'screen-*.ppm' \) \
                ${_keep:+-not -path "*/${_keep}/*"} -delete 2>/dev/null || true
            ;;
    esac

    # Value-redaction: strict no-op when SMOKE_REDACT_VALUES is empty (CE).
    [ -n "${SMOKE_REDACT_VALUES:-}" ] \
        || { printf 'no redaction values (CE leg) — runner-side scrub is a no-op\n'; return 0; }

    # Build redact.sed: literal s###REDACTED### per value. BRE-escape each value
    # (one -e per metachar — NOT a bracket-class — mirrors helpers.py _sed_escape_literal).
    _esc() { printf '%s' "$1" | sed \
        -e 's/\\/\\\\/g' -e 's/\./\\./g' -e 's/\*/\\*/g' \
        -e 's/\[/\\[/g' -e 's/\]/\\]/g' -e 's/\^/\\^/g' \
        -e 's/\$/\\$/g' -e 's/#/\\#/g'; }
    : > redact.sed
    printf '%s\n' "$SMOKE_REDACT_VALUES" | while IFS= read -r _v; do
        [ -n "$_v" ] || continue
        printf 's#%s#REDACTED#gI;\n' "$(_esc "$_v")" >> redact.sed
    done

    # Redact vm*.log files (runner-side VM console logs).
    find . -type f -name 'vm*.log' 2>/dev/null | while IFS= read -r _f; do
        sed -i -f redact.sed "$_f" 2>/dev/null || true
    done

    # Redact text files under each root dir; honour --keep to skip one subtree.
    # shellcheck disable=SC2086
    for _root in ${_roots}; do
        find "$_root" -type f 2>/dev/null | while IFS= read -r _f; do
            if [ -n "${_keep:-}" ]; then
                case "$_f" in
                    */"${_keep}"/*|*/"${_keep}") continue ;;
                esac
            fi
            if LC_ALL=C grep -Iq . "$_f" 2>/dev/null; then sed -i -f redact.sed "$_f" 2>/dev/null || true; fi
        done
    done
    rm -f redact.sed
}

# ── Dispatch ─────────────────────────────────────────────────────────────── #
_RL_CMD="${1:?resolve-legs.sh: subcommand required (legs|image-ref|digest|exact-image-name|vm-identity|scrub)}"
shift

case "$_RL_CMD" in
    legs)             _rl_legs              "$@" ;;
    image-ref)        _rl_image_ref              ;;
    digest)           _rl_digest            "$@" ;;
    exact-image-name) _rl_exact_image_name       ;;
    vm-identity)      _rl_vm_identity       "$@" ;;
    scrub)            _rl_scrub             "$@" ;;
    *) printf 'resolve-legs.sh: unknown subcommand: %s\n' "$_RL_CMD" >&2; exit 1 ;;
esac

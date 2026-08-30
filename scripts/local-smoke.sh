#!/bin/sh
# local-smoke.sh — run the ADR-04 live-VM smoke suite locally via a leased LXC box.
#
# Leases one box from the PFB_BOXES pool (scripts/select-box.sh), bootstraps it
# to the requested git ref, and runs the ENTIRE smoke suite ON the box with the box's
# own tools — images, build, pytest all run there. The orchestrator only provides the
# bootstrap command. The box needs qemu, oras and uv; SMOKE_GHCR_TOKEN,
# SMOKE_ADMIN_USER, SMOKE_ADMIN_PASSWORD, SMOKE_LANE, PFB_DIAG_DIR and
# PFB_LAN_REGISTRY are inherited from the box's own environment.
# The EXIT trap in select-box.sh releases the lease automatically.
#
# Full background + rationale: docs/misc/local-smoke-debian.md
#
# Usage:
#   scripts/local-smoke.sh [--ref REF] [--abi ABI] [--marker M] [--filter EXPR]
#                          [--no-two-vm] [--shards N] [--git-remote URL|NAME]
#                          [--pkgversion V]
#
# Required (env):
#   PFB_BOXES   space-separated ssh targets, e.g. "root@10.0.0.23 root@10.0.0.24"
#
# Optional (env or flags):
#   PFB_REF     git ref (commit/branch) to test (default: current HEAD)
#   --ref REF   same; flag takes precedence over PFB_REF
#   --abi ABI   build ABI (default: FreeBSD:15:amd64)
#   --channel C pkg channel to BUILD: stable|testing|edge|nightly (default: edge, the
#               channel the devel branch's 4.0.0.a* line belongs to, and the one
#               build-pkg-linux.yml builds, issue #2166). The channel picks the port,
#               and the port names the package, so a run on the wrong channel verifies a
#               differently-named artifact than CI ships (issue #2206).
#   --pkgversion V  nightly identity YYYYMMDDHHMMSS.<7-sha>, forwarded to
#               smoke-on-box.sh. Omit to let smoke-on-box.sh derive it from the
#               box's just-checked-out HEAD (the commit it actually builds).
#               Do not derive from this clone: --git-remote may point at a
#               fork/mirror whose ref is a different commit (issue #2754).
#   --marker M  pytest -m marker (default: smoke); see also --filter
#   --filter EXPR  pytest -k filter expression (optional)
#   --no-two-vm skip civm image pull and LAN-client tests
#   --shards N  lease N boxes CONCURRENTLY, each running one module-level shard
#               (issue #797; see scripts/run-smoke.sh --shard/--shard-total).
#               Default 1 (today's single-box flow, unchanged). N>1 REFUSES
#               --filter and any --marker other than smoke (a narrowed run can
#               collect zero tests per shard -- pytest exit 5 would fail the
#               shard spuriously). N should be <= the free PFB_BOXES pool; an
#               oversized N just makes the excess shards fail loudly on
#               select-box.sh's own pool-exhaustion path -- this script does
#               NOT pre-count the pool. Logs land in a kept mktemp dir printed
#               at start/end; exits non-zero iff any shard failed.
#   --git-remote URL|NAME  which git remote the BOX fetches the ref and ci-metadata
#               from (default: origin; env PFB_GIT_REMOTE, flag wins). Per-run by
#               design (issue #2497): repointing a box's origin is persistent state
#               that silently changes later runs and records nothing in the artifacts.
#               Lets a run target a local mirror, a fork, or an air-gapped copy.
#               An EMPTY env value falls back to origin (the ${VAR:-} convention);
#               only an explicit --git-remote '' is rejected.
#
# Test-only (env):
#   PFB_SELECT_BOX  override the select-box.sh path (default: scripts/select-box.sh).
#                   Used by tests/shell/local_smoke_spec.sh to inject a fake.
#   PFB_REF_PREFLIGHT  1 = ls-remote check on; 0 = skip it (SHA expansion
#                   still runs). Unset + PFB_SELECT_BOX set also skips, so
#                   hermetic --ref dummy specs keep working. Production
#                   never sets either, so the check stays on.
#   PFB_LS_REMOTE   override the `git ls-remote` binary (same argv:
#                   --exit-code <remote> <ref>). Spec injects a fake.
#   PFB_ONBOX_REPO_ROOT  override /root/pfBlockerNG for bootstrap fixture tests.
#   PFB_ONBOX_PROC_ROOT  override /proc for ownership fixture tests. Production
#                   never sets either value.
#
# The leased box runs scripts/smoke-on-box.sh, which:
#   - checks out the requested ref
#   - updates FreeBSD-ports (pfblockerng/use-github)
#   - pulls pfSense + civm images into disposable per-run paths via oras
#   - kills stale qemu (the bootstrap above lowers ip_unprivileged_port_start)
#   - builds the .pkg via build-leg.sh
#   - runs scripts/run-smoke.sh (the canonical pytest argv)
#
# POSIX sh; quoted expansions; shellcheck clean.

set -eu

usage() {
    # Self-terminating: print the header up to (not including) the Test-only
    # section, so a growing flag block can never be silently truncated again
    # (issue #2497 review: this drifted twice with fixed line ranges).
    sed -n '2,/^# Test-only (env):/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

case "${1:-}" in
    -h|--help) usage 0 ;;
esac

REPO_ROOT="$(CDPATH='' cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# ── Required env ──────────────────────────────────────────────────────────── #
if [ -z "${PFB_BOXES:-}" ]; then
    printf 'local-smoke: PFB_BOXES is required (space-separated ssh targets)\n' >&2
    printf '             e.g. export PFB_BOXES="root@10.0.0.23 root@10.0.0.24"\n' >&2
    exit 2
fi
export PFB_BOXES

# ── Parse flags ───────────────────────────────────────────────────────────── #
_REF="${PFB_REF:-}"
_ABI="FreeBSD:15:amd64"  # version-literal-ok: local-dev default; overridden by --abi
# A local run must build the same-named package CI does, or a green local smoke proves
# nothing about CI's artifact. NOT mechanically pinned to build-pkg-linux.yml: the guard test
# (tests/test_issue2166_workflow_channel_inputs.py) scans the workflows and tests/smoke, never
# this default, so the two are kept in step by hand. Both build the channel the devel branch's
# 4.0.0.a* line belongs to. Revisit if the branch changes release line.
_CHANNEL="edge"
_MARKER="smoke"
_FILTER=""
_NO_TWO_VM=0
_SHARDS=1
# issue #2497: which git remote the BOX fetches the ref (and ci-metadata) from.
# Per-run, never box state: repointing each box's origin is persistent and invisible
# in the artifacts, so a forgotten switch-back silently changes every later run.
_GIT_REMOTE="${PFB_GIT_REMOTE:-origin}"
_PKGVERSION="${PFB_NIGHTLY_PKGVERSION:-}"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --ref)      shift; _REF="$1";    shift ;;
        --abi)      shift; _ABI="$1";    shift ;;
        --channel)  shift; _CHANNEL="$1"; shift ;;
        --marker|-m) shift; _MARKER="$1"; shift ;;
        --filter)   shift; _FILTER="$1";      shift ;;
        --no-two-vm) _NO_TWO_VM=1;        shift ;;
        --shards)   shift; _SHARDS="$1"; shift ;;
        --git-remote) shift; _GIT_REMOTE="$1"; shift ;;
        --pkgversion) shift; _PKGVERSION="$1"; shift ;;
        --) shift; break ;;
        -*) printf 'local-smoke: unknown flag: %s\n' "$1" >&2; exit 2 ;;
        *)  break ;;
    esac
done
if [ "$#" -gt 0 ]; then
    printf 'local-smoke: unexpected positional args (use --marker/--filter): %s\n' "$*" >&2
    exit 2
fi

if [ -z "$_GIT_REMOTE" ]; then
    printf 'local-smoke: --git-remote requires a non-empty url or remote name\n' >&2
    exit 2
fi

case "$_CHANNEL" in
    stable|testing|edge|nightly) ;;
    *)
        printf 'local-smoke: --channel must be stable|testing|edge|nightly: %s\n' "$_CHANNEL" >&2
        exit 2
        ;;
esac

case "$_SHARDS" in
    ''|*[!0-9]*)
        printf 'local-smoke: --shards must be a positive integer: %s\n' "$_SHARDS" >&2
        exit 2
        ;;
esac
if [ "$_SHARDS" -eq 0 ]; then
    printf 'local-smoke: --shards must be >= 1: %s\n' "$_SHARDS" >&2
    exit 2
fi

if [ "$_SHARDS" -gt 1 ]; then
    if [ -n "$_FILTER" ]; then
        printf 'local-smoke: --shards N>1 refuses --filter (a -k slice can collect zero tests -- pytest exit 5 would fail that shard spuriously); drop one of the two\n' >&2
        exit 2
    fi
    if [ "$_MARKER" != "smoke" ]; then
        printf 'local-smoke: --shards N>1 refuses --marker %s (non-default markers select few tests -- same empty-slice hazard; UI tiers must never be split, which smoke-on-box.sh enforces independently); drop one of the two\n' \
            "$_MARKER" >&2
        exit 2
    fi
fi

_SELECT_BOX="${PFB_SELECT_BOX:-scripts/select-box.sh}"

if [ -z "$_REF" ]; then
    _REF="$(git -C "$REPO_ROOT" symbolic-ref --short HEAD 2>/dev/null)" || true
    if [ -z "$_REF" ]; then
        _REF="$(git -C "$REPO_ROOT" rev-parse HEAD)"
        printf 'local-smoke: WARNING: detached HEAD; using SHA %s (may not be pushed to remote)\n' \
            "$_REF" >&2
    fi
fi

_REF="${_REF#origin/}"

# issue #2780: fail before select-box.sh when the box's git fetch cannot
# succeed. An abbreviated SHA is not a fetch refspec (rc=128 in ~2s, zero
# tests); a branch that exists only on this clone is the same class.
_ref_is_hex() {
    case "$1" in
        *[!0-9a-fA-F]*|'') return 1 ;;
        *) return 0 ;;
    esac
}
_ref_len=${#_REF}
if _ref_is_hex "$_REF" && [ "$_ref_len" -ge 4 ] && [ "$_ref_len" -le 39 ]; then
    if _full="$(git -C "$REPO_ROOT" rev-parse --verify "${_REF}^{commit}" 2>/dev/null)"; then
        _REF=$_full
    else
        printf 'local-smoke: abbreviated SHA %s is not in this clone; pass a full 40-character SHA or a branch that exists on %s\n' \
            "$_REF" "$_GIT_REMOTE" >&2
        exit 2
    fi
fi
_ref_len=${#_REF}
_skip_ls=0
if _ref_is_hex "$_REF" && [ "$_ref_len" -eq 40 ]; then
    # loose objects are not advertised; the box fetch of a full SHA is the
    # check. ls-remote here would reject reachable SHAs that are not tips.
    _skip_ls=1
fi
# Production: preflight ON. Hermetic specs inject PFB_SELECT_BOX and pass
# --ref dummy; skip ls-remote unless they opted in with PFB_REF_PREFLIGHT=1.
if [ "${PFB_REF_PREFLIGHT:-}" = 0 ]; then
    _skip_ls=1
elif [ -z "${PFB_REF_PREFLIGHT+x}" ] && [ -n "${PFB_SELECT_BOX:-}" ]; then
    _skip_ls=1
fi
if [ "$_skip_ls" -eq 0 ]; then
    _ls_rc=0
    if [ -n "${PFB_LS_REMOTE:-}" ]; then
        "$PFB_LS_REMOTE" --exit-code "$_GIT_REMOTE" "$_REF" || _ls_rc=$?
    else
        git ls-remote --exit-code "$_GIT_REMOTE" "$_REF" >/dev/null 2>&1 || _ls_rc=$?
    fi
    if [ "$_ls_rc" -ne 0 ]; then
        printf 'local-smoke: ref %s is not on %s; not leasing a box\n' \
            "$_REF" "$_GIT_REMOTE" >&2
        exit 2
    fi
fi

_sq() { printf '%s' "$1" | sed "s/'/'\\\\''/g"; }
_ONBOX_REPO_ROOT_Q="$(_sq "${PFB_ONBOX_REPO_ROOT:-/root/pfBlockerNG}")"
_ONBOX_PROC_ROOT_Q="$(_sq "${PFB_ONBOX_PROC_ROOT:-/proc}")"

_REF_Q="$(_sq "$_REF")"
_GIT_REMOTE_Q="$(_sq "$_GIT_REMOTE")"
# issue #2497 review B3: with a non-origin remote, seed ci-metadata into a NEUTRAL
# local ref and tell the box's read-version-matrix.sh to read it (MATRIX_REF).
# Seeding refs/remotes/origin/ci-metadata would race the script's own tolerated
# `git fetch origin ci-metadata`: on a box whose origin is reachable, that re-fetch
# overwrites the seed and the run reads a matrix from a DIFFERENT source than the
# code under test — silently. The + prefix force-updates the neutral ref on reuse.
if [ "$_GIT_REMOTE" = "origin" ]; then
    _CIMETA_REFSPEC="ci-metadata:refs/remotes/origin/ci-metadata"
    _MATRIX_REF=""
else
    _CIMETA_REFSPEC="+ci-metadata:refs/pfb/ci-metadata"
    _MATRIX_REF="refs/pfb/ci-metadata"
fi
_CIMETA_REFSPEC_Q="$(_sq "$_CIMETA_REFSPEC")"
_MATRIX_REF_Q="$(_sq "$_MATRIX_REF")"
_ABI_Q="$(_sq "$_ABI")"
_MARKER_Q="$(_sq "$_MARKER")"
_REPO_LIVE_URL_Q="$(_sq "${SMOKE_REPO_LIVE_URL:-}")"
_NIGHTLY_LIVE_URL_Q="$(_sq "${SMOKE_NIGHTLY_LIVE_URL:-}")"
_REPO_EXPECTED_SOURCE_SHA_Q="$(_sq "${SMOKE_REPO_EXPECTED_SOURCE_SHA:-}")"
_REPO_EXPECTED_VERSION_Q="$(_sq "${SMOKE_REPO_EXPECTED_VERSION:-}")"
_REPO_EXPECTED_CHANNEL_Q="$(_sq "${SMOKE_REPO_EXPECTED_CHANNEL:-}")"
_NIGHTLY_EXPECTED_SOURCE_SHA_Q="$(_sq "${SMOKE_NIGHTLY_EXPECTED_SOURCE_SHA:-}")"
_NIGHTLY_EXPECTED_VERSION_Q="$(_sq "${SMOKE_NIGHTLY_EXPECTED_VERSION:-}")"
_PFSENSE_REF_Q="$(_sq "${SMOKE_PFSENSE_REF:-}")"
_CIVM_REF_Q="$(_sq "${CIVM_REF:-}")"
_PHP_VERSION_Q="$(_sq "${SMOKE_PHP_VERSION:-}")"
_PY_FLAVOR_Q="$(_sq "${SMOKE_PY_FLAVOR:-}")"

_ob_flags="--ref '$_REF_Q' --abi '$_ABI_Q' --channel '$_CHANNEL' --marker '$_MARKER_Q'"
# Nightly identity: smoke-on-box.sh derives from the just-checked-out HEAD
# (definitionally the built commit). Forward an explicit override only —
# deriving here from the orchestrator clone stamps a different SHA when
# --git-remote's ref diverges, and hard-fails when the ref is remote-only
# (issue #2754 M1). Other channels never forward the flag.
if [ "$_CHANNEL" = nightly ] && [ -n "$_PKGVERSION" ]; then
    _ob_flags="$_ob_flags --pkgversion '$(_sq "$_PKGVERSION")'"
fi
if [ -n "$_FILTER" ]; then
    _ob_flags="$_ob_flags --filter '$(_sq "$_FILTER")'"
fi
if [ "$_NO_TWO_VM" -eq 1 ]; then
    _ob_flags="$_ob_flags --no-two-vm"
fi

_bootstrap="cd '$_ONBOX_REPO_ROOT_Q' \
 && (lock='$_ONBOX_REPO_ROOT_Q/.git/HEAD.lock'; proc='$_ONBOX_PROC_ROOT_Q'; \
      if [ -e \"\$lock\" ] || [ -L \"\$lock\" ]; then \
          if [ -L \"\$lock\" ] || [ ! -f \"\$lock\" ]; then \
              printf 'local-smoke: box hygiene: ownership ambiguous for .git/HEAD.lock (not a regular file); box unhealthy\n' >&2; \
              exit 75; \
          fi; \
          if [ ! -d \"\$proc/1/fd\" ] || [ ! -r \"\$proc/1/fd\" ] || [ ! -x \"\$proc/1/fd\" ]; then \
              printf 'local-smoke: box hygiene: ownership ambiguous for .git/HEAD.lock (process view unavailable); box unhealthy\n' >&2; \
              exit 75; \
          fi; \
          before=\$(stat -c '%d:%i' \"\$lock\" 2>/dev/null) || { \
              printf 'local-smoke: box hygiene: ownership ambiguous for .git/HEAD.lock (stat failed); box unhealthy\n' >&2; \
              exit 75; \
          }; \
          owner_pid=''; ambiguous=0; \
          for pid_dir in \"\$proc\"/[0-9]*; do \
              [ -d \"\$pid_dir\" ] || continue; \
              pid=\${pid_dir#\"\$proc\"/}; \
              case \"\$pid\" in *[!0-9]*) continue ;; esac; \
              fd_dir=\"\$pid_dir/fd\"; \
              if [ ! -d \"\$fd_dir\" ] || [ ! -r \"\$fd_dir\" ] || [ ! -x \"\$fd_dir\" ]; then \
                  if [ -d \"\$pid_dir\" ]; then ambiguous=2; break; fi; \
                  continue; \
              fi; \
              for fd in \"\$fd_dir\"/*; do \
                  [ -L \"\$fd\" ] || continue; \
                  if target=\$(readlink \"\$fd\" 2>/dev/null); then \
                      if [ \"\$target\" = \"\$lock\" ]; then \
                          owner_pid=\$pid; break; \
                      fi; \
                  elif [ -L \"\$fd\" ]; then \
                      ambiguous=1; break; \
                  fi; \
              done; \
              if [ -n \"\$owner_pid\" ] || [ \"\$ambiguous\" -ne 0 ]; then break; fi; \
              if [ ! -d \"\$fd_dir\" ] || [ ! -r \"\$fd_dir\" ] || [ ! -x \"\$fd_dir\" ]; then \
                  if [ -d \"\$pid_dir\" ]; then ambiguous=2; break; fi; \
              fi; \
          done; \
          if [ \"\$ambiguous\" -eq 2 ]; then \
              printf 'local-smoke: box hygiene: ownership ambiguous for .git/HEAD.lock (process descriptor view unavailable); box unhealthy\n' >&2; \
              exit 75; \
          fi; \
          if [ -n \"\$owner_pid\" ]; then \
              printf 'local-smoke: box hygiene: live owner pid=%s for .git/HEAD.lock; box unhealthy\n' \"\$owner_pid\" >&2; \
              exit 75; \
          fi; \
          if [ \"\$ambiguous\" -ne 0 ]; then \
              printf 'local-smoke: box hygiene: ownership ambiguous for .git/HEAD.lock (descriptor unreadable); box unhealthy\n' >&2; \
              exit 75; \
          fi; \
          if [ -L \"\$lock\" ] || [ ! -f \"\$lock\" ]; then \
              printf 'local-smoke: box hygiene: ownership ambiguous for .git/HEAD.lock (changed during inspection; not a regular file); box unhealthy\n' >&2; \
              exit 75; \
          fi; \
          after=\$(stat -c '%d:%i' \"\$lock\" 2>/dev/null) || { \
              printf 'local-smoke: box hygiene: .git/HEAD.lock changed during inspection; box unhealthy\n' >&2; \
              exit 75; \
          }; \
          if [ \"\$before\" != \"\$after\" ]; then \
              printf 'local-smoke: box hygiene: .git/HEAD.lock changed during inspection; box unhealthy\n' >&2; \
              exit 75; \
          fi; \
          if ! rm -f \"\$lock\" || [ -e \"\$lock\" ] || [ -L \"\$lock\" ]; then \
              printf 'local-smoke: box hygiene: stale .git/HEAD.lock recovery failed; box unhealthy\n' >&2; \
              exit 75; \
          fi; \
          printf 'local-smoke: box hygiene: recovered proven-stale .git/HEAD.lock\n' >&2; \
      fi) \
 && git sparse-checkout init --cone \
 && git sparse-checkout set src scripts stubs/python tests/smoke \
 && git fetch --quiet '$_GIT_REMOTE_Q' '$_REF_Q' \
 && git checkout --quiet --force FETCH_HEAD \
 && git fetch --quiet --no-tags '$_GIT_REMOTE_Q' '$_CIMETA_REFSPEC_Q' \
 && sysctl -w net.ipv4.ip_unprivileged_port_start=53 >/dev/null \
 && exec env \
      SMOKE_PFSENSE_REF='$_PFSENSE_REF_Q' CIVM_REF='$_CIVM_REF_Q' \
      MATRIX_REF='$_MATRIX_REF_Q' \
      SMOKE_REPO_LIVE_URL='$_REPO_LIVE_URL_Q' SMOKE_NIGHTLY_LIVE_URL='$_NIGHTLY_LIVE_URL_Q' \
      SMOKE_REPO_EXPECTED_SOURCE_SHA='$_REPO_EXPECTED_SOURCE_SHA_Q' SMOKE_REPO_EXPECTED_VERSION='$_REPO_EXPECTED_VERSION_Q' \
      SMOKE_REPO_EXPECTED_CHANNEL='$_REPO_EXPECTED_CHANNEL_Q' \
      SMOKE_NIGHTLY_EXPECTED_SOURCE_SHA='$_NIGHTLY_EXPECTED_SOURCE_SHA_Q' SMOKE_NIGHTLY_EXPECTED_VERSION='$_NIGHTLY_EXPECTED_VERSION_Q' \
      SMOKE_PHP_VERSION='$_PHP_VERSION_Q' SMOKE_PY_FLAVOR='$_PY_FLAVOR_Q' \
      sh scripts/smoke-on-box.sh $_ob_flags"

printf 'local-smoke: leasing box (REF=%s marker=%s%s)\n' \
    "$_REF" "$_MARKER" "${_FILTER:+ filter=$_FILTER}" >&2

if [ "$_SHARDS" -eq 1 ]; then
    sh "$_SELECT_BOX" -- "$_bootstrap"
    exit $?
fi

_LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pfb-local-smoke-shards.XXXXXX")"
printf 'local-smoke: sharded run (--shards %s); logs: %s\n' "$_SHARDS" "$_LOG_DIR" >&2

_PIDS=""
_ABORT=0
trap '_ABORT=1; kill $_PIDS 2>/dev/null' INT TERM

_i=0
while [ "$_i" -lt "$_SHARDS" ] && [ "$_ABORT" -eq 0 ]; do
    _shard_bootstrap="${_bootstrap} --shard '$(_sq "$_i")' --shard-total '$(_sq "$_SHARDS")'"
    _shard_log="${_LOG_DIR}/shard-${_i}.log"
    sh "$_SELECT_BOX" -- "$_shard_bootstrap" > "$_shard_log" 2>&1 &
    _pid=$!
    _PIDS="$_PIDS $_pid"
    if [ "$_ABORT" -eq 1 ]; then
        kill "$_pid" 2>/dev/null || true
        break
    fi
    printf 'local-smoke: launched shard %s (pid=%s) -> %s\n' "$_i" "$_pid" "$_shard_log" >&2
    _i=$((_i + 1))
done

_RCS=""
_FAILED=0
for _pid in $_PIDS; do
    if wait "$_pid"; then
        _RCS="$_RCS 0"
    else
        _rc=$?
        _RCS="$_RCS $_rc"
        _FAILED=1
    fi
done

printf 'local-smoke: shard summary (logs: %s):\n' "$_LOG_DIR" >&2
_i=0
for _rc in $_RCS; do
    printf '  shard %s: rc=%s\n' "$_i" "$_rc" >&2
    _i=$((_i + 1))
done

if [ "$_FAILED" -eq 1 ]; then
    _i=0
    for _rc in $_RCS; do
        if [ "$_rc" -ne 0 ]; then
            printf 'local-smoke: ---- shard %s FAILED (rc=%s); last 25 lines of %s ----\n' \
                "$_i" "$_rc" "${_LOG_DIR}/shard-${_i}.log" >&2
            tail -n 25 "${_LOG_DIR}/shard-${_i}.log" >&2
            printf 'local-smoke: ---- end shard %s log ----\n' "$_i" >&2
        fi
        _i=$((_i + 1))
    done
    exit 1
fi

exit 0

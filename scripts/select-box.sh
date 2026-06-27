#!/bin/sh
# scripts/select-box.sh — lease a box from the PFB_BOXES pool, mint RUN_ID.
#
# USAGE:
#   select-box.sh [--release <RUN_ID>] [--print-id] [-- <cmd ...>]
#
# MODES:
#   default        Acquire a lease, mint RUN_ID, emit eval-able KEY=value to stdout.
#                  If -- <cmd> is given, run the command on the leased box over ssh,
#                  then trap-release on EXIT/INT/TERM.
#   --print-id     Emit ci-<GITHUB_RUN_ID>-<GITHUB_RUN_ATTEMPT>-<LEG> and exit.
#                  No lease, no ssh. (CI: the ephemeral runner IS the isolated box.)
#   --release RID  Find the box holding lease RID, verify owner, release. Idempotent.
#
# ENV (defaults):
#   PFB_BOXES        (REQUIRED) space-separated ssh targets, e.g. "root@10.0.0.23 root@10.0.0.24"
#   PFB_LEASE_DIR    shared bind-mount visible from every box (default /var/lib/pfb/leases)
#   PFB_LEASE_TTL    stale threshold in seconds — PRIMARY reclaim rule (default 7200 = 2h)
#   PFB_OWNER_GRACE  seconds before a missing-owner lock is reclaimable (default 30)
#   PFB_RUN_ROOT     base dir for per-run dirs on the leased box (default /var/tmp/pfb-runs)
#   PFB_SSH          ssh command + stock options (overridable for tests)
#   PFB_MAX_RETRIES  full-pool scan retries before giving up (default 5)
#
# OUTPUT (default mode — eval-able KEY=value on stdout):
#   RUN_ID=<local-<boxtok>-<epoch>-<rand8hex>>
#   PFB_BOX=<leased ssh target>
#   PFB_RUN_DIR=<PFB_RUN_ROOT>/<RUN_ID>
#   PFB_OUT_DIR=<PFB_RUN_DIR>/out
#   PFB_DIAG_DIR=<PFB_RUN_DIR>/smoke-diag
#   SMOKE_LANE=0
#
# STDERR: progress and diagnostics only.
# EXIT: 0 on success (lease acquired), non-zero on failure.
#
# LEASE TOPOLOGY:
#   The pool is multiple LXC/VM boxes reachable over ssh. NO host operations,
#   NO lxc commands. Lease markers live in a host directory bind-mounted into
#   every box at the same path (PFB_LEASE_DIR), so mkdir/rename on that path
#   is a single shared object visible to the whole pool.

# ── Locate sibling lib/ (same directory as this script) ──────────────────────
_SB_SELF="$(cd "$(dirname "$0")" && pwd)"

# ── Scrub inherited GIT_* context (via shared lib — ADR-47 P5 chokepoint) ────
# The pre-commit hook exports GIT_DIR / GIT_INDEX_FILE / GIT_WORK_TREE / ...
# pointing at the real repo. Any child process that runs git would operate on
# the real repo instead of its own fixture. Scrub them once here for the whole
# pipeline — all subsequent ssh commands and sourced scripts inherit clean env.
# shellcheck source=scripts/lib/git-env-scrub.sh
. "${_SB_SELF}/lib/git-env-scrub.sh"
pfb_scrub_git_env

# shellcheck disable=SC1091
. "${_SB_SELF}/lib/run-id.sh"

# ── Defaults ──────────────────────────────────────────────────────────────────
: "${PFB_LEASE_DIR:=/var/lib/pfb/leases}"
: "${PFB_LEASE_TTL:=7200}"
: "${PFB_OWNER_GRACE:=30}"
: "${PFB_RUN_ROOT:=/var/tmp/pfb-runs}"
: "${PFB_SSH:=ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR}"
: "${PFB_MAX_RETRIES:=5}"

# ── State ─────────────────────────────────────────────────────────────────────
_SB_LEASED_BOX=""
RUN_ID=""

# ── Internal helpers ──────────────────────────────────────────────────────────

# _sb_box_tok <ssh-target>
# Print a filesystem-safe token: strip user@, remove non-alphanumeric, lowercase.
_sb_box_tok() {
    _sbt="${1##*@}"
    printf '%s' "$_sbt" | tr -cd '[:alnum:]' | tr '[:upper:]' '[:lower:]'
}

# _sb_ssh <target> <cmd-string>
# Run <cmd-string> on <target> over ssh. PFB_SSH is word-split intentionally.
_sb_ssh() {
    # SC2086: word-split of PFB_SSH is intentional — it holds "ssh [opts...]"
    # shellcheck disable=SC2086
    ${PFB_SSH} "$1" "$2"
}

# _sb_jitter_sleep
# Sleep 1-3 seconds drawn from /dev/urandom (NOT $RANDOM — POSIX sh).
# This is a real between-scan backoff; the mkdir lock is the sync primitive.
_sb_jitter_sleep() {
    _sbj="$(od -An -N1 -tu1 /dev/urandom | tr -d ' \t\n')"
    sleep "$(( (_sbj % 3) + 1 ))"
}

# _sb_publish_owner <box> <lockdir> <runid>
# Atomically write owner file: write temp then mv onto owner.
# A reader never sees a half-written owner (write-then-rename = atomic publish).
# NOTE: used only by the deliberately-broken badrmdir test hook now — the live
# acquire/reclaim paths create the lock + .created + owner in one ssh call via
# _sb_claim_lock so a lock is never observable without its .created and owner.
_sb_publish_owner() {
    _sbpb="$1"
    _sbpl="$2"
    _sbpr="$3"
    _sbph="$(hostname)"
    _sbpe="$(date +%s)"
    _sb_ssh "$_sbpb" \
        "printf '%s %s %s\n' '${_sbpr}' '${_sbph}' '${_sbpe}' \
         > '${_sbpl}/owner.tmp' && mv '${_sbpl}/owner.tmp' '${_sbpl}/owner'"
}

# _sb_claim_lock <box> <lockdir> <runid>
# Create the lock AND publish its .created + owner in ONE ssh call, in order:
#   mkdir → .created → owner.tmp → mv owner.tmp owner
# This closes the acquire-side double-grant race: from any concurrent observer
# the lock is never visible without its .created (and owner), because every step
# runs in a single remote sh -c with no network round-trip gap between them.
# If mkdir fails (EEXIST under contention) the && chain short-circuits → ssh
# returns non-zero → the caller falls through to reclaim, exactly as before.
# rid/host/epoch are computed locally before the ssh. Returns the ssh exit code.
_sb_claim_lock() {
    _sbclb="$1"
    _sbcll="$2"
    _sbclr="$3"
    _sbclh="$(hostname)"
    _sbcle="$(date +%s)"
    _sb_ssh "$_sbclb" \
        "mkdir '${_sbcll}' \
         && printf '%s\n' '${_sbcle}' > '${_sbcll}/.created' \
         && printf '%s %s %s\n' '${_sbclr}' '${_sbclh}' '${_sbcle}' > '${_sbcll}/owner.tmp' \
         && mv '${_sbcll}/owner.tmp' '${_sbcll}/owner'"
}

# _sb_maybe_reclaim <box> <lockdir> <session-id>
# Try to reclaim a held lock if stale (by TTL) or missing-owner (past grace).
# ATOMIC-CAPTURE: rename the lockdir to lockdir.reclaim.<SID> — rename(2) is
# atomic, so exactly one concurrent reclaimer wins; the loser gets ENOENT.
# This is NOT rmdir+mkdir: those two ops have a window where another process
# can mkdir in between, allowing two reclaimers to both believe they won.
# Sets _SB_LEASED_BOX and RUN_ID on success. Returns 0 on success, 1 otherwise.
_sb_maybe_reclaim() {
    _sbmrb="$1"
    _sbmrl="$2"
    _sbmrs="$3"

    _sbmrnow="$(date +%s)"

    # Read current owner (may be absent if acquirer crashed before publishing).
    _sbmro="$(_sb_ssh "$_sbmrb" "cat '${_sbmrl}/owner' 2>/dev/null" 2>/dev/null)" \
        || _sbmro=""
    _sbmrorid=""
    _sbmroepoch=""
    if [ -n "$_sbmro" ]; then
        _sbmrorid="$(  printf '%s' "$_sbmro" | cut -d' ' -f1)"
        _sbmroepoch="$(printf '%s' "$_sbmro" | cut -d' ' -f3)"
    fi

    # ── Determine reclaimability ─────────────────────────────────────────────
    _sbmrclaimable=0

    if [ -z "$_sbmro" ]; then
        # No owner file. With the atomic claim (_sb_claim_lock) a lock is never
        # observable without its .created and owner, so a no-owner lock is one of:
        #   (a) .created ABSENT  → torn / in-flight acquire window. NOT reclaimable:
        #       immediate reclaim here would STEAL a freshly-acquired lease (the
        #       acquire-side double-grant race). Left for a conservative TTL sweep
        #       (not implemented here — the single-call acquire makes this window
        #       astronomically small; a residual orphan needs manual cleanup).
        #   (b) .created present but YOUNG (now - created < grace) → owner publish
        #       still pending. NOT reclaimable.
        #   (c) .created present and OLD (now - created >= grace) → genuine crash
        #       between .created and owner. Reclaimable.
        _sbmrcreated="$(_sb_ssh "$_sbmrb" "cat '${_sbmrl}/.created' 2>/dev/null" 2>/dev/null)" \
            || _sbmrcreated=""
        if [ -n "$_sbmrcreated" ] && \
           [ "$(( _sbmrnow - _sbmrcreated ))" -ge "$PFB_OWNER_GRACE" ]; then
            _sbmrclaimable=1
        fi
        # else (a)/(b): in-flight or torn acquire — do NOT reclaim.
    elif [ -n "$_sbmroepoch" ] && \
         [ "$(( _sbmrnow - _sbmroepoch ))" -gt "$PFB_LEASE_TTL" ]; then
        # Owner present but epoch is older than TTL — PRIMARY stale rule.
        # (Kill -0 is unavailable across hosts, so we rely on TTL, not process liveness.)
        _sbmrclaimable=1
    fi

    [ "$_sbmrclaimable" -eq 0 ] && return 1

    # ── TEST HOOK ────────────────────────────────────────────────────────────
    # _PFB_TEST_RECLAIM=badrmdir enables a racy rm-rf+mkdir path used ONLY in
    # tests/shell/select_box_spec.sh to produce the red-before evidence for the
    # two-concurrent-reclaimers case. This path is intentionally broken (ignores
    # the mkdir return code) so that two concurrent reclaimers both 'win', proving
    # the rename-capture approach is necessary. Never set this in production.
    if [ "${_PFB_TEST_RECLAIM:-rename}" = "badrmdir" ]; then
        _sb_ssh "$_sbmrb" "rm -rf '${_sbmrl}'"  2>/dev/null || true
        _sb_ssh "$_sbmrb" "mkdir '${_sbmrl}'"   2>/dev/null || true   # BUG: ignores EEXIST
        _SB_LEASED_BOX="$_sbmrb"
        RUN_ID="$(pfb_mint_run_id_local "$_sbmrb")"
        _sb_publish_owner "$_sbmrb" "$_sbmrl" "$RUN_ID"
        return 0
    fi

    # ── ATOMIC-CAPTURE ───────────────────────────────────────────────────────
    _sbmrreclaim="${_sbmrl}.reclaim.${_sbmrs}"

    # rename(2) is atomic on any POSIX fs: exactly one concurrent reclaimer
    # wins; the loser gets ENOENT and must rescan. This is the key invariant
    # that prevents the double-grant hole present in rmdir+mkdir reclaim.
    if ! _sb_ssh "$_sbmrb" "mv '${_sbmrl}' '${_sbmrreclaim}'" 2>/dev/null; then
        # Another reclaimer won (ENOENT) — rescan.
        return 1
    fi

    # ── TOCTOU confirm ───────────────────────────────────────────────────────
    # Re-read the CAPTURED owner and verify it still equals what we observed.
    # Guards the window where a fresh acquirer won the lock and published their
    # owner AFTER our initial read but BEFORE our rename (we'd have captured
    # their live lease). If the owner changed, restore the lock and back off.
    _sbmrcap="$(_sb_ssh "$_sbmrb" "cat '${_sbmrreclaim}/owner' 2>/dev/null" 2>/dev/null)" \
        || _sbmrcap=""
    _sbmrcaprid="$(printf '%s' "$_sbmrcap" | cut -d' ' -f1)"

    if [ "$_sbmrcaprid" != "$_sbmrorid" ]; then
        # Owner changed — a live lease was in-flight; restore it.
        _sb_ssh "$_sbmrb" "mv '${_sbmrreclaim}' '${_sbmrl}'" 2>/dev/null || true
        return 1
    fi

    # ── Take the fresh lock (atomically: lock + .created + owner in one call) ──
    _sbmrrid="$(pfb_mint_run_id_local "$_sbmrb")"
    if ! _sb_claim_lock "$_sbmrb" "$_sbmrl" "$_sbmrrid" 2>/dev/null; then
        # Another process leased it while we were confirming.
        _sb_ssh "$_sbmrb" "rm -rf '${_sbmrreclaim}'" 2>/dev/null || true
        return 1
    fi

    _SB_LEASED_BOX="$_sbmrb"
    RUN_ID="$_sbmrrid"

    # Clean up the captured reclaim dir.
    _sb_ssh "$_sbmrb" "rm -rf '${_sbmrreclaim}'" 2>/dev/null || true
    return 0
}

# _sb_acquire <box> <session-id>
# Try to acquire a lease on <box>. On success sets _SB_LEASED_BOX and RUN_ID.
# Returns 0 on success, 1 on failure.
_sb_acquire() {
    _sbab="$1"
    _sbas="$2"
    _sbatok="$(_sb_box_tok "$_sbab")"
    _sbalock="${PFB_LEASE_DIR}/${_sbatok}.lock"

    # Atomic claim over ssh: lock + .created + owner in ONE call (mkdir is the
    # create-or-fail exclusive op — exactly one concurrent racer wins the pool).
    # Because .created and owner are published in the SAME ssh call, a concurrent
    # reclaimer never observes a lock without them → no acquire-side double grant.
    _sbarid="$(pfb_mint_run_id_local "$_sbab")"
    if _sb_claim_lock "$_sbab" "$_sbalock" "$_sbarid" 2>/dev/null; then
        _SB_LEASED_BOX="$_sbab"
        RUN_ID="$_sbarid"
        return 0
    fi

    # mkdir returned EEXIST (chain short-circuited) — box is held; check for stale.
    _sb_maybe_reclaim "$_sbab" "$_sbalock" "$_sbas"
}

# _sb_release <runid>
# Find the box holding lease <runid>, verify owner, remove the lock. Idempotent.
_sb_release() {
    _sbrrid="$1"
    [ -z "$_sbrrid" ] && return 0
    # SC2086: intentional word-split on PFB_BOXES (space-separated ssh targets)
    # shellcheck disable=SC2086
    for _sbrb in ${PFB_BOXES}; do
        _sbrtok="$(_sb_box_tok "$_sbrb")"
        _sbrlock="${PFB_LEASE_DIR}/${_sbrtok}.lock"
        # Atomic: read the owner and remove the lock in ONE ssh call to close the
        # TOCTOU window between owner-check and rm-rf.
        if _sb_ssh "$_sbrb" \
            "[ \"\$(cut -d' ' -f1 '${_sbrlock}/owner' 2>/dev/null)\" = '${_sbrrid}' ] \
             && rm -rf '${_sbrlock}'" 2>/dev/null; then
            printf 'select-box: released %s on %s\n' "$_sbrrid" "$_sbrb" >&2
            return 0
        fi
    done
    # Not found — already released or never existed; idempotent.
    printf 'select-box: lease for %s not found (already released)\n' "$_sbrrid" >&2
    return 0
}

# _sb_print_holders
# Print each held box's owner info to stderr (called on pool exhaustion).
_sb_print_holders() {
    # shellcheck disable=SC2086
    for _sbhb in ${PFB_BOXES}; do
        _sbhtok="$(_sb_box_tok "$_sbhb")"
        _sbhlock="${PFB_LEASE_DIR}/${_sbhtok}.lock"
        _sbhowner="$(_sb_ssh "$_sbhb" \
            "cat '${_sbhlock}/owner' 2>/dev/null" 2>/dev/null)" \
            || _sbhowner="(unreadable)"
        [ -z "$_sbhowner" ] && _sbhowner="(empty)"
        printf '  %s: %s\n' "$_sbhb" "$_sbhowner" >&2
    done
}

# _sb_release_trap
# EXIT/INT/TERM trap: release the lease if we hold one.
_sb_release_trap() {
    [ -z "${_SB_LEASED_BOX}" ] && return 0
    _sb_release "${RUN_ID}"
}

# ── Argument parsing ───────────────────────────────────────────────────────────
_SB_MODE="default"
_SB_RELEASE_ID=""
_SB_CMD=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --print-id)
            _SB_MODE="print-id"
            shift
            ;;
        --release)
            _SB_MODE="release"
            shift
            _SB_RELEASE_ID="${1:-}"
            shift
            ;;
        --)
            shift
            _SB_CMD="$*"
            break
            ;;
        *)
            printf 'select-box: unknown argument: %s\n' "$1" >&2
            exit 1
            ;;
    esac
done

# ── Mode: --print-id ──────────────────────────────────────────────────────────
if [ "$_SB_MODE" = "print-id" ]; then
    pfb_mint_run_id_ci
    exit 0
fi

# ── Mode: --release ───────────────────────────────────────────────────────────
if [ "$_SB_MODE" = "release" ]; then
    if [ -z "$_SB_RELEASE_ID" ]; then
        printf 'select-box: --release requires a RUN_ID argument\n' >&2
        exit 1
    fi
    if [ -z "${PFB_BOXES:-}" ]; then
        printf 'select-box: PFB_BOXES is required\n' >&2
        exit 1
    fi
    _sb_release "$_SB_RELEASE_ID"
    exit $?
fi

# ── Mode: default — acquire a lease ───────────────────────────────────────────
if [ -z "${PFB_BOXES:-}" ]; then
    printf 'select-box: PFB_BOXES is required (no default); ' >&2
    printf 'set it to a space-separated list of ssh targets\n' >&2
    exit 1
fi

# Arm the EXIT/INT/TERM trap now. _SB_LEASED_BOX is empty until we successfully
# lease, so the trap is a no-op until then.
trap '_sb_release_trap' EXIT INT TERM

# Pre-mint a session ID for reclaim-dir uniqueness (box-agnostic, unique per run).
_SB_SID="$(od -An -tx1 -N4 /dev/urandom | tr -d ' \t\n')"

# Expand pool into positional parameters for random-indexed access.
# SC2086: intentional word-split on PFB_BOXES (space-separated list).
# shellcheck disable=SC2086
set -- ${PFB_BOXES}
_SB_POOL_SIZE="$#"

_SB_RETRY=0
while [ "$_SB_RETRY" -le "$PFB_MAX_RETRIES" ]; do

    # Random start index (1-based) to avoid thundering herd on the first box.
    _SB_RND="$(od -An -N2 -tu2 /dev/urandom | tr -d ' \t\n')"
    _SB_START=$(( (_SB_RND % _SB_POOL_SIZE) + 1 ))

    _SB_TRIED=0
    _SB_IDX="$_SB_START"
    while [ "$_SB_TRIED" -lt "$_SB_POOL_SIZE" ]; do
        # POSIX sh positional-param indexed access via eval (no arrays).
        # shellcheck disable=SC2082
        eval "_SB_BOX=\"\${${_SB_IDX}}\""
        _SB_TRIED=$(( _SB_TRIED + 1 ))
        _SB_IDX=$(( (_SB_IDX % _SB_POOL_SIZE) + 1 ))

        if _sb_acquire "$_SB_BOX" "$_SB_SID"; then
            break 2
        fi
    done

    _SB_RETRY=$(( _SB_RETRY + 1 ))
    if [ "$_SB_RETRY" -le "$PFB_MAX_RETRIES" ]; then
        # Jittered backoff (1-3s, /dev/urandom) before re-scanning the pool.
        # ponytail: jitter here paces retries, NOT a concurrency primitive —
        # the mkdir atomicity is the sync; the sleep just reduces contention.
        _sb_jitter_sleep
    fi

done

if [ -z "$_SB_LEASED_BOX" ]; then
    printf 'select-box: pool exhausted — no free box after %d scan(s)\n' \
        "$(( PFB_MAX_RETRIES + 1 ))" >&2
    printf 'select-box: current holders:\n' >&2
    _sb_print_holders
    exit 1
fi

# Create the per-run directory tree on the leased box.
_SB_RUN_DIR="${PFB_RUN_ROOT}/${RUN_ID}"
if ! _sb_ssh "$_SB_LEASED_BOX" \
    "mkdir -p '${_SB_RUN_DIR}/out' '${_SB_RUN_DIR}/smoke-diag'" 2>/dev/null; then
    printf 'select-box: failed to create run directories on %s: %s\n' \
        "$_SB_LEASED_BOX" "$_SB_RUN_DIR" >&2
    exit 1
fi

# Emit eval-able KEY=value to stdout.
printf 'RUN_ID=%s\n'       "$RUN_ID"
printf 'PFB_BOX=%s\n'      "$_SB_LEASED_BOX"
printf 'PFB_RUN_DIR=%s\n'  "$_SB_RUN_DIR"
printf 'PFB_OUT_DIR=%s\n'  "${_SB_RUN_DIR}/out"
printf 'PFB_DIAG_DIR=%s\n' "${_SB_RUN_DIR}/smoke-diag"
printf 'SMOKE_LANE=0\n'

printf 'select-box: leased %s (RUN_ID=%s)\n' "$_SB_LEASED_BOX" "$RUN_ID" >&2

# If a command was given (after --), run it on the leased box over ssh.
# The EXIT trap releases the lease when this script exits (normally or on signal).
if [ -n "$_SB_CMD" ]; then
    _sb_ssh "$_SB_LEASED_BOX" "$_SB_CMD"
fi

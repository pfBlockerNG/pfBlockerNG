#shellcheck shell=sh
# select-box.sh + run-id.sh — shellspec pinning the lease contract (ADR-47 P2).
#
# TOPOLOGY UNDER TEST:
#   A fake `ssh` binary on PATH runs the remote command LOCALLY against a temp dir
#   that stands in for the shared bind-mount (PFB_LEASE_DIR). This preserves the
#   real atomicity of mkdir/rename on the local filesystem, so the concurrency
#   contracts — "exactly one mkdir winner", "exactly one rename winner" — are real,
#   not mocked. Two fake "boxes" (root@10.0.0.23 and root@10.0.0.24) share one
#   lease dir, as on the real bind-mount.
#
# TOKEN NOTE: box_tok("root@10.0.0.23") removes user@ then non-alnum chars:
#   10.0.0.23 → tr -cd '[:alnum:]' → 100023 (six digits, dots removed)
#   10.0.0.24 → 100024
#   ALL filesystem setup MUST use these correct tokens, not 10023/10024.
#
# Contracts pinned here:
#   acquire           — one select-box.sh call leases a box; emits RUN_ID + PFB_BOX;
#                       PFB_RUN_DIR is created on the box (not cleaned up by trap).
#   two-contenders    — two concurrent acquires on a two-box pool both exit 0
#                       (pool serves two requesters without error).
#   pool-exhausted    — all boxes pre-locked with live owners → exit non-zero +
#                       holder info printed; never hangs.
#   TTL-stale reclaim — a lock whose owner epoch exceeds PFB_LEASE_TTL is reclaimed;
#                       the new owner runs.
#   missing-owner grace — a lockdir with no owner file, older than PFB_OWNER_GRACE,
#                         is reclaimed.
#   two-concurrent-reclaimers (§7 double-grant gap):
#     GOOD: rename-capture → exactly one wins (winners=1).
#     BAD:  rmdir+mkdir     → both win (winners=2); the red-before evidence that
#                             proves rename-capture is NECESSARY.
#   release           — --release frees only the matching-owner lock; a mismatched
#                       RUN_ID does NOT free the lock.
#   command signals   — INT/TERM/HUP stop the selector before its command completes,
#                       return 128 + signo, and release exactly once.
#   no-alias          — local-<...> and ci-<...> run-ids never collide.

Describe 'select-box.sh'
  SCRIPT="${PFB_ROOT}/scripts/select-box.sh"

  setup() {
    # ── GIT_* scrub ──────────────────────────────────────────────────────────
    # The pre-commit hook exports GIT_DIR / GIT_INDEX_FILE / GIT_WORK_TREE /
    # GIT_PREFIX / GIT_OBJECT_DIRECTORY / GIT_COMMON_DIR pointing at the REAL
    # repo. Without this scrub, any git op inside setup() or the script under
    # test would operate on the real shared checkout. Mandatory in every spec.
    scrub_git_env

    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/selectbox.XXXXXX")"

    # Shared lease dir (stand-in for the bind-mount visible from every box).
    LEASE_DIR="${WORK}/lease"
    mkdir -p "$LEASE_DIR"

    # Fake ssh bin: strip options, skip target, run remote cmd LOCALLY.
    # The lease dir is already a local path (PFB_LEASE_DIR=LEASE_DIR), so
    # commands referencing $PFB_LEASE_DIR/... work directly against LEASE_DIR.
    BIN="${WORK}/bin"
    mkdir -p "$BIN"
    cat > "${BIN}/ssh" <<'SSHEOF'
#!/bin/sh
# Fake ssh for select_box_spec.sh: run the remote command locally.
# Accepts: ssh [-o val]... [-i key] [-p port] ... TARGET CMD
# All options with a value argument are consumed in pairs; bare flags are
# consumed alone. When we hit the first non-option arg (TARGET), skip it
# and exec the remaining CMD string as a local sh -c.
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o|-i|-p|-l|-e|-b|-c|-D|-E|-F|-I|-J|-L|-Q|-R|-S|-w|-W|-m|-B) shift 2 ;;
        -*) shift ;;
        *) break ;;
    esac
done
# $1 is the target (skip); $2 is the remote command string.
shift
if [ -n "${PFB_TEST_RELEASE_GATE:-}" ]; then
    case "$1" in
        *"rm -rf"*)
            true > "$PFB_TEST_RELEASE_STARTED"
            read _release_gate < "$PFB_TEST_RELEASE_GATE"
            sh -c "$1"
            _release_status=$?
            true > "$PFB_TEST_RELEASE_FINISHED"
            exit "$_release_status"
            ;;
    esac
fi
exec sh -c "$1"
SSHEOF
    chmod +x "${BIN}/ssh"

    PATH="${BIN}:${PATH}"
    export PATH

    # Pool: two fake boxes. Both map into the same LEASE_DIR (one bind-mount).
    PFB_BOXES="root@10.0.0.23 root@10.0.0.24"
    PFB_LEASE_DIR="$LEASE_DIR"
    PFB_LEASE_TTL=7200
    PFB_OWNER_GRACE=30
    PFB_MAX_RETRIES=0     # try each box once; keep tests fast
    PFB_SSH="ssh"         # just the bare command; fake bin strips options
    PFB_RUN_ROOT="${WORK}/runs"

    export PFB_BOXES PFB_LEASE_DIR PFB_LEASE_TTL PFB_OWNER_GRACE \
           PFB_MAX_RETRIES PFB_SSH PFB_RUN_ROOT
  }

  cleanup() { rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach  'cleanup'

  # ── Helper: compute the filesystem token select-box.sh uses for a box ───────
  # Mirrors _sb_box_tok in select-box.sh exactly.
  # root@10.0.0.23 → strip user@ → 10.0.0.23 → remove non-alnum → 100023
  box_tok() {
    printf '%s' "${1##*@}" | tr -cd '[:alnum:]' | tr '[:upper:]' '[:lower:]'
  }

  # ── acquire ────────────────────────────────────────────────────────────────
  # GIVEN no locks held
  # WHEN select-box.sh is called
  # THEN it exits 0, emits RUN_ID + PFB_BOX + PFB_RUN_DIR, and the per-run
  #      dir is created on the box.  The EXIT trap releases the lease, so we
  #      check PFB_RUN_DIR (not cleaned by trap) rather than the owner file.
  acquire_result() {
    _out="$(sh "$SCRIPT" 2>/dev/null)" || { printf 'exit=%d\n' "$?"; return; }
    _rid="$(printf '%s' "$_out" | grep '^RUN_ID='      | cut -d= -f2)"
    _box="$(printf '%s' "$_out" | grep '^PFB_BOX='     | cut -d= -f2)"
    _dir="$(printf '%s' "$_out" | grep '^PFB_RUN_DIR=' | cut -d= -f2)"
    # PFB_RUN_DIR is created by the script and NOT removed by the EXIT trap.
    printf 'rid-prefix=%s\n' "$(printf '%s' "$_rid" | cut -c1-6)"
    printf 'box-set=%s\n'    "$([ -n "$_box" ] && echo yes || echo no)"
    printf 'run-dir=%s\n'    "$([ -d "$_dir" ] && echo yes || echo no)"
  }

  It 'acquire: leases a box, emits RUN_ID + PFB_BOX, creates PFB_RUN_DIR'
    When call acquire_result
    The status should be success
    # expected: rid-prefix=local-, box-set=yes, run-dir=yes
    # actual values printed above; a mismatch shows the discrepancy
    The line 1 of output should equal 'rid-prefix=local-'
    The line 2 of output should equal 'box-set=yes'
    The line 3 of output should equal 'run-dir=yes'
  End

  command_signal_result() {
    _signal="$1"
    _expected_status="$2"
    _transport_mode="${3:-normal}"
    _ready="${WORK}/${_signal}.ready"
    _remote_pid_file="${WORK}/${_signal}.pid"
    _command_gate="${WORK}/${_signal}.gate"
    _command_completed="${WORK}/${_signal}.completed"
    _selector_err="${WORK}/${_signal}.err"
    mkfifo "$_command_gate"
    _remote_trap="trap 'exit 0' INT TERM HUP"
    [ "$_transport_mode" = "ignore-term" ] && _remote_trap="trap '' TERM; trap 'exit 0' INT HUP"
    _command="printf '%s\\n' \"\$\$\" > '${_remote_pid_file}'; true > '${_ready}'; ${_remote_trap}; read _signal_gate < '${_command_gate}'; true > '${_command_completed}'"

    python3 -c 'import os, signal, sys; [signal.signal(sig, signal.SIG_DFL) for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)]; os.execvp("sh", ["sh", *sys.argv[1:]])' \
      "$SCRIPT" -- "$_command" > "${WORK}/${_signal}.out" 2> "$_selector_err" &
    _selector_pid=$!

    _ready_checks=0
    while [ ! -f "$_ready" ] && [ "$_ready_checks" -lt 100 ]; do
      sleep 0.05
      _ready_checks=$(( _ready_checks + 1 ))
    done
    if [ ! -f "$_ready" ]; then
      kill -TERM "$_selector_pid" 2>/dev/null || true
      wait "$_selector_pid" 2>/dev/null || true
      printf 'ready=no (stuck/environment)\n'
      return
    fi

    _remote_pid="$(cat "$_remote_pid_file")"
    kill "-${_signal}" "$_selector_pid"

    _exit_checks=0
    while kill -0 "$_selector_pid" 2>/dev/null && [ "$_exit_checks" -lt 100 ]; do
      sleep 0.05
      _exit_checks=$(( _exit_checks + 1 ))
    done
    _exited_before_release=yes
    if kill -0 "$_selector_pid" 2>/dev/null; then
      _exited_before_release='no (stuck/environment)'
      printf '\n' > "$_command_gate"
    fi

    wait "$_selector_pid"
    _selector_status=$?

    _transport_alive=no
    kill -0 "$_remote_pid" 2>/dev/null && _transport_alive=yes
    kill -KILL "$_remote_pid" 2>/dev/null || true

    _release_count="$(grep -c '^select-box: released ' "$_selector_err" || true)"
    _already_released_count="$(grep -c 'not found (already released)' "$_selector_err" || true)"
    printf 'ready=yes\n'
    printf 'selector-exited-before-command-release=%s\n' "$_exited_before_release"
    printf 'status=%s expected=%s\n' "$_selector_status" "$_expected_status"
    printf 'command-completed=%s\n' "$([ -f "$_command_completed" ] && echo yes || echo no)"
    printf 'transport-alive-after-selector=%s\n' "$_transport_alive"
    printf 'release-count=%s\n' "$_release_count"
    printf 'already-released-count=%s\n' "$_already_released_count"
  }

  It 'INT stops a running command and releases its lease exactly once'
    When call command_signal_result INT 130
    The status should be success
    The line 1 of output should equal 'ready=yes'
    The line 2 of output should equal 'selector-exited-before-command-release=yes'
    The line 3 of output should equal 'status=130 expected=130'
    The line 4 of output should equal 'command-completed=no'
    The line 5 of output should equal 'transport-alive-after-selector=no'
    The line 6 of output should equal 'release-count=1'
    The line 7 of output should equal 'already-released-count=0'
  End

  It 'TERM stops a running command and releases its lease exactly once'
    When call command_signal_result TERM 143
    The status should be success
    The line 1 of output should equal 'ready=yes'
    The line 2 of output should equal 'selector-exited-before-command-release=yes'
    The line 3 of output should equal 'status=143 expected=143'
    The line 4 of output should equal 'command-completed=no'
    The line 5 of output should equal 'transport-alive-after-selector=no'
    The line 6 of output should equal 'release-count=1'
    The line 7 of output should equal 'already-released-count=0'
  End

  It 'HUP stops a running command and releases its lease exactly once'
    When call command_signal_result HUP 129
    The status should be success
    The line 1 of output should equal 'ready=yes'
    The line 2 of output should equal 'selector-exited-before-command-release=yes'
    The line 3 of output should equal 'status=129 expected=129'
    The line 4 of output should equal 'command-completed=no'
    The line 5 of output should equal 'transport-alive-after-selector=no'
    The line 6 of output should equal 'release-count=1'
    The line 7 of output should equal 'already-released-count=0'
  End

  It 'TERM escalates and reaps a transport that ignores TERM before releasing'
    When call command_signal_result TERM 143 ignore-term
    The status should be success
    The line 1 of output should equal 'ready=yes'
    The line 2 of output should equal 'selector-exited-before-command-release=yes'
    The line 3 of output should equal 'status=143 expected=143'
    The line 4 of output should equal 'command-completed=no'
    The line 5 of output should equal 'transport-alive-after-selector=no'
    The line 6 of output should equal 'release-count=1'
    The line 7 of output should equal 'already-released-count=0'
  End

  repeated_signal_result() {
    _ready="${WORK}/repeated.ready"
    _remote_pid_file="${WORK}/repeated.pid"
    _command_gate="${WORK}/repeated-command.gate"
    _release_gate="${WORK}/repeated-release.gate"
    _release_started="${WORK}/repeated-release.started"
    _release_finished="${WORK}/repeated-release.finished"
    _selector_err="${WORK}/repeated.err"
    mkfifo "$_command_gate" "$_release_gate"
    PFB_TEST_RELEASE_GATE="$_release_gate"
    PFB_TEST_RELEASE_STARTED="$_release_started"
    PFB_TEST_RELEASE_FINISHED="$_release_finished"
    PFB_BOXES="root@10.0.0.23"
    export PFB_TEST_RELEASE_GATE PFB_TEST_RELEASE_STARTED PFB_TEST_RELEASE_FINISHED
    export PFB_BOXES
    _command="printf '%s\\n' \"\$\$\" > '${_remote_pid_file}'; true > '${_ready}'; trap 'exit 0' TERM; read _signal_gate < '${_command_gate}'"

    python3 -c 'import os, signal, sys; [signal.signal(sig, signal.SIG_DFL) for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)]; os.execvp("sh", ["sh", *sys.argv[1:]])' \
      "$SCRIPT" -- "$_command" > "${WORK}/repeated.out" 2> "$_selector_err" &
    _selector_pid=$!

    _ready_checks=0
    while [ ! -f "$_ready" ] && [ "$_ready_checks" -lt 100 ]; do
      sleep 0.05
      _ready_checks=$(( _ready_checks + 1 ))
    done
    [ -f "$_ready" ] || { printf 'ready=no (stuck/environment)\n'; return; }

    kill -TERM "$_selector_pid"
    _release_checks=0
    while [ ! -f "$_release_started" ] && [ "$_release_checks" -lt 100 ]; do
      sleep 0.05
      _release_checks=$(( _release_checks + 1 ))
    done
    [ -f "$_release_started" ] || { printf 'release-started=no (stuck/environment)\n'; return; }

    kill -TERM "$_selector_pid"
    printf '\n' > "$_release_gate"
    wait "$_selector_pid"
    _selector_status=$?

    _finish_checks=0
    while [ ! -f "$_release_finished" ] && [ "$_finish_checks" -lt 100 ]; do
      sleep 0.05
      _finish_checks=$(( _finish_checks + 1 ))
    done
    _locks="$(find "$LEASE_DIR" -type d -name '*.lock' | wc -l | tr -d ' ')"
    _release_count="$(grep -c '^select-box: released ' "$_selector_err" || true)"
    _already_released_count="$(grep -c 'not found (already released)' "$_selector_err" || true)"
    printf 'ready=yes\n'
    printf 'release-started=yes\n'
    printf 'release-finished=%s\n' "$([ -f "$_release_finished" ] && echo yes || echo no)"
    printf 'status=%s expected=143\n' "$_selector_status"
    printf 'lock-count=%s\n' "$_locks"
    printf 'release-count=%s\n' "$_release_count"
    printf 'already-released-count=%s\n' "$_already_released_count"
  }

  It 'a repeated TERM cannot interrupt lease cleanup'
    When call repeated_signal_result
    The status should be success
    The line 1 of output should equal 'ready=yes'
    The line 2 of output should equal 'release-started=yes'
    The line 3 of output should equal 'release-finished=yes'
    The line 4 of output should equal 'status=143 expected=143'
    The line 5 of output should equal 'lock-count=0'
    The line 6 of output should equal 'release-count=1'
    The line 7 of output should equal 'already-released-count=0'
  End

  # ── two-contenders: both concurrent acquires succeed ───────────────────────
  # GIVEN two-box pool, both free
  # WHEN two select-box.sh processes run concurrently (or in quick succession)
  # THEN both exit 0 (pool serves two requesters without error)
  #
  # Note: On a fast local machine the processes may run sequentially (one
  # finishes, EXIT trap releases, second picks the same box). Distinct-box
  # assertion is NOT made here — the contract is only that both succeed.
  two_contenders_result() {
    _o1="${WORK}/c1.out"
    _o2="${WORK}/c2.out"
    sh "$SCRIPT" > "$_o1" 2>/dev/null &
    _p1=$!
    sh "$SCRIPT" > "$_o2" 2>/dev/null &
    _p2=$!
    wait "$_p1"; _r1=$?
    wait "$_p2"; _r2=$?
    _ok=$(( (_r1 == 0 ? 1 : 0) + (_r2 == 0 ? 1 : 0) ))
    # expected: both-succeeded=yes; actual: both-succeeded=no shows which rc failed
    printf 'both-succeeded=%s\n' "$([ "$_ok" -eq 2 ] && echo yes || echo no)"
    [ "$_ok" -lt 2 ] && printf 'actual-rcs=%d,%d\n' "$_r1" "$_r2" || true
  }

  It 'two-contenders: two-box pool serves two concurrent requesters without error'
    When call two_contenders_result
    The status should be success
    The line 1 of output should equal 'both-succeeded=yes'
  End

  # ── pool-exhausted: all boxes locked → non-zero + holder info ──────────────
  # GIVEN all boxes have live owners (epoch ≈ now, well within TTL)
  # WHEN select-box.sh is called
  # THEN it exits non-zero and prints holder info (never hangs)
  #
  # TOKEN: root@10.0.0.23 → box_tok → 100023 (six digits); must match the
  # lock path that select-box.sh constructs (not hardcoded 10023).
  exhausted_result() {
    _now="$(date +%s)"
    for _b in root@10.0.0.23 root@10.0.0.24; do
      _t="$(box_tok "$_b")"
      mkdir -p "${LEASE_DIR}/${_t}.lock"
      printf 'run-live-holder host1 %s\n' "$_now" \
        > "${LEASE_DIR}/${_t}.lock/owner"
    done
    _combined="$(sh "$SCRIPT" 2>&1)"; _rc=$?
    printf 'rc=%d\n' "$_rc"
    # expected: at least one "run-live-holder" line in the holder output;
    # actual count printed here; 0 means no holder info was emitted.
    printf '%s\n' "$_combined" | grep -c 'run-live-holder' || true
  }

  It 'pool-exhausted: exits non-zero + prints holder info when all boxes busy'
    When call exhausted_result
    The status should be success
    The line 1 of output should equal 'rc=1'
    # expected: at least one holder line printed (count > 0)
    The line 2 of output should not equal '0'
  End

  # ── TTL-stale reclaim ──────────────────────────────────────────────────────
  # GIVEN box 23 holds a lock whose owner epoch is > PFB_LEASE_TTL in the past
  # WHEN select-box.sh is called
  # THEN it reclaims that box and exits 0 with a valid local- RUN_ID
  ttl_stale_result() {
    _old=$(( $(date +%s) - 10000 ))   # 10 000 s ago; PFB_LEASE_TTL=7200 → stale
    _t23="$(box_tok 'root@10.0.0.23')"
    mkdir -p "${LEASE_DIR}/${_t23}.lock"
    printf 'run-stale-expired host1 %s\n' "$_old" \
      > "${LEASE_DIR}/${_t23}.lock/owner"
    # Narrow to single-box pool: forces select-box.sh to reclaim box 23 rather than
    # bypassing it by leasing the free box 24 from the 2-box BeforeEach pool.
    PFB_BOXES="root@10.0.0.23"
    export PFB_BOXES
    _out="$(sh "$SCRIPT" 2>/dev/null)"; _rc=$?
    _rid="$(printf '%s' "$_out" | grep '^RUN_ID=' | cut -d= -f2)"
    printf 'rc=%d\n' "$_rc"
    # expected: rid-prefix=local- (freshly minted); actual above
    printf 'rid-prefix=%s\n' "$(printf '%s' "$_rid" | cut -c1-6)"
    printf 'got-box=%s\n'    "$(printf '%s' "$_out" | grep -c '^PFB_BOX=')"
  }

  It 'TTL-stale reclaim: reclaims a lock whose owner epoch exceeds PFB_LEASE_TTL'
    When call ttl_stale_result
    The status should be success
    The line 1 of output should equal 'rc=0'
    # expected: rid-prefix=local- (a fresh local run-id); actual above
    The line 2 of output should equal 'rid-prefix=local-'
    The line 3 of output should equal 'got-box=1'
  End

  # ── missing-owner grace reclaim ────────────────────────────────────────────
  # GIVEN box 23 holds a lockdir with a .created timestamp > PFB_OWNER_GRACE
  #       in the past and NO owner file (crash between mkdir and publish)
  # WHEN select-box.sh is called with PFB_OWNER_GRACE=60
  # THEN it reclaims that box and exits 0
  missing_owner_result() {
    _old=$(( $(date +%s) - 300 ))   # 5 min ago; well past PFB_OWNER_GRACE=60
    _t23="$(box_tok 'root@10.0.0.23')"
    mkdir -p "${LEASE_DIR}/${_t23}.lock"
    printf '%s\n' "$_old" > "${LEASE_DIR}/${_t23}.lock/.created"
    # Deliberately no owner file (simulates crash between mkdir and publish).
    # Narrow to single-box pool: forces reclaim of box 23 rather than leasing box 24.
    PFB_BOXES="root@10.0.0.23"
    PFB_OWNER_GRACE=60
    export PFB_BOXES PFB_OWNER_GRACE
    _out="$(sh "$SCRIPT" 2>/dev/null)"; _rc=$?
    printf 'rc=%d\n' "$_rc"
    printf 'got-box=%s\n' "$(printf '%s' "$_out" | grep -c '^PFB_BOX=')"
  }

  It 'missing-owner grace: reclaims a no-owner lock older than PFB_OWNER_GRACE'
    When call missing_owner_result
    The status should be success
    The line 1 of output should equal 'rc=0'
    The line 2 of output should equal 'got-box=1'
  End

  # ── acquire-window race: an in-flight fresh lock must NOT be stolen ─────────
  #
  # SECOND double-grant gap (§7-class, ACQUIRE side). A lease is created in
  # stages; from another box's view there is a window where the lock dir exists
  # but its owner (and, in the torn case, its .created) is not yet published.
  # A concurrent reclaimer that lands in that window must NOT treat the lock as
  # reclaimable — doing so steals a freshly-acquired, still-in-flight lease, and
  # two runs end up on one box (acquire-side double grant).
  #
  # The load-bearing case is (b): a held lock with NO owner AND NO .created.
  #   - RED  (pre-fix): the reclaim rule said "no .created → immediate reclaim",
  #          so select-box.sh reclaims the in-flight lock and exits 0.
  #   - GREEN (post-fix): a no-.created lock is the vanishing torn-acquire window,
  #          NOT a normal fresh lock (acquire now writes the lock + .created +
  #          owner in ONE ssh call, so a normal lock is never observable without
  #          .created). It is therefore NOT immediately reclaimable → select-box.sh
  #          refuses (pool exhausted, non-zero exit), leaving the in-flight lease.
  #
  # Single-box pool with a pre-built empty (no-owner, no-.created) lock dir is the
  # deterministic stand-in for "a peer is mid-acquire on this box right now".
  acquire_window_no_created_result() {
    _t23="$(box_tok 'root@10.0.0.23')"
    mkdir -p "${LEASE_DIR}/${_t23}.lock"
    # No owner file, NO .created file — the torn-acquire / in-flight window.
    PFB_BOXES="root@10.0.0.23"
    export PFB_BOXES
    _out="$(sh "$SCRIPT" 2>/dev/null)"; _rc=$?
    # expected (post-fix): refused → rc!=0 AND lock still present (not stolen)
    printf 'refused=%s\n'    "$([ "$_rc" -ne 0 ] && echo yes || echo no)"
    printf 'lock-intact=%s\n' "$([ -d "${LEASE_DIR}/${_t23}.lock" ] && echo yes || echo no)"
  }

  It 'acquire-window (no .created): a held no-owner/no-.created lock is NOT reclaimed'
    When call acquire_window_no_created_result
    The status should be success
    # RED before the fix: refused=no (it stole the in-flight lock and exited 0).
    # GREEN after: refused=yes, and the in-flight lock is left intact.
    The line 1 of output should equal 'refused=yes'
    The line 2 of output should equal 'lock-intact=yes'
  End

  # Companion (a): a no-owner lock whose .created is YOUNGER than grace is also
  # in-flight (owner publish still pending) and must NOT be reclaimed. This pins
  # the young-.created branch of the grace rule (already correct pre-fix; kept as
  # a guard so a future change to the rule can't regress it silently).
  acquire_window_young_created_result() {
    _t23="$(box_tok 'root@10.0.0.23')"
    mkdir -p "${LEASE_DIR}/${_t23}.lock"
    # .created = now (younger than grace) but owner not yet written.
    printf '%s\n' "$(date +%s)" > "${LEASE_DIR}/${_t23}.lock/.created"
    PFB_BOXES="root@10.0.0.23"
    PFB_OWNER_GRACE=30
    export PFB_BOXES PFB_OWNER_GRACE
    _out="$(sh "$SCRIPT" 2>/dev/null)"; _rc=$?
    printf 'refused=%s\n'    "$([ "$_rc" -ne 0 ] && echo yes || echo no)"
    printf 'lock-intact=%s\n' "$([ -d "${LEASE_DIR}/${_t23}.lock" ] && echo yes || echo no)"
  }

  It 'acquire-window (young .created): a no-owner lock within grace is NOT reclaimed'
    When call acquire_window_young_created_result
    The status should be success
    The line 1 of output should equal 'refused=yes'
    The line 2 of output should equal 'lock-intact=yes'
  End

  # ── two-concurrent-reclaimers (§7 double-grant gap) ───────────────────────
  #
  # The critical safety property: when two reclaimers race on ONE stale lock,
  # exactly one must win. This requires the reclaim to be an ATOMIC CAPTURE
  # (rename), NOT rmdir+mkdir.
  #
  # Why rmdir+mkdir breaks:
  #   - `rm -rf` returns 0 even if the path is already gone (idempotent).
  #   - Both reclaimers succeed at rm-rf regardless of ordering.
  #   - mkdir is the only exclusive op, but the bad code ignores its exit code.
  #   - Result: both publish their owner and return 0 → two winners (double grant).
  #
  # Why rename-capture works:
  #   - rename(2) on the SAME source is atomic: exactly one caller gets 0,
  #     the other gets ENOENT. No room for two winners.
  #
  # Test strategy:
  #   GOOD (rename-capture, default): two concurrent select-box.sh invocations on
  #     a single-box pool with one stale lock → winners=1.
  #   BAD  (_PFB_TEST_RECLAIM=badrmdir):  same setup → winners=2 (red-before).

  # Shared stale-lock setup: box 23 only (single-box pool forces both to compete).
  # Uses correct token (100023) so select-box.sh finds the pre-built lock dir.
  _setup_single_stale_lock() {
    _old=$(( $(date +%s) - 10000 ))
    _t23="$(box_tok 'root@10.0.0.23')"
    mkdir -p "${LEASE_DIR}/${_t23}.lock"
    printf 'run-stale-victim host1 %s\n' "$_old" \
      > "${LEASE_DIR}/${_t23}.lock/owner"
    PFB_BOXES="root@10.0.0.23"
    export PFB_BOXES
  }

  two_reclaimers_good_result() {
    _setup_single_stale_lock
    _o1="${WORK}/rg1.out"
    _o2="${WORK}/rg2.out"
    sh "$SCRIPT" > "$_o1" 2>/dev/null &
    _pg1=$!
    sh "$SCRIPT" > "$_o2" 2>/dev/null &
    _pg2=$!
    wait "$_pg1"; _rg1=$?
    wait "$_pg2"; _rg2=$?
    _wins=$(( (_rg1 == 0 ? 1 : 0) + (_rg2 == 0 ? 1 : 0) ))
    printf 'winners=%d\n' "$_wins"
  }

  # RED-BEFORE: the bad rmdir+mkdir variant.  Both concurrent invocations return 0
  # (double grant) because rm-rf is idempotent and the bad code ignores mkdir EEXIST.
  # This spec MUST produce winners=2 — proving that the rename-capture fix is
  # necessary, not just incidental.
  two_reclaimers_bad_result() {
    _setup_single_stale_lock
    _o1="${WORK}/rb1.out"
    _o2="${WORK}/rb2.out"
    _PFB_TEST_RECLAIM=badrmdir sh "$SCRIPT" > "$_o1" 2>/dev/null &
    _pb1=$!
    _PFB_TEST_RECLAIM=badrmdir sh "$SCRIPT" > "$_o2" 2>/dev/null &
    _pb2=$!
    wait "$_pb1"; _rb1=$?
    wait "$_pb2"; _rb2=$?
    _wins=$(( (_rb1 == 0 ? 1 : 0) + (_rb2 == 0 ? 1 : 0) ))
    printf 'winners=%d\n' "$_wins"
  }

  It 'two-concurrent-reclaimers (rename-capture): exactly one wins (winners=1)'
    When call two_reclaimers_good_result
    The status should be success
    # expected: winners=1; if winners=2 the rename-capture logic is broken
    The output should equal 'winners=1'
  End

  It 'two-concurrent-reclaimers (bad rmdir+mkdir): double-grant allowed (red-before evidence, winners=2)'
    When call two_reclaimers_bad_result
    The status should be success
    # expected: winners=2 — BOTH invocations succeed with the bad code,
    # proving rmdir+mkdir cannot serialize concurrent reclaimers.
    The output should equal 'winners=2'
  End

  # ── release ────────────────────────────────────────────────────────────────
  # GIVEN box 23 has a lock with a known RUN_ID
  # WHEN --release is called with the WRONG RID → lock must remain
  # WHEN --release is called with the RIGHT RID → lock must be removed
  release_result() {
    _now="$(date +%s)"
    _rid_right="test-rid-right-abc123"
    _rid_wrong="test-rid-wrong-xxxxxx"
    _t23="$(box_tok 'root@10.0.0.23')"
    mkdir -p "${LEASE_DIR}/${_t23}.lock"
    printf '%s host1 %s\n' "$_rid_right" "$_now" \
      > "${LEASE_DIR}/${_t23}.lock/owner"

    # Wrong RID — should NOT free the lock.
    sh "$SCRIPT" --release "$_rid_wrong" 2>/dev/null
    _still="$([ -d "${LEASE_DIR}/${_t23}.lock" ] && echo yes || echo no)"

    # Correct RID — must free the lock.
    sh "$SCRIPT" --release "$_rid_right" 2>/dev/null
    _freed="$([ -d "${LEASE_DIR}/${_t23}.lock" ] && echo no || echo yes)"

    # expected: wrong-rid-kept-lock=yes, correct-rid-freed=yes
    printf 'wrong-rid-kept-lock=%s\n' "$_still"
    printf 'correct-rid-freed=%s\n'   "$_freed"
  }

  It 'release: wrong RID keeps lock; correct RID frees it'
    When call release_result
    The status should be success
    The line 1 of output should equal 'wrong-rid-kept-lock=yes'
    The line 2 of output should equal 'correct-rid-freed=yes'
  End

  # ── no-alias ───────────────────────────────────────────────────────────────
  # The literal "local-" and "ci-" prefixes are a structural split: no valid
  # GITHUB_RUN_ID equals the string "local", so the two id spaces never collide.
  no_alias_result() {
    # Acquire a local run-id (EXIT trap auto-releases the lease).
    _lid="$(sh "$SCRIPT" 2>/dev/null | grep '^RUN_ID=' | cut -d= -f2)"
    # Mint a CI run-id (--print-id: no lease, no ssh).
    _cid="$(GITHUB_RUN_ID=99999 GITHUB_RUN_ATTEMPT=2 LEG=ce-2.8-amd64 \
            sh "$SCRIPT" --print-id 2>/dev/null)"
    printf 'local-prefix=%s\n' "$(printf '%s' "$_lid" | cut -c1-6)"
    printf 'ci-prefix=%s\n'    "$(printf '%s' "$_cid" | cut -c1-3)"
    printf 'no-collision=%s\n' "$([ "$_lid" != "$_cid" ] && echo yes || echo no)"
  }

  It 'no-alias: local- and ci- prefixes are structurally distinct'
    When call no_alias_result
    The status should be success
    The line 1 of output should equal 'local-prefix=local-'
    The line 2 of output should equal 'ci-prefix=ci-'
    The line 3 of output should equal 'no-collision=yes'
  End

End

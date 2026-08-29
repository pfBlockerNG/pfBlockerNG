#shellcheck shell=sh
# issue #2038: bootstrap may inherit a HEAD lock from an earlier box user. The
# verdict must come from the on-box descriptor view before the checkout mutates anything.
Describe 'local-smoke.sh git HEAD lock hygiene (issue #2038)'
  SCRIPT="${PFB_ROOT}/scripts/local-smoke.sh"

  setup() {
    scrub_git_env
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/localsmokelock.XXXXXX")"
    BOX_REPO="${WORK}/box repo"
    PROC_ROOT="${WORK}/proc"
    REMOTE_BIN="${WORK}/bin"
    REMOTE_EVENTS="${WORK}/events"
    mkdir -p "${BOX_REPO}/.git" "${BOX_REPO}/scripts" \
      "${PROC_ROOT}/1/fd" "$REMOTE_BIN" "$REMOTE_EVENTS"

    cat > "${BOX_REPO}/scripts/smoke-on-box.sh" <<'SMOKE'
#!/bin/sh
printf 'reached\n' > "$REMOTE_EVENTS/handoff"
SMOKE

    REAL_READLINK="$(command -v readlink)"
    REAL_RM="$(command -v rm)"
    REAL_MV="$(command -v mv)"
    export REAL_READLINK REAL_RM REAL_MV

    cat > "${REMOTE_BIN}/git" <<'GIT'
#!/bin/sh
printf '%s\n' "$*" >> "$REMOTE_EVENTS/git"
if [ -e "${BOX_REPO}/.git/HEAD.lock" ] || [ -L "${BOX_REPO}/.git/HEAD.lock" ]; then
  printf 'fatal: Unable to create %s: File exists.\n' "${BOX_REPO}/.git/HEAD.lock" >&2
  exit 128
fi
exit 0
GIT
    cat > "${REMOTE_BIN}/sysctl" <<'SYSCTL'
#!/bin/sh
exit 0
SYSCTL
    cat > "${REMOTE_BIN}/stat" <<'STAT'
#!/bin/sh
printf 'stat\n' >> "$REMOTE_EVENTS/stat"
if [ -f "$REMOTE_EVENTS/raced" ]; then
  printf 'changed\n'
else
  printf 'original\n'
fi
STAT
    cat > "${REMOTE_BIN}/readlink" <<'READLINK'
#!/bin/sh
if [ "${RACE_LOCK:-0}" = 1 ] && [ ! -f "$REMOTE_EVENTS/raced" ]; then
  "$REAL_MV" "${BOX_REPO}/.git/HEAD.lock" "${BOX_REPO}/.git/HEAD.lock.old"
  printf 'replacement\n' > "${BOX_REPO}/.git/HEAD.lock"
  "$REAL_RM" "${BOX_REPO}/.git/HEAD.lock.old"
  printf 'raced\n' > "$REMOTE_EVENTS/raced"
fi
exec "$REAL_READLINK" "$@"
READLINK
    cat > "${REMOTE_BIN}/rm" <<'RM'
#!/bin/sh
printf 'rm\n' >> "$REMOTE_EVENTS/mutations"
exec "$REAL_RM" "$@"
RM
    chmod +x "${REMOTE_BIN}/git" "${REMOTE_BIN}/sysctl" \
      "${REMOTE_BIN}/stat" "${REMOTE_BIN}/readlink" "${REMOTE_BIN}/rm"

    FAKE_SELECT_BOX="${WORK}/fake-select-box.sh"
    cat > "$FAKE_SELECT_BOX" <<'SELECT'
#!/bin/sh
[ "${1:-}" = -- ] && shift
cmd="$*"
# Let untouched local-smoke.sh reach the fixture so RED is about HEAD.lock,
# not its production-only /root path. The implemented test seam needs no rewrite.
cmd="$(printf '%s\n' "$cmd" | sed 's|cd /root/pfBlockerNG|cd "$BOX_REPO"|')"
PATH="${REMOTE_BIN}:$PATH" sh -c "$cmd"
SELECT
    chmod +x "$FAKE_SELECT_BOX"

    PFB_SELECT_BOX="$FAKE_SELECT_BOX"
    PFB_BOXES="dummy@dummy"
    PFB_REF_PREFLIGHT=0
    PFB_ONBOX_REPO_ROOT="$BOX_REPO"
    PFB_ONBOX_PROC_ROOT="$PROC_ROOT"
    export BOX_REPO PROC_ROOT REMOTE_BIN REMOTE_EVENTS
    export PFB_SELECT_BOX PFB_BOXES PFB_REF_PREFLIGHT
    export PFB_ONBOX_REPO_ROOT PFB_ONBOX_PROC_ROOT
    unset RACE_LOCK
  }

  teardown() {
    rm -rf "$WORK"
  }

  BeforeEach 'setup'
  AfterEach 'teardown'

  make_lock() {
    printf 'leftover\n' > "${BOX_REPO}/.git/HEAD.lock"
  }

  run_and_diag() {
    _out="$(sh "$SCRIPT" --ref dummy 2>&1)"
    _rc=$?
    _git_calls=0
    _mutations=0
    _stat_calls=0
    [ ! -f "$REMOTE_EVENTS/git" ] || _git_calls="$(wc -l < "$REMOTE_EVENTS/git" | tr -d ' ')"
    [ ! -f "$REMOTE_EVENTS/mutations" ] || _mutations="$(wc -l < "$REMOTE_EVENTS/mutations" | tr -d ' ')"
    [ ! -f "$REMOTE_EVENTS/stat" ] || _stat_calls="$(wc -l < "$REMOTE_EVENTS/stat" | tr -d ' ')"
    printf 'status=%s\n' "$_rc"
    if [ -e "${BOX_REPO}/.git/HEAD.lock" ] || [ -L "${BOX_REPO}/.git/HEAD.lock" ]; then
      printf 'lock=present\n'
    else
      printf 'lock=absent\n'
    fi
    printf 'git_calls=%s\n' "$_git_calls"
    printf 'mutations=%s\n' "$_mutations"
    printf 'stat_calls=%s\n' "$_stat_calls"
    if [ -f "$REMOTE_EVENTS/handoff" ]; then
      printf 'handoff=reached\n'
    else
      printf 'handoff=blocked\n'
    fi
    printf '%s\n' "$_out"
    return 0
  }

  stale_lock() {
    make_lock
    run_and_diag
  }

  It 'removes a proven-stale unchanged lock'
    When call stale_lock
    The line 1 of output should equal 'status=0'
    The line 2 of output should equal 'lock=absent'
    The line 4 of output should equal 'mutations=1'
    The output should include 'box hygiene: recovered proven-stale .git/HEAD.lock'
  End

  It 'continues through checkout and the smoke handoff after stale recovery'
    When call stale_lock
    The line 1 of output should equal 'status=0'
    The line 3 of output should not equal 'git_calls=0'
    The line 6 of output should equal 'handoff=reached'
  End

  live_lock() {
    make_lock
    mkdir -p "${PROC_ROOT}/4242/fd"
    ln -s "${BOX_REPO}/.git/HEAD.lock" "${PROC_ROOT}/4242/fd/9"
    run_and_diag
  }

  It 'leaves a lock with a live descriptor owner untouched'
    When call live_lock
    The line 1 of output should equal 'status=75'
    The line 2 of output should equal 'lock=present'
    The line 3 of output should equal 'git_calls=0'
    The line 4 of output should equal 'mutations=0'
    The output should include 'live owner pid=4242'
    The output should include 'box unhealthy'
  End

  ambiguous_lock() {
    make_lock
    rm -rf "${PROC_ROOT}/1/fd"
    run_and_diag
  }

  It 'leaves the lock untouched when process ownership is ambiguous'
    When call ambiguous_lock
    The line 1 of output should equal 'status=75'
    The line 2 of output should equal 'lock=present'
    The line 3 of output should equal 'git_calls=0'
    The line 4 of output should equal 'mutations=0'
    The output should include 'ownership ambiguous'
    The output should include 'process view unavailable'
    The output should include 'box unhealthy'
  End

  raced_lock() {
    make_lock
    mkdir -p "${PROC_ROOT}/99/fd"
    ln -s /dev/null "${PROC_ROOT}/99/fd/3"
    RACE_LOCK=1
    export RACE_LOCK
    run_and_diag
  }

  It 'does not mutate a lock that changes before the stale verdict'
    When call raced_lock
    The line 1 of output should equal 'status=75'
    The line 2 of output should equal 'lock=present'
    The line 3 of output should equal 'git_calls=0'
    The line 4 of output should equal 'mutations=0'
    The line 5 of output should equal 'stat_calls=2'
    The line 6 of output should equal 'handoff=blocked'
    The output should include 'changed during inspection'
    The output should include 'box unhealthy'
  End
End

#shellcheck shell=sh
# Environment-selected EPERM coverage for mcp-token-savior.sh lock handling.
# tag: env:eperm

Describe 'mcp-token-savior.sh EPERM lock holder'
  SCRIPT="${PFB_ROOT}/scripts/mcp-token-savior.sh"

  setup() {
    # PID 1 is alive but outside this non-root process's signal permissions. This
    # file is selected only by the host-PID, non-root CI job; fail loudly elsewhere.
    [ -d /proc/1 ] || {
      echo 'EPERM fixture requires /proc/1 in the host PID namespace' >&2
      return 1
    }
    if kill -0 1 2>/dev/null; then
      echo 'EPERM fixture requires a non-root host-PID namespace' >&2
      return 1
    fi
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/mcptseperm.XXXXXX")"
    mkdir -p "${WORK}/shim"
    cat > "${WORK}/shim/python3" <<'EOF'
#!/bin/sh
venv="$3"
mkdir -p "${venv}/bin"
cat > "${venv}/bin/pip" <<'PIPE'
#!/bin/sh
exit 1
PIPE
chmod +x "${venv}/bin/pip"
EOF
    chmod +x "${WORK}/shim/python3"
    cat > "${WORK}/shim/ps" <<'EOF'
#!/bin/sh
exit 0
EOF
    chmod +x "${WORK}/shim/ps"
  }

  cleanup() { [ -n "${WORK:-}" ] && rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'keeps a lock whose holder PID is alive but unsignalable (EPERM)' env:eperm
    mkdir -p "${WORK}/venv.rebuild.lock"
    printf '1\n' > "${WORK}/venv.rebuild.lock/pid"
    When run env PATH="${WORK}/shim:${PATH}" PS_EXIT=0 TS_VENV="${WORK}/venv" TS_LOCK_WAIT=2 sh "${SCRIPT}"
    The status should be failure
    The stderr should include 'concurrent rebuild'
    The directory "${WORK}/venv.rebuild.lock" should be exist
    The file "${WORK}/venv/pip-args.log" should not be exist
  End
End

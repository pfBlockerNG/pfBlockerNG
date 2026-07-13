#shellcheck shell=sh
# mcp-token-savior.sh — INCLUDE_PATTERNS wiring: the server's built-in index globs
# lack .php/.inc/.sh (this repo's main languages), so the launcher must export a
# repo-appropriate default while a caller-set INCLUDE_PATTERNS still wins.

Describe 'mcp-token-savior.sh INCLUDE_PATTERNS export'
  SCRIPT="${PFB_ROOT}/scripts/mcp-token-savior.sh"

  setup() {
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/mcpts.XXXXXX")"
    # Executable venv bin short-circuits the launcher's install path and echoes
    # the one env var under test as seen by the exec'd server process.
    mkdir -p "${WORK}/venv/bin"
    cat > "${WORK}/venv/bin/token-savior" << 'EOF'
#!/bin/sh
printf '%s\n' "${INCLUDE_PATTERNS:-UNSET}"
EOF
    chmod +x "${WORK}/venv/bin/token-savior"
  }

  cleanup() { rm -rf "${WORK}"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'exports an index-glob default covering the languages the server misses'
    When run env -u INCLUDE_PATTERNS TS_VENV="${WORK}/venv" sh "${SCRIPT}"
    The status should be success
    The output should include '**/*.php'
    The output should include '**/*.inc'
    The output should include '**/*.sh'
    The output should include '**/*.py'
  End

  It 'lets a caller-set INCLUDE_PATTERNS win over the default'
    When run env INCLUDE_PATTERNS='**/*.only' TS_VENV="${WORK}/venv" sh "${SCRIPT}"
    The status should be success
    The output should equal '**/*.only'
  End
End

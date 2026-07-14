#shellcheck shell=sh
# mcp-token-savior.sh — env wiring + fork-pin install policy: the server's
# built-in index globs lack .php/.inc/.sh and its 500 KB size cap skips
# pfblockerng.inc (~844 KB), so the launcher must export repo-appropriate
# defaults (caller-set values win); the package installs from the pinned
# TS_SOURCE and a TS_SOURCE change must trigger a clean venv rebuild.

Describe 'mcp-token-savior.sh env exports'
  SCRIPT="${PFB_ROOT}/scripts/mcp-token-savior.sh"

  setup() {
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/mcpts.XXXXXX")"
    # Executable venv bin short-circuits the launcher's install path and echoes
    # the env vars under test as seen by the exec'd server process. The stamp
    # must match the launcher's default TS_SOURCE or it rebuilds the venv.
    mkdir -p "${WORK}/venv/bin"
    cat > "${WORK}/venv/bin/token-savior" << 'EOF'
#!/bin/sh
printf '%s\n' "${INCLUDE_PATTERNS:-UNSET}"
printf '%s\n' "${TOKEN_SAVIOR_MAX_FILE_SIZE:-UNSET}"
EOF
    chmod +x "${WORK}/venv/bin/token-savior"
    default_source="$(sed -n 's/^TS_SOURCE="\${TS_SOURCE:-\(.*\)}"$/\1/p' "${SCRIPT}")"
    printf '%s\n' "${default_source}" > "${WORK}/venv/.pfb-ts-source"
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
    The line 1 of output should equal '**/*.only'
  End

  It 'raises the index size cap so pfblockerng.inc (~844 KB) gets indexed'
    When run env -u TOKEN_SAVIOR_MAX_FILE_SIZE TS_VENV="${WORK}/venv" sh "${SCRIPT}"
    The status should be success
    The line 2 of output should equal '2000000'
  End

  It 'lets a caller-set TOKEN_SAVIOR_MAX_FILE_SIZE win over the default'
    When run env TOKEN_SAVIOR_MAX_FILE_SIZE=777 TS_VENV="${WORK}/venv" sh "${SCRIPT}"
    The status should be success
    The line 2 of output should equal '777'
  End
End

Describe 'mcp-token-savior.sh fork-pin install policy'
  SCRIPT="${PFB_ROOT}/scripts/mcp-token-savior.sh"

  setup() {
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/mcpts.XXXXXX")"
    # python3 shim: emulates `python3 -m venv <dir>` by planting a pip shim
    # that logs its final argument (the requirement string) and plants the
    # server bin — so the install path runs without touching the network.
    mkdir -p "${WORK}/shim"
    cat > "${WORK}/shim/python3" << EOF
#!/bin/sh
venv="\$3"
mkdir -p "\${venv}/bin"
cat > "\${venv}/bin/pip" << 'PIPEOF'
#!/bin/sh
for last; do :; done
printf '%s\n' "\${last}" >> "\$(dirname "\$0")/../pip-args.log"
bin_dir="\$(dirname "\$0")"
printf '#!/bin/sh\nprintf INSTALLED\n' > "\${bin_dir}/token-savior"
chmod +x "\${bin_dir}/token-savior"
PIPEOF
chmod +x "\${venv}/bin/pip"
EOF
    chmod +x "${WORK}/shim/python3"
  }

  cleanup() { rm -rf "${WORK}"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'installs the pinned andrebrait/token-savior integration source on first run'
    When run env PATH="${WORK}/shim:${PATH}" TS_VENV="${WORK}/venv" sh "${SCRIPT}"
    The status should be success
    The output should equal 'INSTALLED'
    The stderr should equal ''
    The contents of file "${WORK}/venv/pip-args.log" should include 'git+https://github.com/andrebrait/token-savior@'
  End

  It 'rebuilds the venv when the recorded TS_SOURCE stamp no longer matches'
    # Pre-seed a venv installed from an OLD source: bin exists, stale stamp.
    mkdir -p "${WORK}/venv/bin"
    printf '#!/bin/sh\nprintf STALE\n' > "${WORK}/venv/bin/token-savior"
    chmod +x "${WORK}/venv/bin/token-savior"
    printf '%s\n' 'token-savior-recall[mcp]' > "${WORK}/venv/.pfb-ts-source"
    When run env PATH="${WORK}/shim:${PATH}" TS_VENV="${WORK}/venv" sh "${SCRIPT}"
    The status should be success
    The output should equal 'INSTALLED'
    The stderr should equal ''
  End

  It 'skips reinstall when bin exists and the stamp matches TS_SOURCE'
    mkdir -p "${WORK}/venv/bin"
    printf '#!/bin/sh\nprintf KEPT\n' > "${WORK}/venv/bin/token-savior"
    chmod +x "${WORK}/venv/bin/token-savior"
    printf '%s\n' 'custom-source' > "${WORK}/venv/.pfb-ts-source"
    When run env PATH="${WORK}/shim:${PATH}" TS_VENV="${WORK}/venv" TS_SOURCE='custom-source' sh "${SCRIPT}"
    The status should be success
    The output should equal 'KEPT'
    The file "${WORK}/venv/pip-args.log" should not be exist
  End
End

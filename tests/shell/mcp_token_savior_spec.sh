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
    # Loud guard: an empty extraction (launcher assignment reformatted) would
    # silently send every example down the slow venv-rebuild path.
    [ -n "${default_source}" ] || { echo "TS_SOURCE extraction failed — launcher line reformatted?" >&2; return 1; }
    printf '%s\n' "${default_source}" > "${WORK}/venv/.pfb-ts-source"
  }

  cleanup() { [ -n "${WORK}" ] && rm -rf "${WORK}"; [ ! -d "${WORK}" ] || return 1; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'exports an index-glob default covering the languages the server misses'
    When run env INCLUDE_PATTERNS="" TS_VENV="${WORK}/venv" sh "${SCRIPT}"
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
    When run env TOKEN_SAVIOR_MAX_FILE_SIZE="" TS_VENV="${WORK}/venv" sh "${SCRIPT}"
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

  cleanup() { [ -n "${WORK}" ] && rm -rf "${WORK}"; [ ! -d "${WORK}" ] || return 1; }
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

  It 'waits on a concurrent rebuild lock and proceeds once the holder finishes'
    # Holder simulation: a background job plants the finished venv and releases
    # the lock; the launcher must wait instead of racing the rebuild.
    When run env PATH="${WORK}/shim:${PATH}" TS_VENV="${WORK}/venv" TS_SOURCE='custom-source' TS_LOCK_WAIT=10 sh -c '
      mkdir -p "${TS_VENV}.rebuild.lock"
      (
        sleep 1
        mkdir -p "${TS_VENV}/bin"
        printf "#!/bin/sh\nprintf WAITED\n" > "${TS_VENV}/bin/token-savior"
        chmod +x "${TS_VENV}/bin/token-savior"
        printf "%s\n" "custom-source" > "${TS_VENV}/.pfb-ts-source"
        rmdir "${TS_VENV}.rebuild.lock"
      ) &
      exec sh "$1"' _ "${SCRIPT}"
    The status should be success
    The output should equal 'WAITED'
  End

  It 'fails loudly when a concurrent rebuild lock never clears'
    mkdir -p "${WORK}/venv.rebuild.lock"
    When run env PATH="${WORK}/shim:${PATH}" TS_VENV="${WORK}/venv" TS_LOCK_WAIT=1 sh "${SCRIPT}"
    The status should be failure
    The stderr should include 'concurrent rebuild'
  End

  It 'refuses a non-absolute TS_VENV instead of rm -rf-ing a relative path'
    # Contained sandbox: an unguarded launcher would rm -rf . right here.
    mkdir -p "${WORK}/sandbox"
    printf 'keep\n' > "${WORK}/sandbox/marker"
    When run sh -c 'cd "$1" && PATH="$3" TS_VENV=. exec sh "$2"' _ "${WORK}/sandbox" "${SCRIPT}" "${WORK}/shim:${PATH}"
    The status should be failure
    The stderr should include 'refusing'
    The file "${WORK}/sandbox/marker" should be exist
  End

  It 'refuses a TS_VENV containing a .. traversal segment'
    # Contained: an unguarded launcher resolves the .. at rm -rf time and
    # deletes the sibling directory's contents.
    mkdir -p "${WORK}/keep/other"
    printf 'keep\n' > "${WORK}/keep/other/marker"
    When run env PATH="${WORK}/shim:${PATH}" TS_VENV="${WORK}/keep/subdir/../other" sh "${SCRIPT}"
    The status should be failure
    The stderr should include 'refusing'
    The file "${WORK}/keep/other/marker" should be exist
  End

  It 'refuses a TS_VENV containing a double slash'
    When run env PATH="${WORK}/shim:${PATH}" TS_VENV="${WORK}//venv2" sh "${SCRIPT}"
    The status should be failure
    The stderr should include 'refusing'
  End

  It 'accepts a trailing-slash TS_VENV and still installs fresh'
    # A trailing slash once nested the lock inside the not-yet-created venv,
    # sending an uncontended first install into the concurrent-wait failure.
    When run env PATH="${WORK}/shim:${PATH}" TS_VENV="${WORK}/venv/" sh "${SCRIPT}"
    The status should be success
    The output should equal 'INSTALLED'
    The stderr should equal ''
  End
End

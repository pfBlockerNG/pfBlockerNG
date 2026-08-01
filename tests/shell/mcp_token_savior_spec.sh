#shellcheck shell=sh
# mcp-token-savior.sh — env wiring + upstream-version install policy: the server's
# built-in index globs lack .php/.inc/.sh and its 500 KB size cap skips
# pfblockerng.inc (~844 KB), so the launcher must export repo-appropriate
# defaults (caller-set values win); the package installs from the exact upstream
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
printf '%s\n' "${TOKEN_SAVIOR_CLIENT:-UNSET}"
printf '%s\n' "${WORKSPACE_ROOTS:-UNSET}"
printf '%s\n' "${CLAUDE_PROJECT_ROOT:-UNSET}"
# Lines 6-7 use '-' (not ':-') to tell an exported-but-empty override apart
# from a variable the launcher never exported; the brackets keep an empty
# value observable, since a bare trailing blank line is not addressable.
printf '[%s]\n' "${WORKSPACE_ROOTS-UNSET}"
printf '[%s]\n' "${CLAUDE_PROJECT_ROOT-UNSET}"
EOF
    chmod +x "${WORK}/venv/bin/token-savior"
    default_source="$(sed -n 's/^TS_SOURCE="\${TS_SOURCE:-\(.*\)}"$/\1/p' "${SCRIPT}")"
    # Loud guard: an empty extraction (launcher assignment reformatted) would
    # silently send every example down the slow venv-rebuild path.
    [ -n "${default_source}" ] || { echo "TS_SOURCE extraction failed — launcher line reformatted?" >&2; return 1; }
    printf '%s\n' "${default_source}" > "${WORK}/venv/.pfb-ts-source"
    ln -s "$(command -v python3)" "${WORK}/venv/bin/python3"
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

  It 'defaults direct launches to the Claude Code telemetry label'
    When run env TOKEN_SAVIOR_CLIENT="" TS_VENV="${WORK}/venv" sh "${SCRIPT}"
    The status should be success
    The line 3 of output should equal 'claude-code'
  End

  It 'lets Codex set its own telemetry label'
    When run env TOKEN_SAVIOR_CLIENT=codex TS_VENV="${WORK}/venv" sh "${SCRIPT}"
    The status should be success
    The line 3 of output should equal 'codex'
  End

  It 'registers every usable worktree and makes the current worktree active'
    mkdir -p "${WORK}/repo root" "${WORK}/detached tree" "${WORK}/prunable tree" "${WORK}/shim"
    cat > "${WORK}/shim/git" << 'EOF'
#!/bin/sh
case "$*" in
  'rev-parse --show-toplevel') printf '%s\n' "${FAKE_DETACHED}" ;;
  'worktree list --porcelain -z')
    printf 'worktree %s\0HEAD 1111111\0branch refs/heads/main\0\0' "${FAKE_PRIMARY}"
    printf 'worktree %s\0HEAD 2222222\0detached\0\0' "${FAKE_DETACHED}"
    printf 'worktree %s\0HEAD 3333333\0detached\0\0' "${FAKE_MISSING}"
    printf 'worktree %s\0HEAD 4444444\0detached\0prunable gitdir file points to non-existent location\0\0' "${FAKE_PRUNABLE}"
    ;;
  *) exit 1 ;;
esac
EOF
    chmod +x "${WORK}/shim/git"
    When run env PATH="${WORK}/shim:${PATH}" FAKE_PRIMARY="${WORK}/repo root" FAKE_DETACHED="${WORK}/detached tree" FAKE_MISSING="${WORK}/missing tree" FAKE_PRUNABLE="${WORK}/prunable tree" TS_VENV="${WORK}/venv" sh "${SCRIPT}"
    The status should be success
    The line 4 of output should equal "${WORK}/repo root,${WORK}/detached tree"
    The line 5 of output should equal "${WORK}/detached tree"
  End

  It 'preserves explicit workspace roots and active-root hints'
    When run env WORKSPACE_ROOTS='/custom/one,/custom/two' CLAUDE_PROJECT_ROOT='/custom/two' TS_VENV="${WORK}/venv" sh "${SCRIPT}"
    The status should be success
    The line 4 of output should equal '/custom/one,/custom/two'
    The line 5 of output should equal '/custom/two'
  End

  It 'preserves an explicitly empty workspace-roots override'
    When run env WORKSPACE_ROOTS='' TS_VENV="${WORK}/venv" sh "${SCRIPT}"
    The status should be success
    The line 6 of output should equal '[]'
  End

  It 'preserves an explicitly empty active-root override'
    When run env CLAUDE_PROJECT_ROOT='' TS_VENV="${WORK}/venv" sh "${SCRIPT}"
    The status should be success
    The line 7 of output should equal '[]'
  End

  It 'uses the Git worktree root as the active root when launched from a subdirectory'
    When run sh -c 'unset WORKSPACE_ROOTS GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_PREFIX; cd "$1" && TS_VENV="$2" exec sh "$3"' _ "${PFB_ROOT}/tests" "${WORK}/venv" "${SCRIPT}"
    The status should be success
    The line 4 of output should include "${PFB_ROOT}"
    The line 5 of output should equal "${PFB_ROOT}"
  End
End

Describe 'Token Savior vendor wiring'
  It 'labels the Claude MCP client explicitly'
    When run jq -r '.mcpServers["token-savior-recall"].env.TOKEN_SAVIOR_CLIENT' "${PFB_ROOT}/.mcp.json"
    The status should be success
    The output should equal 'claude-code'
  End

  It 'labels the Codex MCP client and uses the shared launcher'
    When run python3 -c 'import sys, tomllib; c=tomllib.load(open(sys.argv[1], "rb"))["mcp_servers"]["token-savior-recall"]; print(c["env"]["TOKEN_SAVIOR_CLIENT"]); print(" ".join(c["args"]))' "${PFB_ROOT}/.codex/config.toml"
    The status should be success
    The line 1 of output should equal 'codex'
    The line 2 of output should include 'scripts/mcp-token-savior.sh'
  End

  It 'runs the same capture wrapper from Claude and Codex PostToolUse hooks'
    When run sh -c 'jq -er '\''[.hooks.PostToolUse[].hooks[].command | select(contains("scripts/ts-hook.sh") and contains("tool_capture_hook"))] | length > 0'\'' "$1" >/dev/null && jq -er '\''[.hooks.PostToolUse[].hooks[].command | select(contains("scripts/ts-hook.sh") and contains("tool_capture_hook"))] | length > 0'\'' "$2" >/dev/null' _ "${PFB_ROOT}/.claude/settings.json" "${PFB_ROOT}/.codex/hooks.json"
    The status should be success
  End

  It 'captures Claude tool and token-savior-recall output without blanket MCP matching'
    When run python3 -c 'import json, re, sys; groups=json.load(open(sys.argv[1]))["hooks"]["PostToolUse"]; pattern=next(g["matcher"] for g in groups if any("tool_capture_hook" in h["command"] for h in g["hooks"])); approved=("Bash", "Read", "Grep", "WebFetch", "mcp__playwright__browser_snapshot", "mcp__token-savior-recall__search_codebase", "mcp__token-savior-recall__get_full_context"); rejected=("mcp__github__get_file_contents", "mcp__other__read"); assert all(re.search(pattern, name) for name in approved); assert not any(re.search(pattern, name) for name in rejected)' "${PFB_ROOT}/.claude/settings.json"
    The status should be success
  End

  It 'requests only supported Bash, Playwright, and token-savior-recall capture events in Codex'
    When run python3 -c 'import json, re, sys; groups=json.load(open(sys.argv[1]))["hooks"]["PostToolUse"]; pattern=next(g["matcher"] for g in groups if any("tool_capture_hook" in h["command"] for h in g["hooks"])); approved=("Bash", "mcp__playwright__browser_snapshot", "mcp__token-savior-recall__search_codebase", "mcp__token-savior-recall__get_full_context"); rejected=("Read", "Grep", "WebFetch", "apply_patch", "PrefixBash", "BashSuffix", "mcp__github__get_file_contents", "mcp__other__read"); assert all(re.search(pattern, name) for name in approved); assert not any(re.search(pattern, name) for name in rejected)' "${PFB_ROOT}/.codex/hooks.json"
    The status should be success
  End
End

verify_codex_integrity_pins() {
  python3 - "$PFB_ROOT" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
import tomllib

root = Path(sys.argv[1])
hooks = json.loads((root / ".codex/hooks.json").read_text())
hook_commands = [
    hook["command"]
    for groups in hooks["hooks"].values()
    for group in groups
    for hook in group["hooks"]
]
for relative in (
    ".claude/hooks/session-branch-sync.sh",
    "scripts/claude-bash-guard.sh",
    "scripts/check_retired_tokens.py",
    "scripts/ts-hook.sh",
):
    digest = hashlib.sha256((root / relative).read_bytes()).hexdigest()
    matches = [command for command in hook_commands if relative in command]
    assert len(matches) == 1, f"expected one Codex hook command for {relative}"
    assert digest in matches[0], f"stale Codex hook hash for {relative}"

config = tomllib.loads((root / ".codex/config.toml").read_text())
mcp_command = " ".join(config["mcp_servers"]["token-savior-recall"]["args"])
relative = "scripts/mcp-token-savior.sh"
digest = hashlib.sha256((root / relative).read_bytes()).hexdigest()
assert relative in mcp_command
assert digest in mcp_command, f"stale Codex MCP hash for {relative}"
PY
}

Describe 'Codex repository-script integrity pins'
  It 'pins every hook and MCP launcher to its current SHA-256'
    When call verify_codex_integrity_pins
    The status should be success
  End
End

Describe 'mcp-token-savior.sh upstream install policy'
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

  It 'installs exact upstream Token Savior 4.21.0 on first run'
    When run env PATH="${WORK}/shim:${PATH}" TS_VENV="${WORK}/venv" sh "${SCRIPT}"
    The status should be success
    The output should equal 'INSTALLED'
    The stderr should equal ''
    The contents of file "${WORK}/venv/pip-args.log" should equal 'token-savior-recall[mcp,memory-vector]==4.21.0'
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

  It 'reaps a rebuild lock whose recorded holder PID is dead (issue #1969)'
    # A SIGKILLed holder can never run its EXIT trap, so its lock outlives it and
    # blocked every later session until TS_LOCK_WAIT expired (nine days, in the
    # incident). A dead recorded PID proves the holder is gone: reap and rebuild.
    # TS_LOCK_WAIT=2 keeps a non-reaping launcher failing fast instead of hanging.
    sh -c 'exit 0' &
    dead_pid=$!
    wait "${dead_pid}"
    mkdir -p "${WORK}/venv.rebuild.lock"
    printf '%s\n' "${dead_pid}" > "${WORK}/venv.rebuild.lock/pid"
    When run env PATH="${WORK}/shim:${PATH}" TS_VENV="${WORK}/venv" TS_LOCK_WAIT=2 sh "${SCRIPT}"
    The status should be success
    The output should equal 'INSTALLED'
    The stderr should equal ''
    The directory "${WORK}/venv.rebuild.lock" should not be exist
  End

  It 'records its own live PID in the lock it holds'
    # Without this, the reap above would be unreachable in production: no holder
    # would ever leave a PID for a later session to test. The python3 wrapper runs
    # under the lock, i.e. exactly while the holder is installing.
    mkdir -p "${WORK}/probe"
    cat > "${WORK}/probe/python3" << EOF
#!/bin/sh
holder="\$(cat "${WORK}/venv.rebuild.lock/pid" 2>/dev/null || true)"
if [ -z "\${holder}" ]; then
	printf 'MISSING\n' > "${WORK}/observed"
elif kill -0 "\${holder}" 2>/dev/null; then
	printf 'LIVE\n' > "${WORK}/observed"
else
	printf 'DEAD\n' > "${WORK}/observed"
fi
exec "${WORK}/shim/python3" "\$@"
EOF
    chmod +x "${WORK}/probe/python3"
    When run env PATH="${WORK}/probe:${WORK}/shim:${PATH}" TS_VENV="${WORK}/venv" sh "${SCRIPT}"
    The status should be success
    The output should equal 'INSTALLED'
    The stderr should equal ''
    The contents of file "${WORK}/observed" should equal 'LIVE'
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

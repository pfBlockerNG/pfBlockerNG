#shellcheck shell=sh
# Agent sessions must trust the repository-owned RTK filters from the current
# worktree root. Claude and Codex share the same best-effort bootstrap hook.

Describe 'rtk SessionStart bootstrap'
  hook="${PFB_ROOT}/.claude/hooks/rtk-install.sh"

  setup() {
    scrub_git_env
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/rtk-install.XXXXXX")"
    project="${work}/project"
    shim="${work}/shim"
    log="${work}/rtk.log"
    mkdir -p "${project}/.rtk" "${project}/subdir" "${shim}"
    git init -q "${project}"
    printf '[filters]\n' > "${project}/.rtk/filters.toml"
    git -C "${project}" config user.email test@example.com
    git -C "${project}" config user.name Test
    git -C "${project}" config commit.gpgsign false
    git -C "${project}" add .rtk/filters.toml
    git -C "${project}" commit -q -m filters
    cat > "${shim}/rtk" <<'EOF'
#!/bin/sh
printf '%s|%s\n' "$PWD" "$*" >> "$RTK_LOG"
EOF
    chmod +x "${shim}/rtk"
  }

  cleanup() {
    rm -rf "${work}"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'trusts filters against the Git worktree root when RTK already exists'
    When run env PATH="${shim}:${PATH}" RTK_LOG="${log}" CLAUDE_PROJECT_DIR= \
      sh -c 'cd "$1" && exec sh "$2"' _ "${project}/subdir" "${hook}"
    The status should be success
    The contents of file "${log}" should equal "${project}|trust"
  End

  It 'does not trust a worktree without a project filter file'
    rm "${project}/.rtk/filters.toml"
    When run env PATH="${shim}:${PATH}" RTK_LOG="${log}" CLAUDE_PROJECT_DIR="${project}" sh "${hook}"
    The status should be success
    The file "${log}" should not be exist
  End
End

Describe 'rtk fallback installer integrity'
  hook="${PFB_ROOT}/.claude/hooks/rtk-install.sh"
  fixture="${PFB_ROOT}/tests/shell/fixtures/rtk-install-v0.43.0.sh"

  setup() {
    scrub_git_env
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/rtk-fallback.XXXXXX")"
    home="${work}/home"
    shim="${work}/shim"
    curl_log="${work}/curl.log"
    executed="${work}/executed"
    mkdir -p "${home}" "${shim}"
    cat > "${shim}/curl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$RTK_CURL_LOG"
out=''
url=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o)
      shift
      out="$1"
      ;;
    http*) url="$1" ;;
  esac
  shift
done

case "$url" in
  *raw.githubusercontent.com/rtk-ai/rtk/*/install.sh)
    if [ "${RTK_HOSTILE:-0}" = 1 ]; then
      payload='touch "$RTK_EXECUTED_MARKER"'
      if [ -n "$out" ]; then
        printf '%s\n' "$payload" > "$out"
      else
        printf '%s\n' "$payload"
      fi
    elif [ -n "$out" ]; then
      cp "$RTK_INSTALLER_FIXTURE" "$out"
    else
      cat "$RTK_INSTALLER_FIXTURE"
    fi
    exit 0
    ;;
  *) exit 22 ;;
esac
EOF
    chmod +x "${shim}/curl"
  }

  cleanup() {
    rm -rf "${work}"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'executes the verified immutable installer with a pinned release'
    When run env HOME="${home}" PATH="${shim}:/usr/bin:/bin" RTK_CURL_LOG="${curl_log}" \
      RTK_INSTALLER_FIXTURE="${fixture}" RTK_EXECUTED_MARKER="${executed}" \
      CLAUDE_PROJECT_DIR="${work}" sh "${hook}"
    The status should be success
    The contents of file "${curl_log}" should include 'rtk/5a7880d404db8364d602f2ecdc41dd790f64013f/install.sh'
    The contents of file "${curl_log}" should include '/releases/download/v0.43.0/rtk-'
  End

  It 'rejects changed installer bytes without executing them'
    When run env HOME="${home}" PATH="${shim}:/usr/bin:/bin" RTK_CURL_LOG="${curl_log}" \
      RTK_INSTALLER_FIXTURE="${fixture}" RTK_EXECUTED_MARKER="${executed}" RTK_HOSTILE=1 \
      CLAUDE_PROJECT_DIR="${work}" sh "${hook}"
    The status should be success
    The file "${executed}" should not be exist
  End
End

verify_vendor_rtk_bootstrap() {
  python3 - "$PFB_ROOT" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
relative = ".claude/hooks/rtk-install.sh"
digest = hashlib.sha256((root / relative).read_bytes()).hexdigest()

claude = json.loads((root / ".claude/settings.json").read_text())
claude_commands = [
    hook["command"]
    for group in claude["hooks"]["SessionStart"]
    for hook in group["hooks"]
    if relative in hook["command"]
]
assert len(claude_commands) == 1, "Claude must run the shared RTK bootstrap once"

codex = json.loads((root / ".codex/hooks.json").read_text())
codex_commands = [
    hook["command"]
    for group in codex["hooks"]["SessionStart"]
    for hook in group["hooks"]
    if relative in hook["command"]
]
assert len(codex_commands) == 1, "Codex must run the shared RTK bootstrap once"
assert digest in codex_commands[0], "Codex RTK bootstrap integrity hash is stale"
PY
}

Describe 'RTK bootstrap vendor wiring'
  It 'uses the integrity-pinned shared hook for Claude and Codex'
    When call verify_vendor_rtk_bootstrap
    The status should be success
  End
End

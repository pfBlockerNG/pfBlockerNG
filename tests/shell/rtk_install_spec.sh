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

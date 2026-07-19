#shellcheck shell=sh
# Automatic trust is limited to the committed regular filter file. Local files,
# worktree edits, and symlinks must still require explicit human review.

Describe 'rtk checked-in filter trust boundary'
  hook="${PFB_ROOT}/.claude/hooks/rtk-install.sh"

  setup() {
    scrub_git_env
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/rtk-tracked.XXXXXX")"
    project="${work}/project"
    shim="${work}/shim"
    log="${work}/rtk.log"
    mkdir -p "${project}/.rtk" "${shim}"
    git init -q "${project}"
    git -C "${project}" config user.email test@example.com
    git -C "${project}" config user.name Test
    git -C "${project}" config commit.gpgsign false
    printf '[filters]\n' > "${project}/.rtk/filters.toml"
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

  run_hook() {
    env PATH="${shim}:${PATH}" RTK_LOG="${log}" CLAUDE_PROJECT_DIR="${project}" sh "${hook}"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'trusts the unchanged committed regular filter'
    When run run_hook
    The status should be success
    The contents of file "${log}" should equal "${project}|trust"
  End

  It 'does not trust an untracked filter'
    git -C "${project}" rm -q --cached .rtk/filters.toml
    When run run_hook
    The status should be success
    The file "${log}" should not be exist
  End

  It 'does not trust local edits to the committed filter'
    printf '# local edit\n' >> "${project}/.rtk/filters.toml"
    When run run_hook
    The status should be success
    The file "${log}" should not be exist
  End

  It 'does not trust a symlink replacing the committed filter'
    rm "${project}/.rtk/filters.toml"
    printf '[outside]\n' > "${work}/outside.toml"
    ln -s "${work}/outside.toml" "${project}/.rtk/filters.toml"
    When run run_hook
    The status should be success
    The file "${log}" should not be exist
  End
End

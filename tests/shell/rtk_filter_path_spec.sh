#shellcheck shell=sh
# A regular filter reached through a symlinked .rtk directory is not owned by
# the worktree, even when its bytes equal the committed blob.

Describe 'rtk filter path ownership'
  hook="${PFB_ROOT}/.claude/hooks/rtk-install.sh"

  setup() {
    scrub_git_env
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/rtk-path.XXXXXX")"
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
    mv "${project}/.rtk" "${work}/outside-rtk"
    ln -s "${work}/outside-rtk" "${project}/.rtk"
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

  It 'does not trust a committed blob reached through a symlinked filter directory'
    When run env PATH="${shim}:${PATH}" RTK_LOG="${log}" CLAUDE_PROJECT_DIR="${project}" sh "${hook}"
    The status should be success
    The file "${log}" should not be exist
  End
End

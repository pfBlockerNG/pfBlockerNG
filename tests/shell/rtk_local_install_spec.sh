#shellcheck shell=sh
# A cloud install may place RTK in ~/.local/bin before the current shell has
# refreshed PATH. Session bootstrap must still trust this worktree's filters.

Describe 'rtk local-install bootstrap'
  hook="${PFB_ROOT}/.claude/hooks/rtk-install.sh"

  setup() {
    scrub_git_env
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/rtk-local.XXXXXX")"
    project="${work}/project"
    home="${work}/home"
    log="${work}/rtk.log"
    mkdir -p "${project}/.rtk" "${home}/.local/bin"
    git init -q "${project}"
    printf '[filters]\n' > "${project}/.rtk/filters.toml"
    git -C "${project}" config user.email test@example.com
    git -C "${project}" config user.name Test
    git -C "${project}" config commit.gpgsign false
    git -C "${project}" add .rtk/filters.toml
    git -C "${project}" commit -q -m filters
    cat > "${home}/.local/bin/rtk" <<'EOF'
#!/bin/sh
printf '%s|%s\n' "$PWD" "$*" >> "$RTK_LOG"
exit "${RTK_EXIT:-0}"
EOF
    chmod +x "${home}/.local/bin/rtk"
  }

  cleanup() {
    rm -rf "${work}"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'uses the installed binary even before local bin is on PATH'
    When run env HOME="${home}" PATH="/usr/bin:/bin" RTK_LOG="${log}" \
      CLAUDE_PROJECT_DIR="${project}" sh "${hook}"
    The status should be success
    The contents of file "${log}" should equal "${project}|trust"
  End

  It 'keeps session startup non-blocking when trust fails'
    When run env HOME="${home}" PATH="/usr/bin:/bin" RTK_LOG="${log}" RTK_EXIT=9 \
      CLAUDE_PROJECT_DIR="${project}" sh "${hook}"
    The status should be success
    The contents of file "${log}" should equal "${project}|trust"
  End
End

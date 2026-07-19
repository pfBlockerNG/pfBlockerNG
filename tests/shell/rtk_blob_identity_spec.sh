#shellcheck shell=sh
# Git index optimization flags can hide worktree edits from `git diff`. Trust
# compares actual filter bytes with HEAD and still requires regular-file mode.

Describe 'rtk committed filter identity'
  hook="${PFB_ROOT}/.claude/hooks/rtk-install.sh"

  setup() {
    scrub_git_env
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/rtk-identity.XXXXXX")"
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

  It 'does not trust changed bytes hidden by assume-unchanged'
    git -C "${project}" update-index --assume-unchanged .rtk/filters.toml
    printf '[local]\n' > "${project}/.rtk/filters.toml"
    When run run_hook
    The status should be success
    The file "${log}" should not be exist
  End

  It 'does not trust changed bytes hidden by skip-worktree'
    git -C "${project}" update-index --skip-worktree .rtk/filters.toml
    printf '[local]\n' > "${project}/.rtk/filters.toml"
    When run run_hook
    The status should be success
    The file "${log}" should not be exist
  End

  It 'does not trust a filter committed with executable mode'
    git -C "${project}" update-index --chmod=+x .rtk/filters.toml
    git -C "${project}" commit -q -m executable-filter
    When run run_hook
    The status should be success
    The file "${log}" should not be exist
  End
End

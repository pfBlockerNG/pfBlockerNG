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

  # Premise gate for the clean-filter example (#1883): the example only tests
  # the hook when HEAD holds the CLEANED bytes. If `git add` skipped the clean
  # filter, HEAD equals the worktree bytes and the hook would trust them
  # legitimately — fail the premise loudly instead of flaking on the log check.
  run_hook_with_cleaned_head() {
    head_blob=$(git -C "${project}" cat-file -p HEAD:.rtk/filters.toml) || return 9
    if [ "${head_blob}" != '[FILTERS]' ]; then
      echo "premise failed: HEAD:.rtk/filters.toml is '${head_blob}', expected cleaned '[FILTERS]'" >&2
      return 9
    fi
    run_hook
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

  It 'does not trust metadata redirected through an inherited Git directory'
    evil="${work}/evil"
    mkdir -p "${evil}/.rtk"
    git init -q "${evil}"
    git -C "${evil}" config user.email test@example.com
    git -C "${evil}" config user.name Test
    git -C "${evil}" config commit.gpgsign false
    printf '[local]\n' > "${evil}/.rtk/filters.toml"
    git -C "${evil}" add .rtk/filters.toml
    git -C "${evil}" commit -q -m filters
    printf '[local]\n' > "${project}/.rtk/filters.toml"
    When run env PATH="${shim}:${PATH}" RTK_LOG="${log}" CLAUDE_PROJECT_DIR="${project}" \
      GIT_DIR="${evil}/.git" sh "${hook}"
    The status should be success
    The file "${log}" should not be exist
  End

  It 'does not trust a filter while its index entry is unmerged'
    base_oid=$(printf 'base\n' | git -C "${project}" hash-object -w --stdin)
    ours_oid=$(printf 'ours\n' | git -C "${project}" hash-object -w --stdin)
    theirs_oid=$(printf 'theirs\n' | git -C "${project}" hash-object -w --stdin)
    git -C "${project}" update-index --index-info <<EOF
0 0000000000000000000000000000000000000000	.rtk/filters.toml
100644 ${base_oid} 1	.rtk/filters.toml
100644 ${ours_oid} 2	.rtk/filters.toml
100644 ${theirs_oid} 3	.rtk/filters.toml
EOF
    When run run_hook
    The status should be success
    The file "${log}" should not be exist
  End

  It 'does not trust changed bytes normalized by a Git clean filter'
    # Pin the stat-cache skip deterministically (#1883): a backdated, re-added
    # entry is definitively clean (entry mtime < index mtime), so a plain
    # `git add` would trust the stat cache and never re-run the clean filter —
    # the intermittent CI path. --renormalize forces the re-clean regardless.
    touch -t 202001010000 "${project}/.rtk/filters.toml"
    git -C "${project}" add .rtk/filters.toml
    git -C "${project}" config filter.upper.clean "tr '[:lower:]' '[:upper:]'"
    git -C "${project}" config filter.upper.smudge cat
    printf '*.toml filter=upper\n' > "${project}/.gitattributes"
    git -C "${project}" add .gitattributes
    git -C "${project}" add --renormalize .rtk/filters.toml
    git -C "${project}" commit -q -m clean-filter
    When run run_hook_with_cleaned_head
    The status should be success
    The file "${log}" should not be exist
  End
End

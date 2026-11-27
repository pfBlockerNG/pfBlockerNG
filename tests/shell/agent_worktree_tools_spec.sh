#shellcheck shell=sh
# Direct per-worktree preparation: the primary's .worktrees/ ignores itself (#4265).

Describe 'init-worktree-tools.sh'
  script_abs="${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/init-worktree-tools.sh"

  setup() {
    . "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/lib/git-env-scrub.sh"
    pfb_scrub_git_env
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/worktree_tools.XXXXXX") || return 1
    fixture=$(cd "$fixture" && pwd -P) || return 1
    worktree="$fixture/worktree root"
    git_fixture init -q "$worktree" &&
      git_fixture -C "$worktree" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
        commit -q --allow-empty -m init || return 1
    tool_path="$fixture/tool-path"
    mkdir -p "$tool_path"
    for tool in sh dirname git tr mkdir pwd mv mktemp rm; do
      ln -s "$(command -v "$tool")" "$tool_path/$tool"
    done
  }
  cleanup() { rm -rf "$fixture"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  # A worktree cut under the primary's .worktrees/ (by work-branch.sh or a plain `wt switch -c`) has the folder
  # ignore itself; the primary's path here holds a space.
  linked() {
    git_fixture -C "$worktree" worktree add -q --detach "$1" >/dev/null 2>&1
  }

  It "writes the primary's .worktrees/.gitignore for a worktree cut under it"
    linked "$worktree/.worktrees/topic" || return 1
    When run env PATH="$tool_path" sh "$script_abs" "$worktree/.worktrees/topic"
    The status should equal 0
    The contents of file "$worktree/.worktrees/.gitignore" should equal '*'
    Assert [ -z "$(git_fixture -C "$worktree" status --porcelain --untracked-files=all)" ]
  End

  It "refuses a symlink at the primary's .worktrees/.gitignore and writes nothing through it"
    linked "$worktree/.worktrees/topic" || return 1
    ln -s "$fixture/outside-ignore" "$worktree/.worktrees/.gitignore"
    When run sh "$script_abs" "$worktree/.worktrees/topic"
    The status should equal 2
    The stderr should include 'the worktree root .gitignore must not be a symlink'
    Assert [ ! -e "$fixture/outside-ignore" ]
  End

  It "refuses a .gitignore that is not a regular file and leaves no temporary file"
    linked "$worktree/.worktrees/topic" || return 1
    mkdir "$worktree/.worktrees/.gitignore"
    When run sh "$script_abs" "$worktree/.worktrees/topic"
    The status should equal 2
    The stderr should include 'the worktree root .gitignore must be a regular file'
    Assert [ -z "$(find "$worktree/.worktrees" -maxdepth 1 -name '.gitignore.*')" ]
  End

  It "names a missing tool the ignore needs instead of failing bare"
    linked "$worktree/.worktrees/topic" || return 1
    rm "$tool_path/mktemp"
    When run env PATH="$tool_path" sh "$script_abs" "$worktree/.worktrees/topic"
    The status should equal 4
    The stderr should include 'TOOL-MISSING: mktemp'
    Assert [ ! -e "$worktree/.worktrees/.gitignore" ]
  End

  It "names a missing rm, which the ignore's cleanup needs, instead of failing bare"
    linked "$worktree/.worktrees/topic" || return 1
    rm "$tool_path/rm"
    When run env PATH="$tool_path" sh "$script_abs" "$worktree/.worktrees/topic"
    The status should equal 4
    The stderr should include 'TOOL-MISSING: rm'
    Assert [ ! -e "$worktree/.worktrees/.gitignore" ]
  End

  It "leaves the primary's .worktrees/ alone for a worktree cut elsewhere"
    linked "$fixture/elsewhere" || return 1
    mkdir "$worktree/.worktrees"
    When run sh "$script_abs" "$fixture/elsewhere"
    The status should equal 0
    Assert [ ! -e "$worktree/.worktrees/.gitignore" ]
  End
End

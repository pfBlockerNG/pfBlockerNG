#shellcheck shell=sh
# Direct per-worktree initialization for repository intelligence tools.

Describe 'init-worktree-tools.sh'
  script_abs="${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/init-worktree-tools.sh"

  make_tool_path() {
    destination=$1
    mkdir -p "$destination"
    for tool in sh dirname git tr mkdir pwd mv mktemp; do
      ln -s "$(command -v "$tool")" "$destination/$tool"
    done
  }

  setup() {
    . "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/lib/git-env-scrub.sh"
    pfb_scrub_git_env
    unset OMP_CLI PI_CLI
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/worktree_tools.XXXXXX") || return 1
    fixture=$(cd "$fixture" && pwd -P) || return 1
    worktree="$fixture/worktree root"
    git_fixture init -q "$worktree" &&
      git_fixture -C "$worktree" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
        commit -q --allow-empty -m init || return 1
    stubdir="$fixture/bin"; mkdir -p "$stubdir"
    tool_log="$fixture/tools.log"

    cat > "$stubdir/codegraph" <<'CODEGRAPH'
#!/bin/sh
case "$1" in
  init|index)
    printf 'codegraph:%s:%s\n' "$1" "$2" >> "$WORKTREE_TOOL_LOG"
    [ "${CODEGRAPH_RC:-0}" -eq 0 ] || exit "$CODEGRAPH_RC"
    mkdir -p "$2/.codegraph"
    true > "$2/.codegraph/codegraph.db"
    ;;
  status)
    printf '%s\n' '{"initialized":true,"worktreeMismatch":null,"index":{"reindexRecommended":false,"state":"complete","pendingRefs":0}}'
    ;;
  *) exit 9 ;;
esac
CODEGRAPH
    cat > "$stubdir/serena" <<'SERENA'
#!/bin/sh
[ "$#" -eq 3 ] && [ "$1" = project ] && [ "$2" = index ] || exit 9
printf 'serena:%s:%s:%s\n' "$1" "$2" "$3" >> "$WORKTREE_TOOL_LOG"
exit "${SERENA_RC:-0}"
SERENA
    chmod +x "$stubdir/codegraph" "$stubdir/serena"

    no_codegraph="$fixture/no-codegraph"
    no_serena="$fixture/no-serena"
    make_tool_path "$no_codegraph"
    make_tool_path "$no_serena"
    ln -s "$stubdir/serena" "$no_codegraph/serena"
    ln -s "$stubdir/codegraph" "$no_serena/codegraph"

    export WORKTREE_TOOL_LOG="$tool_log"
    PATH="$stubdir:$PATH"; export PATH
  }
  cleanup() { rm -rf "$fixture"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'runs CodeGraph and skips Serena when OMP marks the invoking harness'
    When run env OMP_CLI=1 sh "$script_abs" "$worktree"
    The status should equal 0
    The contents of file "$tool_log" should equal "$(printf 'codegraph:init:%s' "$worktree")"
    The stderr should include 'Initializing CodeGraph in'
  End

  It 'runs CodeGraph and skips Serena when PI marks the invoking harness'
    When run env PI_CLI=1 sh "$script_abs" "$worktree"
    The status should equal 0
    The contents of file "$tool_log" should equal "$(printf 'codegraph:init:%s' "$worktree")"
    The stderr should include 'Initializing CodeGraph in'
  End

  It 'fails nonzero when mandatory CodeGraph is missing'
    When run env OMP_CLI=1 PATH="$no_codegraph" sh "$script_abs" "$worktree"
    The status should not equal 0
    The stderr should include 'codegraph'
    The file "$tool_log" should not be exist
  End

  It 'stops when mandatory CodeGraph initialization fails'
    When run env OMP_CLI=1 CODEGRAPH_RC=17 sh "$script_abs" "$worktree"
    The status should not equal 0
    The contents of file "$tool_log" should equal "codegraph:init:$worktree"
    The stderr should include 'CodeGraph initialization failed'
  End

  It 'runs Serena project indexing at the exact root outside OMP when Serena is present'
    When run sh "$script_abs" "$worktree"
    The status should equal 0
    The contents of file "$tool_log" should equal \
      "$(printf 'codegraph:init:%s\nserena:project:index:%s' "$worktree" "$worktree")"
    The stderr should include 'Initializing CodeGraph in'
  End

  It 'skips absent Serena outside OMP without weakening mandatory initialization'
    When run env PATH="$no_serena" sh "$script_abs" "$worktree"
    The status should equal 0
    The contents of file "$tool_log" should equal "$(printf 'codegraph:init:%s' "$worktree")"
    The stderr should include 'Initializing CodeGraph in'
  End

  It 'propagates Serena indexing failure'
    When run env SERENA_RC=23 sh "$script_abs" "$worktree"
    The status should equal 23
    The contents of file "$tool_log" should equal \
      "$(printf 'codegraph:init:%s\nserena:project:index:%s' "$worktree" "$worktree")"
    The stderr should include 'Initializing CodeGraph in'
  End

  # #4265: a worktree cut under the primary's .worktrees/ (by work-branch.sh or a plain `wt switch -c`) has the folder
  # ignore itself; the primary's path here holds a space.
  linked() {
    git_fixture -C "$worktree" worktree add -q --detach "$1" >/dev/null 2>&1
  }

  It "writes the primary's .worktrees/.gitignore for a worktree cut under it"
    linked "$worktree/.worktrees/topic" || return 1
    When run env OMP_CLI=1 sh "$script_abs" "$worktree/.worktrees/topic"
    The status should equal 0
    The stderr should include 'Initializing CodeGraph in'
    The contents of file "$worktree/.worktrees/.gitignore" should equal '*'
    Assert [ -z "$(git_fixture -C "$worktree" status --porcelain --untracked-files=all)" ]
  End

  It "refuses a symlink at the primary's .worktrees/.gitignore and writes nothing through it"
    linked "$worktree/.worktrees/topic" || return 1
    ln -s "$fixture/outside-ignore" "$worktree/.worktrees/.gitignore"
    When run env OMP_CLI=1 sh "$script_abs" "$worktree/.worktrees/topic"
    The status should equal 2
    The stderr should include 'the worktree root .gitignore must not be a symlink'
    Assert [ ! -e "$fixture/outside-ignore" ]
  End

  It "refuses a .gitignore that is not a regular file and leaves no temporary file"
    linked "$worktree/.worktrees/topic" || return 1
    mkdir "$worktree/.worktrees/.gitignore"
    When run env OMP_CLI=1 sh "$script_abs" "$worktree/.worktrees/topic"
    The status should equal 2
    The stderr should include 'the worktree root .gitignore must be a regular file'
    Assert [ -z "$(find "$worktree/.worktrees" -maxdepth 1 -name '.gitignore.*')" ]
  End

  It "writes the ignore before it needs CodeGraph, so a cut on a host without it is ignored too"
    linked "$worktree/.worktrees/topic" || return 1
    When run env PATH="$no_codegraph" sh "$script_abs" "$worktree/.worktrees/topic"
    The status should equal 4
    The stderr should include 'codegraph'
    The contents of file "$worktree/.worktrees/.gitignore" should equal '*'
  End

  It "leaves the primary's .worktrees/ alone for a worktree cut elsewhere"
    linked "$fixture/elsewhere" || return 1
    mkdir "$worktree/.worktrees"
    When run env OMP_CLI=1 sh "$script_abs" "$fixture/elsewhere"
    The status should equal 0
    The stderr should include 'Initializing CodeGraph in'
    Assert [ ! -e "$worktree/.worktrees/.gitignore" ]
  End
End

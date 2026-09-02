#shellcheck shell=sh
# work-branch.sh: the CLAUDE.md branch-name sanitiser, pinned so it is never hand-derived
# again. Covers both CLAUDE.md examples, the 30-char boundary truncation, emoji/non-ASCII
# stripping, and the empty-slug bare form.

Describe 'work-branch.sh branch naming'
  script="scripts/agent/work-branch.sh"

  It 'derives the CLAUDE.md issue example'
    When run sh "$script" issue 43 "TLD-Allow KeyError on ..."
    The output should equal 'issue/43-tld-allow-keyerror-on'
  End

  It 'derives the CLAUDE.md ADR example'
    When run sh "$script" adr 10 "Zero_Downtime_DNSBL"
    The output should equal 'adr/10-zero-downtime-dnsbl'
  End

  It 'truncates at a dash boundary, never mid-token and never trailing a dash'
    When run sh "$script" issue 1173 "IP recompute: a priority reorder alone never triggers recompute"
    The output should equal 'issue/1173-ip-recompute-a-priority'
  End

  It 'keeps a slug of exactly 30 characters intact'
    When run sh "$script" issue 1 "abcde-fghij-klmno-pqrst-uvwxyz"
    The output should equal 'issue/1-abcde-fghij-klmno-pqrst-uvwxyz'
  End

  It 'strips emoji and collapses the runs they leave'
    When run sh "$script" issue 7 "🔥 Hot fix!!"
    The output should equal 'issue/7-hot-fix'
  End

  It 'omits an empty slug (bare type/NN)'
    When run sh "$script" issue 99 "🎉🎉🎉"
    The output should equal 'issue/99'
  End

  It 'rejects --base given without a value'
    When run sh "$script" issue 5 title --base
    The status should equal 2
    The stderr should include 'usage'
  End

  It 'rejects a non-numeric issue number'
    When run sh "$script" issue abc "title"
    The status should equal 2
    The stderr should include 'usage'
  End

  It 'rejects an unknown work-item kind'
    When run sh "$script" bug 5 "title"
    The status should equal 2
    The stderr should include 'usage'
  End
End

Describe 'work-branch.sh post-add tool initialization'
  script_abs="${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/work-branch.sh"

  setup() {
    . "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/lib/git-env-scrub.sh"
    pfb_scrub_git_env
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/wb_tools.XXXXXX") || return 1
    fixture=$(cd "$fixture" && pwd -P) || return 1
    primary="$fixture/primary"
    worktree_root="$fixture/.primary_worktrees"
    git_fixture init -q -b devel "$primary" &&
      git_fixture -C "$primary" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
        commit -q --allow-empty -m init || return 1
    stubdir="$fixture/bin"; mkdir -p "$stubdir"
    events="$fixture/events"
    cat > "$stubdir/init-worktree-tools" <<'INIT'
#!/bin/sh
printf 'init:%s\n' "$1" >> "$WB_TOOL_EVENTS"
[ "${WB_INIT_DIRTY:-0}" -eq 0 ] || printf '%s\n' debris > "$1/init-debris"
exit "${WB_INIT_RC:-0}"
INIT
    chmod +x "$stubdir/init-worktree-tools"
    cat > "$stubdir/codegraph" <<'CODEGRAPH'
#!/bin/sh
case "$1" in
  init|index)
    [ -n "${WB_DEFAULT_TOOL_LOG:-}" ] && printf 'codegraph:%s:%s\n' "$1" "$2" >> "$WB_DEFAULT_TOOL_LOG"
    mkdir -p "$2/.codegraph"
    true > "$2/.codegraph/codegraph.db"
    ;;
  status)
    printf '%s\n' '{"initialized":true,"worktreeMismatch":null,"index":{"reindexRecommended":false,"state":"complete","pendingRefs":0}}'
    ;;
  *) exit 9 ;;
esac
CODEGRAPH
    graphify_package="$fixture/toolvenv/package/graphify"
    mkdir -p "$graphify_package"
    interpreter="$fixture/toolvenv/bin/python3"
    mkdir -p "$fixture/toolvenv/bin"
    cat > "$interpreter" <<'INTERPRETER'
#!/bin/sh
case "$*" in
  *os.path.dirname*) printf '%s\n' "$WB_GRAPHIFY_PACKAGE"; exit 0 ;;
  *activate_language_overrides*) exit 0 ;;
esac
exec sh "$@"
INTERPRETER
    chmod +x "$interpreter"
    printf '#!%s\n' "$interpreter" > "$stubdir/graphify"
    cat >> "$stubdir/graphify" <<'GRAPHIFY'
case "$1" in
  update)
    [ "$#" -eq 2 ] || exit 9
    printf 'graphify:%s:%s\n' "$1" "$2" >> "$WB_DEFAULT_TOOL_LOG"
    ;;
  *) exit 9 ;;
esac
GRAPHIFY
    chmod +x "$stubdir/codegraph" "$stubdir/graphify"
    export WB_REAL_GIT="$(command -v git)"
    cat > "$stubdir/git" <<'GIT'
#!/bin/sh
case " $* " in
  *" fetch origin "*) printf '%s\n' fetch >> "$WB_TOOL_EVENTS" ;;
  *" worktree add "*) printf '%s\n' add >> "$WB_TOOL_EVENTS" ;;
esac
exec "$WB_REAL_GIT" "$@"
GIT
    chmod +x "$stubdir/git"
    # `wt` stub: records the call, then cuts the worktree the way real wt does.
    # It reaches the REAL git on purpose — the `add` event exists to catch
    # work-branch.sh calling `git worktree add` itself, i.e. taking the fallback.
    cat > "$stubdir/wt" <<'WT'
#!/bin/sh
printf '%s\n' wt >> "$WB_TOOL_EVENTS"
[ "${WB_WT_RC:-0}" -eq 0 ] || exit "$WB_WT_RC"
wt_path=''
wt_branch=''
while [ "$#" -gt 0 ]; do
  case $1 in
    --config-set)
      wt_path=${2#worktree-path=\"}
      wt_path=${wt_path%\"}
      shift 2
      ;;
    switch)
      shift
      wt_branch=${1:-}
      [ "$#" -eq 0 ] || shift
      ;;
    *) shift ;;
  esac
done
# WB_WT_EMPTY reproduces a wt that reports success and leaves no worktree.
[ "${WB_WT_EMPTY:-0}" -eq 0 ] || exit 0
"$WB_REAL_GIT" worktree add "$wt_path" "$wt_branch" || exit $?
# Real wt runs the tracked .config/wt.toml `pre-start` hook, which initializes the
# worktree's tools. WB_WT_PRESTART reproduces that already-initialized result.
[ "${WB_WT_PRESTART:-0}" -eq 0 ] || {
  mkdir -p "$wt_path/.codegraph"
  true > "$wt_path/.codegraph/codegraph.db"
}
WT
    chmod +x "$stubdir/wt"
    export WB_TOOL_EVENTS="$events"
    default_tool_log="$fixture/default-tools"
    export WB_DEFAULT_TOOL_LOG="$default_tool_log" WB_GRAPHIFY_PACKAGE="$graphify_package"
    export PFB_INIT_WORKTREE_TOOLS="$stubdir/init-worktree-tools"
    PATH="$stubdir:$PATH"; export PATH
  }
  cleanup() {
    unset PFB_INIT_WORKTREE_TOOLS
    rm -rf "$fixture"
  }
  add_origin() {
    git_fixture clone -q --bare "$primary" "$fixture/origin.git" &&
      git_fixture -C "$primary" remote add origin "$fixture/origin.git"
  }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'fetches before add and initializes a relative worktree beneath the sibling root'
    add_origin || return 1
    mkdir -p "$primary/nested"
    When run sh -c 'cd "$1" && exec sh "$2" adr 41 tools --worktree --base HEAD --path nested/worktree' _ "$primary" "$script_abs"
    The status should equal 0
    The output should equal "$(printf 'adr/41-tools\t%s/nested/worktree' "$worktree_root")"
    The stderr should include 'Preparing worktree'
    The contents of file "$events" should equal "$(printf 'fetch\nwt\ninit:%s/nested/worktree' "$worktree_root")"
    The path "$worktree_root" should be directory
  End

  It 'uses the co-located default initializer when no test seam is configured'
    add_origin || return 1
    unset PFB_INIT_WORKTREE_TOOLS
    When run env OMP_CLI=1 sh -c 'cd "$1" && exec sh "$2" adr 44 tools --worktree --base HEAD --path "$3"' _ "$primary" "$script_abs" "$fixture/default-init"
    The status should equal 0
    The output should equal "$(printf 'adr/44-tools\t%s/default-init' "$fixture")"
    The stderr should include 'Preparing worktree'
    The stderr should include 'Initializing CodeGraph in'
    The contents of file "$events" should equal "$(printf 'fetch\nwt')"
    The contents of file "$default_tool_log" should equal "codegraph:init:$fixture/default-init"
    The stderr should include 'run /graphify'
  End

  It 'aborts a configured origin fetch failure before add or initialization'
    git_fixture -C "$primary" remote add origin "$fixture/missing-origin"
    When run sh -c 'cd "$1" && exec sh "$2" adr 42 tools --worktree --base HEAD --path "$3"' _ "$primary" "$script_abs" "$fixture/fetch-fail"
    The status should equal 1
    The output should equal ''
    The stderr should include 'git fetch origin failed'
    The contents of file "$events" should equal fetch
    Assert [ ! -e "$fixture/fetch-fail" ]
    Assert [ -z "$(git_fixture -C "$primary" branch --list 'adr/42-tools')" ]
  End

  It 'force-removes a dirty worktree and preserves the tool initialization status'
    add_origin || return 1
    export WB_INIT_DIRTY=1 WB_INIT_RC=17
    When run sh -c 'cd "$1" && exec sh "$2" adr 43 tools --worktree --base HEAD --path "$3"' _ "$primary" "$script_abs" "$fixture/init-fail"
    The status should equal 17
    The output should equal ''
    The stderr should include 'tool initialization failure'
    The contents of file "$events" should equal "$(printf 'fetch\nwt\ninit:%s/init-fail' "$fixture")"
    Assert [ ! -e "$fixture/init-fail" ]
    Assert [ -z "$(git_fixture -C "$primary" branch --list 'adr/43-tools')" ]
  End

  It 'falls back to git worktree add when wt fails'
    add_origin || return 1
    export WB_WT_RC=1
    When run sh -c 'cd "$1" && exec sh "$2" adr 55 wtfail --worktree --base HEAD --path "$3"' _ "$primary" "$script_abs" "$fixture/wt-fail"
    The status should equal 0
    The output should equal "$(printf 'adr/55-wtfail\t%s/wt-fail' "$fixture")"
    The stderr should include 'wt could not cut'
    The contents of file "$events" should equal "$(printf 'fetch\nwt\nadd\ninit:%s/wt-fail' "$fixture")"
    The path "$fixture/wt-fail" should be directory
  End

  It 'falls back when wt reports success without leaving a worktree'
    add_origin || return 1
    export WB_WT_EMPTY=1
    When run sh -c 'cd "$1" && exec sh "$2" adr 56 wtempty --worktree --base HEAD --path "$3"' _ "$primary" "$script_abs" "$fixture/wt-empty"
    The status should equal 0
    The output should equal "$(printf 'adr/56-wtempty\t%s/wt-empty' "$fixture")"
    The stderr should include 'wt could not cut'
    The contents of file "$events" should equal "$(printf 'fetch\nwt\nadd\ninit:%s/wt-empty' "$fixture")"
    The path "$fixture/wt-empty" should be directory
  End

  It 'does not re-initialize a worktree wt already initialized through its pre-start hook'
    add_origin || return 1
    export WB_WT_PRESTART=1
    When run sh -c 'cd "$1" && exec sh "$2" adr 57 prestart --worktree --base HEAD --path "$3"' _ "$primary" "$script_abs" "$fixture/wt-prestart"
    The status should equal 0
    The stderr should include 'Preparing worktree'
    The output should equal "$(printf 'adr/57-prestart\t%s/wt-prestart' "$fixture")"
    The contents of file "$events" should equal "$(printf 'fetch\nwt')"
    Assert [ -f "$fixture/wt-prestart/.codegraph/codegraph.db" ]
  End
End

Describe 'work-branch.sh --worktree sibling placement'
  # rc-mode / managed sessions run inside a linked session worktree; every
  # implicit path must land beside the primary repository, never inside it.
  script_abs="${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/work-branch.sh"

  setup() {
    # Under a git hook, exported GIT_DIR/GIT_INDEX_FILE would aim the fixture's
    # nested git calls at the hook's repo (see scripts/lib/git-env-scrub.sh).
    . "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/lib/git-env-scrub.sh"
    pfb_scrub_git_env
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/wb_spec.XXXXXX") || return 1
    fixture=$(cd "$fixture" && pwd -P) || return 1
    primary="$fixture/primary repo"
    worktree_root="$fixture/.primary repo_worktrees"
    git_fixture init -q "$primary" &&
      git_fixture -C "$primary" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
        commit -q --allow-empty -m init &&
      git_fixture -C "$primary" worktree add -q --detach "$fixture/session" >/dev/null 2>&1 || return 1
    # Claim gate stub: `gh` answers from WB_ASSIGNEES (comma list, default: the
    # caller) and WB_ME; WB_GH_RC makes every gh call fail; every call is logged.
    stubdir="$fixture/bin"; mkdir -p "$stubdir"
    gh_log="$fixture/gh.log"
    cat > "$stubdir/gh" <<'GH'
#!/bin/sh
printf '%s\n' "$*" >> "$WB_GH_LOG"
[ "${WB_GH_RC:-0}" -eq 0 ] || exit "$WB_GH_RC"
case "$*" in
  "api user --jq .login") printf '%s\n' "${WB_ME:-me}" ;;
  "issue view "*"--json assignees"*) printf '%s\n' "${WB_ASSIGNEES-me}" ;;
  "issue edit "*"--add-assignee @me"*) : ;;
  *) echo "gh stub: unexpected argv: $*" >&2; exit 9 ;;
esac
GH
    chmod +x "$stubdir/gh"
    cat > "$stubdir/date" <<'DATE'
#!/bin/sh
printf '%s\n' 1700000000
DATE
    chmod +x "$stubdir/date"
    export WB_GH_LOG="$gh_log"
    codegraph_log="$fixture/codegraph.log"
    cat > "$stubdir/codegraph" <<'CODEGRAPH'
#!/bin/sh
[ "${WB_CODEGRAPH_RC:-0}" -eq 0 ] || exit "$WB_CODEGRAPH_RC"
case "$1" in
  init|index)
    printf '%s\n' "$*" >> "$WB_CODEGRAPH_LOG"
    mkdir -p "$2/.codegraph"
    true > "$2/.codegraph/codegraph.db"
    ;;
  status)
    printf '%s\n' '{"initialized":true,"worktreeMismatch":null,"index":{"reindexRecommended":false,"state":"complete","pendingRefs":0}}'
    ;;
  *) exit 9 ;;
esac
CODEGRAPH
    chmod +x "$stubdir/codegraph"
    export WB_CODEGRAPH_LOG="$codegraph_log"
    cat > "$stubdir/init-worktree-tools" <<'INIT'
#!/bin/sh
printf 'init %s\n' "$1" >> "$WB_CODEGRAPH_LOG"
mkdir -p "$1/.codegraph"
true > "$1/.codegraph/codegraph.db"
INIT
    chmod +x "$stubdir/init-worktree-tools"
    # Hermetic `wt`: the spec must exercise work-branch.sh, never the host's wt.
    cat > "$stubdir/wt" <<'WT'
#!/bin/sh
wt_path=''
wt_branch=''
while [ "$#" -gt 0 ]; do
  case $1 in
    --config-set)
      wt_path=${2#worktree-path=\"}
      wt_path=${wt_path%\"}
      shift 2
      ;;
    switch)
      shift
      wt_branch=${1:-}
      [ "$#" -eq 0 ] || shift
      ;;
    *) shift ;;
  esac
done
exec git worktree add "$wt_path" "$wt_branch"
WT
    chmod +x "$stubdir/wt"
    export PFB_INIT_WORKTREE_TOOLS="$stubdir/init-worktree-tools"
    PATH="$stubdir:$PATH"; export PATH
  }
  cleanup() {
    unset PFB_INIT_WORKTREE_TOOLS
    rm -rf "$fixture"
  }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'creates the sibling root for a repository name containing spaces'
    When run sh -c 'cd "$1" && CODEX_THREAD_ID= exec sh "$2" issue 7 tld --worktree --base HEAD' _ "$fixture/session" "$script_abs"
    The status should equal 0
    The output should equal "$(printf 'issue/7-tld\t%s/issue-7-tld' "$worktree_root")"
    The output should not include "$primary/"
    The stderr should include 'Preparing worktree'
    The path "$worktree_root" should be directory
  End

  It 'uses the same sibling root when Codex variables are set'
    When run sh -c 'cd "$1" && CODEX_THREAD_ID=thread TMPDIR="$3" exec sh "$2" issue 7 tld --worktree --base HEAD' _ "$fixture/session" "$script_abs" "$fixture"
    The status should equal 0
    The output should equal "$(printf 'issue/7-tld\t%s/issue-7-tld' "$worktree_root")"
    The output should not include "$primary/"
    The output should not include "$fixture/pfblockerng-issue-7"
    The stderr should include 'Preparing worktree'
    The contents of file "$codegraph_log" should equal "init $worktree_root/issue-7-tld"
    Assert [ -f "$worktree_root/issue-7-tld/.codegraph/codegraph.db" ]
  End

  It 'anchors a relative --path beneath the sibling root'
    When run sh -c 'cd "$1" && exec sh "$2" issue 8 tld --worktree --base HEAD --path wt/x' _ "$fixture/session" "$script_abs"
    The status should equal 0
    The output should equal "$(printf 'issue/8-tld\t%s/wt/x' "$worktree_root")"
    The output should not include "$primary/"
    The stderr should include 'Preparing worktree'
  End

  It 'rejects a parent-traversing relative --path before creating a branch or worktree'
    When run sh -c 'cd "$1" && exec sh "$2" adr 45 escape --worktree --base HEAD --path ../escape' _ "$fixture/session" "$script_abs"
    The status should equal 2
    The stderr should include "must not contain a '..' component"
    Assert [ ! -e "$fixture/escape" ]
    Assert [ -z "$(git_fixture -C "$primary" branch --list 'adr/45-escape')" ]
  End

  It 'rejects dot as a relative --path before creating a branch or worktree'
    When run sh -c 'cd "$1" && exec sh "$2" adr 46 dot --worktree --base HEAD --path .' _ "$fixture/session" "$script_abs"
    The status should equal 2
    The stderr should include "must not be '.'"
    Assert [ ! -e "$worktree_root" ]
    Assert [ -z "$(git_fixture -C "$primary" branch --list 'adr/46-dot')" ]
  End

  It 'rejects a relative --path whose parent symlink escapes the sibling root'
    mkdir -p "$worktree_root" "$fixture/outside"
    ln -s "$fixture/outside" "$worktree_root/link"
    When run sh -c 'cd "$1" && exec sh "$2" adr 47 symlink --worktree --base HEAD --path link/worktree' _ "$fixture/session" "$script_abs"
    The status should equal 2
    The stderr should include 'escapes sibling root'
    Assert [ ! -e "$fixture/outside/worktree" ]
    Assert [ -z "$(git_fixture -C "$primary" branch --list 'adr/47-symlink')" ]
  End

  It 'rejects a symlink at the derived sibling root'
    mkdir -p "$fixture/outside-root"
    ln -s "$fixture/outside-root" "$worktree_root"
    When run sh -c 'cd "$1" && exec sh "$2" adr 51 root-symlink --worktree --base HEAD' _ "$fixture/session" "$script_abs"
    The status should equal 2
    The stderr should include 'sibling root must not be a symlink'
    Assert [ ! -e "$fixture/outside-root/adr-51-root-symlink" ]
    Assert [ -z "$(git_fixture -C "$primary" branch --list 'adr/51-root-symlink')" ]
  End

  It 'uses sibling placement from the primary checkout too'
    When run sh -c 'cd "$1" && CODEX_THREAD_ID= exec sh "$2" issue 9 tld --worktree --base HEAD' _ "$primary" "$script_abs"
    The status should equal 0
    The output should equal "$(printf 'issue/9-tld\t%s/issue-9-tld' "$worktree_root")"
    The output should not include "$primary/"
    The stderr should include 'Preparing worktree'
  End

  It 'is immune to an inherited CDPATH when resolving the sibling root'
    # A CDPATH hit makes cd echo the destination AND resolve relative to the
    # CDPATH entry instead of $PWD — either corrupts the derived root.
    When run sh -c 'mkdir -p "$3/.git" && cd "$1" && CODEX_THREAD_ID= CDPATH=$3 exec sh "$2" issue 10 tld --worktree --base HEAD' _ "$primary" "$script_abs" "$fixture/decoy"
    The status should equal 0
    The output should equal "$(printf 'issue/10-tld\t%s/issue-10-tld' "$worktree_root")"
    The output should not include "$primary/"
    The stderr should include 'Preparing worktree'
  End

  It 'uses the suffixed branch name for a colliding default worktree'
    git_fixture -C "$primary" branch issue/14-tld
    When run sh -c 'cd "$1" && exec sh "$2" issue 14 tld --worktree --base HEAD' _ "$fixture/session" "$script_abs"
    The status should equal 0
    The output should equal "$(printf 'issue/14-tld-1700000000\t%s/issue-14-tld-1700000000' "$worktree_root")"
    The output should not include "$primary/"
    The stderr should include 'Preparing worktree'
  End

  It 'advances past repeated deterministic branch collisions'
    git_fixture -C "$primary" branch adr/48-collide
    git_fixture -C "$primary" branch adr/48-collide-1700000000
    When run sh -c 'cd "$1" && exec sh "$2" adr 48 collide --worktree --base HEAD' _ "$fixture/session" "$script_abs"
    The status should equal 0
    The stderr should include 'Preparing worktree'
    The output should equal "$(printf 'adr/48-collide-1700000000-2\t%s/adr-48-collide-1700000000-2' "$worktree_root")"
    The path "$worktree_root/adr-48-collide-1700000000-2" should be directory
  End

  It 'atomically gives synchronized creators distinct branches and default paths'
    race_dir="$fixture/race"
    mkdir -p "$race_dir"
    mkfifo "$race_dir/ready-one" "$race_dir/ready-two" "$race_dir/release-one" "$race_dir/release-two"
    When run sh -c '
      (
        printf "ready\n" > "$3/ready-one"
        IFS= read -r _ < "$3/release-one"
        cd "$1" || exit 125
        exec sh "$2" adr 49 race --worktree --base HEAD
      ) > "$3/one.out" 2> "$3/one.err" &
      one=$!
      (
        printf "ready\n" > "$3/ready-two"
        IFS= read -r _ < "$3/release-two"
        cd "$1" || exit 125
        exec sh "$2" adr 49 race --worktree --base HEAD
      ) > "$3/two.out" 2> "$3/two.err" &
      two=$!
      IFS= read -r _ < "$3/ready-one"
      IFS= read -r _ < "$3/ready-two"
      printf "go\n" > "$3/release-one"
      printf "go\n" > "$3/release-two"
      wait "$one"; one_rc=$?
      wait "$two"; two_rc=$?
      LC_ALL=C sort "$3/one.out" "$3/two.out" > "$3/results"
      printf "%s %s\n" "$one_rc" "$two_rc"
      [ "$one_rc" -eq 0 ] && [ "$two_rc" -eq 0 ]
    ' _ "$fixture/session" "$script_abs" "$race_dir"
    The status should equal 0
    The output should equal '0 0'
    The contents of file "$race_dir/results" should equal "$(printf 'adr/49-race\t%s/adr-49-race\nadr/49-race-1700000000\t%s/adr-49-race-1700000000' "$worktree_root" "$worktree_root")"
    The path "$worktree_root/adr-49-race" should be directory
    The path "$worktree_root/adr-49-race-1700000000" should be directory
  End

  It 'atomically suffixes synchronized creators sharing an explicit relative path'
    race_dir="$fixture/relative-race"
    mkdir -p "$race_dir"
    mkfifo "$race_dir/ready-one" "$race_dir/ready-two" "$race_dir/release-one" "$race_dir/release-two"
    When run sh -c '
      (
        printf "ready\n" > "$3/ready-one"
        IFS= read -r _ < "$3/release-one"
        cd "$1" || exit 125
        exec sh "$2" adr 54 relative-race --worktree --base HEAD --path shared
      ) > "$3/one.out" 2> "$3/one.err" &
      one=$!
      (
        printf "ready\n" > "$3/ready-two"
        IFS= read -r _ < "$3/release-two"
        cd "$1" || exit 125
        exec sh "$2" adr 54 relative-race --worktree --base HEAD --path shared
      ) > "$3/two.out" 2> "$3/two.err" &
      two=$!
      IFS= read -r _ < "$3/ready-one"
      IFS= read -r _ < "$3/ready-two"
      printf "go\n" > "$3/release-one"
      printf "go\n" > "$3/release-two"
      wait "$one"; one_rc=$?
      wait "$two"; two_rc=$?
      LC_ALL=C sort "$3/one.out" "$3/two.out" > "$3/results"
      printf "%s %s\n" "$one_rc" "$two_rc"
      [ "$one_rc" -eq 0 ] && [ "$two_rc" -eq 0 ]
    ' _ "$fixture/session" "$script_abs" "$race_dir"
    The status should equal 0
    The output should equal '0 0'
    The contents of file "$race_dir/results" should equal "$(printf 'adr/54-relative-race\t%s/shared\nadr/54-relative-race-1700000000\t%s/shared-1700000000' "$worktree_root" "$worktree_root")"
    The path "$worktree_root/shared" should be directory
    The path "$worktree_root/shared-1700000000" should be directory
  End

  It 'refuses a --separate-git-dir layout instead of anchoring outside the checkout'
    git_fixture init -q --separate-git-dir "$fixture/gitmeta" "$fixture/sep" &&
      git_fixture -C "$fixture/sep" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
        commit -q --allow-empty -m init
    When run sh -c 'cd "$1/sep" && exec sh "$2" issue 11 tld --worktree --base HEAD' _ "$fixture" "$script_abs"
    The status should equal 2
    The stderr should include 'separate-git-dir'
  End

  It 'leaves an absolute --path untouched when run from a linked worktree'
    When run sh -c 'cd "$1" && exec sh "$2" issue 12 tld --worktree --base HEAD --path "$3"' _ "$fixture/session" "$script_abs" "$fixture/abs-target"
    The status should equal 0
    The output should equal "$(printf 'issue/12-tld\t%s/abs-target' "$fixture")"
    The stderr should include 'Preparing worktree'
  End

  It 'fails an occupied explicit absolute --path without suffixing or leaking a branch'
    mkdir -p "$fixture/occupied"
    printf 'keep\n' > "$fixture/occupied/marker"
    When run sh -c 'cd "$1" && exec sh "$2" adr 50 occupied --worktree --base HEAD --path "$3"' _ "$fixture/session" "$script_abs" "$fixture/occupied"
    The status should equal 2
    The stderr should include 'is occupied'
    The contents of file "$fixture/occupied/marker" should equal keep
    Assert [ ! -e "$fixture/occupied-1700000000" ]
    Assert [ -z "$(git_fixture -C "$primary" branch --list 'adr/50-occupied*')" ]
  End

  It 'treats a leading-dash --base as a ref without deleting the reserved branch'
    git_fixture -C "$primary" branch adr/52-base-option
    When run sh -c 'cd "$1" && exec sh "$2" adr 52 base-option --worktree --base -D --path "$3"' _ "$fixture/session" "$script_abs" "$fixture/base-option"
    The stderr should include 'could not reserve branch'
    The status should not equal 0
    Assert [ -n "$(git_fixture -C "$primary" branch --list 'adr/52-base-option')" ]
    Assert [ ! -e "$fixture/base-option" ]
  End

  It 'advances the branch when only its default worktree path is occupied'
    mkdir -p "$worktree_root/adr-53-path-only"
    When run sh -c 'cd "$1" && exec sh "$2" adr 53 path-only --worktree --base HEAD' _ "$fixture/session" "$script_abs"
    The stderr should include 'Preparing worktree'
    The status should equal 0
    The output should equal "$(printf 'adr/53-path-only-1700000000\t%s/adr-53-path-only-1700000000' "$worktree_root")"
    The path "$worktree_root/adr-53-path-only-1700000000" should be directory
  End

  It 'keeps worktree creation without a configured origin'
    When run sh -c 'cd "$1" && exec sh "$2" issue 13 tld --worktree --base HEAD --path "$3"' _ "$fixture/session" "$script_abs" "$fixture/offline"
    The status should equal 0
    The output should equal "$(printf 'issue/13-tld\t%s/offline' "$fixture")"
    The stderr should include 'Preparing worktree'
    Assert [ -f "$fixture/offline/.codegraph/codegraph.db" ]
  End
End

Describe 'work-branch.sh --worktree claim gate (workflow.md "Claim")'
  # The assignee IS the claim, set before any work: an issue worktree is refused
  # unless the issue is assigned to the caller; --claim assigns an unclaimed one.
  script_abs="${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/work-branch.sh"

  setup() {
    . "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/lib/git-env-scrub.sh"
    pfb_scrub_git_env
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/wb_claim.XXXXXX") || return 1
    fixture=$(cd "$fixture" && pwd -P) || return 1
    primary="$fixture/primary"
    worktree_root="$fixture/.primary_worktrees"
    git_fixture init -q "$primary" &&
      git_fixture -C "$primary" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
        commit -q --allow-empty -m init || return 1
    stubdir="$fixture/bin"; mkdir -p "$stubdir"
    gh_log="$fixture/gh.log"
    cat > "$stubdir/gh" <<'GH'
#!/bin/sh
printf '%s\n' "$*" >> "$WB_GH_LOG"
[ "${WB_GH_RC:-0}" -eq 0 ] || exit "$WB_GH_RC"
case "$*" in
  "api user --jq .login") printf '%s\n' "${WB_ME:-me}" ;;
  "issue view "*"--json assignees"*) printf '%s\n' "${WB_ASSIGNEES-me}" ;;
  "issue edit "*"--add-assignee @me"*) : ;;
  *) echo "gh stub: unexpected argv: $*" >&2; exit 9 ;;
esac
GH
    chmod +x "$stubdir/gh"
    export WB_GH_LOG="$gh_log"
    codegraph_dir="$fixture/codegraph-bin"; mkdir -p "$codegraph_dir"
    codegraph_log="$fixture/codegraph.log"
    cat > "$codegraph_dir/codegraph" <<'CODEGRAPH'
#!/bin/sh
case "$1" in
  init|index)
    printf '%s\n' "$*" >> "$WB_CODEGRAPH_LOG"
    mkdir -p "$2/.codegraph"
    true > "$2/.codegraph/codegraph.db"
    ;;
  status)
    printf '%s\n' '{"initialized":true,"worktreeMismatch":null,"index":{"reindexRecommended":false,"state":"complete","pendingRefs":0}}'
    ;;
  *) exit 9 ;;
esac
CODEGRAPH
    chmod +x "$codegraph_dir/codegraph"
    export WB_CODEGRAPH_LOG="$codegraph_log"
    cat > "$stubdir/init-worktree-tools" <<'INIT'
#!/bin/sh
exit 0
INIT
    chmod +x "$stubdir/init-worktree-tools"
    # Hermetic `wt`: the spec must exercise work-branch.sh, never the host's wt.
    cat > "$stubdir/wt" <<'WT'
#!/bin/sh
wt_path=''
wt_branch=''
while [ "$#" -gt 0 ]; do
  case $1 in
    --config-set)
      wt_path=${2#worktree-path=\"}
      wt_path=${wt_path%\"}
      shift 2
      ;;
    switch)
      shift
      wt_branch=${1:-}
      [ "$#" -eq 0 ] || shift
      ;;
    *) shift ;;
  esac
done
exec git worktree add "$wt_path" "$wt_branch"
WT
    chmod +x "$stubdir/wt"
    export PFB_INIT_WORKTREE_TOOLS="$stubdir/init-worktree-tools"
    PATH="$stubdir:$codegraph_dir:$PATH"; export PATH
  }
  cleanup() {
    unset PFB_INIT_WORKTREE_TOOLS
    rm -rf "$fixture"
  }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'refuses to cut an issue worktree when the issue is unassigned'
    When run sh -c 'cd "$1" && WB_ASSIGNEES= exec sh "$2" issue 7 tld --worktree --base HEAD' _ "$primary" "$script_abs"
    The status should equal 3
    The stderr should include 'issue #7 is not claimed'
    The stderr should include '--claim'
    Assert [ ! -e "$worktree_root/issue-7-tld" ]
  End

  It 'refuses to cut an issue worktree claimed by someone else'
    When run sh -c 'cd "$1" && WB_ASSIGNEES=other exec sh "$2" issue 7 tld --worktree --base HEAD' _ "$primary" "$script_abs"
    The status should equal 3
    The stderr should include 'claimed by other'
    Assert [ ! -e "$worktree_root/issue-7-tld" ]
  End

  It 'proceeds when the issue is assigned to the caller (among others)'
    When run sh -c 'cd "$1" && WB_ASSIGNEES=other,me exec sh "$2" issue 7 tld --worktree --base HEAD' _ "$primary" "$script_abs"
    The status should equal 0
    The output should equal "$(printf 'issue/7-tld\t%s/issue-7-tld' "$worktree_root")"
    The stderr should include 'Preparing worktree'
  End

  It '--claim assigns an unclaimed issue to the caller and proceeds'
    When run sh -c 'cd "$1" && WB_ASSIGNEES= exec sh "$2" issue 7 tld --worktree --base HEAD --claim' _ "$primary" "$script_abs"
    The status should equal 0
    The output should equal "$(printf 'issue/7-tld\t%s/issue-7-tld' "$worktree_root")"
    The stderr should include 'Preparing worktree'
    The contents of file "$gh_log" should include 'issue edit 7 --add-assignee @me'
  End

  It '--claim still refuses an issue claimed by someone else'
    When run sh -c 'cd "$1" && WB_ASSIGNEES=other exec sh "$2" issue 7 tld --worktree --base HEAD --claim' _ "$primary" "$script_abs"
    The status should equal 3
    The stderr should include 'claimed by other'
    The contents of file "$gh_log" should not include 'issue edit'
  End

  It 'warns and proceeds when gh cannot answer (MCP-only or offline sessions verify the claim themselves)'
    When run sh -c 'cd "$1" && WB_GH_RC=1 exec sh "$2" issue 7 tld --worktree --base HEAD' _ "$primary" "$script_abs"
    The status should equal 0
    The output should equal "$(printf 'issue/7-tld\t%s/issue-7-tld' "$worktree_root")"
    The stderr should include 'claim NOT verified'
    The stderr should include 'issue #7'
  End

  It 'warns and proceeds when gh is not installed at all'
    When run sh -c 'cd "$1" && PATH="$4:$3" exec sh "$2" issue 7 tld --worktree --base HEAD' _ "$primary" "$script_abs" "$(dirname "$(command -v git)"):/usr/bin:/bin" "$codegraph_dir"
    The status should equal 0
    The output should equal "$(printf 'issue/7-tld\t%s/issue-7-tld' "$worktree_root")"
    The stderr should include 'claim NOT verified'
  End

  It 'does not gate ADR worktrees on a claim'
    When run sh -c 'cd "$1" && WB_GH_RC=1 exec sh "$2" adr 9 x --worktree --base HEAD' _ "$primary" "$script_abs"
    The status should equal 0
    The output should equal "$(printf 'adr/9-x\t%s/adr-9-x' "$worktree_root")"
    The stderr should include 'Preparing worktree'
    Assert [ ! -e "$gh_log" ]
  End

  It 'does not touch gh when only printing the branch name'
    When run sh -c 'cd "$1" && WB_GH_RC=1 exec sh "$2" issue 7 tld' _ "$primary" "$script_abs"
    The status should equal 0
    The output should equal 'issue/7-tld'
    Assert [ ! -e "$gh_log" ]
  End
End

Describe 'work-branch.sh slugify() truncation edges'
  # shellcheck disable=SC2034 # consumed by the Included script's source-only guard
  AGENT_SOURCE_ONLY=1
  Include scripts/agent/work-branch.sh

  It 'keeps a single over-long token cut at 30 characters (no boundary exists)'
    When call slugify "abcdefghijklmnopqrstuvwxyzabcdefghij"
    The output should equal 'abcdefghijklmnopqrstuvwxyzabcd'
  End

  It 'drops a token that straddles the 30-character cut'
    When call slugify "ip-recompute-a-priority-reorder"
    The output should equal 'ip-recompute-a-priority'
  End

  It 'keeps a token whose end lands exactly on the 30-character cut'
    When call slugify "aaaaaaaaaa-bbbbbbbbbb-cccccccc-ddd"
    The output should equal 'aaaaaaaaaa-bbbbbbbbbb-cccccccc'
  End
End

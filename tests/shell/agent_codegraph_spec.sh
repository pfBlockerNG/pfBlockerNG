#shellcheck shell=sh
# Client-neutral CodeGraph bootstrap and worktree wiring.

Describe 'ensure-codegraph.sh exact-root initialization'
  script_abs="${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/ensure-codegraph.sh"

  setup() {
    . "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/lib/git-env-scrub.sh"
    pfb_scrub_git_env
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/codegraph_spec.XXXXXX") || return 1
    fixture=$(cd "$fixture" && pwd -P) || return 1
    primary="$fixture/primary"
    git_fixture init -q "$primary" &&
      git_fixture -C "$primary" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
        commit -q --allow-empty -m init || return 1
    stubdir="$fixture/bin"; mkdir -p "$stubdir"
    codegraph_log="$fixture/codegraph.log"
    cat > "$stubdir/codegraph" <<'CODEGRAPH'
#!/bin/sh
[ "${CODEGRAPH_RC:-0}" -eq 0 ] || exit "$CODEGRAPH_RC"
case "$1" in
  init|index)
    printf '%s\n' "$*" >> "$CODEGRAPH_LOG"
    if [ "${CODEGRAPH_CREATE_DB:-1}" -eq 1 ]; then
      mkdir -p "$2/.codegraph"
      true > "$2/.codegraph/codegraph.db"
    fi
    ;;
  status)
    printf '%s\n' '{"initialized":true,"worktreeMismatch":null,"index":{"reindexRecommended":false,"state":"complete","pendingRefs":0}}'
    ;;
  *) exit 9 ;;
esac
CODEGRAPH
    chmod +x "$stubdir/codegraph"
    export CODEGRAPH_LOG="$codegraph_log"
    PATH="$stubdir:$PATH"; export PATH
  }
  cleanup() { rm -rf "$fixture"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'initializes the exact checkout root when its database is absent'
    When run sh "$script_abs" "$primary"
    The status should equal 0
    The stderr should include 'Initializing CodeGraph'
    The contents of file "$codegraph_log" should equal "init $primary"
    Assert [ -f "$primary/.codegraph/codegraph.db" ]
  End

  It 'does not reinitialize an exact-root database'
    mkdir -p "$primary/.codegraph"
    true > "$primary/.codegraph/codegraph.db"
    When run sh "$script_abs" "$primary"
    The status should equal 0
    The file "$codegraph_log" should not be exist
  End

  It 'does not accept a parent checkout index for a nested linked worktree'
    mkdir -p "$primary/.codegraph"
    true > "$primary/.codegraph/codegraph.db"
    git_fixture -C "$primary" worktree add -q --detach "$primary/.claude/worktrees/child" HEAD
    child="$primary/.claude/worktrees/child"
    When run sh "$script_abs" "$child"
    The status should equal 0
    The stderr should include 'Initializing CodeGraph'
    The contents of file "$codegraph_log" should equal "init $child"
    Assert [ -f "$child/.codegraph/codegraph.db" ]
  End

  It 'fails when CodeGraph reports success without creating its database'
    When run env CODEGRAPH_CREATE_DB=0 sh "$script_abs" "$primary"
    The status should equal 1
    The stderr should include 'reported success without creating'
  End
End

Describe 'work-branch.sh cross-client CodeGraph initialization'
  script_abs="${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/work-branch.sh"

  setup() {
    . "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/lib/git-env-scrub.sh"
    pfb_scrub_git_env
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/codegraph_client.XXXXXX") || return 1
    fixture=$(cd "$fixture" && pwd -P) || return 1
    primary="$fixture/primary"
    git_fixture init -q "$primary" &&
      git_fixture -C "$primary" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
        commit -q --allow-empty -m init || return 1
    stubdir="$fixture/bin"; mkdir -p "$stubdir"
    codegraph_log="$fixture/codegraph.log"
    cat > "$stubdir/codegraph" <<'CODEGRAPH'
#!/bin/sh
[ "${CODEGRAPH_RC:-0}" -eq 0 ] || exit "$CODEGRAPH_RC"
case "$1" in
  init|index)
    printf '%s\n' "$*" >> "$CODEGRAPH_LOG"
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
  *os.path.dirname*) printf '%s\n' "$CODEGRAPH_GRAPHIFY_PACKAGE"; exit 0 ;;
  *activate_language_overrides*) exit 0 ;;
esac
exec sh "$@"
INTERPRETER
    chmod +x "$interpreter"
    printf '#!%s\n' "$interpreter" > "$stubdir/graphify"
    cat >> "$stubdir/graphify" <<'GRAPHIFY'
[ "$#" -eq 3 ] && [ "$1" = extract ] && [ "$3" = --code-only ] || exit 9
mkdir -p "$2/graphify-out"
true > "$2/graphify-out/graph.json"
GRAPHIFY
    cat > "$stubdir/serena" <<'SERENA'
#!/bin/sh
[ "$#" -eq 3 ] && [ "$1" = project ] && [ "$2" = index ] || exit 9
exit 0
SERENA
    # Hermetic `wt`: work-branch.sh cuts through wt, and this spec must exercise
    # work-branch.sh on every host — with or without Worktrunk installed.
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
    chmod +x "$stubdir/codegraph" "$stubdir/graphify" "$stubdir/serena"
    export CODEGRAPH_LOG="$codegraph_log" CODEGRAPH_GRAPHIFY_PACKAGE="$graphify_package"
    PATH="$stubdir:$PATH"; export PATH
  }
  cleanup() { rm -rf "$fixture"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  create_marked_worktree() {
    marker=$1
    target="$fixture/agent-worktree"
    cd "$primary" || return 1
    env CLAUDECODE= CODEX_THREAD_ID= COPILOT_CLI= COPILOT_AGENT_PROMPT= \
        GROK_SESSION_ID= GROK_AGENT= "$marker=1" \
        sh "$script_abs" adr 9 codegraph --worktree --base HEAD --path "$target"
  }

  create_unmarked_worktree() {
    target="$fixture/agent-worktree"
    cd "$primary" || return 1
    env CLAUDECODE= CODEX_THREAD_ID= COPILOT_CLI= COPILOT_AGENT_PROMPT= \
        GROK_SESSION_ID= GROK_AGENT= \
        sh "$script_abs" adr 9 codegraph --worktree --base HEAD --path "$target"
  }

  fail_divergent_worktree() {
    base_branch=$(git_fixture -C "$primary" branch --show-current) || return 1
    git_fixture -C "$primary" switch -q -c divergent &&
      git_fixture -C "$primary" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
        commit -q --allow-empty -m divergent &&
      git_fixture -C "$primary" switch -q "$base_branch" || return 1
    target="$fixture/divergent-worktree"
    cd "$primary" || return 1
    CODEGRAPH_RC=7 sh "$script_abs" adr 10 codegraph --worktree --base divergent --path "$target"
  }

  It 'initializes a new worktree without relying on a client marker'
    When call create_unmarked_worktree
    The status should equal 0
    The output should equal "$(printf 'adr/9-codegraph\t%s/agent-worktree' "$fixture")"
    The stderr should include 'Preparing worktree'
    The contents of file "$codegraph_log" should equal "init $fixture/agent-worktree"
    Assert [ -f "$fixture/agent-worktree/.codegraph/codegraph.db" ]
  End

  It 'fails loudly when worktree CodeGraph initialization fails'
    export CODEGRAPH_RC=7
    When call create_unmarked_worktree
    The status should equal 1
    The output should equal ''
    The stderr should include 'CodeGraph initialization failed'
    Assert [ ! -e "$fixture/agent-worktree" ]
    Assert [ ! -f "$primary/.git/refs/heads/adr/9-codegraph" ]
    Assert [ ! -f "$fixture/agent-worktree/.codegraph/codegraph.db" ]
  End

  It 'removes the new branch after failure from a divergent base'
    When call fail_divergent_worktree
    The status should equal 1
    The output should equal ''
    The stderr should include 'CodeGraph initialization failed'
    Assert [ ! -e "$fixture/divergent-worktree" ]
    Assert [ ! -f "$primary/.git/refs/heads/adr/10-codegraph" ]
  End

  Parameters
    'CLAUDECODE'
    'CODEX_THREAD_ID'
    'COPILOT_CLI'
    'COPILOT_AGENT_PROMPT'
    'GROK_SESSION_ID'
    'GROK_AGENT'
  End

  It "initializes a new worktree for agent marker $1"
    When call create_marked_worktree "$1"
    The status should equal 0
    The output should equal "$(printf 'adr/9-codegraph\t%s/agent-worktree' "$fixture")"
    The stderr should include 'Preparing worktree'
    The contents of file "$codegraph_log" should equal "init $fixture/agent-worktree"
    Assert [ -f "$fixture/agent-worktree/.codegraph/codegraph.db" ]
  End
End

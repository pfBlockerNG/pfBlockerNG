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
printf '%s\n' "$*" >> "$CODEGRAPH_LOG"
[ "${CODEGRAPH_RC:-0}" -eq 0 ] || exit "$CODEGRAPH_RC"
[ "$1" = init ] || exit 9
if [ "${CODEGRAPH_CREATE_DB:-1}" -eq 1 ]; then
  mkdir -p "$2/.codegraph"
  true > "$2/.codegraph/codegraph.db"
fi
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
printf '%s\n' "$*" >> "$CODEGRAPH_LOG"
mkdir -p "$2/.codegraph"
true > "$2/.codegraph/codegraph.db"
CODEGRAPH
    chmod +x "$stubdir/codegraph"
    export CODEGRAPH_LOG="$codegraph_log"
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

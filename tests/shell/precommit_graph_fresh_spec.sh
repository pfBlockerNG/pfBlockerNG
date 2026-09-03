#shellcheck shell=sh
# .githooks/pre-commit root-graph refresh (issue #3139): a commit that stages any
# path other than graphify-out/graph.json rebuilds graphify-out/graph.json in place
# through scripts/agent/check-graph-fresh.sh --refresh and stages the result, so the
# commit and its graph always agree. Only the graph itself staged, or nothing
# staged, rebuilds nothing; a tracked graphify-out/memory/ record IS a graph node,
# so it rebuilds. A rebase/merge/cherry-pick in progress changes nothing because
# the rebuild is synchronous. A failed or tool-less rebuild fails the commit like
# the Graphify patch step does; a tree that ships no checker opts out only through
# the committed .githooks-exempt manifest.
#
# Sandbox laid out like the repo, the other repo checkers exempted through the
# manifest and shellcheck/npx stubbed, so ONLY the graph step decides the verdict.

Describe '.githooks/pre-commit root-graph refresh (issue #3139)'
  gitc() { git_fixture -C "$repo" "$@"; }

  ALL_CHECKERS='scripts/check_noopener.py
scripts/check_appliance_python.py
scripts/check_version_literals.py
scripts/check_comment_narration.py
scripts/check_agent_roles.py
scripts/check_context_budget.py
scripts/check_composer_vendor.py
scripts/check_url_encoding.py
scripts/check_toggle_registry.py
scripts/check_reentry_bounds.py
scripts/agent/check-agent-config-parity.sh'

  make_repo() {
    scrub_git_env
    export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
    repo="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/precommit-graph.XXXXXX")"
    stubdir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/precommit-graph-stub.XXXXXX")"
    git_fixture -C "$repo" init -q
    gitc config user.name 'Andre Brait'
    gitc config user.email 'andrebrait@gmail.com'
    gitc config commit.gpgsign true
    gitc config gpg.format ssh
    true > "$repo/key.pub"
    gitc config user.signingkey "$repo/key.pub"
    mkdir -p "$repo/.githooks" "$repo/src" "$repo/scripts/agent" "$repo/tests" \
      "$repo/.claude/hooks" "$repo/graphify-out/memory"
    cp "$PFB_ROOT/.githooks/pre-commit" "$repo/.githooks/pre-commit"
    cp "$PFB_ROOT/.githooks/check-commit-identity.sh" "$repo/.githooks/"
    chmod +x "$repo/.githooks/check-commit-identity.sh"
    printf '#!/bin/sh\nexit 0\n' > "$repo/scripts/agent/patch-graphify.sh"
    check_log="$repo/check-graph-fresh.log"
    export GRAPH_CHECK_LOG="$check_log"
    cat > "$repo/scripts/agent/check-graph-fresh.sh" <<'CHECK'
#!/bin/sh
printf '%s\n' "$*" >> "$GRAPH_CHECK_LOG"
[ "${GRAPH_CHECK_RC:-0}" -eq 0 ] || exit "$GRAPH_CHECK_RC"
printf 'rebuilt graph\n' > graphify-out/graph.json
CHECK
    printf 'committed graph\n' > "$repo/graphify-out/graph.json"
    printf '%s\n' "$ALL_CHECKERS" > "$repo/.githooks-exempt"
    gitc add .githooks-exempt graphify-out/graph.json
    gitc -c commit.gpgsign=false commit -q -m seed --no-verify
    printf '#!/bin/sh\nexit 0\n' > "$repo/src/ok.sh"
    for tool in shellcheck npx; do
      printf '#!/bin/sh\nexit 0\n' > "$stubdir/$tool"
      chmod +x "$stubdir/$tool"
    done
    PATH="$stubdir:$PATH"
  }
  cleanup() {
    rm -rf "$repo" "$stubdir"
    unset GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GRAPH_CHECK_LOG GRAPH_CHECK_RC
  }
  Before 'make_repo'
  After 'cleanup'

  staged_graph() { gitc diff --cached --name-only -- graphify-out/graph.json; }

  It 'rebuilds the graph in place and stages it when a path outside graphify-out/ is staged'
    gitc add src/ok.sh
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 0
    The output should include '[pre-commit] graph freshness'
    The stderr should not include 'FAILED'
    The contents of file "$check_log" should equal '--refresh'
    The contents of file "$repo/graphify-out/graph.json" should equal 'rebuilt graph'
    The result of function staged_graph should equal 'graphify-out/graph.json'
  End

  It 'rebuilds nothing when only graphify-out/graph.json itself is staged'
    printf 'hand-refreshed graph\n' > "$repo/graphify-out/graph.json"
    gitc add graphify-out/graph.json
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 0
    The output should not include 'graph freshness'
    The file "$check_log" should not be exist
    The contents of file "$repo/graphify-out/graph.json" should equal 'hand-refreshed graph'
  End

  It 'rebuilds when only a graphify-out/memory/ record is staged: records are graph nodes'
    printf 'query record\n' > "$repo/graphify-out/memory/x.md"
    gitc add graphify-out/memory/x.md
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 0
    The output should include '[pre-commit] graph freshness'
    The contents of file "$check_log" should equal '--refresh'
    The result of function staged_graph should equal 'graphify-out/graph.json'
  End

  It 'rebuilds when the lone staged path merely SPLITS into graph.json lines: the guard is decided NUL-safe, never on a newline listing'
    hostile="$repo/graphify-out/graph.json
graphify-out/graph.json"
    mkdir -p "$(dirname "$hostile")"
    printf 'not the graph\n' > "$hostile"
    gitc add -- "graphify-out/graph.json
graphify-out/graph.json"
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 0
    The output should include '[pre-commit] graph freshness'
    The contents of file "$check_log" should equal '--refresh'
    The result of function staged_graph should equal 'graphify-out/graph.json'
  End

  It 'rebuilds nothing with an empty index'
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 0
    The output should not include 'graph freshness'
    The file "$check_log" should not be exist
  End

  Context 'commit inside an in-progress git operation'
    Parameters
      rebase-merge     dir
      rebase-apply     dir
      MERGE_HEAD       file
      CHERRY_PICK_HEAD file
    End

    It "still rebuilds and stages the graph with $1 present"
      case "$2" in
        dir) mkdir -p "$repo/.git/$1" ;;
        file) true > "$repo/.git/$1" ;;
      esac
      gitc add src/ok.sh
      When run sh -c "cd '$repo' && sh .githooks/pre-commit"
      The status should equal 0
      The output should include '[pre-commit] graph freshness'
      The contents of file "$check_log" should equal '--refresh'
      The result of function staged_graph should equal 'graphify-out/graph.json'
    End
  End

  It 'fails the commit when the rebuild fails'
    export GRAPH_CHECK_RC=1
    gitc add src/ok.sh
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 1
    The output should include '[pre-commit] graph freshness'
    The stderr should include '[pre-commit] FAILED: graph freshness'
    The contents of file "$check_log" should equal '--refresh'
    The result of function staged_graph should equal ''
  End

  It 'fails the commit when Graphify is missing (checker exit 4), like the patch step'
    export GRAPH_CHECK_RC=4
    gitc add src/ok.sh
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 1
    The stderr should include '[pre-commit] FAILED: graph freshness'
    The result of function staged_graph should equal ''
  End

  It 'hard-fails a tree that ships no checker and lists no exemption'
    rm -f "$repo/scripts/agent/check-graph-fresh.sh"
    gitc add src/ok.sh
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 1
    The output should include '[pre-commit] graph freshness'
    The stderr should include '[pre-commit] FAILED: graph freshness'
  End

  It 'exempts a tree that ships no checker only through the committed manifest'
    rm -f "$repo/scripts/agent/check-graph-fresh.sh"
    printf '%s\nscripts/agent/check-graph-fresh.sh\n' "$ALL_CHECKERS" > "$repo/.githooks-exempt"
    gitc add .githooks-exempt src/ok.sh
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 0
    The output should include 'listed in .githooks-exempt): graph freshness'
    The stderr should not include 'FAILED'
    The result of function staged_graph should equal ''
  End
End

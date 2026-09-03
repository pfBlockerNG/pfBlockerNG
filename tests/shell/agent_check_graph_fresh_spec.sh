#shellcheck shell=sh
# The tracked root graph must equal a rebuild of its tree (issue #3139). The
# checker rebuilds through the shared launcher under PYTHONHASHSEED=0, compares
# bytes, and never leaves the tree changed unless --refresh asked for the rebuilt
# graph. A stub `graphify` on PATH writes controllable bytes and records the seed
# it saw; the worktree path carries a space.

Describe 'check-graph-fresh.sh'
  script_abs="${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/check-graph-fresh.sh"

  setup() {
    . "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/lib/git-env-scrub.sh"
    pfb_scrub_git_env
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/check_graph_fresh.XXXXXX") || return 1
    fixture=$(cd "$fixture" && pwd -P) || return 1
    worktree="$fixture/worktree root"
    graph="$worktree/graphify-out/graph.json"
    git_fixture init -q "$worktree" || return 1
    mkdir -p "$worktree/graphify-out"
    printf 'committed graph\n' > "$graph"
    git_fixture -C "$worktree" add graphify-out/graph.json
    git_fixture -C "$worktree" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
      commit -q -m graph || return 1
    scratch="$fixture/scratch"
    mkdir -p "$scratch"
    stubdir="$fixture/bin"
    mkdir -p "$stubdir"
    graphify_log="$fixture/graphify.log"
    cat > "$stubdir/graphify" <<'GRAPHIFY'
#!/bin/sh
printf 'update:%s:hashseed=%s\n' "${2:-}" "${PYTHONHASHSEED:-unset}" >> "$GRAPHIFY_LOG"
[ "${1:-}" = update ] || exit 9
[ -z "${GRAPHIFY_STUB_GRAPH:-}" ] || printf '%s\n' "$GRAPHIFY_STUB_GRAPH" > "$2/graphify-out/graph.json"
[ -z "${GRAPHIFY_STUB_SIGNAL:-}" ] || kill -s "$GRAPHIFY_STUB_SIGNAL" "$PPID"
exit "${GRAPHIFY_RC:-0}"
GRAPHIFY
    chmod +x "$stubdir/graphify"
    # Neither graphify nor uv: the resolver has nothing to fall back to. And a
    # PATH with everything but cmp: the byte compare is mandatory too.
    no_graphify="$fixture/no-graphify"
    no_cmp="$fixture/no-cmp"
    mkdir -p "$no_graphify" "$no_cmp"
    for tool in sh dirname git mktemp cp cmp rm mkdir; do
      ln -s "$(command -v "$tool")" "$no_graphify/$tool"
      [ "$tool" = cmp ] || ln -s "$(command -v "$tool")" "$no_cmp/$tool"
    done
    ln -s "$stubdir/graphify" "$no_cmp/graphify"
    lock="$worktree/graphify-out/.check-graph-fresh.lock"
    export GRAPHIFY_LOG="$graphify_log" TMPDIR="$scratch"
    PATH="$stubdir:$PATH"; export PATH
  }
  cleanup() {
    rm -rf "$fixture"
    unset GRAPHIFY_LOG GRAPHIFY_STUB_GRAPH GRAPHIFY_STUB_SIGNAL GRAPHIFY_RC TMPDIR
  }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  # Anything the checker left behind: scratch entries, and its worktree lock.
  leftovers() { ls -A "$scratch"; [ ! -e "$lock" ] || echo "$lock"; }
  graph_status() { git_fixture -C "$worktree" status --porcelain -- graphify-out; }

  It 'reports a fresh graph under a seeded rebuild of the spaced root and leaves nothing behind'
    export GRAPHIFY_STUB_GRAPH='committed graph'
    When run sh "$script_abs" "$worktree"
    The status should equal 0
    The stderr should include 'graph is fresh'
    The contents of file "$graphify_log" should equal "update:$worktree:hashseed=0"
    The contents of file "$graph" should equal 'committed graph'
    The result of function leftovers should equal ''
  End

  It 'defaults to the current directory'
    export GRAPHIFY_STUB_GRAPH='committed graph'
    When run sh -c 'cd "$1" && sh "$2"' _ "$worktree" "$script_abs"
    The status should equal 0
    The stderr should include 'graph is fresh'
    The contents of file "$graphify_log" should equal "update:$worktree:hashseed=0"
  End

  It 'overrides a PYTHONHASHSEED inherited from the caller'
    export GRAPHIFY_STUB_GRAPH='committed graph'
    When run env PYTHONHASHSEED=7 sh "$script_abs" "$worktree"
    The status should equal 0
    The stderr should include 'graph is fresh'
    The contents of file "$graphify_log" should equal "update:$worktree:hashseed=0"
  End

  It 'refuses a stale graph, names the rebuild command, and restores the committed bytes'
    export GRAPHIFY_STUB_GRAPH='rebuilt graph'
    When run sh "$script_abs" "$worktree"
    The status should equal 1
    The stderr should include 'STALE'
    The stderr should include "PYTHONHASHSEED=0 graphify update ."
    The contents of file "$graph" should equal 'committed graph'
    The result of function graph_status should equal ''
    The result of function leftovers should equal ''
  End

  It 'compares bytes only: a graph that is not JSON is stale, never a parse error'
    printf '{not json\n' > "$graph"
    git_fixture -C "$worktree" add graphify-out/graph.json
    git_fixture -C "$worktree" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
      commit -q -m broken
    export GRAPHIFY_STUB_GRAPH='rebuilt graph'
    When run sh "$script_abs" "$worktree"
    The status should equal 1
    The stderr should include 'STALE'
    The contents of file "$graph" should equal '{not json'
    The result of function graph_status should equal ''
  End

  It 'restores the committed bytes when the rebuild fails'
    export GRAPHIFY_STUB_GRAPH='partial graph' GRAPHIFY_RC=3
    When run sh "$script_abs" "$worktree"
    The status should equal 1
    The stderr should include 'rebuild failed'
    The contents of file "$graph" should equal 'committed graph'
    The result of function graph_status should equal ''
    The result of function leftovers should equal ''
  End

  It 'restores the committed bytes and cleans up when terminated mid-rebuild'
    export GRAPHIFY_STUB_GRAPH='partial graph' GRAPHIFY_STUB_SIGNAL=TERM
    When run sh "$script_abs" "$worktree"
    The status should equal 1
    The contents of file "$graph" should equal 'committed graph'
    The result of function graph_status should equal ''
    The result of function leftovers should equal ''
  End

  It 'exits 1 naming the lock, rebuilds nothing and touches nothing while another checker holds the worktree'
    mkdir "$lock"
    export GRAPHIFY_STUB_GRAPH='rebuilt graph'
    When run sh "$script_abs" "$worktree"
    The status should equal 1
    The stderr should include "$lock"
    The file "$graphify_log" should not be exist
    The contents of file "$graph" should equal 'committed graph'
    The result of function leftovers should equal "$lock"
  End

  It '--refresh keeps a changed rebuild in place and says so'
    export GRAPHIFY_STUB_GRAPH='rebuilt graph'
    When run sh "$script_abs" --refresh "$worktree"
    The status should equal 0
    The stderr should include 'refreshed (changed)'
    The contents of file "$graphify_log" should equal "update:$worktree:hashseed=0"
    The contents of file "$graph" should equal 'rebuilt graph'
    The result of function leftovers should equal ''
  End

  It '--refresh reports an unchanged rebuild'
    export GRAPHIFY_STUB_GRAPH='committed graph'
    When run sh "$script_abs" --refresh "$worktree"
    The status should equal 0
    The stderr should include 'refreshed (unchanged)'
    The contents of file "$graph" should equal 'committed graph'
  End

  It '--refresh fails and restores the committed bytes when the rebuild fails'
    export GRAPHIFY_STUB_GRAPH='partial graph' GRAPHIFY_RC=3
    When run sh "$script_abs" --refresh "$worktree"
    The status should equal 1
    The stderr should include 'rebuild failed'
    The contents of file "$graph" should equal 'committed graph'
    The result of function leftovers should equal ''
  End

  It 'exits 2 and points at /graphify when the tree has no root graph'
    rm -f "$graph"
    When run sh "$script_abs" "$worktree"
    The status should equal 2
    The stderr should include '/graphify'
    The file "$graphify_log" should not be exist
  End

  It 'exits 2 outside a git worktree'
    mkdir -p "$fixture/plain dir"
    When run sh "$script_abs" "$fixture/plain dir"
    The status should equal 2
    The stderr should include 'not a git worktree'
    The file "$graphify_log" should not be exist
  End

  It 'exits 2 on an unknown option'
    When run sh "$script_abs" --bogus "$worktree"
    The status should equal 2
    The stderr should include 'usage:'
    The file "$graphify_log" should not be exist
  End

  It 'exits 2 on a second positional argument'
    When run sh "$script_abs" "$worktree" "$worktree"
    The status should equal 2
    The stderr should include 'usage:'
    The file "$graphify_log" should not be exist
  End

  It 'exits 4 and names graphify when no launcher can be resolved'
    When run env PATH="$no_graphify" sh "$script_abs" "$worktree"
    The status should equal 4
    The stderr should include 'graphify'
    The file "$graphify_log" should not be exist
    The contents of file "$graph" should equal 'committed graph'
  End

  It 'exits 4 and names cmp when the byte compare tool is missing: never a false verdict'
    export GRAPHIFY_STUB_GRAPH='committed graph'
    When run env PATH="$no_cmp" sh "$script_abs" "$worktree"
    The status should equal 4
    The stderr should include 'TOOL-MISSING: cmp'
    The file "$graphify_log" should not be exist
    The contents of file "$graph" should equal 'committed graph'
  End
End

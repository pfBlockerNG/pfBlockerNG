#shellcheck shell=sh
# Direct per-worktree initialization for repository intelligence tools.

Describe 'init-worktree-tools.sh'
  script_abs="${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/init-worktree-tools.sh"

  make_tool_path() {
    destination=$1
    mkdir -p "$destination"
    # sed reads the shebang of the `graphify` on PATH for the .inc override patch.
    for tool in sh dirname git tr mkdir pwd sed; do
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
    graphify_package="$fixture/toolvenv/package/graphify"
    mkdir -p "$graphify_package"
    true > "$graphify_package/__init__.py"
    cat > "$graphify_package/rcfile.py" <<'RCFILE'
def activate_language_overrides(root):
    return {}
RCFILE

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
    # patch-graphify.sh finds the package through the interpreter named on the
    # `graphify` shebang. This fixture interpreter reports an already-patched package
    # and logs the location probe, so no real installed Graphify is touched.
    interpreter="$fixture/toolvenv/bin/python3"
    mkdir -p "$fixture/toolvenv/bin"
    cat > "$interpreter" <<'INTERPRETER'
#!/bin/sh
case "$*" in
  *os.path.dirname*)
    printf 'patch-graphify:probe\n' >> "$WORKTREE_TOOL_LOG"
    printf '%s\n' "$WORKTREE_GRAPHIFY_PACKAGE"
    exit 0
    ;;
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
    printf 'graphify:%s:%s\n' "$1" "$2" >> "$WORKTREE_TOOL_LOG"
    exit "${GRAPHIFY_RC:-0}"
    ;;
  *) exit 9 ;;
esac
GRAPHIFY
    cat > "$stubdir/serena" <<'SERENA'
#!/bin/sh
[ "$#" -eq 3 ] && [ "$1" = project ] && [ "$2" = index ] || exit 9
printf 'serena:%s:%s:%s\n' "$1" "$2" "$3" >> "$WORKTREE_TOOL_LOG"
exit "${SERENA_RC:-0}"
SERENA
    chmod +x "$stubdir/codegraph" "$stubdir/graphify" "$stubdir/serena"

    no_codegraph="$fixture/no-codegraph"
    no_graphify="$fixture/no-graphify"
    no_serena="$fixture/no-serena"
    make_tool_path "$no_codegraph"
    make_tool_path "$no_graphify"
    make_tool_path "$no_serena"
    ln -s "$stubdir/graphify" "$no_codegraph/graphify"
    ln -s "$stubdir/serena" "$no_codegraph/serena"
    ln -s "$stubdir/codegraph" "$no_graphify/codegraph"
    ln -s "$stubdir/serena" "$no_graphify/serena"
    ln -s "$stubdir/codegraph" "$no_serena/codegraph"
    ln -s "$stubdir/graphify" "$no_serena/graphify"

    export WORKTREE_TOOL_LOG="$tool_log" WORKTREE_GRAPHIFY_PACKAGE="$graphify_package"
    # The initializer applies the vendored .inc language-override patch (issue #2810)
    # after CodeGraph, so every log below carries `patch-graphify:probe` after the
    # CodeGraph line.
    PATH="$stubdir:$PATH"; export PATH
  }
  cleanup() { rm -rf "$fixture"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'runs CodeGraph, skips the first Graphify build, and skips Serena when OMP marks the invoking harness'
    When run env OMP_CLI=1 sh "$script_abs" "$worktree"
    The status should equal 0
    The contents of file "$tool_log" should equal "$(printf 'codegraph:init:%s\npatch-graphify:probe' "$worktree")"
    The stderr should include 'Initializing CodeGraph in'
    The stderr should include 'run /graphify'
  End

  It 'runs CodeGraph, skips the first Graphify build, and skips Serena when PI marks the invoking harness'
    When run env PI_CLI=1 sh "$script_abs" "$worktree"
    The status should equal 0
    The contents of file "$tool_log" should equal "$(printf 'codegraph:init:%s\npatch-graphify:probe' "$worktree")"
    The stderr should include 'Initializing CodeGraph in'
    The stderr should include 'run /graphify'
  End

  It 'leaves a tracked root graph byte-identical so a fresh cut is born clean (issue #3091)'
    mkdir -p "$worktree/graphify-out"
    printf 'committed graph\n' > "$worktree/graphify-out/graph.json"
    git_fixture -C "$worktree" add graphify-out/graph.json
    git_fixture -C "$worktree" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
      commit -q -m graph
    # GRAPHIFY_RC=19 makes any `graphify update` call fail loudly, so a green run
    # proves the initializer never issued one, not merely that it succeeded.
    When run env OMP_CLI=1 GRAPHIFY_RC=19 sh "$script_abs" "$worktree"
    The status should equal 0
    The stderr should include 'already provides'
    The stderr should include 'Initializing CodeGraph in'
    The stderr should not include 'run /graphify'
    The contents of file "$tool_log" should equal "$(printf 'codegraph:init:%s\npatch-graphify:probe' "$worktree")"
    The contents of file "$worktree/graphify-out/graph.json" should equal 'committed graph'
    Assert [ -z "$(git_fixture -C "$worktree" status --porcelain -- graphify-out)" ]
  End

  It 'fails nonzero when mandatory CodeGraph is missing'
    When run env OMP_CLI=1 PATH="$no_codegraph" sh "$script_abs" "$worktree"
    The status should not equal 0
    The stderr should include 'codegraph'
    The file "$tool_log" should not be exist
  End

  It 'stops before Graphify when mandatory CodeGraph initialization fails'
    When run env OMP_CLI=1 CODEGRAPH_RC=17 sh "$script_abs" "$worktree"
    The status should not equal 0
    The contents of file "$tool_log" should equal "codegraph:init:$worktree"
    The stderr should include 'CodeGraph initialization failed'
  End

  It 'fails nonzero when mandatory Graphify is missing'
    When run env OMP_CLI=1 PATH="$no_graphify" sh "$script_abs" "$worktree"
    The status should not equal 0
    The stderr should include 'graphify'
  End

  It 'runs Serena project indexing at the exact root outside OMP when Serena is present'
    When run sh "$script_abs" "$worktree"
    The status should equal 0
    The contents of file "$tool_log" should equal \
      "$(printf 'codegraph:init:%s\npatch-graphify:probe\nserena:project:index:%s' "$worktree" "$worktree")"
    The stderr should include 'Initializing CodeGraph in'
  End

  It 'skips absent Serena outside OMP without weakening mandatory initialization'
    When run env PATH="$no_serena" sh "$script_abs" "$worktree"
    The status should equal 0
    The contents of file "$tool_log" should equal "$(printf 'codegraph:init:%s\npatch-graphify:probe' "$worktree")"
    The stderr should include 'Initializing CodeGraph in'
  End

  It 'propagates Serena indexing failure'
    When run env SERENA_RC=23 sh "$script_abs" "$worktree"
    The status should equal 23
    The contents of file "$tool_log" should equal \
      "$(printf 'codegraph:init:%s\npatch-graphify:probe\nserena:project:index:%s' "$worktree" "$worktree")"
    The stderr should include 'Initializing CodeGraph in'
  End
End

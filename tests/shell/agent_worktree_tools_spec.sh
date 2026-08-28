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
    # patch-graphify.sh finds the package to patch through the interpreter named on the
    # shebang of the `graphify` on PATH, so this stub's shebang names a wrapper sitting
    # where a uv tool venv keeps its own interpreter. The wrapper logs the patch
    # script's probe -- which is what pins the patch call's position in this chain --
    # and then fails it, so the patch script skips and the real installed Graphify is
    # never touched from here. Anything that is not that probe is the stub below being
    # executed through this shebang, so it runs as the /bin/sh script it is.
    interpreter="$fixture/toolvenv/bin/python3"
    mkdir -p "$fixture/toolvenv/bin"
    cat > "$interpreter" <<'INTERPRETER'
#!/bin/sh
case "$1" in
  -I) printf 'patch-graphify:probe\n' >> "$WORKTREE_TOOL_LOG"; exit 1 ;;
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

    export WORKTREE_TOOL_LOG="$tool_log"
    # The initializer applies the vendored .inc language-override patch (issue #2810)
    # before refreshing the graph, so every log below carries `patch-graphify:probe`
    # between the CodeGraph line and the Graphify one.
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

  It 'runs the vendored Graphify language override before refreshing the graph, and a stubbed graphify is a skip'
    mkdir -p "$worktree/graphify-out"
    true > "$worktree/graphify-out/graph.json"
    When run env OMP_CLI=1 sh "$script_abs" "$worktree"
    The status should equal 0
    The stderr should include 'cannot locate'
    The contents of file "$tool_log" should equal \
      "$(printf 'codegraph:init:%s\npatch-graphify:probe\ngraphify:update:%s' "$worktree" "$worktree")"
    The stderr should include 'Initializing CodeGraph in'
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

  It 'returns nonzero when refreshing an existing Graphify root graph fails'
    mkdir -p "$worktree/graphify-out"
    true > "$worktree/graphify-out/graph.json"
    When run env OMP_CLI=1 GRAPHIFY_RC=19 sh "$script_abs" "$worktree"
    The status should not equal 0
    The contents of file "$tool_log" should equal \
      "$(printf 'codegraph:init:%s\npatch-graphify:probe\ngraphify:update:%s' "$worktree" "$worktree")"
    The stderr should include 'Initializing CodeGraph in'
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

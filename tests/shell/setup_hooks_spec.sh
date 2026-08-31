#shellcheck shell=sh
# setup-hooks.sh also bootstraps CodeGraph and registers the Graphify merge driver
# for the main checkout when those CLIs are available.

Describe 'setup-hooks.sh CodeGraph bootstrap'
  script_abs="${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/setup-hooks.sh"

  setup() {
    . "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/lib/git-env-scrub.sh"
    pfb_scrub_git_env
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/setup_hooks.XXXXXX") || return 1
    fixture=$(cd "$fixture" && pwd -P) || return 1
    primary="$fixture/primary"
    git_fixture init -q "$primary" &&
      mkdir -p "$primary/.githooks" &&
      true > "$primary/.githooks/pre-commit" &&
      git_fixture -C "$primary" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
        commit -q --allow-empty -m init || return 1
    stubdir="$fixture/bin"; mkdir -p "$stubdir"
    codegraph_log="$fixture/codegraph.log"
    missing_codegraph_path="$fixture/no-codegraph"; mkdir -p "$missing_codegraph_path"
    for tool in sh git basename; do
      ln -s "$(command -v "$tool")" "$missing_codegraph_path/$tool"
    done
    cat > "$stubdir/codegraph" <<'CODEGRAPH'
#!/bin/sh
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
    cat > "$stubdir/graphify" <<'GRAPHIFY'
#!/bin/sh
exit 0
GRAPHIFY
    chmod +x "$stubdir/graphify"
    # A python that CAN import graphify, so the probe's verification passes.
    cat > "$stubdir/python3" <<'PY'
#!/bin/sh
exit 0
PY
    chmod +x "$stubdir/python3"
    # setup-hooks.sh resolves the Graphify interpreter from the sidecar first, then
    # `uv tool run`, then the launcher's shebang. Pin the sidecar so the probe is
    # hermetic: without it the example resolves whatever Graphify the HOST has, so it
    # passed on a developer machine that had one and failed on a runner that did not.
    mkdir -p "$primary/graphify-out"
    printf '%s\n' "$stubdir/python3" > "$primary/graphify-out/.graphify_python"
    chmod +x "$stubdir/codegraph"
    export CODEGRAPH_LOG="$codegraph_log"
    PATH="$stubdir:$PATH"; export PATH
  }
  cleanup() { rm -rf "$fixture"; }
  registered_driver() { git_fixture -C "$primary" config --local --get merge.graphify.driver; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'initializes CodeGraph in the main checkout when the CLI is available'
    When run sh -c 'cd "$1" && exec sh "$2"' _ "$primary" "$script_abs"
    The status should equal 0
    The output should include 'core.hooksPath set to: .githooks'
    The stderr should include 'Initializing CodeGraph'
    The contents of file "$codegraph_log" should equal "init $primary"
    Assert [ -f "$primary/.codegraph/codegraph.db" ]
  End

  It 'still activates Git hooks when CodeGraph is unavailable'
    When run env PATH="$missing_codegraph_path" sh -c 'cd "$1" && exec sh "$2"' _ "$primary" "$script_abs"
    The status should equal 0
    The output should include 'core.hooksPath set to: .githooks'
    The stderr should equal ''
    The file "$codegraph_log" should not be exist
  End

  It 'registers the Graphify merge driver that .gitattributes names'
    When run sh -c 'cd "$1" && exec sh "$2"' _ "$primary" "$script_abs"
    The status should equal 0
    The output should include 'merge.graphify.driver registered'
    The stderr should include 'Initializing CodeGraph'
    The result of function registered_driver should include 'graphify merge-driver %O %A %B'
  End

  It 'leaves the merge driver alone when Graphify is unavailable'
    When run env PATH="$missing_codegraph_path" sh -c 'cd "$1" && exec sh "$2"' _ "$primary" "$script_abs"
    The status should equal 0
    The output should not include 'merge.graphify.driver registered'
    The stderr should equal ''
  End
End

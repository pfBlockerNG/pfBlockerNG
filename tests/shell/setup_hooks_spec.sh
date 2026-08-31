#shellcheck shell=sh
# setup-hooks.sh installs and patches Graphify before activating hooks, then bootstraps
# CodeGraph for the main checkout when available.

Describe 'setup-hooks.sh contributor bootstrap'
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
    graphify_log="$fixture/graphify.log"
    missing_codegraph_path="$fixture/no-codegraph"; mkdir -p "$missing_codegraph_path"
    missing_uv_path="$fixture/no-uv"; mkdir -p "$missing_uv_path"
    for tool in sh git basename dirname; do
      ln -s "$(command -v "$tool")" "$missing_codegraph_path/$tool"
      ln -s "$(command -v "$tool")" "$missing_uv_path/$tool"
    done
    cat > "$stubdir/uv" <<'UV'
#!/bin/sh
printf '%s\n' "$*" >> "$GRAPHIFY_LOG"
UV
    ln -s "$stubdir/uv" "$missing_codegraph_path/uv"
    mkdir -p "$primary/scripts/agent"
    cat > "$primary/scripts/agent/patch-graphify.sh" <<'PATCH_GRAPHIFY'
#!/bin/sh
printf '%s\n' patch-graphify >> "$GRAPHIFY_LOG"
PATCH_GRAPHIFY
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
    chmod +x "$stubdir/uv" "$stubdir/codegraph"
    export CODEGRAPH_LOG="$codegraph_log" GRAPHIFY_LOG="$graphify_log"
    PATH="$stubdir:$PATH"; export PATH
  }
  cleanup() { rm -rf "$fixture"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'initializes CodeGraph in the main checkout when the CLI is available'
    When run sh -c 'cd "$1" && exec sh "$2"' _ "$primary" "$script_abs"
    The status should equal 0
    The output should include 'core.hooksPath set to: .githooks'
    The stderr should include 'Initializing CodeGraph'
    The contents of file "$codegraph_log" should equal "init $primary"
    The contents of file "$graphify_log" should equal \
      "$(printf '%s\n%s' 'tool install --upgrade graphifyy>=0.9.51' patch-graphify)"
    Assert [ -f "$primary/.codegraph/codegraph.db" ]
  End

  It 'still activates Git hooks when CodeGraph is unavailable'
    When run env PATH="$missing_codegraph_path" sh -c 'cd "$1" && exec sh "$2"' _ "$primary" "$script_abs"
    The status should equal 0
    The output should include 'core.hooksPath set to: .githooks'
    The contents of file "$graphify_log" should equal \
      "$(printf '%s\n%s' 'tool install --upgrade graphifyy>=0.9.51' patch-graphify)"
    The file "$codegraph_log" should not be exist
  End

  It 'fails before activating hooks when uv is unavailable'
    When run env PATH="$missing_uv_path" sh -c 'cd "$1" && exec sh "$2"' _ "$primary" "$script_abs"
    The status should equal 4
    The stderr should include 'TOOL-MISSING: uv'
    The value "$(git_fixture -C "$primary" config --get core.hooksPath 2>/dev/null || true)" should equal ''
    The file "$graphify_log" should not be exist
  End
End

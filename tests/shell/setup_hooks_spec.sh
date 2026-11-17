#shellcheck shell=sh
# setup-hooks.sh activates tracked hooks, then bootstraps CodeGraph for the main checkout when available.

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
    missing_codegraph_path="$fixture/no-codegraph"; mkdir -p "$missing_codegraph_path"
    for tool in awk basename cat chmod dirname git grep mkdir mv rm sed sh tr; do
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
    chmod +x "$stubdir/codegraph"
    export CODEGRAPH_LOG="$codegraph_log"
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
    Assert [ -f "$primary/.codegraph/codegraph.db" ]
  End

  It 'still activates Git hooks when CodeGraph is unavailable'
    When run env PATH="$missing_codegraph_path" sh -c 'cd "$1" && exec sh "$2"' _ "$primary" "$script_abs"
    The status should equal 0
    The output should include 'core.hooksPath set to: .githooks'
    The file "$codegraph_log" should not be exist
  End

  It 'still activates Git hooks when the git root and helper checkout have no pyproject.toml'
    # release-published.yml runs setup-hooks.sh from a scripts-only sparse
    # checkout of pfBlockerNG while CWD is the FreeBSD-ports fork. CodeGraph
    # cannot bootstrap without pyproject.toml; hook activation still must.
    foreign="$fixture/ports"
    helper="$foreign/pfblockerng-src"
    git_fixture init -q "$foreign" || return 1
    mkdir -p "$helper/scripts/agent" "$helper/scripts/lib"
    cp "$script_abs" "$helper/scripts/setup-hooks.sh"
    cp "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/"*.sh "$helper/scripts/agent/"
    cp "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/lib/"*.sh "$helper/scripts/lib/"
    When run sh -c 'cd "$1" && exec sh "$2"' _ "$foreign" "$helper/scripts/setup-hooks.sh"
    The status should equal 0
    The output should include 'core.hooksPath set to: .githooks'
    The value "$(git_fixture -C "$foreign" config --get core.hooksPath)" should equal '.githooks'
    The file "$codegraph_log" should not be exist
  End

End

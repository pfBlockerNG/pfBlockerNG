#shellcheck shell=sh
# Failure contracts for the client-neutral CodeGraph bootstrap.

Describe 'ensure-codegraph.sh failures'
  script_abs="${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/ensure-codegraph.sh"

  setup() {
    . "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/lib/git-env-scrub.sh"
    pfb_scrub_git_env
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/codegraph_error.XXXXXX") || return 1
    fixture=$(cd "$fixture" && pwd -P) || return 1
    primary="$fixture/primary"
    git_fixture init -q "$primary" &&
      git_fixture -C "$primary" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
        commit -q --allow-empty -m init || return 1
    stubdir="$fixture/bin"; mkdir -p "$stubdir"
    codegraph_log="$fixture/codegraph.log"
    codegraph_state="$fixture/codegraph.complete"
    missing_codegraph_path="$fixture/no-codegraph"; mkdir -p "$missing_codegraph_path"
    for tool in sh git dirname tr; do
      ln -s "$(command -v "$tool")" "$missing_codegraph_path/$tool"
    done
    cat > "$stubdir/codegraph" <<'CODEGRAPH'
#!/bin/sh
case "$1" in
  init)
    [ "${CODEGRAPH_RC:-0}" -eq 0 ] || exit "$CODEGRAPH_RC"
    mkdir -p "$2/.codegraph"
    true > "$2/.codegraph/codegraph.db"
    true > "$CODEGRAPH_STATE"
    ;;
  index)
    printf '%s\n' "$*" >> "$CODEGRAPH_LOG"
    mkdir -p "$2/.codegraph"
    true > "$2/.codegraph/codegraph.db"
    true > "$CODEGRAPH_STATE"
    ;;
  status)
    if [ -f "$CODEGRAPH_STATE" ]; then
      state=complete
    else
      state=${CODEGRAPH_EXISTING_STATE:-complete}
    fi
    case "$state" in
      corrupt) exit 1 ;;
      incomplete)
        printf '%s\n' '{"initialized":true,"worktreeMismatch":null,"index":{"reindexRecommended":false,"state":"indexing","pendingRefs":0}}'
        ;;
      complete)
        case "${CODEGRAPH_STATUS_FORMAT:-compact}" in
          compact)
            printf '%s\n' '{"initialized":true,"worktreeMismatch":null,"index":{"reindexRecommended":false,"state":"complete","pendingRefs":0}}'
            ;;
          reordered)
            printf '%s\n' '{"index":{"pendingRefs":0,"state":"complete","reindexRecommended":false},"worktreeMismatch":null,"initialized":true}'
            ;;
          spaced)
            printf '%s\n' '{ "initialized" : true, "worktreeMismatch" : null, "index" : { "reindexRecommended" : false, "state" : "complete", "pendingRefs" : 0 } }'
            ;;
        esac
        ;;
    esac
    ;;
  *) exit 9 ;;
esac
CODEGRAPH
    chmod +x "$stubdir/codegraph"
    export CODEGRAPH_LOG="$codegraph_log"
    export CODEGRAPH_STATE="$codegraph_state"
    PATH="$stubdir:$PATH"; export PATH
  }
  cleanup() { rm -rf "$fixture"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'rejects more than one checkout argument'
    When run sh "$script_abs" "$primary" extra
    The status should equal 2
    The stderr should include 'usage:'
  End

  It 'rejects a target outside a git worktree'
    When run sh "$script_abs" "$fixture"
    The status should equal 2
    The stderr should include 'is not a git worktree'
  End

  It 'reports CodeGraph initialization failure'
    When run env CODEGRAPH_RC=7 sh "$script_abs" "$primary"
    The status should equal 1
    The stderr should include 'CodeGraph initialization failed'
  End

  It 'rebuilds an existing corrupt database'
    mkdir -p "$primary/.codegraph"
    true > "$primary/.codegraph/codegraph.db"
    export CODEGRAPH_EXISTING_STATE=corrupt
    When run sh "$script_abs" "$primary"
    The status should equal 0
    The stderr should include 'Rebuilding CodeGraph'
    The contents of file "$codegraph_log" should equal "index $primary"
    Assert [ -f "$codegraph_state" ]
  End

  It 'rebuilds an existing incomplete index'
    mkdir -p "$primary/.codegraph"
    true > "$primary/.codegraph/codegraph.db"
    export CODEGRAPH_EXISTING_STATE=incomplete
    When run sh "$script_abs" "$primary"
    The status should equal 0
    The stderr should include 'Rebuilding CodeGraph'
    The contents of file "$codegraph_log" should equal "index $primary"
    Assert [ -f "$codegraph_state" ]
  End

  It 'accepts complete status fields in a different member order'
    mkdir -p "$primary/.codegraph"
    true > "$primary/.codegraph/codegraph.db"
    export CODEGRAPH_STATUS_FORMAT=reordered
    When run sh "$script_abs" "$primary"
    The status should equal 0
    The stderr should equal ''
    The file "$codegraph_log" should not be exist
  End

  It 'accepts whitespace-formatted complete status'
    mkdir -p "$primary/.codegraph"
    true > "$primary/.codegraph/codegraph.db"
    export CODEGRAPH_STATUS_FORMAT=spaced
    When run sh "$script_abs" "$primary"
    The status should equal 0
    The stderr should equal ''
    The file "$codegraph_log" should not be exist
  End

  It 'uses the agent-tool missing exit contract when CodeGraph is unavailable'
    When run env PATH="$missing_codegraph_path" sh "$script_abs" "$primary"
    The status should equal 4
    The stderr should include 'TOOL-MISSING: codegraph'
  End
End

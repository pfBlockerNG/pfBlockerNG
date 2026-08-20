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
    cat > "$stubdir/codegraph" <<'CODEGRAPH'
#!/bin/sh
exit "${CODEGRAPH_RC:-0}"
CODEGRAPH
    chmod +x "$stubdir/codegraph"
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

  It 'uses the agent-tool missing exit contract when CodeGraph is unavailable'
    tool_path="$(dirname "$(command -v git)"):/usr/bin:/bin"
    When run env PATH="$tool_path" sh "$script_abs" "$primary"
    The status should equal 4
    The stderr should include 'TOOL-MISSING: codegraph'
  End
End

#shellcheck shell=sh

Describe 'ensure-graphify-merge-driver.sh'

  setup() {
    . "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/lib/git-env-scrub.sh"
    pfb_scrub_git_env
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/graphify_driver_spec.XXXXXX") || return 1
    fixture=$(cd "$fixture" && pwd -P) || return 1
    script_home="$fixture/suite/scripts/agent"
    mkdir -p "$script_home" "$fixture/suite/scripts/lib"
    cp "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/lib/git-env-scrub.sh" "$fixture/suite/scripts/lib/"
    cp "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/ensure-graphify-merge-driver.sh" "$script_home/"
    cp "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/ensure-graphify.sh" "$script_home/"
    cp "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/agent_env.sh" "$script_home/"
    if [ -f "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/resolve-graphify.sh" ]; then
      cp "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/resolve-graphify.sh" "$script_home/"
    fi
    script_abs="$script_home/ensure-graphify-merge-driver.sh"
    repo="$fixture/requested-root"
    git_fixture init -q "$repo" || return 1
    stubdir="$fixture/bin"
    mkdir -p "$stubdir"
    uv_log="$fixture/uv.log"
    graphify_log="$fixture/graphify.log"

    cat > "$stubdir/uv" <<'UV'
#!/bin/sh
case "$*" in
  'tool install --upgrade graphifyy[leiden] @ git+https://github.com/pfBlockerNG/graphify@v0.9.53-pfb.2')
    printf '%s\n' "$*" >> "$UV_LOG"
    if [ "${UV_PROGRESS_FIXTURE:-0}" = 1 ]; then printf '%s\n' 'uv progress'; fi
    ;;
  'tool dir --bin')
    [ -n "${UV_TOOL_BIN_FIXTURE:-}" ] || exit 9
    printf '%s\n' "$UV_TOOL_BIN_FIXTURE"
    ;;
  *) exit 9 ;;
esac
UV
    # A tripwire, never a collaborator: the real `graphify hook install` writes
    # post-commit and post-checkout into `git rev-parse --git-path hooks` (which
    # honours core.hooksPath), and the driver is registered by the helper itself
    # (issue #3139). Any call is logged, drops the hooks the way the CLI would,
    # and fails.
    cat > "$stubdir/graphify" <<'GRAPHIFY'
#!/bin/sh
printf '%s\t%s\n' "$PWD" "$*" >> "$GRAPHIFY_LOG"
hooks_dir=$(git rev-parse --git-path hooks) && mkdir -p "$hooks_dir" && # git-env-scrub-guard: the stub mimics the real CLI, which resolves the hooks dir of the tree under test
  true > "$hooks_dir/post-commit" && true > "$hooks_dir/post-checkout"
exit 91
GRAPHIFY
    real_git=$(command -v git)
    gitstub="$fixture/gitstub"
    mkdir -p "$gitstub"
    cat > "$gitstub/git" <<'GIT'
#!/bin/sh
case "${GIT_STUB_MODE:-}:$*" in
  write:*' config merge.graphify.driver '*) exit 1 ;;
  readback:*' config --local --get merge.graphify.driver') printf '%s\n' 'graphify merge-driver %O %A'; exit 0 ;;
esac
exec "$REAL_GIT" "$@"
GIT
    chmod +x "$gitstub/git"
    chmod +x "$stubdir/uv" "$stubdir/graphify"
    export UV_LOG="$uv_log" GRAPHIFY_LOG="$graphify_log"
    PATH="$stubdir:$PATH"
    export PATH
  }

  cleanup() { rm -rf "$fixture"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'installs the pinned Graphify fork and registers its launcher as the union merge driver of the requested Git root'
    When run sh "$script_abs" "$repo"
    The status should equal 0
    The contents of file "$uv_log" should equal 'tool install --upgrade graphifyy[leiden] @ git+https://github.com/pfBlockerNG/graphify@v0.9.53-pfb.2'
    The file "$graphify_log" should not be exist
    The value "$(git_fixture -C "$repo" config --get merge.graphify.name)" should equal 'graphify graph.json union merge'
    The value "$(git_fixture -C "$repo" config --get merge.graphify.driver)" should equal "\"$stubdir/graphify\" merge-driver %O %A %B"
  End

  It 'leaves .githooks/post-commit and .githooks/post-checkout absent: registration never runs `graphify hook install` (issue #3139)'
    git_fixture -C "$repo" config core.hooksPath .githooks
    mkdir -p "$repo/.githooks"
    When run sh "$script_abs" "$repo"
    The status should equal 0
    The path "$repo/.githooks/post-commit" should not be exist
    The path "$repo/.githooks/post-checkout" should not be exist
    The file "$graphify_log" should not be exist
    The value "$(git_fixture -C "$repo" config --get merge.graphify.driver)" should equal "\"$stubdir/graphify\" merge-driver %O %A %B"
  End

  Context 'registration failures'
    Parameters
      write    'git refuses to record the driver'
      readback 'the recorded driver reads back malformed'
    End

    It "fails loudly when $2"
      When run env PATH="$gitstub:$PATH" REAL_GIT="$real_git" GIT_STUB_MODE="$1" sh "$script_abs" "$repo"
      The status should equal 1
      The stderr should include 'merge.graphify.driver'
      The stderr should include 'merge-driver %O %A %B'
    End
  End

  Context 'launcher path the driver string cannot carry'
    # git hands the string to sh inside double quotes, and expands %-sequences
    # (%O %A %B) anywhere in it, quoted or not: such a driver registers but never runs.
    Parameters
      "uv\$bin"  'a shell metacharacter'
      'uv%Abin'  'a git %-sequence'
    End

    It "fails closed on $2 in the launcher path"
      uv_tool_bin="$fixture/$1"
      mkdir -p "$uv_tool_bin"
      cp "$stubdir/graphify" "$uv_tool_bin/graphify"
      off_path="$fixture/off path"
      mkdir -p "$off_path"
      for tool in dirname git sh; do
        ln -s "$(command -v "$tool")" "$off_path/$tool"
      done
      ln -s "$stubdir/uv" "$off_path/uv"
      When run env PATH="$off_path" UV_TOOL_BIN_FIXTURE="$uv_tool_bin" sh "$script_abs" "$repo"
      The status should equal 1
      The stderr should include 'cannot be quoted'
      The value "$(git_fixture -C "$repo" config --get merge.graphify.driver)" should equal ''
    End
  End
End

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
  'tool install --upgrade graphifyy>=0.9.51')
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
    # The vendored .inc language-override patch (issue #2810): this script runs the
    # requested checkout's copy, so the real installed Graphify is never touched here.
    mkdir -p "$repo/scripts/agent"
    cat > "$repo/scripts/agent/patch-graphify.sh" <<'PATCH_GRAPHIFY'
#!/bin/sh
printf 'patch-graphify\t%s\n' "$*" >> "$GRAPHIFY_LOG"
PATCH_GRAPHIFY
    chmod +x "$stubdir/uv" "$stubdir/graphify"
    export UV_LOG="$uv_log" GRAPHIFY_LOG="$graphify_log"
    PATH="$stubdir:$PATH"
    export PATH
  }

  cleanup() { rm -rf "$fixture"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'installs at least the required Graphify, upgrading to the latest, and registers its launcher as the union merge driver of the requested Git root'
    When run sh "$script_abs" "$repo"
    The status should equal 0
    The contents of file "$uv_log" should equal 'tool install --upgrade graphifyy>=0.9.51'
    The contents of file "$graphify_log" should equal "$(printf 'patch-graphify\t')"
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
    The contents of file "$graphify_log" should equal "$(printf 'patch-graphify\t')"
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

  Context 'foreign target without a target-local patch (issue #3004)'
    # The trusted helper checkout runs the helper against a foreign checkout
    # (e.g. FreeBSD-ports) that ships no scripts/agent/patch-graphify.sh; the
    # helper must fall back to its own trusted sibling instead of failing, and
    # must not create anything inside the foreign checkout.
    It 'falls back to the trusted sibling patch next to the helper script'
      helperdir="$fixture/helper/scripts/agent"
      mkdir -p "$helperdir" "$fixture/helper/scripts/lib"
      cp "$script_abs" "$script_home/ensure-graphify.sh" scripts/agent/agent_env.sh "$helperdir/"
      if [ -f "$script_home/resolve-graphify.sh" ]; then
        cp "$script_home/resolve-graphify.sh" "$helperdir/"
      fi
      cp scripts/lib/git-env-scrub.sh "$fixture/helper/scripts/lib/"
      cat > "$helperdir/patch-graphify.sh" <<'PATCH_GRAPHIFY'
#!/bin/sh
printf 'patch-graphify\t%s\n' "$*" >> "$GRAPHIFY_LOG"
PATCH_GRAPHIFY
      chmod +x "$helperdir/patch-graphify.sh"
      rm -rf "$repo/scripts/agent"
      When run sh "$helperdir/ensure-graphify-merge-driver.sh" "$repo"
      The status should equal 0
      The contents of file "$graphify_log" should equal "$(printf 'patch-graphify\t')"
      The value "$(test -e "$repo/scripts/agent" && echo present || echo absent)" should equal "absent"
    End

    It 'uses the off-PATH launcher returned by setup for a foreign target'
      helperdir="$fixture/off-path-helper/scripts/agent"
      mkdir -p "$helperdir" "$fixture/off-path-helper/scripts/lib"
      cp "$script_abs" "$script_home/ensure-graphify.sh" scripts/agent/agent_env.sh "$helperdir/"
      if [ -f "$script_home/resolve-graphify.sh" ]; then
        cp "$script_home/resolve-graphify.sh" "$helperdir/"
      fi
      cp scripts/lib/git-env-scrub.sh "$fixture/off-path-helper/scripts/lib/"
      cat > "$helperdir/patch-graphify.sh" <<'PATCH_GRAPHIFY'
#!/bin/sh
printf 'patch-graphify\t%s\n' "$*" >> "$GRAPHIFY_LOG"
PATCH_GRAPHIFY
      chmod +x "$helperdir/patch-graphify.sh"
      rm -rf "$repo/scripts/agent"
      uv_tool_bin="$fixture/uv tool bin"
      mkdir -p "$uv_tool_bin"
      cp "$stubdir/graphify" "$uv_tool_bin/graphify"
      off_path="$fixture/off path"
      mkdir -p "$off_path"
      for tool in dirname git sh; do
        ln -s "$(command -v "$tool")" "$off_path/$tool"
      done
      ln -s "$stubdir/uv" "$off_path/uv"
      When run env PATH="$off_path" UV_TOOL_BIN_FIXTURE="$uv_tool_bin" \
        UV_PROGRESS_FIXTURE=1 sh "$helperdir/ensure-graphify-merge-driver.sh" "$repo"
      The status should equal 0
      The stderr should include 'uv progress'
      The contents of file "$graphify_log" should equal "$(printf 'patch-graphify\t')"
      The value "$(git_fixture -C "$repo" config --get merge.graphify.driver)" should equal "\"$uv_tool_bin/graphify\" merge-driver %O %A %B"
      The value "$(test -e "$repo/scripts/agent" && echo present || echo absent)" should equal "absent"
    End

    It 'absolutizes a relative PATH launcher before entering a foreign target'
      helperdir="$fixture/relative-helper/scripts/agent"
      mkdir -p "$helperdir" "$fixture/relative-helper/scripts/lib"
      cp "$script_abs" "$script_home/ensure-graphify.sh" "$script_home/resolve-graphify.sh" \
        scripts/agent/agent_env.sh "$helperdir/"
      cp scripts/lib/git-env-scrub.sh "$fixture/relative-helper/scripts/lib/"
      cat > "$helperdir/patch-graphify.sh" <<'PATCH_GRAPHIFY'
#!/bin/sh
printf 'patch-graphify\t%s\n' "$*" >> "$GRAPHIFY_LOG"
PATCH_GRAPHIFY
      chmod +x "$helperdir/patch-graphify.sh"
      rm -rf "$repo/scripts/agent"

      caller="$fixture/caller"
      relative_bin="$caller/relbin"
      mkdir -p "$relative_bin"
      cp "$stubdir/graphify" "$relative_bin/graphify"

      decoy_marker="$fixture/decoy-executed"
      mkdir -p "$repo/relbin"
      cat > "$repo/relbin/graphify" <<'DECOY'
#!/bin/sh
printf 'decoy\t%s\t%s\n' "$PWD" "$*" >> "$GRAPHIFY_LOG"
touch "$DECOY_MARKER"
"$GIT_TOOL" config --local merge.graphify.driver 'graphify merge-driver %O %A %B'
DECOY
      chmod +x "$repo/relbin/graphify"

      tool_path="$fixture/relative-tools"
      mkdir -p "$tool_path"
      for tool in dirname git touch; do
        ln -s "$(command -v "$tool")" "$tool_path/$tool"
      done
      ln -s "$(command -v dash || command -v sh)" "$tool_path/sh"
      ln -s "$stubdir/uv" "$tool_path/uv"
      When run env PATH="relbin:$tool_path" GIT_TOOL="$tool_path/git" \
        DECOY_MARKER="$decoy_marker" sh -c 'cd "$1" && exec sh "$2" "$3"' _ \
        "$caller" "$helperdir/ensure-graphify-merge-driver.sh" "$repo"
      The status should equal 0
      The contents of file "$graphify_log" should equal "$(printf 'patch-graphify\t')"
      The path "$decoy_marker" should not be exist
      The value "$(git_fixture -C "$repo" config --get merge.graphify.driver)" should equal "\"$relative_bin/graphify\" merge-driver %O %A %B"
    End

    It 'absolutizes a relative uv fallback before entering a foreign target'
      helperdir="$fixture/relative-uv-helper/scripts/agent"
      mkdir -p "$helperdir" "$fixture/relative-uv-helper/scripts/lib"
      cp "$script_abs" "$script_home/ensure-graphify.sh" "$script_home/resolve-graphify.sh" \
        scripts/agent/agent_env.sh "$helperdir/"
      cp scripts/lib/git-env-scrub.sh "$fixture/relative-uv-helper/scripts/lib/"
      cat > "$helperdir/patch-graphify.sh" <<'PATCH_GRAPHIFY'
#!/bin/sh
printf 'patch-graphify\t%s\n' "$*" >> "$GRAPHIFY_LOG"
PATCH_GRAPHIFY
      chmod +x "$helperdir/patch-graphify.sh"
      rm -rf "$repo/scripts/agent"

      caller="$fixture/uv-caller"
      relative_bin="$caller/relbin"
      mkdir -p "$relative_bin"
      cp "$stubdir/graphify" "$relative_bin/graphify"

      decoy_marker="$fixture/uv-decoy-executed"
      mkdir -p "$repo/relbin"
      cat > "$repo/relbin/graphify" <<'DECOY'
#!/bin/sh
printf 'decoy\t%s\t%s\n' "$PWD" "$*" >> "$GRAPHIFY_LOG"
touch "$DECOY_MARKER"
"$GIT_TOOL" config --local merge.graphify.driver 'graphify merge-driver %O %A %B'
DECOY
      chmod +x "$repo/relbin/graphify"

      tool_path="$fixture/relative-uv-tools"
      mkdir -p "$tool_path"
      for tool in dirname git touch; do
        ln -s "$(command -v "$tool")" "$tool_path/$tool"
      done
      ln -s "$(command -v dash || command -v sh)" "$tool_path/sh"
      ln -s "$stubdir/uv" "$tool_path/uv"
      When run env PATH="$tool_path" UV_TOOL_BIN_FIXTURE=relbin \
        GIT_TOOL="$tool_path/git" DECOY_MARKER="$decoy_marker" \
        sh -c 'cd "$1" && exec sh "$2" "$3"' _ \
        "$caller" "$helperdir/ensure-graphify-merge-driver.sh" "$repo"
      The status should equal 0
      The contents of file "$graphify_log" should equal "$(printf 'patch-graphify\t')"
      The path "$decoy_marker" should not be exist
      The value "$(git_fixture -C "$repo" config --get merge.graphify.driver)" should equal "\"$relative_bin/graphify\" merge-driver %O %A %B"
    End
  End
End

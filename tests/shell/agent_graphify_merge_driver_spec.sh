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
    cat > "$stubdir/graphify" <<'GRAPHIFY'
#!/bin/sh
printf '%s\t%s\n' "$PWD" "$*" >> "$GRAPHIFY_LOG"
[ "$#" -eq 2 ] && [ "$1" = hook ] && [ "$2" = install ] || exit 91
case "${GRAPHIFY_DRIVER_MODE:-valid}" in
  valid) git config --local merge.graphify.driver 'graphify merge-driver %O %A %B' ;;
  malformed) git config --local merge.graphify.driver 'graphify merge-driver %O %A' ;;
  missing) : ;;
  *) exit 92 ;;
esac
GRAPHIFY
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

  It 'installs at least the required Graphify, upgrading to the latest, and configures the requested Git root'
    When run sh "$script_abs" "$repo"
    The status should equal 0
    The contents of file "$uv_log" should equal 'tool install --upgrade graphifyy>=0.9.51'
    The contents of file "$graphify_log" should equal \
      "$(printf 'patch-graphify\t\n%s\thook install' "$repo")"
    The value "$(git_fixture -C "$repo" config --get merge.graphify.driver)" should include 'graphify merge-driver %O %A %B'
  End

  Context 'driver validation failures'
    Parameters
      'missing'
      'malformed'
    End

    It "fails loudly when the installed driver is $1"
      export GRAPHIFY_DRIVER_MODE="$1"
      When run sh "$script_abs" "$repo"
      The status should equal 1
      The stderr should include 'merge.graphify.driver'
      The stderr should include 'graphify merge-driver %O %A %B'
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
      The contents of file "$graphify_log" should equal \
        "$(printf 'patch-graphify\t\n%s\thook install' "$repo")"
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
      The contents of file "$graphify_log" should equal \
        "$(printf 'patch-graphify\t\n%s\thook install' "$repo")"
      The value "$(git_fixture -C "$repo" config --get merge.graphify.driver)" should include 'graphify merge-driver %O %A %B'
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
      The contents of file "$graphify_log" should equal \
        "$(printf 'patch-graphify\t\n%s\thook install' "$repo")"
      The path "$decoy_marker" should not be exist
      The value "$(git_fixture -C "$repo" config --get merge.graphify.driver)" should include 'graphify merge-driver %O %A %B'
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
      The contents of file "$graphify_log" should equal \
        "$(printf 'patch-graphify\t\n%s\thook install' "$repo")"
      The path "$decoy_marker" should not be exist
      The value "$(git_fixture -C "$repo" config --get merge.graphify.driver)" should include 'graphify merge-driver %O %A %B'
    End
  End
End

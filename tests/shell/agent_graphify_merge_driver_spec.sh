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
    cp "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/ensure-graphify.sh" "$script_home/ensure-graphify-real.sh"
    cp "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/agent_env.sh" "$script_home/"
    script_abs="$script_home/ensure-graphify-merge-driver.sh"
    cat > "$script_home/ensure-graphify.sh" <<'ENSURE_GRAPHIFY'
#!/bin/sh
[ -f "$1/scripts/agent/patch-graphify.sh" ] &&
  printf 'ensure-graphify\t%s\n' "$*" >> "$GRAPHIFY_LOG"
exec sh "$(dirname "$0")/ensure-graphify-real.sh" "$@"
ENSURE_GRAPHIFY
    repo="$fixture/requested-root"
    git_fixture init -q "$repo" || return 1
    stubdir="$fixture/bin"
    mkdir -p "$stubdir"
    uv_log="$fixture/uv.log"
    graphify_log="$fixture/graphify.log"

    cat > "$stubdir/uv" <<'UV'
#!/bin/sh
printf '%s\n' "$*" >> "$UV_LOG"
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
      "$(printf 'ensure-graphify\t%s\npatch-graphify\t\n%s\thook install' "$repo" "$repo")"
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
      cp "$script_abs" "$script_home/ensure-graphify.sh" "$script_home/ensure-graphify-real.sh" \
        scripts/agent/agent_env.sh "$helperdir/"
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
  End
End

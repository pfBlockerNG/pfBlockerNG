#shellcheck shell=sh
# issue #3495: ensure-graphify.sh installs Graphify from PyPI at or above the
# pyproject.toml floor. On a developer or agent host it never replaces a direct-URL
# (git or local) build at or above that floor (issue #3339); GitHub Actions always
# installs from PyPI.

Describe 'ensure-graphify.sh PyPI floor and installed-build handling (issues #3339, #3495)'
  script_abs="${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/ensure-graphify.sh"
  commit=0123456789abcdef0123456789abcdef01234567

  setup() {
    scrub_git_env
    unset GITHUB_ACTIONS
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/ensure_graphify_spec.XXXXXX") || return 1
    fixture=$(cd "$fixture" && pwd -P) || return 1
    repo="$fixture/repo"
    git_fixture init -q "$repo" || return 1
    stubdir="$fixture/bin"
    tools="$fixture/uv-tools"
    mkdir -p "$stubdir" "$tools"
    uv_log="$fixture/uv.log"
    graphify_log="$fixture/graphify.log"
    cat > "$stubdir/uv" <<'UV'
#!/bin/sh
case "$*" in
  'tool install --upgrade '*) printf '%s\n' "$*" >> "$UV_LOG" ;;
  'tool dir --bin') printf '%s\n' "$STUB_BIN" ;;
  'tool dir') printf '%s\n' "$UV_TOOLS" ;;
  *) exit 9 ;;
esac
UV
    cat > "$stubdir/graphify" <<'GRAPHIFY'
#!/bin/sh
printf '%s\n' "$*" >> "$GRAPHIFY_LOG"
[ "$*" = 'install --platform agents' ] || exit 91
GRAPHIFY
    chmod +x "$stubdir/uv" "$stubdir/graphify"
    export UV_LOG="$uv_log" GRAPHIFY_LOG="$graphify_log" STUB_BIN="$stubdir" UV_TOOLS="$tools"
    PATH="$stubdir:$PATH"
    export PATH
  }
  cleanup() { rm -rf "$fixture"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  # pyproject.toml declares the PyPI floor $1.
  floor() {
    pin_spec="graphifyy[leiden]>=$1"
    printf '%s\n' '[dependency-groups]' 'tools = [' "    \"$pin_spec\"," ']' > "$repo/pyproject.toml"
  }

  # uv tool `graphifyy` at version $1; $2 is its direct_url.json, absent when empty
  # (an index install).
  installed() {
    dist="$tools/graphifyy/lib/python3.12/site-packages/graphifyy-$1.dist-info"
    mkdir -p "$dist"
    printf '%s\n' 'Metadata-Version: 2.4' 'Name: graphifyy' "Version: $1" > "$dist/METADATA"
    [ -z "${2:-}" ] || printf '%s\n' "$2" > "$dist/direct_url.json"
  }
  vcs='{"url":"https://github.com/pfBlockerNG/graphify","vcs_info":{"vcs":"git","commit_id":"'$commit'","requested_revision":"'$commit'"}}'
  editable='{"url":"file:///home/dev/graphify","dir_info":{"editable":true}}'

  Context 'on a developer or agent host'
    Parameters
      '0.9.90'    '0.9.89' "$vcs"      "$commit" 'a git build of a higher patch release'
      '0.9.100'   '0.9.99' "$vcs"      "$commit" 'a git build of a numerically (not lexically) higher release'
      '0.10'      '0.9.70' "$vcs"      "$commit" 'a git build of a higher minor release with fewer segments'
      '0.9.90rc1' '0.9.89' "$vcs"      "$commit" 'a git build of a pre-release of a higher release'
      '0.9.89'    '0.9.89' "$vcs"      "$commit" 'a git build of exactly the floor release'
      '0.9.89.0'  '0.9.89' "$vcs"      "$commit" 'a git build of the floor release with a zero-padded segment'
      '0.9.89'    '0.9.89' "$editable" 'unknown' 'an editable local build of the floor release'
    End

    It "keeps $5 instead of installing from PyPI"
      installed "$1" "$3"
      floor "$2"
      When run sh "$script_abs" "$repo"
      The status should equal 0
      The output should equal "$stubdir/graphify"
      The file "$uv_log" should not be exist
      The stderr should equal "ensure-graphify.sh: keeping installed Graphify $1@$4 over graphifyy[leiden]>=$2 (direct-URL build at or above the floor)"
      The contents of file "$graphify_log" should equal 'install --platform agents'
    End
  End

  Context 'on a developer or agent host'
    Parameters
      '0.9.88' '0.9.89'  "$vcs" 'a git build below the floor'
      '0.9.99' '0.9.100' "$vcs" 'a git build numerically (not lexically) below the floor'
      '0.9.89' '0.9.89'  ''     'an index build of the floor release'
      '0.9.95' '0.9.89'  ''     'an index build above the floor, which uv upgrades and never downgrades'
    End

    It "installs from PyPI over $4"
      installed "$1" "$3"
      floor "$2"
      When run sh "$script_abs" "$repo"
      The status should equal 0
      The output should equal "$stubdir/graphify"
      The contents of file "$uv_log" should equal "tool install --upgrade $pin_spec"
      The contents of file "$graphify_log" should equal 'install --platform agents'
    End
  End

  Context 'when the installed build cannot be identified'
    Parameters
      'two installed dist-info directories' ambiguous
      'metadata without a version'          versionless
      'a version with no release segment'   garbage
    End

    It "keeps the installed build ($1) and says why"
      case "$2" in
        ambiguous) installed 0.9.88 "$vcs"; installed 0.9.90 "$vcs"; label=unknown@unknown ;;
        versionless)
          installed 0.9.90 "$vcs"
          printf '%s\n' 'Metadata-Version: 2.4' 'Name: graphifyy' > "$dist/METADATA"
          label=unknown@$commit ;;
        garbage) installed x "$vcs"; label=x@$commit ;;
      esac
      floor 0.9.89
      When run sh "$script_abs" "$repo"
      The status should equal 0
      The output should equal "$stubdir/graphify"
      The file "$uv_log" should not be exist
      The stderr should equal "ensure-graphify.sh: keeping installed Graphify $label over graphifyy[leiden]>=0.9.89 (unidentifiable build)"
      The contents of file "$graphify_log" should equal 'install --platform agents'
    End
  End

  It 'installs from PyPI when no Graphify tool is installed'
    floor 0.9.89
    When run sh "$script_abs" "$repo"
    The status should equal 0
    The output should equal "$stubdir/graphify"
    The contents of file "$uv_log" should equal "tool install --upgrade $pin_spec"
  End

  It 'keeps a direct-URL build when CI=true is exported without GITHUB_ACTIONS, as agent harnesses do'
    installed 0.9.90 "$vcs"
    floor 0.9.89
    When run env CI=true sh "$script_abs" "$repo"
    The status should equal 0
    The output should equal "$stubdir/graphify"
    The file "$uv_log" should not be exist
    The stderr should equal "ensure-graphify.sh: keeping installed Graphify 0.9.90@$commit over graphifyy[leiden]>=0.9.89 (direct-URL build at or above the floor)"
  End

  It 'always installs from PyPI under GitHub Actions, even over a direct-URL build above the floor'
    installed 0.9.90 "$vcs"
    floor 0.9.89
    When run env GITHUB_ACTIONS=true sh "$script_abs" "$repo"
    The status should equal 0
    The output should equal "$stubdir/graphify"
    The contents of file "$uv_log" should equal "tool install --upgrade $pin_spec"
    The contents of file "$graphify_log" should equal 'install --platform agents'
  End
End

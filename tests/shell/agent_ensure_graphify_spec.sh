#shellcheck shell=sh
# issue #3339: ensure-graphify.sh never replaces a newer installed Graphify build with
# an older pin on a developer or agent host; GitHub Actions always installs the pin.

Describe 'ensure-graphify.sh installed-build ordering (issue #3339)'
  script_abs="${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/ensure-graphify.sh"
  fork='https://github.com/pfBlockerNG/graphify'
  absent=0123456789abcdef0123456789abcdef01234567

  # One rebuild of the fork's force-pushed integration branch: a root commit that no
  # ref reaches, with its own author ($1) and committer ($2) epoch seconds.
  build() {
    GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_AUTHOR_DATE="$1 +0000" \
      GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid GIT_COMMITTER_DATE="$2 +0000" \
      git_fixture -C "$server" commit-tree "$tree" -m "$3"
  }

  setup() {
    scrub_git_env
    unset GITHUB_ACTIONS
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/ensure_graphify_spec.XXXXXX") || return 1
    fixture=$(cd "$fixture" && pwd -P) || return 1
    repo="$fixture/repo"
    git_fixture init -q "$repo" || return 1

    # Stand-in for the fork: it serves any commit by id, as GitHub does for builds
    # the rebuilt branch no longer reaches. The later build carries the OLDER
    # author date, so only committer time orders the two correctly.
    server="$fixture/graphify.git"
    git_fixture init -q --bare "$server" || return 1
    git_fixture -C "$server" config uploadpack.allowAnySHA1InWant true || return 1
    git_fixture -C "$server" config uploadpack.allowFilter true || return 1
    tree=$(git_fixture -C "$server" mktree </dev/null) || return 1
    early=$(build 1790200000 1790000000 early) || return 1
    late=$(build 1789900000 1790100000 late) || return 1
    twin=$(build 1789900000 1790100000 twin) || return 1

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
    # Every fetch of the fork URL lands on the local stand-in; no example reaches
    # GitHub, and developer git configuration cannot redirect it elsewhere.
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_COUNT=1
    GIT_CONFIG_KEY_0="url.file://$server.insteadOf" GIT_CONFIG_VALUE_0=$fork
    export GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0
    export UV_LOG="$uv_log" GRAPHIFY_LOG="$graphify_log" STUB_BIN="$stubdir" UV_TOOLS="$tools"
    PATH="$stubdir:$PATH"
    export PATH
  }
  cleanup() { rm -rf "$fixture"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  # Pin version $1 at commit $2 in pyproject.toml, recorded in uv.lock at commit
  # ${3:-$2} the way `uv lock` writes a git source.
  pin() {
    printf '%s\n' '[project]' 'dependencies = [' \
      "    \"graphifyy[leiden] @ git+$fork@$2\"," ']' > "$repo/pyproject.toml"
    printf '%s\n' '[[package]]' 'name = "graphifyy"' "version = \"$1\"" \
      "source = { git = \"$fork?rev=${3:-$2}#${3:-$2}\" }" > "$repo/uv.lock"
    pin_spec="graphifyy[leiden] @ git+$fork@$2"
  }

  # uv tool `graphifyy` at version $1; $2 is its direct_url.json, absent when empty.
  installed() {
    dist="$tools/graphifyy/lib/python3.12/site-packages/graphifyy-$1.dist-info"
    mkdir -p "$dist"
    printf '%s\n' 'Metadata-Version: 2.4' 'Name: graphifyy' "Version: $1" > "$dist/METADATA"
    [ -z "${2:-}" ] || printf '%s\n' "$2" > "$dist/direct_url.json"
  }
  vcs() {
    printf '{"url":"%s","vcs_info":{"vcs":"git","commit_id":"%s","requested_revision":"%s"}}' "$fork" "$1" "$1"
  }

  Context 'on a developer or agent host'
    Parameters
      '0.9.71'    '0.9.70' 'a higher patch release'
      '0.9.100'   '0.9.99' 'a numerically (not lexically) higher release'
      '0.10'      '0.9.70' 'a higher minor release with fewer segments'
      '0.9.71rc1' '0.9.70' 'a pre-release of a higher release'
    End

    It "keeps an installed build of $3 over the pin even when its commit is older"
      installed "$1" "$(vcs "$early")"
      pin "$2" "$late"
      When run sh "$script_abs" "$repo"
      The status should equal 0
      The output should equal "$stubdir/graphify"
      The file "$uv_log" should not be exist
      The stderr should equal "ensure-graphify.sh: keeping installed Graphify $1@$early over pin $2@$late (newer version)"
      The contents of file "$graphify_log" should equal 'install --platform agents'
    End
  End

  Context 'on a developer or agent host'
    Parameters
      '0.9.69' '0.9.70'  'a lower patch release'
      '0.9.70' '0.9.100' 'a numerically (not lexically) lower release'
    End

    It "replaces an installed build of $3 with the pin even when its commit is newer"
      installed "$1" "$(vcs "$late")"
      pin "$2" "$early"
      When run sh "$script_abs" "$repo"
      The status should equal 0
      The output should equal "$stubdir/graphify"
      The contents of file "$uv_log" should equal "tool install --upgrade $pin_spec"
      The contents of file "$graphify_log" should equal 'install --platform agents'
    End
  End

  It 'keeps a same-version build whose commit was committed after the pin commit'
    installed 0.9.70 "$(vcs "$late")"
    pin 0.9.70 "$early"
    When run sh "$script_abs" "$repo"
    The status should equal 0
    The output should equal "$stubdir/graphify"
    The file "$uv_log" should not be exist
    The stderr should equal "ensure-graphify.sh: keeping installed Graphify 0.9.70@$late over pin 0.9.70@$early (later commit)"
    The contents of file "$graphify_log" should equal 'install --platform agents'
  End

  It 'replaces a same-version build whose commit was committed before the pin commit'
    installed 0.9.70 "$(vcs "$early")"
    pin 0.9.70 "$late"
    When run sh "$script_abs" "$repo"
    The status should equal 0
    The output should equal "$stubdir/graphify"
    The contents of file "$uv_log" should equal "tool install --upgrade $pin_spec"
  End

  It 'orders by commit when uv.lock records another commit, ignoring the stale locked version'
    installed 0.9.71 "$(vcs "$early")"
    pin 0.9.60 "$late" "$absent"
    When run sh "$script_abs" "$repo"
    The status should equal 0
    The output should equal "$stubdir/graphify"
    The contents of file "$uv_log" should equal "tool install --upgrade $pin_spec"
  End

  Context 'when the order cannot be established'
    Parameters
      'a local path install'                     local
      'a build without direct_url.json'          none
      'a commit the fork cannot serve'           absent
      'a commit committed in the same second'    twin
    End

    It "keeps the installed same-version build ($1) and says why"
      case "$2" in
        local) installed 0.9.70 '{"url":"file:///home/dev/graphify","dir_info":{"editable":true}}'; label=unknown ;;
        none) installed 0.9.70; label=unknown ;;
        absent) installed 0.9.70 "$(vcs "$absent")"; label=$absent ;;
        twin) installed 0.9.70 "$(vcs "$twin")"; label=$twin ;;
      esac
      pin 0.9.70 "$late"
      When run sh "$script_abs" "$repo"
      The status should equal 0
      The output should equal "$stubdir/graphify"
      The file "$uv_log" should not be exist
      The stderr should equal "ensure-graphify.sh: keeping installed Graphify 0.9.70@$label over pin 0.9.70@$late (order unknown)"
      The contents of file "$graphify_log" should equal 'install --platform agents'
    End
  End

  It 'installs the pin when no Graphify tool is installed'
    pin 0.9.70 "$early"
    When run sh "$script_abs" "$repo"
    The status should equal 0
    The output should equal "$stubdir/graphify"
    The contents of file "$uv_log" should equal "tool install --upgrade $pin_spec"
  End

  It 'reinstalls the pin over the identical commit, refreshing its environment as before'
    installed 0.9.70 "$(vcs "$early")"
    pin 0.9.70 "$early"
    When run sh "$script_abs" "$repo"
    The status should equal 0
    The output should equal "$stubdir/graphify"
    The contents of file "$uv_log" should equal "tool install --upgrade $pin_spec"
  End

  It 'keeps a newer build when CI=true is exported without GITHUB_ACTIONS, as agent harnesses do'
    installed 0.9.71 "$(vcs "$early")"
    pin 0.9.70 "$late"
    When run env CI=true sh "$script_abs" "$repo"
    The status should equal 0
    The output should equal "$stubdir/graphify"
    The file "$uv_log" should not be exist
    The stderr should equal "ensure-graphify.sh: keeping installed Graphify 0.9.71@$early over pin 0.9.70@$late (newer version)"
  End

  It 'always installs the exact pin under GitHub Actions, even over a newer build'
    installed 0.9.71 "$(vcs "$late")"
    pin 0.9.70 "$early"
    When run env GITHUB_ACTIONS=true sh "$script_abs" "$repo"
    The status should equal 0
    The output should equal "$stubdir/graphify"
    The contents of file "$uv_log" should equal "tool install --upgrade $pin_spec"
    The contents of file "$graphify_log" should equal 'install --platform agents'
  End
End

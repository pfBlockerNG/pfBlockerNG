#shellcheck shell=sh
# Cross-platform agent-tool bootstrap: installers are stubbed; repository effects use real fixtures.

Describe 'setup-agent-tools.sh'
  project_root="${SHELLSPEC_PROJECT_ROOT:-$PWD}"
  script_abs="$project_root/scripts/agent/setup-agent-tools.sh"
  canonical_worktree_path='worktree-path = "{{ repo_path }}/../.{{ repo }}_worktrees/{{ branch | sanitize }}"'

  make_base_path() {
    destination=$1
    mkdir -p "$destination"
    for tool in awk basename cat chmod cmp cp cut dirname env git grep head id install ln mkdir mktemp mv pwd readlink rm sed sh sort tail tee touch tr uniq wc; do
      tool_path=$(command -v "$tool" 2>/dev/null) || continue
      ln -s "$tool_path" "$destination/$tool"
    done
  }

  setup() {
    . "$project_root/scripts/lib/git-env-scrub.sh"
    pfb_scrub_git_env
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/agent_tools_setup.XXXXXX") || return 1
    fixture=$(cd "$fixture" && pwd -P) || return 1
    home="$fixture/home root"
    repository="$fixture/repository root"
    xdg_config="$home/config root"
    mkdir -p "$home" "$repository/scripts/agent"
    git_fixture init -q "$repository" &&
      git_fixture -C "$repository" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
        commit -q --allow-empty -m init || return 1
    mkdir -p "$repository/.agents/policy"
    agent_marker="$repository/AGENTS.md"
    policy_marker="$repository/.agents/policy/invariants.txt"
    cat > "$agent_marker" <<'AGENTS_MARKER'
# repository agent marker
Load only tracked repository policy.
AGENTS_MARKER
    cat > "$policy_marker" <<'POLICY_MARKER'
# repository policy marker
preserve = true
POLICY_MARKER
    skill_source="$repository/scripts/agent/skills/receiving-code-review"
    mkdir -p "$skill_source"
    printf '%s\n' '# fixture receiving-code-review skill' > "$skill_source/SKILL.md"
    printf '%s\n' 'fixture license' > "$skill_source/LICENSE"
    cp "$agent_marker" "$fixture/AGENTS.md.before"
    cp "$policy_marker" "$fixture/policy.before"

    helper_log="$fixture/helpers.log"
    cat > "$repository/scripts/setup-hooks.sh" <<'SETUP_HOOKS'
#!/bin/sh
printf 'setup-hooks:%s\n' "$*" >> "$DEBIAN_HELPER_LOG"
SETUP_HOOKS

    basebin="$fixture/base-bin"
    activebin="$fixture/active-bin"
    installables="$fixture/installables"
    mkdir -p "$activebin" "$installables"
    make_base_path "$basebin"

    tool_log="$fixture/tools.log"
    apt_log="$fixture/apt.log"
    curl_log="$fixture/curl.log"

    cat > "$activebin/id" <<'ID'
#!/bin/sh
[ "$#" -eq 1 ] && [ "$1" = -u ] || exit 9
printf '%s\n' "${DEBIAN_TEST_UID:-0}"
ID
    cat > "$activebin/uname" <<'UNAME'
#!/bin/sh
case "${1:-}" in
  ''|-s) printf '%s\n' "${AGENT_TEST_OS:-Linux}" ;;
  *) exit 9 ;;
esac
UNAME
    cat > "$activebin/dpkg-query" <<'DPKG'
#!/bin/sh
package=
for argument do package=$argument; done
case ",${DEBIAN_MISSING_PACKAGES:-}," in
  *,"$package",*) exit 1 ;;
esac
printf '%s\n' 'install ok installed'
DPKG
    cat > "$activebin/apt-get" <<'APT_GET'
#!/bin/sh
printf 'apt-get:%s\n' "$*" >> "$DEBIAN_APT_LOG"
APT_GET
    cat > "$activebin/sudo" <<'SUDO'
#!/bin/sh
printf 'sudo:%s\n' "$*" >> "$DEBIAN_APT_LOG"
exec "$@"
SUDO
    cat > "$activebin/brew" <<'BREW'
#!/bin/sh
printf 'brew:%s\n' "$*" >> "$DEBIAN_TOOL_LOG"
case "$*" in
  'list --versions uv')
    [ "${BREW_UV_INSTALLED:-1}" -eq 1 ] || exit 1
    # An installed formula already has its binary under the prefix.
    mkdir -p "$BREW_UV_PREFIX/bin"
    cp "$DEBIAN_INSTALLABLES/uv" "$BREW_UV_PREFIX/bin/uv"
    printf '%s\n' 'uv 0.8.0'
    ;;
  'install uv')
    mkdir -p "$BREW_UV_PREFIX/bin"
    cp "$DEBIAN_INSTALLABLES/uv" "$BREW_UV_PREFIX/bin/uv"
    ;;
  '--prefix uv') printf '%s\n' "$BREW_UV_PREFIX" ;;
  *) exit 9 ;;
esac
BREW
    cat > "$activebin/curl" <<'CURL'
#!/bin/sh
url=
for argument do
  case "$argument" in
    http://*|https://*) url=$argument ;;
  esac
done
printf '%s\n' "$url" >> "$DEBIAN_CURL_LOG"
case "$url" in
  https://astral.sh/uv/install.sh)
    cat <<'INSTALL_UV'
#!/bin/sh
uv_bin=${XDG_BIN_HOME:-$HOME/.local/bin}
mkdir -p "$uv_bin"
cp "$DEBIAN_INSTALLABLES/uv" "$uv_bin/uv"
INSTALL_UV
    ;;
  https://github.com/max-sixty/worktrunk/releases/latest/download/worktrunk-installer.sh)
    cat <<'INSTALL_WORKTRUNK'
#!/bin/sh
worktrunk_bin=${CARGO_HOME:-$HOME/.cargo}/bin
mkdir -p "$worktrunk_bin"
cp "$DEBIAN_INSTALLABLES/wt" "$worktrunk_bin/wt"
INSTALL_WORKTRUNK
    ;;
  *) exit 9 ;;
esac
CURL

    cat > "$installables/uv" <<'UV'
#!/bin/sh
printf 'uv:%s\n' "$*" >> "$DEBIAN_TOOL_LOG"
case "$*" in
  'tool install --upgrade ast-grep-cli')
    uv_tool_bin=${UV_TOOL_BIN_DIR:-${XDG_BIN_HOME:-$HOME/.local/bin}}
    mkdir -p "$uv_tool_bin"
    [ "${UV_OMIT_TOOL:-}" = ast-grep ] || cp "$DEBIAN_INSTALLABLES/ast-grep" "$uv_tool_bin/ast-grep"
    ;;
  'tool install --upgrade semgrep')
    uv_tool_bin=${UV_TOOL_BIN_DIR:-${XDG_BIN_HOME:-$HOME/.local/bin}}
    mkdir -p "$uv_tool_bin"
    [ "${UV_OMIT_TOOL:-}" = semgrep ] || cp "$DEBIAN_INSTALLABLES/semgrep" "$uv_tool_bin/semgrep"
    ;;
  *) exit 9 ;;
esac
UV
    for tool in ast-grep semgrep; do
      cat > "$installables/$tool" <<'STATIC_TOOL'
#!/bin/sh
exit 0
STATIC_TOOL
    done
    cat > "$installables/wt" <<'WORKTRUNK'
#!/bin/sh
[ "$*" = 'config shell install --yes' ] || exit 9
printf 'wt:%s\n' "$*" >> "$DEBIAN_TOOL_LOG"
WORKTRUNK
    chmod +x "$activebin/id" "$activebin/uname" "$activebin/dpkg-query" \
      "$activebin/apt-get" "$activebin/sudo" "$activebin/brew" "$activebin/curl" "$installables"/*
    for tool in uv wt; do
      cp "$installables/$tool" "$activebin/$tool"
    done

    worktrunk_config="$xdg_config/worktrunk/config.toml"
    brew_prefix="$fixture/homebrew uv"
    export HOME="$home"
    export XDG_CONFIG_HOME="$xdg_config"
    export DEBIAN_HELPER_LOG="$helper_log"
    export DEBIAN_TOOL_LOG="$tool_log"
    export DEBIAN_APT_LOG="$apt_log"
    export DEBIAN_CURL_LOG="$curl_log"
    export DEBIAN_INSTALLABLES="$installables"
    export DEBIAN_REPOSITORY="$repository"
    export BREW_UV_PREFIX="$brew_prefix"
    unset CLAUDECODE CODEX_THREAD_ID COPILOT_CLI GROK_AGENT GROK_SESSION_ID OMP_CLI PI_CLI
    unset DEBIAN_MISSING_PACKAGES
    unset AGENT_TEST_OS BREW_UV_INSTALLED XDG_BIN_HOME UV_TOOL_BIN_DIR
    unset UV_OMIT_TOOL CARGO_HOME
    PATH="$activebin:$basebin"; export PATH
  }

  cleanup() {
    rm -rf "$fixture"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'installs only missing Linux prerequisites through sudo for a non-root user'
    export DEBIAN_MISSING_PACKAGES=ca-certificates,curl,git,libarchive-tools
    When run env DEBIAN_TEST_UID=1000 sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$apt_log" should equal "$(printf '%s\n' \
      'sudo:apt-get update' \
      'apt-get:update' \
      'sudo:apt-get install -y ca-certificates curl git libarchive-tools' \
      'apt-get:install -y ca-certificates curl git libarchive-tools')"
  End

  It 'runs apt-get directly as Linux root and installs only the missing package subset'
    export DEBIAN_MISSING_PACKAGES=git
    When run env DEBIAN_TEST_UID=0 sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$apt_log" should equal "$(printf '%s\n' \
      'apt-get:update' \
      'apt-get:install -y git')"
  End

  It 'uses official installers and current-process user paths on an initial Linux setup'
    rm -f "$activebin/brew" "$activebin/uv" "$activebin/wt"
    When run sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$curl_log" should equal "$(printf '%s\n%s' \
      'https://astral.sh/uv/install.sh' \
      'https://github.com/max-sixty/worktrunk/releases/latest/download/worktrunk-installer.sh')"
    The contents of file "$tool_log" should equal "$(printf '%s\n' \
      'uv:tool install --upgrade ast-grep-cli' \
      'uv:tool install --upgrade semgrep' \
      'wt:config shell install --yes')"
    The path "$home/.local/bin/uv" should be executable
    The path "$home/.local/bin/ast-grep" should be executable
    The path "$home/.local/bin/semgrep" should be executable
    The path "$home/.cargo/bin/wt" should be executable
  End

  It 'installs and refreshes the vendored review skill without disturbing sibling skills'
    skill_destination="$home/.agents/skills/receiving-code-review"
    mkdir -p "$skill_destination" "$home/.agents/skills/keep-me"
    printf '%s\n' 'stale skill' > "$skill_destination/SKILL.md"
    printf '%s\n' 'remove me' > "$skill_destination/stale-only"
    printf '%s\n' 'preserved' > "$home/.agents/skills/keep-me/marker"
    When run sh -c 'sh "$1" "$2" && sh "$1" "$2"' _ "$script_abs" "$repository"
    The status should equal 0
    Assert [ "$(cmp -s "$skill_source/SKILL.md" "$skill_destination/SKILL.md"; printf '%s' "$?")" -eq 0 ]
    Assert [ "$(cmp -s "$skill_source/LICENSE" "$skill_destination/LICENSE"; printf '%s' "$?")" -eq 0 ]
    The file "$skill_destination/stale-only" should not be exist
    The contents of file "$home/.agents/skills/keep-me/marker" should equal 'preserved'
  End

  It 'keeps the installed review skill when the vendored skill file is missing'
    skill_destination="$home/.agents/skills/receiving-code-review"
    mkdir -p "$skill_destination"
    printf '%s\n' 'installed skill' > "$skill_destination/SKILL.md"
    mkdir -p "$home/.agents/skills/.receiving-code-review.new"
    printf '%s\n' 'stale stage' > "$home/.agents/skills/.receiving-code-review.new/marker"
    rm "$skill_source/SKILL.md"
    When run sh "$script_abs" "$repository"
    The status should not equal 0
    The stderr should include "required vendored skill '$skill_source/SKILL.md' is missing"
    The contents of file "$skill_destination/SKILL.md" should equal 'installed skill'
    The directory "$home/.agents/skills/.receiving-code-review.new" should not be exist
  End

  It 'keeps the installed review skill when the vendored license is missing'
    skill_destination="$home/.agents/skills/receiving-code-review"
    mkdir -p "$skill_destination"
    printf '%s\n' 'installed skill' > "$skill_destination/SKILL.md"
    mkdir -p "$home/.agents/skills/.receiving-code-review.new"
    printf '%s\n' 'stale stage' > "$home/.agents/skills/.receiving-code-review.new/marker"
    rm "$skill_source/LICENSE"
    When run sh "$script_abs" "$repository"
    The status should not equal 0
    The stderr should include "required vendored skill license '$skill_source/LICENSE' is missing"
    The contents of file "$skill_destination/SKILL.md" should equal 'installed skill'
    The directory "$home/.agents/skills/.receiving-code-review.new" should not be exist
  End

  It 'keeps the installed review skill and removes staging when its refresh copy fails'
    skill_destination="$home/.agents/skills/receiving-code-review"
    mkdir -p "$skill_destination" "$home/.agents/skills/keep-me"
    printf '%s\n' 'installed skill' > "$skill_destination/SKILL.md"
    printf '%s\n' 'installed license' > "$skill_destination/LICENSE"
    printf '%s\n' 'preserved' > "$home/.agents/skills/keep-me/marker"
    export DEBIAN_SKILL_SOURCE="$skill_source"
    export DEBIAN_REAL_CP="$basebin/cp"
    cat > "$activebin/cp" <<'FAIL_SKILL_COPY'
#!/bin/sh
if [ "$#" -eq 3 ] && [ "$1" = -R ] && [ "$2" = "$DEBIAN_SKILL_SOURCE" ]; then
  mkdir -p "$3"
  printf '%s\n' partial > "$3/partial"
  exit 77
fi
exec "$DEBIAN_REAL_CP" "$@"
FAIL_SKILL_COPY
    chmod +x "$activebin/cp"
    When run sh "$script_abs" "$repository"
    The status should not equal 0
    The contents of file "$skill_destination/SKILL.md" should equal 'installed skill'
    The contents of file "$skill_destination/LICENSE" should equal 'installed license'
    The directory "$home/.agents/skills/.receiving-code-review.new" should not be exist
    The contents of file "$home/.agents/skills/keep-me/marker" should equal 'preserved'
  End

  It 'restores the installed review skill when publishing its refresh fails'
    skill_destination="$home/.agents/skills/receiving-code-review"
    mkdir -p "$skill_destination"
    printf '%s\n' 'installed skill' > "$skill_destination/SKILL.md"
    printf '%s\n' 'installed license' > "$skill_destination/LICENSE"
    export DEBIAN_SKILL_STAGED="$home/.agents/skills/.receiving-code-review.new"
    export DEBIAN_SKILL_DESTINATION="$skill_destination"
    export DEBIAN_REAL_MV="$basebin/mv"
    cat > "$activebin/mv" <<'FAIL_SKILL_PUBLISH'
#!/bin/sh
if [ "$#" -eq 2 ] && [ "$1" = "$DEBIAN_SKILL_STAGED" ] && [ "$2" = "$DEBIAN_SKILL_DESTINATION" ]; then
  exit 77
fi
exec "$DEBIAN_REAL_MV" "$@"
FAIL_SKILL_PUBLISH
    chmod +x "$activebin/mv"
    When run sh "$script_abs" "$repository"
    The status should not equal 0
    The contents of file "$skill_destination/SKILL.md" should equal 'installed skill'
    The contents of file "$skill_destination/LICENSE" should equal 'installed license'
    The directory "$home/.agents/skills/.receiving-code-review.new" should not be exist
    The directory "$home/.agents/skills/.receiving-code-review.old" should not be exist
  End

  It 'resolves every initial Linux tool from its configured destination immediately'
    rm -f "$activebin/uv" "$activebin/wt"
    custom_xdg_bin="$fixture/custom xdg bin"
    custom_uv_tool_bin="$fixture/custom uv tool bin"
    custom_cargo_home="$fixture/custom cargo home"
    When run env \
      XDG_BIN_HOME="$custom_xdg_bin" \
      UV_TOOL_BIN_DIR="$custom_uv_tool_bin" \
      CARGO_HOME="$custom_cargo_home" \
      sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$curl_log" should equal "$(printf '%s\n%s' \
      'https://astral.sh/uv/install.sh' \
      'https://github.com/max-sixty/worktrunk/releases/latest/download/worktrunk-installer.sh')"
    The contents of file "$tool_log" should equal "$(printf '%s\n' \
      'uv:tool install --upgrade ast-grep-cli' \
      'uv:tool install --upgrade semgrep' \
      'wt:config shell install --yes')"
    The path "$custom_xdg_bin/uv" should be executable
    The path "$custom_uv_tool_bin/ast-grep" should be executable
    The path "$custom_uv_tool_bin/semgrep" should be executable
    The path "$custom_cargo_home/bin/wt" should be executable
  End

  It 'requires ast-grep immediately after its uv installation'
    export UV_OMIT_TOOL=ast-grep
    When run sh "$script_abs" "$repository"
    The status should not equal 0
    The stderr should include 'TOOL-MISSING: ast-grep'
    The contents of file "$tool_log" should not include 'wt:'
  End

  It 'requires semgrep immediately after its uv installation'
    export UV_OMIT_TOOL=semgrep
    When run sh "$script_abs" "$repository"
    The status should not equal 0
    The stderr should include 'TOOL-MISSING: semgrep'
    The contents of file "$tool_log" should not include 'wt:'
  End

  It 'leaves an existing Linux uv alone on a rerun'
    When run sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$curl_log" should equal \
      'https://github.com/max-sixty/worktrunk/releases/latest/download/worktrunk-installer.sh'
    The contents of file "$tool_log" should equal "$(printf '%s\n' \
      'uv:tool install --upgrade ast-grep-cli' \
      'uv:tool install --upgrade semgrep' \
      'wt:config shell install --yes')"
    The file "$apt_log" should not be exist
  End

  It 'installs a managed Homebrew uv when an unmanaged Darwin uv command exists'
    cat > "$activebin/uv" <<'UNMANAGED_UV'
#!/bin/sh
printf 'uv-unmanaged:%s\n' "$*" >> "$DEBIAN_TOOL_LOG"
exit 9
UNMANAGED_UV
    chmod +x "$activebin/uv"
    When run env AGENT_TEST_OS=Darwin BREW_UV_INSTALLED=0 sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$tool_log" should equal "$(printf '%s\n' \
      'brew:list --versions uv' \
      'brew:install uv' \
      'brew:--prefix uv' \
      'uv:tool install --upgrade ast-grep-cli' \
      'uv:tool install --upgrade semgrep' \
      'wt:config shell install --yes')"
    The contents of file "$curl_log" should equal \
      'https://github.com/max-sixty/worktrunk/releases/latest/download/worktrunk-installer.sh'
    The path "$brew_prefix/bin/uv" should be executable
    The file "$apt_log" should not be exist
  End

  It 'reuses a managed Homebrew uv from its formula prefix without upgrading it on every Darwin rerun'
    rm -f "$activebin/uv"
    When run env AGENT_TEST_OS=Darwin sh -c 'sh "$1" "$2" && sh "$1" "$2"' _ "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$tool_log" should equal "$(printf '%s\n' \
      'brew:list --versions uv' \
      'brew:--prefix uv' \
      'uv:tool install --upgrade ast-grep-cli' \
      'uv:tool install --upgrade semgrep' \
      'wt:config shell install --yes' \
      'brew:list --versions uv' \
      'brew:--prefix uv' \
      'uv:tool install --upgrade ast-grep-cli' \
      'uv:tool install --upgrade semgrep' \
      'wt:config shell install --yes')"
    Assert [ "$(grep -c '^https://github.com/max-sixty/worktrunk/releases/latest/download/worktrunk-installer.sh$' "$curl_log")" -eq 2 ]
    The path "$brew_prefix/bin/uv" should be executable
    The file "$apt_log" should not be exist
  End

  It 'uses the managed uv prefix for an initial Darwin setup'
    rm -f "$activebin/uv"
    When run env AGENT_TEST_OS=Darwin sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$curl_log" should equal \
      'https://github.com/max-sixty/worktrunk/releases/latest/download/worktrunk-installer.sh'
    The contents of file "$tool_log" should equal "$(printf '%s\n' \
      'brew:list --versions uv' \
      'brew:--prefix uv' \
      'uv:tool install --upgrade ast-grep-cli' \
      'uv:tool install --upgrade semgrep' \
      'wt:config shell install --yes')"
    The path "$brew_prefix/bin/uv" should be executable
    The file "$apt_log" should not be exist
  End

  It 'fails on Darwin when Homebrew is unavailable without touching repository helpers'
    rm -f "$activebin/brew"
    When run env AGENT_TEST_OS=Darwin sh "$script_abs" "$repository"
    The status should not equal 0
    The stderr should include 'brew'
    The file "$apt_log" should not be exist
    The file "$helper_log" should not be exist
  End

  It 'rejects an unsupported host before changing tools, helpers, or user configuration'
    When run env AGENT_TEST_OS=FreeBSD sh "$script_abs" "$repository"
    The status should not equal 0
    The stderr should include 'unsupported platform'
    The file "$apt_log" should not be exist
    The file "$curl_log" should not be exist
    The file "$tool_log" should not be exist
    The file "$helper_log" should not be exist
    The path "$home/.local" should not be exist
    The path "$home/.cargo" should not be exist
    The path "$worktrunk_config" should not be exist
  End

  It 'calls the repository hook setup for the default repository'
    When run sh -c 'cd "$1" && exec sh "$2"' _ "$repository" "$script_abs"
    The status should equal 0
    The contents of file "$helper_log" should equal \
      'setup-hooks:'
    The contents of file "$tool_log" should include 'wt:config shell install --yes'
  End

  It 'ignores agent environment markers and leaves repository agent policy unchanged'
    When run env CLAUDECODE=1 CODEX_THREAD_ID=thread COPILOT_CLI=1 GROK_AGENT=1 \
      GROK_SESSION_ID=session OMP_CLI=1 PI_CLI=1 sh "$script_abs" "$repository"
    The status should equal 0
    Assert [ "$(cmp -s "$fixture/AGENTS.md.before" "$agent_marker"; printf '%s' "$?")" -eq 0 ]
    Assert [ "$(cmp -s "$fixture/policy.before" "$policy_marker"; printf '%s' "$?")" -eq 0 ]
    The file "$apt_log" should not be exist
    The contents of file "$curl_log" should equal \
      'https://github.com/max-sixty/worktrunk/releases/latest/download/worktrunk-installer.sh'
  End

  It 'creates the canonical global Worktrunk key when the user config is missing'
    When run sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$worktrunk_config" should equal "$canonical_worktree_path"
  End

  It 'creates the canonical global Worktrunk key when the user config is empty'
    mkdir -p "$(dirname "$worktrunk_config")"
    true > "$worktrunk_config"
    When run sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$worktrunk_config" should equal "$canonical_worktree_path"
  End

  It 'replaces one existing global Worktrunk key without changing adjacent global values'
    mkdir -p "$(dirname "$worktrunk_config")"
    cat > "$worktrunk_config" <<'CONFIG'
# global comment
worktree-path = "/tmp/inside-repository"
theme = "dark"
CONFIG
    When run sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$worktrunk_config" should equal "$(printf '%s\n' \
      '# global comment' \
      "$canonical_worktree_path" \
      'theme = "dark"')"
    Assert [ "$(grep -Fxc "$canonical_worktree_path" "$worktrunk_config")" -eq 1 ]
  End

  It 'canonicalizes a double-quoted global Worktrunk key without changing a nested quoted key'
    mkdir -p "$(dirname "$worktrunk_config")"
    cat > "$worktrunk_config" <<'CONFIG'
"worktree-path" = "/tmp/double-global"
[projects."demo"]
"worktree-path" = "/srv/double-nested"
CONFIG
    When run sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$worktrunk_config" should equal "$(printf '%s\n' \
      "$canonical_worktree_path" \
      '[projects."demo"]' \
      '"worktree-path" = "/srv/double-nested"')"
    Assert [ "$(grep -Fxc "$canonical_worktree_path" "$worktrunk_config")" -eq 1 ]
  End

  It 'canonicalizes a single-quoted global Worktrunk key without changing a nested quoted key'
    mkdir -p "$(dirname "$worktrunk_config")"
    cat > "$worktrunk_config" <<'CONFIG'
'worktree-path' = "/tmp/single-global"
[projects."demo"]
'worktree-path' = "/srv/single-nested"
CONFIG
    When run sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$worktrunk_config" should equal "$(printf '%s\n' \
      "$canonical_worktree_path" \
      '[projects."demo"]' \
      "'worktree-path' = \"/srv/single-nested\"")"
    Assert [ "$(grep -Fxc "$canonical_worktree_path" "$worktrunk_config")" -eq 1 ]
  End

  It 'fails safely on root multiline TOML instead of parsing fake sections or keys'
    mkdir -p "$(dirname "$worktrunk_config")"
    cat > "$worktrunk_config" <<'CONFIG'
description = """
[not-a-table]
worktree-path = "not-a-real-key"
"""
[projects."demo"]
worktree-path = "/srv/demo"
CONFIG
    worktrunk_multiline_expected="$fixture/worktrunk-multiline.expected"
    cp "$worktrunk_config" "$worktrunk_multiline_expected"
    When run sh "$script_abs" "$repository"
    The status should not equal 0
    The contents of file "$worktrunk_config" should equal "$(cat "$worktrunk_multiline_expected")"
    The value "$(wc -c < "$worktrunk_config" | tr -d '[:space:]')" should equal \
      "$(wc -c < "$worktrunk_multiline_expected" | tr -d '[:space:]')"
    The contents of file "$helper_log" should equal 'setup-hooks:'
  End

  It 'inserts only the global Worktrunk key while preserving hostile comments, tables, and nested paths byte-for-byte'
    mkdir -p "$(dirname "$worktrunk_config")"
    cat > "$worktrunk_config" <<'CONFIG'
# user comment
editor = "vim"

[projects."demo"]
# nested comment
worktree-path = "/srv/demo"
color = "blue"

[other]
enabled = true
CONFIG
    When run sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$worktrunk_config" should equal "$(printf '%s\n' \
      '# user comment' \
      'editor = "vim"' \
      '' \
      "$canonical_worktree_path" \
      '[projects."demo"]' \
      '# nested comment' \
      'worktree-path = "/srv/demo"' \
      'color = "blue"' \
      '' \
      '[other]' \
      'enabled = true')"
    Assert [ "$(grep -Fxc "$canonical_worktree_path" "$worktrunk_config")" -eq 1 ]
    Assert [ "$(grep -Fxc 'worktree-path = "/srv/demo"' "$worktrunk_config")" -eq 1 ]
  End

  It 'preserves an unrelated final Worktrunk line without adding an EOF newline'
    mkdir -p "$(dirname "$worktrunk_config")"
    {
      printf '%s\n' \
        '# no-newline user comment' \
        'editor = "vim"' \
        '' \
        '[projects."demo"]' \
        'worktree-path = "/srv/demo"'
      printf '%s' 'final-value = "keep byte-for-byte"'
    } > "$worktrunk_config"
    worktrunk_expected="$fixture/worktrunk-no-newline.expected"
    {
      printf '%s\n' \
        '# no-newline user comment' \
        'editor = "vim"' \
        '' \
        "$canonical_worktree_path" \
        '[projects."demo"]' \
        'worktree-path = "/srv/demo"'
      printf '%s' 'final-value = "keep byte-for-byte"'
    } > "$worktrunk_expected"
    When run sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$worktrunk_config" should equal "$(cat "$worktrunk_expected")"
    The value "$(wc -c < "$worktrunk_config" | tr -d '[:space:]')" should equal \
      "$(wc -c < "$worktrunk_expected" | tr -d '[:space:]')"
  End

  It 'updates tools and keeps one canonical Worktrunk key across repeated installer runs'
    When run sh -c 'sh "$1" "$2" && sh "$1" "$2"' _ "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$worktrunk_config" should equal "$canonical_worktree_path"
    Assert [ "$(grep -Fxc "$canonical_worktree_path" "$worktrunk_config")" -eq 1 ]
    Assert [ "$(grep -c '^uv:tool install --upgrade ast-grep-cli$' "$tool_log")" -eq 2 ]
    Assert [ "$(grep -c '^uv:tool install --upgrade semgrep$' "$tool_log")" -eq 2 ]
    Assert [ "$(grep -c '^wt:config shell install --yes$' "$tool_log")" -eq 2 ]
    Assert [ "$(grep -c '^https://github.com/max-sixty/worktrunk/releases/latest/download/worktrunk-installer.sh$' "$curl_log")" -eq 2 ]
    Assert [ "$(grep -c '^setup-hooks:$' "$helper_log")" -eq 2 ]
  End

  It 'requires the repository hook setup helper before running it'
    rm -f "$repository/scripts/setup-hooks.sh"
    When run sh "$script_abs" "$repository"
    The status should not equal 0
    The stderr should include 'setup-hooks.sh'
    The file "$helper_log" should not be exist
  End

  It 'rejects more than one repository argument'
    When run sh "$script_abs" "$repository" extra
    The status should equal 2
    The stderr should include 'usage: setup-agent-tools.sh [REPOSITORY]'
    The file "$tool_log" should not be exist
    The file "$helper_log" should not be exist
  End
End

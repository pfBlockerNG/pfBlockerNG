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
    serena_state="$fixture/serena-state"
    mkdir -p "$home" "$repository/scripts/agent" "$serena_state"
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
    cp "$agent_marker" "$fixture/AGENTS.md.before"
    cp "$policy_marker" "$fixture/policy.before"

    helper_log="$fixture/helpers.log"
    cat > "$repository/scripts/agent/ensure-graphify.sh" <<'ENSURE_GRAPHIFY'
#!/bin/sh
printf 'ensure-graphify:%s\n' "$1" >> "$DEBIAN_HELPER_LOG"
uv tool install --upgrade graphifyy
ENSURE_GRAPHIFY
    cat > "$repository/scripts/setup-hooks.sh" <<'SETUP_HOOKS'
#!/bin/sh
printf 'setup-hooks:%s\n' "$*" >> "$DEBIAN_HELPER_LOG"
sh "$(dirname "$0")/agent/ensure-graphify.sh" "$PWD"
SETUP_HOOKS
    cat > "$repository/scripts/agent/init-worktree-tools.sh" <<'INIT_WORKTREE'
#!/bin/sh
printf 'init-worktree-tools:%s\n' "$1" >> "$DEBIAN_HELPER_LOG"
INIT_WORKTREE
    cat > "$repository/scripts/agent/provision-archivers.sh" <<'PROVISION_ARCHIVERS'
#!/bin/sh
printf 'provision-archivers:%s\n' "$*" >> "$DEBIAN_HELPER_LOG"
PROVISION_ARCHIVERS

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
  https://raw.githubusercontent.com/colbymchenry/codegraph/main/install.sh)
    cat <<'INSTALL_CODEGRAPH'
#!/bin/sh
codegraph_bin=${CODEGRAPH_BIN_DIR:-$HOME/.local/bin}
mkdir -p "$codegraph_bin"
cp "$DEBIAN_INSTALLABLES/codegraph" "$codegraph_bin/codegraph"
INSTALL_CODEGRAPH
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
  'tool install --upgrade serena-agent')
    uv_tool_bin=${UV_TOOL_BIN_DIR:-${XDG_BIN_HOME:-$HOME/.local/bin}}
    mkdir -p "$uv_tool_bin"
    cp "$DEBIAN_INSTALLABLES/serena" "$uv_tool_bin/serena"
    ;;
  'tool install --upgrade graphifyy')
    uv_tool_bin=${UV_TOOL_BIN_DIR:-${XDG_BIN_HOME:-$HOME/.local/bin}}
    mkdir -p "$uv_tool_bin"
    cp "$DEBIAN_INSTALLABLES/graphify" "$uv_tool_bin/graphify"
    ;;
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
    cat > "$installables/serena" <<'SERENA'
#!/bin/sh
printf 'serena:%s\n' "$*" >> "$DEBIAN_TOOL_LOG"
if [ "$#" -eq 1 ] && [ "$1" = init ]; then
  mkdir -p "$HOME/.serena"
  if [ ! -f "$HOME/.serena/serena_config.yml" ]; then
    case "${SERENA_CONFIG_MODE:-root}" in
      root)
        cat > "$HOME/.serena/serena_config.yml" <<'CONFIG'
# preserved
web_dashboard: true
projects:
  demo:
    web_dashboard: true
CONFIG
        ;;
      missing-root)
        cat > "$HOME/.serena/serena_config.yml" <<'CONFIG'
projects:
  demo:
    web_dashboard: true
CONFIG
        ;;
      double-root)
        cat > "$HOME/.serena/serena_config.yml" <<'CONFIG'
"web_dashboard": true
projects:
  demo:
    web_dashboard: true
CONFIG
        ;;
      single-root)
        cat > "$HOME/.serena/serena_config.yml" <<'CONFIG'
'web_dashboard': true
projects:
  demo:
    web_dashboard: true
CONFIG
        ;;
      *) exit 9 ;;
    esac
  fi
fi
if [ "$#" -eq 2 ] && [ "$1" = setup ]; then
  case "${SERENA_SETUP_MODE:-ok}" in
    ok) ;;
    duplicate)
      if [ ! -f "$SERENA_STATE_DIR/$2.removed" ]; then
        printf '%s\n' "Serena MCP entry for $2 already exists" >&2
        exit 7
      fi
      ;;
    permission-denied)
      printf '%s\n' 'permission denied' >&2
      exit 7
      ;;
    *) exit 9 ;;
  esac
fi
SERENA
    cat > "$installables/codegraph" <<'CODEGRAPH'
#!/bin/sh
printf 'codegraph:%s\n' "$*" >> "$DEBIAN_TOOL_LOG"
case "$*" in
  upgrade|'install -l global -y -t auto') ;;
  *) exit 9 ;;
esac
CODEGRAPH
    cat > "$installables/graphify" <<'GRAPHIFY'
#!/bin/sh
printf 'graphify:%s:%s\n' "$(pwd -P)" "$*" >> "$DEBIAN_TOOL_LOG"
if [ "$*" = 'agents install' ] && [ "$(pwd -P)" = "$DEBIAN_REPOSITORY" ]; then
  printf '%s\n' '# graphify rewrote repository agents' > "$DEBIAN_REPOSITORY/AGENTS.md"
fi
# Claude/Codex client commands wire integrations only. Copilot, Pi, and agents
# client commands also copy their skill, but every platform installer refreshes it.
case "$*" in
  'install --platform claude') stub_client=claude ;;
  'install --platform codex') stub_client=codex ;;
  'copilot install'|'install --platform copilot') stub_client=copilot ;;
  'pi install'|'install --platform pi') stub_client=pi ;;
  'agents install'|'install --platform agents') stub_client=agents ;;
  *) stub_client='' ;;
esac
if [ -n "$stub_client" ]; then
  case "$stub_client" in
    pi) stub_skill_dir="$HOME/.pi/agent/skills/graphify" ;;
    agents) stub_skill_dir="$HOME/.agents/skills/graphify" ;;
    *) stub_skill_dir="$HOME/.$stub_client/skills/graphify" ;;
  esac
  mkdir -p "$stub_skill_dir"
  printf '%s\n' '0.9.51' > "$stub_skill_dir/.graphify_version"
fi
GRAPHIFY
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
    cat > "$installables/claude" <<'CLAUDE'
#!/bin/sh
printf 'claude:%s\n' "$*" >> "$DEBIAN_TOOL_LOG"
case "$*" in
  'mcp remove serena -s user') touch "$SERENA_STATE_DIR/claude-code.removed" ;;
  *) exit 9 ;;
esac
CLAUDE
    cat > "$installables/codex" <<'CODEX'
#!/bin/sh
printf 'codex:%s\n' "$*" >> "$DEBIAN_TOOL_LOG"
case "$*" in
  'mcp remove serena') touch "$SERENA_STATE_DIR/codex.removed" ;;
  *) exit 9 ;;
esac
CODEX
    for client in copilot omp pi; do
      cat > "$installables/$client" <<'CLIENT'
#!/bin/sh
exit 0
CLIENT
    done
    cat > "$installables/grok" <<'GROK'
#!/bin/sh
printf 'grok:%s\n' "$*" >> "$DEBIAN_TOOL_LOG"
case "$*" in
  'mcp remove serena') touch "$SERENA_STATE_DIR/grok.removed" ;;
  'mcp doctor codegraph --json') exit "${GROK_DOCTOR_RC:-0}" ;;
  'mcp remove codegraph'|'mcp add codegraph -- codegraph serve --mcp') ;;
  *) exit 9 ;;
esac
GROK
    chmod +x "$activebin/id" "$activebin/uname" "$activebin/dpkg-query" \
      "$activebin/apt-get" "$activebin/sudo" "$activebin/brew" "$activebin/curl" "$installables"/*
    for tool in uv serena codegraph graphify wt; do
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
    export SERENA_STATE_DIR="$serena_state"
    unset CLAUDECODE CODEX_THREAD_ID COPILOT_CLI GROK_AGENT GROK_SESSION_ID OMP_CLI PI_CLI
    unset DEBIAN_MISSING_PACKAGES SERENA_CONFIG_MODE SERENA_SETUP_MODE
    unset GROK_DOCTOR_RC AGENT_TEST_OS BREW_UV_INSTALLED XDG_BIN_HOME UV_TOOL_BIN_DIR
    unset UV_OMIT_TOOL CODEGRAPH_BIN_DIR CARGO_HOME
    PATH="$activebin:$basebin"; export PATH
  }

  enable_client() {
    cp "$installables/$1" "$activebin/$1"
  }

  cleanup() {
    rm -rf "$fixture"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'installs only missing Linux prerequisites through sudo for a non-root user'
    export DEBIAN_MISSING_PACKAGES=ca-certificates,curl,git
    When run env DEBIAN_TEST_UID=1000 sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$apt_log" should equal "$(printf '%s\n' \
      'sudo:apt-get update' \
      'apt-get:update' \
      'sudo:apt-get install -y ca-certificates curl git' \
      'apt-get:install -y ca-certificates curl git')"
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
    rm -f "$activebin/brew" "$activebin/uv" "$activebin/serena" "$activebin/codegraph" \
      "$activebin/graphify" "$activebin/wt"
    When run sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$curl_log" should equal "$(printf '%s\n%s\n%s' \
      'https://astral.sh/uv/install.sh' \
      'https://raw.githubusercontent.com/colbymchenry/codegraph/main/install.sh' \
      'https://github.com/max-sixty/worktrunk/releases/latest/download/worktrunk-installer.sh')"
    The contents of file "$tool_log" should equal "$(printf '%s\n' \
      'uv:tool install --upgrade serena-agent' \
      'uv:tool install --upgrade graphifyy' \
      'uv:tool install --upgrade ast-grep-cli' \
      'uv:tool install --upgrade semgrep' \
      'codegraph:install -l global -y -t auto' \
      'wt:config shell install --yes' \
      'serena:init')"
    The path "$home/.local/bin/uv" should be executable
    The path "$home/.local/bin/serena" should be executable
    The path "$home/.local/bin/graphify" should be executable
    The path "$home/.local/bin/ast-grep" should be executable
    The path "$home/.local/bin/semgrep" should be executable
    The path "$home/.local/bin/codegraph" should be executable
    The path "$home/.cargo/bin/wt" should be executable
  End

  It 'resolves every initial Linux tool from its configured destination immediately'
    rm -f "$activebin/uv" "$activebin/serena" "$activebin/codegraph" "$activebin/graphify" "$activebin/wt"
    custom_xdg_bin="$fixture/custom xdg bin"
    custom_uv_tool_bin="$fixture/custom uv tool bin"
    custom_codegraph_bin="$fixture/custom codegraph bin"
    custom_cargo_home="$fixture/custom cargo home"
    When run env \
      XDG_BIN_HOME="$custom_xdg_bin" \
      UV_TOOL_BIN_DIR="$custom_uv_tool_bin" \
      CODEGRAPH_BIN_DIR="$custom_codegraph_bin" \
      CARGO_HOME="$custom_cargo_home" \
      sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$curl_log" should equal "$(printf '%s\n%s\n%s' \
      'https://astral.sh/uv/install.sh' \
      'https://raw.githubusercontent.com/colbymchenry/codegraph/main/install.sh' \
      'https://github.com/max-sixty/worktrunk/releases/latest/download/worktrunk-installer.sh')"
    The contents of file "$tool_log" should equal "$(printf '%s\n' \
      'uv:tool install --upgrade serena-agent' \
      'uv:tool install --upgrade graphifyy' \
      'uv:tool install --upgrade ast-grep-cli' \
      'uv:tool install --upgrade semgrep' \
      'codegraph:install -l global -y -t auto' \
      'wt:config shell install --yes' \
      'serena:init')"
    The path "$custom_xdg_bin/uv" should be executable
    The path "$custom_uv_tool_bin/serena" should be executable
    The path "$custom_uv_tool_bin/graphify" should be executable
    The path "$custom_uv_tool_bin/ast-grep" should be executable
    The path "$custom_uv_tool_bin/semgrep" should be executable
    The path "$custom_codegraph_bin/codegraph" should be executable
    The path "$custom_cargo_home/bin/wt" should be executable
  End

  It 'requires ast-grep immediately after its uv installation'
    export UV_OMIT_TOOL=ast-grep
    When run sh "$script_abs" "$repository"
    The status should not equal 0
    The stderr should include 'TOOL-MISSING: ast-grep'
    The contents of file "$tool_log" should not include 'codegraph:'
  End

  It 'requires semgrep immediately after its uv installation'
    export UV_OMIT_TOOL=semgrep
    When run sh "$script_abs" "$repository"
    The status should not equal 0
    The stderr should include 'TOOL-MISSING: semgrep'
    The contents of file "$tool_log" should not include 'codegraph:'
  End

  It 'leaves an existing Linux uv alone and updates CodeGraph while rerunning global auto configuration'
    When run sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$curl_log" should equal \
      'https://github.com/max-sixty/worktrunk/releases/latest/download/worktrunk-installer.sh'
    The contents of file "$tool_log" should equal "$(printf '%s\n' \
      'uv:tool install --upgrade serena-agent' \
      'uv:tool install --upgrade graphifyy' \
      'uv:tool install --upgrade ast-grep-cli' \
      'uv:tool install --upgrade semgrep' \
      'codegraph:upgrade' \
      'codegraph:install -l global -y -t auto' \
      'wt:config shell install --yes' \
      'serena:init')"
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
      'uv:tool install --upgrade serena-agent' \
      'uv:tool install --upgrade graphifyy' \
      'uv:tool install --upgrade ast-grep-cli' \
      'uv:tool install --upgrade semgrep' \
      'codegraph:upgrade' \
      'codegraph:install -l global -y -t auto' \
      'wt:config shell install --yes' \
      'serena:init')"
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
      'uv:tool install --upgrade serena-agent' \
      'uv:tool install --upgrade graphifyy' \
      'uv:tool install --upgrade ast-grep-cli' \
      'uv:tool install --upgrade semgrep' \
      'codegraph:upgrade' \
      'codegraph:install -l global -y -t auto' \
      'wt:config shell install --yes' \
      'serena:init' \
      'brew:list --versions uv' \
      'brew:--prefix uv' \
      'uv:tool install --upgrade serena-agent' \
      'uv:tool install --upgrade graphifyy' \
      'uv:tool install --upgrade ast-grep-cli' \
      'uv:tool install --upgrade semgrep' \
      'codegraph:upgrade' \
      'codegraph:install -l global -y -t auto' \
      'wt:config shell install --yes' \
      'serena:init')"
    Assert [ "$(grep -c '^https://github.com/max-sixty/worktrunk/releases/latest/download/worktrunk-installer.sh$' "$curl_log")" -eq 2 ]
    The path "$brew_prefix/bin/uv" should be executable
    The file "$apt_log" should not be exist
  End

  It 'uses the official CodeGraph installer and managed uv prefix for an initial Darwin setup'
    rm -f "$activebin/uv" "$activebin/codegraph"
    When run env AGENT_TEST_OS=Darwin sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$curl_log" should equal "$(printf '%s\n%s' \
      'https://raw.githubusercontent.com/colbymchenry/codegraph/main/install.sh' \
      'https://github.com/max-sixty/worktrunk/releases/latest/download/worktrunk-installer.sh')"
    The contents of file "$tool_log" should equal "$(printf '%s\n' \
      'brew:list --versions uv' \
      'brew:--prefix uv' \
      'uv:tool install --upgrade serena-agent' \
      'uv:tool install --upgrade graphifyy' \
      'uv:tool install --upgrade ast-grep-cli' \
      'uv:tool install --upgrade semgrep' \
      'codegraph:install -l global -y -t auto' \
      'wt:config shell install --yes' \
      'serena:init')"
    The path "$brew_prefix/bin/uv" should be executable
    The path "$home/.local/bin/codegraph" should be executable
    The file "$apt_log" should not be exist
  End

  It 'never runs the Linux archiver provisioning on Darwin'
    When run env AGENT_TEST_OS=Darwin sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$helper_log" should equal \
      "$(printf 'setup-hooks:\nensure-graphify:%s\ninit-worktree-tools:%s' "$repository" "$repository")"
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
    The path "$home/.serena/serena_config.yml" should not be exist
  End

  It 'disables only the root Serena dashboard key and calls every repository helper for the default repository'
    When run sh -c 'cd "$1" && exec sh "$2"' _ "$repository" "$script_abs"
    The status should equal 0
    The contents of file "$home/.serena/serena_config.yml" should equal "$(printf '%s\n' \
      '# preserved' \
      'web_dashboard: false' \
      'projects:' \
      '  demo:' \
      '    web_dashboard: true')"
    The contents of file "$helper_log" should equal \
      "$(printf 'provision-archivers:\nsetup-hooks:\nensure-graphify:%s\ninit-worktree-tools:%s' "$repository" "$repository")"
    The contents of file "$tool_log" should include 'serena:init'
    The contents of file "$tool_log" should include 'wt:config shell install --yes'
    The contents of file "$tool_log" should include 'codegraph:install -l global -y -t auto'
  End

  It 'fails before repository initialization when Serena has no root dashboard key to disable'
    export SERENA_CONFIG_MODE=missing-root
    When run sh "$script_abs" "$repository"
    The status should not equal 0
    The contents of file "$home/.serena/serena_config.yml" should equal "$(printf '%s\n' \
      'projects:' \
      '  demo:' \
      '    web_dashboard: true')"
    The contents of file "$helper_log" should equal \
      "$(printf 'provision-archivers:\nsetup-hooks:\nensure-graphify:%s' "$repository")"
    The contents of file "$tool_log" should include 'codegraph:install -l global -y -t auto'
  End

  It 'canonicalizes a double-quoted root Serena dashboard key without changing the nested key'
    export SERENA_CONFIG_MODE=double-root
    When run sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$home/.serena/serena_config.yml" should equal "$(printf '%s\n' \
      'web_dashboard: false' \
      'projects:' \
      '  demo:' \
      '    web_dashboard: true')"
    The contents of file "$tool_log" should include 'codegraph:install -l global -y -t auto'
  End

  It 'canonicalizes a single-quoted root Serena dashboard key without changing the nested key'
    export SERENA_CONFIG_MODE=single-root
    When run sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$home/.serena/serena_config.yml" should equal "$(printf '%s\n' \
      'web_dashboard: false' \
      'projects:' \
      '  demo:' \
      '    web_dashboard: true')"
    The contents of file "$tool_log" should include 'codegraph:install -l global -y -t auto'
  End

  It 'replaces a duplicate Claude Code Serena entry before retrying setup'
    enable_client claude
    export SERENA_SETUP_MODE=duplicate
    When run sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$tool_log" should include "$(printf '%s\n%s\n%s\n%s' \
      'serena:setup claude-code' \
      'claude:mcp remove serena -s user' \
      'serena:setup claude-code' \
      "graphify:$home:claude install")"
    Assert [ "$(grep -Fxc 'serena:setup claude-code' "$tool_log")" -eq 2 ]
    Assert [ "$(grep -Fxc 'claude:mcp remove serena -s user' "$tool_log")" -eq 1 ]
    Assert [ "$(grep -Fxc "graphify:$home:claude install" "$tool_log")" -eq 1 ]
  End

  It 'replaces a duplicate Codex Serena entry before retrying setup'
    enable_client codex
    export SERENA_SETUP_MODE=duplicate
    When run sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$tool_log" should include "$(printf '%s\n%s\n%s\n%s' \
      'serena:setup codex' \
      'codex:mcp remove serena' \
      'serena:setup codex' \
      "graphify:$home:codex install")"
    Assert [ "$(grep -Fxc 'serena:setup codex' "$tool_log")" -eq 2 ]
    Assert [ "$(grep -Fxc 'codex:mcp remove serena' "$tool_log")" -eq 1 ]
    Assert [ "$(grep -Fxc "graphify:$home:codex install" "$tool_log")" -eq 1 ]
  End

  It 'replaces a duplicate Grok Serena entry before retrying setup'
    enable_client grok
    export SERENA_SETUP_MODE=duplicate
    When run sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$tool_log" should include "$(printf '%s\n%s\n%s\n%s' \
      'serena:setup grok' \
      'grok:mcp remove serena' \
      'serena:setup grok' \
      "graphify:$home:install --platform agents")"
    Assert [ "$(grep -Fxc 'serena:setup grok' "$tool_log")" -eq 2 ]
    Assert [ "$(grep -Fxc 'grok:mcp remove serena' "$tool_log")" -eq 1 ]
    Assert [ "$(grep -Fxc "graphify:$home:install --platform agents" "$tool_log")" -eq 1 ]
  End

  It 'keeps a nonduplicate Serena setup failure fatal before removal or Graphify'
    enable_client claude
    export SERENA_SETUP_MODE=permission-denied
    When run sh "$script_abs" "$repository"
    The status should not equal 0
    The stderr should include 'permission denied'
    Assert [ "$(grep -Fxc 'serena:setup claude-code' "$tool_log")" -eq 1 ]
    The contents of file "$tool_log" should not include 'mcp remove serena'
    The contents of file "$tool_log" should not include 'graphify:'
  End

  It 'reruns detected Claude Code setup and its home-scoped Graphify installer on every invocation'
    enable_client claude
    When run sh -c 'sh "$1" "$2" && sh "$1" "$2"' _ "$script_abs" "$repository"
    The status should equal 0
    Assert [ "$(grep -c '^serena:setup claude-code$' "$tool_log")" -eq 2 ]
    Assert [ "$(grep -Fxc "graphify:$home:claude install" "$tool_log")" -eq 2 ]
    Assert [ "$(grep -c '^codegraph:install -l global -y -t auto$' "$tool_log")" -eq 2 ]
    The contents of file "$tool_log" should not include 'serena:setup codex'
    The contents of file "$tool_log" should not include 'serena:setup grok'
    The contents of file "$tool_log" should not include "graphify:$home:codex install"
    The contents of file "$tool_log" should not include "graphify:$home:pi install"
    The contents of file "$tool_log" should not include 'grok:mcp'
  End

  It 'reruns only detected Codex setup and its home-scoped Graphify installer on every invocation'
    enable_client codex
    When run sh -c 'sh "$1" "$2" && sh "$1" "$2"' _ "$script_abs" "$repository"
    The status should equal 0
    Assert [ "$(grep -c '^serena:setup codex$' "$tool_log")" -eq 2 ]
    Assert [ "$(grep -Fxc "graphify:$home:codex install" "$tool_log")" -eq 2 ]
    Assert [ "$(grep -c '^codegraph:install -l global -y -t auto$' "$tool_log")" -eq 2 ]
    The contents of file "$tool_log" should not include 'serena:setup claude-code'
    The contents of file "$tool_log" should not include 'serena:setup grok'
    The contents of file "$tool_log" should not include "graphify:$home:claude install"
    The contents of file "$tool_log" should not include "graphify:$home:pi install"
    The contents of file "$tool_log" should not include 'grok:mcp'
  End

  It 'reruns both Grok Graphify installers without changing repository agent policy'
    enable_client grok
    mkdir -p "$home/.agents/skills/graphify"
    printf '%s\n' '0.9.48' > "$home/.agents/skills/graphify/.graphify_version"
    When run sh -c 'cd "$1" && sh "$2" "$1" && sh "$2" "$1"' _ "$repository" "$script_abs"
    The status should equal 0
    The contents of file "$home/.agents/skills/graphify/.graphify_version" should equal '0.9.51'
    Assert [ "$(grep -c '^serena:setup grok$' "$tool_log")" -eq 2 ]
    Assert [ "$(grep -Fxc "graphify:$home:agents install" "$tool_log")" -eq 2 ]
    Assert [ "$(grep -Fxc "graphify:$home:install --platform agents" "$tool_log")" -eq 2 ]
    Assert [ "$(grep -c '^grok:mcp doctor codegraph --json$' "$tool_log")" -eq 2 ]
    The contents of file "$tool_log" should not include 'grok:mcp remove codegraph'
    The contents of file "$tool_log" should not include 'grok:mcp add codegraph'
    The contents of file "$tool_log" should not include "graphify:$home:claude install"
    The contents of file "$tool_log" should not include "graphify:$home:codex install"
    The contents of file "$tool_log" should not include "graphify:$home:pi install"
    Assert [ "$(grep -c '^codegraph:install -l global -y -t auto$' "$tool_log")" -eq 2 ]
    Assert [ "$(cmp -s "$fixture/AGENTS.md.before" "$agent_marker"; printf '%s' "$?")" -eq 0 ]
    Assert [ "$(cmp -s "$fixture/policy.before" "$policy_marker"; printf '%s' "$?")" -eq 0 ]
  End

  It 'repairs only an unhealthy detected Grok CodeGraph MCP entry with the canonical server command'
    enable_client grok
    export GROK_DOCTOR_RC=7
    When run sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$tool_log" should include "$(printf '%s\n%s\n%s' \
      'grok:mcp doctor codegraph --json' \
      'grok:mcp remove codegraph' \
      'grok:mcp add codegraph -- codegraph serve --mcp')"
    Assert [ "$(grep -c '^grok:mcp doctor codegraph --json$' "$tool_log")" -eq 1 ]
    Assert [ "$(grep -c '^grok:mcp remove codegraph$' "$tool_log")" -eq 1 ]
    Assert [ "$(grep -c '^grok:mcp add codegraph -- codegraph serve --mcp$' "$tool_log")" -eq 1 ]
    Assert [ "$(grep -c '^codegraph:install -l global -y -t auto$' "$tool_log")" -eq 1 ]
  End

  It 'refreshes the detected Copilot Graphify skill as well as its integration'
    enable_client copilot
    mkdir -p "$home/.copilot/skills/graphify"
    printf '%s\n' '0.9.48' > "$home/.copilot/skills/graphify/.graphify_version"
    When run sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$home/.copilot/skills/graphify/.graphify_version" should equal '0.9.51'
    Assert [ "$(grep -Fxc "graphify:$home:copilot install" "$tool_log")" -eq 1 ]
    Assert [ "$(grep -Fxc "graphify:$home:install --platform copilot" "$tool_log")" -eq 1 ]
    The contents of file "$tool_log" should not include 'serena:setup'
  End

  It 'refreshes the detected Claude Code Graphify skill as well as its hook wiring'
    enable_client claude
    mkdir -p "$home/.claude/skills/graphify"
    printf '%s\n' '0.9.48' > "$home/.claude/skills/graphify/.graphify_version"
    When run sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$home/.claude/skills/graphify/.graphify_version" should equal '0.9.51'
    Assert [ "$(grep -Fxc "graphify:$home:claude install" "$tool_log")" -eq 1 ]
    Assert [ "$(grep -Fxc "graphify:$home:install --platform claude" "$tool_log")" -eq 1 ]
  End

  It 'refreshes the detected Codex Graphify skill as well as its hook wiring'
    enable_client codex
    mkdir -p "$home/.codex/skills/graphify"
    printf '%s\n' '0.9.48' > "$home/.codex/skills/graphify/.graphify_version"
    When run sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$home/.codex/skills/graphify/.graphify_version" should equal '0.9.51'
    Assert [ "$(grep -Fxc "graphify:$home:codex install" "$tool_log")" -eq 1 ]
    Assert [ "$(grep -Fxc "graphify:$home:install --platform codex" "$tool_log")" -eq 1 ]
  End

  It 'refreshes the detected OMP Graphify skill through both Pi-compatible installers'
    enable_client omp
    mkdir -p "$home/.pi/agent/skills/graphify"
    printf '%s\n' '0.9.48' > "$home/.pi/agent/skills/graphify/.graphify_version"
    When run sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$home/.pi/agent/skills/graphify/.graphify_version" should equal '0.9.51'
    Assert [ "$(grep -Fxc "graphify:$home:pi install" "$tool_log")" -eq 1 ]
    Assert [ "$(grep -Fxc "graphify:$home:install --platform pi" "$tool_log")" -eq 1 ]
    The contents of file "$tool_log" should not include 'serena:setup'
  End

  It 'does not duplicate either shared Pi-compatible Graphify installer for OMP plus Pi'
    enable_client omp
    enable_client pi
    When run sh "$script_abs" "$repository"
    The status should equal 0
    Assert [ "$(grep -Fxc "graphify:$home:pi install" "$tool_log")" -eq 1 ]
    Assert [ "$(grep -Fxc "graphify:$home:install --platform pi" "$tool_log")" -eq 1 ]
    The contents of file "$tool_log" should not include 'serena:setup'
  End

  It 'reruns both detected Pi Graphify installers without Serena client setup'
    enable_client pi
    When run sh -c 'sh "$1" "$2" && sh "$1" "$2"' _ "$script_abs" "$repository"
    The status should equal 0
    Assert [ "$(grep -Fxc "graphify:$home:pi install" "$tool_log")" -eq 2 ]
    Assert [ "$(grep -Fxc "graphify:$home:install --platform pi" "$tool_log")" -eq 2 ]
    The contents of file "$tool_log" should not include 'serena:setup'
    The contents of file "$tool_log" should not include "graphify:$home:claude install"
    The contents of file "$tool_log" should not include "graphify:$home:codex install"
    The contents of file "$tool_log" should not include 'install --platform agents'
    The contents of file "$tool_log" should not include 'grok:mcp'
    Assert [ "$(grep -c '^codegraph:install -l global -y -t auto$' "$tool_log")" -eq 2 ]
  End

  It 'ignores agent environment markers when no client executable is present'
    When run env CLAUDECODE=1 CODEX_THREAD_ID=thread COPILOT_CLI=1 GROK_AGENT=1 \
      GROK_SESSION_ID=session OMP_CLI=1 PI_CLI=1 sh "$script_abs" "$repository"
    The status should equal 0
    The contents of file "$tool_log" should include 'serena:init'
    The contents of file "$tool_log" should not include 'serena:setup'
    The contents of file "$tool_log" should not include 'graphify:'
    The contents of file "$tool_log" should not include 'grok:mcp'
    The contents of file "$tool_log" should include 'codegraph:install -l global -y -t auto'
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
    The contents of file "$helper_log" should equal \
      "$(printf 'provision-archivers:\nsetup-hooks:\nensure-graphify:%s' "$repository")"
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
    Assert [ "$(grep -c '^uv:tool install --upgrade serena-agent$' "$tool_log")" -eq 2 ]
    Assert [ "$(grep -c '^uv:tool install --upgrade graphifyy$' "$tool_log")" -eq 2 ]
    Assert [ "$(grep -c '^uv:tool install --upgrade ast-grep-cli$' "$tool_log")" -eq 2 ]
    Assert [ "$(grep -c '^uv:tool install --upgrade semgrep$' "$tool_log")" -eq 2 ]
    Assert [ "$(grep -c '^codegraph:upgrade$' "$tool_log")" -eq 2 ]
    Assert [ "$(grep -c '^codegraph:install -l global -y -t auto$' "$tool_log")" -eq 2 ]
    Assert [ "$(grep -c '^wt:config shell install --yes$' "$tool_log")" -eq 2 ]
    Assert [ "$(grep -c '^https://github.com/max-sixty/worktrunk/releases/latest/download/worktrunk-installer.sh$' "$curl_log")" -eq 2 ]
    Assert [ "$(grep -c "^ensure-graphify:$repository$" "$helper_log")" -eq 2 ]
    Assert [ "$(grep -c '^setup-hooks:$' "$helper_log")" -eq 2 ]
    Assert [ "$(grep -c "^init-worktree-tools:$repository$" "$helper_log")" -eq 2 ]
    Assert [ "$(grep -c '^provision-archivers:$' "$helper_log")" -eq 2 ]
  End

  It 'requires every repository setup helper before running any of them'
    rm -f "$repository/scripts/agent/init-worktree-tools.sh"
    When run sh "$script_abs" "$repository"
    The status should not equal 0
    The stderr should include 'init-worktree-tools.sh'
    The file "$helper_log" should not be exist
  End

  It 'requires the archiver provisioning helper before running any helper'
    rm -f "$repository/scripts/agent/provision-archivers.sh"
    When run sh "$script_abs" "$repository"
    The status should not equal 0
    The stderr should include 'provision-archivers.sh'
    The file "$helper_log" should not be exist
    The file "$tool_log" should not be exist
  End

  It 'fails before tool installation when the shared Graphify helper is missing'
    rm -f "$repository/scripts/agent/ensure-graphify.sh"
    When run sh "$script_abs" "$repository"
    The status should not equal 0
    The stderr should include 'ensure-graphify.sh'
    The file "$helper_log" should not be exist
    The file "$tool_log" should not be exist
  End

  It 'rejects more than one repository argument'
    When run sh "$script_abs" "$repository" extra
    The status should equal 2
    The stderr should include 'usage: setup-agent-tools.sh [REPOSITORY]'
    The file "$tool_log" should not be exist
    The file "$helper_log" should not be exist
  End
End

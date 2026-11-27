#shellcheck shell=sh
# setup-hooks.sh activates the tracked hooks.

Describe 'setup-hooks.sh contributor bootstrap'
  script_abs="${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/setup-hooks.sh"

  setup() {
    . "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/lib/git-env-scrub.sh"
    pfb_scrub_git_env
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/setup_hooks.XXXXXX") || return 1
    fixture=$(cd "$fixture" && pwd -P) || return 1
    primary="$fixture/primary"
    git_fixture init -q "$primary" &&
      mkdir -p "$primary/.githooks" &&
      true > "$primary/.githooks/pre-commit" &&
      git_fixture -C "$primary" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
        commit -q --allow-empty -m init || return 1
  }
  cleanup() { rm -rf "$fixture"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'activates the tracked hooks in the main checkout'
    When run sh -c 'cd "$1" && exec sh "$2"' _ "$primary" "$script_abs"
    The status should equal 0
    The output should include 'core.hooksPath set to: .githooks'
    The output should include '  pre-commit'
    The value "$(git_fixture -C "$primary" config --get core.hooksPath)" should equal '.githooks'
  End

  It 'activates Git hooks on the git root when run from a scripts-only helper checkout'
    # release-published.yml runs setup-hooks.sh from a scripts-only sparse
    # checkout of pfBlockerNG while CWD is the FreeBSD-ports fork.
    foreign="$fixture/ports"
    helper="$foreign/pfblockerng-src"
    git_fixture init -q "$foreign" || return 1
    mkdir -p "$helper/scripts"
    cp "$script_abs" "$helper/scripts/setup-hooks.sh"
    When run sh -c 'cd "$1" && exec sh "$2"' _ "$foreign" "$helper/scripts/setup-hooks.sh"
    The status should equal 0
    The output should include 'core.hooksPath set to: .githooks'
    The value "$(git_fixture -C "$foreign" config --get core.hooksPath)" should equal '.githooks'
  End

End

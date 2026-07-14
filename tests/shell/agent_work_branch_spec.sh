#shellcheck shell=sh
# work-branch.sh: the CLAUDE.md branch-name sanitiser, pinned so it is never hand-derived
# again. Covers both CLAUDE.md examples, the 30-char boundary truncation, emoji/non-ASCII
# stripping, and the empty-slug bare form.

Describe 'work-branch.sh branch naming'
  script="scripts/agent/work-branch.sh"

  It 'derives the CLAUDE.md issue example'
    When run sh "$script" issue 43 "TLD-Allow KeyError on ..."
    The output should equal 'issue/43-tld-allow-keyerror-on'
  End

  It 'derives the CLAUDE.md ADR example'
    When run sh "$script" adr 10 "Zero_Downtime_DNSBL"
    The output should equal 'adr/10-zero-downtime-dnsbl'
  End

  It 'truncates at a dash boundary, never mid-token and never trailing a dash'
    When run sh "$script" issue 1173 "IP recompute: a priority reorder alone never triggers recompute"
    The output should equal 'issue/1173-ip-recompute-a-priority'
  End

  It 'keeps a slug of exactly 30 characters intact'
    When run sh "$script" issue 1 "abcde-fghij-klmno-pqrst-uvwxyz"
    The output should equal 'issue/1-abcde-fghij-klmno-pqrst-uvwxyz'
  End

  It 'strips emoji and collapses the runs they leave'
    When run sh "$script" issue 7 "🔥 Hot fix!!"
    The output should equal 'issue/7-hot-fix'
  End

  It 'omits an empty slug (bare type/NN)'
    When run sh "$script" issue 99 "🎉🎉🎉"
    The output should equal 'issue/99'
  End

  It 'rejects --base given without a value'
    When run sh "$script" issue 5 title --base
    The status should equal 2
    The stderr should include 'usage'
  End

  It 'rejects a non-numeric issue number'
    When run sh "$script" issue abc "title"
    The status should equal 2
    The stderr should include 'usage'
  End

  It 'rejects an unknown work-item kind'
    When run sh "$script" bug 5 "title"
    The status should equal 2
    The stderr should include 'usage'
  End
End

Describe 'work-branch.sh --worktree anchors at the primary checkout'
  # rc-mode / managed sessions run inside a linked session worktree; a new
  # worktree must land under the PRIMARY root, never nested in the session tree.
  script_abs="${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/work-branch.sh"

  setup() {
    # Under a git hook, exported GIT_DIR/GIT_INDEX_FILE would aim the fixture's
    # nested git calls at the hook's repo (see scripts/lib/git-env-scrub.sh).
    . "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/lib/git-env-scrub.sh"
    pfb_scrub_git_env
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/wb_spec.XXXXXX") || return 1
    fixture=$(cd "$fixture" && pwd -P) || return 1
    primary="$fixture/primary"
    git init -q "$primary" &&
      git -C "$primary" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
        commit -q --allow-empty -m init &&
      git -C "$primary" worktree add -q --detach "$fixture/session" >/dev/null 2>&1
  }
  cleanup() { rm -rf "$fixture"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'defaults the path under the primary root when run from a linked worktree'
    When run sh -c 'cd "$1" && exec sh "$2" issue 7 tld --worktree --base HEAD' _ "$fixture/session" "$script_abs"
    The status should equal 0
    The output should equal "$(printf 'issue/7-tld\t%s/.claude/worktrees/issue-7' "$primary")"
    The stderr should include 'Preparing worktree'
  End

  It 'anchors a relative --path at the primary root when run from a linked worktree'
    When run sh -c 'cd "$1" && exec sh "$2" issue 8 tld --worktree --base HEAD --path wt/x' _ "$fixture/session" "$script_abs"
    The status should equal 0
    The output should equal "$(printf 'issue/8-tld\t%s/wt/x' "$primary")"
    The stderr should include 'Preparing worktree'
  End

  It 'keeps the primary-checkout default placement unchanged'
    When run sh -c 'cd "$1" && exec sh "$2" issue 9 tld --worktree --base HEAD' _ "$primary" "$script_abs"
    The status should equal 0
    The output should equal "$(printf 'issue/9-tld\t%s/.claude/worktrees/issue-9' "$primary")"
    The stderr should include 'Preparing worktree'
  End
End

Describe 'work-branch.sh slugify() truncation edges'
  # shellcheck disable=SC2034 # consumed by the Included script's source-only guard
  AGENT_SOURCE_ONLY=1
  Include scripts/agent/work-branch.sh

  It 'keeps a single over-long token cut at 30 characters (no boundary exists)'
    When call slugify "abcdefghijklmnopqrstuvwxyzabcdefghij"
    The output should equal 'abcdefghijklmnopqrstuvwxyzabcd'
  End

  It 'drops a token that straddles the 30-character cut'
    When call slugify "ip-recompute-a-priority-reorder"
    The output should equal 'ip-recompute-a-priority'
  End

  It 'keeps a token whose end lands exactly on the 30-character cut'
    When call slugify "aaaaaaaaaa-bbbbbbbbbb-cccccccc-ddd"
    The output should equal 'aaaaaaaaaa-bbbbbbbbbb-cccccccc'
  End
End

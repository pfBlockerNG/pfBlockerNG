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

Describe 'work-branch.sh Graphify store integration'
  script_abs="${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/work-branch.sh"

  setup() {
    . "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/lib/git-env-scrub.sh"
    pfb_scrub_git_env
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/wb_graphify.XXXXXX") || return 1
    fixture=$(cd "$fixture" && pwd -P) || return 1
    primary="$fixture/primary"
    mkdir -p "$primary/scripts/agent"
    git_fixture init -q -b devel "$primary" || return 1
    git_fixture -C "$primary" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
      config user.email t@t
    git_fixture -C "$primary" config user.name t
    cp "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/graphify-store.py" "$primary/scripts/agent/graphify-store.py"
    chmod +x "$primary/scripts/agent/graphify-store.py"
    git_fixture -C "$primary" add scripts/agent/graphify-store.py &&
      git_fixture -C "$primary" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
        commit -q -m helper || return 1
    mkdir -p "$primary/graphify-out/cache"
    printf '%s\n' graph > "$primary/graphify-out/graph.json"
    printf '%s\n' payload > "$primary/graphify-out/cache/payload.txt"
    ln -s cache "$primary/graphify-out/current"
    sha=$(git_fixture -C "$primary" rev-parse HEAD)
    python3 "$primary/scripts/agent/graphify-store.py" publish \
      --store-root "$primary/.git/graphify-store" --builder "$primary" --branch devel --sha "$sha" || return 1
    stubdir="$fixture/bin"; mkdir -p "$stubdir"
    codegraph_log="$fixture/codegraph.log"
    cat > "$stubdir/codegraph" <<'CODEGRAPH'
#!/bin/sh
case "$1" in
  init|index)
    printf '%s\n' "$*" >> "$WB_CODEGRAPH_LOG"
    mkdir -p "$2/.codegraph"
    true > "$2/.codegraph/codegraph.db"
    ;;
  status)
    printf '%s\n' '{"initialized":true,"worktreeMismatch":null,"index":{"reindexRecommended":false,"state":"complete","pendingRefs":0}}'
    ;;
  *) exit 9 ;;
esac
CODEGRAPH
    chmod +x "$stubdir/codegraph"
    export WB_CODEGRAPH_LOG="$codegraph_log"
    PATH="$stubdir:$PATH"; export PATH
  }
  cleanup() { rm -rf "$fixture"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'requires an exact snapshot before creating a worktree'
    rm -rf "$primary/.git/graphify-store"
    When run sh -c 'cd "$1" && exec sh "$2" issue 31 graph --worktree --base HEAD --path "$3"' _ "$primary" "$script_abs" "$fixture/missing"
    The status should equal 1
    The stderr should include "GRAPHIFY-REFRESH-REQUIRED branch=devel sha=$sha"
    Assert [ ! -e "$fixture/missing" ]
  End

  It 'restores the exact opaque snapshot before CodeGraph initialization'
    When run sh -c 'cd "$1" && exec sh "$2" issue 32 graph --worktree --base HEAD --path "$3"' _ "$primary" "$script_abs" "$fixture/exact"
    The status should equal 0
    The output should equal "$(printf 'issue/32-graph\t%s/exact' "$fixture")"
    The stderr should include 'Preparing worktree'
    Assert [ -f "$fixture/exact/graphify-out/cache/payload.txt" ]
    Assert [ -L "$fixture/exact/graphify-out/current" ]
    The contents of file "$codegraph_log" should equal "init $fixture/exact"
  End

  It 'fails loudly when neither kernel lock tool exists'
    minimal="$fixture/minimal-bin"; mkdir -p "$minimal"
    for tool in sh git dirname python3; do ln -s "$(command -v "$tool")" "$minimal/$tool"; done
    When run sh -c 'cd "$1" && PATH="$3" exec sh "$2" adr 33 graph --worktree --base HEAD --path "$4"' _ "$primary" "$script_abs" "$minimal" "$fixture/no-lock"
    The status should equal 4
    The stderr should include 'TOOL-MISSING: lockf/flock'
    Assert [ ! -e "$fixture/no-lock" ]
  End

  It 'uses the flock fallback when lockf is absent and passes fd 9'
    fallback="$fixture/flock-bin"; mkdir -p "$fallback"
    for tool in sh git dirname python3 mkdir tr sed rm pwd; do ln -s "$(command -v "$tool")" "$fallback/$tool"; done
    ln -s "$stubdir/codegraph" "$fallback/codegraph"
    cat > "$fallback/flock" <<'FLOCK'
#!/bin/sh
printf '%s\n' "$1" > "$WB_FLOCK_USED"
FLOCK
    chmod +x "$fallback/flock"
    export WB_FLOCK_USED="$fixture/flock-used"
    When run sh -c 'cd "$1" && PATH="$3" exec sh "$2" adr 35 graph --worktree --base HEAD --path "$4"' _ "$primary" "$script_abs" "$fallback" "$fixture/flock-worktree"
    The status should equal 0
    The output should equal "$(printf 'adr/35-graph\t%s/flock-worktree' "$fixture")"
    The stderr should include 'Preparing worktree'
    The contents of file "$WB_FLOCK_USED" should equal 9
    Assert [ -f "$fixture/flock-worktree/graphify-out/cache/payload.txt" ]
  End

  It 'removes the worktree and branch when exact snapshot restoration fails'
    store="$primary/.git/graphify-store"
    git_fixture -C "$store" rm -q -r graphify-out &&
      git_fixture -C "$store" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
        commit -q -m corrupt &&
      git_fixture -C "$store" tag -f "source/devel/$sha" devel >/dev/null 2>&1 || return 1
    When run sh -c 'cd "$1" && exec sh "$2" issue 34 graph --worktree --base HEAD --path "$3"' _ "$primary" "$script_abs" "$fixture/restore-fail"
    The status should equal 1
    The stderr should include 'Graphify snapshot restore failure'
    Assert [ ! -e "$fixture/restore-fail" ]
    Assert [ -z "$(git_fixture -C "$primary" branch --list 'issue/34-graph')" ]
  End

  It 'serializes concurrent callers across the worktree and CodeGraph sequence'
    release_fifo="$fixture/release.fifo"
    started_fifo="$fixture/started.fifo"
    second_fifo="$fixture/second.fifo"
    mkfifo "$release_fifo" "$started_fifo" "$second_fifo"
    events="$fixture/events"
    cat > "$stubdir/codegraph" <<'CODEGRAPH'
#!/bin/sh
case "$1" in
  init)
    mkdir -p "$2/.codegraph"
    case "$2" in
      *work-31) printf '%s\n' first-start >> "$WB_EVENTS"; printf '%s\n' first-start > "$WB_STARTED_FIFO"; read release_token < "$WB_RELEASE_FIFO"; printf '%s\n' first-end >> "$WB_EVENTS" ;;
      *work-32) printf '%s\n' second-start >> "$WB_EVENTS" ;;
    esac
    true > "$2/.codegraph/codegraph.db"
    ;;
  status) printf '%s\n' '{"initialized":true,"worktreeMismatch":null,"index":{"reindexRecommended":false,"state":"complete","pendingRefs":0}}' ;;
  *) exit 9 ;;
esac
CODEGRAPH
    chmod +x "$stubdir/codegraph"
    real_lockf=$(command -v lockf 2>/dev/null || true)
    real_flock=$(command -v flock 2>/dev/null || true)
    cat > "$stubdir/lockf" <<'LOCKF'
#!/bin/sh
if [ "$WB_CALLER" = second ]; then
  printf '%s\n' second-attempt > "$WB_SECOND_FIFO"
fi
if [ -n "$WB_REAL_LOCKF" ]; then
  exec "$WB_REAL_LOCKF" -k 9
fi
exec "$WB_REAL_FLOCK" 9
LOCKF
    cat > "$stubdir/flock" <<'FLOCK'
#!/bin/sh
if [ "$WB_CALLER" = second ]; then
  printf '%s\n' second-attempt > "$WB_SECOND_FIFO"
fi
exec "$WB_REAL_FLOCK" 9
FLOCK
    chmod +x "$stubdir/lockf" "$stubdir/flock"
    export WB_RELEASE_FIFO="$release_fifo" WB_STARTED_FIFO="$started_fifo" WB_SECOND_FIFO="$second_fifo"
    export WB_REAL_LOCKF="$real_lockf" WB_REAL_FLOCK="$real_flock" WB_EVENTS="$events"
    (cd "$primary" && WB_CALLER=first sh "$script_abs" issue 31 graph --worktree --base HEAD --path "$fixture/work-31" >"$fixture/out1" 2>"$fixture/err1"; printf '%s\n' "$?" >"$fixture/status1") &
    first_pid=$!
    read started_token < "$started_fifo"
    Assert [ "$started_token" = first-start ]
    (cd "$primary" && WB_CALLER=second sh "$script_abs" issue 32 graph --worktree --base HEAD --path "$fixture/work-32" >"$fixture/out2" 2>"$fixture/err2"; printf '%s\n' "$?" >"$fixture/status2") &
    second_pid=$!
    read second_token < "$second_fifo"
    Assert [ "$second_token" = second-attempt ]
    The contents of file "$events" should equal "first-start"
    printf '%s\n' release > "$release_fifo"
    wait "$first_pid"
    wait "$second_pid"
    The contents of file "$events" should equal "$(printf 'first-start\nfirst-end\nsecond-start')"
    The contents of file "$fixture/status1" should equal 0
    The contents of file "$fixture/status2" should equal 0
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
    git_fixture init -q "$primary" &&
      git_fixture -C "$primary" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
        commit -q --allow-empty -m init &&
      git_fixture -C "$primary" worktree add -q --detach "$fixture/session" >/dev/null 2>&1 || return 1
    # Claim gate stub: `gh` answers from WB_ASSIGNEES (comma list, default: the
    # caller) and WB_ME; WB_GH_RC makes every gh call fail; every call is logged.
    stubdir="$fixture/bin"; mkdir -p "$stubdir"
    gh_log="$fixture/gh.log"
    cat > "$stubdir/gh" <<'GH'
#!/bin/sh
printf '%s\n' "$*" >> "$WB_GH_LOG"
[ "${WB_GH_RC:-0}" -eq 0 ] || exit "$WB_GH_RC"
case "$*" in
  "api user --jq .login") printf '%s\n' "${WB_ME:-me}" ;;
  "issue view "*"--json assignees"*) printf '%s\n' "${WB_ASSIGNEES-me}" ;;
  "issue edit "*"--add-assignee @me"*) : ;;
  *) echo "gh stub: unexpected argv: $*" >&2; exit 9 ;;
esac
GH
    chmod +x "$stubdir/gh"
    export WB_GH_LOG="$gh_log"
    codegraph_log="$fixture/codegraph.log"
    cat > "$stubdir/codegraph" <<'CODEGRAPH'
#!/bin/sh
[ "${WB_CODEGRAPH_RC:-0}" -eq 0 ] || exit "$WB_CODEGRAPH_RC"
case "$1" in
  init|index)
    printf '%s\n' "$*" >> "$WB_CODEGRAPH_LOG"
    mkdir -p "$2/.codegraph"
    true > "$2/.codegraph/codegraph.db"
    ;;
  status)
    printf '%s\n' '{"initialized":true,"worktreeMismatch":null,"index":{"reindexRecommended":false,"state":"complete","pendingRefs":0}}'
    ;;
  *) exit 9 ;;
esac
CODEGRAPH
    chmod +x "$stubdir/codegraph"
    export WB_CODEGRAPH_LOG="$codegraph_log"
    PATH="$stubdir:$PATH"; export PATH
  }
  cleanup() { rm -rf "$fixture"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'defaults the path under the primary root outside Codex'
    When run sh -c 'cd "$1" && CODEX_THREAD_ID= exec sh "$2" issue 7 tld --worktree --base HEAD' _ "$fixture/session" "$script_abs"
    The status should equal 0
    The output should equal "$(printf 'issue/7-tld\t%s/.claude/worktrees/issue-7' "$primary")"
    The stderr should include 'Preparing worktree'
  End

  It 'defaults the path under TMPDIR when run from Codex'
    When run sh -c 'cd "$1" && CODEX_THREAD_ID=thread TMPDIR="$3" exec sh "$2" issue 7 tld --worktree --base HEAD' _ "$fixture/session" "$script_abs" "$fixture"
    The status should equal 0
    The output should equal "$(printf 'issue/7-tld\t%s/pfblockerng-issue-7' "$fixture")"
    The stderr should include 'Preparing worktree'
    The contents of file "$codegraph_log" should equal "init $fixture/pfblockerng-issue-7"
    Assert [ -f "$fixture/pfblockerng-issue-7/.codegraph/codegraph.db" ]
  End

  It 'anchors a relative --path at the primary root when run from a linked worktree'
    When run sh -c 'cd "$1" && exec sh "$2" issue 8 tld --worktree --base HEAD --path wt/x' _ "$fixture/session" "$script_abs"
    The status should equal 0
    The output should equal "$(printf 'issue/8-tld\t%s/wt/x' "$primary")"
    The stderr should include 'Preparing worktree'
  End

  It 'keeps the primary-checkout default placement unchanged'
    When run sh -c 'cd "$1" && CODEX_THREAD_ID= exec sh "$2" issue 9 tld --worktree --base HEAD' _ "$primary" "$script_abs"
    The status should equal 0
    The output should equal "$(printf 'issue/9-tld\t%s/.claude/worktrees/issue-9' "$primary")"
    The stderr should include 'Preparing worktree'
  End

  It 'is immune to an inherited CDPATH when resolving the primary root'
    # A CDPATH hit makes cd echo the destination AND resolve relative to the
    # CDPATH entry instead of $PWD — either corrupts the derived root.
    When run sh -c 'mkdir -p "$3/.git" && cd "$1" && CODEX_THREAD_ID= CDPATH=$3 exec sh "$2" issue 10 tld --worktree --base HEAD' _ "$primary" "$script_abs" "$fixture/decoy"
    The status should equal 0
    The output should equal "$(printf 'issue/10-tld\t%s/.claude/worktrees/issue-10' "$primary")"
    The stderr should include 'Preparing worktree'
  End

  It 'refuses a --separate-git-dir layout instead of anchoring outside the checkout'
    git_fixture init -q --separate-git-dir "$fixture/gitmeta" "$fixture/sep" &&
      git_fixture -C "$fixture/sep" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
        commit -q --allow-empty -m init
    When run sh -c 'cd "$1/sep" && exec sh "$2" issue 11 tld --worktree --base HEAD' _ "$fixture" "$script_abs"
    The status should equal 2
    The stderr should include 'separate-git-dir'
  End

  It 'leaves an absolute --path untouched when run from a linked worktree'
    When run sh -c 'cd "$1" && exec sh "$2" issue 12 tld --worktree --base HEAD --path "$3"' _ "$fixture/session" "$script_abs" "$fixture/abs-target"
    The status should equal 0
    The output should equal "$(printf 'issue/12-tld\t%s/abs-target' "$fixture")"
    The stderr should include 'Preparing worktree'
  End
End

Describe 'work-branch.sh --worktree claim gate (workflow.md "Claim")'
  # The assignee IS the claim, set before any work: an issue worktree is refused
  # unless the issue is assigned to the caller; --claim assigns an unclaimed one.
  script_abs="${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/agent/work-branch.sh"

  setup() {
    . "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/lib/git-env-scrub.sh"
    pfb_scrub_git_env
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/wb_claim.XXXXXX") || return 1
    fixture=$(cd "$fixture" && pwd -P) || return 1
    primary="$fixture/primary"
    git_fixture init -q "$primary" &&
      git_fixture -C "$primary" -c user.email=t@t -c user.name=t -c commit.gpgsign=false \
        commit -q --allow-empty -m init || return 1
    stubdir="$fixture/bin"; mkdir -p "$stubdir"
    gh_log="$fixture/gh.log"
    cat > "$stubdir/gh" <<'GH'
#!/bin/sh
printf '%s\n' "$*" >> "$WB_GH_LOG"
[ "${WB_GH_RC:-0}" -eq 0 ] || exit "$WB_GH_RC"
case "$*" in
  "api user --jq .login") printf '%s\n' "${WB_ME:-me}" ;;
  "issue view "*"--json assignees"*) printf '%s\n' "${WB_ASSIGNEES-me}" ;;
  "issue edit "*"--add-assignee @me"*) : ;;
  *) echo "gh stub: unexpected argv: $*" >&2; exit 9 ;;
esac
GH
    chmod +x "$stubdir/gh"
    export WB_GH_LOG="$gh_log"
    codegraph_dir="$fixture/codegraph-bin"; mkdir -p "$codegraph_dir"
    codegraph_log="$fixture/codegraph.log"
    cat > "$codegraph_dir/codegraph" <<'CODEGRAPH'
#!/bin/sh
case "$1" in
  init|index)
    printf '%s\n' "$*" >> "$WB_CODEGRAPH_LOG"
    mkdir -p "$2/.codegraph"
    true > "$2/.codegraph/codegraph.db"
    ;;
  status)
    printf '%s\n' '{"initialized":true,"worktreeMismatch":null,"index":{"reindexRecommended":false,"state":"complete","pendingRefs":0}}'
    ;;
  *) exit 9 ;;
esac
CODEGRAPH
    chmod +x "$codegraph_dir/codegraph"
    export WB_CODEGRAPH_LOG="$codegraph_log"
    PATH="$stubdir:$codegraph_dir:$PATH"; export PATH
  }
  cleanup() { rm -rf "$fixture"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'refuses to cut an issue worktree when the issue is unassigned'
    When run sh -c 'cd "$1" && WB_ASSIGNEES= exec sh "$2" issue 7 tld --worktree --base HEAD' _ "$primary" "$script_abs"
    The status should equal 3
    The stderr should include 'issue #7 is not claimed'
    The stderr should include '--claim'
    Assert [ ! -e "$primary/.claude/worktrees/issue-7" ]
  End

  It 'refuses to cut an issue worktree claimed by someone else'
    When run sh -c 'cd "$1" && WB_ASSIGNEES=other exec sh "$2" issue 7 tld --worktree --base HEAD' _ "$primary" "$script_abs"
    The status should equal 3
    The stderr should include 'claimed by other'
    Assert [ ! -e "$primary/.claude/worktrees/issue-7" ]
  End

  It 'proceeds when the issue is assigned to the caller (among others)'
    When run sh -c 'cd "$1" && WB_ASSIGNEES=other,me exec sh "$2" issue 7 tld --worktree --base HEAD' _ "$primary" "$script_abs"
    The status should equal 0
    The output should equal "$(printf 'issue/7-tld\t%s/.claude/worktrees/issue-7' "$primary")"
    The stderr should include 'Preparing worktree'
  End

  It '--claim assigns an unclaimed issue to the caller and proceeds'
    When run sh -c 'cd "$1" && WB_ASSIGNEES= exec sh "$2" issue 7 tld --worktree --base HEAD --claim' _ "$primary" "$script_abs"
    The status should equal 0
    The output should equal "$(printf 'issue/7-tld\t%s/.claude/worktrees/issue-7' "$primary")"
    The stderr should include 'Preparing worktree'
    The contents of file "$gh_log" should include 'issue edit 7 --add-assignee @me'
  End

  It '--claim still refuses an issue claimed by someone else'
    When run sh -c 'cd "$1" && WB_ASSIGNEES=other exec sh "$2" issue 7 tld --worktree --base HEAD --claim' _ "$primary" "$script_abs"
    The status should equal 3
    The stderr should include 'claimed by other'
    The contents of file "$gh_log" should not include 'issue edit'
  End

  It 'warns and proceeds when gh cannot answer (MCP-only or offline sessions verify the claim themselves)'
    When run sh -c 'cd "$1" && WB_GH_RC=1 exec sh "$2" issue 7 tld --worktree --base HEAD' _ "$primary" "$script_abs"
    The status should equal 0
    The output should equal "$(printf 'issue/7-tld\t%s/.claude/worktrees/issue-7' "$primary")"
    The stderr should include 'claim NOT verified'
    The stderr should include 'issue #7'
  End

  It 'warns and proceeds when gh is not installed at all'
    When run sh -c 'cd "$1" && PATH="$4:$3" exec sh "$2" issue 7 tld --worktree --base HEAD' _ "$primary" "$script_abs" "$(dirname "$(command -v git)"):/usr/bin:/bin" "$codegraph_dir"
    The status should equal 0
    The output should equal "$(printf 'issue/7-tld\t%s/.claude/worktrees/issue-7' "$primary")"
    The stderr should include 'claim NOT verified'
  End

  It 'does not gate ADR worktrees on a claim'
    When run sh -c 'cd "$1" && WB_GH_RC=1 exec sh "$2" adr 9 x --worktree --base HEAD' _ "$primary" "$script_abs"
    The status should equal 0
    The output should equal "$(printf 'adr/9-x\t%s/.claude/worktrees/adr-9' "$primary")"
    The stderr should include 'Preparing worktree'
    Assert [ ! -e "$gh_log" ]
  End

  It 'does not touch gh when only printing the branch name'
    When run sh -c 'cd "$1" && WB_GH_RC=1 exec sh "$2" issue 7 tld' _ "$primary" "$script_abs"
    The status should equal 0
    The output should equal 'issue/7-tld'
    Assert [ ! -e "$gh_log" ]
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

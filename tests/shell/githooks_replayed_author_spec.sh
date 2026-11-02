#shellcheck shell=sh
# .githooks/prepare-commit-msg and .githooks/pre-push replayed-author rule
# (issue #3642): an agent commit keeps the configured committer and signature,
# but its AUTHOR may be someone else when the commit replays a published commit
# (rebase, cherry-pick): same author name, email and author timestamp as a commit
# reachable from a remote-tracking ref. A fresh `--author=` commit is still refused.
#
# Fixture: a bare remote, clone A (the agent, configured user A <a@example.com>,
# SSH-signing) and clone B (a co-maintainer who publishes the foreign commits).
# prepare-commit-msg rows feed the hook the identity git hands it during a
# conflicted rebase pick (GIT_AUTHOR_* in the environment); R2 is a real
# `git rebase --continue`. pre-push rows feed the hook an outgoing signed commit.

Describe 'agent replay of a published foreign author (issue #3642)'
  pcm="${PFB_ROOT}/.githooks/prepare-commit-msg"
  pre_push="${PFB_ROOT}/.githooks/pre-push"
  Z40="0000000000000000000000000000000000000000"
  REFUSED='Agent commits must use the configured user identity'
  PUBLISHED_AT='1577836800 +0000'
  OTHER_AT='1577923200 +0000'
  # shellcheck disable=SC2016 # literal metacharacters are the point
  META_NAME='A.* |"q" $x'

  setup() {
    scrub_git_env
    base="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/replayauthor.XXXXXX")"
    ssh-keygen -q -t ed25519 -N '' -C a@example.com -f "${base}/signing_key"
    { printf 'a@example.com '; cat "${base}/signing_key.pub"; } >"${base}/allowed_signers"
    git_fixture init -q --bare "${base}/remote.git"
    git_fixture clone -q "${base}/remote.git" "${base}/A" 2>/dev/null
    git_fixture clone -q "${base}/remote.git" "${base}/B" 2>/dev/null
    git_fixture -C "${base}/A" config user.email a@example.com
    git_fixture -C "${base}/A" config user.name A
    git_fixture -C "${base}/A" config gpg.format ssh
    git_fixture -C "${base}/A" config user.signingkey "${base}/signing_key"
    git_fixture -C "${base}/A" config gpg.ssh.allowedSignersFile "${base}/allowed_signers"
    git_fixture -C "${base}/A" config commit.gpgsign true
    git_fixture -C "${base}/A" config pfblockerng.allowprimarycommit true
    git_fixture -C "${base}/B" config user.email b@example.com
    git_fixture -C "${base}/B" config user.name B
    git_fixture -C "${base}/B" config commit.gpgsign false
    ( cd "${base}/B" && git_fixture checkout -q -b devel && echo one > f \
        && git_fixture add f && git_fixture commit -q -m base \
        && git_fixture push -q origin devel )
    base_sha="$(git_fixture -C "${base}/B" rev-parse HEAD)"
  }

  cleanup() {
    rm -rf "$base"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  # Run a command as an agent session; the suite itself may run under any marker.
  agent_env() {
    env -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID -u COPILOT_AGENT_PROMPT \
      -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT -u OMP_CLI -u PI_CLI \
      CLAUDECODE=1 "$@"
  }
  agent_git() {
    agent_env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null git "$@"
  }

  # Co-maintainer B publishes a commit authored by "$1 <$2>" at "$3" on devel;
  # A fetches it, so it is reachable from refs/remotes/origin/devel.
  publish_foreign() {
    ( cd "${base}/B" && echo "foreign $1" > f && git_fixture add f \
        && GIT_AUTHOR_NAME="$1" GIT_AUTHOR_EMAIL="$2" GIT_AUTHOR_DATE="$3" \
          git_fixture commit -q -m foreign \
        && git_fixture push -q origin devel ) || return 1
    git_fixture -C "${base}/A" fetch -q origin || return 1
    foreign_sha="$(git_fixture -C "${base}/B" rev-parse HEAD)"
  }

  # --- prepare-commit-msg: identity handed to the hook by a conflicted pick ---
  pcm_as() {
    printf 'msg\n' > "${base}/MSG"
    cd "${base}/A" && agent_env GIT_AUTHOR_NAME="$1" GIT_AUTHOR_EMAIL="$2" \
      GIT_AUTHOR_DATE="$3" GIT_COMMITTER_NAME="${4:-A}" \
      GIT_COMMITTER_EMAIL="${5:-a@example.com}" sh "${PCM_HOOK:-$pcm}" "${base}/MSG" message
  }

  pcm_after_publish() {
    publish_foreign "$1" "$2" "$3" || return 1
    pcm_as "$4" "$5" "$6" "${7:-A}" "${8:-a@example.com}"
  }

  # The hook alone, without replayed-author.sh beside it: a foreign author must fail closed.
  lone_hook() {
    mkdir -p "${base}/lone" && cp "$1" "${base}/lone/" && printf '%s\n' "${base}/lone/$(basename "$1")"
  }

  pcm_without_helper() {
    PCM_HOOK="$(lone_hook "$pcm")" pcm_after_publish Other o@x.io "$PUBLISHED_AT" Other o@x.io "$PUBLISHED_AT"
  }

  # --- pre-push: an outgoing signed agent commit on a new branch ---
  pre_push_run() {
    update="refs/heads/work $(git_fixture -C "${base}/A" rev-parse refs/heads/work) refs/heads/work $Z40"
    cd "${base}/A" && printf '%s\n' "$update" \
      | agent_env sh "${PRE_PUSH_HOOK:-$pre_push}" origin "${base}/remote.git"
  }

  pre_push_without_helper() {
    PRE_PUSH_HOOK="$(lone_hook "$pre_push")" outgoing_after_publish Other o@x.io "$PUBLISHED_AT" Other o@x.io "$PUBLISHED_AT"
  }

  outgoing_fresh() { # author_name author_email author_date [committer_name committer_email]
    cd "${base}/A" || return 1
    git_fixture fetch -q origin || return 1
    git_fixture checkout -q -B work origin/devel || return 1
    echo "fresh $1" >> g
    git_fixture add g || return 1
    agent_env GIT_AUTHOR_NAME="$1" GIT_AUTHOR_EMAIL="$2" GIT_AUTHOR_DATE="$3" \
      GIT_COMMITTER_NAME="${4:-A}" GIT_COMMITTER_EMAIL="${5:-a@example.com}" \
      GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
      git -c core.hooksPath=/dev/null commit -q -m fresh || return 1 # git-env-scrub-guard: agent-env commit under test
    pre_push_run
  }

  outgoing_after_publish() { # fname fmail fdate  aname amail adate [cname cmail]
    publish_foreign "$1" "$2" "$3" || return 1
    outgoing_fresh "$4" "$5" "$6" "${7:-A}" "${8:-a@example.com}"
  }

  outgoing_cherry_pick() {
    publish_foreign Other o@x.io "$PUBLISHED_AT" || return 1
    cd "${base}/A" || return 1
    git_fixture checkout -q -B work "$base_sha" || return 1
    echo mine > g
    git_fixture add g || return 1
    git_fixture -c core.hooksPath=/dev/null commit -q -m mine || return 1
    agent_git -c core.hooksPath=/dev/null cherry-pick "$foreign_sha" >/dev/null || return 1
    pre_push_run
  }

  # R2: real conflicted rebase of a fetched foreign commit, prepare-commit-msg live.
  rebase_foreign() {
    publish_foreign Other o@x.io "$PUBLISHED_AT" || return 1
    cp -R "${PFB_ROOT}/.githooks" "${base}/hooks" || return 1
    rm -f "${base}/hooks/pre-commit"
    cd "${base}/A" || return 1
    git_fixture checkout -q -B rb "$foreign_sha" || return 1
    git_fixture checkout -q -B newbase "$base_sha" || return 1
    echo mine > f
    git_fixture add f || return 1
    git_fixture -c core.hooksPath=/dev/null commit -q -m newbase || return 1
    git_fixture checkout -q rb || return 1
    agent_git -c "core.hooksPath=${base}/hooks" -c commit.gpgsign=false \
      rebase --onto newbase "$base_sha" rb >/dev/null 2>&1 && return 1 # must stop on the conflict
    echo resolved > f
    git_fixture add f || return 1
    agent_git -c "core.hooksPath=${base}/hooks" -c commit.gpgsign=false -c core.editor=true \
      rebase --continue >/dev/null 2>&1 || return 1
    git_fixture log -1 --format='%an <%ae> %at %cn <%ce>' rb
  }

  Describe 'prepare-commit-msg'
    It 'R1: accepts a foreign author matching a published commit exactly'
      When run pcm_after_publish Other o@x.io "$PUBLISHED_AT" Other o@x.io "$PUBLISHED_AT"
      The status should equal 0
      The stderr should equal ''
    End

    It 'R2: a real rebase of a fetched foreign commit completes'
      When run rebase_foreign
      The status should equal 0
      The output should equal 'Other <o@x.io> 1577836800 A <a@example.com>'
    End

    It 'R3: rejects a fresh foreign author nobody published'
      When run pcm_as Other o@x.io "$PUBLISHED_AT"
      The status should equal 1
      The stderr should equal "$REFUSED"
    End

    It 'R4: rejects a published foreign name and email at a different author timestamp'
      When run pcm_after_publish Other o@x.io "$PUBLISHED_AT" Other o@x.io "$OTHER_AT"
      The status should equal 1
      The stderr should equal "$REFUSED"
    End

    It 'R4b: rejects a published foreign timestamp under a different email'
      When run pcm_after_publish Other o@x.io "$PUBLISHED_AT" Other other@x.io "$PUBLISHED_AT"
      The status should equal 1
      The stderr should equal "$REFUSED"
    End

    It 'R5: rejects a replayed author when the committer is overridden'
      When run pcm_after_publish Other o@x.io "$PUBLISHED_AT" Other o@x.io "$PUBLISHED_AT" Other o@x.io
      The status should equal 1
      The stderr should equal "$REFUSED"
    End

    It 'R6: accepts a published author name full of regex and shell metacharacters'
      When run pcm_after_publish "$META_NAME" meta@x.io "$PUBLISHED_AT" "$META_NAME" meta@x.io "$PUBLISHED_AT"
      The status should equal 0
      The stderr should equal ''
    End

    It 'R6b: rejects a name a published name would only match as a pattern (Ax published, A. asked)'
      When run pcm_after_publish Ax meta@x.io "$PUBLISHED_AT" 'A.' meta@x.io "$PUBLISHED_AT"
      The status should equal 1
      The stderr should equal "$REFUSED"
    End

    It 'R6c: rejects a prefix of a published name (Other Person published, Other asked)'
      When run pcm_after_publish 'Other Person' o@x.io "$PUBLISHED_AT" Other o@x.io "$PUBLISHED_AT"
      The status should equal 1
      The stderr should equal "$REFUSED"
    End

    It 'R8: fails closed when the replayed-author helper is missing'
      When run pcm_without_helper
      The status should equal 1
      The stderr should include 'replayed-author helper missing'
    End

    It 'R7: still accepts the configured user as author'
      When run pcm_as A a@example.com "$PUBLISHED_AT"
      The status should equal 0
      The stderr should equal ''
    End
  End

  Describe 'pre-push'
    It 'R1: accepts a signed cherry-pick of a published foreign commit'
      When run outgoing_cherry_pick
      The status should equal 0
      The stderr should equal ''
    End

    It 'R1b: accepts a signed commit whose foreign author matches a published commit'
      When run outgoing_after_publish Other o@x.io "$PUBLISHED_AT" Other o@x.io "$PUBLISHED_AT"
      The status should equal 0
      The stderr should equal ''
    End

    It 'R3: rejects a signed fresh foreign-author commit nobody published'
      When run outgoing_fresh Other o@x.io "$PUBLISHED_AT"
      The status should equal 1
      The stderr should equal "$REFUSED"
    End

    It 'R4: rejects a published foreign name and email at a different author timestamp'
      When run outgoing_after_publish Other o@x.io "$PUBLISHED_AT" Other o@x.io "$OTHER_AT"
      The status should equal 1
      The stderr should equal "$REFUSED"
    End

    It 'R5: rejects a replayed author when the committer is overridden'
      When run outgoing_after_publish Other o@x.io "$PUBLISHED_AT" Other o@x.io "$PUBLISHED_AT" Other o@x.io
      The status should equal 1
      The stderr should equal "$REFUSED"
    End

    It 'R6: accepts a published author name full of regex and shell metacharacters'
      When run outgoing_after_publish "$META_NAME" meta@x.io "$PUBLISHED_AT" "$META_NAME" meta@x.io "$PUBLISHED_AT"
      The status should equal 0
      The stderr should equal ''
    End

    It 'R6b: rejects a name a published name would only match as a pattern (Ax published, A. asked)'
      When run outgoing_after_publish Ax meta@x.io "$PUBLISHED_AT" 'A.' meta@x.io "$PUBLISHED_AT"
      The status should equal 1
      The stderr should equal "$REFUSED"
    End

    It 'R6c: rejects a prefix of a published name (Other Person published, Other asked)'
      When run outgoing_after_publish 'Other Person' o@x.io "$PUBLISHED_AT" Other o@x.io "$PUBLISHED_AT"
      The status should equal 1
      The stderr should equal "$REFUSED"
    End

    It 'R8: fails closed when the replayed-author helper is missing'
      When run pre_push_without_helper
      The status should equal 1
      The stderr should include 'replayed-author helper missing'
    End

    It 'R7: still accepts a signed commit by the configured user'
      When run outgoing_fresh A a@example.com "$PUBLISHED_AT"
      The status should equal 0
      The stderr should equal ''
    End
  End
End

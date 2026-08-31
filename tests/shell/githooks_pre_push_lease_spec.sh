#shellcheck shell=sh
# .githooks/pre-push agent lease-by-effect guard (issue #1307): a recognized
# Claude, Codex, Copilot, Grok, or OMP/Pi session that rewrites a remote branch's
# history is allowed only
# when the hook's advertised remote oid equals the local remote-tracking ref —
# i.e. the agent has fetched the history it is about to overwrite. That is
# --force-with-lease's check, enforced on the push's EFFECT, so an alias or a
# script that never spells a force flag is still caught. Fast-forwards, branch
# creations/deletions, tag refs, and sessions with no recognized agent marker pass untouched.
#
# Fixture: a bare remote, clone A (the agent, whose tracking ref goes stale),
# and clone B (another session that advances the remote behind A's back).
# Direct rows feed the hook its stdin contract ("<lref> <lsha> <rref> <rsha>")
# from A; the integration rows run a real `git push --force` through
# core.hooksPath with a human control proving the deny is caused by the guard.

Describe 'pre-push agent lease-by-effect guard (issue #1307)'
  hook="${PFB_ROOT}/.githooks/pre-push"
  Z40="0000000000000000000000000000000000000000"

  setup() {
    scrub_git_env
    base="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/prepushlease.XXXXXX")"
    gpg_home=''
    ssh-keygen -q -t ed25519 -N '' -C a@example.com -f "${base}/signing_key"
    { printf 'a@example.com '; cat "${base}/signing_key.pub"; } >"${base}/allowed_signers"
    git_fixture init -q --bare "${base}/remote.git"
    git_fixture clone -q "${base}/remote.git" "${base}/A" 2>/dev/null
    git_fixture -C "${base}/A" config user.email a@example.com
    git_fixture -C "${base}/A" config user.name A
    git_fixture -C "${base}/A" config gpg.format ssh
    git_fixture -C "${base}/A" config user.signingkey "${base}/signing_key"
    git_fixture -C "${base}/A" config gpg.ssh.allowedSignersFile "${base}/allowed_signers"
    git_fixture -C "${base}/A" config commit.gpgsign true
    ( cd "${base}/A" && git_fixture checkout -q -b devel && echo one > f \
        && git_fixture add f && git_fixture commit -q -m c1 && git_fixture push -q origin devel )
    git_fixture clone -q "${base}/remote.git" "${base}/B" 2>/dev/null
    git_fixture -C "${base}/B" config user.email b@example.com
    git_fixture -C "${base}/B" config user.name B
    git_fixture -C "${base}/B" config commit.gpgsign false
    ( cd "${base}/B" && git_fixture checkout -q devel && echo two >> f \
        && git_fixture add f && git_fixture commit -q -m c2-other && git_fixture push -q origin devel )
    # A now diverges; its tracking ref still holds c1 while the remote is at c2.
    ( cd "${base}/A" && git_fixture commit -q --amend -m c1-amended )
    a_local="$(git_fixture -C "${base}/A" rev-parse devel)"
    a_tracking="$(git_fixture -C "${base}/A" rev-parse refs/remotes/origin/devel)"
    remote_tip="$(git_fixture -C "${base}/remote.git" rev-parse refs/heads/devel)"
  }

  cleanup() {
    rm -rf "$base"
    [ -z "${gpg_home:-}" ] || rm -rf "$gpg_home"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  remote_tip_now() {
    git_fixture -C "${base}/remote.git" rev-parse refs/heads/devel
  }

  # Feed one stdin line to the hook from inside clone A, agent env explicit
  # per row (the suite itself may run under CLAUDECODE=1).
  agent_hook() {
    cd "${base}/A" && printf '%s\n' "$1" \
      | env -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID -u COPILOT_AGENT_PROMPT \
        -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT -u OMP_CLI -u PI_CLI \
        CLAUDECODE=1 sh "$hook" origin "${base}/remote.git"
  }
  codex_hook() {
    cd "${base}/A" && printf '%s\n' "$1" \
      | env -u CLAUDE_CODE_USER_EMAIL -u CLAUDECODE -u COPILOT_AGENT_PROMPT \
        -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT -u OMP_CLI -u PI_CLI \
        CODEX_THREAD_ID=codex-test \
        sh "$hook" origin "${base}/remote.git"
  }
  grok_hook() {
    cd "${base}/A" && printf '%s\n' "$1" \
      | env -u CLAUDE_CODE_USER_EMAIL -u CLAUDECODE -u COPILOT_AGENT_PROMPT \
        -u COPILOT_CLI -u CODEX_THREAD_ID -u OMP_CLI -u PI_CLI \
        GROK_AGENT=1 GROK_SESSION_ID=grok-test \
        sh "$hook" origin "${base}/remote.git"
  }
  omp_hook() {
    cd "${base}/A" && printf '%s\n' "$1" \
      | env -u CLAUDE_CODE_USER_EMAIL -u CLAUDECODE -u CODEX_THREAD_ID \
        -u COPILOT_AGENT_PROMPT -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
        -u PI_CLI OMP_CLI=1 sh "$hook" origin "${base}/remote.git"
  }
  pi_hook() {
    cd "${base}/A" && printf '%s\n' "$1" \
      | env -u CLAUDE_CODE_USER_EMAIL -u CLAUDECODE -u CODEX_THREAD_ID \
        -u COPILOT_AGENT_PROMPT -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
        -u OMP_CLI PI_CLI=1 sh "$hook" origin "${base}/remote.git"
  }
  human_hook() {
    cd "${base}/A" && printf '%s\n' "$1" \
      | env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
        -u COPILOT_AGENT_PROMPT -u COPILOT_CLI \
        -u GROK_SESSION_ID -u GROK_AGENT -u OMP_CLI -u PI_CLI \
        sh "$hook" origin "${base}/remote.git"
  }

  outgoing_agent_hook() {
    mode=$1
    author_name=$2
    author_email=$3
    committer_name=$4
    committer_email=$5
    target_branch=${6:-devel}
    runtime=${7:-agent}
    cd "${base}/A" || return 1
    git_fixture fetch -q origin || return 1
    git_fixture checkout -q -B integrity origin/devel || return 1
    signing_key_override=''

    case "$mode" in
      openpgp)
        gpg_home="$(mktemp -d "${TMPDIR:-/tmp}/pfb-gpg.XXXXXX")" || return 1
        chmod 700 "$gpg_home" || return 1
        GNUPGHOME=$gpg_home
        export GNUPGHOME
        if ! gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
          --quick-generate-key 'A <a@example.com>' ed25519 sign 0 >"${base}/gpg-keygen.log" 2>&1; then
          cat "${base}/gpg-keygen.log" >&2
          return 1
        fi
        git_fixture config gpg.format openpgp || return 1
        openpgp_fingerprint=$(
          gpg --batch --with-colons --list-secret-keys 2>/dev/null |
            awk -F: '$1 == "fpr" { print $10; exit }'
        )
        [ -n "$openpgp_fingerprint" ] || return 1
        git_fixture config user.signingkey "$openpgp_fingerprint" || return 1
        ;;
      wrong-signer|wrong-key-same-email)
        if [ "$mode" = wrong-signer ]; then
          signing_principal=other@example.com
        else
          signing_principal=a@example.com
        fi
        ssh-keygen -q -t ed25519 -N '' -C "$signing_principal" \
          -f "${base}/other_signing_key" || return 1
        { printf '%s ' "$signing_principal"; cat "${base}/other_signing_key.pub"; } \
          >>"${base}/allowed_signers"
        signing_key_override="${base}/other_signing_key"
        ;;
    esac

    printf '%s\n' "$mode" >>f
    git_fixture add f || return 1
    printf 'integrity fixture\n' >"${base}/commit-message"
    case "$mode" in
      coauthor|tag-lightweight|tag-annotated)
        printf '\nCo-authored-by: Other <other@example.com>\n' >>"${base}/commit-message"
        ;;
      coauthor-space)
        printf '\nCo-authored-by   : Other <other@example.com>\n' >>"${base}/commit-message"
        ;;
      coauthor-tab)
        printf '\nCo-authored-by\t:\tOther <other@example.com>\n' >>"${base}/commit-message"
        ;;
    esac

    set -- -c core.hooksPath=/dev/null commit -q -F "${base}/commit-message"
    case "$mode" in
      unsigned|unsigned-then-valid)
        set -- -c core.hooksPath=/dev/null commit -q --no-gpg-sign \
          -F "${base}/commit-message"
        ;;
    esac
    case "$mode" in
      wrong-signer|wrong-key-same-email)
        set -- -c core.hooksPath=/dev/null \
          -c "user.signingkey=${signing_key_override}" \
          commit -q -F "${base}/commit-message"
        ;;
    esac
    CLAUDECODE=1 \
      GIT_AUTHOR_NAME="$author_name" GIT_AUTHOR_EMAIL="$author_email" \
      GIT_COMMITTER_NAME="$committer_name" GIT_COMMITTER_EMAIL="$committer_email" \
      git_fixture "$@" || return 1

    if [ "$mode" = unsigned-then-valid ]; then
      printf 'valid tip\n' >>f
      git_fixture add f || return 1
      CLAUDECODE=1 \
        GIT_AUTHOR_NAME="$author_name" GIT_AUTHOR_EMAIL="$author_email" \
        GIT_COMMITTER_NAME="$committer_name" GIT_COMMITTER_EMAIL="$committer_email" \
        git_fixture -c core.hooksPath=/dev/null commit -q -m 'valid tip' || return 1
    fi

    local_sha=$(git_fixture rev-parse refs/heads/integrity) || return 1
    if [ "$mode" = openpgp ]; then
      git_fixture log -1 --format='%%G?=%G?%n%%GS=%GS' "$local_sha" || return 1
    fi
    case "$mode" in
      wrong-signer|wrong-key-same-email)
        signature_metadata=$(
          git_fixture log -1 --format='%G?|%GS|%GF' "$local_sha"
        ) || return 1
        signature_status=${signature_metadata%%|*}
        signature_rest=${signature_metadata#*|}
        signature_signer=${signature_rest%%|*}
        signature_fingerprint=${signature_rest#*|}
        configured_fingerprint=$(
          ssh-keygen -lf "${base}/signing_key.pub" | awk '{ print $2 }'
        ) || return 1
        if [ "$mode" = wrong-signer ]; then
          expected_signer=other@example.com
        else
          expected_signer=a@example.com
        fi
        [ "$signature_status" = G ] || return 1
        [ "$signature_signer" = "$expected_signer" ] || return 1
        [ -n "$configured_fingerprint" ] || return 1
        [ "$signature_fingerprint" != "$configured_fingerprint" ] || return 1
        printf '%%G?=%s\n%%GS=%s\n%%GF!=configured=true\n' \
          "$signature_status" "$signature_signer"
        ;;
    esac

    case "$mode" in
      tag-lightweight)
        git_fixture tag scratch-bad "$local_sha" || return 1
        tag_sha=$(git_fixture rev-parse refs/tags/scratch-bad) || return 1
        human_hook "refs/tags/scratch-bad $tag_sha refs/tags/scratch-bad $Z40"
        return
        ;;
      tag-annotated)
        git_fixture tag -a -m 'scratch bad' scratch-bad "$local_sha" || return 1
        tag_sha=$(git_fixture rev-parse refs/tags/scratch-bad) || return 1
        human_hook "refs/tags/scratch-bad $tag_sha refs/tags/scratch-bad $Z40"
        return
        ;;
    esac

    if [ "$target_branch" = new ]; then
      remote_sha=$Z40
    else
      remote_sha=$(git_fixture rev-parse "refs/remotes/origin/${target_branch}") || return 1
    fi
    update="refs/heads/integrity $local_sha refs/heads/${target_branch} $remote_sha"
    if [ "$runtime" = human ]; then
      human_hook "$update"
    else
      agent_hook "$update"
    fi
  }

  It 'denies an agent history rewrite when the remote moved past the tracking ref'
    When run agent_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 1
    The stderr should include 'unfetched'
    The stderr should include 'git fetch origin'
  End

  It 'allows the same rewrite once the tracking ref matches the advertised remote'
    git_fixture -C "${base}/A" fetch -q origin
    fresh_tracking() {
      tracking="$(git_fixture -C "${base}/A" rev-parse refs/remotes/origin/devel)"
      [ "$tracking" = "$remote_tip" ] || { echo "tracking=$tracking != remote=$remote_tip" >&2; return 1; }
      agent_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    }
    When run fresh_tracking
    The status should equal 0
    The stderr should equal ''
  End

  It 'denies the same stale rewrite for a Codex session'
    When run codex_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 1
    The stderr should include 'unfetched'
  End

  It 'denies the same stale rewrite for a Grok session'
    When run grok_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 1
    The stderr should include 'unfetched'
  End

  It 'denies the same stale rewrite for an OMP session'
    When run omp_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 1
    The stderr should include 'unfetched'
  End

  It 'denies the same stale rewrite for a Pi-compatible session'
    When run pi_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 1
    The stderr should include 'unfetched'
  End

  It 'allows an agent fast-forward push with a stale tracking ref'
    ff_push() {
      cd "${base}/A" && git_fixture fetch -q origin \
        && git_fixture update-ref refs/remotes/origin/devel "$a_tracking" \
        && git_fixture checkout -q -B devel "$remote_tip" && echo three >> f \
        && git_fixture add f && git_fixture commit -q -m c3 \
        && agent_hook "refs/heads/devel $(git_fixture rev-parse devel) refs/heads/devel $remote_tip"
    }
    When run ff_push
    The status should equal 0
    The stderr should equal ''
  End

  It 'allows an agent branch creation'
    When run agent_hook "refs/heads/new $a_local refs/heads/new $Z40"
    The status should equal 0
    The stderr should equal ''
  End

  It 'allows an agent branch deletion'
    When run agent_hook "refs/heads/devel $Z40 refs/heads/devel $remote_tip"
    The status should equal 0
    The stderr should equal ''
  End

  It 'ignores tag refs (a non-version tag passes untouched)'
    When run agent_hook "refs/tags/scratch $a_local refs/tags/scratch $remote_tip"
    The status should equal 0
    The stderr should equal ''
  End

  It 'denies a multi-ref push whose second ref is the stale rewrite'
    two_refs() {
      cd "${base}/A" && printf '%s\n%s\n' \
        "refs/heads/new $a_local refs/heads/new $Z40" \
        "refs/heads/devel $a_local refs/heads/devel $remote_tip" \
        | env -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID -u COPILOT_AGENT_PROMPT \
          -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          CLAUDECODE=1 sh "$hook" origin "${base}/remote.git"
    }
    When run two_refs
    The status should equal 1
    The stderr should include 'unfetched'
  End

  It 'leaves a human history rewrite to git itself'
    When run human_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 0
    The stderr should equal ''
  End

  It 'allows a signed outgoing agent commit with the configured identity'
    When call outgoing_agent_hook valid A a@example.com A a@example.com
    The status should equal 0
    The stderr should equal ''
  End

  It 'allows an OpenPGP-signed outgoing commit from the configured identity'
    When call outgoing_agent_hook openpgp A a@example.com A a@example.com
    The status should equal 0
    The output should equal "$(printf '%s\n%s' '%G?=G' '%GS=A <a@example.com>')"
    The stderr should equal ''
  End

  It 'allows a new branch whose existing base is already reachable from origin'
    When call outgoing_agent_hook valid A a@example.com A a@example.com new
    The status should equal 0
    The stderr should equal ''
  End

  It 'rejects a markerless human commit containing a Co-authored-by trailer'
    When call outgoing_agent_hook coauthor A a@example.com A a@example.com devel human
    The status should equal 1
    The stderr should equal 'Co-authored-by trailers are forbidden'
  End

  Context 'outgoing non-version tag attribution'
    Parameters
      tag-lightweight lightweight
      tag-annotated   annotated
    End

    It "rejects a $2 tag whose peeled commit contains a Co-authored-by trailer"
      When call outgoing_agent_hook "$1" A a@example.com A a@example.com
      The status should equal 1
      The stderr should equal 'Co-authored-by trailers are forbidden'
    End
  End

  Context 'outgoing agent commit integrity'
    Parameters
      coauthor        A       a@example.com     A       a@example.com     'Co-authored-by trailers are forbidden'
      coauthor-space  A       a@example.com     A       a@example.com     'Co-authored-by trailers are forbidden'
      coauthor-tab    A       a@example.com     A       a@example.com     'Co-authored-by trailers are forbidden'
      unsigned        A       a@example.com     A       a@example.com     'Agent commits must be signed by the configured user identity'
      unsigned-then-valid A   a@example.com     A       a@example.com     'Agent commits must be signed by the configured user identity'
      author-name     Other   a@example.com     A       a@example.com     'Agent commits must use the configured user identity'
      author-email    A       other@example.com A       a@example.com     'Agent commits must use the configured user identity'
      committer-name  A       a@example.com     Other   a@example.com     'Agent commits must use the configured user identity'
      committer-email A       a@example.com     A       other@example.com 'Agent commits must use the configured user identity'
    End

    It "rejects an outgoing $1 commit"
      When call outgoing_agent_hook "$1" "$2" "$3" "$4" "$5"
      The status should equal 1
      The stderr should equal "$6"
    End
  End

  Context 'outgoing SSH signer binding'
    Parameters
      wrong-signer         other@example.com
      wrong-key-same-email a@example.com
    End

    It "rejects a good signature from unconfigured key mode $1"
      When call outgoing_agent_hook "$1" A a@example.com A a@example.com
      The status should equal 1
      The output should equal "$(printf '%s\n%s\n%s' \
        '%G?=G' "%GS=$2" '%GF!=configured=true')"
      The stderr should equal 'Agent commits must be signed by the configured user identity'
    End
  End

  # The money rows: a REAL bare force push through core.hooksPath. The human
  # control proves the abort is caused by the guard, not the harness setup.
  It 'blocks a real agent force-push and leaves the remote tip untouched'
    real_force() {
      cd "${base}/A" \
        && git_fixture config core.hooksPath "${PFB_ROOT}/.githooks" \
        && [ "$(remote_tip_now)" = "$remote_tip" ] \
        && env -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID -u COPILOT_AGENT_PROMPT \
          -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          CLAUDECODE=1 git push --force origin devel # git-env-scrub-guard: allow hook-under-test push
    }
    When run real_force
    The status should not equal 0
    The stderr should include 'unfetched'
    The result of function remote_tip_now should equal "$remote_tip"
  End

  It 'blocks the same real force-push for a Codex agent marker'
    real_force_codex() {
      cd "${base}/A" \
        && git_fixture config core.hooksPath "${PFB_ROOT}/.githooks" \
        && [ "$(remote_tip_now)" = "$remote_tip" ] \
        && env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u COPILOT_AGENT_PROMPT \
          -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          CODEX_THREAD_ID=codex-test git push --force origin devel # git-env-scrub-guard: allow hook-under-test push
    }
    When run real_force_codex
    The status should not equal 0
    The stderr should include 'unfetched'
    The result of function remote_tip_now should equal "$remote_tip"
  End

  It 'blocks the same real force-push for a Grok agent marker'
    real_force_grok() {
      cd "${base}/A" \
        && git_fixture config core.hooksPath "${PFB_ROOT}/.githooks" \
        && [ "$(remote_tip_now)" = "$remote_tip" ] \
        && env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
          -u COPILOT_AGENT_PROMPT -u COPILOT_CLI \
          GROK_AGENT=1 GROK_SESSION_ID=grok-test \
          git push --force origin devel # git-env-scrub-guard: allow hook-under-test push
    }
    When run real_force_grok
    The status should not equal 0
    The stderr should include 'unfetched'
    The result of function remote_tip_now should equal "$remote_tip"
  End

  It 'lands the same real force-push for a human (control)'
    real_force_human() {
      cd "${base}/A" \
        && git_fixture config core.hooksPath "${PFB_ROOT}/.githooks" \
        && [ "$(remote_tip_now)" = "$remote_tip" ] \
        && env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
          -u COPILOT_AGENT_PROMPT -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          -u OMP_CLI -u PI_CLI \
          git push --force origin devel # git-env-scrub-guard: allow hook-under-test push
    }
    When run real_force_human
    The status should equal 0
    The result of function remote_tip_now should equal "$a_local"
  End
End

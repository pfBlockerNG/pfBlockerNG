#shellcheck shell=sh
# Commit identity & signing prerequisite gate (issue #2982): the checker rejects
# placeholder/generic author and committer identity (config and GIT_* overrides)
# and missing signing prerequisites fail-closed; the pre-commit hook runs it even
# for allow-empty commits (before the no-staged exit), resolves it relative to $0,
# and fails closed on a missing or non-executable checker without suppressing the
# other staged gates. A PATH of only test stubs proves binary selection without
# host leakage; no signing-key material is ever printed.

Describe '.githooks/check-commit-identity.sh + pre-commit wiring (issue #2982)'
  gitc() { git_fixture -C "$repo" "$@"; }

  # Sandbox repo with a fully VALID baseline (identity + SSH signing); each
  # example overrides exactly one prerequisite, so failures are deterministic.
  make_repo() {
    scrub_git_env
    export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
    repo="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/precommit-identity.XXXXXX")"
    stubdir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/precommit-identity-stub.XXXXXX")"
    git_fixture -C "$repo" init -q
    gitc config user.name 'Andre Brait'
    gitc config user.email 'andrebrait@gmail.com'
    gitc config commit.gpgsign true
    gitc config gpg.format ssh
    true > "$repo/key.pub"
    gitc config user.signingkey "$repo/key.pub"
    mkdir -p "$repo/.githooks"
    cp "$PFB_ROOT/.githooks/pre-commit" "$repo/.githooks/pre-commit"
    if [ -f "$PFB_ROOT/.githooks/check-commit-identity.sh" ]; then
      cp "$PFB_ROOT/.githooks/check-commit-identity.sh" "$repo/.githooks/"
      chmod +x "$repo/.githooks/check-commit-identity.sh"
    fi
    PATH="$stubdir:$PATH"
  }
  cleanup() {
    rm -rf "$repo" "$stubdir"
    unset GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM
  }
  Before 'make_repo'
  After 'cleanup'

  # ------------- identity: effective config (author and committer) ------------- #

  Describe 'generic placeholder author name variants'
    Parameters
      'Verifier'
      'verifier'
      '  VERIFIER  '
      'root'
      'ROOT'
      'ci'
    End

    It 'rejects the name case- and whitespace-insensitively'
      gitc config user.name "$1"
      When run sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
      The status should equal 1
      The stderr should include "[check-commit-identity] FAILED: author name is a generic placeholder: '$1'"
    End
  End

  It 'rejects a generic placeholder committer name from GIT_COMMITTER_NAME despite valid config'
    When run env GIT_COMMITTER_NAME=Verifier sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
    The status should equal 1
    The stderr should include "[check-commit-identity] FAILED: committer name is a generic placeholder: 'Verifier'"
  End

  It 'rejects a generic placeholder author name from GIT_AUTHOR_NAME despite valid config'
    When run env GIT_AUTHOR_NAME=verifier sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
    The status should equal 1
    The stderr should include "[check-commit-identity] FAILED: author name is a generic placeholder: 'verifier'"
  End

  It 'rejects a placeholder author email from GIT_AUTHOR_EMAIL despite valid config'
    When run env GIT_AUTHOR_EMAIL=b@localhost sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
    The status should equal 1
    The stderr should include "[check-commit-identity] FAILED: author email domain is a placeholder or empty: 'b@localhost'"
  End

  It 'rejects a missing author name'
    gitc config --unset user.name
    When run sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
    The status should equal 1
    The stderr should include '[check-commit-identity] FAILED: author name is missing or empty'
  End

  It 'rejects a missing author email'
    gitc config --unset user.email
    When run sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
    The status should equal 1
    The stderr should include '[check-commit-identity] FAILED: author email is missing or empty'
  End

  It 'rejects a malformed author email without an @'
    gitc config user.email 'andrebrait_at_gmail.com'
    When run sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
    The status should equal 1
    The stderr should include "[check-commit-identity] FAILED: author email is malformed (no '@'): 'andrebrait_at_gmail.com'"
  End

  Describe 'placeholder and empty author email domain variants'
    Parameters
      'a@example.invalid'
      'a@EXAMPLE.com'
      'a@localhost'
      'a@'
      'a@example.invalid.'
      'a@EXAMPLE.invalid.'
      'a@sub.example.com'
      'a@sub.example.invalid'
      'a@deep.sub.example.org'
      'a@x.example.net'
      'a@y.localhost'
    End

    It 'rejects the domain case-insensitively, including trailing-dot and subdomain variants'
      gitc config user.email "$1"
      When run sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
      The status should equal 1
      The stderr should include "[check-commit-identity] FAILED: author email domain is a placeholder or empty: '$1'"
    End
  End

  Describe 'hostile author email internal-whitespace variants'
    Parameters
      'a@ example.invalid'
      'a@ex ample.com'
      'a b@realcorp.dev'
    End

    It 'rejects the email without deleting the whitespace into a different address'
      gitc config user.email "$1"
      When run sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
      The status should equal 1
      The stderr should include "[check-commit-identity] FAILED: author email contains internal whitespace: '$1'"
    End
    End

  It 'rejects an email whose domain contains a tab'
    gitc config user.email "a@example$(printf '\t')invalid"
    When run sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
    The status should equal 1
    The stderr should include "[check-commit-identity] FAILED: author email contains internal whitespace: 'a@example$(printf '\t')invalid'"
  End

  It 'rejects a placeholder committer email from GIT_COMMITTER_EMAIL despite valid config'
    When run env GIT_COMMITTER_EMAIL=b@localhost sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
    The status should equal 1
    The stderr should include "[check-commit-identity] FAILED: committer email domain is a placeholder or empty: 'b@localhost'"
  End

  It 'rejects a malformed committer email from GIT_COMMITTER_EMAIL despite valid config'
    When run env GIT_COMMITTER_EMAIL=no-at-sign sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
    The status should equal 1
    The stderr should include "[check-commit-identity] FAILED: committer email is malformed (no '@'): 'no-at-sign'"
  End

  Describe 'real human identities (no exact allowlist: external contributors pass too)'
    Parameters
      'Andre Brait|andrebrait@gmail.com'
      'BBcan177|bbcan177@gmail.com'
      'Some Contributor|some@realcorp.dev'
      'Deep Sub|a@mail.realcorp.dev'
    End

    It 'accepts the identity when signing prerequisites are valid'
      gitc config user.name "${1%%|*}"
      gitc config user.email "${1##*|}"
      When run sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
      The status should equal 0
      The stderr should not include 'FAILED'
    End
  End

  # --------------------------- signing prerequisites --------------------------- #

  It 'rejects when commit.gpgsign is absent'
    gitc config --unset commit.gpgsign
    When run sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
    The status should equal 1
    The stderr should include '[check-commit-identity] FAILED: commit.gpgsign is not enabled'
  End

  It 'rejects when commit.gpgsign is false'
    gitc config commit.gpgsign false
    When run sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
    The status should equal 1
    The stderr should include '[check-commit-identity] FAILED: commit.gpgsign is not enabled'
  End

  It 'rejects when user.signingkey is absent'
    gitc config --unset user.signingkey
    When run sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
    The status should equal 1
    The stderr should include '[check-commit-identity] FAILED: user.signingkey is not configured'
  End

  It 'rejects an unknown gpg.format'
    gitc config gpg.format pgp
    When run sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
    The status should equal 1
    The stderr should include "[check-commit-identity] FAILED: unknown gpg.format: 'pgp'"
  End

  It 'rejects a configured SSH signing program that does not exist'
    gitc config gpg.ssh.program pfb-test-ssh-keygen
    When run sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
    The status should equal 1
    The stderr should include '[check-commit-identity] FAILED: SSH signing program not found in PATH: pfb-test-ssh-keygen'
  End

  It 'rejects a missing default SSH signing program under a PATH of only test stubs'
    ln -s "$(command -v git)" "$stubdir/git"
    ln -s /usr/bin/tr "$stubdir/tr"
    ln -s /usr/bin/sed "$stubdir/sed"
    ln -s "$(command -v dash)" "$stubdir/sh"
    When run sh -c "cd '$repo' && PATH='$stubdir' sh .githooks/check-commit-identity.sh"
    The status should equal 1
    The stderr should include '[check-commit-identity] FAILED: SSH signing program not found in PATH: ssh-keygen'
  End

  It 'accepts SSH signing with only stub PATH binaries, proving binary selection without host leakage'
    ln -s "$(command -v git)" "$stubdir/git"
    ln -s /usr/bin/tr "$stubdir/tr"
    ln -s /usr/bin/sed "$stubdir/sed"
    ln -s "$(command -v dash)" "$stubdir/sh"
    ln -s /usr/bin/ssh-keygen "$stubdir/ssh-keygen"
    When run sh -c "cd '$repo' && PATH='$stubdir' sh .githooks/check-commit-identity.sh"
    The status should equal 0
    The stderr should not include 'FAILED'
  End

  It 'rejects a missing SSH signing key path (including paths with spaces)'
    gitc config user.signingkey "$repo/my missing key.pub"
    When run sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
    The status should equal 1
    The stderr should include "[check-commit-identity] FAILED: SSH signing key not found or unreadable: $repo/my missing key.pub"
  End

  It 'rejects an unreadable SSH signing key path'
    Skip if 'root bypasses file permissions' [ "$(id -u)" -eq 0 ]
    true > "$repo/locked.pub"
    chmod 000 "$repo/locked.pub"
    gitc config user.signingkey "$repo/locked.pub"
    When run sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
    The status should equal 1
    The stderr should include "[check-commit-identity] FAILED: SSH signing key not found or unreadable: $repo/locked.pub"
  End

  It 'accepts a readable SSH signing key path containing spaces'
    true > "$repo/my key file.pub"
    gitc config user.signingkey "$repo/my key file.pub"
    When run sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
    The status should equal 0
    The stderr should not include 'FAILED'
  End

  It 'accepts a key:: SSH literal key and leaves its validation to Git'
    gitc config user.signingkey 'key::ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test-only-literal'
    When run sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
    The status should equal 0
    The stderr should not include 'FAILED'
  End

  It 'rejects a configured OpenPGP program that does not exist'
    gitc config gpg.format openpgp
    gitc config gpg.openpgp.program pfb-test-gpg
    When run sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
    The status should equal 1
    The stderr should include '[check-commit-identity] FAILED: OpenPGP signing program not found in PATH: pfb-test-gpg'
  End

  It 'selects the legacy gpg.program when gpg.openpgp.program is unset, and rejects it if missing'
    gitc config gpg.format openpgp
    gitc config gpg.program pfb-test-gpg-legacy
    When run sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
    The status should equal 1
    The stderr should include '[check-commit-identity] FAILED: OpenPGP signing program not found in PATH: pfb-test-gpg-legacy'
  End

  It 'rejects a missing default gpg under a PATH of only test stubs'
    ln -s "$(command -v git)" "$stubdir/git"
    ln -s /usr/bin/tr "$stubdir/tr"
    ln -s /usr/bin/sed "$stubdir/sed"
    ln -s "$(command -v dash)" "$stubdir/sh"
    gitc config gpg.format openpgp
    When run sh -c "cd '$repo' && PATH='$stubdir' sh .githooks/check-commit-identity.sh"
    The status should equal 1
    The stderr should include '[check-commit-identity] FAILED: OpenPGP signing program not found in PATH: gpg'
  End

  It 'accepts a readable OpenPGP program under a PATH of only test stubs'
    ln -s "$(command -v git)" "$stubdir/git"
    ln -s /usr/bin/tr "$stubdir/tr"
    ln -s /usr/bin/sed "$stubdir/sed"
    ln -s "$(command -v dash)" "$stubdir/sh"
    printf '#!/bin/sh\nexit 0\n' > "$stubdir/pfb-test-gpg"
    chmod +x "$stubdir/pfb-test-gpg"
    gitc config gpg.format openpgp
    gitc config gpg.program pfb-test-gpg
    When run sh -c "cd '$repo' && PATH='$stubdir' sh .githooks/check-commit-identity.sh"
    The status should equal 0
    The stderr should not include 'FAILED'
  End

  It 'rejects a configured X.509 program that does not exist'
    gitc config gpg.format x509
    gitc config gpg.x509.program pfb-test-gpgsm
    When run sh -c "cd '$repo' && sh .githooks/check-commit-identity.sh"
    The status should equal 1
    The stderr should include '[check-commit-identity] FAILED: X.509 signing program not found in PATH: pfb-test-gpgsm'
  End

  It 'rejects a missing default gpgsm under a PATH of only test stubs'
    ln -s "$(command -v git)" "$stubdir/git"
    ln -s /usr/bin/tr "$stubdir/tr"
    ln -s /usr/bin/sed "$stubdir/sed"
    ln -s "$(command -v dash)" "$stubdir/sh"
    gitc config gpg.format x509
    When run sh -c "cd '$repo' && PATH='$stubdir' sh .githooks/check-commit-identity.sh"
    The status should equal 1
    The stderr should include '[check-commit-identity] FAILED: X.509 signing program not found in PATH: gpgsm'
  End

  It 'accepts a readable X.509 program under a PATH of only test stubs'
    ln -s "$(command -v git)" "$stubdir/git"
    ln -s /usr/bin/tr "$stubdir/tr"
    ln -s /usr/bin/sed "$stubdir/sed"
    ln -s "$(command -v dash)" "$stubdir/sh"
    printf '#!/bin/sh\nexit 0\n' > "$stubdir/pfb-test-gpgsm"
    chmod +x "$stubdir/pfb-test-gpgsm"
    gitc config gpg.format x509
    gitc config gpg.x509.program pfb-test-gpgsm
    When run sh -c "cd '$repo' && PATH='$stubdir' sh .githooks/check-commit-identity.sh"
    The status should equal 0
    The stderr should not include 'FAILED'
  End

  # ------------------------------ hook wiring ---------------------------------- #

  ALL_CHECKERS='scripts/check_noopener.py
scripts/check_appliance_python.py
scripts/check_version_literals.py
scripts/check_comment_narration.py
scripts/check_agent_roles.py
scripts/check_context_budget.py
scripts/check_composer_vendor.py
scripts/check_url_encoding.py
scripts/check_toggle_registry.py
scripts/check_reentry_bounds.py
scripts/agent/check-agent-config-parity.sh
scripts/agent/check-graph-fresh.sh'

  # Sandbox laid out like the repo (all sh -n scan roots exist), the legacy
  # opt-out manifest committed, and shellcheck stubbed, so ONLY the identity
  # gate decides the hook verdict.
  make_wired_repo() {
    make_repo
    mkdir -p "$repo/src" "$repo/scripts/agent" "$repo/tests" "$repo/.claude/hooks"
    printf '%s\n' "$ALL_CHECKERS" > "$repo/.githooks-exempt"
    # Commit the manifest so the index starts EMPTY: the allow-empty example
    # below must exercise the hook's no-staged exit, not a staged manifest
    # (review round: the ordering claim was never truly exercised before).
    # -c commit.gpgsign=false: the sandbox key.pub is an empty stand-in, and this
    # fixture commit is plumbing, not a signing test.
    gitc add .githooks-exempt
    gitc -c commit.gpgsign=false commit -q -m seed --no-verify
    printf '#!/bin/sh\nexit 0\n' > "$repo/src/ok.sh"
    printf '#!/bin/sh\nexit 0\n' > "$stubdir/shellcheck"
    chmod +x "$stubdir/shellcheck"
  }

  It 'fails closed when the checker file is missing'
    make_wired_repo
    rm -f "$repo/.githooks/check-commit-identity.sh"
    gitc add src/ok.sh
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 1
    The stderr should include '[pre-commit] FAILED: commit identity checker missing or not executable: '
    The output should include '[pre-commit] commit identity & signing prerequisites'
  End

  It 'fails closed when the checker is not executable'
    make_wired_repo
    chmod -x "$repo/.githooks/check-commit-identity.sh"
    gitc add src/ok.sh
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 1
    The stderr should include '[pre-commit] FAILED: commit identity checker missing or not executable: '
    The output should include '[pre-commit] commit identity & signing prerequisites'
  End

  It 'runs the identity gate before the no-staged-files exit, covering allow-empty commits'
    make_wired_repo
    gitc config user.name Verifier
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 1
    The stderr should include '[pre-commit] FAILED: commit identity & signing prerequisites'
    The stderr should include "[check-commit-identity] FAILED: author name is a generic placeholder: 'Verifier'"
    The output should include '[pre-commit] commit identity & signing prerequisites'
  End

  It 'fails closed on a missing checker even with an empty index (allow-empty path)'
    make_wired_repo
    rm -f "$repo/.githooks/check-commit-identity.sh"
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 1
    The stderr should include '[pre-commit] FAILED: commit identity checker missing or not executable: '
    The output should include '[pre-commit] commit identity & signing prerequisites'
  End


  It 'does not suppress the other staged gates when the identity check fails'
    make_wired_repo
    gitc config user.name Verifier
    gitc add src/ok.sh
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 1
    The stderr should include '[pre-commit] FAILED: commit identity & signing prerequisites'
    The output should include '[pre-commit] shell (sh -n)'
  End

  It 'passes the hook end to end with a valid identity and signing setup'
    make_wired_repo
    gitc add src/ok.sh
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 0
    The output should include '[pre-commit] commit identity & signing prerequisites'
    The stderr should not include 'FAILED'
  End
End

#shellcheck shell=sh
# .githooks/pre-commit and C-quoted paths: git C-quotes a path that holds a double
# quote, a backslash, a control byte or (by default) a non-ASCII byte, so the
# hook's suffix regexes match nothing and the tracked-file scans read nothing —
# that commit's language gates silently never run and its shebang goes unchecked
# (issue #2212). The 'plain' row is the control: it already passed before the fix,
# so a green hostile row is not a probe artefact.

Describe '.githooks/pre-commit with a C-quoted path'
  gitc() { git_fixture -C "$repo" -c user.email=t@t -c user.name=t "$@"; }

  make_repo() {
    scrub_git_env
    repo="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/precommithostile.XXXXXX")"
    git_fixture -C "$repo" init -q
    # issue #2982: the pre-commit identity gate is fail-closed, so the sandbox
    # carries a valid identity, SSH signing prerequisites, and the checker itself.
    gitc config user.name t
    gitc config user.email t@t
    gitc config commit.gpgsign true
    gitc config gpg.format ssh
    true > "$repo/key.pub"
    gitc config user.signingkey "$repo/key.pub"
    mkdir -p "$repo/.githooks" "$repo/scripts/agent" "$repo/src" "$repo/vendor/bin"
    cp "$PFB_ROOT/.githooks/pre-commit" "$repo/.githooks/pre-commit"
    cp "$PFB_ROOT/.githooks/check-commit-identity.sh" "$repo/.githooks/" \
      && chmod +x "$repo/.githooks/check-commit-identity.sh"
    printf '#!/bin/sh\nexit 0\n' > "$repo/scripts/agent/patch-graphify.sh"
    printf '#!/bin/sh\nmkdir -p graphify-out && : > graphify-out/graph.json\n' > "$repo/scripts/agent/check-graph-fresh.sh"
    # The staged checker makes staged_sh=1, so the shell gates run; create their
    # scan roots so the sandbox stays silent (the spec pins classification only).
    mkdir -p "$repo/scripts" "$repo/tests" "$repo/.claude/hooks"
    # Stubs stand in for the real analysis tools: this spec pins WHICH gates the
    # hook decides to run and what its own scans see, not what those tools conclude.
    stubdir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/precommithostilestub.XXXXXX")"
    php_marker="$stubdir/php-ran"
    printf '#!/bin/sh\ntouch "%s"\nexit 0\n' "$php_marker" > "$stubdir/php"
    chmod +x "$stubdir/php"
    for tool in python python3 shellcheck shellspec markdownlint-cli2; do
      printf '#!/bin/sh\nexit 0\n' > "$stubdir/$tool"
      chmod +x "$stubdir/$tool"
    done
    printf '#!/bin/sh\nexit 0\n' > "$repo/vendor/bin/phpstan"
    printf '#!/bin/sh\nexit 0\n' > "$repo/vendor/bin/phpcs"
    chmod +x "$repo/vendor/bin/phpstan" "$repo/vendor/bin/phpcs"
    PATH="$stubdir:$PATH"
  }
  cleanup() { rm -rf "$repo" "$stubdir"; }
  Before 'make_repo'
  After 'cleanup'

  Describe 'stage classification'
    Parameters
      'plain'
      'has"quote'
      'has\backslash'
      "$(printf 'has\ttab')"
      "$(printf 'has\nnewline')"
      "$(printf 'has\001control')"
      'café'
    End

    It "runs the PHP gates for a staged file named '$1'"
      printf '<?php echo 1;\n' > "$repo/src/$1.php"
      gitc add -A
      When run sh -c "cd '$repo' && sh .githooks/pre-commit"
      The status should equal 0
      The output should include '[pre-commit] php -l'
      Assert [ -e "$php_marker" ]
    End
  End

  Describe 'shebang policy scan'
    Parameters
      'plain'
      'has"quote'
      'has\backslash'
      "$(printf 'has\ttab')"
      "$(printf 'has\nnewline')"
      "$(printf 'has\001control')"
      'café'
    End

    It "rejects a bash shebang in a tracked file named '$1'"
      printf '#!/bin/bash\necho hi\n' > "$repo/src/$1.sh"
      gitc add -A
      When run sh -c "cd '$repo' && sh .githooks/pre-commit"
      The status should equal 1
      The stderr should include 'bash shebang not allowed'
      The output should include '[pre-commit] shebang policy'
    End
  End
End

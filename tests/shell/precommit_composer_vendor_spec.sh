#shellcheck shell=sh
# .githooks/pre-commit Composer vendor guard: a failed guard blocks Composer tools.

Describe '.githooks/pre-commit Composer vendor guard'
  gitc() { git_fixture -C "$repo" -c user.email=t@t -c user.name=t "$@"; }
  make_repo() {
    scrub_git_env
    repo="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/precommitphp.XXXXXX")"
    git_fixture -C "$repo" init -q
    # issue #2982: the pre-commit identity gate is fail-closed, so the sandbox
    # carries a valid identity and SSH signing prerequisites for hook-pass rows.
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
    printf '#!/bin/sh\nmkdir -p graphify-out && true > graphify-out/graph.json\n' > "$repo/scripts/agent/check-graph-fresh.sh"
    printf '<?php echo 1;\n' > "$repo/src/a.php"
    gitc add src/a.php

    stubdir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/precommitphpstub.XXXXXX")"
    checker_marker="$stubdir/checker-ran"
    php_marker="$stubdir/php-ran"
    phpcs_marker="$stubdir/phpcs-ran"
    printf '#!/bin/sh\ntouch "%s"\nexit 0\n' "$php_marker" > "$stubdir/php"
    printf '#!/bin/sh\ntouch "%s"\nexit 0\n' "$phpcs_marker" > "$repo/vendor/bin/phpcs"
    chmod +x "$stubdir/php" "$repo/vendor/bin/phpcs"
    PATH="$stubdir:$PATH"
  }
  cleanup() { rm -rf "$repo" "$stubdir"; }
  Before 'make_repo'
  After 'cleanup'

  It 'fails closed before PHPCS when the checker is unavailable'
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 1
    The output should not include '[pre-commit] phpcs'
    The stderr should include '[pre-commit] FAILED: composer vendor'
    Assert [ ! -e "$php_marker" ]
    Assert [ ! -e "$phpcs_marker" ]
  End

  It 'runs every PHP style gate when the Composer vendor checker succeeds'
    for interpreter in python python3; do
      printf '#!/bin/sh\ntouch "%s"\nexit 0\n' "$checker_marker" > "$stubdir/$interpreter"
    done
    chmod +x "$stubdir/python" "$stubdir/python3"
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 0
    The output should include '[pre-commit] php -l'
    The output should include '[pre-commit] phpcs'
    Assert [ -e "$checker_marker" ]
    Assert [ -e "$php_marker" ]
    Assert [ -e "$phpcs_marker" ]
  End
End

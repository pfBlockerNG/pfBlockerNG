#shellcheck shell=sh
# .githooks/pre-commit Composer vendor guard: a failed guard blocks Composer tools.

Describe '.githooks/pre-commit Composer vendor guard'
  gitc() { git_fixture -C "$repo" -c user.email=t@t -c user.name=t "$@"; }
  make_repo() {
    scrub_git_env
    repo="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/precommitphp.XXXXXX")"
    git_fixture -C "$repo" init -q
    gitc config commit.gpgsign false
    mkdir -p "$repo/.githooks" "$repo/scripts" "$repo/src" "$repo/vendor/bin"
    cp "$PFB_ROOT/.githooks/pre-commit" "$repo/.githooks/pre-commit"
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

  It 'reports php -l as SKIPPED, not passed, when php is absent'
    # The host gate is only honest if an absent tool reads as a skip. Reporting it as a
    # pass would make a workstation without php look like one that linted cleanly.
    for interpreter in python python3; do
      printf '#!/bin/sh\ntouch "%s"\nexit 0\n' "$checker_marker" > "$stubdir/$interpreter"
    done
    chmod +x "$stubdir/python" "$stubdir/python3"
    rm -f "$stubdir/php"
    NOPHP_PATH=''
    _oldifs="$IFS"; IFS=':'
    for _d in $PATH; do
      [ -x "${_d}/php" ] && continue
      NOPHP_PATH="${NOPHP_PATH:+${NOPHP_PATH}:}${_d}"
    done
    IFS="$_oldifs"

    When run sh -c "cd '$repo' && PATH='$NOPHP_PATH' sh .githooks/pre-commit"
    The status should equal 0
    # The hook runs to completion (its later gates still report) and exits 0, while the
    # interpreter is never invoked: an absent tool is a skip, not a failure and not a
    # silent pass. The sibling example above proves php -l DOES run when php is present,
    # so this cannot pass by the PHP block never being reached.
    The output should include '[pre-commit] comment-narration'
    Assert [ ! -e "$php_marker" ]
  End
End

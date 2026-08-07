#shellcheck shell=sh
# .githooks/pre-commit stage classification: git C-quotes a staged path that holds
# a double quote, a backslash or a control byte, so the hook's suffix regexes
# (`\.(php|inc)$` and friends) match nothing and that commit's language gates
# silently never run (issue #2212). The 'plain' row is the control — it already
# passed before the fix, so a green hostile row is not a probe artefact.

Describe '.githooks/pre-commit stage classification'
  gitc() { git_fixture -C "$repo" -c user.email=t@t -c user.name=t "$@"; }

  make_repo() {
    scrub_git_env
    repo="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/precommithostile.XXXXXX")"
    git_fixture -C "$repo" init -q
    gitc config commit.gpgsign false
    mkdir -p "$repo/.githooks" "$repo/src" "$repo/vendor/bin"
    cp "$PFB_ROOT/.githooks/pre-commit" "$repo/.githooks/pre-commit"

    # Stubs stand in for the real analysis tools: this spec pins WHICH gates the
    # hook decides to run, not what they conclude.
    stubdir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/precommithostilestub.XXXXXX")"
    php_marker="$stubdir/php-ran"
    printf '#!/bin/sh\ntouch "%s"\nexit 0\n' "$php_marker" > "$stubdir/php"
    for interpreter in python python3; do
      printf '#!/bin/sh\nexit 0\n' > "$stubdir/$interpreter"
      chmod +x "$stubdir/$interpreter"
    done
    printf '#!/bin/sh\nexit 0\n' > "$repo/vendor/bin/phpstan"
    printf '#!/bin/sh\nexit 0\n' > "$repo/vendor/bin/phpcs"
    chmod +x "$stubdir/php" "$repo/vendor/bin/phpstan" "$repo/vendor/bin/phpcs"
    PATH="$stubdir:$PATH"
  }
  cleanup() { rm -rf "$repo" "$stubdir"; }
  Before 'make_repo'
  After 'cleanup'

  Parameters
    'plain'
    'has"quote'
    'has\backslash'
    "$(printf 'has\ttab')"
    "$(printf 'has\nnewline')"
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

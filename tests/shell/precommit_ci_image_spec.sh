#shellcheck shell=sh
# .githooks/pre-commit PHP gates run in the CI runner image, never against a host PHP
# (issue #2350).
#
# WHY ONLY THE PHP GATES: a commit hook that hard-requires Docker is too heavy a gate, so
# the fast host-native linters (ruff, shellcheck, sh -n, markdownlint, the Python policy
# checkers) keep running exactly where they always did. PHP is the exception — the repo's
# only PHP consumer is this project, the matrix pins 8.3 and 8.5, and a host PHP is
# whichever version that machine happens to carry. There is nothing to gain from grading
# `php -l` and PHPCS against it, and a silent version divergence to lose.
#
# The hook prepends Homebrew's bin to PATH by design, so "assert the host php was not
# found" is not a property this spec can hold on a developer machine. It asserts the
# positive instead: the gate command reaches the WRAPPER, and a planted host `php` on
# PATH is never invoked.

Describe '.githooks/pre-commit PHP gates in the CI image'
  gitc() { git_fixture -C "$repo" -c user.email=t@t -c user.name=t "$@"; }

  make_repo() {
    scrub_git_env
    repo="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/precommitimage.XXXXXX")"
    git_fixture -C "$repo" init -q
    gitc config commit.gpgsign false
    mkdir -p "$repo/.githooks" "$repo/scripts" "$repo/src" "$repo/vendor/bin"
    cp "$PFB_ROOT/.githooks/pre-commit" "$repo/.githooks/pre-commit"
    printf '<?php echo 1;\n' > "$repo/src/a.php"
    gitc add src/a.php

    wrapper_log="$repo/wrapper.log"
    # exit 0 by default; WRAPPER_RC lets an example make the container unreachable.
    printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s"\nexit "${WRAPPER_RC:-0}"\n' "$wrapper_log" \
      > "$repo/scripts/run-in-docker.sh"
    chmod +x "$repo/scripts/run-in-docker.sh"

    stubdir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/precommitimagestub.XXXXXX")"
    host_php_marker="$stubdir/host-php-ran"
    # A host php AND a host phpcs, both of which must stay untouched: this is the exact
    # thing the change removes from the hook's reach.
    printf '#!/bin/sh\ntouch "%s"\nexit 0\n' "$host_php_marker" > "$stubdir/php"
    printf '#!/bin/sh\ntouch "%s"\nexit 0\n' "$host_php_marker" > "$repo/vendor/bin/phpcs"
    # The Composer vendor guard is fail-closed and runs before every PHP style gate, so
    # it has to succeed for those gates to be reached at all.
    for interpreter in python python3; do
      printf '#!/bin/sh\nexit 0\n' > "$stubdir/$interpreter"
    done
    chmod +x "$stubdir/php" "$stubdir/python" "$stubdir/python3" "$repo/vendor/bin/phpcs"
    PATH="$stubdir:$PATH"
  }
  cleanup() { rm -rf "$repo" "$stubdir"; }
  Before 'make_repo'
  After 'cleanup'

  It 'sends php -l and phpcs through the wrapper and never runs the host PHP'
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 0
    The output should include '[pre-commit] php -l'
    The output should include '[pre-commit] phpcs'
    The contents of file "$wrapper_log" should include 'php -l'
    The contents of file "$wrapper_log" should include 'phpcs'
    Assert [ ! -e "$host_php_marker" ]
  End

  It 'fails the commit when the container is unreachable'
    # The defect direction that matters: the hook used to report `skipped (tool not
    # found)` for an absent php, and a skipped gate reads greener than a failed one.
    # An unreachable container is a FAILED gate, and it blocks the commit.
    export WRAPPER_RC=125
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 1
    The output should include '[pre-commit] php -l'
    The stderr should include '[pre-commit] FAILED: php -l'
    The stderr should not include 'skipped (tool not found)'
  End

  It 'drops an inherited PFB_ALLOW_HOST so the PHP gates cannot silently grade on host PHP'
    # The wrapper honours PFB_ALLOW_HOST by design, and that variable is commonly left
    # exported by an ad-hoc run, direnv, or an agent shell. run-gates.sh drops it for
    # the same reason (#2350); the hook's PHP block must too, or the "never against a
    # host PHP" comment above the gates is a lie whenever the container is unreachable.
    printf '#!/bin/sh\nprintf "allow_host=%%s\\n" "${PFB_ALLOW_HOST:-unset}"\nexit 0\n' \
      > "$repo/scripts/run-in-docker.sh"
    chmod +x "$repo/scripts/run-in-docker.sh"
    When run sh -c "cd '$repo' && PFB_ALLOW_HOST=1 sh .githooks/pre-commit"
    The status should equal 0
    The output should include 'allow_host=unset'
    The output should not include 'allow_host=1'
  End

  It 'still blocks the PHP gates when the Composer vendor guard fails'
    # The guard is fail-closed and ordered before the style gates; routing them through
    # the image must not reorder that.
    rm -f "$stubdir/python" "$stubdir/python3"
    When run sh -c "cd '$repo' && PATH='$stubdir:/usr/bin:/bin' sh .githooks/pre-commit"
    The status should equal 1
    The stderr should include '[pre-commit] FAILED: composer vendor'
    Assert [ ! -e "$wrapper_log" ]
  End
End

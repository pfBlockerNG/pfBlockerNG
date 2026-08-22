#shellcheck shell=sh
# .githooks/pre-commit legacy-branch opt-out (issue #2633): a repo-script gate whose
# checker is absent from the tree is skipped ONLY when the tree explicitly commits
# that exact script path in .githooks-exempt; a missing checker with no listed
# exemption stays a hard failure, and a listed checker that IS present still runs.

Describe '.githooks/pre-commit .githooks-exempt legacy opt-out'
  gitc() { git_fixture -C "$repo" -c user.email=t@t -c user.name=t "$@"; }
  # The sandbox stages a PHP file so the hook wants all seven repo checkers, none
  # of which exist in the sandbox scripts/ dir -- the release-line situation. The
  # REAL host python runs, so a missing checker fails exactly as it does live.
  ALL_CHECKERS='scripts/check_noopener.py
scripts/check_appliance_python.py
scripts/check_version_literals.py
scripts/check_comment_narration.py
scripts/check_agent_roles.py
scripts/check_context_budget.py
scripts/check_composer_vendor.py'
  make_repo() {
    scrub_git_env
    repo="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/precommitexempt.XXXXXX")"
    git_fixture -C "$repo" init -q
    gitc config commit.gpgsign false
    mkdir -p "$repo/.githooks" "$repo/scripts" "$repo/src" "$repo/vendor/bin"
    cp "$PFB_ROOT/.githooks/pre-commit" "$repo/.githooks/pre-commit"
    printf '<?php echo 1;\n' > "$repo/src/a.php"
    gitc add src/a.php

    stubdir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/precommitexemptstub.XXXXXX")"
    checker_marker="$stubdir/checker-ran"
    printf '#!/bin/sh\nexit 0\n' > "$stubdir/php"
    printf '#!/bin/sh\nexit 0\n' > "$repo/vendor/bin/phpcs"
    chmod +x "$stubdir/php" "$repo/vendor/bin/phpcs"
    PATH="$stubdir:$PATH"
  }
  cleanup() { rm -rf "$repo" "$stubdir"; }
  Before 'make_repo'
  After 'cleanup'

  It 'skips an absent checker only through the committed manifest and passes'
    printf '%s\n' "$ALL_CHECKERS" > "$repo/.githooks-exempt"
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 0
    The output should include 'listed in .githooks-exempt): composer vendor'
    The output should include 'listed in .githooks-exempt): noopener'
    The output should include '[pre-commit] php -l'
    The output should include '[pre-commit] phpcs'
    The stderr should not include 'FAILED'
  End

  It 'still hard-fails a missing checker when no manifest exists'
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 1
    The output should include '[pre-commit] composer vendor'
    The stderr should include '[pre-commit] FAILED: composer vendor'
  End

  It 'still hard-fails a missing checker the manifest does not list'
    printf 'scripts/check_noopener.py\n' > "$repo/.githooks-exempt"
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 1
    The output should include 'listed in .githooks-exempt): noopener'
    The stderr should include '[pre-commit] FAILED: composer vendor'
  End

  It 'runs a checker that is present even when the manifest lists it'
    printf '%s\n' "$ALL_CHECKERS" > "$repo/.githooks-exempt"
    printf 'import pathlib, sys\npathlib.Path(%s).touch()\nsys.exit(0)\n' "'$checker_marker'" \
      > "$repo/scripts/check_composer_vendor.py"
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 0
    The output should include '[pre-commit] composer vendor'
    The output should not include 'listed in .githooks-exempt): composer vendor'
    Assert [ -e "$checker_marker" ]
  End
End

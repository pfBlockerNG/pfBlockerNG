#shellcheck shell=sh
# .githooks/pre-commit legacy-branch opt-out (issue #2633): a repo-script gate whose
# checker is absent from the tree is skipped ONLY when the tree explicitly commits
# that exact script path in .githooks-exempt; a missing checker with no listed
# exemption stays a hard failure, and a listed checker that IS present still runs.

Describe '.githooks/pre-commit .githooks-exempt legacy opt-out'
  gitc() { git_fixture -C "$repo" -c user.email=t@t -c user.name=t "$@"; }
  # The sandbox stages PHP and shell files so the hook wants the repo checkers,
  # none of which exist in the sandbox scripts/ dir -- the release-line situation.
  # The REAL host python runs, so a missing checker fails exactly as it does live.
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
  make_repo() {
    scrub_git_env
    repo="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/precommitexempt.XXXXXX")"
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
    gitc add .githooks-exempt
    printf '#!/bin/sh\nexit 0\n' > "$repo/src/b.sh"
    gitc add src/b.sh
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 0
    The output should include 'listed in .githooks-exempt): composer vendor'
    The output should include 'listed in .githooks-exempt): noopener'
    The output should include 'listed in .githooks-exempt): url-encoding'
    # issue #2016: the re-entry-bounds step is gated on staged .php/.inc OR .sh, and this
    # example stages both -- so an unlisted absent checker here would hard-fail the hook.
    The output should include 'listed in .githooks-exempt): reentry-bounds'
    The output should include '[pre-commit] php -l'
    The output should include '[pre-commit] phpcs'
    The stderr should not include 'FAILED'
  End

  It 'ignores a manifest that is not tracked by git'
    printf '%s\n' "$ALL_CHECKERS" > "$repo/.githooks-exempt"
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 1
    The output should include '[pre-commit] composer vendor'
    The output should not include 'listed in .githooks-exempt'
    The stderr should include '[pre-commit] FAILED: composer vendor'
  End

  It 'grades exemptions against the staged manifest, not working-tree edits'
    printf 'scripts/check_noopener.py\n' > "$repo/.githooks-exempt"
    gitc add .githooks-exempt
    printf '%s\n' "$ALL_CHECKERS" > "$repo/.githooks-exempt"
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 1
    The output should include 'listed in .githooks-exempt): noopener'
    The output should not include 'listed in .githooks-exempt): composer vendor'
    The stderr should include '[pre-commit] FAILED: composer vendor'
  End

  It 'rejects a symlinked manifest whose target text names a checker'
    # The discriminating construction for the index-mode guard: a staged symlink's
    # blob IS its target path text, so this one reads back as exactly the composer
    # checker's path and would exempt it if only blob content were graded.
    ln -s scripts/check_composer_vendor.py "$repo/.githooks-exempt"
    gitc add .githooks-exempt
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 1
    The output should not include 'listed in .githooks-exempt'
    The stderr should include '[pre-commit] FAILED: composer vendor'
  End

  It 'exempts the agent-config parity gate only through the manifest'
    printf '%s\n' "$ALL_CHECKERS" > "$repo/.githooks-exempt"
    gitc add .githooks-exempt
    printf '# sandbox agent adapter\n' > "$repo/CLAUDE.md"
    gitc add CLAUDE.md
    # markdownlint would shell out through npx for the staged .md; stub it.
    printf '#!/bin/sh\nexit 0\n' > "$stubdir/npx"
    chmod +x "$stubdir/npx"
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 0
    The output should include 'listed in .githooks-exempt): agent-config parity'
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
    gitc add .githooks-exempt
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 1
    The output should include 'listed in .githooks-exempt): noopener'
    The stderr should include '[pre-commit] FAILED: composer vendor'
  End

  It 'runs a checker that is present even when the manifest lists it'
    printf '%s\n' "$ALL_CHECKERS" > "$repo/.githooks-exempt"
    gitc add .githooks-exempt
    printf 'import pathlib, sys\npathlib.Path(%s).touch()\nsys.exit(0)\n' "'$checker_marker'" \
      > "$repo/scripts/check_composer_vendor.py"
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 0
    The output should include '[pre-commit] composer vendor'
    The output should not include 'listed in .githooks-exempt): composer vendor'
    Assert [ -e "$checker_marker" ]
  End

  It 'treats a directory at a listed checker path as present and fails closed'
    printf '%s\n' "$ALL_CHECKERS" > "$repo/.githooks-exempt"
    gitc add .githooks-exempt
    mkdir "$repo/scripts/check_composer_vendor.py"
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 1
    The output should not include 'listed in .githooks-exempt): composer vendor'
    The stderr should include '[pre-commit] FAILED: composer vendor'
  End

  It 'skips a tool gate this branch declines, and says so'
    # issue #2696: a maintenance line runs a narrower CI contract than devel (3.3 is
    # pytest-only), but every worktree runs the PRIMARY checkout's hook. Without a way
    # to decline a TOOL gate, that line is graded by rules it never adopted -- and the
    # only escapes are --no-verify or adopting the gate with an allowlist for its
    # pre-existing findings.
    printf '%s\ngate:shellcheck\n' "$ALL_CHECKERS" > "$repo/.githooks-exempt"
    gitc add .githooks-exempt
    printf '#!/bin/sh\nif [ "$x" == 1 ]; then :; fi\n' > "$repo/src/bad.sh"
    gitc add src/bad.sh
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 0
    The output should include 'gate not adopted on this branch; listed in .githooks-exempt): shellcheck'
    The stderr should not include 'FAILED'
  End

  It 'still runs a tool gate the manifest does not decline'
    # The same tree, the same bad script, without the gate line: the sweep runs and the
    # commit fails. This is what makes the example above evidence rather than decoration.
    printf '%s\n' "$ALL_CHECKERS" > "$repo/.githooks-exempt"
    gitc add .githooks-exempt
    printf '#!/bin/sh\nif [ "$x" == 1 ]; then :; fi\n' > "$repo/src/bad.sh"
    gitc add src/bad.sh
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 1
    The output should include '[pre-commit] shellcheck'
    The stderr should include 'FAILED'
  End

  It 'ignores a gate line that is only in the working tree'
    # Keyed on the STAGED blob like every other entry: an unstaged edit exempts nothing,
    # so a gate cannot be dropped by a change reviewers never see.
    printf '%s\ngate:shellcheck\n' "$ALL_CHECKERS" > "$repo/.githooks-exempt"
    gitc add .githooks-exempt
    # -c commit.gpgsign=false: the sandbox key.pub is an empty stand-in, and this
    # fixture commit is plumbing, not a signing test.
    gitc -c commit.gpgsign=false commit -q -m seed --no-verify
    printf '%s\n' "$ALL_CHECKERS" > "$repo/.githooks-exempt"
    gitc add .githooks-exempt
    printf 'gate:shellcheck\n' >> "$repo/.githooks-exempt"
    printf '#!/bin/sh\nif [ "$x" == 1 ]; then :; fi\n' > "$repo/src/bad.sh"
    gitc add src/bad.sh
    When run sh -c "cd '$repo' && sh .githooks/pre-commit"
    The status should equal 1
    The output should include '[pre-commit] shellcheck'
    The output should not include 'gate not adopted'
    The stderr should include 'FAILED'
  End
End

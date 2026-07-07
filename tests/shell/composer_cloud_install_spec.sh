#shellcheck shell=sh
# composer-cloud-install.sh — the cloud egress fallback's offline-testable pieces
# (issue #950): the lock-ref extraction, the json/lock phpstan strip, and the
# uncommitted-edits guard. The network stages (composer --prefer-source, the
# shallow phpstan fetch) need live egress and are exercised by actually using
# the script in a cloud session.

Describe 'composer-cloud-install.sh helpers (issue #950)'
  SCRIPT="${PFB_ROOT}/scripts/composer-cloud-install.sh"

  setup() {
    # Scrub inherited git context (GIT_DIR etc. would corrupt the fixture repo).
    scrub_git_env
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/composercloud.XXXXXX")"
    cat > "${WORK}/composer.json" << 'EOF'
{
    "require-dev": {
        "phpstan/phpstan": "^2.1",
        "phpunit/phpunit": "^11.0"
    }
}
EOF
    cat > "${WORK}/composer.lock" << 'EOF'
{
    "packages": [],
    "packages-dev": [
        {
            "name": "phpstan/phpstan",
            "version": "2.2.1",
            "dist": {
                "type": "zip",
                "url": "https://api.github.com/repos/phpstan/phpstan/zipball/abc123def456",
                "reference": "abc123def456"
            }
        },
        {
            "name": "phpunit/phpunit",
            "version": "11.5.55",
            "dist": {
                "type": "zip",
                "url": "https://api.github.com/repos/sebastianbergmann/phpunit/zipball/fff",
                "reference": "fff"
            }
        }
    ]
}
EOF
  }

  cleanup() {
    rm -rf "$WORK"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  # shellcheck disable=SC1090  # sourced for its function definitions only
  source_script() { . "$SCRIPT"; }
  BeforeAll 'source_script'

  Describe 'phpstan_ref_from_lock'
    It "echoes phpstan/phpstan's pinned dist reference"
      When call phpstan_ref_from_lock "${WORK}/composer.lock"
      The output should equal 'abc123def456'
    End

    It 'echoes nothing when the lock has no phpstan/phpstan'
      # Reuse the strip to produce a phpstan-less lock, then extract from it.
      strip_phpstan "${WORK}/composer.json" "${WORK}/composer.lock"
      When call phpstan_ref_from_lock "${WORK}/composer.lock"
      The output should equal ''
    End
  End

  Describe 'strip_phpstan'
    It 'removes phpstan/phpstan from both files and keeps every other package'
      When call strip_phpstan "${WORK}/composer.json" "${WORK}/composer.lock"
      The status should be success
      The contents of file "${WORK}/composer.json" should not include 'phpstan/phpstan'
      The contents of file "${WORK}/composer.json" should include 'phpunit/phpunit'
      The contents of file "${WORK}/composer.lock" should not include 'phpstan/phpstan'
      The contents of file "${WORK}/composer.lock" should include 'phpunit/phpunit'
    End

    # A helper function, not an inline multi-line `When call php -r` -- shellspec's
    # DSL rewrites multi-line call arguments and corrupts the PHP snippet.
    # shellcheck disable=SC2016  # the $-signs are PHP variables, not shell expansions
    json_still_parses() {
      php -r '
        $j = json_decode(file_get_contents($argv[1]), true);
        $l = json_decode(file_get_contents($argv[2]), true);
        echo ($j !== null && $l !== null && is_array($l["packages"]) && is_array($l["packages-dev"])) ? "ok" : "broken";
      ' "$1" "$2"
    }

    It 'leaves both files as parseable JSON with the lock package arrays intact'
      strip_phpstan "${WORK}/composer.json" "${WORK}/composer.lock"
      When call json_still_parses "${WORK}/composer.json" "${WORK}/composer.lock"
      The output should equal 'ok'
    End
  End

  Describe 'refuse_if_composer_files_dirty'
    # Turn the WORK fixture dir into a git repo with both files committed, so
    # the guard's HEAD comparison has a baseline to diff against.
    commit_baseline() {
      git -C "$WORK" init -q
      git -C "$WORK" -c user.name=spec -c user.email=spec@example.invalid \
        add composer.json composer.lock
      git -C "$WORK" -c user.name=spec -c user.email=spec@example.invalid \
        commit -qm baseline
    }

    It 'passes on a clean composer.json/composer.lock'
      commit_baseline
      When call refuse_if_composer_files_dirty "$WORK"
      The status should be success
    End

    It 'refuses UNSTAGED composer.json edits'
      commit_baseline
      echo '{"changed": true}' > "${WORK}/composer.json"
      When call refuse_if_composer_files_dirty "$WORK"
      The status should be failure
      The stderr should include 'uncommitted changes'
    End

    # PR #953 review: `git diff --quiet` alone compares worktree vs index and
    # silently passes STAGED edits; the guard must diff against HEAD instead.
    It 'refuses STAGED composer.lock edits'
      commit_baseline
      echo '{"packages": []}' > "${WORK}/composer.lock"
      git -C "$WORK" add composer.lock
      When call refuse_if_composer_files_dirty "$WORK"
      The status should be failure
      The stderr should include 'uncommitted changes'
    End
  End
End

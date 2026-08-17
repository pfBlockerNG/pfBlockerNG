#shellcheck shell=sh
# ci_vendor_spec.sh — shellspec suite for scripts/ci-vendor.sh (issue #2502: the
# Composer vendor tree is baked into ci-runner instead of resolved per job).
#
# Pins the contract: the baked tree is COPIED into the worktree (never symlinked —
# the generated autoloader derives $baseDir from its own real path), a lock the
# baked tree does not match fails loud and names the VERSION bump, and an absent
# baked tree is an error rather than a silent skip. Hermetic: fake worktree, fake
# baked tree, no network and no real vendor.

Describe 'ci-vendor.sh'
  SCRIPT="${PFB_ROOT}/scripts/ci-vendor.sh"

  # One package, present in both files, so the checker agrees.
  lock_json() {
    printf '{"packages":[],"packages-dev":[{"name":"acme/tool","version":"%s","dist":{"reference":"%s"}}]}' "$1" "$2"
  }
  installed_json() {
    printf '{"packages":[{"name":"acme/tool","version":"%s","dist":{"reference":"%s"}}]}' "$1" "$2"
  }

  setup() {
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/civendor.XXXXXX")"
    ROOT="${WORK}/checkout"
    BAKED="${WORK}/baked/vendor"
    mkdir -p "${ROOT}/scripts" "${BAKED}/composer" "${BAKED}/bin"
    cp "${PFB_ROOT}/scripts/check_composer_vendor.py" "${ROOT}/scripts/"
    cp "$SCRIPT" "${ROOT}/scripts/"
    lock_json 1.0.0 aaaa > "${ROOT}/composer.lock"
    installed_json 1.0.0 aaaa > "${BAKED}/composer/installed.json"
    printf '#!/bin/sh\nexit 0\n' > "${BAKED}/bin/phpstan"
    chmod +x "${BAKED}/bin/phpstan"
    export PFB_BAKED_VENDOR="$BAKED"
  }
  cleanup() { rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'copies the baked tree into the worktree'
    When run sh "${ROOT}/scripts/ci-vendor.sh"
    The status should be success
    The path "${ROOT}/vendor/bin/phpstan" should be executable
    The path "${ROOT}/vendor" should not be symlink
    The stdout should include 'vendor'
  End

  It 'replaces a stale vendor tree instead of merging into it'
    mkdir -p "${ROOT}/vendor"
    true > "${ROOT}/vendor/leftover"
    When run sh "${ROOT}/scripts/ci-vendor.sh"
    The status should be success
    The path "${ROOT}/vendor/leftover" should not be exist
    The stdout should include 'vendor'
  End

  It 'fails loud when the checkout lock has moved past the baked tree'
    lock_json 2.0.0 bbbb > "${ROOT}/composer.lock"
    When run sh "${ROOT}/scripts/ci-vendor.sh"
    The status should be failure
    The stdout should include 'materialised'
    The stderr should include 'acme/tool'
    The stderr should include '.github/docker/VERSION'
  End

  It 'fails when no baked tree is present'
    rm -rf "$BAKED"
    When run sh "${ROOT}/scripts/ci-vendor.sh"
    The status should be failure
    # The guard's OWN message, not just any failure: letting `cp` fail naturally also
    # exits nonzero and echoes the path, so a bare failure assertion cannot tell the
    # guard from its absence.
    The stderr should include 'no baked Composer tree at'
    The stderr should include "$BAKED"
    The path "${ROOT}/vendor" should not be exist
  End
End

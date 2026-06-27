#!/bin/sh
# shellcheck shell=sh
# tests/shell/git_env_scrub_spec.sh — spec for the git-env-scrub lib + meta-assertion guard.
#
# Scenario: GIT_* scrub discipline (ADR-47 P5)
#   The pre-commit hook exports GIT_DIR / GIT_INDEX_FILE / GIT_WORK_TREE /
#   GIT_PREFIX / GIT_OBJECT_DIRECTORY / GIT_COMMON_DIR pointing at the live
#   repo. Any git op in a child script or spec setup() would then operate on
#   the REAL repo instead of a fixture. pfb_scrub_git_env() unsets all six in
#   the caller's own shell context; scrub_git_env() in spec_helper.sh is its
#   spec-side alias.

# shellcheck disable=SC2317  # shellspec wraps each example's body
Describe 'scripts/lib/git-env-scrub.sh'

    SCRUB_LIB="${PFB_ROOT}/scripts/lib/git-env-scrub.sh"

    Describe 'pfb_scrub_git_env'

        It 'unsets all 6 GIT_* vars when they were set'
            # Given the 6 vars are all set.
            # When pfb_scrub_git_env is called.
            # Then all 6 vars are unset in the same shell context.
            check_all_unset() {
                # Run inside this subshell: source lib, set all 6, call, verify.
                # shellcheck disable=SC1090
                . "$SCRUB_LIB"
                GIT_DIR=/a
                GIT_INDEX_FILE=/b
                GIT_WORK_TREE=/c
                GIT_PREFIX=d
                GIT_OBJECT_DIRECTORY=/e
                GIT_COMMON_DIR=/f
                pfb_scrub_git_env
                # ${VAR+x} expands to 'x' if set, empty if unset.
                [ -z "${GIT_DIR+x}" ] || return 1
                [ -z "${GIT_INDEX_FILE+x}" ] || return 1
                [ -z "${GIT_WORK_TREE+x}" ] || return 1
                [ -z "${GIT_PREFIX+x}" ] || return 1
                [ -z "${GIT_OBJECT_DIRECTORY+x}" ] || return 1
                [ -z "${GIT_COMMON_DIR+x}" ] || return 1
            }
            When call check_all_unset
            The status should be success
        End

        It 'is a no-op when none of the GIT_* vars are set'
            check_noset_noop() {
                # shellcheck disable=SC1090
                . "$SCRUB_LIB"
                # Use pfb_scrub_git_env to clear any inherited state before testing.
                pfb_scrub_git_env
                # Now call it again on an already-clean env — should still succeed.
                pfb_scrub_git_env
                [ -z "${GIT_DIR+x}" ] || return 1
                [ -z "${GIT_COMMON_DIR+x}" ] || return 1
            }
            When call check_noset_noop
            The status should be success
        End

        It 'leaves unrelated env vars untouched'
            check_unrelated_preserved() {
                # shellcheck disable=SC1090
                . "$SCRUB_LIB"
                UNRELATED_VAR=keep_me
                pfb_scrub_git_env
                [ "${UNRELATED_VAR}" = "keep_me" ]
            }
            When call check_unrelated_preserved
            The status should be success
        End

    End

End

Describe 'scripts/git-env-scrub-guard.sh'

    GUARD="${PFB_ROOT}/scripts/git-env-scrub-guard.sh"

    Describe 'meta-assertion'

        It 'passes on the clean repo (all unsets in lib, scrub_git_env in every git-using spec)'
            When run sh "$GUARD" "$PFB_ROOT"
            The status should be success
            The output should include 'git-env-scrub-guard: clean'
        End

        It 'fails when a script has a bare unset GIT_DIR outside the lib'
            # Given a script with a raw unset GIT_DIR outside the lib.
            # When the guard runs.
            # Then it exits 1 (violation detected).
            setup_violating_script() {
                WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/guardspec.XXXXXX")"
                mkdir -p "${WORK}/scripts/lib" "${WORK}/tests/shell"
                # Write a minimal lib (no unset — the guard must tolerate its presence).
                printf '#!/bin/sh\npfb_scrub_git_env() { unset GIT_DIR GIT_INDEX_FILE GIT_WORK_TREE GIT_PREFIX GIT_OBJECT_DIRECTORY GIT_COMMON_DIR; }\n' \
                    > "${WORK}/scripts/lib/git-env-scrub.sh"
                # Write a violating production script with bare unset.
                printf '#!/bin/sh\nunset GIT_DIR GIT_INDEX_FILE GIT_WORK_TREE GIT_PREFIX GIT_OBJECT_DIRECTORY GIT_COMMON_DIR\necho hi\n' \
                    > "${WORK}/scripts/violating.sh"
                sh "$GUARD" "$WORK"
            }
            When run setup_violating_script
            The status should be failure
            The error should include 'violations found'
        End

        It 'fails when a spec calls git without scrub_git_env'
            setup_violating_spec() {
                WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/guardspec.XXXXXX")"
                mkdir -p "${WORK}/scripts/lib" "${WORK}/tests/shell"
                printf '#!/bin/sh\npfb_scrub_git_env() { unset GIT_DIR GIT_INDEX_FILE GIT_WORK_TREE GIT_PREFIX GIT_OBJECT_DIRECTORY GIT_COMMON_DIR; }\n' \
                    > "${WORK}/scripts/lib/git-env-scrub.sh"
                # Write a spec that calls `git init` but never calls scrub_git_env.
                printf '#!/bin/sh\nDescribe foo\n  It bar\n    git init /tmp/x 2>/dev/null || true\n  End\nEnd\n' \
                    > "${WORK}/tests/shell/bad_spec.sh"
                sh "$GUARD" "$WORK"
            }
            When run setup_violating_spec
            The status should be failure
            The error should include 'violations found'
        End

    End

End

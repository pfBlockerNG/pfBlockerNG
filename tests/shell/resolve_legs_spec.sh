#!/bin/sh
# shellcheck shell=sh
# tests/shell/resolve_legs_spec.sh — behaviour oracle for scripts/resolve-legs.sh.
#
# Scenario: resolve-legs.sh legs subcommand (ADR-47 P5)
#   The legs subcommand must produce byte-identical output to the inline jq
#   previously in smoke.yml / ui-tests.yml. The oracle is the spec itself:
#   each example asserts the EXACT output the inline code would have produced.
#
# Background:
#   The CI matrix fixture has three legs: CE 2.8, CE 2.10, Plus 26.03.
#   2.10 > 2.8 numerically; lexically "2.10" < "2.8" — the numeric sort test
#   proves the correct component-wise comparison (split(".") | map(tonumber)).

# shellcheck disable=SC2317  # shellspec wraps each example's body

SCRIPT="${PFB_ROOT}/scripts/resolve-legs.sh"

# CI matrix fixture: 3 legs (CE 2.8, CE 2.10, Plus 26.03).
# All have ci:true (the reader pre-filters; we replicate that here).
FIXTURE_MATRIX='[{"pfsense_version":"2.10","channel":"CE","ci":true,"image_name":"pfsense-ce","mac":"","freebsd_major":"15","php_version":"8.3","py_flavor":"py311","abi":"FreeBSD:15:amd64"},{"pfsense_version":"2.8","channel":"CE","ci":true,"image_name":"pfsense-ce","mac":"","freebsd_major":"15","php_version":"8.3","py_flavor":"py311","abi":"FreeBSD:15:amd64"},{"pfsense_version":"26.03","channel":"Plus","ci":true,"image_name":"pfsense-plus","mac":"","freebsd_major":"16","php_version":"8.5","py_flavor":"py312","abi":"FreeBSD:16:amd64"}]'

Describe 'resolve-legs.sh legs — scope + leg selection'

    setup() {
        scrub_git_env
        unset SCOPE_INPUT VERSION_INPUT PYTEST_FILTER_INPUT GITHUB_OUTPUT GITHUB_ENV PFB_BASE_REF
    }
    BeforeEach 'setup'

    # ── full scope ──────────────────────────────────────────────────────────

    It 'schedule event → full scope → all 3 legs'
        # Given: schedule trigger (always full regardless of other inputs).
        # When: legs subcommand runs.
        # Then: stdout is the full 3-leg array (order preserved from matrix).
        #       stderr carries the informational banner (scope=... legs=... -k=[...]).
        When run env \
            CI_MATRIX="$FIXTURE_MATRIX" \
            EVENT_NAME="schedule" \
            sh "$SCRIPT" legs --test-dir tests/smoke --label marker
        The status should be success
        The output should include '"pfsense_version":"2.10"'
        The output should include '"pfsense_version":"2.8"'
        The output should include '"pfsense_version":"26.03"'
        The error should include 'scope='
    End

    It 'SCOPE_INPUT=full → all 3 legs'
        When run env \
            CI_MATRIX="$FIXTURE_MATRIX" \
            EVENT_NAME="workflow_dispatch" \
            SCOPE_INPUT="full" \
            sh "$SCRIPT" legs --test-dir tests/smoke --label marker
        The status should be success
        The output should include '"pfsense_version":"2.8"'
        The output should include '"pfsense_version":"26.03"'
        The error should include 'scope='
    End

    It 'workflow_call → full scope → all 3 legs'
        When run env \
            CI_MATRIX="$FIXTURE_MATRIX" \
            EVENT_NAME="workflow_call" \
            sh "$SCRIPT" legs --test-dir tests/smoke --label marker
        The status should be success
        The output should include '"pfsense_version":"2.8"'
        The output should include '"pfsense_version":"26.03"'
        The error should include 'scope='
    End

    # ── impacted scope ──────────────────────────────────────────────────────

    It 'bare dispatch → impacted scope → only the minimum CE leg (2.8, not 2.10)'
        # Given: workflow_dispatch with no SCOPE_INPUT (impacted default).
        # When: legs runs the numeric-sort min-CE jq.
        # Then: only 2.8 in stdout (numeric sort: 2.8 < 2.10; lexical would give 2.10).
        #       stderr carries the informational banner and the impacted message.
        When run env \
            CI_MATRIX="$FIXTURE_MATRIX" \
            EVENT_NAME="workflow_dispatch" \
            PFB_IMPACTED_CHANGED_FILES="" \
            sh "$SCRIPT" legs --test-dir tests/smoke --label marker
        The status should be success
        The output should include '"pfsense_version":"2.8"'
        The output should not include '"pfsense_version":"2.10"'
        The output should not include '"pfsense_version":"26.03"'
        The error should include 'scope='
    End

    It 'numeric sort: 2.8 < 2.10 (not lexical 2.10 < 2.8)'
        # Given: CE legs 2.8 and 2.10 only.
        # When: impacted scope runs.
        # Then: 2.8 is the minimum (numeric), not 2.10 (which would be minimum lexically).
        MATRIX_CE_ONLY='[{"pfsense_version":"2.10","channel":"CE","ci":true,"image_name":"pfsense-ce","mac":"","freebsd_major":"15","php_version":"8.3","py_flavor":"py311","abi":"FreeBSD:15:amd64"},{"pfsense_version":"2.8","channel":"CE","ci":true,"image_name":"pfsense-ce","mac":"","freebsd_major":"15","php_version":"8.3","py_flavor":"py311","abi":"FreeBSD:15:amd64"}]'
        When run env \
            CI_MATRIX="$MATRIX_CE_ONLY" \
            EVENT_NAME="workflow_dispatch" \
            PFB_IMPACTED_CHANGED_FILES="" \
            sh "$SCRIPT" legs --test-dir tests/smoke --label marker
        The status should be success
        The output should include '"pfsense_version":"2.8"'
        The output should not include '"pfsense_version":"2.10"'
        The error should include 'scope='
    End

    # ── version-exact ───────────────────────────────────────────────────────

    It 'VERSION_INPUT=2.8 → only the 2.8 CE leg'
        When run env \
            CI_MATRIX="$FIXTURE_MATRIX" \
            EVENT_NAME="workflow_dispatch" \
            VERSION_INPUT="2.8" \
            sh "$SCRIPT" legs --test-dir tests/smoke --label marker
        The status should be success
        The output should include '"pfsense_version":"2.8"'
        The output should not include '"pfsense_version":"2.10"'
        The output should not include '"pfsense_version":"26.03"'
        The error should include 'scope='
    End

    It 'VERSION_INPUT for a non-existent version → exit 1 with ::error::'
        When run env \
            CI_MATRIX="$FIXTURE_MATRIX" \
            EVENT_NAME="workflow_dispatch" \
            VERSION_INPUT="9.9" \
            sh "$SCRIPT" legs --test-dir tests/smoke --label marker
        The status should be failure
        The error should include '::error::'
    End

    It 'impacted scope with no CE leg in matrix → exit 1 with ::error::'
        PLUS_ONLY='[{"pfsense_version":"26.03","channel":"Plus","ci":true,"image_name":"pfsense-plus","mac":"","freebsd_major":"16","php_version":"8.5","py_flavor":"py312","abi":"FreeBSD:16:amd64"}]'
        When run env \
            CI_MATRIX="$PLUS_ONLY" \
            EVENT_NAME="workflow_dispatch" \
            PFB_IMPACTED_CHANGED_FILES="" \
            sh "$SCRIPT" legs --test-dir tests/smoke --label marker
        The status should be failure
        The error should include '::error::'
    End

    # ── unknown scope ───────────────────────────────────────────────────────

    It 'unknown SCOPE_INPUT → exit 1 with ::error::'
        When run env \
            CI_MATRIX="$FIXTURE_MATRIX" \
            EVENT_NAME="workflow_dispatch" \
            SCOPE_INPUT="bogus" \
            sh "$SCRIPT" legs --test-dir tests/smoke --label marker
        The status should be failure
        The error should include '::error::'
    End

End

Describe 'resolve-legs.sh legs — -k derivation'

    setup() {
        scrub_git_env
        unset SCOPE_INPUT VERSION_INPUT PYTEST_FILTER_INPUT GITHUB_OUTPUT GITHUB_ENV PFB_BASE_REF
    }
    BeforeEach 'setup'

    It 'explicit PYTEST_FILTER_INPUT → used verbatim as -k'
        # stdout = legs JSON; stderr = -k value + scope banner (informational).
        When run env \
            CI_MATRIX="$FIXTURE_MATRIX" \
            EVENT_NAME="workflow_dispatch" \
            SCOPE_INPUT="full" \
            PYTEST_FILTER_INPUT="test_foo or test_bar" \
            sh "$SCRIPT" legs --test-dir tests/smoke --label marker
        The status should be success
        The output should include '"pfsense_version"'
        The error should include '-k=[test_foo or test_bar]'
    End

    It 'impacted scope with PFB_IMPACTED_CHANGED_FILES seam → auto-derives -k'
        # Given: a changed test module visible via the PFB_IMPACTED_CHANGED_FILES seam.
        # When: impacted scope with no explicit PYTEST_FILTER_INPUT.
        # Then: stdout = legs JSON; stderr = auto-derived -k expression.
        When run env \
            CI_MATRIX="$FIXTURE_MATRIX" \
            EVENT_NAME="workflow_dispatch" \
            PFB_IMPACTED_CHANGED_FILES="tests/smoke/test_dns_redirect.py" \
            sh "$SCRIPT" legs --test-dir tests/smoke --label marker
        The status should be success
        The output should include '"pfsense_version"'
        The error should include 'test_dns_redirect'
    End

    It 'full scope → no -k auto-derivation (whole marker runs)'
        When run env \
            CI_MATRIX="$FIXTURE_MATRIX" \
            EVENT_NAME="workflow_dispatch" \
            SCOPE_INPUT="full" \
            PFB_IMPACTED_CHANGED_FILES="tests/smoke/test_dns_redirect.py" \
            sh "$SCRIPT" legs --test-dir tests/smoke --label marker
        The status should be success
        The output should include '"pfsense_version"'
        The error should include '-k=[]'
    End

    It 'impacted scope with no changed smoke tests → empty -k (whole marker)'
        When run env \
            CI_MATRIX="$FIXTURE_MATRIX" \
            EVENT_NAME="workflow_dispatch" \
            PFB_IMPACTED_CHANGED_FILES="src/usr/local/pkg/pfblockerng/pfb_unbound.py" \
            sh "$SCRIPT" legs --test-dir tests/smoke --label marker
        The status should be success
        The output should include '"pfsense_version"'
        The error should include '-k=[]'
    End

    It '--test-dir filter: tests/smoke/ui does not pick up tests/smoke/test_*.py'
        # Given: a changed tests/smoke/test_foo.py (NOT in tests/smoke/ui/).
        # When: legs with --test-dir tests/smoke/ui.
        # Then: stdout = legs JSON; stderr = empty -k (the smoke test is not a UI module).
        When run env \
            CI_MATRIX="$FIXTURE_MATRIX" \
            EVENT_NAME="workflow_dispatch" \
            PFB_IMPACTED_CHANGED_FILES="tests/smoke/test_dns_redirect.py" \
            sh "$SCRIPT" legs --test-dir tests/smoke/ui --label tier
        The status should be success
        The output should include '"pfsense_version"'
        The error should include '-k=[]'
    End

End

Describe 'resolve-legs.sh legs — shard expansion (issue #797)'

    # One CE + one Plus leg (mirrors the FIXTURE_MATRIX style above).
    ONE_CE_ONE_PLUS='[{"pfsense_version":"2.8","channel":"CE","ci":true,"image_name":"pfsense-ce","mac":"","freebsd_major":"15","php_version":"8.3","py_flavor":"py311","abi":"FreeBSD:15:amd64"},{"pfsense_version":"26.03","channel":"Plus","ci":true,"image_name":"pfsense-plus","mac":"","freebsd_major":"16","php_version":"8.5","py_flavor":"py312","abi":"FreeBSD:16:amd64"}]'

    # 3 known test_*.py modules — --test-dir clamp target (PFB_FIXTURES/shard-modules).
    SHARD_DIR="${PFB_FIXTURES}/shard-modules"

    setup() {
        scrub_git_env
        unset SCOPE_INPUT VERSION_INPUT PYTEST_FILTER_INPUT MARKER_INPUT SHARDS_INPUT GITHUB_OUTPUT GITHUB_ENV PFB_BASE_REF
    }
    BeforeEach 'setup'

    It 'SHARDS_INPUT=2, no -k, marker smoke -> EVERY leg expands to 2 shards (CE and Plus alike), total 4 legs'
        # Given: full scope (no -k), default marker, a 3-module test-dir (>= 2 shards).
        # When: legs runs with SHARDS_INPUT=2.
        # Then: one `shards` value drives every channel — CE and Plus each
        #       become 2 entries (0-based shard 0/1 of 2, display labels 1/2 and
        #       2/2); no entry keeps a capped shard_total "1" (issue #856
        #       validated same-identity parallel Plus boots, so Plus is no
        #       longer special-cased); the array carries 4 legs total.
        When run env \
            CI_MATRIX="$ONE_CE_ONE_PLUS" \
            EVENT_NAME="workflow_dispatch" \
            SCOPE_INPUT="full" \
            SHARDS_INPUT="2" \
            sh "$SCRIPT" legs --test-dir "$SHARD_DIR" --label marker
        The status should be success
        The output should include '"channel":"CE"'
        The output should include '"shard":"0","shard_label":"1","shard_total":"2"'
        The output should include '"shard":"1","shard_label":"2","shard_total":"2"'
        The output should include '"channel":"Plus"'
        The output should not include '"shard_total":"1"'
        The error should include 'legs=4'
    End

    It 'SHARDS_INPUT=2 + PYTEST_FILTER_INPUT set -> collapses to 1 (no expansion)'
        # Given: an explicit -k narrows the run.
        # When: SHARDS_INPUT=2 is also requested.
        # Then: a -k'd run must never fan out to shards that may not contain the
        #       selected tests -- every leg stays shard_total "1".
        When run env \
            CI_MATRIX="$ONE_CE_ONE_PLUS" \
            EVENT_NAME="workflow_dispatch" \
            SCOPE_INPUT="full" \
            SHARDS_INPUT="2" \
            PYTEST_FILTER_INPUT="test_foo" \
            sh "$SCRIPT" legs --test-dir "$SHARD_DIR" --label marker
        The status should be success
        The output should include '"shard":"0","shard_label":"1","shard_total":"1"'
        The output should not include 'shard_total":"2"'
        The error should include 'legs=2'
    End

    It 'SHARDS_INPUT=2 + MARKER_INPUT=repo -> collapses to 1 (no expansion)'
        # Given: a non-default marker (few tests -- a shard slice can collect zero).
        # When: SHARDS_INPUT=2 is also requested.
        # Then: every leg stays shard_total "1".
        When run env \
            CI_MATRIX="$ONE_CE_ONE_PLUS" \
            EVENT_NAME="workflow_dispatch" \
            SCOPE_INPUT="full" \
            SHARDS_INPUT="2" \
            MARKER_INPUT="repo" \
            sh "$SCRIPT" legs --test-dir "$SHARD_DIR" --label marker
        The status should be success
        The output should include '"shard":"0","shard_label":"1","shard_total":"1"'
        The output should not include 'shard_total":"2"'
        The error should include 'legs=2'
    End

    It 'SHARDS_INPUT=5 over a 3-module test-dir -> BOTH legs clamped to 3 shards'
        # Given: a fixture dir with exactly 3 test_*.py modules.
        # When: SHARDS_INPUT requests more shards than modules exist.
        # Then: every leg (CE and Plus) is clamped to 3 shards (0/1/2 of 3),
        #       never 5 — 6 legs total.
        When run env \
            CI_MATRIX="$ONE_CE_ONE_PLUS" \
            EVENT_NAME="workflow_dispatch" \
            SCOPE_INPUT="full" \
            SHARDS_INPUT="5" \
            sh "$SCRIPT" legs --test-dir "$SHARD_DIR" --label marker
        The status should be success
        The output should include '"shard":"0","shard_label":"1","shard_total":"3"'
        The output should include '"shard":"1","shard_label":"2","shard_total":"3"'
        The output should include '"shard":"2","shard_label":"3","shard_total":"3"'
        The output should not include 'shard_total":"5"'
        The output should not include '"shard_total":"1"'
        The error should include 'legs=6'
    End

    It 'SHARDS_INPUT unset/empty -> 1 (uniform fields still present)'
        When run env \
            CI_MATRIX="$ONE_CE_ONE_PLUS" \
            EVENT_NAME="workflow_dispatch" \
            SCOPE_INPUT="full" \
            sh "$SCRIPT" legs --test-dir "$SHARD_DIR" --label marker
        The status should be success
        The output should include '"shard":"0","shard_label":"1","shard_total":"1"'
        The output should not include 'shard_total":"2"'
        The error should include 'legs=2'
    End

    Context 'shard-count parsing errors'
        # Parameters scopes to Examples within THIS Context only (it leaks to
        # every sibling It in the enclosing scope otherwise).
        Parameters
            "abc"
            "0"
            "-1"
        End
        It "SHARDS_INPUT garbage ('$1') -> 1"
            When run env \
                CI_MATRIX="$ONE_CE_ONE_PLUS" \
                EVENT_NAME="workflow_dispatch" \
                SCOPE_INPUT="full" \
                SHARDS_INPUT="$1" \
                sh "$SCRIPT" legs --test-dir "$SHARD_DIR" --label marker
            The status should be success
            The output should include '"shard":"0","shard_label":"1","shard_total":"1"'
            The output should not include 'shard_total":"2"'
            The error should include 'legs=2'
        End
    End

    It 'emitted shard/shard_total are JSON STRINGS, not bare numbers'
        # Given: workflow_call inputs are typed string -- a bare JSON number would
        #        need coercion at every consumer.
        # When: legs runs with shards.
        # Then: the JSON carries "0"/"2" (quoted strings), never bare 0/2.
        When run env \
            CI_MATRIX="$ONE_CE_ONE_PLUS" \
            EVENT_NAME="workflow_dispatch" \
            SCOPE_INPUT="full" \
            SHARDS_INPUT="2" \
            sh "$SCRIPT" legs --test-dir "$SHARD_DIR" --label marker
        The status should be success
        The output should include '"shard":"0"'
        The output should include '"shard_label":"1"'
        The output should include '"shard_total":"2"'
        The output should not include '"shard":0,'
        The output should not include '"shard_label":1,'
        The output should not include '"shard_total":2,'
        The output should not include '"shard_total":2}'
        The error should include 'legs=4'
    End

End

Describe 'resolve-legs.sh image-ref'

    setup() {
        scrub_git_env
        unset INPUT_REF INPUT_VERSION INPUT_IMAGE_NAME SMOKE_IMAGE_REPO SMOKE_IMAGE_NAME SMOKE_IMAGE_TAG GITHUB_OUTPUT
    }
    BeforeEach 'setup'

    It 'INPUT_REF wins over all other vars'
        When run env \
            INPUT_REF="ghcr.io/pfblockerng/pfsense-ce@sha256:abc" \
            INPUT_VERSION="99.99" \
            sh "$SCRIPT" image-ref
        The status should be success
        The output should equal 'ghcr.io/pfblockerng/pfsense-ce@sha256:abc'
        The error should include 'resolved image ref'
    End

    It 'composes ref from SMOKE_IMAGE_REPO + INPUT_IMAGE_NAME + INPUT_VERSION'
        When run env \
            SMOKE_IMAGE_REPO="ghcr.io/pfblockerng" \
            INPUT_IMAGE_NAME="pfsense-ce" \
            INPUT_VERSION="2.8" \
            sh "$SCRIPT" image-ref
        The status should be success
        The output should equal 'ghcr.io/pfblockerng/pfsense-ce:2.8'
        The error should include 'resolved image ref'
    End

    It 'applies defaults when no vars set (pfsense-ce:2.8)'
        # GITHUB_REPOSITORY_OWNER must be set for the fallback REPO compose.
        When run env \
            GITHUB_REPOSITORY_OWNER="pfblockerng" \
            sh "$SCRIPT" image-ref
        The status should be success
        The output should include 'pfsense-ce:2.8'
        The error should include 'resolved image ref'
    End

End

Describe 'resolve-legs.sh exact-image-name'

    setup() {
        scrub_git_env
        unset IMAGE_REF INPUT_IMAGE_NAME
    }
    BeforeEach 'setup'

    It 'strips ghcr path, digest, and tag from IMAGE_REF'
        When run env \
            IMAGE_REF="ghcr.io/pfblockerng/pfsense-ce:2.8@sha256:abc" \
            sh "$SCRIPT" exact-image-name
        The status should be success
        The output should equal 'pfsense-ce'
    End

    It 'falls back to INPUT_IMAGE_NAME when IMAGE_REF is unset'
        When run env \
            INPUT_IMAGE_NAME="pfsense-plus" \
            sh "$SCRIPT" exact-image-name
        The status should be success
        The output should equal 'pfsense-plus'
    End

    It 'defaults to pfsense-ce when both IMAGE_REF and INPUT_IMAGE_NAME are unset'
        When run sh "$SCRIPT" exact-image-name
        The status should be success
        The output should equal 'pfsense-ce'
    End

End

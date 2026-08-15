"""Static contract for the branch-independent Nightly workflow."""

import itertools
import re
from pathlib import Path

import pytest

WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "nightly.yml"
ALERT_WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "nightly-failure-alert.yml"


def _extract_indented_block(text: str, anchor: str) -> str:
    """Return the ``anchor:`` line plus every following line indented deeper than
    it (blank lines pass through), stopping at the first line back at or above
    the anchor's own indent.

    Replaces a fixed-width slice: a hardcoded character count silently
    truncates (or reads past the block into an unrelated sibling key) the
    moment the block's rendered length drifts from the guess.
    """
    lines = text.splitlines()
    anchor_index = next(i for i, line in enumerate(lines) if line.strip() == anchor)
    anchor_indent = len(lines[anchor_index]) - len(lines[anchor_index].lstrip(" "))
    body = itertools.takewhile(
        lambda line: not line.strip() or (len(line) - len(line.lstrip(" "))) > anchor_indent,
        lines[anchor_index + 1 :],
    )
    return "\n".join([lines[anchor_index], *body])


def _extract_job(text: str, job_name: str) -> str:
    """Return the body of a top-level ``  <job_name>:`` job block, bounded to the
    next sibling job at the same (2-space) indentation, or end-of-file.

    Mirrors ``tests/_workflow_steps.extract_step``'s sibling-boundary idea, one
    indentation level up (job keys, not `- name:` step items).
    """
    marker = re.compile(rf"^  {re.escape(job_name)}:\n", re.MULTILINE)
    match = marker.search(text)
    assert match is not None, f"job {job_name!r} not found in workflow"
    start = match.end()
    sibling = re.compile(r"^  [A-Za-z0-9_-]+:\n", re.MULTILINE)
    next_match = sibling.search(text, start)
    end = next_match.start() if next_match else len(text)
    return text[start:end]


def test_nightly_workflow_exists_and_is_branch_independent() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "name: Nightly snapshot" in text
    assert "workflow_dispatch:" in text
    assert "schedule:" in text
    assert "NIGHTLY_SOURCE_REF: ${{ vars.NIGHTLY_SOURCE_REF }}" in text
    assert "source_ref:" in text
    assert "source_sha:" in text
    assert "rev-parse HEAD" in text
    assert "cancel-in-progress: false" in text
    assert "queue: max" in text
    assert "read-version-matrix.sh" in text
    assert "--print-build" in text
    assert "--print-route" in text
    assert "build-record" in text
    assert "pkgversion" in text
    assert "actions/upload-artifact@" in text
    assert "nightly-handoff-" in text
    assert "nightly-state" not in text
    assert "contents: write" not in _extract_indented_block(text, "permissions:")
    assert "::error::missing live BUILD/ROUTE matrix rows" in text
    assert 'nightly_provenance.py" handoff' in text
    assert '--pkg-version "$PKG_VERSION"' in text
    assert "PORTS_REF_COUNT" in text
    assert "PORTS_HEAD_SHA" in text
    assert "PORTS_TAG_SHA" in text
    assert "refs/tags/${PORTS_REF}^{}" in text
    assert "LC_ALL=C sort -u" in text
    assert "^[0-9a-f]{40}$" in text
    assert 'SOURCE_SHORT_SHA="$(printf \'%.7s\' "$SOURCE_SHA")"' in text
    assert 'PKG_VERSION="${BUILD_TIMESTAMP}.${SOURCE_SHORT_SHA}"' in text

    forbidden = ("gh release", "git tag", "git push", "release notes", "PORTVERSION")
    assert not any(token in text for token in forbidden), "Nightly workflow must not publish or mutate Ports"


def test_matrix_gate_red_canary_guards_live_matrix_enforcement() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    start = text.index("      - name: Resolve pinned source, Ports, and live matrices")
    end = text.index("\n      - name: Expose pinned plan", start)
    step = text[start:end]

    canary = (
        "if matrix_gate '[]' '[]'; then\n"
        '            echo "::error::matrix gate red canary passed"\n'
        "            exit 1\n"
        "          fi"
    )
    assert "matrix_nonempty() {" in step
    assert "matrix_gate() {" in step
    assert canary in step
    assert 'echo "matrix gate red canary: expected rejection"' in step
    assert '(cd "$TRUSTED_DIR" && sh scripts/read-version-matrix.sh \\' in step
    assert 'if ! matrix_gate "$BUILD_MATRIX" "$ROUTE_MATRIX"; then' in step
    assert 'echo "::error::missing live BUILD/ROUTE matrix rows"' in step
    assert "TOOLS_SHA=" in step
    assert "matrix_sha" in step
    assert "tools_sha" in step
    assert step.index(canary) < step.index('if ! matrix_gate "$BUILD_MATRIX" "$ROUTE_MATRIX"')


def test_nightly_failure_alert_watches_snapshot_workflow() -> None:
    text = ALERT_WORKFLOW.read_text(encoding="utf-8")

    assert '- "Nightly snapshot"' in text


def _build_and_verify_step(text: str) -> str:
    start = text.index("      - name: Build and verify package")
    end = text.index("\n      - name: Upload verified build", start)
    return text[start:end]


def _build_leg_invocation(step: str) -> str:
    marker = 'sh "$TRUSTED_DIR/scripts/build-leg.sh"'
    start = step.index(marker)
    end = step.index(")", start)
    return step[start:end]


def _assert_build_leg_pins_prepare_sha(build_leg: str) -> None:
    assert '--ports-ref "$PORTS_SHA"' in build_leg
    assert '--ports-ref "$PORTS_REF"' not in build_leg


def test_build_step_clones_ports_at_prepare_sha() -> None:
    """issue #2406: BUILD clones prepare's PORTS_SHA; PORTS_REF is ls-remote only."""
    text = WORKFLOW.read_text(encoding="utf-8")
    step = _build_and_verify_step(text)
    build_leg = _build_leg_invocation(step)

    _assert_build_leg_pins_prepare_sha(build_leg)
    assert 'if [ "$ACTUAL_PORTS_SHA" != "$PORTS_SHA" ]; then' in step

    prepare_start = text.index("      - name: Resolve pinned source, Ports, and live matrices")
    prepare_end = text.index("\n      - name: Expose pinned plan", prepare_start)
    prepare = text[prepare_start:prepare_end]
    assert prepare.count('git ls-remote "$PORTS_URL"') == 1
    assert "refs/heads/${PORTS_REF}" in prepare
    assert 'echo "ports_sha=$PORTS_SHA"' in prepare


def test_build_leg_ports_ref_pin_rejects_moving_branch() -> None:
    """issue #2406: swapping SHA for REF on the build-leg line is RED."""
    text = WORKFLOW.read_text(encoding="utf-8")
    build_leg = _build_leg_invocation(_build_and_verify_step(text))
    mutated = build_leg.replace('--ports-ref "$PORTS_SHA"', '--ports-ref "$PORTS_REF"', 1)
    with pytest.raises(AssertionError):
        _assert_build_leg_pins_prepare_sha(mutated)


_ORIGIN_COUNT_COMPARE = 'if [ "$DEP_COPIED" -ne "$ORIGIN_COUNT" ]; then'
_DEP_PKG_GLOB = 'for DEP_PKG in "$DEP_PKG_DIR"/*.pkg;'


def _assert_build_step_compares_dep_pkg_count(step: str) -> None:
    """issue #2405: after the glob, ORIGIN_COUNT == copied dep *.pkg count."""
    assert _DEP_PKG_GLOB in step
    assert _ORIGIN_COUNT_COMPARE in step
    assert step.index(_DEP_PKG_GLOB) < step.index(_ORIGIN_COUNT_COMPARE)
    compare_tail = step[step.index(_ORIGIN_COUNT_COMPARE) :]
    assert 'echo "::error::' in compare_tail
    assert "exit 1" in compare_tail


def test_build_step_compares_origin_count_to_copied_dep_pkgs() -> None:
    """issue #2405: BUILD step compares ORIGIN_COUNT to copied dep *.pkg files."""
    step = _build_and_verify_step(WORKFLOW.read_text(encoding="utf-8"))
    _assert_build_step_compares_dep_pkg_count(step)
    assert "result/*.pkg" in step


def test_dropping_origin_count_compare_leaves_glob_and_goes_red() -> None:
    """issue #2405: deleting the ORIGIN_COUNT compare, leaving the glob, is RED."""
    step = _build_and_verify_step(WORKFLOW.read_text(encoding="utf-8"))
    _assert_build_step_compares_dep_pkg_count(step)
    mutated = step.replace(_ORIGIN_COUNT_COMPARE, "", 1)
    assert _DEP_PKG_GLOB in mutated
    with pytest.raises(AssertionError):
        _assert_build_step_compares_dep_pkg_count(mutated)


def test_build_step_builds_and_hands_off_dependency_packages() -> None:
    """issue #2146 S1: the BUILD leg also builds this leg's extra_pkgs dep
    .pkgs (issue #1806), with NO tagged-style rename, and folds them into
    result.json's dep_artifacts."""
    text = WORKFLOW.read_text(encoding="utf-8")
    start = text.index("      - name: Build and verify package")
    end = text.index("\n      - name: Upload verified build", start)
    step = text[start:end]

    # W1: build-dep-pkg-portable.py invoked with the full flag set.
    assert "build-dep-pkg-portable.py" in step
    assert "--ports" in step
    assert "--port" in step
    assert "--py-flavor" in step
    assert "--freebsd-major" in step
    assert "--out-dir" in step

    # W2: loop driven by the matrix row's extra_pkgs, sparse-checkout add per origin.
    assert ".extra_pkgs" in step
    assert 'git -C "$PORTS_DIR" sparse-checkout add "$ORIGIN"' in step

    # W3: no rename -- nightly dep .pkgs keep their canonical filename.
    assert "-${VARIANT}-${PFSENSE_VERSION}.pkg" not in step
    assert "RENAMED_DEP" not in step

    # W4: result.json construction includes dep_artifacts.
    assert "dep_artifacts" in step
    assert "DEP_ARTIFACTS_JSON" in step


def test_handoff_step_has_no_durable_completion() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    start = text.index("      - name: Create verified publisher handoff")
    end = text.index("\n      - name: Upload verified publisher handoff", start)
    step = text[start:end]

    assert "--pkg-version" in step
    assert "complete" not in step
    assert "state" not in step


# --------------------------------------------------------------------------- #
# issue #2146 S3 — the publish-pkg-repo job: the only production catalogue
# mutation, ordered after the handoff job's own success.
# --------------------------------------------------------------------------- #


def test_publish_pkg_repo_job_runs_after_prepare_and_handoff() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    job = _extract_job(text, "publish-pkg-repo")

    assert 'name: "Publish the pkg catalogue"' in job
    assert "needs: [prepare, handoff]" in job
    assert "needs.prepare.outputs.outcome" not in job


def test_publish_pkg_repo_job_permissions_are_read_only() -> None:
    """W3: job-level permissions never carry contents: write -- the push rides the
    minted App token (create-github-app-token), never GITHUB_TOKEN."""
    text = WORKFLOW.read_text(encoding="utf-8")
    job = _extract_job(text, "publish-pkg-repo")
    perms_block = _extract_indented_block(job, "permissions:")
    assert "packages: read" in perms_block
    assert "contents: read" in perms_block
    assert "contents: write" not in perms_block


def test_publish_pkg_repo_job_checks_out_pinned_trusted_tools() -> None:
    """W4: trusted-tools checkout pinned to prepare's own tools_sha, path trusted --
    same pinned-checkout idiom every other job in this workflow already uses, and
    the security rationale release-published.yml's own pinned checkout documents
    (this step is EXECUTED AS SHELL and, via publish_nightly.py, holds an App
    token able to push to pfBlockerNG/pkg)."""
    text = WORKFLOW.read_text(encoding="utf-8")
    job = _extract_job(text, "publish-pkg-repo")
    assert "ref: ${{ needs.prepare.outputs.tools_sha }}" in job
    assert "path: trusted" in job
    assert "SECURITY" in job


def test_publish_pkg_repo_job_mints_scoped_app_token() -> None:
    """W5: mirrors release-published.yml's own App-token step -- same secrets,
    same narrowed permission-contents: write, scoped to pfBlockerNG/pkg."""
    text = WORKFLOW.read_text(encoding="utf-8")
    job = _extract_job(text, "publish-pkg-repo")
    assert "actions/create-github-app-token@v3" in job
    assert "app-id: ${{ secrets.PKG_GITHUB_APP_ID }}" in job
    assert "private-key: ${{ secrets.PKG_GITHUB_APP_PRIVATE_KEY }}" in job
    assert "owner: pfBlockerNG" in job
    assert "repositories: pkg" in job
    assert "permission-contents: write" in job


def test_publish_pkg_repo_job_checks_out_pkg_repo_with_app_token() -> None:
    """W6: pfBlockerNG/pkg checkout carries the minted token with
    persist-credentials true (publish-pkg-repo.sh's push rides this checkout's
    own credential helper)."""
    text = WORKFLOW.read_text(encoding="utf-8")
    job = _extract_job(text, "publish-pkg-repo")
    assert "repository: pfBlockerNG/pkg" in job
    assert "ref: main" in job
    assert "token: ${{ steps.app-token.outputs.token }}" in job
    assert "persist-credentials: true" in job
    assert "path: pkg-repo" in job
    assert "fetch-depth: 1" in job


def test_publish_pkg_repo_job_downloads_both_handoff_and_result_artifacts() -> None:
    """W7: both artifact downloads -- the single-file handoff and every
    nightly-result-<major>/ leg, merge-multiple false (one directory per leg,
    matching what the handoff job's own download step already requires)."""
    text = WORKFLOW.read_text(encoding="utf-8")
    job = _extract_job(text, "publish-pkg-repo")
    assert "name: nightly-handoff-${{ github.run_id }}" in job
    assert "path: handoff" in job
    assert "pattern: nightly-result-*" in job
    assert "path: results" in job
    assert "merge-multiple: false" in job


def test_publish_pkg_repo_job_invokes_the_trusted_wrapper_with_nightly_kind() -> None:
    """W8: PUBLISH_KIND=nightly, SOURCE_RUN_ID = run_id:run_attempt (same
    composition as the handoff job's own stale-callback identity), path env vars
    exported in the RUN BODY not the env: map (issue #2231), and the wrapper is
    invoked from the TRUSTED checkout, never the pkg-repo one."""
    text = WORKFLOW.read_text(encoding="utf-8")
    job = _extract_job(text, "publish-pkg-repo")
    assert "PUBLISH_KIND=nightly" in job
    assert 'SOURCE_RUN_ID="${GITHUB_RUN_ID}:${GITHUB_RUN_ATTEMPT}"' in job
    assert 'PFB_SRC="$GITHUB_WORKSPACE/trusted"' in job
    assert 'PKG_REPO="$GITHUB_WORKSPACE/pkg-repo"' in job
    assert 'HANDOFF_FILE="$GITHUB_WORKSPACE/handoff/nightly-handoff.json"' in job
    assert 'RESULTS_DIR="$GITHUB_WORKSPACE/results"' in job
    assert "BASE_URL=https://pfblockerng.github.io/pkg" in job
    assert "sh trusted/scripts/publish-pkg-repo.sh" in job


def test_publish_pkg_repo_job_documents_new_dispatch_after_failure() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    job = _extract_job(text, "publish-pkg-repo")
    assert "Failed Nightly? Dispatch another one." in job
    assert "No durable allocation exists" in job

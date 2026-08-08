"""Static contract for the branch-independent Nightly workflow."""

from pathlib import Path

WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "nightly.yml"
ALERT_WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "nightly-failure-alert.yml"


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
    assert "read-version-matrix.sh" in text
    assert "--print-build" in text
    assert "--print-route" in text
    assert "build-record" in text
    assert "pkgversion" in text
    assert "actions/upload-artifact@" in text
    assert "nightly-handoff-" in text
    assert "nightly-state" in text
    assert "contents: write" in text
    assert "always()" in text
    assert "::error::missing live BUILD/ROUTE matrix rows" in text
    assert "::error::BUILD matrix failed or did not complete successfully" in text
    assert 'nightly_provenance.py" handoff' in text
    assert "--state plan/state.json" in text
    assert "--allocation plan/allocation.json" in text
    assert "--expected-input-digest" in text
    assert "PORTS_REF_COUNT" in text
    assert "PORTS_HEAD_SHA" in text
    assert "PORTS_TAG_SHA" in text
    assert "refs/tags/${PORTS_REF}^{}" in text
    assert "LC_ALL=C sort -u" in text
    assert "^[0-9a-f]{40}$" in text
    assert ".encoding" in text
    assert "(HTTP 404)" in text
    assert "VERIFIED=0" in text
    assert "for _ in 1 2 3 4 5" in text
    assert "persisted nightly-state.json does not match" in text
    assert "jq -er '.pkg_version' allocation.json" in text

    forbidden = ("gh release", "git tag", "git push", "release notes", "PORTVERSION")
    assert not any(token in text for token in forbidden), "Nightly workflow must not publish or mutate Ports"


def test_matrix_gate_red_canary_guards_live_matrix_enforcement() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    start = text.index("      - name: Resolve pinned source, Ports, and live matrices")
    end = text.index("\n      - name: Select plan outcome", start)
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


def test_handoff_step_artifact_extraction_stays_canonical_only() -> None:
    """W5: the handoff step's durable-state artifact extraction remains
    canonical-only -- dep_artifacts must never reach `complete`/state.json."""
    text = WORKFLOW.read_text(encoding="utf-8")
    start = text.index("      - name: Create verified publisher handoff")
    end = text.index("\n      - name: Upload verified publisher handoff", start)
    step = text[start:end]

    assert "jq '[.builds[].artifact]' nightly-handoff.json > artifacts.json" in step
    assert "dep_artifacts" not in step

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

    forbidden = ("gh release", "git tag", "git push", "release notes", "PORTVERSION")
    assert not any(token in text for token in forbidden), "Nightly workflow must not publish or mutate Ports"


def test_matrix_gate_red_canary_guards_live_matrix_enforcement() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    start = text.index("      - name: Resolve pinned source, Ports, and live matrices")
    end = text.index("\n      - name: Select plan outcome", start)
    step = text[start:end]

    canary = (
        "if matrix_nonempty '[]'; then\n"
        '            echo "::error::matrix gate red canary passed"\n'
        "            exit 1\n"
        "          fi"
    )
    assert "matrix_nonempty() {" in step
    assert canary in step
    assert 'echo "matrix gate red canary: expected rejection"' in step
    assert 'BUILD_MATRIX="$(sh "$TRUSTED_DIR/scripts/read-version-matrix.sh" \\' in step
    assert 'ROUTE_MATRIX="$(sh "$TRUSTED_DIR/scripts/read-version-matrix.sh" \\' in step
    assert 'if ! matrix_nonempty "$BUILD_MATRIX" || ! matrix_nonempty "$ROUTE_MATRIX"; then' in step
    assert 'echo "::error::missing live BUILD/ROUTE matrix rows"' in step
    assert step.index(canary) < step.index('if ! matrix_nonempty "$BUILD_MATRIX"')


def test_nightly_failure_alert_watches_snapshot_workflow() -> None:
    text = ALERT_WORKFLOW.read_text(encoding="utf-8")

    assert '- "Nightly snapshot"' in text

"""Issue #2450 step 3: pkg-render-site.yml wired into every catalogue publisher.

scripts/render-pkg-site.sh (step 2) renders the pkg website (everything under
pkg's docs/ EXCEPT the catalogue-owned trees) from this repo's pkg-site/. This
step wires it into CI: a reusable + dispatchable workflow that runs it, called
by every catalogue-publishing workflow after its own publish job, plus removes
the retired PUBLISH_REFRESH_LANDING/BASE_URL knobs those publishers no longer
need (publish-pkg-repo.sh dropped both when site rendering split out).
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"

RENDER = (WORKFLOWS / "pkg-render-site.yml").read_text(encoding="utf-8")
REPUBLISH = (WORKFLOWS / "pkg-republish.yml").read_text(encoding="utf-8")
PUBLISHED = (WORKFLOWS / "release-published.yml").read_text(encoding="utf-8")
NIGHTLY = (WORKFLOWS / "nightly.yml").read_text(encoding="utf-8")


def _extract_job(text: str, job_name: str) -> str:
    """Return the body of a top-level ``  <job_name>:`` job block, bounded to the
    next sibling job at the same (2-space) indentation, or end-of-file.

    Same sibling-boundary idiom as tests/_workflow_steps.extract_step and the
    other workflow suites' own ``_extract_job`` (tests/test_issue2389_live_pages_gate.py,
    tests/test_nightly_workflow_contract.py) — duplicated locally rather than
    imported, matching their own convention.
    """
    marker = re.compile(rf"^  {re.escape(job_name)}:\n", re.MULTILINE)
    match = marker.search(text)
    assert match is not None, f"job {job_name!r} not found"
    start = match.end()
    nxt = re.search(r"^  [A-Za-z0-9_-]+:\n", text[start:], re.MULTILINE)
    end = start + nxt.start() if nxt else len(text)
    return text[start:end]


# --------------------------------------------------------------------------- #
# 1. pkg-render-site.yml itself.
# --------------------------------------------------------------------------- #


def test_render_site_workflow_declares_both_triggers_with_source_ref() -> None:
    on_block = RENDER.split("on:", 1)[1].split("permissions:", 1)[0]
    assert "workflow_call:" in on_block
    assert "workflow_dispatch:" in on_block
    assert on_block.count("source_ref:") == 2


def test_render_site_job_runs_the_renderer_with_full_env_contract() -> None:
    job = _extract_job(RENDER, "render")
    step = job.split("- name: Render the pkg website", 1)[1]
    assert "sh scripts/render-pkg-site.sh" in step
    assert "SOURCE_RUN_ID: ${{ github.run_id }}:${{ github.run_attempt }}" in step
    assert "ROUTE_MATRIX: ${{ steps.route.outputs.route_matrix }}" in step
    assert "BASE_URL: https://pkg.pfblockerng.com" in step
    assert 'export PFB_SRC="$GITHUB_WORKSPACE"' in step
    assert 'export PKG_REPO="$GITHUB_WORKSPACE/pkg-repo"' in step


def test_render_site_job_pins_source_ref_and_credentials() -> None:
    job = _extract_job(RENDER, "render")
    assert "ref: ${{ inputs.source_ref || github.sha }}" in job
    assert "permission-contents: write" in job
    assert "repositories: pkg" in job
    assert "persist-credentials: true" in job


def test_render_site_job_has_no_second_concurrency_lock() -> None:
    assert "concurrency:" not in _extract_job(RENDER, "render")


def test_render_site_workflow_declares_an_explicit_secrets_contract() -> None:
    """Least-privilege secrets (CodeRabbit finding, PR #2451 review): workflow_call
    must declare exactly the two secrets the render job needs, both required — so a
    caller can never fall back to forwarding every repository/org secret."""
    on_block = RENDER.split("on:", 1)[1].split("permissions:", 1)[0]
    call_block = on_block.split("workflow_call:", 1)[1].split("workflow_dispatch:", 1)[0]
    secrets_block = call_block.split("secrets:", 1)[1]
    assert re.search(r"^\s+PKG_GITHUB_APP_ID:\n\s+required: true\s*$", secrets_block, re.MULTILINE), secrets_block
    assert re.search(r"^\s+PKG_GITHUB_APP_PRIVATE_KEY:\n\s+required: true\s*$", secrets_block, re.MULTILINE), (
        secrets_block
    )


# --------------------------------------------------------------------------- #
# 2. Every publisher workflow calls it after its own publish job.
# --------------------------------------------------------------------------- #

# The explicit two-key secrets map every render-site caller must use instead of
# `secrets: inherit` (least-privilege, CodeRabbit finding, PR #2451 review) —
# PKG_GITHUB_APP_ID and PKG_GITHUB_APP_PRIVATE_KEY are the ONLY secrets
# pkg-render-site.yml's own `workflow_call.secrets` block declares.
_EXPLICIT_RENDER_SECRETS = (
    "PKG_GITHUB_APP_ID: ${{ secrets.PKG_GITHUB_APP_ID }}",
    "PKG_GITHUB_APP_PRIVATE_KEY: ${{ secrets.PKG_GITHUB_APP_PRIVATE_KEY }}",
)


def test_pkg_republish_calls_render_site_after_publish() -> None:
    job = _extract_job(REPUBLISH, "render-site")
    assert "uses: ./.github/workflows/pkg-render-site.yml" in job
    assert "secrets: inherit" not in job
    for line in _EXPLICIT_RENDER_SECRETS:
        assert line in job, job
    assert "needs: publish" in job or "needs: [publish]" in job
    assert 'source_ref: "${{ github.workflow_sha }}"' in job or "source_ref: ${{ github.workflow_sha }}" in job


def test_release_published_calls_render_site_after_publish_and_promote() -> None:
    job = _extract_job(PUBLISHED, "render-site")
    assert "uses: ./.github/workflows/pkg-render-site.yml" in job
    assert "secrets: inherit" not in job
    for line in _EXPLICIT_RENDER_SECRETS:
        assert line in job, job
    assert "needs: [publish-pkg-repo, promote-pkg-repo]" in job
    assert "if: always() && needs.publish-pkg-repo.result == 'success'" in job
    assert 'source_ref: "${{ github.workflow_sha }}"' in job or "source_ref: ${{ github.workflow_sha }}" in job


def test_nightly_calls_render_site_after_publish_with_trusted_ref() -> None:
    job = _extract_job(NIGHTLY, "render-site")
    assert "uses: ./.github/workflows/pkg-render-site.yml" in job
    assert "secrets: inherit" not in job
    for line in _EXPLICIT_RENDER_SECRETS:
        assert line in job, job
    assert "needs: [prepare, publish-pkg-repo]" in job
    assert (
        'source_ref: "${{ needs.prepare.outputs.tools_sha }}"' in job
        or "source_ref: ${{ needs.prepare.outputs.tools_sha }}" in job
    )


# --------------------------------------------------------------------------- #
# 3. Retired knobs are gone from every publisher; BASE_URL lives only in the
#    render workflow.
# --------------------------------------------------------------------------- #


def test_no_publisher_step_still_sets_the_retired_knobs() -> None:
    for name, text in (
        ("pkg-republish.yml", REPUBLISH),
        ("release-published.yml", PUBLISHED),
        ("nightly.yml", NIGHTLY),
    ):
        assert "BASE_URL" not in text, f"{name} still sets BASE_URL — that belongs to pkg-render-site.yml alone"
        assert "refresh_landing" not in text, f"{name} still carries the retired refresh_landing input"
        assert "PUBLISH_REFRESH_LANDING" not in text, f"{name} still sets the retired PUBLISH_REFRESH_LANDING knob"


def test_no_other_github_workflow_references_the_retired_knobs() -> None:
    for path in sorted(WORKFLOWS.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        assert "refresh_landing" not in text, f"{path.relative_to(ROOT)} still references refresh_landing"
        assert "PUBLISH_REFRESH_LANDING" not in text, (
            f"{path.relative_to(ROOT)} still references PUBLISH_REFRESH_LANDING"
        )


# --------------------------------------------------------------------------- #
# 4. CATALOGUE_DIRS stays pinned identical across both shell scripts and
#    gen_landing.py's own constant of the same name.
# --------------------------------------------------------------------------- #

_SPEC = importlib.util.spec_from_file_location("gen_landing", ROOT / "scripts" / "gen_landing.py")
assert _SPEC and _SPEC.loader
gl = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(gl)


def _shell_catalogue_dirs(script_relpath: str) -> tuple[str, ...]:
    text = (ROOT / script_relpath).read_text(encoding="utf-8")
    match = re.search(r'^CATALOGUE_DIRS="([^"]*)"$', text, re.MULTILINE)
    assert match is not None, f'{script_relpath} has no CATALOGUE_DIRS="..." literal'
    return tuple(match.group(1).split())


def test_render_pkg_site_sh_catalogue_dirs_matches_gen_landing() -> None:
    assert _shell_catalogue_dirs("scripts/render-pkg-site.sh") == gl.CATALOGUE_DIRS


def test_publish_pkg_repo_sh_catalogue_dirs_matches_gen_landing() -> None:
    assert _shell_catalogue_dirs("scripts/publish-pkg-repo.sh") == gl.CATALOGUE_DIRS

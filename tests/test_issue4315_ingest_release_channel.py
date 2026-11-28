"""Issue #4315 -- the tagged-release ingest gate builds the release's own source with its own recipe.

``pkg-tagged-ingest.yml``'s live gate calls ``smoke-single.yml``, whose ``build-pkg`` job builds the
branch ``.pkg`` through ``build-pkg-linux.yml``. That gate used to check out the ``devel`` commit
the workflow ran from and build it with the nightly recipe, so a nightly-only ports change broke
the ingest of an edge tag (``v4.0.0.b6``). The ingest now passes the release's channel and
``source_sha``; every other caller keeps building ``nightly`` from its own ref.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"
NIGHTLY_FALLBACK = "inputs.channel || 'nightly'"


def _workflow(name: str) -> dict[Any, Any]:
    doc: dict[Any, Any] = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    return doc


def _triggers(name: str) -> dict[str, Any]:
    doc = _workflow(name)
    triggers: dict[str, Any] = doc[True]  # PyYAML reads the bare `on:` key as the boolean True
    return triggers


def _checkout_refs(job: dict[str, Any]) -> list[Any]:
    return [
        s.get("with", {}).get("ref") for s in job["steps"] if str(s.get("uses", "")).startswith("actions/checkout@")
    ]


def test_ingest_gate_builds_the_release_source_with_the_release_channel() -> None:
    """The live gate passes the tag's channel and checks out the tag's pinned source SHA."""
    gate = _workflow("pkg-tagged-ingest.yml")["jobs"]["validate-live-pages-install"]

    assert gate["uses"] == "./.github/workflows/smoke-single.yml"
    assert gate["with"].get("channel") == "${{ inputs.channel }}", gate["with"]
    assert gate["with"].get("checkout_ref") == "${{ inputs.source_sha }}", gate["with"]


def test_smoke_single_channel_defaults_to_nightly() -> None:
    """Devel's own smoke runs, which pass no channel, keep the nightly recipe devel pairs with.

    Callers get a ``channel`` input defaulting to nightly. A dispatch cannot carry one (GitHub
    caps workflow_dispatch at 25 inputs, all taken), so its empty value falls back to nightly too.
    """
    triggers = _triggers("smoke-single.yml")
    build = _workflow("smoke-single.yml")["jobs"]["build-pkg"]

    assert triggers["workflow_call"]["inputs"].get("channel", {}).get("default") == "nightly"
    assert "channel" not in triggers["workflow_dispatch"]["inputs"]
    assert build["with"].get("channel") == NIGHTLY_FALLBACK.join(("${{ ", " }}")), build["with"]


def test_smoke_single_builds_the_checked_out_source() -> None:
    """The branch .pkg is built from the ref the suite checks out (blank = the caller's ref)."""
    build = _workflow("smoke-single.yml")["jobs"]["build-pkg"]

    assert build["uses"] == "./.github/workflows/build-pkg-linux.yml"
    assert build["with"].get("checkout_ref") == "${{ inputs.checkout_ref }}", build["with"]


def test_build_pkg_linux_packages_the_caller_named_ref() -> None:
    """The portable build packages the caller's ref; blank keeps actions/checkout's default."""
    call_inputs = _triggers("build-pkg-linux.yml")["workflow_call"]["inputs"]
    build = _workflow("build-pkg-linux.yml")["jobs"]["build"]

    assert call_inputs.get("checkout_ref", {}).get("default") == "", call_inputs.get("checkout_ref")
    assert _checkout_refs(build) == ["${{ inputs.checkout_ref }}"]


def test_nightly_pkg_step_runs_only_for_a_nightly_channel() -> None:
    """The repo-flow -nightly .pkg serves only the nightly-install cases.

    Building it from a release line's source would pair that source with the nightly recipe,
    the mismatch this issue removes; a nightly caller (repo-install.yml, nightly.yml) still builds it.
    """
    steps = _workflow("smoke-single.yml")["jobs"]["smoke"]["steps"]
    nightly = [s for s in steps if s.get("name") == "Build a nightly .pkg (repo-flow nightly smoke)"]

    assert len(nightly) == 1, [s.get("name") for s in steps]
    condition = str(nightly[0].get("if", ""))
    assert "(inputs.pytest_marker || 'smoke') == 'repo'" in condition, condition
    assert f"({NIGHTLY_FALLBACK}) == 'nightly'" in condition, condition
    unwrapped = condition.replace("(inputs.pytest_marker || 'smoke')", "").replace(f"({NIGHTLY_FALLBACK})", "")
    assert "||" not in unwrapped, condition


def test_other_smoke_single_callers_keep_the_nightly_default() -> None:
    """Only the tagged ingest names a channel: every other caller keeps building nightly."""
    callers = {}
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for job_id, job in (_workflow(path.name).get("jobs") or {}).items():
            if job.get("uses") == "./.github/workflows/smoke-single.yml":
                callers[f"{path.name}:{job_id}"] = (job.get("with") or {}).get("channel")

    assert "pkg-tagged-ingest.yml:validate-live-pages-install" in callers, sorted(callers)
    named = {caller: channel for caller, channel in callers.items() if channel is not None}
    assert named == {"pkg-tagged-ingest.yml:validate-live-pages-install": "${{ inputs.channel }}"}

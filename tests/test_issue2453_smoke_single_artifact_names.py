"""Pin issue #2453: smoke-single.yml's self-build path must key pkg / dep-pkgs
artifact names on live route and pfsense_version, not only image_name + shard.

repo-install.yml fans smoke-single.yml out over the ci-metadata matrix, and CE 2.8 / CE 2.9
share image_name=pfsense-ce (Plus legs share pfsense-plus). With image_name-only names two
per-version legs of ONE run upload the same artifact name and the CE 2.9 leg can download the
CE 2.8 (FreeBSD:15) .pkg -> `pkg: wrong architecture: FreeBSD:15:* instead of FreeBSD:16:amd64`.
Tagged publication also runs stable/testing/edge siblings for one version, so their nested
build artifacts need the explicit route key used by build-pkg-linux concurrency.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMOKE_SINGLE_WORKFLOW = ROOT / ".github/workflows/smoke-single.yml"

ROUTE_KEY = "${{ inputs.concurrency_key || 'non-live' }}"
ARTIFACT_AXES = "${{ inputs.image_name }}-${{ inputs.pfsense_version }}-s${{ inputs.shard }}"
PKG_NAME = f"pfBlockerNG-pkg-{ROUTE_KEY}-{ARTIFACT_AXES}"
DEP_NAME = f"pfBlockerNG-deppkgs-{ROUTE_KEY}-{ARTIFACT_AXES}"
DEP_DOWNLOAD = (
    "format('pfBlockerNG-deppkgs-{0}-{1}-{2}-s{3}', inputs.concurrency_key || 'non-live', "
    "inputs.image_name, inputs.pfsense_version, inputs.shard)"
)


def _lines() -> list[str]:
    return SMOKE_SINGLE_WORKFLOW.read_text(encoding="utf-8").splitlines()


def _value_lines(key: str) -> list[str]:
    return [line.strip() for line in _lines() if line.strip().startswith(f"{key}:") and "${{" in line]


def test_self_build_pkg_artifact_name_carries_pfsense_version() -> None:
    lines = _value_lines("artifact_name")
    assert lines == [f"artifact_name: {PKG_NAME}"], lines


def test_self_build_dep_artifact_name_carries_pfsense_version() -> None:
    lines = _value_lines("dep_artifact_name")
    assert lines == [f"dep_artifact_name: {DEP_NAME}"], lines


def test_dep_download_fallback_matches_self_build_name() -> None:
    lines = [line for line in _lines() if "inputs.dep_artifact != ''" in line]
    assert len(lines) == 1, lines
    assert DEP_DOWNLOAD in lines[0], lines[0]


LEGACY_FORMS = (
    "pfBlockerNG-pkg-${{ inputs.image_name }}-s${{",
    "pfBlockerNG-deppkgs-${{ inputs.image_name }}-s${{",
    "format('pfBlockerNG-deppkgs-{0}-s{1}', inputs.image_name, inputs.shard)",
    "<image_name>-s<shard>",
)


def test_no_image_name_only_pkg_names_remain() -> None:
    text = SMOKE_SINGLE_WORKFLOW.read_text(encoding="utf-8")
    for legacy in LEGACY_FORMS:
        assert legacy not in text, legacy


def test_legacy_forms_are_what_the_pre_fix_workflow_carried() -> None:
    """Fixture for the negative sweep above: rebuild the pre-#2453 text by dropping
    pfsense_version from every fixed site and check each LEGACY_FORMS entry hits it, so
    a typo in a legacy pattern cannot turn the sweep vacuous."""
    text = SMOKE_SINGLE_WORKFLOW.read_text(encoding="utf-8")
    pre_fix = (
        text.replace(f"pfBlockerNG-pkg-{ROUTE_KEY}-", "pfBlockerNG-pkg-")
        .replace(f"pfBlockerNG-deppkgs-{ROUTE_KEY}-", "pfBlockerNG-deppkgs-")
        .replace("-${{ inputs.pfsense_version }}-s${{", "-s${{")
        .replace(DEP_DOWNLOAD, "format('pfBlockerNG-deppkgs-{0}-s{1}', inputs.image_name, inputs.shard)")
        .replace("<concurrency_key-or-non-live>-<image_name>-<pfsense_version>-s<shard>", "<image_name>-s<shard>")
    )
    assert pre_fix != text
    for legacy in LEGACY_FORMS:
        assert legacy in pre_fix, legacy

"""Workflow-file hygiene gates (issue #2231).

Successor to the retired ``test_workflow_container_migration.py`` (removed with
this change), carrying the two invariants that file could never see plus the one
surface it never scanned:

1. GitHub's workflow parser REJECTS a YAML mapping with a duplicate key and
   silently disables the workflow — it shows in the Actions UI under its file
   path instead of its name, and its triggers (including ``schedule:``) never
   fire. PyYAML's default loader keeps one duplicate and hides the breakage, so
   every repo-side check stayed green while five scheduled workflows were dead.
2. GitHub Actions never shell-expands ``env:`` map VALUES — only ``${{ }}``
   expressions are substituted there. A bare ``$GITHUB_*``/``$RUNNER_*`` in an
   env-map value reaches the job as a literal dollar-string; paths derived from
   those variables belong in ``run:`` bodies, where a shell actually expands
   them (and where the container-translated value is the correct one).
3. ``scripts/local-smoke.sh`` must run the same ci-runner image series the
   workflows pin (``.github/docker/VERSION``): the local-smoke container spec
   strips the tag before asserting and the workflow-side gates scan only
   ``.github/workflows/``, so the bootstrap's tag had no drift gate at all.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _workflow_files() -> list[Path]:
    files = sorted((ROOT / ".github/workflows").glob("*.yml"))
    files += sorted((ROOT / ".github/actions").glob("*/action.yml"))
    assert files, "no workflow files found — wrong ROOT?"
    return files


# --------------------------------------------------------------------------- #
# 1. Duplicate mapping keys — what GitHub rejects, PyYAML must not hide.
# --------------------------------------------------------------------------- #


class _DuplicateKeyError(yaml.YAMLError):
    pass


class _DuplicateRejectingLoader(yaml.SafeLoader):
    """SafeLoader that refuses what GitHub's parser refuses."""


def _construct_mapping_rejecting_duplicates(
    loader: _DuplicateRejectingLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    seen: set[Any] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=True)
        if key in seen:
            raise _DuplicateKeyError(f"duplicate key {key!r} at line {key_node.start_mark.line + 1}")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


_DuplicateRejectingLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping_rejecting_duplicates
)


def _load_rejecting_duplicates(path: Path) -> Any:
    return yaml.load(path.read_text(encoding="utf-8"), _DuplicateRejectingLoader)


def test_no_workflow_carries_a_duplicate_mapping_key() -> None:
    offenders: list[str] = []
    for path in _workflow_files():
        try:
            _load_rejecting_duplicates(path)
        except _DuplicateKeyError as exc:
            offenders.append(f"{path.relative_to(ROOT)}: {exc}")
    assert not offenders, (
        "GitHub refuses a workflow whose YAML carries a duplicate mapping key — the file "
        "loses its name in the Actions UI and its triggers never fire:\n  " + "\n  ".join(offenders)
    )


# --------------------------------------------------------------------------- #
# 2. env: map values are never shell-expanded.
# --------------------------------------------------------------------------- #

# $GITHUB_FOO and ${GITHUB_FOO} alike; ${{ github.foo }} never matches (lowercase).
_BARE_RUNNER_VAR = re.compile(r"\$\{?(?:GITHUB|RUNNER)_[A-Z]")


def _env_map_offences(doc: Any, where: str) -> list[str]:
    """Recursively collect env-map values carrying a bare runner variable."""
    offences: list[str] = []
    if isinstance(doc, dict):
        env = doc.get("env")
        if isinstance(env, dict):
            for key, value in env.items():
                if isinstance(value, str) and _BARE_RUNNER_VAR.search(value):
                    offences.append(f"{where}: env {key}: {value!r}")
        for child in doc.values():
            offences.extend(_env_map_offences(child, where))
    elif isinstance(doc, list):
        for child in doc:
            offences.extend(_env_map_offences(child, where))
    return offences


def test_env_map_values_never_carry_bare_runner_path_variables() -> None:
    offenders: list[str] = []
    for path in _workflow_files():
        # Duplicate keys are gate 1's finding; the default loader keeps this
        # gate's scan independent of it.
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        offenders.extend(_env_map_offences(doc, str(path.relative_to(ROOT))))
    assert not offenders, (
        "GitHub Actions performs no shell expansion inside env: map values — these reach "
        "the job as literal dollar-strings. Export the path inside the run: body instead:\n  " + "\n  ".join(offenders)
    )


# --------------------------------------------------------------------------- #
# 3. local-smoke.sh runs the pinned image series.
# --------------------------------------------------------------------------- #


def test_local_smoke_pins_the_current_ci_runner_series() -> None:
    version = int((ROOT / ".github/docker/VERSION").read_text(encoding="utf-8").strip())
    text = (ROOT / "scripts/local-smoke.sh").read_text(encoding="utf-8")
    tags = [int(tag) for tag in re.findall(r"ci-runner(?:-vm)?:([0-9]+)", text)]
    assert tags, "local-smoke.sh no longer names a ci-runner image — update this gate"
    assert tags == [version] * len(tags), (
        f"local-smoke.sh pins ci-runner series {tags}, but .github/docker/VERSION is "
        f"{version} — a local run would exercise a different toolchain than CI ships"
    )

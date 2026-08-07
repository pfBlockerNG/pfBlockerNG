"""Workflow-file hygiene gates (issue #2231).

1. No duplicate mapping keys: GitHub's workflow parser rejects the file and
   silently disables the workflow (path shown instead of name, triggers —
   including ``schedule:`` — never fire); PyYAML's default loader keeps one
   duplicate, so only a duplicate-rejecting load can see this.
2. No bare ``$GITHUB_*``/``$RUNNER_*`` in ``env:`` map values: GitHub Actions
   substitutes only ``${{ }}`` expressions there, never shell variables — such
   a value reaches the job as a literal dollar-string. Paths derived from
   runner variables belong in ``run:`` bodies.
3. ``scripts/local-smoke.sh`` runs the same ci-runner image series the
   workflows pin (``.github/docker/VERSION``) — no other gate scans that file.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _workflow_files() -> list[Path]:
    workflows = ROOT / ".github/workflows"
    files = sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")])
    actions = ROOT / ".github/actions"
    files += sorted([*actions.glob("*/action.yml"), *actions.glob("*/action.yaml")])
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

"""Workflow-file hygiene gates (issue #2231).

Deliberately stdlib-only: the CI pytest leg runs inside ci-runner, which bakes
no PyYAML, and the test.yml drift gate (test_benchmarks_ci_deps.py) bans any
`pip install` there. Duplicate-key/schema/expression validation is actionlint's
job (the `actionlint` job in test.yml; adoption tracked in #2232) — these gates
cover only what actionlint cannot:

1. No bare ``$GITHUB_*``/``$RUNNER_*`` in ``env:`` map values: GitHub Actions
   substitutes only ``${{ }}`` expressions there, never shell variables — such
   a value reaches the job as a literal dollar-string (schema-legal, so
   actionlint accepts it). Paths derived from runner variables belong in
   ``run:`` bodies.
2. ``scripts/local-smoke.sh`` runs the same ci-runner image series the
   workflows pin (``.github/docker/VERSION``) — no other gate scans that file.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _workflow_files() -> list[Path]:
    workflows = ROOT / ".github/workflows"
    files = sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")])
    actions = ROOT / ".github/actions"
    files += sorted([*actions.glob("*/action.yml"), *actions.glob("*/action.yaml")])
    assert files, "no workflow files found — wrong ROOT?"
    return files


# --------------------------------------------------------------------------- #
# 1. env: map values are never shell-expanded.
# --------------------------------------------------------------------------- #

# $GITHUB_FOO and ${GITHUB_FOO} alike; ${{ github.foo }} never matches (lowercase).
_BARE_RUNNER_VAR = re.compile(r"\$\{?(?:GITHUB|RUNNER)_[A-Z]")
_ENV_KEY = re.compile(r"^(\s*)env:\s*(?:#.*)?$")
_MAP_ENTRY = re.compile(r"^(\s*)([A-Za-z_][\w.-]*):\s*(.*)$")
# `key: |` / `key: >` open a block scalar (a run body, a folded step name).
# The `- ` list-item form puts SIBLING keys two columns deeper than the dash,
# so the scalar's effective indent is the KEY's, not the dash's.
_BLOCK_SCALAR = re.compile(r"^(\s*)(- )?[\w.-]+:\s*[|>][+-]?\d*\s*(?:#.*)?$")


def _env_map_offences(text: str, where: str) -> list[str]:
    """Line scanner: report env-map entries whose value carries a bare runner
    variable. Tracks block scalars so ``run:`` bodies (plain text to YAML) are
    never scanned, and tracks the current ``env:`` block by indentation."""
    offences: list[str] = []
    scalar_indent: int | None = None  # inside a block scalar deeper than this
    env_indent: int | None = None  # inside an env: map opened at this indent
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if scalar_indent is not None:
            if indent > scalar_indent:
                continue
            scalar_indent = None
        if env_indent is not None and indent <= env_indent:
            env_indent = None
        scalar = _BLOCK_SCALAR.match(line)
        if scalar:
            scalar_indent = indent + (2 if scalar.group(2) else 0)
            continue
        env_open = _ENV_KEY.match(line)
        if env_open:
            env_indent = len(env_open.group(1))
            continue
        if env_indent is None:
            continue
        entry = _MAP_ENTRY.match(line)
        if entry and _BARE_RUNNER_VAR.search(entry.group(3)):
            offences.append(f"{where}:{line_no}: env {entry.group(2)}: {entry.group(3)!r}")
    return offences


def test_env_map_values_never_carry_bare_runner_path_variables() -> None:
    offenders: list[str] = []
    for path in _workflow_files():
        offenders.extend(_env_map_offences(path.read_text(encoding="utf-8"), str(path.relative_to(ROOT))))
    assert not offenders, (
        "GitHub Actions performs no shell expansion inside env: map values — these reach "
        "the job as literal dollar-strings. Export the path inside the run: body instead:\n  " + "\n  ".join(offenders)
    )


def test_env_map_scanner_catches_a_planted_offence() -> None:
    """Vacuity guard for the scanner itself: a planted env-map literal is
    reported, and the same variable inside a run: block scalar is not."""
    fixture = (
        "jobs:\n"
        "  x:\n"
        "    env:\n"
        "      GOOD: ${{ github.workspace }}/out\n"
        "      BAD: $GITHUB_WORKSPACE/out\n"
        "      WORSE: ${RUNNER_TEMP}/assets\n"
        "    steps:\n"
        "      - run: |\n"
        '          export FINE="$GITHUB_WORKSPACE/out"\n'
        "      - name: >-\n"
        "          a folded step name must not swallow its sibling keys\n"
        "        env:\n"
        "          AFTER_FOLD: $RUNNER_TEMP/x\n"
    )
    offences = _env_map_offences(fixture, "fixture.yml")
    assert [o.split(" env ")[1] for o in offences] == [
        "BAD: '$GITHUB_WORKSPACE/out'",
        "WORSE: '${RUNNER_TEMP}/assets'",
        "AFTER_FOLD: '$RUNNER_TEMP/x'",
    ], offences


# --------------------------------------------------------------------------- #
# 2. local-smoke.sh runs the pinned image series.
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

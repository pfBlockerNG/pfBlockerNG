"""Workflow-file hygiene gates (issue #2231).

Deliberately stdlib-only: the CI pytest leg runs inside ci-runner, which bakes
no PyYAML, and the test.yml drift gate (test_benchmarks_ci_deps.py) bans any
`pip install` there. For WORKFLOW files, duplicate-key/schema/expression
validation is actionlint's job (the `actionlint` job in test.yml; #2232).
actionlint speaks only the workflow schema, so `.github/actions/*/action.yml`
has no duplicate-key gate — tolerable because a malformed action manifest
fails its referencing job LOUDLY at use, unlike a workflow file, which GitHub
disables silently. These gates cover what actionlint cannot:

1. No bare ``$GITHUB_*``/``$RUNNER_*`` in ``env:`` map values: GitHub Actions
   substitutes only ``${{ }}`` expressions there, never shell variables — such
   a value reaches the job as a literal dollar-string (schema-legal, so
   actionlint accepts it). Paths derived from runner variables belong in
   ``run:`` bodies.
2. Every workflow ``image:`` pin rides the series ``.github/docker/VERSION``
   names — a stale pin runs a whole job family on an old toolchain silently.
3. ``scripts/local-smoke.sh`` runs that same series — no other gate scans it.
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
    never scanned — EXCEPT a scalar that is itself an env entry's value, whose
    body is exactly the unexpanded string the job receives — and tracks the
    current ``env:`` block by indentation."""
    offences: list[str] = []
    scalar_indent: int | None = None  # inside a block scalar deeper than this
    scalar_env_key: str | None = None  # ...which is an env VALUE under this key
    env_indent: int | None = None  # inside an env: map opened at this indent
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip() or (scalar_indent is None and line.lstrip().startswith("#")):
            continue
        indent = len(line) - len(line.lstrip())
        if scalar_indent is not None:
            if indent > scalar_indent:
                if scalar_env_key is not None and _BARE_RUNNER_VAR.search(line):
                    offences.append(f"{where}:{line_no}: env {scalar_env_key}: {line.strip()!r}")
                continue
            scalar_indent = None
            scalar_env_key = None
        if env_indent is not None and indent <= env_indent:
            env_indent = None
        scalar = _BLOCK_SCALAR.match(line)
        if scalar:
            scalar_indent = indent + (2 if scalar.group(2) else 0)
            if env_indent is not None:
                scalar_env_key = line.strip().split(":", 1)[0]
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
        "          MULTILINE: >-\n"
        "            an env VALUE spelled as a block scalar is still\n"
        "            unexpanded $GITHUB_WORKSPACE text\n"
    )
    offences = _env_map_offences(fixture, "fixture.yml")
    assert [o.split(" env ")[1] for o in offences] == [
        "BAD: '$GITHUB_WORKSPACE/out'",
        "WORSE: '${RUNNER_TEMP}/assets'",
        "AFTER_FOLD: '$RUNNER_TEMP/x'",
        "MULTILINE: 'unexpanded $GITHUB_WORKSPACE text'",
    ], offences


# --------------------------------------------------------------------------- #
# 2. Workflows and local-smoke.sh run the pinned image series.
# --------------------------------------------------------------------------- #


def test_workflows_pin_the_current_ci_runner_series() -> None:
    """Every container job must ride the series `.github/docker/VERSION` names —
    the invariant lost with the retired migration test (PR #2233), resurrected
    here where CI actually executes it. A stale pin runs a whole job family on
    an old toolchain while the gates read as green (issue #2232).

    The series lives in the trailing `/pfblockerng/ci-runner(-vm)?:N` path
    segment regardless of what prefixes it: a bare `ghcr.io/...` ref (hosted
    jobs) or the `${{ vars.PFB_LAN_REGISTRY || 'ghcr.io' }}/...` expression
    (self-hosted jobs, issue #2230) both name the same series the same way.
    Matching only `ghcr\\.io/...` would silently stop scanning the six
    self-hosted sites the day #2230 landed — the floor assertion below is the
    tripwire for that regression."""
    version = int((ROOT / ".github/docker/VERSION").read_text(encoding="utf-8").strip())
    offenders: list[str] = []
    refs_found = 0
    for path in _workflow_files():
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for tag in re.findall(r"/pfblockerng/ci-runner(?:-vm)?:([0-9]+)", line):
                refs_found += 1
                if int(tag) != version:
                    offenders.append(f"{path.relative_to(ROOT)}:{line_no}: series {tag} != {version}")
    # Today's count (issue #2230): 64 total ci-runner(-vm) refs across workflows
    # + actions. A regex that stops matching the expression-form sites would
    # scan fewer refs and pass vacuously instead of failing loudly.
    assert refs_found >= 64, (
        f"only found {refs_found} ci-runner(-vm) refs, expected at least 64 — "
        "the series regex likely stopped matching some ref form"
    )
    assert not offenders, "workflow image pins must match .github/docker/VERSION:\n  " + "\n  ".join(offenders)


def test_local_smoke_pins_the_current_ci_runner_series() -> None:
    version = int((ROOT / ".github/docker/VERSION").read_text(encoding="utf-8").strip())
    text = (ROOT / "scripts/local-smoke.sh").read_text(encoding="utf-8")
    tags = [int(tag) for tag in re.findall(r"ci-runner(?:-vm)?:([0-9]+)", text)]
    assert tags, "local-smoke.sh no longer names a ci-runner image — update this gate"
    assert tags == [version] * len(tags), (
        f"local-smoke.sh pins ci-runner series {tags}, but .github/docker/VERSION is "
        f"{version} — a local run would exercise a different toolchain than CI ships"
    )

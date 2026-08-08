"""Self-hosted fleet pulls route through the LAN zot registry (issue #2230).

Deliberately stdlib-only, mirroring tests/test_issue2231_workflow_hygiene.py: the
CI pytest leg runs inside ci-runner, which bakes no PyYAML. Workflow-schema
validation is actionlint's job (the `actionlint` job in test.yml; #2232); this
is a stray-ref guard actionlint cannot express — a self-hosted `container.image`
naming a literal `ghcr.io/...` ref is schema-legal but bypasses the LAN registry
routing, silently reverting every pull on that job to the public path.

Only `runs-on:` blocks naming `self-hosted` AND carrying a `container.image` are
in scope: GitHub-hosted jobs cannot reach the LAN registry (10.0.0.111) at all,
so their literal `ghcr.io/...` refs are correct and must never be flagged.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_EXPECTED_IMAGE_PREFIX = "${{ vars.PFB_LAN_REGISTRY || 'ghcr.io' }}/"

_JOBS_KEY = re.compile(r"^jobs:\s*$", re.MULTILINE)
_JOB_HEADER = re.compile(r"^  ([A-Za-z0-9_.-]+):\s*(?:#.*)?$")
_SELF_HOSTED = re.compile(r"runs-on:.*self-hosted")
_IMAGE_LINE = re.compile(r"^\s*image:\s*(\S.*?)\s*$", re.MULTILINE)


def _workflow_files() -> list[Path]:
    workflows = ROOT / ".github/workflows"
    files = sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")])
    assert files, "no workflow files found — wrong ROOT?"
    return files


def _job_blocks(text: str) -> list[tuple[str, str]]:
    """Split the ``jobs:`` mapping into ``(job_name, block_text)`` pairs.

    Job entries sit at 2-space indent directly under a top-level ``jobs:`` key;
    everything more-indented (or blank) belongs to that job until the next
    2-space-indent header or a dedent back to column 0."""
    jobs_start = _JOBS_KEY.search(text)
    if not jobs_start:
        return []
    blocks: list[tuple[str, list[str]]] = []
    current_name: str | None = None
    current_lines: list[str] = []
    for line in text[jobs_start.end() :].splitlines():
        header = _JOB_HEADER.match(line)
        if header:
            if current_name is not None:
                blocks.append((current_name, current_lines))
            current_name = header.group(1)
            current_lines = [line]
            continue
        if current_name is None:
            continue
        if line and not line[0].isspace():
            # Dedented out of the jobs: mapping entirely.
            blocks.append((current_name, current_lines))
            current_name = None
            current_lines = []
            continue
        current_lines.append(line)
    if current_name is not None:
        blocks.append((current_name, current_lines))
    return [(name, "\n".join(lns)) for name, lns in blocks]


def _flag_stray_refs(blocks: dict[str, str]) -> list[str]:
    """Return the names of self-hosted+container jobs whose image is not the
    LAN-registry expression."""
    flagged: list[str] = []
    for name, block in blocks.items():
        if not _SELF_HOSTED.search(block):
            continue
        image_match = _IMAGE_LINE.search(block)
        if image_match is None:
            continue
        if not image_match.group(1).startswith(_EXPECTED_IMAGE_PREFIX):
            flagged.append(name)
    return flagged


def test_self_hosted_container_jobs_pull_through_the_lan_registry() -> None:
    """Every self-hosted job with a `container.image` must route the pull
    through `${{ vars.PFB_LAN_REGISTRY || 'ghcr.io' }}/...` (issue #2230): the
    box fleet hijacks ghcr.io via /etc/hosts to the LAN zot mirror at
    10.0.0.111, and a literal ref skips that routing silently rather than
    failing loudly."""
    offenders: list[str] = []
    checked = 0
    for path in _workflow_files():
        blocks = dict(_job_blocks(path.read_text(encoding="utf-8")))
        for name in blocks:
            if not _SELF_HOSTED.search(blocks[name]):
                continue
            if _IMAGE_LINE.search(blocks[name]) is None:
                continue
            checked += 1
        for name in _flag_stray_refs(blocks):
            offenders.append(f"{path.relative_to(ROOT)} job {name!r}")
    assert checked >= 6, (
        f"expected at least 6 self-hosted container jobs (issue #2230's six sites), found {checked} "
        "— job-block scanner regressed or the workflows changed shape"
    )
    assert not offenders, (
        "self-hosted container jobs must pull via ${{ vars.PFB_LAN_REGISTRY || 'ghcr.io' }}/... "
        "not a literal ghcr.io ref (issue #2230):\n  " + "\n  ".join(offenders)
    )


def test_scanner_catches_a_planted_stray_ref() -> None:
    """Vacuity guard for the scanner itself: a self-hosted job with a literal
    ref is flagged, the LAN-registry expression form is not, and a
    GitHub-hosted job with a literal ref is never even considered."""
    fixture = (
        "jobs:\n"
        "  ok:\n"
        "    runs-on: [self-hosted, Linux, X64]\n"
        "    container:\n"
        "      image: ${{ vars.PFB_LAN_REGISTRY || 'ghcr.io' }}/pfblockerng/ci-runner-vm:4\n"
        "  stray:\n"
        "    runs-on: [self-hosted, Linux, X64]\n"
        "    container:\n"
        "      image: ghcr.io/pfblockerng/ci-runner-vm:4\n"
        "  hosted:\n"
        "    runs-on: ubuntu-latest\n"
        "    container:\n"
        "      image: ghcr.io/pfblockerng/ci-runner:4\n"
        "  no-container:\n"
        "    runs-on: [self-hosted, Linux, X64]\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    blocks = dict(_job_blocks(fixture))
    assert set(blocks) == {"ok", "stray", "hosted", "no-container"}, blocks
    assert _flag_stray_refs(blocks) == ["stray"], _flag_stray_refs(blocks)

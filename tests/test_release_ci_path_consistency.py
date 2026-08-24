"""Keep release CI fallback exclusions aligned with workflow path filters."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

_JOB_HEADER_RE = re.compile(r"^  ([A-Za-z][A-Za-z0-9_-]*):[ \t]*$")


def _workflow_jobs(path: Path) -> dict[str, list[str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    body = lines[lines.index("jobs:") + 1 :]
    jobs: dict[str, list[str]] = {}
    current: str | None = None
    for line in body:
        match = _JOB_HEADER_RE.match(line)
        if match is not None:
            current = match.group(1)
            jobs[current] = []
        elif current is not None:
            jobs[current].append(line)
    return jobs


def _workflow_paths_from_source(source: str, trigger: str) -> list[str]:
    lines = source.splitlines()
    trigger_line = f"  {trigger}:"
    try:
        start = lines.index(trigger_line)
    except ValueError as exc:
        raise AssertionError(f"workflow trigger {trigger!r} is missing") from exc
    end = next(
        (index for index in range(start + 1, len(lines)) if re.fullmatch(r"  [A-Za-z_][A-Za-z0-9_-]*:", lines[index])),
        len(lines),
    )
    try:
        paths_start = next(index for index in range(start + 1, end) if lines[index] == "    paths-ignore:")
    except StopIteration as exc:
        raise AssertionError(f"{trigger}: missing paths-ignore") from exc
    paths: list[str] = []
    for line in lines[paths_start + 1 : end]:
        if line and not line.startswith("      "):
            break
        if not line:
            continue
        match = re.fullmatch(r"      - '(.+)'", line)
        if match is None:
            raise AssertionError(f"unparsed paths-ignore entry: {line!r}")
        paths.append(match.group(1))
    return paths


def _workflow_paths(trigger: str) -> list[str]:
    source = (ROOT / ".github/workflows/test.yml").read_text()
    return _workflow_paths_from_source(source, trigger)


def _release_gate_paths() -> list[str]:
    source = (ROOT / "scripts/release-ci-gate.sh").read_text()
    return re.findall(r"':\(top,exclude,(?:glob|literal)\)([^']+)'", source)


def test_release_fallback_exclusions_match_both_workflow_triggers() -> None:
    push = _workflow_paths("push")
    pull_request = _workflow_paths("pull_request")
    release_gate = _release_gate_paths()

    assert push, "push paths-ignore must not be empty"
    assert pull_request, "pull_request paths-ignore must not be empty"
    assert release_gate, "release fallback exclusions must not be empty"
    assert pull_request == push, f"pull_request paths-ignore differs from push: {pull_request!r} != {push!r}"
    assert release_gate == push, f"release fallback exclusions differ from workflow: {release_gate!r} != {push!r}"


def test_issue_2388_ports_sync_runs_only_after_published_release_resolution() -> None:
    published_path = ROOT / ".github/workflows/release-published.yml"
    published = published_path.read_text(encoding="utf-8")
    release_jobs = _workflow_jobs(ROOT / ".github/workflows/release.yml")
    published_jobs = _workflow_jobs(published_path)
    assert "sync-ports-fork" not in release_jobs, "the draft workflow must stop at the complete draft"
    assert "sync-ports-fork" in published_jobs, "publishing must trigger the FreeBSD-ports bump"
    job_names = list(published_jobs)
    assert job_names.index("sync-ports-fork") == job_names.index("resolve") + 1
    concurrency = published.split("\nconcurrency:\n", 1)[1].split("\njobs:\n", 1)[0]
    assert "  queue: max" in concurrency, "every published release must keep its queued ports bump"

    sync = "\n".join(published_jobs["sync-ports-fork"])
    assert re.search(r"^    needs: \[resolve\]$", sync, re.MULTILINE), sync
    assert "dry_run" not in sync, "the published event has no draft-workflow dry-run gate"
    for env_name, output in {
        "SOURCE": "source",
        "TAG": "release_tag",
        "CHANNEL": "channel",
        "PORTVERSION": "portversion",
    }.items():
        assert re.search(
            rf"^          {env_name}:\s+\$\{{\{{ needs\.resolve\.outputs\.{output} \}}\}}$",
            sync,
            re.MULTILINE,
        ), f"{env_name} must consume needs.resolve.outputs.{output}"

    resolve = "\n".join(published_jobs["resolve"])
    for output, classify_output in {
        "source": "source",
        "release_tag": "tag",
        "channel": "channel",
        "portversion": "portversion",
    }.items():
        assert re.search(
            rf"^      {output}:\s+\$\{{\{{ steps\.classify\.outputs\.{classify_output} \}}\}}$",
            resolve,
            re.MULTILINE,
        ), f"resolve must expose {output} for sync-ports-fork"


def test_workflow_parser_does_not_cross_trigger_boundaries() -> None:
    source = """\
on:
  push:
    branches:
      - devel
  pull_request:
    paths-ignore:
      - '**/*.md'
"""

    with pytest.raises(AssertionError, match="push: missing paths-ignore"):
        _workflow_paths_from_source(source, "push")


def test_workflow_parser_rejects_unparsed_path_entries() -> None:
    source = """\
on:
  push:
    paths-ignore:
      - "**/*.md"
"""

    with pytest.raises(AssertionError, match="unparsed paths-ignore entry"):
        _workflow_paths_from_source(source, "push")

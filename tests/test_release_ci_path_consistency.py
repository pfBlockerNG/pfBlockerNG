"""Keep release CI fallback exclusions and workflow concurrency contracts aligned."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _workflow_steps import extract_step

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


def test_issue_2387_tagged_build_uses_one_pinned_route_and_ports_identity() -> None:
    release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    jobs = _workflow_jobs(ROOT / ".github/workflows/release.yml")
    read_matrix = "\n".join(jobs["read-matrix"])
    build = "\n".join(jobs["build-pkgs-portable"])

    for output in ("route_matrix", "ci_metadata_sha", "ports_sha"):
        assert re.search(
            rf"^      {output}:\s+\$\{{\{{ steps\.pins\.outputs\.{output} \}}\}}$",
            read_matrix,
            re.MULTILINE,
        ), f"read-matrix must expose the build-time {output}"
    assert "ref: ${{ steps.pins.outputs.ci_metadata_sha }}" in read_matrix
    assert read_matrix.count("git ls-remote https://github.com/pfBlockerNG/FreeBSD-ports") == 1

    assert "git ls-remote" not in build
    build_step = extract_step(release, "Build the .pkg via build-leg.sh")
    assert "PORTS_SHA: ${{ needs.read-matrix.outputs.ports_sha }}" in build_step
    assert build_step.count("sh scripts/build-leg.sh") == 1
    assert build_step.count('--ports-ref  "$PORTS_SHA"') == 1


def test_issue_2387_pin_step_executes_against_exact_ci_metadata_sha(tmp_path: Path) -> None:
    release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    script = textwrap.dedent(
        extract_step(release, "Pin ci-metadata, ROUTE, and Ports identities").split("run: |\n", 1)[1]
    )
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    git_log = tmp_path / "git.log"
    matrix = tmp_path / "supported-versions.json"
    output = tmp_path / "github-output"
    ci_sha = "a" * 40
    ports_sha = "b" * 40
    matrix.write_text(
        '{"versions":[{"pfsense_version":"2.8","channel":"CE",'
        '"freebsd_version":"15.0-RELEASE","freebsd_major":"15",'
        '"php_version":"8.3","py_flavor":"py311","variant":"CE",'
        '"status":"active","extra_pkgs":[]}]}\n',
        encoding="utf-8",
    )
    fake_git = fake_bin / "git"
    fake_git.write_text(
        textwrap.dedent(
            """\
            #!/bin/sh
            printf '%s\\n' "$*" >> "$GIT_LOG"
            case "$1" in
              fetch) exit 0 ;;
              rev-parse) printf '%s\\n' "$CI_SHA" ;;
              ls-remote) printf '%s\\trefs/heads/pfblockerng/use-github\\n' "$PORTS_SHA" ;;
              show) cat "$MATRIX_FIXTURE" ;;
              *) printf 'unexpected git command: %s\\n' "$*" >&2; exit 1 ;;
            esac
            """
        ),
        encoding="utf-8",
    )
    fake_git.chmod(0o755)

    completed = subprocess.run(
        ["sh", "-c", script],
        cwd=ROOT,
        env=os.environ
        | {
            "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}",
            "GITHUB_OUTPUT": str(output),
            "GITHUB_WORKSPACE": str(ROOT),
            "GIT_LOG": str(git_log),
            "MATRIX_FIXTURE": str(matrix),
            "CI_SHA": ci_sha,
            "PORTS_SHA": ports_sha,
        },
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    emitted = output.read_text(encoding="utf-8")
    assert f"ci_metadata_sha={ci_sha}" in emitted
    assert f"ports_sha={ports_sha}" in emitted
    assert '"pfsense_version":"2.8"' in emitted
    commands = git_log.read_text(encoding="utf-8")
    assert "fetch --no-tags origin +refs/heads/ci-metadata:refs/remotes/origin/ci-metadata" in commands
    assert "rev-parse refs/remotes/origin/ci-metadata^{commit}" in commands
    assert f"show {ci_sha}:supported-versions.json" in commands
    assert commands.count("ls-remote ") == 1


def test_issue_2387_draft_persists_the_exact_tagged_handoff_asset() -> None:
    release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    create = extract_step(release, "Create tagged release handoff")
    for value in (
        "RELEASE_TAG: ${{ needs.prepare-release.outputs.tag }}",
        "SOURCE_SHA: ${{ needs.prepare-release.outputs.sha }}",
        "CI_METADATA_SHA: ${{ needs.read-matrix.outputs.ci_metadata_sha }}",
        "PORTS_SHA: ${{ needs.read-matrix.outputs.ports_sha }}",
        '--release-tag "$RELEASE_TAG"',
        '--source-sha "$SOURCE_SHA"',
        '--ci-metadata-sha "$CI_METADATA_SHA"',
        '--ports-sha "$PORTS_SHA"',
        'ROUTE_MATRIX_FILE="$RUNNER_TEMP/route-matrix.json"',
        '--route-matrix "$ROUTE_MATRIX_FILE"',
    ):
        assert value in create
    draft = extract_step(release, "Create the GitHub Release as a DRAFT")
    assert "${{ env.RELEASE_HANDOFF }}" in draft
    healthcheck = extract_step(release, "Health-check the draft release is complete")
    assert "pfblockerng-release-handoff.json" in healthcheck
    assert "HANDOFF_COUNT" in healthcheck
    assert 'HANDOFF_COUNT" -eq 1' in healthcheck


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


_RELEASE_GROUP_RE = re.compile(
    r"release-\$\{\{ github\.event\.inputs\.dry_run == '(?P<dry>true)' "
    r"&& format\('(?P<template>dry-run-\{0\})', github\.run_id\) "
    r"\|\| github\.event\.inputs\.channel \}\}"
)
_RELEASE_GROUP = (
    "release-${{ github.event.inputs.dry_run == 'true' "
    "&& format('dry-run-{0}', github.run_id) || github.event.inputs.channel }}"
)
_PKG_REPO_MUTATION_GROUP = "pkg-repository-mutation"


def _top_level_concurrency(source: str) -> dict[str, str]:
    lines = source.splitlines()
    try:
        start = lines.index("concurrency:")
    except ValueError as exc:
        raise AssertionError("missing top-level concurrency block") from exc
    end = next(
        (index for index in range(start + 1, len(lines)) if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*:", lines[index])),
        len(lines),
    )
    values: dict[str, str] = {}
    for line in lines[start + 1 : end]:
        if not line or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"  ([A-Za-z][A-Za-z0-9_-]*):[ \t]+(.+)", line)
        assert match is not None, f"unparsed top-level concurrency entry: {line!r}"
        key, value = match.groups()
        assert key not in values, f"duplicate top-level concurrency key: {key}"
        values[key] = value
    return values


def _assert_release_concurrency(source: str) -> None:
    concurrency = _top_level_concurrency(source)
    assert concurrency.get("queue") == "max", "real cuts must retain every queued dispatch"
    assert concurrency.get("cancel-in-progress") == "false", "a running cut must never be cancelled"
    group = concurrency.get("group", "")
    assert _RELEASE_GROUP_RE.fullmatch(group), f"release concurrency group has the wrong ownership: {group!r}"


def _release_group(source: str, *, dry_run: str, channel: str, run_id: int) -> str:
    _assert_release_concurrency(source)
    match = _RELEASE_GROUP_RE.fullmatch(_top_level_concurrency(source)["group"])
    assert match is not None
    suffix = match.group("template").format(run_id) if dry_run == match.group("dry") else channel
    return f"release-{suffix}"


def _assert_pkg_repository_concurrency(source: str) -> None:
    concurrency = _top_level_concurrency(source)
    assert concurrency.get("group") == _PKG_REPO_MUTATION_GROUP
    assert concurrency.get("queue") == "max"
    assert concurrency.get("cancel-in-progress") == "false"


def test_issue_2391_real_release_cuts_are_channel_serialized_and_dry_runs_are_unique() -> None:
    source = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    assert _release_group(source, dry_run="false", channel="stable", run_id=101) == "release-stable"
    assert _release_group(source, dry_run="false", channel="stable", run_id=102) == "release-stable"
    assert _release_group(source, dry_run="false", channel="testing", run_id=101) == "release-testing"
    assert _release_group(source, dry_run="true", channel="stable", run_id=101) == "release-dry-run-101"
    assert _release_group(source, dry_run="true", channel="stable", run_id=102) == "release-dry-run-102"


@pytest.mark.parametrize(
    "offence",
    (
        "missing-block",
        "missing-group",
        "wrong-group",
        "missing-queue",
        "wrong-queue",
        "missing-cancel",
        "wrong-cancel",
    ),
)
def test_issue_2391_release_concurrency_planted_offences_go_red(offence: str) -> None:
    valid = (
        "name: Release\n"
        "concurrency:\n"
        f"  group: {_RELEASE_GROUP}\n"
        "  queue: max\n"
        "  cancel-in-progress: false\n"
        "jobs:\n"
        "  build:\n"
    )
    _assert_release_concurrency(valid)
    mutations = {
        "missing-block": valid.replace(
            f"concurrency:\n  group: {_RELEASE_GROUP}\n  queue: max\n  cancel-in-progress: false\n",
            "",
        ),
        "missing-group": valid.replace(f"  group: {_RELEASE_GROUP}\n", ""),
        "wrong-group": valid.replace("github.event.inputs.channel", "github.run_id"),
        "missing-queue": valid.replace("  queue: max\n", ""),
        "wrong-queue": valid.replace("  queue: max", "  queue: latest"),
        "missing-cancel": valid.replace("  cancel-in-progress: false\n", ""),
        "wrong-cancel": valid.replace("  cancel-in-progress: false", "  cancel-in-progress: true"),
    }
    with pytest.raises(AssertionError):
        _assert_release_concurrency(mutations[offence])


def test_issue_2391_every_external_pkg_repository_mutator_shares_one_queue() -> None:
    workflows = ROOT / ".github/workflows"
    mutators: dict[str, str] = {}
    for path in workflows.glob("*.yml"):
        source = path.read_text(encoding="utf-8")
        if (
            re.search(r"^\s+repository: pfBlockerNG/pkg$", source, re.MULTILINE)
            and "\n  workflow_call:" not in source.split("\njobs:\n", 1)[0]
        ):
            mutators[path.name] = source
    assert set(mutators) == {"nightly.yml", "release-published.yml", "pkg-republish.yml"}
    for source in mutators.values():
        _assert_pkg_repository_concurrency(source)


@pytest.mark.parametrize(
    ("key", "wrong_value"),
    (
        ("group", "tagged-publish-only"),
        ("queue", "latest"),
        ("cancel-in-progress", "true"),
    ),
)
def test_issue_2391_pkg_repository_concurrency_planted_offences_go_red(key: str, wrong_value: str) -> None:
    valid = f"""\
name: Mutator
concurrency:
  group: {_PKG_REPO_MUTATION_GROUP}
  queue: max
  cancel-in-progress: false
jobs:
  publish:
"""
    _assert_pkg_repository_concurrency(valid)
    current_value = _top_level_concurrency(valid)[key]
    mutated = valid.replace(f"  {key}: {current_value}\n", f"  {key}: {wrong_value}\n")
    with pytest.raises(AssertionError):
        _assert_pkg_repository_concurrency(mutated)

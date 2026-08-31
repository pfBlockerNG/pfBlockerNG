"""Keep release CI fallback exclusions and workflow concurrency contracts aligned."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import cast

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _workflow_steps import extract_after, extract_between, extract_step

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
    concurrency = extract_between(published, "\nconcurrency:\n", "\njobs:\n")
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
    assert "dependency_builder: ${{ steps.dependencies.outputs.dependency_builder || 'null' }}" in read_matrix
    assert "dependency_packages: ${{ steps.dependencies.outputs.dependency_packages || '{}' }}" in read_matrix
    assert read_matrix.count("git ls-remote https://github.com/pfBlockerNG/FreeBSD-ports") == 1
    builder_checkout = extract_step(release, "Check out pinned dependency-builder source")
    assert "uses: actions/checkout@v6" in builder_checkout
    assert (
        "ref: ${{ github.event.inputs.source == 'release/3.3' && github.workflow_sha || "
        "steps.destinations.outputs.source_sha }}" in builder_checkout
    )
    assert "path: pinned-builder" in builder_checkout

    assert "git ls-remote" not in build
    build_step = extract_step(release, "Build the .pkg via build-leg.sh")
    assert "PORTS_SHA: ${{ needs.read-matrix.outputs.ports_sha }}" in build_step
    assert build_step.count("sh scripts/build-leg.sh") == 1


@pytest.mark.parametrize(
    ("source", "expected_extra_pkgs", "expected_has_dependencies"),
    [
        ("release/4.0", '["textproc/py-charset-normalizer"]', "true"),
        ("release/3.3", "[]", "false"),
    ],
)
def test_issue_2387_pin_step_executes_against_exact_ci_metadata_sha(
    tmp_path: Path,
    source: str,
    expected_extra_pkgs: str,
    expected_has_dependencies: str,
) -> None:
    release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    script = textwrap.dedent(
        extract_after(extract_step(release, "Pin ci-metadata, ROUTE, and Ports identities"), "run: |\n")
    )
    dependency_script = textwrap.dedent(
        extract_after(extract_step(release, "Resolve dependency identities"), "run: |\n")
    )
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    output = tmp_path / "github-output"
    git_log = tmp_path / "git.log"
    ci_sha = "a" * 40
    ports_sha = "b" * 40
    source_sha = "c" * 40
    source_epoch = 1_700_000_000
    matrix = tmp_path / "supported-versions.json"
    matrix.write_text(
        '{"versions":[{"pfsense_version":"2.8","channel":"CE",'
        '"freebsd_version":"15.0-RELEASE","freebsd_major":"15",'
        '"php_version":"8.3","py_flavor":"py311","variant":"CE",'
        '"status":"active","extra_pkgs":["textproc/py-charset-normalizer"]},'
        '{"pfsense_version":"2.9","channel":"CE",'
        '"freebsd_version":"16.0-RELEASE","freebsd_major":"16",'
        '"php_version":"8.3","py_flavor":"py311","variant":"CE",'
        '"status":"active","extra_pkgs":["textproc/py-charset-normalizer"]}]}\n',
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
              show)
                if [ "$2" = "-s" ]; then printf '%s\\n' "$SOURCE_EPOCH"; else cat "$MATRIX_FIXTURE"; fi
                ;;
              clone)
                for destination do :; done
                mkdir -p "$destination"
                ;;
              -C) exit 0 ;;
              *) printf 'unexpected git command: %s\\n' "$*" >&2; exit 1 ;;
            esac
            """
        ),
        encoding="utf-8",
    )
    fake_git.chmod(0o755)
    builder = tmp_path / "pinned-builder/scripts/build-dep-pkg-portable.py"
    builder.parent.mkdir(parents=True)
    builder.write_text(
        "import json, sys\n"
        "if '--print-port-identity' in sys.argv:\n"
        " print(json.dumps({'port_origin':'textproc/py-charset-normalizer',"
        "'portname':'charset-normalizer','port_version':'3.4.7',"
        "'distfile':'charset_normalizer-3.4.7.tar.gz',"
        "'distfile_sha256':'ae89db9e5f98a11a4bf50407d4363e7b09b31e55bc117b4f7d80aab97ba009e5',"
        "'distfile_size':144271}, separators=(',', ':')))\n"
        "else:\n"
        " print(json.dumps({'python':'3.11.15','pip':'26.2.1','setuptools':'75.6.0',"
        "'wheel':'0.45.1','zstandard':'0.25.0','uv':'0.12.6',"
        "'uv_lock_sha256':'d'*64}, separators=(',', ':')))\n",
        encoding="utf-8",
    )

    completed = subprocess.run(
        ["sh", "-c", script],
        cwd=ROOT,
        env=os.environ
        | {
            "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}",
            "GITHUB_OUTPUT": str(output),
            "GITHUB_WORKSPACE": str(tmp_path),
            "RUNNER_TEMP": str(tmp_path),
            "GIT_LOG": str(git_log),
            "MATRIX_FIXTURE": str(matrix),
            "CI_SHA": ci_sha,
            "PORTS_SHA": ports_sha,
            "SOURCE_SHA": source_sha,
            "SOURCE_EPOCH": str(source_epoch),
            "INPUT_SOURCE": source,
        },
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    emitted = output.read_text(encoding="utf-8")
    assert f"ci_metadata_sha={ci_sha}" in emitted
    assert f"ports_sha={ports_sha}" in emitted
    assert f'"extra_pkgs":{expected_extra_pkgs}' in emitted
    assert f"has_dependencies={expected_has_dependencies}" in emitted
    if source == "release/3.3":
        assert "dependency_builder=" not in emitted
        assert "dependency_packages=" not in emitted
        assert "textproc/py-charset-normalizer" not in emitted
    else:
        route_line = next(line for line in emitted.splitlines() if line.startswith("route_matrix="))
        dependency_output = tmp_path / "dependency-output"
        dependency_completed = subprocess.run(
            ["sh", "-c", dependency_script],
            cwd=ROOT,
            env=os.environ
            | {
                "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}",
                "GITHUB_OUTPUT": str(dependency_output),
                "GITHUB_WORKSPACE": str(tmp_path),
                "RUNNER_TEMP": str(tmp_path),
                "GIT_LOG": str(git_log),
                "ROUTE_MATRIX": route_line.partition("=")[2],
                "PORTS_SHA": ports_sha,
                "SOURCE_DATE_EPOCH": str(source_epoch),
            },
            capture_output=True,
            text=True,
            check=False,
        )
        assert dependency_completed.returncode == 0, dependency_completed.stderr
        dependency_emitted = dependency_output.read_text(encoding="utf-8")
        toolchain = {
            "python": "3.11.15",
            "pip": "26.2.1",
            "setuptools": "75.6.0",
            "wheel": "0.45.1",
            "zstandard": "0.25.0",
            "uv": "0.12.6",
            "uv_lock_sha256": "d" * 64,
        }
        expected: dict[str, dict[str, dict[str, object]]] = {}
        for version, major in (("2.8", "15"), ("2.9", "16")):
            suffix = f"-CE-{version}.pkg"
            identity = {
                "abi": f"FreeBSD:{major}:*",
                "distfile": "charset_normalizer-3.4.7.tar.gz",
                "distfile_sha256": "ae89db9e5f98a11a4bf50407d4363e7b09b31e55bc117b4f7d80aab97ba009e5",
                "distfile_size": 144_271,
                "filename": f"py311-charset-normalizer-3.4.7{suffix}",
                "freebsd_major": major,
                "freebsd_ports_sha": ports_sha,
                "package_name": "py311-charset-normalizer",
                "package_version": "3.4.7",
                "port_version": "3.4.7",
                "portname": "charset-normalizer",
                "py_flavor": "py311",
                "source_date_epoch": source_epoch,
                "toolchain": toolchain,
            }
            expected[suffix] = {"textproc/py-charset-normalizer": identity}
        line = next(line for line in dependency_emitted.splitlines() if line.startswith("dependency_packages="))
        assert json.loads(line.partition("=")[2]) == expected
    commands = git_log.read_text(encoding="utf-8")
    assert "fetch --no-tags origin +refs/heads/ci-metadata:refs/remotes/origin/ci-metadata" in commands
    assert "rev-parse refs/remotes/origin/ci-metadata^{commit}" in commands
    assert f"show {ci_sha}:supported-versions.json" in commands
    assert commands.count("ls-remote ") == 1


def test_release_dependency_loop_executes_every_origin_with_locked_python(tmp_path: Path) -> None:
    release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    script = textwrap.dedent(extract_after(extract_step(release, "Build the .pkg via build-leg.sh"), "run: |\n"))
    lines = script.splitlines()
    start = next(index for index, line in enumerate(lines) if line.strip().startswith("DEP_PKG_DIR="))
    end = next(index for index, line in enumerate(lines[start:], start) if line.strip().startswith("for DEP_PKG in"))
    command = "\n".join(lines[start:end])
    locked_python = tmp_path / ".venv/bin/python"
    locked_python.parent.mkdir(parents=True)
    locked_log = tmp_path / "locked-argv"
    locked_python.write_text('#!/bin/sh\nprintf \'%s\\0\' "$@" >> "$LOCKED_LOG"\n', encoding="utf-8")
    locked_python.chmod(0o755)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    ambient_log = tmp_path / "ambient-argv"
    ambient_python = fake_bin / "python3"
    ambient_python.write_text('#!/bin/sh\nprintf \'%s\\0\' "$@" >> "$AMBIENT_LOG"\n', encoding="utf-8")
    ambient_python.chmod(0o755)
    fake_git = fake_bin / "git"
    fake_git.write_text('#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$GIT_LOG"\n', encoding="utf-8")
    fake_git.chmod(0o755)
    origins = ["textproc/py-charset-normalizer", "devel/py-demo"]
    env = os.environ | {
        "GITHUB_WORKSPACE": str(tmp_path),
        "PFB_RUN_ROOT": str(tmp_path / "run"),
        "RUN_ID": "release-test",
        "EXTRA_PKGS": json.dumps(origins),
        "PORTS_SHA": "a" * 40,
        "PY": "py311",
        "MAJOR": "15",
        "CREATED": "1700000000",
        "LOCKED_LOG": str(locked_log),
        "AMBIENT_LOG": str(ambient_log),
        "GIT_LOG": str(tmp_path / "git.log"),
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
    }

    completed = subprocess.run(
        ["dash", "-c", command],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert not ambient_log.exists()
    argv = locked_log.read_bytes().split(b"\0")[:-1]
    assert argv.count(b"scripts/build-dep-pkg-portable.py") == len(origins)
    for origin in origins:
        assert argv.count(origin.encode()) == 1
    assert (tmp_path / "git.log").read_text(encoding="utf-8").count("sparse-checkout add") == len(origins)


def test_issue_2387_draft_persists_the_exact_tagged_handoff_asset() -> None:
    release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    create = extract_step(release, "Create tagged release handoff")
    for value in (
        "RELEASE_TAG: ${{ needs.prepare-release.outputs.tag }}",
        "SOURCE_SHA: ${{ needs.prepare-release.outputs.sha }}",
        "CI_METADATA_SHA: ${{ needs.read-matrix.outputs.ci_metadata_sha }}",
        "PORTS_SHA: ${{ needs.read-matrix.outputs.ports_sha }}",
        "DEPENDENCY_PACKAGES: ${{ needs.read-matrix.outputs.dependency_packages }}",
        '--release-tag "$RELEASE_TAG"',
        '--source-sha "$SOURCE_SHA"',
        '--ci-metadata-sha "$CI_METADATA_SHA"',
        '--ports-sha "$PORTS_SHA"',
        'ROUTE_MATRIX_FILE="$RUNNER_TEMP/route-matrix.json"',
        '--route-matrix "$ROUTE_MATRIX_FILE"',
        '--dependency-packages "$DEPENDENCY_PACKAGES_FILE"',
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


def _workflow_document(source: str) -> dict[object, object]:
    document: object = yaml.safe_load(source)
    assert isinstance(document, dict), "workflow must be a YAML mapping"
    return document


def _contains_mapping_value(value: object, key: str, expected: str) -> bool:
    if isinstance(value, dict):
        return any(
            (item_key == key and item_value == expected) or _contains_mapping_value(item_value, key, expected)
            for item_key, item_value in value.items()
        )
    if isinstance(value, list):
        return any(_contains_mapping_value(item, key, expected) for item in value)
    return False


def _external_workflow(document: dict[object, object]) -> bool:
    triggers = document.get(True)  # PyYAML 1.1 resolves the plain `on` key to True.
    assert isinstance(triggers, dict), "workflow must declare an on mapping"
    return any(trigger != "workflow_call" for trigger in triggers)


def _workflow_sources(directory: Path) -> dict[str, str]:
    paths = {path.name: path for pattern in ("*.yml", "*.yaml") for path in directory.glob(pattern)}
    return {name: paths[name].read_text(encoding="utf-8") for name in sorted(paths)}


def _top_level_concurrency(source: str) -> dict[str, object]:
    concurrency = _workflow_document(source).get("concurrency")
    assert isinstance(concurrency, dict), "missing top-level concurrency block"
    assert all(isinstance(key, str) for key in concurrency)
    return cast(dict[str, object], concurrency)


def _assert_release_concurrency(source: str) -> None:
    concurrency = _top_level_concurrency(source)
    assert concurrency.get("queue") == "max", "real cuts must retain every queued dispatch"
    assert concurrency.get("cancel-in-progress") is False, "a running cut must never be cancelled"
    group = concurrency.get("group", "")
    assert isinstance(group, str)
    assert _RELEASE_GROUP_RE.fullmatch(group), f"release concurrency group has the wrong ownership: {group!r}"


def _release_group(source: str, *, dry_run: str, channel: str, run_id: int) -> str:
    _assert_release_concurrency(source)
    group = _top_level_concurrency(source)["group"]
    assert isinstance(group, str)
    match = _RELEASE_GROUP_RE.fullmatch(group)
    assert match is not None
    suffix = match.group("template").format(run_id) if dry_run == match.group("dry") else channel
    return f"release-{suffix}"


def _assert_pkg_repository_concurrency(source: str) -> None:
    concurrency = _top_level_concurrency(source)
    assert concurrency.get("group") == _PKG_REPO_MUTATION_GROUP
    assert concurrency.get("queue") == "max"
    assert concurrency.get("cancel-in-progress") is False


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


def test_source_workflows_never_mutate_the_external_pkg_repository() -> None:
    sources = _workflow_sources(ROOT / ".github/workflows")
    mutators = {
        name
        for name, source in sources.items()
        if _contains_mapping_value(_workflow_document(source), "repository", "pfBlockerNG/pkg")
        and _external_workflow(_workflow_document(source))
    }
    assert not mutators


def test_source_workflows_never_call_the_retired_renderer() -> None:
    sources = _workflow_sources(ROOT / ".github/workflows")
    callers = {name for name, source in sources.items() if "pkg-render-site.yml" in source}
    assert not callers


@pytest.mark.parametrize(
    "repository",
    (
        "repository: pfBlockerNG/pkg # valid inline YAML comment",
        'repository: "pfBlockerNG/pkg"',
    ),
)
def test_issue_2391_pkg_mutator_inventory_uses_yaml_values(repository: str) -> None:
    source = f"on:\n  workflow_dispatch:\njobs:\n  mutate:\n    steps:\n      - with:\n          {repository}\n"
    document = _workflow_document(source)
    assert _external_workflow(document)
    assert _contains_mapping_value(document, "repository", "pfBlockerNG/pkg")


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
    current_value = {
        "group": _PKG_REPO_MUTATION_GROUP,
        "queue": "max",
        "cancel-in-progress": "false",
    }[key]
    mutated = valid.replace(f"  {key}: {current_value}\n", f"  {key}: {wrong_value}\n")
    with pytest.raises(AssertionError):
        _assert_pkg_repository_concurrency(mutated)

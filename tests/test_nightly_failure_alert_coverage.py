"""Every scheduled workflow is watched by the nightly failure alert or exempt."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = ROOT / ".github" / "workflows"
_WORKFLOW_GLOBS = ("*.yml", "*.yaml")

_MAPPING_KEY_RE = re.compile(r"^(?P<key>[A-Za-z0-9_.-]+|'[^']*'|\"[^\"]*\")\s*:(?P<rest>.*)$")
_CANONICAL_ON_RE = re.compile(r"^on:\s*(?:#.*)?$")
_CANONICAL_EVENT_RE = re.compile(r"^  [A-Za-z0-9_.-]+:")
_WORKFLOW_RUN_RE = re.compile(r"^  workflow_run:\s*(?:#.*)?$")
_WORKFLOWS_RE = re.compile(r"^    workflows:\s*(?:#.*)?$")
_WORKFLOW_ITEM_RE = re.compile(r"^      -\s*(?P<value>.+?)\s*$")

EXEMPT_SCHEDULED_WORKFLOWS: dict[str, str] = {
    "Top1M Provider Health Check": ("top1m-healthcheck.yml owns its alert and recovery issue lifecycle."),
}


def _is_comment(line: str) -> bool:
    return line.lstrip().startswith("#")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _block_end(lines: list[str], start: int, indent: int) -> int:
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if not line.strip() or _is_comment(line):
            continue
        if _indent(line) <= indent:
            return index
    return len(lines)


def _mapping_key(line: str) -> tuple[str, str] | None:
    match = _MAPPING_KEY_RE.match(line.lstrip(" "))
    if match is None:
        return None
    raw_key = match.group("key")
    if raw_key[0] in "'\"":
        return raw_key[1:-1], match.group("rest")
    return raw_key, match.group("rest")


def _top_level_block(lines: list[str], key: str) -> tuple[int, int] | None:
    for index, line in enumerate(lines):
        if _is_comment(line) or _indent(line) != 0:
            continue
        parsed = _mapping_key(line)
        if parsed is not None and parsed[0] == key:
            return index, _block_end(lines, index, 0)
    return None


def _canonical_on_block(lines: list[str], *, source: str) -> tuple[int, int]:
    on_index = next(
        (
            index
            for index, line in enumerate(lines)
            if not _is_comment(line) and _indent(line) == 0 and (_mapping_key(line) or (None, ""))[0] == "on"
        ),
        None,
    )
    if on_index is None:
        raise ValueError(f"{source}: missing canonical top-level on:")
    if _CANONICAL_ON_RE.fullmatch(lines[on_index]) is None:
        raise ValueError(f"{source}: noncanonical top-level on: syntax")
    end = _block_end(lines, on_index, 0)
    direct_child_seen = False
    for index in range(on_index + 1, end):
        line = lines[index]
        if not line.strip() or _is_comment(line):
            continue
        indent = _indent(line)
        if indent < 2:
            raise ValueError(f"{source}: noncanonical on child indentation")
        if not direct_child_seen:
            if indent != 2:
                raise ValueError(f"{source}: noncanonical on child indentation")
            direct_child_seen = True
        if indent == 2 and _CANONICAL_EVENT_RE.match(line) is None:
            raise ValueError(f"{source}: noncanonical on child key")
    return on_index, end


def _has_schedule_trigger(text: str) -> bool:
    lines = text.splitlines()
    start, end = _canonical_on_block(lines, source="workflow")
    return any(
        _indent(lines[index]) == 2
        and _CANONICAL_EVENT_RE.match(lines[index]) is not None
        and lines[index].partition(":")[0].strip() == "schedule"
        for index in range(start + 1, end)
    )


def _normalize_scalar(raw: str, *, source: str) -> str:
    value = raw.strip()
    if not value or value.startswith("#"):
        raise ValueError(f"{source}: invalid workflow name")
    if value[0] in "'\"":
        quote = value[0]
        closing = value.find(quote, 1)
        if closing < 0 or value[closing + 1 :].strip() not in ("",):
            trailing = value[closing + 1 :].strip() if closing >= 0 else value
            if not trailing.startswith("#"):
                raise ValueError(f"{source}: malformed quoted scalar")
        if closing <= 1:
            raise ValueError(f"{source}: empty or malformed quoted scalar")
        return value[1:closing]
    value = value.split(" #", 1)[0].rstrip()
    if not value or value in {"null", "Null", "NULL", "~"} or value.startswith(("!", "&")):
        raise ValueError(f"{source}: invalid workflow name")
    return value


def _top_level_workflow_name(text: str, *, source: str) -> str:
    for line in text.splitlines():
        if _is_comment(line) or _indent(line) != 0:
            continue
        parsed = _mapping_key(line)
        if parsed is None or parsed[0] != "name":
            continue
        if not line.startswith("name:"):
            raise ValueError(f"{source}: noncanonical top-level name: key")
        return _normalize_scalar(parsed[1], source=source)
    raise ValueError(f"{source}: scheduled workflow missing top-level name")


def _scheduled_workflow_names(paths: list[Path]) -> set[str]:
    scheduled_owners: dict[str, Path] = {}
    for path in paths:
        text = path.read_text(encoding="utf-8")
        name = _top_level_workflow_name(text, source=str(path))
        if _has_schedule_trigger(text):
            if name in scheduled_owners:
                raise ValueError(f"duplicate scheduled workflow name {name!r}: {scheduled_owners[name]} and {path}")
            scheduled_owners[name] = path
    return set(scheduled_owners)


def _nightly_watched_workflows(text: str) -> set[str]:
    lines = text.splitlines()
    on_block = _top_level_block(lines, "on")
    if on_block is None:
        raise ValueError("nightly alert: missing top-level on block")
    on_start, on_end = on_block
    workflow_run = next(
        (index for index in range(on_start + 1, on_end) if _WORKFLOW_RUN_RE.fullmatch(lines[index])),
        None,
    )
    if workflow_run is None:
        raise ValueError("nightly alert: missing on.workflow_run block")
    workflow_run_end = _block_end(lines, workflow_run, 2)
    workflows = next(
        (index for index in range(workflow_run + 1, workflow_run_end) if _WORKFLOWS_RE.fullmatch(lines[index])),
        None,
    )
    if workflows is None:
        raise ValueError("nightly alert: missing on.workflow_run.workflows block")
    names: set[str] = set()
    for index in range(workflows + 1, workflow_run_end):
        line = lines[index]
        if not line.strip() or _is_comment(line):
            continue
        if _indent(line) <= 4:
            break
        match = _WORKFLOW_ITEM_RE.fullmatch(line)
        if match:
            names.add(_normalize_scalar(match.group("value"), source=f"nightly alert line {index + 1}"))
    if not names:
        raise ValueError("nightly alert: on.workflow_run.workflows is empty")
    return names


def _workflow_files(directory: Path = WORKFLOWS_DIR) -> list[Path]:
    by_name: dict[str, Path] = {}
    for pattern in _WORKFLOW_GLOBS:
        for path in directory.glob(pattern):
            by_name.setdefault(path.name, path)
    return [by_name[name] for name in sorted(by_name)]


def test_every_scheduled_workflow_is_watched_or_explicitly_exempt() -> None:
    scheduled = _scheduled_workflow_names(_workflow_files())
    watched = _nightly_watched_workflows((WORKFLOWS_DIR / "nightly-failure-alert.yml").read_text(encoding="utf-8"))
    exempt = set(EXEMPT_SCHEDULED_WORKFLOWS)

    assert all(reason.strip() for reason in EXEMPT_SCHEDULED_WORKFLOWS.values())
    assert exempt <= scheduled, f"stale scheduled-workflow exemptions: {sorted(exempt - scheduled)}"
    assert watched <= scheduled, f"nightly alert watches non-scheduled workflows: {sorted(watched - scheduled)}"
    overlap = watched & exempt
    assert not overlap, f"workflows cannot be both watched and exempt: {sorted(overlap)}"
    missing = scheduled - watched - exempt
    assert not missing, f"uncovered scheduled workflows: {sorted(missing)}"
    assert scheduled == watched | exempt, (
        f"scheduled={sorted(scheduled)} watched={sorted(watched)} exempt={sorted(exempt)}"
    )


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("on:\n  # schedule:\n  push:\n", False),
        ("on: # {schedule: fake}\n  push:\n", False),
        ("name: Plain\non:\n  schedule:\n    - cron: x\n", True),
        ('name: Inline schedule\non:\n  schedule: [{cron: "0 0 * * *"}]\n', True),
        ("name: Outside\non:\n  push:\njobs:\n  schedule:\n", False),
        (
            "name: Nested input\non:\n  workflow_dispatch:\n    inputs:\n      schedule:\n        description: x\n",
            False,
        ),
    ],
)
def test_schedule_parser_uses_only_top_level_on(text: str, expected: bool) -> None:
    assert _has_schedule_trigger(text) is expected


@pytest.mark.parametrize(
    "text",
    [
        'name: Flow\non: {schedule: [{cron: "0 0 * * *"}]}\n',
        'name: Quoted top level\n"on":\n  schedule:\n    - cron: "0 0 * * *"\n',
        'name: Tagged top level\n!!str on:\n  schedule:\n    - cron: "0 0 * * *"\n',
        'name: Aliased top level\n&trigger on:\n  schedule:\n    - cron: "0 0 * * *"\n',
        'name: Quoted event\non:\n  "schedule":\n    - cron: "0 0 * * *"\n',
        'name: Tagged event\non:\n  !!str schedule:\n    - cron: "0 0 * * *"\n',
        'name: Aliased event\non:\n  &trigger schedule:\n    - cron: "0 0 * * *"\n',
        'name: Alternate indentation\non:\n    schedule:\n      - cron: "0 0 * * *"\n',
        'name: Whitespace event\non:\n  schedule :\n    - cron: "0 0 * * *"\n',
        'name: Whitespace quoted event\non:\n  "schedule" :\n    - cron: "0 0 * * *"\n',
    ],
)
def test_noncanonical_schedule_forms_fail_closed(text: str) -> None:
    with pytest.raises(ValueError, match="canonical"):
        _has_schedule_trigger(text)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("name: Plain\non:\n  schedule:\n", "Plain"),
        ("name: 'Single quoted'\non:\n  schedule:\n", "Single quoted"),
        ('name: "Double quoted"\non:\n  schedule:\n', "Double quoted"),
    ],
)
def test_top_level_workflow_name_normalizes_outer_quotes(text: str, expected: str) -> None:
    assert _top_level_workflow_name(text, source="fixture") == expected


def test_scheduled_workflow_name_must_be_top_level_and_well_formed() -> None:
    with pytest.raises(ValueError, match="missing top-level name"):
        _top_level_workflow_name("on:\n  schedule:\n", source="missing")
    with pytest.raises(ValueError, match="malformed quoted scalar"):
        _top_level_workflow_name("name: 'broken\non:\n  schedule:\n", source="malformed")
    with pytest.raises(ValueError, match="canonical"):
        _top_level_workflow_name('"name": "Quoted key"\non:\n  schedule:\n', source="quoted-key")


@pytest.mark.parametrize(
    "text",
    [
        "name:\non:\n  push:\n",
        "name: # comment\non:\n  push:\n",
        "name: null\non:\n  push:\n",
        "name: ~\non:\n  push:\n",
        "name: !!str\non:\n  push:\n",
    ],
)
def test_workflow_name_rejects_null_comment_and_tag_only_values(text: str) -> None:
    with pytest.raises(ValueError, match="name"):
        _top_level_workflow_name(text, source="invalid-name")


def test_workflow_files_scan_both_yaml_extensions(tmp_path: Path) -> None:
    workflow_tail = "jobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
    (tmp_path / "scheduled.yml").write_text(
        "name: YML\non:\n  schedule:\n" + workflow_tail,
        encoding="utf-8",
    )
    (tmp_path / "scheduled.yaml").write_text(
        "name: YAML\non:\n  schedule:\n" + workflow_tail,
        encoding="utf-8",
    )

    paths = _workflow_files(tmp_path)
    assert {path.suffix for path in paths} == {".yml", ".yaml"}
    assert _scheduled_workflow_names(paths) == {"YML", "YAML"}


def test_duplicate_scheduled_workflow_names_fail_closed(tmp_path: Path) -> None:
    workflow = (
        'name: Top1M Provider Health Check\non:\n  schedule:\n    - cron: "0 0 * * *"\n'
        "jobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
    )
    first = tmp_path / "first.yml"
    second = tmp_path / "second.yml"
    first.write_text(workflow, encoding="utf-8")
    second.write_text(workflow, encoding="utf-8")

    with pytest.raises(ValueError) as exc_info:
        _scheduled_workflow_names(_workflow_files(tmp_path))
    message = str(exc_info.value)
    assert "duplicate scheduled workflow name 'Top1M Provider Health Check'" in message
    assert str(first) in message
    assert str(second) in message


def test_duplicate_manual_workflow_names_are_allowed(tmp_path: Path) -> None:
    workflow = (
        "name: Manual duplicate\non:\n  workflow_dispatch:\n"
        "jobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
    )
    (tmp_path / "first.yml").write_text(workflow, encoding="utf-8")
    (tmp_path / "second.yml").write_text(workflow, encoding="utf-8")

    assert _scheduled_workflow_names(_workflow_files(tmp_path)) == set()


def test_manual_and_scheduled_name_collision_is_allowed(tmp_path: Path) -> None:
    manual = (
        "name: Mixed trigger\non:\n  workflow_dispatch:\n"
        "jobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
    )
    scheduled = (
        'name: Mixed trigger\non:\n  schedule:\n    - cron: "0 0 * * *"\n'
        "jobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
    )
    (tmp_path / "manual.yml").write_text(manual, encoding="utf-8")
    (tmp_path / "scheduled.yml").write_text(scheduled, encoding="utf-8")

    assert _scheduled_workflow_names(_workflow_files(tmp_path)) == {"Mixed trigger"}


def test_nightly_workflow_run_parser_ignores_decoy_workflow_lists() -> None:
    text = """\
name: Synthetic nightly alert
on:
  workflow_run:
    workflows:
      - "Watched workflow"
    types: [completed]
  workflow_dispatch:
    workflows:
      - "Decoy dispatch list"
jobs:
  decoy:
    workflows:
      - "Decoy job list"
"""

    assert _nightly_watched_workflows(text) == {"Watched workflow"}

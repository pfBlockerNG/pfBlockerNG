#!/usr/bin/env python3
"""Block diff-scoped named-test retirements without successor evidence."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
from collections import Counter, defaultdict, deque
from collections.abc import Callable, Hashable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import TypeVar

HISTORY_PATH = "docs/history/retired-tests.md"
_PYTHON_DECLARATION = re.compile(r"^[ \t]*(?:async[ \t]+)?def[ \t]+(?P<name>[^\s(]+)[ \t]*\(")
_PHPUNIT_DECLARATION = re.compile(r"^[ \t]*(?:[^#/\"']*\{[ \t]*)?public[ \t]+function[ \t]+(?P<name>test\w*)[ \t]*\(")
_SHELLSPEC_DECLARATION = re.compile(r"^[ \t]*It[ \t]+(?P<body>.*)$")
_SUCCESSOR = re.compile(r"^[ \t]*# successor: (?P<value>\S(?:.*\S)?)[ \t]*$")
_SUCCESSOR_ATTEMPT = re.compile(r"^[ \t]*(?:#+|//)[ \t]*successor\b", re.IGNORECASE)
_TOMBSTONE_ATTEMPT = re.compile(r"^[ \t]*-[ \t]*\{")
_TOMBSTONE = re.compile(r"^- (?P<payload>\{.*)$")


class CheckError(Exception):
    pass


@dataclass(frozen=True)
class Change:
    status: str
    old_path: str | None
    new_path: str | None


@dataclass(frozen=True)
class Declaration:
    path: str
    language: str
    name: str
    line: int

    @property
    def identity(self) -> str:
        return f"{self.path}::{self.name}"


@dataclass(frozen=True)
class Marker:
    path: str
    line: int
    raw: str
    value: str | None


@dataclass(frozen=True)
class ParsedFile:
    path: str
    language: str
    lines: tuple[str, ...]
    declarations: tuple[Declaration, ...]
    markers: tuple[Marker, ...]


@dataclass(frozen=True)
class DiffInput:
    changes: tuple[Change, ...]
    old_ref: str
    new_ref: str | None


Item = TypeVar("Item")


def _git(*args: str) -> bytes:
    try:
        result = subprocess.run(["git", *args], capture_output=True, check=False)
    except OSError as exc:
        raise CheckError(f"cannot run git: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="backslashreplace").strip()
        command = "git " + " ".join(repr(arg) for arg in args)
        raise CheckError(f"{command} failed" + (f": {detail}" if detail else ""))
    return result.stdout


def _decode_ascii(data: bytes, description: str) -> str:
    try:
        value = data.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise CheckError(f"{description} is not ASCII") from exc
    if not value:
        raise CheckError(f"{description} is empty")
    return value


def _resolve_commit(ref: str) -> str:
    commit = _decode_ascii(
        _git("rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"),
        f"resolved revision {ref!r}",
    )
    if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", commit):
        raise CheckError(f"resolved revision {ref!r} is not an object ID")
    return commit


def _decode_path(raw: bytes) -> str:
    try:
        path = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CheckError("Git reported a path that is not valid UTF-8") from exc
    if not path:
        raise CheckError("Git reported an empty path")
    return path


def _parse_name_status(data: bytes) -> tuple[Change, ...]:
    if data and not data.endswith(b"\0"):
        raise CheckError("Git name-status output is not NUL-terminated")
    fields = data.split(b"\0")[:-1] if data else []
    changes: list[Change] = []
    index = 0
    while index < len(fields):
        try:
            status = fields[index].decode("ascii")
        except UnicodeDecodeError as exc:
            raise CheckError("Git reported a non-ASCII status") from exc
        index += 1
        kind = status[:1]
        if kind in {"R", "C"}:
            if not re.fullmatch(r"[RC][0-9]{1,3}", status) or int(status[1:]) > 100:
                raise CheckError(f"invalid Git name-status record: {status!r}")
            path_count = 2
        elif status in {"A", "D", "M", "T"}:
            path_count = 1
        else:
            raise CheckError(f"invalid Git name-status record: {status!r}")
        if index + path_count > len(fields):
            raise CheckError(f"truncated Git name-status record: {status!r}")
        paths = tuple(_decode_path(raw) for raw in fields[index : index + path_count])
        index += path_count
        if kind == "A":
            changes.append(Change(kind, None, paths[0]))
        elif kind == "D":
            changes.append(Change(kind, paths[0], None))
        elif kind == "C":
            changes.append(Change(kind, None, paths[1]))
        elif kind == "R":
            changes.append(Change(kind, paths[0], paths[1]))
        else:
            changes.append(Change(kind, paths[0], paths[0]))
    return tuple(changes)


def _diff_input(staged: bool, base: str | None) -> DiffInput:
    if staged:
        data = _git("diff", "--cached", "--name-status", "-z", "--find-renames", "HEAD", "--")
        return DiffInput(_parse_name_status(data), "HEAD", None)
    assert base is not None
    base_commit = _resolve_commit(base)
    merge_base = _decode_ascii(_git("merge-base", base_commit, "HEAD"), "merge base")
    if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", merge_base):
        raise CheckError("merge base is not an object ID")
    data = _git("diff", "--name-status", "-z", "--find-renames", f"{base_commit}...HEAD", "--")
    return DiffInput(_parse_name_status(data), merge_base, "HEAD")


def _language(path: str) -> str | None:
    if path.startswith("tests/") and path.endswith(".py"):
        return "python"
    if path.startswith("tests/php/") and path.endswith(".php"):
        return "phpunit"
    if path.startswith("tests/shell/") and path.endswith(".sh"):
        return "shellspec"
    return None


def _blob(ref: str | None, path: str) -> str:
    spec = f":{path}" if ref is None else f"{ref}:{path}"
    data = _git("show", spec)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CheckError(f"{path} contains invalid UTF-8") from exc


def _shellspec_name(path: str, line_number: int, body: str) -> str | None:
    if not body.startswith(("'", '"')):
        return None
    try:
        words = shlex.split(f"It {body}", comments=False, posix=True)
    except ValueError as exc:
        raise CheckError(f"cannot parse ShellSpec declaration in {path}:{line_number}: {exc}") from exc
    if len(words) < 2 or words[0] != "It":
        raise CheckError(f"cannot parse ShellSpec declaration in {path}:{line_number}")
    return words[1]


def _parse_file(path: str, language: str, text: str) -> ParsedFile:
    lines = tuple(text.splitlines())
    declarations: list[Declaration] = []
    markers: list[Marker] = []
    for line_number, line in enumerate(lines, 1):
        name: str | None = None
        if language == "python":
            match = _PYTHON_DECLARATION.match(line)
            if match and match.group("name").startswith("test_") and match.group("name").isidentifier():
                name = match.group("name")
        elif language == "phpunit":
            match = _PHPUNIT_DECLARATION.match(line)
            if match:
                name = match.group("name")
        else:
            match = _SHELLSPEC_DECLARATION.match(line)
            if match:
                name = _shellspec_name(path, line_number, match.group("body"))
        if name is not None:
            declarations.append(Declaration(path, language, name, line_number))
        marker_match = _SUCCESSOR.fullmatch(line)
        if marker_match:
            markers.append(Marker(path, line_number, line, marker_match.group("value")))
        elif _SUCCESSOR_ATTEMPT.search(line):
            markers.append(Marker(path, line_number, line, None))
    return ParsedFile(path, language, lines, tuple(declarations), tuple(markers))


def _consume_matches(
    old: Sequence[Item],
    new: Sequence[Item],
    old_left: set[int],
    new_left: set[int],
    old_key: Callable[[Item], Hashable],
    new_key: Callable[[Item], Hashable],
    old_candidates: Iterable[int] | None = None,
    new_candidates: Iterable[int] | None = None,
) -> None:
    buckets: dict[Hashable, deque[int]] = defaultdict(deque)
    candidates = new_left if new_candidates is None else new_candidates
    for index in candidates:
        if index in new_left:
            buckets[new_key(new[index])].append(index)
    candidates = old_left if old_candidates is None else old_candidates
    for index in tuple(candidates):
        if index not in old_left:
            continue
        bucket = buckets.get(old_key(old[index]))
        if bucket:
            matched = bucket.popleft()
            old_left.remove(index)
            new_left.remove(matched)


def _match_declarations(
    old_files: dict[str, ParsedFile],
    new_files: dict[str, ParsedFile],
    renames: tuple[tuple[str, str], ...],
) -> tuple[tuple[Declaration, ...], tuple[Declaration, ...]]:
    old = [declaration for parsed in old_files.values() for declaration in parsed.declarations]
    new = [declaration for parsed in new_files.values() for declaration in parsed.declarations]
    old_left = set(range(len(old)))
    new_left = set(range(len(new)))
    _consume_matches(
        old,
        new,
        old_left,
        new_left,
        lambda item: (item.path, item.language, item.name),
        lambda item: (item.path, item.language, item.name),
    )
    for old_path, new_path in renames:
        old_candidates = [i for i in old_left if old[i].path == old_path]
        new_candidates = [i for i in new_left if new[i].path == new_path]
        _consume_matches(
            old,
            new,
            old_left,
            new_left,
            lambda item: (item.language, item.name),
            lambda item: (item.language, item.name),
            old_candidates,
            new_candidates,
        )
    _consume_matches(
        old,
        new,
        old_left,
        new_left,
        lambda item: (item.language, item.name),
        lambda item: (item.language, item.name),
    )
    return (
        tuple(old[index] for index in sorted(old_left)),
        tuple(new[index] for index in sorted(new_left)),
    )


def _new_markers(old_files: dict[str, ParsedFile], new_files: dict[str, ParsedFile]) -> set[Marker]:
    old = [marker for parsed in old_files.values() for marker in parsed.markers]
    new = [marker for parsed in new_files.values() for marker in parsed.markers]
    old_left = set(range(len(old)))
    new_left = set(range(len(new)))
    _consume_matches(
        old,
        new,
        old_left,
        new_left,
        lambda item: (item.path, item.raw),
        lambda item: (item.path, item.raw),
    )
    _consume_matches(old, new, old_left, new_left, lambda item: item.raw, lambda item: item.raw)
    return {new[index] for index in new_left}


def _associated_declaration(marker: Marker, parsed: ParsedFile) -> Declaration | None:
    declarations = {declaration.line: declaration for declaration in parsed.declarations}
    exact_marker_lines = {candidate.line for candidate in parsed.markers if candidate.value is not None}
    line_number = marker.line + 1
    while line_number <= len(parsed.lines):
        stripped = parsed.lines[line_number - 1].strip()
        if not stripped or line_number in exact_marker_lines:
            line_number += 1
            continue
        if parsed.language == "python" and stripped.startswith("@"):
            line_number += 1
            continue
        if parsed.language == "phpunit" and stripped.startswith("#["):
            line_number += 1
            continue
        return declarations.get(line_number)
    return None


def _select_retirement(value: str, retired: tuple[Declaration, ...]) -> tuple[Declaration, ...]:
    canonical = tuple(declaration for declaration in retired if declaration.identity == value)
    if canonical:
        return canonical
    return tuple(declaration for declaration in retired if declaration.name == value)


def _marker_evidence(
    retired: tuple[Declaration, ...],
    added: tuple[Declaration, ...],
    old_files: dict[str, ParsedFile],
    new_files: dict[str, ParsedFile],
) -> tuple[set[Declaration], list[str]]:
    new_markers = _new_markers(old_files, new_files)
    added_set = set(added)
    active: list[Marker] = []
    violations: list[str] = []
    for parsed in new_files.values():
        for marker in parsed.markers:
            is_new = marker in new_markers
            if marker.value is None:
                if is_new:
                    violations.append(f"malformed successor marker at {marker.path}:{marker.line}")
                continue
            declaration = _associated_declaration(marker, parsed)
            if declaration is None:
                if is_new:
                    violations.append(
                        f"successor marker at {marker.path}:{marker.line} is not attached to a named test"
                    )
                continue
            if declaration not in added_set:
                if is_new:
                    violations.append(
                        f"successor marker at {marker.path}:{marker.line} is attached to "
                        f"unchanged test {declaration.identity}"
                    )
                continue
            active.append(marker)
    counts = Counter(marker.value for marker in active)
    for value, count in counts.items():
        if count > 1:
            violations.append(f"duplicate successor marker value {value!r}")
    discharged: set[Declaration] = set()
    for marker in active:
        assert marker.value is not None
        selected = _select_retirement(marker.value, retired)
        if not selected:
            violations.append(f"successor marker {marker.value!r} names no retirement")
        elif len(selected) > 1:
            identities = ", ".join(declaration.identity for declaration in selected)
            violations.append(f"successor marker {marker.value!r} is ambiguous: {identities}")
        else:
            discharged.add(next(iter(selected)))
    return discharged, violations


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _added_tombstone_lines(old_text: str | None, new_text: str | None) -> list[tuple[int, str]]:
    if new_text is None:
        return []
    old_lines = Counter(old_text.splitlines() if old_text is not None else ())
    added: list[tuple[int, str]] = []
    for line_number, line in enumerate(new_text.splitlines(), 1):
        if old_lines[line]:
            old_lines[line] -= 1
        elif _TOMBSTONE_ATTEMPT.match(line):
            added.append((line_number, line))
    return added


def _tombstone_evidence(
    retired: tuple[Declaration, ...], old_text: str | None, new_text: str | None
) -> tuple[set[Declaration], list[str]]:
    discharged: set[Declaration] = set()
    violations: list[str] = []
    records: set[tuple[str, str, str]] = set()
    for line_number, line in _added_tombstone_lines(old_text, new_text):
        match = _TOMBSTONE.fullmatch(line)
        if not match:
            violations.append(f"malformed tombstone row at {HISTORY_PATH}:{line_number}")
            continue
        try:
            record = json.loads(match.group("payload"), object_pairs_hook=_json_object)
        except (json.JSONDecodeError, ValueError) as exc:
            violations.append(f"malformed tombstone JSON at {HISTORY_PATH}:{line_number}: {exc}")
            continue
        if not isinstance(record, dict) or set(record) != {"date", "test", "reason"}:
            violations.append(f"tombstone at {HISTORY_PATH}:{line_number} requires exactly date, test, and reason")
            continue
        when = record["date"]
        identity = record["test"]
        reason = record["reason"]
        if not isinstance(when, str) or not isinstance(identity, str) or not isinstance(reason, str):
            violations.append(f"tombstone at {HISTORY_PATH}:{line_number} fields must be strings")
            continue
        try:
            parsed_date = date.fromisoformat(when)
        except ValueError:
            violations.append(f"tombstone at {HISTORY_PATH}:{line_number} has invalid date {when!r}")
            continue
        if parsed_date.isoformat() != when or parsed_date > datetime.now(UTC).date():
            violations.append(f"tombstone at {HISTORY_PATH}:{line_number} has invalid or future date {when!r}")
            continue
        if not reason.strip():
            violations.append(f"tombstone at {HISTORY_PATH}:{line_number} has a blank reason")
            continue
        key = (when, identity, reason)
        if key in records:
            violations.append(f"duplicate added tombstone at {HISTORY_PATH}:{line_number}")
            continue
        records.add(key)
        selected = _select_retirement(identity, retired)
        if not selected:
            violations.append(f"tombstone {identity!r} names no retirement")
        elif len(selected) > 1:
            identities = ", ".join(declaration.identity for declaration in selected)
            violations.append(f"tombstone {identity!r} is ambiguous: {identities}")
        else:
            discharged.add(next(iter(selected)))
    return discharged, violations


def _evaluate(diff: DiffInput) -> list[str]:
    old_files: dict[str, ParsedFile] = {}
    new_files: dict[str, ParsedFile] = {}
    renames: list[tuple[str, str]] = []
    old_history: str | None = None
    new_history: str | None = None
    for change in diff.changes:
        if change.old_path is not None:
            language = _language(change.old_path)
            if language is not None and change.old_path not in old_files:
                old_files[change.old_path] = _parse_file(
                    change.old_path, language, _blob(diff.old_ref, change.old_path)
                )
            if change.old_path == HISTORY_PATH:
                old_history = _blob(diff.old_ref, change.old_path)
        if change.new_path is not None:
            language = _language(change.new_path)
            if language is not None and change.new_path not in new_files:
                new_files[change.new_path] = _parse_file(
                    change.new_path, language, _blob(diff.new_ref, change.new_path)
                )
            if change.new_path == HISTORY_PATH:
                new_history = _blob(diff.new_ref, change.new_path)
        if (
            change.status == "R"
            and change.old_path is not None
            and change.new_path is not None
            and _language(change.old_path) is not None
            and _language(change.new_path) is not None
        ):
            renames.append((change.old_path, change.new_path))
    retired, added = _match_declarations(old_files, new_files, tuple(renames))
    marker_discharged, violations = _marker_evidence(retired, added, old_files, new_files)
    tombstone_discharged, tombstone_violations = _tombstone_evidence(retired, old_history, new_history)
    violations.extend(tombstone_violations)
    discharged = marker_discharged | tombstone_discharged
    for declaration in retired:
        if declaration not in discharged:
            violations.append(f"retired named test {declaration.identity} needs a successor marker or new tombstone")
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged", action="store_true", help="compare HEAD with the staged index")
    mode.add_argument("--diff", metavar="BASE", help="compare BASE...HEAD")
    args = parser.parse_args(argv)
    try:
        violations = _evaluate(_diff_input(args.staged, args.diff))
    except CheckError as exc:
        print(f"Named-test retirement check error: {exc}", file=sys.stderr)
        return 2
    if violations:
        print("Named-test retirement check failed:")
        for violation in violations:
            print(f"  - {violation}")
        return 1
    print("Named-test retirement check OK.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

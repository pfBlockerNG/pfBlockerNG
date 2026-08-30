#!/usr/bin/env python3
"""Block diff-scoped named-test retirements without successor evidence."""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tokenize
from collections import Counter, defaultdict, deque
from collections.abc import Callable, Hashable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import TypeVar

HISTORY_PATH = "docs/history/retired-tests.md"
_PYTHON_DECLARATION = re.compile(r"^[ \t]*(?:async[ \t]+)?def[ \t]+(?P<name>[^\s(]+)[ \t]*\(")
_PHPUNIT_METHOD = re.compile(
    r"^[ \t]*(?:[^#/\"']*\{[ \t]*)?(?:(?:final|abstract|static)[ \t]+)*"
    r"public[ \t]+(?:(?:final|abstract|static)[ \t]+)*function[ \t]+&?[ \t]*"
    r"(?P<name>[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)[ \t]*\("
)
_PHPUNIT_TEST_IMPORT = re.compile(
    r"^[ \t]*use[ \t]+\\?PHPUnit\\Framework\\Attributes\\Test"
    r"(?:[ \t]+as[ \t]+(?P<alias>[A-Za-z_]\w*))?[ \t]*;"
)
_PHPUNIT_TEST_GROUP_IMPORT = re.compile(
    r"^[ \t]*use[ \t]+\\?PHPUnit\\Framework\\Attributes\\\{(?P<body>[^}]*)\}[ \t]*;"
)
_PHPUNIT_TEST_GROUP_MEMBER = re.compile(r"^[ \t]*Test(?:[ \t]+as[ \t]+(?P<alias>[A-Za-z_]\w*))?[ \t]*$")
_PHP_ATTRIBUTE = re.compile(r"#\[(?P<body>[^\]]*)\]")
_PHP_ATTRIBUTE_PREFIX = re.compile(r"^[ \t]*(?:#\[[^\]]*\][ \t]*)+")
_SHELLSPEC_DECLARATION = re.compile(r"^[ \t]*It[ \t]+(?P<body>.*)$")
_PHP_HEREDOC_START = re.compile(
    r"<<<[ \t]*(?:'(?P<single>[A-Za-z_]\w*)'|\"(?P<double>[A-Za-z_]\w*)\"|(?P<bare>[A-Za-z_]\w*))"
)
_SHELL_HEREDOC_START = re.compile(r"(?<!<)<<(?P<strip>-)?[ \t]*(?P<word>'[^']+'|\"[^\"]+\"|\\?[A-Za-z_]\w*)")
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
    worktree: bool = False


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


def _diff_input(staged: bool, base: str | None, worktree_base: str | None = None) -> DiffInput:
    if staged:
        data = _git("diff", "--cached", "--name-status", "-z", "--find-renames", "HEAD", "--")
        return DiffInput(_parse_name_status(data), "HEAD", None)
    selected_base = worktree_base or base
    assert selected_base is not None
    base_commit = _resolve_commit(selected_base)
    merge_base = _decode_ascii(_git("merge-base", base_commit, "HEAD"), "merge base")
    if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", merge_base):
        raise CheckError("merge base is not an object ID")
    if worktree_base is not None:
        data = _git("diff", "--name-status", "-z", "--find-renames", merge_base, "--")
        untracked = _git("ls-files", "-z", "--others", "--exclude-standard", "--")
        if untracked and not untracked.endswith(b"\0"):
            raise CheckError("Git untracked-path output is not NUL-terminated")
        untracked_records = b"".join(
            b"A\0" + path + b"\0" for path in (untracked.split(b"\0")[:-1] if untracked else ())
        )
        changes = _synthesize_worktree_renames(
            _parse_name_status(data),
            _parse_name_status(untracked_records),
            merge_base,
        )
        return DiffInput(changes, merge_base, None, worktree=True)
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


def _decode_blob(data: bytes, path: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CheckError(f"{path} contains invalid UTF-8") from exc


def _blob_bytes(ref: str | None, path: str) -> bytes:
    spec = f":{path}" if ref is None else f"{ref}:{path}"
    return _git("show", spec)


def _blob(ref: str | None, path: str) -> str:
    return _decode_blob(_blob_bytes(ref, path), path)


def _worktree_blob_bytes(path: str) -> bytes:
    worktree_path = Path(path)
    try:
        mode = worktree_path.lstat().st_mode
        if stat.S_ISLNK(mode):
            return os.readlink(os.fsencode(path))
        return worktree_path.read_bytes()
    except OSError as exc:
        raise CheckError(f"cannot read worktree path {path!r}: {exc}") from exc


def _worktree_blob(path: str) -> str:
    return _decode_blob(_worktree_blob_bytes(path), path)


def _synthesize_worktree_renames(
    tracked: tuple[Change, ...],
    untracked: tuple[Change, ...],
    old_ref: str,
) -> tuple[Change, ...]:
    deleted_by_language: dict[str, list[int]] = defaultdict(list)
    for index, change in enumerate(tracked):
        if change.status == "D" and change.old_path is not None:
            language = _language(change.old_path)
            if language is not None:
                deleted_by_language[language].append(index)

    old_by_blob: dict[tuple[str, bytes], deque[int]] = defaultdict(deque)
    for language, indices in deleted_by_language.items():
        if not any(change.new_path is not None and _language(change.new_path) == language for change in untracked):
            continue
        for index in indices:
            old_path = tracked[index].old_path
            assert old_path is not None
            old_by_blob[(language, _blob_bytes(old_ref, old_path))].append(index)

    replacements: dict[int, Change] = {}
    paired_additions: set[int] = set()
    for index, change in enumerate(untracked):
        if change.new_path is None:
            continue
        language = _language(change.new_path)
        if language is None or language not in deleted_by_language:
            continue
        old_candidates = old_by_blob.get((language, _worktree_blob_bytes(change.new_path)))
        if not old_candidates:
            continue
        old_index = old_candidates.popleft()
        old_path = tracked[old_index].old_path
        assert old_path is not None
        replacements[old_index] = Change("R", old_path, change.new_path)
        paired_additions.add(index)

    return (
        *(replacements.get(index, change) for index, change in enumerate(tracked)),
        *(change for index, change in enumerate(untracked) if index not in paired_additions),
    )


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


def _python_literal_body_lines(path: str, text: str) -> set[int]:
    ignored: set[int] = set()
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        for token_info in tokens:
            if token_info.type == tokenize.STRING and token_info.start[0] < token_info.end[0]:
                ignored.update(range(token_info.start[0] + 1, token_info.end[0] + 1))
    except (IndentationError, SyntaxError, tokenize.TokenError) as exc:
        raise CheckError(f"cannot tokenize Python test {path!r}: {exc}") from exc
    return ignored


def _php_literal_body_lines(path: str, lines: tuple[str, ...]) -> set[int]:
    ignored: set[int] = set()
    heredoc: tuple[str, int] | None = None
    quote: tuple[str, int] | None = None
    block_comment: int | None = None
    for line_number, line in enumerate(lines, 1):
        if heredoc is not None:
            ignored.add(line_number)
            label = heredoc[0]
            if re.fullmatch(
                rf"[ \t]*{re.escape(label)}[ \t]*[;,)\]]*[ \t]*(?://.*|#.*)?",
                line,
            ):
                heredoc = None
            continue

        index = 0
        if quote is not None or block_comment is not None:
            ignored.add(line_number)
        while index < len(line):
            if quote is not None:
                delimiter = quote[0]
                if line[index] == "\\":
                    index += 2
                elif line[index] == delimiter:
                    quote = None
                    index += 1
                else:
                    index += 1
                continue
            if block_comment is not None:
                end = line.find("*/", index)
                if end < 0:
                    break
                block_comment = None
                index = end + 2
                continue
            if line.startswith(("//", "#"), index):
                break
            if line.startswith("/*", index):
                block_comment = line_number
                index += 2
                continue
            if line[index] in {"'", '"'}:
                quote = (line[index], line_number)
                index += 1
                continue
            heredoc_match = _PHP_HEREDOC_START.match(line, index)
            if heredoc_match:
                label = next(value for value in heredoc_match.groupdict().values() if value is not None)
                heredoc = (label, line_number)
                break
            index += 1

    if heredoc is not None:
        label, start = heredoc
        raise CheckError(f"unterminated PHP heredoc {label!r} in {path}:{start}")
    if quote is not None:
        start = quote[1]
        raise CheckError(f"unterminated PHP string in {path}:{start}")
    if block_comment is not None:
        raise CheckError(f"unterminated PHP block comment in {path}:{block_comment}")
    return ignored


def _shell_heredocs(
    path: str,
    line_number: int,
    line: str,
    initial_quote: str | None,
) -> tuple[list[tuple[str, bool]], str | None]:
    heredocs: list[tuple[str, bool]] = []
    quote = initial_quote
    index = 0
    while index < len(line):
        if quote is not None:
            if quote == '"' and line[index] == "\\":
                index += 2
            elif line[index] == quote:
                quote = None
                index += 1
            else:
                index += 1
            continue
        if line[index] == "\\":
            index += 2
            continue
        if line[index] in {"'", '"'}:
            quote = line[index]
            index += 1
            continue
        if line[index] == "#" and (index == 0 or line[index - 1].isspace()):
            break
        match = _SHELL_HEREDOC_START.match(line, index)
        if match:
            try:
                words = shlex.split(match.group("word"), comments=False, posix=True)
            except ValueError as exc:
                raise CheckError(f"cannot parse shell heredoc in {path}:{line_number}: {exc}") from exc
            if len(words) != 1 or not words[0]:
                raise CheckError(f"cannot parse shell heredoc in {path}:{line_number}")
            heredocs.append((words[0], match.group("strip") is not None))
            index = match.end()
            continue
        index += 1
    return heredocs, quote


def _shell_literal_body_lines(path: str, lines: tuple[str, ...]) -> set[int]:
    ignored: set[int] = set()
    pending: deque[tuple[str, bool, int]] = deque()
    quote: tuple[str, int] | None = None
    for line_number, line in enumerate(lines, 1):
        if pending:
            ignored.add(line_number)
            delimiter, strip_tabs, _ = pending[0]
            candidate = line.lstrip("\t") if strip_tabs else line
            if candidate == delimiter:
                pending.popleft()
            continue
        if quote is not None:
            ignored.add(line_number)
        heredocs, remaining_quote = _shell_heredocs(
            path,
            line_number,
            line,
            quote[0] if quote is not None else None,
        )
        if remaining_quote is None:
            quote = None
        elif quote is None:
            quote = (remaining_quote, line_number)
        pending.extend((delimiter, strip_tabs, line_number) for delimiter, strip_tabs in heredocs)
    if pending:
        delimiter, _, start = pending[0]
        raise CheckError(f"unterminated shell heredoc {delimiter!r} in {path}:{start}")
    if quote is not None:
        raise CheckError(f"unterminated shell string in {path}:{quote[1]}")
    return ignored


def _literal_body_lines(path: str, language: str, text: str, lines: tuple[str, ...]) -> set[int]:
    if language == "python":
        return _python_literal_body_lines(path, text)
    if language == "phpunit":
        return _php_literal_body_lines(path, lines)
    return _shell_literal_body_lines(path, lines)


def _parse_file(path: str, language: str, text: str) -> ParsedFile:
    lines = tuple(text.splitlines())
    ignored_lines = _literal_body_lines(path, language, text, lines)
    declarations: list[Declaration] = []
    markers: list[Marker] = []
    phpunit_test_names: set[str] = set()
    if language == "phpunit":
        for line_number, line in enumerate(lines, 1):
            if line_number in ignored_lines:
                continue
            imported = _PHPUNIT_TEST_IMPORT.match(line)
            if imported:
                phpunit_test_names.add(imported.group("alias") or "Test")
                continue
            group_imported = _PHPUNIT_TEST_GROUP_IMPORT.match(line)
            if group_imported:
                for member in group_imported.group("body").split(","):
                    group_member = _PHPUNIT_TEST_GROUP_MEMBER.fullmatch(member)
                    if group_member:
                        phpunit_test_names.add(group_member.group("alias") or "Test")
    phpunit_attribute_pending = False
    for line_number, line in enumerate(lines, 1):
        if line_number in ignored_lines:
            continue
        name: str | None = None
        if language == "python":
            match = _PYTHON_DECLARATION.match(line)
            if match and match.group("name").startswith("test_") and match.group("name").isidentifier():
                name = match.group("name")
        elif language == "phpunit":
            for attribute in _PHP_ATTRIBUTE.finditer(line):
                body = attribute.group("body")
                candidates = phpunit_test_names | {
                    r"\PHPUnit\Framework\Attributes\Test",
                    r"PHPUnit\Framework\Attributes\Test",
                }
                if any(
                    re.search(
                        rf"(?:^|,)[ \t]*{re.escape(candidate)}(?:[ \t]*(?:,|$|\())",
                        body,
                    )
                    for candidate in candidates
                ):
                    phpunit_attribute_pending = True
            method_line = _PHP_ATTRIBUTE_PREFIX.sub("", line)
            match = _PHPUNIT_METHOD.match(method_line)
            if match:
                method_name = match.group("name")
                if method_name.startswith("test") or phpunit_attribute_pending:
                    name = method_name
                phpunit_attribute_pending = False
            else:
                stripped = method_line.strip()
                if stripped and not stripped.startswith(("#[", "//", "#", "/*", "*")):
                    phpunit_attribute_pending = False
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
    return (
        tuple(old[index] for index in sorted(old_left)),
        tuple(new[index] for index in sorted(new_left)),
    )


def _marker_identity(marker: Marker) -> tuple[str, str]:
    if marker.value is not None:
        return ("successor", marker.value)
    return ("malformed", marker.raw.strip())


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
        lambda item: (item.path, _marker_identity(item)),
        lambda item: (item.path, _marker_identity(item)),
    )
    _consume_matches(
        old,
        new,
        old_left,
        new_left,
        _marker_identity,
        _marker_identity,
    )
    return {new[index] for index in new_left}


def _associated_declaration(marker: Marker, parsed: ParsedFile) -> Declaration | None:
    declarations = {declaration.line: declaration for declaration in parsed.declarations}
    exact_marker_lines = {candidate.line for candidate in parsed.markers if candidate.value is not None}
    line_number = marker.line + 1
    while line_number <= len(parsed.lines):
        declaration = declarations.get(line_number)
        if declaration is not None:
            return declaration
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
        return None
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
) -> tuple[list[Declaration], list[str]]:
    new_markers = _new_markers(old_files, new_files)
    added_set = set(added)
    active: list[Marker] = []
    violations: list[str] = []
    for parsed in new_files.values():
        for marker in parsed.markers:
            is_new = marker in new_markers
            if not is_new:
                continue
            if marker.value is None:
                violations.append(f"malformed successor marker at {marker.path}:{marker.line}")
                continue
            declaration = _associated_declaration(marker, parsed)
            if declaration is None:
                violations.append(f"successor marker at {marker.path}:{marker.line} is not attached to a named test")
                continue
            if declaration not in added_set:
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
    discharged: list[Declaration] = []
    for marker in active:
        assert marker.value is not None
        selected = _select_retirement(marker.value, retired)
        if not selected:
            violations.append(f"successor marker {marker.value!r} names no retirement")
        elif len(selected) > 1:
            identities = ", ".join(declaration.identity for declaration in selected)
            violations.append(f"successor marker {marker.value!r} is ambiguous: {identities}")
        else:
            discharged.append(next(iter(selected)))
    return discharged, violations


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _added_tombstone_lines(old_text: str | None, new_text: str | None) -> tuple[list[tuple[int, str]], list[str]]:
    if new_text is None:
        if old_text is not None:
            return [], [f"{HISTORY_PATH} is append-only; existing history was removed"]
        return [], []
    new_lines = new_text.splitlines()
    start = 0
    if old_text is not None:
        old_lines = old_text.splitlines()
        if new_lines[: len(old_lines)] != old_lines:
            return [], [f"{HISTORY_PATH} is append-only; existing history was changed or removed"]
        start = len(old_lines)
    added = [
        (line_number, line)
        for line_number, line in enumerate(new_lines[start:], start + 1)
        if _TOMBSTONE_ATTEMPT.match(line)
    ]
    return added, []


def _tombstone_evidence(
    retired: tuple[Declaration, ...], old_text: str | None, new_text: str | None
) -> tuple[list[Declaration], list[str]]:
    discharged: list[Declaration] = []
    added_lines, violations = _added_tombstone_lines(old_text, new_text)
    records: set[tuple[str, str, str]] = set()
    for line_number, line in added_lines:
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
            discharged.append(next(iter(selected)))
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
                new_text = _worktree_blob(change.new_path) if diff.worktree else _blob(diff.new_ref, change.new_path)
                new_files[change.new_path] = _parse_file(change.new_path, language, new_text)
            if change.new_path == HISTORY_PATH:
                new_history = _worktree_blob(change.new_path) if diff.worktree else _blob(diff.new_ref, change.new_path)
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
    evidence_counts = Counter((*marker_discharged, *tombstone_discharged))
    for declaration in retired:
        evidence_count = evidence_counts[declaration]
        if evidence_count == 0:
            violations.append(f"retired named test {declaration.identity} needs a successor marker or new tombstone")
        elif evidence_count > 1:
            violations.append(
                f"retired named test {declaration.identity} has {evidence_count} discharges; exactly one is required"
            )
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged", action="store_true", help="compare HEAD with the staged index")
    mode.add_argument("--diff", metavar="BASE", help="compare BASE...HEAD")
    mode.add_argument(
        "--worktree",
        metavar="BASE",
        dest="worktree_base",
        help="compare the BASE merge-base with the effective worktree",
    )
    args = parser.parse_args(argv)
    try:
        violations = _evaluate(_diff_input(args.staged, args.diff, args.worktree_base))
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

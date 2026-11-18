#!/usr/bin/env python3
"""Gate PR diffs for shipped tests and frozen-RED proof.

The checker enforces three path rules:

1. changed ``src/**`` requires a changed non-documentation ``tests/**`` path;
2. changed ``src/usr/local/www/**`` additionally requires a changed
   ``tests/smoke/ui/**`` path;
3. changed release-plane code under ``scripts/**`` or non-documentation
   ``.github/**`` requires a changed non-documentation ``tests/**`` path.

``scripts/*.md``, ``.github/ISSUE_TEMPLATE/**``, documentation, ``.agents/**``,
``.claude/**``, and ``legacy/**`` are neutral. ``tests/smoke/**`` is test-side:
tests, helpers, fixtures, and shell harnesses can satisfy pairing but never
trigger a production rule themselves.

When ``--pr-body-file`` is supplied, a release-plane change must also carry at
least one frozen-RED record using the landing evidence fields in one Markdown
table:

``| Frozen RED test | git hash-object | RED run tail |``

Each data row names one shipped non-documentation ``tests/**`` path, its
repository-native ``git hash-object`` at RED time, and a non-empty failing-run
tail. Every changed test-side file needs its own row. CI and the local gate
runner use NUL-delimited Git name-status records so deletions and both rename
sides remain visible without normalizing path bytes.

The existing behavior-preserving escape is unchanged: ``--warn-only`` plus a
PR-body line starting ``no-test-needed: <why>`` downgrades violations. It covers
comment-only/refactor changes without introducing a second or wider escape.
"""

from __future__ import annotations

import re
import subprocess
import sys

_FIX_HINT = (
    "add the paired test, or — if none is warranted — apply the `no-test-needed` label, "
    "add a `no-test-needed: <why>` line to the PR body, and re-run this check "
    "(labels/body are re-read live on every run; issue #969)"
)


_DATA_ONLY = frozenset(
    {
        # Public Suffix List snapshot; regenerated weekly by psl-refresh.yml.
        "src/usr/local/pkg/pfblockerng/dnsbl_psl",
        # Chromium HSTS preload snapshot; regenerated weekly by hsts-refresh.yml.
        "src/usr/local/pkg/pfblockerng/pfb_py_hsts.txt",
        # Vendored-asset digest manifest; guarded by its own webassets drift job.
        "src/usr/local/www/pfblockerng/vendor/codemirror/MANIFEST.sha256",
    }
)

_NEUTRAL_PREFIXES = (
    ".agents/",
    ".claude/",
    ".github/ISSUE_TEMPLATE/",
    "legacy/",
)


def _is_docs(path: str) -> bool:
    """True if ``path`` is documentation and therefore neutral to both rules."""
    return path.lower().endswith(".md") or path.startswith("docs/")


def _is_neutral(path: str) -> bool:
    """True if ``path`` counts toward neither side of any pairing rule."""
    return _is_docs(path) or path in _DATA_ONLY or path.startswith(_NEUTRAL_PREFIXES)


def _is_src(path: str) -> bool:
    """True if ``path`` is production ``src/**`` code (neutral paths excluded)."""
    return not _is_neutral(path) and path.startswith("src/")


def _is_www(path: str) -> bool:
    """True if ``path`` is ``src/usr/local/www/**`` (not e.g. ``www-legacy/``)."""
    return not _is_neutral(path) and path.startswith("src/usr/local/www/")


def _is_test(path: str) -> bool:
    """True for a non-neutral path under ``tests/**``."""
    return not _is_neutral(path) and path.startswith("tests/")


def _is_ui_test(path: str) -> bool:
    """True for non-neutral Tier-A UI coverage under ``tests/smoke/ui/**``."""
    return _is_test(path) and path.startswith("tests/smoke/ui/")


def _is_release_plane(path: str) -> bool:
    """True for behavior-bearing release/CI code."""
    return not _is_neutral(path) and (path.startswith("scripts/") or path.startswith(".github/"))


def evaluate(changed: list[str], shipped: list[str] | None = None) -> list[str]:
    """Classify triggering paths and return pairing violations."""
    live = changed if shipped is None else shipped
    has_src = any(_is_src(p) for p in changed)
    has_www = any(_is_www(p) for p in changed)
    has_release = any(_is_release_plane(p) for p in changed)
    has_test = any(_is_test(p) for p in live)
    has_ui_test = any(_is_ui_test(p) for p in live)

    violations: list[str] = []
    if has_src and not has_test:
        violations.append(
            "src<->tests coverage pairing violated: this PR changes `src/**` but ships no "
            "`tests/**` change (test mandate #2: 'every change ships WITH its tests'). "
            f"{_FIX_HINT}."
        )
    if has_www and not has_ui_test:
        violations.append(
            "www<->ui-tests coverage pairing violated: this PR changes `src/usr/local/www/**` "
            "but ships no `tests/smoke/ui/**` change (Tier-A `ui_render` coverage, test "
            f"mandate #4). {_FIX_HINT}."
        )
    if has_release and not has_test:
        violations.append(
            "release-plane<->tests coverage pairing violated: this PR changes behavior under "
            "`scripts/**` or `.github/**` but ships no non-documentation `tests/**` change. "
            f"{_FIX_HINT}."
        )
    return violations


def _has_justification(body: str) -> bool:
    """True if a LINE of ``body`` starts with ``no-test-needed:`` plus non-blank text.

    Line-anchored on purpose: a mid-sentence mention of the token (prose
    describing the feature), a blockquoted ``> no-test-needed: …``, or an
    indented code block never counts as a justification — only a line the
    author deliberately started with the token does. Case-insensitive;
    ``splitlines()`` handles CRLF bodies natively. Documented accepted
    limitation: a fenced code block whose line STARTS with the token still
    matches (fence-stripping is not worth the complexity for this gate).
    """
    prefix = "no-test-needed:"
    for line in body.splitlines():
        if line.lower().startswith(prefix) and line[len(prefix) :].strip():
            return True
    return False


_FROZEN_RED_HEADER = ("frozen red test", "git hash-object", "red run tail")
_GIT_HASH = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_DELIMITER = re.compile(r":?-{3,}:?")


def _cell_text(cell: str) -> str:
    value = cell.strip()
    if len(value) >= 2 and value.startswith("`") and value.endswith("`"):
        return value[1:-1]
    return value


def _table_cells(line: str) -> list[str]:
    if not (line.startswith("|") and line.endswith("|")):
        return []
    return line[1:-1].split("|")


def _visible_markdown_lines(body: str) -> list[str]:
    visible: list[str] = []
    in_comment = False
    fence: tuple[str, int] | None = None
    for line in body.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if in_comment:
            if "-->" in line:
                in_comment = False
            continue
        if "<!--" in line:
            if "-->" not in line.split("<!--", 1)[1]:
                in_comment = True
            continue
        match = re.fullmatch(r" {0,3}((`{3,}|~{3,}))(.*)", line)
        if match:
            run = match.group(1)
            char = run[0]
            trailing = match.group(3)
            if fence is None:
                fence = (char, len(run))
            elif char == fence[0] and len(run) >= fence[1] and re.fullmatch(r"[ \t]*", trailing):
                fence = None
            continue
        if fence is None:
            visible.append(line)
    return visible


def _parse_frozen_red(body: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Parse one visible, unindented, delimiter-bearing evidence table."""
    lines = _visible_markdown_lines(body)
    headers = [
        i
        for i, line in enumerate(lines)
        if tuple(_cell_text(cell).lower() for cell in _table_cells(line)) == _FROZEN_RED_HEADER
    ]
    if len(headers) != 1:
        return [], [f"expected exactly one visible unindented Frozen RED test table; found {len(headers)}"]

    header = headers[0]
    if header + 1 >= len(lines):
        return [], ["Frozen RED table is missing its Markdown delimiter row"]
    delimiter = _table_cells(lines[header + 1])
    if len(delimiter) != 3 or not all(_DELIMITER.fullmatch(cell.strip()) for cell in delimiter):
        return [], ["Frozen RED table is missing its Markdown delimiter row"]

    records: list[tuple[str, str]] = []
    errors: list[str] = []
    for line in lines[header + 2 :]:
        cells = _table_cells(line)
        if not cells:
            break
        if len(cells) != 3:
            errors.append("Frozen RED table rows must contain path, git hash-object, and RED run tail")
            continue
        path_cell = cells[0].strip()
        if len(path_cell) < 2 or not (path_cell.startswith("`") and path_cell.endswith("`")):
            errors.append("Frozen RED test paths must be enclosed in backticks")
            continue
        path = path_cell[1:-1]
        digest = _cell_text(cells[1])
        tail = _cell_text(cells[2])
        if not path.startswith("tests/"):
            errors.append(f"Frozen RED test path must be under tests/**: {path!r}")
            continue
        if _GIT_HASH.fullmatch(digest) is None:
            errors.append(f"Frozen RED git hash-object is not a Git object ID for {path}")
            continue
        if not tail:
            errors.append(f"Frozen RED record for {path} has no RED run tail")
            continue
        records.append((path, digest))
    if not records and not errors:
        errors.append("Frozen RED table has no evidence rows")
    return records, errors


def _working_tree_blob_hash(path: str) -> str:
    result = subprocess.run(
        ["git", "hash-object", "--", path],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise OSError(result.stderr.strip() or f"git hash-object failed for {path}")
    return result.stdout.strip()


def _frozen_red_violations(changed: list[str], shipped: list[str], body: str) -> list[str]:
    if not any(_is_release_plane(path) for path in changed):
        return []
    records, errors = _parse_frozen_red(body)
    if errors:
        return errors

    violations: list[str] = []
    changed_tests = {path for path in shipped if _is_test(path)}
    seen: set[str] = set()
    for path, recorded in records:
        if path in seen:
            violations.append(f"duplicate Frozen RED record for {path}")
            continue
        seen.add(path)
        if path not in changed_tests:
            violations.append(f"Frozen RED test {path} is not changed by this PR")
            continue
        try:
            actual = _working_tree_blob_hash(path)
        except OSError as exc:
            violations.append(f"cannot hash Frozen RED test {path}: {exc}")
            continue
        if actual != recorded:
            violations.append(
                f"Frozen RED hash mismatch for {path}: PR body records {recorded}, shipped file is {actual}"
            )
    for path in sorted(changed_tests - seen):
        violations.append(f"changed test-side file {path} has no Frozen RED evidence row")
    return violations


def _decode_status_path(raw: bytes) -> str:
    if b"\n" in raw or b"\r" in raw:
        raise ValueError("changed path cannot be represented in Markdown: contains a newline")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("changed path cannot be represented in Markdown: invalid UTF-8") from exc


def _parse_name_status_z(data: bytes) -> tuple[list[str], list[str]]:
    if data and not data.endswith(b"\0"):
        raise ValueError("name-status input is not NUL-terminated")
    fields = data.split(b"\0")[:-1] if data else []
    changed: list[str] = []
    live: dict[str, None] = {}
    i = 0
    while i < len(fields):
        try:
            status = fields[i].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("invalid non-ASCII Git status") from exc
        i += 1
        kind = status[:1]
        count = 2 if kind in {"R", "C"} else 1
        if kind not in {"A", "C", "D", "M", "R", "T"} or i + count > len(fields):
            raise ValueError(f"invalid Git name-status record: {status!r}")
        paths = [_decode_status_path(raw) for raw in fields[i : i + count]]
        i += count
        if kind == "R":
            changed.extend(paths)
            live.pop(paths[0], None)
            live[paths[1]] = None
        elif kind == "C":
            changed.append(paths[1])
            live[paths[1]] = None
        else:
            changed.append(paths[0])
            if kind == "D":
                live.pop(paths[0], None)
            else:
                live[paths[0]] = None
    return changed, list(live)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    ``--name-status-z`` reads exact NUL-delimited ``git diff --name-status -z``
    records from stdin. Positional and legacy stdin paths remain available for
    direct callers and tests.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    warn_only = "--warn-only" in args
    name_status_z = "--name-status-z" in args
    body_file: str | None = None
    while "--pr-body-file" in args:
        i = args.index("--pr-body-file")
        if i + 1 >= len(args):
            print("error: --pr-body-file requires a file path argument")
            return 2
        body_file = args[i + 1]
        del args[i : i + 2]
    paths = [a for a in args if a not in {"--warn-only", "--name-status-z"}]

    if name_status_z:
        if paths:
            print("error: --name-status-z does not accept positional paths")
            return 2
        try:
            paths, shipped = _parse_name_status_z(sys.stdin.buffer.read())
        except ValueError as exc:
            print(f"error: {exc}")
            return 2
    else:
        if not paths:
            stdin = sys.stdin.read()
            paths = stdin.split("\0") if "\0" in stdin else stdin.split("\n")
        paths = [p.strip() for p in paths if p.strip()]
        shipped = paths

    body: str | None = None
    if body_file is not None:
        try:
            # utf-8-sig: a BOM at byte 0 must not hide a justification line.
            with open(body_file, encoding="utf-8-sig", errors="replace") as fh:
                body = fh.read()
        except OSError as exc:
            print(f"error: cannot read --pr-body-file {body_file!r}: {exc}")
            return 2
        if warn_only and not _has_justification(body):
            print(
                "no-test-needed label is set but the PR body has no 'no-test-needed: <why>' "
                "justification line (issue #921: the label must be applied deliberately, with "
                "its justification recorded in the PR body)."
            )
            return 1

    violations = evaluate(paths, shipped)
    if body is not None:
        violations.extend(_frozen_red_violations(paths, shipped, body))

    if not violations:
        print("Coverage pairing OK: shipped tests and available frozen-RED evidence satisfy all rules.")
        return 0

    if warn_only:
        print("WARNING (no-test-needed label): coverage pairing would otherwise FAIL this PR:")
    else:
        print("Coverage pairing FAILED:")
    for msg in violations:
        print(f"  - {msg}")

    if warn_only:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

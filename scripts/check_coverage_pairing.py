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

Each data row names a changed ``tests/**`` path, its 40-character blob hash at
RED time, and a non-empty failing-run tail. The hash is recomputed from the
shipped file, so editing the reproduction between RED and GREEN fails the gate.
The local gate runner omits the body file and checks pairing only; CI always
passes the live PR body and therefore enforces both pairing and frozen proof.

The existing behavior-preserving escape is unchanged: ``--warn-only`` plus a
PR-body line starting ``no-test-needed: <why>`` downgrades violations. It covers
comment-only/refactor changes without introducing a second or wider escape.
"""

from __future__ import annotations

import hashlib
import os
import re
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


def evaluate(changed: list[str]) -> list[str]:
    """Classify ``changed`` paths and return pairing violations."""
    has_src = any(_is_src(p) for p in changed)
    has_www = any(_is_www(p) for p in changed)
    has_release = any(_is_release_plane(p) for p in changed)
    has_test = any(_is_test(p) for p in changed)
    has_ui_test = any(_is_ui_test(p) for p in changed)

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
_GIT_HASH = re.compile(r"[0-9a-fA-F]{40}")


def _table_cells(line: str) -> list[str]:
    stripped = line.strip()
    if not (stripped.startswith("|") and stripped.endswith("|")):
        return []
    return [cell.strip().strip("`").strip() for cell in stripped[1:-1].split("|")]


def _parse_frozen_red(body: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Return ``(path, hash)`` records and malformed-record errors."""
    records: list[tuple[str, str]] = []
    errors: list[str] = []
    in_table = False
    for line in body.splitlines():
        cells = _table_cells(line)
        normalized = tuple(cell.replace("`", "").lower() for cell in cells)
        if not in_table:
            if normalized == _FROZEN_RED_HEADER:
                in_table = True
            continue
        if not cells:
            break
        if len(cells) == 3 and all(cell and set(cell) <= {"-", ":"} for cell in cells):
            continue
        if len(cells) != 3:
            errors.append("Frozen RED table rows must contain path, git hash-object, and RED run tail")
            continue
        path, digest, tail = cells
        if not path.startswith("tests/"):
            errors.append(f"Frozen RED test path must be under tests/**: {path!r}")
            continue
        if _GIT_HASH.fullmatch(digest) is None:
            errors.append(f"Frozen RED git hash-object must be 40 hexadecimal characters for {path}")
            continue
        if not tail:
            errors.append(f"Frozen RED record for {path} has no RED run tail")
            continue
        records.append((path, digest.lower()))
    return records, errors


def _working_tree_blob_hash(path: str) -> str:
    if os.path.islink(path):
        data = os.readlink(os.fsencode(path))
    else:
        with open(path, "rb") as fh:
            data = fh.read()
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def _frozen_red_violations(changed: list[str], body: str) -> list[str]:
    if not any(_is_release_plane(path) for path in changed):
        return []
    records, errors = _parse_frozen_red(body)
    if errors:
        return errors
    if not records:
        return [
            "release-plane changes require a Frozen RED test table with columns "
            "`Frozen RED test`, `git hash-object`, and `RED run tail`"
        ]

    violations: list[str] = []
    changed_set = set(changed)
    seen: set[str] = set()
    for path, recorded in records:
        if path in seen:
            violations.append(f"duplicate Frozen RED record for {path}")
            continue
        seen.add(path)
        if path not in changed_set or not _is_test(path):
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
    return violations


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Positional args are changed paths (used by tests); with none, changed paths
    are read from stdin — NUL-separated as the CI job pipes ``git diff
    --name-only -z`` output in, newline-separated otherwise. Every entry point is
    normalized the same way (surrounding whitespace stripped, blank entries
    dropped), so a padded positional arg and a trailing-newline stdin line
    classify identically.

    ``--pr-body-file <path>`` carries the live PR body. With ``--warn-only`` it
    must contain the existing ``no-test-needed: <why>`` justification. Without
    ``--warn-only``, release-plane changes use it for frozen-RED validation.
    Omitting the flag keeps local/path-only callers pairing-only.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    warn_only = "--warn-only" in args
    body_file: str | None = None
    while "--pr-body-file" in args:  # strip EVERY occurrence — a leaked repeat must
        i = args.index("--pr-body-file")  # never enter the path list; last value wins
        if i + 1 >= len(args):
            print("error: --pr-body-file requires a file path argument")
            return 2
        body_file = args[i + 1]
        del args[i : i + 2]
    paths = [a for a in args if a != "--warn-only"]

    if not paths:
        # NUL-separated is the CI job's transport (`git diff --name-only -z`):
        # the newline form C-quotes a path holding a quote, backslash, control
        # byte or non-ASCII byte, and a quoted path matches no rule at all
        # (issues #2137, #2212). A newline-separated stream still works, so the
        # positional/`echo`-piped entry points keep classifying identically.
        stdin = sys.stdin.read()
        # split("\n"), not splitlines(): the latter also breaks on \f, \x85 and
        # the Unicode line separators, which are ordinary path bytes here.
        paths = stdin.split("\0") if "\0" in stdin else stdin.split("\n")
    paths = [p.strip() for p in paths if p.strip()]

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

    violations = evaluate(paths)
    if body is not None:
        violations.extend(_frozen_red_violations(paths, body))

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

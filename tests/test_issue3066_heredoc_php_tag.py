"""Issue #3066: a PHP open tag inside an INTERPOLATING heredoc breaks code-graph extraction.

`tree-sitter-php` 0.24.1 (the newest published grammar, and the one Graphify's
extractor uses) fails to parse a `<<<EOF` body that contains a PHP open tag: it
emits `ERROR` nodes from the heredoc onwards, so the file is only partially
extracted even though `php -l` accepts it. A nowdoc (`<<<'EOF'`) body carrying
the same tags parses fine, so the shipped rule is narrow: generated PHP source
that needs a literal `<?php` / `<?=` tag keeps it OUT of an interpolating
heredoc body.

`test_src_tree_has_no_php_tag_in_interpolating_heredoc` is the red->green proof:
RED against the unfixed tree (`pfblockerng_geoip.inc` line 225's heredoc opened
with `<?php` on its first body line), GREEN once that tag moved out of the
heredoc.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_ROOT = _REPO_ROOT / "src"

# `<<<EOF` and `<<<"EOF"` interpolate; `<<<'EOF'` (nowdoc) does not and parses fine.
_HEREDOC_OPEN = re.compile(r"<<<[ \t]*(?:\"(\w+)\"|(\w+))[ \t]*$")
_PHP_OPEN_TAG = re.compile(r"<\?")


def find_violations(text: str, source: str = "t.inc") -> list[tuple[str, int, str]]:
    """Return (source, 1-based line, label) for every PHP tag in a heredoc body."""
    violations: list[tuple[str, int, str]] = []
    lines = text.split("\n")
    index = 0
    while index < len(lines):
        opened = _HEREDOC_OPEN.search(lines[index])
        index += 1
        if opened is None:
            continue
        label = opened.group(1) or opened.group(2)
        closing = re.compile(rf"^[ \t]*{re.escape(label)}\b")
        while index < len(lines) and not closing.match(lines[index]):
            if _PHP_OPEN_TAG.search(lines[index]):
                violations.append((source, index + 1, label))
            index += 1
    return violations


def test_php_open_tag_in_interpolating_heredoc_is_flagged() -> None:
    text = "<?php\n$a = <<<EOF\n<?php\nfoo();\nEOF;\n"
    assert find_violations(text) == [("t.inc", 3, "EOF")]


def test_short_echo_tag_in_interpolating_heredoc_is_flagged() -> None:
    text = "<?php\n$a = <<<EOF\nx\n<?=f()?>\nEOF;\n"
    assert find_violations(text) == [("t.inc", 4, "EOF")]


def test_double_quoted_label_is_treated_as_interpolating() -> None:
    text = '<?php\n$a = <<<"EOF"\n<?php\nEOF;\n'
    assert find_violations(text) == [("t.inc", 3, "EOF")]


def test_nowdoc_body_with_php_tags_is_clean() -> None:
    text = "<?php\n$a = <<<'EOF'\n<?php\nfoo();\n?>\nEOF;\n"
    assert find_violations(text) == []


def test_interpolating_heredoc_without_php_tags_is_clean() -> None:
    text = '<?php\n$a = <<<EOF\n$continent = "{$continent}";\nEOF;\n'
    assert find_violations(text) == []


def test_php_tag_after_the_closing_marker_is_not_body_text() -> None:
    text = '<?php\n$a = <<<EOF\nbody\nEOF;\n$b = "<?php";\n'
    assert find_violations(text) == []


def test_src_tree_has_no_php_tag_in_interpolating_heredoc() -> None:
    violations: list[tuple[str, int, str]] = []
    for path in sorted(_SRC_ROOT.rglob("*")):
        if path.suffix not in {".inc", ".php"} or not path.is_file():
            continue
        violations += find_violations(
            path.read_text(encoding="utf-8", errors="replace"),
            str(path.relative_to(_REPO_ROOT)),
        )
    assert violations == [], (
        "PHP open tag inside an interpolating heredoc body (breaks tree-sitter-php "
        f"extraction, issue #3066): expected [], got {violations}"
    )

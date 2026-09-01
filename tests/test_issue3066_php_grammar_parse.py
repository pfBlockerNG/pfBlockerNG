"""Issue #3066: every tracked PHP source must parse under the code-graph grammar.

Code-graph extraction (Graphify) parses PHP with `tree-sitter-php`, not with PHP
itself, and a file the grammar cannot parse is silently HALF extracted: symbols
and call edges from the first ERROR node onwards go missing while `php -l` still
reports the file clean. `pfblockerng_geoip.inc` sat in that state -- its
generated-page heredoc produced 14 ERROR spans and extraction warned
"1 file(s) had syntax errors and may be partially extracted".

The upstream cause is NOT isolated, so this test pins the property that is,
rather than a source shape. What was observed with tree-sitter-php 0.24.1: the
file parses clean while that heredoc's body starts at its `/*` license comment,
and prepending ANY line to the body reproduces the identical spans -- `<?php`,
`xyz` and `declare(strict_types=1);` alike. A shape rule about PHP open tags
would therefore have stayed green through the very regression it was written
for, which is why the guard parses the bytes instead.

`test_every_tracked_php_source_parses_under_the_code_graph_grammar` is the
red->green proof: RED against the unfixed tree (`pfblockerng_geoip.inc`, 14 ERROR
spans), GREEN once the heredoc body starts at `/*`.
"""

from __future__ import annotations

from pathlib import Path

import tree_sitter
import tree_sitter_php
from _git_paths import nul_listing

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SUFFIXES = {".inc", ".php"}
_PARSER = tree_sitter.Parser(tree_sitter.Language(tree_sitter_php.language_php()))

# The file the defect was found in: named explicitly so a scan that stops
# reaching it fails instead of passing on an empty file set.
_DEFECT_FILE = "src/usr/local/pkg/pfblockerng/pfblockerng_geoip.inc"


def error_spans(source: bytes) -> list[tuple[int, int]]:
    """1-based (first, last) line of every ERROR or MISSING node in `source`."""
    root = _PARSER.parse(source).root_node
    if not root.has_error:
        return []
    spans: list[tuple[int, int]] = []
    pending = [root]
    while pending:
        node = pending.pop()
        if node.type == "ERROR" or node.is_missing:
            spans.append((node.start_point[0] + 1, node.end_point[0] + 1))
        else:
            pending.extend(node.children)
    return sorted(spans)


def test_error_spans_reports_a_genuine_parse_failure() -> None:
    """The detector's own red canary: invalid PHP must come back with spans."""
    assert error_spans(b"<?php\nfunction {\n") != []


def test_error_spans_is_silent_on_valid_php() -> None:
    assert error_spans(b"<?php\nfunction f(): int\n{\n\treturn 1;\n}\n") == []


def test_every_tracked_php_source_parses_under_the_code_graph_grammar() -> None:
    scanned = [
        path
        for path in nul_listing(_REPO_ROOT, "ls-files", "-z", "--", "*.php", "*.inc")
        if Path(path).suffix in _SUFFIXES
    ]
    assert _DEFECT_FILE in scanned, (
        f"the scan must reach {_DEFECT_FILE}; it walked {len(scanned)} file(s), so a "
        "green result here would prove nothing"
    )

    failures = {path: spans for path in sorted(scanned) if (spans := error_spans((_REPO_ROOT / path).read_bytes()))}
    assert failures == {}, (
        "tree-sitter-php cannot parse these files, so code-graph extraction drops "
        f"every symbol and edge after the first span (issue #3066): expected {{}}, got {failures}"
    )

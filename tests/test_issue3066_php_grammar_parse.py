"""Issue #3066: every tracked PHP source must parse under the code-graph grammar.

Code-graph extraction parses PHP with `tree-sitter-php`, not with PHP itself, so
a file the grammar chokes on is silently HALF extracted while `php -l` still
calls it clean. The upstream cause is NOT isolated, so this pins the property
that is: observed with tree-sitter-php 0.24.1, `pfblockerng_geoip.inc` parses
clean while its generated-page heredoc body starts at the `/*` license comment,
and prepending ANY line reproduces the identical 14 ERROR spans -- `<?php`,
`xyz` and `declare(strict_types=1);` alike. A shape rule about PHP open tags
would have stayed green through the very regression it was written for, which is
why this parses the bytes instead.
"""

from __future__ import annotations

from pathlib import Path

import tree_sitter
import tree_sitter_php
from _git_paths import nul_listing

_REPO_ROOT = Path(__file__).resolve().parent.parent
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
    scanned = nul_listing(_REPO_ROOT, "ls-files", "-z", "--", "*.php", "*.inc")
    assert _DEFECT_FILE in scanned, (
        f"the scan must reach {_DEFECT_FILE}; it walked {len(scanned)} file(s), so a "
        "green result here would prove nothing"
    )

    failures = {path: spans for path in sorted(scanned) if (spans := error_spans((_REPO_ROOT / path).read_bytes()))}
    assert failures == {}, (
        "tree-sitter-php cannot parse these files, so code-graph extraction drops "
        f"every symbol and edge after the first span (issue #3066): expected {{}}, got {failures}"
    )

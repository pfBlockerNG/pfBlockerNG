"""Keep Claude workflow schemas and Codex CLI schemas semantically identical."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / ".claude" / "workflows" / "schemas"


def _embedded_schema(workflow: str, name: str) -> dict[str, object]:
    source = (ROOT / ".claude" / "workflows" / workflow).read_text()
    match = re.search(rf"const {name} = JSON\.parse\(String\.raw`(.*?)`\)", source, re.DOTALL)
    assert match, f"{workflow} must embed {name} as JSON for parity checking"
    return json.loads(match.group(1))


def _schema(name: str) -> dict[str, object]:
    return json.loads((SCHEMA_DIR / name).read_text())


def test_findings_schema_is_shared_by_both_workflows_and_codex() -> None:
    expected = _schema("review-findings.schema.json")
    assert _embedded_schema("review-single.js", "FINDINGS") == expected
    assert _embedded_schema("review-fanout.js", "FINDINGS") == expected


def test_fanout_verdict_schema_matches_codex() -> None:
    assert _embedded_schema("review-fanout.js", "VERDICT") == _schema("review-verdict.schema.json")

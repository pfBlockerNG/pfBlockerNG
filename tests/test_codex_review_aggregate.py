from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "agent" / "codex_review_aggregate.py"
SPEC = importlib.util.spec_from_file_location("codex_review_aggregate", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _finding(location: str, explanation: str, severity: str = "blocking") -> dict:
    return {
        "severity": severity,
        "location": location,
        "explanation": explanation,
        "reproduce": "probe output",
        "suggested_fix": "fix it",
    }


def test_prepare_deduplicates_like_canonical_fanout(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    duplicate = _finding("a:1", "same defect")
    first.write_text(json.dumps({"findings": [duplicate], "per_file": [{"file": "a", "verdict": "finding"}]}))
    second.write_text(
        json.dumps(
            {
                "findings": [duplicate, _finding("b:2", "other")],
                "per_file": [{"file": "b", "verdict": "finding"}],
            }
        )
    )

    merged = tmp_path / "merged"
    MODULE.prepare(merged, [first, second])

    assert (merged / "count").read_text() == "2\n"
    assert json.loads((merged / "per-file.json").read_text()) == [
        {"file": "a", "verdict": "finding"},
        {"file": "b", "verdict": "finding"},
    ]


def test_finalize_separates_confirmed_and_refuted(tmp_path: Path) -> None:
    merged = tmp_path / "merged"
    merged.mkdir()
    (merged / "count").write_text("2\n")
    (merged / "per-file.json").write_text("[]\n")
    (merged / "finding-1.json").write_text(json.dumps(_finding("a:1", "holds")))
    (merged / "finding-2.json").write_text(json.dumps(_finding("b:2", "fails")))
    verdicts = tmp_path / "verdicts"
    verdicts.mkdir()
    (verdicts / "verdict-1.json").write_text(
        json.dumps({"holds": True, "evidence": "yes", "revised_severity": "nitpick"})
    )
    (verdicts / "verdict-2.json").write_text(json.dumps({"holds": False, "evidence": "no", "revised_severity": None}))

    output = tmp_path / "result.json"
    MODULE.finalize(merged, verdicts, output)
    result = json.loads(output.read_text())

    assert result["confirmed"][0]["severity"] == "nitpick"
    assert result["confirmed"][0]["verified"]["holds"] is True
    assert result["refuted"] == [{"location": "b:2", "explanation": "fails", "evidence": "no"}]
    assert result["lenses_returned"] == 3

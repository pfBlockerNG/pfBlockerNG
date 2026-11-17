"""CI's smoke legs skip the production-cadence case; that skip must be on the recorded allowlist (#3996)."""

from __future__ import annotations

from pathlib import Path

from scripts import check_skip_allowlist as csa

ROOT = Path(__file__).resolve().parent.parent


def _report(tmp_path: Path, classname: str, name: str) -> Path:
    path = tmp_path / "smoke.xml"
    path.write_text(
        '<?xml version="1.0" encoding="UTF-8"?><testsuites><testsuite name="t" tests="1">'
        f'<testcase classname="{classname}" name="{name}"><skipped message="x"/></testcase>'
        "</testsuite></testsuites>\n",
        encoding="utf-8",
    )
    return path


def _run(report: Path) -> int:
    return csa.main(["--suite", "smoke", "--allowlist", str(ROOT / "tests" / "skip-allowlist.txt"), str(report)])


def test_the_scheduled_maintenance_skip_is_allowlisted(tmp_path: Path) -> None:
    name = "test_core_scheduled_maintenance_preserves_tick_duties"
    assert _run(_report(tmp_path, "tests.smoke.test_core_scheduled_maintenance", name)) == 0


def test_a_sibling_skip_in_that_module_is_not(tmp_path: Path) -> None:
    assert _run(_report(tmp_path, "tests.smoke.test_core_scheduled_maintenance", "test_some_other_case")) == 1

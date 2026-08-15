"""Historical material stays isolated from active repository checks."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_historical_roots_live_only_under_legacy() -> None:
    for path in ("archive", "benchmarks", "ADRs", "ADR_RESULTS"):
        assert (ROOT / "legacy" / path).is_dir(), f"legacy/{path} is missing"

    for path in ("archive", "benchmarks", ".ADRs", "RESULTS"):
        assert not (ROOT / path).exists(), f"{path} must move under legacy/"


def test_active_repository_checks_exclude_legacy() -> None:
    coderabbit = (ROOT / ".coderabbit.yaml").read_text()
    attributes = (ROOT / ".gitattributes").read_text()
    snyk = (ROOT / ".snyk").read_text()
    precommit = (ROOT / ".githooks/pre-commit").read_text()
    gate_runner = (ROOT / "scripts/agent/run-gates.sh").read_text()
    markdownlint = (ROOT / ".markdownlint-cli2.jsonc").read_text()
    pyproject = (ROOT / "pyproject.toml").read_text()
    shellspec = (ROOT / ".shellspec").read_text()
    phpunit = (ROOT / "phpunit.xml").read_text()
    workflow = (ROOT / ".github/workflows/test.yml").read_text()

    assert '"!legacy/**"' in coderabbit
    assert "legacy/** linguist-documentation" in attributes
    assert "- legacy/**" in snyk
    assert "legacy/*) continue" in precommit
    assert "grep -v '^legacy/'" in precommit
    assert "grep -v '^legacy/'" in gate_runner
    assert '"legacy/**"' in markdownlint
    assert '"tests/fixtures/**"' in markdownlint
    assert '"legacy"' in pyproject
    assert "--default-path tests/shell" in shellspec
    assert "<directory>tests/php</directory>" in phpunit
    assert "legacy/*) continue" in workflow
    assert workflow.count("- 'legacy/**'") == 2
    assert "python legacy/benchmarks/" in workflow

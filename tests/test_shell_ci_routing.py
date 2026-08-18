"""Contract tests for issue #2318's environment-sensitive ShellSpec routing."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_ports_parity_examples_are_isolated_and_explicitly_routed() -> None:
    default = _read("tests/shell/build_leg_spec.sh")
    parity_path = ROOT / "tests/shell/build_leg_ports_parity_env.sh"
    parity = parity_path.read_text(encoding="utf-8") if parity_path.exists() else ""
    workflow = _read(".github/workflows/build-pkg-linux.yml")

    assert "Skip" not in default and "pending" not in default
    assert parity_path.exists() and parity
    assert "env:ports" in parity
    assert "REAL_PORTS_DIR" in parity
    assert '--ports "$REAL_PORTS_DIR"' in parity
    assert "remote get-url origin" in parity
    assert '--ports-repo "$ports_url"' in parity
    assert "file://${REAL_PORTS_DIR}" not in parity
    assert "direct-ports" not in parity
    assert "--fail-no-examples" in workflow
    assert "build_leg_ports_parity_env.sh" in workflow
    assert "--tag env:ports" in workflow
    assert "${PFB_RUN_ROOT}/${RUN_ID}/ports" in workflow


def test_kcov_coverage_selectors_are_focused() -> None:
    workflow = _read(".github/workflows/test.yml")
    match = re.search(r"shellspec --kcov --shell bash(?P<body>[\s\S]*?)(?:\n\s*else|\n\s*fi)", workflow)
    assert match, "kcov step must invoke shellspec with an explicit selector"
    body = match.group(0)
    assert "tests/shell/ip_pre_aws_spec.sh" in body
    assert "tests/shell/pfb_python_spec.sh" in body
    assert "tests/shell/pfblockerng_*_spec.sh" in body
    assert not re.search(r"shellspec --kcov --shell bash\s*$", body, re.MULTILINE)


def test_the_shellspec_job_provides_the_locale_the_adr26_contract_needs() -> None:
    """`pfblockerng_adr26_locale_spec.sh` skips itself when de_DE.UTF-8 is absent, so
    a CI runner without that locale turns the ADR-26 collation contract off in silence
    rather than failing. The job must therefore generate the locale AND prove it
    resolves, in the job itself: `locale -a` listing it is the only evidence that the
    generation actually took, and LC_NUMERIC is the half the shard/module specs read."""
    rest = _read(".github/workflows/test.yml").split("\n  shell-tests:\n", 1)[1]
    end = re.search(r"^  [A-Za-z0-9_.-]+:\s*$", rest, re.MULTILINE)
    job = rest[: end.start()] if end else rest
    assert "locale-gen de_DE.UTF-8" in job, (
        "the shellspec job must generate de_DE.UTF-8 (`sudo locale-gen de_DE.UTF-8`); "
        "ubuntu-latest ships none, so the ADR-26 locale contract silently skips"
    )
    assert "locale -a" in job, "the shellspec job must prove the generated locale resolves, not just run locale-gen"
    assert "LC_ALL=de_DE.UTF-8 locale -k LC_NUMERIC" in job, (
        "the proof must read LC_NUMERIC under de_DE.UTF-8 — the decimal comma is what the "
        "shard and module-duration specs contrast against C"
    )


def test_adr26_locale_contract_uses_sorting_contrast() -> None:
    spec = _read("tests/shell/pfblockerng_adr26_locale_spec.sh")
    assert "soft hyphen" not in spec
    assert "z\\nä" in spec
    assert "de_DE.UTF-8" in spec

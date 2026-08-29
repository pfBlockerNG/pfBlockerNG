"""Contract tests for issue #2318's environment-sensitive ShellSpec routing."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from tests._workflow_steps import extract_after

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


def test_linux_dependency_builder_uses_structured_locked_reproducibility_contract() -> None:
    workflow = yaml.safe_load(_read(".github/workflows/build-pkg-linux.yml"))
    steps = workflow["jobs"]["build"]["steps"]
    setup = next(step for step in steps if step.get("name") == "Set up uv and the pinned Python")
    sync = next(step for step in steps if step.get("name") == "Sync the locked dependency-package toolchain")
    build = next(step for step in steps if step.get("name") == "Build .pkg via build-leg.sh")

    assert setup["with"]["version"] == "0.12.6"
    assert setup["with"]["activate-environment"] is True
    assert sync["run"] == "uv sync --locked --only-group dep-pkg-build"
    assert '--ports-sha "$PORTS_SHA"' in build["run"]
    assert '--source-date-epoch "$SOURCE_DATE_EPOCH"' in build["run"]


def test_kcov_coverage_selectors_are_focused() -> None:
    workflow = _read(".github/workflows/test.yml")
    match = re.search(r"shellspec --kcov --shell bash(?P<body>[\s\S]*?)(?:\n\s*else|\n\s*fi)", workflow)
    assert match, "kcov step must invoke shellspec with an explicit selector"
    body = match.group(0)
    assert "tests/shell/ip_pre_aws_spec.sh" in body
    assert "tests/shell/pfb_python_spec.sh" in body
    assert "tests/shell/pfblockerng_*_spec.sh" in body
    assert not re.search(r"shellspec --kcov --shell bash\s*$", body, re.MULTILINE)


# Every proof has to FAIL when de_DE.UTF-8 is missing or dotted, which is what the
# pipe into a quiet grep buys: `locale -a` and `locale -k LC_NUMERIC` both exit 0 with
# the locale absent, so a bare listing proves nothing about what got generated.
_LOCALE_PROOFS = (
    ("generates the locale", re.compile(r"locale-gen de_DE\.UTF-8")),
    ("fails when `locale -a` omits it", re.compile(r"locale -a\s*\|[^\n]*grep[^\n]*de_DE", re.IGNORECASE)),
    ("fails when LC_NUMERIC stays dotted", re.compile(r"LC_ALL=de_DE\.UTF-8 locale -k LC_NUMERIC\s*\|[^\n]*grep")),
    ("fails when awk stays dotted", re.compile(r"LC_ALL=de_DE\.UTF-8 awk[^\n]*\|[^\n]*grep")),
)


def _locale_proof_gaps(job: str) -> list[str]:
    """Which locale proofs the job text never runs. Comment lines are dropped first:
    a `#` line documents a command, it does not execute one."""
    code = "\n".join(line for line in job.splitlines() if not line.lstrip().startswith("#"))
    return [what for what, pattern in _LOCALE_PROOFS if not pattern.search(code)]


def test_the_shellspec_job_provides_the_locale_the_adr26_contract_needs() -> None:
    """`pfblockerng_adr26_locale_spec.sh` skips itself when de_DE.UTF-8 is absent, so
    a CI runner without that locale turns the ADR-26 collation contract off in silence
    rather than failing. The job must therefore generate the locale AND prove it
    resolves, in the job itself, through commands that exit NONZERO when it does not:
    that it is listed at all, that LC_NUMERIC carries the decimal comma, and that awk
    — the interpreter the shard and module-duration specs probe through — reads it."""
    rest = extract_after(_read(".github/workflows/test.yml"), "\n  shell-tests:\n")
    end = re.search(r"^  [A-Za-z0-9_.-]+:\s*$", rest, re.MULTILINE)
    job = rest[: end.start()] if end else rest
    gaps = _locale_proof_gaps(job)
    assert gaps == [], (
        "the shellspec job must generate de_DE.UTF-8 and prove it took, with checks that "
        f"fail when it did not — ubuntu-latest ships no such locale. Missing: {gaps}"
    )


def test_the_locale_proof_scan_rejects_a_listing_that_cannot_fail() -> None:
    """Vacuity guard: a bare `locale -a` exits 0 with the locale absent, and a
    commented command runs nothing at all — neither may satisfy a proof."""
    complete = (
        "        run: |\n"
        "          sudo locale-gen de_DE.UTF-8\n"
        "          locale -a | grep -Eqi '^de_DE\\.utf-?8$'\n"
        "          LC_ALL=de_DE.UTF-8 locale -k LC_NUMERIC | grep -Fq 'decimal_point=\",\"'\n"
        "          LC_ALL=de_DE.UTF-8 awk 'BEGIN { printf \"%.2f\", 1.5 }' | grep -q ','\n"
    )
    assert _locale_proof_gaps(complete) == []
    bare = complete.replace("locale -a | grep -Eqi '^de_DE\\.utf-?8$'", "locale -a")
    assert _locale_proof_gaps(bare) == ["fails when `locale -a` omits it"]
    commented = "\n".join(f"          # {line.strip()}" for line in complete.splitlines())
    assert len(_locale_proof_gaps(commented)) == len(_LOCALE_PROOFS)


def test_adr26_locale_contract_uses_sorting_contrast() -> None:
    spec = _read("tests/shell/pfblockerng_adr26_locale_spec.sh")
    assert "soft hyphen" not in spec
    assert "z\\nä" in spec
    assert "de_DE.UTF-8" in spec

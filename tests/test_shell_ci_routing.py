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
    sync = next(step for step in steps if step.get("name") == "Sync the locked dependency-package toolchain")
    build = next(step for step in steps if step.get("name") == "Build .pkg via build-leg.sh")

    # uv and the pinned Python are baked into the ci image (UV_VERSION is pinned by test_ci_tool_pins.py), so
    # only the sync remains, and the synced venv goes on PATH where the activated environment used to put it.
    assert workflow["jobs"]["build"].get("container", {}).get("image") == "${{ needs.ci-image.outputs.ci }}"
    assert sync["run"].splitlines() == [
        "set -eu",
        "uv sync --locked --only-group dep-pkg-build",
        'echo "$GITHUB_WORKSPACE/.venv/bin" >> "$GITHUB_PATH"',
    ]
    assert '--ports-sha "$PORTS_SHA"' in build["run"]
    assert '--source-date-epoch "$SOURCE_DATE_EPOCH"' in build["run"]


def _kcov_step_run() -> str:
    """The `run:` text of the shell-tests job's `Coverage (kcov)` step, from the parsed workflow."""
    steps = yaml.safe_load(_read(".github/workflows/test.yml"))["jobs"]["shell-tests"]["steps"]
    runs = [step["run"] for step in steps if step.get("name") == "Coverage (kcov)"]
    assert len(runs) == 1, f"shell-tests must have exactly one `Coverage (kcov)` step with a run, found {len(runs)}"
    return runs[0]


def test_kcov_coverage_selectors_are_focused() -> None:
    body = _kcov_step_run()
    assert re.search(r"shellspec --kcov --shell bash", body), (
        "kcov step must invoke shellspec with an explicit selector"
    )
    assert "tests/shell/ip_pre_aws_spec.sh" in body
    assert "tests/shell/pfb_python_spec.sh" in body
    assert "tests/shell/pfblockerng_*_spec.sh" in body
    assert not re.search(r"shellspec --kcov --shell bash\s*$", body, re.MULTILINE)


def test_the_kcov_step_fails_rather_than_skips_when_kcov_is_missing() -> None:
    """The ci image copies kcov in and its build fails without it, so a kcov that is missing at job
    time is a broken image. A `command -v kcov` guard with a skip branch would let the coverage run
    vanish from the job with the job still green."""
    run = _kcov_step_run()
    assert "shellspec --kcov" in run, "the kcov step must run shellspec under kcov"
    assert "command -v kcov" not in run, f"the kcov step probes for kcov instead of requiring it:\n{run}"
    assert not re.search(r"\b(?:else|elif)\b|\bskip", run, re.IGNORECASE), f"the kcov step has a skip branch:\n{run}"
    # Nothing may follow the selectors either: `|| true` or `; exit 0` would mask a failing run.
    command = " ".join(run.replace("\\\n", " ").split())
    assert re.fullmatch(r"shellspec --kcov --shell bash(?: [\w./*-]+)+", command), f"not one bare kcov run:\n{run}"


# The ci image generates de_DE.UTF-8 (its Dockerfile); the shellspec job proves it took. Every
# proof has to FAIL when de_DE.UTF-8 is missing or dotted, which is what the pipe into a quiet
# grep buys: `locale -a` and `locale -k LC_NUMERIC` both exit 0 with the locale absent, so a
# bare listing proves nothing about what got generated.
_LOCALE_PROOFS = (
    ("fails when `locale -a` omits it", re.compile(r"locale -a\s*\|[^\n]*grep[^\n]*de_DE", re.IGNORECASE)),
    ("fails when LC_NUMERIC stays dotted", re.compile(r"LC_ALL=de_DE\.UTF-8 locale -k LC_NUMERIC\s*\|[^\n]*grep")),
    ("fails when awk stays dotted", re.compile(r"LC_ALL=de_DE\.UTF-8 awk[^\n]*\|[^\n]*grep")),
)


def _locale_proof_gaps(job: str) -> list[str]:
    """Which locale proofs the job text never runs. Comment lines are dropped first:
    a `#` line documents a command, it does not execute one."""
    code = "\n".join(line for line in job.splitlines() if not line.lstrip().startswith("#"))
    return [what for what, pattern in _LOCALE_PROOFS if not pattern.search(code)]


def test_the_ci_image_generates_the_locale_the_adr26_contract_needs() -> None:
    """`pfblockerng_adr26_locale_spec.sh` skips itself when de_DE.UTF-8 is absent; the image the
    shellspec job runs in is what has to generate it."""
    dockerfile = "\n".join(
        line for line in _read(".github/docker/Dockerfile").splitlines() if not line.lstrip().startswith("#")
    )
    assert re.search(r"locale-gen de_DE\.UTF-8", dockerfile), "the ci image must run `locale-gen de_DE.UTF-8`"


def test_the_shellspec_job_proves_the_locale_the_adr26_contract_needs() -> None:
    """A job without that locale turns the ADR-26 collation contract off in silence rather than
    failing, so the job must prove, through commands that exit NONZERO when it does not
    resolve, that the locale is listed at all, that LC_NUMERIC carries the decimal comma, and
    that awk -- the interpreter the shard and module-duration specs probe through -- reads it."""
    rest = extract_after(_read(".github/workflows/test.yml"), "\n  shell-tests:\n")
    end = re.search(r"^  [A-Za-z0-9_.-]+:\s*$", rest, re.MULTILINE)
    job = rest[: end.start()] if end else rest
    gaps = _locale_proof_gaps(job)
    assert gaps == [], (
        f"the shellspec job must prove de_DE.UTF-8 took, with checks that fail when it did not. Missing: {gaps}"
    )


def test_the_locale_proof_scan_rejects_a_listing_that_cannot_fail() -> None:
    """Vacuity guard: a bare `locale -a` exits 0 with the locale absent, and a
    commented command runs nothing at all -- neither may satisfy a proof."""
    complete = (
        "        run: |\n"
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

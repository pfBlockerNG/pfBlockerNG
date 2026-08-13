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


def test_locale_is_baked_and_proved_in_both_images() -> None:
    base = _read(".github/docker/ci-runner.Dockerfile")
    vm = _read(".github/docker/ci-runner-vm.Dockerfile")
    workflow = _read(".github/workflows/ci-images.yml")
    assert "locales" in base and "locale-gen de_DE.UTF-8" in base
    assert "LANG=C.UTF-8" in base
    assert "locale charmap" in base
    assert "LC_ALL=de_DE.UTF-8 locale -k LC_NUMERIC" in base
    assert "ci-runner:${TAG}-${ARCH}" in workflow
    assert "ci-runner-vm:${TAG}-${ARCH}" in workflow
    assert "de_DE.UTF-8" in workflow
    assert "locale charmap" in workflow
    assert "LC_ALL=de_DE.UTF-8 locale -k LC_NUMERIC" in workflow
    assert "ci-runner" in vm and "BASE_IMAGE" in vm


def test_adr26_locale_contract_uses_sorting_contrast() -> None:
    spec = _read("tests/shell/pfblockerng_adr26_locale_spec.sh")
    assert "soft hyphen" not in spec
    assert "z\\nä" in spec
    assert "de_DE.UTF-8" in spec


def test_ci_runner_series_bumped_and_all_consumers_follow_it() -> None:
    version = _read(".github/docker/VERSION").strip()
    assert version == "8"
    for path in (ROOT / ".github/workflows").glob("*.yml"):
        text = path.read_text(encoding="utf-8")
        assert ":7" not in text, f"stale ci-runner series in {path}"
    smoke = _read("scripts/local-smoke.sh")
    assert ":7" not in smoke

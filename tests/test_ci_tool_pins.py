from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_ruff_ci_install_is_pinned() -> None:
    workflow = (ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8")
    ruff_job = workflow.split("\n  ruff:\n", 1)[1].split("\n  shellcheck:\n", 1)[0]
    install_step = ruff_job.split("      - name: Install Ruff\n", 1)[1].split("\n      - name:", 1)[0].strip()
    ruff_installs = [line.strip() for line in ruff_job.splitlines() if "pip install" in line and "ruff" in line]

    assert install_step == "run: pip install ruff==0.15.22"
    assert ruff_installs == ["run: pip install ruff==0.15.22"]

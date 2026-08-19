"""Active tracked files use the canonical package and main-site endpoints."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).parents[1]
TEST_PATH = Path(__file__).relative_to(ROOT)
LEGACY_PACKAGE_HOST = ".".join(("pfblockerng", "github", "io"))
INSECURE_MAIN_URL = "http://" + ".".join(("pfblockerng", "com"))


def test_active_files_have_no_retired_project_endpoints() -> None:
    tracked = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout.split(b"\0")
    findings: list[str] = []

    for raw_path in tracked:
        if not raw_path:
            continue
        path = Path(os.fsdecode(raw_path))
        if path == TEST_PATH or path.parts[0] == "legacy":
            continue
        file_path = ROOT / path
        if not file_path.is_file():
            continue
        text = file_path.read_bytes().decode("utf-8", errors="replace")
        for line_number, line in enumerate(text.splitlines(), 1):
            if LEGACY_PACKAGE_HOST in line or INSECURE_MAIN_URL in line:
                findings.append(f"{path}:{line_number}: {line}")

    assert not findings, "retired active endpoints remain:\n" + "\n".join(findings)

"""issue #3924: the live check that Core's state directory holds no retired settings file can fail.

Each retired file is asked on its own: a directory holding only ``settings.json`` (one of three) must be reported,
which a single ``ls`` over the three paths missed (its non-zero exit for the two absent ones passed the check).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from tests.smoke.test_smoke_core_api import RETIRED_SETTINGS, retired_settings_present


def _exists(path: str) -> bool:
    """``test -e`` as the live check runs it on the box."""
    return subprocess.run(["test", "-e", path], check=False).returncode == 0


def test_a_state_directory_holding_only_settings_json_is_reported(tmp_path: Path) -> None:
    (tmp_path / "core.lock").touch()
    (tmp_path / "settings.json").touch()

    assert retired_settings_present(str(tmp_path), _exists) == [f"{tmp_path}/settings.json"]


def test_each_retired_file_is_reported_on_its_own(tmp_path: Path) -> None:
    for name in RETIRED_SETTINGS:
        (tmp_path / name).touch()

    assert retired_settings_present(str(tmp_path), _exists) == [f"{tmp_path}/{name}" for name in RETIRED_SETTINGS]


def test_a_directory_with_only_cores_lock_reports_nothing(tmp_path: Path) -> None:
    (tmp_path / "core.lock").touch()

    assert retired_settings_present(str(tmp_path), _exists) == []

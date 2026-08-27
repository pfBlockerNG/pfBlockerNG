"""Issue #1718: an empty MAIN regex marker is authoritative."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import unboundmodule

import pfb_unbound as P


def _write_manifest(path: Path) -> None:
    path.write_text('{"version": 1, "config": {}, "feeds": []}\n', encoding="utf-8")


def test_empty_main_regex_marker_loads_no_user_regexes(tmp_path: Path, monkeypatch: Any) -> None:
    """An explicitly empty MAIN blob produces no user regex entries."""
    (tmp_path / "pfb_unbound.ini").write_text(
        "[MAIN]\npython_enable = true\nregex_list = \n",
        encoding="utf-8",
    )
    _write_manifest(tmp_path / "pfb_py_sources.json")
    monkeypatch.chdir(tmp_path)
    P.pfb["mod_maxminddb_e"] = "stub"
    P.pfb["mod_threading_e"] = "stub"
    P.pfb["mod_sqlite3_e"] = "stub"
    P.pfb["mod_sqlite3"] = False
    P.pfb["mod_threading"] = False

    try:
        assert P.init_standard(0, unboundmodule.module_env()) is True
        assert dict(P.regexDB) == {}

        swapped = P._build_swap_snapshot()
        assert swapped is not None
        assert swapped.regex_db == {}
    finally:
        P.deinit(0)

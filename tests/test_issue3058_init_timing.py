"""issue #3058: init_standard reports the build duration and the loaded entry count.

The duration of a DNSBL build is user-visible -- it is the window during which
unbound is unresponsive on a restart -- and was previously discoverable only by
subtracting two unix timestamps out of the log by hand.
"""

from __future__ import annotations

import builtins
import re
import sys
from typing import Any

import unboundmodule

import pfb_unbound

# The line the package has always emitted, now carrying the two numbers.
_LOADED = re.compile(r"\[pfBlockerNG\]: init_standard script loaded in (\d+\.\d+)s \((\d+) entries\)$")
_PREFIX = "[pfBlockerNG]: init_standard script loaded"


def _init_capturing(tmp_path: Any, monkeypatch: Any) -> list[str]:
    """Drive the real init_standard off-appliance; return every log_info line."""
    (tmp_path / "pfb_unbound.ini").write_text("[MAIN]\npython_enable\t= false\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    # init_standard() replaces sys.stderr; register monkeypatch's auto-restore.
    monkeypatch.setattr(sys, "stderr", sys.stderr)
    # The autouse reset fixture omits the mod_*_e strings; init reads this one.
    pfb_unbound.pfb["mod_maxminddb_e"] = "stub"
    lines: list[str] = []
    monkeypatch.setattr(builtins, "log_info", lambda msg: lines.append(msg))
    try:
        assert pfb_unbound.init_standard(0, unboundmodule.module_env()) is True
    finally:
        pfb_unbound.deinit(0)
    return lines


def test_init_standard_reports_duration_and_entry_count(tmp_path: Any, monkeypatch: Any) -> None:
    """The one line emitted per build carries how long it took and how much it loaded."""
    loaded = [line for line in _init_capturing(tmp_path, monkeypatch) if _PREFIX in line]

    assert len(loaded) == 1, loaded
    match = _LOADED.match(loaded[0])
    assert match is not None, f"no duration/entry count in: {loaded[0]!r}"
    assert float(match.group(1)) >= 0.0
    assert int(match.group(2)) >= 0


def test_the_existing_prefix_survives_for_log_scrapers(tmp_path: Any, monkeypatch: Any) -> None:
    """Appended, never rewritten: anything matching the historical line still matches.

    The prefix has been in released logs for a long time and is the obvious thing
    for a user's grep or a support script to key on, so the numbers go after it.
    """
    loaded = [line for line in _init_capturing(tmp_path, monkeypatch) if line.startswith(_PREFIX)]

    assert len(loaded) == 1, loaded

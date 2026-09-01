"""issue #3058: init_standard reports the build duration and the loaded entry count.

The duration of a DNSBL build is user-visible -- it is the window in which unbound
is unresponsive on a restart -- and was previously discoverable only by subtracting
two unix timestamps out of the log by hand.
"""

from __future__ import annotations

import builtins
import json
import re
import sys
from pathlib import Path
from typing import Any

import unboundmodule

import pfb_unbound

# The line the package has always emitted, now carrying the two numbers.
_LOADED = re.compile(r"\[pfBlockerNG\]: init_standard script loaded in (\d+\.\d+)s \((\d+) entries\)$")
_PREFIX = "[pfBlockerNG]: init_standard script loaded"

# A feed of three plain domains, and two blacklisted TLDs. build() routes these to
# DIFFERENT structures -- the domains to dataDB, the blacklisted TLDs to zoneDB as
# synthetic DNSBL_TLD zone rows -- so len(dataDB) and len(dataDB)+len(zoneDB) are
# distinguishable. With both empty, or both equal, dropping either term from the
# sum would pass unnoticed.
_FEED_DOMAINS = ("one.example", "two.example", "three.example")
_BLACKLIST_TLDS = ("zz", "yy")


def _init_capturing(tmp_path: Path, monkeypatch: Any) -> list[str]:
    """Drive the real init_standard over a real manifest; return every log_info line."""
    (tmp_path / "feed.raw").write_text("\n".join(_FEED_DOMAINS) + "\n", encoding="utf-8")
    (tmp_path / "pfb_py_sources.json").write_text(
        json.dumps(
            {
                "version": 1,
                "config": {
                    "tld_wildcard_blacklist": list(_BLACKLIST_TLDS),
                    "tld_wildcard_exclusion": [],
                    "user_whitelist": [],
                },
                "feeds": [{"raw": "feed.raw", "feed": "F", "group": "G", "log_flag": "1"}],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "pfb_unbound.ini").write_text("[MAIN]\npython_enable\t= true\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    # init_standard() replaces sys.stderr; register monkeypatch's auto-restore.
    monkeypatch.setattr(sys, "stderr", sys.stderr)
    for _key in ("mod_maxminddb_e", "mod_threading_e", "mod_sqlite3_e"):
        pfb_unbound.pfb[_key] = "stub"
    pfb_unbound.pfb["mod_sqlite3"] = False
    pfb_unbound.pfb["mod_threading"] = False

    lines: list[str] = []
    monkeypatch.setattr(builtins, "log_info", lambda msg: lines.append(msg))
    try:
        assert pfb_unbound.init_standard(0, unboundmodule.module_env()) is True
    finally:
        pfb_unbound.deinit(0)
    return lines


def test_init_standard_reports_duration_and_the_exact_loaded_total(tmp_path: Path, monkeypatch: Any) -> None:
    """The one line emitted per build carries how long it took and how much it loaded.

    The count is asserted as an exact value against both structures, not merely as
    "some number": with a feed in dataDB and blacklisted TLDs in zoneDB, dropping
    either term from the sum changes the printed total.

    The historical prefix is asserted here too. It has been in released logs for a
    long time and is the obvious thing for a user's grep or a support script to key
    on, so the numbers are appended to it rather than replacing it.
    """
    lines = _init_capturing(tmp_path, monkeypatch)

    loaded = [line for line in lines if _PREFIX in line]
    assert len(loaded) == 1, lines
    assert loaded[0].startswith(_PREFIX), loaded[0]

    match = _LOADED.match(loaded[0])
    assert match is not None, f"no duration/entry count in: {loaded[0]!r}"
    assert float(match.group(1)) >= 0.0

    data_len = len(pfb_unbound.dataDB)
    zone_len = len(pfb_unbound.zoneDB)
    assert data_len, "fixture built no dataDB rows; the count assertion below would be vacuous"
    assert zone_len, "fixture built no zoneDB rows; dropping the zoneDB term would go unnoticed"
    assert data_len != zone_len, "equal halves make a swapped/duplicated term invisible"
    assert int(match.group(2)) == data_len + zone_len

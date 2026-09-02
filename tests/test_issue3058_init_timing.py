"""issue #3058: init_standard reports the build duration and the loaded entry count.

The duration of a DNSBL build is user-visible -- it is the window in which unbound
is unresponsive on a restart -- and was previously discoverable only by subtracting
two unix timestamps out of the log by hand.
"""

from __future__ import annotations

import base64
import builtins
import json
import re
import sys
from pathlib import Path
from typing import Any

import unboundmodule

import pfb_unbound

# The line the package has always emitted, now carrying the two numbers.
_LOADED = re.compile(
    r"\[pfBlockerNG\]: init_standard script loaded in (\d+\.\d+)s "
    r"\(dnsbl (\d+), regex (\d+), whitelist (\d+)\)$"
)
_PREFIX = "[pfBlockerNG]: init_standard script loaded"

# A feed of three plain domains, and two blacklisted TLDs. build() routes these to
# DIFFERENT structures -- the domains to dataDB, the blacklisted TLDs to zoneDB as
# synthetic DNSBL_TLD zone rows -- so len(dataDB) and len(dataDB)+len(zoneDB) are
# distinguishable. With both empty, or both equal, dropping either term from the
# sum would pass unnoticed.
_FEED_DOMAINS = ("one.example", "two.example", "three.example")
_BLACKLIST_TLDS = ("zz", "yy")
# Distinct non-zero sizes for every structure the line reports, so no term can be
# dropped, swapped or folded into another and still produce the same numbers.
_USER_REGEX = ("^adserve[0-9]*[-.]", "^trackpix[-.]")
# An ABP allow-regex row, so allowRegexDB is non-zero too -- otherwise the regex
# figure's two halves are indistinguishable and dropping one goes unnoticed.
_FEED_ALLOW_REGEX = ("@@/^keepme[0-9]*\\./",)
_WHITELIST = ("keep-one.example", "keep-two.example", "keep-three.example", "keep-four.example")


def _init_capturing(tmp_path: Path, monkeypatch: Any) -> list[str]:
    """Drive the real init_standard over a real manifest; return every log_info line."""
    (tmp_path / "feed.raw").write_text("\n".join(_FEED_DOMAINS + _FEED_ALLOW_REGEX) + "\n", encoding="utf-8")
    (tmp_path / "pfb_py_sources.json").write_text(
        json.dumps(
            {
                "version": 1,
                "config": {
                    "tld_wildcard_blacklist": list(_BLACKLIST_TLDS),
                    "tld_wildcard_exclusion": [],
                    "user_whitelist": list(_WHITELIST),
                },
                "feeds": [{"raw": "feed.raw", "feed": "F", "group": "G", "log_flag": "1"}],
            }
        ),
        encoding="utf-8",
    )
    regex_payload = base64.b64encode(
        "\n".join(f"{pattern} #R{i}" for i, pattern in enumerate(_USER_REGEX, 1)).encode("utf-8")
    ).decode("ascii")
    (tmp_path / "pfb_unbound.ini").write_text(
        f"[MAIN]\npython_enable\t= true\nregex_list = {regex_payload}\n", encoding="utf-8"
    )
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
    """The one line emitted per build carries how long it took and what it loaded.

    Each structure is named and asserted as an exact value, not summed into one
    "entries" figure: a single total claims to cover everything while omitting regex
    and the whitelist, which are loaded too and published separately (or not at all).

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
    assert len(pfb_unbound.regexDB), "fixture loaded no user regex; the regex term would be vacuous"
    assert len(pfb_unbound.whiteDB), "fixture loaded no whitelist; the whitelist term would be vacuous"
    assert len(pfb_unbound.allowRegexDB), "fixture loaded no allow-regex; half the regex term would be vacuous"

    # Each structure is asserted against its own live length, so no term can be
    # dropped, swapped or folded into another without changing the line.
    assert int(match.group(2)) == data_len + zone_len
    assert int(match.group(3)) == len(pfb_unbound.regexDB) + len(pfb_unbound.allowRegexDB)
    assert int(match.group(4)) == len(pfb_unbound.whiteDB)

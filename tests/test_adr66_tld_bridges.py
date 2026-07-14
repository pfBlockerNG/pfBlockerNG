"""ADR-66 Phase 1 -- TLD Allow / TLD Wildcard bridge oracle + rename seam.

WHY THIS FILE EXISTS
--------------------
ADR-66 renames ~90 identifiers naming Feature A ("TLD Allow", query-time,
``evaluate_domain``) and Feature B ("TLD Wildcard", build-time, ``classify()``)
across ``pfblockerng.inc`` + ``pfb_unbound.py``. Phases 2/3 must re-run the
frozen decision oracle (``tests/test_adr66_tld_naming_oracle.py``)
BYTE-IDENTICAL after each rename -- which means that file may hold NO
identifier from the ADR-66 SS2.1/SS2.2 rename maps.

THE SEAM: this module is the ADR-66 rename phases' ONLY editable surface for
the oracle's identifier dependencies. Phase 2 updates the Feature-A constants
(``TLD_ALLOW_*``); Phase 3 updates the Feature-B aliases
(``tld_wildcard_classify`` / ``load_tld_wildcard_master``) and
``MANIFEST_TLD_KEYS``. The frozen oracle imports these names and never spells
an old/new identifier itself.

This module also carries the two cross-language bridge round-trips (the
``.inc`` ini writer -> ``.py`` reader hop; the manifest writer -> reader hop)
and the Semantic-6 substring-over-reach guard -- editable alongside the seam
since they, too, must track a rename.
"""

from __future__ import annotations

import os
import sys
from typing import Any

import unboundmodule

import pfb_unbound

# --------------------------------------------------------------------------- #
# THE SEAM -- update ONLY these when the underlying identifier renames.
# --------------------------------------------------------------------------- #
TLD_ALLOW_ENABLE_KEY = "python_tld"  # Phase 2: cfg/pfb/ini enable-flag key
TLD_ALLOW_LIST_KEY = "python_tlds"  # Phase 2: cfg/pfb/ini allow-list key
TLD_WILDCARD_INI_KEY = "python_tld_wildcard"  # ADR "stays" row -- unchanged by P2 or P3
MANIFEST_TLD_KEYS = ("tld_blacklist", "tld_exclusion")  # Phase 3: manifest config + return-blob keys

tld_wildcard_classify = pfb_unbound.classify  # Phase 3 rename target
load_tld_wildcard_master = pfb_unbound._dnsbl_load_tld_master  # Phase 3 rename target


_SRC_DIR = os.path.join(os.path.dirname(__file__), "..", "src", "usr", "local", "pkg", "pfblockerng")
SRC_INC = os.path.join(_SRC_DIR, "pfblockerng.inc")
SRC_PY = os.path.join(_SRC_DIR, "pfb_unbound.py")


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# --------------------------------------------------------------------------- #
# C1/C2 -- .inc ini writer -> .py reader bridge.
# C1 (the .inc side: python_tld/python_tlds keys derived + emitted) is pinned
# structurally by tests/php/TldBridgeEmitTest.php (mirrors
# PythonTldWildcardIniEmitTest.php). C2 (here): the .py READER survives the
# hop -- driven through the real init_standard() (not a re-implementation of
# its MAIN-section read slice), so a forgotten production read goes red here.
# --------------------------------------------------------------------------- #
class TestIniBridgeRoundTrip:
    """C2 -- ini keys written under the seam names survive init_standard()'s
    real MAIN-section read and reach a real block decision."""

    def _init_from_ini(self, tmp_path: Any, monkeypatch: Any, ini_body: str) -> bool:
        (tmp_path / "pfb_unbound.ini").write_text(ini_body, encoding="utf-8")
        # init_standard() resets the ini path to the chroot-relative bare name;
        # CWD is the lookup root off-appliance.
        monkeypatch.chdir(tmp_path)
        # init_standard() replaces sys.stderr; register monkeypatch's auto-restore.
        monkeypatch.setattr(sys, "stderr", sys.stderr)
        # The autouse reset fixture omits the mod_*_e strings; the (test-forced)
        # False maxmind flag reads this one during init -- KeyError without it.
        pfb_unbound.pfb["mod_maxminddb_e"] = "stub"
        return pfb_unbound.init_standard(0, unboundmodule.module_env())

    def test_values_survive_the_writer_to_reader_hop(self, tmp_path: Any, monkeypatch: Any) -> None:
        ini_body = (
            "[MAIN]\n"
            "python_enable\t= false\n"
            f"{TLD_WILDCARD_INI_KEY}\t= true\n"
            f"{TLD_ALLOW_ENABLE_KEY}\t= true\n"
            f"{TLD_ALLOW_LIST_KEY}\t= com, net\n"
        )
        try:
            assert self._init_from_ini(tmp_path, monkeypatch, ini_body) is True
            assert pfb_unbound.pfb[TLD_WILDCARD_INI_KEY] is True
            assert pfb_unbound.pfb[TLD_ALLOW_ENABLE_KEY] is True
            assert pfb_unbound.pfb[TLD_ALLOW_LIST_KEY] == ["com", "net"]
        finally:
            pfb_unbound.deinit(0)

    def test_values_flow_into_a_real_block_decision(self, tmp_path: Any, monkeypatch: Any) -> None:
        ini_body = f"[MAIN]\npython_enable\t= false\n{TLD_ALLOW_ENABLE_KEY}\t= true\n{TLD_ALLOW_LIST_KEY}\t= com\n"
        try:
            assert self._init_from_ini(tmp_path, monkeypatch, ini_body) is True
            cfg: dict[str, Any] = {
                "python_blocking": False,
                "dataDB": False,
                "zoneDB": False,
                "regexDB": False,
                "whiteDB": False,
                "hstsDB": False,
                "dnsbl_ipv4": "10.10.10.1",
                "dnsbl_ipv6": "::1",
                TLD_ALLOW_ENABLE_KEY: pfb_unbound.pfb[TLD_ALLOW_ENABLE_KEY],
                TLD_ALLOW_LIST_KEY: pfb_unbound.pfb[TLD_ALLOW_LIST_KEY],
            }
            containers: dict[str, Any] = {
                "dataDB": {},
                "zoneDB": {},
                "whiteDB": {},
                "hstsDB": {},
                "regexDB": {},
                "feedGroupIndexDB": {},
            }
            # A tld NOT on the ini-loaded allow-list is a real TLD_Allow block --
            # proving the ini-derived value actually gates the decision, not just
            # that it parsed.
            dec = pfb_unbound.evaluate_domain("uuid-bridge.net", "uuid-bridge.net", "net", False, cfg, containers)
            assert dec.is_found is True
            assert dec.feed == "TLD_Allow"
            assert dec.group == "DNSBL_TLD_Allow"
        finally:
            pfb_unbound.deinit(0)


# --------------------------------------------------------------------------- #
# C3/C4 -- manifest writer -> reader bridge.
# C3 (the .inc side: pfb_unbound_python_sources() derives + emits
# config.tld_blacklist/tld_exclusion) is pinned by
# tests/php/TldBridgeEmitTest.php (mirrors UnboundPythonSourcesTest.php). C4
# (here): the .py READER (_dnsbl_config_from_manifest -- function name itself
# is NOT renamed) survives the hop.
# --------------------------------------------------------------------------- #
class TestManifestBridgeRoundTrip:
    """C4 -- manifest keys named by MANIFEST_TLD_KEYS survive
    ``_dnsbl_config_from_manifest``. The shipped-oracle ignore-gate for a
    stale manifest ``tld_master`` key is ALREADY pinned by
    ``tests/test_manifest_path_confinement.py`` (``TestTldWildcardOracleGating``,
    lines 98-130) -- not duplicated here.
    """

    def test_configured_values_pass_through(self, tmp_path: Any) -> None:
        manifest = {
            "config": {
                MANIFEST_TLD_KEYS[0]: ["evil-tld"],
                MANIFEST_TLD_KEYS[1]: ["good.example"],
            }
        }
        config = pfb_unbound._dnsbl_config_from_manifest(manifest, str(tmp_path))
        assert config[MANIFEST_TLD_KEYS[0]] == ["evil-tld"]
        assert config[MANIFEST_TLD_KEYS[1]] == ["good.example"]

    def test_absent_keys_default_empty(self, tmp_path: Any) -> None:
        config = pfb_unbound._dnsbl_config_from_manifest({"config": {}}, str(tmp_path))
        assert config[MANIFEST_TLD_KEYS[0]] == []
        assert config[MANIFEST_TLD_KEYS[1]] == []


# --------------------------------------------------------------------------- #
# G -- Semantic-6 guard: a substring rename must not swallow a sibling
# identifier that merely shares a prefix. Structural (grep-on-source) by
# necessity -- these are IDENTIFIERS, not runtime values, so no Python call
# can observe a rename; presence is checked as a plain substring (ADR-28 item
# 4: str-ops over regex) so the assertion fails the instant the token is
# gone, wherever it moved.
# --------------------------------------------------------------------------- #
class TestSemantic6SubstringGuard:
    def test_g1_dnsbl_tld_data_and_remove_survive_verbatim_in_inc(self) -> None:
        # ADR SS2.3 Semantic 6's own example pair: a `dnsbl_tld`-prefixed
        # rename must not catch these two path vars.
        inc = _read(SRC_INC)
        assert "$pfb['dnsbl_tld_data']" in inc
        assert "$pfb['dnsbl_tld_remove']" in inc

    def test_g2_classify_siblings_survive_verbatim_in_py(self) -> None:
        # ADR SS2.3 Semantic 6: a `classify`-prefixed rename must not catch
        # these three unrelated classifiers.
        py = _read(SRC_PY)
        assert "def classify_idn(" in py
        assert "def classify_label(" in py
        assert "def classify_upstream_block(" in py

    def test_g3_python_tld_wildcard_survives_verbatim_in_inc(self) -> None:
        # Planner addition: python_tld_wildcard contains python_tld as a
        # prefix -- a naive Phase-2 substring rename of python_tld would
        # corrupt Feature B's flag.
        assert "python_tld_wildcard" in _read(SRC_INC)

    def test_g4_python_tld_wildcard_survives_verbatim_in_py(self) -> None:
        assert "python_tld_wildcard" in _read(SRC_PY)

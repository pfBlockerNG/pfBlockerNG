"""ADR-61 Phase 4 -- Python-owned DNSBL parse-stage status file.

WHY THIS FILE EXISTS
--------------------
pfb_unbound.py's parse/load failures previously reached only py_error.log
(freetext, via sys.stderr.write). This phase adds a SEPARATE, Python-owned
structured status file (pfb_py_status.json) written/cleared alongside the
existing freetext writes -- never replacing them -- so DNSBL parse-stage
failures become enumerable the same way the PHP-side ledger's entries are.

Covers:
  * pfb_py_status_open / pfb_py_status_close -- the pure open/refresh/close
    library (mirrors PfbSyncStatusLedgerTest.php's coverage shape).
  * Fail-before/pass-after wiring at the 4 MANDATORY sites: _load_zone_db,
    _load_data_db, _load_whitelist_db, _load_hsts_db (extracted out of
    init_standard for testability, mirroring the existing
    _load_safesearch_db precedent).
  * Fail-before/pass-after wiring at the 2 STRONGLY-ENCOURAGED sites:
    _load_safesearch_db, and _load_ini_config (pfb_unbound.ini -- newly
    extracted out of init_standard this round, same rationale).
  * Fail-before/pass-after wiring at dnsbl_build_from_manifest (the ADR-06
    manifest path -- the PRIMARY parse path when a manifest is present).
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from typing import Any

import pfb_unbound


def _read_status_file(path: str) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)  # type: ignore[no-any-return]


class TestPfbPyStatusOpenClose:
    """Pure library coverage: new key, refresh-in-place, close, close-absent."""

    def setup_method(self) -> None:
        pfb_unbound.pfb["pfb_py_status"] = None

    def test_open_new_key_creates_one_entry(self, tmp_path: Any) -> None:
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

        pfb_unbound.pfb_py_status_open("dnsbl", "pfb_py_zone.txt", "parse", "boom", clock_fn=lambda: 1000)

        entries = _read_status_file(pfb_unbound.pfb["pfb_py_status"])
        assert len(entries) == 1
        assert entries[0]["facility"] == "dnsbl"
        assert entries[0]["item"] == "pfb_py_zone.txt"
        assert entries[0]["stage"] == "parse"
        assert entries[0]["message"] == "boom"
        assert entries[0]["first_seen"] == 1000
        assert entries[0]["last_seen"] == 1000

    def test_open_existing_key_refreshes_without_duplicating(self, tmp_path: Any) -> None:
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

        pfb_unbound.pfb_py_status_open("dnsbl", "pfb_py_zone.txt", "parse", "first", clock_fn=lambda: 1000)
        pfb_unbound.pfb_py_status_open("dnsbl", "pfb_py_zone.txt", "parse", "second", clock_fn=lambda: 2000)

        entries = _read_status_file(pfb_unbound.pfb["pfb_py_status"])
        assert len(entries) == 1, "reopening the SAME key must refresh, never duplicate"
        assert entries[0]["message"] == "second"
        assert entries[0]["first_seen"] == 1000, "first_seen must be preserved from the original open"
        assert entries[0]["last_seen"] == 2000

    def test_open_defaults_to_real_clock_when_none_injected(self, tmp_path: Any) -> None:
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")
        import time

        before = int(time.time())
        pfb_unbound.pfb_py_status_open("dnsbl", "x", "parse", "boom")
        after = int(time.time())

        entries = _read_status_file(pfb_unbound.pfb["pfb_py_status"])
        assert before <= entries[0]["first_seen"] <= after

    def test_close_existing_key_removes_entry(self, tmp_path: Any) -> None:
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")
        pfb_unbound.pfb_py_status_open("dnsbl", "pfb_py_zone.txt", "parse", "boom", clock_fn=lambda: 1000)
        # Before-state: the entry is genuinely open first, so close() closing it
        # is a real transition, not a no-op that happens to leave zero entries.
        assert len(_read_status_file(pfb_unbound.pfb["pfb_py_status"])) == 1

        pfb_unbound.pfb_py_status_close("dnsbl", "pfb_py_zone.txt", "parse")

        assert _read_status_file(pfb_unbound.pfb["pfb_py_status"]) == []

    def test_close_absent_key_is_safe_no_op(self, tmp_path: Any) -> None:
        status_path = str(tmp_path / "pfb_py_status.json")
        pfb_unbound.pfb["pfb_py_status"] = status_path

        pfb_unbound.pfb_py_status_close("dnsbl", "never_opened", "parse")

        assert not os.path.isfile(status_path), "close on an absent key must not write a file"

    def test_close_leaves_unrelated_key_intact(self, tmp_path: Any) -> None:
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")
        pfb_unbound.pfb_py_status_open("dnsbl", "pfb_py_zone.txt", "parse", "boom", clock_fn=lambda: 1000)

        pfb_unbound.pfb_py_status_close("dnsbl", "pfb_py_data.txt", "parse")

        entries = _read_status_file(pfb_unbound.pfb["pfb_py_status"])
        assert len(entries) == 1
        assert entries[0]["item"] == "pfb_py_zone.txt"


class TestPfbPyStatusReadDegradation:
    """Absent/corrupt/wrong-shape content all degrade to an empty read, never raise."""

    def setup_method(self) -> None:
        pfb_unbound.pfb["pfb_py_status"] = None

    def test_absent_path_key_reads_as_empty(self) -> None:
        # pfb["pfb_py_status"] unset entirely (e.g. a pre-ADR-61 python module).
        assert pfb_unbound._pfb_py_status_read_all() == []

    def test_absent_file_reads_as_empty(self, tmp_path: Any) -> None:
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "does_not_exist.json")
        assert pfb_unbound._pfb_py_status_read_all() == []

    def test_corrupt_non_json_reads_as_empty(self, tmp_path: Any) -> None:
        path = tmp_path / "pfb_py_status.json"
        path.write_text("this is not json{{{", encoding="utf-8")
        pfb_unbound.pfb["pfb_py_status"] = str(path)
        assert pfb_unbound._pfb_py_status_read_all() == []

    def test_wrong_top_level_type_reads_as_empty(self, tmp_path: Any) -> None:
        path = tmp_path / "pfb_py_status.json"
        path.write_text('{"facility": "dnsbl"}', encoding="utf-8")  # object, not a list
        pfb_unbound.pfb["pfb_py_status"] = str(path)
        assert pfb_unbound._pfb_py_status_read_all() == []

    def test_open_self_heals_a_corrupt_file(self, tmp_path: Any) -> None:
        # Fail-open extends to WRITES: opening a new entry against a corrupt
        # existing file must not raise -- it replaces the unreadable content.
        path = tmp_path / "pfb_py_status.json"
        path.write_text("{{{not json", encoding="utf-8")
        pfb_unbound.pfb["pfb_py_status"] = str(path)

        pfb_unbound.pfb_py_status_open("dnsbl", "x", "parse", "boom", clock_fn=lambda: 1000)

        entries = _read_status_file(str(path))
        assert len(entries) == 1
        assert entries[0]["item"] == "x"


def _new_feed_group_db() -> defaultdict[str, int]:
    return defaultdict(int)


class TestLoadZoneDbLedgerWiring:
    """_load_zone_db(): fail-before/pass-after against the ledger, plus the
    UNCHANGED freetext sys.stderr.write diagnostic."""

    def setup_method(self) -> None:
        pfb_unbound.zoneDB = defaultdict(list)
        pfb_unbound.feedGroupIndexDB = defaultdict(list)
        pfb_unbound.pfb["zoneDB"] = False
        pfb_unbound.pfb["python_blacklist"] = False

    def test_load_failure_opens_entry_and_keeps_freetext_log(
        self, tmp_path: Any, monkeypatch: Any, capsys: Any
    ) -> None:
        zone_path = tmp_path / "pfb_py_zone.txt"
        zone_path.write_text("a,b,c,d,e,f\n", encoding="utf-8")
        pfb_unbound.pfb["pfb_py_zone"] = str(zone_path)
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

        real_open = open

        def _boom_open(path: Any, *a: Any, **k: Any) -> Any:
            if str(path) == str(zone_path):
                raise OSError("simulated read failure")
            return real_open(path, *a, **k)

        monkeypatch.setattr("builtins.open", _boom_open)

        pfb_unbound._load_zone_db(_new_feed_group_db(), 0)

        err = capsys.readouterr().err
        assert str(zone_path) in err, "the existing freetext diagnostic must be unchanged"
        entries = _read_status_file(pfb_unbound.pfb["pfb_py_status"])
        assert len(entries) == 1
        assert entries[0] == {
            "facility": "dnsbl",
            "item": str(zone_path),
            "stage": "parse",
            "message": "Failed to load: {}: simulated read failure".format(zone_path),
            "first_seen": entries[0]["first_seen"],
            "last_seen": entries[0]["last_seen"],
        }

    def test_success_after_failure_clears_the_entry(self, tmp_path: Any, monkeypatch: Any) -> None:
        zone_path = tmp_path / "pfb_py_zone.txt"
        zone_path.write_text("a,b,c,d,e,f\n", encoding="utf-8")
        pfb_unbound.pfb["pfb_py_zone"] = str(zone_path)
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

        real_open = open

        def _boom_open(path: Any, *a: Any, **k: Any) -> Any:
            if str(path) == str(zone_path):
                raise OSError("simulated read failure")
            return real_open(path, *a, **k)

        monkeypatch.setattr("builtins.open", _boom_open)
        pfb_unbound._load_zone_db(_new_feed_group_db(), 0)
        # Before-state: the entry is genuinely open first.
        assert len(_read_status_file(pfb_unbound.pfb["pfb_py_status"])) == 1

        monkeypatch.undo()
        zone_path.write_text("evil.com,evil.com,0,1,FeedA,GroupA\n", encoding="utf-8")

        pfb_unbound._load_zone_db(_new_feed_group_db(), 0)

        assert _read_status_file(pfb_unbound.pfb["pfb_py_status"]) == []
        assert pfb_unbound.zoneDB["evil.com"]["log"] == "1"

    def test_no_file_present_leaves_ledger_untouched(self, tmp_path: Any) -> None:
        pfb_unbound.pfb["pfb_py_zone"] = str(tmp_path / "does_not_exist.txt")
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

        pfb_unbound._load_zone_db(_new_feed_group_db(), 0)

        assert not os.path.isfile(pfb_unbound.pfb["pfb_py_status"])


class TestLoadDataDbLedgerWiring:
    """_load_data_db(): same fail-before/pass-after shape as zone, different item key."""

    def setup_method(self) -> None:
        pfb_unbound.dataDB = defaultdict(list)
        pfb_unbound.feedGroupIndexDB = defaultdict(list)
        pfb_unbound.pfb["dataDB"] = False
        pfb_unbound.pfb["python_blacklist"] = False

    def test_load_failure_opens_entry(self, tmp_path: Any, monkeypatch: Any, capsys: Any) -> None:
        data_path = tmp_path / "pfb_py_data.txt"
        data_path.write_text("a,b,c,d,e,f\n", encoding="utf-8")
        pfb_unbound.pfb["pfb_py_data"] = str(data_path)
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

        real_open = open

        def _boom_open(path: Any, *a: Any, **k: Any) -> Any:
            if str(path) == str(data_path):
                raise OSError("simulated read failure")
            return real_open(path, *a, **k)

        monkeypatch.setattr("builtins.open", _boom_open)

        pfb_unbound._load_data_db(_new_feed_group_db(), 0)

        err = capsys.readouterr().err
        assert str(data_path) in err
        entries = _read_status_file(pfb_unbound.pfb["pfb_py_status"])
        assert len(entries) == 1
        assert entries[0]["item"] == str(data_path)
        assert entries[0]["stage"] == "parse"

    def test_success_after_failure_clears_the_entry(self, tmp_path: Any, monkeypatch: Any) -> None:
        data_path = tmp_path / "pfb_py_data.txt"
        data_path.write_text("a,b,c,d,e,f\n", encoding="utf-8")
        pfb_unbound.pfb["pfb_py_data"] = str(data_path)
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

        real_open = open

        def _boom_open(path: Any, *a: Any, **k: Any) -> Any:
            if str(path) == str(data_path):
                raise OSError("simulated read failure")
            return real_open(path, *a, **k)

        monkeypatch.setattr("builtins.open", _boom_open)
        pfb_unbound._load_data_db(_new_feed_group_db(), 0)
        assert len(_read_status_file(pfb_unbound.pfb["pfb_py_status"])) == 1

        monkeypatch.undo()
        data_path.write_text("evil.com,evil.com,0,1,FeedA,GroupA\n", encoding="utf-8")

        pfb_unbound._load_data_db(_new_feed_group_db(), 0)

        assert _read_status_file(pfb_unbound.pfb["pfb_py_status"]) == []
        assert pfb_unbound.dataDB["evil.com"]["log"] == "1"


class TestLoadWhitelistDbLedgerWiring:
    """_load_whitelist_db(): fail-before/pass-after."""

    def setup_method(self) -> None:
        pfb_unbound.whiteDB = defaultdict(str)
        pfb_unbound.pfb["whiteDB"] = False

    def test_load_failure_opens_entry(self, tmp_path: Any, monkeypatch: Any, capsys: Any) -> None:
        wl_path = tmp_path / "pfb_py_whitelist.txt"
        wl_path.write_text("a,1\n", encoding="utf-8")
        pfb_unbound.pfb["pfb_py_whitelist"] = str(wl_path)
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

        real_open = open

        def _boom_open(path: Any, *a: Any, **k: Any) -> Any:
            if str(path) == str(wl_path):
                raise OSError("simulated read failure")
            return real_open(path, *a, **k)

        monkeypatch.setattr("builtins.open", _boom_open)

        pfb_unbound._load_whitelist_db()

        err = capsys.readouterr().err
        assert str(wl_path) in err
        entries = _read_status_file(pfb_unbound.pfb["pfb_py_status"])
        assert len(entries) == 1
        assert entries[0]["item"] == str(wl_path)

    def test_success_after_failure_clears_the_entry(self, tmp_path: Any, monkeypatch: Any) -> None:
        wl_path = tmp_path / "pfb_py_whitelist.txt"
        wl_path.write_text("a,1\n", encoding="utf-8")
        pfb_unbound.pfb["pfb_py_whitelist"] = str(wl_path)
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

        real_open = open

        def _boom_open(path: Any, *a: Any, **k: Any) -> Any:
            if str(path) == str(wl_path):
                raise OSError("simulated read failure")
            return real_open(path, *a, **k)

        monkeypatch.setattr("builtins.open", _boom_open)
        pfb_unbound._load_whitelist_db()
        assert len(_read_status_file(pfb_unbound.pfb["pfb_py_status"])) == 1

        monkeypatch.undo()

        pfb_unbound._load_whitelist_db()

        assert _read_status_file(pfb_unbound.pfb["pfb_py_status"]) == []
        assert pfb_unbound.whiteDB["a"] == {"wildcard": True, "important": True}


class TestLoadHstsDbLedgerWiring:
    """_load_hsts_db(): fail-before/pass-after via a REAL open() failure (a
    production-realistic OSError -- e.g. permission denied / I/O error -- not
    a fault production could never hit)."""

    def setup_method(self) -> None:
        pfb_unbound.hstsDB = defaultdict(str)
        pfb_unbound.pfb["hstsDB"] = False
        pfb_unbound.pfb["python_hsts"] = True

    def test_load_failure_opens_entry(self, tmp_path: Any, monkeypatch: Any, capsys: Any) -> None:
        hsts_path = tmp_path / "pfb_py_hsts.txt"
        hsts_path.write_text("bad.example\n", encoding="utf-8")
        pfb_unbound.pfb["pfb_py_hsts"] = str(hsts_path)
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

        real_open = open

        def _boom_open(path: Any, *a: Any, **k: Any) -> Any:
            if str(path) == str(hsts_path):
                raise OSError("simulated read failure")
            return real_open(path, *a, **k)

        monkeypatch.setattr("builtins.open", _boom_open)

        pfb_unbound._load_hsts_db()

        err = capsys.readouterr().err
        assert str(hsts_path) in err
        entries = _read_status_file(pfb_unbound.pfb["pfb_py_status"])
        assert len(entries) == 1
        assert entries[0]["item"] == str(hsts_path)

    def test_success_after_failure_clears_the_entry(self, tmp_path: Any, monkeypatch: Any) -> None:
        hsts_path = tmp_path / "pfb_py_hsts.txt"
        hsts_path.write_text("bad.example\n", encoding="utf-8")
        pfb_unbound.pfb["pfb_py_hsts"] = str(hsts_path)
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

        real_open = open

        def _boom_open(path: Any, *a: Any, **k: Any) -> Any:
            if str(path) == str(hsts_path):
                raise OSError("simulated read failure")
            return real_open(path, *a, **k)

        monkeypatch.setattr("builtins.open", _boom_open)
        pfb_unbound._load_hsts_db()
        assert len(_read_status_file(pfb_unbound.pfb["pfb_py_status"])) == 1

        monkeypatch.undo()

        pfb_unbound._load_hsts_db()

        assert _read_status_file(pfb_unbound.pfb["pfb_py_status"]) == []
        assert "bad.example" in pfb_unbound.hstsDB

    def test_hsts_disabled_never_opens_an_entry(self, tmp_path: Any) -> None:
        # python_hsts OFF must never touch pfb_py_hsts, even if it exists.
        pfb_unbound.pfb["python_hsts"] = False
        hsts_path = tmp_path / "pfb_py_hsts.txt"
        hsts_path.write_text("bad.example\n", encoding="utf-8")
        pfb_unbound.pfb["pfb_py_hsts"] = str(hsts_path)
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

        pfb_unbound._load_hsts_db()

        assert not os.path.isfile(pfb_unbound.pfb["pfb_py_status"])


class TestLoadSafeSearchDbLedgerWiring:
    """_load_safesearch_db(): same fail-before/pass-after shape as the 4 mandatory
    sites, via a REAL open() OSError (not a monkeypatched csv.reader)."""

    def setup_method(self) -> None:
        pfb_unbound.safeSearchDB = defaultdict(list)
        pfb_unbound.pfb["safeSearchDB"] = False

    def test_load_failure_opens_entry_and_keeps_freetext_log(
        self, tmp_path: Any, monkeypatch: Any, capsys: Any
    ) -> None:
        ss_path = tmp_path / "pfb_py_ss.txt"
        ss_path.write_text("forcesafe.com,1.2.3.4,::1\n", encoding="utf-8")
        pfb_unbound.pfb["pfb_py_ss"] = str(ss_path)
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

        real_open = open

        def _boom_open(path: Any, *a: Any, **k: Any) -> Any:
            if str(path) == str(ss_path):
                raise OSError("simulated read failure")
            return real_open(path, *a, **k)

        monkeypatch.setattr("builtins.open", _boom_open)

        pfb_unbound._load_safesearch_db()

        err = capsys.readouterr().err
        assert str(ss_path) in err, "the existing freetext diagnostic must be unchanged"
        entries = _read_status_file(pfb_unbound.pfb["pfb_py_status"])
        assert len(entries) == 1
        assert entries[0]["item"] == str(ss_path)
        assert entries[0]["stage"] == "parse"

    def test_success_after_failure_clears_the_entry(self, tmp_path: Any, monkeypatch: Any) -> None:
        ss_path = tmp_path / "pfb_py_ss.txt"
        ss_path.write_text("forcesafe.com,1.2.3.4,::1\n", encoding="utf-8")
        pfb_unbound.pfb["pfb_py_ss"] = str(ss_path)
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

        real_open = open

        def _boom_open(path: Any, *a: Any, **k: Any) -> Any:
            if str(path) == str(ss_path):
                raise OSError("simulated read failure")
            return real_open(path, *a, **k)

        monkeypatch.setattr("builtins.open", _boom_open)
        pfb_unbound._load_safesearch_db()
        # Before-state: the entry is genuinely open first.
        assert len(_read_status_file(pfb_unbound.pfb["pfb_py_status"])) == 1

        monkeypatch.undo()

        pfb_unbound._load_safesearch_db()

        assert _read_status_file(pfb_unbound.pfb["pfb_py_status"]) == []
        assert pfb_unbound.safeSearchDB["forcesafe.com"] == {"A": "1.2.3.4", "AAAA": "::1"}

    def test_no_file_present_leaves_ledger_untouched(self, tmp_path: Any) -> None:
        pfb_unbound.pfb["pfb_py_ss"] = str(tmp_path / "does_not_exist.txt")
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

        pfb_unbound._load_safesearch_db()

        assert not os.path.isfile(pfb_unbound.pfb["pfb_py_status"])


class TestLoadIniConfigLedgerWiring:
    """_load_ini_config(): fail-before/pass-after via a REAL configparser parse
    failure. ConfigParser.read() swallows OSError internally (a permission-
    denied/missing file is silently skipped, never raised -- verified: an
    open()-monkeypatch fault would never reach the except branch), so the only
    production-realistic fault reaching it is a malformed ini file -- content
    before any section header raises a real MissingSectionHeaderError."""

    def test_missing_file_returns_none_and_never_opens_an_entry(self, tmp_path: Any) -> None:
        pfb_unbound.pfb["pfb_unbound.ini"] = str(tmp_path / "does_not_exist.ini")
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

        assert pfb_unbound._load_ini_config() is None
        assert not os.path.isfile(pfb_unbound.pfb["pfb_py_status"])

    def test_parse_failure_opens_entry_and_keeps_freetext_log(self, tmp_path: Any, capsys: Any) -> None:
        ini_path = tmp_path / "pfb_unbound.ini"
        ini_path.write_text("bogus_line_with_no_section_header\n", encoding="utf-8")
        pfb_unbound.pfb["pfb_unbound.ini"] = str(ini_path)
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

        config = pfb_unbound._load_ini_config()

        assert config is not None
        assert config.has_section("MAIN") is False, "a failed parse must fall through to an empty config"
        err = capsys.readouterr().err
        assert "Failed to load ini configuration" in err, "the existing freetext diagnostic must be unchanged"
        entries = _read_status_file(pfb_unbound.pfb["pfb_py_status"])
        assert len(entries) == 1
        assert entries[0]["facility"] == "dnsbl"
        assert entries[0]["item"] == str(ini_path)
        assert entries[0]["stage"] == "parse"

    def test_success_after_failure_clears_the_entry(self, tmp_path: Any) -> None:
        ini_path = tmp_path / "pfb_unbound.ini"
        ini_path.write_text("bogus_line_with_no_section_header\n", encoding="utf-8")
        pfb_unbound.pfb["pfb_unbound.ini"] = str(ini_path)
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

        pfb_unbound._load_ini_config()
        # Before-state: the entry is genuinely open first.
        assert len(_read_status_file(pfb_unbound.pfb["pfb_py_status"])) == 1

        ini_path.write_text("[MAIN]\npython_enable = true\n", encoding="utf-8")

        config = pfb_unbound._load_ini_config()

        assert config is not None
        assert config.has_section("MAIN") is True
        assert _read_status_file(pfb_unbound.pfb["pfb_py_status"]) == []


class TestDnsblBuildFromManifestLedgerWiring:
    """dnsbl_build_from_manifest(): the ADR-06 manifest path -- fail-before/
    pass-after for BOTH failure shapes (unparseable JSON, build() exception),
    funneled into the SAME (facility, item, stage) key."""

    def test_missing_manifest_never_opens_an_entry(self, tmp_path: Any) -> None:
        # The legitimate "not using the manifest path" case (init falls back to
        # the legacy CSV loaders) must NOT be treated as a parse failure.
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")
        manifest_path = str(tmp_path / "nope.json")

        assert pfb_unbound.dnsbl_build_from_manifest(manifest_path) is None
        assert not os.path.isfile(pfb_unbound.pfb["pfb_py_status"])

    def test_corrupt_json_opens_entry_and_keeps_freetext_log(self, tmp_path: Any, capsys: Any) -> None:
        manifest_path = tmp_path / "pfb_py_sources.json"
        manifest_path.write_text("{ this is not json", encoding="utf-8")
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

        result = pfb_unbound.dnsbl_build_from_manifest(str(manifest_path))

        assert result is None
        err = capsys.readouterr().err
        assert "Failed to load DNSBL manifest" in err
        assert str(manifest_path) in err
        entries = _read_status_file(pfb_unbound.pfb["pfb_py_status"])
        assert len(entries) == 1
        assert entries[0]["facility"] == "dnsbl"
        assert entries[0]["item"] == str(manifest_path)
        assert entries[0]["stage"] == "parse"

    def test_build_exception_opens_the_same_key(self, tmp_path: Any, monkeypatch: Any, capsys: Any) -> None:
        manifest_path = tmp_path / "pfb_py_sources.json"
        manifest_path.write_text(json.dumps({"version": 1, "config": {}, "feeds": []}), encoding="utf-8")
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

        def _boom(*a: Any, **k: Any) -> Any:
            raise RuntimeError("build boom")

        monkeypatch.setattr(pfb_unbound, "build", _boom)

        result = pfb_unbound.dnsbl_build_from_manifest(str(manifest_path))

        assert result is None
        err = capsys.readouterr().err
        assert "Failed to build DNSBL structures from raw" in err
        entries = _read_status_file(pfb_unbound.pfb["pfb_py_status"])
        assert len(entries) == 1
        assert entries[0]["item"] == str(manifest_path)

    def test_success_after_failure_clears_the_entry(self, tmp_path: Any) -> None:
        manifest_path = tmp_path / "pfb_py_sources.json"
        manifest_path.write_text("{ this is not json", encoding="utf-8")
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

        assert pfb_unbound.dnsbl_build_from_manifest(str(manifest_path)) is None
        # Before-state: the entry is genuinely open first.
        assert len(_read_status_file(pfb_unbound.pfb["pfb_py_status"])) == 1

        manifest_path.write_text(json.dumps({"version": 1, "config": {}, "feeds": []}), encoding="utf-8")

        result = pfb_unbound.dnsbl_build_from_manifest(str(manifest_path))

        assert result is not None
        assert _read_status_file(pfb_unbound.pfb["pfb_py_status"]) == []


class TestPfbPyStatusRegisteredPath:
    """The production path init_standard registers (chroot-relative bare name,
    exactly like pfb_py_reload -- Unbound's CWD is the chroot root)."""

    def test_source_default_is_bare_filename(self) -> None:
        import inspect

        src = inspect.getsource(pfb_unbound)
        assert 'pfb["pfb_py_status"] = "pfb_py_status.json"' in src

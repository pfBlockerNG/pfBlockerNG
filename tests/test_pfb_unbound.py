import builtins
import random
import re
import types
from collections import defaultdict
from configparser import ConfigParser
from typing import Any

import pytest

# Unbound injects these as module-level globals at runtime; conftest copies them
# from the unboundmodule stub onto builtins so pfb_unbound (which references them
# as bare globals) imports cleanly. Bind the same stub objects locally for the
# tests -- importing them from the stub (rather than builtins) also keeps them
# resolvable for the static type checkers.
from unboundmodule import (
    MODULE_ERROR,
    MODULE_EVENT_MODDONE,
    MODULE_EVENT_NEW,
    MODULE_FINISHED,
    MODULE_RESTART_NEXT,
    MODULE_WAIT_MODULE,
    PKT_AA,
    PKT_QR,
    PKT_RA,
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    RR_CLASS_IN,
    DNSMessage,
    sec_status_insecure,
    storeQueryInCache,
)

import pfb_unbound
from pfb_unbound import (
    _parse_ini_int,
    convert_ipv4,
    convert_ipv6,
    convert_other,
    evaluate_domain,
    evaluate_noaaaa,
    find_noaaaa_wildcard_parent,
    find_zone_match,
    hsts_check_domain,
    is_unknown,
    iter_domain_suffixes,
    parse_python_tlds,
    python_control_duration,
    resolve_feed_group,
    whitelist_check_domain,
)

# ---------------------------------------------------------------------------
# Test-only insert helpers
# Each helper writes into the relevant flat dict (the runtime matching structure)
# AND sets the enabling pfb[...] flag, so tests don't poke module internals
# directly. (ADR-01's trie was rejected and rolled back; see benchmarks/.)
# ---------------------------------------------------------------------------


def add_data(domain: str, log: str = "1", index: int = 0) -> None:
    pfb_unbound.dataDB[domain] = {"log": log, "index": index}
    pfb_unbound.pfb["dataDB"] = True


def add_zone(domain: str, log: str = "1", index: int = 0) -> None:
    pfb_unbound.zoneDB[domain] = {"log": log, "index": index}
    pfb_unbound.pfb["zoneDB"] = True


def add_white(domain: str, wildcard: bool = False) -> None:
    pfb_unbound.whiteDB[domain] = wildcard
    pfb_unbound.pfb["whiteDB"] = True


def add_noaaaa(domain: str, wildcard: bool = False) -> None:
    pfb_unbound.noAAAADB[domain] = wildcard
    pfb_unbound.pfb["noAAAADB"] = True


def add_hsts(domain: str) -> None:
    pfb_unbound.hstsDB[domain] = 0
    pfb_unbound.pfb["hstsDB"] = True


def set_feed_group(index: int, feed: str, group: str) -> None:
    pfb_unbound.feedGroupIndexDB[index] = {"feed": feed, "group": group}


def _is_block(dec: Any) -> bool:
    # A decisionDB entry's DNSBL axis is a block iff found and not whitelisted -- the
    # same predicate operate()/get_details_dnsbl use. dec is a composed Decision (or
    # None); the DNSBL verdict lives on dec.dnsbl (UNSET until the DNSBL stratum ran).
    if dec is None or dec.dnsbl is pfb_unbound.UNSET:
        return False
    return dec.dnsbl.is_found and not dec.dnsbl.in_whitelist


def _dnsbl_decision(**kw: Any) -> Any:
    # A bare DnsblDecision; kw overrides defaults (a not-found/allow verdict by default).
    fields: dict[str, Any] = {
        "is_found": False,
        "in_whitelist": False,
        "in_hsts": False,
        "null_blocking": True,
        "nxdomain": False,
        "log_type": "",
        "b_type": "",
        "p_type": "",
        "feed": "",
        "group": "",
        "b_eval": "",
    }
    fields.update(kw)
    return pfb_unbound.DnsblDecision(**fields)


def allow_decision() -> Any:
    # A composed Decision whose DNSBL axis is a not-found (allow) verdict -- seeds the
    # allow short-circuit path (the old excludeDB membership).
    return pfb_unbound.Decision(dnsbl=_dnsbl_decision())


def block_decision(**kw: Any) -> Any:
    # A composed Decision whose DNSBL axis is a block; kw overrides DnsblDecision fields.
    base = {"is_found": True, "log_type": "1", "b_type": "DNSBL", "p_type": "Python", "feed": "F", "group": "G"}
    base.update(kw)
    return pfb_unbound.Decision(dnsbl=_dnsbl_decision(**base))


class TestIsUnknown:
    def test_none_returns_unknown(self) -> None:
        assert is_unknown(None) == "Unknown"

    def test_empty_string_returns_unknown(self) -> None:
        assert is_unknown("") == "Unknown"

    def test_zero_returns_unknown(self) -> None:
        assert is_unknown(0) == "Unknown"

    def test_false_returns_unknown(self) -> None:
        assert is_unknown(False) == "Unknown"

    def test_nonempty_string_returned_as_is(self) -> None:
        assert is_unknown("example.com") == "example.com"

    def test_ip_string_returned_as_is(self) -> None:
        assert is_unknown("192.168.1.1") == "192.168.1.1"

    def test_string_zero_returned_as_is(self) -> None:
        # '0' is a non-empty string, so it is not unknown
        assert is_unknown("0") == "0"

    def test_nonzero_int_returned_as_is(self) -> None:
        assert is_unknown(42) == 42


class TestConvertIPv4:
    # x[2], x[3], x[4], x[5] are the four octets; x[0] and x[1] are ignored

    def test_standard_address(self) -> None:
        assert convert_ipv4(bytes([0, 0, 192, 168, 1, 1])) == "192.168.1.1"

    def test_loopback(self) -> None:
        assert convert_ipv4(bytes([0, 0, 127, 0, 0, 1])) == "127.0.0.1"

    def test_broadcast(self) -> None:
        assert convert_ipv4(bytes([0, 0, 255, 255, 255, 255])) == "255.255.255.255"

    def test_all_zeros(self) -> None:
        assert convert_ipv4(bytes([0, 0, 0, 0, 0, 0])) == "0.0.0.0"

    def test_empty_bytes_returns_unknown(self) -> None:
        assert convert_ipv4(b"") == "Unknown"

    def test_none_returns_unknown(self) -> None:
        assert convert_ipv4(None) == "Unknown"


class TestConvertIPv6:
    # x[2] through x[17] are the 16 address bytes; x[0] and x[1] are ignored

    def test_loopback(self) -> None:
        x = bytes([0, 0] + [0] * 15 + [1])
        assert convert_ipv6(x) == "0000:0000:0000:0000:0000:0000:0000:0001"

    def test_known_prefix(self) -> None:
        # 2001:0db8::1
        x = bytes([0, 0, 0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        assert convert_ipv6(x) == "2001:0db8:0000:0000:0000:0000:0000:0001"

    def test_all_zeros_not_unknown(self) -> None:
        # All-zeros IPv6 address is a valid (if unusual) value
        x = bytes([0, 0] + [0] * 16)
        assert convert_ipv6(x) == "0000:0000:0000:0000:0000:0000:0000:0000"

    def test_empty_bytes_returns_unknown(self) -> None:
        assert convert_ipv6(b"") == "Unknown"

    def test_none_returns_unknown(self) -> None:
        assert convert_ipv6(None) == "Unknown"


class TestConvertOther:
    # x[0:3] are ignored; x[3:] is the payload
    # Encoding rules:
    #   val == 0          → '|'
    #   1 <= val <= 12    → '.'
    #   val == 13         → stop
    #   val == 32         → ' '
    #   val == 58         → ':'
    #   val <= 33 or > 126 → skip
    #   else              → chr(val)
    # Leading/trailing '.' and '|' are stripped from the result.

    def test_printable_ascii(self) -> None:
        x = bytes([0, 0, 0, ord("A"), ord("B"), ord("C")])
        assert convert_other(x) == "ABC"

    def test_null_becomes_pipe(self) -> None:
        x = bytes([0, 0, 0, ord("A"), 0, ord("B")])
        assert convert_other(x) == "A|B"

    def test_low_byte_becomes_dot(self) -> None:
        x = bytes([0, 0, 0, ord("A"), 1, ord("B")])
        assert convert_other(x) == "A.B"

    def test_carriage_return_stops_processing(self) -> None:
        x = bytes([0, 0, 0, ord("A"), 13, ord("B")])
        assert convert_other(x) == "A"

    def test_space_preserved(self) -> None:
        x = bytes([0, 0, 0, ord("A"), 32, ord("B")])
        assert convert_other(x) == "A B"

    def test_colon_preserved(self) -> None:
        x = bytes([0, 0, 0, ord("h"), 58, ord("1")])
        assert convert_other(x) == "h:1"

    def test_control_chars_skipped(self) -> None:
        # val 14..31 (excluding 13) and 33 are skipped
        x = bytes([0, 0, 0, ord("A"), 14, ord("B")])
        assert convert_other(x) == "AB"

    def test_high_bytes_skipped(self) -> None:
        x = bytes([0, 0, 0, ord("A"), 200, ord("B")])
        assert convert_other(x) == "AB"

    def test_leading_trailing_stripped(self) -> None:
        # Result '.A.' → strip('.|') → 'A'
        x = bytes([0, 0, 0, ord("."), ord("A"), ord(".")])
        assert convert_other(x) == "A"

    def test_empty_payload_returns_unknown(self) -> None:
        # x[3:] is empty
        x = bytes([0, 0, 0])
        assert convert_other(x) == "Unknown"

    def test_empty_bytes_returns_unknown(self) -> None:
        assert convert_other(b"") == "Unknown"

    def test_none_returns_unknown(self) -> None:
        assert convert_other(None) == "Unknown"


class TestPythonControlDuration:
    def test_valid_duration(self) -> None:
        assert python_control_duration("60") == 60

    def test_minimum_valid(self) -> None:
        assert python_control_duration("1") == 1

    def test_maximum_valid(self) -> None:
        assert python_control_duration("3600") == 3600

    def test_zero_rejected(self) -> None:
        assert python_control_duration("0") is False

    def test_above_maximum_rejected(self) -> None:
        assert python_control_duration("3601") is False

    def test_non_numeric_rejected(self) -> None:
        assert python_control_duration("abc") is False

    def test_negative_rejected(self) -> None:
        # isnumeric() returns False for strings with a leading '-'
        assert python_control_duration("-1") is False

    def test_empty_string_rejected(self) -> None:
        assert python_control_duration("") is False

    def test_none_rejected(self) -> None:
        # AttributeError on None.isnumeric() is caught internally
        assert python_control_duration(None) is False


class TestGetQIpComm:
    def test_pfb_addr_key_present(self) -> None:
        kwargs = {"pfb_addr": "1.2.3.4"}
        assert pfb_unbound.get_q_ip_comm(kwargs) == "1.2.3.4"

    def test_fallback_to_repinfo_addr(self) -> None:
        kwargs = {"repinfo": types.SimpleNamespace(addr="5.6.7.8")}
        assert pfb_unbound.get_q_ip_comm(kwargs) == "5.6.7.8"

    def test_pfb_addr_takes_precedence(self) -> None:
        kwargs = {"pfb_addr": "1.2.3.4", "repinfo": types.SimpleNamespace(addr="5.6.7.8")}
        assert pfb_unbound.get_q_ip_comm(kwargs) == "1.2.3.4"

    def test_empty_kwargs_returns_unknown(self) -> None:
        assert pfb_unbound.get_q_ip_comm({}) == "Unknown"

    def test_none_kwargs_returns_unknown(self) -> None:
        assert pfb_unbound.get_q_ip_comm(None) == "Unknown"

    def test_repinfo_empty_addr_returns_unknown(self) -> None:
        kwargs = {"repinfo": types.SimpleNamespace(addr="")}
        assert pfb_unbound.get_q_ip_comm(kwargs) == "Unknown"


class TestLogEntry:
    def test_normal_write(self, tmp_path: Any) -> None:
        log = tmp_path / "dnsbl.log"
        pfb_unbound._log_entry_direct("a,b,c", str(log))
        assert log.read_text() == "a,b,c\n"

    def test_multiple_calls_accumulate(self, tmp_path: Any) -> None:
        log = tmp_path / "dnsbl.log"
        pfb_unbound._log_entry_direct("line1", str(log))
        pfb_unbound._log_entry_direct("line2", str(log))
        assert log.read_text() == "line1\nline2\n"

    def test_file_created_when_missing(self, tmp_path: Any) -> None:
        log = tmp_path / "sub" / "dnsbl.log"
        log.parent.mkdir()
        assert not log.exists()
        pfb_unbound._log_entry_direct("x", str(log))
        assert log.exists()


class TestDbSubsystem:
    """Persistent sqlite subsystem (ADR-03). With no DB worker running, pfb_db_enqueue
    falls back to synchronous execution, so these drive the same SQL the worker batches."""

    def _resolver(self, tmp_path: Any) -> str:
        db = str(tmp_path / "resolver.sqlite")
        pfb_unbound.pfb["pfb_py_resolver"] = db
        pfb_unbound.pfb["sqlite3_resolver_con"] = True
        return db

    def test_validate_creates_table_and_seed_row(self, tmp_path: Any) -> None:
        db = self._resolver(tmp_path)
        assert pfb_unbound.pfb_db_validate(pfb_unbound.DB_RESOLVER) is True
        import sqlite3

        con = sqlite3.connect(db)
        try:
            assert con.execute("SELECT totalqueries FROM resolver WHERE row = 0").fetchone()[0] == 0
        finally:
            con.close()

    def test_seed_is_idempotent_and_preserves_resolver_counter(self, tmp_path: Any) -> None:
        # The atomic row-0 seed (INSERT ... WHERE NOT EXISTS) must not reset or
        # duplicate the row on a later init/reconnect. Accumulate, re-create, assert.
        import sqlite3

        con = sqlite3.connect(str(tmp_path / "resolver.sqlite"))
        try:
            pfb_unbound._db_create(pfb_unbound.DB_RESOLVER, con.cursor())
            con.commit()
            assert con.execute("SELECT totalqueries FROM resolver").fetchall() == [(0,)]  # before: single seed at 0
            con.execute("UPDATE resolver SET totalqueries = totalqueries + 7 WHERE row = 0")
            con.commit()

            pfb_unbound._db_create(pfb_unbound.DB_RESOLVER, con.cursor())  # re-init
            con.commit()

            # Single row, counter preserved (not reset to 0, not duplicated).
            assert con.execute("SELECT totalqueries FROM resolver").fetchall() == [(7,)]
        finally:
            con.close()

    def test_resolver_counter_accumulates(self, tmp_path: Any) -> None:
        self._resolver(tmp_path)
        for _ in range(5):
            pfb_unbound.pfb_db_enqueue(("resolver",))
        con = pfb_unbound._db_conns[pfb_unbound.DB_RESOLVER]
        assert con.execute("SELECT totalqueries FROM resolver WHERE row = 0").fetchone()[0] == 5

    def test_resolver_counting_gated_by_flag(self, tmp_path: Any) -> None:
        db = str(tmp_path / "resolver.sqlite")
        pfb_unbound.pfb["pfb_py_resolver"] = db
        pfb_unbound.pfb["sqlite3_resolver_con"] = False
        pfb_unbound.pfb_db_enqueue(("resolver",))
        # Gated off -> no connection opened, nothing written.
        assert pfb_unbound.DB_RESOLVER not in pfb_unbound._db_conns

    def test_relative_increment_survives_concurrent_reset(self, tmp_path: Any) -> None:
        db = self._resolver(tmp_path)
        pfb_unbound.pfb_db_enqueue(("resolver",))
        pfb_unbound.pfb_db_enqueue(("resolver",))
        # Simulate a concurrent PHP pfBlockerNG_clearsqlite reset on a 2nd connection.
        import sqlite3

        other = sqlite3.connect(db)
        try:
            other.execute("UPDATE resolver SET totalqueries = 0 WHERE row = 0")
            other.commit()
        finally:
            other.close()
        pfb_unbound.pfb_db_enqueue(("resolver",))  # relative += 1, must not clobber the reset
        con = pfb_unbound._db_conns[pfb_unbound.DB_RESOLVER]
        assert con.execute("SELECT totalqueries FROM resolver WHERE row = 0").fetchone()[0] == 1

    def test_dnsbl_counter_per_group(self, tmp_path: Any) -> None:
        db = str(tmp_path / "dnsbl.sqlite")
        pfb_unbound.pfb["pfb_py_dnsbl"] = db
        pfb_unbound.pfb["sqlite3_dnsbl_con"] = True
        pfb_unbound.pfb_db_validate(pfb_unbound.DB_DNSBL)
        con = pfb_unbound._db_conns[pfb_unbound.DB_DNSBL]
        con.execute("INSERT INTO dnsbl (groupname, timestamp, entries, counter) VALUES ('G1', '', 0, 0)")
        con.execute("INSERT INTO dnsbl (groupname, timestamp, entries, counter) VALUES ('G2', '', 0, 0)")
        con.commit()
        for _ in range(3):
            pfb_unbound.pfb_db_enqueue(("dnsbl", "G1"))
        pfb_unbound.pfb_db_enqueue(("dnsbl", "G2"))
        assert con.execute("SELECT counter FROM dnsbl WHERE groupname = 'G1'").fetchone()[0] == 3
        assert con.execute("SELECT counter FROM dnsbl WHERE groupname = 'G2'").fetchone()[0] == 1

    def test_cache_inserts_preserve_order(self, tmp_path: Any) -> None:
        db = str(tmp_path / "cache.sqlite")
        pfb_unbound.pfb["pfb_py_cache"] = db
        for d in ["a.com", "b.com", "a.com"]:
            pfb_unbound.pfb_db_enqueue(("cache", ("DNSBL", d, "G", d, "feed")))
        con = pfb_unbound._db_conns[pfb_unbound.DB_CACHE]
        rows = [r[0] for r in con.execute("SELECT domain FROM dnsblcache").fetchall()]
        assert rows == ["a.com", "b.com", "a.com"]

    def test_reconnect_after_db_removed(self, tmp_path: Any) -> None:
        # pfb removes a DB file underneath us (init / write-error path); the next
        # write must transparently reconnect, re-create the table, and not lose
        # the subsequent op.
        import os as _os

        db = self._resolver(tmp_path)
        pfb_unbound.pfb_db_enqueue(("resolver",))
        pfb_unbound._db_close(pfb_unbound.DB_RESOLVER)
        if _os.path.isfile(db):
            _os.remove(db)
        pfb_unbound.pfb_db_enqueue(("resolver",))  # reconnect + re-create + write
        con = pfb_unbound._db_conns[pfb_unbound.DB_RESOLVER]
        assert con.execute("SELECT totalqueries FROM resolver WHERE row = 0").fetchone()[0] == 1

    def test_worker_batches_and_flushes(self, tmp_path: Any) -> None:
        import queue as _queue
        import threading as _threading

        self._resolver(tmp_path)
        pfb_unbound.pfb_db_queue = _queue.Queue(maxsize=100)
        pfb_unbound.pfb["db_worker"] = True
        th = _threading.Thread(target=pfb_unbound.pfb_db_worker, daemon=True)
        th.start()
        try:
            for _ in range(10):
                pfb_unbound.pfb_db_enqueue(("resolver",))
            pfb_unbound.pfb_db_queue.put(("stop",))
            th.join(timeout=5)
            assert not th.is_alive()
        finally:
            pfb_unbound.pfb["db_worker"] = False
        con = pfb_unbound._db_conns[pfb_unbound.DB_RESOLVER]
        assert con.execute("SELECT totalqueries FROM resolver WHERE row = 0").fetchone()[0] == 10


class TestDbConcurrencyAndPerf:
    """ADR-03 P3: validate WAL coexistence with a concurrent (PHP-style) writer and
    that the persistent connection actually eliminates per-call connects."""

    def test_wal_concurrent_writers_no_lock(self, tmp_path: Any) -> None:
        import sqlite3
        import threading

        db = str(tmp_path / "resolver.sqlite")
        pfb_unbound.pfb["pfb_py_resolver"] = db
        pfb_unbound.pfb["sqlite3_resolver_con"] = True
        pfb_unbound.pfb_db_validate(pfb_unbound.DB_RESOLVER)  # create table+row, sets WAL

        n = 100
        errors: list = []

        def py_side() -> None:
            try:
                for _ in range(n):
                    pfb_unbound.pfb_db_enqueue(("resolver",))  # sync -> persistent WAL conn
            except Exception as e:
                errors.append(e)

        def php_side() -> None:
            # Mimics pfBlockerNG_clearsqlite / widget: a separate connection writing
            # the same WAL db with a busy timeout, concurrently.
            try:
                con = sqlite3.connect(db, timeout=30)
                con.execute("PRAGMA busy_timeout=30000")
                for _ in range(n):
                    con.execute("UPDATE resolver SET totalqueries = totalqueries + 1 WHERE row = 0")
                    con.commit()
                con.close()
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=py_side)
        t2 = threading.Thread(target=php_side)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert errors == [], errors  # no 'database is locked'
        con = pfb_unbound._db_conns[pfb_unbound.DB_RESOLVER]
        # Every increment from both writers was applied (relative += 1, no clobber).
        assert con.execute("SELECT totalqueries FROM resolver WHERE row = 0").fetchone()[0] == 2 * n

    def test_persistent_connection_single_connect(self, tmp_path: Any, monkeypatch: Any) -> None:
        import sqlite3

        db = str(tmp_path / "resolver.sqlite")
        pfb_unbound.pfb["pfb_py_resolver"] = db
        pfb_unbound.pfb["sqlite3_resolver_con"] = True

        real_connect = sqlite3.connect
        count = {"n": 0}

        def counting_connect(*a: Any, **k: Any) -> Any:
            count["n"] += 1
            return real_connect(*a, **k)

        monkeypatch.setattr(pfb_unbound.sqlite3, "connect", counting_connect)
        for _ in range(20):
            pfb_unbound.pfb_db_enqueue(("resolver",))
        # Persistent: one connect for 20 writes (the per-call design connected 20 times).
        assert count["n"] == 1
        con = pfb_unbound._db_conns[pfb_unbound.DB_RESOLVER]
        assert con.execute("SELECT totalqueries FROM resolver WHERE row = 0").fetchone()[0] == 20


class TestLogging:
    """Persistent-handle logging pipeline (ADR-03 P2): QueueHandler -> QueueListener
    -> WatchedFileHandler. Lines must be byte-identical to the old open/append."""

    def _setup(self, tmp_path: Any, monkeypatch: Any) -> tuple[str, str]:
        paths = (
            str(tmp_path / "dnsbl.log"),
            str(tmp_path / "dns_reply.log"),
        )
        monkeypatch.setattr(pfb_unbound, "PFB_LOG_FILES", paths)
        pfb_unbound.pfb_setup_logging()
        return paths

    def test_pipeline_writes_exact_lines_to_correct_files(self, tmp_path: Any, monkeypatch: Any) -> None:
        dnsbl, dns_reply = self._setup(tmp_path, monkeypatch)
        pfb_unbound.pfb_log(dnsbl, "a.com,blocked")
        pfb_unbound.pfb_log(dnsbl, "b.com,100%match")  # literal % must not be formatted
        pfb_unbound.pfb_log(dns_reply, "r-1")
        pfb_unbound.pfb_log_listener.stop()  # flush + join
        pfb_unbound.pfb["log_listener"] = False
        with open(dnsbl) as f:
            assert f.read() == "a.com,blocked\nb.com,100%match\n"
        with open(dns_reply) as f:
            assert f.read() == "r-1\n"

    def test_fallback_direct_append_when_no_pipeline(self, tmp_path: Any) -> None:
        log = str(tmp_path / "x.log")
        pfb_unbound.pfb_log(log, "direct-1")
        pfb_unbound.pfb_log(log, "direct-2")
        with open(log) as f:
            assert f.read() == "direct-1\ndirect-2\n"

    def test_watched_handler_reopens_after_external_rotation(self, tmp_path: Any, monkeypatch: Any) -> None:
        import os

        dnsbl = self._setup(tmp_path, monkeypatch)[0]
        pfb_unbound.pfb_log(dnsbl, "before")
        pfb_unbound.pfb_log_queue.join()  # wait for the listener to write+flush
        os.rename(dnsbl, dnsbl + ".rotated")  # simulate the line-cap trim (mv)
        pfb_unbound.pfb_log(dnsbl, "after")
        pfb_unbound.pfb_log_queue.join()
        pfb_unbound.pfb_log_listener.stop()
        pfb_unbound.pfb["log_listener"] = False
        with open(dnsbl) as f:  # WatchedFileHandler reopened/recreated it
            assert f.read() == "after\n"
        with open(dnsbl + ".rotated") as f:
            assert "before" in f.read()


class TestGetRepTtl:
    def test_ttl_present(self) -> None:
        rep = types.SimpleNamespace(ttl=300)
        assert pfb_unbound.get_rep_ttl(rep) == "300"

    def test_none_rep_returns_unk(self) -> None:
        assert pfb_unbound.get_rep_ttl(None) == "Unk"

    def test_falsy_ttl_returns_unk(self) -> None:
        rep = types.SimpleNamespace(ttl=0)
        assert pfb_unbound.get_rep_ttl(rep) == "Unk"


class TestPythonControlThread:
    def test_active_thread_found(self) -> None:
        import threading

        stop = threading.Event()
        t = threading.Thread(name="pfb-test-thread", target=stop.wait, daemon=True)
        t.start()
        try:
            assert pfb_unbound.python_control_thread("pfb-test-thread") is True
        finally:
            stop.set()
            t.join()

    def test_unknown_thread_returns_false(self) -> None:
        assert pfb_unbound.python_control_thread("nonexistent-thread-xyz") is False


class TestGetQNameQstate:
    def test_primary_strips_trailing_dot(self) -> None:
        qstate = types.SimpleNamespace(qinfo=types.SimpleNamespace(qname_str="example.com."), return_msg=None)
        assert pfb_unbound.get_q_name_qstate(qstate) == "example.com"

    def test_fallback_to_return_msg(self) -> None:
        qstate = types.SimpleNamespace(
            qinfo=types.SimpleNamespace(qname_str="   "),
            return_msg=types.SimpleNamespace(qinfo=types.SimpleNamespace(qname_str="fallback.com.")),
        )
        assert pfb_unbound.get_q_name_qstate(qstate) == "fallback.com"

    def test_both_empty_returns_unknown(self) -> None:
        qstate = types.SimpleNamespace(qinfo=types.SimpleNamespace(qname_str=""), return_msg=None)
        assert pfb_unbound.get_q_name_qstate(qstate) == "Unknown"


class TestGetQNameQinfo:
    def test_present_stripped(self) -> None:
        qinfo = types.SimpleNamespace(qname_str="example.com.")
        assert pfb_unbound.get_q_name_qinfo(qinfo) == "example.com"

    def test_whitespace_returns_unknown(self) -> None:
        qinfo = types.SimpleNamespace(qname_str="   ")
        assert pfb_unbound.get_q_name_qinfo(qinfo) == "Unknown"

    def test_none_returns_unknown(self) -> None:
        assert pfb_unbound.get_q_name_qinfo(None) == "Unknown"


class TestGetQType:
    def test_prefers_qstate(self) -> None:
        qstate = types.SimpleNamespace(qinfo=types.SimpleNamespace(qtype_str="A"))
        qinfo = types.SimpleNamespace(qtype_str="AAAA")
        assert pfb_unbound.get_q_type(qstate, qinfo) == "A"

    def test_falls_back_to_qinfo(self) -> None:
        qstate = types.SimpleNamespace(qinfo=types.SimpleNamespace(qtype_str=""))
        qinfo = types.SimpleNamespace(qtype_str="AAAA")
        assert pfb_unbound.get_q_type(qstate, qinfo) == "AAAA"

    def test_both_none_returns_unknown(self) -> None:
        qstate = types.SimpleNamespace(qinfo=types.SimpleNamespace(qtype_str=""))
        qinfo = types.SimpleNamespace(qtype_str="")
        assert pfb_unbound.get_q_type(qstate, qinfo) == "Unknown"


class TestGetDetailsDnsblQtype:
    """Issue #44: DNSBL reporting must account for query type. The cached decision
    in decisionDB is qtype-independent, so q_type is folded into the consecutive-dedup
    signature and appended as the trailing dnsbl.log field. Two same-name blocks
    that differ only by record type (a client's A+AAAA pair) must each count, and
    the log must record which record type was blocked."""

    @staticmethod
    def _decision() -> Any:
        # A composed Decision whose DNSBL axis is a block (decisionDB values are
        # Decision, the DNSBL verdict lives on .dnsbl).
        return pfb_unbound.Decision(
            dnsbl=pfb_unbound.DnsblDecision(
                is_found=True,
                in_whitelist=False,
                in_hsts=False,
                null_blocking=False,
                nxdomain=False,
                log_type="1",
                b_type="DNSBL_Python",
                p_type="Python",
                feed="feedX",
                group="groupY",
                b_eval="blocked.com",
            )
        )

    def _qstate(self, qtype: str) -> types.SimpleNamespace:
        return types.SimpleNamespace(
            qinfo=types.SimpleNamespace(qname_str="blocked.com.", qtype_str=qtype),
            return_msg=None,
        )

    def _prep(self, monkeypatch: Any) -> list[tuple[str, str]]:
        monkeypatch.setitem(pfb_unbound.pfb, "python_nolog", False)
        monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_resolver_con", False)
        monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_dnsbl_con", False)
        monkeypatch.setattr(pfb_unbound, "decisionDB", {"blocked.com": self._decision()})
        lines: list[tuple[str, str]] = []
        monkeypatch.setattr(pfb_unbound, "pfb_log", lambda path, line: lines.append((path, line)))
        return lines

    def _block(self, qtype: str) -> None:
        pfb_unbound.get_details_dnsbl("dnsbl", None, self._qstate(qtype), None, {"pfb_addr": "1.2.3.4"})

    @staticmethod
    def _dnsbl_fields(lines: list[tuple[str, str]]) -> list[list[str]]:
        return [line.split(",") for path, line in lines if path.endswith("dnsbl.log")]

    def test_qtype_is_trailing_log_field(self, monkeypatch: Any) -> None:
        lines = self._prep(monkeypatch)
        self._block("AAAA")
        (fields,) = self._dnsbl_fields(lines)
        assert fields[0] == "DNSBL-python"
        assert fields[10] == "AAAA"  # query type appended after dupEntry

    def test_dual_stack_pair_both_count(self, monkeypatch: Any) -> None:
        # A then AAAA for the SAME name: the old qtype-blind dedup collapsed the
        # AAAA into a duplicate of the A. Now both are non-duplicate ("+").
        lines = self._prep(monkeypatch)
        self._block("A")
        self._block("AAAA")
        a_fields, aaaa_fields = self._dnsbl_fields(lines)
        assert (a_fields[9], a_fields[10]) == ("+", "A")
        assert (aaaa_fields[9], aaaa_fields[10]) == ("+", "AAAA")

    def test_same_qtype_repeat_is_duplicate(self, monkeypatch: Any) -> None:
        # A true consecutive repeat (same name AND same record type) still dedups.
        lines = self._prep(monkeypatch)
        self._block("AAAA")
        self._block("AAAA")
        first, second = self._dnsbl_fields(lines)
        assert first[9] == "+"
        assert second[9] == "-"

    def test_distinct_names_not_deduped(self, monkeypatch: Any) -> None:
        # Two different names blocked by the SAME list entry share an identical
        # DnsblDecision payload (e.g. two subdomains of one blocked zone -> same
        # b_eval). The consecutive-dedup signature must still tell them apart by
        # name, or the second is wrongly marked a duplicate (zone under-count). The
        # decision is the same object for both, so name is the only differentiator.
        monkeypatch.setitem(pfb_unbound.pfb, "python_nolog", False)
        monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_resolver_con", False)
        monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_dnsbl_con", False)
        dec = pfb_unbound.DnsblDecision(
            is_found=True,
            in_whitelist=False,
            in_hsts=False,
            null_blocking=False,
            nxdomain=False,
            log_type="1",
            b_type="TLD",
            p_type="Python",
            feed="feedX",
            group="groupY",
            b_eval="evil.com",
        )
        monkeypatch.setattr(
            pfb_unbound,
            "decisionDB",
            {"a.evil.com": pfb_unbound.Decision(dnsbl=dec), "b.evil.com": pfb_unbound.Decision(dnsbl=dec)},
        )
        lines: list[tuple[str, str]] = []
        monkeypatch.setattr(pfb_unbound, "pfb_log", lambda path, line: lines.append((path, line)))
        for name in ("a.evil.com.", "b.evil.com."):
            qstate = types.SimpleNamespace(
                qinfo=types.SimpleNamespace(qname_str=name, qtype_str="A"),
                return_msg=None,
            )
            pfb_unbound.get_details_dnsbl("dnsbl", None, qstate, None, {"pfb_addr": "1.2.3.4"})
        a_fields, b_fields = self._dnsbl_fields(lines)
        assert a_fields[9] == "+"
        assert b_fields[9] == "+"

    def test_mixed_case_query_is_attributed(self, monkeypatch: Any) -> None:
        # operate() stores decisionDB keys lowercased; a mixed-case query must still
        # be attributed here (lookup normalized), or the block is silently dropped from
        # dnsbl.log / the per-group counter (per-feed under-count).
        monkeypatch.setitem(pfb_unbound.pfb, "python_nolog", False)
        monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_resolver_con", False)
        monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_dnsbl_con", False)
        monkeypatch.setattr(pfb_unbound, "decisionDB", {"blocked.com": self._decision()})
        lines: list[tuple[str, str]] = []
        monkeypatch.setattr(pfb_unbound, "pfb_log", lambda path, line: lines.append((path, line)))
        qstate = types.SimpleNamespace(
            qinfo=types.SimpleNamespace(qname_str="Blocked.COM.", qtype_str="A"),
            return_msg=None,
        )
        pfb_unbound.get_details_dnsbl("dnsbl", None, qstate, None, {"pfb_addr": "1.2.3.4"})
        assert len(self._dnsbl_fields(lines)) == 1  # attributed despite mixed-case query


class TestGetDetailsDnsblNxdomain:
    """Issue #31: the per-event logger must treat the two NXDOMAIN variants like the
    two null variants -- "3" (NXDOMAIN logging) writes a dnsbl.log line, "4" (NXDOMAIN
    no logging) is silenced, exactly as "0"/"2" are for null. Same skip gate
    (log_type in ("2","4")), so the no-logging branch is shared and pinned here.
    """

    def _emit(self, monkeypatch: Any, log_type: str) -> list[tuple[str, str]]:
        # Given a memoized NXDOMAIN block for blocked.com with the given log flag
        monkeypatch.setitem(pfb_unbound.pfb, "python_nolog", False)
        monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_resolver_con", False)
        monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_dnsbl_con", False)
        dnsbl = _dnsbl_decision(
            is_found=True,
            nxdomain=True,
            log_type=log_type,
            b_type="DNSBL",
            p_type="Python",
            feed="F",
            group="G",
            b_eval="blocked.com",
        )
        monkeypatch.setattr(pfb_unbound, "decisionDB", {"blocked.com": pfb_unbound.Decision(dnsbl=dnsbl)})
        lines: list[tuple[str, str]] = []
        monkeypatch.setattr(pfb_unbound, "pfb_log", lambda path, line: lines.append((path, line)))
        qstate = types.SimpleNamespace(
            qinfo=types.SimpleNamespace(qname_str="blocked.com.", qtype_str="A"),
            return_msg=None,
        )
        # When the logger runs for that block
        pfb_unbound.get_details_dnsbl("dnsbl", None, qstate, None, {"pfb_addr": "1.2.3.4"})
        return lines

    def test_nxdomain_logging_writes_a_line(self, monkeypatch: Any) -> None:
        # Then the "3" variant records the block to dnsbl.log
        lines = self._emit(monkeypatch, "3")
        assert any(path.endswith("dnsbl.log") for path, _ in lines)

    def test_nxdomain_no_logging_is_silent(self, monkeypatch: Any) -> None:
        # Then the "4" variant writes nothing -- contrast the "3" case: same NXDOMAIN
        # block, logging flag flipped, proves the skip gate is a real branch.
        lines = self._emit(monkeypatch, "4")
        assert lines == []


class TestGetOType:
    def test_return_msg_rrset_branch(self) -> None:
        rk = types.SimpleNamespace(type_str="A")
        rrset = types.SimpleNamespace(rk=rk)
        qstate = types.SimpleNamespace(
            return_msg=types.SimpleNamespace(rep=types.SimpleNamespace(rrsets=[rrset])),
            qinfo=types.SimpleNamespace(qtype_str="AAAA"),
        )
        assert pfb_unbound.get_o_type(qstate, None) == "A"

    def test_qinfo_qtype_branch(self) -> None:
        qstate = types.SimpleNamespace(return_msg=None, qinfo=types.SimpleNamespace(qtype_str="AAAA"))
        assert pfb_unbound.get_o_type(qstate, None) == "AAAA"

    def test_rep_branch(self) -> None:
        rk = types.SimpleNamespace(type_str="TXT")
        rep = types.SimpleNamespace(rrsets=[types.SimpleNamespace(rk=rk)])
        qstate = types.SimpleNamespace(return_msg=None, qinfo=types.SimpleNamespace(qtype_str=""))
        assert pfb_unbound.get_o_type(qstate, rep) == "TXT"

    def test_no_qstate_returns_unknown(self) -> None:
        assert pfb_unbound.get_o_type(None, None) == "Unknown"


class TestGetTld:
    # Production Unbound's qname_list carries the trailing empty root label
    # (GetNameAsLabelList), so a real query for "sub.example.com." arrives as
    # ["sub", "example", "com", ""] and the TLD is qname_list[-2]. Modelling the
    # root label is what makes these assert the real TLD rather than the SLD (#706).
    def test_multilabel(self) -> None:
        qstate = types.SimpleNamespace(qinfo=types.SimpleNamespace(qname_list=["sub", "example", "com", ""]))
        assert pfb_unbound.get_tld(qstate) == "com"

    def test_tld_only_query(self) -> None:
        # A bare-TLD query "com." -> ["com", ""]; [-2] is the TLD itself.
        qstate = types.SimpleNamespace(qinfo=types.SimpleNamespace(qname_list=["com", ""]))
        assert pfb_unbound.get_tld(qstate) == "com"

    def test_root_query_returns_empty(self) -> None:
        # The root query "." -> [""] is the only len<=1 case in production; no TLD.
        qstate = types.SimpleNamespace(qinfo=types.SimpleNamespace(qname_list=[""]))
        assert pfb_unbound.get_tld(qstate) == ""

    def test_none_qstate_returns_empty(self) -> None:
        assert pfb_unbound.get_tld(None) == ""

    def test_invalid_utf8_qname_returns_empty_not_raise(self) -> None:
        # Regression (issue #328): a qname carrying an invalid UTF-8 byte (0xdc) makes
        # Unbound's qname_list access raise while decoding the labels. get_tld must
        # swallow it and return an empty TLD, not propagate and crash the Python module.
        class _RaisingQinfo:
            @property
            def qname_list(self) -> list[str]:
                raise UnicodeDecodeError("utf-8", b"\xdc", 0, 1, "invalid continuation byte")

        qstate = types.SimpleNamespace(qinfo=_RaisingQinfo())
        assert pfb_unbound.get_tld(qstate) == ""


class TestGetTldFromName:
    # The string counterpart of get_tld(): both must yield the real TLD -- the LAST
    # label of the name -- so a CNAME target's TLD-Allow/HSTS check runs against its
    # own TLD, not its second-level label. Pre-#706 this returned parts[-2] (the SLD),
    # so a target whose TLD was allowed was falsely blocked. (#706)
    def test_multilabel(self) -> None:
        assert pfb_unbound.get_tld_from_name("sub.example.com") == "com"
        assert pfb_unbound.get_tld_from_name("evil.net") == "net"

    def test_trailing_dot_ignored(self) -> None:
        assert pfb_unbound.get_tld_from_name("evil.net.") == "net"

    def test_single_label_returns_empty(self) -> None:
        assert pfb_unbound.get_tld_from_name("com") == ""
        assert pfb_unbound.get_tld_from_name("") == ""


class TestGetQIp:
    def test_first_node_with_addr_wins(self) -> None:
        node2 = types.SimpleNamespace(query_reply=types.SimpleNamespace(addr="2.2.2.2"), next=None)
        node1 = types.SimpleNamespace(query_reply=types.SimpleNamespace(addr="1.1.1.1"), next=node2)
        qstate = types.SimpleNamespace(mesh_info=types.SimpleNamespace(reply_list=node1))
        assert pfb_unbound.get_q_ip(qstate) == "1.1.1.1"

    def test_no_reply_list_returns_unknown(self) -> None:
        qstate = types.SimpleNamespace(mesh_info=types.SimpleNamespace(reply_list=None))
        assert pfb_unbound.get_q_ip(qstate) == "Unknown"


def make_qstate(
    qname: str = "example.com.",
    qtype: int = 1,
    q_ip: str | None = None,
    return_msg: Any = None,
    return_rcode: int = 0,
) -> types.SimpleNamespace:
    reply_list = None
    if q_ip is not None:
        reply_list = types.SimpleNamespace(query_reply=types.SimpleNamespace(addr=q_ip), next=None)
    qinfo = types.SimpleNamespace(
        qname_str=qname,
        qtype=qtype,
        qtype_str="",
        # Production Unbound's qname_list carries the trailing empty root label
        # (GetNameAsLabelList), so ["example", "com", ""] -- get_tld reads [-2].
        # Modelling that here is what makes get_tld return the real TLD, not the SLD.
        qname_list=qname.rstrip(".").split(".") + [""],
    )
    return types.SimpleNamespace(
        qinfo=qinfo,
        mesh_info=types.SimpleNamespace(reply_list=reply_list),
        return_msg=return_msg,
        return_rcode=return_rcode,
        ext_state={},
        no_cache_store=0,
    )


# RR_TYPE constants mirror the conftest stubs
RR_A = 1
RR_AAAA = 28
RR_TXT = 16


class TestSetReturnMsgStubFidelity:
    """DNSMessage.set_return_msg() must model real Unbound's createResponse
    (pythonmod/pythonmod_utils.c): replace ``return_msg`` wholesale, never
    mutate an existing one, and never stamp ``rep.security`` itself -- a
    caller that skips its own stamp must see an unchecked (not falsely
    secure) reply, or a real DNSSEC-failure class (issue #149) goes untested.
    """

    def test_leaves_security_unchecked(self) -> None:
        # Given a fresh DNSMessage, When set_return_msg() attaches it to a
        # qstate with no prior return_msg, Then rep.security stays at
        # sec_status_unchecked (0) -- createResponse never stamps security.
        qstate = make_qstate("example.com.")
        msg = DNSMessage("example.com.", RR_A, RR_CLASS_IN, PKT_QR)
        assert msg.set_return_msg(qstate) is True
        assert qstate.return_msg.rep.security == 0

    def test_replaces_existing_return_msg(self) -> None:
        # Given a qstate that already carries a return_msg (e.g. a resolved
        # CNAME chain), When set_return_msg() runs, Then it REPLACES the
        # object wholesale (a fresh rep/qinfo), never mutating the prior one
        # in place -- real createResponse always allocates a new reply. The
        # empty-rep assertions are faithful here because this message appends
        # no answer RRs (on-box, createResponse parses the answer section into
        # the fresh rep; the stub leaves rep empty as a documented
        # simplification -- answers ride DNSMessage.instances).
        sentinel = types.SimpleNamespace(
            rep=types.SimpleNamespace(security=0, an_numrrsets=2, rrsets=["sentinel"]),
            qinfo=types.SimpleNamespace(qname_str="old.example.com.", qname_list=[]),
        )
        qstate = make_qstate("example.com.", return_msg=sentinel)
        msg = DNSMessage("example.com.", RR_A, RR_CLASS_IN, PKT_QR)
        assert msg.set_return_msg(qstate) is True
        assert qstate.return_msg is not sentinel
        assert qstate.return_msg.rep is not sentinel.rep
        assert qstate.return_msg.rep.rrsets == []
        assert qstate.return_msg.rep.an_numrrsets == 0

    def test_rep_flags_carry_wire_format_bits(self) -> None:
        # Given a message built with runtime PKT_* constants, When
        # set_return_msg() attaches it, Then rep.flags carries the WIRE-format
        # header word (as real createResponse's packet parse yields), not the
        # runtime PKT_* vocabulary -- QR|RA maps to 0x8000|0x0080.
        qstate = make_qstate("example.com.")
        msg = DNSMessage("example.com.", RR_A, RR_CLASS_IN, PKT_QR | PKT_RA)
        assert msg.set_return_msg(qstate) is True
        assert qstate.return_msg.rep.flags == 0x8080

    def test_authoritative_set_only_when_pkt_aa_flagged(self) -> None:
        # Given PKT_AA is set on the message's flags, When set_return_msg()
        # attaches it, Then rep.authoritative is 1; given PKT_AA is absent,
        # Then it stays 0 -- both branches of the real Python wrapper's
        # post-success authoritative stamp.
        qstate_aa = make_qstate("example.com.")
        msg_aa = DNSMessage("example.com.", RR_A, RR_CLASS_IN, PKT_QR | PKT_AA)
        msg_aa.set_return_msg(qstate_aa)
        assert qstate_aa.return_msg.rep.authoritative == 1

        qstate_no_aa = make_qstate("example.com.")
        msg_no_aa = DNSMessage("example.com.", RR_A, RR_CLASS_IN, PKT_QR)
        msg_no_aa.set_return_msg(qstate_no_aa)
        assert qstate_no_aa.return_msg.rep.authoritative == 0


class TestStoreQueryInCacheStubFidelity:
    """storeQueryInCache() must model real Unbound's refusal to cache an
    authoritative reply (pythonmod_utils.c: PyErr_SetString(ValueError,
    "Authoritative answer can't be stored") + return 0). Without it, a
    production path that cached a PKT_AA reply would stay green off-appliance
    while the real box fails the store (issue #747).
    """

    def test_refuses_authoritative_reply(self) -> None:
        # Given a reply marked authoritative (PKT_AA message), When it is
        # stored, Then the stub raises ValueError exactly like the pending
        # PyErr the real box surfaces -- never a silent success.
        qstate = make_qstate("example.com.")
        msg = DNSMessage("example.com.", RR_A, RR_CLASS_IN, PKT_QR | PKT_AA)
        assert msg.set_return_msg(qstate) is True
        assert qstate.return_msg.rep.authoritative == 1
        with pytest.raises(ValueError, match="Authoritative answer can't be stored"):
            storeQueryInCache(qstate, qstate.qinfo, qstate.return_msg.rep, 0)

    def test_stores_non_authoritative_reply(self) -> None:
        # Given a non-authoritative reply (no PKT_AA), When it is stored,
        # Then the store succeeds -- the refusal branch must not over-reach.
        qstate = make_qstate("example.com.")
        msg = DNSMessage("example.com.", RR_A, RR_CLASS_IN, PKT_QR)
        assert msg.set_return_msg(qstate) is True
        assert qstate.return_msg.rep.authoritative == 0
        assert storeQueryInCache(qstate, qstate.qinfo, qstate.return_msg.rep, 0) is True


class TestOperateNoAAAA:
    def test_exact_match_blocks(self, monkeypatch: Any) -> None:
        add_noaaaa("example.com", wildcard=False)
        qstate = make_qstate("example.com.", qtype=RR_AAAA)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED
        assert qstate.return_rcode == RCODE_NOERROR
        # The synthesized AAAA -> A reply is unsigned; it must be stamped
        # non-bogus or the validator SERVFAILs it (issue #149 class).
        assert qstate.return_msg.rep.security == 2

    def test_wildcard_blocks_subdomain_and_caches(self) -> None:
        add_noaaaa("example.com", wildcard=True)
        qstate = make_qstate("sub.example.com.", qtype=RR_AAAA)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED
        # The wildcard-path synthesized reply needs the same non-bogus stamp
        # as the exact-match one (issue #149 class).
        assert qstate.return_msg.rep.security == 2
        # The wildcard-parent hit is memoized as the child's noaaaa verdict on its
        # Decision, so a subsequent identical query short-circuits on the cache.
        assert pfb_unbound.decisionDB["sub.example.com"].noaaaa is True
        assert evaluate_noaaaa("sub.example.com", pfb_unbound.noAAAADB) is True
        # Fast-path is unchanged: a subsequent identical query still blocks,
        # and the memoized-verdict reply carries the stamp too.
        qstate2 = make_qstate("sub.example.com.", qtype=RR_AAAA)
        rcd2 = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate2, None)
        assert rcd2 is True
        assert qstate2.ext_state[0] == MODULE_FINISHED
        assert qstate2.return_msg.rep.security == 2

    def test_excluded_domain_not_blocked(self) -> None:
        add_noaaaa("example.com", wildcard=False)
        # A cached allow verdict (noaaaa False) short-circuits -- the old excludeAAAADB.
        pfb_unbound.decisionDB["example.com"] = pfb_unbound.Decision(noaaaa=False)
        qstate = make_qstate("example.com.", qtype=RR_AAAA)
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE

    def test_non_aaaa_skips_logic(self) -> None:
        add_noaaaa("example.com", wildcard=False)
        qstate = make_qstate("example.com.", qtype=RR_A)
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE

    def test_no_match_caches_allow(self) -> None:
        add_noaaaa("other.com", wildcard=True)
        qstate = make_qstate("example.com.", qtype=RR_AAAA)
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert pfb_unbound.decisionDB["example.com"].noaaaa is False
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE


class TestOperateDnsbl:
    def _enable(self, monkeypatch: Any) -> None:
        pfb_unbound.pfb["python_blacklist"] = True
        pfb_unbound.pfb["python_blocking"] = True
        monkeypatch.setattr(pfb_unbound, "pfb_log", lambda *a: None)
        monkeypatch.setattr(pfb_unbound, "pfb_db_enqueue", lambda *a: None)

    def test_data_lookup_blocks_with_dnsbl_ipv4(self, monkeypatch: Any) -> None:
        self._enable(monkeypatch)
        add_data("evil.com", log="1", index=0)
        set_feed_group(0, "TestFeed", "TestGroup")
        qstate = make_qstate("evil.com.", qtype=RR_A)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED
        assert qstate.return_rcode == RCODE_NOERROR
        answers = DNSMessage.instances[-1].answer
        assert any(pfb_unbound.pfb["dnsbl_ipv4"] in a for a in answers)

    def test_nxdomain_mode_returns_bare_nxdomain(self, monkeypatch: Any) -> None:
        # Issue #31. Scenario: a DNSBL hit in NXDOMAIN-logging mode ("3").
        #   Given evil.com on a feed whose Logging/Blocking mode is NXDOMAIN ("3")
        #   When operate() handles an A query
        #   Then it FINISHES with rcode NXDOMAIN, builds NO synthetic answer message,
        #        and the reply is left uncached (#43) -- contrast the VIP test above,
        #        which returns NOERROR + a dnsbl_ipv4 record.
        self._enable(monkeypatch)
        add_data("evil.com", log="3", index=0)
        set_feed_group(0, "TestFeed", "TestGroup")
        qstate = make_qstate("evil.com.", qtype=RR_A)
        assert qstate.no_cache_store == 0  # before-state: cacheable by default
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED
        assert qstate.return_rcode == RCODE_NXDOMAIN
        assert qstate.return_msg is None  # no A/AAAA reply synthesized
        assert DNSMessage.instances == []  # the VIP/null DNSMessage path was NOT taken
        assert qstate.no_cache_store == 1  # not cached, same as VIP/null blocks
        assert pfb_unbound.decisionDB["evil.com"].dnsbl.nxdomain is True

    def test_nxdomain_no_logging_mode_also_returns_nxdomain(self, monkeypatch: Any) -> None:
        # The "4" (no-logging) variant produces the IDENTICAL block SHAPE as "3"; only
        # the dnsbl.log line differs (covered in TestGetDetailsDnsblNxdomain). Pins that
        # the response shape is logging-independent.
        self._enable(monkeypatch)
        add_data("evil.com", log="4", index=0)
        set_feed_group(0, "TestFeed", "TestGroup")
        qstate = make_qstate("evil.com.", qtype=RR_A)
        assert qstate.no_cache_store == 0  # before-state: cacheable by default
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED
        # IDENTICAL shape to the "3" case: bare NXDOMAIN, no message, uncached, nxdomain.
        assert qstate.return_rcode == RCODE_NXDOMAIN
        assert qstate.return_msg is None
        assert DNSMessage.instances == []
        assert qstate.no_cache_store == 1
        assert pfb_unbound.decisionDB["evil.com"].dnsbl.nxdomain is True

    def test_block_sets_no_cache_store(self, monkeypatch: Any) -> None:
        # #43: the synthetic block reply must NOT be stored in Unbound's C message
        # cache. A cached block is served ahead of this module, so repeat queries
        # skip operate() -> the feed-attributed logger never runs (per-feed
        # under-count) and a removed name keeps serving the stale block until TTL.
        self._enable(monkeypatch)
        add_data("evil.com", log="1", index=0)
        set_feed_group(0, "TestFeed", "TestGroup")
        qstate = make_qstate("evil.com.", qtype=RR_A)
        assert qstate.no_cache_store == 0  # before-state: default is cacheable
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert qstate.ext_state[0] == MODULE_FINISHED
        assert qstate.no_cache_store == 1

        # The memoized re-block path (name already in decisionDB) must set it too --
        # that is the whole point: every blocked query, miss or memo, re-runs here.
        assert _is_block(pfb_unbound.decisionDB.get("evil.com"))
        qstate2 = make_qstate("evil.com.", qtype=RR_A)
        assert qstate2.no_cache_store == 0  # before-state
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate2, None)
        assert qstate2.ext_state[0] == MODULE_FINISHED
        assert qstate2.no_cache_store == 1

    def test_pass_through_leaves_cache_store_enabled(self, monkeypatch: Any) -> None:
        # A non-blocked name falls through to the resolver and MUST stay cacheable
        # -- no_cache_store is the block path's alone.
        self._enable(monkeypatch)
        add_data("evil.com", log="1", index=0)
        set_feed_group(0, "TestFeed", "TestGroup")
        qstate = make_qstate("good.com.", qtype=RR_A)
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE
        assert qstate.no_cache_store == 0

    def test_zone_lookup_matches_subdomain(self, monkeypatch: Any) -> None:
        self._enable(monkeypatch)
        add_zone("example.com", log="1", index=0)
        set_feed_group(0, "TestFeed", "TestGroup")
        qstate = make_qstate("sub.example.com.", qtype=RR_A)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED

    def test_whitelist_override_not_blocked(self, monkeypatch: Any) -> None:
        self._enable(monkeypatch)
        add_data("evil.com", log="1", index=0)
        set_feed_group(0, "TestFeed", "TestGroup")
        add_white("evil.com", wildcard=False)
        qstate = make_qstate("evil.com.", qtype=RR_A)
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE
        dec = pfb_unbound.decisionDB.get("evil.com")
        assert dec is not None and not _is_block(dec)  # whitelisted -> memoized as an allow

    def test_regex_block(self, monkeypatch: Any) -> None:
        self._enable(monkeypatch)
        pfb_unbound.pfb["regexDB"] = True
        pfb_unbound.regexDB["bad-pattern"] = re.compile(r"evil")
        qstate = make_qstate("evil-domain.com.", qtype=RR_A)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED
        entry = pfb_unbound.decisionDB.get("evil-domain.com")
        assert entry.dnsbl.group == "DNSBL_Regex"

    def test_allow_decision_short_circuit(self, monkeypatch: Any) -> None:
        # A cached allow verdict ("let it resolve") short-circuits the matcher -- the
        # unified-cache equivalent of the old excludeDB membership skip.
        self._enable(monkeypatch)
        add_data("evil.com", log="1", index=0)
        set_feed_group(0, "TestFeed", "TestGroup")
        pfb_unbound.decisionDB["evil.com"] = allow_decision()
        qstate = make_qstate("evil.com.", qtype=RR_A)
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE

    def test_block_decision_reuse_without_reeval(self, monkeypatch: Any) -> None:
        # A cached BLOCK verdict short-circuits the matcher: operate() blocks straight
        # from decisionDB without dataDB/evaluate_domain. The name is NOT on any list,
        # so if it blocks, the memo -- not re-evaluation -- did it.
        self._enable(monkeypatch)
        pfb_unbound.decisionDB["cached-block.com"] = block_decision(b_eval="cached-block.com")
        qstate = make_qstate("cached-block.com.", qtype=RR_A)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED
        answers = DNSMessage.instances[-1].answer
        assert any(a.startswith("cached-block.com. ") for a in answers)

    def test_group_policy_bypass(self, monkeypatch: Any) -> None:
        self._enable(monkeypatch)
        add_data("evil.com", log="1", index=0)
        set_feed_group(0, "TestFeed", "TestGroup")
        pfb_unbound.pfb["gpListDB"] = True
        pfb_unbound.gpListDB["1.2.3.4"] = 0
        qstate = make_qstate("evil.com.", qtype=RR_A, q_ip="1.2.3.4")
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE

    @staticmethod
    def _cname_reply(orig_qname: str = "orig.com.") -> types.SimpleNamespace:
        # A resolved answer carrying a CNAME chain: a CNAME rrset + an A rrset
        # (an_numrrsets > 1) -- the exact shape operate()'s CNAME walk reads. The
        # CNAME target string comes from convert_other(rr_data) (monkeypatched in the
        # tests to the blocked target). Mirrors a real "orig -> CNAME -> target -> A".
        cname_rrset = types.SimpleNamespace(
            rk=types.SimpleNamespace(type_str="CNAME"),
            entry=types.SimpleNamespace(data=types.SimpleNamespace(count=1, rr_data=[b"\x00"])),
        )
        a_rrset = types.SimpleNamespace(
            rk=types.SimpleNamespace(type_str="A"),
            entry=types.SimpleNamespace(data=types.SimpleNamespace(count=1, rr_data=[b"\x00"])),
        )
        return types.SimpleNamespace(
            rep=types.SimpleNamespace(security=0, an_numrrsets=2, rrsets=[a_rrset, cname_rrset]),
            qinfo=types.SimpleNamespace(qname_str=orig_qname, qname_list=orig_qname.rstrip(".").split(".")),
        )

    def test_cname_target_blocks_and_marks_original(self, monkeypatch: Any) -> None:
        # CNAME validation ON: domain A (orig.com) CNAMEs to a BLOCKED target B
        # (evil-cname.com, on the blocklist) -> A is blocked. The block is recorded
        # against the ORIGINAL name, the b_type gains the _CNAME suffix, and the reply
        # answer is built for the original name (operate() reassigns q_name =
        # q_name_original on a CNAME hit).
        self._enable(monkeypatch)
        pfb_unbound.pfb["python_cname"] = True
        monkeypatch.setattr(pfb_unbound, "convert_other", lambda b: "evil-cname.com")
        monkeypatch.setattr(pfb_unbound, "get_details_dnsbl", lambda *a, **k: None)
        add_data("evil-cname.com", log="1", index=0)
        set_feed_group(0, "F", "G")

        qstate = make_qstate("orig.com.", qtype=RR_A, return_msg=self._cname_reply("orig.com."))
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED

        entry = pfb_unbound.decisionDB.get("orig.com")
        assert entry is not None
        assert entry.dnsbl.b_type == "DNSBL_CNAME"
        # Block is keyed on the original name after the q_name reassignment,
        # not on the CNAME target itself.
        assert not _is_block(pfb_unbound.decisionDB.get("evil-cname.com"))
        answers = DNSMessage.instances[-1].answer
        assert any(a.startswith("orig.com. ") for a in answers)

    def test_cname_disabled_original_not_blocked(self, monkeypatch: Any) -> None:
        # CNAME validation OFF (the default): the SAME setup -- A (orig.com) CNAMEs to
        # the BLOCKED target B (evil-cname.com, still on the blocklist) -- but the
        # chain is NOT walked, so only A itself is validated, and A is not listed ->
        # A is NOT blocked. convert_other is monkeypatched to the blocked target, so
        # the ONLY reason A survives is python_cname=False (if the walk ran it WOULD
        # block). This is the with/without pair for test_cname_target_blocks_*.
        self._enable(monkeypatch)
        pfb_unbound.pfb["python_cname"] = False
        monkeypatch.setattr(pfb_unbound, "convert_other", lambda b: "evil-cname.com")
        add_data("evil-cname.com", log="1", index=0)  # B is on the blocklist
        set_feed_group(0, "F", "G")

        qstate = make_qstate("orig.com.", qtype=RR_A, return_msg=self._cname_reply("orig.com."))
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        # Not blocked -> passes through to the resolver (no block return_msg set).
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE
        assert not _is_block(pfb_unbound.decisionDB.get("orig.com"))

    def test_cname_target_blocked_when_queried_directly(self, monkeypatch: Any) -> None:
        # The ERRATA invariant: B (the CNAME target) is genuinely on the blocklist in
        # BOTH scenarios. A DIRECT query for B is blocked regardless of python_cname --
        # the with/without difference is ONLY whether A (which CNAMEs to B) is blocked.
        self._enable(monkeypatch)
        pfb_unbound.pfb["python_cname"] = False  # irrelevant for a direct (non-CNAME) query
        add_data("evil-cname.com", log="1", index=0)
        set_feed_group(0, "F", "G")
        qstate = make_qstate("evil-cname.com.", qtype=RR_A)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED  # B is blocked
        assert _is_block(pfb_unbound.decisionDB.get("evil-cname.com"))

    def test_cname_target_allowed_by_its_own_tld(self, monkeypatch: Any) -> None:
        # #706 red->green: operate() must derive the TLD-Allow tld from the CNAME TARGET
        # being evaluated (a name STRING) using its REAL TLD -- the last label -- not its
        # second-level label. TLD-Allow lists "com" and "net"; the original (orig.com,
        # TLD "com") passes, and its CNAME target (good.net, TLD "net") is ALSO allowed,
        # so the chain must NOT block. With the pre-fix bug get_tld_from_name("good.net")
        # returned the SLD "good", which is not in the allow-list, so the target was
        # falsely blocked. So this asserts the target RESOLVES: red pre-fix (blocked),
        # green post-fix (allowed).
        self._enable(monkeypatch)
        pfb_unbound.pfb["python_cname"] = True
        pfb_unbound.pfb["python_tld"] = True
        pfb_unbound.pfb["python_tlds"] = ["com", "net"]
        monkeypatch.setattr(pfb_unbound, "convert_other", lambda b: "good.net")
        qstate = make_qstate("orig.com.", qtype=RR_A, return_msg=self._cname_reply("orig.com."))
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        # Neither the original nor its target is blocked -> passes to the resolver.
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE
        assert not _is_block(pfb_unbound.decisionDB.get("orig.com"))

    def test_cname_target_blocked_by_its_own_tld(self, monkeypatch: Any) -> None:
        # The paired block branch: TLD-Allow lists ONLY "com", so the original (orig.com)
        # passes but its CNAME target (good.net, TLD "net") is NOT allowed -> the chain
        # blocks, keyed on the original, via the target's own TLD. Together with the test
        # above this proves the TLD-Allow check on the target is real and branches on the
        # target's TLD, not an always-pass or a check against the original.
        self._enable(monkeypatch)
        pfb_unbound.pfb["python_cname"] = True
        pfb_unbound.pfb["python_tld"] = True
        pfb_unbound.pfb["python_tlds"] = ["com"]
        monkeypatch.setattr(pfb_unbound, "convert_other", lambda b: "good.net")
        qstate = make_qstate("orig.com.", qtype=RR_A, return_msg=self._cname_reply("orig.com."))
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED  # blocked via the TARGET's TLD
        entry = pfb_unbound.decisionDB.get("orig.com")
        assert entry is not None
        assert entry.dnsbl.group == "DNSBL_TLD_Allow"

    def test_cname_repeat_short_circuits_without_chain(self, monkeypatch: Any) -> None:
        # The unified-cache CNAME fix: a CNAME-blocked name is keyed on the ORIGINAL in
        # decisionDB, so a later query short-circuits to a block WITHOUT a resolved chain
        # -- no re-resolution, no re-evaluation of the target. Pre-refactor the original
        # sat in excludeDB and could only re-block by re-resolving and re-walking.
        self._enable(monkeypatch)
        pfb_unbound.pfb["python_cname"] = True
        monkeypatch.setattr(pfb_unbound, "convert_other", lambda b: "evil-cname.com")
        add_data("evil-cname.com", log="1", index=0)
        set_feed_group(0, "F", "G")

        # First query carries the resolved CNAME chain -> blocks and memoizes orig.
        q1 = make_qstate("orig.com.", qtype=RR_A, return_msg=self._cname_reply("orig.com."))
        pfb_unbound.operate(0, MODULE_EVENT_NEW, q1, None)
        assert q1.ext_state[0] == MODULE_FINISHED
        assert _is_block(pfb_unbound.decisionDB.get("orig.com"))

        # Second query has NO resolved chain -- it still blocks, purely from
        # decisionDB[orig], with the answer built for the original name.
        q2 = make_qstate("orig.com.", qtype=RR_A, return_msg=None)
        pfb_unbound.operate(0, MODULE_EVENT_NEW, q2, None)
        assert q2.ext_state[0] == MODULE_FINISHED
        answers = DNSMessage.instances[-1].answer
        assert any(a.startswith("orig.com. ") for a in answers)

    def test_block_sets_return_msg_exactly_once(self, monkeypatch: Any) -> None:
        # The DNSBL block path previously called msg.set_return_msg(qstate)
        # twice (standalone + inside the guard); it must run exactly once.
        self._enable(monkeypatch)
        calls = {"n": 0}
        orig = DNSMessage.set_return_msg

        def counting(self: Any, qstate: Any) -> bool:
            calls["n"] += 1
            return orig(self, qstate)

        monkeypatch.setattr(DNSMessage, "set_return_msg", counting)
        add_data("evil.com", log="1", index=0)
        set_feed_group(0, "F", "G")
        qstate = make_qstate("evil.com.", qtype=RR_A)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED
        assert calls["n"] == 1
        # The synthesized DNSBL block reply is unsigned; it must be stamped
        # non-bogus or the validator SERVFAILs it (issue #149 class).
        assert qstate.return_msg.rep.security == 2

    def test_cname_unknown_sentinel_is_never_evaluated(self, monkeypatch: Any) -> None:
        # #714 FIX #3: convert_other() returns the is_unknown() decode-failure sentinel
        # "Unknown" (capital U) for a CNAME target it can't parse. The guard filtering it
        # out must compare BEFORE lowering -- lowering first turns "Unknown" into
        # "unknown", which never equals "Unknown", so the (pre-fix) guard was a no-op and
        # the bogus "unknown" string was appended to `validate` and DNSBL-evaluated.
        #
        # Prove it by putting "unknown" itself on the blocklist: pre-fix, the leaked
        # sentinel is evaluated, matches, and blocks the ORIGINAL query (chained through
        # decisionDB.get(q_name_original) reassignment); post-fix, the sentinel is
        # dropped before ever reaching the evaluated `validate` list, so the query
        # resolves clean and "unknown" is never memoized as a decided name.
        self._enable(monkeypatch)
        pfb_unbound.pfb["python_cname"] = True
        monkeypatch.setattr(pfb_unbound, "convert_other", lambda b: "Unknown")
        add_data("unknown", log="1", index=0)
        set_feed_group(0, "F", "G")

        qstate = make_qstate("orig.com.", qtype=RR_A, return_msg=self._cname_reply("orig.com."))
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)

        assert qstate.ext_state[0] == MODULE_WAIT_MODULE  # resolves clean, not blocked
        assert not _is_block(pfb_unbound.decisionDB.get("orig.com"))
        # The sentinel itself must never be memoized as an evaluated decision.
        assert pfb_unbound.decisionDB.get("unknown") is None


class TestOperateEvents:
    def test_moddone_logs_and_finishes(self) -> None:
        qstate = make_qstate("example.com.", qtype=RR_A)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_MODDONE, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED

    def test_unknown_event_returns_error(self) -> None:
        qstate = make_qstate("example.com.", qtype=RR_A)
        rcd = pfb_unbound.operate(0, 99, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_ERROR


class TestOperatePythonControlLegacy:
    """The deprecated DNS-TXT control channel (PFBL-03) is inert unless
    python_control_legacy is explicitly opted in, but when it IS, its
    synthesized TXT reply must go through the same DNSSEC-stamping discipline
    as every other set_return_msg() site (issue #149 class).
    """

    def test_disable_command_answers_txt_and_stamps_security(self) -> None:
        # Given the legacy control channel is enabled and the query comes from
        # loopback, When a valid "python_control.disable" TXT query arrives,
        # Then operate() synthesizes a TXT reply AND stamps rep.security
        # non-bogus -- an unstamped synthesized reply is SERVFAILed by the
        # validator.
        pfb_unbound.pfb["python_control_legacy"] = True
        pfb_unbound.pfb["python_control"] = True
        qstate = make_qstate("python_control.disable.", qtype=RR_TXT, q_ip="127.0.0.1")
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED
        assert qstate.return_rcode == RCODE_NOERROR
        assert any("IN TXT" in a for a in DNSMessage.instances[-1].answer)
        assert qstate.return_msg.rep.security == 2


class TestLoadSafeSearchDb:
    """_load_safesearch_db() -- extracted out of init_standard (#714 FIX #6) so the
    SafeSearch CSV load, and its failure diagnostic, are unit-testable."""

    def test_parses_3_and_5_column_rows(self, tmp_path: Any) -> None:
        # Behaviour-preserving: same 3-col (A/AAAA rewrite) and 5-col (CNAME redirect,
        # issue #149) row shapes init_standard always parsed.
        path = tmp_path / "pfb_py_ss.txt"
        path.write_text(
            "forcesafe.com,1.2.3.4,::1\ncname.com,cname,target.com,5.6.7.8,::2\n",
            encoding="utf-8",
        )
        pfb_unbound.pfb["pfb_py_ss"] = str(path)

        pfb_unbound._load_safesearch_db()

        assert pfb_unbound.safeSearchDB["forcesafe.com"] == {"A": "1.2.3.4", "AAAA": "::1"}
        assert pfb_unbound.safeSearchDB["cname.com"] == {
            "A": "cname",
            "AAAA": "target.com",
            "v4": "5.6.7.8",
            "v6": "::2",
        }
        assert pfb_unbound.pfb["safeSearchDB"] is True

    def test_load_failure_names_the_safesearch_file_not_the_zone_file(
        self, tmp_path: Any, monkeypatch: Any, capsys: Any
    ) -> None:
        # #714 FIX #6: the failure diagnostic must name pfb_py_ss (the SafeSearch
        # source that just failed to load), not pfb_py_zone -- a copy-paste leftover
        # from the neighbouring zone-list loader that pointed a real SafeSearch load
        # failure at the WRONG file. Force the parse to raise so the except path runs,
        # with pfb_py_zone set to a visibly different path (the wrong-file trap), and
        # assert the emitted message carries the right one.
        ss_path = tmp_path / "pfb_py_ss.txt"
        ss_path.write_text("forcesafe.com,1.2.3.4,::1\n", encoding="utf-8")
        pfb_unbound.pfb["pfb_py_ss"] = str(ss_path)
        pfb_unbound.pfb["pfb_py_zone"] = str(tmp_path / "pfb_py_zone.txt")

        def _boom(*a: Any, **k: Any) -> Any:
            raise RuntimeError("csv boom")

        monkeypatch.setattr(pfb_unbound.csv, "reader", _boom)

        pfb_unbound._load_safesearch_db()

        err = capsys.readouterr().err
        assert str(ss_path) in err
        assert str(pfb_unbound.pfb["pfb_py_zone"]) not in err


class TestSafeSearchEntry:
    """safesearch_entry() lookup + 'www.' fallback + memoization (issue #149)."""

    def test_exact_match_returns_entry(self) -> None:
        pfb_unbound.pfb["safeSearchDB"] = True
        pfb_unbound.safeSearchDB["forcesafe.com"] = {"A": "1.2.3.4", "AAAA": ""}
        assert pfb_unbound.safesearch_entry("forcesafe.com") == {"A": "1.2.3.4", "AAAA": ""}

    def test_www_fallback_matches_bare_entry(self) -> None:
        # A query for 'x.com' (no www) falls back to the 'www.x.com' entry.
        pfb_unbound.pfb["safeSearchDB"] = True
        pfb_unbound.safeSearchDB["www.x.com"] = {"A": "1.2.3.4", "AAAA": ""}
        assert pfb_unbound.safesearch_entry("x.com") == {"A": "1.2.3.4", "AAAA": ""}

    def test_no_match_memoizes_none(self) -> None:
        # A miss is memoized as None on the Decision so it is decided once.
        pfb_unbound.pfb["safeSearchDB"] = True
        assert pfb_unbound.safesearch_entry("nomatch.com") is None
        assert pfb_unbound.decisionDB.get("nomatch.com").safesearch is None


class TestSafeSearchAnswerHelpers:
    """The post-restart detectors used by the CNAME redirect (issue #149)."""

    @staticmethod
    def _reply(rrtypes: list[str]) -> types.SimpleNamespace:
        rrsets = [
            types.SimpleNamespace(
                rk=types.SimpleNamespace(type_str=t),
                entry=types.SimpleNamespace(data=types.SimpleNamespace(count=1, rr_data=[b"\x00"])),
            )
            for t in rrtypes
        ]
        return types.SimpleNamespace(
            return_msg=types.SimpleNamespace(rep=types.SimpleNamespace(an_numrrsets=len(rrsets), rrsets=rrsets))
        )

    def test_has_cname_to_true_when_target_matches(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(pfb_unbound, "convert_other", lambda b: "safe.duckduckgo.com")
        qstate = self._reply(["CNAME", "A"])
        assert pfb_unbound._ss_answer_has_cname_to(qstate, "safe.duckduckgo.com") is True

    def test_has_cname_to_false_for_other_target(self, monkeypatch: Any) -> None:
        # A genuine CNAME chain to some OTHER name is not our planted redirect.
        monkeypatch.setattr(pfb_unbound, "convert_other", lambda b: "cdn.example.net")
        qstate = self._reply(["CNAME"])
        assert pfb_unbound._ss_answer_has_cname_to(qstate, "safe.duckduckgo.com") is False

    def test_has_cname_to_false_when_no_return_msg(self) -> None:
        qstate = types.SimpleNamespace(return_msg=None)
        assert pfb_unbound._ss_answer_has_cname_to(qstate, "safe.duckduckgo.com") is False

    def test_has_address_true_with_a(self) -> None:
        assert pfb_unbound._ss_answer_has_address(self._reply(["CNAME", "A"])) is True

    def test_has_address_true_with_aaaa(self) -> None:
        assert pfb_unbound._ss_answer_has_address(self._reply(["CNAME", "AAAA"])) is True

    def test_has_address_false_bare_cname(self) -> None:
        # The chase produced only a bare CNAME -> no address -> #2 fallback territory.
        assert pfb_unbound._ss_answer_has_address(self._reply(["CNAME"])) is False


class TestSafeSearchCnameRedirect:
    """SafeSearch CNAME redirect state machine (issue #149): duckduckgo / pixabay.

    Scenario: redirect a CNAME-SafeSearch name to its safe variant.
      Background:
        Given SafeSearch is enabled
        And 'duckduckgo.com' is a CNAME entry -> 'safe.duckduckgo.com'
        And the entry carries baked #2-fallback IPs (v4 203.0.113.7 / v6 2001:db8::7)
      Unbound will not chase a module-handed CNAME (#976), so the redirect runs
      post-resolution (MODDONE) in two phases: phase 1 plants the CNAME in cache and
      restarts the iterator; phase 2 finalizes the chased answer (DNSSEC re-stamped),
      or, when the chase yields no address, answers from the baked fallback IP.
    """

    TARGET = "safe.duckduckgo.com"

    def _enable(self, *, v4: str = "203.0.113.7", v6: str = "2001:db8::7") -> None:
        pfb_unbound.pfb["safeSearchDB"] = True
        entry = {"A": "cname", "AAAA": self.TARGET}
        if v4 or v6:
            entry["v4"] = v4
            entry["v6"] = v6
        pfb_unbound.safeSearchDB["duckduckgo.com"] = entry

    @staticmethod
    def _spy_cache(monkeypatch: Any) -> dict[str, Any]:
        calls: dict[str, Any] = {"store": [], "invalidate": 0}
        monkeypatch.setattr(builtins, "storeQueryInCache", lambda qs, qi, rep, ref: calls["store"].append(ref))
        monkeypatch.setattr(
            builtins, "invalidateQueryInCache", lambda qs, qi: calls.update(invalidate=calls["invalidate"] + 1)
        )
        return calls

    @staticmethod
    def _reply(qname: str, *, cname: bool, has_a: bool) -> types.SimpleNamespace:
        # A resolved answer: optional CNAME rrset (its target read via convert_other,
        # monkeypatched to TARGET) and/or an A rrset (the chased address).
        rrsets = []
        if has_a:
            rrsets.append(
                types.SimpleNamespace(
                    rk=types.SimpleNamespace(type_str="A"),
                    entry=types.SimpleNamespace(data=types.SimpleNamespace(count=1, rr_data=[b"\x00"])),
                )
            )
        if cname:
            rrsets.append(
                types.SimpleNamespace(
                    rk=types.SimpleNamespace(type_str="CNAME"),
                    entry=types.SimpleNamespace(data=types.SimpleNamespace(count=1, rr_data=[b"\x00"])),
                )
            )
        return types.SimpleNamespace(
            rep=types.SimpleNamespace(security=0, an_numrrsets=len(rrsets), rrsets=rrsets),
            qinfo=types.SimpleNamespace(qname_str=qname, qname_list=qname.rstrip(".").split(".")),
        )

    def test_cname_deferred_in_new_pass(self) -> None:
        # Given a CNAME entry, When the query first arrives (NEW), Then no answer is
        # synthesized pre-resolution -- the name passes to the resolver (the redirect
        # is deferred to MODDONE). Contrast with test_a_entry_answered_in_new_pass.
        self._enable()
        qstate = make_qstate("duckduckgo.com.", qtype=RR_A)
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE
        assert DNSMessage.instances == []

    def test_a_entry_answered_in_new_pass(self) -> None:
        # The with/without pair: a plain A-rewrite SafeSearch entry IS answered in the
        # NEW pass (no resolution needed), proving the CNAME case is specifically the
        # one deferred above.
        pfb_unbound.pfb["safeSearchDB"] = True
        pfb_unbound.safeSearchDB["forcesafe.com"] = {"A": "1.2.3.4", "AAAA": ""}
        qstate = make_qstate("forcesafe.com.", qtype=RR_A)
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert qstate.ext_state[0] == MODULE_FINISHED
        assert any(a.startswith("forcesafe.com. ") and " A 1.2.3.4" in a for a in DNSMessage.instances[-1].answer)
        # The synthesized SafeSearch answer is unsigned; it must be stamped
        # non-bogus or the validator SERVFAILs it (issue #149 class).
        assert qstate.return_msg.rep.security == 2

    def test_phase1_plants_cname_and_restarts(self, monkeypatch: Any) -> None:
        # Phase 1 (When the resolved answer does not yet carry our CNAME): plant the
        # synthetic 'duckduckgo.com -> CNAME -> safe.duckduckgo.com' into the cache as a
        # REFERRAL and restart the iterator so it chases the target itself.
        self._enable()
        calls = self._spy_cache(monkeypatch)
        qstate = make_qstate("duckduckgo.com.", qtype=RR_A, return_msg=None)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_MODDONE, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_RESTART_NEXT
        assert qstate.no_cache_store == 1
        assert calls["store"] == [1]  # is_referral=1
        assert calls["invalidate"] == 1
        assert any("IN CNAME safe.duckduckgo.com" in a for a in DNSMessage.instances[-1].answer)

    def test_phase2_success_restamps_dnssec_and_finishes(self, monkeypatch: Any) -> None:
        # Phase 2 success (the AFTER of phase 1): the iterator chased our CNAME to an
        # address. Force rep.security to insecure (the synthesized hop is unsigned;
        # without this a signed original zone would go bogus -> SERVFAIL), re-cache as a
        # final answer (is_referral=0), and finish.
        self._enable()
        monkeypatch.setattr(pfb_unbound, "convert_other", lambda b: self.TARGET)
        calls = self._spy_cache(monkeypatch)
        qstate = make_qstate(
            "duckduckgo.com.", qtype=RR_A, return_msg=self._reply("duckduckgo.com.", cname=True, has_a=True)
        )
        # Given the chased answer is not yet marked (security 0 = unchecked)...
        assert qstate.return_msg.rep.security == 0
        rcd = pfb_unbound.operate(0, MODULE_EVENT_MODDONE, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED
        assert qstate.return_msg.rep.security == sec_status_insecure
        assert calls["store"] == [0]  # is_referral=0 (final answer)
        assert calls["invalidate"] == 1

    def test_phase2_baked_fallback_when_chase_has_no_address_a(self, monkeypatch: Any) -> None:
        # #2 fallback (When the chase yields only a bare CNAME, no address): answer the
        # A query from the baked v4 fallback IP.
        self._enable()
        monkeypatch.setattr(pfb_unbound, "convert_other", lambda b: self.TARGET)
        qstate = make_qstate(
            "duckduckgo.com.", qtype=RR_A, return_msg=self._reply("duckduckgo.com.", cname=True, has_a=False)
        )
        rcd = pfb_unbound.operate(0, MODULE_EVENT_MODDONE, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED
        assert any("IN A 203.0.113.7" in a for a in DNSMessage.instances[-1].answer)

    def test_phase2_baked_fallback_aaaa_uses_v6(self, monkeypatch: Any) -> None:
        # The AAAA leg of the baked fallback uses the v6 column.
        self._enable()
        monkeypatch.setattr(pfb_unbound, "convert_other", lambda b: self.TARGET)
        qstate = make_qstate(
            "duckduckgo.com.", qtype=RR_AAAA, return_msg=self._reply("duckduckgo.com.", cname=True, has_a=False)
        )
        pfb_unbound.operate(0, MODULE_EVENT_MODDONE, qstate, None)
        assert qstate.ext_state[0] == MODULE_FINISHED
        assert any("IN AAAA 2001:db8::7" in a for a in DNSMessage.instances[-1].answer)

    def test_phase2_no_address_no_baked_falls_through(self, monkeypatch: Any) -> None:
        # The without-baked side of the fallback pair: a CNAME entry with NO baked IPs
        # whose chase produced no address falls THROUGH the redirect (synthesizes
        # nothing) to the normal MODDONE logger. Proves the baked-IP branch is real,
        # not an always-answer path.
        self._enable(v4="", v6="")
        monkeypatch.setattr(pfb_unbound, "convert_other", lambda b: self.TARGET)
        monkeypatch.setattr(pfb_unbound, "get_details_reply", lambda *a, **k: None)
        qstate = make_qstate(
            "duckduckgo.com.", qtype=RR_A, return_msg=self._reply("duckduckgo.com.", cname=True, has_a=False)
        )
        pfb_unbound.operate(0, MODULE_EVENT_MODDONE, qstate, None)
        assert qstate.ext_state[0] == MODULE_FINISHED  # finished by the generic logger
        assert DNSMessage.instances == []  # redirect synthesized nothing

    def test_non_address_qtype_not_redirected(self, monkeypatch: Any) -> None:
        # A non-A/AAAA query (e.g. MX) for a CNAME-SafeSearch name is NOT redirected;
        # it falls through to the normal MODDONE logger.
        self._enable()
        monkeypatch.setattr(pfb_unbound, "get_details_reply", lambda *a, **k: None)
        qstate = make_qstate("duckduckgo.com.", qtype=RR_TXT, return_msg=None)
        assert (
            pfb_unbound.safesearch_cname_redirect(0, qstate, RR_TXT, pfb_unbound.safeSearchDB["duckduckgo.com"])
            is False
        )

    def test_non_safesearch_name_unaffected_at_moddone(self, monkeypatch: Any) -> None:
        # A name with no SafeSearch entry is never touched by the redirect at MODDONE.
        pfb_unbound.pfb["safeSearchDB"] = True
        monkeypatch.setattr(pfb_unbound, "get_details_reply", lambda *a, **k: None)
        qstate = make_qstate("normal.com.", qtype=RR_A, return_msg=None)
        pfb_unbound.operate(0, MODULE_EVENT_MODDONE, qstate, None)
        assert qstate.ext_state[0] == MODULE_FINISHED
        assert DNSMessage.instances == []


class TestGetDetailsReplyNoaaaa:
    """The reply-x gate in get_details_reply proceeds for an AAAA reply whose name is
    noAAAA-blocked -- exact OR via a wildcard parent. Stage 2 removed the noAAAADB
    query-time memo, so this gate uses ``evaluate_noaaaa`` (exact + wildcard) rather
    than a bare ``noAAAADB.get(name)``, which only saw exact (or memoized) names."""

    def _aaaa_qstate(self, qname: str) -> types.SimpleNamespace:
        qstate = make_qstate(qname, qtype=RR_AAAA)
        qstate.qinfo.qtype_str = "AAAA"  # get_o_type falls back to this when return_msg is None
        qstate.return_msg = None
        return qstate

    def test_reply_x_aaaa_exact_noaaaa_proceeds(self, monkeypatch: Any) -> None:
        calls = []
        monkeypatch.setattr(pfb_unbound, "pfb_db_enqueue", lambda *a, **k: calls.append(a))
        pfb_unbound.pfb["sqlite3_resolver_con"] = True
        add_noaaaa("blocked.example.com", wildcard=False)
        qstate = self._aaaa_qstate("blocked.example.com.")
        rcd = pfb_unbound.get_details_reply("reply-x", None, qstate, None, {"pfb_addr": "1.2.3.4"})
        assert rcd is True
        # Gate passed -> proceeds past the reply-x gate to the resolver counter.
        assert len(calls) == 1

    def test_reply_x_aaaa_without_noaaaa_short_circuits(self, monkeypatch: Any) -> None:
        calls = []
        monkeypatch.setattr(pfb_unbound, "pfb_db_enqueue", lambda *a, **k: calls.append(a))
        pfb_unbound.pfb["sqlite3_resolver_con"] = True
        qstate = self._aaaa_qstate("notblocked.example.com.")
        rcd = pfb_unbound.get_details_reply("reply-x", None, qstate, None, {"pfb_addr": "1.2.3.4"})
        assert rcd is True
        # Gate failed -> early return before the resolver counter fires.
        assert calls == []

    def test_reply_x_aaaa_wildcard_child_proceeds(self, monkeypatch: Any) -> None:
        # Stage 2: a wildcard-parent noAAAA child (not an exact entry) now passes the
        # gate via evaluate_noaaaa. Pre-Stage-2 the gate read noAAAADB.get(child), which
        # only saw the child once the (now-removed) query-time memo wrote it.
        calls: list[Any] = []
        assert calls == []  # before-state: no side effect yet
        monkeypatch.setattr(pfb_unbound, "pfb_db_enqueue", lambda *a, **k: calls.append(a))
        pfb_unbound.pfb["sqlite3_resolver_con"] = True
        add_noaaaa("example.com", wildcard=True)
        assert "sub.example.com" not in pfb_unbound.noAAAADB  # not exact -> gate must pass via wildcard
        qstate = self._aaaa_qstate("sub.example.com.")
        rcd = pfb_unbound.get_details_reply("reply-x", None, qstate, None, {"pfb_addr": "1.2.3.4"})
        assert rcd is True
        assert len(calls) == 1


class TestStage2UnifiedDecision:
    """Stage 2: one decisionDB[name] = Decision carries every axis (dnsbl / noaaaa /
    safesearch), each filled lazily and cached -- replacing excludeAAAADB / excludeSS
    and the noAAAADB query-time memo."""

    def _enable(self, monkeypatch: Any) -> None:
        pfb_unbound.pfb["python_blacklist"] = True
        pfb_unbound.pfb["python_blocking"] = True
        monkeypatch.setattr(pfb_unbound, "pfb_log", lambda *a: None)
        monkeypatch.setattr(pfb_unbound, "pfb_db_enqueue", lambda *a: None)

    def test_one_decision_accumulates_axes(self, monkeypatch: Any) -> None:
        # An AAAA query for a DNSBL-listed name that is noAAAA-allow + SafeSearch-no-match
        # leaves ONE decisionDB entry with all three axes filled -- the unification end
        # state (noaaaa False, safesearch None, dnsbl block).
        self._enable(monkeypatch)
        add_data("multi.com", log="1", index=0)
        set_feed_group(0, "F", "G")
        add_noaaaa("unrelated.com", wildcard=False)  # enables the noAAAA path; multi.com unlisted
        pfb_unbound.pfb["safeSearchDB"] = True  # enables the SafeSearch path; multi.com unlisted
        assert "multi.com" not in pfb_unbound.decisionDB  # before-state: no Decision yet
        qstate = make_qstate("multi.com.", qtype=RR_AAAA)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED  # DNSBL blocked
        dec = pfb_unbound.decisionDB["multi.com"]
        assert dec.noaaaa is False  # noAAAA allow, evaluated + cached
        assert dec.safesearch is None  # SafeSearch no-match, evaluated + cached
        assert _is_block(dec)  # DNSBL block

    def test_noaaaa_verdict_reused_without_reeval(self, monkeypatch: Any) -> None:
        # A cached noaaaa=True blocks an AAAA query straight from the Decision, with the
        # name NOT in the noAAAADB source -> the memo, not re-evaluation, did it.
        self._enable(monkeypatch)
        add_noaaaa("unrelated.com", wildcard=False)  # enable the path; x.com unlisted
        assert "x.com" not in pfb_unbound.noAAAADB  # absent from source -> only the cache can block
        pfb_unbound.decisionDB["x.com"] = pfb_unbound.Decision(noaaaa=True)
        qstate = make_qstate("x.com.", qtype=RR_AAAA)
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert qstate.ext_state[0] == MODULE_FINISHED

    def test_safesearch_verdict_reused_without_reeval(self, monkeypatch: Any) -> None:
        # A cached safesearch entry rewrites straight from the Decision, with the name
        # NOT in the safeSearchDB source -> the memo did it.
        self._enable(monkeypatch)
        pfb_unbound.pfb["safeSearchDB"] = True
        assert "x.com" not in pfb_unbound.safeSearchDB  # absent from source -> only the cache rewrites
        pfb_unbound.decisionDB["x.com"] = pfb_unbound.Decision(safesearch={"A": "1.2.3.4", "AAAA": ""})
        qstate = make_qstate("x.com.", qtype=RR_A)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED
        answers = DNSMessage.instances[-1].answer
        assert any("1.2.3.4" in a for a in answers)

    def test_operate_respects_decisiondb_cap(self, monkeypatch: Any) -> None:
        # decisionDB is the LRU; with cap 1, querying a second blocked name evicts the
        # first, so the cache never exceeds the configured cap.
        self._enable(monkeypatch)
        monkeypatch.setattr(pfb_unbound, "decisionDB", pfb_unbound._LruCache(1))
        add_data("one.com", log="1", index=0)
        set_feed_group(0, "F1", "G1")
        add_data("two.com", log="1", index=1)
        set_feed_group(1, "F2", "G2")
        assert len(pfb_unbound.decisionDB) == 0  # before-state
        pfb_unbound.operate(0, MODULE_EVENT_NEW, make_qstate("one.com.", qtype=RR_A), None)
        assert len(pfb_unbound.decisionDB) == 1
        pfb_unbound.operate(0, MODULE_EVENT_NEW, make_qstate("two.com.", qtype=RR_A), None)
        assert len(pfb_unbound.decisionDB) == 1  # capped; one.com (LRU) evicted
        assert "two.com" in pfb_unbound.decisionDB
        assert "one.com" not in pfb_unbound.decisionDB


class TestLruCache:
    def test_get_set_contains_len(self) -> None:
        c = pfb_unbound._LruCache(0)
        assert "a" not in c
        assert c.get("a") is None
        c["a"] = 1
        assert "a" in c and c["a"] == 1 and c.get("a") == 1 and len(c) == 1

    def test_unbounded_when_maxsize_zero(self) -> None:
        c = pfb_unbound._LruCache(0)
        for i in range(1000):
            c[str(i)] = i
        assert len(c) == 1000  # 0 = no eviction (pre-LRU behaviour)

    def test_evicts_lru_at_cap(self) -> None:
        c = pfb_unbound._LruCache(2)
        c["a"] = 1
        c["b"] = 2
        c["c"] = 3  # over cap -> evict the LRU ("a")
        assert "a" not in c and "b" in c and "c" in c and len(c) == 2

    def test_get_bumps_recency_keeps_hot(self) -> None:
        c = pfb_unbound._LruCache(2)
        c["a"] = 1
        c["b"] = 2
        assert c.get("a") == 1  # bump "a" -> MRU, so "b" becomes LRU
        c["c"] = 3
        assert "a" in c and "b" not in c and "c" in c

    def test_setitem_existing_bumps_recency(self) -> None:
        c = pfb_unbound._LruCache(2)
        c["a"] = 1
        c["b"] = 2
        c["a"] = 10  # update bumps "a" -> MRU
        c["c"] = 3
        assert c["a"] == 10 and "b" not in c and "c" in c

    def test_clear_and_delitem(self) -> None:
        c = pfb_unbound._LruCache(0)
        c["a"] = 1
        c["b"] = 2
        del c["a"]
        assert "a" not in c
        c.clear()
        assert len(c) == 0 and "b" not in c


# ---------------------------------------------------------------------------
# Oracle / property tests for pure domain-match helpers
# ---------------------------------------------------------------------------


class TestIterDomainSuffixes:
    def test_single_label(self) -> None:
        assert list(iter_domain_suffixes("com")) == ["com"]

    def test_two_labels(self) -> None:
        assert list(iter_domain_suffixes("example.com")) == ["example.com", "com"]

    def test_three_labels(self) -> None:
        assert list(iter_domain_suffixes("sub.example.com")) == ["sub.example.com", "example.com", "com"]

    def test_empty_string(self) -> None:
        # Empty string has no dots; yields one item (the empty string itself)
        assert list(iter_domain_suffixes("")) == [""]


class TestFindZoneMatch:
    def test_exact_self_match(self) -> None:
        zone_db = {"example.com": {"log": "1", "index": 0}}
        matched, entry = find_zone_match("example.com", zone_db)
        assert matched == "example.com"
        assert entry == {"log": "1", "index": 0}

    def test_subdomain_matches_parent_zone(self) -> None:
        zone_db = {"example.com": {"log": "1", "index": 0}}
        matched, entry = find_zone_match("sub.example.com", zone_db)
        assert matched == "example.com"
        assert entry is not None

    def test_deep_subdomain_matches(self) -> None:
        zone_db = {"example.com": {"log": "1", "index": 0}}
        matched, entry = find_zone_match("a.b.example.com", zone_db)
        assert matched == "example.com"

    def test_no_match_returns_none_none(self) -> None:
        zone_db = {"evil.com": {"log": "1", "index": 0}}
        matched, entry = find_zone_match("good.com", zone_db)
        assert matched is None
        assert entry is None

    def test_data_exact_not_wildcard(self) -> None:
        # dataDB uses exact only; simulate: zone_db contains 'evil.com'
        # but query is 'x.evil.com' — zone DOES match (wildcard incl. self),
        # while a separate exact-only check would not.
        # This test pins that find_zone_match IS the wildcard matcher.
        zone_db = {"evil.com": {"log": "1", "index": 0}}
        matched, _ = find_zone_match("x.evil.com", zone_db)
        assert matched == "evil.com"

    def test_matched_parent_string_correct(self) -> None:
        # b_eval = matched parent string; must be the zone key, not the query name
        zone_db = {"example.com": {"log": "1", "index": 0}}
        matched, _ = find_zone_match("deep.sub.example.com", zone_db)
        assert matched == "example.com"

    def test_most_specific_match_wins(self) -> None:
        # iter_domain_suffixes walks q_name → ... TLD, so first hit is most specific
        zone_db = {
            "sub.example.com": {"log": "1", "index": 1},
            "example.com": {"log": "1", "index": 2},
        }
        matched, entry = find_zone_match("sub.example.com", zone_db)
        assert matched == "sub.example.com"
        assert entry["index"] == 1


class TestWhitelistCheckDomain:
    def test_exact_match(self) -> None:
        white_db: dict = {"allowed.com": False}
        assert whitelist_check_domain("allowed.com", white_db, tld_seg=2) is True

    def test_no_match(self) -> None:
        white_db: dict = {"other.com": False}
        assert whitelist_check_domain("allowed.com", white_db, tld_seg=2) is False

    def test_www_strip(self) -> None:
        # "www.allowed.com" → strips "www." → checks "allowed.com"
        white_db: dict = {"allowed.com": False}
        assert whitelist_check_domain("www.allowed.com", white_db, tld_seg=2) is True

    def test_www_strip_not_triggered_for_non_www(self) -> None:
        white_db: dict = {"allowed.com": False}
        assert whitelist_check_domain("sub.allowed.com", white_db, tld_seg=2) is False

    def test_suffix_walk_at_tld_seg_boundary_matches(self) -> None:
        # "sub.evil.com": suffix walk starts at "evil.com" (x=2, tld_seg=2) → match
        white_db: dict = {"evil.com": True}
        assert whitelist_check_domain("sub.evil.com", white_db, tld_seg=2) is True

    def test_suffix_walk_below_tld_seg_does_not_match(self) -> None:
        # "evil.com": suffix walk starts at "com" (x=1, tld_seg=2) → 1 < 2 → no match
        white_db: dict = {"com": True}
        assert whitelist_check_domain("evil.com", white_db, tld_seg=2) is False

    def test_suffix_walk_with_high_tld_seg_blocks_intermediate(self) -> None:
        # "a.b.example.com" with tld_seg=3:
        #   suffix walk q starts at "b.example.com", x counts down from 3:
        #   x=3 >= 3 → check "b.example.com" (not in db)
        #   x=2 < 3 → skip "example.com"  (below tld_seg gate)
        white_db: dict = {"example.com": True}
        assert whitelist_check_domain("a.b.example.com", white_db, tld_seg=3) is False

    def test_suffix_walk_respects_tld_seg_allows_higher(self) -> None:
        # Same domain but entry is at "b.example.com" (x=3 >= 3) → match
        white_db: dict = {"b.example.com": True}
        assert whitelist_check_domain("a.b.example.com", white_db, tld_seg=3) is True


class TestFindNoaaaaWildcardParent:
    def test_exact_name_not_matched_by_wildcard_fn(self) -> None:
        # find_noaaaa_wildcard_parent starts from PARENT, so self is never checked
        noaaaa_db: dict = {"example.com": True}
        result = find_noaaaa_wildcard_parent("example.com", noaaaa_db)
        assert result is None

    def test_direct_parent_matched(self) -> None:
        noaaaa_db: dict = {"example.com": True}
        result = find_noaaaa_wildcard_parent("sub.example.com", noaaaa_db)
        assert result == "example.com"

    def test_grandparent_matched(self) -> None:
        noaaaa_db: dict = {"example.com": True}
        result = find_noaaaa_wildcard_parent("a.b.example.com", noaaaa_db)
        assert result == "example.com"

    def test_no_match_returns_none(self) -> None:
        noaaaa_db: dict = {"other.com": True}
        result = find_noaaaa_wildcard_parent("sub.example.com", noaaaa_db)
        assert result is None

    def test_wildcard_false_value_not_matched(self) -> None:
        # noaaaa_db.get(q) is truthy check; wildcard=False means value is False → not matched
        noaaaa_db: dict = {"example.com": False}
        result = find_noaaaa_wildcard_parent("sub.example.com", noaaaa_db)
        assert result is None

    def test_single_label_parent_not_checked(self) -> None:
        # "sub.com": parent = "com", but loop range(0, 0, -1) is empty → no check
        noaaaa_db: dict = {"com": True}
        result = find_noaaaa_wildcard_parent("sub.com", noaaaa_db)
        assert result is None


def _noaaaa_db(entries: dict[str, bool]) -> dict[str, bool]:
    """A {domain: wildcard} noAAAA dict (the runtime structure for noAAAA)."""
    return dict(entries)


class TestEvaluateNoaaaa:
    def test_exact_match_no_wildcard_flag(self) -> None:
        # wildcard=False → exact branch fires on presence (get(name) is not None)
        db = _noaaaa_db({"example.com": False})
        assert evaluate_noaaaa("example.com", db) is True

    def test_exact_match_wildcard_flag(self) -> None:
        db = _noaaaa_db({"example.com": True})
        assert evaluate_noaaaa("example.com", db) is True

    def test_wildcard_parent_matches_subdomain(self) -> None:
        db = _noaaaa_db({"example.com": True})
        assert evaluate_noaaaa("sub.example.com", db) is True

    def test_wildcard_false_does_not_match_subdomain(self) -> None:
        # wildcard=False → wildcard-parent branch skips it (truthy check)
        db = _noaaaa_db({"example.com": False})
        assert evaluate_noaaaa("sub.example.com", db) is False

    def test_no_match(self) -> None:
        db = _noaaaa_db({"other.com": True})
        assert evaluate_noaaaa("example.com", db) is False

    def test_self_not_matched_by_wildcard_branch(self) -> None:
        # wildcard branch is parent-only; exact branch handles self
        db = _noaaaa_db({"example.com": True})
        assert evaluate_noaaaa("example.com", db) is True


class TestHstsCheckDomain:
    def test_tld_in_hsts_tlds_returns_hsts_tld(self) -> None:
        hsts_db: dict = {}
        assert hsts_check_domain("example.app", hsts_db, ("app",), "app") == (True, "HSTS_TLD")

    def test_tld_not_in_hsts_tlds_falls_through(self) -> None:
        hsts_db: dict = {}
        result = hsts_check_domain("example.com", hsts_db, ("app",), "com")
        assert result == (False, "Python")

    def test_exact_domain_in_hsts_db(self) -> None:
        hsts_db: dict = {"example.com": 0}
        result = hsts_check_domain("example.com", hsts_db, (), "com")
        assert result == (True, "HSTS")

    def test_suffix_walk_hits_parent(self) -> None:
        # "sub.example.com" (2 dots): the walk checks "sub.example.com" (miss), steps
        # to "example.com" (hit) -- every parent suffix level is visited in order.
        hsts_db: dict = {"example.com": 0}
        result = hsts_check_domain("sub.example.com", hsts_db, (), "com")
        assert result == (True, "HSTS")

    def test_every_parent_suffix_is_checked_for_hsts(self) -> None:
        # issue #713: the walk used to stride by -2, skipping every OTHER parent
        # suffix level. For "a.b.c.d" (3 dots) the buggy walk checked only
        # "a.b.c.d" and "b.c.d" -- it never reached "c.d" -- so a name whose HSTS
        # parent is exactly "c.d" incorrectly fell through to ("Python") instead of
        # ("HSTS"), forcing a VIP block instead of NULL for that HSTS-preloaded
        # parent (wrong TLS cert on the block page). The corrected stride-1 walk
        # checks every level ("a.b.c.d", "b.c.d", "c.d", "d") and finds it.
        hsts_db: dict = {"c.d": 0}
        result = hsts_check_domain("a.b.c.d", hsts_db, (), "d")
        assert result == (True, "HSTS")

    def test_second_level_parent_suffix_matches(self) -> None:
        # The second suffix level checked ("b.c.d", one step up from the full name)
        # resolves to HSTS -- confirms the walk isn't only correct at the extremes.
        hsts_db: dict = {"b.c.d": 0}
        result = hsts_check_domain("a.b.c.d", hsts_db, (), "d")
        assert result == (True, "HSTS")

    def test_bare_tld_suffix_is_checked(self) -> None:
        # issue #713: the walk must reach the LAST level -- the bare TLD label itself.
        # The buggy stride-2 walk for this 4-label name stopped two levels short of
        # "d" (it only ever reached "b.c.d"), so a parent HSTS entry at the bare TLD
        # was never found. Confirms the loop count now covers every suffix down to
        # (and including) the TLD.
        hsts_db: dict = {"d": 0}
        result = hsts_check_domain("a.b.c.d", hsts_db, (), "d")
        assert result == (True, "HSTS")

    def test_no_match_returns_python(self) -> None:
        hsts_db: dict = {"other.com": 0}
        result = hsts_check_domain("example.com", hsts_db, (), "com")
        assert result == (False, "Python")


class TestParsePythonTlds:
    """issue #713: the MAIN-ini ``python_tlds`` value must parse to a CLEANED list so
    an empty/degenerate value is falsy -- the caller's guard (``python_tld and
    python_tlds``) then correctly skips enabling the TLD-Allow blacklist gate instead
    of force-enabling it (the old ``!= ""`` list-vs-str compare was always True)."""

    def test_empty_value_parses_to_empty_list(self) -> None:
        assert parse_python_tlds("") == []

    def test_whitespace_only_value_parses_to_empty_list(self) -> None:
        assert parse_python_tlds("   ") == []

    def test_populated_value_parses_and_strips_entries(self) -> None:
        assert parse_python_tlds("com, net ,org") == ["com", "net", "org"]

    def test_empty_parsed_list_does_not_enable_tld_blacklist(self) -> None:
        # Reproduces init_standard's guard verbatim: `if python_tld and python_tlds:`.
        # An empty/degenerate TLD-Allow value must NOT force python_blacklist on.
        python_tlds = parse_python_tlds("")
        python_tld = True
        assert bool(python_tld and python_tlds) is False

    def test_populated_parsed_list_enables_tld_blacklist(self) -> None:
        python_tlds = parse_python_tlds("com,net")
        python_tld = True
        assert bool(python_tld and python_tlds) is True


class TestParseIniInt:
    """issue #713: ``config.getint()`` raises ``ValueError`` on a non-integer ini
    value. init_standard's ``python_tld_seg``/``decisiondb_max`` reads called it
    UNGUARDED, so a malformed ini value crashed the whole Unbound Python module at
    init. ``_parse_ini_int`` guards it (mirrors the existing ``regex_warn_ms``/
    ``regex_evict_ms`` try/except-ValueError pattern) and reports failure via
    ``None`` instead of raising, so the caller keeps its current default."""

    def _config(self, value: str) -> ConfigParser:
        config = ConfigParser()
        config.read_string("[MAIN]\npython_tld_seg = {}\n".format(value))
        return config

    def test_malformed_value_returns_none_instead_of_raising(self) -> None:
        config = self._config("not-an-int")
        assert _parse_ini_int(config, "MAIN", "python_tld_seg") is None

    def test_well_formed_value_parses_to_int(self) -> None:
        config = self._config("3")
        assert _parse_ini_int(config, "MAIN", "python_tld_seg") == 3

    def test_default_is_preserved_when_parse_fails(self) -> None:
        # Mirrors init_standard's call-site guard: only overwrite the current default
        # when the parse actually succeeded.
        current_default = 2
        config = self._config("garbage")
        parsed = _parse_ini_int(config, "MAIN", "python_tld_seg")
        result = parsed if parsed is not None else current_default
        assert result == current_default

    def test_default_is_replaced_when_parse_succeeds(self) -> None:
        current_default = 2
        config = self._config("9")
        parsed = _parse_ini_int(config, "MAIN", "python_tld_seg")
        result = parsed if parsed is not None else current_default
        assert result == 9


class TestResolveFeedGroup:
    def test_hit_returns_feed_and_group(self) -> None:
        fgidb = {0: {"feed": "MyFeed", "group": "MyGroup"}}
        assert resolve_feed_group(0, fgidb) == ("MyFeed", "MyGroup")

    def test_miss_returns_unknown_unknown(self) -> None:
        fgidb: dict = {}
        assert resolve_feed_group(99, fgidb) == ("Unknown", "Unknown")

    def test_none_index_returns_unknown(self) -> None:
        fgidb = {0: {"feed": "F", "group": "G"}}
        assert resolve_feed_group(None, fgidb) == ("Unknown", "Unknown")


# ---------------------------------------------------------------------------
# Randomized property test for pure matchers
# Seeded for reproducibility.
# ---------------------------------------------------------------------------


class TestPureMatcherProperties:
    """Fuzz pure matchers against brute-force reference impls; seed=42."""

    SEED = 42
    LABELS = ["a", "bb", "cc", "example", "evil", "sub", "www", "foo", "bar", "xyz"]
    TLDS = ["com", "net", "org", "io"]
    N_ENTRIES = 30
    N_QUERIES = 60

    def _rand_domain(self, rng: random.Random, max_labels: int = 4) -> str:
        n = rng.randint(1, max_labels)
        parts = [rng.choice(self.LABELS) for _ in range(n - 1)] + [rng.choice(self.TLDS)]
        return ".".join(parts)

    def test_find_zone_match_vs_brute_force(self) -> None:
        rng = random.Random(self.SEED)
        zone_db: dict = {}
        entries = [self._rand_domain(rng) for _ in range(self.N_ENTRIES)]
        for d in entries:
            zone_db[d] = {"log": "1", "index": 0}

        def brute_zone(q: str) -> str | None:
            # Check every suffix from most-specific to least-specific
            parts = q.split(".")
            for i in range(len(parts)):
                suffix = ".".join(parts[i:])
                if suffix in zone_db:
                    return suffix
            return None

        for _ in range(self.N_QUERIES):
            q = self._rand_domain(rng)
            expected = brute_zone(q)
            matched, _ = find_zone_match(q, zone_db)
            assert matched == expected, f"find_zone_match({q!r}) -> {matched!r}, expected {expected!r}"

    def test_whitelist_check_domain_vs_brute_force(self) -> None:
        rng = random.Random(self.SEED + 1)
        white_db: dict = {}
        entries = [self._rand_domain(rng) for _ in range(self.N_ENTRIES)]
        for d in entries:
            white_db[d] = False
        tld_seg = 2

        def brute_white(name: str) -> bool:
            if name in white_db:
                return True
            if name.startswith("www.") and name[4:] in white_db:
                return True
            parts = name.split(".")
            # suffix walk: start from parts[1:] down
            for i in range(1, len(parts)):
                suffix = ".".join(parts[i:])
                x = len(parts) - i  # remaining label count
                if x >= tld_seg and white_db.get(suffix):
                    return True
            return False

        for _ in range(self.N_QUERIES):
            q = self._rand_domain(rng)
            expected = brute_white(q)
            result = whitelist_check_domain(q, white_db, tld_seg)
            assert result == expected, f"whitelist_check_domain({q!r}) -> {result}, expected {expected}"

    def test_evaluate_noaaaa_vs_brute_force(self) -> None:
        rng = random.Random(self.SEED + 2)
        noaaaa_db: dict = {}
        entries = [self._rand_domain(rng) for _ in range(self.N_ENTRIES)]
        for d in entries:
            noaaaa_db[d] = rng.choice([True, False])

        def brute_noaaaa(q: str) -> bool:
            # Exact branch: presence check (is not None) — wildcard flag irrelevant
            if noaaaa_db.get(q) is not None:
                return True
            # Wildcard-parent branch mirrors find_noaaaa_wildcard_parent exactly:
            #   start from immediate parent; walk while parent still has a dot;
            #   truthy check (wildcard=False is falsy → not matched);
            #   stops before single-label (TLD) suffix.
            parent = q.split(".", 1)[-1]
            for _ in range(parent.count("."), 0, -1):
                if noaaaa_db.get(parent):
                    return True
                parent = parent.split(".", 1)[-1]
            return False

        for _ in range(self.N_QUERIES):
            q = self._rand_domain(rng)
            expected = brute_noaaaa(q)
            result = evaluate_noaaaa(q, noaaaa_db)
            assert result == expected, f"evaluate_noaaaa({q!r}) -> {result}, expected {expected}"


# ---------------------------------------------------------------------------
# Golden tests for evaluate_domain / evaluate_noaaaa orchestration
# These are the contract the trie-backed implementation must reproduce.
# ---------------------------------------------------------------------------


def _make_cfg(**overrides: Any) -> dict:
    """Return a minimal cfg dict with safe defaults; caller overrides as needed."""
    base = {
        "python_blocking": True,
        "dataDB": False,
        "zoneDB": False,
        "python_tld": False,
        "python_tlds": [],
        "dnsbl_ipv4": "10.10.10.1",
        "dnsbl_ipv6": "::1",
        "python_idn": False,
        "regexDB": False,
        "whiteDB": False,
        "python_tld_seg": 2,
        "hstsDB": False,
        "hsts_tlds": ("app", "dev"),
    }
    base.update(overrides)
    return base


def _make_containers(**overrides: Any) -> dict:
    """Return a containers dict of the flat matching structures; the caller
    overrides individual ones (dataDB/zoneDB/whiteDB/hstsDB/regexDB/
    feedGroupIndexDB), matching what evaluate_domain reads."""
    base: dict = {
        "dataDB": {},
        "zoneDB": {},
        "whiteDB": {},
        "hstsDB": {},
        "regexDB": defaultdict(str),
        "feedGroupIndexDB": defaultdict(list),
    }
    base.update(overrides)
    return base


class TestEvaluateDomainGolden:
    def test_data_hit(self) -> None:
        data_db: dict = {"evil.com": {"log": "1", "index": 0}}
        fgi_db: dict = {0: {"feed": "BadFeed", "group": "BadGroup"}}
        containers = _make_containers(dataDB=data_db, feedGroupIndexDB=fgi_db)
        cfg = _make_cfg(dataDB=True)
        dec = evaluate_domain("evil.com", "evil.com", "com", False, cfg, containers)
        assert dec.is_found is True
        assert dec.in_whitelist is False
        assert dec.b_type == "DNSBL"
        assert dec.b_eval == "evil.com"
        assert dec.feed == "BadFeed"
        assert dec.group == "BadGroup"
        assert dec.log_type == "1"
        assert dec.null_blocking is False  # log_type="1" and not in_hsts -> null_blocking=False
        assert dec.nxdomain is False  # VIP is neither null nor NXDOMAIN (issue #31 contrast)

    def test_data_exact_does_not_match_subdomain(self) -> None:
        data_db: dict = {"evil.com": {"log": "1", "index": 0}}
        containers = _make_containers(dataDB=data_db)
        cfg = _make_cfg(dataDB=True)
        dec = evaluate_domain("sub.evil.com", "sub.evil.com", "com", False, cfg, containers)
        assert dec.is_found is False

    def test_zone_hit_wildcard_incl_self(self) -> None:
        zone_db: dict = {"example.com": {"log": "1", "index": 0}}
        fgi_db: dict = {0: {"feed": "ZoneFeed", "group": "ZoneGroup"}}
        containers = _make_containers(zoneDB=zone_db, feedGroupIndexDB=fgi_db)
        cfg = _make_cfg(zoneDB=True)
        # Self match
        dec_self = evaluate_domain("example.com", "example.com", "com", False, cfg, containers)
        assert dec_self.is_found is True
        assert dec_self.b_type == "TLD"
        assert dec_self.b_eval == "example.com"
        # Subdomain match
        dec_sub = evaluate_domain("sub.example.com", "sub.example.com", "com", False, cfg, containers)
        assert dec_sub.is_found is True
        assert dec_sub.b_type == "TLD"
        assert dec_sub.b_eval == "example.com"  # matched parent, not query name

    def test_zone_b_eval_is_parent_not_query(self) -> None:
        zone_db: dict = {"example.com": {"log": "1", "index": 0}}
        containers = _make_containers(zoneDB=zone_db)
        cfg = _make_cfg(zoneDB=True)
        dec = evaluate_domain("deep.sub.example.com", "deep.sub.example.com", "com", False, cfg, containers)
        assert dec.b_eval == "example.com"

    def test_tld_allow(self) -> None:
        cfg = _make_cfg(python_tld=True, python_tlds=["com", "net"])
        containers = _make_containers()
        # "com" NOT in allowed list → block
        dec = evaluate_domain("example.org", "example.org", "example", False, cfg, containers)
        assert dec.is_found is True
        assert dec.feed == "TLD_Allow"
        assert dec.group == "DNSBL_TLD_Allow"

    def test_tld_allow_passthrough_when_tld_allowed(self) -> None:
        cfg = _make_cfg(python_tld=True, python_tlds=["com"])
        containers = _make_containers()
        dec = evaluate_domain("example.com", "example.com", "com", False, cfg, containers)
        assert dec.is_found is False

    def test_tld_allow_empty_list_is_a_noop(self) -> None:
        """issue #713: an empty ``python_tlds`` (TLD-Allow enabled but no TLDs
        configured) must NOT block every domain. Pre-fix, ``tld not in []`` is
        always True, so this arm fired for any query regardless of tld -- the
        "empty TLD-Allow blocks all" bug, still reachable here even after the
        config-load ``python_blacklist`` enable guard was fixed, because this
        decision site only gates on ``cfg["python_tld"]``."""
        cfg = _make_cfg(python_tld=True, python_tlds=[])
        containers = _make_containers()
        dec = evaluate_domain("example.com", "example.com", "com", False, cfg, containers)
        assert dec.is_found is False

    def test_tld_allow_branches_both_ways_on_a_populated_list(self) -> None:
        """With a populated TLD-Allow list, a disallowed tld is still blocked
        (the empty-list guard must not swallow the real case) and an allowed
        tld still passes through."""
        cfg = _make_cfg(python_tld=True, python_tlds=["com"])
        containers = _make_containers()

        dec_blocked = evaluate_domain("example.net", "example.net", "net", False, cfg, containers)
        assert dec_blocked.is_found is True
        assert dec_blocked.feed == "TLD_Allow"
        assert dec_blocked.group == "DNSBL_TLD_Allow"

        dec_allowed = evaluate_domain("example.com", "example.com", "com", False, cfg, containers)
        assert dec_allowed.is_found is False

    def test_idn_block(self) -> None:
        cfg = _make_cfg(python_idn=True)
        containers = _make_containers()
        dec = evaluate_domain("xn--evil.com", "xn--evil.com", "com", False, cfg, containers)
        assert dec.is_found is True
        assert dec.feed == "IDN"
        assert dec.group == "DNSBL_IDN"

    def test_regex_block(self) -> None:
        regex_db: dict = {"bad-pattern": re.compile(r"tracker")}
        cfg = _make_cfg(regexDB=True)
        containers = _make_containers(regexDB=regex_db)
        dec = evaluate_domain("tracker.evil.com", "tracker.evil.com", "com", False, cfg, containers)
        assert dec.is_found is True
        assert dec.group == "DNSBL_Regex"
        assert dec.feed == "bad-pattern"

    def test_regex_not_evaluated_for_empty_qname(self) -> None:
        # An empty q_name must not be run against the regex set. This preserves
        # the pre-ADR `pfb_regex_match` guard (`if q_name:`); an empty-matching
        # pattern (e.g. r"") would otherwise spuriously flag an empty query.
        regex_db: dict = {"match-all": re.compile(r"")}
        cfg = _make_cfg(regexDB=True)
        containers = _make_containers(regexDB=regex_db)
        dec = evaluate_domain("", "", "", False, cfg, containers)
        assert dec.is_found is False

    def test_regex_first_matching_pattern_wins(self) -> None:
        # Linear scan over regex_db.items() in insertion order; first hit wins.
        regex_db: dict = {"first": re.compile(r"foo"), "second": re.compile(r"bar")}
        cfg = _make_cfg(regexDB=True)
        containers = _make_containers(regexDB=regex_db)
        dec = evaluate_domain("barfoo.com", "barfoo.com", "com", False, cfg, containers)
        assert dec.is_found is True
        assert dec.feed == "first"

    def test_whitelist_override(self) -> None:
        data_db: dict = {"evil.com": {"log": "1", "index": 0}}
        white_db: dict = {"evil.com": False}
        fgi_db: dict = {0: {"feed": "F", "group": "G"}}
        containers = _make_containers(dataDB=data_db, whiteDB=white_db, feedGroupIndexDB=fgi_db)
        cfg = _make_cfg(dataDB=True, whiteDB=True)
        dec = evaluate_domain("evil.com", "evil.com", "com", False, cfg, containers)
        assert dec.is_found is True
        assert dec.in_whitelist is True
        # Whitelisted → null_blocking stays True (default), b_type stays "DNSBL"
        assert dec.null_blocking is True

    def test_hsts_null_blocking(self) -> None:
        data_db: dict = {"evil.com": {"log": "1", "index": 0}}
        hsts_db: dict = {"evil.com": 0}
        fgi_db: dict = {0: {"feed": "F", "group": "G"}}
        containers = _make_containers(dataDB=data_db, hstsDB=hsts_db, feedGroupIndexDB=fgi_db)
        cfg = _make_cfg(dataDB=True, hstsDB=True, hsts_tlds=())
        dec = evaluate_domain("evil.com", "evil.com", "com", False, cfg, containers)
        assert dec.is_found is True
        assert dec.in_hsts is True
        assert dec.p_type == "HSTS"
        # in_hsts → null_blocking stays True even though log_type="1"
        assert dec.null_blocking is True

    def test_hsts_tld_null_blocking(self) -> None:
        data_db: dict = {"evil.app": {"log": "1", "index": 0}}
        fgi_db: dict = {0: {"feed": "F", "group": "G"}}
        containers = _make_containers(dataDB=data_db, feedGroupIndexDB=fgi_db)
        cfg = _make_cfg(dataDB=True, hstsDB=True, hsts_tlds=("app",))
        dec = evaluate_domain("evil.app", "evil.app", "app", False, cfg, containers)
        assert dec.in_hsts is True
        assert dec.p_type == "HSTS_TLD"
        assert dec.null_blocking is True

    def test_cname_b_type_suffix(self) -> None:
        data_db: dict = {"evil.com": {"log": "1", "index": 0}}
        fgi_db: dict = {0: {"feed": "F", "group": "G"}}
        containers = _make_containers(dataDB=data_db, feedGroupIndexDB=fgi_db)
        cfg = _make_cfg(dataDB=True)
        dec = evaluate_domain("evil.com", "original.com", "com", True, cfg, containers)
        assert dec.is_found is True
        assert dec.b_type == "DNSBL_CNAME"

    def test_not_found_returns_default_decision(self) -> None:
        containers = _make_containers()
        cfg = _make_cfg()
        dec = evaluate_domain("notblocked.com", "notblocked.com", "com", False, cfg, containers)
        assert dec.is_found is False
        assert dec.in_whitelist is False
        assert dec.in_hsts is False
        assert dec.feed == "Unknown"
        assert dec.group == "Unknown"
        assert dec.b_eval == ""
        assert dec.b_type == "Python"
        assert dec.p_type == "Python"
        # null_blocking stays True when not found (no DNSBL response sent)
        assert dec.null_blocking is True

    def test_python_blocking_false_skips_data_zone(self) -> None:
        data_db: dict = {"evil.com": {"log": "1", "index": 0}}
        containers = _make_containers(dataDB=data_db)
        cfg = _make_cfg(dataDB=True, python_blocking=False)
        dec = evaluate_domain("evil.com", "evil.com", "com", False, cfg, containers)
        assert dec.is_found is False

    def test_log_type_2_does_not_change_null_blocking(self) -> None:
        # log_type != "1" → null_blocking stays True (default)
        data_db: dict = {"evil.com": {"log": "2", "index": 0}}
        fgi_db: dict = {0: {"feed": "F", "group": "G"}}
        containers = _make_containers(dataDB=data_db, feedGroupIndexDB=fgi_db)
        cfg = _make_cfg(dataDB=True)
        dec = evaluate_domain("evil.com", "evil.com", "com", False, cfg, containers)
        assert dec.is_found is True
        assert dec.null_blocking is True  # log_type="2" != "1" → no null_blocking flip
        assert dec.nxdomain is False  # null block is not NXDOMAIN (issue #31 contrast)


class TestEvaluateDomainNxdomain:
    """Issue #31: log_type "3"/"4" select the NXDOMAIN block shape in evaluate_domain.

    Scenario: a DNSBL data hit whose per-list Logging/Blocking mode is one of the two
    new NXDOMAIN variants.
      Background: a feed entry for evil.com mapped to feed F / group G.
      Given the entry's log flag is "3" (NXDOMAIN logging) or "4" (NXDOMAIN no logging)
      When evaluate_domain resolves the block
      Then dec.nxdomain is True, dec.null_blocking stays True (no 0.0.0.0 reply), and
           dec.log_type carries the raw flag through for the logger to branch on.
    Branch coverage pairs these against the VIP ("1", nxdomain False) and null ("2",
    nxdomain False) cases above, proving "3"/"4" is a real, distinct branch.
    """

    def _dec(self, log: str, **cfg_kw: Any) -> Any:
        # Given a single-entry dataDB whose log flag is `log`
        data_db: dict = {"evil.com": {"log": log, "index": 0}}
        fgi_db: dict = {0: {"feed": "F", "group": "G"}}
        containers = _make_containers(dataDB=data_db, feedGroupIndexDB=fgi_db)
        cfg = _make_cfg(dataDB=True, **cfg_kw)
        # When the domain is evaluated
        return evaluate_domain("evil.com", "evil.com", "com", False, cfg, containers)

    def test_log_type_3_selects_nxdomain_logging(self) -> None:
        dec = self._dec("3")
        # Then it is a block flagged NXDOMAIN, not a null/VIP reply
        assert dec.is_found is True
        assert dec.nxdomain is True
        assert dec.null_blocking is True  # no synthesized 0.0.0.0 / VIP record
        assert dec.log_type == "3"  # logger logs this variant

    def test_log_type_4_selects_nxdomain_no_logging(self) -> None:
        dec = self._dec("4")
        assert dec.is_found is True
        assert dec.nxdomain is True
        assert dec.null_blocking is True
        assert dec.log_type == "4"  # logger silences this variant

    def test_nxdomain_does_not_inherit_hsts_attribution(self) -> None:
        # NXDOMAIN avoids the TLS handshake HSTS guards, so the HSTS null-override
        # (which forces a VIP "1" block to null) must NOT touch an NXDOMAIN block AND
        # the block must not be MISreported as HSTS in the logs (issue #31 / PR review).
        # Given evil.com is in the HSTS DB AND its mode is NXDOMAIN-logging ("3") --
        # hsts_check_domain WILL match it, so without the clear it would set in_hsts/p_type.
        data_db: dict = {"evil.com": {"log": "3", "index": 0}}
        hsts_db: dict = {"evil.com": 0}
        fgi_db: dict = {0: {"feed": "F", "group": "G"}}
        containers = _make_containers(dataDB=data_db, hstsDB=hsts_db, feedGroupIndexDB=fgi_db)
        cfg = _make_cfg(dataDB=True, hstsDB=True, hsts_tlds=())
        # When evaluated
        dec = evaluate_domain("evil.com", "evil.com", "com", False, cfg, containers)
        # Then the block stays NXDOMAIN (not reshaped to null/VIP) AND reports as a clean
        # Python block -- the HSTS attribution is cleared, not carried into the decision.
        assert dec.nxdomain is True
        assert dec.null_blocking is True
        assert dec.in_hsts is False  # HSTS membership did not influence NXDOMAIN -> cleared
        assert dec.p_type == "Python"  # mislabeled "HSTS"/"HSTS_TLD" before the fix


class TestEvaluateNoaaaGolden:
    def test_exact_match(self) -> None:
        db = _noaaaa_db({"example.com": False})
        assert evaluate_noaaaa("example.com", db) is True

    def test_exact_match_wildcard_true(self) -> None:
        db = _noaaaa_db({"example.com": True})
        assert evaluate_noaaaa("example.com", db) is True

    def test_wildcard_parent_matches_child(self) -> None:
        db = _noaaaa_db({"example.com": True})
        assert evaluate_noaaaa("sub.example.com", db) is True

    def test_wildcard_false_parent_does_not_match_child(self) -> None:
        db = _noaaaa_db({"example.com": False})
        assert evaluate_noaaaa("sub.example.com", db) is False

    def test_no_entry(self) -> None:
        db = _noaaaa_db({})
        assert evaluate_noaaaa("example.com", db) is False

    def test_parent_only_semantics_self_requires_exact_key(self) -> None:
        # Wildcard on "example.com" does NOT match self via wildcard branch;
        # exact branch handles self. Both give True but via different paths.
        db = _noaaaa_db({"example.com": True})
        # "example.com" itself: exact branch fires → True
        assert evaluate_noaaaa("example.com", db) is True
        # "sub.example.com": wildcard-parent branch fires → True
        assert evaluate_noaaaa("sub.example.com", db) is True
        # A domain with only the sub key (wildcard) should match deeper sub
        db2 = _noaaaa_db({"sub.example.com": True})
        # "deep.sub.example.com": parent chain includes "sub.example.com" → True
        assert evaluate_noaaaa("deep.sub.example.com", db2) is True


# ---------------------------------------------------------------------------
# ADR-02: Python-only DNSBL invariant tests
#
# ADR-02 removes the native Unbound DNSBL mode and pins python_blocking=True
# permanently in the generated .ini config (PHP always emits "python_blocking = on").
# These tests verify:
#   (a) the evaluate_domain contract for the now-invariant python_blocking=True path,
#   (b) that secondary matchers (regex, IDN, TLD-Allow) sit OUTSIDE the
#       python_blocking gate and therefore fire regardless of that flag, and
#   (c) that data-DB lookup takes priority over zone-DB lookup, and that
#       whitelist overrides both data and zone matches.
# ---------------------------------------------------------------------------


class TestADR02PythonOnlyBlocking:
    """Regression tests for the ADR-02 'Python is the sole DNSBL implementation'
    invariant.  python_blocking is always True at runtime after ADR-02; the tests
    below verify the evaluate_domain contract for that path and pin its edge cases."""

    # ------------------------------------------------------------------
    # Positive-path: python_blocking=True (the post-ADR-02 only state)
    # ------------------------------------------------------------------

    def test_python_blocking_true_enables_data_lookup(self) -> None:
        # With python_blocking=True (the ADR-02 invariant), an exact domain in
        # dataDB is found and returned as a DNSBL block.
        data_db: dict = {"evil.com": {"log": "1", "index": 0}}
        fgi_db: dict = {0: {"feed": "TestFeed", "group": "TestGroup"}}
        containers = _make_containers(dataDB=data_db, feedGroupIndexDB=fgi_db)
        cfg = _make_cfg(dataDB=True)  # python_blocking defaults to True
        dec = evaluate_domain("evil.com", "evil.com", "com", False, cfg, containers)
        assert dec.is_found is True
        assert dec.b_type == "DNSBL"
        assert dec.b_eval == "evil.com"
        assert dec.feed == "TestFeed"

    def test_python_blocking_true_enables_zone_lookup(self) -> None:
        # Zone/wildcard lookup is also inside the python_blocking gate.
        # Subdomain of a zone entry → found via zone path.
        zone_db: dict = {"example.com": {"log": "1", "index": 0}}
        fgi_db: dict = {0: {"feed": "ZoneFeed", "group": "ZoneGroup"}}
        containers = _make_containers(zoneDB=zone_db, feedGroupIndexDB=fgi_db)
        cfg = _make_cfg(zoneDB=True)  # python_blocking defaults to True
        dec = evaluate_domain("deep.sub.example.com", "deep.sub.example.com", "com", False, cfg, containers)
        assert dec.is_found is True
        assert dec.b_type == "TLD"
        assert dec.b_eval == "example.com"
        assert dec.feed == "ZoneFeed"

    def test_data_lookup_takes_priority_over_zone_when_both_match(self) -> None:
        # When a domain appears in BOTH dataDB (exact) and zoneDB (wildcard),
        # data is checked first (evaluate_domain lines 1471 before 1481).
        # After ADR-02 this ordering is always active because python_blocking=True.
        data_db: dict = {"example.com": {"log": "1", "index": 0}}
        zone_db: dict = {"example.com": {"log": "1", "index": 1}}
        fgi_db: dict = {
            0: {"feed": "DataFeed", "group": "DataGroup"},
            1: {"feed": "ZoneFeed", "group": "ZoneGroup"},
        }
        containers = _make_containers(dataDB=data_db, zoneDB=zone_db, feedGroupIndexDB=fgi_db)
        cfg = _make_cfg(dataDB=True, zoneDB=True)
        dec = evaluate_domain("example.com", "example.com", "com", False, cfg, containers)
        assert dec.is_found is True
        assert dec.b_type == "DNSBL"  # data path wins, not zone/TLD
        assert dec.feed == "DataFeed"
        assert dec.group == "DataGroup"

    def test_zone_lookup_fires_only_when_data_misses(self) -> None:
        # If a domain is absent from dataDB (even when the flag is enabled) but
        # present in zoneDB, the zone path fires as a fallback.
        zone_db: dict = {"example.com": {"log": "1", "index": 0}}
        fgi_db: dict = {0: {"feed": "ZoneFeed", "group": "ZoneGroup"}}
        # dataDB flag enabled but backing dict is empty → miss → falls through to zoneDB
        containers = _make_containers(zoneDB=zone_db, feedGroupIndexDB=fgi_db)
        cfg = _make_cfg(dataDB=True, zoneDB=True)
        dec = evaluate_domain("sub.example.com", "sub.example.com", "com", False, cfg, containers)
        assert dec.is_found is True
        assert dec.b_type == "TLD"
        assert dec.b_eval == "example.com"

    def test_empty_dbs_with_python_blocking_true_returns_not_found(self) -> None:
        # python_blocking=True does not block anything by itself; it only enables
        # the lookup paths.  With no entries in any DB, the result is not_found.
        containers = _make_containers()
        cfg = _make_cfg(dataDB=True, zoneDB=True)
        dec = evaluate_domain("innocent.com", "innocent.com", "com", False, cfg, containers)
        assert dec.is_found is False
        assert dec.null_blocking is True  # no block sent → null_blocking stays True

    # ------------------------------------------------------------------
    # Whitelist overrides: both data and zone matches are overridable
    # ------------------------------------------------------------------

    def test_whitelist_overrides_data_match(self) -> None:
        # An exact whitelist entry suppresses a data-path block.
        data_db: dict = {"evil.com": {"log": "1", "index": 0}}
        white_db: dict = {"evil.com": False}
        fgi_db: dict = {0: {"feed": "F", "group": "G"}}
        containers = _make_containers(dataDB=data_db, whiteDB=white_db, feedGroupIndexDB=fgi_db)
        cfg = _make_cfg(dataDB=True, whiteDB=True)
        dec = evaluate_domain("evil.com", "evil.com", "com", False, cfg, containers)
        assert dec.is_found is True
        assert dec.in_whitelist is True
        assert dec.null_blocking is True  # whitelisted → no DNSBL response

    def test_whitelist_overrides_zone_match(self) -> None:
        # A whitelisted subdomain is not blocked even when its parent zone entry
        # would otherwise match.  Confirms the whitelist check runs after is_found
        # regardless of which lookup path (data or zone) set is_found.
        zone_db: dict = {"example.com": {"log": "1", "index": 0}}
        white_db: dict = {"sub.example.com": False}
        fgi_db: dict = {0: {"feed": "ZoneFeed", "group": "ZoneGroup"}}
        containers = _make_containers(zoneDB=zone_db, whiteDB=white_db, feedGroupIndexDB=fgi_db)
        cfg = _make_cfg(zoneDB=True, whiteDB=True)
        dec = evaluate_domain("sub.example.com", "sub.example.com", "com", False, cfg, containers)
        assert dec.is_found is True
        assert dec.in_whitelist is True
        assert dec.null_blocking is True

    def test_wildcard_whitelist_overrides_zone_match_for_subdomain(self) -> None:
        # A wildcard whitelist entry (wildcard=True) covers the domain and its
        # children.  A zone match on the parent should still be suppressed for a
        # whitelisted subdomain.
        zone_db: dict = {"example.com": {"log": "1", "index": 0}}
        white_db: dict = {"example.com": True}  # wildcard: covers *.example.com too
        fgi_db: dict = {0: {"feed": "ZF", "group": "ZG"}}
        containers = _make_containers(zoneDB=zone_db, whiteDB=white_db, feedGroupIndexDB=fgi_db)
        cfg = _make_cfg(zoneDB=True, whiteDB=True)
        dec = evaluate_domain("deep.sub.example.com", "deep.sub.example.com", "com", False, cfg, containers)
        assert dec.is_found is True
        assert dec.in_whitelist is True

    # ------------------------------------------------------------------
    # Secondary matchers are OUTSIDE the python_blocking gate
    # They run regardless of python_blocking value.
    # ------------------------------------------------------------------

    def test_regex_still_evaluates_when_python_blocking_is_false(self) -> None:
        # Regex matching sits after the `if cfg["python_blocking"]:` block, so it
        # fires even when python_blocking=False.  (In practice, python_blocking is
        # now always True after ADR-02; this test pins that the gate boundary is
        # not accidentally moved.)
        regex_db: dict = {"bad-pattern": re.compile(r"malicious")}
        containers = _make_containers(regexDB=regex_db)
        cfg = _make_cfg(regexDB=True, python_blocking=False)
        dec = evaluate_domain("malicious.tracker.com", "malicious.tracker.com", "com", False, cfg, containers)
        assert dec.is_found is True
        assert dec.group == "DNSBL_Regex"
        assert dec.feed == "bad-pattern"

    def test_idn_still_evaluates_when_python_blocking_is_false(self) -> None:
        # IDN detection is likewise outside the gate.
        containers = _make_containers()
        cfg = _make_cfg(python_idn=True, python_blocking=False)
        dec = evaluate_domain("xn--test.com", "xn--test.com", "com", False, cfg, containers)
        assert dec.is_found is True
        assert dec.group == "DNSBL_IDN"
        assert dec.feed == "IDN"

    def test_tld_allow_still_evaluates_when_python_blocking_is_false(self) -> None:
        # TLD-Allow also lives outside the python_blocking gate.
        containers = _make_containers()
        cfg = _make_cfg(python_tld=True, python_tlds=["com", "net"], python_blocking=False)
        # "org" is not in the allowed list → fires TLD-Allow block
        dec = evaluate_domain("example.org", "example.org", "example", False, cfg, containers)
        assert dec.is_found is True
        assert dec.group == "DNSBL_TLD_Allow"
        assert dec.feed == "TLD_Allow"

    def test_data_skipped_but_regex_fires_when_python_blocking_false(self) -> None:
        # Compound case: python_blocking=False disables data/zone lookups but regex
        # still runs, producing a block via a different code path.
        data_db: dict = {"evil.com": {"log": "1", "index": 0}}
        regex_db: dict = {"catch-evil": re.compile(r"evil")}
        containers = _make_containers(dataDB=data_db, regexDB=regex_db)
        cfg = _make_cfg(dataDB=True, regexDB=True, python_blocking=False)
        dec = evaluate_domain("evil.com", "evil.com", "com", False, cfg, containers)
        assert dec.is_found is True
        assert dec.group == "DNSBL_Regex"  # regex fired, NOT the data-path DNSBL entry
        assert dec.b_type != "DNSBL"  # confirm data path was skipped

    # ------------------------------------------------------------------
    # operate() integration: pfb["python_blocking"] is passed into cfg
    # ------------------------------------------------------------------

    def test_operate_blocks_when_python_blocking_true(self, monkeypatch: Any) -> None:
        # ADR-02 guarantee: pfb["python_blocking"] is always True at runtime.
        # operate() copies pfb["python_blocking"] into the cfg dict forwarded to
        # evaluate_domain.  Verify that the end-to-end operate() call blocks a
        # domain in dataDB when python_blocking=True.
        pfb_unbound.pfb["python_blacklist"] = True
        pfb_unbound.pfb["python_blocking"] = True
        monkeypatch.setattr(pfb_unbound, "pfb_log", lambda *a: None)
        monkeypatch.setattr(pfb_unbound, "pfb_db_enqueue", lambda *a: None)
        add_data("adr02-blocked.com", log="1", index=0)
        set_feed_group(0, "ADR02Feed", "ADR02Group")
        qstate = make_qstate("adr02-blocked.com.", qtype=RR_A)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED
        assert qstate.return_rcode == RCODE_NOERROR
        answers = DNSMessage.instances[-1].answer
        assert any(pfb_unbound.pfb["dnsbl_ipv4"] in a for a in answers)

    def test_operate_does_not_block_when_python_blocking_false(self, monkeypatch: Any) -> None:
        # Boundary check: with python_blocking=False in the pfb global (the old
        # native-Unbound state, no longer reachable after ADR-02), operate() must
        # not block an exact-data entry — confirming the gate in evaluate_domain is
        # the single control point.
        pfb_unbound.pfb["python_blacklist"] = True
        pfb_unbound.pfb["python_blocking"] = False
        monkeypatch.setattr(pfb_unbound, "pfb_log", lambda *a: None)
        monkeypatch.setattr(pfb_unbound, "pfb_db_enqueue", lambda *a: None)
        add_data("adr02-not-blocked.com", log="1", index=0)
        set_feed_group(0, "ADR02Feed", "ADR02Group")
        qstate = make_qstate("adr02-not-blocked.com.", qtype=RR_A)
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        # Without python_blocking, the domain is memoized as an allow and passed through
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE
        dec = pfb_unbound.decisionDB.get("adr02-not-blocked.com")
        assert dec is not None and not _is_block(dec)

    def test_operate_zone_block_with_python_blocking_true(self, monkeypatch: Any) -> None:
        # Wildcard/zone blocking via operate() with the ADR-02 invariant state.
        pfb_unbound.pfb["python_blacklist"] = True
        pfb_unbound.pfb["python_blocking"] = True
        monkeypatch.setattr(pfb_unbound, "pfb_log", lambda *a: None)
        monkeypatch.setattr(pfb_unbound, "pfb_db_enqueue", lambda *a: None)
        add_zone("blocked-zone.net", log="1", index=0)
        set_feed_group(0, "ZoneFeed", "ZoneGroup")
        qstate = make_qstate("any.subdomain.blocked-zone.net.", qtype=RR_A)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED
        entry = pfb_unbound.decisionDB.get("any.subdomain.blocked-zone.net")
        assert entry is not None
        assert entry.dnsbl.b_type == "TLD"
        assert entry.dnsbl.feed == "ZoneFeed"

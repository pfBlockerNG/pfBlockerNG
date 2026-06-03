import builtins
import random
import re
import types
from collections import defaultdict

import pfb_unbound

# Unbound injects these as module-level globals at runtime; conftest stubs them
# onto builtins so pfb_unbound can be imported. Bind local names for the tests
# (and so static analysis sees them defined).
DNSMessage = builtins.DNSMessage
MODULE_EVENT_NEW = builtins.MODULE_EVENT_NEW
MODULE_EVENT_MODDONE = builtins.MODULE_EVENT_MODDONE
MODULE_FINISHED = builtins.MODULE_FINISHED
MODULE_WAIT_MODULE = builtins.MODULE_WAIT_MODULE
MODULE_ERROR = builtins.MODULE_ERROR
RCODE_NOERROR = builtins.RCODE_NOERROR
from pfb_unbound import (
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


class TestIsUnknown:
    def test_none_returns_unknown(self):
        assert is_unknown(None) == "Unknown"

    def test_empty_string_returns_unknown(self):
        assert is_unknown("") == "Unknown"

    def test_zero_returns_unknown(self):
        assert is_unknown(0) == "Unknown"

    def test_false_returns_unknown(self):
        assert is_unknown(False) == "Unknown"

    def test_nonempty_string_returned_as_is(self):
        assert is_unknown("example.com") == "example.com"

    def test_ip_string_returned_as_is(self):
        assert is_unknown("192.168.1.1") == "192.168.1.1"

    def test_string_zero_returned_as_is(self):
        # '0' is a non-empty string, so it is not unknown
        assert is_unknown("0") == "0"

    def test_nonzero_int_returned_as_is(self):
        assert is_unknown(42) == 42


class TestConvertIPv4:
    # x[2], x[3], x[4], x[5] are the four octets; x[0] and x[1] are ignored

    def test_standard_address(self):
        assert convert_ipv4(bytes([0, 0, 192, 168, 1, 1])) == "192.168.1.1"

    def test_loopback(self):
        assert convert_ipv4(bytes([0, 0, 127, 0, 0, 1])) == "127.0.0.1"

    def test_broadcast(self):
        assert convert_ipv4(bytes([0, 0, 255, 255, 255, 255])) == "255.255.255.255"

    def test_all_zeros(self):
        assert convert_ipv4(bytes([0, 0, 0, 0, 0, 0])) == "0.0.0.0"

    def test_empty_bytes_returns_unknown(self):
        assert convert_ipv4(b"") == "Unknown"

    def test_none_returns_unknown(self):
        assert convert_ipv4(None) == "Unknown"


class TestConvertIPv6:
    # x[2] through x[17] are the 16 address bytes; x[0] and x[1] are ignored

    def test_loopback(self):
        x = bytes([0, 0] + [0] * 15 + [1])
        assert convert_ipv6(x) == "0000:0000:0000:0000:0000:0000:0000:0001"

    def test_known_prefix(self):
        # 2001:0db8::1
        x = bytes([0, 0, 0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        assert convert_ipv6(x) == "2001:0db8:0000:0000:0000:0000:0000:0001"

    def test_all_zeros_not_unknown(self):
        # All-zeros IPv6 address is a valid (if unusual) value
        x = bytes([0, 0] + [0] * 16)
        assert convert_ipv6(x) == "0000:0000:0000:0000:0000:0000:0000:0000"

    def test_empty_bytes_returns_unknown(self):
        assert convert_ipv6(b"") == "Unknown"

    def test_none_returns_unknown(self):
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

    def test_printable_ascii(self):
        x = bytes([0, 0, 0, ord("A"), ord("B"), ord("C")])
        assert convert_other(x) == "ABC"

    def test_null_becomes_pipe(self):
        x = bytes([0, 0, 0, ord("A"), 0, ord("B")])
        assert convert_other(x) == "A|B"

    def test_low_byte_becomes_dot(self):
        x = bytes([0, 0, 0, ord("A"), 1, ord("B")])
        assert convert_other(x) == "A.B"

    def test_carriage_return_stops_processing(self):
        x = bytes([0, 0, 0, ord("A"), 13, ord("B")])
        assert convert_other(x) == "A"

    def test_space_preserved(self):
        x = bytes([0, 0, 0, ord("A"), 32, ord("B")])
        assert convert_other(x) == "A B"

    def test_colon_preserved(self):
        x = bytes([0, 0, 0, ord("h"), 58, ord("1")])
        assert convert_other(x) == "h:1"

    def test_control_chars_skipped(self):
        # val 14..31 (excluding 13) and 33 are skipped
        x = bytes([0, 0, 0, ord("A"), 14, ord("B")])
        assert convert_other(x) == "AB"

    def test_high_bytes_skipped(self):
        x = bytes([0, 0, 0, ord("A"), 200, ord("B")])
        assert convert_other(x) == "AB"

    def test_leading_trailing_stripped(self):
        # Result '.A.' → strip('.|') → 'A'
        x = bytes([0, 0, 0, ord("."), ord("A"), ord(".")])
        assert convert_other(x) == "A"

    def test_empty_payload_returns_unknown(self):
        # x[3:] is empty
        x = bytes([0, 0, 0])
        assert convert_other(x) == "Unknown"

    def test_empty_bytes_returns_unknown(self):
        assert convert_other(b"") == "Unknown"

    def test_none_returns_unknown(self):
        assert convert_other(None) == "Unknown"


class TestPythonControlDuration:
    def test_valid_duration(self):
        assert python_control_duration("60") == 60

    def test_minimum_valid(self):
        assert python_control_duration("1") == 1

    def test_maximum_valid(self):
        assert python_control_duration("3600") == 3600

    def test_zero_rejected(self):
        assert python_control_duration("0") is False

    def test_above_maximum_rejected(self):
        assert python_control_duration("3601") is False

    def test_non_numeric_rejected(self):
        assert python_control_duration("abc") is False

    def test_negative_rejected(self):
        # isnumeric() returns False for strings with a leading '-'
        assert python_control_duration("-1") is False

    def test_empty_string_rejected(self):
        assert python_control_duration("") is False

    def test_none_rejected(self):
        # AttributeError on None.isnumeric() is caught internally
        assert python_control_duration(None) is False


class TestGetQIpComm:
    def test_pfb_addr_key_present(self):
        kwargs = {"pfb_addr": "1.2.3.4"}
        assert pfb_unbound.get_q_ip_comm(kwargs) == "1.2.3.4"

    def test_fallback_to_repinfo_addr(self):
        kwargs = {"repinfo": types.SimpleNamespace(addr="5.6.7.8")}
        assert pfb_unbound.get_q_ip_comm(kwargs) == "5.6.7.8"

    def test_pfb_addr_takes_precedence(self):
        kwargs = {"pfb_addr": "1.2.3.4", "repinfo": types.SimpleNamespace(addr="5.6.7.8")}
        assert pfb_unbound.get_q_ip_comm(kwargs) == "1.2.3.4"

    def test_empty_kwargs_returns_unknown(self):
        assert pfb_unbound.get_q_ip_comm({}) == "Unknown"

    def test_none_kwargs_returns_unknown(self):
        assert pfb_unbound.get_q_ip_comm(None) == "Unknown"

    def test_repinfo_empty_addr_returns_unknown(self):
        kwargs = {"repinfo": types.SimpleNamespace(addr="")}
        assert pfb_unbound.get_q_ip_comm(kwargs) == "Unknown"


class TestLogEntry:
    def test_normal_write(self, tmp_path):
        log = tmp_path / "dnsbl.log"
        pfb_unbound._log_entry_direct("a,b,c", str(log))
        assert log.read_text() == "a,b,c\n"

    def test_multiple_calls_accumulate(self, tmp_path):
        log = tmp_path / "dnsbl.log"
        pfb_unbound._log_entry_direct("line1", str(log))
        pfb_unbound._log_entry_direct("line2", str(log))
        assert log.read_text() == "line1\nline2\n"

    def test_file_created_when_missing(self, tmp_path):
        log = tmp_path / "sub" / "unified.log"
        log.parent.mkdir()
        assert not log.exists()
        pfb_unbound._log_entry_direct("x", str(log))
        assert log.exists()


class TestDbSubsystem:
    """Persistent sqlite subsystem (ADR-03). With no DB worker running, pfb_db_enqueue
    falls back to synchronous execution, so these drive the same SQL the worker batches."""

    def _resolver(self, tmp_path):
        db = str(tmp_path / "resolver.sqlite")
        pfb_unbound.pfb["pfb_py_resolver"] = db
        pfb_unbound.pfb["sqlite3_resolver_con"] = True
        return db

    def test_validate_creates_table_and_seed_row(self, tmp_path):
        db = self._resolver(tmp_path)
        assert pfb_unbound.pfb_db_validate(pfb_unbound.DB_RESOLVER) is True
        import sqlite3

        con = sqlite3.connect(db)
        try:
            assert con.execute("SELECT totalqueries FROM resolver WHERE row = 0").fetchone()[0] == 0
        finally:
            con.close()

    def test_resolver_counter_accumulates(self, tmp_path):
        self._resolver(tmp_path)
        for _ in range(5):
            pfb_unbound.pfb_db_enqueue(("resolver",))
        con = pfb_unbound._db_conns[pfb_unbound.DB_RESOLVER]
        assert con.execute("SELECT totalqueries FROM resolver WHERE row = 0").fetchone()[0] == 5

    def test_resolver_counting_gated_by_flag(self, tmp_path):
        db = str(tmp_path / "resolver.sqlite")
        pfb_unbound.pfb["pfb_py_resolver"] = db
        pfb_unbound.pfb["sqlite3_resolver_con"] = False
        pfb_unbound.pfb_db_enqueue(("resolver",))
        # Gated off -> no connection opened, nothing written.
        assert pfb_unbound.DB_RESOLVER not in pfb_unbound._db_conns

    def test_relative_increment_survives_concurrent_reset(self, tmp_path):
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

    def test_dnsbl_counter_per_group(self, tmp_path):
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

    def test_cache_inserts_preserve_order(self, tmp_path):
        db = str(tmp_path / "cache.sqlite")
        pfb_unbound.pfb["pfb_py_cache"] = db
        for d in ["a.com", "b.com", "a.com"]:
            pfb_unbound.pfb_db_enqueue(("cache", ("DNSBL", d, "G", d, "feed")))
        con = pfb_unbound._db_conns[pfb_unbound.DB_CACHE]
        rows = [r[0] for r in con.execute("SELECT domain FROM dnsblcache").fetchall()]
        assert rows == ["a.com", "b.com", "a.com"]

    def test_reconnect_after_db_removed(self, tmp_path):
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

    def test_worker_batches_and_flushes(self, tmp_path):
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

    def test_wal_concurrent_writers_no_lock(self, tmp_path):
        import sqlite3
        import threading

        db = str(tmp_path / "resolver.sqlite")
        pfb_unbound.pfb["pfb_py_resolver"] = db
        pfb_unbound.pfb["sqlite3_resolver_con"] = True
        pfb_unbound.pfb_db_validate(pfb_unbound.DB_RESOLVER)  # create table+row, sets WAL

        n = 100
        errors: list = []

        def py_side():
            try:
                for _ in range(n):
                    pfb_unbound.pfb_db_enqueue(("resolver",))  # sync -> persistent WAL conn
            except Exception as e:
                errors.append(e)

        def php_side():
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

    def test_persistent_connection_single_connect(self, tmp_path, monkeypatch):
        import sqlite3

        db = str(tmp_path / "resolver.sqlite")
        pfb_unbound.pfb["pfb_py_resolver"] = db
        pfb_unbound.pfb["sqlite3_resolver_con"] = True

        real_connect = sqlite3.connect
        count = {"n": 0}

        def counting_connect(*a, **k):
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

    def _setup(self, tmp_path, monkeypatch):
        paths = (
            str(tmp_path / "dnsbl.log"),
            str(tmp_path / "dns_reply.log"),
            str(tmp_path / "unified.log"),
        )
        monkeypatch.setattr(pfb_unbound, "PFB_LOG_FILES", paths)
        pfb_unbound.pfb_setup_logging()
        return paths

    def test_pipeline_writes_exact_lines_to_correct_files(self, tmp_path, monkeypatch):
        dnsbl, dns_reply, unified = self._setup(tmp_path, monkeypatch)
        pfb_unbound.pfb_log(dnsbl, "a.com,blocked")
        pfb_unbound.pfb_log(dnsbl, "b.com,100%match")  # literal % must not be formatted
        pfb_unbound.pfb_log(unified, "u-1")
        pfb_unbound.pfb_log(dns_reply, "r-1")
        pfb_unbound.pfb_log_listener.stop()  # flush + join
        pfb_unbound.pfb["log_listener"] = False
        with open(dnsbl) as f:
            assert f.read() == "a.com,blocked\nb.com,100%match\n"
        with open(unified) as f:
            assert f.read() == "u-1\n"
        with open(dns_reply) as f:
            assert f.read() == "r-1\n"

    def test_fallback_direct_append_when_no_pipeline(self, tmp_path):
        log = str(tmp_path / "x.log")
        pfb_unbound.pfb_log(log, "direct-1")
        pfb_unbound.pfb_log(log, "direct-2")
        with open(log) as f:
            assert f.read() == "direct-1\ndirect-2\n"

    def test_watched_handler_reopens_after_external_rotation(self, tmp_path, monkeypatch):
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
    def test_ttl_present(self):
        rep = types.SimpleNamespace(ttl=300)
        assert pfb_unbound.get_rep_ttl(rep) == "300"

    def test_none_rep_returns_unk(self):
        assert pfb_unbound.get_rep_ttl(None) == "Unk"

    def test_falsy_ttl_returns_unk(self):
        rep = types.SimpleNamespace(ttl=0)
        assert pfb_unbound.get_rep_ttl(rep) == "Unk"


class TestPythonControlThread:
    def test_active_thread_found(self):
        import threading

        stop = threading.Event()
        t = threading.Thread(name="pfb-test-thread", target=stop.wait, daemon=True)
        t.start()
        try:
            assert pfb_unbound.python_control_thread("pfb-test-thread") is True
        finally:
            stop.set()
            t.join()

    def test_unknown_thread_returns_false(self):
        assert pfb_unbound.python_control_thread("nonexistent-thread-xyz") is False


class TestGetQNameQstate:
    def test_primary_strips_trailing_dot(self):
        qstate = types.SimpleNamespace(qinfo=types.SimpleNamespace(qname_str="example.com."), return_msg=None)
        assert pfb_unbound.get_q_name_qstate(qstate) == "example.com"

    def test_fallback_to_return_msg(self):
        qstate = types.SimpleNamespace(
            qinfo=types.SimpleNamespace(qname_str="   "),
            return_msg=types.SimpleNamespace(qinfo=types.SimpleNamespace(qname_str="fallback.com.")),
        )
        assert pfb_unbound.get_q_name_qstate(qstate) == "fallback.com"

    def test_both_empty_returns_unknown(self):
        qstate = types.SimpleNamespace(qinfo=types.SimpleNamespace(qname_str=""), return_msg=None)
        assert pfb_unbound.get_q_name_qstate(qstate) == "Unknown"


class TestGetQNameQinfo:
    def test_present_stripped(self):
        qinfo = types.SimpleNamespace(qname_str="example.com.")
        assert pfb_unbound.get_q_name_qinfo(qinfo) == "example.com"

    def test_whitespace_returns_unknown(self):
        qinfo = types.SimpleNamespace(qname_str="   ")
        assert pfb_unbound.get_q_name_qinfo(qinfo) == "Unknown"

    def test_none_returns_unknown(self):
        assert pfb_unbound.get_q_name_qinfo(None) == "Unknown"


class TestGetQType:
    def test_prefers_qstate(self):
        qstate = types.SimpleNamespace(qinfo=types.SimpleNamespace(qtype_str="A"))
        qinfo = types.SimpleNamespace(qtype_str="AAAA")
        assert pfb_unbound.get_q_type(qstate, qinfo) == "A"

    def test_falls_back_to_qinfo(self):
        qstate = types.SimpleNamespace(qinfo=types.SimpleNamespace(qtype_str=""))
        qinfo = types.SimpleNamespace(qtype_str="AAAA")
        assert pfb_unbound.get_q_type(qstate, qinfo) == "AAAA"

    def test_both_none_returns_unknown(self):
        qstate = types.SimpleNamespace(qinfo=types.SimpleNamespace(qtype_str=""))
        qinfo = types.SimpleNamespace(qtype_str="")
        assert pfb_unbound.get_q_type(qstate, qinfo) == "Unknown"


class TestGetOType:
    def test_return_msg_rrset_branch(self):
        rk = types.SimpleNamespace(type_str="A")
        rrset = types.SimpleNamespace(rk=rk)
        qstate = types.SimpleNamespace(
            return_msg=types.SimpleNamespace(rep=types.SimpleNamespace(rrsets=[rrset])),
            qinfo=types.SimpleNamespace(qtype_str="AAAA"),
        )
        assert pfb_unbound.get_o_type(qstate, None) == "A"

    def test_qinfo_qtype_branch(self):
        qstate = types.SimpleNamespace(return_msg=None, qinfo=types.SimpleNamespace(qtype_str="AAAA"))
        assert pfb_unbound.get_o_type(qstate, None) == "AAAA"

    def test_rep_branch(self):
        rk = types.SimpleNamespace(type_str="TXT")
        rep = types.SimpleNamespace(rrsets=[types.SimpleNamespace(rk=rk)])
        qstate = types.SimpleNamespace(return_msg=None, qinfo=types.SimpleNamespace(qtype_str=""))
        assert pfb_unbound.get_o_type(qstate, rep) == "TXT"

    def test_no_qstate_returns_unknown(self):
        assert pfb_unbound.get_o_type(None, None) == "Unknown"


class TestGetTld:
    def test_multilabel(self):
        qstate = types.SimpleNamespace(qinfo=types.SimpleNamespace(qname_list=["sub", "example", "com"]))
        assert pfb_unbound.get_tld(qstate) == "example"

    def test_single_label_returns_empty(self):
        qstate = types.SimpleNamespace(qinfo=types.SimpleNamespace(qname_list=["com"]))
        assert pfb_unbound.get_tld(qstate) == ""

    def test_none_qstate_returns_empty(self):
        assert pfb_unbound.get_tld(None) == ""


class TestGetQIp:
    def test_first_node_with_addr_wins(self):
        node2 = types.SimpleNamespace(query_reply=types.SimpleNamespace(addr="2.2.2.2"), next=None)
        node1 = types.SimpleNamespace(query_reply=types.SimpleNamespace(addr="1.1.1.1"), next=node2)
        qstate = types.SimpleNamespace(mesh_info=types.SimpleNamespace(reply_list=node1))
        assert pfb_unbound.get_q_ip(qstate) == "1.1.1.1"

    def test_no_reply_list_returns_unknown(self):
        qstate = types.SimpleNamespace(mesh_info=types.SimpleNamespace(reply_list=None))
        assert pfb_unbound.get_q_ip(qstate) == "Unknown"


def make_qstate(qname="example.com.", qtype=1, q_ip=None, return_msg=None, return_rcode=0):
    reply_list = None
    if q_ip is not None:
        reply_list = types.SimpleNamespace(query_reply=types.SimpleNamespace(addr=q_ip), next=None)
    qinfo = types.SimpleNamespace(
        qname_str=qname,
        qtype=qtype,
        qtype_str="",
        qname_list=qname.rstrip(".").split("."),
    )
    return types.SimpleNamespace(
        qinfo=qinfo,
        mesh_info=types.SimpleNamespace(reply_list=reply_list),
        return_msg=return_msg,
        return_rcode=return_rcode,
        ext_state={},
    )


# RR_TYPE constants mirror the conftest stubs
RR_A = 1
RR_AAAA = 28
RR_TXT = 16


class TestOperateNoAAAA:
    def test_exact_match_blocks(self, monkeypatch):
        add_noaaaa("example.com", wildcard=False)
        qstate = make_qstate("example.com.", qtype=RR_AAAA)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED
        assert qstate.return_rcode == RCODE_NOERROR

    def test_wildcard_blocks_subdomain_and_caches(self):
        add_noaaaa("example.com", wildcard=True)
        qstate = make_qstate("sub.example.com.", qtype=RR_AAAA)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED
        # The wildcard-parent hit memoizes an exact noAAAADB entry for the child,
        # so a subsequent identical query short-circuits on the exact branch.
        assert pfb_unbound.noAAAADB.get("sub.example.com") is True
        assert evaluate_noaaaa("sub.example.com", pfb_unbound.noAAAADB) is True
        # Fast-path is unchanged: a subsequent identical query still blocks.
        qstate2 = make_qstate("sub.example.com.", qtype=RR_AAAA)
        rcd2 = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate2, None)
        assert rcd2 is True
        assert qstate2.ext_state[0] == MODULE_FINISHED

    def test_excluded_domain_not_blocked(self):
        add_noaaaa("example.com", wildcard=False)
        pfb_unbound.excludeAAAADB.append("example.com")
        qstate = make_qstate("example.com.", qtype=RR_AAAA)
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE

    def test_non_aaaa_skips_logic(self):
        add_noaaaa("example.com", wildcard=False)
        qstate = make_qstate("example.com.", qtype=RR_A)
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE

    def test_no_match_adds_to_exclude(self):
        add_noaaaa("other.com", wildcard=True)
        qstate = make_qstate("example.com.", qtype=RR_AAAA)
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert "example.com" in pfb_unbound.excludeAAAADB
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE


class TestOperateDnsbl:
    def _enable(self, monkeypatch):
        pfb_unbound.pfb["python_blacklist"] = True
        pfb_unbound.pfb["python_blocking"] = True
        monkeypatch.setattr(pfb_unbound, "pfb_log", lambda *a: None)
        monkeypatch.setattr(pfb_unbound, "pfb_db_enqueue", lambda *a: None)

    def test_data_lookup_blocks_with_dnsbl_ipv4(self, monkeypatch):
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

    def test_zone_lookup_matches_subdomain(self, monkeypatch):
        self._enable(monkeypatch)
        add_zone("example.com", log="1", index=0)
        set_feed_group(0, "TestFeed", "TestGroup")
        qstate = make_qstate("sub.example.com.", qtype=RR_A)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED

    def test_whitelist_override_not_blocked(self, monkeypatch):
        self._enable(monkeypatch)
        add_data("evil.com", log="1", index=0)
        set_feed_group(0, "TestFeed", "TestGroup")
        add_white("evil.com", wildcard=False)
        qstate = make_qstate("evil.com.", qtype=RR_A)
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE
        assert "evil.com" in pfb_unbound.excludeDB

    def test_regex_block(self, monkeypatch):
        self._enable(monkeypatch)
        pfb_unbound.pfb["regexDB"] = True
        pfb_unbound.regexDB["bad-pattern"] = re.compile(r"evil")
        qstate = make_qstate("evil-domain.com.", qtype=RR_A)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED
        entry = pfb_unbound.dnsblDB.get("evil-domain.com")
        assert entry["group"] == "DNSBL_Regex"

    def test_excludedb_short_circuit(self, monkeypatch):
        self._enable(monkeypatch)
        add_data("evil.com", log="1", index=0)
        set_feed_group(0, "TestFeed", "TestGroup")
        pfb_unbound.excludeDB.append("evil.com")
        qstate = make_qstate("evil.com.", qtype=RR_A)
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE

    def test_group_policy_bypass(self, monkeypatch):
        self._enable(monkeypatch)
        add_data("evil.com", log="1", index=0)
        set_feed_group(0, "TestFeed", "TestGroup")
        pfb_unbound.pfb["gpListDB"] = True
        pfb_unbound.gpListDB["1.2.3.4"] = 0
        qstate = make_qstate("evil.com.", qtype=RR_A, q_ip="1.2.3.4")
        pfb_unbound.operate(0, MODULE_EVENT_NEW, qstate, None)
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE

    @staticmethod
    def _cname_reply(orig_qname="orig.com."):
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

    def test_cname_target_blocks_and_marks_original(self, monkeypatch):
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

        entry = pfb_unbound.dnsblDB.get("orig.com")
        assert entry is not None
        assert entry["b_type"] == "DNSBL_CNAME"
        # Block is keyed on the original name after the q_name reassignment,
        # not on the CNAME target itself.
        assert "evil-cname.com" not in pfb_unbound.dnsblDB
        answers = DNSMessage.instances[-1].answer
        assert any(a.startswith("orig.com. ") for a in answers)

    def test_cname_disabled_original_not_blocked(self, monkeypatch):
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
        assert "orig.com" not in pfb_unbound.dnsblDB

    def test_cname_target_blocked_when_queried_directly(self, monkeypatch):
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
        assert "evil-cname.com" in pfb_unbound.dnsblDB

    def test_block_sets_return_msg_exactly_once(self, monkeypatch):
        # The DNSBL block path previously called msg.set_return_msg(qstate)
        # twice (standalone + inside the guard); it must run exactly once.
        self._enable(monkeypatch)
        calls = {"n": 0}
        orig = DNSMessage.set_return_msg

        def counting(self, qstate):
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


class TestOperateEvents:
    def test_moddone_logs_and_finishes(self):
        qstate = make_qstate("example.com.", qtype=RR_A)
        rcd = pfb_unbound.operate(0, MODULE_EVENT_MODDONE, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_FINISHED

    def test_unknown_event_returns_error(self):
        qstate = make_qstate("example.com.", qtype=RR_A)
        rcd = pfb_unbound.operate(0, 99, qstate, None)
        assert rcd is True
        assert qstate.ext_state[0] == MODULE_ERROR


class TestGetDetailsReplyNoaaaa:
    """The reply-x gate in get_details_reply only proceeds for an AAAA reply
    whose name has an exact noAAAA entry (``noAAAADB.get(name) is not None``)."""

    def _aaaa_qstate(self, qname):
        qstate = make_qstate(qname, qtype=RR_AAAA)
        qstate.qinfo.qtype_str = "AAAA"  # get_o_type falls back to this when return_msg is None
        qstate.return_msg = None
        return qstate

    def test_reply_x_aaaa_exact_noaaaa_proceeds(self, monkeypatch):
        calls = []
        monkeypatch.setattr(pfb_unbound, "pfb_db_enqueue", lambda *a, **k: calls.append(a))
        pfb_unbound.pfb["sqlite3_resolver_con"] = True
        add_noaaaa("blocked.example.com", wildcard=False)
        qstate = self._aaaa_qstate("blocked.example.com.")
        rcd = pfb_unbound.get_details_reply("reply-x", None, qstate, None, {"pfb_addr": "1.2.3.4"})
        assert rcd is True
        # Gate passed -> proceeds past the reply-x gate to the resolver counter.
        assert len(calls) == 1

    def test_reply_x_aaaa_without_noaaaa_short_circuits(self, monkeypatch):
        calls = []
        monkeypatch.setattr(pfb_unbound, "pfb_db_enqueue", lambda *a, **k: calls.append(a))
        pfb_unbound.pfb["sqlite3_resolver_con"] = True
        qstate = self._aaaa_qstate("notblocked.example.com.")
        rcd = pfb_unbound.get_details_reply("reply-x", None, qstate, None, {"pfb_addr": "1.2.3.4"})
        assert rcd is True
        # Gate failed -> early return before the resolver counter fires.
        assert calls == []


# ---------------------------------------------------------------------------
# Oracle / property tests for pure domain-match helpers
# ---------------------------------------------------------------------------


class TestIterDomainSuffixes:
    def test_single_label(self):
        assert list(iter_domain_suffixes("com")) == ["com"]

    def test_two_labels(self):
        assert list(iter_domain_suffixes("example.com")) == ["example.com", "com"]

    def test_three_labels(self):
        assert list(iter_domain_suffixes("sub.example.com")) == ["sub.example.com", "example.com", "com"]

    def test_empty_string(self):
        # Empty string has no dots; yields one item (the empty string itself)
        assert list(iter_domain_suffixes("")) == [""]


class TestFindZoneMatch:
    def test_exact_self_match(self):
        zone_db = {"example.com": {"log": "1", "index": 0}}
        matched, entry = find_zone_match("example.com", zone_db)
        assert matched == "example.com"
        assert entry == {"log": "1", "index": 0}

    def test_subdomain_matches_parent_zone(self):
        zone_db = {"example.com": {"log": "1", "index": 0}}
        matched, entry = find_zone_match("sub.example.com", zone_db)
        assert matched == "example.com"
        assert entry is not None

    def test_deep_subdomain_matches(self):
        zone_db = {"example.com": {"log": "1", "index": 0}}
        matched, entry = find_zone_match("a.b.example.com", zone_db)
        assert matched == "example.com"

    def test_no_match_returns_none_none(self):
        zone_db = {"evil.com": {"log": "1", "index": 0}}
        matched, entry = find_zone_match("good.com", zone_db)
        assert matched is None
        assert entry is None

    def test_data_exact_not_wildcard(self):
        # dataDB uses exact only; simulate: zone_db contains 'evil.com'
        # but query is 'x.evil.com' — zone DOES match (wildcard incl. self),
        # while a separate exact-only check would not.
        # This test pins that find_zone_match IS the wildcard matcher.
        zone_db = {"evil.com": {"log": "1", "index": 0}}
        matched, _ = find_zone_match("x.evil.com", zone_db)
        assert matched == "evil.com"

    def test_matched_parent_string_correct(self):
        # b_eval = matched parent string; must be the zone key, not the query name
        zone_db = {"example.com": {"log": "1", "index": 0}}
        matched, _ = find_zone_match("deep.sub.example.com", zone_db)
        assert matched == "example.com"

    def test_most_specific_match_wins(self):
        # iter_domain_suffixes walks q_name → ... TLD, so first hit is most specific
        zone_db = {
            "sub.example.com": {"log": "1", "index": 1},
            "example.com": {"log": "1", "index": 2},
        }
        matched, entry = find_zone_match("sub.example.com", zone_db)
        assert matched == "sub.example.com"
        assert entry["index"] == 1


class TestWhitelistCheckDomain:
    def test_exact_match(self):
        white_db: dict = {"allowed.com": False}
        assert whitelist_check_domain("allowed.com", white_db, tld_seg=2) is True

    def test_no_match(self):
        white_db: dict = {"other.com": False}
        assert whitelist_check_domain("allowed.com", white_db, tld_seg=2) is False

    def test_www_strip(self):
        # "www.allowed.com" → strips "www." → checks "allowed.com"
        white_db: dict = {"allowed.com": False}
        assert whitelist_check_domain("www.allowed.com", white_db, tld_seg=2) is True

    def test_www_strip_not_triggered_for_non_www(self):
        white_db: dict = {"allowed.com": False}
        assert whitelist_check_domain("sub.allowed.com", white_db, tld_seg=2) is False

    def test_suffix_walk_at_tld_seg_boundary_matches(self):
        # "sub.evil.com": suffix walk starts at "evil.com" (x=2, tld_seg=2) → match
        white_db: dict = {"evil.com": True}
        assert whitelist_check_domain("sub.evil.com", white_db, tld_seg=2) is True

    def test_suffix_walk_below_tld_seg_does_not_match(self):
        # "evil.com": suffix walk starts at "com" (x=1, tld_seg=2) → 1 < 2 → no match
        white_db: dict = {"com": True}
        assert whitelist_check_domain("evil.com", white_db, tld_seg=2) is False

    def test_suffix_walk_with_high_tld_seg_blocks_intermediate(self):
        # "a.b.example.com" with tld_seg=3:
        #   suffix walk q starts at "b.example.com", x counts down from 3:
        #   x=3 >= 3 → check "b.example.com" (not in db)
        #   x=2 < 3 → skip "example.com"  (below tld_seg gate)
        white_db: dict = {"example.com": True}
        assert whitelist_check_domain("a.b.example.com", white_db, tld_seg=3) is False

    def test_suffix_walk_respects_tld_seg_allows_higher(self):
        # Same domain but entry is at "b.example.com" (x=3 >= 3) → match
        white_db: dict = {"b.example.com": True}
        assert whitelist_check_domain("a.b.example.com", white_db, tld_seg=3) is True


class TestFindNoaaaaWildcardParent:
    def test_exact_name_not_matched_by_wildcard_fn(self):
        # find_noaaaa_wildcard_parent starts from PARENT, so self is never checked
        noaaaa_db: dict = {"example.com": True}
        result = find_noaaaa_wildcard_parent("example.com", noaaaa_db)
        assert result is None

    def test_direct_parent_matched(self):
        noaaaa_db: dict = {"example.com": True}
        result = find_noaaaa_wildcard_parent("sub.example.com", noaaaa_db)
        assert result == "example.com"

    def test_grandparent_matched(self):
        noaaaa_db: dict = {"example.com": True}
        result = find_noaaaa_wildcard_parent("a.b.example.com", noaaaa_db)
        assert result == "example.com"

    def test_no_match_returns_none(self):
        noaaaa_db: dict = {"other.com": True}
        result = find_noaaaa_wildcard_parent("sub.example.com", noaaaa_db)
        assert result is None

    def test_wildcard_false_value_not_matched(self):
        # noaaaa_db.get(q) is truthy check; wildcard=False means value is False → not matched
        noaaaa_db: dict = {"example.com": False}
        result = find_noaaaa_wildcard_parent("sub.example.com", noaaaa_db)
        assert result is None

    def test_single_label_parent_not_checked(self):
        # "sub.com": parent = "com", but loop range(0, 0, -1) is empty → no check
        noaaaa_db: dict = {"com": True}
        result = find_noaaaa_wildcard_parent("sub.com", noaaaa_db)
        assert result is None


def _noaaaa_db(entries: dict[str, bool]) -> dict[str, bool]:
    """A {domain: wildcard} noAAAA dict (the runtime structure for noAAAA)."""
    return dict(entries)


class TestEvaluateNoaaaa:
    def test_exact_match_no_wildcard_flag(self):
        # wildcard=False → exact branch fires on presence (get(name) is not None)
        db = _noaaaa_db({"example.com": False})
        assert evaluate_noaaaa("example.com", db) is True

    def test_exact_match_wildcard_flag(self):
        db = _noaaaa_db({"example.com": True})
        assert evaluate_noaaaa("example.com", db) is True

    def test_wildcard_parent_matches_subdomain(self):
        db = _noaaaa_db({"example.com": True})
        assert evaluate_noaaaa("sub.example.com", db) is True

    def test_wildcard_false_does_not_match_subdomain(self):
        # wildcard=False → wildcard-parent branch skips it (truthy check)
        db = _noaaaa_db({"example.com": False})
        assert evaluate_noaaaa("sub.example.com", db) is False

    def test_no_match(self):
        db = _noaaaa_db({"other.com": True})
        assert evaluate_noaaaa("example.com", db) is False

    def test_self_not_matched_by_wildcard_branch(self):
        # wildcard branch is parent-only; exact branch handles self
        db = _noaaaa_db({"example.com": True})
        assert evaluate_noaaaa("example.com", db) is True


class TestHstsCheckDomain:
    def test_tld_in_hsts_tlds_returns_hsts_tld(self):
        hsts_db: dict = {}
        assert hsts_check_domain("example.app", hsts_db, ("app",), "app") == (True, "HSTS_TLD")

    def test_tld_not_in_hsts_tlds_falls_through(self):
        hsts_db: dict = {}
        result = hsts_check_domain("example.com", hsts_db, ("app",), "com")
        assert result == (False, "Python")

    def test_exact_domain_in_hsts_db(self):
        hsts_db: dict = {"example.com": 0}
        result = hsts_check_domain("example.com", hsts_db, (), "com")
        assert result == (True, "HSTS")

    def test_suffix_walk_hits_parent(self):
        # "sub.example.com" (2 dots): range(3,0,-2) → [3, 1]
        # iter 0: check "sub.example.com" (miss), step → "example.com"
        # iter 1: check "example.com" (hit)
        hsts_db: dict = {"example.com": 0}
        result = hsts_check_domain("sub.example.com", hsts_db, (), "com")
        assert result == (True, "HSTS")

    def test_stride_2_skips_alternate_label(self):
        # "a.b.c.d" (3 dots): range(4,0,-2) → 2 iterations
        # The loop runs twice: q starts at "a.b.c.d", then steps to "b.c.d".
        # Positions checked: "a.b.c.d" (iter 0), "b.c.d" (iter 1).
        # "c.d" is never checked (one more step would be needed).
        # This pins the stride-2 quirk: "c.d" alone is NOT found.
        hsts_db: dict = {"c.d": 0}
        result = hsts_check_domain("a.b.c.d", hsts_db, (), "d")
        assert result == (False, "Python")

    def test_stride_2_hits_second_position(self):
        # The second position checked is "b.c.d" (after one step from "a.b.c.d").
        # A stride-1 walk would also check "c.d" and "d"; stride-2 stops after "b.c.d".
        hsts_db: dict = {"b.c.d": 0}
        result = hsts_check_domain("a.b.c.d", hsts_db, (), "d")
        assert result == (True, "HSTS")

    def test_no_match_returns_python(self):
        hsts_db: dict = {"other.com": 0}
        result = hsts_check_domain("example.com", hsts_db, (), "com")
        assert result == (False, "Python")


class TestResolveFeedGroup:
    def test_hit_returns_feed_and_group(self):
        fgidb = {0: {"feed": "MyFeed", "group": "MyGroup"}}
        assert resolve_feed_group(0, fgidb) == ("MyFeed", "MyGroup")

    def test_miss_returns_unknown_unknown(self):
        fgidb: dict = {}
        assert resolve_feed_group(99, fgidb) == ("Unknown", "Unknown")

    def test_none_index_returns_unknown(self):
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

    def test_find_zone_match_vs_brute_force(self):
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

    def test_whitelist_check_domain_vs_brute_force(self):
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

    def test_evaluate_noaaaa_vs_brute_force(self):
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


def _make_cfg(**overrides):
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


def _make_containers(**overrides):
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
    def test_data_hit(self):
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

    def test_data_exact_does_not_match_subdomain(self):
        data_db: dict = {"evil.com": {"log": "1", "index": 0}}
        containers = _make_containers(dataDB=data_db)
        cfg = _make_cfg(dataDB=True)
        dec = evaluate_domain("sub.evil.com", "sub.evil.com", "com", False, cfg, containers)
        assert dec.is_found is False

    def test_zone_hit_wildcard_incl_self(self):
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

    def test_zone_b_eval_is_parent_not_query(self):
        zone_db: dict = {"example.com": {"log": "1", "index": 0}}
        containers = _make_containers(zoneDB=zone_db)
        cfg = _make_cfg(zoneDB=True)
        dec = evaluate_domain("deep.sub.example.com", "deep.sub.example.com", "com", False, cfg, containers)
        assert dec.b_eval == "example.com"

    def test_tld_allow(self):
        cfg = _make_cfg(python_tld=True, python_tlds=["com", "net"])
        containers = _make_containers()
        # "com" NOT in allowed list → block
        dec = evaluate_domain("example.org", "example.org", "example", False, cfg, containers)
        assert dec.is_found is True
        assert dec.feed == "TLD_Allow"
        assert dec.group == "DNSBL_TLD_Allow"

    def test_tld_allow_passthrough_when_tld_allowed(self):
        cfg = _make_cfg(python_tld=True, python_tlds=["com"])
        containers = _make_containers()
        dec = evaluate_domain("example.com", "example.com", "com", False, cfg, containers)
        assert dec.is_found is False

    def test_idn_block(self):
        cfg = _make_cfg(python_idn=True)
        containers = _make_containers()
        dec = evaluate_domain("xn--evil.com", "xn--evil.com", "com", False, cfg, containers)
        assert dec.is_found is True
        assert dec.feed == "IDN"
        assert dec.group == "DNSBL_IDN"

    def test_regex_block(self):
        regex_db: dict = {"bad-pattern": re.compile(r"tracker")}
        cfg = _make_cfg(regexDB=True)
        containers = _make_containers(regexDB=regex_db)
        dec = evaluate_domain("tracker.evil.com", "tracker.evil.com", "com", False, cfg, containers)
        assert dec.is_found is True
        assert dec.group == "DNSBL_Regex"
        assert dec.feed == "bad-pattern"

    def test_regex_not_evaluated_for_empty_qname(self):
        # An empty q_name must not be run against the regex set. This preserves
        # the pre-ADR `pfb_regex_match` guard (`if q_name:`); an empty-matching
        # pattern (e.g. r"") would otherwise spuriously flag an empty query.
        regex_db: dict = {"match-all": re.compile(r"")}
        cfg = _make_cfg(regexDB=True)
        containers = _make_containers(regexDB=regex_db)
        dec = evaluate_domain("", "", "", False, cfg, containers)
        assert dec.is_found is False

    def test_regex_first_matching_pattern_wins(self):
        # Linear scan over regex_db.items() in insertion order; first hit wins.
        regex_db: dict = {"first": re.compile(r"foo"), "second": re.compile(r"bar")}
        cfg = _make_cfg(regexDB=True)
        containers = _make_containers(regexDB=regex_db)
        dec = evaluate_domain("barfoo.com", "barfoo.com", "com", False, cfg, containers)
        assert dec.is_found is True
        assert dec.feed == "first"

    def test_whitelist_override(self):
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

    def test_hsts_null_blocking(self):
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

    def test_hsts_tld_null_blocking(self):
        data_db: dict = {"evil.app": {"log": "1", "index": 0}}
        fgi_db: dict = {0: {"feed": "F", "group": "G"}}
        containers = _make_containers(dataDB=data_db, feedGroupIndexDB=fgi_db)
        cfg = _make_cfg(dataDB=True, hstsDB=True, hsts_tlds=("app",))
        dec = evaluate_domain("evil.app", "evil.app", "app", False, cfg, containers)
        assert dec.in_hsts is True
        assert dec.p_type == "HSTS_TLD"
        assert dec.null_blocking is True

    def test_cname_b_type_suffix(self):
        data_db: dict = {"evil.com": {"log": "1", "index": 0}}
        fgi_db: dict = {0: {"feed": "F", "group": "G"}}
        containers = _make_containers(dataDB=data_db, feedGroupIndexDB=fgi_db)
        cfg = _make_cfg(dataDB=True)
        dec = evaluate_domain("evil.com", "original.com", "com", True, cfg, containers)
        assert dec.is_found is True
        assert dec.b_type == "DNSBL_CNAME"

    def test_not_found_returns_default_decision(self):
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

    def test_python_blocking_false_skips_data_zone(self):
        data_db: dict = {"evil.com": {"log": "1", "index": 0}}
        containers = _make_containers(dataDB=data_db)
        cfg = _make_cfg(dataDB=True, python_blocking=False)
        dec = evaluate_domain("evil.com", "evil.com", "com", False, cfg, containers)
        assert dec.is_found is False

    def test_log_type_2_does_not_change_null_blocking(self):
        # log_type != "1" → null_blocking stays True (default)
        data_db: dict = {"evil.com": {"log": "2", "index": 0}}
        fgi_db: dict = {0: {"feed": "F", "group": "G"}}
        containers = _make_containers(dataDB=data_db, feedGroupIndexDB=fgi_db)
        cfg = _make_cfg(dataDB=True)
        dec = evaluate_domain("evil.com", "evil.com", "com", False, cfg, containers)
        assert dec.is_found is True
        assert dec.null_blocking is True  # log_type="2" != "1" → no null_blocking flip


class TestEvaluateNoaaaGolden:
    def test_exact_match(self):
        db = _noaaaa_db({"example.com": False})
        assert evaluate_noaaaa("example.com", db) is True

    def test_exact_match_wildcard_true(self):
        db = _noaaaa_db({"example.com": True})
        assert evaluate_noaaaa("example.com", db) is True

    def test_wildcard_parent_matches_child(self):
        db = _noaaaa_db({"example.com": True})
        assert evaluate_noaaaa("sub.example.com", db) is True

    def test_wildcard_false_parent_does_not_match_child(self):
        db = _noaaaa_db({"example.com": False})
        assert evaluate_noaaaa("sub.example.com", db) is False

    def test_no_entry(self):
        db = _noaaaa_db({})
        assert evaluate_noaaaa("example.com", db) is False

    def test_parent_only_semantics_self_requires_exact_key(self):
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

    def test_python_blocking_true_enables_data_lookup(self):
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

    def test_python_blocking_true_enables_zone_lookup(self):
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

    def test_data_lookup_takes_priority_over_zone_when_both_match(self):
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

    def test_zone_lookup_fires_only_when_data_misses(self):
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

    def test_empty_dbs_with_python_blocking_true_returns_not_found(self):
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

    def test_whitelist_overrides_data_match(self):
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

    def test_whitelist_overrides_zone_match(self):
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

    def test_wildcard_whitelist_overrides_zone_match_for_subdomain(self):
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

    def test_regex_still_evaluates_when_python_blocking_is_false(self):
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

    def test_idn_still_evaluates_when_python_blocking_is_false(self):
        # IDN detection is likewise outside the gate.
        containers = _make_containers()
        cfg = _make_cfg(python_idn=True, python_blocking=False)
        dec = evaluate_domain("xn--test.com", "xn--test.com", "com", False, cfg, containers)
        assert dec.is_found is True
        assert dec.group == "DNSBL_IDN"
        assert dec.feed == "IDN"

    def test_tld_allow_still_evaluates_when_python_blocking_is_false(self):
        # TLD-Allow also lives outside the python_blocking gate.
        containers = _make_containers()
        cfg = _make_cfg(python_tld=True, python_tlds=["com", "net"], python_blocking=False)
        # "org" is not in the allowed list → fires TLD-Allow block
        dec = evaluate_domain("example.org", "example.org", "example", False, cfg, containers)
        assert dec.is_found is True
        assert dec.group == "DNSBL_TLD_Allow"
        assert dec.feed == "TLD_Allow"

    def test_data_skipped_but_regex_fires_when_python_blocking_false(self):
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

    def test_operate_blocks_when_python_blocking_true(self, monkeypatch):
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

    def test_operate_does_not_block_when_python_blocking_false(self, monkeypatch):
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
        # Without python_blocking, the domain is added to excludeDB and passed through
        assert qstate.ext_state[0] == MODULE_WAIT_MODULE
        assert "adr02-not-blocked.com" in pfb_unbound.excludeDB

    def test_operate_zone_block_with_python_blocking_true(self, monkeypatch):
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
        entry = pfb_unbound.dnsblDB.get("any.subdomain.blocked-zone.net")
        assert entry is not None
        assert entry["b_type"] == "TLD"
        assert entry["feed"] == "ZoneFeed"

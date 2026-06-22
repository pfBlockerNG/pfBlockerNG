import builtins
import os
import sys
from collections import defaultdict

# pfb_unbound.py is designed to run inside Unbound's Python plugin loader, which
# injects Unbound-specific functions and integer constants as module-level
# globals before executing the script. Reproduce that here by copying the symbols
# from the shared stubs/python/unboundmodule.py stub onto builtins, so the file
# can be imported in a plain Python environment for unit testing. That same stub
# is what static type checkers resolve for pfb_unbound.py's TYPE_CHECKING
# `from unboundmodule import ...` block, keeping a single source of truth.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "stubs", "python"))

import unboundmodule  # noqa: E402

for _name in unboundmodule.__all__:
    setattr(builtins, _name, getattr(unboundmodule, _name))

# Make pfb_unbound importable from its installed location within the repo.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "usr", "local", "pkg", "pfblockerng"))

import pytest  # noqa: E402

import pfb_unbound  # noqa: E402


@pytest.fixture(autouse=True)
def reset_pfb_globals() -> None:
    unboundmodule.DNSMessage.instances = []

    pfb_unbound.pfb = {
        "mod_threading": True,
        "mod_ipaddress": True,
        "mod_maxminddb": False,
        "mod_sqlite3": True,
        "python_enable": False,
        "python_blacklist": False,
        "python_blocking": False,
        "python_reply": False,
        "python_nolog": False,
        "python_cname": False,
        "python_control": False,
        "python_control_legacy": False,
        "python_hsts": False,
        "python_idn": False,
        "python_tld": False,
        "python_maxmind": False,
        "python_tld_seg": 2,
        "python_tlds": [],
        "dnsbl_ipv4": "10.10.10.1",
        "dnsbl_ipv6": "::1",
        "dataDB": False,
        "zoneDB": False,
        "regexDB": False,
        "allowRegexDB": False,
        "important_rules": False,
        "regex_cap": False,
        "regex_warn_ms": pfb_unbound.REGEX_WARN_MS_DEFAULT,
        "regex_evict_ms": pfb_unbound.REGEX_EVICT_MS_DEFAULT,
        "whiteDB": False,
        "hstsDB": False,
        "gpListDB": False,
        "noAAAADB": False,
        "safeSearchDB": False,
        "sqlite3_dnsbl_con": False,
        "sqlite3_resolver_con": False,
        "rr_types": (1, 28, 255, 5, 39, 24, 15, 2, 12, 33, 16, 64, 65),
        "hsts_tlds": (
            "android",
            "app",
            "bank",
            "chrome",
            "dev",
            "foo",
            "gle",
            "gmail",
            "google",
            "hangout",
            "insurance",
            "meet",
            "new",
            "page",
            "play",
            "search",
            "youtube",
        ),
        "pfb_py_dnsbl": ":memory:",
        "pfb_py_resolver": ":memory:",
        "pfb_py_cache": ":memory:",
        # PFBL-03: the local privileged control channel + its applied-seq marker
        # (chroot-relative, exactly as init_standard sets them). Tests that drive the
        # reader thread override these to a temp path; the keys exist here so a unit
        # test can read the stable names without spinning up the watcher.
        "pfb_py_control": "pfb_py_control",
        "pfb_py_control_applied": "pfb_py_control.applied",
        # ADR-38 Phase 4: syslog export defaults (off, LOG_LOCAL6, LOG_NOTICE).
        "syslog_enable": False,
        "syslog_facility": 22,
        "syslog_priority": 5,
    }
    pfb_unbound.dataDB = defaultdict(list)
    pfb_unbound.zoneDB = defaultdict(list)
    pfb_unbound.decisionDB = pfb_unbound._LruCache(0)  # real type, unbounded -> logic tests never evict
    pfb_unbound._dnsbl_last_event = None
    pfb_unbound.safeSearchDB = defaultdict(list)
    pfb_unbound.feedGroupIndexDB = defaultdict(list)
    pfb_unbound.regexDB = defaultdict(str)
    pfb_unbound.allowRegexDB = defaultdict(str)
    # ADR-07 P7: reset the per-pattern warn rate-limit + perf-fallback strike state so
    # each test starts with a clean runtime warn/evict bookkeeping.
    pfb_unbound._regex_warned.clear()
    pfb_unbound._regex_perf_strikes.clear()
    # Reset the literal-prefilter index caches so each test starts with a clean index.
    pfb_unbound._block_regex_index = None
    pfb_unbound._allow_regex_index = None
    pfb_unbound.whiteDB = defaultdict(str)
    pfb_unbound.hstsDB = defaultdict(str)
    pfb_unbound.gpListDB = defaultdict(str)
    pfb_unbound.noAAAADB = defaultdict(str)
    pfb_unbound.threads = []

    # ADR-10 P2: init_standard bundles the matcher strata into ONE immutable Snapshot
    # and operate() reads every stratum off it. Mirror that here: build the single
    # ``_snapshot`` ref from the SAME dict objects assigned above, so a test helper that
    # mutates a global dict IN PLACE (e.g. ``pfb_unbound.dataDB[name] = ...``) is visible
    # through the snapshot -- exactly as the shared dict objects behave at runtime
    # between reloads. (A reload rebuilds the whole Snapshot; tests that need a fresh
    # snapshot rebind ``pfb_unbound._snapshot`` themselves.)
    pfb_unbound._snapshot = pfb_unbound.Snapshot(
        data_db=pfb_unbound.dataDB,
        zone_db=pfb_unbound.zoneDB,
        white_db=pfb_unbound.whiteDB,
        regex_db=pfb_unbound.regexDB,
        allow_regex_db=pfb_unbound.allowRegexDB,
        feed_group_index_db=pfb_unbound.feedGroupIndexDB,
        hsts_db=pfb_unbound.hstsDB,
        important_rules=False,
    )

    # Reset the persistent sqlite connection cache between tests (the :memory:
    # DBs above are per-connection, so a leaked connection would carry state).
    for _db in list(pfb_unbound._db_conns.keys()):
        pfb_unbound._db_close(_db)
    pfb_unbound._db_conns.clear()

    # ADR-38 Phase 4: reset the module-level syslog handler state so each test
    # starts with no active handler and no failure latch.
    pfb_unbound._syslog_handler = None
    pfb_unbound._syslog_failed = False

    # Reset the logging pipeline between tests (stop a leaked QueueListener thread
    # and drop the cached per-file loggers so the synchronous fallback is used by
    # default and pipeline tests start clean).
    _listener = getattr(pfb_unbound, "pfb_log_listener", None)
    if _listener is not None:
        try:
            _listener.stop()
        except Exception:
            pass
    pfb_unbound.pfb_loggers.clear()

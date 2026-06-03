# pfb_unbound.py
# pfBlockerNG - Unbound resolver python integration

# part of pfSense (https://www.pfsense.org)
# Copyright (c) 2015-2026 Rubicon Communications, LLC (Netgate)
# Copyright (c) 2015-2024 BBcan177@gmail.com
# All rights reserved.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import csv
import json
import logging
import logging.handlers
import os
import re
import sys
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    # Symbols injected by Unbound's embedded Python interpreter (pythonmod) into
    # this script's globals at runtime. They are imported here only so static
    # type checkers can resolve them; the import is never executed at runtime.
    from unboundmodule import (  # noqa: F401
        MODULE_ERROR,
        MODULE_EVENT_MODDONE,
        MODULE_EVENT_NEW,
        MODULE_EVENT_PASS,
        MODULE_FINISHED,
        MODULE_WAIT_MODULE,
        PKT_QR,
        PKT_RA,
        PKT_RD,
        RCODE_NOERROR,
        RCODE_NXDOMAIN,
        RR_CLASS_IN,
        RR_TYPE_A,
        RR_TYPE_AAAA,
        RR_TYPE_ANY,
        RR_TYPE_CNAME,
        RR_TYPE_DNAME,
        RR_TYPE_MX,
        RR_TYPE_NS,
        RR_TYPE_PTR,
        RR_TYPE_SIG,
        RR_TYPE_SRV,
        RR_TYPE_TXT,
        DNSMessage,
        log_err,
        log_info,
        module_env,
        module_qstate,
        query_info,
        register_inplace_cb_reply,
        register_inplace_cb_reply_cache,
        register_inplace_cb_reply_local,
        register_inplace_cb_reply_servfail,
        reply_info,
    )

global pfb
pfb: dict[str, Any] = {}

from collections import defaultdict
from configparser import ConfigParser

# Module-level globals populated by init_standard() at runtime. Declared here
# without assignment (PEP 526) so type checkers can resolve them across the
# functions that reference them via `global`; no runtime object is created.
rcodeDB: dict[int, str]
dataDB: defaultdict[str, Any]
zoneDB: defaultdict[str, Any]
regexDB: defaultdict[str, Any]
allowRegexDB: defaultdict[str, Any]
hstsDB: defaultdict[str, Any]
whiteDB: defaultdict[str, Any]
gpListDB: defaultdict[str, Any]
noAAAADB: defaultdict[str, Any]
dnsblDB: defaultdict[str, Any]
safeSearchDB: defaultdict[str, Any]
feedGroupIndexDB: defaultdict[int, Any]
excludeDB: list[str]
excludeAAAADB: list[str]
excludeSS: list[str]
maxmindReader: Any

# Background I/O worker (file + sqlite writes off the DNS response path)
pfb_task_queue: queue.Queue
pfb_worker_thread: Any
pfb_db_queue: queue.Queue
pfb_db_worker_thread: Any
pfb_log_queue: queue.Queue
pfb_log_listener: Any
pfb_loggers: dict[str, Any] = {}

if TYPE_CHECKING:
    # Modules imported defensively in the try/except guards below. Declared here
    # unconditionally so static checkers treat them as always bound (the runtime
    # guards leave them possibly-unbound). This block never executes at runtime.
    import ipaddress
    import queue
    import sqlite3
    import threading

    import maxminddb

# Import additional python modules
try:
    import queue  # noqa: F811
    import threading  # noqa: F811

    pfb["mod_threading"] = True
    threads: list[Any] = list()
except Exception as e:
    pfb["mod_threading"] = False
    pfb["mod_threading_e"] = e
    pass

try:
    import ipaddress  # noqa: F811

    pfb["mod_ipaddress"] = True
except Exception as e:
    pfb["mod_ipaddress"] = False
    pfb["mod_ipaddress_e"] = e
    pass

try:
    import maxminddb  # noqa: F811

    pfb["mod_maxminddb"] = True
except Exception as e:
    pfb["mod_maxminddb"] = False
    pfb["mod_maxminddb_e"] = e
    pass

try:
    import sqlite3  # noqa: F811

    pfb["mod_sqlite3"] = True
except Exception as e:
    pfb["mod_sqlite3"] = False
    pfb["mod_sqlite3_e"] = e
    pass


PFB_QUEUE_MAXSIZE = 5000


def pfb_async_worker() -> None:
    # Single background consumer for file/sqlite I/O. FIFO order is preserved so
    # query counters and log lines stay consistent and chronological.
    while True:
        task = pfb_task_queue.get()
        try:
            if task is None:
                break
            func, args = task
            func(*args)
        except Exception as e:
            err = sys.__stderr__
            if err is not None:
                try:
                    err.write("[pfBlockerNG]: async I/O worker error: {}\n".format(e))
                except Exception:
                    pass
        finally:
            pfb_task_queue.task_done()


def pfb_async(func: Callable[..., Any], *args: Any) -> None:
    # Enqueue file/sqlite I/O for the background worker. Falls back to
    # synchronous execution when the worker is not running (during init, in the
    # test suite, or when threading is unavailable). Drops the task if the
    # bounded queue is saturated, so the DNS response path is never blocked.
    if pfb.get("async_worker"):
        try:
            pfb_task_queue.put_nowait((func, args))
            return
        except queue.Full:
            pfb["async_dropped"] = pfb.get("async_dropped", 0) + 1
            return
    func(*args)


def init_standard(id: int, env: module_env) -> bool:
    global \
        pfb, \
        rcodeDB, \
        dataDB, \
        zoneDB, \
        regexDB, \
        allowRegexDB, \
        hstsDB, \
        whiteDB, \
        excludeDB, \
        excludeAAAADB, \
        excludeSS, \
        dnsblDB, \
        noAAAADB, \
        gpListDB, \
        safeSearchDB, \
        feedGroupIndexDB, \
        maxmindReader, \
        pfb_task_queue, \
        pfb_worker_thread, \
        pfb_db_queue, \
        pfb_db_worker_thread

    if not register_inplace_cb_reply(inplace_cb_reply, env, id):
        log_info("[pfBlockerNG]: Failed register_inplace_cb_reply")
        return False

    if not register_inplace_cb_reply_cache(inplace_cb_reply_cache, env, id):
        log_info("[pfBlockerNG]: Failed register_inplace_cb_reply_cache")
        return False

    if not register_inplace_cb_reply_local(inplace_cb_reply_local, env, id):
        log_info("[pfBlockerNG]: Failed register_inplace_cb_reply_local")
        return False

    if not register_inplace_cb_reply_servfail(inplace_cb_reply_servfail, env, id):
        log_info("[pfBlockerNG]: Failed register_inplace_cb_reply_servfail")
        return False

    # Store previous error message to avoid repeating
    pfb["p_err"] = ""

    # Log stderr to file
    class log_stderr(object):
        def __init__(self, logger: logging.Logger) -> None:
            self.logger = logger
            self.linebuf = ""

        def write(self, msg: str) -> None:
            if msg != pfb["p_err"]:
                pfb_async(self.logger.log, logging.ERROR, msg.rstrip())
            pfb["p_err"] = msg

    # Create python error logfile
    logfile = "/var/log/pfblockerng/py_error.log"

    for i in range(2):
        try:
            logging.basicConfig(format="%(asctime)s|%(levelname)s| %(message)s", filename=logfile, filemode="a")
            break
        except IOError:
            # Remove logfile if ownership is not 'unbound:unbound'
            if os.path.isfile(logfile):
                os.remove(logfile)
    sys.stderr = log_stderr(logging.getLogger("pfb_stderr"))

    # Validate write access to log files
    for l_file in ("dnsbl", "dns_reply", "unified"):
        lfile = "/var/log/pfblockerng/" + l_file + ".log"

        try:
            if os.path.isfile(lfile) and not os.access(lfile, os.W_OK):
                new_file = "/var/log/pfblockerng/" + l_file + str(datetime.now().strftime("_%Y%m%-d%H%M%S.log"))
                os.rename(lfile, new_file)
        except Exception as e:
            sys.stderr.write("[pfBlockerNG]: Failed to validate write permission: {}.log: {}".format(l_file, e))
            if os.path.isfile(lfile):
                new_file = "/var/log/pfblockerng/" + l_file + str(datetime.now().strftime("_%Y%m%-d%H%M%S.log"))
                os.rename(lfile, new_file)
            pass

    if not pfb["mod_threading"]:
        sys.stderr.write("[pfBlockerNG]: Failed to load python module 'threading': {}".format(pfb["mod_threading_e"]))

    if not pfb["mod_ipaddress"]:
        sys.stderr.write("[pfBlockerNG]: Failed to load python module 'ipaddress': {}".format(pfb["mod_ipaddress_e"]))

    if not pfb["mod_maxminddb"]:
        sys.stderr.write("[pfBlockerNG]: Failed to load python module 'maxminddb': {}".format(pfb["mod_maxminddb_e"]))

    if not pfb["mod_sqlite3"]:
        sys.stderr.write("[pfBlockerNG]: Failed to load python module 'sqlite3': {}".format(pfb["mod_sqlite3_e"]))

    # Initialize default settings
    pfb["dnsbl_ipv4"] = ""
    pfb["dnsbl_ipv6"] = ""
    pfb["dataDB"] = False
    pfb["zoneDB"] = False
    pfb["hstsDB"] = False
    pfb["whiteDB"] = False
    pfb["regexDB"] = False
    # ADR-07 P3: allow-regex container (@@/re/) and the $important/$badfilter fast-path
    # flag. Both are inert today (no ABP rule is parsed yet) -- the matcher keeps its
    # existing early-exit path while important_rules is False (behaviour-preserving).
    pfb["allowRegexDB"] = False
    pfb["important_rules"] = False
    # ADR-07 P7 regex-safety defaults: cap OFF (nothing dropped at load unless the
    # user enables "Limit long/complex regex"); runtime warn/evict ALWAYS on at the
    # Phase-1 ceilings. The ini MAIN section overrides these.
    pfb["regex_cap"] = False
    pfb["regex_warn_ms"] = REGEX_WARN_MS_DEFAULT
    pfb["regex_evict_ms"] = REGEX_EVICT_MS_DEFAULT
    pfb["whiteDB"] = False
    pfb["gpListDB"] = False
    pfb["noAAAADB"] = False
    pfb["python_idn"] = False
    pfb["python_hsts"] = False
    pfb["python_reply"] = False
    pfb["python_cname"] = False
    pfb["safeSearchDB"] = False
    pfb["group_policy"] = False
    pfb["python_enable"] = False
    pfb["python_nolog"] = False
    pfb["python_control"] = False
    pfb["python_maxmind"] = False
    pfb["python_blocking"] = False
    pfb["python_blacklist"] = False
    pfb["sqlite3_dnsbl_con"] = False
    pfb["sqlite3_resolver_con"] = False
    pfb["async_worker"] = False

    # DNSBL Python files
    pfb["pfb_unbound.ini"] = "pfb_unbound.ini"
    pfb["pfb_py_whitelist"] = "pfb_py_whitelist.txt"
    pfb["pfb_py_zone"] = "pfb_py_zone.txt"
    pfb["pfb_py_data"] = "pfb_py_data.txt"
    pfb["pfb_py_hsts"] = "pfb_py_hsts.txt"
    pfb["pfb_py_ss"] = "pfb_py_ss.txt"
    # ADR-06: per-feed manifest (the new shell->Python boundary) and the
    # Python-emitted entry count. When the manifest is present, init builds the
    # DNSBL structures from the raw feeds via the pure build() layer (ADR-06 P4);
    # otherwise it falls back to the legacy data/zone CSV load (shell/PHP still
    # produce those files until Phase 5 removes the duplication).
    pfb["pfb_py_sources"] = "pfb_py_sources.json"
    pfb["pfb_py_count"] = "pfb_py_count"
    # ADR-07 P8: the ADMITTED (cap-filtered) feed+user regex total -- the count the
    # DNSBL_Regex UI alias reads (inc:8329). It is the live size of regexDB +
    # allowRegexDB AFTER both the user REGEX-ini load and the feed-regex merge, so
    # patterns the static cap dropped are excluded (value changes by design, ADR §2).
    pfb["pfb_py_regex_count"] = "pfb_py_regex_count"
    pfb["pfb_py_dnsbl"] = "pfb_py_dnsbl.sqlite"
    pfb["pfb_py_cache"] = "pfb_py_cache.sqlite"
    pfb["pfb_py_resolver"] = "pfb_py_resolver.sqlite"
    pfb["maxminddb"] = "/usr/local/share/GeoIP/GeoLite2-Country.mmdb"

    # Remove DNSBL cache file (For Reports tab query)
    if os.path.isfile(pfb["pfb_py_cache"]):
        os.remove(pfb["pfb_py_cache"])

    # DNSBL validation on these RR_TYPES only
    pfb["rr_types"] = (
        RR_TYPE_A,
        RR_TYPE_AAAA,
        RR_TYPE_ANY,
        RR_TYPE_CNAME,
        RR_TYPE_DNAME,
        RR_TYPE_SIG,
        RR_TYPE_MX,
        RR_TYPE_NS,
        RR_TYPE_PTR,
        RR_TYPE_SRV,
        RR_TYPE_TXT,
        64,
        65,
    )

    # List of HSTS preload TLDs
    pfb["hsts_tlds"] = (
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
    )

    # Initialize dicts/lists
    dataDB = defaultdict(list)
    zoneDB = defaultdict(list)
    dnsblDB = defaultdict(list)
    safeSearchDB = defaultdict(list)
    feedGroupIndexDB = defaultdict(list)

    regexDB = defaultdict(str)
    allowRegexDB = defaultdict(str)
    # ADR-07 P7: clear the runtime warn rate-limit + perf-fallback strike state on a
    # (re)load so a fresh regex set starts with clean warn/evict bookkeeping.
    _regex_warned.clear()
    _regex_perf_strikes.clear()
    whiteDB = defaultdict(str)
    hstsDB = defaultdict(str)
    gpListDB = defaultdict(str)
    noAAAADB = defaultdict(str)
    feedGroupDB: defaultdict[str, Any] = defaultdict(str)
    excludeDB = []
    excludeAAAADB = []
    excludeSS = []

    # Read pfb_unbound.ini settings
    if os.path.isfile(pfb["pfb_unbound.ini"]):
        config = ConfigParser()
        try:
            config.read(pfb["pfb_unbound.ini"])
        except Exception as e:
            sys.stderr.write("[pfBlockerNG]: Failed to load ini configuration: {}".format(e))
            pass

        if config.has_section("MAIN"):
            if config.has_option("MAIN", "python_enable"):
                pfb["python_enable"] = config.getboolean("MAIN", "python_enable")
            if config.has_option("MAIN", "python_reply"):
                pfb["python_reply"] = config.getboolean("MAIN", "python_reply")
            if config.has_option("MAIN", "python_blocking"):
                pfb["python_blocking"] = config.getboolean("MAIN", "python_blocking")
            if config.has_option("MAIN", "python_hsts"):
                pfb["python_hsts"] = config.getboolean("MAIN", "python_hsts")
            if config.has_option("MAIN", "python_idn"):
                pfb["python_idn"] = config.getboolean("MAIN", "python_idn")
            if config.has_option("MAIN", "python_tld_seg"):
                pfb["python_tld_seg"] = config.getint("MAIN", "python_tld_seg")
            if config.has_option("MAIN", "python_tld"):
                pfb["python_tld"] = config.getboolean("MAIN", "python_tld")
            if config.has_option("MAIN", "python_tlds"):
                pfb["python_tlds"] = config.get("MAIN", "python_tlds").split(",")
            if config.has_option("MAIN", "dnsbl_ipv4"):
                pfb["dnsbl_ipv4"] = config.get("MAIN", "dnsbl_ipv4")
            if config.has_option("MAIN", "dnsbl_ipv6"):
                pfb["dnsbl_ipv6"] = config.get("MAIN", "dnsbl_ipv6")
            if config.has_option("MAIN", "python_nolog"):
                pfb["python_nolog"] = config.getboolean("MAIN", "python_nolog")
            if config.has_option("MAIN", "python_cname"):
                pfb["python_cname"] = config.getboolean("MAIN", "python_cname")
            if config.has_option("MAIN", "python_control"):
                pfb["python_control"] = config.getboolean("MAIN", "python_control")

            # ADR-07 P7: regex-safety knobs. ``regex_cap`` is the opt-in "Limit
            # long/complex regex" static pre-filter (drops over-long/nested-quantifier
            # patterns at load -- feed AND user). ``regex_warn_ms`` / ``regex_evict_ms``
            # are the always-on runtime warn/evict ceilings (per-match thread CPU). All
            # default to OFF / the Phase-1 defaults when absent.
            if config.has_option("MAIN", "regex_cap"):
                pfb["regex_cap"] = config.getboolean("MAIN", "regex_cap")
            if config.has_option("MAIN", "regex_warn_ms"):
                try:
                    pfb["regex_warn_ms"] = config.getfloat("MAIN", "regex_warn_ms")
                except ValueError:
                    pass
            if config.has_option("MAIN", "regex_evict_ms"):
                try:
                    pfb["regex_evict_ms"] = config.getfloat("MAIN", "regex_evict_ms")
                except ValueError:
                    pass

            if pfb["dnsbl_ipv6"] == "":
                pfb["dnsbl_ipv6"] = "::"

            # List of DNS R_CODES
            rcodeDB = {
                0: "NoError",
                1: "FormErr",
                2: "ServFail",
                3: "NXDOMAIN",
                4: "NotImp",
                5: "Refused",
                6: "YXDomain",
                7: "YXRRSet",
                8: "NXRRSet",
                9: "NotAuth",
                10: "NotZone",
                11: "DSOTYPENI",
                16: "BADVERS",
                17: "BADKEY",
                18: "BADTIME",
                19: "BADMODE",
                20: "BADNAME",
                21: "BADALG",
                22: "BADTRUNC",
                23: "BADCOOKIE",
            }

        if pfb["python_enable"]:
            # Enable the Blacklist functions (IDN)
            if pfb["python_idn"]:
                pfb["python_blacklist"] = True

            # Enable the Blacklist functions (TLD Allow)
            if pfb["python_tld"] and pfb["python_tlds"] != "":
                pfb["python_blacklist"] = True

            # Collect user-defined Regex patterns
            if config.has_section("REGEX"):
                regex_config = config.items("REGEX")
                if regex_config:
                    r_count = 1
                    for name, pattern in regex_config:
                        # ADR-07 P7: the opt-in static cap also covers the un-vetted
                        # USER regex list -- an over-long / nested-quantifier user
                        # pattern is dropped at load (logged, not compiled) when the
                        # "Limit long/complex regex" setting is enabled.
                        if pfb["regex_cap"] and _regex_exceeds_static_cap(pattern):
                            sys.stderr.write(
                                "[pfBlockerNG]: dropping long/complex user regex [ {} ] pattern [ {} ] "
                                "on line #{} (static cap)".format(name, pattern, r_count)
                            )
                            r_count += 1
                            continue
                        try:
                            # ADR-07: a USER regex is SOVEREIGN -- band 5 (user block),
                            # so it beats ANY feed allow (@@ band 2 / @@$important band 4),
                            # matching the decision oracle's Provenance.USER block. Stored
                            # as the {"re","important","band"} payload the matcher scores
                            # via _block_entry_band; a bare compiled pattern would score the
                            # feed-block band 1 and be overridden by a feed @@. ($badfilter-
                            # immunity is inherent: user regex never enter the feed reconcile
                            # rule list.) A user regex never loses to a feed allow, only to
                            # the user whitelist (band 6) -- preserved by the fast path.
                            regexDB[name] = {
                                "re": re.compile(pattern),
                                "important": False,
                                "band": PRIO_USER_BLOCK,
                            }
                            pfb["regexDB"] = True
                            pfb["python_blacklist"] = True
                        except Exception as e:
                            sys.stderr.write(
                                "[pfBlockerNG]: Regex [ {} ] compile error pattern [  {}  ] on line #{}: {}".format(
                                    name, pattern, r_count, e
                                )
                            )
                            pass
                        r_count += 1

            # Collect user-defined no AAAA domains
            if config.has_section("noAAAA"):
                noaaaa_config = config.items("noAAAA")
                if noaaaa_config:
                    try:
                        for key, line in noaaaa_config:
                            data = line.rstrip("\r\n").split(",")
                            if data and len(data) == 2:
                                if data[1] == "1":
                                    wildcard = True
                                else:
                                    wildcard = False
                                noAAAADB[data[0]] = wildcard
                            else:
                                sys.stderr.write(
                                    "[pfBlockerNG]: Failed to parse: noAAAA: row:{} line:{}".format(key, line)
                                )

                        pfb["noAAAADB"] = True
                    except Exception as e:
                        sys.stderr.write("[pfBlockerNG]: Failed to load no AAAA domain list: {}".format(e))
                        pass

            # Collect user-defined Group Policy Global Bypass List
            if config.has_section("GP_Bypass_List"):
                gp_bypass_list = config.items("GP_Bypass_List")
                if gp_bypass_list:
                    try:
                        for key, line in gp_bypass_list:
                            gpListDB[line.rstrip("\r\n")] = 0

                        pfb["gpListDB"] = True
                    except Exception as e:
                        sys.stderr.write("[pfBlockerNG]: Failed to load GP Bypass List: {}".format(e))
                        pass

            # Collect SafeSearch Redirection list
            if os.path.isfile(pfb["pfb_py_ss"]):
                try:
                    with open(pfb["pfb_py_ss"]) as csv_file:
                        csv_reader = csv.reader(csv_file, delimiter=",")
                        for row in csv_reader:
                            if row and len(row) == 3:
                                safeSearchDB[row[0]] = {"A": row[1], "AAAA": row[2]}
                            else:
                                sys.stderr.write("[pfBlockerNG]: Failed to parse: {}: {}".format(pfb["pfb_py_ss"], row))

                        pfb["safeSearchDB"] = True
                except Exception as e:
                    sys.stderr.write("[pfBlockerNG]: Failed to load: {}: {}".format(pfb["pfb_py_zone"], e))
                    pass

            # ADR-06 P4: prefer BUILDING the DNSBL structures from the raw feeds via
            # the pure build() layer (the new shell->Python boundary). When the
            # per-feed manifest is present, Python parses -> normalises -> classifies
            # (data/zone) -> builds dataDB/zoneDB/feedGroupIndexDB/whiteDB and emits
            # the entry count -- it is now the source of truth for the built
            # structures. The legacy data/zone/whitelist CSV load below is the
            # FALLBACK (shell/PHP still produce those files until Phase 5 removes the
            # duplication), used only when no manifest is present. Python ignores
            # stray IP lines and never touches the firewall/IP path (DNSBL-IP stays
            # in PHP). The build call site is the future zero-downtime swap point;
            # no background-thread/restart-free behaviour is added here.
            dnsbl_built = False
            build_result = dnsbl_build_from_manifest(pfb["pfb_py_sources"])
            if build_result is not None:
                # Atomic assign of the freshly-built structures into the module
                # globals (build() mutated nothing global; this is the swap).
                dataDB = build_result.data_db
                zoneDB = build_result.zone_db
                feedGroupIndexDB = build_result.feed_group_index_db
                whiteDB = build_result.white_db

                # ADR-07 P6: MERGE the ABP feed block-regex into regexDB (preserving the
                # user-regex patterns compiled from the REGEX ini section above) and load
                # the @@/re/ allow-regex into allowRegexDB. Feed regex carry an explicit
                # band + $important; user regex stay bare compiled (feed band 1).
                regexDB.update(build_result.regex_db)
                allowRegexDB.update(build_result.allow_regex_db)

                pfb["zoneDB"] = bool(zoneDB)
                pfb["dataDB"] = bool(dataDB)
                pfb["whiteDB"] = bool(whiteDB)
                pfb["regexDB"] = bool(regexDB)
                pfb["allowRegexDB"] = bool(allowRegexDB)
                # The fast path stays byte-identical while important_rules is False; it
                # flips True only when an ABP $important / feed @@ / feed regex loaded.
                pfb["important_rules"] = bool(build_result.important_rules)
                if dataDB or zoneDB or regexDB or allowRegexDB:
                    pfb["python_blacklist"] = True

                # Emit pfb_py_count (the LOADED total) for the UI (inc:3149).
                dnsbl_emit_count(pfb["pfb_py_count"], build_result.counts)
                dnsbl_built = True

            # While reading 'data|zone' CSV files: Replace 'Feed/Group' pairs with an index value (Memory performance)
            feedGroup_index = 0

            # Zone dicts
            if not dnsbl_built and os.path.isfile(pfb["pfb_py_zone"]):
                try:
                    with open(pfb["pfb_py_zone"]) as csv_file:
                        csv_reader = csv.reader(csv_file, delimiter=",")
                        for row in csv_reader:
                            if row and len(row) == 6:
                                # Query Feed/Group/index
                                isInFeedGroupDB = feedGroupDB.get(row[4] + row[5])

                                # Add Feed/Group/index
                                if isInFeedGroupDB is None:
                                    feedGroupDB[row[4] + row[5]] = feedGroup_index
                                    feedGroupIndexDB[feedGroup_index] = {"feed": row[4], "group": row[5]}
                                    final_index = feedGroup_index
                                    feedGroup_index += 1

                                # Use existing Feed/Group/index
                                else:
                                    final_index = isInFeedGroupDB

                                zoneDB[row[1]] = {"log": row[3], "index": final_index, "important": False}
                            else:
                                sys.stderr.write(
                                    "[pfBlockerNG]: Failed to parse: {}: {}".format(pfb["pfb_py_zone"], row)
                                )

                        pfb["zoneDB"] = True
                        pfb["python_blacklist"] = True
                except Exception as e:
                    sys.stderr.write("[pfBlockerNG]: Failed to load: {}: {}".format(pfb["pfb_py_zone"], e))
                    pass

            # Data dicts
            if not dnsbl_built and os.path.isfile(pfb["pfb_py_data"]):
                try:
                    with open(pfb["pfb_py_data"]) as csv_file:
                        csv_reader = csv.reader(csv_file, delimiter=",")
                        for row in csv_reader:
                            if row and len(row) == 6:
                                # Query Feed/Group/index
                                isInFeedGroupDB = feedGroupDB.get(row[4] + row[5])

                                # Add Feed/Group/index
                                if isInFeedGroupDB is None:
                                    feedGroupDB[row[4] + row[5]] = feedGroup_index
                                    feedGroupIndexDB[feedGroup_index] = {"feed": row[4], "group": row[5]}
                                    final_index = feedGroup_index
                                    feedGroup_index += 1

                                # Use existing Feed/Group/index
                                else:
                                    final_index = isInFeedGroupDB

                                dataDB[row[1]] = {"log": row[3], "index": final_index, "important": False}
                            else:
                                sys.stderr.write(
                                    "[pfBlockerNG]: Failed to parse: {}: {}".format(pfb["pfb_py_data"], row)
                                )

                        pfb["dataDB"] = True
                        pfb["python_blacklist"] = True
                except Exception as e:
                    sys.stderr.write("[pfBlockerNG]: Failed to load: {}: {}".format(pfb["pfb_py_data"], e))
                    pass

            # Clear temporary Feed/Group/Index list
            feedGroupDB.clear()

            if pfb["python_blacklist"]:
                # Collect user-defined Whitelist (legacy CSV path -- the build()
                # already loaded whiteDB from the manifest config when dnsbl_built).
                if not dnsbl_built and os.path.isfile(pfb["pfb_py_whitelist"]):
                    try:
                        with open(pfb["pfb_py_whitelist"]) as csv_file:
                            csv_reader = csv.reader(csv_file, delimiter=",")
                            for row in csv_reader:
                                if row and len(row) == 2:
                                    if row[1] == "1":
                                        wildcard = True
                                    else:
                                        wildcard = False
                                    # ADR-07 P3: whiteDB value widens to
                                    # {"wildcard", "important"}; the legacy CSV is the
                                    # USER whitelist -> important=True (sovereignty).
                                    whiteDB[row[0]] = {"wildcard": wildcard, "important": True}
                                    pfb["whiteDB"] = True
                                else:
                                    sys.stderr.write(
                                        "[pfBlockerNG]: Failed to parse: {}: {}".format(pfb["pfb_py_whitelist"], row)
                                    )

                    except Exception as e:
                        sys.stderr.write("[pfBlockerNG]: Failed to load: {}: {}".format(pfb["pfb_py_whitelist"], e))
                        pass

                # HSTS dicts
                if pfb["python_hsts"] and os.path.isfile(pfb["pfb_py_hsts"]):
                    try:
                        with open(pfb["pfb_py_hsts"]) as hsts:
                            for line in hsts:
                                hstsDB[line.rstrip("\r\n")] = 0
                            pfb["hstsDB"] = True
                    except Exception as e:
                        sys.stderr.write("[pfBlockerNG]: Failed to load: {}: {}".format(pfb["pfb_py_hsts"], e))
                        pass

            # ADR-07 P8: emit the ADMITTED regex total for the DNSBL_Regex UI alias
            # (inc:8329). regexDB now holds USER regex (REGEX-ini) + FEED block regex
            # (merged from build()); allowRegexDB holds FEED @@/re/ allow regex. Both
            # have already had over-cap patterns dropped at load when the static cap is
            # on, so this live size is the cap-filtered admitted count (value changes by
            # design, ADR §2). Emitted whenever the plugin is enabled so the alias is
            # accurate even with feed regex but no user regex.
            dnsbl_emit_count(pfb["pfb_py_regex_count"], len(regexDB) + len(allowRegexDB))

            # Validate SQLite3 database connections
            if pfb["mod_sqlite3"]:
                # Enable Resolver query statistics
                for i in range(2):
                    try:
                        if pfb_db_validate(1):
                            pfb["sqlite3_resolver_con"] = True
                            break
                    except Exception as e:
                        sys.stderr.write(
                            "[pfBlockerNG]: Failed to open pfb_py_resolver.sqlite database (Attempt: {}/2): {}".format(
                                i + 1, e
                            )
                        )
                        pass
                        if os.path.isfile(pfb["pfb_py_resolver"]):
                            os.remove(pfb["pfb_py_resolver"])

                # Enable DNSBL statistics
                if pfb["python_blacklist"]:
                    for i in range(2):
                        try:
                            if pfb_db_validate(2):
                                pfb["sqlite3_dnsbl_con"] = True
                                break
                        except Exception as e:
                            sys.stderr.write(
                                "[pfBlockerNG]: Failed to open pfb_py_dnsbl.sqlite database (Attempt: {}/2): {}".format(
                                    i + 1, e
                                )
                            )
                            pass
                            if os.path.isfile(pfb["pfb_py_dnsbl"]):
                                os.remove(pfb["pfb_py_dnsbl"])

            # Open MaxMind db reader for DNS Reply GeoIP logging
            if pfb["mod_maxminddb"] and pfb["python_reply"] and os.path.isfile(pfb["maxminddb"]):
                try:
                    maxmindReader = maxminddb.open_database(pfb["maxminddb"])
                    pfb["python_maxmind"] = True
                except Exception as e:
                    sys.stderr.write("[pfBlockerNG]: Failed to open MaxMind DB: {}".format(e))
                    pass
    else:
        log_info("[pfBlockerNG]: Failed to load ini configuration. Ini file missing.")

    # Start background DB-write worker (persistent sqlite connection, batched)
    if pfb["mod_threading"] and not pfb.get("db_worker"):
        try:
            pfb_db_queue = queue.Queue(maxsize=PFB_DB_QUEUE_MAXSIZE)
            pfb_db_worker_thread = threading.Thread(name="pfb_db_io", target=pfb_db_worker, daemon=True)
            pfb_db_worker_thread.start()
            pfb["db_worker"] = True
        except Exception as e:
            pfb["db_worker"] = False
            sys.stderr.write("[pfBlockerNG]: Failed to start DB I/O worker: {}".format(e))

    # Start background I/O worker (off-loads file/sqlite writes from the DNS path)
    if pfb["mod_threading"] and not pfb.get("async_worker"):
        try:
            pfb_task_queue = queue.Queue(maxsize=PFB_QUEUE_MAXSIZE)
            pfb_worker_thread = threading.Thread(name="pfb_async_io", target=pfb_async_worker, daemon=True)
            pfb_worker_thread.start()
            pfb["async_worker"] = True
        except Exception as e:
            pfb["async_worker"] = False
            sys.stderr.write("[pfBlockerNG]: Failed to start async I/O worker: {}".format(e))

    pfb_setup_logging()

    log_info("[pfBlockerNG]: init_standard script loaded")
    return True


def is_idn_domain(q_name: str) -> bool:
    return q_name.startswith("xn--") or ".xn--" in q_name


def get_q_name_qstate(qstate: module_qstate | None) -> str:
    q_name = ""
    try:
        if qstate and qstate.qinfo and qstate.qinfo.qname_str and qstate.qinfo.qname_str.strip():
            q_name = qstate.qinfo.qname_str.rstrip(".")
        elif qstate and qstate.return_msg and qstate.return_msg.qinfo and qstate.return_msg.qinfo.qname_str.strip():
            q_name = qstate.return_msg.qinfo.qname_str.rstrip(".")
    except Exception as e:
        sys.stderr.write("[pfBlockerNG]: Failed get_q_name_qstate: {}".format(e))
        pass
    return is_unknown(q_name)


def get_q_name_qinfo(qinfo: query_info | None) -> str:
    q_name = ""
    try:
        if qinfo and qinfo.qname_str and qinfo.qname_str.strip():
            q_name = qinfo.qname_str.rstrip(".")
    except Exception as e:
        sys.stderr.write("[pfBlockerNG]: Failed get_q_name_qinfo: {}".format(e))
        pass
    return is_unknown(q_name)


def get_q_ip(qstate: module_qstate) -> str:
    q_ip = ""

    try:
        if qstate and qstate.mesh_info.reply_list:
            reply_list = qstate.mesh_info.reply_list
            while reply_list:
                if reply_list.query_reply:
                    q_ip = reply_list.query_reply.addr
                    break
                reply_list = reply_list.next
    except Exception as e:
        sys.stderr.write("[pfBlockerNG]: Failed get_q_ip: {}".format(e))
        pass
    return is_unknown(q_ip)


def get_q_ip_comm(kwargs: dict[str, Any] | None) -> str:
    q_ip = ""

    try:
        if kwargs and kwargs is not None and ("pfb_addr" in kwargs):
            q_ip = kwargs["pfb_addr"]
        elif kwargs and kwargs is not None and kwargs["repinfo"] and kwargs["repinfo"].addr:
            q_ip = kwargs["repinfo"].addr
    except Exception as e:
        for a in e.args:
            sys.stderr.write("[pfBlockerNG]: Failed get_q_ip_comm: {}".format(a))
        pass
    return is_unknown(q_ip)


def get_q_type(qstate: module_qstate | None, qinfo: query_info | None) -> str:
    q_type = ""
    if qstate and qstate.qinfo.qtype_str:
        q_type = qstate.qinfo.qtype_str
    elif qinfo and qinfo.qtype_str:
        q_type = qinfo.qtype_str
    return is_unknown(q_type)


def get_o_type(qstate: module_qstate | None, rep: reply_info | None) -> str:
    o_type = ""
    if qstate:
        if (
            qstate.return_msg
            and qstate.return_msg.rep
            and qstate.return_msg.rep.rrsets[0]
            and qstate.return_msg.rep.rrsets[0].rk
        ):
            o_type = qstate.return_msg.rep.rrsets[0].rk.type_str
        elif qstate.qinfo.qtype_str:
            o_type = qstate.qinfo.qtype_str
        elif rep is not None and rep.rrsets[0] is not None and rep.rrsets[0].rk is not None:
            o_type = rep.rrsets[0].rk.type_str
    return is_unknown(o_type)


def get_rep_ttl(rep: reply_info | None) -> str:
    ttl = ""
    if rep and rep.ttl:
        ttl = rep.ttl
    return str(is_unknown(ttl)).replace("Unknown", "Unk")


def get_tld(qstate: module_qstate) -> str:
    tld = ""
    if qstate and qstate.qinfo and len(qstate.qinfo.qname_list) > 1:
        tld = qstate.qinfo.qname_list[-2]
    return tld


def convert_ipv4(x: Any) -> str:
    ipv4 = ""
    if x:
        ipv4 = "{}.{}.{}.{}".format(x[2], x[3], x[4], x[5])
    return is_unknown(ipv4)


def convert_ipv6(x: Any) -> str:
    ipv6 = ""
    if x:
        ipv6 = (
            "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}"
        ).format(x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11], x[12], x[13], x[14], x[15], x[16], x[17])
    return is_unknown(ipv6)


def convert_other(x: Any) -> str:
    final = ""
    if x:
        for i in x[3:]:
            val = i
            if val == 0:
                i = "|"
            elif 1 <= val <= 12:
                i = "."
            elif val == 13:
                break
            elif val == 32:
                i = " "
            elif val == 58:
                i = ":"
            elif val <= 33 or val > 126:
                continue
            else:
                i = chr(i)
            final += i
        final = final.strip(".|")
    return is_unknown(final)


def is_unknown(x: Any) -> Any:
    try:
        if not x or x is None:
            return "Unknown"
    except Exception as e:
        for a in e.args:
            sys.stderr.write("[pfBlockerNG]: Failed is_unknown: {}".format(a))
        pass
    return x


class _NullLock:
    def __enter__(self) -> Any:
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False


# All connection access is serialized by _db_lock; connections are opened with
# check_same_thread=False so the DB worker and the synchronous fallback (init,
# tests) can share them safely under the lock.
_db_lock: Any = threading.Lock() if pfb.get("mod_threading") else _NullLock()
_db_conns: dict[int, Any] = {}

PFB_DB_QUEUE_MAXSIZE = 5000
PFB_DB_FLUSH_INTERVAL = 1.0
PFB_DB_MAX_BATCH = 2000

DB_RESOLVER = 1
DB_DNSBL = 2
DB_CACHE = 3


def _db_file(db: int) -> str:
    if db == DB_RESOLVER:
        return pfb["pfb_py_resolver"]
    if db == DB_DNSBL:
        return pfb["pfb_py_dnsbl"]
    if db == DB_CACHE:
        return pfb["pfb_py_cache"]
    return ""


def _db_create(db: int, cursor: Any) -> None:
    if db == DB_RESOLVER:
        cursor.execute("CREATE TABLE IF NOT EXISTS resolver (row integer, totalqueries integer, queries integer)")
        cursor.execute("SELECT COUNT(*) FROM resolver")
        if cursor.fetchone()[0] == 0:
            cursor.execute("INSERT INTO resolver ( row, totalqueries, queries ) VALUES ( 0, 0, 0 )")
    elif db == DB_DNSBL:
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS dnsbl ( groupname TEXT, timestamp TEXT, entries INTEGER, counter INTEGER )"
        )
    elif db == DB_CACHE:
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS dnsblcache ( type TEXT, domain TEXT, groupname TEXT, final TEXT, feed TEXT );"
        )


def _db_connect(db: int) -> Any:
    con = sqlite3.connect(_db_file(db), timeout=100000, check_same_thread=False)
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA busy_timeout=100000")
        con.execute("PRAGMA synchronous=NORMAL")
    except Exception:
        pass
    _db_create(db, con.cursor())
    con.commit()
    return con


def _db_close(db: int) -> None:
    con = _db_conns.pop(db, None)
    if con is not None:
        try:
            con.close()
        except Exception:
            pass


def _db_run(db: int, work: Callable[[Any], None]) -> bool:
    # Run work(con) against the persistent connection and commit. On fault,
    # reconnect (which re-creates the tables) and re-run, bounded retries, so a
    # dequeued write is never silently dropped on a transient error.
    with _db_lock:
        for attempt in range(4):
            try:
                con = _db_conns.get(db)
                if con is None:
                    con = _db_connect(db)
                    _db_conns[db] = con
                work(con)
                con.commit()
                return True
            except Exception as e:
                _db_close(db)
                if attempt == 3:
                    sys.stderr.write("[pfBlockerNG]: sqlite write failed db {}: {}\n".format(_db_file(db), e))
                    # Preserve historical behaviour: clear a corrupt DNSBL cache db.
                    if db == DB_CACHE:
                        try:
                            if os.path.isfile(pfb["pfb_py_cache"]):
                                os.remove(pfb["pfb_py_cache"])
                        except Exception:
                            pass
                    return False
                time.sleep(0.25)
        return False


def _db_flush_resolver(delta: int) -> bool:
    if not delta or not pfb["sqlite3_resolver_con"]:
        return True
    return _db_run(
        DB_RESOLVER,
        lambda con: con.execute("UPDATE resolver SET totalqueries = totalqueries + ? WHERE row = 0", (delta,)),
    )


def _db_flush_dnsbl(deltas: dict[str, int]) -> bool:
    if not deltas or not pfb["sqlite3_dnsbl_con"]:
        return True
    rows = [(d, g) for g, d in deltas.items()]
    return _db_run(
        DB_DNSBL, lambda con: con.executemany("UPDATE dnsbl SET counter = counter + ? WHERE groupname = ?", rows)
    )


def _db_flush_cache(rows: list[Any]) -> bool:
    if not rows:
        return True
    return _db_run(
        DB_CACHE,
        lambda con: con.executemany(
            "INSERT INTO dnsblcache (type, domain, groupname, final, feed) VALUES (?,?,?,?,?)", rows
        ),
    )


def pfb_db_validate(db: int) -> bool:
    # Ensure the database/table exists (used at init to gate statistics).
    return _db_run(db, lambda con: None)


def _db_apply(task: tuple) -> None:
    # Synchronous fallback when no DB worker is running (init, tests).
    kind = task[0]
    if kind == "resolver":
        _db_flush_resolver(1)
    elif kind == "dnsbl":
        _db_flush_dnsbl({task[1]: 1})
    elif kind == "cache":
        _db_flush_cache([task[1]])


def pfb_db_worker() -> None:
    # Batch DB writes off the DNS path. Counter increments accumulate as per-key
    # deltas (commutative); cache rows keep FIFO order. Flush on a timer, on a
    # size threshold, when idle, and on stop.
    resolver_delta = 0
    dnsbl_deltas: dict[str, int] = {}
    cache_rows: list[Any] = []
    last_flush = time.monotonic()
    stop = False

    def accumulate(t: tuple) -> None:
        nonlocal resolver_delta
        if t[0] == "resolver":
            resolver_delta += 1
        elif t[0] == "dnsbl":
            dnsbl_deltas[t[1]] = dnsbl_deltas.get(t[1], 0) + 1
        elif t[0] == "cache":
            cache_rows.append(t[1])

    def flush() -> None:
        nonlocal resolver_delta, dnsbl_deltas, cache_rows, last_flush
        if resolver_delta and _db_flush_resolver(resolver_delta):
            resolver_delta = 0
        if dnsbl_deltas and _db_flush_dnsbl(dnsbl_deltas):
            dnsbl_deltas = {}
        if cache_rows and _db_flush_cache(cache_rows):
            cache_rows = []
        last_flush = time.monotonic()

    while True:
        try:
            task = pfb_db_queue.get(timeout=PFB_DB_FLUSH_INTERVAL)
        except queue.Empty:
            task = None
        try:
            if task is not None:
                if task[0] == "stop":
                    while True:
                        try:
                            t = pfb_db_queue.get_nowait()
                        except queue.Empty:
                            break
                        try:
                            if t is not None and t[0] != "stop":
                                accumulate(t)
                        finally:
                            pfb_db_queue.task_done()
                    stop = True
                else:
                    accumulate(task)
        finally:
            if task is not None:
                pfb_db_queue.task_done()

        if (
            stop
            or task is None
            or (resolver_delta + len(dnsbl_deltas) + len(cache_rows)) >= PFB_DB_MAX_BATCH
            or (time.monotonic() - last_flush) >= PFB_DB_FLUSH_INTERVAL
        ):
            flush()
        if stop:
            break


def pfb_db_enqueue(task: tuple) -> None:
    # Enqueue a DB op for the worker; drop on a saturated queue so the DNS
    # response path is never blocked. Falls back to synchronous execution when
    # no worker is running (init, tests, threading unavailable).
    if pfb.get("db_worker"):
        try:
            pfb_db_queue.put_nowait(task)
            return
        except queue.Full:
            pfb["db_dropped"] = pfb.get("db_dropped", 0) + 1
            return
    _db_apply(task)


def get_details_dnsbl(
    m_type: str,
    qinfo: query_info | None,
    qstate: module_qstate | None,
    rep: reply_info | None,
    kwargs: dict[str, Any] | None,
) -> bool:
    global pfb, rcodeDB, dnsblDB, noAAAADB, maxmindReader

    if qstate and qstate is not None:
        q_name = get_q_name_qstate(qstate)
    elif qinfo and qinfo is not None:
        q_name = get_q_name_qinfo(qinfo)
    else:
        return True

    # Increment totalqueries counter
    if pfb["sqlite3_resolver_con"]:
        pfb_db_enqueue(("resolver",))

    # Determine if event is a 'reply' or DNSBL block
    isDNSBL = dnsblDB.get(q_name)
    if isDNSBL is not None:
        # If logging is disabled, do not log blocked DNSBL events (Utilize DNSBL Webserver)
        # except for Python nullblock events
        if pfb["python_nolog"] and not isDNSBL["null"]:
            return True

        # Increment dnsblgroup counter
        if pfb["sqlite3_dnsbl_con"] and isDNSBL["group"] != "":
            pfb_db_enqueue(("dnsbl", isDNSBL["group"]))

        dupEntry = "+"
        lastEvent = dnsblDB.get("last-event")
        if lastEvent is not None:
            if str(lastEvent) == str(isDNSBL):
                dupEntry = "-"
            else:
                dnsblDB["last-event"] = isDNSBL
        else:
            dnsblDB["last-event"] = isDNSBL

        # Skip logging
        if isDNSBL["log"] == "2":
            return True

        q_ip = get_q_ip_comm(kwargs)
        if q_ip == "Unknown":
            q_ip = "127.0.0.1"

        timestamp = make_timestamp()

        csv_line = ",".join(
            "{}".format(v)
            for v in (
                "DNSBL-python",
                timestamp,
                q_name,
                q_ip,
                isDNSBL["p_type"],
                isDNSBL["b_type"],
                isDNSBL["group"],
                isDNSBL["b_eval"],
                isDNSBL["feed"],
                dupEntry,
            )
        )
        pfb_log("/var/log/pfblockerng/dnsbl.log", csv_line)
        pfb_log("/var/log/pfblockerng/unified.log", csv_line)

    return True


def make_timestamp() -> str:
    for _ in range(2):
        try:
            return datetime.now().strftime("%b %-d %H:%M:%S")
        except TypeError:
            continue
    return ""


def _log_entry_direct(line: str, log: str) -> None:
    # Synchronous fallback used when the logging pipeline is not running (during
    # init, in the test suite, or if it failed to start): open/append/close per line.
    for i in range(1, 5):
        try:
            with open(log, "a") as append_log:
                append_log.write(line + "\n")
        except Exception as e:
            if i == 4:
                sys.stderr.write("[pfBlockerNG]: log_entry: {}: {}".format(i, e))
            time.sleep(0.25)
            continue
        break


PFB_LOG_QUEUE_MAXSIZE = 5000

PFB_LOG_FILES = (
    "/var/log/pfblockerng/dnsbl.log",
    "/var/log/pfblockerng/dns_reply.log",
    "/var/log/pfblockerng/unified.log",
)


class _PfbLogFilter(logging.Filter):
    # Route each record to exactly one file handler, by logger name.
    def __init__(self, name: str) -> None:
        super().__init__()
        self._name = name

    def filter(self, record: Any) -> bool:
        return record.name == self._name


class _PfbDropQueueHandler(logging.handlers.QueueHandler):
    # Never block the DNS path: drop the record when the bounded queue is full.
    def enqueue(self, record: Any) -> None:
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            pfb["log_dropped"] = pfb.get("log_dropped", 0) + 1


def pfb_setup_logging() -> None:
    # One persistent-handle file logger per app log, written from a single
    # QueueListener thread off the DNS path. WatchedFileHandler reopens the file
    # when it is rotated/truncated externally (the line-cap trim, the viewer clear).
    global pfb_log_queue, pfb_log_listener
    if pfb.get("log_listener"):
        return
    try:
        pfb_log_queue = queue.Queue(maxsize=PFB_LOG_QUEUE_MAXSIZE)
        handlers = []
        for path in PFB_LOG_FILES:
            name = "pfb.applog." + path
            logger = logging.getLogger(name)
            logger.setLevel(logging.INFO)
            logger.propagate = False
            logger.handlers = [_PfbDropQueueHandler(pfb_log_queue)]
            pfb_loggers[path] = logger

            handler = logging.handlers.WatchedFileHandler(path, mode="a", delay=True)
            handler.setFormatter(logging.Formatter("%(message)s"))
            handler.addFilter(_PfbLogFilter(name))
            handlers.append(handler)

        pfb_log_listener = logging.handlers.QueueListener(pfb_log_queue, *handlers)
        pfb_log_listener.start()
        pfb["log_listener"] = True
    except Exception as e:
        pfb["log_listener"] = False
        pfb_loggers.clear()
        sys.stderr.write("[pfBlockerNG]: Failed to start log listener: {}".format(e))


def pfb_log(log: str, line: str) -> None:
    # Emit a line to an app log via the async logging pipeline; fall back to a
    # synchronous append when the pipeline is not running (init, tests).
    logger = pfb_loggers.get(log)
    if logger is not None:
        logger.info(line)
    else:
        _log_entry_direct(line, log)


def get_details_reply(
    m_type: str,
    qinfo: query_info | None,
    qstate: module_qstate | None,
    rep: reply_info | None,
    kwargs: dict[str, Any] | None,
) -> bool:
    global pfb, rcodeDB, dnsblDB, noAAAADB, maxmindReader

    if qstate and qstate is not None:
        q_name = get_q_name_qstate(qstate)
    elif qinfo and qinfo is not None:
        q_name = get_q_name_qinfo(qinfo)
    else:
        return True

    q_ip = get_q_ip_comm(kwargs)
    if q_ip == "Unknown" or q_ip == "127.0.0.1":
        q_ip = "127.0.0.1"
        m_type = "resolver"

    o_type = get_q_type(qstate, qinfo)
    if m_type == "cache" or o_type == "PTR":
        q_type = o_type
    else:
        q_type = get_o_type(qstate, rep)

    # Collect 'python_control' and 'noAAAA' events from inplace_cb_reply
    if m_type == "reply-x":
        is_reply = False
        if q_name.startswith("python_control."):
            is_reply = True
        if not is_reply and q_type == "AAAA" and noAAAADB.get(q_name) is not None:
            is_reply = True

        if not is_reply:
            return True
        m_type = "reply"

    # Increment totalqueries counter (Don't include the Resolver DNS requests)
    if pfb["sqlite3_resolver_con"] and q_ip != "127.0.0.1":
        pfb_db_enqueue(("resolver",))

    # Do not log Replies, if disabled
    if not pfb["python_reply"]:
        return True

    r_addr = ""
    if rep and rep is not None:
        if rep.an_numrrsets and rep.an_numrrsets > 0:
            for i in range(0, rep.an_numrrsets):
                if rep.rrsets[i].rk and rep.rrsets[i].entry.data:
                    e = rep.rrsets[i].rk
                    if e.type_str:
                        d = rep.rrsets[i].entry.data
                        if e.type_str == "CNAME" and d.count > 1:
                            continue

                        for j in range(0, d.count):
                            x = d.rr_data[j]
                            if e.type_str == "A":
                                r_addr = convert_ipv4(x)
                                break
                            elif e.type_str == "AAAA":
                                if pfb["mod_ipaddress"]:
                                    r_addr = convert_ipv6(x)
                                    try:
                                        r_addr = ipaddress.ip_address(r_addr).compressed
                                    except Exception as ex:
                                        sys.stderr.write(
                                            "[pfBlockerNG]: Failed to compress IPv6: {}, {}".format(r_addr, ex)
                                        )
                                        pass
                                break
                            elif e.type_str in ("DNSKEY", "DS"):
                                r_addr = "DNSSEC"
                                break
                            else:
                                r_addr = r_addr + "|" + convert_other(x)
                                r_addr = r_addr.strip("|")
                            if not r_addr:
                                r_addr = "NXDOMAIN"

        else:
            # No Answer section found
            r_addr = "NXDOMAIN"

    # Collect RCODE for non-NOError codes
    try:
        if qstate and qstate.return_rcode is not None and qstate.return_rcode != 0:
            isrcode = rcodeDB.get(qstate.return_rcode)
            if isrcode is not None:
                r_addr = isrcode
    except Exception as e:
        sys.stderr.write("[pfBlockerNG]: RCODE {}: {}".format(e, q_name))
        pass

    r_addr = is_unknown(r_addr)

    if q_type == "SOA" and r_addr == "NXDOMAIN":
        r_addr = "SOA"

    if q_type == "NSEC3" and r_addr == "NXDOMAIN":
        r_addr = "NSEC3"

    if q_type == "NS" and q_name == "Unknown":
        q_name = "NS"

    # Determine if domain was noAAAA blocked
    if r_addr == "NXDOMAIN" and q_type == "AAAA" and noAAAADB.get(q_name) is not None:
        r_addr = "noAAAA"

    if pfb["python_maxmind"] and r_addr not in ("", "Unknown", "NXDOMAIN", "NODATA", "DNSSEC", "SOA", "NS"):
        version: int | str = ""
        try:
            version = ipaddress.ip_address(r_addr).version
        except Exception:
            pass

        if version != "":
            try:
                isPrivate = ipaddress.ip_address(r_addr).is_private
                isLoopback = ipaddress.ip_address(r_addr).is_loopback

                if isPrivate:
                    iso_code = "prv"
                elif isLoopback:
                    iso_code = "l.b."
                else:
                    geoip = maxmindReader.get(r_addr)
                    if geoip:
                        if "country" in geoip:
                            country = geoip["country"]
                            if "iso_code" in country:
                                iso_code = geoip["country"]["iso_code"]
                            else:
                                iso_code = "unk"
                        elif "continent" in geoip:
                            continent = geoip["continent"]
                            if "code" in continent:
                                iso_code = geoip["continent"]["code"]
                            else:
                                iso_code = "unk"
                        else:
                            iso_code = "unk"
                    else:
                        iso_code = "unk"

            except Exception as e:
                sys.stderr.write("[pfBlockerNG]: MaxMind Reader failed: {}: IP: {}".format(e, r_addr))
                iso_code = "unk"
                pass
        else:
            iso_code = "unk"
    else:
        iso_code = "unk"

    ttl = get_rep_ttl(rep)
    # Cached TTLs are in unix timestamp (time remaining)
    if m_type == "cache":
        if ttl.isdigit() and len(ttl) == 10:
            ttl = str(int(ttl) - int(time.time()))
        else:
            ttl = ""

    timestamp = make_timestamp()

    csv_line = ",".join(
        "{}".format(v) for v in ("DNS-reply", timestamp, m_type, o_type, q_type, ttl, q_name, q_ip, r_addr, iso_code)
    )
    pfb_log("/var/log/pfblockerng/dns_reply.log", csv_line)
    pfb_log("/var/log/pfblockerng/unified.log", csv_line)

    return True


# Is sleep duration valid
def python_control_duration(duration: str) -> int | bool:

    try:
        if duration.isnumeric():
            value = int(duration)
            if 0 < value <= 3600:
                return value
        return False
    except Exception as e:
        sys.stderr.write("[pfBlockerNG] python_control_duration: {}".format(e))
        pass
    return False


# Is thread still active
def python_control_thread(tname: str) -> bool:
    global threads

    try:
        for t in threading.enumerate():
            if t.name == tname:
                return True
    except Exception as e:
        sys.stderr.write("[pfBlockerNG] python_control_thread: {}".format(e))
        pass
    return False


# Python_control Start Thread
def python_control_start_thread(tname: str, fcall: Callable[..., Any], arg1: Any, arg2: Any) -> bool:
    global threads

    try:
        t1 = threading.Thread(name=tname, target=fcall, args=(arg1, arg2), daemon=True)
        threads.append(t1)
        t1.start()
        return True
    except Exception as e:
        sys.stderr.write("[pfBlockerNG] python_control_start_thread: {}".format(e))
        pass
    return False


# Python_control sleep timer
def python_control_sleep(duration: int, arg: Any) -> bool:
    global pfb

    try:
        time.sleep(duration)
        pfb["python_blacklist"] = True
    except Exception as e:
        sys.stderr.write("[pfBlockerNG] python_control_sleep: {}".format(e))
        pass
    return True


# Python_control Add Bypass IP for specified duration
def python_control_addbypass(duration: int, b_ip: str) -> bool:
    global pfb, gpListDB

    try:
        time.sleep(duration)
        if gpListDB.get(b_ip) is not None:
            gpListDB.pop(b_ip)
            return True
    except Exception as e:
        sys.stderr.write("[pfBlockerNG] python_control_addbypass: {}".format(e))
        pass
    return False


def inplace_cb_reply(
    qinfo: query_info,
    qstate: module_qstate,
    rep: reply_info,
    rcode: int,
    edns: Any,
    opt_list_out: Any,
    region: Any,
    **kwargs: Any,
) -> bool:
    get_details_reply("reply-x", qinfo, qstate, rep, kwargs)
    return True


def inplace_cb_reply_cache(
    qinfo: query_info,
    qstate: module_qstate,
    rep: reply_info,
    rcode: int,
    edns: Any,
    opt_list_out: Any,
    region: Any,
    **kwargs: Any,
) -> bool:
    get_details_reply("cache", qinfo, qstate, rep, kwargs)
    return True


def inplace_cb_reply_local(
    qinfo: query_info,
    qstate: module_qstate,
    rep: reply_info,
    rcode: int,
    edns: Any,
    opt_list_out: Any,
    region: Any,
    **kwargs: Any,
) -> bool:
    get_details_reply("local", qinfo, qstate, rep, kwargs)
    return True


def inplace_cb_reply_servfail(
    qinfo: query_info,
    qstate: module_qstate,
    rep: reply_info,
    rcode: int,
    edns: Any,
    opt_list_out: Any,
    region: Any,
    **kwargs: Any,
) -> bool:
    get_details_reply("servfail", qinfo, qstate, rep, kwargs)
    return True


def deinit(id: int) -> bool:
    global pfb, maxmindReader, pfb_task_queue, pfb_worker_thread, pfb_db_queue, pfb_db_worker_thread

    if pfb["python_maxmind"]:
        maxmindReader.close()

    # Drain and stop the background DB-write worker, then close connections
    if pfb.get("db_worker"):
        try:
            pfb_db_queue.put(("stop",))
            pfb_db_worker_thread.join(timeout=5)
        except Exception:
            pass
        pfb["db_worker"] = False
    # Close under the lock: if the worker outlived the join timeout it may still be
    # mid-_db_run (which holds _db_lock), so serialize the close to avoid a race.
    with _db_lock:
        for _db in list(_db_conns.keys()):
            _db_close(_db)

    # Stop the logging pipeline (QueueListener flushes queued records on stop)
    if pfb.get("log_listener"):
        try:
            pfb_log_listener.stop()
        except Exception:
            pass
        pfb["log_listener"] = False

    # Drain and stop the background I/O worker
    if pfb.get("async_worker"):
        try:
            pfb_task_queue.put(None)
            pfb_worker_thread.join(timeout=5)
        except Exception:
            pass
        pfb["async_worker"] = False

    log_info("[pfBlockerNG]: pfb_unbound.py script exiting")
    return True


def inform_super(id: int, qstate: module_qstate, superqstate: module_qstate, qdata: Any) -> bool:
    return True


# --------------------------------------------------------------------------- #
# DNSBL build layer (ADR-06) -- pure, stdlib-only, Unbound-symbol-free.
#
# Moves the DNSBL list preprocessing (parse -> normalise -> classify data/zone ->
# build dicts) out of shell/PHP into this plugin. The boundary is "shell/PHP fetch
# + tag; Python parse -> normalise -> classify -> build dicts -> emit counts"
# (ADR.md SS2). The layer is wired into init() via dnsbl_build_from_manifest()
# (Phase 4), and the duplicated shell/PHP preprocessing has since been removed
# (Phase 5); decision-equivalence is pinned against the Phase-2 oracle.
#
# Design notes the contract pins (RESULTS/01_Results.txt, RESULTS/02_Results.txt):
#   * Build-time OPTIMISATIONS are dropped, not reimplemented: no within/cross-feed
#     dedup, no subdomain collapse, no build-time user-whitelist or TOP1M removal.
#     The dict load dedups keys for free (last-wins) and redundant subdomains stay
#     because the parent zone still matches them.
#   * Data/zone CLASSIFICATION is kept (it is not an optimisation) and mirrors
#     tld_analysis/tld_search exactly: a registrable parent -> wildcard ZONE; a
#     deeper sub-domain whose parent is not a known public suffix -> exact DATA;
#     TLD exclusion forces exact DATA; a blacklisted TLD -> a whole-TLD ZONE entry.
#   * Whitelisting is QUERY-TIME: build() loads the user whitelist into whiteDB
#     (input normalisation moves here) and loads the TOP1M list into whiteDB ONLY
#     when enabled. No list pruning at build time.
#   * IP extraction is NOT Python's job -- it stays in PHP (Phase 5). The parser
#     SKIPS non-domain lines (bare IPs fail domain validation); it never produces
#     firewall input.
#   * ENTRY MODEL: every entry carries a ``kind`` tag (block | allow | regex) so the
#     model is ABP-ready, BUT this phase produces ONLY ``block`` and still IGNORES
#     ``@@`` exceptions, regex rules, element-hiding (``##`` / ``#@#``), path/URL
#     rules and non-domain ``$options`` -- exactly as today. The allow/regex kinds
#     and their query-time matching are the future ABP ADR, not here.
#   * build() is REENTRANT: it returns a NEW structure-set and mutates no module
#     global, so a future zero-downtime reload can run it on a background thread and
#     atomically swap the result in (the swap itself is not built here).
#
# No Unbound symbol is referenced below; only the stdlib (csv) is used.
# --------------------------------------------------------------------------- #

# Entry kinds (ABP-ready seam). The ADR-06 plain/hosts/csv path emits ONLY BLOCK;
# the ADR-07 ABP Stage-A parser (``parse_abp``) emits BLOCK *and* ALLOW. ``REGEX``
# here is an entry kind kept for the legacy ParsedEntry seam; the ABP Rule model
# below uses ``RULE_TARGET_*`` to say whether a rule targets a domain or a regex.
DNSBL_KIND_BLOCK = "block"
DNSBL_KIND_ALLOW = "allow"
DNSBL_KIND_REGEX = "regex"

# Classification outcomes for an entry's key.
DNSBL_CLASS_DATA = "data"  # exact match  (loaded into dataDB)
DNSBL_CLASS_ZONE = "zone"  # wildcard-incl-self match (loaded into zoneDB)

# --------------------------------------------------------------------------- #
# ADR-07 -- the intermediate ABP Rule model (Stage A).
#
# ``parse_abp(line, ...) -> Rule | None`` turns one raw ABP line into a typed
# Rule (or None to skip). This is PURE + ADDITIVE: it is NOT wired into build()
# / init in this phase (the reconcile/reduce/emit + the live matcher are later
# phases). The reference TARGET for this parser is the Phase-2 oracle
# (tests/test_adr07_decision_spec.py::parse_abp_line); this production parser
# agrees with it on every corpus line.
#
# A Rule's ``target`` says what it matches:
#   RULE_TARGET_DOMAIN -- an exact-or-wildcard domain literal (``wildcard`` says
#                         whether subdomains are covered); ``key`` is the domain.
#   RULE_TARGET_REGEX  -- an irreducible regex pattern (NOT compiled here -- the
#                         raw inner pattern is stored in ``key``; compile/load is
#                         a later phase, runtime safety is a later phase).
# A Rule's ``kind`` is DNSBL_KIND_BLOCK (``||`` / hosts / plain / ``/re/``) or
# DNSBL_KIND_ALLOW (``@@||`` / ``@@/re/``).
# A Rule's ``provenance`` is RULE_PROV_FEED (a downloaded feed line) or
# RULE_PROV_USER (a user-supplied rule -- sovereign, $badfilter-immune, fact 7).
# --------------------------------------------------------------------------- #
RULE_TARGET_DOMAIN = "domain"
RULE_TARGET_REGEX = "regex"

RULE_PROV_USER = "user"
RULE_PROV_FEED = "feed"

# Lower-cased label alphabet for the domain-shape gate (mirrors PFB_FILTER_DOMAIN,
# pfblockerng.inc:7995-8016: labels of [a-z0-9-], not edge-hyphenated, with a dot).
_DNSBL_LABEL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")


@dataclass(frozen=True)
class Rule:
    """One typed, DNS-only ABP rule (Stage A) -- the output of ``parse_abp``.

    This is the intermediate model the reconcile / precedence stages (Phase 5+)
    stand on; it carries everything ``$badfilter`` / ``$important`` / provenance
    resolution need, none of which can survive being folded into a domain-keyed
    dict. Mirrors the Phase-2 oracle Rule (tests/test_adr07_decision_spec.py) and
    RESULTS/01_Results.txt SS1c.

    Fields:
        kind            DNSBL_KIND_BLOCK (``||`` / hosts / plain / ``/re/``) or
                        DNSBL_KIND_ALLOW (``@@||`` / ``@@/re/``).
        target          RULE_TARGET_DOMAIN (``key_or_pattern`` is a domain literal;
                        ``wildcard`` says whether subdomains are covered) or
                        RULE_TARGET_REGEX (``key_or_pattern`` is the raw inner regex
                        pattern -- NOT compiled here; compile/load is a later phase).
        key_or_pattern  the validated, lower-cased domain (DOMAIN) or the raw regex
                        inner pattern (REGEX).
        wildcard        DOMAIN only: True -> domain + all subdomains (zone); False ->
                        exact (data). Ignored for REGEX.
        important       the rule carried ``$important`` (raises its feed band 1/2 ->
                        3/4). Always meaningless for, but recorded on, USER rules
                        (they are sovereign regardless).
        badfilter       the rule carried ``$badfilter`` (feed-only prune key; the
                        rule itself emits no decision -- Phase 5 consumes it).
        provenance      RULE_PROV_USER (sovereign, $badfilter-immune, fact 7) or
                        RULE_PROV_FEED.
        feed/group/log  the per-feed manifest row metadata (attached by the caller;
                        ``parse_abp`` plumbs whatever it is given through unchanged).
        signature       the ``$badfilter`` match key:
                        ``(key_or_pattern, tuple(sorted DNS-options)) MINUS $badfilter``.
                        Two rules with the same signature are the same target+options
                        (a feed ``$badfilter`` prunes a feed rule with a matching
                        signature in Phase 5).
    """

    kind: str
    target: str
    key_or_pattern: str
    important: bool
    badfilter: bool
    provenance: str
    feed: str
    group: str
    log: str
    signature: tuple[str, tuple[str, ...]]
    wildcard: bool = False


@dataclass
class ParsedEntry:
    """One parsed feed line, pre-normalisation.

    ``kind`` is the ABP-ready tag; this phase only ever sets ``DNSBL_KIND_BLOCK``.
    ``value`` is the raw domain token extracted from the line (not yet validated /
    lower-cased). ``feed`` / ``group`` / ``log`` come from the per-feed manifest row.
    """

    kind: str
    value: str
    feed: str
    group: str
    log: str


@dataclass
class DnsblEntry:
    """A normalised, classified blocklist entry ready to load into the matcher dicts.

    ``cls`` is ``DNSBL_CLASS_DATA`` (exact) or ``DNSBL_CLASS_ZONE`` (wildcard); ``key``
    is the registrable parent for a ZONE or the exact domain for DATA.
    """

    kind: str
    cls: str
    key: str
    feed: str
    group: str
    log: str


@dataclass
class BuildResult:
    """The structure-set build() returns -- decision-equivalent to the loader
    contract (RESULTS/01_Results.txt SS1f). All dicts are FRESH (no module global
    is mutated), so the result is safe to atomically swap in later.

    Shapes (ADR-07 widened payloads). For a non-ABP (plain/hosts/csv) build every
    ``important`` is ``False`` and ``band`` is the feed-block band (1); the ABP path
    (Phase 6, format_hint='abp') sets ``important``/``band`` from the reconciled rule:
        data_db[domain]          = {"log": <"0"|"1"|"2">, "index": <int>, "important": bool, "band": int}
        zone_db[registrable]     = {"log": <flag>,        "index": <int>, "important": bool, "band": int}
        feed_group_index_db[idx] = {"feed": <str>, "group": <str>}
        white_db[domain]         = {"wildcard": bool, "important": bool, "band": int}
        regex_db[name]           = {"re": <compiled>, "important": bool, "band": int}   (ABP block-regex)
        allow_regex_db[name]     = {"re": <compiled>, "important": bool, "band": int}   (ABP @@/re/ allow-regex)
    ``important_rules`` is the build-emitted fast-path gate (ADR.md SS2): True iff any
    surviving rule needs the numeric 6-band branch (any $important / feed @@ / feed
    regex). ``counts`` is the LOADED total (len(data_db) + len(zone_db)); init emits
    it as pfb_py_count (its value legitimately rises -- lists are un-pruned).
    ``regex_count`` is the ADMITTED feed-regex total for the DNSBL_Regex alias (UI).
    """

    data_db: dict[str, dict[str, Any]]
    zone_db: dict[str, dict[str, Any]]
    feed_group_index_db: dict[int, dict[str, str]]
    white_db: dict[str, dict[str, Any]]
    counts: int
    regex_db: dict[str, dict[str, Any]] = field(default_factory=dict)
    allow_regex_db: dict[str, dict[str, Any]] = field(default_factory=dict)
    important_rules: bool = False
    regex_count: int = 0


def _dnsbl_is_ipv4(token: str) -> bool:
    """Mirror is_ipaddrv4: dotted-quad, each octet 0-255, no leading zeros.

    Used only to RECOGNISE and SKIP bare-IP lines (the firewall path stays in PHP);
    Python never emits IPs.
    """
    parts = token.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not (0 <= int(p) <= 255) or (len(p) > 1 and p[0] == "0"):
            return False
    return True


def _dnsbl_parse_abp_line(line: str) -> str | None:
    """Current basic-ABP token-strip (pfblockerng.inc:7706-7717).

    Keep ONLY a plain ``||domain^`` network line and strip the ``||`` / ``^`` tokens
    to a bare domain. IGNORE everything else exactly as today: ``@@`` exceptions,
    ``##`` / ``#@#`` element-hiding, ``$options``, ``*`` and ``/`` (path / regex).
    Returns the bare domain or ``None``. (The future ABP ADR replaces this.)
    """
    if not line.startswith("||") or not line.endswith("^"):
        return None
    if "$" in line or "*" in line or "/" in line:
        return None
    return line[2:-1]


# --------------------------------------------------------------------------- #
# ADR-07 Stage-A -- DNS-only ABP option / scope classification.
#
# A ``$options`` tail is KEPT only if EVERY option is DNS-relevant ($important /
# $badfilter). Any page-context option ($third-party / $domain= / $script /
# $image / $csp / ...), any non-DNS AdGuard modifier whose only effect is a
# rewrite ($dnsrewrite / $dnstype / $client / $ctag), OR any UNRECOGNISED option
# makes the whole rule out of DNS scope -> the rule is skipped (parse_abp returns
# None). Mirrors the Phase-2 oracle _classify_options + ADR.md SS2 "Scope".
# --------------------------------------------------------------------------- #
# Options that DO modify a DNS block/allow decision (kept):
_DNSBL_DNS_RELEVANT_OPTS = frozenset({"important", "badfilter"})
# Options that imply a page/element context, never a DNS decision (-> SKIP rule):
_DNSBL_PAGE_CONTEXT_OPTS = frozenset(
    {
        "third-party",
        "~third-party",
        "domain",  # $domain=...
        "script",
        "image",
        "stylesheet",
        "object",
        "subdocument",
        "document",
        "xmlhttprequest",
        "websocket",
        "ping",
        "media",
        "font",
        "popup",
        "csp",
        "elemhide",
        "generichide",
        "genericblock",
        "rewrite",  # $rewrite= (response rewriting, not a DNS decision)
    }
)
# AdGuard DNS modifiers whose ONLY effect is a rewrite, not block/allow (-> SKIP):
_DNSBL_NON_DNS_MODIFIERS = frozenset({"dnsrewrite", "dnstype", "client", "ctag"})


def _dnsbl_opt_name(opt: str) -> str:
    """Bare option name: drop a ``=value`` tail and a leading ``~`` is preserved
    only via the explicit ``~third-party`` membership (we never KEEP a ``~`` opt)."""
    return opt.split("=", 1)[0].strip()


def _dnsbl_classify_options(opts_str: str) -> tuple[tuple[str, ...], bool, bool] | None:
    """Parse the ``$...`` suffix. Return ``(sorted_dns_opts, important, badfilter)``
    if EVERY option is DNS-relevant, else ``None`` (skip the rule).

    ``sorted_dns_opts`` is the sorted tuple of DNS-relevant option NAMES that are
    NOT ``$badfilter`` (i.e. ``("important",)`` or ``()``) -- it feeds the rule's
    $badfilter signature (Phase 5). A page-context option, a non-DNS modifier, or
    an unrecognised option returns None (conservative: never invent a DNS decision
    for a modifier we do not model).
    """
    important = False
    badfilter = False
    kept: list[str] = []
    for raw in opts_str.split(","):
        raw = raw.strip()
        if not raw:
            continue
        name = _dnsbl_opt_name(raw)
        if name in _DNSBL_PAGE_CONTEXT_OPTS or name in _DNSBL_NON_DNS_MODIFIERS:
            return None
        if name == "important":
            important = True
            kept.append(name)
            continue
        if name == "badfilter":
            badfilter = True
            continue  # excluded from the signature by design
        # An unrecognised option -> out of DNS scope (skip the whole rule).
        return None
    return tuple(sorted(kept)), important, badfilter


def _dnsbl_parse_abp_regex(stripped: str) -> tuple[str, str, str] | None:
    """Recognise a regex rule. Return ``(kind, inner, opts_str)`` for ``/re/`` (block)
    or ``@@/re/`` (allow), with an OPTIONAL ``$options`` suffix after the closing
    slash (``/re/$important``, ``@@/re/$badfilter``); else ``None``. ``inner`` is the
    raw pattern between the slashes (NOT compiled here -- reduction is Phase 5,
    compile/load is Phase 6); ``opts_str`` is the ``$``-suffix (without the ``$``) or
    "" when absent. The closing slash is the last ``/`` of the rule (no options) or
    the ``/`` immediately preceding ``$`` (options) -- so a ``/`` inside the pattern
    body does not end it."""
    if stripped.startswith("@@/"):
        kind, body = DNSBL_KIND_ALLOW, stripped[2:]
    elif stripped.startswith("/"):
        kind, body = DNSBL_KIND_BLOCK, stripped
    else:
        return None
    # body now starts with the opening "/". A regex rule is "/<inner>/" optionally
    # followed by "$<options>". Find the closing slash + options tail.
    if body.endswith("/"):
        inner, opts_str = body[1:-1], ""
    else:
        # options present: the closing slash is the one directly before "/$".
        marker = body.rfind("/$")
        if marker <= 0:
            return None
        inner, opts_str = body[1:marker], body[marker + 2 :]
    if not inner:
        return None
    return kind, inner, opts_str


def parse_abp(
    line: str,
    *,
    provenance: str = RULE_PROV_FEED,
    feed: str = "",
    group: str = "",
    log: str = "",
) -> Rule | None:
    """The full DNS-only ABP Stage-A parser: one raw ABP line -> a typed ``Rule``
    (or ``None`` to skip). PURE -- no Unbound symbol, no side effect; NOT wired into
    build()/init this phase. The reference TARGET is the Phase-2 oracle
    (tests/test_adr07_decision_spec.py::parse_abp_line); this agrees with it on
    every corpus line.

    KEEP (-> Rule):
        ``||domain^`` (+DNS-options)                 block, domain, wildcard
        ``@@||domain^`` (+DNS-options)               allow, domain, wildcard
        ``<ip> domain`` (hosts)                      block, domain, wildcard
        plain bare ``domain``                        block, domain, wildcard
        ``/re/`` (block) / ``@@/re/`` (allow)        block/allow, regex (raw inner)
    SKIP (-> None):
        comment / control (``!`` / ``[``), plain ``#`` lines, element-hiding
        (``##`` / ``#@#`` / ``#?#`` / ``#%#`` / ``#$#``), path/URL rules (``/`` or
        ``*`` in the anchor), page-context / non-DNS / unrecognised ``$options``,
        and IP-VALUED anchors (``||1.2.3.4^``, hosts ``<ip> <ip>``) -- those are the
        PHP firewall path (no-leak contract, ADR-06 fact 7).

    ``feed`` / ``group`` / ``log`` / ``provenance`` are plumbed through unchanged
    (the caller supplies them from the manifest row). Domain targets pass through
    ``normalise()`` (lower-case + shape gate); an invalid domain -> ``None``.
    """
    s = line.strip()
    if not s:
        return None
    # comment / control headers
    if s.startswith("!") or s.startswith("["):
        return None
    if s.startswith("#"):
        # a plain-feed ``#`` comment (element-hiding needs a ``##`` token, caught next)
        return None
    # element-hiding / cosmetic (``##`` / ``#@#`` / ``#?#`` / ``#%#`` / ``#$#``) -> SKIP
    if "##" in s or "#@#" in s or "#?#" in s or "#%#" in s or "#$#" in s:
        return None

    # ---- regex rules: /re/ (block) or @@/re/ (allow) --------------------- #
    regex_hit = _dnsbl_parse_abp_regex(s)
    if regex_hit is not None:
        kind, inner, opts_str = regex_hit
        if opts_str:
            classified = _dnsbl_classify_options(opts_str)
            if classified is None:
                return None  # page-context / non-DNS / unrecognised -> skip whole rule
            dns_opts, important, badfilter = classified
        else:
            dns_opts, important, badfilter = (), False, False
        return Rule(
            kind=kind,
            target=RULE_TARGET_REGEX,
            key_or_pattern=inner,
            important=important,
            badfilter=badfilter,
            provenance=provenance,
            feed=feed,
            group=group,
            log=log,
            signature=(inner, dns_opts),
            wildcard=False,
        )

    # ---- network rules: @@||domain^ (allow) / ||domain^ (block) ---------- #
    is_allow = s.startswith("@@||")
    is_block = s.startswith("||")
    if is_allow or is_block:
        rest = s[4:] if is_allow else s[2:]
        anchor, _, opts_str = rest.partition("$")
        # split the anchor at the ABP separator ``^``; reject any path token
        host = anchor.split("^", 1)[0]
        tail = anchor.split("^", 1)[1] if "^" in anchor else ""
        if "/" in host or "*" in host or "/" in tail or tail.strip("^"):
            return None
        if _dnsbl_is_ipv4(host):
            return None  # IP-anchored -> PHP firewall path; Python skips (no leak)
        dom = normalise(host)
        if dom is None:
            return None
        if opts_str:
            classified = _dnsbl_classify_options(opts_str)
            if classified is None:
                return None
            dns_opts, important, badfilter = classified
        else:
            dns_opts, important, badfilter = (), False, False
        return Rule(
            kind=DNSBL_KIND_ALLOW if is_allow else DNSBL_KIND_BLOCK,
            target=RULE_TARGET_DOMAIN,
            key_or_pattern=dom,
            important=important,
            badfilter=badfilter,
            provenance=provenance,
            feed=feed,
            group=group,
            log=log,
            signature=(dom, dns_opts),
            wildcard=True,  # ||domain^ / @@||domain^ cover the domain + subdomains
        )

    # ---- hosts: "<ip> <domain>" ----------------------------------------- #
    if " " in s:
        first, _, target = s.partition(" ")
        target = target.strip()
        if not _dnsbl_is_ipv4(first):
            return None  # not a hosts line (a real ABP line never has a bare space)
        if _dnsbl_is_ipv4(target):
            return None  # "<ip> <ip>" -> firewall path
        dom = normalise(target)
        if dom is None:
            return None
        return Rule(
            kind=DNSBL_KIND_BLOCK,
            target=RULE_TARGET_DOMAIN,
            key_or_pattern=dom,
            important=False,
            badfilter=False,
            provenance=provenance,
            feed=feed,
            group=group,
            log=log,
            signature=(dom, ()),
            wildcard=True,  # plain/hosts cover the domain + subdomains (Phase-2 spec)
        )

    # ---- bare plain domain ---------------------------------------------- #
    if "/" in s or "*" in s:
        return None
    dom = normalise(s)
    if dom is None:
        return None
    return Rule(
        kind=DNSBL_KIND_BLOCK,
        target=RULE_TARGET_DOMAIN,
        key_or_pattern=dom,
        important=False,
        badfilter=False,
        provenance=provenance,
        feed=feed,
        group=group,
        log=log,
        signature=(dom, ()),
        wildcard=True,
    )


def _dnsbl_strip_hosts_prefix(line: str) -> str:
    """Hosts format: ``<sink-ip> <domain>`` -> take the domain token (inc:7899-7907).

    Handles ``0.0.0.0 domain`` and ``127.0.0.1 domain``; a non-IP first token keeps
    the chars before the space (PHP's behaviour).
    """
    if " " in line:
        first, _, rest = line.partition(" ")
        rest = rest.strip()
        if _dnsbl_is_ipv4(first):
            return rest
        return first
    return line


def parse(format_hint: str, line: str) -> ParsedEntry | None:
    """Parse one raw feed line into a kind-tagged block entry, or ``None`` to skip.

    ``format_hint`` dispatches the per-format handler (the manifest replaces the old
    in-loop CSV-type sniffing). This subsumes the current basic-ABP token-strip and
    reproduces today's per-format behaviour, including which lines are IGNORED.

    Bare-IP lines and the csv:pon col-0 IP are NOT returned here -- IP extraction is
    a PHP/firewall concern (Phase 5); a stray bare IP simply yields ``None`` (and
    would fail domain validation anyway). ``feed`` / ``group`` / ``log`` are attached
    by build() from the manifest row, so parse() only resolves the domain token.

    NOTE: the ABP-ready ``kind`` field is always ``DNSBL_KIND_BLOCK`` in this phase;
    ``@@`` / regex / element / ``$options`` lines are dropped, not emitted as allow /
    regex kinds (that is the future ABP ADR).
    """
    stripped = line.strip()
    if not stripped:
        return None

    if format_hint == "abp":
        # ABP control / comment lines (header, '!', '[') are dropped first.
        if stripped.startswith("!") or stripped.startswith("["):
            return None
        host = _dnsbl_parse_abp_line(stripped)
        if host is None:
            return None
        return ParsedEntry(kind=DNSBL_KIND_BLOCK, value=host, feed="", group="", log="")

    if format_hint == "csv:pon":
        # 9-col CSV: domain = col2 (always kept). col0 is handled by the PHP DNSBL-IP
        # pass (Phase 5); Python ignores it here.
        if stripped.startswith("!") or stripped.lower().startswith("timestamp"):
            return None
        try:
            row = next(csv.reader([stripped]))
        except (csv.Error, StopIteration):
            return None
        if len(row) != 9:
            return None
        domain = row[2]
        if not domain:
            return None
        return ParsedEntry(kind=DNSBL_KIND_BLOCK, value=domain, feed="", group="", log="")

    # hosts / plain
    if stripped.startswith("#") or stripped.startswith("!"):
        return None
    token = _dnsbl_strip_hosts_prefix(stripped)
    token = token.strip().strip(".")
    if not token:
        return None
    # Bare IP -> firewall path (PHP); skipped from the domain build.
    if _dnsbl_is_ipv4(token):
        return None
    return ParsedEntry(kind=DNSBL_KIND_BLOCK, value=token, feed="", group="", log="")


def normalise(value: str) -> str | None:
    """Lower-case + PFB_FILTER_DOMAIN domain-shape gate (inc:7995-8016).

    Returns the validated, lower-cased domain or ``None`` when the token is not a
    valid domain (which is how stray non-domain entries -- including any IP that
    slipped past parse() -- are dropped without ever reaching the dicts).
    """
    host = value.strip().strip(".").lower()
    if "." not in host:
        return None
    for label in host.split("."):
        if not label or label[0] == "-" or label[-1] == "-":
            return None
        if any(c not in _DNSBL_LABEL_CHARS for c in label):
            return None
    return host


def _dnsbl_load_tld_master(
    suffix_lines: Iterable[str],
    tld_blacklist: Iterable[str],
    tld_exclusion: Iterable[str],
) -> dict[str, dict[str, str]]:
    """Build the public-suffix oracle tlds[tld][full-suffix] (tld_analysis:2630-2642),
    minus any blacklisted or excluded TLD (inc:2749-2751 / 2791-2793)."""
    blacklist = {t.strip(".") for t in tld_blacklist}
    exclusion_keys = {e.strip(".") for e in tld_exclusion}
    tlds: dict[str, dict[str, str]] = {}
    for line in suffix_lines:
        suffix = line.strip()
        if not suffix or suffix.startswith("#"):
            continue
        tld = suffix.rsplit(".", 1)[-1]
        if tld in blacklist or tld in exclusion_keys:
            continue
        tlds.setdefault(tld, {})[suffix] = ""
    return tlds


def _dnsbl_tld_search(tlds: dict[str, dict[str, str]], tld: str, dparts: list[str], j: int, k: int) -> str | None:
    """tld_search (inc:2595-2603): if the j-label suffix is a known public suffix,
    the registrable parent is the k-label slice."""
    tld_query = ".".join(dparts[-j:])
    if tld_query in tlds.get(tld, {}):
        return ".".join(dparts[-k:])
    return None


def classify(domain: str, tlds: dict[str, dict[str, str]], exclusion: set[str]) -> tuple[str, str]:
    """Return ``(DNSBL_CLASS_ZONE, registrable-parent)`` or ``(DNSBL_CLASS_DATA, domain)``.

    Mirrors tld_analysis:2832-2874 exactly: a registrable parent -> wildcard ZONE; a
    deeper sub-domain whose parent is not a known public suffix -> exact DATA; a
    whole-domain TLD exclusion forces exact DATA (transparent, not wildcarded).
    """
    dparts = domain.split(".")
    dcnt = len(dparts)
    tld = dparts[-1]
    dfound = ""

    if dcnt > 5:
        dfound = ""
    elif dcnt == 5:
        dfound = _dnsbl_tld_search(tlds, tld, dparts, 4, 5) or ""
    elif dcnt == 4:
        dfound = _dnsbl_tld_search(tlds, tld, dparts, 3, 4) or ""
    elif dcnt == 3:
        dfound = _dnsbl_tld_search(tlds, tld, dparts, 2, 3) or ""
    elif dcnt == 2:
        dfound = ".".join(dparts[-2:])

    # TLD exclusion: whole domain in the exclusion set -> force exact DATA.
    if domain in exclusion:
        dfound = ""

    if dfound:
        return DNSBL_CLASS_ZONE, dfound
    return DNSBL_CLASS_DATA, domain


# --------------------------------------------------------------------------- #
# ADR-07 Stage-B reconcile: $badfilter prune + regex reduction + classify +
# priority bands. PURE / reentrant -- consumes the typed ``Rule`` stream from
# Stage-A (parse_abp) and produces the pre-emit rule sets. NOT wired into
# build()/init (Phase 6) and NEVER compiles/executes a regex.
#
# The reference TARGETs are tests/test_adr07_decision_spec.py (reduce_regex /
# reconcile / priority / decide) and benchmarks/spike_adr07_regex.reduce_pattern;
# this agrees with both. ADR.md SS2 ($badfilter / Regex-reduction / Precedence).
# --------------------------------------------------------------------------- #

# Regex-reduction grammar (mirrors the Phase-2 oracle reduce_regex + the spike
# reduce_pattern). A reducible ``/re/`` decides IDENTICALLY to a domain/wildcard
# rule, so it folds to a domain Rule at zero per-query cost. ``D`` is a domain
# literal: labels of [a-z0-9-] joined by ESCAPED dots (``\.``), no other metachar.
_DNSBL_RX_DOMAIN_LITERAL = re.compile(r"^[a-z0-9-]+(?:\\\.[a-z0-9-]+)+$")
# Prefixes that mean "domain + all subdomains" (-> wildcard zone after fold):
_DNSBL_RX_WILDCARD_PREFIXES = (r"^(.+\.)?", r"(^|\.)", r"^(?:.+\.)?")
# Prefix that means "exact domain only" (-> exact data after fold):
_DNSBL_RX_EXACT_PREFIXES = (r"^",)
# A leading ``(www\.)?`` after ``^`` is exact-with-optional-www -> still exact.
_DNSBL_RX_WWW_OPT = r"(www\.)?"


def _dnsbl_reduce_regex(inner: str) -> tuple[bool, str] | None:
    """Return ``(wildcard, domain)`` if a regex inner pattern folds to a
    domain/wildcard rule, else ``None`` (irreducible -- stays a compiled pattern).

    ``wildcard`` True -> domain + subdomains (zone); False -> exact (data). Mirrors
    the Phase-2 oracle ``reduce_regex`` + ``spike.reduce_pattern`` exactly (so a
    reducible feed regex == its dict form). Pure; does NOT compile the pattern.
    Per ADR.md SS2 we do NOT expand finite classes (``ad[0-9]\\.x`` stays a regex).
    """
    if not inner.endswith("$"):
        return None
    body = inner[:-1]
    for pre in _DNSBL_RX_WILDCARD_PREFIXES:
        if body.startswith(pre):
            lit = body[len(pre) :]
            if _DNSBL_RX_DOMAIN_LITERAL.match(lit):
                return True, lit.replace("\\.", ".")
            return None
    for pre in _DNSBL_RX_EXACT_PREFIXES:
        if body.startswith(pre):
            lit = body[len(pre) :]
            if lit.startswith(_DNSBL_RX_WWW_OPT):
                lit = lit[len(_DNSBL_RX_WWW_OPT) :]
            if _DNSBL_RX_DOMAIN_LITERAL.match(lit):
                return False, lit.replace("\\.", ".")
            return None
    return None


def _dnsbl_rule_band(rule: Rule) -> int:
    """The numeric priority band (1-6) for a surviving rule (ADR.md SS2 / the P3
    PRIO_* constants). USER -> band 5/6 (sovereign); FEED -> 1/2, +$important ->
    3/4. ``important`` is meaningless for USER rules (they are always sovereign)."""
    user = rule.provenance == RULE_PROV_USER
    if rule.kind == DNSBL_KIND_ALLOW:
        return _allow_priority(rule.important, user=user)
    return _block_priority(rule.important, user=user)


@dataclass(frozen=True)
class BlockDomainRule:
    """A reconciled domain BLOCK ready to emit into dataDB/zoneDB (Phase 6).

    ``cls`` is DNSBL_CLASS_DATA (exact) or DNSBL_CLASS_ZONE (wildcard); ``key`` is
    the registrable parent for a ZONE or the exact domain for DATA (from classify).
    """

    cls: str
    key: str
    band: int
    important: bool
    provenance: str
    feed: str
    group: str
    log: str


@dataclass(frozen=True)
class AllowDomainRule:
    """A reconciled domain ALLOW ready to emit into whiteDB (Phase 6).

    ``wildcard`` True -> domain + subdomains; False -> exact. ``important`` raises a
    feed allow's band to 4 (and is always effectively sovereign for USER rules)."""

    domain: str
    wildcard: bool
    band: int
    important: bool
    provenance: str


@dataclass(frozen=True)
class RegexRule:
    """A reconciled IRREDUCIBLE regex (block or allow) handed to Phase 6 to
    COMPILE (raw ``pattern`` -- NOT compiled here; Stage B never executes a regex).

    ``kind`` is DNSBL_KIND_BLOCK or DNSBL_KIND_ALLOW. ``band`` is the priority band;
    ``important`` is carried for the 6-band resolution."""

    pattern: str
    kind: str
    band: int
    important: bool
    provenance: str
    feed: str
    group: str
    log: str


@dataclass
class ReconcileResult:
    """The Stage-B pre-emit rule sets (pure return value -- no global is touched).

    Phase 6 folds these into the matcher dicts + compiles the irreducible regex:
        block_domains            -> dataDB/zoneDB (+band/important/feed/group/log)
        allow_domains            -> whiteDB ({wildcard, important} + band)
        block_regex_irreducible  -> regexDB     (compiled in Phase 6)
        allow_regex_irreducible  -> allowRegexDB (compiled in Phase 6)
    ``important_rules`` is the build-emitted fast-path flag (ADR.md SS2 "Query-time
    matcher"): True iff ANY surviving rule would engage the numeric 6-band branch
    (any $important, any feed allow/@@ or feed regex). False keeps today's matcher.
    ``pruned`` / ``reduced`` / ``skipped_badfilter`` are diagnostic counts."""

    block_domains: list[BlockDomainRule] = field(default_factory=list)
    allow_domains: list[AllowDomainRule] = field(default_factory=list)
    block_regex_irreducible: list[RegexRule] = field(default_factory=list)
    allow_regex_irreducible: list[RegexRule] = field(default_factory=list)
    important_rules: bool = False
    pruned: int = 0
    reduced: int = 0
    skipped_badfilter: int = 0


def reconcile(
    rules: Iterable[Rule],
    tlds: dict[str, dict[str, str]],
    exclusion: set[str],
) -> ReconcileResult:
    """Stage-B: reconcile the typed ``Rule`` stream into the pre-emit rule sets.

    PURE + REENTRANT: builds and returns a FRESH ``ReconcileResult``, mutates no
    argument and no module global, never compiles/executes a regex -- two calls on
    equal inputs yield equal results. Steps (ADR.md SS2 / RESULTS/04 SS7):

      1. $BADFILTER PRUNE (feed-only): collect the signatures of FEED rules carrying
         ``$badfilter``; drop every FEED rule with a matching signature; the
         ``$badfilter`` rules themselves emit nothing. USER rules are IMMUNE (never
         collected, never pruned -- sovereignty, fact 7).
      2. REGEX REDUCTION: a reducible regex Rule folds to a domain rule (block ->
         data/zone via classify, allow -> whiteDB wildcard); irreducible regex
         passes through into the irreducible set (compiled in Phase 6).
      3. CLASSIFY domain blocks data vs zone via ``classify`` (reuse ADR-06).
      4. ASSIGN priority BANDS to every surviving rule (``_dnsbl_rule_band``).

    ``tlds`` / ``exclusion`` are the classify inputs (same shapes build() uses).
    Matches the Phase-2 oracle ``reconcile`` + ``decide`` precedence.
    """
    rule_list = list(rules)

    # --- Step 1: feed-only $badfilter prune ------------------------------- #
    bad_sigs = {r.signature for r in rule_list if r.badfilter and r.provenance == RULE_PROV_FEED}
    result = ReconcileResult()
    survivors: list[Rule] = []
    for r in rule_list:
        if r.badfilter:
            result.skipped_badfilter += 1
            continue  # the $badfilter rule itself never emits a decision
        if r.provenance == RULE_PROV_FEED and r.signature in bad_sigs:
            result.pruned += 1
            continue  # pruned by a feed $badfilter (USER rules are never here)
        survivors.append(r)

    # --- Steps 2-4: reduce, classify, band -------------------------------- #
    for r in survivors:
        # A surviving rule engages the numeric 6-band branch (vs today's fast path)
        # whenever it is $important, or a feed ALLOW (@@), or a feed regex -- i.e.
        # anything beyond a band-1 feed block / a user rule the fast path handles.
        if r.important or (r.provenance == RULE_PROV_FEED and r.kind == DNSBL_KIND_ALLOW):
            result.important_rules = True

        if r.target == RULE_TARGET_REGEX:
            reduced = _dnsbl_reduce_regex(r.key_or_pattern)
            if reduced is None:
                # Irreducible -> hand the RAW pattern to Phase 6 (compile candidate).
                if r.provenance == RULE_PROV_FEED:
                    result.important_rules = True  # any feed regex engages numeric path
                regex_rule = RegexRule(
                    pattern=r.key_or_pattern,
                    kind=r.kind,
                    band=_dnsbl_rule_band(r),
                    important=r.important,
                    provenance=r.provenance,
                    feed=r.feed,
                    group=r.group,
                    log=r.log,
                )
                if r.kind == DNSBL_KIND_ALLOW:
                    result.allow_regex_irreducible.append(regex_rule)
                else:
                    result.block_regex_irreducible.append(regex_rule)
                continue
            # Reducible -> fold to a domain rule (zero per-query cost).
            result.reduced += 1
            wildcard, domain = reduced
        elif r.target == RULE_TARGET_DOMAIN:
            wildcard, domain = r.wildcard, r.key_or_pattern
        else:  # pragma: no cover - defensive; parse_abp only emits domain/regex
            continue

        band = _dnsbl_rule_band(r)
        if r.kind == DNSBL_KIND_ALLOW:
            result.allow_domains.append(
                AllowDomainRule(
                    domain=domain,
                    wildcard=wildcard,
                    band=band,
                    important=r.important,
                    provenance=r.provenance,
                )
            )
        else:
            # BLOCK domain -> classify data vs zone (reuse ADR-06 classify). A
            # wildcard=False fold (exact /^D$/) is forced to DATA; otherwise the
            # registrable-parent classify decides (matching the plain/hosts path).
            if wildcard:
                cls, key = classify(domain, tlds, exclusion)
            else:
                cls, key = DNSBL_CLASS_DATA, domain
            result.block_domains.append(
                BlockDomainRule(
                    cls=cls,
                    key=key,
                    band=band,
                    important=r.important,
                    provenance=r.provenance,
                    feed=r.feed,
                    group=r.group,
                    log=r.log,
                )
            )
        # NOTE: a user rule alone does NOT force ``important_rules`` -- today's fast
        # path already handles a pure user whitelist (important whiteDB) + user
        # blocks (P3 SS3). The flag is about the feed $important/@@/regex the fast
        # path cannot resolve; once that is set, the numeric branch sees the user
        # bands (5/6) too.

    return result


def _dnsbl_normalise_whitelist(
    user_whitelist: Iterable[str],
    top1m_list: Iterable[str],
    top1m_enabled: bool,
) -> dict[str, dict[str, Any]]:
    """User-whitelist normalisation (pfb_unbound_python_whitelist, inc:2259) into the
    query-time whiteDB shape: www-strip; leading-dot -> wildcard True else False.
    TOP1M entries are loaded ONLY when enabled (bare domains -> exact). No build-time
    list pruning -- this only populates whiteDB.

    ADR-07 P3: the whiteDB value widens from a bare ``bool`` (wildcard?) to
    ``{"wildcard": bool, "important": bool}``. User whitelist + TOP1M load as
    ``important=True`` (user-intent sovereignty, ADR.md SS2 / fact 7). Because an
    allow already beats every block today, this changes NO decision now -- the
    ``important`` flag is only consulted by the (currently unreachable) numeric
    6-band branch of ``evaluate_domain``.
    """
    white_db: dict[str, dict[str, Any]] = {}
    for raw in user_whitelist:
        line = raw.strip()
        if not line:
            continue
        if line.startswith("www."):
            line = line[4:]
        if line.startswith("."):
            white_db[line.lstrip(".")] = {"wildcard": True, "important": True, "band": PRIO_USER_ALLOW}
        else:
            white_db[line] = {"wildcard": False, "important": True, "band": PRIO_USER_ALLOW}

    if top1m_enabled:
        for raw in top1m_list:
            dom = raw.strip()
            if dom:
                # TOP1M behaves as a user allow (sovereign, band 6) -- fact 7.
                white_db.setdefault(dom, {"wildcard": False, "important": True, "band": PRIO_USER_ALLOW})

    return white_db


# ============================================================================ #
# ADR-07 P7 -- regex safety (opt-in static cap + always-on runtime warn/evict)  #
# ============================================================================ #
# `re` does not release the GIL during a match and a Python thread cannot be
# killed (ADR.md fact 2), so a query-time timeout CANNOT interrupt a catastrophic
# match. The accepted design is a bounded residual: a pathological pattern's FIRST
# match may block one query, but it is then EVICTED so it cannot hang again. Two
# layers, both stdlib + in-process, applied to FEED *and* user regex:
#   (1) opt-in static cap -- drop over-long / nested-quantifier patterns at LOAD
#       (no execution) when the "Limit long/complex regex" setting is enabled;
#   (2) always-on runtime timing -- time each match (per-thread CPU); over a WARN
#       ceiling log (rate-limited), over a higher EVICT ceiling log + remove the
#       pattern from the live regexDB/allowRegexDB (snapshot-iterate, evict-after-
#       loop -- never mutate mid-iteration; dict.pop is atomic under the GIL).

# Static-cap defaults (Phase-1 RESULTS/01 SS3c heuristic): a pattern over this
# many characters, OR carrying a nested/overlapping unbounded quantifier, is the
# genuinely catastrophic shape and is dropped at load when the cap is enabled.
REGEX_STATIC_LEN_CAP = 200

# A quantified group that itself sits inside a quantifier: (a+)+, (a*)*, (\w+\.)+,
# ([a-z]+)*, (.*a){20}. Phase-1 measured this catching 1/1 catastrophic patterns in
# the corpus with no false-negatives and no false-positives on the cap-passing set.
_REGEX_NESTED_QUANTIFIER = re.compile(r"\([^()]*[+*][^()]*\)\s*[+*{]")

# Alternation-overlap: a quantified group whose body contains an alternation `|`,
# e.g. (a|a)+, (a|ab)*, (foo|foobar)+. Overlapping/ambiguous alternatives under a
# quantifier backtrack catastrophically just like a nested quantifier, yet the
# nested-quantifier shape above does not catch them (no inner quantifier). Kept
# conservative: a single `(...)` (no inner parens) with a `|`, then a quantifier.
_REGEX_ALTERNATION_OVERLAP = re.compile(r"\([^()]*\|[^()]*\)\s*[+*{]")

# Runtime warn/evict ceilings (milliseconds of per-match thread CPU; Phase-1
# defaults, ADR.md SS2). Overridable via the pfb_unbound.ini MAIN section
# (regex_warn_ms / regex_evict_ms) -> cfg, so they are not hardcoded magic.
REGEX_WARN_MS_DEFAULT = 10.0
REGEX_EVICT_MS_DEFAULT = 100.0

# perf_counter fallback needs TWO consecutive over-evict strikes before evicting,
# so a single wall-clock spike (a descheduled thread) cannot false-evict a good
# pattern. thread_time is jitter-robust and evicts on the first crossing.
REGEX_PERF_STRIKES = 2

# `time.thread_time` is present on CPython/FreeBSD (CLOCK_THREAD_CPUTIME_ID); fall
# back to `time.perf_counter` (+ the 2-strike guard) only where it is absent.
_REGEX_HAVE_THREAD_TIME = hasattr(time, "thread_time")

# Rate-limit the WARN log to one line per pattern name (a slow pattern warns once,
# not on every query) and track perf_counter strikes per name. Module-level dicts
# mutated under the GIL; small + bounded by the loaded regex count.
_regex_warned: set[str] = set()
_regex_perf_strikes: dict[str, int] = {}


def _regex_exceeds_static_cap(pattern: str) -> bool:
    """Pure static-cap check (NO execution): True if ``pattern`` is over the length
    ceiling OR matches the nested-quantifier heuristic OR the alternation-overlap
    heuristic. Used at LOAD time, gated by the opt-in "Limit long/complex regex"
    setting -- when the setting is OFF nothing is dropped. Catches the catastrophic
    shapes cheaply without running the regex."""
    if len(pattern) > REGEX_STATIC_LEN_CAP:
        return True
    if _REGEX_NESTED_QUANTIFIER.search(pattern) is not None:
        return True
    return _REGEX_ALTERNATION_OVERLAP.search(pattern) is not None


def _regex_timed_search(pattern: Any, q_name: str) -> tuple[Any, float]:
    """Run ``pattern.search(q_name)`` and return ``(match, elapsed_ms)`` where
    ``elapsed_ms`` is per-thread CPU time (``time.thread_time``) when available, else
    wall clock (``time.perf_counter``). Thread CPU is jitter-robust: a thread merely
    descheduled under load does not inflate the measurement, so a good pattern is not
    false-evicted. NO timeout is attempted -- a match cannot be interrupted (fact 2);
    this only MEASURES so the caller can warn/evict AFTER the (first) match returns."""
    if _REGEX_HAVE_THREAD_TIME:
        start = time.thread_time()
        match = pattern.search(q_name)
        elapsed_ms = (time.thread_time() - start) * 1000.0
    else:
        start = time.perf_counter()
        match = pattern.search(q_name)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
    return match, elapsed_ms


def _regex_should_evict(name: str, elapsed_ms: float, warn_ms: float, evict_ms: float, group: str, feed: Any) -> bool:
    """Apply the runtime warn/evict policy for ONE match of pattern ``name`` that took
    ``elapsed_ms``. Logs a rate-limited warning over ``warn_ms`` (once per name) and
    returns True when the pattern should be EVICTED (over ``evict_ms``). With
    ``time.thread_time`` an over-evict crossing evicts on the FIRST hit; on the
    perf_counter fallback it requires ``REGEX_PERF_STRIKES`` consecutive crossings so
    a lone wall-clock spike cannot false-evict. The caller collects names to evict and
    pops them AFTER the scan loop (snapshot-iterate; never mutate mid-iteration)."""
    if elapsed_ms <= warn_ms:
        # A fast match clears any accumulated perf-fallback strike streak.
        if not _REGEX_HAVE_THREAD_TIME:
            _regex_perf_strikes.pop(name, None)
        return False

    if elapsed_ms <= evict_ms:
        if name not in _regex_warned:
            _regex_warned.add(name)
            sys.stderr.write(
                "[pfBlockerNG]: slow {} regex [ {} ] feed [ {} ] took {:.1f} ms (warn ceiling {:.1f} ms)".format(
                    group, name, feed, elapsed_ms, warn_ms
                )
            )
        if not _REGEX_HAVE_THREAD_TIME:
            _regex_perf_strikes.pop(name, None)
        return False

    # Over the EVICT ceiling.
    if not _REGEX_HAVE_THREAD_TIME:
        strikes = _regex_perf_strikes.get(name, 0) + 1
        _regex_perf_strikes[name] = strikes
        if strikes < REGEX_PERF_STRIKES:
            return False
        _regex_perf_strikes.pop(name, None)

    sys.stderr.write(
        "[pfBlockerNG]: EVICTING {} regex [ {} ] feed [ {} ] -- match took {:.1f} ms (evict ceiling {:.1f} ms); "
        "it will no longer be evaluated".format(group, name, feed, elapsed_ms, evict_ms)
    )
    _regex_warned.discard(name)
    return True


def _regex_evict_names(db: dict[str, Any], names: Iterable[str]) -> None:
    """Pop evicted pattern keys from a live regex DB AFTER the scan loop. ``dict.pop``
    is atomic under the GIL, so this is safe even though the matcher runs across many
    Unbound query threads; the scan iterates a SNAPSHOT (list(...)) so this never
    mutates a dict mid-iteration (ADR.md fact 3)."""
    for name in names:
        db.pop(name, None)


def _dnsbl_compile_regex_rules(
    regex_rules: Iterable[RegexRule],
    *,
    static_cap: bool = False,
) -> tuple[dict[str, dict[str, Any]], int]:
    """Compile a list of irreducible ``RegexRule`` into the live regex-DB shape.

    Returns ``(db, admitted)`` where ``db[name] = {"re": <compiled>, "important":
    bool, "band": int}`` and ``admitted`` is the count of patterns that compiled.
    A pattern that fails ``re.compile`` is logged and skipped (mirrors the init REGEX
    load) -- it never aborts the build. Names are unique per pattern occurrence so two
    feeds carrying the same pattern both load.

    ADR-07 P7: when ``static_cap`` is True (the opt-in "Limit long/complex regex"
    setting) an over-length / nested-quantifier pattern is DROPPED at load (logged,
    not compiled, not counted) -- the cheap no-execution pre-filter. The always-on
    runtime warn/evict guard lives in the matcher (it is what bounds the residual).
    """
    db: dict[str, dict[str, Any]] = {}
    admitted = 0
    seq = 0
    for rule in regex_rules:
        if static_cap and _regex_exceeds_static_cap(rule.pattern):
            sys.stderr.write(
                "[pfBlockerNG]: dropping long/complex {} regex feed [ {} ] pattern [ {} ] (static cap)".format(
                    rule.kind, rule.feed, rule.pattern
                )
            )
            continue
        try:
            compiled = re.compile(rule.pattern)
        except re.error as e:
            sys.stderr.write(
                "[pfBlockerNG]: ABP regex compile error feed [ {} ] pattern [ {} ]: {}".format(
                    rule.feed, rule.pattern, e
                )
            )
            continue
        # Key by feed + a per-build sequence so identical patterns from different feeds
        # (or the same feed) do not collide and each is independently evictable (P7).
        name = "{}#{}".format(rule.feed or "DNSBL", seq)
        seq += 1
        db[name] = {"re": compiled, "important": rule.important, "band": rule.band}
        admitted += 1
    return db, admitted


def build(
    manifest: dict[str, Any],
    config: dict[str, Any],
    *,
    line_reader: Callable[[str], Iterable[str]],
    top1m_enabled: bool = False,
) -> BuildResult:
    """Pure, reentrant DNSBL build: raw feeds + config -> matcher structure-set.

    ``manifest`` is the per-feed boundary (RESULTS/01_Results.txt SS1i): one row per
    raw feed file mapping it to ``{raw, feed, group, format_hint, log_flag}``.
    ``config`` carries the classification + whitelist inputs (``tld_master`` suffix
    lines, ``tld_blacklist``, ``tld_exclusion``, ``user_whitelist``, ``top1m_list``).
    ``line_reader`` yields the raw lines for a feed's ``raw`` reference -- injected so
    this stays pure and side-effect-free (no filesystem coupling, unit-testable; the
    init wiring in Phase 4 supplies a file-backed reader).

    Returns a FRESH ``BuildResult`` and mutates no module global -- calling it twice
    yields equal structures (reentrant / zero-downtime-ready). It performs NO dedup,
    NO subdomain collapse and NO build-time whitelist/TOP1M removal: duplicate keys
    are simply overwritten last-wins by dict assignment (the documented attribution
    change, ADR.md SS2), and redundant subdomains stay because their parent zone still
    matches them.
    """
    suffix_lines = list(config.get("tld_master", []))
    tld_blacklist = list(config.get("tld_blacklist", []))
    tld_exclusion = list(config.get("tld_exclusion", []))
    exclusion = {e.strip(".") for e in tld_exclusion}

    # ADR-07 P7: the opt-in static cap (drop over-long / nested-quantifier feed regex
    # at load). Read from the manifest config; OFF by default so nothing is dropped.
    static_cap = bool(config.get("regex_cap", False))

    tlds = _dnsbl_load_tld_master(suffix_lines, tld_blacklist, tld_exclusion)

    data_db: dict[str, dict[str, Any]] = {}
    zone_db: dict[str, dict[str, Any]] = {}
    feed_group_index_db: dict[int, dict[str, str]] = {}
    feed_group_db: dict[str, int] = {}
    next_index = 0

    def index_for(feed: str, group: str) -> int:
        nonlocal next_index
        key = feed + group
        idx = feed_group_db.get(key)
        if idx is None:
            idx = next_index
            feed_group_db[key] = idx
            feed_group_index_db[idx] = {"feed": feed, "group": group}
            next_index += 1
        return idx

    # Whole-TLD block: a blacklisted TLD becomes a synthetic DNSBL_TLD zone entry
    # (inc:2740 ``,<tld>,,1,DNSBL_TLD,DNSBL_TLD``).
    for raw_tld in tld_blacklist:
        tld = raw_tld.strip(".")
        if not tld:
            continue
        idx = index_for("DNSBL_TLD", "DNSBL_TLD")
        zone_db[tld] = {"log": "1", "index": idx, "important": False, "band": PRIO_FEED_BLOCK}

    white_db = _dnsbl_normalise_whitelist(
        config.get("user_whitelist", []),
        config.get("top1m_list", []),
        top1m_enabled,
    )

    # ADR-07 P6: ABP feeds (format_hint='abp') are parsed into the typed Rule stream
    # (Stage A, parse_abp) and reconciled (Stage B) into the banded pre-emit rule
    # sets; non-ABP feeds keep the ADR-06 lite parse() -> block-only path unchanged.
    # The reconciled ABP structures (incl. @@/regex/important/badfilter) are emitted
    # below alongside the plain blocks. Each ABP rule carries its manifest-row
    # feed/group/log straight through parse_abp onto the Rule.
    abp_rules: list[Rule] = []

    for feed_row in manifest.get("feeds", []):
        feed = feed_row["feed"]
        group = feed_row["group"]
        fmt = feed_row["format_hint"]
        log_flag = feed_row["log_flag"]
        if fmt == "abp":
            for raw_line in line_reader(feed_row["raw"]):
                rule = parse_abp(raw_line, provenance=RULE_PROV_FEED, feed=feed, group=group, log=log_flag)
                if rule is not None:
                    abp_rules.append(rule)
            continue
        for raw_line in line_reader(feed_row["raw"]):
            entry = parse(fmt, raw_line)
            if entry is None:
                continue
            domain = normalise(entry.value)
            if domain is None:
                continue
            # Only BLOCK is produced by the lite path (ABP-ready seam; module header).
            if entry.kind != DNSBL_KIND_BLOCK:
                continue
            idx = index_for(feed, group)
            cls, key = classify(domain, tlds, exclusion)
            # Non-ABP block: feed-block band 1, never $important (no $options grammar).
            payload = {"log": log_flag, "index": idx, "important": False, "band": PRIO_FEED_BLOCK}
            if cls == DNSBL_CLASS_ZONE:
                zone_db[key] = payload  # last-wins (dict; ADR-06 SS2 attribution change)
            else:
                data_db[key] = payload

    # ---- Stage-B reconcile + Stage-C emit for the ABP rule stream -------------- #
    regex_db: dict[str, dict[str, Any]] = {}
    allow_regex_db: dict[str, dict[str, Any]] = {}
    important_rules = False
    regex_count = 0
    if abp_rules:
        result = reconcile(abp_rules, tlds, exclusion)
        important_rules = result.important_rules

        # Domain blocks -> dataDB/zoneDB (carry band + $important).
        for b in result.block_domains:
            idx = index_for(b.feed or "DNSBL", b.group or "DNSBL")
            payload = {"log": b.log or "1", "index": idx, "important": b.important, "band": b.band}
            if b.cls == DNSBL_CLASS_ZONE:
                zone_db[b.key] = payload
            else:
                data_db[b.key] = payload

        # Domain allows (@@||domain^ and reduced @@/re/) -> whiteDB. A user whitelist
        # entry (band 6) must never be downgraded by a feed allow on the SAME key, so
        # only widen when the key is absent or the existing band is lower.
        for a in result.allow_domains:
            existing = white_db.get(a.domain)
            if existing is None:
                white_db[a.domain] = {"wildcard": a.wildcard, "important": a.important, "band": a.band}
                continue
            if _white_entry_band(existing) < a.band:
                white_db[a.domain] = {"wildcard": a.wildcard, "important": a.important, "band": a.band}
                continue
            # Same key, SAME band: a key can carry both an exact (reduced @@/^d$/)
            # and a wildcard (@@||d^) allow. The suffix-walk only honours wildcard
            # entries, so first-writer-wins would silently drop subdomain coverage.
            # Merge monotonically (widen) -- keep the strongest of each field.
            if _white_entry_band(existing) == a.band:
                white_db[a.domain] = {
                    "wildcard": _white_entry_wildcard(existing) or a.wildcard,
                    "important": _white_entry_important(existing) or a.important,
                    "band": a.band,
                }

        # Irreducible regex -> regexDB (block) / allowRegexDB (allow). Compile here
        # (Phase 6); a broken pattern is logged + skipped, mirroring the init regex
        # load (pfb_unbound.py REGEX section). NO runtime cap/evict guard yet (P7).
        # Iterate over a stable list so the emit order is deterministic.
        regex_db, block_admitted = _dnsbl_compile_regex_rules(result.block_regex_irreducible, static_cap=static_cap)
        allow_regex_db, allow_admitted = _dnsbl_compile_regex_rules(
            result.allow_regex_irreducible, static_cap=static_cap
        )
        regex_count = block_admitted + allow_admitted

    return BuildResult(
        data_db=data_db,
        zone_db=zone_db,
        feed_group_index_db=feed_group_index_db,
        white_db=white_db,
        counts=len(data_db) + len(zone_db),
        regex_db=regex_db,
        allow_regex_db=allow_regex_db,
        important_rules=important_rules,
        regex_count=regex_count,
    )


def _dnsbl_file_line_reader(base_dir: str) -> Callable[[str], Iterable[str]]:
    """A file-backed ``line_reader`` for build(): map a feed_row["raw"] reference to
    its raw lines, streamed lazily so peak RAM stays at the dict floor (RESULTS/01).

    ``raw`` may be an absolute path or a name relative to ``base_dir`` (the directory
    holding the manifest). Yields stripped-of-newline lines; a missing/unreadable feed
    yields nothing (and is logged by the caller) rather than aborting the whole build.
    """

    def reader(raw: str) -> Iterable[str]:
        path = raw if os.path.isabs(raw) else os.path.join(base_dir, raw)
        try:
            fh = open(path, encoding="utf-8", errors="replace")
        except OSError as e:
            # A single missing/unreadable feed is logged and skipped -- it must not
            # abort the whole build (the other feeds still load).
            sys.stderr.write("[pfBlockerNG]: Failed to read DNSBL feed '{}': {}".format(path, e))
            return
        with fh:
            for line in fh:
                yield line.rstrip("\r\n")

    return reader


def _dnsbl_config_from_manifest(manifest: dict[str, Any], base_dir: str) -> dict[str, Any]:
    """Shape the manifest's ``config`` block into the build() config blob.

    The on-box manifest carries ``tld_master`` as a FILE PATH (the public-suffix
    oracle); the build takes the suffix LINES directly (pure, filesystem-decoupled),
    so read the file here. ``tld_blacklist`` / ``tld_exclusion`` / ``user_whitelist``
    / ``top1m_list`` are passed through as lists. Missing keys default empty so a
    partial manifest still builds.
    """
    config = manifest.get("config", {})

    tld_master_lines: list[str] = []
    tld_master = config.get("tld_master")
    if isinstance(tld_master, list):
        tld_master_lines = list(tld_master)
    elif isinstance(tld_master, str) and tld_master:
        path = tld_master if os.path.isabs(tld_master) else os.path.join(base_dir, tld_master)
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                tld_master_lines = fh.read().splitlines()
        except OSError as e:
            sys.stderr.write("[pfBlockerNG]: Failed to read tld_master '{}': {}".format(path, e))

    # ADR-07 P7: the static-cap flag reaches build() via the ini-derived pfb setting
    # (the cap setting lives in pfb_unbound.ini MAIN, not the manifest); a manifest
    # ``config.regex_cap`` (if present) takes precedence so the build stays a pure
    # function of (manifest+config) in tests that inject it directly.
    regex_cap = bool(config.get("regex_cap", pfb.get("regex_cap", False)))

    return {
        "tld_master": tld_master_lines,
        "tld_blacklist": list(config.get("tld_blacklist", [])),
        "tld_exclusion": list(config.get("tld_exclusion", [])),
        "user_whitelist": list(config.get("user_whitelist", [])),
        "top1m_list": list(config.get("top1m_list", [])),
        "regex_cap": regex_cap,
    }


def dnsbl_build_from_manifest(manifest_path: str) -> BuildResult | None:
    """Read the per-feed manifest JSON and BUILD the DNSBL structure-set from raw.

    This is the ADR-06 P4 init swap point: a pure ``(manifest+raw) -> BuildResult``
    step (build() mutates no global) that a future zero-downtime reload can run on a
    background thread and atomically swap in. This phase only calls it synchronously
    at init and assigns the result into the module globals -- no background/restart-
    free behaviour is added here.

    The manifest carries ``feeds`` (one row per raw feed file) and a ``config`` block
    (RESULTS/01 SS2). ``top1m_enabled`` is taken from ``config["top1m_enabled"]``.
    Returns ``None`` when the manifest is absent or cannot be parsed (init then falls
    back to the legacy CSV load -- shell/PHP still produce those files until Phase 5).
    """
    if not os.path.isfile(manifest_path):
        return None

    try:
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError) as e:
        sys.stderr.write("[pfBlockerNG]: Failed to load DNSBL manifest '{}': {}".format(manifest_path, e))
        return None

    base_dir = os.path.dirname(os.path.abspath(manifest_path))
    config = _dnsbl_config_from_manifest(manifest, base_dir)
    top1m_enabled = bool(manifest.get("config", {}).get("top1m_enabled", False))

    try:
        return build(
            manifest,
            config,
            line_reader=_dnsbl_file_line_reader(base_dir),
            top1m_enabled=top1m_enabled,
        )
    except Exception as e:
        sys.stderr.write("[pfBlockerNG]: Failed to build DNSBL structures from raw: {}".format(e))
        return None


def dnsbl_emit_count(count_path: str, count: int) -> bool:
    """Write the Python-emitted entry total to ``pfb_py_count`` (the UI reads it at
    pfblockerng.inc:3149).

    ADR-06 redefines ``pfb_py_count`` to the LOADED entry total (len(dataDB)+len(
    zoneDB)); its value legitimately RISES vs today because the lists are no longer
    dedup/collapse/whitelist/TOP1M-pruned (RESULTS/01 SS1e). The sync-check at
    inc:3149-3156 still subtracts this value -- it must be reconciled when shell/PHP
    is slimmed (Phase 5); flagged in the handoff. Returns True on success.
    """
    try:
        with open(count_path, "w", encoding="utf-8") as fh:
            fh.write("{}\n".format(count))
        return True
    except OSError as e:
        sys.stderr.write("[pfBlockerNG]: Failed to write DNSBL count '{}': {}".format(count_path, e))
        return False


def iter_domain_suffixes(name: str) -> Iterator[str]:
    q = name
    for _ in range(name.count(".") + 1, 0, -1):
        yield q
        q = q.split(".", 1)[-1]


def find_zone_match(q_name: str, zone_db: dict[str, Any]) -> tuple[str, dict] | tuple[None, None]:
    for q in iter_domain_suffixes(q_name):
        entry = zone_db.get(q)
        if entry is not None:
            return q, entry
    return None, None


def find_noaaaa_wildcard_parent(q_name: str, noaaaa_db: dict[str, Any]) -> str | None:
    q = q_name.split(".", 1)[-1]
    for _ in range(q.count("."), 0, -1):
        if noaaaa_db.get(q):
            return q
        q = q.split(".", 1)[-1]
    return None


def _white_entry_wildcard(entry: Any) -> bool:
    """Wildcard flag of a whiteDB value, tolerant of both shapes.

    ADR-07 P3 widens whiteDB values from a bare ``bool`` (wildcard?) to
    ``{"wildcard": bool, "important": bool}``. Existing callers/tests still seed bare
    bools (e.g. ``add_white`` and the retained ADR-06 oracle), so the matcher accepts
    either: a dict reads ``["wildcard"]``; a bare bool IS the wildcard flag.
    """
    if isinstance(entry, dict):
        return bool(entry.get("wildcard", False))
    return bool(entry)


def _white_entry_important(entry: Any) -> bool:
    """Sovereignty flag of a whiteDB value (ADR-07 P3). Bare-bool legacy entries are
    treated as not-important (False); only the new dict shape can carry it. Consulted
    solely by the numeric 6-band branch (unreachable while important_rules is False)."""
    if isinstance(entry, dict):
        return bool(entry.get("important", False))
    return False


def _white_entry_band(entry: Any) -> int:
    """Numeric band of a whiteDB value (ADR-07 P6). A dict entry carries an explicit
    ``band`` (feed allow 2/4, user allow 6); else it is derived from ``important``
    (an important entry is a user allow -> band 6, a bare-bool/legacy feed allow ->
    band 2). Consulted only by the numeric 6-band branch."""
    if isinstance(entry, dict):
        band = entry.get("band")
        if isinstance(band, int):
            return band
        return PRIO_USER_ALLOW if entry.get("important", False) else PRIO_FEED_ALLOW
    return PRIO_FEED_ALLOW


def whitelist_lookup_domain(name: str, white_db: dict[str, Any], tld_seg: int) -> tuple[bool, bool]:
    """Resolve a whitelist hit to ``(matched, important)``.

    Same match algorithm as the historical ``whitelist_check_domain`` (exact, then
    ``www.``-strip, then a parent-suffix walk gated by ``tld_seg`` that only honours
    WILDCARD entries), but also returns the matched entry's ``important`` flag so the
    numeric 6-band resolution can place a user allow in band 6. Behaviour for the
    boolean ``matched`` result is byte-identical to the pre-P3 function.
    """
    entry = white_db.get(name)
    if entry is not None:
        return True, _white_entry_important(entry)
    if name.startswith("www."):
        entry = white_db.get(name[4:])
        if entry is not None:
            return True, _white_entry_important(entry)
    q = name.split(".", 1)[-1]
    for x in range(q.count(".") + 1, 0, -1):
        if x >= tld_seg:
            entry = white_db.get(q)
            if entry is not None and _white_entry_wildcard(entry):
                return True, _white_entry_important(entry)
        q = q.split(".", 1)[-1]
    return False, False


def whitelist_check_domain(name: str, white_db: dict[str, Any], tld_seg: int) -> bool:
    matched, _ = whitelist_lookup_domain(name, white_db, tld_seg)
    return matched


def resolve_feed_group(index: Any, feed_group_index_db: dict[int, Any]) -> tuple[Any, Any]:
    feedGroup = feed_group_index_db.get(index)
    if feedGroup is not None:
        return feedGroup["feed"], feedGroup["group"]
    return "Unknown", "Unknown"


def hsts_check_domain(
    name: str,
    hsts_db: dict[str, Any],
    hsts_tlds: tuple[str, ...] | list[str],
    tld: str,
) -> tuple[bool, str]:
    if tld in hsts_tlds:
        return True, "HSTS_TLD"
    q = name
    for _ in range(q.count(".") + 1, 0, -2):
        if hsts_db.get(q) is not None:
            return True, "HSTS"
        q = q.split(".", 1)[-1]
    return False, "Python"


@dataclass
class DnsblDecision:
    is_found: bool
    in_whitelist: bool
    in_hsts: bool
    null_blocking: bool
    log_type: Any
    b_type: str
    p_type: str
    feed: Any
    group: Any
    b_eval: str


# ADR-07 P3: the 6-band precedence scale (ADR.md SS2 / RESULTS-P2 SS2). Highest wins;
# a block wins iff block_prio > allow_prio (no ties: block in {1,3,5}, allow in {2,4,6}).
#   6 user allow   5 user block   4 feed allow+important
#   3 feed block+important   2 feed allow (@@)   1 feed block (||)
# These name the bands the (currently UNREACHABLE) numeric resolution assigns; the
# fast path never computes them. Until a later phase tags rule provenance, every
# loaded BLOCK is a feed rule (band 1, or 3 with $important); user provenance reaches
# the numeric branch only via the whiteDB ``important`` flag (a user allow -> band 6).
PRIO_FEED_BLOCK = 1
PRIO_FEED_ALLOW = 2
PRIO_FEED_BLOCK_IMPORTANT = 3
PRIO_FEED_ALLOW_IMPORTANT = 4
PRIO_USER_BLOCK = 5
PRIO_USER_ALLOW = 6


def _block_priority(important: bool, *, user: bool = False) -> int:
    """Band of a matched BLOCK. ``user`` is reserved for a later provenance-tagging
    phase; production blocks are feed-sourced today (band 1, or 3 with $important)."""
    if user:
        return PRIO_USER_BLOCK
    return PRIO_FEED_BLOCK_IMPORTANT if important else PRIO_FEED_BLOCK


def _allow_priority(important: bool, *, user: bool = False) -> int:
    """Band of a matched ALLOW. A user allow (whiteDB ``important`` entry / TOP1M /
    settings whitelist) is band 6; a feed allow (@@/allow-regex) is band 2, or 4 with
    $important."""
    if user:
        return PRIO_USER_ALLOW
    return PRIO_FEED_ALLOW_IMPORTANT if important else PRIO_FEED_ALLOW


def _block_entry_band(entry: Any) -> int:
    """Numeric band of a block payload (dataDB / zoneDB / regexDB value).

    A payload carries an explicit ``band`` (ABP feed/user block, 1/3/5); a payload
    without one is the historical feed block and is derived from its ``important``
    flag (band 3 if $important, else feed block band 1) -- so a synthetic strata-test
    payload (no ``band`` key) still resolves to the right band. A bare compiled
    pattern (legacy/user regex) is a non-important feed block (band 1)."""
    if isinstance(entry, dict):
        band = entry.get("band")
        if isinstance(band, int):
            return band
        return _block_priority(bool(entry.get("important", False)))
    return PRIO_FEED_BLOCK


def _scan_block_band(
    q_name: str,
    cfg: dict[str, Any],
    data_db: dict[str, Any],
    zone_db: dict[str, Any],
    regex_db: dict[str, Any],
) -> int:
    """Highest block band that matches ``q_name`` across dataDB (exact), zoneDB (the
    suffix walk) and the block-regex DB; 0 if none match. Used by the numeric 6-band
    resolution to take the max block band (decide() semantics) -- the fast-path
    discovery short-circuits on the first hit, which is wrong for the max. Snapshot-
    iterates the regex DB (Phase-7 eviction safety)."""
    best = 0
    if cfg.get("dataDB"):
        entry = data_db.get(q_name)
        if entry is not None:
            best = max(best, _block_entry_band(entry))
    if cfg.get("zoneDB"):
        for q in iter_domain_suffixes(q_name):
            entry = zone_db.get(q)
            if entry is not None:
                best = max(best, _block_entry_band(entry))
    if cfg.get("regexDB") and q_name:
        # Snapshot-iterate + time each match (ADR-07 P7), same warn/evict policy as the
        # fast-path discovery scan; collect evicted names and pop AFTER the loop.
        warn_ms = cfg.get("regex_warn_ms", REGEX_WARN_MS_DEFAULT)
        evict_ms = cfg.get("regex_evict_ms", REGEX_EVICT_MS_DEFAULT)
        to_evict: list[str] = []
        for _k, r in list(regex_db.items()):
            pattern = r.get("re") if isinstance(r, dict) else r
            match, elapsed_ms = _regex_timed_search(pattern, q_name)
            if _regex_should_evict(_k, elapsed_ms, warn_ms, evict_ms, "DNSBL_Regex", _k):
                to_evict.append(_k)
                continue
            if match:
                best = max(best, _block_entry_band(r))
        if to_evict:
            _regex_evict_names(regex_db, to_evict)
    return best


def _scan_allow_regex_band(
    q_name: str,
    allow_regex_db: dict[str, Any],
    warn_ms: float = REGEX_WARN_MS_DEFAULT,
    evict_ms: float = REGEX_EVICT_MS_DEFAULT,
) -> int:
    """Highest allow band over the allow-regex (@@/re/) entries that match ``q_name``;
    0 if none match. Values mirror regexDB's tolerant shape: a bare compiled pattern,
    or a {"re", "important", "band"} payload. Iterates a SNAPSHOT (list(...)) and TIMES
    each match (ADR-07 P7): over the warn ceiling logs once, over the evict ceiling is
    removed from the live allow-regex DB AFTER the loop (snapshot-iterate, evict-after-
    loop -- the same warn/evict policy as the block-regex scans; fact 3)."""
    if not q_name:
        return 0
    best = 0
    to_evict: list[str] = []
    for _k, r in list(allow_regex_db.items()):
        pattern = r.get("re") if isinstance(r, dict) else r
        match, elapsed_ms = _regex_timed_search(pattern, q_name)
        if _regex_should_evict(_k, elapsed_ms, warn_ms, evict_ms, "DNSBL_AllowRegex", _k):
            to_evict.append(_k)
            continue
        if match:
            important = bool(r.get("important", False)) if isinstance(r, dict) else False
            band = r.get("band") if isinstance(r, dict) else None
            if not isinstance(band, int):
                band = _allow_priority(important)
            best = max(best, band)
    if to_evict:
        _regex_evict_names(allow_regex_db, to_evict)
    return best


def whitelist_lookup_band(name: str, white_db: dict[str, Any], tld_seg: int) -> int:
    """Highest whiteDB allow band that matches ``name`` (exact, ``www.``-strip, then
    the wildcard suffix walk gated by ``tld_seg``); 0 if no whitelist entry matches.
    A user whitelist / TOP1M entry is band 6; a feed @@/reduced-allow entry carries
    its reconciled band (2 or 4). The match algorithm is identical to
    whitelist_lookup_domain; this variant returns the numeric band for the 6-band
    resolution instead of a bare ``important`` bool."""
    entry = white_db.get(name)
    if entry is not None:
        return _white_entry_band(entry)
    if name.startswith("www."):
        entry = white_db.get(name[4:])
        if entry is not None:
            return _white_entry_band(entry)
    best = 0
    q = name.split(".", 1)[-1]
    for x in range(q.count(".") + 1, 0, -1):
        if x >= tld_seg:
            entry = white_db.get(q)
            if entry is not None and _white_entry_wildcard(entry):
                best = max(best, _white_entry_band(entry))
        q = q.split(".", 1)[-1]
    return best


def _resolve_numeric_allow(
    q_name: str,
    q_name_original: str,
    is_cname: bool,
    cfg: dict[str, Any],
    white_db: dict[str, Any],
    allow_regex_db: dict[str, Any],
    block_band: int,
) -> bool:
    """Numeric 6-band resolution (ADR.md SS2): return True iff an ALLOW overrides the
    matched BLOCK (i.e. the name resolves) -- mapped onto ``in_whitelist`` so the
    downstream hsts/null-blocking logic is shared with the fast path.

    A block always matched here (the caller gates on ``is_found``); ``block_band`` is
    its highest matching band (computed by the caller over data/zone/block-regex).
    Blocked iff ``block_band > allow_band``; with no allow match ``allow_band`` is 0
    so the block stands. Engaged only when ``important_rules`` is True (an ABP
    $important / feed @@ / feed regex was loaded); proven against the Phase-2 band
    table by synthetic-payload unit tests and the production ABP equivalence tests.
    """
    allow_band = 0
    names = [q_name] + ([q_name_original] if is_cname else [])
    if cfg["whiteDB"]:
        for n in names:
            allow_band = max(allow_band, whitelist_lookup_band(n, white_db, cfg["python_tld_seg"]))

    if cfg.get("allowRegexDB", False):
        allow_band = max(
            allow_band,
            _scan_allow_regex_band(
                q_name,
                allow_regex_db,
                cfg.get("regex_warn_ms", REGEX_WARN_MS_DEFAULT),
                cfg.get("regex_evict_ms", REGEX_EVICT_MS_DEFAULT),
            ),
        )

    return allow_band >= block_band


def evaluate_domain(
    q_name: str,
    q_name_original: str,
    tld: str,
    is_cname: bool,
    cfg: dict[str, Any],
    containers: dict[str, Any],
) -> DnsblDecision:
    is_found = False
    log_type: Any = False
    in_whitelist = False
    in_hsts = False
    null_blocking = True
    b_type = "Python"
    p_type = "Python"
    feed: Any = "Unknown"
    group: Any = "Unknown"
    b_eval = ""

    # ``block_band`` carries the discovered block's numeric band (1-5) into the numeric
    # resolution below; it stays at the feed-block default on the fast path. The fast
    # path never reads it (the historical "allow overrides block" early-exit).
    block_band = 0

    data_db: dict[str, Any] = containers["dataDB"]
    zone_db: dict[str, Any] = containers["zoneDB"]
    white_db: dict[str, Any] = containers["whiteDB"]
    regex_db: dict[str, Any] = containers["regexDB"]
    allow_regex_db: dict[str, Any] = containers.get("allowRegexDB", {})
    feed_group_index_db: dict[int, Any] = containers["feedGroupIndexDB"]
    hsts_db: dict[str, Any] = containers["hstsDB"]

    # STEP A/B/C strata (ADR.md SS2): user-allow / user-block / feed rules. Provenance
    # is not tagged on loaded entries yet, so today's discovery is structurally the
    # feed stratum -- data (exact) -> zone (wildcard) -> tld-allow -> idn -> block-regex.
    if cfg["python_blocking"]:
        if cfg["dataDB"]:
            data_entry = data_db.get(q_name)
            if data_entry is not None:
                is_found = True
                log_type = data_entry["log"]
                feed, group = resolve_feed_group(data_entry["index"], feed_group_index_db)
                b_type = "DNSBL"
                b_eval = q_name
                block_band = _block_entry_band(data_entry)

        if not is_found and cfg["zoneDB"]:
            matched_q, zone_entry = find_zone_match(q_name, zone_db)
            if matched_q is not None and zone_entry is not None:
                is_found = True
                log_type = zone_entry["log"]
                feed, group = resolve_feed_group(zone_entry["index"], feed_group_index_db)
                b_type = "TLD"
                b_eval = matched_q
                block_band = _block_entry_band(zone_entry)

    if not is_found:
        if (
            cfg["python_tld"]
            and tld != ""
            and q_name not in (cfg["dnsbl_ipv4"], cfg["dnsbl_ipv6"])
            and tld not in cfg["python_tlds"]
        ):
            is_found = True
            feed = "TLD_Allow"
            group = "DNSBL_TLD_Allow"

        if not is_found and cfg["python_idn"] and is_idn_domain(q_name):
            is_found = True
            feed = "IDN"
            group = "DNSBL_IDN"

        if not is_found and cfg["regexDB"] and q_name:
            # Snapshot-iterate (list(...)) so the runtime eviction can mutate the live
            # regexDB without corrupting this scan (fact 3). Each match is TIMED (per-
            # thread CPU); a pattern over the warn ceiling logs once, over the evict
            # ceiling is removed from the live DB AFTER the loop -- so it cannot hang
            # twice (the accepted residual is the single slow first-hit; fact 2).
            warn_ms = cfg.get("regex_warn_ms", REGEX_WARN_MS_DEFAULT)
            evict_ms = cfg.get("regex_evict_ms", REGEX_EVICT_MS_DEFAULT)
            to_evict: list[str] = []
            for k, r in list(regex_db.items()):
                # regexDB values may be a bare compiled pattern (today / user-regex) or
                # a {"re", "important", "band"} payload (ABP feed block-regex). Read
                # both shapes; the bare-pattern path is byte-identical to today.
                pattern = r.get("re") if isinstance(r, dict) else r
                match, elapsed_ms = _regex_timed_search(pattern, q_name)
                if _regex_should_evict(k, elapsed_ms, warn_ms, evict_ms, "DNSBL_Regex", k):
                    to_evict.append(k)
                    continue
                if match:
                    is_found = True
                    feed = k
                    group = "DNSBL_Regex"
                    block_band = _block_entry_band(r)
                    break
            if to_evict:
                _regex_evict_names(regex_db, to_evict)

        if is_found:
            b_eval = q_name
            log_type = "1"

    # Resolution stratum. FAST PATH (important_rules False, today): the historical
    # "a block is found, then an allow overrides it" -- whiteDB checked as a plain
    # override, byte-for-byte the pre-P3 matcher. The numeric 6-band resolution is the
    # important_rules==True branch; it is UNREACHABLE in production today (no $important
    # rule is loaded) and is exercised only by synthetic-payload unit tests.
    if is_found:
        if not cfg.get("important_rules", False):
            if cfg["whiteDB"]:
                names = [q_name] + ([q_name_original] if is_cname else [])
                in_whitelist = any(whitelist_check_domain(n, white_db, cfg["python_tld_seg"]) for n in names)
        else:
            # NUMERIC 6-band path (an ABP $important / feed @@ / feed regex is loaded).
            # decide() resolves by the HIGHEST matching block band vs the highest
            # matching allow band, so augment the first-discovered block's band with a
            # full scan over every matching block (data/zone-suffix/block-regex) -- the
            # discovery above short-circuits on the first hit (right for metadata, but
            # the resolution needs the max band).
            block_band = max(
                block_band,
                _scan_block_band(q_name, cfg, data_db, zone_db, regex_db),
            )
            in_whitelist = _resolve_numeric_allow(
                q_name,
                q_name_original,
                is_cname,
                cfg,
                white_db,
                allow_regex_db,
                block_band,
            )

    if is_found and not in_whitelist:
        if cfg["hstsDB"]:
            in_hsts, p_type = hsts_check_domain(q_name, hsts_db, cfg["hsts_tlds"], tld)

        if log_type == "1" and not in_hsts:
            null_blocking = False

        if is_cname:
            b_type = b_type + "_CNAME"

    return DnsblDecision(
        is_found=is_found,
        in_whitelist=in_whitelist,
        in_hsts=in_hsts,
        null_blocking=null_blocking,
        log_type=log_type,
        b_type=b_type,
        p_type=p_type,
        feed=feed,
        group=group,
        b_eval=b_eval,
    )


def evaluate_noaaaa(q_name: str, noaaaa_db: dict[str, Any]) -> bool:
    if noaaaa_db.get(q_name) is not None:
        return True
    return find_noaaaa_wildcard_parent(q_name, noaaaa_db) is not None


def operate(id: int, event: int, qstate: module_qstate, qdata: Any) -> bool:
    global pfb, threads, dataDB, zoneDB, hstsDB, whiteDB, excludeDB, excludeAAAADB
    global excludeSS, dnsblDB, noAAAADB, gpListDB, safeSearchDB

    qstate_valid = False
    q_type: Any = None
    q_name_original = ""
    q_ip = ""
    try:
        if qstate is not None and qstate.qinfo.qtype is not None:
            qstate_valid = True
            q_type = qstate.qinfo.qtype
            q_name_original = get_q_name_qstate(qstate).lower()
            q_ip = get_q_ip(qstate)
        else:
            sys.stderr.write("[pfBlockerNG] qstate is not None and qstate.qinfo.qtype is not None")
    except Exception as e:
        sys.stderr.write("[pfBlockerNG] qstate_valid: {}: {}".format(event, e))
        pass

    if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):
        # no AAAA validation
        if qstate_valid and q_type == RR_TYPE_AAAA and pfb["noAAAADB"] and q_name_original not in excludeAAAADB:
            isin_noAAAA = evaluate_noaaaa(q_name_original, noAAAADB)

            # Create FQDN Reply Message (AAAA -> A)
            if isin_noAAAA:
                if noAAAADB.get(q_name_original) is None:
                    noAAAADB[q_name_original] = True

                msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA)
                if msg is None or not msg.set_return_msg(qstate):
                    qstate.ext_state[id] = MODULE_ERROR
                    return True

                qstate.return_rcode = RCODE_NOERROR
                qstate.return_msg.rep.security = 2
                qstate.ext_state[id] = MODULE_FINISHED
                return True

            # Add domain to excludeAAAADB to skip subsequent no AAAA validation
            else:
                excludeAAAADB.append(q_name_original)

        # SafeSearch Redirection validation
        if qstate_valid and pfb["safeSearchDB"]:
            # Determine if domain has been previously validated
            if q_name_original not in excludeSS:
                isSafeSearch = safeSearchDB.get(q_name_original)

                # Validate 'www.' Domains
                if isSafeSearch is None and not q_name_original.startswith("www."):
                    isSafeSearch = safeSearchDB.get("www." + q_name_original)

                # TODO: See CNAME message below
                # if isSafeSearch is None and q_name_original != 'safe.duckduckgo.com'
                #        and q_name_original.endswith('duckduckgo.com'):
                #    isSafeSearch = safeSearchDB.get('duckduckgo.com')
                # if isSafeSearch is None and q_name_original != 'safesearch.pixabay.com'
                #        and q_name_original.endswith('pixabay.com'):
                #    isSafeSearch = safeSearchDB.get('pixabay.com')

                if isSafeSearch is not None:
                    ss_found = False
                    msg = None
                    cname_msg = None
                    if isSafeSearch["A"] == "nxdomain":
                        qstate.return_rcode = RCODE_NXDOMAIN
                        qstate.ext_state[id] = MODULE_FINISHED
                        return True

                    # TODO: Wait for Unbound code changes to allow for this functionality,
                    # using local-zone/local-data entries for CNAMES for now
                    elif isSafeSearch["A"] == "cname":
                        if isSafeSearch["AAAA"] is not None and isSafeSearch["AAAA"] != "":
                            if q_type == RR_TYPE_A:
                                cname_msg = DNSMessage(
                                    qstate.qinfo.qname_str, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RD | PKT_RA
                                )
                                cname_msg.answer.append(
                                    "{} 3600 IN CNAME {}".format(qstate.qinfo.qname_str, isSafeSearch["AAAA"])
                                )
                                ss_found = True
                            elif q_type == RR_TYPE_AAAA:
                                cname_msg = DNSMessage(
                                    qstate.qinfo.qname_str, RR_TYPE_AAAA, RR_CLASS_IN, PKT_QR | PKT_RD | PKT_RA
                                )
                                cname_msg.answer.append(
                                    "{} 3600 IN CNAME {}".format(qstate.qinfo.qname_str, isSafeSearch["AAAA"])
                                )
                                ss_found = True

                            if ss_found:
                                if cname_msg is None or not cname_msg.set_return_msg(qstate):
                                    qstate.ext_state[id] = MODULE_ERROR
                                    return True

                                MODULE_RESTART_NEXT = 3
                                qstate.no_cache_store = 1
                                qstate.ext_state[id] = MODULE_RESTART_NEXT
                                return True
                    else:
                        if (q_type == RR_TYPE_A and isSafeSearch["A"] != "") or (
                            q_type == RR_TYPE_AAAA and isSafeSearch["AAAA"] == ""
                        ):
                            msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA)
                            msg.answer.append("{} 300 IN {} {}".format(qstate.qinfo.qname_str, "A", isSafeSearch["A"]))
                            ss_found = True
                        elif q_type == RR_TYPE_AAAA and isSafeSearch["AAAA"] != "":
                            msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_AAAA, RR_CLASS_IN, PKT_QR | PKT_RA)
                            msg.answer.append(
                                "{} 300 IN {} {}".format(qstate.qinfo.qname_str, "AAAA", isSafeSearch["AAAA"])
                            )
                            ss_found = True

                    if ss_found:
                        if msg is None or not msg.set_return_msg(qstate):
                            qstate.ext_state[id] = MODULE_ERROR
                            return True

                        qstate.return_rcode = RCODE_NOERROR
                        qstate.return_msg.rep.security = 2
                        qstate.ext_state[id] = MODULE_FINISHED
                        return True

            # Add domain to excludeSS to skip subsequent SafeSearch validation
            else:
                excludeSS.append(q_name_original)

        # Python_control - Receive TXT commands from pfSense local IP
        if qstate_valid and q_type == RR_TYPE_TXT and q_name_original.startswith("python_control."):
            control_rcd = False
            control_msg = ""
            if pfb["python_control"] and q_ip == "127.0.0.1":
                control_command = q_name_original.split(".")
                if len(control_command) >= 2:
                    if control_command[1] == "disable":
                        control_rcd = True
                        control_msg = "Python_control: DNSBL disabled"
                        pfb["python_blacklist"] = False

                        # If duration specified, disable DNSBL Blocking for specified time in seconds
                        if pfb["mod_threading"] and len(control_command) == 3 and control_command[2] != "":
                            # Validate Duration argument
                            duration = python_control_duration(control_command[2])
                            if duration:
                                # Ensure thread is not active
                                if not python_control_thread("sleep"):
                                    # Start Thread
                                    if not python_control_start_thread("sleep", python_control_sleep, duration, None):
                                        control_rcd = False
                                        control_msg = "Python_control: DNSBL disabled: Thread failed"
                                    else:
                                        control_msg = "{} for {} second(s)".format(control_msg, duration)
                                else:
                                    control_rcd = False
                                    control_msg = "Python_control: DNSBL disabled: Previous call still in progress"
                            else:
                                control_rcd = False
                                control_msg = (
                                    "Python_control: DNSBL disabled: duration [ {} ] out of range (1-3600sec)".format(
                                        control_command[2]
                                    )
                                )

                    elif control_command[1] == "enable":
                        control_rcd = True
                        control_msg = "Python_control: DNSBL enabled"
                        pfb["python_blacklist"] = True

                    elif control_command[1] == "addbypass" or control_command[1] == "removebypass":
                        b_ip = (control_command[2]).replace("-", ".")
                        isIPValid = ipaddress.ip_address(b_ip)

                        if isIPValid:
                            if not pfb["gpListDB"]:
                                pfb["gpListDB"] = True

                            control_rcd = True
                            if control_command[1] == "addbypass":
                                control_msg = "Python_control: Add bypass for IP: [ {} ]".format(b_ip)

                                # If duration specified, disable DNSBL Blocking for specified time in seconds
                                if pfb["mod_threading"] and len(control_command) == 4 and control_command[3] != "":
                                    # Validate Duration argument
                                    duration = python_control_duration(control_command[3])
                                    if duration:
                                        # Ensure thread is not active
                                        if not python_control_thread("addbypass" + b_ip):
                                            # Start Thread
                                            if not python_control_start_thread(
                                                "addbypass" + b_ip, python_control_addbypass, duration, b_ip
                                            ):
                                                control_rcd = False
                                                control_msg = (
                                                    "Python_control: Add bypass for IP: [ {} ] thread failed".format(
                                                        b_ip
                                                    )
                                                )
                                            else:
                                                control_msg = "{} for {} second(s)".format(control_msg, duration)
                                        else:
                                            control_rcd = False
                                            control_msg = (
                                                "Python_control: Add bypass for IP:"
                                                " [ {} ]: Previous call still in progress"
                                            ).format(b_ip)
                                    else:
                                        control_rcd = False
                                        control_msg = (
                                            "Python_control: Add bypass for IP:"
                                            " [ {} ]: duration [ {} ] out of range (1-3600sec)"
                                        ).format(b_ip, control_command[3])
                                else:
                                    # Add bypass called without duration
                                    if control_rcd:
                                        gpListDB[b_ip] = 0

                            elif control_command[1] == "removebypass":
                                if gpListDB.get(b_ip) is not None:
                                    control_msg = "Python_control: Remove bypass for IP: [ {} ]".format(b_ip)
                                    gpListDB.pop(b_ip)
                                else:
                                    control_msg = "Python_control: IP not in Group Policy: [ {} ]".format(b_ip)

                if control_rcd:
                    q_reply = "python_control"
                else:
                    if control_msg == "":
                        control_msg = "Python_control: Command not authorized! [ {} ]".format(q_name_original)
                    q_reply = "python_control_fail"

                txt_msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_TXT, RR_CLASS_IN, PKT_QR | PKT_RA)
                txt_msg.answer.append('{}. 0 IN TXT "{}"'.format(q_reply, control_msg))

                if txt_msg is None or not txt_msg.set_return_msg(qstate):
                    qstate.ext_state[id] = MODULE_ERROR
                    return True

                qstate.return_rcode = RCODE_NOERROR
                qstate.return_msg.rep.security = 2
                qstate.ext_state[id] = MODULE_FINISHED
                return True

    # DNSBL Validation for specific RR_TYPES only
    if qstate_valid and pfb["python_blacklist"] and q_type in pfb["rr_types"]:
        # Group Policy - Bypass DNSBL Validation
        bypass_dnsbl = False
        if pfb["gpListDB"]:
            q_ip = get_q_ip(qstate)

            if q_ip != "Unknown":
                isgpBypass = gpListDB.get(q_ip)

                if isgpBypass is not None:
                    bypass_dnsbl = True

        # Create list of Domain/CNAMES to be evaluated
        validate = []

        # Skip 'in-addr.arpa' domains
        if not q_name_original.endswith(".in-addr.arpa") and not bypass_dnsbl:
            validate.append(q_name_original)

            # DNSBL CNAME Validation
            if pfb["python_cname"] and qstate.return_msg:
                r = qstate.return_msg.rep
                if r.an_numrrsets > 1:
                    for i in range(0, r.an_numrrsets):
                        rr = r.rrsets[i]

                        if rr.rk.type_str != "CNAME":
                            continue

                        for j in range(0, rr.entry.data.count):
                            domain = convert_other(rr.entry.data.rr_data[j]).lower()
                            if domain != "Unknown":
                                validate.append(domain)

        isCNAME = False
        for val_counter, q_name in enumerate(validate, start=1):
            if val_counter > 1:
                isCNAME = True

            # Determine if domain has been previously validated
            if q_name not in excludeDB:
                isFound = False
                isInWhitelist = False
                nullBlocking = True

                # Determine if domain was previously DNSBL blocked
                isDomainInDNSBL = dnsblDB.get(q_name)
                if isDomainInDNSBL is None:
                    tld = get_tld(qstate)
                    cfg = {
                        "python_blocking": pfb["python_blocking"],
                        "dataDB": pfb["dataDB"],
                        "zoneDB": pfb["zoneDB"],
                        "python_tld": pfb["python_tld"],
                        "python_tlds": pfb["python_tlds"],
                        "dnsbl_ipv4": pfb["dnsbl_ipv4"],
                        "dnsbl_ipv6": pfb["dnsbl_ipv6"],
                        "python_idn": pfb["python_idn"],
                        "regexDB": pfb["regexDB"],
                        "whiteDB": pfb["whiteDB"],
                        "allowRegexDB": pfb["allowRegexDB"],
                        "important_rules": pfb["important_rules"],
                        "regex_warn_ms": pfb["regex_warn_ms"],
                        "regex_evict_ms": pfb["regex_evict_ms"],
                        "python_tld_seg": pfb["python_tld_seg"],
                        "hstsDB": pfb["hstsDB"],
                        "hsts_tlds": pfb["hsts_tlds"],
                    }
                    containers = {
                        "dataDB": dataDB,
                        "zoneDB": zoneDB,
                        "whiteDB": whiteDB,
                        "regexDB": regexDB,
                        "allowRegexDB": allowRegexDB,
                        "feedGroupIndexDB": feedGroupIndexDB,
                        "hstsDB": hstsDB,
                    }
                    dec = evaluate_domain(q_name, q_name_original, tld, isCNAME, cfg, containers)
                    isFound = dec.is_found
                    isInWhitelist = dec.in_whitelist
                    nullBlocking = dec.null_blocking
                    b_type = dec.b_type
                    p_type = dec.p_type
                    log_type = dec.log_type
                    feed = dec.feed
                    group = dec.group
                    b_eval = dec.b_eval

                    # Add domain to excludeDB to skip subsequent blacklist validation
                    if not isFound or isInWhitelist:
                        excludeDB.append(q_name)

                    # Domain to be blocked and is not whitelisted
                    if isFound and not isInWhitelist:
                        if isCNAME:
                            q_name = q_name_original

                        # Skip subsequent DNSBL validation for domain, add to dict for get_details_dnsbl
                        dnsblDB[q_name] = {
                            "qname": q_name,
                            "b_type": b_type,
                            "p_type": p_type,
                            "null": nullBlocking,
                            "log": log_type,
                            "feed": feed,
                            "group": group,
                            "b_eval": b_eval,
                        }
                        # Skip subsequent DNSBL validation for original domain (CNAME validation),
                        # add to dict for get_details_dnsbl
                        if isCNAME and dnsblDB.get(q_name_original) is None:
                            dnsblDB[q_name_original] = {
                                "qname": q_name_original,
                                "b_type": b_type,
                                "p_type": p_type,
                                "null": nullBlocking,
                                "log": log_type,
                                "feed": feed,
                                "group": group,
                                "b_eval": b_eval,
                            }

                        # Add domain data to DNSBL cache for Reports tab
                        pfb_db_enqueue(("cache", (b_type, q_name, group, b_eval, feed)))

                # Use previously blocked domain details
                else:
                    nullBlocking = isDomainInDNSBL["null"]
                    isFound = True

                if isFound and not isInWhitelist:
                    # Create FQDN Reply Message
                    msg = DNSMessage(qstate.qinfo.qname_str, q_type, RR_CLASS_IN, PKT_QR | PKT_RA)

                    if q_type == RR_TYPE_A or q_type == RR_TYPE_ANY:
                        msg.answer.append(
                            "{}. 3600 IN A {}".format(q_name, "0.0.0.0" if nullBlocking else pfb["dnsbl_ipv4"])
                        )
                    if q_type == RR_TYPE_AAAA or q_type == RR_TYPE_ANY:
                        msg.answer.append(
                            "{}. 3600 IN AAAA {}".format(q_name, "::" if nullBlocking else pfb["dnsbl_ipv6"])
                        )

                    if msg is None or not msg.set_return_msg(qstate):
                        qstate.ext_state[id] = MODULE_ERROR
                        return True

                    # Log entry
                    kwargs = {"pfb_addr": q_ip}
                    if qstate.return_msg:
                        get_details_dnsbl("dnsbl", None, qstate, qstate.return_msg.rep, kwargs)
                    else:
                        get_details_dnsbl("dnsbl", None, qstate, None, kwargs)

                    qstate.return_rcode = RCODE_NOERROR
                    qstate.return_msg.rep.security = 2
                    qstate.ext_state[id] = MODULE_FINISHED
                    return True

    if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):
        qstate.ext_state[id] = MODULE_WAIT_MODULE
        return True

    if event == MODULE_EVENT_MODDONE:
        # Log entry
        if qstate_valid and qstate.return_msg:
            kwargs = {"pfb_addr": q_ip}
            get_details_reply("reply", None, qstate, qstate.return_msg.rep, kwargs)
        else:
            get_details_reply("reply", None, qstate, None, None)

        qstate.ext_state[id] = MODULE_FINISHED
        return True

    log_err("[pfBlockerNG]: BAD event")
    qstate.ext_state[id] = MODULE_ERROR
    return True


log_info("[pfBlockerNG]: pfb_unbound.py script loaded")

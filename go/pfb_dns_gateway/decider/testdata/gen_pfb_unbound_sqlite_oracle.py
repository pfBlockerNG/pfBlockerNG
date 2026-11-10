# Records what the shipped pfb_unbound.py (CPython 3.11, booted through the dns_proxy shim) leaves in its two stats
# databases, pfb_py_resolver.sqlite and pfb_py_dnsbl.sqlite, for the scenarios pfb_unbound_sqlite_oracle_test.go
# replays: every scenario stages a module directory (plus, for a migration, the old-schema database files made here
# with Python's own sqlite3), boots the module, runs its steps with make_timestamp and time.time fixed, and dumps both
# databases after the steps marked "dump". A dump is every table's SQL, columns and rows; the randomblob epochs are
# replaced by one token per distinct value and the init-time stamp of the Upstream seed row by "<now>". The .sqlite
# bytes are never compared.
# Run from the repo root:
#   TMPDIR=<scratch dir> uv run python go/pfb_dns_gateway/decider/testdata/gen_pfb_unbound_sqlite_oracle.py
# It rewrites testdata/pfb_unbound_sqlite_oracle.json.
import asyncio
import calendar
import json
import os
import re
import secrets
import shutil
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SHIPPED = ROOT / "src" / "usr" / "local" / "pkg" / "pfblockerng"
sys.path.insert(0, str(SHIPPED / "dns_proxy"))
sys.path.insert(0, str(ROOT / "tests" / "dns_proxy"))
import pfb_dns_proxy  # noqa: E402
import unbound_shim as shim  # noqa: E402
from frontend_helpers import FakeUnbound, build_query  # noqa: E402

secrets.randbits = lambda bits: 0x1234  # the SafeSearch chase asks Unbound with a random id

STAMP = "2026-10-18 12:00:00"
NOW = calendar.timegm((2026, 10, 18, 12, 0, 0))
CLIENT = "192.0.2.10"
OUT = HERE / "pfb_unbound_sqlite_oracle.json"
RESOLVER_DB = "pfb_py_resolver.sqlite"
DNSBL_DB = "pfb_py_dnsbl.sqlite"
DBS = {"resolver": RESOLVER_DB, "dnsbl": DNSBL_DB}
EPOCH = re.compile(r"^[0-9a-f]{32}$")
STAMPED = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$")
VARIABLE = re.compile(r"\$(\w+)")

MAIN = {"python_enable": "true", "python_blocking": "true", "python_reply": "true", "dnsbl_ipv4": "10.10.10.1"}
FEEDS = [
    ("F0", "G0", "0", ["lf0.example"]),
    ("F1", "G1", "1", ["lf1.example", "other.example"]),
    ("F2", "G2", "2", ["lf2.example"]),
    ("F3", "G3", "3", ["lf3.example"]),
    ("F4", "G4", "4", ["lf4.example"]),
    ("F5", "G5", "5", ["lf5.example"]),
    ("F6", "G6", "6", ["lf6.example"]),
]
GROUPS = [feed[1] for feed in FEEDS]


def module_files(main=None, feeds=()):
    ini = "[MAIN]\n" + "".join(f"{k} = {v}\n" for k, v in {**MAIN, **(main or {})}.items())
    files = {"pfb_unbound.ini": ini}
    rows = []
    for i, (feed, group, flag, domains) in enumerate(feeds):
        rel = f"pfb_py_raw/feed{i}.txt"
        files[rel] = "".join(f"{d}\n" for d in domains)
        rows.append({"raw": rel, "feed": feed, "group": group, "log_flag": flag})
    files["pfb_py_sources.json"] = json.dumps({"version": 1, "config": {}, "feeds": rows})
    return files


def custom_groups(names, counter=0):
    """The dnsbl database as PHP's dnsbl_save_stats() leaves it: a counter row and a custom owner epoch per group."""
    return [
        "CREATE TABLE dnsbl (groupname TEXT, timestamp TEXT, entries INTEGER, counter INTEGER)",
        "CREATE TABLE dnsbl_group_epochs (owner TEXT NOT NULL, origin TEXT NOT NULL, epoch TEXT NOT NULL, "
        "PRIMARY KEY(owner, origin))",
    ] + [
        stmt
        for i, name in enumerate(names)
        for stmt in (
            f"INSERT INTO dnsbl VALUES ('{name}', '', 1, {counter})",
            f"INSERT INTO dnsbl_group_epochs VALUES ('{name}', 'custom', '{i + 1:032x}')",
        )
    ]


# ---- the dumps ---------------------------------------------------------------------------------------------------


def cell_key(value, masked):
    if masked:
        return (2, "<epoch>")
    if value is None:
        return (0, 0)
    return (1, value) if isinstance(value, int) else (2, value)


def dump_all(directory):
    """Both databases, every table sorted by name and every row by its cells with the epochs masked, the epochs then
    named E1, E2... in the order they first appear: the tokens do not depend on the random values."""
    tokens = {}
    out = {}
    for label, name in DBS.items():
        path = directory / name
        if not path.exists():
            out[label] = None
            continue
        con = sqlite3.connect(path)
        tables = {}
        names = [
            r[0]
            for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        for table in names:
            sql = con.execute("SELECT sql FROM sqlite_master WHERE name=?", (table,)).fetchone()[0]
            info = list(con.execute(f"PRAGMA table_info({table})"))
            columns = [list(r[1:]) for r in info]
            masked = [r[1] == "epoch" for r in info]
            raw = [list(r) for r in con.execute(f"SELECT * FROM {table}")]
            raw.sort(key=lambda row: [cell_key(v, m) for v, m in zip(row, masked)])
            rows = []
            for row in raw:
                cells = []
                for value, is_epoch, column in zip(row, masked, info):
                    if is_epoch:
                        assert EPOCH.match(value), (table, value)
                        value = tokens.setdefault(value, f"E{len(tokens) + 1}")
                    elif (
                        column[1] == "timestamp" and isinstance(value, str) and STAMPED.match(value) and value != STAMP
                    ):
                        value = "<now>"
                    cells.append(value)
                rows.append(cells)
            tables[table] = {"sql": sql, "columns": columns, "rows": rows}
        con.close()
        out[label] = tables
    return out


# ---- the Python side of one scenario -----------------------------------------------------------------------------


class Clock:
    """Stands in for the module's `time`: time.time() is fixed, everything else is the real module's."""

    def __getattr__(self, name):
        return getattr(time, name)

    @staticmethod
    def time():
        return float(NOW)


class Runner:
    def __init__(self, name, files, presql=None, worker=False):
        self.name, self.files, self.presql, self.worker = name, files, presql or {}, worker
        self.dir = Path(tempfile.mkdtemp(prefix="pfbsqlite"))
        for rel, text in files.items():
            target = self.dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        for shipped in ("pfb_unbound.py", "pfb_dnsbl_regex_rules.py"):
            (self.dir / shipped).symlink_to(SHIPPED / shipped)
        for db, statements in self.presql.items():
            con = sqlite3.connect(self.dir / DBS[db])
            for statement in statements:
                con.execute(statement)
            con.commit()
            con.close()
        self.cwd = os.getcwd()
        self.vars = {}
        self.steps = []
        self.module = None
        self.start()

    def start(self):
        self.module = pfb_dns_proxy.boot(str(self.dir))
        m = self.module
        m.pfb_log = lambda log, line: None
        m.make_timestamp = lambda: STAMP
        m.time = Clock()
        m._dnsbl_last_event = None
        if not self.worker:
            self.stop_worker()

    def close(self):
        if self.module is not None:
            pfb_dns_proxy.shutdown(self.module)
        os.chdir(self.cwd)
        shutil.rmtree(self.dir)

    def stop_worker(self):
        """close-and-wait: the stop task drains and flushes the queue; later counters are written synchronously."""
        m = self.module
        if m.pfb.get("db_worker"):
            m.pfb_db_queue.put(("stop",))
            m.pfb_db_worker_thread.join(timeout=10)
            assert not m.pfb_db_worker_thread.is_alive()
            m.pfb["db_worker"] = False

    def record(self, step):
        self.steps.append(step)

    def sub(self, value):
        return VARIABLE.sub(lambda match: self.vars[match.group(1)], value) if isinstance(value, str) else value

    # ---- steps that touch the databases directly
    def sql(self, db, *statements):
        con = sqlite3.connect(self.dir / DBS[db])
        for statement in statements:
            con.execute(self.sub(statement))
        con.commit()
        con.close()
        self.record({"op": "sql", "db": db, "statements": list(statements)})

    def let(self, name, db, query):
        con = sqlite3.connect(self.dir / DBS[db])
        self.vars[name] = con.execute(query).fetchone()[0]
        con.close()
        self.record({"op": "let", "name": name, "db": db, "query": query})

    def dump(self):
        self.record({"op": "dump", "dump": dump_all(self.dir)})

    def reconnect(self, db):
        number = self.module.DB_RESOLVER if db == "resolver" else self.module.DB_DNSBL
        self.module._db_close(number)
        assert self.module.pfb_db_validate(number)
        self.record({"op": "reconnect", "db": db})

    def remove(self, db):
        number = self.module.DB_RESOLVER if db == "resolver" else self.module.DB_DNSBL
        self.module._db_close(number)
        path = self.dir / DBS[db]
        for suffix in ("", "-wal", "-shm"):
            Path(str(path) + suffix).unlink(missing_ok=True)
        self.record({"op": "remove", "db": db})

    def reboot(self):
        pfb_dns_proxy.shutdown(self.module)
        os.chdir(self.cwd)
        self.start()
        self.record({"op": "reboot"})

    def stop(self):
        self.stop_worker()
        self.record({"op": "stop"})

    def refresh_epochs(self):
        self.module._snapshot.group_epochs.update(self.module._db_group_epochs(True, {}))
        self.record({"op": "refresh_epochs"})

    def enqueue(self, *task):
        self.module.pfb_db_enqueue(tuple(self.sub(x) for x in task))
        self.record({"op": "enqueue", "task": list(task)})

    def flush_resolver(self, delta, details):
        self.module._db_flush_resolver(delta, {tuple(self.sub(x) for x in key): n for key, n in details})
        self.record({"op": "flush_resolver", "delta": delta, "details": details})

    def flush_dnsbl(self, deltas, details):
        self.module._db_flush_dnsbl(
            {tuple(self.sub(x) for x in key): n for key, n in deltas},
            {tuple(self.sub(x) for x in key): n for key, n in details},
        )
        self.record({"op": "flush_dnsbl", "deltas": deltas, "details": details})

    # ---- steps that go through the module
    def control(self, *command):
        self.module.pfb_apply_control_command(list(command))
        self.record({"op": "control", "command": list(command)})

    def control_sleep(self):
        self.module.python_control_sleep(0, None)
        self.record({"op": "control_sleep"})

    def swap(self, with_list):
        import dataclasses

        m = self.module
        data_db = {"swapped.example": {"log": "1", "index": 0}} if with_list else {}
        m.rebuild_and_swap(lambda: dataclasses.replace(m._snapshot, data_db=data_db))
        self.record({"op": "swap", "with_list": with_list})

    def resolve(self, qname, qtype=1, *, client=CLIENT, transport="UDP", lip="", lif=""):
        wire = build_query(qname, qtype)
        unbound = FakeUnbound({})
        forwards = []

        async def forward(data):
            reply = unbound.answer(data)
            forwards.append(reply.hex())
            return reply

        asyncio.run(
            pfb_dns_proxy.Frontend(self.module).resolve(
                wire, client, forward, transport=transport, listener_ip=lip, listener_interface=lif
            )
        )
        self.record(
            {
                "op": "resolve",
                "qname": qname,
                "qtype": qtype,
                "wire": wire.hex(),
                "client": client,
                "transport": transport,
                "lip": lip,
                "lif": lif,
                "forwards": forwards,
            }
        )

    def qstate(self, spec):
        if spec is None:
            return None
        q = shim.module_qstate(
            shim.query_info(spec["qname"], spec["qtype"]),
            spec.get("client", CLIENT),
            0,
            0,
            spec.get("transport", "Unknown"),
            spec.get("lip", ""),
            spec.get("lif", ""),
        )
        return q

    def details_reply(self, m_type, qstate, kwargs, qinfo=None):
        info = None if qinfo is None else shim.query_info(qinfo["qname"], qinfo["qtype"])
        self.module.get_details_reply(
            m_type, info, self.qstate(qstate), None, dict(kwargs) if kwargs is not None else None
        )
        self.record({"op": "details_reply", "m_type": m_type, "qstate": qstate, "qinfo": qinfo, "kwargs": kwargs})

    def details_dnsbl(self, qstate, dnsbl, kwargs, epoch="@snap"):
        spec = {**DECISION, **dnsbl}
        decision = self.module.DnsblDecision(**spec)
        if epoch == "@snap":
            epoch_value = self.module._snapshot.group_epochs.get((decision.group_owner, decision.group_origin), "")
        else:
            epoch_value = self.sub(epoch)
        self.module.get_details_dnsbl(
            "dnsbl", None, self.qstate(qstate), dict(kwargs) if kwargs is not None else None, decision, epoch_value
        )
        self.record({"op": "details_dnsbl", "qstate": qstate, "dnsbl": dnsbl, "kwargs": kwargs, "epoch": epoch})


DECISION = {
    "is_found": True,
    "in_whitelist": False,
    "in_hsts": False,
    "null_blocking": False,
    "nxdomain": False,
    "log_type": "1",
    "b_type": "DNSBL",
    "p_type": "Python",
    "feed": "Feed",
    "group": "G1",
    "b_eval": "example.com",
    "idn_alert": None,
    "group_owner": "G1",
    "group_origin": "custom",
}

SCENARIOS = []


def scenario(name, files, presql=None, worker=False):
    def decorate(build):
        runner = Runner(name, files, presql, worker)
        try:
            build(runner)
            SCENARIOS.append(
                {"name": name, "files": files, "presql": presql or {}, "worker": worker, "steps": runner.steps}
            )
        finally:
            runner.close()
        return build

    return decorate


def q(name, qtype=1, client=CLIENT, transport="UDP", lip="", lif=""):
    return {"qname": name, "qtype": qtype, "client": client, "transport": transport, "lip": lip, "lif": lif}


def both(r):
    for db in ("resolver", "dnsbl"):
        r.reconnect(db)


# ---- a: schema -----------------------------------------------------------------------------------------------------


@scenario("create-and-recreate", module_files(feeds=FEEDS))
def _(r):
    r.dump()  # created on an empty file: the seeds, the builtin owners, the metric tables
    r.enqueue("resolver", "A", "UDP", "", "", "", "")
    r.sql("resolver", "UPDATE resolver SET totalqueries = totalqueries + 6 WHERE row = 0")
    both(r)  # the tables are created again over the existing ones
    r.dump()


@scenario(
    "custom-owner-rows",
    module_files(feeds=FEEDS),
    {
        "dnsbl": [
            "CREATE TABLE dnsbl (groupname TEXT, timestamp TEXT, entries INTEGER, counter INTEGER)",
            "INSERT INTO dnsbl VALUES ('DNSBL_Alpha', '', 1, 4), ('DNSBL_Beta', '', 1, 0), ('DNSBL_Alpha', '', 1, 0)",
            "INSERT INTO dnsbl VALUES ('DNSBL_Homoglyph', '', 1, 0), ('DNSBL_TLD', '', 1, 0), ('Plain', '', 1, 2)",
            "INSERT INTO dnsbl VALUES ('DNSBL_', '', 1, 0), ('dnsbl_lower', '', 1, 0), ('DNSBL_Upstream', '', 1, 0)",
        ]
    },
)
def _(r):
    r.dump()


@scenario(
    "migrate-resolver-v1",
    module_files(feeds=FEEDS),
    {
        "resolver": [
            "CREATE TABLE resolver (row integer, totalqueries integer, queries integer)",
            "INSERT INTO resolver VALUES (0, 40, 0)",
            "CREATE TABLE dns_metric_queries (qtype TEXT NOT NULL DEFAULT '', transport TEXT NOT NULL DEFAULT '', "
            "count INTEGER NOT NULL, PRIMARY KEY(qtype,transport))",
            "INSERT INTO dns_metric_queries VALUES ('A', 'UDP', 30), ('AAAA', '', 10)",
        ]
    },
)
def _(r):
    r.dump()  # the old rows carry over under blank listener, interface and client
    r.resolve("lf1.example.", transport="TCP", lip="192.0.2.1", lif="em0")
    r.dump()


@scenario(
    "migrate-dnsbl-v1",
    module_files(feeds=FEEDS),
    {
        "dnsbl": custom_groups(["G1"], 9)
        + [
            "CREATE TABLE dns_metric_blocks (owner TEXT NOT NULL DEFAULT '', origin TEXT NOT NULL DEFAULT '', "
            "groupname TEXT NOT NULL DEFAULT '', qtype TEXT NOT NULL DEFAULT '', transport TEXT NOT NULL DEFAULT '', "
            "count INTEGER NOT NULL, PRIMARY KEY(owner,origin,groupname,qtype,transport))",
            "INSERT INTO dns_metric_blocks VALUES ('G1', 'custom', 'G1', 'A', 'UDP', 9)",
        ],
    },
)
def _(r):
    r.dump()
    r.resolve("lf1.example.")
    r.dump()


@scenario(
    "migrate-current-schema-is-kept",
    module_files(feeds=FEEDS),
)
def _(r):
    r.resolve("lf1.example.")
    r.reboot()  # the second init finds both metric tables already current
    r.dump()


@scenario(
    "unknown-schema-is-recovered",
    module_files(feeds=FEEDS),
    {
        "resolver": [
            "CREATE TABLE resolver (row integer, totalqueries integer, queries integer)",
            "INSERT INTO resolver VALUES (0, 77, 0)",
            "CREATE TABLE dns_metric_queries (qtype TEXT, other TEXT, count INTEGER)",
            "INSERT INTO dns_metric_queries VALUES ('A', 'x', 3)",
        ],
        "dnsbl": custom_groups(["G1"], 5)
        + [
            "CREATE TABLE dns_metric_blocks (groupname TEXT, count INTEGER)",
            "INSERT INTO dns_metric_blocks VALUES ('G1', 5)",
        ],
    },
)
def _(r):
    r.dump()  # init could not use either file: both were removed and created fresh, the old counts gone


# ---- b: resolver counters ------------------------------------------------------------------------------------------


@scenario("resolver-counters", module_files(feeds=FEEDS))
def _(r):
    for qtype, name, transport in [
        (1, "A", "UDP"),
        (28, "AAAA", "TCP"),
        (16, "TXT", "DoT"),
        (65, "HTTPS", "DoH"),
        (64, "SVCB", "DoQ"),
        (65400, "TYPE65400", "DoH"),
        (65401, "TYPE65401", "Unknown"),
        (65400, "TYPE65400", ""),
        (1, "A", "UDP"),
    ]:
        r.details_reply("cache", q("counted.example.", qtype, transport=transport), {"pfb_addr": CLIENT})
    r.details_reply("cache", q("counted.example.", 1), {"pfb_addr": "127.0.0.1"})  # the resolver's own: not counted
    r.details_reply("cache", q("counted.example.", 1), {"pfb_addr": "Unknown"})
    r.details_reply("cache", q("counted.example.", 1, client=""), None)
    r.details_reply(
        "cache", None, {"pfb_addr": CLIENT, "pfb_transport": "DoH"}, qinfo={"qname": "q.example.", "qtype": 65400}
    )
    r.details_reply("cache", None, {"pfb_addr": CLIENT}, qinfo={"qname": "q.example.", "qtype": 65400})
    for lip, lif in (
        ("192.0.2.1", "em0"),
        ("2001:db8::1", "vlan,10"),
        ("not-an-ip", "em0"),
        ("192.0.2.1", "em\x1b0"),
        ("", "em0"),
    ):
        r.details_reply("reply", q("counted.example.", 1, lip=lip, lif=lif), {"pfb_addr": CLIENT})
    r.details_reply("reply-x", q("counted.example.", 1), {"pfb_addr": CLIENT})  # the filter drops it before the counter
    r.details_reply("reply-x", q("python_control.x.example.", 1), {"pfb_addr": CLIENT})
    r.resolve("lf1.example.")
    r.resolve("nothing.example.", 28, client="2001:db8::12", transport="DoT", lip="192.0.2.1", lif="em0")
    r.dump()


@scenario("resolver-reply-logging-off", module_files(main={"python_reply": "false"}, feeds=FEEDS))
def _(r):
    r.details_reply("cache", q("counted.example.", 1), {"pfb_addr": CLIENT})  # counted although no row is written
    r.dump()


# ---- c: DNSBL counters ---------------------------------------------------------------------------------------------


@scenario("dnsbl-counters", module_files(feeds=FEEDS), {"dnsbl": custom_groups(GROUPS, 7)})
def _(r):
    for flag in range(7):  # every log type, the silent 2, 4 and 6 included, counts
        r.resolve(f"lf{flag}.example.")
    r.resolve("lf1.example.", 28, transport="TCP", lip="192.0.2.1", lif="em0")
    r.resolve("lf1.example.", 255, transport="DoT")
    r.resolve("lf0.example.", 28, client="2001:db8::12")
    r.resolve("other.example.", client="192.0.2.99")
    r.resolve("LF1.Example.")  # the memo-served repeat
    r.resolve("sub.lf1.example.")  # not blocked: no counter
    r.dump()
    for log_type in ("1", "2", "4", "6"):
        r.details_dnsbl(
            q("x.example.", 1), {"log_type": log_type, "group": "G2", "group_owner": "G2"}, {"pfb_addr": CLIENT}
        )
    r.details_dnsbl(
        q("x.example.", 28), {"null_blocking": True, "group": "G3", "group_owner": "G3"}, {"pfb_addr": CLIENT}
    )
    r.details_dnsbl(q("x.example.", 1), {"group": ""}, {"pfb_addr": CLIENT})  # no group: no group counter
    r.details_dnsbl(q("x.example.", 1), {"in_whitelist": True}, {"pfb_addr": CLIENT})  # not a block: resolver only
    r.details_dnsbl(q("x.example.", 1), {"is_found": False}, {"pfb_addr": CLIENT})
    r.details_dnsbl(q("x.example.", 1), {}, {"pfb_addr": CLIENT}, epoch="")  # no epoch: no group counter
    r.details_dnsbl(q("x.example.", 1), {"group": "Gnew", "group_owner": "Gnew"}, {"pfb_addr": CLIENT})  # no epoch row
    r.dump()


@scenario(
    "dnsbl-python-nolog", module_files(main={"python_nolog": "true"}, feeds=FEEDS), {"dnsbl": custom_groups(GROUPS, 7)}
)
def _(r):
    r.resolve("lf1.example.")  # a VIP block: no row and no group counter, the resolver still counts
    r.resolve("lf0.example.")  # a null block: logged and counted
    r.resolve("lf2.example.")
    r.dump()


@scenario("dnsbl-builtin-and-upstream", module_files(feeds=FEEDS))
def _(r):
    r.let("up", "dnsbl", "SELECT epoch FROM dnsbl_group_epochs WHERE owner='Upstream' AND origin='builtin'")
    r.let("idn", "dnsbl", "SELECT epoch FROM dnsbl_group_epochs WHERE owner='DNSBL_IDN' AND origin='builtin'")
    for transport in ("UDP", "TCP", "DoT", "DoH", "DoQ", ""):
        r.enqueue("dnsbl", "Upstream", "Upstream", "builtin", "$up", "TXT", transport, "", "", "", "")
    r.enqueue("dnsbl", "Upstream", "Upstream", "builtin", "$up", "TXT", "UDP", "192.0.2.1", "em0", "", "")
    r.enqueue(
        "dnsbl", "Upstream", "Upstream", "custom", "$up", "TXT", "UDP", "", "", "", ""
    )  # custom has no such owner
    r.enqueue("dnsbl", "Upstream", "Upstream", "builtin", "wrong", "TXT", "UDP", "", "", "", "")  # a stale epoch
    r.enqueue(
        "dnsbl", "Upstream", "Upstream", "weird", "$up", "TXT", "UDP", "", "", "", ""
    )  # origin is not custom/builtin
    r.enqueue("dnsbl", "DNSBL_IDN", "DNSBL_IDN", "builtin", "$idn", "A", "UDP", "", "", "", "")
    r.enqueue(
        "dnsbl", "Feed group", "DNSBL_IDN", "builtin", "$idn", "A", "UDP", "", "", "", ""
    )  # group differs from owner
    r.dump()


@scenario("dnsbl-deleted-incarnation", module_files(feeds=FEEDS), {"dnsbl": custom_groups(["G1"], 7)})
def _(r):
    r.resolve("lf1.example.")  # counted under the first incarnation
    r.let("old", "dnsbl", "SELECT epoch FROM dnsbl_group_epochs WHERE owner='G1'")
    r.sql(
        "dnsbl",
        "DELETE FROM dnsbl_group_epochs WHERE owner='G1'",
        "INSERT INTO dnsbl_group_epochs VALUES ('G1', 'custom', lower(hex(randomblob(16))))",
    )  # the group was deleted and created again
    r.details_dnsbl(q("x.example.", 1), {}, {"pfb_addr": CLIENT}, epoch="$old")  # an old snapshot: not resurrected
    r.resolve("LF1.example.", 28)  # the live snapshot still carries the old epoch too
    r.dump()
    r.refresh_epochs()
    r.details_dnsbl(q("x.example.", 1), {}, {"pfb_addr": CLIENT})  # the new incarnation counts
    r.dump()
    r.sql("dnsbl", "DELETE FROM dnsbl_group_epochs WHERE owner='G1'")  # deleted for good
    r.details_dnsbl(q("x.example.", 1), {}, {"pfb_addr": CLIENT})
    r.dump()


@scenario(
    "dnsbl-row-self-heals",
    module_files(feeds=FEEDS),
    {
        "dnsbl": [
            "CREATE TABLE dnsbl (groupname TEXT, timestamp TEXT, entries INTEGER, counter INTEGER)",
            "CREATE TABLE dnsbl_group_epochs (owner TEXT NOT NULL, origin TEXT NOT NULL, epoch TEXT NOT NULL, "
            "PRIMARY KEY(owner, origin))",
            "INSERT INTO dnsbl_group_epochs VALUES ('G1', 'custom', '00000000000000000000000000000001')",
        ]
    },
)
def _(r):
    r.dump()  # the owner has an epoch and no counter row
    r.resolve("lf1.example.")  # the write creates the row and counts
    r.dump()


# ---- d: privacy ----------------------------------------------------------------------------------------------------

CLIENTS = ("192.0.2.10", "2001:db8::53", "::ffff:192.0.2.7", "fe80::1%em0", "0.0.0.0", "::", "Unknown", "bad")


def count_clients(r):
    for client in CLIENTS:
        r.details_dnsbl(q("x.example.", 1, client=client, lip="192.0.2.53", lif="LAN"), {}, {"pfb_addr": client})
        r.details_reply("cache", q("x.example.", 1, client=client, lip="192.0.2.53", lif="LAN"), {"pfb_addr": client})


@scenario("privacy-default-off", module_files(feeds=FEEDS), {"dnsbl": custom_groups(["G1"])})
def _(r):
    count_clients(r)  # metrics_client_ip is off: no client is stored
    r.dump()


@scenario(
    "privacy-ini-optin-cannot-promote",
    module_files(main={"metrics_client_ip": "true"}, feeds=FEEDS),
    {"dnsbl": custom_groups(["G1"])},
)
def _(r):
    count_clients(r)  # the databases are client_ip=0: the ini alone grants no authority
    r.dump()


@scenario(
    "privacy-optin-epochs",
    module_files(main={"metrics_client_ip": "true"}, feeds=FEEDS),
    {"dnsbl": custom_groups(["G1"])},
)
def _(r):
    r.sql("resolver", "UPDATE dns_metric_settings SET client_ip=1 WHERE row=0")
    r.sql("dnsbl", "UPDATE dns_metric_settings SET client_ip=1 WHERE row=0")
    r.reboot()  # init captures the opted-in epochs
    count_clients(r)
    r.dump()
    r.sql("resolver", "UPDATE dns_metric_settings SET epoch=lower(hex(randomblob(16))) WHERE row=0")
    r.sql("dnsbl", "UPDATE dns_metric_settings SET client_ip=0 WHERE row=0")
    count_clients(r)  # the epoch moved on and the policy went off: the clients this process holds are no longer stored
    r.dump()


@scenario("privacy-ini-off-withholds-optin", module_files(feeds=FEEDS), {"dnsbl": custom_groups(["G1"])})
def _(r):
    r.sql("resolver", "UPDATE dns_metric_settings SET client_ip=1 WHERE row=0")
    r.sql("dnsbl", "UPDATE dns_metric_settings SET client_ip=1 WHERE row=0")
    r.reboot()
    count_clients(r)
    r.dump()


@scenario(
    "privacy-retained-details",
    module_files(main={"metrics_client_ip": "true"}, feeds=FEEDS),
    {"dnsbl": custom_groups(["G1"])},
)
def _(r):
    r.sql("resolver", "UPDATE dns_metric_settings SET client_ip=1 WHERE row=0")
    r.sql("dnsbl", "UPDATE dns_metric_settings SET client_ip=1 WHERE row=0")
    r.let("rs", "resolver", "SELECT epoch FROM dns_metric_settings WHERE row=0")
    r.let("ds", "dnsbl", "SELECT epoch FROM dns_metric_settings WHERE row=0")
    r.let("g1", "dnsbl", "SELECT epoch FROM dnsbl_group_epochs WHERE owner='G1'")
    r.flush_resolver(
        3, [(["A", "UDP", "", "", "2001:db8::53", "$rs"], 2), (["A", "UDP", "", "", "2001:db8::54", "stale"], 1)]
    )
    r.flush_dnsbl(
        [(["G1", "G1", "custom", "$g1"], 3)],
        [
            (["G1", "G1", "custom", "$g1", "A", "UDP", "", "", "2001:db8::53", "$ds"], 2),
            (["G1", "G1", "custom", "$g1", "A", "UDP", "", "", "2001:db8::54", "stale"], 1),
            (["G1", "G1", "custom", "$g1", "A", "UDP", "", "", "", ""], 4),
        ],
    )  # a retained batch: the stale-epoch clients fold into the blank row
    r.sql("dnsbl", "UPDATE dns_metric_settings SET epoch='ffffffffffffffffffffffffffffffff' WHERE row=0")
    r.flush_dnsbl(
        [(["G1", "G1", "custom", "$g1"], 1)],
        [(["G1", "G1", "custom", "$g1", "A", "UDP", "", "", "2001:db8::53", "$ds"], 1)],
    )
    r.dump()


# ---- e: worker -----------------------------------------------------------------------------------------------------


@scenario(
    "worker-batches-and-stop-flushes", module_files(feeds=FEEDS), {"dnsbl": custom_groups(GROUPS, 7)}, worker=True
)
def _(r):
    for i in range(40):
        r.resolve(
            f"lf{i % 7}.example.", 1 + (i % 3) * 27, transport=("UDP", "TCP", "DoT")[i % 3], client=f"192.0.2.{i % 5}"
        )
    r.details_reply("cache", q("counted.example.", 1), {"pfb_addr": CLIENT})
    r.stop()  # the stop task flushes what the worker holds
    r.dump()
    r.resolve("lf1.example.")  # after the stop the counters are written synchronously
    r.dump()


@scenario("reconnect-after-database-removed", module_files(feeds=FEEDS), {"dnsbl": custom_groups(["G1"], 7)})
def _(r):
    r.enqueue("resolver", "A", "UDP", "", "", "", "")
    r.remove("resolver")
    r.enqueue("resolver", "A", "UDP", "", "", "", "")  # reconnect, create again, write
    r.remove("dnsbl")  # the custom owner rows are gone with the file: the next counter is refused
    r.resolve("lf1.example.")
    r.dump()


# ---- f: gating -----------------------------------------------------------------------------------------------------


@scenario("gating-python-enable-off", module_files(main={"python_enable": "false"}, feeds=FEEDS))
def _(r):
    r.resolve("lf1.example.")
    r.dump()  # no database is opened


@scenario("gating-no-lists", module_files())
def _(r):
    r.resolve("nothing.example.")
    r.dump()  # the resolver database only: nothing wants DNSBL statistics


@scenario("gating-forwarding-only", module_files(main={"forwarding": "true"}))
def _(r):
    r.dump()  # forwarding alone wants the DNSBL database for the Upstream counter


@scenario("gating-control-enable", module_files())
def _(r):
    r.control("python_control", "disable")
    r.dump()
    r.control("python_control", "enable")
    r.dump()  # enabling opens the DNSBL database init skipped


@scenario("gating-control-timer-expiry", module_files())
def _(r):
    r.control_sleep()  # the disable timer expired: blocking is back and the database opens
    r.dump()


@scenario("gating-swap-opens-dnsbl", module_files())
def _(r):
    r.swap(True)  # a swap that brings lists flips the blocking gate and opens the DNSBL database
    r.dump()


@scenario("gating-swap-without-lists-keeps-closed", module_files())
def _(r):
    r.swap(False)
    r.dump()


def module_constants():
    runner = Runner("constants", module_files())
    try:
        m = runner.module
        return {
            "queue_maxsize": m.PFB_DB_QUEUE_MAXSIZE,
            "flush_interval": m.PFB_DB_FLUSH_INTERVAL,
            "max_batch": m.PFB_DB_MAX_BATCH,
            "builtin_owners": list(m._DNSBL_BUILTIN_OWNERS),
        }
    finally:
        runner.close()


def main():
    out = {
        "python": sys.version.split()[0],
        "stamp": STAMP,
        "now": NOW,
        "constants": module_constants(),
        "scenarios": SCENARIOS,
    }
    OUT.write_text(json.dumps(out, indent=1, ensure_ascii=True) + "\n", encoding="utf-8")
    steps = [step for scenario in SCENARIOS for step in scenario["steps"]]
    print(f"{OUT.name}: {len(SCENARIOS)} scenarios, {len(steps)} steps, {sum(s['op'] == 'dump' for s in steps)} dumps")


if __name__ == "__main__":
    main()

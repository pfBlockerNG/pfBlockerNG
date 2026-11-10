# Records what the shipped pfb_unbound.py (CPython 3.11, booted through the dns_proxy shim) does with the upstream
# observer's reports, for pfb_unbound_observer_oracle_test.go to replay: every scenario boots a module with a staged
# module directory, then feeds each datagram through the REAL pfb_dns_proxy.Frontend.relay_upstream_response with
# make_timestamp and time.time fixed and pfb_log captured. A datagram step records the dnsbl.log rows it wrote, the
# lines it printed to stderr (the proxy's warning and the module's own error line), and the bytes of Frontend.resolve's
# answer to one fixed query before and after it, which must be equal. A dump step records both stats databases: every
# table's SQL, columns and rows, the randomblob epochs replaced by one token per distinct value.
# Run from the repo root:
#   TMPDIR=<scratch dir> uv run --python 3.11.15 python \
#     go/pfb_dns_gateway/decider/testdata/gen_pfb_unbound_observer_oracle.py
# It rewrites testdata/pfb_unbound_observer_oracle.json.
import asyncio
import calendar
import io
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

secrets.randbits = lambda bits: 0x1234

STAMP = "2026-10-18 12:00:00"
NOW = calendar.timegm((2026, 10, 18, 12, 0, 0))
CLIENT = "192.0.2.10"
OUT = HERE / "pfb_unbound_observer_oracle.json"
RESOLVER_DB = "pfb_py_resolver.sqlite"
DNSBL_DB = "pfb_py_dnsbl.sqlite"
DBS = {"resolver": RESOLVER_DB, "dnsbl": DNSBL_DB}
EPOCH = re.compile(r"^[0-9a-f]{32}$")
STAMPED = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$")

MAIN = {"python_enable": "true", "python_blocking": "true", "dnsbl_ipv4": "10.10.10.1", "forwarding": "true"}
PROBE_NAME = "probe.example."
PROBE_ZONE = {(PROBE_NAME, 1): [f"{PROBE_NAME} 300 IN A 192.0.2.99"]}
PROBE_WIRE = build_query(PROBE_NAME, 1)
PROBE_REPLY = FakeUnbound(PROBE_ZONE).answer(PROBE_WIRE)

NXDOMAIN_RECURSIVE = 0x8183  # QR RD RA, NXDOMAIN
NXRA = 0x8103  # QR RD, NXDOMAIN: RA clear
NXDOMAIN_AUTHORITATIVE = 0x8503  # QR AA RD, NXDOMAIN
NXDOMAIN_AUTHORITATIVE_RA = 0x8583
NOERROR = 0x8180


def is_surrogate(char):
    return "\ud800" <= char <= "\udfff"


def hx(data):
    return None if data is None else data.hex()


def ede(info, text=b""):
    return [15, (info.to_bytes(2, "big") + text).hex()]


EDE15_BLOCKED = ede(15, b"Blocked by Quad9")


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


def report(**overrides):
    fields = {
        "client": CLIENT,
        "qname": "blocked.example.",
        "qtype": 1,
        "flags": NXDOMAIN_RECURSIVE,
        "opts": [EDE15_BLOCKED],
    }
    return json.dumps({**fields, **overrides}).encode()


def raw_report(client='"192.0.2.10"', qname='"blocked.example."', qtype="1", flags=str(NXRA), opts="[]"):
    """A report from JSON tokens written by hand, for the spellings json.dumps never writes."""
    return f'{{"client":{client},"qname":{qname},"qtype":{qtype},"flags":{flags},"opts":{opts}}}'.encode()


def option_of_hex_size(digits):
    """The EDE15 block option padded (extra text) to exactly `digits` hex digits."""
    return [15, (bytes.fromhex(EDE15_BLOCKED[1]) + b"a" * (digits // 2 - len(EDE15_BLOCKED[1]) // 2)).hex()]


def utf8_report(**overrides):
    """A report with its non-ASCII characters written as themselves, so that a long name still fits a datagram."""
    fields = {
        "client": CLIENT,
        "qname": "blocked.example.",
        "qtype": 1,
        "flags": NXDOMAIN_RECURSIVE,
        "opts": [EDE15_BLOCKED],
    }
    return json.dumps({**fields, **overrides}, ensure_ascii=False).encode()


def block_with_options(count):
    return report(opts=[EDE15_BLOCKED, *[[10, "0102"]] * (count - 1)])


def oversize_report():
    return report(opts=[EDE15_BLOCKED, *[[10, "ab" * 512]] * 7])


def padded_to(size):
    """A valid report of exactly `size` bytes: an unknown key, which the receiver ignores, takes up the rest."""
    base = len(report(pad=""))
    return report(pad="a" * (size - base))


# The 27 fixtures tests/dns_proxy/test_upstream_observer.py calls MALFORMED, in its order.
MALFORMED = {
    "not json": b"not json",
    "empty": b"",
    "not utf-8": b"\xff\xfe\x00",
    "not an object": b"[1, 2]",
    "nested deeper than the parser recurses": b"[" * 5000,
    "json null": b"null",
    "no fields": b"{}",
    "qname not a string": report(qname=7),
    "qname too long": report(qname="a" * 1025),
    "qtype not a number": report(qtype="A"),
    "qtype a boolean": report(qtype=True),
    "qtype out of range": report(qtype=70000),
    "flags not a number": report(flags="x"),
    "flags fractional": report(flags=1.5),
    "flags negative": report(flags=-1),
    "flags out of range": report(flags=70000),
    "client not an address": report(client="not-an-ip"),
    "client not a string": report(client=5),
    "opts not a list": report(opts="x"),
    "option not a pair": report(opts=[[15]]),
    "option code not a number": report(opts=[["a", "00"]]),
    "option code out of range": report(opts=[[70000, "00"]]),
    "option data not hex": report(opts=[[15, "zz"]]),
    "option data not a string": report(opts=[[15, 5]]),
    "option data over the cap": report(opts=[option_of_hex_size(pfb_dns_proxy.MAX_REPORT_OPTION_HEX + 2)]),
    "too many options": block_with_options(pfb_dns_proxy.MAX_REPORT_OPTIONS + 1),
    "over a datagram in all": oversize_report(),
}
assert len(MALFORMED) == 27

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


# ---- the Python side of one scenario -------------------------------------------------------------------------------


class Clock:
    """Stands in for the module's `time`: time.time() is fixed, everything else is the real module's."""

    def __getattr__(self, name):
        return getattr(time, name)

    @staticmethod
    def time():
        return float(NOW)


class Runner:
    def __init__(self, name, files):
        self.name, self.files = name, files
        self.dir = Path(tempfile.mkdtemp(prefix="pfbobserver"))
        for rel, text in files.items():
            target = self.dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        for shipped in ("pfb_unbound.py", "pfb_dnsbl_regex_rules.py"):
            (self.dir / shipped).symlink_to(SHIPPED / shipped)
        self.cwd = os.getcwd()
        self.steps = []
        self.rows = []
        self.module = None
        self.frontend = None
        self.start()

    def start(self):
        self.module = pfb_dns_proxy.boot(str(self.dir))
        m = self.module
        m.pfb_log = self.capture
        m.make_timestamp = lambda: STAMP
        m.time = Clock()
        m._dnsbl_last_event = None
        if m.pfb.get("db_worker"):  # close-and-wait: later counters are written synchronously
            m.pfb_db_queue.put(("stop",))
            m.pfb_db_worker_thread.join(timeout=10)
            assert not m.pfb_db_worker_thread.is_alive()
            m.pfb["db_worker"] = False
        self.frontend = pfb_dns_proxy.Frontend(m)

    def capture(self, log, line):
        self.rows.append([os.path.basename(log), line])

    def close(self):
        if self.module is not None:
            pfb_dns_proxy.shutdown(self.module)
        os.chdir(self.cwd)
        shutil.rmtree(self.dir)

    def record(self, step):
        self.steps.append(step)

    def probe(self):
        """Frontend.resolve's answer to the fixed query; the rows the query itself writes are not the scenario's."""
        mark = len(self.rows)

        async def forward(data):
            return PROBE_REPLY

        answer = asyncio.run(pfb_dns_proxy.Frontend(self.module).resolve(PROBE_WIRE, CLIENT, forward, transport="UDP"))
        del self.rows[mark:]
        return answer

    def observe(self, act, step):
        """Run `act` between two probes, recording the rows and the stderr lines it produced and both answers."""
        before = self.probe()
        mark = len(self.rows)
        printed = io.StringIO()
        saved = sys.stderr, sys.__stderr__
        sys.stderr = sys.__stderr__ = printed
        try:
            act()
        finally:
            sys.stderr, sys.__stderr__ = saved
        rows = self.rows[mark:]
        del self.rows[mark:]
        after = self.probe()
        assert before == after, step["note"]
        wtf8 = {}
        if any(is_surrogate(c) for _, line in rows for c in line):
            # A row holding a lone surrogate has no JSON spelling a Go reader keeps: its bytes, as surrogatepass writes
            # them, stand in for it.
            wtf8 = {"rows_wtf8": [[name, line.encode("utf-8", "surrogatepass").hex()] for name, line in rows]}
            rows = []
        self.record(
            {
                **step,
                **wtf8,
                "rows": rows,
                "stderr": printed.getvalue().splitlines(),
                "before": hx(before),
                "after": hx(after),
            }
        )

    def datagram(self, data, note, new_frontend=True):
        if new_frontend:
            self.frontend = pfb_dns_proxy.Frontend(self.module)
        step = {"op": "datagram", "note": note, "hex": data.hex(), "new_frontend": new_frontend}
        self.observe(lambda: self.frontend.relay_upstream_response(data), step)

    def fire(
        self,
        note,
        flags,
        opts,
        *,
        qname="blocked.example.",
        qtype=1,
        client=CLIENT,
        transport="Unknown",
        lip="",
        lif="",
    ):
        """The shim's fire_query_response with a qstate of the test's own making: the listener and transport the
        observer path never has, and the upstream's EDNS options."""
        qinfo = shim.query_info(qname, qtype)
        qstate = shim.module_qstate(qinfo, client, 0, 0, transport, lip, lif)
        qstate.edns_opts_back_in_iter = [shim.EdnsOpt(code, bytes.fromhex(data)) for code, data in opts]
        step = {
            "op": "fire",
            "note": note,
            "qname": qname,
            "qtype": qtype,
            "client": client,
            "transport": transport,
            "lip": lip,
            "lif": lif,
            "flags": flags,
            "opts": opts,
        }
        self.observe(lambda: shim.fire_query_response(qstate, shim.DnsMsg(qinfo, flags, [], [], [])), step)

    def dump(self):
        self.record({"op": "dump", "dump": dump_all(self.dir)})

    def sql(self, db, *statements):
        con = sqlite3.connect(self.dir / DBS[db])
        for statement in statements:
            con.execute(statement)
        con.commit()
        con.close()
        self.record({"op": "sql", "db": db, "statements": list(statements)})

    def reboot(self):
        pfb_dns_proxy.shutdown(self.module)
        os.chdir(self.cwd)
        self.start()
        self.record({"op": "reboot"})

    def gate_off(self):
        self.module.pfb["sqlite3_dnsbl_con"] = False
        self.record({"op": "gate_off"})

    def drop_epoch(self):
        del self.module._snapshot.group_epochs[("Upstream", "builtin")]
        self.record({"op": "drop_epoch"})

    def log_raises(self):
        def raises(log, line):
            raise RuntimeError("boom")

        self.module.pfb_log = raises
        self.record({"op": "log_raises"})

    def log_works(self):
        self.module.pfb_log = self.capture
        self.record({"op": "log_works"})


SCENARIOS = []


def scenario(name, files):
    def decorate(build):
        runner = Runner(name, files)
        try:
            build(runner)
            SCENARIOS.append({"name": name, "files": files, "steps": runner.steps})
        finally:
            runner.close()
        return build

    return decorate


# ---- the classifier's signals --------------------------------------------------------------------------------------


@scenario("signals", module_files())
def _(r):
    r.dump()  # the seeded Upstream row at zero
    d = r.datagram
    d(report(flags=NXRA, opts=[]), "NXRA: rcode NXDOMAIN, RA clear, no EDE")
    d(report(), "EDE15 with a provider")
    d(report(opts=[ede(17, b"Filtered by Quad9")], flags=NOERROR), "EDE17 with a provider")
    d(report(opts=[ede(15)]), "EDE15 with no provider text: External")
    d(report(opts=[ede(17)], flags=NOERROR), "EDE17 with no provider text: External")
    d(report(opts=[ede(17, b"second"), ede(15, b"first")]), "EDE15 and EDE17 together, EDE15 first whatever the order")
    d(report(opts=[ede(15, b"one"), ede(15, b"two")]), "only the first EDE15 counts")
    d(report(opts=[ede(17, b"one"), ede(17, b"two")], flags=NOERROR), "only the first EDE17 counts")
    d(report(opts=[ede(15, b"one"), ede(17, b"two"), ede(15, b"three")]), "the first EDE15 wins over a later one")
    d(report(opts=[ede(5, b"Other")], flags=NOERROR), "an unrecognised EDE code on a NOERROR reply: no block")
    d(report(opts=[ede(5, b"Other")], flags=NXRA), "an unrecognised EDE code on an NXRA reply: NXRA")
    d(report(opts=[ede(5, b"Other"), ede(17, b"Seventeen")], flags=NOERROR), "an unrecognised code, then EDE17")
    d(report(opts=[[15, "0f"]], flags=NOERROR), "an EDE option of one byte is not an EDE: no block")
    d(report(opts=[[15, "0f"]], flags=NXRA), "an EDE option of one byte on an NXRA reply: NXRA")
    d(report(opts=[[15, ""]], flags=NXRA), "an EDE option of no bytes on an NXRA reply: NXRA")
    d(report(opts=[[10, "000f426c6f636b6564"]], flags=NOERROR), "info bytes under another option code: no block")
    d(report(opts=[[10, "000f426c6f636b6564"]], flags=NXRA), "info bytes under another option code on NXRA: NXRA")
    d(report(opts=[ede(0x010F, b"x")], flags=NXRA), "info code 0x010F is not 15: NXRA")
    d(report(opts=[ede(15, b"x")], flags=NOERROR), "EDE15 on a NOERROR reply")
    d(report(opts=[ede(15, b"x")], flags=0x8182), "EDE15 on a SERVFAIL reply")
    d(report(flags=NXDOMAIN_RECURSIVE, opts=[]), "a natural NXDOMAIN (RA set): no block")
    d(report(flags=NXDOMAIN_AUTHORITATIVE, opts=[]), "an authoritative NXDOMAIN (AA set): no block")
    d(report(flags=NXDOMAIN_AUTHORITATIVE_RA, opts=[]), "an authoritative NXDOMAIN with RA: no block")
    d(report(flags=NXDOMAIN_AUTHORITATIVE, opts=[ede(15, b"AA wins nothing")]), "EDE15 beats the AA exclusion")
    d(report(flags=NOERROR, opts=[]), "NOERROR with no EDE: no block")
    d(report(flags=0x0003, opts=[]), "an NXDOMAIN with QR clear and RA clear is still NXRA")
    d(report(flags=0x8110, opts=[]), "a header bit above the rcode nibble is not the rcode: NOERROR, no block")
    d(report(flags=0x8113, opts=[]), "a header bit above the rcode nibble does not hide the rcode: NXRA")
    d(report(opts=[ede(15, b"  Quad9 \t")]), "provider text stripped of whitespace")
    d(report(opts=[ede(15, "\u00a0Unicode\u3000".encode())]), "provider text stripped of Unicode whitespace")
    d(report(opts=[ede(15, b"   ")]), "provider text of only whitespace: External")
    d(report(opts=[ede(15, b"bad\xff\xfeutf8")]), "provider text that is not UTF-8: replacement characters")
    d(report(opts=[ede(15, b"cut\xe2\x82")]), "provider text cut inside a character: one replacement character")
    d(report(opts=[ede(15, b"\xf0\x9f\x98\x80 smile")]), "provider text with a character above the BMP")
    d(report(opts=[ede(15, b'<b>"x"</b>, a\\b&\'c\\')]), "hostile provider text: HTML, comma, quote, backslashes")
    d(report(opts=[ede(15, b"ctl\x01\x1b[31m\x7f\xc2\x85line\nfeed\rreturn")]), "provider text with control characters")
    d(report(opts=[ede(15, "zw\u200bbidi\u202e\u2066end".encode())]), "provider text with format characters")
    d(report(opts=[ede(15, b"end with backslash\\")]), "provider text ending in a backslash")
    d(report(opts=[ede(15, b"a" * 509)]), "provider text of 509 bytes")
    d(report(opts=[[3, "00"], [15, "000f50"], [10, "ff"]]), "the block among unrelated options")
    d(report(opts=[[0, ""], [65535, "ff"], ede(17, b"k")], flags=NOERROR), "options at the ends of the code range")
    r.dump()


@scenario("fire", module_files())
def _(r):
    block = [EDE15_BLOCKED[0:1] + [EDE15_BLOCKED[1]]]
    f = r.fire
    f(
        "a qstate that carries a listener and a transport: the row has them",
        NXRA,
        [],
        transport="UDP",
        lip="192.0.2.53",
        lif="LAN",
    )
    f("DoT on an IPv6 listener", NOERROR, block, transport="DoT", lip="2001:db8::53", lif="WAN")
    f("DoH on an IPv4-mapped listener", NOERROR, block, transport="DoH", lip="::ffff:192.0.2.53", lif="")
    f("DoQ", NOERROR, block, transport="DoQ", lip="192.0.2.53", lif="LAN")
    f("TCP", NOERROR, block, transport="TCP", lip="192.0.2.53", lif="LAN")
    f("a transport that is not one of the five: Unknown", NOERROR, block, transport="XYZ", lip="192.0.2.53", lif="LAN")
    f(
        "a lower-case transport is not one of the five: Unknown",
        NOERROR,
        block,
        transport="udp",
        lip="192.0.2.53",
        lif="LAN",
    )
    f("a listener address that is not one: no listener at all", NOERROR, block, transport="UDP", lip="nope", lif="LAN")
    f("an unspecified listener address: no listener at all", NOERROR, block, transport="UDP", lip="0.0.0.0", lif="LAN")
    f(
        "a listener address with a zone: no listener at all",
        NOERROR,
        block,
        transport="UDP",
        lip="fe80::1%em0",
        lif="LAN",
    )
    f(
        "an interface label with a control character: dropped",
        NOERROR,
        block,
        transport="UDP",
        lip="192.0.2.53",
        lif="L\x01N",
    )
    f(
        "an interface label with a format character: dropped",
        NOERROR,
        block,
        transport="UDP",
        lip="192.0.2.53",
        lif="L\u200bN",
    )
    f(
        "an interface label with a line separator: dropped",
        NOERROR,
        block,
        transport="UDP",
        lip="192.0.2.53",
        lif="L\u2028N",
    )
    f(
        "an interface label with a comma and a quote: quoted in the row",
        NOERROR,
        block,
        transport="UDP",
        lip="192.0.2.53",
        lif='a,"b',
    )
    f(
        "an interface label that is HTML: not escaped, an admin-set name",
        NOERROR,
        block,
        transport="UDP",
        lip="192.0.2.53",
        lif="<b>&",
    )
    f("a client that is not an address: the qstate is not validated", NXRA, [], client="not-an-ip")
    f("a client that is the word Unknown: counted as no client", NXRA, [], client="Unknown")
    f("no client", NXRA, [], client="")
    f("a name with no characters: Unknown", NXRA, [], qname="")
    f("a name of a dot: Unknown", NXRA, [], qname=".")
    f("a name of spaces and a dot: Unknown", NXRA, [], qname="  .")
    f("EDE17 whose data is its two info bytes only: no provider", NOERROR, [[15, "0011"]], qname="ede.example.")
    f("EDE17 with a one-letter provider", NOERROR, [[15, "0011" + "41"]], qname="ede2.example.")
    r.dump()


@scenario("clients", module_files())
def _(r):
    d = r.datagram
    d(report(client=""), "no client: logged against 127.0.0.1")
    d(report(client="2001:db8::53"), "an IPv6 client")
    d(report(client="2001:0DB8:0:0:0:0:0:0053"), "an IPv6 client written long, logged as written")
    d(report(client="::ffff:192.0.2.7"), "an IPv4-mapped client, logged as written")
    d(report(client="fe80::1%em0"), "a client with a zone id")
    d(report(client='fe80::1%a,b"c'), "a client whose zone id holds a comma and a quote")
    d(report(client="fe80::1%a\nb"), "a client whose zone id holds a line feed")
    d(report(client="fe80::1%é"), "a client whose zone id is not ASCII")
    d(report(client="0.0.0.0"), "the unspecified IPv4 client")
    d(report(client="127.0.0.1"), "a real loopback client, not a missing one")
    d(report(client="Unknown"), "the word Unknown is not an address: refused")
    d(report(client=" 192.0.2.10"), "a client with a leading space: refused")
    d(report(client="192.0.2.10 "), "a client with a trailing space: refused")
    d(report(client="192.0.2.010"), "a client with a leading zero: refused")
    d(report(client="fe80::1%"), "a client with an empty zone id: refused")
    d(report(client="::1%a/b"), "a client with a slash in the zone id: refused")
    d(report(client="1.2.3.4%x"), "an IPv4 client with a zone id: refused")
    d(report(client="\u0663.\u0663.\u0663.\u0663"), "a client of non-ASCII digits: refused")
    r.dump()


@scenario("qnames", module_files())
def _(r):
    d = r.datagram
    d(report(qname="plain.example."), "a plain name")
    d(report(qname="NoTrailingDot.Example"), "a name with no trailing dot, kept in its case")
    d(report(qname="."), "the root name")
    d(report(qname=".."), "two dots")
    d(report(qname="   "), "a name of only spaces")
    d(report(qname="<b>\"a\"&'c'</b>,x\\.example."), "a hostile name: HTML, comma, quote, backslash")
    d(report(qname="ctl\x01\x1b\x7f\u0085.example."), "a name with control characters")
    d(report(qname="line\nfeed\rreturn.example."), "a name with a line feed and a carriage return")
    d(report(qname="zw\u200b\u202e\u2066.example."), "a name with format and bidi characters")
    d(report(qname="\u00e9\u4e2d\U0001f600.example."), "a name with multibyte characters")
    d(report(qname="end.with.backslash\\"), "a name ending in a backslash")
    d(utf8_report(qname="\u00e9" * 1024), "1024 two-byte characters cannot fit one datagram: refused for their size")
    d(
        utf8_report(qname="a" * 1023 + "\u00e9"),
        "1024 code points in 1025 bytes: accepted, the limit counts code points",
    )
    d(utf8_report(qname="a" * 1022 + "\u4e2d\u4e2d"), "1024 code points in 1028 bytes: accepted")
    d(utf8_report(qname="a" * 1020 + "\U0001f600" * 4), "1024 code points in 1036 bytes: accepted")
    d(utf8_report(qname="\u00e9" * 600 + "a" * 424), "1024 code points, 600 of them two bytes: accepted")
    d(utf8_report(qname="\u00e9" * 600 + "a" * 400), "1000 code points in 1600 bytes: accepted")
    d(report(qname="a" * 1024), "1024 ASCII characters: accepted")
    d(report(qname="a" * 1025), "1025 ASCII characters: refused")
    d(utf8_report(qname="a" * 1024 + "\u00e9"), "1025 code points: refused")
    d(utf8_report(qname="\u00e9" * 1000 + "a" * 25), "1025 code points: refused, in 2025 bytes")
    d(report(qname="\u00e9" * 200), "200 characters written as escapes: accepted")
    d(report(qname="\U0001f600" * 150), "150 characters above the BMP written as surrogate pairs: accepted")
    d(report(qtype=28), "type AAAA")
    d(report(qtype=255), "type ANY")
    d(report(qtype=65280), "a private-use type: the log says Unknown, the counter TYPE65280")
    d(report(qtype=0), "type 0")
    d(report(qtype=65535), "type 65535")
    d(report(qtype=65536), "type 65536: refused")
    d(report(qtype=99, flags=NXRA, opts=[]), "type 99 on an NXRA reply")
    r.dump()


# ---- the gates -----------------------------------------------------------------------------------------------------


@scenario("no-nolog-gate", module_files({"python_nolog": "true"}))
def _(r):
    r.datagram(report(), "python_nolog is on: the Upstream row is still written")
    r.datagram(report(), "the same block twice running: no duplicate mark, the counter counts both")
    r.dump()


@scenario("forwarding-off", module_files({"forwarding": "false"}))
def _(r):
    r.datagram(report(), "an EDE15 block while the resolver is not forwarding: no row, no counter")
    r.datagram(report(flags=NXRA, opts=[]), "an NXRA block while the resolver is not forwarding")
    r.datagram(b"not json", "a malformed report is still warned about")
    r.dump()


@scenario("forwarding-off-blacklist-on", module_files({"forwarding": "false"}, [("F1", "G1", "1", ["lf1.example"])]))
def _(r):
    r.datagram(report(), "forwarding off with the DNSBL database open: still no row, no counter")
    r.dump()


@scenario("sqlite-gate-off", module_files())
def _(r):
    r.datagram(report(), "counted while the DNSBL connection is up")
    r.gate_off()
    r.datagram(report(qname="uncounted.example."), "the row is written and the counter skipped")
    r.dump()


@scenario("no-upstream-epoch", module_files())
def _(r):
    r.datagram(report(), "counted while the snapshot has the Upstream epoch")
    r.drop_epoch()
    r.datagram(report(qname="uncounted.example."), "the row is written and the counter skipped")
    r.dump()


@scenario("privacy-clients", module_files({"metrics_client_ip": "true"}))
def _(r):
    r.sql("dnsbl", "UPDATE dns_metric_settings SET client_ip=1 WHERE row=0")
    r.reboot()  # init captures the opted-in epoch
    d = r.datagram
    d(report(), "an IPv4 client")
    d(report(), "the same client again")
    d(report(client="2001:db8::53"), "an IPv6 client")
    d(report(client="::ffff:192.0.2.7"), "an IPv4-mapped client is counted as its IPv4 address")
    d(report(client="fe80::1%em0"), "a client with a zone id is not counted by address")
    d(report(client=""), "no client: the counter keeps it separate from loopback")
    d(report(client="127.0.0.1"), "a real loopback client")
    d(report(client="0.0.0.0"), "the unspecified client is not stored")
    d(report(qtype=65280), "the private-use type is counted as TYPE65280")
    r.dump()
    r.sql("dnsbl", "UPDATE dns_metric_settings SET client_ip=0 WHERE row=0")
    d(report(client="192.0.2.99"), "the policy went off: the address is no longer stored")
    r.dump()


@scenario("privacy-off", module_files())
def _(r):
    r.datagram(report(), "the default: no client address is stored")
    r.datagram(report(client=""), "no client")
    r.dump()


# ---- the receiver --------------------------------------------------------------------------------------------------


@scenario("malformed", module_files())
def _(r):
    for name, data in MALFORMED.items():
        r.datagram(data, f"malformed: {name}")
        r.datagram(
            report(qname=f"after-{len(r.steps)}.example."), "the next good report is still logged", new_frontend=False
        )
    r.dump()


@scenario("malformed-more", module_files())
def _(r):
    d = r.datagram
    d(report(qtype=1.0), "qtype 1.0 is a float")
    d(raw_report(qtype="1e0"), "qtype 1e0 is a float")
    d(raw_report(qtype="NaN"), "qtype NaN")
    d(raw_report(flags="Infinity"), "flags Infinity")
    d(raw_report(flags="-Infinity"), "flags -Infinity")
    d(raw_report(flags="true"), "flags true")
    d(raw_report(flags="false"), "flags false")
    d(raw_report(qtype="null"), "qtype null")
    d(raw_report(qtype="99999999999999999999999"), "qtype beyond 64 bits")
    d(raw_report(qtype="1" * 1500), "qtype of 1500 digits")
    d(raw_report(client="null"), "client null")
    d(raw_report(opts="null"), "opts null")
    d(raw_report(opts="{}"), "opts an object")
    d(raw_report(opts="[[15,null]]"), "option data null")
    d(raw_report(opts='[[15,"00",1]]'), "option of three items")
    d(raw_report(opts="[[]]"), "option of no items")
    d(raw_report(opts="[{}]"), "option an object")
    d(raw_report(opts='[[1.0,"00"]]'), "option code a float")
    d(raw_report(opts='[[true,"00"]]'), "option code a boolean")
    d(raw_report(opts='[[-1,"00"]]'), "option code negative")
    d(raw_report(opts='[[15,"0"]]'), "option data of an odd number of digits")
    d(raw_report(opts='[[15,"00 0"]]'), "option data with a digit left over after a space")
    d(raw_report(opts='[[15,"0 0"]]'), "option data with a space inside a byte")
    d(raw_report(opts='[[15,"\\u00e900"]]'), "option data with a non-ASCII character first")
    d(raw_report(opts='[[15,"00\\u00e9"]]'), "option data with a non-ASCII character last")
    d(raw_report(opts='[[15,"\\u00a000"]]'), "option data with a no-break space")
    d(raw_report(opts='[[15,"0x00"]]'), "option data with a 0x prefix")
    d(raw_report(opts='[[15,"-100"]]'), "option data with a sign")
    d(report(opts=[[15, "00" * 512 + "00"]]), "option data of 1026 digits")
    d(
        utf8_report(opts=[[15, "00" * 511 + "0\u00e9"]]),
        "option data of 1024 characters, one of two bytes: not hex, within the cap",
    )
    d(utf8_report(opts=[[15, "00" * 511 + "00\u00e9"]]), "option data of 1025 characters: over the cap")
    d(report(opts=[[15, "\u00e9" * 100]]), "option data of 100 non-ASCII characters: not hex")
    d(report(opts=[EDE15_BLOCKED, ["a", "00"]]), "a good option, then a bad one")
    d(report(opts=[[15, "zz"], ["a", "00"]]), "the first bad option is the one reported")
    d(raw_report(client="5", qname="7", qtype='"A"'), "qname, qtype and flags are checked before client and opts")
    d(raw_report(client="5", opts="7"), "client and opts bad together")
    d(b"\xef\xbb\xbf\xef\xbb\xbf" + raw_report(), "a BOM twice")
    d(b"\xff\xfe" + "{}".encode("utf-16-le")[:3], "UTF-16 cut in a code unit")
    d(b'{"client":"","qname":"a.example.","qtype":1}', "no flags")
    d(b'{"client":"","qname":"a.example.","qtype":1,"flags":33155}', "no opts")
    d(b'{"qname":"a.example.","qtype":1,"flags":33155,"opts":[]}', "no client")
    d(b'{"client":"","qtype":1,"flags":33155,"opts":[]}', "no qname")
    d(b'{"client":"","qname":"a.example.","flags":33155,"opts":[]}', "no qtype")
    d(b'{"client":"","qname":"","qtype":1,"flags":33155,"opts":[]}', "an empty qname")
    d(b'{"client":"","qname":"a.example.","qtype":1,"flags":33155,"opts":[]} x', "text after the report")
    d(b'{"client":"","qname":"a.example.","qtype":1,"flags":33155,"opts":[],}', "a trailing comma")
    d(b"{'client':''}", "single quotes")
    d(
        b'{"client":"","qname":"a.\x01example.","qtype":1,"flags":33155,"opts":[]}',
        "a raw control character in a string",
    )
    d(b'{"client":"","qname":"a.\\x41","qtype":1,"flags":33155,"opts":[]}', "an invalid escape")
    d(b'{"client":"","qname":"a.\\u12","qtype":1,"flags":33155,"opts":[]}', "a short unicode escape")
    d(b"\x00", "one NUL byte")
    d(b" ", "only whitespace")
    d(b"1", "a bare number")
    d(b'"x"', "a bare string")
    d(b"true", "a bare true")
    d(b"1.5", "a bare float")
    d(b"[]", "an empty array")
    d(b"NaN", "NaN")
    d(raw_report().replace(b"[]", b"[" + b"[]," * 600 + b"[]]"), "an array of 601 options")
    d(b"[" * 2000, "2000 opening brackets: nested deeper than the parser recurses")
    d(b'{"x":' * 300 + b"1" + b"}" * 300, "300 nested objects with no report in them")
    r.dump()


@scenario("accepted-spellings", module_files())
def _(r):
    d = r.datagram
    d(raw_report(qtype="-0"), "qtype -0 is the int 0")
    d(raw_report(flags="-0"), "flags -0 is the int 0: no block")
    d(raw_report(flags="33155"), "flags written as a plain number")
    d(
        b'  \t\n{"client":"","qname":"ws.example.","qtype":1,"flags":33027,"opts":[]}\r\n ',
        "whitespace around the object",
    )
    d(b'{"opts":[],"flags":33027,"qtype":1,"qname":"order.example.","client":""}', "the keys in another order")
    d(
        b'{"client":"","qname":"extra.example.","qtype":1,"flags":33027,"opts":[],"other":[1,{"a":null}]}',
        "an extra key",
    )
    d(
        b'{"client":"bad","client":"192.0.2.10","qname":"dup.example.","qtype":1,"flags":33027,"opts":[]}',
        "a repeated key: the last wins",
    )
    d(b'{"client":"","qname":"a\\u0062c.example.","qtype":1,"flags":33027,"opts":[]}', "a unicode escape in the name")
    d(b'{"client":"","qname":"s\\/lash.example.","qtype":1,"flags":33027,"opts":[]}', "an escaped slash")
    d(b'{"client":"","qname":"\\ud83d\\ude00.example.","qtype":1,"flags":33027,"opts":[]}', "an escaped surrogate pair")
    d(raw_report(opts='[[15,"000f 426c 6f63 6b65 64"]]'), "hex with a space between byte pairs")
    d(raw_report(opts='[[15,"  000f\\t426c\\n6f63\\u000b6b\\f65\\r64  "]]'), "hex with every ASCII whitespace")
    d(raw_report(opts='[[15,"000F426C6F636B6564"]]'), "hex in upper case")
    d(raw_report(opts='[[15,""]]'), "empty option data")
    d(raw_report(opts='[[15,"   "]]'), "option data of only spaces")
    d(
        b'{"client":"","qname":"deep.example.","qtype":1,"flags":33027,"opts":[],"x":' + b"[" * 600 + b"]" * 600 + b"}",
        "nesting 600 deep under an ignored key",
    )
    d(b"\xef\xbb\xbf" + report(qname="bom8.example."), "UTF-8 with a BOM")
    d(report(qname="bom16le.example.").decode().encode("utf-16"), "UTF-16 with a BOM")
    d(b"\xfe\xff" + report(qname="bom16be.example.").decode().encode("utf-16-be"), "UTF-16 big endian with a BOM")
    d(report(qname="nobom16le.example.").decode().encode("utf-16-le"), "UTF-16 little endian with no BOM")
    d(report(qname="nobom16be.example.").decode().encode("utf-16-be"), "UTF-16 big endian with no BOM")
    d(report(qname="bom32le.example.").decode().encode("utf-32"), "UTF-32 with a BOM")
    d(
        b"\x00\x00\xfe\xff" + report(qname="bom32be.example.").decode().encode("utf-32-be"),
        "UTF-32 big endian with a BOM",
    )
    d(report(qname="nobom32le.example.").decode().encode("utf-32-le"), "UTF-32 little endian with no BOM")
    d(report(qname="nobom32be.example.").decode().encode("utf-32-be"), "UTF-32 big endian with no BOM")
    d(report(qname="\u00e9\u4e2d\U0001f600.example.").decode().encode("utf-16"), "UTF-16 with a pair and a BOM")
    d(utf8_report(qname="\u00e9.example.", client="").decode().encode("latin-1"), "Latin-1 bytes: not UTF-8")
    d(padded_to(2048), "a report of exactly 2048 bytes")
    d(padded_to(2049), "a report of 2049 bytes is refused before it is parsed")
    d(b"x" * 2049, "2049 bytes that are not JSON: refused for their size")
    d(b"x" * 5000, "5000 bytes that are not JSON: refused for their size")
    d(block_with_options(pfb_dns_proxy.MAX_REPORT_OPTIONS), "options at the cap")
    d(report(opts=[option_of_hex_size(pfb_dns_proxy.MAX_REPORT_OPTION_HEX)]), "option data at the cap")
    r.dump()


@scenario("warn-once", module_files())
def _(r):
    r.datagram(b"not json", "the first malformed report is warned about")
    r.datagram(b"not json", "the second is not", new_frontend=False)
    r.datagram(oversize_report(), "an oversize report after it is not", new_frontend=False)
    r.datagram(report(qname="good.example."), "a good one is logged", new_frontend=False)
    r.datagram(b"[1,2]", "a malformed one after a good one is still not warned about", new_frontend=False)
    r.datagram(b"x" * 3000, "a later oversize report is silent too", new_frontend=False)
    r.datagram(b"not json", "a new Frontend warns again")
    r.dump()


@scenario("oversize-first", module_files())
def _(r):
    r.datagram(b"x" * 2049, "an oversize report spends the warning")
    r.datagram(b"not json", "a malformed one after it is silent", new_frontend=False)
    r.datagram(report(qname="good.example."), "a good one is logged", new_frontend=False)
    r.dump()


RAW_SURROGATE_REPORT = b'{"client":"","qname":"\xed\xa0\x80.example.","qtype":1,"flags":33027,"opts":[]}'


def utf16_lone_surrogate(big_endian=False, name="\ud800"):
    text = '{"client":"","qname":"' + name + 'x.example.","qtype":1,"flags":33027,"opts":[]}'
    if big_endian:
        return b"\xfe\xff" + text.encode("utf-16-be", "surrogatepass")
    return b"\xff\xfe" + text.encode("utf-16-le", "surrogatepass")


def utf32_lone_surrogate(name="\ud800"):
    text = '{"client":"","qname":"' + name + 'x.example.","qtype":1,"flags":33027,"opts":[]}'
    return b"\xff\xfe\x00\x00" + text.encode("utf-32-le", "surrogatepass")


@scenario("surrogates", module_files())
def _(r):
    d = r.datagram
    esc = "\\ud800"  # the JSON escape of a lone high surrogate, as the text of a hand-written report
    lo = "\\udc00"
    d(report(qname="a\ud800b.example."), "a lone high surrogate in the name, as json.dumps writes it")
    d(raw_report(qname=f'"{esc}.example."', flags="33027"), "a lone high surrogate, first")
    d(raw_report(qname=f'"{lo}.example."', flags="33027"), "a lone low surrogate")
    d(raw_report(qname=f'"{esc}\\u0041.example."', flags="33027"), "a high surrogate then a plain escape")
    d(raw_report(qname=f'"{lo}{esc}.example."', flags="33027"), "a low surrogate then a high one: two lone ones")
    d(raw_report(qname=f'"{esc}{lo}.example."', flags="33027"), "a high then a low one: one character above the BMP")
    d(raw_report(qname=f'"{esc}x{lo}.example."', flags="33027"), "a high and a low one apart: two lone ones")
    d(raw_report(qname=f'"x{esc}"', flags="33027"), "a lone surrogate last in the name")
    d(raw_report(qname=f'"{esc}"', flags="33027"), "a name that is one lone surrogate")
    d(raw_report(qname='"' + esc * 1024 + '"', flags="33027"), "1024 lone surrogates fill a datagram: refused for size")
    d(raw_report(qname='"' + esc * 300 + '"', flags="33027"), "300 lone surrogates: accepted, 300 code points")
    d(raw_report(qname='"' + "a" * 1023 + esc + '"', flags="33027"), "1024 code points with a lone surrogate: accepted")
    d(raw_report(qname='"' + "a" * 1024 + esc + '"', flags="33027"), "1025 code points with a lone surrogate: refused")
    d(raw_report(qname=f'"{esc}.{esc}"', flags="33027", client='""'), "a name with two lone surrogates and a dot")
    d(
        raw_report(qname=f'"{esc}"', flags="33027", client='"2001:db8::53"'),
        "an IPv6 client behind a name it cannot encode",
    )
    d(raw_report(client=f'"{esc}"'), "a lone surrogate as the client: refused, named by its repr")
    d(raw_report(client=f'"192.0.2.1{esc}"'), "a lone surrogate after an address: refused")
    d(raw_report(opts=f'[["{esc}","00"]]'), "a lone surrogate as an option code: not a pair")
    d(raw_report(opts=f'[[15,"{esc}"]]'), "a lone surrogate as option data: not hex")
    d(raw_report(opts=f'[[15,"00{esc}"]]'), "a lone surrogate after hex digits: not hex, at its position")
    d(raw_report(opts='[[15,"' + esc * 250 + '"]]'), "250 lone surrogates as option data: not hex")
    d(raw_report(opts='[[15,"00' + esc * 250 + '"]]'), "250 surrogates after hex digits: not hex at their position")
    d(report(opts=[ede(15, b"\xed\xa0\x80")]), "an encoded surrogate in the provider is three replacement characters")
    d(
        raw_report(qname='"a."', flags="33027").replace(b"}", b',"x":"' + esc.encode() + b'"}'),
        "a lone surrogate under an ignored key",
    )
    d(
        raw_report(qname='"a."', flags="33027").replace(b'"client"', b'"' + esc.encode() + b'":1,"client"'),
        "a lone surrogate in a key",
    )
    d(RAW_SURROGATE_REPORT, "a surrogate as raw UTF-8: Python decodes it")
    d(utf16_lone_surrogate(), "an unpaired UTF-16 unit: Python decodes it")
    d(utf16_lone_surrogate(True), "a high UTF-16 unit then a plain one, big endian")
    d(utf16_lone_surrogate(False, "\udc00"), "a lone low UTF-16 unit")
    d(utf16_lone_surrogate(False, "\ud800\udc00"), "a UTF-16 pair is one character")
    d(utf16_lone_surrogate(False, "\udc00\ud800"), "a low then a high UTF-16 unit: two lone ones")
    d(utf32_lone_surrogate(), "a UTF-32 surrogate: Python decodes it")
    d(utf32_lone_surrogate("\ud800\udc00"), "a UTF-32 surrogate pair is two lone ones, not one character")
    d(b"\xef\xbb\xbf" + RAW_SURROGATE_REPORT, "a BOM and a raw UTF-8 surrogate")
    pair = b"\xed\xa0\xbd\xed\xb8\x80"
    d(RAW_SURROGATE_REPORT.replace(b"\xed\xa0\x80", pair), "a surrogate pair as two raw UTF-8 surrogates: not combined")
    d(RAW_SURROGATE_REPORT.replace(b"\xed\xa0\x80", b"\xed\xa0"), "a raw UTF-8 surrogate cut short: not text")
    d(
        RAW_SURROGATE_REPORT.replace(b"\xed\xa0\x80", b"\xed\x80\x80"),
        "U+D000, the last character before the surrogates",
    )
    d(
        RAW_SURROGATE_REPORT.replace(b"\xed\xa0\x80", b"\xed\xc0\x80"),
        "ED followed by a non-continuation byte: not text",
    )
    d(
        RAW_SURROGATE_REPORT.replace(b"\xed\xa0\x80", b"\xee\x80\x80"),
        "U+E000, the first character after the surrogates",
    )
    d(RAW_SURROGATE_REPORT.replace(b"\xed\xa0\x80", b"\xf0\x9f\x98\x80"), "a character above the BMP as raw UTF-8")
    d(RAW_SURROGATE_REPORT.replace(b"\xed\xa0\x80", b"\xf4\x90\x80\x80"), "above U+10FFFF: not text")
    d(RAW_SURROGATE_REPORT.replace(b"\xed\xa0\x80", b"\xc0\x80"), "an overlong NUL: not text")
    d(raw_report(client='"fe80::1%' + esc + '"'), "a lone surrogate as a zone id: a client Python accepts")
    r.dump()


@scenario("answers-unblocked", module_files())
def _(r):
    d = r.datagram
    d(report(qname=PROBE_NAME, flags=NXRA, opts=[]), "an NXRA report for the very name the fixed query asks")
    d(report(qname=PROBE_NAME), "an EDE15 report for it")
    d(report(qname=PROBE_NAME.upper()), "the same name in capitals")
    d(report(qname=PROBE_NAME[:-1], opts=[ede(17, b"x")], flags=NOERROR), "the same name with no trailing dot, EDE17")
    d(report(qname=PROBE_NAME, client=""), "no client")
    d(report(qname=PROBE_NAME, qtype=28), "type AAAA")
    d(report(qname=PROBE_NAME, flags=NXDOMAIN_RECURSIVE, opts=[]), "a natural NXDOMAIN: no block")
    d(b"not json", "a malformed report")
    d(report(qname=PROBE_NAME, client="bad"), "a malformed report that names the probe")
    d(oversize_report(), "an oversize report")
    r.fire("a shim call for it", NXRA, [], qname=PROBE_NAME, transport="UDP", lip="192.0.2.53", lif="LAN")
    r.log_raises()
    d(report(qname=PROBE_NAME), "a report whose row cannot be written")
    r.log_works()
    r.dump()


@scenario("answers-blocked", module_files(feeds=[("F1", "G1", "1", ["probe.example", "other.example"])]))
def _(r):
    d = r.datagram
    d(report(qname=PROBE_NAME, flags=NXRA, opts=[]), "an NXRA report for the very name the list blocks")
    d(report(qname=PROBE_NAME), "an EDE15 report for it")
    d(report(qname="other.example."), "an EDE15 report for another listed name")
    d(report(qname="unlisted.example."), "an EDE15 report for an unlisted name")
    d(b"not json", "a malformed report")
    d(report(qname=PROBE_NAME, client="bad"), "a malformed report that names the probe")
    d(oversize_report(), "an oversize report")
    r.fire("a shim call for the blocked name", NXRA, [], qname=PROBE_NAME)
    d(report(qname=PROBE_NAME), "a second EDE15 report for it")
    r.dump()
    assert r.steps[0]["before"] != hx(PROBE_REPLY), "the listed name must be answered by the module, not by Unbound"


@scenario("callback-panics", module_files())
def _(r):
    r.log_raises()
    r.datagram(report(), "the row writer raises: the module prints its own error line and the answer stands")
    r.datagram(report(flags=NXRA, opts=[]), "again: printed each time")
    r.dump()
    r.log_works()
    r.datagram(report(qname="after.example."), "the next report is logged")
    r.dump()


def constants():
    return {
        "max_report_bytes": pfb_dns_proxy.MAX_REPORT_BYTES,
        "max_report_options": pfb_dns_proxy.MAX_REPORT_OPTIONS,
        "max_report_option_hex": pfb_dns_proxy.MAX_REPORT_OPTION_HEX,
        "max_report_qname": pfb_dns_proxy.MAX_REPORT_QNAME,
    }


def main():
    out = {
        "python": sys.version.split()[0],
        "stamp": STAMP,
        "now": NOW,
        "constants": constants(),
        "probe": {"wire": PROBE_WIRE.hex(), "reply": PROBE_REPLY.hex(), "client": CLIENT, "transport": "UDP"},
        "scenarios": SCENARIOS,
    }
    OUT.write_text(json.dumps(out, indent=1, ensure_ascii=True) + "\n", encoding="utf-8")
    steps = [step for sc in SCENARIOS for step in sc["steps"]]
    observed = [step for step in steps if step["op"] in ("datagram", "fire")]
    rows = sum(len(s["rows"]) + len(s.get("rows_wtf8", [])) for s in observed)
    print(
        f"{OUT.name}: {len(SCENARIOS)} scenarios, {len(observed)} datagrams and shim calls, "
        f"{rows} rows, {sum(s['op'] == 'dump' for s in steps)} dumps"
    )


if __name__ == "__main__":
    main()

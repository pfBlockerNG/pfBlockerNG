# Records what the shipped pfb_unbound.py (CPython 3.11, booted through the dns_proxy shim) writes for the DNSBL and
# DNS Reply log rows pfb_unbound_log_rows_oracle_test.go describes: every scenario boots a module from a staged module
# directory, runs its steps (a query through pfb_dns_proxy.Frontend, a reply callback, or one row writer called
# directly) with make_timestamp and time.time fixed and pfb_log captured, and records the (file, line) pairs written.
# The tables hold the pure helpers the rows are built from (_log_text, _csv_row, get_q_transport, _metric_ip,
# get_q_listener, convert_*, ipaddress).
# Run from the repo root:
#   uv run --python 3.11.15 --with maxminddb==3.2.0 python \
#     go/pfb_dns_gateway/decider/testdata/gen_pfb_unbound_log_rows_oracle.py
# It rewrites testdata/pfb_unbound_log_rows_oracle.json. The GeoIP fixtures are MaxMind's own test databases (README).
import asyncio
import calendar
import ipaddress
import json
import os
import secrets
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SHIPPED = ROOT / "src" / "usr" / "local" / "pkg" / "pfblockerng"
sys.path.insert(0, str(SHIPPED / "dns_proxy"))
sys.path.insert(0, str(ROOT / "tests" / "dns_proxy"))
import dnswire  # noqa: E402
import pfb_dns_proxy  # noqa: E402
import unbound_shim as shim  # noqa: E402
from frontend_helpers import FakeUnbound, UpstreamVerdict, build_query  # noqa: E402

secrets.randbits = lambda bits: (
    0x1234
)  # the SafeSearch chase asks Unbound with a random id; the recorded replies must not vary

STAMP = "2026-10-18 12:00:00"
NOW = calendar.timegm((2026, 10, 18, 12, 0, 0))
CLIENT = "192.0.2.10"
OUT = HERE / "pfb_unbound_log_rows_oracle.json"
GEOLITE = "GeoLite2-Country-Test.mmdb"
GEOIP2 = "GeoIP2-Country-Test.mmdb"

MAIN = {
    "python_enable": "true",
    "python_blocking": "true",
    "python_reply": "true",
    "python_cname": "true",
    "dnsbl_ipv4": "10.10.10.1",
    "dnsbl_ipv6": "fd00::1",
}


def rr_data(rdata):
    return (len(rdata)).to_bytes(2, "big") + rdata


def dname(*labels):
    return b"".join(bytes([len(x)]) + x for x in labels) + b"\x00"


def strings(*items):
    return b"".join(bytes([len(x)]) + x for x in items)


def hx(data):
    return None if data is None else data.hex()


# ---- module files ------------------------------------------------------------------------------------------------


def module_files(main=None, feeds=(), config=None, sections=""):
    """The files a module directory holds besides the shipped code: ini, manifest, raw feeds. feeds: (feed, group,
    log_flag, [domain, ...]) rows."""
    ini = "[MAIN]\n" + "".join(f"{k} = {v}\n" for k, v in {**MAIN, **(main or {})}.items()) + sections
    files = {"pfb_unbound.ini": ini}
    rows = []
    for i, (feed, group, flag, domains) in enumerate(feeds):
        rel = f"pfb_py_raw/feed{i}.txt"
        files[rel] = "".join(f"{d}\n" for d in domains)
        rows.append({"raw": rel, "feed": feed, "group": group, "log_flag": flag})
    files["pfb_py_sources.json"] = json.dumps({"version": 1, "config": config or {}, "feeds": rows})
    return files


FEEDS = [
    ("F0", "G0", "0", ["lf0.example"]),
    ("F1", "G1", "1", ["lf1.example", "other.example"]),
    ("F2", "G2", "2", ["lf2.example"]),
    ("F3", "G3", "3", ["lf3.example"]),
    ("F4", "G4", "4", ["lf4.example"]),
    ("F5", "G5", "5", ["lf5.example"]),
    ("F6", "G6", "6", ["lf6.example"]),
    ('Fe,"<b>"&', "Gr'ou,p", "1", ["hostile-feed.example"]),
]


# ---- the Python side of one scenario -------------------------------------------------------------------------------


class Clock:
    """Stands in for the module's `time`: time.time() is fixed, everything else is the real module's."""

    def __getattr__(self, name):
        return getattr(time, name)

    @staticmethod
    def time():
        return float(NOW)


class Runner:
    def __init__(self, name, files, mmdb=None):
        self.name, self.files, self.mmdb = name, files, mmdb
        self.dir = Path(tempfile.mkdtemp(prefix="pfblogrows"))
        for rel, text in files.items():
            target = self.dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        for shipped in ("pfb_unbound.py", "pfb_dnsbl_regex_rules.py"):
            (self.dir / shipped).symlink_to(SHIPPED / shipped)
        self.cwd = os.getcwd()
        self.module = pfb_dns_proxy.boot(str(self.dir))
        self.rows = []
        self.module.pfb_log = lambda log, line: self.rows.append([os.path.basename(log), line])
        self.module.make_timestamp = lambda: STAMP
        self.module.time = Clock()
        self.module._dnsbl_last_event = None
        if mmdb:
            self.module.maxmindReader = self.module.maxminddb.open_database(str(HERE / mmdb))
            self.module.pfb["python_maxmind"] = True
        self.steps = []

    def close(self):
        pfb_dns_proxy.shutdown(self.module)
        os.chdir(self.cwd)
        shutil.rmtree(self.dir)

    def record(self, step):
        step["rows"], self.rows[:] = list(self.rows), []
        self.steps.append(step)

    # a query through the Frontend: the module decides, Unbound answers from `zone`/`verdicts` (or stays silent)
    def resolve(
        self,
        qname,
        qtype=1,
        *,
        client=CLIENT,
        transport="UDP",
        lip="",
        lif="",
        zone=None,
        verdicts=None,
        silent=False,
        wire=None,
    ):
        wire = wire or build_query(qname, qtype)
        unbound = FakeUnbound(zone or {})
        unbound.verdicts.update(verdicts or {})
        forwards = []

        async def forward(data):
            reply = None if silent else unbound.answer(data)
            forwards.append(reply)
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
                "forwards": [hx(f) for f in forwards],
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
        q.return_rcode = spec.get("return_rcode", 0)
        if spec.get("return_msg") is not None:
            msg = spec["return_msg"]
            q.return_msg = shim.DnsMsg(shim.query_info(msg["qname"], msg.get("qtype", 1)), 0, [], [], [])
            q.return_msg.rep = self.rep(msg.get("rep"))
        return q

    @staticmethod
    def rep(spec):
        if spec is None:
            return None
        sets = shim.RRSets()
        for rtype, rr in spec["rrsets"]:
            data = [bytes.fromhex(x) for x in rr]
            sets.append(
                shim.RRSet(
                    shim.RRSetKey(rtype), shim.RRSetEntry(shim.RRSetData(len(data), 0, data, [spec["ttl"]] * len(data)))
                )
            )
        an = spec.get("an", len(sets))
        return shim.reply_info(0, sets, (an, 0, 0), spec["ttl"])

    @staticmethod
    def kwargs(spec):
        """The kwargs dict a callback hands the writers: the client rides in `repinfo` as the shim's ReplyAddr."""
        if spec is None:
            return None
        return {**spec, "repinfo": shim.ReplyAddr(spec["repinfo"])} if "repinfo" in spec else dict(spec)

    def callback(self, kind, qstate, rep):
        shim.fire_reply_callback(kind, self.qstate(qstate), self.rep(rep), 2 if kind == "reply_servfail" else 0)
        self.record({"op": "callback", "kind": kind, "qstate": qstate, "rep": rep})

    def details_reply(self, m_type, qstate, rep, kwargs, qinfo=None):
        info = None if qinfo is None else shim.query_info(qinfo["qname"], qinfo["qtype"])
        failed = False
        try:
            self.module.get_details_reply(m_type, info, self.qstate(qstate), self.rep(rep), self.kwargs(kwargs))
        except IndexError:  # a record too short for its type: operate() lets it out, the proxy answers SERVFAIL
            failed = True
        self.record(
            {
                "op": "details_reply",
                "m_type": m_type,
                "qstate": qstate,
                "qinfo": qinfo,
                "rep": rep,
                "kwargs": kwargs,
                "raises": failed,
            }
        )

    def details_dnsbl(self, qstate, dnsbl, kwargs, qinfo=None):
        info = None if qinfo is None else shim.query_info(qinfo["qname"], qinfo["qtype"])
        decision = self.module.UNSET if dnsbl == "UNSET" else self.module.DnsblDecision(**decision_args(dnsbl))
        self.module.get_details_dnsbl("dnsbl", info, self.qstate(qstate), self.kwargs(kwargs), decision, "")
        self.record({"op": "details_dnsbl", "qstate": qstate, "qinfo": qinfo, "dnsbl": dnsbl, "kwargs": kwargs})

    def idn_alert(self, q_name, q_ip, alert, q_type, transport="Unknown", lip="", lif=""):
        self.module._log_idn_alert(
            q_name, q_ip, tuple(alert), q_type, transport, listener_ip=lip, listener_interface=lif
        )
        self.record(
            {
                "op": "idn_alert",
                "q_name": q_name,
                "q_ip": q_ip,
                "alert": alert,
                "q_type": q_type,
                "transport": transport,
                "lip": lip,
                "lif": lif,
            }
        )

    def send(self, qname, qtype, *, msg, authority=0, return_rcode=0, relay=False, client=CLIENT, transport="TCP"):
        """Frontend._send for a state a query rarely reaches: an answer too big for a stream, an error rcode, a relay"""
        query = dnswire.parse(build_query(qname, qtype))
        qstate = shim.module_qstate(shim.query_info(qname, qtype), client, 0, 0, transport, "", "")
        qstate.return_rcode = return_rcode
        if msg:
            answers = [dnswire.rr_from_text(f"{qname} 300 IN A 192.0.2.77")]
            padding = [dnswire.RR(qname, dnswire.TYPE_TXT, 1, 300, strings(b"x" * 255)) for _ in range(authority)]
            qstate.return_msg = shim.DnsMsg(
                shim.query_info(qname, qtype), dnswire.QR | dnswire.RA, answers, padding, []
            )
        pfb_dns_proxy.Frontend(self.module)._send(query, qstate, b"relayed" if relay else None, None)
        self.record(
            {
                "op": "send",
                "qname": qname,
                "qtype": qtype,
                "client": client,
                "transport": transport,
                "msg": msg,
                "authority": authority,
                "return_rcode": return_rcode,
                "relay": relay,
            }
        )


def decision_args(spec):
    out = {
        "is_found": True,
        "in_whitelist": False,
        "in_hsts": False,
        "null_blocking": False,
        "nxdomain": False,
        "log_type": "1",
        "b_type": "DNSBL",
        "p_type": "Python",
        "feed": "Feed",
        "group": "Group",
        "b_eval": "example.com",
        "idn_alert": None,
        "group_owner": "",
        "group_origin": "",
    }
    out.update(spec)
    if out["idn_alert"] is not None:
        out["idn_alert"] = tuple(out["idn_alert"])
    return out


SCENARIOS = []


def scenario(name, files, mmdb=None):
    def decorate(build):
        runner = Runner(name, files, mmdb)
        try:
            build(runner)
            SCENARIOS.append({"name": name, "files": files, "mmdb": mmdb, "steps": runner.steps})
        finally:
            runner.close()
        return build

    return decorate


# ---- block rows ----------------------------------------------------------------------------------------------------


@scenario("block-shapes", module_files(feeds=FEEDS))
def _(r):
    for flag in range(7):  # VIP, null, NXDOMAIN and NODATA shapes, logged and silent
        r.resolve(f"lf{flag}.example.")
    r.resolve("lf1.example.", 28)
    r.resolve("lf1.example.", 255)
    r.resolve("lf0.example.", 28)
    r.resolve("lf0.example.", 255)
    r.resolve("lf5.example.", 28)
    r.resolve("lf1.example.", 16)  # TXT is outside the DNSBL record types
    r.resolve("hostile-feed.example.")
    r.resolve("LF1.Example.")  # mixed case
    r.resolve("sub.lf1.example.")  # not listed as a wildcard: not blocked
    r.resolve("other.example.", 1, client="2001:db8::12")


@scenario("block-transports", module_files(feeds=FEEDS))
def _(r):
    for transport in ("TCP", "UDP", "DoT", "DoH", "DoQ", "Unknown", "udp", "UDP,TCP", ""):
        r.resolve("lf1.example.", 1, transport=transport)
    for lip, lif in (
        ("192.0.2.1", "em0"),
        ("2001:db8::1", "vlan,10"),
        ("2001:DB8::1", 'a"b'),
        ("not-an-ip", "em0"),
        ("", "em0"),
        ("192.0.2.1", "em\x1b0"),
        ("192.0.2.1", "em\u200b0"),
        ("192.0.2.1", "em\u20280"),
        ("192.0.2.1", "ém0"),
        ("::ffff:192.0.2.1", "lan"),
        ("fe80::1%em0", "lan"),
        ("0.0.0.0", "lan"),
        ("::", "lan"),
        ("192.0.2.1", ""),
        ("192.0.2.1", " "),
    ):
        r.resolve("lf1.example.", 1, lip=lip, lif=lif)
    for client in ("127.0.0.1", "", "::1", "2001:db8::12", "::ffff:192.0.2.7", "192.0.2.255"):
        r.resolve("lf1.example.", 1, client=client)


@scenario("dedupe", module_files(feeds=FEEDS))
def _(r):
    r.resolve("lf1.example.")
    r.resolve("lf1.example.")  # same event: a duplicate
    r.resolve("lf1.example.", client="192.0.2.11")  # another client
    r.resolve("lf1.example.", client="192.0.2.11")
    r.resolve("lf1.example.")  # back to the first client: not the last event
    r.resolve("lf1.example.", transport="TCP")  # another transport
    r.resolve("lf1.example.", transport="TCP")
    r.resolve("lf1.example.", transport="TCP", lip="192.0.2.1")  # another listener
    r.resolve("lf1.example.", transport="TCP", lip="192.0.2.1", lif="em0")  # another interface
    r.resolve("lf1.example.", transport="TCP", lip="192.0.2.1", lif="em0")
    r.resolve("other.example.", transport="TCP", lip="192.0.2.1", lif="em0")  # another name, same decision
    r.resolve("LF1.example.", transport="TCP", lip="192.0.2.1", lif="em0")  # a name's case is not part of the event
    r.resolve("lf1.example.", 28)  # another qtype
    r.resolve("lf1.example.", 28)
    r.resolve("lf0.example.", 28)  # another decision
    r.resolve("lf0.example.", 28)
    r.resolve("lf2.example.", 28)  # a silent event is the last event too
    r.resolve("lf2.example.", 28)
    r.resolve("lf0.example.", 28)
    r.resolve("lf3.example.")  # an NXDOMAIN block
    r.resolve("lf3.example.")
    r.resolve("hostile-feed.example.")
    r.resolve("hostile-feed.example.")
    r.resolve("lf1.example.", client="")  # Unknown client: 127.0.0.1 in the row, Unknown in the event
    r.resolve("lf1.example.", client="127.0.0.1")
    r.resolve("lf1.example.", client="")


@scenario("python-nolog", module_files(main={"python_nolog": "true"}, feeds=FEEDS))
def _(r):
    r.resolve("lf1.example.")  # VIP: silent, and not an event
    r.resolve("lf0.example.")  # null: logged
    r.resolve("lf1.example.")
    r.resolve("lf0.example.")  # a duplicate: the VIP query left the last event alone
    r.resolve("lf3.example.")  # NXDOMAIN: null_blocking is its default
    r.resolve("lf5.example.")
    r.resolve("lf2.example.")
    r.resolve("hostile-feed.example.")


@scenario("reply-logging-off", module_files(main={"python_reply": "false"}, feeds=FEEDS))
def _(r):
    r.resolve("lf1.example.")
    r.resolve("allowed.example.", zone={("allowed.example.", 1): ["allowed.example. 300 IN A 192.0.2.77"]})
    r.resolve("allowed.example.", silent=True)


# ---- reply rows through the Frontend -------------------------------------------------------------------------------

ALLOWED = "allowed.example."
HOSTILE = "a,b\"c<d>\\010e&'.example."
ZONE = {
    (ALLOWED, 1): [f"{ALLOWED} 300 IN A 192.0.2.77"],
    (ALLOWED, 28): [f"{ALLOWED} 300 IN AAAA 2001:db8::77"],
    (ALLOWED, 16): [f'{ALLOWED} 300 IN TXT "hello world"'],
    (ALLOWED, 6): [f"{ALLOWED} 300 IN SOA ns.example. hostmaster.example. 1 2 3 4 60"],
    (ALLOWED, 255): [f"{ALLOWED} 300 IN A 192.0.2.77"],
    ("alias.example.", 1): ["alias.example. 300 IN CNAME allowed.example.", f"{ALLOWED} 300 IN A 192.0.2.77"],
    ("nodata.example.", 28): [],
    ("geo.example.", 1): ["geo.example. 300 IN A 8.8.8.8"],
    ("lan.example.", 1): ["lan.example. 300 IN A 10.1.2.3"],
    ("python_control.test.", 1): ["python_control.test. 300 IN A 192.0.2.78"],
    ("noaaaa.example.", 1): ["noaaaa.example. 300 IN A 192.0.2.79"],
    ("sub.noaaaa.example.", 28): ["sub.noaaaa.example. 300 IN AAAA 2001:db8::79"],
    ("wild.noaaaa-wild.example.", 28): ["wild.noaaaa-wild.example. 300 IN AAAA 2001:db8::7a"],
    ("ptr.example.", 12): ["ptr.example. 300 IN CNAME allowed.example."],
    (HOSTILE.lower(), 1): [],
}
VERDICTS = {
    "refused.example.": UpstreamVerdict(rcode=5),
    "servfail.example.": UpstreamVerdict(rcode=2),
    "nxd.example.": UpstreamVerdict(rcode=3),
    "nxcname.example.": UpstreamVerdict(rcode=3, answers=("{name} 300 IN CNAME allowed.example.",)),
    "formerr.example.": UpstreamVerdict(rcode=1),
    "notimp.example.": UpstreamVerdict(rcode=4),
}
NOAAAA = "[noAAAA]\nrow1 = noaaaa.example,0\nrow2 = noaaaa-wild.example,1\n"


@scenario("replies", module_files(main={"python_control": "true"}, feeds=FEEDS, sections=NOAAAA))
def _(r):
    kw = {"zone": ZONE, "verdicts": VERDICTS}
    r.resolve(ALLOWED, **kw)
    r.resolve(ALLOWED, 28, **kw)
    r.resolve(ALLOWED, 16, **kw)
    r.resolve(ALLOWED, 6, **kw)
    r.resolve(ALLOWED, 255, **kw)
    r.resolve("alias.example.", **kw)
    r.resolve("nx.example.", **kw)
    r.resolve("nxd.example.", **kw)
    r.resolve("nxcname.example.", **kw)
    r.resolve("nodata.example.", 28, **kw)
    r.resolve("refused.example.", **kw)
    r.resolve("servfail.example.", **kw)
    r.resolve("formerr.example.", **kw)
    r.resolve("notimp.example.", **kw)
    r.resolve("silent.example.", silent=True)
    r.resolve(HOSTILE, **kw)
    r.resolve("ALLOWED.Example.", **kw)  # mixed case
    r.resolve("ptr.example.", 12, **kw)
    r.resolve("python_control.test.", **kw)  # reply-x: a control name passes the filter
    r.resolve("noaaaa.example.", 28, **kw)  # the module answers NODATA itself
    r.resolve("noaaaa.example.", 1, **kw)  # not an AAAA query: no reply-x row
    r.resolve("sub.noaaaa.example.", 28, **kw)
    r.resolve("wild.noaaaa-wild.example.", 28, **kw)
    r.resolve(ALLOWED, client="127.0.0.1", **kw)  # the firewall itself: a resolver row
    r.resolve(ALLOWED, client="", **kw)
    r.resolve(ALLOWED, client="::1", **kw)
    r.resolve(ALLOWED, transport="DoH", lip="2001:db8::1", lif="wan", **kw)
    r.resolve(ALLOWED, transport="TCP", client="2001:db8::12", **kw)
    r.resolve("lf1.example.", **kw)  # a block: a block row, no reply row


# ---- a block found through a CNAME chain ---------------------------------------------------------------------------

CHAIN = {
    ("alias.cn.example.", 1): ["alias.cn.example. 300 IN CNAME lf1.example.", "lf1.example. 300 IN A 192.0.2.50"],
    ("nxalias.cn.example.", 1): ["nxalias.cn.example. 300 IN CNAME lf3.example.", "lf3.example. 300 IN A 192.0.2.50"],
    ("nodata-alias.cn.example.", 1): [
        "nodata-alias.cn.example. 300 IN CNAME lf5.example.",
        "lf5.example. 300 IN A 192.0.2.50",
    ],
    ("silent-alias.cn.example.", 1): [
        "silent-alias.cn.example. 300 IN CNAME lf2.example.",
        "lf2.example. 300 IN A 192.0.2.50",
    ],
    ("deep.cn.example.", 1): [
        "deep.cn.example. 300 IN CNAME alias.cn.example.",
        "alias.cn.example. 300 IN CNAME lf1.example.",
        "lf1.example. 300 IN A 192.0.2.50",
    ],
}


@scenario("cname-block", module_files(feeds=FEEDS))
def _(r):
    r.resolve("alias.cn.example.", zone=CHAIN)  # blocked by the target, logged against the queried name
    r.resolve("alias.cn.example.", zone=CHAIN)  # served from the memo: the same feed, a duplicate
    r.resolve("alias.cn.example.", zone=CHAIN, client="192.0.2.11", transport="TCP")
    r.resolve("lf1.example.", zone=CHAIN)  # the target itself, memoised under its own name
    r.resolve("nxalias.cn.example.", zone=CHAIN)
    r.resolve("nodata-alias.cn.example.", zone=CHAIN)
    r.resolve("silent-alias.cn.example.", zone=CHAIN)
    r.resolve("deep.cn.example.", zone=CHAIN)
    r.resolve("DEEP.cn.example.", zone=CHAIN)


# ---- IDN alerts ----------------------------------------------------------------------------------------------------

IDN_MAIN = {"idn_mode": "confusable", "python_idn_block_malicious": "false", "python_idn_escalate_suspicious": "false"}
UPSTREAM_IDN = {
    ("xn--bnk-1ce.com.", 1): ["xn--bnk-1ce.com. 300 IN A 192.0.2.10"],
    ("xn--pple-43d.com.", 1): ["xn--pple-43d.com. 300 IN A 192.0.2.11"],
    ("alias.idn.example.", 1): [
        "alias.idn.example. 300 IN CNAME xn--bnk-1ce.com.",
        "xn--bnk-1ce.com. 300 IN A 192.0.2.10",
    ],
}


@scenario("idn-alert", module_files(main=IDN_MAIN, config={"builtin_log_flag": "1"}))
def _(r):
    r.resolve("xn--bnk-1ce.com.", zone=UPSTREAM_IDN)  # an alert row, then the reply
    r.resolve("xn--bnk-1ce.com.", zone=UPSTREAM_IDN)  # the memo: not alerted again
    r.resolve("xn--pple-43d.com.", zone=UPSTREAM_IDN)  # malicious with the block toggle off: an alert
    r.resolve("alias.idn.example.", zone=UPSTREAM_IDN, transport="DoT", lip="192.0.2.1", lif="lan")
    r.resolve("xn--bnk-1ce.com.", 28, zone=UPSTREAM_IDN)
    r.resolve("XN--BNK-1CE.com.", zone=UPSTREAM_IDN, client="")


@scenario("idn-block", module_files(main={"idn_mode": "confusable"}, config={"builtin_log_flag": "1"}))
def _(r):
    r.resolve("xn--pple-43d.com.", zone=UPSTREAM_IDN)  # malicious: blocked by default, the block row only
    r.resolve("xn--bnk-1ce.com.", zone=UPSTREAM_IDN)


# the user regex `xn--bnk-1ce` (MAIN.regex_list, base64 of one pattern per line)
REGEX_B64 = "eG4tLWJuay0xY2U="
OVERLAP_MAIN = {**IDN_MAIN, "regex_list": REGEX_B64}


@scenario("idn-overlapping-regex", module_files(main=OVERLAP_MAIN, config={"builtin_log_flag": "1"}))
def _(r):
    r.resolve("xn--bnk-1ce.com.", zone=UPSTREAM_IDN)  # blocked by the regex: the block row, no alert row


@scenario(
    "idn-whitelisted-regex",
    module_files(main=OVERLAP_MAIN, config={"builtin_log_flag": "1", "user_whitelist": ["xn--bnk-1ce.com"]}),
)
def _(r):
    r.resolve("xn--bnk-1ce.com.", zone=UPSTREAM_IDN)  # the whitelist allows it: the alert row, then the reply


@scenario("idn-alert-direct", module_files(main=IDN_MAIN, config={"builtin_log_flag": "1"}))
def _(r):
    alert = ["feedX", "groupY", "xn--eval [ev] mixed"]
    r.idn_alert("plain.example.com", "192.0.2.7", alert, "A")
    r.idn_alert("plain.example.com", "Unknown", alert, "AAAA", "DoH", "192.0.2.1", "lan")
    r.idn_alert("a,b.example.com", "192.0.2.7", alert, "A")
    r.idn_alert('a,"q".example.com', "192.0.2.7", alert, "A")
    r.idn_alert("a\r\nquoted.example.com", "192.0.2.7", alert, "A")
    r.idn_alert("a\rquoted.example.com", "192.0.2.7", alert, "A")
    r.idn_alert("a\nquoted.example.com", "192.0.2.7", alert, "A")
    r.idn_alert("a<b>'&\x1b\x7f.example.com", "192.0.2.7", alert, "A")
    r.idn_alert("plain.example.com", "192.0.2.7", ['a,"q"_feed', "real_group", "xn--eval"], "A")
    r.idn_alert("plain.example.com", "192.0.2.7", ["f", "g", "b<'\"&>\x1b\\"], "A")
    r.idn_alert("plain.example.com", "192.0.2.7", ["f", "g", "xn--b \u200b \u202e \u2066 \u00e9\u0661"], "A")
    r.idn_alert("plain.example.com", "192.0.2.7", alert, "A", "bogus", "bad-ip", "lan")
    r.idn_alert("plain.example.com", "192.0.2.7", alert, "A", "UDP", "192.0.2.1", "l\u202en")
    r.idn_alert("plain.example.com", "192.0.2.7", alert, "A", "DoQ", "::ffff:192.0.2.1", "")
    r.idn_alert("plain.example.com", "127.0.0.1", alert, "TYPE65280")
    r.idn_alert("", "192.0.2.7", alert, "")


# ---- states the Frontend reaches rarely ----------------------------------------------------------------------------


@scenario("send", module_files(main={"python_control": "true"}))
def _(r):
    q = "python_control.big."
    r.send(
        q, 1, msg=True, authority=300
    )  # over a stream's limit: the bare SERVFAIL, and its callback is reply_servfail
    r.send(q, 1, msg=True, authority=3)  # a small answer: reply
    r.send(q, 1, msg=True, authority=3, relay=True)  # the module left Unbound's bytes alone: still a reply row
    r.send(q, 1, msg=False)  # no message, no rcode: SERVFAIL
    r.send(q, 1, msg=False, return_rcode=5)  # an error rcode with no message
    r.send(q, 1, msg=True, authority=3, return_rcode=2)
    r.send("plain.example.", 1, msg=True, authority=300)
    r.send("plain.example.", 1, msg=False)
    r.send(q, 1, msg=True, authority=300, client="127.0.0.1")


# a SafeSearch CNAME redirect and a rewrite: the module answers or chases, and no row is its own
SAFESEARCH = (
    "duck.example,cname,safe.duck.example,198.51.100.7,2001:db8::7\n"
    "google.example,198.51.100.8,2001:db8::8\n"
    "nx.example,nxdomain,nxdomain\n"
)


@scenario("safesearch", {**module_files(), "pfb_py_ss.txt": SAFESEARCH})
def _(r):
    zone = {("safe.duck.example.", 1): ["safe.duck.example. 300 IN A 192.0.2.99"]}
    r.resolve("duck.example.", zone=zone)  # the chase finds the target
    r.resolve("duck.example.", zone={})  # the chase finds nothing: the baked address
    r.resolve("duck.example.", 28, zone=zone)
    r.resolve("google.example.")
    r.resolve("google.example.", 28)
    r.resolve("nx.example.")
    r.resolve("duck.example.", zone=zone, client="127.0.0.1")


# ---- GeoIP ---------------------------------------------------------------------------------------------------------


def rep(*rrsets, ttl=300, an=None):
    out = {"ttl": ttl, "rrsets": [[t, [rr_data(x).hex() for x in rdata]] for t, rdata in rrsets]}
    if an is not None:
        out["an"] = an
    return out


def ipv4(text):
    return bytes(int(x) for x in text.split("."))


def ipv6(text):
    return ipaddress.IPv6Address(text).packed


def qs(qname="q.example.", qtype=1, **extra):
    return {"qname": qname, "qtype": qtype, **extra}


ADDR = {"pfb_addr": "192.0.2.7"}
V4 = [
    "2.125.160.216",
    "81.2.69.142",
    "216.160.83.56",
    "67.43.156.1",
    "217.65.48.1",
    "202.196.224.9",
    "8.8.8.8",
    "1.1.1.1",
    "10.1.2.3",
    "127.0.0.1",
    "127.1.2.3",
    "192.168.1.1",
    "172.16.0.1",
    "172.31.255.255",
    "172.32.0.1",
    "169.254.1.1",
    "100.64.0.1",
    "0.0.0.0",
    "255.255.255.255",
    "224.0.0.1",
    "240.0.0.1",
    "198.18.0.1",
    "198.51.100.1",
    "203.0.113.1",
    "192.0.0.9",
    "192.0.0.10",
    "192.0.0.170",
    "192.0.0.171",
    "192.0.2.1",
    "11.0.0.1",
    "126.255.255.255",
    "128.0.0.1",
]
V6 = [
    "2001:218::1",
    "2a02:d500::1",
    "2001:480::1",
    "::1",
    "::",
    "fe80::1",
    "fc00::1",
    "fd12:3456::1",
    "2001:db8::1",
    "2002::1",
    "2001::1",
    "2001:1::1",
    "2001:1::2",
    "2001:3::1",
    "2001:4:112::1",
    "2001:20::1",
    "2001:30::1",
    "2001:2::1",
    "64:ff9b:1::1",
    "100::1",
    "3fff::1",
    "3fff:fff::1",
    "4000::1",
    "::ffff:2.125.160.216",
    "::ffff:127.0.0.1",
    "::ffff:10.0.0.1",
    "::ffff:8.8.8.8",
    "::102:304",
    "1:0:2:3:4:5:6:7",
    "2001:0:0:1::1",
    "2a02:d080::7",
    "2606:4700:4700::1111",
]


@scenario("geoip-addresses", module_files(), GEOLITE)
def _(r):
    for text in V4:
        r.details_reply("reply", qs("geo.example."), rep(("A", [ipv4(text)])), ADDR)
    for text in V6:
        r.details_reply("reply", qs("geo.example.", 28), rep(("AAAA", [ipv6(text)])), ADDR)
    # a TXT string that reads as an address is looked up too; the other literals are not
    for text in (
        "2.125.160.216",
        "8.8.8.8",
        "10.0.0.1",
        "2001:218::1",
        "fe80::1%em0",
        "fe80::1%",
        # a scope id: private and loopback are decided before the lookup, which refuses the text (unk)
        "fd12:3456::1%em0",
        "::ffff:127.0.0.1%em0",
        "::ffff:10.0.0.1%em0",
        "2001:218::1%em0",
        # libmaxminddb takes a numeric scope id (digits, up to 2**32 - 1) and refuses any other
        "2001:218::1%1",
        "2001:218::1%0",
        "::ffff:2.125.160.216%4294967295",
        "2001:218::1%4294967296",
        "2001:218::1%1a",
        "2001:218::1%+1",
        "2001:218::1%\uff11",
        "2001:218::1%0x1",
        "2001:218::1%1_0",
        "::ffff:2.125.160.216%em0",
        "2a02:d500::1%em0",
        "1.2.3",
        "01.2.3.4",
        "2.125.160.216 ",
        "2.125.160.216/24",
        "::ffff:1.2.3.4",
        "::FFFF:2.125.160.216",
    ):
        r.details_reply("reply", qs("geo.example.", 16), rep(("TXT", [strings(text.encode())])), ADDR)
    for literal in ("NXDOMAIN", "NODATA", "DNSSEC", "SOA", "NS", "Unknown"):
        r.details_reply("reply", qs("geo.example.", 16), rep(("TXT", [strings(literal.encode())])), ADDR)
    r.details_reply(
        "reply", qs("geo.example.", 16), rep(("A", [ipv4("2.125.160.216")]), ("TXT", [strings(b"x")])), ADDR
    )  # "addr|x" is no address
    r.details_reply(
        "reply", qs("geo.example.", 1), rep(("CNAME", [dname(b"a", b"example")]), ("A", [ipv4("216.160.83.56")])), ADDR
    )
    r.details_reply("reply", qs("geo.example.", 1), rep(), ADDR)  # NXDOMAIN
    r.details_reply("reply", qs("geo.example.", 1), None, ADDR)


@scenario("geoip-record-shapes", module_files(), GEOIP2)
def _(r):
    for text in ("5.83.124.1", "214.1.1.1", "2.125.160.216", "81.2.69.142"):
        r.details_reply("reply", qs("geo.example."), rep(("A", [ipv4(text)])), ADDR)
    for text in ("2a02:d500::1", "2a02:ec80::1", "2001:218::1"):
        r.details_reply("reply", qs("geo.example.", 28), rep(("AAAA", [ipv6(text)])), ADDR)


@scenario("geoip-continent-fallback", module_files(), GEOLITE)
def _(r):
    for text in ("2a02:d500::1", "2a02:ec80::1", "2a02:ec80::ffff"):
        r.details_reply("reply", qs("geo.example.", 28), rep(("AAAA", [ipv6(text)])), ADDR)


@scenario("geoip-reader-absent", module_files())
def _(r):
    for text in ("2.125.160.216", "8.8.8.8", "10.0.0.1"):
        r.details_reply("reply", qs("geo.example."), rep(("A", [ipv4(text)])), ADDR)
    r.details_reply("reply", qs("geo.example.", 28), rep(("AAAA", [ipv6("2001:218::1")])), ADDR)


@scenario("geoip-through-the-frontend", module_files(), GEOLITE)
def _(r):
    zone = {
        ("gb.example.", 1): ["gb.example. 300 IN A 2.125.160.216"],
        ("jp.example.", 28): ["jp.example. 300 IN AAAA 2001:218::1"],
        ("alias.gb.example.", 1): ["alias.gb.example. 300 IN CNAME gb.example.", "gb.example. 300 IN A 2.125.160.216"],
    }
    r.resolve("gb.example.", zone=zone)
    r.resolve("jp.example.", 28, zone=zone)
    r.resolve("alias.gb.example.", zone=zone)


# ---- reply rows written directly -----------------------------------------------------------------------------------

HOSTILE_BYTES = b'we"ird<x>'
MIXED = b"a'b&c\x1b"


@scenario("reply-rrtypes", module_files(sections=NOAAAA))
def _(r):
    q = qs()
    cases = [
        ("CNAME", dname(HOSTILE_BYTES, b"example")),
        ("NS", dname(b"ns1", HOSTILE_BYTES, b"example")),
        ("PTR", dname(HOSTILE_BYTES, b"example")),
        ("DNAME", dname(HOSTILE_BYTES, b"example")),
        ("SOA", dname(HOSTILE_BYTES, b"example") + dname(b"admin", b"example") + bytes(20)),
        ("HINFO", strings(HOSTILE_BYTES, MIXED)),
        ("TXT", strings(MIXED)),
        ("CNAME", dname(b"cdn", b"example", b"net")),
        ("SOA", dname(b"ns1", b"example", b"com") + dname(b"admin", b"example", b"com") + bytes(20)),
        ("HINFO", strings(b"INTEL", b"Linux")),
        ("TXT", strings(b"v=spf1 include:_spf.google.com ~all")),
        ("TXT", strings(b"v=DMARC1; p=none; rua=mailto:d@example.com")),
        ("A", ipv4("192.0.2.41")),
        ("AAAA", ipv6("2001:db8::41")),
        ("DNSKEY", b"\x01\x01\x03\x08" + b"k" * 8),
        ("DS", b"\x30\x39\x08\x02" + b"d" * 32),
        ("MX", b"\x00\x0a" + dname(HOSTILE_BYTES, b"example")),
        ("SRV", b"\x00\x00\x00\x05\x13\xc4" + dname(HOSTILE_BYTES, b"example")),
        ("CAA", b"\x00\x05issue" + HOSTILE_BYTES),
        ("HTTPS", b"\x00\x01" + dname(HOSTILE_BYTES, b"example")),
        ("SVCB", b"\x00\x01" + dname(HOSTILE_BYTES, b"example")),
        ("NAPTR", b"\x00\x64\x00\x0a" + strings(b"u", b"E2U+sip", HOSTILE_BYTES) + b"\x00"),
        ("TXT", strings(b"<" * 64)),
        ("TXT", strings(b"<" * 63)),
        ("TXT", b""),
        ("TXT", b"\x00"),
        ("TXT", strings(b"")),
        ("TXT", strings(b"|")),
        ("TXT", strings(b"a", b"|")),
        ("TXT", strings(b"a", b"b")),
        ("TXT", strings(b"a\r\nb\x1bc")),
        ("TXT", strings("é ü€".encode("latin-1", "replace"))),
        ("TXT", strings(bytes(range(0x80, 0xA0)))),
        ("TXT", strings("\u0e01".encode("utf-8"))),
        ("TXT", strings(b"a,b")),
        ("CNAME", dname(b"a,b", b"example")),
        ("CNAME", b""),
        ("CNAME", b"\xc0\x0c"),
        ("CNAME", b"\x05ab"),
        ("TYPE9999", dname(b"x", b"y")),
        ("A", ipv4("192.0.2.41") + b"\x01"),
        ("AAAA", ipv6("2001:db8::41") + b"\x01"),
    ]
    for rtype, rdata in cases:
        r.details_reply("reply", qs("q.example.", 1), rep((rtype, [rdata])), ADDR)
    # more than one record, more than one rrset
    r.details_reply("reply", q, rep(("TXT", [strings(b"v=spf1 -all"), strings(HOSTILE_BYTES)])), ADDR)
    r.details_reply("reply", q, rep(("CNAME", [dname(HOSTILE_BYTES, b"example")]), ("A", [ipv4("203.0.113.8")])), ADDR)
    r.details_reply(
        "reply", q, rep(("CNAME", [dname(b"a", b"b"), dname(b"c", b"d")]), ("A", [ipv4("203.0.113.9")])), ADDR
    )
    r.details_reply("reply", q, rep(("CNAME", [dname(b"a", b"b"), dname(b"c", b"d")])), ADDR)
    r.details_reply("reply", q, rep(("A", [ipv4("192.0.2.1"), ipv4("192.0.2.2")])), ADDR)
    r.details_reply("reply", q, rep(("AAAA", [ipv6("2001:db8::1"), ipv6("2001:db8::2")])), ADDR)
    r.details_reply("reply", q, rep(("A", [ipv4("192.0.2.1")]), ("TXT", [strings(b"x")])), ADDR)
    r.details_reply("reply", q, rep(("TXT", [strings(b"x")]), ("A", [ipv4("192.0.2.1")])), ADDR)
    r.details_reply(
        "reply", q, rep(("TXT", [strings(b"x")]), ("TXT", [strings(b"y")]), ("NS", [dname(b"n", b"s")])), ADDR
    )
    r.details_reply("reply", q, rep(("DNSKEY", [b"k"]), ("A", [ipv4("192.0.2.1")])), ADDR)
    r.details_reply("reply", q, rep(("A", [ipv4("192.0.2.1")]), ("DNSKEY", [b"k"])), ADDR)
    r.details_reply("reply", q, rep(("TXT", [strings(b"x")]), ("DS", [b"k"])), ADDR)
    r.details_reply(
        "reply",
        q,
        rep(
            (
                "TXT",
                [strings(b"x")],
            ),
            ("RRSIG", [b"sig"]),
        ),
        ADDR,
    )
    r.details_reply(
        "reply",
        q,
        rep(
            (
                "A",
                [ipv4("192.0.2.1")],
            ),
            ("TXT", [strings(b"x")]),
            an=1,
        ),
        ADDR,
    )
    r.details_reply("reply", q, rep(("A", [ipv4("192.0.2.1")]), an=0), ADDR)
    r.details_reply("reply", q, rep(("A", [ipv4("192.0.2.1")]), ("A", [ipv4("192.0.2.2")])), ADDR)
    r.details_reply("reply", q, rep(("A", [])), ADDR)
    r.details_reply("reply", q, rep(("TXT", [])), ADDR)
    r.details_reply("reply", q, rep(("", [ipv4("192.0.2.1")])), ADDR)
    r.details_reply("reply", q, rep(), ADDR)
    # a record too short for its type: Python raises, the answer is a SERVFAIL
    for rtype, rdata in (("A", b"\x01\x02\x03"), ("A", b""), ("AAAA", bytes(15)), ("AAAA", b"")):
        r.details_reply("reply", q, rep((rtype, [rdata])), ADDR)


@scenario("reply-columns", module_files(sections=NOAAAA))
def _(r):
    a = rep(("A", [ipv4("192.0.2.1")]))
    r.details_reply("reply", qs("q.example.", 1), None, ADDR)
    r.details_reply("reply", qs("q.example.", 1), rep(ttl=0), ADDR)
    r.details_reply("reply", qs("q.example.", 1), rep(("A", [ipv4("192.0.2.1")]), ttl=0), ADDR)
    r.details_reply("reply", qs("q.example.", 1), rep(("A", [ipv4("192.0.2.1")]), ttl=4294967295), ADDR)
    r.details_reply("reply", qs("q.example.", 1), rep(("A", [ipv4("192.0.2.1")]), ttl=1), ADDR)
    for code in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 16, 17, 18, 19, 20, 21, 22, 23, 12, 24, 100):
        r.details_reply("reply", qs("q.example.", 1, return_rcode=code), a, ADDR)
        r.details_reply("reply", qs("q.example.", 1, return_rcode=code), None, ADDR)
    r.details_reply("reply", qs("q.example.", 1, return_rcode=3), rep(), ADDR)
    # q_type: the query's type for PTR and cache, else the type of the first rrset of the message
    msg = {"qname": "q.example.", "rep": rep(("SOA", [dname(b"ns", b"example") + dname(b"h", b"example") + bytes(20)]))}
    for qtype in (1, 12, 28, 2, 6, 50, 16, 255, 65, 9999):
        r.details_reply("reply", qs("q.example.", qtype), a, ADDR)
        r.details_reply("reply", qs("q.example.", qtype, return_msg=msg), a, ADDR)
        r.details_reply("reply", qs("q.example.", qtype, return_msg=msg), rep(), ADDR)
        r.details_reply("cache", qs("q.example.", qtype, return_msg=msg), rep(ttl=NOW + 60), ADDR)
    r.details_reply("reply", qs("q.example.", 1, return_msg={"qname": "q.example.", "rep": rep()}), a, ADDR)
    r.details_reply("reply", qs("q.example.", 1, return_msg={"qname": "q.example.", "rep": None}), a, ADDR)
    # the name: blank falls back to the message's, the root is Unknown, an NS of it is "NS"
    r.details_reply("reply", qs("", 1, return_msg={"qname": "fallback.example.", "rep": None}), a, ADDR)
    r.details_reply("reply", qs("  ", 1, return_msg={"qname": "fallback.example.", "rep": None}), a, ADDR)
    r.details_reply("reply", qs("", 1), a, ADDR)
    r.details_reply("reply", qs(".", 1), a, ADDR)
    r.details_reply("reply", qs(".", 2), rep(("NS", [dname(b"a", b"root")])), ADDR)
    r.details_reply("reply", qs(".", 2), None, ADDR)
    r.details_reply("reply", qs("", 2), None, ADDR)
    r.details_reply("reply", qs("a.example.", 2), None, ADDR)
    r.details_reply("reply", qs("a..example.", 1), a, ADDR)
    r.details_reply("reply", qs("a.example", 1), a, ADDR)
    r.details_reply("reply", qs("a.example...", 1), a, ADDR)
    r.details_reply("reply", qs(" a.example. ", 1), a, ADDR)
    # SOA / NSEC3 over NXDOMAIN become the type; an AAAA over NXDOMAIN is noAAAA when the name is listed
    r.details_reply("reply", qs("q.example.", 6), rep(), ADDR)
    r.details_reply("reply", qs("q.example.", 50), rep(), ADDR)
    r.details_reply("reply", qs("q.example.", 2), rep(), ADDR)
    r.details_reply("reply", qs("noaaaa.example.", 28), rep(), ADDR)
    r.details_reply(
        "reply", qs("NOAAAA.example.", 28), rep(), ADDR
    )  # the table is keyed lower case, the name is not folded
    r.details_reply("reply", qs("sub.noaaaa-wild.example.", 28), rep(), ADDR)
    r.details_reply("reply", qs("noaaaa-wild.example.", 28), rep(), ADDR)
    r.details_reply("reply", qs("sub.noaaaa.example.", 28), rep(), ADDR)
    r.details_reply("reply", qs("noaaaa.example.", 28), None, ADDR)
    r.details_reply("reply", qs("noaaaa.example.", 28), rep(("AAAA", [ipv6("2001:db8::1")])), ADDR)
    r.details_reply("reply", qs("noaaaa.example.", 1), rep(), ADDR)
    # the client: Unknown and the firewall itself are a resolver row
    for kwargs in (
        {"pfb_addr": "127.0.0.1"},
        {"pfb_addr": ""},
        {"pfb_addr": "::1"},
        {"pfb_addr": "2001:db8::1"},
        {"pfb_addr": "127.0.0.2"},
        {"pfb_addr": "0:0:0:0:0:0:0:1"},
        {"pfb_addr": "a,b"},
        {"pfb_addr": '"'},
        None,
        {},
    ):
        for m_type in ("reply", "cache", "local", "servfail", "reply-x"):
            r.details_reply(m_type, qs("python_control.x.", 1), a, kwargs)
    # kwargs without pfb_addr: the client is the repinfo's
    r.details_reply("reply", qs("q.example.", 1), a, {"repinfo": "192.0.2.9"})
    r.details_reply("reply", qs("q.example.", 1), a, {"repinfo": ""})
    r.details_reply("reply", qs("q.example.", 1), a, {"repinfo": "192.0.2.9", "pfb_addr": "192.0.2.8"})
    r.details_reply("reply", qs("q.example.", 1), a, {"pfb_transport": "DoQ"})
    # the qstate is absent: the query's own info and the kwargs' transport and listener
    for transport in ("TCP", "UDP", "DoT", "DoH", "DoQ", "nope", ""):
        r.details_reply(
            "reply",
            None,
            a,
            {
                "pfb_addr": "192.0.2.7",
                "pfb_transport": transport,
                "pfb_listener_ip": "192.0.2.1",
                "pfb_listener_interface": "em0",
            },
            qinfo=qs("q.example.", 1),
        )
    r.details_reply("reply", None, a, ADDR, qinfo=qs("q.example.", 28))
    r.details_reply("cache", None, a, ADDR, qinfo=qs("q.example.", 28))
    r.details_reply("reply", None, a, ADDR, qinfo=qs("", 1))
    r.details_reply("reply", None, a, ADDR)
    r.details_reply("reply", None, None, None)
    # the transport and the listener of the qstate
    for transport in (
        "TCP",
        "UDP",
        "DoT",
        "DoH",
        "DoQ",
        "Unknown",
        "",
        "udp",
        " UDP",
        "UDP ",
        "UDP,TCP",
        "UDP\r\nTCP",
        "<b>UDP</b>",
        "ÜDP",
        "U" * 300,
    ):
        r.details_reply("reply", qs("q.example.", 1, transport=transport), a, ADDR)
    for lip, lif in (
        ("192.0.2.1", "em0"),
        ("2001:DB8:0:0::1", "em,0"),
        ("bad", "em0"),
        ("", "em0"),
        ("192.0.2.1", 'a"b'),
        ("192.0.2.1", "\u00ad"),
        ("192.0.2.1", "a\ufeffb"),
        ("192.0.2.1", "\u2029"),
        ("192.0.2.1", "\u0085"),
        ("192.0.2.1", "\x7f"),
        ("192.0.2.1", "a b"),
        ("192.0.2.1", "\u00a0"),
        ("192.0.2.1", "\u3000"),
    ):
        r.details_reply("reply", qs("q.example.", 1, lip=lip, lif=lif), a, ADDR)
    # a hostile name
    for name in (
        "a<b>.example.",
        HOSTILE,
        "a\tb.example.",
        "\u00e9.example.",
        "x\u200b.example.",
        "x\u202e.example.",
        "x\u2066.example.",
        "x\u2069.example.",
        "x\u206a.example.",
        "x\u061c.example.",
        "x\u200c\u200d.example.",
        "x\u200e\u200f.example.",
        "\u0080\u009f.example.",
        "x\u007f.example.",
        "x\\.example.",
        "x\\092.example.",
    ):
        r.details_reply("reply", qs(name, 1), rep(("TXT", [strings(name.encode("latin-1", "replace"))])), ADDR)
        r.details_reply("reply", qs(name, 1), None, ADDR)


@scenario("reply-callbacks", module_files(main={"python_control": "true"}, sections=NOAAAA))
def _(r):
    a = rep(("A", [ipv4("192.0.2.1")]))
    aaaa = rep(("AAAA", [ipv6("2001:db8::1")]))
    for kind in ("reply", "reply_cache", "reply_local", "reply_servfail"):
        for name in (
            "python_control.x.",
            "python_control.",
            "PYTHON_CONTROL.x.",
            "q.example.",
            "noaaaa.example.",
            "sub.noaaaa-wild.example.",
        ):
            for qtype in (1, 28):
                r.callback(kind, qs(name, qtype, client="192.0.2.7"), a if qtype == 1 else aaaa)
                r.callback(kind, qs(name, qtype, client="192.0.2.7"), rep(an=0))
                r.callback(kind, qs(name, qtype, client="192.0.2.7"), None)
    for transport in ("TCP", "UDP", "DoT", "DoH", "DoQ", "Unknown", "x"):
        for kind in ("reply", "reply_cache", "reply_local", "reply_servfail"):
            r.callback(
                kind,
                qs("python_control.x.", 1, client="2001:db8::12", transport=transport, lip="192.0.2.1", lif="em0"),
                a,
            )
    r.callback("reply_cache", qs("q.example.", 1, client="127.0.0.1"), rep(("A", [ipv4("192.0.2.1")]), ttl=NOW + 300))
    r.callback("reply_cache", qs("q.example.", 1, client=""), rep(("A", [ipv4("192.0.2.1")]), ttl=NOW + 300))
    for ttl in (
        NOW + 300,
        NOW,
        NOW - 5,
        NOW + 1,
        300,
        0,
        4294967295,
        999999999,
        1000000000,
        9999999999 % 4294967296,
        1000000001,
        NOW + 86400 * 365,
    ):
        r.callback("reply_cache", qs("q.example.", 1, client="192.0.2.7"), rep(("A", [ipv4("192.0.2.1")]), ttl=ttl))
    r.callback("reply_cache", qs("q.example.", 1, client="192.0.2.7"), None)
    r.callback(
        "reply_cache", qs("q.example.", 12, client="192.0.2.7"), rep(("CNAME", [dname(b"a", b"b")]), ttl=NOW + 10)
    )
    r.callback("reply_local", qs("q.example.", 1, client="192.0.2.7"), rep(("A", [ipv4("192.0.2.1")]), ttl=NOW + 300))
    r.callback("reply_servfail", qs("q.example.", 1, client="192.0.2.7", return_rcode=2), None)
    r.callback("reply_servfail", qs("q.example.", 1, client="192.0.2.7", return_rcode=2, transport="TCP"), None)
    r.callback("reply", qs("python_control.x.", 1, client="192.0.2.7", return_rcode=2), None)
    r.callback("reply", qs("python_control.x.", 1, client="192.0.2.7", return_rcode=5), a)
    r.callback("reply", qs("noaaaa.example.", 28, client="192.0.2.7", return_rcode=3), rep())
    r.callback(
        "reply",
        qs(
            "noaaaa.example.",
            28,
            client="192.0.2.7",
            return_msg={
                "qname": "noaaaa.example.",
                "rep": rep(("SOA", [dname(b"ns", b"example") + dname(b"h", b"example") + bytes(20)])),
            },
        ),
        rep(),
    )


# ---- DNSBL rows written directly -----------------------------------------------------------------------------------


@scenario("dnsbl-rows", module_files(sections=NOAAAA))
def _(r):
    base = {"feed": "Feed", "group": "Group", "b_eval": "example.com"}
    q = qs("blocked.example.", 1, client="192.0.2.7")
    r.details_dnsbl(q, {**base}, ADDR)
    r.details_dnsbl(q, {**base}, ADDR)  # a duplicate
    r.details_dnsbl(q, {**base}, ADDR)
    r.details_dnsbl(q, {**base, "feed": "Other"}, ADDR)
    r.details_dnsbl(q, {**base, "feed": "Other"}, ADDR)
    for field, value in (("is_found", False), ("in_whitelist", True)):  # not a block: no row, no event
        r.details_dnsbl(q, {**base, field: value}, ADDR)
    r.details_dnsbl(q, {**base, "feed": "Other"}, ADDR)  # still a duplicate: those left the event alone
    r.details_dnsbl(q, "UNSET", ADDR)
    r.details_dnsbl(None, {**base}, ADDR)
    r.details_dnsbl(None, {**base}, ADDR, qinfo=qs("blocked.example.", 1))
    r.details_dnsbl(None, {**base}, ADDR, qinfo=qs("blocked.example.", 28))
    r.details_dnsbl(
        None,
        {**base},
        {
            "pfb_addr": "192.0.2.7",
            "pfb_transport": "DoH",
            "pfb_listener_ip": "192.0.2.1",
            "pfb_listener_interface": "em0",
        },
        qinfo=qs("blocked.example.", 28),
    )
    r.details_dnsbl(
        None,
        {**base},
        {
            "pfb_addr": "192.0.2.7",
            "pfb_transport": "DoH",
            "pfb_listener_ip": "192.0.2.1",
            "pfb_listener_interface": "em0",
        },
        qinfo=qs("blocked.example.", 28),
    )
    r.details_dnsbl(
        None,
        {**base},
        {
            "pfb_addr": "192.0.2.7",
            "pfb_transport": "DoH",
            "pfb_listener_ip": "192.0.2.1",
            "pfb_listener_interface": "em\u200b0",
        },
        qinfo=qs("blocked.example.", 28),
    )
    r.details_dnsbl(None, {**base}, None, qinfo=qs("blocked.example.", 28))
    r.details_dnsbl(None, {**base}, {"repinfo": "192.0.2.9"}, qinfo=qs("blocked.example.", 28))
    r.details_dnsbl(q, {**base}, None)
    r.details_dnsbl(q, {**base}, {"pfb_addr": ""})
    r.details_dnsbl(q, {**base}, {"pfb_addr": "Unknown"})
    r.details_dnsbl(q, {**base}, {"pfb_addr": "127.0.0.1"})
    r.details_dnsbl(q, {**base}, {"pfb_addr": "a,b"})
    # every log type: logged and silent
    for log_type in ("0", "1", "2", "3", "4", "5", "6", "7", "", "x"):
        r.details_dnsbl(q, {**base, "log_type": log_type, "feed": f"L{log_type}"}, ADDR)
    for b_type, p_type in (
        ("DNSBL", "Python"),
        ("TLD", "HSTS"),
        ("DNSBL_CNAME", "Python"),
        ("Python", "Python"),
        ("", ""),
        ("a,b", 'c"d'),
    ):
        r.details_dnsbl(q, {**base, "b_type": b_type, "p_type": p_type}, ADDR)
    # the text columns: the name and the evaluated name are escaped, the feed and the group are not
    hostile = [
        "a,b.example.",
        'a,"q".example.',
        "a\r\nb.example.",
        "a\rb.example.",
        "a\nb.example.",
        "a<b>'&.example.",
        "a\x1b\x7f\x00.example.",
        "x\u200b\u202e\u2066\u00e9.example.",
        "x\\y.example.",
        " lead.example.",
        "\u00a0nb.example.",
        "\\.",
        ".\\.",
        "a\tb.example.",
        "x\u0085\u2028\u2029.example.",
    ]
    for name in hostile:
        r.details_dnsbl(
            qs(name, 1, client="192.0.2.7"), {**base, "b_eval": name.rstrip("."), "feed": name, "group": name}, ADDR
        )
    for text in ('Fe,"<b>"&', "Gr'ou,p", " lead", "\u00a0nb", "\\.", "a\\.", "", ",", '"', '""', "\r\n", "a\nb"):
        r.details_dnsbl(q, {**base, "feed": text, "group": text, "b_eval": text}, ADDR)
    r.details_dnsbl(qs("a\u00e9\u00fc.example.", 1), {**base}, ADDR)
    r.details_dnsbl(qs("MiXeD.Example.", 1), {**base}, ADDR)
    r.details_dnsbl(qs("mixed.example.", 1), {**base}, ADDR)
    r.details_dnsbl(qs("MIXED.EXAMPLE.", 1), {**base}, ADDR)  # the same event in another case
    r.details_dnsbl(qs("\u0130.example.", 1), {**base}, ADDR)
    r.details_dnsbl(qs("i\u0307.example.", 1), {**base}, ADDR)
    # idn_alert, nxdomain and the owner are part of the decision the event compares
    r.details_dnsbl(q, {**base, "idn_alert": ["f", "g", "b"]}, ADDR)
    r.details_dnsbl(q, {**base, "idn_alert": ["f", "g", "b"]}, ADDR)
    r.details_dnsbl(q, {**base, "idn_alert": ["f", "g", "c"]}, ADDR)
    r.details_dnsbl(q, {**base, "nxdomain": True, "log_type": "3"}, ADDR)
    r.details_dnsbl(q, {**base, "nxdomain": True, "log_type": "3"}, ADDR)
    r.details_dnsbl(q, {**base, "null_blocking": True}, ADDR)
    r.details_dnsbl(q, {**base, "null_blocking": True}, ADDR)
    r.details_dnsbl(q, {**base, "in_hsts": True}, ADDR)
    r.details_dnsbl(q, {**base, "in_hsts": True}, ADDR)
    r.details_dnsbl(q, {**base, "group_owner": "o"}, ADDR)
    r.details_dnsbl(q, {**base, "group_owner": "o"}, ADDR)
    r.details_dnsbl(q, {**base, "group_owner": "o", "group_origin": "builtin"}, ADDR)
    r.details_dnsbl(q, {**base, "group_owner": "o", "group_origin": "builtin"}, ADDR)
    r.details_dnsbl(q, {**base, "p_type": "HSTS"}, ADDR)
    r.details_dnsbl(q, {**base, "p_type": "HSTS"}, ADDR)
    for transport in ("TCP", "UDP", "DoT", "DoH", "DoQ", "Unknown", "", "bogus", "UDP,TCP"):
        r.details_dnsbl(qs("blocked.example.", 1, client="192.0.2.7", transport=transport), {**base}, ADDR)
    for lip, lif in (
        ("192.0.2.1", "em0"),
        ("2001:DB8::1", "a,b"),
        ("bad", "x"),
        ("", "x"),
        ("::ffff:192.0.2.1", 'q"q'),
        ("0.0.0.0", "x"),
        ("192.0.2.1", "x\x1b"),
        ("192.0.2.1", "x\u2028"),
        ("192.0.2.1", "x\u202ey"),
    ):
        r.details_dnsbl(qs("blocked.example.", 1, client="192.0.2.7", lip=lip, lif=lif), {**base}, ADDR)
    for qtype in (1, 28, 255, 16, 12, 9999, 65280):
        r.details_dnsbl(qs("blocked.example.", qtype, client="192.0.2.7"), {**base}, ADDR)


# ---- the pure helpers ----------------------------------------------------------------------------------------------


def helper_tables(module):
    texts = [
        "",
        "plain",
        "a,b",
        'a"b',
        "a<b>c",
        "it's",
        "a&b",
        "a\\b",
        "\\",
        "a\x00b",
        "a\x01\x1f",
        "a\tb",
        "a\nb",
        "a\rb",
        "a\r\nb",
        "\x7f",
        "\x80\x9f",
        "\xa0",
        "\xff",
        "\u0100",
        "\u061c",
        "\u200b\u200c\u200d\u200e\u200f",
        "\u2028\u2029",
        "\u202a\u202b\u202c\u202d\u202e",
        "\u2066\u2067\u2068\u2069\u206a",
        "\u2065\u206f",
        "\u00e9\u00fc\u20ac\U0001f600",
        "a\u200bb",
        "xn--bnk-1ce",
        " lead",
        "trail ",
        "\\.",
        "a\\.",
        "\u3000",
        "\ufeff",
        "\u00ad",
    ]
    log_text = [{"in": t, "out": module._log_text(t)} for t in texts]
    rows = [
        [""],
        ["", ""],
        [" lead"],
        ["\xa0nb"],
        ["\\."],
        ["a\\."],
        ["a,b"],
        ['a"b'],
        ['"'],
        ['""'],
        ["a\nb"],
        ["a\rb"],
        ["a\r\nb"],
        ["a\r\n\r\nb", "\n", "\r"],
        ["a", "", "b"],
        ["a", "b", ""],
        ["", "", ""],
        [",", ",,"],
        ["\x00"],
        ["\u00e9", "\u20ac", "\U0001f600"],
        ["a b", " ", "  "],
        ["#", "\t", "\x0b", "\x0c"],
        [
            "DNSBL-python",
            STAMP,
            "a.example",
            "192.0.2.7",
            "Python",
            "DNSBL",
            "G",
            "a.example",
            "F",
            "+",
            "A",
            "UDP",
            "",
            "",
        ],
        ["x"] * 14,
    ]
    csv_row = [{"in": row, "out": module._csv_row(tuple(row))} for row in rows]
    transports = ["TCP", "UDP", "DoT", "DoH", "DoQ", "Unknown", "", "tcp", " UDP", "UDP\n", "<b>", "ÜDP", "DoQ,", "DOQ"]
    q_transport = [{"in": t, "out": module.get_q_transport(None, {"pfb_transport": t})} for t in transports]
    ips = [
        "192.0.2.1",
        "0.0.0.0",
        "255.255.255.255",
        "01.2.3.4",
        "1.2.3",
        "1.2.3.4.5",
        "1.2.3.256",
        "1.2.3.4/24",
        " 1.2.3.4",
        "1.2.3.4 ",
        "::",
        "::1",
        "2001:DB8::1",
        "2001:db8:0:0:0:0:0:1",
        "2001:0db8::0001",
        "::ffff:192.0.2.1",
        "::FFFF:C000:201",
        "::ffff:0.0.0.0",
        "0:0:0:0:0:ffff:1.2.3.4",
        "::1.2.3.4",
        "fe80::1%em0",
        "fe80::1%",
        "fe80::1%a%b",
        "1::2::3",
        "12345::1",
        "::g",
        "1:2:3:4:5:6:7:8:9",
        "1:2:3:4:5:6:7::",
        "::2:3:4:5:6:7:8",
        "1:2:3:4:5:6:1.2.3.4",
        "1:2:3:4:5:6:7:1.2.3.4",
        "\u0661.\u0662.\u0663.\u0664",
        "",
        "not-an-ip",
        "2001:db8::1/64",
        "1:0:0:2:0:0:0:3",
        "1:0:0:0:2:0:0:3",
        "0:0:1:0:0:2:0:0",
        "1:0:2:0:3:0:4:0",
    ]
    metric_ip = [{"in": t, "out": module._metric_ip(t)} for t in ips]
    listeners = [
        ["192.0.2.1", "em0"],
        ["192.0.2.1", ""],
        ["", "em0"],
        ["bad", "em0"],
        ["192.0.2.1", "a,b"],
        ["::ffff:192.0.2.1", "lan"],
        ["192.0.2.1", "\x00"],
        ["192.0.2.1", "a\u200bb"],
        ["192.0.2.1", "a\u2028b"],
        ["192.0.2.1", "a\u2029b"],
        ["192.0.2.1", "\u00ad"],
        ["192.0.2.1", "\u0600"],
        ["192.0.2.1", "\u2066"],
        ["192.0.2.1", "\u180e"],
        ["192.0.2.1", "\U000e0001"],
        ["192.0.2.1", "\U0001d173"],
        ["192.0.2.1", "\u0085"],
        ["192.0.2.1", "\u00a0"],
        ["192.0.2.1", "\u3000"],
        ["192.0.2.1", "\u2003"],
        ["192.0.2.1", "\u0378"],
        ["192.0.2.1", "\ue000"],
        ["192.0.2.1", "\U0010ffff"],
        ["192.0.2.1", "ém0\u20ac"],
        ["fe80::1%em0", "lan"],
        ["2001:DB8::1", "VLAN.10"],
    ]
    q_listener = [
        {
            "in": [ip, label],
            "out": list(module.get_q_listener(None, {"pfb_listener_ip": ip, "pfb_listener_interface": label})),
        }
        for ip, label in listeners
    ]
    wires = [
        b"",
        b"\x00\x00",
        b"\x00\x04\x01\x02\x03\x04",
        b"\x00\x04\x01\x02\x03\x04\x05",
        b"\x00\x03\x01\x02\x03",
        b"\x00\x02\x01\x02",
        b"\x00\x01\x01",
        b"\x00\x04\xff\xff\xff\xff",
        b"\x00\x04\x00\x00\x00\x00",
    ]
    wires6 = [
        b"",
        b"\x00\x00",
        rr_data(ipv6("2001:db8::1")),
        rr_data(ipv6("2001:db8::1") + b"\x00"),
        rr_data(bytes(15)),
        rr_data(ipv6("::")),
        rr_data(ipv6("::ffff:1.2.3.4")),
        rr_data(ipv6("::1")),
        rr_data(ipv6("fe80::1")),
        rr_data(bytes(range(16))),
        rr_data(bytes.fromhex("00010000000200000000000300000004")),
        rr_data(bytes.fromhex("20010db8000000010000000000000001")),
    ]
    wiresn = [
        b"",
        b"\x00\x00",
        rr_data(dname(b"a", b"b")),
        rr_data(b"\x01a\x01b"),
        rr_data(b"\x00"),
        rr_data(b"\x01a\x00"),
        rr_data(b"\x3f" + b"x" * 63),
        rr_data(b"\x40" + b"x" * 64),
        rr_data(b"\x05ab"),
        rr_data(b"\xc0\x0c"),
        rr_data(b"\x02\xe9\xfc\x01\x7f\x00"),
        rr_data(b"\x01|"),
        rr_data(b"\x01|\x01|"),
        b"\x00\x05\x03abc",
        b"\x00\x01",
    ]

    def guarded(fn, w):
        try:
            return {"in": w.hex(), "out": fn(w), "error": False}
        except Exception:
            return {"in": w.hex(), "out": "", "error": True}

    convert = {
        "ipv4": [guarded(module.convert_ipv4, w) for w in wires],
        "ipv6": [guarded(module.convert_ipv6, w) for w in wires6],
        "other": [guarded(module.convert_other, w) for w in wiresn],
    }
    addresses = [
        "0.0.0.0",
        "127.0.0.1",
        "10.0.0.1",
        "8.8.8.8",
        "100.64.0.1",
        "192.0.0.9",
        "192.0.0.10",
        "::",
        "::1",
        "fe80::1",
        "::ffff:1.2.3.4",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:100.64.0.1",
        "2001:db8::1",
        "2606:4700::1111",
        "fe80::1%em0",
    ]
    ipaddress_table = []
    for text in ips + addresses + V4 + V6:
        try:
            a = ipaddress.ip_address(text)
            ipaddress_table.append(
                {
                    "in": text,
                    "version": a.version,
                    "private": a.is_private,
                    "loopback": a.is_loopback,
                    "unspecified": a.is_unspecified,
                    "compressed": a.compressed,
                    "str": str(a),
                    "mapped": None if a.version == 4 or a.ipv4_mapped is None else str(a.ipv4_mapped),
                }
            )
        except ValueError:
            ipaddress_table.append({"in": text, "version": 0})
    return {
        "log_text": log_text,
        "csv_row": csv_row,
        "q_transport": q_transport,
        "metric_ip": metric_ip,
        "q_listener": q_listener,
        "convert": convert,
        "ipaddress": ipaddress_table,
    }


def main():
    helper_runner = Runner("helpers", module_files())
    try:
        tables = helper_tables(helper_runner.module)
    finally:
        helper_runner.close()
    out = {
        "python": sys.version.split()[0],
        "maxminddb": "3.2.0",
        "stamp": STAMP,
        "now": NOW,
        "tables": tables,
        "scenarios": SCENARIOS,
    }
    OUT.write_text(json.dumps(out, indent=1, ensure_ascii=True) + "\n", encoding="utf-8")
    steps = [step for scenario in SCENARIOS for step in scenario["steps"]]
    print(
        f"{OUT.name}: {len(SCENARIOS)} scenarios, {len(steps)} steps, {sum(len(step['rows']) for step in steps)} rows"
    )


if __name__ == "__main__":
    main()

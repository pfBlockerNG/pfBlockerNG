# Records what pfb_unbound.py (CPython 3.11) answers on the ADR-65 query channel for the scenarios
# pfb_unbound_query_test.go describes: the SHIPPED pfb_query_watcher runs on its own thread over a temp channel, each
# step rewrites the channel (or breaks it), waits until the watcher has finished with it and freezes the bytes of the
# reply file it left (null: none), its mode and what it wrote to stderr.
# Run from the repo root: uv run python go/pfb_dns_gateway/decider/testdata/gen_pfb_unbound_query_oracle.py
# It rewrites testdata/pfb_unbound_query_oracle.json.
import base64
import builtins
import contextlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
root = str(HERE.parents[3])
sys.path.insert(0, root + "/stubs/python")
import unboundmodule

for _name in unboundmodule.__all__:
    setattr(builtins, _name, getattr(unboundmodule, _name))
sys.path.insert(0, root + "/src/usr/local/pkg/pfblockerng")
sys.path.insert(0, root)
import pfb_unbound as P

BLOCK, ALLOW, IMPORTANT = P.PRIO_FEED_BLOCK, P.PRIO_FEED_ALLOW, P.PRIO_FEED_BLOCK_IMPORTANT

SETTINGS = {
    "python_blocking": True,
    "tld_allow": False,
    "tld_allow_list": [],
    "dnsbl_ipv4": "10.10.10.1",
    "dnsbl_ipv6": "::1",
    "python_idn": False,
    "idn_mode": P.IDN_MODE_OFF,
    "python_idn_block_malicious": True,
    "python_idn_escalate_suspicious": False,
    "regex_warn_ms": P.REGEX_WARN_MS_DEFAULT,
    "python_tld_seg": 2,
    "hsts_tlds": [],
}


def blk(log="1", index=0, band=BLOCK, important=False):
    return {"log": log, "index": index, "important": important, "band": band}


EPOCH_A = "0123456789abcdef0123456789abcdef"
EPOCH_B = "fedcba9876543210fedcba9876543210"

# fixture -> the snapshot's strata and the pfb settings it is read with. white: true is the legacy {name: True} shape.
FIXTURES = {
    "plain": {
        "settings": SETTINGS,
        "important_rules": False,
        "feed_group_index": {"0": ["TestFeed", "TestGroup"], "1": ["F\u00e9ed \u2603 \U0001f600", "Gr\u00fcp"]},
        "data": {
            "listed.example.com": blk(),
            "unicode-feed.example.com": blk(index=1),
            "hsts.example.com": blk(),
            "nx.example.com": blk(log="3"),
            "allowed.example.com": blk(),
            "bucher.zzexample": blk(),
        },
        "zone": {"zone.example.net": blk()},
        "white": {"allowed.example.com": True},
        "regex": [["MyBlockRegex", "^regex-hit-[0-9]+\\.example\\.org$", BLOCK, False, "RegexOwner", "custom"]],
        "allow_regex": [],
        "user_regex": [],
        "user_allow_regex": [],
        "hsts": ["hsts.example.com", "nx.example.com"],
        "group_epochs": [["TestGroup", "custom", EPOCH_A], ["RegexOwner", "custom", EPOCH_B]],
    },
    "bands": {
        "settings": SETTINGS,
        "important_rules": True,
        "feed_group_index": {"0": ["TestFeed", "TestGroup"]},
        "data": {
            "allow-wins.example.com": blk(),
            "important-wins.example.org": blk(band=IMPORTANT, important=True),
        },
        "zone": {},
        "white": {
            "allow-wins.example.com": {"wildcard": False, "important": False, "band": ALLOW},
            "important-wins.example.org": {"wildcard": False, "important": False, "band": ALLOW},
        },
        "regex": [],
        "allow_regex": [],
        "user_regex": [],
        "user_allow_regex": [],
        "hsts": [],
        "group_epochs": [],
    },
    "tld_idn": {
        "settings": dict(SETTINGS, tld_allow=True, tld_allow_list=["com", "net"], idn_mode=P.IDN_MODE_ALL),
        "important_rules": False,
        "feed_group_index": {"0": ["TestFeed", "TestGroup"]},
        "data": {},
        "zone": {},
        "white": {},
        "regex": [],
        "allow_regex": [],
        "user_regex": [],
        "user_allow_regex": [],
        "hsts": [],
        "group_epochs": [],
    },
}


def regex_db(rows):
    return {
        name: {
            "re": re.compile(pattern),
            "important": important,
            "band": band,
            "group_owner": owner,
            "group_origin": origin,
        }
        for name, pattern, band, important, owner, origin in rows
    }


def install(fixture):
    for key, value in fixture["settings"].items():
        P.pfb[key] = value
    P._snapshot = P.Snapshot(
        data_db={k: dict(v) for k, v in fixture["data"].items()},
        zone_db={k: dict(v) for k, v in fixture["zone"].items()},
        white_db={k: (v if v is True else dict(v)) for k, v in fixture["white"].items()},
        regex_db=regex_db(fixture["regex"]),
        allow_regex_db=regex_db(fixture["allow_regex"]),
        user_regex_db=regex_db(fixture["user_regex"]),
        user_allow_regex_db=regex_db(fixture["user_allow_regex"]),
        feed_group_index_db={int(k): {"feed": v[0], "group": v[1]} for k, v in fixture["feed_group_index"].items()},
        hsts_db={k: 0 for k in fixture["hsts"]},
        important_rules=fixture["important_rules"],
        group_epochs={(owner, origin): epoch for owner, origin, epoch in fixture["group_epochs"]},
    )


def req(id, domain, **more):
    return json.dumps({"id": id, "domain": domain, "qtype": "A", **more})


def text(raw):
    return {"op": "text", "text": raw}


def raw_bytes(data):
    return {"op": "bytes", "b64": base64.b64encode(data).decode("ascii")}


def answer(id, domain):
    return text(req(id, domain))


# scenario name -> (fixture, reply target, steps). Every step of a scenario but the dedupe ones is a distinct record.
SCENARIOS = {}


def scenario(name, fixture, steps, reply="ok"):
    SCENARIOS[name] = (fixture, reply, steps)


scenario(
    "verdicts",
    "plain",
    [
        answer("v1", "listed.example.com"),  # listed
        answer("v2", "LISTED.Example.COM."),  # lower-cased, root dot stripped
        answer("v3", "clean.example.com"),  # unlisted
        answer("v4", "allowed.example.com"),  # listed and allowlisted
        answer("v5", "zone.example.net"),  # zone entry itself
        answer("v6", "deep.sub.zone.example.net"),  # zone wildcard
        answer("v7", "regex-hit-42.example.org"),  # regex hit: group owner and origin, epoch of another group
        answer("v8", "regex-hit-x.example.org"),  # regex miss
        answer("v9", "hsts.example.com"),  # HSTS listed
        answer("v10", "nx.example.com"),  # NXDOMAIN shape, HSTS listed
        answer("v11", "unicode-feed.example.com"),  # non-ASCII feed and group: json.dumps escapes
        answer("v12", "xn--bcher-kva.zzexample"),
        answer("v13", "b\u00fccher.zzexample"),
        answer("v14", "a" * 300 + ".com"),  # oversized name
        answer("v15", ("a" * 63 + ".") * 4 + "com"),  # 4 maximal labels
        answer("v16", "evil\ndomain,foo;bar"),
        answer("v17", "UPPER.CASE.Example.Com..."),  # several root dots
        text(req("v18", "listed.example.com", qtype=None)),
        text(req("v19", "listed.example.com", qtype=42)),
        text(req("v20", "listed.example.com", qtype="FOO", extra=[1, {"a": None}])),
        text('{"id": "v21", "domain": "listed.example.com"}'),  # no qtype
        text('{"id": "v22", "domain": "listed.example.com", "domain": "clean.example.com"}'),  # last duplicate key wins
    ],
)

scenario(
    "bands",
    "bands",
    [
        answer("b1", "allow-wins.example.com"),  # a numeric allow band beats a block
        answer("b2", "important-wins.example.org"),  # an important block beats a plain allow
    ],
)

scenario(
    "tld_idn",
    "tld_idn",
    [
        answer("t1", "anything.example.org"),  # TLD Allow blocks a TLD outside the list
        answer("t2", "anything.example.com"),
        answer("t3", "xn--any1234.example.com"),  # IDN mode all blocks any xn--
        answer("t4", "b\u00fccher.example.com"),
    ],
)

# a record that carries no usable id is never answered; a usable id with no usable domain gets the miss-shaped reply
scenario(
    "invalid_requests",
    "plain",
    [
        text('{"domain": "listed.example.com", "qtype": "A"}'),  # no id
        text(req("", "listed.example.com")),
        text(json.dumps({"id": 123, "domain": "listed.example.com"})),
        text(json.dumps({"id": True, "domain": "listed.example.com"})),
        text(json.dumps({"id": None, "domain": "listed.example.com"})),
        text(json.dumps({"id": ["x"], "domain": "listed.example.com"})),
        text('{"id": "m1"}'),  # no domain
        text('{"id": "m2", "domain": ""}'),
        text('{"id": "m3", "domain": 123}'),
        text('{"id": "m4", "domain": null}'),
        text('{"id": "m5", "domain": ["listed.example.com"]}'),
        text('{"id": "m6", "domain": "..."}'),  # only root dots
        text('{"id": "m7", "domain": "  "}'),
        text('{"id": "m8", "domain": "\\u00a0\\u2003"}'),  # str.strip() strips Unicode spaces
        text('{"id": "m9", "domain": "\\u001c\\u001f"}'),  # ... and the ASCII separators
        text('{"id": "m10", "domain": ". ."}'),  # stripped after the dots: "." is left, and it is evaluated
        text('{"id": "m11", "domain": "listed.example.com.  "}'),  # the dot is not trailing: evaluated as is
        text('{"id": "q\\"b\\\\s\\n\\t\\u007f\\u00e9\\ud83d\\ude00", "domain": "listed.example.com"}'),  # id escapes
        text('{"id": "s\\ud800", "domain": "listed.example.com"}'),  # a lone surrogate is echoed as an escape
        text(req("i" * 5000, "listed.example.com")),  # a long id
        text('{"\\u0069d": "esc1", "domain": "listed.example.com"}'),  # keys are unescaped
    ],
)

# the reader: no record is no answer, whatever the file holds
scenario(
    "unreadable_channel",
    "plain",
    [
        text('{"id":"x",'),  # truncated
        text("[1, 2]"),
        text('"just a string"'),
        text("null"),
        text("12"),
        text("   \n  "),
        text(""),
        text("x" * (1024 * 1024)),  # 1 MB of junk
        text("\ufeff" + req("bom", "listed.example.com")),  # a BOM is not JSON whitespace
        raw_bytes(b'{"id": "bad", "domain": "\xff\xfe"}'),  # not UTF-8
        raw_bytes(b'{"id": "sur", "domain": "\xed\xa0\x80"}'),  # an encoded surrogate is not UTF-8 either
        {"op": "dir"},  # the channel is a directory
        {"op": "remove"},  # the channel is gone
        text(req("after", "listed.example.com")),  # and a good record is answered again
    ],
)

# the watcher keeps the last record it read and answers only a changed one
scenario(
    "dedupe",
    "plain",
    [
        answer("d1", "listed.example.com"),
        answer("d1", "listed.example.com"),  # byte-identical redelivery: no reply
        text('{"qtype": "A", "domain": "listed.example.com", "id": "d1"}'),  # same dict, other order: no reply
        text('{"id": "d1", "domain": "listed.example.com", "qtype": "A", "x": 1}'),  # an extra key: answered
        text('{"id": "d1", "domain": "listed.example.com", "qtype": "A", "x": 1.0}'),  # 1 == 1.0: no reply
        text('{"id": "d1", "domain": "listed.example.com", "qtype": "A", "x": true}'),  # 1.0 == True: no reply
        text('{"id": "d1", "domain": "listed.example.com", "qtype": "A", "x": 2}'),  # changed: answered
        text('{"id": "d1", "domain": "clean.example.com", "qtype": "A", "x": 2}'),  # same id, new domain: answered
        text('{"id": "d2", "domain": "clean.example.com", "qtype": "A", "x": 2}'),  # new id: answered
        text('{"id": "d2", "domain": "clean.example.com", "qtype": "A", "x": NaN}'),  # answered
        text('{"id": "d2", "domain": "clean.example.com", "qtype": "A", "x": NaN}'),  # NaN is one object: no reply
        text('{"id": "d2", "domain": "clean.example.com", "qtype": "A", "x": [1, {"k": null}]}'),
        text('{"id": "d2", "domain": "clean.example.com", "qtype": "A", "x": [1.0, {"k": null}]}'),  # no reply
        text('{"id": "d2", "domain": "clean.example.com", "qtype": "A", "x": [1, {"k": 0}]}'),  # answered
        text('{"id": "d2", "domain": "clean.example.com", "qtype": "A", "x": [1, {"k": false}]}'),  # no reply
        text("{broken"),  # no record: the last one is kept
        text('{"id": "d2", "domain": "clean.example.com", "qtype": "A", "x": [1, {"k": false}]}'),  # no reply
        text('{"id": "d3", "domain": "", "qtype": "A"}'),  # a miss-shaped reply is remembered too
        text('{"id": "d3", "domain": "", "qtype": "A"}'),  # no reply
        text('{"id": "d4", "domain": 1e999}'),  # an int-like float, answered miss-shaped
        text('{"id": "d4", "domain": 1e999}'),  # no reply
        text('{"id": "d4", "domain": 10000000000000000000000000000000000001}'),  # a big int: answered
        text('{"id": "d4", "domain": 10000000000000000000000000000000000001.0}'),  # a float: answered
        text('{"id": "d4", "domain": 10000000000000000000000000000000000001}'),  # int != float 1e37: answered
    ],
)

# the reply file cannot be written: the error is logged, nothing is left behind and the watcher goes on
scenario(
    "reply_missing_dir",
    "plain",
    [
        answer("w1", "listed.example.com"),
        answer("w2", "clean.example.com"),
    ],
    reply="missing-dir",
)
scenario(
    "reply_is_dir",
    "plain",
    [
        answer("w3", "listed.example.com"),
    ],
    reply="is-dir",
)


class Harness:
    def __init__(self, tmp):
        self.tmp = tmp
        self.channel = os.path.join(tmp, "pfb_py_query")
        self.reply = os.path.join(tmp, "pfb_py_query.reply")
        self.reads = 0
        self.lock = threading.Lock()
        real = P._control_read_record

        def counted(path):
            try:
                return real(path)
            finally:
                with self.lock:
                    self.reads += 1

        P._control_read_record = counted
        P.RELOAD_POLL_INTERVAL = 0.02

    def count(self):
        with self.lock:
            return self.reads

    def settle(self):
        # the loop reads, answers the record if it changed, reads again, sleeps: three reads that finished after the
        # write started after the write, so the second one's answer is done by the time the third returns
        target = self.count() + 3
        deadline = time.monotonic() + 30
        while self.count() < target:
            if time.monotonic() > deadline:
                raise RuntimeError("the watcher did not settle")
            time.sleep(0.005)

    def clear_channel(self):
        if os.path.isdir(self.channel):
            shutil.rmtree(self.channel)
        elif os.path.lexists(self.channel):
            os.unlink(self.channel)

    def put(self, data):
        tmp = self.channel + ".new"
        with open(tmp, "wb") as fh:
            fh.write(data)
        if os.path.isdir(self.channel):
            shutil.rmtree(self.channel)
        os.replace(tmp, self.channel)


def run_scenario(name, fixture_name, reply_mode, steps):
    install(FIXTURES[fixture_name])
    with tempfile.TemporaryDirectory(prefix="pfbquery") as tmp:
        h = Harness(tmp)
        P.pfb["pfb_py_query"] = h.channel
        reply_path = h.reply
        if reply_mode == "missing-dir":
            reply_path = os.path.join(tmp, "gone", "pfb_py_query.reply")
        elif reply_mode == "is-dir":
            os.mkdir(h.reply)
        P.pfb["pfb_py_query_reply"] = reply_path
        P.decisionDB = P._LruCache(10000)  # init_standard's
        P.pfb_query_stop = threading.Event()
        thread = threading.Thread(name="pfb_query_watcher_oracle", target=P.pfb_query_watcher, daemon=True)
        thread.start()
        out = []
        try:
            for step in steps:
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    if step["op"] == "text":
                        h.put(step["text"].encode("utf-8"))
                    elif step["op"] == "bytes":
                        h.put(base64.b64decode(step["b64"]))
                    elif step["op"] == "dir":
                        h.clear_channel()
                        os.mkdir(h.channel)
                    else:
                        h.clear_channel()
                    h.settle()
                row = dict(step)
                row["reply"] = row["mode"] = None
                if reply_mode == "ok" and os.path.exists(h.reply):
                    with open(h.reply, "rb") as fh:
                        row["reply"] = fh.read().decode("ascii")
                    row["mode"] = oct(os.stat(h.reply).st_mode & 0o777)
                    os.unlink(h.reply)
                for leftover in (h.reply + ".tmp", reply_path + ".tmp"):
                    assert not os.path.exists(leftover), leftover
                row["stderr"] = err.getvalue().replace(tmp, "<dir>")
                out.append(row)
        finally:
            P.pfb_query_stop.set()
            thread.join(10)
            assert not thread.is_alive()
    return {"name": name, "fixture": fixture_name, "reply_mode": reply_mode, "steps": out}


results = []
for name, (fixture_name, reply_mode, steps) in SCENARIOS.items():
    results.append(run_scenario(name, fixture_name, reply_mode, steps))

(HERE / "pfb_unbound_query_oracle.json").write_text(
    json.dumps({"fixtures": FIXTURES, "scenarios": results}, indent=1, ensure_ascii=True) + "\n",
    encoding="utf-8",
)
print(len(results), "scenarios,", sum(len(r["steps"]) for r in results), "steps")

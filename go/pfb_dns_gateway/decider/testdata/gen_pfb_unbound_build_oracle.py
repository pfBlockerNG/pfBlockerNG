# Records what pfb_unbound.py (CPython 3.11) returns for the inputs pfb_unbound_build_test.go describes: the oracle
# rows.
# Run from the repo root: uv run python go/pfb_dns_gateway/decider/testdata/gen_pfb_unbound_build_oracle.py
# It rewrites testdata/pfb_unbound_build_oracle.json.
#
# "build" rows stage a module directory (manifest, raw feeds, sidecar, PSL authority), set the pfb settings the ini
# would give, run dnsbl_build_from_manifest and record the BuildResult (or the None and the ledger entry it leaves).
# The other tables call one helper each: _load_user_regex_entries, the two regex compilers, the feed line reader, the
# TOP1M sidecar reader, base64 / UTF-8 decoding as those use them, dnsbl_emit_reject_stats.
import base64
import builtins
import configparser
import contextlib
import glob
import io
import itertools
import json
import os
import random
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
root = str(HERE.parents[3])
sys.path.insert(0, root + "/stubs/python")
import unboundmodule

# pfb_unbound.py runs inside Unbound, which injects these names; tests/conftest.py copies them onto builtins too.
for _name in unboundmodule.__all__:
    setattr(builtins, _name, getattr(unboundmodule, _name))
sys.path.insert(0, root + "/src/usr/local/pkg/pfblockerng")
sys.path.insert(0, root)
import pfb_unbound as P

FIXTURES = root + "/tests/fixtures"
PARITY = root + "/tests/dns_proxy/fixtures/parity"

DEFAULT_PFB = {
    "python_tld_wildcard": False,
    "tld_allow": False,
    "psl_include_private": True,
    "psl_feed_private_policy": "honor",
    "psl_feed_icann_policy": "honor",
    "regex_cap": False,
    "pfb_py_psl": "",
}


def b64(data):
    return base64.b64encode(data).decode("ascii")


def entry(e):
    d = dict(e)
    if "top1m" in d:
        d["top1m"] = sorted(d["top1m"])
    if "top1m_fallback" in d:
        d["top1m_fallback"] = entry(d["top1m_fallback"])
    return d


def regex_db(db):
    return [
        [
            name,
            {
                "pattern": v["re"].pattern,
                "important": v["important"],
                "band": v["band"],
                "group_owner": v.get("group_owner"),
                "group_origin": v.get("group_origin"),
            },
        ]
        for name, v in db.items()
    ]


# The loaded authority is PslImpl's; it is recorded only for the rows that pin the load gates.
KEEP_PSL_RULES = ("2371-load-gate", "tld-master-key", "golden", "corpus-v1-wildcard")


def dump(r, keep_psl_rules):
    out = {
        "data_db": {k: entry(v) for k, v in r.data_db.items()},
        "zone_db": {k: entry(v) for k, v in r.zone_db.items()},
        "feed_group_index_db": {str(i): v for i, v in r.feed_group_index_db.items()},
        "white_db": dict(r.white_db),
        "counts": r.counts,
        "regex_db": regex_db(r.regex_db),
        "allow_regex_db": regex_db(r.allow_regex_db),
        "user_regex_db": regex_db(r.user_regex_db),
        "user_allow_regex_db": regex_db(r.user_allow_regex_db),
        "important_rules": r.important_rules,
        "regex_count": r.regex_count,
        "rejects": [[f, g, dict(c)] for (f, g), c in sorted(r.rejects.items())],
        "builtin_log_flag": r.builtin_log_flag,
    }
    if keep_psl_rules:
        out["psl_rules"] = {
            name: list(getattr(r.psl_rules, name))
            for name in (
                "icann_exact",
                "icann_wildcard",
                "icann_exception",
                "private_exact",
                "private_wildcard",
                "private_exception",
            )
        }
    return out


def run_build(name, files, manifest=None, manifest_bytes=None, pfb=None, sidecar_mode=None):
    """One `build` row. files: rel -> bytes. The manifest is JSON of `manifest`, or the raw `manifest_bytes`."""
    overrides = dict(DEFAULT_PFB)
    overrides.update(pfb or {})
    with tempfile.TemporaryDirectory(prefix="pfbbuild") as tmp:
        base = Path(tmp)
        for rel, data in files.items():
            target = base / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        if sidecar_mode == "symlink":
            (base / "pfb_py_top1m.txt").unlink()
            (base / "elsewhere.txt").write_bytes(files["pfb_py_top1m.txt"])
            os.symlink(base / "elsewhere.txt", base / "pfb_py_top1m.txt")
        elif sidecar_mode == "directory":
            (base / "pfb_py_top1m.txt").unlink()
            (base / "pfb_py_top1m.txt").mkdir()
        elif sidecar_mode == "absent":
            (base / "pfb_py_top1m.txt").unlink()
        manifest_path = base / "pfb_py_sources.json"
        if manifest_bytes is not None:
            manifest_path.write_bytes(manifest_bytes)
        elif manifest is not None:
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        status = base / "pfb_py_status.json"
        saved = {k: P.pfb.get(k) for k in list(overrides) + ["pfb_py_status"]}
        for k, v in overrides.items():
            P.pfb[k] = os.path.join(tmp, v) if k == "pfb_py_psl" and v else v
        P.pfb["pfb_py_status"] = str(status)
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                result = P.dnsbl_build_from_manifest(str(manifest_path))
        finally:
            for k, v in saved.items():
                if v is None:
                    P.pfb.pop(k, None)
                else:
                    P.pfb[k] = v
        ledger = json.loads(status.read_text()) if status.exists() else []

        def norm(s):
            return s.replace(tmp, "<DIR>")

        return {
            "name": name,
            "files": {rel: b64(d) for rel, d in files.items()},
            "manifest": manifest,
            "manifest_b64": b64(manifest_bytes) if manifest_bytes is not None else None,
            "pfb": overrides,
            "sidecar_mode": sidecar_mode,
            "want": dump(result, name.startswith(KEEP_PSL_RULES)) if result is not None else None,
            "ledger": [norm(e["message"]) for e in ledger],
            "stderr": norm(err.getvalue()),
        }


def feed_row(raw, feed, group, log_flag="1", **extra):
    row = {"raw": raw, "feed": feed, "group": group, "log_flag": log_flag}
    row.update(extra)
    return row


def text(*lines):
    return ("".join(f"{line}\n" for line in lines)).encode("utf-8")


def authority(*icann, private=()):
    return text(
        "// ===BEGIN ICANN DOMAINS===",
        *icann,
        "// ===END ICANN DOMAINS===",
        "// ===BEGIN PRIVATE DOMAINS===",
        *private,
        "// ===END PRIVATE DOMAINS===",
    )


build_rows = []

# ---- the ADR-06 golden fixtures, both TOP1M scenarios (test_adr06_init_from_raw._write_onbox_manifest) ----
GOLDEN = FIXTURES + "/adr06_golden"
src_manifest = json.load(open(GOLDEN + "/manifest.json"))
src_config = json.load(open(GOLDEN + "/config.json"))
tld_master = open(GOLDEN + "/tld_master.txt", encoding="utf-8").read()
for top1m_enabled in (False, True):
    files = {}
    feeds = []
    for row in src_manifest["feeds"]:
        rel = "pfb_py_raw/" + os.path.basename(row["raw"])
        files[rel] = open(os.path.join(GOLDEN, row["raw"]), "rb").read()
        feeds.append(
            {
                "raw": rel,
                "feed": row["feed"],
                "group": row["group"],
                "log_flag": row["log_flag"],
                "top1m": row.get("top1m", False),
            }
        )
    files["dnsbl_psl"] = (
        "// ===BEGIN ICANN DOMAINS===\n" + tld_master + "// ===END ICANN DOMAINS===\n"
        "// ===BEGIN PRIVATE DOMAINS===\n// ===END PRIVATE DOMAINS===\n"
    ).encode()
    if top1m_enabled:
        files["pfb_py_top1m.txt"] = "".join(f"{d}\n" for d in src_config.get("top1m_list", [])).encode()
    manifest = {
        "version": 1,
        "config": {
            "tld_wildcard_blacklist": src_config.get("tld_wildcard_blacklist", []),
            "tld_wildcard_exclusion": src_config.get("tld_wildcard_exclusion", []),
            "user_whitelist": src_config.get("user_whitelist", []),
            "builtin_log_flag": "1",
            "top1m_enabled": top1m_enabled,
        },
        "feeds": feeds,
    }
    build_rows.append(
        run_build(
            f"golden-top1m-{'on' if top1m_enabled else 'off'}",
            files,
            manifest,
            pfb={"python_tld_wildcard": True, "pfb_py_psl": "dnsbl_psl"},
        )
    )

# ---- the manifest/v1 corpus fixture (test_dnsbl_manifest_v1_contract._stage_fixture) ----
CORPUS = FIXTURES + "/dnsbl_corpus"
corpus_manifest = json.load(open(CORPUS + "/manifest-v1.json", encoding="utf-8"))
corpus_files = {row["raw"]: open(os.path.join(CORPUS, row["raw"]), "rb").read() for row in corpus_manifest["feeds"]}
corpus_files["pfb_py_top1m.txt"] = open(CORPUS + "/pfb_py_top1m.txt", "rb").read()
build_rows.append(run_build("corpus-v1", corpus_files, corpus_manifest))
corpus_psl = dict(corpus_files)
corpus_psl["dnsbl_psl"] = authority(*open(CORPUS + "/tld/tld_master.txt", encoding="utf-8").read().split())
build_rows.append(
    run_build(
        "corpus-v1-wildcard", corpus_psl, corpus_manifest, pfb={"python_tld_wildcard": True, "pfb_py_psl": "dnsbl_psl"}
    )
)
abs_manifest = json.loads(json.dumps(corpus_manifest))
abs_manifest["feeds"] = [abs_manifest["feeds"][0]]
abs_manifest["config"]["top1m_enabled"] = False
build_rows.append(run_build("corpus-v1-one-feed", corpus_files, abs_manifest))
empty_group = json.loads(json.dumps(abs_manifest))
empty_group["feeds"][0]["group"] = ""
empty_group["feeds"][0]["log_flag"] = ""
build_rows.append(run_build("empty-group-and-log-flag", corpus_files, empty_group))
additive = json.loads(json.dumps(corpus_manifest))
additive["future_root"] = {"enabled": True}
additive["config"]["future_config"] = {"value": 7}
additive["feeds"][0]["future_feed"] = ["kept additive"]
build_rows.append(run_build("additive-keys", corpus_files, additive))
empty_feeds = {"version": 1, "config": {}, "feeds": []}
build_rows.append(run_build("empty-feeds", {}, empty_feeds))

# ---- every manifest/v1 contract violation (test_dnsbl_manifest_v1_contract) ----
mutations = {
    "version-missing": lambda m: m.pop("version"),
    "version-2": lambda m: m.__setitem__("version", 2),
    "version-string": lambda m: m.__setitem__("version", "1"),
    "version-true": lambda m: m.__setitem__("version", True),
    "version-null": lambda m: m.__setitem__("version", None),
    "config-missing": lambda m: m.pop("config"),
    "config-list": lambda m: m.__setitem__("config", []),
    "blacklist-string": lambda m: m["config"].__setitem__("tld_wildcard_blacklist", "zip"),
    "whitelist-int-item": lambda m: m["config"].__setitem__("user_whitelist", ["ok.example", 1]),
    "unlock-null": lambda m: m["config"].__setitem__("user_unlock", None),
    "top1m-list-dict": lambda m: m["config"].__setitem__("top1m_list", {}),
    "top1m-enabled-int": lambda m: m["config"].__setitem__("top1m_enabled", 1),
    "regex-cap-string": lambda m: m["config"].__setitem__("regex_cap", "on"),
    "feeds-missing": lambda m: m.pop("feeds"),
    "feeds-dict": lambda m: m.__setitem__("feeds", {}),
    "feed-string": lambda m: m["feeds"].__setitem__(0, "row"),
    "raw-missing": lambda m: m["feeds"][0].pop("raw"),
    "raw-empty": lambda m: m["feeds"][0].__setitem__("raw", ""),
    "raw-list": lambda m: m["feeds"][0].__setitem__("raw", ["feed.raw"]),
    "feed-missing": lambda m: m["feeds"][0].pop("feed"),
    "feed-int": lambda m: m["feeds"][0].__setitem__("feed", 1),
    "feed-empty": lambda m: m["feeds"][0].__setitem__("feed", ""),
    "group-missing": lambda m: m["feeds"][0].pop("group"),
    "log-flag-missing": lambda m: m["feeds"][0].pop("log_flag"),
    "log-flag-false": lambda m: m["feeds"][0].__setitem__("log_flag", False),
    "provenance-other": lambda m: m["feeds"][0].__setitem__("provenance", "other"),
    "provenance-list": lambda m: m["feeds"][0].__setitem__("provenance", []),
    "mode-other": lambda m: m["feeds"][0].__setitem__("mode", "other"),
    "mode-dict": lambda m: m["feeds"][0].__setitem__("mode", {}),
    "top1m-on": lambda m: m["feeds"][0].__setitem__("top1m", "on"),
    "top1m-int": lambda m: m["feeds"][0].__setitem__("top1m", 1),
    "builtin-7": lambda m: m["config"].__setitem__("builtin_log_flag", "7"),
    "builtin-empty": lambda m: m["config"].__setitem__("builtin_log_flag", ""),
    "builtin-space-before": lambda m: m["config"].__setitem__("builtin_log_flag", " 1"),
    "builtin-space-after": lambda m: m["config"].__setitem__("builtin_log_flag", "1 "),
    "builtin-01": lambda m: m["config"].__setitem__("builtin_log_flag", "01"),
    "builtin-fullwidth": lambda m: m["config"].__setitem__("builtin_log_flag", "\uff11"),
    "builtin-int": lambda m: m["config"].__setitem__("builtin_log_flag", 1),
    "builtin-true": lambda m: m["config"].__setitem__("builtin_log_flag", True),
    "builtin-null": lambda m: m["config"].__setitem__("builtin_log_flag", None),
    "builtin-list": lambda m: m["config"].__setitem__("builtin_log_flag", []),
    "builtin-dict": lambda m: m["config"].__setitem__("builtin_log_flag", {}),
    "raw-missing-file": lambda m: m["feeds"][0].__setitem__("raw", "missing.raw"),
    "raw-traversal": lambda m: m["feeds"][0].__setitem__("raw", "../outside.raw"),
    "raw-directory": lambda m: m["feeds"][0].__setitem__("raw", "pfb_py_raw"),
    "raw-absolute-outside": lambda m: m["feeds"][0].__setitem__("raw", "/etc/hostname"),
    "shapes-before-raw-io": lambda m: (
        m["feeds"][0].__setitem__("raw", "missing.raw"),
        m["feeds"][0].__setitem__("log_flag", 1),
    ),
}
base_manifest = {
    "version": 1,
    "config": {"top1m_enabled": False},
    "feeds": [feed_row("pfb_py_raw/feed.raw", "Feed", "Grp")],
}
base_files = {"pfb_py_raw/feed.raw": text("evil.example", "ads.example"), "pfb_py_top1m.txt": text("popular.example")}
for label, mutate in mutations.items():
    manifest = json.loads(json.dumps(base_manifest))
    mutate(manifest)
    build_rows.append(run_build("contract-" + label, base_files, manifest))
build_rows.append(run_build("contract-ok", base_files, base_manifest))
build_rows.append(run_build("contract-absent-manifest", base_files))
for label, data in {
    "json-array-root": b"[]",
    "json-trailing-data": b'{"version": 1, "config": {}, "feeds": []} {}',
    "json-empty": b"",
    "json-bom": b'\xef\xbb\xbf{"version": 1, "config": {}, "feeds": []}',
    "json-invalid-utf8": b'{"version": 1, "config": {}, "feeds": [], "x": "\xff"}',
    "json-version-float": b'{"version": 1.0, "config": {}, "feeds": []}',
    "json-version-exp": b'{"version": 1e0, "config": {}, "feeds": []}',
    "json-version-big": b'{"version": 100000000000000000000000000, "config": {}, "feeds": []}',
    "json-version-neg-zero": b'{"version": -0, "config": {}, "feeds": []}',
    "json-duplicate-key-last-wins": b'{"version": 2, "version": 1, "config": {}, "feeds": []}',
    "json-crlf": b'{"version": 1,\r\n"config": {},\r\n"feeds": []}\r\n',
    "json-trailing-comma": b'{"version": 1, "config": {}, "feeds": [],}',
    "json-lone-surrogate": b'{"version": 1, "config": {}, "feeds": [], "x": "\\ud800"}',
}.items():
    build_rows.append(run_build(label, {}, manifest_bytes=data))

# ---- feed lines: CR removal, invalid UTF-8, no trailing newline, blank lines ----
framing = (
    b"plain1.example\r\n"
    b"plain2.example\n"
    b"\r\n"
    b"  spaced.example  \n"
    b"mid\rcr.example\n"
    b"bad\xffbyte.example\n"
    b"trunc\xe2\x82.example\n"
    b"cut\xf0\x90\x80\n"
    b"||abp-bad\xc3.example^\n"
    b"\xfe\xfftail.example\n"
    b"last.example"
)
build_rows.append(
    run_build(
        "framing",
        {"pfb_py_raw/feed.raw": framing},
        {"version": 1, "config": {}, "feeds": [feed_row("pfb_py_raw/feed.raw", "Feed", "Grp")]},
    )
)

# ---- precedence, permit mode, unlock, whitelist, tally, duplicates (test_adr06_build_module) ----
long_label = "a" * 64
name_254 = ".".join(["b" * 61] * 4) + "." + "b" * 6
build_rows.append(
    run_build(
        "tally-abp-and-plain",
        {
            "abp.raw": text(
                "||good.example.com^", "||no-dot-host^", "||-bad.example.com^", f"||{long_label}.com^", f"||{name_254}^"
            ),
            "plain.raw": text("good.example.com", "no-dot-host"),
        },
        {
            "version": 1,
            "config": {},
            "feeds": [feed_row("abp.raw", "RejFeed", "RejGroup"), feed_row("plain.raw", "PlainFeed", "PlainGroup")],
        },
    )
)
skip_lines = [
    "",
    "   ",
    "! Title: comment",
    "# plain comment",
    "example.com##.ad-banner",
    "##.global-ad",
    "example.net#@#.whitelisted-ad",
    "example.org#?#div:has(> .ad)",
    "example.com#%#//scriptlet('x')",
    "example.com#$#body { color: red; }",
    "||example.com/ads/*",
    "||cdn.example.net/track.js",
    "||shop.example^/affiliate?id=",
    "||wild.*^",
    "||203.0.113.7^",
    "||198.51.100.42^",
    "0.0.0.0 203.0.113.99",
    "127.0.0.1 10.0.0.1",
    "||gone.example^$badfilter",
    "[Adblock Plus 2.0]",
    "not a domain at all",
    "/banners/*.gif",
]
build_rows.append(
    run_build(
        "skip-classes",
        {"skip.raw": text(*skip_lines)},
        {"version": 1, "config": {}, "feeds": [feed_row("skip.raw", "SkipFeed", "SkipGroup")]},
    )
)
build_rows.append(
    run_build(
        "user-list-tally",
        {},
        {
            "version": 1,
            "config": {
                "user_whitelist": ["bad domain!", "ok.com", long_label + ".com", "." + "a" * 64],
                "user_unlock": ["-bad.com", "also-bad", "ok2.com", long_label + ".com"],
            },
            "feeds": [],
        },
    )
)
build_rows.append(
    run_build(
        "feed-named-like-user-list",
        {"r.raw": text("good.example.com", "no-dot-host")},
        {
            "version": 1,
            "config": {"user_whitelist": ["bad domain!"], "user_unlock": ["also-bad"]},
            "feeds": [feed_row("r.raw", "user_whitelist", "DNSBL")],
        },
    )
)
for label, lists in {
    "leading-dot-then-www": [".collapex.com", "www.collapex.com"],
    "leading-dot-then-bare": [".collapex.com", "collapex.com"],
    "www-then-leading-dot": ["www.collapex.com", ".collapex.com"],
    "www-then-bare": ["www.collapex.com", "collapex.com"],
    "leading-dot-plus-mail": [".collapex.com", "mail.collapex.com"],
    "single-label-wildcard": [".lan", ".internal", "lan", "www.com", ".a_b"],
}.items():
    build_rows.append(
        run_build(
            "whitelist-" + label,
            {"pfb_py_top1m.txt": text("collapex.com")},
            {"version": 1, "config": {"user_whitelist": lists, "top1m_enabled": True}, "feeds": []},
        )
    )
build_rows.append(
    run_build(
        "unlock-widens-whitelist",
        {},
        {
            "version": 1,
            "config": {
                "user_whitelist": [".x.com", "y.com", "www.z.com"],
                "user_unlock": ["x.com", ".y.com", "z.com", "w.com"],
            },
            "feeds": [],
        },
    )
)
build_rows.append(
    run_build(
        "permit-feed",
        {
            "permit.raw": text(
                "allowed.example",
                "! c",
                "[hdr]",
                "@@||abp.example^",
                "||abp2.example^",
                "0.0.0.0 hosts.example",
                "bad domain",
                "",
                "  padded.example ",
                "no-dot",
                "mixed.example",
            ),
            "plain.raw": text("blocked.example", "mixed.example", "allowed.example"),
        },
        {
            "version": 1,
            "config": {"user_whitelist": ["mixed.example", "kept.example"]},
            "feeds": [
                feed_row("plain.raw", "Plain", "G1"),
                feed_row("permit.raw", "Permit", "G2", mode="permit"),
                feed_row("permit.raw", "Permit2", "G3", mode="deny"),
            ],
        },
    )
)
build_rows.append(
    run_build(
        "permit-feed-user-whitelist-band-six",
        {"permit.raw": text("userowned.example", "other.example")},
        {
            "version": 1,
            "config": {"user_whitelist": ["userowned.example"]},
            "feeds": [feed_row("permit.raw", "Permit", "G2", mode="permit")],
        },
    )
)
build_rows.append(
    run_build(
        "index-concatenation-collision",
        {"a.raw": text("one.example"), "b.raw": text("two.example"), "c.raw": text("three.example")},
        {
            "version": 1,
            "config": {},
            "feeds": [feed_row("a.raw", "ab", "c"), feed_row("b.raw", "a", "bc"), feed_row("c.raw", "x", "")],
        },
    )
)
build_rows.append(
    run_build(
        "last-writer-wins",
        {
            "a.raw": text("tracker.org", "||zone.org^", "data.deep.zone.org"),
            "b.raw": text("tracker.org", "||zone.org^$important"),
        },
        {
            "version": 1,
            "config": {},
            "feeds": [feed_row("a.raw", "First", "G", "2"), feed_row("b.raw", "Second", "H", "3")],
        },
    )
)
build_rows.append(
    run_build(
        "abp-allow-merge",
        {
            "abp.raw": text(
                "@@||merge.example^",
                "@@/^merge\\.example$/",
                "@@||keep.example^$important",
                "@@/^keep\\.example$/",
                "||blk.example^",
                "@@||blk.example^",
            ),
        },
        {
            "version": 1,
            "config": {"user_whitelist": ["keep.example", "user.example"]},
            "feeds": [feed_row("abp.raw", "Abp", "G")],
        },
    )
)
psl_basic = authority("com", "uk", "co.uk", "zip", "xyz", "example")
build_rows.append(
    run_build(
        "tld-blacklist-and-exclusion",
        {
            "f.raw": text(
                "a.zip",
                "x.com",
                "excluded.com",
                "y.co.uk",
                "deep.sub.example.com",
                "||b.zip^",
                "||excluded.com^",
                "||co.uk^",
                "||keep.com^",
                "@@||excluded.com^",
            ),
            "dnsbl_psl": psl_basic,
        },
        {
            "version": 1,
            "config": {
                "tld_wildcard_blacklist": ["zip", ".xyz.", "", "."],
                "tld_wildcard_exclusion": ["excluded.com", ".co.uk."],
                "builtin_log_flag": "3",
            },
            "feeds": [feed_row("f.raw", "F", "G")],
        },
        pfb={"python_tld_wildcard": True, "pfb_py_psl": "dnsbl_psl"},
    )
)

# ---- TOP1M: the sidecar, the retired inline list, the name normalisation ----
top1m_names = [
    " PopularCDN.COM. ",
    "popularcdn.com",
    "www.Example.COM",
    "",
    "bad domain!",
    ",retired.com,",
    "lan",
    "cdn.shared.example",
    "popular.example",
]
top1m_feeds = {
    "t.raw": text(
        "popularcdn.com",
        "||example.com^",
        "www.example.com",
        "other.example",
        "||cdn.shared.example^",
        "||shared.example^",
        "popular.example",
        "www.popular.example",
        "deep.popular.example",
    ),
    "u.raw": text("popularcdn.com", "||shared.example^", "popular.example"),
}
for label, rows in {
    "ticked": [feed_row("t.raw", "T", "GT", top1m=True)],
    "cleared": [feed_row("t.raw", "T", "GT")],
    "ticked-then-cleared": [feed_row("t.raw", "T", "GT", top1m=True), feed_row("u.raw", "U", "GU")],
    "cleared-then-ticked": [feed_row("u.raw", "U", "GU"), feed_row("t.raw", "T", "GT", top1m=True)],
    "two-ticked": [feed_row("t.raw", "T", "GT", top1m=True), feed_row("u.raw", "U", "GT", top1m=True)],
    "user-ticked": [feed_row("t.raw", "T", "GT", top1m=True, provenance="user"), feed_row("u.raw", "U", "GU")],
}.items():
    for enabled in (True, False):
        build_rows.append(
            run_build(
                f"top1m-{label}-{'on' if enabled else 'off'}",
                dict(top1m_feeds, **{"pfb_py_top1m.txt": text(*top1m_names)}),
                {"version": 1, "config": {"top1m_enabled": enabled, "tld_wildcard_blacklist": ["zip"]}, "feeds": rows},
            )
        )
# issue #3648 matrix: ticked/cleared Groups, both shapes, both orders, the numeric path engaged by an unrelated allow
TOP1M_LIST = ("popular.example", "cdn.shared.example", "popular.zip")
SHAPES = {"exact": "{}", "wildcard": "||{}^"}


def group_case(name, feeds, *, top1m_enabled=True, user_whitelist=(), tld_blacklist=(), numeric=False):
    if numeric:
        feeds = [*feeds, ("AllowFeed", "DNSBL_Allow", ["@@||unrelated-allow.example^"], False, False)]
    files, rows = {}, []
    for index, (feed, group, lines, ticked, user) in enumerate(feeds):
        raw = f"{index}_{feed}.raw"
        files[raw] = text(*lines)
        row = {"raw": raw, "feed": feed, "group": group, "log_flag": "1", "provenance": "user" if user else "feed"}
        if ticked:
            row["top1m"] = True
        rows.append(row)
    files["pfb_py_top1m.txt"] = text(*TOP1M_LIST)
    manifest = {
        "version": 1,
        "config": {
            "top1m_enabled": top1m_enabled,
            "user_whitelist": list(user_whitelist),
            "tld_wildcard_blacklist": list(tld_blacklist),
        },
        "feeds": rows,
    }
    build_rows.append(run_build(name, files, manifest))


for numeric in (False, True):
    tag = "numeric" if numeric else "fast"
    for shape, template in SHAPES.items():
        entry_line = template.format("popular.example")
        group_case(
            f"3648-{tag}-ticked-{shape}",
            [("PhishFeed", "DNSBL_Phish", [entry_line, "evil.example"], True, False)],
            numeric=numeric,
        )
        group_case(
            f"3648-{tag}-cleared-{shape}",
            [("PhishFeed", "DNSBL_Phish", [entry_line, "evil.example"], False, False)],
            numeric=numeric,
        )
        group_case(
            f"3648-{tag}-off-{shape}",
            [("PhishFeed", "DNSBL_Phish", [entry_line], True, False)],
            top1m_enabled=False,
            numeric=numeric,
        )
        group_case(
            f"3648-{tag}-whitelist-{shape}",
            [("AdsFeed", "DNSBL_Ads", [entry_line], False, False)],
            user_whitelist=["popular.example"],
            numeric=numeric,
        )
    group_case(
        f"3648-{tag}-wildcard-spares-top1m-names",
        [("PhishFeed", "DNSBL_Phish", ["||shared.example^", "||popular.example^"], True, False)],
        numeric=numeric,
    )
    for ticked_first, cleared_shape, ticked_shape in itertools.product((True, False), SHAPES, SHAPES):
        ticked = ("PhishFeed", "DNSBL_Phish", [SHAPES[ticked_shape].format("popular.example")], True, False)
        cleared = ("AdsFeed", "DNSBL_Ads", [SHAPES[cleared_shape].format("popular.example")], False, False)
        group_case(
            f"3648-{tag}-both-{ticked_shape}-{cleared_shape}-{'tf' if ticked_first else 'cf'}",
            [ticked, cleared] if ticked_first else [cleared, ticked],
            numeric=numeric,
        )
    group_case(
        f"3648-{tag}-cleared-parent-wildcard",
        [
            ("PhishFeed", "DNSBL_Phish", ["||cdn.shared.example^"], True, False),
            ("AdsFeed", "DNSBL_Ads", ["||shared.example^"], False, False),
        ],
        numeric=numeric,
    )
    group_case(
        f"3648-{tag}-custom-list-of-cleared-group",
        [
            ("Ads_custom", "DNSBL_Ads", ["popular.example"], False, True),
            ("PhishFeed", "DNSBL_Phish", ["popular.example"], True, False),
        ],
        numeric=numeric,
    )
    group_case(
        f"3648-{tag}-tld-blacklist",
        [("PhishFeed", "DNSBL_Phish", ["popular.zip"], True, False)],
        tld_blacklist=["zip"],
        numeric=numeric,
    )

# ---- issue #2371: feed-at-suffix policy ----
PSL2371 = authority("com", "io", "co.uk", "xn--p1ai", "*.ck", "!www.ck", private=["github.io"])
POLICIES = ("honor", "ignore", "apex")
LINESETS = {
    "github-plain": ["github.io"],
    "couk-plain": ["co.uk"],
    "github-abp": ["||github.io^"],
    "github-abp-important": ["||github.io^$important"],
    "couk-abp": ["||co.uk^"],
    "ck-apex": ["ck"],
    "ck-sub": ["foo.ck"],
    "ck-exception": ["www.ck"],
    "punycode": ["xn--p1ai"],
    "underscore": ["foo_bar.com"],
    "both": ["github.io", "||co.uk^"],
    "non-suffix": ["example.com", "a.b.example.github.io", "sub.co.uk"],
    "non-suffix-abp": ["||example.com^", "||a.b.example.github.io^", "||sub.co.uk^"],
    "allow-at-suffix": ["||github.io^", "@@||github.io^"],
    "regex-at-suffix": ["/(a|b)\\.github\\.io$/"],
}
for lines_name, lines in LINESETS.items():
    for private_policy, icann_policy in itertools.product(POLICIES, POLICIES):
        for provenance in (
            ("feed", "user") if lines_name in ("github-plain", "github-abp", "couk-abp", "both") else ("feed",)
        ):
            build_rows.append(
                run_build(
                    f"2371-{lines_name}-{private_policy}-{icann_policy}-{provenance}",
                    {"feed.raw": text(*lines), "dnsbl_psl": PSL2371},
                    {"version": 1, "config": {}, "feeds": [feed_row("feed.raw", "FEED", "GRP", provenance=provenance)]},
                    pfb={
                        "python_tld_wildcard": True,
                        "pfb_py_psl": "dnsbl_psl",
                        "psl_feed_private_policy": private_policy,
                        "psl_feed_icann_policy": icann_policy,
                    },
                )
            )
for lines_name in ("github-plain", "couk-abp"):
    for private_policy, icann_policy in itertools.product(POLICIES, POLICIES):
        for wildcard, include_private in ((False, True), (True, False), (False, False)):
            build_rows.append(
                run_build(
                    f"2371-{lines_name}-{private_policy}-{icann_policy}-wildcard{int(wildcard)}-private{int(include_private)}",
                    {"feed.raw": text(*LINESETS[lines_name]), "dnsbl_psl": PSL2371},
                    {"version": 1, "config": {}, "feeds": [feed_row("feed.raw", "FEED", "GRP")]},
                    pfb={
                        "python_tld_wildcard": wildcard,
                        "psl_include_private": include_private,
                        "pfb_py_psl": "dnsbl_psl",
                        "psl_feed_private_policy": private_policy,
                        "psl_feed_icann_policy": icann_policy,
                    },
                )
            )
for private_policy, icann_policy in (("apex", "honor"), ("honor", "honor")):
    build_rows.append(
        run_build(
            f"2371-load-gate-{private_policy}-{icann_policy}",
            {"feed.raw": text("example.com"), "dnsbl_psl": PSL2371},
            {
                "version": 1,
                "config": {"tld_wildcard_blacklist": [], "tld_wildcard_exclusion": []},
                "feeds": [feed_row("feed.raw", "feed", "group")],
            },
            pfb={
                "psl_feed_private_policy": private_policy,
                "psl_feed_icann_policy": icann_policy,
                "pfb_py_psl": "dnsbl_psl",
            },
        )
    )
build_rows.append(
    run_build(
        "2371-load-gate-corrupt-authority",
        {"feed.raw": text("example.com"), "dnsbl_psl": b"\xff"},
        {"version": 1, "config": {}, "feeds": [feed_row("feed.raw", "feed", "group")]},
        pfb={"psl_feed_private_policy": "ignore", "pfb_py_psl": "dnsbl_psl"},
    )
)
build_rows.append(
    run_build(
        "2371-load-gate-missing-authority",
        {"feed.raw": text("example.com")},
        {"version": 1, "config": {}, "feeds": [feed_row("feed.raw", "feed", "group")]},
        pfb={"python_tld_wildcard": True, "pfb_py_psl": "dnsbl_psl"},
    )
)
for flag_on in (False, True):
    files = {"feed.raw": text("example.com")}
    if flag_on:
        files["dnsbl_psl"] = authority("com", "net")
    build_rows.append(
        run_build(
            f"tld-master-key-ignored-wildcard{int(flag_on)}",
            files,
            {"version": 1, "config": {"tld_master": "/etc/passwd"}, "feeds": [feed_row("feed.raw", "feed", "group")]},
            pfb={"python_tld_wildcard": flag_on, "pfb_py_psl": "dnsbl_psl"},
        )
    )

# ---- regex: the ABP corpus and the regex fixtures, as feed and as user list, cap on and off ----
CORP = FIXTURES + "/adr07_corpus"
corp = {
    name: open(os.path.join(CORP, name), "rb").read()
    for name in ("abp_sample.txt", "regex_irreducible.txt", "regex_reducible.txt")
}
for cap in (False, True):
    for provenance in ("feed", "user"):
        build_rows.append(
            run_build(
                f"adr07-corpus-{provenance}-cap{int(cap)}",
                corp,
                {
                    "version": 1,
                    "config": {"regex_cap": cap},
                    "feeds": [
                        feed_row(name, name.split(".")[0], "G" + str(i), provenance=provenance)
                        for i, name in enumerate(corp)
                    ],
                },
            )
        )
MINE = r"/^mine[0-9]+\.example$/"
MINE_ALLOW = r"@@/^ok[0-9]+\.example$/"
long_row = "^" + "a" * 210 + "$"
hostile = "^[a-z]{1,255}[a-z]{1,255}[a-z]{1,255}x"
LEADING_DOT_ROW = r".*[0-9]\.x\.com$"
for label, (feeds, user) in {
    "split-by-provenance": ({"Custom": [MINE, MINE_ALLOW], "Feed": [MINE, MINE_ALLOW]}, ("Custom",)),
    "gate-and-cap": ({"Custom": [f"/{hostile}/", f"/{long_row}/", "/^keep[0-9]+\\.example$/"]}, ("Custom",)),
    "leading-dot": (
        {
            "Feed": [f"/{LEADING_DOT_ROW}/", f"@@/{LEADING_DOT_ROW}/"],
            "Custom": [f"/{LEADING_DOT_ROW}/", f"@@/{LEADING_DOT_ROW}/"],
        },
        ("Custom",),
    ),
    "fast-path-gate": (
        {"Feed": ["||ads.example.com^", "||evil.example.com^"], "Custom": [r"@@/^ads[0-9]?\.example\.com$/"]},
        ("Custom",),
    ),
    "feed-allow-regex": ({"Feed": ["||ads.example.com^", r"@@/^ads[0-9]?\.example\.com$/"]}, ()),
    "refused-by-the-gate": (
        {"Feed": ["||ads.example.com^"], "Custom": ["/^[a-z]{1,255}[a-z]{1,255}[a-z]{1,255}x/"]},
        ("Custom",),
    ),
    "plain-custom-rows": ({"Feed": ["||ads.example.com^"], "Custom": ["||x.example^", "@@||y.example^"]}, ("Custom",)),
    "many-feed-rules": (
        {
            "Feed": [f"/^b[0-9]+x{i}\\.example$/" for i in range(60)]
            + [f"@@/^c[0-9]+x{i}\\.example$/" for i in range(30)],
            "Custom": [MINE],
        },
        ("Custom",),
    ),
    "refusal-log-cap": (
        {"Feed": [f"/(a+)+x{i}/" for i in range(25)], "Custom": [f"/(a+)+y{i}/" for i in range(23)]},
        ("Custom",),
    ),
    "unset-log-flag": ({"Feed": [MINE]}, ()),
}.items():
    for cap in (False, True):
        build_rows.append(
            run_build(
                f"regex-{label}-cap{int(cap)}",
                {name + ".raw": text(*lines) for name, lines in feeds.items()},
                {
                    "version": 1,
                    "config": {"regex_cap": cap},
                    "feeds": [
                        feed_row(
                            name + ".raw",
                            name,
                            name,
                            "" if label == "unset-log-flag" else "1",
                            provenance="user" if name in user else "feed",
                        )
                        for name in feeds
                    ],
                },
            )
        )

# ---- parity fixture modules: the manifests the corpus runs, settings read from the module's ini ----
for path in sorted(glob.glob(PARITY + "/*.json")):
    data = json.load(open(path, encoding="utf-8"))
    module = data.get("module") if isinstance(data, dict) else None
    if not module or "manifest" not in module:
        continue
    main = configparser.ConfigParser(interpolation=None)
    main.read_dict(module.get("ini", {}))
    cfg = main["MAIN"] if main.has_section("MAIN") else {}

    def flag(option, default):
        return main.getboolean("MAIN", option) if main.has_option("MAIN", option) else default

    def policy(option):
        value = main.get("MAIN", option, raw=True).strip().lower() if main.has_option("MAIN", option) else "honor"
        return value if value in ("honor", "ignore", "apex") else "honor"

    pfb = {
        "python_tld_wildcard": flag("python_tld_wildcard", False),
        "tld_allow": flag("tld_allow", False),
        "psl_include_private": flag("psl_include_private", True),
        "psl_feed_private_policy": policy("psl_feed_private_policy"),
        "psl_feed_icann_policy": policy("psl_feed_icann_policy"),
        "regex_cap": flag("regex_cap", False),
        "pfb_py_psl": "dnsbl_psl",
    }
    files = {rel: ("\n".join(lines) + "\n").encode("utf-8") for rel, lines in module.get("files", {}).items()}
    build_rows.append(run_build("parity-" + os.path.basename(path)[:-5], files, module["manifest"], pfb=pfb))

# ---- the TOP1M sidecar as a file (a symlink, a directory, a missing file) ----
sidecar_manifest = {"version": 1, "config": {"top1m_enabled": True}, "feeds": [feed_row("f.raw", "F", "G")]}
sidecar_files = {"f.raw": text("popular.example", "other.example"), "pfb_py_top1m.txt": text("popular.example")}
for mode in ("symlink", "directory", "absent"):
    build_rows.append(run_build("sidecar-" + mode, sidecar_files, sidecar_manifest, sidecar_mode=mode))
build_rows.append(
    run_build(
        "sidecar-invalid-utf8",
        dict(sidecar_files, **{"pfb_py_top1m.txt": b"popular.example\n\xff\nother.example\n"}),
        sidecar_manifest,
    )
)
build_rows.append(run_build("sidecar-empty", dict(sidecar_files, **{"pfb_py_top1m.txt": b""}), sidecar_manifest))
build_rows.append(
    run_build(
        "sidecar-crlf-and-padding",
        dict(sidecar_files, **{"pfb_py_top1m.txt": b"  popular.example \r\n\tother.example\n\n"}),
        sidecar_manifest,
    )
)
build_rows.append(
    run_build(
        "legacy-inline-top1m-on",
        {"f.raw": text("popular.example", "other.example")},
        {
            "version": 1,
            "config": {"top1m_enabled": True, "top1m_list": ["popular.example", " Other.Example. "]},
            "feeds": [feed_row("f.raw", "F", "G", top1m=True)],
        },
    )
)
build_rows.append(
    run_build(
        "legacy-inline-top1m-off",
        {"f.raw": text("popular.example", "other.example")},
        {
            "version": 1,
            "config": {"top1m_enabled": False, "top1m_list": ["popular.example"]},
            "feeds": [feed_row("f.raw", "F", "G", top1m=True)],
        },
    )
)

# ---- _load_user_regex_entries ----
user_rows = []


def user_entries(label, ini_text):
    config = configparser.ConfigParser()
    config.read_string(ini_text)
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        entries = P._load_user_regex_entries(config)
    user_rows.append({"name": label, "ini": ini_text, "want": [list(e) for e in entries], "stderr": err.getvalue()})


def ini_for(text_value):
    return "[MAIN]\npython_enable = true\nregex_list = " + b64(text_value.encode("utf-8")) + "\n"


user_entries(
    "transport-names",
    ini_for('# full comment\r\n A%=:;"\\D#Foo desc \nB%=:;"\\D#Foo desc\n unnamed#Inline description\rblank\r\n'),
)
user_entries("swap-matches-initial", ini_for("alpha#Description\r\nbeta\n"))
user_entries(
    "unsafe-row-kept-here",
    ini_for("^[a-z]+[a-z]+(a|(?:b))+[a-z]+[a-z]+@x\\.com$#unsafe\n^[a-z]+\\.[a-z]+\\.[a-z]+$#safe\n"),
)
user_entries("absent-marker", "[MAIN]\npython_enable = true\n[REGEX]\nlegacy = old\n")
user_entries("no-main-section", "[OTHER]\nregex_list = YQ==\n")
user_entries("malformed-base64", "[MAIN]\nregex_list = %%%\n")
user_entries("non-utf8", "[MAIN]\nregex_list = " + b64(b"\xff") + "\n")
user_entries("non-ascii-marker", "[MAIN]\nregex_list = caf\u00e9\n")
user_entries("empty-marker", "[MAIN]\nregex_list =\n")
user_entries("escaped-hash", ini_for("a\\#b#desc\nc\\\\#second\n  #only comment\n\n   \n"))
user_entries(
    "description-specials",
    ini_for(
        "x1#  My Name! (v2)  \nx2#caf\u00e9 \u00e9\u00e8 tab\there\nx3# #nested\nx4##\n"
        "x5#__A_b__ \nx6#UPPER\nx7#upper\nx8#Upper\n"
    ),
)
user_entries("rows-without-pattern", ini_for(" #desc only\n  \n#c\nreal#ok\n\t#t\nreal2\n"))
user_entries("collision-suffix", ini_for("a#same\nb#same\nc#same\nd#same_2\ne#same_2\n"))
user_entries("whitespace-pattern", ini_for("  pat1  \t#d1\n\u00a0pat2\u00a0\n\u2003pat3\u2003#d3\n"))
user_entries("empty-description-names", ini_for("p1#\np2#!!!\np3# \np4#???\n"))
user_entries("crlf-runs", ini_for("p1\r\r\n\n\rp2\n\n\n"))
for payload in (
    "YQ",
    "YQ=",
    "YQ==",
    "YQ===",
    "YWI",
    "YWI=",
    "YWI==",
    "YWJj",
    "YWJj=",
    "YWJj==",
    "YWJjZ",
    "Y",
    "====",
    "",
    "YQ==YQ==",
    "YQ ==",
    "A=",
    "AA=",
    "AAA==",
    "AAAA=",
    "AAAAA=",
    "YQ=a",
    "YQ==a",
    "=YQ==",
    "YQ==%",
    "YQ_=",
    "Y+/-",
):
    user_entries("b64-" + payload, "[MAIN]\nregex_list = " + payload + "\n")

# ---- UTF-8 / base64 helpers ----
rng = random.Random(3779)
alphabet = [
    0x00,
    0x0A,
    0x0D,
    0x41,
    0x7F,
    0x80,
    0x8F,
    0x90,
    0x9F,
    0xA0,
    0xBF,
    0xC0,
    0xC1,
    0xC2,
    0xDF,
    0xE0,
    0xE1,
    0xEC,
    0xED,
    0xEE,
    0xEF,
    0xF0,
    0xF1,
    0xF3,
    0xF4,
    0xF5,
    0xFF,
]
decode_rows = []
seen = set()
for length in range(0, 5):
    for _ in range(0, {0: 1, 1: 400, 2: 1500, 3: 1500, 4: 600}[length]):
        data = bytes(rng.choice(alphabet) for _ in range(length))
        if data not in seen:
            seen.add(data)
            decode_rows.append({"hex": data.hex(), "want": [ord(c) for c in data.decode("utf-8", errors="replace")]})
for text_value in ["", "caf\u00e9", "\U0001f600", "a\u0130b"]:
    data = text_value.encode("utf-8")
    decode_rows.append({"hex": data.hex(), "want": [ord(c) for c in text_value]})

b64_rows = []
for length in range(0, 5):
    for chars in itertools.product("AQ=+\n-", repeat=length):
        s = "".join(chars)
        try:
            out = base64.b64decode(s.encode("ascii"), validate=True)
            b64_rows.append({"s": s, "ok": True, "hex": out.hex()})
        except Exception:
            b64_rows.append({"s": s, "ok": False, "hex": ""})
for s in [
    "YWJjZGVm",
    "YWJjZGU=",
    "YWJjZA==",
    "YWJjZA=",
    "YWJjZA",
    "AAAA",
    "AAA=",
    "AA==",
    "A===",
    "+/+/",
    "-_-_",
    "AB==",
    "AC==",
    "AD==",
    "AAB=",
    "AAC=",
    "AAD=",
]:
    try:
        out = base64.b64decode(s.encode("ascii"), validate=True)
        b64_rows.append({"s": s, "ok": True, "hex": out.hex()})
    except Exception:
        b64_rows.append({"s": s, "ok": False, "hex": ""})

# ---- the regex compilers (test_adr07_regex_safety, test_adr07_user_regex_containers) ----
compile_rows = []


def long_benign():
    return "^" + "a" * 60 + "$"


def feed_rule(pattern, kind="block", feed="Feed", group="Grp", band=1, important=False):
    return {"pattern": pattern, "kind": kind, "feed": feed, "group": group, "band": band, "important": important}


def to_rule(spec):
    return P.RegexRule(
        pattern=spec["pattern"],
        kind=spec["kind"],
        band=spec["band"],
        important=spec["important"],
        provenance="feed",
        feed=spec["feed"],
        group=spec["group"],
        log="1",
    )


def feed_compile(label, rules, static_cap=False):
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        db, admitted = P._dnsbl_compile_regex_rules([to_rule(r) for r in rules], static_cap=static_cap)
    compile_rows.append(
        {
            "name": label,
            "kind": "feed",
            "rules": rules,
            "static_cap": static_cap,
            "want_db": regex_db(db),
            "admitted": admitted,
            "stderr": err.getvalue(),
        }
    )


def user_compile(label, entries, regex_cap=False):
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        db = P._dnsbl_compile_user_regex(entries, regex_cap)
    compile_rows.append(
        {
            "name": label,
            "kind": "user",
            "entries": [list(e) for e in entries],
            "regex_cap": regex_cap,
            "want_db": regex_db(db),
            "stderr": err.getvalue(),
        }
    )


unsafe = [
    r"^([a-z])(?(1)[a-z]+[a-z]+[a-z]+[a-z]+|b)@x\.com$",
    r"^[a-z]+[a-z]+(?>ab)[a-z]+[a-z]+@x\.com$",
    r"^[a-z]+[a-z]+(a|(?:b))+[a-z]+[a-z]+@x\.com$",
]
safe = r"^[a-z]+\.[a-z]+\.[a-z]+$"
for cap in (False, True):
    feed_compile(f"unsafe-separators-cap{int(cap)}", [feed_rule(p) for p in unsafe] + [feed_rule(safe)], cap)
    user_compile(f"unsafe-separators-user-cap{int(cap)}", [(f"r{i}", p) for i, p in enumerate(unsafe + [safe])], cap)
feed_compile(
    "benign-admitted",
    [feed_rule(p) for p in (r"^ads[0-9]+\.example\.com$", r"\d+\.\d+", r"[a-z]+[0-9]+\.example\.com")],
)
feed_compile("quantified-group", [feed_rule(r"(a+)+x"), feed_rule(r"^(a*)*$"), feed_rule(r"(a|b)+c")])
feed_compile(
    "adjacent-groups-and-oversized-repeats",
    [feed_rule(r"^(a+)(b+)(c+)x"), feed_rule(r"a{1,256}"), feed_rule(r"a{300}")],
)
feed_compile("long-benign-cap-off", [feed_rule(long_benign())], False)
feed_compile("long-benign-cap-on", [feed_rule("^" + "a" * 210 + "$")], True)
feed_compile("cap-boundary-exact", [feed_rule("^" + "a" * 198 + "$")], True)
feed_compile("cap-boundary-over", [feed_rule("^" + "a" * 199 + "$")], True)
feed_compile(
    "kinds-feeds-and-groups",
    [
        feed_rule(r"^a\.example$", "block", "F1", "G1", 1),
        feed_rule(r"^b\.example$", "allow", "F1", "G2", 2, True),
        feed_rule(r"^c\.example$", "block", "", "", 3, True),
        feed_rule(r"^a\.example$", "block", "F1", "G1", 1),
    ],
)
feed_compile(
    "last-kind-names-the-summary",
    [feed_rule(f"(a+)+x{i}", "allow") for i in range(25)] + [feed_rule(r"^ok\.example$", "block")],
)
for count in (0, 1, 19, 20, 21, 22, 40):
    feed_compile(f"log-cap-{count}", [feed_rule(f"(a+)+x{i}", "allow") for i in range(count)])
    user_compile(f"user-log-cap-{count}", [(f"row{i}", f"(a+)+x{i}") for i in range(count)])
feed_compile("many-admitted", [feed_rule(rf"^b[0-9]+x{i}\.example$") for i in range(100)])
feed_compile(
    "wide-classes-refused",
    [
        feed_rule("^[" + "".join(chr(c) for c in range(0x21, 0x7F)) + "]+x$"),
        feed_rule(r"^[a-zA-Z0-9]{1,3}[a-zA-Z0-9]{1,3}\.example$"),
    ],
)
feed_compile("control-characters-in-refused-pattern", [feed_rule("(a+)+x\x00\x1b\u00e9\u2028\U0001f600\n\ty")])
feed_compile("long-pattern-excerpt", [feed_rule("(a+)+" + "q" * 100)])
feed_compile("long-pattern-excerpt-cap", [feed_rule("^" + "z" * 300 + "$")], True)
feed_compile("leading-dot-run", [feed_rule(LEADING_DOT_ROW), feed_rule(r"^keep[0-9]+\.example$")])
feed_compile("leading-dot-run-allow", [feed_rule(LEADING_DOT_ROW, "allow")])
feed_compile("latin-1", [feed_rule(r"^caf\w\.example$"), feed_rule(r"^cai\W\.example$")])
feed_compile("non-ascii-pattern-length", [feed_rule("^\u00e9" * 150 + "$"), feed_rule("^\u00e9" * 100 + "$")], True)
user_compile("user-mixed", [("hostile", hostile), ("long", long_row), ("keep", r"^keep[0-9]+\.example$")], False)
user_compile("user-mixed-cap", [("hostile", hostile), ("long", long_row), ("keep", r"^keep[0-9]+\.example$")], True)
user_compile("user-leading-dot", [("lead", LEADING_DOT_ROW), ("keep", r"^keep[0-9]+\.example$")])
user_compile("user-same-name-twice", [("dup", r"^a\.example$"), ("dup", r"^b\.example$"), ("other", r"^c\.example$")])
user_compile(
    "user-row-numbers", [("one", "(a+)+x"), ("two", "(a+)+y"), ("three", r"^fine\.example$"), ("four", "(b+)+z")]
)
user_compile(
    "user-wide-classes",
    [("wide", "^[" + "".join(chr(c) for c in range(0x21, 0x7F)) + "]+x$"), ("keep", r"^keep\.example$")],
)
user_compile("user-latin-1", [("latin", r"^caf\w\.example$")])
user_compile(
    "user-refusal-then-fitting",
    [(f"r{i}", f"(a+)+x{i}") for i in range(30)] + [(f"k{i}", rf"^k{i}\.example$") for i in range(5)],
)
user_compile("user-empty", [])
user_compile("user-non-ascii-length", [("wide", "^\u00e9" * 150 + "$"), ("narrow", "^\u00e9" * 100 + "$")], True)

# ---- the feed line reader (test_issue1284_dnsbl_feed_line_framing, test_manifest_path_confinement) ----
reader_rows = []
for label, data in {
    "empty": b"",
    "one-lf": b"\n",
    "lf-lines": b"a\nb\n",
    "no-trailing-newline": b"a\nb",
    "crlf": b"a\r\nb\r\n",
    "bare-cr": b"a\rb\n",
    "cr-only": b"\r",
    "double-lf": b"a\n\nb\n",
    "invalid-utf8": b"a\xffb\nc\xc3\n\xe2\x82\n\xf0\x90\x80\xf0\n",
    "surrogate-bytes": b"\xed\xa0\x80x\xed\xbf\xbf\n",
    "overlong": b"\xc0\x80\xe0\x80\x80\xf0\x80\x80\x80\n",
    "above-max": b"\xf4\x90\x80\x80\xf5\x80\x80\x80\n",
    "nul": b"a\x00b\n",
    "bom": b"\xef\xbb\xbfa\n",
    "line-separator": "a\u2028b\u0085c\n".encode("utf-8"),
    "long-line": b"x" * 3000 + b"\n" + b"y" * 10,
}.items():
    with tempfile.TemporaryDirectory(prefix="pfbreader") as tmp:
        Path(tmp, "feed.raw").write_bytes(data)
        lines = list(P._dnsbl_file_line_reader(tmp)("feed.raw"))
    reader_rows.append({"name": label, "hex": data.hex(), "want": lines})

# ---- the TOP1M sidecar reader ----
top1m_rows = []
for label, data in {
    "plain": b"a.example\nb.example\n",
    "padding": b"  a.example \r\n\tb.example\x0b\n\x1c\x1d\n",
    "unicode-space": "\u00a0a.example\u2003\n\u3000\n".encode(),
    "empty": b"",
    "no-trailing-newline": b"a.example",
    "invalid": b"a.example\n\xff\n",
    "truncated": b"a.example\n\xe2\x82",
    "surrogate": b"\xed\xa0\x80\n",
    "nul": b"a\x00.example\n",
    "bom": b"\xef\xbb\xbfa.example\n",
}.items():
    with tempfile.TemporaryDirectory(prefix="pfbtop1m") as tmp:
        Path(tmp, "pfb_py_top1m.txt").write_bytes(data)
        try:
            lines = list(P._dnsbl_fixed_top1m_lines(tmp))
            top1m_rows.append({"name": label, "hex": data.hex(), "want": lines, "error": None})
        except P._DnsblGenerationError as e:
            top1m_rows.append({"name": label, "hex": data.hex(), "want": None, "error": str(e).replace(tmp, "<DIR>")})

# ---- dnsbl_emit_reject_stats / dnsbl_emit_count ----
stats_rows = []
for label, tally in {
    "empty": {},
    "legacy-buckets": {("RejFeed", "RejGroup"): {"shape": 3, "wire_cap": 5}},
    "all-buckets": {("F", "G"): {"shape": 0, "wire_cap": 0, "suffix_drop": 2, "suffix_demote": 1}},
    "zero-row-omitted": {("Z", "Z"): {"shape": 0, "wire_cap": 0}, ("A", "B"): {"shape": 1, "wire_cap": 0}},
    "sorted": {
        ("b", "a"): {"shape": 1, "wire_cap": 0},
        ("a", "b"): {"shape": 1, "wire_cap": 0},
        ("a", "a"): {"shape": 2, "wire_cap": 1},
        ("B", "a"): {"shape": 1, "wire_cap": 0},
    },
    "non-ascii": {("f\u00e9ed", "g\U0001f600<&>"): {"shape": 1, "wire_cap": 0}},
    "suffix-only": {("F", "G"): {"shape": 0, "wire_cap": 0, "suffix_demote": 4}},
}.items():
    with tempfile.TemporaryDirectory(prefix="pfbstats") as tmp:
        out = Path(tmp, "stats.json")
        ok = P.dnsbl_emit_reject_stats(str(out), tally)
        stats_rows.append(
            {
                "name": label,
                "tally": [[f, g, c] for (f, g), c in tally.items()],
                "ok": ok,
                "want": json.loads(out.read_text()),
            }
        )

# ---- os.path.realpath and _dnsbl_path_within_base over one tree of files, directories and links ----
# "@TMP@" in a link target or a probe is the tree's own directory.
TREE = [
    ("dir", "base", None),
    ("file", "base/in.txt", None),
    ("dir", "base2", None),
    ("file", "base2/in.txt", None),
    ("dir", "base/sub", None),
    ("dir", "outside", None),
    ("file", "outside/secret.txt", None),
    ("symlink", "base/to_out", "../outside"),
    ("symlink", "base/to_out_file", "../outside/secret.txt"),
    ("symlink", "base/to_in", "in.txt"),
    ("symlink", "base/abs_in", "@TMP@/base/in.txt"),
    ("symlink", "base/loop_a", "loop_b"),
    ("symlink", "base/loop_b", "loop_a"),
    ("symlink", "base/dangling", "nothing"),
    ("symlink", "base/self", "self"),
    ("symlink", "base/sub/up", "../.."),
    ("symlink", "base/sub/parent", ".."),
    ("symlink", "chain1", "chain2"),
    ("symlink", "chain2", "base/in.txt"),
    ("symlink", "linkbase", "base"),
    ("symlink", "base/dotdot_loop", "dotdot_loop/.."),
]
PROBES = [
    "base/in.txt",
    "base/to_out/secret.txt",
    "base/to_out_file",
    "base/to_out",
    "base/to_in",
    "base/abs_in",
    "base/loop_a",
    "base/loop_a/x",
    "base/dangling",
    "base/dangling/x",
    "base/self",
    "base/sub/up",
    "base/sub/up/outside/secret.txt",
    "base/sub/../in.txt",
    "base/../outside/secret.txt",
    "base//in.txt",
    "base/./in.txt",
    "base/in.txt/",
    "base/missing/../in.txt",
    "base/nonexist",
    "base/to_out/..",
    "chain1",
    "base/sub/up/base/in.txt",
    "@TMP@/base/in.txt",
    "linkbase/in.txt",
    "linkbase/to_out/secret.txt",
    "base/sub/parent/in.txt",
    "base/dotdot_loop",
    "base/dotdot_loop/x",
    "base/in.txt/../sub",
    "base",
    "base/",
    "outside",
    ".",
    "base2/in.txt",
    "base2",
    "/",
    "/etc/passwd",
    "/etc/../etc/hostname",
]
BASES = ["base", "base/sub", "linkbase", "base/to_in", "base/nonexist", "outside", ".", "base/", "/"]
realpath_rows = []
with tempfile.TemporaryDirectory(prefix="pfbpath") as tmp:
    real_tmp = os.path.realpath(tmp)
    for kind, rel, target in TREE:
        path = Path(tmp, rel)
        if kind == "dir":
            path.mkdir(parents=True, exist_ok=True)
        elif kind == "file":
            path.write_text("x")
        else:
            os.symlink(target.replace("@TMP@", tmp), path)

    def shown(value):
        return value.replace(real_tmp, "<DIR>").replace(tmp, "<DIR>")

    def resolve(spec):
        return (
            spec.replace("@TMP@", tmp) if spec.startswith("@TMP@") or spec.startswith("/") else os.path.join(tmp, spec)
        )

    cwd = os.getcwd()
    os.chdir(tmp)
    try:
        for probe in PROBES:
            realpath_rows.append({"probe": probe, "want": shown(os.path.realpath(resolve(probe)))})
        for base in BASES:
            for probe in PROBES:
                realpath_rows.append(
                    {"base": base, "probe": probe, "within": P._dnsbl_path_within_base(resolve(probe), resolve(base))}
                )
    finally:
        os.chdir(cwd)

out = {
    "build": build_rows,
    "user_regex_entries": user_rows,
    "decode": decode_rows,
    "b64": b64_rows,
    "compile": compile_rows,
    "reader": reader_rows,
    "top1m": top1m_rows,
    "stats": stats_rows,
    "realpath": realpath_rows,
    "tree": [list(row) for row in TREE],
}
(HERE / "pfb_unbound_build_oracle.json").write_text(
    json.dumps(out, indent=None, separators=(",", ":"), ensure_ascii=True) + "\n"
)
print({k: len(v) for k, v in out.items()})

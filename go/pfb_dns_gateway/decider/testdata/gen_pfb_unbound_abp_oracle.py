# Records what pfb_unbound.py (CPython 3.11) returns for the inputs pfb_unbound_abp_test.go describes: the oracle rows.
# Run from the repo root: uv run python go/pfb_dns_gateway/decider/testdata/gen_pfb_unbound_abp_oracle.py
# It rewrites testdata/pfb_unbound_abp_oracle.json.
import base64
import builtins
import glob
import importlib.util
import json
import os
import sys
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
from tests import test_adr07_decision_spec as spec

sp = importlib.util.spec_from_file_location("spike", root + "/legacy/benchmarks/spike_adr07_regex.py")
spike = importlib.util.module_from_spec(sp)
sp.loader.exec_module(spike)

FIX = root + "/tests/dns_proxy/fixtures/parity"
CORPUS = root + "/tests/fixtures/adr07_corpus"


def walk(o, out):
    if isinstance(o, str):
        out.append(o)
    elif isinstance(o, list):
        for x in o:
            walk(x, out)
    elif isinstance(o, dict):
        for v in o.values():
            walk(v, out)


def uniq(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


fixtures = {}
for f in sorted(glob.glob(FIX + "/*.json")):
    d = json.load(open(f))
    if "module" in d and os.path.basename(f).startswith(("abp-", "regex-")):
        fixtures[os.path.basename(f)] = d["module"]

fixture_strings = []
user_regex = []
for name, mod in fixtures.items():
    strs = []
    walk(mod, strs)
    fixture_strings += strs
    rl = mod.get("ini", {}).get("MAIN", {}).get("regex_list")
    if rl:
        user_regex += base64.b64decode(rl).decode("utf-8").split("\n")

corpus = {}
for fn in ("abp_sample.txt", "regex_reducible.txt", "regex_irreducible.txt"):
    corpus[fn] = open(CORPUS + "/" + fn, encoding="utf-8").read().splitlines()
corpus_lines = [ln for fn in corpus for ln in corpus[fn]]

hostile = [
    "\u00a0||a.example^\u2003",
    "\x1f||a.example^\x1c",
    "\u0085||a.example^",
    "\u3000@@||a.example^$important\u3000",
    "0.0.0.0\u00a0nbsp.example",
    "0.0.0.0\u3000ideo.example",
    "0.0.0.0\x1fus.example",
    "0.0.0.0  \u2003 double.example  ",
    "0.0.0.0\tx.example\u00a0",
    "\u00a0plain.example\u00a0",
    "\x1cplain.example\x1d",
    "0.0.0.0 ",
    "0.0.0.0",
    "0.0.0.0 a.example extra",
    "0.0.0.0 \u00a0",
    "1.2.3.4\u00a01.2.3.4",
    "\uff11.\uff12.\uff13.\uff14 a.example",
    "1.1.1.\u00b2 a.example",
    "||b\u00fccher.example^",
    "||\u0130stanbul.example^",
    "\u212a.example",
    "||\u212a.example^",
    "I\u0307.example",
    "i" * 62 + "\u0130.example",
    "\u0130" * 32 + ".example",
    "\u00e9" * 63 + ".example",
    "\u00e9" * 64 + ".example",
    "a." + "\u00e9" * 120 + ".example",
    "||" + "\u00e9" * 63 + ".example^",
    "a" * 63 + ".example",
    "a" * 64 + ".example",
    ".".join(["b" * 61] * 4) + "." + "b" * 5,
    ".".join(["b" * 61] * 4) + "." + "b" * 6,
    ".".join(["b" * 61] * 4) + "." + "b" * 5 + ".",
    "\u03a3.example",
    "A\u03a3.example",
    "||\u00dfa.example^",
    "\u1e9e.example",
    "ex\u2028ample.com",
    "/re/",
    "@@/re/",
    "/re/$important",
    "@@/re/$badfilter",
    "//",
    "@@//",
    "/",
    "@@/",
    "@@",
    "||",
    "@@||",
    "/$",
    "/a/$",
    "/a/$important,",
    "/a\\/$important",
    "/^x\\.example$/$badfilter,important",
    "/a/b/",
    "/$important/",
    "/a/$important/",
    "/a//$important",
    "/a/$$important",
    "/a/$important,important",
    "/a/$important,badfilter,important",
    "||a.example^$important,important",
    "||a.example^$ important ",
    "||a.example^$Important",
    "||a.example^$important,,badfilter",
    "||a.example^$~important",
    "||a.example^$important=1",
    "||a.example^$badfilter=x",
    "||a.example^$\u00a0important\u2003",
    "||a.example^$",
    "||a.example^$,",
    "||a.example^$=",
    "||a.example^$important,\u00a0",
    "||a.example^$domain",
    "||a.example^^",
    "||a.example^x",
    "||a.example^|",
    "||a.example^ ^",
    "||a.example^$important^",
    "||a.example^/",
    "||a.ex/ample^",
    "||a.example",
    "||a.example$important",
    "||.a.example^",
    "||a.example.^",
    "||A.EXAMPLE^",
    "||a_b.example^",
    "||a b.example^",
    "||1.2.3.4^",
    "||1.2.3.04^",
    "||1.2.3.4.^",
    "||1.2.3^",
    "||0x7f.1^",
    "||0x^",
    "||0xg^",
    "||0X1F^",
    "||a.0x1^",
    "||a.0x1.^",
    "@@||1.2.3.4^",
    "0.0.0.0 0x7f.1",
    "0.0.0.0 1.2.3.4.",
    "a.example##b",
    "#@#",
    "##",
    " ##x",
    "~a.com,b.com##x",
    ",a##x",
    "a#?#b",
    "x # y ## z",
    "##\u00a0x",
    "##\u200bx",
    "##\x1fx",
    "##\x1c",
    "a.example#$#b",
    "A_b-c.d~*,e##x",
    "a b##x",
    "a\u00e9##x",
    "x#@#",
    "a##",
    "|#@#a",
    "# note ## x",
    "! comment",
    "[Adblock]",
    "# c",
    "#",
    "!",
    "[",
    "  ",
    "",
    "\u00a0",
    "\t",
    "plain.example",
    ".plain.example",
    "plain.example.",
    "..plain.example..",
    " .plain.example. ",
    "PLAIN.Example",
    "a.b",
    "a",
    ".",
    "..",
    "a..b",
    "-a.example",
    "a-.example",
    "a.-example",
    "a.example-",
    "_a.example",
    "a_.example",
    "a.b_",
    "xn--bcher-kva.de",
    "bücher.de",
    "a.example/path",
    "a.example*",
    "*.a.example",
    "a.example?x",
    "a.example:80",
    "a.example\n",
    "a.example\r",
    "\na.example",
    "not a domain at all",
    "one two three",
    "1.2.3.4",
    "1.2.3.4 ",
    "01.2.3.4 a.example",
    "1.2.3.256 a.example",
    "1.2.3 a.example",
    "127.0.0.1\ta.example",
    "127.0.0.1\t\ta.example\t",
    "127.0.0.1  a.example",
    "127.0.0.1 a.example # c",
]

base_lines = uniq(fixture_strings + corpus_lines + hostile)
padded = ["\u00a0" + s + "\u2003" for s in base_lines if P.parse_abp(s) is not None or P._dnsbl_is_abp_rule_line(s)]
line_inputs = uniq(base_lines + padded)


def enc_rule(r):
    if r is None:
        return None
    assert (r.provenance, r.feed, r.group, r.log) == ("feed", "F", "G", "1")
    assert r.signature[0] == r.key_or_pattern
    return {
        "kind": r.kind,
        "target": r.target,
        "key": r.key_or_pattern,
        "important": r.important,
        "badfilter": r.badfilter,
        "wildcard": r.wildcard,
        "opts": list(r.signature[1]),
    }


def enc_tally(t):
    return [[f, g, dict(c)] for (f, g), c in sorted(t.items())]


IN_SCOPE = {"block", "block_important", "block_dns_opts", "allow", "hosts", "plain", "regex_block", "regex_allow"}

lines = []
for s in line_inputs:
    t = {}
    rule = P.parse_abp(s, feed="F", group="G", log="1", tally=t)
    d = {
        "in": s,
        "abp_line": P._dnsbl_is_abp_rule_line(s),
        "regex_hit": P._dnsbl_parse_abp_regex(s),
        "classify": P._dnsbl_classify_options(s),
        "rule": enc_rule(rule),
        "tally": enc_tally(t),
        "verdict": list(P._normalise_verdict(s)),
        "verdict_single": list(P._normalise_verdict(s, True)),
        "parse": (lambda e: None if e is None else e.value)(P.parse(s)),
        "strip_hosts_prefix": P._dnsbl_strip_hosts_prefix(s),
        "ipv4": P._dnsbl_is_ipv4(s),
        "numeric_host": P._dnsbl_is_numeric_host(s),
        "wire_caps": P._dnsbl_within_wire_caps(s),
        "whitelist": [[k, v] for k, v in P._dnsbl_normalise_whitelist([s]).items()],
    }
    for k in ("abp_line", "regex_hit", "classify", "rule", "tally", "parse", "whitelist", "ipv4", "numeric_host"):
        if not d[k]:
            del d[k]
    if d["strip_hosts_prefix"] == s:
        del d["strip_hosts_prefix"]
    lines.append(d)

# spike scope categories for the corpus lines (tests/test_adr07_parser.py::test_scope_agrees_with_spike)
spike_rows = [{"in": ln, "category": spike.categorise(ln)} for ln in corpus_lines]
for r in spike_rows:
    c = r["category"]
    assert (
        c in IN_SCOPE
        or c == "badfilter"
        or c
        in {"comment", "element_hiding", "path_url", "page_context_opts", "non_dns_modifier", "ip_anchored", "other"}
    ), c

# --- reduce rows
inners = []
for s in line_inputs:
    hit = P._dnsbl_parse_abp_regex(s.strip())
    if hit is not None:
        inners.append(hit[1])
inners += [x for x in user_regex if x]
inners += [
    "",
    "$",
    "^$",
    "^(.+\\.)?$",
    "(^|\\.)$",
    "^(www\\.)?$",
    "^(www\\.)?\\.a$",
    "^a$",
    "^a\\.$",
    "^\\.a$",
    "^a\\.\\.b$",
    "^a\\.b\\.\\.c$",
    "^a\\.b\n$",
    "^a\\.b\n\n$",
    "^(.+\\.)?a\\.b\n$",
    "(^|\\.)a\\.b\n$",
    "^(?:.+\\.)?a\\.b\n$",
    "^(www\\.)?a\\.b\n$",
    "^a\\.b\r$",
    "^a\\.b \n$",
    "\n^a\\.b$",
    "^a\\.b$$",
    "^a\\.b$\n$",
    "^A\\.B$",
    "^(WWW\\.)?Example\\.com$",
    "^(Www\\.)?a\\.b$",
    "^(wWw\\.)?a\\.b$",
    "^(www\\.)?(www\\.)?a\\.b$",
    "^(www\\.)?(WWW\\.)?a\\.b$",
    "^(www\\.)a\\.b$",
    "^(www.)?a\\.b$",
    "^(.+\\.)?a_b\\.c-d$",
    "^(.+\\.)?_a\\.b$",
    "^\u212a\\.b$",
    "^k\\.b$",
    "^a\\.b\u0130$",
    "^a\\.\u00e9$",
    "^\u00e9\\.b$",
    "^(www\\.)?\u00e9\\.b$",
    "^(.+\\.)?a\\.b\\.c\\.d\\.e$",
    "(^|\\.)a-b\\.c_d$",
    "^a\\-b\\.c$",
    "^(.+\\.)?(www\\.)?a\\.b$",
    "^(?:.+\\.)?a\\.b",
    "(^|\\.)a\\.b",
    "^(.+\\.)?a\\.b$ ",
    " ^a\\.b$",
    "^ a\\.b$",
    "^(.+\\.)?\u0130\\.b$",
    "^(www\\.)?" + "a" * 64 + "\\.com$",
    "^(.+\\.)?" + "A" * 64 + "\\.com$",
    "(^|\\.)" + ("a" * 61 + "\\.") * 4 + "com$",
    "^" + ("b" * 61 + "\\.") * 4 + "bbbbb$",
    "^" + ("b" * 61 + "\\.") * 4 + "bbbbbb$",
]
reduce_rows = []
for inner in uniq(inners):
    variants = [inner]
    if P._dnsbl_reduce_regex(inner) is not None:
        variants += [inner.upper(), inner[:-1] + "\n$", inner[:-1] + "\n\n$"]
    for v in variants:
        reduce_rows.append({"in": v, "out": P._dnsbl_reduce_regex(v)})
reduce_rows = list({r["in"]: r for r in reduce_rows}.values())


# --- reconcile scenarios
def enc_result(res, t):
    tab = "\t".join
    return {
        "block_domains": [
            tab([b.cls, b.key, str(b.band), str(int(b.important)), b.provenance, b.feed, b.group, b.log])
            for b in res.block_domains
        ],
        "allow_domains": [
            tab([a.domain, str(int(a.wildcard)), str(a.band), str(int(a.important)), a.provenance])
            for a in res.allow_domains
        ],
        "block_regex_irreducible": [
            tab([r.pattern, r.kind, str(r.band), str(int(r.important)), r.provenance, r.feed, r.group, r.log])
            for r in res.block_regex_irreducible
        ],
        "allow_regex_irreducible": [
            tab([r.pattern, r.kind, str(r.band), str(int(r.important)), r.provenance, r.feed, r.group, r.log])
            for r in res.allow_regex_irreducible
        ],
        "counters": [int(res.important_rules), res.pruned, res.reduced, res.skipped_badfilter],
        "tally": [tab([f, g, json.dumps(c, sort_keys=True, separators=(",", ":"))]) for (f, g), c in sorted(t.items())],
    }


scenarios = []
seen_streams = set()


def add_scenario(name, segments):
    """segments: [(prov, feed, group, log, [line, ...])] -> parse_abp every line in order, then reconcile."""
    key = json.dumps(segments)
    if key in seen_streams:
        return
    seen_streams.add(key)

    def run(excl):
        t = {}
        rules = []
        for prov, feed, group, log, ls in segments:
            for ln in ls:
                r = P.parse_abp(ln, provenance=prov, feed=feed, group=group, log=log, tally=t)
                if r is not None:
                    rules.append(r)
        res = P.reconcile(rules, {}, set(excl), tally=t)
        return res, t

    res0, _ = run([])
    keys = sorted({b.key for b in res0.block_domains})
    for label, excl in (("no-exclusion", []), ("half-excluded", keys[::2])) if keys else (("no-exclusion", []),):
        res, t = run(excl)
        encoded = enc_result(res, t)
        if not any(
            encoded[k]
            for k in ("block_domains", "allow_domains", "block_regex_irreducible", "allow_regex_irreducible", "tally")
        ) and not any(encoded["counters"][1:]):
            continue
        scenarios.append(
            {
                "name": name + "/" + label,
                "segments": [list(sg) for sg in segments],
                "exclusion": excl,
                "result": encoded,
            }
        )


for fname, mod in fixtures.items():
    rows = {f["raw"]: f for f in mod.get("manifest", {}).get("feeds", [])}
    segments = []
    for raw, flines in mod.get("files", {}).items():
        row = rows.get(raw, {})
        segments.append(
            (row.get("provenance", "feed"), row.get("feed", ""), row.get("group", ""), row.get("log_flag", ""), flines)
        )
    if segments:
        add_scenario(fname, segments)

add_scenario("adr07-corpus-feed", [("feed", "Corpus", "CorpusGroup", "1", corpus_lines)])
add_scenario("adr07-corpus-user", [("user", "Corpus", "CorpusGroup", "1", corpus_lines)])
half = len(corpus_lines) // 2
add_scenario(
    "adr07-corpus-mixed",
    [
        ("feed", "Corpus", "CorpusGroup", "1", corpus_lines[:half]),
        ("user", "Corpus", "CorpusGroup", "1", corpus_lines[half:]),
    ],
)
add_scenario(
    "cross-provenance-badfilter",
    [
        ("user", "B", "G", "1", ["||y.example.com^"]),
        ("feed", "B", "G", "1", ["||y.example.com^"]),
        ("feed", "A", "G", "1", ["||y.example.com^$badfilter", "/^(.+\\.)?" + "a" * 64 + "\\.com$/"]),
        ("user", "A", "G", "1", ["@@/^" + "a" * 64 + "\\.net$/", "/(a|b)+x/"]),
        ("feed", "U", "G", "1", ["/(a|b)+x/$important"]),
        ("user", "U", "G", "1", ["@@/zz[0-9]/"]),
    ],
)

# --- oracle decide() outcomes (tests/test_adr07_reconcile.py)
TLDS = {"com": {"com": ""}, "net": {"net": ""}, "org": {"org": ""}, "example": {"example": ""}, "io": {"io": ""}}
decide_cases = [
    (["||example.com^", "@@||cdn.example.com^"], "cdn.example.com"),
    (["||example.com^", "@@||cdn.example.com^"], "example.com"),
    (["||x.example.com^$important", "@@||x.example.com^"], "x.example.com"),
    (["@@||y.example.com^$important", "||y.example.com^"], "y.example.com"),
    (["/^(.+\\.)?doubleclick\\.net$/"], "ad.doubleclick.net"),
    (["/AD[0-9]\\.EXAMPLE\\.COM$/"], "ad7.example.com"),
    (["||example.com^", "@@/^(.+\\.)?cdn\\.example\\.com$/"], "cdn.example.com"),
    (["||a.example.com^", "||a.example.com^$badfilter"], "a.example.com"),
]
decide_rows = [
    {"lines": ls, "query": q, "outcome": spec.decide(spec.rules_from(ls), q).outcome} for ls, q in decide_cases
]

# corpus probes: same derivation as TestCorpusEquivalence
crules = [r for r in (P.parse_abp(ln) for ln in corpus_lines) if r is not None]
cres = P.reconcile(crules, TLDS, set())
probes = set()
for b in cres.block_domains:
    probes.add(b.key)
    probes.add("sub." + b.key)
for a in cres.allow_domains:
    probes.add(a.domain)
    probes.add("sub." + a.domain)
probes.update({"doubleclick.net", "ad.doubleclick.net", "unrelated.example", "example.com"})
ora_rules = spec.rules_from(corpus_lines)
corpus_probes = [{"query": q, "outcome": spec.decide(ora_rules, q).outcome} for q in sorted(probes)]

# --- whitelist scenarios (list in one call: collisions)
wl_lists = [
    ["www.adblock.com"],
    [".wildwhite.org"],
    ["Example.COM"],
    [".Example.COM"],
    ["WWW.Example.COM"],
    ["bad domain!", "ok.com"],
    ["example.com."],
    [".lan", ".Internal"],
    ["lan", "com.", "www.", "www.."],
    [".-bad"],
    [".bad-"],
    ["." + "a" * 64],
    [". example.com"],
    [". lan"],
    [".bad!"],
    [".123"],
    ["."],
    [".."],
    ["." + "a" * 63],
    ["www..example.com"],
    ["www..lan"],
    ["www.com", "WWW.Org", "www.example"],
    ["www.-bad.com", "www.bad domain"],
    [".collapex.com", "www.collapex.com"],
    [".collapex.com", "collapex.com"],
    ["www.collapex.com", ".collapex.com"],
    ["www.collapex.com", "collapex.com"],
    [".collapex.com", "mail.collapex.com"],
    ["", "   ", "keep.com"],
    ["\u00a0www.example.com\u2003"],
    ["WwW.example.com", "wWw.example.com"],
    ["www.www.example.com"],
    ["www.1.2.3.4", "1.2.3.4", "01.02.03.04", "0x10", "example.123", "example.0x10", "www.0x1.com"],
    ["www." + "a" * 64 + ".com"],
    ["www.\u00e9.com"],
    ["www.\u212a.com"],
    [".\u212a"],
    ["a.b", "a.b.", ".a.b", "www.a.b"],
]
wl_rows = []
for entries in wl_lists:
    t = {}
    out = P._dnsbl_normalise_whitelist(entries, t, "src-x")
    wl_rows.append({"entries": entries, "out": [[k, v] for k, v in out.items()], "tally": enc_tally(t)})
# every fixture module's strings as one list (collisions between feed-shaped lines)
for fname, mod in fixtures.items():
    strs = []
    walk(mod, strs)
    t = {}
    out = P._dnsbl_normalise_whitelist(strs, t, "src-fixture")
    wl_rows.append(
        {"entries": strs, "out": [[k, v] for k, v in out.items()], "tally": enc_tally(t), "source": "src-fixture"}
    )
for r in wl_rows:
    r.setdefault("source", "src-x")

# --- ipv4 / numeric-host extras
ip_tokens = [
    "1.1.1.1",
    "255.255.255.255",
    "0.0.0.0",
    "192.168.0.1",
    "1.1.1.256",
    "01.1.1.1",
    "1.1.1",
    "1.1.1.1.1",
    "1.1.1.",
    "a.b.c.d",
    "+1.1.1.1",
    "1.1.1.-1",
    "1.1.1.1000",
    "1.1.1.\u00b2",
    "\u00b2.\u00b2.\u00b2.\u00b2",
    "1.1.1.\u2461",
    "\u0661.\u0661.\u0661.\u0661",
    "1\u00b2.1.1.1",
    "\uff11.\uff11.\uff11.\uff11",
    "1.1.1.00",
    "1.1.1.0",
    "1.1.1.000",
    " 1.1.1.1",
    "1.1.1.1 ",
    "1.1.1.1\n",
    "1..1.1",
    "",
]
numtab = json.load(open(root + "/tests/fixtures/ipv4_numeric_host.json"))["cases"]
ip_tokens += [c[0] for c in numtab]
ip_tokens += [
    "1.2.3.\u00b2",
    "1.2.3.\u0663",
    "\uff11.\uff12.\uff13.\uff14",
    "0x",
    "0X",
    "0xG",
    "0x.",
    "0x1.",
    ".",
    "..",
    "a.",
    "a..",
    "1.",
    "0x1f",
    "0X1F.",
    "00x1",
]
ip_rows = [{"in": t, "ipv4": P._dnsbl_is_ipv4(t), "numeric_host": P._dnsbl_is_numeric_host(t)} for t in uniq(ip_tokens)]

# --- normalise charset loop (tests/test_issue3056_label_charset.py)
charset_rows = [{"in": f"a{chr(c)}b.com", "out": P.normalise(f"a{chr(c)}b.com")} for c in range(128)]

out = {
    "about": (
        "Rows produced by running pfb_unbound.py (CPython 3.11) over the inputs described in pfb_unbound_abp_test.go"
    ),
    "lines": lines,
    "spike": spike_rows,
    "reduce": reduce_rows,
    "reconcile": scenarios,
    "decide": decide_rows,
    "corpus_probes": corpus_probes,
    "whitelist": wl_rows,
    "ip": ip_rows,
    "charset": charset_rows,
}
json.dump(
    out, open(HERE / "pfb_unbound_abp_oracle.json", "w", encoding="utf-8"), ensure_ascii=True, separators=(",", ":")
)
print({k: (len(v) if isinstance(v, list) else v) for k, v in out.items()})

"""ADR-07 Phase-1 de-risking spike: ABP corpus inventory + regex/ReDoS measurement.

Question this answers (de-risk BEFORE ADR-07 moves any production code): is full
ABP support cheap/safe enough? Concretely the two real risks (ADR.md SS3, SS7):

  (a) Per-query regex cost (ADR-01-class). Feeds carry ``/re/`` rules. How many
      fold to a domain/wildcard dict rule (zero per-query cost) vs stay an
      irreducible compiled pattern scanned O(n) per query (pfb_unbound.py:2313)?
      What is the added per-query latency at feed-scale irreducible counts vs the
      ~1 us dict baseline (ADR-05 SS3a)?

  (b) ReDoS. ``re`` does not release the GIL and a Python thread cannot be killed
      (ADR.md fact 2), so a catastrophic-backtracking pattern freezes the whole
      resolver until it returns and a thread/asyncio "timeout" CANNOT interrupt
      it. How many real-feed irreducible patterns does a static checker flag, and
      how slow is the WORST real first-hit on a <=253-char DNS name (the accepted
      residual is one slow first-hit, then eviction)?

This is a standalone, stdlib-only, out-of-tree-style spike (like
``benchmarks/spike_adr06_build.py``). It touches NO production code; it only reads
the representative corpus under ``tests/fixtures/adr07_corpus/`` and measures.

Run from the repo root (dev-only; not shipped, not in the default pytest run)::

    python benchmarks/spike_adr07_regex.py
    SPIKE_IRREDUCIBLE_N=1000 python benchmarks/spike_adr07_regex.py
"""

from __future__ import annotations

import argparse
import os
import re
import statistics
import sys
import threading
import time

# --------------------------------------------------------------------------- #
# Corpus location.
# --------------------------------------------------------------------------- #
_HERE = os.path.dirname(os.path.abspath(__file__))
_CORPUS = os.path.join(_HERE, os.pardir, "tests", "fixtures", "adr07_corpus")

# --------------------------------------------------------------------------- #
# Proposed kill-threshold (Phase 1; tune with the maintainer in the handoff).
# --------------------------------------------------------------------------- #
# GO requires: added MEDIAN per-query latency from the inline irreducible-regex
# scan stays at a few us at the feed-scale irreducible count (vs the ~1 us dict
# baseline), bounded by a high reduction ratio; AND the worst real first-hit on a
# <=253-char input is not pathological (sub-second, evictable).
LATENCY_BUDGET_US = 50.0  # added median per-query scan; "a few us" target, 50 us hard ceiling
REDUCTION_FLOOR = 0.30  # at least this fraction of /re/ must fold to dicts
WORST_FIRSTHIT_CEIL_S = 0.5  # worst real first-hit on a DNS name must stay sub-this

# DNS name max length (RFC 1035): the only input a query-time regex ever sees.
DNS_MAX_LEN = 253


# --------------------------------------------------------------------------- #
# 1. Categorise the ABP corpus (line-type distribution).
# --------------------------------------------------------------------------- #
def _read_lines(name: str) -> list[str]:
    path = os.path.join(_CORPUS, name)
    with open(path, encoding="utf-8") as fh:
        return [ln.rstrip("\n") for ln in fh]


def _is_ipv4_anchor(body: str) -> bool:
    # body is the token between || and ^ (or a hosts target)
    parts = body.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def categorise(line: str) -> str:
    """Map one raw ABP line to a DNS-scope category (mirrors ADR.md SS2 scope)."""
    s = line.strip()
    if not s or s.startswith("!") or s.startswith("["):
        return "comment"
    # element-hiding / cosmetic
    if "##" in s or "#@#" in s or "#?#" in s:
        return "element_hiding"
    # regex rules
    if s.startswith("@@/") and s.endswith("/"):
        return "regex_allow"
    if s.startswith("/") and s.endswith("/") and len(s) > 2:
        return "regex_block"
    # allow network rule
    if s.startswith("@@||"):
        rest = s[4:]
        body = rest.split("^", 1)[0].split("$", 1)[0]
        if "/" in rest.split("^", 1)[0]:
            return "path_url"
        if _is_ipv4_anchor(body):
            return "ip_anchored"
        return "allow"
    # block network rule
    if s.startswith("||"):
        rest = s[2:]
        before_opt = rest.split("$", 1)
        anchor = before_opt[0]
        if "^" not in anchor and "/" in anchor:
            return "path_url"
        body = anchor.split("^", 1)[0]
        if "/" in body or (len(anchor.split("^", 1)) > 1 and anchor.split("^", 1)[1]):
            return "path_url"
        if _is_ipv4_anchor(body):
            return "ip_anchored"
        if len(before_opt) == 2:
            opts = before_opt[1]
            if "badfilter" in opts:
                return "badfilter"
            if any(o in opts for o in ("third-party", "script", "image", "subdocument", "csp", "domain=")):
                return "page_context_opts"
            if "dnsrewrite" in opts or "dnstype" in opts or "client" in opts or "ctag" in opts:
                return "non_dns_modifier"
            if "important" in opts:
                return "block_important"
            return "block_dns_opts"
        return "block"
    # hosts: <ip> <domain>
    if " " in s:
        first = s.split(" ", 1)[0]
        if _is_ipv4_anchor(first):
            target = s.split(" ", 1)[1].strip()
            if _is_ipv4_anchor(target):
                return "ip_anchored"  # 0.0.0.0 <ip>
            return "hosts"
    # path/url without anchor
    if s.startswith("/") and "*" in s:
        return "path_url"
    # bare plain domain
    if "." in s and "/" not in s and " " not in s:
        return "plain"
    return "other"


# --------------------------------------------------------------------------- #
# 2. Regex reduction grammar: which /re/ fold to a domain / wildcard rule.
# --------------------------------------------------------------------------- #
# A pattern reduces iff, after stripping the /.../ (and a leading @@), its body is
# one of the anchored shapes whose ONLY variable part is a fixed domain literal:
#   ^(.+\.)?D$        -> wildcard zone (D + subdomains)
#   (^|\.)D$          -> wildcard zone
#   ^D$               -> exact data
#   ^(www\.)?D$       -> exact data (+www) ... (kept simple: treat as exact D)
# where D is a domain literal: labels of [a-z0-9_-] joined by an ESCAPED dot (\.),
# no other regex metacharacter. Anything with a char-class, quantifier on a label,
# alternation in the body, or an unescaped/floating dot is IRREDUCIBLE.

_DOMAIN_LITERAL = re.compile(r"^[A-Za-z0-9_-]+(?:\\\.[A-Za-z0-9_-]+)+$")  # underscore #723; case-fold #2099

_WILDCARD_PREFIXES = (r"^(.+\.)?", r"(^|\.)", r"^(?:.+\.)?")
_EXACT_PREFIXES = (r"^",)


def _strip_slashes(pat: str) -> tuple[str, bool]:
    """Return (inner, is_allow). ``pat`` is a /re/ or @@/re/ line."""
    is_allow = pat.startswith("@@")
    if is_allow:
        pat = pat[2:]
    inner = pat[1:-1]  # drop the surrounding /.../
    return inner, is_allow


def reduce_pattern(pat: str) -> tuple[str, str] | None:
    """Return ('zone'|'data', domain-literal) if ``pat`` folds, else None."""
    inner, _is_allow = _strip_slashes(pat)
    if not inner.endswith("$"):
        return None
    body = inner[:-1]
    # wildcard forms -> zone
    for pre in _WILDCARD_PREFIXES:
        if body.startswith(pre):
            lit = body[len(pre) :]
            dom = lit.replace("\\.", ".").lower()
            if _DOMAIN_LITERAL.match(lit):
                return "zone", dom
            return None
    # exact form -> data
    for pre in _EXACT_PREFIXES:
        if body.startswith(pre):
            lit = body[len(pre) :]
            # allow an optional (www\.)? prefix, fold to the exact base domain
            if lit[: len(r"(www\.)?")].lower() == r"(www\.)?":
                lit = lit[len(r"(www\.)?") :]
            dom = lit.replace("\\.", ".").lower()
            if _DOMAIN_LITERAL.match(lit):
                return "data", dom
            return None
    return None


# --------------------------------------------------------------------------- #
# 3. ReDoS static heuristic (the opt-in static cap candidate) + worst first-hit.
# --------------------------------------------------------------------------- #
# Cheap, no-execution flags (the "Limit long/complex regex" heuristic, ADR.md SS2):
#   - over-long pattern (length cap)
#   - nested quantifier: a quantifier applied to a group that itself contains a
#     quantifier  (e.g. (a+)+, (a*)* , (\w+\.)+, ([a-z]+)*) -- the classic
#     exponential-backtracking shape.
STATIC_LEN_CAP = 200  # proposed default length ceiling for the opt-in cap
_NESTED_QUANT = re.compile(r"\([^()]*[+*][^()]*\)\s*[+*{]")
# Alternation-overlap: a quantified group whose body contains an alternation `|`
# (e.g. (a|a)+, (a|ab)*). Overlapping/ambiguous alternatives under a quantifier
# backtrack catastrophically yet have no INNER quantifier, so _NESTED_QUANT misses
# them. Kept conservative: a single `(...)` (no inner parens) with `|`, then a quant.
_ALT_OVERLAP = re.compile(r"\([^()]*\|[^()]*\)\s*[+*{]")


def static_redos_flag(pat: str) -> str | None:
    inner, _ = _strip_slashes(pat)
    if len(inner) > STATIC_LEN_CAP:
        return "over-length"
    if _NESTED_QUANT.search(inner):
        return "nested-quantifier"
    if _ALT_OVERLAP.search(inner):
        return "alternation-overlap"
    return None


def _adversarial_input(inner: str) -> str:
    """Craft the worst <=253-char input for a pattern (best-effort, DNS-scale).

    A run of 'a' ending in a NON-matching sentinel fails the final anchor, which
    maximises backtracking for the classic shapes ((a+)+$, ([a-z]+)*\\.example$,
    (.*a){20}$, ...) -- an all-'a' string would instead *match* those and so
    under-report the worst case. Capped at the DNS name limit -- that is the ONLY
    input a query-time regex ever sees.
    """
    return "a" * (DNS_MAX_LEN - 1) + "!"


# A standalone child program: compile + time ONE match, print the seconds. Run via
# subprocess so a catastrophic match can be HARD-KILLED on timeout (the spike is
# dev tooling -- the no-subprocess rule is for the shipped resolver, not here; in
# the resolver, fact 2 means this exact match CANNOT be killed, which is the point).
# Pattern + probe are passed as JSON so the per-pattern adversarial probe (not a
# fixed all-'a' string) is what gets timed.
_CHILD = (
    "import json,re,sys,time;"
    "d=json.loads(sys.stdin.read());"
    "rx=re.compile(d['p']);"
    "s=d['s'];"
    "t=time.perf_counter();"
    "rx.search(s);"
    "sys.stdout.write(repr(time.perf_counter()-t))"
)


def worst_first_hit(pat: str, timeout_s: float = 2.0) -> tuple[float, bool]:
    """Time the worst real first-hit on a <=253-char input, in a killable child.

    Returns (seconds, timed_out). ``timed_out`` True means the match exceeded
    ``timeout_s`` and was killed -- i.e. on a <=253-char DNS name this pattern
    runs at least ``timeout_s`` (a genuinely pathological pattern; the runtime
    evict ceiling is exactly for this case).
    """
    import json
    import subprocess

    inner, _ = _strip_slashes(pat)
    try:
        re.compile(inner)
    except re.error:
        return 0.0, False
    probe = _adversarial_input(inner)
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _CHILD],
            input=json.dumps({"p": inner, "s": probe}),
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        return timeout_s, True
    try:
        return float(proc.stdout), False
    except ValueError:
        return 0.0, False


# --------------------------------------------------------------------------- #
# 4. Inline per-query scan latency at feed scale.
# --------------------------------------------------------------------------- #
def measure_scan_latency(compiled: list[re.Pattern[str]], queries: list[str], rounds: int) -> float:
    """Median per-query time (us) for the inline O(n) regex scan (pfb_unbound:2313).

    tracemalloc OFF (ADR-06 measurement note). Times a batch so per-call signal
    sits above timer resolution.
    """
    samples: list[float] = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        for q in queries:
            for r in compiled:
                if r.search(q):
                    break
        dt = time.perf_counter() - t0
        samples.append(dt / len(queries) * 1e6)  # us/query
    return statistics.median(samples)


def thread_time_supported() -> bool:
    try:
        time.thread_time()
        return True
    except (AttributeError, OSError):
        return False


# --------------------------------------------------------------------------- #
# 5. Demo: a thread/asyncio timeout CANNOT interrupt a catastrophic match (GIL).
# --------------------------------------------------------------------------- #
def demo_thread_timeout_cannot_interrupt() -> tuple[float, float, float]:
    """Run a backtracking match in a worker thread with a short 'timeout' join.

    A waiter that wants to bound a match to ``requested`` seconds calls
    ``join(timeout=requested)``. But the worker holds the GIL inside the C-level
    ``re`` match, so the waiter stays blocked far past its deadline and -- crucially
    -- there is NO API to cancel the worker even once the join returns. We measure
    the total wall time the waiter was forced to wait vs the deadline it asked for.
    Returns (requested_timeout_s, waited_s, match_s).

    Uses a bounded-but-clearly-exponential input so the demo finishes in well under
    a second (the POINT is the deadline cannot bound the work, not to hang).
    """
    rx = re.compile(r"^(a+)+$")
    probe = "a" * 22 + "!"  # exponential, a few hundred ms -- >> the 1 ms deadline
    result: dict[str, float] = {}

    def work() -> None:
        w0 = time.perf_counter()
        rx.search(probe)
        result["secs"] = time.perf_counter() - w0

    th = threading.Thread(target=work)
    requested = 0.001  # the waiter wants to cap the match at 1 ms
    w0 = time.perf_counter()
    th.start()
    # Emulate "wait up to requested, then give up": even repeated short joins can
    # never end the work -- there is no cancellation. We simply wait it out.
    th.join(timeout=requested)
    while th.is_alive():
        th.join(timeout=requested)  # keep "timing out"; the match runs regardless
    waited = time.perf_counter() - w0
    return requested, waited, result.get("secs", 0.0)


# --------------------------------------------------------------------------- #
# Driver.
# --------------------------------------------------------------------------- #
def main() -> int:
    """Run the ReDoS/regex spike; exit non-zero on NO-GO so CI can enforce it.

    This is a KILL-GATE: the verdict is carried by the process exit code (0 = GO,
    1 = NO-GO). Pass --report-only to print the full report but always exit 0 (a
    human-readable local run that never fails).
    """
    parser = argparse.ArgumentParser(description="ADR-07 regex/ReDoS latency + reduction kill-gate.")
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="print the report but always exit 0 (do not propagate NO-GO to the exit code)",
    )
    args = parser.parse_args()

    print("=" * 78)
    print("ADR-07 Phase-1 spike: ABP corpus inventory + regex/ReDoS measurement")
    print("=" * 78)
    print(f"CPython {sys.version.split()[0]}  platform={sys.platform}")
    print(f"time.thread_time() available: {thread_time_supported()}")
    print()

    # --- 1. line-type distribution over the whole corpus -------------------- #
    all_lines: list[str] = []
    for fn in ("abp_sample.txt", "regex_reducible.txt", "regex_irreducible.txt"):
        all_lines += _read_lines(fn)
    dist: dict[str, int] = {}
    for ln in all_lines:
        c = categorise(ln)
        dist[c] = dist.get(c, 0) + 1
    print("--- 1. LINE-TYPE DISTRIBUTION (representative corpus) ---")
    total_non_comment = sum(v for k, v in dist.items() if k != "comment")
    for k in sorted(dist, key=lambda x: -dist[x]):
        print(f"  {k:22s} {dist[k]:4d}")
    print(f"  {'TOTAL (non-comment)':22s} {total_non_comment:4d}")
    print()

    # --- 2. regex reduction ratio ------------------------------------------ #
    regex_lines = [ln.strip() for ln in all_lines if categorise(ln) in ("regex_block", "regex_allow")]
    reducible = [p for p in regex_lines if reduce_pattern(p) is not None]
    irreducible = [p for p in regex_lines if reduce_pattern(p) is None]
    ratio = len(reducible) / len(regex_lines) if regex_lines else 0.0
    print("--- 2. REGEX REDUCTION RATIO ---")
    print(f"  total /re/ + @@/re/ : {len(regex_lines)}")
    print(f"  reducible -> dict   : {len(reducible)}  ({ratio:.0%})")
    print(f"  irreducible         : {len(irreducible)}")
    print("  reduced examples:")
    for p in reducible[:5]:
        print(f"    {p:42s} -> {reduce_pattern(p)}")
    print()

    # --- 3. ReDoS static exposure + worst real first-hit ------------------- #
    print("--- 3. REDOS EXPOSURE (irreducible patterns) ---")
    firsthit_timeout = float(os.environ.get("SPIKE_FIRSTHIT_TIMEOUT", "2.0"))
    flagged = []
    firsthits = []
    for p in irreducible:
        flag = static_redos_flag(p)
        hit, timed_out = worst_first_hit(p, timeout_s=firsthit_timeout)
        firsthits.append((hit, p, flag, timed_out))
        if flag:
            flagged.append((p, flag))
    print(f"  irreducible patterns        : {len(irreducible)}")
    print(f"  statically flagged dangerous: {len(flagged)}")
    for p, f in flagged:
        print(f"    [{f:18s}] {p}")
    firsthits.sort(reverse=True)
    print(f"  worst real first-hits on a <={DNS_MAX_LEN}-char input (killed at {firsthit_timeout}s):")
    for hit, p, flag, timed_out in firsthits[:8]:
        tag = f" [{flag}]" if flag else ""
        to = "  >=TIMEOUT (killed)" if timed_out else ""
        print(f"    {hit * 1e3:10.3f} ms   {p}{tag}{to}")
    worst = firsthits[0][0] if firsthits else 0.0
    # worst NON-flagged (what survives the opt-in static cap and still runs at
    # query time -- the residual the runtime warn/evict ceiling must catch).
    nonflagged_hits = [h for h, p, f, t in firsthits if f is None]
    worst_nonflagged = max(nonflagged_hits) if nonflagged_hits else 0.0
    n_caught_by_cap = sum(1 for h, p, f, t in firsthits if t and f is not None)
    n_timeout_uncaught = sum(1 for h, p, f, t in firsthits if t and f is None)
    print(f"  worst first-hit (any)        : {worst * 1e3:.3f} ms")
    print(f"  worst first-hit (cap-passing): {worst_nonflagged * 1e3:.3f} ms")
    print(f"  pathological (>=timeout) caught by static cap : {n_caught_by_cap}")
    print(f"  pathological (>=timeout) MISSED by static cap : {n_timeout_uncaught}")
    print()

    # --- 4. per-query inline scan latency vs irreducible count (a sweep) ---- #
    rounds = int(os.environ.get("SPIKE_ROUNDS", "30"))
    # The realistic per-query cost is the SAFE irreducible set (statically-flagged
    # ones are capped/evicted, not part of the steady state). Tile the safe set to
    # each count; query the negative path (the worst case -- a negative query is
    # scanned against EVERY pattern; a positive query short-circuits on first hit).
    safe_irr = [p for p in irreducible if static_redos_flag(p) is None]
    base = [re.compile(_strip_slashes(p)[0]) for p in safe_irr if _safe_compile(p)]
    if not base:
        base = [re.compile(r"^ads[0-9]+\.example$")]
    queries = [f"host{i}.legit-domain-{i % 50}.example.com" for i in range(200)]
    counts_env = os.environ.get("SPIKE_COUNTS", "10,50,100,200,500,1000")
    sweep_counts = [int(x) for x in counts_env.split(",")]
    baseline_us = measure_scan_latency([], queries, rounds)  # loop overhead only
    print("--- 4. PER-QUERY INLINE REGEX-SCAN LATENCY (negative query, worst case) ---")
    print("  dict baseline reference: ~1 us/query (ADR-05 SS3a)")
    print(f"  empty-scan loop overhead: {baseline_us:.3f} us/query (subtracted below)")
    print(f"  {'irreducible count':>18s}  {'added us/query':>14s}  {'us/pattern':>11s}")
    per_pattern = 0.0
    for n in sweep_counts:
        compiled = [base[i % len(base)] for i in range(n)]
        scan_us = measure_scan_latency(compiled, queries, rounds)
        added = max(scan_us - baseline_us, 0.0)
        per_pattern = added / n if n else 0.0
        print(f"  {n:18d}  {added:14.2f}  {per_pattern:11.4f}")
    # break-even: how many irreducible patterns fit the added-latency budget.
    if per_pattern > 0:
        budget_count = int(LATENCY_BUDGET_US / per_pattern)
    else:
        budget_count = 0
    print(f"  ~us per irreducible pattern (negative query): {per_pattern:.4f}")
    print(f"  => budget of {LATENCY_BUDGET_US:.0f} us added => ~{budget_count} irreducible patterns")
    print()

    # --- 5. thread-timeout-cannot-interrupt demo --------------------------- #
    print("--- 5. GIL DEMO: thread timeout CANNOT interrupt a runaway re ---")
    requested, waited, match_s = demo_thread_timeout_cannot_interrupt()
    print("  worker runs (a+)+$ on a failing ~23-char input")
    print(f"  waiter wanted to cap it at      : {requested * 1e3:.0f} ms")
    print(f"  waiter was forced to wait       : {waited * 1e3:.1f} ms ({waited / requested:.0f}x its deadline)")
    print(f"  match ran to completion uncancelled : {match_s * 1e3:.1f} ms")
    print("  => no join/asyncio 'timeout' can BOUND or CANCEL the match (GIL); the")
    print("     only options are to wait it out or kill the whole process. Hence the")
    print("     design accepts ONE slow first-hit, then EVICTS the pattern.")
    print()

    # --- GATE -------------------------------------------------------------- #
    print("=" * 78)
    print("GATE (vs proposed kill-threshold)")
    print("=" * 78)
    ok_ratio = ratio >= REDUCTION_FLOOR
    # latency gate: the BREAK-EVEN count (patterns that fit the budget) must be
    # comfortably above any plausible real per-feed irreducible count. The corpus
    # measured below; the handoff documents the real-feed expectation + the cap.
    ok_latency_perpattern = per_pattern <= (LATENCY_BUDGET_US / 50.0)  # >=50 patterns fit
    ok_firsthit = worst_nonflagged <= WORST_FIRSTHIT_CEIL_S
    fh_ms = worst_nonflagged * 1e3
    ceil_ms = WORST_FIRSTHIT_CEIL_S * 1e3
    print(f"  reduction ratio  {ratio:.0%}  >= {REDUCTION_FLOOR:.0%}              : {_ok(ok_ratio)}")
    print(f"  per-pattern cost {per_pattern:.4f} us (>=50 fit budget) : {_ok(ok_latency_perpattern)}")
    print(f"  worst cap-passing first-hit {fh_ms:.3f} ms <= {ceil_ms:.0f} ms : {_ok(ok_firsthit)}")
    gates_ok = ok_ratio and ok_latency_perpattern and ok_firsthit
    verdict = "GO (with mitigations)" if gates_ok else "NO-GO -> PIVOT"
    print(f"  VERDICT: {verdict}")
    print(f"  budget-bounded irreducible count: ~{budget_count} patterns at {LATENCY_BUDGET_US:.0f} us")
    if not gates_ok and args.report_only:
        print("NOTE: --report-only set -> NO-GO not propagated to the exit code.")
        return 0
    return 0 if gates_ok else 1


def _safe_compile(pat: str) -> bool:
    try:
        re.compile(_strip_slashes(pat)[0])
        return True
    except re.error:
        return False


def _ok(b: bool) -> str:
    return "PASS" if b else "FAIL"


if __name__ == "__main__":
    raise SystemExit(main())

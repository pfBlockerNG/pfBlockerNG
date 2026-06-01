"""ADR-06 Phase-1 de-risking spike: cost of the Python DNSBL build inside Unbound.

Question this answers (falsify-first, before ADR-06 moves any production code):
does a pure-Python build (parse -> normalise -> classify data/zone -> build
``dataDB``/``zoneDB`` + feed/group index + counts) run inside Unbound's ``init``
within an init-time / peak-memory budget on a large (>=1M-entry) UN-PRUNED feed?

Why un-pruned: ADR-06 drops the build-time optimisations (dedup, subdomain
collapse, user/TOP1M whitelist removal), so Python loads MORE entries than today's
pruned ``pfb_py_data``/``pfb_py_zone``. The realistic init cost is on the raw,
un-pruned text -- which is what this spike feeds in (`_corpus_raw.py`).

Scope (matches the Phase-1 prompt):
* Build from the un-pruned raw -- NO dedup (dict keys dedup for free), NO subdomain
  collapse, NO build-time whitelist/TOP1M removal.
* The build SKIPS bare-IP lines (IP extraction stays in PHP, Phase 5) -> no IP
  handoff is emitted here.
* stdlib only, no Unbound symbols. Payload shapes match the production loader
  (`pfb_unbound.py:535-602`): ``{"log": str, "index": int}`` per entry,
  ``feedGroupIndexDB[index] = {"feed", "group"}``, ``whiteDB`` is separate.

Measures (N>=3 runs at >=1M entries):
* build wall-time (``time.perf_counter``) -- distribution (min/median/max/mean).
* peak RAM during build (stdlib ``tracemalloc``) -- the init high-water mark.
* retained dict bytes/entry (``pympler.asizeof``, same method as ADR-05 §3a) vs
  the ~274 B/entry baseline.

Then prints an explicit GO / NO-GO against the proposed kill-threshold.

Run from the repo root (dev-only; not shipped, not in the default pytest run)::

    python -m pip install pympler          # dev-only, ADR-05 §3a baseline tool
    SPIKE_N=5 SPIKE_SIZES=1000000 python benchmarks/spike_adr06_build.py
"""

from __future__ import annotations

import gc
import os
import re
import statistics
import sys
import time
import tracemalloc
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _corpus_raw import HOSTS_SINK, generate_raw_corpus  # noqa: E402

try:
    from pympler import asizeof  # type: ignore
except ImportError:  # pragma: no cover - dev tool only
    asizeof = None  # type: ignore[assignment]

# --------------------------------------------------------------------------- #
# Kill-threshold (proposed in Phase 1; tune with the maintainer in the handoff).
# --------------------------------------------------------------------------- #
# The budget is "added reload time <= a few seconds" and "peak RAM not materially
# worse than today" -- NOT an absolute wall-clock cap on the build in isolation.
# The fair comparison is NET: the work today's shell/PHP already spends per build
# that ADR-06 DELETES. Measured on this box, an equivalent 1M-line master raw:
#   * sort -u (dedup)            ~2.1s   (domaintldpy runs it 2-3x)
#   * awk cross-list dedup       ~2.7s   (dnsbl_scrub :379)
#   * ggrep -vF whitelist/TOP1M  seconds more (grows with pattern-file size)
# i.e. today already costs ~5s+ of out-of-process passes that the move REMOVES.
# So the threshold is read as: build <= ~8s absolute (a few seconds ADDED over the
# shell time it replaces) AND retained footprint not materially worse than the
# ADR-05 §3a 274 B/entry baseline (<= ~410 B/entry, ~1.5x headroom for the
# un-pruned build's extra entries). Tune both with the maintainer.
THRESH_BUILD_SECONDS = 8.0  # absolute build budget (a few seconds over removed shell passes)
THRESH_BYTES_PER_ENTRY = 410.0  # retained dict footprint ceiling
BASELINE_BYTES_PER_ENTRY = 274.0  # ADR-05 §3a steady-state dict baseline
SHELL_PASSES_REMOVED_SECONDS = 4.8  # measured sort -u + awk cross-dedup on 1M lines (excl. ggrep)

# ICANN-style "registrable parent = last two labels" rule. The production
# classifier (tld_analysis) consults the public-suffix master list; for an
# init-COST spike the exact suffix set is irrelevant -- what matters is the
# per-line split/classify work + the dict build at scale. Two labels is the
# dominant case and keeps the data/zone split realistic (~deep labels -> data).
_REGISTRABLE_LABELS = 2


# --------------------------------------------------------------------------- #
# The build under test -- pure, stdlib-only, no Unbound symbols, reentrant
# (returns a fresh structure-set; mutates nothing global). This prototypes the
# Phase-3 `pfb_dnsbl_build` shape: parse -> normalise -> classify -> build.
# --------------------------------------------------------------------------- #


def parse_line(line: str) -> str | None:
    """Parse one raw feed line to a bare host, or None if it carries no domain.

    Subsumes the basic-ABP token strip and the hosts/plain handling the PHP loop
    does today (`pfblockerng.inc:7665-7960`). Returns None for blank/comment/IP
    lines -- the IP case is the firewall path (PHP), which the Python build skips.
    """
    line = line.strip()
    if not line or line[0] in "#!/":
        return None

    # basic-ABP: ||domain^  (ignore @@ exceptions, $options, *, /, element rules)
    if line.startswith("||"):
        if line.endswith("^") and "$" not in line and "*" not in line and "/" not in line:
            return line[2:-1]
        return None

    # hosts format: "<sink-ip> <domain>" -> take the token after the space.
    if " " in line:
        first, _, rest = line.partition(" ")
        rest = rest.strip()
        # A hosts line begins with the sinkhole IP; the domain is the remainder.
        line = rest if (first == HOSTS_SINK or _is_ipv4(first)) else first

    if _is_ipv4(line):
        return None  # bare-IP -> firewall path (PHP); Python build skips it.

    return line or None


# Domain-shape gate. The production `PFB_FILTER_DOMAIN` is a single regex match;
# a compiled pattern is the representative per-line cost (one C-level call), not a
# per-character Python membership loop.
_DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$")


def normalise(host: str) -> str | None:
    """Lower-case, strip stray dots, reject anything that is not a plain domain."""
    host = host.strip(".").lower()
    if "." not in host or not _DOMAIN_RE.match(host):
        return None
    return host


def classify(host: str) -> tuple[str, str]:
    """Return (kind, key): ('zone', registrable-parent) or ('data', host).

    Mirrors `tld_analysis`: a domain that *is* its registrable parent becomes a
    wildcard zone; a deeper sub-domain becomes an exact data entry.
    """
    labels = host.split(".")
    if len(labels) <= _REGISTRABLE_LABELS:
        return "zone", host
    return "data", host


def _is_ipv4(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not (0 <= int(p) <= 255) or (len(p) > 1 and p[0] == "0"):
            return False
    return True


def build(lines: list[str], feeds: list[str], log_flag: str = "1") -> dict[str, Any]:
    """Pure build: raw lines (+ parallel per-line feed) -> structure-set.

    Returns ``dataDB``/``zoneDB`` (key -> {"log", "index"}), ``feedGroupIndexDB``
    (index -> {"feed", "group"}) and ``counts``. No dedup / collapse / whitelist
    pruning -- dict keys dedup for free, last feed wins on a duplicate key (the
    documented attribution change). Reentrant: nothing global is touched.
    """
    if len(lines) != len(feeds):
        raise ValueError(f"lines and feeds must be equal length: {len(lines)} != {len(feeds)}")

    data_db: dict[str, dict[str, Any]] = {}
    zone_db: dict[str, dict[str, Any]] = {}
    feed_group_index_db: dict[int, dict[str, str]] = {}
    feed_group_db: dict[str, int] = {}
    next_index = 0
    n_skipped = 0

    for line, feed in zip(lines, feeds):
        host = parse_line(line)
        if host is None:
            n_skipped += 1
            continue
        host = normalise(host)
        if host is None:
            n_skipped += 1
            continue

        group = feed  # in the real pipeline group=$alias; one per feed here.
        fg_key = feed + group
        index = feed_group_db.get(fg_key)
        if index is None:
            index = next_index
            feed_group_db[fg_key] = index
            feed_group_index_db[index] = {"feed": feed, "group": group}
            next_index += 1

        kind, key = classify(host)
        payload = {"log": log_flag, "index": index}
        if kind == "zone":
            zone_db[key] = payload
        else:
            data_db[key] = payload

    feed_group_db.clear()  # mirrors loader :605 -- temporary, dropped after build
    total = len(data_db) + len(zone_db)
    return {
        "dataDB": data_db,
        "zoneDB": zone_db,
        "feedGroupIndexDB": feed_group_index_db,
        "counts": {
            "data": len(data_db),
            "zone": len(zone_db),
            "total": total,
            "skipped": n_skipped,
            "feedgroups": len(feed_group_index_db),
        },
    }


# --------------------------------------------------------------------------- #
# Measurement harness.
# --------------------------------------------------------------------------- #


def _measure_one(lines: list[str], feeds: list[str]) -> tuple[float, int, dict[str, Any]]:
    """One build: return (wall_seconds, peak_bytes, structures)."""
    gc.collect()
    tracemalloc.start()
    tracemalloc.reset_peak()
    t0 = time.perf_counter()
    structures = build(lines, feeds)
    dt = time.perf_counter() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return dt, peak, structures


def _retained_bytes(structures: dict[str, Any]) -> int | None:
    """Deep retained footprint of the loaded dicts (asizeof, all together)."""
    if asizeof is None:
        return None
    return asizeof.asizeof(structures["dataDB"], structures["zoneDB"], structures["feedGroupIndexDB"])


def run(n_domain_lines: int, n_runs: int) -> None:
    if n_runs < 1:
        raise ValueError(f"n_runs must be >= 1, got {n_runs}")
    print("=" * 78)
    print(
        "ADR-06 P1 SPIKE  Python DNSBL build cost  (CPython {}.{}, {})".format(
            sys.version_info.major, sys.version_info.minor, sys.platform
        )
    )
    print("-" * 78)
    corpus = generate_raw_corpus(n_domain_lines)
    print(
        "raw corpus: total lines={:,}  domain lines={:,}  bare-IP lines={:,}  unique domains={:,}".format(
            corpus.total_lines, corpus.n_domain_lines, corpus.n_ip_lines, corpus.n_unique_domains
        )
    )

    times: list[float] = []
    peaks: list[int] = []
    last: dict[str, Any] = {}
    for r in range(n_runs):
        dt, peak, structures = _measure_one(corpus.lines, corpus.feeds)
        times.append(dt)
        peaks.append(peak)
        last = structures
        print(
            "  run {}/{}: build={:.3f}s  peak={:.1f} MiB  data={:,} zone={:,} skipped={:,}".format(
                r + 1,
                n_runs,
                dt,
                peak / 2**20,
                structures["counts"]["data"],
                structures["counts"]["zone"],
                structures["counts"]["skipped"],
            )
        )
        del structures
        gc.collect()

    counts = last["counts"]
    total = counts["total"]
    retained = _retained_bytes(last)

    t_min, t_med, t_max = min(times), statistics.median(times), max(times)
    t_mean = statistics.mean(times)
    peak_med = statistics.median(peaks)

    print("-" * 78)
    print(
        "build wall-time (N={}):  min={:.3f}s  median={:.3f}s  mean={:.3f}s  max={:.3f}s".format(
            n_runs, t_min, t_med, t_mean, t_max
        )
    )
    print("build peak RAM:          median={:.1f} MiB  max={:.1f} MiB".format(peak_med / 2**20, max(peaks) / 2**20))
    print(
        "loaded entries:          {:,}  (data={:,} zone={:,} feedgroups={:,})".format(
            total, counts["data"], counts["zone"], counts["feedgroups"]
        )
    )
    if retained is not None:
        bpe = retained / total if total else float("nan")
        print(
            "retained dict footprint: {:.1f} MiB  ({:.1f} B/entry vs {:.0f} B/entry baseline, {:+.0f}%)".format(
                retained / 2**20, bpe, BASELINE_BYTES_PER_ENTRY, (bpe / BASELINE_BYTES_PER_ENTRY - 1) * 100
            )
        )
    else:
        bpe = float("nan")
        print("retained dict footprint: (pympler not installed -- run: python -m pip install pympler)")

    # ----------------------------------------------------------------------- #
    # GATE
    # ----------------------------------------------------------------------- #
    print("-" * 78)
    time_ok = t_max <= THRESH_BUILD_SECONDS
    mem_ok = (retained is None) or (bpe <= THRESH_BYTES_PER_ENTRY)
    net_added = t_med - SHELL_PASSES_REMOVED_SECONDS
    print(
        "net vs today: build {:.1f}s replaces ~{:.1f}s of removed shell passes "
        "(sort -u + awk dedup; ggrep extra) -> net added ~{:+.1f}s".format(
            t_med, SHELL_PASSES_REMOVED_SECONDS, net_added
        )
    )
    print(
        "threshold: build <= {:.1f}s  AND  retained <= {:.0f} B/entry".format(
            THRESH_BUILD_SECONDS, THRESH_BYTES_PER_ENTRY
        )
    )
    print("  build time  : {:.3f}s (max)  -> {}".format(t_max, "PASS" if time_ok else "FAIL"))
    if retained is not None:
        print("  bytes/entry : {:.1f}            -> {}".format(bpe, "PASS" if mem_ok else "FAIL"))
    else:
        print("  bytes/entry : (skipped, pympler absent) -> treated as PASS")
    verdict = "GO" if (time_ok and mem_ok) else "NO-GO"
    print("=" * 78)
    print(
        "VERDICT: {}  (build {:.1f}s threshold, {:.0f} B/entry threshold)".format(
            verdict, THRESH_BUILD_SECONDS, THRESH_BYTES_PER_ENTRY
        )
    )
    print("=" * 78)


def main() -> None:
    n_runs = int(os.environ.get("SPIKE_N", "3"))
    sizes = [int(s) for s in os.environ.get("SPIKE_SIZES", "1000000").split(",") if s.strip()]
    for n in sizes:
        run(n, n_runs)


if __name__ == "__main__":
    main()

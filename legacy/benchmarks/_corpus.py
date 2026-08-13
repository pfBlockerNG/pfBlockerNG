"""Deterministic blocklist corpus generator + structure builders for benchmarks.

Produces a single corpus of blocklist entries (data/zone/white/hsts/noaaaa) and
builds BOTH the pre-ADR flat dicts and the post-ADR domain trie from it, so the
two can be compared on identical input. Domains are generated with shared
suffixes (many entries under a smaller pool of second-level domains), mirroring
real feeds where ``ads.x.com`` and ``track.x.com`` share ``x.com``.

Not shipped: lives under benchmarks/, excluded from release archives.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

import _trie

TLDS = ("com", "net", "org", "io", "co", "app", "dev")
LABELS = (
    "ads",
    "track",
    "cdn",
    "img",
    "api",
    "mail",
    "shop",
    "news",
    "sub",
    "node",
    "edge",
    "px",
    "beacon",
    "stat",
    "log",
    "data",
    "feed",
    "pool",
    "asset",
    "tag",
)


@dataclass
class Corpus:
    data: list[str] = field(default_factory=list)  # exact-match domains
    zone: list[str] = field(default_factory=list)  # wildcard-incl-self domains
    white: list[tuple[str, bool]] = field(default_factory=list)
    hsts: list[str] = field(default_factory=list)
    noaaaa: list[tuple[str, bool]] = field(default_factory=list)
    slds: list[str] = field(default_factory=list)  # parent pool (for query gen)

    @property
    def total(self) -> int:
        return len(self.data) + len(self.zone) + len(self.white) + len(self.hsts) + len(self.noaaaa)


def generate_corpus(n_entries: int, seed: int = 1234) -> Corpus:
    """Generate ~n_entries blocklist entries spread across the five categories.

    Distribution (roughly): 70% exact data, 20% wildcard zone, 5% whitelist,
    3% hsts, 2% noAAAA — a feed-shaped mix dominated by exact entries.
    """
    rng = random.Random(seed)
    n_slds = max(1, n_entries // 8)  # fewer parents than entries -> shared suffixes
    slds = ["{}{}.{}".format(rng.choice(LABELS), rng.randrange(100_000), rng.choice(TLDS)) for _ in range(n_slds)]

    c = Corpus(slds=sorted(set(slds)))
    seen: set[str] = set()
    for i in range(n_entries):
        sld = rng.choice(slds)
        bucket = rng.random()
        if bucket < 0.70:
            d = "{}{}.{}".format(rng.choice(LABELS), i, sld)
            if d not in seen:
                seen.add(d)
                c.data.append(d)
        elif bucket < 0.90:
            if sld not in seen:
                seen.add(sld)
                c.zone.append(sld)
        elif bucket < 0.95:
            d = "wl{}.{}".format(i, sld)
            if d not in seen:
                seen.add(d)
                c.white.append((d, rng.random() < 0.5))
        elif bucket < 0.98:
            if sld not in seen:
                seen.add(sld)
                c.hsts.append(sld)
        else:
            d = "na{}.{}".format(i, sld)
            if d not in seen:
                seen.add(d)
                c.noaaaa.append((d, rng.random() < 0.5))
    return c


# --------------------------------------------------------------------------- #
# Structure builders — identical payload shapes on both sides.
# --------------------------------------------------------------------------- #


def build_dicts(c: Corpus) -> dict:
    """Build the pre-ADR flat dicts (the five removed containers)."""
    data_db = {d: {"log": "1", "index": 0} for d in c.data}
    zone_db = {d: {"log": "1", "index": 0} for d in c.zone}
    white_db = {d: w for d, w in c.white}
    hsts_db = {d: 0 for d in c.hsts}
    noaaaa_db = {d: w for d, w in c.noaaaa}
    return {
        "dataDB": data_db,
        "zoneDB": zone_db,
        "whiteDB": white_db,
        "hstsDB": hsts_db,
        "noAAAADB": noaaaa_db,
    }


def build_trie(c: Corpus):
    """Build the (rejected) domain trie via the frozen insert API in _trie.py."""
    root = _trie.TrieNode()
    for d in c.data:
        _trie.trie_insert_data(root, d, {"log": "1", "index": 0})
    for d in c.zone:
        _trie.trie_insert_zone(root, d, {"log": "1", "index": 0})
    for d, w in c.white:
        _trie.trie_insert_white(root, d, w)
    for d in c.hsts:
        _trie.trie_insert_hsts(root, d)
    for d, w in c.noaaaa:
        _trie.trie_insert_noaaaa(root, d, w)
    return root


# --------------------------------------------------------------------------- #
# Query-set builders. Each returns a list of (qname, tld).
# --------------------------------------------------------------------------- #


def _tld(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def queries_positive_data(c: Corpus, n: int, seed: int = 7) -> list[tuple[str, str]]:
    """Exact data hits."""
    rng = random.Random(seed)
    pool = c.data or c.zone
    return [(q, _tld(q)) for q in (rng.choice(pool) for _ in range(n))]


def queries_positive_zone(c: Corpus, n: int, seed: int = 8) -> list[tuple[str, str]]:
    """Subdomains of zone entries (data-miss, zone-hit; exercises the suffix walk)."""
    rng = random.Random(seed)
    pool = c.zone or c.slds
    out = []
    for _ in range(n):
        parent = rng.choice(pool)
        out.append(("zq{}.{}".format(rng.randrange(1_000_000), parent), _tld(parent)))
    return out


def queries_negative(c: Corpus, n: int, seed: int = 9) -> list[tuple[str, str]]:
    """Domains that match nothing — the bypass-to-Unbound path.

    Uses label prefixes ('neg'/'miss') absent from the generator pool so a
    collision with a real entry is impossible, while keeping a shared TLD.
    """
    rng = random.Random(seed)
    out = []
    for k in range(n):
        tld = rng.choice(TLDS)
        out.append(("neg{}.miss{}.{}".format(k, rng.randrange(1_000_000), tld), tld))
    return out


def queries_noaaaa_positive(c: Corpus, n: int, seed: int = 10) -> list[tuple[str, str]]:
    rng = random.Random(seed)
    pool = [d for d, _ in c.noaaaa] or c.data
    return [(q, _tld(q)) for q in (rng.choice(pool) for _ in range(n))]

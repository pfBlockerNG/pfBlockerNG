"""Un-pruned raw DNSBL corpus generator for the ADR-06 Phase-1 spike.

ADR-06 moves parse -> normalise -> classify -> build into the Python plugin and
*drops* the build-time list optimisations (dedup, subdomain collapse, user/TOP1M
whitelist removal). The realistic init load is therefore the **un-pruned** raw
feed text, which is LARGER than today's pruned `pfb_py_data`/`pfb_py_zone`. This
module emits exactly that: literal downloaded feed lines, with duplicates kept,
no whitelist/TOP1M removal, and no subdomain collapse.

Three feed shapes are produced (a feed-shaped mix), matching the formats the PHP
parse loop handles (`pfblockerng.inc:7665-7973`):

* ``hosts``  -> ``0.0.0.0 ads3.x.com`` (hosts-file format; the leading IP is the
  sinkhole address, NOT a feed-embedded firewall IP).
* ``plain``  -> ``ads3.x.com`` (bare domain, one per line).
* ``abp``    -> ``||ads3.x.com^`` (basic EasyList/ABP; PHP strips ``|| . ^``).

It also injects:

* ``bare-IP`` lines (``198.51.100.7``) — the "DNSBL IP" firewall feature. In the
  real pipeline PHP extracts these into ``*_v4.ip`` -> ``DNSBLIP_v4`` and strips
  them from Python's input (ADR-06 §2). The spike SKIPS them in the build (the
  Python build never produces firewall input), but emits them so the corpus is
  realistic and the skip cost is measured.
* duplicates (a domain appearing in several feeds) — kept un-deduped; the dict
  load dedups keys for free.

Not shipped: lives under benchmarks/, excluded from release archives. stdlib only.
"""

from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass, field

from _corpus import LABELS, TLDS

# Sinkhole address a hosts-format feed prepends to every domain. This is NOT a
# feed-embedded firewall IP — it is stripped as "characters before the space".
HOSTS_SINK = "0.0.0.0"


@dataclass
class RawCorpus:
    """A flat list of literal raw feed lines + bookkeeping for the spike."""

    lines: list[str] = field(default_factory=list)  # literal raw feed text lines
    feeds: list[str] = field(default_factory=list)  # per-line feed header (parallel)
    n_domain_lines: int = 0  # lines carrying a domain (hosts/plain/abp)
    n_ip_lines: int = 0  # bare-IP lines (PHP firewall path; Python skips)
    n_unique_domains: int = 0  # distinct domains across all domain lines

    @property
    def total_lines(self) -> int:
        return len(self.lines)


def generate_raw_corpus(
    n_domain_lines: int,
    seed: int = 1234,
    dup_factor: float = 0.18,
    ip_factor: float = 0.02,
    n_feeds: int = 24,
) -> RawCorpus:
    """Generate ~``n_domain_lines`` un-pruned raw feed lines across mixed formats.

    ``dup_factor`` of the domain lines are deliberate cross-feed duplicates (a
    domain re-emitted under a different feed) so the build's free key-dedup and
    last-wins feed/group attribution are exercised. ``ip_factor`` of the *extra*
    lines are bare IPv4 (the firewall path the Python build skips).

    The domain distribution mirrors `_corpus.generate_corpus`: many entries share
    a smaller pool of second-level domains (so classification has realistic
    registrable-parent sharing), ~70/20/5/3/2 across label depth — but here every
    entry is emitted as raw text, un-classified and un-pruned.
    """
    rng = random.Random(seed)
    n_slds = max(1, n_domain_lines // 8)
    slds = ["{}{}.{}".format(rng.choice(LABELS), rng.randrange(100_000), rng.choice(TLDS)) for _ in range(n_slds)]
    feeds = ["feed_{:02d}".format(i) for i in range(n_feeds)]

    c = RawCorpus()
    seen: set[str] = set()
    emitted_domains: list[str] = []  # pool to draw duplicates from

    def emit_domain(domain: str) -> None:
        feed = rng.choice(feeds)
        fmt = rng.random()
        if fmt < 0.40:
            line = "{} {}".format(HOSTS_SINK, domain)  # hosts format
        elif fmt < 0.80:
            line = domain  # plain
        else:
            line = "||{}^".format(domain)  # basic-ABP
        c.lines.append(line)
        c.feeds.append(feed)
        c.n_domain_lines += 1
        if domain not in seen:
            seen.add(domain)
            emitted_domains.append(domain)

    for i in range(n_domain_lines):
        # Decide whether this line is a duplicate of an already-emitted domain.
        if emitted_domains and rng.random() < dup_factor:
            emit_domain(rng.choice(emitted_domains))
            continue

        sld = rng.choice(slds)
        bucket = rng.random()
        if bucket < 0.70:  # deep label -> exact data after classify
            emit_domain("{}{}.{}".format(rng.choice(LABELS), i, sld))
        elif bucket < 0.90:  # registrable parent -> wildcard zone after classify
            emit_domain(sld)
        elif bucket < 0.95:  # would have been whitelisted (kept in-list now)
            emit_domain("wl{}.{}".format(i, sld))
        elif bucket < 0.98:  # hsts-ish host
            emit_domain("hs{}.{}".format(i, sld))
        else:  # noaaaa-ish host
            emit_domain("na{}.{}".format(i, sld))

    # Inject bare-IP lines (firewall path) interleaved at the end. These fail the
    # domain validation in the Python build and are skipped (never become dicts).
    n_ip = int(n_domain_lines * ip_factor)
    ip_base = int(ipaddress.IPv4Address("198.51.100.0"))
    for k in range(n_ip):
        ip = str(ipaddress.IPv4Address((ip_base + rng.randrange(0, 65536)) & 0xFFFFFFFF))
        c.lines.append(ip)
        c.feeds.append(rng.choice(feeds))
        c.n_ip_lines += 1

    # Shuffle so IP/domain/format ordering is realistic (feeds interleave).
    order = list(range(len(c.lines)))
    rng.shuffle(order)
    c.lines = [c.lines[i] for i in order]
    c.feeds = [c.feeds[i] for i in order]

    c.n_unique_domains = len(seen)
    return c

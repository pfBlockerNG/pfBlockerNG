# ADR-07 ABP DNS-feed corpus (representative, trimmed)

A small, hand-curated, **representative** sample of the ABP/AdGuard filter line
types real DNS blocklists ship — drawn in shape from the AdGuard DNS filter, the
AdGuardHome adblock-style hosts-blocklist syntax, the EasyList DNS-relevant
subset, and the hagezi lists. It is **not** a verbatim copy of any feed (we do not
vendor large copyrighted feeds into the repo, per the Phase-1 constraint); every
line is a syntactic exemplar of a category the parser/reducer/matcher must handle.

The point of the corpus is the **line-type distribution and the regex-reduction /
ReDoS behaviour**, not blocklist coverage. `legacy/benchmarks/spike_adr07_regex.py`
categorises and counts these lines, measures the regex reduction ratio, the
irreducible count at feed scale, the inline per-query scan latency, and the ReDoS
exposure (static-flag + worst real first-hit). The full measured distribution and
the GO/NO-GO are written into
`legacy/ADRs/ADR_07_ABP_DNSBL_Support/RESULTS/01_Results.txt`.

## Files

- `abp_sample.txt` — the mixed ABP feed sample (all line categories).
- `regex_reducible.txt` — `/re/` and `@@/re/` patterns that SHOULD fold to a
  domain/wildcard rule (zero per-query cost).
- `regex_irreducible.txt` — `/re/` patterns that stay real compiled patterns,
  including a few deliberately ReDoS-shaped ones for the safety measurement.

## Line categories (what each exemplar maps to, DNS-only)

| Category | Example | DNS decision |
| --- | --- | --- |
| `\|\|domain^` block | `\|\|ads.example.com^` | block domain |
| `\|\|domain^$dns-opts` | `\|\|t.example.com^$important` | block + precedence |
| `@@\|\|domain^` allow | `@@\|\|cdn.example.com^` | un-block (global) |
| hosts | `0.0.0.0 tracker.example.net` | block domain |
| plain domain | `bad.example.org` | block domain |
| `\|\|IP^` anchored IP | `\|\|203.0.113.7^` | PHP firewall, Python skips |
| `/re/` block | `/^ads?[0-9]*\\./` | block regex |
| `@@/re/` allow | `@@/analytics/` | allow regex |
| element-hiding | `example.com##.ad-banner` | SKIP (not DNS) |
| path/URL | `\|\|example.com/ads/*` | SKIP (not DNS) |
| page-context `$opts` | `\|\|x.com^$third-party,script` | SKIP (not DNS) |
| `$badfilter` | `\|\|y.example^$badfilter` | feed-only prune |

# ADR-49 feed corpus — offline false-positive survey fixture

A one-time, committed snapshot of the **first 8 KiB of every feed** in the catalogue
(`src/usr/local/www/pfblockerng/pfblockerng_feeds.json`). It exists so the ADR-49
false-positive survey — the gate that `pfb_text_sanity()` returns `null` for every real
text feed — runs **offline**, repeatably, and without hammering feed hosts (several
rate-limit downloads, per issue #581).

## Layout

- `manifest.json` — one record per catalogue `url` (primaries **and** alternates):
  `header`, `section` (`ipv4`/`ipv6`/`dnsbl`), `url`, `fetched_at`, and for a reachable
  feed `http_status`, `content_type`, `sample_file`, `sample_bytes`, `sample_sha256`, and
  an `archive` flag (magic-byte sniff — gzip/zip/bz2/7z; archives are not text feeds and
  the survey skips them). An unreachable feed carries an `error` string instead of a sample.
- `samples/<slug>.bin` — the raw first bytes exactly as served (no transcoding). `<slug>`
  is derived from the feed header and deduped **case-insensitively** (so the corpus is
  identical on a case-sensitive Linux CI runner and a case-insensitive macOS dev box).

## Regenerating

Run once from the repo root, on a dev box (never the appliance — it fetches live over the
network):

```sh
python3 scripts/fetch_feed_corpus.py
```

It rewrites `manifest.json` and `samples/`. Commit the diff. Refresh when the catalogue
changes materially; day-to-day feed-content drift is the documented out-of-CI limitation
(ADR-49 §7) and does not require a refresh.

## What the corpus is NOT

- **Not a completeness guarantee.** Feeds unreachable at fetch time (rate-limit, 403,
  DNS, timeout) have no sample — the survey judges only what was actually served. A large
  unreachable fraction means the corpus should be refreshed, not that those feeds are clean.
- **Not shipped.** `tests/` is dev-only; release archives contain `src/` only.
- **Not authoritative feed data.** These are inert first-bytes snapshots for testing the
  scanner heuristic, not a blocklist source.
- **Verbatim public bytes.** Samples are the raw first bytes of public spam/abuse
  blocklists exactly as served — they can contain third-party contact or spammer email
  addresses that are already public in those feeds. No credentials or private data (the
  feeds carry none); the `binary` pin in `.gitattributes` keeps every byte intact.

Consumed by `tests/php/FeedCorpusSurveyTest.php`.

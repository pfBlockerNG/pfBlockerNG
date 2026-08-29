# Smoke feed fixtures (ADR-16 Part C)

Inert sample feed bodies served to the live pfSense smoke VM by `_MockFeedServer`
(`tests/smoke/conftest.py`, the `mock_feeds` fixture). Each file is the raw body
`curl` fetches; the guest reaches it at `http://192.168.89.2:<port>/<filename>` over
SLIRP. **Phase 4 authors these fixtures only** — Phase 5 registers them on an
`IpCase`/`DnsblCase`, runs Force Update, and asserts the load on the box.

All data is inert: IP files use RFC 5737 / RFC 3849 documentation ranges; DNSBL
files use `uuid-<hex>.com` names. Per the smoke-domain rule, DNSBL fixtures NEVER
use RFC-6761 TLDs (`.test`/`.example`/`.invalid` — Unbound's built-in local-zones
shadow them) and NEVER HSTS-preload names (HSTS forces a VIP block to NULL).

**Exception (issue #760):** a fixture exercised under the global Suppression
checkbox ON (`tests/smoke/test_smoke_suppression.py`) must NOT use RFC
5737/3849/2544/6598 (or any other reserved-class) address — `sanitize_ipaddr()`/
`pfb_sanitize_ipaddr_v6()` drop those classes unconditionally whenever Suppression is
on, which would silently empty the fixture before it ever reached the pf table.
Those fixtures use public, non-reserved space instead — arbitrary octets/hextets
(e.g. `81.169.0.0/16`, `2606:4700::/32`), chosen only as inert content, never
dialed, and never a literal with harness meaning elsewhere in this suite (e.g.
`1.1.1.1`/`1.0.0.1`, the smoke image's baked DNS-forwarder default) or a
well-known public resolver address; see the "IP suppression..." sections below.

Line shapes match the real parsers — IP `auto` in `pfblockerng.inc`
(`~:10410-10560`), DNSBL plain/hosts/ABP in `pfb_unbound.py`
(`parse` / `parse_abp`, `~:2675-2900`). A leading `#` (IP, DNSBL plain/hosts) or
`!` / `[` (ABP) is a comment, exercised in every file.

## IP feeds (format `auto`, `IpCase`)

| File | Format | Family | Member (loads) | Non-member (must NOT) |
| --- | --- | --- | --- | --- |
| `ip_plain_cidr.txt` | plain IPv4 + CIDR | v4 | `203.0.113.5`; `198.51.100.7` (in `198.51.100.0/24`) | `203.0.113.250` |
| `ip_range.txt` | IPv4 range `a-b` | v4 | `198.51.100.15` (in `198.51.100.10-198.51.100.20`) | `198.51.100.21`, `198.51.100.200` |
| `ip_ipv6.txt` | IPv6 single + CIDR | v6 | `2001:db8::1`; `2001:db8:1::99` (in `2001:db8:1::/48`) | `2001:db8:dead::1` |

IP assertion: `pfctl_table_members(pfB_<alias>_<family>)` with the CIDR-tolerant
`member_present`. The v4 range expands via `ip_range_to_subnet_array()` into the
CIDRs that exactly cover `.10`–`.20`, so `.21` is intentionally just outside.

## DNSBL feeds (`DnsblCase`)

| File | Format | Member (blocks) | Allow-exception (resolves) | Non-member (resolves) |
| --- | --- | --- | --- | --- |
| `dnsbl_plain.txt` | plain domain | `uuid-a344db4286a4.com` | — | `uuid-06cf362c2890.com` |
| `dnsbl_hosts.txt` | hosts `0.0.0.0 d` | `uuid-947e69114606.com` | — | `uuid-55ca85f92f34.com` |
| `dnsbl_abp.txt` | ABP / EasyList | `uuid-22f166f56cca.com` | `uuid-f26156c6df69.com` (block then `@@` allow) | `uuid-8ed2df53e469.com` |

DNSBL assertion: `dns_probe` block-shape on the box (NOERROR + VIP, or NULL per the
list's `logging`); the non-member (and the ABP allow-exception, where a feed `@@`
allow band 2 beats the `||` block band 1) must RESOLVE, not block.

## BOM-led '!' first line fixture (issue #946, `DnsblCase`, `test_smoke_feeds.py`)

| File | First line | Anchor member (blocks) | Hosts member (blocks) |
| --- | --- | --- | --- |
| `dnsbl_bom_header.txt` | UTF-8-BOM-led `! ...` comment | `uuid-6c91761cef48.com` (`\|\|domain^`) | `uuid-2329767ef078.com` (`0.0.0.0 domain`) |

Header-less, non-ABP feed whose FIRST bytes are a UTF-8 BOM (`EF BB BF`) directly
ahead of a `!` comment line -- `pfb_dnsbl_strip_bom()` is hoisted to the top of the
per-line parse loop so this line is skipped as a comment before the ADR-21 `||`
anchor short-circuit and CSV autodetection ever see it. Neither the anchor line nor
the hosts line carries a BOM. Assertion: both members block (VIP), AND the DNSBL
parse-error log gains no new line for the BOM-led comment (the RED->GREEN carrier --
pre-fix the still-BOM'd line missed the `!` skip and was logged as invalid data).

## Plain-text sanity scan fixture (ADR-49, `IpCase`, `test_smoke_feeds.py`)

| File | on-box `file(1)` | Purpose |
| --- | --- | --- |
| `html_error_page.html` | expected `text/html` (verify on first live run) | A realistic 403/error-page body (`<!doctype html>...403 Forbidden...</html>`) carrying NO blocklist-shaped line (no IP/CIDR, no `domain.tld` token, no `#`/`!` comment) anywhere, so `pfb_text_sanity()` returns `html_error_page` when the ADR-49 `pfb_feed_sanity` scan is ON. Its on-box MIME classification is asserted at test time (`file -b --mime-type`, per the ADR-45 libmagic-divergence lesson) before the reject is asserted, so a libmagic surprise fails loudly with the actual verdict rather than silently not exercising the gate. |

The scan's healthy-feed control reuses the already-verified `ip_plain_cidr.txt` (IP
feeds) / `dnsbl_plain.txt` (DNSBL feeds) above — both are plain `text/plain` bodies
that load successfully today, proving `pfb_feed_sanity=on` is a real branch (rejects
the error page, not every text feed).

## Archive corpus (ADR-45 — structural integrity)

Binary fixtures for the ADR-45 structural-probe + octet-stream-recovery smoke cases
(`test_corrupt_*_rejected`, `test_octet_stream_zip_recovered`,
`test_junk_octet_stream_rejected` in `test_smoke_feeds.py`). **Committed rather than
built inline** because the relevant FreeBSD tooling (`file(1)` libmagic, `bsdtar`
libarchive) classifies/parses these bytes DIFFERENTLY from the macOS/Linux dev+CI
host — an inline fixture that looked corrupt/octet-stream on the dev box behaved as
valid/`image/x-tga` on the live pfSense VM. Each file below is **verified on a
pfSense CE 2.8 box** (FreeBSD 15, `file-5.46`, `bsdtar 3.7.7`); the table records the
on-box verdict and why it matters.

| File | on-box `file(1)` | integrity test | Purpose / FreeBSD peculiarity |
| --- | --- | --- | --- |
| `archive_corrupt.zip` | `application/zip` | `tar -tf` → **rc≠0** | Leading local-header signature (`PK\x03\x04`) clobbered, **EOCD left intact**. `file(1)` still reports `application/zip` (it reads the EOCD) → the ZIP branch runs, and `bsdtar -tf` fails on the broken header → the probe rejects. **Why not just truncate:** libarchive streams local headers without needing the central directory, so a tail-truncated ZIP still lists+extracts (`tar -tf` rc=0) and is NOT rejected. |
| `archive_corrupt.gz` | `application/gzip` | `gunzip -t` → **rc≠0** | Valid gzip truncated past the header (no payload/CRC/ISIZE trailer). gzip is a single stream with no streamable directory, so truncation IS reliably corrupt to the codec. |
| `archive_corrupt.bz2` | `application/x-bzip2` | `bzip2 -t` → **rc≠0** | Valid bzip2 truncated mid-block; `bzip2 -t` fails. |
| `archive_octet_recover.zip` | `application/octet-stream` | `tar -tf` → **rc=0**, extracts the IP list | The #581 recovery case: a valid ZIP behind a short text SFX-stub preamble (`#!/bin/false …`). FreeBSD `file(1)` cannot classify the text-then-binary stream → `application/octet-stream` (not allow-listed), triggering `pfb_octet_recover_type()`, which probes with `bsdtar` (rc=0) → recovers `application/zip` → imports. **Why not a raw `\x00\x01…` prefix:** FreeBSD libmagic misreads that as `image/x-tga` (a non-allow-listed type rejected outright, never reaching recovery), even though macOS/Linux read it as octet-stream. The text preamble avoids every magic rule. |
| `archive_junk_octet.bin` | `application/octet-stream` | none (not an archive) | The ADR §7 "never blanket-accept octet-stream" branch: pure NUL/control bytes → `octet-stream`, no archive type passes any probe → `pfb_octet_recover_type()` returns NULL → rejected. |
| `archive_traversal.zip` | `application/zip` (expected — verify on-box in the fan-out) | `tar -tf` → **rc=0**, lists both members | ADR-46 member-name guard: a structurally VALID two-member ZIP whose second member is `../pfb_adr46_escape.txt` (parent-dir escape). Stock `zip`/`bsdtar` refuse to *create* such a member, so it is crafted as raw bytes via Python `zipfile` and committed. Two members are required to steer the GeoIP/top-1M branch into the disk-writing `tar -xf -C` path (a single member takes the guard-free `-xOf` stdout path). Pre-guard behaviour is SILENT partial success (bsdtar skips the `..` member and the branch returns TRUE); the guard turns it into an explicit `stage=member` reject (`test_adr46_hostile_member_zip_rejected`). |
| `archive_traversal.tar.gz` | `application/gzip` (expected — verify on-box in the fan-out) | `gunzip -t` → **rc=0** (valid stream); `tar -tf` → **rc=0**, lists both members | The tar.gz sibling of `archive_traversal.zip` for the OTHER two disk-writing sites: the gzip GeoIP branch (`tar -xf --strip=1` into a staging directory inside `{geoipshare}` since issue #2668) and the UT1/blacklist branch (`tar -xf … -C {dbdir}/…`). Members `cat/domains` (benign, the UT1 layout) + `../pfb_adr46_escape.txt` (hostile). Crafted via Python `tarfile` (stock tar refuses `..` members) with zeroed mtimes so regeneration is byte-stable. Note the ADR-45 probe for these branches is only `gunzip -t` (gzip-stream integrity — it never inspects the inner tar), which is exactly why the member guard fails CLOSED on an unlistable archive. Drives `test_adr46_hostile_member_geoip_gz_rejected` and `test_adr46_hostile_member_blacklist_rejected`. |
| `archive_partial_extract.zip` | `application/zip` (expected — verify on-box in the fan-out) | `tar -tf` → **rc=0**, lists both members; `tar -xf` → **rc≠0** (`ZIP bad CRC`) | issue #2668: a corrupt archive that fails PART-WAY through extraction, after one member is already written. Two STORED members (`geoip/one.dat`, `geoip/two.dat`) with one byte of the second member's stored body flipped, so its data no longer matches its recorded CRC. Header-only listing still succeeds — which is what makes this reach extraction at all, since an unlistable archive is refused by the ADR-46 member guard first — and inflating the second member is where bsdtar fails. **Why not just truncate:** a tail-truncated ZIP both lists AND extracts (see `archive_corrupt.zip`). Two members are also what steers the GeoIP ZIP branch into the disk-writing `tar -xf -C` path. Crafted via Python `zipfile` with zeroed timestamps so regeneration is byte-stable. |

All bodies are inert (RFC 5737 IPs). The recoverable ZIP fixture extracts to
`203.0.113.11` (`_ADR45_MEMBER`). Regenerate + re-verify on a FreeBSD box if
libmagic/libarchive behaviour ever shifts; the tests read each file's exact bytes for the
on-box `file(1)` guard (`_fixture_bytes`), so the served feed and the guard never drift.

## IP suppression carve fixtures (ADR-53, `IpCase`, `test_smoke_suppression.py`)

Delivered via `write_local_feed` (a committed, documented fixture body copied onto the guest
as a local file), not the HTTP `mock_feeds` path -- these tests exercise the persisted
suppression engine (`pfblockerng.sh suppress()` for v4, `pfb_suppress_file_v6()` for v6), not
the HTTP-fetch contract Part C already covers.

| File | Contents | Purpose |
| --- | --- | --- |
| `ip_suppress_v4.txt` | `81.169.0.0/16` (public, non-reserved) + two well-separated public bare hosts (`83.246.7.7`, `82.165.5.5`) | Containing-range carve (a `/32`/`/24` suppression carves the `/16`), plus whole-token bare-host removal |
| `ip_suppress_v6.txt` | `2606:4700:53::/64` (public, non-reserved) + two well-separated public bare hosts (`2606:4700:99::10`, `2606:4700:aa::20`) | Same shape, IPv6 (`/128` suppression carves the `/64`) |

The bare hosts are deliberately non-adjacent to each other and to the CIDR block: iprange's
minimal-CIDR aggregation would otherwise merge two adjacent addresses into one covering entry,
which would throw off the exact covering-CIDR-count assertions (`/16 - /32 = 16`,
`/64 - /128 = 64`, `/16 - /24 = 8` -- ADR-53 §1.2, mathematically invariant regardless of the
hole's exact position within its container). Public (not RFC 5737/3849/2544) space is used
throughout, per the issue #760 exception above.

## IP reserved-class / CIDR-floor fixtures (issue #760, `IpCase`, `test_smoke_suppression.py`)

Scenarios D/E of the same module -- a THIRD Suppression-gated mechanism, distinct from the
carve engine above: `sanitize_ipaddr()`/`pfb_sanitize_ipaddr_v6()`'s unconditional reserved-class
drop (§1) and the per-category IPv6 CIDR floor `suppression_cidr_v6` (§3).

| File | Contents | Purpose |
| --- | --- | --- |
| `ip_suppress_reserved_v6.txt` | One public entry (`2606:4700:7777::1111`) + one each of documentation (`2001:db8::1`), multicast (`ff02::1`), NAT64 (`64:ff9b::1`) | Proves the public entry loads while every reserved class is dropped outright |
| `ip_suppress_cidr_floor_v6.txt` | A network-aligned public `/48` (`2606:4700:aaaa::/48`) + a separate bare host (`2606:4700:bbbb::99`) | Proves a floor narrower than the feed's mask clamps the `/48` to its bare base address, leaving the sibling host untouched |

The v4 companion for the reserved-class test (`82.165.5.5` public + `100.64.0.1` CGN) is a
two-line inline body written directly by the test (mirrors the Scenario B companion above) --
not a committed fixture, since it needs no documentation beyond the test itself.

## GeoIP fixtures — CSV + binary mmdb (issue #1219, #1228, #1246)

MaxMind's own public test corpus (`maxmind/MaxMind-DB`, dual Apache-2.0/MIT licensed,
redistributable with attribution), pinned at commit `77c4d49493b99249ce631960a65776fae4aaa518`
and regenerated by `scripts/update-geoip-fixtures.py` (`python3
scripts/update-geoip-fixtures.py`; sha256-verifies every download against a pinned digest and
hard-fails on drift — never re-run casually, only when the pin or the generator-owned
addendum is deliberately changed). The CSVs are derived from the pinned 244-network dataset
and add two deterministic continent-only rows for Asia and Europe; the `.mmdb` remains a
byte-verbatim upstream copy. Seeding both halves via `helpers.seed_geoip_dataset` drives the
*entire* pipeline end to end: the CSVs feed
`pfblockerng.php ugc` (the credential-free, network-free local conversion verb) for the 9
continent/category pages, and the binary `.mmdb` feeds `mmdblookup` for the dMax reputation
classify loop (`pfblockerng.sh:1148`) — the same command shape, same corpus, same on-box
`/usr/local/share/GeoIP/` seed step.

| File | Contents | Purpose |
| --- | --- | --- |
| `GeoLite2-Country.mmdb` | Byte-verbatim copy of MaxMind's `GeoLite2-Country-Test.mmdb` (18012 bytes) | Backs `mmdblookup -f … country iso_code` — the exact call `pfblockerng.sh`'s dMax classify loop makes |
| `GeoLite2-Country-Locations-en.csv` | 48 rows: 46 upstream countries plus continent-only Asia (`6255147`) and Europe (`6255148`) | Covers the continent-only IDs that real GeoLite2 Locations files expose even though MaxMind's test corpus omits them |
| `GeoLite2-Country-Blocks-IPv4.csv` | 16 rows: 14 upstream rows plus one documentation-range host for each continent-only ID | Exercises the upstream Blocks-CSV paths and the missing continent-only v4 conversion path |
| `GeoLite2-Country-Blocks-IPv6.csv` | 232 rows: 230 upstream rows plus one documentation-range host for each continent-only ID | Exercises the empty-`geoname_id` branch and the missing continent-only v6 conversion path |

This corpus carries **zero** `is_anonymous_proxy`/`is_satellite_provider` rows — real GeoLite2
has none either (issue #1221) — so the `A1`/`A2` proxy/satellite aggregates render `(0)`; the
synthetic fixture's manufactured A1/A2 rows do not carry over, by design.

**Upstream public space plus a CSV-only documentation addendum.** A GeoIP database can only
classify addresses it actually knows, so the upstream Blocks rows retain MaxMind's real
test/public IP space (`67.43.156.0/24`, `81.2.69.0/24`, et al.). The two CSV-only continent
rows use RFC 5737/3849 addresses because they exercise `ugc`/pfctl conversion, not mmdb lookup.
No traffic is ever sent to any of these addresses.

## Omitted formats (and why)

CSV/iblocklist, regex, and the ABP IP-anchor (`||1.2.3.4^`) variants are out of the
Phase 5 representative set: they either duplicate the plain/hosts/range coverage or
divert to the PHP DNSBL-IP firewall path rather than the domain build. The
egress/binary formats (geoip/asn/whois/rsync) are explicitly out of the hermetic
smoke (ADR-16 §2) — they need MaxMind/egress. The pre-existing
`sample_ip_feed.txt` is the ADR-04 scaffolding placeholder, left in place.

**ADR-62 closing rows** (`tests/smoke/test_smoke_adr62.py`) cover a CSV feed type
(Bambenek `bbc`), a bracketed-IPv6 literal vs. a genuine `[Adblock]` marker, an
IDN/punycode line, a reused old-dialect `.txt`, and a TLD-enabled run — each
delivered via `write_local_feed` (not a committed fixture here) because every case
needs a per-run `unique_domain()` body, matching the established pattern for
runtime-unique DNSBL bodies (`test_abp_perline_detection_in_plain_feed` et al.).

## Structured-text shapes + the reject control (issue #2511)

Measured `file(1)` type, as the archive table above does — the tests assert this verdict on
the box before asserting behaviour, so a fixture that drifts back to `text/plain` fails
loudly instead of silently re-covering the plain-text entry.

| File | Shape | `file -b --mime-type` |
| --- | --- | --- |
| `ip_json.json` | JSON document with an `entries` array | `application/json` |
| `ip_csv.csv` | header + three `cidr,note,source` rows (file(1) needs >=3 fields) | `text/csv` |
| `ip_xml.xml` | `<feed><ip>…</ip></feed>` | `text/xml` |
| `ip_ndjson.ndjson` | one JSON object per line | `application/x-ndjson` |
| `ip_unsupported_xz.xz` | xz stream over a plain list | `application/x-xz` |

All five hold RFC 5737 documentation addresses only. Each import row compares the alias
table as a SET against the addresses its fixture contains, so a feed importing more or
fewer than it should fails.

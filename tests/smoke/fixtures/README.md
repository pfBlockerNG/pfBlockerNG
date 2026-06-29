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

All bodies are inert (RFC 5737 IPs). The recoverable ZIP extracts to `203.0.113.11`
(`_ADR45_MEMBER`). Regenerate + re-verify on a FreeBSD box if libmagic/libarchive
behaviour ever shifts; the tests read each file's exact bytes for the on-box
`file(1)` guard (`_fixture_bytes`), so the served feed and the guard never drift.

## Omitted formats (and why)

CSV/iblocklist, regex, and the ABP IP-anchor (`||1.2.3.4^`) variants are out of the
Phase 5 representative set: they either duplicate the plain/hosts/range coverage or
divert to the PHP DNSBL-IP firewall path rather than the domain build. The
egress/binary formats (geoip/asn/whois/rsync) are explicitly out of the hermetic
smoke (ADR-16 §2) — they need MaxMind/egress. The pre-existing
`sample_ip_feed.txt` is the ADR-04 scaffolding placeholder, left in place.

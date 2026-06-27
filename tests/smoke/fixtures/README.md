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

## Omitted formats (and why)

CSV/iblocklist, regex, and the ABP IP-anchor (`||1.2.3.4^`) variants are out of the
Phase 5 representative set: they either duplicate the plain/hosts/range coverage or
divert to the PHP DNSBL-IP firewall path rather than the domain build. The
egress/binary formats (geoip/asn/whois/rsync) are explicitly out of the hermetic
smoke (ADR-16 §2) — they need MaxMind/egress. The pre-existing
`sample_ip_feed.txt` is the ADR-04 scaffolding placeholder, left in place.

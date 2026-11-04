---
type: "query"
date: "2026-11-04T14:31:15.328212+00:00"
question: "DoH 443 legacy checkbox migration issue3694 DDR missing DNS Name upgrade notices"
contributor: "graphify"
outcome: "useful"
source_nodes: ["pfb_dns_ddr_doh_443_migrate", "DnsProxyDdrDoh443MigrationTest", "MigrationRegistryTest", "pfb_dns_proxy_ddr_warnings"]
---

# Q: DoH 443 legacy checkbox migration issue3694 DDR missing DNS Name upgrade notices

## Answer

Graphify located the Nightly-only migration class DnsProxyDdrDoh443MigrationTest (235 lines) and its consumers: the issue3694-ddr-doh-443-interfaces registry entry plus pfb_dns_ddr_doh_443_migrate in pfblockerng_extra.inc (which files the DoH-443 notice), MigrationRegistryTest's registry-index assertion, and the NO_NAME upgrade banner returned by pfb_dns_proxy_ddr_warnings() in pfblockerng.inc, with UI smoke and docs promises. Source and defaults support deleting them: the dns/pfb_dns_ddr_doh_443_interfaces schema default is empty, so the migration only copies retired Nightly switches and files a notice. Owner decision (issue #3694 amendment, 2026-11-04) authorizes removal.

## Outcome

- Signal: useful

## Source Nodes

- pfb_dns_ddr_doh_443_migrate
- DnsProxyDdrDoh443MigrationTest
- MigrationRegistryTest
- pfb_dns_proxy_ddr_warnings
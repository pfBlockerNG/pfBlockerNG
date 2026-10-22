# Encrypted DNS discovery for pfB-DNS

## Goal

Decide, for every mechanism that could move LAN clients onto the DoT, DoH and DoQ listeners of pfB-DNS without
per-device configuration, whether pfB-DNS drives it (a toggle whose effect ends when pfB-DNS is off), whether users set it
up themselves (documentation), or whether it does not apply. The investigation is
[#3554](https://github.com/pfBlockerNG/pfBlockerNG/issues/3554). This specification records the answers to its open
questions, one verdict per candidate, and the follow-up work. It ships no `src/` or `tests/` change.

## Fixed constraints

- ISC dhcpd is out of scope; only the Kea DHCP backend is considered.
- Router Advertisement DNR is not pursued now (owner guidance for #3554: not there yet, minimal gain; pfSense's radvd
  version is not chased).
- pfB-DNS is the Go gateway (`go/pfb_dns_gateway`) in front of Unbound, started by the rc script that
  `pfb_dns_proxy_service()` writes. It serves plain DNS, DoT, DoH (HTTP/1.1 and HTTP/2, no HTTP/3) and DoQ with the
  certificate selected in `dns/pfb_dns_sslcertref` ([dns-gateway-transports.md](../misc/dns-gateway-transports.md),
  "Certificate" and "Listeners").
- A pfB-DNS feature must not leave anything behind in pfSense-owned or user-owned configuration when pfB-DNS is turned off.
- Every registered setting goes through `PfbConfig`.
- Code references in this document are to `devel` at `0a15e0e99d742b90d4ed5e890692aff3975f36fb`. pfSense CE 2.8.1
  references are to the files shipped in its package catalogue, identified below by SHA-256.

## Decisions

### Sources and probes

| Ref | What | Where |
|---|---|---|
| S1 | pfSense CE package catalogues | `packagesite.pkg` of `pfSense_v2_8_0_amd64-pfSense_v2_8_0` and `pfSense_v2_8_1_amd64-pfSense_v2_8_1` at `https://pkg00-atx.netgate.com/`, read 2026-10-22 |
| S2 | pfSense CE 2.8.1 base files (`/etc/inc/services.inc`, `util.inc`, `system.inc`, `/etc/rc.filter_synchronize`, `/usr/local/www/services_dhcp.php`, `/usr/local/bin/kea_run4`) | `All/pfSense-2.8.1.pkg` from S1, SHA-256 `e9c39a5d84cf2addec07b211cba52d510e4a642341c62104c494ed87556917ac` |
| S3 | pfSense ACME package 1.3.2 | `All/pfSense-pkg-acme-1.3.2.pkg` from S1, SHA-256 `69a4616faee5757f45066c89eee85a7d48d19c0c584bad39ff1b5c7da768c7b1` |
| S4 | pfSense `master` `services.inc` (same Kea logic as S2) | [pfsense/pfsense@9363ac5](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/etc/inc/services.inc) |
| P1 | Read-only probe of a pfSense Plus 26.07 appliance, 2026-10-22: `pkg info -x kea acme radvd unbound`, `kea-dhcp4 -V`, `grep` of `/etc/inc/services.inc`, `unbound-control list_local_zones`, `drill @127.0.0.1 _dns.resolver.arpa SVCB` | output quoted where used |

No live CE 2.8.x box was reachable; nothing on any box was changed.

### Answers to the open questions

**Q1. Can the pfSense ACME package request IP-identifier certificates with the `shortlived` profile?** Yes, on paper; an
issuance was not run [UNVERIFIED end to end].

- CE 2.8.1 ships `pfSense-pkg-acme` 1.3.2 (S1); P1 has the same version. CE 2.8.0 shipped 1.0, whose profile support was
  not checked [UNVERIFIED].
- The certificate form accepts an IP address as a domain name (`acme_certificates_edit.php:224-231` in S3) and has a
  "Certificate Profile" field whose help names `shortlived` (`acme_certificates_edit.php:418-425`); the value is passed to
  acme.sh as `--cert-profile` (`acme_sh.inc:217-219`).
- The bundled acme.sh is 3.1.5 (`acme.sh:3`); it sends an IP address as an `ip` identifier (`acme.sh:4886-4892`, used
  at `acme.sh:5151`).
- IP identifiers cannot be validated with DNS-01 ([RFC 8738 §7](https://www.rfc-editor.org/rfc/rfc8738#section-7)).
  The package offers a standalone HTTP server on port 80, a standalone TLS-ALPN server on port 443, and webroot methods
  (`acme.inc:241-320`), so the WAN must accept HTTP-01 or TLS-ALPN-01 validation from Let's Encrypt.
- Let's Encrypt issues IP certificates only as short-lived certificates, valid 160 hours, IPv4 and IPv6
  ([announcement, 2026-01-15](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability);
  [profiles](https://letsencrypt.org/docs/profiles/)).
- Renewal: the package's cron job runs daily at 03:16 (`acme.inc:3839`) and renews at two thirds of the lifetime
  (`acme.inc:4116-4126`), so a six-day certificate is renewed with about four days left. The renewed certificate replaces
  the Certificate Manager entry of the same name, keeping its refid (`acme.inc:3972-3979`), so `dns/pfb_dns_sslcertref`
  stays valid and pfB-DNS pushes the new certificate within one cron tick
  ([dns-gateway-transports.md](../misc/dns-gateway-transports.md), "The control socket").

**Q2. Which clients use opportunistic DDR (RFC 9462 §4.3) for a private resolver IP?** None that pfB-DNS can serve today.

- Apple: "DDR does not work if your DNS server's IP address is a private IP address"
  ([WWDC22, Improve DNS security for apps and servers](https://developer.apple.com/videos/play/wwdc2022/10079/)).
  Apple uses verified discovery only.
- Windows: Microsoft describes DDR as verified only: the discovered resolver "is only used ... if the TLS certificate of
  the server can claim ownership of the original resolver IP address"
  ([Microsoft, 2021-10-27](https://techcommunity.microsoft.com/blog/networkingblog/making-doh-discoverable-introducing-ddr/2887289)).
  DDR is set per interface with `netsh dnsclient set interface ... ddr=yes`; the documentation does not state the default
  ([netsh dnsclient](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-dnsclient),
  dated 2025-07-28). Whether current GA builds enable it by default is [UNVERIFIED].
- Android: DDR exists behind the NetworkStack experiment flag `dns_ddr_version`
  ([NetworkStackUtils.java:253-256](https://android.googlesource.com/platform/packages/modules/NetworkStack/+/83ea07ed94890b52265e07d6760c7ed8f4cbd344/src/com/android/networkstack/util/NetworkStackUtils.java#253),
  [NetworkMonitor.java:679-682](https://android.googlesource.com/platform/packages/modules/NetworkStack/+/83ea07ed94890b52265e07d6760c7ed8f4cbd344/src/com/android/server/connectivity/NetworkMonitor.java#679));
  which devices have the experiment on is [UNVERIFIED]. Where it runs, it is opportunistic in "Automatic" mode (it keeps
  only designated addresses equal to the unencrypted resolver's,
  [DdrTracker.java:364-378](https://android.googlesource.com/platform/packages/modules/NetworkStack/+/83ea07ed94890b52265e07d6760c7ed8f4cbd344/src/com/android/server/connectivity/DdrTracker.java#364)),
  but it reads only SVCB records with ALPN `h3`
  ([DdrTracker.java:399-414](https://android.googlesource.com/platform/packages/modules/NetworkStack/+/83ea07ed94890b52265e07d6760c7ed8f4cbd344/src/com/android/server/connectivity/DdrTracker.java#399)),
  accepts only `dohpath=/dns-query{?dns}`, and connects on port 443
  ([PrivateDnsConfiguration.cpp:652-665](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/4d70e9efa5ae4b5eae682e5267fa09a2d694d23e/PrivateDnsConfiguration.cpp#652),
  [PrivateDnsCommon.h:21](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/4d70e9efa5ae4b5eae682e5267fa09a2d694d23e/PrivateDnsCommon.h#21)).
  The gateway serves no HTTP/3, so Android gains nothing from a pfB-DNS DDR answer.
- No other client with opportunistic DDR was found [UNVERIFIED negative].

**Q3. Where does the SVCB answer belong?** In the Go gateway, answered before the decider. Reasons:

1. The answer depends on the address the client queried: RFC 9462 §4.2 checks the certificate against that address and
   §4.3 allows opportunistic use only when the designated address equals it. The gateway binds one socket per listen
   address and knows the local address of every query: UDP at `go/pfb_dns_gateway/plain.go:181`, TCP and DoT at
   `plain.go:365`, DoH at `doh.go:117`, DoQ at `doq.go:150`. The decider receives only the client's transport and IP
   (`src/usr/local/pkg/pfblockerng/dns_proxy/decision_service.py:60-70`), and Unbound `local-data` is one static answer
   for every client and interface.
2. The gateway runs in every pfB-DNS mode, with or without the DNSBL module (`--no-module`,
   `src/usr/local/pkg/pfblockerng/pfblockerng.inc:4690`), and does not run when pfB-DNS is off. An answer built there
   disappears with pfB-DNS without any cleanup. Unbound `local-data` would have to be written into, and removed again
   from, the Resolver's Custom Options block that pfBlockerNG already manages (`pfblockerng.inc:14869-14879`).
3. The gateway already knows which transports listen on which addresses and ports: its `--dot-listen`, `--doh-listen`,
   `--doq-listen` and port flags (`go/pfb_dns_gateway/main.go:106-115`), built by `pfb_dns_proxy_tls_flags()`
   (`pfblockerng.inc:4351-4382`).
4. It already builds answers itself before the decider: `screen()` returns a REFUSED it builds for ACL-refused clients
   (`go/pfb_dns_gateway/query.go:196-207`, `dnsmsg.go:39`). The DDR answer goes after the ACL check in the same place.

**Q4. Is the Windows 11 DNR client on by default in current GA builds?** Not shown by any primary source. The only
Microsoft source found says client DNR shipped in Insider build 25982, is enabled by setting
`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableDnr` to 1 and rebooting, reads DHCPv4 and DHCPv6 only
(no RA, no ADN-only mode, one DHCPv6 instance)
([Microsoft, 2023-10-25](https://techcommunity.microsoft.com/blog/networkingblog/introducing-dnr-support-for-windows-insiders/3959895)).
The GA default is [UNVERIFIED]; no Windows host was probed. The verdicts do not depend on it.

**Q5. Which Kea version does pfSense 2.8.x ship?** Kea 2.6.2 in both CE 2.8.0 and CE 2.8.1 (S1). P1 (Plus 26.07) runs
Kea 3.0.4 (`kea-3.0.4`, `kea-dhcp4 -V` prints `3.0.4`). The CE 2.9.0 notes list "Upgrade to Kea 3.0.2 #16388"
([2.9.0 notes](https://docs.netgate.com/pfsense/en/latest/releases/2-9-0.html)). All of them are at or above 2.6.0, so the
`v4-dnr` and `v6-dnr` string syntax is available
([Kea 2.6.2 ARM, DHCPv4 DNR](https://kea.readthedocs.io/en/kea-2.6.2/arm/dhcp4-srv.html),
[DHCPv6 DNR](https://kea.readthedocs.io/en/kea-2.6.2/arm/dhcp6-srv.html)).

**Q6. Can a package safely own entries in the Kea Custom Configuration JSON, and is there a hook?** There is no hook, and
owning entries is possible only with risks the owner has to accept (Open forks, F1).

- No hook. `services_kea4_configure()` and `services_kea6_configure()` call no package plugin (S4 has no
  `pkg_call_plugins` call). Kea's run-script hook (`/usr/local/bin/kea_run4` in S2, the
  [run_script library](https://kea.readthedocs.io/en/kea-2.6.2/arm/hooks.html)) passes packet-processing events to
  scripts; it does not add options to a reply [INFERENCE from the documented interface].
- An entry can carry an owner marker: Kea accepts `user-context` on `option-data`
  ([Kea 2.6.2 ARM, User Contexts in IPv4](https://kea.readthedocs.io/en/kea-2.6.2/arm/dhcp4-srv.html)), so a package
  could add `{"name": "v4-dnr", "data": "...", "user-context": {"pfblockerng": "dnr"}}` and later remove exactly the
  entries carrying that marker.
- The merge appends lists: `array_merge_override_recursive()` appends numerically indexed arrays (S2 `util.inc:4153-4175`),
  so an `option-data` entry in custom JSON is added next to the GUI-generated ones.
- Global custom JSON is never tested. In S2, only interface, pool and static-mapping JSON sets `$has_custom`
  (`services.inc:2024-2027`, `2468-2471`, `2481-2488`); the global `kea/custom_kea_config` merge (`services.inc:2531-2536`)
  does not, so the `kea-dhcp4 -t` test and its fallback (`services.inc:2558-2569`) are skipped and Kea is started with
  whatever was merged. The DHCPv6 side is the same (`services.inc:1199-1203`, `1227-1235`). S4 has the same code
  (`services.inc:2571-2576`, `2598-2607`), and P1's `services.inc` sets `$has_custom` at the same three places only.
- Interface JSON is tested, but a failed test restarts Kea with no custom configuration at all (`services.inc:2564-2567`):
  a bad package entry would also drop every custom entry the user wrote, reported only by a DHCP notice.
- The per-interface field is the one that fits DNR, because the advertised address differs per interface. It is
  `dhcpd/<if>/custom_kea_config` (base64 JSON), saved wholesale by the DHCP Server page (`services_dhcp.php:631-636`,
  `824`): the package would have to merge into text the user edits, and re-add its entry if the user deletes it.
- HA sync copies the `dhcpd` and `kea` sections to the peer (`rc.filter_synchronize:248-262`), so a package entry
  carrying the primary's interface address would reach the secondary.
- Two `v4-dnr` entries in one subnet (one the user's, one the package's) were not tested against Kea [UNVERIFIED].

**Q7** was answered in the issue body (no supported path to RA option 144) and is confirmed: CE 2.8.0 and 2.8.1 ship
radvd 2.20 (S1), P1 has `radvd-2.20`, and radvd's `DNR` block exists only on `master` (manual page change
[4c23a8f](https://github.com/radvd-project/radvd/commit/4c23a8fb3234), 2026-08-06), not in the latest release v2.21
(2026-05-25), whose `radvd.conf.5.man` has no DNR entry. pfSense writes `radvd.conf` itself with RDNSS and DNSSL only
(S4 `services.inc:318-348`).

### Verdicts

| # | Candidate | Verdict | Reason |
|---|---|---|---|
| 1 | DNR in DHCPv4/DHCPv6 as a pfB-DNS toggle | Owner decision; recommended: not applicable | No hook exists, and owning entries in user-owned Kea JSON risks an untested Kea start (global JSON) or the loss of all user custom JSON (interface JSON), and spreads through HA sync (Q6). Clients are few: opt-in Windows builds and systemd-networkd v257+ (Q4, [systemd v257 NEWS](https://github.com/systemd/systemd/blob/v257/NEWS)). Options under F1. |
| 2 | DNR as documentation | Documentation | Kea 2.6.2+ on every supported pfSense builds DNR from the string syntax (Q5); users paste a known-good snippet into their own JSON. |
| 3 | DNR in Router Advertisements | Not applicable now | No released radvd supports DNR, pfSense ships radvd 2.20 and generates `radvd.conf` with no custom field (Q7). Revisit only if pfSense ships a DNR-capable radvd and exposes it. |
| 4 | DDR toggle on the pfB-DNS page | Toggle | The gateway can answer per queried address and the answer disappears with pfB-DNS (Q3). Today it helps verified-discovery clients (Apple, Windows with DDR on) reaching a public listener address (candidate 7); for private addresses no current client uses it (Q2). |
| 5 | Opportunistic DoT | Documentation | Already works with no pfB-DNS change: Android's default "Automatic" mode upgrades to DoT if the network's DNS server supports it ([Android, 2018](https://android-developers.googleblog.com/2018/04/dns-over-tls-support-in-android-p.html)), connects to port 853 of each DHCP- or RA-provided server ([DnsTlsServer.h:39](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/4d70e9efa5ae4b5eae682e5267fa09a2d694d23e/DnsTlsServer.h#39), [PrivateDnsCommon.h:22](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/4d70e9efa5ae4b5eae682e5267fa09a2d694d23e/PrivateDnsCommon.h#22)) and verifies no certificate when no hostname is set ([DnsTlsSocket.cpp:238-251](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/4d70e9efa5ae4b5eae682e5267fa09a2d694d23e/DnsTlsSocket.cpp#238)). Verified from source; not run on a device [UNVERIFIED on a device]. |
| 6 | Certificate guidance and warning | Documentation plus a page warning | Verified DDR needs the queried address as an `iPAddress` SAN and a trusted chain (RFC 9462 §4.2); DNR needs the ADN as a name in the certificate (RFC 9463 §3.3). The page today checks only that a certificate is selected (`pfblockerng.inc:4304-4309`). |
| 7 | Public resolver address | Documentation | The only route to verified DDR that Apple accepts (Q2). Feasible with the ACME package (Q1); the costs and failure cases stay as listed in #3554. |

### DDR answer (candidate 4)

- Setting: one toggle on the pfB-DNS page, `dns/pfb_dns_ddr`, off by default, registered through `PfbConfig`. When it is
  on, `pfb_dns_proxy_service()` adds `--ddr` to the gateway command line. A change restarts the gateway, as other
  flag changes do (`pfblockerng.inc:4627-4628`).
- Scope: with `--ddr`, after the ACL check and before the decider, the gateway answers every query for a name at or
  under `resolver.arpa.` itself. Refused or denied clients get what they get today. These answers are not sent to the
  decider and are not written to the DNS reply log.
- `_dns.resolver.arpa.` SVCB IN, received on local address L: one ServiceMode record per encrypted transport whose
  listen set contains L, TTL 300:
  - DoH: priority 1, `alpn=h2`, `port` = the DoH port, `dohpath=/dns-query{?dns}`. No `h3`: the gateway serves no HTTP/3.
  - DoT: priority 2, `alpn=dot`, `port` = the DoT port.
  - DoQ: priority 3, `alpn=doq`, `port` = the DoQ port.
  - TargetName: the firewall's FQDN, `system/hostname` + `.` + `system/domain` (never `.` or `resolver.arpa`, RFC 9462
    §4). pfSense resolves that name only to the LAN address (S2 `system.inc:402-437`), so the answer carries the address
    itself:
  - `ipv4hint` or `ipv6hint` = L, and an A or AAAA record for TargetName = L in the Additional section (RFC 9462 §4).
- No transport listens on L, any other type at `_dns.resolver.arpa.`, or any other name under `resolver.arpa.`: NODATA
  with `resolver.arpa. 10800 IN SOA localhost. nobody.invalid. 1 3600 1200 604800 10800` in the Authority section
  (RFC 9462 §4 and §6.4; the SOA matches Unbound's default zone,
  [unbound.conf.rst:2869-2876 at release-1.26.1](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/doc/unbound.conf.rst)).
- Toggle off, or pfB-DNS off: the gateway does not answer these names. Unbound 1.23.0 and later have `resolver.arpa.` as a
  default static zone ([localzone.c:66-74 at release-1.26.1](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/services/localzone.c#L66-L74);
  absent in release-1.22.0). P1 (Unbound 1.25.2) lists `resolver.arpa. static` and answers the SVCB query with
  NXDOMAIN, not the NODATA that RFC 9462 §4 recommends. That is Unbound's answer and is left as it is. CE 2.8.0 ships
  Unbound 1.22.0 and CE 2.8.1 ships 1.26.1 (S1).
- The certificate needs no SNI-specific handling: the gateway serves the selected certificate whatever the SNI, as
  RFC 9462 §6.3 requires.

### Certificate warning (candidate 6)

Shown on the pfB-DNS page, not blocking a save, computed from the selected certificate's SANs and issuer:

- DDR on and a listen address advertised by DDR is not an `iPAddress` SAN: verified discovery is impossible for that
  address.
- DDR on and TargetName is not a DNS SAN, or a DNR ADN the user documents is not: name-based checks fail.
- The certificate is self-signed or its CA is a pfSense-internal CA: clients verify it only if that CA is installed on
  them.

### Documentation scope (candidates 2, 5, 6, 7)

One user-facing page, "Encrypted DNS discovery with pfB-DNS". The repository has no user-documentation home for pfB-DNS
yet (`docs/misc/` holds developer notes), so the first documentation follow-up to land picks the location and the others
add their sections:

- DNR with Kea (candidate 2): where the per-interface Custom Configuration lives; `v4-dnr` and `v6-dnr` snippets; that
  one instance has one `port`, so DoT and DoQ on 853 and DoH on its own port (4443 by default) are separate instances
  (`|` between DHCPv4 instances, one `option-data` entry per DHCPv6 instance); that Windows takes only one DHCPv6
  instance (Q4); that DNR SvcParams must not contain `ipv4hint` or `ipv6hint` (RFC 9463 §3.1.8); that the ADN must be a
  name in the pfB-DNS certificate; and that the entries must be removed when pfB-DNS or its encrypted transports are
  turned off, because the options would then point at nothing. The #3554 example
  `alpn=dot\\,doq\\,h2 dohpath=/dns-query{?dns}` without a port advertises DoH on 443 and is wrong for the default
  pfB-DNS DoH port.
- Opportunistic DoT (candidate 5): DoT enabled on the interface whose address DHCP hands out, on port 853; Android
  "Automatic" mode; no certificate requirement.
- Certificate guidance (candidate 6): which SANs each mechanism checks, and that public CAs cannot certify private
  addresses (RFC 9462 §4.3).
- Public resolver address (candidate 7): the IPv6 and IPv4 setups, costs and failure cases from #3554, the ACME settings
  from Q1, and that DHCP must hand out the public address for verified DDR (RFC 9462 §4.2).

## Acceptance criteria

These apply to the follow-up work; this specification is met when it is on `devel` with every fork filed.

1. WHEN the DDR toggle is on and a client sends `_dns.resolver.arpa. SVCB` to a pfB-DNS plain listener address L
   THEN the answer has one record per encrypted transport listening on L, with the ALPN, port and `dohpath` above,
   TargetName the firewall FQDN, a hint equal to L, and an A or AAAA record for TargetName equal to L in the Additional
   section.
2. WHEN the DDR toggle is on and the query is another type at `_dns.resolver.arpa.` or any name under `resolver.arpa.`
   THEN the answer is NODATA with the `resolver.arpa.` SOA, and the decider saw no query.
3. WHEN the DDR toggle is off, or pfB-DNS is off, THEN `resolver.arpa.` queries get Unbound's own answer, relayed
   unchanged.
4. WHEN a client the Resolver ACL refuses sends the DDR query THEN it gets REFUSED, as today.
5. WHEN the selected certificate lacks a SAN that an enabled mechanism needs THEN the pfB-DNS page shows the matching
   warning, and the save still succeeds.
6. WHEN reading the documentation page THEN each of its sections states the pfSense, Kea and client versions it was
   checked against, with sources.

## Out of scope

- ISC dhcpd (`numberoptions` custom options included).
- Router Advertisement DNR, a patched radvd, or any pfSense core change (DHCP or RA hooks, generator fields).
- HTTP/3 in the gateway, which Android's DDR would need (Q2).
- Editing pfSense or Kea configuration on any box, unless the owner chooses option B of F1.
- Browser DoH policies (Chrome, Firefox), NetworkManager, dhcpcd: they consume none of these mechanisms (#3554).
- DNR ADN-only mode and resolver-name DDR (RFC 9462 §5).

## Open forks

Each entry becomes a follow-up issue in a later phase of #3554; links replace "(issue to be filed)" when they exist.

- **F1 (candidate 1)** Task, `ready-for-human`: "Decide whether pfB-DNS may own DNR entries in Kea custom configuration"
  (issue to be filed). Options:
  - A. Do not own them; candidate 2's documentation is the only DNR route. Recommended: no hook exists and the risks
    in Q6 fall on the user's DHCP service.
  - B. Own per-interface entries in `dhcpd/<if>/custom_kea_config` and `dhcpdv6/<if>/custom_kea_config`, marked with
    `user-context`, added on pfB-DNS apply and removed on disable, then call `services_kea4_configure()` and
    `services_kea6_configure()`. Accepts: a failed Kea test drops all custom JSON (the user's too), HA sync copies the
    entries to the peer, and a user who deletes an entry gets it back at the next apply.
  - C. Own an entry in the global `kea/custom_kea_config`. Rejected: one address cannot serve every interface, and the
    global JSON is never tested before Kea starts.
- **F2 (candidate 2)** Task: "Document DNR setup with Kea for pfB-DNS" (issue to be filed). Scope: the DNR section of the
  documentation page. Acceptance: snippets for DHCPv4 and DHCPv6 with separate DoH and DoT/DoQ instances, checked with
  `kea-dhcp4 -t` and `kea-dhcp6 -t` on Kea 2.6.2 and 3.0.x, and the removal note.
- **F4 (candidate 4)** Feature: "Answer DDR queries from the pfB-DNS gateway" (issue to be filed). Scope: `--ddr` in the
  gateway, the `dns/pfb_dns_ddr` toggle, the rc command line. Acceptance: criteria 1-4.
- **F5 (candidate 5)** Task: "Document opportunistic DoT for Android with pfB-DNS" (issue to be filed). Scope: the
  opportunistic DoT section. Acceptance: states the port-853 and interface conditions with sources, and is confirmed on
  an Android device (Private DNS "Automatic") against a pfB-DNS DoT listener.
- **F6 (candidate 6)** Feature: "Warn when the pfB-DNS certificate cannot satisfy DDR or DNR" (issue to be filed). Scope:
  the page warning and the certificate section of the documentation page. Acceptance: criterion 5.
- **F7 (candidate 7)** Task: "Document the public-address route to verified DDR" (issue to be filed). Scope: the public
  resolver address section. Acceptance: the IPv4 and IPv6 setups with ACME `shortlived` IP certificates, the WAN rules
  that keep 53, 853 and the DoH port closed to the internet, and the failure cases.

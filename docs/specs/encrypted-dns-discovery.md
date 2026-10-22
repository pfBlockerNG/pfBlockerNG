# Encrypted DNS discovery for pfB-DNS

## Goal

Decide, for every mechanism that could move LAN clients onto the DoT, DoH and DoQ listeners of pfB-DNS without
per-device configuration, whether pfB-DNS drives it (a toggle whose effect ends when pfB-DNS is off), whether users set
it up themselves (documentation), or whether it does not apply. The investigation is
[#3554](https://github.com/pfBlockerNG/pfBlockerNG/issues/3554). This specification records the answers to its open
questions, one verdict per candidate, and the follow-up work. It ships no `src/` or `tests/` change.

Amended 2026-10-22 (owner decision): the optional "Advertised DoH URL" setting is replaced by one toggle,
`dns/pfb_dns_ddr_doh_443` ("Advertise DoH on port 443"); see "DoH on port 443 (candidate 4)".

## Fixed constraints

- ISC dhcpd is out of scope; only the Kea DHCP backend is considered.
- Router Advertisement DNR is not pursued now. The #3554 body records the finding ("either not there yet, or the gain
  is minimal") and the owner confirmed it while this investigation was set up (2026-10-22): pfSense's radvd version is
  not chased.
- pfB-DNS does not write DNR entries into Kea custom configuration (owner decision, 2026-10-22: "docs only, yes"; see
  Decisions, candidate 1).
- pfB-DNS is the Go gateway (`go/pfb_dns_gateway`) in front of Unbound, started by the rc script that
  `pfb_dns_proxy_service()` writes. It serves plain DNS, DoT, DoH (HTTP/1.1 and HTTP/2, no HTTP/3) and DoQ with the
  certificate selected in `dns/pfb_dns_sslcertref` ([dns-gateway-transports.md](../misc/dns-gateway-transports.md),
  "Certificate" and "Listeners").
- A pfB-DNS feature must not leave anything behind in pfSense-owned or user-owned configuration when pfB-DNS is off.
- Every registered setting goes through `PfbConfig`.
- Code references are to `devel` at `0a15e0e99d742b90d4ed5e890692aff3975f36fb`. pfSense CE references are to the
  package files listed under Sources, identified by URL and SHA-256.

## Decisions

### Sources and probes

Netgate publishes two catalogues per CE release on its package mirrors. The live repository,
`https://pkg00-atx.netgate.com/pfSense_v2_8_<n>_amd64-pfSense_v2_8_<n>/`, is the path that
`pkg+https://pkg.pfsense.org/` resolves to (`_https._tcp.pkg.pfsense.org` SRV records name `pkg00-atx.netgate.com` and
`pkg01-atx.netgate.com`) and carries package updates after the release. The snapshot repository,
`https://pkg00-atx.netgate.com/packages/pfSense_v2_8_<n>_amd64-pfSense_v2_8_<n>/`, holds the packages as they were when
the release was built. A CE 2.8.1 box probed on 2026-07-22 ran Unbound 1.24.2
([research note 1557](../research/1557-recipient-local-reply-isolation.md), "Scope"), a version in neither
catalogue today (snapshot 1.23.0, live 1.26.1), so installed boxes take updates from the live repository.

| Ref | What | Where |
|---|---|---|
| S1 | Live CE catalogues, read 2026-10-22 | `packagesite.pkg` of `pfSense_v2_8_0_amd64-pfSense_v2_8_0` and `pfSense_v2_8_1_amd64-pfSense_v2_8_1` under `https://pkg00-atx.netgate.com/` |
| S1s | Snapshot CE catalogues, read 2026-10-22 | the same names under `https://pkg00-atx.netgate.com/packages/` |
| S2 | CE 2.8.1 base files (`/etc/inc/services.inc`, `util.inc`, `system.inc`, `unbound.inc`, `/etc/rc.filter_synchronize`, `/usr/local/www/services_dhcp.php`, `/usr/local/bin/kea_run4`) | `All/pfSense-2.8.1.pkg` in S1, SHA-256 `e9c39a5d84cf2addec07b211cba52d510e4a642341c62104c494ed87556917ac`. The snapshot's `All/pfSense-2.8.1.b.20250729.1541.pkg` (S1s) has the same line references for the files cited here (checked by the spec review). |
| S3 | ACME package 1.3.2 (live CE 2.8.1) | `All/pfSense-pkg-acme-1.3.2.pkg` in S1, SHA-256 `69a4616faee5757f45066c89eee85a7d48d19c0c584bad39ff1b5c7da768c7b1` |
| S3a | ACME package 1.0 (live CE 2.8.0) | `All/pfSense-pkg-acme-1.0.pkg` in S1, SHA-256 `bee2370acd5bd8bdc78bb0fdd847b99b75183a3f758a6735900e9b28bab92d09` |
| S3b | ACME package 0.9_1 (both snapshots) | `All/pfSense-pkg-acme-0.9_1.pkg` in the 2.8.1 snapshot, SHA-256 `edc475947550a366067a87b72c0039eae3307434d2bcdd330a9b3961d5d82a90` |
| S4 | pfSense `master` `services.inc`, 2026-03-31 | [pfsense/pfsense@9363ac5](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/etc/inc/services.inc). It predates the pfSense-SA-26_20 fix (2026-07-21). |
| P1 | Read-only probe of a pfSense Plus 26.07 appliance, 2026-10-22 | `pkg info -x kea acme radvd unbound`, `kea-dhcp4 -V`, `grep` of `/etc/inc/services.inc`, `unbound-control list_local_zones`, `drill @127.0.0.1 _dns.resolver.arpa SVCB`. Probe-only: not reproducible from outside. |

Package versions:

| Package | CE 2.8.0 live | CE 2.8.1 live | CE 2.8.0 / 2.8.1 snapshot | Plus 26.07 (P1) |
|---|---|---|---|---|
| `pfSense-pkg-acme` | 1.0 (acme.sh 3.1.2) | 1.3.2 (acme.sh 3.1.5) | 0.9_1 (acme.sh 3.1.0) | 1.3.2 |
| `kea` | 2.6.2 | 2.6.2 | 2.6.2 | 3.0.4 |
| `unbound` | 1.22.0_1 | 1.26.1 | 1.22.0_1 / 1.23.0 | 1.25.2 |
| `radvd` | 2.20 | 2.20 | 2.20 | 2.20 |

No live CE 2.8.x box was reachable; nothing on any box was changed.

### Answers to the open questions

**Q1. Can the pfSense ACME package request IP-identifier certificates with the `shortlived` profile?** Yes, with ACME
package 1.3.2, which CE 2.8.1 installs from the live repository and Plus 26.07 runs (P1). The owner treats CE 2.8.1 as the
baseline ("everyone ends up in 2.8.1 anyway", 2026-10-22). No issuance was run [UNVERIFIED end to end].

- 1.3.2 (S3): the certificate form accepts an IP address as a domain name (`acme_certificates_edit.php:224-231`) and has
  a "Certificate Profile" field whose help names `shortlived` (`acme_certificates_edit.php:418-425`); the value reaches
  acme.sh as `--cert-profile` (`acme_sh.inc:217-219`). The bundled acme.sh 3.1.5 (`acme.sh:3`) sends an IP address as an
  `ip` identifier (`acme.sh:4886-4892`, used at `acme.sh:5151`).
- Package 1.0 on CE 2.8.0 and 0.9_1 in the snapshots (S3a, S3b) have no certificate profile, so `shortlived` cannot be
  selected there; the baseline is CE 2.8.1.
- IP identifiers cannot be validated with DNS-01 ([RFC 8738 §7](https://www.rfc-editor.org/rfc/rfc8738#section-7)).
  1.3.2 offers a standalone HTTP server on port 80, a standalone TLS-ALPN server on port 443, and webroot methods
  (`acme.inc:241-320`), so the WAN must accept HTTP-01 or TLS-ALPN-01 validation from Let's Encrypt.
- Let's Encrypt issues IP certificates only as short-lived certificates, valid 160 hours, IPv4 and IPv6
  ([announcement, 2026-01-15](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability);
  [profiles](https://letsencrypt.org/docs/profiles/)).
- Renewal in 1.3.2: the cron job runs daily at 03:16 (`acme.inc:3839`), and a certificate is renewed once its remaining
  days are at most `ceil(total / 3) * 2` of its total lifetime in days (`acme.inc:4116-4126`). The exact day count for
  a 160-hour certificate depends on how `cert_get_lifetime()` rounds [UNVERIFIED]. The renewed certificate replaces the
  Certificate Manager entry of the same name and keeps its refid (`acme.inc:3972-3979`), so `dns/pfb_dns_sslcertref`
  stays valid and pfB-DNS pushes the new certificate within one cron tick
  ([dns-gateway-transports.md](../misc/dns-gateway-transports.md), "The control socket").

**Q2. Which clients use opportunistic DDR (RFC 9462 §4.3) for a private resolver IP?** None that pfB-DNS can serve
today.

- Apple: "DDR does not work if your DNS server's IP address is a private IP address"
  ([WWDC22, Improve DNS security for apps and servers](https://developer.apple.com/videos/play/wwdc2022/10079/)).
  Apple uses verified discovery only.
- Windows: Microsoft describes DDR as verified only: the discovered resolver "is only used ... if the TLS certificate of
  the server can claim ownership of the original resolver IP address"
  ([Microsoft, 2021-10-27](https://techcommunity.microsoft.com/blog/networkingblog/making-doh-discoverable-introducing-ddr/2887289)).
  DDR has a global switch, `netsh dnsclient set global ddr=yes`, and a per-interface one,
  `netsh dnsclient set interface name=<interface> ddr=yes`
  ([netsh dnsclient](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-dnsclient),
  dated 2025-07-28); the blog enables both. Neither source states the default; whether current GA builds enable DDR by
  default is [UNVERIFIED].
- Android: DDR exists behind the NetworkStack experiment flag `dns_ddr_version`
  ([NetworkStackUtils.java:253-256](https://android.googlesource.com/platform/packages/modules/NetworkStack/+/83ea07ed94890b52265e07d6760c7ed8f4cbd344/src/com/android/networkstack/util/NetworkStackUtils.java#253),
  [NetworkMonitor.java:679-682](https://android.googlesource.com/platform/packages/modules/NetworkStack/+/83ea07ed94890b52265e07d6760c7ed8f4cbd344/src/com/android/server/connectivity/NetworkMonitor.java#679));
  which devices have the experiment on is [UNVERIFIED]. Where it runs, it is opportunistic in "Automatic" mode: it keeps
  only designated addresses equal to the unencrypted resolver's
  ([DdrTracker.java:364-378](https://android.googlesource.com/platform/packages/modules/NetworkStack/+/83ea07ed94890b52265e07d6760c7ed8f4cbd344/src/com/android/server/connectivity/DdrTracker.java#364)).
  It reads only SVCB records with ALPN `h3`
  ([DdrTracker.java:399-414](https://android.googlesource.com/platform/packages/modules/NetworkStack/+/83ea07ed94890b52265e07d6760c7ed8f4cbd344/src/com/android/server/connectivity/DdrTracker.java#399)),
  accepts only `dohpath=/dns-query{?dns}`, and connects on port 443
  ([PrivateDnsConfiguration.cpp:652-665](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/4d70e9efa5ae4b5eae682e5267fa09a2d694d23e/PrivateDnsConfiguration.cpp#652),
  [PrivateDnsCommon.h:21](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/4d70e9efa5ae4b5eae682e5267fa09a2d694d23e/PrivateDnsCommon.h#21)).
  The gateway serves no HTTP/3, so Android gains nothing from a pfB-DNS DDR answer.
- No other client with opportunistic DDR was found [UNVERIFIED negative].

**Q3. Where does the SVCB answer belong?** In the Go gateway, answered before the decider. Reasons:

1. The answer depends on the address the client queried: RFC 9462 §4.2 checks the certificate against that address and
   §4.3 allows opportunistic use only when the designated address equals it. The gateway binds one socket per listen
   address and knows the local address of every plain query: UDP at `go/pfb_dns_gateway/plain.go:181`, TCP at
   `plain.go:365`. Behind the gateway that address is gone: the decider receives only the client's transport and IP
   (`src/usr/local/pkg/pfblockerng/dns_proxy/decision_service.py:60-70`), and Unbound listens only on loopback for the
   gateway (`pfblockerng.inc:14869-14871`). Unbound's per-interface answers (`interface-view`, `interface-tag-data`)
   key on the interface Unbound itself received the query on, which there is always loopback
   ([unbound.conf.rst at release-1.26.1](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/doc/unbound.conf.rst),
   `interface-view`).
2. The gateway runs in every pfB-DNS mode, with or without the DNSBL module (`--no-module`,
   `src/usr/local/pkg/pfblockerng/pfblockerng.inc:4690`), and does not run when pfB-DNS is off. An answer built there
   disappears with pfB-DNS without any cleanup. Unbound `local-data` would have to be written into, and removed again
   from, the Resolver's Custom Options block that pfBlockerNG already manages (`pfblockerng.inc:14869-14879`).
3. The gateway already knows which transports listen on which addresses and ports: its `--dot-listen`,
   `--doh-listen`, `--doq-listen` and port flags (`go/pfb_dns_gateway/main.go:106-115`), built by
   `pfb_dns_proxy_tls_flags()` (`pfblockerng.inc:4351-4382`).
4. It already builds answers itself before the decider: `screen()` returns a REFUSED it builds for ACL-refused clients
   (`go/pfb_dns_gateway/query.go:196-207`, `dnsmsg.go:39`). The DDR answer goes after the ACL check in the same place.

**Q4. Is the Windows 11 DNR client on by default in current GA builds?** Not shown by any primary source. The only
Microsoft source found says client DNR shipped in Insider build 25982, is enabled by setting
`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableDnr` to 1 and rebooting, and reads DHCPv4 and DHCPv6
only (no RA, no ADN-only mode, one DHCPv6 instance)
([Microsoft, 2023-10-25](https://techcommunity.microsoft.com/blog/networkingblog/introducing-dnr-support-for-windows-insiders/3959895)).
The GA default is [UNVERIFIED]; no Windows host was probed. The verdicts do not depend on it.

**Q5. Which Kea version does pfSense 2.8.x ship?** Kea 2.6.2 in CE 2.8.0 and CE 2.8.1, in both the live and the
snapshot catalogues (S1, S1s). P1 (Plus 26.07) runs Kea 3.0.4 (`kea-dhcp4 -V` prints `3.0.4`). The CE 2.9.0 notes list
"Upgrade to Kea 3.0.2 #16388" ([2.9.0 notes](https://docs.netgate.com/pfsense/en/latest/releases/2-9-0.html)). All are
at or above 2.6.0, so the `v4-dnr` and `v6-dnr` string syntax is available
([Kea 2.6.2 ARM, DHCPv4 DNR](https://kea.readthedocs.io/en/kea-2.6.2/arm/dhcp4-srv.html),
[DHCPv6 DNR](https://kea.readthedocs.io/en/kea-2.6.2/arm/dhcp6-srv.html)).

**Q6. Can a package safely own entries in the Kea Custom Configuration JSON, and is there a hook?** There is no hook,
and owning entries carries risks that fall on the user's DHCP service. The owner chose not to (candidate 1).

- No hook. `services_kea4_configure()` and `services_kea6_configure()` call no package plugin (S4 has no
  `pkg_call_plugins` call). Kea's run-script hook (`/usr/local/bin/kea_run4` in S2, the
  [run_script library](https://kea.readthedocs.io/en/kea-2.6.2/arm/hooks.html)) passes packet-processing events to
  scripts; it does not add options to a reply [INFERENCE from the documented interface].
- An entry could carry an owner marker: Kea accepts `user-context` on `option-data`
  ([Kea 2.6.2 ARM, User Contexts in IPv4](https://kea.readthedocs.io/en/kea-2.6.2/arm/dhcp4-srv.html)).
- The merge appends lists: `array_merge_override_recursive()` appends numerically indexed arrays
  (S2 `util.inc:4153-4175`), so an `option-data` entry in custom JSON is added next to the GUI-generated ones.
- Global custom JSON is never tested. In S2, only interface, pool and static-mapping JSON sets `$has_custom`
  (`services.inc:2024-2027`, `2468-2471`, `2481-2488`); the global `kea/custom_kea_config` merge
  (`services.inc:2531-2536`) does not, so the `kea-dhcp4 -t` test and its fallback (`services.inc:2558-2569`) are
  skipped and Kea is started with whatever was merged. DHCPv6 is the same (`services.inc:1199-1203`, `1227-1235`). S4
  has the same code (`services.inc:2571-2576`, `2598-2607`), and P1's `services.inc` sets `$has_custom` at the same three
  places only.
- Interface JSON is tested, but a failed test restarts Kea with no custom configuration at all
  (`services.inc:2564-2567`): a bad package entry would also drop every custom entry the user wrote.
- The per-interface field, `dhcpd/<if>/custom_kea_config`, is saved wholesale by the DHCP Server page
  (`services_dhcp.php:631-636`, `824`), and HA sync copies the `dhcpd` and `kea` sections to the peer
  (`rc.filter_synchronize:248-262`).
- pfSense treats this JSON as privileged: pfSense-SA-26_20 (announced 2026-08-13) fixed authenticated command execution
  through it in CE 2.9.0 and Plus 26.07; CE 2.8.1 and earlier are affected
  ([advisory](https://docs.netgate.com/downloads/pfSense-SA-26_20.webgui.asc)).

**Q7** was answered in the issue body (no supported path to RA option 144) and is confirmed: CE 2.8.0 and 2.8.1 ship
radvd 2.20 (S1, S1s), P1 has `radvd-2.20`, and radvd's `DNR` block exists only on `master` (manual page change
[4c23a8f](https://github.com/radvd-project/radvd/commit/4c23a8fb3234), 2026-08-06), not in the latest release v2.21
(2026-05-25), whose `radvd.conf.5.man` has no DNR entry. pfSense writes `radvd.conf` itself with RDNSS and DNSSL only
(S4 `services.inc:318-348`).

### Verdicts

| # | Candidate | Verdict | Reason |
|---|---|---|---|
| 1 | DNR in DHCPv4/DHCPv6 as a pfB-DNS toggle | Not applicable (owner decision, 2026-10-22) | No hook exists; owning entries in user-owned Kea JSON risks an untested Kea start (global JSON) or the loss of all user custom JSON (interface JSON), spreads through HA sync, and touches a surface pfSense treats as privileged (Q6). Few clients read DNR: opt-in Windows builds and systemd-networkd v257+ (Q4, [systemd v257 NEWS](https://github.com/systemd/systemd/blob/v257/NEWS)). Candidate 2 is the DNR route. |
| 2 | DNR as documentation | Documentation | Kea 2.6.2 and later, on every supported pfSense, build DNR from the string syntax (Q5); users paste a known-good snippet into their own JSON. |
| 3 | DNR in Router Advertisements | Not applicable now | No released radvd supports DNR; pfSense ships radvd 2.20 and generates `radvd.conf` with no custom field (Q7). Revisit only if pfSense ships a DNR-capable radvd and exposes it. |
| 4 | DDR toggle on the pfB-DNS page | Toggle | The gateway can answer per queried address and the answer disappears with pfB-DNS (Q3). It can help only verified-discovery clients (Apple; Windows with DDR on) that query a public listener address (candidate 7); for private addresses no current client uses it (Q2). Whether Apple and Windows accept DoH on a port other than 443 is [UNVERIFIED]. An optional "Advertise DoH on port 443" toggle omits the DoH `port` for clients that reject one, for DoH behind a reverse proxy on 443. |
| 5 | Opportunistic DoT | Documentation | Works with no pfB-DNS change: Android's default "Automatic" mode upgrades to DoT if the network's DNS server supports it ([Android, 2018](https://android-developers.googleblog.com/2018/04/dns-over-tls-support-in-android-p.html)), connects to port 853 of each DHCP- or RA-provided server ([DnsTlsServer.h:39](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/4d70e9efa5ae4b5eae682e5267fa09a2d694d23e/DnsTlsServer.h#39), [PrivateDnsCommon.h:22](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/4d70e9efa5ae4b5eae682e5267fa09a2d694d23e/PrivateDnsCommon.h#22)) and verifies no certificate when no hostname is set ([DnsTlsSocket.cpp:238-251](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/4d70e9efa5ae4b5eae682e5267fa09a2d694d23e/DnsTlsSocket.cpp#238)). Verified from source, not on a device [UNVERIFIED on a device]. |
| 6 | Certificate guidance and warning | Documentation and page warning for public addresses | Verified DDR needs a trusted chain and the queried address as an `iPAddress` SAN (RFC 9462 §4.2); DNR needs the ADN as a name in the certificate (RFC 9463 §3.3). The page warns, only with the DDR toggle on and only for public listener addresses missing from the certificate's `iPAddress` SANs, and not for the DoH listener when "Advertise DoH on port 443" is on (clients then reach the reverse proxy's certificate). Loopback, private, CGNAT, link-local, ULA and reserved addresses never warn (RFC 9462 §4.3 names the private ones; the rest are not globally routable). It says nothing about CA trust, and nothing about DNR ADNs, which pfB-DNS cannot see in the user's Kea JSON. See "Certificate warning". |
| 7 | Public resolver address | Documentation | The only route to verified DDR that Apple accepts (Q2). An IP certificate from Let's Encrypt needs ACME package 1.3.2 (CE 2.8.1 baseline, Plus 26.07; Q1). With a reverse proxy such as HAProxy on 443, the certificate it serves must carry the queried resolver address as an `iPAddress` SAN ("DoH on port 443"). Costs and failure cases stay as listed in #3554. |

### DDR answer (candidate 4)

- Setting: one toggle on the pfB-DNS page, `dns/pfb_dns_ddr`, off by default, registered through `PfbConfig`. When it
  is on, `pfb_dns_proxy_service()` adds `--ddr` to the gateway command line. A change restarts the gateway, as other flag
  changes do (`pfblockerng.inc:4627-4628`).
- Scope: with `--ddr`, after the ACL check and before the decider, the gateway answers every query for a name at or
  under `resolver.arpa.` itself, on every transport. Refused or denied clients get what they get today. These answers
  are not sent to the decider and are not written to the DNS reply log.
- Designation is given only over plain DNS (UDP and TCP), the transport RFC 9462 §4 defines it for, and the one where
  the gateway's local address is the address the client queried. Over DoT, DoH and DoQ the client already uses an
  encrypted resolver, and for DoH behind a front end the local address is the front end's backend address, not the
  client's destination (`go/pfb_dns_gateway/doh.go:111-117`). There, `_dns.resolver.arpa.` SVCB gets NODATA.
- `_dns.resolver.arpa.` SVCB IN over plain DNS, received on local address L: one ServiceMode record per encrypted
  transport that listens on L and has a certificate loaded (a listener with no certificate fails every handshake,
  [dns-gateway-transports.md](../misc/dns-gateway-transports.md), "Certificate"), TTL 300:
  - DoH: priority 1, `alpn=h2`, `dohpath=/dns-query{?dns}`, and `port` only when the DoH port is not 443. No `h3`:
    the gateway serves no HTTP/3. With `dns/pfb_dns_ddr_doh_443` on, `port` is omitted (see "DoH on port 443").
  - DoT: priority 2, `alpn=dot`, and `port` only when the DoT port is not 853.
  - DoQ: priority 3, `alpn=doq`, and `port` only when the DoQ port is not 853.
  - `port` is a mandatory key for clients ([RFC 9461 §4.2](https://www.rfc-editor.org/rfc/rfc9461#section-4.2)), so a
    client that does not support it ignores the record; leaving it out at the default port avoids that.
  - TargetName: the firewall's FQDN, `system/hostname` + `.` + `system/domain` (never `.` or `resolver.arpa`,
    RFC 9462 §4). pfSense registers that name in the Resolver for the LAN address only (S2 `system.inc:402-459`), so the
    answer carries the address itself:
  - An A or AAAA record for TargetName = L in the Additional section (RFC 9462 §4: SHOULD), and `ipv4hint` or
    `ipv6hint` = L in the record ([RFC 9460 §7.3](https://www.rfc-editor.org/rfc/rfc9460#section-7.3)).
- `resolver.arpa.` SOA: `resolver.arpa. 300 IN SOA localhost. nobody.invalid. 1 3600 1200 604800 300`.
  `resolver.arpa.` NS: `resolver.arpa. 300 IN NS localhost.`. These match Unbound's default zone
  ([unbound.conf.rst:2869-2876 at release-1.26.1](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/doc/unbound.conf.rst))
  except for the TTLs: 300 instead of 10800, so a negative answer is not cached for three hours after a transport is
  enabled.
- Every other query at or under `resolver.arpa.`, and a plain query on an address where no transport qualifies: NODATA
  with that SOA in the Authority section (RFC 9462 §4 and §6.4).
- The certificate needs no SNI-specific handling: the gateway serves the selected certificate whatever the SNI, as
  RFC 9462 §6.3 requires.

### Off state (candidate 4)

With the toggle off, or pfB-DNS off, the gateway does not touch `resolver.arpa.` and the client gets whatever Unbound
answers. This deviates from the "NODATA when the toggle is off" in #3554 on purpose: pfB-DNS off must leave the
Resolver's behaviour unchanged, and the same must hold for its own toggle. What clients get:

- Unbound 1.23.0 and later have `resolver.arpa.` as a default static zone
  ([localzone.c:66-74 at release-1.26.1](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/services/localzone.c#L66-L74);
  absent in release-1.22.0). P1 (Unbound 1.25.2) lists `resolver.arpa. static` and answers
  `_dns.resolver.arpa. SVCB` with NXDOMAIN and the zone SOA, not the NODATA that RFC 9462 §4 recommends; the NXDOMAIN
  was observed on 1.25.2 only. pfB-DNS relays whatever Unbound answers, NXDOMAIN included, unchanged. The owner agreed
  to mirror Unbound's answer (2026-10-22).
- CE 2.8.1, the baseline, runs Unbound 1.26.1 from the live repository (S1), so it has that zone. Unbound 1.22.0_1 on
  CE 2.8.0 has none and forwards `resolver.arpa.` names like any other (RFC 9462 §6.1 says a forwarder SHOULD NOT);
  that is existing behaviour pfB-DNS does not change.

### DoH on port 443 (candidate 4)

- Setting: optional toggle `dns/pfb_dns_ddr_doh_443`, labelled "Advertise DoH on port 443", registered through
  `PfbConfig`, off by default (owner decision, 2026-10-22). Off: the DoH record is as in "DDR answer", with `port`
  exactly when the DoH port is not 443. On: the DoH record omits `port` even when the DoH listener port is not 443.
  Everything else in the record is unchanged: TargetName the firewall FQDN, `ipv4hint` or `ipv6hint` and the Additional
  A or AAAA record = L, `dohpath=/dns-query{?dns}`. It is still emitted only where DoH listens on L with a certificate
  loaded. DoT and DoQ records are unchanged.
- Page: the toggle is rendered disabled (greyed out) when the configured DoH port is already 443, where it would change
  nothing. Help text (owner wording): "Some clients might not accept a port for the DoH server provided over DDR. This
  option removes the port, so clients reach DoH on port 443. If DoH is not already listening on port 443, it will no
  longer be reachable. It is intended for users who, for example, serve multiple sites over HTTPS through a reverse
  proxy, and who are responsible for configuring that reverse proxy correctly."
- Use: the owner runs `https://dns.brait.dev` behind HAProxy (443 to gateway port 4443). With the toggle on, a client
  that follows the record connects to the firewall FQDN on 443, where the reverse proxy answers. Configuring the proxy
  is the user's responsibility; pfB-DNS cannot see it.
- Limit: RFC 9462 §4.2 checks the certificate the client gets on 443 against the resolver address it queried. A
  hostname-only certificate (for example Let's Encrypt for `dns.brait.dev`) therefore does not make DDR verified. It
  matters for verified DDR only with the public-address route (candidate 7) and a reverse-proxy certificate that carries
  the queried resolver address as an `iPAddress` SAN. For DNR (candidate 2) the ADN must be a name in the certificate
  the client reaches (RFC 9463 §3.3), the reverse proxy's when DoH is fronted on 443; the documentation follow-up says
  so.
- No URL, hostname, path, or DoT or DoQ override (owner decision, 2026-10-22). DoQ cannot be fronted by HAProxy, and a
  DoT name is irrelevant to DDR verification, which checks the queried address (RFC 9462 §4.2).

### Certificate warning (candidate 6)

With the DDR toggle on, the pfB-DNS page shows a non-blocking warning for each address an encrypted listener serves that
is classified public and is not an `iPAddress` SAN of the selected certificate (`dns/pfb_dns_sslcertref`). Verified DDR
needs that SAN (RFC 9462 §4.2). Addresses are compared as parsed addresses, not strings.

- Never warned (not public): 127.0.0.0/8, ::1/128, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10,
  169.254.0.0/16, fe80::/10, fc00::/7, plus the reserved ranges 0.0.0.0/8, ::/128, the deprecated site-local range
  fec0::/10 ([RFC 3879 §4](https://www.rfc-editor.org/rfc/rfc3879#section-4)), the documentation ranges
  192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and 2001:db8::/32, and the benchmarking range 198.18.0.0/15. An
  IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is classified by its embedded IPv4 address. Every other address is public.
  RFC 9462 §4.3 names the private ranges (RFC 1918, ULA, link-local) as the ones a public CA cannot certify; the rest
  are reserved or not globally routable, so a missing SAN there is not actionable either.
- With `dns/pfb_dns_ddr_doh_443` on, the DoH listener is excluded: its clients reach the reverse proxy's certificate,
  which pfB-DNS cannot see. DoT and DoQ listeners are still checked.
- No certificate selected: no warning. Saving already requires one when DoT, DoH or DoQ is on.
- No warning about CA trust or DNR ADNs. The owner asked for this scope (2026-10-22). Acceptance criterion 8.

### Documentation scope (candidates 2, 5, 6, 7)

One user-facing page, "Encrypted DNS discovery with pfB-DNS". The repository has no user-documentation home for pfB-DNS
yet (`docs/misc/` holds developer notes); the documentation issue picks the location. Sections:

- DNR with Kea (candidate 2): where the per-interface Custom Configuration lives; `v4-dnr` and `v6-dnr` snippets; that
  one instance has one `port`, so DoT and DoQ on 853 and DoH on its own port (4443 by default) are separate instances
  (`|` between DHCPv4 instances, one `option-data` entry per DHCPv6 instance); that Windows takes only one DHCPv6
  instance (Q4); that DNR SvcParams must not contain `ipv4hint` or `ipv6hint` (RFC 9463 §3.1.8); that the ADN must be a
  name in the pfB-DNS certificate; that the entries must be removed when pfB-DNS or its encrypted transports are turned
  off, because the options would then point at nothing; and that the JSON field is privileged (pfSense-SA-26_20). The
  #3554 example `alpn=dot\\,doq\\,h2 dohpath=/dns-query{?dns}` without a port advertises DoH on 443 and is wrong for
  the default pfB-DNS DoH port. The ADN must be a name in the certificate the client reaches: the pfB-DNS certificate,
  or the reverse proxy's when a reverse proxy such as HAProxy serves DoH on 443 (RFC 9463 §3.3); the instance then
  carries no `port`.
- Opportunistic DoT (candidate 5): DoT enabled on the interface whose address DHCP hands out, on port 853; Android
  "Automatic" mode; no certificate requirement.
- Certificates (candidate 6): which SANs each mechanism checks (DDR: `iPAddress` of the queried address; DNR: the ADN),
  that public CAs cannot certify private addresses (RFC 9462 §4.3), the page warning for public addresses (see
  "Certificate warning"), and that a hostname-only certificate behind a reverse proxy does not make DDR verified (see
  "DoH on port 443").
- Public resolver address (candidate 7): the IPv6 and IPv4 setups, costs and failure cases from #3554, the ACME
  package version and settings from Q1, that DHCP must hand out the public address for verified DDR (RFC 9462 §4.2),
  and the WAN rules that keep 53, 853 and the DoH port closed to the internet.

## Acceptance criteria

These apply to the follow-up work; this specification is met when it is on `devel` with every fork filed.

1. WHEN the DDR toggle is on and a client sends `_dns.resolver.arpa. SVCB` over plain UDP or TCP to a pfB-DNS listener
   address L THEN the answer has one record per encrypted transport listening on L with a certificate loaded, with the
   ALPN, `dohpath` and non-default `port` above, TargetName the firewall FQDN, a hint equal to L, and an A or AAAA
   record for TargetName equal to L in the Additional section.
2. WHEN the DDR toggle is on and the query is another type at `_dns.resolver.arpa.`, any other name under
   `resolver.arpa.`, or `_dns.resolver.arpa.` SVCB over DoT, DoH or DoQ THEN the answer is NODATA with the 300-second
   `resolver.arpa.` SOA, apex SOA and NS queries get those records, and the decider saw none of these queries.
3. WHEN the DDR toggle is off, or pfB-DNS is off, THEN `resolver.arpa.` queries get Unbound's own answer, relayed
   unchanged.
4. WHEN a client the Resolver ACL refuses sends the DDR query THEN it gets REFUSED, as today.
5. WHEN a macOS or iOS client and a Windows client with DDR on use a pfB-DNS listener on a public address with an
   `iPAddress` SAN certificate from a trusted CA THEN each is observed sending its DNS over DoT or DoH after the DDR
   query; the result, including whether DoH on a non-443 port is used, is recorded.
6. WHEN a client opens DoT to the gateway offering ALPN `dot` THEN the handshake succeeds (the DoT TLS configuration sets
   no `NextProtos`, `go/pfb_dns_gateway/tlsconfig.go:89`), and the behaviour is pinned by a test.
7. WHEN reading the documentation page THEN each section states the pfSense, Kea, ACME package and client versions it
   was checked against, with sources.
8. WHEN the DDR toggle is on THEN the pfB-DNS page shows a non-blocking warning for each address an encrypted listener
   serves that is classified public (see "Certificate warning") and is not an `iPAddress` SAN of the selected
   certificate (`dns/pfb_dns_sslcertref`), and for no other address:

   | Case | Result |
   |---|---|
   | Public listener address, certificate has no matching `iPAddress` SAN | Warning that names the address |
   | Public listener address, certificate has the matching `iPAddress` SAN | No warning |
   | Same address written differently (`2606:4700::1` listener, SAN `2606:4700:0:0:0:0:0:1`) | No warning: SANs are compared as parsed addresses, not strings |
   | Only loopback, private, CGNAT, link-local or ULA listener addresses | No warning |
   | Reserved or documentation address (`0.0.0.1`, `::`, `192.0.2.1`, `2001:db8::1`, `198.18.0.1`, `fec0::1`) | No warning |
   | `::ffff:10.0.0.1` (classified by the embedded IPv4) | No warning |
   | `::ffff:8.8.8.8` with no matching SAN | Warning |
   | `dns/pfb_dns_ddr_doh_443` on, the DoH listener serves a public address missing from the certificate | No warning for the DoH listener; DoT and DoQ listeners are still checked |
   | No certificate selected | No warning (saving already requires one for DoT, DoH and DoQ) |
   | DDR toggle off | No warning |

   The page never warns about CA trust or DNR ADNs, and the warning never blocks saving.
9. WHEN `dns/pfb_dns_ddr_doh_443` is off THEN the DoH record carries `port` exactly when the DoH port is not 443. WHEN
   it is on THEN the DoH record carries no `port` and is otherwise identical to the off case (TargetName the firewall
   FQDN, `ipv4hint` or `ipv6hint` and Additional A or AAAA = L, `dohpath=/dns-query{?dns}`), still emitted only where
   DoH listens on L with a certificate loaded, and the DoT and DoQ records are unchanged. WHEN the configured DoH port
   is 443 THEN the page renders the toggle disabled.
10. Removed (owner decision, 2026-10-22): the advertised DoH URL setting and its save-time validation no longer exist.
    The number is kept so references stay stable.
11. WHEN reading the documentation page THEN its Kea DNR section states that the ADN must be a name in the certificate
    the client reaches (the pfB-DNS certificate, or a reverse proxy's when one serves DoH on 443), and its certificate
    section states the limit given under "DoH on port 443".

## Out of scope

- ISC dhcpd (`numberoptions` custom options included).
- pfB-DNS writing Kea configuration (candidate 1).
- Router Advertisement DNR, a patched radvd, or any pfSense core change (DHCP or RA hooks, generator fields).
- URL, hostname or DoT and DoQ overrides for the advertised records (only the port-443 toggle exists, see "DoH on port
  443").
- HTTP/3 in the gateway, which Android's DDR would need (Q2).
- Browser DoH policies (Chrome, Firefox), NetworkManager, dhcpcd: they consume none of these mechanisms (#3554).
- DNR ADN-only mode and resolver-name DDR (RFC 9462 §5).

## Open forks

None. Candidates 1 and 3 are decided as not applicable (Verdicts); candidate 6 is documentation plus a page warning
limited to public addresses. The follow-up work is filed:

- Candidate 4 and the candidate 6 warning: Feature [#3583](https://github.com/pfBlockerNG/pfBlockerNG/issues/3583),
  "pfB-DNS: answer DDR queries from the gateway". Acceptance criteria 1-6, 8 and 9.
- Candidates 2, 5, 6 and 7: Task [#3584](https://github.com/pfBlockerNG/pfBlockerNG/issues/3584),
  "Document encrypted DNS discovery for pfB-DNS (Kea DNR, Android opportunistic DoT, certificates, public-address DDR)".
  Acceptance criteria 7 and 11.

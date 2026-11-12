# Encrypted DNS discovery with pfB-DNS

Choose a mechanism your clients support, then enable the corresponding encrypted listener under
**Firewall > pfBlockerNG > DNS > General**. Discovery is not a policy that forces every device or application to use
pfB-DNS. DNR advertises configuration through DHCP; DDR discovers encrypted service from the DNS address the client
already uses; Android can also try DoT without either mechanism. [RFC 9463 §3.3][dnr-validation],
[RFC 9462 §4][ddr], and [Android's announcement][android-blog] describe these different paths.

This guide lives in `docs/user/pfb-dns/` because it is operator documentation, not a developer note in `docs/misc/`.
It covers Kea only: pfB-DNS does **not** write DNR options for you.
The [design specification](../../specs/encrypted-dns-discovery.md) records that boundary and the investigation.

**Baseline checked on 2026-10-22:** pfSense CE 2.8.1 package sources, Kea 2.6.2, and ACME package 1.3.2 from the
live CE repository; pfB-DNS labels and behavior at [devel `558169c39`][ui]. No CE appliance deployment was tested.
A reachable pfSense Plus 26.07 appliance reported Kea 3.0.4 and ACME 1.3.2; only version queries and scratch-file
configuration checks were run there. The [specification's package inventory][inventory] identifies the CE packages,
URLs, and checksums. Client sources and untested behavior are identified in each section below.

## Shared DNS settings and per-family ports

The top-level **DNS** tab opens **General**. **DNS Reply Logging** and **Resolver addresses** live there, not on
the **DNSBL** sub-tab; the pfB-DNS settings are on the same page. Resolver addresses offers an optional existing VIP or **Create VIP automatically**
for each family; **Automatic VIP interface** defaults to Localhost and applies only to automatic creation.
On a selected VIP, port 443 may already be taken; an automatically created resolver VIP leaves 443 free.

Resolver VIPs remain available with a **Localhost**-only listener selection. Empty selections and selections containing
only down or unusable interfaces do not gain a VIP listener. Loopback remains available independently.

Resolver addresses adds the VIP to the DNS servers of each DHCPv4 scope, each DHCPv6 scope and the Router Advertisement
list, but leaves alone any of those lists that names a server you chose: an address that is neither the interface's own
address nor one pfBlockerNG added. **DNS > General** warns about each list left alone, naming the interface, the list and
those servers; add the Resolver VIP to that list by hand if you want clients to use it. A VIP pfBlockerNG added earlier is
removed from a list when you later add a server of your own to it, and returns when that server is gone. A VIP you added
by hand is never touched. A second address of the interface, such as an IP alias or CARP VIP, counts as a server you chose.
While the interface's own address cannot be determined, for example a tracked IPv6 prefix that is down, a non-empty list is
left exactly as it is, DNS General does not warn about it, and the pfBlockerNG log gets one line for it on each apply.
Disabling Resolver addresses behaves as before.

A Resolver VIP joins the interface addresses; it does not replace them. Plain DNS, DoT, DoH and DoQ listen on the selected
interfaces' addresses and on the VIP, so a host whose DNS setting or lease still names an interface address keeps
working, and DDR answers that address with the listeners it queried. The exception is DoH for an address family whose
**DoH port** is 443: there only the VIP listens, because port 443 on the interface address belongs to the webConfigurator
or a reverse proxy.

A VIP that **Create VIP automatically** made also serves DoH on **port 443**, beside the configured DoH port, while DoH is on (unless
that family's DoH port is already 443). DDR advertises 443 on it with no setting to change, because the gateway serves 443
there. If the box refuses the bind (something else holds 443 on that address), the startup check says `DoH is not served on
<VIP>:443` with the reason, and DDR advertises the configured DoH port on that VIP. A VIP you chose yourself gets no such listener,
since port 443 may already be taken on it.

On a policy receiver, an existing listener VIP is moved only after the published address passes validation and
conflict checks. Equivalent IPv6 spellings reuse the same VIP. A missing or invalid publication is not replaced
by an unrelated local VIP, and unspecified addresses (`0.0.0.0` and `::`) are not valid dedicated listener VIPs.
New VIP ownership is saved with creation, so an advertisement-save failure does not prevent later cleanup.
Disabling the option removes only owned VIPs; uninstall also removes recorded advertisements and reapplies the
affected DHCP and DNS Resolver settings.

Transport controls, the certificate and DDR remain under **DNS > General**. Each transport has an **IPv4** port and
an **IPv6** port; an empty IPv6 port uses the IPv4 value. DDR has one **Advertise DoH on port 443** selection of interfaces
(and Resolver VIPs you chose). It advertises 443 on the addresses of the selected entries; it does not change the listening ports.

DDR omits `port` when the listener uses the transport default (DoH 443, DoT/DoQ 853), the compatible form for clients
that do not understand the port key. A non-default listener port is advertised unless the address is advertised on 443 under
**Advertise DoH on port 443**.

## Check which transport clients use

Open **Firewall > pfBlockerNG > Reports**. The existing **DNSBL** and **DNS Reply** tables show a
**Transport** column: **UDP**, **TCP**, **DoT**, **DoH**, or **DoQ**. Use the corresponding Transport
filter to narrow the rows. Unified reports also retain this information.

This is the transport the client used to reach pfB-DNS, not the connection pfB-DNS or Unbound used
upstream. A trusted DoH reverse proxy can supply the originating client address; the transport remains
**DoH**. Headers from an untrusted peer do not replace the client address.

An em dash (**—**) means the original transport is unavailable, including historical rows and native
Unbound events whose API does not supply that information. It does not mean UDP or unencrypted DNS.
Existing DNSBL logging modes and **DNS > General > DNS Reply Logging** still determine which events
are recorded; enabling a listener does not enable additional query collection.

A DoT, DoH, or DoQ row confirms that query arrived over encrypted DNS. It does **not** establish that
DDR caused the client to choose it.

## DNR with Kea

**Checked against:** CE 2.8.1 [DHCP page and generator sources][ce-package]; Kea 2.6.2 and 3.0.2/3.0.3 containers;
Plus 26.07 / Kea 3.0.4 scratch checks below. ACME 1.3.2 is the baseline but is not needed if you already have a suitable
certificate. Client reference: [Microsoft's Windows Insider build 25982 announcement][windows-dnr] (2023-10-25).
Windows current GA support/defaults and actual DNR uptake of these snippets are **[UNVERIFIED]**; no Windows client
was tested. That announcement requires `EnableDnr=1` under
`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters`, followed by a reboot; do not treat it as proof of
current GA defaults.

### Add the per-interface configuration

1. Confirm **System > Advanced > Networking > DHCP Options > Server Backend** is **Kea DHCP**.
   Open **Services > DHCP Server > [interface]** for IPv4, or **Services > DHCPv6 Server > [interface]** for IPv6. Use the interface's
   **Custom Configuration > JSON Configuration**, not the global **Settings** field or a pool/static mapping.
   The CE 2.8.1 pages `services_dhcp.php:1854-1859` and `services_dhcpv6.php:1414-1419` say this JSON merges into the
   generated subnet and must not include a wrapper key. [DHCPv4 documentation][dhcp4], [CE package][ce-package].
2. Enable the transports and select **SSL/TLS Certificate** on **DNS > General**. Its default ports are DoT TCP 853,
   DoQ UDP 853, and DoH TCP 4443 at `/dns-query`; select the appropriate **DoT Interface(s)**,
   **DoH Interface(s)**, and **DoQ Interface(s)**. Advertise only listeners you actually enabled. [Page source][ui],
   [listener defaults][defaults], [transport reference](../../misc/dns-gateway-transports.md#listeners).
3. Replace `dns.example.com.` with your Authentication Domain Name (ADN), and replace the example addresses with
   client-reachable listener addresses. **The ADN must be a name in the certificate the client reaches** and the
   certificate must chain to a CA the client trusts. For direct connections this is the pfB-DNS certificate; for
   TLS terminated by a reverse proxy it is the proxy's certificate. This is hostname authentication, not DDR's IP
   address check. [RFC 9463 §3.3][dnr-validation].
4. Merge the appropriate object below into the interface's existing JSON, preserving any existing `option-data`
   entries; do not paste a second JSON object alongside it or duplicate an existing DNR option. Save and apply the
   DHCP settings. CE 2.8.1 appends custom option lists to generated lists; its per-interface custom-config test can
   fall back to **all custom configuration disabled** if the merged configuration is invalid
   (`services.inc:1180-1185,1227-1235,2481-2486,2558-2569`; `util.inc:4153-4173`). [CE package][ce-package].

**IPv4 — one `v4-dnr` option, two instances separated by `|`:**

```json
{
  "option-data": [
    {
      "name": "v4-dnr",
      "data": "1, dns.example.com., 192.168.1.1, alpn=h2 port=4443 dohpath=/dns-query{?dns} | 2, dns.example.com., 192.168.1.1, alpn=dot\\,doq port=853"
    }
  ]
}
```

**IPv6 — one `v6-dnr` option-data entry per instance:**

```json
{
  "option-data": [
    {
      "name": "v6-dnr",
      "data": "1, dns.example.com., 2001:db8:1::1, alpn=h2 port=4443 dohpath=/dns-query{?dns}"
    },
    {
      "name": "v6-dnr",
      "data": "2, dns.example.com., 2001:db8:1::1, alpn=dot\\,doq port=853"
    }
  ]
}
```

The IPv6 address is a documentation placeholder, not a usable public address. Private/ULA listener addresses can be
used with DNR because clients authenticate the ADN, not that address. Use a domain you control and a certificate
trusted by your clients. [RFC 3849][documentation-ipv6], [RFC 9463 §3.3][dnr-validation].

These examples follow the [Kea 2.6.2 DHCPv4 DNR][kea4] and [DHCPv6 DNR][kea6] string syntax. The first field is service
priority (lower first); each instance has a single `port` value, so DoH on 4443 must be separate from DoT/DoQ on 853.
Keep the double backslashes in JSON's `alpn=dot\\,doq`. If only one of DoT/DoQ is enabled, advertise only that ALPN.
Do not add `ipv4hint` or `ipv6hint`: DNR already carries addresses, and [RFC 9463 §3.1.8][dnr-checks] requires clients
to discard an option containing either hint. The gateway has no native HTTP/3, so these examples advertise `h2`, not
`h3`. [Gateway transport reference](../../misc/dns-gateway-transports.md#listeners).

**Windows limit:** the cited Insider implementation accepts only **one DHCPv6 DNR instance**, with no ADN-only mode
and no RA DNR support. For those clients, keep just the single IPv6 instance for the service you want them to use
(for example, the DoH entry); do not rely on them choosing between the two entries above. [Microsoft][windows-dnr].

### DoH behind a reverse proxy on 443

If HAProxy or another reverse proxy terminates TLS on 443 and forwards DoH to pfB-DNS on 4443, use the **name on the
proxy's certificate as the DoH ADN**, keep `dohpath=/dns-query{?dns}`, and **remove `port=4443` from the DoH instance**.
Without `port`, DoH uses 443 ([RFC 9461 §4.2][dns-port]). Leave the separate DoT/DoQ instance on 853 unchanged,
with its own certificate's ADN if different. Example DoH instance data for each address family:

```text
1, dns.example.com., 192.168.1.1, alpn=h2 dohpath=/dns-query{?dns}
1, dns.example.com., 2001:db8:1::1, alpn=h2 dohpath=/dns-query{?dns}
```

This does not depend on the DDR toggle. The proxy must really serve DoH at the advertised address, name, path and
port. A hostname-only proxy certificate can satisfy DNR but **does not make DDR verified**: DDR checks the original
resolver IP instead. [RFC 9463 §3.3][dnr-validation], [RFC 9461 §5][doh-svcb], [RFC 9462 §4.2][ddr-verified].

**Remove the DNR entries when pfB-DNS or the advertised encrypted transports are turned off**, or update them before
changing an address/port/certificate name. They are your Kea configuration: pfB-DNS does not remove them, and stale
entries advertise unavailable services. [Design boundary](../../specs/encrypted-dns-discovery.md#fixed-constraints).

**Treat this field as privileged configuration.** [pfSense-SA-26_20][sa] describes authenticated arbitrary command
execution through Kea custom JSON; CE 2.8.1 and earlier are affected, and the fix is in CE 2.9.0 / Plus 26.07.
Restrict access to trusted administrators; these snippets do not fix that vulnerability.

### Executed Kea checks

On 2026-10-22, the two JSON objects above were saved as scratch `v4.json` and `v6.json`, then placed **unchanged** in a
minimal full configuration for `-t`: `Dhcp4`/`Dhcp6`, `interfaces-config: {"interfaces": []}`,
`lease-database: {"type": "memfile", "persist": false}`, `valid-lifetime: 3600`, and a single `subnet4`/`subnet6`
entry with `id: 1`, subnet `192.168.1.0/24` / `2001:db8:1::/64`, plus the snippet's `option-data`.
Files were `kea4.json` and `kea6.json`; `kea4-443.json` / `kea6-443.json` removed only the DoH `port=4443`.
No DHCP service was started. Kea documents `-t` as a configuration load/check followed by exit, **not** a comprehensive
runtime test. [Kea ARM][kea4].

To repeat a container check, put the full scratch configuration described above in `/path/to/scratch/kea4.json`
or `kea6.json`, set `V` to the version and `N` to `4` or `6`, then run:

```sh
docker run --rm --network none \
  --mount type=bind,src=/path/to/scratch,dst=/check,readonly \
  --entrypoint kea-dhcp$N docker.cloudsmith.io/isc/docker/kea-dhcp$N:$V -t /check/kea$N.json
```

| Environment | `kea-dhcp4 -v` / `kea-dhcp6 -v` | Default and proxy variants, v4 + v6 |
|---|---|---|
| ISC containers | `2.6.2` / `2.6.2` | All four `-t` invocations exit 0 |
| ISC containers | `3.0.2` / `3.0.2` | All four exit 0 |
| ISC containers | `3.0.3` / `3.0.3` | All four exit 0 |
| Plus `26.07-RELEASE`, `kea-3.0.4`, `pfSense-pkg-acme-1.3.2` | `3.0.4` / `3.0.4` | All four exit 0 |

The [executed command/version/output transcript][kea-evidence] records the complete scratch configurations,
all commands, output tails, the normal queue-control/reservation warnings, and deletion of the appliance's scratch
files. No live Kea configuration was read or changed, and no service was restarted.
These checks prove syntax acceptance only; DHCP delivery and client switching remain **[UNVERIFIED]**.

## Android opportunistic DoT

**Checked against:** pfB-DNS at [558169c39][ui], baseline CE 2.8.1 / Kea 2.6.2 / ACME 1.3.2 sources;
ACME and DNR options are not required for this mechanism. Client references: Android P's announcement and AOSP
DnsResolver commit `4d70e9efa5ae4b5eae682e5267fa09a2d694d23e`, not a tested device build.
**[UNVERIFIED on a device]**: no Android device was available for a Private DNS **Automatic** test against pfB-DNS.

1. Have DHCP supply the pfB-DNS listener's address as the client's DNS server (or RDNSS in IPv6 Router Advertisements).
   It must be the address actually supplied to the device, not just some other address of the firewall. Android's
   opportunistic path uses those network-provided servers. [AOSP `DnsTlsServer.h`][android-server].
2. Enable **DoT** and include that address's interface in **DoT Interface(s)**, with the family's **DoT Port** set to **853**.
   Permit LAN clients to reach TCP 853. Android's DoT default is 853; changing pfB-DNS to another port will not change
   the client's opportunistic probe port. [AOSP `PrivateDnsCommon.h`][android-common], [pfB-DNS settings source][ui].
3. Leave the device in **Private DNS: Automatic**, rather than **Off** or a provider-hostname mode. Android describes
   automatic upgrade as the default. With no hostname, the cited TLS code does **not** authenticate the certificate;
   a publicly trusted certificate or matching SAN is not required by this client mode. pfB-DNS still needs a selected,
   usable server certificate for TLS to work. This provides opportunistic encryption, **not authenticated DNS** or a
   guarantee against fallback to plaintext. [Android announcement][android-blog],
   [AOSP `DnsTlsSocket.cpp`][android-tls], [RFC 7858 §4.1][opportunistic-dot], [pfB-DNS certificate handling][gateway].

No DDR toggle or Kea DNR option is needed for that attempt. Do not confuse it with Android's experimental DDR/DoH
path: the AOSP implementation in the [specification's Q2](../../specs/encrypted-dns-discovery.md#answers-to-the-open-questions) requires `h3`, port 443 and
`/dns-query{?dns}`; pfB-DNS's native DoH serves HTTP/1.1 and HTTP/2, not HTTP/3. Experiment rollout on actual Android
builds is **[UNVERIFIED]**, and this guide does not claim Android DDR interoperability.

## Certificates and the DDR controls

**Checked against:** CE 2.8.1 / Kea 2.6.2 / ACME 1.3.2 source baseline; Kea does not control DDR certificate checks.
The controls and warning were read at [558169c39][ui]. Client references are iOS 16 / macOS Ventura (13) in
[Apple's WWDC22 presentation][apple]. Microsoft's [2021-10-27 DDR announcement][windows-ddr] describes Windows Insider
Dev builds without a build number; its [netsh reference][netsh] documents the controls. A Windows DDR build/version
tested here is **[UNVERIFIED]**. Actual macOS/iOS and Windows DDR results, including non-443 DoH, are **[UNVERIFIED]**,
pending [pfBlockerNG/pfBlockerNG#3590][client-checks]; no device/build was tested here.

| Mechanism | What the client authenticates |
|---|---|
| Verified DDR | A trusted chain and the **original plain DNS resolver address** as an `iPAddress` SAN, even if the encrypted connection goes to another address. A DNS-name SAN is not a substitute. [RFC 9462 §4.2][ddr-verified]. |
| DNR | A trusted chain and the **ADN** as a name in the certificate the client receives. That is the reverse proxy's certificate when it terminates TLS. [RFC 9463 §3.3][dnr-validation]. |
| Android opportunistic DoT without a hostname | No certificate authentication in the cited implementation. This is not verified DDR. [AOSP TLS code][android-tls]. |

Public CAs cannot issue certificates for private/reserved resolver addresses; RFC 1918, ULA and link-local addresses
therefore do not offer the public-CA route to verified DDR. [RFC 9462 §4.3][ddr-opportunistic],
[CA/Browser Forum Baseline Requirements §7.1.2.7.12][cabf]. A public **hostname** certificate used on a private LAN
can still satisfy DNR if it matches the ADN. It does not satisfy DDR's IP-address check.
See [Public resolver addresses](#public-resolver-addresses) for that separate route.

### The DNS Name

**DNS Name** (`dns/pfb_dns_name`) is the text input right after **SSL/TLS Certificate** on **DNS > General**. It is the target
name DDR gives clients and the one name pfB-DNS answers for itself. There is no predefined name and none is filled in for you.
Like the certificate it is stored per node, never synced, and applied on the next **Update**.

- **Format:** a fully qualified name of at least two labels, each of 1 to 63 ASCII letters, digits and hyphens (not starting or
  ending with one), at most 253 characters, with an optional trailing dot that is not stored. An IP address, a wildcard,
  a single label and `resolver.arpa` or a name under it are refused; an internationalized name is entered as its punycode form.
  Case is kept.
- **What pfB-DNS answers:** `A` and `AAAA` queries for exactly this name (ASCII case-insensitive), after the Resolver ACL, with
  TTL 300, on every transport. The answer depends on the address the query arrived on: an interface address is answered
  with that interface's IPv4 and IPv6 addresses (a query for `A` on `10.0.0.1` gets `10.0.0.1`, whether or not a Resolver VIP is
  active); a Resolver VIP with the VIP and the other family's VIP, if there is one. Where there is no address of the
  family asked for, or the query arrived on loopback or on an address no interface carries, Unbound answers as before.
  Subdomains and every other type (`MX`, `TXT`, `HTTPS`, ...) are Unbound's too.
- **No name:** DDR answers nothing (Unbound answers `resolver.arpa`, as with DDR off) and pfB-DNS intercepts no query.
  Turning **DDR** on without a name is refused when you save: *DDR needs a DNS name: enter the name the certificate
  covers, or turn DDR off.*
- **Upgrading:** a box that had DDR on before the name existed answers no DDR queries until you enter one. No name is chosen for you,
  not even the firewall's hostname.
- **Certificate:** clients that connect by the name, DDR's target included, need it among the certificate's DNS names
  (`dNSName` SANs); `*.example.lan` covers `fw.example.lan` but not `example.lan` or `a.fw.example.lan`. The page warns when
  it does not (below).

### Read the applied status

**DNS > General > pfB-DNS Status** shows the running gateway's **DNS Name**, not an unapplied form value.
**DDR Advertisements** shows its current per-address advertisements and local DNS Name answers.
The page refresh reads one snapshot from pfB-DNS's existing private control socket, without querying every listener.

- **None** means pfB-DNS is off/not active, or the running gateway deliberately has no DNS Name.
- **Unavailable** means pfB-DNS is in use or expected to run but its applied status could not be obtained or validated.
  Saved settings are not shown as applied. A still-running gateway keeps its applied name while a saved disable is pending.
- Advertisements describe what pfB-DNS would answer locally. They do **not** verify client reachability,
  reverse-proxy routing, certificate trust or encrypted endpoint connectivity.

An update pass or cron tick leaves an existing gateway running when its status is unavailable or the Resolver backend is down.
**Service** then shows **Starting**, not **Running**; this does not prove DNS is answering.
A foreign process on the port Unbound's backend uses is the exception: pfB-DNS moves Unbound's backend to a free loopback port pair,
or stops the gateway when no move is possible, and a notice says which. It never gives the Resolver back by itself, only turning it
off does. A start that does not serve is reported and left running.

Rare IPv4-compatible (`::/96`) and mapped address spellings retain the existing acceptance behavior and may show
unavailable or refused status. Their normalization is tracked separately in
[#3849](https://github.com/pfBlockerNG/pfBlockerNG/issues/3849).

### DDR and DoH on port 443

Under **Discovery of Designated Resolvers (DDR)** on **DNS > General**:

- **DDR — Enable** (`dns_shared/pfb_dns_ddr`): experimental, disabled by default, applied on the next **Update**. It lets
  pfB-DNS answer `resolver.arpa` discovery queries, naming the **DNS Name** as the target, so it needs one. A plain DNS query
  to an address gets designation only for encrypted transports listening on that address with a certificate loaded. With DDR
  disabled, or pfB-DNS off, the DNS Resolver answers as before. Enabling it alone does not make private-address DDR usable by
  Apple clients.
- **Advertise DoH on port 443** (`dns/pfb_dns_ddr_doh_443_interfaces`): a multi-select, empty by default, applied on the next
  **Update**, node-local like the DoH interface list it is drawn from. Its entries are the **DoH Interface(s)** (never Localhost) and each
  Resolver VIP you chose under **Resolver addresses**, shown by its address; the VIP the package created is not offered, because it
  serves DoH on 443 itself. On the addresses of a selected entry DDR advertises DoH **without a `port`**, so clients use 443, while
  pfB-DNS keeps listening on its configured DoH port there; every other address advertises its own DoH port. Selecting an interface
  advertises that interface's addresses only, never a Resolver VIP that joins them: choose the VIP separately. It changes no listening
  port, name, path, DoT/DoQ record or proxy. It has no effect without DDR enabled, and it only helps where a reverse proxy really answers
  DoH on 443 at that address.
- **Upgrading** from the two checkboxes of the first DDR version (Nightly builds only): they are ignored, so the selection starts empty.
  Choose the interfaces again. The select is never disabled: an interface whose family is on 443 is not listened on for DoH (the VIP
  serves it), so selecting it advertises nothing there.

These are the [shipped labels/help text][ui] and [gateway behavior][gateway]. The page help warns that some clients might not
accept a port for the DoH server provided over DDR, and that the proxy must really serve DoH on 443 there: if DoH is not reachable on
port 443 at an advertised address, clients that follow DDR no longer reach it.

DDR advertises the **DNS Name**, whatever the firewall's own hostname and domain are, and not a separately chosen DNR ADN.
Configure the reverse proxy to route SNI/HTTP Host for that name to DoH and to present the certificate with the original resolver IP SAN.
[Gateway behavior][gateway], [RFC 9461 §5][doh-svcb], [RFC 9462 §6.3](https://www.rfc-editor.org/rfc/rfc9462#section-6.3).

For a listener on 4443, only enable this if you have configured a working client-facing DoH service on 443, for
example HAProxy forwarding to pfB-DNS. **A hostname-only certificate on that proxy does not make DDR verified**;
its certificate must also contain the original queried resolver IP as an `iPAddress` SAN. The toggle neither fixes
that certificate nor makes DHCP hand out a public resolver address. [RFC 9462 §4.2][ddr-verified].

Apple documents automatic DDR from iOS 16/macOS Ventura but excludes private resolver IPs. Microsoft describes verified
DDR and documents global and interface DDR switches in `netsh dnsclient`; the default in current Windows GA builds is
**[UNVERIFIED]**. Do not treat the toggles as proof that any particular client has switched. [Apple][apple],
[Microsoft][windows-ddr], [netsh][netsh], [pending client checks][client-checks].

### The DNS Name warnings

One non-blocking warning concerns the name; it does not depend on the address warning below.

> DNS Name: the selected SSL/TLS Certificate has no DNS name (dNSName) SAN for NAME; clients that connect by that name will
> not accept it.

appears when a name is set, DoT, DoH or DoQ is on, a certificate is selected and none of its `dNSName` SANs is the name or a
wildcard that covers it (`*.example.lan` covers exactly one label under `example.lan`; the comparison ignores ASCII case).
An `iPAddress` SAN never covers a name. It is shown with DDR off too, because the name is also what pfB-DNS answers `A` and
`AAAA` for. Like the address warning below it reads the SANs as one text, so a crafted SAN could hide it.

### The public-address certificate warning

With DDR on, a **DNS Name** set and an **SSL/TLS Certificate** selected, the page warns about public encrypted-listener addresses missing
from that certificate's `iPAddress` SANs. The message names the address and transports:

> DDR: DoT on ADDRESS will not be used by clients that verify DDR, because the selected SSL/TLS Certificate has no IP
> address (iPAddress) SAN for it.

This is a non-blocking warning, not certificate validation: it does **not** check CA trust, expiry, or DNR ADNs.
It does not warn for loopback, RFC 1918, CGNAT, link-local, ULA, documentation, benchmarking, deprecated site-local or
other explicitly excluded ranges, or for a public IPv6 address (a global IPv6 prefix changes, so a missing SAN there
cannot be fixed). It compares parsed addresses, so equivalent IPv6 spellings match.
For an address that is advertised under **Advertise DoH on port 443** **and** where DoH does not listen on 443, DoH is excluded because
pfB-DNS cannot see the proxy's certificate; DoT and DoQ are still checked. If DoH itself listens on 443 there, it is checked even
if the address is selected. The VIP the package created is checked like any other address, and being private it never warns. With DDR off, no DNS Name or no selected certificate, no address warning is shown. The exact excluded ranges and
conditions are in the [shipped warning implementation][warning]. Absence of a warning is not proof of verified DDR.

## Public resolver addresses

**Checked against:** CE 2.8.1 package sources, Kea 2.6.2 syntax checks, ACME package 1.3.2 (bundled acme.sh 3.1.5),
and the Plus 26.07 version probe above. Client references: iOS 16 / macOS 13 and Microsoft's Windows Insider Dev
DDR announcement (2021-10-27, no build number). A tested Windows version is **[UNVERIFIED]**.
**[UNVERIFIED end to end]**: no IP certificate issuance/renewal or IPv4/IPv6 client deployment was performed;
real-client DDR is pending [#3590][client-checks]. These are setup instructions, not measured results.

Verified DDR checks the address used for the **initial plain DNS query**. DHCP must therefore hand out the public
address as the DNS server; for IPv6 clients using RDNSS instead, advertise that same public address there. Merely
putting a public address in a DDR answer while clients query a private address does not work.
[RFC 9462 §4.2][ddr-verified], [DHCP DNS Server setting][dhcp4].

| Setup | Listener and LAN reachability | What breaks it |
|---|---|---|
| IPv6 | Use a global IPv6 address of the firewall's **LAN interface**, from the delegated prefix; listen for plain and encrypted DNS there. LAN clients reach it without NAT. | ISP prefix changes invalidate the address, DHCP/RDNSS advertisement and IP certificate. |
| IPv4 | Use the firewall's own **public WAN IPv4 address**; listen there for plain and encrypted DNS. LAN traffic is addressed to the firewall itself, not sent through a port forward to another host. Permit it on LAN. | Dynamic WAN changes invalidate the advertisement/certificate. A CGNAT address (`100.64.0.0/10`) is not publicly certifiable; with double NAT the firewall's WAN address is not the upstream public address. |

Select **DNS Interface(s)** and the desired **DoT/DoH/DoQ Interface(s)** on **DNS > General** to include those addresses
(LAN for the IPv6 design, WAN for the IPv4 design). Interface selection binds its addresses, not just one chosen IP.
After an address or prefix change, use **Update** to rebind listeners as well as updating DHCP/RDNSS and the
certificate; the old listener addresses were resolved at the preceding apply.
[Page controls][ui], [interface binding](https://github.com/pfBlockerNG/pfBlockerNG/blob/558169c3928f2c23076149d6dc764c59b2bf6843/src/usr/local/pkg/pfblockerng/pfblockerng.inc#L4104-L4148).

These designs and failure cases come from the [public/private address investigation][public-design]. Treat both as
**[UNVERIFIED deployments]** here. LAN-originated traffic is governed by LAN/floating rules rather than simply the WAN
tab; check for DNS redirects or policy-routing rules that would alter the destination. [pfSense processing order][pf-order].
For double NAT, this guide supplies no forwarding workaround; use DNR or opportunistic DoT instead if appropriate.

### Obtain and maintain an IP certificate

1. On the **CE 2.8.1 baseline**, install/update **ACME package 1.3.2** from the live package repository. Its form accepts
   IP identifiers and exposes **Certificate Profile**, passed as `--cert-profile` to acme.sh. CE 2.8.0's live ACME 1.0
   and the 0.9_1 snapshots lack that profile field; this guide uses CE 2.8.1. [Package inventory][inventory],
   [ACME 1.3.2 source package][acme-package] (`acme_certificates_edit.php:224-231,418-425`, `acme_sh.inc:217-219`).
2. For Let's Encrypt, enter the public IPv4 and/or IPv6 address as the identifier and set **Certificate Profile** to
   **`shortlived`**. Let's Encrypt IP certificates support both families and last **160 hours** (just over six days).
   [Let's Encrypt announcement][le-ip].
3. Choose **HTTP-01** or **TLS-ALPN-01** validation; **DNS-01 cannot validate an IP identifier**. The package offers
   **Standalone HTTP server** (80) and **Standalone TLS-ALPN server** (443), among its methods. The HTTP method's
   **IPv6** checkbox says “Bind to IPv6 instead of IPv4.” Choose the binding appropriate to the identifier;
   IPv6 issuance is **[UNVERIFIED]** here. Arrange inbound validation access and handle port conflicts with the GUI
   or reverse proxy yourself; the 443 DDR toggle does not do this.
   [RFC 8738 §§5-7][ip-validation], [ACME package][acme-package] (`acme.inc:287-320`).
4. Select the resulting Certificate Manager certificate in pfB-DNS's **SSL/TLS Certificate**, or install it on the
   client-facing reverse proxy if that is where TLS terminates. Ensure its SANs cover **every address** clients use for
   verified DDR, and that clients trust the chain. If also using DNR, include the ADN name in the certificate clients
   reach. [RFC 9462 §4.2][ddr-verified], [RFC 9463 §3.3][dnr-validation], [pfB-DNS settings source][ui].
5. Automate and monitor renewal before relying on the six-day lifetime. ACME 1.3.2 runs its renewal cron daily at 03:16;
   the exact renewal day for a 160-hour certificate is **[UNVERIFIED]**. pfB-DNS can push a changed selected certificate
   on apply/its 15-minute cron tick without restarting listeners; verify the certificate actually served, including
   the proxy if used. [ACME source][acme-package] (`acme.inc:3839,4116-4126`),
   [certificate reload reference](../../misc/dns-gateway-transports.md#the-control-socket).

### Keep DNS private even though its address is public

Permit intended LAN clients and the Resolver ACL to reach the public address, then enable **DDR** as described above.
Do **not** expose an open resolver. Keep WAN access to **UDP/TCP 53**, **TCP 853** (DoT), **UDP 853** (DoQ), and the
**DoH TCP port** (4443 by default, or 443 when fronted there) blocked for both address families. Check floating rules,
port forwards and any reverse-proxy frontend as well as WAN rules. The listener binding is not a firewall policy.
[pfB-DNS listeners](../../misc/dns-gateway-transports.md#listeners), [pfSense rule order][pf-order].

Permit only the required ACME challenge service: inbound TCP 80 for HTTP-01, or TLS-ALPN validation on TCP 443.
If 443 is also your DoH frontend, it must allow the challenge **without** allowing internet clients to use `/dns-query`;
otherwise choose HTTP-01 or a different arrangement. A blanket allow rule for 443 would expose that DoH frontend.
[RFC 8738 §§4-6](https://www.rfc-editor.org/rfc/rfc8738#section-4), [pfSense processing order][pf-order]. Verify DNS ports are blocked from an external
network and that LAN clients still resolve using the intended address; neither check was performed for this guide
**[UNVERIFIED]**. Keep fallback/recovery access available before changing DHCP/RDNSS to a WAN-dependent address.

[ui]: https://github.com/pfBlockerNG/pfBlockerNG/blob/558169c3928f2c23076149d6dc764c59b2bf6843/src/usr/local/www/pfblockerng/pfblockerng_dns.php#L136-L369
[defaults]: https://github.com/pfBlockerNG/pfBlockerNG/blob/558169c3928f2c23076149d6dc764c59b2bf6843/src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc#L2433-L2515
[warning]: https://github.com/pfBlockerNG/pfBlockerNG/blob/558169c3928f2c23076149d6dc764c59b2bf6843/src/usr/local/pkg/pfblockerng/pfblockerng.inc#L4456-L4558
[gateway]: https://github.com/pfBlockerNG/pfBlockerNG/blob/558169c3928f2c23076149d6dc764c59b2bf6843/docs/misc/dns-gateway-transports.md
[inventory]: ../../specs/encrypted-dns-discovery.md#sources-and-probes
[ce-package]: https://pkg00-atx.netgate.com/pfSense_v2_8_1_amd64-pfSense_v2_8_1/All/pfSense-2.8.1.pkg
[acme-package]: https://pkg00-atx.netgate.com/pfSense_v2_8_1_amd64-pfSense_v2_8_1/All/pfSense-pkg-acme-1.3.2.pkg
[kea4]: https://kea.readthedocs.io/en/kea-2.6.2/arm/dhcp4-srv.html#dnr-discovery-of-network-designated-resolvers-options-for-dhcpv4
[kea6]: https://kea.readthedocs.io/en/kea-2.6.2/arm/dhcp6-srv.html#dnr-discovery-of-network-designated-resolvers-options-for-dhcpv6
[kea-evidence]: https://github.com/pfBlockerNG/pfBlockerNG/issues/3584#issuecomment-6346132368
[dhcp4]: https://docs.netgate.com/pfsense/en/latest/services/dhcp/ipv4.html
[dnr-checks]: https://www.rfc-editor.org/rfc/rfc9463#section-3.1.8
[dnr-validation]: https://www.rfc-editor.org/rfc/rfc9463#section-3.3
[doh-svcb]: https://www.rfc-editor.org/rfc/rfc9461#section-5
[dns-port]: https://www.rfc-editor.org/rfc/rfc9461#section-4.2
[ddr]: https://www.rfc-editor.org/rfc/rfc9462#section-4
[ddr-verified]: https://www.rfc-editor.org/rfc/rfc9462#section-4.2
[ddr-opportunistic]: https://www.rfc-editor.org/rfc/rfc9462#section-4.3
[sa]: https://docs.netgate.com/downloads/pfSense-SA-26_20.webgui.asc
[windows-dnr]: https://techcommunity.microsoft.com/blog/networkingblog/introducing-dnr-support-for-windows-insiders/3959895
[windows-ddr]: https://techcommunity.microsoft.com/blog/networkingblog/making-doh-discoverable-introducing-ddr/2887289
[netsh]: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-dnsclient
[apple]: https://developer.apple.com/videos/play/wwdc2022/10079/
[client-checks]: https://github.com/pfBlockerNG/pfBlockerNG/issues/3590
[android-blog]: https://android-developers.googleblog.com/2018/04/dns-over-tls-support-in-android-p.html
[android-server]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/4d70e9efa5ae4b5eae682e5267fa09a2d694d23e/DnsTlsServer.h#39
[android-common]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/4d70e9efa5ae4b5eae682e5267fa09a2d694d23e/PrivateDnsCommon.h#22
[android-tls]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/4d70e9efa5ae4b5eae682e5267fa09a2d694d23e/DnsTlsSocket.cpp#238
[opportunistic-dot]: https://www.rfc-editor.org/rfc/rfc7858#section-4.1
[documentation-ipv6]: https://www.rfc-editor.org/rfc/rfc3849
[cabf]: https://cabforum.org/working-groups/server/baseline-requirements/requirements/#712712-subscriber-certificate-subject-alternative-name
[le-ip]: https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability
[ip-validation]: https://www.rfc-editor.org/rfc/rfc8738#section-7
[public-design]: https://github.com/pfBlockerNG/pfBlockerNG/issues/3554
[pf-order]: https://docs.netgate.com/pfsense/en/latest/nat/process-order.html

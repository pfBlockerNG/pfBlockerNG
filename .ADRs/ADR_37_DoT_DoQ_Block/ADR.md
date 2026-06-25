# ADR-37: Optional firewall BLOCK of DNS-over-TLS and DNS-over-QUIC (port 853)

- **Status:** **Implemented** (2026-06-23) — see the implementation note below.
- **Date:** 2026-06-20
- **Branch:** `adr/37-dot-doq-block` (off `devel`)
- **Folds in maintainer's working config** (config.xml filter "Block DNS-over-TLS (DoT)" —
  ground truth for the exact rule shape; see §2.2)
- **Component(s):** `src/usr/local/pkg/pfblockerng/pfblockerng.inc` (rule builder + sync
  wiring), `src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc` (PfbConfig registry — 5 new
  fields, incl. `dnsbl_dot_block_action` + `dnsbl_dot_block_floating`; see Addendum 2026-06-25),
  `src/usr/local/pkg/pfblockerng/pfblockerng_fwobj.inc` (ADR-35 registration),
  `src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php` (UI control block)
- **Target runtime:** PHP 8.3 (pfSense CE 2.8)
- **Test suite:** `tests/php/` (PHPUnit, off-appliance), `tests/smoke/` (ADR-04 live-VM),
  `tests/smoke/ui/` (ADR-14 `ui_render`)
- **Depends on:** ADR-35 (Managed Firewall Objects) — the ADR-35 seam
  (`pfb_fwobj_register` / `pfb_fwobj_find` / `pfb_fwobj_remove` / `pfb_fwobj_sweep`,
  ownership-by-descr-marker) must be in place before Phase 2 of this ADR.
- **Sibling of:** ADR-36 (DNS Redirection) — same UI page, same interface-selector pattern,
  same PfbConfig approach; keep consistent.

> **Implementation note (2026-06-23, issue #476).** The shipped DoT/DoQ block rule is built,
> reconciled, and removed **inline in `pfblockerng.inc`** (`sync_package_pfblockerng()`), NOT
> through the ADR-35 `pfb_fwobj_*` seam: that generic framework was retired and
> `pfblockerng_fwobj.inc` / `pfblockerng_dns_bypass.inc` were deleted (#476). It ships as a single
> `inet46` `filter/rule` per interface, carrying a deterministic managed-rule tracker so the GUI can
> manage it and change-detection doesn't churn. The "Depends on: ADR-35" and `pfblockerng_fwobj.inc`
> references above are historical; the object-shape decisions in §2 still hold and are what ships.
>
> **Addendum (2026-06-25) — rule action is now selectable; default Reject.** The DoT/DoQ block
> rules are outbound (LAN→WAN) rules. The original shape hardcoded `type=block` (a silent drop),
> but pfBlockerNG's own outbound deny auto-rules default to **Reject** (`outbound_deny_action`,
> IP settings) so the client fast-fails to plain DNS instead of letting the encrypted-DNS
> connection hang until timeout. The rules now **default to Reject** and expose a user-selectable
> **Rule Action** (Block | Reject) on the DNSBL settings page, mirroring the inbound/outbound Rule
> Action selector on the IP settings page. This adds a **fourth** registered field,
> `dnsbl_dot_block_action` (default `'reject'`). The `<type>block</type>` invariant in §2.2 is
> superseded accordingly — see the updated invariant there. Because the feature is unreleased
> (4.0.0 alpha), the absent-key default flips existing alpha installs to Reject on upgrade with no
> grandfather seed: there was no user-chosen disposition to preserve (the prior value was an
> implicit hardcode), and Reject is the corrected default the change exists to establish.
>
> The same addendum adds the **Floating Rule** option (`dnsbl_dot_block_floating`, toggle,
> default off) — the "future maintainer decision moves to floating" path anticipated in the
> §3 alternative below. **On** builds a **single floating rule** (`floating=yes`, `quick=yes`,
> **`direction=in`** — explicitly set, per that note) over all selected interfaces, with the
> shared `pfB_DoT_Block_Floating` marker; **off** keeps the per-interface default. The action
> (Reject/Block), interface selection, and exception alias apply unchanged in both modes. The
> sync reconcile prunes the other mode's rule(s) when the toggle flips. This brings the field
> count to **five**.

## 1. Context

pfBlockerNG's DNSBL blocks known-bad domains at the resolver level. Clients that bypass the
pfSense resolver via encrypted DNS channels — specifically **DNS-over-TLS (DoT, RFC 7858)** or
**DNS-over-QUIC (DoQ, RFC 9250)** — are never subject to DNSBL matching. Both protocols use
**port 853** as their well-known port, making them distinguishable at the firewall layer.

The conventional mitigation is a `filter/rule` BLOCK on destination port 853. The maintainer
runs exactly this rule manually today (the ground-truth config.xml entry this ADR formalises).
Without pfBlockerNG management, the rule has no ownership marker and is never swept on
uninstall.

**DNS-over-HTTPS (DoH, port 443)** is explicitly **not** addressed here. Blocking port 443
would break all HTTPS traffic. The correct countermeasure for DoH is the DNSBL feed approach:
known DoH resolver IPs are already present in the **Dibdot DoH-IP** and similar IP feeds that
pfBlockerNG can block at the IP-alias layer, and known DoH hostnames are blockable at the DNSBL
domain layer. This ADR covers only port 853 (DoT + DoQ).

ADR-36 (DNS Redirection) closes the plaintext port-53 bypass. ADR-37 closes the encrypted
port-853 bypass. Together they form the standard port-based encrypted-DNS containment, alongside
the DoH-IP feed approach for port 443. Neither ADR alone provides a complete encrypted-DNS seal:
a client using DoH over 443, DoT/DoQ on a non-standard port, or DoH over Tor would still
bypass. That limitation is documented explicitly.

Load-bearing facts:

- **A single `inet46` BLOCK rule covers both IPv4 and IPv6.** The maintainer's working rule uses
  `ipprotocol inet46` — a single filter rule matching both address families. This is simpler
  than ADR-36's per-family split (which was required because NAT redirect targets are
  family-specific; a BLOCK rule has no such constraint).
- **Protocol `tcp/udp`** in one rule covers both DoT (TCP 853) and DoQ (UDP 853) without
  requiring two separate rules.
- **Self-exempt is mandatory and always on.** The firewall must never block its own outbound
  connections to port 853 — the firewall may itself act as a DoT/DoH/DoQ server in a future
  pfSense release, and must not block its own traffic. Implemented via destination
  `<network>(self)</network><not/>` — negated, so the firewall's own traffic to port 853 is
  excluded from the block.
- **The existing filter-rule rebuild** already strips and rebuilds all `pfB_`-prefixed rules
  on each `sync_package_pfblockerng()` call (see `pfblockerng.inc:13709`). The managed DoT/DoQ
  block rules carry the `pfB_` marker prefix and are naturally covered by this rebuild. The
  ADR-35 registration additionally provides the explicit sweep for disable and uninstall paths.
- **No live pf in CI** — the rule builder is unit-tested off-appliance against config-shaped
  fixtures; the real pf interaction is a live-VM smoke (ADR-04).
- **Marker collision with ADR-36 is not possible** — distinct marker prefixes:
  `pfB_DoT_Block_<iface>` (this ADR) vs `pfB_DNS_Redirect_<iface>_v4/v6` (ADR-36).

## 2. Decision

Add an **optional, default-off** firewall block feature. When enabled, pfBlockerNG creates and
maintains one `filter/rule` BLOCK entry per selected interface — blocking all traffic from any
source to any non-self destination on port 853 (TCP + UDP) on that interface. The rules are
registered as ADR-35 managed objects (pfBlockerNG-marker ownership) and are created, reconciled,
and removed through the ADR-35 seam. No ADR-35 marker/teardown logic is re-invented here.

### 2.1 Per-area decision

| Area | Decision |
| --- | --- |
| Feature scope | Port-853 TCP+UDP BLOCK only. DoH (443) is out of scope (see §2.3); blocking 443 would break HTTPS. |
| Protocol | `tcp/udp` in a single rule — covers DoT (TCP 853) and DoQ (UDP 853) simultaneously. |
| IP protocol | `inet46` — one rule covers both IPv4 and IPv6 clients. No per-family split needed (block has no family-specific target, unlike NAT redirect). |
| Source | `<any>` by default. An optional **free-text exceptions field** (zero or more entries — each an IP / CIDR / host or an existing alias name; "these hosts get direct encrypted DNS") — when non-empty, applied as a negated source (an alias when a single alias name is given, else the inline address set) so listed hosts bypass the block. Each entry PFBL-01-validated. |
| Destination | Always: negated `(self)` (`<network>(self)</network><not/>`) + port 853. Firewall-self exemption is structural and cannot be disabled. |
| State type | `keep state` — matches the maintainer's ground-truth rule. |
| Firewall-self exemption | **Always on and non-disableable.** The firewall may itself serve DoT/DoH/DoQ in future; blocking its own port-853 traffic would be self-defeating. Structural via negated `(self)`. |
| Interface selection | Multi-select using `pfb_build_if_list(FALSE, FALSE)` (WAN-excluded), stored comma-joined (plain string) — **reuse the "Permit Firewall Rules" pattern** (`dnsbl_allow_int`, `pfblockerng_dnsbl.php:2921`), mirroring ADR-36 exactly. Quick-fill option tracks the pfBlockerNG fw-rule interface set. |
| Rule count per interface | 1 filter BLOCK rule per selected interface (not 4 like ADR-36 — no NAT, no associated filter; just the single block rule). |
| Ownership + lifecycle | Each rule carries a pfBlockerNG descr marker (`pfB_DoT_Block_<iface>` — exact naming confirmed at implementation time against the `pfB_` codebase convention). Registered via `pfb_fwobj_register()` per ADR-35. Created/reconciled idempotently on `sync_package_pfblockerng()`; removed on disable; swept on uninstall via `pfb_fwobj_sweep()`. |
| Reconcile (stale-interface pruning) | On each sync, rules for interfaces no longer in the selected set are pruned by the marker sweep. An interface removed from config is treated as absent. |
| Config fields | 5 new registered `PfbConfig` fields in `pfblockerngdnsblsettings/config/0` (see §2.2). The fourth (`dnsbl_dot_block_action`, Rule Action; default `reject`) and fifth (`dnsbl_dot_block_floating`, Floating Rule; default off) were added in the Addendum 2026-06-25. ADR-29 5-step adding process. |
| Rule action (disposition) | **Reject by default**, user-selectable Block \| Reject (Addendum 2026-06-25). These are outbound LAN→WAN rules, so Reject matches `outbound_deny_action` and fast-fails the client to plain DNS; Block silently drops. |
| Rule mode | **Per-interface by default** (one rule per selected interface). Opt-in **Floating Rule** (Addendum 2026-06-25) builds a single floating rule (`floating=yes`, `quick=yes`, `direction=in`) over all selected interfaces instead. Marker `pfB_DoT_Block_Floating`. |
| UI location | DNSBL settings page (`pfblockerng_dnsbl.php`) — new control block adjacent to ADR-36's redirect control and the existing DoH/DoT/DoQ blocking section. Enable checkbox + interface multi-select + quick-fill + optional exception-alias field + brief help text. Server-side PFBL-01 validation before any rule build. |
| Naming (config keys + marker) | **Provisional** — follow the `dnsbl_*` / `*_int` sibling convention beside `dnsbl_allow_int` and the ADR-36 keys: `dnsbl_dot_block` (enable toggle), `dnsbl_dot_block_int` (interface list), `dnsbl_dot_block_exclude` (exception alias). Final names aligned with the maintainer before keys are frozen (CLAUDE.md "Naming — follow the established pattern"; storage freeze applies once chosen). |
| Complementary features | Port-853 block + ADR-36 port-53 redirect together close the standard-port bypass paths. Port 443 DoH is handled by the DoH-IP feed (IP-alias layer) and DNSBL domain blocking — not by this ADR. |

### 2.2 Semantics that MUST be preserved / hold (the contract — pin with tests)

**Ground-truth rule shape** (from the maintainer's working config.xml; every field below is
mandatory and exactly matched):

```xml
<rule>                                          <!-- filter/rule -->
  <type>reject</type>                           <!-- default; 'block' selectable (Addendum 2026-06-25) -->
  <interface>lan</interface>                    <!-- one rule per selected interface -->
  <ipprotocol>inet46</ipprotocol>              <!-- single rule covers IPv4 + IPv6 -->
  <protocol>tcp/udp</protocol>                 <!-- DoT (TCP 853) + DoQ (UDP 853) -->
  <source><any></any></source>                 <!-- <any> when no exception alias -->
  <!-- when exception alias is set: -->
  <!-- <source><address>ALIAS</address><not></not></source> -->
  <destination>
    <network>(self)</network><not></not>        <!-- firewall self-exempt, always on -->
    <port>853</port>
  </destination>
  <statetype><![CDATA[keep state]]></statetype>
  <descr><![CDATA[pfB_DoT_Block_lan]]></descr> <!-- pfBlockerNG ownership marker -->
</rule>
```

Invariants (each asserted by PHPUnit tests with full branch coverage):

- **Type follows the Rule Action setting** (Addendum 2026-06-25): `reject` by default, `block`
  when the user selects it. No generated rule has any other type; an unknown/absent stored value
  resolves to the Reject default. Both dispositions are asserted by PHPUnit branch-coverage tests.
- **`ipprotocol` is always `inet46`.** One rule covers both families; no per-family split.
- **`protocol` is always `tcp/udp`.** Covers both DoT (TCP) and DoQ (UDP) in one rule.
- **Destination is always negated `(self)` with port 853** — the firewall-self-exempt is
  structurally present in every generated rule. No code path produces a rule without it.
- **Source is negated-alias when exception alias is set; `<any>` when alias is empty.**
  Both branches produce structurally valid rules. The transition (empty → set → empty)
  round-trips stably.
- **`statetype` is `keep state`** on every generated rule.
- **`descr` carries the pfBlockerNG marker** (`pfB_DoT_Block_<iface>`) and is the sole
  ownership signal (ADR-35 contract).
- **Multiple interfaces → one rule per interface.** Each carries the interface name in its
  marker; they are independent and independently prunable.
- **Disable removes all owned rules** (marker sweep via ADR-35). A user filter rule (no marker)
  is never touched.
- **Reconcile is idempotent** — calling the builder twice with identical settings produces the
  same config.xml state; no duplicate rules accumulate.
- **Stale-interface rules are pruned on reconcile** — an interface removed from the selection
  has its rule removed on the next sync.
- **New config fields round-trip** through `PfbConfig` (ADR-29 backward-compat contract):
  `write(read(v)) == v` for every stored vocabulary value.

### 2.3 Explicitly kept / out of scope

- **DoH (DNS-over-HTTPS) port blocking** — explicitly out. Blocking port 443 would break all
  HTTPS traffic. DoH is addressed at the domain level via DNSBL feeds (known DoH hostnames) and
  at the IP level via the Dibdot DoH-IP and similar IP feeds. This ADR does not attempt to
  intercept or block DoH.
- **Non-standard port DoT/DoQ** — out. This rule blocks only the well-known port 853. A client
  using DoT/DoQ on a non-standard port bypasses this rule; that gap is inherent and documented.
- **Per-client or per-subnet policies beyond the single exception alias** — out. One alias covers
  the use case; per-row policies are a future extension.
- **Creating/managing an alias object** — out. The exceptions field is a plain reference: it
  accepts inline IP/CIDR/host entries and/or the name of an alias the user maintains through the
  normal pfSense Firewall → Aliases UI. pfBlockerNG does not create or own that alias.
- **Changing the filter-rule rebuild model** — out. The existing `pfB_`-prefix rebuild-each-sync
  already handles the block rules. ADR-35 registration is additive.
- **Renaming or modifying existing pfBlockerNG filter markers** — out (storage freeze, ADR-28).
  This ADR introduces the `pfB_DoT_Block_<iface>` marker only.
- **Changing `pfb_remove_config_settings()` or the ADR-35 sweep logic** — out. The sweep is
  provided by ADR-35; this ADR registers through it.

## 3. Consequences

**Positive**

- Stops LAN clients from bypassing pfBlockerNG DNSBL via encrypted DNS on the standard port —
  DoT (TCP 853) and DoQ (UDP 853) are blocked at the firewall before the connection completes.
- Firewall-self exemption is structural (negated `(self)`) — cannot be accidentally removed;
  the firewall's own outbound to port 853 is never disrupted.
- One `inet46` rule per interface is simpler than per-family rules — less config churn, clearer
  intent.
- Lifecycle managed via ADR-35 (register/reconcile/remove/sweep) — no bespoke teardown code;
  consistent with the ADR-36 sibling.
- Default off — zero impact on existing installations that do not opt in.
- Config fields are registered in `PfbConfig` with ADR-29 backward-compat invariants; an older
  release ignores the keys (inert), a rollback preserves them for roll-forward.

**Negative / risks**

- **Risk: blocking legitimate port-853 traffic.** Port 853 is exclusively assigned to DoT/DoQ
  (IANA). Blocking it should not affect normal LAN traffic; however, any self-hosted DoT
  resolver on the LAN that clients should be able to reach is blocked too. Documented in help
  text; out of scope to gate on resolver topology.
- **Risk: incomplete encrypted-DNS coverage.** Port-853 block stops standard-port DoT/DoQ. A
  client using DoH over port 443, DoT/DoQ on a non-standard port, or DoH over Tor still
  bypasses. Documented limitation; complementary to ADR-36 and the DoH-IP feed.
- **Risk: user exception alias mismatch** (alias name changed or deleted outside pfBlockerNG).
  If the alias no longer exists, pfSense treats it as matching nothing — the source `<not/>`
  negation means the block applies to everyone; effectively the exception is lost. Documented in
  help text.
- **Risk: interface churn leaving stale rules.** Mitigated by reconcile-time stale-prune (marker
  scan for rules belonging to interfaces no longer in the selected set).

**Alternative considered — floating block rule instead of per-interface**

A floating block rule with direction `in` on all selected interfaces would achieve similar effect
with fewer config.xml entries. The maintainer notes floating rules are probably the right choice
for most users. However, the `in`/`out`/`any` direction selector on floating rules has caused
real bugs in pfSense integrations in the past: a floating rule without an explicit direction (or
with the wrong direction) can have surprising or silently-wrong behaviour.

Per-interface block rules avoid the direction footgun entirely — they apply at the interface
level without a direction selector, matching client egress on the LAN side with no ambiguity.
This is the safer default for an automated, managed rule.

If a future maintainer decision moves to floating, the direction MUST be set explicitly to `in`
and the smoke test MUST verify the pf rule is active and effective. The block-rule builder is
designed to be upgraded to floating cleanly (a single field change in the rule array).

**Update (Addendum 2026-06-25): floating is now an opt-in option, not the default.** Rather than
choosing one model, the **Floating Rule** toggle (`dnsbl_dot_block_floating`, default off) lets the
user pick: off keeps the safe per-interface default; on builds the single floating rule with
`direction=in` set explicitly (honouring the requirement above), verified by a live-VM smoke case
(`test_dot_doq_block_floating_mode_single_rule`). The per-interface model remains the default
precisely because of the direction footgun described above.

## 4. Requirements (acceptance)

- A pure `pfb_build_dot_block_rule($settings)` builder function returning the exact rule array
  matching the §2.2 ground-truth shape, for any combination of interface, exception alias state
  (set/empty), and number of interfaces.
- The builder registered via `pfb_fwobj_register()` (ADR-35); create/reconcile/remove/sweep
  wired into `sync_package_pfblockerng()` and the disable/uninstall paths.
- Five new `PfbConfig`-registered fields: `dnsbl_dot_block` (toggle), `dnsbl_dot_block_int`
  (plain string), `dnsbl_dot_block_exclude` (plain string), `dnsbl_dot_block_action` (plain
  string, `block` | `reject`, default `reject`), and `dnsbl_dot_block_floating` (toggle, default
  off — both Addendum 2026-06-25) — ADR-29 5-step process, including `CfgGatewayTest.php`
  round-trip tests + inventory update + `$registeredPaths` in the sniff.
- UI control block on `pfblockerng_dnsbl.php`: enable checkbox + interface multi-select +
  quick-fill + exception-alias field + help text (noting DoH/443 is handled by the DoH-IP feed,
  not this control); server-side PFBL-01 validation.
- All gates green (§5); live-VM smoke proves the full lifecycle.

## 5. Constraints (from CLAUDE.md)

- PHP tabs, PHP 8.3; no `die()`/`exit()` in library code.
- **ADR-28**: uppercase `TRUE`/`FALSE`; storage freeze (new stored vocabulary defined once and
  never changed; existing markers are immutable).
- **ADR-29**: three new fields registered in `PfbConfig` via the 5-step process. The managed
  section (`filter/rule`) stays pfSense-core foreign → direct `config_*_path`, NOT `PfbConfig`.
  The sniff's `$registeredPaths` must be updated for all three new keys.
  `pfblockerng_extra.inc` is excluded from the sniff (the gateway itself).
- **ADR-35**: use `pfb_fwobj_register` / `pfb_fwobj_find` / `pfb_fwobj_remove` /
  `pfb_fwobj_sweep` exclusively. Do NOT re-invent marker detection, teardown logic, or orphan
  sweep.
- **PFBL-01**: the rule builder and any UI form handler that accepts interface names or alias
  names is an in-scope input-handling surface. Add the new functions to the PHPCS
  `scopeFunctions` allow-list; validate interface names against `pfb_build_if_list()` output and
  alias names via `pfb_filter()` / `is_validaliasname()` before any rule construction or path
  composition.
- **ADR-04 smoke** for the end-to-end create/disable/uninstall lifecycle and pf table
  verification.
- **ADR-14 `ui_render`** for the modified DNSBL settings page.

## 6. Action plan

### Phase 1 — Config fields + golden rule-builder tests

- Prompt: `01_Config_Fields_And_Builder_Tests.txt`
- Register the three new `PfbConfig` fields in `pfb_cfg_registry()` (`pfblockerng_extra.inc`):
  `dnsbl_dot_block` (toggle adapter, stored `'on'`/`''`, default `''`),
  `dnsbl_dot_block_int` (plain adapter, stored comma-joined string, default `''`),
  `dnsbl_dot_block_exclude` (plain adapter, stored string, default `''`).
  Follow the ADR-29 5-step process: registry entry + `since: '4.0.0'` + round-trip verify +
  `CfgGatewayTest.php` (round-trip + default-absent) + inventory update +
  `$registeredPaths` in `RequireConfigGatewaySniff.php`.
- Write a pure `pfb_build_dot_block_rule($iface, $exclude_alias)` skeleton function in
  `pfblockerng.inc` (or a new helper include — implementer's call based on code size). The
  function takes: interface name (string), exception alias string (may be empty). It returns a
  single filter rule array matching the §2.2 ground-truth field-for-field.
- **Tests (oracle first):** PHPUnit golden tests pinning the exact rule structure. Required
  branches:
  - (a) exception alias empty → source is `<any>`;
  - (b) exception alias set → source is negated-alias;
  - (c) multiple interfaces → one independent rule per interface, each with the correct marker;
  - (d) descr marker is `pfB_DoT_Block_<iface>` (exact interface name in marker);
  - (e) type is `block`, ipprotocol `inet46`, protocol `tcp/udp`, destination negated `(self)`
    - port 853, statetype `keep state` — all asserted in every branch.
  All branches before the builder implementation is wired to any live sync.
- Tests: `CfgGatewayTest.php` round-trip for all three new fields.

### Phase 2 — Builder implementation + ADR-35 registration + sync wiring

- Prompt: `02_Builder_And_Sync.txt`
- FIRST, read the prior phase's handoff:
  `.ADRs/ADR_37_DoT_DoQ_Block/RESULTS/01_Results.txt`
  and the ADR-35 implementation in `pfblockerng_fwobj.inc`. If either is missing, STOP and
  report.
- Complete the `pfb_build_dot_block_rule()` implementation so it passes all Phase-1 golden
  tests.
- Register the builder via `pfb_fwobj_register()` (ADR-35): spec includes type `filter`, the
  `pfB_DoT_Block_` marker prefix, and the builder callable. Read `pfblockerng_fwobj.inc` first
  to confirm the exact spec shape before implementing.
- Wire create/reconcile into `sync_package_pfblockerng()`: when `dnsbl_dot_block == 'on'`, build
  and write one rule per selected interface; when off or no interfaces selected, remove all owned
  rules (marker sweep). On each sync, prune rules for any interface no longer in the selected set
  (stale-interface reconcile).
- Tests: reconcile is idempotent (two syncs → same config); disable removes all
  `pfB_DoT_Block_*` rules while a seeded user filter rule (no marker) survives; stale-interface
  rules are pruned on the next sync (rule for removed interface is gone; rule for retained
  interface stays).

### Phase 3 — UI on the DNSBL settings page + PFBL-01 validation

- Prompt: `03_UI.txt`
- FIRST, read the prior phase's handoff:
  `.ADRs/ADR_37_DoT_DoQ_Block/RESULTS/02_Results.txt`
  and the ADR-36 UI implementation at `pfblockerng_dnsbl.php` ~2921 for the exact
  `Form_Group('Permit Firewall Rules')` + `pfb_build_if_list()` pattern. If either is missing,
  STOP and report.
- Add a new control block in `pfblockerng_dnsbl.php` adjacent to ADR-36's redirect control and
  the existing DoH/DoT/DoQ section. Block contains:
  - (a) enable checkbox bound to `dnsbl_dot_block`;
  - (b) interface multi-select (`pfb_build_if_list(FALSE, FALSE)`, WAN-excluded, pre-selected
    from `dnsbl_dot_block_int`) — same `Form_Group` pattern as ADR-36 and `dnsbl_allow_int`;
  - (c) a quick-fill button/link that populates the multi-select with the union of the current
    `inbound_interface` + `outbound_interface` values (the pfBlockerNG fw-rule interface set);
  - (d) exception-alias free-text field bound to `dnsbl_dot_block_exclude`;
  - (e) brief help text (style matches neighbouring text) noting: (i) blocks standard-port
    DoT (TCP 853) and DoQ (UDP 853) only; (ii) DoH (port 443) is handled by the DoH-IP feed,
    not this control — blocking 443 would break all HTTPS; (iii) the exception alias must exist
    in Firewall → Aliases; (iv) the firewall itself is always exempt.
- Server-side POST handler: validate selected interface names against `pfb_build_if_list()`
  output before accepting; validate alias name via `pfb_filter()` / `is_validaliasname()` if
  non-empty (PFBL-01 surface — add the handler function to PHPCS `scopeFunctions`).
- Save via `PfbConfig::write()` for all three registered fields.
- Tests: PHPUnit for the server-side validator (valid/invalid interface name; valid/empty/invalid
  alias); ADR-14 `ui_render` for `pfblockerng_dnsbl.php` (200, no PHP errors, page marker
  present, no new `php_error.log` line).

### Phase 4 — Smoke + DoD + docs

- Prompt: `04_Smoke_DoD_Docs.txt`
- FIRST, read the prior phase's handoff:
  `.ADRs/ADR_37_DoT_DoQ_Block/RESULTS/03_Results.txt`. If missing, STOP and report.
- ADR-04 live-VM smoke (`tests/smoke/test_dot_doq_block.py` or appended to an existing smoke
  file). Required cases:
  - **Enable path:** enable on the LAN interface → assert the block rule appears in
    `config.xml` with the `pfB_DoT_Block_lan` marker, type `block`, ipprotocol `inet46`,
    protocol `tcp/udp`, destination negated `(self)` + port 853; assert `pfctl -sr` shows the
    rule active.
  - **Disable path:** disable → assert all `pfB_DoT_Block_*` entries removed from `config.xml`;
    assert `pfctl -sr` shows no pfBlockerNG port-853 block rules.
  - **User-rule survival:** seed a user filter rule (no marker) before enable; after disable +
    uninstall, assert the user rule survives untouched.
  - **Stale-interface prune:** enable on two interfaces, then reduce to one → assert the rule
    for the removed interface is gone; the retained interface rule remains.
  - **Exception alias branch (config.xml assertion):** enable with a non-empty alias → assert
    source is `<address>ALIAS</address><not/>` in config.xml; enable with empty alias → assert
    source is `<any>` (both branches).
  - **Uninstall sweep:** install + enable → uninstall → assert all `pfB_DoT_Block_*` gone, no
    pfBlockerNG-owned filter/rule entries remain, and `installedpackages/pfblockerng*` gone.
  - **Self-exempt assertion (CI-feasible gate):** `pfctl -sr` shows the block rule present;
    verify the rule carries the `!<self>` guard (or equivalent pfSense pf output confirming the
    self-exempt is active). Full client-to-:853 block behaviour requires a second host and is a
    documented maintainer manual-smoke item (see §7).
- `docs/misc/architecture-notes.md` blurb covering the DoT/DoQ block feature, the inet46
  single-rule design, the self-exempt mechanism, and the complementary relationship with ADR-36
  (port-53 redirect) and the DoH-IP feed.
- ADR-14 `ui_render` for `pfblockerng_dnsbl.php` (if not already green from Phase 3 CI).

## 7. Definition of done

- [x] `pfb_build_dot_block_rule()` passes all golden tests — exact §2.2 rule shape, all
      branches (alias set/empty, multiple interfaces, type/ipprotocol/protocol/destination/
      statetype/marker all asserted).
- [x] Three `PfbConfig`-registered fields (`dnsbl_dot_block`, `dnsbl_dot_block_int`,
      `dnsbl_dot_block_exclude`) with ADR-29 round-trip + forward/backward invariants green
      (`CfgGatewayTest.php`, `RollbackContractTest.php`).
- [x] ADR-35 registration in place; create/reconcile/remove/sweep exercised for the DoT/DoQ
      block rule set (idempotent, stale-prune, user-rule survival — all asserted).
- [x] UI control block on `pfblockerng_dnsbl.php`: enable + multi-select + quick-fill +
      exception alias + help text (DoH/443 note included); server-side PFBL-01 validation.
- [x] All gates green: `vendor/bin/phpunit`, PHPStan, PHPCS (PFBL-01 + ADR-28 + ADR-29 sniffs),
      `php -l`, `python -m pytest`, ADR-14 `ui_render`.
- [ ] Live-VM smoke proves: block rule appears on enable with correct shape + `pfctl -sr`
      confirms active; rule removed on disable; user rule survives uninstall; stale-interface
      prune works; self-exempt guard confirmed in `pfctl -sr` output.

**Manual smoke (owner: maintainer):**

- [ ] Enable DoT/DoQ block on LAN → attempt a TCP connection from a LAN client to an external
      host on port 853 → confirm the connection is blocked (firewall drops it).
- [ ] Confirm the firewall's own outbound port-853 connections are NOT blocked (self-exempt
      working).
- [ ] Populate the exception alias with a client IP → confirm that client can reach port 853
      (exception bypass working).
- [ ] Enable on LAN + OPT1 → disable on OPT1 only → confirm OPT1 rule gone, LAN rule remains.
- [ ] Uninstall pfBlockerNG with DoT/DoQ block enabled → confirm no `pfB_DoT_Block_*` rules
      remain in Firewall → Rules and no dangling entries.

**Reject criteria:** if the `inet46` ipprotocol is not supported for a BLOCK rule in the pfSense
version targeted (CE 2.8 / FreeBSD 15), **reduce** to two per-family rules (inet + inet6,
mirroring ADR-36's split) with updated tests and docs. If the ADR-35 registration seam cannot
cover a pure filter-block rule (vs NAT + filter atomicity required by ADR-36), **reduce** to a
direct `pfB_`-prefix filter rebuild (the existing rebuild-each-sync model) with a documented
seam limitation.

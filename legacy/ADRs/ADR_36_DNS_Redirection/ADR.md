# ADR-36: Optional NAT DNS-redirection rule set (DNS hijack)

- **Status:** **Implemented** (2026-06-23) — see the implementation note below.
- **Date:** 2026-06-20
- **Branch:** `adr/36-dns-redirection` (off `devel`)
- **Folds in maintainer's working config** (config.xml NAT "Redirect DNS IPv4/IPv6" — ground
  truth for the exact rule shape; see §2.2)
- **Component(s):** `src/usr/local/pkg/pfblockerng/pfblockerng.inc` (rule builder + sync wiring),
  `src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc` (PfbConfig registry — 3 new fields),
  `src/usr/local/pkg/pfblockerng/pfblockerng_fwobj.inc` (ADR-35 registration),
  `src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php` (UI control block)
- **Target runtime:** PHP 8.3 (pfSense CE 2.8)
- **Test suite:** `tests/php/` (PHPUnit, off-appliance), `tests/smoke/` (ADR-04 live-VM),
  `tests/smoke/ui/` (ADR-14 `ui_render`)
- **Depends on:** ADR-35 (Managed Firewall Objects) — the ADR-35 seam
  (`pfb_fwobj_register` / `pfb_fwobj_find` / `pfb_fwobj_remove` / `pfb_fwobj_sweep`,
  ownership-by-descr-marker) must be in place before Phase 2 of this ADR.

> **Implementation note (2026-06-23, issue #476).** The shipped redirect NAT is built, reconciled,
> and removed **inline in `pfblockerng.inc`** (`sync_package_pfblockerng()`), NOT through the ADR-35
> `pfb_fwobj_*` seam: that generic framework was retired and `pfblockerng_fwobj.inc` /
> `pfblockerng_dns_bypass.inc` were deleted (#476). One NAT rdr per interface × family carries
> `associated-rule-id => 'pass'`, so pfSense emits the inline `rdr pass` and owns the companion
> firewall rule — no hand-rolled or separately-tracked filter rule. The "Depends on: ADR-35" and
> `pfblockerng_fwobj.inc` references above are historical; the object-shape decisions in §2 still
> hold and are what ships.

## 1. Context

pfBlockerNG's DNSBL blocks DNS resolution of known-bad domains at the resolver level. However,
clients that are configured with a hardcoded external DNS server (e.g. `8.8.8.8`) bypass Unbound
entirely and are never subject to DNSBL matching. The result is a security gap: a device on a
LAN interface can evade pfBlockerNG DNSBL by simply ignoring the DHCP-advertised DNS server.

The conventional pfSense mitigation is a NAT port-forward (redirect) rule: intercept any
outbound DNS query on port 53 (TCP + UDP) and redirect it to the firewall's own resolver
(`127.0.0.1:53` for IPv4, `::1:53` for IPv6). Clients see no difference in normal operation
(the firewall answers), but a client that would have bypassed pfBlockerNG is now answered by it.

Today there is no pfBlockerNG-managed mechanism for this. Admins who want it must add the NAT
rule(s) manually, maintain them by hand, and remember to remove them when uninstalling the
package. The rules have no pfBlockerNG ownership marker, so they will not be swept on uninstall.

Two critical scoping decisions are settled by the maintainer:

1. **Only port-53 (plaintext DNS) is covered here.** Clients using DoH (DNS-over-HTTPS) or
   DoT/DoQ (DNS-over-TLS/QUIC) bypass port-53 interception entirely. That gap is
   **complementary** to this ADR — DoH is addressed at the domain level via the DNSBL feed, and
   port-853/443 blocking is **ADR-37**. This ADR does not try to intercept encrypted DNS; it
   closes only the plaintext :53 path.

2. **The firewall itself must be exempted.** A redirect that catches the firewall's own outbound
   DNS queries would break upstream resolution and prevent the firewall from resolving anything.
   The exemption is structural (negated destination `(self)` — see §2.2) and is always on.

Load-bearing facts:

- **pfSense port-forwards auto-create an associated filter PASS rule.** When a `nat/rule` entry
  carries an `<associated-rule-id>`, pfSense writes a companion `filter/rule` that passes the
  redirected traffic. Each NAT rdr rule therefore corresponds to exactly one filter pass rule;
  both must be created and removed atomically (same pfBlockerNG descr marker so the ADR-35 sweep
  covers both).
- **These are pfSense-core sections** (`nat/rule`, `filter/rule`) — on the ADR-29 foreign-key
  exclusion list; accessed via direct `config_*_path`. Unchanged by this ADR.
- **The three new config fields** (`dns_redirect_enable`, `dns_redirect_iface`,
  `dns_redirect_exception`) live in `installedpackages/pfblockerngdnsblsettings/config/0` and are
  registered in `PfbConfig` per ADR-29. They are the only `config.xml` additions this ADR makes.
- **Interface selection tracks pfBlockerNG's own firewall-rule interface set.** The quick-fill
  option populates the multi-select with the union of the IP-feature `inbound_interface` +
  `outbound_interface` fields (plus floating) — the same set pfBlockerNG already builds filter
  rules for — because these NAT redirect rules are firewall rules and should follow the same
  scope as the rest of pfBlockerNG's enforcement.
- **No live pf in CI.** Rule-builder logic is unit-tested off-appliance against config-shaped
  fixtures; the real NAT + pf interaction is a live-VM smoke (ADR-04).

## 2. Decision

Add an **optional, default-off** NAT DNS-redirection feature. When enabled, pfBlockerNG creates
and maintains a set of NAT port-forward (rdr) rules — one pair per selected interface (IPv4 +
IPv6) — that redirect all outbound port-53 DNS traffic on those interfaces to the firewall's own
resolver. The rules are registered as ADR-35 managed objects (pfBlockerNG-marker ownership)
and are created, reconciled, and removed through the ADR-35 seam. No ADR-35 marker/teardown
logic is re-invented here.

### 2.1 Per-area decision

| Area | Decision |
| --- | --- |
| Feature scope | Port-53 TCP+UDP redirection only. DoH/DoT/DoQ bypass is out of scope (see §2.3). Plaintext :53 only. |
| Redirect target | `127.0.0.1:53` for inet (IPv4) rules; `::1:53` for inet6 (IPv6) rules. `local-port 53`. `natreflection disable`. Protocol `tcp/udp`. |
| Firewall-self exemption | **Always on.** Destination negated `<network>(self)</network><not/>` ensures the firewall's own outbound DNS is never intercepted. Cannot be disabled. |
| User exception list | An optional **free-text exceptions field** holding zero or more entries — each an **IP / CIDR / host or an existing alias name** (whatever the maintainer needs for "these hosts get direct DNS"). Not restricted to a pre-existing alias. When non-empty it builds a negated source (`<source><not/>…</source>` — an alias when a single alias name is given, else the inline address set) so listed hosts bypass the redirect; when empty (default) source is `<any>`. Each entry is PFBL-01-validated before use. Both branches (empty / non-empty) tested. |
| Interface selection | Multi-select using `pfb_build_if_list()` (WAN-excluded by default), stored comma-joined (plain string) — **reuse the existing "Permit Firewall Rules" pattern** (`dnsbl_allow_int`, `pfblockerng_dnsbl.php:2921`: `Form_Group('Permit Firewall Rules')` → multi `Form_Select` from `pfb_build_if_list(FALSE, FALSE)`, `size` = interface count), not an ad-hoc control. A **quick-fill** option tracks the union of pfBlockerNG's IP-feature `inbound_interface` + `outbound_interface` (plus floating) — the same scope as the existing firewall rules. Per selected interface: one inet + one inet6 rdr rule, each with its associated filter PASS rule. |
| Rule count per interface | 2 NAT rdr rules (inet + inet6) + 2 associated filter PASS rules. Total: 4 config.xml entries per interface. |
| Ownership + lifecycle | All 4 entries per interface carry a pfBlockerNG descr marker (`pfB_DNS_Redirect_<iface>_v4` / `pfB_DNS_Redirect_<iface>_v6` — exact naming confirmed in implementing phase against the codebase `pfB_` conventions). Registered via `pfb_fwobj_register()` per ADR-35. Created/reconciled idempotently on `sync_package_pfblockerng()`; removed on disable; swept on uninstall via `pfb_fwobj_sweep()`. |
| Reconcile (stale-interface pruning) | On each sync, rules for interfaces **no longer in the selected set** are removed. A removed-from-config interface is treated as absent from the set; its rules are pruned by the marker sweep. |
| Config fields | 3 new registered `PfbConfig` fields in `pfblockerngdnsblsettings/config/0` (see §2.2). ADR-29 5-step adding process. |
| UI location | DNSBL settings page (`pfblockerng_dnsbl.php`) — new control block adjacent to the existing DoH/DoT/DoQ blocking section, **folding into / mirroring the existing `Form_Group('Permit Firewall Rules')` structure** (`:2921`) the interface multi-select already uses. Enable checkbox + interface multi-select + quick-fill button + exception-alias field + brief help text matching neighbouring style. Server-side validation (PFBL-01) before any rule build or path composition. |
| Naming (config keys + marker) | Follow the established sibling convention rather than ad-hoc names: keys live beside `dnsbl_allow_int` / `dnsbl_interface` in `pfblockerngdnsblsettings`, so the `dns_redirect_*` names below are **provisional** — final names align to the `dnsbl_*` / `*_int` pattern (e.g. `dnsbl_redir` / `dnsbl_redir_int` / `dnsbl_redir_exclude`), confirmed with the maintainer before the keys are frozen (CLAUDE.md "Naming — follow the established pattern"; storage freeze applies once chosen). |
| Complementary features | Port-53 redirect is complementary to the DoH/DoT/DoQ domain NXDOMAIN approach. ADR-37 adds port-853/443 blocking. This ADR does not replace either; it closes only the plaintext :53 bypass path. |

### 2.2 Semantics that MUST be preserved / hold (the contract — pin with tests)

**Ground-truth rule shape** (from the maintainer's working config.xml; every field below is
mandatory and exactly matched):

```xml
<rule>                                    <!-- nat/rule -->
  <!-- source: negated exception alias; <any> when alias is empty -->
  <source><address>EXCEPTION_ALIAS</address><not></not></source>
  <!-- destination: negated (self) = firewall-self-exempt; port 53 -->
  <destination><network>(self)</network><not></not><port>53</port></destination>
  <ipprotocol>inet</ipprotocol>           <!-- inet for v4 rule; inet6 for v6 rule -->
  <protocol>tcp/udp</protocol>
  <target>127.0.0.1</target>              <!-- v4: 127.0.0.1  v6: ::1 -->
  <local-port>53</local-port>
  <interface>lan</interface>              <!-- one rule set per selected interface -->
  <descr><![CDATA[pfB_DNS_Redirect_lan_v4]]></descr>   <!-- pfBlockerNG marker -->
  <associated-rule-id>nat_...</associated-rule-id>
  <natreflection>disable</natreflection>
</rule>
```

Invariants (each asserted by PHPUnit tests with full branch coverage):

- **Destination is always negated `(self)` with port 53** — the firewall-self-exempt is
  structurally present in every generated rule, for both inet and inet6 families. No code path
  produces a rule without it.
- **Source is negated-alias when exception alias is set; `<any>` when alias is empty.** Both
  branches produce structurally valid rules. The transition (empty → set → empty) is
  round-trip stable.
- **Target is family-specific**: inet rule → `127.0.0.1`; inet6 rule → `::1`. Never crossed.
- **`natreflection` is `disable`** on every generated rule.
- **Protocol is `tcp/udp`** on every generated rule.
- **`local-port` is `53`** on every generated rule.
- **`descr` carries the pfBlockerNG marker** and is the sole ownership signal (ADR-35 contract).
  The associated filter PASS rule carries a corresponding marker so the ADR-35 sweep removes
  both atomically.
- **Multiple interfaces → one rule set (inet + inet6 rdr + 2 filter) per interface.** Each
  set is independent and carries the interface name in its marker.
- **Disable removes all owned rules** (marker sweep via ADR-35). A user NAT rule (no marker)
  is never touched.
- **Reconcile is idempotent** — calling the builder twice with identical settings produces the
  same config.xml state; no duplicate rules accumulate.
- **Stale-interface rules are pruned on reconcile** — if an interface is removed from the
  selection, its rules (identified by marker) are removed on the next sync.
- **New config fields round-trip** through `PfbConfig` (ADR-29 backward-compat contract):
  `write(read(v)) == v` for every stored vocabulary value.

### 2.3 Explicitly kept / out of scope

- **DoH (DNS-over-HTTPS) interception** — out. Clients using DoH on port 443 bypass port-53
  redirect entirely; domain-level DNSBL blocking is the existing countermeasure.
- **DoT/DoQ port-853 blocking** — out; that is ADR-37. The two features are complementary but
  independent.
- **Per-client or per-subnet policies beyond the single exception alias** — out. A single
  alias covers the use case; per-row policies are a future extension.
- **Redirecting non-53 DNS** (e.g. non-standard ports, DNS-over-TLS on 853) — out.
- **NAT reflection** — explicitly disabled (`natreflection disable`). The redirect targets
  the firewall loopback; reflection is meaningless here.
- **Creating/managing an alias object** — out. The exceptions field is a plain reference: it
  accepts inline IP/CIDR/host entries and/or the name of an alias the user maintains through the
  normal pfSense Firewall → Aliases UI. pfBlockerNG does not create or own that alias.
- **Renaming or modifying existing pfBlockerNG NAT markers** — out (storage freeze, ADR-28).
  This ADR introduces new markers only.
- **Changing `pfb_remove_config_settings()` or the ADR-35 sweep logic** — out. The sweep is
  already provided by ADR-35; this ADR registers through it.

## 3. Consequences

**Positive**

- Closes the plaintext :53 DNS-bypass gap: a client with a hardcoded external DNS server is
  redirected to the firewall's resolver and is subject to pfBlockerNG DNSBL matching.
- Firewall-self exemption is structural (negated destination `(self)`) — cannot be accidentally
  removed; upstream resolution is never disrupted.
- Lifecycle managed via ADR-35 (register/reconcile/remove/sweep) — no bespoke teardown code;
  the feature stays thin and consistent with ADR-36/37 siblings.
- Default off — zero impact on existing installations that do not opt in.
- Config fields are registered in `PfbConfig` with the ADR-29 backward-compat invariants;
  an older release ignores the keys (inert), a rollback preserves them for roll-forward.

**Negative / risks**

- **Risk: breaking the firewall's own DNS.** The negated `(self)` destination exempts the
  firewall structurally. Tested: a rule without negation would redirect the firewall's own
  queries to itself (loopback), causing a resolution loop. The structural exemption prevents
  this; every generated rule is asserted to carry it.
- **Risk: redirect with no active DNS resolver on loopback.** If Unbound is not listening on
  `127.0.0.1:53` / `::1:53` (unusual pfSense configuration), the redirect sends DNS queries to
  a dead port, effectively breaking DNS for affected clients. Documented in the UI help text;
  out of scope to gate on the resolver state.
- **Risk: DoH/DoT bypass.** Port-53 redirect does not catch DNS-over-HTTPS or DNS-over-TLS
  clients. Documented limitation; ADR-37 addresses the DoT/DoQ side. Users must understand
  the feature does not provide complete bypass protection.
- **Risk: NAT + associated filter rule atomicity.** If the NAT rule is created but the filter
  PASS rule is absent (or vice versa), traffic is either redirected without a pass rule
  (dropped) or a dangling filter rule exists. Both are registered via ADR-35 with the same
  marker so the sweep removes both; idempotent create ensures both are written in the same
  `write_config()` flush.
- **Risk: interface churn leaving stale rules.** Mitigated by the reconcile-time stale-prune
  (marker scan for rules belonging to interfaces no longer in the selected set).
- **Risk: user exception alias mismatch** (alias name changed or deleted outside pfBlockerNG).
  Out of scope to validate alias existence at runtime; the rule will reference a non-existent
  alias, which pfSense treats as matching nothing — the rule becomes effectively a catch-all
  redirect. Documented in help text.

## 4. Requirements (acceptance)

- A pure `pfb_build_dns_redirect_rules($settings)` builder function returning the exact
  rule-set array (NAT + associated filter) matching the §2.2 ground-truth shape, for any
  combination of interface / IP family / exception alias state.
- The builder registered via `pfb_fwobj_register()` (ADR-35); create/reconcile/remove/sweep
  wired into `sync_package_pfblockerng()` and the disable/uninstall paths.
- Three new `PfbConfig`-registered fields: `dns_redirect_enable` (toggle), `dns_redirect_iface`
  (plain string), `dns_redirect_exception` (plain string) — ADR-29 5-step process, including
  `CfgGatewayTest.php` round-trip tests + inventory update + `$registeredPaths` in the sniff.
- UI control block on `pfblockerng_dnsbl.php`: enable checkbox + interface multi-select +
  quick-fill (tracks pfBlockerNG fw-rule interface set) + exception-alias field + help text;
  server-side PFBL-01 validation of interface names and alias name before rule build.
- All gates green (§5); live-VM smoke proves the full lifecycle.

## 5. Constraints (from CLAUDE.md)

- PHP tabs, PHP 8.3; no `die()`/`exit()` in library code.
- **ADR-28**: uppercase `TRUE`/`FALSE`; storage freeze (new stored vocabulary defined once and
  never changed; existing markers are immutable).
- **ADR-29**: three new fields registered in `PfbConfig` via the 5-step process. The managed
  sections (`nat/rule`, `filter/rule`) stay pfSense-core foreign → direct `config_*_path`, NOT
  `PfbConfig`. The sniff's `$registeredPaths` must be updated for all three new keys.
  `pfblockerng_extra.inc` is excluded from the sniff (the gateway itself).
- **ADR-35**: use `pfb_fwobj_register` / `pfb_fwobj_find` / `pfb_fwobj_remove` / `pfb_fwobj_sweep`
  exclusively. Do NOT re-invent marker detection, teardown logic, or orphan sweep.
- **PFBL-01**: the rule builder and any UI form handler that accepts interface names or alias
  names is an in-scope input-handling surface. Add the new functions to the PHPCS
  `scopeFunctions` allow-list; validate interface names against `pfb_build_if_list()` output
  and alias names via `pfb_filter()` / `is_validaliasname()` before any rule construction or
  path composition.
- **ADR-04 smoke** for the end-to-end create/disable/uninstall lifecycle and the pf table
  verification.
- **ADR-14 `ui_render`** for the modified DNSBL settings page.

## 6. Action plan

### Phase 1 — Config fields + golden rule-builder tests

- Prompt: `01_Config_Fields_And_Builder_Tests.txt`
- Register the three new `PfbConfig` fields in `pfb_cfg_registry()` (`pfblockerng_extra.inc`):
  `dns_redirect_enable` (toggle adapter, stored `'on'`/`''`, default `''`),
  `dns_redirect_iface` (plain adapter, stored comma-joined string, default `''`),
  `dns_redirect_exception` (plain adapter, stored string, default `''`).
  Follow the ADR-29 5-step process: registry entry + `since: '4.0.0'` + round-trip verify +
  `CfgGatewayTest.php` (round-trip + default-absent) + inventory update +
  `$registeredPaths` in `RequireConfigGatewaySniff.php`.
- Write a pure `pfb_build_dns_redirect_rules($settings)` skeleton function in
  `pfblockerng.inc` (or a new helper include — implementer's call based on code size). The
  function takes: interface name, IP family (`inet`/`inet6`), exception alias string (may be
  empty). It returns an array with exactly two entries: the NAT rdr rule array + the associated
  filter rule array, matching the §2.2 ground-truth field-for-field.
- **Tests (oracle first):** PHPUnit golden tests pinning the exact rule structure. Required
  branches: (a) inet family → target `127.0.0.1`, source `<any>`; (b) inet6 family → target
  `::1`, source `<any>`; (c) exception alias set → source negated-alias; (d) exception alias
  empty → source `<any>`; (e) multiple interfaces → independent rule sets; (f) descr marker
  present in both NAT and filter entries. Assert destination is always negated `(self)` + port
  53. Assert `natreflection` is `disable`. Assert `protocol` is `tcp/udp`. Assert `local-port`
  is `53`. All branches before the builder implementation is wired to any live sync.
- Tests: `CfgGatewayTest.php` round-trip for all three new fields.

### Phase 2 — Rule builder + ADR-35 registration + sync wiring

- Prompt: `02_Builder_And_Sync.txt`
- Complete the `pfb_build_dns_redirect_rules()` implementation so it passes all Phase-1 golden
  tests.
- Register the builder via `pfb_fwobj_register()` (ADR-35): spec includes type `nat`, the
  `pfB_DNS_Redirect_*` marker prefix, the builder callable, and the associated filter rule
  builder so both are tracked under the same registration (or register as two entries sharing
  the marker prefix — implementer decides based on ADR-35 spec shape, reading
  `pfblockerng_fwobj.inc` first).
- Wire create/reconcile into `sync_package_pfblockerng()`: when `dns_redirect_enable == 'on'`,
  build and write the rule set for each selected interface; when off or no interfaces selected,
  remove all owned rules (marker sweep). On each sync, prune rules for any interface no longer
  in the selected set (stale-interface reconcile).
- Tests: reconcile-is-idempotent (two syncs → same config); disable removes all marked rules
  while a seeded user NAT rule (no marker) survives; stale-interface rules are pruned on the
  next sync (rule for removed interface is gone; rule for retained interface stays).

### Phase 3 — UI on the DNSBL settings page

- Prompt: `03_UI.txt`
- Add a new control block in `pfblockerng_dnsbl.php` adjacent to the DoH/DoT/DoQ section.
  Block contains: (a) enable checkbox bound to `dns_redirect_enable`; (b) interface
  multi-select (`pfb_build_if_list()`, WAN-excluded by default, pre-selected from
  `dns_redirect_iface`); (c) a quick-fill button/link that populates the multi-select with
  the union of the current `inbound_interface` + `outbound_interface` values (the pfBlockerNG
  fw-rule interface set); (d) exception-alias free-text field bound to
  `dns_redirect_exception`; (e) brief help text (style matches neighbouring DoH/DoT/DoQ help
  text) warning that (i) port-53 only, (ii) DoH/DoT bypass is not covered, (iii) the alias must
  exist in Firewall → Aliases.
- Server-side POST handler: validate selected interface names against `pfb_build_if_list()`
  output before accepting; validate alias name via `pfb_filter()` / `is_validaliasname()` if
  non-empty (PFBL-01 surface — add the handler function to PHPCS `scopeFunctions`).
- Save via `PfbConfig::write()` for all three registered fields.
- Tests: PHPUnit for the server-side validator (valid/invalid interface name, valid/empty/invalid
  alias); ADR-14 `ui_render` for `pfblockerng_dnsbl.php` (200, no PHP errors, page marker
  present, no new `php_error.log` line).

### Phase 4 — Smoke + DoD + docs

- Prompt: `04_Smoke_DoD_Docs.txt`
- ADR-04 live-VM smoke (`tests/smoke/test_dns_redirect.py` or appended to an existing smoke
  file). Required cases:
  - **Enable path:** enable redirect on the LAN interface → assert both NAT rdr rules (inet +
    inet6) appear in `config.xml` with the pfBlockerNG marker; assert the associated filter PASS
    rules are present; assert `pfctl -sn` shows the rdr rules active.
  - **Disable path:** disable → assert all pfB_DNS_Redirect_* entries removed from
    `config.xml`; assert `pfctl -sn` shows no pfBlockerNG rdr rules.
  - **User-rule survival:** seed a user NAT rule (no marker) before enable; after disable +
    uninstall, assert the user rule survives untouched.
  - **Stale-interface prune:** enable on two interfaces, then reduce to one → assert the rule
    set for the removed interface is gone; the retained interface rules remain.
  - **Exception alias branch (config.xml assertion):** enable with a non-empty alias → assert
    the source is `<address>ALIAS</address><not/>` in config.xml; enable with empty alias →
    assert source is `<any>` (both branches, both IP families).
  - **Uninstall sweep:** use ADR-35's sweep test pattern — install + enable → uninstall →
    assert all pfB_DNS_Redirect_* gone, no pfBlockerNG `nat/rule` or `filter/rule` entries
    remain, and `installedpackages/pfblockerng*` gone.
  - **Full client-redirect behaviour** (on-box `pfctl -sn` assertion of the rdr rule is the
    CI-feasible gate; actual client DNS interception requires a second host and is a documented
    maintainer manual-smoke item — see §7).
- `docs/misc/architecture-notes.md` blurb covering the redirect feature, the self-exempt
  mechanism, and the DoH/DoT complementary relationship.
- ADR-14 `ui_render` for `pfblockerng_dnsbl.php` (if not already green from Phase 3 CI).

## 7. Definition of done

- [x] `pfb_build_dns_redirect_rules()` passes all golden tests — exact §2.2 rule shape, all
      branches (inet/inet6, alias set/empty, multiple interfaces, marker present in NAT +
      filter entries). *(Phase 1 + 2 PHPUnit golden tests — green)*
- [x] Three `PfbConfig`-registered fields (`dnsbl_redir`, `dnsbl_redir_int`,
      `dnsbl_redir_exclude`) with ADR-29 round-trip + forward/backward invariants green
      (`CfgGatewayTest.php`, `RollbackContractTest.php`). *(Phase 1 — green)*
- [x] ADR-35 registration in place; create/reconcile/remove/sweep exercised for the redirect
      rule set (idempotent, stale-prune, user-rule survival — all asserted). *(Phase 2 PHPUnit — green)*
- [x] UI control block on `pfblockerng_dnsbl.php`: enable + multi-select + quick-fill +
      exception alias + help text; server-side PFBL-01 validation. *(Phase 3 — green)*
- [x] All off-VM gates green: `vendor/bin/phpunit`, PHPStan, PHPCS (PFBL-01 + ADR-28 + ADR-29
      sniffs), `php -l`, `python -m pytest`, `ruff check/format`. *(Phases 1–4 — green)*
- [x] ADR-14 `ui_render` — `pfblockerng_dnsbl.php` marker tuple updated to assert "DNS Redirect"
      section present; pending live-VM run via `ui-tests.yml` CI on the PR. *(Phase 3)*
- [ ] Live-VM smoke proves: NAT + filter rules appear on enable, are removed on disable, survive
      uninstall correctly (pfB_DNS_Redirect_* gone; user rule survives); stale-interface prune
      works; `pfctl -sn` confirms the rdr rules are active.
      *(smoke file written: `tests/smoke/test_dns_redirect.py`, 6 cases — pending live fan-out)*

**Manual smoke (owner: maintainer):**

- [ ] Enable DNS redirect on LAN with an empty exception alias → confirm a client with `8.8.8.8`
      as DNS server has its port-53 queries answered by the pfSense resolver (verified by a DNS
      query to an external server that should return DNSBL-blocked result — block is applied).
- [ ] Populate the exception alias with the client's IP → confirm that client now bypasses the
      redirect (external DNS server answers again).
- [ ] Enable redirect on LAN + OPT1 → disable on OPT1 only → confirm OPT1 rules gone, LAN rules
      remain.
- [ ] Uninstall pfBlockerNG with redirect enabled → confirm no pfB_DNS_Redirect_* rules remain
      in Firewall → NAT and no dangling filter rules.

**Reject criteria:** if the pfSense port-forward + associated-filter-rule creation cannot be
driven deterministically from config.xml writes alone (e.g. if pfSense requires a PHP function
call that cannot be replicated off-appliance to wire the `associated-rule-id`), **reduce** to
a documented limitation (the associated filter rule is created manually or via a pfSense-internal
hook on package apply). If the ADR-35 registration seam cannot cover both the NAT and associated
filter rule atomically, **reduce** to a single-marker sweep with a documented atomicity caveat
and a verify-both-exist assertion on every reconcile.

## Amendment — 2026-07-20: package rollback promise superseded (issue #1593)

DNS-redirection behaviour and current configuration round trips are unchanged. The old-package
ignore/preserve promise and inherited `RollbackContractTest` requirement are superseded. Package
downgrade is unsupported; forward upgrade and grandfathering remain supported.

# ADR-13: Automatic creation of DNSBL sinkhole Virtual IPs

- **Status:** **Proposed** (2026-06-03)
- **Date:** 2026-06-03
- **Branch:** `adr/13` (off **`devel`** — the refactored VIP model (`pfb_get_vips`/`pfb_validate_vips`/`_vip<uniqid>`) exists on `devel`; the feature is DNSBL-mode-agnostic PHP/UI, no Python/Unbound-matcher coupling. Independent of the ADR-07/10 chain; promote `devel → next` by rebase) / **Component(s):** `src/usr/local/pkg/pfblockerng/pfblockerng.inc` (VIP candidate/pick helpers, `pfb_manage_dnsbl_vip()`, the `pfb_create_dnsbl($mode)` fire point, `pfb_validate_vips`/`pfb_global` v6-mandatory rule, `pfb_unbound_listens_v6()`), `src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php` + its inline JS (the "Create VIPs automatically" checkbox, prefill/disable, warning tooltip, save-time create), `stubs/pfsense/` (interface/vip apply fns), `README.md`/`CLAUDE.md` + the settings help.
- **Target runtime:** PHP 8.3 + jQuery (the DNSBL settings page) on pfSense CE 2.8. **No Python** — the Unbound plugin and `pytest` suite are untouched. No new shell.
- **Test suite:** **No `pytest` oracle** (PHP/JS; no PHP unit harness in-repo — same reality as ADR-11/12). Validation = `php -l` + PHPStan + ShellCheck (the automated gate) + a **manual smoke checklist** (auto-create on enable, teardown on disable, conflict → disabled checkbox + warning, v6-mandatory when the resolver listens on IPv6, HA sync). The `pytest` suite must stay **green/unchanged**.

---

## 1. Context

### Today

A DNSBL "block" sinks the name to a **Virtual IP** (the sinkhole the DNSBL web server / Unbound answers with). That VIP must already exist and be **manually selected**:

1. **The admin must pre-create an IP-Alias VIP** (Firewall > Virtual IPs), then pick it. The DNSBL settings page offers two dropdowns, `pfb_dnsvip4` / `pfb_dnsvip6`, populated **only from existing VIPs** by `pfb_get_vip_options()` (`pfblockerng_dnsbl.php:2504-2523`); the group help text literally says *"VIPs **must be configured first** at Firewall > Virtual IPs."* The web-server interface is `dnsbl_interface` (default `lo0`, `:2496-2502`).
2. **VIP enumeration / validation.** `pfb_get_vips()` (`inc:669`) lists IP-Alias VIPs via `get_configured_vip_list()` filtered by `SPECIALNET_VIPS`. `pfb_validate_vips($interface,$vip4,$vip6)` (`inc:727`) checks each chosen VIP is on `$interface` (`get_configured_vip_interface`), exists, and **does not overlap an existing subnet** (`where_is_ipaddr_configured`, `:745`/`:752`). On save the page runs the same validator (`:466-475`) and errors out; `pfb_global()` resolves the ids to IPs and **force-disables DNSBL** if invalid/missing (`inc:826-836`).
3. **The package never creates the VIP.** `pfb_create_dnsbl($mode)` (`inc:1921`) creates/removes the DNSBL **NAT rules** (`:1950-1976` create, `:1986-1992` remove), lighttpd conf and cert — but **not** the VIP. Its main-pass call site comment already anticipates the gap: *"Modify DNSBL NAT **and VIP** and lighttpd web server conf, as required"* (`inc:8697-8698`). `$mode` is `enabled` when `enable=='on' && dnsbl=='on' && unbound_state=='on'`, `disabled` when `(enable=='' || dnsbl=='') && !install` (`inc:8684-8689`).
4. **History.** Old pfBlockerNG stored a raw `pfb_dnsvip` IP + CARP fields (`pfb_dnsvip_type/vhid/base/skew/pass`) and **did manage the VIP itself**. The `next`/`devel` refactor dropped auto-create for explicit manual selection; `pfblockerng_install.inc:33-107` only **migrates** an existing `pfB DNSBL` VIP (renames `descr` → `pfBlockerNG DNSBL` `:53`, repoints the `_vip{uniqid}` id `:56`), else `file_notice` *"The DNSBL VIP needs to be configured manually"* (`:70`). This ADR re-adds automatic creation in the new id-based model.
5. **VIP config shape** (from the migration + stubs): an entry under `virtualip/vip` = `{mode:'ipalias', interface, type:'single', subnet, subnet_bits, descr, uniqid}`; the selectable id is `"_vip{$vip['uniqid']}"`. Apply with `interface_ipalias_configure(&$vip)` (`stubs/pfsense/interfaces.php:192`); remove with `interface_vip_bring_down($vip)` (`:147`). **No sibling pfSense package auto-creates a VIP** (haproxy/snort/suricata only *read* `virtualip/vip`) — the canonical create+apply precedent is pfSense core `firewall_virtual_ip_edit.php`.

### Disable / teardown is already the norm (the premise this ADR leans on — confirmed)

pfBlockerNG treats its rules/aliases/NAT/DNSBL data as **managed artifacts that disappear on disable**:

- List collection is gated by `enable=='on'` (`inc:6990`, `:7034`) → on disable the alias/rule set empties → `pfb_aliastables('update')` + `filter_configure()` (`inc:10166`, `:10288`) drop the pf tables/rules. `keep=='on'` only retains blocklist **data/masterfiles** (`inc:6981`), not the live rules.
- DNSBL on disable → `pfb_reload_unbound('disabled')` strips the DNSBL data (`inc:3372`) and `pfb_create_dnsbl('disabled')` removes the DNSBL NAT (`inc:1986-1992`).
- Uninstall runs the **same** disable pass (`sync_package_pfblockerng()`, `inc:10508`) plus config/file removal (`inc:10500-10586`, settings `pfb_remove_config_settings()` `:10590`).

→ An auto-created VIP is just another managed artifact: **create it in `pfb_create_dnsbl('enabled')`, delete it in `pfb_create_dnsbl('disabled')`**, alongside the NAT it already owns.

### Load-bearing facts

1. **Feature, not a premise to falsify.** No perf/memory claim (unlike ADR-01); the risk is **operational correctness** — never delete a VIP we don't own; never create one that conflicts; behave under HA/CARP and on every enable/disable path.
2. **No PHP/JS unit harness** (same as ADR-11/12) → validation = lint + manual smoke. No oracle. The `pytest` suite is untouched.
3. **The settings are the source of truth and persist independent of enable state** — the admin can change DNSBL settings while pfBlockerNG is disabled. The **VIP** (the managed artifact) is created/destroyed to follow enable state; the **decision** (`pfb_dnsvip_auto`) and chosen address live in config and persist.
4. **The smoke harness injects the VIP today** (`tests/smoke/helpers.py:454 ensure_dnsbl_vip`, default `10.10.10.1`, comment "pfBlockerNG never auto-creates it" `:85-90`) precisely because the package won't. Keeping `pfb_dnsvip_auto` **default OFF** means the harness — and the "no VIP configured" scenario — are unaffected (today's behaviour is byte-identical).

---

## 2. Decision

Add an opt-in **"Create VIPs automatically"** checkbox to the DNSBL settings. When enabled, pfBlockerNG **owns** the DNSBL sinkhole VIP(s): it picks a free, DNS-themed address, creates a clearly-marked IP-Alias VIP on enable, and deletes it on disable — keeping the existing manual-selection model fully intact when the box is off.

| Area | Decision |
| --- | --- |
| **UX model** | Keep the existing `pfb_dnsvip4`/`pfb_dnsvip6` dropdowns (manual selection of an existing VIP). Add a **checkbox `pfb_dnsvip_auto`** ("Create VIPs automatically", default **off**). When **checked**, JS **pre-fills** the VIP field(s) with the address(es) the package would create and **disables** the manual dropdowns (`disableInput`/`.prop('disabled', …)` driven by the checkbox `.click()`/`.change()` handler — the page already uses this pattern at `:3015-3045`). The **actual create happens server-side on Save**. Box off ⇒ today's behaviour, byte-identical. |
| **Preferred addresses (DNS homage)** | IPv4 `10.10.10.53/32`, IPv6 `fd00::53/128`. On conflict, sweep `10.10.X.53` / `fd00:X::53` (third group/hextet bounded, e.g. `X = 0..15`) and pick the **first non-conflicting** candidate. |
| **Conflict detection** | Reuse the already-fetched VIP set (`pfb_get_vips`) **plus** `where_is_ipaddr_configured()` (the same overlap check `pfb_validate_vips` uses) against every candidate. A candidate is free iff it is not an existing VIP **and** overlaps no configured subnet. If **no** candidate is free, the checkbox is rendered **disabled** with an `fa-exclamation-triangle` warning whose tooltip explains why (and points to Firewall > Virtual IPs). |
| **Marker (ownership)** | Auto-created VIPs carry a machine-detectable marker — `descr = 'pfB_AUTO_VIP_v4'` / `'pfB_AUTO_VIP_v6'` — plus a fresh `uniqid`. **Only** VIPs carrying this marker are ever managed/deleted by the package. |
| **Lifecycle (create)** | Inside `pfb_create_dnsbl('enabled')`: if `pfb_dnsvip_auto` is on, **ensure** the marked VIP(s) exist at the configured address on `dnsbl_interface` — create + `interface_ipalias_configure()` if absent (idempotent: reuse the existing marked VIP if present), then set `pfb_dnsvip4`/`pfb_dnsvip6` to the `_vip{uniqid}` ids and `write_config`. |
| **Lifecycle (delete)** | Inside `pfb_create_dnsbl('disabled')` (i.e. pfBlockerNG **or** DNSBL disabled), and whenever a VIP is no longer managed (auto turned off, or v6 no longer listened-on while it was auto-created): **delete** the VIP(s) matching **marker `pfB_AUTO_VIP_v*` AND the IP currently resolved from the stored `pfb_dnsvip4`/`pfb_dnsvip6` config** — `interface_vip_bring_down()` + drop from `virtualip/vip` + `write_config`. Never touch unmarked (manually-created) VIPs. |
| **Scope: interface** | Auto-create places the VIP on the configured `dnsbl_interface` (default `lo0`; non-`lo0` already generates the DNSBL NAT, `inc:1946-1976`). |
| **Scope: IPv6 / mandatory rule** | IPv4 auto-created always; IPv6 auto-created **when requested OR when the DNS Resolver listens on IPv6**. If the resolver listens on IPv6, a v6 sinkhole VIP becomes **mandatory**: in auto mode it is provisioned with no friction; in manual mode `pfb_validate_vips`/`pfb_global` require it (input error on save / force-disable). Detection via a new `pfb_unbound_listens_v6()` (resolver active-interface addresses) — the exact predicate verified against upstream pfSense source per CLAUDE.md and on-box. |
| **HA / CARP sync** | The auto flag + VIP live in config → replicate to the CARP/HA secondary and the secondary creates/deletes its own VIP when it runs the pass. lo0 IP-Alias is node-local; this is correct and documented. |

### Semantics that MUST be preserved (the contract)

- **Additive / default-off.** With `pfb_dnsvip_auto` off, the DNSBL settings, save path, and update pass are **byte-identical** to today (manual dropdowns, manual validation). The smoke harness and the "no VIP" scenario are unaffected.
- **We only ever delete VIPs we own.** Deletion requires the `pfB_AUTO_VIP_v*` marker **and** an IP match against stored config. A user's manually-created VIP is never modified or removed.
- **Lifecycle follows enable state.** Auto VIP created on `pfb_create_dnsbl('enabled')`, removed on `pfb_create_dnsbl('disabled')` (DNSBL or pfBlockerNG disabled, and on uninstall via the same pass) — consistent with rules/aliases/NAT.
- **Settings persist across enable/disable.** Disabling pfBlockerNG removes the VIP but **keeps** `pfb_dnsvip_auto` + the address choice; re-enabling re-creates it.
- **No conflict, ever.** An auto-created address overlaps no configured subnet and no existing VIP; if none can be found the feature disables itself in the UI (checkbox disabled + warning) rather than creating a bad VIP.
- **Manual selection still works** unchanged when the box is off, including the existing overlap/interface validation.
- **Visually + behaviourally native.** The new control reuses existing `Form_*`/`gui_lib` components, styles, and idioms — no bespoke markup or CSS — and is indistinguishable from the surrounding pfBlockerNG/pfSense settings in look, positioning, and interaction (see §5 "UI consistency").

### Explicitly kept / out of scope

- **Auto-create defaulting ON for fresh installs** — out for v1 (opt-in checkbox, default off, to stay additive and keep smoke green). Revisit once proven.
- **CARP-type sinkhole VIPs / VHID management** — out; auto-create makes a plain `ipalias` (the old CARP fields were dropped in the refactor and are not reintroduced).
- **Auto-picking across arbitrary RFC1918 ranges / a user-configurable candidate pool** — out; the bounded `10.10.X.53` / `fd00:X::53` sweep is sufficient and predictable.
- **Migrating existing manual VIPs to auto-managed** — out; the install.inc migration is untouched. Auto-create only applies when the admin opts in.
- **Removing the auto VIP on `keep=='on'` mid-toggle** — the VIP follows the DNSBL/enable state regardless of `keep` (which governs blocklist data, not the sinkhole); documented.

---

## 3. Consequences

**Positive**

- Removes the single biggest DNSBL setup friction ("go create a VIP first, in an isolated range, then come back") — one checkbox and it just works, with a DNS-themed address.
- Safe by construction: opt-in, default-off, additive; only ever manages marker-owned VIPs; refuses (UI-disabled + warning) rather than create a conflicting VIP.
- Lifecycle is idiomatic — reuses the exact `pfb_create_dnsbl($mode)` create/destroy hook the package already uses for DNSBL NAT, so create/teardown ride the existing enable/disable/uninstall paths and HA sync for free.
- Closes a real correctness gap: a v6 sinkhole is provisioned automatically when the resolver listens on IPv6, instead of silently lacking one.

**Negative / risks**

- **Deleting the wrong VIP.** Mitigated: marker `pfB_AUTO_VIP_v*` **and** IP-match required; unmarked VIPs are untouchable; covered by manual smoke.
- **v6-mandatory is a behaviour change for existing manual setups** that listen on IPv6 without a v6 VIP — they will now see a validation error (auto mode provisions it for them). Mitigated: documented; auto-create makes compliance one click. A reject/pivot lever if it proves too disruptive (soften to a warning).
- **Address conflict / multi-homed networks.** Mitigated: overlap check against all configured subnets + VIPs across a bounded sweep; UI disables + warns when nothing is free.
- **HA double-management.** Each node creates/deletes its own node-local lo0 VIP — correct, but documented so it is not surprising.
- **No automated oracle** (PHP/JS). Mitigated: thin helpers, lint-clean, isolated prep phase, and a tight manual smoke checklist.

---

## 4. Requirements (acceptance)

1. **Additive:** `pfb_dnsvip_auto` off ⇒ DNSBL settings page, save path, and update pass byte-identical to today; smoke + "no VIP" scenario unaffected.
2. **Create:** with the box on, enabling DNSBL creates a marked IP-Alias VIP at a free `10.10.10.53`-style v4 address (and a v6 `fd00::53` when required), on `dnsbl_interface`, applied live, with `pfb_dnsvip4`/`6` pointing at it.
3. **Delete:** disabling DNSBL or pfBlockerNG (and uninstall) removes **only** the marked VIP(s) matching marker + stored-config IP; manual VIPs untouched.
4. **Conflict:** the auto address never overlaps a configured subnet or existing VIP; when no candidate is free the checkbox is disabled with an explanatory warning tooltip.
5. **IPv6 mandatory:** when the resolver listens on IPv6, a v6 VIP is required — auto-provisioned in auto mode, an input error / force-disable in manual mode.
6. **UI:** checking the box prefills the address(es) and disables the manual dropdowns; unchecking restores them; help documents the marker, the address scheme, and the lifecycle.
7. **Persistence:** the auto flag + address choice survive enable→disable→enable; the VIP is recreated on re-enable.
8. **Lint-clean:** `php -l` + PHPStan + ShellCheck clean; `python -m pytest` green/unchanged.

---

## 5. Constraints (from `CLAUDE.md`)

- **PHP:** tabs, 8.3, no `die()`/`exit()` in library code; pfSense fns resolved via `stubs/pfsense/` (add `interface_ipalias_configure`/`interface_vip_bring_down`/`get_configured_vip_interface`/`where_is_ipaddr_configured`/`get_configured_vip_list` if not already present; PHPStan is the gate — prefer a real stub over a baseline suppression).
- **UI consistency (hard requirement):** every element, style, position, and interaction must **reuse what already exists** and integrate seamlessly — no bespoke widgets, no custom CSS, no one-off markup. Use the same `Form_*` components and `gui_lib` helpers the rest of the page uses (`Form_Checkbox`, `Form_Group`, `setHelp`, `setWidth`, `disableInput`), the same Font-Awesome + Bootstrap-tooltip idioms pfSense ships (`fa-exclamation-triangle`, `data-toggle="tooltip"`), and the same inline-jQuery style already in `pfblockerng_dnsbl.php` (`.click()`/`.change()` handlers — e.g. `:3015-3045`). Match the surrounding grouping, label/help phrasing, indentation (tabs), and field positioning so the new control is indistinguishable in look and behaviour from the existing settings. If a desired affordance has no existing precedent in pfBlockerNG/pfSense, prefer the closest existing pattern over inventing one.
- **No shipped Python change**; the Unbound plugin and `pytest` suite untouched.
- **Investigate the live system / upstream source** for the v6-listen predicate and the VIP create+apply sequence — verify against pfSense `firewall_virtual_ip_edit.php` / `services_unbound.php` at the relevant dated refs, and on-box (`pfb_validate_vips` overlap semantics, `interface_ipalias_configure` effect).
- Commit style `<scope>: <imperative summary>`; **work inline on `adr/13`, one commit per phase, push directly** (PR only if rejected); PR bodies via `--body-file`. Promote `devel → next` by rebase + `--force-with-lease`.
- **Docs:** README/CLAUDE.md + the settings help updated when the feature lands (final phase).

---

## 6. Action plan

Each phase = one commit, leaves the tree lint-clean (`php -l`/PHPStan/ShellCheck) and `python -m pytest` **green/unchanged**. The **pure helpers land first, unwired (Phase 1)** — behaviour-preserving building blocks — before any lifecycle wiring, validation change, or UI.

### Phase 1 — PREP (behaviour-preserving): marker + candidate/pick + v6-listen helpers (unwired)

Prompt: `01_VIP_Helpers_Prep.txt`

- Add the marker constants (`pfB_AUTO_VIP_v4` / `pfB_AUTO_VIP_v6`). Implement (a) `pfb_dnsbl_vip_candidates(int $family): array` — the ordered DNS-themed candidate list (`10.10.X.53` / `fd00:X::53`, bounded sweep); (b) `pfb_pick_free_dnsbl_vip(int $family, string $interface): ?string` — first candidate that is neither an existing VIP nor overlapping a configured subnet (`pfb_get_vips` + `where_is_ipaddr_configured`); (c) `pfb_unbound_listens_v6(): bool` — resolver-listens-on-IPv6 detection (verify the predicate against upstream + on-box). Add any missing pfSense stubs. **Nothing calls these yet** — no observable change. Lint-clean.

### Phase 2 — VIP lifecycle manager wired into `pfb_create_dnsbl($mode)`

Prompt: `02_VIP_Lifecycle.txt`

- Add the `pfb_dnsvip_auto` config key (default off). Implement `pfb_manage_dnsbl_vip(string $mode): void`: on `enabled`+auto → ensure the marked VIP(s) exist (create via the picker + `interface_ipalias_configure`, idempotent reuse), set `pfb_dnsvip4`/`6` to the `_vip{uniqid}` ids, `write_config`; on `disabled` (or auto-off / no-longer-managed) → delete **only** VIPs matching marker + stored-config IP (`interface_vip_bring_down` + drop from config). Call it from `pfb_create_dnsbl($mode)` (`inc:8698`, the existing "…and VIP…" hook). **Additive:** auto off ⇒ no-op ⇒ byte-identical.

### Phase 3 — IPv6-mandatory validation when the resolver listens on IPv6

Prompt: `03_IPv6_Mandatory.txt`

- Extend `pfb_validate_vips()` and the `pfb_global()` force-disable path so that when `pfb_unbound_listens_v6()` is true a v6 sinkhole VIP is required: auto mode provisions it (Phase 2), manual mode raises the input error on save / force-disables in `pfb_global`. Keep the existing v4 + manual semantics intact when v6 is not listened-on.

### Phase 4 — Settings UI: the checkbox, prefill/disable, warning tooltip, save-time create

Prompt: `04_Settings_UI.txt`

- Add the `pfb_dnsvip_auto` checkbox to the "DNSBL Virtual IP" group. Inline JS: on check → prefill the VIP field(s) with the picked address(es) and `disableInput` the dropdowns; on uncheck → restore. When `pfb_pick_free_dnsbl_vip` finds nothing free, render the checkbox **disabled** with an `fa-exclamation-triangle` warning + tooltip. Wire the POST handler (`:466-475`, `:572-573`) so saving with the box on triggers the server-side create (via Phase 2 on the next pass, or inline) and stores the flag. Update the group help (marker, address scheme, lifecycle, the "isolated range" note).

### Phase 5 — Docs + smoke note + DoD

Prompt: `05_Docs_Smoke_DoD.txt`

- Document the feature (README/CLAUDE.md + settings help): the checkbox, the `pfB_AUTO_VIP_v*` marker, the address scheme, the enable/disable lifecycle, the v6-mandatory rule, and the HA behaviour. Note the smoke interplay (default-off keeps `ensure_dnsbl_vip` valid; optionally add an auto-create smoke case). Finalise §7 manual smoke + reject criteria.

---

## 7. Definition of done

- `pfb_dnsvip_auto` off ⇒ byte-identical DNSBL settings/save/update pass; smoke + "no VIP" scenario unaffected.
- With the box on: enable creates a marked, conflict-free VIP (v4 always, v6 when required) on `dnsbl_interface`, applied live; disable/uninstall removes **only** marker+IP-matched VIPs; manual VIPs never touched.
- v6 is mandatory when the resolver listens on IPv6 (auto-provisioned or required in manual mode); conflict-exhaustion disables the checkbox with a warning.
- `php -l` + PHPStan + ShellCheck clean; `python -m pytest` green/unchanged.
- Status → **Accepted** only after the maintainer confirms the manual smoke below on a live pfSense box.

### Reject / pivot criteria (decide cheaply)

- **Can't delete safely / idempotently:** if the marker+IP predicate proves unable to distinguish ours from a user VIP in some real config (e.g. user copies our descr), or `interface_vip_bring_down` leaves a stale alias on lo0 → tighten the marker (dedicated config-tracked uniqid) or pivot deletion to a config-stored id list. Settle in Phase 2 before the UI.
- **v6-mandatory too disruptive:** if forcing a v6 VIP on existing manual, v6-listening setups breaks more than it helps → soften manual mode to a non-blocking warning (auto mode still provisions). Decide in Phase 3.
- **No reliable v6-listen predicate:** if `pfb_unbound_listens_v6()` can't be made correct across CE/Plus → scope IPv6 to opt-in only (drop the mandatory rule), keep v4 auto-create.

### Manual smoke (owner: maintainer) — required before Accept

> CI has no live pf/Unbound to apply a VIP. Run on a live pfSense CE box.
>
> Items verified in CI / by code inspection are noted; the rest require on-box confirmation.

- [ ] **No-op (default off).** Fresh/upgraded install with the box off behaves exactly as today; manual dropdowns + validation unchanged. *(verified: save + render byte-identical when `pfb_dnsvip_auto` is absent/off — Phase 4 trace)*
- [ ] **Auto create.** Check the box, save, enable DNSBL → a `pfB_AUTO_VIP_v4` IP-Alias VIP at `10.10.10.53/32` appears on `lo0`, is live (`ifconfig lo0`), and `pfb_dnsvip4` points at it; a blocked name sinks to it.
- [ ] **Conflict.** With `10.10.10.53` already used (a manual VIP / interface subnet), the sweep picks the next free `.53`; with the whole sweep exhausted the checkbox is disabled + warning tooltip shown.
- [ ] **Range fills up post-enable.** Enable auto-create (VIP provisioned), then consume all `10.10.X.53` / `fd00:X::53` candidates with other VIPs — on the next settings page load the checkbox renders disabled+unchecked with the warning; `pfb_dnsvip_auto` stays `on` in stored config until the next save; the lifecycle manager no-ops safely (logs, leaves config untouched).
- [ ] **Teardown.** Disable DNSBL → the marked VIP is removed (config + `ifconfig`); disable pfBlockerNG → same; the `pfb_dnsvip_auto` setting + address choice persist; re-enable recreates it. A manually-created VIP present throughout is never touched.
- [ ] **IPv6 mandatory.** With the resolver listening on IPv6: auto mode provisions `pfB_AUTO_VIP_v6` `fd00::53/128`; manual mode without a v6 VIP errors on save / force-disables. *(on-box needed: confirm `pfb_unbound_listens_v6()` returns true when the resolver uses `interface-automatic` and the box has a real v6 address — link-local vs global caveat from Phase 1)*
- [ ] **HA sync.** On a CARP pair, the flag + VIP replicate and each node creates/removes its own lo0 VIP on its own enable/disable.
- [ ] **Uninstall.** Removing the package deletes the marked VIP(s); no orphan alias on lo0.

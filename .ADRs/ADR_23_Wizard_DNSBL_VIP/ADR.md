# ADR-23: DNSBL Wizard VIP Auto-Toggle

**Status:** Proposed
**Issue:** [#178](https://github.com/pfBlockerNG/pfBlockerNG/issues/178)
**Slack:** [thread](https://pfblockerng.slack.com/archives/C0B9QBZBEQG/p1781160111017199?thread_ts=1781008355.595609&cid=C0B9QBZBEQG)

---

## 1  Context

### 1.1  History

The original pfBlockerNG wizard included a **VIP setup step** where users typed a DNSBL
sinkhole IP address (`10.10.10.1` default) and optionally configured CARP parameters (VHID,
advbase, advskew, password). The package created and managed the VIP entry directly in
pfSense's `config.xml`.

Netgate **removed** this VIP handling in FreeBSD-ports commit
[8934050](https://github.com/pfsense/FreeBSD-ports/commit/8934050dfc892272d6848b32c6dd7764f09dd736).
The wizard step was replaced with two VIP selector dropdowns (`pfb_dnsvip4` / `pfb_dnsvip6`)
that require a pre-existing pfSense VIP — shifting ownership to the user.

### 1.2  ADR-13 re-introduction (without knowledge of the old code)

ADR-13 added an **auto-create** mechanism on the DNSBL settings page
(`pfblockerng_dnsbl.php`): a `pfb_dnsvip_auto` checkbox (default OFF) that lets pfBlockerNG
pick a free address from the `10.10.X.53` / `fd00:X::53` sweep, create a marked `pfB_AUTO_VIP_v4/v6`
Virtual IP on `lo0`, and remove it on disable/uninstall. The wizard was **not** updated to
expose this toggle — it still shows only the manual VIP selectors.

### 1.3  Problem

Users who run the setup wizard must pre-create a VIP at Firewall > Virtual IPs before the
wizard step can be completed, even though ADR-13's auto-create mechanism could handle it
automatically. The familiar "create a DNSBL VIP" workflow that existed before Netgate's
removal is missing from the wizard.

---

## 2  Decision

Extend wizard step 4 (DNSBL configuration) to expose ADR-13's `pfb_dnsvip_auto` toggle:

- Add a `pfb_dnsvip_auto` **checkbox** field in `pfblockerng_wizard.xml` bound to wizard
  step3 temp config; positioned before the manual VIP selectors.
- Add a **HA/CARP disclaimer** in the checkbox help text. CARP fields are **not**
  reintroduced — users on HA clusters use the manual VIP path and configure CARP via pfSense
  Firewall > Virtual IPs.
- In `pfblockerng_wizard.inc`: skip `pfb_validate_vips()` when auto is ON (step3 validation);
  persist `pfb_dnsvip_auto` to DNSBL settings and skip writing the manual VIP ids when auto
  is ON (step4 finalization).
- Wording echoes the original wizard: 10.10.X.53 address range, same familiar IP space that
  users remember from before the removal.
- **No JS prefill/disable** — the pfSense wizard framework has no JS injection point. The
  help text states "manual selections below are ignored" when auto is on.

The ADR-13 lifecycle engine (`pfb_manage_dnsbl_vip`, `pfb_pick_free_dnsbl_vip`,
`pfb_validate_vips`) in `pfblockerng.inc` is **unchanged** — this ADR only wires the wizard
UI to call through to it.

### Out of scope

- CARP field reintroduction
- JS-based dropdown prefill/disable in the wizard
- Conflict exhaustion pre-check in the wizard (the manager degrades safely; manual path available)
- Default-on for auto-create

---

## 3  Consequences

### Positive

- Users running the wizard for the first time can enable auto-VIP with one checkbox click —
  no manual VIP creation needed.
- Wording and IP range (`10.10.X.53`) align with what users remember from the original wizard.
- The manual VIP selector path (for HA/CARP users) is preserved unchanged.
- Zero changes to the ADR-13 engine: a 2-file, ~30-line change surfaces existing behaviour.

### Negative / risks

- No JS prefill means the manual selects remain visible and active-looking even when auto is
  checked (mitigated by the help text).
- No exhaustion pre-check means a wizard completion with auto=ON on a fully-conflicted system
  silently defers failure to the enable pass (same as the settings page sans checkbox-disable).

---

## 4  Implementation

Two PHP files change; one new PHPUnit test file.

### 4.1  `src/usr/local/www/wizards/pfblockerng_wizard.xml`

**Step 4 `<description>` (line ~252):** Replace "A VIP … must be configured first" mandate
with a choice framing:

```xml
<description><![CDATA[On this screen the pfBlockerNG DNSBL Category parameters will be set.<br />
Enable <strong>Create VIPs automatically</strong> below to have pfBlockerNG manage the
DNSBL sinkhole Virtual IP, or configure a VIP on the Localhost interface manually first at
<a target="_blank" href="/firewall_virtual_ip.php">Firewall &gt; Virtual IPs</a>.]]></description>
```

**New `pfb_dnsvip_auto` checkbox** (insert after the `DNSBL Webserver Configuration`
listtopic, before `pfb_dnsvip4`):

```xml
<field>
    <name>pfb_dnsvip_auto</name>
    <displayname>Auto VIP</displayname>
    <bindstofield>pfblockerng_wizard-&gt;step3-&gt;pfb_dnsvip_auto</bindstofield>
    <description><![CDATA[Create VIPs automatically. When enabled, pfBlockerNG creates and
manages the DNSBL sinkhole Virtual IP in the <strong>10.10.X.53</strong> range
(IPv6: <strong>fd00:X::53</strong>) — the manual selections below are ignored.<br />
<span class="text-danger">Note:</span> auto-created VIPs are
<strong>not HA/CARP aware</strong>. On a CARP/HA cluster, configure the DNSBL Virtual IP
manually instead.]]>
    </description>
    <type>checkbox</type>
    <value>on</value>
</field>
```

**`pfb_dnsvip4` / `pfb_dnsvip6` `<description>` text**: append
`(manual mode only — ignored when Auto VIP is enabled)`.

### 4.2  `src/usr/local/www/wizards/pfblockerng_wizard.inc`

**`step3_submitphpaction()` — gate VIP validation (lines ~114–124):**

```php
$pfb_auto = (isset($_POST['pfb_dnsvip_auto']) && $_POST['pfb_dnsvip_auto'] == 'on');
if (!$pfb_auto) {
    if ($_POST['pfb_dnsvip4'] == 'none') { $_POST['pfb_dnsvip4'] = ''; }
    if ($_POST['pfb_dnsvip6'] == 'none') { $_POST['pfb_dnsvip6'] = ''; }
    list($vips_valid, $error) = pfb_validate_vips('lo0', $_POST['pfb_dnsvip4'], $_POST['pfb_dnsvip6']);
    if (!$vips_valid) {
        $input_errors[] = "DNSBL: {$error}";
    }
}
```

**`step4_submitphpaction()` — persist flag + guard VIP id writes (after line ~165):**

```php
$pfb_auto = (config_get_path('pfblockerng_wizard/step3/pfb_dnsvip_auto') == 'on');
$new_config['pfblockerngdnsblsettings']['config'][0]['pfb_dnsvip_auto'] = $pfb_auto ? 'on' : '';
if (!$pfb_auto) {
    $new_config['pfblockerngdnsblsettings']['config'][0]['pfb_dnsvip4'] =
        config_get_path('pfblockerng_wizard/step3/pfb_dnsvip4');
    $new_config['pfblockerngdnsblsettings']['config'][0]['pfb_dnsvip6'] =
        config_get_path('pfblockerng_wizard/step3/pfb_dnsvip6');
}
```

The existing redirect to `pfblockerng_update.php?wizard=reload` triggers the enable pass →
`pfb_manage_dnsbl_vip('enabled')` provisions the auto VIPs. No further wiring needed.

### 4.3  `tests/php/WizardVipAutoTest.php` (new)

PHPUnit branch coverage for the `pfb_dnsvip_auto` gate. Three areas:

**Decision predicate** (`pfb_wizard_vip_auto_enabled(array $post): bool` helper, or test
`step3_submitphpaction` indirectly via a POST mock):

- `['pfb_dnsvip_auto' => 'on']` → true
- `[]` (absent) → false
- `['pfb_dnsvip_auto' => '']`, `['pfb_dnsvip_auto' => '0']` → false

**Persistence shape** (via `step4_submitphpaction` if testable under bootstrap doubles):

- Assert the before-state (auto=OFF) first: `pfb_dnsvip_auto=''`, `pfb_dnsvip4`/`pfb_dnsvip6`
  written from step3 config.
- Then flip to auto=ON: `pfb_dnsvip_auto='on'`, `pfb_dnsvip4`/`pfb_dnsvip6` absent.

Style: `DnsblMarkedVipTest.php`, `DnsblV6RequiredTest.php`.

---

## 5  Reference files (unchanged)

| File | Relevant symbols |
|------|-----------------|
| `pfblockerng.inc` | `pfb_manage_dnsbl_vip()` (~980), `pfb_validate_vips()` (~753), `pfb_pick_free_dnsbl_vip()` (~834), `pfb_unbound_listens_v6()` (~895) |
| `pfblockerng_dnsbl.php` | ADR-13 canonical implementation to mirror (lines ~490–538, ~2597–2656, ~3077–3236) |

---

## 6  Migration

No migration logic needed: `pfb_dnsvip_auto` defaults to absent/off in existing configs —
`pfb_global()` treats absent as off (already guarded in ADR-13 via `?? ''` coalesce).

---

## 7  Definition of Done

### Automated (CI)

- [ ] `php -l` both changed files — no parse errors
- [ ] PHPStan clean (no new un-stubbed calls)
- [ ] `vendor/bin/phpunit` — all tests pass including new `WizardVipAutoTest`
- [ ] ADR-14 Tier A (`ui_render`): GET wizard page → 200, no PHP errors, `pfb_dnsvip_auto`
      checkbox present in response body, no new `php_error.log` line

### Manual smoke (maintainer, on-box)

- [ ] Wizard auto=ON: complete wizard → `config.xml`
      `pfblockerngdnsblsettings/config/0/pfb_dnsvip_auto = 'on'`; after reload a
      `pfB_AUTO_VIP_v4` VIP at `10.10.X.53` appears at Firewall > Virtual IPs; `pfb_dnsvip4`
      repointed to the new `_vip{uniqid}` id
- [ ] Wizard auto=OFF + manual `lo0` VIP: validation rejects missing/wrong-interface VIP;
      accepts valid lo0 VIP; `pfb_dnsvip4` stored correctly
- [ ] Back navigation from step 4: checkbox state restored correctly
- [ ] HA/CARP disclaimer visible in rendered wizard step 4

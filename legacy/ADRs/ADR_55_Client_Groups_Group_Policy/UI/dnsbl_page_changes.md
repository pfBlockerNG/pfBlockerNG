# ADR-55 UI reference — `pfblockerng_dnsbl.php` + tab-sweep splice instructions

Companion to the two reference pages in this directory. Phase 3 applies these changes;
divergences go in the phase handoff.

## 1. Replace the legacy DNSBL Group Policy section

Target: the `Form_Section('DNSBL Group Policy', 'Python_Group_Policy', COLLAPSIBLE|SEC_CLOSED)`
block (at authoring time `pfblockerng_dnsbl.php:2966-2984`) **and** the `pfb_gp` enable
checkbox (`:2788-2794`).

- The checkbox and the `pfb_gp_bypass_list` textarea are **removed from the page** (the keys
  stay in config — the legacy enforcement path is untouched until ADR-25 Phase 6; only the
  editing surface moves).
- In the section's place, a single static text in the same position:

```php
$section = new Form_Section('DNSBL Group Policy', 'Python_Group_Policy', COLLAPSIBLE|SEC_CLOSED);
$section->addInput(new Form_StaticText(
        NULL,
        'Group Policy has moved to the <a href="/pfblockerng/pfblockerng_group_policy.php">Group Policy</a> tab.<br />'
        . 'The previous Bypass IP list was migrated to the \'Legacy_Bypass\' Client Group.'));
$form->add($section);
```

- ADR-25 Phase 6 later updates this text when the legacy keys retire (its prompt owns that).

## 2. Tab sweep — add `Group Policy` after `Feeds` on every page

Every page under `src/usr/local/www/pfblockerng/` that builds the top `$tab_array` (grep
`display_top_tabs`) gains one line after the Feeds entry:

```php
$tab_array[]    = array(gettext('Group Policy'),        FALSE,  '/pfblockerng/pfblockerng_group_policy.php');
```

(`FALSE` becomes the page's `$active`-style flag only on the two new Group Policy pages,
which carry their own tab arrays — see the reference files.)

List every touched file in the phase handoff. The widget/wizard pages without the top tab
row are out of scope.

## 3. Privileges

Follow the existing `.priv.inc` pattern under `src/etc/inc/priv/` — add the two new page
URLs to the pfBlockerNG privilege definition (same entry style as the other
`pfblockerng_*.php` pages) so restricted admins keep working.

## 4. Tier A markers

- `pfblockerng_group_policy.php` marker: the `Client Groups Summary` panel title.
- `pfblockerng_group_policy_edit.php` marker: the `Save Client Group Settings` form title.

Register both in `tests/smoke/ui/` per the existing PAGE_TABLE pattern.

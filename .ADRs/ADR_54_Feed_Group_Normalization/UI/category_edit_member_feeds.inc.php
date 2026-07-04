<?php
/*
 * category_edit_member_feeds.inc.php — ADR-54 UI REFERENCE SPLICE SECTION
 *
 * NOT a standalone page. Phase 4 splices these two blocks into
 * src/usr/local/www/pfblockerng/pfblockerng_category_edit.php:
 *
 *   BLOCK A replaces the "{$type} Source Definitions" Form_Section (the repeatable
 *           per-feed url/header row grid — at authoring time built around lines
 *           1051-1360) with the Member Feeds picker. The old act=add / act=addgroup
 *           deep links from the Feeds page now PRE-SELECT entries in this
 *           multi-select ($preselect_fids) and pre-create FEED entities on save.
 *   BLOCK B adjusts the Settings section: retitle 'Action' -> 'Default Action'
 *           (help appended), and the DNSBL action select gains
 *           'Unbound (Policy-only)'.
 *
 * Helper contracts consumed (ADR-54 Phase 2):
 *   pfb_feed_options(string $family): array
 *       — fid => "header — url" label, Enabled first then natural sort (the
 *         ordering rule the old row grid applied at :1063-1080)
 *   pfb_feedgroup_members(int $rowid, string $family): array — member fids
 * Saving: the page's save handler maps the posted 'members' array to the group's
 * member list through the Phase-2 helpers; per-feed fields are edited on
 * pfblockerng_feed_edit.php only.
 *
 * Licensed under the Apache License, Version 2.0 — see the page header it is
 * spliced into.
 */

// ============================ BLOCK A =========================================
// Replaces: $section = new Form_Section("{$type} Source Definitions"); ... (the
// row grid + its sort/anchor machinery). $gtype/$rowid are page-scope as today.

$section = new Form_Section('Member Feeds');

$section->addInput(new Form_Select(
	'members',
	'Member of this Group',
	pfb_feedgroup_members($rowid, $gtype),
	pfb_feed_options($gtype),
	TRUE
))->setHelp('Default: <strong>none</strong><br />'
		. 'Select the Feed(s) that belong to this Group. '
		. 'A Feed may belong to several Groups; it is downloaded once and applied per Group.');

$section->addInput(new Form_StaticText(
	'Manage Feeds',
	'<small>'
	. '<a href="/pfblockerng/pfblockerng_feed_edit.php?family=' . htmlspecialchars($gtype) . '">Add a new custom Feed</a>&emsp;'
	. '<a href="/pfblockerng/pfblockerng_feeds.php?type=' . htmlspecialchars($gtype) . '">Browse the Feed catalog</a>'
	. '</small>'));

$form->add($section);

// ============================ BLOCK B =========================================
// 1) The Settings section's Action select (at authoring time :1399-1405):
//    label 'Action' -> 'Default Action'; $action_txt gains this appended line:
//
//      . '<br />Client Group policies (Group Policy tab) may override this action for '
//      . 'specific source networks. Select an <strong>Alias</strong> action to create '
//      . 'the alias without any global firewall rule (policy-only).'
//
// 2) DNSBL only — the action options array (at authoring time :405) becomes:

$options_action_dnsbl = array(
	'Disabled'	=> 'Disabled',
	'unbound'	=> 'Unbound',
	'policy_only'	=> 'Unbound (Policy-only)',
);

// with the select's help gaining:
//
//      . '<br />&#8226 <strong>Unbound (Policy-only)</strong>, the Group is compiled '
//      . 'into DNSBL but only enforced for Client Groups bound to it.'
//
// (Until ADR-25's decision layer lands, ADR-54 SS2.2 keeps policy_only
// enforcement-inert — the help text ships a trailing '(Not enforced yet.)' note
// that ADR-25 Phase 6 removes.)

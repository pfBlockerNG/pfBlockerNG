<?php
/*
 * pfblockerng_group_policy_edit.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2016-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2015-2024 BBcan177@gmail.com
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * ============================================================================
 * ADR-55 UI REFERENCE IMPLEMENTATION (Phase 3 splices this into src/).
 * Authoritative design target — adapt mechanically to drift, never redesign
 * silently (divergences go in the phase handoff).
 *
 * Helper contracts consumed (defined by ADR-55 Phases 1-2):
 *   pfb_cg_read(int $rowid): ?array        — one Client Group row or NULL
 *   pfb_cg_save(int $rowid, array $cg): void
 *   pfb_cg_validate(array $cg, int $rowid): array          — input_errors (Phase 1)
 *   pfb_cg_binding_validate(array $binding): array         — incl. the dead-override
 *       refusal + cross-family vocabulary checks (Phase 2)
 *   pfb_cg_rule_counts(): array            — ['total', 'per_cg' => [name => int]]
 *   pfb_feedgroup_options(array $families): array          — FG name => label
 *       (ADR-54 helper; ADR-55 passes ['ipv4','ipv6'] — dnsbl UNLOCKS in ADR-25 P6)
 *   pfb_cg_alias_options(): array           — non-pfB_ host/network alias names
 *       (same source/filter as the DNSBL exception-alias picker)
 * Bindings use the stock pfSense repeatable row-helper (addrow/deleterowN buttons +
 * Form_Group::addClass('repeatable')) — verify against the live row-helper JS when
 * splicing; NO custom widget may be introduced.
 * ============================================================================
 */

require_once('guiconfig.inc');
require_once('globals.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');

global $pfb;
pfb_global();

$input_errors = array();
$rowid = 0;
if (isset($_REQUEST['rowid'])) {
	$temp_value = pfb_filter($_REQUEST['rowid'], PFB_FILTER_NUM, 'Group Policy Edit');
	if (!empty($temp_value) || $_REQUEST['rowid'] == 0) {
		$rowid = $temp_value ?: 0;
	}
}

// dnsbl stays LOCKED until ADR-25 Phase 6 flips this list (ADR-55 SS2.4).
$binding_families	= array('ipv4', 'ipv6');
$options_fg		= pfb_feedgroup_options($binding_families);

// '' = inherit the Feed Group's Default Action. No Alias_* (bindings always emit rules).
$options_override = array(
	''		=> 'Group default',
	'Deny_Inbound'	=> 'Deny Inbound',	'Deny_Outbound'		=> 'Deny Outbound',	'Deny_Both'	=> 'Deny Both',
	'Permit_Inbound' => 'Permit Inbound',	'Permit_Outbound'	=> 'Permit Outbound',	'Permit_Both'	=> 'Permit Both',
	'Match_Inbound'	=> 'Match Inbound',	'Match_Outbound'	=> 'Match Outbound',	'Match_Both'	=> 'Match Both',
);

$options_log = array('' => 'Group default', 'enabled' => 'Enabled', 'disabled' => 'Disabled');

$options_sched = array('' => 'none (always)');
foreach (config_get_path('schedules/schedule', []) as $schedule) {
	if (!empty($schedule['name'])) {
		$options_sched[$schedule['name']] = $schedule['name'];
	}
}

$pconfig = pfb_cg_read($rowid) ?: array(
	'name'		=> '',
	'description'	=> '',
	'enabled'	=> 'on',
	'addresses'	=> '',
	'aliases'	=> array(),
	'allow_domains'	=> '',
	'deny_domains'	=> '',
	'binding'	=> array(),
);

if ($_POST && isset($_POST['save'])) {

	$input_errors = array();

	$cg = array(
		'name'		=> pfb_filter($_POST['name'] ?? '', PFB_FILTER_WORD, 'Group Policy Edit'),
		'description'	=> pfb_filter($_POST['description'] ?? '', PFB_FILTER_HTML, 'Group Policy Edit'),
		'enabled'	=> (isset($_POST['enabled']) && $_POST['enabled'] == 'on') ? 'on' : '',
		'addresses'	=> base64_encode((string)($_POST['addresses'] ?? '')),
		'aliases'	=> array_values(array_filter(array_map('strval', (array)($_POST['aliases'] ?? array())))),
		'allow_domains'	=> base64_encode((string)($_POST['allow_domains'] ?? '')),
		'deny_domains'	=> base64_encode((string)($_POST['deny_domains'] ?? '')),
		'binding'	=> array(),
	);

	// Collect repeatable binding rows (fg-N / override-N / log-N / sched-N)
	foreach ($_POST as $key => $value) {
		if (strpos($key, 'fg-') !== 0) {
			continue;
		}
		$b_id = substr($key, 3);
		if (pfb_filter($b_id, PFB_FILTER_NUM, 'Group Policy Edit') === FALSE && $b_id !== '0') {
			continue;
		}
		if (empty($value)) {
			continue;	// blank FG select = removed/empty row
		}
		$cg['binding'][] = array(
			'feedgroup'	=> pfb_filter($value, PFB_FILTER_WORD, 'Group Policy Edit'),
			'enabled'	=> 'on',
			'action_override' => pfb_filter($_POST['override-' . $b_id] ?? '', PFB_FILTER_HTML, 'Group Policy Edit'),
			'log_override'	=> pfb_filter($_POST['log-' . $b_id] ?? '', PFB_FILTER_HTML, 'Group Policy Edit'),
			'sched'		=> pfb_filter($_POST['sched-' . $b_id] ?? '', PFB_FILTER_HTML, 'Group Policy Edit'),
		);
	}

	// Phase-1 entity validation (name/addresses/aliases/uniqueness) +
	// Phase-2 per-binding validation (vocabulary, (CG,FG) uniqueness, dead-override).
	$input_errors = array_merge($input_errors, pfb_cg_validate($cg, $rowid));
	foreach ($cg['binding'] as $binding) {
		$input_errors = array_merge($input_errors, pfb_cg_binding_validate($binding));
	}

	if (!$input_errors) {
		pfb_cg_save($rowid, $cg);
		write_config("pfBlockerNG: Saved Client Group [ {$cg['name']} ]");
		pfb_mark_pending_changes();	// alias/rules apply on the next Update
		header('Location: /pfblockerng/pfblockerng_group_policy.php?savemsg='
			. urlencode("Client Group [ {$cg['name']} ] saved"));
		exit;
	}

	// Redisplay with errors: keep the submitted values
	$pconfig		= $cg;
	$pconfig['addresses']	= (string)($_POST['addresses'] ?? '');
	$pconfig['allow_domains'] = (string)($_POST['allow_domains'] ?? '');
	$pconfig['deny_domains']  = (string)($_POST['deny_domains'] ?? '');
} else {
	// Decode the base64 textareas for display
	$pconfig['addresses']	 = pfbng_text_area_decode($pconfig['addresses'] ?? '', TRUE, FALSE);
	$pconfig['allow_domains'] = pfbng_text_area_decode($pconfig['allow_domains'] ?? '', TRUE, FALSE);
	$pconfig['deny_domains']  = pfbng_text_area_decode($pconfig['deny_domains'] ?? '', TRUE, FALSE);
}

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('Group Policy'), gettext('Edit'));
include_once('head.inc');

$get_req = pfb_alerts_default_page();

$tab_array	= array();
$tab_array[]	= array(gettext('General'),	FALSE,	'/pfblockerng/pfblockerng_general.php');
$tab_array[]	= array(gettext('IP'),		FALSE,	'/pfblockerng/pfblockerng_ip.php');
$tab_array[]	= array(gettext('DNSBL'),	FALSE,	'/pfblockerng/pfblockerng_dnsbl.php');
$tab_array[]	= array(gettext('Update'),	FALSE,	'/pfblockerng/pfblockerng_update.php');
$tab_array[]	= array(gettext('Reports'),	FALSE,	"/pfblockerng/pfblockerng_alerts.php{$get_req}");
$tab_array[]	= array(gettext('Feeds'),	FALSE,	'/pfblockerng/pfblockerng_feeds.php');
$tab_array[]	= array(gettext('Group Policy'), TRUE,	'/pfblockerng/pfblockerng_group_policy.php');
$tab_array[]	= array(gettext('Logs'),	FALSE,	'/pfblockerng/pfblockerng_log.php');
$tab_array[]	= array(gettext('Sync'),	FALSE,	'/pfblockerng/pfblockerng_sync.php');
pfb_software_add_tab($tab_array);
display_top_tabs($tab_array, TRUE);
pfb_print_pending_changes_box();

if ($input_errors) {
	print_input_errors($input_errors);
}

$form = new Form('Save Client Group Settings');
$form->addGlobal(new Form_Input('rowid', 'rowid', 'hidden', "{$rowid}"));

// ---- Info ------------------------------------------------------------------
$section = new Form_Section('Info');
$section->addInput(new Form_StaticText(
	'Links',
	'<small>'
	. '<a href="/firewall_aliases.php" target="_blank">Firewall Aliases</a>&emsp;'
	. '<a href="/firewall_rules.php" target="_blank">Firewall Rules</a>&emsp;'
	. '<a href="/firewall_schedule.php" target="_blank">Firewall Schedules</a></small>'
));

$group = new Form_Group('Name / Description');
$group->add(new Form_Input(
	'name',
	'Name (No spaces or special/Int. chars)',
	'text',
	$pconfig['name']
))->setWidth(3);

$group->add(new Form_Input(
	'description',
	'Description',
	'text',
	$pconfig['description']
))->setWidth(6);
$section->add($group);

$section->addInput(new Form_StaticText(
	NULL,
	'Enter Name&nbsp;( Max 24 characters ) and Description.'
	. '<div class="infoblock alert-info clearfix">'
	. 'The Client Group is created as Firewall Alias <strong>pfB_CG_&lt;Name&gt;</strong>.<br />'
	. 'Do not prefix the Name with <strong>pfB_</strong> or <strong>pfb_</strong><br />'
	. '<strong>Names must be unique.</strong><br />'
	. '<strong>International, special or space characters are not allowed.</strong>'
	. '</div>'));

$section->addInput(new Form_Checkbox(
	'enabled',
	'Enable',
	'Enable this Client Group',
	($pconfig['enabled'] == 'on'),
	'on'
))->setHelp('When disabled, the Client Group is kept but no Alias, firewall rules or DNSBL policy are generated.');

$form->add($section);

// ---- Members ----------------------------------------------------------------
$section = new Form_Section('Members');

$section->addInput(new Form_Textarea(
	'addresses',
	'Source Addresses',
	$pconfig['addresses']
))->setRows(8)
  ->setHelp('Enter the Local IPv4/IPv6 Addresses or CIDRs (one per line) that belong to this Client Group.');

$alias_select = new Form_Select(
	'aliases',
	'Source Aliases',
	$pconfig['aliases'],
	pfb_cg_alias_options(),
	TRUE
);
$section->addInput($alias_select)
	->setHelp('<a target="_blank" href="/firewall_aliases.php?tab=ip">Click Here to add/edit Aliases</a><br />'
		. 'Select existing Network or Host-type Alias(es) to include. Do not use \'pfB_\' Aliases.<br />'
		. '<span class="text-danger">Note:</span>&nbsp;FQDN Alias entries apply to IP firewall rules only; '
		. 'they are ignored for DNSBL client matching.');

$form->add($section);

// ---- DNSBL Domain Rules ------------------------------------------------------
$section = new Form_Section('DNSBL Domain Rules', 'dnsbl_domain_rules', COLLAPSIBLE|SEC_CLOSED);

$section->addInput(new Form_Textarea(
	'allow_domains',
	'Allow Domains',
	$pconfig['allow_domains']
))->setRows(6)
  ->setHelp('Domains always allowed for this Client Group (one per line). Allow wins over any Block.');

$section->addInput(new Form_Textarea(
	'deny_domains',
	'Deny Domains',
	$pconfig['deny_domains']
))->setRows(6)
  ->setHelp('Domains always blocked for this Client Group (one per line).');

$form->add($section);

// ---- Feed Group Policies (repeatable binding rows) ---------------------------
$section = new Form_Section('Feed Group Policies');

$section->addInput(new Form_StaticText(
	NULL,
	'<span class="text-danger">Note:</span>&nbsp;Policies never remove a Feed Group\'s default rules — '
	. 'they add rules scoped to this Client Group:<br />'
	. '<dl class="dl-horizontal">'
	. '<dt>Outbound</dt><dd>source: this Client Group, destination: the Feed Group alias</dd>'
	. '<dt>Inbound</dt><dd>source: the Feed Group alias, destination: this Client Group</dd>'
	. '</dl>'
	. 'Select an \'Alias\' Default Action on the Feed Group to enforce it through Policies only.'));

$bindings = $pconfig['binding'];
if (empty($bindings)) {
	$bindings = array(array('feedgroup' => '', 'action_override' => '', 'log_override' => '', 'sched' => ''));
}

$last = count($bindings) - 1;
foreach ($bindings as $b_id => $binding) {

	$group = new Form_Group($b_id == 0 ? 'Policies' : '');
	$group->addClass('repeatable');

	$group->add(new Form_Select(
		'fg-' . $b_id,
		'',
		$binding['feedgroup'],
		array('' => 'none') + $options_fg
	))->setHelp(($b_id == $last) ? 'Feed Group' : NULL)
	  ->setAttribute('style', 'width: auto')
	  ->setWidth(3);

	$group->add(new Form_Select(
		'override-' . $b_id,
		'',
		$binding['action_override'],
		$options_override
	))->setHelp(($b_id == $last) ? 'Action (blank = Group default)' : NULL)
	  ->setAttribute('style', 'width: auto')
	  ->setWidth(3);

	$group->add(new Form_Select(
		'log-' . $b_id,
		'',
		$binding['log_override'],
		$options_log
	))->setHelp(($b_id == $last) ? 'Logging' : NULL)
	  ->setAttribute('style', 'width: auto')
	  ->setWidth(2);

	$group->add(new Form_Select(
		'sched-' . $b_id,
		'',
		$binding['sched'],
		$options_sched
	))->setHelp(($b_id == $last) ? 'Schedule' : NULL)
	  ->setAttribute('style', 'width: auto')
	  ->setWidth(2);

	$group->add(new Form_Button(
		'deleterow' . $b_id,
		'Delete',
		NULL,
		'fa-solid fa-trash-can'
	))->addClass('btn-warning');

	$section->add($group);
}

$section->addInput(new Form_Button(
	'addrow',
	'Add Policy',
	NULL,
	'fa-solid fa-plus'
))->addClass('btn-success addbtn');

$rule_counts = pfb_cg_rule_counts();
$section->addInput(new Form_StaticText(
	NULL,
	'This Client Group generates <strong>'
	. htmlspecialchars((string)($rule_counts['per_cg'][$pconfig['name']] ?? 0))
	. '</strong> firewall rules.'));

$form->add($section);

print ($form);
?>
<script src="pfBlockerNG.js" type="text/javascript"></script>
<?php include('foot.inc');?>

<?php
/*
 * pfblockerng_feed_edit.php
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
 * ADR-54 UI REFERENCE IMPLEMENTATION (Phase 4 splices this into src/).
 * Authoritative design target — adapt mechanically to drift, never redesign
 * silently (divergences go in the phase handoff).
 *
 * Helper contracts consumed (defined by ADR-54 Phase 2):
 *   pfb_feed_read(string $fid): ?array      — one FEED row or NULL
 *   pfb_feed_save(string $fid, array $feed, array $memberships): void
 *       ($memberships = Feed Group names this feed belongs to; the helper updates
 *        the groups' member lists atomically)
 *   pfb_feed_validate(array $feed, array $memberships, string $orig_fid): array
 *       — input_errors: header PFB_FILTER_WORD + per-family uniqueness (the SWC
 *         fixture), URL validity (reuse the category_edit checks), enabled-orphan
 *         refusal ("Feed must be a member of at least one Feed Group (or set
 *         State to Disabled).")
 *   pfb_feed_memberships(string $fid): array — Feed Group names containing the feed
 *   pfb_feedgroup_options(array $families): array — FG name => label
 * ============================================================================
 */

require_once('guiconfig.inc');
require_once('globals.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');

global $pfb;
pfb_global();

$family = 'ipv4';
$fid = '';

if (isset($_REQUEST['family'])) {
	$temp_value = pfb_filter($_REQUEST['family'], PFB_FILTER_HTML, 'Feed Edit');
	if (in_array($temp_value, array('ipv4', 'ipv6', 'dnsbl'))) {
		$family = $temp_value;
	}
}
if (isset($_REQUEST['fid'])) {
	// fid = "{family}:{header}" — both halves \w-only after the split
	$temp_value = (string)$_REQUEST['fid'];
	$parts = explode(':', $temp_value, 2);
	if (count($parts) == 2 &&
	    in_array($parts[0], array('ipv4', 'ipv6', 'dnsbl')) &&
	    pfb_filter($parts[1], PFB_FILTER_WORD, 'Feed Edit') !== FALSE) {
		$fid = "{$parts[0]}:{$parts[1]}";
		$family = $parts[0];
	}
}

$options_state = array('Enabled' => 'ON', 'Disabled' => 'OFF', 'Hold' => 'HOLD', 'Flex' => 'FLEX');
if ($family == 'dnsbl') {
	$options_format = array('auto' => 'Auto', 'rsync' => 'rsync');
} else {
	$options_format = array('auto' => 'Auto', 'geoip' => 'GeoIP', 'regex' => 'Regex',
				'whois' => 'Whois', 'asn' => 'ASN', 'rsync' => 'rsync');
}

$pconfig = ($fid !== '') ? pfb_feed_read($fid) : NULL;
if ($pconfig === NULL) {
	$pconfig = array(
		'family'	=> $family,
		'header'	=> '',
		'url'		=> '',
		'state'		=> 'Disabled',
		'format'	=> 'auto',
		'feed_action'	=> 'Deny',
	);
}
$memberships = ($fid !== '') ? pfb_feed_memberships($fid) : array();

if ($_POST && isset($_POST['save'])) {

	$input_errors = array();

	$feed = array(
		'family'	=> $family,
		'header'	=> pfb_filter($_POST['header'] ?? '', PFB_FILTER_WORD, 'Feed Edit'),
		'url'		=> trim((string)($_POST['url'] ?? '')),
		'state'		=> in_array($_POST['state'] ?? '', array_keys($options_state)) ? $_POST['state'] : 'Disabled',
		'format'	=> in_array($_POST['format'] ?? '', array_keys($options_format)) ? $_POST['format'] : 'auto',
		'feed_action'	=> ($family == 'dnsbl' && ($_POST['feed_action'] ?? '') == 'Permit') ? 'Permit' : 'Deny',
	);
	$new_memberships = array_values(array_filter(array_map('strval', (array)($_POST['groups'] ?? array()))));

	$input_errors = pfb_feed_validate($feed, $new_memberships, $fid);

	if (!$input_errors) {
		$new_fid = "{$feed['family']}:{$feed['header']}";
		pfb_feed_save($fid !== '' ? $fid : $new_fid, $feed, $new_memberships);
		write_config("pfBlockerNG: Saved Feed [ {$feed['header']} ]");
		pfb_mark_pending_changes();	// applies on the next Update, not on save
		header('Location: /pfblockerng/pfblockerng_feeds.php?type=' . urlencode($family)
			. '&savemsg=' . urlencode("Feed [ {$feed['header']} ] saved"));
		exit;
	}

	$pconfig = $feed;
	$memberships = $new_memberships;
}

$type_label = strtoupper($family == 'dnsbl' ? 'DNSBL' : $family);
$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('Feeds'), gettext('Edit Feed'));
include_once('head.inc');

$get_req = pfb_alerts_default_page();

$tab_array	= array();
$tab_array[]	= array(gettext('General'),	FALSE,	'/pfblockerng/pfblockerng_general.php');
$tab_array[]	= array(gettext('IP'),		FALSE,	'/pfblockerng/pfblockerng_ip.php');
$tab_array[]	= array(gettext('DNSBL'),	FALSE,	'/pfblockerng/pfblockerng_dnsbl.php');
$tab_array[]	= array(gettext('Update'),	FALSE,	'/pfblockerng/pfblockerng_update.php');
$tab_array[]	= array(gettext('Reports'),	FALSE,	"/pfblockerng/pfblockerng_alerts.php{$get_req}");
$tab_array[]	= array(gettext('Feeds'),	TRUE,	'/pfblockerng/pfblockerng_feeds.php');
$tab_array[]	= array(gettext('Group Policy'), FALSE,	'/pfblockerng/pfblockerng_group_policy.php');
$tab_array[]	= array(gettext('Logs'),	FALSE,	'/pfblockerng/pfblockerng_log.php');
$tab_array[]	= array(gettext('Sync'),	FALSE,	'/pfblockerng/pfblockerng_sync.php');
pfb_software_add_tab($tab_array);
display_top_tabs($tab_array, TRUE);
pfb_print_pending_changes_box();

if ($input_errors) {
	print_input_errors($input_errors);
}

$form = new Form('Save Feed');
$form->addGlobal(new Form_Input('fid', 'fid', 'hidden', "{$fid}"));
$form->addGlobal(new Form_Input('family', 'family', 'hidden', "{$family}"));

// ---- Info ------------------------------------------------------------------
$section = new Form_Section("{$type_label} Feed");

$group = new Form_Group('Header / Source URL');
$group->add(new Form_Input(
	'header',
	'Header/Label (No spaces or special/Int. chars)',
	'text',
	$pconfig['header']
))->setWidth(3);

$group->add(new Form_Input(
	'url',
	'Source URL',
	'text',
	$pconfig['url']
))->setWidth(6);
$section->add($group);

$section->addInput(new Form_StaticText(
	NULL,
	'Enter the Header/Label and Source URL.'
	. '<div class="infoblock alert-info clearfix">'
	. 'The Header/Label is used as the on-disk filename.<br />'
	. '<strong>Names must be unique per tab (IPv4/IPv6/DNSBL).</strong><br />'
	. '<strong>International, special or space characters are not allowed.</strong>'
	. '</div>'));

$form->add($section);

// ---- Settings ----------------------------------------------------------------
$section = new Form_Section('Settings');

$section->addInput(new Form_Select(
	'state',
	'State',
	$pconfig['state'],
	$options_state
))->setHelp('Default: <strong>OFF</strong><br />'
		. '&#8226 <strong>ON</strong>, the Feed is downloaded and applied via its Feed Group(s).<br />'
		. '&#8226 <strong>OFF</strong>, the Feed is kept but not used.<br />'
		. '&#8226 <strong>HOLD</strong>, download once and do not update.<br />'
		. '&#8226 <strong>FLEX</strong>, allow a downgraded SSL download on failure.')
  ->setAttribute('style', 'width: auto');

$section->addInput(new Form_Select(
	'format',
	'Format',
	$pconfig['format'],
	$options_format
))->setHelp('Select the Format of the Feed. <strong>Auto</strong> suits most Feeds.')
  ->setAttribute('style', 'width: auto');

if ($family == 'dnsbl') {
	$section->addInput(new Form_Select(
		'feed_action',
		'List Action',
		$pconfig['feed_action'],
		array('Deny' => 'Deny', 'Permit' => 'Permit')
	))->setHelp('Default: <strong>Deny</strong><br />'
			. 'A <strong>Permit</strong> Feed whitelists its domains from DNSBL blocking.')
	  ->setAttribute('style', 'width: auto');
}

$form->add($section);

// ---- Membership ----------------------------------------------------------------
$section = new Form_Section('Membership');

$section->addInput(new Form_Select(
	'groups',
	'Member of Feed Groups',
	$memberships,
	pfb_feedgroup_options(array($family)),
	TRUE
))->setHelp('Default: <strong>none</strong><br />'
		. 'Select the Feed Group(s) this Feed belongs to. '
		. 'An Enabled Feed must belong to at least one Feed Group.');

$section->addInput(new Form_StaticText(
	NULL,
	'<span class="text-danger">Note:</span>&nbsp;Removing the last Feed Group membership disables this Feed.'));

$form->add($section);

print ($form);
?>
<script src="pfBlockerNG.js" type="text/javascript"></script>
<?php include('foot.inc');?>

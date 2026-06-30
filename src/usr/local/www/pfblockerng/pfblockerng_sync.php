<?php
/*
 * pfblockerng_sync.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2016-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2015-2024 BBcan177@gmail.com
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the \"License\");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an \"AS IS\" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

require_once('guiconfig.inc');
require_once('globals.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');

global $pfb;
pfb_global();

$pfb['sconfig'] = PfbConfig::readSection('installedpackages/pfblockerngsync/config/0');

$pconfig = array();
$pconfig['varsynconchanges']	= $pfb['sconfig']['varsynconchanges']	?: '';
$pconfig['varsynctimeout']	= $pfb['sconfig']['varsynctimeout']	?: 150;
$pconfig['syncinterfaces']	= $pfb['sconfig']['syncinterfaces']	?: '';

// Select field options
$options_varsynconchanges	= [ 'disabled' => 'Do not sync this package configuration', 'auto' => 'Sync to configured system backup server', 'manual' => 'Sync to host(s) defined below' ];

// $input_errors is read unconditionally in the render section below, so it must be
// defined on every request path. Initialise it once.
$input_errors = array();

// Validate input fields and save
if ($_POST) {
	if (isset($_POST['save'])) {

		// Validate varsynctimeout. Default 150 and max at 5000
		$_POST['varsynctimeout'] = min(5000, pfb_filter($_POST['varsynctimeout'], PFB_FILTER_NUM, 'Sync', 150));

		// Validate Select field options
		$select_options = array(	'varsynconchanges'	=> ''
						);

		foreach ($select_options as $s_option => $s_default) {
			if (is_array($_POST[$s_option])) {
				$_POST[$s_option] = $s_default;
			}
			elseif (!array_key_exists($_POST[$s_option], ${"options_$s_option"})) {
				$_POST[$s_option] = $s_default;
			}
		}

		$rowhelper_exist = array();
		foreach ($_POST as $key => $value) {

			// Parse 'rowhelper' fields and save new values
			if (strpos($key, '-') !== FALSE) {
				$k_field = explode('-', $key);

				// Collect all rowhelper keys
				$rowhelper_exist[$k_field[1]] = '';

				switch ($k_field[0]) {
					case 'syncinterfaces':
						if ($value == 'on' || $value == '') {
							//
						} else {
							$input_errors[] = gettext('Invalid XMLRPC Replication target enabled');
						}
						break;
					case 'varsyncusername':
						// Validate Username field
						if (preg_match("/[^a-zA-Z0-9\._-]/", $value)) {
							$input_errors[] = gettext('The username contains invalid characters.');
						}
						if (strlen($value) > 16) {
							$input_errors[] = gettext('The username is longer than 16 characters.');
						}
						break;
					case 'varsyncpassword':
						// Store verbatim: the password is a secret credential used for
						// XMLRPC authentication, not rendered as raw HTML. HTML-escaping
						// it here corrupted any password containing & " ' < > (the
						// escaped form was sent to the peer, breaking auth). Form_Input
						// escapes it for safe display on re-render.
						$value = pfb_sync_filter_password($value);
						break;
					case 'varsyncipaddress':
						// Validate IP Address/Hostname
						if (($_POST['varsynconchanges'] == 'auto') && (mb_strlen(strval($value)) < 1)) {
							continue 2;
						}
						$value = pfb_filter($value, PFB_FILTER_HOSTNAME, 'Sync');
						if (empty($value)) {
							$input_errors[] = gettext('The Target IP Address is invalid.');
						}
						break;
					case 'varsyncprotocol':
						// Validate Protocol
						if (!in_array($value, array('http', 'https'))) {
							$input_errors[] = gettext('The Protocol is invalid.');
						}
						break;
					case 'varsyncport':
						// Validate Port
						if (!is_port($value)) {
							$input_errors[] = gettext('The Port is invalid.');
						}
						break;
					default:
						continue 2;
				}
				$pfb['sconfig']['row'][$k_field[1]][$k_field[0]] = $value;
				// foreign structure: pfblockerngsync/config/0/row is a dynamic XMLRPC row blob, not in registry
				config_set_path("installedpackages/pfblockerngsync/config/0/row/{$k_field[1]}/{$k_field[0]}", $pfb['sconfig']['row'][$k_field[1]][$k_field[0]]);

			}
		}

		// Per-target enable checkbox: an unchecked box sends no POST field, so the
		// in-loop switch cannot persist it. Resolve it for every touched row after
		// the loop -- 'on' when checked, '' otherwise -- so a new or re-enabled
		// target stores 'on' (the XMLRPC engine gates on $sh['varsyncdestinenable'])
		// and a new or cleared disabled target stores the canonical '' (not absent).
		foreach (array_keys($rowhelper_exist) as $r_idx) {
			$enabled = ((($_POST["varsyncdestinenable-{$r_idx}"] ?? '') == 'on') ? 'on' : '');
			$pfb['sconfig']['row'][$r_idx]['varsyncdestinenable'] = $enabled;
			// foreign structure: pfblockerngsync/config/0/row is a dynamic XMLRPC row blob, not in registry
			config_set_path("installedpackages/pfblockerngsync/config/0/row/{$r_idx}/varsyncdestinenable", $enabled);
		}

		// Remove all undefined rowhelpers
		foreach ($pfb['sconfig']['row'] as $r_key => $row) {
			if (!isset($rowhelper_exist[$r_key])) {
				unset($pfb['sconfig']['row'][$r_key]);
				// foreign structure: pfblockerngsync/config/0/row is a dynamic XMLRPC row blob, not in registry
				config_del_path("installedpackages/pfblockerngsync/config/0/row/{$r_key}");
			}
		}

		if (!$input_errors) {

			$pfb['sconfig']['varsynconchanges']	= $_POST['varsynconchanges']						?: '';
			$pfb['sconfig']['varsynctimeout']	= $_POST['varsynctimeout']						?: '';
			$pfb['sconfig']['syncinterfaces']	= pfb_filter($_POST['syncinterfaces'], PFB_FILTER_ON_OFF, 'Sync')	?: '';

			PfbConfig::writeSection('installedpackages/pfblockerngsync/config/0', $pfb['sconfig']);
			write_config('[pfBlockerNG] save XMLRPC sync settings');
			header('Location: /pfblockerng/pfblockerng_sync.php');
			exit;
		}
	}
}

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('Sync'));
$pglinks = array('', '/pfblockerng/pfblockerng_general.php', '@self');
$shortcut_section = 'pfblockerng';
include_once('head.inc');

if ($input_errors) {
	print_input_errors($input_errors);
}

// Define default Alerts Tab href link (Top row)
$get_req = pfb_alerts_default_page();

$tab_array	= array();
$tab_array[]	= array(gettext('General'),	FALSE,	'/pfblockerng/pfblockerng_general.php');
$tab_array[]	= array(gettext('IP'),		FALSE,	'/pfblockerng/pfblockerng_ip.php');
$tab_array[]	= array(gettext('DNSBL'),	FALSE,	'/pfblockerng/pfblockerng_dnsbl.php');
$tab_array[]	= array(gettext('Update'),	FALSE,	'/pfblockerng/pfblockerng_update.php');
$tab_array[]	= array(gettext('Reports'),	FALSE,	"/pfblockerng/pfblockerng_alerts.php{$get_req}");
$tab_array[]	= array(gettext('Feeds'),	FALSE,	'/pfblockerng/pfblockerng_feeds.php');
$tab_array[]	= array(gettext('Logs'),	FALSE,	'/pfblockerng/pfblockerng_log.php');
$tab_array[]	= array(gettext('Sync'),	TRUE,	'/pfblockerng/pfblockerng_sync.php');
pfb_software_add_tab($tab_array);
display_top_tabs($tab_array, TRUE);
pfb_print_pending_changes_box();

$form = new Form('Save XMLRPC sync settings');

$section = new Form_Section('XMLRPC Sync Settings');
$section->addInput(new Form_StaticText(
	'Links',
	'<small>'
	. '<a href="/firewall_aliases.php" target="_blank">Firewall Aliases</a>&emsp;'
	. '<a href="/firewall_rules.php" target="_blank">Firewall Rules</a>&emsp;'
	. '<a href="/status_logs_filter.php" target="_blank">Firewall Logs</a></small>'
));

$section->addInput(new Form_Select(
	'varsynconchanges',
	'Enable Sync',
	$pconfig['varsynconchanges'],
	$options_varsynconchanges
))->setHelp('Push this firewall\'s pfBlockerNG configuration to other firewalls. '
		. '<b>Sync to configured system backup server</b> includes pfBlockerNG in the firewall\'s '
		. 'normal config sync to the peer set under System &gt; High Availability Sync '
		. '(the Replication Targets below are ignored). <b>Sync to host(s) defined below</b> pushes '
		. 'to the Replication Targets configured here.<br /><br />'
		. '<b>Important:</b> While using "Sync to host(s) defined below", only sync from host A to B, A to C'
		. '<br /> but <b>do not</b> enable XMLRPC sync <b>to</b> A. This will result in a loop!');

$section->addInput(new Form_Input(
	'varsynctimeout',
	'XMLRPC Timeout',
	'number',
	$pconfig['varsynctimeout'],
	[ 'min' => 0, 'max' => 5000, 'step' => 50, 'placeholder' => 'Enter timeout in seconds' ]
));

$section->addInput(new Form_Checkbox(
	'syncinterfaces',
	'Disable General/IP/DNSBL tab settings sync',
	NULL,
	pfb_cfg_toggle_read($pconfig['syncinterfaces']) === PfbToggle::On,
	'on'
))->setHelp('When selected, the \'General\', \'IP\', and \'DNSBL\' tab customizations will not be sync\'d');
$form->add($section);

$section = new Form_Section('XMLRPC Replication Targets');
$section->addInput(new Form_StaticText(
	'Notes',
	'<small>'
	. 'For each target, match the protocol, IP/hostname and port of the remote firewall\'s '
	. 'webConfigurator &mdash; the protocol (http or https) must match the remote, or the sync will fail.<br />'
	. 'Using a dedicated user in the <i>admins</i> group on the target (rather than the primary admin '
	. 'account) is recommended, so the primary account is not exposed for syncing.'
	. '</small>'
));
$rowdata = $pfb['sconfig']['row'];

// Add empty row placeholder if no rows defined
if (empty($rowdata)) {
	$rowdata = array();
	$rowdata = array ( array(	'varsyncdestinenable'	=> '',
					'varsyncprotocol'	=> 'https',
					'varsyncipaddress'	=> '',
					'varsyncport'		=> '443',
					'varsyncusername'	=> 'admin',
					'varsyncpassword'	=> ''));
}

$numrows	= count($rowdata) -1;
$rowcounter	= 0;

foreach ($rowdata as $r_id => $row) {

	$target = 'Target #' . ($r_id + 1);

	$group = new Form_Group($target);
	$group->addClass('repeatable');
	$group->add(new Form_Checkbox(
		'varsyncdestinenable-' . $r_id,
		NULL,
		NULL,
		isset($row['varsyncdestinenable']) && pfb_cfg_toggle_read($row['varsyncdestinenable']) === PfbToggle::On,
		'on'
	))->setHelp(($numrows == $rowcounter) ? 'Enable' : NULL)
	  ->setWidth(1);

	$group->add(new Form_Select(
		'varsyncprotocol-' . $r_id,
		NULL,
		$row['varsyncprotocol'],
		[ 'http' => 'http', 'https' => 'https' ]
	))->setHelp(($numrows == $rowcounter) ? 'Protocol' : NULL)
	  ->setAttribute('size', 1)
	  ->setAttribute('style', 'width: auto')
	  ->setWidth(1);

	$group->add(new Form_Input(
		'varsyncipaddress-' . $r_id,
		NULL,
		'text',
		htmlspecialchars($row['varsyncipaddress']),
		[ 'placeholder' => 'Target IP/Hostname' ]
	))->setHelp(($numrows == $rowcounter) ? 'Target IP/Hostname' : NULL)
	  ->setWidth(2);

	$group->add(new Form_Input(
		'varsyncport-' . $r_id,
		NULL,
		'number',
		$row['varsyncport'],
		[ 'min' => 1, 'max' => 65535, 'placeholder' => 'Port' ]
	))->setHelp(($numrows == $rowcounter) ? 'Target Port' : NULL)
	  ->setWidth(1);

	$group->add(new Form_Input(
		'varsyncusername-' . $r_id,
		NULL,
		'text',
		htmlspecialchars($row['varsyncusername']),
		[ 'placeholder' => 'Target username' ]
	))->setHelp(($numrows == $rowcounter) ? 'Target Username (admin)' : NULL)
	  ->setWidth(2);

	$group->add(new Form_Input(
		'varsyncpassword-' . $r_id,
		NULL,
		'password',
		$row['varsyncpassword'],
		[ 'placeholder' => 'Target password' ]
	))->setHelp(($numrows == $rowcounter) ? 'Target Password' : NULL)
	  ->setWidth(2);

	$group->add(new Form_Button(
		'deleterow' . $rowcounter,
		'Delete',
		null,
		'fa-solid fa-trash-can'
	))->removeClass('btn-primary')->addClass('btn-warning btn-xs');

	$rowcounter++;
	$section->add($group);
}

$btnadd = new Form_Button(
	'addrow',
	'Add',
	NULL,
	'fa-solid fa-plus'
);
$btnadd->removeClass('btn-primary')
	->addClass('btn-success btn-xs')
	->setAttribute('title', 'Click to Enable all State fields');

$group = new Form_Group(NULL);
$group->add(new Form_StaticText(
	NULL,
	$btnadd
));
$section->add($group);

$form->add($section);
print ($form);
print_callout('<strong>Setting changes are applied via CRON or \'Force Update|Reload\' only!</strong>');

include('foot.inc');
?>

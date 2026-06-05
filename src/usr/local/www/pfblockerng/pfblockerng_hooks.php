<?php
/*
 * pfblockerng_hooks.php
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

// ADR-12: pre/post Update Hooks. Admin-configurable commands run as root at the
// start ('pre') and end ('post') of the pfBlockerNG update pass. The runner
// (pfb_run_hooks/pfb_get_hooks) reads these entries from:
//   installedpackages/pfblockerng/config/0/hooks/row   (a list)
// with the per-entry shape { command, when, enabled, description, timeout }.
// Entries are nested under the 'row' listtag (not directly under <hooks>): a list
// stored straight under the non-listtag <hooks> serializes to invalid numeric
// child tags (<hooks><0>...) that never round-trip; 'row' is a pfSense listtag, so
// <hooks><row>...</row>...</hooks> parses back as a list for 1..N rows. See
// pfb_get_hooks() for the full xmlparse.inc rationale.
$pfb['gconfig'] = config_get_path('installedpackages/pfblockerng/config/0', []);

// Select field options
$options_when = [ 'pre' => 'Pre', 'post' => 'Post' ];

// $input_errors is read unconditionally in the render section below, so it must be
// defined on every request path. Initialise it once.
$input_errors = array();

// Validate input fields and save
if ($_POST) {
	if (isset($_POST['save'])) {

		// Parse the repeatable 'rowhelper' hook fields (field-<rowid>) and save
		// new values into the hooks list, validating each as it is collected.
		$rowhelper_exist = array();
		foreach ($_POST as $key => $value) {

			if (strpos($key, '-') === FALSE) {
				continue;
			}

			$k_field = explode('-', $key);
			$field   = $k_field[0];
			$rowid   = $k_field[1];

			// Only handle this page's hook fields.
			if (!in_array($field, array('hook_enabled', 'hook_when', 'hook_command', 'hook_timeout', 'hook_description'), true)) {
				continue;
			}

			// A crafted POST (e.g. hook_command-0[]=x) makes $value an array; the
			// scalar validators below (array_key_exists/preg_match) would throw a
			// PHP 8 TypeError and break the save. Reject non-scalars up front.
			if (!is_scalar($value)) {
				$input_errors[] = gettext('Invalid hook field value.');
				continue;
			}

			// Collect all rowhelper keys (so empty checkboxes still register a row).
			$rowhelper_exist[$rowid] = '';

			switch ($field) {
				case 'hook_enabled':
					if ($value !== 'on' && $value !== '') {
						$input_errors[] = gettext('Invalid hook enabled value.');
					}
					break;
				case 'hook_when':
					if (!array_key_exists($value, $options_when)) {
						$input_errors[] = gettext('The hook \'When\' value must be Pre or Post.');
					}
					break;
				case 'hook_command':
					// The command line is passed verbatim to /bin/sh -c by the
					// runner (escapeshellarg'd there), so shell metacharacters are
					// intentionally allowed; only reject control characters and an
					// empty command (an empty command is silently skipped at run
					// time, so treat it as a user error here).
					if (preg_match('/[\p{C}]+/u', $value)) {
						$input_errors[] = gettext('The hook command contains invalid control characters.');
					}
					if (trim($value) === '') {
						$input_errors[] = gettext('The hook command cannot be empty.');
					}
					break;
				case 'hook_timeout':
					// Optional; blank => default. Otherwise digits only.
					if ($value !== '' && pfb_filter($value, PFB_FILTER_NUM, 'Hooks', '') === '') {
						$input_errors[] = gettext('The hook timeout must be a positive number of seconds.');
					}
					break;
				case 'hook_description':
					if (preg_match('/[\p{C}]+/u', $value)) {
						$input_errors[] = gettext('The hook description contains invalid control characters.');
					}
					break;
				default:
					continue 2;
			}
		}

		if (!$input_errors) {

			// Rebuild the hooks list from POST, preserving row order. Map each
			// rowhelper field to the Phase-1 config key the runner consumes.
			$hooks = array();
			foreach (array_keys($rowhelper_exist) as $rowid) {
				$hook = array(
					'command'	=> trim((string) ($_POST["hook_command-{$rowid}"] ?? '')),
					'when'		=> (string) ($_POST["hook_when-{$rowid}"] ?? 'pre'),
					'enabled'	=> (isset($_POST["hook_enabled-{$rowid}"]) && $_POST["hook_enabled-{$rowid}"] === 'on') ? 'on' : '',
					'description'	=> trim((string) ($_POST["hook_description-{$rowid}"] ?? '')),
					'timeout'	=> trim((string) ($_POST["hook_timeout-{$rowid}"] ?? '')),
				);
				$hooks[] = $hook;
			}

			if (empty($hooks)) {
				config_del_path('installedpackages/pfblockerng/config/0/hooks');
			} else {
				// Store under the 'row' listtag so the list round-trips through
				// config.xml for any count (a bare list under the non-listtag
				// <hooks> serializes to invalid <0> tags). See pfb_get_hooks().
				config_set_path('installedpackages/pfblockerng/config/0/hooks/row', $hooks);
			}

			write_config('[pfBlockerNG] save Update Hooks settings');
			header('Location: /pfblockerng/pfblockerng_hooks.php');
			exit;
		}
	}
}

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('Update Hooks'));
$pglinks = array('', '/pfblockerng/pfblockerng_general.php', '@self');
include_once('head.inc');

if ($input_errors) {
	print_input_errors($input_errors);
}

// Define default Alerts Tab href link (Top row)
$get_req = pfb_alerts_default_page();

$tab_array	= array();
$tab_array[]	= array(gettext('General'),	false,	'/pfblockerng/pfblockerng_general.php');
$tab_array[]	= array(gettext('IP'),		false,	'/pfblockerng/pfblockerng_ip.php');
$tab_array[]	= array(gettext('DNSBL'),	false,	'/pfblockerng/pfblockerng_dnsbl.php');
$tab_array[]	= array(gettext('Update'),	false,	'/pfblockerng/pfblockerng_update.php');
$tab_array[]	= array(gettext('Update Hooks'),true,	'/pfblockerng/pfblockerng_hooks.php');
$tab_array[]	= array(gettext('Reports'),	false,	"/pfblockerng/pfblockerng_alerts.php{$get_req}");
$tab_array[]	= array(gettext('Feeds'),	false,	'/pfblockerng/pfblockerng_feeds.php');
$tab_array[]	= array(gettext('Logs'),	false,	'/pfblockerng/pfblockerng_log.php');
$tab_array[]	= array(gettext('Sync'),	false,	'/pfblockerng/pfblockerng_sync.php');
display_top_tabs($tab_array, true);

$form = new Form('Save');

$section = new Form_Section('Update Hooks (Pre/Post Update Commands)');
$section->addInput(new Form_StaticText(
	'About',
	'<small>'
	. gettext('Update Hooks are admin-defined commands that pfBlockerNG runs <strong>once per update pass</strong> '
		. '&mdash; a <strong>Pre</strong> hook at the start of the update (before any feed is processed) and a '
		. '<strong>Post</strong> hook at the end (after all IP/DNSBL reloads). They are <strong>not</strong> the '
		. 'per-feed <em>ip_pre_*.sh</em> list pre-scripts (which transform a single downloaded feed); these run once '
		. 'for the whole pass and are intended for downstream nudges such as reloading another service.')
	. '</small>'
));

$section->addInput(new Form_StaticText(
	'Run as root',
	'<span class="text-danger">' . gettext('Warning: ') . '</span>'
	. '<small>'
	. gettext('Each command runs <strong>as root</strong> via <code>/bin/sh -c</code> &mdash; the same trust class as '
		. 'pfSense Shellcmd / cron. Only an administrator can edit this page. A command runs under '
		. '<code>/usr/bin/timeout</code>; if it exceeds its timeout it is killed (SIGTERM, then SIGKILL after a short '
		. 'grace period). A hook\'s non-zero exit <strong>or</strong> timeout is logged to the pfBlockerNG log and the '
		. 'update <strong>continues</strong> &mdash; a hook can never abort or stall an update. Hooks run in the order '
		. 'listed: all Pre hooks before processing, all Post hooks after everything.')
	. '</small>'
));

$section->addInput(new Form_StaticText(
	'Environment',
	'<small>'
	. gettext('Each hook receives these environment variables:') . '<br />'
	. '<code>PFB_WHEN</code> &mdash; ' . gettext('the fire point: <code>pre</code> or <code>post</code>.') . '<br />'
	. '<code>PFB_TRIGGER</code> &mdash; ' . gettext('what started the update: <code>cron</code> (scheduled update, '
		. 'and the GUI <em>Force Update</em> / <em>Force Reload (All)</em>), <code>update</code> (a settings save), '
		. 'or <code>force-reload</code> (a GUI <em>Force Reload</em> of IP-only or DNSBL-only). '
		. 'Set for both <code>pre</code> and <code>post</code>.') . '<br />'
	. gettext('The following are set on <code>post</code> hooks only (a <code>pre</code> hook runs before anything is '
		. 'downloaded, so nothing has changed yet):') . '<br />'
	. '<code>PFB_IP_CHANGED</code> &mdash; ' . gettext('<code>1</code> if the IP/firewall side changed (a filter '
		. 'reload was applied) this pass, else <code>0</code>.') . '<br />'
	. '<code>PFB_DNSBL_CHANGED</code> &mdash; ' . gettext('<code>1</code> if the DNSBL side changed this pass, else '
		. '<code>0</code>.') . '<br />'
	. '<code>PFB_STATUS</code> &mdash; ' . gettext('overall pass status. Currently always <code>ok</code> (reserved '
		. 'for future use).') . '<br />'
	. '<code>PFB_CHANGED_ALIASES</code> &mdash; ' . gettext('space-separated list of changed aliases. Currently '
		. 'always empty (reserved for future use).')
	. '</small>'
));

$section->addInput(new Form_StaticText(
	'HA / sync',
	'<small>'
	. gettext('Hooks are stored in the pfBlockerNG configuration, so they replicate to a CARP/HA secondary and run on '
		. 'whichever node performs the update.')
	. '</small>'
));
$form->add($section);

$section = new Form_Section('Hook Entries');

// Entries live under the 'row' listtag (config/0/hooks/row); fall back to a bare
// list under 'hooks' for tolerance. See the save block / pfb_get_hooks().
$rowdata = $pfb['gconfig']['hooks']['row'] ?? ($pfb['gconfig']['hooks'] ?? array());

// Add an empty row placeholder if no hooks are defined.
if (!is_array($rowdata) || empty($rowdata)) {
	$rowdata = array( array(	'command'	=> '',
					'when'		=> 'post',
					'enabled'	=> '',
					'description'	=> '',
					'timeout'	=> '') );
}

$numrows	= count($rowdata) - 1;
$rowcounter	= 0;

foreach ($rowdata as $r_id => $row) {

	$group = new Form_Group('Hook #' . ($rowcounter + 1));
	$group->addClass('repeatable');

	$group->add(new Form_Checkbox(
		'hook_enabled-' . $r_id,
		NULL,
		NULL,
		(isset($row['enabled']) && $row['enabled'] === 'on') ? true : false,
		'on'
	))->setHelp(($numrows == $rowcounter) ? 'Enabled' : NULL)
	  ->setWidth(1);

	$group->add(new Form_Select(
		'hook_when-' . $r_id,
		NULL,
		($row['when'] ?? 'post'),
		$options_when
	))->setHelp(($numrows == $rowcounter) ? 'When' : NULL)
	  ->setAttribute('size', 1)
	  ->setAttribute('style', 'width: auto')
	  ->setWidth(1);

	$group->add(new Form_Input(
		'hook_command-' . $r_id,
		NULL,
		'text',
		htmlspecialchars($row['command'] ?? ''),
		[ 'placeholder' => 'Command (run as root via /bin/sh -c)' ]
	))->setHelp(($numrows == $rowcounter) ? 'Command' : NULL)
	  ->setWidth(4);

	$group->add(new Form_Input(
		'hook_timeout-' . $r_id,
		NULL,
		'number',
		htmlspecialchars($row['timeout'] ?? ''),
		[ 'min' => 1, 'placeholder' => '60' ]
	))->setHelp(($numrows == $rowcounter) ? 'Timeout (s)' : NULL)
	  ->setWidth(1);

	$group->add(new Form_Input(
		'hook_description-' . $r_id,
		NULL,
		'text',
		htmlspecialchars($row['description'] ?? ''),
		[ 'placeholder' => 'Description (log label)' ]
	))->setHelp(($numrows == $rowcounter) ? 'Description' : NULL)
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
	->setAttribute('title', 'Click to add a hook');

$group = new Form_Group(NULL);
$group->add(new Form_StaticText(
	NULL,
	$btnadd
));
$section->add($group);

$form->add($section);
print($form);
print_callout('<strong>' . gettext('Hooks run on the next CRON update or \'Force Update|Reload\'.') . '</strong>');

include('foot.inc');
?>

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

// ADR-12: pre/post Update Hooks. At the start ('pre') and end ('post') of the
// pfBlockerNG update pass the runner executes admin-VETTED script files as root.
// The script is NOT typed here: a shell-access admin authors it in the hook-script
// dir (named hook_pre_*/hook_post_*); this page only PICKS one. The runner
// (pfb_run_hooks/pfb_get_hooks) reads these entries from:
//   installedpackages/pfblockerng/config/0/hooks/row   (a list)
// with the per-entry shape { script, when, enabled, description, timeout }.
// Entries are nested under the 'row' listtag (not directly under <hooks>): a list
// stored straight under the non-listtag <hooks> serializes to invalid numeric
// child tags (<hooks><0>...) that never round-trip; 'row' is a pfSense listtag, so
// <hooks><row>...</row>...</hooks> parses back as a list for 1..N rows. See
// pfb_get_hooks() for the full xmlparse.inc rationale.
$pfb['gconfig'] = config_get_path('installedpackages/pfblockerng/config/0', []);

// Select field options
$options_when = [ 'pre' => 'Pre', 'post' => 'Post' ];

// Hook scripts are admin-authored files in the hook-script dir, named
// hook_pre_*/hook_post_* (.sh/.py). The picker offers ONLY these (ADR-12 security
// model: a hook runs a vetted on-box script, never a GUI-entered command), and the
// save handler / runner accept ONLY these. Build the per-'when' option maps (with a
// leading 'None'); the runner re-validates against the same list at run time.
$options_script = [
	'pre'  => array_merge([ '' => gettext('None') ], pfb_hook_scripts('pre')),
	'post' => array_merge([ '' => gettext('None') ], pfb_hook_scripts('post')),
];

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
			if (!in_array($field, array('hook_enabled', 'hook_when', 'hook_script', 'hook_timeout', 'hook_description'), TRUE)) {
				continue;
			}

			// A crafted POST (e.g. hook_script-0[]=x) makes $value an array; the
			// scalar validators below (array_key_exists/preg_match) would throw a
			// PHP 8 TypeError and break the save. Reject non-scalars up front.
			if (!is_scalar($value)) {
				$input_errors[] = gettext('Invalid hook field value.');
				continue;
			}

			// issue #1761: sanitize at ingestion -- before any validation below.
			if ($field === 'hook_description' || $field === 'hook_timeout') {
				$value = pfb_sanitize_text((string) $value);
				$_POST[$key] = $value;
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
				case 'hook_script':
					// The ADR-12 security gate: the selected script must be one the
					// box will actually run for THIS row's Pre/Post -- a
					// hook_<when>_*.{sh,py} present in the hook-script dir. A stale
					// pick, a crafted POST (path/traversal), or a Pre/Post mismatch
					// is rejected, so the config never stores -- and the runner never
					// execs -- an unvetted value. The row's 'when' decides which
					// scripts are valid, so reject the script when 'when' is missing
					// or out of range too -- otherwise a crafted POST that OMITS
					// hook_when-N (its own validator case never fires) would slip an
					// unvetted script past this gate.
					$row_when = (string) ($_POST["hook_when-{$rowid}"] ?? '');
					if (!array_key_exists($row_when, $options_when)) {
						$input_errors[] = gettext('The hook row is missing a valid Pre/Post selection.');
					} elseif (!pfb_hook_script_valid($value, $row_when)) {
						$input_errors[] = gettext('Select a valid hook script for this row\'s Pre/Post. ' .
							'Author it in the scripts folder first (see the help above).');
					}
					break;
				case 'hook_timeout':
					// Optional; blank => default. Otherwise digits only.
					if ($value !== '' && pfb_filter($value, PFB_FILTER_NUM, 'Hooks', '') === '') {
						$input_errors[] = gettext('The hook timeout must be a positive number of seconds.');
					}
					break;
				case 'hook_description':
					// !== 0 fails closed on invalid UTF-8: with /u, preg_match() returns
					// FALSE (not 0) rather than a real no-match, and a bare truthiness
					// check would silently let a malformed value through.
					if (preg_match('/[\p{C}]+/u', $value) !== 0) {
						$input_errors[] = gettext('The hook description contains invalid control characters.');
					}
					break;
				default:
					continue 2;
			}
		}

		if (!$input_errors) {

			// Rebuild the hooks list from POST, preserving row order. Map each
			// rowhelper field to the config key the runner consumes.
			$hooks = array();
			foreach (array_keys($rowhelper_exist) as $rowid) {
				$hook = array(
					'script'	=> (string) ($_POST["hook_script-{$rowid}"] ?? ''),
					'when'		=> (string) ($_POST["hook_when-{$rowid}"] ?? 'pre'),
					'enabled'	=> (isset($_POST["hook_enabled-{$rowid}"]) && $_POST["hook_enabled-{$rowid}"] === 'on') ? 'on' : '',
					'description'	=> (string) ($_POST["hook_description-{$rowid}"] ?? ''),
					'timeout'	=> (string) ($_POST["hook_timeout-{$rowid}"] ?? ''),
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
			pfb_mark_pending_changes();	// hooks run during the Update, not on save
			header('Location: /pfblockerng/pfblockerng_hooks.php');
			exit;
		}
	}
}

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('Update'), gettext('Hooks'));
$pglinks = array('', '/pfblockerng/pfblockerng_general.php', '/pfblockerng/pfblockerng_update.php', '@self');
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
$tab_array[]	= array(gettext('DNS'),		FALSE,	'/pfblockerng/pfblockerng_dns_general.php');
$tab_array[]	= array(gettext('Update'),	TRUE,	'/pfblockerng/pfblockerng_update.php');
$tab_array[]	= array(gettext('Reports'),	FALSE,	"/pfblockerng/pfblockerng_alerts.php{$get_req}");
$tab_array[]	= array(gettext('Feeds'),	FALSE,	'/pfblockerng/pfblockerng_feeds.php');
$tab_array[]	= array(gettext('Logs'),	FALSE,	'/pfblockerng/pfblockerng_log.php');
$tab_array[]	= array(gettext('Sync'),	FALSE,	'/pfblockerng/pfblockerng_sync.php');
pfb_software_add_tab($tab_array);
display_top_tabs($tab_array, TRUE);

// Update sub-tabs: Run (update page), Hooks (this page), and Edit Hooks (issue #1669
// Part B: the gated hook-script authoring editor, directly after Hooks).
// Second display_top_tabs row, matching the Feeds page IPv4/IPv6/DNSBL sub-tab idiom.
$tab_array_sub = pfb_edit_hooks_tabs('hooks');
display_top_tabs($tab_array_sub, TRUE);
pfb_print_pending_changes_box();

$form = new Form('Save');

$section = new Form_Section('Update Hooks (Pre/Post Update Scripts)');
$section->addInput(new Form_StaticText(
	'About',
	'<small>'
	. gettext('Update Hooks run a script once per update: a <strong>Pre</strong> hook at the start, before any feed '
		. 'is processed, and a <strong>Post</strong> hook at the end, after all IP and DNSBL reloads. They are not the '
		. 'per-feed <code>ip_pre_*.sh</code> list scripts, which transform one downloaded feed. Intended for follow-up '
		. 'actions such as reloading another service.')
	. '</small>'
));

$section->addInput(new Form_StaticText(
	'Script source',
	'<small>'
	. sprintf(gettext('A hook runs a script file from <code>%1$s</code>, never a command typed here. Name it '
		. '<code>hook_pre_NAME.sh</code> or <code>hook_post_NAME.sh</code> for a shell script, or '
		. '<code>hook_pre_NAME.py</code> or <code>hook_post_NAME.py</code> for Python. Create it on the '
		. '<strong>Edit Hooks</strong> tab (full administrators only) or from a shell. The <strong>Script</strong> '
		. 'list shows only files that match the selected <strong>When</strong>. Python hooks use the package Python '
		. 'interpreter and need no shebang or execute bit; shell hooks need both.'), PFB_HOOK_SCRIPT_DIR)
	. '</small>'
));

$section->addInput(new Form_StaticText(
	'Run as root',
	'<span class="text-danger"><strong>' . gettext('Warning:') . '</strong></span> '
	. '<small>'
	. gettext('The selected script runs <strong>as root</strong>. Anyone who can use <strong>Edit Hooks</strong> or a '
		. 'root shell can create such a script. Each hook runs under <code>/usr/bin/timeout</code> and is stopped at its '
		. 'timeout (SIGTERM, then SIGKILL after a short grace period). A non-zero exit or a timeout is logged to the '
		. 'pfBlockerNG log and the update continues: a hook cannot abort or stall an update. Hooks run in the listed '
		. 'order: all Pre hooks before processing, all Post hooks after everything else.')
	. '</small>'
));

$section->addInput(new Form_StaticText(
	'Environment',
	'<small>'
	. '<p><strong>' . gettext('All hooks') . '</strong></p>'
	. '<dl>'
	. '<dt><code>PFB_WHEN</code></dt><dd>' . gettext('<code>pre</code> or <code>post</code>.') . '</dd>'
	. '<dt><code>PFB_TRIGGER</code></dt><dd><ul>'
	. '<li>' . gettext('<code>cron</code>: scheduled update, or <strong>Run Now</strong> with <strong>Force</strong> set '
		. 'to <strong>Download</strong> or <strong>Both</strong>.') . '</li>'
	. '<li>' . gettext('<code>update</code>: automatic apply of saved settings, or <strong>Run Now</strong> with '
		. '<strong>Force</strong> set to <strong>None</strong>.') . '</li>'
	. '<li>' . gettext('<code>force-reload</code>: <strong>Run Now</strong> with <strong>Force</strong> set to '
		. '<strong>Parse</strong>.') . '</li>'
	. '</ul></dd>'
	. '<dt><code>PFB_POST_INSTALL</code></dt><dd>' . gettext('<code>1</code> for reconfiguration after installation or '
		. 'upgrade; otherwise <code>0</code>.') . '</dd>'
	. '<dt><code>PFB_PRE_UNINSTALL</code></dt><dd>' . gettext('<code>1</code> during package removal, including a major '
		. 'pfSense upgrade; otherwise <code>0</code>. Normal package updates do not remove the package.') . '</dd>'
	. '<dt><code>PFB_PKG_OP</code></dt><dd>' . gettext('<code>install</code>, <code>upgrade</code>, <code>reinstall</code> '
		. 'or <code>delete</code>; empty outside package operations.') . '</dd>'
	. '</dl>'
	. '<p><strong>' . gettext('Post hooks only') . '</strong></p>'
	. '<dl>'
	. '<dt><code>PFB_IP_CHANGED</code></dt><dd>' . gettext('<code>1</code> when a filter reload was applied or '
		. 'temporarily unlocked IPs were locked again; otherwise <code>0</code>.') . '</dd>'
	. '<dt><code>PFB_DNSBL_CHANGED</code></dt><dd>' . gettext('<code>1</code> when the DNSBL side changed; otherwise '
		. '<code>0</code>.') . '</dd>'
	. '<dt><code>PFB_STATUS</code></dt><dd>' . gettext('Pass status; currently always <code>ok</code>.') . '</dd>'
	. '<dt><code>PFB_CHANGED_IP_ALIASES</code></dt><dd>' . gettext('Space-separated updated IP aliases; empty when none '
		. 'changed.') . '</dd>'
	. '<dt><code>PFB_CHANGED_DNSBL_GROUPS</code></dt><dd>' . gettext('Space-separated updated DNSBL groups; empty when '
		. 'none changed.') . '</dd>'
	. '</dl>'
	. '</small>'
));

$section->addInput(new Form_StaticText(
	'HA / sync',
	'<small>'
	. gettext('Hook entries are copied to other firewalls only when <strong>Sync Scope</strong> on <strong>Sync</strong> '
		. 'is <strong>All settings (legacy)</strong>. Sync never copies hook script files: install them on each node. '
		. 'Hooks run on whichever node performs the update.')
	. '</small>'
));
$form->add($section);

$section = new Form_Section('Hook Entries');

// Entries live under the 'row' listtag (config/0/hooks/row); fall back to a bare
// list under 'hooks' for tolerance. See the save block / pfb_get_hooks().
$rowdata = $pfb['gconfig']['hooks']['row'] ?? ($pfb['gconfig']['hooks'] ?? array());

// Add an empty row placeholder if no hooks are defined.
if (!is_array($rowdata) || empty($rowdata)) {
	$rowdata = array( array(	'script'	=> '',
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
		isset($row['enabled']) && pfb_cfg_toggle_read($row['enabled']) === PfbToggle::On,
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

	// Script picker, filtered to the row's Pre/Post (the file prefix). The options
	// rendered server-side already match $row['when']; client JS re-filters them
	// when the When select changes (and the save handler re-validates regardless).
	$row_when = (($row['when'] ?? 'post') === 'pre') ? 'pre' : 'post';
	$group->add(new Form_Select(
		'hook_script-' . $r_id,
		NULL,
		($row['script'] ?? ''),
		$options_script[$row_when]
	))->setHelp(($numrows == $rowcounter) ? 'Script' : NULL)
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
print_callout(gettext('Hooks run during every update, including <strong>Run Now</strong> and the automatic apply of saved '
	. 'changes. Saving this page does not run them immediately.'));

// Client-side convenience: keep each row's Script picker in sync with its Pre/Post
// selection (the file prefix decides which scripts apply). Pure progressive
// enhancement -- the server renders the correct options per row and the save handler
// re-validates the choice, so this is not a trust boundary. The option lists come
// from the same pfb_hook_scripts() the picker and validator use.
$pfb_hook_scripts_json = json_encode($options_script, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
?>
<script type="text/javascript">
//<![CDATA[
(function () {
	var HOOK_SCRIPTS = <?=$pfb_hook_scripts_json?>;

	function rowidOf(id) {
		var i = id.lastIndexOf('-');
		return (i < 0) ? '' : id.slice(i + 1);
	}

	// Repopulate a Script <select> with the options for $when, preserving the current
	// selection when it is still valid (else falling back to the leading 'None').
	function repopulate(sel, when) {
		var opts = HOOK_SCRIPTS[when] || {};
		var keep = sel.value;
		var matched = false;
		while (sel.options.length) {
			sel.remove(0);
		}
		Object.keys(opts).forEach(function (val) {
			var o = document.createElement('option');
			o.value = val;
			o.text = opts[val];
			if (val === keep) {
				o.selected = true;
				matched = true;
			}
			sel.appendChild(o);
		});
		if (!matched) {
			sel.value = '';
		}
	}

	function syncRow(rowid) {
		var when = document.getElementById('hook_when-' + rowid);
		var script = document.getElementById('hook_script-' + rowid);
		if (when && script) {
			repopulate(script, when.value);
		}
	}

	function syncAll() {
		var whens = document.querySelectorAll('select[id^="hook_when-"]');
		for (var i = 0; i < whens.length; i++) {
			syncRow(rowidOf(whens[i].id));
		}
	}

	// A When change re-filters that row's Script picker (event delegation also covers
	// rows the rowhelper clones in later).
	document.addEventListener('change', function (e) {
		var t = e.target;
		if (t && t.id && t.id.indexOf('hook_when-') === 0) {
			syncRow(rowidOf(t.id));
		}
	});

	document.addEventListener('DOMContentLoaded', function () {
		syncAll();
		// After the rowhelper clones a new row (it copies row 0's options/value),
		// re-sync so the new row reflects its own When and resets a stale selection.
		var add = document.getElementById('addrow');
		if (add) {
			add.addEventListener('click', function () { setTimeout(syncAll, 0); });
		}
	});
})();
//]]>
</script>
<?php
include('foot.inc');
?>

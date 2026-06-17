<?php
/*
 * pfblockerng_software.php
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
 */

// ADR-19: the "Software" page — show the installed pfBlockerNG channel/version vs our-repo
// latest (from the cron-maintained cache), toggle the "Check for new versions" setting, and
// run same-channel Check / Update actions. Disable NGINX output buffering so the Update live
// terminal streams (mirrors _update.php).
header("X-Accel-Buffering: no");

require_once('guiconfig.inc');
require_once('globals.inc');
require_once('pfsense-utils.inc');
require_once('util.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');

global $pfb;
pfb_global();

// PROVENANCE GUARD — FIRST executable thing. The Software page exists ONLY on a
// build installed from one of OUR repos (ADR-19 2026-06-15 amendment). A
// Netgate-ports / sideloaded install (repo 'pfSense'/unknown/'') must never see
// this page; redirect it away before any rendering or action handler runs.
if (!pfb_software_provenance_ok()) {
	header('Location: /index.php');
	exit;
}

// Resolve the installed package + channel ONCE (used by display + the actions).
$pfb_sw_pkgname	= pfb_pkg_installed_name();
$pfb_sw_channel	= pfb_channel_from_pkgname($pfb_sw_pkgname);

// The "Check for new versions" setting (default ENABLED). Persisted as 'on'/'off'; an unset
// value (never saved) reads as enabled via pfb_software_check_enabled().
$pfb_sw_check_raw = config_get_path('installedpackages/pfblockerng/config/0/pfb_software_check', null);
$pfb_sw_check	= pfb_software_check_enabled(is_string($pfb_sw_check_raw) ? $pfb_sw_check_raw : null);


// Stream one line to the live terminal window (reuses the _update.php mechanic).
function pfb_software_output($text) {
	$text = htmlspecialchars(str_replace("\n", "\\n", $text), ENT_COMPAT);
	print("\n<script type=\"text/javascript\">");
	print("\n//<![CDATA[");
	print("\nthis.document.forms[0].pfb_output.value += \"" . $text . "\\n\";");
	print("\nthis.document.forms[0].pfb_output.scrollTop = this.document.forms[0].pfb_output.scrollHeight;");
	print("\n//]]>");
	print("\n</script>");
	ob_flush();
	flush();
}


// Post a one-line status to the terminal status window.
function pfb_software_status($status) {
	$status = htmlspecialchars(str_replace("\n", "\\n", $status), ENT_COMPAT);
	print("\n<script type=\"text/javascript\">");
	print("\n//<![CDATA[");
	print("\nthis.document.forms[0].pfb_status.value=\"" . $status . "\";");
	print("\n//]]>");
	print("\n</script>");
	ob_flush();
	flush();
}


// Run a fixed command and stream its output to the terminal, line by line. The
// command is a FIXED string (no request input is interpolated), so there is no
// shell-injection surface — the only variable parts are pkg-derived names already
// escapeshellarg'd by the caller.
function pfb_software_run_stream($cmd) {
	$fh = popen("{$cmd} 2>&1", 'r');
	if (!is_resource($fh)) {
		pfb_software_output(gettext('Failed to start the task.'));
		return;
	}
	while (($line = fgets($fh)) !== false) {
		pfb_software_output(rtrim($line, "\r\n"));
	}
	pclose($fh);
}


$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('Software'));
$pglinks = array('', '/pfblockerng/pfblockerng_general.php', '@self');

// Determine which (POST-guarded) action was requested. The destructive Update and the
// cache-refreshing Check run on POST only — never on a GET (so the ui_render gate's GET
// cannot trigger pkg).
$pfb_sw_action = '';
if ($_POST && !empty($_POST['pfb_sw_action'])) {
	$pfb_sw_action = (string) $_POST['pfb_sw_action'];
}

// "Save" the settings (standard pfSense CSRF POST). A checkbox is absent from the POST when
// unticked, so persist an explicit 'on'/'off' — an unset value defaults to enabled, an
// explicit 'off' is the user opting out.
if ($_POST && isset($_POST['save'])) {
	config_set_path('installedpackages/pfblockerng/config/0/pfb_software_check', isset($_POST['pfb_software_check']) ? 'on' : 'off');
	write_config('[pfBlockerNG] save Software settings');
	header('Location: /pfblockerng/pfblockerng_software.php');
	exit;
}

// "Check now" — a manual, explicit cache refresh from our repo, then redisplay. $force=true
// bypasses the "Check for new versions" enable-gate so a one-off check always works.
if ($pfb_sw_action === 'check') {
	pfb_software_update_check(true);
	header('Location: /pfblockerng/pfblockerng_software.php');
	exit;
}

include_once('head.inc');

// Tab bar (the Software tab is the active one here; gated like every page).
$get_req = pfb_alerts_default_page();

$tab_array	= array();
$tab_array[]	= array(gettext('General'),	false,	'/pfblockerng/pfblockerng_general.php');
$tab_array[]	= array(gettext('IP'),		false,	'/pfblockerng/pfblockerng_ip.php');
$tab_array[]	= array(gettext('DNSBL'),	false,	'/pfblockerng/pfblockerng_dnsbl.php');
$tab_array[]	= array(gettext('Update'),	false,	'/pfblockerng/pfblockerng_update.php');
$tab_array[]	= array(gettext('Reports'),	false,	"/pfblockerng/pfblockerng_alerts.php{$get_req}");
$tab_array[]	= array(gettext('Feeds'),	false,	'/pfblockerng/pfblockerng_feeds.php');
$tab_array[]	= array(gettext('Logs'),	false,	'/pfblockerng/pfblockerng_log.php');
$tab_array[]	= array(gettext('Sync'),	false,	'/pfblockerng/pfblockerng_sync.php');
pfb_software_add_tab($tab_array, true);
display_top_tabs($tab_array, true);

// Channel + installed version are read LIVE (local `pkg query`, no network) so they are
// always known on an installed box. Only the our-repo "latest" + status + last-checked come
// from the cron-maintained cache (empty/unknown renders a clean "Not checked yet" — never a
// warning — so the page passes ui_render on the first GET, before any check has run).
$cache		= pfb_software_read_cache();
$installed_ver	= pfb_pkg_installed_version($pfb_sw_pkgname);
$disp_channel	= $pfb_sw_channel ?: gettext('unknown');
$disp_installed	= ($installed_ver !== '') ? $installed_ver : gettext('unknown');
$disp_latest	= !empty($cache['latest']) ? (string) $cache['latest'] : gettext('Not checked yet');
$disp_checked	= !empty($cache['last_checked'])
			? date('Y-m-d H:i:s', (int) $cache['last_checked'])
			: gettext('never');

$update_available = pfb_update_available($installed_ver, (string) ($cache['latest'] ?? ''));
if ($update_available) {
	$disp_status = '<span class="text-warning">' . gettext('Update available') . '</span>';
} elseif (!empty($cache['latest'])) {
	$disp_status = '<span class="text-success">' . gettext('Up to date') . '</span>';
} else {
	$disp_status = gettext('Not checked yet');
}

// pfb-software-panel — the page-specific render marker (ADR-14 ui_render oracle).
$form = new Form('Save');

$section = new Form_Section('Software Status');
$section->addInput(new Form_StaticText(
	'Channel',
	'<span id="pfb-software-panel">' . htmlspecialchars((string) $disp_channel) . '</span>'
));
$section->addInput(new Form_StaticText(
	'Installed version',
	htmlspecialchars((string) $disp_installed)
));
$section->addInput(new Form_StaticText(
	'Latest version',
	htmlspecialchars((string) $disp_latest)
));
$section->addInput(new Form_StaticText(
	'Status',
	$disp_status
));
$section->addInput(new Form_StaticText(
	'Last checked',
	htmlspecialchars((string) $disp_checked)
));
$form->add($section);

$section = new Form_Section('Updates');
$section->addInput(new Form_Checkbox(
	'pfb_software_check',
	'New version check',
	'Enabled',
	$pfb_sw_check
))->setHelp('Periodically check for a new version and notify when one is available.');
$form->add($section);

$section = new Form_Section('Actions');

$btn_check = new Form_Button(
	'pfb_sw_check',
	'Check now',
	null,
	'fa-solid fa-arrows-rotate'
);
$btn_check->removeClass('btn-primary')->addClass('btn-primary btn-xs')->setWidth(2);
// A button is a Form_Element, not a Form_Input — wrap each in a Form_StaticText (the
// established pattern) so it gets its own labelled row + per-line help.
$section->addInput(new Form_StaticText(null, $btn_check))
	->setHelp('Check for a new version now.');

$btn_update = new Form_Button(
	'pfb_sw_update',
	'Update now',
	null,
	'fa-solid fa-download'
);
$btn_update->removeClass('btn-primary')->addClass('btn-warning btn-xs')->setWidth(2);
// Enabled ONLY when an update is available (there is something to install).
if (!$update_available) {
	$btn_update->setAttribute('disabled', 'disabled');
}
$section->addInput(new Form_StaticText(null, $btn_update))
	->setHelp('Install the latest version. Available only when an update is found.');
$form->add($section);

// Live terminal window (shown when an Update is streaming).
$section = new Form_Section('Output');
$section->addInput(new Form_Textarea(
	'pfb_status',
	null,
	'Standby'
))->removeClass('form-control')->addClass('row-fluid col-sm-12')->setAttribute('rows', '1')->setAttribute('wrap', 'off')
  ->setAttribute('style', 'background:#fafafa; width: 100%');
$section->addInput(new Form_Textarea(
	'pfb_output',
	null,
	null
))->removeClass('form-control')->addClass('row-fluid col-sm-12')->setAttribute('rows', '20')->setAttribute('wrap', 'off')
  ->setAttribute('style', 'background:#fafafa; width: 100%');
$form->add($section);

print($form);

// The destructive Update streams into the terminal AFTER the form has rendered (so the
// textareas exist for the JS to write into). POST-guarded only.
if ($pfb_sw_action === 'update') {
	if ($pfb_sw_pkgname === '') {
		pfb_software_status(gettext('No pfBlockerNG package detected — cannot update.'));
	} else {
		pfb_software_status(gettext('Updating pfBlockerNG...'));
		$bin = escapeshellarg(PFB_PKG_BIN);
		$pkg = escapeshellarg($pfb_sw_pkgname);
		pfb_software_run_stream("{$bin} upgrade -y {$pkg}");
		pfb_software_status(gettext('Update task finished.'));
	}
}
?>

<script type="text/javascript">
//<![CDATA[
events.push(function() {

	// Wire each action button to a POST. Update is destructive (it runs pkg) so it
	// confirms first; Check is a cache refresh and posts straight through.
	function pfb_sw_submit(action) {
		var f = document.forms[0];
		var i = document.createElement('input');
		i.type = 'hidden';
		i.name = 'pfb_sw_action';
		i.value = action;
		f.appendChild(i);
		f.submit();
	}

	$('#pfb_sw_check').click(function(e) {
		e.preventDefault();
		pfb_sw_submit('check');
	});
	$('#pfb_sw_update').click(function(e) {
		e.preventDefault();
		if (confirm('Update pfBlockerNG to the latest version now?')) {
			pfb_sw_submit('update');
		}
	});
});
//]]>
</script>

<?php include('foot.inc'); ?>

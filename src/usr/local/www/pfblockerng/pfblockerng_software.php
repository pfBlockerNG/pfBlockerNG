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

// ADR-19: the "Software" page — show the installed pfBlockerNG channel/version vs
// our-repo latest (from the cron-maintained cache), toggle the new-version notice,
// and run same-channel Check / Update / Bootstrap actions. Disable NGINX output
// buffering so the Update/Bootstrap live terminal streams (mirrors _update.php).
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

// The notify knob (default|on|off) — persisted to config like the other general knobs.
$pfb_sw_notify	= (string) config_get_path('installedpackages/pfblockerng/config/0/pfb_software_notify', 'default');

$options_pfb_software_notify = array(
	'default'	=> 'Default (per channel)',
	'on'		=> 'On',
	'off'		=> 'Off'
);


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

// Determine which (POST-guarded) action was requested. Destructive actions
// (Update/Bootstrap) and the cache-refreshing Check run on POST only — never on a
// GET (so the ui_render gate's GET cannot trigger pkg).
$pfb_sw_action = '';
if ($_POST && !empty($_POST['pfb_sw_action'])) {
	$pfb_sw_action = (string) $_POST['pfb_sw_action'];
}

// "Save" the notify knob (standard pfSense CSRF POST).
if ($_POST && isset($_POST['save'])) {
	$notify_post = (string) ($_POST['pfb_software_notify'] ?? 'default');
	if (!array_key_exists($notify_post, $options_pfb_software_notify)) {
		$notify_post = 'default';
	}
	config_set_path('installedpackages/pfblockerng/config/0/pfb_software_notify', $notify_post);
	write_config('[pfBlockerNG] save Software notify setting');
	header('Location: /pfblockerng/pfblockerng_software.php');
	exit;
}

// "Check now" — force a cache refresh from our repo, then redisplay.
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

// Read the cron-maintained cache for the display state. Empty/unknown renders a
// clean "not checked yet" — never a warning (the page must pass ui_render on the
// first GET, before any check has run).
$cache		= pfb_software_read_cache();
$disp_channel	= !empty($cache['channel']) ? $cache['channel'] : ($pfb_sw_channel ?: gettext('unknown'));
$disp_installed	= !empty($cache['installed']) ? $cache['installed'] : gettext('unknown');
$disp_latest	= !empty($cache['latest']) ? $cache['latest'] : gettext('not checked yet');
$disp_checked	= !empty($cache['last_checked'])
			? date('Y-m-d H:i:s', (int) $cache['last_checked'])
			: gettext('never');

$update_available = pfb_update_available((string) ($cache['installed'] ?? ''), (string) ($cache['latest'] ?? ''));
if ($update_available) {
	$disp_status = '<span class="text-warning">' . gettext('Update available') . '</span>';
} elseif (!empty($cache['latest'])) {
	$disp_status = '<span class="text-success">' . gettext('Up to date') . '</span>';
} else {
	$disp_status = gettext('Not checked yet');
}

// pfb-software-panel — the page-specific render marker (ADR-14 ui_render oracle).
$form = new Form(false);

$section = new Form_Section('Software Status');
$section->addInput(new Form_StaticText(
	'Channel',
	'<span id="pfb-software-panel">' . htmlspecialchars((string) $disp_channel) . '</span>'
));
$section->addInput(new Form_StaticText(
	'Installed Version',
	htmlspecialchars((string) $disp_installed)
));
$section->addInput(new Form_StaticText(
	'Latest (our repo)',
	htmlspecialchars((string) $disp_latest)
));
$section->addInput(new Form_StaticText(
	'Status',
	$disp_status
));
$section->addInput(new Form_StaticText(
	'Last Checked',
	htmlspecialchars((string) $disp_checked)
));
$form->add($section);

$section = new Form_Section('Notification');
$section->addInput(new Form_Select(
	'pfb_software_notify',
	'New-version Notice',
	$pfb_sw_notify,
	$options_pfb_software_notify
))->setHelp('Default: <strong>per channel</strong> &mdash; nightly notifies, stable/devel stay quiet. '
		. 'Raise a notification when a newer pfBlockerNG build is available on your channel.')
  ->setAttribute('style', 'width: auto');

$btn_save = new Form_Button(
	'save',
	'Save',
	null,
	'fa-solid fa-save'
);
$btn_save->setAttribute('value', 'save');
$section->addInput(new Form_StaticText(
	null,
	$btn_save
));
$form->add($section);

$section = new Form_Section('Actions');
$section->addInput(new Form_StaticText(
	null,
	gettext('Check refreshes the version cache from your channel. Update installs the latest build on '
		. 'your CURRENT channel (no cross-channel switch). Bootstrap repo (re)writes the pfBlockerNG '
		. 'pkg repository so future installs/updates resolve to our build.')
));

$btn_check = new Form_Button(
	'pfb_sw_check',
	'Check now',
	null,
	'fa-solid fa-arrows-rotate'
);
$btn_check->removeClass('btn-primary')->addClass('btn-primary btn-xs')->setWidth(2);

$btn_update = new Form_Button(
	'pfb_sw_update',
	'Update now',
	null,
	'fa-solid fa-download'
);
$btn_update->removeClass('btn-primary')->addClass('btn-warning btn-xs')->setWidth(2)
	   ->setAttribute('title', gettext('Same-channel upgrade only'));

$btn_bootstrap = new Form_Button(
	'pfb_sw_bootstrap',
	'Bootstrap repo',
	null,
	'fa-solid fa-screwdriver-wrench'
);
$btn_bootstrap->removeClass('btn-primary')->addClass('btn-default btn-xs')->setWidth(2);

$section->addInput(new Form_StaticText(
	null,
	$btn_check . $btn_update . $btn_bootstrap
));
$form->add($section);

// Live terminal window (shown when an Update/Bootstrap is streaming).
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

// Destructive actions stream into the terminal AFTER the form has rendered (so the
// textareas exist for the JS to write into). POST-guarded only.
if ($pfb_sw_action === 'update') {
	if ($pfb_sw_pkgname === '') {
		pfb_software_status(gettext('No pfBlockerNG package detected — cannot update.'));
	} else {
		pfb_software_status(gettext('Running same-channel update...'));
		$bin = escapeshellarg(PFB_PKG_BIN);
		$pkg = escapeshellarg($pfb_sw_pkgname);
		pfb_software_run_stream("{$bin} upgrade -y {$pkg}");
		pfb_software_status(gettext('Update task finished.'));
	}
} elseif ($pfb_sw_action === 'bootstrap') {
	pfb_software_status(gettext('Bootstrapping the pfBlockerNG pkg repository...'));
	// Reproduce add-repo.sh's effect for the current channel (the dev-only script
	// is not shipped). nightly -> the separate nightly repo; stable/devel share the
	// release repo (the package, not the repo, is the channel — ADR-19 amendment 2).
	if ($pfb_sw_channel === 'nightly') {
		$repo_name = 'pfblockerng-nightly';
		$conf_name = 'pfblockerng-nightly.conf';
		$url_subpath = 'nightly/';
	} else {
		$repo_name = 'pfblockerng';
		$conf_name = 'pfblockerng.conf';
		$url_subpath = '';
	}
	$base_url = 'https://pkg.pfblockerng.workers.dev';
	$conf =	"# pfBlockerNG self-hosted pkg repository (ADR-17). Managed by pfBlockerNG.\n"
		. "{$repo_name}: {\n"
		. "  url: \"{$base_url}/{$url_subpath}\${ABI}\",\n"
		. "  mirror_type: none,\n"
		. "  signature_type: none,\n"
		. "  priority: 100,\n"
		. "  enabled: yes\n"
		. "}\n";
	$conf_dir = '/usr/local/etc/pkg/repos';
	safe_mkdir($conf_dir);
	if (@file_put_contents("{$conf_dir}/{$conf_name}", $conf, LOCK_EX) === false) {
		pfb_software_output(gettext('Failed to write the repository conf.'));
	} else {
		pfb_software_output(sprintf(gettext('Wrote %s'), "{$conf_dir}/{$conf_name}"));
		$bin = escapeshellarg(PFB_PKG_BIN);
		$repo = escapeshellarg($repo_name);
		pfb_software_run_stream("{$bin} update -r {$repo}");
	}
	pfb_software_status(gettext('Bootstrap task finished.'));
}
?>

<script type="text/javascript">
//<![CDATA[
events.push(function() {

	// Wire each action button to a confirm + POST. Update/Bootstrap are
	// destructive (they run pkg / write a repo conf) so they confirm first;
	// Check is a cache refresh and posts straight through.
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
		if (confirm('Run a same-channel pfBlockerNG update now?')) {
			pfb_sw_submit('update');
		}
	});
	$('#pfb_sw_bootstrap').click(function(e) {
		e.preventDefault();
		if (confirm('(Re)write the pfBlockerNG pkg repository configuration?')) {
			pfb_sw_submit('bootstrap');
		}
	});
});
//]]>
</script>

<?php include('foot.inc'); ?>

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

// SECONDARY PRIVILEGE GATE (issue #485). The framework page-guard already requires
// page-firewall-pfblockerng to reach here; this page can now UNINSTALL the package, so
// additionally require the Package Manager "Installed" privilege — the priv pfSense uses for
// its own package-Remove page (page-system-packagemanager-installed, match 'pkg_mgr_installed.php*').
// pfSense match-based privilege is OR across groups, so this AND can only be enforced by an
// explicit in-page check. Use isAllowedPage() against that page, NOT userHasPrivilege() with the
// raw priv id: isAllowedPage honours the admin (uid 0) short-circuit AND the 'page-all' wildcard
// match, whereas userHasPrivilege does an exact priv-id membership test that wrongly excludes a
// page-all admin (who lacks the literal '…-installed' priv) — that would lock admins out.
if (!isAllowedPage('pkg_mgr_installed.php')) {
	header('Location: /index.php');
	exit;
}

// Resolve the installed package + channel ONCE (used by display + the actions).
$pfb_sw_pkgname	= pfb_pkg_installed_name();
$pfb_sw_channel	= pfb_channel_from_pkgname($pfb_sw_pkgname);

// The "Check for new versions" setting (default ENABLED). Persisted as 'on'/'off'; an unset
// value (never saved) reads as enabled via pfb_software_check_enabled().
$pfb_sw_check_raw = PfbConfig::read('pfb_software_check');
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
// escapeshellarg'd by the caller. Returns the command's exit status (0 = success,
// -1 if it could not be started) so the caller can act on the result.
// Each streamed line is also written to /var/log/pfblockerng/software.log (truncated at
// run start) so a subsequent plain GET can prefill the output textarea.
function pfb_software_run_stream($cmd) {
	$log    = '/var/log/pfblockerng/software.log';
	$log_fh = @fopen($log, 'w');
	$fh     = popen("{$cmd} 2>&1", 'r');
	if (!is_resource($fh)) {
		pfb_software_output(gettext('Failed to start the task.'));
		if (is_resource($log_fh)) {
			@fclose($log_fh);
		}
		return -1;
	}
	while (($line = fgets($fh)) !== FALSE) {
		if (is_resource($log_fh)) {
			@fwrite($log_fh, $line);
		}
		pfb_software_output(rtrim($line, "\r\n"));
	}
	if (is_resource($log_fh)) {
		@fclose($log_fh);
	}
	return pclose($fh);
}


// Reload the Software page after a short delay so the freshly-installed version and
// status are shown. Navigates (GET) to the page URL rather than reloading the current
// request, so the Update POST is never resubmitted. The delay lets the final terminal
// output settle on screen first.
function pfb_software_reload($url = '/pfblockerng/pfblockerng_software.php') {
	print("\n<script type=\"text/javascript\">");
	print("\n//<![CDATA[");
	print("\nsetTimeout(function(){ window.location.assign(" . json_encode($url) . "); }, 1500);");
	print("\n//]]>");
	print("\n</script>");
	ob_flush();
	flush();
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
	PfbConfig::write('pfb_software_check', isset($_POST['pfb_software_check']) ? 'on' : 'off');
	write_config('[pfBlockerNG] save Software settings');
	header('Location: /pfblockerng/pfblockerng_software.php');
	exit;
}

// "Check now" — a manual, explicit cache refresh from our repo, then redisplay. $force=true
// bypasses the "Check for new versions" enable-gate so a one-off check always works.
if ($pfb_sw_action === 'check') {
	pfb_software_update_check(TRUE);
	header('Location: /pfblockerng/pfblockerng_software.php');
	exit;
}

$shortcut_section = 'pfblockerng';
include_once('head.inc');

// Tab bar (the Software tab is the active one here; gated like every page).
$get_req = pfb_alerts_default_page();

$tab_array	= array();
$tab_array[]	= array(gettext('General'),	FALSE,	'/pfblockerng/pfblockerng_general.php');
$tab_array[]	= array(gettext('IP'),		FALSE,	'/pfblockerng/pfblockerng_ip.php');
$tab_array[]	= array(gettext('DNSBL'),	FALSE,	'/pfblockerng/pfblockerng_dnsbl.php');
$tab_array[]	= array(gettext('Update'),	FALSE,	'/pfblockerng/pfblockerng_update.php');
$tab_array[]	= array(gettext('Reports'),	FALSE,	"/pfblockerng/pfblockerng_alerts.php{$get_req}");
$tab_array[]	= array(gettext('Feeds'),	FALSE,	'/pfblockerng/pfblockerng_feeds.php');
$tab_array[]	= array(gettext('Logs'),	FALSE,	'/pfblockerng/pfblockerng_log.php');
$tab_array[]	= array(gettext('Sync'),	FALSE,	'/pfblockerng/pfblockerng_sync.php');
pfb_software_add_tab($tab_array, TRUE);
display_top_tabs($tab_array, TRUE);
pfb_print_pending_changes_box();

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

$section->addInput(new Form_Checkbox(
	'pfb_sw_uninstall_confirm',
	'Confirm uninstall',
	'Confirm I want to uninstall pfBlockerNG',
	FALSE
))->setHelp('Required before the Uninstall button is enabled. Uninstalling removes pfBlockerNG entirely.');

$btn_uninstall = new Form_Button(
	'pfb_sw_uninstall',
	'Uninstall',
	null,
	'fa-solid fa-trash-can'
);
$btn_uninstall->removeClass('btn-primary')->addClass('btn-danger btn-xs')->setWidth(2);
$btn_uninstall->setAttribute('disabled', 'disabled');
$section->addInput(new Form_StaticText(null, $btn_uninstall))
	->setHelp('Remove pfBlockerNG from this firewall. Enabled only after the confirmation box is checked.');
$form->add($section);

// Live terminal window (shown when an Update is streaming).
// Plain GET (no active update/uninstall stream) → prefill pfb_output with the last software log.
$pfb_sw_active = ($pfb_sw_action !== '');
$section = new Form_Section('Output');
$section->addInput(new Form_Textarea(
	'pfb_status',
	null,
	'Standby'
))->removeClass('form-control')->addClass('row-fluid col-sm-12')->setAttribute('rows', '1')->setAttribute('wrap', 'off')
  ->setAttribute('readonly', 'readonly')->setAttribute('style', 'background:#fafafa; width: 100%');
$section->addInput(new Form_Textarea(
	'pfb_output',
	null,
	$pfb_sw_active ? null : pfb_log_tail('/var/log/pfblockerng/software.log')
))->removeClass('form-control')->addClass('row-fluid col-sm-12')->setAttribute('rows', '20')->setAttribute('wrap', 'off')
  ->setAttribute('readonly', 'readonly')->setAttribute('style', 'background:#fafafa; width: 100%');
$form->add($section);

print($form);

// The destructive Update streams into the terminal AFTER the form has rendered (so the
// textareas exist for the JS to write into). POST-guarded only.
if ($pfb_sw_action === 'update') {
	// Defense-in-depth: the "Update now" button is only disabled client-side, so also
	// refuse the action server-side when there is nothing to install — never run pkg on a
	// stale/no-op POST. (Request authenticity is enforced by pfSense's CSRF token.)
	if (!$update_available) {
		pfb_software_status(gettext('No update is currently available.'));
	} elseif ($pfb_sw_pkgname === '') {
		pfb_software_status(gettext('No pfBlockerNG package detected — cannot update.'));
	} else {
		pfb_software_status(gettext('Updating pfBlockerNG...'));
		$bin = escapeshellarg(PFB_PKG_BIN);
		$pkg = escapeshellarg($pfb_sw_pkgname);
		$pfb_sw_rc = pfb_software_run_stream("{$bin} upgrade -y {$pkg}");
		// On success, reload so the page reflects the new installed version + status;
		// on failure, leave the terminal log on screen for the user to inspect.
		if ($pfb_sw_rc === 0) {
			pfb_software_status(gettext('Update complete — refreshing the page...'));
			pfb_software_reload();
		} else {
			pfb_software_status(gettext('Update task finished with errors — see the log above.'));
		}
	}
}

// Uninstall streams AFTER the form renders (textareas must exist for the JS). POST-guarded.
if ($pfb_sw_action === 'uninstall') {
	// Defense-in-depth: the Uninstall button is only disabled client-side, so re-check the
	// confirmation server-side and refuse without it. (CSRF token enforces request authenticity.)
	if (!isset($_POST['pfb_sw_uninstall_confirm'])) {
		pfb_software_status(gettext('Uninstall not confirmed — tick the confirmation box first.'));
	} elseif ($pfb_sw_pkgname === '') {
		pfb_software_status(gettext('No pfBlockerNG package detected — cannot uninstall.'));
	} else {
		pfb_software_status(gettext('Uninstalling pfBlockerNG...'));
		$bin = escapeshellarg(PFB_PKG_BIN);
		$pkg = escapeshellarg($pfb_sw_pkgname);
		$pfb_sw_rc = pfb_software_run_stream("{$bin} delete -y {$pkg}");
		// Success removes the very package serving this page; redirect somewhere safe instead
		// of leaving the user on a now-404 tab. Failure leaves the log on screen to inspect.
		if ($pfb_sw_rc === 0) {
			pfb_software_status(gettext('Uninstall complete — redirecting...'));
			pfb_software_reload('/pkg_mgr_installed.php');
		} else {
			pfb_software_status(gettext('Uninstall task finished with errors — see the log above.'));
		}
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

	function pfb_sw_uninstall_sync() {
		document.getElementById('pfb_sw_uninstall').disabled = !document.getElementById('pfb_sw_uninstall_confirm').checked;
	}
	$('#pfb_sw_uninstall_confirm').on('change', pfb_sw_uninstall_sync);
	pfb_sw_uninstall_sync();

	$('#pfb_sw_uninstall').click(function(e) {
		e.preventDefault();
		if (confirm('Uninstall pfBlockerNG from this firewall? This cannot be undone.')) {
			pfb_sw_submit('uninstall');
		}
	});
});
//]]>
</script>

<?php include('foot.inc'); ?>

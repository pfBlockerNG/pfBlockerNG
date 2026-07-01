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
// offer Check / Update / Uninstall. The Update and Uninstall actions are SHORTCUTS to pfSense's
// base-system Package Manager (pkg_mgr_install.php): it runs pkg and streams its own progress
// from a page that SURVIVES pfBlockerNG's own removal/upgrade, so this page never self-hosts a
// pkg dispatch (no detached daemon, no live-tail endpoint, no state files to vanish mid-operation).

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
// page-firewall-pfblockerng to reach here; the Update/Uninstall shortcuts lead to the Package
// Manager, so additionally require the Package Manager "Installed" privilege — the priv pfSense
// uses for its own package-Remove page (page-system-packagemanager-installed, match
// 'pkg_mgr_installed.php*'). pfSense match-based privilege is OR across groups, so this AND can
// only be enforced by an explicit in-page check. Use isAllowedPage() against that page, NOT
// userHasPrivilege() with the raw priv id: isAllowedPage honours the admin (uid 0) short-circuit
// AND the 'page-all' wildcard match, whereas userHasPrivilege does an exact priv-id membership
// test that wrongly excludes a page-all admin (who lacks the literal '…-installed' priv) — that
// would lock admins out.
if (!isAllowedPage('pkg_mgr_installed.php')) {
	header('Location: /index.php');
	exit;
}

// Resolve the installed package + channel ONCE (used by display + the action shortcuts).
$pfb_sw_pkgname	= pfb_pkg_installed_name();
$pfb_sw_channel	= pfb_channel_from_pkgname($pfb_sw_pkgname);

// The "Check for new versions" setting (default ENABLED). Persisted as 'on'/'off'; an unset
// value (never saved) reads as enabled via pfb_software_check_enabled().
$pfb_sw_check_raw = PfbConfig::read('pfb_software_check');
$pfb_sw_check	= pfb_software_check_enabled(is_string($pfb_sw_check_raw) ? $pfb_sw_check_raw : null);

// Which (POST-guarded) action was requested. Only the cache-refreshing Check runs here now;
// Update/Uninstall are plain links to pkg_mgr_install.php, not POST actions.
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

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('Software'));
$pglinks = array('', '/pfblockerng/pfblockerng_general.php', '@self');

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
	'<span id="pfb-sw-installed">' . htmlspecialchars((string) $disp_installed) . '</span>'
));
$section->addInput(new Form_StaticText(
	'Latest version',
	htmlspecialchars((string) $disp_latest)
));
$section->addInput(new Form_StaticText(
	'Status',
	'<span id="pfb-sw-status">' . $disp_status . '</span>'
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

// Check now — a local cache refresh from our repo (no network mutation), POSTed below.
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

// Update now — a LINK to pfSense's Package Manager (reinstallpkg = pfSense's own single-package
// upgrade path; pkg resolves the newest candidate, which is ours by repo priority). The base page
// runs pkg and streams progress from a page that survives the swap. Enabled only when an update
// is available and the package name is known.
$pfb_pkg_arg = rawurlencode((string) $pfb_sw_pkgname);
// The href itself is the gate (an anchor's disabled/aria-disabled are advisory only, so a
// stray activation must land nowhere actionable): a real reinstall target ONLY when an update
// is available and the package name is known, else '#'. The disabled styling is the visual cue.
$btn_update = new Form_Button(
	'pfb_sw_update',
	'Update now',
	($update_available && $pfb_sw_pkgname !== '') ? "/pkg_mgr_install.php?mode=reinstallpkg&pkg={$pfb_pkg_arg}" : '#',
	'fa-solid fa-download'
);
$btn_update->removeClass('btn-primary')->addClass('btn-warning btn-xs')->setWidth(2);
if (!$update_available || $pfb_sw_pkgname === '') {
	$btn_update->addClass('disabled')->setAttribute('disabled', 'disabled')->setAttribute('aria-disabled', 'true');
}
$section->addInput(new Form_StaticText(null, $btn_update))
	->setHelp('Install the latest version via the pfSense Package Manager. Available only when an update is found.');

// Uninstall — a link straight to pfSense's Package Manager delete flow (its own confirm step runs
// there). #697: a delete always performs a full teardown (uninstall = OFF), so no intent marker is
// needed; a version upgrade is a `pkg delete` we cannot distinguish and is handled the same way.
$btn_uninstall = new Form_Button(
	'pfb_sw_uninstall',
	'Uninstall',
	($pfb_sw_pkgname !== '') ? "/pkg_mgr_install.php?mode=delete&pkg={$pfb_pkg_arg}" : '#',
	'fa-solid fa-trash-can'
);
$btn_uninstall->removeClass('btn-primary')->addClass('btn-danger btn-xs')->setWidth(2);
if ($pfb_sw_pkgname === '') {
	$btn_uninstall->addClass('disabled')->setAttribute('disabled', 'disabled')->setAttribute('aria-disabled', 'true');
}
$section->addInput(new Form_StaticText(null, $btn_uninstall))
	->setHelp('Remove pfBlockerNG from this firewall via the pfSense Package Manager (it will ask you to confirm).');
$form->add($section);

print($form);
?>

<script type="text/javascript">
//<![CDATA[
events.push(function() {

	// Check now is the only in-page action left — a cache refresh POSTed back to this page.
	// Update / Uninstall are plain links to the Package Manager (no JS, no POST).
	$('#pfb_sw_check').click(function(e) {
		e.preventDefault();
		var f = document.forms[0];
		var i = document.createElement('input');
		i.type = 'hidden';
		i.name = 'pfb_sw_action';
		i.value = 'check';
		f.appendChild(i);
		f.submit();
	});
});
//]]>
</script>

<?php include('foot.inc'); ?>

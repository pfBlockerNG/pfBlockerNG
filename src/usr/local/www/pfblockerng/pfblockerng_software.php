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

// ADR-19 (issue #2360 backport): the "Software" page — show the installed pfBlockerNG
// channel/version vs our-repo latest (from the cron-maintained cache), toggle the "Check
// for new versions" setting, and offer Check / Update / Uninstall. The Update and
// Uninstall actions are SHORTCUTS to pfSense's base-system Package Manager
// (pkg_mgr_install.php): it runs pkg and streams its own progress from a page that
// SURVIVES pfBlockerNG's own removal/upgrade, so this page never self-hosts a pkg
// dispatch (no detached daemon, no live-tail endpoint, no state files to vanish
// mid-operation).

require_once('guiconfig.inc');
require_once('globals.inc');
require_once('pfsense-utils.inc');
require_once('util.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng_software.inc');

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
// Channel is CATALOGUE placement — all four catalogues publish the canonical
// 'pfSense-pkg-pfBlockerNG', so the repo the package came from names the channel, with the
// name as the fallback for the legacy shared repo. pfb_channel_for_install() is that one
// rule, shared with pfb_software_update_check() so the page label and the notice text
// cannot drift apart.
$pfb_sw_pkgname	= pfb_pkg_installed_name();
$pfb_sw_repo	= pfb_pkg_installed_repo($pfb_sw_pkgname);
$pfb_sw_channel	= pfb_channel_for_install($pfb_sw_repo, $pfb_sw_pkgname);

// The "Check for new versions" setting (default ENABLED). The accessor reads the
// file-local config accessor (pfb_software_check_config_read() in pfblockerng_software.inc);
// no raw value handling here.

// Which (POST-guarded) action was requested. Only the cache-refreshing Check runs here now;
// Update/Uninstall are plain links to pkg_mgr_install.php, not POST actions.
$pfb_sw_action = '';
if ($_POST && !empty($_POST['pfb_sw_action'])) {
	$pfb_sw_action = (string) $_POST['pfb_sw_action'];
}

$input_errors = array();

// "Save" the settings (standard pfSense CSRF POST). A checkbox is absent from the POST when
// unticked, so persist the owner-ruled empty Off token; an absent config key defaults On.
if ($_POST && isset($_POST['save'])) {
	pfb_software_check_config_write((pfb_filter($_POST['pfb_software_check'] ?? '', PFB_FILTER_ON_OFF, 'software') ?: '') === 'on');
	$pfb_ca_was_consented = pfb_pkg_ca_consent_enabled();
	$pfb_ca_token = pfb_pkgconf_ca_save($_POST);
	write_config('[pfBlockerNG] save Software settings');
	$pfb_ca_ok = pfb_pkgconf_ca_apply($pfb_ca_token, $pfb_ca_was_consented);
	if ($pfb_ca_ok) {
		header('Location: /pfblockerng/pfblockerng_software.php');
		exit;
	}
	$input_errors[] = sprintf(
		gettext(
			'The setting was saved, but pfBlockerNG could not update %s right now (its CA '
			. 'certificate directory may be missing or empty -- try running `certctl rehash` '
			. 'from the shell). pfBlockerNG will retry at the next boot or package check.'
		),
		PFB_PKG_CONF
	);
}

// Read after the save block so a failed CA sync re-render shows the just-posted software choice.
$pfb_sw_check	= pfb_software_check_enabled();

// "Check now" — a manual, explicit cache refresh from the pfBlockerNG repo, then redisplay. $force=true
// bypasses the "Check for new versions" enable-gate so a one-off check always works.
if ($pfb_sw_action === 'check') {
	pfb_software_update_check(TRUE);
	header('Location: /pfblockerng/pfblockerng_software.php');
	exit;
}

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('Software'));
$pglinks = array('', '/pfblockerng/pfblockerng_general.php', '@self');
include_once('head.inc');

if ($input_errors) {
	print_input_errors($input_errors);
}

// Define default Alerts Tab href link (Top row) — same pattern as every sibling page.
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
pfb_software_add_tab($tab_array, TRUE);
display_top_tabs($tab_array, true);

// Channel + installed version are read LIVE (local `pkg query`, no network) so they are
// always known on an installed box. Only the our-repo "latest" + status + last-checked come
// from the cron-maintained cache (empty/unknown renders a clean "Not checked yet" — never a
// warning — so the page passes ui_render on the first GET, before any check has run).
//
// The cache is trusted only while it describes the install the box carries NOW — the same
// package name from the same repository. pfb_software_update_check() rescopes it on a
// change, but that lands on the next tick, so between a channel migration (or an in-repo
// identity swap on the legacy shared catalogue) and that tick this page would otherwise
// pair the current install's label with the PREVIOUS one's version and an "Update
// available"/"Up to date" verdict it has no business showing. Identical call to the
// orchestrator's, so the two can never disagree about which cache is current.
$cache		= pfb_software_read_cache();
$cache_current	= pfb_software_cache_matches_install($cache, $pfb_sw_pkgname, $pfb_sw_repo);
$cached_latest	= $cache_current ? (string) ($cache['latest'] ?? '') : '';
$installed_ver	= pfb_pkg_installed_version($pfb_sw_pkgname);
$disp_channel	= $pfb_sw_channel ?: gettext('unknown');
$disp_installed	= ($installed_ver !== '') ? $installed_ver : gettext('unknown');
$disp_latest	= ($cached_latest !== '') ? $cached_latest : gettext('Not checked yet');
$disp_checked	= ($cache_current && !empty($cache['last_checked']))
			? date('Y-m-d H:i:s', (int) $cache['last_checked'])
			: gettext('never');

$update_available = pfb_update_available($installed_ver, $cached_latest);
if ($update_available) {
	$disp_status = '<span class="text-warning">' . gettext('Update available') . '</span>';
} elseif ($cached_latest !== '') {
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
	$pfb_sw_check,
	'on'
))->setHelp('Periodically check for a new version and notify when one is available.');
$form->add($section);

// The installed repository hook owns pkg.conf; Plus is the only edition with the vendor pin.
if (pfb_pkg_ca_is_plus()) {
	pfb_pkgconf_ca_add_form_controls($form, pfb_pkg_ca_consent_enabled());
}

$section = new Form_Section('Actions');

// Check now — a local cache refresh from the pfBlockerNG repo (no network mutation), POSTed below.
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
// there). This is a `pkg delete`, which the pre-deinstall detects as a removal and fully tears
// down (uninstall = OFF), so no intent marker is needed. (A package Update is `pkg install -f`, a
// different op the pre-deinstall keeps live.)
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

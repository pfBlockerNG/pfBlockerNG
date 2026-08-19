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
// offer Check / Update / Uninstall. Update and Uninstall link to pfSense Package Manager
// ONLY when %R is pfSense (Netgate). A pfblockerng-* origin is invisible there (issue #2380),
// so those controls are disabled and the page prints the repo-qualified pkg CLI instead.

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
// issue #2148 / #2395: channel is CATALOGUE placement — all four catalogues publish the
// canonical 'pfSense-pkg-pfBlockerNG'. Repo first, then pfb_build_record.channel, then a
// leftover name suffix. pfb_channel_for_install() is that one rule, shared with
// pfb_software_update_check() so the page label and the notice text cannot drift apart.
$pfb_sw_pkgname	= pfb_pkg_installed_name();
$pfb_sw_repo	= pfb_pkg_installed_repo($pfb_sw_pkgname);
$pfb_sw_record	= ($pfb_sw_pkgname !== '')
	? pfb_channel_from_build_record(pfb_pkg_annotation($pfb_sw_pkgname, 'pfb_build_record'))
	: null;
$pfb_sw_channel	= pfb_channel_for_install($pfb_sw_repo, $pfb_sw_pkgname, $pfb_sw_record);

// Which (POST-guarded) action was requested. Only the cache-refreshing Check runs here now;
// Update/Uninstall are links (or disabled CLI help), not POST actions.
$pfb_sw_action = '';
if ($_POST && !empty($_POST['pfb_sw_action'])) {
	$pfb_sw_action = (string) $_POST['pfb_sw_action'];
}

// $input_errors is read unconditionally in the render section below (the house pattern; see
// pfblockerng_general.php), so it must be defined on every request path, including a POST
// without 'save'.
$input_errors = array();

// "Save" the settings (standard pfSense CSRF POST). A checkbox is absent from the POST when
// unticked, so persist the owner-ruled empty Off token; an absent config key defaults On.
if ($_POST && isset($_POST['save'])) {
	PfbConfig::write('gen/pfb_software_check', pfb_filter($_POST['pfb_software_check'] ?? '', PFB_FILTER_ON_OFF, 'software') ?: '');

	// issue #2518 B1/N-write-order: pfb_pkgconf_ca_save() ONLY persists the posted consent
	// token (into the in-memory config array) -- it never touches pkg.conf. The flush below
	// (write_config()) must land BEFORE pkg.conf is ever mutated on the admin's behalf:
	// consent is this feature's security boundary, and a crash between patching pkg.conf and
	// flushing config.xml would otherwise leave the box patched with no recorded consent that
	// survives a reboot. pfb_pkgconf_ca_apply() (the sync half) runs only after the flush.
	$pfb_ca_was_consented = PfbConfig::read('gen/pfb_pkg_ca_consent') === PfbToggle::On;
	$pfb_ca_token = pfb_pkgconf_ca_save($_POST);
	write_config('[pfBlockerNG] save Software settings');

	// The consent flag is already durable; the installed hook now owns the file mutation.
	$pfb_ca_ok = pfb_pkgconf_ca_apply($pfb_ca_token, $pfb_ca_was_consented);
	if ($pfb_ca_ok) {
		header('Location: /pfblockerng/pfblockerng_software.php');
		exit;
	}
	$input_errors[] = 'The setting was saved, but pfBlockerNG could not update ' . PFB_PKG_CONF
		. ' right now (its CA certificate directory may be missing or empty -- try running '
		. '`certctl rehash` from the shell). pfBlockerNG will retry at the next boot or '
		. 'package operation.';
}

// N-stale-checkbox (issue #2518 fix round): read AFTER the save block above, not before -- a
// CA-sync failure re-renders this SAME request (no redirect), and the admin's just-posted
// 'pfb_software_check' choice must be reflected on that re-render, not the value from before
// this Save.
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

$shortcut_section = 'pfblockerng';
include_once('head.inc');

if ($input_errors) {
	print_input_errors($input_errors);
}

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
//
// issue #2148: the cache is trusted only while it describes the install the box carries
// NOW — the same package name from the same repository. pfb_software_update_check()
// rescopes it on a change, but that lands on the next tick, so between a channel migration
// (or an in-repo identity swap on the legacy shared catalogue) and that tick this page
// would otherwise pair the current install's label with the PREVIOUS one's version and an
// "Update available"/"Up to date" verdict it has no business showing. Identical call to the
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
// The 5th argument is the token this box POSTS when ticked, and it is load-bearing:
// pfSense defaults it to 'yes', which the save path's PFB_FILTER_ON_OFF rejects, so a
// checked Save would persist the disabled token and the setting could never be turned
// back on (issue #2367).
$section->addInput(new Form_Checkbox(
	'pfb_software_check',
	'New version check',
	'Enabled',
	$pfb_sw_check,
	'on'
))->setHelp('Periodically check for a new version and notify when one is available.');
$form->add($section);

// The installed repository hook owns pkg.conf; Plus is the only edition with the vendor pin.
$pfb_ca_plus = pfb_pkg_ca_is_plus();
if ($pfb_ca_plus) {
	$pfb_ca_consent = PfbConfig::read('gen/pfb_pkg_ca_consent') === PfbToggle::On;
	$pfb_ca_help = $pfb_ca_consent
		? 'Consent is on; pfBlockerNG verifies the SSL_CA_CERT_PATH line before each package operation. '
		: 'Right now, pkg on this firewall trusts only Netgate\'s own certificate bundle. '
			. 'Checking this box adds one SSL_CA_CERT_PATH=/etc/ssl/certs line in ' . PFB_PKG_CONF . '. ';
	$pfb_ca_help .= 'pfBlockerNG re-applies the line at boot and before package operations. '
		. 'Unchecking this removes only that one line; the rest of the file is left as pfSense wrote it.';

	$section = new Form_Section('Package manager CA trust');
	$section->addInput(new Form_Checkbox(
		'pfb_pkg_ca_consent',
		'Allow pfBlockerNG to manage the pkg.conf CA path',
		'Enabled',
		$pfb_ca_consent,
		'on'
	))->setHelp($pfb_ca_help);
	$form->add($section);
	$form->addGlobal(new Form_Input('pfb_pkg_ca_consent_shown', 'pfb_pkg_ca_consent_shown', 'hidden', '1'));
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

// Update / Uninstall. Package Manager only sees %R=pfSense (issue #2380). A pfblockerng-*
// origin is disabled here with the repo-qualified pkg CLI; never emit pkg_mgr_install.php
// for that origin (those pages hide the package and a reinstall can resolve against -r pfSense).
$pfb_sw_pkgmgr		= pfb_software_pkgmgr_usable($pfb_sw_repo);
$pfb_sw_update_href	= pfb_software_update_href($pfb_sw_pkgname, $pfb_sw_repo, $update_available);
$pfb_sw_uninstall_href	= pfb_software_uninstall_href($pfb_sw_pkgname, $pfb_sw_repo);
$pfb_sw_cli_pkg		= ($pfb_sw_pkgname !== '') ? $pfb_sw_pkgname : 'pfSense-pkg-pfBlockerNG';
$pfb_sw_cli_repo	= ($pfb_sw_repo !== '') ? $pfb_sw_repo : '<repo>';

$btn_update = new Form_Button(
	'pfb_sw_update',
	'Update now',
	$pfb_sw_update_href,
	'fa-solid fa-download'
);
$btn_update->removeClass('btn-primary')->addClass('btn-warning btn-xs')->setWidth(2);
if ($pfb_sw_update_href === '#') {
	$btn_update->addClass('disabled')->setAttribute('disabled', 'disabled')->setAttribute('aria-disabled', 'true');
}
if ($pfb_sw_pkgmgr) {
	$pfb_sw_update_help = 'Install the latest version via the pfSense Package Manager. Available only when an update is found.';
} else {
	$pfb_sw_update_help = 'Package Manager cannot see this origin. To update, run <code>pkg install -y -r '
		. htmlspecialchars($pfb_sw_cli_repo) . ' ' . htmlspecialchars($pfb_sw_cli_pkg)
		. '</code> from the shell.';
	if ($pfb_ca_plus) {
		// On Plus, point an unavailable Package Manager origin at the CA consent control.
		$pfb_sw_update_help .= ' pkg on this firewall currently trusts only Netgate\'s CA '
			. 'bundle, so that command will fail with a TLS error until you enable "Allow '
			. 'pfBlockerNG to manage the pkg.conf CA path" above.';
	}
}
$section->addInput(new Form_StaticText(null, $btn_update))
	->setHelp($pfb_sw_update_help);

// Uninstall. #697: a `pkg delete` is a removal (pre-deinstall tears down). Package Manager
// delete is only offered for a Netgate-origin install.
$btn_uninstall = new Form_Button(
	'pfb_sw_uninstall',
	'Uninstall',
	$pfb_sw_uninstall_href,
	'fa-solid fa-trash-can'
);
$btn_uninstall->removeClass('btn-primary')->addClass('btn-danger btn-xs')->setWidth(2);
if ($pfb_sw_uninstall_href === '#') {
	$btn_uninstall->addClass('disabled')->setAttribute('disabled', 'disabled')->setAttribute('aria-disabled', 'true');
}
if ($pfb_sw_pkgmgr) {
	$pfb_sw_uninstall_help = 'Remove pfBlockerNG from this firewall via the pfSense Package Manager (it will ask you to confirm).';
} else {
	$pfb_sw_uninstall_help = 'Package Manager cannot see this origin. To uninstall, run <code>pkg delete '
		. htmlspecialchars($pfb_sw_cli_pkg) . '</code> from the shell.';
}
$section->addInput(new Form_StaticText(null, $btn_uninstall))
	->setHelp($pfb_sw_uninstall_help);
$form->add($section);

print($form);
?>

<script type="text/javascript">
//<![CDATA[
events.push(function() {

	// Check now is the only in-page action — a cache refresh POSTed back to this page.
	// Update / Uninstall are plain links to the Package Manager only when %R is pfSense.
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

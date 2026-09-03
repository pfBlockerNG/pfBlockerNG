<?php
/*
 * pfblockerng_install.inc
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2015-2026 Rubicon Communications, LLC (Netgate)
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

require_once('pfsense-utils.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');

global $g, $pfb;
pfb_global();

// issue #3062: serialise this install against feed passes BEFORE anything it shares with
// one is touched (config surgery, service restarts, the chroot restage below). The hold
// lasts until this process exits, so the post-install resync reenters it.
update_status("\nSerialising against any in-flight pfBlockerNG feed pass...");
update_status(pfb_install_feed_pass_hold() ? " done.\n" : " lock not taken; continuing anyway.\n");

// issue #2371: capture DNSBL freshness before settings-family restore or migrations mutate it.
$pfb_psl_feed_policy_fresh_install = pfb_psl_feed_policy_is_fresh_install(
	PfbConfig::readSection(PFB_SECTIONS['dnsbl'])
);

$pfb_installed_family = pfb_install_settings_family_capture_restore();
pfb_global();

// issue #2372: capture modes from the restored target family before migrations mutate it.
$pfb_registry_sections = array();
foreach (PFB_SECTIONS as $pfb_registry_section) {
	$pfb_registry_sections[$pfb_registry_section] = PfbConfig::readSection($pfb_registry_section);
}
$pfb_registry_modes = pfb_registry_section_modes($pfb_registry_sections);
unset($pfb_registry_sections, $pfb_registry_section);

// Set 'Install flag' to skip sync process during installations.
$g['pfblockerng_install'] = TRUE;
$pfb['hook_lifecycle'] = 'install';

// #684: mark this process an install/upgrade so the resync (custom_php_resync_config_command,
// run next in the same install_package_xml process) publishes PFB_POST_INSTALL=1 to the hooks its
// turn-ON pass fires. Scoped to install.inc, so a boot/config-restore resync -- which does NOT run
// this file -- carries PFB_POST_INSTALL=0 (the vars are always emitted as '1'/'0', #695). Context
// only: pfBlockerNG never branches on it.
// Migrate old VIP configuration.
$pfb_dnsbl_config = PfbConfig::readSection('installedpackages/pfblockerngdnsblsettings/config/0');
if (
	isset($pfb_dnsbl_config['pfb_dnsvip']) ||
	isset($pfb_dnsbl_config['pfb_dnsblv6']) ||
	isset($pfb_dnsbl_config['pfb_dnsvip_type']) ||
	isset($pfb_dnsbl_config['pfb_dnsvip_vhid']) ||
	isset($pfb_dnsbl_config['pfb_dnsvip_base']) ||
	isset($pfb_dnsbl_config['pfb_dnsvip_skew']) ||
	isset($pfb_dnsbl_config['pfb_dnsvip_pass'])
) {
	// Update existing VIPs.
	$vips_found = FALSE;
	$vips_config = config_get_path('virtualip/vip', []); // foreign key — out of ADR-29 gateway scope
	foreach ($vips_config as &$vip) {
		if (!str_starts_with($vip['descr'], 'pfB DNSBL')) {
			continue;
		}
		$vips_found = TRUE;

		$vip['descr'] = 'pfBlockerNG DNSBL';
		$vip['uniqid'] = $vip['uniqid'] ?? uniqid();

		$vip_id = "_vip{$vip['uniqid']}";
		if ($pfb_dnsbl_config['pfb_dnsvip'] == $vip['subnet']) {
			$pfb_dnsbl_config['pfb_dnsvip4'] = $vip_id;
		} elseif (empty($pfb_dnsbl_config['pfb_dnsvip4']) && is_ipaddrv4($vip['subnet'])) {
			$pfb_dnsbl_config['pfb_dnsvip4'] = $vip_id;
		} elseif (is_ipaddrv6($vip['subnet'])) {
			$pfb_dnsbl_config['pfb_dnsvip6'] = $vip_id;
		}
	}
	unset($vip);
	if ($vips_found) {
		config_set_path('virtualip/vip', $vips_config); // foreign key — out of ADR-29 gateway scope
	} elseif (is_ipaddrv4($pfb_dnsbl_config['pfb_dnsvip'])) {
		// DNSBL is enabled but a VIP isn't configured.
		file_notice('pfBlockerNG', gettext('The DNSBL VIP needs to be configured manually'), 'pfBlockerNG', '/pfblockerng/pfblockerng_dnsbl.php', 2);
	}

	// If DNSBL is not configured, don't set new config.
	if (
		isset($pfb_dnsbl_config['pfb_dnsvip4']) &&
		(!isset($pfb_dnsbl_config['pfb_dnsvip']) || !is_ipaddrv4($pfb_dnsbl_config['pfb_dnsvip']) ||
			!is_string($pfb_dnsbl_config['pfb_dnsvip4']) ||
			!str_starts_with($pfb_dnsbl_config['pfb_dnsvip4'], '_vip'))
	) {
		unset($pfb_dnsbl_config['pfb_dnsvip4']);
	}
	if (
		isset($pfb_dnsbl_config['pfb_dnsvip6']) &&
		(($pfb_dnsbl_config['pfb_dnsblv6'] != 'on') ||
			!is_string($pfb_dnsbl_config['pfb_dnsvip6']) ||
			!str_starts_with($pfb_dnsbl_config['pfb_dnsvip6'], '_vip'))
	) {
		unset($pfb_dnsbl_config['pfb_dnsvip6']);
	}

	// Remove old configuration.
	unset(
		$pfb_dnsbl_config['pfb_dnsvip'],
		$pfb_dnsbl_config['pfb_dnsblv6'],
		$pfb_dnsbl_config['pfb_dnsvip_type'],
		$pfb_dnsbl_config['pfb_dnsvip_vhid'],
		$pfb_dnsbl_config['pfb_dnsvip_base'],
		$pfb_dnsbl_config['pfb_dnsvip_skew'],
		$pfb_dnsbl_config['pfb_dnsvip_pass']
	);
	// Reset saved wizard configuration.
	config_del_path('pfblockerng_wizard'); // foreign key — out of ADR-29 gateway scope (root-level, not installedpackages/pfblockerng*)

	// issue #1921: RAW write-back keeps bystander values byte-identical so
	// pfb_registry_pass() receives exact stored inputs for rename/grandfather decisions.
	PfbConfig::writeSectionRawSystem('installedpackages/pfblockerngdnsblsettings/config/0', $pfb_dnsbl_config);
	write_config('Migrated old pfBlockerNG VIP configuration');
	pfb_global();
}

// ADR-29: run all registered upgrade migrations in order. Each migration's apply()
// callable reads the section, returns the updated array or NULL (no-op), and the driver
// writes back and calls write_config() only when a change is needed. Replaces the
// hand-wired ADR-02/PFBL-03/#1898 blocks with a single ordered registry.
pfb_install_settings_family_finalize($pfb_installed_family);

// issue #3088: return Regex Exceptions the editor now accepts; notice remaining Python rejects.
$pfb_regex_ex_text = pfb_b64_text(PfbConfig::read('dnsbl/pfb_regex_exception_list'));
if ($pfb_regex_ex_text !== '') {
	$pfb_regex_cap_on = PfbConfig::read('dnsbl/pfb_regex_cap') === PfbToggle::On;
	$pfb_regex_ex_errors = pfb_dnsbl_regex_validation_errors(
		$pfb_regex_ex_text,
		PFB_PYTHON_WRAPPER,
		$pfb_regex_cap_on
	);
	$pfb_regex_ex_upgrade = pfb_dnsbl_regex_exceptions_upgrade(
		(string) PfbConfig::read('dnsbl/pfb_regex_list'),
		(string) PfbConfig::read('dnsbl/pfb_regex_exception_list'),
		[],
		pfb_dnsbl_regex_error_line_numbers($pfb_regex_ex_errors)
	);
	if ($pfb_regex_ex_upgrade['returned'] > 0) {
		PfbConfig::writeSystem('dnsbl/pfb_regex_list', $pfb_regex_ex_upgrade['main_b64']);
		PfbConfig::writeSystem('dnsbl/pfb_regex_exception_list', $pfb_regex_ex_upgrade['exception_b64']);
		write_config('[pfBlockerNG] returned Regex Exceptions the editor now accepts');
	}
	if ($pfb_regex_ex_upgrade['returned'] > 0 || $pfb_regex_ex_upgrade['python_rejects_remain']) {
		$pfb_regex_ex_notice = pfb_dnsbl_regex_upgrade_notice(
			$pfb_regex_ex_upgrade['returned'],
			$pfb_regex_ex_upgrade['python_rejects_remain']
		);
		update_status("\n{$pfb_regex_ex_notice}\n");
		file_notice('pfBlockerNG', $pfb_regex_ex_notice, 'pfBlockerNG', '/pfblockerng/pfblockerng_dnsbl.php', 2);
	}
}

// MaxMind Database is no longer pre-installed during package installation
if (empty($pfb['maxmind_key'])) {
	update_status("\nMaxMind GeoIP databases are not pre-installed during installation.\nTo utilize the MaxMind GeoIP functionalities, you will be required to register for a free MaxMind user account and access key. Review the IP tab: MaxMind Settings for more details.\n\n");
}
elseif (pfb_geoip_generation_ready()) {
	// Update any PHP changes to GeoIP Tabs
	update_status("\nRebuilding GeoIP tabs...");
	if (pfblockerng_get_countries()) {
		update_status(" done.");
	} else {
		update_status(" failed.");
	}
}
else {
	update_status("\nGeoIP tab rebuild deferred until the interrupted GeoIP refresh is retried.\n");
}

// Create Reputation tab
if (!file_exists('/usr/local/www/pfblockerng/pfblockerng_reputation.php') || empty($pfb['maxmind_key'])) {
	update_status("\nRebuild Reputation tab...");
	if (pfb_build_reputation_tab()) {
		update_status(" done.");
	} else {
		update_status(" failed.");
	}
}

$widgets = config_get_path('widgets/sequence'); // foreign key — out of ADR-29 gateway scope
if (strpos($widgets, 'pfblockerng') === FALSE) {
	update_status("\nAdding pfBlockerNG Widget to the Dashboard...");
	if (empty($widgets)) {
		config_set_path('widgets/sequence', 'pfblockerng:col2:open:0'); // foreign key — out of ADR-29 gateway scope
	} else {
		config_set_path('widgets/sequence', $widgets . ',pfblockerng:col2:open:0'); // foreign key — out of ADR-29 gateway scope
	}
	update_status(" done.");
	write_config('Added pfBlockerNG widget to the dashboard');
}

// Create Firewall filter service and link required executables
update_status("\nCreating Firewall filter service...");
pfb_filter_service();
stop_service('pfb_filter');
update_status(" done.\nRenew Firewall filter executables...");
unlink_if_exists('/usr/local/bin/php_pfb');
link('/usr/local/bin/php', '/usr/local/bin/php_pfb');

// clog is not required for pfSense 2.5 and above
unlink_if_exists('/usr/local/sbin/clog_pfb');
unlink_if_exists('/usr/bin/tail_pfb');
link('/usr/bin/tail', '/usr/bin/tail_pfb');

// Remove cache databases
unlink_if_exists("{$pfb['asn_cache']}");
unlink_if_exists("{$pfb['ip_cache']}");
foreach (array($pfb['dnsbl_cache'], "{$pfb['dnsbl_cache']}-wal", "{$pfb['dnsbl_cache']}-shm") as $legacy_cache) {
	unlink_if_exists($legacy_cache);
}
rmdir_recursive("{$pfb['dbdir']}/dnsblalias");

// issue #1541: the pre-PSL chroot oracle copy is unowned after upgrade and its
// basename matches the pfb_py_* cache-save glob -- remove it once here.
unlink_if_exists('/var/unbound/pfb_py_tld.txt');

update_status(" done.\nStarting Firewall filter Service...");
start_service('pfb_filter');

// Create DNSBL service and link required executables
update_status(" done.\n\nCreating DNSBL service...");
pfb_dnsbl_service();
stop_service('pfb_dnsbl');
update_status(" done.\nRenew DNSBL lighttpd executable...");
unlink_if_exists('/usr/local/sbin/lighttpd_pfb');
link('/usr/local/sbin/lighttpd', '/usr/local/sbin/lighttpd_pfb');
update_status(" done.\n");

// Create DNSBL Lighttpd config file and DNSBL Certificate and restart DNSBL Service
if (!empty($pfb['dnsbl_port']) && !empty($pfb['dnsbl_port_ssl']) && ($pfb['dnsbl'] === PfbToggle::On)) {

	update_status("Creating DNSBL web server config ...");
	pfb_create_lighttpd();
	update_status(" done.\n");

	unlink_if_exists($pfb['dnsbl_cert']);
	update_status("Creating DNSBL Certificate...");
	pfb_create_dnsbl_cert();
	update_status(" done.\n");

	update_status("Starting DNSBL Service...");
	start_service('pfb_dnsbl');
	update_status(" done.\n\n");
}

// Replace 'default' DNSBL active blocked webpage
if (!file_exists('/usr/local/www/pfblockerng/www/dnsbl_active.php') ||
    pfb_dnsbl_webpage() == 'dnsbl_default.php') {
    @copy('/usr/local/www/pfblockerng/www/dnsbl_default.php', '/usr/local/www/pfblockerng/www/dnsbl_active.php');
}



// *** [ UPGRADE previous settings ] ***
update_status("Upgrading previous settings:\n");

// Relocate user-supplied list pre/post scripts into list_scripts/. The shipped
// AWS region scripts now install there; move any *_pre_*/*_post_* (.sh/.py) a
// previous version left at the package root, UNLESS a same-named file already
// exists in list_scripts/ (i.e. it is a shipped script pkg will clean up itself).
// Config stores only the basename, so the relocation needs no config change.
update_status(" Relocating custom list scripts to list_scripts/...");
$pfb_pkgdir  = '/usr/local/pkg/pfblockerng';
$pfb_listdir = "{$pfb_pkgdir}/list_scripts";
if (!is_dir($pfb_listdir)) {
	@mkdir($pfb_listdir, 0755, TRUE);
}
$pfb_moved = 0;
foreach (glob("{$pfb_pkgdir}/{ip,dnsbl}_{pre,post}_*.{sh,py}", GLOB_BRACE) ?: [] as $pfb_oldscript) {
	$pfb_dest = "{$pfb_listdir}/" . basename($pfb_oldscript);
	if (!file_exists($pfb_dest) && @rename($pfb_oldscript, $pfb_dest)) {
		@chmod($pfb_dest, 0755);
		$pfb_moved++;
	}
}
update_status(($pfb_moved > 0 ? " moved {$pfb_moved} ... done.\n" : " none ... done.\n"));

// issue #1250: BREAKING CHANGE -- relocate machine-owned match artifacts (ETMatch.txt,
// matchdedup_v4.txt, match<Header>_<fam>.txt) into matchgendir under their new pfB_Match_*
// names; a same-named user Match-list file is left in place. See pfb_matchdir_migrate_plan().
update_status(" Relocating machine-generated match artifacts...");
$pfb_matchgen_warn = array();
if (is_dir($pfb['matchdir'])) {
	// pfb_global() (above) already safe_mkdir()'d matchgendir at 0755 via folder_array, so
	// the perm-sync below runs unconditionally rather than gated on "did I just create it" --
	// it still ends up matching matchdir's LIVE mode/owner/group either way.
	if (!is_dir($pfb['matchgendir'])) {
		@mkdir($pfb['matchgendir'], 0755, TRUE);
	}
	$pfb_mg_mode = @fileperms($pfb['matchdir']);
	if ($pfb_mg_mode !== FALSE) {
		@chmod($pfb['matchgendir'], $pfb_mg_mode & 0777);
	}
	$pfb_mg_uid = @fileowner($pfb['matchdir']);
	if ($pfb_mg_uid !== FALSE) {
		@chown($pfb['matchgendir'], $pfb_mg_uid);
	}
	$pfb_mg_gid = @filegroup($pfb['matchdir']);
	if ($pfb_mg_gid !== FALSE) {
		@chgrp($pfb['matchgendir'], $pfb_mg_gid);
	}

	// Same config sections + header-build rule sync_package_pfblockerng() uses (header =
	// "{$row['header']}{$vtype}", \W-stripped, plus the custom/DNSBLIP/continent synthetic
	// names) -- install.inc runs standalone, before any sync pass populates $pfb['existing'].
	$pfb_continent_configs = array();
	foreach ($pfb['continents'] as $pfb_cont_name => $pfb_cont_alias) {
		$pfb_cont_key = 'pfblockerng' . strtolower(str_replace(' ', '', $pfb_cont_name));
		$pfb_continent_configs[$pfb_cont_alias] = config_get_path("installedpackages/{$pfb_cont_key}/config/0", []); // foreign key — out of ADR-29 gateway scope
	}
	$pfb_headers = pfb_matchdir_config_headers(
		array(
			'_v4' => config_get_path('installedpackages/pfblockernglistsv4/config', []), // foreign key — out of ADR-29 gateway scope
			'_v6' => config_get_path('installedpackages/pfblockernglistsv6/config', []), // foreign key — out of ADR-29 gateway scope
		),
		config_get_path('installedpackages/pfblockerngdnsblsettings/config/0', []), // foreign key — out of ADR-29 gateway scope
		$pfb_continent_configs
	);
	$pfb_deny_headers  = $pfb_headers['deny'];
	$pfb_match_headers = $pfb_headers['match'];
	$pfb_list_rows     = $pfb_headers['rows'];
	$pfb_rep_config = config_get_path('installedpackages/pfblockerngreputation/config/0', []); // section-level read (ccwhite is unregistered); issue #1896 registered the section's three Reputation toggles per-key, this whole-section read stays direct

	$pfb_matchdir_listing = array();
	foreach (glob("{$pfb['matchdir']}/*.txt") ?: [] as $pfb_f) {
		$pfb_matchdir_listing[] = basename($pfb_f);
	}
	$pfb_matchgendir_listing = array();
	foreach (glob("{$pfb['matchgendir']}/*.txt") ?: [] as $pfb_f) {
		$pfb_matchgendir_listing[] = basename($pfb_f);
	}

	$pfb_plan = pfb_matchdir_migrate_plan($pfb_matchdir_listing, $pfb_deny_headers, $pfb_match_headers,
		($pfb_rep_config['ccwhite'] ?? '') === 'match', $pfb_matchgendir_listing);

	// Warnings below are keyed on the renames that actually happened, never the plan --
	// a rename skipped by the live no-clobber guard leaves the old file valid (issue #1250).
	$pfb_moved_files = pfb_matchdir_apply_moves($pfb_plan['move'], $pfb['matchdir'], $pfb['matchgendir']);
	$pfb_moved_match = count($pfb_moved_files);

	$pfb_stale_refs = pfb_matchdir_stale_localfile_refs($pfb_list_rows, $pfb['matchdir'], $pfb_moved_files);

	if ($pfb_moved_match > 0 || !empty($pfb_plan['undecidable']) || !empty($pfb_stale_refs)) {
		$pfb_matchgen_warn[] = 'BREAKING CHANGE: machine-generated match artifacts moved from';
		$pfb_matchgen_warn[] = "  {$pfb['matchdir']}  to  {$pfb['matchgendir']}  (renamed to pfB_Match_*).";
		if (!empty($pfb_moved_files)) {
			$pfb_matchgen_warn[] = 'Moved: ' . implode(', ', $pfb_moved_files);
		}
		foreach ($pfb_plan['undecidable'] as $pfb_u) {
			$pfb_matchgen_warn[] = "AMBIGUOUS, left in place: {$pfb_u['file']} could belong to " . implode(' OR ', $pfb_u['candidates']) . ' -- rename one to disambiguate.';
		}
		foreach ($pfb_stale_refs as $pfb_r) {
			$pfb_matchgen_warn[] = "List \"{$pfb_r['list']}\" (header \"{$pfb_r['header']}\") Localfile still points at the OLD path {$pfb_r['url']} -- you must repoint it yourself.";
		}
	}
}
update_status(($pfb_moved_match ?? 0) > 0 ? " moved {$pfb_moved_match} ... done.\n" : " none ... done.\n");

if (!empty($pfb_matchgen_warn)) {
	$pfb_warn_text = implode("\n", $pfb_matchgen_warn);
	update_status("\n****************************************************************\n");
	update_status("*  BREAKING CHANGE -- pfBlockerNG match artifacts relocated!      *\n");
	update_status("****************************************************************\n");
	update_status("{$pfb_warn_text}\n\n");
	file_notice('pfBlockerNG Match', $pfb_warn_text, 'pfBlockerNG', '/pfblockerng/pfblockerng_ip.php', 2);
}

// ADR-12 update hooks live in their own dir (PFB_HOOK_SCRIPT_DIR = hooks/), separate
// from list_scripts/. No files ship there (hooks are admin-authored), so create the
// empty dir here for the picker to scan and admins to drop scripts into.
$pfb_hookdir = "{$pfb_pkgdir}/hooks";
if (!is_dir($pfb_hookdir)) {
	@mkdir($pfb_hookdir, 0755, TRUE);
}

// Remove discontinued pfBlockerNG CRON job
foreach (config_get_path('cron/item', []) as $key => $item) { // foreign key — out of ADR-29 gateway scope
	if (strpos($item['command'], 'pfblockerng.php dc >>') !== FALSE) {
		config_del_path("cron/item/{$key}"); // foreign key — out of ADR-29 gateway scope
	}
}

// Remove incorrect xml setting
PfbConfig::deleteSection('installedpackages/pfblockerngantartica');

// Upgrade Adv. Inbound settings to new variable names.
update_status(" Adv. Inbound firewall rule settings...");

$ufound = FALSE;
$upgrade_type = array('pfblockernglistsv4', 'pfblockernglistsv6', 'pfblockerngdnsblsettings', 'pfblockerngafrica', 'pfblockerngantarctica',
		    'pfblockerngasia', 'pfblockerngeurope', 'pfblockerngnorthamerica', 'pfblockerngoceania', 'pfblockerngsouthamerica',
		    'pfblockerngtopspammers', 'pfblockerngproxyandsatellite');

foreach ($upgrade_type as $type) {
	$pfb_type_config = PfbConfig::readSection("installedpackages/{$type}/config");

	// Skip absent sections entirely — readSection() returns [] for a missing
	// section, so is_array() is always true; use empty() to distinguish absent
	// from present (restores the pre-ADR-29 NULL → is_array(NULL)=false guard).
	if (empty($pfb_type_config)) {
		continue;
	}

	$pfb_type_items = $pfb_type_config;
	$type_ufound    = FALSE;

	// Remove any empty '<config></config>' XML tags.
	// Only unset index 0 when it actually exists and is empty.
	if (array_key_exists(0, $pfb_type_items) && empty($pfb_type_items[0])) {
		unset($pfb_type_items[0]);
		$type_ufound = TRUE;
	}

	foreach ($pfb_type_items as $key => $utype) {
		if (isset($utype['autoports'])) {
			$type_ufound = TRUE;
			if ($utype['autoports'] == 'on' && !empty($utype['aliasports']) && !isset($pfb_type_items[$key]['autoports_in'])) {
				$pfb_type_items[$key]['autoports_in']  = 'on';
				$pfb_type_items[$key]['aliasports_in'] = $utype['aliasports'];
			}
			unset($pfb_type_items[$key]['autoports'], $pfb_type_items[$key]['aliasports']);
		}
		if (isset($utype['autodest'])) {
			$type_ufound = TRUE;
			if ($utype['autodest'] == 'on' && !empty($utype['aliasdest']) && !isset($pfb_type_items[$key]['autoaddr_in'])) {
				$pfb_type_items[$key]['autoaddr_in']  = 'on';
				$pfb_type_items[$key]['aliasaddr_in'] = $utype['aliasdest'];
			}
			unset($pfb_type_items[$key]['autodest'], $pfb_type_items[$key]['aliasdest']);
		}
		if (isset($utype['autonot'])) {
			$type_ufound = TRUE;
			if ($utype['autonot'] == 'on' && !isset($pfb_type_items[$key]['autonot_in'])) {
				$pfb_type_items[$key]['autonot_in'] = $utype['autonot'];
			}
			unset($pfb_type_items[$key]['autonot']);
		}
		if (isset($utype['autoproto'])) {
			$type_ufound = TRUE;
			$pfb_type_items[$key]['autoproto_in'] = $utype['autoproto'];
			unset($pfb_type_items[$key]['autoproto']);
		}
	}
	if ($type_ufound) {
		// issue #1921: pre-pass legacy reshape -- raw write-back keeps bystander values
		// byte-identical for pfb_registry_pass()'s rename/grandfather decisions.
		PfbConfig::writeSectionRawSystem("installedpackages/{$type}/config", $pfb_type_items);
		$ufound = TRUE;
	}
}

if ($ufound) {
	update_status(" saving new changes ... done.\n");
} else {
	update_status(" no changes required ... done.\n");
}

// Upgrade OpenVPN and IPSec 'checkbox options' to pfBlockerNG In/Out interface selections
update_status(" OpenVPN/IPSec interface selections...");
$ufound = FALSE;
// INIT-GAP (#1497): only assigned inside the nested !empty($pfb['config'])
// block below, but read again (unconditionally, once $ufound) further down.
$u_msg = '';

$pfb_interfaces = PfbConfig::readSection('installedpackages/pfblockerng/config/0');
if (!empty($pfb_interfaces)) {
	if (!empty($pfb['config'])) {

		$u_msg = '[';

		// pfBlockerNG OpenVPN interface selection upgrade
		if (array_get_path($pfb_interfaces, 'openvpn_action', '') == 'on') {

			if (config_get_path('openvpn/openvpn-server') != null && // foreign key — out of ADR-29 gateway scope
			    strpos($pfb_interfaces['outbound_interface'], 'openvpn') === FALSE) {

				$csv_string = '';
				if (isset($pfb_interfaces['outbound_interface'])) {
					$csv_string = ',';
				}

				$pfb_interfaces['outbound_interface'] .= "{$csv_string}openvpn";
				$ufound = TRUE;
				$u_msg .= ' OpenVPN (Outbound) &';
			}

			if (config_get_path('openvpn/openvpn-client') != null) { // foreign key — out of ADR-29 gateway scope
				if (strpos($pfb_interfaces['outbound_interface'], 'openvpn') === FALSE && !$ufound) {
					$csv_string = '';
					if (isset($pfb_interfaces['outbound_interface'])) {
						$csv_string = ',';
					}
					$pfb_interfaces['outbound_interface'] .= "{$csv_string}openvpn";
					$ufound = TRUE;
					$u_msg .= ' OpenVPN (Outbound) &';
				}

				if (strpos($pfb_interfaces['inbound_interface'], 'openvpn') === FALSE) {
					$csv_string = '';
					if (isset($pfb_interfaces['inbound_interface'])) {
						$csv_string = ',';
					}
					$pfb_interfaces['inbound_interface'] .= "{$csv_string}openvpn";
					$ufound = TRUE;
					$u_msg .= ' OpenVPN (Inbound) &';
				}
			}
		}

		// pfBlockerNG IPSec interface selection upgrade
		if (isset($pfb['config']['ipsec_action']) &&
		    $pfb_interfaces['ipsec_action'] == 'on' &&
		    !empty(config_get_path('ipsec')) && // foreign key — out of ADR-29 gateway scope
		    strpos($pfb_interfaces['outbound_interface'], 'enc0') === FALSE) {

			$csv_string = '';
			if (isset($pfb_interfaces['outbound_interface'])) {
				$csv_string = ',';
			}
			$pfb_interfaces['outbound_interface'] .= "{$csv_string}enc0";
			$ufound = TRUE;
			$u_msg .= ' IPSec (Outbound)';
		}

		if (isset($pfb_interfaces['openvpn_action'])) {
			unset($pfb_interfaces['openvpn_action']);
		}
		if (isset($pfb_interfaces['ipsec_action'])) {
			unset($pfb_interfaces['ipsec_action']);
		}
		// issue #1921: pre-pass legacy reshape -- raw write-back keeps bystander values
		// byte-identical for pfb_registry_pass()'s rename/grandfather decisions.
		PfbConfig::writeSectionRawSystem('installedpackages/pfblockerng/config/0', $pfb_interfaces);
	}
}

if ($ufound) {
	$u_msg = rtrim($u_msg, '&');
	update_status(" saving new changes for {$u_msg} ] ... done.\n");
} else {
	update_status(" no changes required ... done.\n");
}

// Upgrade ET IQRisk categories
update_status(" Proofpoint/ET IQRisk settings...");
$ufound = FALSE;

$et_type = [];
$pfb_iqrisk = PfbConfig::readSection('installedpackages/pfblockerngreputation/config/0');
$pfb_iqrisk = empty($pfb_iqrisk) ? NULL : $pfb_iqrisk;
if (is_array($pfb_iqrisk)) {
	$et_type = array();
	foreach (array('etblock', 'etmatch') as $type) {
		if (isset($pfb_iqrisk[$type])) {

			$et_cat = explode(',', $pfb_iqrisk[$type]);
			foreach ($et_cat as $cat) {
				switch ($cat) {
					case 'ET_P2P':
						$cat = 'ET_P2Pnode';
						$ufound = TRUE;
						break;
					case 'ET_DDos':
						$cat = 'ET_DDostarget';
						$ufound = TRUE;
						break;
					case 'ET_DDosattack':
						$cat = 'ET_DDosattacker';
						$ufound = TRUE;
						break;
					case 'ET_Unknown':
						$ufound = TRUE;
						continue 2;
				}
				$et_type[$type][] = $cat;
			}
		}
	}
}

if ($ufound) {
	update_status(" saving new changes ... done.\n");
	foreach ($et_type as $type => $cats) {
		$pfb_iqrisk[$type] = implode(',', $cats);
	}
	// issue #1921: pre-pass legacy reshape -- raw write-back keeps bystander values
	// byte-identical for pfb_registry_pass()'s rename/grandfather decisions.
	PfbConfig::writeSectionRawSystem('installedpackages/pfblockerngreputation/config/0', $pfb_iqrisk);
} else {
	update_status(" no changes required ... done.\n");
}

// Move General Tab 'IP settings' to new IP tab
update_status(" General Tab -> IP Tab settings...");

$pfb_gen_section  = PfbConfig::readSection('installedpackages/pfblockerng/config/0');
$pfb_ip_section   = PfbConfig::readSection('installedpackages/pfblockerngipsettings/config/0');
// issue #1772: gate on the 14 source keys, not operator-view emptiness.
// pfb_schedule_migrate() (via pfb_install_settings_family_finalize, above)
// seeds schedule keys into General on a virgin box; those survive
// pfb_gconfig_operator_view() and must not count as pre-existing IP settings.
$settings = array(	'enable_dup', 'enable_agg', 'suppression', 'enable_log', 'maxmind_locale', 'database_cc',
			'inbound_interface', 'inbound_deny_action', 'outbound_interface', 'outbound_deny_action',
			'enable_float', 'pass_order', 'autorule_suffix', 'killstates' );
$has_migratable = FALSE;
foreach ($settings as $setting) {
	if (array_key_exists($setting, $pfb_gen_section)) {
		$has_migratable = TRUE;
		break;
	}
}
if ($has_migratable && empty($pfb_ip_section)) {

	$pfb['gconfig'] = $pfb_gen_section;
	$pfb['iconfig'] = $pfb_ip_section;

	foreach ($settings as $setting) {
		if (!array_key_exists($setting, $pfb['gconfig'])) {
			continue;
		}
		// issue #1772: copy only keys that exist so a stored '0' stays '0'
		// (the empty('0') falsiness class, issues #1787/#1792) and absent
		// keys are not planted as ''.
		$pfb['iconfig'][$setting] = $pfb['gconfig'][$setting];
		unset($pfb['gconfig'][$setting]);
	}
	// issue #1921: pre-pass legacy reshape -- raw write-back keeps bystander values
	// byte-identical for pfb_registry_pass()'s rename/grandfather decisions.
	PfbConfig::writeSectionRawSystem('installedpackages/pfblockerngipsettings/config/0', $pfb['iconfig']);
	PfbConfig::writeSectionRawSystem('installedpackages/pfblockerng/config/0', $pfb['gconfig']);
	// issue #2123: this branch fires only when the IP section was EMPTY, which is exactly
	// when the mode captured above reads NEWCFG -- and the pass's NEWCFG branch assigns
	// every registered key its default unconditionally, so it would erase the operator
	// values just migrated here (six of the fourteen are registered IP toggles). A section
	// that has received migrated operator data IS an existing install: correct the mode.
	$pfb_registry_modes[PFB_SECTIONS['ip']] = 'OLDCFG';
	update_status(" saving new changes ... done.\n");
}
else {
	update_status(" no changes required ... done.\n");
}

// Reverse DNS lookups (enable_rdns) default OFF for new installs; preserve the
// historical always-on behaviour for existing installs with a one-time seed.
update_status(" Reverse DNS lookup default...");
// issue #1775: pfb_gconfig_operator_view() strips the installer's settings_family
// marker so a marker-only section (General never saved -- genuine fresh install)
// reads empty here too, same chokepoint as the #1770/#1771 grandfathers above.
$pfb_rdns_seed = pfb_rdns_seed_value(
	pfb_gconfig_operator_view(PfbConfig::readSection('installedpackages/pfblockerng/config/0')),
	PfbConfig::readSection('installedpackages/pfblockerngipsettings/config/0')
);
if ($pfb_rdns_seed !== null) {
	// issue #2123: 'ip/enable_rdns' is a registered key now, so the seed goes through
	// the gateway's system writer (no web session here). A present key alone is NOT
	// enough to survive the pass -- its NEWCFG branch assigns the registered default
	// regardless -- so the mode correction below is what preserves this decision.
	PfbConfig::writeSystem('ip/enable_rdns', $pfb_rdns_seed);
	// issue #2123: same reason as the reshape above -- this seed exists to preserve the
	// historical always-on behaviour, and a captured NEWCFG (General configured, IP tab
	// never saved) would let the pass overwrite it with the registered ''.
	$pfb_registry_modes[PFB_SECTIONS['ip']] = 'OLDCFG';
	update_status(" saving new changes ... done.\n");
} else {
	update_status(" no changes required ... done.\n");
}

// Upgrade pfBlockerNGSuppress alias to IPv4 Suppression custom list
update_status(" pfBlockerNGSuppress Alias -> IPv4 Suppression Customlist...");
$ufound = FALSE;

$pfb_ip_cfg = PfbConfig::readSection('installedpackages/pfblockerngipsettings/config/0');
// ADR-53: v4suppression IS registered, but this needs the raw "key literally
// absent from config.xml" check (never-migrated) vs "present but empty" --
// a distinction PfbConfig::read()'s absent-default can't express -- so the
// section-level read/write stays correct here (allowed per PfbConfig rules).
if (!isset($pfb_ip_cfg['v4suppression'])) {
	$customlist = '';
	foreach (config_get_path('aliases/alias', []) as $key => $alias) { // foreign key — out of ADR-29 gateway scope
		if ($alias['name'] == 'pfBlockerNGSuppress') {

			$slist = array(explode(' ', $alias['address']), explode('||', $alias['detail']));
			array_multisort($slist[0], SORT_ASC, SORT_NUMERIC, $slist[1]);

			foreach ($slist as $key => $data) {
				if ($key == 0) {
					foreach ($data as $key2 => $line) {
						if (!empty(array_get_path($slist, "1/{$key2}"))) {
							$customlist .= "{$line} # " . array_get_path($slist, "1/{$key2}") . "\r\n";
						} else {
							$customlist .= "{$line}\r\n";
						}
					}
				}
			}
			// ADR-53: write via the same section array read above (a bulk migration
			// write alongside the rest of $pfb_ip_cfg, not a lone per-field save).
			// issue #1921: RAW write-back -- this import keys on pre-registry-pass
			// literal absence; canonicalising a bystander key here would destroy a
			// raw value the pass still needs to see.
			$pfb_ip_cfg['v4suppression'] = pfb_text_area_encode($customlist) ?: '';
			PfbConfig::writeSectionRawSystem('installedpackages/pfblockerngipsettings/config/0', $pfb_ip_cfg);
			// unset($config['aliases']['alias'][$key]);
			$ufound = TRUE;
			break;
		}
	}
}

if ($ufound) {
	update_status(" saving new changes ... done.\n");
} else {
	update_status(" no changes required ... done.\n");
}

// Convert dnsbl_info CSV file to SQLite3 database format
if (file_exists('/var/db/pfblockerng/dnsbl_info') &&
    !file_exists('/var/db/pfblockerng/dnsbl.sqlite') &&
    function_exists('pfb_open_sqlite')) {

	$db_handle = pfb_open_sqlite(1, 'Convert dnsbl_info');
	if ($db_handle) {

		$dnsbl_info = @file('/var/db/pfblockerng/dnsbl_info');
		if (!empty($dnsbl_info)) {
			foreach ($dnsbl_info as $group) {
				$group = str_getcsv($group, ',', '"', "\\");
				if (!str_starts_with($group[0], '#')) {
					$db_update = "INSERT INTO dnsbl ( groupname, timestamp, entries, counter )"
							. " VALUES ( :group0, :group1, :group2, :group3 );\n";

					$stmt = $db_handle->prepare($db_update);
					if ($stmt) {
						$stmt->bindValue(':group0', $group[0], SQLITE3_TEXT);
						$stmt->bindValue(':group1', $group[1], SQLITE3_TEXT);
						$stmt->bindValue(':group2', $group[2], SQLITE3_TEXT);
						$stmt->bindValue(':group3', $group[3], SQLITE3_INTEGER);
						$stmt->execute();
					}
				}
			}
		}
	}
	pfb_close_sqlite($db_handle);
}
unlink_if_exists('/var/db/pfblockerng/dnsbl_info');

// issue #1098: purge any leftover change-detect probe body ({header}.md5.raw) so a
// pre-#1072 corrupted one is never reused verbatim by the next sync ingest.
pfb_install_probe_cleanup();

// Move dnsbl_levent.sqlite -> /var/unbound folder
$ufound = FALSE;
if (file_exists('/var/db/pfblockerng/dnsbl_levent.sqlite') && !file_exists($pfb['dnsbl_resolver'])) {
	$ufound = TRUE;
	@copy('/var/db/pfblockerng/dnsbl_levent.sqlite', $pfb['dnsbl_resolver']);
	@chown($pfb['dnsbl_resolver'], 'unbound');
	@chgrp($pfb['dnsbl_resolver'], 'unbound');
}
unlink_if_exists('/var/db/pfblockerng/dnsbl_levent.sqlite');

// Move dnsbl.sqlite -> /var/unbound folder
if (file_exists('/var/db/pfblockerng/dnsbl.sqlite') && !file_exists($pfb['dnsbl_info'])) {
	$ufound = TRUE;
	@copy('/var/db/pfblockerng/dnsbl.sqlite', $pfb['dnsbl_info']);
	@chown($pfb['dnsbl_info'], 'unbound');
	@chgrp($pfb['dnsbl_info'], 'unbound');
}
unlink_if_exists('/var/db/pfblockerng/dnsbl.sqlite');

/* Update unbound python files. #468: the shipped-file list lives ONLY in
 * 'pfblockerng.sh dnsbl_cache stage' (single source of truth); it also mkdirs the
 * chroot + nullfs mount-point dirs, so a fresh RAM-disk /var (e.g. after an upgrade
 * with RAM Disks enabled) can't make the copy fail. */
exec('/usr/local/pkg/pfblockerng/pfblockerng.sh dnsbl_cache stage >/dev/null 2>&1');

if ($ufound) {
	$final = pfb_stop_start_unbound('');
	// issue #3094: the return value used to be assigned and never read, so an install
	// could finish "successfully" with the resolver never restarted.
	if (($final['retval'] ?? 0) != 0) {
		update_status(" Unbound Resolver did not restart; see the pfBlockerNG log.");
	}
}

// Upgrade EasyList to new Format
update_status(" Upgrading previous EasyLists to new format...");
$ufound = FALSE;
$pfb_general_schedule = PfbConfig::readSection('installedpackages/pfblockerng/config/0');

if (!empty(PfbConfig::readSection('installedpackages/pfblockerngdnsbleasylist'))) {

	// Collect all enabled EasyLists
	$enabled	= array();
	$ex_easylists	= PfbConfig::readSection('installedpackages/pfblockerngdnsbleasylist/config/0');

	foreach (array_get_path($ex_easylists, 'row', []) as $easylist) {
		if ($easylist['state'] == 'Enabled') {
				$enabled[$easylist['header']] = '';
		}
	}

	// Load all pfBlockerNG Feeds
	if (!empty($enabled)) {
		$feed_info_raw = json_decode(@file_get_contents("{$pfb['feeds']}"), TRUE);
		if (json_last_error() === JSON_ERROR_NONE && is_array($feed_info_raw)) {

			$add			= array();
			$add['aliasname']	= $ex_easylists['aliasname']	?: 'EasyList';
			$add['description']	= $ex_easylists['description']	?: '';
			$add['row']		= array();

			foreach ($feed_info_raw['dnsbl']['EasyList'] as $easylists) {
				if (is_array($easylists)) {
					foreach ($easylists as $easylist) {
						if (isset($enabled[$easylist['header']])) {
							$add['row'][] = array(	'format'	=> 'auto',
										'state'		=> 'Enabled',
										'url'		=> $easylist['url'],
										'header'	=> $easylist['header']);
							$ufound = TRUE;
						}
					}
				}
			}
		}
	}

	if ($ufound) {
		$add['action']	= $ex_easylists['action'];
		$add['cron']	= $ex_easylists['cron'];
		$pfb_easylist_weekday = pfb_schedule_numeric_token($ex_easylists['dow'] ?? NULL, 1, 7);
		$add['schedule_override'] = ($add['cron'] === 'Weekly' && $pfb_easylist_weekday !== NULL) ? 'on' : '';
		$add['schedule_weekday'] = $pfb_easylist_weekday
			?? pfb_schedule_numeric_token($pfb_general_schedule['pfb_schedule_weekday'] ?? NULL, 1, 7) ?? '7';
		$add['schedule_hour'] = pfb_schedule_numeric_token($pfb_general_schedule['pfb_schedule_hour'] ?? NULL, 0, 23) ?? '0';
		$add['schedule_minute'] = pfb_schedule_minute_token($pfb_general_schedule['pfb_schedule_minute'] ?? NULL) ?? '0';
		$add['logging']	= $ex_easylists['logging'];
		$add['order']	= $ex_easylists['order'];

		$dnsblcfg   = PfbConfig::readSection('installedpackages/pfblockerngdnsbl/config');
		$dnsblcfg[] = $add;
		// issue #1921: pre-pass legacy reshape -- raw write-back keeps bystander values
		// byte-identical for pfb_registry_pass()'s rename/grandfather decisions.
		PfbConfig::writeSectionRawSystem('installedpackages/pfblockerngdnsbl/config', $dnsblcfg);
	}

	// Remove Previous EasyList configuration
	PfbConfig::deleteSection('installedpackages/pfblockerngdnsbleasylist');
}

if ($ufound) {
	update_status(" saving new changes ... done.\n");
} else {
	update_status(" no changes required ... done.\n");
}

// Firefox Doh settings to new DoH settings
update_status(" Upgrading previous Firefox DoH to new format...");
$ufound = FALSE;

$doh_config = PfbConfig::readSection('installedpackages/pfblockerngsafesearch');
if (!empty($doh_config)) {
	if (isset($doh_config['safesearch_firefoxdoh'])) {
		$ufound = TRUE;

		$doh_config['safesearch_doh'] = $doh_config['safesearch_firefoxdoh'];
		if ($doh_config['safesearch_firefoxdoh'] == 'Enable') {
			$doh_config['safesearch_doh_list'] = 'use-application-dns.net';
		}
		unset($doh_config['safesearch_firefoxdoh']);
		// issue #1921: pre-pass legacy reshape -- raw write-back keeps bystander values
		// byte-identical for pfb_registry_pass()'s rename/grandfather decisions.
		PfbConfig::writeSectionRawSystem('installedpackages/pfblockerngsafesearch', $doh_config);
	}
}

if ($ufound) {
	update_status(" saving new changes ... done.\n");
} else {
	update_status(" no changes required ... done.\n");
}

// #740: migrate the legacy 'yandex.dns' DoH-list token (malformed conf entry that never
// matched real traffic) to the corrected 'dns.yandex' substring key.
update_status(" Migrating legacy Yandex DoH token...");
$ufound = FALSE;

$doh_list_migrated = pfb_ss_doh_list_yandex_migrate(PfbConfig::read('ss/safesearch_doh_list'));
if ($doh_list_migrated !== NULL) {
	$ufound = TRUE;
	PfbConfig::writeSystem('ss/safesearch_doh_list', $doh_list_migrated);
}

if ($ufound) {
	update_status(" saving new changes ... done.\n");
} else {
	update_status(" no changes required ... done.\n");
}

// Move MaxMind Key to new configuration location
update_status(" MaxMind License Key configuration setting...");
$ufound = FALSE;

$pfb_maxmind_gen = PfbConfig::readSection('installedpackages/pfblockerng/config/0');
$pfb_maxmind_ip  = PfbConfig::readSection('installedpackages/pfblockerngipsettings/config/0');
// maxmind_key is unregistered; absence is checked via section read
if (!empty($pfb_maxmind_gen) && !isset($pfb_maxmind_ip['maxmind_key'])) {
	$maxmind_config = $pfb_maxmind_gen;
	foreach (array('maxmind_key', 'maxmind_locale', 'database_cc') as $m_setting) {
		if (isset($maxmind_config[$m_setting])) {
			$ufound = TRUE;
			$pfb_maxmind_ip[$m_setting] = $maxmind_config[$m_setting];
			unset($maxmind_config[$m_setting]);
		}
	}
	if ($ufound) {
		// issue #1921: pre-pass legacy reshape -- raw write-back keeps bystander values
		// byte-identical for pfb_registry_pass()'s rename/grandfather decisions.
		PfbConfig::writeSectionRawSystem('installedpackages/pfblockerngipsettings/config/0', $pfb_maxmind_ip);
		PfbConfig::writeSectionRawSystem('installedpackages/pfblockerng/config/0', $maxmind_config);
	}
}

if ($ufound) {
	update_status(" saving new changes ... done.\n");
} else {
	update_status(" no changes required ... done.\n");
}

// Validate widget pfBlockerNG clear [ dnsbl/IP ] counter CRON jobs
update_status(" Validating Widget cron settings...");
$ufound = FALSE;

// widget-clearip / widget-cleardnsbl are unregistered keys in pfblockerngglobal; read via section.
$pfb_global_cfg = PfbConfig::readSection('installedpackages/pfblockerngglobal');
foreach (array('clearip', 'cleardnsbl') as $type) {
	$pfb_widget_val = $pfb_global_cfg["widget-{$type}"] ?? NULL;
	if ($pfb_widget_val !== NULL) {

		// Remove incorrect cron entries
		$pfb_cmd_esc = "/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php '{$type}' >/dev/null 2>&1";
		if (pfblockerng_cron_exists($pfb_cmd_esc, '0', '0', '*', '*')) {
			$ufound = TRUE;
			install_cron_job("pfblockerng.php '{$type}'", FALSE);
		}
		if (pfblockerng_cron_exists($pfb_cmd_esc, '0', '0', '*', '7')) {
			$ufound = TRUE;
			install_cron_job("pfblockerng.php '{$type}'", FALSE);
		}

		// Add correct cron entry, if enabled
		if ($pfb_widget_val != 'never') {

			$pfb_day = '*';
			if ($pfb_widget_val == 'weekly') {
				$pfb_day = '7';
			}

			$pfb_cmd = "/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php {$type} >/dev/null 2>&1";
			if (!pfblockerng_cron_exists($pfb_cmd, '0', '0', '*', $pfb_day)) {
				$ufound = TRUE;
				install_cron_job($pfb_cmd, TRUE, '0', '0', '*', '*', $pfb_day, 'root');
			}
		}
	}
}

if ($ufound) {
	update_status(" saving new changes ... done.\n");
} else {
	update_status(" no changes required ... done.\n");
}

// issue #1921: the ONE registry-driven pass -- rename, grandfather-map, and seed, in
// that branch order per key -- over every PFB_SECTIONS section. This MUST stay after
// pfb_run_migrations() (whose write-back is deliberately RAW) AND after the ADR-53
// v4suppression import above, which keys on literal pre-pass absence and must observe
// pre-pass state. Rides the trailing write_config() below rather than adding a flush of
// its own. Adapter canonicalisation on the pass's OUTPUT -- unlike the migration
// driver's raw write-back -- is correct and deliberate here: it is what coalesces a
// renamed key's legacy token (e.g. top1m_source 'alexa' -> 'tranco') to its canonical
// stored form.
update_status("Recording default settings...");
$pfb_registry_sections = array();
foreach (PFB_SECTIONS as $pfb_registry_section) {
	$pfb_registry_sections[$pfb_registry_section] = PfbConfig::readSection($pfb_registry_section);
}
pfb_install_registry_writeback($pfb_registry_sections, $pfb_registry_modes);
unset($pfb_registry_sections, $pfb_registry_section, $pfb_registry_modes);
update_status(" done.\n");

// issue #2371: apply the fresh-install feed-at-suffix PSL policy seed captured at the
// top of this file, now that the registry pass has already persisted its own (unrelated)
// '' defaults for these two fields -- see pfb_psl_feed_policy_is_fresh_install()'s and
// pfb_install_psl_feed_policy_seed()'s docblocks (pfblockerng.inc) for why this runs
// AFTER pfb_install_registry_writeback() rather than as a pfb_migration_registry() entry.
pfb_install_psl_feed_policy_seed($pfb_psl_feed_policy_fresh_install);
unset($pfb_psl_feed_policy_fresh_install);

// issue #2675: correct this box's repo conf now rather than at the next boot, for a box
// whose hook is already installed. An upgrade from a pre-signing conf (plain
// signature_type: none over HTTPS, which pkg cannot fetch on Plus during a system
// upgrade) is the moment the trusted fingerprint and the signed-repo conf land.
update_status("Refreshing the pkg repository configuration...");
pfb_repo_conf_regenerate();
update_status(" done.\n");

unset($g['pfblockerng_install']);	// Remove 'Install flag'
update_status("Upgrading... done\n\nCustom commands completed ... ");

return TRUE;

?>

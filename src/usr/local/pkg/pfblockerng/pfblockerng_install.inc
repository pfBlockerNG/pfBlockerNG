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
require_once('/usr/local/www/pfblockerng/pfblockerng.php');

global $g, $pfb;
pfb_global();

// Set 'Install flag' to skip sync process during installations.
$g['pfblockerng_install'] = TRUE;

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

	PfbConfig::writeSection('installedpackages/pfblockerngdnsblsettings/config/0', $pfb_dnsbl_config);
	write_config('Migrated old pfBlockerNG VIP configuraiton');
	pfb_global();
}

// ADR-29 P2: run all registered upgrade migrations in order. Each migration's apply()
// callable reads the section, returns the updated array or NULL (no-op), and the driver
// writes back and calls write_config() only when a change is needed. Replaces the four
// hand-wired blocks (ADR-02, PFBL-03, ADR-22, issue #281) with a single ordered registry.
pfb_run_migrations();

// MaxMind Database is no longer pre-installed during package installation
if (empty($pfb['maxmind_key'])) {
	update_status("\nMaxMind GeoIP databases are not pre-installed during installation.\nTo utilize the MaxMind GeoIP functionalities, you will be required to register for a free MaxMind user account and access key. Review the IP tab: MaxMind Settings for more details.\n\n");
}
else {
	// Update any PHP changes to GeoIP Tabs
	update_status("\nRebuilding GeoIP tabs...");
	pfblockerng_get_countries();
	update_status(" done.");
}

// Create Reputation tab
if (!file_exists('/usr/local/www/pfblockerng/pfblockerng_reputation.php') || empty($pfb['maxmind_key'])) {
	update_status("\nRebuild Reputation tab...");
	pfb_build_reputation_tab();
	update_status(" done.");
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
unlink_if_exists("{$pfb['dnsbl_cache']}");

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
if (!empty($pfb['dnsbl_port']) && !empty($pfb['dnsbl_port_ssl']) && ($pfb['dnsbl'] == 'on')) {

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
    PfbConfig::read('dnsblwebpage') == 'dnsbl_default.php') {
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
		PfbConfig::writeSection("installedpackages/{$type}/config", $pfb_type_items);
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
		PfbConfig::writeSection('installedpackages/pfblockerng/config/0', $pfb_interfaces);
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
	PfbConfig::writeSection('installedpackages/pfblockerngreputation/config/0', $pfb_iqrisk);
} else {
	update_status(" no changes required ... done.\n");
}

// Move General Tab 'IP settings' to new IP tab
update_status(" General Tab -> IP Tab settings...");

$pfb_gen_section  = PfbConfig::readSection('installedpackages/pfblockerng/config/0');
$pfb_ip_section   = PfbConfig::readSection('installedpackages/pfblockerngipsettings/config/0');
if (!empty($pfb_gen_section) && empty($pfb_ip_section)) {

	$pfb['gconfig'] = $pfb_gen_section;
	$pfb['iconfig'] = $pfb_ip_section;

	$settings = array(	'enable_dup', 'enable_agg', 'suppression', 'enable_log', 'maxmind_locale', 'database_cc',
				'inbound_interface', 'inbound_deny_action', 'outbound_interface', 'outbound_deny_action',
				'enable_float', 'pass_order', 'autorule_suffix', 'killstates' );

	foreach ($settings as $setting) {
		$pfb['iconfig'][$setting] = $pfb['gconfig'][$setting] ?: '';
		if (isset($pfb['gconfig'][$setting])) {
			unset($pfb['gconfig'][$setting]);
		}
	}
	PfbConfig::writeSection('installedpackages/pfblockerngipsettings/config/0', $pfb['iconfig']);
	PfbConfig::writeSection('installedpackages/pfblockerng/config/0', $pfb['gconfig']);
	update_status(" saving new changes ... done.\n");
}
else {
	update_status(" no changes required ... done.\n");
}

// Reverse DNS lookups (enable_rdns) default OFF for new installs; preserve the
// historical always-on behaviour for existing installs with a one-time seed.
update_status(" Reverse DNS lookup default...");
$pfb_rdns_seed = pfb_rdns_seed_value(
	config_get_path('installedpackages/pfblockerng/config/0', []),
	config_get_path('installedpackages/pfblockerngipsettings/config/0', [])
);
if ($pfb_rdns_seed !== null) {
	config_set_path('installedpackages/pfblockerngipsettings/config/0/enable_rdns', $pfb_rdns_seed);
	update_status(" saving new changes ... done.\n");
} else {
	update_status(" no changes required ... done.\n");
}

// Upgrade pfBlockerNGSuppress alias to IPv4 Suppression custom list
update_status(" pfBlockerNGSuppress Alias -> IPv4 Suppression Customlist...");
$ufound = FALSE;

$pfb_ip_cfg = PfbConfig::readSection('installedpackages/pfblockerngipsettings/config/0');
if (!isset($pfb_ip_cfg['v4suppression'])) { // v4suppression is unregistered — check via section read
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
			// v4suppression is unregistered; write via section to stay within the gateway surface.
			$pfb_ip_cfg['v4suppression'] = base64_encode($customlist) ?: '';
			PfbConfig::writeSection('installedpackages/pfblockerngipsettings/config/0', $pfb_ip_cfg);
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

// Feed-host filter defaults ON for new installs; pin OFF once on an already-configured
// install so existing feeds are never silently dropped (operator can re-enable). The
// run-once decision is pfb_feed_filter_install_default() (NULL => leave unset => default
// ON); the !isset guard there makes this idempotent across repeated installs/upgrades.
$pfb_gcfg = PfbConfig::readSection('installedpackages/pfblockerng/config/0');
$pfb_gcfg = empty($pfb_gcfg) ? NULL : $pfb_gcfg;
$pfb_feed_default = pfb_feed_filter_install_default($pfb_gcfg);
if ($pfb_feed_default !== null) {
	PfbConfig::write('pfb_feed_internal_filter', $pfb_feed_default);
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
				if (substr($group[0], 0, 1) != '#') {
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

// Move dnsbl_levent.sqlite -> /var/unbound folder
$u_found = FALSE;
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

/* Update unbound python files.
 * The target directory may not exist yet e.g. after an upgrade with
 * RAM Disks enabled; defer the file copy to pfb_unbound_dnsbl(). */
if (is_dir(g_get('unbound_chroot_path'))) {
	@copy("/usr/local/pkg/pfblockerng/pfb_unbound.py", "{$g['unbound_chroot_path']}/pfb_unbound.py");
	@copy("/usr/local/pkg/pfblockerng/pfb_unbound_include.inc", "{$g['unbound_chroot_path']}/pfb_unbound_include.inc");
	@copy("/usr/local/pkg/pfblockerng/pfb_py_hsts.txt", "{$g['unbound_chroot_path']}/pfb_py_hsts.txt");
}

if ($ufound) {
	$final = pfb_stop_start_unbound('');
}

// Upgrade EasyList to new Format
update_status(" Upgrading previous EasyLists to new format...");
$ufound = FALSE;

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
		$add['dow']	= $ex_easylists['dow'];
		$add['logging']	= $ex_easylists['logging'];
		$add['order']	= $ex_easylists['order'];

		$dnsblcfg   = PfbConfig::readSection('installedpackages/pfblockerngdnsbl/config');
		$dnsblcfg[] = $add;
		PfbConfig::writeSection('installedpackages/pfblockerngdnsbl/config', $dnsblcfg);
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
		PfbConfig::writeSection('installedpackages/pfblockerngsafesearch', $doh_config);
	}
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
		PfbConfig::writeSection('installedpackages/pfblockerngipsettings/config/0', $pfb_maxmind_ip);
		PfbConfig::writeSection('installedpackages/pfblockerng/config/0', $maxmind_config);
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

unset($g['pfblockerng_install']);	// Remove 'Install flag'
update_status("Upgrading... done\n\nCustom commands completed ... ");

// ADR-38 §2.1: Ensure the Unbound chroot log socket directory exists before
// (re)starting syslogd.  syslogd uses the <logging><logsocket> element
// (/var/unbound/var/run/log) to bind an extra unix socket reachable inside the
// Unbound chroot.  The directory must exist and be owned by unbound BEFORE
// system_syslogd_start() is called, because syslogd will try to create the
// socket there.  safe_mkdir() is a no-op when the directory already exists
// (idempotent); @chown() likewise silently succeeds or no-ops on re-install.
safe_mkdir('/var/unbound/var/run');
@chown('/var/unbound/var/run', 'unbound');
system_syslogd_start(TRUE);

write_config('[pfBlockerNG] Save installation settings');
return TRUE;

?>

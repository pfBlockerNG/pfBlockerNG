<?php
/*
 * pfblockerng_wizard.inc
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2004-2026 Rubicon Communications, LLC (Netgate)
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

require_once('config.inc');
require_once('util.inc');
require_once('services.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');
pfb_global();

global $pfb_wizard;

$pfb_wizard['interface_list']		= pfb_build_if_list(TRUE, FALSE);
$pfb_wizard['interface_list_cnt']	= count($pfb_wizard['interface_list']) ?: '1';

// Persist the 'Do not show this again' choice ('disable' only; 'skip' is
// session-only) so the setup wizard never auto-launches again. Stored outside
// config/0 so a fresh, unconfigured install still reads as unconfigured
// (config/0 == null) for the upgrade-migration paths in pfblockerng_install.inc.
// Called only from pfb_wizard_skip_check(), inside the wizard's csrf-magic-
// validated POST — the ?wizard= GET on pfblockerng_general.php must never
// write config (issue #1651: csrf-magic validates POSTs only, so a
// state-changing GET is CSRF-forgeable).
function pfb_wizard_persist_disable(?string $action): void {
	if ($action !== 'disable') {
		return;
	}
	config_del_path('pfblockerng_wizard');
	// foreign key — out of ADR-29 gateway scope (pfb_wizard_skip is not a /config/0 scalar)
	config_set_path('installedpackages/pfblockerng/pfb_wizard_skip', 'on');
	write_config('[pfBlockerNG] Disable setup wizard auto-launch');
}

// Exit the wizard when the 'Skip' button is pressed on any step. If the
// 'Do not show this again' checkbox is ticked, persist the choice HERE — in
// the csrf-magic-validated POST — so the wizard never auto-launches again
// ('disable'); otherwise skip for this session only ('skip'). The redirect is
// a plain GET and stays state-free (issue #1651); pfblockerng_general.php
// only reads ?wizard= to suppress the auto-launch for that request.
function pfb_wizard_skip_check() {
	$action = pfb_wizard_skip_action($_POST ?: array());
	if ($action === null) {
		return;
	}

	pfb_wizard_persist_disable($action);

	header("Location: /pfblockerng/pfblockerng_general.php?wizard={$action}");
	exit;
}

function step2_stepbeforeformdisplay() {
	global $pkg, $stepid, $pfb_wizard;

	// foreign section: pfblockerng_wizard is a wizard temp section, not in registry
	config_del_path('pfblockerng_wizard');

	$fields	= &$pkg['step'][2]['fields']['field'];

	for ($key = 0; $key < 2; $key++) {
		$fields[$key]['options']['option'] = array();
		foreach ($pfb_wizard['interface_list'] as $value => $name) {
			$fields[$key]['options']['option'][]	= array('name' => $name, 'value' => $value);
			$fields[$key]['size']			= $pfb_wizard['interface_list_cnt'];
		}
	}
}

function step2_submitphpaction() {
	global $stepid, $input_errors, $pfb_wizard;

	pfb_wizard_skip_check();

	if ($_POST) {
		if ($_POST['back'] == 'Back') {
			$stepid = 0;
			return;
		}

		foreach (array($_POST['inbound_interface'], $_POST['outbound_interface']) as $wizard_interface) {
			if (empty($wizard_interface)) {
				$input_errors[] = 'pfBlockerNG IP Category configuration | Atleast one Inbound and one Outbound interfaces must be selected.';
			}
			if (is_array($wizard_interface)) {
				foreach ($wizard_interface as $w_interface) {
					if (!array_key_exists($w_interface, $pfb_wizard['interface_list'])) {
						$input_errors[] = 'pfBlockerNG IP Category configuration | Invalid Interface selection';
					}
				}
			}
			elseif (!array_key_exists($wizard_interface, $pfb_wizard['interface_list'])) {
				$input_errors[] = 'pfBlockerNG IP Category configuration | Invalid Interface selection';
			}
		}

		if ($input_errors) {
			step2_stepbeforeformdisplay(); // Reload interface options
			$stepid = 1;
			return;
		}
	}

	// foreign section: pfblockerng_wizard is a wizard temp section, not in registry
	config_set_path('pfblockerng_wizard/step2/inbound_interface', implode(',', (array)$_POST['inbound_interface']));
	// foreign section: pfblockerng_wizard is a wizard temp section, not in registry
	config_set_path('pfblockerng_wizard/step2/outbound_interface', implode(',', (array)$_POST['outbound_interface']));
}

// issue #3539: the DNSBL rows the wizard installs for one catalog group -- feeds that need
// registration and discontinued feeds are left out.
function pfb_wizard_group_rows(array $info): array {
	$rows = array();
	foreach (($info['feeds'] ?? array()) as $row) {
		if (isset($row['register']) || (isset($row['status']) && $row['status'] == 'discontinued')) {
			continue;
		}
		$rows[] = array('format' => 'auto', 'state' => 'Enabled', 'url' => $row['url'], 'header' => $row['header']);
	}
	return $rows;
}

// issue #3539: the DNSBL settings section the wizard writes (slice order is config order). The wizard sets up a fresh
// install, so it stores the fresh-install policy; its ADs_Basic group follows it and never answers with the VIP. A blank
// port stores its default, as a DNSBL page save does, so a later VIP mechanism finds usable ports.
function pfb_wizard_dnsbl_section(bool $auto, $vip4, $vip6, $port, $port_ssl): array {
	$registry = pfb_cfg_registry();
	return pfb_wizard_dnsvip_settings($auto, $vip4, $vip6)
		+ array('pfb_dnsport' => $port ?: $registry['dnsbl/pfb_dnsport']['default'],
			'pfb_dnsport_ssl' => $port_ssl ?: $registry['dnsbl/pfb_dnsport_ssl']['default'], 'pfb_dnsbl' => 'on',
			'global_log_mode' => $registry['dnsbl/global_log_mode']['default'], 'global_log' => $registry['dnsbl/global_log']['default']);
}

// The ADs_Basic group step 4 writes.
function pfb_wizard_dnsbl_group(array $info): array {
	$group = array('aliasname' => 'ADs_Basic', 'description' => $info['description'] ?? '');
	$rows = pfb_wizard_group_rows($info);
	if (!empty($rows)) {
		$group['row'] = $rows;
	}
	return $group + array('action' => 'unbound', 'cron' => 'EveryDay', 'logging' => 'default', 'order' => 'default');
}

function step3_submitphpaction() {
	global $stepid, $input_errors;

	pfb_wizard_skip_check();

	if ($_POST) {
		if ($_POST['back'] == 'Back') {
			$stepid = 0;
			return;
		}
	}

	// The manual VIP selects' sentinel is never stored as a VIP id (manual mode only; Auto VIP disables them).
	$pfb_auto = (isset($_POST['pfb_dnsvip_auto']) && $_POST['pfb_dnsvip_auto'] == 'on');
	if (!$pfb_auto) {
		if ($_POST['pfb_dnsvip4'] == 'none') {
			$_POST['pfb_dnsvip4'] = '';
		}
		if ($_POST['pfb_dnsvip6'] == 'none') {
			$_POST['pfb_dnsvip6'] = '';
		}
	}

	// issue #3539: the setup the wizard writes answers no block with the VIP, so it needs no VIP and no ports; a port given
	// must still be valid.
	foreach (array($_POST['pfb_dnsport'] ?? '', $_POST['pfb_dnsport_ssl'] ?? '') as $pfb_port) {
		if ($pfb_port !== '' && !is_port($pfb_port)) {
			$input_errors[] = 'DNSBL Ports: A valid port must be defined.';
			break;
		}
	}

	if ($input_errors) {
		$stepid = 2;
	}
}

function step4_submitphpaction() {
	global $pfb, $input_errors, $stepid;
	// wizard.php increments $stepid after this action: a refusal sets 3, so the Finalize step (4) is re-rendered.

	pfb_wizard_skip_check();

	// Load all pfBlockerNG Feeds
	$feed_info_raw = json_decode(@file_get_contents("{$pfb['feeds']}"), TRUE);
	if (json_last_error() !== JSON_ERROR_NONE || !is_array($feed_info_raw)) {
		$input_errors[] = 'pfBlockerNG: Feeds database missing. Cannot continue - Reinstall package.';
		$stepid = 3;
		return;
	}

	$pfb_general_schedule = PfbConfig::readSection('installedpackages/pfblockerng/config/0');

	// issue #3515: the Resolver snapshot lives in the package config swept below; put the Resolver back first.
	// The return value is FALSE both for "nothing to restore" and for an abandoned restore: a snapshot or our block that
	// survived the call says the Resolver is still moved, and the sweep would delete what the next attempt needs. A stored
	// marker that is no snapshot (recovery required, no ownership) is kept the same way: it is the only record of what the
	// Resolver was, and the sweep would erase it. All of it is read from config.xml under the lock: this request's copy can
	// predate a takeover, and a config.xml that cannot be read to check counts as still moved. issue #3558: the lock is kept
	// through the reset's write, so a pfB-DNS enable another save makes meanwhile waits for it instead of being overwritten.
	pfb_dns_proxy_resolver(FALSE);
	$lock = pfb_dns_config_lock();
	$checked = ($lock !== NULL);
	if (!$checked || pfb_dns_proxy_owns_resolver() || pfb_dns_proxy_recovery_required()) {
		unlock($lock);
		if (pfb_dns_proxy_owns_resolver() || !pfb_dns_proxy_recovery_required()) {
			$input_errors[] = 'DNS proxy: the DNS Resolver could not be put back, so pfBlockerNG was not reset. Follow the DNS proxy notice, then run the wizard again.';
		} elseif (!$checked) {
			// The marker comes from a copy that config.xml was not read to check: it is not known to be invalid
			$input_errors[] = 'DNS proxy: config.xml was locked by another save or could not be read, so pfBlockerNG\'s saved copy of the DNS Resolver\'s ' .
			    'previous settings (pfb_dns_saved) could not be confirmed and pfBlockerNG was not reset. Run the wizard again once no other ' .
			    'configuration save is in progress.';
		} else {
			$input_errors[] = 'DNS proxy: pfBlockerNG\'s saved copy of the DNS Resolver\'s previous settings (pfb_dns_saved) is invalid, so what the Resolver was before ' .
			    'cannot be confirmed and pfBlockerNG was not reset. Check the Resolver in Services > DNS Resolver (restore a known-good configuration ' .
			    'backup if needed), empty pfb_dns_saved in the pfblockerngdns section of config.xml only after that check, then run the wizard again.';
		}
		$stepid = 3;
		return;
	}

	// Remove any pfBlockerNG settings (file/folder contents go once the lock is released)
	pfb_remove_config_settings();

	// Add default pfBlockerNG configuration
	// foreign structure: bulk wizard init reads the whole installedpackages blob for re-write; not routed per-key
	$new_config = config_get_path('installedpackages');
	$new_config['pfblockerng']['config'][0]['enable_cb']				= 'on';
	$new_config['pfblockerng']['config'][0]['pfb_keep']				= 'on';
	$new_config['pfblockerng']['config'][0]['pfb_scheduled_feed_updates']	= pfb_cfg_toggle_write(pfb_cfg_toggle_read($pfb_general_schedule['pfb_scheduled_feed_updates'] ?? 'on'));
	$new_config['pfblockerng']['config'][0]['pfb_schedule_weekday']		= pfb_schedule_numeric_token($pfb_general_schedule['pfb_schedule_weekday'] ?? NULL, 1, 7) ?? '7';
	$new_config['pfblockerng']['config'][0]['pfb_schedule_hour']		= pfb_schedule_numeric_token($pfb_general_schedule['pfb_schedule_hour'] ?? NULL, 0, 23) ?? '0';
	$new_config['pfblockerng']['config'][0]['pfb_schedule_minute']		= pfb_schedule_minute_token($pfb_general_schedule['pfb_schedule_minute'] ?? NULL) ?? '0';
	$new_config['pfblockerng']['config'][0]['skipfeed']				= pfb_schedule_numeric_token($pfb_general_schedule['skipfeed'] ?? NULL, 0, 6) ?? '3';

	$new_config['pfblockerngipsettings']['config'][0]['enable_dup']			= 'on';
	$new_config['pfblockerngipsettings']['config'][0]['suppression']		= 'on';
	$new_config['pfblockerngipsettings']['config'][0]['inbound_interface']		= config_get_path('pfblockerng_wizard/step2/inbound_interface');
	$new_config['pfblockerngipsettings']['config'][0]['inbound_deny_action']	= 'block';
	$new_config['pfblockerngipsettings']['config'][0]['outbound_interface']		= config_get_path('pfblockerng_wizard/step2/outbound_interface'); 
	$new_config['pfblockerngipsettings']['config'][0]['outbound_deny_action']	= 'reject';	
	$new_config['pfblockerngipsettings']['config'][0]['pass_order']			= 'order_0';
	$new_config['pfblockerngipsettings']['config'][0]['autorule_suffix']		= 'autorule';	// the registry fresh-install default, written so the upgrade grandfather pass cannot flip it
	$new_config['pfblockerngipsettings']['config'][0]['suppression_cidr']		= '8';	// the fresh-install limits (issue #3413): the wizard rebuilds this section after the installer seeded them
	$new_config['pfblockerngipsettings']['config'][0]['suppression_cidr_v6']	= '32';

	// foreign section: pfblockerng_wizard/step3/* are wizard temp keys, not in registry
	$dnsbl_section = pfb_wizard_dnsbl_section(
		(pfb_cfg_toggle_read(config_get_path('pfblockerng_wizard/step3/pfb_dnsvip_auto')) === PfbToggle::On),
		config_get_path('pfblockerng_wizard/step3/pfb_dnsvip4'),
		config_get_path('pfblockerng_wizard/step3/pfb_dnsvip6'),
		config_get_path('pfblockerng_wizard/step3/pfb_dnsport'),
		config_get_path('pfblockerng_wizard/step3/pfb_dnsport_ssl')
	);
	foreach ($dnsbl_section as $pfb_dnsbl_key => $pfb_dnsbl_val) {
		$new_config['pfblockerngdnsblsettings']['config'][0][$pfb_dnsbl_key] = $pfb_dnsbl_val;
	}

	// Default DNSBL Whitelist
	// foreign section: pfblockerng_wizard/step3/suppression is a wizard temp key, not in registry
	if (pfb_cfg_toggle_read(config_get_path('pfblockerng_wizard/step3/suppression')) === PfbToggle::On) {

		$new_config['pfblockerngdnsblsettings']['config'][0]['whitelist']	=

"czMuYW1hem9uYXdzLmNvbQ0KczMtMS5hbWF6b25hd3MuY29tICMgQ05BTUUgZm9yIChzMy5hbWF6
b25hd3MuY29tKQ0KLmdpdGh1Yi5jb20NCi5naXRodWJ1c2VyY29udGVudC5jb20gDQpnaXRodWIu
bWFwLmZhc3RseS5uZXQgIyBDTkFNRSBmb3IgKHJhdy5naXRodWJ1c2VyY29udGVudC5jb20pDQou
Z2l0bGFiLmNvbQ0KLnNvdXJjZWZvcmdlLm5ldA0KLmZscy1uYS5hbWF6b24uY29tICMgYWxleGEN
Ci5jb250cm9sLmtvY2hhdmEuY29tICMgYWxleGEgMg0KLmRldmljZS1tZXRyaWNzLXVzLTIuYW1h
em9uLmNvbSAjIGFsZXhhIDMNCi5hbWF6b24tYWRzeXN0ZW0uY29tICMgYW1hem9uIGFwcCBhZHMN
Ci5weC5tb2F0YWRzLmNvbSAjIGFtYXpvbiBhcHAgMg0KLndpbGRjYXJkLm1vYXRhZHMuY29tLmVk
Z2VrZXkubmV0ICMgQ05BTUUgZm9yIChweC5tb2F0YWRzLmNvbSkNCi5lMTMxMzYuZy5ha2FtYWll
ZGdlLm5ldCAjIENOQU1FIGZvciAocHgubW9hdGFkcy5jb20pDQouc2VjdXJlLWdsLmltcndvcmxk
d2lkZS5jb20gIyBhbWF6b24gYXBwIDMNCi5waXhlbC5hZHNhZmVwcm90ZWN0ZWQuY29tICMgYW1h
em9uIGFwcCA0DQouYW55Y2FzdC5waXhlbC5hZHNhZmVwcm90ZWN0ZWQuY29tICMgQ05BTUUgZm9y
IChwaXhlbC5hZHNhZmVwcm90ZWN0ZWQuY29tKQ0KLmJzLnNlcnZpbmctc3lzLmNvbSAjIGFtYXpv
biBhcHAgNQ0KLmJzLmV5ZWJsYXN0ZXIuYWthZG5zLm5ldCAjIENOQU1FIGZvciAoYnMuc2Vydmlu
Zy1zeXMuY29tKQ0KLmJzbGEuZXllYmxhc3Rlci5ha2FkbnMubmV0ICMgQ05BTUUgZm9yIChicy5z
ZXJ2aW5nLXN5cy5jb20pDQouYWRzYWZlcHJvdGVjdGVkLmNvbSAjIGFtYXpvbiBhcHAgNg0KLmFu
eWNhc3Quc3RhdGljLmFkc2FmZXByb3RlY3RlZC5jb20gIyBDTkFNRSBmb3IgKHN0YXRpYy5hZHNh
ZmVwcm90ZWN0ZWQuY29tKQ0KZ29vZ2xlLmNvbQ0Kd3d3Lmdvb2dsZS5jb20NCnlvdXR1YmUuY29t
DQp3d3cueW91dHViZS5jb20NCnlvdXR1YmUtdWkubC5nb29nbGUuY29tICMgQ05BTUUgZm9yICh5
b3V0dWJlLmNvbSkNCnN0YWNrb3ZlcmZsb3cuY29tDQp3d3cuc3RhY2tvdmVyZmxvdy5jb20NCmRy
b3Bib3guY29tDQp3d3cuZHJvcGJveC5jb20NCnd3dy5kcm9wYm94LWRucy5jb20gIyBDTkFNRSBm
b3IgKGRyb3Bib3guY29tKQ0KLmFkc2FmZXByb3RlY3RlZC5jb20NCmNvbnRyb2wua29jaGF2YS5j
b20NCnNlY3VyZS1nbC5pbXJ3b3JsZHdpZGUuY29tDQpwYnMudHdpbWcuY29tICMgdHdpdHRlciBp
bWFnZXMNCnd3dy5wYnMudHdpbWcuY29tICMgdHdpdHRlciBpbWFnZXMNCmNzMTk2LndhYy5lZGdl
Y2FzdGNkbi5uZXQgIyBDTkFNRSBmb3IgKHBicy50d2ltZy5jb20pDQpjczItd2FjLmFwci04MzE1
LmVkZ2VjYXN0ZG5zLm5ldCAjIENOQU1FIGZvciAocGJzLnR3aW1nLmNvbSkNCmNzMi13YWMtdXMu
ODMxNS5lY2Rucy5uZXQgIyBDTkFNRSBmb3IgKHBicy50d2ltZy5jb20pDQpjczQ1LndhYy5lZGdl
Y2FzdGNkbi5uZXQgIyBDTkFNRSBmb3IgKHBicy50d2ltZy5jb20pDQpjczItd2FjLmFwci04MzE1
LmVkZ2VjYXN0ZG5zLm5ldCAjIENOQU1FIGZvciAocGJzLnR3aW1nLmNvbSkNCmNzMi13YWMtdXMu
ODMxNS5lY2Rucy5uZXQgIyBDTkFNRSBmb3IgKHBicy50d2ltZy5jb20pDQpjczQ1LndhYy5lZGdl
Y2FzdGNkbi5uZXQgIyBDTkFNRSBmb3IgKHBicy50d2ltZy5jb20pDQoucGZzZW5zZS5vcmcNCi5u
ZXRnYXRlLmNvbQ0K
";
	}

	// Selected Alias/Groups to add to default installation
	$new = array();
	$new['pfblockernglistsv4']		= $new['pfblockerngdnsbl'] = array();
	$new['pfblockernglistsv4']['PRI1']	= $feed_info_raw['ipv4']['PRI1'];
	$new['pfblockerngdnsbl']['ADs_Basic']	= $feed_info_raw['dnsbl']['ADs_Basic'];

	foreach ($new as $key => $data) {
		foreach ($data as $alias => $info) {

			if (strpos($key, 'dnsbl') !== FALSE) {
				$add = pfb_wizard_dnsbl_group($info);
			} else {
				$add			= array();
				$add['aliasname']	= $alias;
				$add['description']	= $info['description'];
				$rows = pfb_wizard_group_rows($info);
				if (!empty($rows)) {
					$add['row'] = $rows;
				}
				$add['action']		= 'Deny_Outbound';
				$add['cron']		= '01hour';
				$add['aliaslog']	= 'enabled';
			}
			$add['schedule_override']	= '';
			$add['schedule_weekday']	= pfb_schedule_numeric_token($pfb_general_schedule['pfb_schedule_weekday'] ?? NULL, 1, 7) ?? '7';
			$add['schedule_hour']		= pfb_schedule_numeric_token($pfb_general_schedule['pfb_schedule_hour'] ?? NULL, 0, 23) ?? '0';
			$add['schedule_minute']		= pfb_schedule_minute_token($pfb_general_schedule['pfb_schedule_minute'] ?? NULL) ?? '0';
			$new_config[$key]['config'][] = $add;
		}
	}

	// foreign structure: bulk wizard init writes the whole installedpackages blob; not routed per-key
	config_set_path('installedpackages', $new_config);
	// foreign section: pfblockerng_wizard is a wizard temp section, not in registry
	config_del_path('pfblockerng_wizard');

	try {
		write_config('pfBlockerNG: Default Wizard configuration saved');
	} finally {
		unlock($lock);
	}
	pfb_clear_contents();
	pfb_global();

	// Restart Unbound - Code from services_unbound.php 'apply'
	pfb_unbound_dnsbl('disabled');
	$retval = services_unbound_configure();
	if ($retval == 0) {
		clear_subsystem_dirty('unbound');
	}
	system_resolvconf_generate();   // Update resolv.conf
	system_dhcpleases_configure();  // Start or restart dhcpleases

	// Load Update page to download IP/DNSBL Feeds and finish the installation
	header("Location: /pfblockerng/pfblockerng_update.php?wizard=reload");
	exit;
}
?>

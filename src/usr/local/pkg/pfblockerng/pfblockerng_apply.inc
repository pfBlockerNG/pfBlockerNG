<?php
/*
 * pfblockerng_apply.inc
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

// Parsed-failure log is skipped for these names: hosts-file boilerplate and HTML scraps, not feed content.
const PFB_DNSBL_SKIP_NAMES = [
	'broadcasthost' => TRUE, 'local' => TRUE, 'localhost' => TRUE, '<pre>' => TRUE, 'Vault' => TRUE, 'Site' => TRUE,
	'list' => TRUE, '::1' => TRUE, ':' => TRUE, 'ip6-localhost' => TRUE, 'ip6-localnet' => TRUE,
	'ip6-mcastprefix' => TRUE, 'ip6-allnodes' => TRUE, 'ip6-allrouters' => TRUE, 'ip6-allhosts' => TRUE,
];

// Alienvault OTX indicator types that name a domain.
const PFB_DNSBL_OTX_TYPES = ['domain' => TRUE, 'hostname' => TRUE, 'URL' => TRUE];

// pfb_dnsbl_parse_line() result for a line that writes no row and does not end the feed.
const PFB_DNSBL_LINE_NO_ROW = ['row' => NULL, 'stop' => FALSE];

/** Keep the reload and ADR-12 post-hook change signal on one predicate. */
function pfb_dnsbl_reload_needed(bool $publish_failed, bool $data_changed, bool $update, bool $python,
    bool $safesearch_update, bool $unlock_forced): bool {
	return !$publish_failed && ($data_changed || $update || $python || $safesearch_update || $unlock_forced);
}

/** Remove the transient staged path and known cleanup path after a list-script pass. */
function pfb_list_script_cleanup_staged(string $parse_path, ?string $staged_path,
    ?string $known_path = NULL): void {
	if ($staged_path !== NULL && $parse_path === $staged_path) {
		unlink_if_exists($staged_path);
	}
	if ($known_path !== NULL) {
		unlink_if_exists($known_path);
	}
}

/** Consume a staged pre-script path, then remove transient and known copies. */
function pfb_list_script_consume_staged(string $parse_path, ?string $staged_path, callable $consumer,
    ?string $known_path = NULL): mixed {
	try {
		return $consumer($parse_path);
	} finally {
		pfb_list_script_cleanup_staged($parse_path, $staged_path, $known_path);
	}
}

function pfb_dnsbl_script_consume_staged(string $parse_path, ?string $staged_path, callable $consumer,
    ?string $known_path = NULL): mixed {
	return pfb_list_script_consume_staged($parse_path, $staged_path, $consumer, $known_path);
}

/*
 * Detached fire-and-forget firewall-configuration reload (owner directive
 * 2026-09-05). pfSense's reload is not ours to bound or kill; the script loads
 * the ruleset synchronously under pfSense's filter lock, but the launch is
 * detached, so the rules can land after the pass returns. Output is discarded so
 * the child holds no capture pipe; the only owned failure is the launch itself.
 */
function pfb_filter_reload_exec(): int {
	global $pfb;

	$script = $pfb['filter_configure_sync'] ?? '/etc/rc.filter_configure_sync';
	if (!is_file($script) || !is_executable($script)) {
		pfb_logger("\nFirewall configuration reload script missing or not executable [ {$script} ]\n", 2);
		return -1;
	}

	$discard = array();
	$retval  = 0;
	if (exec(escapeshellarg($script) . ' > /dev/null 2>&1 < /dev/null &', $discard, $retval) === FALSE && $retval === 0) {
		// exec() itself failed to launch (fork/pipe).
		$retval = -1;
	}
	return ($retval === 0) ? 0 : -1;
}

/**
 * The apply's entry, under the held feed-pass lock; sets $pfb_sync_absorb. FALSE when the DNS configuration lock is
 * unavailable: the changes are then already marked pending and each lock whose owner flag is TRUE already released,
 * so the caller returns at once and must not release those locks again.
 */
function pfb_apply_enter(bool $pfb_feed_pass_owner, bool $pfb_dispatch_owner, ?bool &$pfb_sync_absorb): bool {
	// issue #3674: a pass that starts suppressed applies a received policy; its own writes into synced sections stay unsent.
	$pfb_sync_absorb = pfb_sync_receive_suppressed();

	if (PfbConfig::read('gen/pfb_dns_listen_vip') === PfbToggle::On
	    || PfbConfig::read('gen/pfb_dns_listen_added') !== ''
	    || PfbConfig::read('gen/pfb_dns_listen_auto4') !== ''
	    || PfbConfig::read('gen/pfb_dns_listen_auto6') !== '') {
		$pfb_listen_lock = pfb_dns_config_lock();
		if ($pfb_listen_lock === NULL) {
			pfb_logger("\n sync aborted: DNS configuration lock unavailable; pending changes retained.\n", 1);
			pfb_mark_pending_changes();
			if ($pfb_feed_pass_owner) {
				pfb_feed_pass_release();
			}
			if ($pfb_dispatch_owner) {
				pfb_schedule_dispatch_release();
			}
			return FALSE;
		}
		try {
			if (!pfb_dns_listen_vips_apply()) {
				pfb_mark_pending_changes();
				pfb_logger("\n DNS listener advertisements could not be written.\n", 2);
			}
		} finally {
			unlock($pfb_listen_lock);
		}
	}

	// issue #3288: opportunistically bring a legacy/still-fresh DNSBL policy
	// state up to date under the held feed-pass lock, before this pass
	// resolves any group's effective mechanism -- refresh pfb_global() only
	// when something actually changed, so its cached policy fields never lag
	// behind config.xml.
	if (pfb_dnsbl_policy_upgrade()) {
		pfb_global();
	}

	return TRUE;
}

/**
 * The apply's settings: the RAM-disk registrations, the table entries limit, the rule options and the DNSBL and Reputation
 * settings into $pfb, the rule tracker ids, the auto rule suffix and the rule interfaces. Shared by the update pass and the
 * version 2 apply. Returns the pass's locals it sets up (the run's log redirection, its empty alias accumulators and the
 * group and continent family maps).
 *
 * @return array{elog:string,new_aliases:array,new_aliases_list:array,pfb_alias_lists:array,pfb_alias_lists_all:array,ip_types:array<string,string>,cont_types:array<string,string>}
 */
function pfb_apply_settings(): array {
	global $pfb;

	// Call function for Ramdisk processes.
	pfb_aliastables('conf');

	// #468: keep the DNSBL RAM-disk restore earlyshellcmd in sync with DNSBL state
	// (registered iff DNSBL enabled AND use_mfs_tmpvar; removed + archive deleted else).
	pfb_dnsbl_cache('conf');

	// If table limit not defined, set default to 2M
	if (empty(config_get_path('system/maximumtableentries'))) {
		config_set_path('system/maximumtableentries', '2000000');
		write_config('pfBlockerNG: save max Firewall table entries limit', FALSE);
	}
	$pfb['table_limit'] = config_get_path('system/maximumtableentries');

	// Collect local web gui configuration
	$pfb['weblocal'] = config_get_path('system/webgui/protocol', 'http');
	$pfb['port'] = config_get_path('system/webgui/port');
	if (empty($pfb['port'])) {
		if (config_get_path('system/webgui/protocol') == 'http') {
			$pfb['port'] = '80';
		} else {
			$pfb['port'] = '443';
		}
	}
	$pfb['weblocal'] .= "://127.0.0.1:{$pfb['port']}/pfblockerng/pfblockerng.php";

	// Define Inbound/Outbound action is not user selected.
	$pfb['deny_action_inbound']  = PfbConfig::read('ip/inbound_deny_action');
	$pfb['deny_action_outbound'] = PfbConfig::read('ip/outbound_deny_action');

	$pfb['float']		= PfbConfig::read('ip/enable_float');				// Enable/Disable floating autorules
	$pfb['fw_self']		= PfbConfig::read('ip/fw_self_outbound');			// Also apply outbound autorules to the firewall's own traffic
	$pfb['dup']		= PfbConfig::read('ip/enable_dup');				// Enable remove of duplicate IPs utilizing grepcidr
	$pfb['agg']		= PfbConfig::read('ip/enable_agg');				// Enable aggregation of CIDRs
	$pfb['order']		= PfbConfig::read('ip/pass_order');				// Order of the autorules (registry default order_0, matching the IP-settings UI; an empty value drops user pass-rules on a managed interface — issue #532)
	$pfb['global_log']	= PfbConfig::read('ip/enable_log');				// Enable Global IP logging
	$pfb['suffix']		= PfbConfig::read('ip/autorule_suffix');			// Suffix used for autorules
	$pfb['kstates'] 	= PfbConfig::read('ip/killstates');				// Firewall states removal

	$pfb['ip_ph']		= pfb_filter(PfbConfig::read('ip/ip_placeholder'), PFB_FILTER_IPV4, 'Placeholder IP Address', '127.1.7.7');	// Placeholder IP Address
	// issue #3140/#3144: pfblockerng.sh init prefers the PHP-exported values; its shell
	// config.xml fallbacks remain for boot and hand-run invocations.
	putenv("PFB_IP_PLACEHOLDER={$pfb['ip_ph']}"); putenv('PFB_REENTRY_TIMEOUT=' . pfb_reentry_budget(NULL));
	putenv('PFB_USE_MFS_TMPVAR=' . (config_path_enabled('system', 'use_mfs_tmpvar') ? '1' : '0'));

	// DNSBL settings
	$pfb['dnsbl_ip']	= pfb_dnsblip_action_value($pfb['dnsblconfig']['action'] ?? NULL);	// Enable/Disable IP blocking from DNSBL lists
	$pfb['dnsbl_top1m_cnt']	= $pfb['dnsblconfig']['top1m_count']	?: '1000';		// TOP1M whitelist domain setting
	$pfb['dnsbl_top1m_inc']	= $pfb['dnsblconfig']['top1m_inclusion']?: '';			// TOP1M TLDs inclusions for whitelisting
	pfb_dnsbl_ini_inputs();	// the module's ini inputs, derived by the same loader the removal's recovery uses

	// Validate pfB Script variable
	$pfb['dnsbl_top1m_inc'] = pfb_filter($pfb['dnsbl_top1m_inc'], PFB_FILTER_CSV, 'Validate pfB Script variable');

	// Reputation config variables
	$pfb['config_rep'] = config_get_path('installedpackages/pfblockerngreputation/config/0', []);

	// Validate pfB Script variables
	foreach (array(
			'et_update'		=> 'etupdate',					// Force an update of ET categories
			'ccwhite'		=> 'ccwhite',					// Action for whitelist Country category
			'ccblack'		=> 'ccblack',					// Action for blacklist Country category
			'etblock'		=> 'etblock',					// Emerging Threats IQRisk block categories
			'etmatch'		=> 'etmatch',					// Emerging Threats IQRisk match categories
			'p24_max_var'		=> 'max',					// 'Max' variable setting for Reputation
			'p24_dmax_var'		=> 'dmax',					// 'dMax' variable setting for Reputation
			'p24_pmax_var'		=> 'pmax',					// 'pMax' variable setting for Reputation
			'ccexclude'		=> 'ccexclude'					// List of Countries to whitelist
		) as $conf_value => $pfb_value) {

		$pfb_variable = $pfb['config_rep'][$conf_value] ?: 'x';
		if (empty(pfb_filter($pfb_variable, PFB_FILTER_CSV, 'Validate pfB Script variables'))) {
			$pfb[$pfb_value] = 'x';
		} else {
			$pfb[$pfb_value] = $pfb_variable;
		}
	}

	// issue #1896: registered toggle mirrors -- typed PfbToggle via the gateway, not the
	// loop's raw-string-or-'x' shape above (that placeholder exists for the numeric/CSV
	// fields' shell-arg positional integrity; a toggle already has a well-formed enum for
	// every input, so it never needs it).
	$pfb['rep']	= PfbConfig::read('rep/enable_rep');	// Enable/Disable 'Max' Reputation
	$pfb['prep']	= PfbConfig::read('rep/enable_pdup');	// Enable/Disable 'pRep' Reputation
	$pfb['drep']	= PfbConfig::read('rep/enable_dedup');	// Enable/Disable 'dRep' Reputation

	// Starting variable to skip Reputation functions, if no changes are required
	$pfb['repcheck'] = FALSE;
	// issue #1840: unconditional, like $pfb['repcheck'] just above -- the alias-configure
	// loop's suppression-body calls (pfb_ip_suppress_body_active(), v4 site further down,
	// v6 sibling right after it) read this on EVERY pass reachable via
	// `if (!empty($lists) && $pfb['enable'] === PfbToggle::On)`, which has no '!save' guard. A
	// POST-INSTALL/GUI resync (custom_php_resync_config_command sets $pfb['save'] = TRUE
	// before calling this function) still reaches that loop, so this must be seeded here
	// -- not only inside the `!$pfb['save']` download block below, which a save=TRUE pass
	// never enters -- or the key stays undefined (NULL) and TypeErrors the strictly-typed
	// bool parameter.
	$pfb['supp_update'] = FALSE;
	// $pfb['save'] is used to determine if user pressed "save" button to avoid collision with CRON.

	// For 'script' calls using exec() (used to shorten length of line)
	$elog = ">> {$pfb['log']} 2>&1";


	#################################
	#	Configure ARRAYS	#
	#################################

	$new_aliases		= array();		// An array of aliases (full details)
	$new_aliases_list	= array();		// An array of alias names
	$pfb_alias_lists	= array();		// An array of aliases whose lists were updated during this pass. ('Reputation' disabled)
	$pfb_alias_lists_all	= array();		// An array of all active aliases. ('Reputation' enabled)

	$ip_types		= array( 'pfblockernglistsv4' => '_v4', 'pfblockernglistsv6' => '_v6');
	$cont_types		= array( 'countries4' => '_v4', 'countries6' => '_v6');

	#################################
	#	Tracker IDs		#
	#################################

	$pfb['trackerids']	    = array();					// An array of pfBlockerNG Firewall rule Tracker IDs.
	$pfb['last_trackerid']	= 1700000009;				// Pre-defined 'starting' Tracker ID (Only used if duplicates found)
	$pfb['foreign_trackerids'] = pfb_collect_foreign_trackers();	// Tracker IDs already in use by non-pfB rules.


	#########################################
	#	Configure Rule Suffix		#
	#########################################

	// Discover if any rules are autorules (If no autorules found, $pfb['autorules'] is FALSE, skip rules re-order )
	// To configure auto rule suffix. pfBlockerNG must be disabled to change suffix and to avoid duplicate rules
	$pfb['autorules'] = FALSE;
	$action = array('Deny_Both', 'Deny_Inbound', 'Deny_Outbound', 'Match_Both', 'Match_Inbound',
			'Match_Outbound', 'Permit_Both', 'Permit_Inbound', 'Permit_Outbound');

	foreach ($pfb['continents'] as $continent => $pfb_alias) {
		$cont_key = 'pfblockerng' . strtolower(str_replace(' ', '', $continent));
		if (!empty(config_get_path("installedpackages/{$cont_key}/config"))) {
			$continent_config = config_get_path("installedpackages/{$cont_key}/config/0");
			if (!pfb_group_action_valid($continent_config['action'] ?? NULL, 'geoip')) {
				continue;
			}
			if ($continent_config['action'] != 'Disabled' && in_array($continent_config['action'], $action)) {
				$pfb['autorules'] = TRUE;
				break;
			}
		}
	}

	if (!$pfb['autorules']) {
		foreach ($ip_types as $ip_type => $vtype) {
			foreach(config_get_path("installedpackages/{$ip_type}/config", []) as $list) {
				if (!pfb_group_action_valid($list['action'] ?? NULL, 'ipv4')) {
					continue;
				}
				if ($list['action'] != 'Disabled' && in_array($list['action'], $action)) {
					$pfb['autorules'] = TRUE;
					break;
				}
			}
		}
	}

	// Check if DNSBL 'Auto Deny' rules for DNSBL IPs are defined
	if (strpos($pfb['dnsbl_ip'], 'Deny_') !== FALSE) {
		$pfb['autorules'] = TRUE;
	}

	// Configure auto rule suffix.
	$pfb_filter_rules = config_get_path('filter/rule', []);
	foreach ($pfb_filter_rules as $rule) {

		// Query for previous IPv4 pfBlockerNG 'alias type' aliasnames which are not in the new '_v4' suffix format
		foreach (array('source', 'destination') as $rtype) {
			if (pfb_rule_alias_needs_v4_suffix($rule[$rtype]['address'] ?? '', $rule['ipprotocol'] ?? '')) {
				$pfb['autorules'] = TRUE;	// Set flag to re-configure Firewall rules and add missing '_v4' suffix
			}
		}
	}

	// Collect any pre-existing suffix from an already-deployed pfB_ rule
	// (issue #713 — 'found' must reflect a real match, not stay permanently FALSE).
	$pfb_autorule_suffix = pfb_collect_autorule_suffix($pfb_filter_rules);
	$pfbfound = $pfb_autorule_suffix['found'];
	$pfb_suffix_match = $pfb_autorule_suffix['suffix'];

	// Change suffix only if no pfB rules found and autorules are enabled.
	if ($pfb['autorules'] && !$pfbfound) {
		switch ($pfb['suffix']) {
			case 'autorule':
				$pfb['suffix'] = ' auto rule';
				break;
			case 'standard':
				$pfb['suffix'] = '';
				break;
			case 'ar':
				$pfb['suffix'] = ' AR';
				break;
		}
	} else {
		$pfb['suffix'] = '';
		if ($pfb['autorules']) {
			$pfb['suffix'] = $pfb_suffix_match;	// Use existing suffix match
		}
	}


	#########################################################
	#	Configure INBOUND/OUTBOUND INTERFACES		#
	#########################################################

	// Collect pfSense interface order
	$ifaces = pfb_build_if_list(TRUE, FALSE);

	$pfb['base_rule'] = array();	// no inbound or outbound interface selected: the auto rules start from no base rule
	foreach (array('inbound', 'outbound') as $type) {
		$pfb["{$type}_interfaces"] = $pfb["{$type}_floating"] = array();

		$configured = PfbConfig::read("ip/{$type}_interface");
		if (!empty($configured)) {
			$interfaces = explode(',', $configured);

			// CSV string for 'pfB_' match rules
			$pfb["{$type}_floating"]		= ltrim(implode(',', $interfaces), ',');

			// Assign base rule/interfaces
			if ($pfb['float'] === PfbToggle::On) {
				$pfb['base_rule']		= $pfb['base_rule_float'];
				$pfb["{$type}_interfaces"]	= explode(' ', $pfb["{$type}_floating"]);
			} else {
				$pfb['base_rule']		= $pfb['base_rule_reg'];
				$pfb["{$type}_interfaces"]	= $interfaces;
			}
		}
	}

	return compact('elog', 'new_aliases', 'new_aliases_list', 'pfb_alias_lists', 'pfb_alias_lists_all', 'ip_types', 'cont_types');
}

/**
 * ADR-38 Amendment 1: register the package's syslog routing (the <logging> block a `pkg add` install does not copy) and
 * materialize its syslog.d drop-in when it is missing.
 */
function pfb_syslog_logging_register(): void {
	// ADR-38 Amendment 1: ensure the dedicated syslog routing is materialized.
	// pfSense core turns a package's installedpackages/package/<n>/logging block into
	// the syslog.d drop-in (!pfblockerng -> /var/log/pfblockerng_syslog.log), the
	// newsyslog rotation entry, and the Status->System Logs->Packages subtab. But the
	// `pkg add` install path does NOT copy the package XML's <logging> block into that
	// section (only a GUI install does), so register it here, keyed on the
	// configurationfile (channel-independent: pfBlockerNG vs pfBlockerNG-devel).
	$pfb_pkg_logged = FALSE;
	$pfb_log_want = pfb_syslog_logging_want();
	foreach (config_get_path('installedpackages/package', array()) as $pfb_idx => $pfb_pkg) {
		if (($pfb_pkg['configurationfile'] ?? '') !== 'pfblockerng.xml') {
			continue;
		}
		// Write the canonical block when it is missing OR carries STALE values — not only
		// when empty. An upgrade from an older config can leave a row with a wrong
		// facility/filename, a missing 'logtab' (the pre-241302e block, which makes the
		// Packages subtab read "pfBlockerNG-devel"), or a leftover <logsocket> (which would
		// make core regenerate the now-removed in-chroot socket). Replacing the whole block
		// on any mismatch fixes the label and drops the stale logsocket; an already-canonical
		// row is left untouched.
		if (pfb_syslog_logging_needs_update($pfb_pkg['logging'] ?? array(), $pfb_log_want)) {
			config_set_path("installedpackages/package/{$pfb_idx}/logging", $pfb_log_want);
			write_config('[pfBlockerNG] register syslog routing');
		}
		$pfb_pkg_logged = TRUE;
		break;
	}

	// Materialize/refresh the routing when the drop-in is missing — covers a fresh
	// registration AND the #484 lifecycle gap (core runs system_syslogd_start only at
	// install/resync, so a CLI reload / uninstall->redeploy could lose the drop-in).
	// Graceful HUP, not a restart. Emission stays gated live by the log_syslog toggle.
	if ($pfb_pkg_logged && !file_exists('/var/etc/syslog.d/pfblockerng_syslog.log.conf')) {
		require_once('syslog.inc');
		system_syslogd_start(TRUE);
	}
}

/**
 * The boot branch (#3977): Outpost work with no Update, under the apply lock. It retires what an older version left (the
 * block-page web server, a legacy received-policy record) and registers the syslog routing; it fetches, parses and applies
 * nothing, since the Core Updater's first Update applies the lists.
 */
function pfb_outpost_boot(): bool {
	global $pfb;
	pfb_global();
	$dispatch_owner = !isset($GLOBALS['pfb_schedule_dispatch_lock']) || !is_resource($GLOBALS['pfb_schedule_dispatch_lock']);
	$owner = !isset($GLOBALS['pfb_feed_pass_lock']);
	$contended = FALSE;
	if (!pfb_schedule_dispatch_begin(0.1, $contended)) {
		pfb_logger("\n Boot: the scheduler dispatcher lock is unavailable; nothing was done.\n", 1);
		return FALSE;
	}
	if (!pfb_feed_pass_begin('sync', $contended)) {
		if ($dispatch_owner) {
			pfb_schedule_dispatch_release();
		}
		pfb_logger("\n Boot: the apply lock is unavailable; nothing was done.\n", 1);
		return FALSE;
	}
	$absorb = FALSE;
	if (!pfb_apply_enter($owner, $dispatch_owner, $absorb)) {
		return FALSE;	// pfb_apply_enter() released the locks it owned
	}
	try {
		pfb_syslog_logging_register();
		pfb_dnsbl_webserver_retire();	// issue #4053: the block-page web server, NAT and auto-VIP an older version left
		if ($absorb) {
			pfb_sync_receive_legacy_absorb($pfb['dbdir']);
		}
		pfb_logger("\nSync terminated during boot process.\nUPDATE PROCESS ENDED\n", 1);
		logger(LOG_INFO, localize_text('Sync terminated during boot process.'), LOG_PREFIX_PKG_PFBLOCKERNG);
		return TRUE;
	} finally {
		if ($owner) {
			pfb_feed_pass_release();
		}
		if ($dispatch_owner) {
			pfb_schedule_dispatch_release();
		}
	}
}

/**
 * The uninstall disable pass (#3977): Outpost apply code with no Update, under the apply lock. It turns pfBlockerNG off
 * through the apply steps alone: the settings, the removal of the lists unless they are kept, the DNS teardown, the alias,
 * aggregate and rule teardown, and the pre and post hooks, which an uninstall sends to pfb-core (pfb_pass_hooks()). It
 * fetches and parses nothing. FALSE when a lock is unavailable.
 */
function pfb_outpost_disable_pass(): bool {
	global $pfb;
	$pfb['disable_pass'] = TRUE;	// pfb_global() keeps enable and DNSBL off while it is set
	try {
		return pfb_outpost_disable_pass_run();
	} finally {
		unset($pfb['disable_pass']);
	}
}

/** The body of pfb_outpost_disable_pass(), with the settings held off. */
function pfb_outpost_disable_pass_run(): bool {
	global $pfb;
	pfb_global();
	$dispatch_owner = !isset($GLOBALS['pfb_schedule_dispatch_lock']) || !is_resource($GLOBALS['pfb_schedule_dispatch_lock']);
	$owner = !isset($GLOBALS['pfb_feed_pass_lock']);
	$contended = FALSE;
	if (!pfb_schedule_dispatch_begin(0.1, $contended)) {
		pfb_logger("\n Disable pass: the scheduler dispatcher lock is unavailable; nothing was removed.\n", 1);
		return FALSE;
	}
	if (!pfb_feed_pass_begin('sync', $contended)) {
		if ($dispatch_owner) {
			pfb_schedule_dispatch_release();
		}
		pfb_logger("\n Disable pass: the apply lock is unavailable; nothing was removed.\n", 1);
		return FALSE;
	}
	$absorb = FALSE;
	if (!pfb_apply_enter($owner, $dispatch_owner, $absorb)) {
		return FALSE;	// pfb_apply_enter() released the locks it owned
	}
	try {
		pfb_runlog_begin();
		$pfb['filter_configure'] = $pfb['domain_update'] = $pfb['domain_clear'] = FALSE;
		$pfb['dnsbl_publish_failed'] = $pfb['dnsbl_accounting_failed'] = FALSE;
		$pfb['reuse_dnsbl'] = '';
		pfb_pass_hooks('pre', ['TRIGGER' => 'update']);
		pfb_logger("\n**Saving configuration**\n", 1);
		['new_aliases' => $new_aliases, 'new_aliases_list' => $new_aliases_list, 'pfb_alias_lists_all' => $alias_lists_all]
			= pfb_apply_settings();

		if ($pfb['keep'] !== PfbToggle::On) {
			pfb_logger("\n  Removing DB Files/Folders \n", 1);
			pfb_clear_contents();
		}
		foreach (['_v4', '_v6'] as $vtype) {
			unlink_if_exists("{$pfb['dbdir']}/DNSBLIP{$vtype}.txt");
			unlink_if_exists("{$pfb['dbdir']}/DNSBLIP{$vtype}.txt.fp");
			unlink_if_exists("{$pfb['denydir']}/DNSBLIP{$vtype}.*");
			unlink_if_exists("{$pfb['nativedir']}/DNSBLIP{$vtype}.*");
		}
		if (file_exists("{$pfb['dnsbl_file']}.conf")) {
			$pfb['domain_clear'] = TRUE;
			@unlink("{$pfb['dnsbl_file']}.conf");
		}
		pfb_top1m_teardown_call();

		[$mode, $update, $python] = pfb_apply_dns();
		$dnsbl_changed = pfb_dnsbl_reload_needed(FALSE, $pfb['domain_clear'], $update, $python, FALSE, FALSE);
		if ($dnsbl_changed) {
			pfb_update_unbound($mode, $update, $python);
		}
		unlink_if_exists("{$pfb['dnsbl_file']}.reload");
		pfb_apply_dns_proxy();

		$alias_lists = $prev_sets = [];
		pfb_build_aggregate_aliases($new_aliases, $new_aliases_list, $alias_lists, $prev_sets);
		['changedAliases' => $alias_lists, 'ipUnlockForced' => $ip_unlock_forced]
			= pfb_apply_objects($new_aliases, $new_aliases_list, $alias_lists, $alias_lists_all, $prev_sets, [], $absorb);

		pfb_pass_hooks('post', [
			'TRIGGER'		=> 'update',
			'IP_CHANGED'		=> (!empty($pfb['filter_configure']) || $ip_unlock_forced) ? '1' : '0',
			'DNSBL_CHANGED'		=> $dnsbl_changed ? '1' : '0',
			'STATUS'		=> 'ok',
			'CHANGED_IP_ALIASES'	=> implode(' ', array_unique(is_array($alias_lists) ? $alias_lists : [])),
			'CHANGED_DNSBL_GROUPS'	=> '',
		]);
		return TRUE;
	} finally {
		if ($owner) {
			pfb_feed_pass_release();
		}
		if ($dispatch_owner) {
			pfb_schedule_dispatch_release();
		}
	}
}

/**
 * The apply's DNS step: the Resolver integration, the retired block-page objects, the DNS-redirect NAT rules and the DoT/DoQ
 * block rules, in that order. Shared by the update pass and the version 2 apply. Returns the mode it ran in ('enabled',
 * 'disabled' or '') and whether the Resolver's conf and its python settings changed.
 *
 * @return array{0:string,1:bool,2:bool}
 */
function pfb_apply_dns(): array {
	global $pfb;

	#################################
	#	UNBOUND INTEGRATION	#
	#################################

	$pfbupdate = $pfbpython = FALSE;
	// $mode must be a defined string for the consumers below; the if/elseif does not cover every state
	// (e.g. DNSBL enabled while the DNS Resolver is disabled). '' is a no-op mode.
	$mode = '';
	if (pfb_dnsbl_active() && $pfb['unbound_state'] === PfbToggle::On) {
		$mode = 'enabled';
	}
	elseif (!pfb_dnsbl_active() && !$pfb['install']) {
		$mode = 'disabled';
	}

	// issue #3515: whether pfB-DNS is wanted is decided here, from the same runtime view as $mode (a removal pass has just
	// turned pfBlockerNG off in it), and handed to pfb_unbound_python(), which re-reads config.xml and would see it back on.
	$pfb_dns_wanted = pfb_dns_wanted();

	// Modify Unbound's python settings (the upstream observer) and mount lib/bin folders, as required
	$pfbpython = pfb_unbound_python($mode, $pfb_dns_wanted);

	// Modify Unbound.conf file, as required
	$pfbupdate = pfb_unbound_dnsbl($mode);

	// issue #4053: strip the block-page web server, NAT and auto-VIP an older version left.
	pfb_dnsbl_webserver_retire();

	pfb_apply_dns_redirect($mode);
	pfb_apply_dot_block($mode);

	return [$mode, (bool) $pfbupdate, (bool) $pfbpython];
}

// Sync DNS-redirect NAT rules (create / reconcile / prune / remove).
// Each rule uses associated-rule-id='pass' — pfSense emits an inline rdr pass and
// manages the companion firewall pass automatically; no filter/rule entry is written.
// Reads dnsbl_redir (toggle) via PfbConfig; manages nat/rule directly
// (pfSense-core foreign section — ADR-29 exclusion list).
// Coupled to DNSBL being enabled: rules are created only when $mode === 'enabled'
// (master enable + pfB-DNS + DNSBL toggle + resolver up); force-removed otherwise. Feeds/lists
// are NOT required — only the DNSBL toggle + resolver state.
function pfb_apply_dns_redirect(string $mode): void {
	global $pfb;

	$redir_changed = FALSE;
	$redir_toggle  = PfbConfig::read('dnsbl/dnsbl_redir');
	$redir_enabled = ($mode === 'enabled') && ($redir_toggle instanceof PfbToggle && $redir_toggle === PfbToggle::On);

	// Read before any removal below: the detector must still see an external row the writer erases.
	$redir_current = pfb_managed_obj_rows('nat/rule', PFB_DNS_REDIR_DESCR_V4_PFX);

	if (!$redir_enabled) {
		// DISABLED: remove all pfB_DNS_Redirect_* NAT rules.
		if (pfb_remove_managed_obj('nat/rule', PFB_DNS_REDIR_DESCR_V4_PFX)) {
			$redir_changed = TRUE;
		}
	} else {
		// ENABLED: read interfaces (comma-separated) and exception alias.
		$redir_iface_raw = (string) PfbConfig::read('dnsbl/dnsbl_redir_int');
		$redir_exception = trim((string) PfbConfig::read('dnsbl/dnsbl_redir_exclude'));

		$redir_ifaces_raw = array_filter(array_map('trim', explode(',', $redir_iface_raw)), 'strlen');
		$redir_ifaces     = [];
		foreach ($redir_ifaces_raw as $redir_iface_entry) {
			$redir_validated = pfb_filter($redir_iface_entry, PFB_FILTER_WORD, 'dns_redirect_sync');
			if (empty($redir_validated)) {
				pfb_logger(
					"\nDNS redirect: interface failed validation [ " .
					substr(htmlspecialchars((string) $redir_iface_entry), 0, 100) . " ] *skipping*", 2
				);
				continue;
			}
			$redir_ifaces[] = $redir_validated;
		}

		if (empty($redir_ifaces)) {
			// No valid interfaces remain — remove all rules.
			if (pfb_remove_managed_obj('nat/rule', PFB_DNS_REDIR_DESCR_V4_PFX)) {
				$redir_changed = TRUE;
			}
		} else {
			// Build the expected marker set for the current iface × family grid.
			$redir_expected_descrs = [];
			foreach ($redir_ifaces as $redir_iface) {
				$redir_expected_descrs[] = PFB_DNS_REDIR_DESCR_V4_PFX . $redir_iface . PFB_DNS_REDIR_DESCR_V4_SFX;
				$redir_expected_descrs[] = PFB_DNS_REDIR_DESCR_V4_PFX . $redir_iface . PFB_DNS_REDIR_DESCR_V6_SFX;
			}

			// Stale-interface prune: remove pfB_DNS_Redirect_* rows no longer in the expected set.
			$redir_stale_guard = static function (array $row) use ($redir_expected_descrs): bool {
				$descr = $row['descr'] ?? '';
				return str_starts_with($descr, PFB_DNS_REDIR_DESCR_V4_PFX)
					&& !in_array($descr, $redir_expected_descrs, TRUE);
			};
			if (pfb_remove_managed_obj('nat/rule', PFB_DNS_REDIR_DESCR_V4_PFX, $redir_stale_guard)) {
				$redir_changed = TRUE;
			}

			// Bucket existing nat/rule rows: redirect-owned vs other.
			$redir_ex_owned = $redir_ex_other = [];
			foreach (config_get_path('nat/rule', []) as $redir_ex_nat) {
				if (str_starts_with($redir_ex_nat['descr'] ?? '', PFB_DNS_REDIR_DESCR_V4_PFX)) {
					$redir_ex_owned[] = $redir_ex_nat;
				} else {
					$redir_ex_other[] = $redir_ex_nat;
				}
			}

			// Build new NAT rdr rules for each interface × family. The builder resolves the
			// exception source PER rule with a context label (interface + IP version), so when
			// the exception alias is not usable the log names the specific rule that dropped it
			// (#664) instead of an identical line per grid cell. The lookup itself is cheap.
			$redir_new_owned = [];
			foreach ($redir_ifaces as $redir_iface) {
				foreach (['inet', 'inet6'] as $redir_family) {
					$redir_new_owned[] = pfb_dns_redirect_rule($redir_iface, $redir_family, $redir_exception);
				}
			}

			if ($redir_ex_owned !== $redir_new_owned) {
				$redir_changed = TRUE;
				config_set_path('nat/rule', array_merge($redir_ex_other, $redir_new_owned));
			}
		}
	}
	pfb_sync_copied_check('nat', $redir_current, $redir_new_owned ?? [], $pfb['dbdir']);

	if ($redir_changed) {
		write_config('pfBlockerNG: saving DNS-redirect rule changes');
		// The NAT rdr rows changed — flag a pf reload so filter_configure()
		// actually loads them into the ruleset.
		$pfb['filter_configure'] = TRUE;
	}
}

// Sync DoT/DoQ block filter rules (create / reconcile / prune / remove).
// Reads dnsbl_dot_block (toggle) via PfbConfig; manages filter/rule directly
// (pfSense-core foreign section — ADR-29 exclusion list).
// Coupled to DNSBL being enabled: rules are created only when $mode === 'enabled'
// (master enable + pfB-DNS + DNSBL toggle + resolver up); force-removed otherwise. Feeds/lists
// are NOT required — only the DNSBL toggle + resolver state.
function pfb_apply_dot_block(string $mode): void {
	global $pfb;

	$dot_changed = FALSE;
	$dot_toggle  = PfbConfig::read('dnsbl/dnsbl_dot_block');
	$dot_enabled = ($mode === 'enabled') && ($dot_toggle instanceof PfbToggle && $dot_toggle === PfbToggle::On);

	// Read before any removal below: the detector must still see an external row the writer erases.
	$dot_current = pfb_managed_obj_rows('filter/rule', PFB_DOT_BLOCK_DESCR_PFX);

	if (!$dot_enabled) {
		// DISABLED: remove all pfB_DoT_Block_* filter rules.
		if (pfb_remove_managed_obj('filter/rule', PFB_DOT_BLOCK_DESCR_PFX)) {
			$dot_changed = TRUE;
		}
	} else {
		// ENABLED: read interfaces (comma-separated), exception alias, rule action, floating mode.
		$dot_iface_raw    = (string) PfbConfig::read('dnsbl/dnsbl_dot_block_int');
		$dot_exclude_alias = trim((string) PfbConfig::read('dnsbl/dnsbl_dot_block_exclude'));
		$dot_action       = pfb_dot_block_action((string) PfbConfig::read('dnsbl/dnsbl_dot_block_action'));
		$dot_floating_cfg = PfbConfig::read('dnsbl/dnsbl_dot_block_floating');
		$dot_floating     = ($dot_floating_cfg instanceof PfbToggle && $dot_floating_cfg === PfbToggle::On);

		$dot_ifaces_raw = array_filter(array_map('trim', explode(',', $dot_iface_raw)), 'strlen');
		$dot_ifaces     = [];
		foreach ($dot_ifaces_raw as $dot_iface_entry) {
			$dot_validated = pfb_filter($dot_iface_entry, PFB_FILTER_WORD, 'dot_block_sync');
			if (empty($dot_validated)) {
				pfb_logger(
					"\nDoT/DoQ block: interface failed validation [ " .
					substr(htmlspecialchars((string) $dot_iface_entry), 0, 100) . " ] *skipping*", 2
				);
				continue;
			}
			$dot_ifaces[] = $dot_validated;
		}

		if (empty($dot_ifaces)) {
			// No valid interfaces remain — remove all rules.
			if (pfb_remove_managed_obj('filter/rule', PFB_DOT_BLOCK_DESCR_PFX)) {
				$dot_changed = TRUE;
			}
		} else {
			// Build the expected marker set for the current mode. Floating mode owns a
			// single marker (one rule for all interfaces); per-interface mode owns one
			// marker per interface. The stale-prune below removes any owned row not in
			// this set — so switching modes drops the other mode's rule(s) automatically.
			if ($dot_floating) {
				$dot_expected_descrs = [PFB_DOT_BLOCK_FLOATING_DESCR];
			} else {
				$dot_expected_descrs = [];
				foreach ($dot_ifaces as $dot_iface) {
					$dot_expected_descrs[] = PFB_DOT_BLOCK_DESCR_PFX . $dot_iface;
				}
			}

			// Stale-interface prune: remove pfB_DoT_Block_* rows no longer in the expected set.
			$dot_stale_guard = static function (array $row) use ($dot_expected_descrs): bool {
				$descr = $row['descr'] ?? '';
				return str_starts_with($descr, PFB_DOT_BLOCK_DESCR_PFX)
					&& !in_array($descr, $dot_expected_descrs, TRUE);
			};
			if (pfb_remove_managed_obj('filter/rule', PFB_DOT_BLOCK_DESCR_PFX, $dot_stale_guard)) {
				$dot_changed = TRUE;
			}

			// Bucket existing filter/rule rows: dot-owned vs other.
			$dot_ex_owned = $dot_ex_other = [];
			foreach (config_get_path('filter/rule', []) as $dot_ex_rule) {
				if (str_starts_with($dot_ex_rule['descr'] ?? '', PFB_DOT_BLOCK_DESCR_PFX)) {
					$dot_ex_owned[] = $dot_ex_rule;
				} else {
					$dot_ex_other[] = $dot_ex_rule;
				}
			}

			// Preserve each rule's existing tracker by descr so it is stable across
			// re-syncs (the GUI keys rule edit/delete/separators on a unique numeric
			// tracker); mint a deterministic one only for genuinely new rows. Stored
			// as a STRING to match the config-roundtrip type, so the change-detection
			// compare below stays an exact match when nothing changed.
			$dot_existing_trackers = [];
			foreach ($dot_ex_owned as $dot_existing_rule) {
				if (!empty($dot_existing_rule['descr']) && isset($dot_existing_rule['tracker'])) {
					$dot_tracker = (string) $dot_existing_rule['tracker'];
					$dot_existing_trackers[$dot_existing_rule['descr']] = $dot_tracker;
					// Register the preserved tracker so pfb_managed_rule_tracker() treats it as
					// occupied — a newly-minted deterministic id can't then collide with it.
					if (ctype_digit($dot_tracker)) {
						$pfb['trackerids'][] = (int) $dot_tracker;
					}
				}
			}

			// Build the new owned rule(s). The rule shape (incl. the configurable
			// block/reject disposition) is built by the per-mode builder; the
			// deterministic tracker is appended here (last key) so the change-detection
			// compare below stays stable. Floating mode = one rule for all interfaces;
			// per-interface mode = one rule each.
			$dot_new_owned = [];
			if ($dot_floating) {
				$dot_descr = PFB_DOT_BLOCK_FLOATING_DESCR;
				$dot_rule  = pfb_dot_block_floating_rule($dot_ifaces, $dot_exclude_alias, $dot_action);
				$dot_rule['tracker'] = $dot_existing_trackers[$dot_descr] ?? (string) pfb_managed_rule_tracker($dot_descr);
				$dot_new_owned[] = $dot_rule;
			} else {
				foreach ($dot_ifaces as $dot_iface) {
					$dot_descr = PFB_DOT_BLOCK_DESCR_PFX . $dot_iface;
					$dot_rule  = pfb_dot_block_rule($dot_iface, $dot_exclude_alias, $dot_action);
					$dot_rule['tracker'] = $dot_existing_trackers[$dot_descr] ?? (string) pfb_managed_rule_tracker($dot_descr);
					$dot_new_owned[] = $dot_rule;
				}
			}

			if ($dot_ex_owned !== $dot_new_owned) {
				$dot_changed = TRUE;
				config_set_path('filter/rule', array_merge($dot_ex_other, $dot_new_owned));
			}
		}
	}
	pfb_sync_copied_check('dot_filter', $dot_current, $dot_new_owned ?? [], $pfb['dbdir']);

	if ($dot_changed) {
		write_config('pfBlockerNG: saving DoT/DoQ block rule changes');
		// The block rule changed — force a pf reload so it loads.
		$pfb['filter_configure'] = TRUE;
	}
}

/** The apply's last DNS step: the DNS proxy runs. Shared by the update pass and the version 2 apply. */
function pfb_apply_dns_proxy(): void {
	// issue #3515: pfB-DNS serves with DNSBL on or off ($mode only says whether DNSBL is): bring up a proxy that died since
	// the last pass, and restart one whose rc script changed. A reload above has already restarted a proxy that hosts the module.
	// A proxy that does not become ready is reported (its startup notice) and left running with the Resolver moved: only the admin's
	// own switches give the Resolver back, so the pass goes on with the Resolver as the move left it. A gateway stopped for a foreign
	// process on Unbound's backend port is a deliberate stop (pfb_dns_proxy_backend_block() filed its notice), not a start that failed;
	// issue #3872: so is one whose marker could not be written, which this pass still knows of
	if (!pfb_dns_proxy_ensure_running()) {
		pfb_logger((pfb_dns_proxy_backend_blocked() || pfb_dns_proxy_cannot_serve())
		    ? "\npfB-DNS is not serving: a foreign process holds Unbound's backend port; see the notices"
		    : "\npfB-DNS: the DNS proxy did not become ready; see the notices", 2);
	}
}

/**
 * The pass's pfSense objects. Returns what the `post` hook and the settle read: the aliases whose table changed,
 * whether an IP unlock forced a re-block, whether the reload launch failed, and the loaded tables whose replace failed on
 * the path with a rule change. $pfb_push, when given, pushes each changed table that has a mirror on the path without a
 * rule change, in place of the delta from $pfb_alias_prev_sets: it is called with the alias, the delta mode, the batch size
 * and whether an IP unlock forced the re-block (the version 2 apply, which holds the delta in files).
 *
 * @param ?callable(string, string, int, bool): mixed $pfb_push
 * @return array{changedAliases:array,ipUnlockForced:bool,reloadUnknown:bool,tableFailed:list<string>}
 */
function pfb_apply_objects(array $new_aliases, array $new_aliases_list, array $pfb_alias_lists, array $pfb_alias_lists_all,
    array $pfb_alias_prev_sets, array $pfb_feed_changed, bool $pfb_sync_absorb, ?callable $pfb_push = NULL): array {
	global $g, $pfb;

	#########################################
	#	UPDATE pfSense ALIAS TABLES	#
	#########################################

	// Reload config.xml to get any recent changes
	config_read_file(FALSE, TRUE);

	$exist_aliases = config_get_path('aliases/alias', []);

	// Copied-object detector: only the pfB aliases, before the non-pfB ones are appended below.
	$pfb_alias_is_managed = static fn (array $alias): bool => str_starts_with($alias['name'], 'pfB_');
	$pfb_aliases_current  = array_values(array_filter($exist_aliases, $pfb_alias_is_managed));
	$pfb_aliases_expected = array_values(array_filter($new_aliases, $pfb_alias_is_managed));
	pfb_sync_copied_check('aliases', $pfb_aliases_current, $pfb_aliases_expected, $pfb['dbdir']);

	foreach ($exist_aliases as $cbalias) {

		if (str_starts_with($cbalias['name'], 'pfB_')) {
			// Remove unreferenced pfB aliastable files
			if (!in_array($cbalias['name'], $new_aliases_list)) {
				unlink_if_exists("{$pfb['aliasdir']}/{$cbalias['name']}.*");
			}
		}
		else {
			$new_aliases[] = $cbalias;
		}
	}

	// Update config.xml, if changes required
	if ($exist_aliases !== $new_aliases) {
		config_set_path('aliases/alias', $new_aliases);
		write_config('pfBlockerNG: saving Aliases');
	}
	unset($new_aliases, $exist_aliases);

	#########################
	#	Assign Rules	#
	#########################

	// Any pfB alias not in this list will be killed.
	$pfb_active_aliases = null;

	// Only execute if autorules are defined or if an alias has been removed.
	if ($pfb['autorules'] || $pfb['enable'] !== PfbToggle::On || $pfb['remove']) {
		$pfb_active_aliases = [];
		$message = '';
		if (!empty($pfb['deny_inbound']) || !empty($pfb['permit_inbound']) || !empty($pfb['match_inbound']) ||
		    !empty($pfb['deny_self']) || !empty($pfb['permit_self']) || !empty($pfb['match_self'])) {
			if (empty($pfb['inbound_interfaces'])) {
				$message = " Unable to apply rules. Inbound interface option not configured.";
			}
		}
		if (!empty($pfb['deny_outbound']) || !empty($pfb['permit_outbound']) || !empty($pfb['match_outbound'])) {
			if (empty($pfb['outbound_interfaces'])) {
				$message .= "\n Unable to apply rules. Outbound interface option not configured.";
			}
		}

		if (empty($message)) {
			$new_rules = array();

			// Reload config.xml to get any recent changes
			config_read_file(FALSE, TRUE);

			// New vs old rules array comparison
			$orig_rules_nocreated = $new_rules_nocreated = array();

			// Collect all existing rules
			$rules = config_get_path('filter/rule', []);

			// Track pfB aliases referenced by any rule; also build orig_rules_nocreated
			// for the write-gate comparison (done here, before calling the helper, so
			// the helper stays side-effect-free).
			if (!empty($rules)) {
				foreach ($rules as $rule) {
					foreach (array('source', 'destination') as $rtype) {
						if ((str_starts_with($rule[$rtype]['address'] ?? '', 'pfB_')) &&
						    !in_array($rule[$rtype]['address'], $pfb_active_aliases)) {
							$pfb_active_aliases[] = $rule[$rtype]['address'];
						}
					}
					if (isset($rule['created'])) {
						unset($rule['created']);
					}
					$orig_rules_nocreated[] = $rule;
				}
			}

			$pfb_dnsbl_float = [];

			// Build the pfB-generated rule templates (produced by pfb_firewall_rule() above).
			$pfb_generated = [
				'permit_inbound'    => $pfb['permit_inbound']    ?? [],
				'permit_outbound'   => $pfb['permit_outbound']   ?? [],
				'deny_inbound'      => $pfb['deny_inbound']      ?? [],
				'deny_outbound'     => $pfb['deny_outbound']     ?? [],
				'match_inbound'     => $pfb['match_inbound']     ?? [],
				'match_outbound'    => $pfb['match_outbound']    ?? [],
				'permit_self'       => $pfb['permit_self']       ?? [],
				'deny_self'         => $pfb['deny_self']         ?? [],
				'match_self'        => $pfb['match_self']        ?? [],
				'inbound_floating'  => $pfb['inbound_floating']  ?? '',
				'outbound_floating' => $pfb['outbound_floating'] ?? '',
				'dnsbl_float'       => $pfb_dnsbl_float,
			];

			#################################################################################
			#			IP FIREWALL RULES ORDER					#
			#  ORDER 0 |	pfB (p/m/b/r)	| All other	|				#
			#  ORDER 1 |	pfSense (p/m)	| pfB (p/m)	| pfB (b/r) 	| pfSense (b/r)	#
			#  ORDER 2 |	pfB (p/m)	| pfSense (p/m) | pfB (b/r)	| pfSense (b/r)	#
			#  ORDER 3 |	pfB (p/m)	| pfB (b/r) 	| pfSense (p/m)	| pfSense (b/r)	#
			#  ORDER 4 |	pfB (p/m)	| pfB (b/r)	| pfSense (b/r)	| pfSense (p/m)	#
			#################################################################################
			# NOTE (ADR-41): pfb_build_autorule_list() implements this table as a STABLE bucket
			# reorder -- it sorts every surviving rule into one of the four buckets (pfB p/m, pfB
			# b/r, user p/m, user b/r) and concatenates them in the column order above, applied
			# independently to the FLOATING and INTERFACE pf groups. Whole buckets move; nothing
			# inside a bucket is reordered, and no user rule is duplicated, dropped, or mutated.
			# All four columns are reproduced (a single before/after anchor cannot: order_1/order_2
			# split the user rules around the pfB block, so a pfB Permit must precede a user Block;
			# order_4 places the user's own Block before its Pass). Absent/unknown order -> order_0.

			$new_rules = pfb_build_autorule_list(
				$rules ?? [],
				$pfb_generated,
				$pfb['order'],
				$pfb['float'],
				$pfb['inbound_interfaces']  ?? [],
				$pfb['outbound_interfaces'] ?? []
			);

			// Copied-object detector: only the pfB-owned rules, before the write decision below.
			$pfb_rules_current  = array_values(array_filter($rules, 'pfb_rule_is_pfb_owned'));
			// pfb_tracker() builds int trackers and a config reread returns strings, so compare the tracker as a string.
			$pfb_rules_expected = array_map(
				static fn (array $rule): array => isset($rule['tracker']) ? array_replace($rule, array('tracker' => (string) $rule['tracker'])) : $rule,
				array_values(array_filter($new_rules, 'pfb_rule_is_pfb_owned'))
			);
			pfb_sync_copied_check('filter', $pfb_rules_current, $pfb_rules_expected, $pfb['dbdir']);

			unset($pfb['permit_inbound'], $pfb['permit_outbound'], $pfb['deny_inbound'],
			    $pfb['deny_outbound'], $pfb['match_inbound'], $pfb['match_outbound'],
			    $pfb['permit_self'], $pfb['deny_self'], $pfb['match_self']);

			// Remove 'created' tag (New vs old rules array comparison)
			foreach ($new_rules as $rule) {
				if (isset($rule['created'])) {
					unset($rule['created']);
				}
				$new_rules_nocreated[] = $rule;
			}

			// Update config.xml, if changes required
			if ($orig_rules_nocreated != $new_rules_nocreated) {
				config_set_path('filter/rule', $new_rules);
				write_config('pfBlockerNG: saving Firewall rules');
			}
		}
		else {
			$log = "\n\n{$message}\n";
			pfb_logger("{$log}", 1);
		}
	}

	#################################
	#	pfSense Integration	#
	#################################

	// If 'Rule Changes' are found, utilize the 'filter_configure()' function, if not, utilize 'pfctl replace' command
	// Captured here (before the if/else) so it is always defined at the post-hook emit.
	$pfb_ip_unlock_forced = FALSE;
	$pfb_table_failed = [];
	if ($pfb['autorules'] && ($orig_rules_nocreated ?? []) != ($new_rules_nocreated ?? []) || $pfb['enable'] !== PfbToggle::On || $pfb['remove']) {

		if (!$pfb['save']) {
			$log = "\n===[  Aliastables / Rules  ]================================\n\n";
			pfb_logger("{$log}", 1);

			$log = localize_text("Firewall rule changes found, applying Filter Reload");
			logger(LOG_NOTICE, $log, LOG_PREFIX_PKG_PFBLOCKERNG);
			pfb_logger("{$log}\n", 1);

			$rule_diff = pfb_diff_managed_rules($orig_rules_nocreated ?? [], $new_rules_nocreated ?? []);
			if ($rule_diff['reordered']) {
				pfb_logger(" " . localize_text("Rule order changed (no pfB rules added, modified, or removed)") . "\n", 1);
			} else {
				foreach ($rule_diff['created'] as $descr) {
					pfb_logger(" Created: {$descr}\n", 1);
				}
				foreach ($rule_diff['modified'] as $descr) {
					pfb_logger(" Modified: {$descr}\n", 1);
				}
				foreach ($rule_diff['removed'] as $descr) {
					pfb_logger(" Removed: {$descr}\n", 1);
				}
			}
			if (!empty($pfb_alias_lists)) {
				pfb_logger(localize_text("Alias tables: skipped (Filter Reload rebuilds them from the alias files)") . "\n", 1);
			}
		}

		exec("{$pfb['pfctl']} -s Tables 2>/dev/null | {$pfb['grep']} '^pfB_'", $pfb_tables);
		if (isset($pfb_tables)) {
			// ADR-40: $pfb_alias_lists is the content-diff set (aliases whose
			// canonical membership set changed this pass).
			// Rule-change path: filter_configure() rebuilds all pf tables from the
			// aliasdir files after this block, so we always do a full -T replace here
			// to pre-sync the kernel before filter_configure runs. The delta apply
			// (pfb_apply_alias_delta) is used only on the no-rule-change path below.
			$pfb_active_aliases = isset($pfb_active_aliases) ? array_unique($pfb_active_aliases) : [];
			$pfb_table_keep_aliases = pfb_rule_change_keep_aliases($new_aliases_list);
			$final_alias        = empty($pfb_alias_lists)
				? []
				: array_values(array_intersect(array_unique($pfb_alias_lists), $pfb_active_aliases));
			foreach ($pfb_tables as $pfb_table) {
				$pfb_table_path_esc = escapeshellarg("{$pfb['aliasdir']}/{$pfb_table}.txt");
				if (in_array($pfb_table, $pfb_active_aliases)) {
					if (in_array($pfb_table, $final_alias)) {
						// Active + changed: full -T replace so the kernel table is in sync
						// before filter_configure() rebuilds the ruleset from the aliasdir file.
						if (pfb_pfctl_table_op($pfb_table, 'replace', "-f {$pfb_table_path_esc}")['failed']) {
							$pfb_table_failed[] = $pfb_table;
						}
					}
				} elseif (in_array($pfb_table, $pfb_table_keep_aliases, TRUE)) {
					// Aggregates are urltable aliases, so ADR-11 deliberately gives them no rule.
					// Keep selected registrations for filter_configure() to rebuild below.
					continue;
				} else {
					// Remove inactive pfB aliastables
					pfb_pfctl_table_op($pfb_table, 'kill');
				}
			}
		}

		$pfb['filter_configure'] = TRUE;		// Set flag for filter_configure which will create the pfctl tables

		// Call function for Ramdisk processes.
		pfb_aliastables('update');

		// issue #4309: hot-swap pfb-core's in-memory SPOA radix tree without reloading HAProxy
		if (PfbConfig::read('ip/spoa_enable') === PfbToggle::On && function_exists('pfb_core_call')) {
			pfb_core_call('ReloadSPOA', array('requestId' => 'apply-' . bin2hex(random_bytes(8))));
		}
	}
	else {
		// Don't execute on user 'save'
		if (!$pfb['save']) {
			$log = "\n\n===[  Aliastables / Rules  ]==========================================\n\n";
			pfb_logger("{$log}", 1);

			$log = localize_text("No changes to Firewall rules, skipping Filter Reload");
			logger(LOG_NOTICE, $log, LOG_PREFIX_PKG_PFBLOCKERNG);
			pfb_logger("{$log}\n", 1);

			// Remove Alerts IP unlock file and force Reload of all Aliastables
			if (file_exists("{$pfb['ip_unlock']}")) {
				// Captured BEFORE unlink: flag that a temporary unlock forced a re-block this
				// pass, so PFB_IP_CHANGED reports '1' even though filter_configure() did NOT
				// run (issue #519 -- mirrors $pfb_dnsbl_unlock_forced / issue #517 on the DNSBL side).
				$pfb_ip_unlock_forced = TRUE;
				unlink_if_exists("{$pfb['ip_unlock']}");
				$pfb['repcheck'] = TRUE;
				// ADR-40: ip_unlock forces a re-block of all active aliases (the previously
				// unlocked IP must be re-added to every alias it belongs to).  With content
				// gating, $pfb_alias_lists may be empty (if no feed changed this pass), so
				// explicitly add all active aliases to the reload set here — same as the old
				// $pfb_alias_lists_all widening via repcheck, but explicit (#519 contract).
				$pfb_alias_lists = array_unique(array_merge($pfb_alias_lists, $pfb_alias_lists_all));
			}

			// ADR-40: $pfb_alias_lists is the content-diff set — aliases whose
			// canonical membership set changed this pass (or ip_unlock forced a re-block).
			// Apply each changed alias via forward delta (or replace per mode/churn).
			$final_alias = array_unique($pfb_alias_lists);

			if (!empty($final_alias)) {
				pfb_logger(localize_text("Alias table changes detected, updating:") . "\n", 1);

				// ADR-40: read mode/batch once for the loop (PfbConfig gateway).
				$pfb_delta_mode  = (string) PfbConfig::read('gen/pfb_alias_delta_mode')->toStored();
				$pfb_delta_batch = pfb_alias_delta_batch_clamp((string) PfbConfig::read('gen/pfb_alias_delta_batch'));

				foreach ($final_alias as $final) {
					if ($pfb_push !== NULL && file_exists("{$pfb['aliasdir']}/{$final}.txt")) {
						$pfb_push($final, $pfb_delta_mode, $pfb_delta_batch, $pfb_ip_unlock_forced);
						continue;
					}
					if (file_exists("{$pfb['aliasdir']}/{$final}.txt")) {
						// ADR-40: compute delta from the stashed previous canonical set.
						// Two cases always get force_rpl = TRUE here:
						//   • a pending ip_unlock: the unlocked IP is out of the kernel table
						//     but in both sets, so no delta re-adds it (issue #4213).
						//   • Empty-kernel aliases: stashed as [] explicitly (M1 fix), so
						//     empty([]) = TRUE → full -T replace repopulates the kernel.
						// Content-changed aliases stash their actual previous set (non-empty
						// array), so force_rpl = FALSE and the delta path applies normally.
						$mirror_path = "{$pfb['aliasdir']}/{$final}.txt";
						$desired     = pfb_canonical_alias_set(@file_get_contents($mirror_path) ?: '');
						$previous    = $pfb_alias_prev_sets[$final] ?? $desired;
						// Pending unlock, or boot / empty table (no stashed previous set): full replace.
						$force_rpl   = $pfb_ip_unlock_forced || empty($pfb_alias_prev_sets[$final] ?? NULL);
						pfb_apply_alias_delta(
							$pfb['pfctl'],
							$final,
							$mirror_path,
							$desired,
							$previous,
							$pfb_delta_mode,
							$pfb_delta_batch,
							$force_rpl
						);
					} else {
						pfb_logger(" Updating [ {$final} ]: Aliastable file not found\n", 1);
					}
				}
				pfb_logger("\n", 1);
				unset($pfb_delta_mode, $pfb_delta_batch, $desired, $previous, $mirror_path, $force_rpl);

				// Call function for Ramdisk processes.
				pfb_aliastables('update');
			} else {
				$log = "No changes to Aliases, skipping pfctl Update\n";
				pfb_logger("{$log}", 1);
			}
		}
	}
	unset($rules, $new_rules, $orig_rules_nocreated, $new_rules_nocreated);


	#################################
	#	SAVE CONFIGURATION	#
	#################################

	// Uncheck the "reuse existing downloads" flag — this update consumed the request,
	// so clear the one-shot. It is the only setting pfBlockerNG persists on the way out
	// of the update, so the save is gated directly on it (no staging array needed).
	if (!$pfb['save'] && $pfb['enable'] === PfbToggle::On &&
	    pfb_cfg_toggle_read($pfb['config']['pfb_reuse']) === PfbToggle::On) {

		pfb_logger("\nSaving config changes", 1);

		// Reload config.xml FIRST to pick up edits made concurrently during this
		// (long-running) update, THEN clear the flag through the gateway so the write
		// lands on the freshly-reloaded config. Writing before the reload would be
		// discarded by it; a single registered-key write needs no whole-config
		// array_replace_recursive() merge. ADR-29: registered key -> PfbConfig.
		config_read_file(FALSE, TRUE);
		// issue #1895: this update-apply pass runs with no web session in scope, so the
		// registered-field write asserts as a system caller, not a page privilege.
		PfbConfig::writeSystem('gen/pfb_reuse', PfbToggle::Off);
		write_config('pfBlockerNG: save settings');

		pfb_logger("... completed", 1);
	}


	// Query NAT Rules for previous IPv4 pfBlockerNG aliasnames which are not in the new '_v4' suffix format
	$pfb_found	= FALSE;
	config_read_file(FALSE, TRUE);

	foreach (config_get_path('nat/rule', []) as $key => $ex_nat) {
		foreach (array('source', 'destination') as $rtype) {
			if (isset($ex_nat[$rtype]['address']) && str_starts_with($ex_nat[$rtype]['address'], 'pfB_')) {
				$pfb_suffix = substr($ex_nat[$rtype]['address'], -3);

				if ($pfb_suffix == '_v6') {
					continue;
				}

				// Add '_v4' suffix if missing
				elseif ($pfb_suffix != '_v4') {
					config_set_path("nat/rule/{$key}/{$rtype}/address", "{$ex_nat[$rtype]['address']}_v4");
					$pfb_found = TRUE;
				}
			}
		}
	}

	if ($pfb_found) {
		write_config("pfBlockerNG: update NAT rule(s) aliasnames to include '_v4' suffix");
	}

	// Before the reload (pfSense HA sync) and the XMLRPC sync below can see this pass's own writes.
	if ($pfb_sync_absorb) {
		pfb_sync_receive_legacy_absorb($pfb['dbdir']);
	}

	#################################
	#  Call filter_configure once	#
	#################################

	$log = '';
	$pfb_filter_reload_unknown = FALSE;
	if ($pfb['filter_configure'] || !empty($pfb_feed_changed)) {
		// Remove IP Cache file
		unlink_if_exists($pfb['ip_cache']);
	}

	if ($pfb['filter_configure']) {

		// Remove any IPs in Alerts unlock feature
		unlink_if_exists("{$pfb['ip_unlock']}");

		// Only a LAUNCH failure leaves the firewall state unknown (pending + flagged so
		// the closing clear cannot wipe it): a detached reload's outcome is pfSense's
		// own -- it loads the ruleset under pfSense's filter lock and logs its
		// own results.
		$reload_status = pfb_filter_reload_exec();
		if ($reload_status !== 0) {
			pfb_mark_pending_changes();
			$pfb_filter_reload_unknown = TRUE;
		}


		// Stop/Restart pfb_filter service for new rule changes
		if ($pfb['enable'] !== PfbToggle::On) {
			if (is_service_running('pfb_filter')) {
				$log = 'Stopping firewall filter daemon';
				stop_service('pfb_filter');
			}
		}
		else {
			$log = 'Restarting firewall filter daemon';
			restart_service('pfb_filter');
		}
	}
	else {
		// Stop/Start Firewall filter daemon
		if ($pfb['enable'] !== PfbToggle::On && is_service_running('pfb_filter')) {
			$log = 'Stopping firewall filter daemon';
			stop_service('pfb_filter');
		}
		elseif ($pfb['enable'] === PfbToggle::On && !is_service_running('pfb_filter')) {
			$log = 'Starting firewall filter daemon';
			start_service('pfb_filter');
		}
	}

	if (!empty($log)) {
		pfb_logger("\n\n** {$log} **\n", 1);
		logger(LOG_NOTICE, localize_text($log), LOG_PREFIX_PKG_PFBLOCKERNG);
	}


	#################################
	#	KILL STATES		#
	#################################

	if (!$pfb['save'] && $pfb['kstates'] === PfbToggle::On && !$pfb['filter_configure']) {
		pfb_remove_states();
	}


	#########################################
	#	XMLRPC - sync process		#
	#########################################

	if (!is_platform_booting() && !$g['pfblockerng_install']) {
		pfblockerng_sync_on_changes();
	}

	#########################################
	#	Define/Apply CRON Jobs		#
	#########################################

	pfb_metrics_configure_export(
		$pfb['enable'] === PfbToggle::On && PfbConfig::read('gen/pfb_metrics_export') === PfbToggle::On
	);

	// Core runs every schedule; this pass only retires the crontab entries earlier versions installed, after the metrics lock is released.
	pfblockerng_retire_cron_jobs();

	return ['changedAliases' => $pfb_alias_lists, 'ipUnlockForced' => $pfb_ip_unlock_forced, 'reloadUnknown' => $pfb_filter_reload_unknown,
		'tableFailed' => $pfb_table_failed];
}

/**
 * Settles what a real Update pass applied; $pfb_pending_seen is the pending mark it saw at its start. $pfb_failure, when given,
 * is why the apply did not complete (the version 2 apply's failures), recorded as the apply record's reason; it keeps the
 * due-ledger flag. Returns TRUE when the apply is settled as applied (or for a settings save), FALSE when it is recorded failed.
 */
function pfb_apply_settle(bool $pfb_accounting_pending, bool $pfb_filter_reload_unknown, ?string $pfb_pending_seen,
    int $pfb_pass_started, ?string $pfb_failure = NULL): bool {
	global $pfb;

	if (!$pfb['save']) {
		$pending_cleared = !$pfb_accounting_pending && $pfb_failure === NULL && pfb_core_update_clear_pending_apply();
		if ($pending_cleared && !$pfb_filter_reload_unknown) {
			pfb_settle_pending_changes($pfb_pending_seen);
			pfb_sync_apply_record('applied', $pfb['filter_configure'] ? 'update pass completed; firewall reload started' : 'update pass completed', $pfb['dbdir'], FALSE, $pfb_pass_started);
			if (pfb_sync_receive_state_read($pfb['dbdir'])['accepted_digest'] !== NULL) {	// only a node holding an accepted policy reports what of it cannot take effect
				pfb_sync_findings_record(pfb_sync_effective_findings(pfb_sync_effective_facts()), $pfb['dbdir']);
			}
			return TRUE;
		}
		$reason = $pfb_accounting_pending ? 'DNSBL accounting or reload not confirmed; pending changes kept'
			: ($pfb_filter_reload_unknown || $pfb_failure === NULL ? 'firewall reload not confirmed; pending changes kept' : $pfb_failure);
		pfb_sync_apply_record('failed', $reason, $pfb['dbdir'], FALSE, $pfb_pass_started);
		return FALSE;
	}
	return TRUE;
}

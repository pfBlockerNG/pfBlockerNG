<?php
/*
 * pfblockerng_cron.inc
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

// Determine if source list file has an updated timestamp
function pfb_update_check($header, $list_url, $pfbfolder, $pfborig, $pflex, $format, $vtype, $srcint=FALSE): ?PfbScheduleTerminalResult {
	global $pfb;

	pfb_logger("[ {$header} ]\n", 1);
	$pfb['cron_update'] = FALSE;

	if (empty(pfb_filter($header, PFB_FILTER_WORD, 'php'))) {
		pfb_logger("\n Failed to update due to Invalid header name!", 2);
		return NULL;
	}

	if ($format === 'whois' || $format === 'asn') {
		if (strpos($list_url, ' ') !== FALSE) {
			$list_url = strstr($list_url, ' ', TRUE);
		}
		$filter_type = $format === 'whois' ? PFB_FILTER_DOMAIN : PFB_FILTER_ALNUM;
		$filter_name = $format === 'whois' ? 'WHOIS' : 'ASN';
		if (empty(pfb_filter($list_url, $filter_type, 'php'))) {
			pfb_logger("\n Invalid {$filter_name}. Terminating Download! [ " . pfb_redact_url($list_url) . " ]\n", 1);
			return NULL;
		}
	} elseif ($format === 'geoip') {
		if (strpos($list_url, ' ') !== FALSE) {
			$list_url = strstr($list_url, ' ', TRUE);
		}
		if (empty(pfb_filter($list_url, PFB_FILTER_WORD, 'php'))) {
			pfb_logger("\n Invalid GEOIP. Terminating Download! [ " . pfb_redact_url($list_url) . " ]\n", 1);
			return NULL;
		}
		$list_url = "/usr/local/share/GeoIP/cc/{$list_url}{$vtype}.txt";
	} elseif (!pfb_filter($list_url, PFB_FILTER_URL, 'php')) {
		pfb_log_feed_host_reject($list_url, $header, 1);
		pfb_logger("\n Invalid URL. Terminating Download! [ " . pfb_redact_url($list_url) . " ]\n", 1);
		return NULL;
	}

	pfb_failures();
	if ($pfb['skipfeed'] != 0 && ($pfb['failed'][$header] ?? 0) >= $pfb['skipfeed']) {
		pfb_logger("  Max daily download failure attempts exceeded. Clear widget 'failed downloads' to reset.\n\n", 1);
		unlink_if_exists("{$pfbfolder}/{$header}.fail");
		return PfbScheduleTerminalResult::RetryCapReached;
	}

	if (file_exists("{$pfbfolder}/{$header}.fail")) {
		pfb_logger(pfb_log_status_line('', 'Previous download failed.', 'Re-attempt download') . "\n", 1);
	} else {
		pfb_logger(pfb_log_status_line('', '', 'Update check delegated to Core') . "\n", 1);
	}
	$pfb['cron_update'] = TRUE;
	$pfb['update_cron'] = TRUE;
	touch("{$pfbfolder}/{$header}.update");
	return NULL;
}


// Function to update Lists/Feeds as per Cron.
// $force_all — when TRUE, bypass the per-list hour-gate and call pfb_update_check()
//   unconditionally for every non-disabled, non-Hold, non-Never row (used by forcecheck).
//   Defaults to FALSE to preserve the existing cron behaviour byte-identically.
// $scope — 'both' (default), 'ip', or 'dnsbl'; filters which list types are probed.
//   Defaults to 'both' so existing callers (case 'cron') are unchanged.
// $feed_ids — issue #3941: the feeds (pfb_schedule_feed_id()) a scheduled pass checks, as Core named them; the
//   `*.fail` retries are added as always. Each terminal check is reported through pfb_schedule_outcome_record().
function pfblockerng_sync_cron(
	// issue #2491: typed because the RETURN VALUE now depends on its truthiness.
	bool $force_all = FALSE,
	$scope = 'both',
	bool $pending_change = FALSE,
	bool $clear_hashes = FALSE,
	?string &$deferred_by = NULL,
	array $feed_ids = []
): bool {
	global $pfb, $pfbarr;
	$deferred_by = NULL;

	$pfb_dispatch_owner = !isset($GLOBALS['pfb_schedule_dispatch_lock'])
		|| !is_resource($GLOBALS['pfb_schedule_dispatch_lock']);
	$pfb_dispatch_contended = FALSE;
	if (!pfb_schedule_dispatch_begin(0.1, $pfb_dispatch_contended)) {
		if (!$pfb_dispatch_contended) {
			return FALSE;
		}
		$deferred_by = 'dispatcher-lock';
		pfb_logger("\n Scheduled feed pass deferred: dispatcher lock unavailable; durable pending occurrences retained.\n", 1);
		// issue #2505: feed-pass parity (pfb_feed_pass_begin() raises LOG_NOTICE) --
		// a live wedged lock holder must be visible outside /var/log/pfblockerng.
		logger(LOG_NOTICE, localize_text('Feed pass [ %s ] deferred - the scheduler dispatcher lock is unavailable.',
			$force_all ? 'forcecheck' : 'cron'), LOG_PREFIX_PKG_PFBLOCKERNG);
		// Preserve the internal result: scheduled cron deferrals retain TRUE and
		// Force Check deferrals retain FALSE. The CLI maps $deferred_by to rc=75
		// independently of that bool.
		return !$force_all;
	}

	// issue #1175: serialize feed passes -- same ownership discipline as
	// sync_package_pfblockerng(); its tail call below reenters the SAME lock.
	$pfb_feed_pass_owner = !isset($GLOBALS['pfb_feed_pass_lock']);
	$pfb_feed_pass_contended = FALSE;
	if (!pfb_feed_pass_begin('cron', $pfb_feed_pass_contended)) {
		if (!$pfb_feed_pass_contended) {
			if ($pfb_dispatch_owner) {
				pfb_schedule_dispatch_release();
			}
			return FALSE;
		}
		$deferred_by = 'feed-pass-lock';
		pfb_logger("\n Scheduled feed pass deferred: feed lock unavailable; durable pending occurrences retained.\n", 1);
		if ($pfb_dispatch_owner) {
			pfb_schedule_dispatch_release();
		}
		// issue #2491: benign for the scheduled tick, observable for Force Check —
		// see the dispatcher-lock guard above.
		return !$force_all;
	}
	if ($force_all) {
		$dirs = pfb_force_scope_dirs($scope, $pfb['origdir'], $pfb['dnsorigdir']);
		pfb_force_clear_validators($dirs, $clear_hashes);
	}

	// Open the per-run log window BEFORE the first log line so the live viewer mirrors the whole
	// feed pass. Force Check / cron dispatch through here (not sync_package_pfblockerng directly,
	// which is only reached at the very end); without this the tail would stay silent until then.
	pfb_runlog_begin();

	$pfb['update_cron'] = FALSE;
	$scheduled_runtime = !$force_all;
	$pending_ids = $scheduled_runtime ? array_fill_keys($feed_ids, TRUE) : [];
	$pfb['scheduled_runtime_cron'] = $scheduled_runtime;
	$pfb['scheduled_selected_ids'] = $pending_ids;
	$check = static function (
		string $feed_id,
		string $header,
		string $url,
		string $folder,
		string $orig,
		bool $flex,
		string $format,
		string $vtype,
		mixed $srcint
	) use ($scheduled_runtime): void {
		global $pfb;
		$result = pfb_update_check($header, $url, $folder, $orig, $flex, $format, $vtype, $srcint);
		if ($scheduled_runtime && $result !== NULL) {
			if ($result === PfbScheduleTerminalResult::Success && !empty($pfb['cron_update'])) {
				pfb_mark_pending_changes();
				if (!pfb_due_ledger_set_pending('cron', $pfb['dbdir'])) {
					pfb_logger("\n Failed to publish pending apply marker; occurrence retained.\n", 2);
					return;
				}
			}
			pfb_schedule_outcome_record($feed_id, $result);
		}
	};
	$log = " CRON  PROCESS  START [ " . pfb_pkg_ver() . " ]\n";
	pfb_logger("{$log}", 1);

	$list_type = array('pfblockernglistsv4' => '_v4', 'pfblockernglistsv6' => '_v6', 'pfblockerngdnsbl' => '_v4');
	foreach ($list_type as $ltype => $vtype) {
		// Scope filter: skip list types not covered by $scope.
		$is_dnsbl = ($ltype === 'pfblockerngdnsbl');
		if ($scope === 'ip'    &&  $is_dnsbl) { continue; }
		if ($scope === 'dnsbl' && !$is_dnsbl) { continue; }

		foreach (config_get_path("installedpackages/{$ltype}/config", []) as $list) {
			if (!pfb_group_action_valid($list['action'] ?? NULL, $is_dnsbl ? 'dnsbl' : 'ipv4')) {
				continue;
			}
			if (isset($list['row']) && $list['action'] != 'Disabled' && $list['cron'] != 'Never') {
				foreach ($list['row'] as $row) {
					if (!empty($row['url']) && $row['state'] != 'Disabled') {

						if ($ltype == 'pfblockerngdnsbl') {
							$header = "{$row['header']}";
						} else {
							$header = "{$row['header']}{$vtype}";
						}

						if (empty(pfb_filter($header, PFB_FILTER_WORD, 'php'))) {
							pfb_logger("\n Invalid Header:{$row['header']} *skipping*", 1);
							continue;
						}

						// Determine cURL source interface (sets CURLOPT_INTERFACE; applies to entire alias)
						$srcint = $list['srcint'] ?: FALSE;

						// Determine folder location for alias (return array $pfbarr)
						pfb_determine_list_detail($list['action'], '', '', '');
						$pfbfolder	= $pfbarr['folder'];
						$pfborig	= $pfbarr['orig'];
						$family = $is_dnsbl ? 'dnsbl' : ($vtype === '_v4' ? 'ipv4' : 'ipv6');
						$feed_id = pfb_schedule_feed_id($family, $header);
						if ($feed_id === NULL) {
							continue;
						}

						// Bypass update if state is defined as 'Hold' and list file exists
						if ($row['state'] == 'Hold' && file_exists("{$pfbfolder}/{$header}.txt")) {
							unlink_if_exists("{$pfbfolder}/{$header}.fail");
							if ($scheduled_runtime && isset($pending_ids[$feed_id])) {
								pfb_schedule_outcome_record($feed_id, PfbScheduleTerminalResult::Success);
							}
							continue;
						}

						// Allow cURL SSL downgrade if user configured. $pflex must be derived
						// per-row before any update-check call below — PHP loop variables
						// persist across iterations (issue #1154).
						$pflex = FALSE;
						if ($row['state'] == 'Flex') {
							$pflex = TRUE;
						}

						// Attempt download, when a previous 'fail' file marker is found.
						if (file_exists("{$pfbfolder}/{$header}.fail")) {
							if ($scheduled_runtime) {
								$pfb['scheduled_selected_ids'][$feed_id] = TRUE;
							}
								$check($feed_id, $header, $row['url'], $pfbfolder, $pfborig, $pflex, $row['format'] ?? '', $vtype, $srcint);
							continue;
						}

						if ($force_all) {
								$check($feed_id, $header, $row['url'], $pfbfolder, $pfborig, $pflex, $row['format'] ?? '', $vtype, $srcint);
							} elseif (isset($pending_ids[$feed_id])) {
								$check($feed_id, $header, $row['url'], $pfbfolder, $pfborig, $pflex, $row['format'] ?? '', $vtype, $srcint);
						}
					}
				}
			}
		}
	}

	// If no lists require updates, check if Continents are configured and update accordingly.
	if (!$pfb['update_cron']) {
		foreach ($pfb['continents'] as $continent => $pfb_alias) {
			$continent_config = config_get_path('installedpackages/pfblockerng' . strtolower(str_replace(' ', '', $continent)) . '/config/0');
			if (!pfb_group_action_valid($continent_config['action'] ?? NULL, 'geoip')) {
				continue;
			}
			if ($continent_config['action'] != 'Disabled') {
				$pfb['update_cron'] = TRUE;
				break;
			}
		}
	}

	$sync_ok = TRUE;
	$apply_now = !$scheduled_runtime || pfb_quiet_hours_in_window(
		time(), (string) PfbConfig::read('gen/pfb_quiet_hours')
	);
	if ($pfb['update_cron']) {
		if ($apply_now) {
			$sync_ok = sync_package_pfblockerng('cron');
		} else {
			pfb_mark_pending_changes();
			pfb_due_ledger_set_pending('cron', $pfb['dbdir']);
			pfb_logger("\n Updates detected; automatic apply deferred until the configured window.\n", 1);
		}
		$pfb['update_cron'] = FALSE;
	} elseif ($pending_change && !$apply_now) {
		pfb_mark_pending_changes();
		pfb_due_ledger_set_pending('cron', $pfb['dbdir']);
		pfb_logger("\n Pending content change retained until the configured apply window.\n", 1);
	} else {
		$sync_ok = sync_package_pfblockerng('noupdates');
		$log = "\n  No Updates required.\n CRON  PROCESS  ENDED\n UPDATE PROCESS ENDED\n";
		pfb_logger("{$log}", 1);
	}

	// ADR-19: once-per-cron-tick software-update check. Best-effort + fully guarded
	// (provenance gate, pkg-lock + DNS guards inside) — it can never throw, so it does
	// not affect the feed cron timing/outcome. Provenance-gated: a no-op on a
	// Netgate-installed build.
	pfb_software_update_check();

	// issue #1175: release only if this call transitioned the lock (see head of function) --
	// the tail sync_package_pfblockerng() calls above reentered the SAME lock and no-op'd.
	if ($pfb_feed_pass_owner) {
		pfb_feed_pass_release();
	}
	if ($pfb_dispatch_owner) {
		pfb_schedule_dispatch_release();
	}
	return $sync_ok;
}

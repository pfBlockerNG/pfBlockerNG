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

	$log = "[ {$header} ]\n";
	pfb_logger("{$log}", 1);
	$pfb['cron_update'] = FALSE;

	if (empty(pfb_filter($header, PFB_FILTER_WORD, 'php'))) {
		pfb_logger("\n Failed to update due to Invalid header name!", 2);
		return NULL;
	}

	// Re-evaluate URL
	if ($format == 'whois' || $format == 'asn') {

		if (strpos($list_url, ' ') !== FALSE) {
			$list_url = strstr($list_url, ' ', TRUE);
		}

		$pfb_filter_type = PFB_FILTER_ALNUM;
		$pfb_filter_text = 'ASN';
		if ($format == 'whois') {
			$pfb_filter_type = PFB_FILTER_DOMAIN;
			$pfb_filter_text = 'WHOIS';
		}

		if (empty(pfb_filter($list_url, $pfb_filter_type, 'php'))) {
                        pfb_logger("\n Invalid {$pfb_filter_text}. Terminating Download! [ " . pfb_redact_url($list_url) . " ]\n", 1);
			return NULL;
		}

		$log = "\t\t\t\t\t\t\tUpdate found\n";
		pfb_logger("{$log}", 1);
		$pfb['cron_update'] = TRUE;
		$pfb['update_cron'] = TRUE;
		touch("{$pfbfolder}/{$header}.update");
		return PfbScheduleTerminalResult::Success;
	}
	elseif ($format == 'geoip') {
		if (strpos($list_url, ' ') !== FALSE) {
			$list_url = strstr($list_url, ' ', TRUE);
		}
		if (!empty(pfb_filter($list_url, PFB_FILTER_WORD, 'php'))) {
			$list_url = "/usr/local/share/GeoIP/cc/{$list_url}{$vtype}.txt";
		} else {
			pfb_logger("\n Invalid GEOIP. Terminating Download! [ " . pfb_redact_url($list_url) . " ]\n", 1);
			return NULL;
		}
	}
	elseif (!pfb_filter($list_url, PFB_FILTER_URL, 'php')) {
		// Issue #811: in the update flow this reject fires BEFORE any download is
		// scheduled, so pfb_download()'s entry/fetch gates never run — land the
		// header-scoped feed-host skip line here too (no-op unless the guard is
		// why vetting failed). The line below stays for non-guard rejects.
		pfb_log_feed_host_reject($list_url, $header, 1);
		pfb_logger("\n Invalid URL. Terminating Download! [ " . pfb_redact_url($list_url) . " ]\n", 1);
		return NULL;
	}

	$list_url_esc	= escapeshellarg("{$list_url}");
	$list_download	= trim("{$list_url_esc}", "'");

	// Call function to get all previous download fails
	pfb_failures();

	if ($pfb['skipfeed'] != 0) {
		// Determine if previous download fails have exceeded threshold.
		if (($pfb['failed'][$header] ?? 0) >= $pfb['skipfeed']) {
			$log = "  Max daily download failure attempts exceeded. Clear widget 'failed downloads' to reset.\n\n";
			pfb_logger("{$log}", 1);
			unlink_if_exists("{$pfbfolder}/{$header}.fail");
			return PfbScheduleTerminalResult::RetryCapReached;
		}
	}

	// Attempt download, when a previous 'fail' file marker is found.
	if (file_exists("{$pfbfolder}/{$header}.fail")) {
		$log = "\t\t\tPrevious download failed.\tRe-attempt download\n";
		pfb_logger("{$log}", 1);
		$pfb['update_cron'] = TRUE;
		touch("{$pfbfolder}/{$header}.update");
		return NULL;
	}

	// Check if List file doesn't exist or Format is 'whois'.
	if (!file_exists("{$pfbfolder}/{$header}.txt") || $format == 'whois') {
		$log = "\t\t\t\t\t\t\tUpdate found\n";
		pfb_logger("{$log}", 1);
		$pfb['update_cron'] = TRUE;
		return NULL;
	}

	$local_file = "{$pfborig}/{$header}.orig";

	// Compare previously downloaded file timestamp with remote timestamp
	if (file_exists($local_file)) {
		if ($format == 'rsync') {
			$log = "\t\t\t\t( rsync )\t\tUpdate found\n";
			pfb_logger("{$log}", 1);
			$pfb['cron_update'] = TRUE;
			$pfb['update_cron'] = TRUE;
			touch("{$pfbfolder}/{$header}.update");
			return PfbScheduleTerminalResult::Success;
		}

		// Determine if URL is a pfSense localfile
		$localfile = FALSE;
		if (pfb_filter($list_download, PFB_FILTER_URL, 'php', '', TRUE)) {
			$localfile = TRUE;
		}

		if ($localfile) {
			// ADR-42: local-file change detection delegated to pfb_local_feed_changed()
			// (pfblockerng.inc) -- content-hash (xxh128) gate, mtime removed; pinned by
			// FeedChangeHashHelpersTest.
			$pfb['cron_update'] = pfb_local_feed_changed($list_download, $local_file);
			if (!$pfb['cron_update']) {
				$log = "[ {$header} ] ( local feed unchanged )\tUpdate not required\n";
				pfb_logger("{$log}", 1);
				return PfbScheduleTerminalResult::Success;
			}
		}
		else {
			// ADR-42: replaces the HEAD+Last-Modified compare and whole-feed md5 fallback
			// with a conditional GET via pfb_download() (probe mode, type='change_detect'),
			// decided by pfb_conditional_get_decision() (decision matrix documented
			// there). The SSRF guard + redirect revalidation loop stay intact because the
			// probe goes through pfb_download(), not a bare curl_init().
			$probe_result = pfb_download(new PfbDownloadRequest(
				listUrl: "{$list_download}",
				downloadPath: "{$pfborig}/{$header}.md5",
				flex: $pflex,
				header: $header,
				format: '',
				logType: 1,
				versionType: '',
				timeout: 300,
				type: 'change_detect',
				username: '',
				password: '',
				sourceInterface: $srcint,
				extraHeaders: array(),
			));

			if (!$probe_result->success || $probe_result->responseMeta === NULL) {
				// Probe failed entirely (connection error, bad URL, etc.) → fail-safe.
				$log = "\n\tFailed to probe feed for change detection!\tUpdate skipped\n";
				unlink_if_exists("{$pfborig}/{$header}.md5.raw");
				touch("{$pfbfolder}/{$header}.fail");
				pfb_logger("{$log}", 1);
				return NULL;
			}

			$probe_meta = $probe_result->responseMeta;
			$probe_status = $probe_meta['status'];

			if ($probe_status === '304') {
				// Server confirmed not-modified via conditional GET → no re-ingest needed.
				$log = "\n[ {$header} ] ( 304 not modified )\tUpdate not required\n";
				pfb_logger("{$log}", 1);
				unlink_if_exists("{$pfborig}/{$header}.md5.raw");
				// Persist any refreshed validators from the 304 response.
				pfb_validator_write("{$local_file}", $probe_meta['etag'], $probe_meta['lastmod']);
				return PfbScheduleTerminalResult::Success;
			}

			if ($probe_status === '200') {
				// Compute the body hash and compare against the persisted .orig hash.
				$body_hash      = pfb_content_hash("{$pfborig}/{$header}.md5.raw", TRUE);
				$persisted_sidecar = pfb_hash_read($local_file);
				// A legacy .md5 sidecar (algo !== 'xxh128') collapses to '' intentionally:
				// remote feeds do not carry a dual-hash .md5 baseline, so the first cron
				// after upgrade cannot confirm "unchanged" and re-ingests once.  The next
				// write lays down an .xxhash128 sidecar and subsequent runs go conditional.
				$persisted_hash = ($persisted_sidecar['algo'] === 'xxh128') ? $persisted_sidecar['digest'] : '';

				$changed = pfb_conditional_get_decision($probe_status, $body_hash, $persisted_hash);

				if ($changed) {
					$log = "\n[ {$header} ] ( content changed )\tUpdate found\n";
					pfb_logger("{$log}", 1);
					// Persist the validators from this 200 response so the next run
					// can send a conditional GET.
					pfb_validator_write("{$local_file}", $probe_meta['etag'], $probe_meta['lastmod']);
					$pfb['cron_update'] = TRUE;
					$pfb['update_cron'] = TRUE;
					touch("{$pfbfolder}/{$header}.update");
					return PfbScheduleTerminalResult::Success;
				}
				else {
					$log = "\n[ {$header} ] ( content unchanged )\tUpdate not required\n";
					pfb_logger("{$log}", 1);
					unlink_if_exists("{$pfborig}/{$header}.md5.raw");
					// Refresh validators even on a spurious 200 so the next run can
					// go conditional (the server may start honouring ETags).
					pfb_validator_write("{$local_file}", $probe_meta['etag'], $probe_meta['lastmod']);
					return PfbScheduleTerminalResult::Success;
				}
			}

			// Any other status → fail-safe: treat as changed, re-ingest.
			$log = "\n\tUnexpected probe status [{$probe_status}]!\tUpdate forced (fail-safe)\n";
			unlink_if_exists("{$pfborig}/{$header}.md5.raw");
			pfb_logger("{$log}", 1);
			$pfb['update_cron'] = TRUE;
			touch("{$pfbfolder}/{$header}.update");
			return NULL;
		}
	} else {
		$pfb['cron_update'] = TRUE;
	}

	if ($pfb['cron_update']) {
		// Trigger CRON process if updates are found.
		$pfb['update_cron'] = TRUE;

		$log = "Update found\n";
		pfb_logger("{$log}", 1);
		touch("{$pfbfolder}/{$header}.update");
	}
	return $pfb['cron_update'] ? PfbScheduleTerminalResult::Success : NULL;
}


// Function to update Lists/Feeds as per Cron.
// $force_all — when TRUE, bypass the per-list hour-gate and call pfb_update_check()
//   unconditionally for every non-disabled, non-Hold, non-Never row (used by forcecheck).
//   Defaults to FALSE to preserve the existing cron behaviour byte-identically.
// $scope — 'both' (default), 'ip', or 'dnsbl'; filters which list types are probed.
//   Defaults to 'both' so existing callers (case 'cron') are unchanged.
function pfblockerng_sync_cron(
	// issue #2491: typed because the RETURN VALUE now depends on its truthiness.
	bool $force_all = FALSE,
	$scope = 'both',
	bool $pending_change = FALSE,
	bool $clear_hashes = FALSE
): bool {
	global $pfb, $pfbarr;

	$pfb_dispatch_owner = !isset($GLOBALS['pfb_schedule_dispatch_lock'])
		|| !is_resource($GLOBALS['pfb_schedule_dispatch_lock']);
	if (!pfb_schedule_dispatch_begin()) {
		pfb_logger("\n Scheduled feed pass deferred: dispatcher lock unavailable; durable pending occurrences retained.\n", 1);
		// issue #2505: feed-pass parity (pfb_feed_pass_begin() raises LOG_NOTICE) --
		// a live wedged lock holder must be visible outside /var/log/pfblockerng.
		logger(LOG_NOTICE, localize_text('Feed pass [ %s ] deferred - the scheduler dispatcher lock is unavailable.',
			$force_all ? 'forcecheck' : 'cron'), LOG_PREFIX_PKG_PFBLOCKERNG);
		// issue #2491: a deferral is benign for the UNATTENDED cron verb and a real
		// non-event for Force Check. Both reach here; only $force_all separates them
		// (pfblockerng.php:255 passes nothing, :304 passes TRUE).
		//
		// Unattended cron verb: another pass holds the lock, this run stood down with its
		// durable pending occurrence intact, and the next tick retries. Nothing failed, so
		// a hand-run `pfblockerng.php cron` or a third-party wrapper must not be told one
		// did -- and rc=0 is what tests/smoke/test_feed_pass_lock.py has asserted for this
		// path since ee8af959. No SCHEDULED job reaches this: the installed entry is
		// `cron-tick` (pfblockerng.inc pfblockerng_configure_tick_cron()), which returns
		// void and exits 0, and any legacy bare `pfblockerng.php cron` entry is removed
		// there on every sync pass.
		//
		// Force Check: the operator asked for an update NOW and did not get one. That
		// must stay observable (SyncCronFeedPassDeferralTest pins it).
		return !$force_all;
	}

	// issue #1175: serialize feed passes -- same ownership discipline as
	// sync_package_pfblockerng(); its tail call below reenters the SAME lock.
	$pfb_feed_pass_owner = !isset($GLOBALS['pfb_feed_pass_lock']);
	if (!pfb_feed_pass_begin('cron')) {
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
	$state_dir = (string) ($pfb['schedule_state_dir'] ?? '/usr/local/etc');
	$runtime_model = NULL;
	$runtime_state = NULL;
	$pending_ids = [];
	if ($scheduled_runtime) {
		$runtime_model = pfb_schedule_runtime_config();
		$runtime_state = pfb_schedule_state_read($state_dir);
		if ($runtime_model === NULL || $runtime_state === NULL) {
			pfb_logger("\n Scheduled feed runtime unavailable; cron selection suppressed.\n", 2);
			if ($pfb_feed_pass_owner) {
				pfb_feed_pass_release();
			}
			if ($pfb_dispatch_owner) {
				pfb_schedule_dispatch_release();
			}
			return FALSE;
		}
		if ($runtime_model['scheduled']) {
			foreach ($runtime_model['entries'] as $id => $entry) {
				$item = $runtime_state['items'][$id] ?? NULL;
				if ($entry['enabled'] && is_array($item) && array_key_exists('pending_occurrence', $item)) {
					$pending_ids[$id] = TRUE;
				}
			}
		}
	}
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
	) use ($scheduled_runtime, $state_dir): void {
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
			pfb_schedule_state_record_outcome($feed_id, $result, $state_dir);
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
								pfb_schedule_state_record_outcome(
									$feed_id, PfbScheduleTerminalResult::Success, $state_dir
								);
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

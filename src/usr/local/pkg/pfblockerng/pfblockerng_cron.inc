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
function pfb_update_check($header, $list_url, $pfbfolder, $pfborig, $pflex, $format, $vtype, $srcint=FALSE) {
	global $pfb;

	$log = "[ {$header} ]\n";
	pfb_logger("{$log}", 1);
	$pfb['cron_update'] = FALSE;

	if (empty(pfb_filter($header, PFB_FILTER_WORD, 'php'))) {
		pfb_logger("\n Failed to update due to Invalid header name!", 2);
		return;
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
			return;
		}

		$log = "\t\t\t\t\t\t\tUpdate found\n";
		pfb_logger("{$log}", 1);
		$pfb['update_cron'] = TRUE;
		touch("{$pfbfolder}/{$header}.update");
		return;
	}
	elseif ($format == 'geoip') {
		if (strpos($list_url, ' ') !== FALSE) {
			$list_url = strstr($list_url, ' ', TRUE);
		}
		if (!empty(pfb_filter($list_url, PFB_FILTER_WORD, 'php'))) {
			$list_url = "/usr/local/share/GeoIP/cc/{$list_url}{$vtype}.txt";
		} else {
			pfb_logger("\n Invalid GEOIP. Terminating Download! [ " . pfb_redact_url($list_url) . " ]\n", 1);
			return;
		}
	}
	elseif (!pfb_filter($list_url, PFB_FILTER_URL, 'php')) {
		// Issue #811: in the update flow this reject fires BEFORE any download is
		// scheduled, so pfb_download()'s entry/fetch gates never run — land the
		// header-scoped feed-host skip line here too (no-op unless the guard is
		// why vetting failed). The line below stays for non-guard rejects.
		pfb_log_feed_host_reject($list_url, $header, 1);
		pfb_logger("\n Invalid URL. Terminating Download! [ " . pfb_redact_url($list_url) . " ]\n", 1);
		return;
	}

	$list_url_esc	= escapeshellarg("{$list_url}");
	$list_download	= trim("{$list_url_esc}", "'");

	// Call function to get all previous download fails
	pfb_failures();

	if ($pfb['skipfeed'] != 0) {
		// Determine if previous download fails have exceeded threshold.
		if ($pfb['failed'][$header] >= $pfb['skipfeed']) {
			$log = "  Max daily download failure attempts exceeded. Clear widget 'failed downloads' to reset.\n\n";
			pfb_logger("{$log}", 1);
			unlink_if_exists("{$pfbfolder}/{$header}.fail");
			return;
		}
	}

	// Attempt download, when a previous 'fail' file marker is found.
	if (file_exists("{$pfbfolder}/{$header}.fail")) {
		$log = "\t\t\tPrevious download failed.\tRe-attempt download\n";
		pfb_logger("{$log}", 1);
		$pfb['update_cron'] = TRUE;
		touch("{$pfbfolder}/{$header}.update");
		return;
	}

	// Check if List file doesn't exist or Format is 'whois'.
	if (!file_exists("{$pfbfolder}/{$header}.txt") || $format == 'whois') {
		$log = "\t\t\t\t\t\t\tUpdate found\n";
		pfb_logger("{$log}", 1);
		$pfb['update_cron'] = TRUE;
		return;
	}

	$local_file = "{$pfborig}/{$header}.orig";

	// Compare previously downloaded file timestamp with remote timestamp
	if (file_exists($local_file)) {
		if ($format == 'rsync') {
			$log = "\t\t\t\t( rsync )\t\tUpdate found\n";
			pfb_logger("{$log}", 1);
			$pfb['update_cron'] = TRUE;
			touch("{$pfbfolder}/{$header}.update");
			return;
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
				return;
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
				return;
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
					$pfb['update_cron'] = TRUE;
					touch("{$pfbfolder}/{$header}.update");
					return;
				}
				else {
					$log = "\n[ {$header} ] ( content unchanged )\tUpdate not required\n";
					pfb_logger("{$log}", 1);
					unlink_if_exists("{$pfborig}/{$header}.md5.raw");
					// Refresh validators even on a spurious 200 so the next run can
					// go conditional (the server may start honouring ETags).
					pfb_validator_write("{$local_file}", $probe_meta['etag'], $probe_meta['lastmod']);
					return;
				}
			}

			// Any other status → fail-safe: treat as changed, re-ingest.
			$log = "\n\tUnexpected probe status [{$probe_status}]!\tUpdate forced (fail-safe)\n";
			unlink_if_exists("{$pfborig}/{$header}.md5.raw");
			pfb_logger("{$log}", 1);
			$pfb['update_cron'] = TRUE;
			touch("{$pfbfolder}/{$header}.update");
			return;
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
	return;
}


// Function to update Lists/Feeds as per Cron.
// $force_all — when TRUE, bypass the per-list hour-gate and call pfb_update_check()
//   unconditionally for every non-disabled, non-Hold, non-Never row (used by forcecheck).
//   Defaults to FALSE to preserve the existing cron behaviour byte-identically.
// $scope — 'both' (default), 'ip', or 'dnsbl'; filters which list types are probed.
//   Defaults to 'both' so existing callers (case 'cron') are unchanged.
function pfblockerng_sync_cron($force_all = FALSE, $scope = 'both', $manual = FALSE, $force_mode = 'download') {
	global $pfb, $pfbarr;

	// issue #1175: serialize feed passes -- same ownership discipline as
	// sync_package_pfblockerng(); its tail call below reenters the SAME lock.
	$pfb_feed_pass_owner = !isset($GLOBALS['pfb_feed_pass_lock'])
		|| !is_resource($GLOBALS['pfb_feed_pass_lock']);
	if (!pfb_feed_pass_begin('cron',TRUE,$manual)) {
		return;
	}
	if ($force_all && $manual) {
		$dirs = pfb_force_scope_dirs($scope, $pfb['origdir'], $pfb['dnsorigdir']);
		pfb_force_clear_validators($dirs, $force_mode === 'both');
	}

	// Open the per-run log window BEFORE the first log line so the live viewer mirrors the whole
	// feed pass. Force Check / cron dispatch through here (not sync_package_pfblockerng directly,
	// which is only reached at the very end); without this the tail would stay silent until then.
	pfb_runlog_begin();

	$hour = date('G');
	$dow  = date('N');
	$pfb['update_cron'] = FALSE;
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

						// Bypass update if state is defined as 'Hold' and list file exists
						if ($row['state'] == 'Hold' && file_exists("{$pfbfolder}/{$header}.txt")) {
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
							pfb_update_check($header, $row['url'], $pfbfolder, $pfborig, $pflex, $row['format'], $vtype, $srcint);
							continue;
						}

						if ($force_all) {
							// Bypass the hour-gate: check every in-scope feed unconditionally.
							pfb_update_check($header, $row['url'], $pfbfolder, $pfborig, $pflex, $row['format'], $vtype, $srcint);
						} else {
							switch ($list['cron']) {
								case 'EveryDay':
									if ($hour == $pfb['24hour']) {
										pfb_update_check($header, $row['url'], $pfbfolder, $pfborig, $pflex, $row['format'], $vtype, $srcint);
									}
									break;
								case 'Weekly':
									if ($hour == $pfb['24hour'] && $dow == $list['dow']) {
										pfb_update_check($header, $row['url'], $pfbfolder, $pfborig, $pflex, $row['format'], $vtype, $srcint);
									}
									break;
								default:
									$pfb_sch = pfb_cron_base_hour($list['cron']);
									if (in_array($hour, $pfb_sch)) {
										pfb_update_check($header, $row['url'], $pfbfolder, $pfborig, $pflex, $row['format'], $vtype, $srcint);
									}
									break;
							}
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

	if ($pfb['update_cron']) {
		sync_package_pfblockerng('cron');
		$pfb['update_cron'] = FALSE;
	} else {
		sync_package_pfblockerng('noupdates');
		$log = "\n  No Updates required.\n CRON  PROCESS  ENDED\n UPDATE PROCESS ENDED\n";
		pfb_logger("{$log}", 1);
	}

	// ADR-19: once-per-cron-tick software-update check. Best-effort + fully guarded
	// (provenance gate, pkg-lock + DNS guards inside) — it can never throw, so it does
	// not affect the feed cron timing/outcome. Provenance-gated: a no-op on a
	// Netgate-installed build.
	pfb_software_update_check();
	if ($manual && $scope === 'both') {
		$interval = ((int) ($pfb['interval'] ?: 1)) * 3600;
		pfb_due_ledger_mark_ran('cron', $interval, time(), pfb_tick_seed(), 0, $pfb['dbdir']);
	}

	// issue #1175: release only if this call transitioned the lock (see head of function) --
	// the tail sync_package_pfblockerng() calls above reentered the SAME lock and no-op'd.
	if ($pfb_feed_pass_owner) {
		pfb_feed_pass_release();
	}
}

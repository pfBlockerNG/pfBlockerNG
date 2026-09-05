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

/** @return array{reuse:string,reuse_dnsbl:string,updatednsbl:bool,save:bool,clear_masterfiles:bool} */
function pfb_sync_run_plan(array $request, bool $no_updates, bool $cron_tick, string $configured_reuse): array {
	$plan = [
		'reuse'             => $configured_reuse,
		'reuse_dnsbl'       => '',
		'updatednsbl'       => FALSE,
		'save'              => $no_updates,
		'clear_masterfiles' => FALSE,
	];
	if ($no_updates) {
		return $plan;
	}

	$scope = $request['scope'] ?? '';
	$force = !empty($request['force']);
	if ($scope === 'both' && $force) {
		$plan['reuse']             = 'on';
		$plan['reuse_dnsbl']       = 'on';
		$plan['updatednsbl']       = TRUE;
		$plan['clear_masterfiles'] = TRUE;
	} elseif ($scope === 'ip' && $force) {
		$plan['reuse']             = 'on';
		$plan['clear_masterfiles'] = TRUE;
	} elseif ($scope === 'dnsbl' && $force) {
		$plan['reuse']       = '';
		$plan['reuse_dnsbl'] = 'on';
		$plan['updatednsbl'] = TRUE;
	} elseif ($cron_tick && $configured_reuse === 'on') {
		$plan['reuse_dnsbl']       = 'on';
		$plan['clear_masterfiles'] = TRUE;
	}

	return $plan;
}

/**
 * TOP1M's live CSV is usable only while its raw detector baseline is present too.
 */
function pfb_top1m_refresh_needed(string $dbdir): bool {
	return !file_exists("{$dbdir}/top-1m.csv") || !file_exists("{$dbdir}/top-1m.csv.zip.orig");
}

function pfb_download_ledger_failure(string $facility, string $alias, string $header, string $ledger_dir): void {
	$message = "[ {$alias} - {$header} ] Download FAIL";
	if ($facility === 'dnsbl') {
		pfb_dnsbl_download_ledger_update(FALSE, $alias, $message, $ledger_dir);
	} elseif ($facility === 'ip') {
		pfb_ip_download_ledger_update(FALSE, $alias, $message, $ledger_dir);
	}
}

function pfb_download_ledger_close_if_clean(string $facility, string $alias, bool $failed, string $ledger_dir): void {
	if ($failed) {
		return;
	}
	if ($facility === 'dnsbl') {
		pfb_dnsbl_download_ledger_update(TRUE, $alias, '', $ledger_dir);
	} elseif ($facility === 'ip') {
		pfb_ip_download_ledger_update(TRUE, $alias, '', $ledger_dir);
	}
}

/** @return array{range:string,ipv4:string,ipv6:string} */
function pfb_ip_regex_config(): array {
	return [
		'range' => '/(?<![\w.])((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))-((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))(?![\w.])/',
		'ipv4'  => '/(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\/(?:\d|[12]\d|3[0-2])(?![\w.\/]))?(?![\w.])/',
		'ipv6'  => '/(?<![\w:.])(?:(?:(?:[[:xdigit:]]{1,4}:){7}(?:[[:xdigit:]]{1,4}|:))|(?:(?:[[:xdigit:]]{1,4}:){6}(?::[[:xdigit:]]{1,4}|(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(?:(?:[[:xdigit:]]{1,4}:){5}(?:(?:(?::[[:xdigit:]]{1,4}){1,2})|:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(?:(?:[[:xdigit:]]{1,4}:){4}(?:(?:(?::[[:xdigit:]]{1,4}){1,3})|(?:(?::[[:xdigit:]]{1,4})?:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?:(?:[[:xdigit:]]{1,4}:){3}(?:(?:(?::[[:xdigit:]]{1,4}){1,4})|(?:(?::[[:xdigit:]]{1,4}){0,2}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?:(?:[[:xdigit:]]{1,4}:){2}(?:(?:(?::[[:xdigit:]]{1,4}){1,5})|(?:(?::[[:xdigit:]]{1,4}){0,3}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?:(?:[[:xdigit:]]{1,4}:){1}(?:(?:(?::[[:xdigit:]]{1,4}){1,6})|(?:(?::[[:xdigit:]]{1,4}){0,4}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?::(?:(?:(?::[[:xdigit:]]{1,4}){1,7})|(?:(?::[[:xdigit:]]{1,4}){0,5}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(?:%.+)?(?:\/(?:1(?:2[0-8]|[01]\d)|[1-9]?\d)(?![\w.\/]))?(?![\w:.])/',
	];
}

function pfb_ip_regex_matches(string $family, string $line, array $config): array {
	if ($family === 'v4') {
		if (substr_count($line, '.') < 3) {
			return [];
		}
		$pattern = $config['ipv4'];
	} elseif ($family === 'v6') {
		if (strpos($line, ':') === FALSE) {
			return [];
		}
		$pattern = $config['ipv6'];
	} else {
		return [];
	}
	return preg_match_all($pattern, $line, $matches) ? $matches[0] : [];
}

// #3121: $ip_data is appended in place, never returned -- a by-value copy handed back
// through the result made every append copy the whole buffer (O(n²) over the feed).
/** @return array{line_number:int,raw_line:string,line:string,ip_suppressed:bool,parse_fail:int,messages:list<string>,detailed_parse_fail:bool} */
function pfb_ip_parse_line_replay(string $raw_line, array $config, int $line_number,
    string &$ip_data, bool $ip_suppressed, int $parse_fail): array {
	$parsed = pfb_ip_parse_line($raw_line, $config);
	foreach ($parsed['entries'] as $entry) {
		$ip_data .= $entry . "\n";
	}
	return [
		'line_number'       => $line_number + 1,
		'raw_line'          => $raw_line,
		'line'              => $parsed['line'],
		'ip_suppressed'     => $ip_suppressed || $parsed['suppressed'],
		'parse_fail'        => $parse_fail + $parsed['parse_fail_delta'],
		'messages'          => $parsed['messages'],
		'detailed_parse_fail' => $parsed['detailed_parse_fail'],
	];
}

function pfb_ip_recompute_order_scope(mixed $save, bool $enabled, bool $dup_on, bool $drep_on,
    bool $prep_on): bool {
	return !$save && $enabled && pfb_cross_list_scope($dup_on, $drep_on || $prep_on);
}

function pfb_ip_recompute_order_families(bool $dup_on): array {
	return $dup_on ? ['v4', 'v6'] : ['v4'];
}

function pfb_ip_recompute_mark_ran(string $family, callable $runner, bool &$ran_v4, bool &$ran_v6): void {
	$runner();
	if ($family === 'v4') {
		$ran_v4 = TRUE;
	} elseif ($family === 'v6') {
		$ran_v6 = TRUE;
	}
}

function pfb_dnsbl_alias_count_verbatim(string $path, int $current): int {
	return $current + (pfb_count_lines($path) ?? 0);
}

function pfb_dnsbl_alias_count_norm_skip(string $path, int $current): int {
	return $current + (pfb_count_lines($path) ?? 0);
}

function pfb_dnsbl_alias_count_script_failure(string $path, int $current): int {
	return $current + (pfb_count_lines($path) ?? 0);
}

function pfb_dnsbl_alias_count_rebuild(string $path, int $current): int {
	return $current + (pfb_count_lines($path) ?? 0);
}

/** @return array{header:string,custom:mixed,format:string,state:string,url:string} */
function pfb_dnsbl_custom_row(string $aliasname, mixed $custom): array {
	return [
		'header' => "{$aliasname}_custom",
		'custom' => $custom,
		'format' => 'regex',
		'state'  => 'Enabled',
		'url'    => 'custom',
	];
}

/** @return array{count:int,loggable:bool} */
function pfb_dnsbl_ipv4_count_decision(string $path): array {
	$count = pfb_count_lines($path) ?? 0;
	return ['count' => $count, 'loggable' => $count > 0];
}

/** @return array{count:int,loggable:bool} */
function pfb_dnsbl_ipv6_count_decision(string $path): array {
	$count = pfb_count_lines($path) ?? 0;
	return ['count' => $count, 'loggable' => $count > 0];
}

function pfb_apply_trailing_newline_ok(string $path): bool {
	if (pfb_ensure_trailing_newline($path)) {
		return TRUE;
	}
	$handle = @fopen($path, 'rb');
	if ($handle === FALSE || @fseek($handle, -1, SEEK_END) !== 0) {
		if (is_resource($handle)) {
			fclose($handle);
		}
		return FALSE;
	}
	$last = @fread($handle, 1);
	fclose($handle);
	return $last === "\n";
}

function pfb_apply_geoip_orig_pipeline(string $source, string $orig, string $mirror,
    ?callable $consumer = NULL): bool {
	$renamed = @rename($source, $orig);
	$normalized = pfb_apply_trailing_newline_ok($orig);
	$mirrored = @copy($orig, $mirror);
	if ($consumer !== NULL) {
		$consumer($orig, $mirror);
	}
	return $renamed && $normalized && $mirrored;
}

function pfb_apply_gunzip_orig_pipeline(string $source, string $orig, ?callable $consumer = NULL): bool {
	$published = FALSE;
	if (file_exists($source)) {
		// issue #2115: stage beside the active file — a redirect onto $orig truncates
		// the last-good publication before gunzip's exit status can be read.
		$staged = "{$orig}.tmp";
		$output = array();
		// issue #2658: same expansion ceiling every pfb_download() extraction runs under.
		exec(pfb_extract_cmd('/usr/bin/gunzip -c ' . escapeshellarg($source) . ' > ' . escapeshellarg($staged)), $output, $retval);
		if ($retval === 0 && pfb_apply_trailing_newline_ok($staged)) {
			$published = @rename($staged, $orig);
		}
		if (!$published) {
			@unlink($staged);
			return FALSE;
		}
	}
	// A missing source is the supported reuse path: consume whatever is already published.
	if ($consumer !== NULL && file_exists($orig)) {
		$consumer($orig);
	}
	return $published;
}

/**
 * Attempt the TOP1M provider fetch when either live source file is absent.
 * The optional fetcher is a no-network test seam; production uses the CLI command.
 */
function pfb_top1m_fetch_if_needed(string $dbdir, ?callable $fetch = NULL): bool {
	if (!pfb_top1m_refresh_needed($dbdir)) {
		return FALSE;
	}
	if ($fetch !== NULL) {
		$fetch();
	} else {
		pfb_reentry_exec('al', ['scheduled']);
	}
	return TRUE;
}

/** Rebuild only from an active TOP1M source whose detector baseline is current. */
function pfb_top1m_reprocess_needed(string $dbdir): bool {
	if (pfb_top1m_refresh_needed($dbdir)) {
		return FALSE;
	}

	$whitelist = "{$dbdir}/pfbalexawhitelist.txt";
	if ((!file_exists($whitelist) && !is_link($whitelist)) || file_exists("{$dbdir}/top-1m.update")) {
		return TRUE;
	}
	if (is_link($whitelist) || !is_file($whitelist)) {
		return FALSE;
	}

	$handle = @fopen($whitelist, 'r');
	if ($handle === FALSE) {
		return FALSE;
	}
	$first_byte = @fread($handle, 1);
	@fclose($handle);

	return $first_byte === '.';
}

function pfb_top1m_apply_reprocess_if_ready(string $dbdir, callable $reprocess): bool {
	if (!pfb_top1m_reprocess_needed($dbdir)) {
		return FALSE;
	}
	$reprocess();
	return TRUE;
}

/** Record the manifest publication outcome without logging a false completion. */
function pfb_dnsbl_publish_result(bool $published, ?callable $logger = NULL): bool {
	global $pfb;
	$logger = $logger ?? 'pfb_logger';
	if (!$published) {
		$pfb['dnsbl_publish_failed'] = TRUE;
		$logger('... FAILED (publication error)', 2);
		return FALSE;
	}
	$logger('... completed', 1);
	return TRUE;
}

/** Keep the reload and ADR-12 post-hook change signal on one predicate. */
function pfb_dnsbl_reload_needed(bool $publish_failed, bool $data_changed, bool $update, bool $python,
    bool $safesearch_update, bool $unlock_forced): bool {
	return !$publish_failed && ($data_changed || $update || $python || $safesearch_update || $unlock_forced);
}

/**
 * Parse one generic IP-feed line without touching run state or emitting output.
 * @param array{vtype:string,pftype:string,custom:bool,cidr_floor_v4:int|string,cidr_floor_v6:int|string,suppression:PfbToggle|string,range:string,ipv4:string,ipv6:string} $config
 * @return array{entries:list<string>,line:string,suppressed:bool,parse_fail_delta:int,detailed_parse_fail:bool,messages:list<string>}
 */
function pfb_ip_parse_line(string $raw_line, array $config): array {
	$line = trim($raw_line);
	$result = [
		'entries'             => [],
		'line'                => $line,
		'suppressed'          => FALSE,
		'parse_fail_delta'    => 0,
		'detailed_parse_fail' => FALSE,
		'messages'            => [],
	];
	if (pfb_is_blank_or_comment_line($line)) {
		return $result;
	}

	$vtype       = $config['vtype'];
	$pftype      = $config['pftype'];
	$custom      = $config['custom'];
	$pfbcidr     = $config['cidr_floor_v4'];
	$pfbcidr_v6  = $config['cidr_floor_v6'];
	$suppression = pfb_cfg_toggle_read($config['suppression'] ?? '');
	$parse_error = FALSE;

	if ($vtype == '_v4' && $pftype == 'auto') {
		// iBlocklist/PeerGuardian ".p2p": "<Org Name>:<start-ip>-<end-ip>" (sample
		// "JKS Media, LLC:4.53.2.12-4.53.2.15") -- strip the org name, leaving the
		// range for the '-' expander below. Reached because iBlocklist URLs map to
		// the 'iblock' extension, absent from the 'regex' parser list. Anchored on
		// the WHOLE shape, split at the LAST colon (issue #1923: a bare "contains
		// '-' and ':'" test mangles unrelated lines; an org name may contain ':').
		if (preg_match('/^.*:((?:\d{1,3}\.){3}\d{1,3}-(?:\d{1,3}\.){3}\d{1,3})$/', $line, $pfb_iblock)) {
			$line = $pfb_iblock[1];
		}
		if (strpos($line, ' ') !== FALSE) {
			$line = strstr($line, ' ', TRUE);
		}
		if (strpos($line, '#') !== FALSE) {
			$line = str_replace('#', '', strstr($line, '#', TRUE));
		}
		$line = trim($line);
	}

	// issue #2604: DShield start<TAB>end<TAB>prefix rows declare their own
	// family; accept only one exact CIDR and leave opposite-family rows alone.
	if ($pftype == 'auto' && strpos($line, "\t") !== FALSE) {
		$pfb_tab = explode("\t", $line);
		$pfb_tab_family = NULL;
		if (count($pfb_tab) >= 3 && ctype_digit($pfb_tab[2]) &&
			!str_contains($pfb_tab[0], "\0") && !str_contains($pfb_tab[1], "\0")) {
			if (validate_ipv4($pfb_tab[0]) && validate_ipv4($pfb_tab[1])) {
				$pfb_tab_family = '_v4';
			} elseif (validate_ipv6($pfb_tab[0]) && validate_ipv6($pfb_tab[1])) {
				$pfb_tab_family = '_v6';
			}
		}
		if ($pfb_tab_family !== NULL) {
			$a_cidr = ip_range_to_subnet_array($pfb_tab[0], $pfb_tab[1]);
			$pfb_tab_cidr = count($a_cidr) === 1 ? explode('/', $a_cidr[0], 2) : [];
			if (count($pfb_tab_cidr) === 2 && $pfb_tab_cidr[1] === $pfb_tab[2] &&
				inet_pton($pfb_tab_cidr[0]) === inet_pton($pfb_tab[0])) {
				$result['line'] = $line;
				if ($pfb_tab_family !== $vtype) {
					return $result;
				}
				$sanitized = $vtype == '_v4'
					? pfb_sanitize_ipaddr($a_cidr[0], $custom, $pfbcidr, $suppression)
					: pfb_sanitize_ipaddr_v6($a_cidr[0], $custom, $pfbcidr_v6, $suppression);
				$result['messages'] = array_merge($result['messages'], $sanitized['messages']);
				if (!pfb_is_empty($sanitized['address']) &&
					(($vtype == '_v4' && validate_ipv4($sanitized['address'])) ||
					($vtype == '_v6' && validate_ipv6($sanitized['address'])))) {
					$result['entries'][] = $sanitized['address'];
				} elseif ($vtype == '_v6') {
					$result['suppressed'] = TRUE;
				}
				return $result;
			}
		}
	}

	if ($vtype == '_v4' && $pftype == 'auto') {
		if (strpos($line, '-') !== FALSE) {
			$matches = explode('-', $line);
			if (count($matches) == 2 && validate_ipv4($matches[0]) && validate_ipv4($matches[1])) {
				$a_cidr = ip_range_to_subnet_array($matches[0], $matches[1]);
				if (!empty($a_cidr)) {
					foreach ($a_cidr as $cidr) {
						$sanitized = pfb_sanitize_ipaddr($cidr, $custom, $pfbcidr, $suppression);
						$result['messages'] = array_merge($result['messages'], $sanitized['messages']);
						if (!empty($sanitized['address'])) {
							if (validate_ipv4($sanitized['address'])) {
								$result['entries'][] = $sanitized['address'];
							} else {
								$parse_error = TRUE;
							}
						}
					}
					if (!$parse_error) {
						$result['line'] = $line;
						return $result;
					}
				}
			} else {
				$parse_error = TRUE;
			}
		}

		if (!$parse_error) {
			$sanitized = pfb_sanitize_ipaddr($line, $custom, $pfbcidr, $suppression);
			$result['messages'] = array_merge($result['messages'], $sanitized['messages']);
			if (!empty($sanitized['address']) && validate_ipv4($sanitized['address'])) {
				$result['entries'][] = $sanitized['address'];
				$result['line'] = $line;
				return $result;
			}
			$parse_error = TRUE;
		}
	}

	if ($vtype == '_v4' && ($pftype == 'regex' || $parse_error)) {
		if (strpos($raw_line, '-') !== FALSE && strpos($raw_line, '.') !== FALSE &&
			preg_match($config['range'], $raw_line, $matches)) {
			$a_cidr = ip_range_to_subnet_array($matches[1], $matches[2]);
			if (!empty($a_cidr)) {
				foreach ($a_cidr as $cidr) {
					$sanitized = pfb_sanitize_ipaddr($cidr, $custom, $pfbcidr, $suppression);
					$result['messages'] = array_merge($result['messages'], $sanitized['messages']);
					if (!empty($sanitized['address']) && validate_ipv4($sanitized['address'])) {
						$result['entries'][] = $sanitized['address'];
					} else {
						$result['parse_fail_delta']++;
					}
				}
			}
			$result['line'] = $line;
			return $result;
		}

		$ipv4_matches = pfb_ip_regex_matches('v4', $raw_line, $config);
		if (!empty($ipv4_matches)) {
			foreach (array_unique($ipv4_matches) as $match) {
				if (strpos($raw_line, 'cf-footer-item') === FALSE) {
					$sanitized = pfb_sanitize_ipaddr($match, $custom, $pfbcidr, $suppression);
					$result['messages'] = array_merge($result['messages'], $sanitized['messages']);
					if (!empty($sanitized['address']) && validate_ipv4($sanitized['address'])) {
						$result['entries'][] = $sanitized['address'];
					}
				}
			}
			$result['line'] = $line;
			return $result;
		}
	}

	if ($vtype == '_v6') {
		if ($pftype == 'auto' && strpos($line, ':') !== FALSE) {
			if (strpos($line, '#') !== FALSE) {
				$line = str_replace('#', '', strstr($line, '#', TRUE));
			}
			if (validate_ipv6($line)) {
				$sanitized = pfb_sanitize_ipaddr_v6($line, $custom, $pfbcidr_v6, $suppression);
				$result['messages'] = array_merge($result['messages'], $sanitized['messages']);
				if (!empty($sanitized['address'])) {
					$result['entries'][] = $sanitized['address'];
				} else {
					$result['suppressed'] = TRUE;
				}
				$result['line'] = $line;
				return $result;
			}
		}

		if (strpos($line, '-') !== FALSE && strpos($line, ':') !== FALSE) {
			$matches = explode('-', $line);
			if (count($matches) == 2 && !str_contains($raw_line, "\0")) {
				$a_cidr = ip_range_to_subnet_array($matches[0], $matches[1]);
				if (!empty($a_cidr)) {
					foreach ($a_cidr as $cidr) {
						if (!empty($cidr)) {
							if (validate_ipv6($cidr)) {
								$sanitized = pfb_sanitize_ipaddr_v6($cidr, $custom, $pfbcidr_v6, $suppression);
								$result['messages'] = array_merge($result['messages'], $sanitized['messages']);
								if (!empty($sanitized['address'])) {
									$result['entries'][] = $sanitized['address'];
								} else {
									$result['suppressed'] = TRUE;
								}
							} else {
								$parse_error = TRUE;
							}
						}
					}
				}
				if (!$parse_error) {
					$result['line'] = $line;
					return $result;
				}
			} else {
				$parse_error = TRUE;
			}
		}

		$ipv6_matches = pfb_ip_regex_matches('v6', $raw_line, $config);
		if (!empty($ipv6_matches)) {
			foreach (array_unique($ipv6_matches) as $match) {
				if (strpos($match, '#') !== FALSE) {
					$match = str_replace('#', '', strstr($match, '#', TRUE));
				}
				if (strpos($raw_line, 'cf-footer-item') === FALSE && validate_ipv6($match)) {
					$sanitized = pfb_sanitize_ipaddr_v6($match, $custom, $pfbcidr_v6, $suppression);
					$result['messages'] = array_merge($result['messages'], $sanitized['messages']);
					if (!empty($sanitized['address'])) {
						$result['entries'][] = $sanitized['address'];
					} else {
						$result['suppressed'] = TRUE;
					}
				}
			}
			$result['line'] = $line;
			return $result;
		}
	}

	if (!empty($line) && !preg_match('/[a-zA-Z,;|\"\'?]/', $line) && !pfb_ip_is_opposite_family($line, $vtype)) {
		$result['parse_fail_delta']++;
		$result['detailed_parse_fail'] = TRUE;
	}
	$result['line'] = $line;
	return $result;
}

/**
 * pfb_list_script_failure_record -- issue #1958/#2059: a per-feed pre- or
 * post-script that exits non-zero must not let the alias pass close as full
 * success. Opens a distinct ADR-61 stage='script' ledger entry -- separate
 * from stage='download', since the download itself genuinely succeeded and
 * only the script failed. ADR-61 symmetric ownership: the paired close is
 * pfb_list_script_failure_close() at the alias-pass end.
 *
 * $update_marker NULL writes no retry marker; the pre-script sites pass one
 * because a row that entered the update branch via a '.fail' marker alone had
 * that marker unlinked by the successful download, and without this write the
 * next pass takes the verbatim-reuse fast path and never retries the
 * transform. The write is best-effort (@-suppressed): ledger visibility must
 * never depend on it. Post-script callers pass NULL -- see
 * pfb_list_post_script_failure_record().
 */
function pfb_list_script_failure_record(string $facility, string $item, string $message,
    string $ledger_dir, ?string $update_marker, ?array &$state = NULL): void {
	if ($state !== NULL) {
		$state['failed'] = TRUE;
	}
	if ($update_marker !== NULL) {
		@touch($update_marker);
	}
	pfb_sync_status_open($facility, $item, 'script', $message, $ledger_dir);
}

/**
 * pfb_list_post_script_failure_record -- issue #2059: record a post-script's
 * exit status, no-op on 0. The status test lives here, not in an `if` at each
 * call site, so "a clean post-script records nothing" is testable: the
 * download loops cannot be driven off-appliance (#993).
 *
 * No retry marker: pfb_list_script_reuse_decision() re-runs a configured pre
 * OR post script every pass a local '.orig' baseline exists (#1278), so there
 * is nothing to arm -- and on the non-stale paths that reach here both loops
 * unlink '{header}.update' further down the same iteration anyway.
 */
function pfb_list_post_script_failure_record(int $exit_status, string $facility, string $item,
    string $message, string $ledger_dir, ?array &$state = NULL): void {
	if ($exit_status === 0) {
		return;
	}
	pfb_list_script_failure_record($facility, $item, $message, $ledger_dir, NULL, $state);
}

function pfb_list_script_failure_close(string $facility, string $item, string $ledger_dir, array $state): void {
	if (empty($state['failed'])) {
		pfb_sync_status_close($facility, $item, 'script', $ledger_dir);
	}
}

function pfb_ip_script_failure_close(string $item, string $ledger_dir, array $state): void {
	pfb_list_script_failure_close('ip', $item, $ledger_dir, $state);
}

function pfb_dnsbl_script_failure_close(string $item, string $ledger_dir, array $state): void {
	pfb_list_script_failure_close('dnsbl', $item, $ledger_dir, $state);
}

/** Record a failed pre-script and optionally retain its current staged manifest row. */
function pfb_list_script_failure_continue(string $facility, string $item, string $message,
    string $ledger_dir, string $update_marker, array &$state, bool $staging_current_generation,
    string $staged_txt, ?callable $manifest = NULL): bool {
	pfb_list_script_failure_record($facility, $item, $message, $ledger_dir, $update_marker, $state);
	if ($staging_current_generation && file_exists($staged_txt) && $manifest !== NULL) {
		$manifest();
	}
	return TRUE;
}

function pfb_ip_script_failure_continue(string $item, string $message, string $ledger_dir,
    string $update_marker, array &$state, bool $staging_current_generation, string $staged_txt,
    ?callable $manifest = NULL): bool {
	return pfb_list_script_failure_continue('ip', $item, $message, $ledger_dir, $update_marker,
	    $state, $staging_current_generation, $staged_txt, $manifest);
}

function pfb_dnsbl_script_failure_continue(string $item, string $message, string $ledger_dir,
    string $update_marker, array &$state, bool $staging_current_generation, string $staged_txt,
    ?callable $manifest = NULL): bool {
	return pfb_list_script_failure_continue('dnsbl', $item, $message, $ledger_dir, $update_marker,
	    $state, $staging_current_generation, $staged_txt, $manifest);
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

function pfb_ip_script_consume_staged(string $parse_path, ?string $staged_path, callable $consumer,
    ?string $known_path = NULL): mixed {
	return pfb_list_script_consume_staged($parse_path, $staged_path, $consumer, $known_path);
}

function pfb_ip_script_probe_staged(bool $custom, string $parse_path, ?string $staged_path, callable $probe,
    ?string $known_path = NULL): mixed {
	return pfb_ip_script_consume_staged($parse_path, $staged_path,
	    static fn (string $path): mixed => $custom ? NULL : $probe($path), $known_path);
}

function pfb_dnsbl_script_consume_staged(string $parse_path, ?string $staged_path, callable $consumer,
    ?string $known_path = NULL): mixed {
	return pfb_list_script_consume_staged($parse_path, $staged_path, $consumer, $known_path);
}

/**
 * pfb_list_user_script_active -- issue #1960: a feed with a configured
 * pre/post script must never take an early verbatim-reuse fast path, because
 * the transform has to re-run every pass; this is the same has_user_script
 * term the IP and DNSBL loops' normalization-level reuse-skip gates (the
 * norm_reuse_skip pair, one per loop) already carry at the normalization
 * level. One helper for both loops keeps them in lock-step by construction.
 * $script_pre/$script_post stay untyped: pfb_resolve_list_script() returns
 * FALSE or a string, and both call sites hold that same union.
 */
function pfb_list_user_script_active($script_pre, $script_post): bool {
	return ($script_pre && is_file("{$script_pre}")) ||
	    ($script_post && is_file("{$script_post}"));
}

/**
 * pfb_list_script_reparse_active -- issue #1960 re-runs a configured script's
 * transform every pass, but issue #1278's Hold contract ("download once,
 * never again") is protected ONLY by the early verbatim-reuse fast path, so
 * the script term may push a row off that path SOLELY when a local '.orig'
 * baseline exists to reparse -- the row then routes to the existing
 * local-reuse branch (Reload/Rebuild) and never reaches the network. No
 * baseline -> stay on the fast path; there is no Hold-specific branch
 * anywhere. Sibling one-purpose `_active` predicates in this style:
 * pfb_ip_reuse_skip_active, pfb_dnsbl_verbatim_reuse_active,
 * pfb_supp_update_active. The shared reuse-decision seam calls this once per
 * row for both loops, keeping them in lock-step by construction.
 */
function pfb_list_script_reparse_active(bool $verbatim_reuse_ok, bool $has_user_script, bool $orig_exists): bool {
	return $verbatim_reuse_ok && $has_user_script && $orig_exists;
}

/** @return array{has_user_script:bool,orig_exists:bool,reparse:bool,verbatim:bool} */
function pfb_list_script_reuse_decision(bool $verbatim_reuse_ok, $script_pre, $script_post,
    string $orig_path): array {
	$has_user_script = pfb_list_user_script_active($script_pre, $script_post);
	$orig_exists = is_file($orig_path);
	$reparse = pfb_list_script_reparse_active($verbatim_reuse_ok, $has_user_script, $orig_exists);
	return [
		'has_user_script' => $has_user_script,
		'orig_exists'    => $orig_exists,
		'reparse'        => $reparse,
		'verbatim'       => $verbatim_reuse_ok && !$reparse,
	];
}

function pfb_ip_script_reuse_decision(bool $verbatim_reuse_ok, $script_pre, $script_post,
    string $orig_path): array {
	return pfb_list_script_reuse_decision($verbatim_reuse_ok, $script_pre, $script_post, $orig_path);
}

function pfb_dnsbl_script_reuse_decision(bool $verbatim_reuse_ok, $script_pre, $script_post,
    string $orig_path): array {
	return pfb_list_script_reuse_decision($verbatim_reuse_ok, $script_pre, $script_post, $orig_path);
}

/*
 * Detached fire-and-forget firewall-configuration reload (issue #2878 bound
 * superseded by owner directive 2026-09-05). pfSense's reload is not ours to
 * bound or kill, and the script signals filterd asynchronously anyway (rules
 * land after exit), so the pass neither waits on it nor judges its outcome:
 * output stays discarded so the backgrounded child holds no capture pipe, and
 * the only owned failure is the launch itself.
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

// Main pfBlockerNG function
function sync_package_pfblockerng($cron='', ?string &$deferred_by = NULL): bool {
	global $g, $pfb, $pfbarr;
	$deferred_by = NULL;
	pfb_global();

	// Preserve the internal bool contract: an unattended trigger=cron force=false
	// deferral is benign and retains TRUE with its durable retry state intact.
	// Operator-triggered requests retain FALSE. CLI callers independently map the
	// by-reference lock identity to PFB_EXIT_LOCKED.
	//
	// Only the two lock guards below set $deferred_by. Stage/publish recovery and
	// GeoIP-swap failures keep FALSE with a NULL reason.
	$pfb_deferral_benign = is_array($cron)
		&& ($cron['trigger'] ?? '') === 'cron'
		&& empty($cron['force']);

	// The update owns scheduler state from before feed selection through final publication.
	// Nested calls made by a scheduled tick reuse its existing dispatcher hold.
	$pfb_dispatch_owner = !isset($GLOBALS['pfb_schedule_dispatch_lock'])
		|| !is_resource($GLOBALS['pfb_schedule_dispatch_lock']);
	$pfb_dispatch_contended = FALSE;
	if (!pfb_schedule_dispatch_begin(0.1, $pfb_dispatch_contended)) {
		if (!$pfb_dispatch_contended) {
			pfb_mark_pending_changes();
			pfb_due_ledger_set_pending('cron', $pfb['dbdir']);
			return FALSE;
		}
		$deferred_by = 'dispatcher-lock';
		// issue #2496: pfblockerng.php exits 1 on a FALSE from this function with no
		// other output, so every guard must name itself or the failure is undiagnosable.
		pfb_logger("\n sync aborted: dispatcher lock unavailable; pending changes retained.\n", 1);
		// issue #2505: feed-pass parity (pfb_feed_pass_begin() raises LOG_NOTICE) --
		// a live wedged lock holder must be visible outside /var/log/pfblockerng.
		logger(LOG_NOTICE, localize_text('Feed pass [ sync ] deferred - the scheduler dispatcher lock is unavailable.'),
			LOG_PREFIX_PKG_PFBLOCKERNG);
		pfb_mark_pending_changes();
		return $pfb_deferral_benign;
	}

	// issue #1175: serialize feed passes. Capture ownership BEFORE acquiring -- only the
	// invocation that transitions the lock releases it (a nested reentrant call no-ops).
	$pfb_feed_pass_owner = !isset($GLOBALS['pfb_feed_pass_lock']);
	$pfb_feed_pass_contended = FALSE;
	if (!pfb_feed_pass_begin('sync', $pfb_feed_pass_contended)) {
		if (!$pfb_feed_pass_contended) {
			pfb_mark_pending_changes();
			pfb_due_ledger_set_pending('cron', $pfb['dbdir']);
			if ($pfb_dispatch_owner) {
				pfb_schedule_dispatch_release();
			}
			return FALSE;
		}
		$deferred_by = 'feed-pass-lock';
		// issue #1277: a lost race must not silently drop the GUI Save/Force --
		// mirror pfblockerng_tick()'s 'cron' deferral so the next tick retries.
		pfb_mark_pending_changes();
		pfb_due_ledger_set_pending('cron', $pfb['dbdir']);
		if ($pfb_dispatch_owner) {
			pfb_schedule_dispatch_release();
		}
		return $pfb_deferral_benign;
	}
	if (!pfb_stage_publish_dir_recover($pfb['dbdir'])) {
		pfb_logger("\n sync aborted: stage/publish recovery failed in {$pfb['dbdir']}; pending changes retained.\n", 1);
		pfb_mark_pending_changes();
		if ($pfb_feed_pass_owner) {
			pfb_feed_pass_release();
		}
		if ($pfb_dispatch_owner) {
			pfb_schedule_dispatch_release();
		}
		return FALSE;
	}
	if (!pfb_geoip_generation_ready()) {
		pfb_logger("\n sync aborted: GeoIP generation swap in progress; pending changes retained.\n", 1);
		pfb_mark_pending_changes();
		if ($pfb_feed_pass_owner) {
			pfb_feed_pass_release();
		}
		if ($pfb_dispatch_owner) {
			pfb_schedule_dispatch_release();
		}
		return FALSE;
	}

	// Open the per-run log window for the live viewer (no-op if pfblockerng_sync_cron() already
	// opened it for a Force Check / cron pass -- see pfb_runlog_begin).
	pfb_runlog_begin();

	$pfb['filter_configure']	= FALSE;	// Flag to call filter_configure once

	// ADR-12: TWO pass-scoped accumulators of the names UPDATED this pass,
	// split by side because DNSBL groups are NOT firewall aliases. They feed the
	// 'post' hook's PFB_CHANGED_IP_ALIASES and PFB_CHANGED_DNSBL_GROUPS. Both are
	// initialised empty here so they are always defined at the hook (even on a pass
	// that processes nothing); each is the SINGLE source its post key reads, and each
	// collects names the pass ALREADY decided were updated -- no new tracking
	// machinery. Fed from two existing signals:
	//   * changed_ip_aliases <- the IP-side updated set ($pfb_alias_lists, pfB_*_v4/_v6)
	//     copied in at the tail below.
	//   * changed_dnsbl_groups <- the DNSBL-side per-group feed loop appends the
	//     DNSBL_<group> name only when $pfb['aliasupdate'] is TRUE (a feed in that
	//     group was actually (re)downloaded+parsed -- stays FALSE on file-reuse).
	//     The always-rebuilt specials (DNSBL_IDN/DNSBL_TLD_Allow/DNSBL_Regex) are
	//     added OUTSIDE that loop and are deliberately NOT recorded here.
	// Each is de-duped when emitted. Semantic = "updated this pass" (feeds re-processed
	// / list rebuilt / removed), Reputation-mode-INDEPENDENT (it is NOT $final_alias,
	// which rep mode inflates to all active aliases).
	$pfb['changed_ip_aliases']	= array();
	$pfb['changed_dnsbl_groups']	= array();

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

	// Detect boot process or package installation
	if (is_platform_booting() || $g['pfblockerng_install']) {
		// Create DNSBL NAT, VIP, Lighttpd service and certs if required on reboot.
		if ($pfb['dnsbl'] === PfbToggle::On) {
			pfb_create_dnsbl('enabled');
		}
		$log = 'Sync terminated during boot process.';
		pfb_logger("\n{$log}\nUPDATE PROCESS ENDED\n", 1);
		logger(LOG_INFO, localize_text($log), LOG_PREFIX_PKG_PFBLOCKERNG);
		if ($pfb_feed_pass_owner) {
			pfb_feed_pass_release();
		}
		if ($pfb_dispatch_owner) {
			pfb_schedule_dispatch_release();
		}
		return TRUE;
	}

	// ADR-43: normalize the trigger input.
	// Array = new API (explicit request, no deprecation log).
	// String = back-compat (routes through pfb_trigger_request(); deprecated verbs log once).
	if (is_array($cron)) {
		$pfb_req       = $cron;
		$pfb_hook_val  = pfb_req_to_hook_trigger($pfb_req['trigger']);
		$pfb_is_noups  = FALSE;
		$pfb_cron_tick = ($pfb_req['trigger'] === 'cron' && !$pfb_req['force']);
	} else {
		$pfb_cron_str  = (string) $cron;
		$pfb_dep_warn  = pfb_verb_deprecation_warning($pfb_cron_str);
		if ($pfb_dep_warn !== '') {
			pfb_logger("{$pfb_dep_warn}\n", 1);
		}
		$pfb_req       = pfb_trigger_request($pfb_cron_str);
		$pfb_hook_val  = pfb_hook_trigger($pfb_cron_str);
		$pfb_is_noups  = ($pfb_cron_str === 'noupdates');
		// 'update' is the deprecated CLI verb that historically called sync_package_pfblockerng('cron'),
		// so it got $pfb_cron_tick=TRUE and the reuse_dnsbl propagation below fired.
		// Now it reaches here as 'update' → trigger='manual' → cron_tick FALSE.
		// Restore back-compat for this DEPRECATED STRING path only: treat 'update' like 'cron'
		// for the reuse_dnsbl elseif guard. The new ARRAY path stays unaffected (trigger='manual'
		// from pfb_trigger_request('update') keeps cron_tick FALSE there, as intended).
		$pfb_cron_tick = ($pfb_cron_str === 'cron' || $pfb_cron_str === 'update');
	}

	// ADR-12: pre-update hooks. Fire at the TOP of the pass (after the boot/install
	// early-return above, before any feed processing). 'pre' cannot know what changed
	// yet -- nothing is downloaded -- so its context is just the trigger. No enabled
	// 'pre' hook => pfb_run_hooks() returns immediately (byte-identical pass).
	pfb_run_hooks('pre', array('TRIGGER' => $pfb_hook_val));

	$pfb_run_plan = pfb_sync_run_plan(
		$pfb_req,
		$pfb_is_noups,
		$pfb_cron_tick,
		(string) $pfb['config']['pfb_reuse']
	);
	$pfb['reuse']       = $pfb_run_plan['reuse'];
	$pfb['reuse_dnsbl'] = $pfb_run_plan['reuse_dnsbl'];
	if ($pfb_run_plan['save']) {
		$pfb['save'] = TRUE;
	}
	if ($pfb_run_plan['updatednsbl']) {
		$pfb['updatednsbl'] = TRUE;
	}
	if ($pfb_run_plan['clear_masterfiles']) {
		unlink_if_exists("{$pfb['dbdir']}/masterfile");
		unlink_if_exists("{$pfb['dbdir']}/mastercat");
	}

	// Start of pfBlockerNG logging to 'pfblockerng.log'
	if ($pfb['enable'] === PfbToggle::On && !$pfb['save']) {
		$log = " UPDATE PROCESS START [ " . pfb_pkg_ver() . " ]\n";
		pfb_logger("{$log}", 1);
	} else {
		if (!$pfb_is_noups) {
			$log = "\n**Saving configuration**\n";
			pfb_logger("{$log}", 1);
		}
	}

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
	$pfb['deny_action_inbound']  = $pfb['ipconfig']['inbound_deny_action']	?: 'block';
	$pfb['deny_action_outbound'] = $pfb['ipconfig']['outbound_deny_action']	?: 'reject';

	$pfb['float']		= PfbConfig::read('ip/enable_float');				// Enable/Disable floating autorules
	$pfb['dup']		= PfbConfig::read('ip/enable_dup');				// Enable remove of duplicate IPs utilizing grepcidr
	$pfb['agg']		= PfbConfig::read('ip/enable_agg');				// Enable aggregation of CIDRs
	$pfb['order']		= $pfb['ipconfig']['pass_order'] ?: 'order_0';			// Order of the autorules (default order_0, matching the IP-settings UI; an empty value drops user pass-rules on a managed interface — issue #532)
	$pfb['global_log']	= PfbConfig::read('ip/enable_log');				// Enable Global IP logging
	$pfb['suffix']		= $pfb['ipconfig']['autorule_suffix'];				// Suffix used for autorules
	$pfb['kstates'] 	= PfbConfig::read('ip/killstates');				// Firewall states removal

	$pfb['ip_ph']		= pfb_filter($pfb['ipconfig']['ip_placeholder'], PFB_FILTER_IPV4, 'Placeholder IP Address', '127.1.7.7');	// Placeholder IP Address
	// issue #3140/#3144: pfblockerng.sh init prefers the PHP-exported values; its shell
	// config.xml fallbacks remain for boot and hand-run invocations.
	putenv("PFB_IP_PLACEHOLDER={$pfb['ip_ph']}"); putenv('PFB_REENTRY_TIMEOUT=' . pfb_reentry_budget(NULL));
	putenv('PFB_USE_MFS_TMPVAR=' . (config_path_enabled('system', 'use_mfs_tmpvar') ? '1' : '0'));

	// DNSBL settings
	$pfb['dnsbl_ip']	= pfb_dnsblip_action_value($pfb['dnsblconfig']['action'] ?? NULL);	// Enable/Disable IP blocking from DNSBL lists
	$pfb['dnsbl_rule']	= $pfb['dnsblconfig']['pfb_dnsbl_rule'] ?: 'Disabled';		// Auto create a Floating Pass Rule for other Lan subnets
	$pfb['dnsbl_top1m_cnt']	= $pfb['dnsblconfig']['top1m_count']	?: '1000';		// TOP1M whitelist domain setting
	// DNSBL Python decision-cache cap (LRU); 0 = unlimited. 0 is meaningful so avoid the
	// ?: idiom (0 is falsy), and reject non-numeric input -- else the intval() at the ini
	// emit would coerce a malformed value to 0 = silently unlimited. Clamp to the WebUI range.
	$pfb_dcm_raw = (string) ($pfb['dnsblconfig']['pfb_py_cache_max'] ?? '');
	$pfb['dnsbl_decisiondb_max'] = ctype_digit($pfb_dcm_raw) ? (string) min(5000000, (int) $pfb_dcm_raw) : '10000';
	$pfb['dnsbl_top1m_inc']	= $pfb['dnsblconfig']['top1m_inclusion']?: '';			// TOP1M TLDs inclusions for whitelisting
	$pfb['dnsbl_tld_wildcard']	= $pfb['dnsblconfig']['tld_wildcard'];				// Enable TLD Function
	$pfb['dnsbl_control']	= pfb_cfg_toggle_read($pfb['dnsblconfig']['pfb_control']	?: '');			// Python Control integration
	$pfb['dnsbl_control_legacy']	= pfb_cfg_toggle_read($pfb['dnsblconfig']['pfb_control_legacy']	?? '');	// PFBL-03: deprecated legacy DNS-TXT control transport

	// Validate pfB Script variable
	$pfb['dnsbl_top1m_inc'] = pfb_filter($pfb['dnsbl_top1m_inc'], PFB_FILTER_CSV, 'Validate pfB Script variable');

	// Reputation config variables
	$pfb['config_rep'] = config_get_path('installedpackages/pfblockerngreputation/config/0', []);

	// Validate pfB Script variables
	foreach (array(
			'et_update'		=> 'etupdate',					// Perform a Force Update on ET categories
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
	$pfb_alias_lists	= array();		// An array of aliases that have updated lists via CRON/force update. ('Reputation' disabled)
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

	// Check if DNSBL auto permit rule or DNSBL 'Auto Deny' rules for DNSBL IPs are defined
	if (!empty($pfb['dnsblconfig']['dnsbl_allow_int']) || strpos($pfb['dnsbl_ip'], 'Deny_') !== FALSE) {
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

	foreach (array('inbound', 'outbound') as $type) {
		$pfb["{$type}_interfaces"] = $pfb["{$type}_floating"] = array();

		if (!empty($pfb['ipconfig']["{$type}_interface"])) {
			$interfaces = explode(',', $pfb['ipconfig']["{$type}_interface"]);

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

	#################################################
	#	Clear Removed Lists from Masterfiles	#
	#################################################

	$pfb['sync_master']	= TRUE;		// Process to keep IP Masterfiles in sync with valid Lists from config.conf file
	$pfb['remove']		= FALSE;	// Flag to execute pfctl and rules ordering or reload of DNSBL domains
	$pfb['summary']		= FALSE;	// Execute final summary as a list was removed

	// Don't execute this function when pfBlockerNG is disabled and 'keep blocklists' is enabled.
	if ($pfb['enable'] !== PfbToggle::On && $pfb['keep'] === PfbToggle::On) {
		$pfb['sync_master'] = FALSE;
	}

	if ($pfb['sync_master']) {

		// Find all enabled Continents lists
		foreach ($pfb['continents'] as $continent => $pfb_alias) {
			$cont_key = 'pfblockerng' . strtolower(str_replace(' ', '', $continent));
			if (!empty(config_get_path("installedpackages/{$cont_key}/config")) && $pfb['enable'] === PfbToggle::On) {
				$continent_config = config_get_path("installedpackages/{$cont_key}/config/0");
				if (!pfb_group_action_valid($continent_config['action'] ?? NULL, 'geoip')) {
					continue;
				}
				if ($continent_config['action'] != 'Disabled') {
					foreach ($cont_types as $c_type => $vtype) {
						if (!empty($continent_config[$c_type])) {

							// Force 'Alias Native' setting to any Alias with 'Advanced Inbound/Outbound -Invert src/dst' settings.
							// This will bypass Deduplication and Reputation features.
							if (pfb_dnsbl_toggle_enabled($continent_config['autoaddrnot_in'] ?? '') ||
							    pfb_dnsbl_toggle_enabled($continent_config['autoaddrnot_out'] ?? '')) {
								$pfb['existing']['native'][]		= "{$pfb_alias}{$vtype}";
							}
							else {
								if (strpos($continent_config['action'], 'Match') !== FALSE) {
									$pfb['existing']['match'][]	= "{$pfb_alias}{$vtype}";
								}
								elseif (strpos($continent_config['action'], 'Permit') !== FALSE) {
									$pfb['existing']['permit'][]	= "{$pfb_alias}{$vtype}";
								}
								elseif (strpos($continent_config['action'], 'Deny') !== FALSE) {
									$pfb['existing']['deny'][]	= "{$pfb_alias}{$vtype}";
								}
								elseif ($continent_config['action'] == 'Alias_Native') {
									$pfb['existing']['native'][]	= "{$pfb_alias}{$vtype}";
								}
							}
						}
					}
				}
			}
		}

		// Find all enabled IPv4/IPv6 lists and DNSBL lists
		// Find all enabled IPv4 'Custom List' header names and check if 'Emerging Threats Update' and 'Custom List Update' needs force updating
		$list_types = array(	'pfblockernglistsv4'		=> '_v4',
					'pfblockernglistsv6'		=> '_v6',
					'pfblockerngdnsbl'		=> '_v4'
					);

		$pfb_invalid = FALSE;
		$pfb_reserved_skips = array();	// issue #1270: headers skipped as reserved (batched into one notice below)
		foreach ($list_types as $ltype => $vtype) {
			$lists = array();
			$dnsblip_lists_key = NULL;	// issue #1270: exempts the package's OWN synthesized DNSBLIP row below

			$type_config = config_get_path("installedpackages/{$ltype}/config");
			if (!empty($type_config) && $pfb['enable'] === PfbToggle::On) {
				foreach ($type_config as $list) {
					if (!pfb_group_action_valid($list['action'] ?? NULL, $ltype === 'pfblockerngdnsbl' ? 'dnsbl' : 'ipv4')) {
						continue;
					}

					// If only the 'customlist' is defined. Remove the 'List row' data.
					if (isset($list['row']) && empty($list['row'][0]['url'])) {
						unset($list['row']);
					}

					if (!empty($list['custom'])) {
						$list['row'][] = pfb_dnsbl_custom_row($list['aliasname'], $list['custom']);
					}
					$lists[] = $list;
				}
			}

			// ADD DNSBL IP
			if (($ltype == 'pfblockernglistsv4' || $ltype == 'pfblockernglistsv6') && $pfb['enable'] === PfbToggle::On && $pfb['dnsbl'] === PfbToggle::On
			    && pfb_group_action_valid($pfb['dnsbl_ip'] ?? NULL, 'ipv4') && $pfb['dnsbl_ip'] != 'Disabled') {
				$list = array();
				$list['action'] = "{$pfb['dnsbl_ip']}";
				$list['row'][]	= array('format'	=> 'auto',
							'state'		=> 'Enabled',
							'url'		=> "{$pfb['dbdir']}/DNSBLIP{$vtype}.txt",
							'header'	=> 'DNSBLIP');
				$lists[] = $list;
				$dnsblip_lists_key = array_key_last($lists);
			}

			if (!empty($lists)) {
				foreach ($lists as $key => $list) {

					// Remove any spaces or special characters in existing Aliasnames
					if (preg_match("/\W/", $list['aliasname'])) {
						$pfb_invalid = TRUE;
						$list['aliasname'] = preg_replace("/\W/", '', $list['aliasname']);
						config_set_path("installedpackages/{$ltype}/config/{$key}/aliasname", $list['aliasname']);
					}

					if (isset($list['row']) && $list['action'] != 'Disabled') {

						// Force 'Alias Native' setting to any Alias with 'Advanced Inbound/Outbound -Invert src/dst' settings.
						// This will bypass Deduplication and Reputation features.
						if ($list['action'] != 'unbound' && (pfb_dnsbl_toggle_enabled($list['autoaddrnot_in'] ?? '') ||
						    pfb_dnsbl_toggle_enabled($list['autoaddrnot_out'] ?? ''))) {
							$list['action'] = 'Alias_Native';
						}

						foreach ($list['row'] as $hkey => $row) {

							// issue #1270: normalize (same \W-strip as before) + reject a header
							// colliding with a package-owned name; the DNSBLIP synthesized row is exempt.
							// Cast: a row missing 'header' (foreign config) is NULL, which TypeErrors below.
							$pfb_norm_hdr = pfb_normalize_row_header((string) ($row['header'] ?? ''));
							if ($pfb_norm_hdr['reserved_error'] !== '' && $key !== $dnsblip_lists_key) {
								$pfb_reserved_skips[] = "{$pfb_norm_hdr['header']} ({$ltype})";
								continue;
							}

							if ($pfb_norm_hdr['changed']) {
								$pfb_invalid	= TRUE;
								$row['header']	= $pfb_norm_hdr['header'];
								config_set_path("installedpackages/{$ltype}/config/{$key}/row/{$hkey}/header", $row['header']);
							}

							if ($ltype == 'pfblockerngdnsbl') {
								$header = "{$row['header']}";
							} else {
								$header = "{$row['header']}{$vtype}";
							}

							// Collect enabled lists
							if (!empty($row['url']) && $row['state'] != 'Disabled') {
								if (strpos($list['action'], 'Match') !== FALSE) {
									$pfb['existing']['match'][]	= "{$header}";
								}
								elseif (strpos($list['action'], 'Permit') !== FALSE) {
									$pfb['existing']['permit'][]	= "{$header}";
								}
								elseif (strpos($list['action'], 'Deny') !== FALSE) {
									$pfb['existing']['deny'][]	= "{$header}";
								}
								elseif ($list['action'] == 'Alias_Native') {
									$pfb['existing']['native'][]	= "{$header}";
								}
								elseif ($list['action'] == 'unbound') {
									$pfb['existing']['dnsbl'][]	= "{$header}";
								}
							}
						}
					}
				}
			}
		}

		// Save any existing Alias/Header names that have spaces or special characters
		if ($pfb_invalid) {
			write_config('pfBlockerNG: Remove spaces/special characters in Alias/Header names');
		}

		// issue #1270: one batched notice for every header skipped as reserved this pass
		if (!empty($pfb_reserved_skips)) {
			$pfb_reserved_msg = 'pfBlockerNG: skipped reserved header(s) (collides with a package-owned name): ' . implode(', ', $pfb_reserved_skips);
			pfb_logger("\n\nURGENT:\n    {$pfb_reserved_msg}\n", 1);
			file_notice('pfBlockerNG Header', $pfb_reserved_msg, 'pfBlockerNG', '/pfblockerng/pfblockerng_category_edit.php', 2);
		}

		// If 'TLD' enabled and TLD Blacklists are defined, add to enabled DNSBL lists
		if ($pfb['dnsbl_tld_wildcard']) {
			$tld_wildcard_blacklist = pfb_text_area_decode($pfb['dnsblconfig']['tld_wildcard_blacklist'], TRUE, FALSE, TRUE);
			if (!empty($tld_wildcard_blacklist)) {
				$pfb['existing']['dnsbl'][] = 'DNSBL_TLD';
			}
		}

		// issue #1250: matchgendir artifacts (dMax outputs, ccwhite exempt, ET match) match no
		// config header, so the per-type sweep below can't reap them -- own keep-list/sweep,
		// logged like that sweep so orphan cleanup stays visible in pfblockerng.log.
		$pfb_matchgen_reaped = pfb_matchgen_reap($pfb['existing']['deny'], $pfb['ccwhite'] == 'match', $pfb['matchgendir']);
		if (!empty($pfb_matchgen_reaped)) {
			pfb_logger("\n[ Removing 'matchgen' \tArtifact(s) : " . implode(',', $pfb_matchgen_reaped) . ' ]', 1);
		}

		// Add enabled 'DNSBL Blacklist categories'
		if (isset($pfb['blconfig']) &&
		    $pfb['blconfig']['blacklist_enable'] != 'Disable' &&
		    !empty($pfb['blconfig']['blacklist_selected'])) {

			$selected = array_flip(explode(',', $pfb['blconfig']['blacklist_selected'])) ?: array();
			foreach ($pfb['blconfig']['item'] as $item) {

				if (isset($selected[$item['xml']]) && !empty($item['selected'])) {
					$categories = explode(',', $item['selected']) ?: array();
					foreach ($categories as $category) {
						if (!empty($category)) {
							$category = str_replace('-', '_', $category);
							$pfb['existing']['dnsbl'][] = "{$item['title']}_{$category}";
						}
					}
				}
			}
		}

		// Collect all .txt file names for each list type
		$list_types = array(	'match' => $pfb['matchdir'], 'permit' => $pfb['permitdir'], 'deny' => $pfb['denydir'],
					'native' => $pfb['nativedir'], 'dnsbl' => $pfb['dnsdir']);

		// Collect all previouly downloaded filename headers
		foreach ($list_types as $pftype => $pfbfolder) {

			$pfb_files = glob("{$pfbfolder}/*.txt");
			foreach ($pfb_files as $pfb_list) {
				$pfb['actual'][$pftype][] = basename($pfb_list, '.txt');
			}

			$results = array_diff($pfb['actual'][$pftype], $pfb['existing'][$pftype]);

			// Remove any DNSBL Orig files that are not referenced
			if ($pftype == 'dnsbl') {
				$orig_list = glob("{$pfb['dnsorigdir']}/*.orig");
				if (!empty($orig_list) && is_array($orig_list)) {
					$orig_list_final = array();
					foreach ($orig_list as $pfb_orig) {
						$orig_list_final[] = basename($pfb_orig, '.orig');
					}

					$results_flip = array_flip($pfb['actual'][$pftype]);
					if (!empty($results_flip) && is_array($results_flip)) {
						foreach ($orig_list_final as $orig) {
							if (!isset($results_flip[$orig])) {
								unlink_if_exists("{$pfb['dnsorigdir']}/{$orig}.*");
							}
						}
					}
				}
			}

			if (empty($results)) {
				continue;	// No changes required
			}

			$f_result = implode(',', $results);
			if (empty(pfb_filter($f_result, PFB_FILTER_CSV, 'Failed to complete sync of Feeds'))) {
				pfb_logger("\nFailed to complete sync of Feeds!", 1);
				continue;
			}

			$log = "\n[ Removing '{$pftype}' \tList(s) : {$f_result} ]";
			pfb_logger("{$log}", 1);

			// Process to remove lists from IP Masterfile/DB folder if they are not referenced any longer
			switch ($pftype) {
				case 'deny':
					// Script to Remove un-associated List(s)
					exec("{$pfb['script']} remove x x x {$f_result} {$elog}");
					// issue #1084: drop each removed header's recompute snapshot too, else it
					// outlives this removal and feeds the next recompute pass phantom content.
					// repcheck: a removal must trigger the recompute pass that drops the
					// header's masterfile rows (memberlist completeness).
					foreach ($results as $pfb_removed_header) {
						pfb_ip_recompute_forget_header($pfb_removed_header, $pfb['snapdir'], $pfb['origdir']);
						$pfb['repcheck'] = TRUE;
					}
					$pfb['summary'] = $pfb['remove'] = TRUE;
					break;
				case 'match':
				case 'permit':
				case 'native':
					foreach ($results as $pfb_result) {
						if (!empty(pfb_filter($pfb_result, PFB_FILTER_WORD, "Remove un-associated List - {$pftype}"))) {
							unlink_if_exists("{$pfbfolder}/{$pfb_result}.txt");
							unlink_if_exists("{$pfb['origdir']}/{$pfb_result}.*");
						} else {
							pfb_logger("\nFailed to remove Native Feed [$pfb_result}]", 1);
						}
					}
					$pfb['summary'] = $pfb['remove'] = TRUE;
					break;
				case 'dnsbl':
					foreach ($results as $pfb_result) {
						if (!empty(pfb_filter($pfb_result, PFB_FILTER_WORD, "Remove un-associated List - {$pftype}"))) {
							unlink_if_exists("{$pfb['dnsorigdir']}/{$pfb_result}.*");
						} else {
							pfb_logger("\nFailed to remove DNSBL Feed [{$pfb_result}]", 1);
						}
					}

					rmdir_recursive("{$pfb['dnsdir']}");
					safe_mkdir("{$pfb['dnsdir']}");

					pfb_logger("\n ** DNSBL Changes found, Reloading...\n", 1);
					$pfb['reuse_dnsbl'] = 'on';
					break;
			}

			// Allow rebuilding of changed Alias to purge 'SKIP' Lists (when pfBlockerNG is enabled)
			if ($pfb['enable'] === PfbToggle::On && $pftype != 'dnsbl') {
				foreach ($ip_types as $ltype => $vtype) {
					foreach ($results as $removed_header) {
						foreach (config_get_path("installedpackages/{$ltype}/config", []) as $list) {
							if (!empty($list['row'])) {
								foreach ($list['row'] as $row) {
									$removed = rtrim($removed_header, ',');
									if ($row['header'] == $removed) {
										$pfb['summary'] = $pfb['remove'] = TRUE;

										// Add Alias to update array
										$pfb_alias_lists[]	= "pfB_{$list['aliasname']}{$vtype}";
										$pfb_alias_lists_all[]	= "pfB_{$list['aliasname']}{$vtype}";
									}
								}
							}
						}
					}
				}
			}
		}

		// Remove orphaned IP "original" feed files -- but ONLY for feeds no longer CONFIGURED,
		// never merely because a .txt is currently missing. The .orig is the cached download the
		// reparse/reuse path re-reads, and a configured feed can legitimately have no .txt this
		// pass (reuse/reparse, an empty or all-filtered result), so keying on .txt would delete a
		// live feed's source. origdir is shared by deny/permit/match/native, so reconcile it ONCE
		// against the union of those types' configured headers ($existing, built from config
		// above): a removed feed has no config entry, so its <header>.orig (+ change-detect probe
		// + sidecars) is deleted -- otherwise it lingers forever in the IPv4/6 "Last Updated List
		// Summary" (pfb_list_orig_by_mtime lists every *.orig). Sibling of the DNSBL dnsorigdir
		// prune above, keyed on config (the removed-feed signal) rather than on .txt presence.
		$ip_orig_keep = array_flip(array_merge(
			$pfb['existing']['deny']   ?? [], $pfb['existing']['permit'] ?? [],
			$pfb['existing']['match']  ?? [], $pfb['existing']['native'] ?? []
		));
		foreach (glob("{$pfb['origdir']}/*.orig") ?: [] as $pfb_orig) {
			// {header}.orig (sync baseline) and {header}.md5.orig (change-detect probe) belong to
			// the same feed; strip the probe infix so a live feed's probe file is not mistaken for
			// an orphan (a removed feed's probe file is still swept by the {header}.* unlink).
			$header = basename($pfb_orig, '.orig');
			if (str_ends_with($header, '.md5')) {
				$header = substr($header, 0, -4);
			}
			if (!isset($ip_orig_keep[$header])) {
				unlink_if_exists("{$pfb['origdir']}/{$header}.*");
			}
		}
	}

	#########################################################
	#	Clear Match/Pass/ET/Original Files/Folders	#
	#########################################################

	// When pfBlockerNG is Disabled and 'Keep Blocklists' is Disabled.
	// Runtime toggles are enums; any state other than On disables this path.
	if ($pfb['enable'] !== PfbToggle::On && $pfb['keep'] !== PfbToggle::On && !$pfb['install']) {
		$log = "\n  Removing DB Files/Folders \n";
		pfb_logger("{$log}", 1);
		pfb_clear_contents();
	}

	#################################################
	#	Create IP Suppression Txt File		#
	#################################################

	if ($pfb['enable'] === PfbToggle::On && $pfb['supp'] === PfbToggle::On) {
		pfb_create_suppression_file();
	}

	#########################################
	#	DNSBL - Processes		#
	#########################################

	if (!$pfb['save']) {
		$log = "\n===[  DNSBL Process  ]================================================\n";
		pfb_logger("{$log}", 1);
	}

	// Define DNSBL arrays and variables
	$pfb['alias_dnsbl_all']		= array();	// Array of all DNSBL aliases
	$dnsbl_tld_group_counts		= array();	// Deferred DNSBL group counts for TLD-mode statistics
	$pfb['domain_update']		= FALSE;	// Flag to signal update Unbound
	$pfb['dnsbl_publish_failed']	= FALSE;	// Fixed TOP1M/manifest publication failed; suppress reload
	$pfb['updateip']		= FALSE;	// Flag to signal updates to DNSBL IP lists
	$pfb_py_feeds			= array();	// ADR-06: per-feed manifest rows [header,group,log] for pfb_unbound_python_sources()
	$safesearch_update		= FALSE;	// Flag: SafeSearch CSV changed -> force an Unbound restart (issue #149)
	$pfb_fp_old			= null;		// Fingerprint of loaded input files BEFORE this pass (null => DNSBL not active this pass)

	$dnsbl_error = FALSE;
	if ($pfb['enable'] === PfbToggle::On && $pfb['dnsbl'] === PfbToggle::On && !$pfb['save']) {

		// Terminate if DNSBL VIP is empty
		if (empty($pfb['dnsbl_port']) || empty($pfb['dnsbl_port_ssl'])) {
			$log = "\n\n===[  DNSBL Ports are not defined. Exiting  ]======\n";
			pfb_logger("{$log}", 1);
			$dnsbl_error = TRUE;
		}
	}

	if ($pfb['enable'] === PfbToggle::On && $pfb['dnsbl'] === PfbToggle::On && !$pfb['save'] && !$dnsbl_error) {
		if ((config_get_path('installedpackages/pfblockerngdnsbl/config') != null) ||
		    (config_get_path('installedpackages/pfblockerngblacklist/blacklist_enable') == 'Enable')) {

			$dnsbl_missing = FALSE;

			// Collect existing DNSBL group statistics
			// SQLite3 Database format [ group name, updated timestamp, total domain count, total blocked count ]

			$pfb['dnsbl_info_stats'] = array();
			if (file_exists("{$pfb['dnsbl_info']}")) {
				pfb_logger("\n Loading DNSBL Statistics...", 1);

				$db_handle = pfb_open_sqlite(1, 'Reading DNSBL database');
				if ($db_handle) {
					$result = $db_handle->query("SELECT * FROM dnsbl;");
					if ($result) {
						while ($res = $result->fetchArray(SQLITE3_ASSOC)) {
							$pfb['dnsbl_info_stats'][] = $res;
						}
					}
				}
				else {
					pfb_logger(" FAILED", 1);
					unlink_if_exists("{$pfb['dnsbl_info']}");
					$dnsbl_missing = TRUE;
				}

				pfb_close_sqlite($db_handle);
				pfb_logger(" completed", 1);
			}
			else {
				$dnsbl_missing = TRUE;
			}


			// ADR-65: the health check reads the manifest boundary directly.
			if (pfb_dnsbl_manifest_missing($pfb)) {
				$dnsbl_missing = TRUE;
			}

			if ($dnsbl_missing) {
				$log = "\n Missing DNSBL stats and/or Unbound DNSBL files - Rebuilding\n";
				pfb_logger("{$log}", 1);
				$pfb['reuse_dnsbl'] = 'on';
				touch("{$pfb['dnsbl_file']}.reload");
			}

			// SafeSearch
			pfb_logger("\n Loading DNSBL SafeSearch...", 1);
			$safesearch_hosts = array();
			$pfb['safesearch_tlds'] = array();
			$safesearch_types = array(	array( 'safesearch_enable',	'Enable',	'safesearch'),
							array( 'safesearch_youtube',	'Strict',	'youtube_restrict'),
							array( 'safesearch_youtube',	'Moderate',	'youtube_restrictmoderate'),
							array( 'safesearch_doh',	'Enable',	'doh')
							);

			$safesearch_update = $pfb_found = FALSE;
			$CNAME_LOG = '';

			// Remove deprecated firefox conf file
			if (file_exists("{$pfb['dnsbldir']}/pfb_dnsbl.firefoxdoh.conf")) {
				unlink_if_exists("{$pfb['dnsbldir']}/pfb_dnsbl.firefoxdoh.conf");
				$safesearch_update = TRUE;
			}

			foreach ($safesearch_types as $safe_type) {
				if ($pfb[$safe_type[0]] == $safe_type[1]) {
					$pfb_found = TRUE;

					// SafeSearch DoH validation (Add/remove comment '#' to DoH entries)
					if ($safe_type[0] == 'safesearch_doh') {
						$doh_file = file($pfb["dnsbl_{$safe_type[2]}"]);
						if (!empty($doh_file)) {
							$doh_file_final = '';
							foreach ($doh_file as $host) {
								if (strpos($host, '#') !== FALSE) {
									$host = ltrim(str_replace('#', '', $host));
								}

								$doh_found = FALSE;
								if (!empty($pfb['safesearch_doh_list'])) {
									foreach ($pfb['safesearch_doh_list'] as $doh) {
										if (strpos($host, $doh) !== FALSE) {
											$doh_found = TRUE;
											break;
										}
									}
								}
								if (!$doh_found) {
									$doh_file_final .= "# {$host}";
								} else {
									$doh_file_final .= "{$host}";
								}
							}
							if (!empty($doh_file_final)) {
								@file_put_contents($pfb["dnsbl_{$safe_type[2]}"], $doh_file_final, LOCK_EX);
							}
						}
					}


					// pfBlockerNG <= 3.2.x wrote the SafeSearch CNAMEs (duckduckgo /
					// pixabay) to a native Unbound-mode local-data conf and included it.
					// The CNAME redirect is now done in Python (issue #149), so drop any
					// leftover native conf on upgrade (its include line is stripped in
					// pfb_unbound_dnsbl()).
					unlink_if_exists("{$pfb['dnsbldir']}/pfb_dnsbl.{$safe_type[2]}.conf");

					$safesearch_file = file($pfb["dnsbl_{$safe_type[2]}"]);
					if (!empty($safesearch_file)) {
						foreach ($safesearch_file as $host) {

							if (str_starts_with($host, '#')) {
								continue;
							}

							$line = str_replace('"', '', strstr($host, '"', FALSE));
							$host_ip = trim(str_replace('A ', '', strstr($line, 'A ', FALSE)));
							$domain = strstr($line, ' ', TRUE);
							if (str_starts_with($domain, 'www.')) {
								$domain = substr($domain, 4);
							}

							if (strpos($line, ' A ') !== FALSE) {
								$safesearch_hosts[$domain]['A'] = $host_ip;
							} elseif (strpos($line, ' AAAA ') !== FALSE) {
								$safesearch_hosts[$domain]['AAAA'] = $host_ip;

							// CNAME SafeSearch (duckduckgo.com / pixabay.com): redirected in
							// Python via a cache-planted CNAME the iterator chases (issue
							// #149). Store a 'cname' entry; the CSV writer below bakes the
							// target's A/AAAA as the #2 fallback.
							} elseif (strpos($line, ' CNAME ') !== FALSE) {
								$cname = trim(str_replace('CNAME ', '', strstr($line, 'CNAME', FALSE)));
								$safesearch_hosts[$domain]['A'] = 'cname';
								$safesearch_hosts[$domain]['AAAA'] = $cname;
							} elseif (strpos($line, 'always_nxdomain') !== FALSE) {
								$safesearch_hosts[$domain]['nxdomain'] = '';
							}
						}
					}

				}
				elseif (file_exists("{$pfb['dnsbldir']}/pfb_dnsbl.{$safe_type[2]}.conf")) {
					unlink("{$pfb['dnsbldir']}/pfb_dnsbl.{$safe_type[2]}.conf");
					$safesearch_update = TRUE;
				}
			}

			// Python mode create a CSV list of SafeSearch hosts
			if (!empty($safesearch_hosts)) {
				foreach ($safesearch_hosts as $host => $data) {
					$v4 = $v6 = '';
					// CNAME redirect: bake the target's current A/AAAA as the #2
					// fallback (issue #149); the freshness cron keeps them current.
					if (($data['A'] ?? '') === 'cname') {
						list($v4, $v6) = pfb_ss_resolve_target($data['AAAA'] ?? '');
					}
					@file_put_contents('/var/unbound/pfb_py_ss.raw', pfb_ss_csv_rows($host, $data, $v4, $v6), FILE_APPEND);
				}

				// Copy file if not exists or has been updated
				if (!file_exists("{$pfb['unbound_py_ss']}") ||
				    @md5_file("{$pfb['unbound_py_ss']}") !==
				    @md5_file('/var/unbound/pfb_py_ss.raw')) {
					@rename('/var/unbound/pfb_py_ss.raw', "{$pfb['unbound_py_ss']}");
					$safesearch_update = TRUE;
					touch("{$pfb['dnsbl_file']}.reload");
				}
				unlink_if_exists('/var/unbound/pfb_py_ss.raw');
			}
			else {
				// SafeSearch off (no hosts): drop the CSV. If one existed, flag a
				// change so Unbound RESTARTS and the module clears its loaded
				// safeSearchDB (issue #149 -- init-only; the data swap won't clear it,
				// so without this a disabled SafeSearch keeps redirecting until restart).
				if (file_exists("{$pfb['unbound_py_ss']}")) {
					$safesearch_update = TRUE;
				}
				unlink_if_exists("/var/unbound/pfb_py_ss.*");
			}

			// Wildcard whitelist SafeSearch domains (Unbound mode only)
			$pfb_whitelist = '';


			$s_log = ' disabled';
			if ($pfb_found) {
				$s_log = ' enabled';
			}
			pfb_logger("{$s_log}{$CNAME_LOG}", 1);

			// Fingerprint the Python-loaded input files BEFORE this pass rewrites them.
			// issue #1255: pfb_dnsbl_reload_fingerprint() narrows the path set (excludes
			// data/zone) in TLD mode instead of nulling the whole comparison -- see its
			// docblock.
			$pfb_fp_old = pfb_dnsbl_reload_fingerprint($pfb);

			// Collect Whitelist, create string, and save to file (for grep -vF -f cmd)
			pfb_logger("\n Loading DNSBL Whitelist...", 1);
			$pfb_white = pfb_text_area_decode($pfb['dnsblconfig']['whitelist'], TRUE, FALSE, TRUE);
			if (!empty($pfb_white)) {
				foreach ($pfb_white as $line) {
					if (!empty($line)) {
						$wildcard = FALSE;
						if (str_starts_with($line, '.')) {
							$line = pfb_strip_wildcard_marker($line, 'DNSBL Whitelist');
							if (pfb_is_blank($line)) {
								continue;
							}
							$wildcard = TRUE;
						}

						// Remove 'www.' prefix
						if (str_starts_with($line, 'www.')) {
							$line = substr($line, 4);
						}

						if ($wildcard) {
							$pfb_whitelist .= ".{$line},,\n,{$line},,\n";
						} else {
							$pfb_whitelist .= ",{$line},,\n,www.{$line},,\n";
						}
					}
				}
			}

			//  Added due to SWC Feed
			$pfb_whitelist .= ",localhost.localdomain,,\n";

			@file_put_contents("{$pfb['dnsbl_supptxt']}", $pfb_whitelist, LOCK_EX);
			pfb_logger(" completed", 1);



			// Call TOP1M whitelist process
			if ($pfb['dnsbl_top1m'] === PfbToggle::On) {
				pfb_logger("\n Loading TOP1M Whitelist...", 1);

				// Check if TOP1M database and the detector's raw baseline exist.
				if (pfb_top1m_refresh_needed($pfb['dbdir'])) {
					// Check if TOP1M download already in progress
					exec('/bin/ps -wax', $result_cron);
					if (!preg_grep("/pfblockerng[.]php\s+al/", $result_cron)) {
						$log = "\n TOP1M Database downloading ( approx 21MB ) ... Please wait ...\n";
						pfb_logger("{$log}", 1);
						pfb_top1m_fetch_if_needed($pfb['dbdir']);

						// Download attempted above (blocking exec) -- top-1m.csv still
						// missing means the fetch failed (404/timeout/invalid). Warn
						// rather than silently keeping (or wiping) any prior whitelist
						// (issue #886); pfblockerng_top1m() below is not invoked when a
						// previous whitelist exists and no top-1m.update marker was set.
						// Not unit-tested: this exec()'s a real download attempt --
						// deep pfSense-runtime integration is the live-VM smoke's job
						// (tests/php/README.md "Out of scope"; ADR-04).
						if (!file_exists("{$pfb['dbdir']}/top-1m.csv")) {
							pfb_logger("\n  TOP1M: feed download failed -- keeping the previous TOP1M whitelist (if any).\n", 2);
						}
					}
					else {
						$log = "\n TOP1M download already in process...\n";
						pfb_logger("{$log}", 1);
					}
				}

				// Process TOP1M database
				if (pfb_top1m_apply_reprocess_if_ready($pfb['dbdir'], 'pfblockerng_top1m')) {
					$pfb['reuse_dnsbl'] = 'on';
					touch("{$pfb['dnsbl_file']}.reload");
					pfb_logger("\n DNSBL - TOP1M changes found - Rebuilding!\n", 1);
				}
				pfb_logger(" completed", 1);
			}
			pfb_logger("\n", 1);

			// List of invalid Domains to skip parsed failed logging function
			$dnsbl_skip = array_flip (array('broadcasthost',
							'local',
							'localhost',
							'<pre>',
							'Vault',
							'Site',
							'list',
							'::1',
							':',
							'ip6-localhost',
							'ip6-localnet',
							'ip6-mcastprefix',
							'ip6-allnodes',
							'ip6-allrouters',
							'ip6-allhosts'
							));

			// List of Alienvault OTX Indicator Types
			$alienvault_types = array_flip(array('domain', 'hostname', 'URL'));

			// Collect feeds and custom list configuration and format into one array ($lists).
			$lists = array();

			// Add DNSBL Category to '$lists array'
			if (isset($pfb['blconfig']) &&
			    $pfb['blconfig']['blacklist_enable'] != 'Disable' &&
			    !empty($pfb['blconfig']['blacklist_selected'])) {

				$bl_count = 0;
				$bl_validate = FALSE;

				$selected = array_flip(explode(',', $pfb['blconfig']['blacklist_selected'])) ?: array();
				foreach ($pfb['blconfig']['item'] as $item) {
					$type = "{$item['xml']}";

					if (isset($selected[$type]) && !empty($item['selected'])) {

						$bl_count++;
						$categories = explode(',', $item['selected']) ?: array();

						$list			= array();
						$list['aliasname']	= "{$item['title']}";
						$list['action']		= 'unbound';
						$list['logging']	= $pfb['blconfig']['blacklist_logging'] ?: 'enabled';
						$list['filter_top1m']	= '';

						$feedname	= strtolower($item['title']);
						$update_flag	= "{$pfb['dbdir']}/{$feedname}/{$feedname}.update";

						foreach ($categories as $category) {

							// Replace dash to underscore in Header name
							$category = str_replace('-', '_', $category);

							if (!empty($category)) {
								$list['row'][] = array(	'format'	=> 'auto',
											'state'		=> 'Enabled',
											'url'		=> "{$pfb['dbdir']}/{$type}/{$type}_{$category}",
											'header'	=> "{$item['title']}_{$category}"
											);

								// If update available set Update flag for each selected Category
								if (file_exists("{$update_flag}")) {
									touch("{$pfb['dnsdir']}/{$item['title']}_{$category}.update");
								}
							}
						}
						unlink_if_exists("{$update_flag}");

						if (isset($list['row'])) {
							$lists[] = $list;
						}

						// Check if Blacklist database has not been previously downloaded
						if (!is_dir("{$pfb['dbdir']}/{$type}") ||
						    is_dir("{$pfb['dbdir']}/{$type}") && (count(scandir("{$pfb['dbdir']}/{$type}")) <= 2)) {
							if (!is_array($bl_validate)) {
								$bl_validate = array();
							}
							$bl_validate[$type] = $item['size'];
						}
					}
				}

				// Download Blacklist databases that are not previously downloaded
				if ($bl_validate) {

					// Create commandline arguments for download script
					$bl_string = $bl_sources = '';
					foreach ($bl_validate as $type => $size) {
						$bl_string	.= ",{$type}";
						$bl_sources	.= " {$type} (~{$size}MB) |";
					}

					if (!empty(pfb_filter($bl_string, PFB_FILTER_CSV, 'Blacklist database commandline arguments'))) {
						$bl_string	= ltrim($bl_string, ',');
						$bl_sources	= rtrim($bl_sources, ' |');

						// Check if Blacklist download already in progress
						exec('/bin/ps -wax', $result_cron);
						if (!preg_grep("/pfblockerng[.]php\s+?(bl|bls)/", $result_cron)) {

							$log = "\nDownloading Blacklist Database(s) [{$bl_sources} ] ... Please wait ...\n";
							pfb_logger("{$log}", 1);
							pfb_reentry_exec('bls', ['scheduled', $bl_string], NULL, $pfb_return);

							if (is_array($pfb_return)) {
								foreach ($pfb_return as $return_output) {
									pfb_logger("{$return_output}\n", 1);
								}

								// On download failure, remove the associated Blacklist category
								// by matching the feed NAME in the child's output line, not the
								// stdout-line index (the child skips already-downloaded/some feeds,
								// so the index does not map to $lists) — #711.
								$lists = pfb_prune_failed_bl_lists($lists, $pfb_return);
							}
						}
						else {
							$log = "\nBlacklist Database download already in process... Try again later...\n";
							pfb_logger("{$log}", 1);

							// Remove Blacklist Category updates until database download is completed
							while ($bl_count != 0) {
								array_pop($lists);
								$bl_count--;
							}
						}
					}
					else {
						pfb_logger("\n Invalid Blacklist arguments [{$bl_string}]", 1);
					}
				}
				else {
					pfb_logger(" Blacklist database(s) ... exists.\n", 1);
				}
			}

			foreach (config_get_path('installedpackages/pfblockerngdnsbl/config', []) as $list) {
				if (!pfb_group_action_valid($list['action'] ?? NULL, 'dnsbl')) {
					continue;
				}
				// If only the 'customlist' is defined. Remove the 'List row' data.
				if (isset($list['row']) && empty($list['row'][0]['url'])) {
					unset($list['row']);
				}

				if (!empty($list['custom'])) {
					$list['row'][] = pfb_dnsbl_custom_row($list['aliasname'], $list['custom']);
				}

				// Move DNSBL Group to primary position before the Blacklist settings
				if ($list['order'] == 'primary') {
					$list_primary = array();
					$list_primary[] = $list;
					$lists = array_merge($list_primary, $lists);
				} else {
					$lists[] = $list;
				}
			}

			// issue #1494: the empty-header skip message below reads $logtab before
			// its per-row assignment when the very first row hits that branch.
			$logtab = '';

			foreach ($lists as $list) {

				// Reset variables once per alias
				$pfb['aliasupdate']	= FALSE;		// Flag to signal changes to alias
				$pfb['domain_clear']	= FALSE;		// Flag to signal no Aliases defined or all Aliases disabled.
				$alias_cnt		= 0;
				// issue #1048: per-alias-pass failure flag -- a sibling feed's success must
				// never close a DIFFERENT feed's still-open download-failure ledger entry.
				$pfb_dl_failed		= FALSE;
				// issue #1958: per-alias-pass script state is independent for each alias.
				$pfb_script_state = ['failed' => FALSE];

				$alias = "DNSBL_{$list['aliasname']}";
				if (empty(pfb_filter($alias, PFB_FILTER_WORD, 'DNSBL - Processes'))) {
					pfb_logger("\n Invalid Aliasname:{$list['aliasname']}, *skipping*", 1);
					continue;
				}

				if ($list['action'] != 'Disabled' && isset($list['row'])) {
					$pfb['alias_dnsbl_all'][]	= "{$alias}";

					// cURL Source Interface (sets CURLOPT_INTERFACE) — per-DNSBL-group
					// field, mirrors the IP loop. Previously $srcint was undefined here
					// (only assigned later in the IP loop), so the configured interface was
					// silently ignored on DNSBL ingest (#712). '?? '' keeps a legacy DNSBL
					// config with no srcint field warning-free.
					$srcint = $list['srcint'] ?? '' ?: FALSE;

					// DNSBL Advanced Tunable - (Pre/Post Script processing) — issue #1926:
					// pickers were saved but never executed; mirrors the IP loop.
					$pfb_dnsbl_script_pre  = FALSE;
					$pfb_dnsbl_script_post = FALSE;
					if (!empty($list['script_pre'])) {
						$pfb_dnsbl_script_pre = pfb_resolve_list_script($list['script_pre']);
					}
					if (!empty($list['script_post'])) {
						$pfb_dnsbl_script_post = pfb_resolve_list_script($list['script_post']);
					}
					foreach ($list['row'] as $key => $row) {
						$pfb_row_script_pre  = $pfb_dnsbl_script_pre;
						$pfb_row_script_post = $pfb_dnsbl_script_post;
						if (!empty($row['url']) && $row['state'] != 'Disabled') {

							// Empty header field validation check
							$header		= pfb_filter($row['header'], PFB_FILTER_WORD, 'DNSBL - Processes');
							if (empty($header)) {
								$log = "\n[ {$row['url']} ]{$logtab} Header Field cannot be empty. *Skipping* \n";
								pfb_logger("{$log}", 2);
								continue;
							}
							$header_esc	= escapeshellarg($header);

							$rev_format	= FALSE;	// Host style format is reversed
							$domain_data_ip	= array();	// Array of IPs found in feed
							$domain_data_ip6 = array();	// Array of IPv6 IPs found in feed
							$domain_data	= '';		// List of Domains found in feed

							// If row is a custom_list, set flag.
							if (isset($row['custom'])) {
								$custom = TRUE;
							} else {
								$custom = FALSE;
							}

							// ADR-31: per-row action → manifest mode.
							// 'action' is a dynamic per-row key (like 'custom') — read
							// directly; default/absent ⇒ 'Deny' (deny path, byte-identical).
							// Config storage freeze (ADR-28): only 'Permit'/'Deny' are stored;
							// absent is treated as 'Deny'.
							$mode = (($row['action'] ?? '') === 'Permit') ? 'permit' : 'deny';

							// Global DNSBL Logging/Blocking mode
							if (!empty($pfb['dnsbl_global_log'])) {
								$list['logging'] = $pfb['dnsbl_global_log'];
							}

							// Force Unbound mode Logging for 'disabled_log' to 'enabled'


							// If Null Blocking mode is selected, use '0.0.0.0|::0', otherwise utilize DNSBL WebServer/DNSBL VIP
							// NXDOMAIN modes ('3'/'4', issue #31) emit a bare NXDOMAIN in pfb_unbound.py; no sinkhole IP applies.
							if ($list['logging'] == 'disabled') {
								$logging_type	= '2';	// Null Blocking no logging
							}
							elseif ($list['logging'] == 'disabled_log') {
								$logging_type	= '0';	// Null Blocking logging
							}
							elseif ($list['logging'] == 'nxdomain_log') {
								$logging_type	= '3';	// NXDOMAIN logging
							}
							elseif ($list['logging'] == 'nxdomain') {
								$logging_type	= '4';	// NXDOMAIN no logging
							} else {
								$logging_type	= '1';	// DNSBL VIP logging
							}

							// Determine 'list' details (return array $pfbarr)
							pfb_determine_list_detail($list['action'], $header, 'pfblockerngdnsblsettings', '0');
							$pfbadv		= $pfbarr['adv'];
							$pfbfolder	= $pfbarr['folder'];
							$pfborig	= $pfbarr['orig'];
							$pfbreuse	= $pfbarr['reuse'];
							$logtab		= $pfbarr['logtab'];

							$txt_exists	= file_exists("{$pfbfolder}/{$header}.txt");
							$scheduled_selected = pfb_schedule_feed_selected('dnsbl', $header);
							if (!$scheduled_selected && !$txt_exists) {
								continue;
							}
							$reuse_unset	= $pfbreuse == '';
							$staging_current_generation = pfb_dnsbl_staging_is_current_generation(
								pfb_dnsbl_staging_first_line("{$pfbfolder}/{$header}.txt"));
							if (!$scheduled_selected) {
								$pfb_row_script_pre = $pfb_row_script_post = FALSE;
								$staging_current_generation = TRUE;
							}

							// issue #1960/#1278: a configured pre/post script re-runs its transform
							// every pass, but the Hold contract ("download once, never again") is
							// protected ONLY by this fast path -- so the script term may push a row
							// off it solely when a local '.orig' baseline exists to reparse (routes
							// to the existing local-reuse branch below, never the network). No
							// baseline -> stay on the fast path; no Hold-specific branch anywhere.
							// (the #1083 stale-generation re-call below is a DIFFERENT question
							// and stays deliberately ungated -- see the comment there).
							$pfb_dnsbl_verbatim_reuse = pfb_dnsbl_verbatim_reuse_active(
								$txt_exists,
								$scheduled_selected && file_exists("{$pfbfolder}/{$header}.update"),
								$scheduled_selected && file_exists("{$pfbfolder}/{$header}.fail"),
								$reuse_unset,
								$staging_current_generation);
							$pfb_dnsbl_reuse_decision = pfb_dnsbl_script_reuse_decision(
								$pfb_dnsbl_verbatim_reuse, $pfb_row_script_pre, $pfb_row_script_post,
								"{$pfborig}/{$header}.orig");
							$pfb_dnsbl_user_script = $pfb_dnsbl_reuse_decision['has_user_script'];
							$pfb_dnsbl_script_reparse = $pfb_dnsbl_reuse_decision['reparse'];

							if ($pfb_dnsbl_reuse_decision['verbatim']) {


								if ($row['state'] == 'Hold') {
									$log = "\n[ {$header} ]{$logtab} static hold.";
								} else {
									$log = "\n[ {$header} ]{$logtab} exists.";
								}
								pfb_logger("{$log}", 1);

								// Collect existing list stats
								$lists_dnsbl_all[]	= "{$row['header']}.txt";
								// ADR-31: delegate to pfb_feed_manifest_row() (deny default).
								// ADR-31: pass $mode derived from per-row 'action' (above).
								$pfb_py_feeds[]		= pfb_feed_manifest_row(
									$header, $alias, $logging_type,
									$custom ? 'user' : 'feed',
									$mode);
								// issue #1162/#1261: pfb_count_lines() returns NULL on a read
								// failure -- 0 preserves the exec()-era fallback.
								$alias_cnt		= pfb_dnsbl_alias_count_verbatim("{$pfbfolder}/{$header}.txt", $alias_cnt);
							}
							else {
								// #1083/#1960: this branch is entered when the fast-path check above
								// is FALSE -- either the FILE-STATE conditions rejected verbatim reuse
								// (staging generation, txt/update/fail existence, reuse toggle), OR
								// they all held but $pfb_dnsbl_script_reparse pushed the row off the
								// fast path (a configured script with a local '.orig' baseline to
								// reparse). Rebuild via the same reparse-from-.orig machinery a Reload
								// uses, never a network refetch when .orig is available.
								// issue #1960: this re-call is deliberately NOT gated by
								// $pfb_dnsbl_user_script/$pfb_dnsbl_script_reparse -- it answers a
								// DIFFERENT question than the fast path above ("among the file-state
								// conditions, was stale staging generation the ONLY reason reuse was
								// rejected?"). A stale-generation .txt with a configured script still
								// re-runs its pre-script on this cheaper reparse (the
								// normalize/reuse-skip call below is FALSE anyway here, since
								// $downloaded_fresh is FALSE); gating this call would only force an
								// unneeded network refetch for that case, silently changing #1083's
								// Rebuild / pfb_dnsbl_hold_stale_rebuild_skip /
								// pfb_dnsbl_stale_rebuild_converge_txt behaviour that nobody asked for.
								$stale_generation_rebuild = !$staging_current_generation &&
									pfb_dnsbl_verbatim_reuse_active(
										$txt_exists,
										file_exists("{$pfbfolder}/{$header}.update"),
										file_exists("{$pfbfolder}/{$header}.fail"),
										$reuse_unset,
										TRUE);
								// issue #1278: OR in the script-reparse route so a scripted row with
								// a local '.orig' baseline reuses it (Reload, never a network
								// refetch); a Hold row with no baseline never reaches this branch at
								// all (see the fast path above).
								$pfbreuse_effective = $pfbreuse == 'on' || $stale_generation_rebuild ||
									$pfb_dnsbl_script_reparse;

								if ($stale_generation_rebuild) {
									$log = "\n[ {$header} ]{$logtab} Rebuild";
								} elseif ($pfbreuse_effective && file_exists("{$pfborig}/{$header}.orig")) {
									$log = "\n[ {$header} ]{$logtab} Reload";
								} else {
									$log = "\n[ {$header} ]{$logtab} Downloading update";
								}
								pfb_logger("{$log}", 1);
								$file_dwn = "{$pfborig}/{$header}";
								$orig_content_stale = FALSE;
								$downloaded_fresh = FALSE;

								// issue #1278: Hold means "download once, never again" -- skip the network
								// fallback entirely and retry next pass; staging stays untouched.
								if (pfb_dnsbl_hold_stale_rebuild_skip($stale_generation_rebuild, $row['state'] == 'Hold', file_exists("{$file_dwn}.orig"))) {
									pfb_logger(" -- Hold: staying held, no baseline to reparse.\n", 1);
									continue;
								}

								if (!$custom) {
									pfb_logger(' .', 1);

									// Allow cURL SSL downgrade 'Flex' if user configured.
									$pflex = FALSE;
									if ($row['state'] == 'Flex') {
										$pflex = TRUE;
									}

									// Determine if list needs to be downloaded or reuse previously downloaded file.
									if ($pfbreuse_effective && file_exists("{$file_dwn}.orig")) {
										// File exists/reuse
										pfb_logger(' completed .', 1);
									} else {
										// Download file
										if (!(pfb_download(new PfbDownloadRequest(
											listUrl: $row['url'],
											downloadPath: $file_dwn,
											flex: $pflex,
											header: $header,
											format: $row['format'],
											logType: 1,
											versionType: '',
											timeout: 300,
											type: '',
											username: '',
											password: '',
											sourceInterface: $srcint,
											extraHeaders: array(),
										))->success)) {

											// Determine reason for download failure
											pfb_download_failure($alias, $header, $pfbfolder, $row['url'], $row['format'], '');
											// ADR-61: keyed on $alias (pfB_/DNSBL_-prefixed), not $header --
											// the widget's deep-link match needs that prefix (issue #998).
											// issue #1048: close moves to once-per-alias-pass below, so a
											// sibling feed's success can never mask this failure.
											$pfb_dl_failed = TRUE;
											pfb_download_ledger_failure('dnsbl', $alias, $header, $pfb['dbdir']);

											// Utilize previously download file (If 'fail' marker exists)
											if (file_exists("{$pfbfolder}/{$header}.fail") &&
											    file_exists("{$file_dwn}.orig")) {
												pfb_logger("\n  Restoring previously downloaded file\n ", 2);
												$orig_content_stale = TRUE;
											} else {
												continue;
											}
										}
										else {
											// Clear any previous download fail marker
											unlink_if_exists("{$pfbfolder}/{$header}.fail");
											$downloaded_fresh = TRUE;
											if (!empty($pfb['scheduled_runtime_cron'])) {
												pfb_schedule_state_record_outcome(
													"dnsbl:{$header}", PfbScheduleTerminalResult::Success,
													(string) ($pfb['schedule_state_dir'] ?? '/usr/local/etc')
												);
											}
										}
									}
								}
								else {
									// Collect custom list data.
									$custom_list = pfb_text_area_decode($row['custom'], FALSE, TRUE, TRUE);
									@file_put_contents("{$file_dwn}.orig", $custom_list, LOCK_EX);
									unset($custom_list);
								}

								// issue #1797: normalize once per file; the parse below reads .norm
								// (raw .orig on normalize failure). A fresh download whose NORMALIZED
								// content is byte-identical to the previous pass reuses the staged
								// '.txt' the same way the verbatim-reuse branch does.
								$pfb_norm = pfb_feed_normalize("{$file_dwn}.orig");
								if (pfb_dnsbl_norm_reuse_skip($downloaded_fresh, (bool) $custom, $orig_content_stale,
								    $pfb_norm['changed'], file_exists("{$pfbfolder}/{$header}.txt"), $staging_current_generation,
								    $pfb_dnsbl_user_script)) {
									pfb_logger("\n[ {$header} ]{$logtab} unchanged after normalization.", 1);
									$lists_dnsbl_all[]	= "{$row['header']}.txt";
									// ADR-31: same manifest-row shape as the verbatim-reuse branch above.
									$pfb_py_feeds[]		= pfb_feed_manifest_row(
										$header, $alias, $logging_type,
										$custom ? 'user' : 'feed',
										$mode);
									$alias_cnt		= pfb_dnsbl_alias_count_norm_skip("{$pfbfolder}/{$header}.txt", $alias_cnt);
									unlink_if_exists("{$pfbfolder}/{$header}.update");
									continue;
								}

								// issue #1926: DNSBL pre-script runs on a staged copy of the
								// normalized output (#1925 shape); a failed transform keeps the
								// last known-good staging and the '.update' marker for retry.
								$pfb_parse_path = $pfb_norm['path'];
								$pfb_staged_path = NULL;
								if ($pfb_row_script_pre && is_file("{$pfb_row_script_pre}")) {
									pfb_logger("\nExecuting pre-script: {$list['script_pre']}\n", 1);
									$pfb_pre = pfb_list_pre_script_run($pfb_norm['path'], "{$file_dwn}.pre",
									    $pfb_row_script_pre, $list['script_pre'], $header,
									    escapeshellarg("{$file_dwn}.pre") . " dnsbl {$elog}");
									if (!$pfb_pre['ok']) {
										// issue #1958: pre-script failure genuinely served last-known-good --
										// mark it in the ledger (distinct 'script' stage, never 'download') and
										// retry the transform on the next ordinary pass via the '.update' marker.
										pfb_dnsbl_script_failure_continue($alias,
										    "[ {$alias} - {$header} ] Pre-script FAIL - serving last known-good",
										    $pfb['dbdir'], "{$pfbfolder}/{$header}.update", $pfb_script_state,
										    $staging_current_generation, "{$pfbfolder}/{$header}.txt",
										    static function () use (&$lists_dnsbl_all, &$pfb_py_feeds, &$alias_cnt,
										        $row, $header, $alias, $logging_type, $custom, $mode, $pfbfolder): void {
										        $lists_dnsbl_all[] = "{$row['header']}.txt";
										        $pfb_py_feeds[] = pfb_feed_manifest_row(
										            $header, $alias, $logging_type, $custom ? 'user' : 'feed', $mode);
										        $alias_cnt = pfb_dnsbl_alias_count_script_failure("{$pfbfolder}/{$header}.txt", $alias_cnt);
										    });
										continue;
									}
									$pfb_parse_path = $pfb_pre['path'];
									$pfb_staged_path = $pfb_pre['path'];
								}

								$run_once = $csv_parser = FALSE;
								$csv_type = '';
								$ipcount = $ip_cnt = $ip_cnt6 = 0;
								$ip_decision = ['count' => 0, 'loggable' => FALSE];
								$ip6_decision = ['count' => 0, 'loggable' => FALSE];
								$pfb_scheme_skipped = 0;	// ADR-22: per-feed strict scheme/path skips
								$dnsbl_lineno = 0;		// issue #1004: per-line counter for the parse-error detail sink

								// Parse downloaded file for Domain names
								if (($fhandle = @fopen($pfb_parse_path, 'r')) !== FALSE) {
									if (($dhandle = @fopen("{$pfbfolder}/{$header}.bk", 'w')) !== FALSE) {
										while (($line = @fgets($fhandle)) !== FALSE) {

											// issue #1004: incremented every iteration, regardless of outcome
											$dnsbl_lineno++;

											// Collect original line
											$oline = $line;

											// Issue #946: strip a UTF-8 BOM before ANY per-line classification -- the
											// control-line skip, the ADR-62 per-line capture guard and the CSV
											// autodetection below do not handle a BOM themselves; a BOM-led first line
											// would be misclassified by all three. $oline keeps the original bytes for
											// the parse-error log. This also strips a BOM from captured ABP-shaped
											// lines before their verbatim passthrough to Python -- intentional and
											// harmless (Python's parser is byte-oriented too).
											$line = pfb_dnsbl_strip_bom($line);

											$line = pfb_dnsbl_scrub_line($line);

											// ADR-06 fact 7 / ADR-62: an ABP network anchor or
											// hosts-line target that is itself an IP address is
											// pulled to the firewall alias here -- never passed to
											// Python (no double-handling, no leak) -- checked BEFORE
											// the generic verbatim capture below.
											if ($pfb['dnsbl_ip'] != 'Disabled') {
												$abp_ip = pfb_dnsbl_abp_extract_ip($line);
												if ($abp_ip !== '') {
													if (pfb_dnsbl_collect_feed_ip($abp_ip, $abp_ip, $custom, $domain_data_ip, $domain_data_ip6)) {
														$pfb['updateip'] = TRUE;
														$ipcount++;
													}
													continue;
												}
											}

											// ADR-62 Decision 2: any self-identifying ABP shape (||/@@
											// anchors, /regex/[$opts], ##-family) is captured BEFORE
											// CSV autodetection and URL/path/'?'-query stripping (which
											// would otherwise truncate/mangle them) and written VERBATIM
											// to the '.bk'/'.txt' staging file; the manifest builder
											// copies it to the '.raw' and Python's build() routes it to
											// parse_abp() (never a domain/IP/path anchor -> silently
											// skipped).
											if (pfb_dnsbl_is_abp_rule_line($line)) {
												$domain_data = pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Abp, $line);
												@fwrite($dhandle, $domain_data);
												continue;
											}

											// If 'tab' character found, replace with whitespace
											if (strpos($line, "\x09") !== FALSE) {
												$line = str_replace("\x09", ' ', $line);
											}

											// If '%20' found, remove.
											if (strpos($line, '%20') !== FALSE) {
												$line = str_replace('%20', '', $line);
											}

											// Remove comment lines and special format considerations. Checked
											// BEFORE the generic '!'/'//' skip below since these side effects
											// (hpHosts end marker, Spamhaus format, h3x CSV header) must run.
											if (str_starts_with($line, '#')) {
												$pfb_hash_class = pfb_dnsbl_hash_line_classify($line);
												// Exit (hpHosts) when end of domain names found.
												if ($pfb_hash_class['stop']) {
													break;
												}

												// Spamhaus format validation
												if ($pfb_hash_class['rev_format']) {
													$rev_format = TRUE;
												}

												if ($pfb_hash_class['csv_type'] !== NULL) {
													$csv_type	= $pfb_hash_class['csv_type'];
												}
												if ($pfb_hash_class['csv_parser']) {
													$csv_parser	= TRUE;
												}
												continue;
											}

											// ADR-62 Decision 4: universal control-line skip
											// (blank / '!' / '//' / non-IPv6 '[...]'); the '#'
											// classifier above already ran (side effects). A
											// bracketed IPv6 literal is never skipped here --
											// the helper consults pfb_dnsbl_unbracket_ip6().
											if (pfb_dnsbl_is_skippable_control_line($line)) {
												continue;
											}

											// Remove any 'End of line' comments (Some contains commas)
											if (strpos($line, ' #') !== FALSE) {
												$line = strstr($line, ' #', TRUE);
											}

											// Default per line so $csvline is defined for the count()/index reads below;
											// str_getcsv overwrites it whenever the CSV path runs. Behaviour-preserving.
											$csvline = array();

											// Convert CSV line into array
											if ($csv_parser) {
												$csvline = str_getcsv($line, ',', '"', '"');
											}
											elseif (!$run_once) {
												if (substr_count($line, ',') >= 2) {
													$csvline = str_getcsv($line, ',', '"', '"');
													$csv_parser = TRUE;
												}
												$run_once = TRUE;
											}

											// Remove blank lines
											if (empty($line)) {
												continue;
											}

											// issue #1118: pfb_dnsbl_csv_extract() owns the whole upstream-CSV
											// classify/extract switch (unit-tested off-appliance); action='skip'
											// matches every one of the original block's `continue`/`continue 2` sites.
											$csv_result = pfb_dnsbl_csv_extract($line, $csvline, $csv_type, $csv_parser,
												$run_once, $alienvault_types, $pfb['dnsbl_ip'] != 'Disabled', $custom,
												$domain_data_ip, $domain_data_ip6, $header, $oline, $dnsbl_lineno,
												$pfb['dnsbl_parse_err']);
											$line		= $csv_result['line'];
											$csv_type	= $csv_result['csv_type'];
											$csv_parser	= $csv_result['csv_parser'];
											$run_once	= $csv_result['run_once'];
											if ($csv_result['ip_collected']) {
												$pfb['updateip'] = TRUE;
												$ipcount++;
											}
											if ($csv_result['action'] === 'skip') {
												continue;
											}
											$line = trim($line);

											// Typical Host Feed format - Remove characters before space
											if (!$rev_format && strpos($line, ' ') !== FALSE) {
												$line = trim(strstr($line, ' ', FALSE));
											}

											// Remove characters after space
											if (strpos($line, ' ') !== FALSE) {
												$line = strstr($line, ' ', TRUE);
											}

											// Determine if line contains only an alpha-numeric Domain name
											$lite = FALSE;
											if (strpos($line, '.') !== FALSE &&
											    ctype_alnum(str_replace('.', '', $line))) {
												$lite = TRUE;
											}

											if (!$lite) {
												$strict = ($pfb['dnsbl_lenient'] !== PfbToggle::On);
												$line = pfb_dnsbl_extract_host($line, $strict, $header, $oline,
													$dnsbl_lineno, $pfb['dnsbl_parse_err'], $pfb_scheme_skipped);
												if ($line === FALSE) {
													continue;
												}
											}
											$line = trim($line);

											// Collect any IPs (v4 or v6) found in domain feed. The family
											// check gates the 'continue' regardless of dnsbl_ip -- an IP
											// line never falls through to domain validation either way.
											if (is_ipaddrv4($line) || is_ipaddrv6($line)) {
												if ($pfb['dnsbl_ip'] != 'Disabled' &&
												    pfb_dnsbl_collect_feed_ip($line, $line, $custom, $domain_data_ip, $domain_data_ip6)) {
													$pfb['updateip'] = TRUE;
													$ipcount++;
												}
												continue;
											}

											// Convert IDN (Unicode domains) to ASCII (punycode)
											if (!empty($line) && !ctype_print($line)) {

												// Convert encodings to UTF-8
												$line = mb_convert_encoding($line, 'UTF-8',
													mb_detect_encoding($line, 'UTF-8, ASCII, ISO-8859-1'));

												$log = "\n  IDN converted: [ {$line} ]\t";
												$line = pfb_idn_to_ascii_wildcard($line);
												if (!empty($line)) {
													pfb_logger("{$log} [ {$line} ]", 1);
												}
												else {
													// Record failed parsed line
													pfb_parse_fail_log($header, '', $oline, $pfb['dnsbl_parse_err'], $dnsbl_lineno);
													continue;
												}
											}

											// Remove leading/trailing dots ($line is already
											// whitespace-trimmed above)
											$line = trim($line, '.');

											// Domain Validation
											if (empty(pfb_filter($line, PFB_FILTER_DOMAIN, 'DNSBL_Download'))) {

												// Skip yHost '@' prefixed lines
												if (str_starts_with($line, '@')) {
													continue;
												}

												// Log invalid Domains
												if (!isset($dnsbl_skip[$line])) {
													pfb_parse_fail_log($header, $line, $oline, $pfb['dnsbl_parse_err'], $dnsbl_lineno);
												}
												continue;
											}

											// For DNSBL python, save domain and Logging type
											$domain_data = pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, strtolower($line));
											@fwrite($dhandle, $domain_data);
										}
									}
									if ($dhandle) {
										@fclose($dhandle);
									}
								}
								if ($fhandle) {
									@fclose($fhandle);
								}
								// issue #1926: the staged pre-script copy is transient -- parsed above.
								pfb_list_script_cleanup_staged($pfb_parse_path, $pfb_staged_path, "{$file_dwn}.pre");

								// Close the "Reload . completed ." progress line with its trailing dot
								// BEFORE the strict-parsing WARNING below, else the warning's own
								// leading/trailing newlines strand this dot on its own line.
								if (!empty($domain_data)) {
									pfb_logger(".\n", 1);
								}

								// ADR-22: one WARNING per feed summarising strict-mode skips (silent
								// when none -- lenient never increments the counter).
								pfb_dnsbl_scheme_skip_warn($pfb_scheme_skipped, $header);

								// issue #1926: DNSBL post-script runs on a throwaway copy of the
								// download — nothing downstream re-parses it (same observable as
								// the IP loop, which discards post-script edits via restore).
								if ($pfb_row_script_post && is_file("{$pfb_row_script_post}")) {
									pfb_logger("\nExecuting post-script: {$list['script_post']}\n", 1);
									if (@copy("{$file_dwn}.orig", "{$file_dwn}.post")) {
										$pfb_post_status = pfb_list_script_exec($pfb_row_script_post, $list['script_post'], 'post', $header,
										    escapeshellarg("{$file_dwn}.post") . " dnsbl {$elog}");
										unlink_if_exists("{$file_dwn}.post");
										// issue #2059: 'script' stage, never 'download' -- the feed refreshed.
										pfb_list_post_script_failure_record($pfb_post_status, 'dnsbl', $alias,
										    "[ {$alias} - {$header} ] Post-script FAIL - feed updated, side effects incomplete",
										    $pfb['dbdir'], $pfb_script_state);
									} else {
										pfb_logger("\n[ {$header} ] post-script '{$list['script_post']}' could not stage its input; skipping\n", 2);
									}
								}

								if (isset($csvline)) {
									unset($csvline);
								}

								// Remove duplicates and save any IPs found in domain feed
								if (!empty($domain_data_ip)) {
									$domain_data_ip = implode("\n", array_unique($domain_data_ip)) . "\n";
									@file_put_contents("{$pfbfolder}/{$header}_v4.ip", $domain_data_ip, LOCK_EX);
									// issue #1261: display/log-gate only -- NULL (read failure) -> 0.
									$ip_decision = pfb_dnsbl_ipv4_count_decision("{$pfbfolder}/{$header}_v4.ip");
									$ip_cnt = $ip_decision['count'];
								}
								else {
									// Remove previous IP feed
									unlink_if_exists("{$pfbfolder}/{$header}_v4.ip");
								}

								// Remove duplicates and save any IPv6 IPs found in domain feed
								if (!empty($domain_data_ip6)) {
									$domain_data_ip6 = implode("\n", array_unique($domain_data_ip6)) . "\n";
									@file_put_contents("{$pfbfolder}/{$header}_v6.ip", $domain_data_ip6, LOCK_EX);
									// issue #1261: display/log-gate only -- NULL (read failure) -> 0.
									$ip6_decision = pfb_dnsbl_ipv6_count_decision("{$pfbfolder}/{$header}_v6.ip");
									$ip_cnt6 = $ip6_decision['count'];
								}
								else {
									// Remove previous IPv6 feed
									unlink_if_exists("{$pfbfolder}/{$header}_v6.ip");
								}

								// Validate feed with Unbound-checkconf
								if (!empty($domain_data)) {
									$conf  = "server:\n";
									$conf .= "chroot: {$pfb['dnsbldir']}\n";
									$conf .= "username: \"unbound\"\n";
									$conf .= "directory: \"{$pfb['dnsbldir']}\"\n";
									$conf .= "pidfile: \"/var/run/unbound.pid\"\n";
									$conf .= "server:include: {$pfbfolder}/{$header}.bk";
									@file_put_contents("{$pfb['dnsbldir']}/check.conf", $conf, LOCK_EX);

									// ADR-06: The build-time De-Duplication / user-whitelist /
									// TOP1M removal passes (dnsbl_scrub) are DROPPED. The Python
									// dict load dedups keys for free, the user whitelist + TOP1M
									// are applied at QUERY TIME via the whiteDB, and redundant
									// subdomains are matched by their parent zone -- so no
									// build-time list pruning is performed here anymore.

									if ($ip_decision['loggable']) {
										pfb_logger("  IPv4 count={$ip_cnt}\n", 1);
									}
									if ($ip6_decision['loggable']) {
										pfb_logger("  IPv6 count={$ip_cnt6}\n", 1);
									}

									$result = array('unbound-checkconf: no errors');
									unlink_if_exists("{$pfb['dnsbldir']}/check.conf");
								}
								else {
									$log = "\n No Domains Found! Ensure only domain based Feeds are used for DNSBL!\n";
									pfb_logger("{$log}", 1);

									// Copy downloaded file to /tmp for debugging
									$ts = date('Y-m-d', time());
									@copy("{$file_dwn}.orig", "/tmp/Error_{$header}_{$ts}.orig");

									unlink_if_exists("{$pfbfolder}/{$header}.bk");
									// issue #1083: converge a stale-generation rebuild that
									// found zero domains -- else the pre-NDJSON '.txt' survives and
									// the guard re-triggers 'Rebuild' every subsequent pass.
									pfb_dnsbl_stale_rebuild_converge_txt($stale_generation_rebuild, "{$pfbfolder}/{$header}.txt");
									$result = array('unbound-checkconf: no errors');
								}

								// If parse error found, use previously downloaded file if available


								// Save DNSBL feed info for next steps
								$pfb['domain_update']	= $pfb['aliasupdate'] = $pfb['summary'] = TRUE;
								$lists_dnsbl_all[]	= "{$row['header']}.txt";
								// ADR-31: delegate to pfb_feed_manifest_row() (deny default).
								// ADR-31: pass $mode derived from per-row 'action' (above).
								$pfb_py_feeds[]		= pfb_feed_manifest_row(
									$header, $alias, $logging_type,
									$custom ? 'user' : 'feed',
									$mode);

								// Rename newly downloaded file to final location
								if (file_exists("{$pfbfolder}/{$header}.bk")) {
									@rename("{$pfbfolder}/{$header}.bk", "{$pfbfolder}/{$header}.txt");
								}

								// Create empty placeholder file
								if (!file_exists("{$pfbfolder}/{$header}.txt")) {
									touch("{$pfbfolder}/{$header}.txt");
								}

								// issue #1162/#1261: pfb_count_lines() returns NULL on a read
								// failure -- 0 preserves the exec()-era fallback.
								$alias_cnt	= pfb_dnsbl_alias_count_rebuild("{$pfbfolder}/{$header}.txt", $alias_cnt);

								// Remove update file indicator -- skip if this row fell through to
								// the stale-.orig download-failure fallback, else a pending rebuild
								// is stranded like #1002 but via the download-failure path. (#1031)
								if (pfb_dnsbl_update_marker_clear_active($orig_content_stale)) {
									unlink_if_exists("{$pfbfolder}/{$header}.update");
								}
							}
						}
					}

					// issue #1048: close the download ledger entry once for the WHOLE
					// alias-pass, iff no row in it failed -- a per-row close let a later
					// feed's success mask an earlier feed's still-live failure.
					pfb_download_ledger_close_if_clean('dnsbl', $alias, $pfb_dl_failed, $pfb['dbdir']);

					// issue #1958/#2059: ADR-61 symmetric ownership -- close the 'script'
					// stage entry once for the WHOLE alias-pass, iff no row's pre- or
					// post-script failed.
					pfb_dnsbl_script_failure_close($alias, $pfb['dbdir'], $pfb_script_state);

					// ADR-12: record GENUINELY-changed DNSBL groups for
					// PFB_CHANGED_DNSBL_GROUPS. $pfb['aliasupdate'] is final for the
					// group here (reset at :8859, set TRUE at :9500 ONLY when a feed in
					// this group was actually (re)downloaded+parsed -- stays FALSE on
					// file-reuse). Captured BEFORE the TLD/non-TLD routing split below so
					// it covers BOTH modes. $alias is the DNSBL_<group> name (set :8864)
					// and we are inside the foreach ($lists ...) group loop. The
					// always-rebuilt specials (DNSBL_IDN/DNSBL_TLD_Allow/DNSBL_Regex) are
					// added later, OUTSIDE this loop (:9572/:9586/:9613), so they are
					// excluded here -- only real feed changes ride the env var. De-dup is
					// handled at emit (array_unique). DNSBL groups are NOT firewall
					// aliases, so this is split from the IP-side $pfb['changed_ip_aliases'].
					if ($pfb['aliasupdate']) {
						$pfb['changed_dnsbl_groups'][] = $alias;
					}

					// Update changed group stats immediately when TLD mode is disabled
					if ($pfb['aliasupdate'] && !$pfb['dnsbl_tld_wildcard']) {
						dnsbl_stats_update('update', $alias, $alias_cnt);
					}

					// Defer all active group stats until a TLD-mode reload is committed
					if ($pfb['dnsbl_tld_wildcard']) {
						$dnsbl_tld_group_counts[$alias] = $alias_cnt;
					}
				}
				else {
					dnsbl_stats_update('disabled', $alias, '');
				}
			}

		}

		// Add DNSBL Python options to widget statistics. ADR-08: All-IDN keeps the
		// DNSBL_IDN alias exactly as before; Confusable mode surfaces the homoglyph +
		// suspect groups so the Reports/Alerts pages render their counts. Counts are
		// symbolic (=1) markers -- the Python matcher decides per-query at runtime.
		if ($pfb['dnsbl_idn'] === PfbIdnMode::All) {
			$idn_cnt = 1;
			$pfb['alias_dnsbl_all'][] = 'DNSBL_IDN';
			dnsbl_stats_update('update', 'DNSBL_IDN', $idn_cnt);
		}
		elseif ($pfb['dnsbl_idn'] === PfbIdnMode::Confusable) {
			$pfb['alias_dnsbl_all'][] = 'DNSBL_Homoglyph';
			dnsbl_stats_update('update', 'DNSBL_Homoglyph', 1);
			$pfb['alias_dnsbl_all'][] = 'DNSBL_Homoglyph_Suspect';
			dnsbl_stats_update('update', 'DNSBL_Homoglyph_Suspect', 1);
		}
		if ($pfb['dnsbl_tld_allow'] === PfbToggle::On) {
			$tld_allow_cnt = 0;
			foreach (array('gtld', 'cctld', 'itld', 'bgtld') as $tld_allow_bucket) {
				if (isset($pfb['dnsblconfig']['tld_allow_' . $tld_allow_bucket]) && !empty($pfb['dnsblconfig']['tld_allow_' . $tld_allow_bucket])) {
					$p_cnt = count(explode(',', $pfb['dnsblconfig']['tld_allow_' . $tld_allow_bucket]));
					if (is_numeric($p_cnt) && $p_cnt > 0) {
						$tld_allow_cnt += $p_cnt;
					}
				}
			}

			$pfb['alias_dnsbl_all'][] = 'DNSBL_TLD_Allow';
			dnsbl_stats_update('update', 'DNSBL_TLD_Allow', $tld_allow_cnt);
		}
		// ADR-07: use Python's admitted feed + user regex count after the shared
		// catastrophic-shape gate and opt-in length cap; otherwise fall back to the
		// configured user-regex count.
		$py_regex_cnt = NULL;
		if (file_exists($pfb['unbound_py_regex_count'])) {
			$raw_rc = trim((string) @file_get_contents($pfb['unbound_py_regex_count']));
			if ($raw_rc !== '' && ctype_digit($raw_rc)) {
				$py_regex_cnt = (int) $raw_rc;
			}
		}
		if ($pfb['dnsbl_regex'] === PfbToggle::On || ($py_regex_cnt !== NULL && $py_regex_cnt > 0)) {
			if ($py_regex_cnt !== NULL) {
				$regex_cnt = $py_regex_cnt;
			} else {
				$regex_cnt = 0;
				if (isset($pfb['dnsbl_regex_list'])) {
					$regex_cnt = count(pfb_text_area_decode($pfb['dnsbl_regex_list'], TRUE, FALSE, FALSE)) ?: 0;
				}
			}
			$pfb['alias_dnsbl_all'][] = 'DNSBL_Regex';
			dnsbl_stats_update('update', 'DNSBL_Regex', $regex_cnt);
		}

		// Save DNSBL Alias statistics (Not for TLD mode)
		if ($pfb['domain_update'] && !$pfb['dnsbl_tld_wildcard']) {
			dnsbl_save_stats();
		}
	}

	// Collect all DNSBL IP feeds (IPv4 only) into DNSBLIP_v4.txt -- but ONLY when the source
	// *_v4.ip set actually changed (or the output is missing). Rebuilding + re-filtering DNSBLIP
	// on every IP update churned it needlessly (issue #653); the content fingerprint (ADR-42
	// style) gates the rebuild, the '.update' reprocess marker, and the ip_cache flush, so an
	// unchanged source is left alone (the feed loop then logs "exists" instead of reprocessing).
	if ($pfb['dnsbl_ip'] != 'Disabled' && ($pfb['updateip'] || !file_exists("{$pfb['dbdir']}/DNSBLIP_v4.txt"))) {

		$dnsblip_v4 = "{$pfb['dbdir']}/DNSBLIP_v4.txt";
		$dnsbl_ip   = glob("{$pfb['dnsdir']}/*_v4.ip") ?: array();
		list($pfb_dnsblip_rebuild, $pfb_dnsblip_fp) = pfb_dnsblip_rebuild_check($dnsblip_v4, $dnsbl_ip, "{$dnsblip_v4}.fp");

		if ($pfb_dnsblip_rebuild) {
			$pfb_dnsblip_built = TRUE;
			if (!empty($dnsbl_ip)) {
				$pfb_dnsblip_built = pfb_dnsbl_concat_files($dnsblip_v4, $dnsbl_ip);
			}

			// Add empty placeholder IP
			else {
				$pfb_dnsblip_built = (@file_put_contents($dnsblip_v4, "{$pfb['ip_ph']}\n", LOCK_EX) !== FALSE);
			}
			pfb_dnsblip_finalize($dnsblip_v4, $pfb_dnsblip_fp, $pfb_dnsblip_built, $pfb['ip_cache'], $pfb['dnsbl_ip'], '_v4');
		}
	}

	// Remove DNSBL IP feed, if disabled. The prior action is unknown here, so clear the
	// marker/destination from BOTH folders DNSBLIP can land in (denydir + nativedir). (#655)
	if ($pfb['dnsbl_ip'] == 'Disabled') {
		unlink_if_exists("{$pfb['dbdir']}/DNSBLIP_v4.txt");
		unlink_if_exists("{$pfb['dbdir']}/DNSBLIP_v4.txt.fp");
		unlink_if_exists("{$pfb['denydir']}/DNSBLIP_v4.*");
		unlink_if_exists("{$pfb['nativedir']}/DNSBLIP_v4.*");
	}

	// Collect all DNSBL IP feeds (IPv6 only) into DNSBLIP_v6.txt -- gated on the *_v6.ip source
	// set changing, identical to the v4 path above (issue #653).
	if ($pfb['dnsbl_ip'] != 'Disabled' && ($pfb['updateip'] || !file_exists("{$pfb['dbdir']}/DNSBLIP_v6.txt"))) {

		$dnsblip_v6 = "{$pfb['dbdir']}/DNSBLIP_v6.txt";
		$dnsbl_ip   = glob("{$pfb['dnsdir']}/*_v6.ip") ?: array();
		list($pfb_dnsblip_rebuild, $pfb_dnsblip_fp) = pfb_dnsblip_rebuild_check($dnsblip_v6, $dnsbl_ip, "{$dnsblip_v6}.fp");

		if ($pfb_dnsblip_rebuild) {
			$pfb_dnsblip_built = TRUE;
			if (!empty($dnsbl_ip)) {
				$pfb_dnsblip_built = pfb_dnsbl_concat_files($dnsblip_v6, $dnsbl_ip);
			}

			// Add empty placeholder IP
			else {
				$pfb_dnsblip_built = (@file_put_contents($dnsblip_v6, "::{$pfb['ip_ph']}\n", LOCK_EX) !== FALSE);
			}
			pfb_dnsblip_finalize($dnsblip_v6, $pfb_dnsblip_fp, $pfb_dnsblip_built, $pfb['ip_cache'], $pfb['dnsbl_ip'], '_v6');
		}
	}

	// Remove DNSBL IP feed, if disabled. The prior action is unknown here, so clear the
	// marker/destination from BOTH folders DNSBLIP can land in (denydir + nativedir). (#655)
	if ($pfb['dnsbl_ip'] == 'Disabled') {
		unlink_if_exists("{$pfb['dbdir']}/DNSBLIP_v6.txt");
		unlink_if_exists("{$pfb['dbdir']}/DNSBLIP_v6.txt.fp");
		unlink_if_exists("{$pfb['denydir']}/DNSBLIP_v6.*");
		unlink_if_exists("{$pfb['nativedir']}/DNSBLIP_v6.*");
	}

	#########################################
	#	UPDATE Unbound DNS Database	#
	#########################################

	if ($pfb['domain_update']) {
		if (!empty($lists_dnsbl_all)) {
			pfb_logger("\n------------------------------------------------------------------------\n", 1);

			pfb_logger('Assembling DNSBL database...', 1);

			// ADR-06: Write the per-feed manifest + IP-stripped raw that the Python
			// plugin's init builds the DNSBL structures from. Python then owns
			// parse/normalise/classify (the dropped shell/PHP passes) and emits
			// pfb_py_count itself.
			pfb_dnsbl_publish_result(pfb_unbound_python_sources($pfb_py_feeds) !== FALSE);
		}

		else {
			$log = "\nDNSBL not Updated!\n";
			pfb_logger("{$log}", 1);
		}
	}
	else {
		if ($pfb['enable'] === PfbToggle::On && $pfb['dnsbl'] === PfbToggle::On) {

			// When DNSBL is enabled and no Aliases are defined, or all Aliases are Disabled
			if (empty($lists_dnsbl_all) && !$pfb['save']) {
				// Only log/flag domain_clear when feeds were actually loaded (#546):
				// pfb_dnsbl_has_loaded_feeds() excludes the shipped pfb_py_hsts and the
				// always-present manifest/whitelist so a no-feeds setup never looks "loaded".
				$had_feeds = pfb_dnsbl_has_loaded_feeds($pfb);
				if ($had_feeds) {
					pfb_logger("\nClearing all DNSBL Feeds", 1);
					$pfb['domain_clear'] = TRUE;
				}

				// Materialize the manifest/rawdir as present-but-EMPTY rather than deleting
				// them (#546). Empty-but-present files are byte-identical pass-to-pass, so the
				// fingerprint gate treats empty→empty as unchanged (no reload). A genuine
				// loaded→empty transition still diverges on the first pass (one reload), then
				// stabilises. DO NOT delete pfb_py_wh: pfb_unbound_python() reads it to detect
				// a whitelist change; missing=FALSE !== '' triggers $pfbpython=TRUE every pass.
				if (pfb_unbound_python_sources(array()) === FALSE) {
					$pfb['dnsbl_publish_failed'] = TRUE;
				}		// valid feeds:[] manifest + empty rawdir
				unlink_if_exists($pfb['unbound_py_count']);
				unlink_if_exists($pfb['unbound_py_regex_count']);		// ADR-07
			}
		}
		else {
			foreach (array("{$pfb['dnsbl_file']}.conf") as $pfb_file) {
				if (file_exists($pfb_file)) {
					$pfb['domain_clear'] = TRUE;
					@unlink($pfb_file);
				}
			}
			pfb_top1m_teardown_call();
		}
	}

	#################################
	#	UNBOUND INTEGRATION	#
	#################################

	$pfbupdate = $pfbpython = FALSE;
	// $mode must be a defined string for the consumers below (incl. the typed
	// pfb_manage_dnsbl_vip(string $mode)); the if/elseif does not cover every state
	// (e.g. DNSBL enabled while the DNS Resolver is disabled). '' is a no-op mode.
	$mode = '';
	if ($pfb['enable'] === PfbToggle::On && $pfb['dnsbl'] === PfbToggle::On && $pfb['unbound_state'] === PfbToggle::On) {
		$mode = 'enabled';
	}
	elseif (($pfb['enable'] !== PfbToggle::On || $pfb['dnsbl'] !== PfbToggle::On) && !$pfb['install']) {
		$mode = 'disabled';
	}

	// [ ADR-13 ] Provision (or remove) the auto-created DNSBL sinkhole VIP(s) BEFORE the
	// DNSBL config consumers below. pfb_unbound_python() bakes the sinkhole IP
	// ($pfb['dnsbl_vip4']/[vip6]) into the module ini, so the marked VIP must already exist
	// and pfb_dnsvip4/6 must be repointed FIRST — otherwise the module answers blocks with
	// the stale VIP (a one-pass lag). pfb_manage_dnsbl_vip() refreshes $pfb (via pfb_global)
	// so every consumer below sees the provisioned address. No-op when auto-create is off.
	// pfb_create_dnsbl($mode) calls it again idempotently (covers the boot/install path).
	pfb_manage_dnsbl_vip($mode);

	// Modify Unbound python configuration and mount lib/bin folders, as required
	$pfbpython = pfb_unbound_python($mode);

	// Modify Unbound.conf file, as required
	$pfbupdate = pfb_unbound_dnsbl($mode);

	// Modify DNSBL NAT and VIP and lighttpd web server conf, as required.
	pfb_create_dnsbl($mode);

	// Sync DNS-redirect NAT rules (create / reconcile / prune / remove).
	// Each rule uses associated-rule-id='pass' — pfSense emits an inline rdr pass and
	// manages the companion firewall pass automatically; no filter/rule entry is written.
	// Reads dnsbl_redir (toggle) via PfbConfig; manages nat/rule directly
	// (pfSense-core foreign section — ADR-29 exclusion list).
	// Coupled to DNSBL being enabled: rules are created only when $mode === 'enabled'
	// (master enable + DNSBL toggle + resolver up); force-removed otherwise. Feeds/lists
	// are NOT required — only the DNSBL toggle + resolver state.
	{
		$redir_changed = FALSE;
		$redir_toggle  = PfbConfig::read('dnsbl/dnsbl_redir');
		$redir_enabled = ($mode === 'enabled') && ($redir_toggle instanceof PfbToggle && $redir_toggle === PfbToggle::On);

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

				// Build new NAT rdr rules for each interface × family. Resolve the exception
				// source PER rule with a context label (interface + IP version), so when the
				// exception alias is not usable the log names the specific rule that dropped it
				// (#664) instead of an identical line per grid cell. The lookup itself is cheap.
				$redir_new_owned = [];
				foreach ($redir_ifaces as $redir_iface) {
					foreach (['inet', 'inet6'] as $redir_family) {
						$redir_sfx    = ($redir_family === 'inet') ? PFB_DNS_REDIR_DESCR_V4_SFX : PFB_DNS_REDIR_DESCR_V6_SFX;
						$redir_target = ($redir_family === 'inet') ? '127.0.0.1' : '::1';
						$redir_ver    = ($redir_family === 'inet') ? 'IPv4' : 'IPv6';
						$redir_descr  = PFB_DNS_REDIR_DESCR_V4_PFX . $redir_iface . $redir_sfx;
						$redir_source = pfb_redirect_exclude_source($redir_exception, "DNS Redirect on {$redir_iface} {$redir_ver}");
						$redir_new_owned[] = [
							'source'             => $redir_source,
							'destination'        => ['network' => '(self)', 'not' => '', 'port' => '53'],
							'ipprotocol'         => $redir_family,
							'protocol'           => 'tcp/udp',
							'target'             => $redir_target,
							'local-port'         => '53',
							'interface'          => $redir_iface,
							'descr'              => $redir_descr,
							'associated-rule-id' => 'pass',
							'natreflection'      => 'disable',
						];
					}
				}

				if ($redir_ex_owned !== $redir_new_owned) {
					$redir_changed = TRUE;
					config_set_path('nat/rule', array_merge($redir_ex_other, $redir_new_owned));
				}
			}
		}

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
	// (master enable + DNSBL toggle + resolver up); force-removed otherwise. Feeds/lists
	// are NOT required — only the DNSBL toggle + resolver state.
	{
		$dot_changed = FALSE;
		$dot_toggle  = PfbConfig::read('dnsbl/dnsbl_dot_block');
		$dot_enabled = ($mode === 'enabled') && ($dot_toggle instanceof PfbToggle && $dot_toggle === PfbToggle::On);

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

		if ($dot_changed) {
			write_config('pfBlockerNG: saving DoT/DoQ block rule changes');
			// The block rule changed — force a pf reload so it loads.
			$pfb['filter_configure'] = TRUE;
		}
	}

	// Fingerprint the loaded input files AFTER this pass rebuilt them.
	// Equal fingerprints => Python would produce a byte-identical blocklist => skip reload.
	// fp_old === null => DNSBL was not active this pass (the block above never ran) --
	// fall back to domain_update / domain_clear as before.
	// The all-missing stable sentinel means empty→empty always yields equal fingerprints,
	// so an unchanged no-feeds steady state no longer triggers a reload every pass.
	$pfb_fp_new = ($pfb_fp_old === null) ? null : pfb_dnsbl_reload_fingerprint($pfb);
	$pfb_data_changed = ($pfb_fp_old === null || $pfb_fp_new === null)
		? ($pfb['domain_update'] || $pfb['domain_clear'])
		: ($pfb_fp_old !== $pfb_fp_new);

	// An explicit "Force Reload DNSBL" (the updatednsbl trigger) must ALWAYS reload — the
	// operator forces it to apply a change the fingerprint can't see (e.g. an out-of-band
	// edit to a chroot file outside the fingerprinted input set, or to recover from
	// suspected runtime drift), independent of the fingerprint. reuse_dnsbl / the .reload
	// marker can't serve as this
	// signal — cron-reuse mode and the dnsbl-missing path also set them, which would
	// reintroduce the every-pass reload this gate removes; $pfb['updatednsbl'] is set ONLY
	// by the Force-Reload-DNSBL path (scope=dnsbl + force=true in the normalization block).
	if (!empty($pfb['updatednsbl'])) {
		$pfb_data_changed = TRUE;
	}

	// Load new DNSBL updates to Unbound Resolver, as required. ADR-06 (#51): a pending
	// temporary-unlock store ($pfb['dnsbl_unlock']) also forces the reload so a Cron/
	// Force re-locks it even when no feed changed -- parity with main, where the
	// ungated whitelist regeneration sets $pfbpython for the same effect. The reload
	// path (pfb_update_unbound) then drops the store and clears the manifest's
	// user_unlock. Captured BEFORE the reload: pfb_update_unbound() unlinks the file,
	// so a post-reload file_exists() would always return false (issue #517).
	$pfb_dnsbl_unlock_forced = file_exists($pfb['dnsbl_unlock']);
	if (pfb_dnsbl_reload_needed(!empty($pfb['dnsbl_publish_failed']), !empty($pfb_data_changed), !empty($pfbupdate),
	    !empty($pfbpython), !empty($safesearch_update), !empty($pfb_dnsbl_unlock_forced))) {

		// Create backup of existing DNSBL Unbound database

		// SafeSearch data (safeSearchDB, incl. the issue #149 CNAME redirect rows) is
		// loaded ONLY at python-module init, so a SafeSearch CSV change must RESTART
		// Unbound, not take the zero-downtime data swap (which rebuilds only the DNSBL
		// matcher, not safeSearchDB). Force the config-change/restart path. Pre-#149
		// this restart was an incidental side effect of toggling the native SafeSearch
		// 'pfb_dnsbl.*conf' include (now removed), so it must be requested explicitly.
		if ($safesearch_update) {
			$pfbpython = TRUE;
		}

		pfb_update_unbound($mode, $pfbupdate, $pfbpython, $dnsbl_tld_group_counts);

		// #468: DNSBL actually changed this pass and the reload above has applied (the
		// zero-downtime swap waited / Unbound restarted). On a RAM-disk /var, re-archive
		// the generated DNSBL state so the boot 'dnsbl_cache restore' brings it back after
		// the next reboot. Gated like the IP side (archive only inside the change branch):
		// DNSBL active ($mode === 'enabled', i.e. enable + dnsbl + resolver on) +
		// use_mfs_tmpvar. Read $pfb directly (not $mode) to keep the gate self-contained.
		// #520 NOTE: an HSTS-only change now enters this branch too ($pfb_data_changed
		// fingerprints the shipped pfb_py_hsts.txt), so the archive is re-saved even
		// though it EXCLUDES the shipped files -- a harmless no-op re-compress of
		// identical generated content. Deliberately NOT separately gated: the shipped
		// HSTS list ships per-release (changes ~never), so the rare extra save isn't
		// worth a second generated-only fingerprint.
		if ($pfb['enable'] === PfbToggle::On && $pfb['dnsbl'] === PfbToggle::On && $pfb['unbound_state'] === PfbToggle::On &&
		    config_path_enabled('system', 'use_mfs_tmpvar')) {
			pfb_dnsbl_cache('save');
		}
	}


	#################################
	#	Assign Countries	#
	#################################

	if (!$pfb['save']) {
		$log = "\n\n===[  GeoIP Process  ]============================================\n";
		pfb_logger("{$log}", 1);
	}

	// Download MaxMind Databases if not found
	$maxmind_verify = FALSE;
	if (!empty($pfb['maxmind_key']) && !empty($pfb['maxmind_account'])) {

		$maxmind_verify = TRUE;
		if (!file_exists("{$pfb['geoipshare']}/GeoLite2-Country.mmdb") ||
		    !file_exists("{$pfb['geoipshare']}/GeoLite2-Country-Blocks-IPv4.csv") ||
		    !file_exists("{$pfb['dbdir']}/geoip.txt") ||
		    !file_exists("{$pfb['ccdir']}/Top_Spammers_v4.info")) {

			// Check if MaxMind download already in progress
			exec('/bin/ps -wax', $result_cron);
			if (!preg_grep("/pfblockerng[.]php\s+dc/", $result_cron)) {
				$log = "\nMaxMind Database downloading and processing ( approx 4MB ) ... Please wait ...\n";
				pfb_logger("{$log}", 1);
				$maxmind_status = pfb_reentry_exec('dc', ['scheduled'], $pfb['log']);
				if (!in_array($maxmind_status, [0, 2], TRUE) || !pfb_geoip_generation_ready()) {
					pfb_mark_pending_changes();
					pfb_due_ledger_set_pending('cron', $pfb['dbdir']);
					pfb_logger("MaxMind processing failed; update deferred.\n", 2);
					if ($pfb_feed_pass_owner) {
						pfb_feed_pass_release();
					}
					if ($pfb_dispatch_owner) {
						pfb_schedule_dispatch_release();
					}
					return FALSE;
				}
				restart_service('pfb_filter');
			}
			else {
				$log = "\nMaxMind download already in process...\n";
				pfb_logger("{$log}", 1);
			}
		}
	}

	$maxmind_run_once = TRUE;
	foreach ($pfb['continents'] as $continent => $pfb_alias) {
		$cont_key = 'pfblockerng' . strtolower(str_replace(' ', '', $continent));
		if (!empty(config_get_path("installedpackages/{$cont_key}/config"))) {
			$continent_config = config_get_path("installedpackages/{$cont_key}/config/0");
			if (!pfb_group_action_valid($continent_config['action'] ?? NULL, 'geoip')) {
				continue;
			}
			$cc_name = 'pfblockerng' . strtolower(str_replace(' ', '', $continent));
			if (isset($continent_config['action']) && $continent_config['action'] != 'Disabled' && $pfb['enable'] === PfbToggle::On) {

				// Maxmind credential verification and user notification
				if ($maxmind_run_once && !$maxmind_verify) {
					$mmsg = pfb_maxmind_credential_notice($pfb['maxmind_key'], $pfb['maxmind_account']);
					if ($mmsg !== '') {
						pfb_logger("\n\nURGENT:\n    {$mmsg}\n", 1);
						file_notice('pfBlockerNG MaxMind', $mmsg, 'pfBlockerNG', '/pfblockerng/pfblockerng_ip.php', 2);
					}
					$maxmind_run_once = FALSE;
				}

				$urlvalue = '';	// Firewall: Aliases value field

				// Determine if Continent lists require action (IPv4 and IPv6)
				foreach ($cont_types as $c_type => $vtype) {

					// Only the '_v4'/'_v6' suffix may build an alias/path
					if (!pfb_valid_vtype($vtype)) {
						continue;
					}

					$cc_alias = "{$pfb_alias}{$vtype}";

					// Determine 'list' details (return array $pfbarr)
					pfb_determine_list_detail($continent_config['action'], "{$cc_alias}", $cc_name, '0');
					$pfbadv		= $pfbarr['adv'];
					$pfbdescr	= $pfbarr['descr'];
					$pfbfolder	= $pfbarr['folder'];
					$pfborig	= $pfbarr['orig'];
					$logtab		= $pfbarr['logtab'];

					if (!empty($continent_config[$c_type])) {

						// Collect selected GeoIP ISOs
						if (($pfb_output = @fopen("{$pfb['geoip_tmp']}", 'w')) !== FALSE) {
							foreach (explode(',', $continent_config[$c_type]) as $iso) {

								$urlvalue .= "{$iso},";
								$isofile = "{$pfb['ccdir']}/{$iso}{$vtype}.txt";
								if (($handle = @fopen("{$isofile}", 'r')) !== FALSE) {
									while (($line = @fgets($handle)) !== FALSE) {
										@fwrite($pfb_output, $line);
									}
								}
								else {
									pfb_logger("\nCould not open ISO [ {$iso}{$vtype} ]\n", 1);
								}
								if ($handle) {
									@fclose($handle);
								}
							}
						}
						else {
							pfb_logger("\n[ {$cc_alias} ] Could not create GeoIP file handle\n", 1);
						}
						if ($pfb_output) {
							@fclose($pfb_output);
						}

						// Collect md5 of new Continent data
						$continent		= 'md5_0';
						if (file_exists("{$pfb['geoip_tmp']}")) {
							$continent	= @md5_file("{$pfb['geoip_tmp']}");
						}

						// Collect md5 of existing Continent data
						$continent_ex		= 'md5_1';
						if (file_exists("{$pfborig}/{$cc_alias}.orig")) {
							$continent_ex	= @md5_file("{$pfborig}/{$cc_alias}.orig");
						}

						// Check if pfBlockerNG pfctl Continent tables are empty (pfBlockerNG was disabled w/ "keep", then re-enabled)
						$pfctlck = pfb_pfctl_table_count($cc_alias);

						if (empty($pfctlck) && file_exists("{$pfbfolder}/{$cc_alias}.txt")) {
							@copy("{$pfbfolder}/{$cc_alias}.txt", "{$pfb['aliasdir']}/{$cc_alias}.txt");
							// Collect updated alias lists ('Reputation' disabled)
							$pfb_alias_lists[] = "{$cc_alias}";
						}

						// Collect active alias lists (Used for pfctl update when 'Reputation' is enabled).
						$pfb_alias_lists_all[] = "{$cc_alias}";

						// Compare existing (original file) and new Continent data
						if ($continent == $continent_ex && !empty($pfctlck)
						    && $pfb['reuse'] == ''
						    && file_exists("{$pfbfolder}/{$cc_alias}.txt")
						    && !file_exists("{$pfb['dbdir']}/geoip.update")) {
							if (!$pfb['save']) {
								$log = "\n[ {$cc_alias} ]{$logtab} exists.";
								pfb_logger("{$log}", 1);
							}
						} else {
							// Do not proceed with changes on user 'save'
							if (!$pfb['save']) {
								$log = "\n[ {$cc_alias} ]{$logtab} Changes found... Updating\n";
								pfb_logger("{$log}", 1);

								// Execute Reputation functions, when changes are found.
								if ($pfbadv && $vtype == '_v4') {
									$pfb['repcheck'] = TRUE;
								}

								// Collect updated alias lists ('Reputation' disabled)
								$pfb_alias_lists[] = "{$cc_alias}";

								if ($continent != 'md5_0') {
									pfb_apply_geoip_orig_pipeline(
										"{$pfb['geoip_tmp']}", "{$pfborig}/{$cc_alias}.orig", "{$pfbfolder}/{$cc_alias}.txt",
										static function (string $orig, string $mirror) use ($pfb, $cc_alias, $vtype, $elog, $pfbadv, $pfbfolder): void {
											if ($pfb['agg'] === PfbToggle::On && $vtype == '_v4') {
												exec("{$pfb['script']} cidr_aggregate {$cc_alias} {$pfbfolder} {$elog}");
											}
											if ($pfbadv) {
													pfb_ip_recompute_write_snapshot($mirror, $cc_alias, $pfb['snapdir'], $pfb['origdir']);
											}
										}
									);

									// Save Continent data to aliastable folder
									@copy("{$pfbfolder}/{$cc_alias}.txt", "{$pfb['aliasdir']}/{$cc_alias}.txt");
								}

								// Check if file exists and is > 0 in size and save alias file
								$file_chk = 0;
								$cont_chk = "{$pfbfolder}/{$cc_alias}.txt";
								if (file_exists($cont_chk) && @filesize($cont_chk) > 0) {
									$file_chk = exec("{$pfb['grep']} -cv '^#\|^\$' {$cont_chk}");
								}

								if ($file_chk == 0) {
									if ($vtype == '_v6') {
                                                                                $p_ip = "::{$pfb['ip_ph']}";
                                                                        } else {
                                                                                $p_ip = $pfb['ip_ph'];
                                                                        }

									@file_put_contents("{$pfbfolder}/{$cc_alias}.txt", "{$p_ip}\n", LOCK_EX);
									@copy("{$pfbfolder}/{$cc_alias}.txt", "{$pfb['aliasdir']}/{$cc_alias}.txt");
									$log = "[ {$cc_alias} ] Found no unique IPs, adding '{$p_ip}' to avoid empty file\n";
									pfb_logger("{$log}", 1);
								}
							}
						}

						if (file_exists("{$pfbfolder}/{$cc_alias}.txt")) {
							// Create alias config
							$new_aliases_list[] = "{$cc_alias}";
							$new_aliases[] = array( 'name'		=> "{$cc_alias}",
										'url'		=> "{$pfb['weblocal']}?pfb={$cc_alias}",
										'updatefreq'	=> '32',
										'address'	=> '',
										'descr'		=> "pfBlockerNG {$pfbdescr} GeoIP Alias [ {$urlvalue} ]",
										'type'		=> 'urltable',
										'detail'	=> 'DO NOT EDIT THIS ALIAS'
										);

							// Define firewall rule settings
							pfb_firewall_rule($continent_config['action'], $cc_alias, $vtype, $continent_config['aliaslog'],
							    $pfbarr['agateway_in'], $pfbarr['agateway_out'], $pfbarr['aaddrnot_in'], $pfbarr['aaddr_in'],
							    $pfbarr['aports_in'], $pfbarr['aproto_in'], $pfbarr['anot_in'], $pfbarr['aaddrnot_out'],
							    $pfbarr['aaddr_out'], $pfbarr['aports_out'], $pfbarr['aproto_out'], $pfbarr['anot_out']);
						}
						else {
							// unlink Continent list
							unlink_if_exists("{$pfb['aliasdir']}/{$cc_alias}.txt");
						}
					}
				}
			}
		}
	}

	// Remove temp file
	unlink_if_exists("{$pfb['geoip_tmp']}");

	#################################################
	#	Download and Collect IPv4/IPv6 lists	#
	#################################################

	$pfb_ip_regex = pfb_ip_regex_config();
	$pfb['range'] = $pfb_ip_regex['range'];
	$pfb['ipv4'] = $pfb_ip_regex['ipv4'];
	$pfb['ipv6'] = $pfb_ip_regex['ipv6'];

	if ($pfb['enable'] === PfbToggle::On && !$pfb['save']) {

		// issue #1840: init moved to the function's unconditional seeds (near
		// $pfb['repcheck']) -- this loop's TRUE flip below is unaffected.
		$runonce_v4 = $runonce_v6 = TRUE;
		$lists = array();

		// Collect lists and custom list configuration and format into one array ($lists).
		foreach	($ip_types as $ip_type	=> $vtype) {

			// Only the '_v4'/'_v6' suffix may build an alias/path
			if (!pfb_valid_vtype($vtype)) {
				continue;
			}

			foreach (config_get_path("installedpackages/{$ip_type}/config", []) as $key => $list) {
				if (!is_array($list) || !pfb_group_action_valid($list['action'] ?? NULL, 'ipv4')) {
					continue;
				}
				if (!is_array($list['row'])) {
					$list['row'] = array();
				}

				$list['vtype']	= "{$vtype}";	// Collect list IP type
				$list['key']	= "{$key}";	// Collect list array key location

				// If only the 'customlist' is defined. Remove the 'List row' data.
				if (empty(array_get_path($list, 'row/0/url'))) {
					unset($list['row']);
				}

				if (!empty($list['custom'])) {
					array_init_path($list, 'row');
					$list['row'][] = pfb_dnsbl_custom_row($list['aliasname'], $list['custom']);
				}
				$lists[] = $list;
			}

			// Add DNSBLIP, if configured (IPv4 + IPv6)
			if ($pfb['dnsbl'] === PfbToggle::On && pfb_group_action_valid($pfb['dnsbl_ip'] ?? NULL, 'ipv4')
			    && $pfb['dnsbl_ip'] != 'Disabled' && ($vtype == '_v4' || $vtype == '_v6')) {

				$list = array(	'aliasname'	=> 'DNSBLIP',
						'vtype'		=> "{$vtype}",
						'key'		=> 0,
						'dnsblip'	=> '',
						'action'	=> "{$pfb['dnsbl_ip']}",
						);

				$list['row'][] = array(	'format'	=> 'auto',
							'state'		=> 'Enabled',
							'url'		=> "{$pfb['dbdir']}/DNSBLIP{$vtype}.txt",
							'header'	=> 'DNSBLIP');
				$lists[] = $list;
			}
		}

		$maxmind_run_once = $asn_run_once = TRUE;
		foreach	($lists	as $list) {
			if ($runonce_v4 && $list['vtype'] == '_v4') {
				$runonce_v4 = FALSE;
				$log = "\n\n===[  IPv4 Process  ]=================================================\n";
				pfb_logger("{$log}", 1);
			} elseif ($runonce_v6 && $list['vtype'] == '_v6') {
				$runonce_v6 = FALSE;
				$log = "\n\n===[  IPv6 Process  ]=================================================\n";
				pfb_logger("{$log}", 1);
			}

			if ($list['action'] != 'Disabled' && isset($list['row'])) {
				$alias = "pfB_{$list['aliasname']}{$list['vtype']}";	// Capture Alias name
				if (empty(pfb_filter($alias, PFB_FILTER_WORD, 'Download and Collect IPv4/IPv6 lists'))) {
					pfb_logger("\n Invalid Aliasname:{$list['aliasname']}{$list['vtype']}, *skipping*", 1);
					continue;
				}
				// issue #1048: per-alias-pass failure flag -- a sibling feed's success must
				// never close a DIFFERENT feed's still-open download-failure ledger entry.
				$pfb_dl_failed = FALSE;
				// issue #1958: per-alias-pass script state is independent for each alias.
				$pfb_script_state = ['failed' => FALSE];

				foreach	($list['row'] as $row) {
					if (!empty($row['url']) && $row['state'] != 'Disabled') {

						// issue #1270: a header colliding with a reserved package-owned name (e.g.
						// foreign config that bypassed GUI validation) must not download+write to
						// that name's own file; the synthesized DNSBLIP list (below) is exempt.
						if (pfb_reserved_header_skip_active(isset($list['dnsblip']), $row['header'] ?? '')) {
							pfb_logger("\n Reserved Header:{$row['header']}, *skipping*", 1);
							continue;
						}

						$header = "{$row['header']}{$list['vtype']}";	// Capture Header/Label name
						if (empty(pfb_filter($header, PFB_FILTER_WORD, 'Download and Collect IPv4/IPv6 lists'))) {
							pfb_logger("\n Invalid Aliasname:{$list['aliasname']}{$list['vtype']} | Header:{$row['header']}{$list['vtype']}, *skipping*", 1);
							continue;
						}
						$header_esc = escapeshellarg($header);

						// If row is a custom_list, set	flag.
						if (isset($row['custom'])) {
							$custom	= TRUE;
						} else {
							$custom	= FALSE;
						}

						// Maxmind credential verification
						if ($maxmind_run_once && $row['format'] == 'geoip') {
							$mmsg = pfb_maxmind_credential_notice($pfb['maxmind_key'], $pfb['maxmind_account']);
							if ($mmsg !== '') {
								pfb_logger("\n\nURGENT:\n    {$mmsg}\n", 1);
								file_notice('pfBlockerNG MaxMind', $mmsg, 'pfBlockerNG', '/pfblockerng/pfblockerng_ip.php', 2);
							}
							$maxmind_run_once = FALSE;
						}

						// IPinfo ASN Token verification
						if ($asn_run_once && $row['format'] == 'asn') {
							$mmsg = 'To utilize the ASN functionality, you must register for a free IPinfo Account. Review IP Tab for more information.';
							if (empty($pfb['asn_token'])) {
								// issue #1494: $logtype had zero assignments in this function;
								// sibling credential-notice call (MaxMind, above) uses level 1.
								pfb_logger($mmsg, 1);
								file_notice('pfBlockerNG ASN', $mmsg, 'pfBlockerNG', '/pfblockerng/pfblockerng_ip.php', 2);
							}
							$asn_run_once = FALSE;
						}

						// IPv4 Advanced Tunables
						$pfbcidr = 'Disabled';
						if (isset($list['suppression_cidr']) && $list['suppression_cidr'] != 'Disabled' && is_numeric($list['suppression_cidr'])) {
							$pfbcidr = "{$list['suppression_cidr']}";
						}

						// IPv6 Advanced Tunables (issue #760 §3)
						$pfbcidr_v6 = 'Disabled';
						if (isset($list['suppression_cidr_v6']) && $list['suppression_cidr_v6'] != 'Disabled' && is_numeric($list['suppression_cidr_v6'])) {
							$pfbcidr_v6 = "{$list['suppression_cidr_v6']}";
						}

						// cURL Source Interface (sets CURLOPT_INTERFACE)
						$srcint = $list['srcint'] ?: FALSE;

						// IP v4/6 Advanced Tunable - (Pre/Post Script processing)
						// list_scripts/ first, legacy package root as upgrade fallback.
						$pfb_script_pre  = FALSE;
						$pfb_script_post = FALSE;
						if (isset($list['script_pre']) && !empty($list['script_pre'])) {
							$pfb_script_pre = pfb_resolve_list_script($list['script_pre']);
						}
						if (isset($list['script_post']) && !empty($list['script_post'])) {
							$pfb_script_post = pfb_resolve_list_script($list['script_post']);
						}
						// Determine 'list' details (return array $pfbarr)
						if (isset($list['dnsblip'])) {
							$list_type = 'pfblockerngdnsblsettings';
						} else {
							// $ip_type is stale here (this download loop runs after the
							// collection loop); derive the section from the list's vtype (#709).
							$list_type = pfb_list_section_for_vtype($list['vtype']);
						}

						pfb_determine_list_detail($list['action'], $header, $list_type, $list['key']);
						$pfbadv		= $pfbarr['adv'];
						$pfbfolder	= $pfbarr['folder'];
						$pfborig	= $pfbarr['orig'];
						$pfbreuse	= $pfbarr['reuse'];
						$logtab		= $pfbarr['logtab'];
						$scheduled_family = $list['vtype'] === '_v4' ? 'ipv4' : 'ipv6';
						$scheduled_selected = pfb_schedule_feed_selected($scheduled_family, $header);
						if (!$scheduled_selected && !file_exists("{$pfbfolder}/{$header}.txt")) {
							continue;
						}
						if (!$scheduled_selected) {
							$pfb_script_pre = $pfb_script_post = FALSE;
						}

						// Collect active alias list (Used for pfctl update when 'Reputation' is enabled.
						$pfb_alias_lists_all[] = "{$alias}";

						// Set update flags on new downloads available for GeoIP and ASN
						if ($row['format'] == 'geoip' && file_exists("{$pfb['dbdir']}/geoip.update")) {
							touch("{$pfbfolder}/{$header}.update");
						}
						if ($row['format'] == 'asn' && file_exists("{$pfb['dbdir']}/asn.update")) {
							touch("{$pfbfolder}/{$header}.update");
						}

						// issue #1960/#1278: a configured pre/post script re-runs its transform
						// every pass, but the Hold contract ("download once, never again") is
						// protected ONLY by this fast path -- so the script term may push a row
						// off it solely when a local '.orig' baseline exists to reparse (routes
						// to the existing local-reuse branch below, never the network). No
						// baseline -> stay on the fast path; no Hold-specific branch anywhere.
						$pfb_ip_verbatim_reuse = file_exists("{$pfbfolder}/{$header}.txt") &&
						    (!$scheduled_selected || !file_exists("{$pfbfolder}/{$header}.update")) &&
						    (!$scheduled_selected || !file_exists("{$pfbfolder}/{$header}.fail")) &&
						    $pfbreuse == '';
						$pfb_ip_reuse_decision = pfb_ip_script_reuse_decision(
						    $pfb_ip_verbatim_reuse, $pfb_script_pre, $pfb_script_post,
						    "{$pfborig}/{$header}.orig");
						$pfb_user_script = $pfb_ip_reuse_decision['has_user_script'];
						$pfb_script_reparse = $pfb_ip_reuse_decision['reparse'];

						if ($pfb_ip_reuse_decision['verbatim']) {

							if ($row['state'] == 'Hold') {
								$log = "\n[ {$header} ]{$logtab} static hold.";
							} else {
								$log = "\n[ {$header} ]{$logtab} exists.";
							}
							pfb_logger("{$log}", 1);
						}
						else {
							// Short-circuit: skip the stat() below when reuse is off (ADR-28);
							// FALSE here is truth-functionally identical since the callee ANDs $reuse_on anyway.
							// issue #1278: OR in the script-reparse route -- a scripted row with a
							// local '.orig' baseline reuses it (never a network refetch); a Hold row
							// with no baseline never reaches this branch (see the fast path above).
							$pfbreuse_on = $pfbreuse == 'on' || $pfb_script_reparse;
							$orig_exists_if_reused = $pfbreuse_on && file_exists("{$pfborig}/{$header}.orig");
							if (pfb_ip_reuse_skip_active($pfbreuse_on, $orig_exists_if_reused, isset($list['dnsblip']))) {
								$log = "\n[ {$header} ]{$logtab} Reload";
							} else {
								$log = "\n[ {$header} ]{$logtab} Downloading update";
							}
							pfb_logger("{$log}", 1);
							$file_dwn = "{$pfborig}/{$header}";
							$orig_content_stale = FALSE;
							$downloaded_fresh = FALSE;

							// Force 'Alias Native' setting to any Alias with 'Advanced Inbound/Outbound -Invert src/dst' settings.
							// This will bypass Deduplication and Reputation features.
							if ($pfbarr['aaddrnot_in'] == 'on' || $pfbarr['aaddrnot_out'] == 'on') {
								pfb_logger("Using Alias Native\n", 1);
							}

							if (!$custom) {
								pfb_logger(' .', 1);

								// Allow cURL SSL downgrade 'Flex' if user configured.
								$pflex = FALSE;
								if ($row['state'] == 'Flex') {
									$pflex = TRUE;
								}

								// Adjust 'geoip' format to GeoIP path location
								if ($row['format'] == 'geoip') {
									if (strpos($row['url'], ' ') !== FALSE) {
										$row['url'] = strstr($row['url'], ' ', TRUE);
									}
									if (!empty(pfb_filter($row['url'], PFB_FILTER_WORD, 'Adjust geoip format to GeoIP path location'))) {
										$row['url'] = "/usr/local/share/GeoIP/cc/{$row['url']}{$list['vtype']}.txt";
									} else {
										$row['url'] = '';
									}
								}

								// Remove 'whois' source field description
								elseif ($row['format'] == 'asn') {
									if (strpos($row['url'], ' ') !== FALSE) {
										$row['url'] = strstr($row['url'], ' ', TRUE);
									}
								}

								// Determine if	list needs to be downloaded or reuse previously downloaded file.
								$orig_exists_if_reused = $pfbreuse_on && file_exists("{$file_dwn}.orig");
								if (pfb_ip_reuse_skip_active($pfbreuse_on, $orig_exists_if_reused, isset($list['dnsblip']))) {
									// File exists/reuse

									// Process Emerging Threats IQRisk if required
								if (strpos($row['url'], 'iprepdata.txt') !== FALSE) {
									// issue #2776: record whether a leftover .raw existed BEFORE the
									// pipeline call -- the supported pure-reuse path (no .raw) also
									// returns FALSE, so only a leftover .raw may fail the pass.
									$et_raw_exists = file_exists("{$file_dwn}.raw");
									$et_pipeline_ok = pfb_apply_gunzip_orig_pipeline(
										"{$file_dwn}.raw", "{$file_dwn}.orig",
										static function (string $orig) use ($pfb, $header_esc, $elog, &$et_status): void {
											// issue #2776: the reuse arm reads processet()'s exit status too --
											// the gated shape issue #2683 gave pfb_download()'s et arm, with the
											// same extraction ceiling riding along via pfb_extract_cmd().
											exec(pfb_extract_cmd("{$pfb['script']} et {$header_esc} x x x x x {$pfb['etblock']} {$pfb['etmatch']} {$elog}"), $et_output, $et_status);
										}
									);
									// issue #2776 (CodeRabbit round 2): a leftover .raw whose staged
									// gunzip publish fails never runs the consumer above, so $et_status
									// keeps its initial 0 -- escalate that staging failure first, the
									// same way the exit-status gate below escalates a failed processet().
									if ($et_raw_exists && !$et_pipeline_ok) {
										pfb_logger("\n[ {$header} ] ET reuse staging failed ({$file_dwn}.raw publish skipped, pfB_Match_ET_* not refreshed)", 2);
										$pfb_dl_failed = TRUE;
										pfb_download_ledger_failure('ip', $alias, $header, $pfb['dbdir']);
									}
									// issue #2776: an aborted reuse pass must not read as completed -- the
									// pfB_Match_ET_* publications it should have refreshed stay stale, so
									// escalate the way the download arm's failure above already does.
									elseif (!pfb_download_extraction_succeeded($et_status)) {
										pfb_logger("\n[ {$header} ] ET processet failed on reuse (script exit {$et_status})" . pfb_extract_cap_note($et_status), 2);
										$pfb_dl_failed = TRUE;
										pfb_download_ledger_failure('ip', $alias, $header, $pfb['dbdir']);
									}
								}
								}
								else {
									// Download list
									if (!(pfb_download(new PfbDownloadRequest(
										listUrl: $row['url'],
										downloadPath: $file_dwn,
										flex: $pflex,
										header: $header,
										format: $row['format'],
										logType: 1,
										versionType: $list['vtype'],
										timeout: 300,
										type: '',
										username: '',
										password: '',
										sourceInterface: $srcint,
										extraHeaders: array(),
									))->success)) {

										// Determine reason for download failure
										pfb_download_failure($alias, $header, $pfbfolder, $row['url'], $row['format'], $list['vtype']);
										// ADR-61: sync-status ledger, mirrors the download-fail log above. Keyed on
										// $alias (the pfB_*-prefixed table name), not $header (the per-row label,
										// never prefixed) -- the widget's deep-link recognition matches on the
										// pfB_/DNSBL_ prefix, so keying on $header would leave every entry unlinked.
										// issue #1048: close moves to once-per-alias-pass below, so a
										// sibling feed's success can never mask this failure.
										$pfb_dl_failed = TRUE;
											pfb_download_ledger_failure('ip', $alias, $header, $pfb['dbdir']);

										// Utilize previously download file (If 'fail' marker exists)
										if (file_exists("{$pfbfolder}/{$header}.fail") &&
										    file_exists("{$file_dwn}.orig")) {
											pfb_logger("\n  Restoring previously downloaded file contents...", 2);
											$orig_content_stale = TRUE;
										}
										else {
											if ($pfbadv) {
												// Script to Remove failed lists from masterfile
												exec("{$pfb['script']} remove x x x {$header_esc} {$elog}");
												// issue #1084: drop the stale recompute snapshot too;
												// repcheck so the recompute pass rebuilds without it.
												pfb_ip_recompute_forget_header($header, $pfb['snapdir'], $pfb['origdir']);
												$pfb['repcheck'] = TRUE;
											}
											continue;
										}
									}
									else {
										// Clear any previous download fail marker
										unlink_if_exists("{$pfbfolder}/{$header}.fail");
										$downloaded_fresh = TRUE;
										if (!empty($pfb['scheduled_runtime_cron'])) {
											pfb_schedule_state_record_outcome(
												"{$scheduled_family}:{$header}", PfbScheduleTerminalResult::Success,
												(string) ($pfb['schedule_state_dir'] ?? '/usr/local/etc')
											);
										}
										pfb_logger('.', 1);
									}
								}
								pfb_logger(' completed .', 1);
							}
							else {
								if ($list['whois_convert'] == 'on') {
									// Process Domain/AS based custom list
									$custom_list = str_replace("\n", ',', pfb_text_area_decode($list['custom'], FALSE, TRUE, TRUE));
									if (!empty(pfb_filter($custom_list, PFB_FILTER_CSV_WHOIS, 'Process Domain/AS based custom list'))) {
										exec("{$pfb['script']} whoisconvert {$header_esc} {$list['vtype']} {$custom_list} {$elog}");
									} else {
										pfb_logger("\nFailed to process customlist [AS/Whois convert | " . htmlspecialchars($custom_list) . " ]", 1);
									}
								}
								else {
									// Process IP based custom list
									$custom_list = pfb_text_area_decode($list['custom'], FALSE, TRUE, FALSE);
									@file_put_contents("{$file_dwn}.orig", $custom_list, LOCK_EX);
								}
								pfb_logger(' . completed .', 1);
							}

							$ip_data = '';		// IPs collected from feed
							$ip_suppressed = FALSE;	// TRUE when suppression dropped otherwise-valid IPv6 entries
							$parse_fail = 0;	// Failed parsed lines from feed
							$ip_lineno = 0;		// issue #1004: per-line counter for the parse-error detail sink
							pfb_logger('.', 1);

							// Set 'auto' format for all lists, except for lists that require 'regex' parsing.
							if ($row['format'] == 'regex') {
								$pftype = 'regex';
							}
							else {
								$url = pathinfo($row['url']);

								// Strip any text after '?'
								if (strpos($url['extension'], '?') !== FALSE) {
									$url['extension'] = strstr($url['extension'], '?', TRUE);
								}

								// Determine if list is an IBlock list
								if (strpos($url['dirname'], 'iblocklist') !== FALSE) {
									$url['extension'] = 'iblock';
								}

								// Use 'regex' IP parser for non-standard IP lists.
								if (in_array($url['extension'], array('html', 'htm', 'php', 'aspx', 'cgi', 'csv', 'rules', ''))) {
									$pftype = 'regex';
								} else {
									$pftype = 'auto';
								}
							}

							// issue #1925: normalize once per file; the parse below reads .norm
							// (raw .orig on normalize failure). A fresh download whose NORMALIZED
							// content is byte-identical to the previous pass keeps the staged
							// '.txt' untouched; any pre-script (below) runs on a staged copy of
							// this normalized output, never on the raw download.
							$pfb_norm = pfb_feed_normalize("{$file_dwn}.orig");
							if (pfb_ip_norm_reuse_skip($downloaded_fresh, (bool) $custom, $orig_content_stale,
							    $pfb_norm['changed'], file_exists("{$pfbfolder}/{$header}.txt"), $pfb_user_script)) {
								pfb_logger("\n[ {$header} ]{$logtab} unchanged after normalization.\n", 1);
								unlink_if_exists("{$pfbfolder}/{$header}.update");
								continue;
							}

							// issue #1925: the pre-script runs on a staged copy of the
							// normalized output -- '.orig' and '.norm' stay untouched; a
							// failed transform keeps the last known-good staged list.
							$pfb_parse_path = $pfb_norm['path'];
							$pfb_staged_path = NULL;
							if ($pfb_script_pre && is_file("{$pfb_script_pre}")) {
								pfb_logger("\nExecuting pre-script: {$list['script_pre']}\n", 1);
								$pfb_pre = pfb_list_pre_script_run($pfb_norm['path'], "{$file_dwn}.pre",
								    $pfb_script_pre, $list['script_pre'], $header,
								    escapeshellarg("{$file_dwn}.pre") . " {$list['vtype']} {$elog}");
								if (!$pfb_pre['ok']) {
									// issue #1958: pre-script failure genuinely served last-known-good --
									// mark it in the ledger (distinct 'script' stage, never 'download') and
									// retry the transform on the next ordinary pass via the '.update' marker.
									pfb_ip_script_failure_continue($alias,
									    "[ {$alias} - {$header} ] Pre-script FAIL - serving last known-good",
									    $pfb['dbdir'], "{$pfbfolder}/{$header}.update", $pfb_script_state,
									    FALSE, "{$pfbfolder}/{$header}.txt");
									continue;
								}
								$pfb_parse_path = $pfb_pre['path'];
								$pfb_staged_path = $pfb_pre['path'];
							}

								if (($fhandle = @fopen($pfb_parse_path, 'r')) !== FALSE) {
									while (($line = @fgets($fhandle)) !== FALSE) {
										$replayed_line = pfb_ip_parse_line_replay($line, [
											'vtype'         => $list['vtype'],
											'pftype'        => $pftype,
											'custom'        => $custom,
											'cidr_floor_v4' => $pfbcidr,
											'cidr_floor_v6' => $pfbcidr_v6,
											'suppression'   => $pfb['supp'],
											'range'         => $pfb['range'],
											'ipv4'          => $pfb['ipv4'],
											'ipv6'          => $pfb['ipv6'],
										], $ip_lineno, $ip_data, $ip_suppressed, $parse_fail);
										$ip_lineno    = $replayed_line['line_number'];
										$line         = $replayed_line['line'];
										$ip_suppressed = $replayed_line['ip_suppressed'];
										$parse_fail   = $replayed_line['parse_fail'];
										foreach ($replayed_line['messages'] as $message) {
											pfb_logger($message, 1);
										}
										if ($replayed_line['detailed_parse_fail']) {
											pfb_parse_fail_log($header, $line, $replayed_line['raw_line'], $pfb['ip_parse_err'], $ip_lineno, TRUE);
										}
								}
							}
							if ($fhandle) {
								@fclose($fhandle);
							}

							// One summary line per feed with the final count (mirrors the DNSBL
							// strict-scheme WARNING) -- was previously one spammed line PER failed
							// line, e.g. "[!] Parse Errors [ 1 ]" through "[ 967 ]" for a single feed.
							// Names the feed: this is logtype 2 (also written to the error log,
							// which has no surrounding "[ header ] Reload..." context of its own).
							// Leading \n: closes the unterminated "Reload . completed .." progress
							// line above (a rarely-configured per-list Pre Script tunable can print
							// its own newline-terminated line first instead -- one harmless extra
							// blank line in that case, not a rejoin).
							pfb_ip_parse_fail_warn($parse_fail, $header);
							pfb_logger("\n", 1);

							// IP v4/6 Advanced Tunable - (Post Script processing)
							if ($pfb_script_post && is_file("{$pfb_script_post}")) {
								pfb_logger("\nExecuting post-script: {$list['script_post']}\n", 1);
								$file_org_esc = escapeshellarg("{$file_dwn}.orig");
								@copy("{$file_dwn}.orig", "{$file_dwn}.orig.post"); // Save original file for restoration
								$pfb_post_status = pfb_list_script_exec($pfb_script_post, $list['script_post'], 'post', $header,
								    "{$file_org_esc} {$list['vtype']} {$elog}");
								if ($pfb_post_status !== 0) {
									// issue #1927: restore the download now so the empty-feed check
									// below reads it, not the failed script's leftovers.
									if (file_exists("{$file_dwn}.orig.post")) {
										@rename("{$file_dwn}.orig.post", "{$file_dwn}.orig");
									}
								}
								// issue #2059: 'script' stage, never 'download' -- the feed refreshed.
								pfb_list_post_script_failure_record($pfb_post_status, 'ip', $alias,
								    "[ {$alias} - {$header} ] Post-script FAIL - feed updated, side effects incomplete",
								    $pfb['dbdir'], $pfb_script_state);
							}

							// Check to see if list actually failed download or has no IPs listed.
							// issue #1925: probe the content the parse consumed -- a pre-script
							// synthesizes or reduces entries, so the raw download's emptiness is
							// not the feed's (post-script-only feeds still probe '.orig'). Custom
							// rows skip the probe but still discard their transient staged copy.
							$file_chk = pfb_ip_script_probe_staged(
								$custom, $pfb_parse_path, $pfb_staged_path,
								static function (string $parse_path) use ($pfb, $pfb_norm, $file_dwn): string {
										$pfb_probe = ($parse_path === $pfb_norm['path']) ? "{$file_dwn}.orig" : $parse_path;
										if (file_exists($pfb_probe) && @filesize($pfb_probe) > 0) {
											return (string) exec("{$pfb['grep']} -cv '^#\|^\$' " . escapeshellarg($pfb_probe));
										}
										return '';
									}, "{$file_dwn}.pre");

							if (!$custom && $file_chk == 0) {
									if ($list['vtype'] == '_v6') {
										$p_ip = "::{$pfb['ip_ph']}";
									} else {
										$p_ip = $pfb['ip_ph'];
									}

									$ip_data	= "{$p_ip}\n";
									$log		= "  Empty file, Adding '{$p_ip}' to avoid download failure.\n";
									pfb_logger("{$log}", 1);
							}
							// All parsed IPv6 entries were suppressed; replace the list with the IPv6
							// placeholder so stale (previously-loaded) entries are not left in the alias.
							if (empty($ip_data) && $ip_suppressed && $list['vtype'] == '_v6') {
								$p_ip     = "::{$pfb['ip_ph']}";
								$ip_data  = "{$p_ip}\n";
								pfb_logger("  All IPv6 entries suppressed, adding '{$p_ip}' to avoid stale alias contents.\n", 1);
							}

							if (!empty($ip_data)) {
								// Save List to '.txt' format in appropriate folder
								@file_put_contents("{$pfbfolder}/{$header}.txt", "{$ip_data}", LOCK_EX);

								// Call 'shell script' functions (Deny Actions only)
								if ($pfbadv && $list['vtype'] == '_v4') {
									$args = pfb_ip_preprocess_args($pfb['dup'] === PfbToggle::On, $pfb['agg'] === PfbToggle::On, $pfb['rep'] === PfbToggle::On);
									if (!empty($args)) {
										// issue #1896: boundary conversion -- the shell script reads this
										// positional token raw ('on'/''), never the enum itself.
										$pfb_drep_token = $pfb['drep']->toStored();
										exec("{$pfb['script']} {$args} {$header_esc} {$pfb['max']} " . escapeshellarg($pfb_drep_token) . " {$pfb['ccexclude']} {$pfb['ccwhite']} {$pfb['ccblack']} {$elog}");
									}

									// issue #1084: snapshot the pristine post-preprocessing feed for the
									// batch recompute memberlist -- replaces duplicate()'s per-feed write.
									pfb_ip_recompute_write_snapshot("{$pfbfolder}/{$header}.txt", $header, $pfb['snapdir'], $pfb['origdir']);
								}

								if (!$pfbadv && $list['vtype'] == '_v4') {
									// Call Aggregate process
									if ($pfb['agg'] === PfbToggle::On) {
										exec("{$pfb['script']} cidr_aggregate {$header_esc} {$pfbfolder} {$elog}");
									}
								}

								// issue #1084: v6 Deny has no _255/_agg/_rep chain -- the parsed .txt IS
								// the snapshot the recompute memberlist reads. A v6 change must flip
								// repcheck too (v6 now joins cross-list dedup + the closing pass).
								if ($pfbadv && $list['vtype'] == '_v6') {
									pfb_ip_recompute_write_snapshot("{$pfbfolder}/{$header}.txt", $header, $pfb['snapdir'], $pfb['origdir']);
									$pfb['repcheck'] = TRUE;
								}

								// Collect updated alias lists ('Reputation' disabled)
								$pfb_alias_lists[] = "{$alias}";

								if ($pfbadv && $list['vtype'] == '_v4') {
									// Execute Reputation functions, when changes are found
									// (v4-only: dedup/reputation bookkeeping is v4-only,
									// ADR-53 §1.2).
									$pfb['repcheck'] = TRUE;
								}

								// Enable suppression process due to updates -- BOTH families
								// (ADR-53 review finding A): a v6-only Deny alias must also be
								// able to unlock the v6 suppress pass below, not just v4's.
								if (pfb_supp_update_active($pfbadv, $pfb['supp'] === PfbToggle::On)) {
									$pfb['supp_update'] = TRUE;
								}
							} else {
								if (!$custom) {
									$log = "[ {$alias} {$header} ] No IPs found! Ensure only IP based Feeds are used! ]\n";
								} else {
									$log = "[ {$alias} {$header} ] Custom List: No IPs found! Ensure only IP based Feeds are used! ]\n";
								}
								pfb_logger("{$log}", 1);
							}
							unset($ip_data);

							// Remove update file indicator -- skip if this row fell through to the
							// stale-.orig download-failure fallback, else a pending rebuild is
							// stranded like #1002 but via the download-failure path. (#1022)
							if (pfb_ip_update_marker_clear_active($orig_content_stale)) {
								unlink_if_exists("{$pfbfolder}/{$header}.update");
							}

							// Restore Original Downloaded file after Post Script function
							if (file_exists("{$file_dwn}.orig.post")) {
								@rename("{$file_dwn}.orig.post", "{$file_dwn}.orig");
							}
						}
					}
				}

				// issue #1048: close the download ledger entry once for the WHOLE
				// alias-pass, iff no row in it failed -- a per-row close let a later
				// feed's success mask an earlier feed's still-live failure.
				pfb_download_ledger_close_if_clean('ip', $alias, $pfb_dl_failed, $pfb['dbdir']);

				// issue #1958/#2059: ADR-61 symmetric ownership -- close the 'script'
				// stage entry once for the WHOLE alias-pass, iff no row's pre- or
				// post-script failed.
				pfb_ip_script_failure_close($alias, $pfb['dbdir'], $pfb_script_state);
			}
		}
	}

	// Remove database update file markers
	unlink_if_exists("{$pfb['dbdir']}/geoip.update");
	unlink_if_exists("{$pfb['dbdir']}/asn.update");

	#################################
	#	REPUTATION PROCESSES	#
	#################################

	// issue #1173: a pure priority reorder flips no feed-change repcheck; ownership
	// follows memberlist order, so compare against the last recompute's memberlist and
	// recompute on mismatch.
	if (pfb_ip_recompute_order_scope(
	    $pfb['save'],
	    $pfb['enable'] === PfbToggle::On,
	    $pfb['dup'] === PfbToggle::On,
	    $pfb['drep'] === PfbToggle::On,
	    $pfb['prep'] === PfbToggle::On
	)) {
		foreach (pfb_ip_recompute_order_families($pfb['dup'] === PfbToggle::On) as $pfb_rec_family) {
			if (pfb_ip_recompute_order_changed(
			    pfb_ip_recompute_family_headers($pfb['existing']['deny'] ?? [], $pfb_rec_family),
			    $pfb['snapdir'],
			    "{$pfb['dbdir']}/pfb_recompute_{$pfb_rec_family}.members")) {
				$pfb['repcheck'] = TRUE;
				break;
			}
		}
	}

	// issue #1084: batch recompute replaces the incremental duplicate()/dmax/pmax pass.
	// enable_dup drives a full v4+v6 pass; dedup-off + reputation alone is v4-only; both
	// off skips recompute (parse output stands) -- see pfb_ip_recompute_matrix(). The
	// whole block rides the feed-changed trigger: a quiet pass (no snapshot written, no
	// removal -- repcheck FALSE) runs no recompute at all.
	$pfb_rec_trigger = $pfb['repcheck'] && !$pfb['save'] && $pfb['enable'] === PfbToggle::On;
	$pfb_rec_matrix  = pfb_ip_recompute_matrix(
		$pfb['dup'] === PfbToggle::On && $pfb_rec_trigger,
		$pfb_rec_trigger,
		$pfb['drep'] === PfbToggle::On,
		$pfb['prep'] === PfbToggle::On
	);

	// issue #1084 review: whether the recompute exec actually ran THIS pass, per family --
	// set exactly where the exec fires. Snapshots are pre-suppression captures, but
	// recompute rewrites EVERY family alias whenever it runs, so a downstream gate keyed
	// only on "this alias's OWN feed changed" (suppression body, the FINAL REPORTING
	// closing verb) misses an alias recompute resurrected via an unrelated sibling's
	// change. Consumed by pfb_ip_suppress_body_active() / pfb_ip_closing_pass_active().
	$pfb_recompute_ran_v4 = FALSE;
	$pfb_recompute_ran_v6 = FALSE;

	foreach (array('v4', 'v6') as $pfb_rec_family) {
		if (!$pfb_rec_matrix["invoke_{$pfb_rec_family}"]) {
			continue;
		}

		$pfb_rec_paths = array();
		foreach (pfb_ip_recompute_family_headers($pfb['existing']['deny'] ?? [], $pfb_rec_family) as $pfb_rec_header) {
			$pfb_rec_paths[] = pfb_ip_recompute_seed_snapshot($pfb_rec_header, $pfb['snapdir'], $pfb['denydir']);
		}
		$pfb_rec_memberlist = "{$pfb['dbdir']}/pfb_recompute_{$pfb_rec_family}.members";
		$pfb_rec_countsfile = "{$pfb['dbdir']}/pfb_recompute_{$pfb_rec_family}.counts";
		pfb_ip_recompute_memberlist_write($pfb_rec_memberlist, $pfb_rec_paths);

		// Reputation is v4-only (§1.2); the v6 pass is always a dedup-only passthrough.
		$pfb_rec_repmode = ($pfb_rec_family === 'v4') ? $pfb_rec_matrix['repmode'] : 'off';
		$pfb_rec_max     = ($pfb_rec_repmode === 'dmax') ? $pfb['dmax'] : (($pfb_rec_repmode === 'pmax') ? $pfb['pmax'] : '0');

		pfb_ip_recompute_mark_ran(
			$pfb_rec_family,
			static function () use ($pfb, $pfb_rec_family, $pfb_rec_memberlist, $pfb_rec_countsfile, $pfb_rec_matrix, $pfb_rec_repmode, $pfb_rec_max, $elog): void {
				exec("{$pfb['script']} recompute {$pfb_rec_family} " . escapeshellarg($pfb_rec_memberlist) . ' ' . escapeshellarg($pfb_rec_countsfile)
					. " {$pfb_rec_matrix['dedup']} {$pfb_rec_repmode} {$pfb_rec_max} {$pfb['ccexclude']} {$pfb['ccwhite']} {$pfb['ccblack']} {$elog}");
			},
			$pfb_recompute_ran_v4,
			$pfb_recompute_ran_v6
		);
	}

	// Both dRep and pRep enabled: recompute already applied dMax (the matrix's tie-break)
	// above; run the legacy pMax exec over the emitted deny files -- today's pMax
	// semantics, unmodified (issue #1084).
	if ($pfb_rec_matrix['legacy_pmax_followup']) {
		exec("{$pfb['script']} pmax x {$pfb['pmax']} {$elog}");
	}

	#################################################
	#	CONFIGURE ALIASES AND FIREWALL RULES	#
	#################################################

	// ADR-40: Snapshot the feed-changed set (populated by the download loop above)
	// before the file-write loop.  The file-write loop will rebuild $pfb_alias_lists
	// as the content-diff set (aliases whose canonical membership set actually changed),
	// which is what the pfctl regions and ADR-12 emit consume.
	// $pfb_feed_changed: input to the hybrid scope gate; keeps the suppression sub-process
	// and "read member files" decision anchored to feed-changed aliases.
	$pfb_feed_changed    = $pfb_alias_lists;
	$pfb_alias_lists     = array();   // reset: refilled below with content-validated aliases
	// ADR-40: per-alias map from alias name -> previous canonical set (what was in the
	// mirror BEFORE this pass wrote the new one).  Captured in the write loop (below) so the
	// no-rule-change reload site can compute add/del deltas without a second file read.
	$pfb_alias_prev_sets = array();

	// ADR-40: hoist cross-list scope and feed-changed alias selection here — both
	// inputs ($pfb['dup'], $pfb['drep'], $pfb['prep'], $pfb_feed_changed,
	// $pfb_alias_lists_all) are invariant across the $ip_types / $lists loops below.
	// Avoids redundant recomputation on every list iteration.
	$pfb_cross_list  = pfb_cross_list_scope(
		$pfb['dup'] === PfbToggle::On,
		$pfb['drep'] === PfbToggle::On || $pfb['prep'] === PfbToggle::On
	);
	// $final_alias_old: feed-changed aliases only (for suppression gate).
	// Uses $pfb_feed_changed (the pre-write-loop snapshot) — not $pfb_alias_lists
	// which is now being built as the content-diff set this pass.
	$final_alias_old = pfb_select_reload_aliases(
		FALSE,
		$pfb_feed_changed,
		$pfb_alias_lists_all
	);

	foreach ($ip_types as $ip_type => $vtype) {

		// Only the '_v4'/'_v6' suffix may build an alias/path
		if (!pfb_valid_vtype($vtype)) {
			continue;
		}

		$lists = config_get_path("installedpackages/{$ip_type}/config");

		// Add DNSBLIP, if configured (IPv4 + IPv6)
		if ($pfb['dnsbl'] === PfbToggle::On && pfb_group_action_valid($pfb['dnsbl_ip'] ?? NULL, 'ipv4')
		    && $pfb['dnsbl_ip'] != 'Disabled' && ($vtype == '_v4' || $vtype == '_v6')) {

			$list = array(	'aliasname'	=> 'DNSBLIP',
					'vtype'		=> "{$vtype}",
					'key'		=> 0,
					'dnsblip'	=> '',
					'action'	=> "{$pfb['dnsbl_ip']}",
					'aliaslog'	=> "{$pfb['dnsblconfig']['aliaslog']}");

			$list['row'][] = array( 'format'	=> 'auto',
						'state'		=> 'Enabled',
						'url'		=> "{$pfb['dbdir']}/DNSBLIP{$vtype}.txt",
						'header'	=> 'DNSBLIP');
			$lists[] = $list;
		}

		if (!empty($lists) && $pfb['enable'] === PfbToggle::On) {
			$pfbrunonce = TRUE;
			foreach ($lists as $key => $list) {
				if (!pfb_group_action_valid($list['action'] ?? NULL, 'ipv4')) {
					continue;
				}
				$alias = "pfB_{$list['aliasname']}{$vtype}";
				if (empty(pfb_filter($alias, PFB_FILTER_WORD, 'Configure Aliases and Firewall Rules'))) {
					pfb_logger("\n Invalid Aliasname:{$list['aliasname']}{$vtype}, *skipping*", 1);
					continue;
				}

				// Skip any Alias that are 'enabled' but Lists/customlists are not defined.
				if (empty($list['row'][0]['url']) && empty($list['custom'])) {
					pfb_pfctl_table_op($alias, 'kill');
					continue;
				}

				if (isset($list['dnsblip'])) {
					$list_type = 'pfblockerngdnsblsettings';
				} else {
					$list_type = "{$ip_type}";
				}

				// Determine 'list' details (return array $pfbarr). Use the list's own key
				// (the synthetic DNSBLIP entry carries key=0 for the pfblockerngdnsblsettings
				// singleton); real config rows have no 'key', so fall back to the foreach index
				// = the config row index (#710). Mirrors the download-loop call.
				pfb_determine_list_detail($list['action'], '', $list_type, $list['key'] ?? $key);
				$pfbadv		= $pfbarr['adv'];
				$pfbdescr	= $pfbarr['descr'];
				$pfbfolder	= $pfbarr['folder'];

				// ADR-40: Content-addressed reload gate (hybrid scope).
				// $pfb_cross_list and $final_alias_old are computed once before the
				// $ip_types / $lists loops (their inputs are loop-invariant) — see
				// the hoist above.

				if ($list['action'] != 'Disabled') {
					$pfbupdate	= FALSE;
					$alias_ips	= '';	// IP Collection of all Lists in the Alias
					$urlvalue	= '';	// Firewall: Aliases value field

					if (isset($list['row'])) {
						foreach ($list['row'] as $row) {
							if (!empty($row['url']) && $row['state'] != 'Disabled') {

								// issue #1270: this loop reads config independently of the
								// download loop above -- a reserved header must not be read
								// into an alias/firewall rule here either.
								if (pfb_reserved_header_skip_active(isset($list['dnsblip']), $row['header'] ?? '')) {
									pfb_logger("\n Reserved Header:{$row['header']}, *skipping*", 1);
									continue;
								}

								$header = "{$row['header']}{$vtype}";
								if (empty(pfb_filter($header, PFB_FILTER_WORD, 'Configure Aliases and Firewall Rules'))) {
									pfb_logger("\n Invalid Aliasname:{$list['aliasname']}{$vtype} | Header:{$row['header']}{$vtype}, *skipping*", 1);
									continue;
								}
								$header_esc	= escapeshellarg($header);
								$urlvalue	.= "{$header},";

								$pfctlck = pfb_pfctl_table_count($alias);

								// ADR-40: read member files when:
								//   (a) cross-list scope → always (dedup/rep can shift any alias), OR
								//   (b) this alias had a feed change this pass, OR
								//   (c) kernel table is empty (boot/repopulation).
								$member_eligible = $pfb_cross_list
									|| in_array($alias, $final_alias_old)
									|| empty($pfctlck);
								if (file_exists("{$pfbfolder}/{$header}.txt") && $member_eligible) {
									$suppression_body_active = pfb_ip_suppress_body_for_vtype($pfb['supp'] === PfbToggle::On, $vtype, $pfb['supp_update'], $pfbadv, in_array($alias, $final_alias_old), $pfb_recompute_ran_v4, $pfb_recompute_ran_v6);
									// Script to run suppression process (print header only)
									if ($pfbrunonce && $pfb['supp'] === PfbToggle::On && $vtype == '_v4' && $pfb['supp_update']
									    && pfb_ip_suppress_list_present($pfb['supptxt'])) {
										exec("{$pfb['script']} suppress suppressheader {$elog}");
										$pfbrunonce = FALSE;
									}
									// Script to run suppression process (body) — feed-changed aliases, OR any
									// alias recompute rewrote this pass (issue #1084 review: recompute rewrites
									// every family alias on any trigger, not just feed-changed ones).
									if ($suppression_body_active && $vtype == '_v4'
									    && pfb_ip_suppress_list_present($pfb['supptxt'])) {
										if ($pfb['dup'] === PfbToggle::On) {
											exec("{$pfb['script']} suppress {$header_esc} {$pfbfolder} on {$elog}");
										} else {
											exec("{$pfb['script']} suppress {$header_esc} {$pfbfolder} off {$elog}");
										}
									}

									// ADR-53: v6 sibling of the v4 suppression block above -- a direct
									// PHP call (pfb_suppress_file_v6()), no shell round-trip (ADR-53 §2.1 v6
									// wiring). No masterfile/dedup resync here: that bookkeeping is v4-only
									// (§1.2). $pfbrunonce is reset TRUE at the top of EVERY vtype pass (see
									// the "$pfbrunonce = TRUE;" above the alias loop), so it is still
									// available -- untouched by the v4 branch above during a '_v6' pass --
									// to gate this print-once header the same way v4 gates its own.
									if ($pfbrunonce && $pfb['supp'] === PfbToggle::On && $vtype == '_v6' && $pfb['supp_update']) {
										$supp_v6_header = "\n===[ Suppression Stats (v6) ]===============================\n\n"
											. sprintf("%-20s %-10s %-10s\n", 'List', 'Pre', 'Suppress')
											. "-------------------------------------------------------------\n";
										@file_put_contents("{$pfb['log']}", $supp_v6_header, FILE_APPEND);
										$pfbrunonce = FALSE;
									}
									if ($suppression_body_active && $vtype == '_v6'
									    && pfb_ip_suppress_list_present($pfb['supptxt_v6'])) {
										$member_file = "{$pfbfolder}/{$header}.txt";
										$pre_count   = count(@file($member_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: []);
										if (pfb_suppress_file_v6($member_file, "{$pfb['supptxt_v6']}")) {
											$post_count = count(@file($member_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: []);
											@file_put_contents("{$pfb['log']}", sprintf("%-20s %-10s %-10s\n", $header, $pre_count, $post_count), FILE_APPEND);
										} else {
											pfb_logger(" Suppression {$header}: v6 suppression failed; keeping previous list", 2);
										}
									}

									$alias_ips .= file_get_contents("{$pfbfolder}/{$header}.txt");
									$pfbupdate = TRUE;
								}
							}
						}
					}

					// check custom network list
					$aliasname = "{$list['aliasname']}_custom{$vtype}";

					// Update alias if list file exists and its been updated or if the alias URL table is empty.
					$pfctlck = pfb_pfctl_table_count($alias);
					if (!empty($list['custom'])) {
						$urlvalue .= "{$aliasname},";
						// ADR-40: same scope logic for custom lists.
						$custom_eligible = file_exists("{$pfbfolder}/{$aliasname}.txt")
							&& ($pfb_cross_list || in_array($alias, $final_alias_old) || empty($pfctlck));
						if ($custom_eligible) {
							$alias_ips .= file_get_contents("{$pfbfolder}/{$aliasname}.txt");
							$pfbupdate = TRUE;
						}
					}

					// Determine validity of alias URL tables/rules. ie: Don't create empty URL tables or aliases
					if (empty($alias_ips) && empty($pfctlck)) {
						unlink_if_exists("{$pfb['aliasdir']}/{$alias}.txt");
					}
					else {
						// ADR-40: Compute the canonical set from the raw concat, compare
						// against the last-applied mirror (the existing aliasdir file), and write
						// only when the set changed.  This replaces the old pfbupdate flag write
						// (which wrote on every feed-fetch) with a content-addressed gate.
						if ($pfbupdate) {
							$alias_mirror  = "{$pfb['aliasdir']}/{$alias}.txt";
							$canonical_set = pfb_canonical_alias_set($alias_ips);
							if (pfb_alias_set_different($canonical_set, $alias_mirror) || empty($pfctlck)) {
								// ADR-40: capture the previous canonical set before overwriting
								// the mirror, so the reload site has last_set for delta computation.
								// When the kernel table is empty (empty($pfctlck)), stash an empty
								// array so the reload site's force_rpl = empty([]) = TRUE fires a
								// full -T replace to repopulate the kernel (fixes #468 regression:
								// mirror == desired → empty delta → table silently stays empty).
								// When the kernel table is non-empty, stash the mirror content as
								// the true previous set for an accurate forward delta.
								$prev_raw = file_exists($alias_mirror) ? @file_get_contents($alias_mirror) : '';
								$pfb_alias_prev_sets[$alias] = empty($pfctlck) ? array() : pfb_canonical_alias_set($prev_raw ?: '');
								// Set changed (or kernel table is empty) → write the new canonical
								// mirror and flag this alias for pfctl reload.
								pfb_write_canonical_alias($alias_mirror, $canonical_set);
								$pfb_alias_lists[] = "{$alias}";
							}
							// When set is unchanged: aliasdir file is already correct; no reload needed.
						}

						// Add '[s]' to Alias descriptions (Bypass States removal feature)
						$adescr = "pfBlockerNG {$pfbdescr} Alias";
						if ($list['stateremoval'] == 'disabled') {
							$adescr = "pfBlockerNG {$pfbdescr} Alias [s]";
						}

						// Create alias
						$new_aliases_list[] = "{$alias}";
						$new_aliases[] = array(	'name'		=> "{$alias}",
									'url'		=> "{$pfb['weblocal']}?pfb={$alias}",
									'updatefreq'	=> '32',
									'address'	=> '',
									'descr'		=> "{$adescr} [ {$urlvalue} ]",
									'type'		=> 'urltable',
									'detail'	=> 'DO NOT EDIT THIS ALIAS'
									);

						// Define firewall rule settings
						pfb_firewall_rule($list['action'], $alias, $vtype, $list['aliaslog'], $pfbarr['agateway_in'], $pfbarr['agateway_out'],
						    $pfbarr['aaddrnot_in'], $pfbarr['aaddr_in'], $pfbarr['aports_in'], $pfbarr['aproto_in'], $pfbarr['anot_in'],
						    $pfbarr['aaddrnot_out'], $pfbarr['aaddr_out'], $pfbarr['aports_out'], $pfbarr['aproto_out'], $pfbarr['anot_out']);
					}
				}
				else {
					// unlink previous pfblockerNG alias list
					unlink_if_exists("{$pfb['aliasdir']}/{$alias}.txt");
				}
			}
		}
	}
	// Clear variables
	$alias_ips = '';

	// Define DNSBL VIP Ports alias
	if ($pfb['dnsbl_rule'] != 'Disabled' && !empty($pfb['dnsbl_port']) && !empty($pfb['dnsbl_port_ssl'])
	    && !empty($pfb['dnsblconfig']['dnsbl_allow_int']) && ($pfb['dnsbl'] === PfbToggle::On)) {

		$new_aliases_list[] = 'pfB_DNSBL_Ports';
		$new_aliases[] = array( 'name'		=> 'pfB_DNSBL_Ports',
					'address'	=> $pfb['dnsbl_iface'] != 'lo0' ? "{$pfb['dnsbl_port']} {$pfb['dnsbl_port_ssl']}" : '80 443',
					'descr'		=> 'pfBlockerNG DNSBL VIP Ports',
					'type'		=> 'port',
					'detail'	=> 'DO NOT EDIT THIS PORT||DO NOT EDIT THIS PORT'
					);

		if (!empty($pfb['dnsbl_vip6'])) {
			$new_aliases_list[] = 'pfB_DNSBL_VIPs';
			$new_aliases[] = array(	'name'		=> 'pfB_DNSBL_VIPs',
						'address'	=> "{$pfb['dnsbl_vip4']} {$pfb['dnsbl_vip6']}",
						'descr'		=> 'pfBlockerNG DNSBL VIPs',
						'type'		=> 'host',
						'detail'	=> 'DO NOT EDIT THIS HOST||DO NOT EDIT THIS HOST'
						);
		}
	}

	#########################################################################
	#  ADR-11: per-type aggregate ("Uber") Native aliases (opt-in)		#
	#  Wired here -- after every member alias materialises (Deny AFTER the	#
	#  per-member suppress step above, so denydir is post-suppression) and	#
	#  while $new_aliases is still being assembled (config write is below)	#
	#  -- so each selected aggregate is registered + its file built BEFORE	#
	#  the alias-reconcile region and filter_configure() load the tables,	#
	#  which themselves precede the ADR-12 post-update hook (closing tail).	#
	#  Native => registered urltable but NEVER pfb_firewall_rule (no rule).	#
	#########################################################################
	pfb_build_aggregate_aliases($new_aliases, $new_aliases_list, $pfb_alias_lists, $pfb_alias_prev_sets);

	#########################################
	#	UPDATE pfSense ALIAS TABLES	#
	#########################################

	// Reload config.xml to get any recent changes
	config_read_file(FALSE, TRUE);

	$exist_aliases = config_get_path('aliases/alias', []);
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
		if (!empty($pfb['deny_inbound']) || !empty($pfb['permit_inbound']) || !empty($pfb['match_inbound'])) {
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

			// Build the DNSBL floating pass rules (ping + permit pair) to pass into the helper.
			$pfb_dnsbl_float = [];
			if ($pfb['enable'] === PfbToggle::On && $pfb['dnsbl'] === PfbToggle::On && $pfb['dnsbl_rule'] != 'Disabled'
			    && !empty($pfb['dnsbl_port']) && !empty($pfb['dnsbl_port_ssl'])
			    && !empty($pfb['dnsblconfig']['dnsbl_allow_int'])) {

				$rule			= $pfb['base_rule_float'];
				$rule['tracker']	= pfb_tracker('pfB_DNSBL_Ping', '', '');
				$rule['type']		= 'pass';
				$rule['direction']	= 'any';
				$rule['interface']	= "{$pfb['dnsblconfig']['dnsbl_allow_int']}";
				$rule['ipprotocol']	= (!empty($pfb['dnsbl_vip6']) ? $rule['ipprotocol'] = 'inet46' : $rule['ipprotocol'] = 'inet');
				$rule['descr']		= "pfB_DNSBL_Ping{$pfb['suffix']}";
				$rule['protocol']	= 'icmp';
				$rule['icmptype']	= 'echoreq';
				$rule['source']		= array('any' => '');
				$rule['destination']	= array('address' => (!empty($pfb['dnsbl_vip6']) ? 'pfB_DNSBL_VIPs' : $pfb['dnsbl_vip4']));
				$rule['created']	= array('time' => (int)microtime(TRUE), 'username' => 'Auto');
				$pfb_dnsbl_float[]	= $rule;

				$rule			= $pfb['base_rule_float'];
				$rule['tracker']	= pfb_tracker('pfB_DNSBL_Permit', '', '');
				$rule['type']		= 'pass';
				$rule['direction']	= 'any';
				$rule['interface']	= "{$pfb['dnsblconfig']['dnsbl_allow_int']}";
				$rule['ipprotocol']	= (!empty($pfb['dnsbl_vip6']) ? $rule['ipprotocol'] = 'inet46' : $rule['ipprotocol'] = 'inet');
				$rule['descr']		= "pfB_DNSBL_Permit{$pfb['suffix']}";
				$rule['protocol']	= 'tcp/udp';
				$rule['source']		= array('any' => '');
				$rule['destination']	= array('address' => (!empty($pfb['dnsbl_vip6']) ? 'pfB_DNSBL_VIPs' : $pfb['dnsbl_vip4']),
								 'port' => 'pfB_DNSBL_Ports');
				$rule['created']	= array('time' => (int)microtime(TRUE), 'username' => 'Auto');
				$pfb_dnsbl_float[]	= $rule;
			}

			// Build the pfB-generated rule templates (produced by pfb_firewall_rule() above).
			$pfb_generated = [
				'permit_inbound'    => $pfb['permit_inbound']    ?? [],
				'permit_outbound'   => $pfb['permit_outbound']   ?? [],
				'deny_inbound'      => $pfb['deny_inbound']      ?? [],
				'deny_outbound'     => $pfb['deny_outbound']     ?? [],
				'match_inbound'     => $pfb['match_inbound']     ?? [],
				'match_outbound'    => $pfb['match_outbound']    ?? [],
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

			unset($pfb['permit_inbound'], $pfb['permit_outbound'], $pfb['deny_inbound'],
			    $pfb['deny_outbound'], $pfb['match_inbound'], $pfb['match_outbound']);

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

		exec("{$pfb['pfctl']} -s Tables | {$pfb['grep']} '^pfB_'", $pfb_tables);
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
						pfb_pfctl_table_op($pfb_table, 'replace', "-f {$pfb_table_path_esc}");
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
					if (file_exists("{$pfb['aliasdir']}/{$final}.txt")) {
						// ADR-40: compute delta from the stashed previous canonical set.
						// Two cases always get force_rpl = TRUE here:
						//   • ip_unlock-widened aliases: not in $pfb_alias_prev_sets (added
						//     after the write loop), so ?? NULL → empty(NULL) = TRUE.
						//   • Empty-kernel aliases: stashed as [] explicitly (M1 fix), so
						//     empty([]) = TRUE → full -T replace repopulates the kernel.
						// Content-changed aliases stash their actual previous set (non-empty
						// array), so force_rpl = FALSE and the delta path applies normally.
						$mirror_path = "{$pfb['aliasdir']}/{$final}.txt";
						$desired     = pfb_canonical_alias_set(@file_get_contents($mirror_path) ?: '');
						$previous    = $pfb_alias_prev_sets[$final] ?? $desired;
						// Boot / empty-table signal: if the alias was not in the prev-set stash
						// and the kernel table was empty, force a full replace.
						$force_rpl   = empty($pfb_alias_prev_sets[$final] ?? NULL);
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
		// own -- it signals filterd asynchronously and logs its own reload results.
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

	// ADR-43: one fixed 15-minute trigger-tick replaces the cron/dcc/ss_refresh/bl fleet.
	// A single */15 cron entry fires; the tick reads the due-ledger
	// and dispatches each job only when its entry says "due". clearip/cleardnsbl
	// are out of scope (ADR-30 territory) and remain as separate jobs below.
	pfblockerng_configure_tick_cron(
		$pfb['enable'] === PfbToggle::On,
		$pfb['log'],
		NULL,
		FALSE
	);

	// Define pfBlockerNG clear [ dnsbl and/or IP ] counter CRON job
	foreach (array( 'clearip', 'cleardnsbl') as $type) {
		$pfb_cmd = "/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php {$type} >/dev/null 2>&1";
		if (config_get_path("installedpackages/pfblockerngglobal/widget-{$type}") !== null) {
			if (config_get_path("installedpackages/pfblockerngglobal/widget-{$type}") != 'never') {
				$pfb_day = '*';
				if (config_get_path("installedpackages/pfblockerngglobal/widget-{$type}") == 'weekly') {
					$pfb_day = '7';
				}

				// Remove unreferenced 'daily' or 'weekly' cron job
				$pfb_other = ($pfb_day == '*') ? '7' : '*';
				if (pfblockerng_cron_exists($pfb_cmd, '0', '0', '*', $pfb_other)) {
					install_cron_job("pfblockerng.php {$type}", FALSE);
				}

				if (!pfblockerng_cron_exists($pfb_cmd, '0', '0', '*', $pfb_day)) {
					install_cron_job($pfb_cmd, TRUE, '0', '0', '*', '*', $pfb_day, 'root');
				}
			}
			else {
				if (pfblockerng_cron_exists($pfb_cmd, '0', '0', '*', '*')) {
					install_cron_job("pfblockerng.php {$type}", FALSE);
			}
				if (pfblockerng_cron_exists($pfb_cmd, '0', '0', '*', '7')) {
					install_cron_job("pfblockerng.php {$type}", FALSE);
				}
			}
		}
		else {
			if (pfblockerng_cron_exists($pfb_cmd, '0', '0', '*', '*')) {
				install_cron_job("pfblockerng.php {$type}", FALSE);
			}
			if (pfblockerng_cron_exists($pfb_cmd, '0', '0', '*', '7')) {
				install_cron_job("pfblockerng.php {$type}", FALSE);
			}
		}
	}

	#################################
	#	FINAL REPORTING		#
	#################################

	// Only run with CRON or Force invoked process
	if ((!$pfb['save'] && $pfb['repcheck'] && $pfb['enable'] === PfbToggle::On) || $pfb['summary']) {
		// issue #1084 review: dedup off + recompute having run the v4 family (the
		// dup-off+rep-on passthrough) still invokes 'closing off' so emptyfiles() refills
		// any alias pMax/dMax collapsed to zero rows -- see pfb_ip_closing_pass_active().
		[$pfb_closing_invoke, $pfb_closing_alias_arg] = pfb_ip_closing_pass_active($pfb['dup'] === PfbToggle::On, $pfb_recompute_ran_v4);
		if ($pfb_closing_invoke) {
			exec("{$pfb['script']} closing {$pfb_closing_alias_arg} {$elog}");
		}
		if ($pfb['dup'] === PfbToggle::On) {
			pfb_sync_status_dedup_check($pfb['log'], $pfb['dbdir']);
		} else {
			// ADR-61: dedup disabled -- its sanity signal doesn't apply; clear any stale entry.
			pfb_sync_status_close('ip', 'dedup', 'dedup', $pfb['dbdir']);
		}
	}

	// ADR-12: post-update hooks. Fire at the closing tail -- AFTER the IP/DNSBL
	// reloads, filter_configure(), and the FINAL REPORTING 'closing' step above --
	// so the change flags are final. Context is derived ONLY from existing flags
	// (no new tracking):
	//   PFB_IP_CHANGED    = $pfb['filter_configure'] || $pfb_ip_unlock_forced -- set TRUE
	//       when firewall rule/aliastable changes were found and a filter reload was
	//       applied (the IP side), OR when a pending /tmp/ip_unlock file forced a
	//       pfctl-replace re-block without a filter reload -- captured before the unlink,
	//       issue #519 (mirrors $pfb_dnsbl_unlock_forced / issue #517 on the DNSBL side).
	//   PFB_DNSBL_CHANGED = mirrors the gate that drives pfb_update_unbound above:
	//       $pfb_data_changed (fingerprint-derived, or domain_update/domain_clear when
	//       TLD mode / DNSBL inactive), || $pfbupdate || $pfbpython || $safesearch_update,
	//       || $pfb_dnsbl_unlock_forced (a pending /tmp/dnsbl_unlock file forced the
	//       reload — captured before pfb_update_unbound() unlinks it, issue #517).
	//       Reports '1' only when a reload actually fired, so a skipped pass (unchanged
	//       blocklist, fingerprints equal) correctly emits '0'. !empty() guards any flag
	//       whose block did not run — no undefined-variable warning.
	//   PFB_TRIGGER       = $pfb_hook_val (from pfb_req_to_hook_trigger / pfb_hook_trigger).
	//   PFB_CHANGED_IP_ALIASES = the space-separated list of IP firewall aliases UPDATED
	//       this pass (ADR-12) = $pfb_alias_lists (the content-diff set --
	//       pfB_*_v4/_v6 whose canonical membership set actually changed this pass,
	//       as determined by pfb_alias_set_different(); ADR-40).  Reputation/dedup
	//       no longer inflate this to all active aliases -- only moved tables appear here.
	//       The IP locals are in scope only at this tail, so they are merged into
	//       $pfb['changed_ip_aliases'] here, then de-duped at emit.
	//   PFB_CHANGED_DNSBL_GROUPS = the space-separated list of DNSBL groups UPDATED this
	//       pass (ADR-12) = the DNSBL_<group> names appended in the per-group
	//       feed loop under $pfb['aliasupdate'] (genuine feed (re)parse only -- file-reuse
	//       and the always-rebuilt DNSBL_IDN/DNSBL_TLD_Allow/DNSBL_Regex specials are
	//       excluded), de-duped at emit. DNSBL groups are NOT firewall aliases, so they
	//       ride their own var. Both lists are empty on a no-op pass. Semantic =
	//       "updated this pass", Reputation-mode-INDEPENDENT; a member-level diff stays a
	//       future increment.
	// PFB_STATUS has no clean pass-wide ok/partial/error signal today, so it is reported
	// as 'ok' (a stable reserved placeholder; the ADR forbids inventing an accumulator
	// for it -- do not branch a recipe on its value). No enabled 'post' hook =>
	// pfb_run_hooks() returns immediately (byte-identical pass).
	if (!empty($pfb_alias_lists) && is_array($pfb_alias_lists)) {
		$pfb['changed_ip_aliases'] = array_merge($pfb['changed_ip_aliases'], $pfb_alias_lists);
	}
	pfb_run_hooks('post', array(
		'TRIGGER'		=> $pfb_hook_val,
		'IP_CHANGED'		=> (!empty($pfb['filter_configure']) || !empty($pfb_ip_unlock_forced)) ? '1' : '0',
		'DNSBL_CHANGED'		=> pfb_dnsbl_reload_needed(!empty($pfb['dnsbl_publish_failed']),
						!empty($pfb_data_changed), !empty($pfbupdate), !empty($pfbpython),
						!empty($safesearch_update), !empty($pfb_dnsbl_unlock_forced)) ? '1' : '0',
		'STATUS'		=> 'ok',
		'CHANGED_IP_ALIASES'	=> implode(' ', array_unique($pfb['changed_ip_aliases'])),
		'CHANGED_DNSBL_GROUPS'	=> implode(' ', array_unique($pfb['changed_dnsbl_groups'])),
	));

	// Terminal marker -- emitted AFTER the post-update hooks so it is genuinely the
	// last line of the update log (the hooks' progressive output, e.g. a HAProxy reload
	// running up to its timeout, must precede it). The Update-page live tail now stops on
	// the dispatched process exiting (its pidfile), not on this marker, but keeping the
	// marker last preserves a clean end-of-run boundary in the log.
	// A real Update pass (NOT a settings-save sync, $pfb['save']) has rebuilt from the current
	// config, so any deferred-settings changes are now applied: clear the GUI "pending changes"
	// banner unless this pass's filter reload expired or failed to launch (firewall state
	// unknown; the pending mark must survive so the next tick re-applies).

	if (!$pfb['save']) {
		$pending_cleared = !pfb_due_ledger_is_pending('cron', $pfb['dbdir'])
			|| pfb_due_ledger_update_entry(
				'cron',
				static function (?array $entry): array {
					$entry ??= ['last_run' => 0, 'next_due' => 0, 'jitter' => 0];
					unset($entry['pending_apply']);
					return $entry;
				},
				$pfb['dbdir']
			);
		if ($pending_cleared && !$pfb_filter_reload_unknown) {
			pfb_clear_pending_changes();
		}

		if ($pfb['enable'] === PfbToggle::On) {
			pfb_schedule_cache_refresh_locked();
		}
	}

	if ($pfb['enable'] === PfbToggle::On && !$pfb['save'] || $pfb['summary']) {
		pfb_logger("\n UPDATE PROCESS ENDED\n", 1);
	}

	// issue #1175: release only if this call transitioned the lock (see head of function).
	if ($pfb_feed_pass_owner) {
		pfb_feed_pass_release();
	}
	if ($pfb_dispatch_owner) {
		pfb_schedule_dispatch_release();
	}
	return TRUE;
}

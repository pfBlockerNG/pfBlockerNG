<?php
/*
 * pfblockerng.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2015-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2015-2024 BBcan177@gmail.com
 * All rights reserved.
 *
 * Originally based upon pfBlocker by
 * Copyright (c) 2011 Marcello Coutinho
 * All rights reserved.
 *
 * Hour Schedule Convertor code by Snort Package
 * Copyright (c) 2016 Bill Meeks
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

if ($_SERVER['REMOTE_ADDR'] == '127.0.0.1' && $_REQUEST && $_REQUEST['pfb']) {
	if (strpos($_REQUEST['pfb'], ' ') !== FALSE) {
		$query = basename(htmlspecialchars(trim(strstr($_REQUEST['pfb'], ' ', TRUE))));
	} else {
		$query = basename(htmlspecialchars($_REQUEST['pfb']));
	}

	if (!preg_match("/\W/", $query)) {
		foreach (array("{$query}.txt", "{$query}_v4.txt", "{$query}_v6.txt") as $file) {
			$file = "/var/db/aliastables/{$file}";
			if (file_exists($file)) {
				if (@filesize($file) > 0) {
					$return = @file_get_contents($file);
					print $return;
				}
				break;
			}
		}
	}
	return;
}


require_once('util.inc');
require_once('functions.inc');
require_once('pkg-utils.inc');
require_once('globals.inc');
require_once('services.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');	// 'include functions' not yet merged into pfSense

global $g, $pfb;
pfb_global();

// Clear IP/DNSBL counters via CRON
if (isset($argv[1])) {
	if ($argv[1] == 'clearip') {
		pfBlockerNG_clearip();
		pfBlockerNG_clearsqlite('clearip');
		exit;
	}
	elseif ($argv[1] == 'cleardnsbl') {
		pfBlockerNG_clearsqlite('cleardnsbl');
		exit;
	}
	// ADR-12: manual hook-runner test path (unwired from the update pass). Usage:
	// pfblockerng.php runhooks <pre|post> [trigger]. Runs the configured pre/post
	// hooks with a synthetic context WITHOUT sync_package_pfblockerng (nothing is
	// updated) -- the real CHANGED_* context is built only in pfblockerng.inc's
	// closing tail. Both lists are '' here because no pass ran, not a reserved
	// placeholder; PFB_STATUS stays the reserved 'ok'.
	elseif ($argv[1] == 'runhooks') {
		$when = ($argv[2] ?? '') === 'post' ? 'post' : 'pre';
		$ctx  = array('TRIGGER' => ($argv[3] ?? 'manual-test'));
		if ($when == 'post') {
			$ctx['IP_CHANGED']           = '0';
			$ctx['DNSBL_CHANGED']        = '0';
			$ctx['STATUS']               = 'ok';
			$ctx['CHANGED_IP_ALIASES']   = '';	// no update performed by this test path
			$ctx['CHANGED_DNSBL_GROUPS'] = '';	// no update performed by this test path
		}
		pfb_run_hooks($when, $ctx);
		exit;
	}
	// issue #149: SafeSearch CNAME fallback freshness. Legacy direct verb:
	// re-resolves the SafeSearch CNAME targets (duckduckgo/pixabay) and
	// refreshes their baked #2-fallback IPs in the SafeSearch CSV, triggering a
	// python reload only on change. Does NOT run sync_package_pfblockerng.
	elseif ($argv[1] == 'ss_refresh') {
		pfblockerng_ss_refresh();
		exit;
	}
	// ADR-43: due-ledger trigger-tick. Reads the ledger, dispatches due Extras and feeds,
	// then runs due SafeSearch refresh work (cheap).
	elseif ($argv[1] == 'tick') {
		pfblockerng_tick();
		exit;
	}
	// issue #1204: cron-only verb the installed crontab entry calls. A present
	// .pfb_cron_disable sentinel suppresses just this scheduled dispatch -- the
	// direct 'tick' verb above stays fully live regardless.
	elseif ($argv[1] == 'cron-tick') {
		if (pfb_cron_disabled()) {
			print '[ Disabled by ' . pfb_cron_disable_path() . " ]\n";
			exit;
		}
		pfblockerng_tick();
		exit;
	}
	// PFBL-03: root-only DNSBL-control entrypoint. Writes a validated command to the
	// local privileged command channel consumed by pfb_unbound.py.
	// Usage: pfblockerng.php dnsbl-control <disable [sec] | enable |
	//        addbypass <ip> [sec] | removebypass <ip>>
	// The writer (pfb_unbound_py_write_control) re-validates the command + argument and
	// the reader re-validates again, so an invalid command prints an error and exits 1.
	elseif ($argv[1] == 'dnsbl-control') {
		$cmd = $argv[2] ?? '';
		$ip  = '';
		$dur = '';
		if ($cmd == 'addbypass' || $cmd == 'removebypass') {
			$ip  = $argv[3] ?? '';
			$dur = $argv[4] ?? '';	// only addbypass honours it; writer ignores it for removebypass
		} else {
			$dur = $argv[3] ?? '';	// disable [sec]; enable ignores it
		}
		$seq = pfb_unbound_py_write_control($cmd, $ip, $dur);
		if ($seq === FALSE) {
			echo "DNSBL control command failed (invalid command/argument or write error)\n";
			exit(1);
		}
		echo "DNSBL control command [ {$cmd} ] queued (seq {$seq})\n";
		exit;
	}
}

// Extras - MaxMind/TOP1M Download URLs/filenames/settings
$pfb['extras']			= array();

// MaxMind GeoIP Databases
$pfb['extras'][0]		= array();
$pfb['extras'][0]['url']	= 'https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz';
$pfb['extras'][0]['file_dwn']	= 'GeoLite2-Country.tar.gz';
$pfb['extras'][0]['file']	= 'GeoLite2-Country.mmdb';
$pfb['extras'][0]['folder']	= "{$pfb['geoipshare']}";
$pfb['extras'][0]['type']	= 'geoip';

$pfb['extras'][1]		= array();
$pfb['extras'][1]['url']	= 'https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip';
$pfb['extras'][1]['file_dwn']	= 'GeoLite2-Country-CSV.zip';
$pfb['extras'][1]['file']	= '';
$pfb['extras'][1]['folder']	= "{$pfb['geoipshare']}";
$pfb['extras'][1]['type']	= 'geoip';

// TOP1M database (ADR-59: URL sourced from the provider descriptor table)
$pfb_top1m_provider		= pfb_top1m_providers()[$pfb['dnsbl_top1m_type']->value];
$pfb['extras'][2]			= array();
$pfb['extras'][2]['url']	= $pfb_top1m_provider['url'];

$pfb['extras'][2]['file_dwn']	= 'top-1m.csv.zip';
$pfb['extras'][2]['file']	= 'top-1m.csv';
$pfb['extras'][2]['folder']	= "{$pfb['dbdir']}";
$pfb['extras'][2]['type']	= 'top1m';
$pfb['extras'][2]['provider']	= $pfb['dnsbl_top1m_type']->value;

// ADR-59: header auth (Cloudflare Radar's Bearer token) via the $feed['headers']
// plumbing. A keyless provider's 'auth' is 'none', so pfb_top1m_auth_headers() returns
// array() and this is a no-op for tranco/cisco/openpagerank/majestic — their behaviour is unchanged.
// An empty/absent top1m_token also yields array() -- no Authorization header is sent,
// so a missing token fails the download safely (pfblockerng_top1m()'s #886 preserve+warn
// path keeps the previous TOP1M whitelist) rather than sending a malformed header.
$pfb['extras'][2]['headers']	= pfb_top1m_auth_headers($pfb_top1m_provider, (string) PfbConfig::read('dnsbl/top1m_token'));

// IPinfo ASN databases
$pfb['extras'][3]		= array();
$pfb['extras'][3]['url']	= 'https://ipinfo.io/data/free/asn.mmdb?token=';
$pfb['extras'][3]['file_dwn']	= 'asn.mmdb';
$pfb['extras'][3]['file']	= 'asn.mmdb';
$pfb['extras'][3]['folder']	= "{$pfb['geoipshare']}"; 
$pfb['extras'][3]['type']	= 'asn';

$pfb['extras'][4]               = array();
$pfb['extras'][4]['url']        = 'https://ipinfo.io/data/free/asn.csv.gz?token=';
$pfb['extras'][4]['file_dwn']   = 'asn.csv.gz';
$pfb['extras'][4]['file']       = 'asn.csv';
$pfb['extras'][4]['folder']     = "{$pfb['geoipshare']}"; 
$pfb['extras'][4]['type']       = 'asn';

// Next Available Extras Key value for Blacklist Category Downloads
$next_key = $next_key_start = 5;

if (isset($argv[1]) && ($argv[1] == 'bl' || $argv[1] == 'bls')) {
	$bl_arg = (($argv[2] ?? '') === 'scheduled') ? ($argv[3] ?? '') : ($argv[2] ?? '');

	if (empty(pfb_filter($bl_arg, PFB_FILTER_CSV, 'php'))) {
		$bl_arg = '';
	}

	if (!empty($bl_arg) && $pfb['blconfig'] &&
	    !empty($pfb['blconfig']['blacklist_selected']) &&
	    isset($pfb['blconfig']['item'])) {

		$selected = array_flip(explode(',', $bl_arg)) ?: array();
		foreach ($pfb['blconfig']['item'] as $item) {

			// Temporarily Discontinue Shallalist
			if ($item['title'] == 'Shallalist') {
				pfb_logger("\nTerminating Shallalist as its now discontinued!\n", 2);
				continue;
			}

			if (isset($selected[$item['xml']])) {
				$pfb['extras'][$next_key]		= array();
				$pfb['extras'][$next_key]['url']	= $item['feed'];
				$pfb['extras'][$next_key]['name']	= $item['title'];
				$pfb['extras'][$next_key]['file_dwn']	= pathinfo($item['feed'], PATHINFO_BASENAME);
				$pfb['extras'][$next_key]['file']	= pathinfo($item['feed'], PATHINFO_BASENAME);
				$pfb['extras'][$next_key]['folder']	= "{$pfb['dbdir']}";
				$pfb['extras'][$next_key]['type']	= 'blacklist';

				if (isset($item['username']) && isset($item['password'])) {
					$pfb['extras'][$next_key]['username'] = $item['username'];
					$pfb['extras'][$next_key]['password'] = $item['password'];
				}

				// Patch UT1 filename. Keyed on the provider id, never its feed URL: the
				// download name decides the category filenames, so a URL change would
				// otherwise rename the whole category set (issue #2636).
				if ($item['xml'] == 'ut1') {
					$pfb['extras'][$next_key]['file_dwn'] = $pfb['extras'][$next_key]['file'] = 'ut1.tar.gz';
				}
				$next_key++;
			}
		}
	}
}

// Call include file and collect updated Global settings
if (isset($argv[1]) && in_array($argv[1], array('update', 'updateip', 'updatednsbl', 'dc', 'dcc', 'bu', 'uc', 'gc', 'al', 'asn', 'asn_shell', 'bl', 'bls', 'cron', 'ugc', 'pfb_trigger', 'tick', 'forcecheck'))) {
	pfb_global();

	$pfb['extras_update'] = FALSE;  // Flag when Extras (MaxMind/TOP1M) are updateded via cron job

	// Script Arguments
	switch($argv[1]) {
		case 'cron':		// Sync 'cron'
			logger(LOG_NOTICE, localize_text('Starting cron process.'), LOG_PREFIX_PKG_PFBLOCKERNG);
			exit(pfblockerng_sync_cron() ? 0 : 1);
		case 'updateip':	// Sync 'Force Reload IP only' [DEPRECATED — use pfb_trigger scope=ip force=true trigger=force]
		case 'updatednsbl':	// Sync 'Force Reload DNSBL only' [DEPRECATED — use pfb_trigger scope=dnsbl force=true trigger=force]
			exit(sync_package_pfblockerng($argv[1]) ? 0 : 1);	// deprecation warning logged inside sync_package_pfblockerng
		case 'update':		// Sync 'Force update' [DEPRECATED — use pfb_trigger scope=both force=false trigger=manual]
			exit(sync_package_pfblockerng('update') ? 0 : 1);	// deprecation warning logged inside sync_package_pfblockerng
		case 'pfb_trigger':	// ADR-43: explicit {scope, force, trigger} API
			// Usage: pfblockerng.php pfb_trigger scope=<both|ip|dnsbl> force=<true|false> trigger=<cron|manual|force>
			$pfb_tscope   = 'both';
			$pfb_tforce   = FALSE;
			$pfb_ttrigger = 'manual';
			foreach (array_slice($argv, 2) as $pfb_targ) {
				if (str_starts_with($pfb_targ, 'scope=')) {
					$pfb_tscope = substr($pfb_targ, 6);
				} elseif ($pfb_targ === 'force=true') {
					$pfb_tforce = TRUE;
				} elseif (str_starts_with($pfb_targ, 'trigger=')) {
					$pfb_ttrigger = substr($pfb_targ, 8);
				}
			}
			// Allow-list: reject unknown scope/trigger values (argv is user-controlled).
			// Unknown scope → 'both' (full pass); unknown trigger → 'manual' (safe default).
			if (!in_array($pfb_tscope, array('ip', 'dnsbl', 'both'), TRUE)) {
				pfb_logger("pfb_trigger: unknown scope={$pfb_tscope} ignored — defaulting to 'both'\n", 1);
				$pfb_tscope = 'both';
			}
			if (!in_array($pfb_ttrigger, array('cron', 'manual', 'force'), TRUE)) {
				pfb_logger("pfb_trigger: unknown trigger={$pfb_ttrigger} ignored — defaulting to 'manual'\n", 1);
				$pfb_ttrigger = 'manual';
			}
			exit(sync_package_pfblockerng(array('scope' => $pfb_tscope, 'force' => $pfb_tforce, 'trigger' => $pfb_ttrigger)) ? 0 : 1);
		case 'forcecheck':	// On-demand detector: bypass hour-gate, run pfb_update_check for all in-scope feeds.
			// Usage: pfblockerng.php forcecheck scope=<both|ip|dnsbl>
			// Validators (and optionally hashes) must be cleared by the caller before dispatching
			// this verb so the detector re-fetches and re-evaluates feed content.
			$pfb_fcscope = 'both';
			$pfb_fchashes = FALSE;
			foreach (array_slice($argv, 2) as $pfb_fcarg) {
				if (str_starts_with($pfb_fcarg, 'scope=')) {
					$pfb_fcscope = substr($pfb_fcarg, 6);
				} elseif ($pfb_fcarg === 'hashes=true') {
					$pfb_fchashes = TRUE;
				}
			}
			if (!in_array($pfb_fcscope, array('ip', 'dnsbl', 'both'), TRUE)) {
				pfb_logger("forcecheck: unknown scope={$pfb_fcscope} ignored — defaulting to 'both'\n", 1);
				$pfb_fcscope = 'both';
			}
			pfb_logger("\n [ Force check - scope={$pfb_fcscope} ]\n", 1);
			exit(pfblockerng_sync_cron(TRUE, $pfb_fcscope, FALSE, $pfb_fchashes) ? 0 : 1);
		case 'dc':		// Update Extras - MaxMind/TOP1M/ASN database files
		case 'dcc':
			$scheduled = ($argv[2] ?? '') === 'scheduled';
			if (!$scheduled && !pfb_extras_process_begin()) {
				exit(1);
			}

			// 'dcc' called via Cron job
			if ($argv[1] == 'dcc') {

				$logtype = 3;
				$pfb['extras_update'] = TRUE;

				// Remove MaxMind updates if Key or Account not defined
				if (empty($pfb['maxmind_key']) || empty($pfb['maxmind_account'])) {
					unset($pfb['extras'][0], $pfb['extras'][1]);
				}

				// Skip TOP1M update, if disabled
				if (pfb_cfg_toggle_read($pfb['dnsbl_top1m']) !== PfbToggle::On) {
					unset($pfb['extras'][2]); // Remove TOP1M
				}

				// Skip ASN update, if disabled or Token not defined
				if (empty($pfb['asn_token'])) {
					unset($pfb['extras'][3], $pfb['extras'][4]);
				}
			}
			else {
				$logtype = 4;
				unset($pfb['extras'][2], $pfb['extras'][3], $pfb['extras'][4]); // Remove TOP1M and ASN
			}

			// If 'IP Tab' skip MaxMind download setting if checked, only download binary updates for Reputation/Alerts page.
			if (!empty($pfb['cc']) && isset($pfb['extras'][1])) {
				unset($pfb['extras'][1]); // Remove MaxMind GeoIP CSV
			}

			// Download Database updates
			$extras_ok = pfblockerng_download_extras(600, $logtype);
			$top1m_changed = pfb_top1m_dispatch_if_changed($extras_ok, !$scheduled);
			if (empty($pfb['maxmind_feed_error'])) {
				// Proceed with conversion of MaxMind files on download success
				if (empty($pfb['cc']) || !empty($pfb['maxmind_key']) || !empty($pfb['maxmind_account'])) {
						$extras_ok = pfblockerng_uc_countries('/usr/local/www/pfblockerng') && $extras_ok;
				}
			}
			$dcc_changed = $top1m_changed || file_exists("{$pfb['dbdir']}/geoip.update");
			exit(!$extras_ok ? ($scheduled && $dcc_changed ? 3 : 1) : ($scheduled && $dcc_changed ? 2 : 0));
			break;
		case 'bu':		// Update MaxMind binary database files only.
			$scheduled = ($argv[2] ?? '') === 'scheduled';
			if (!$scheduled && !pfb_extras_process_begin()) {
				exit(1);
			}
			// Remove MaxMind updates if Key or Account not defined
			if (empty($pfb['maxmind_key']) || empty($pfb['maxmind_account'])) {
				pfb_logger("\nTerminating MaxMind download due to invalid Account or Key", 2);
				return;
			}

			unset($pfb['extras'][1], $pfb['extras'][2], $pfb['extras'][3], $pfb['extras'][4]); // Remove MaxMind GeoIP CSV, TOP1M and ASN 
			pfblockerng_download_extras(600, 3);
			break;
		case 'al':		// Update TOP1M database only.
			$scheduled = ($argv[2] ?? '') === 'scheduled';
			if (!$scheduled && !pfb_extras_process_begin()) {
				exit(1);
			}
			unset($pfb['extras'][0], $pfb['extras'][1], $pfb['extras'][3], $pfb['extras'][4]); // Remove MaxMind GeoIP mmdb, CSV and ASN
			pfblockerng_download_extras(600, 3);
			break;
		case 'asn':		// Update ASN database only
		case 'asn_shell':
			$scheduled = ($argv[2] ?? '') === 'scheduled';
			if (!$scheduled && !pfb_extras_process_begin()) {
				exit(1);
			}
			// Skip ASN update, if disabled or Token not defined
			if (empty($pfb['asn_token'])) {
				$asn_log = "\n  ASN Token not defined. Terminating Download. ";
				if ($argv[1] == 'asn') {
					pfb_logger($asn_log, 2);
				} else {
					pfb_logger($asn_log, 1);
				}
				return;
			}
			
			unset($pfb['extras'][0], $pfb['extras'][1], $pfb['extras'][2]);
			pfblockerng_download_extras(600, 3);
			break;
		case 'bl':		// Update DNSBL Category database(s) only.
		case 'bls':
			$scheduled = ($argv[2] ?? '') === 'scheduled';
			if (!$scheduled && !pfb_extras_process_begin()) {
				exit(1);
			}
			// Exit if no Blacklist Extra found
			if (empty($pfb['extras'][$next_key_start])) {
				break;
			}
			unset($pfb['extras'][0], $pfb['extras'][1], $pfb['extras'][2], $pfb['extras'][3], $pfb['extras'][4]); // Remove MaxMind GeoIP mmdb, CSV, TOP1M and ASN

			// 'bls' called via 'Force Update|Reload'
			if ($argv[1] == 'bls') {
				$extras_ok = pfblockerng_download_extras(600, 'blacklist');
				exit($extras_ok ? 0 : 1);
			}
			else {
				$extras_ok = pfblockerng_download_extras(600, 3);
				exit($extras_ok ? 0 : 1);
			}
			break;
		case 'uc':		// Update MaxMind ISO files from local database files.
			if (!pfb_extras_process_begin()) {
				exit(1);
			}
			exit(pfblockerng_uc_countries() ? 0 : 1);
			break;
		case 'gc':		// Update Continent XML files.
			if (!pfb_extras_process_begin()) {
				exit(1);
			}
			exit(pfblockerng_get_countries() ? 0 : 1);
			break;
		case 'ugc':
			if (!pfb_extras_process_begin()) {
				exit(1);
			}
			if (!pfblockerng_uc_countries('/usr/local/www/pfblockerng')) {
				exit(1);
			}

			if (!empty($argv[2]) && !empty($argv[3])) {
				$argv2 = htmlspecialchars($argv[2]);
				$argv3 = htmlspecialchars($argv[3]);

				if (in_array($argv2, array('en', 'fr', 'de', 'pt-BR', 'ja', 'zh-CN', 'es')) &&
				    in_array($argv3, array('en', 'fr', 'de', 'pt-BR', 'ja', 'zh-CN', 'es'))) {

					file_notice('pfBlockerNG', "The MaxMind GeoIP Locale has been changed from [ {$argv2} ]"
							. " to [ {$argv3} ]", gettext('MaxMind Locale Changed'), '', 0);
				}
			}
			break;
		default:
			return;
	}
}


function pfb_top1m_detector_decision(
	$probe_ok,
	$http_status,
	$body_hash,
	$persisted_hash,
	$base,
	$identity_matches,
	$require_validator
) {
	if ($base !== NULL) {
		$raw_path = "{$base}.orig";
		if (!$identity_matches || !is_file($raw_path) || !is_readable($raw_path)) {
			return $probe_ok ? 'changed' : 'failed';
		}
		$sidecar = pfb_hash_read($base);
		if (($sidecar['algo'] ?? '') !== 'xxh128') {
			return $probe_ok ? 'changed' : 'failed';
		}
		$baseline_hash = pfb_content_hash($raw_path, TRUE);
		if ($baseline_hash === FALSE || $baseline_hash !== $sidecar['digest']) {
			return $probe_ok ? 'changed' : 'failed';
		}
		if ($require_validator && $http_status === '304') {
			$validators = pfb_validator_read("{$base}.orig");
			$has_validator = (is_string($validators['etag']) && $validators['etag'] !== '')
				|| (is_int($validators['lastmod']) && $validators['lastmod'] > 0);
			if (!$has_validator) {
				return $probe_ok ? 'changed' : 'failed';
			}
		}
		$persisted_hash = $sidecar['digest'];
	}
	return pfb_top1m_probe_decision($probe_ok, $http_status, $body_hash, $persisted_hash);
}

function pfb_top1m_dispatch_if_changed($extras_ok, bool $dispatch = TRUE) {
	global $argv, $pfb;
	if (($argv[1] ?? '') !== 'dcc' || empty($pfb['top1m_changed']) || !empty($pfb['top1m_dispatch_done'])) {
		return FALSE;
	}
	$pfb['top1m_dispatch_done'] = TRUE;
	if ($dispatch) {
		exec("{$pfb['php']} /usr/local/www/pfblockerng/pfblockerng.php pfb_trigger scope=dnsbl force=false trigger=cron >> {$pfb['runlog']} 2>&1 &");
	}
	return TRUE;
}


// Download Extras - MaxMind/TOP1M/Category feeds via cURL
function pfblockerng_download_extras($timeout=600, $type='') {
	global $pfb;
	pfb_global();

	$pfb_return	= '';
	$pfb_error	= FALSE;
	$pfb['top1m_changed'] = FALSE;
	$pfb['maxmind_feed_error'] = FALSE;

	$logtype = 3;
	if ($type == 4) {
		$logtype = 4;
	}

	pfb_logger("\nDownload Process Starting\n", $logtype);
	foreach ($pfb['extras'] as $feed) {

		if (empty($feed)) {
			continue;
		}

		// Add Credentials. Issue #1906: normalized for EVERY feed type, not per branch --
		// the ASN feeds carry no username/password keys at all, and the per-type branch this
		// replaced left them undefined (NULL), fataling on PfbDownloadRequest's string
		// parameters and aborting the whole extras run.
		list($feed['username'], $feed['password']) =
		    pfb_extras_credentials($feed, $pfb['maxmind_account'], $pfb['maxmind_key']);

		// Add Token
		if ($feed['type'] == 'asn') {
			// rawurlencode the token so URL correctness does not depend on the input
			// validator's strictness. Today's tokens are word chars only (rawurlencode
			// is a no-op on them), but encoding here keeps the query well-formed if the
			// token format ever changes (e.g. base64/JWT with '=' '.' '/').
			$feed['url'] = "{$feed['url']}" . rawurlencode($pfb['asn_token']);
		}

		$file_dwn = "{$feed['folder']}/{$feed['file_dwn']}";
		$is_top1m_detector = ($feed['type'] == 'top1m' && (int) $type === 3 && ($GLOBALS['argv'][1] ?? '') === 'dcc');
		$top1m_base = $file_dwn;
		$top1m_identity = '';
		$top1m_probe_meta = array();
		if ($feed['type'] == 'top1m') {
			$top1m_identity = pfb_top1m_source_identity(
				$feed['provider'] ?? '',
				$feed['url'],
				$feed['headers'] ?? array()
			);
		}

		if ($is_top1m_detector) {
			$stored_identity = @file_get_contents("{$top1m_base}.source");
			$identity_matches = ($stored_identity !== FALSE && $stored_identity === $top1m_identity);
			if (!$identity_matches) {
				pfb_top1m_invalidate_baseline($top1m_base);
			}
			$probe_result = pfb_download(new PfbDownloadRequest(
				listUrl: $feed['url'],
				downloadPath: "{$file_dwn}.md5",
				flex: FALSE,
				header: $file_dwn,
				format: '',
				logType: $logtype,
				timeout: $timeout,
				type: 'change_detect',
				username: $feed['username'],
				password: $feed['password'],
				sourceInterface: FALSE,
				extraHeaders: $feed['headers'] ?? array(),
			));
			$probe_ok = $probe_result->success;
			$top1m_probe_meta = $probe_result->responseMeta ?? array();
			$probe_status = $top1m_probe_meta['status'] ?? '';
			$probe_hash = ($probe_status === '200')
				? pfb_content_hash("{$file_dwn}.md5.raw", TRUE) : FALSE;
			$probe_decision = pfb_top1m_detector_decision(
				$probe_ok,
				$probe_status,
				$probe_hash,
				'',
				$top1m_base,
				$identity_matches,
				$probe_status === '304'
			);
			if ($probe_decision === 'failed') {
				unlink_if_exists("{$file_dwn}.md5.raw");
				pfb_top1m_download_ledger_update(FALSE, $pfb['dbdir'], 'TOP1M probe failed');
				$pfb_error = TRUE;
				continue;
			}
			if ($probe_decision === 'unchanged') {
				unlink_if_exists("{$file_dwn}.md5.raw");
				pfb_validator_write("{$top1m_base}.orig", $top1m_probe_meta['etag'] ?? FALSE, $top1m_probe_meta['lastmod'] ?? 0);
				@file_put_contents("{$top1m_base}.source", $top1m_identity, LOCK_EX);
				pfb_top1m_download_ledger_update(TRUE, $pfb['dbdir']);
				continue;
			}
		}

		// ADR-59: thread the per-feed 'headers' field through as caller-supplied HTTP
		// headers. The TOP1M provider sets it above via pfb_top1m_auth_headers()
		// (Cloudflare Radar's Bearer token; array() for every keyless provider) --
		// every other feed leaves it unset, so ?? array() keeps their downloads
		// unaffected.
		if (!(pfb_download(new PfbDownloadRequest(
			listUrl: $feed['url'],
			downloadPath: $file_dwn,
			flex: FALSE,
			header: "{$feed['folder']}/{$feed['file']}",
			format: '',
			logType: $logtype,
			versionType: '',
			timeout: $timeout,
			type: $feed['type'],
			username: $feed['username'],
			password: $feed['password'],
			sourceInterface: FALSE,
			extraHeaders: $feed['headers'] ?? array(),
		))->success)) {

			$log = "\nFailed to Download {$feed['file']}\n";
			pfb_logger("{$log}", $logtype);

			// Report aggregate Extras failure, but only GeoIP failure blocks country conversion.
			$pfb_error = TRUE;
			if ($feed['type'] == 'geoip') {
				$pfb['maxmind_feed_error'] = TRUE;
			}

			if ($type == 'blacklist') {
				$pfb_return .= "\t{$feed['name']} ... Failed\n";
			}
			if ($feed['type'] == 'top1m') {
				unlink_if_exists("{$file_dwn}.md5.raw");
				pfb_top1m_download_ledger_update(FALSE, $pfb['dbdir'], 'TOP1M download failed');
			}
		}
		else {
			if ($feed['type'] == 'top1m') {
				@file_put_contents("{$top1m_base}.source", $top1m_identity, LOCK_EX);
				if ($is_top1m_detector) {
					pfb_validator_write("{$top1m_base}.orig", $top1m_probe_meta['etag'] ?? FALSE, $top1m_probe_meta['lastmod'] ?? 0);
					$pfb['top1m_changed'] = TRUE;
					pfb_top1m_download_ledger_update(TRUE, $pfb['dbdir']);
				}
			}
			if ($type == 'blacklist') {
				$pfb_return .= "\t{$feed['name']} ... Completed\n";
			}
		}
	}
	pfb_logger("Download Process Ended\n\n", $logtype);

	if ($type == 'blacklist') {
		print "{$pfb_return}";
	}
	return !$pfb_error;
}

// Function to process the downloaded MaxMind database and format into Continent txt files.
function pfblockerng_uc_countries(?string $output_root = NULL) {
	global $g, $pfb;

	// Create folders if not exist
	$folder_array = array ("{$pfb['dbdir']}", "{$pfb['logdir']}", "{$pfb['ccdir']}");
	foreach ($folder_array as $folder) {
		safe_mkdir ("{$folder}", 0755);
	}

	$log = "Country code update Start\n";
	pfb_logger("{$log}", 4);

	$maxmind_cont = "{$pfb['geoipshare']}/GeoLite2-Country-Locations-{$pfb['maxmind_locale']}.csv";
	if (!file_exists($maxmind_cont)) {
		$log = " [ MAXMIND UPDATE FAIL, Language File Missing, using previous Country code database ]\n";
		pfb_logger("{$log}", 4); 
		return FALSE;
	}

	// Build a complete private generation before replacing the live last-known-good data.
	$live_ccdir = $pfb['ccdir'];
	$live_geoip_isos = $pfb['geoip_isos'];
	$generation = getmypid() . '.' . bin2hex(random_bytes(4));
	$stage_ccdir = "{$live_ccdir}.new.{$generation}";
	$stage_geoip_isos = "{$live_geoip_isos}.new.{$generation}";
	$stage_output_root = $output_root === NULL ? NULL : "{$output_root}.new.{$generation}";
	$discard_generation = static function () use (
		&$pfb, $live_ccdir, $live_geoip_isos, $stage_ccdir, $stage_geoip_isos, $stage_output_root
	): void {
		$pfb['ccdir'] = $live_ccdir;
		$pfb['geoip_isos'] = $live_geoip_isos;
		rmdir_recursive($stage_ccdir);
		unlink_if_exists($stage_geoip_isos);
		if ($stage_output_root !== NULL) {
			rmdir_recursive($stage_output_root);
		}
	};
	rmdir_recursive($stage_ccdir);
	unlink_if_exists($stage_geoip_isos);
	safe_mkdir($stage_ccdir, 0755);
	if ($stage_output_root !== NULL && !@mkdir($stage_output_root, 0755, TRUE)) {
		$discard_generation();
		return FALSE;
	}
	$pfb['ccdir'] = $stage_ccdir;
	$pfb['geoip_isos'] = $stage_geoip_isos;
	$generation_ok = TRUE;

	// Save Date/Time stamp to MaxMind version file
	$local_tds	 = @gmdate('Y-m-d H:i:s', pfb_file_mtime($maxmind_cont));
	$maxmind_ver	 = "MaxMind GeoLite2 Date/Time Stamp\n";
	$maxmind_ver	.= "Last-Modified: {$local_tds}\n";
	@file_put_contents("{$pfb['logdir']}/maxmind_ver", $maxmind_ver, LOCK_EX);

	// Remove any previous tmp working files
	rmdir_recursive("{$pfb['ccdir_tmp']}");
	safe_mkdir("{$pfb['ccdir_tmp']}");

	$pfb_geoip = array();
	$pfb_geoip['country'] = array();

	$top_20 = array_flip( array('CN', 'RU', 'JP', 'UA', 'GB', 'DE', 'BR', 'FR', 'IN', 'TR',
			'IT', 'KR', 'PL', 'ES', 'VN', 'AR', 'CO', 'TW', 'MX', 'CL') );

	// Read GeoLite2 database and create array by geoname_ids
	if (($handle = @fopen("{$maxmind_cont}", 'r')) !== FALSE) {
		while (($cc = @fgetcsv($handle)) !== FALSE) {

			if ($cc[0] == 'geoname_id') {
				continue;
			}

			/*	Sample MaxMind lines:
				geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name
				49518,en,AF,Africa,RW,Rwanda	*/

			if (!empty($cc[0]) && !empty($cc[1]) && !empty($cc[2]) && !empty($cc[3]) && !empty($cc[4]) && !empty($cc[5])) {
				$pfb_geoip['country'][$cc[0]] = array('id' => $cc[0], 'continent' => $cc[3], 'name' => $cc[5], 'iso' => array("{$cc[4]}"));

				// Collect English Continent name for filenames only
				if ($cc[1] != 'en') {
					$geoip_en	= escapeshellarg(str_replace("Locations-{$pfb['maxmind_locale']}", 'Locations-en', $maxmind_cont));
					$cc_2		= escapeshellarg(",en,{$cc[2]}");
					$continent_en	= exec("{$pfb['grep']} -m1 {$cc_2} {$geoip_en} | {$pfb['cut']} -d',' -f4");
				} else {
					$continent_en	= "{$cc[3]}";
				}
				$continent_en = str_replace(array(' ', '"'), array('_', ''), $continent_en);
				$pfb_geoip['country'][$cc[0]]['continent_en'] = "{$continent_en}";

				// Collect data for TOP 20 tab
				if (isset($top_20[$cc[4]])) {
					$top20 = 'A' . str_pad($top_20[$cc[4]], 5, '0', STR_PAD_LEFT);
					$pfb_geoip['country'][$top20] = array('name' => $cc[5], 'iso' => $cc[4], 'id' => $cc[0]);
				}
			}
		}

		if ($cc) {
			unset($cc);
		}
		if ($handle) {
			@fclose($handle);
		}
	}
	else {
		$generation_ok = FALSE;
	}

	// Add 'Proxy and Satellite' geoname_ids
	$pfb_geoip['country']['proxy']		= array('continent' => 'Proxy and Satellite', 'name' => 'Proxy', 'iso' => array('A1'),
							'continent_en' => 'Proxy_and_Satellite');
	$pfb_geoip['country']['satellite']	= array('continent' => 'Proxy and Satellite', 'name' => 'Satellite', 'iso' => array('A2'),
							'continent_en' => 'Proxy_and_Satellite');

	// Add 'Asia/Europe' undefined geoname_ids
	$pfb_geoip['country']['6255147']	= array('continent' => 'Asia', 'name' => 'AA ASIA UNDEFINED', 'iso' => array('6255147'),
							'continent_en' => 'Asia');
	$pfb_geoip['country']['6255148']	= array('continent' => 'Europe', 'name' => 'AA EUROPE UNDEFINED', 'iso' => array('6255148'),
							'continent_en' => 'Europe');

	// List of all known Countries via Geonames.org (Used to validate MaxMind Country listings)
	$pfb_geoip_all = array( '3041565'	=> array ( 'iso' => 'AD', 'name' => 'Andorra',			'continent' => 'Europe' ),
				'290557'	=> array ( 'iso' => 'AE', 'name' => 'United Arab Emirates',	'continent' => 'Asia' ),
				'1149361'	=> array ( 'iso' => 'AF', 'name' => 'Afghanistan',		'continent' => 'Asia' ),
				'3576396'	=> array ( 'iso' => 'AG', 'name' => 'Antigua and Barbuda',	'continent' => 'North America' ),
				'3573511'	=> array ( 'iso' => 'AI', 'name' => 'Anguilla',			'continent' => 'North America' ),
				'783754'	=> array ( 'iso' => 'AL', 'name' => 'Albania',			'continent' => 'Europe' ),
				'174982'	=> array ( 'iso' => 'AM', 'name' => 'Armenia',			'continent' => 'Asia' ),
				'3351879'	=> array ( 'iso' => 'AO', 'name' => 'Angola',			'continent' => 'Africa' ),
				'6697173'	=> array ( 'iso' => 'AQ', 'name' => 'Antarctica',		'continent' => 'Antarctica' ),
				'3865483'	=> array ( 'iso' => 'AR', 'name' => 'Argentina',		'continent' => 'South America' ),
				'5880801'	=> array ( 'iso' => 'AS', 'name' => 'American Samoa',		'continent' => 'Oceania' ),
				'2782113'	=> array ( 'iso' => 'AT', 'name' => 'Austria',			'continent' => 'Europe' ),
				'2077456'	=> array ( 'iso' => 'AU', 'name' => 'Australia',		'continent' => 'Oceania' ),
				'3577279'	=> array ( 'iso' => 'AW', 'name' => 'Aruba',			'continent' => 'North America' ),
				'661882'	=> array ( 'iso' => 'AX', 'name' => 'Aland Islands',		'continent' => 'Europe' ),
				'587116'	=> array ( 'iso' => 'AZ', 'name' => 'Azerbaijan',		'continent' => 'Asia' ),
				'3277605'	=> array ( 'iso' => 'BA', 'name' => 'Bosnia and Herzegovina',	'continent' => 'Europe' ),
				'3374084'	=> array ( 'iso' => 'BB', 'name' => 'Barbados',			'continent' => 'North America' ),
				'1210997'	=> array ( 'iso' => 'BD', 'name' => 'Bangladesh',		'continent' => 'Asia' ),
				'2802361'	=> array ( 'iso' => 'BE', 'name' => 'Belgium',			'continent' => 'Europe' ),
				'2361809'	=> array ( 'iso' => 'BF', 'name' => 'Burkina Faso',		'continent' => 'Africa' ),
				'732800'	=> array ( 'iso' => 'BG', 'name' => 'Bulgaria',			'continent' => 'Europe' ),
				'290291'	=> array ( 'iso' => 'BH', 'name' => 'Bahrain',			'continent' => 'Asia' ),
				'433561'	=> array ( 'iso' => 'BI', 'name' => 'Burundi',			'continent' => 'Africa' ),
				'2395170'	=> array ( 'iso' => 'BJ', 'name' => 'Benin',			'continent' => 'Africa' ),
				'3578476'	=> array ( 'iso' => 'BL', 'name' => 'Saint Barthelemy',		'continent' => 'North America' ),
				'3573345'	=> array ( 'iso' => 'BM', 'name' => 'Bermuda',			'continent' => 'North America' ),
				'1820814'	=> array ( 'iso' => 'BN', 'name' => 'Brunei',			'continent' => 'Asia' ),
				'3923057'	=> array ( 'iso' => 'BO', 'name' => 'Bolivia',			'continent' => 'South America' ),
				'7626844'	=> array ( 'iso' => 'BQ', 'name' => 'Bonaire, Saint Eustatius and Saba ', 'continent' => 'North America' ),
				'3469034'	=> array ( 'iso' => 'BR', 'name' => 'Brazil',			'continent' => 'South America' ),
				'3572887'	=> array ( 'iso' => 'BS', 'name' => 'Bahamas',			'continent' => 'North America' ),
				'1252634'	=> array ( 'iso' => 'BT', 'name' => 'Bhutan',			'continent' => 'Asia' ),
				'3371123'	=> array ( 'iso' => 'BV', 'name' => 'Bouvet Island',		'continent' => 'Antarctica' ),
				'933860'	=> array ( 'iso' => 'BW', 'name' => 'Botswana',			'continent' => 'Africa' ),
				'630336'	=> array ( 'iso' => 'BY', 'name' => 'Belarus',			'continent' => 'Europe' ),
				'3582678'	=> array ( 'iso' => 'BZ', 'name' => 'Belize',			'continent' => 'North America' ),
				'6251999'	=> array ( 'iso' => 'CA', 'name' => 'Canada',			'continent' => 'North America' ),
				'1547376'	=> array ( 'iso' => 'CC', 'name' => 'Cocos Islands',		'continent' => 'Asia' ),
				'203312'	=> array ( 'iso' => 'CD', 'name' => 'Democratic Republic of the Congo', 'continent' => 'Africa' ),
				'239880'	=> array ( 'iso' => 'CF', 'name' => 'Central African Republic',	'continent' => 'Africa' ),
				'2260494'	=> array ( 'iso' => 'CG', 'name' => 'Republic of the Congo',	'continent' => 'Africa' ),
				'2658434'	=> array ( 'iso' => 'CH', 'name' => 'Switzerland',		'continent' => 'Europe' ),
				'2287781'	=> array ( 'iso' => 'CI', 'name' => 'Ivory Coast',		'continent' => 'Africa' ),
				'1899402'	=> array ( 'iso' => 'CK', 'name' => 'Cook Islands',		'continent' => 'Oceania' ),
				'3895114'	=> array ( 'iso' => 'CL', 'name' => 'Chile',			'continent' => 'South America' ),
				'2233387'	=> array ( 'iso' => 'CM', 'name' => 'Cameroon',			'continent' => 'Africa' ),
				'1814991'	=> array ( 'iso' => 'CN', 'name' => 'China',			'continent' => 'Asia' ),
				'3686110'	=> array ( 'iso' => 'CO', 'name' => 'Colombia',			'continent' => 'South America' ),
				'3624060'	=> array ( 'iso' => 'CR', 'name' => 'Costa Rica',		'continent' => 'North America' ),
				'3562981'	=> array ( 'iso' => 'CU', 'name' => 'Cuba',			'continent' => 'North America' ),
				'3374766'	=> array ( 'iso' => 'CV', 'name' => 'Cape Verde',		'continent' => 'Africa' ),
				'7626836'	=> array ( 'iso' => 'CW', 'name' => 'Curacao',			'continent' => 'North America' ),
				'2078138'	=> array ( 'iso' => 'CX', 'name' => 'Christmas Island',		'continent' => 'Asia' ),
				'146669'	=> array ( 'iso' => 'CY', 'name' => 'Cyprus',			'continent' => 'Europe' ),
				'3077311'	=> array ( 'iso' => 'CZ', 'name' => 'Czechia',			'continent' => 'Europe' ),
				'2921044'	=> array ( 'iso' => 'DE', 'name' => 'Germany',			'continent' => 'Europe' ),
				'223816'	=> array ( 'iso' => 'DJ', 'name' => 'Djibouti',			'continent' => 'Africa' ),
				'2623032'	=> array ( 'iso' => 'DK', 'name' => 'Denmark',			'continent' => 'Europe' ),
				'3575830'	=> array ( 'iso' => 'DM', 'name' => 'Dominica',			'continent' => 'North America' ),
				'3508796'	=> array ( 'iso' => 'DO', 'name' => 'Dominican Republic',	'continent' => 'North America' ),
				'2589581'	=> array ( 'iso' => 'DZ', 'name' => 'Algeria',			'continent' => 'Africa' ),
				'3658394'	=> array ( 'iso' => 'EC', 'name' => 'Ecuador',			'continent' => 'South America' ),
				'453733'	=> array ( 'iso' => 'EE', 'name' => 'Estonia',			'continent' => 'Europe' ),
				'357994'	=> array ( 'iso' => 'EG', 'name' => 'Egypt',			'continent' => 'Africa' ),
				'2461445'	=> array ( 'iso' => 'EH', 'name' => 'Western Sahara',		'continent' => 'Africa' ),
				'338010'	=> array ( 'iso' => 'ER', 'name' => 'Eritrea',			'continent' => 'Africa' ),
				'2510769'	=> array ( 'iso' => 'ES', 'name' => 'Spain',			'continent' => 'Europe' ),
				'337996'	=> array ( 'iso' => 'ET', 'name' => 'Ethiopia',			'continent' => 'Africa' ),
				'660013'	=> array ( 'iso' => 'FI', 'name' => 'Finland',			'continent' => 'Europe' ),
				'2205218'	=> array ( 'iso' => 'FJ', 'name' => 'Fiji',			'continent' => 'Oceania' ),
				'3474414'	=> array ( 'iso' => 'FK', 'name' => 'Falkland Islands',		'continent' => 'South America' ),
				'2081918'	=> array ( 'iso' => 'FM', 'name' => 'Micronesia',		'continent' => 'Oceania' ),
				'2622320'	=> array ( 'iso' => 'FO', 'name' => 'Faroe Islands',		'continent' => 'Europe' ),
				'3017382'	=> array ( 'iso' => 'FR', 'name' => 'France',			'continent' => 'Europe' ),
				'2400553'	=> array ( 'iso' => 'GA', 'name' => 'Gabon',			'continent' => 'Africa' ),
				'2635167'	=> array ( 'iso' => 'GB', 'name' => 'United Kingdom',		'continent' => 'Europe' ),
				'3580239'	=> array ( 'iso' => 'GD', 'name' => 'Grenada',			'continent' => 'North America' ),
				'614540'	=> array ( 'iso' => 'GE', 'name' => 'Georgia',			'continent' => 'Asia' ),
				'3381670'	=> array ( 'iso' => 'GF', 'name' => 'French Guiana',		'continent' => 'South America' ),
				'3042362'	=> array ( 'iso' => 'GG', 'name' => 'Guernsey',			'continent' => 'Europe' ),
				'2300660'	=> array ( 'iso' => 'GH', 'name' => 'Ghana',			'continent' => 'Africa' ),
				'2411586'	=> array ( 'iso' => 'GI', 'name' => 'Gibraltar',		'continent' => 'Europe' ),
				'3425505'	=> array ( 'iso' => 'GL', 'name' => 'Greenland',		'continent' => 'North America' ),
				'2413451'	=> array ( 'iso' => 'GM', 'name' => 'Gambia',			'continent' => 'Africa' ),
				'2420477'	=> array ( 'iso' => 'GN', 'name' => 'Guinea',			'continent' => 'Africa' ),
				'3579143'	=> array ( 'iso' => 'GP', 'name' => 'Guadeloupe',		'continent' => 'North America' ),
				'2309096'	=> array ( 'iso' => 'GQ', 'name' => 'Equatorial Guinea',	'continent' => 'Africa' ),
				'390903'	=> array ( 'iso' => 'GR', 'name' => 'Greece',			'continent' => 'Europe' ),
				'3474415'	=> array ( 'iso' => 'GS', 'name' => 'South Georgia and the South Sandwich Islands', 'continent' => 'Antarctica' ),
				'3595528'	=> array ( 'iso' => 'GT', 'name' => 'Guatemala',		'continent' => 'North America' ),
				'4043988'	=> array ( 'iso' => 'GU', 'name' => 'Guam',			'continent' => 'Oceania' ),
				'2372248'	=> array ( 'iso' => 'GW', 'name' => 'Guinea-Bissau',		'continent' => 'Africa' ),
				'3378535'	=> array ( 'iso' => 'GY', 'name' => 'Guyana',			'continent' => 'South America' ),
				'1819730'	=> array ( 'iso' => 'HK', 'name' => 'Hong Kong',		'continent' => 'Asia' ),
				'1547314'	=> array ( 'iso' => 'HM', 'name' => 'Heard Island and McDonald Islands', 'continent' => 'Antarctica' ),
				'3608932'	=> array ( 'iso' => 'HN', 'name' => 'Honduras',			'continent' => 'North America' ),
				'3202326'	=> array ( 'iso' => 'HR', 'name' => 'Croatia',			'continent' => 'Europe' ),
				'3723988'	=> array ( 'iso' => 'HT', 'name' => 'Haiti',			'continent' => 'North America' ),
				'719819'	=> array ( 'iso' => 'HU', 'name' => 'Hungary',			'continent' => 'Europe' ),
				'1643084'	=> array ( 'iso' => 'ID', 'name' => 'Indonesia',		'continent' => 'Asia' ),
				'2963597'	=> array ( 'iso' => 'IE', 'name' => 'Ireland',			'continent' => 'Europe' ),
				'294640'	=> array ( 'iso' => 'IL', 'name' => 'Israel',			'continent' => 'Asia' ),
				'3042225'	=> array ( 'iso' => 'IM', 'name' => 'Isle of Man',		'continent' => 'Europe' ),
				'1269750'	=> array ( 'iso' => 'IN', 'name' => 'India',			'continent' => 'Asia' ),
				'1282588'	=> array ( 'iso' => 'IO', 'name' => 'British Indian Ocean Territory', 'continent' => 'Asia' ),
				'99237'		=> array ( 'iso' => 'IQ', 'name' => 'Iraq',			'continent' => 'Asia' ),
				'130758'	=> array ( 'iso' => 'IR', 'name' => 'Iran',			'continent' => 'Asia' ),
				'2629691'	=> array ( 'iso' => 'IS', 'name' => 'Iceland',			'continent' => 'Europe' ),
				'3175395'	=> array ( 'iso' => 'IT', 'name' => 'Italy',			'continent' => 'Europe' ),
				'3042142'	=> array ( 'iso' => 'JE', 'name' => 'Jersey',			'continent' => 'Europe' ),
				'3489940'	=> array ( 'iso' => 'JM', 'name' => 'Jamaica',			'continent' => 'North America' ),
				'248816'	=> array ( 'iso' => 'JO', 'name' => 'Jordan',			'continent' => 'Asia' ),
				'1861060'	=> array ( 'iso' => 'JP', 'name' => 'Japan',			'continent' => 'Asia' ),
				'192950'	=> array ( 'iso' => 'KE', 'name' => 'Kenya',			'continent' => 'Africa' ),
				'1527747'	=> array ( 'iso' => 'KG', 'name' => 'Kyrgyzstan',		'continent' => 'Asia' ),
				'1831722'	=> array ( 'iso' => 'KH', 'name' => 'Cambodia',			'continent' => 'Asia' ),
				'4030945'	=> array ( 'iso' => 'KI', 'name' => 'Kiribati',			'continent' => 'Oceania' ),
				'921929'	=> array ( 'iso' => 'KM', 'name' => 'Comoros',			'continent' => 'Africa' ),
				'3575174'	=> array ( 'iso' => 'KN', 'name' => 'Saint Kitts and Nevis',	'continent' => 'North America' ),
				'1873107'	=> array ( 'iso' => 'KP', 'name' => 'North Korea',		'continent' => 'Asia' ),
				'1835841'	=> array ( 'iso' => 'KR', 'name' => 'South Korea',		'continent' => 'Asia' ),
				'831053'	=> array ( 'iso' => 'XK', 'name' => 'Kosovo',			'continent' => 'Europe' ),
				'285570'	=> array ( 'iso' => 'KW', 'name' => 'Kuwait',			'continent' => 'Asia' ),
				'3580718'	=> array ( 'iso' => 'KY', 'name' => 'Cayman Islands',		'continent' => 'North America' ),
				'1522867'	=> array ( 'iso' => 'KZ', 'name' => 'Kazakhstan',		'continent' => 'Asia' ),
				'1655842'	=> array ( 'iso' => 'LA', 'name' => 'Laos',			'continent' => 'Asia' ),
				'272103'	=> array ( 'iso' => 'LB', 'name' => 'Lebanon',			'continent' => 'Asia' ),
				'3576468'	=> array ( 'iso' => 'LC', 'name' => 'Saint Lucia',		'continent' => 'North America' ),
				'3042058'	=> array ( 'iso' => 'LI', 'name' => 'Liechtenstein',		'continent' => 'Europe' ),
				'1227603'	=> array ( 'iso' => 'LK', 'name' => 'Sri Lanka',		'continent' => 'Asia' ),
				'2275384'	=> array ( 'iso' => 'LR', 'name' => 'Liberia',			'continent' => 'Africa' ),
				'932692'	=> array ( 'iso' => 'LS', 'name' => 'Lesotho',			'continent' => 'Africa' ),
				'597427'	=> array ( 'iso' => 'LT', 'name' => 'Lithuania',		'continent' => 'Europe' ),
				'2960313'	=> array ( 'iso' => 'LU', 'name' => 'Luxembourg',		'continent' => 'Europe' ),
				'458258'	=> array ( 'iso' => 'LV', 'name' => 'Latvia',			'continent' => 'Europe' ),
				'2215636'	=> array ( 'iso' => 'LY', 'name' => 'Libya',			'continent' => 'Africa' ),
				'2542007'	=> array ( 'iso' => 'MA', 'name' => 'Morocco',			'continent' => 'Africa' ),
				'2993457'	=> array ( 'iso' => 'MC', 'name' => 'Monaco',			'continent' => 'Europe' ),
				'617790'	=> array ( 'iso' => 'MD', 'name' => 'Moldova',			'continent' => 'Europe' ),
				'3194884'	=> array ( 'iso' => 'ME', 'name' => 'Montenegro',		'continent' => 'Europe' ),
				'3578421'	=> array ( 'iso' => 'MF', 'name' => 'Saint Martin',		'continent' => 'North America' ),
				'1062947'	=> array ( 'iso' => 'MG', 'name' => 'Madagascar',		'continent' => 'Africa' ),
				'2080185'	=> array ( 'iso' => 'MH', 'name' => 'Marshall Islands',		'continent' => 'Oceania' ),
				'718075'	=> array ( 'iso' => 'MK', 'name' => 'Macedonia',		'continent' => 'Europe' ),
				'2453866'	=> array ( 'iso' => 'ML', 'name' => 'Mali',			'continent' => 'Africa' ),
				'1327865'	=> array ( 'iso' => 'MM', 'name' => 'Myanmar',			'continent' => 'Asia' ),
				'2029969'	=> array ( 'iso' => 'MN', 'name' => 'Mongolia',			'continent' => 'Asia' ),
				'1821275'	=> array ( 'iso' => 'MO', 'name' => 'Macao',			'continent' => 'Asia' ),
				'4041468'	=> array ( 'iso' => 'MP', 'name' => 'Northern Mariana Islands',	'continent' => 'Oceania' ),
				'3570311'	=> array ( 'iso' => 'MQ', 'name' => 'Martinique',		'continent' => 'North America' ),
				'2378080'	=> array ( 'iso' => 'MR', 'name' => 'Mauritania',		'continent' => 'Africa' ),
				'3578097'	=> array ( 'iso' => 'MS', 'name' => 'Montserrat',		'continent' => 'North America' ),
				'2562770'	=> array ( 'iso' => 'MT', 'name' => 'Malta',			'continent' => 'Europe' ),
				'934292'	=> array ( 'iso' => 'MU', 'name' => 'Mauritius',		'continent' => 'Africa' ),
				'1282028'	=> array ( 'iso' => 'MV', 'name' => 'Maldives',			'continent' => 'Asia' ),
				'927384'	=> array ( 'iso' => 'MW', 'name' => 'Malawi',			'continent' => 'Africa' ),
				'3996063'	=> array ( 'iso' => 'MX', 'name' => 'Mexico',			'continent' => 'North America' ),
				'1733045'	=> array ( 'iso' => 'MY', 'name' => 'Malaysia',			'continent' => 'Asia' ),
				'1036973'	=> array ( 'iso' => 'MZ', 'name' => 'Mozambique',		'continent' => 'Africa' ),
				'3355338'	=> array ( 'iso' => 'NA', 'name' => 'Namibia',			'continent' => 'Africa' ),
				'2139685'	=> array ( 'iso' => 'NC', 'name' => 'New Caledonia',		'continent' => 'Oceania' ),
				'2440476'	=> array ( 'iso' => 'NE', 'name' => 'Niger',			'continent' => 'Africa' ),
				'2155115'	=> array ( 'iso' => 'NF', 'name' => 'Norfolk Island',		'continent' => 'Oceania' ),
				'2328926'	=> array ( 'iso' => 'NG', 'name' => 'Nigeria',			'continent' => 'Africa' ),
				'3617476'	=> array ( 'iso' => 'NI', 'name' => 'Nicaragua',		'continent' => 'North America' ),
				'2750405'	=> array ( 'iso' => 'NL', 'name' => 'Netherlands',		'continent' => 'Europe' ),
				'3144096'	=> array ( 'iso' => 'NO', 'name' => 'Norway',			'continent' => 'Europe' ),
				'1282988'	=> array ( 'iso' => 'NP', 'name' => 'Nepal',			'continent' => 'Asia' ),
				'2110425'	=> array ( 'iso' => 'NR', 'name' => 'Nauru',			'continent' => 'Oceania' ),
				'4036232'	=> array ( 'iso' => 'NU', 'name' => 'Niue',			'continent' => 'Oceania' ),
				'2186224'	=> array ( 'iso' => 'NZ', 'name' => 'New Zealand',		'continent' => 'Oceania' ),
				'286963'	=> array ( 'iso' => 'OM', 'name' => 'Oman',			'continent' => 'Asia' ),
				'3703430'	=> array ( 'iso' => 'PA', 'name' => 'Panama',			'continent' => 'North America' ),
				'3932488'	=> array ( 'iso' => 'PE', 'name' => 'Peru',			'continent' => 'South America' ),
				'4030656'	=> array ( 'iso' => 'PF', 'name' => 'French Polynesia',		'continent' => 'Oceania' ),
				'2088628'	=> array ( 'iso' => 'PG', 'name' => 'Papua New Guinea',		'continent' => 'Oceania' ),
				'1694008'	=> array ( 'iso' => 'PH', 'name' => 'Philippines',		'continent' => 'Asia' ),
				'1168579'	=> array ( 'iso' => 'PK', 'name' => 'Pakistan',			'continent' => 'Asia' ),
				'798544'	=> array ( 'iso' => 'PL', 'name' => 'Poland',			'continent' => 'Europe' ),
				'3424932'	=> array ( 'iso' => 'PM', 'name' => 'Saint Pierre and Miquelon','continent' => 'North America' ),
				'4030699'	=> array ( 'iso' => 'PN', 'name' => 'Pitcairn',			'continent' => 'Oceania' ),
				'4566966'	=> array ( 'iso' => 'PR', 'name' => 'Puerto Rico',		'continent' => 'North America' ),
				'6254930'	=> array ( 'iso' => 'PS', 'name' => 'Palestinian Territory',	'continent' => 'Asia' ),
				'2264397'	=> array ( 'iso' => 'PT', 'name' => 'Portugal',			'continent' => 'Europe' ),
				'1559582'	=> array ( 'iso' => 'PW', 'name' => 'Palau',			'continent' => 'Oceania' ),
				'3437598'	=> array ( 'iso' => 'PY', 'name' => 'Paraguay',			'continent' => 'South America' ),
				'289688'	=> array ( 'iso' => 'QA', 'name' => 'Qatar',			'continent' => 'Asia' ),
				'935317'	=> array ( 'iso' => 'RE', 'name' => 'Reunion',			'continent' => 'Africa' ),
				'798549'	=> array ( 'iso' => 'RO', 'name' => 'Romania',			'continent' => 'Europe' ),
				'6290252'	=> array ( 'iso' => 'RS', 'name' => 'Serbia',			'continent' => 'Europe' ),
				'2017370'	=> array ( 'iso' => 'RU', 'name' => 'Russia',			'continent' => 'Europe' ),
				'49518'		=> array ( 'iso' => 'RW', 'name' => 'Rwanda',			'continent' => 'Africa' ),
				'102358'	=> array ( 'iso' => 'SA', 'name' => 'Saudi Arabia',		'continent' => 'Asia' ),
				'2103350'	=> array ( 'iso' => 'SB', 'name' => 'Solomon Islands',		'continent' => 'Oceania' ),
				'241170'	=> array ( 'iso' => 'SC', 'name' => 'Seychelles',		'continent' => 'Africa' ),
				'366755'	=> array ( 'iso' => 'SD', 'name' => 'Sudan',			'continent' => 'Africa' ),
				'7909807'	=> array ( 'iso' => 'SS', 'name' => 'South Sudan',		'continent' => 'Africa' ),
				'2661886'	=> array ( 'iso' => 'SE', 'name' => 'Sweden',			'continent' => 'Europe' ),
				'1880251'	=> array ( 'iso' => 'SG', 'name' => 'Singapore',		'continent' => 'Asia' ),
				'3370751'	=> array ( 'iso' => 'SH', 'name' => 'Saint Helena',		'continent' => 'Africa' ),
				'3190538'	=> array ( 'iso' => 'SI', 'name' => 'Slovenia',			'continent' => 'Europe' ),
				'607072'	=> array ( 'iso' => 'SJ', 'name' => 'Svalbard and Jan Mayen',	'continent' => 'Europe' ),
				'3057568'	=> array ( 'iso' => 'SK', 'name' => 'Slovakia',			'continent' => 'Europe' ),
				'2403846'	=> array ( 'iso' => 'SL', 'name' => 'Sierra Leone',		'continent' => 'Africa' ),
				'3168068'	=> array ( 'iso' => 'SM', 'name' => 'San Marino',		'continent' => 'Europe' ),
				'2245662'	=> array ( 'iso' => 'SN', 'name' => 'Senegal',			'continent' => 'Africa' ),
				'51537'		=> array ( 'iso' => 'SO', 'name' => 'Somalia',			'continent' => 'Africa' ),
				'3382998'	=> array ( 'iso' => 'SR', 'name' => 'Suriname',			'continent' => 'South America' ),
				'2410758'	=> array ( 'iso' => 'ST', 'name' => 'Sao Tome and Principe',	'continent' => 'Africa' ),
				'3585968'	=> array ( 'iso' => 'SV', 'name' => 'El Salvador',		'continent' => 'North America' ),
				'7609695'	=> array ( 'iso' => 'SX', 'name' => 'Sint Maarten',		'continent' => 'North America' ),
				'163843'	=> array ( 'iso' => 'SY', 'name' => 'Syria',			'continent' => 'Asia' ),
				'934841'	=> array ( 'iso' => 'SZ', 'name' => 'Swaziland',		'continent' => 'Africa' ),
				'3576916'	=> array ( 'iso' => 'TC', 'name' => 'Turks and Caicos Islands','continent' => 'North America' ),
				'2434508'	=> array ( 'iso' => 'TD', 'name' => 'Chad',			'continent' => 'Africa' ),
				'1546748'	=> array ( 'iso' => 'TF', 'name' => 'French Southern Territories', 'continent' => 'Antarctica' ),
				'2363686'	=> array ( 'iso' => 'TG', 'name' => 'Togo',			'continent' => 'Africa' ),
				'1605651'	=> array ( 'iso' => 'TH', 'name' => 'Thailand',			'continent' => 'Asia' ),
				'1220409'	=> array ( 'iso' => 'TJ', 'name' => 'Tajikistan',		'continent' => 'Asia' ),
				'4031074'	=> array ( 'iso' => 'TK', 'name' => 'Tokelau',			'continent' => 'Oceania' ),
				'1966436'	=> array ( 'iso' => 'TL', 'name' => 'East Timor',		'continent' => 'Oceania' ),
				'1218197'	=> array ( 'iso' => 'TM', 'name' => 'Turkmenistan',		'continent' => 'Asia' ),
				'2464461'	=> array ( 'iso' => 'TN', 'name' => 'Tunisia',			'continent' => 'Africa' ),
				'4032283'	=> array ( 'iso' => 'TO', 'name' => 'Tonga',			'continent' => 'Oceania' ),
				'298795'	=> array ( 'iso' => 'TR', 'name' => 'Turkey',			'continent' => 'Asia' ),
				'3573591'	=> array ( 'iso' => 'TT', 'name' => 'Trinidad and Tobago',	'continent' => 'North America' ),
				'2110297'	=> array ( 'iso' => 'TV', 'name' => 'Tuvalu',			'continent' => 'Oceania' ),
				'1668284'	=> array ( 'iso' => 'TW', 'name' => 'Taiwan',			'continent' => 'Asia' ),
				'149590'	=> array ( 'iso' => 'TZ', 'name' => 'Tanzania',			'continent' => 'Africa' ),
				'690791'	=> array ( 'iso' => 'UA', 'name' => 'Ukraine',			'continent' => 'Europe' ),
				'226074'	=> array ( 'iso' => 'UG', 'name' => 'Uganda',			'continent' => 'Africa' ),
				'5854968'	=> array ( 'iso' => 'UM', 'name' => 'United States Minor Outlying Islands', 'continent' => 'Oceania' ),
				'6252001'	=> array ( 'iso' => 'US', 'name' => 'United States',		'continent' => 'North America' ),
				'3439705'	=> array ( 'iso' => 'UY', 'name' => 'Uruguay',			'continent' => 'South America' ),
				'1512440'	=> array ( 'iso' => 'UZ', 'name' => 'Uzbekistan',		'continent' => 'Asia' ),
				'3164670'	=> array ( 'iso' => 'VA', 'name' => 'Vatican',			'continent' => 'Europe' ),
				'3577815'	=> array ( 'iso' => 'VC', 'name' => 'Saint Vincent and the Grenadines', 'continent' => 'North America' ),
				'3625428'	=> array ( 'iso' => 'VE', 'name' => 'Venezuela',		'continent' => 'South America' ),
				'3577718'	=> array ( 'iso' => 'VG', 'name' => 'British Virgin Islands',	'continent' => 'North America' ),
				'4796775'	=> array ( 'iso' => 'VI', 'name' => 'U.S. Virgin Islands',	'continent' => 'North America' ),
				'1562822'	=> array ( 'iso' => 'VN', 'name' => 'Vietnam',			'continent' => 'Asia' ),
				'2134431'	=> array ( 'iso' => 'VU', 'name' => 'Vanuatu',			'continent' => 'Oceania' ),
				'4034749'	=> array ( 'iso' => 'WF', 'name' => 'Wallis and Futuna',	'continent' => 'Oceania' ),
				'4034894'	=> array ( 'iso' => 'WS', 'name' => 'Samoa',			'continent' => 'Oceania' ),
				'69543'		=> array ( 'iso' => 'YE', 'name' => 'Yemen',			'continent' => 'Asia' ),
				'1024031'	=> array ( 'iso' => 'YT', 'name' => 'Mayotte',			'continent' => 'Africa' ),
				'953987'	=> array ( 'iso' => 'ZA', 'name' => 'South Africa',		'continent' => 'Africa' ),
				'895949'	=> array ( 'iso' => 'ZM', 'name' => 'Zambia',			'continent' => 'Africa' ),
				'878675'	=> array ( 'iso' => 'ZW', 'name' => 'Zimbabwe',			'continent' => 'Africa' )
				);

	// Remove previous list of GeoIP ISOs for IPv4/6 Source Field lookup
	unlink_if_exists("{$pfb['geoip_isos']}");

	// Determine if any Countries are missing from the MaxMind Database
	foreach ($pfb_geoip_all as $iso => $cc) {

		// Create list of GeoIP ISOs for IPv4/6 Source Field lookup
		@file_put_contents("{$pfb['geoip_isos']}", "{$cc['iso']} [ {$cc['name']} ],{$cc['iso']}_rep [ {$cc['name']} ],", FILE_APPEND | LOCK_EX);

		// Add missing Country as a 'placeholder'
		if (!isset($pfb_geoip['country'][$iso])) {
			$continent_en = str_replace(array(' ', '"'), array('_', ''), $cc['continent']);

			$pfb_geoip['country'][$iso] = array (	'missing_iso' => TRUE, 'id' => $iso, 'name' => $cc['name'],
								'iso' => array ( "{$cc['iso']}", "{$cc['iso']}_rep" ),
								'continent' => $cc['continent'], 'continent_en' => $continent_en);

			$pfb_geoip['country']['proxy']['iso'][]		= "A1_{$cc['iso']}_rep";
			$pfb_geoip['country']['satellite']['iso'][]	= "A2_{$cc['iso']}_rep";
		}
	}

	// Add Continents to GeoIP ISOs for IPv4/6 Source Field lookup
	$add_continents = 'Africa [Continent],Antarctica [Continent],Asia [Continent],Europe [Continent],North_America [Continent],Oceania [Continent]';
	$add_continents .= ',South_America [Continent],Proxy_and_Satellite [GeoIP]';
	@file_put_contents("{$pfb['geoip_isos']}", "{$add_continents}", FILE_APPEND | LOCK_EX);

	ksort($pfb_geoip['country'], SORT_NATURAL);

	// Collect Country ISO data and sort to Continent arrays (IPv4 and IPv6)
	foreach (array('4', '6') as $type) {
	
		$log = " Processing ISO IPv{$type} Continent/Country Data\n";
		pfb_logger("{$log}", 4);

		$geoip_dup = 0;		// Count of Geoname_ids which have both a different 'Registered and Represented' geoname_id

		$maxmind_cc = "{$pfb['geoipshare']}/GeoLite2-Country-Blocks-IPv{$type}.csv";
		if (($handle = @fopen("{$maxmind_cc}", 'r')) !== FALSE) {
			while (($cc = @fgetcsv($handle)) !== FALSE) {

				/*	Sample lines:
					Network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider
					1.0.0.0/24,2077456,2077456,,0,0		*/

				if ($cc[0] == 'network') {
					continue;
				}

				$iso = $iso_rep = '';
				if ($type == 4) {

					// Remove all Countries listed by MaxMind from list of all known Countries
					if (isset($pfb_geoip_all[$cc[1]])) {
						unset($pfb_geoip_all[$cc[1]]);
					}

					// Is Anonymous Proxy?
					if ($cc[4] == 1) {
	
						if (!empty($cc[1])) {
							$iso = "A1_{$pfb_geoip['country']['proxy']['iso'][0]}";
						}
						if (!empty($cc[2]) && $cc[1] != $cc[2]) {
							$geoip_dup++;
							$iso_rep = "A1_{$pfb_geoip['country'][$cc[2]]['iso'][0]}_rep";
						}
						if (empty($cc[1]) && empty($cc[2])) {
							$iso = 'A1';
						}
						$cc[2] = 'proxy';	// Re-define variable
					}

					// Is Satellite Provider?
					elseif ($cc[5] == 1) {

						if (!empty($cc[1])) {
							$iso = "A2_{$pfb_geoip['country']['satellite']['iso'][0]}";
						}
						if (!empty($cc[2]) && $cc[1] != $cc[2]) {
							$geoip_dup++;
							$iso_rep = "A2_{$pfb_geoip['country'][$cc[2]]['iso'][0]}_rep";
						}
						if (empty($cc[1]) && empty($cc[2])) {
							$iso = 'A2';
						}
						$cc[2] = 'satellite';	// Re-define variable
					}
					else {
						if (!empty($cc[1])) {
							$iso = "{$pfb_geoip['country'][$cc[1]]['iso'][0]}";
						}
						if (!empty($cc[2]) && $cc[1] != $cc[2]) {
							$geoip_dup++;
							$iso_rep = "{$pfb_geoip['country'][$cc[2]]['iso'][0]}_rep";
						}
					}

					// Add 'ISO Represented' to Country ISO list
					if (!empty($iso_rep) && !empty($cc[2])) {

						// Only add if not existing
						if (!isset($pfb_geoip['country'][$cc[2]]) ||
						    !in_array($iso_rep, $pfb_geoip['country'][$cc[2]]['iso'])) {
							$pfb_geoip['country'][$cc[2]]['iso'][] = "{$iso_rep}";
						}
					}

					// Add placeholders for 'undefined ISO Represented' to Country ISO list
					if (!empty($cc[1])) {
						foreach (array( '' => $cc[1], 'A1_' => 'proxy', 'A2_' => 'satellite' ) as $reptype => $iso_placeholder) {
							$iso_rep_placeholder = "{$reptype}{$pfb_geoip['country'][$cc[1]]['iso'][0]}_rep";

							// Only add if not existing
							if (!isset($pfb_geoip['country'][$iso_placeholder]) ||
							    !in_array($iso_rep_placeholder, $pfb_geoip['country'][$iso_placeholder]['iso'])) {
								$pfb_geoip['country'][$iso_placeholder]['iso'][] = "{$iso_rep_placeholder}";
							}
						}
					}

					// Save ISO 'Represented Network' to ISO file
					if (!empty($iso_rep) && !empty($cc[0]) && !empty(pfb_filter($iso_rep, PFB_FILTER_WORD, 'php'))) {
						@file_put_contents("{$pfb['ccdir_tmp']}/{$iso_rep}_v{$type}.txt", "{$cc[0]}\n", FILE_APPEND | LOCK_EX);
					}
				}
				else {
					if (!empty($cc[1])) {
						$iso = "{$pfb_geoip['country'][$cc[1]]['iso'][0]}";
					}
				}

				// Save 'ISO Registered Network' to ISO file
				if (!empty($iso) && !empty($cc[0]) && !empty(pfb_filter($iso, PFB_FILTER_WORD, 'php'))) {
					@file_put_contents("{$pfb['ccdir_tmp']}/{$iso}_v{$type}.txt", "{$cc[0]}\n", FILE_APPEND | LOCK_EX);
				}
			}

			// For IPv4 - Add A1 & A2 placeholders for any Countries that MaxMind has not listed any data
			if ($type == 4) {
				if (!empty($pfb_geoip_all)) {
					foreach ($pfb_geoip_all as $cc) {
						foreach (array( 'A1_' => 'proxy', 'A2_' => 'satellite' ) as $reptype => $iso_placeholder) {
							$pfb_geoip['country'][$iso_placeholder]['iso'][] = "{$reptype}{$cc['iso']}_rep";
						}
					}
				}
				unset($pfb_geoip_all);
			}

			// Report number of Geoname_ids which have both a different 'Registered and Represented' geoname_id
			if ($geoip_dup != 0) {
				@file_put_contents("{$pfb['logdir']}/maxmind_ver", "Duplicate Represented IP{$type} Networks: {$geoip_dup}\n", FILE_APPEND | LOCK_EX);
			}

			// Delete previous GeoIP Continent files
			array_map('unlink_if_exists', array(	"{$pfb['ccdir']}/Top_Spammers_v{$type}.info",
								"{$pfb['ccdir']}/Africa_v{$type}.txt",
								"{$pfb['ccdir']}/Antarctica_v{$type}.txt",
								"{$pfb['ccdir']}/Asia_v{$type}.txt",
								"{$pfb['ccdir']}/Europe_v{$type}.txt",
								"{$pfb['ccdir']}/*_America_v{$type}.txt",
								"{$pfb['ccdir']}/Oceania_v{$type}.txt",
								"{$pfb['ccdir']}/Proxy_and_Satellite_v{$type}.txt" ));

			// Create Continent txt files
			if (!empty($pfb_geoip['country'])) {
				foreach ($pfb_geoip['country'] as $key => $geoip) {

					// Save 'TOP 20' data
					if (strpos($key, 'A000') !== FALSE) {
						$pfb_file = "{$pfb['ccdir']}/Top_Spammers_v{$type}.info";

						if (!file_exists($pfb_file)) {
							$header  = '# Generated from MaxMind Inc. on: ' . date('Y-m-d H:i:s', time()) . "\n";
							$header .= "# Continent IPv{$type}: Top_Spammers\n";
							$header .= "# Continent en: Top_Spammers\n";
							@file_put_contents($pfb_file, $header, LOCK_EX);
						}

						$iso_header  = "# Country: {$geoip['name']} ({$geoip['id']})\n";
						$iso_header .= "# ISO Code: {$geoip['iso']}\n";
						$iso_header .= "# Total Networks: Top20\n";
						$iso_header .= "Top20\n";

						// Add any 'TOP 20' Represented ISOs Networks
						if (file_exists("{$pfb['ccdir_tmp']}/{$geoip['iso']}_rep_v{$type}.txt")) {
							$iso_header .= "# Country: {$geoip['name']} ({$geoip['id']})\n";
							$iso_header .= "# ISO Code: {$geoip['iso']}_rep\n";
							$iso_header .= "# Total Networks: Top20\n";
							$iso_header .= "Top20\n";
						}
						@file_put_contents($pfb_file, $iso_header, FILE_APPEND | LOCK_EX);
					}

					else {
						if (!empty($geoip['continent_en']) && !empty(pfb_filter($geoip['continent_en'], PFB_FILTER_WORD, 'php'))) {

							$pfb_file	= "{$pfb['ccdir']}/{$geoip['continent_en']}_v{$type}.txt";

							if (!file_exists($pfb_file)) {
								$header  = '# Generated from MaxMind Inc. on: ' . date('Y-m-d H:i:s', time()) . "\n";
								$header .= "# Continent IPv{$type}: {$geoip['continent']}\n";
								$header .= "# Continent en: {$geoip['continent_en']}\n";
								@file_put_contents($pfb_file, $header, LOCK_EX);
							}

							if (!empty($geoip['iso'])) {
								foreach ($geoip['iso'] as $iso) {
									if (!empty(pfb_filter($iso, PFB_FILTER_WORD, 'php'))) {

										$iso_file	= "{$pfb['ccdir_tmp']}/{$iso}_v{$type}.txt";
										$geoip_id = '';
										if (!empty($geoip['id'])) {
											$geoip_id = " [{$geoip['id']}]";
										}

										if (file_exists($iso_file)) {
											$iso_header = pfb_geoip_networks_header($iso_file, $geoip['name'], $geoip_id, $iso);
											@file_put_contents($pfb_file, $iso_header, FILE_APPEND | LOCK_EX);

										// Concat ISO Networks to Continent file
										if (!pfb_geoip_append_iso_data($pfb['cat'], $iso_file, $pfb_file, $pfb['ccdir_tmp'], $iso, $type)) {
											$discard_generation();
											return FALSE;
										}
										}
										else {
											// Create placeholder file for undefined 'ISO Represented' or undefined Countries
											$iso_header  = "# Country: {$geoip['name']}{$geoip_id}\n";
											$iso_header .= "# ISO Code: {$iso}\n";
											$iso_header .= "# Total Networks: NA\n";
											@file_put_contents($pfb_file, $iso_header, FILE_APPEND | LOCK_EX);
										}
									}
								}

								// Reset ISOs to original setting (Remove any Represented ISOs)
								$pfb_geoip['country'][$key]['iso'] = array($pfb_geoip['country'][$key]['iso'][0]);
							}
							else {
								$log = "\n Missing ISO data: {$geoip['continent']}";
								pfb_logger("{$log}", 4);
								
							}
						}
						else {
							$log = "\n Failed to create Continent file: {$geoip['continent']}";
							pfb_logger("{$log}", 4);
						}
					}
				}
			}
			if ($cc) {
				unset($cc);
			}
			if ($handle) {
				@fclose($handle);
			}
		}
		else {
			$log = "\n Failed to load file: {$maxmind_cc}\n";
			pfb_logger("{$log}", 4);
			$generation_ok = FALSE;
		}

	}
	unset($pfb_geoip);
	rmdir_recursive("{$pfb['ccdir_tmp']}");
	$required_files = array($stage_geoip_isos);
	foreach (array('4', '6') as $type) {
		foreach (array('Africa', 'Antarctica', 'Asia', 'Europe', 'North_America', 'Oceania', 'South_America', 'Proxy_and_Satellite') as $continent) {
			$required_files[] = "{$stage_ccdir}/{$continent}_v{$type}.txt";
		}
	}
	foreach ($required_files as $required_file) {
		if (!is_file($required_file)) {
			$generation_ok = FALSE;
			break;
		}
	}
	if (!$generation_ok) {
		$discard_generation();
		return FALSE;
	}
	if ($stage_output_root !== NULL && !pfblockerng_get_countries($stage_output_root)) {
		$discard_generation();
		return FALSE;
	}

	$pfb['ccdir'] = $live_ccdir;
	$pfb['geoip_isos'] = $live_geoip_isos;
	$publication_lock = pfb_geoip_generation_publication_lock($live_ccdir);
	if ($publication_lock === FALSE) {
		$discard_generation();
		return FALSE;
	}
	$backup_root = "{$live_ccdir}.old.{$generation}";
	$backup_ccdir = "{$backup_root}/countries";
	$backup_output_root = $stage_output_root === NULL ? NULL : "{$output_root}.old.{$generation}";
	$swap_sentinel = "{$live_ccdir}/.pfb_generation_swapping";
	safe_mkdir($backup_ccdir, 0755);
	if ($backup_output_root !== NULL) {
		safe_mkdir($backup_output_root, 0755);
	}
	safe_mkdir($live_ccdir, 0755);
	$original_country_files = [];
	foreach (glob("{$live_ccdir}/*") ?: [] as $live_file) {
		if (is_file($live_file)) {
			$name = basename($live_file);
			$original_country_files[$name] = TRUE;
			if (!@copy($live_file, "{$backup_ccdir}/{$name}")) {
				$discard_generation();
				rmdir_recursive($backup_root);
				if ($backup_output_root !== NULL) {
					rmdir_recursive($backup_output_root);
				}
				pfb_geoip_generation_publication_unlock($publication_lock);
				return FALSE;
			}
		}
	}
	$had_geoip_isos = is_file($live_geoip_isos);
	if ($had_geoip_isos && !@copy($live_geoip_isos, "{$backup_root}/geoip_isos")) {
		$discard_generation();
		rmdir_recursive($backup_root);
		if ($backup_output_root !== NULL) {
			rmdir_recursive($backup_output_root);
		}
		pfb_geoip_generation_publication_unlock($publication_lock);
		return FALSE;
	}
	if (@file_put_contents($swap_sentinel, $generation, LOCK_EX) === FALSE) {
		$discard_generation();
		rmdir_recursive($backup_root);
		if ($backup_output_root !== NULL) {
			rmdir_recursive($backup_output_root);
		}
		pfb_geoip_generation_publication_unlock($publication_lock);
		return FALSE;
	}
	$published_country_files = [];
	$published_output_files = [];
	$publish_ok = TRUE;
	foreach (glob("{$stage_ccdir}/*") ?: [] as $stage_file) {
		if (is_file($stage_file)) {
			$name = basename($stage_file);
			$published_country_files[$name] = TRUE;
			if (!@rename($stage_file, "{$live_ccdir}/{$name}")) {
				$publish_ok = FALSE;
				break;
			}
		}
	}
	if ($publish_ok && !@rename($stage_geoip_isos, $live_geoip_isos)) {
		$publish_ok = FALSE;
	}
	if ($publish_ok && $stage_output_root !== NULL) {
		foreach (glob("{$stage_output_root}/*") ?: [] as $stage_file) {
			if (is_file($stage_file)) {
				$name = basename($stage_file);
				if (is_file("{$output_root}/{$name}") && !@copy("{$output_root}/{$name}", "{$backup_output_root}/{$name}")) {
					$publish_ok = FALSE;
					break;
				}
				$published_output_files[$name] = TRUE;
				if (!@rename($stage_file, "{$output_root}/{$name}")) {
					$publish_ok = FALSE;
					break;
				}
			}
		}
	}
	if (!$publish_ok) {
		foreach ($published_country_files as $name => $_) {
			unlink_if_exists("{$live_ccdir}/{$name}");
		}
		foreach (glob("{$backup_ccdir}/*") ?: [] as $backup_file) {
			@rename($backup_file, "{$live_ccdir}/" . basename($backup_file));
		}
		if ($had_geoip_isos) {
			@rename("{$backup_root}/geoip_isos", $live_geoip_isos);
		} else {
			unlink_if_exists($live_geoip_isos);
		}
		foreach ($published_output_files as $name => $_) {
			unlink_if_exists("{$output_root}/{$name}");
			if (is_file("{$backup_output_root}/{$name}")) {
				@rename("{$backup_output_root}/{$name}", "{$output_root}/{$name}");
			}
		}
		$discard_generation();
		rmdir_recursive($backup_root);
		if ($backup_output_root !== NULL) {
			rmdir_recursive($backup_output_root);
		}
		unlink_if_exists($swap_sentinel);
		pfb_geoip_generation_publication_unlock($publication_lock);
		return FALSE;
	}
	foreach ($original_country_files as $name => $_) {
		if (!isset($published_country_files[$name])) {
			unlink_if_exists("{$live_ccdir}/{$name}");
		}
	}
	$discard_generation();
	rmdir_recursive($backup_root);
	if ($backup_output_root !== NULL) {
		rmdir_recursive($backup_output_root);
	}
	unlink_if_exists($swap_sentinel);
	pfb_geoip_generation_publication_unlock($publication_lock);
	return TRUE;
}

<?php
/*
 * pfblockerng.inc
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

require_once('config.lib.inc');
require_once('util.inc');
require_once('functions.inc');
require_once('pkg-utils.inc');
require_once('pfsense-utils.inc');
require_once('globals.inc');
require_once('services.inc');
require_once('service-utils.inc');
if (file_exists('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc')) {
	require_once('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');	// 'include functions' not yet merged into pfSense
}
define('LOG_PREFIX_PKG_PFBLOCKERNG', 'pfBlockerNG');

global $g, $pfb;
if (!is_array($pfb)) {
	$pfb = array();
}

/**
 * Capture the installed settings family, then restore the package snapshot for the current
 * version. Install callers run migrations separately so the legacy VIP migration retains its
 * historical position between restore and migration.
 */
function pfb_install_settings_family_capture_restore(
	?callable $current = NULL,
	?callable $save = NULL,
	?callable $version = NULL,
	?callable $from_version = NULL,
	?callable $replace = NULL
): string {
	$current ??= 'pfb_settings_family_current';
	$save ??= 'pfb_settings_family_save';
	$version ??= 'pfb_pkg_ver';
	$from_version ??= 'pfb_settings_family_from_version';
	$replace ??= 'pfb_settings_family_replace';
	$source_family = $current();
	$installed_family = $from_version((string) $version());
	$bridge_rank = PFB_SETTINGS_FAMILY_RANK['3.3'];
	$source_rank = (is_string($source_family) && isset(PFB_SETTINGS_FAMILY_RANK[$source_family]))
		? PFB_SETTINGS_FAMILY_RANK[$source_family]
		: -1;
	$target_rank = (is_string($installed_family) && isset(PFB_SETTINGS_FAMILY_RANK[$installed_family]))
		? PFB_SETTINGS_FAMILY_RANK[$installed_family]
		: NULL;
	// Owner ruling #2158: 3.3 is the migration floor. Skip the guard when
	// owned sections are empty (first install); current() defaults missing
	// markers to '3.2', which is indistinguishable from a real 3.2 box.
	if ($target_rank !== NULL && $target_rank > $bridge_rank && $source_rank < $bridge_rank
		&& pfb_settings_family_owned_sections() !== []) {
		throw new RuntimeException('pfBlockerNG: install the 3.3 bridge before a 4.x family');
	}
	if ($source_family === NULL || !$save($source_family)) {
		throw new RuntimeException('pfBlockerNG: unable to save source settings family');
	}
	if ($installed_family === NULL || !$replace($installed_family)) {
		$replace($source_family);
		throw new RuntimeException('pfBlockerNG: unable to restore settings family');
	}
	return $installed_family;
}

function pfb_install_settings_family_finalize(
	string $installed_family,
	?callable $migrations = NULL,
	?callable $record = NULL
): void {
	$migrations ??= 'pfb_run_migrations';
	$record ??= 'pfb_settings_family_record';
	$migrations();
	if (!$record($installed_family)) {
		throw new RuntimeException('pfBlockerNG: unable to record settings family');
	}
}

function pfb_install_registry_writeback(
	array $sections,
	?array $modes = NULL,
	?callable $pass = NULL,
	?callable $write_section = NULL,
	?callable $flush = NULL
): void {
	$pass ??= 'pfb_registry_pass';
	$write_section ??= 'PfbConfig::writeSectionSystem';
	$flush ??= 'write_config';
	foreach ($pass($sections, NULL, $modes) as $path => $blob) {
		$write_section($path, $blob);
	}
	$flush('[pfBlockerNG] Save installation settings');
}

/**
 * issue #2371: apply the fresh-install feed-at-suffix PSL policy seed. $fresh is
 * pfb_psl_feed_policy_is_fresh_install()'s PRE-migration read, captured by the
 * installer before pfb_run_migrations()/pfb_registry_pass() run; this seam itself
 * must be called by the installer AFTER pfb_install_registry_writeback() -- see
 * pfb_psl_feed_policy_is_fresh_install()'s docblock for why (folding the seed into
 * pfb_migration_registry() would flip pfb_registry_pass()'s NEWCFG/OLDCFG mode for
 * every OTHER registered dnsbl/* field once the seeded keys make the section
 * non-empty). A no-op (no write, no flush) when $fresh is FALSE -- an existing
 * install's absent keys stay absent and read Honor via the registry default.
 *
 * DI seam (mirrors pfb_install_registry_writeback() above) so tests exercise this
 * EXACT function rather than a hand-copied reimplementation: a mutation to this body
 * is caught by both the installer's real call site (source-scan, see
 * InstallPrePassWriteOrderTest.php's pattern) and a direct DI-based unit test.
 */
function pfb_install_psl_feed_policy_seed(
	bool $fresh,
	?callable $write = NULL,
	?callable $flush = NULL
): void {
	if (!$fresh) {
		return;
	}
	$write ??= 'PfbConfig::writeSystem';
	$flush ??= 'write_config';
	$write('dnsbl/pfb_psl_feed_private_policy', 'apex');
	$write('dnsbl/pfb_psl_feed_icann_policy', 'apex');
	$flush('pfBlockerNG: seeded feed-at-suffix PSL policy defaults for fresh install (issue #2371)');
}

function pfb_install_probe_cleanup(?callable $purge = NULL): void {
	$purge ??= 'pfb_purge_probe_bodies';
	$purge();
}

function pfb_lint_response(array $server, array $post, callable $allowed, callable $diagnostics): array {
	$reply = static function (int $status, array $payload): array {
		return [
			'status'  => $status,
			'headers' => ['Content-Type: application/json; charset=utf-8'],
			'body'    => (string) json_encode($payload, JSON_INVALID_UTF8_SUBSTITUTE),
		];
	};
	if (($server['REQUEST_METHOD'] ?? '') !== 'POST') {
		return $reply(405, ['error' => 'POST only']);
	}
	$lang = $post['lang'] ?? NULL;
	if (!is_string($lang) || !in_array($lang, ['regex', 'sh', 'py'], TRUE)) {
		return $reply(400, ['error' => 'lang must be one of regex, sh, py']);
	}
	$privilege = $lang === 'regex' ? 'pfblockerng/pfblockerng_dnsbl.php' : 'diag_command.php';
	if (!$allowed($privilege)) {
		return $reply(403, ['error' => 'insufficient privilege']);
	}
	$content = $post['content'] ?? '';
	if (!is_string($content)) {
		return $reply(400, ['error' => 'content must be a string']);
	}
	if (strlen($content) > 1048576) {
		return $reply(413, ['error' => 'content too large']);
	}
	$cap = ($post['cap'] ?? '') === '1';
	return $reply(200, ['diagnostics' => $diagnostics($lang, $content, $cap)]);
}

function pfb_update_tail_response(array $query, callable $tail): array {
	$has_offset = isset($query['offset']) && ctype_digit((string) $query['offset']);
	$payload = $tail('update', $has_offset ? (int) $query['offset'] : -1, $has_offset);
	return [
		'headers' => ['Content-Type: application/json', 'Cache-Control: no-cache, no-store, must-revalidate'],
		'body'    => (string) json_encode($payload, JSON_INVALID_UTF8_SUBSTITUTE),
	];
}

function pfb_widget_table_call(array $table, string $mode = '', ?callable $render = NULL): mixed {
	$render ??= 'pfBlockerNG_get_table';
	return $render($table, $mode);
}

function pfb_widget_post_guard(array $post, array $server, string $field): bool {
	$present = $field === 'pfb_submit' ? isset($post[$field]) : !empty($post[$field]);
	return $present && pfb_widget_post_allowed($server);
}

function pfb_geoip_doc_link(): string {
	return '<a target="_blank" rel="noopener noreferrer" href="https://dev.maxmind.com/geoip/whats-new-in-geoip2/">'
		. '<span class="text-danger"><strong>What\'s new in GeoIP2</strong></span></a>';
}

// Folders
$pfb['dbdir']		= "{$g['vardb_path']}/pfblockerng";
$pfb['aliasdir']	= "{$g['vardb_path']}/aliastables";
$pfb['logdir']		= "{$g['varlog_path']}/pfblockerng";
$pfb['etdir']		= "{$pfb['dbdir']}/ET";
$pfb['nativedir']	= "{$pfb['dbdir']}/native";
$pfb['denydir']		= "{$pfb['dbdir']}/deny";
$pfb['matchdir']	= "{$pfb['dbdir']}/match";
// issue #1250: machine-generated match artifacts, kept out of matchdir so a
// user-chosen Match-list header can never collide with them.
$pfb['matchgendir']	= "{$pfb['matchdir']}/generated";
$pfb['permitdir']	= "{$pfb['dbdir']}/permit";
$pfb['origdir']		= "{$pfb['dbdir']}/original";
$pfb['snapdir']		= "{$pfb['dbdir']}/snapshot";	// issue #1084: pristine post-preprocessing feed snapshots (recompute memberlist inputs)
$pfb['dnsdir']		= "{$pfb['dbdir']}/dnsbl";
$pfb['dnsorigdir']	= "{$pfb['dbdir']}/dnsblorig";
$pfb['geoipshare']	= '/usr/local/share/GeoIP';
$pfb['ccdir']		= '/usr/local/share/GeoIP/cc';
$pfb['ccdir_tmp']	= '/tmp/geoip_cc';
$pfb['dnsbl_tmp']	= '/tmp/dnsbl_tmp';
$pfb['dnsbl_tmpdir']	= '/tmp/DNSBL_TMP';

// Application Paths
$pfb['grep']	= '/usr/bin/grep';
$pfb['ggrep']	= '/usr/local/bin/ggrep';	// textproc/gnugrep
$pfb['awk']	= '/usr/bin/awk';
$pfb['cut']	= '/usr/bin/cut';
$pfb['sed']	= '/usr/bin/sed';
$pfb['cat']	= '/bin/cat';
$pfb['ls']	= '/bin/ls';
$pfb['php']	= '/usr/local/bin/php';
$pfb['pfctl']	= '/sbin/pfctl';
$pfb['wc']	= '/usr/bin/wc';

// Folder Array
$pfb['folder_array'] = array(	"{$pfb['dbdir']}", "{$pfb['logdir']}", "{$pfb['ccdir']}", "{$pfb['origdir']}", "{$pfb['nativedir']}",
				"{$pfb['denydir']}", "{$pfb['matchdir']}","{$pfb['permitdir']}", "{$pfb['aliasdir']}",
				"{$pfb['dnsdir']}", "{$pfb['dnsorigdir']}", "{$pfb['snapdir']}",
				"{$pfb['matchgendir']}");

// Files
$pfb['log']		= "{$pfb['logdir']}/pfblockerng.log";
// Per-run log for the live Update viewer (AJAX tail). Mirrors the main-log lines of the CURRENT
// run only; truncated at each run start and NOT registered with pfb_log_mgmt(), so byte offsets
// stay stable for the tail even when pfb_log_mgmt() trims the cumulative log mid-schedule.
$pfb['runlog']		= "{$pfb['logdir']}/pfblockerng_run.log";
$pfb['dnslog']		= "{$pfb['logdir']}/dnsbl.log";
$pfb['dnsreplylog']	= "{$pfb['logdir']}/dns_reply.log";
$pfb['ip_blocklog']	= "{$pfb['logdir']}/ip_block.log";
$pfb['ip_permitlog']	= "{$pfb['logdir']}/ip_permit.log";
$pfb['ip_matchlog']	= "{$pfb['logdir']}/ip_match.log";
$pfb['unilog']		= "{$pfb['logdir']}/unified.log";
$pfb['errlog']		= "{$pfb['logdir']}/error.log";
$pfb['pyerrlog']	= "{$pfb['logdir']}/py_error.log";
$pfb['extraslog']	= "{$pfb['logdir']}/extras.log";
$pfb['dnsbl_parse_err']	= "{$pfb['logdir']}/dnsbl_parsed_error.log";
$pfb['ip_parse_err']	= "{$pfb['logdir']}/ip_parsed_error.log";

$pfb['master']		= "{$pfb['dbdir']}/masterfile";
$pfb['supptxt']		= "{$pfb['dbdir']}/pfbsuppression.txt";
$pfb['supptxt_v6']	= "{$pfb['dbdir']}/pfbsuppression_v6.txt";	// ADR-53: IPv6 suppression customlist
$pfb['dnsbl_supptxt']	= "{$pfb['dbdir']}/pfbdnsblsuppression.txt";
$pfb['geoip_isos']	= "{$pfb['dbdir']}/geoip.txt";
$pfb['dnsbl_info']	= '/var/unbound/pfb_py_dnsbl.sqlite';
$pfb['dnsbl_resolver']	= '/var/unbound/pfb_py_resolver.sqlite';
// Legacy reports-cache path retained for exact upgrade cleanup only.
$pfb['dnsbl_cache']	= '/var/unbound/pfb_py_cache.sqlite';
$pfb['asn_cache']	= "{$pfb['dbdir']}/asn_cache.sqlite";
$pfb['ip_cache']	= "{$pfb['dbdir']}/ip_cache.sqlite";

$pfb['script']		= '/usr/local/pkg/pfblockerng/pfblockerng.sh';
$pfb['feeds']		= '/usr/local/www/pfblockerng/pfblockerng_feeds.json';
// #468: extension-less BASES. pfb_archive_{compress,extract} (pfblockerng.sh) append
// .zst (zstd) or .bz2 (bzip2 fallback / pre-#468 legacy) and pick the codec by what is
// available; teardown removes both extensions.
$pfb['aliasarchive']	= '/usr/local/etc/aliastables.tar';
// #468: DNSBL python-integration cache (RAM-disk /var restore). SEPARATE base from the IP
// aliastables archive -- managed by pfb_dnsbl_cache() / 'pfblockerng.sh dnsbl_cache'.
$pfb['dnsblarchive']	= '/usr/local/etc/pfb_dnsbl_cache.tar';
// "Pending changes" marker (deferred DNSBL/IP/Feeds settings await the next Update). Kept in
// /usr/local/etc, NOT $pfb['dbdir'] (/var/db): use_mfs_tmpvar RAM-disks only /var + /tmp, so a
// marker here survives a reboot (the change really is still unapplied) until a real Update clears
// it. See pfb_pending_changes_marker().
$pfb['pending_marker']	= '/usr/local/etc/pfb_pending_changes';

$pfb['dnsbl_conf']	= '/var/unbound/pfb_dnsbl_lighty.conf';
$pfb['dnsbl_cert']	= '/var/unbound/dnsbl_cert.pem';
$pfb['unbound_py_conf']	= '/var/unbound/pfb_unbound.ini';
$pfb['unbound_py_wh']	= '/var/unbound/pfb_py_whitelist.txt';
$pfb['unbound_py_data']	= '/var/unbound/pfb_py_data.txt';
$pfb['unbound_py_zone'] = '/var/unbound/pfb_py_zone.txt';
$pfb['unbound_py_ss']	= '/var/unbound/pfb_py_ss.txt';
$pfb['unbound_py_hsts']	= '/var/unbound/pfb_py_hsts.txt';	// SHIPPED file re-staged by dnsbl_cache_stage() cp -f; fingerprinted so a package update ships a new list and triggers a zero-downtime reload
$pfb['unbound_py_psl']	= '/var/unbound/dnsbl_psl';	// SHIPPED PSL authority, staged/fingerprinted exactly like unbound_py_hsts above
$pfb['unbound_py_count']= '/var/unbound/pfb_py_count';
$pfb['unbound_py_regex_count']= '/var/unbound/pfb_py_regex_count';	// ADR-07: Python-emitted admitted feed+user regex total for the DNSBL_Regex alias
$pfb['unbound_py_reject_stats']= '/var/unbound/pfb_py_reject_stats.json';	// ADR-48: Python-emitted per-entry reject tally (issue #789), read by pfb_emit_entry_reject_stats()
$pfb['unbound_py_sources']= '/var/unbound/pfb_py_sources.json';	// ADR-06: per-feed manifest consumed by pfb_unbound.py init
$pfb['unbound_py_top1m']= '/var/unbound/pfb_py_top1m.txt';	// issue #1542: fixed TOP1M sidecar consumed by pfb_unbound.py
$pfb['unbound_py_rawdir']= '/var/unbound/pfb_py_raw';		// #1357: basename for immutable per-feed raw generations

$pfb['dnsbl_safesearch']		= '/usr/local/pkg/pfblockerng/pfb_dnsbl.safesearch.conf';
$pfb['dnsbl_youtube_restrict']		= '/usr/local/pkg/pfblockerng/pfb_dnsbl.youtube_restrict.conf';
$pfb['dnsbl_youtube_restrictmoderate']	= '/usr/local/pkg/pfblockerng/pfb_dnsbl.youtube_restrictmoderate.conf';
$pfb['dnsbl_doh']			= '/usr/local/pkg/pfblockerng/pfb_dnsbl.doh.conf';

// tmp files
$pfb['geoip_tmp']		= '/tmp/pfb_continent';
$pfb['ip_unlock']		= '/tmp/ip_unlock';

$pfb['dnsbl_tld_remove']	= '/tmp/dnsbl_tld_remove';
$pfb['dnsbl_add']		= '/tmp/dnsbl_add';
$pfb['dnsbl_add_zone']		= '/tmp/dnsbl_add_zone';
$pfb['dnsbl_add_data']		= '/tmp/dnsbl_add_data';
$pfb['dnsbl_remove']		= '/tmp/dnsbl_remove';
$pfb['dnsbl_remove_zone']	= '/tmp/dnsbl_remove_zone';
$pfb['dnsbl_remove_data']	= '/tmp/dnsbl_remove_data';
$pfb['dnsbl_unlock']		= '/tmp/dnsbl_unlock';
$pfb['states_tmp']		= '/tmp/pfb_states';

// Unbound files and folders
$pfb['dnsbl_file']	= '/var/unbound/pfb_dnsbl';	// Filename Extension not referenced
$pfb['dnsbldir']	= '/var/unbound';

// Array definitions
$pfb['continents'] = array (	'Top Spammers'		=> 'pfB_Top',
				'Africa'		=> 'pfB_Africa',
				'Antarctica'		=> 'pfB_Antarctica',
				'Asia'			=> 'pfB_Asia',
				'Europe'		=> 'pfB_Europe',
				'North America'		=> 'pfB_NAmerica',
				'Oceania'		=> 'pfB_Oceania',
				'South America'		=> 'pfB_SAmerica',
				'Proxy and Satellite'	=> 'pfB_PS'
				);

$pfb['continent_list'] = array_flip(array('pfB_Africa', 'pfB_Antarctica', 'pfB_Asia', 'pfB_Europe', 'pfB_NAmerica', 'pfB_Oceania', 'pfB_SAmerica', 'pfB_Top'));

// Base rule array
$pfb['base_rule_reg'] = array('ipprotocol' => 'inet');

// Floating rules, base rule array
$pfb['base_rule_float'] = array('quick' => 'yes', 'floating' => 'yes', 'ipprotocol' => 'inet');

// Define Arrays for managing the IP mastefile
foreach (array('existing', 'actual') as $pftype) {
	$pfb[$pftype]['match']	= array();
	$pfb[$pftype]['permit']	= array();
	$pfb[$pftype]['deny']	= array();
	$pfb[$pftype]['native']	= array();
	$pfb[$pftype]['dnsbl']	= array();
}

// issue #2658: ceilings on how much one feed may pull down and how much it may
// expand to. Real feeds are tens to low hundreds of MB, so both sit far above
// anything legitimate -- they exist to stop a pathological body or an expansion
// bomb, never to tune ingest.
define('PFB_DOWNLOAD_MAX_BYTES', 2147483648);

// ulimit(1) takes a count of blocks whose size the shell defines -- 512 bytes in
// a POSIX sh, 1024 in bash -- so the effective ceiling lands between 2 GiB and
// 4 GiB depending on which /bin/sh runs the extraction. Either reading bounds an
// expansion bomb and clears every real feed, so the ambiguity needs no resolving.
// The limit is RLIMIT_FSIZE, which the kernel applies per file.
define('PFB_EXTRACT_MAX_BLOCKS', 4194304);

// Exit status a shell reports for a child killed by SIGXFSZ (128 + 25) -- what a
// writer hitting the ceiling above produces.
define('PFB_EXTRACT_SIGXFSZ_EXIT', 153);

// issue #2659: extraction runs as root, and a disk-writing tar restores whatever
// the archive asks for. These trees are staging directories -- scraped for tokens,
// then deleted or swapped into place -- so the archive's owner, extended
// attributes, ACLs and file flags are refused outright, and its permission bits
// stop being restored exactly: the mode becomes the archive's masked by the
// extracting process's umask, with setuid/setgid/sticky dropped. The appliance's
// bsdtar accepts all six; GNU tar has no --no-fflags, so this set is for the
// appliance's tar and belongs only on the calls that create directory entries,
// never on a -xO call whose output the shell redirect owns.
define('PFB_TAR_EXTRACT_FLAGS', '--no-same-owner --no-same-permissions --numeric-owner --no-xattrs --no-acls --no-fflags');

// Default cURL options
$pfb['curl_defaults'] = array(  CURLOPT_USERAGENT	=> 'pfSense/pfBlockerNG cURL download agent-' . system_get_uniqueid(),
				CURLOPT_SSL_CIPHER_LIST	=> 'TLSv1.3, TLSv1.2',
				CURLOPT_FOLLOWLOCATION	=> TRUE,
				CURLOPT_SSL_VERIFYPEER	=> TRUE,
				CURLOPT_SSL_VERIFYHOST	=> TRUE,
				CURLOPT_FRESH_CONNECT	=> TRUE,
				CURLOPT_FILETIME	=> TRUE,
				CURLOPT_TCP_NODELAY	=> TRUE,
				CURLOPT_CONNECTTIMEOUT	=> 15,
				CURLOPT_AUTOREFERER	=> TRUE,
				CURLOPT_MAXREDIRS	=> 10,
				CURLOPT_HTTP_VERSION	=> CURL_HTTP_VERSION_NONE,
				CURLOPT_FORBID_REUSE	=> TRUE,
				CURLOPT_SSL_ENABLE_ALPN	=> TRUE,
				CURLOPT_SSL_ENABLE_NPN	=> TRUE,
				// issue #2634: no Accept-Encoding is offered -- a decoded body breaks both the
				// ADR-42 raw-byte digest and MIME dispatch (architecture-notes, "Transfer
				// encoding").
				// Constrain libcurl to the schemes pfBlockerNG fetches feeds over (http/https/ftp;
				// rsync uses exec separately) — an independent backstop to the PFB_FILTER_URL scheme
				// allowlist, since PHP parse_url and libcurl can disagree on crafted input.
				CURLOPT_PROTOCOLS	=> CURLPROTO_HTTP | CURLPROTO_HTTPS | CURLPROTO_FTP,
				// issue #2658: refuse an over-large body at the transport instead of writing
				// it to disk in full. The _LARGE variant keeps the cap free of the 2 GiB
				// ceiling a plain long imposes. Enforcement depends on the appliance's
				// libcurl (a declared Content-Length is refused before any body arrives;
				// mid-transfer enforcement is version-dependent), so the extraction
				// ceiling below is the backstop that depends on nothing.
				CURLOPT_MAXFILESIZE_LARGE => PFB_DOWNLOAD_MAX_BYTES,
				);

// RFC7231 HTTP response codes
$pfb['rfc7231'] = array(
			1 => 'Unsupported Protocol',		2 => 'Early Initilization failed',		3 => 'Malformed URL',
			4 => 'Requested feature not found',	5 => 'Could not Resolve Proxy',			6 => 'Could not Resolve Host',
			7 => 'Failed to connect',		8 => 'Failed to parse data',			9 => 'Denied access',
			10 => 'FTP failed',			11 => 'FTP password failure',			12 => 'FTP Accept timeout',
			13 => 'FTP PASV failure',		14 => 'FTP 227 Format failure',			15 => 'FTP Host lookup failure',
			16 => 'HTTP2 framing layer failure',	17 => 'FTP Could not set transfer mode',	18 => 'File Transfer failure',
			19 => 'FTP weird reply',		20 => 'Obsolete error',				21 => 'FTP quote command error',
			22 => 'HTTP Returned Error code',	23 => 'Write Error',				24 => 'Obsolete error',
			25 => 'FTP failted starting upload',	26 => 'Read Error',				27 => 'Memory allocation request error',
			28 => 'Operation timed out',		29 => 'Obsolete error',				30 => 'FTP Port command failure',
			31 => 'FTP REST failure',		32 => 'Obsolete error',				33 => 'Range Request failure',
			34 => 'HTTP Post error',		35 => 'SSL Connect error',			37 => 'Could not read file',
			38 => 'LDAP Cannot bind',		39 => 'LDAP Search failed',			40 => 'Obsolete error',
			41 => 'Function not found',		42 => 'Aborted by callback',			43 => 'Bad parameter',
			44 => 'Obsolete error',			45 => 'Interface failure',			46 => 'Obsolete error',
			47 => 'Too many redirects',		48 => 'Unknown option',				49 => 'Setopt Syntax error',
			50 => 'Obsolete error',			51 => 'Obsolete error',				52 => 'Curl got nothing',
			53 => 'SSL Engine not found',		54 => 'SSL Engine failure',			55 => 'Failed sending data',
			56 => 'Failure receving data',		57 => 'Obsolete error',				58 => 'Local client certificate error',
			59 => 'Cipher error',			60 => 'SSL certificate error',			61 => 'Transfer encoding error',
			62 => 'Obsolete error',			63 => 'Maximum file size exceeded',		64 => 'FTP SSL level failure',
			65 => 'Rewinding operation failed',	66 => 'SSL Engine failure',			67 => 'Login Denied',
			68 => 'TFTP server not found',		69 => 'TFTP permission error',			70 => 'Out of disk space on server',
			71 => 'Illegal TFTP operation',		72 => 'Unknown TFTP transfer ID',		73 => 'File already exists',
			74 => 'TFTP no such user',		75 => 'Obsolete error',				76 => 'Obsolete error',
			77 => 'SSL CA certificate error',	78 => 'Remote file not found',			79 => 'SSH connection failure',
			80 => 'SSH connection failure',		81 => 'Socket is not ready',			82 => 'CRL Bad File error',
			83 => 'SSL Issurer failure',		84 => 'FTP PRET failure',			85 => 'RTSP CSeq number error',
			86 => 'RTSP Session mismatch',		87 => 'FTP Bad file list',			88 => 'Chunk callback error',
			89 => 'No connection available',	90 => 'Pin Key match failure',			91 => 'Invalid Certificate status',
			92 => 'HTTP/2 framing error',		93 => 'Recursive API call error',		94 => 'Authentication function error',
			95 => 'HTTP/3 layer error',
			96 => 'QUIC connect error',		97 => 'Proxy handshake error',			98 => 'SSL Client certificate required',
			99 => 'Unrecoveranle Poll error',

			100 => '100 Continue',			101 => '101 Switching Protocols',		102 => '102 Processing',

			200 => '200 OK',			201 => '201 Created',				202 => '202 Accepted',
			203 => '203 Non-Authoritative Info',	204 => '204 No Content',			205 => '205 Reset Content',
			206 => '206 Partial Content',		207 => '207 Multi-Status',			208 => '208 Already Reported',
			226 => '226 IM Used',

			300 => '300 Multiple Choices',		301 => '301 Moved Permanently',			302 => '302 Found',
			303 => '303 See Other',			304 => '304 Not Modified',			305 => '305 Use Proxy',
			306 => '306 Switch Proxy',		307 => '307 Temporary Redirect',		308 => '308 Permanent Redirect',

			400 => '400 Bad Request',		401 => '401 Unauthorized',			402 => '402 Payment Required',
			403 => '403 Forbidden',			404 => '404 Not Found',				405 => '405 Method Not Allowed',
			406 => '406 Not Acceptable',		407 => '407 Proxy Authentication Required',	408 => '408 Request Timeout',
			409 => '409 Conflict',			410 => '410 Gone',				411 => '411 Length Required',
			412 => '412 Precondition Failed',	413 => '413 Request Entity Too Large',		414 => '414 Request-URI Too Long',
			415 => '415 Unsupported Media Type',	416 => '416 Requested Range Not Satisfiable',	417 => '417 Expectation Failed',
			418 => '418 Im a teapot',		419 => '419 Authentication Timeout',		420 => '420 Method Failure',
			421 => '421 Misdirected Request',	422 => '422 Unprocessable Entity',		423 => '423 Locked',
			424 => '424 Failed Dependency',		426 => '426 Upgrade Required',			428 => '428 Precondition Required',
			429 => '429 Too Many Requests',		431 => '431 Request Header Fields Large',	440 => '440 Login Timeout',
			444 => '444 No Response',		449 => '449 Retry With',			450 => '450 Blocked Windows Parental Controls',
			451 => '451 Unavailable Legal Reasons',	494 => '494 Request Header too Large',		495 => '495 Cert Error',
			496 => '496 No Cert',			497 => '497 HTTP to HTTPS',			498 => '498 Token expired/invalid',
			499 => '499 Client Closed Request',

			500 => '500 Internal Server Error',	501 => '501 Not Implemented',			502 => '502 Bad Gateway',
			503 => '503 Service Unavailable',	504 => '504 Gateway Timeout',			505 => '505 HTTP Version Not Supported',
			506 => '506 Variant Also Negotiates',	507 => '507 Insufficient Storage',		508 => '508 Loop Detected',
			509 => '509 Bandwidth Limit Exceeded',	510 => '510 Not Extended',			511 => '511 Network Authentication Required',
			521 => '521 Web Server is down',	598 => '598 Network read timeout error',	599 => '599 Network connect timeout error',

			520 => 'CF 520 Unknown Error',		522 => 'CF 522 Connection Timed Out',
			523 => 'CF 523 Origin is Unreachable',	524 => 'CF 524 A Timeout Occured',		525 => 'CF 525 SSL Handshake Failed',
			526 => 'CF 526 Invalid SSL Certificate',527 => 'CF 527 Railgun Error'
			);

// File download Mime-Types
$pfb['mime_types'] = array_flip(array(	'inode/x-empty',
					'text/x-file',
					'text/plain',
					'text/html',
					'text/xml',
					'text/csv',
					'application/csv',
					'application/json',
					'application/x-ndjson',
					'application/gzip',
					'application/x-gzip',
					'application/x-bzip2',
					'application/zip',
					'application/x-tar'));

// pfb_filter constants
define('PFB_FILTER_HTML', 1);
define('PFB_FILTER_URL', 2);
define('PFB_FILTER_WORD', 3);
define('PFB_FILTER_WORD_DOT', 4);
define('PFB_FILTER_TLD', 5);
define('PFB_FILTER_DOMAIN', 6);
define('PFB_FILTER_HOSTNAME', 7);
define('PFB_FILTER_IPV4', 8);
define('PFB_FILTER_IP', 9);
define('PFB_FILTER_ALPHA', 10);
define('PFB_FILTER_ALNUM', 11);
define('PFB_FILTER_NUM', 12);
define('PFB_FILTER_CSV', 13);
define('PFB_FILTER_CSV_WHOIS', 14);
define('PFB_FILTER_CSV_CRON', 15);
define('PFB_FILTER_FILE_MIME_COMPARE', 16);
define('PFB_FILTER_FILE_MIME', 17);
define('PFB_FILTER_FILE_MIME_COMPRESSED', 18);
define('PFB_FILTER_ATYPE', 19);
define('PFB_FILTER_HEX_COLOR', 20);
define('PFB_FILTER_ON_OFF', 21);
define('PFB_FILTER_TOKEN', 22);

// Maximum number of HTTP redirects pfb_download() follows manually (each hop's
// host is re-vetted by the feed-host guard before it is dialled). Matches the
// previous cURL CURLOPT_MAXREDIRS auto-follow cap.
define('PFB_DOWNLOAD_MAXREDIRS', 10);

// Machine-detectable markers (the VIP 'descr') stamped on DNSBL sinkhole VIPs that
// pfBlockerNG auto-creates and therefore owns (ADR-13). ONLY VIPs carrying one of
// these markers are ever managed/deleted by the package; a manually-created VIP is
// never touched. Single source of truth for the ownership marker.
define('PFB_AUTO_VIP_DESCR_V4', 'pfB_AUTO_VIP_v4');
define('PFB_AUTO_VIP_DESCR_V6', 'pfB_AUTO_VIP_v6');

// Firewall-object ownership/marker constants.
// Filter-rule prefix: any rule descr that starts with this prefix is owned by pfBlockerNG.
define('PFB_MANAGED_FILTER_PFX', 'pfB_');
// Full NAT rule description written by pfBlockerNG for DNSBL.
define('PFB_MANAGED_NAT_DESCR', 'pfB DNSBL - DO NOT EDIT');
// Legacy NAT prefix: any descr containing this prefix is owned (covers bare 'pfB DNSBL'
// and any variant suffixed with extra text, e.g. the ' - DO NOT EDIT' form above).
define('PFB_MANAGED_NAT_LEGACY_PFX', 'pfB DNSBL');

// NAT rdr rule descr prefix for inet (IPv4) DNS-redirect rules.
// Pattern: pfB_DNS_Redirect_<iface>_v4
define('PFB_DNS_REDIR_DESCR_V4_PFX', 'pfB_DNS_Redirect_');
// Suffix for inet (IPv4) DNS-redirect descr markers.
define('PFB_DNS_REDIR_DESCR_V4_SFX', '_v4');
// Suffix for inet6 (IPv6) DNS-redirect descr markers.
define('PFB_DNS_REDIR_DESCR_V6_SFX', '_v6');
// Descr prefix for DoT/DoQ block filter rules. Pattern: pfB_DoT_Block_<iface>
define('PFB_DOT_BLOCK_DESCR_PFX', 'pfB_DoT_Block_');
// Descr marker for the single floating DoT/DoQ block rule (floating mode). Carries the
// shared prefix so the disable/uninstall sweep removes it like the per-interface rules.
// 'Floating' is never a real (WAN-excluded) interface key, so it cannot collide with a
// per-interface marker.
define('PFB_DOT_BLOCK_FLOATING_DESCR', PFB_DOT_BLOCK_DESCR_PFX . 'Floating');

// Returns TRUE iff $descr indicates pfBlockerNG ownership.
// Recognised patterns (UNION — any one match → owned):
//   • str_starts_with($descr, 'pfB_')    — new prefix (covers PFB_AUTO_VIP_DESCR_V4/V6)
//   • str_contains($descr, 'pfB DNSBL') — legacy NAT marker
function pfb_is_managed_obj(string $descr): bool {
	if ($descr === '') {
		return FALSE;
	}
	if (str_starts_with($descr, PFB_MANAGED_FILTER_PFX)) {
		return TRUE;
	}
	if (str_contains($descr, PFB_MANAGED_NAT_LEGACY_PFX)) {
		return TRUE;
	}
	return FALSE;
}

// Reads config_get_path($section, []) and returns the FIRST row whose 'descr'
// satisfies pfb_is_managed_obj() AND matches $marker:
//   • If $marker starts with PFB_MANAGED_FILTER_PFX ('pfB_'): str_starts_with match.
//   • Otherwise: str_contains match.
// If $guard is provided it is called with the candidate row and must return TRUE to accept.
// Returns the matching row array, or FALSE if no row matches.
function pfb_find_managed_obj(string $section, string $marker, ?callable $guard = NULL): array|false {
	$use_prefix = str_starts_with($marker, PFB_MANAGED_FILTER_PFX);
	foreach (config_get_path($section, []) as $row) {
		$descr = $row['descr'] ?? '';
		if (!pfb_is_managed_obj($descr)) {
			continue;
		}
		if ($use_prefix) {
			if (!str_starts_with($descr, $marker)) {
				continue;
			}
		} else {
			if (!str_contains($descr, $marker)) {
				continue;
			}
		}
		if ($guard !== NULL && !$guard($row)) {
			continue;
		}
		return $row;
	}
	return FALSE;
}

// Reads config_get_path($section, []), filters OUT every owned row matching $marker.
// Any row that fails the ownership check is NEVER removed — user-safety invariant.
// When at least one row was removed the filtered array is written back via config_set_path().
// Returns TRUE if at least one row was removed, FALSE if nothing matched.
function pfb_remove_managed_obj(string $section, string $marker, ?callable $guard = NULL): bool {
	$use_prefix = str_starts_with($marker, PFB_MANAGED_FILTER_PFX);
	$rows       = config_get_path($section, []);
	$filtered   = [];
	$removed    = FALSE;
	foreach ($rows as $row) {
		$descr = $row['descr'] ?? '';
		if (!pfb_is_managed_obj($descr)) {
			$filtered[] = $row;
			continue;
		}
		$marker_match = $use_prefix
			? str_starts_with($descr, $marker)
			: str_contains($descr, $marker);
		if (!$marker_match) {
			$filtered[] = $row;
			continue;
		}
		if ($guard !== NULL && !$guard($row)) {
			$filtered[] = $row;
			continue;
		}
		$removed = TRUE;
	}
	if ($removed) {
		config_set_path($section, $filtered);
	}
	return $removed;
}

// Shared interface-allowlist + exception-alias validation for the DNSBL settings POST
// forms — DNS Redirect and DoT/DoQ Block apply identical rules, differing only in the
// $label prefix on each error message.
// Returns an array of validation error messages (empty = all inputs valid).
function pfb_validate_redirect_exclude_alias(
	string $label,
	array $posted_ifaces,
	array $valid_iface_list,
	string $posted_alias
): array {
	$errors = [];
	foreach ($posted_ifaces as $iface) {
		if (!in_array($iface, $valid_iface_list, TRUE)) {
			$errors[] = "{$label}: Invalid interface selection: " .
				htmlspecialchars((string) $iface, ENT_QUOTES);
		}
	}
	if ($posted_alias !== '') {
		if (!is_validaliasname($posted_alias)) {
			$errors[] = "{$label}: Invalid exception alias name: " .
				htmlspecialchars($posted_alias, ENT_QUOTES);
		} elseif (str_starts_with($posted_alias, PFB_MANAGED_FILTER_PFX)) {
			$errors[] = "{$label}: Exception alias must not be a pfBlockerNG-managed (" .
				PFB_MANAGED_FILTER_PFX . '*) alias: ' . htmlspecialchars($posted_alias, ENT_QUOTES);
		} elseif (pfb_alias_type($posted_alias) === NULL) {
			$errors[] = "{$label}: Exception alias does not exist: " .
				htmlspecialchars($posted_alias, ENT_QUOTES) .
				' (create it under Firewall > Aliases first)';
		} elseif (!pfb_exclude_alias_exists($posted_alias)) {
			$errors[] = "{$label}: Exception alias must be an address alias usable in " .
				'firewall rules (port aliases are not allowed): ' . htmlspecialchars($posted_alias, ENT_QUOTES);
		}
	}
	return $errors;
}

// Validate the DNS-redirect fields submitted via the DNSBL settings POST form.
// Each interface name is checked against the allow-list; the exception alias is
// validated by is_validaliasname() when non-empty.
// Returns an array of validation error messages (empty = all inputs valid).
function pfb_validate_dns_redirect_post(
	array $posted_ifaces,
	array $valid_iface_list,
	string $posted_alias
): array {
	return pfb_validate_redirect_exclude_alias('DNS Redirect', $posted_ifaces, $valid_iface_list, $posted_alias);
}

// The two valid dispositions for a DoT/DoQ block rule. 'reject' is the default
// (an outbound LAN->WAN block, so Reject fast-fails the client to plain DNS rather
// than letting the encrypted-DNS connection hang); 'block' silently drops. Mirrors
// the inbound/outbound Rule Action selector on the IP settings page.
define('PFB_DOT_BLOCK_ACTION_DEFAULT', 'reject');

// Normalise a stored/posted DoT/DoQ-block action to one of the two valid
// dispositions. Any unknown/empty value falls back to the default ('reject').
function pfb_dot_block_action(string $action): string {
	return ($action === 'block') ? 'block' : PFB_DOT_BLOCK_ACTION_DEFAULT;
}

// Validate the DoT/DoQ-block fields submitted via the DNSBL settings POST form.
// Each interface name is checked against the allow-list; the exception alias is
// validated by is_validaliasname() when non-empty; the rule action must be one of
// the two known dispositions ('block' | 'reject').
// Returns an array of validation error messages (empty = all inputs valid).
function pfb_validate_dot_block_post(
	array $posted_ifaces,
	array $valid_iface_list,
	string $posted_alias,
	string $posted_action = PFB_DOT_BLOCK_ACTION_DEFAULT
): array {
	$errors = pfb_validate_redirect_exclude_alias('DoT/DoQ Block', $posted_ifaces, $valid_iface_list, $posted_alias);
	if (!in_array($posted_action, ['block', 'reject'], TRUE)) {
		$errors[] = 'DoT/DoQ Block: Invalid rule action: ' .
			htmlspecialchars($posted_action, ENT_QUOTES);
	}
	return $errors;
}

// Alias types usable as a firewall-rule SOURCE (an address-bearing alias) — and therefore
// valid as a DNS-redirect/DoT exception. Covers the four address types: 'host', 'network',
// 'url' (URL of IPs/hosts) and 'urltable' (URL Table of IPs). Port aliases ('port',
// 'url_ports', 'urltable_ports') are excluded: a port alias cannot be a rule source. Single
// source of truth for the save-time validators, the rule builder, and the Exception-Alias
// autocomplete (pfblockerng_dnsbl.php).
function pfb_exclude_alias_types(): array {
	return ['host', 'network', 'url', 'urltable'];
}

// Port-bearing firewall alias types, valid for the Adv. In/Outbound Custom Port field --
// the port-side counterpart to pfb_exclude_alias_types(): a 'port' alias plus the two
// port-list types.
function pfb_port_alias_types(): array {
	return ['port', 'url_ports', 'urltable_ports'];
}

// Alias-name maps for the Adv. In/Outbound autocomplete + save-time option validation on the
// IP/DNSBL/Feed pages. NAME-KEYED so a save-time array_key_exists($posted, $options) works.
// Ports: pfb_port_alias_types(). Addresses: pfb_exclude_alias_types() (host/network/url/
// urltable, so a single-IP Host alias autocompletes/saves too). pfB_-managed aliases are
// skipped from both — forbidden by field help and not valid user rule sources.
//
// @param array $aliases The config_get_path('aliases/alias', []) list.
// @return array{ports: array<string,string>, networks: array<string,string>}
function pfb_alias_autocomplete_lists(array $aliases): array {
	$ports    = [];
	$networks = [];
	foreach ($aliases as $alias) {
		$name = (string) ($alias['name'] ?? '');
		// Skip empty names and pfB_-managed aliases (forbidden in both fields).
		if ($name === '' || str_starts_with($name, PFB_MANAGED_FILTER_PFX)) {
			continue;
		}
		$type = (string) ($alias['type'] ?? '');
		if (in_array($type, pfb_port_alias_types(), TRUE)) {
			$ports[$name] = $name;
		} elseif (in_array($type, pfb_exclude_alias_types(), TRUE)) {
			$networks[$name] = $name;
		}
	}
	return ['ports' => $ports, 'networks' => $networks];
}

// Return the configured type of the firewall alias named $alias ('host'|'network'|'urltable'|
// 'port'|…), or NULL when no alias by that name exists. Reads the configuration directly,
// which is correct in EVERY context — unlike is_alias(), which consults the in-memory
// $aliastable cache that alias_make_table() only populates during filter generation, so in a
// cron/service-restart sync (e.g. the DNSBL reload) that cache is empty and is_alias() reports
// every user-defined alias as missing (#664). Config is the authoritative source the cache is
// derived from, and the same source the Exception-Alias autocomplete and the rest of the
// package use.
function pfb_alias_type(string $alias): ?string {
	if ($alias === '') {
		return NULL;
	}
	foreach (config_get_path('aliases/alias', []) as $pfb_cfg_alias) {
		if (($pfb_cfg_alias['name'] ?? '') === $alias) {
			return (string) ($pfb_cfg_alias['type'] ?? '');
		}
	}
	return NULL;
}

// TRUE iff $alias is a configured alias usable as a DNS-redirect/DoT exception source: it
// exists, is an address-bearing type (not a port alias), and is NOT a pfBlockerNG-managed
// (pfB_*) alias. Enforced here — not only in the save-time validators — so a stale or
// hand-edited config that references a port/managed alias still falls back safely at
// rule-build time rather than emitting a bad rule.
function pfb_exclude_alias_exists(string $alias): bool {
	if (str_starts_with($alias, PFB_MANAGED_FILTER_PFX)) {
		return FALSE;
	}
	$type = pfb_alias_type($alias);
	return $type !== NULL && in_array($type, pfb_exclude_alias_types(), TRUE);
}

// Build the NAT/filter SOURCE array for a DNS-redirect/DoT-block exception alias. Empty alias
// -> source 'any'. Non-empty alias -> negated source ONLY when it resolves to a usable,
// non-pfB_ address alias; otherwise falls back to 'any' (logged) — a non-resolving alias must
// never reach a sourceless "from ! ..." rule, which pf rejects and fails the WHOLE ruleset load.
// Shared by pfb_dot_block_rule(), pfb_dot_block_floating_rule(), and the DNS-redirect NAT
// builder. $context names the rule so the log identifies WHICH rule dropped its exception (#664).
function pfb_redirect_exclude_source(string $alias, string $context = ''): array {
	if ($alias === '') {
		return ['any' => ''];
	}
	if (!pfb_exclude_alias_exists($alias)) {
		$where = ($context !== '') ? " [ {$context} ]" : '';
		pfb_logger("\nDNS redirect/DoT block{$where}: exception alias [ " .
			substr(htmlspecialchars($alias), 0, 100) . " ] not usable — ignoring (no exception applied)", 2);
		return ['any' => ''];
	}
	return ['address' => $alias, 'not' => ''];
}

// Build a single DoT/DoQ block filter/rule array for $iface. $action is the rule
// disposition ('block' | 'reject'); any other value falls back to the default
// (Reject) via pfb_dot_block_action(). When $exclude_alias is non-empty it becomes a
// negated source so listed hosts bypass the block; empty -> source 'any'. The
// destination is always the firewall itself ('(self)') on port 853, negated so the
// box's own resolver is exempt. The caller assigns the 'tracker' (last key) after
// build, preserving the stored key order so the sync change-detection compare stays
// stable when nothing changed.
function pfb_dot_block_rule(string $iface, string $exclude_alias, string $action): array {
	$source = pfb_redirect_exclude_source($exclude_alias, "DoT/DoQ Block on {$iface}");

	return [
		'type'        => pfb_dot_block_action($action),
		'interface'   => $iface,
		'ipprotocol'  => 'inet46',
		'protocol'    => 'tcp/udp',
		'source'      => $source,
		'destination' => ['network' => '(self)', 'not' => '', 'port' => '853'],
		'statetype'   => 'keep state',
		'descr'       => PFB_DOT_BLOCK_DESCR_PFX . $iface,
	];
}

// Build the SINGLE floating DoT/DoQ block filter/rule covering all selected $ifaces in
// one rule (floating mode), instead of one rule per interface. $action is the disposition
// ('block' | 'reject', default Reject via pfb_dot_block_action()). The rule is floating +
// quick with direction 'in' (matches client egress entering the firewall on the selected
// interfaces — the direction ADR-37 mandates for a floating variant) and carries the same
// negated-(self):853 destination + optional exception-alias source as the per-interface
// rule. The caller appends the 'tracker' (last key) after build.
function pfb_dot_block_floating_rule(array $ifaces, string $exclude_alias, string $action): array {
	$source = pfb_redirect_exclude_source($exclude_alias, 'DoT/DoQ Block (floating)');

	return [
		'type'        => pfb_dot_block_action($action),
		'interface'   => implode(',', $ifaces),
		'floating'    => 'yes',
		'quick'       => 'yes',
		'direction'   => 'in',
		'ipprotocol'  => 'inet46',
		'protocol'    => 'tcp/udp',
		'source'      => $source,
		'destination' => ['network' => '(self)', 'not' => '', 'port' => '853'],
		'statetype'   => 'keep state',
		'descr'       => PFB_DOT_BLOCK_FLOATING_DESCR,
	];
}

// Allowlist the alias-type suffix ($vtype) before it is interpolated into an
// alias name or filesystem path. The only legitimate values are '_v4' and '_v6';
// any other value is rejected so a stray/unexpected suffix can never reach a
// path/alias build. Returns TRUE only for an exact-match allowed suffix.
function pfb_valid_vtype($vtype) {
	return ($vtype === '_v4' || $vtype === '_v6');
}

/** Validate the General-page quarter-hour schedule and optional apply window. */
function pfb_general_schedule_validate(array $post): array
{
	$errors = [];
	$values = [];
	$scalar_set = static function (string $key, array $allowed, string $label) use (&$errors, &$values, $post): void {
		$value = $post[$key] ?? NULL;
		if ($value === NULL) {
			$errors[] = "{$label} is required.";
			return;
		}
		if (!is_string($value) || !in_array($value, $allowed, TRUE)) {
			$errors[] = "{$label} is invalid.";
			return;
		}
		$values[$key] = $value;
	};

	$scheduled = $post['pfb_scheduled_feed_updates'] ?? '';
	if (is_array($scheduled) || !in_array($scheduled, ['', 'on'], TRUE)) {
		$errors[] = 'Scheduled Feed Updates is invalid.';
	} else {
		$values['pfb_scheduled_feed_updates'] = $scheduled;
	}
	$scalar_set('pfb_schedule_weekday', ['1', '2', '3', '4', '5', '6', '7'], 'Schedule weekday');
	$scalar_set('pfb_schedule_hour', array_map('strval', range(0, 23)), 'Schedule hour');
	$scalar_set('pfb_schedule_minute', ['0', '15', '30', '45'], 'Schedule minute');

	$window_enabled = $post['pfb_quiet_hours_enabled'] ?? '';
	if (is_array($window_enabled) || !in_array($window_enabled, ['', 'on'], TRUE)) {
		$errors[] = 'Automatic Apply Window is invalid.';
		$window_enabled = '';
	}
	if ($window_enabled === 'on') {
		$start = $post['pfb_quiet_hours_start'] ?? NULL;
		$end = $post['pfb_quiet_hours_end'] ?? NULL;
		$time_valid = static function (mixed $value): bool {
			return is_string($value) && preg_match('/^(?:[01][0-9]|2[0-3]):(?:00|15|30|45)$/D', $value) === 1;
		};
		if (!$time_valid($start) || !$time_valid($end)) {
			$errors[] = 'Automatic Apply Window endpoints must be quarter-hour times.';
		} elseif ($start === $end) {
			$errors[] = 'Automatic Apply Window endpoints must differ.';
		} else {
			$values['pfb_quiet_hours'] = $start . '-' . $end;
		}
	} else {
		$values['pfb_quiet_hours'] = '';
	}

	return ['errors' => $errors, 'values' => $errors === [] ? $values : []];
}

/** Validate and canonicalize a feed-group schedule override before config save. */
function pfb_category_schedule_validate(
	array $post,
	array $stored,
	array $general,
	string $cadence,
	string $action,
	bool $has_active_rows
): array {
	$errors = [];
	$values = [];
	$token = static function (mixed $value, int $min, int $max): ?string {
		if (!is_string($value) || !preg_match('/^(?:0|[1-9][0-9]*)$/D', $value)) {
			return NULL;
		}
		$number = (int) $value;
		return $number >= $min && $number <= $max ? $value : NULL;
	};
	$minute = static function (mixed $value) use ($token): ?string {
		$value = $token($value, 0, 45);
		return $value !== NULL && in_array($value, ['0', '15', '30', '45'], TRUE) ? $value : NULL;
	};
	$general_weekday = $token($general['pfb_schedule_weekday'] ?? NULL, 1, 7) ?? '7';
	$general_hour = $token($general['pfb_schedule_hour'] ?? NULL, 0, 23) ?? '0';
	$general_minute = $minute($general['pfb_schedule_minute'] ?? NULL) ?? '0';
	$stored_weekday = $token($stored['schedule_weekday'] ?? NULL, 1, 7) ?? $general_weekday;
	$stored_hour = $token($stored['schedule_hour'] ?? NULL, 0, 23) ?? $general_hour;
	$stored_minute = $minute($stored['schedule_minute'] ?? NULL) ?? $general_minute;
	$override = $post['schedule_override'] ?? '';
	if (!is_string($override)) {
		$errors[] = 'Override Default Schedule is invalid.';
		$override = '';
	} elseif (!in_array($override, ['', 'on'], TRUE)) {
		$errors[] = 'Override Default Schedule is invalid.';
		$override = '';
	}
	$strict_inputs = !is_string($post['schedule_override'] ?? NULL)
		|| !in_array($post['schedule_override'] ?? NULL, ['', 'on'], TRUE)
		|| $override === 'on';
	$active = $has_active_rows && $action !== 'Disabled' && $cadence !== 'Never';
	foreach (['schedule_weekday', 'schedule_hour', 'schedule_minute'] as $key) {
		if (array_key_exists($key, $post) && is_array($post[$key])) {
			$errors[] = ucfirst(str_replace('_', ' ', $key)) . ' is invalid.';
		} elseif ($strict_inputs && array_key_exists($key, $post)) {
			$valid = $key === 'schedule_weekday'
				? $token($post[$key], 1, 7)
				: ($key === 'schedule_hour' ? $token($post[$key], 0, 23) : $minute($post[$key]));
			if ($valid === NULL) {
				$errors[] = ucfirst(str_replace('_', ' ', $key)) . ' is invalid.';
			}
		}
	}
	$values = [
		'schedule_override' => $override,
		'schedule_weekday' => $stored_weekday,
		'schedule_hour' => $stored_hour,
		'schedule_minute' => $stored_minute,
	];
	if ($override === '') {
		return ['errors' => $errors, 'values' => $errors === [] ? $values : []];
	}
	$weekday = $token($post['schedule_weekday'] ?? NULL, 1, 7);
	$hour = $token($post['schedule_hour'] ?? NULL, 0, 23);
	$minute_value = $minute($post['schedule_minute'] ?? NULL);
	if ($cadence === 'Weekly' && ($weekday === NULL || $hour === NULL || $minute_value === NULL)) {
		$errors[] = 'Weekly schedule requires a valid weekday, hour, and minute.';
	} elseif ($active && $cadence === '01hour' && $minute_value === NULL) {
		$errors[] = 'Hourly schedule requires a valid minute.';
	} elseif ($active && $cadence !== 'Weekly' && $cadence !== '01hour'
		&& ($hour === NULL || $minute_value === NULL)) {
		$errors[] = 'Schedule requires a valid hour and minute.';
	} elseif (!$active) {
		$weekday ??= $stored_weekday;
		$hour ??= $stored_hour;
		$minute_value ??= $stored_minute;
	}
	if ($errors !== []) {
		return ['errors' => $errors, 'values' => []];
	}
	$values['schedule_hour'] = $hour ?? $stored_hour;
	$values['schedule_minute'] = $minute_value ?? $stored_minute;
	$values['schedule_weekday'] = $weekday ?? $stored_weekday;
	if ($cadence === '01hour') {
		$values['schedule_hour'] = $stored_hour;
	}
	return ['errors' => [], 'values' => $values];
}

// DNSBL-IP is an IP group even though its setting lives on the DNSBL page.
// Invalid persisted/HA values fail closed before any autorule, path, or alias use.
function pfb_dnsblip_action_value(mixed $action): string {
	return pfb_group_action_valid($action, 'ipv4') ? (string) $action : 'Disabled';
}

// Reformat a stored timestamp string to ISO 8601 'YYYY-MM-DD HH:MM:SS' for display.
// Accepts any date string parseable by strtotime() (e.g. the DNSBL SQLite timestamp
// written as 'M j H:i:s' — 'Nov 31 14:30:45'). An already-ISO value round-trips
// unchanged. An unparseable or empty value is returned as-is so callers never see
// a garbled '1970-01-01 00:00:00' placeholder.
function pfb_iso_timestamp(string $raw): string {
	if ($raw === '') {
		return $raw;
	}
	$epoch = strtotime($raw);
	if ($epoch === FALSE) {
		return $raw;
	}
	return date('Y-m-d H:i:s', $epoch);
}

// Returns TRUE only for a legacy bare pfB_ alias on an IPv4-family rule that
// still needs the '_v4' suffix appended. Addresses already ending in '_v4' or
// '_v6' are left alone (the '_v6' skip mirrors the NAT-rule upgrade path and
// fixes issue #360: a 'pfB_*_v6' alias must never become 'pfB_*_v6_v4').
function pfb_rule_alias_needs_v4_suffix($address, $ipprotocol) {
	return str_starts_with((string) $address, 'pfB_') &&
	       !str_ends_with((string) $address, '_v4') &&
	       !str_ends_with((string) $address, '_v6') &&
	       $ipprotocol === 'inet';
}

// Collect the auto-rule suffix already in use by an existing pfB_ firewall rule (issue #713).
// Scans $rules for the FIRST rule whose descr matches 'pfB_<Type><suffix>'; when found, reports
// existence ('found') and extracts 'suffix' so the caller preserves it instead of re-applying
// the configured suffix over already-deployed rules. PURE — no I/O, no globals, no side effects.
//
// @param array<int, array<string, mixed>> $rules  config 'filter/rule' entries.
// @return array{found: bool, suffix: string}
function pfb_collect_autorule_suffix(array $rules): array {
	$found  = FALSE;
	$suffix = '';

	foreach ($rules as $rule) {
		if (empty($suffix) && preg_match('/^pfB_\w+(\s.*)/', $rule['descr'] ?? '', $match)) {
			$found  = TRUE;
			$suffix = $match[1];
		}
	}

	return ['found' => $found, 'suffix' => $suffix];
}

// Validate/normalise the Reports-tab whitelist composite 'atype' param ('Whitelist|<ip>|
// <description>'). IP validated via PFB_FILTER_IP; an invalid IP yields an empty slot that the
// addgroup block surfaces as a user error. Description: control chars/newlines collapsed to a
// space (blocks line injection into the base64-stored custom list); NOT HTML-encoded here —
// each display sink escapes on output. Split limit 3 preserves '|' inside the description; a
// non-'Whitelist' first token is rejected (returns '').
function pfb_filter_whitelist_atype(string $raw): string {
	$parts = explode('|', $raw, 3);
	if (($parts[0] ?? '') !== 'Whitelist') {
		return '';
	}
	$ip    = isset($parts[1]) ? pfb_filter($parts[1], PFB_FILTER_IP, 'Category_edit') : '';
	$descr = isset($parts[2]) ? trim(preg_replace('/[\x00-\x1f\x7f]+/', ' ', (string) $parts[2])) : '';
	return "Whitelist|{$ip}|{$descr}";
}

// Normalise an XMLRPC sync password for storage. The password is a secret
// credential sent to the replication peer for authentication; it is never
// rendered as raw HTML (the Sync form's Form_Input escapes the value attribute
// for display via Form_Element). It is therefore stored VERBATIM — HTML-encoding
// it on save corrupted any password containing & " ' < > (the escaped form was
// sent to the peer, so authentication failed and repeated attempts tripped
// sshguard). Storage is frozen as the literal secret; escaping is an output concern.
function pfb_sync_filter_password(string $value): string {
	return $value;
}

// Pure allow-list membership test for a MIME-type string. Encapsulates the
// isset($pfb['mime_types'][...]) lookup used by the PFB_FILTER_FILE_MIME (17) and
// PFB_FILTER_FILE_MIME_COMPRESSED (18) branches as a single insertion point.
function pfb_mime_in_allowlist(string $mime, array $allowlist): bool {
	return isset($allowlist[$mime]);
}

// ADR-44: canonicalise known archive MIME variant strings before the allow-list
// gate. Pure: string in -> string out. The stripos('zip') catch-all rewrites any
// non-gzip/bzip string containing "zip" (e.g. application/epub+zip) to
// application/zip; it does not promote unrelated types like application/octet-stream.
function pfb_mime_normalise(string $raw): string {
	// Exact-match canonicalisations first (so x-gzip maps to gzip, NOT zip).
	switch ($raw) {
		case 'application/x-zip-compressed':
		case 'application/x-zip':
			return 'application/zip';
		case 'application/x-gzip':
			return 'application/gzip';
	}
	// Generic catch-all for other ZIP-creator variant strings — but the literal
	// substring "zip" also lives inside "gzip"/"bzip2", which are distinct valid
	// archive types that MUST pass through unchanged. Exclude them explicitly.
	if (stripos($raw, 'zip') !== FALSE
	    && stripos($raw, 'gzip') === FALSE
	    && stripos($raw, 'bzip') === FALSE) {
		return 'application/zip';
	}
	return $raw;
}

// ADR-45: pure mapping — canonical archive MIME → base integrity-test argv.
// Returns the binary + flags array (file NOT included; pfb_validate_archive() appends
// it at call time so this helper stays pure and trivially oracle-testable).
// Returns NULL for non-archive types — nothing to probe.
//
// issue #3068: application/zip probes with `unzip -t`, not `tar -tf`. Both binaries
// live at the same absolute path on both platforms (FreeBSD's /usr/bin/unzip is
// bsdunzip, Debian's is Info-ZIP), so this depends on no new package -- while
// `tar -tf` only read a ZIP at all because the appliance's /usr/bin/tar happens to be
// bsdtar. Two things came with that accident: the probe could not run on a GNU-tar
// dev host, and -- worse -- libarchive reads gzip and tar too, so "is this a valid
// application/zip?" answered TRUE for a plain .tar.gz. pfb_octet_recover_type() asks
// exactly that, zip FIRST, so an octet-stream-typed tarball was recovered as
// application/zip. `unzip -t` is also the real analogue of the gunzip/bzip2 arms: it
// inflates and CRC-checks the members instead of walking the central directory, so a
// body-corrupt ZIP is now refused at the structural gate rather than at extraction.
function pfb_archive_probe(string $canonical_type): ?array {
	switch ($canonical_type) {
		case 'application/zip':
			return array('/usr/bin/unzip', '-t');
		case 'application/gzip':
		case 'application/x-gzip':
			return array('/usr/bin/gunzip', '-t');
		case 'application/x-bzip2':
			return array('/usr/bin/bzip2', '-t');
		case 'application/x-tar':
			return array('/usr/bin/tar', '-tf');
		default:
			return NULL;
	}
}

// ADR-45: run the structural integrity probe for $file.
// Returns TRUE for non-archive types (nothing to test), TRUE if the probe exits 0
// (archive is intact), FALSE if the probe exits non-zero (corrupt/truncated archive).
// The $runner callable(array $argv): int is injectable for unit tests — default runner
// escapeshellarg()s every element, execs to /dev/null, and returns the exit code.
// Mirror of the ?callable $guard seam in pfb_find_managed_obj().
function pfb_validate_archive(string $file, string $canonical_type, ?callable $runner = NULL): bool {
	$argv = pfb_archive_probe($canonical_type);
	if ($argv === NULL) {
		return TRUE;    // non-archive: nothing to test
	}
	$argv[] = $file;    // file appended here, escaped in the runner
	if ($runner === NULL) {
		$runner = function (array $a): int {
			$cmd = implode(' ', array_map('escapeshellarg', $a));
			exec($cmd . ' >/dev/null 2>&1', $out, $rv);
			return (int) $rv;
		};
	}
	return $runner($argv) === 0;
}

// ADR-45: seamed recovery helper for application/octet-stream (or empty) MIME.
// Loops $supported_types in order; returns the first $type for which $validator($file, $type)
// is TRUE (positive structural identification), or NULL when no probe matches.
// $validator shape: callable(string $file, string $type): bool — production value is
// 'pfb_validate_archive'; tests inject a fake closure to exercise the loop without shell.
function pfb_octet_recover_type(string $file, array $supported_types, callable $validator): ?string {
	foreach ($supported_types as $type) {
		if ($validator($file, $type)) {
			return $type;
		}
	}
	return NULL;
}

// ADR-48: pure formatter for the canonical download-validation reject line — a single
// greppable line naming feed/stage/reason + raw detected detail. $stage is one of
// mime|structural|inner|member|plaintext|entries|size (caller-owned vocabulary, unvalidated here).
// Shape: "\npfb_validate: REJECT feed=<feed> stage=<stage> reason=<reason> detected=<detail>"
// (leading "\n" per pfb_logger() convention). Each value has control bytes -> space (blocks
// forging/splitting the line via attacker-influenced detail) — HTML-escaping is NOT applied
// here: the sole renderer of this line (the Logs tab's #fileContent textarea) never parses
// HTML, so escaping here only mangled the operator's view of the real bytes. Pure: string in,
// string out, no I/O, no globals.
function pfb_validate_log_line(string $feed, string $stage, string $reason, string $detail = ''): string {
	[$feed, $stage, $reason, $detail] = array_map(
		static function (string $value): string {
			return preg_replace('/[\x00-\x1F\x7F]/', ' ', $value) ?? '';
		},
		[$feed, $stage, $reason, $detail]
	);
	return "\npfb_validate: REJECT feed={$feed} stage={$stage} reason={$reason} detected={$detail}";
}

// ADR-48: thin emit wrapper -- builds the canonical reject line via
// pfb_validate_log_line() and emits it through pfb_logger() at the reject level
// (default 2 = pfB log + error log). One call site per rejection.
function pfb_validate_log(string $feed, string $stage, string $reason, string $detail = '', int $level = 2): void {
	pfb_logger(pfb_validate_log_line($feed, $stage, $reason, $detail), $level);
}

// ADR-48: the one formatter for the detected= summary built from pfb_filter()'s
// $reject_detail out-param -- every wired pfb_download() call site uses it, so the
// shape has a single place to change.
function pfb_reject_detail_summary(array $reject_detail): string {
	return "{$reject_detail['mime_raw']} rc={$reject_detail['retval']}";
}

// ADR-46: list an archive's member names. The lister is chosen by the archive's own
// canonical MIME type (issue #3068): `unzip -Z1` for application/zip, `tar -tf` for
// every other container. Listing a ZIP with tar only worked because the appliance's
// /usr/bin/tar is bsdtar; /usr/bin/unzip is present on both platforms (bsdunzip on
// FreeBSD, Info-ZIP on Debian) and reads exactly one format, so the guard no longer
// depends on which tar the host installed. Callers pass the type they already
// dispatched on; a gzip-wrapped tar lists through the tar arm, which reads it.
//
// stderr goes to /dev/null so a tool diagnostic (e.g. "tar: Failed to set default
// locale") can NEVER be mistaken for a member name -- merging streams and
// prefix-filtering would let a member literally named "tar: ../x" be silently
// dropped, bypassing the guard. Info-ZIP additionally writes some complaints to
// STDOUT, which is why the rc check comes FIRST and $output is never read on a
// failure: rc, not the absence of output, is what decides.
//
// Returns NULL on a listing failure (rc != 0) so every DISK-writing caller fails
// CLOSED: the gzip/UT1 sites' ADR-45 probe is only `gunzip -t` (gzip-stream
// integrity, not the inner tar), so a valid-gzip / corrupt-inner-tar archive lists
// rc != 0 here and must be rejected, not fail-open extracted. A genuinely intact
// archive always lists rc 0, so this rejects nothing legitimate.
function pfb_archive_member_names(string $file, string $canonical_type): ?array {
	$lister = $canonical_type === 'application/zip'
		? '/usr/bin/unzip -Z1 '
		: '/usr/bin/tar -tf ';
	$output = array();
	$retval = 1;
	exec($lister . escapeshellarg($file) . ' 2>/dev/null', $output, $retval);
	if ($retval != 0) {
		return NULL;
	}
	return array_values(array_filter($output, static function (string $line): bool {
		return $line !== '';
	}));
}

// ADR-46: the first archive member name unsafe to extract to DISK, or NULL when all
// are safe. A NULL $names (the lister could not read the archive) is itself unsafe --
// fail closed with a sentinel reason. Unsafe = absolute path, a '..' path component
// (directory escape), a path component over 255 bytes (FreeBSD NAME_MAX), or a total
// name over 1024 bytes (PATH_MAX) -- names above the filesystem limits cannot extract
// anyway, so the caps reject nothing legitimate. Known limit: the check is NAME-only,
// so a symlink member pointing outside -C plus a write-through entry is invisible to
// it; libarchive's own "Cannot extract through symlink" default covers that vector.
// Pure: no I/O.
function pfb_archive_unsafe_member(?array $names): ?string {
	if ($names === NULL) {
		return 'unlistable-archive';
	}
	foreach ($names as $name) {
		if (!is_string($name) || $name === '') {
			continue;
		}
		if ($name[0] === '/' || strlen($name) > 1024) {
			return $name;
		}
		foreach (explode('/', $name) as $component) {
			if ($component === '..' || strlen($component) > 255) {
				return $name;
			}
		}
	}
	return NULL;
}

// ADR-48 (issue #789): reads the Python-emitted per-entry reject tally
// artifact (pfb_py_reject_stats.json -- build()'s normalise() domain-shape rejects
// and #753 wire-cap rejects, bucketed shape/wire_cap, per feed/group; issue #2371
// adds suffix_drop/suffix_demote) and emits
// ONE canonical stage=entries line per (feed, nonzero bucket) via pfb_validate_log().
// Missing, unreadable, corrupt, or non-array JSON is a silent no-op -- a fresh boot
// or an old python module that predates the artifact, never an error. Python only
// WRITES the artifact; this is the sole place the line is EMITTED (sinks stay
// PHP-only, ADR §2 item 2).
function pfb_emit_entry_reject_stats(string $path): void {
	$raw = @file_get_contents($path);
	if ($raw === FALSE || $raw === '') {
		return;
	}
	$stats = json_decode($raw, TRUE);
	if (!is_array($stats)) {
		return;
	}
	foreach ($stats as $entry) {
		if (!is_array($entry) || !isset($entry['feed']) || !is_scalar($entry['feed'])) {
			continue;
		}
		$feed = (string) $entry['feed'];
		foreach (array('shape', 'wire_cap', 'suffix_drop', 'suffix_demote') as $bucket) {
			$count = (isset($entry[$bucket]) && is_scalar($entry[$bucket])) ? (int) $entry[$bucket] : 0;
			if ($count > 0) {
				pfb_validate_log($feed, 'entries', $bucket, (string) $count);
			}
		}
	}
}

// issue #946: detect a UTF-16/UTF-32 BOM at the start of $head, returning the
// mb_convert_encoding() encoding name to decode it with, or NULL if none matches.
// Order is load-bearing: UTF-32LE's BOM ("\xFF\xFE\x00\x00") is a strict superset
// of UTF-16LE's ("\xFF\xFE") -- checking UTF-16LE first would misdetect every
// UTF-32LE feed. Pure: string in, ?string out, no I/O.
function pfb_utf16_bom_encoding(string $head): ?string {
	if (strncmp($head, "\xFF\xFE\x00\x00", 4) === 0) {
		return 'UTF-32LE';
	}
	if (strncmp($head, "\x00\x00\xFE\xFF", 4) === 0) {
		return 'UTF-32BE';
	}
	if (strncmp($head, "\xFF\xFE", 2) === 0) {
		return 'UTF-16LE';
	}
	if (strncmp($head, "\xFE\xFF", 2) === 0) {
		return 'UTF-16BE';
	}
	return NULL;
}

// issue #946: decode a UTF-16/UTF-32-BOM-prefixed sample to UTF-8 for pfb_text_sanity()'s
// benefit. No BOM match -> returned unchanged. Fail-open: a conversion failure returns the
// ORIGINAL sample unchanged, never throws -- the sanity scan then sees the same bytes it did
// before this helper existed. Pure: string in, string out, no I/O.
function pfb_utf16_sample_to_utf8(string $sample): string {
	$enc = pfb_utf16_bom_encoding($sample);
	if ($enc === NULL) {
		return $sample;
	}

	$bom_len = ($enc === 'UTF-32LE' || $enc === 'UTF-32BE') ? 4 : 2;
	// Stock mbstring substitutes invalid sequences with '?' rather than returning FALSE,
	// so this fail-open branch is believed unreachable in practice -- kept as cheap
	// insurance against a build where the conversion does fail.
	$converted = @mb_convert_encoding(substr($sample, $bom_len), 'UTF-8', $enc);

	return ($converted === FALSE) ? $sample : $converted;
}

// issue #946: transcode a UTF-16/UTF-32-BOM-prefixed FILE to UTF-8 in place, atomically. Reads
// only the first 4 bytes to sniff the BOM (feeds can be tens of MB; a full read risks the PHP
// memory limit) — the full read happens only on an actual BOM match. Returns FALSE (untouched)
// on an unreadable path, no BOM match, or a failed mb_convert_encoding() (fail-open in every
// case). Returns TRUE after a same-filesystem rename() with the original mtime/permission bits
// restored (tempnam() creates 0600 files, so the mode must be carried over explicitly).
//
// ponytail: whole-file read/rewrite for the BOM-matched case only; switch to streaming if
// BOM-marked feeds stop being rare/small.
function pfb_utf16_transcode_file(string $path): bool {
	if (!@is_readable($path)) {
		return FALSE;
	}
	$head = @file_get_contents($path, FALSE, NULL, 0, 4);
	if ($head === FALSE) {
		return FALSE;
	}

	$enc = pfb_utf16_bom_encoding($head);
	if ($enc === NULL) {
		return FALSE;
	}

	$content = @file_get_contents($path);
	if ($content === FALSE) {
		return FALSE;
	}

	$bom_len = ($enc === 'UTF-32LE' || $enc === 'UTF-32BE') ? 4 : 2;
	$converted = @mb_convert_encoding(substr($content, $bom_len), 'UTF-8', $enc);
	if ($converted === FALSE) {
		pfb_logger("\npfb_utf16_transcode_file: mb_convert_encoding failed for [{$path}] ({$enc}) -- leaving file untouched", 2);
		return FALSE;
	}

	$mtime = @filemtime($path);
	$perms = @fileperms($path);
	$tmp = @tempnam(dirname($path), 'pfb_u16_');
	if ($tmp === FALSE || @file_put_contents($tmp, $converted) === FALSE) {
		if ($tmp !== FALSE) {
			@unlink($tmp);
		}
		return FALSE;
	}
	if ($perms !== FALSE) {
		@chmod($tmp, $perms & 0777);
	}
	if (!@rename($tmp, $path)) {
		@unlink($tmp);
		return FALSE;
	}
	if ($mtime !== FALSE) {
		@touch($path, $mtime);
	}
	return TRUE;
}

// issue #1263: append '\n' if the stored file's last byte isn't one -- cat
// concatenates bytes, not records, and welds an unterminated feed's last line
// onto the next file's first downstream. Only reads the last byte (feeds can
// be tens of MB). Empty/unreadable file -> FALSE, untouched (nothing to weld).
function pfb_ensure_trailing_newline(string $path): bool {
	$fh = @fopen($path, 'rb');
	if ($fh === FALSE) {
		return FALSE;
	}
	if (@fseek($fh, -1, SEEK_END) !== 0) {
		fclose($fh);
		return FALSE;
	}
	$last = @fread($fh, 1);
	fclose($fh);
	// A failed/short read can't tell terminated from not -- leave the file alone
	// rather than risk a spurious append.
	if ($last === FALSE || $last === '' || $last === "\n") {
		return FALSE;
	}

	$ap = @fopen($path, 'ab');
	if ($ap === FALSE) {
		return FALSE;
	}
	$written = @fwrite($ap, "\n");
	fclose($ap);
	// Only a full 1-byte write counts as success -- else a failed append would
	// report TRUE, masking the exact unterminated-file condition this exists to fix.
	return $written !== FALSE && $written === 1;
}


/**
 * issue #1797: on-demand text normalization of a downloaded feed baseline.
 * {base}.orig -> {base}.norm, regenerated ONLY when {base}.norm is missing or
 * the recorded source digest ({base}.norm.src.xxhash128, the xxh128 of the
 * .orig the .norm was built FROM) no longer matches the current .orig -- so
 * custom-list re-synthesis, reload-without-refetch, user pre-script mutation
 * and a first upgrade (populated orig dir, zero .norm) all converge without a
 * download-time hook having to see them. Written tmp + atomic rename in the
 * same directory; the #1263 trailing-newline guarantee is re-applied (the sed
 * pass never adds one). The wire-byte ADR-42 sidecar ({base}.orig.xxhash128)
 * is a DIFFERENT, untouched artifact.
 *
 * Returns array{path:string, changed:bool, normalized:bool}:
 *   path       -- file the caller should parse: .norm, or .orig on any failure
 *                 (fallback: a feed must degrade to raw parsing, never to empty).
 *   changed    -- FALSE only when the normalized CONTENT is proven unchanged
 *                 against a recorded baseline (fresh sidecar match, or a
 *                 regeneration that produced byte-identical .norm). A missing/
 *                 corrupt baseline reports TRUE (fail-safe, ADR-42 semantics;
 *                 the Force clear-hashes sweep relies on this to defeat the
 *                 downstream-skip gate).
 *   normalized -- TRUE iff path points at a usable .norm.
 *
 * @return array{path:string, changed:bool, normalized:bool}
 */
function pfb_feed_normalize(string $orig_path, ?string $interpreter = NULL): array {
	$fallback = array('path' => $orig_path, 'changed' => TRUE, 'normalized' => FALSE);
	if (!str_ends_with($orig_path, '.orig') || !file_exists($orig_path)) {
		return $fallback;
	}
	$base      = substr($orig_path, 0, -strlen('.orig'));
	$norm_path = "{$base}.norm";
	$src_base  = "{$base}.norm.src";

	// Hash the source BEFORE generating: a mid-run .orig replacement then reads
	// as stale next pass and re-normalizes (fail-safe), never as falsely fresh.
	$src_digest = pfb_content_hash($orig_path, TRUE);
	if ($src_digest === FALSE) {
		return $fallback;
	}

	$sidecar = pfb_hash_read($src_base);
	if ($sidecar['algo'] === 'xxh128' && $sidecar['digest'] === $src_digest && file_exists($norm_path)) {
		return array('path' => $norm_path, 'changed' => FALSE, 'normalized' => TRUE);
	}

	$prev_digest  = file_exists($norm_path) ? pfb_content_hash($norm_path, TRUE) : FALSE;
	$had_baseline = ($sidecar['algo'] === 'xxh128' && $prev_digest !== FALSE);

	// Exclusive-create the tmp IN the target directory: tempnam() silently
	// falls back to the system tmp dir when the target is unwritable, and a
	// cross-filesystem rename() is not atomic (or fails outright).
	$tmp = dirname($norm_path) . '/.pfbnorm_' . getmypid() . '_' . bin2hex(random_bytes(4));
	$th  = @fopen($tmp, 'x');
	if ($th === FALSE) {
		return $fallback;
	}
	fclose($th);

	if (!pfb_feed_normalize_generate($orig_path, $tmp, $interpreter)) {
		@unlink($tmp);
		pfb_logger("\n[ pfb_feed_normalize ] normalization failed for {$orig_path} -- parsing the raw .orig\n", 2);
		return $fallback;
	}
	pfb_ensure_trailing_newline($tmp);

	$new_digest = pfb_content_hash($tmp, TRUE);
	if ($new_digest === FALSE || !@rename($tmp, $norm_path)) {
		@unlink($tmp);
		return $fallback;
	}
	@file_put_contents("{$src_base}.xxhash128", $src_digest, LOCK_EX);

	return array(
		'path'       => $norm_path,
		'changed'    => !($had_baseline && $new_digest === $prev_digest),
		'normalized' => TRUE,
	);
}


// issue #1797: the normalize pipeline body -- $src (.orig bytes) -> $dst (UTF-8,
// control-stripped, per-line right-trimmed). Ordering is load-bearing:
//   (b) whole-file iconv validity gate first -- a server-declared charset is
//       NOT trusted over provable UTF-8 validity (a wrong ISO-8859-1 label on
//       a UTF-8 body would double-encode it), and iconv -c can never be the
//       converter (it DELETES undecodable bytes silently, no signal);
//   (c) only an invalid file reaches the Python detector/converter
//       (charset_normalizer whole-file detection + errors='replace' decode,
//       U+FFFD replacements counted and logged as the wrong-guess signal);
//       if conversion is unavailable the raw bytes fall through to (d) --
//       sed passes invalid sequences through untouched while still stripping
//       controls, graceful degradation rather than an empty feed;
//   (d) one C.UTF-8 sed pass strips every non-printable except tab (Cc, Cf
//       incl. BOM/ZWJ, C1, NUL, mid-line CR) and right-trims [[:space:]] runs
//       per line -- interior tabs (hosts/TSV) and interior NBSP survive as
//       data. Membership probed on CE 2.8 (FreeBSD 15) and Plus (FreeBSD 16).
function pfb_feed_normalize_generate(string $src, string $dst, ?string $interpreter = NULL): bool {
	$src_esc = escapeshellarg($src);
	$dst_esc = escapeshellarg($dst);

	$ret = 1;
	exec("/usr/bin/iconv -f UTF-8 -t UTF-8 < {$src_esc} > /dev/null 2>&1", $unused_out, $ret);

	$strip_src = $src;
	$conv_tmp  = '';
	if ($ret !== 0) {
		$conv_tmp = "{$dst}.conv";
		if (pfb_feed_convert_encoding($src, $conv_tmp, $interpreter)) {
			$strip_src = $conv_tmp;
		} else {
			pfb_logger("\n[ pfb_feed_normalize ] encoding conversion unavailable for {$src} -- stripping raw bytes\n", 2);
		}
	}

	$sed_expr = "s/[^[:print:]\t]+|[[:space:]]+\$//g";
	$ret2 = 1;
	exec('LC_ALL=C.UTF-8 /usr/bin/sed -E ' . escapeshellarg($sed_expr) . ' < ' .
		escapeshellarg($strip_src) . " > {$dst_esc} 2>/dev/null", $unused_out2, $ret2);
	if ($conv_tmp !== '') {
		@unlink($conv_tmp);
	}
	return $ret2 === 0 && file_exists($dst);
}


// issue #1797: detect + convert a non-UTF-8 feed file to UTF-8 via
// pfb_feed_normalize.py (charset_normalizer, a RUN_DEPENDS). The wrapper
// resolves the interpreter on the appliance ($interpreter is a test seam).
// U+FFFD replacements reported by the script are logged: a high
// count means the detection was probably wrong, and silence here would be
// silent data corruption.
function pfb_feed_convert_encoding(string $src, string $dst, ?string $interpreter = NULL): bool {
	$py = $interpreter ?? PFB_PYTHON_WRAPPER;
	if ($py === '') {
		return FALSE;
	}
	$script = __DIR__ . '/pfb_feed_normalize.py';
	$out = array();
	$ret = 1;
	exec(escapeshellarg($py) . ' ' . escapeshellarg($script) . ' ' .
		escapeshellarg($src) . ' ' . escapeshellarg($dst) . ' 2>&1', $out, $ret);
	if ($ret !== 0 || !file_exists($dst)) {
		pfb_logger("\n[ pfb_feed_normalize ] encoding detection failed for {$src}: " . implode(' | ', $out) . "\n", 2);
		return FALSE;
	}
	$fields   = explode(' ', trim((string) end($out)));
	$encoding = $fields[0] ?? '?';
	$replaced = (int) ($fields[1] ?? 0);
	pfb_logger("\n[ pfb_feed_normalize ] converted {$src} from '{$encoding}' to UTF-8\n", 1);
	if ($replaced > 0) {
		pfb_logger("[ pfb_feed_normalize ] {$replaced} undecodable byte sequence(s) replaced with U+FFFD in {$src} -- the detected encoding '{$encoding}' may be wrong\n", 2);
	}
	return TRUE;
}


// ADR-49: content-sanity gate for a downloaded text feed's first 64-KiB chunk; pinned by
// PfbTextSanityTest. Reason order (first hit wins): 'nul_bytes' (any NUL byte) >
// 'html_error_page' (opens as HTML AND no line is blocklist-shaped: an IPv4/IPv6/CIDR
// anywhere, or a whole-line domain.tld token) > 'below_min_content' (zero non-blank,
// non-comment lines) > NULL. BYTE-LEVEL matching only (no `/u`) so a chunk-truncated
// multibyte tail can never flip a verdict. Pure: string in, ?string out, no I/O.
//
// issue #946: a UTF-16/32-BOM-prefixed sample is decoded to UTF-8 FIRST (before the UTF-8
// BOM strip below) -- else a legitimate wide-char feed trips 'nul_bytes' on its own bytes.
function pfb_text_sanity(string $sample): ?string {
	$sample = pfb_utf16_sample_to_utf8($sample);

	// Strip a UTF-8 BOM up front -- encoding metadata, not content. Left in place
	// it defeats the '<!doctype html'/'<html' opening-tag check (ltrim strips no
	// BOM) AND lets a BOM-prefixed comment line count as data in the content floor.
	if (strncmp($sample, "\xEF\xBB\xBF", 3) === 0) {
		$sample = substr($sample, 3);
	}

	if (strpos($sample, "\x00") !== FALSE) {
		return 'nul_bytes';
	}

	$lines = preg_split('/\r\n|\r|\n/', $sample);

	$leading_trimmed = ltrim($sample);
	$opens_as_html = stripos($leading_trimmed, '<!doctype html') === 0
		|| stripos($leading_trimmed, '<html') === 0;

	// Blocklist-shaped, per branch:
	//   - IPv4/CIDR: SUBSTRING match, deliberately -- real catalogue feeds
	//     (ProjectHoneypot, cybercrime-tracker) serve their IPs embedded in HTML
	//     markup, and those pages must keep suppressing the verdict.
	//   - IPv6: substring too, but bounded (lookarounds + at least one hex group)
	//     so a CSS pseudo-element ("h1::before" in an error page's inline styles)
	//     or a "403 :: Forbidden" separator cannot suppress it.
	//   - domain.tld (bare/ABP/wildcard/FQDN): the token must BE the whole line.
	//     A substring match here lets the domain-shaped tokens of real error-page
	//     markup (a DOCTYPE's w3.org DTD URL, favicon.ico / *.css hrefs, CDN
	//     links) suppress the verdict -- and genuine domain feeds are
	//     one-token-per-line formats anyway.
	// ponytail: the {3,7}-group IPv6 branch also matches MAC-like / timestamp
	// hex-colon runs -- acceptable ceiling: a spurious suppression only defers to
	// downstream parsing (today's behaviour); tighten to real address shapes if
	// it ever misfires in practice.
	$ipv4_shaped = '/(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?/';
	$ipv6_shaped = '/(?<![A-Za-z0-9:])(?:(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4}'
		. '|[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?'
		. '|::[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)(?![A-Za-z0-9:])/';
	$domain_only_line = '/^(?:\|\|)?(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?'
		. '(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}\.?\^?$/';

	// The guard scans EVERY line of the sample (already capped at 64 KiB by the
	// caller), not a fixed head window: HTML-wrapped real feeds (ProjectHoneypot)
	// carry their first IP only after ~90 lines of boilerplate, while a genuine
	// error page has no blocklist-shaped line anywhere.
	if ($opens_as_html) {
		$has_blocklist_line = FALSE;
		foreach ($lines as $line) {
			$line = trim($line);
			if ($line === '') {
				continue;
			}
			if (preg_match($ipv4_shaped, $line) === 1
				|| preg_match($ipv6_shaped, $line) === 1
				|| preg_match($domain_only_line, $line) === 1) {
				$has_blocklist_line = TRUE;
				break;
			}
		}
		if (!$has_blocklist_line) {
			return 'html_error_page';
		}
	}

	foreach ($lines as $line) {
		$content = ltrim($line);
		if ($content === '' || $content[0] === '#' || $content[0] === '!') {
			continue;
		}
		return NULL;    // at least one non-blank, non-comment line -- floor met
	}

	return 'below_min_content';
}

// Punycode-convert a domain, preserving a leading '.' wildcard marker; returns '' when the
// conversion fails. idn_to_ascii() rejects a leading dot, so strip exactly ONE and re-prefix
// it (issue #1730/#1740: ltrim() would promote an invalid '..host' row to the wildcard form).
function pfb_idn_to_ascii_wildcard(string $host): string {

	$wildcard = str_starts_with($host, '.');
	$host = $wildcard ? substr($host, 1) : $host;
	// No label left to convert: idn_to_ascii() raises on an empty domain. The value is
	// converted UNTRIMMED -- trimming it here would launder a padded domain past
	// pfb_filter()'s charset check, which is fail-closed on purpose.
	if (pfb_is_blank($host)) {
		return '';
	}
	$ascii = idn_to_ascii($host);
	if (empty($ascii)) {
		return '';
	}
	return $wildcard ? ".{$ascii}" : $ascii;
}


// Strip the leading '.' DNSBL wildcard marker from a row whose first character is a dot;
// returns '' (after logging the skip) when more than one leading dot is present. issue #1741:
// ltrim() strips them all, promoting an invalid '..host' row into the legal wildcard form and
// whitelisting a whole domain the operator never wrote.
function pfb_strip_wildcard_marker(string $row, string $reference): string {

	$stripped = substr($row, 1);
	if (str_starts_with($stripped, '.')) {
		pfb_logger("\n{$reference}: Row is not a wildcard entry [ " .
			substr(htmlspecialchars($row), 0, 100) . " ] *skipping*", 2);
		return '';
	}
	return $stripped;
}


// Function to filter/sanitize user input.
//
// ADR-48: $reject_detail is an optional by-ref out-param for the PFB_FILTER_FILE_MIME /
// PFB_FILTER_FILE_MIME_COMPRESSED reject paths only. A caller that pre-sets it to an array()
// opts in: on rejection this fills it with the raw detail and SUPPRESSES the legacy message so
// the caller can emit the canonical pfb_validate_log() line instead. A caller that leaves it
// NULL (default) gets the legacy in-filter message unchanged -- no rejection loses its log.
function pfb_filter($input, $type, $reference='Unknown', $default='', $escape=FALSE, &$reject_detail=NULL) {
	global $pfb;

	$header = "\n PFB_FILTER - {$type} | {$reference}";

	$return_type = $default;
	if (in_array($type, array(PFB_FILTER_URL, PFB_FILTER_FILE_MIME_COMPARE, PFB_FILTER_FILE_MIME, PFB_FILTER_FILE_MIME_COMPRESSED))) {
		$return_type = FALSE;
	}

	if (!in_array($type, array(PFB_FILTER_ON_OFF, PFB_FILTER_NUM))) {
		if (empty($input) || is_null($input)) {
			return $return_type;
		}
	}

	// issue #1768: ON_OFF/NUM skip the early return above (NULL==''/0 are legitimate
	// stored values), but still flow into the scalar ops below (preg_match/htmlspecialchars).
	// Coerce NULL -> '' here (not is_null-guard) so 'NULL==""' stays byte-identical while
	// null-deprecations stop; caller-side Undefined-array-key warnings are untouched.
	if (!is_array($input)) {
		$input = (string) ($input ?? '');
	}

	// issue #1070: every non-FILE_MIME type runs scalar string ops below (htmlspecialchars/
	// preg_match) that PHP 8 TypeErrors on an array -- reject an array up front, before any
	// such op runs, for those types. issue #1139: must run before the control-char loop
	// below, which itself TypeErrors on a nested (non-scalar) array element.
	if (is_array($input) && !in_array($type, array(PFB_FILTER_FILE_MIME_COMPARE, PFB_FILTER_FILE_MIME, PFB_FILTER_FILE_MIME_COMPRESSED))) {
		return $return_type;
	}

	// Check for control characters. The /u modifier is required: without it, \p{Cc}
	// classifies each raw BYTE as a Latin-1 codepoint, so a valid multibyte UTF-8
	// character (e.g. "€", "日") whose continuation byte falls in 0x80-0x9F is
	// falsely rejected while other non-ASCII bytes pass through unexamined -- and a
	// genuinely invalid-UTF-8 subject is silently accepted. With /u, preg_match()
	// returns FALSE (not 0) on invalid UTF-8, so the check must reject on `!== 0`
	// to fail closed (this is a PFBL-01 input-sanitisation gate) rather than open.
	// The reject above already returned for every non-FILE_MIME type, so this array
	// branch only ever sees FILE_MIME's flat literal-string arrays (ADR-48).
	// issue #1723: narrowed from \p{C} (Cc+Cf+Co+Cs+Cn) to \p{Cc}+BOM (\x{FEFF}).
	// Unicode format characters (Cf: ZWJ/ZWNJ, bidi marks, zero-width) are no
	// longer grounds to reject a whole field -- free-text fields must accept
	// Unicode; domain-shaped fields validate them via their type-specific
	// ASCII/IDNA rules below. Cc and the BOM stay rejected;
	// invalid UTF-8 stays fail-closed.
	if (is_array($input)) {
		foreach ($input as $vline) {
			if (preg_match("/[\p{Cc}\x{FEFF}]+/u", $vline) !== 0) {
				pfb_logger("{$header} Control characters found [ " . htmlspecialchars($vline) . " ]", 6);
				// ADR-48: this early return precedes the switch, so it also rejects
				// the FILE_MIME types -- fill the out-param for an opted-in caller
				// (keep the level-6 diagnostic; it is errlog-only, not the legacy
				// reject message the contract suppresses).
				if (is_array($reject_detail)) {
					$reject_detail = array('mime_raw' => 'control-characters', 'mime' => '', 'retval' => -1);
				}
				return $return_type;
			}
		}
	}
	else {
		if (preg_match("/[\p{Cc}\x{FEFF}]+/u", $input) !== 0) {
			pfb_logger("{$header} Control characters found [ " . htmlspecialchars($input) . " ]", 6);
			if (is_array($reject_detail)) {
				$reject_detail = array('mime_raw' => 'control-characters', 'mime' => '', 'retval' => -1);
			}
			return $return_type;
		}
	}

	$result = FALSE;
	switch ($type) {
		case PFB_FILTER_HTML:
			$result = htmlspecialchars(trim($input));
			break;
		case PFB_FILTER_URL:
			// PFB_FILTER_URL is the single validation gate for feed URLs and local
			// feed paths. Composition order: the control-char filter above, then the
			// scheme allow-list (http/https/rsync/ftp), then a self/local branch, then
			// — for a non-self remote host — the shared feed-host check.
			//
			// A host counts as self-hosted only when EVERY resolved address is the
			// firewall itself (own configured address / loopback). A host that also
			// resolves to a non-self address is not self-hosted and defers to the
			// shared host check, so the gate's verdict matches the fetch's.
			//
			// The $escape flag selects the context:
			//   $escape = TRUE  -> pfSense-local / Alerts-tab refresh: a URL is accepted
			//                      only when its host is self-hosted AND it points at the
			//                      web root — a file directly under '/' (pathinfo() dirname
			//                      '/'), not a nested path. Everything else is rejected.
			//   $escape = FALSE -> feed-remote: a self-hosted host stays exempt at the web
			//                      root; any other host — including one resolving to both
			//                      self and a non-self address — is routed through
			//                      pfb_feed_host_allowed() (the shared host check) when
			//                      the feed-host filter is enabled (pfb_feed_filter_enabled()),
			//                      so a non-self, non-allowlisted internal address is
			//                      rejected. With the filter off the host check is skipped.
			//
			// A non-URL input is treated as a local file path: it is canonicalised with
			// realpath() and accepted only when it sits directly under one of the allowed
			// directories (see the else branch below).
			//
			// The fetch path (pfb_download) re-runs the SAME pfb_feed_host_allowed()
			// before dialling, so the host this gate accepts is the host the fetch will
			// permit — the validation-time and fetch-time verdicts agree (pinned by
			// FeedFilterParityTest).
			$is_RSYNC = FALSE;
			if (strpos($input, '::') !== FALSE && !$escape) {
				$rsync = explode('::', $input);
				if (count($rsync) == 2 && !empty($rsync[0]) && filter_var($rsync[0], FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
					$is_RSYNC = TRUE;
				}
			}

			if ($is_RSYNC || filter_var($input, FILTER_VALIDATE_URL)) {
				if ($is_RSYNC) {
					$data = array('host' => $rsync[0], 'path' => $rsync[1]);
				} else {
					$data = parse_url($input);
					if (!in_array($data['scheme'], array('http', 'https', 'rsync', 'ftp'))) {
						pfb_logger("{$header} Invalid URL Scheme [ " . htmlspecialchars(pfb_redact_url($input)) . " ]", 6);
						return FALSE;
					}
				}

				$validate_list = '';
				if (!$data || !is_array($data)) {
					pfb_logger("{$header} Invalid URL (missing data) [ " . htmlspecialchars(pfb_redact_url($input)) . " ]", 6);
					return FALSE;
				} elseif (!isset($data['host']) || empty($data['host'])) {
					pfb_logger("{$header} Invalid URL (missing hostname) [ " . htmlspecialchars(pfb_redact_url($input)) . " ]", 6);
					return FALSE;
				} elseif (is_ipaddr($data['host'])) {
					$validate_list = array(array('type' => 'IP', 'data' => $data['host']));
				} else {
					$validate_list = resolve_host_addresses("{$data['host']}.");
				}

				// Classify every resolved address. $pfsense_configured records that
				// at least one address is the firewall itself; $self_only stays TRUE
				// only while EVERY resolved address is the firewall itself. A host
				// that also resolves to a non-self address (foreign-internal or
				// public) is not a self-hosted URL: it must defer to the shared
				// pfb_feed_host_allowed() check so the validation-time verdict matches
				// the fetch-time verdict (parity). Hence no early break — every
				// candidate is examined.
				$pfsense_configured = FALSE;
				$self_only          = TRUE;
				if (!empty($validate_list) && is_array($validate_list)) {
					foreach ($validate_list as $validate) {
						if ($validate['type'] == 'CNAME' && !empty($validate['data'])) {

							if (is_ipaddr($validate['data'])) {
								$cname_list = resolve_host_addresses($validate['data']);
							} else {
								$cname_list = resolve_host_addresses("{$validate['data']}.");
							}

							if (!empty($cname_list) && is_array($cname_list)) {
								foreach ($cname_list as $cname) {
									if (!empty($cname['data']) && is_ipaddr($cname['data'])) {
										if (pfb_ip_is_self($cname['data'])) {
											$pfsense_configured = TRUE;
										} else {
											$self_only = FALSE;
										}
									}
								}
							}
						}
						if (!empty($validate['data']) && is_ipaddr($validate['data'])) {
							if (pfb_ip_is_self($validate['data'])) {
								$pfsense_configured = TRUE;
							} else {
								$self_only = FALSE;
							}
						}
					}
				}
				else {
					// Cannot resolve host
					pfb_logger("{$header} Invalid URL (cannot resolve) [ " . htmlspecialchars(pfb_redact_url($input)) . " ]", 6);
					return FALSE;
				}

				$path = pathinfo($data['path'], PATHINFO_DIRNAME);

				// Validate only pfSense URLS (localfile check and Alerts Tab refresh)
				if ($escape) {
					// Self-hosted only: every resolved address must be the firewall
					// itself. A host that also resolves to a non-self address is not
					// accepted on this pfSense-local path.
					if (($pfsense_configured && $self_only) ||
					    ($data['host'] == '127.0.0.1') ||
					    ($data['host'] == '::1')) {

						// Allowed only when the URL points at the web root — a file
						// directly under '/' (pathinfo() dirname '/'), not a nested path.
						if ($path == '/') {
							return TRUE;
						}
					}

					if ($reference == 'alerts refresh') {
						pfb_logger("{$header} Invalid URL (alerts tab) [ " . htmlspecialchars(pfb_redact_url($input)) . " ]", 6);
					}
					return FALSE;
				}

				// Self-hosted feed URL: every resolved address is the firewall
				// itself. Allowed only at the web root (pathinfo() dirname '/'). A
				// host that also resolves to any non-self address is NOT handled
				// here — it falls through to the shared feed-host check below so the
				// validation-time and fetch-time verdicts stay in parity.
				if (($pfsense_configured && $self_only) ||
				    ($data['host'] == '127.0.0.1') ||
				    ($data['host'] == '::1')) {

					if ($path == '/') {
						return TRUE;
					}
					pfb_logger("{$header} Invalid URL (not allowed) [ " . htmlspecialchars(pfb_redact_url($input)) . " ]", 6);
					return FALSE;
				}

				// All other remote feed URLs: route through the shared feed-host
				// check so a non-self, non-allowlisted internal address is rejected
				// when the feed-host filter is enabled. Self and allowlisted hosts
				// are exempted inside the helper, so this preserves the prior allow
				// for self/public; it only adds the reject the helper defines.
				$reason	= '';
				$pinned	= '';
				if (pfb_feed_filter_enabled() &&
				    !pfb_feed_host_allowed($data['host'], $reason, $pinned)) {
					pfb_logger("{$header} Invalid URL ({$reason}) [ " . htmlspecialchars(pfb_redact_url($input)) . " ]", 6);
					return FALSE;
				}
				return TRUE;
			}

			// Local file path validation
			else {
				$allowed_path	= array(	'/var/db/pfblockerng/',
									'/var/db/pfblockerng/deny/',
									'/var/db/pfblockerng/permit/',
									'/var/db/pfblockerng/match/',
									'/var/db/pfblockerng/native/',
									'/var/db/pfblockerng/original/',
									'/var/db/pfblockerng/dnsbl/',
									'/var/db/pfblockerng/dnsblorig/',
									'/var/db/pfblockerng/ET/',
									'/var/db/pfblockerng/ut1/',
									'/var/db/pfblockerng/shallalist/',
									'/usr/local/www/',
									'/usr/local/share/GeoIP/',
									'/usr/local/share/GeoIP/cc/' );
				if (!empty($pfb['dbdir']) && is_string($pfb['dbdir']) && realpath($pfb['dbdir']) !== FALSE) {
					$allowed_path[] = rtrim(realpath($pfb['dbdir']), '/') . '/';
				}

				// Canonicalize before any membership test so a relative
				// ('..') or redundant-separator path cannot escape an allowed
				// directory. realpath() returns FALSE for a path that does not
				// exist (or cannot be resolved) — reject it.
				$real = realpath($input);
				if ($real === FALSE) {
					pfb_logger("\n[PFB_FILTER - {$type}] Invalid URL (cannot resolve path) [ " . htmlspecialchars(pfb_redact_url($input)) . " ]", 6);
					return FALSE;
				}

				// The basename must be a plain filename — no directory
				// separators or '..' surviving canonicalization.
				$base = basename($real);
				if ($base === '' || $base === '.' || $base === '..' ||
				    strpbrk($base, '/\\') !== FALSE) {
					pfb_logger("\n[PFB_FILTER - {$type}] Invalid URL (not allowed2) [ " . htmlspecialchars(pfb_redact_url($input)) . " ]", 6);
					return FALSE;
				}

				// Strict containment: the canonical file must sit DIRECTLY in
				// one of the allowed directories (no subfolder support), and be
				// a regular file.
				$real_dir = rtrim(dirname($real), '/') . '/';
				if (in_array($real_dir, $allowed_path, TRUE) && is_file($real)) {
					return TRUE;
				}
			}
			pfb_logger("\n[PFB_FILTER - {$type}] Invalid URL (not allowed2) [ " . htmlspecialchars(pfb_redact_url($input)) . " ]", 6);
			return FALSE;
			break;
		case PFB_FILTER_WORD:
			// Validate for 'Any word character (letter, number, underscore)'
			if (!preg_match("/\W/", $input)) {
				$result = htmlspecialchars($input);
			}
			break;
		case PFB_FILTER_WORD_DOT:
			// Validate for '(letter, number, underscore, dash) dot (letter, number, underscore, dash)'
			if (preg_match("/^[a-zA-Z0-9_\-]+\.{1}[a-zA-Z0-9_\-]+$/", $input)) {
				$result = htmlspecialchars($input);
			}
			break;
		case PFB_FILTER_TLD:
			// Validate TLD. issue #1723: a non-ASCII (IDN) TLD is converted to its
			// punycode candidate before the charset check; on success the ORIGINAL
			// input is returned (the read path IDN-converts separately). issue #1812:
			// nontransitional CONTEXTJ validation rejects forbidden joiner placements.
			$candidate = $input;
			if (preg_match('/[^\x00-\x7F]/', $input)) {
				$candidate = idn_to_ascii($input, IDNA_CHECK_CONTEXTJ | IDNA_NONTRANSITIONAL_TO_ASCII);
				$candidate = empty($candidate) ? FALSE : $candidate;
			}
			if (($candidate !== FALSE) && preg_match("/^[a-zA-Z0-9_\.\-]+$/", $candidate)) {
				$result = htmlspecialchars($input);
			}
			break;
		case PFB_FILTER_DOMAIN:
			// Validate domain. issue #1723: a non-ASCII (Unicode/IDN) domain is
			// converted to its punycode candidate before the existing dots/length/
			// labels/charset checks run below; on success the ORIGINAL (Unicode)
			// input is returned (htmlspecialchars'd) -- callers use the return as
			// a pass/fail gate and persist the raw text, the read path
			// (pfb_text_area_decode()'s IDN branch) IDN-converts separately at
			// read time, so what is returned on success must not change. issue #1812:
			// validation uses nontransitional CONTEXTJ checks; read conversion stays
			// on pfb_idn_to_ascii_wildcard()'s existing default semantics.
			$candidate = $input;
			if (preg_match('/[^\x00-\x7F]/', $input)) {
				$wildcard = str_starts_with($input, '.');
				$host      = $wildcard ? substr($input, 1) : $input;
				if (pfb_is_blank($host)) {
					$candidate = FALSE;
				} else {
					$ascii = idn_to_ascii($host, IDNA_CHECK_CONTEXTJ | IDNA_NONTRANSITIONAL_TO_ASCII);
					$candidate = empty($ascii) ? FALSE : ($wildcard ? ".{$ascii}" : $ascii);
				}
			}
			if (($candidate !== FALSE) &&
			    (strpos($candidate, '.') !== FALSE) &&			// Exclude no dots
			    (strpos($candidate, '..') === FALSE) &&			// Exclude double dot
			    (strlen($candidate) < 255) &&				// Validate length of domain (Max 255 chars)
			    (pfb_validate_domain_labels($candidate) !== FALSE) &&	// Validate length of labels (Max of 63 chars)
			    (preg_match("/^[a-zA-Z0-9_\.\-]+$/", $candidate))) {  	// Exclude any other characters
				$result = TRUE;
			}
			if ($result) {
				$result = htmlspecialchars($input);
			}
			break;
		case PFB_FILTER_HOSTNAME:
			// Validate hostname. issue #1731: same punycode-candidate approach as
			// PFB_FILTER_TLD -- a non-ASCII (IDN) hostname converts to its
			// punycode candidate before is_hostname(); on success the ORIGINAL
			// input is returned (the read path IDN-converts separately).
			// issue #1807: run nontransitional UTS46 with CONTEXTJ checks so a
			// joiner placement IDNA2008 forbids is rejected. IDNA_CHECK_CONTEXTJ
			// alone is a no-op here: default (transitional) processing DELETES
			// ZWJ/ZWNJ before the check runs, silently accepting the forbidden
			// placement and returning the joiner-bearing original.
			$candidate = $input;
			if (preg_match('/[^\x00-\x7F]/', $input)) {
				$candidate = idn_to_ascii($input, IDNA_CHECK_CONTEXTJ | IDNA_NONTRANSITIONAL_TO_ASCII);
				$candidate = empty($candidate) ? FALSE : $candidate;
			}
			if (($candidate !== FALSE) && is_hostname($candidate)) {
				$result = htmlspecialchars($input);
			}
			break;
		case PFB_FILTER_IPV4:
			// Validate IPv4
			if (is_ipaddrv4($input)) {
				$result = htmlspecialchars($input);
			}
			break;
		case PFB_FILTER_IP:
			// Validate any IP address v4/v6
			if (is_ipaddr($input)) {
				$result = htmlspecialchars($input);
			}
			break;
		case PFB_FILTER_ALPHA:
			// Validate input is alphabetic only
			if (ctype_alpha($input)) {
				$result = htmlspecialchars($input);
			}
			break;
		case PFB_FILTER_ALNUM:
			// Validate input is alphanumeric only
			if (ctype_alnum($input)) {
				$result = htmlspecialchars($input);
			}
			break;
		case PFB_FILTER_NUM:
			// Validate input is number only
			if (preg_match("/^[0-9]+$/", $input)) {
				$result = htmlspecialchars($input);
			}
			break;
		case PFB_FILTER_CSV:
			// Validate CSV string
			if (preg_match("/^[a-zA-Z0-9,_-]+$/", $input)) {
				$result = htmlspecialchars($input);
			}
			break;
		case PFB_FILTER_CSV_WHOIS:
			// Validate Whoisconvert string
			if (preg_match("/^[a-zA-Z0-9,\._\-]+$/", $input)) {
				$result = htmlspecialchars($input);
			}
			break;
		case PFB_FILTER_CSV_CRON:
			// Validate CSV string (cron hour setting)
			if ($input == '*' || preg_match("/^[0-9,]+$/", $input)) {
				$result = htmlspecialchars($input);
			}
			break;
		case PFB_FILTER_FILE_MIME_COMPARE:
			// Validate mime-type
			// $input [0] path/file, [1] mime-type to be validated against
			unset($retval);
			unset($output);
			if (!file_exists($input[0])) {
				pfb_logger("{$header} Invalid Mime-type (file missing): [" .  htmlspecialchars($input[0]) . "|" . htmlspecialchars($input[1]) . "]", 2);
				return FALSE;
			}
			exec("/usr/bin/file -b --mime-type " . escapeshellarg($input[0]) . " 2>&1", $output, $retval);
			if ($retval != 0 || empty($output[0]) || $output[0] !== $input[1]) {
				pfb_logger("{$header} Invalid Mime-type: [" .  htmlspecialchars($input[0]) . "|" . htmlspecialchars($input[1]) . "]", 2);
				return FALSE;
			}
			return TRUE;
			break;
		case PFB_FILTER_FILE_MIME:
			// Validate File Mime-types
			// $input [0] path/file (legacy, unused), [1] path/file [2] URL
			// The probed path ($input[1]) is escapeshellarg()'d at the sink below,
			// so callers need not pre-escape it.

			unset($retval);
			unset($output);
			if (!file_exists($input[1])) {
				// ADR-48: honour the out-param contract on EVERY reject path — an
				// opted-in caller emits the canonical line itself, so fill the detail
				// and suppress the legacy message (mirrors the mime-reject branch).
				if (is_array($reject_detail)) {
					$reject_detail = array('mime_raw' => 'file-not-found', 'mime' => '', 'retval' => -1);
				} else {
					pfb_logger("{$header} Downloaded file not found: [" .  htmlspecialchars($input[0]) . "|" . htmlspecialchars($input[1]) . "]", 2);
				}
				return FALSE;
			}
			exec("/usr/bin/file -b --mime-type " . escapeshellarg($input[1]) . " 2>&1", $output, $retval);
			if (!empty($output[0])) {
				$mime_raw = $output[0];
				$output[0] = pfb_mime_normalise($mime_raw);
				if ($output[0] !== $mime_raw) {
					// ADR-44: debug-log every normalisation event (raw -> canonical).
					pfb_logger("MIME normalised: raw=\"" . htmlspecialchars($mime_raw) . "\" -> canonical=\"" . htmlspecialchars($output[0]) . "\"", 5);
				}
			}
			if ($retval != 0 || empty($output[0]) || !pfb_mime_in_allowlist($output[0], $pfb['mime_types'])) {

				// Exceptions
				$hostname = parse_url($input[2], PHP_URL_HOST);
				if ($output[0] == 'text/x-asm' &&
				    ($hostname == 'easylist-downloads.adblockplus.org' || $hostname == 'easylist.to' )) {
					$output[0] = 'text/plain';
				}
				elseif ($output[0] == 'application/octet-stream' && $hostname == 'ipinfo.io') {
					$output[0] = 'text/plain';
				}
				else {
					$recovered = NULL;
					if ($output[0] === 'application/octet-stream' || empty($output[0])) {
						$recovered = pfb_octet_recover_type(
							$input[1],
							array('application/zip', 'application/gzip', 'application/x-bzip2', 'application/x-tar'),
							'pfb_validate_archive'
						);
					}
					if ($recovered !== NULL) {
						pfb_logger("MIME recovered: octet-stream positively identified as \"" . htmlspecialchars($recovered) . "\" via structural probe", 5);
						$output[0] = $recovered;
					} else {
						// ADR-48: opted-in caller (pre-set $reject_detail = array())
						// gets the raw detail back instead of the legacy message.
						if (is_array($reject_detail)) {
							$reject_detail = array(
								'mime_raw' => $mime_raw ?? $output[0],
								'mime'     => $output[0],
								'retval'   => $retval,
							);
						} else {
							pfb_logger("\n[PFB_FILTER - {$type}] Failed or invalid Mime Type: [" .  htmlspecialchars($output[0]) . "|" . htmlspecialchars($retval) . "]", 2);
						}
						unlink_if_exists($input[1]);
						return FALSE;
					}
				}
			}
			$result = htmlspecialchars($output[0]);
			break;
		case PFB_FILTER_FILE_MIME_COMPRESSED:
			// Validate File Mime-types in compressed files
			// $input [0] path/file (legacy, unused), [1] path/file [2] URL
			// The probed path ($input[1]) is escapeshellarg()'d at the sink below,
			// so callers need not pre-escape it.
			unset($retval);
			unset($output);
			if (!file_exists($input[1])) {
				// ADR-48: same out-param contract as the FILE_MIME branch above.
				if (is_array($reject_detail)) {
					$reject_detail = array('mime_raw' => 'file-not-found', 'mime' => '', 'retval' => -1);
				} else {
					pfb_logger("{$header} Downloaded file not found: [" .  htmlspecialchars($input[0]) . "|" . htmlspecialchars($input[1]) . "]", 2);
				}
				return FALSE;
			}
			exec("/usr/bin/file -bZ --mime-type " . escapeshellarg($input[1]) . " 2>&1", $output, $retval);
			if ($retval != 0 || empty($output[0]) || !pfb_mime_in_allowlist($output[0], $pfb['mime_types'])) {
				// ADR-48: same out-param contract as the FILE_MIME branch above.
				if (is_array($reject_detail)) {
					$reject_detail = array(
						'mime_raw' => $output[0],
						'mime'     => $output[0],
						'retval'   => $retval,
					);
				} else {
					pfb_logger("{$header} Failed or invalid Mime Type Compressed: [" .  htmlspecialchars($output[0]) . "|" . htmlspecialchars($retval) . "]", 2);
				}
				unlink_if_exists($input[1]);
				return FALSE;
			}
			$result = htmlspecialchars($output[0]);
			break;
		case PFB_FILTER_ATYPE:
			// Validate atype entry in category_edit.php
			if (preg_match("/^[a-zA-Z0-9\.|_]+$/", $input)) {
				$result = htmlspecialchars($input);
			}
			break;
		case PFB_FILTER_HEX_COLOR:
			// Alerts Tab - Hex code validation
			if ($input == 'none' || preg_match("/^#([a-fA-F0-9]{6}|[a-fA-F0-9]{3})$/", $input)) {
				$result = htmlspecialchars($input);
			}
			break;
		case PFB_FILTER_ON_OFF:
			// Validate on or off
			if ($input == 'on' || $input == '') {
				$result = htmlspecialchars($input);
			} else {
				pfb_logger("{$header} Invalid on/off [ " . htmlspecialchars($input) . " ]", 6);
			}
			break;
		case PFB_FILTER_TOKEN:
			// ADR-59: validate a base64url/JWT-shaped credential token (e.g. a Cloudflare
			// Radar API token) -- letters, digits, and the base64url/JWT punctuation set
			// '._~+/=-', bounded length so a pathological input can't be used for resource
			// exhaustion. PFB_FILTER_WORD ([A-Za-z0-9_] only) would reject a real token
			// (dashes, dots). Callers pass reference 'top1m_token' to suppress the
			// failed-validation log line below -- a rejected token must never be logged,
			// even at debug level (the secret itself, not just its download URL).
			if (strlen($input) >= 8 && strlen($input) <= 512 && preg_match("/^[A-Za-z0-9._~+\/=-]+$/D", $input)) {
				$result = htmlspecialchars($input);
			}
			break;
		default:
			pfb_logger("{$header} Type invalid [ " . htmlspecialchars($input) . " ]", 6);
			break;
	}

	if ($result && $escape) {
		$result = escapeshellarg($result);
	}

	// Log validation errors
	if (!empty($input) && empty($result) &&
	    !in_array($type, array(PFB_FILTER_URL, PFB_FILTER_FILE_MIME_COMPARE, PFB_FILTER_FILE_MIME, PFB_FILTER_FILE_MIME_COMPRESSED, PFB_FILTER_ON_OFF, PFB_FILTER_NUM))) {

		// Exceptions: parsed feed-line volume, plus write-only credentials whose rejected
		// values must never be logged: top1m_token (ADR-59), maxmind_key (#924),
		// and asn_token (#2922).
		if (in_array($reference, array('DNSBL_Download', 'top1m_token', 'maxmind_key', 'asn_token'))) {
			//
		} else {
			pfb_logger("{$header} Failed validation [ " . htmlspecialchars($input) . " ]", 6);
		}
	}

	return $result === FALSE ? $default : $result;
}

function pfb_get_vips(): array {
	$vips = get_specialnet('', [SPECIALNET_VIPS]);
	$vips4 = [];
	$vips6 = [];

	foreach (get_configured_vip_list() as $vip_id => $vip_address) {
		if (!isset($vips[$vip_address])) {
			continue;
		}
		switch (is_ipaddr($vip_address)) {
			case 4:
				$vips4[$vip_id] = $vips[$vip_address];
				break;
			case 6:
				$vips6[$vip_id] = $vips[$vip_address];
				break;
			default:
				break;
		}
	}

	return [
		'v4' => $vips4,
		'v6' => $vips6
	];
}

function pfb_get_vip_options(int $family, bool $pkg_xml_format = FALSE) {
	$vips = pfb_get_vips();
	if ($family == AF_INET) {
		$selection = &$vips['v4'];
	} elseif ($family == AF_INET6) {
		$selection = &$vips['v6'];
	} else {
		$selection = [];
	}

	if ($pkg_xml_format) {
		$options = [[
			'id' => 'none',
			'descr' => ''
		]];
		foreach ($selection as $vip_id => $vip_address) {
			$options[] = [
				'id' => $vip_id,
				'descr' => $vip_address
			];
		}
	} else {
		$options = array_merge(
			['none' => ''],
			$selection
		);
	}

	return $options;
}

// [ADR-13] Pure decision: is a v6 sinkhole VIP WANTED for this DNSBL config? True iff the DNS
// Resolver listens on IPv6 AND auto-provisioning is off (manual mode) — a NON-BLOCKING
// recommendation (ADR-13 §7): pfb_global logs a warning, DNSBL keeps running on IPv4. NOT a hard
// requirement — a v6-listening resolver without a v6 VIP is a common, valid manual setup. Pure:
// no global/config access, single directly-testable source of truth.
function pfb_dnsbl_v6_vip_required(bool $listens_v6, bool $auto): bool {
	return $listens_v6 && !$auto;
}

/*
 * Resolve a per-feed list pre/post script (config-stored basename) to its
 * absolute path, or FALSE. The script must be a regular file whose canonical
 * path sits directly in one of the allowed list-script dirs (list_scripts/,
 * with the legacy package root as upgrade fallback). realpath() + strict
 * dirname containment = parity with pfb_filter() LOCALFILE, so a symlink
 * escaping the dir is rejected. Executable bit is NOT required (presence in
 * the dir is the authorization). $dirs is overridable for off-appliance tests.
 */
function pfb_resolve_list_script($name, $dirs = null) {
	$name = basename((string) $name);	// traversal defense
	if ($name === '') {
		return FALSE;
	}
	if ($dirs === null) {
		$dirs = array('/usr/local/pkg/pfblockerng/list_scripts', '/usr/local/pkg/pfblockerng');
	}
	foreach ($dirs as $dir) {
		$real_dir = realpath($dir);
		if ($real_dir === FALSE) {
			continue;
		}
		$real = realpath("{$dir}/{$name}");
		if ($real !== FALSE && dirname($real) === $real_dir && is_file($real)) {
			return "{$dir}/{$name}";	// in-dir path; exec follows the (contained) link
		}
	}
	return FALSE;
}

/* Return the ordered list of input paths the Python DNSBL module loads.
   These are fingerprinted before/after a pass to detect real changes.
   Includes unbound_py_hsts: the shipped HSTS preload list re-staged by dnsbl_cache_stage()
   via cp -f between the two fingerprint snapshots, so a package update that ships a new
   list is detected (old chroot copy vs freshly staged copy differ) and triggers a reload.
   Excluded: unbound_py_count / unbound_py_regex_count (Python-emitted outputs —
   including them makes every pass look changed), unbound_py_ss (has its own
   md5 gate via $safesearch_update; double-gating would suppress SafeSearch restarts), and
   unbound_py_data/unbound_py_zone (ADR-65: retired writer targets, never written again).
   Pure (no global access): caller passes $pfb explicitly so tests can inject any paths. */
function pfb_unbound_py_normalize_absolute_path(string $path) {
	if ($path === '' || $path[0] !== '/') {
		return FALSE;
	}

	$parts = array();
	foreach (explode('/', $path) as $part) {
		if ($part === '' || $part === '.') {
			continue;
		}
		if ($part === '..') {
			if (empty($parts)) {
				return FALSE;
			}
			array_pop($parts);
			continue;
		}
		$parts[] = $part;
	}
	return '/' . implode('/', $parts);
}

// ADR-65/#1357: resolve only manifest-authoritative raw refs under the manifest's
// directory. Missing confined refs stay in the set so the reload fingerprint fails loud.
function pfb_unbound_py_manifest_raw_paths(string $manifest_path, bool $deduplicate=TRUE): array {
	$json = @file_get_contents($manifest_path);
	if ($json === FALSE) {
		return array();
	}
	$manifest = json_decode($json, TRUE);
	if (!is_array($manifest) || !isset($manifest['feeds']) || !is_array($manifest['feeds'])) {
		return array();
	}

	$base_path = dirname($manifest_path);
	if ($base_path === '' || $base_path[0] !== '/') {
		$base_path = getcwd() . "/{$base_path}";
	}
	$base_normalized = pfb_unbound_py_normalize_absolute_path($base_path);
	$base_resolved = realpath($base_path);
	if ($base_normalized === FALSE || $base_resolved === FALSE) {
		return array();
	}

	$paths = array();
	foreach ($manifest['feeds'] as $feed) {
		if (!is_array($feed) || !isset($feed['raw']) || !is_string($feed['raw']) || $feed['raw'] === '') {
			continue;
		}
		if (str_contains($feed['raw'], "\0")) {
			continue;
		}
		$path = $feed['raw'][0] === '/' ? $feed['raw'] : "{$base_normalized}/{$feed['raw']}";
		$normalized = pfb_unbound_py_normalize_absolute_path($path);
		if ($normalized === FALSE) {
			continue;
		}
		$resolved = realpath($path);
		$confined = $resolved !== FALSE ? $resolved : $normalized;
		$confined_base = $resolved !== FALSE ? $base_resolved : $base_normalized;
		if ($confined !== $confined_base && !str_starts_with($confined, "{$confined_base}/")) {
			continue;
		}
		$paths[] = $normalized;
	}

	if ($deduplicate) {
		$paths = array_values(array_unique($paths));
	}
	sort($paths, SORT_STRING);
	return $paths;
}

function pfb_dnsbl_loaded_input_paths(array $pfb): array {
	$raw_files = pfb_unbound_py_manifest_raw_paths((string) ($pfb['unbound_py_sources'] ?? ''));
	$top1m_files = (($pfb['dnsbl_top1m'] ?? PfbToggle::Off) === PfbToggle::On)
		? array($pfb['unbound_py_top1m'] ?? '/var/unbound/pfb_py_top1m.txt') : array();
	return array_merge(
		array($pfb['unbound_py_wh'], $pfb['unbound_py_sources'], $pfb['unbound_py_hsts'], $pfb['unbound_py_psl']),
		$top1m_files,
		$raw_files
	);
}

/* issue #1255: the reload fingerprint. Thin wrapper -- ADR-65 retired
   unbound_py_data/unbound_py_zone as writer targets, so they are excluded from
   pfb_dnsbl_loaded_input_paths() unconditionally now; the TLD-mode-only narrowing this
   helper used to apply is gone (a no-op once the base path list never carries them).
   Pure (no global access). */
function pfb_dnsbl_reload_fingerprint(array $pfb): string {
	$paths = pfb_dnsbl_loaded_input_paths($pfb);
	$include = $pfb['dnsbl_psl_include_private'] ?? PfbToggle::On;
	$allow = $pfb['dnsbl_psl_allow_private'] ?? PfbToggle::Off;
	$include = $include instanceof PfbToggle ? $include->value : (is_bool($include) ? ($include ? 'on' : 'off') : (string) $include);
	$allow = $allow instanceof PfbToggle ? $allow->value : (is_bool($allow) ? ($allow ? 'on' : 'off') : (string) $allow);
	$paths[] = "\0pfb-psl-policy:include={$include}";
	$paths[] = "\0pfb-psl-policy:allow={$allow}";
	// issue #2371: salt the feed-at-suffix PSL policy fields too, same sentinel family.
	$feed_private_policy = $pfb['dnsbl_psl_feed_private_policy'] ?? PfbFeedSuffixPolicy::Honor;
	$feed_icann_policy = $pfb['dnsbl_psl_feed_icann_policy'] ?? PfbFeedSuffixPolicy::Honor;
	$feed_private_policy = $feed_private_policy instanceof PfbFeedSuffixPolicy ? $feed_private_policy->value : (string) $feed_private_policy;
	$feed_icann_policy = $feed_icann_policy instanceof PfbFeedSuffixPolicy ? $feed_icann_policy->value : (string) $feed_icann_policy;
	$paths[] = "\0pfb-psl-policy:feed_private={$feed_private_policy}";
	$paths[] = "\0pfb-psl-policy:feed_icann={$feed_icann_policy}";
	return pfb_dnsbl_loaded_fingerprint($paths);
}

/* TRUE iff genuine FEED-derived DNSBL content is currently loaded — i.e. at least one
   per-feed *.raw file in the rawdir. Deliberately EXCLUDES the shipped pfb_py_hsts, the
   always-present manifest/whitelist, and (ADR-65) a stale retired pfb_py_data.txt/
   pfb_py_zone.txt: none are feed-derived, and counting any of them makes a no-feed setup
   look "loaded" forever, triggering a clear+reload every cron pass (#546).
   Pure (no global access). */
function pfb_dnsbl_has_loaded_feeds(array $pfb): bool {
	foreach (pfb_unbound_py_manifest_raw_paths((string) ($pfb['unbound_py_sources'] ?? '')) as $raw_path) {
		if (is_file($raw_path) && is_readable($raw_path)) {
			return TRUE;
		}
	}
	return FALSE;
}

/* Return a stable fingerprint of the given input-file set.
   A missing/unreadable file contributes '-' so that all-missing == all-missing (equal),
   and a first-seen file vs no-file produces a difference. Path list is sorted so
   glob order differences never cause false positives. Pure (read-only fs). */
function pfb_dnsbl_loaded_fingerprint(array $paths): string {
	sort($paths, SORT_STRING);
	$parts = array();
	foreach ($paths as $path) {
		if ($path === '') {
			continue;
		}
		if (str_starts_with($path, "\0pfb-psl-policy:")) {
			$parts[] = $path;
			continue;
		}
		$parts[] = $path . ':' . (@md5_file($path) ?: '-');
	}
	return md5(implode("\n", $parts));
}

/* DNSBLIP rebuild gate (issue #653). DNSBLIP_<fam> is the union of the *_v<fam>.ip files (the IPs
   extracted from the DNSBL feeds). Rebuilding + re-filtering it on every IP update is wasteful when
   no source .ip changed. Decide via a content fingerprint of the .ip source set (ADR-42 style --
   mtime-agnostic, since a .ip file may be rewritten with identical content): rebuild iff the output
   is missing, the stored fingerprint is missing, or the current fingerprint differs. Returns
   [bool $rebuild, string $fp_now]; the caller persists $fp_now beside the output on a rebuild.
   Pure (read-only fs on the given paths). */
function pfb_dnsblip_rebuild_check(string $output, array $ip_files, string $fp_path): array {
	$fp_now  = pfb_dnsbl_loaded_fingerprint($ip_files);
	$rebuild = !is_file($output)
		|| !is_file($fp_path)
		|| trim((string) @file_get_contents($fp_path)) !== $fp_now;
	return array($rebuild, $fp_now);
}

// Resolve the working folder a DNSBLIP feed lands in from its configured action
// ($pfb['dnsbl_ip']). This is the SAME action -> folder routing the IP-feed loop applies
// via pfb_determine_list_detail() (Deny_*/Alias_Deny -> denydir, Alias_Native -> nativedir),
// so the reprocess marker and the loop's reprocess gate agree on the folder. Returns ''
// for a non-routable action (e.g. 'Disabled'). (#655)
function pfb_dnsblip_action_folder($action): string {
	global $pfbarr;
	if (!pfb_group_action_valid($action, 'ipv4')) {
		return '';
	}
	// key 0 + the DNSBL settings section mirror what the IP loop passes for DNSBLIP,
	// so the force-Native override (Advanced Invert) routes identically here.
	pfb_determine_list_detail($action, 'DNSBLIP', 'pfblockerngdnsblsettings', 0);
	return (string) ($pfbarr['folder'] ?? '');
}

// Write the DNSBLIP '.update' reprocess marker into the folder that matches the feed's
// configured action, NOT a hardcoded denydir. With $pfb['dnsbl_ip'] = 'Alias_Native' the
// feed loop looks in nativedir; a denydir marker was never seen there, so a changed
// Alias_Native DNSBLIP fell into the "exists" branch and was not reprocessed. (#655)
function pfb_dnsblip_mark_reprocess($action, string $vtype): void {
	$folder = pfb_dnsblip_action_folder($action);
	if ($folder !== '') {
		touch("{$folder}/DNSBLIP{$vtype}.update");
	}
}

// DNSBLIP v4/v6 post-build bookkeeping (.fp stamp / ip_cache flush / reprocess marker).
// issue #1097: a failed rebuild ($built = FALSE) must NOT advance the fingerprint -- a
// stamped .fp marks the stale output current and suppresses every future retry.
function pfb_dnsblip_finalize(string $dnsblip, string $fp, bool $built, string $ip_cache, $action, string $vtype): void {
	if (!$built) {
		return;
	}
	@file_put_contents("{$dnsblip}.fp", $fp, LOCK_EX);
	unlink_if_exists($ip_cache);
	pfb_dnsblip_mark_reprocess($action, $vtype);
}

// Only an exact full-length fwrite() counts as written -- FALSE or a short (disk-full)
// write must fail the assembly, or a truncated destination would advance the rebuild
// bookkeeping as current. Same rule as pfb_prefetch_pattern_file_write_ok().
function pfb_dnsbl_concat_write_ok($written, string $line): bool {
	return $written !== FALSE && $written === strlen($line);
}

// issue #1097: fwrite(FALSE)/fclose(FALSE) throw TypeError on PHP 8 ('@' only
// silences warnings) -- guard both the destination and each source open. An
// empty $src is skipped before fopen(): PHP 8 throws ValueError for it too.
function pfb_dnsbl_concat_files(string $dest, array $sources): bool {
	if (($out = @fopen($dest, 'w')) !== FALSE) {
		foreach ($sources as $src) {
			$src = (string) $src;
			if ($src !== '' && ($in = @fopen($src, 'r')) !== FALSE) {
				while (($line = @fgets($in)) !== FALSE) {
					if (!pfb_dnsbl_concat_write_ok(@fwrite($out, $line), $line)) {
						@fclose($in);
						@fclose($out);
						// issue #1275: fopen() above already truncated $dest -- leaving it
						// behind stalls every retry gate that checks file_exists($dest).
						unlink_if_exists($dest);
						pfb_logger("\nDNSBL: write failed for [ {$dest} ] -- assembly aborted", 2);
						return FALSE;
					}
				}
				@fclose($in);
			}
		}
		@fclose($out);
		return TRUE;
	}
	pfb_logger("\nDNSBL: failed to open [ {$dest} ] for writing", 2);
	return FALSE;
}

// Non-lite DNSBL host-munging pipeline, extracted pure out of the download/parse loop's
// `if (!$lite)` branch. Order is load-bearing: scheme strip -> '/'/'#'/'?' truncation ->
// ';'-truncation -> trailing-port strip -> IPv6-unbracket LAST. Returns FALSE when
// pfb_dnsbl_scheme_line rejects (strict mode) -- caller must skip the line.
function pfb_dnsbl_extract_host(string $line, bool $strict, string $header, string $oline,
	int $dnsbl_lineno, string $parse_err, int &$scheme_skipped): string|false {

	// ADR-22: strip the '<scheme>://' prefix. Lenient (toggle ON, the migrated/legacy
	// default) keeps today's permissive strip; strict (toggle OFF, the new-install default)
	// validates the scheme against RFC 3986 and rejects URL paths -- a rejected line is
	// skipped, recorded per-line in the parse-error log, and counted for the once-per-feed
	// summary WARNING below.
	$line = pfb_dnsbl_scheme_line($line, $strict, $header, $oline, $dnsbl_lineno, $parse_err,
		$scheme_skipped);
	if ($line === FALSE) {
		return FALSE;
	}

	// If '/' character found, remove characters after '/'
	if (strpos($line, '/') !== FALSE) {
		$line = strstr($line, '/', TRUE);
	}

	// If '#' character found, remove characters after '#'
	if (strpos($line, '#') !== FALSE) {
		$line = strstr($line, '#', TRUE);
	}

	// If '?' character found, remove characters after '?'
	if (strpos($line, '?') !== FALSE) {
		$line = strstr($line, '?', TRUE);
	}

	// issue #1237: parse_url()'s scheme-less host:port heuristic (no '//' authority needed)
	// mis-picked 'host;param:digits' as a hostname, keeping the ';param' remainder in it.
	if (strpos($line, ';') !== FALSE) {
		$line = strstr($line, ';', TRUE);
	}

	// Remove any Port numbers at end of line (IPv6-safe:
	// never mangle a bare IPv6 literal's trailing hextet).
	$line = pfb_strip_trailing_port($line);

	// Issue #938: unwrap a bracketed IPv6 literal (e.g. a
	// URI-style '[2604:2dc0::]') so the is_ipaddrv6($line)
	// collection branch below recognises it.
	return pfb_dnsbl_unbracket_ip6($line);
}

/**
 * DNSBL interchange rows are compact tagged arrays: ["d", domain] or ["a", raw].
 * The reader also accepts schema-v1 objects for upgrade compatibility.
 */
enum PfbDnsblRowKind: string
{
	case Domain = 'd';
	case Abp    = 'a';
}

function pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind $kind, string $payload): string {
	return json_encode(
		array($kind, $payload),
		JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
	) . "\n";
}

function pfb_dnsbl_ndjson_parse_row(string $line): ?array {
	$row = json_decode($line, TRUE);
	if (!is_array($row)) {
		return NULL;
	}
	$trimmed = ltrim($line);
	if (str_starts_with($trimmed, '[')) {
		if (count($row) !== 2 || array_keys($row) !== [0, 1] || !is_string($row[0]) ||
			!is_string($row[1]) || $row[1] === '') {
			return NULL;
		}
		$kind = PfbDnsblRowKind::tryFrom($row[0]);
		return match ($kind) {
			PfbDnsblRowKind::Domain => ['kind' => $kind, 'domain' => $row[1]],
			PfbDnsblRowKind::Abp    => ['kind' => $kind, 'raw' => $row[1]],
			NULL                     => NULL,
		};
	}
	if (!str_starts_with($trimmed, '{') || !array_key_exists('kind', $row)) {
		return NULL;
	}
	$kind = match ($row['kind']) {
		'domain' => PfbDnsblRowKind::Domain,
		'abp'    => PfbDnsblRowKind::Abp,
		default  => NULL,
	};
	if ($kind === NULL) {
		return NULL;
	}
	$required = match ($kind) {
		PfbDnsblRowKind::Domain => array('domain', 'log', 'feed', 'group'),
		PfbDnsblRowKind::Abp    => array('raw'),
	};
	foreach ($required as $key) {
		if (!isset($row[$key]) || !is_string($row[$key]) || $row[$key] === '') {
			return NULL;
		}
	}
	$row['kind'] = $kind;
	return $row;
}

// DNSBLIP's "download" is a local-file copy of a just-rebuilt source, not a network
// fetch -- the reuse-skip optimization (meant for real feeds) must never apply to it,
// or a same-pass rebuild is silently stranded until the next .ip source change. (#1002)
function pfb_ip_reuse_skip_active(bool $reuse_on, bool $orig_exists, bool $is_dnsblip): bool {
	return $reuse_on && $orig_exists && !$is_dnsblip;
}

// A stale-.orig download-failure fallback never refreshed the row's content, so the
// '.update' reprocess marker must survive it -- else a pending rebuild/refresh is
// stranded exactly like #1002, but reached via the download-failure path. (#1022)
function pfb_ip_update_marker_clear_active(bool $orig_content_stale): bool {
	return !$orig_content_stale;
}

// A stale-.orig download-failure fallback in the DNSBL-domain loop (e.g. a Blacklist
// category row's local-file re-read) never refreshed the row's content, so the
// '.update' reprocess marker must survive it, same class as #1022. (#1031)
function pfb_dnsbl_update_marker_clear_active(bool $orig_content_stale): bool {
	return !$orig_content_stale;
}

// #1083: a field box upgrading with a pre-NDJSON staging .txt (a feed never
// redownloaded since the flip) must not verbatim-reuse it -- every interchange
// reader now expects NDJSON and would silently skip every old-dialect line. A
// leading JSON delimiter alone is not proof (e.g. a truncated/corrupt line);
// this actually PARSES the line via the compact-plus-legacy reader (one json_decode per
// feed per pass) -- an empty/absent file has no stale content to misread either.
function pfb_dnsbl_staging_is_current_generation(string $first_line): bool {
	return $first_line === '' || pfb_dnsbl_ndjson_parse_row($first_line) !== NULL;
}

// Reads $path's first NON-BLANK line for pfb_dnsbl_staging_is_current_generation();
// '' for an absent file or one with no non-blank line (both current-generation --
// nothing stale to reject). issue #1083: a blank leading physical line must
// not mask stale content on the line(s) after it.
function pfb_dnsbl_staging_first_line(string $path): string {
	$fh = @fopen($path, 'r');
	if ($fh === FALSE) {
		return '';
	}
	while (($line = fgets($fh)) !== FALSE) {
		$line = rtrim($line, "\r\n");
		if ($line !== '') {
			fclose($fh);
			return $line;
		}
	}
	fclose($fh);
	return '';
}

// The DNSBL verbatim-reuse fork (pfblockerng.inc sync loop): skip re-parsing
// entirely and reuse the existing staged '.txt' as-is. All five conditions must
// hold, including that the staging content is current-generation (#1083) --
// else a pre-NDJSON '.txt' would be reused forever on a never-redownloaded feed.
function pfb_dnsbl_verbatim_reuse_active(bool $txt_exists, bool $update_exists, bool $fail_exists,
	bool $reuse_unset, bool $staging_current_generation): bool
{
	return $txt_exists && !$update_exists && !$fail_exists && $reuse_unset && $staging_current_generation;
}

// issue #1797: skip the DNSBL reparse when a FRESH download normalized to
// byte-identical content -- upstream churn that normalizes away (CRLF flips,
// trailing whitespace, a BOM) rebuilds nothing. Deliberately narrow: only a
// completed non-custom download qualifies (a Reload/Force pass must keep its
// reparse-everything semantics; a custom list re-synthesizes per pass; a
// stale-.orig download-failure fallback stays fail-safe like #1022/#1031),
// and only onto a current-generation staged '.txt' (#1083). issue #1926: a
// configured pre/post script never skips either -- its contract is a full
// pass over the normalized output every run.
function pfb_dnsbl_norm_reuse_skip(bool $downloaded_fresh, bool $custom, bool $orig_content_stale,
	bool $norm_changed, bool $txt_exists, bool $staging_current_generation, bool $has_user_script): bool
{
	return $downloaded_fresh && !$custom && !$orig_content_stale && !$norm_changed &&
		$txt_exists && $staging_current_generation && !$has_user_script;
}

// issue #1797: the IP-loop counterpart of pfb_dnsbl_norm_reuse_skip(). Feeds
// carrying a user pre/post script never skip -- the scripts' contract is a
// full pass over the downloaded file every run.
function pfb_ip_norm_reuse_skip(bool $downloaded_fresh, bool $custom, bool $orig_content_stale,
	bool $norm_changed, bool $txt_exists, bool $has_user_script): bool
{
	return $downloaded_fresh && !$custom && !$orig_content_stale && !$norm_changed &&
		$txt_exists && !$has_user_script;
}

// issue #1083: a stale-generation rebuild ($stale_generation_rebuild, above) that
// reparses '.orig' and finds ZERO domains must converge staging to empty -- else the
// pre-NDJSON '.txt' is never touched, its stale lines are silently double-counted, and
// the guard re-detects stale-generation (re-logs 'Rebuild') on every subsequent pass. A
// non-stale-generation zero-domain result keeps its existing '.txt' (the pre-existing
// fail-safe, unaffected). The caller's shared placeholder step (touch if absent) then
// creates the current-generation empty file this unlink makes room for.
function pfb_dnsbl_stale_rebuild_converge_txt(bool $stale_generation_rebuild, string $txt_path): void {
	if ($stale_generation_rebuild) {
		unlink_if_exists($txt_path);
	}
}

// issue #1278: Hold means "download once, never again" (mirrors pfblockerng.php's
// Hold bypass) -- a stale-generation rebuild (#1083) must never fall through to the
// network when no '.orig' baseline survives to reparse locally.
function pfb_dnsbl_hold_stale_rebuild_skip(bool $stale_generation_rebuild, bool $is_hold, bool $orig_exists): bool {
	return $stale_generation_rebuild && $is_hold && !$orig_exists;
}

// v6 stays OPTIONAL (ADR-13 §7 pivot): a missing v6 VIP never fails validation, even when
// the resolver listens on IPv6 — pfb_global surfaces that as a non-blocking warning, not a
// force-disable. The validator only checks the VIPs that ARE configured (existence,
// interface, overlap). Behaviour is identical to before the (reverted) hard rule.
function pfb_validate_vips(string $interface, string|null $vip4 = '', string|null $vip6 = ''): array {
	$enabled4 = !empty($vip4);
	$enabled6 = !empty($vip6);

	if (!$enabled4 && !$enabled6) {
		return [FALSE, gettext('no VIP configured')];
	}

	if ($enabled4 && ($interface != get_configured_vip_interface($vip4))) {
		return [FALSE, sprintf(gettext('IPv4 VIP not found on interface %s'), convert_friendly_interface_to_friendly_descr($interface))];
	}
	if ($enabled6 && ($interface != get_configured_vip_interface($vip6))) {
		return [FALSE, sprintf(gettext('IPv6 VIP not found on interface %s'), convert_friendly_interface_to_friendly_descr($interface))];
	}

	$vips = pfb_get_vips();
	if ($enabled4) {
		if (!isset($vips['v4'][$vip4])) {
			return [FALSE, gettext('invalid IPv4 VIP')];
		} elseif (count(where_is_ipaddr_configured(get_configured_vip_ipv4($vip4), '' , TRUE, TRUE, ''))) {
			return [FALSE, gettext('IPv4 VIP overlaps with an existing subnet')];
		}
	}
	if ($enabled6) {
		if (!isset($vips['v6'][$vip6])) {
			return [FALSE, gettext('invalid IPv6 VIP')];
		} elseif ($enabled6 && count(where_is_ipaddr_configured(get_configured_vip_ipv6($vip6), '' , TRUE, TRUE, ''))) {
			return [FALSE, gettext('IPv6 VIP overlaps with an existing subnet')];
		}
	}

	return [TRUE, null];
}

// [ADR-13] (issue #473 / #487) Fixed ordered candidate sinkhole VIP list per family, each a
// DNS-port-homage .53 host; IPv4 ordered least-used RFC1918 first (Class B, C, then A). IPv6:
// single ULA fd00:53:53:53:53:53:53:53/128 — on conflict the picker returns null and the user
// resolves it manually. pfb_pick_free_dnsbl_vip() returns the first free candidate. Pure.
function pfb_dnsbl_vip_candidates(int $family): array {

	if ($family === AF_INET) {
		return ['172.16.53.53', '192.168.53.53', '10.53.53.53'];
	} elseif ($family === AF_INET6) {
		return ['fd00:53:53:53:53:53:53:53'];
	}

	return [];
}

// [ ADR-13 ] Return the first candidate sinkhole address (pfb_dnsbl_vip_candidates)
// for the given family that is free to use as an auto-created DNSBL VIP, or null if
// every candidate conflicts. A candidate is free iff it is (a) not already an
// existing IP-Alias VIP (pfb_get_vips) and (b) overlaps no configured subnet
// (where_is_ipaddr_configured) — the SAME overlap semantics pfb_validate_vips uses
// (inc:746/:753). Pure: enumerates state, creates/changes nothing. $interface is
// accepted for parity with the create path and future per-interface scoping; the
// conflict checks here are interface-independent (a VIP/subnet conflict anywhere is
// disqualifying).
function pfb_pick_free_dnsbl_vip(int $family, string $interface): ?string {

	$candidates = pfb_dnsbl_vip_candidates($family);
	if (empty($candidates)) {
		return null;
	}

	// Existing IP-Alias VIP addresses for this family (values are the addresses).
	$vips = pfb_get_vips();
	if ($family === AF_INET) {
		$existing = $vips['v4'];
	} elseif ($family === AF_INET6) {
		$existing = $vips['v6'];
	} else {
		return null;
	}
	$existing_addresses = array_values($existing);

	foreach ($candidates as $candidate) {
		// (a) Not an address already used by an existing VIP.
		if (in_array($candidate, $existing_addresses, TRUE)) {
			continue;
		}
		// (b) Does not overlap any configured subnet (interface IPs, other VIPs,
		// etc.) — same call shape as pfb_validate_vips.
		if (count(where_is_ipaddr_configured($candidate, '', TRUE, TRUE, ''))) {
			continue;
		}
		return $candidate;
	}

	return null;
}

// [ADR-13] True iff Unbound is configured to listen on IPv6. Mirrors unbound_generate_config_text()
// (src/etc/inc/unbound.inc) — verified verbatim against upstream at RELENG_2_7_2 and master.
// Predicate: resolver disabled -> false; active_interface empty/'all' -> 'interface-automatic:
// yes', true iff ANY enabled interface currently has a v6 address; else true iff ANY listed
// token is a v6 literal or an interface resolving to v6 (mirrors upstream's bind loop, incl.
// the up/enabled guard from redmine #11087). MUST be confirmed on-box (no PHP/Unbound runtime
// in CI): that an automatic bind's v6 is routable (not link-local only), and that
// 'interface-automatic: yes' does accept v6 queries. Not yet wired into the v6-mandatory rule.
function pfb_unbound_listens_v6(): bool {

	// A disabled resolver listens on nothing.
	if (!config_path_enabled('unbound')) {
		return FALSE;
	}

	$active_interface = config_get_path('unbound/active_interface', '');
	$active_interfaces = array_filter(explode(',', (string) $active_interface));

	// Empty or 'all' => 'interface-automatic: yes' => bind every address on the
	// enabled interfaces. v6 is listened-on iff any configured interface has a v6.
	if (empty($active_interfaces) || in_array('all', $active_interfaces, TRUE)) {
		foreach (array_keys(get_configured_interface_list()) as $ubif) {
			if (is_ipaddrv6(get_interface_ipv6($ubif))) {
				return TRUE;
			}
		}
		return FALSE;
	}

	// Explicit interface list: mirror unbound_generate_config_text()'s bind loop.
	foreach ($active_interfaces as $ubif) {
		// Skip interfaces that are down/disabled (redmine #11087), same as upstream.
		$ifinfo = get_interface_info($ubif);
		if ($ifinfo && (($ifinfo['status'] != 'up') || !$ifinfo['enable'])) {
			continue;
		}
		// A literal IPv6 address binds directly.
		if (is_ipaddrv6($ubif)) {
			return TRUE;
		}
		// An interface name resolves to its v6 address (if any).
		if (is_ipaddrv6(get_interface_ipv6($ubif))) {
			return TRUE;
		}
	}

	return FALSE;
}

// [ADR-13] Locate the index of the auto-managed DNSBL VIP this package owns inside a
// virtualip/vip array. Pure. Ownership requires BOTH: (1) MARKER — pfb_is_managed_obj($descr)
// AND a prefix/contains match against PFB_AUTO_VIP_DESCR_V4/V6 (same logic as
// pfb_find_managed_obj); (2) IP MATCH — when $match_ip is non-empty, $vip['subnet'] must equal
// it (binds delete to the address currently resolved from stored config, so a marked VIP whose
// address no longer matches is never deleted). Pass null to match on the marker alone (create).
function pfb_find_marked_vip(array $vips_config, string $marker, ?string $match_ip): ?int {
	$use_prefix = str_starts_with($marker, PFB_MANAGED_FILTER_PFX);
	foreach ($vips_config as $idx => $vip) {
		$descr = $vip['descr'] ?? '';
		if (!pfb_is_managed_obj($descr)) {
			continue;
		}
		$marker_match = $use_prefix
			? str_starts_with($descr, $marker)
			: str_contains($descr, $marker);
		if (!$marker_match) {
			continue;
		}
		if ($match_ip !== null && $match_ip !== '' && ($vip['subnet'] ?? '') !== $match_ip) {
			continue;
		}
		if (is_int($idx)) {
			return $idx;
		}
	}
	return null;
}

// [ADR-13] VIP lifecycle manager: creates the marked DNSBL sinkhole VIP(s) on enable (auto
// on), removes ONLY the marked + IP-matched VIP(s) on disable/unmanaged. ADDITIVE: with
// pfb_dnsvip_auto never turned on, no marked VIP is found -> no write_config -> byte-identical
// runtime. Delete guard: removed iff descr == PFB_AUTO_VIP_DESCR_V4/_V6 AND subnet == the
// address resolved from stored pfb_dnsvip4/6 (pfb_find_marked_vip) — a manual or
// address-drifted VIP is NEVER deleted. Apply order matches upstream firewall_virtual_ip.inc.
// PFBL-01: $interface must pass pfb_filter(PFB_FILTER_WORD) before use, else the run aborts;
// pinned by tests/php/PfbFilterContractTest.php.
function pfb_manage_dnsbl_vip(string $mode): void {
	global $pfb;

	// Only the two lifecycle modes drive VIP management; anything else is a no-op.
	if ($mode !== 'enabled' && $mode !== 'disabled') {
		return;
	}

	$auto      = ($pfb['dnsbl_vip_auto'] ?? PfbToggle::Off) === PfbToggle::On;
	$interface = $pfb['dnsbl_iface'] ?? 'lo0';

	// PFBL-01: $interface is a singular required parameter -- validate it as a \w-only
	// friendly interface name before anything else runs. On failure: log + abort the
	// whole run (no config read/write, no VIP operation).
	if (empty(pfb_filter($interface, PFB_FILTER_WORD, 'pfb_manage_dnsbl_vip'))) {
		pfb_logger("\npfb_manage_dnsbl_vip: DNSBL VIP interface failed validation [ " .
			substr(htmlspecialchars((string) $interface), 0, 100) . " ] *aborting*", 2);
		return;
	}

	$dnsblcfg_path = 'installedpackages/pfblockerngdnsblsettings/config/0';

	// NOTE: the enabled+auto-OFF case deliberately does NOT early-return. It falls through
	// so the delete branch below can clean up a previously auto-created VIP when the admin
	// switches auto-create back to manual (ADR-13 §2: "whenever a VIP is no longer managed
	// (auto turned off ...) delete the VIP(s)"). For a setup that never used auto-create
	// there is no marker+IP-matched VIP, so nothing changes -> byte-identical to today.

	// Families to provision when creating. v4 is always managed. v6 is managed when a
	// v6 VIP is already requested (an id stored) or the resolver listens on IPv6
	// (provisioned here; not yet made mandatory in that case).
	$want_v6 = !empty($pfb['dnsblconfig']['pfb_dnsvip6']) || pfb_unbound_listens_v6();

	// Per-family descriptor table: marker, AF, subnet_bits, the stored-id config key.
	$families = [
		[
			'marker'   => PFB_AUTO_VIP_DESCR_V4,
			'family'   => AF_INET,
			'bits'     => 32,
			'idkey'    => 'pfb_dnsvip4',
			'managed'  => ($mode === 'enabled' && $auto),	// v4 always managed on create
		],
		[
			'marker'   => PFB_AUTO_VIP_DESCR_V6,
			'family'   => AF_INET6,
			'bits'     => 128,
			'idkey'    => 'pfb_dnsvip6',
			'managed'  => ($mode === 'enabled' && $auto && $want_v6),
		],
	];

	$vips_config = config_get_path('virtualip/vip', []);
	$dnsblconfig = config_get_path($dnsblcfg_path, []);
	$changed     = FALSE;

	foreach ($families as $fam) {
		if ($fam['managed']) {
			// CREATE / ENSURE (idempotent). Reuse an existing marked VIP if present
			// (match on marker alone — its address is whatever we created earlier),
			// else pick a free candidate and create one.
			$idx = pfb_find_marked_vip($vips_config, $fam['marker'], null);
			if ($idx !== null) {
				$vip    = $vips_config[$idx];
				$uniqid = $vip['uniqid'] ?? uniqid();
				if (!isset($vip['uniqid'])) {
					$vips_config[$idx]['uniqid'] = $uniqid;
					$changed = TRUE;
				}
				// Reconcile the interface: if dnsbl_interface changed while auto stayed on, a
				// reused VIP would otherwise keep its old interface and pfb_validate_vips()
				// would force-disable DNSBL on the mismatch. Bring the stale alias down and
				// repoint it (the apply block below re-adds it live on the configured interface).
				if (($vip['interface'] ?? '') !== $interface) {
					interface_vip_bring_down($vips_config[$idx]);
					$vips_config[$idx]['interface'] = $interface;
					$changed = TRUE;
				}
			} else {
				$address = pfb_pick_free_dnsbl_vip($fam['family'], $interface);
				if ($address === null) {
					// No free candidate -> do not create; leave config as-is and log.
					pfb_logger("\nDNSBL auto-VIP: no free {$fam['marker']} address available; not created", 1);
					continue;
				}
				$uniqid = uniqid();
				$vips_config[] = [
					'mode'        => 'ipalias',
					'interface'   => $interface,
					'type'        => 'single',
					'subnet'      => $address,
					'subnet_bits' => (string) $fam['bits'],
					'descr'       => $fam['marker'],
					'uniqid'      => $uniqid,
				];
				$changed = TRUE;
				pfb_logger("\nDNSBL auto-VIP: created {$fam['marker']} at {$address}/{$fam['bits']} on {$interface}", 1);
			}

			// Point the stored DNSBL settings id at this VIP.
			$vip_id = "_vip{$uniqid}";
			if (($dnsblconfig[$fam['idkey']] ?? '') !== $vip_id) {
				$dnsblconfig[$fam['idkey']] = $vip_id;
				$changed = TRUE;
			}
		} else {
			// DELETE (marker + IP-match only). The address must match what the stored
			// config currently resolves to, so we never delete a marked VIP that is no
			// longer the one our config points at, and never an unmarked VIP.
			$match_ip = ($fam['family'] === AF_INET)
				? (string) (get_configured_vip_ipv4($dnsblconfig[$fam['idkey']] ?? '') ?? '')
				: (string) (get_configured_vip_ipv6($dnsblconfig[$fam['idkey']] ?? '') ?? '');

			if ($match_ip === '') {
				continue;
			}

			// Double-guard: marker match AND subnet must equal the stored resolved IP.
			// Use pfb_find_managed_obj with the guard to locate the row, then
			// pfb_remove_managed_obj with the same guard to strip it from config.
			$guard     = static function(array $row) use ($match_ip): bool {
				return ($row['subnet'] ?? '') === $match_ip;
			};
			$found_row = pfb_find_managed_obj('virtualip/vip', $fam['marker'], $guard);
			if ($found_row === FALSE) {
				continue;
			}

			// Bring the alias down live, then drop it from config via the shared helper.
			interface_vip_bring_down($found_row);
			pfb_logger("\nDNSBL auto-VIP: removed {$fam['marker']} at {$match_ip}", 1);
			pfb_remove_managed_obj('virtualip/vip', $fam['marker'], $guard);
			// Re-sync $vips_config from global config (pfb_remove_managed_obj wrote it back).
			$vips_config = config_get_path('virtualip/vip', []);

			if (!empty($dnsblconfig[$fam['idkey']])) {
				unset($dnsblconfig[$fam['idkey']]);
			}
			$changed = TRUE;
		}
	}

	if (!$changed) {
		return;
	}

	// Apply order mirrors upstream firewall_virtual_ip.inc: persist config first,
	// then bring the alias(es) up.
	config_set_path('virtualip/vip', $vips_config);
	config_set_path($dnsblcfg_path, $dnsblconfig);
	write_config('pfBlockerNG: saving DNSBL auto-VIP changes');

	// Apply any created/ensured marked VIP live (config-first, then configure).
	if ($mode === 'enabled' && $auto) {
		foreach ($families as $fam) {
			if (!$fam['managed']) {
				continue;
			}
			$idx = pfb_find_marked_vip($vips_config, $fam['marker'], null);
			if ($idx !== null) {
				$vip = $vips_config[$idx];
				interface_ipalias_configure($vip);
			}
		}
	}

	// Refresh $pfb so callers (NAT create) see the resolved VIP addresses.
	pfb_global();
}

// Validate length of labels (Max of 63 chars)
function pfb_validate_domain_labels($input) {

	$labels = explode('.', $input);
	if (!empty($labels) && is_array($labels)) {
		foreach ($labels as $label) {
			if (strlen($label) > 63) {
				return FALSE;
			}
		}
		return TRUE;
	}
	return FALSE;
}


// Field-aware MaxMind credential notice. MaxMind GeoLite2 requires BOTH an
// Account ID and a License Key. Returns the notice naming the missing field(s),
// or '' when both are present.
function pfb_maxmind_credential_notice(string $maxmind_key, string $maxmind_account): string {
	$key_missing     = ($maxmind_key === '');
	$account_missing = ($maxmind_account === '');
	if (!$key_missing && !$account_missing) {
		return '';
	}
	if ($key_missing && $account_missing) {
		$need = 'an Account ID and License Key';
	} elseif ($account_missing) {
		$need = 'an Account ID';
	} else {
		$need = 'a License Key';
	}
	return "MaxMind now requires {$need}! Review the IP tab: MaxMind settings for more information.";
}


// [ $pfb ] pfBlockerNG global array. This needs to be called to get the updated settings.
function pfb_global() {
	global $g, $pfb;

	// Create folders if not exist.
	foreach ($pfb['folder_array'] as $folder) {
		safe_mkdir("{$folder}", 0755);
	}

	// Reload config.xml to get any recent changes
	config_read_file(FALSE, TRUE);

	// General variables — registered sections read through the gateway (ADR-29).
	$pfb['config']		= PfbConfig::readSection('installedpackages/pfblockerng/config/0');
	$pfb['ipconfig']	= config_get_path('installedpackages/pfblockerngipsettings/config/0', []);
	$pfb['dnsblconfig']	= PfbConfig::readSection('installedpackages/pfblockerngdnsblsettings/config/0');
	$pfb['blconfig']	= config_get_path('installedpackages/pfblockerngblacklist', []);
	$pfb['config_global']	= config_get_path('installedpackages/pfblockerngglobal', []);

	$pfb['enable']		= PfbConfig::read('gen/enable_cb');		// Enable/Disable of pfBlockerNG
	$pfb['keep']		= PfbConfig::read('gen/pfb_keep');		// Keep blocklists on pfBlockerNG Disable (default ON via registry; #281)

	// ADR-11: opt-in per-type aggregate ("Uber") aliases. CSV scalar of the action types
	// to aggregate (subset of Deny/Permit/Match/Native), default NONE -> [] -> no-op pass.
	// CSV (a single string, like blacklist_selected) so it round-trips with no '<0>' list XML.
	$pfb['agg_types']	= array_values(array_intersect(
					array('Deny', 'Permit', 'Match', 'Native'),
					array_filter(explode(',', PfbConfig::read('gen/pfb_agg_types')))));

	$pfb['supp']		= PfbConfig::read('ip/suppression');					// Enable Suppression (default on, issue #1907)
	$pfb['cc']		= PfbConfig::read('ip/database_cc') === PfbToggle::On;	// Disable Country database CRON updates
	$pfb['maxmind_locale']	= $pfb['ipconfig']['maxmind_locale']	?: 'en';	// MaxMind Localized Language setting
	$pfb['asn_reporting']	= $pfb['ipconfig']['asn_reporting']	?: 'disabled';	// ASN Reporting
	$pfb['asn_token']	= $pfb['ipconfig']['asn_token']		?: '';		// ASN Token (IPinfo)
	$pfb['rdns']		= pfb_resolve_enabled();					// Reverse-DNS lookup for block-log entries (issue #336)

	$pfb['maxmind_account']	= pfb_filter($pfb['ipconfig']['maxmind_account'], PFB_FILTER_WORD, 'pfb_global')	?: '';		// Maxmind Account ID
	$pfb['maxmind_key']	= pfb_filter($pfb['ipconfig']['maxmind_key'], PFB_FILTER_WORD, 'maxmind_key')		?: '';		// Maxmind License Key (issue #924: log-safe reference -- a rejected key is never logged on this consumer path either)

	$pfb['dnsbl']		= PfbConfig::read('dnsbl/pfb_dnsbl');							// Enabled state of DNSBL
	$pfb['dnsbl_vip_auto']	= PfbConfig::read('dnsbl/pfb_dnsvip_auto');						// [ ADR-13 ] Auto-create/remove the DNSBL sinkhole VIP(s) (default off)
	$pfb['dnsbl_nonat']	= PfbConfig::read('dnsbl/pfb_dnsbl_nonat');						// [ #381 ] Opt out of automatic DNSBL NAT rule generation (default off)
	$pfb['dnsbl_vip4'] = get_configured_vip_ipv4($pfb['dnsblconfig']['pfb_dnsvip4']) ?? '';
	$pfb['dnsbl_vip6'] = get_configured_vip_ipv6($pfb['dnsblconfig']['pfb_dnsvip6']) ?? '';
	$pfb['dnsbl_iface']	= PfbConfig::read('dnsbl/dnsbl_interface');							// VIP Local Interface setting (default 'lo0')
	if ($pfb['dnsbl'] === PfbToggle::On) {
		// VIP validation: force-disable DNSBL on a genuinely invalid/missing/overlapping
		// VIP — UNLESS auto-create mode is active, in which case pfb_manage_dnsbl_vip()
		// owns provisioning and will (re)create a valid VIP during this same update pass.
		// Disabling DNSBL here in auto mode would prevent the bootstrap from ever running.
		$vips_valid_result = pfb_validate_vips($pfb['dnsbl_iface'], $pfb['dnsblconfig']['pfb_dnsvip4'], $pfb['dnsblconfig']['pfb_dnsvip6']);
		if (!$vips_valid_result[0]) {
			if ($pfb['dnsbl_vip_auto'] === PfbToggle::On) {
				// [ ADR-13 / issue #487 ] Auto-create OWNS the DNSBL sinkhole VIP:
				// pfb_manage_dnsbl_vip() (re)provisions a valid VIP on the configured
				// interface during this same update pass. A stale / missing / wrong-interface
				// manual reference must NOT force-disable DNSBL here, or the auto bootstrap
				// can never run (mode would compute to 'disabled' and creation would be skipped).
				pfb_logger("\nDNSBL auto-VIP: VIP validation deferred to auto-create ({$vips_valid_result[1]})", 1);
			} else {
				// Manual mode: a genuinely invalid/missing/mismatched VIP disables DNSBL.
				$pfb['dnsbl'] = PfbToggle::Off;
				$vip_notice = "DNSBL disabled: {$vips_valid_result[1]}";
				pfb_logger("\n{$vip_notice}", 1);
				// issue #331: this was log-only, invisible in the GUI. Surface it like
				// the MaxMind/ASN credential notices below.
				file_notice('pfBlockerNG DNSBL', $vip_notice, 'pfBlockerNG', '/pfblockerng/pfblockerng_dnsbl.php', 2);
			}
		} elseif (pfb_dnsbl_v6_vip_required(pfb_unbound_listens_v6(), ($pfb['dnsbl_vip_auto'] === PfbToggle::On)) && empty($pfb['dnsblconfig']['pfb_dnsvip6'])) {
			// [ ADR-13 §7 pivot ] NON-BLOCKING: the resolver listens on IPv6 but no v6
			// sinkhole VIP is configured (manual mode). DNSBL stays enabled on IPv4;
			// AAAA blocks simply are not sinkholed. Recommend auto-create or a v6 VIP.
			// (In auto mode pfb_manage_dnsbl_vip provisions the v6 VIP, so this never fires.)
			pfb_logger("\nDNSBL: the DNS Resolver listens on IPv6 but no IPv6 sinkhole VIP is configured; AAAA blocks will not be sinkholed. Enable 'Create VIPs automatically' or add an IPv6 VIP.", 1);
		}
	}

	$pfb['dnsbl_port']	= $pfb['dnsblconfig']['pfb_dnsport'];									// Lighttpd web server http port setting
	$pfb['dnsbl_port_ssl']	= $pfb['dnsblconfig']['pfb_dnsport_ssl'];								// Lighttpd web server https port setting
	$pfb['dnsbl_top1m']	= pfb_cfg_toggle_read($pfb['dnsblconfig']['top1m_enable'] ?? '');							// TOP1M whitelist
	$pfb['dnsbl_top1m_type']	= PfbConfig::read('dnsbl/top1m_source');						// TOP1M type (PfbTop1mSource enum; legacy 'alexa' coalesces to Tranco, #877) (default Tranco)
	$pfb['dnsbl_res_cache']	= PfbConfig::read('dnsbl/pfb_cache');							// DNSBL Option to backup/restore Resolver cache (default on, issue #1907)
	$pfb['dnsbl_cache_flush']	= PfbConfig::read('dnsbl/pfb_cache_flush');						// Opt-in full cache flush after DNSBL data swaps
	$pfb['dnsbl_global_log']= PfbConfig::read('dnsbl/global_log');							// Global Logging/Blocking mode (default '')
	// ADR-22: lenient feed parsing. 'on' = permissive scheme strip (today); anything else =
	// strict RFC 3986 scheme validation + URL-path rejection. New installs default OFF
	// (strict); existing installs are grandfathered to 'on' by the registry pass at
	// install/upgrade (issue #1921).
	$pfb['dnsbl_lenient']	= PfbConfig::read('dnsbl/pfb_dnsbl_lenient');							// DNSBL scheme-parsing leniency (PfbToggle enum)

	$pfb['dnsbl_py_reply']	= PfbConfig::read('dnsbl/pfb_py_reply');			// DNSBL Resolver python DNS Reply logging (default on, issue #1907)
	$pfb['dnsbl_hsts']	= PfbConfig::read('dnsbl/pfb_hsts');			// DNSBL Resolver python block HSTS via Null Blocking mode (default on, issue #1907)
	// ADR-08: IDN mode selector. PfbConfig::read() returns a PfbIdnMode enum via the
	// registry adapter: 'on' -> All (preserves block-all-IDN on upgrade); 'confusable'
	// -> Confusable; '' / 'off' / absent / the dropped 4.0.0-alpha 'all' -> Off. Downstream
	// consumers compare against the enum; the ini build serialises the canonical token.
	$pfb['dnsbl_idn']	= PfbConfig::read('dnsbl/pfb_idn');				// DNSBL Resolver python IDN mode (PfbIdnMode enum)
	$pfb['dnsbl_idn_block_malicious']	= PfbConfig::read('dnsbl/pfb_idn_block_malicious');		// Confusable: block malicious homoglyphs (default 'on')
	$pfb['dnsbl_idn_escalate_suspicious']	= PfbConfig::read('dnsbl/pfb_idn_escalate_suspicious');	// Confusable: escalate suspicious mixed-script to block (opt-in)
	$pfb['dnsbl_regex']	= pfb_cfg_toggle_read($pfb['dnsblconfig']['pfb_regex'] ?? '');			// DNSBL Resolver python regex
	$pfb['dnsbl_regex_list']= $pfb['dnsblconfig']['pfb_regex_list'] ?? '';	// DNSBL Resolver python regex list
	$pfb['dnsbl_regex_cap']	= PfbConfig::read('dnsbl/pfb_regex_cap');			// DNSBL Resolver Python opt-in regex length cap
	$pfb['dnsbl_cname']	= pfb_cfg_toggle_read($pfb['dnsblconfig']['pfb_cname'] ?? '');			// DNSBL Resolver python CNAME Validation
	$pfb['dnsbl_tld_allow']	= pfb_cfg_toggle_read($pfb['dnsblconfig']['tld_allow'] ?? '');			// DNSBL Resolver TLD Allow option
	$pfb['dnsbl_psl_include_private'] = PfbConfig::read('dnsbl/pfb_psl_include_private');			// PSL PRIVATE recognition (default On)
	$pfb['dnsbl_psl_allow_private'] = PfbConfig::read('dnsbl/pfb_psl_allow_private');			// PSL PRIVATE TLD-Allow precision (default Off)
	$pfb['dnsbl_psl_feed_private_policy'] = PfbConfig::read('dnsbl/pfb_psl_feed_private_policy');	// issue #2371: feed-at-suffix PSL PRIVATE policy (PfbFeedSuffixPolicy enum; absent -> Honor)
	$pfb['dnsbl_psl_feed_icann_policy'] = PfbConfig::read('dnsbl/pfb_psl_feed_icann_policy');		// issue #2371: feed-at-suffix PSL ICANN policy (PfbFeedSuffixPolicy enum; absent -> Honor)
	$pfb['dnsbl_py_nolog']	= pfb_cfg_toggle_read($pfb['dnsblconfig']['pfb_py_nolog'] ?? '');			// DNSBL Resolver python - Log events via DNSBL Webserver vs python
	$pfb['dnsbl_noaaaa']	= pfb_cfg_toggle_read($pfb['dnsblconfig']['pfb_noaaaa'] ?? '');			// DNSBL Resolver python no AAAA
	$pfb['dnsbl_noaaaa_list']=$pfb['dnsblconfig']['pfb_noaaaa_list'] ?? '';	// DNSBL Resolver python no AAAA list

	$pfb['dnsbl_gp']		= pfb_cfg_toggle_read($pfb['dnsblconfig']['pfb_gp'] ?? '');		// DNSBL Resolver python - DNSBL Bypass
	$pfb['dnsbl_gp_bypass_list']	= $pfb['dnsblconfig']['pfb_gp_bypass_list'] ?? '';	// DNSBL Resolver python - List of Local IPs to bypass DNSBL

	// SafeSearch — read via gateway (ADR-29).
	$pfb['safesearch_enable']	= PfbConfig::read('ss/safesearch_enable');
	$pfb['safesearch_youtube']	= PfbConfig::read('ss/safesearch_youtube');
	$pfb['safesearch_doh']		= PfbConfig::read('ss/safesearch_doh');
	$pfb['safesearch_doh_list']	= array_values(array_filter(array_map('trim', explode(',', PfbConfig::read('ss/safesearch_doh_list'))), 'strlen'));

	// DNSBL SafeSearch
	$pfb['dnsbl_safe_search'] = FALSE;
	if ($pfb['safesearch_enable'] !== 'Disable' ||
	    $pfb['safesearch_youtube'] !== 'Disable' ||
	    $pfb['safesearch_doh'] !== 'Disable') {
		$pfb['dnsbl_safe_search'] = TRUE;
	}

	// External DNS Server for TLD drill and CNAME Queries
	$pfb['extdns'] = pfb_filter($pfb['config_global']['pfbextdns'], PFB_FILTER_IPV4, 'pfb_global', '8.8.8.8');

	// Unbound chroot cmd
	$pfb['chroot_cmd'] = "/usr/sbin/chroot -u unbound -g unbound / /usr/local/sbin/unbound-control -c {$g['unbound_chroot_path']}/unbound.conf";

	// Define SQLite3 parameters
	$pfb['sqlite_timeout']	= 100000;

	// Max daily download failure threshold (default to '0' unlimited failures)
	$pfb['skipfeed']	= $pfb['config']['skipfeed'] != '' ? $pfb['config']['skipfeed'] : 0;

	if (config_path_enabled('unbound')) {
		$pfb['unbound_state'] = PfbToggle::On;
	} else {
		$pfb['unbound_state'] = PfbToggle::Off;
	}

	// cURL - system proxy server setttings, if configured
	if (!empty(config_get_path('system/proxyurl'))) {
		$pfb['curl_defaults'][CURLOPT_PROXY]			= config_get_path('system/proxyurl');
		if (!empty(config_get_path('system/proxyport'))) {
			$pfb['curl_defaults'][CURLOPT_PROXYPORT]	= config_get_path('system/proxyport');
		}
		if (!empty(config_get_path('system/proxyuser')) && !empty(config_get_path('system/proxypass'))) {
			$pfb['curl_defaults'][CURLOPT_PROXYAUTH]	= 'CURLAUTH_ANY | CURLAUTH_ANYSAFE';
			$pfb['curl_defaults'][CURLOPT_PROXYUSERPWD]	= config_get_path('system/proxyuser') . ':' . config_get_path('system/proxypass');
		}
	}
	else {
		$pfb['curl_defaults'][CURLOPT_TCP_FASTOPEN]		= TRUE;
	}

	// Set pfBlockerNG to disabled on 're-install'
	if (isset($pfb['install']) && $pfb['install']) {
		$pfb['enable'] = $pfb['dnsbl'] = PfbToggle::Off;
		$pfb['install']	= FALSE;
	}
}

// Function to get pfBlockerNG package version
function pfb_pkg_ver() {
	$pkg_ver = 'v??';
	foreach (config_get_path('installedpackages/package', []) as $pkg_info_data) {
		if (strpos($pkg_info_data['name'], 'pfBlockerNG') !== FALSE) {
			$pkg_ver = 'v' . $pkg_info_data['version'];
			break;
		}
	}
	return $pkg_ver;
}


// Firewall Filter Service
function pfb_filter_service() {
	$LOG_PREFIX_PKG_PFBLOCKERNG = LOG_PREFIX_PKG_PFBLOCKERNG;

	$rc		= array();
	$rc['file']	= 'pfb_filter.sh';
	$rc['start']	= <<<EOF

	# Check if pfBlockerNG is enabled
	pfbcheck="\$(/usr/local/sbin/read_xml_tag.sh string installedpackages/pfblockerng/config/enable_cb)"
	if [ "\${pfbcheck}" != 'on' ]; then
		exit
	fi

	# Ensure all processes are stopped
	rc_stop

	# clog is not required for pfSense 2.5 and above
	filter_type='tail_pfb'
	if [ -e "/usr/local/sbin/clog_pfb" ]; then
		filter_type='clog_pfb'
	fi

	# Compare php/php_pfb versions
	php_path='/usr/local/bin'

	phpver="\$(/usr/bin/stat \${php_path}/php | cut -d '/' -f1)"
	if [ -e "\${php_path}/php_pfb" ]; then
		phppfbver="\$(/usr/bin/stat \${php_path}/php_pfb | cut -d '/' -f1)"
	else
		phppfbver=''
	fi

	# Create new hard link for php_pfb on version mismatch
	if [ "\${phpver}" != "\${phppfbver}" ]; then
		if [ -e "\${php_path}/php_pfb" ]; then
			tmpfile="\$(/usr/bin/mktemp /tmp/pfb_php.XXXXXX)"
			/bin/mv "\${php_path}/php_pfb" "\${tmpfile}"
		fi

		/bin/ln "\${php_path}/php" "\${php_path}/php_pfb"
	fi

	# Start pfBlockerNG Firewall filter Daemon
	if [ -e '/var/log/filter.log' ]; then
		/usr/bin/logger -p daemon.info -t "\${filter_type}" "INFO [{$LOG_PREFIX_PKG_PFBLOCKERNG}] Firewall Filter Service started"

		# Detach the daemon's std fds (#662): a backgrounded daemon that inherits the
		# caller's pipe -- e.g. the package-manager capture pipe when start_service() runs
		# during a package install/upgrade -- holds it open for its whole life, so pkg's
		# streamed output never reaches EOF and the upgrade page's live log freezes. Group
		# the pipeline and redirect its outer fds to /dev/null (stdin too); the internal
		# tail->php_pfb pipe is unaffected, so only the inherited descriptor is released.
		if [ "\${filter_type}" == 'clog_pfb' ]; then
			# clog_pfb is the pre-2.5 circular-log reader (below min CE 2.8); it reads
			# only the filter.log clog. The DNSBL feature-log tail is tail_pfb-only.
			{ /usr/local/sbin/clog_pfb -f /var/log/filter.log | /usr/local/bin/php_pfb -f /usr/local/pkg/pfblockerng/pfblockerng.inc filterlog ; } >/dev/null 2>&1 </dev/null &
		else
			# ADR-38 Amendment 1: one daemon also tails the DNSBL feature logs so it
			# can write unified.log + emit DNSBL syslog host-side. -q suppresses tail's
			# per-file "==> name <==" headers; -F retries files that don't exist yet.
			{ /usr/bin/tail_pfb -q -n0 -F /var/log/filter.log /var/log/pfblockerng/dnsbl.log /var/log/pfblockerng/dns_reply.log | /usr/local/bin/php_pfb -f /usr/local/pkg/pfblockerng/pfblockerng.inc filterlog ; } >/dev/null 2>&1 </dev/null &
		fi
	fi

EOF;
	$rc['stop']	= <<<EOF

	# clog is not required for pfSense 2.5 and above
	filter_type='tail_pfb'
	if [ -e "/usr/local/sbin/clog_pfb" ]; then
		filter_type='clog_pfb'
	fi

	# Terminate pfBlockerNG Firewall filter Daemon (clog) and filter Daemon, if found
	/usr/bin/logger -p daemon.info -t "\${filter_type}" "INFO [{$LOG_PREFIX_PKG_PFBLOCKERNG}] Firewall Filter Service stopped"
	/usr/bin/logger -p daemon.info -t php_pfb "INFO [{$LOG_PREFIX_PKG_PFBLOCKERNG}] filterlog daemon stopped"
	pidnum="\$(/bin/ps -wax | /usr/bin/grep '[c]log_pfb -f /var/log/filter.log\|[t]ail_pfb -q -n0 -F /var/log/filter.log\|[p]fblockerng.inc filterlog' | /usr/bin/awk '{print \$1}')"
	if [ ! -z "\${pidnum}" ]; then
		for i in \${pidnum}; do
			/bin/kill -9 "\${i}"
		done
	fi

EOF;
	write_rcfile($rc);
}


// DNSBL Service
function pfb_dnsbl_service() {
	$LOG_PREFIX_PKG_PFBLOCKERNG = LOG_PREFIX_PKG_PFBLOCKERNG;

	$rc		= array();
	$rc['file']	= 'pfb_dnsbl.sh';
	$rc['start']	= <<<EOF

	# Check if DNSBL is enabled
	dnsblcheck="\$(/usr/local/sbin/read_xml_tag.sh string installedpackages/pfblockerngdnsblsettings/config/pfb_dnsbl)"
	if [ "\${dnsblcheck}" != 'on' ]; then
		exit
	fi

	# Ensure all processes are stopped
	rc_stop

	# Start DNSBL Lighttpd webserver (Python mode)
	if [ -e '/var/unbound/pfb_dnsbl_lighty.conf' ]; then
		/usr/bin/logger -p daemon.info -t lighttpd_pfb "INFO [{$LOG_PREFIX_PKG_PFBLOCKERNG}] DNSBL Webserver started"
		# Detach std fds (#662): lighttpd self-daemonizes, and its forked child would
		# otherwise inherit the caller's pipe (the package-manager capture pipe during a
		# package install/upgrade) and hold it open, freezing the upgrade page's live log.
		# Redirect so the daemon never holds an inherited descriptor.
		/usr/local/sbin/lighttpd_pfb -f /var/unbound/pfb_dnsbl_lighty.conf >/dev/null 2>&1 </dev/null
	fi

	# Warn if the DNSBL python script is missing
	if [ ! -e '/var/unbound/pfb_unbound.py' ]; then
		/usr/bin/logger -p daemon.err -t php_pfb "ERROR [{$LOG_PREFIX_PKG_PFBLOCKERNG}] DNSBL missing python script - forced reload required"
	fi

EOF;
	$rc['stop']	= <<<EOF

	# Terminate DNSBL Lighttpd webserver, if found
	/usr/bin/logger -p daemon.info -t lighttpd_pfb "INFO [{$LOG_PREFIX_PKG_PFBLOCKERNG}] DNSBL Webserver stopped"
	pidnum="\$(/bin/pgrep lighttpd_pfb)"
	if [ ! -z "\${pidnum}" ]; then
		/usr/bin/killall lighttpd_pfb
	fi

EOF;
	write_rcfile($rc);
}


// Create Firewall filter service
if (!file_exists('/usr/local/etc/rc.d/pfb_filter.sh')) {
	pfb_filter_service();
}

// Create DNSBL service
if (!file_exists('/usr/local/etc/rc.d/pfb_dnsbl.sh')) {
	pfb_dnsbl_service();
}

// clog is not required for pfSense 2.5 and above
if (file_exists('/usr/local/sbin/clog_pfb')) {
	unlink_if_exists('/usr/local/sbin/clog_pfb');
	unlink_if_exists('/usr/bin/tail_pfb');
	link('/usr/bin/tail', '/usr/bin/tail_pfb');
	restart_service('pfb_filter');
}

// Commandline arguments for daemons
if (isset($argv[1])) {

	// DNSBL Lighttpd HTTPS daemon (Collects HTTPS events from the Lighttpd dnsbl_error.log)
	if ($argv[1] == 'dnsbl') {
			pfb_global();
			ignore_user_abort(TRUE);
			set_time_limit(0);
			pfb_daemon_dnsbl();
			exit;
	}

	// DNSBL Lighttpd HTTP daemon (Collects HTTP events from the index.php script)
	elseif ($argv[1] == 'index') {
			pfb_global();
			ignore_user_abort(TRUE);
			set_time_limit(0);
			pfb_daemon_dnsbl_index();
			exit;
	}

	// IP filter daemon to convert filter.log to ip_block|ip_permit|ip_match log format
	elseif ($argv[1] == 'filterlog') {
			pfb_global();
			ignore_user_abort(TRUE);
			set_time_limit(0);
			if (!file_exists('/var/log/filter.log')) {
				logger(LOG_INFO, localize_text('pfSense Firewall log missing'), LOG_PREFIX_PKG_PFBLOCKERNG);
				exit;
			}
			pfb_daemon_filterlog();
			exit;
	}
}


// Function to convert string to lowercase (Not for comment line section)
function pfb_strtolower($line) {
	if (strpos($line, '#') === FALSE) {
		return trim(strtolower($line));
	}
	return trim($line);
}


/**
 * preg_replace() wrapper that fails open: pathological input can exhaust the
 * regex engine (JIT stack, pcre.backtrack_limit) and preg_replace() returns
 * NULL. Returning NULL up through a `: string` contract either wipes data
 * (an earlier NULL coerces to '' through a later preg_replace) or throws a
 * TypeError. This wrapper keeps $subject unchanged on NULL instead.
 */
function pfb_preg_replace_safe($pattern, $replacement, string $subject): string {
	return preg_replace($pattern, $replacement, $subject) ?? $subject;
}


/**
 * TRUE iff $value is absent, empty, or nothing but whitespace -- ASCII, Unicode
 * (\p{Z}), or the BOM. Unlike empty(), the row "0" is NOT blank: it is a valid
 * list entry (issue #1707). A pathological preg_replace() failure degrades
 * fail-open, reading as non-blank rather than blank.
 */
function pfb_is_blank(?string $value): bool {
	if ($value === NULL || trim($value) === '') {
		return TRUE;
	}
	return pfb_preg_replace_safe('/[\s\p{Z}\x{FEFF}]+/u', '', $value) === '';
}


/**
 * TRUE iff $value is absent or the empty string — the actual "is this an empty
 * string?" answer (issue #1787). Unlike empty(), the string "0" is NOT empty:
 * it is a real value. Whitespace is content here; use pfb_is_blank() for the
 * "nothing but whitespace" question.
 */
function pfb_is_empty(?string $value): bool {
	return $value === NULL || $value === '';
}


/**
 * Right-strip trailing whitespace — ASCII (rtrim()'s default set) plus Unicode
 * whitespace/separators (\s under /u, \p{Z}) and the BOM — the same character
 * class pfb_is_blank() calls blank (issue #1787). Leading whitespace and the
 * value "0" survive untouched. A pathological preg_replace() failure degrades
 * fail-open to the ASCII-rtrim'd value, so Unicode stripping may not apply for
 * that call.
 */
function pfb_rstrip(string $value): string {
	$value = rtrim($value);
	return pfb_preg_replace_safe('/[\s\p{Z}\x{FEFF}]+$/u', '', $value);
}


/**
 * Left-strip counterpart of pfb_rstrip() — same whitespace class (ASCII,
 * Unicode \s/\p{Z}, BOM), leading side only. Lets a caller ask what a line's
 * first NONBLANK character is (e.g. comment detection when '#' hides behind
 * indentation). Same fail-open degradation to the ASCII-ltrim'd value.
 */
function pfb_lstrip(string $value): string {
	$value = ltrim($value);
	return pfb_preg_replace_safe('/^[\s\p{Z}\x{FEFF}]+/u', '', $value);
}


/**
 * Double-sided pfb_lstrip()+pfb_rstrip(): trim() with the same Unicode
 * whitespace class the other issue-#1787 helpers use. The value "0" survives.
 * ASCII fast path: after trim(), ASCII bytes at both ends prove no Unicode
 * whitespace remains there (every \p{Z}/BOM codepoint is multi-byte), so the
 * hot per-line callers skip the two preg passes entirely.
 */
function pfb_strip(string $value): string {
	$value = trim($value);
	if ($value === '' ||
	    (ord($value[0]) < 0x80 && ord($value[strlen($value) - 1]) < 0x80)) {
		return $value;
	}
	return pfb_lstrip(pfb_rstrip($value));
}


/**
 * Split a comma-joined config scalar into its list, honestly (issue #1792).
 * Replaces the `explode(',', $x ?? '') ?: $default` idiom, whose elvis arm is
 * unreachable -- explode() on a string subject always returns a non-empty
 * (truthy) array, so an absent/empty scalar yielded [''] and the intended
 * $default NEVER applied. Absent/empty ('' exactly -- pfb_is_empty, so a
 * stored "0" is one real entry) now genuinely yields $default.
 */
function pfb_csv_list(?string $value, array $default = array()): array {
	return pfb_is_empty($value) ? $default : explode(',', $value);
}


/**
 * Decode a base64 config scalar for display/re-edit, honestly (issue #1792).
 * Replaces the `base64_decode($x ?? '') ?: ''` idiom, whose elvis arm ate a
 * stored "0" (base64_decode('MA==') === '0', falsy) along with the FALSE it
 * was guarding against. Only a FALSE decode (malformed input) degrades to '';
 * every decoded string -- "0" included -- survives verbatim.
 */
function pfb_b64_text(?string $value): string {
	$decoded = base64_decode((string) ($value ?? ''));
	return $decoded === FALSE ? '' : $decoded;
}


/**
 * Sanitize a single-line/scalar text field: converts legacy encodings to
 * UTF-8, strips every \p{C} character (Cc/Cf/Co/Cs/Cn -- includes CR/LF/TAB
 * and the BOM, since this contract is single-line), then trims (Unicode
 * whitespace \p{Z}/tab, then the ASCII trim() backstop). issue #1795: this
 * package has no use for Unicode format characters (ZWJ/ZWNJ/bidi marks)
 * either, so they no longer survive. A pathological preg_replace() failure
 * degrades to the unstripped input, never to NULL. Under a pathological
 * (~1M-char) whitespace run the guarded preg pass degrades fail-open the
 * same way, so Unicode-whitespace stripping may not apply for that call.
 */
function pfb_sanitize_text(string $text): string {
	// issue #1797 (A6): browser-fed input is UTF-8 by construction; the old
	// mb_detect_encoding() recovery could never fail (every byte sequence is
	// valid ISO-8859-1) and only manufactured mojibake. Scrub deterministically
	// instead -- the valid-UTF-8 output invariant is load-bearing:
	// pfb_preg_replace_safe()'s /u patterns return the subject UNCHANGED on
	// invalid UTF-8, so without it the strips below silently degrade to trim().
	if (!mb_check_encoding($text, 'UTF-8')) {
		$text = mb_convert_encoding($text, 'UTF-8', 'UTF-8');
	}
	$text = pfb_preg_replace_safe('/\p{C}+/u', '', $text);
	$text = pfb_preg_replace_safe('/^[\p{Z}\t]+|[\p{Z}\t]+$/u', '', $text);
	return trim($text);
}


/**
 * Sanitize a multi-line textarea blob: converts legacy encodings to UTF-8,
 * normalizes CRLF/CR/LF line endings to LF, strips every \p{C} character
 * (Cc/Cf/Co/Cs/Cn, plus the BOM) except \n/\t -- so VT/FF/NEL/ZWJ/etc. never
 * become row separators or survive as data (issue #1795) -- then
 * right-strips trailing whitespace per line (pfb_rstrip). The right-strip is
 * Unicode-aware, so NBSP/ideographic
 * space/line-separator runs are stripped like ASCII space/tab, and a row of
 * only Unicode whitespace right-strips to '' same as an ASCII-blank row. Does
 * NOT drop blank lines; that is the caller's job (issue #1707). A
 * pathological preg_replace() failure degrades to the unstripped input (or,
 * per line, the ASCII-rtrim'd line) instead of wiping rows or fatal-ing.
 * Under a pathological (~1M-char) whitespace run the guarded preg pass
 * degrades fail-open the same way, so Unicode-whitespace stripping may not
 * apply for that call.
 */
function pfb_sanitize_text_area(string $text): string {
	if (!mb_check_encoding($text, 'UTF-8')) {
		$text = mb_convert_encoding($text, 'UTF-8',
			mb_detect_encoding($text, 'UTF-8, ASCII, ISO-8859-1'));
	}
	$text = str_replace(array("\r\n", "\r"), "\n", $text);
	$text = pfb_preg_replace_safe('/[^\P{C}\t\n]+/u', '', $text);

	$lines = explode("\n", $text);
	foreach ($lines as &$line) {
		$line = pfb_rstrip($line);
	}
	unset($line);
	return implode("\n", $lines);
}


// Function to decode alias custom entry box.
// Default (False, True): Return as string with comments
function pfb_text_area_decode($text, $mode=FALSE, $type=TRUE, $idn=FALSE) {

	// issue #1768: untyped $text feeds base64_decode() below; coerce NULL -> ''
	// so an absent/unset caller stops emitting the null-deprecation.
	$text = (string) ($text ?? '');

	if ($mode) {
		$custom = array();
	} else {
		$custom = '';	// string accumulator; '' (not undef) when no lines match
	}

	// issue #1710/#1707: split on any line ending, drop whitespace-only rows, keep '0'.
	$customlist = explode("\n", pfb_sanitize_text_area(base64_decode($text)));
	if (!empty($customlist)) {
		foreach ($customlist as $line) {
			$trimmed_line = trim($line);
			if (!str_starts_with($trimmed_line, '#') && ($trimmed_line !== '')) {
				if ($idn && !ctype_print($line)) {
					$line_old = $line;
					// Convert encodings to UTF-8
					$line = mb_convert_encoding($line, 'UTF-8',
						mb_detect_encoding($line, 'UTF-8, ASCII, ISO-8859-1'));
					if (strpos($line, '#') !== FALSE) {
						$tmpline = preg_split('/(?=#)/', $line);
						$tmpline[0] = pfb_idn_to_ascii_wildcard($tmpline[0]);
						if (pfb_is_blank($tmpline[0])) {
							$log = "\nError converting IDN line '{$line_old}'\n";
							pfb_logger($log, 2);
							continue;
						}
						$line = implode(' ', $tmpline);
					} else {
						$line = pfb_idn_to_ascii_wildcard($line);
						if (pfb_is_blank($line)) {
							$log = "\nError converting IDN line '{$line_old}'\n";
							pfb_logger($log, 2);
							continue;
						}
					}
				}
				// '#' commentline found
				if (strpos($line, '#') !== FALSE) {
					if ($mode) {
						if ($type) {
							// Split line into two elements (array)
							$custom[] = array_map('pfb_strtolower', preg_split('/(?=#)/', $line));
						} else {
							// Remove commentline
							$custom[] = trim(strtolower(strstr($line, '#', TRUE)));
						}
					} else {
						// Remove commentline
						$custom .= trim(strtolower(strstr($line, '#', TRUE))) . "\n";
					}
				}

				// No '#' commentline found
				else {
					$line = trim(strtolower($line));

					if ($mode) {
						if ($type) {
							$custom[][0] = $line;
						} else {
							$custom[] = $line;
						}
					} else {
						$custom .= "{$line}\n";
					}
				}
			}
		}
		return $custom;
	}
}


/**
 * Persist-boundary counterpart to pfb_text_area_decode(): sanitizes a raw
 * textarea blob (pfb_sanitize_text_area()) and base64-encodes it for config
 * storage. Every textarea save routes through it (issue #1723).
 */
function pfb_text_area_encode(string $raw): string {
	return base64_encode(pfb_sanitize_text_area($raw));
}


// Resolve a stored 'log_max_<type>' config value to the truncation limit pfb_log_mgmt() should
// apply. UI stores literal 'nolimit' for "No Limit"; PFB_FILTER_NUM accepts digits only, so
// filtering the raw value directly silently collapses 'nolimit' to the numeric default and the
// opt-out never takes effect (issue #713) — must run on the RAW value first. PURE.
//
// @param mixed $raw  Raw 'log_max_<type>' config value.
// @return int|string  'nolimit', or a positive int line count (numeric raw, else 20000 default).
function pfb_log_max_lines($raw) {
	if ($raw === 'nolimit') {
		return 'nolimit';
	}
	if (is_scalar($raw) && preg_match('/^[0-9]+$/', (string) $raw)) {
		return (int) $raw;
	}
	return 20000;
}

// Resolve a stored 'log_max_days_<type>' config value to an age-cutoff day count
// (ADR-60 S2.2). Mirrors pfb_log_max_lines()'s fallback shape: non-numeric/
// garbage/absent -> 0 (off), never a silent crash on an operator's typo. PURE.
function pfb_log_max_days($raw): int {
	if (is_scalar($raw) && preg_match('/^[0-9]+$/', (string) $raw)) {
		// Clamp so days*86400 (pfb_log_age_trim_temp()) can never overflow int into a
		// float -- an oversized-but-numeric operator typo must never crash pfb_log_mgmt().
		return min((int) $raw, 3650000);
	}
	return 0;
}

// Resolve a stored 'pfb_log_trim_margin_pct' config value to the hysteresis
// margin percent pfb_log_trim_needed() applies (issue #1109). Mirrors
// pfb_log_max_days()'s fallback shape: non-numeric/garbage/absent -> 0 (off). PURE.
function pfb_log_trim_margin_pct($raw): int {
	if (is_scalar($raw) && preg_match('/^[0-9]+$/', (string) $raw)) {
		// Clamp: 1000% keeps the age high-water arithmetic exact well under
		// PHP_INT_MAX even at pfb_log_max_days()'s own 3650000-day clamp.
		return min((int) $raw, 1000);
	}
	return 0;
}

// ADR-60 S2.1: where a log type's Y-m-d H:i:s timestamp lives in a line -- a
// leading line-prefix for the free-text logs, else a fixed CSV field (verified
// per writer: pfb_logger()/pfb_daemon_filterlog()/pfb_parse_fail_log()/dnsbl.log's
// python+PHP writers/pfb_unified_format_ip()'s comma-join).
function pfb_log_age_field_mode(string $logtype): string {
	switch ($logtype) {
		case 'log':
		case 'errlog':
		case 'extraslog':
			return 'prefix';
		case 'dnslog':
		case 'dnsreplylog':
		case 'unilog':
			return 'field1';
		default: // ip_blocklog, ip_permitlog, ip_matchlog, ip_parse_err, dnsbl_parse_err
			return 'field0';
	}
}

// Extract + strictly validate the Y-m-d H:i:s timestamp at $field_mode's position
// in $line ('prefix' = leading 19 chars; 'field0'/'field1' = the CSV column at
// that index). NULL for anything not an exact, real timestamp -- a truncated,
// garbled, or legacy pre-rework line is deliberately unparseable (ADR-60 S2.2
// "Unparseable line policy": treated as expired by the caller).
function pfb_log_line_timestamp(string $line, string $field_mode): ?int {
	switch ($field_mode) {
		case 'field0':
			$candidate = explode(',', $line, 2)[0];
			break;
		case 'field1':
			$fields = explode(',', $line, 3);
			$candidate = $fields[1] ?? '';
			break;
		default: // 'prefix'
			$candidate = substr($line, 0, 19);
			break;
	}

	if (strlen($candidate) !== 19) {
		return NULL;
	}

	// createFromFormat() alone is too lenient (silently overflows an invalid
	// shape like '2026-13-45 99:99:99' into a different, valid date) -- the
	// round-trip + getLastErrors() checks together reject that class of input.
	$dt = DateTime::createFromFormat('Y-m-d H:i:s', $candidate);
	if ($dt === FALSE || $dt->format('Y-m-d H:i:s') !== $candidate) {
		return NULL;
	}
	$errors = DateTime::getLastErrors();
	if ($errors !== FALSE && ($errors['warning_count'] > 0 || $errors['error_count'] > 0)) {
		return NULL;
	}

	return $dt->getTimestamp();
}

// ADR-60 S2.2 age-cutoff scan: log lines are chronologically appended, so this
// walks from the top and stops at the first non-expired line -- everything from
// there on is kept without re-checking. An unparseable/corrupted timestamp
// counts as expired (safe: only ever runs on the already line-capped candidate --
// issue #1012 moved the 'nolimit' whole-file case off this array-based path). PURE.
function pfb_log_age_cutoff(array $lines, int $cutoff_ts, string $field_mode): array {
	foreach ($lines as $i => $line) {
		$ts = pfb_log_line_timestamp($line, $field_mode);
		if ($ts !== NULL && $ts >= $cutoff_ts) {
			return array_slice($lines, $i);
		}
	}
	return array();
}

// Same leading-run drop as pfb_log_age_cutoff(), streamed line-by-line into a
// scratch file instead of an in-memory array -- issue #1012: a 'nolimit' log
// has no line-count cap, so the candidate can be the whole unbounded file.
function pfb_log_age_trim_temp_stream(string $temp, int $cutoff_ts, string $field_mode): bool {
	$in = @fopen($temp, 'r');
	if ($in === FALSE) {
		return FALSE;
	}

	$scratch = @tempnam(dirname($temp), 'pfb_logtrim_');
	$out = ($scratch !== FALSE) ? @fopen($scratch, 'w') : FALSE;
	if ($out === FALSE) {
		fclose($in);
		if ($scratch !== FALSE) {
			unlink_if_exists($scratch);
		}
		return FALSE;
	}

	$kept = FALSE;
	$ok = TRUE;
	while (($line = fgets($in)) !== FALSE) {
		if (!$kept) {
			$ts = pfb_log_line_timestamp(rtrim($line, "\r\n"), $field_mode);
			if ($ts === NULL || $ts < $cutoff_ts) {
				continue;
			}
			$kept = TRUE;
		}
		$written = @fwrite($out, $line);
		if ($written === FALSE || $written !== strlen($line)) {
			$ok = FALSE;
			break;
		}
	}
	// issue #1036: NOT stream_copy_to_stream() + early break -- feof() doesn't
	// reliably flag EOF after a zero-byte bulk copy on Linux; this loop only
	// exits via a real past-EOF fgets() unless a write already failed above.
	if ($ok && !feof($in)) {
		$ok = FALSE;
	}
	fclose($in);
	fclose($out);

	if ($ok) {
		$ok = @rename($scratch, $temp);
	}
	if (!$ok) {
		unlink_if_exists($scratch);
		return FALSE;
	}
	return TRUE;
}

// Rewrite the truncation-candidate file $temp in place, keeping only lines
// within the last $days (ADR-60 S2.2) per $logtype's field position. Returns
// FALSE on any read/write failure so the caller can gate its exec chain on it,
// exactly like the existing tail/cat steps -- a failed pass must never reach
// the final cat-over-the-live-log step with truncated/garbage content.
// $unbounded_candidate (issue #1012): route 'nolimit' through the streaming
// helper -- the array/@file() path below stays exact for the line-capped case.
function pfb_log_age_trim_temp(string $temp, int $days, string $logtype, bool $unbounded_candidate = FALSE): bool {
	$field_mode = pfb_log_age_field_mode($logtype);
	$cutoff_ts = time() - ($days * 86400);

	if ($unbounded_candidate) {
		return pfb_log_age_trim_temp_stream($temp, $cutoff_ts, $field_mode);
	}

	$lines = @file($temp, FILE_IGNORE_NEW_LINES);
	if ($lines === FALSE) {
		return FALSE;
	}
	$kept = pfb_log_age_cutoff($lines, $cutoff_ts, $field_mode);
	$content = $kept ? implode("\n", $kept) . "\n" : '';
	return pfb_log_age_trim_write_ok(file_put_contents($temp, $content), $content);
}

// issue #1053: a short (partial, non-FALSE) write must count as failure -- else a
// disk-full write silently truncates the candidate that then gets cat-ed over the
// live log. Mirrors pfb_prefetch_pattern_file_write_ok()'s decision shape.
function pfb_log_age_trim_write_ok($written, string $content): bool {
	return $written !== FALSE && $written === strlen($content);
}

// issue #1052/#1109: probe-before-copy (both branches); unparseable/empty/
// unopenable fall through TRUE. issue #1258: parses $margin_raw HERE
// (self-defending) -- no caller can hand an unclamped margin.
function pfb_log_age_trim_needed(string $path, int $agedays, string $logtype, $margin_raw = 0): bool {
	$margin_pct = pfb_log_trim_margin_pct($margin_raw);
	$fh = @fopen($path, 'r');
	if ($fh === FALSE) {
		return TRUE;
	}
	$first = fgets($fh);
	fclose($fh);
	if ($first === FALSE) {
		return TRUE; // empty file -- let the existing pass handle it (no-op either way)
	}

	$ts = pfb_log_line_timestamp(rtrim($first, "\r\n"), pfb_log_age_field_mode($logtype));
	if ($ts === NULL) {
		return TRUE; // unparseable/legacy first line -- must run the full pass
	}

	$window = (int) ($agedays * 86400 * (1 + $margin_pct / 100));
	return $ts < (time() - $window);
}

// issue #1257: ONE line-count primitive, replacing two counters that disagreed.
// Streamed, tail(1)/grep -c ^ semantics: an unterminated final line IS a line.
// NULL = could not count reliably -- the CALLER picks the safe fail direction.
function pfb_count_lines(string $path): ?int {
	$fh = @fopen($path, 'rb');
	if ($fh === FALSE) {
		return NULL;
	}

	$lines = 0;
	$last_byte = '';
	while (($chunk = @fread($fh, 1048576)) !== FALSE && $chunk !== '') {
		$lines += substr_count($chunk, "\n");
		$last_byte = $chunk[-1];
	}
	$read_failed = $chunk === FALSE;
	$ok = feof($fh);
	fclose($fh);

	if ($read_failed || !$ok) {
		return NULL;
	}

	return $lines + ($last_byte === '' || $last_byte === "\n" ? 0 : 1);
}

// issue #1263: per-file pfb_count_lines() sum over a '*.txt' glob, replacing
// `cat *.txt | grep -c ^` -- cat welds an unterminated file's last line onto
// the next file's first, undercounting; summing per-file counts cannot weld.
// Missing dir / empty glob -> 0, never a warning or TypeError.
function pfb_dnsbl_feed_count(string $dir): int {
	$total = 0;
	foreach ((glob("{$dir}/*.txt") ?: array()) as $file) {
		$total += pfb_count_lines($file) ?? 0;
	}
	return $total;
}

function pfb_update_unbound_feed_count(string $dir, ?callable $counter = NULL): int {
	$counter ??= 'pfb_dnsbl_feed_count';
	return $counter($dir);
}

function pfb_geoip_networks_header(string $iso_file, string $country, string $geoip_id, string $iso): string {
	$networks = pfb_count_lines($iso_file) ?? 'ERROR';
	$geoip_id = $geoip_id === '' || str_starts_with($geoip_id, ' [') ? $geoip_id : " [{$geoip_id}]";
	return "# Country: {$country}{$geoip_id}\n# ISO Code: {$iso}\n# Total Networks: {$networks}\n";
}

function pfb_geoip_append_iso_data(
	string $cat,
	string $iso_file,
	string $pfb_file,
	string $build_tmp,
	string $iso,
	string $type,
	?callable $logger = NULL
): bool {
	$logger ??= 'pfb_logger';
	$output = array();
	$status = 0;
	exec(
		$cat . ' ' . escapeshellarg($iso_file) . ' >> ' . escapeshellarg($pfb_file),
		$output,
		$status
	);
	if ($status !== 0) {
		$logger("\n Failed to append ISO data [ {$iso} IPv{$type} ] (cat status {$status})\n", 4);
		@unlink($pfb_file);
		rmdir_recursive($build_tmp);
		return FALSE;
	}
	return TRUE;
}

/** Hold a shared generation lock until the caller finishes reading and publishing its result. */
function pfb_geoip_generation_read_lock() {
	global $pfb;

	if (isset($GLOBALS['pfb_geoip_generation_read_lock']) &&
	    is_resource($GLOBALS['pfb_geoip_generation_read_lock'])) {
		$GLOBALS['pfb_geoip_generation_read_depth']++;
		return $GLOBALS['pfb_geoip_generation_read_lock'];
	}
	if (empty($pfb['ccdir']) || !pfb_geoip_generation_ready()) {
		return FALSE;
	}
	$lock = @fopen($pfb['ccdir'] . '/.pfb_generation.lock', 'c');
	if ($lock === FALSE || !@flock($lock, LOCK_SH | LOCK_NB)) {
		if (is_resource($lock)) {
			@fclose($lock);
		}
		return FALSE;
	}
	if (!pfb_geoip_generation_ready()) {
		@flock($lock, LOCK_UN);
		@fclose($lock);
		return FALSE;
	}
	$GLOBALS['pfb_geoip_generation_read_lock'] = $lock;
	$GLOBALS['pfb_geoip_generation_read_depth'] = 1;
	return $lock;
}

function pfb_geoip_generation_read_unlock($lock): void {
	if (!is_resource($lock) || !isset($GLOBALS['pfb_geoip_generation_read_lock']) ||
	    $lock !== $GLOBALS['pfb_geoip_generation_read_lock']) {
		return;
	}
	$GLOBALS['pfb_geoip_generation_read_depth']--;
	if ($GLOBALS['pfb_geoip_generation_read_depth'] > 0) {
		return;
	}
	@flock($lock, LOCK_UN);
	@fclose($lock);
	unset($GLOBALS['pfb_geoip_generation_read_lock'], $GLOBALS['pfb_geoip_generation_read_depth']);
}

/** Exclude readers while a complete staged GeoIP generation replaces live files. */
function pfb_geoip_generation_publication_lock(string $ccdir) {
	$lock = @fopen($ccdir . '/.pfb_generation.lock', 'c');
	if ($lock === FALSE) {
		return FALSE;
	}
	$timed_out = FALSE;
	if (!pfb_flock_bounded($lock, LOCK_EX, 60.0, $timed_out)) {
		@fclose($lock);
		return FALSE;
	}
	return $lock;
}

function pfb_geoip_generation_publication_unlock($lock): void {
	if (is_resource($lock)) {
		@flock($lock, LOCK_UN);
		@fclose($lock);
	}
}

function pfb_download_extraction_succeeded(int $retval): bool {
	return $retval === 0;
}

/**
 * issue #2658: wrap an extraction command so the child that writes cannot exceed
 * PFB_EXTRACT_MAX_BLOCKS. RLIMIT_FSIZE is inherited by every descendant, so one
 * prefix covers pipelines and the extractor's own children alike; a write past the
 * ceiling kills the writer with SIGXFSZ and the caller's existing nonzero-exit gate
 * rejects the extraction. `|| exit 1` keeps it fail-closed -- a shell that cannot
 * set the limit runs no extractor at all. $blocks exists so a test can prove the
 * ceiling fires without writing gigabytes.
 *
 * Known limit: RLIMIT_FSIZE bounds each file, not an archive's total output, so a
 * multi-member archive is bounded per member plus the free-space precheck. Member
 * counts are out of scope by the issue -- real feeds are multi-member.
 */
function pfb_extract_cmd(string $cmd, int $blocks = PFB_EXTRACT_MAX_BLOCKS): string {
	return "ulimit -f {$blocks} || exit 1; {$cmd}";
}

/**
 * issue #2658: name the ceiling when a nonzero extraction exit is the kernel
 * killing the writer for exceeding it, so an operator reads "too large" instead of
 * a bare exit code. Every other status keeps the caller's existing wording.
 */
function pfb_extract_cap_note(int $retval): string {
	return $retval === PFB_EXTRACT_SIGXFSZ_EXIT
		? ' -- output exceeded the extraction size ceiling'
		: '';
}

/**
 * issue #2658: the first staging directory without room for an extraction needing
 * $need bytes, or NULL when every candidate has room. Only absolute paths are
 * probed -- a caller's list carries feed names beside real directories, and a feed
 * name must never make the guard measure the working directory's filesystem. A
 * directory whose free space cannot be read is NOT a shortfall: a failed statfs is
 * not evidence of a full disk and must not refuse a legitimate feed. $free is the
 * free-space probe, injectable so the verdict is testable without a full disk.
 *
 * @param callable(string):(float|false)|null $free
 */
function pfb_extract_space_shortfall(array $dirs, int $need, ?callable $free = NULL): ?string {
	$free ??= static fn (string $dir) => @disk_free_space($dir);
	foreach ($dirs as $dir) {
		if (!is_string($dir) || strpos($dir, '/') !== 0) {
			continue;
		}
		$avail = $free($dir);
		if ($avail !== FALSE && $avail < $need) {
			return $dir;
		}
	}
	return NULL;
}

/**
 * issue #2684: the temp root the shell helpers unpack into, resolved the way the
 * CHILD resolves it -- `${TMPDIR:-/tmp}`, against the environment exec() hands it.
 * Deliberately NOT sys_get_temp_dir(): PHP's `sys_temp_dir` INI setting outranks
 * TMPDIR, so on an install that sets it a free-space precheck would measure one
 * filesystem while `pfb_make_tmpdir()`'s `mktemp -d` wrote to another. Deliberately
 * not `?:` either -- that discards the legitimate value "0", which the shell keeps.
 */
function pfb_extract_temp_root(): string {
	$tmp = (string) getenv('TMPDIR');
	return $tmp !== '' ? $tmp : '/tmp';
}

function pfb_download_initial_retval(): int {
	return 1;
}

/**
 * After a Blacklist tar extract, keep only staged category files.
 * glob('*domains') matches directories; an empty file list must not publish.
 */
function pfb_blacklist_tar_finalize_staged(string $staged, string $filename, int $retval): int {
	if (!pfb_download_extraction_succeeded($retval)) {
		return $retval;
	}
	$list = glob("{$staged}/{$filename}*");
	if (!is_array($list)) {
		$list = array();
	}
	$list = array_values(array_filter($list, 'is_file'));
	if (empty($list)) {
		return pfb_download_initial_retval();
	}
	foreach ($list as $verify) {
		if (strpos(basename($verify), '-') !== FALSE) {
			rename($verify, dirname($verify) . '/' . str_replace('-', '_', basename($verify)));
		}
	}
	return $retval;
}

/**
 * After a successful Blacklist tar publish, drop leftover orig/hash sidecars
 * and write the category update marker. Gzip and uncompressed x-tar share this.
 */
function pfb_blacklist_tar_mark_updated(string $file_dwn, string $filename): PfbDownloadResult {
	global $pfb;

	foreach (array("{$file_dwn}.orig", "{$file_dwn}.xxhash128", "{$file_dwn}.md5") as $blacklist_stale) {
		unlink_if_exists($blacklist_stale);
	}
	touch("{$pfb['dbdir']}/{$filename}/{$filename}.update");
	return PfbDownloadResult::success();
}

/**
 * Disk-writing GeoIP tar extract into geoipshare. The gzip container and the
 * uncompressed x-tar share this path; -C is a staging directory inside the share,
 * never the live share itself and never a .mmdb file (issue #2638 B7). The zip
 * container's multi-member arm publishes to its own caller target, so it stages
 * through the same merge helper rather than through this function.
 */
function pfb_geoip_extract_tar_to_share(
	string $header,
	string $file_download,
	string $file_dwn_esc,
	int &$retval
): PfbDownloadResult {
	global $pfb;

	// The gzip and uncompressed x-tar GeoIP arms share this helper; both are tar
	// containers, and tar reads the gzip wrapper itself.
	$unsafe_member = pfb_archive_unsafe_member(pfb_archive_member_names($file_download, 'application/x-tar'));
	if ($unsafe_member !== NULL) {
		pfb_validate_log($header, 'member', 'unsafe_member_name', $unsafe_member);
		unlink_if_exists($file_download);
		return PfbDownloadResult::failure();
	}
	$output = array();
	$retval = pfb_download_initial_retval();
	// issue #2668: the extraction runs in a staging directory and its members are
	// published only once tar reports success, so a failure part-way -- a killed
	// child at issue #2658's ceiling, ENOSPC, a member libarchive refuses -- leaves
	// the share already in service byte-identical.
	if (!pfb_stage_publish_dir_merge($pfb['geoipshare'],
	    static function (string $staged) use ($file_dwn_esc, &$output, &$retval): int {
		exec(pfb_extract_cmd("/usr/bin/tar -xf {$file_dwn_esc} " . PFB_TAR_EXTRACT_FLAGS . " --strip=1 -C " . escapeshellarg($staged) . " >/dev/null 2>&1"), $output, $retval);
		return $retval;
	})) {
		unlink_if_exists($file_download);
		pfb_logger("\n[pfb_download] geoip " . pfb_stage_publish_failure_note($retval), 2);
		return PfbDownloadResult::failure();
	}
	unlink_if_exists($file_download);
	return PfbDownloadResult::success();
}

/**
 * Publish an extraction atomically. $extract writes to a staged path beside $target and
 * returns its exit code; $target is replaced only once that code reports success, so a
 * failed extraction leaves the publication already in service untouched.
 *
 * @param callable(string):int $extract
 */
function pfb_stage_publish(string $target, callable $extract): bool {
	$staged = @tempnam(dirname($target), '.pfbstage_');
	if ($staged === FALSE) {
		return FALSE;
	}
	// issue #2169: tempnam() creates at 0600, but published feeds have unprivileged readers.
	if (!pfb_download_extraction_succeeded((int) $extract($staged)) ||
	    !@chmod($staged, 0644) || !@rename($staged, $target)) {
		unlink_if_exists($staged);
		return FALSE;
	}
	return TRUE;
}

/**
 * issue #2660: the content-sanity verdict for an extraction's STAGED output -- the text
 * gate in pfb_download() sees only the wire body's MIME, so an archive feed's payload
 * would otherwise reach the parser unscanned. Scanning the staged copy is what lets a
 * verdict refuse the publication instead of replacing it.
 *
 * NULL when there is nothing to refuse: a failed extraction (its exit code owns that
 * rejection), the opt-in scan off, an unreadable sample (fail open, as the text gate
 * does), or a payload that looks like a list.
 */
function pfb_extracted_text_sanity(string $staged, int $retval): ?string {
	if (!pfb_download_extraction_succeeded($retval) ||
	    PfbConfig::read('gen/pfb_feed_sanity') !== PfbToggle::On) {
		return NULL;
	}
	// Same 64 KiB read cap as the text gate -- a cap, not a minimum.
	$sample = @file_get_contents($staged, FALSE, NULL, 0, 65536);
	return $sample === FALSE ? NULL : pfb_text_sanity($sample);
}

/** Remove one directory tree without treating its literal path as a glob. */
function pfb_stage_publish_dir_remove(string $path): bool {
	if (!is_dir($path) || is_link($path)) {
		return FALSE;
	}
	// issue #2659: the tar arms now extract with --no-fflags, so a staged tree THIS
	// path creates can no longer carry an immutable flag. Kept anyway: it still has
	// to remove trees staged before that change, and a restored flag is only one of
	// the ways a staged entry becomes undeletable.
	if (is_executable('/bin/chflags')) {
		exec('/bin/chflags -R 0 ' . escapeshellarg($path) . ' 2>/dev/null');
	}
	try {
		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ($iterator as $entry) {
			$entry_path = $entry->getPathname();
			$removed = $entry->isDir() && !$entry->isLink()
				? @rmdir($entry_path)
				: @unlink($entry_path);
			if (!$removed && (file_exists($entry_path) || is_link($entry_path))) {
				return FALSE;
			}
		}
	} catch (UnexpectedValueException) {
		return FALSE;
	}
	return @rmdir($path) || !is_dir($path);
}

/** Recover deterministic directory backups left by an interrupted publication. */
function pfb_stage_publish_dir_recover(string $directory): bool {
	$entries = @scandir($directory);
	if ($entries === FALSE) {
		return FALSE;
	}
	$prefix = '.pfbstagebak2_';
	$success = TRUE;
	foreach ($entries as $entry) {
		if ($entry === '.' || $entry === '..' || !str_starts_with($entry, $prefix)) {
			continue;
		}
		$suffix = substr($entry, strlen($prefix));
		if ($suffix === '') {
			continue;
		}
		$backup = "{$directory}/{$entry}";
		if (!is_dir($backup) || is_link($backup)) {
			continue;
		}
		$target = "{$directory}/{$suffix}";
		if (file_exists($target) || is_link($target)) {
			if (!is_dir($target) || is_link($target)) {
				$success = FALSE;
				continue;
			}
			if (!pfb_stage_publish_dir_remove($backup)) {
				$success = FALSE;
			}
			continue;
		}
		if (!@rename($backup, $target)) {
			$success = FALSE;
		}
	}
	return $success;
}

/**
 * Publish a directory extraction atomically. $extract writes into an empty staging
 * directory beside $target and returns its exit code; $target is replaced only once
 * that code reports success, so a failed extraction leaves the directory already in
 * service intact (issue #2172).
 *
 * @param callable(string):int $extract
 */
function pfb_stage_publish_dir(string $target, callable $extract): bool {
	if (!pfb_stage_publish_dir_recover(dirname($target))) {
		return FALSE;
	}
	$staged = @tempnam(dirname($target), '.pfbstagedir_');
	if ($staged === FALSE) {
		return FALSE;
	}
	// tempnam() hands back a FILE; the extractor needs a directory at that path.
	// 0755, not tempnam's 0600: a published category has unprivileged readers.
	if (!@unlink($staged) || !@mkdir($staged, 0755) || !@chmod($staged, 0755)) {
		is_dir($staged) ? rmdir_recursive($staged) : unlink_if_exists($staged);
		return FALSE;
	}
	if (!pfb_download_extraction_succeeded((int) $extract($staged))) {
		rmdir_recursive($staged);
		return FALSE;
	}
	// rename() cannot replace a non-empty directory, so the previous publication moves
	// aside first and is restored if the swap does not complete.
	$backup = NULL;
	if (is_link($target) || (file_exists($target) && !is_dir($target))) {
		rmdir_recursive($staged);
		return FALSE;
	}
	if (is_dir($target)) {
		$backup = dirname($target) . '/.pfbstagebak2_' . basename($target);
		if (file_exists($backup) || is_link($backup) || !@rename($target, $backup)) {
			rmdir_recursive($staged);
			return FALSE;
		}
	}
	if (!@rename($staged, $target)) {
		if ($backup !== NULL) {
			pfb_stage_publish_dir_recover(dirname($target));
		}
		rmdir_recursive($staged);
		return FALSE;
	}
	if ($backup !== NULL && !pfb_stage_publish_dir_remove($backup)) {
		return FALSE;
	}
	return TRUE;
}

/**
 * Publish an extraction that MERGES into a directory holding other publications
 * (issue #2668). $extract writes into an empty staging directory INSIDE $target and
 * returns its exit code; the extracted members are moved over their live
 * counterparts only once that code reports success, so an extraction that fails
 * part-way leaves everything already in service byte-identical.
 *
 * Merging, not replacing: the whole-directory sibling helper REPLACES $target, and
 * $pfb['geoipshare'] is shared ground -- $pfb['ccdir'] (the published country-code
 * generation and the file its generation lock is taken on) sits inside it, and the
 * ASN feeds publish their databases there too. Probed: replacing the directory
 * deletes all of it while a publication lock is held, leaving the holder locking an
 * unlinked inode.
 *
 * Staging INSIDE $target is what keeps every publication a same-filesystem rename:
 * a directory just created there cannot be a mount point. tempnam() falls back to
 * the system temp directory when $target is not writable, so a staged path that
 * escaped is refused rather than published across a device boundary. Known limit:
 * the refusal compares resolved paths, so it assumes $target's parent is not being
 * mutated concurrently -- true of every shipped caller, whose targets sit under
 * root-owned package directories behind the feed-pass locks.
 *
 * @param callable(string):int $extract
 */
function pfb_stage_publish_dir_merge(string $target, callable $extract): bool {
	if (!is_dir($target) || is_link($target)) {
		return FALSE;
	}
	$staged = @tempnam($target, '.pfbstagedir_');
	if ($staged === FALSE) {
		return FALSE;
	}
	if (realpath(dirname($staged)) !== realpath($target)) {
		unlink_if_exists($staged);
		return FALSE;
	}
	// tempnam() hands back a FILE; the extractor needs a directory at that path.
	// 0755, not tempnam's 0600: the members published from it have unprivileged
	// readers, and tar carries each member's own mode across the rename.
	if (!@unlink($staged) || !@mkdir($staged, 0755) || !@chmod($staged, 0755)) {
		is_dir($staged) ? rmdir_recursive($staged) : unlink_if_exists($staged);
		return FALSE;
	}
	$published = pfb_download_extraction_succeeded((int) $extract($staged)) &&
		pfb_stage_publish_dir_merge_swap($staged, $target);
	rmdir_recursive($staged);
	return $published;
}

/**
 * Move every top-level entry of $staged over its live counterpart in $target.
 * rename() replaces a file atomically, so no reader can observe a half-written
 * member; a directory on either side cannot be replaced that way, so the whole
 * publication is refused BEFORE the first move rather than part-way through it.
 * That refusal is also what stops a feed member named like $pfb['ccdir'] from
 * taking the published country-code generation with it.
 */
function pfb_stage_publish_dir_merge_swap(string $staged, string $target): bool {
	$entries = @scandir($staged);
	if ($entries === FALSE) {
		return FALSE;
	}
	$entries = array_values(array_diff($entries, array('.', '..')));
	foreach ($entries as $entry) {
		$live = "{$target}/{$entry}";
		$live_exists = file_exists($live) || is_link($live);
		if ((is_dir($live) && !is_link($live)) ||
		    (is_dir("{$staged}/{$entry}") && !is_link("{$staged}/{$entry}") && $live_exists)) {
			return FALSE;
		}
	}
	foreach ($entries as $entry) {
		if (!@rename("{$staged}/{$entry}", "{$target}/{$entry}")) {
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * issue #2668: a staged publication can fail with the extractor's status still
 * zero -- the members were refused, not the archive. Naming that "tar exit 0" tells
 * an operator the opposite of what happened, so the two outcomes read differently.
 * Every failing status keeps its existing wording, ceiling note included.
 */
function pfb_stage_publish_failure_note(int $retval): string {
	return pfb_download_extraction_succeeded($retval)
		? 'publication failed'
		: "extraction failed (tar exit {$retval})" . pfb_extract_cap_note($retval);
}

function pfb_download_retval_success(?int $retval): bool {
	return $retval === 0;
}

// issue #1109/#1258: ONE unified high-water guard for both pfb_log_mgmt()
// branches -- fires past a margin-widened high-water mark; $margin_raw is
// parsed HERE (self-defending). $logmax unclamped -- float math, not intdiv().
function pfb_log_trim_needed(int|string $logmax, int $agedays, string $path, string $logtype, $margin_raw): bool {
	$margin_pct = pfb_log_trim_margin_pct($margin_raw);
	if ($logmax !== 'nolimit') {
		$high_water = (float) $logmax * (1.0 + ($margin_pct / 100.0));
		// fail HIGH: a count failure must never silently skip a trim that IS needed.
		if ((float) (pfb_count_lines($path) ?? PHP_INT_MAX) > $high_water) {
			return TRUE;
		}
	}

	return $agedays > 0 && pfb_log_age_trim_needed($path, $agedays, $logtype, $margin_pct);
}

// Manage log files line limit + age-based retention (ADR-60)
function pfb_log_mgmt() {
	global $g, $pfb;
	pfb_global();

	$chroot_folder = '/var/unbound';

	// The RAW value, never a parsed one: the guards clamp it themselves (#1258), so no
	// caller can hand them an out-of-range margin. Hoisting the read is fine; hoisting
	// the parse is what let an unclamped margin reach the window arithmetic.
	$margin_raw = $pfb['config']['pfb_log_trim_margin_pct'] ?? '';

	foreach (array(	'log', 'errlog', 'extraslog', 'ip_blocklog', 'ip_permitlog', 'ip_matchlog',
			'ip_parse_err', 'dnslog', 'dnsbl_parse_err', 'dnsreplylog', 'unilog') as $logtype) {

		// Max lines in Log file
		$logmax = pfb_log_max_lines($pfb['config']['log_max_' . $logtype] ?? '');

		// ADR-60 S2.2/S2.3 item 3: age cap is independent of $logmax/'nolimit' --
		// 'nolimit' only opts this type out of the LINE-COUNT step below.
		$agedays = pfb_log_max_days($pfb['config']['log_max_days_' . $logtype] ?? '');

		// Neither cap active for this type: nothing to do (byte-identical to
		// pre-ADR-60 behaviour for every operator who has not opted in).
		if ($logmax === 'nolimit' && $agedays === 0) {
			continue;
		}

		if (file_exists($pfb[$logtype])) {
			if ($logtype == 'dnslog' || $logtype == 'dnsreplylog' || $logtype == 'unilog') {

				// Set DNSBL python logfile permissions using chroot folder
				if (is_dir("{$chroot_folder}/var/log/pfblockerng")) {
					$final_log_file = "{$chroot_folder}{$pfb[$logtype]}";
					$temp = tempnam("{$chroot_folder}/var/log/pfblockerng", 'pfb_log_');
				} else {
					$final_log_file = $pfb[$logtype];
					$temp = tempnam("{$g['tmp_path']}/", 'pfb_log_');
				}

				if (file_exists($final_log_file)) {
					// issue #1109: skip this tick's whole pass unless an active cap is
					// past its margin-widened high-water mark (the hysteresis trigger).
					if (!pfb_log_trim_needed($logmax, $agedays, $final_log_file, $logtype, $margin_raw)) {
						unlink_if_exists($temp);
						continue;
					}

					// Truncate in place to preserve the inode (#264): mv replaces the
					// inode, so a remote syslog shipper keyed on (inode, offset) treats
					// it as a rotation and re-sends the whole log. cat over '>' keeps the
					// same inode - the file just shrinks - and so keeps its ownership.
					// Gate on each exit code: unlike the atomic mv, '>' truncates first,
					// so a failed tail/cat must not be allowed to leave an empty/partial log.
					if ($logmax === 'nolimit') {
						// No line-count candidate exists (ADR-60 S2.2): age-cutoff
						// scans the whole file instead of a tail(1) candidate.
						$ret = @copy($final_log_file, $temp) ? 0 : 1;
					} else {
						exec("/usr/bin/tail -n " . escapeshellarg($logmax) . " " . escapeshellarg($final_log_file) . " > " . escapeshellarg($temp), $out, $ret);
					}
					if ($ret !== 0) {
						pfb_logger("\npfb_log_mgmt: failed to produce {$final_log_file}'s truncation candidate", 2);
					} elseif ($agedays > 0 && !pfb_log_age_trim_temp($temp, $agedays, $logtype, $logmax === 'nolimit')) {
						pfb_logger("\npfb_log_mgmt: failed to age-trim {$final_log_file}'s truncation candidate", 2);
						$ret = 1;
					}
					if ($ret === 0) {
						exec("/bin/cat " . escapeshellarg($temp) . " > " . escapeshellarg($final_log_file), $out, $ret);
						if ($ret === 0) {
							@chown($final_log_file, 'unbound');
							@chgrp($final_log_file, 'unbound');
						} else {
							pfb_logger("\npfb_log_mgmt: failed to overwrite {$final_log_file} during truncation", 2);
						}
					}
				}
			}
			else {
				$temp = tempnam("{$g['tmp_path']}/", 'pfb_log_');
				// issue #1109: same unified high-water guard as the chroot branch above.
				if (!pfb_log_trim_needed($logmax, $agedays, $pfb[$logtype], $logtype, $margin_raw)) {
					unlink_if_exists($temp);
					continue;
				}
				// Truncate in place to preserve the inode (#264) - see above. Gate on
				// each exit code so a failed tail/cat cannot truncate the live log.
				if ($logmax === 'nolimit') {
					$ret = @copy($pfb[$logtype], $temp) ? 0 : 1;
				} else {
					exec("/usr/bin/tail -n " . escapeshellarg($logmax) . " {$pfb[$logtype]} > " . escapeshellarg($temp), $out, $ret);
				}
				if ($ret !== 0) {
					pfb_logger("\npfb_log_mgmt: failed to produce {$pfb[$logtype]}'s truncation candidate", 2);
				} elseif ($agedays > 0 && !pfb_log_age_trim_temp($temp, $agedays, $logtype, $logmax === 'nolimit')) {
					pfb_logger("\npfb_log_mgmt: failed to age-trim {$pfb[$logtype]}'s truncation candidate", 2);
					$ret = 1;
				}
				if ($ret === 0) {
					exec("/bin/cat " . escapeshellarg($temp) . " > {$pfb[$logtype]}", $out, $ret);
					if ($ret !== 0) {
						pfb_logger("\npfb_log_mgmt: failed to overwrite {$pfb[$logtype]} during truncation", 2);
					}
				}
			}
			unlink_if_exists($temp);
		}
	}
}


// TRUE when this run's progress should stream to the process's STDOUT. Only when STDOUT is a real
// watched surface: a package lifecycle callback (the pkg Software page's pipe to `tee`) OR an
// interactive terminal. NOT when STDOUT is redirected to a log file we already write (the cron
// tick's `>> log`, the detached Run-Now's `>> runlog`, a nested extras dispatch) -- printing there
// would double every line -- and NOT for a web in-process caller (the HTTP response). This is a
// widening of issue #690's lifecycle-only mirror to add the terminal case. Test-overridable.
function pfb_run_streams_to_stdout(): bool {
	global $pfb;
	return $pfb['run_stdout_override'] ?? (!empty($pfb['hook_lifecycle']) || pfb_stdout_is_terminal());
}

// Whether this process's real STDOUT (fd 1) is an interactive terminal. FALSE when redirected to a
// file/pipe or under a non-CLI SAPI. Opened by URI (the bare STDOUT constant is undefined outside
// CLI); the fresh stream does not close fd 1 on fclose(). Cached -- fd 1 does not change mid-run.
function pfb_stdout_is_terminal(): bool {
	static $tty = NULL;
	if ($tty === NULL) {
		$h = @fopen('php://stdout', 'w');
		$tty = is_resource($h) && @stream_isatty($h);
		if (is_resource($h)) {
			@fclose($h);
		}
	}
	return (bool) $tty;
}

// ISO-8601 'YYYY-MM-DD HH:MM:SS' (unambiguous, locale-independent, sorts lexically) --
// shared timestamp helper for pfBlockerNG's log writers.
function pfb_log_iso_timestamp(): string {
	return date('Y-m-d H:i:s', time());
}

// ADR-60 S2.1: BSD year-infers vs $now, rolling back a year past a 6h skew
// (rollback reparse unchecked -- mirrors pre-extraction behaviour); syslog keeps
// $f[1]'s real year. Both fall back to pfb_log_iso_timestamp() on initial FALSE.
function pfb_filterlog_timestamp(array $f, string $log_type, int $now): string {
	if ($log_type == 'BSD') {
		$ts = strtotime("{$f[0]} {$f[1]} {$f[2]}", $now);
		if ($ts === FALSE) {
			return pfb_log_iso_timestamp();
		}
		if ($ts > $now + 6 * 3600) {
			$ts = strtotime("{$f[0]} {$f[1]} {$f[2]} " . ((int) date('Y', $now) - 1), $now);
		}
		return date('Y-m-d H:i:s', $ts);
	}
	$ts = strtotime($f[1]);
	return ($ts === FALSE) ? pfb_log_iso_timestamp() : date('Y-m-d H:i:s', $ts);
}

// issue #1054: TRUE when $path's NEXT pfb_logger() write starts a new physical
// line -- the file is absent/empty, or its last byte is "\n". Probed on EVERY
// write, never cached: other writers append to these same files in-process
// (hook-output persistence :4250, pfb_open_sqlite() errlog writes) and a
// short write can leave the file mid-line, so only the real last byte is safe.
function pfb_logger_target_starts_at_bol(string $path): bool {
	clearstatcache(FALSE, $path);
	if (!file_exists($path) || @filesize($path) === 0) {
		return TRUE;
	}
	$fh = @fopen($path, 'rb');
	if ($fh === FALSE) {
		return TRUE;
	}
	fseek($fh, -1, SEEK_END);
	$last = fread($fh, 1);
	fclose($fh);
	return $last === "\n";
}

// issue #1054 (ADR-60's stamped-unit contract: the physical LINE, not the
// write): decide + apply the ISO stamp for ONE target file, independently of
// every other sink pfb_logger() writes -- a sub-line progress fragment (e.g.
// pfb_logger('.', 1)) must not get a mid-line stamp just because a DIFFERENT
// target happens to be at BOL. $raw is the caller's unstamped message; a
// leading run of "\n" always forces BOL for what follows (it just ended the
// previous line), matching the existing leading-newline convention.
function pfb_logger_format_for_target(string $path, string $raw, int $lead, string $now): string {
	return ($lead > 0 || pfb_logger_target_starts_at_bol($path))
		? substr($raw, 0, $lead) . "{$now} " . substr($raw, $lead)
		: $raw;
}

function pfb_logger($log, $logtype) {
	global $g, $pfb;

	$now = pfb_log_iso_timestamp();

	// Insert the stamp AFTER any leading newlines -- ADR-48's pfb_validate_log_line()
	// (among other callers) uses a leading "\n" as a separator from the PREVIOUS
	// write, not this line's content.
	$lead = strspn($log, "\n");

	// Mirror the main-log lines into the per-run log while a run is active (set by
	// sync_package_pfblockerng). The live Update viewer tails this file; the cumulative log is
	// untouched. Only writes inside a run process (the dispatched daemon) -- a stray pfb_logger
	// call from a normal page never pollutes it.
	$runlog = (!empty($pfb['runlog']) && !empty($pfb['runlog_active'])) ? $pfb['runlog'] : '';

	// issue #1054: $log_out mirrors whatever was decided for $pfb['log'] (cases 1/2)
	// to the STDOUT copy below -- STDOUT isn't a probed target of its own, it only
	// ever echoes the SAME bytes already committed to the main log file.
	$log_out = $log;

	switch ($logtype) {

		// Print to pfBlockerNG log
		case 1:
			$log_out = pfb_logger_format_for_target($pfb['log'], $log, $lead, $now);
			@file_put_contents("{$pfb['log']}", "{$log_out}", FILE_APPEND);
			if ($runlog !== '') {
				@file_put_contents($runlog, pfb_logger_format_for_target($runlog, $log, $lead, $now), FILE_APPEND);
			}
			break;

		// Print to pfBlockerNG log and Error log
		case 2:
			$log_out = pfb_logger_format_for_target($pfb['log'], $log, $lead, $now);
			@file_put_contents("{$pfb['log']}", "{$log_out}", FILE_APPEND);
			@file_put_contents("{$pfb['errlog']}", pfb_logger_format_for_target($pfb['errlog'], $log, $lead, $now), FILE_APPEND);
			if ($runlog !== '') {
				@file_put_contents($runlog, pfb_logger_format_for_target($runlog, $log, $lead, $now), FILE_APPEND);
			}
			break;

		// Print to Extras log
		case 3:
			@file_put_contents("{$pfb['extraslog']}", pfb_logger_format_for_target($pfb['extraslog'], $log, $lead, $now), FILE_APPEND);
			break;

		// Print to screen and Extras log
		case 4:
			$extras_out = pfb_logger_format_for_target($pfb['extraslog'], $log, $lead, $now);
			if (empty($g['pfblockerng_install']) && empty($pfb['extras_update'])) {
				print "{$extras_out}";
			}
			@file_put_contents("{$pfb['extraslog']}", "{$extras_out}", FILE_APPEND);
			break;

		// Print to debugger
		case 5:
			@file_put_contents("/tmp/pfb_debug", pfb_logger_format_for_target('/tmp/pfb_debug', $log, $lead, $now), FILE_APPEND);
			break;

		// Print to Error log
		case 6:
			@file_put_contents("{$pfb['errlog']}", pfb_logger_format_for_target($pfb['errlog'], $log, $lead, $now), FILE_APPEND);
			break;
		default:
			break;
	}

	// #690: a package install/upgrade/uninstall runs its work synchronously inside the pkg
	// lifecycle callbacks, but pfSense's native Software page (and the pkg CLI) show only what
	// reaches STDOUT. pfb_logger() otherwise writes the whole sync pass to the log FILE, so the
	// page sits silent through it -- worst case the ~30s pfb_stop_start_unbound() wait, which
	// emits its progress dots through this same function -- and looks like a frozen/lost pipe.
	// So mirror the main-log lines (cases 1 and 2) to STDOUT whenever STDOUT is a real watched
	// surface -- pfb_run_streams_to_stdout(): a lifecycle callback ($pfb['hook_lifecycle'], the pkg
	// pipe) OR an interactive terminal (ADR-58's addition, so a hand-run pass streams too). NOT when
	// STDOUT is redirected to a log FILE we already write above (the cron tick's `>> log`, the
	// detached Run-Now's `>> runlog`, a nested extras dispatch) -- that would double every line -- and
	// NOT for a web in-process caller (the HTTP response). This also closes the silent unbound-stop
	// gap with no separate keepalive, since that wait already logs via case 1. The redirected update
	// hooks and the detached rc.d daemons are untouched -- visibility only, not the process-safety.
	if (($logtype == 1 || $logtype == 2) && pfb_run_streams_to_stdout()) {
		print "{$log_out}";
	}
}


/*
 * ADR-12: Pre/Post update hooks.
 *
 * At the start ('pre') and end ('post') of the pfBlockerNG update pass, the runner
 * executes admin-VETTED script files as root. The script is NOT typed into the GUI:
 * a shell-access admin authors it in the hook-script dir (PFB_HOOK_SCRIPT_DIR),
 * named hook_pre_* / hook_post_* (.sh/.py), and the GUI only PICKS it from that folder
 * (mirrors the per-feed list pre/post-script picker). This is the security model:
 * a GUI-only user can never inject a shell command, only select a file an admin
 * already placed on the box. Each hook entry lives in the pfBlockerNG config under
 * the 'row' listtag at installedpackages/pfblockerng/config/0/hooks/row (see
 * pfb_get_hooks() for why 'row' and not a bare list under <hooks>) and has the shape:
 *
 *   array(
 *     'script'      => 'hook_<when>_<name>.sh', // basename in PFB_HOOK_SCRIPT_DIR
 *     'when'        => 'pre' | 'post',          // fire point (also the script prefix)
 *     'enabled'     => 'on' | '' ,              // pfSense checkbox convention
 *     'description' => '<free text>',           // optional, for logs/UI
 *     'timeout'     => '<seconds>',             // optional, per-hook override
 *   )
 *
 * Failure semantics (the ADR-12 contract): a hook's non-zero exit OR timeout is
 * logged and the update CONTINUES. A hook can never throw, abort, or stall the
 * update pass. No die()/exit() here (library code).
 */

// Default per-hook timeout (seconds) when a hook does not set its own.
if (!defined('PFB_HOOK_TIMEOUT_DEFAULT')) {
	define('PFB_HOOK_TIMEOUT_DEFAULT', 60);
}

// Grace period (seconds) after SIGTERM before timeout(1) sends SIGKILL.
if (!defined('PFB_HOOK_KILL_GRACE')) {
	define('PFB_HOOK_KILL_GRACE', 5);
}

// Ceiling (seconds) for per-feed list pre/post transform scripts.
if (!defined('PFB_LIST_SCRIPT_TIMEOUT')) {
	define('PFB_LIST_SCRIPT_TIMEOUT', 300);
}

// Ceiling (seconds) for a nested `pfblockerng.php` re-entry launched from inside an
// update pass (issue #2016). Generous on purpose: it must exceed a full MaxMind +
// blacklist download pass on a slow link, and its only job is to stop a stalled child
// from holding the pass -- and pfblockerng_tick()'s log-maintenance gate -- open forever.
// Since issue #2851 it is also the ABSENT/INVALID value of the configurable budget
// (General -> Advanced, 'Nested pass timeout'), so a degraded setting lands here.
if (!defined('PFB_REENTRY_TIMEOUT')) {
	define('PFB_REENTRY_TIMEOUT', 1800);
}

// issue #2851: the window (whole seconds) an operator may configure the nested-pass
// budget to. BBcan177's case is a slow link or low-powered appliance needing longer than
// the default; the bounds keep that from degrading into an impractical or unbounded wait.
// pfblockerng.sh's pfb_reentry_timeout() mirrors both values (pinned by
// ReentryTimeoutSettingTest), so one stored value means the same seconds in both seams.
if (!defined('PFB_REENTRY_TIMEOUT_MIN')) {
	define('PFB_REENTRY_TIMEOUT_MIN', 60);
}
if (!defined('PFB_REENTRY_TIMEOUT_MAX')) {
	define('PFB_REENTRY_TIMEOUT_MAX', 7200);
}

// The re-entry target. Single-sourced so no caller composes the child command itself.
if (!defined('PFB_REENTRY_SCRIPT')) {
	define('PFB_REENTRY_SCRIPT', '/usr/local/www/pfblockerng/pfblockerng.php');
}

// Directory holding the admin-authored hook scripts the picker offers and the
// runner executes (ADR-12 security model: a hook runs a vetted on-box script
// file, never a GUI-entered command). A dedicated dir, separate from the per-feed
// list pre/post scripts (list_scripts/), so update hooks and feed transforms don't
// share a folder; hook scripts are named hook_pre_*/hook_post_* (.sh/.py). Created
// at install by pfblockerng_install.inc (no shipped files live here).
if (!defined('PFB_HOOK_SCRIPT_DIR')) {
	define('PFB_HOOK_SCRIPT_DIR', '/usr/local/pkg/pfblockerng/hooks');
}

/*
 * issue #1927: run a per-feed list pre/post transform script and HONOUR its exit
 * status — a failed transform's leftovers are not feed data; the caller decides
 * what to keep. Non-zero (124 = timed out) is logged to the pfBlockerNG log AND
 * the error log, naming the stage, script, and feed. timeout(1) stays in default
 * (reaper) mode on purpose: a hung transform pipeline must die as a whole tree
 * (docs/misc/external-process-waits.md "Choosing the mode"). $tmo_prefix is
 * injectable for off-appliance tests. $args_tail (pre-escaped args + the log
 * redirect) is appended verbatim.
 */
function pfb_list_script_exec(string $script_path, string $script_name, string $stage,
    string $header, string $args_tail, ?string $tmo_prefix = NULL): int {

	if ($tmo_prefix === NULL) {
		$tmo_prefix = '/usr/bin/timeout -s TERM -k ' . PFB_HOOK_KILL_GRACE . ' ' . PFB_LIST_SCRIPT_TIMEOUT . ' ';
	}

	$discard = array();
	$retval  = 0;
	if (exec("{$tmo_prefix}" . escapeshellarg($script_path) . " {$args_tail}", $discard, $retval) === FALSE &&
	    $retval === 0) {
		// exec() itself failed to launch (fork/pipe): a script that never ran
		// must never read as success.
		$retval = -1;
	}

	if ($retval === 124) {
		// No duration in the message: the budget lives inside $tmo_prefix, so a
		// restated constant would desync from an injected prefix.
		pfb_logger("\n[ {$header} ] {$stage}-script '{$script_name}' TIMED OUT (killed); discarding its output\n", 2);
	} elseif ($retval !== 0) {
		pfb_logger("\n[ {$header} ] {$stage}-script '{$script_name}' exited non-zero [ {$retval} ]; discarding its output\n", 2);
	}
	return $retval;
}

/*
 * issue #2851: resolve a STORED or SUBMITTED nested-pass timeout to the seconds the seam
 * may use. Whole seconds inside [PFB_REENTRY_TIMEOUT_MIN, PFB_REENTRY_TIMEOUT_MAX] are
 * honoured; absent, empty, non-integral, signed, padded, zero, negative, out-of-range,
 * 64-bit-overflowing and non-scalar values ALL resolve to the finite
 * PFB_REENTRY_TIMEOUT -- never to no timeout, which is issue #2488's degradation class.
 * Both the General page's save and pfb_reentry_budget() below normalize through here, so
 * the stored value is always the effective one. The /D anchor is load-bearing: without it
 * a trailing newline would slip past $ and the shell seam (which rejects it) would
 * disagree. PURE.
 */
function pfb_reentry_timeout($raw): int {
	if (is_int($raw) || (is_string($raw) && preg_match('/^[0-9]+$/D', $raw) === 1)) {
		$secs = (int) $raw;
		if ($secs >= PFB_REENTRY_TIMEOUT_MIN && $secs <= PFB_REENTRY_TIMEOUT_MAX) {
			return $secs;
		}
	}
	return PFB_REENTRY_TIMEOUT;
}

/*
 * issue #2016/#2488: resolve a nested re-entry budget FAIL-SAFE BY CONSTRUCTION --
 * start at the configured value and take the caller's only once it is proven positive-
 * integral, so no input can leave timeout(1) an empty or non-numeric duration (which
 * is how a bound silently degrades back into an unbounded wait). The caller's budget is
 * the off-appliance injection point (ReentryBoundsTest's executed expiry rows); no
 * production call site names one, so the configured value (issue #2851) is what the
 * appliance actually runs.
 */
function pfb_reentry_budget($budget): int {
	if (is_int($budget) && $budget > 0) {
		return $budget;
	}
	if (is_string($budget) && ctype_digit($budget) && (int) $budget > 0) {
		return (int) $budget;
	}
	global $pfb;
	// The gen-section mirror pfb_global() populates through PfbConfig::readSection().
	return pfb_reentry_timeout($pfb['config']['pfb_reentry_timeout'] ?? NULL);
}

/*
 * issue #2016: compose the ONE bounded nested-pfblockerng.php command; pure builder.
 * timeout(1) stays in default (reaper) mode -- a hung download pass must die as a whole
 * tree, and --foreground would SIGKILL php alone and orphan a blocked fetch
 * (docs/misc/external-process-waits.md). Output lands on $outfile and stdin on
 * /dev/null so no descendant can hold exec()'s capture pipe past the child's exit.
 * $pfb['timeout'] / $pfb['php'] are the established off-appliance injection points.
 */
function pfb_reentry_cmd(string $verb, array $args, string $outfile, $budget = NULL): string {
	global $pfb;

	$timeout_esc = escapeshellarg($pfb['timeout'] ?? '/usr/bin/timeout');
	$php_esc     = escapeshellarg($pfb['php'] ?? '/usr/local/bin/php');
	$argv_esc    = escapeshellarg(PFB_REENTRY_SCRIPT) . ' ' . escapeshellarg($verb);
	foreach ($args as $arg) {
		$argv_esc .= ' ' . escapeshellarg((string) $arg);
	}

	return "{$timeout_esc} -s TERM -k " . PFB_HOOK_KILL_GRACE . ' ' . pfb_reentry_budget($budget) .
	    " {$php_esc} {$argv_esc} > " . escapeshellarg($outfile) . ' 2>&1 < /dev/null';
}

/*
 * issue #2016: run a nested pfblockerng.php re-entry under that bound and return
 * the child's status, output as a fresh line array, and raw bytes appended to
 * $append_to. An expiry is named here once, so every caller surfaces it without
 * composing anything.
 */
function pfb_reentry_exec(string $verb, array $args = [], ?string $append_to = NULL,
    ?array &$lines = NULL, $budget = NULL): int {

	$secs    = pfb_reentry_budget($budget);
	$outfile = @tempnam(sys_get_temp_dir(), 'pfbre');
	if ($outfile === FALSE) {
		// A child that never ran must never read as success.
		pfb_logger("\nNested pfblockerng.php [ {$verb} ] could not stage its output; not run\n", 2);
		$lines = array();
		return -1;
	}

	$discard = array();
	$status  = 0;
	if (exec(pfb_reentry_cmd($verb, $args, $outfile, $secs), $discard, $status) === FALSE &&
	    $status === 0) {
		// exec() itself failed to launch (fork/pipe).
		$status = -1;
	}

	$raw   = (string) @file_get_contents($outfile);
	$lines = ($raw === '') ? array() : explode("\n", $raw);
	if (end($lines) === '') {
		// exec()'s $output carries no trailing empty element for a newline-terminated child.
		array_pop($lines);
	}
	if ($append_to !== NULL) {
		@file_put_contents($append_to, $raw, FILE_APPEND);
	}
	@unlink($outfile);

	if ($status === 124) {
		pfb_logger("\nNested pfblockerng.php [ {$verb} ] TIMED OUT after {$secs}s and was killed\n", 2);
	}
	return $status;
}

/*
 * issue #1925: stage the normalized feed for a pre-script and run it. Copies
 * $norm_path to $staged_path and hands the script the copy (in-place rewrite
 * contract unchanged), so neither '.orig' nor '.norm' is ever touched. Honours
 * the exit status (#1927): 'ok' FALSE on copy failure, non-zero exit, or the
 * script deleting its input -- the staged copy is removed and the caller keeps
 * its last known-good staging. On success 'path' is the staged copy to parse.
 */
function pfb_list_pre_script_run(string $norm_path, string $staged_path, string $script_path,
    string $script_name, string $header, string $args_tail, ?string $tmo_prefix = NULL): array {

	if (!@copy($norm_path, $staged_path)) {
		pfb_logger("\n[ {$header} ] pre-script '{$script_name}' could not stage its input; skipping\n", 2);
		unlink_if_exists($staged_path);
		return array('ok' => FALSE, 'path' => $norm_path);
	}

	if (pfb_list_script_exec($script_path, $script_name, 'pre', $header, $args_tail, $tmo_prefix) !== 0) {
		unlink_if_exists($staged_path);
		return array('ok' => FALSE, 'path' => $norm_path);
	}

	if (!file_exists($staged_path)) {
		pfb_logger("\n[ {$header} ] pre-script '{$script_name}' deleted its staged input\n", 2);
		return array('ok' => FALSE, 'path' => $norm_path);
	}

	return array('ok' => TRUE, 'path' => $staged_path);
}

/*
 * Setup-wizard decision helpers (pure; pinned by tests/php/WizardDecisionTest.php).
 * The pfblockerng_wizard.inc / pfblockerng_general.php controllers do the impure work
 * (read $_POST/$_GET/config, redirect, write_config, set $pfb_wizard); the branchy
 * decisions live here so the fast PHPUnit tier covers them (issue #88).
 */

/*
 * From a submitted Skip on the setup wizard, decide the exit action: 'disable' (also
 * stop future auto-launch) when the suppress checkbox is ticked, 'skip' (this session
 * only) otherwise, or NULL when Skip was not pressed.
 */
function pfb_wizard_skip_action(array $post): ?string {
	if (!isset($post['skip'])) {
		return null;
	}
	return !empty($post['pfb_wizard_disable']) ? 'disable' : 'skip';
}

/*
 * Normalise the ?wizard=<action> query parameter to the recognised set ('skip' |
 * 'disable'); NULL for anything else. Drives the auto-launch suppression only —
 * the GET is state-free; the 'disable' persist happens in the wizard's
 * csrf-magic-validated POST (pfb_wizard_persist_disable, issue #1651).
 */
function pfb_wizard_get_action(array $get): ?string {
	$action = $get['wizard'] ?? '';
	return in_array($action, array('skip', 'disable'), TRUE) ? $action : null;
}

/*
 * TRUE if the setup wizard must NOT auto-launch: an explicit ?wizard=skip this
 * request, the persisted disable flag ($wizard_skip_flag === 'on'), or the package
 * already configured ($config_zero non-empty). A fresh, unconfigured install with no
 * skip/disable returns FALSE (the wizard does auto-launch).
 */
function pfb_wizard_suppress_autolaunch(?string $get_action, $wizard_skip_flag, $config_zero): bool {
	return $get_action === 'skip'
		|| $wizard_skip_flag === 'on'
		|| !empty($config_zero);
}

/*
 * ADR-23: the DNSBL sinkhole-VIP settings the setup wizard persists to the DNSBL config,
 * given the Auto VIP choice. Auto on -> pfb_dnsvip_auto='on' and the manual selector ids
 * are NOT written (ADR-13 provisions and owns the VIP at enable time); auto off -> the flag
 * is '' and the operator's step3 lo0 VIP selections are persisted. step4_submitphpaction()
 * merges the returned slice into the dnsbl settings config.
 */
function pfb_wizard_dnsvip_settings(bool $auto, $vip4, $vip6): array {
	$settings = array('pfb_dnsvip_auto' => $auto ? 'on' : '');
	if (!$auto) {
		$settings['pfb_dnsvip4'] = $vip4;
		$settings['pfb_dnsvip6'] = $vip6;
	}
	return $settings;
}

/*
 * ADR-19 software-update decision core (pure; pinned by tests/php/SoftwareUpdateDecisionTest.php).
 *
 * These are the branchy "do we have a newer build, and should we notify about it"
 * deciders behind the Software tab + the cron new-version notice. They take strings
 * (installed/latest version, the installed package name + the repo it came from, the
 * notify knob) and return decisions ONLY — no GUI, no cron, no `pkg` IO/file_notice
 * (the thin pfb_pkg_*() shellout wrapper + the cache/notice wiring live in later
 * phases). Keeping the risky logic pure lets the fast PHPUnit tier prove every branch
 * off-appliance.
 */

/*
 * Channel leftover from an installed package NAME suffix (issue #2395):
 *   pfSense-pkg-pfBlockerNG         -> NULL     (canonical name is not a channel)
 *   pfSense-pkg-pfBlockerNG-testing -> 'testing'
 *   pfSense-pkg-pfBlockerNG-edge    -> 'edge'
 *   pfSense-pkg-pfBlockerNG-devel   -> 'devel'   (retired port; installed boxes remain)
 *   pfSense-pkg-pfBlockerNG-NIGHTLY -> 'nightly' (ADR-18)
 * Anything unrecognised/empty -> NULL. Suffix match is case-insensitive so the
 * NIGHTLY/devel spellings are tolerant.
 *
 * issue #2166: the ports tree replaced the -devel recipe with -testing/-edge/-nightly, so
 * a build from the current CI channel reports one of those names. -devel stays mapped:
 * boxes installed before the rename still carry it, and dropping it here would read them
 * as an unknown channel — i.e. not our build.
 *
 * issue #2148 made channel catalogue placement: all four catalogues publish the canonical
 * 'pfSense-pkg-pfBlockerNG', so an empty suffix cannot mean 'stable'. pfb_channel_from_repo_name()
 * is authoritative; pfb_build_record.channel is next; this suffix map is leftovers only.
 * Identity (is this our package at all) lives in pfb_pkg_is_our_name().
 */
function pfb_channel_from_pkgname(?string $name): ?string {
	if (!is_string($name) || $name === '') {
		return null;
	}
	$lname = strtolower($name);
	if (!str_starts_with($lname, 'pfsense-pkg-pfblockerng')) {
		return null;
	}
	$suffix = substr($lname, strlen('pfsense-pkg-pfblockerng'));
	switch ($suffix) {
		case '':
			return null;
		case '-testing':
			return 'testing';
		case '-edge':
			return 'edge';
		case '-devel':
			return 'devel';
		case '-nightly':
			return 'nightly';
		default:
			return null;
	}
}

/*
 * TRUE when $name is a pfBlockerNG package identity: the canonical name or a recognised
 * leftover suffix. Used by pfb_pkg_installed_name() so dropping the empty-suffix -> stable
 * lie (#2395) does not hide pfSense-pkg-pfBlockerNG from the install probe.
 */
function pfb_pkg_is_our_name(?string $name): bool {
	if (!is_string($name) || $name === '') {
		return FALSE;
	}
	$lname = strtolower($name);
	if (!str_starts_with($lname, 'pfsense-pkg-pfblockerng')) {
		return FALSE;
	}
	$suffix = substr($lname, strlen('pfsense-pkg-pfblockerng'));
	return $suffix === '' || pfb_channel_from_pkgname($name) !== null;
}

/*
 * Channel a build is on, from the pkg REPOSITORY it was installed from (`pkg query '%R'`):
 *   pfblockerng-stable  -> 'stable'
 *   pfblockerng-testing -> 'testing'
 *   pfblockerng-edge    -> 'edge'
 *   pfblockerng-nightly -> 'nightly'
 * Anything else -> NULL.
 *
 * issue #2148 (four-channel cutover): every channel catalogue publishes the ONE canonical
 * package identity 'pfSense-pkg-pfBlockerNG' — channel is catalogue placement, never a
 * package-name suffix — so the installed NAME can no longer say which channel a box is on.
 * A box subscribes to exactly one project repository at a time, so the recorded repo is both
 * the only repo the package can upgrade within and the authoritative channel signal.
 *
 * The LEGACY shared repo 'pfblockerng' returns NULL deliberately: it carries BOTH
 * pfSense-pkg-pfBlockerNG and pfSense-pkg-pfBlockerNG-devel, so there the NAME still
 * discriminates and callers fall back to pfb_channel_from_pkgname(). Matching is EXACT
 * (unlike the name mapper's case-insensitive suffixes): we author every one of these conf
 * names ourselves, so a case variant is a repo we never created, not a spelling of ours.
 */
function pfb_channel_from_repo_name(?string $repo): ?string {
	if (!is_string($repo) || $repo === '') {
		return null;
	}
	switch ($repo) {
		case 'pfblockerng-stable':
			return 'stable';
		case 'pfblockerng-testing':
			return 'testing';
		case 'pfblockerng-edge':
			return 'edge';
		case 'pfblockerng-nightly':
			return 'nightly';
		default:
			return null;
	}
}

/*
 * A recognised software channel token, or NULL. Used for pfb_build_record.channel and any
 * other already-decoded annotation so a junk/foreign string cannot become a channel label.
 */
function pfb_channel_recognized(?string $channel): ?string {
	if (!is_string($channel) || $channel === '') {
		return null;
	}
	switch (strtolower($channel)) {
		case 'stable':
		case 'testing':
		case 'edge':
		case 'devel':
		case 'nightly':
			return strtolower($channel);
		default:
			return null;
	}
}

/*
 * Channel from a pfb_build_record JSON blob (the package annotation), or NULL when the
 * blob is missing/unparseable/has no recognised channel. Sideloaded GitHub Release
 * assets carry this even when %R is empty (issue #2395).
 */
function pfb_channel_from_build_record(?string $json): ?string {
	if (!is_string($json) || $json === '') {
		return null;
	}
	$data = json_decode($json, TRUE);
	if (!is_array($data) || !array_key_exists('channel', $data) || !is_string($data['channel'])) {
		return null;
	}
	return pfb_channel_recognized($data['channel']);
}

/*
 * The channel an install is on (issue #2148 / #2395).
 *
 * Precedence:
 *   1. pfb_channel_from_repo_name($repo) when the %R is a pfblockerng-* catalogue;
 *   2. a recognised $record_channel (pfb_build_record.channel from the installed .pkg);
 *   3. a non-empty recognised name suffix (legacy leftovers);
 *   4. NULL — callers render 'unknown'. Never invent 'stable' from the canonical name.
 *
 * $record_channel is the already-decoded annotation so this stays hermetic: live callers
 * pass pfb_channel_from_build_record(pfb_pkg_annotation(...)); tests pass a literal.
 */
function pfb_channel_for_install(?string $repo, ?string $pkgname, ?string $record_channel = null): ?string {
	return pfb_channel_from_repo_name($repo)
		?? pfb_channel_recognized($record_channel)
		?? pfb_channel_from_pkgname($pkgname);
}

/*
 * Does a software-update cache describe the install currently on this box? (issue #2148)
 *
 * An install is identified by BOTH halves, because either can change alone:
 *   - the REPO, since all four catalogues publish the one canonical identity, so the name
 *     cannot tell two catalogues apart — a channel switch changes only this;
 *   - the NAME, since the legacy shared 'pfblockerng' catalogue carries both
 *     pfSense-pkg-pfBlockerNG and ...-devel — an in-repo identity swap changes only this.
 *
 * Both consumers of the cache ask this one question, and must ask the WHOLE of it: the
 * cron orchestrator, deciding whether cached latest/last_notified may be reused, and the
 * Software page, deciding whether cached latest/last-checked/status may be DISPLAYED. The
 * orchestrator's reset lands only on the next tick, so a page asking a looser question
 * shows the new install's label beside the previous one's version and verdict until then.
 *
 * A cache with NO 'repo' key predates #2148. That is not a catalogue change — it is every
 * existing box, once — so that half is adopted rather than discarded; discarding it would
 * re-announce an already-notified version and blank the last-known latest.
 */
function pfb_software_cache_matches_install(array $cache, string $pkgname, string $repo): bool {
	// The cache is a JSON file on disk, so a non-scalar can reach either half; casting one
	// to string emits "Array to string conversion" on every call before returning the same
	// FALSE (issue #2367). A half that is present but not scalar names nothing, so it is
	// refused before the cast -- including JSON null, which would otherwise coalesce to ''
	// and match an install whose own name is empty. Both live callers reach this through
	// pfb_software_read_cache(), which drops the same values a layer earlier; this stays for
	// a caller that hands over a cache array from anywhere else.
	if (array_key_exists('pkgname', $cache) && !is_scalar($cache['pkgname'])) {
		return FALSE;
	}
	if ((string) ($cache['pkgname'] ?? '') !== $pkgname) {
		return FALSE;
	}
	if (!array_key_exists('repo', $cache)) {
		return TRUE;
	}
	return is_scalar($cache['repo']) && (string) $cache['repo'] === $repo;
}

/*
 * Provenance gate (2026-06-15 amendment; widened by issue #2148): TRUE only when the build
 * was installed FROM one of OUR repos — the legacy shared 'pfblockerng' (stable + the
 * retired -devel identity) or one of the four per-channel catalogues
 * 'pfblockerng-stable' / '-testing' / '-edge' / '-nightly'. The repo is read from
 * `pkg query '%R' <pkgname>`. A Netgate-installed add-on (repo 'pfSense'), an empty/'unknown'
 * origin, or anything else -> FALSE: the Software tab, the page, the priv match[] line, AND
 * the cron notice all gate on this so a stock build shows none of them. Before #2148 only the
 * first and last were listed, so a box moved onto a -stable/-testing/-edge catalogue read as
 * not-our-build and silently lost the whole feature.
 */
function pfb_software_is_our_build(?string $installed_repo): bool {
	return in_array(
		$installed_repo,
		array('pfblockerng', 'pfblockerng-stable', 'pfblockerng-testing', 'pfblockerng-edge', 'pfblockerng-nightly'),
		TRUE
	);
}

/*
 * Update-now / Uninstall hrefs into pfSense's Package Manager, for every origin.
 *
 * The deep link carries the package NAME and pkg_mgr_install.php acts on that name: it
 * validates pkg_valid_name() and runs pfSense-upgrade with -i <pkg> -f (reinstall) or
 * -r <pkg> (delete). The %R filter that keeps a channel install out of the Package
 * Manager tables lives in get_pkg_info(), which drives the LISTING pages only. So the
 * origin decides whether Package Manager can show or announce the package -- it does not
 * decide whether these two operations work (issue #2653; #2380 gated them on
 * %R === 'pfSense' and disabled both controls on every channel install).
 *
 * Which repository the reinstall then resolves against is a repository-priority
 * question: the generated conf sets priority 100 above the Netgate repo for exactly
 * that reason (ADR-17, ADR-39).
 *
 * Neither function takes the origin, so #2380's gate is not merely off here: it cannot
 * be expressed without re-adding a parameter and every call site that feeds it.
 */
function pfb_software_update_href(string $pkgname, bool $update_available): string {
	if (!$update_available || $pkgname === '') {
		return '#';
	}
	return '/pkg_mgr_install.php?mode=reinstallpkg&pkg=' . rawurlencode($pkgname);
}

function pfb_software_uninstall_href(string $pkgname): string {
	if ($pkgname === '') {
		return '#';
	}
	return '/pkg_mgr_install.php?mode=delete&pkg=' . rawurlencode($pkgname);
}

/*
 * WHEN the most recent version check failed, or 0 when the page must show nothing (issue
 * #2674). The Software page pairs this with "Last checked" — the last SUCCESSFUL read — so an
 * admin can tell "checked, and you are up to date" from "the check failed and you are looking
 * at a cached answer".
 *
 * $cache_current is the page's own pfb_software_cache_matches_install() verdict, so a failure
 * recorded against a previous install is never shown against the current one. The cache is a
 * JSON file on disk, so only a value this box could actually have RECORDED is accepted: an
 * int, or its plain decimal string (json_decode hands back either). Everything else names no
 * time and shows nothing. That exclusion is load-bearing, not defensive: a JSON integer too
 * large for a PHP int decodes to a FLOAT, and casting one emits "not representable as an int"
 * into php_error.log on every page load -- noise the UI tiers read as a page defect (issue
 * #2367) -- while PHP_INT_MAX would render a year-292277 date in the Status section.
 */
function pfb_software_failed_at(array $cache, bool $cache_current): int {
	if (!$cache_current || !isset($cache['last_failed'])) {
		return 0;
	}
	$raw = $cache['last_failed'];
	if (!is_int($raw) && !(is_string($raw) && ctype_digit($raw))) {
		return 0;
	}
	// An oversized decimal string saturates to PHP_INT_MAX rather than warning, so the range
	// check below is what refuses it. The day of slack absorbs a clock stepped backwards by
	// NTP without letting a hand-edited or overflowed value through.
	$at = (int) $raw;
	return ($at > 0 && $at <= time() + 86400) ? $at : 0;
}

/*
 * Where "Check now" redirects after the check it forced (issue #2674).
 *
 * The handler POSTs, checks, and redirects, so before #2674 an admin who explicitly asked for
 * a fresh answer was silently re-served the old page. A failed forced check carries a query
 * token the page's render arm turns into a warning box; a successful one redirects clean, so a
 * benign load never raises it. Same shape as pfb_general_schedule_save_redirect().
 */
function pfb_software_check_redirect(
	bool $check_ok,
	string $failure_redirect = '/pfblockerng/pfblockerng_software.php?check=failed'
): string {
	return $check_ok ? '/pfblockerng/pfblockerng_software.php' : $failure_redirect;
}

/*
 * TRUE when $latest is strictly newer than $installed, via pfSense pkg_version_compare()
 * (never a string compare — it returns '<' | '=' | '>'). Empty/invalid inputs -> FALSE
 * (no update): a missing installed or latest version is never "an update is available".
 * Nightly's dated versions are only ever compared nightly-to-nightly (ADR-18 §1.5).
 */
function pfb_update_available(?string $installed, ?string $latest): bool {
	if (!is_string($installed) || $installed === '' || !is_string($latest) || $latest === '') {
		return FALSE;
	}
	return pkg_version_compare($installed, $latest) === '<';
}

/*
 * Whether the "Check for new versions" setting (pfb_software_check) is enabled. Default
 * ENABLED: an our-repo install checks for and notifies of new versions out of the box. An
 * absent value receives that default; case-insensitive 'on' enables it, and every other
 * present token disables it. The Software page persists unchecked as canonical empty Off.
 */
function pfb_software_check_enabled(): bool {
	// issue #1887: the ON default lives in the registry now; the accessor just asks.
	return PfbConfig::read('gen/pfb_software_check') === PfbToggle::On;
}

/*
 * Persist the "Check for new versions" token from a Software-page Save POST, and return the
 * token that was stored. A checkbox is absent from the POST when unticked, and
 * PFB_FILTER_ON_OFF accepts only 'on' and '' -- so every other token, pfSense's Form_Checkbox
 * default 'yes' included, canonicalises to the owner-ruled empty Off. The caller flushes
 * config.xml.
 *
 * issue #2525: named, so the persistence a test executes is the persistence the page runs.
 */
function pfb_software_check_save(array $post): string {
	$token = pfb_filter($post['pfb_software_check'] ?? '', PFB_FILTER_ON_OFF, 'software') ?: '';
	PfbConfig::write('gen/pfb_software_check', $token);
	return $token;
}

/*
 * The notify state machine: TRUE iff a `file_notice` should fire THIS tick.
 *
 * The single "Check for new versions" boolean ($enabled) gates notifications equally on every
 * channel: a notice fires ONLY when checking is enabled AND an update is available (latest >
 * installed) AND we have not already notified for this exact latest ($latest !== $last_notified).
 * The last clause is the per-version de-dupe (ADR-19 §2 "persist last-notified"): a daily cron at
 * the same latest does NOT renotify; a newer latest does.
 */
function pfb_should_notify(?string $installed, ?string $latest, ?string $last_notified, bool $enabled): bool {
	if (!$enabled) {
		return FALSE;
	}
	if (!pfb_update_available($installed, $latest)) {
		return FALSE;
	}
	return $latest !== $last_notified;
}

/*
 * ADR-19 — pkg IO wrapper + cron-driven update check (consumes the pure core).
 *
 * The pfb_pkg_*() functions below are the ONLY new code that shells to `pkg`; isolating
 * the shellout in thin wrappers keeps pfb_software_update_check() unit-testable (the
 * tests inject the installed/latest/installed-repo via its $io override rather than run
 * `pkg`). The pkg(8) port binary (libpkg) lives at /usr/local/sbin/pkg on every supported
 * target — the same binary pfSense itself and our install.sh/build-repo.sh invoke.
 * The base /usr/sbin/pkg bootstrap stub does NOT report the repository origin ('%R') the
 * same way, so the provenance gate read FALSE on a genuine our-repo install when it was
 * used; the port binary returns the recorded repo name (issue #2148: the legacy shared
 * 'pfblockerng' or one of the per-channel 'pfblockerng-<channel>' catalogues), which is
 * now the authoritative channel signal AND the repo latest is read from.
 */
define('PFB_PKG_BIN', '/usr/local/sbin/pkg');

if (!defined('PFB_REPO_GENERATE_HOOK')) {
	define('PFB_REPO_GENERATE_HOOK', '/usr/local/etc/rc.d/pfblockerng_repo_generate.sh');
}
if (!defined('PFB_PKG_TIMEOUT')) {
	define('PFB_PKG_TIMEOUT', '/usr/bin/timeout -s TERM -k 5 60');
}

/*
 * Regenerate this box's pkg repo conf (and install the catalogue signing key's trusted
 * fingerprint) by running the installed rc.d hook's start verb, bounded by timeout(1).
 *
 * Called from the package's POST-INSTALL path: the hook ships with the package, so an
 * upgrade is the moment a box carrying a conf written before issue #2675 -- plain
 * `signature_type: none` over HTTPS -- gets corrected, rather than at the next boot.
 * An absent or non-executable hook is FALSE, not a failure to install: a box whose
 * previous package predates hook delivery simply has none yet.
 */
function pfb_repo_conf_regenerate(
	string $hook = PFB_REPO_GENERATE_HOOK,
	string $timeout = PFB_PKG_TIMEOUT
): bool {
	if (!is_executable($hook)) {
		return FALSE;
	}
	$out = [];
	$ret = -1;
	exec($timeout . ' ' . escapeshellarg($hook) . ' onestart 2>/dev/null', $out, $ret);
	return $ret === 0;
}

/*
 * Run a pkg(8) shell command directly.
 */
function pfb_pkg_exec(string $command, array &$out = [], int &$ret = -1): void {
	$out = [];
	$ret = -1;
	exec($command, $out, $ret);
}

if (!defined('PFB_PYTHON_WRAPPER')) {
	define('PFB_PYTHON_WRAPPER', __DIR__ . '/pfb_python.sh');
}

/*
 * The installed pfBlockerNG package NAME (e.g. 'pfSense-pkg-pfBlockerNG-devel'), read
 * from `pkg query '%n'` filtered to our prefix; '' when not installed via pkg or the
 * query fails. Feeds pfb_pkg_is_our_name() so the canonical identity still matches
 * after empty-suffix stopped meaning 'stable' (issue #2395).
 */
function pfb_pkg_installed_name(): string {
	$out = array();
	$ret = -1;
	// -g: match the trailing '*' as a glob. pkg query treats the pattern as an EXACT
	// pkg-name without it, so 'pfSense-pkg-pfBlockerNG*' would match nothing and the
	// provenance gate would wrongly read the package as not-our-build on every install.
	pfb_pkg_exec(escapeshellarg(PFB_PKG_BIN) . " query -g '%n' " . escapeshellarg('pfSense-pkg-pfBlockerNG*') . ' 2>/dev/null', $out, $ret);
	if ($ret !== 0) {
		return '';
	}
	foreach ($out as $line) {
		$line = trim($line);
		if (pfb_pkg_is_our_name($line)) {
			return $line;
		}
	}
	return '';
}

/*
 * Resolve the package-provided Python interpreter through the single POSIX wrapper.
 * A supplied dependency list is a pure off-box/test path marshalled into the
 * wrapper. The live path invokes the wrapper once and caches success or failure.
 */
function pfb_python_interpreter(?array $dependencies = null): string {
	$live_lookup = $dependencies === null;
	static $live_result = null;
	if ($live_lookup) {
		if ($live_result !== null) {
			return $live_result;
		}
	}

	$env = '';
	if (!$live_lookup) {
		$marshalled = array();
		foreach ($dependencies as $dependency) {
			if (is_string($dependency)) {
				$marshalled[] = $dependency;
			}
		}
		$env = 'PFB_PYTHON_DEPENDENCIES=' . escapeshellarg(implode("\n", $marshalled)) . ' ';
	}
	$output = array();
	$ret = -1;
	exec($env . escapeshellarg(PFB_PYTHON_WRAPPER) . ' --print-interpreter 2>/dev/null', $output, $ret);
	if ($ret !== 0 || !isset($output[0])) {
		return $live_lookup ? ($live_result = '') : '';
	}
	$interpreter = trim((string) $output[0]);
	return $live_lookup ? ($live_result = $interpreter) : $interpreter;
}

/*
 * The installed version of $pkgname via `pkg query '%v'`; '' when absent/failed.
 */
function pfb_pkg_installed_version(string $pkgname): string {
	if ($pkgname === '') {
		return '';
	}
	$out = array();
	$ret = -1;
	pfb_pkg_exec(escapeshellarg(PFB_PKG_BIN) . " query '%v' " . escapeshellarg($pkgname) . ' 2>/dev/null', $out, $ret);
	return ($ret === 0 && isset($out[0])) ? trim($out[0]) : '';
}

/*
 * The repo $pkgname was installed FROM via `pkg query '%R'` (the provenance signal the
 * 2026-06-15 gate keys on); '' when absent/failed. Fed to pfb_software_is_our_build().
 *
 * issue #2148 made this the single authoritative signal: under one-repository-at-a-time
 * subscription the recorded repo is the ONLY repo the package can upgrade within, so it is
 * also the repo pfb_software_update_check() reads latest from and (via
 * pfb_channel_from_repo_name()) the channel it reports.
 */
function pfb_pkg_installed_repo(string $pkgname): string {
	if ($pkgname === '') {
		return '';
	}
	$out = array();
	$ret = -1;
	pfb_pkg_exec(escapeshellarg(PFB_PKG_BIN) . " query '%R' " . escapeshellarg($pkgname) . ' 2>/dev/null', $out, $ret);
	return ($ret === 0 && isset($out[0])) ? trim($out[0]) : '';
}

/*
 * One installed-package annotation value (`pkg query '%At %Av'`), or '' when absent/failed.
 * Used to read pfb_build_record off the live .pkg (issue #2395).
 */
function pfb_pkg_annotation(string $pkgname, string $key): string {
	if ($pkgname === '' || $key === '') {
		return '';
	}
	$out = array();
	$ret = -1;
	pfb_pkg_exec(escapeshellarg(PFB_PKG_BIN) . " query '%At %Av' " . escapeshellarg($pkgname) . ' 2>/dev/null', $out, $ret);
	if ($ret !== 0) {
		return '';
	}
	foreach ($out as $line) {
		$line = trim((string) $line);
		$pos = strpos($line, ' ');
		if ($pos === FALSE) {
			continue;
		}
		if (substr($line, 0, $pos) === $key) {
			return trim(substr($line, $pos + 1));
		}
	}
	return '';
}

/*
 * Newest non-empty version in $versions via pkg_version_compare() (issue #2379).
 * Catalogues retain older builds; rquery lists them in catalog order, not version order.
 * Nightly is YYYYMMDDHHMMSS.<7hex> — never lexical / PHP version_compare at the call site.
 */
function pfb_pkg_newest_version(array $versions): string {
	$latest = '';
	foreach ($versions as $line) {
		if (!is_scalar($line)) {
			continue;
		}
		$ver = trim((string) $line);
		if ($ver === '') {
			continue;
		}
		if ($latest === '' || pkg_version_compare($latest, $ver) === '<') {
			$latest = $ver;
		}
	}
	return $latest;
}

/*
 * Did the live catalogue read just performed actually SUCCEED? (issue #2674)
 *
 * All three inputs matter, and the refresh one is the reason this rule exists. A non-zero
 * `pkg update -f` means the catalogue was NOT refreshed, so any version rquery then prints
 * came off the STALE local DB — reading it is a fallback, never a successful check. Before
 * #2674 the refresh's return value was discarded at the call site, so a stale answer was
 * indistinguishable from a fresh one and the page advanced "Last checked" for it.
 */
function pfb_pkg_read_ok(int $refresh_ret, int $rquery_ret, string $latest): bool {
	return $refresh_ret === 0 && $rquery_ret === 0 && $latest !== '';
}

/*
 * The pfBlockerNG repo's latest version of $pkgname: `pkg update -f -r <repo>` (forced
 * refresh of just that repo's catalog DB) then `pkg rquery -r <repo> '%v' <pkgname>`.
 * Reads ONLY that repo ($reponame) — never -r pfSense / get_pkg_info (ADR-19 §2 "Read
 * latest"). Picks the newest rquery line with pkg_version_compare(); $out[0] is catalog
 * order, not newest (issue #2379). Returns '' (the caller then serves cache) when:
 *   - $pkgname/$reponame is empty;
 *   - the pkg subsystem is locked (is_subsystem_dirty('pkg')) — never fight a base update;
 *   - DNS is unavailable (get_dnsavailable()) — never stall on a network read;
 *   - the rquery yields nothing (repo/conf absent).
 *
 * $read_ok reports the OUTCOME to the caller, which an empty return alone cannot (issue
 * #2674 — a failing check was indistinguishable from a successful one):
 *   TRUE   the catalogue was refreshed and named a version;
 *   FALSE  the read was attempted and FAILED (either pkg call exited non-zero, or the
 *          catalogue named nothing) — the caller records that;
 *   NULL   no read was attempted, because a guard above deliberately deferred it. A
 *          deferral is not a failure: turning "pkg is busy" or "no DNS yet" into a failed
 *          check is exactly the scary page #2674 asks us not to produce.
 */
function pfb_pkg_latest(string $pkgname, string $reponame, ?bool &$read_ok = null): string {
	$read_ok = null;
	if ($pkgname === '' || $reponame === '') {
		return '';
	}
	if (is_subsystem_dirty('pkg')) {
		return '';
	}
	if (function_exists('get_dnsavailable') && !get_dnsavailable()) {
		return '';
	}
	$bin = escapeshellarg(PFB_PKG_BIN);
	$repo = escapeshellarg($reponame);
	// Bound both networked pkg calls with timeout(1) (same idiom as the hook runner) so a
	// hung mirror can never stall the cron pass or the page's forced "Check now".
	$tmo = '/usr/bin/timeout -s TERM -k 5 60 ';
	// Forced catalog refresh of the pfBlockerNG repo only. A failure is NOT fatal -- the
	// stale DB still reads, which is #2379's fallback -- but its return value is CAPTURED
	// and fed to pfb_pkg_read_ok() rather than discarded, so the caller can tell a refreshed
	// answer from a stale one (issue #2674). stderr stays redirected on both calls: what is
	// observable is a state, never a pkg diagnostic on the page.
	// -f is required: Pages/file:// catalogs can keep an unchanged mtime/etag (issue #2379).
	// pfb_pkg_exec() clears its $out at entry, so the two calls share one buffer; only the
	// two return codes have to be kept apart.
	$out = array();
	$refresh_ret = -1;
	pfb_pkg_exec("{$tmo}{$bin} update -f -r {$repo} 2>/dev/null", $out, $refresh_ret);
	$ret = -1;
	pfb_pkg_exec("{$tmo}{$bin} rquery -r {$repo} '%v' " . escapeshellarg($pkgname) . ' 2>/dev/null', $out, $ret);
	$latest = ($ret === 0) ? pfb_pkg_newest_version($out) : '';
	$read_ok = pfb_pkg_read_ok($refresh_ret, $ret, $latest);
	return $latest;
}

/*
 * Absolute path of the software-update cache (the page reads it; the cron writes it).
 */
function pfb_software_cache_file(): string {
	global $pfb;
	$dbdir = $pfb['dbdir'] ?? '/var/db/pfblockerng';
	return "{$dbdir}/software_update.json";
}

/*
 * Read the cache file as an assoc array (channel, installed, latest, last_checked,
 * last_notified, last_failed); [] when absent/unreadable/corrupt. last_failed is present
 * only while the most recent check ATTEMPT failed (issue #2674); its absence is the ordinary
 * state and is what a successful check restores.
 */
function pfb_software_read_cache(): array {
	$file = pfb_software_cache_file();
	if (!is_file($file)) {
		return array();
	}
	$raw = @file_get_contents($file);
	if ($raw === FALSE || $raw === '') {
		return array();
	}
	$data = json_decode($raw, TRUE);
	if (!is_array($data)) {
		return array();
	}
	// Consumers read these values through a (string) cast -- the orchestrator's
	// latest/last_notified, the page's displayed fields, the install matcher -- or, for the
	// timestamps, through a validating accessor (pfb_software_failed_at()). A non-scalar
	// value (a hand-edit, a future writer) makes each of those casts emit "Array to string
	// conversion" once per call, so it is dropped HERE rather than guarded at each site,
	// where the next site added would be unguarded again (issue #2367). Every key the writer
	// stores is a scalar or NULL; a stored NULL drops too, which costs nothing because the
	// only nullable one ('channel') is recomputed live and never read back from here.
	return array_filter($data, static function ($value): bool {
		return is_scalar($value);
	});
}

/*
 * Persist the cache atomically (encode -> write). Best-effort; a write failure is
 * swallowed (the next tick retries) so it can never throw into the cron pass.
 */
function pfb_software_write_cache(array $cache): void {
	$json = json_encode($cache, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
	if ($json === FALSE) {
		return;
	}
	// Stage to a temp file then rename() into place: a concurrent reader (which takes no
	// shared lock) then sees either the old or the new complete file, never a truncated one
	// that would decode to [] and drop last_notified (re-emitting a notice).
	$file = pfb_software_cache_file();
	$tmp = @tempnam(dirname($file), '.pfbsw_');
	if ($tmp === FALSE) {
		return;
	}
	if (@file_put_contents($tmp, $json . "\n", LOCK_EX) === FALSE || !@rename($tmp, $file)) {
		@unlink($tmp);
	}
}

/*
 * The cron-driven software-update check (ADR-19 §2 "Background check").
 *
 * Order is deliberate:
 *   1. Resolve installed name + version. These can be injected for unit tests via
 *      $io ['installed_name','installed','installed_repo','latest']; absent keys fall
 *      through to the live pfb_pkg_*() shellout.
 *   2. PROVENANCE GATE FIRST: gate on pfb_software_provenance_ok() — the SAME predicate
 *      that decides whether the Software PAGE is displayable (our-repo install, honouring
 *      the hidden CI/support override) — so a build that cannot show the page never runs
 *      the background check or raises an update notice, even if "Check for new versions"
 *      remains enabled from a prior our-repo install. Injectable via $io['provenance_ok']
 *      for off-box tests.
 *   3. Read latest from the repo the package was INSTALLED from (guarded inside
 *      pfb_pkg_latest()). A live read that did not SUCCEED preserves the cached latest so
 *      the page keeps showing the last-known value rather than regressing to '', and does
 *      NOT advance last_checked (issue #2379). "Succeeded" is pfb_pkg_latest()'s reported
 *      outcome, not merely a non-empty return: a version rquery printed off a catalogue
 *      whose refresh failed is a fallback, so promoting it would let the notice in step 4
 *      announce an update nothing verified (issue #2674).
 *   4. Refresh the cache (pkgname/repo/channel/installed/latest; last_checked only on a
 *      successful live read, last_failed only while the last attempt failed) and, when
 *      pfb_should_notify() says so, raise a DE-DUPED file_notice and persist
 *      last_notified = latest (so repeated ticks at the same latest do not renotify).
 *
 * $read_ok reports THIS call's read outcome to the caller, with pfb_pkg_latest()'s meanings:
 * TRUE succeeded, FALSE attempted and failed, NULL not attempted (a gate above returned
 * early, or a guard deferred the read). The page's "Check now" keys its feedback on this
 * rather than on the cache, because the cache deliberately KEEPS a failure across a later
 * deferral — reading it there made an identical deferral report "failed" or "fine" depending
 * only on what an earlier tick had recorded (issue #2674).
 *
 * Best-effort throughout: it returns the cache array and never throws, so wiring it into
 * the cron pass can never break a feed update. $force (the page's "Check now" button) bypasses
 * the "Check for new versions" enable-gate so a manual check always runs; it never bypasses the
 * provenance gate, and notifications still require the setting enabled.
 */
function pfb_software_update_check(bool $force = FALSE, ?array $io = null, ?bool &$read_ok = null): array {
	$read_ok = null;
	$io = is_array($io) ? $io : array();

	$pkgname = array_key_exists('installed_name', $io)
		? (string) $io['installed_name']
		: pfb_pkg_installed_name();
	$installed = array_key_exists('installed', $io)
		? (string) $io['installed']
		: pfb_pkg_installed_version($pkgname);

	// 2. Provenance gate FIRST — gate on the SAME predicate that decides whether the Software
	// PAGE is displayable (pfb_software_provenance_ok(): our-repo install, honouring the
	// hidden CI/support override), so a build that cannot show the page never runs the
	// background check or notifies — even if "Check for new versions" is still enabled from a
	// prior our-repo install. Injectable via $io['provenance_ok'] for off-box tests.
	$provenance_ok = array_key_exists('provenance_ok', $io)
		? (bool) $io['provenance_ok']
		: pfb_software_provenance_ok();
	if (!$provenance_ok) {
		return pfb_software_read_cache();
	}

	// The single "Check for new versions" setting (default ENABLED) gates the BACKGROUND
	// (cron) check + notifications. A manual "Check now" ($force) always runs, so a user can
	// do a one-off check without leaving background checking enabled.
	$enabled = pfb_software_check_enabled();
	if (!$enabled && !$force) {
		return pfb_software_read_cache();
	}

	// issue #2148: the INSTALLED REPOSITORY is authoritative — never a channel->repo mapping.
	// All four catalogues publish the ONE canonical identity 'pfSense-pkg-pfBlockerNG', and a
	// box subscribes to exactly one project repo at a time (all at priority 100, so pkg would
	// not order across them anyway), which makes the recorded '%R' both the only repo this
	// install can upgrade within and the channel it is on. Correct for legacy 'pfblockerng'
	// installs too: that is exactly where their upgrades come from.
	$repo = array_key_exists('installed_repo', $io)
		? (string) $io['installed_repo']
		: pfb_pkg_installed_repo($pkgname);
	// Repo, then build-record, then leftover name suffix — the ONE shared accessor so the
	// cached channel, the notice text and the Software page label can never disagree.
	// Tests inject $io['record_channel'] (or omit it to mean "no annotation"); the live
	// path ($io empty) reads pfb_build_record off the installed package (issue #2395).
	if (array_key_exists('record_channel', $io)) {
		$record_channel = is_string($io['record_channel']) ? $io['record_channel'] : null;
	} elseif ($io === array() && $pkgname !== '') {
		$record_channel = pfb_channel_from_build_record(pfb_pkg_annotation($pkgname, 'pfb_build_record'));
	} else {
		$record_channel = null;
	}
	$channel = pfb_channel_for_install($repo, $pkgname, $record_channel);

	$cache = pfb_software_read_cache();

	// 3. Read latest from the installed repo; keep the cached value when the live read did
	// not succeed. $read_ok — not merely a non-empty version — is what "successful" means
	// (issue #2674): a version rquery printed off a catalogue whose refresh failed came from
	// a stale DB, so it is neither promoted nor notified from. The cache keeps the last
	// version a SUCCESSFUL read produced (issue #2379's fallback), and last_checked keeps
	// naming that read.
	if (array_key_exists('latest', $io)) {
		$live_latest = (string) $io['latest'];
		// An explicitly injected outcome wins. A non-bool states none, and fails CLOSED:
		// nothing is promoted, timestamped or notified on an outcome nobody named. Absent,
		// an injected latest means what it means on the live path.
		$read_ok = array_key_exists('read_ok', $io)
			? (is_bool($io['read_ok']) ? $io['read_ok'] : null)
			: ($live_latest !== '');
	} else {
		$live_latest = pfb_pkg_latest($pkgname, $repo, $read_ok);
	}
	// pfb_pkg_read_ok() already requires a non-empty version for TRUE on the live path; the
	// second half closes the $io seam against a contradictory outcome/value pair.
	$read_succeeded = ($read_ok === TRUE && $live_latest !== '');
	// Only reuse cached latest/last_notified when the cache belongs to the SAME install.
	// pfb_software_cache_matches_install() is the whole question — name AND repo — and the
	// Software page gates its DISPLAYED values on the identical call, so the two can never
	// disagree about which cache is current.
	$cache_matches_install = pfb_software_cache_matches_install($cache, $pkgname, $repo);
	if ($read_succeeded) {
		$latest = $live_latest;
	} elseif ($cache_matches_install) {
		$latest = (string) ($cache['latest'] ?? '');
	} else {
		$latest = '';
	}

	$last_notified = $cache_matches_install ? (string) ($cache['last_notified'] ?? '') : '';
	$kept_checked = ($cache_matches_install && array_key_exists('last_checked', $cache))
		? $cache['last_checked']
		: null;
	$kept_failed = ($cache_matches_install && array_key_exists('last_failed', $cache))
		? $cache['last_failed']
		: null;

	// 4. Refresh the cache. last_notified is written from the scoped value so a cache left
	// by a different install (a different package name OR a different catalogue) is reset
	// rather than carried forward. last_checked stays put when the live catalog read failed.
	$cache['pkgname']       = $pkgname;
	$cache['repo']          = $repo;
	$cache['channel']       = $channel;
	$cache['installed']     = $installed;
	$cache['latest']        = $latest;
	$cache['last_notified'] = $last_notified;
	if ($read_succeeded) {
		$cache['last_checked'] = time();
	} elseif ($kept_checked !== null) {
		$cache['last_checked'] = $kept_checked;
	} else {
		unset($cache['last_checked']);
	}
	// last_failed is the record #2674 was missing: WHEN the most recent attempt failed, or
	// absent when the last thing that happened was not a failure. Scoped exactly like
	// last_checked, so a failure from a previous install is never shown against this one.
	// A successful read supersedes it; a deliberate deferral leaves the failure that stands.
	if ($read_ok === FALSE) {
		$cache['last_failed'] = time();
	} elseif (!$read_succeeded && $kept_failed !== null) {
		$cache['last_failed'] = $kept_failed;
	} else {
		unset($cache['last_failed']);
	}

	if (pfb_should_notify($installed, $latest, $last_notified, $enabled)) {
		file_notice('pfBlockerNG', "pfBlockerNG {$latest} available ({$channel})", 'pfBlockerNG', '/pfblockerng/pfblockerng_software.php', 1);
		$cache['last_notified'] = $latest;
	}

	pfb_software_write_cache($cache);
	return $cache;
}

/*
 * ADR-19 — provenance gate for the shipped GUI surfaces.
 *
 * Live wrapper over the pure pfb_software_is_our_build() (ADR-19 2026-06-15
 * amendment): reads the installed package's provenance from `pkg query '%R'`
 * and returns true ONLY when pfBlockerNG was installed from one of OUR repos —
 * the legacy shared `pfblockerng` or one of the four per-channel catalogues
 * `pfblockerng-stable|-testing|-edge|-nightly` (issue #2148). A Netgate-ports
 * install (repo 'pfSense'/unknown/'') returns false.
 *
 * The Software tab append, the pfblockerng_software.php top-of-file guard, and
 * the priv match line all gate on this single predicate so a Netgate-installed
 * add-on shows no Software page anywhere.
 */
// Hidden test/support override for the Software-page provenance gate (ADR-19). A file
// containing 'on' or 'off' FORCES the gate (case-insensitive, trimmed); absent or any other
// content => fall through to the auto-detect below. NOT a GUI knob: the webConfigurator never
// writes it. It lets CI render BOTH the enabled and disabled states deterministically (the
// Tier-A UI deploy is a sideloaded `pkg add`, whose %R is empty, so auto-detect alone could
// only ever show the hidden state), and gives support a force-on/off escape-hatch on a real box.
define('PFB_SOFTWARE_PANEL_OVERRIDE', '/var/db/pfblockerng/.pfb_software_panel');

/*
 * The forced Software-gate state, or NULL when not forced. Reads the hidden override sentinel
 * (PFB_SOFTWARE_PANEL_OVERRIDE; $path is injectable for off-box tests): 'on' => true,
 * 'off' => false, absent / any other content => NULL (the auto-detect applies).
 */
function pfb_software_panel_override(?string $path = null): ?bool {
	$path = $path ?? PFB_SOFTWARE_PANEL_OVERRIDE;
	if (!is_file($path)) {
		return null;
	}
	$v = strtolower(trim((string) @file_get_contents($path)));
	if ($v === 'on') {
		return TRUE;
	}
	if ($v === 'off') {
		return FALSE;
	}
	return null;
}

function pfb_software_provenance_ok(): bool {
	// A hidden override (CI / support) wins; otherwise auto-detect from the install's repo (%R).
	$forced = pfb_software_panel_override();
	if ($forced !== null) {
		return $forced;
	}
	return pfb_software_is_our_build(pfb_pkg_installed_repo(pfb_pkg_installed_name()));
}

// issue #1204: hidden dbdir sentinel suppressing the scheduled cron-tick verb without
// touching config.xml (house pattern: PFB_SOFTWARE_PANEL_OVERRIDE above). Presence-only
// -- the file's content is never read. $path/$dbdir are injectable for off-box tests.
function pfb_cron_disable_path(?string $dbdir = NULL): string {
	global $pfb;
	return ($dbdir ?? $pfb['dbdir']) . '/.pfb_cron_disable';
}

function pfb_cron_disabled(?string $path = NULL): bool {
	return is_file($path ?? pfb_cron_disable_path());
}

/*
 * Pending-changes flag. A save on a DEFERRED settings page (DNSBL/IP/Feeds) writes config.xml
 * but does NOT apply — only a real Update/cron pass applies it. The flag drives a GUI banner
 * ("applies on the next Update") that stays up until a real Update runs.
 *
 * It is a PERSISTED marker file ($pfb['pending_marker'], in /usr/local/etc), NOT pfSense's
 * mark_subsystem_dirty() (which stores the flag in /var/run, wiped on every reboot) and NOT
 * $pfb['dbdir'] (/var/db, RAM-disked on use_mfs_tmpvar): pfBlockerNG only RESTORES its cache on
 * boot (it does not re-apply config), so a reboot must NOT silently drop a still-unapplied change.
 * /usr/local/etc survives a RAM-disk-/var reboot (only /var + /tmp are volatile), so "pending"
 * stays true across a reboot until a genuine Update clears it.
 *
 * A General save ($pfb['save']=TRUE) neither applies the deferred changes nor clears this flag —
 * only sync_package_pfblockerng() with !$pfb['save'] clears it.
 */
function pfb_pending_changes_marker(): string {
	global $pfb;
	return $pfb['pending_marker'] ?? '/usr/local/etc/pfb_pending_changes';
}
function pfb_mark_pending_changes(): void {
	@touch(pfb_pending_changes_marker());
}
function pfb_clear_pending_changes(): void {
	@unlink(pfb_pending_changes_marker());
}
function pfb_pending_changes(): bool {
	return file_exists(pfb_pending_changes_marker());
}

/*
 * #738 F7: the deinstall-side counterpart of the clear above. The update-end guard
 * (pfb_clear_pending_changes(), just above) is gated on `!$pfb['save']`, and the pre-deinstall
 * disable pass always sets $pfb['save'] = TRUE before its sync_package_pfblockerng() call, so
 * that guard never fires there -- nothing else unlinked the marker, so it survived `pkg delete`
 * into any later reinstall and re-showed the banner before the first real Update. A thin,
 * separately named wrapper (rather than inlining pfb_clear_pending_changes() at the deinstall
 * call site) so the deinstall path stays a CLIENT of this module, not a second owner of the
 * marker file.
 */
function pfb_deinstall_clear_pending_changes(): void {
	pfb_clear_pending_changes();
}

/*
 * Print the "settings changed — apply on the next Update" info banner when there are pending
 * changes; no-op otherwise. Call immediately after display_top_tabs() on each pfBlockerNG page.
 * $on_update_page drops the redundant cross-link when already on the Update page.
 */
function pfb_print_pending_changes_box(bool $on_update_page = FALSE): void {
	if (!pfb_pending_changes()) {
		return;
	}
	$msg = gettext('Pending changes will be applied on the next list update.');
	if ($on_update_page) {
		$msg .= ' ' . gettext('Use the Run Now function below to apply them now.');
	} else {
		$msg .= ' ' . sprintf(
			gettext('To run an update now, go to the %s tab and use the Run Now function.'),
			'<a href="/pfblockerng/pfblockerng_update.php">' . gettext('Update') . '</a>'
		);
	}
	print_info_box($msg, 'warning');
}

/*
 * Append the "Software" tab to a page's $tab_array — ONLY when BOTH hold: an our-repo build
 * (pfb_software_provenance_ok()) AND the viewer holds the Package Manager "Installed" privilege
 * (isAllowedPage('pkg_mgr_installed.php')) — the SAME secondary gate pfblockerng_software.php
 * itself enforces (issue #485), so a user without that priv never sees a tab that dead-ends at
 * /index.php. $provenance_ok is injectable for off-box unit tests (the real predicate reads
 * on-appliance state); NULL (the production default) reads it. Shared by every pfBlockerNG page
 * so the tab is consistently present or absent across the GUI. Call immediately before
 * display_top_tabs(); $active marks it the current tab.
 */
function pfb_software_add_tab(array &$tab_array, bool $active = FALSE, ?bool $provenance_ok = null): void {
	$provenance_ok = $provenance_ok ?? pfb_software_provenance_ok();
	if ($provenance_ok && isAllowedPage('pkg_mgr_installed.php')) {
		$tab_array[] = array(gettext('Software'), $active, '/pfblockerng/pfblockerng_software.php');
	}
}

/*
 * Return the enabled hook entries matching $when ('pre'|'post'), in list order.
 *
 * Pure helper: takes the pfBlockerNG config array (config/0) so it can be unit
 * tested without a live config. pfb_run_hooks() reads the live config and feeds
 * it here. Malformed entries (missing script/when, disabled) are skipped.
 */
function pfb_get_hooks($pfbconfig, $when) {

	if ($when !== 'pre' && $when !== 'post') {
		return array();
	}

	$hooks = array();
	if (!is_array($pfbconfig) || !isset($pfbconfig['hooks']) || !is_array($pfbconfig['hooks'])) {
		return $hooks;
	}

	// Hook entries are stored under the 'row' listtag: config/0/hooks/row. This
	// matters because 'hooks' is NOT a pfSense listtag (verified in
	// xmlparse.inc::listtags() on RELENG_2_7_2 -- == min-CE-2.8 behaviour, the
	// frozen stub source -- and master: the array carries 'row'/'hosts'/'rule'/
	// 'item' but no 'hooks'). A list stored DIRECTLY under <hooks> serializes via
	// dump_xml_config_sub() to numeric child tags -- <hooks><0>...</0></hooks> --
	// which is INVALID XML (a name cannot start with a digit, XML_ERR_NAME_REQUIRED
	// on read), so it never round-trips for ANY count, one hook or many. Nesting
	// the rows under the 'row' listtag instead emits a proper repeated element --
	// <hooks><row>...</row><row>...</row></hooks> -- that parses back as a list for
	// 1..N rows (a lone <row> stays a 1-element list because 'row' is a listtag),
	// matching how every other pfBlockerNG rowhelper list (IP/DNSBL) is stored.
	//
	// Be tolerant of the shape: prefer hooks/row; fall back to a bare list under
	// 'hooks'; and wrap a lone assoc (a flat single-hook collapse) back into a list.
	if (isset($pfbconfig['hooks']['row']) && is_array($pfbconfig['hooks']['row'])) {
		$list = $pfbconfig['hooks']['row'];
	} else {
		$list = $pfbconfig['hooks'];
	}
	if (isset($list['script']) || isset($list['when']) || isset($list['enabled'])) {
		$list = array($list);
	}
	if (!is_array($list)) {
		return $hooks;
	}

	foreach ($list as $hook) {
		if (!is_array($hook)) {
			continue;
		}
		// pfSense checkbox convention: enabled === 'on'.
		if (($hook['enabled'] ?? '') !== 'on') {
			continue;
		}
		if (($hook['when'] ?? '') !== $when) {
			continue;
		}
		if (pfb_is_blank((string) ($hook['script'] ?? ''))) {
			continue;
		}
		$hooks[] = $hook;
	}

	return $hooks;
}

/*
 * Resolve a hook's timeout (seconds) to a sane positive integer, falling back to
 * PFB_HOOK_TIMEOUT_DEFAULT when unset/invalid.
 */
function pfb_hook_timeout($hook) {
	$timeout = (int) ($hook['timeout'] ?? 0);
	if ($timeout <= 0) {
		$timeout = PFB_HOOK_TIMEOUT_DEFAULT;
	}
	return $timeout;
}

/*
 * Enumerate the admin-authored hook scripts available for $when ('pre'|'post'):
 * the basenames of hook_<when>_*.{sh,py} in the hook-script dir, keyed by basename
 * (sorted), shape { basename => basename } for direct use as Form_Select options.
 *
 * These are the ONLY values the hook picker offers, the save handler accepts, and
 * the runner executes (ADR-12 security model: a hook runs a vetted on-box script
 * file authored by a shell-access admin, never a command typed into the GUI). $dir
 * is overridable so the off-appliance unit tests can point at a fixture directory.
 */
function pfb_hook_scripts($when, $dir = null) {
	if ($when !== 'pre' && $when !== 'post') {
		return array();
	}
	if ($dir === null) {
		$dir = PFB_HOOK_SCRIPT_DIR;
	}
	// Resolve the allowed directory once. realpath() returns FALSE when the
	// directory does not exist or is unresolvable — bail early.
	$real_dir = realpath($dir);
	if ($real_dir === FALSE) {
		return array();
	}
	$out = array();
	foreach (glob("{$dir}/hook_{$when}_*.{sh,py}", GLOB_BRACE) ?: array() as $path) {
		// Canonicalize the candidate. realpath() follows symlinks and resolves
		// '..'; FALSE means dangling symlink or unresolvable — skip.
		// Parity with pfb_filter() LOCALFILE containment: dirname($real) must
		// equal $real_dir so a symlink pointing outside the hook dir is excluded.
		// is_file($real) rejects symlinks-to-directories.
		// Executable bit is intentionally NOT gated here: presence as a regular
		// file in the allowed dir is the authorization. Python hooks run through
		// the dependency-derived interpreter even when non-executable; a shell hook
		// without its executable bit fails at run time and is logged by pfb_run_hooks.
		$real = realpath($path);
		if ($real === FALSE || dirname($real) !== $real_dir || !is_file($real)) {
			continue;
		}
		// Key by the name as it appears in the dir (the symlink's own basename,
		// not the target's), matching what the picker stores in config and what
		// pfb_run_hooks() rebuilds the path from.
		$base = basename($path);
		$out[$base] = $base;
	}
	ksort($out);
	return $out;
}

/*
 * TRUE if $script is a hook script the box will actually run for $when: a bare
 * basename (no path separator / traversal), named hook_<when>_*.{sh,py}, that
 * EXISTS in the hook-script dir. This is the allow-list gate shared by the save
 * handler (reject on POST) and the runner (skip at run time): the picker can only
 * offer these, and a crafted or stale config value that is not one of them never
 * executes. $dir matches pfb_hook_scripts() for testing.
 */
function pfb_hook_script_valid($script, $when, $dir = null) {
	$script = (string) $script;
	// Reject anything that is not a plain basename BEFORE touching the filesystem
	// (defence against ../ traversal and absolute paths in a hand-edited config).
	if ($script === '' || basename($script) !== $script) {
		return FALSE;
	}
	return array_key_exists($script, pfb_hook_scripts($when, $dir));
}

/*
 * Build the command for an allow-listed hook. Python hooks are dispatched through
 * the package wrapper; shell hooks retain their direct execution/shebang behavior.
 */
function pfb_hook_script_command(string $script, string $path, string $python): string {
	if (str_ends_with($script, '.py')) {
		return $python !== '' ? escapeshellarg($python) . ' ' . escapeshellarg($path) : '';
	}
	if (str_ends_with($script, '.sh')) {
		return escapeshellarg($path);
	}
	return '';
}

/*
 * Map a package-lifecycle marker to the extra PFB_* hook-context keys (issue #684).
 *
 * pfBlockerNG does NOT branch on the lifecycle -- hooks fire the same way on every enable/disable
 * pass. This only PUBLISHES which pkg transition (if any) the pass belongs to, so a hook owner can
 * decide what to do; it is context, not special handling. $lifecycle is $pfb['hook_lifecycle'],
 * set to 'install' by the install-command path (turn ON via the resync) and 'uninstall' by the
 * pre-deinstall (turn OFF), and unset on a normal cron/manual/force update.
 *
 * Both keys are ALWAYS emitted as '1'/'0' (issue #695), matching the '1'/'0' contract of the other
 * context vars (PFB_IP_CHANGED / PFB_DNSBL_CHANGED) so a hook can guard every PFB_* flag uniformly
 * (`[ "$PFB_PRE_UNINSTALL" = '1' ]`): POST_INSTALL=1 only on the install/upgrade resync, PRE_UNINSTALL=1
 * only on the pre-deinstall, and both '0' on a normal cron/manual/force update. (Supersedes the
 * earlier present-only form, where the key was unset off-phase and a hook tested `[ -n ... ]`.)
 */
function pfb_hook_lifecycle_ctx($lifecycle): array {
	return array(
		'POST_INSTALL'  => ((string) $lifecycle === 'install')   ? '1' : '0',
		'PRE_UNINSTALL' => ((string) $lifecycle === 'uninstall') ? '1' : '0',
	);
}


/*
 * #697: from a pkg/pkg-static argv ($argv[0] = the binary), return the mapped subcommand:
 * 'delete' (delete/remove/autoremove), 'upgrade', 'reinstall' (install with -f/--force), 'install'
 * (bare install), or '' (anything else).
 *
 * pkg's grammar is `pkg [GLOBAL opts] <command> [command flags]`, and several GLOBAL options come
 * BEFORE the subcommand and CONSUME the following token as their value (-o -j -c -r -C -R and the
 * long forms). Those are skipped WITH their value before the subcommand is read -- pfSense passes
 * -c <chroot> / -r <rootdir> during an OS upgrade, so a naive "first non-dash token" read would
 * misfire exactly then.
 */
function pfb_pkg_argv_subcommand(array $argv): string {
	// Global options that consume the FOLLOWING token as their value (separated form).
	$arg_taking_long  = array('--option', '--jail', '--chroot', '--rootdir', '--config', '--repo-conf-dir');
	$arg_taking_short = array('-o', '-j', '-c', '-r', '-C', '-R');

	$n = count($argv);
	$i = 1;	// $argv[0] is the binary
	while ($i < $n) {
		$tok = (string) $argv[$i];
		if ($tok === '' || $tok[0] !== '-') {
			break;	// first non-option token => the subcommand
		}
		// Attached value (`--rootdir=/x`, `-r/x`) consumes no extra token.
		if (str_contains($tok, '=')) {
			$i++;
			continue;
		}
		if (in_array($tok, $arg_taking_short, TRUE) || in_array($tok, $arg_taking_long, TRUE)) {
			$i += 2;	// skip the flag AND its value
			continue;
		}
		// Short arg-taking flag with the value glued on (`-r/root`, `-jname`): consume only this token.
		if (strlen($tok) > 2 && in_array(substr($tok, 0, 2), $arg_taking_short, TRUE)) {
			$i++;
			continue;
		}
		// No-arg global flag (-v -d -l -N -4 -6, bundles), or an unrecognised bare flag: skip just it.
		$i++;
	}
	if ($i >= $n) {
		return '';
	}

	switch (strtolower((string) $argv[$i])) {
		case 'delete':
		case 'remove':
		case 'autoremove':
			return 'delete';
		case 'upgrade':
			return 'upgrade';
		case 'install':
			// -f/--force among the COMMAND flags => a forced reinstall.
			for ($j = $i + 1; $j < $n; $j++) {
				$f = (string) $argv[$j];
				if ($f === '-f' || $f === '--force') {
					return 'reinstall';
				}
				if (strlen($f) > 1 && $f[0] === '-' && $f[1] !== '-' && str_contains($f, 'f')) {
					return 'reinstall';	// bundled short flags, e.g. -fy
				}
			}
			return 'install';
		default:
			return '';
	}
}


/*
 * #697: classify the current package-manager operation by reading the pkg/pkg-static ANCESTOR's
 * argv. Pure (no I/O) so it is unit-testable: $ps_lines is `ps -o pid,ppid,command` output (one
 * process per line, "PID PPID COMMAND ..."), $start_pid is the pid to walk up from. Walks the ppid
 * chain and, at the first ancestor that is pkg/pkg-static, parses + maps the subcommand. Returns ''
 * when there is no pkg ancestor (a normal cron/manual update, or the GUI) or the subcommand is
 * unrecognised.
 *
 * KEY limitation (the reason the pre-deinstall no longer branches on this): a real uninstall and a
 * pfSense OS-upgrade removal are the SAME `pkg delete` -- indistinguishable here. The op's
 * discriminating value is in the post-install (fresh 'install' vs 'upgrade' vs forced 'reinstall');
 * it rides to update hooks as PFB_PKG_OP for context only, never a teardown decision.
 */
function pfb_parse_pkg_operation(array $ps_lines, int $start_pid): string {
	$procs = array();	// pid => array(ppid, argv[])
	foreach ($ps_lines as $line) {
		$parts = preg_split('/\s+/', trim((string) $line));
		if (!is_array($parts) || count($parts) < 3 || !ctype_digit($parts[0]) || !ctype_digit($parts[1])) {
			continue;	// header row / malformed
		}
		$procs[(int) $parts[0]] = array((int) $parts[1], array_slice($parts, 2));
	}

	$pid  = $start_pid;
	$seen = array();
	for ($hops = 0; $hops < 64; $hops++) {
		if (!isset($procs[$pid]) || isset($seen[$pid])) {
			break;
		}
		$seen[$pid] = TRUE;
		list($ppid, $argv) = $procs[$pid];

		// $argv always has >= 1 element (the count()<3 guard above skips shorter rows).
		$bin = basename((string) $argv[0]);
		if ($bin === 'pkg' || $bin === 'pkg-static') {
			$op = pfb_pkg_argv_subcommand($argv);
			if ($op !== '') {
				return $op;
			}
		}

		if ($ppid <= 1 || $ppid === $pid) {
			break;
		}
		$pid = $ppid;
	}
	return '';
}


/*
 * #697: thin, cached wrapper around pfb_parse_pkg_operation() that reads the live process table.
 * Returns the current pkg operation ('install'/'upgrade'/'reinstall'/'delete') or '' when not run
 * under pkg. Cached per-process: hooks call it once per fire point and it must not re-ps each time.
 */
function pfb_pkg_operation(): string {
	static $cached = NULL;
	if ($cached !== NULL) {
		return $cached;
	}
	$out = array();
	$rc  = 0;
	exec('/bin/ps -axww -o pid,ppid,command 2>/dev/null', $out, $rc);
	$cached = ($rc === 0) ? pfb_parse_pkg_operation($out, (int) getmypid()) : '';
	return $cached;
}


/*
 * #697: does a pre-deinstall pass that saw pkg operation $op perform a FULL teardown (turn
 * pfBlockerNG OFF + remove live objects), or SKIP it to keep pfBlockerNG live? Pure decision.
 *
 * pfSense reaches our pre-deinstall for BOTH a genuine removal and an in-place package
 * reinstall/upgrade, but with a DIFFERENT pkg operation: a real uninstall (and a major OS upgrade's
 * mass-removal) is `pkg delete` -> 'delete'; the GUI Update / a `pkg upgrade` / a forced reinstall
 * is `pkg install -f` / `pkg upgrade` -> 'install'|'reinstall'|'upgrade'. So tear down ONLY on a
 * delete; keep pfBlockerNG live across a package upgrade/reinstall (its resync re-applies). An
 * unrecognised/undetectable op ('') FAILS SAFE to teardown -- a real uninstall is always a
 * detectable `pkg delete`, so '' can only be an odd case, and tearing down (rebuilt by any following
 * resync, config kept by keep=on) never orphans live objects the way a wrong skip would.
 */
function pfb_pkg_op_tears_down(string $op): bool {
	return $op === 'delete' || $op === '';
}


/*
 * #693 (follow-up to #690): mirror a completed hook's captured stdout/stderr to the
 * package-manager output during a pkg install/upgrade/uninstall.
 *
 * pfb_run_hooks() redirects each hook's stdout+stderr to a LOG FILE, never a pipe, so a hook that
 * (re)starts a daemon -- e.g. the documented HAProxy graceful reload -- cannot hold exec()'s
 * capture pipe open and hang the pass (#662). The cost: the hook's own output then lands only in
 * that file, so pfSense's Software page (which shows only STDOUT) frames the hook with its
 * "[ pfB Hook ] ..." markers but shows an empty body. While a lifecycle callback is active
 * ($pfb['hook_lifecycle'], set by the install command / pre-deinstall), print exactly the bytes
 * the hook just appended ($logfile from $offset to EOF) so the page shows what it did.
 *
 * The bytes are ALREADY in the log file (the shell append), so this only prints -- it never
 * re-logs. Reading a regular file cannot hang: a lingering daemon holds a harmless file fd, not
 * this reader. No-op outside a lifecycle callback (a normal cron/manual/Run-Now pass already
 * streams the hook body to the per-run log the Update-page tail reads).
 */
function pfb_mirror_hook_output(string $logfile, int $offset): void {
	global $pfb;

	if (empty($pfb['hook_lifecycle']) || $logfile === '') {
		return;
	}
	clearstatcache(TRUE, $logfile);
	$end = @filesize($logfile);
	if ($end === FALSE || $end <= $offset) {
		return;
	}
	$body = @file_get_contents($logfile, FALSE, NULL, $offset, $end - $offset);
	if (is_string($body) && $body !== '') {
		print $body;
	}
}


/*
 * issue #973: restores ADR-12's persistence promise for the normal cron/manual/Run-Now pass --
 * copies the delta a hook wrote to runlog back into $pfb['log']. No-op when $logfile IS
 * $pfb['log'] already (outside a run) -- else this would duplicate its own tail into itself.
 */
function pfb_persist_hook_output(string $logfile, int $offset): void {
	global $pfb;

	if ($logfile === '' || $logfile === $pfb['log']) {
		return;
	}
	clearstatcache(TRUE, $logfile);
	$end = @filesize($logfile);
	if ($end === FALSE || $end <= $offset) {
		return;
	}
	$body = @file_get_contents($logfile, FALSE, NULL, $offset, $end - $offset);
	if (is_string($body) && $body !== '') {
		@file_put_contents($pfb['log'], $body, FILE_APPEND);
	}
}


/*
 * Run every enabled hook matching $when, in list order, as root.
 *
 * $ctx is a flat name => value map exported to each hook as PFB_* environment
 * variables (e.g. ['TRIGGER' => 'cron'] => PFB_TRIGGER=cron). PFB_WHEN is always
 * set to $when. Each script runs under /usr/bin/timeout so a hung child is
 * killed (SIGTERM, then SIGKILL after PFB_HOOK_KILL_GRACE seconds); stdout+stderr
 * are captured and written to the pfBlockerNG log under a per-hook header.
 *
 * A non-zero exit (incl. timeout(1)'s 124) or any failure is logged and the next
 * hook runs. This function never throws and never aborts the caller.
 */
function pfb_run_hooks($when, $ctx = array()) {
	global $pfb;

	$pfbconfig = config_get_path('installedpackages/pfblockerng/config/0', []);
	$hooks = pfb_get_hooks($pfbconfig, $when);
	if (empty($hooks)) {
		return;	// No enabled hooks for this fire point: byte-identical no-op.
	}
	$python = null;

	// Build the PFB_* env-var prefix shared by every hook of this run.
	if (!is_array($ctx)) {
		$ctx = array();
	}
	$ctx['WHEN'] = $when;
	// Package-lifecycle context (issue #684): a lifecycle transition fires these hooks like any
	// other enable/disable, and tells the hook WHICH transition so its owner can react (or no-op).
	// PFB_POST_INSTALL=1 when the pass is the install/upgrade resync (turn ON); PFB_PRE_UNINSTALL=1
	// when it is the pre-deinstall (turn OFF); both '0' on a normal cron/manual/force update
	// (always emitted as '1'/'0', #695).
	$ctx += pfb_hook_lifecycle_ctx($pfb['hook_lifecycle'] ?? '');
	// #697: the actual package-manager operation read from the pkg ancestor's argv, so a hook can
	// tell a fresh install from an upgrade (PFB_PKG_OP = install|upgrade|reinstall|delete; '' when
	// the pass is not run under pkg -- a normal cron/manual update). Context only.
	$ctx['PKG_OP'] = pfb_pkg_operation();
	$env = array();
	foreach ($ctx as $name => $value) {
		// Names are developer-controlled (PFB_TRIGGER, PFB_IP_CHANGED, ...); values
		// are escaped. Defence in depth: a name is a shell var-assignment LHS (it
		// cannot be quoted), so drop any key that is not a bare word -- so a future
		// caller can never turn a $ctx key into shell syntax. Values ride
		// escapeshellarg; the prefix (VAR=val cmd ...) is inherited by timeout(1) and
		// exported to the hook's child only.
		$pfbvar = strtoupper((string) $name);
		if (!preg_match('/^[A-Z0-9_]+$/', $pfbvar)) {
			continue;
		}
		$env[] = 'PFB_' . $pfbvar . '=' . escapeshellarg((string) $value);
	}
	$envprefix = implode(' ', $env);

	foreach ($hooks as $idx => $hook) {
		$desc    = trim((string) ($hook['description'] ?? ''));
		$script  = (string) ($hook['script'] ?? '');
		$timeout = pfb_hook_timeout($hook);
		$label   = ($desc !== '') ? $desc : "#{$idx}";

		// Security model (ADR-12): a hook runs a VETTED on-box script file, never a
		// GUI-entered command. Re-check the allow-list at run time (defence in depth
		// vs a hand-edited config.xml): the script must be a hook_<when>_*.{sh,py}
		// basename present in the hook-script dir. Anything else is logged + skipped,
		// never executed.
		if (!pfb_hook_script_valid($script, $when)) {
			$missing = ($script !== '') ? "'{$script}' " : '';
			pfb_logger("[ pfB Hook ] {$when} {$label} script {$missing}not a valid file in " .
				PFB_HOOK_SCRIPT_DIR . "; skipping\n", 2);
			continue;
		}
		$path = PFB_HOOK_SCRIPT_DIR . '/' . basename($script);
		if (str_ends_with($script, '.py') && $python === null) {
			$python = pfb_python_interpreter() !== '' ? PFB_PYTHON_WRAPPER : '';
		}
		$hookcmd = pfb_hook_script_command($script, $path, (string) $python);
		if ($hookcmd === '') {
			pfb_logger("[ pfB Hook ] {$when} {$label} script '{$script}' has no usable launcher; skipping\n", 2);
			continue;
		}

		// The script basename is safe to log (a filename, not a command line that
		// could carry inline secrets); it aids correlating the log to the file.
		$header = "\n[ pfB Hook ] {$when} {$label} ({$script}, timeout {$timeout}s)\n";
		pfb_logger($header, 1);

		// Run the vetted script as root under timeout(1): SIGTERM at $timeout,
		// SIGKILL after the grace period. The PFB_* context rides the env prefix
		// (the script reads it from the environment). Shell scripts run via their own
		// shebang + execute bit; Python scripts use the package wrapper.
		//
		// Two independent reasons a hook that (re)starts a daemon -- e.g. the documented
		// HAProxy graceful-reload recipe -- would otherwise hang the WHOLE pass for the
		// timeout budget and then falsely report TIMED OUT, though the hook's own work
		// finished in milliseconds:
		//
		//   1. timeout(1) (FreeBSD, default mode) acquires a process REAPER
		//      (procctl PROC_REAP_ACQUIRE) and does NOT exit when its direct child exits
		//      -- it waits until EVERY descendant is gone (reap rs_children == 0), then on
		//      the alarm signals the whole reaped tree. A daemon the hook spawned keeps it
		//      waiting, so the budget elapses and the SIGTERM would even kill the
		//      just-reloaded daemon. --foreground disables the reaper: timeout exits as
		//      soon as the DIRECT hook process exits (a genuine overrun is still SIGTERM'd,
		//      kill(child)), leaving any daemon reparented to init.
		//   2. A spawned daemon inherits the hook's stdout/stderr. If those are exec()'s
		//      capture pipe, exec() never reads EOF while the daemon lives. Redirecting to a
		//      regular FILE (the pfB log, held harmlessly by the daemon) + stdin from /dev/null
		//      decouples exec() from the daemon.
		//
		// Together, completion depends ONLY on the hook process exiting.
		//
		// Append straight to a REGULAR FILE (not a temp file flushed after exec(), and never a
		// pipe/tee -- reason #2 above: a pipe the hook's spawned daemon inherits would hang exec()
		// on missing EOF). During a run this is the per-run log the live tail reads ($pfb['runlog'],
		// with pfb_logger() mirroring into the same file, so the hook's output and the surrounding
		// "[ pfB Hook ] ..." markers interleave and stream AS the hook runs); outside a run it falls
		// back to the cumulative log. (A rare lingering daemon could append a stray line later --
		// cosmetic.)
		$logtarget = pfb_run_log_target();
		$logf = escapeshellarg($logtarget);
		$cmd = "{$envprefix} /usr/bin/timeout --foreground -s TERM -k " . PFB_HOOK_KILL_GRACE .
			" {$timeout} {$hookcmd} >> {$logf} 2>&1 < /dev/null";

		// #693: the hook's own stdout/stderr goes to the log FILE above (never a pipe -- a hook
		// that restarts a daemon would otherwise hang exec(), #662), so on the pkg Software page
		// only the surrounding pfb_logger() markers show and the hook body is invisible. Record
		// where the log ends BEFORE the hook runs so we can mirror exactly what it appends.
		clearstatcache(TRUE, $logtarget);
		$hook_log_offset = (int) (@filesize($logtarget) ?: 0);

		$discard = array();
		$retval  = 0;

		if (empty($pfb['hook_lifecycle'])) {
			// Normal cron/manual/Run-Now pass: unchanged synchronous exec(). The Update page's own
			// AJAX tail already streams $logtarget (the per-run log) live, so no extra STREAMING
			// mirror is needed here -- issue #973's pfb_persist_hook_output() below only persists.
			exec($cmd, $discard, $retval);
			pfb_persist_hook_output($logtarget, $hook_log_offset);
		} else {
			// pkg install/upgrade/uninstall (lifecycle callback): STREAM the hook's own output to
			// the pkg Software page AS it runs, instead of one block after it exits.
			// pfb_mirror_hook_output() (below) only closed the "arrives at all" gap (#693); this
			// closes "arrives live". proc_open() runs the hook as a DIRECT child with its
			// stdout/stderr pointed at the log FILE via the descriptor spec -- never a pipe back to
			// PHP, so a hook that restarts a daemon inheriting fd 1 still can't hang us (#662), the
			// daemon just holds a harmless file fd. We track the child with proc_get_status() (no
			// daemon(8)/pidfile needed) and tail the file to stdout while it runs; the exit code
			// (124 on timeout, else the hook's own) comes straight off the status.
			$descriptors = array(
				0 => array('file', '/dev/null', 'r'),
				1 => array('file', $logtarget, 'a'),
				2 => array('file', $logtarget, 'a'),
			);
			$proccmd = "{$envprefix} /usr/bin/timeout --foreground -s TERM -k " .
				PFB_HOOK_KILL_GRACE . " {$timeout} {$hookcmd}";
			$pipes = array();
			$proc  = @proc_open($proccmd, $descriptors, $pipes);

			if (!is_resource($proc)) {
				// proc_open unavailable/failed -- never lose the hook run: fall back to the exact
				// synchronous path, then mirror the captured body once.
				exec($cmd, $discard, $retval);
				pfb_mirror_hook_output($logtarget, $hook_log_offset);
			} else {
				// Tail the delta while the hook is alive, then drain the trailing partial line.
				// The loop is bounded so a wedged status can't spin forever -- timeout(1) already
				// kills the hook at $timeout + PFB_HOOK_KILL_GRACE, so a healthy child always reports
				// exit well inside the cap; exhausting it means the child never reported dead.
				$off     = $hook_log_offset;
				$maxiter = (int) ceil(($timeout + PFB_HOOK_KILL_GRACE + 10) / 0.2);
				$exited  = FALSE;
				for ($i = 0; $i < $maxiter; $i++) {
					$chunk = pfb_log_tail_chunk($logtarget, $off, FALSE);
					if ($chunk['data'] !== '') {
						print $chunk['data'];
					}
					$off = $chunk['offset'];
					$st  = proc_get_status($proc);
					if (!$st['running']) {
						// First not-running read carries the real exit code (later reads/close give -1).
						$retval = (int) $st['exitcode'];
						$exited = TRUE;
						break;
					}
					usleep(200000);
				}
				$chunk = pfb_log_tail_chunk($logtarget, $off, TRUE);
				if ($chunk['data'] !== '') {
					print $chunk['data'];
				}
				if (!$exited) {
					// Cap exhausted with the child still "running" -- a pathologically wedged process.
					// Don't let proc_close() block on it, and don't mis-log success: kill it and mark
					// the status unknown (-1) so the branch below logs a failure, not "completed".
					@proc_terminate($proc, 9);
					$retval = -1;
				}
				proc_close($proc);
			}

			// issue #988: this branch streams to $logtarget same as the normal pass does --
			// persist its delta into $pfb['log'] too (covers both the proc_open and the
			// exec() fallback sub-paths above; no-op outside a run).
			pfb_persist_hook_output($logtarget, $hook_log_offset);
		}

		if ($retval === 124) {
			pfb_logger("[ pfB Hook ] {$when} {$label} TIMED OUT after {$timeout}s (killed); continuing\n", 2);
		} elseif ($retval !== 0) {
			pfb_logger("[ pfB Hook ] {$when} {$label} exited non-zero [ {$retval} ]; continuing\n", 2);
		} else {
			pfb_logger("[ pfB Hook ] {$when} {$label} completed\n", 1);
		}
	}
}

/*
 * Map sync_package_pfblockerng()'s $cron argument to a stable PFB_TRIGGER value
 * for the hook context. The ADR's nominal set is cron|update|force-update|force-reload;
 * in practice this emits cron|update|force-reload (see below -- force-update collapses
 * to cron because the GUI Force Update dispatches the same 'pfblockerng.php update' that
 * calls sync_package_pfblockerng('cron'), indistinguishable from the scheduled cron).
 *
 * What each $cron value means at the fire points (verified against the callers):
 *   'updateip' / 'updatednsbl' -> a GUI "Force Reload" of just IP or just DNSBL
 *       (pfblockerng_update.php -> pfblockerng.php updateip|updatednsbl) => force-reload.
 *   'cron'  -> the scheduled cron job (pfblockerng.php cron -> pfblockerng_sync_cron),
 *       AND the GUI "Force Update" / "Force Reload (All)" actions, which dispatch
 *       'pfblockerng.php update' and likewise call sync_package_pfblockerng('cron').
 *       These are INDISTINGUISHABLE inside the pass (same $cron), so 'cron' is the
 *       honest label; a hook that needs to know it ran from the GUI cannot tell here.
 *   'noupdates' -> the cron path's "nothing to update" branch => cron.
 *   '' (default) -> a settings save (pfblockerng_general.php) or the de-install path
 *       => update.
 */
function pfb_hook_trigger($cron) {
	switch ((string) $cron) {
		case 'updateip':
		case 'updatednsbl':
			return 'force-reload';
		case 'cron':
		case 'noupdates':
			return 'cron';
		default:
			return 'update';
	}
}


/*
 * Map a pfblockerng.php verb (or the $cron value passed to sync_package_pfblockerng())
 * to an explicit trigger request struct: reload scope, force flag, and trigger identity.
 *
 * Returns: array { 'scope'   => 'ip'|'dnsbl'|'both',
 *                  'force'   => bool,
 *                  'trigger' => 'cron'|'manual'|'force' }
 *
 * ADR-43: 'update' now gets its own 'manual' trigger identity (previously 'cron').
 * PFB_TRIGGER is now derived by pfb_req_to_hook_trigger() from the struct's 'trigger' field:
 *   'cron'   → 'cron'          (scheduled cron and noupdates)
 *   'manual' → 'update'        (pfblockerng.php 'update' verb, HA-sync, settings save)
 *   'force'  → 'force-reload'  (updateip / updatednsbl)
 *
 * 'noupdates' and '' (settings save / de-install) carry the same struct as 'cron'; their
 * side-channel behaviour ($pfb['save']=TRUE; no-scope-change) is handled by sync_package.
 *
 * ADR-43 — oracle: TriggerRequestTest.php pins this table (trigger 'cron'→'manual' for 'update').
 */
function pfb_trigger_request($verb) {
	switch ((string) $verb) {
		case 'updateip':
			return ['scope' => 'ip',   'force' => TRUE,  'trigger' => 'force'];
		case 'updatednsbl':
			return ['scope' => 'dnsbl', 'force' => TRUE,  'trigger' => 'force'];
		case 'update':
			// ADR-43: 'update' gets its own 'manual' trigger identity.
			// pfblockerng.php now passes 'update' (not 'cron') so the verb is distinguishable
			// inside the pass. PFB_TRIGGER = pfb_req_to_hook_trigger('manual') = 'update'.
			return ['scope' => 'both', 'force' => FALSE, 'trigger' => 'manual'];
		default:
			// 'cron', 'noupdates', '', unknown
			return ['scope' => 'both', 'force' => FALSE, 'trigger' => 'cron'];
	}
}


/*
 * Map the 'trigger' field of a pfb_trigger_request() struct to the ADR-12 PFB_TRIGGER value.
 *
 * ADR-43: replaces the direct pfb_hook_trigger($cron) calls in sync_package_pfblockerng()
 * for the array (new API) path. The string path still uses pfb_hook_trigger() directly so the
 * back-compat mapping is preserved without duplication.
 *
 *   'force'  → 'force-reload'
 *   'manual' → 'update'
 *   'cron'   → 'cron'   (default)
 */
function pfb_req_to_hook_trigger($trigger) {
	switch ((string) $trigger) {
		case 'force':  return 'force-reload';
		case 'manual': return 'update';
		default:       return 'cron';
	}
}


/*
 * Return the deprecation warning string for a legacy verb string, or '' if not deprecated.
 *
 * ADR-43: 'update', 'updateip', 'updatednsbl' are DEPRECATED as sync_package_pfblockerng()
 * string arguments. Callers should pass the explicit {scope, force, trigger} request array instead
 * (or use pfb_trigger_request($verb) to build it). Removal is scheduled for a future major release.
 *
 * Called from sync_package_pfblockerng()'s string-path normalization for the safety-net case where
 * a caller bypasses the pfblockerng.php adapters and passes a deprecated string directly.
 * Also called from pfblockerng.php's deprecated verb cases before they route to the new API.
 */
function pfb_verb_deprecation_warning($verb) {
	static $map = [
		'update'      => 'scope=both force=false trigger=manual',
		'updateip'    => 'scope=ip force=true trigger=force',
		'updatednsbl' => 'scope=dnsbl force=true trigger=force',
	];
	$v = (string) $verb;
	if (!isset($map[$v])) {
		return '';
	}
	return "DEPRECATED: pfblockerng verb '{$v}' — use explicit request ({$map[$v]}); removal scheduled";
}


// issue #993: per-feed parse-error summary wrapper extracted for unit coverage.
function pfb_ip_parse_fail_warn($parse_fail, $header) {
	if ($parse_fail > 0) {
		pfb_logger("\n[!] Parse Errors [ {$header} ]: {$parse_fail}\n", 2);
	}
}


// issue #1408: the merged CSV parse-failure sink for DNSBL + IP per-line failures.
// $keep_falsy_line: FALSE (DNSBL callers, default) coerces any falsy $line (incl.
// '0') to 'null'; TRUE (the IP caller) coerces only the empty string.
function pfb_parse_fail_log($header, $line, $oline, $logfile, $lineno = '', bool $keep_falsy_line = FALSE) {
	$line = $keep_falsy_line ? ($line !== '' ? $line : 'null') : ($line ?: 'null');
	// issue #1004: strip the raw fgets() line's trailing \n and terminate the row here,
	// so the appended $lineno column can't split the record and empty field0 (ADR-60).
	$oline = rtrim((string) $oline, "\r\n");
	$now   = pfb_log_iso_timestamp();
	$log   = "{$now},{$header},{$line},{$oline},{$lineno}\n";
	@file_put_contents("{$logfile}", "{$log}", FILE_APPEND);
}


// Map an IP list's vtype ('_v4'/'_v6') to its config section. The download loop
// runs AFTER the $ip_types collection loop, so $ip_type is left at its last value
// ('pfblockernglistsv6') there; deriving the section from the list's own vtype keeps
// a v4 list reading the v4 section instead of the stale v6 one (#709).
function pfb_list_section_for_vtype(string $vtype): string {
	return ($vtype === '_v6') ? 'pfblockernglistsv6' : 'pfblockernglistsv4';
}


// issue #993: opposite-family predicate extracted for unit coverage. A syntactically
// valid address of the list's OTHER family is not a parse failure (mixed-family feeds).
function pfb_ip_is_opposite_family(string $line, string $vtype): bool {
	return ($vtype === '_v4' && str_contains($line, ':') && validate_ipv6($line)) ||
		($vtype === '_v6' && !str_contains($line, ':') && validate_ipv4($line));
}

// Drop the Blacklist categories whose download Failed, matching by feed NAME in the
// child's output line rather than the stdout-line index. pfblockerng_download_extras
// only processes the not-yet-downloaded types and silently skips some feeds (e.g.
// Shallalist), so the stdout-line index does NOT map to the $lists index; a positional
// unset() removed the wrong (often a healthy, already-downloaded) category (#711). The
// child prints "\t{name} ... Failed" / "... Completed" (pfblockerng.php) with
// name == $list['aliasname']; the " ... " delimiter guards against a prefix collision.
function pfb_prune_failed_bl_lists(array $lists, array $pfb_return): array {
	foreach ($pfb_return as $return_output) {
		if (strpos($return_output, 'Failed') === FALSE) {
			continue;
		}
		foreach ($lists as $list_key => $list_val) {
			if (isset($list_val['aliasname']) &&
			    str_starts_with(ltrim($return_output), "{$list_val['aliasname']} ... ")) {
				unset($lists[$list_key]);
				break;
			}
		}
	}
	return $lists;
}

// Determine 'list' details
function pfb_determine_list_detail($list='', $header='', $confconfig='', $key='') {
	global $pfb, $pfbarr;
	$pfbarr = array();

	switch($list) {
		case 'Deny_Both':
		case 'Deny_Inbound':
		case 'Deny_Outbound':
		case 'Alias_Deny':
			$pfbarr = array('adv' => TRUE, 'folder' => "{$pfb['denydir']}", 'orig' => "{$pfb['origdir']}", 'reuse' => "{$pfb['reuse']}");
			break;
		case 'unbound':
			$pfbarr = array('adv' => FALSE, 'folder' => "{$pfb['dnsdir']}", 'orig' => "{$pfb['dnsorigdir']}", 'reuse' => "{$pfb['reuse_dnsbl']}");
			break;
		case 'Permit_Both':
		case 'Permit_Inbound':
		case 'Permit_Outbound':
		case 'Alias_Permit':
			$pfbarr = array('adv' => FALSE, 'folder' => "{$pfb['permitdir']}", 'orig' => "{$pfb['origdir']}", 'reuse' => "{$pfb['reuse']}");
			break;
		case 'Match_Both':
		case 'Match_Inbound':
		case 'Match_Outbound':
		case 'Alias_Match':
			$pfbarr = array('adv' => FALSE, 'folder' => "{$pfb['matchdir']}", 'orig' => "{$pfb['origdir']}", 'reuse' => "{$pfb['reuse']}");
			break;
		case 'Alias_Native':
			$pfbarr = array('adv' => FALSE, 'folder' => "{$pfb['nativedir']}", 'orig' => "{$pfb['origdir']}", 'reuse' => "{$pfb['reuse']}");
			break;
	}

	// Collect proper alias table description (alias only vs autorules)
	if (strpos($list, 'Alias') !== FALSE) {
		$pfbarr['descr'] = '';
	} else {
		$pfbarr['descr'] = ' Auto ';
	}

	// issue #2989: fixed spaces keep status columns aligned after the 20-character ISO timestamp.
	$pfbarr['logtab'] = str_repeat(' ', max(0, 28 - strlen($header)));

	// Configure autoports/protocol and auto destination if required.
	$conf_path = "installedpackages/{$confconfig}/config/{$key}";
	if (!empty($confconfig) && is_array(config_get_path($conf_path))) {

		$conf_config	= config_get_path($conf_path);
		$registered	= $confconfig === 'pfblockerngdnsblsettings' && (string) $key === '0';
		$toggle_enabled = static function (string $field) use ($conf_config, $registered): bool {
			if ($registered) {
				return PfbConfig::read("dnsbl/{$field}") === PfbToggle::On;
			}
			return pfb_dnsbl_toggle_enabled($conf_config[$field] ?? '');
		};
		$autotype	= array( 'autoports' => 'aliasports', 'autoaddr' => 'aliasaddr');

		foreach (array('_out', '_in') as $dir) {

			$pfbarr['aproto' . $dir]	= $conf_config['autoproto' . $dir];
			$pfbarr['anot' . $dir]		= $toggle_enabled('autonot' . $dir) ? 'on' : '';
			$pfbarr['aaddrnot' . $dir]	= $toggle_enabled('autoaddrnot' . $dir) ? 'on' : '';
			$pfbarr['agateway' . $dir]	= $conf_config['agateway' . $dir];

			foreach ($autotype as $akey => $atype) {
				if ($toggle_enabled($akey . $dir)) {
					foreach (config_get_path('aliases/alias', []) as $palias) {
						if ($palias['name'] == $conf_config[$atype . $dir]) {
							if (!empty($palias['address'])) {
								$dalias = "{$atype}{$dir}";
								switch($akey) {
									case 'autoports':
										$ctype = "aports{$dir}";
										$pfbarr[$ctype] = $conf_config[$dalias];
										break;
									case 'autoaddr':
										$ctype = "aaddr{$dir}";
										$pfbarr[$ctype] = $conf_config[$dalias];
										break;
								}
							}
						}
					}
				}
			}
		}
	}

	// Force 'Alias Native' setting to any Alias with 'Advanced Inbound/Outbound -Invert src/dst' settings.
	// This will bypass Deduplication and Reputation features.
	if ($pfbarr['aaddrnot_in'] === 'on' || $pfbarr['aaddrnot_out'] === 'on') {
		$pfbarr['adv'] = FALSE;
		$pfbarr['folder'] = "{$pfb['nativedir']}";
	}

	return $pfbarr;
}


// ADR-11: Return the EFFECTIVE member-file list for one aggregate action type + family — the
// input `pfblockerng.sh aggregate` unions into pfB_<Type>_Aggregated_<fam>. Pure: reads the
// per-type dir off disk (Deny->denydir, Permit->permitdir, Match->matchdir, Native->nativedir);
// no side effects; not yet called from the update pass. denydir's '<header>_<fam>.txt' members
// are ALREADY the effective (post-suppression/whitelist) set — the shell 'suppress' action
// rewrites each Deny member file in place before the alias read, so this helper must run AFTER
// that step and applies NO further suppression. DNSBLIP + Deny-action GeoIP continents fold in
// for free (land in denydir like any other member). $type/$family per GUI; [] if unknown.
function pfb_aggregate_member_list($type, $family) {
	global $pfb;

	$type_dirs = array(
		'Deny'   => $pfb['denydir'],
		'Permit' => $pfb['permitdir'],
		'Match'  => $pfb['matchdir'],
		'Native' => $pfb['nativedir'],
	);

	if (!isset($type_dirs[$type]) || ($family !== 'v4' && $family !== 'v6')) {
		return array();
	}

	// Family-suffixed '.txt' members only -- this excludes '.update' markers, '.ip'
	// feeds and any non-family scratch files in the dir.
	$members = glob("{$type_dirs[$type]}/*_{$family}.txt");
	if ($members === FALSE) {
		return array();
	}

	sort($members);

	// Drop placeholder-only member files. pfBlockerNG pads a zero-IP/failed feed (and an
	// empty DNSBLIP file) with the synthetic placeholder IP -- $pfb['ip_ph'] (e.g.
	// 127.1.7.7), '::'-prefixed for v6 -- so the per-alias file is never empty (inc:9901 /
	// :10841). That is an internal empty-file hack: it must NOT enter the aggregate union or
	// pfB_<Type>_Aggregated_<fam> would carry the fake IP. An empty union is already handled
	// by the action's never-empty consumer, so skipping these here is safe.
	$ip_ph = (string) ($pfb['ip_ph'] ?? '');
	$placeholder = ($ip_ph === '') ? '' : pfb_placeholder_for_family($ip_ph, $family);
	$kept = array();
	foreach ($members as $member) {
		if (!pfb_member_file_is_placeholder_only($member, $placeholder)) {
			$kept[] = $member;
		}
	}
	return $kept;
}


// TRUE iff every non-blank, non-comment line of $path equals $placeholder -- i.e. the file
// is an empty-feed placeholder ($pfb['ip_ph']) that contributes nothing real to an aggregate
// (see pfb_aggregate_member_list). An empty placeholder, or an unreadable/empty file, is NOT
// placeholder-only (an empty file simply unions to nothing); a comment-only file is treated
// as placeholder-only (it likewise adds no addresses).
function pfb_member_file_is_placeholder_only($path, $placeholder) {
	if ($placeholder === '') {
		return FALSE;
	}
	$bare = str_starts_with($placeholder, '::') ? substr($placeholder, 2) : $placeholder;
	$tokens = array($placeholder);
	if ($bare !== '' && $bare !== $placeholder) {
		$tokens[] = $bare;
	} elseif ($bare !== '') {
		$tokens[] = '::' . $bare;
	}
	$lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
	if ($lines === FALSE || empty($lines)) {
		return FALSE;
	}
	foreach ($lines as $line) {
		$line = trim($line);
		if ($line === '' || $line[0] === '#') {
			continue;
		}
		if (!in_array($line, $tokens, TRUE)) {
			return FALSE;
		}
	}
	return TRUE;
}


// Widget requests do not run apply.inc, so $pfb['ip_ph'] is unset —
// read and filter the IP-tab value pfb_global() loads (default 127.1.7.7).
function pfb_ip_placeholder(): string {
	global $pfb;
	$raw = $pfb['ipconfig']['ip_placeholder'] ?? '';
	$filtered = pfb_filter($raw, PFB_FILTER_IPV4, 'Placeholder IP Address', '127.1.7.7');
	if (!is_string($filtered) || $filtered === '') {
		return '127.1.7.7';
	}
	return $filtered;
}


// v6 alias files are padded as ::<ip_ph>; v4 as the bare IPv4.
function pfb_placeholder_for_family(string $ip_ph, string $family): string {
	return ($family === 'v6') ? "::{$ip_ph}" : $ip_ph;
}


// Widget/IP-table display count (issue #2645). Kernel Addresses includes
// the placeholder when pf loaded the padded file. A placeholder-only file
// with Addresses==1 is an empty feed — show 0. Addresses>1 skips the file
// slurp (deny lists can be 10^5–10^6 lines). Mixed files keep Addresses.
function pfb_widget_alias_display_count(int $addresses, string $alias_file, string $placeholder): int {
	if ($addresses > 1) {
		return $addresses;
	}
	if ($addresses < 1) {
		return 0;
	}
	if (pfb_member_file_is_placeholder_only($alias_file, $placeholder)) {
		return 0;
	}
	return $addresses;
}


/**
 * issue #1250: sweep matchgendir's machine-generated artifacts -- Reputation dMax's per-alias
 * 'pfB_Match_Rep_<header>_<fam>.txt', the ccwhite consolidated exempt file, and the ET/
 * Proofpoint match file all moved off pfbmatch, so the generic per-type reaper (keyed on
 * config headers) can never reap them; this is their own keep-list + sweep, extracted so it
 * is unit-testable outside sync_package_pfblockerng() (MatchGenReapTest).
 *
 * @param string[] $existing_deny $pfb['existing']['deny'] -- '<header>_v4'/'<header>_v6' names.
 * @param bool     $ccwhite_match TRUE iff $pfb['ccwhite'] == 'match' (the exempt file's only writer).
 * @param string   $matchgendir   Absolute matchgendir path (no trailing slash).
 * @return string[] Basenames actually reaped; staging artifacts retain their '.txt.new' suffix.
 */
function pfb_matchgen_reap(array $existing_deny, bool $ccwhite_match, string $matchgendir): array {
	// pfB_Match_ET_v4/_v6 are always kept: the reaper runs before processet() in
	// sync_package_pfblockerng(), so gating on "did ET run this pass" reaped a live file
	// on any pass ET did not execute (issue #1269). Family-complete: a keep entry for an
	// absent file is a no-op, a MISSING entry is a deletion the day a v6 writer lands.
	$keep = array('pfB_Match_ET_v4', 'pfB_Match_ET_v6');
	if ($ccwhite_match) {
		$keep[] = 'pfB_Match_Exempt_v4';
		$keep[] = 'pfB_Match_Exempt_v6';
	}
	foreach ($existing_deny as $pfb_deny_name) {
		$keep[] = "pfB_Match_Rep_{$pfb_deny_name}";
	}

	$actual = array();
	foreach (glob("{$matchgendir}/*.txt") ?: [] as $pfb_file) {
		$actual[] = basename($pfb_file, '.txt');
	}

	$reaped = array();
	foreach (array_diff($actual, $keep) as $pfb_orphan) {
		if (!empty(pfb_filter($pfb_orphan, PFB_FILTER_WORD, 'Remove un-associated matchgen artifact'))) {
			unlink_if_exists("{$matchgendir}/{$pfb_orphan}.txt");
			$reaped[] = $pfb_orphan;
		}
	}
	foreach (glob("{$matchgendir}/*.txt.new") ?: [] as $pfb_file) {
		$pfb_orphan = basename($pfb_file, '.txt.new');
		if (!empty(pfb_filter($pfb_orphan, PFB_FILTER_WORD, 'Remove stale matchgen staging artifact'))) {
			unlink_if_exists($pfb_file);
			$reaped[] = "{$pfb_orphan}.txt.new";
		}
	}
	return $reaped;
}


/**
 * issue #1250: upgrade migration -- decide the fate of every top-level *.txt in the OLD
 * matchdir before machine-owned artifacts move into matchgendir under pfB_Match_* names. A
 * user's own Match-list file always carries a family suffix ('<header>_v4'/'_v6',
 * pfblockerng.inc's Download/Collect header build), so the un-suffixed 'ETMatch.txt' is
 * unambiguous; 'matchdedup_v4'/'match<header>_<fam>' can collide with a same-named user list
 * and are cross-referenced against the configured Deny/Match headers -- same shape as
 * pfb_matchgen_reap()'s keep-list, extended with the Match side for the collision check.
 * Pure: no filesystem writes, so the whole decision table is unit-testable.
 *
 * @param string[] $matchdir_files    Top-level basenames (with '.txt') found in matchdir.
 * @param string[] $existing_deny     $pfb['existing']['deny'] -- '<header>_v4'/'<header>_v6'.
 * @param string[] $existing_match    $pfb['existing']['match'] -- same shape, Match lists.
 * @param bool     $ccwhite_match     TRUE iff $pfb['ccwhite'] == 'match'.
 * @param string[] $matchgendir_files Basenames (with '.txt') already in matchgendir (no-clobber).
 * @return array{move: array<string,string>, leave: string[],
 *               undecidable: array<int,array{file:string,candidates:string[]}>}
 */
function pfb_matchdir_migrate_plan(array $matchdir_files, array $existing_deny, array $existing_match, bool $ccwhite_match, array $matchgendir_files): array {
	$plan = array('move' => array(), 'leave' => array(), 'undecidable' => array());

	// No-clobber: record the move unless the destination already exists in matchgendir --
	// covers both a genuine name clash and a re-run against an already-migrated file.
	$plan_move = function (string $src, string $dest) use (&$plan, $matchgendir_files): void {
		if (in_array($dest, $matchgendir_files, TRUE)) {
			$plan['leave'][] = $src;
		} else {
			$plan['move'][$src] = $dest;
		}
	};

	foreach ($matchdir_files as $pfb_file) {
		if (substr($pfb_file, -4) !== '.txt') {
			$plan['leave'][] = $pfb_file;
			continue;
		}
		$pfb_stem = substr($pfb_file, 0, -4);

		if ($pfb_stem === 'ETMatch') {
			// No family suffix: unreachable by any user list -- always the ET artifact.
			$plan_move($pfb_file, 'pfB_Match_ET_v4.txt');
			continue;
		}

		// Anchored at the end, so an embedded underscore in the header (e.g.
		// 'match_Spam_Feed_v4') never gets mis-split at the FIRST underscore; the ccwhite
		// Exempt write is just a third candidate source cross-referenced like Deny/Match.
		if (preg_match('/^match(.*)_(v4|v6)$/', $pfb_stem, $pfb_m)) {
			$pfb_header     = $pfb_m[1];
			$pfb_fam        = $pfb_m[2];
			$pfb_deny_hit   = in_array("{$pfb_header}_{$pfb_fam}", $existing_deny, TRUE);
			$pfb_match_hit  = in_array("match{$pfb_header}_{$pfb_fam}", $existing_match, TRUE);
			// The consolidated write only ever produced the _v4 stem -- _v6 never collides.
			$pfb_exempt_hit = ($pfb_header === 'dedup' && $pfb_fam === 'v4' && $ccwhite_match);

			$pfb_candidates = array();
			if ($pfb_deny_hit) {
				$pfb_candidates[] = "Deny list \"{$pfb_header}\"";
			}
			if ($pfb_match_hit) {
				$pfb_candidates[] = "Match list \"match{$pfb_header}\"";
			}
			if ($pfb_exempt_hit) {
				$pfb_candidates[] = 'the consolidated ccwhite Exempt write';
			}

			if (count($pfb_candidates) >= 2) {
				$plan['undecidable'][] = array('file' => $pfb_file, 'candidates' => $pfb_candidates);
			} elseif ($pfb_deny_hit) {
				$plan_move($pfb_file, "pfB_Match_Rep_{$pfb_header}_{$pfb_fam}.txt");
			} elseif ($pfb_exempt_hit) {
				$plan_move($pfb_file, 'pfB_Match_Exempt_v4.txt');
			} else {
				// Match-only (the user's file) or neither (an orphan -- the matchgendir
				// reaper's problem, never re-homed into the namespace it'd be reaped from).
				$plan['leave'][] = $pfb_file;
			}
			continue;
		}

		$plan['leave'][] = $pfb_file;
	}

	return $plan;
}

/**
 * issue #1250: upgrade migration -- build the Deny/Match header-name sets and the flattened
 * real-row list pfb_matchdir_migrate_plan() and pfb_matchdir_stale_localfile_refs() need,
 * mirroring sync_package_pfblockerng()'s own header build ("{header}{vtype}", \W-stripped;
 * the '<alias>_custom' / DNSBLIP / GeoIP-continent synthetic rows) so the migration is fed the
 * SAME names the disk actually contains -- install.inc runs standalone, before any sync pass
 * populates $pfb['existing']. Match-set membership ignores list/row Disabled state: a stale
 * user file's own list may since have been disabled or retyped, so its history is unknowable
 * and every configured name must count (issue #1250). Pure: no filesystem/config writes.
 *
 * @param array<string,array<int,array<string,mixed>>> $lists_by_vtype ['_v4' => v4 list
 *        config rows, '_v6' => v6 list config rows] -- installedpackages/pfblockernglistsv{4,6}/config.
 * @param array<string,mixed>              $dnsbl_config      installedpackages/pfblockerngdnsblsettings/config/0.
 * @param array<string,array<string,mixed>> $continent_configs Continent alias => its config/0 (or []).
 * @return array{deny: string[], match: string[], rows: array<int,array{list:string,header:string,url:string}>}
 */
function pfb_matchdir_config_headers(array $lists_by_vtype, array $dnsbl_config, array $continent_configs): array {
	$deny  = array();
	$match = array();
	$rows  = array();

	foreach ($lists_by_vtype as $pfb_vtype => $pfb_lists) {
		foreach ($pfb_lists as $pfb_list) {
			$pfb_action = $pfb_list['action'] ?? NULL;
			$pfb_is_deny = pfb_group_action_valid($pfb_action, 'ipv4') && strpos($pfb_action, 'Deny') !== FALSE;

			if (!empty($pfb_list['custom'])) {
				$pfb_alias_norm = preg_replace('/\W/', '', (string) ($pfb_list['aliasname'] ?? ''));
				if ($pfb_alias_norm !== '') {
					$match[] = "{$pfb_alias_norm}_custom{$pfb_vtype}";
					if ($pfb_is_deny) {
						$deny[] = "{$pfb_alias_norm}_custom{$pfb_vtype}";
					}
				}
			}

			foreach ($pfb_list['row'] ?? [] as $pfb_row) {
				$pfb_header_norm = preg_replace('/\W/', '', (string) ($pfb_row['header'] ?? ''));
				if ($pfb_header_norm !== '') {
					$match[] = "{$pfb_header_norm}{$pfb_vtype}";
					if ($pfb_is_deny) {
						$deny[] = "{$pfb_header_norm}{$pfb_vtype}";
					}
				}
				if (!empty($pfb_row['url'])) {
					$rows[] = array('list' => $pfb_list['aliasname'] ?? '', 'header' => $pfb_row['header'] ?? '', 'url' => $pfb_row['url']);
				}
			}
		}
	}

	$pfb_dnsbl_action = pfb_dnsblip_action_value($dnsbl_config['action'] ?? NULL);
	if (strpos($pfb_dnsbl_action, 'Deny') !== FALSE) {
		$deny[] = 'DNSBLIP_v4';
		$deny[] = 'DNSBLIP_v6';
	}

	foreach ($continent_configs as $pfb_alias => $pfb_cont_config) {
		$pfb_cont_action = $pfb_cont_config['action'] ?? NULL;
		if (pfb_group_action_valid($pfb_cont_action, 'geoip') && strpos($pfb_cont_action, 'Deny') !== FALSE) {
			$deny[] = "{$pfb_alias}_v4";
			$deny[] = "{$pfb_alias}_v6";
		}
	}

	return array('deny' => $deny, 'match' => $match, 'rows' => $rows);
}

/**
 * issue #1250: upgrade migration -- find every configured IP-list row whose Localfile/`url`
 * still points at a matchdir artifact THIS RUN ACTUALLY MOVED. The GUI once instructed admins
 * to point a Match alias's Localfile at e.g. '/var/db/pfblockerng/match/ETMatch.txt'; any such
 * row breaks the moment that artifact moves, and we do not rewrite the admin's config for
 * them. Keyed on the plan's actual move list, not a filename shape -- a same-shaped user
 * file that was never moved must never trigger a repoint warning for a path that still exists.
 * Pure.
 *
 * @param array<int,array{list:string,header:string,url:string}> $rows Flattened
 *        pfblockernglistsv4/v6 rows (any action, any state -- any alias can consume a local file).
 * @param string   $matchdir        The OLD matchdir path (no trailing slash).
 * @param string[] $moved_basenames Basenames (with '.txt') pfb_matchdir_apply_moves() actually moved this run.
 * @return array<int,array{list:string,header:string,url:string}> The rows that reference one of them.
 */
function pfb_matchdir_stale_localfile_refs(array $rows, string $matchdir, array $moved_basenames): array {
	$hits = array();
	foreach ($rows as $pfb_row) {
		if (empty($pfb_row['url']) || dirname($pfb_row['url']) !== $matchdir) {
			continue;
		}
		if (in_array(basename($pfb_row['url']), $moved_basenames, TRUE)) {
			$hits[] = $pfb_row;
		}
	}
	return $hits;
}

/**
 * issue #1250: upgrade migration -- apply the plan's renames with a live no-clobber
 * re-check (the plan's check ran against a snapshot; this is the guard at the actual
 * rename()). Returns the OLD basenames actually renamed: the stale-Localfile warning and
 * the 'Moved:' banner must be keyed on real outcomes, never the planned set -- a skipped
 * rename leaves the old file live and valid, so warning on it would be a false alarm.
 *
 * @param array<string,string> $moves       Old basename => new basename (the plan's 'move').
 * @param string               $matchdir    Source dir (no trailing slash).
 * @param string               $matchgendir Destination dir (no trailing slash).
 * @return string[] The old basenames whose rename actually succeeded.
 */
function pfb_matchdir_apply_moves(array $moves, string $matchdir, string $matchgendir): array {
	$applied = array();
	foreach ($moves as $pfb_old => $pfb_new) {
		$pfb_dest = "{$matchgendir}/{$pfb_new}";
		if (!file_exists($pfb_dest) && @rename("{$matchdir}/{$pfb_old}", $pfb_dest)) {
			$applied[] = $pfb_old;
		}
	}
	return $applied;
}

// issue #1084: batch IP dedup/reputation recompute -- caller-side helpers. pfb_recompute()
// (pfblockerng.sh) replaces duplicate()/dmax/pmax's incremental masterfile surgery with one
// deterministic pass per family over pristine per-feed snapshots; these functions decide WHEN
// to invoke it and build its inputs.

// Per-feed v4-Deny shell preprocessing stages to run before snapshotting (post _255/_agg/_rep
// -- see pfb_recompute()'s memberlist contract). '_dup' is INTENTIONALLY never appended: the
// batch recompute verb now owns cross-feed dedup, replacing duplicate()'s per-feed call.
function pfb_ip_preprocess_args(bool $dup_on, bool $agg_on, bool $rep_on): string {
	$args = '';
	if ($dup_on || $agg_on) {
		$args = '_255';
	}
	if ($agg_on) {
		$args .= '_agg';
	}
	if ($rep_on) {
		$args .= '_rep';
	}
	return $args;
}

/**
 * Decide how the batch `recompute` verb is invoked this pass from the enable_dup / dRep /
 * pRep toggle state -- the "dedup-off invocation matrix" pinned in issue #1084's benchmark-
 * plan comment. Both-dRep-and-pRep is a design-decided tie-break: recompute applies dMax,
 * then the caller runs the legacy pMax exec afterward over the emitted deny files (today's
 * pMax semantics, unmodified).
 *
 * @param bool $dedup_on    Dedup pass due: $pfb['dup'] === PfbToggle::On ANDed by the caller with the
 *                          feed-changed trigger (repcheck && !save && enable) -- a quiet pass
 *                          (no IP-Deny snapshot written, no removal) invokes nothing, so the
 *                          placeholder refill from the closing pass is never truncated away.
 * @param bool $rep_trigger dRep/pRep's shared "changes found" gate: $pfb['repcheck'] &&
 *                          !$pfb['save'] && $pfb['enable'] === PfbToggle::On.
 * @param bool $drep_on     $pfb['drep'] === PfbToggle::On.
 * @param bool $prep_on     $pfb['prep'] === PfbToggle::On.
 * @return array{invoke_v4:bool,invoke_v6:bool,dedup:string,repmode:string,legacy_pmax_followup:bool}
 */
function pfb_ip_recompute_matrix(bool $dedup_on, bool $rep_trigger, bool $drep_on, bool $prep_on): array {
	$repmode = 'off';
	$legacy_pmax_followup = FALSE;
	if ($rep_trigger && $drep_on) {
		$repmode = 'dmax';
		$legacy_pmax_followup = $prep_on;
	} elseif ($rep_trigger && $prep_on) {
		$repmode = 'pmax';
	}

	if ($dedup_on) {
		return array('invoke_v4' => TRUE, 'invoke_v6' => TRUE, 'dedup' => 'on', 'repmode' => $repmode, 'legacy_pmax_followup' => $legacy_pmax_followup);
	}
	if ($rep_trigger && ($drep_on || $prep_on)) {
		return array('invoke_v4' => TRUE, 'invoke_v6' => FALSE, 'dedup' => 'off', 'repmode' => $repmode, 'legacy_pmax_followup' => $legacy_pmax_followup);
	}
	return array('invoke_v4' => FALSE, 'invoke_v6' => FALSE, 'dedup' => 'off', 'repmode' => 'off', 'legacy_pmax_followup' => FALSE);
}

/**
 * issue #1084 review — whether the FINAL REPORTING `closing` verb (emptyfiles() +
 * closingprocess()) fires this reload, and its alias arg ('on'/'off'). Dedup on always
 * fires with 'on' (today's masterfile-sanity contract). Dedup off only fires (with 'off',
 * skipping the masterfile-specific block dedup-off never populates) when the v4 recompute
 * pass actually ran this pass -- else a dup-off+rep-on alias collapsed to zero rows by
 * pMax/dMax never gets its emptyfiles() placeholder refill and stays a genuine 0-byte
 * deny file forever.
 *
 * @return array{0:bool,1:string} [invoke, alias_arg]
 */
function pfb_ip_closing_pass_active(bool $dup_on, bool $recompute_ran_v4): array {
	if ($dup_on) {
		return array(TRUE, 'on');
	}
	return array($recompute_ran_v4, 'off');
}

/**
 * Filter the config-order enabled-Deny header list ($pfb['existing']['deny'], built by the
 * removal-detection pre-pass) down to one family, preserving order -- the recompute
 * memberlist's PRIORITY order (config order, not glob/accretion order; a deliberate delta
 * from today's sticky historical masterfile ownership).
 *
 * @param string[] $existing_deny $pfb['existing']['deny'] -- '<header>_v4'/'<header>_v6' names.
 * @param string   $family        'v4' | 'v6'.
 * @return string[] Headers ending in "_{$family}", original relative order preserved.
 */
function pfb_ip_recompute_family_headers(array $existing_deny, string $family): array {
	$suffix = "_{$family}";
	$out = array();
	foreach ($existing_deny as $header) {
		if (str_ends_with((string) $header, $suffix)) {
			$out[] = $header;
		}
	}
	return $out;
}

// The recompute snapshot path for one header -- basename-strip-at-first-'.' round-trips to
// $header exactly (pfb_recompute()'s memberlist contract, pfblockerng.sh:754-757).
function pfb_ip_recompute_snapshot_path(string $snapdir, string $header): string {
	return "{$snapdir}/{$header}.snap";
}

// Single source of the memberlist serialization -- the invocation loop's write site and
// pfb_ip_recompute_order_changed() both route through this so their formats can never
// drift (issue #1173).
function pfb_ip_recompute_memberlist_content(array $paths): string {
	return $paths ? implode("\n", $paths) . "\n" : '';
}

// issue #1184: log a failed memberlist write -- a silent failure re-ran the full recompute every tick.
function pfb_ip_recompute_memberlist_write(string $memberlist_path, array $paths): int|false {
	$result = @file_put_contents($memberlist_path, pfb_ip_recompute_memberlist_content($paths), LOCK_EX);
	if ($result === FALSE) {
		pfb_logger("\nIP-Recompute: write failed for [ {$memberlist_path} ] -- recompute still runs this pass", 2);
	}
	return $result;
}

/**
 * issue #1173: a pure IPv4/IPv6 Deny-list priority reorder flips no feed-change repcheck --
 * no feed content changed -- yet recompute ownership follows memberlist ORDER
 * (pfb_ip_recompute_family_headers()'s config order), so a reorder-only save still needs a
 * recompute. Baseline is the memberlist the invocation loop wrote on its last attempt
 * (write-time, not read-time -- same failure semantics as feed-change repcheck); a missing
 * or unreadable baseline is a fail-safe TRUE.
 */
function pfb_ip_recompute_order_changed(array $family_headers, string $snapdir, string $memberlist_path): bool {
	$paths = array();
	foreach ($family_headers as $header) {
		$paths[] = pfb_ip_recompute_snapshot_path($snapdir, $header);
	}
	$expected = pfb_ip_recompute_memberlist_content($paths);
	$stored   = @file_get_contents($memberlist_path);
	if ($stored === FALSE) {
		return TRUE;
	}
	return $stored !== $expected;
}

/**
 * The recompute memberlist entry for one header -- the existing snapshot when present, else a
 * full copy of the live deny .txt seeded in its place (first run after upgrade, or a header
 * whose snapshot was never written on this box). Load-bearing for upgrade continuity: without
 * it, a pre-#1084 deny alias would vanish from the memberlist (and the masterfile) on the first
 * recompute pass instead of carrying its current content forward.
 */
function pfb_ip_recompute_seed_snapshot(string $header, string $snapdir, string $denydir): string {
	$snap = pfb_ip_recompute_snapshot_path($snapdir, $header);
	if (!file_exists($snap)) {
		$live = "{$denydir}/{$header}.txt";
		if (file_exists($live) && !@copy($live, $snap)) {
			pfb_logger("recompute [ {$header} ]: could not seed snapshot from the live deny file [ {$live} ]\n", 2);
		}
	}
	return $snap;
}

// Persist the pristine post-preprocessing snapshot pfb_recompute() reads, plus the
// '.aggcount' original-count sidecar closingprocess() sums for the FINAL Processing report --
// both used to live inside the now-retired duplicate() (issue #1084).
function pfb_ip_recompute_write_snapshot(string $src, string $header, string $snapdir, string $origdir): void {
	if (!file_exists($src)) {
		return;
	}
	@copy($src, pfb_ip_recompute_snapshot_path($snapdir, $header));
	// fail to 0: this is a report/sidecar count, not a retention guard.
	@file_put_contents("{$origdir}/{$header}.aggcount", (pfb_count_lines($src) ?? 0) . "\n", LOCK_EX);
}

// Drop a header's recompute snapshot (+ aggcount sidecar) on removal/download-failure -- else
// a stale snapshot would outlive the live deny-file removal ('remove x x x' call sites) and
// feed the next recompute pass phantom content.
function pfb_ip_recompute_forget_header(string $header, string $snapdir, string $origdir): void {
	unlink_if_exists(pfb_ip_recompute_snapshot_path($snapdir, $header));
	unlink_if_exists("{$origdir}/{$header}.aggcount");
}


// Format a single log line for a failed pfctl table operation.  Pure function:
// no side-effects, fully unit-testable without a live pfctl binary.
// Callers: pfb_pfctl_table_op() (below) and pfb_live_punch_apply()
// (pfblockerng_extra.inc; also reached via pfb_pfctl_checked_op()) — the exec()
// routes for pfctl -T mutation ops.  The message names every field so "Table does not exist"
// floods carry table/op attribution in the log.
function pfb_pfctl_error_message(string $table, string $op, int $rc, string $stderr): string {
	$msg = trim(str_replace(["\r\n", "\r", "\n"], ' ', $stderr));
	if ($msg === '') {
		// No stderr: end at the rc -- never a dangling ": " (#723).
		return "[pfctl] op={$op} table={$table} failed (rc={$rc})";
	}
	return "[pfctl] op={$op} table={$table} failed (rc={$rc}): {$msg}";
}


// Should a completed pfctl mutation op be logged as an attributed failure?  Pure predicate:
// no side-effects, unit-testable without a live pfctl (sibling of pfb_pfctl_error_message()).
// A `kill` that reports "Table does not exist" is the IDEMPOTENT SUCCESS case for kill (goal:
// table gone — it already is): the unguarded kill sites (an enabled alias with no
// URL/customlist; an empty aggregate union) call it every sync/cron tick, so treating an
// absent-table kill as a failure would flood the log with a benign no-op forever.  Any OTHER
// kill error (permissions, syntax), and every non-kill op with a non-zero rc / pfctl error,
// stays a real failure.
function pfb_pfctl_op_failed(string $op, int $rc, string $stderr): bool {
	if ($op === 'kill' && stripos($stderr, 'Table does not exist') !== FALSE) {
		return FALSE;
	}
	return $rc !== 0 || stripos($stderr, 'pfctl:') !== FALSE || stripos($stderr, 'Table does not exist') !== FALSE;
}


// Thin wrapper around `pfctl -t <table> -T <op>` for mutation ops (kill/replace/add/delete).
// Owns the escapeshellarg() for the table; $args must already be fully escaped by
// the caller (e.g. "-f " . escapeshellarg($path)).  $op is a fixed verb literal
// (kill|replace|add|delete), interpolated UNescaped — never pass a caller-supplied value.
// On failure (non-zero rc or pfctl error output) logs one attributed line via pfb_logger().
// $pfctl_bin defaults to $pfb['pfctl']; pass explicitly when the binary is a
// per-call parameter (e.g. pfb_apply_alias_delta, which accepts a mock binary in tests).
function pfb_pfctl_table_op(string $table, string $op, string $args = '', string $pfctl_bin = ''): array {
	global $pfb;
	if ($pfctl_bin === '') {
		$pfctl_bin = $pfb['pfctl'];
	}
	$table_esc = escapeshellarg($table);
	$args_part = $args !== '' ? " {$args}" : '';
	$out       = [];
	$rc        = 0;
	exec("{$pfctl_bin} -t {$table_esc} -T {$op}{$args_part} 2>&1", $out, $rc);
	$stderr    = implode(' ', $out);
	if (pfb_pfctl_op_failed($op, $rc, $stderr)) {
		pfb_logger(pfb_pfctl_error_message($table, $op, $rc, $stderr) . "\n", 2);
		// ADR-61: sync-status ledger -- every $table here is a pfB_* IP alias table.
		pfb_sync_status_open('ip', $table, 'apply', pfb_pfctl_error_message($table, $op, $rc, $stderr), $pfb['dbdir']);
	} else {
		pfb_sync_status_close('ip', $table, 'apply', $pfb['dbdir']);
	}
	return ['out' => $out, 'rc' => $rc];
}


// ADR-61: tick-driven reconciliation for one stuck (ip,$item,apply) ledger entry --
// re-apply against the aliasdir mirror already persisted by the last normal pass
// (no re-download/parse/dedup). Mirrors pfb_apply_alias_delta()'s force_replace
// branch; a missing mirror means the desired content IS empty, so kill instead of
// erroring on a nonexistent -f path. pfb_pfctl_table_op() re-opens/closes the SAME
// key on its own (above) -- this never touches the ledger directly.
function pfb_ip_apply_retry(string $item): void {
	global $pfb;
	$mirror = "{$pfb['aliasdir']}/{$item}.txt";
	if (is_file($mirror)) {
		pfb_pfctl_table_op($item, 'replace', '-f ' . escapeshellarg($mirror));
	} else {
		pfb_pfctl_table_op($item, 'kill');
	}
}


// Number of entries in pf table $table, or 0 when the table does not exist yet (a benign read
// on boot / mid-reload). Reads via `pfctl -T show` with pfctl's OWN stderr suppressed: a missing
// table writes "pfctl: Table does not exist" to stderr, which would otherwise leak UNATTRIBUTED
// into the update / Software-page output. (The mutation wrapper pfb_pfctl_table_op() only covers
// add/delete/replace/kill; reading an absent table is not a failure to attribute -- just "no
// entries yet".) Counts in PHP, not `| wc -l`, so a wrapping 2>&1 can't bind to wc instead of
// pfctl and let the error through.
function pfb_pfctl_table_count(string $table): int {
	global $pfb;
	$out = [];
	exec("{$pfb['pfctl']} -t " . escapeshellarg($table) . " -T show 2>/dev/null", $out);
	return count($out);
}


// Parse the numeric match count out of `pfctl -t <table> -T test <ip> 2>&1` output --
// "N/1 addresses match." on a normal run, or (because of the merged 2>&1) an error
// string such as "pfctl: Table does not exist." when the table is absent. (int) casts
// the leading numeric prefix, which PHP resolves to 0 for any non-numeric string --
// unlike the old `substr($output, 0, 1) > 0` comparison it replaces, which took the
// output's first CHARACTER and let PHP 8's string/int comparison rules turn a leading
// letter (e.g. the 'p' in "pfctl: ...") into a false positive match (issue #713).
//
// PURE -- no I/O, no globals, no side effects.
function pfb_pfctl_test_match_count(string $output): int {
	return (int) $output;
}


// ONE `pfctl -vvsTables` exec. Full dump — do not pipe through grep -A4 (that
// truncation drops the In/Out packet lines the parser is meant to read).
// Returns the line array exec() collected; never throws.
function pfb_pfctl_tables_raw(string $pfctl_bin = ''): array {
	global $pfb;
	if ($pfctl_bin === '') {
		$pfctl_bin = $pfb['pfctl'] ?? '/sbin/pfctl';
	}
	$out = [];
	exec(escapeshellarg($pfctl_bin) . ' -vvsTables 2>/dev/null', $out);
	return $out;
}


// Parse `pfctl -vvsTables` lines into per-table stats. PURE — no I/O, no
// globals. Missing packet/eval fields default to 0 so callers never isset().
//
// Header is flags, then a tab (pfctl 8), then the table name. Body lines are
// tab-indented `Key: value` / `In/Block: [ Packets: N Bytes: N ]`.
function pfb_pfctl_tables_parse(array $lines): array {
	$tables = [];
	$current = '';

	$empty = static function (string $flags = ''): array {
		return [
			'flags' => $flags,
			'addresses' => 0,
			'cleared' => '',
			'references_anchors' => 0,
			'references_rules' => 0,
			'evaluations_nomatch' => 0,
			'evaluations_match' => 0,
			'in_block_packets' => 0,
			'in_block_bytes' => 0,
			'in_pass_packets' => 0,
			'in_pass_bytes' => 0,
			'in_xpass_packets' => 0,
			'in_xpass_bytes' => 0,
			'out_block_packets' => 0,
			'out_block_bytes' => 0,
			'out_pass_packets' => 0,
			'out_pass_bytes' => 0,
			'out_xpass_packets' => 0,
			'out_xpass_bytes' => 0,
		];
	};

	foreach ($lines as $line) {
		if ($line === '') {
			continue;
		}
		// Flags then name. Leading '-' misses const tables (`c…`) and
		// would apply the next Addresses line to the previous table.
		if (preg_match('/^([c-][p-][ai-][\w-]*)\s+(\S+)\s*$/', $line, $hm)) {
			// Duplicate names last-win; pfctl does not emit them.
			$current = $hm[2];
			$tables[$current] = $empty($hm[1]);
			continue;
		}
		if ($line[0] !== "\t") {
			$current = '';
			continue;
		}
		if ($current === '') {
			continue;
		}

		$stripped = trim(str_replace(['[', ']'], '', $line));
		if (str_starts_with($stripped, 'Addresses:')) {
			$tables[$current]['addresses'] = (int) trim(substr($stripped, strlen('Addresses:')));
			continue;
		}
		if (str_starts_with($stripped, 'Cleared:')) {
			$tables[$current]['cleared'] = trim(substr($stripped, strlen('Cleared:')));
			continue;
		}
		if (str_starts_with($stripped, 'References:')) {
			if (preg_match('/Anchors:\s*(\d+)/', $stripped, $m)) {
				$tables[$current]['references_anchors'] = (int) $m[1];
			}
			if (preg_match('/Rules:\s*(\d+)/', $stripped, $m)) {
				$tables[$current]['references_rules'] = (int) $m[1];
			}
			continue;
		}
		if (str_starts_with($stripped, 'Evaluations:')) {
			// '/Match:/' also matches inside 'NoMatch:' — capture both in order.
			if (preg_match('/NoMatch:\s*(\d+).*Match:\s*(\d+)/', $stripped, $m)) {
				$tables[$current]['evaluations_nomatch'] = (int) $m[1];
				$tables[$current]['evaluations_match'] = (int) $m[2];
			}
			continue;
		}

		$dir_key = '';
		if (str_starts_with($stripped, 'In/Block:')) {
			$dir_key = 'in_block';
		} elseif (str_starts_with($stripped, 'In/Pass:')) {
			$dir_key = 'in_pass';
		} elseif (str_starts_with($stripped, 'In/XPass:')) {
			$dir_key = 'in_xpass';
		} elseif (str_starts_with($stripped, 'Out/Block:')) {
			$dir_key = 'out_block';
		} elseif (str_starts_with($stripped, 'Out/Pass:')) {
			$dir_key = 'out_pass';
		} elseif (str_starts_with($stripped, 'Out/XPass:')) {
			$dir_key = 'out_xpass';
		}
		if ($dir_key === '') {
			continue;
		}
		$packets = 0;
		$bytes = 0;
		if (preg_match('/Packets:\s*(\d+)/', $stripped, $m)) {
			$packets = (int) $m[1];
		}
		if (preg_match('/Bytes:\s*(\d+)/', $stripped, $m)) {
			$bytes = (int) $m[1];
		}
		$tables[$current][$dir_key . '_packets'] = $packets;
		$tables[$current][$dir_key . '_bytes'] = $bytes;
	}

	return $tables;
}


// ADR-11: build + register the opt-in per-type aggregate ("Uber") Native aliases. ONE generic
// loop over type->dir {Deny,Permit,Match,Native} x family {v4,v6}: each SELECTED type
// ($pfb['agg_types']) gets a memberlist, an mtime-gated `pfblockerng.sh aggregate` run, and a
// standard pfB urltable alias pfB_<Type>_Aggregated_<fam> (NEVER a firewall rule). A rebuilt
// aggregate's name merges into $pfb['changed_ip_aliases']/$pfb_alias_lists (reload gating); a
// non-selected type is torn down (files + pf table removed, omitted from $new_aliases_list so
// the caller's orphan-prune unlinks it). Additive: nothing selected => byte-identical pass.
// Array args are by-reference (caller's alias-registration arrays).
function pfb_build_aggregate_aliases(array &$new_aliases, array &$new_aliases_list, array &$pfb_alias_lists) {
	global $pfb;

	$all_types	= array('Deny', 'Permit', 'Match', 'Native');
	$selected	= is_array($pfb['agg_types'] ?? null) ? $pfb['agg_types'] : array();

	// Disabled pfBlockerNG => nothing is selected effectively (tear all down below).
	if ($pfb['enable'] !== PfbToggle::On) {
		$selected = array();
	}

	foreach ($all_types as $type) {
		foreach (array('v4', 'v6') as $family) {

			$aliasname	= "pfB_{$type}_Aggregated_{$family}";
			$aggout		= "{$pfb['aliasdir']}/{$aliasname}.txt";
			$consumer	= "{$pfb['dbdir']}/{$aliasname}.lst";	// never-empty '-f' consumer (ADR-12)

			// ---- Teardown: a NON-selected type (or disabled) leaves no orphans. ----
			// Strictly additive: only act when this aggregate actually exists -- on a box
			// that never selected this type, nothing is touched (byte-identical to today).
			if (!in_array($type, $selected, TRUE)) {
				if (file_exists($aggout) || file_exists($consumer)) {
					unlink_if_exists($aggout);
					unlink_if_exists($consumer);
					// Also drop the shell action's member-set snapshot + any temp (no orphans).
					unlink_if_exists("{$aggout}.members");
					unlink_if_exists("{$aggout}.tmp");
					// Kill the pf table only when we had built this aggregate before.
					pfb_pfctl_table_op($aliasname, 'kill');
				}
				continue;
			}

			// ---- Build: write the per-(type,family) memberlist, then run the action. ----
			$members	= pfb_aggregate_member_list($type, $family);
			$memberlist	= "{$pfb['dbdir']}/{$aliasname}.members";
			@file_put_contents($memberlist, $members ? (implode("\n", $members) . "\n") : '', LOCK_EX);

			// mtime BEFORE the build, to detect whether the action actually rebuilt.
			$mtime_before = file_exists($aggout) ? pfb_file_mtime($aggout) : 0;

			$family_esc	= escapeshellarg($family);
			$memberlist_esc	= escapeshellarg($memberlist);
			$aggout_esc	= escapeshellarg($aggout);
			$consumer_esc	= escapeshellarg($consumer);
			// CIDR Aggregation state: with it ON every member feed is already CIDR-collapsed, so
			// the shell skips the union's redundant iprange for v4 and just sort -u's it (like v6).
			$agg_esc	= escapeshellarg((($pfb['agg'] ?? PfbToggle::Off) === PfbToggle::On) ? 'on' : 'off');
			exec("{$pfb['script']} aggregate {$family_esc} {$memberlist_esc} {$aggout_esc} {$consumer_esc} {$agg_esc} 2>&1");

			$rebuilt = file_exists($aggout) && (pfb_file_mtime($aggout) > $mtime_before);

			// Register the Native urltable alias (mirror the member-alias shape).
			// NEVER pfb_firewall_rule() -- Native means no firewall rule.
			$new_aliases_list[]	= $aliasname;
			$new_aliases[]		= array('name'		=> $aliasname,
							'url'		=> "{$pfb['weblocal']}?pfb={$aliasname}",
							'updatefreq'	=> '32',
							'address'	=> '',
							'descr'		=> "pfBlockerNG {$type} Aggregated Alias [ {$family} ]",
							'type'		=> 'urltable',
							'detail'	=> 'DO NOT EDIT THIS ALIAS'
							);

			// Load the table now (well before the ADR-12 post-hook), so a hook consumer
			// (e.g. an HAProxy graceful reload) always sees the FRESH aggregate. A 0-byte
			// aggout (empty union) is pruned to an empty table, matching pfB member aliases.
			if (file_exists($aggout) && filesize($aggout) > 0) {
				pfb_pfctl_table_op($aliasname, 'replace', "-f {$aggout_esc}");
			} else {
				pfb_pfctl_table_op($aliasname, 'kill');
			}

			// Merge a (re)built aggregate's name into the changed-alias set so the ADR-12
			// post-hook's PFB_CHANGED_IP_ALIASES reflects it; additive -- an unchanged
			// (mtime-gated, skipped) aggregate adds nothing.
			if ($rebuilt) {
				$pfb['changed_ip_aliases'][]	= $aliasname;
				$pfb_alias_lists[]		= $aliasname;
			}

			// Member list is transient scratch; the never-empty consumer + the alias file
			// persist for downstream use.
			unlink_if_exists($memberlist);
		}
	}
}


// ---------------------------------------------------------------------------
// ADR-40 — alias reload-scope helpers (extracted from sync_package_pfblockerng)
// ---------------------------------------------------------------------------

/**
 * Compute the reload alias set from the feed-tracking state.
 *
 * Encapsulates the three $final_alias computations in sync_package_pfblockerng:
 *   (a) file-write scope  (14410–14420): pass repEnabled = (drep||prep on), active = null
 *   (b) rule-change pfctl (14955–14964): pass repEnabled = (repcheck && drep||prep), active = $pfb_active_aliases
 *   (c) no-rule-change    (15008–15016): pass repEnabled = (repcheck && drep||prep), active = null
 *
 * @param bool        $rep_enabled   TRUE when the reputation branch should use $alias_lists_all.
 *                                   Caller derives this as: (repcheck && (drep=='on' || prep=='on'))
 *                                   for pfctl paths, or (drep=='on' || prep=='on') for the file-write path.
 * @param array       $alias_lists     $pfb_alias_lists  — aliases with a changed feed this pass.
 * @param array       $alias_lists_all $pfb_alias_lists_all — all active aliases.
 * @param array|null  $active_aliases  When non-null the result is intersected with this set
 *                                     (the rule-change pfctl path only). Pass null to skip.
 * @return array Ordered, unique list of alias names to reload. Empty = nothing to reload.
 */
function pfb_select_reload_aliases(
	bool   $rep_enabled,
	array  $alias_lists,
	array  $alias_lists_all,
	?array $active_aliases = null
): array {
	$final_alias = array();
	if ($rep_enabled) {
		if (!empty($alias_lists_all)) {
			$final_alias = array_unique($alias_lists_all);
		}
	} else {
		if (!empty($alias_lists)) {
			$final_alias = array_unique($alias_lists);
		}
	}

	if ($active_aliases !== null) {
		$final_alias = array_intersect($final_alias, array_unique($active_aliases));
	}

	return $final_alias;
}

/**
 * Concatenate the content of the member .txt files for one alias.
 *
 * The current aliasdir file is a raw concatenation of each enabled member feed's .txt
 * (pfblockerng.inc:14460 / :14481) — order-dependent, not deduplicated. This helper
 * captures that exact semantic: read each existing path in order and concatenate.
 *
 * This is the oracle for the current (pre-content-addressed) behaviour; callers move to
 * pfb_canonical_alias_set() once content-addressed gating lands.
 *
 * @param string[] $member_paths Absolute paths to the per-feed .txt files, in the order
 *                               they should be concatenated (matches the row iteration order
 *                               in the alias build loop).
 * @return string Raw concatenated content — may contain duplicates and is NOT sorted.
 *                Returns '' when no paths are provided or none exist.
 */
function pfb_concat_member_files(array $member_paths): string {
	$out = '';
	foreach ($member_paths as $path) {
		if (file_exists($path)) {
			$out .= file_get_contents($path);
		}
	}
	return $out;
}

/**
 * Build the canonical membership set for an alias.
 *
 * Applies LC_ALL=C sort -u (ADR-26) to the concatenated member content, returning
 * an array of unique, C-sorted IP/CIDR strings with blank lines and comments stripped.
 * Used as the content-addressed gate input and the delta last_set source (ADR-40).
 *
 * @param string $member_content Raw concatenated member content (output of pfb_concat_member_files).
 * @return string[] Sorted, unique, non-empty lines. Empty array for empty/blank input.
 */
function pfb_canonical_alias_set(string $member_content): array {
	if ($member_content === '') {
		return array();
	}
	// Split on newlines, strip blank lines and comment lines, dedup, then C-locale sort.
	$lines = array_filter(
		explode("\n", $member_content),
		static fn(string $l): bool => $l !== '' && $l[0] !== '#'
	);
	$unique = array_unique(array_values($lines));
	// LC_ALL=C sort: strcmp gives the byte-level C-locale order.
	usort($unique, 'strcmp');
	return $unique;
}

/**
 * Write the canonical alias set to its last-applied mirror file (the aliasdir .txt).
 *
 * The file written here becomes the reference for pfb_alias_set_different() on
 * the next pass. Format: one entry per line, trailing newline, no comments or blanks.
 *
 * @param string   $path          Absolute path to the aliasdir .txt file.
 * @param string[] $canonical_set Sorted, unique entries (output of pfb_canonical_alias_set).
 */
function pfb_write_canonical_alias(string $path, array $canonical_set): void {
	$content = empty($canonical_set) ? '' : implode("\n", $canonical_set) . "\n";
	@file_put_contents($path, $content, LOCK_EX);
}

/**
 * Compare a freshly-computed canonical set against the last-applied mirror.
 *
 * Returns TRUE when the alias table must be reloaded this pass — i.e. when
 * the desired membership set differs from what was last applied (or the mirror
 * does not exist yet, as on boot/initial-load for non-empty sets).
 *
 * Set comparison is ORDER- and DUPLICATE-immune: the mirror is also passed
 * through pfb_canonical_alias_set() before comparing, so a legacy
 * non-canonical mirror (raw concat with dups) round-trips correctly on
 * the first upgrade pass.
 *
 * ADR-40 contract items satisfied:
 *   (3)  Cross-list dedup: sibling B returns TRUE when feed A removal freed an
 *        IP from B's effective set — even though B's own feed was not refetched.
 *   (4)  Reputation non-amplification: unchanged alias returns FALSE even when
 *        rep is on and its set did not move.
 *   (5)  Empty-table repopulation: missing mirror returns TRUE for non-empty set.
 *   (8)  Idempotence: same set on second pass returns FALSE.
 *
 * @param string[] $new_set     Desired canonical set (sorted, unique IPs/CIDRs).
 * @param string   $mirror_path Absolute path to the last-applied aliasdir .txt file.
 * @return bool TRUE = reload required; FALSE = set unchanged, skip reload.
 */
function pfb_alias_set_different(array $new_set, string $mirror_path): bool {
	if (!file_exists($mirror_path)) {
		// No mirror: treat as changed for non-empty sets (empty-table repopulation).
		return !empty($new_set);
	}
	$mirror_content = @file_get_contents($mirror_path);
	if ($mirror_content === FALSE) {
		// Unreadable mirror → assume changed.
		return !empty($new_set);
	}
	$mirror_set = pfb_canonical_alias_set($mirror_content);
	return $new_set !== $mirror_set;
}

/**
 * Return TRUE when a cross-list feature is active and ALL aliases must be
 * recomputed (not just feed-changed ones) this pass.
 *
 * Two features make a feed-A change able to alter a sibling alias B's
 * effective membership set:
 *   - Deduplication ($dup_on / enable_dup): the masterfile dedup is cross-list;
 *     removing an IP from feed A can release it to a lower-priority alias B.
 *   - Reputation ($rep_on / drep or prep on): dMax/pMax are cross-list;
 *     reputation scoring on one alias feeds into another.
 *
 * When either is active, the desired set of EVERY alias must be recomputed
 * and content-gated; with both off, single-feed → single-table already holds
 * and only the touched alias needs recomputing (hybrid scope, ADR §2).
 *
 * @param bool $dup_on  TRUE when dedup (enable_dup) is enabled.
 * @param bool $rep_on  TRUE when drep or prep reputation is enabled.
 * @return bool TRUE = recompute all aliases; FALSE = recompute touched-feed alias only.
 */
function pfb_cross_list_scope(bool $dup_on, bool $rep_on): bool {
	return $dup_on || $rep_on;
}

/**
 * pfb_supp_update_active — whether this pass should flip $pfb['supp_update']
 * TRUE, unlocking BOTH families' suppression sub-pass this reload (ADR-53
 * review finding A).
 *
 * $pfb['supp_update'] gates the v4 AND v6 suppression sub-passes alike
 * (pfblockerng.inc's alias-build loop checks it for both '_v4' and '_v6'
 * vtype passes). Before this fix it was set TRUE only inside the v4-only
 * dedup/reputation block (`$pfbadv && $list['vtype'] == '_v4'`), so a
 * deployment with ONLY v6 Deny aliases configured never flipped it and the
 * v6 suppress pass could never fire, even with v6suppression populated. The
 * fix is family-agnostic: any feed-changed DENY-folder alias (v4 or v6)
 * unlocks suppression for this reload, mirroring the scope suppression
 * itself already applies (Deny_* + Alias_Deny only, both families,
 * ADR-53 §2.1 "Scope of application"). Dedup/reputation bookkeeping stays
 * v4-only (ADR-53 §1.2) — that gate is untouched, only this one is split out.
 *
 * @param bool $pfbadv       TRUE for a Deny-folder alias (adv => TRUE).
 * @param bool $supp_enabled TRUE when the master "Enable Suppression" toggle is on.
 * @return bool TRUE = flip $pfb['supp_update'] TRUE for this reload.
 */
function pfb_supp_update_active(bool $pfbadv, bool $supp_enabled): bool {
	return $pfbadv && $supp_enabled;
}

/**
 * issue #1084 review — whether the per-alias suppression BODY (the v4 `suppress` exec /
 * the v6 pfb_suppress_file_v6() call) runs this reload. Snapshots are pre-suppression
 * captures, but recompute rewrites EVERY family alias on any trigger while the
 * suppression body only ran for a feed-changed alias -- so a suppressed IP recompute
 * resurrected into an alias whose OWN feed did not change (an unrelated sibling feed
 * drove the shared family-wide recompute pass) was never re-suppressed. Fix: EITHER
 * $feed_changed OR $recompute_ran unlocks the body.
 *
 * @param bool $supp_on       $pfb['supp'] === PfbToggle::On.
 * @param bool $vtype_matches $vtype == '_v4' (or '_v6' for the sibling call site).
 * @param bool $supp_update   $pfb['supp_update'].
 * @param bool $adv           $pfbadv (Deny-folder alias).
 * @param bool $feed_changed  in_array($alias, $final_alias_old).
 * @param bool $recompute_ran $pfb_recompute_ran_v4 / _v6 for this family.
 */
function pfb_ip_suppress_body_active(bool $supp_on, bool $vtype_matches, bool $supp_update, bool $adv, bool $feed_changed, bool $recompute_ran): bool {
	return $supp_on && $vtype_matches && $supp_update && $adv && ($feed_changed || $recompute_ran);
}

function pfb_ip_recompute_ran_for_vtype(string $vtype, bool $ran_v4, bool $ran_v6): bool {
	return $vtype === '_v4' ? $ran_v4 : ($vtype === '_v6' ? $ran_v6 : FALSE);
}

function pfb_ip_suppress_body_for_vtype(bool $supp_on, string $vtype, bool $supp_update, bool $adv,
    bool $feed_changed, bool $ran_v4, bool $ran_v6): bool {
	return pfb_ip_suppress_body_active($supp_on, $vtype === '_v4' || $vtype === '_v6', $supp_update,
	    $adv, $feed_changed, pfb_ip_recompute_ran_for_vtype($vtype, $ran_v4, $ran_v6));
}

// ---------------------------------------------------------------------------
// ADR-40 — forward-delta alias-table apply
// ---------------------------------------------------------------------------

/** Churn-ratio threshold above which 'auto' mode falls back to -T replace (5%). */
const PFB_DELTA_CHURN_THRESHOLD = 0.05;

/**
 * Clamp an integer batch-size value to the valid range [64, 4096].
 *
 * @param int|string $raw  Raw value (numeric string or int).
 * @return int             Clamped batch size.
 */
function pfb_alias_delta_batch_clamp(int|string $raw): int {
	$v = (int) $raw;
	if ($v < 64)   { return 64; }
	if ($v > 4096) { return 4096; }
	return $v;
}

/**
 * Resolve a raw POST batch-size field to its clamped stored value.
 *
 * An empty field (user cleared it in the UI) means "use the default 512" —
 * it must NOT cast to (int) '' == 0 and clamp down to the 64 floor.
 *
 * @param string $raw  Trimmed raw POST value (may be '').
 * @return int          Clamped batch size, ready for PfbConfig::write().
 */
function pfb_alias_delta_batch_resolve(string $raw): int {
	return pfb_alias_delta_batch_clamp($raw === '' ? 512 : (int) $raw);
}

/**
 * Apply an alias-table change via forward delta (-T add / -T delete) or full replace.
 *
 * Decision (when $force_replace is FALSE):
 *   - 'replace' mode → always -T replace.
 *   - 'delta' / 'auto' → compute add/del sets; if churn_ratio < threshold (auto) OR
 *     mode is 'delta', apply delta in batches of $batch_size.  Fall back to -T replace
 *     when churn_ratio >= threshold and mode is 'auto' (large-churn escape hatch).
 *
 * ADR-40 contract items satisfied:
 *   (1) End-state == replace: after delta apply, table membership equals $desired_set.
 *   (5) Empty-table: full replace handles initial population (mirrors the content-addressed gate).
 *   (8) Idempotence: identical $desired_set and $last_set → empty delta → zero pfctl calls.
 *
 * Failures: a pfctl error is logged; the caller can still verify the table state.
 *
 * @param string   $pfctl_bin    Absolute path to pfctl (e.g. $pfb['pfctl']).
 * @param string   $table        pf table name (e.g. 'pfB_Deny_v4').
 * @param string   $table_file   Absolute path to the aliasdir .txt file.
 * @param string[] $desired_set  Canonical sorted-unique desired membership (pfb_canonical_alias_set output).
 * @param string[] $last_set     Canonical sorted-unique last-applied set (from pfb_canonical_alias_set on mirror).
 * @param string   $mode         PfbAliasDeltaMode stored value ('auto'|'delta'|'replace').
 * @param int      $batch_size   Max entries per pfctl call (clamped to [64,4096]).
 * @param bool     $force_replace Force -T replace regardless of mode (boot/enable-disable path).
 * @return bool TRUE = delta path taken; FALSE = replace path taken.
 */
function pfb_apply_alias_delta(
	string $pfctl_bin,
	string $table,
	string $table_file,
	array  $desired_set,
	array  $last_set,
	string $mode,
	int    $batch_size,
	bool   $force_replace = FALSE
): bool {
	$table_file_esc = escapeshellarg($table_file);
	$batch_size     = pfb_alias_delta_batch_clamp($batch_size);

	// Force replace: boot/enable-disable initial load path.
	if ($force_replace || $mode === 'replace') {
		// issue #722: nothing else on a live box distinguishes the delta path from a
		// replace (pfb_pfctl_table_op logs only on error) — this line is the sole apply-path
		// oracle the smoke suite (and a human reading the log) can grep for.
		pfb_logger(" Updating [ {$table} ]: replace\n", 1);
		pfb_pfctl_table_op($table, 'replace', "-f {$table_file_esc}", $pfctl_bin);
		return FALSE;
	}

	// Compute add/del sets (LC_ALL=C byte-order; arrays are already canonical).
	$add_set = array_values(array_diff($desired_set, $last_set));
	$del_set = array_values(array_diff($last_set, $desired_set));

	$churn      = count($add_set) + count($del_set);
	$table_size = max(count($desired_set), count($last_set));

	// Churn-ratio fallback: auto mode with large churn → replace.
	if ($mode === 'auto' && $table_size > 0 && ($churn / $table_size) >= PFB_DELTA_CHURN_THRESHOLD) {
		pfb_logger(" Updating [ {$table} ]: replace\n", 1);
		pfb_pfctl_table_op($table, 'replace', "-f {$table_file_esc}", $pfctl_bin);
		return FALSE;
	}

	// issue #722: log the delta decision (incl. the zero-churn idempotent no-op below) so the
	// delta path is just as observable on a live box as the replace path logged above.
	pfb_logger(" Updating [ {$table} ]: delta +" . count($add_set) . '/-' . count($del_set) . "\n", 1);

	// Idempotence: empty delta → zero pfctl calls.
	if (empty($add_set) && empty($del_set)) {
		return TRUE;
	}

	// Apply adds in batches.
	foreach (array_chunk($add_set, $batch_size) as $chunk) {
		$entries = implode("\n", $chunk);
		$tmp     = tempnam(sys_get_temp_dir(), 'pfb_add_');
		if ($tmp === FALSE) {
			pfb_logger(" pfb_apply_alias_delta: tempnam failed — dropped add chunk ({$table})\n", 1);
			continue;
		}
		@file_put_contents($tmp, $entries . "\n");
		$tmp_esc = escapeshellarg($tmp);
		pfb_pfctl_table_op($table, 'add', "-f {$tmp_esc}", $pfctl_bin);
		@unlink($tmp);
	}

	// Apply deletes in batches.
	foreach (array_chunk($del_set, $batch_size) as $chunk) {
		$entries = implode("\n", $chunk);
		$tmp     = tempnam(sys_get_temp_dir(), 'pfb_del_');
		if ($tmp === FALSE) {
			pfb_logger(" pfb_apply_alias_delta: tempnam failed — dropped delete chunk ({$table})\n", 1);
			continue;
		}
		@file_put_contents($tmp, $entries . "\n");
		$tmp_esc = escapeshellarg($tmp);
		pfb_pfctl_table_op($table, 'delete', "-f {$tmp_esc}", $pfctl_bin);
		@unlink($tmp);
	}

	return TRUE;
}

// ---------------------------------------------------------------------------

// Determine if cron task requires updating
function pfblockerng_cron_exists($pfb_cmd, $pfb_min, $pfb_hour, $pfb_mday, $pfb_wday) {
	foreach (config_get_path('cron/item', []) as $item) {
		if (strpos($item['command'], $pfb_cmd) !== FALSE) {
			if ($item['command'] != $pfb_cmd) {
				return FALSE;
			}
			if ($item['minute'] != $pfb_min) {
				return FALSE;
			}
			if ($item['mday'] != $pfb_mday) {
				return FALSE;
			}
			if ($item['wday'] != $pfb_wday) {
				return FALSE;
			}
			if ($pfb_hour == 'random' && $item['hour'] != '') {
				// MaxMind/Blacklist hour is randomized. Skip comparison.
				return TRUE;
			}
			if ($item['hour'] != $pfb_hour) {
				return FALSE;
			}
			return TRUE;
		}
	}
	return FALSE;
}

// issue #1204: extracted from sync_package_pfblockerng() so PHPUnit can pin the
// tick cron's install/teardown behaviour without driving the whole sync pass.
function pfblockerng_configure_tick_cron(
	bool $enabled,
	string $log,
	?callable $regenerate = NULL,
	bool $regenerate_cache = TRUE
): void {
	$pfb_tick_min = '*/15';
	$pfb_tick_cmd = "/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php cron-tick >> {$log} 2>&1";

	if ($enabled) {
		$regenerate ??= function_exists('pfb_schedule_cache_regenerate') ? 'pfb_schedule_cache_regenerate' : NULL;
		if ($regenerate_cache && $regenerate !== NULL) {
			$regenerate();
		}
		if (!pfblockerng_cron_exists($pfb_tick_cmd, $pfb_tick_min, '*', '*', '*')) {
			install_cron_job('pfblockerng.php cron-tick', FALSE);	// remove stale cron-tick (interval changed)
			install_cron_job('pfblockerng.php tick', FALSE);	// remove legacy pre-#1204 entry
			install_cron_job($pfb_tick_cmd, TRUE, $pfb_tick_min, '*', '*', '*', '*', 'root');
		}
	}
	else {
		install_cron_job('pfblockerng.php cron-tick', FALSE);
		install_cron_job('pfblockerng.php tick', FALSE);
	}

	// issue #1204: trailing space -- a bare 'pfblockerng.php cron' needle substring-matches
	// 'pfblockerng.php cron-tick' and would delete the just-installed entry every sync.
	install_cron_job('pfblockerng.php cron ', FALSE);
	install_cron_job('pfblockerng.php dcc', FALSE);
	install_cron_job('pfblockerng.php ss_refresh', FALSE);
	install_cron_job('pfblockerng.php bl', FALSE);
}


// Collect 'gateway(s)' and 'gateway group(s)' for Adv. In/Outbound customizations
function pfb_get_gateways() {
	$gateway = array();
	$gateway['default'] = 'default';

	foreach (config_get_path('gateways/gateway_item', []) as $item) {
		$gateway[$item['name']] = $item['name'];
	}
	foreach (config_get_path('gateways/gateway_group', []) as $item) {
		$gateway[$item['name']] = $item['name'];
	}

	return $gateway;
}


// Collect all Interfaces for General Tab and DNSBL Firewall Permit Rule
function pfb_build_if_list($show_wan=FALSE, $show_groups=FALSE) {
	$pfb_interfaces = array();

	foreach (get_configured_interface_with_descr() as $ifent => $ifdesc) {
		if ($show_wan || $ifent != 'wan') {
			$pfb_interfaces[$ifent] = $ifdesc;
		}
	}

	if ($show_groups) {
		foreach (config_get_path('ifgroups/ifgroupentry', []) as $ifgen) {
			$pfb_interfaces[$ifgen['ifname']] = $ifgen['ifname'];
		}
	}

	if (ipsec_enabled()) {
		$pfb_interfaces['enc0'] = 'IPsec';
	}

	if (config_get_path('openvpn/openvpn-server') || config_get_path('openvpn/openvpn-client')) {
		$pfb_interfaces['openvpn'] = 'OpenVPN';
	}

	if (config_get_path('l2tp/mode') == 'server') {
		$pfb_interfaces['l2tp'] = 'L2TP VPN';
	}

	if (function_exists('is_wg_enabled') && is_wg_enabled()) {
		$pfb_interfaces['wireguard'] = 'WireGuard';
	}

	return $pfb_interfaces;
}


// Create suppression file(s) from the v4/v6 suppression lists
function pfb_create_suppression_file() {
	global $pfb;

	// ADR-53 review finding B: '?? ""' -- both keys are absent from config.xml
	// on every install until its first IP-settings save post-upgrade (the
	// install migration only seeds v4suppression when a legacy
	// pfBlockerNGSuppress alias existed; v6suppression is never migrated), so
	// a direct array read here throws a PHP8 "undefined array key" warning.
	$v4suppression = pfb_text_area_decode($pfb['ipconfig']['v4suppression'] ?? '', FALSE, TRUE);
	if (!empty($v4suppression)) {
		@file_put_contents("{$pfb['supptxt']}", $v4suppression, LOCK_EX);
	} else {
		unlink_if_exists("{$pfb['supptxt']}");
	}

	// ADR-53: v6 sibling -- same decode/write/unlink-when-empty shape as v4 above.
	$v6suppression = pfb_text_area_decode($pfb['ipconfig']['v6suppression'] ?? '', FALSE, TRUE);
	if (!empty($v6suppression)) {
		@file_put_contents("{$pfb['supptxt_v6']}", $v6suppression, LOCK_EX);
	} else {
		unlink_if_exists("{$pfb['supptxt_v6']}");
	}
}


// Function to update DNSBL widget stats
function dnsbl_stats_update($mode, $alias, $alias_cnt) {
	global $pfb;

	if ($mode == 'update') {
		// Update DNSBL alias statistics
		$dns_now = date('Y-m-d H:i:s', time());
		$pfbfound = FALSE;

		if (!empty($pfb['dnsbl_info_stats'])) {
			foreach ($pfb['dnsbl_info_stats'] as $key => $line) {

				// Update existing alias stats
				if ($line['groupname'] == "{$alias}") {
					$pfbfound = TRUE;
					$pfb['dnsbl_info_stats'][$key]['timestamp']	= "{$dns_now}";
					$pfb['dnsbl_info_stats'][$key]['entries']	= (int) $alias_cnt;
					break;
				}
			}
		}

		if (!$pfbfound) {
			$pfb['dnsbl_info_stats'][] = array ( 'groupname' => $alias, 'timestamp' => $dns_now, 'entries' => (int) $alias_cnt, 'counter' => 0);
		}

	}
	elseif ($mode == 'disabled') {
		// Record disabled alias statistics
		$pfbfound = FALSE;
		if (!empty($pfb['dnsbl_info_stats'])) {
			foreach ($pfb['dnsbl_info_stats'] as $line) {
				if ($line['groupname'] == "{$alias}") {
					$pfbfound = TRUE;
					break;
				}
			}
		}

		if (!$pfbfound) {
			$dns_now = date('Y-m-d H:i:s', time());
			$pfb['dnsbl_info_stats'][] = array ('groupname' => $alias, 'timestamp' => $dns_now, 'entries' => 'disabled', 'counter' => 0);
		}
	}
}


// Function to save DNSBL Group statistics
function dnsbl_save_stats() {
	global $pfb;

	// Save group statistics to SQLite3 database (Remove any feeds that are not referenced)
	$db_update = $db_delete = '';
	pfb_logger("\nSaving DNSBL statistics...", 1);

	// Collect existing SQL group names
	$sql_groupnames = array();
	$db_handle = pfb_open_sqlite(1, 'Collect Group');
	if ($db_handle) {
		$result = $db_handle->query("SELECT * FROM dnsbl;");
		if ($result) {
			while ($res = $result->fetchArray(SQLITE3_ASSOC)) {
				$sql_groupnames[$res['groupname']] = '';
			}
		}
	}
	pfb_close_sqlite($db_handle);

	// Compare SQL database Group names to latest Group names
	if (!empty($pfb['dnsbl_info_stats'])) {

		$db_handle = pfb_open_sqlite(1, 'Save DNSBL stats');
		if ($db_handle) {

			foreach ($pfb['dnsbl_info_stats'] as $group) {

				// Keep row
				$pfb_delete = FALSE;
				if (in_array($group['groupname'], $pfb['alias_dnsbl_all'])) {

					// Update existing row
					if (isset($sql_groupnames[$group['groupname']])) {
						$db_update 	= "UPDATE dnsbl SET timestamp = :timestamp, entries = :entries"
								. " WHERE groupname = :groupname;\n";
					}

					// Add new row
					else {
						$db_update	= "INSERT INTO dnsbl (groupname, timestamp, entries, counter)"
								. " VALUES (:groupname, :timestamp, :entries, 0);\n";
					}
				}

				// Remove row
				else {
					$db_update	= "DELETE FROM dnsbl WHERE groupname = :groupname;\n";
					$pfb_delete	= TRUE;
				}

				if (is_numeric($group['entries'])) {
					$group['groupname'] = pfb_filter($group['groupname'], PFB_FILTER_HTML, 'dnsbl_save_stats');

					$stmt = $db_handle->prepare($db_update);
					if ($stmt) {
						$stmt->bindValue(':groupname', $group['groupname'], SQLITE3_TEXT);
						if (!$pfb_delete) {
							$group['timestamp'] = pfb_filter($group['timestamp'], PFB_FILTER_HTML, 'dnsbl_save_stats');

							$stmt->bindValue(':timestamp', $group['timestamp'], SQLITE3_TEXT);
							$stmt->bindValue(':entries', $group['entries'], SQLITE3_TEXT);
						}
						$stmt->execute();
					}
				}
			}
		}
		pfb_close_sqlite($db_handle);
	}
	else {
		$db_delete = 'DROP TABLE dnsbl;';
		$db_handle = pfb_open_sqlite(1, 'Delete table');
		if ($db_handle) {
			$db_handle->exec("BEGIN TRANSACTION;"
				. "{$db_delete}"
				. "END TRANSACTION;");
		}
		pfb_close_sqlite($db_handle);
	}
	pfb_logger(" completed", 1);
}


// Function to create DNSBL Lighttpd configuration file
function pfb_create_lighttpd() {
	global $pfb;

	$lighttpd_bind = $pfb['dnsbl_iface'] != 'lo0' ? "127.0.0.1" : "{$pfb['dnsbl_vip4']}";
	$lighttpd_port = $pfb['dnsbl_iface'] != 'lo0' ? "{$pfb['dnsbl_port']}" : '80';

	$pfb_conf = '';
	$pfb_conf = <<<EOF
#
#pfBlockerNG DNSBL Lighttpd configuration file
#
server.tag			= "pfBlockerNG DNSBL"
server.bind			= "{$lighttpd_bind}"
server.port			= "{$lighttpd_port}"
server.event-handler		= "freebsd-kqueue"
server.network-backend		= "freebsd-sendfile"
server.dir-listing		= "disable"
server.document-root		= "/usr/local/www/pfblockerng/www/"
server.max-request-size		= "1"
server.pid-file			= "/var/run/dnsbl.pid"

EOF;

if ($pfb['dnsbl_py_nolog'] === PfbToggle::On) {
	$pfb_conf .= <<<EOF
server.errorlog			= "|/usr/local/bin/php -f /usr/local/pkg/pfblockerng/pfblockerng.inc dnsbl"

EOF;
}

	if (file_exists('/usr/local/lib/lighttpd/mod_openssl.so')) {
		if ($pfb['dnsbl_py_nolog'] === PfbToggle::On) {
			$pfb_conf .= 'server.modules			= ( "mod_access", "mod_accesslog", "mod_fastcgi", "mod_rewrite", "mod_openssl" )';
		} else {
			$pfb_conf .= 'server.modules			= ( "mod_fastcgi", "mod_rewrite", "mod_openssl" )';
		}
	} else {
		if ($pfb['dnsbl_py_nolog'] === PfbToggle::On) {
			$pfb_conf .= 'server.modules			= ( "mod_access", "mod_accesslog", "mod_fastcgi", "mod_rewrite" )';
		} else {
			$pfb_conf .= 'server.modules			= ( "mod_fastcgi", "mod_rewrite" )';
		}
	}

	// mod_access backs url.access-deny below; load it unconditionally so the
	// ".inc"/"~" denial is enforced regardless of the logging branch above.
	$pfb_conf .= <<<EOF

server.modules			+= ( "mod_access" )
index-file.names		= ( "index.php" )
mimetype.assign			= ( ".html" => "text/html", ".gif" => "image/gif" )
url.access-deny			= ( "~", ".inc" )
fastcgi.server			= ( ".php" => ( "localhost" => ( "socket" => "/var/run/php-fpm.socket", "broken-scriptfilename" => "enable" ) ) )

EOF;
	if ($pfb['dnsbl_py_nolog'] === PfbToggle::On) {

	$pfb_conf .= <<<EOF
debug.log-condition-handling	= "enable"
accesslog.use-syslog		= "disable"
accesslog.format		= "INDEX!%r!%V!%h!%{Referer}i * %r * %{User-Agent}i"
accesslog.filename		= "|/usr/local/bin/php -f /usr/local/pkg/pfblockerng/pfblockerng.inc index"

EOF;
}
	// Lighttpd v1.4.58+ conditional error log with 'ssl.verifyclient.activate' to collect the domain name
	$lighty_ver = exec('/usr/local/sbin/lighttpd -v 2>&1');
	if (($pfb['dnsbl_py_nolog'] === PfbToggle::On) &&
  	    (strpos($lighty_ver, 'lighttpd/1.4.58') !== FALSE ||
	    strpos($lighty_ver, 'lighttpd/1.4.59') !== FALSE ||
	    strpos($lighty_ver, 'lighttpd/1.4.60') !== FALSE ||
	    strpos($lighty_ver, 'lighttpd/1.4.61') !== FALSE ||
	    strpos($lighty_ver, 'lighttpd/1.4.67') !== FALSE ||
	    strpos($lighty_ver, 'lighttpd/1.5') !== FALSE)) {

		$pfb_conf .= <<<EOF
ssl.verifyclient.activate	= "enable"

EOF;
	}

	$pfb_conf .= <<<EOF

\$HTTP["scheme"] == "http" {
	url.rewrite-once = ( ".*" => "/index.php" )
}

\$HTTP["remoteip"] =~ ".*" {

EOF;

	if ($pfb['dnsbl_iface'] != 'lo0') {
		$pfb_conf .= <<<EOF

	\$SERVER["socket"] == "127.0.0.1:{$pfb['dnsbl_port_ssl']}" {
		ssl.engine			= "enable"
		ssl.pemfile			= "/var/unbound/dnsbl_cert.pem"
		ssl.dh-file			= "/etc/dh-parameters.4096"
		ssl.ec-curve			= "secp384r1"
		ssl.honor-cipher-order		= "enable"
		ssl.openssl.ssl-conf-cmd	= ("MinProtocol"	=> "TLSv1.2",
					 	   "Options"		=> "-ServerPreference",
						   "CipherString"	=> "EECDH+AESGCM:AES256+EECDH:CHACHA20:!SHA1:!SHA256:!SHA384")
	}

	\$SERVER["socket"] == "{$pfb['dnsbl_vip4']}:80" {
		#
	}

EOF;
	}
	$pfb_conf .= <<<EOF

	\$SERVER["socket"] == "{$pfb['dnsbl_vip4']}:443" {
		ssl.engine			= "enable"
		ssl.pemfile			= "/var/unbound/dnsbl_cert.pem"
		ssl.dh-file			= "/etc/dh-parameters.4096"
		ssl.ec-curve			= "secp384r1"
		ssl.honor-cipher-order		= "enable"
		ssl.openssl.ssl-conf-cmd	= ("MinProtocol"	=> "TLSv1.2",
                                                   "Options"		=> "-ServerPreference",
                                                   "CipherString"	=> "EECDH+AESGCM:AES256+EECDH:CHACHA20:!SHA1:!SHA256:!SHA384")
	}

EOF;
	if (!empty($pfb['dnsbl_vip6'])) {
		if ($pfb['dnsbl_iface'] != 'lo0') {
			$pfb_conf .= <<<EOF

	\$SERVER["socket"] == "[::1]:{$pfb['dnsbl_port']}" {
		#
	}

	\$SERVER["socket"] == "[::1]:{$pfb['dnsbl_port_ssl']}" {
		ssl.engine			= "enable"
		ssl.pemfile			= "/var/unbound/dnsbl_cert.pem"
		ssl.dh-file			= "/etc/dh-parameters.4096"
		ssl.ec-curve			= "secp384r1"
		ssl.honor-cipher-order 		= "enable"
		ssl.openssl.ssl-conf-cmd	= ("MinProtocol"	=> "TLSv1.2",
						   "Options"		=> "-ServerPreference",
						   "CipherString"	=> "EECDH+AESGCM:AES256+EECDH:CHACHA20:!SHA1:!SHA256:!SHA384")
	}

EOF;
		}
		$pfb_conf .= <<<EOF

	\$SERVER["socket"] == "[{$pfb['dnsbl_vip6']}]:80" {
		#
	}

	\$SERVER["socket"] == "[{$pfb['dnsbl_vip6']}]:443" {
		ssl.engine			= "enable"
		ssl.pemfile			= "/var/unbound/dnsbl_cert.pem"
		ssl.dh-file			= "/etc/dh-parameters.4096"
		ssl.ec-curve			= "secp384r1"
		ssl.honor-cipher-order		= "enable"
		ssl.openssl.ssl-conf-cmd	= ("MinProtocol"	=> "TLSv1.2",
						   "Options"		=> "-ServerPreference",
						   "CipherString"	=> "EECDH+AESGCM:AES256+EECDH:CHACHA20:!SHA1:!SHA256:!SHA384")
	}

EOF;
	}
	$pfb_conf .= <<<EOF

	\$HTTP["host"] =~ ".*" {
		url.rewrite-once = ( ".*" => "/index.php" )
	}
}

EOF;
	return $pfb_conf;
}


// Function to create DNSBL SSL certificate
function pfb_create_dnsbl_cert() {
	global $pfb, $cert_strict_values;

	$cert		= array();
	$cert['refid']	= uniqid();
	$cert['descr']	= sprintf(gettext("pfBlockerNG DNSBL (%s)"), $cert['refid']);
	$cert_hostname	= config_get_path('system/hostname') . "-pfBNG-DNSBL-{$cert['refid']}";

	$dn = array(
		'organizationName'	=> "pfBlockerNG DNSBL Self-Signed Certificate",
		'commonName'		=> $cert_hostname,
		'subjectAltName'	=> "DNS:{$cert_hostname}");

	$old_err_level = error_reporting(0); /* otherwise openssl_ functions throw warnings directly to a page screwing menu tab */
	if (!cert_create($cert, null, 2048, $cert_strict_values['max_server_cert_lifetime'] ?: 398, $dn, 'self-signed', 'sha256')) {
		while ($ssl_err = openssl_error_string()) {
			logger(LOG_ERR, localize_text("Could not create DNSBL Certificate: openssl library returns: %s", $ssl_err), LOG_PREFIX_PKG_PFBLOCKERNG);
		}
		error_reporting($old_err_level);
		return null;
	}
	error_reporting($old_err_level);
	$privatekey	= base64_decode($cert['prv']);
	$publickey	= base64_decode($cert['crt']);
 
	@file_put_contents("{$pfb['dnsbl_cert']}", "{$privatekey}{$publickey}", LOCK_EX);
}


// [ #381 ] DNSBL sinkhole NAT generation is gated on a real (non-lo0) listening
// interface AND the user not having opted out via pfb_dnsbl_nonat. Pure predicate so
// the branch is unit-testable off-appliance (PfbDnsblNatEnabledTest).
function pfb_dnsbl_nat_enabled(string $iface, PfbToggle $nonat): bool {
	return $iface !== 'lo0' && $nonat !== PfbToggle::On;
}

// Create DNSBL VIP and NAT rules, lighttpd conf and services
function pfb_create_dnsbl($mode) {
	global $pfb;
	pfb_global();

	// [ ADR-13 ] Create/remove the marked DNSBL sinkhole VIP(s) before the NAT pass so the
	// NAT generation below sees the resolved VIP address(es). In the main update pass this
	// is idempotent — sync_package_pfblockerng() already provisioned it before
	// pfb_unbound_python() (so the module ini bakes the right sinkhole IP); here it covers
	// the boot/install call path. No-op (byte-identical) when auto-create is off. Refreshes $pfb.
	pfb_manage_dnsbl_vip($mode);

	$new_nat = $pfb_ex_nat = $dnsbl_ex_nat = array();
	$pfbupdate = FALSE;

	if ((!empty($pfb['dnsbl_port']) && !empty($pfb['dnsbl_port_ssl']) && ($pfb['dnsbl'] === PfbToggle::On) && $mode == 'enabled') || $mode == 'disabled') {

		// DNSBL NAT rules generation
		if ($mode == 'enabled') {
			// Collect existing pfSense NAT rules for comparison.
			foreach (config_get_path('nat/rule', []) as $ex_nat) {
				// Bucket only DNSBL-owned NAT (descr carries 'pfB DNSBL') for rebuild,
				// matching the original strpos() detection — other pfBlockerNG-owned
				// NAT (e.g. a future managed rule) stays in the preserved 'other' bucket.
				if (str_contains($ex_nat['descr'] ?? '', PFB_MANAGED_NAT_LEGACY_PFX)) {
					// Collect DNSBL NAT rules
					$dnsbl_ex_nat[] = $ex_nat;
				} else {
					// Collect all 'other' NAT rules
					$pfb_ex_nat[] = $ex_nat;
				}
			}

			// Generate new DNSBL NAT per DNSBL listening ports except for 'localhost' interface setting.
			$dnsbl_new_nat = array();
			if (pfb_dnsbl_nat_enabled($pfb['dnsbl_iface'], $pfb['dnsbl_nonat'])) {
				$selected_ports = array("{$pfb['dnsbl_port']}" => '80', "{$pfb['dnsbl_port_ssl']}" => '443');
				foreach ($selected_ports as $port => $lport) {

					$dnsbl_new_nat[] =	array ( 'source'		=> array('any'  => ''),
									'destination'		=> array('address' => "{$pfb['dnsbl_vip4']}", 'port' => "{$lport}"),
									'protocol'		=> 'tcp',
									'target'		=> '127.0.0.1',
									'local-port'		=> "{$port}",
									'interface'		=> "{$pfb['dnsbl_iface']}",
									'descr'			=> 'pfB DNSBL - DO NOT EDIT',
									'associated-rule-id'	=> 'pass',
									'natreflection'		=> 'purenat'
									);

					// Add DNSBL IPv6 NAT Rules
					if (!empty($pfb['dnsbl_vip6'])) {
						$dnsbl_new_nat[] = array (	'source'		=> array('any'  => ''),
										'destination'		=> array('address' => "{$pfb['dnsbl_vip6']}",
														'port' => "{$lport}"),
										'protocol'		=> 'tcp',
										'target'		=> '::1',
										'local-port'		=> "{$port}",
										'interface'		=> "{$pfb['dnsbl_iface']}",
										'ipprotocol'		=> 'inet6',
										'descr'			=> 'pfB DNSBL - DO NOT EDIT',
										'associated-rule-id'	=> 'pass',
										'natreflection'		=> 'purenat'
										);
					}
				}
			}

			// Compare existing to new and if they are not identical update
			if ($dnsbl_ex_nat !== $dnsbl_new_nat) {
				$pfbupdate = TRUE;
				$new_nat = array_merge($pfb_ex_nat, $dnsbl_new_nat);
			} else {
				$new_nat = array_merge($pfb_ex_nat, $dnsbl_ex_nat);
			}
		} else {
			// DISABLE: strip pfB DNSBL NAT rules; pfb_remove_managed_obj preserves user-owned
			// rules and returns TRUE iff anything was removed.
			if (pfb_remove_managed_obj('nat/rule', PFB_MANAGED_NAT_LEGACY_PFX)) {
				$pfbupdate = TRUE;
			}
		}

		// Compare previous Lighttpd conf
		$pfb_lighty_conf = pfb_create_lighttpd();
		$pfb_lighty_conf_ex = @file_get_contents($pfb['dnsbl_conf']);
		if ($pfb_lighty_conf !== $pfb_lighty_conf_ex) {
			$pfbupdate = TRUE;
			@file_put_contents($pfb['dnsbl_conf'], $pfb_lighty_conf, LOCK_EX);
			$log = "\nSaving new DNSBL web server configuration to port [ {$pfb['dnsbl_port']} and {$pfb['dnsbl_port_ssl']} ]";
			pfb_logger("{$log}", 1);
		}

		// Update config.xml, if changes required.
		// On enable: write the full new NAT set. On disable: pfb_remove_managed_obj wrote the
		// config change; just persist via write_config.
		if ($pfbupdate) {
			if ($mode == 'enabled') {
				config_set_path('nat/rule', $new_nat);
			}
			write_config('pfBlockerNG: saving DNSBL changes');
		}
	}

	// Save settings, restart services as required
	if ($mode == 'enabled') {

		// Create DNSBL SSL certificate
		if (!file_exists("{$pfb['dnsbl_cert']}")) {
			pfb_create_dnsbl_cert();

			$log = "\nNew DNSBL certificate created";
			pfb_logger("{$log}", 1);
		}

		if ($pfbupdate || !is_service_running('pfb_dnsbl')) {

			// Remove any existing and create link for DNSBL lighttpd executable
			unlink_if_exists('/usr/local/sbin/lighttpd_pfb');
			link('/usr/local/sbin/lighttpd', '/usr/local/sbin/lighttpd_pfb');

			$log = "\nRestarting DNSBL Service";
			pfb_logger("{$log}", 1);
			restart_service('pfb_dnsbl');
		}
	}
	else {
		if (is_service_running('pfb_dnsbl')) {
			pfb_logger("Stop Service DNSBL\n", 1);
			stop_service('pfb_dnsbl');
		}
	}
}


// Resolve a SafeSearch CNAME target (e.g. safe.duckduckgo.com) to its current A/AAAA via the
// configured external DNS server — the baked-fallback IPs in the SafeSearch CSV (issue #149);
// pfb_unbound.py uses them only when the live CNAME chase fails. Returns array($v4, $v6), each
// '' when unresolved. PFBL-01: $target is built into an exec() command line (escapeshellarg()
// handles quoting) and must ALSO validate as a domain via pfb_filter(PFB_FILTER_DOMAIN) first —
// semantic validation and shell quoting are distinct layers. A rejected value returns array('',
// '') with no command run (same shape as a failed resolution); pinned by
// tests/php/PfbFilterContractTest.php.
function pfb_ss_resolve_target($target) {
	global $pfb;

	if (empty($target)) {
		return array('', '');
	}

	// PFBL-01: validate the target as a domain before any command is composed.
	$filtered = pfb_filter($target, PFB_FILTER_DOMAIN, 'pfb_ss_resolve_target');
	if (empty($filtered)) {
		pfb_logger("\npfb_ss_resolve_target: SafeSearch target failed validation [ " .
			substr(htmlspecialchars((string) $target), 0, 100) . " ] *skipping*", 2);
		return array('', '');
	}

	$target_esc = escapeshellarg($filtered);
	$extdns_esc = escapeshellarg("@{$pfb['extdns']}");
	// Injectable resolver binary (#723): tests stub it so a unit run never emits real
	// DNS traffic (a box with a loopback resolver made the real exec succeed and the
	// off-appliance test fail). Production default unchanged.
	$drill_esc = escapeshellarg($pfb['drill'] ?? '/usr/bin/drill');
	// Bound the transient drill | awk pipeline as a whole. FreeBSD timeout's default
	// reaper mode kills every descendant on expiry; --foreground would orphan awk/drill.
	$timeout_esc = escapeshellarg($pfb['timeout'] ?? '/usr/bin/timeout');

	$out4 = array();
	$ret4 = 0;
	$pipeline4 = "{$drill_esc} A {$target_esc} {$extdns_esc} | /usr/bin/awk '/[ \\t]IN[ \\t]+A[ \\t]/ {print \$5; exit}'";
	exec("{$timeout_esc} -s TERM -k 5 30 /bin/sh -c " . escapeshellarg($pipeline4), $out4, $ret4);
	if ($ret4 === 124) {
		pfb_logger("\npfb_ss_resolve_target: A lookup TIMED OUT (killed); treating as unresolved\n", 2);
		$v4 = '';
	} else {
		$v4 = filter_var(trim($out4[0] ?? ''), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ?: '';
	}

	$out6 = array();
	$ret6 = 0;
	$pipeline6 = "{$drill_esc} AAAA {$target_esc} {$extdns_esc} | /usr/bin/awk '/[ \\t]IN[ \\t]+AAAA[ \\t]/ {print \$5; exit}'";
	exec("{$timeout_esc} -s TERM -k 5 30 /bin/sh -c " . escapeshellarg($pipeline6), $out6, $ret6);
	if ($ret6 === 124) {
		pfb_logger("\npfb_ss_resolve_target: AAAA lookup TIMED OUT (killed); treating as unresolved\n", 2);
		$v6 = '';
	} else {
		$v6 = filter_var(trim($out6[0] ?? ''), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ?: '';
	}

	return array($v4, $v6);
}

// Format the SafeSearch python CSV row(s) for one host. Pure (resolution is done
// by the caller via pfb_ss_resolve_target) so it is unit-testable off-appliance.
// Columns: 3 = domain,A,AAAA (A/AAAA rewrite or nxdomain); 5 =
// domain,cname,target,baked_v4,baked_v6 (a CNAME redirect, issue #149). Emits the
// host AND its 'www.' variant for the rewrite/cname forms (matching A/AAAA).
function pfb_ss_csv_rows($host, $data, $v4 = '', $v6 = '') {
	if (isset($data['nxdomain'])) {
		return "{$host},nxdomain,nxdomain\n";
	}
	if (($data['A'] ?? '') === 'cname') {
		$target = $data['AAAA'] ?? '';
		return "{$host},cname,{$target},{$v4},{$v6}\n" .
			"www.{$host},cname,{$target},{$v4},{$v6}\n";
	}
	$a = $data['A'] ?? '';
	$aaaa = $data['AAAA'] ?? '';
	return "{$host},{$a},{$aaaa}\n" .
		"www.{$host},{$a},{$aaaa}\n";
}

// Pure transform behind pfblockerng_ss_refresh(): given the SafeSearch CSV lines
// and a $resolver($target) => array($v4, $v6) callable, refresh the baked #2-fallback
// IPs on each CNAME row (domain,cname,target,v4,v6) in place; every other row is kept
// verbatim. Re-resolution failure (empty result) KEEPS the prior baked IP (never
// blanks a good value). Each distinct target is resolved once. Returns
// array($out_lines, $changed). Side-effect-free so it is unit-testable off-appliance.
function pfb_ss_refresh_lines(array $lines, callable $resolver) {
	$resolved = array();	// target => array(v4, v6), resolved once per target
	$changed = FALSE;
	$out = array();
	foreach ($lines as $line) {
		$cols = explode(',', $line);

		// CNAME row: domain,cname,target,baked_v4,baked_v6
		if (count($cols) === 5 && $cols[1] === 'cname') {
			$target = $cols[2];
			if (!isset($resolved[$target])) {
				$resolved[$target] = $resolver($target);
			}
			list($v4, $v6) = $resolved[$target];

			// Keep the prior baked IP when re-resolution fails (don't blank it).
			$v4 = $v4 ?: $cols[3];
			$v6 = $v6 ?: $cols[4];
			if ($v4 !== $cols[3] || $v6 !== $cols[4]) {
				$changed = TRUE;
			}
			$out[] = "{$cols[0]},cname,{$target},{$v4},{$v6}";
		} else {
			$out[] = $line;
		}
	}

	return array($out, $changed);
}

// #740 install/upgrade migration: the shipped DoH-block conf's dead 'yandex.dns' local-zone
// token (never a real hostname) is now 'dns.yandex'; an install with 'yandex.dns' still
// selected in its 'safesearch_doh_list' CSV would silently lose that selection. Migrates the
// CSV in place: replaces 'yandex.dns' with 'dns.yandex' (preserving order, de-duplicating
// against an existing 'dns.yandex'). $stored is the raw CSV string; returns the rewritten CSV,
// or NULL when nothing to migrate (absent/empty/non-string input, or token not present).
function pfb_ss_doh_list_yandex_migrate($stored) {

	if (!is_string($stored) || $stored === '') {
		return NULL;
	}

	$tokens = explode(',', $stored);
	if (!in_array('yandex.dns', $tokens, TRUE)) {
		return NULL;
	}

	$migrated = array();
	foreach ($tokens as $token) {
		if ($token === 'yandex.dns') {
			$token = 'dns.yandex';
		}
		if (!in_array($token, $migrated, TRUE)) {
			$migrated[] = $token;
		}
	}

	return implode(',', $migrated);
}

// SafeSearch CNAME fallback freshness (issue #149). Light cron task: re-resolve each
// CNAME target in the SafeSearch CSV and refresh its baked #2-fallback IPs in place.
// On change, rewrite the CSV and touch the reload sentinel so pfb_unbound.py picks up
// the new IPs without a full DNSBL rebuild. No-op when the CSV or its CNAME rows are
// absent (or nothing changed). Pure row transform lives in pfb_ss_refresh_lines().
function pfblockerng_ss_refresh() {
	global $pfb;
	pfb_global();

	$ss_file = $pfb['unbound_py_ss'];
	if (!file_exists($ss_file)) {
		return;
	}

	$lines = file($ss_file, FILE_IGNORE_NEW_LINES);
	if (empty($lines)) {
		return;
	}

	list($out, $changed) = pfb_ss_refresh_lines($lines, 'pfb_ss_resolve_target');

	if ($changed) {
		@file_put_contents($ss_file, implode("\n", $out) . "\n", LOCK_EX);
		touch("{$pfb['dnsbl_file']}.reload");
		pfb_logger("\n SafeSearch CNAME fallback IPs refreshed", 1);
	}
}

// Define DNSBL Unbound include settings (config.xml)
function pfb_unbound_dnsbl($mode) {
	global $g, $pfb;
	pfb_global();

	// Reload config.xml to get any recent changes
	config_read_file(FALSE, TRUE);

	$pfbupdate = FALSE;
	$log = '';

	// Collect Unbound custom option pfSense conf line
	$pfb['unboundconfig']	= config_get_path('unbound/custom_options');

	if (!empty($pfb['unboundconfig'])) {
		$unbound_custom = base64_decode($pfb['unboundconfig']);
	} else {
		$unbound_custom = '';
	}

	// The legacy SafeSearch CNAME include (server:include: pfb_dnsbl.*conf) is no
	// longer produced -- the CNAME redirect is done in Python (issue #149). Strip it
	// from the Resolver custom options so an upgraded box drops the orphaned
	// native-mode include; it is never re-added.
	if (!empty($unbound_custom) && strstr($unbound_custom, 'pfb_dnsbl.*conf')) {
		$custom = explode("\n", $unbound_custom);
		foreach ($custom as $key => $line) {
			if (strpos($line, 'pfb_dnsbl.*conf') !== FALSE) {
				unset($custom[$key]);
				$pfbupdate = TRUE;
			}
		}
		$unbound_custom = implode("\n", $custom);
		$log = "\nRemoving orphaned DNSBL SafeSearch CNAME include (Resolver adv. setting)";
	}

	// Remove the previous include line, see Bug #6603
	$custom = explode ("\n", $unbound_custom);
	foreach ($custom as $key => $line) {
		if (strpos($line, 'pfb_dnsbl.conf') !== FALSE) {
			$pfbupdate = TRUE;
			$log .= "\nDNSBL - Removing previous DNSBL Unbound custom option\n";
			unset($custom[$key]);
		}
	}
	$unbound_custom = implode("\n", $custom);

	// Update config.xml, if changes required
	if ($pfbupdate) {
		pfb_logger("{$log}", 1);
		$unbound_custom = pfb_text_area_encode($unbound_custom);
		$pfb['unboundconfig'] = "{$unbound_custom}";
		config_set_path('unbound/custom_options', $pfb['unboundconfig']);
		write_config('pfBlockerNG: saving Unbound custom options');
	}

	// Modify unbound.conf file as required
	if (file_exists("{$pfb['dnsbldir']}/unbound.conf")) {
		$conf = file("{$pfb['dnsbldir']}/unbound.conf");
		if (empty($conf)) {
			pfb_logger("\nDNS Resolver configuration file missing or empty, Exiting!", 1);
		}

		$unbound_py_script = FALSE;	// pfb_unbound.py 'python:' script block present

		$u_update = FALSE;
		$u_msg = '';
		foreach ($conf as $key => $line) {

			if (empty($line)) {
				continue;
			}

			elseif (strpos($line, 'pfb_dnsbl.*conf') !== FALSE) {
				// Orphaned native SafeSearch CNAME include (issue #149) -- always drop;
				// the CNAME redirect is now done by pfb_unbound.py.
				$u_update = TRUE;
				$u_msg .= "  Removed orphaned DNSBL SafeSearch CNAME include\n";
				unset($conf[$key]);
			}

			elseif (strpos($line, 'module-config:') !== FALSE) {
				if ($mode == 'enabled') {
					// Ensure the python module is loaded. The pfb_unbound.py script
					// block is tracked separately ($unbound_py_script) and ensured
					// after the loop, so do NOT infer its presence from this line.
					if (strpos($line, 'module-config: "python') === FALSE) {
						$u_update = TRUE;
						$u_msg .= "  Added DNSBL Unbound Python mode\n";
						$conf[$key] = str_replace('module-config: "', 'module-config: "python ', $line);
					}
				}
				else {
					// Only remove python module if script is 'pfb_unbound'
					if (strpos($line, 'module-config: "python') !== FALSE && in_array("python-script: pfb_unbound.py\n", $conf)) {
						$u_update = TRUE;
						$u_msg .= "  Removed DNSBL Unbound Python mode\n";
						$conf[$key] = str_replace('module-config: "python ', 'module-config: "', $line);
					}
				}
			}

			// Remove any DNSBL VIPs added to unbound.conf on 'disable'
			elseif ((strpos($line, 'interface:') !== FALSE) && ($mode == 'disabled') &&
			    !empty($pfb['dnsbl_vip4']) && (strpos($line, $pfb['dnsbl_vip4']) !== FALSE)) { 
				$u_update = TRUE;
				$u_msg .= "  Removed DNSBL VIP from Unbound Interface settings\n";
				unset($conf[$key]);
			}

			elseif (strpos($line, 'python-script: pfb_unbound.py') !== FALSE) {
				if ($mode == 'enabled') {
					$unbound_py_script = TRUE;
				} else {
					$u_update = TRUE;
					$u_msg .= "  Removed DNSBL Unbound Python mode script\n";
					unset($conf[$key-1]); // remove 'python:' line above
					unset($conf[$key]);
				}
			}
		}

		// Add python script line
		if (!$unbound_py_script && $mode == 'enabled') {
			$u_update = TRUE;
			$u_msg .= "  Added DNSBL Unbound Python mode script\n";
			$conf[] = "\npython:\npython-script: pfb_unbound.py\n";
		}

		if ($mode == 'enabled') {
			// #468: the shipped-file list lives ONLY in 'dnsbl_cache stage' (single
			// source of truth); it also mkdirs the chroot + nullfs mount-point dirs.
			exec('/usr/local/pkg/pfblockerng/pfblockerng.sh dnsbl_cache stage >/dev/null 2>&1');
		} else {
			exec('/usr/local/pkg/pfblockerng/pfblockerng.sh dnsbl_cache teardown >/dev/null 2>&1');
		}

		// Save changes to unbound.conf
		if ($u_update) {
			pfb_logger("\nDNS Resolver ( {$mode} ) unbound.conf modifications:\n{$u_msg}", 1);
			@file_put_contents("{$pfb['dnsbldir']}/unbound.tmp", $conf, LOCK_EX);
			@chown("{$pfb['dnsbldir']}/unbound.tmp", 'unbound');
			@chgrp("{$pfb['dnsbldir']}/unbound.tmp", 'unbound');
			return TRUE;
		}
	}
	else {
		pfb_logger("\n\n*** [ Unbound.conf file missing. Exiting! ] ***\n\n", 1);
	}

	return FALSE;
}


// Create DNSBL Whitelist
function pfb_unbound_python_whitelist($mode='') {
	global $pfb;
	pfb_global();

	$dnsbl_whitelist = '';
	$dnsbl_white = pfb_text_area_decode($pfb['dnsblconfig']['whitelist'] ?? '', TRUE, FALSE, TRUE);
	if (!empty($dnsbl_white)) {
		foreach ($dnsbl_white as $key => $line) {
			if (!empty($line)) {
				if (str_starts_with($line, 'www.')) {
					$line = substr($line, 4);
				}

				if (str_starts_with($line, '.')) {
					$line = pfb_strip_wildcard_marker($line, 'pfb_unbound_python_whitelist');
					if (pfb_is_blank($line)) {
						continue;
					}
					$dnsbl_whitelist .= "{$line},1\n";
				} else {
					$dnsbl_whitelist .= "{$line},0\n";
				}
			}
		}
	}

	if ($mode == 'alerts') {
		@file_put_contents($pfb['unbound_py_wh'], $dnsbl_whitelist, LOCK_EX);
	} else {
		return $dnsbl_whitelist;
	}
}


// ADR-06: Collect the user DNSBL whitelist as normalised source lines for the Python build
// manifest (config.user_whitelist); Python does the www-strip/leading-dot->wildcard
// normalisation itself, so this hands the RAW suppression lines through. PFBL-01: each line
// (free-form textarea input) must validate via pfb_filter(PFB_FILTER_DOMAIN) — accepting the
// leading-dot wildcard form — before it reaches the manifest and query-time whiteDB; a failing
// line is SKIPPED + logged, never silently dropped.
function pfb_dnsbl_whitelist_lines() {
	global $pfb;

	$lines = pfb_text_area_decode($pfb['dnsblconfig']['whitelist'] ?? '', TRUE, FALSE, TRUE);
	$out = array();
	if (!empty($lines)) {
		foreach ($lines as $line) {
			$line = trim($line);
			if ($line === '') {
				continue;
			}
			// PFBL-01: only domain-valid lines (incl. '.example.com' wildcards) may
			// enter the manifest; skip the line + log on failure.
			if (empty(pfb_filter($line, PFB_FILTER_DOMAIN, 'pfb_dnsbl_whitelist_lines'))) {
				pfb_logger("\npfb_dnsbl_whitelist_lines: Suppression line failed validation [ " .
					substr(htmlspecialchars($line), 0, 100) . " ] *skipping*", 2);
				continue;
			}
			$out[] = $line;
		}
	}
	return $out;
}

// ADR-06 (#51): collect the TEMPORARY per-alert DNSBL unlock store ($pfb['dnsbl_unlock'], CSV
// "domain,type" rows toggled by the alerts Lock/Unlock icon) as domains for the Python build
// manifest (config.user_unlock), merged into whiteDB as band-6 user allows. Deliberately
// temporary: lives in /tmp, deleted by a full update/Force/Cron, so a FULL build emits an EMPTY
// user_unlock and re-locks every unlock (documented in the alerts icon tooltip); only the
// incremental alerts path feeds the live store into the manifest. PFBL-01: the store is a plain
// file re-read here, so this reader is its own trust boundary — each domain re-validates via
// pfb_filter(PFB_FILTER_DOMAIN) before entering the manifest; a failing row is SKIPPED + logged.
function pfb_dnsbl_unlock_lines() {
	global $pfb;

	$out = array();
	$store = pfb_unlock('read', 'dnsbl', '', '', '');
	if (is_array($store)) {
		foreach (array_keys($store) as $domain) {
			$domain = trim((string) $domain);
			if ($domain === '') {
				continue;
			}
			// PFBL-01: the store is re-read from a plain file; re-validate each
			// domain before it enters the manifest (skip the row + log on failure).
			if (empty(pfb_filter($domain, PFB_FILTER_DOMAIN, 'pfb_dnsbl_unlock_lines'))) {
				pfb_logger("\npfb_dnsbl_unlock_lines: Unlock domain failed validation [ " .
					substr(htmlspecialchars($domain), 0, 100) . " ] *skipping*", 2);
				continue;
			}
			$out[] = $domain;
		}
	}
	return $out;
}

// ADR-07: extract an IP from an ABP-anchored / hosts line for the DNSBL-IP
// firewall pass (coexistence). The raw ABP line itself still flows to Python, which
// SKIPS IP-valued anchors (parse_abp returns None) -- so IP -> firewall only,
// domain/regex -> Python only (no double-handling, no leak; ADR-06 fact 7).
// Recognises:
//   ||1.2.3.4^            -> '1.2.3.4'   (ABP network anchor with an IP host)
//   ||1.2.3.4^$options    -> '1.2.3.4'   (options stripped before the IP test)
//   <sink-ip> <ip>        -> the second token (hosts line whose target is an IP)
// Returns the IP string when the line carries one, else ''.
function pfb_dnsbl_abp_extract_ip($line) {
	$s = trim($line);
	if ($s === '') {
		return '';
	}

	// ABP network anchor: ||host^[$options]
	if (str_starts_with($s, '||')) {
		$rest	= substr($s, 2);
		// Drop any $options modifier suffix.
		if (($dpos = strpos($rest, '$')) !== FALSE) {
			$rest = substr($rest, 0, $dpos);
		}
		// The host is the token before the ABP separator '^'.
		$host = $rest;
		if (($cpos = strpos($host, '^')) !== FALSE) {
			$host = substr($host, 0, $cpos);
		}
		$host = trim($host);
		if (is_ipaddrv4($host) || is_ipaddrv6($host)) {
			return $host;
		}
		return '';
	}

	// hosts line: "<sink-ip> <target>" where the target is itself an IP. Gate on
	// any whitespace (space OR tab) so tab-delimited hosts entries are not skipped;
	// preg_split('/\s+/') already handles both.
	if (preg_match('/\s/', $s)) {
		$parts = preg_split('/\s+/', $s);
		if (is_array($parts) && count($parts) >= 2 &&
		    (is_ipaddrv4($parts[0]) || is_ipaddrv6($parts[0]))) {
			$target = trim($parts[1]);
			if (is_ipaddrv4($target) || is_ipaddrv6($target)) {
				return $target;
			}
		}
	}

	return '';
}


// Strip a trailing ":<port>" from a host:port feed line (e.g. 'evil.com:8080' ->
// 'evil.com'), but NEVER from an IPv6 literal: an address like '2001:db8:5::7' ends
// in ':<hextet>', so the naive /:[0-9]{1,5}$/ rewrite would mangle it into the
// invalid '2001:db8:5:' -- is_ipaddrv6() then rejects it and the IP is dropped,
// leaving pfB_DNSBLIP_v6 with only the '::<placeholder>' sentinel (the dual-stack
// partition smoke regression, ex-issue #35). A valid IPv6 literal carries no
// host:port, so guarding on is_ipaddrv6() is safe and leaves every non-v6 line
// (domains, domain:port, IPv4, IPv4:port) stripped exactly as before.
function pfb_strip_trailing_port($line) {
	if (!is_ipaddrv6($line) && strpos($line, ':') !== FALSE) {
		return preg_replace("/:[0-9]{1,5}$/", '', $line);
	}
	return $line;
}


// ADR-22: the non-lite scheme strip, gated on the 'pfb_dnsbl_lenient' toggle. No '://' ->
// line unchanged. $strict === FALSE (lenient, today's default/byte-identical): strip through
// the FIRST '://' (permissive: '123://evil.com', '://evil.com', mid-token schemes all accepted,
// matching legacy behaviour). $strict === TRUE (lenient OFF): the text before '://' must match
// the RFC 3986 scheme grammar; a single trailing '/' is normalised away, any other '/' is a
// real path -> FALSE. FALSE tells the caller to skip + log the line (ADR §2.3/§2.4).
function pfb_dnsbl_strip_scheme(string $line, bool $strict = FALSE): string|false {
	$pos = strpos($line, '://');
	if ($pos === FALSE) {
		return $line;
	}
	if ($strict) {
		$scheme = substr($line, 0, $pos);
		if ($scheme === '') {
			// DandelionSprouts' "block regardless of scheme" shape: a bare '://' in
			// front of a bracketed IPv6 literal. Return the bare address directly
			// (already unwrapped and validated here); any other empty scheme is rejected.
			$remainder = substr($line, $pos + 3);
			if (str_starts_with($remainder, '[') && str_ends_with($remainder, ']')) {
				$inner = substr($remainder, 1, -1);
				if (is_ipaddrv6($inner)) {
					return $inner;
				}
			}
			return FALSE;
		}
		if (!preg_match('/^[a-zA-Z][a-zA-Z0-9+\-.]*$/', $scheme)) {
			return FALSE;
		}
	}
	$remainder = substr($line, $pos + 3);
	if ($strict) {
		// A single trailing '/' is the root path -- normalise it away.
		if (str_ends_with($remainder, '/')) {
			$remainder = substr($remainder, 0, -1);
		}
		// Any remaining '/' means an actual path is present -- reject.
		if (strpos($remainder, '/') !== FALSE) {
			return FALSE;
		}
	}
	return $remainder;
}


// Issue #938: strip a leading UTF-8 BOM (EF BB BF) -- encoding metadata, not content,
// the same class of noise pfb_text_sanity() strips up front. Left in place on a feed's
// first line it defeats the str_starts_with($line, '#') comment check, so a BOM-led '# Title: ...'
// header is treated as data and error-logged instead of skipped as a comment. Strips
// exactly ONE BOM (a malformed doubled BOM keeps its second copy rather than looping).
function pfb_dnsbl_strip_bom(string $line): string {
	if (str_starts_with($line, "\xEF\xBB\xBF")) {
		return substr($line, 3);
	}
	return $line;
}


// Per-line scrub for the DNSBL feed parse loop (issue #1797). CR is removed
// EVERYWHERE (a lone CR embeds mid-row after fgets()); the trim charlist is
// ASCII-only so a byte-wise trim can never slice a multi-byte character and
// create invalid UTF-8. Unicode whitespace hygiene (trailing NBSP etc.) is
// the whole-file normalize stage's job. Contract pinned by DnsblScrubLineTest.
function pfb_dnsbl_scrub_line(string $line): string {
	if (strpos($line, "\r") !== FALSE) {
		$line = str_replace("\r", '', $line);
	}
	return trim($line, " \t\n\0\x0B");
}


// Issue #938: unwrap a bracketed IPv6 literal ('[2604:2dc0:100:4ed8::]' -> '2604:2dc0:100:4ed8::')
// so the existing is_ipaddrv6($line) collection branch (feeding $domain_data_ip6) recognises it.
// is_ipaddrv6() rejects the brackets outright and pfb_filter() rejects it as a domain, so today
// every such line hits the DNSBL parse-error log on every feed update. Only a '[' ... ']' wrapper
// around a VALID IPv6 literal is unwrapped; anything else ('[not-an-ip]', '[]', a bracketed IPv4
// literal -- IPv4 is never bracket-legal here) is returned UNCHANGED and keeps flowing to domain
// validation (and the parse-error log) exactly as before.
function pfb_dnsbl_unbracket_ip6(string $line): string {
	if (str_starts_with($line, '[') && str_ends_with($line, ']')) {
		$inner = substr($line, 1, -1);
		if (is_ipaddrv6($inner)) {
			return $inner;
		}
	}
	return $line;
}


// A blank line, or one led by a well-known full-line comment marker: '#' (hosts-style),
// '!' (ABP/uBlock), '//' (C-style) -- the three conventions feeds in this ecosystem mix
// together regardless of the list's own declared format. Callers whose '#' handling
// carries side effects (hpHosts/Spamhaus/CSV-header sniffing in the DNSBL hosts-format
// branch) check '#' themselves first and do not route it through here. The helper strips
// the line itself (pfb_strip, Unicode class -- issue #1787), so indentation the caller's
// ASCII trim() can't remove (NBSP et al.) never hides a marker; blank detection is
// pfb_is_empty()'s exact '' match (empty() would eat the valid line "0").
function pfb_is_blank_or_comment_line(string $line): bool {
	$line = pfb_strip($line);
	return pfb_is_empty($line) ||
		str_starts_with($line, '#') ||
		str_starts_with($line, '!') ||
		str_starts_with($line, '//');
}


// ADR-22: per-line scheme parse for the non-lite download path. Returns the parsed host
// string to keep, or FALSE when strict parsing rejected the line (invalid scheme or a URL
// path). On rejection it records the line in the DNSBL parse-error log (the established
// per-line sink) and increments the per-feed skip counter so the caller can emit one summary
// WARNING (pfb_dnsbl_scheme_skip_warn) after the feed. In lenient mode it never rejects, so
// the counter is untouched and no parse-error line is written -- byte-identical to today.
function pfb_dnsbl_scheme_line(string $line, bool $strict, $header, $oline, $lineno, $logfile, &$skipped): string|false {
	$stripped = pfb_dnsbl_strip_scheme($line, $strict);
	if ($stripped === FALSE) {
		pfb_parse_fail_log($header, $line, $oline, $logfile, $lineno);
		$skipped++;
		return FALSE;
	}
	return $stripped;
}


// ADR-22: the once-per-feed strict-parsing skip summary. A WARNING to the main pfBlockerNG
// log only (logtype 1) naming the feed + the count, so a feed with many malformed lines
// summarises in one line (per-line detail stays in the DNSBL parse-error log; the summary
// is not error-log noise). Silent when nothing was skipped (lenient never bumps the counter).
function pfb_dnsbl_scheme_skip_warn($skipped, $header) {
	if ($skipped > 0) {
		pfb_logger("\n[ DNSBL ] {$header}: {$skipped} line(s) skipped - strict parsing rejected an invalid scheme or URL path (see DNSBL parse-error log)\n", 1);
	}
}


// issue #995: DNSBL '#'-marker classifier extracted for unit coverage. Flags are
// report-only (never clear a caller's existing state) -- a plain '#' comment line
// returns all-false/null and the caller must leave rev_format/csv_type untouched.
function pfb_dnsbl_hash_line_classify(string $line): array {
	if (str_contains($line, 'Append critical updates below')) {
		return ['stop' => TRUE, 'rev_format' => FALSE, 'csv_type' => NULL, 'csv_parser' => FALSE];
	}
	$rev_format = str_contains($line, 'The Spamhaus Project Ltd');
	$csv_type = ($line === '#family,type,url,status,first_seen,'
			. 'first_active,last_active,last_update') ? 'h3x' : NULL;
	return ['stop' => FALSE, 'rev_format' => $rev_format, 'csv_type' => $csv_type, 'csv_parser' => ($csv_type === 'h3x')];
}


// ADR-62: the shape shared by the 6 DNSBL IP-collection call sites (3 v4 + 3 v6
// pairs). Asymmetric by design (kept, not flattened): v4 sanitizes $candidate_value
// THEN validates the SANITIZED result; v6 validates $candidate_value RAW (never
// sanitized) and appends it as-is. $guard_value is the family-check target (equal to
// $candidate_value at two sites; a distinct CSV column at the pon-feed CSV site).
// $pfb['updateip']/$ipcount and any 'continue' differ per call site and stay there;
// this returns TRUE iff an IP was appended.
function pfb_dnsbl_collect_feed_ip(string $guard_value, string $candidate_value, bool $custom, array &$domain_data_ip, array &$domain_data_ip6): bool {
	if (is_ipaddrv4($guard_value)) {
		$parsed = sanitize_ipaddr($candidate_value, $custom, 'Disabled');
		if (validate_ipv4($parsed)) {
			$domain_data_ip[] = $parsed;
			return TRUE;
		}
		return FALSE;
	}
	if (is_ipaddrv6($guard_value)) {
		if (validate_ipv6($candidate_value)) {
			$domain_data_ip6[] = $candidate_value;
			return TRUE;
		}
		return FALSE;
	}
	return FALSE;
}


// issue #1118: the 6-type upstream-CSV classify/extract switch, pulled pure out of
// the download/parse loop's `if ($csv_parser) { ... }` block (mirrors
// pfb_dnsbl_extract_host()'s sentinel-action pattern). $csv_parser=FALSE is a pure
// passthrough (nothing ran in the original block either). Every `continue 2` site
// becomes action='skip' -- the caller's own `continue` replaces it, same as the
// fail-path (pfb_parse_fail_log() moved in here, mirroring pfb_dnsbl_scheme_line()'s
// own logging inside pfb_dnsbl_extract_host()).
function pfb_dnsbl_csv_extract(string $line, array $csvline, string $csv_type, bool $csv_parser,
	bool $run_once, array $alienvault_types, bool $dnsbl_ip_enabled, bool $custom,
	array &$domain_data_ip, array &$domain_data_ip6, string $header, string $oline,
	int $dnsbl_lineno, string $parse_err): array {

	$result = function (string $action, bool $ip_collected = FALSE) use (&$line, &$csv_type,
		&$csv_parser, &$run_once): array {
		return ['action' => $action, 'line' => $line, 'csv_type' => $csv_type,
			'csv_parser' => $csv_parser, 'run_once' => $run_once, 'ip_collected' => $ip_collected];
	};

	if (!$csv_parser) {
		return $result('use');
	}

	$csv_found = FALSE;
	$csv_count = count($csvline);
	$ip_collected = FALSE;

	switch ($csv_type) {
		case 'pt':
			if ($csv_count == 8) {
				if (strpos($csvline[1], ' ') !== FALSE) {
					$line = str_replace(' ', '', $csvline[1]);
				} else {
					$line = $csvline[1];
				}
				$csv_found = TRUE;
			}
			break;
		case 'bbc':
			if ($csv_count == 4) {
				$line		= $csvline[0];
				$csv_found	= TRUE;
			}
			break;
		case 'h3x':
			if ($csv_count == 8) {
				$line		= $csvline[2];
				if (strpos($line, 'btc://') !== FALSE) {
					return $result('skip');
				}
				$csv_found	= TRUE;
			}
			break;
		case 'otx':
			if ($csv_count == 3) {
				if (isset($alienvault_types[$csvline[0]])) {
					$line		= $csvline[1];
					$csv_found	= TRUE;
				} else {
					return $result('skip');
				}
			}
			break;
		case 'pon':
			if ($csv_count == 9) {
				$line		= $csvline[2];
				$csv_found	= TRUE;

				// Collect additional IP csv entry (guard value is
				// csvline[0], the collected value is line).
				if ($dnsbl_ip_enabled &&
				    pfb_dnsbl_collect_feed_ip($csvline[0], $line, $custom, $domain_data_ip, $domain_data_ip6)) {
					$ip_collected = TRUE;
				}
			}
			break;
		case 'et':
			if ($csv_count == 3) {
				$line		= $csvline[0];
				$csv_found	= TRUE;
			}
			break;
		default:

			// Parse Phishtank Feed
			if (strpos($line, 'phish_id,url,'
					. 'phish_detail_url') !== FALSE) {
				$csv_type = 'pt';
				return $result('skip');
			}

			// Parse Bambenek Consulting Feed (issue #1118: guard $csvline[3] -- the
			// otx/et header lines that reach this sniff are only 3 columns).
			elseif (strpos($csvline[3] ?? '', 'osint.'
				. 'bambenekconsulting.com') !== FALSE) {
				$csv_type	= 'bbc';
				$line		= $csvline[0];
				$csv_found	= TRUE;
			}

			// Parse Alienvault OTX pulse Feed
			elseif ($line == 'Indicator type,Indicator,'
					. 'Description') {
				$csv_type	= 'otx';
				return $result('skip');
			}

			// Parse Ponomocup Feed
			elseif (strpos($csvline[0], 'timestamp') !== FALSE) {
				$csv_type	= 'pon';
				return $result('skip');
			}

			// Parse Proofpoint/ET IQRisk IPRep Feed
			elseif ($line == 'domain, category, score') {
				$csv_type	= 'et';
				return $result('skip');
			}

			// Reset variables for CSV determination
			else {
				$csv_parser = $run_once = FALSE;
			}
			break;
	}

	// Record Failed CSV Parse event
	if (!$csv_found || empty($csv_type)) {
		pfb_parse_fail_log($header, '', $oline, $parse_err, $dnsbl_lineno);
		return $result('skip');
	}

	return $result('use', $ip_collected);
}


// ADR-62 §2 Decision 4: the universal plain-path control-line skip. Mirrors
// pfb_is_blank_or_comment_line's contract: the helper strips the line itself
// (pfb_strip, Unicode class -- issue #1787; blank = pfb_is_empty()'s exact '' match,
// so the line "0" is data). Deliberately excludes '#' -- pfb_dnsbl_hash_line_
// classify() owns it (side effects). A bracketed IPv6 literal is an ADDRESS, never
// skipped as an ABP section marker.
function pfb_dnsbl_is_skippable_control_line(string $line): bool {
	$line = pfb_strip($line);
	if (pfb_is_empty($line) || str_starts_with($line, '!') || str_starts_with($line, '//')) {
		return TRUE;
	}
	if (str_starts_with($line, '[') && str_ends_with($line, ']')) {
		return pfb_dnsbl_unbracket_ip6($line) === $line;
	}
	return FALSE;
}


// ADR-62 §2 Decision 2: the per-line ABP-shape capture guard -- answers "should
// Python's parse_abp() decide this line?", never parses it itself. Mirrors parse_abp()/
// _dnsbl_parse_abp_regex()'s recognised shapes: '||'/'@@' anchors, a '/regex/' (optional
// trailing '$options') block/allow rule, and the element-hiding marker family. A bare
// domain line is deliberately FALSE (stays on the plain path, delta D1).
// The element-hiding branch requires everything BEFORE the first marker to be an ABP
// cosmetic domain-list prefix ([A-Za-z0-9._,~*-]; empty = generic rule) -- a mid-line
// ' ## ' inline comment (hosts dialect), a '#'-led comment mentioning '##', or a CSV row
// with a '#'-fragment URL is NOT a cosmetic rule and must keep its plain-path handling
// (the '#'-classifier's side effects included). '//'-led lines are comments by feed
// convention, never '/re/' regex rules. A leading ',' is never valid ABP syntax (empty
// first cosmetic domain-list entry), excluded up front. Kept in lockstep with
// _dnsbl_is_abp_rule_line().
// issue #1792: deliberately does NOT self-strip (unlike the pfb_is_blank_or_comment_line
// family) -- its single caller sits in the parse loop after the per-line scrub, and the
// Python mirror is pinned row-for-row by the ADR-62 parity oracle; a one-sided strip
// here would be drift the oracle exists to prevent.
function pfb_dnsbl_is_abp_rule_line(string $line): bool {
	// issue #1067: a leading comma is never valid ABP syntax (empty first cosmetic
	// domain-list entry) -- excluded up front regardless of downstream encoding.
	if (str_starts_with($line, ',')) {
		return FALSE;
	}
	if (str_starts_with($line, '||') || str_starts_with($line, '@@')) {
		return TRUE;
	}
	if (str_contains($line, '#')) {
		$first = FALSE;
		$marker_len = 0;
		foreach (array('##', '#@#', '#?#', '#%#', '#$#') as $eh_marker) {
			$pos = strpos($line, $eh_marker);
			if ($pos !== FALSE && ($first === FALSE || $pos < $first)) {
				$first = $pos;
				$marker_len = strlen($eh_marker);
			}
		}
		if ($first !== FALSE) {
			if ($first === 0) {
				// issue #1345: position-zero marker comments use Python's exact whitespace set.
				$after = substr($line, $marker_len);
				if ($after !== '' &&
				    preg_match('/\A(?:[\x{0009}-\x{000D}\x{001C}-\x{001F}\x{0085}]|\p{Z})/u', mb_substr($after, 0, 1, 'UTF-8')) !== 1) {
					return TRUE;
				}
			} elseif (strspn($line, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._,~*-') >= $first) {
				return TRUE;
			}
		}
	}
	if (str_starts_with($line, '/') && !str_starts_with($line, '//')) {
		if (str_ends_with($line, '/') && strlen($line) > 1) {
			return TRUE;
		}
		$marker = strrpos($line, '/$');
		return ($marker !== FALSE && $marker > 0);
	}
	return FALSE;
}


// ADR-10: atomically publish a file to the chroot (/var/unbound). The same-directory
// rename is the runtime visibility commit; crash durability needs the #1357 FreeBSD
// parent-directory fsync probe and is not claimed by this helper.
// Returns TRUE on success. No die()/exit(): a failure is logged + returned FALSE so
// the caller can fall back to the restart path.
function pfb_unbound_py_stream_sync($fh, string $content, $write_fn=NULL, $flush_fn=NULL, $fsync_fn=NULL): bool {
	$write_fn = $write_fn ?? static fn($stream, $bytes) => @fwrite($stream, $bytes);
	$flush_fn = $flush_fn ?? static fn($stream) => @fflush($stream);
	$fsync_fn = $fsync_fn ?? static fn($stream) => @fsync($stream);
	$written = $write_fn($fh, $content);
	return $written !== FALSE && $written === strlen($content) && $flush_fn($fh) && $fsync_fn($fh);
}

function pfb_unbound_py_atomic_write($path, $content, array $stream_ops=array()) {
	$dir = dirname($path);
	$tmp = @tempnam($dir, '.pfbpub_');
	if ($tmp === FALSE) {
		pfb_logger("\nADR-10: failed to stage atomic write for [ {$path} ]", 2);
		return FALSE;
	}

	$fh = @fopen($tmp, 'wb');
	if ($fh === FALSE) {
		@unlink($tmp);
		pfb_logger("\nADR-10: failed to open staging file [ {$tmp} ]", 2);
		return FALSE;
	}

	$ok = pfb_unbound_py_stream_sync($fh, $content,
		$stream_ops['write'] ?? NULL, $stream_ops['flush'] ?? NULL, $stream_ops['fsync'] ?? NULL);
	$ok = @fclose($fh) && $ok;

	if (!$ok) {
		@unlink($tmp);
		pfb_logger("\nADR-10: failed to write staging file [ {$tmp} ]", 2);
		return FALSE;
	}

	// Preserve the helper's existing best-effort ownership semantics: test/dev hosts
	// need not have an unbound account, while appliance writes still request it.
	@chown($tmp, 'unbound');
	@chgrp($tmp, 'unbound');

	$rename_fn = $stream_ops['rename'] ?? static fn($from, $to) => @rename($from, $to);
	if (!$rename_fn($tmp, $path)) {
		@unlink($tmp);
		pfb_logger("\nADR-10: failed to publish [ {$path} ]", 2);
		return FALSE;
	}

	return TRUE;
}

// Issue #1569: preserve canonical TOP1M bytes while projecting either retired
// three-line wire family to the strict one-domain-per-line Python sidecar.
function pfb_unbound_py_top1m_atomic_copy(string $source, string $path, array $stream_ops=array()): bool {
	if (is_link($source) || !is_file($source) || !is_readable($source)) {
		return FALSE;
	}
	$source_h = @fopen($source, 'rb');
	if ($source_h === FALSE) {
		return FALSE;
	}
	$first_byte = @fread($source_h, 1);
	if ($first_byte === FALSE) {
		@fclose($source_h);
		return FALSE;
	}
	if (!@rewind($source_h)) {
		@fclose($source_h);
		return FALSE;
	}

	$tmp = @tempnam(dirname($path), '.pfbtop1m_');
	if ($tmp === FALSE) {
		@fclose($source_h);
		return FALSE;
	}
	$target_h = @fopen($tmp, 'wb');
	if ($target_h === FALSE) {
		@fclose($source_h);
		@unlink($tmp);
		return FALSE;
	}
	$write_fn = $stream_ops['write'] ?? static fn($stream, $bytes) => @fwrite($stream, $bytes);
	$flush_fn = $stream_ops['flush'] ?? static fn($stream) => @fflush($stream);
	$fsync_fn = $stream_ops['fsync'] ?? static fn($stream) => @fsync($stream);
	$ok = TRUE;
	if ($first_byte !== '.') {
		while (!feof($source_h)) {
			$chunk = @fread($source_h, 1048576);
			if ($chunk === FALSE) {
				$ok = FALSE;
				break;
			}
			if ($chunk !== '') {
				$written = $write_fn($target_h, $chunk);
				if ($written === FALSE || $written !== strlen($chunk)) {
					$ok = FALSE;
					break;
				}
			}
		}
	}

	$patterns = array(
		'comma' => array(
			'/\A\.([A-Za-z0-9.-]+),,\n\z/D',
			'/\A,([A-Za-z0-9.-]+),,\n\z/D',
			'/\A,www\.([A-Za-z0-9.-]+),,\n\z/D',
		),
		'native' => array(
			'/\A\.([A-Za-z0-9.-]+) 60\n\z/D',
			'/\A"([A-Za-z0-9.-]+) 60\n\z/D',
			'/\A"www\.([A-Za-z0-9.-]+) 60\n\z/D',
		),
	);
	$validate_domain = static function (string $domain): bool {
		if (strlen($domain) > 253 || !str_contains($domain, '.')) {
			return FALSE;
		}
		foreach (explode('.', $domain) as $label) {
			$length = strlen($label);
			if ($length < 1 || $length > 63 ||
			    preg_match('/\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/D', $label) !== 1) {
				return FALSE;
			}
		}
		return TRUE;
	};
	$family = NULL;
	while ($first_byte === '.') {
		$lines = array(@fgets($source_h, 1024));
		if ($lines[0] === FALSE) {
			$ok = feof($source_h);
			break;
		}
		$lines[] = @fgets($source_h, 1024);
		$lines[] = @fgets($source_h, 1024);
		if ($lines[1] === FALSE || $lines[2] === FALSE) {
			$ok = FALSE;
			break;
		}

		$record_family = NULL;
		$domains = array();
		foreach ($patterns as $candidate_family => $candidate_patterns) {
			$matches = array();
			if (preg_match($candidate_patterns[0], $lines[0], $matches) !== 1) {
				continue;
			}
			$record_family = $candidate_family;
			$domains[] = $matches[1];
			for ($index = 1; $index < 3; $index++) {
				$matches = array();
				if (preg_match($candidate_patterns[$index], $lines[$index], $matches) !== 1) {
					$ok = FALSE;
					break 2;
				}
				$domains[] = $matches[1];
			}
			break;
		}
		if (!$ok || $record_family === NULL || ($family !== NULL && $family !== $record_family)) {
			$ok = FALSE;
			break;
		}
		$family = $record_family;
		$domain = strtolower($domains[0]);
		if (strtolower($domains[1]) !== $domain || strtolower($domains[2]) !== $domain ||
		    !$validate_domain($domain)) {
			$ok = FALSE;
			break;
		}
		$output = "{$domain}\n";
		$written = $write_fn($target_h, $output);
		if ($written === FALSE || $written !== strlen($output)) {
			$ok = FALSE;
			break;
		}
	}
	$ok = @fclose($source_h) && $ok;
	$ok = $ok && $flush_fn($target_h) && $fsync_fn($target_h);
	$ok = @fclose($target_h) && $ok;
	if (!$ok) {
		@unlink($tmp);
		return FALSE;
	}
	$chown_fn = $stream_ops['chown'] ?? static fn($file, $owner) => @chown($file, $owner);
	$chgrp_fn = $stream_ops['chgrp'] ?? static fn($file, $group) => @chgrp($file, $group);
	$chmod_fn = $stream_ops['chmod'] ?? static fn($file, $mode) => @chmod($file, $mode);
	$metadata_fn = $stream_ops['metadata'] ?? static function ($file) use ($chown_fn, $chgrp_fn, $chmod_fn): bool {
		return $chown_fn($file, 'root') && $chgrp_fn($file, 'unbound') && $chmod_fn($file, 0640);
	};
	if (!$metadata_fn($tmp)) {
		@unlink($tmp);
		return FALSE;
	}
	$rename_fn = $stream_ops['rename'] ?? static fn($from, $to) => @rename($from, $to);
	if (!$rename_fn($tmp, $path)) {
		@unlink($tmp);
		return FALSE;
	}
	return TRUE;
}

// issue #1780: the bounded default every NULL caller of the publication lock
// resolves to. Holders are local manifest/GC/teardown file writes; the worst-case
// hold is unmeasured, so 60s is a deliberately loose finite cap -- it exists to
// terminate a wedged acquire, not to time a healthy one.
function pfb_unbound_py_publication_lock_timeout(): float {
	return 60.0;
}

// #1357: one exclusive lock serializes full-set publication, scalar manifest patches,
// convergence-gated generation GC, and teardown. Python readers never take this lock.
function pfb_unbound_py_publication_lock(?float $timeout_s=NULL) {
	global $pfb;

	$manifest_path = $pfb['unbound_py_sources'] ?? '';
	if ($manifest_path === '') {
		pfb_logger("\nDNSBL publication lock path unavailable", 2);
		return FALSE;
	}
	$lock = @fopen(dirname($manifest_path) . '/pfb_py_sources.lock', 'c');
	if ($lock === FALSE) {
		pfb_logger("\nDNSBL publication lock unavailable", 2);
		return FALSE;
	}

	if ($timeout_s === NULL) {
		$timeout_s = pfb_unbound_py_publication_lock_timeout();
	}

	$timed_out = FALSE;
	if (pfb_flock_bounded($lock, LOCK_EX, $timeout_s, $timed_out)) {
		return $lock;
	}

	@fclose($lock);
	// issue #1780: "timed out" only on a genuine deadline expiry; a real
	// flock() error is "unavailable", matching every other hard failure above.
	pfb_logger($timed_out ? "\nDNSBL publication lock timed out" : "\nDNSBL publication lock unavailable", 2);
	return FALSE;
}

function pfb_unbound_py_publication_unlock($lock): void {
	if (is_resource($lock)) {
		@flock($lock, LOCK_UN);
		@fclose($lock);
	}
}

// Strictly enumerate only #1357 generation/stage siblings; never broaden this prefix.
function pfb_unbound_py_raw_artifacts(array $pfb): array {
	$rawdir = $pfb['unbound_py_rawdir'] ?? '';
	if ($rawdir === '' || $rawdir[0] !== '/') {
		return array();
	}
	$parent = realpath(dirname($rawdir)) ?: dirname($rawdir);
	$rawdir = "{$parent}/" . basename($rawdir);
	$base = basename($rawdir);
	$entries = @scandir($parent);
	if ($entries === FALSE) {
		return array();
	}
	$pattern = '/^' . preg_quote($base, '/') . '\.(?:[0-9a-f]{32}|stage\.[0-9a-f]{32})$/D';
	$paths = (file_exists($rawdir) || is_link($rawdir)) ? array($rawdir) : array();
	foreach ($entries as $entry) {
		if (preg_match($pattern, $entry) === 1) {
			$paths[] = "{$parent}/{$entry}";
		}
	}
	sort($paths, SORT_STRING);
	return $paths;
}

function pfb_unbound_py_remove_raw_artifact(string $path): bool {
	if (is_dir($path) && !is_link($path)) {
		rmdir_recursive($path);
	} else {
		@unlink($path);
	}
	return !file_exists($path) && !is_link($path);
}

// #1357: collect only after a watcher apply or restart has truly converged.
function pfb_unbound_py_gc(bool $converged): bool {
	global $pfb;

	$lock = pfb_unbound_py_publication_lock(0.25);
	if ($lock === FALSE) {
		return FALSE;
	}
	try {
		if (!$converged) {
			return FALSE;
		}
		$json = @file_get_contents($pfb['unbound_py_sources']);
		$manifest = $json !== FALSE ? json_decode($json, TRUE) : NULL;
		if (!is_array($manifest) || !isset($manifest['feeds']) || !is_array($manifest['feeds'])) {
			return FALSE;
		}
		$raw_paths = pfb_unbound_py_manifest_raw_paths($pfb['unbound_py_sources'], FALSE);
		if (count($raw_paths) !== count($manifest['feeds'])) {
			return FALSE;
		}
		$protected = array();
		foreach ($raw_paths as $raw_path) {
			$raw_dir = realpath(dirname($raw_path));
			if ($raw_dir === FALSE || !is_file($raw_path)) {
				return FALSE;
			}
			$protected[$raw_dir] = TRUE;
		}
		$ok = TRUE;
		foreach (pfb_unbound_py_raw_artifacts($pfb) as $artifact) {
			if (isset($protected[$artifact])) {
				continue;
			}
			if (!pfb_unbound_py_remove_raw_artifact($artifact)) {
				pfb_logger("\nDNSBL raw generation cleanup failed", 2);
				$ok = FALSE;
			}
		}
		return $ok;
	} finally {
		pfb_unbound_py_publication_unlock($lock);
	}
}

function pfb_unbound_py_teardown_raw_set(): bool {
	global $pfb;

	$lock = pfb_unbound_py_publication_lock();
	if ($lock === FALSE) {
		return FALSE;
	}
	try {
		unlink_if_exists($pfb['unbound_py_sources']);
		// issue #2607: every Python-emitted artifact describes the generation this manifest
		// defines and is rewritten only for a build that produced a snapshot, so each one
		// left behind is read back as live by the update log, the RAM gate or the alias count.
		foreach (array('unbound_py_count', 'unbound_py_regex_count', 'unbound_py_reject_stats') as $emitted) {
			if (!empty($pfb[$emitted])) {
				unlink_if_exists($pfb[$emitted]);
			}
		}
		pfb_unbound_py_remove_raw_artifact($pfb['unbound_py_rawdir']);
		$ok = TRUE;
		foreach (pfb_unbound_py_raw_artifacts($pfb) as $artifact) {
			$ok = pfb_unbound_py_remove_raw_artifact($artifact) && $ok;
		}
		$top1m_base = "{$pfb['dbdir']}/top-1m.csv.zip";
		foreach (array(
			$pfb['unbound_py_top1m'] ?? '/var/unbound/pfb_py_top1m.txt',
			"{$top1m_base}.orig",
			"{$top1m_base}.xxhash128",
			"{$top1m_base}.md5",
			"{$top1m_base}.source",
			"{$top1m_base}.orig.etag",
			"{$top1m_base}.orig.lastmod",
		) as $artifact) {
			if (file_exists($artifact) || is_link($artifact)) {
				$ok = unlink_if_exists($artifact) && $ok;
			}
		}
		foreach (array(
			"{$pfb['dbdir']}/.pfbtop1m_*",
			dirname($pfb['unbound_py_top1m'] ?? '/var/unbound/pfb_py_top1m.txt') . '/.pfbtop1m_*',
		) as $pattern) {
			foreach (glob($pattern) ?: array() as $artifact) {
				$ok = pfb_unbound_py_remove_raw_artifact($artifact) && $ok;
			}
		}
		return $ok;
	} finally {
		pfb_unbound_py_publication_unlock($lock);
	}
}

function pfb_top1m_teardown_call(?callable $teardown = NULL): bool {
	$teardown ??= 'pfb_unbound_py_teardown_raw_set';
	return (bool) $teardown();
}


// ADR-10: flip the zero-downtime RELOAD SENTINEL (the all-or-nothing commit that
// wakes the Python reload-watcher). The sentinel host path is /var/unbound/pfb_py_reload
// (Unbound is chrooted at /var/unbound; the module opens it as the chroot-relative
// "pfb_py_reload"). Its content is a monotonically NON-DECREASING
// base-10 integer GENERATION on the FIRST LINE. The watcher swaps IFF the freshly-read
// generation is a STRICT ADVANCE over its last-seen value, so we write current+1 (or 1
// when the sentinel is absent/empty/non-integer). The write is atomic (stage -> fsync ->
// rename via pfb_unbound_py_atomic_write) so the watcher's directory watch sees a clean
// RENAME and never reads a half-written integer. Returns TRUE when the sentinel advanced.
function pfb_unbound_py_flip_sentinel() {
	global $pfb;

	$sentinel = "{$pfb['dnsbldir']}/pfb_py_reload";

	$cur = 0;
	if (file_exists($sentinel)) {
		$raw = @file_get_contents($sentinel);
		if ($raw !== FALSE) {
			$first = strtok($raw, "\n");
			if ($first !== FALSE) {
				$first = trim($first);
				if ($first !== '' && ctype_digit($first)) {
					$cur = (int) $first;
				}
			}
		}
	}

	$next = $cur + 1;
	if (!pfb_unbound_py_atomic_write($sentinel, "{$next}\n")) {
		return FALSE;
	}
	$published_hook = $GLOBALS['pfb_test_unbound_py_sentinel_published'] ?? NULL;
	if (is_callable($published_hook)) {
		$published_hook($sentinel, $next);
	}

	// Return the generation just published (>= 1) so the caller can wait for the
	// watcher's applied-generation marker to reach it -- the readiness handshake that
	// replaces "wait for the Unbound restart" for a no-restart data update (ADR-10).
	return $next;
}


// Poll (bounded) an applied-generation/sequence marker file until its first line
// parses as an integer >= $target, or $timeout_s elapses. Shared by
// pfb_unbound_py_wait_applied() (the ADR-10 reload-watcher handshake) and
// pfb_unbound_py_wait_control_applied() (the control-channel watcher). 200 ms
// poll interval; returns TRUE once applied, FALSE on timeout.
function pfb_unbound_py_wait_marker($path, $target, $timeout_s) {
	$target = (int) $target;
	$deadline = microtime(TRUE) + (float) $timeout_s;

	do {
		if (file_exists($path)) {
			$raw = @file_get_contents($path);
			if ($raw !== FALSE) {
				$first = strtok($raw, "\n");
				if ($first !== FALSE) {
					$first = trim($first);
					if ($first !== '' && ctype_digit($first) && (int) $first >= $target) {
						return TRUE;
					}
				}
			}
		}
		usleep(200000);	// 200 ms between polls
	} while (microtime(TRUE) < $deadline);

	return FALSE;
}


// ADR-10: wait (bounded) for the reload-watcher to APPLY a published generation. After
// flipping the sentinel to $gen, blocks until the watcher writes a value >= $gen to the applied
// marker (/var/unbound/pfb_py_reload.applied) — restoring the "lists live on return" invariant
// the restart had. Queries NEVER stop during the wait (zero-downtime/zero-dropped). Returns
// TRUE once applied; FALSE on timeout, where the caller falls back to the restart (fail-safe).
// Poll cadence (~2s) + rebuild time bound the latency; the default budget covers a large ABP rebuild.
function pfb_unbound_py_wait_applied($gen, $timeout_s = 30) {
	global $pfb;

	return pfb_unbound_py_wait_marker("{$pfb['dnsbldir']}/pfb_py_reload.applied", $gen, $timeout_s);
}


// Poll until the control-channel watcher has applied sequence $seq (or beyond), confirming
// the published command was consumed. Mirrors pfb_unbound_py_wait_applied() in structure:
// reads the applied marker (/var/unbound/pfb_py_control.applied), parses the first line as
// an integer, and returns TRUE when the stored value >= $seq. Returns FALSE on timeout.
// A $timeout_s <= 0 is never passed here (the caller guards); 200 ms poll interval.
function pfb_unbound_py_wait_control_applied($seq, $timeout_s = 5) {
	global $pfb;

	return pfb_unbound_py_wait_marker("{$pfb['dnsbldir']}/pfb_py_control.applied", $seq, $timeout_s);
}


// PFBL-03: atomically publish the DNSBL-control command channel to the chroot
// (/var/unbound/pfb_py_control). Mirrors pfb_unbound_py_atomic_write (stage -> fwrite ->
// fflush -> fsync -> rename) but uses a COMMAND-CHANNEL permission model rather than the
// data model: the published file keeps owner ROOT, group unbound, mode 0640 -- root
// WRITES, unbound READS via its group, no write for group/other, no access for other.
// The authorization is therefore purely "only root may write": the channel is unwritable
// by the unbound user that consumes it (and by everyone else). This is why the data
// publisher (which chowns to owner unbound) is NOT reused here. Returns TRUE on success;
// no die()/exit() -- a failure is logged + returned FALSE.
function pfb_unbound_py_atomic_write_root($path, $content) {
	$dir = dirname($path);
	$tmp = @tempnam($dir, '.pfbctl_');
	if ($tmp === FALSE) {
		pfb_logger("\nPFBL-03: failed to stage control write for [ {$path} ]", 2);
		return FALSE;
	}

	$fh = @fopen($tmp, 'wb');
	if ($fh === FALSE) {
		@unlink($tmp);
		pfb_logger("\nPFBL-03: failed to open control staging file [ {$tmp} ]", 2);
		return FALSE;
	}

	// Require the FULL content to land (fwrite returns the byte count, not just
	// TRUE/FALSE) and that the durability barrier itself succeeds, so a truncated or
	// unflushed command record is never published as success.
	$written = @fwrite($fh, $content);
	$ok = ($written === strlen($content));
	if ($ok) {
		// Durably persist the staged bytes before the rename so a crash cannot
		// expose a half-written command record.
		$ok = (@fflush($fh) && @fsync($fh));
	}
	@fclose($fh);

	if (!$ok) {
		@unlink($tmp);
		pfb_logger("\nPFBL-03: failed to write control staging file [ {$tmp} ]", 2);
		return FALSE;
	}

	// Command-channel permission model: owner root, group unbound, mode 0640. Set it on
	// the staging inode so the rename publishes the correctly-owned/permissioned file
	// atomically. root is the staging file's owner already (the package runs as root);
	// set the group explicitly so the consuming (chrooted) unbound user can READ it, and
	// the mode so only the owner may write.
	@chown($tmp, 'root');
	@chgrp($tmp, 'unbound');
	@chmod($tmp, 0640);

	if (!@rename($tmp, $path)) {
		@unlink($tmp);
		pfb_logger("\nPFBL-03: failed to publish control channel [ {$path} ]", 2);
		return FALSE;
	}

	return TRUE;
}


// PFBL-03: root-only DNSBL-control writer. Validates command + argument (bypass IP via
// PFB_FILTER_IP, duration via PFB_FILTER_NUM clamped 1-3600), assembles a JSON record with a
// monotonically-advancing SEQUENCE, and atomically publishes to the privileged command channel
// (root:unbound 0640, pfb_unbound_py_atomic_write_root). pfb_unbound.py's control-watcher
// consumes a record only when its seq advances and re-validates every argument itself — writer
// + reader form a dual-validation boundary. $cmd: disable|enable|addbypass|removebypass; $ip
// required for add/removebypass; $duration optional 1-3600s. Returns the published sequence
// (>= 1) or FALSE on failure; $wait_timeout <= 0 = fire-and-forget.
function pfb_unbound_py_write_control($cmd, $ip = '', $duration = '', $wait_timeout = 5) {
	global $pfb;

	// Validate the command allow-list before touching the lock -- cheap guard first.
	$valid_cmds = array('disable', 'enable', 'addbypass', 'removebypass');
	if (!in_array($cmd, $valid_cmds, TRUE)) {
		pfb_logger("\nPFBL-03: control command not authorized [ " . htmlspecialchars((string) $cmd) . " ]", 2);
		return FALSE;
	}

	$record = array('cmd' => $cmd);

	// Validate the bypass IP for the commands that take one (the semantic layer).
	if ($cmd == 'addbypass' || $cmd == 'removebypass') {
		$clean_ip = pfb_filter($ip, PFB_FILTER_IP, 'pfb_unbound_py_write_control');
		if (empty($clean_ip)) {
			pfb_logger("\nPFBL-03: control command [ {$cmd} ] rejected: invalid IP", 2);
			return FALSE;
		}
		$record['ip'] = $clean_ip;
	}

	// Validate the optional duration for the commands that take one (1-3600 seconds).
	if (($cmd == 'disable' || $cmd == 'addbypass') && $duration !== '' && $duration !== NULL) {
		$clean_dur = pfb_filter($duration, PFB_FILTER_NUM, 'pfb_unbound_py_write_control');
		if (empty($clean_dur) || (int) $clean_dur < 1 || (int) $clean_dur > 3600) {
			pfb_logger("\nPFBL-03: control command [ {$cmd} ] rejected: duration out of range (1-3600)", 2);
			return FALSE;
		}
		$record['duration'] = (int) $clean_dur;
	}

	// Serialize concurrent writers: acquire an exclusive lock before read->increment->publish
	// so two writers cannot read the same seq and issue duplicate records, and a second
	// writer cannot overwrite a still-unapplied command.
	$lockpath = "{$pfb['dnsbldir']}/pfb_py_control.lock";
	$lock = @fopen($lockpath, 'c');	// 'c': create if absent, no truncate
	if ($lock === FALSE) {
		pfb_logger("\nPFBL-03: control channel lock open failed [ {$lockpath} ]", 2);
		return FALSE;
	}
	$timed_out = FALSE;
	if (!pfb_flock_bounded($lock, LOCK_EX, 5.0, $timed_out)) {
		@fclose($lock);
		// issue #1780: "timed out" only on a genuine deadline expiry; a real
		// flock() error is "acquire failed", matching every other hard failure above.
		pfb_logger($timed_out
			? "\nPFBL-03: control channel lock acquire timed out [ {$lockpath} ]"
			: "\nPFBL-03: control channel lock acquire failed [ {$lockpath} ]", 2);
		return FALSE;
	}

	// Read the current sequence from the channel and advance it. A missing/unparseable
	// record -> seq 0 -> next publish is 1.
	$channel = "{$pfb['dnsbldir']}/pfb_py_control";
	$cur = 0;
	if (file_exists($channel)) {
		$raw = @file_get_contents($channel);
		if ($raw !== FALSE && $raw !== '') {
			$prev = @json_decode($raw, TRUE);
			if (is_array($prev) && isset($prev['seq']) && is_int($prev['seq'])) {
				$cur = $prev['seq'];
			}
		}
	}
	$record['seq'] = $cur + 1;
	$record['ts']  = time();

	$payload = json_encode($record);
	if ($payload === FALSE) {
		@flock($lock, LOCK_UN);
		@fclose($lock);
		pfb_logger("\nPFBL-03: control command [ {$cmd} ] rejected: encode failure", 2);
		return FALSE;
	}

	if (!pfb_unbound_py_atomic_write_root($channel, $payload . "\n")) {
		@flock($lock, LOCK_UN);
		@fclose($lock);
		return FALSE;
	}

	// While still holding the lock, optionally wait for the watcher to apply the command
	// before returning. The command IS on disk regardless; the wait only confirms consumption.
	if ($wait_timeout > 0) {
		$applied = pfb_unbound_py_wait_control_applied($record['seq'], $wait_timeout);
		if (!$applied) {
			pfb_logger("\nPFBL-03: control command [ {$cmd} ] seq {$record['seq']} published"
				. " but not confirmed applied within {$wait_timeout}s; the watcher will still apply it", 2);
		}
	}

	@flock($lock, LOCK_UN);
	@fclose($lock);
	return $record['seq'];
}


// ADR-10: PRIMARY RAM gate for the zero-downtime swap (the Python watcher re-checks it as a
// safety net). The background rebuild holds OLD + NEW matcher structures resident at once
// (~2x transient); on a constrained box that bust would OOM mid-swap. Mirrors the Python
// projection: 2 * loaded_entries * 276 B + 64 MiB headroom, measured against hw.usermem.
// Returns TRUE when the projected build FITS (zero-downtime allowed); FALSE -> the caller
// takes the restart fallback. Unknown RAM/count -> FALSE (fail-closed: restart never doubles,
// frees the old set by dying before rebuilding).
function pfb_unbound_py_swap_fits_ram() {
	global $pfb;

	// Bytes-per-entry + headroom mirror pfb_unbound.py RELOAD_BYTES_PER_ENTRY (276) and
	// RELOAD_RAM_HEADROOM_BYTES (64 MiB). Keep the two ends of this contract in step.
	$bytes_per_entry = 276;
	$headroom	 = 64 * 1024 * 1024;

	// Loaded entry count = the live snapshot size the Python build emits (data+zone).
	$loaded = @file_get_contents($pfb['unbound_py_count']);
	if ($loaded === FALSE) {
		return FALSE;
	}
	$loaded = trim((string) $loaded);
	if ($loaded === '' || !ctype_digit($loaded)) {
		// No emitted count yet (first build) -> cannot project -> fail-closed to restart.
		return FALSE;
	}
	$entries = (int) $loaded;

	// hw.usermem = physical memory minus the kernel's wired pages (bytes). This is the
	// AUTHORITATIVE pre-flip gate; the Python watcher re-checks the same TOTAL-RAM basis
	// (SC_PHYS_PAGES) as a coarse backstop, so a swap PHP approves here is not then
	// second-guessed away on free-page tightness (which would force a needless restart).
	$usermem = get_single_sysctl('hw.usermem');
	if (!is_numeric($usermem) || (int) $usermem <= 0) {
		return FALSE;
	}

	$projected = 2 * $entries * $bytes_per_entry;
	return ((int) $usermem >= $projected + $headroom);
}


// PFBL-01: validate a feed header / list label before it is used to derive a file
// path or a manifest key. Returns the header UNCHANGED when it validates via
// pfb_filter(PFB_FILTER_WORD); returns FALSE on rejection, after logging the
// supplied $reference and a truncated (max 100 chars) htmlspecialchars()-encoded
// copy of the offending value (never the raw bytes). Pure apart from the log
// write. Callers MUST check the return strictly (=== FALSE) and SKIP the row when
// iterating a list, or ABORT when the header is a singular required parameter.
function pfb_sanitise_feed_header(string $header, string $reference = 'pfb_sanitise_feed_header'): string|false {
	if (empty(pfb_filter($header, PFB_FILTER_WORD, $reference))) {
		pfb_logger("\n{$reference}: Feed header failed validation [ " .
			substr(htmlspecialchars($header), 0, 100) . " ] *skipping*", 2);
		return FALSE;
	}
	return $header;
}


// ADR-31: Build a single per-feed manifest row for $pfb_py_feeds[], parameterised by $mode so
// DNSWL feeds can reuse the same structure as DNSBL. $mode = 'deny' omits the 'mode' key
// (byte-identical with pre-ADR-31 entries; Python treats absent as deny); $mode = 'permit' adds
// 'mode' => 'permit'. No file I/O, no exec, no validation side-effects — pure array
// construction; callers have already validated $header and resolved $provenance.
function pfb_feed_manifest_row(string $header, string $group, string $log_flag,
	string $provenance, string $mode = 'deny'): array
{
	$row = array(
		'header'     => $header,
		'group'      => $group,
		'log'        => $log_flag,
		'provenance' => $provenance,
	);
	// deny (or default absent) → omit the 'mode' key; permit → emit it.
	if ($mode !== 'deny') {
		$row['mode'] = $mode;
	}
	return $row;
}


// ADR-06: Build the shell->Python contract: the per-feed manifest ($pfb['unbound_py_sources'])
// plus a per-feed IP-stripped raw domain file that pfb_unbound.py's dnsbl_build_from_manifest
// consumes. raw is the bare-domain extraction of the parsed '.txt' NDJSON (IPs already routed
// elsewhere; #1083), with 'abp'-kind NDJSON rows' raw payload passed through verbatim so
// Python's per-line capture guard routes them to parse_abp() intact. $feeds rows:
// header/group/log/provenance ('user' Custom_List -> band 5, 'feed' download -> band 1).
// PFBL-01: RE-validates each header via pfb_sanitise_feed_header() (PFB_FILTER_WORD, not
// DOMAIN); a failing row is SKIPPED + logged before any file touch; pinned by
// tests/php/PfbFilterContractTest.php.
function pfb_unbound_py_generation_matches(string $dir, array $metadata): bool {
	$entries = @scandir($dir);
	if ($entries === FALSE) {
		return FALSE;
	}
	$actual = array_values(array_diff($entries, array('.', '..')));
	$expected = array();
	foreach ($metadata as $header => $meta) {
		$expected[] = "{$header}.raw";
	}
	sort($actual, SORT_STRING);
	sort($expected, SORT_STRING);
	if ($actual !== $expected) {
		return FALSE;
	}
	foreach ($metadata as $header => $meta) {
		$path = "{$dir}/{$header}.raw";
		if (is_link($path) || !is_file($path) || !is_readable($path) || filesize($path) !== $meta['bytes'] ||
		    @hash_file('xxh128', $path) !== $meta['hash']) {
			return FALSE;
		}
	}
	return TRUE;
}

function pfb_unbound_python_sources($feeds, array $publication_ops=array()) {
	$lock = pfb_unbound_py_publication_lock();
	if ($lock === FALSE) {
		$manifest_path = $GLOBALS['pfb']['unbound_py_sources'] ?? 'unknown path';
		$manifest_notice = "DNSBL manifest publication lock failed: {$manifest_path}";
		file_notice('pfBlockerNG DNSBL', $manifest_notice, 'pfBlockerNG',
			'/pfblockerng/pfblockerng_dnsbl.php', 2);
		return FALSE;
	}
	try {
		return pfb_unbound_python_sources_locked($feeds, $publication_ops);
	} finally {
		pfb_unbound_py_publication_unlock($lock);
	}
}

function pfb_unbound_python_sources_locked($feeds, array $publication_ops=array()) {
	global $pfb;

	if (!is_array($feeds)) {
		$feeds = array();
	}
	$top1m_enabled = (($pfb['dnsbl_top1m'] ?? PfbToggle::Off) === PfbToggle::On);
	$top1m_source = "{$pfb['dbdir']}/pfbalexawhitelist.txt";
	$top1m_target = $pfb['unbound_py_top1m'] ?? '/var/unbound/pfb_py_top1m.txt';
	if ($top1m_enabled && (is_link($top1m_source) || !is_file($top1m_source) || !is_readable($top1m_source))) {
		pfb_logger("\nTOP1M fixed-file source unavailable: {$top1m_source}", 2);
		return FALSE;
	}

	$raw_parent = dirname($pfb['unbound_py_rawdir']);
	$raw_base = basename($pfb['unbound_py_rawdir']);
	$stage_digest = hash('xxh128', uniqid('', TRUE) . ':' . getmypid());
	$stage_dir = "{$raw_parent}/{$raw_base}.stage.{$stage_digest}";
	$stage_mkdir = $publication_ops['stage_mkdir'] ?? static fn($dir, $mode) => @mkdir($dir, $mode);
	if (!$stage_mkdir($stage_dir, 0755)) {
		pfb_logger("\nDNSBL raw generation staging failed", 2);
		return FALSE;
	}
	$abort_generation = static function (string $reason) use ($stage_dir) {
		rmdir_recursive($stage_dir);
		pfb_logger("\nDNSBL raw generation failed: {$reason}", 2);
		file_notice('pfBlockerNG DNSBL', 'DNSBL raw generation publish failed', 'pfBlockerNG',
			'/pfblockerng/pfblockerng_dnsbl.php', 2);
		return FALSE;
	};

	$manifest_feeds = array();
	$raw_metadata = array();
	foreach ($feeds as $feed) {
		$header	= isset($feed['header']) ? $feed['header'] : '';
		$group	= isset($feed['group'])  ? $feed['group']  : '';
		$logf	= isset($feed['log'])    ? (string) $feed['log'] : '1';

		if ($header === '') {
			continue;
		}

		// PFBL-01: re-validate the header at this choke point, BEFORE it derives the
		// source/raw paths or any manifest key (skip the row + log on failure).
		if (pfb_sanitise_feed_header($header, 'pfb_unbound_python_sources') === FALSE) {
			continue;
		}

		$src	= "{$pfb['dnsdir']}/{$header}.txt";
		if (!file_exists($src)) {
			continue;
		}
		if (!is_file($src)) {
			return $abort_generation('source type');
		}

		$in_h = @fopen($src, 'r');
		if ($in_h === FALSE) {
			return $abort_generation('source open');
		}
		$rawpath = "{$stage_dir}/{$header}.raw";
		$raw_h = @fopen($rawpath, 'wb');
		if ($raw_h === FALSE) {
			@fclose($in_h);
			return $abort_generation('raw open');
		}
		$raw_hash = hash_init('xxh128');
		$raw_bytes = 0;
		$raw_ok = TRUE;
		while (($line = @fgets($in_h)) !== FALSE) {
			// #1083: an 'abp' row's raw payload (the download loop captured it
			// verbatim) passes straight through to the '.raw' -- Python's build()
			// routes it to parse_abp(). A 'domain' row extracts its bare domain,
			// already IP-free and cleaned/validated by the download loop. NULL
			// (undecodable, e.g. stale pre-flip residue) is silently skipped.
			$row = pfb_dnsbl_ndjson_parse_row($line);
			if ($row === NULL) {
				continue;
			}
			$raw_line = match ($row['kind']) {
				PfbDnsblRowKind::Domain => "{$row['domain']}\n",
				PfbDnsblRowKind::Abp    => "{$row['raw']}\n",
			};
			$written = @fwrite($raw_h, $raw_line);
			if ($written === FALSE || $written !== strlen($raw_line)) {
				$raw_ok = FALSE;
				break;
			}
			hash_update($raw_hash, $raw_line);
			$raw_bytes += $written;
		}
		$raw_ok = $raw_ok && feof($in_h);
		$raw_ok = @fclose($in_h) && $raw_ok;
		$raw_ok = $raw_ok && @fflush($raw_h) && @fsync($raw_h);
		$raw_ok = @fclose($raw_h) && $raw_ok;
		if (!$raw_ok) {
			return $abort_generation('raw write');
		}
		$raw_metadata[$header] = array('bytes' => $raw_bytes, 'hash' => hash_final($raw_hash));

		// Store the raw path RELATIVE to the manifest's directory. pfb_unbound.py
		// runs inside Unbound's chroot (/var/unbound), so an absolute HOST path
		// like /var/unbound/pfb_py_raw/<f>.raw resolves to
		// /var/unbound/var/unbound/pfb_py_raw/<f>.raw inside the chroot and is not
		// found (feeds silently fail to load -> nothing blocked). The Python build
		// joins a relative path against the manifest's dir (the chroot root), which
		// resolves correctly both chrooted and not.
		$manifest_feeds[] = array(
			'raw'		=> "{$header}.raw",
			'feed'		=> $header,
			'group'		=> $group,
			'provenance'	=> (isset($feed['provenance']) && $feed['provenance'] === 'user') ? 'user' : 'feed',
			'log_flag'	=> $logf
		);

		// ADR-31: carry the permit-mode flag into the manifest JSON so the Python
		// build (dnsbl_build_from_manifest -> build()) routes this feed's hosts into
		// whiteDB as band-2 allows. Deny/absent omits the key (byte-identical with
		// pre-ADR-31 entries; the Python side treats an absent 'mode' as deny).
		if (isset($feed['mode']) && $feed['mode'] === 'permit') {
			$manifest_feeds[count($manifest_feeds) - 1]['mode'] = 'permit';
		}
	}

	$generation_hash = hash_init('xxh128');
	ksort($raw_metadata, SORT_STRING);
	foreach ($raw_metadata as $header => $meta) {
		hash_update($generation_hash,
			strlen($header) . ":{$header}:{$meta['bytes']}:{$meta['hash']}\n");
	}
	$generation_digest = hash_final($generation_hash);
	$generation_base = "{$raw_base}.{$generation_digest}";
	$generation_dir = "{$raw_parent}/{$generation_base}";
	$generation_created = FALSE;
	if (file_exists($generation_dir) || is_link($generation_dir)) {
		if (!pfb_unbound_py_generation_matches($generation_dir, $raw_metadata)) {
			return $abort_generation('generation collision');
		}
		rmdir_recursive($stage_dir);
		if (file_exists($stage_dir)) {
			return $abort_generation('duplicate stage cleanup');
		}
	} else {
		$generation_rename = $publication_ops['generation_rename']
			?? static fn($from, $to) => @rename($from, $to);
		if (!$generation_rename($stage_dir, $generation_dir)) {
			return $abort_generation('generation publish');
		}
		$generation_created = TRUE;
	}
	$discard_unpublished_generation = static function () use (&$generation_created, $generation_dir): void {
		if (!$generation_created) {
			return;
		}
		if (!pfb_unbound_py_remove_raw_artifact($generation_dir)) {
			pfb_logger("\nDNSBL unpublished raw generation cleanup failed", 2);
		}
		$generation_created = FALSE;
	};
	foreach ($manifest_feeds as &$manifest_feed) {
		$manifest_feed['raw'] = "{$generation_base}/{$manifest_feed['raw']}";
	}
	unset($manifest_feed);

	// Synthetic whole-TLD blacklist feed (DNSBL_TLD): the Python build emits these
	// as whole-TLD ZONE entries from config.tld_wildcard_blacklist, so no raw file is needed.

	// TOP1M (Tranco/Cisco) popularity whitelist is a fixed sidecar. Publish it
	// before the manifest so a durable manifest always names a complete snapshot.
	$top1m_atomic_ops = isset($publication_ops['top1m_atomic']) && is_array($publication_ops['top1m_atomic'])
		? $publication_ops['top1m_atomic'] : array();
	$top1m_restore_fn = $top1m_atomic_ops['restore'] ?? static fn($from, $to) => @rename($from, $to);
	$top1m_backup = FALSE;
	$top1m_had_previous = file_exists($top1m_target) || is_link($top1m_target);
	$restore_top1m = static function () use (&$top1m_backup, $top1m_target, $top1m_had_previous, $top1m_restore_fn): void {
		if ($top1m_backup === FALSE) {
			return;
		}
		if ($top1m_had_previous && $top1m_backup !== FALSE) {
			$top1m_restore_fn($top1m_backup, $top1m_target);
		} elseif ($top1m_backup !== FALSE) {
			if (file_exists($top1m_target) || is_link($top1m_target)) {
				is_dir($top1m_target) && !is_link($top1m_target)
					? rmdir_recursive($top1m_target)
					: @unlink($top1m_target);
			}
			@unlink($top1m_backup);
		}
		$top1m_backup = FALSE;
	};
	if ($top1m_enabled) {
		$top1m_backup = @tempnam(dirname($top1m_target), '.pfbtop1m_prev_');
		if ($top1m_backup !== FALSE) {
			@unlink($top1m_backup);
		}
		$top1m_backup_ok = $top1m_backup !== FALSE &&
			(!$top1m_had_previous || @link($top1m_target, $top1m_backup) || @copy($top1m_target, $top1m_backup));
		if (!$top1m_backup_ok) {
			if ($top1m_backup !== FALSE) {
				@unlink($top1m_backup);
			}
			$discard_unpublished_generation();
			pfb_logger("\nTOP1M fixed-file staging failed: {$top1m_target}", 2);
			return FALSE;
		}
		if (!pfb_unbound_py_top1m_atomic_copy($top1m_source, $top1m_target, $top1m_atomic_ops)) {
			if ($top1m_backup !== FALSE) {
				@unlink($top1m_backup);
				$top1m_backup = FALSE;
			}
			$discard_unpublished_generation();
			pfb_logger("\nTOP1M fixed-file publication failed: {$top1m_target}", 2);
			return FALSE;
		}
	}

	// issue #1255: TLD-Wildcard toggle gates the WHOLE wildcard-blocking contribution --
	// tld_wildcard_blacklist/tld_wildcard_exclusion (user config, stay in the manifest) are
	// emptied when off, even if configured. The public-suffix oracle itself (tld_master) no
	// longer rides the manifest at all: it is a SHIPPED file (unbound_py_psl) gated by the same
	// toggle's ini flag (python_tld_wildcard), mirroring HSTS (unbound_py_hsts /
	// python_hsts) -- see pfb_unbound_python()'s ini emit and pfb_unbound.py's
	// _dnsbl_config_from_manifest().
	$tld_wildcard_blacklist = array();
	$tld_wildcard_exclusion = array();
	if (!empty($pfb['dnsbl_tld_wildcard'])) {
		$tld_wildcard_blacklist = pfb_text_area_decode($pfb['dnsblconfig']['tld_wildcard_blacklist'], TRUE, FALSE, TRUE) ?: array();
		$tld_wildcard_exclusion = pfb_text_area_decode($pfb['dnsblconfig']['tld_wildcard_exclusion'], TRUE, FALSE, TRUE) ?: array();
	}

	$manifest = array(
		'version'	=> 1,
		'config'	=> array(
			'tld_wildcard_blacklist'	=> array_values($tld_wildcard_blacklist),
			'tld_wildcard_exclusion'	=> array_values($tld_wildcard_exclusion),
			'user_whitelist'=> pfb_dnsbl_whitelist_lines(),
			// ADR-06 (#51): a FULL build CLEARS the temporary unlock set. A Force/Cron
			// update deletes the pfb_unlock store (pfb_update_unbound) right after this
			// manifest is written, so reading the live store here would bake unlocks
			// into the rebuilt manifest and they would survive the Force/Cron reload
			// (the manifest is not rewritten post-delete) -- breaking the documented
			// "re-locked on Cron/Force" semantic. Only pfb_unbound_python_sources_unlock()
			// (the incremental alerts dnsbl_remove path) repopulates user_unlock.
			'user_unlock'	=> array(),
			'top1m_enabled'	=> $top1m_enabled
		),
		'feeds'		=> $manifest_feeds
	);

	$json = json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
	if ($json !== FALSE) {
		// #1357: every raw is complete in an immutable content-addressed directory;
		// this manifest rename is the sole visibility commit for the complete set. The
		// sentinel flip that ACTS on it is driven by pfb_reload_unbound's data
		// fast path (so a full feed update advances the generation exactly once,
		// after every manifest+raw file is in place), not here.
		$manifest_atomic_ops = isset($publication_ops['manifest_atomic'])
			&& is_array($publication_ops['manifest_atomic']) ? $publication_ops['manifest_atomic'] : array();
		if (!pfb_unbound_py_atomic_write($pfb['unbound_py_sources'], $json, $manifest_atomic_ops)) {
			$restore_top1m();
			$discard_unpublished_generation();
			// ADR-65: a swallowed publish failure left Python running on a stale/absent
			// manifest with no operator-visible signal -- surface it like the existing
			// MaxMind/VIP credential notices (issue #331 pattern).
			$manifest_notice = "DNSBL manifest publish failed: {$pfb['unbound_py_sources']}";
			pfb_logger("\n{$manifest_notice}", 2);
			file_notice('pfBlockerNG DNSBL', $manifest_notice, 'pfBlockerNG', '/pfblockerng/pfblockerng_dnsbl.php', 2);
			return FALSE;
		}
		if ($top1m_enabled && $top1m_backup !== FALSE) {
			@unlink($top1m_backup);
			$top1m_backup = FALSE;
		}
	} else {
		$restore_top1m();
		$discard_unpublished_generation();
		pfb_logger("\nDNSBL manifest JSON encoding failed: " . json_last_error_msg(), 2);
		return FALSE;
	}

	return $manifest;
}


// ADR-06: patch a single scalar key of the manifest's config section in place
// (shared by the whitelist/unlock in-place patchers below), without a full
// feed re-enumeration. The query-time whiteDB is rebuilt from this on reload.
function pfb_unbound_python_sources_patch($key, $values, array $publication_ops=array()) {
	$lock_fn = $publication_ops['lock'] ?? static fn() => pfb_unbound_py_publication_lock(0.25);
	$lock = $lock_fn();
	if ($lock === FALSE) {
		pfb_logger("\nDNSBL scalar manifest patch skipped while publication was busy; retry the action or run a DNSBL update", 2);
		return FALSE;
	}
	try {
		return pfb_unbound_python_sources_patch_locked($key, $values);
	} finally {
		pfb_unbound_py_publication_unlock($lock);
	}
}

function pfb_unbound_python_sources_patch_locked($key, $values) {
	global $pfb;

	if (!file_exists($pfb['unbound_py_sources'])) {
		return FALSE;
	}

	$json = @file_get_contents($pfb['unbound_py_sources']);
	if ($json === FALSE) {
		return FALSE;
	}

	$manifest = json_decode($json, TRUE);
	if (!is_array($manifest)) {
		return FALSE;
	}

	if (!isset($manifest['config']) || !is_array($manifest['config'])) {
		$manifest['config'] = array();
	}
	$manifest['config'][$key] = $values;

	$json = json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
	if ($json !== FALSE) {
		// ADR-10: atomic publish (the sentinel flip is driven by the reload).
		return pfb_unbound_py_atomic_write($pfb['unbound_py_sources'], $json);
	}

	pfb_logger("\nDNSBL manifest JSON encoding failed: " . json_last_error_msg(), 2);
	return FALSE;
}


// ADR-06: Update only the manifest's config.user_whitelist in place (used by the
// alerts "add to whitelist" button, which changes the suppression config without a
// full feed re-enumeration). The query-time whiteDB is rebuilt from this on reload.
function pfb_unbound_python_sources_whitelist() {
	return pfb_unbound_python_sources_patch('user_whitelist', pfb_dnsbl_whitelist_lines());
}


// ADR-06 (#51): update ONLY the manifest's config.user_unlock in place, recomputed
// from the live temporary-unlock store (pfb_dnsbl_unlock_lines). Mirrors
// pfb_unbound_python_sources_whitelist(): the alerts Lock/Unlock icon toggles the
// pfb_unlock state without a full feed re-enumeration, so patch the manifest and let
// the query-time whiteDB rebuild from it on the next reload. The alerts handler's
// reload (pfb_reload_unbound) does NOT delete the store, so store and manifest stay in
// step; a full update/Force/Cron is the only thing that clears both.
function pfb_unbound_python_sources_unlock() {
	return pfb_unbound_python_sources_patch('user_unlock', pfb_dnsbl_unlock_lines());
}


// Build the Python INI from the current, gateway-loaded DNSBL settings.
function pfb_unbound_python_ini($mode, ?string $now = NULL): string {
	global $pfb;

	$python_enable = ($mode == 'enabled') ? 'on' : 'off';
	$python_reply = ($pfb['dnsbl_py_reply'] === PfbToggle::On) ? 'on' : 'off';
	$python_blocking = 'on';
	$python_hsts = ($pfb['dnsbl_hsts'] === PfbToggle::On) ? 'on' : 'off';
	$dnsbl_tld_wildcard = $pfb['dnsbl_tld_wildcard'];
	$python_tld_wildcard = !empty($dnsbl_tld_wildcard) ? 'on' : 'off';
	$psl_include_private = ($pfb['dnsbl_psl_include_private'] === PfbToggle::On) ? 'on' : 'off';
	$psl_allow_private = ($pfb['dnsbl_psl_allow_private'] === PfbToggle::On) ? 'on' : 'off';
	$psl_feed_private_policy = $pfb['dnsbl_psl_feed_private_policy']->toStored();
	$psl_feed_icann_policy = $pfb['dnsbl_psl_feed_icann_policy']->toStored();

	$idn_mode = $pfb['dnsbl_idn']->toStored();
	$python_idn = ($pfb['dnsbl_idn'] === PfbIdnMode::All) ? 'on' : 'off';
	$python_idn_block_malicious = (pfb_cfg_toggle_read($pfb['dnsbl_idn_block_malicious']) === PfbToggle::On) ? 'on' : 'off';
	$python_idn_escalate_suspicious = (pfb_cfg_toggle_read($pfb['dnsbl_idn_escalate_suspicious']) === PfbToggle::On) ? 'on' : 'off';
	$python_cname = ($pfb['dnsbl_cname'] === PfbToggle::On) ? 'on' : 'off';

	$dnsbl_control = $pfb['dnsbl_control'];
	$dnsbl_control_legacy = $pfb['dnsbl_control_legacy'];
	$python_control = ($dnsbl_control === PfbToggle::On) ? 'on' : 'off';
	$python_control_legacy = ($dnsbl_control === PfbToggle::On && $dnsbl_control_legacy === PfbToggle::On) ? 'on' : 'off';
	$python_noaaaa = ($pfb['dnsbl_noaaaa'] === PfbToggle::On) ? 'on' : 'off';

	$tld_allow = 'off';
	$tld_allow_list = '';
	if ($pfb['dnsbl_tld_allow'] === PfbToggle::On) {
		foreach (['tld_allow_gtld', 'tld_allow_cctld', 'tld_allow_itld', 'tld_allow_bgtld'] as $field) {
			if (!empty($pfb['dnsblconfig'][$field])) {
				$tld_allow = 'on';
				$tld_allow_list .= ',' . $pfb['dnsblconfig'][$field];
			}
		}
		$tld_allow_list = ltrim($tld_allow_list, ',');
	}

	$python_nolog = ($pfb['dnsbl_py_nolog'] === PfbToggle::On) ? 'on' : 'off';
	$regex_cap = ($pfb['dnsbl_regex_cap'] === PfbToggle::On) ? 'on' : 'off';
	$decisiondb_max = $pfb['dnsbl_decisiondb_max'] ?? '10000';
	$forwarding = (config_get_path('unbound/forwarding') == 'on') ? 'on' : 'off';
	$now ??= date('Y-m-d H:i:s', time());

	$pfb_py_conf = <<<EOF
; pfBlockerNG DNSBL Unbound python configuration file
; pfb_unbound.ini [ File created: {$now} ]
[MAIN]
dnsbl_ipv4	= {$pfb['dnsbl_vip4']}
dnsbl_ipv6	= {$pfb['dnsbl_vip6']}
python_enable	= {$python_enable}
python_reply	= {$python_reply}
python_blocking	= {$python_blocking}
python_hsts	= {$python_hsts}
python_tld_wildcard	= {$python_tld_wildcard}
psl_include_private	= {$psl_include_private}
psl_allow_private	= {$psl_allow_private}
psl_feed_private_policy	= {$psl_feed_private_policy}
psl_feed_icann_policy	= {$psl_feed_icann_policy}
python_idn	= {$python_idn}
idn_mode	= {$idn_mode}
python_idn_block_malicious	= {$python_idn_block_malicious}
python_idn_escalate_suspicious	= {$python_idn_escalate_suspicious}
python_tld_seg	= 1
decisiondb_max	= {$decisiondb_max}
tld_allow	= {$tld_allow}
tld_allow_list	= {$tld_allow_list}
python_nolog	= {$python_nolog}
python_cname	= {$python_cname}
python_control	= {$python_control}
python_control_legacy	= {$python_control_legacy}
regex_cap	= {$regex_cap}
forwarding	= {$forwarding}

EOF;
	if ($pfb['dnsbl_regex'] === PfbToggle::On && isset($pfb['dnsbl_regex_list']) && !empty($pfb['dnsbl_regex_list'])) {
		$pfb_py_conf .= "regex_list = {$pfb['dnsbl_regex_list']}\n";
	}

	if ($pfb['dnsbl_noaaaa'] === PfbToggle::On && isset($pfb['dnsbl_noaaaa_list']) && !empty($pfb['dnsbl_noaaaa_list'])) {
		$noaaaa = '';
		$noaaaa_list = pfb_text_area_decode($pfb['dnsbl_noaaaa_list'], TRUE, TRUE, TRUE);
		if (!empty($noaaaa_list)) {
			foreach ($noaaaa_list as $key => $list) {
				if (str_starts_with($list[0], '.')) {
					$list[0] = pfb_strip_wildcard_marker($list[0], 'pfb_unbound_python noAAAA');
					if (pfb_is_blank($list[0])) {
						continue;
					}
					$noaaaa .= "{$key} = {$list[0]},1\n";
				} else {
					$noaaaa .= "{$key} = {$list[0]},0\n";
				}
			}
			if (!pfb_is_blank($noaaaa)) {
				$pfb_py_conf .= <<<EOF

[noAAAA]
{$noaaaa}
EOF;
			}
		}
	}

	if ($pfb['dnsbl_gp'] === PfbToggle::On && isset($pfb['dnsbl_gp_bypass_list']) && !empty($pfb['dnsbl_gp_bypass_list'])) {
		$gp_bypass = '';
		$gp_bypass_list = pfb_text_area_decode($pfb['dnsbl_gp_bypass_list'], TRUE, TRUE, FALSE);
		if (!empty($gp_bypass_list)) {
			foreach ($gp_bypass_list as $key => $list) {
				$gp_bypass .= "{$key} = {$list[0]}\n";
			}
			$pfb_py_conf .= <<<EOF

[GP_Bypass_List]
{$gp_bypass}
EOF;
		}
	}

	return $pfb_py_conf;
}


// ADR-06 (#51): map a per-alert DNSBL Lock/Unlock action (dnsbl_remove POST value) to its
// temporary-unlock STORE operation + status message. The four icon actions collapse onto two
// pfb_unlock modes: unlock/relock ADD the domain ('unlock'), lock/reunlock REMOVE it ('lock').
// An UNKNOWN action returns an empty mode so the handler does NOTHING — a crafted POST cannot
// mutate the store. 'msg' carries a single %s for the domain (sprintf in the handler); empty
// for an unknown action so the redirect shows no status.
function pfb_dnsbl_unlock_action($action) {
	switch ($action) {
		case 'unlock':
			return array('mode' => 'unlock', 'msg' => 'The Domain [ %s ] has been temporarily Unlocked from DNSBL!');
		case 'lock':
			return array('mode' => 'lock',   'msg' => 'The Domain [ %s ] has been Locked into DNSBL!');
		case 'relock':
			return array('mode' => 'unlock', 'msg' => 'The Domain [ %s ] has been temporarily Re-Locked into DNSBL!');
		case 'reunlock':
			return array('mode' => 'lock',   'msg' => 'The Domain [ %s ] has been Unlocked from DNSBL!');
		default:
			return array('mode' => '', 'msg' => '');
	}
}


// Unbound python configuration file
function pfb_unbound_python($mode) {
	global $pfb;
	pfb_global();

	// Reload config.xml to get any recent changes
	config_read_file(FALSE, TRUE);

	$pfbpython = FALSE;

	// Ensure log file permissions are set as 'unbound:unbound' (unified.log excluded:
	// the host daemon is now its sole writer, as root — ADR-38 Amendment 1).
	foreach (array('dnsbl.log', 'dns_reply.log') as $logfile) {

		if (!file_exists("{$pfb['logdir']}/{$logfile}")) {
			touch("{$pfb['logdir']}/{$logfile}");
		}

		@chown("{$pfb['logdir']}/{$logfile}", 'unbound');
		@chgrp("{$pfb['logdir']}/{$logfile}", 'unbound');
	}

	// Add python settings to DNS Resolver configuration
	if ($mode == 'enabled') {
		if (!config_path_enabled('unbound', 'python') ||
		    config_get_path('unbound/python_script') != 'pfb_unbound') {

			config_set_path('unbound/python', '');
			config_set_path('unbound/python_order', 'pre_validator');
			config_set_path('unbound/python_script', 'pfb_unbound');

			$pfbpython = TRUE;
			$log = 'Added DNSBL Unbound python integration settings';
			pfb_logger("\n{$log}", 1);
			write_config("pfBlockerNG: {$log}");
		}

		// If DNSBL python blocking mode enabled

		// Create DNSBL Whitelist
		$dnsbl_whitelist = pfb_unbound_python_whitelist();

		// Compare previous DNSBL Whitelist to new Whitelist
		$pfb_py_whitelist_ex = @file_get_contents($pfb['unbound_py_wh']);
		if ($dnsbl_whitelist !== $pfb_py_whitelist_ex) {
			$pfbpython = TRUE;
			@file_put_contents($pfb['unbound_py_wh'], $dnsbl_whitelist, LOCK_EX);

			// ADR-06: keep the manifest's config.user_whitelist (the source for the
			// query-time whiteDB) in sync with a settings-textarea whitelist edit, so
			// the change applies even when no feed update rewrites the full manifest.
			pfb_unbound_python_sources_whitelist();
		}

		$now = date('Y-m-d H:i:s', time());
		$pfb_py_conf = pfb_unbound_python_ini($mode, $now);

		// Compare previous ini file to new ini (bypass file timestamp string)
		$pfb_py_conf_ex		= @file_get_contents($pfb['unbound_py_conf']);
		$pfb_py_conf_ex2	= preg_replace("/File created:.* ]/", "File created: {$now} ]", $pfb_py_conf_ex);

		if ($pfb_py_conf !== $pfb_py_conf_ex2) {
			$pfbpython = TRUE;
			@file_put_contents($pfb['unbound_py_conf'], $pfb_py_conf, LOCK_EX);
		}
	}

	else {
		$mode = 'disabled';

		// Remove python settings from DNS Resolver configuration
		if (config_path_enabled('unbound', 'python') && config_get_path('unbound/python_script') == 'pfb_unbound') {
			config_del_path('unbound/python');
			config_set_path('unbound/python_order', '');
			config_set_path('unbound/python_script', '');

			$log = 'Removing DNSBL Unbound python integration settings';
			pfb_logger("\n{$log}", 1);
			write_config("pfBlockerNG: {$log}");
		}
	}

	// Mount lib and bin folders
	$base_py = '/usr/local';

	$log = '';
	foreach (array('/bin', '/lib') as $dir) {
		$validate = exec("/sbin/mount | {$pfb['grep']} " . escapeshellarg("{$pfb['dnsbldir']}{$base_py}{$dir}") . " 2>&1");

		if ($mode == 'enabled' && empty($validate)) {
			if (!is_dir("{$pfb['dnsbldir']}{$base_py}{$dir}")) {
				$log .= "\n  Creating: {$pfb['dnsbldir']}{$base_py}{$dir}";
				safe_mkdir("{$pfb['dnsbldir']}{$base_py}{$dir}");
			}
			$pfbpython = TRUE;
			$log .= "\n  Mounting: /usr/local{$dir}";
			exec("/sbin/mount_nullfs -o ro " . escapeshellarg("/usr/local{$dir}") . ' '
				. escapeshellarg("{$pfb['dnsbldir']}{$base_py}{$dir}") . " 2>&1", $output, $retval);
			if ($retval != 0) {
				$log .= "\n  Failed to mount [ /usr/local{$dir} ] to [ {$pfb['dnsbldir']}{$base_py}{$dir} ]!";
			}
		}
	}

	if (!empty($log)) {
		pfb_logger("\nAdding DNSBL Unbound python mounts:{$log}\n", 1);
	}

	// Set flag to unmount python folders after the next reboot is completed to avoid crashing Unbound
	if ($mode == 'disabled') {
		$pfb['dnsbl_python_unmount'] = TRUE;
	}
	return $pfbpython;
}


// Unbound python unmount
function pfb_unbound_python_unmount() {
	global $pfb;

	// Unmount lib and bin folders
	$base_py = '/usr/local';

	$log = '';
	foreach (array('/bin', '/lib') as $dir) {
		$validate = exec("/sbin/mount | {$pfb['grep']} " . escapeshellarg("{$pfb['dnsbldir']}{$base_py}{$dir}") . " 2>&1");
		if (!empty($validate)) {
			$log .= "\n  Unmounting: /usr/local{$dir}";
			exec("/sbin/umount -t nullfs " . escapeshellarg("{$pfb['dnsbldir']}{$base_py}{$dir}") . " 2>&1", $output, $retval);
			if ($retval != 0) {
				$log .= "\n  Failed to unmount [ {$pfb['dnsbldir']}{$base_py}{$dir} ]!";
			}
		}

		foreach (array( "/usr/local{$dir}", '/usr/local', '/usr') as $folder) {
			if (is_dir("{$pfb['dnsbldir']}{$folder}")) {
				$log .= "\n  Removing: {$pfb['dnsbldir']}{$folder}";
				@rmdir("{$pfb['dnsbldir']}{$folder}");
			}

			// Delete remaining subfolders on next loop
			if ($dir == '/bin') {
				break;
			}
		}
	}

	if (!empty($log)) {
		pfb_logger("\nRemoving DNSBL Unbound python mounts:{$log}\n", 1);
	}
}


// ADR-65: finalize TLD-mode widget stats from counts already collected by the feed loop.
function pfb_dnsbl_tld_stats_finalize(array $group_counts): void {
	global $pfb;

	if (!$pfb['domain_update']) {
		return;
	}

	// Collect TLD Blacklist(s). If configured the whole TLD will be blocked
	$tld_blacklist = pfb_text_area_decode($pfb['dnsblconfig']['tld_wildcard_blacklist'], TRUE, FALSE, TRUE);
	if (!empty($tld_blacklist)) {
		$tld_blacklist = array_flip($tld_blacklist);
	}

	// Process TLD Blacklist(s). If configured the whole TLD will be blocked
	if (!empty($tld_blacklist)) {

		$tld_cnt	= 0;

		foreach ($tld_blacklist as $tld => $key) {

			unset($tld_blacklist[$tld]);			// Remove old entry
			$tld = trim($tld, '.');				// Remove any leading/trailing dots
			if ($tld === '') {
				continue;
			}
			$tld_blacklist[$tld] = '';			// Add new TLD entry

			$tld_cnt++;
			continue;

		}

		if ($tld_cnt > 0) {
			$group_counts['DNSBL_TLD'] = $tld_cnt;
			$pfb['alias_dnsbl_all'][] = 'DNSBL_TLD';
		}
	}

	// Update DNSBL widget stats
	if (!empty($group_counts)) {
		foreach ($group_counts as $alias => $alias_cnt) {
			dnsbl_stats_update('update', $alias, $alias_cnt);
		}
	}

	// Save DNSBL Alias statistics
	dnsbl_save_stats();
}

// The daemon-start command and stop/start budgets are named so a harness can override
// them before this file loads (issue #2613: the unit suite would otherwise start a real
// resolver or pay the appliance waits).
if (!defined('PFB_UNBOUND_START_CMD')) {
	define('PFB_UNBOUND_START_CMD', '/usr/local/sbin/unbound -c /var/unbound/unbound.conf 2>&1');
}
if (!defined('PFB_UNBOUND_STOP_WAIT')) {
	define('PFB_UNBOUND_STOP_WAIT', 30);
}
if (!defined('PFB_UNBOUND_KILL_WAIT')) {
	define('PFB_UNBOUND_KILL_WAIT', 5);
}
// issue #3094: callers treat any non-zero retval as a bad unbound.conf. A stop that
// could not be completed is not that, so it gets its own code to branch on.
if (!defined('PFB_UNBOUND_STOP_FAILED')) {
	define('PFB_UNBOUND_STOP_FAILED', -2);
}
if (!defined('PFB_UNBOUND_START_WAIT')) {
	define('PFB_UNBOUND_START_WAIT', 30);
}
if (!defined('PFB_UNBOUND_START_SETUP_WAIT')) {
	define('PFB_UNBOUND_START_SETUP_WAIT', 5);
}

// Function to Start Unbound
function pfb_stop_start_unbound($type) {
	global $g, $pfb;

	$final = array();
	if (file_exists("{$g['varrun_path']}/unbound.pid")) {
		pfb_logger("\nStopping Unbound Resolver", 1);
		sigkillbypid("{$g['varrun_path']}/unbound.pid", 'TERM');
	}

	// If unbound is still running, wait up to PFB_UNBOUND_STOP_WAIT seconds for it to terminate.
	for ($i=1; $i <= PFB_UNBOUND_STOP_WAIT; $i++) {
		if (is_process_running('unbound')) {
			pfb_logger('.', 1);
			sleep(1);
		} else {
			pfb_logger("\nUnbound stopped in {$i} sec.", 1);
			break;
		}
	}

	// issue #3055: the bounded wait above can expire with Unbound still up (a large DNSBL
	// keeps it inside pythonmod init); starting anyway double-binds :53.
	if (is_process_running('unbound')) {
		pfb_logger("\nUnbound did not stop in " . PFB_UNBOUND_STOP_WAIT .
			" sec; escalating to KILL", 2);
		sigkillbyname('unbound', 'KILL');
		for ($i=1; $i <= PFB_UNBOUND_KILL_WAIT; $i++) {
			if (!is_process_running('unbound')) {
				pfb_logger("\nUnbound killed after {$i} sec.", 2);
				break;
			}
			sleep(1);
		}
		// ponytail: process-liveness only. 'bind' is really about :53 and a socket can
		// outlive the pid -- add a `sockstat -46l` check here if the double-bind is ever
		// seen with no surviving unbound process.
		if (is_process_running('unbound')) {
			$final['result'] = array('Unbound could not be stopped; Resolver not restarted');
			$final['retval'] = PFB_UNBOUND_STOP_FAILED;
			pfb_logger("\nUnbound still running after TERM and KILL; not starting a " .
				"second instance. Resolver NOT restarted", 2);
			return $final;
		}
	}

	// Add/Remove additional python mounts
	if (file_exists('/var/unbound/pfb_unbound_include.inc')) {
		$g['pfblockerng_include_verbose'] = TRUE;
		pfb_logger("\nAdditional mounts{$type}:", 1);
		require_once('/var/unbound/pfb_unbound_include.inc');
		unset($g['pfblockerng_include_verbose']);
	}

	// Remove Unbound python mounts
	if ($pfb['dnsbl_python_unmount']) {
		pfb_unbound_python_unmount();
	}

	pfb_logger("\nStarting Unbound Resolver", 1);
	$outfile = @tempnam(sys_get_temp_dir(), 'pfbus');
	if ($outfile === FALSE) {
		$final['result'] = array('could not stage Unbound start output');
		$final['retval'] = -1;
		pfb_logger("\nUnbound Resolver start could not stage output; not run", 2);
		return $final;
	}

	$ready = "{$outfile}.ready";
	$release = "{$outfile}.release";
	$command_started = "{$outfile}.started";
	$done = "{$outfile}.done";
	$proc = NULL;
	$pid = 0;
	$group_ready = FALSE;
	$retval = NULL;
	$failure = '';
	$expired = FALSE;
	$start_ack_deadline = NULL;
	$deadline = NULL;

	// A successful Unbound daemon creates its own session and leaves this group.
	// Any ordinary helper stays with the launcher, so expiry can reap the whole tree.
	$stop_group = static function (&$proc, int $pid, bool $group_ready): void {
		if (!is_resource($proc) || $pid <= 0) {
			return;
		}
		if ($group_ready) {
			@posix_kill(-$pid, 15);
		} else {
			@proc_terminate($proc, 15);
		}

		$grace_deadline = hrtime(TRUE) + (PFB_HOOK_KILL_GRACE * 1000000000);
		while (is_resource($proc) && hrtime(TRUE) < $grace_deadline) {
			$status = @proc_get_status($proc);
			if (!is_array($status) || !$status['running']) {
				@proc_close($proc);
				$proc = NULL;
				break;
			}
			usleep(10000);
		}
		if (is_resource($proc)) {
			if ($group_ready) {
				@posix_kill(-$pid, 9);
			}
			@proc_terminate($proc, 9);
			@proc_close($proc);
			$proc = NULL;
			return;
		}

		// Once the group leader is reaped, a still-live group is made solely of
		// descendants; wait out their TERM grace, then kill any that ignored it.
		if (!$group_ready || !@posix_kill(-$pid, 0)) {
			return;
		}
		while (hrtime(TRUE) < $grace_deadline) {
			if (!@posix_kill(-$pid, 0)) {
				return;
			}
			usleep(10000);
		}
		@posix_kill(-$pid, 9);
	};

	try {
		foreach (array('proc_open', 'proc_get_status', 'posix_setpgid', 'posix_getpgid', 'posix_kill') as $required) {
			if (!function_exists($required)) {
				throw new RuntimeException("{$required}() unavailable; Unbound start not run");
			}
		}

		// The child establishes its own process group, publishes readiness, then waits
		// for the parent to verify that group before executing the configured command.
		$launcher_code =
			'if (!posix_setpgid(0, 0)) { exit(126); } ' .
			'$pid = getmypid(); putenv("PFB_UNBOUND_START_PGID={$pid}"); ' .
			'$ready_tmp = $argv[1] . ".new"; ' .
			'if (@file_put_contents($ready_tmp, (string) $pid) === FALSE || ' .
			'!@rename($ready_tmp, $argv[1])) { exit(126); } ' .
			'$barrier_deadline = hrtime(TRUE) + ((int) $argv[4] * 1000000000); ' .
			'while (!file_exists($argv[2])) { ' .
			'if (hrtime(TRUE) >= $barrier_deadline) { exit(125); } usleep(1000); } ' .
			'$started_tmp = $argv[5] . ".new"; ' .
			'if (@file_put_contents($started_tmp, "1") === FALSE || ' .
			'!@rename($started_tmp, $argv[5])) { exit(126); } ' .
			'passthru($argv[3], $status); ' .
			'$done_tmp = $argv[6] . ".new"; ' .
			'if (@file_put_contents($done_tmp, (string) $status) === FALSE || ' .
			'!@rename($done_tmp, $argv[6])) { exit(126); } ' .
			'$linger_deadline = hrtime(TRUE) + ((int) $argv[4] * 1000000000); ' .
			'while (hrtime(TRUE) < $linger_deadline) { usleep(10000); } exit($status);';
		$descriptors = array(
			0 => array('file', '/dev/null', 'r'),
			1 => array('file', $outfile, 'a'),
			2 => array('file', $outfile, 'a'),
		);
		$pipes = array();
		$php_cli = (string) ($pfb['php'] ?? (PHP_BINDIR . '/php'));
		$setup_deadline = hrtime(TRUE) + (PFB_UNBOUND_START_SETUP_WAIT * 1000000000);
		$proc = @proc_open(array(
			$php_cli,
			'-r',
			$launcher_code,
			'--',
			$ready,
			$release,
			PFB_UNBOUND_START_CMD,
			(string) (PFB_UNBOUND_START_SETUP_WAIT + PFB_HOOK_KILL_GRACE),
			$command_started,
			$done,
		), $descriptors, $pipes);
		if (!is_resource($proc)) {
			throw new RuntimeException('could not launch supervised Unbound start');
		}

		$status = proc_get_status($proc);
		$pid = (int) $status['pid'];
		while (!file_exists($ready)) {
			$status = proc_get_status($proc);
			if (!$status['running']) {
				$retval = (int) $status['exitcode'];
				break;
			}
			if (hrtime(TRUE) >= $setup_deadline) {
				$failure = 'Unbound start process-group setup TIMED OUT after ' .
					PFB_UNBOUND_START_SETUP_WAIT . 's; not run';
				break;
			}
			usleep(1000);
		}

		if ($retval === NULL && $failure === '' && file_exists($ready)) {
			$published_pid = (int) trim((string) @file_get_contents($ready));
			$group_ready = @posix_getpgid($pid) === $pid;
			if ($published_pid !== $pid || !$group_ready) {
				$failure = 'Unbound start process-group barrier verification failed';
			} elseif (!@touch($release)) {
				$failure = 'Unbound start process-group barrier release failed';
			} else {
				$start_ack_deadline = hrtime(TRUE) + (PFB_UNBOUND_START_SETUP_WAIT * 1000000000);
			}
		}

		while ($retval === NULL && $failure === '' && !file_exists($command_started)) {
			if ($start_ack_deadline === NULL) {
				$failure = 'Unbound command-start acknowledgement deadline not armed';
				break;
			}
			$status = proc_get_status($proc);
			if (!$status['running']) {
				$retval = (int) $status['exitcode'];
				break;
			}
			if (hrtime(TRUE) >= $start_ack_deadline) {
				$failure = 'Unbound command-start acknowledgement TIMED OUT after ' .
					PFB_UNBOUND_START_SETUP_WAIT . 's; not run';
				break;
			}
			usleep(1000);
		}
		if ($retval === NULL && $failure === '' && file_exists($command_started)) {
			$deadline = hrtime(TRUE) + (PFB_UNBOUND_START_WAIT * 1000000000);
		}

		while ($retval === NULL && !$expired && $failure === '' && !file_exists($done)) {
			if ($deadline === NULL) {
				$failure = 'Unbound start deadline not armed';
				break;
			}
			$status = proc_get_status($proc);
			if (!$status['running']) {
				$retval = (int) $status['exitcode'];
				break;
			}
			if (hrtime(TRUE) >= $deadline) {
				$expired = TRUE;
				break;
			}
			usleep(10000);
		}
		if ($retval === NULL && !$expired && $failure === '' && file_exists($done)) {
			$done_status = trim((string) @file_get_contents($done));
			if (preg_match('/^[0-9]+$/D', $done_status) !== 1) {
				$failure = 'Unbound start completion status invalid';
			} else {
				$retval = (int) $done_status;
			}
		}

		if ($expired) {
			$group_ready = $group_ready || @posix_getpgid($pid) === $pid;
			$stop_group($proc, $pid, $group_ready);
			$retval = 124;
		} elseif ($failure !== '') {
			$group_ready = $group_ready || @posix_getpgid($pid) === $pid;
			$stop_group($proc, $pid, $group_ready);
			$retval = -1;
		} elseif ($group_ready) {
			// Reap the supervisor and any completed command's non-daemon helpers.
			$stop_group($proc, $pid, TRUE);
		} elseif (is_resource($proc)) {
			@proc_close($proc);
			$proc = NULL;
		}
	} catch (Throwable $error) {
		$failure = $error->getMessage();
		$retval = -1;
	} finally {
		if (is_resource($proc)) {
			$group_ready = $group_ready || ($pid > 0 && @posix_getpgid($pid) === $pid);
			$stop_group($proc, $pid, $group_ready);
		}
		$raw = (string) @file_get_contents($outfile);
		@unlink("{$done}.new");
		@unlink($done);
		@unlink($release);
		@unlink("{$command_started}.new");
		@unlink($command_started);
		@unlink("{$ready}.new");
		@unlink($ready);
		@unlink($outfile);
	}

	if ($failure !== '') {
		$raw .= ($raw !== '' && !str_ends_with($raw, "\n") ? "\n" : '') . "{$failure}\n";
		pfb_logger("\n{$failure}", 2);
	}
	$final['result'] = ($raw === '') ? array() : explode("\n", $raw);
	if (end($final['result']) === '') {
		array_pop($final['result']);
	}
	$final['retval'] = (int) ($retval ?? -1);

	if ($final['retval'] === 124) {
		pfb_logger("\nUnbound Resolver start TIMED OUT after " . PFB_UNBOUND_START_WAIT .
			"s and was killed", 2);
	}
	return $final;
}


// ADR-10: is the DNSBL Unbound python integration the LIVE resolver mode? The
// zero-downtime swap only applies when the in-memory matcher (pfb_unbound.py) is the
// active blocklist source -- i.e. the resolver config has the python module wired in.
// Read from config.xml (the source of truth), not a generated file.
function pfb_unbound_py_mode_active() {
	return (config_path_enabled('unbound', 'python') &&
		config_get_path('unbound/python_script') == 'pfb_unbound');
}


// Targeted C-cache flush for an exact Alerts allow->block transition. block->allow needs NO
// flush (decisionDB.clear() suffices); the caller supplies domains only after reload returns.
// Each name is VALIDATED as a domain (issue #153) before interpolation, dropped otherwise
// — defence in depth atop
// escapeshellarg(). Pure; coalesced into ONE chroot session, de-duped per name + 'www.' sibling.
function pfb_unbound_py_ccache_flush_cmds($names, $chroot_cmd) {
	$cmds = array();
	if (!is_array($names) || empty($names)) {
		return $cmds;
	}

	// Flush each name + its 'www.' sibling so the prior resolved A/AAAA cannot keep serving.
	$seen = array();
	foreach ($names as $name) {
		// Drop anything that is not a valid domain BEFORE it can reach the command.
		$name = pfb_filter(trim((string) $name), PFB_FILTER_DOMAIN, 'pfb_unbound_py_ccache_flush_cmds');
		if (empty($name)) {
			continue;
		}
		foreach (array($name, "www.{$name}") as $variant) {
			if (isset($seen[$variant])) {
				continue;
			}
			$seen[$variant] = TRUE;
			$cmds[] = "{$chroot_cmd} flush " . escapeshellarg($variant) . ' 2>&1';
		}
	}

	return $cmds;
}

function pfb_unbound_py_ccache_flush($names) {
	global $pfb;

	$cmds = pfb_unbound_py_ccache_flush_cmds($names, $pfb['chroot_cmd']);
	if (empty($cmds)) {
		return;
	}

	// Alerts callers invoke this after the applied-generation reload returns.
	foreach ($cmds as $cmd) {
		exec($cmd);
	}
}


// Read a reload/applied marker's first-line generation with the IDENTICAL parsing
// convention as pfb_unbound_py_flip_sentinel()/_wait_marker() (first line, trim,
// ctype_digit) -- an absent/empty/non-integer file reads as 0, the shared "never
// flipped yet" baseline pfb_dnsbl_converged() relies on for its 0 == 0 case.
function pfb_unbound_py_marker_generation(string $path): int {
	if (!file_exists($path)) {
		return 0;
	}
	$raw = @file_get_contents($path);
	if ($raw === FALSE) {
		return 0;
	}
	$first = strtok($raw, "\n");
	if ($first === FALSE) {
		return 0;
	}
	$first = trim($first);
	if ($first === '' || !ctype_digit($first)) {
		return 0;
	}
	return (int) $first;
}

// ADR-65: the DNSBL health check re-keyed onto the manifest boundary -- TRUE iff the
// per-feed manifest is absent, or the reload/applied marker generations disagree (a
// stuck zero-downtime apply). Presence-only: manifest content validity is the ADR-61
// parse ledger's job. Pure read, no writes.
function pfb_dnsbl_manifest_missing(array $pfb): bool {
	if (!file_exists($pfb['unbound_py_sources'])) {
		return TRUE;
	}
	$sentinel = pfb_unbound_py_marker_generation("{$pfb['dnsbldir']}/pfb_py_reload");
	$applied  = pfb_unbound_py_marker_generation("{$pfb['dnsbldir']}/pfb_py_reload.applied");
	return $sentinel !== $applied;
}

// ADR-61: is DNSBL's live matcher state actually caught up with what it was told to
// become? TRUE iff the sentinel/applied generations agree (or neither has ever been
// written), Unbound is running, and unbound.conf still wires pfb_unbound.py. Pure
// read -- no writes, no waiting/polling. Reused by pfb_reload_unbound()'s own
// apply-stage writer/clearer and by the tick reconciliation step.
function pfb_dnsbl_converged(): bool {
	global $pfb;

	$sentinel = pfb_unbound_py_marker_generation("{$pfb['dnsbldir']}/pfb_py_reload");
	$applied  = pfb_unbound_py_marker_generation("{$pfb['dnsbldir']}/pfb_py_reload.applied");
	if ($sentinel !== $applied) {
		return FALSE;
	}

	if (!is_process_running('unbound')) {
		return FALSE;
	}

	// Mirrors the widget's $unbound_validate check (pfblockerng.widget.php) verbatim.
	$unbound_conf = "{$pfb['dnsbldir']}/unbound.conf";
	if (!file_exists($unbound_conf)) {
		return FALSE;
	}
	// @-suppressed: a TOCTOU race (deleted/unreadable between the check above and here)
	// returns FALSE, not a string -- strpos(FALSE, ...) is a PHP 8+ TypeError otherwise.
	$conf_contents = @file_get_contents($unbound_conf);
	return $conf_contents !== FALSE && strpos($conf_contents, 'pfb_unbound.py') !== FALSE;
}

// ADR-61: the DNSBL apply-stage writer/clearer decision, shared by every point in
// pfb_reload_unbound() where convergence might settle (the zero-downtime swap's own
// success return, and the shared restart path's completion). Kept separate from
// pfb_dnsbl_converged() so it stays directly unit-testable.
function pfb_dnsbl_apply_ledger_update(): bool {
	global $pfb;

	$converged = pfb_dnsbl_converged();
	if ($converged) {
		pfb_sync_status_close('dnsbl', 'dnsbl', 'apply', $pfb['dbdir']);
	} else {
		pfb_sync_status_open('dnsbl', 'dnsbl', 'apply',
			'DNSBL apply not converged -- Unbound not fully live with pfb_unbound.py; see error.log',
			$pfb['dbdir']);
	}
	return $converged;
}

// ADR-61: tick-driven reconciliation for a stuck (dnsbl,dnsbl,apply) ledger entry.
// A full Unbound restart (pfb_stop_start_unbound(): a real ~30s stop-wait plus an
// actual daemon restart) is deliberately out of scope for a per-tick retry -- only
// re-publishes the reload sentinel (one atomic file write, no wait_applied poll,
// no restart), and only when a live python-mode watcher could actually consume
// it; otherwise nothing safe/cheap is left to try, so the entry just stays open.
function pfb_dnsbl_apply_retry(): void {
	global $pfb;

	if (!pfb_dnsbl_converged()
	    && pfb_unbound_py_mode_active()
	    && is_process_running('unbound')
	    && empty($pfb['dnsbl_python_unmount'])
	    && !file_exists("{$pfb['dnsbldir']}/unbound.tmp")) {
		pfb_unbound_py_flip_sentinel();
	}

	pfb_dnsbl_apply_ledger_update();
}

// ADR-65: surface a still-open DNSBL manifest parse-stage ledger entry (Python's
// pfb_py_status.json -- fail-loud absent/unparseable/build-failed manifest) as a
// GUI file_notice, the same visibility the MaxMind/VIP credential notices get
// (issue #331 pattern). Read-only; never writes the ledger. Returns TRUE iff a
// notice fired.
function pfb_dnsbl_manifest_failure_notice(): bool {
	global $pfb;

	foreach (pfb_py_sync_status_list_open($pfb['dnsbldir']) as $entry) {
		if ($entry['stage'] === 'parse' && basename($entry['item']) === basename($pfb['unbound_py_sources'])) {
			$manifest_notice = "DNSBL manifest not loaded: {$entry['message']}";
			pfb_logger("\n{$manifest_notice}", 2);
			file_notice('pfBlockerNG DNSBL', $manifest_notice, 'pfBlockerNG', '/pfblockerng/pfblockerng_dnsbl.php', 2);
			return TRUE;
		}
	}

	return FALSE;
}

// Reload Resolver. ADR-10: $datapath signals a pure DNSBL-DATA update (feed/cron or a #51
// custom-list edit) already published atomically to the manifest. When python is live, unbound
// is running, no config change is pending, and the RAM gate fits, this takes the ZERO-DOWNTIME
// fast path (flip the reload sentinel, no restart). Any other case falls back to the restart
// (fail-safe; PHP is the PRIMARY gate — never "flip and hope"). Returns TRUE only after the
// applied-generation handshake; restart fallback returns FALSE.
function pfb_reload_unbound($mode, $cache=FALSE, $pfbpython=FALSE, $datapath=FALSE, ?callable $apply_ledger = NULL) {
	global $g, $pfb;
	$apply_ledger ??= static function (): bool {
		return pfb_dnsbl_apply_ledger_update();
	};

	$final = array();
	$type = '';
	if ($mode == 'enabled') {
		$type = ' (DNSBL python)';
	}

	// ZERO-DOWNTIME DATA FAST PATH (no restart). Eligible iff this is a data-only update
	// in the live python mode, unbound is up, NO config change is staged (a pending
	// unbound.tmp or an unmount-in-progress means the resolver config changed -> restart),
	// and the primary RAM gate says the ~2x transient build fits. Otherwise fall through
	// to the restart path below (also the fallback when the swap is unavailable).
	if ($datapath &&
	    $mode == 'enabled' &&
	    pfb_unbound_py_mode_active() &&
	    is_process_running('unbound') &&
	    empty($pfb['dnsbl_python_unmount']) &&
	    !file_exists("{$pfb['dnsbldir']}/unbound.tmp")) {

		if (pfb_unbound_py_swap_fits_ram()) {
			// Suppress the DNSBL Queries daemon's control-socket use during the swap +
			// flush (parity with pfb_update_unbound, which also touches this marker).
			touch("{$pfb['dnsbl_file']}.sync");

			$gen = pfb_unbound_py_flip_sentinel();
			if ($gen !== FALSE) {
				pfb_logger("\nReloading Unbound Resolver{$type} [ zero-downtime swap ]", 1);

				// Readiness handshake: block (bounded) until the watcher APPLIES this
				// generation, so the new lists are LIVE before we return -- the ADR-12
				// post hook + the #51 alert page then see the new state, not a pending
				// async swap. Queries keep flowing on the old snapshot during the wait.
				if (pfb_unbound_py_wait_applied($gen)) {
					pfb_logger(" completed", 1);
					// Clear the daemon-suppression marker before this early return: the
					// alert/#51 path (pfb_reload_unbound called from pfblockerng_alerts.php)
					// has no later clear_work_files, so '.sync' would otherwise leak and keep
					// the DNSBL Queries daemon suppressed. The restart-fallback paths below
					// reach the normal clear, so this is the only fast-path exit that needs it.
					unlink_if_exists("{$pfb['dnsbl_file']}.sync");
					// ADR-61: this swap just confirmed applied == sentinel -- a second,
					// independent convergence point besides the restart path's completion.
					$converged = $apply_ledger();
					pfb_unbound_py_gc($converged);
					return TRUE;
				}

				// The swap did not confirm within the budget (watcher stuck / declined
				// its own RAM re-check / very slow box) -> fall back to the restart so
				// the new lists definitely load. NOT an error: fail-safe by design.
				pfb_logger(" not confirmed in time -- falling back to Unbound restart", 2);
				// Clear the daemon-suppression marker touched above before falling
				// through: the inline restart path below (pfb_stop_start_unbound) does
				// NOT touch '.sync' at all -- a normal, non-fast-path reload restarts
				// with no suppression marker involved -- so clearing it here is safe.
				// It is still REQUIRED because the alert/#51 caller (pfb_reload_unbound
				// invoked from pfblockerng_alerts.php) has no later clear_work_files, so
				// leaving it set here would leak and suppress the DNSBL Queries daemon
				// until the next full update (issue #713 bug 3).
				unlink_if_exists("{$pfb['dnsbl_file']}.sync");
			}
			else {
				// Sentinel flip failed (could not stage/rename) -> fall back to the restart
				// so the new lists still load (don't leave a flipped-but-no-op state).
				pfb_logger("\nADR-10: sentinel flip failed -- falling back to Unbound restart", 2);
				// Same rationale as the timeout branch above: the inline restart path
				// below does not touch '.sync', and clearing it here only exists to stop
				// the marker leaking to the alert/#51 caller (no later clear_work_files).
				unlink_if_exists("{$pfb['dnsbl_file']}.sync");
			}
		}
		else {
			// PRIMARY RAM gate declined: the box cannot fit the ~2x transient build.
			// Restart instead (it never doubles -- it frees the old set by dying before
			// rebuilding) so the new lists actually load.
			pfb_logger("\nADR-10: RAM-constrained box -- using Unbound restart instead of the zero-downtime swap", 1);
		}
	}



	$cache_dumpfile = tempnam('/var/tmp/', 'unbound_cache_');
	if ($mode == 'enabled' && is_process_running('unbound') && !$pfb['dnsbl_python_unmount'] && !$pfbpython) {

		$log = "\nReloading Unbound Resolver{$type}";
		pfb_logger($log, 1);

		if ($cache && $pfb['dnsbl_res_cache'] === PfbToggle::On) {
			exec("{$pfb['chroot_cmd']} dump_cache > " . escapeshellarg($cache_dumpfile) . " 2>&1");
			pfb_logger('.', 1);
		}
	}

	$final = pfb_stop_start_unbound($type);
	pfb_logger('.', 1);

	// issue #3094: a refused stop is not a config fault -- the quarantine/rollback/retry
	// below would trash a good config and retry a stop that already failed. The callee
	// has logged the reason and the shared else-arm logs it again, so say only what is new.
	if ($final['retval'] === PFB_UNBOUND_STOP_FAILED) {
		pfb_logger("\nDNSBL {$mode} FAIL  *** Resolver could not be stopped; " .
			"config left unchanged ***\n", 2);
	}
	elseif ($final['retval'] != 0) {

		@copy("{$pfb['dnsbldir']}/unbound.conf", "{$pfb['dnsbldir']}/unbound.conf.error");
		if ($mode == 'enabled') {
			$log = "\nDNSBL {$mode} FAIL  *** Fix error(s) and a Force Reload required! ***\n";
			if (file_exists("{$pfb['dnsbldir']}/unbound.bk")) {
				@rename("{$pfb['dnsbldir']}/unbound.bk", "{$pfb['dnsbldir']}/unbound.conf");
			}
			pfb_logger("{$log}", 2);
		}
		else {
			$log = "\nDNSBL {$mode} - Unbound conf update FAIL *** Fix error(s) and a Force Reload required! ***\n";
			pfb_logger("{$log}", 2);
		}

		$log = htmlspecialchars(implode("\n", $final['result']));
		pfb_logger("\n\n====================\n\n{$log}\n\n====================\n\n", 2);
		$final = pfb_stop_start_unbound($type);
	}

	// Confirm that Resolver is running. A refused stop is excluded: the process that
	// answers here is the daemon we failed to replace, not one this pass started (#3094).
	if ($final['retval'] !== PFB_UNBOUND_STOP_FAILED && is_process_running('unbound')) {
		pfb_logger('.', 1);

		// $final['result'] will be appended with previous result above
		exec("{$pfb['chroot_cmd']} status 2>&1", $final['result'], $final['retval']);
		pfb_logger('.', 1);
		if (preg_grep("/is running.../", $final['result'])) {
			pfb_logger(" completed", 1);

			// Restore Resolver cache
			if ($cache && $pfb['dnsbl_res_cache'] === PfbToggle::On && file_exists($cache_dumpfile) && filesize($cache_dumpfile) > 0) {
				exec("{$pfb['chroot_cmd']} load_cache < " . escapeshellarg($cache_dumpfile) . " 2>&1");
				$log = "\nResolver cache restored";
				pfb_logger($log, 1);
			}
		}
		else {
			$log = htmlspecialchars(implode("\n", $final['result']));
			pfb_logger(" Not completed.\n{$log}\n", 1);
		}
	}
	else {
		$log = htmlspecialchars(implode("\n", $final['result']));
		pfb_logger(" Not completed.\n{$log}\n", 1);
	}

	// ADR-61: mode=='enabled' is the only state DNSBL's apply is meant to converge to --
	// a deliberate 'disabled' teardown clears any stale entry rather than flagging its
	// own (expected) non-convergence as a failure.
	if ($mode == 'enabled') {
		$converged = $apply_ledger();
		pfb_unbound_py_gc($converged);
	} else {
		pfb_sync_status_close('dnsbl', 'dnsbl', 'apply', $pfb['dbdir']);
	}

	unlink_if_exists($cache_dumpfile);
	return FALSE;
}


// Function to clear Unbound/DNSBL work files
function pfb_unbound_clear_work_files() {
	global $pfb;

	foreach (array( $pfb['dnsbl_cache'],
			"{$pfb['dnsbl_cache']}-wal",
			"{$pfb['dnsbl_cache']}-shm",
			"{$pfb['dnsbldir']}/unbound.bk",
			"{$pfb['dnsbldir']}/unbound.tmp",
			"{$pfb['dnsbl_file']}.bk",
			"{$pfb['dnsbl_file']}.tsp",
			"{$pfb['dnsbl_file']}.sync",
			"/tmp/dnsbl_remove*",
			"/tmp/dnsbl_add*",
			"/tmp/dnsbl_tld*",
			"{$pfb['unbound_py_data']}.raw",
			"{$pfb['unbound_py_zone']}.raw",
			// issue #1083: opportunistic sweep of the retired DNSBL_TLD.txt diagnostic
			// -- else a pre-upgrade box's stray copy sits forever (writer/unlink sites retired).
			"{$pfb['dnsdir']}/DNSBL_TLD.txt",
			// ADR-65: same opportunistic-sweep rationale for the retired interchange files.
			$pfb['unbound_py_data'],
			$pfb['unbound_py_zone'],
			"/var/tmp/unbound_cache_*") as $remove) {
		unlink_if_exists($remove);
	}
}


// Load new DNSBL updates to Unbound Resolver
function pfb_update_unbound($mode, $pfbupdate, $pfbpython, array $dnsbl_tld_group_counts = array()) {
	global $g, $pfb;

	if ($mode == 'enabled') {
		$ext = '.bk';
	} else {
		$ext = '.*';	// Remove all DNSBL Unbound files
	}

	// Finalize deferred TLD-mode statistics, if configured
	if ($pfb['enable'] === PfbToggle::On && $pfb['dnsbl'] === PfbToggle::On && !$pfb['save']) {
		if ($pfb['dnsbl_tld_wildcard']) {
			if ($pfb['domain_update']) {
				pfb_dnsbl_tld_stats_finalize($dnsbl_tld_group_counts);
			}
		}
	}

	// Create file marker to disable DNSBL Queries daemon to avoid unbound-control collisions
	touch("{$pfb['dnsbl_file']}.sync");

	// Marker file(s) to instruct Unbound to be reloaded
	if ($pfb['reuse_dnsbl'] == 'on' ||
	    file_exists("{$pfb['dnsbl_file']}.reload") ||
	    file_exists("{$pfb['dnsbl_unlock']}")) {

		$pfbupdate = TRUE;
		unlink_if_exists("{$pfb['dnsbl_file']}.reload");

		// ADR-06 (#51): re-lock the temporary unlocks on this reload (Cron/Force
		// parity with main, which drops them from the regenerated whitelist). Under
		// ADR-06 the resolver is driven by the manifest's config.user_unlock, so
		// deleting the store alone leaves a STALE allow -- the domain keeps resolving
		// while the UI shows it locked. Drop the store, then recompute user_unlock
		// from it (now empty) so the reload below re-reads a cleared whiteDB.
		$pfb_had_unlock = file_exists("{$pfb['dnsbl_unlock']}");
		unlink_if_exists("{$pfb['dnsbl_unlock']}");
		unlink_if_exists("{$pfb['dnsbl_unlock']}.data");
		if ($pfb_had_unlock) {
			pfb_unbound_python_sources_unlock();
		}
	}

	// Backup existing unbound.conf and rename new unbound.conf file
	if (file_exists("{$pfb['dnsbldir']}/unbound.tmp")) {
		@copy("{$pfb['dnsbldir']}/unbound.conf", "{$pfb['dnsbldir']}/unbound.bk");
		@rename("{$pfb['dnsbldir']}/unbound.tmp", "{$pfb['dnsbldir']}/unbound.conf");
	}

	// When pfBlockerNG is disabled and 'keep blocklists' is disabled.
	// Runtime values are PfbToggle enums; anything other than On is disabled.
	if ($pfb['enable'] !== PfbToggle::On && $pfb['keep'] !== PfbToggle::On && !$pfb['install']) {
		unlink_if_exists("{$pfb['dnsbl_file']}{$ext}");
	}

	// Disable DNSBL
	if (($pfb['enable'] !== PfbToggle::On || $pfb['dnsbl'] !== PfbToggle::On) && !$pfb['install']) {

		pfb_reload_unbound('disabled', FALSE, $pfbpython);
		if (is_service_running('pfb_dnsbl')) {
			pfb_logger("\nStop Service DNSBL", 1);
			stop_service('pfb_dnsbl');
		}
		pfb_unbound_clear_work_files();

		// Unmount Unbound python 'lib/bin' folders after Unbound has been reloaded with the python integration enabled
		if ($pfb['dnsbl_python_unmount']) {
			pfb_unbound_python_unmount();
			unset($pfb['dnsbl_python_unmount']);
		}
		pfb_logger("\nDNSBL is disabled\n", 1);
		return;
	}

	// Load new DNSBL updates
	if (is_service_running('unbound')) {

		// ADR-10: a feed/cron DNSBL-DATA update takes the zero-downtime swap when the
		// reload introduces NO config change ($pfbpython FALSE -> unbound.conf/ini/mounts
		// unchanged). The manifest + per-feed raw were already published atomically by
		// pfb_unbound_python_sources() above; flip the sentinel, no restart. A config
		// change ($pfbpython TRUE) -> $datapath FALSE -> the restart path. The bulk
		// fast path optionally flushes the full resolver cache after the applied-generation
		// handshake; config restarts preserve cache, data fallback clears it by passing FALSE.
		$datapath = !$pfbpython;
		$swapped = pfb_reload_unbound($mode, !$datapath, $pfbpython, $datapath);
		if ($datapath && $swapped &&
		    ($pfb['dnsbl_cache_flush'] ?? PfbToggle::Off) === PfbToggle::On) {
			exec("{$pfb['chroot_cmd']} flush_zone +c . 2>&1");
		}
	}

	// Start Unbound Service with new DNSBL Updates
	else {
		// Unbound is down -> there is nothing to swap into; always (re)start.
		pfb_reload_unbound($mode, FALSE, $pfbpython);
	}

	if ($pfbpython) {
		$log = "\nRestarting DNSBL Service (DNSBL python)";
		pfb_logger("{$log}", 1);
		restart_service('pfb_dnsbl');
	}

	// issue #1263: per-file sum, not cat|grep -c ^ -- differs from the old count
	// when a stored feed lacks a trailing newline (the old command welded two
	// records into one and undercounted); the sum is the correct total.
	$dnsbl_cnt = pfb_update_unbound_feed_count($pfb['dnsdir']);

	// ADR-06: pfb_py_count is now Python-emitted and means the LOADED entry total
	// (len(dataDB)+len(zoneDB)), written by pfb_unbound.py dnsbl_emit_count(). The
	// lists are no longer dedup/collapse/whitelist/TOP1M-pruned at build time, so
	// this value legitimately differs from (and is typically >=) the raw '*.txt'
	// feed line count. The old subtract-and-compare sync-check (which assumed the
	// count meant 'entries removed by subdomain collapse') no longer applies; just
	// report both numbers for visibility.
	$loaded_cnt = trim((string) @file_get_contents($pfb['unbound_py_count']));
	// issue #2607: no emitted count means nothing is loaded -- Python writes it only for a
	// build that produced a snapshot, and the teardown removes it with its manifest.
	if ($loaded_cnt === '') {
		$loaded_cnt = '0';
	}
	$log = "\nDNSBL update [ feed lines: {$dnsbl_cnt} | loaded entries: {$loaded_cnt} ]... completed";
	pfb_logger("{$log}", 1);

	// ADR-65: the manifest is Python's sole DNSBL source now -- surface a fail-loud
	// parse-stage ledger entry (absent/unparseable/build-failed manifest) here, the
	// same per-update-pass cadence the MaxMind/VIP notices already use.
	if (pfb_unbound_py_mode_active()) {
		pfb_dnsbl_manifest_failure_notice();
	}

	// ADR-48 (issue #789): emit stage=entries reject lines for any feed
	// with a nonzero per-entry tally, BEFORE clearing work files.
	pfb_emit_entry_reject_stats($pfb['unbound_py_reject_stats']);

	// Clear work files
	pfb_unbound_clear_work_files();
	pfb_logger("\n------------------------------------------------------------------------", 1);
}


function pfb_top1m_active_provider(): array
{
	global $pfb;
	$source = $pfb['dnsbl_top1m_type'] ?? PfbTop1mSource::Tranco;
	$key = $source instanceof PfbTop1mSource ? $source->value : (string) $source;
	return pfb_top1m_providers()[$key] ?? pfb_top1m_providers()[PfbTop1mSource::Tranco->value];
}

function pfb_top1m_parse_source_row(string $line, array $provider): ?string
{
	$domain_col = (int) ($provider['domain_col'] ?? 1);
	if ($line === '' || strpos($line, '.') === FALSE
		|| ($domain_col > 0 && strpos($line, ',') === FALSE)) {
		return NULL;
	}
	$csvline = str_getcsv($line, ',', '"', "\\");
	if (isset($provider['columns']) && count($csvline) !== (int) $provider['columns']) {
		return NULL;
	}
	if (($provider['parse'] ?? 'rank_domain') === 'rank_domain'
		&& !ctype_digit((string) ($csvline[0] ?? ''))) {
		return NULL;
	}
	$domain = strtolower($csvline[$domain_col] ?? '');
	if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9.-]*\.(?:[A-Za-z]{2,}|[Xx][Nn]--[A-Za-z0-9][A-Za-z0-9-]+)$/D', $domain)) {
		return NULL;
	}
	return $domain;
}

function pfb_top1m_candidate_valid(string $path, array $provider): bool
{
	if (!is_file($path) || !is_readable($path)) {
		return FALSE;
	}
	$sample = @file_get_contents($path, FALSE, NULL, 0, 65536);
	if ($sample === FALSE || pfb_text_sanity($sample) !== NULL) {
		return FALSE;
	}
	$handle = @fopen($path, 'r');
	if ($handle === FALSE) {
		return FALSE;
	}
	$pending_header = !empty($provider['header']);
	$valid = FALSE;
	while (($line = @fgets($handle)) !== FALSE) {
		if ($pending_header) {
			$pending_header = FALSE;
			continue;
		}
		if (pfb_top1m_parse_source_row($line, $provider) !== NULL) {
			$valid = TRUE;
			break;
		}
	}
	fclose($handle);
	return $valid;
}

// Process TOP1M database
// $provider_override (ADR-59 test seam): when given, its 'parse'/'header'/
// 'domain_col' knobs drive the builder directly instead of resolving through
// pfb_top1m_providers()[$pfb['dnsbl_top1m_type']->value] -- lets a unit test
// exercise a synthetic descriptor's knobs without a live provider. Production
// never passes it, so the resolved-provider path is exactly today's behaviour.
// $stream_ops is the filesystem-boundary test seam; production uses fwrite().
function pfblockerng_top1m(?array $provider_override = NULL, array $stream_ops=array()) {
	global $pfb;

	if (empty($pfb['dnsbl_top1m_inc'])) {
		pfb_logger("\n  TOP1M: No TLD Inclusions found.\n", 1);
		return;
	}

	// ADR-59: the active provider descriptor drives the parse knobs below.
	// $pfb['dnsbl_top1m_type'] may be unset in an isolated unit-test context
	// (it is normally set by pfb_global() -- PfbConfig::read('dnsbl/top1m_source') --
	// which some tests never call); default to Tranco, the same absent-default
	// the registry itself uses, so the resolved shape stays rank_domain/zip.
	$top1m_type	= $pfb['dnsbl_top1m_type'] ?? PfbTop1mSource::Tranco;
	$top1m_provider	= $provider_override ?? (pfb_top1m_providers()[$top1m_type->value] ?? array());
	$top1m_header	= $top1m_provider['header'] ?? FALSE;

	// Array of TLDs to include in Whitelist
	$pfb_include = explode(',', $pfb['dnsbl_top1m_inc']);
	if (!empty($pfb_include)) {
		$pfb_include = array_flip($pfb_include);
	}

	$whitelist_file	= "{$pfb['dbdir']}/pfbalexawhitelist.txt";
	$had_previous	= file_exists($whitelist_file);

	$linecnt = $x = 0;
	pfb_logger(" Building TOP1M Whitelist [", 1);

	if (($handle = @fopen("{$pfb['dbdir']}/top-1m.csv", 'r')) !== FALSE) {
		// Build into a TEMP file first -- an empty/invalid top-1m.csv must never
		// truncate a previously-good whitelist (issue #886); only a build that
		// actually parsed source lines is swapped into place below. tempnam()
		// (not a fixed '.tmp' name) so a manual "Run Now" racing a cron tick can't
		// collide on the same staging file (#886 review).
		$tmp_file	= @tempnam(dirname($whitelist_file), '.pfbtop1m_');
		$pfb_output	= ($tmp_file !== FALSE) ? @fopen($tmp_file, 'w') : FALSE;

		if ($pfb_output === FALSE) {
			// Could not stage the build at all (perms/full disk) -- never touch
			// the existing whitelist; warn and move on (#886 review). Not
			// deterministically unit-triggerable without an open_basedir-restricted
			// child process (tempnam() falls back to the system temp dir for a
			// merely-unwritable-but-existing dir) -- see the covered rename-failure
			// branches (+ this gap's rationale) in
			// tests/php/Top1mPreserveOnEmptyFeedTest.php.
			if ($tmp_file !== FALSE) {
				unlink_if_exists($tmp_file);
			}
			@fclose($handle);
			pfb_logger("\n  TOP1M: could not create the temp whitelist file -- keeping the previous TOP1M whitelist.\n", 2);
		}
		else {
			$write_fn = $stream_ops['write'] ?? static fn($stream, $bytes) => @fwrite($stream, $bytes);
			$write_failed = FALSE;

			// ADR-59: skip exactly the first physical line unconditionally when
			// the provider ships a header row -- before the content filter below, so
			// a header line's shape (which may not even contain a '.'/',') never
			// matters.
			$top1m_pending_header = $top1m_header;

			while (($line = @fgets($handle)) !== FALSE) {

				if ($top1m_pending_header) {
					$top1m_pending_header = FALSE;
					continue;
				}

				// Display progress indicator
				if ($linecnt % 100000 == 0) {
					pfb_logger('.', 1);
				}

				// Collect Domain TLD. For the 'rank_domain' parse (Tranco/Cisco), a row whose
				// rank column is non-numeric is not real parsed source data -- a prose/HTML/
				// error body (e.g. "error, service temporarily unavailable.") still has a '.'
				// and a ',' and would otherwise pass the filter above, so a dead feed would
				// classify as "valid" below and wipe the whitelist (#886 review). The other
				// parse mode ('csv': OpenPageRank/Majestic/Cloudflare) has no rank column at
				// all. The hostname-shape regex below now applies to EVERY parse mode; the
				// rank-column check still applies only where a rank column exists
				// (rank_domain) -- a numeric rank alone is not proof the domain field itself
				// is usable. A dotless/
				// malformed rank_domain domain field (e.g. Tranco/Cisco row
				// "1,garbage,extra.dot") used to satisfy the rank-only guard and reach the
				// TLD-extraction strrpos() below with a garbage result, wrongly counting the
				// row as valid (#954 review) -- the SAME garbage-body-wipe class as #886/#892.
				$domain = pfb_top1m_parse_source_row($line, $top1m_provider);
				if ($domain === NULL) {
					continue;
				}
				// Count every valid CSV row BEFORE the match/break below, so a
				// small dnsbl_top1m_cnt (e.g. 1) that breaks on the first match
				// still leaves $linecnt > 0 and classifies as a valid feed
				// (not the dead-feed $linecnt === 0 path) (#886 review).
				$linecnt++;
				$tld = substr($domain, strrpos($domain, '.') + 1);

				if (isset($pfb_include[$tld])) {
					// Whitelist both 'www.example.com' and 'example.com'
					if (str_starts_with($domain, 'www.')) {
						$domain = substr($domain, 4);
					}
					$x++;

					// Canonical TOP1M wire: one bare domain per line; exact lookup also allows only www.
					// Deeper subdomains remain unallowed.
					$record = "{$domain}\n";
					$written = $write_fn($pfb_output, $record);
					if ($written === FALSE || $written !== strlen($record)) {
						$write_failed = TRUE;
						break;
					}
				}

				if ($x >= $pfb['dnsbl_top1m_cnt']) {
					break;
				}
			}
			@fclose($pfb_output);
			@fclose($handle);

			if ($write_failed) {
				unlink_if_exists($tmp_file);
				pfb_logger("\n  TOP1M: failed to write the new whitelist build -- publication aborted.\n", 2);
			}
			else if ($linecnt === 0) {
				// Dead feed (empty/invalid top-1m.csv) -- discard the temp build and
				// keep whatever whitelist was already on disk instead of wiping it.
				unlink_if_exists($tmp_file);
				if ($had_previous) {
					pfb_logger("\n  TOP1M: feed returned no valid data (empty/invalid) -- keeping the previous TOP1M whitelist.\n", 2);
				}
				else {
					pfb_logger("\n  TOP1M: feed returned no valid data (empty/invalid) -- no TOP1M whitelist available.\n", 2);
				}
			}
			else if (@rename($tmp_file, $whitelist_file)) {
				// Valid feed -- atomically swap the validated build into place.
				pfb_logger("] [ Parsed {$linecnt} lines | Found {$x} of {$pfb['dnsbl_top1m_cnt']} ]...", 1);
				if ($x === 0) {
					pfb_logger("\n  TOP1M: 0 domains matched the configured TLD inclusions.\n", 1);
				}
			}
			else {
				// The parse looked valid but publishing it did not (perms/cross-device/
				// disk) -- never report success while silently keeping a stale whitelist
				// (#886 review).
				unlink_if_exists($tmp_file);
				pfb_logger("\n  TOP1M: failed to publish the new whitelist build -- keeping the previous TOP1M whitelist.\n", 2);
			}
		}
	}
	else {
		$log = "\nTOP1M conversion Failed. File: top-1m.csv, not found...";
		pfb_logger("{$log}", 2);
	}

	// Remove Top1M update file marker
	unlink_if_exists("{$pfb['dbdir']}/top-1m.update");
}


// Function to remove any leading zeros in octets and to exclude private/reserved addresses.
// A downloaded feed's explicit /0 is clamped to a single host and logged (issue #744);
// a custom list's /0 is honored as written. Under Suppression, also drops documentation
// (RFC 5737), multicast, CGN (RFC 6598), benchmarking (RFC 2544) and the deprecated 6to4
// relay anycast space that PHP's filter flags leave routable (issue #760).
function sanitize_ipaddr($ipaddr, $custom, $pfbcidr) {
	global $pfb;

	$result = pfb_sanitize_ipaddr($ipaddr, $custom, $pfbcidr, $pfb['supp']);
	foreach ($result['messages'] as $message) {
		pfb_logger($message, 1);
	}
	return $result['address'];
}

/**
 * Normalize one IPv4 entry without reading global state or emitting logs.
 *
 * @return array{address: ?string, messages: list<string>}
 */
function pfb_sanitize_ipaddr($ipaddr, $custom, $pfbcidr, PfbToggle $supp): array {
	$messages = [];

	$parts	= explode('/', $ipaddr, 3);
	$subnet	= $parts[0];
	// issue #1933: with more than one '/', $parts[1] is a URL path segment, not
	// a mask — recover the bare host (the issue #1922 regex mask-guard outcome);
	// discarding $parts[2..] read the first path segment as the prefix length.
	$mask	= isset($parts[2]) ? '' : ($parts[1] ?? '');	// '' (not undef) when no CIDR

	// An IPv4 prefix length must be 0..32; drop the line outright. A substring
	// strip here (str_replace('32', '')) used to rewrite an invalid mask into a
	// valid, far broader one (/132 -> /1 = half of IPv4) (issue #719).
	if ($mask !== '' && (!ctype_digit($mask) || (int)$mask > 32)) {
		return ['address' => NULL, 'messages' => $messages];
	}

	// An explicit /0 covers the entire IPv4 space and is never honored from a
	// downloaded feed: clamp to a single host so the address itself stays
	// blocked (issue #744). Custom-list entries are user-authored, so /0 is
	// kept as written — except 0.x.x.x, rejected below (issue #1922).
	if ($mask !== '' && (int)$mask === 0 && !$custom) {
		// Unlike the v6 sibling, callers reach this before validate_ipv4(), so
		// $ipaddr is raw feed text — strip control chars to keep the log clean.
		$messages[] = "\n  Feed /0 CIDR clamped to single host: " . preg_replace('/[[:cntrl:]]/', '', $ipaddr);
		$mask = '';
	}
	$iparr = explode('.', $subnet);

	foreach ($iparr as $key => $octet) {
		// Remove any leading zeros in octets
		if ($octet == 0) {
			$ip[$key] = 0;
		} else {
			$ip[$key] = ltrim($octet, '0');
		}

		if ($key == 3) {
			// If mask is '24', force 4th octet to '0' (normalise to the
			// network address). A bare IPv4 with no mask is treated as a
			// single host (/32) - the trailing '.0' is a valid host, so it
			// is NOT widened to a /24 (that silently over-blocks 255 extra
			// addresses; a feed that means the network writes '.0/24').
			if ($mask == 24 && $octet != 0) {
				$ip[$key] = 0;
			}
		}
	}

	if ((int)$mask == 32) {
		$mask = '';	// Strip '/32' mask (bare host)
	}
	$ip_final = implode('.', $ip);

	// issue #1922: 0.x.x.x is "this network" (RFC 791) — never a valid entry
	// under any mask, suppression setting, or list type. Previously gated on
	// Suppression, which let a 0.0.0.0/0 reach a live WAN block table.
	if ($ip[0] == 0 || empty($ip[0])) {
		return ['address' => NULL, 'messages' => $messages];
	}

	// Exclude private/reserved IPs (bypass exclusion for custom lists)
	if ($supp === PfbToggle::On && !$custom) {

		// Remove 'loopback' IPs
		if ($ip[0] == 127) {
			return ['address' => NULL, 'messages' => $messages];
		}

		// Advanced IPv4 Tunable (Set CIDR Block size limit)
		if ($pfbcidr != 'Disabled' && !empty($mask) && $mask < $pfbcidr) {
			$messages[] = "\n  Suppression CIDR Limit: {$ip_final}/{$mask}";
			$mask = '32';
		}

		if (!filter_var($ip_final, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== FALSE) {
			return ['address' => NULL, 'messages' => $messages];
		}

		// FILTER_FLAG_NO_PRIV_RANGE|NO_RES_RANGE keep documentation (RFC 5737),
		// multicast, CGN (RFC 6598), benchmarking (RFC 2544) and the deprecated
		// 6to4 relay anycast prefix routable; explicit checks close that gap
		// (issue #760). Judged on the address only, same as the filter above -
		// the CIDR span is not inspected (issue #760 §4).
		$long = ip2long($ip_final);
		if ($long !== FALSE && (
			($long & 0xffffff00) === 0xc0000200 ||	// 192.0.2.0/24 documentation
			($long & 0xffffff00) === 0xc6336400 ||	// 198.51.100.0/24 documentation
			($long & 0xffffff00) === 0xcb007100 ||	// 203.0.113.0/24 documentation
			($long & 0xf0000000) === 0xe0000000 ||	// 224.0.0.0/4 multicast
			($long & 0xffc00000) === 0x64400000 ||	// 100.64.0.0/10 CGN
			($long & 0xfffe0000) === 0xc6120000 ||	// 198.18.0.0/15 benchmarking
			($long & 0xffffff00) === 0xc0586300	// 192.88.99.0/24 6to4 relay anycast
		)) {
			return ['address' => NULL, 'messages' => $messages];
		}
	}

	// '!== '' (not !empty()): empty('0') is TRUE, which silently collapsed a
	// custom list's honored /0 to a bare host (issue #744).
	if ($mask !== '') {
		return ['address' => "{$ip_final}/{$mask}", 'messages' => $messages];
	}
	return ['address' => "{$ip_final}", 'messages' => $messages];
}


/**
 * Normalize one IPv6 entry without reading global state or emitting logs —
 * the IPv6 sibling of pfb_sanitize_ipaddr(). Excludes private/reserved/loopback
 * IPv6 from loaded block lists when Suppression is enabled ($supp); a feed's
 * explicit /0 clamps to a single host (issue #744). Also drops documentation
 * (RFC 3849), multicast, and the NAT64 prefix (RFC 6052), which PHP's filter
 * flags leave routable (issue #760) — explicit prefix checks so behaviour is
 * independent of PHP's patch level (RFC 6890 moved 2001:db8::/32 between
 * filter sets in 8.3.16/8.4.3). $pfbcidr: per-category Advanced "Suppression
 * CIDR Limit" floor (issue #760 §3). The returned address is the canonical
 * inet_ntop() form (issue #1084): textual variants of one address (case,
 * zero-run, leading zeros) collapse to one string, and an unparseable address
 * is dropped rather than passed through.
 *
 * @return array{address: ?string, messages: list<string>}
 */
function pfb_sanitize_ipaddr_v6($ipaddr, $custom, $pfbcidr, PfbToggle $supp): array {
	$messages = [];

	// Extract the address part (before '/' for a CIDR like 'fc00::/7')
	$parts	= explode('/', $ipaddr);
	$s_ip	= $parts[0];
	$mask	= $parts[1] ?? '';

	// issue #1084: single inet_pton() per address, reused by the suppression
	// reserved-prefix checks below; an unparseable address drops the row. A %zone
	// form is dropped explicitly first -- inet_pton()'s handling of it is
	// platform-dependent (FreeBSD/glibc reject it, macOS strips the zone).
	if (strpos($s_ip, '%') !== FALSE) {
		return ['address' => NULL, 'messages' => $messages];
	}
	$bin = inet_pton($s_ip);
	if ($bin === FALSE) {
		return ['address' => NULL, 'messages' => $messages];
	}

	// An explicit /0 covers the entire IPv6 space and is never honored from a
	// downloaded feed: clamp to a single host so the address itself stays
	// blocked (issue #744). Custom-list entries are user-authored, so /0 is
	// kept as written.
	$mask_clamped = FALSE;
	if ($mask !== '' && ctype_digit($mask) && (int)$mask === 0 && !$custom) {
		$messages[] = "\n  Feed /0 CIDR clamped to single host: {$ipaddr}";
		$mask_clamped = TRUE;
	}

	// issue #1922: '::' is never a valid entry under any mask, suppression
	// setting, or list type — the IPv6 sibling of pfb_sanitize_ipaddr()'s
	// unconditional 0.x.x.x reject.
	if ($bin === str_repeat("\x00", 16)) {
		return ['address' => NULL, 'messages' => $messages];
	}

	// Exclude private/reserved IPs (bypass exclusion for custom lists)
	if ($supp === PfbToggle::On && !$custom) {

		// Advanced IPv6 Tunable (Set CIDR Block size limit) (issue #760 §3).
		// A /0 was already clamped above (mask stays '0', never > 0, so this
		// guard never double-clamps it). All three feed call sites gate on
		// validate_ipv6() BEFORE calling this function, so $mask is already
		// 0-128 here; the ctype_digit()/range checks are defensive redundancy
		// for any direct caller that skips that guard.
		if ($pfbcidr != 'Disabled' && $mask !== '' && ctype_digit($mask) && (int)$mask > 0 && (int)$mask < (int)$pfbcidr) {
			$messages[] = "\n  Suppression CIDR Limit: {$s_ip}/{$mask}";
			$mask_clamped = TRUE;
		}

		// Drop ULA (fc00::/7), link-local (fe80::/10), loopback (::1),
		// IPv4-mapped and the reserved set (mirrors inc:7118-7119).
		if (!filter_var($s_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) ||
		    !filter_var($s_ip, FILTER_CALLBACK, array('options' => 'FILTER_FLAG_NO_LOOPBACK_RANGE'))) {
			return ['address' => NULL, 'messages' => $messages];
		}

		// The filter flags above keep documentation (2001:db8::/32), multicast
		// (ff00::/8) and the NAT64 well-known prefix (64:ff9b::/96) routable;
		// explicit prefix checks close that gap (issue #760). Judged on the
		// address part only, same as the filter above -- the CIDR span is not
		// inspected (issue #760 §4).
		if (substr($bin, 0, 4) === "\x20\x01\x0d\xb8" ||					// 2001:db8::/32 documentation
			substr($bin, 0, 1) === "\xff" ||								// ff00::/8 multicast
			substr($bin, 0, 12) === "\x00\x64\xff\x9b" . str_repeat("\x00", 8)	// 64:ff9b::/96 NAT64
		) {
			return ['address' => NULL, 'messages' => $messages];
		}
	}

	// issue #1084: canonical inet_ntop() form; mask re-appended only when
	// neither clamp above dropped it.
	if ($mask !== '' && !$mask_clamped) {
		return ['address' => inet_ntop($bin) . '/' . $mask, 'messages' => $messages];
	}
	return ['address' => inet_ntop($bin), 'messages' => $messages];
}


// Validate IPv4 IP addresses
function validate_ipv4($ipaddr) {
	if (str_contains($ipaddr, "\0")) {
		return FALSE;
	}
	if (strpos($ipaddr, '/') !== FALSE) {
		return is_subnetv4($ipaddr);
	}
	return is_ipaddrv4($ipaddr);
}


// Validate IPv6 IP addresses
function validate_ipv6($ipaddr) {
	if (strpos($ipaddr, '/') !== FALSE) {
		return is_subnetv6($ipaddr);
	}
	return is_ipaddrv6($ipaddr);
}


// Return a BRE pattern for one complete validated IP/CIDR feed entry.
// Invalid inputs return NULL so callers preserve no-pattern miss behaviour.
function pfb_ip_exact_entry_pattern($entry): ?string {
	if (!is_string($entry) || strpos($entry, "\0") !== FALSE || (!is_ipaddr($entry) && !is_subnet($entry))) {
		return NULL;
	}

	return '^' . str_replace('.', '\.', $entry) . '$';
}


// Function to check for loopback addresses (IPv4 range: 127.0.0.0/8, excluding IPv6)
function FILTER_FLAG_NO_LOOPBACK_RANGE($value) {
	// http://www.php.net/manual/en/filter.filters.flags.php
	return filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? $value : (((ip2long($value) & 0xff000000) == 0x7f000000) ? FALSE : $value);
}


// Explode IP for evaluations
function ip_explode($ip) {

	$ix1	= '';
	$ix	= explode('.', $ip);
	foreach ($ix as $key => $octet) {
		if ($key != 3) {
			$ix1 .= "{$octet}.";
		}
	}
	array_unshift($ix, $ip);
	$ix[] = "{$ix1}0/24";
	$ix[] = "{$ix1}";

	return $ix;
}


// Determine the header which Alerted an IP address and return the header name
function find_reported_header($ip, $pfbfolder, $geoip=FALSE) {
	global $pfb;
	$geoip_lock = FALSE;
	if ($geoip) {
		$geoip_lock = pfb_geoip_generation_read_lock();
		if ($geoip_lock === FALSE) {
			return array('Unknown', 'Unknown');
		}
	}

	// Find exact IP match
	$q_ip = pfb_ip_exact_entry_pattern($ip);
	if ($q_ip === NULL) {
		pfb_geoip_generation_read_unlock($geoip_lock);
		return array('Unknown', 'Unknown');
	}
	$q_ip = escapeshellarg($q_ip);
	// issue #833: /dev/null forces grep to always be given >=2 files, so it
	// always emits the "path:" prefix -- even when $pfbfolder's glob resolves to
	// exactly ONE .txt file. Without it, pfb_parse_query() gets an unprefixed
	// line and returns a 1-element array (no [1]), corrupting every downstream
	// consumer that reads it.
	$query	= exec("{$pfb['grep']} -s {$q_ip} {$pfbfolder} /dev/null 2>&1");
	if (!empty($query)) {
		$rx = pfb_parse_query($query);
		pfb_geoip_generation_read_unlock($geoip_lock);
		return $rx;
	}
	else {
		$v4_type = FALSE;
		if (substr_count($ip, ':') > 1) {
			$query		= strstr($ip, ':', TRUE);	// IPv6 Prefix
			$query_esc	= escapeshellarg("^{$query}:");
		} else {
			$query		= strstr($ip, '.', TRUE);	// IPv4 Octet #1
			$query_esc	= escapeshellarg("^{$query}\.");
			$v4_type	= TRUE;
		}

		$result = array();
		if (!$geoip) {
			// issue #833: same /dev/null forced-prefix fix as the exact-match exec
			// above.
			exec("{$pfb['grep']} -s {$query_esc} {$pfbfolder} /dev/null 2>&1", $result);
		} else {
			$geoip_list = "Africa\|Antarctica\|Asia\|Europe\|North_America\|South_America\|Oceania\|Proxy_and_Satellite\|Top_Spammers";
			exec("{$pfb['grep']} -s {$query_esc} {$pfb['ccdir']}/*.txt /dev/null | {$pfb['grep']} -v '{$geoip_list}' 2>&1", $result);
		}

		// issue #809: the CIDR-selection loop (collect CIDR-shaped candidates
		// from $result, then walk them doing the v4 mask math / v6 gen_subnetv6 +
		// Net_IPv6::isInNetmask() match) is extracted to pfb_match_reported_cidr() so the
		// batched pfb_find_reported_headers() sibling below can reuse the EXACT same logic
		// against a SHARED grep-output array. Same $result, same v4/v6 math, same
		// "first CIDR containing $ip wins" order -- this function's own behaviour is
		// unchanged.
		$rx = pfb_match_reported_cidr($result, $ip, $v4_type);
		unset($result);
		if ($rx !== NULL) {
			pfb_geoip_generation_read_unlock($geoip_lock);
			return $rx;
		}
	}

	unset($result);
	pfb_geoip_generation_read_unlock($geoip_lock);
	return array('Unknown', 'Unknown');
}


// Shared CIDR-selection core of find_reported_header()'s prefix-match branch (issue #809):
// given the RAW grep output lines already collected for a first-octet (v4) or
// prefix (v6) query, parse out every CIDR-shaped candidate and return the first one
// containing $ip, or NULL if none does. find_reported_header() calls this on its own
// single-host $result array (behaviour unchanged); the batched pfb_find_reported_headers()
// sibling calls it once per GROUP on a SHARED $result array (every still-unresolved host in
// that group), once per host.
function pfb_match_reported_cidr(array $result, string $ip, bool $v4_type): ?array {

	$cidrs = array();
	if (!empty($result)) {
		foreach ($result as $line) {
			$rx = pfb_parse_query($line);

			// Collect all CIDRs for analysis if Alert is from a CIDR (a non-".txt:"-shaped
			// stderr line parses to an empty value and is skipped here -- issue #843)
			if (strpos($rx[1], '/') !== FALSE) {
				$cidrs[] = $rx;
			}
		}
	}

	if (!empty($cidrs)) {
		foreach ($cidrs as $line) {
			$validate = FALSE;
			if ($v4_type) {
				list($addr, $mask) = explode('/', $line[1]);
				// issue #1157: skip malformed CIDR candidates -- a bad mask fataled
				// (TypeError/negative shift) here
				if (!ctype_digit((string) $mask) || (int) $mask > 32 || !is_ipaddrv4($addr)) {
					continue;
				}
				$mask = (0xffffffff << (32 - $mask)) & 0xffffffff;
				$validate = ((ip2long($ip) & $mask) == (ip2long($addr) & $mask));
			}
			else {
				/* Normalize IPv6 prefix to its start address to avoid PHP errors
				 * https://redmine.pfsense.org/issues/14256
				 */
				list($prefix, $length) = explode('/', $line[1]);
				// issue #1157: skip malformed CIDR candidates -- a bad length false-matched here
				if (!ctype_digit((string) $length) || (int) $length > 128 || !is_ipaddrv6($prefix)) {
					continue;
				}
				$prefix = gen_subnetv6($prefix, $length);
				$subnet = "{$prefix}/{$length}";

				$validate = (Net_IPv6::isInNetmask($ip, $subnet));
			}

			// Return header on CIDR match
			if ($validate) {
				return $line;
			}
		}
	}

	return NULL;
}


// issue #1250: the feed dirs a 'match' event is attributed against -- matchdir holds the user's
// own Match lists, matchgendir the machine-generated reputation/ET artifacts. Globs '.txt'
// because matchdir NESTS matchgendir: a bare '/*' would hand grep the subdirectory itself.
// Callers append their own nativedir glob (the two call sites differ in its suffix).
function pfb_ip_match_folders(): string {
	global $pfb;

	return "{$pfb['matchdir']}/*.txt {$pfb['matchgendir']}/*.txt";
}


// issue #809: the exact per-row query derivation pfb_ip_render_attribution() needs before
// validating/re-locating a reported IP — extracted VERBATIM so the batched
// prefetch pass (pfb_ip_prefetch()) derives IDENTICAL lookup groups from the same $fields.
// $fields must already be in convert_ip_log()'s POST-REORDER shape (called AFTER
// `$fields[99] = array_shift($fields);`).
//
// Returns: host (reported IP/CIDR); hostname (array('src','dst'), RAW); pfb_geoip (TRUE iff a
// GeoIP continent alias); field15 (Proofpoint IQRisk prefix stripped, render-visible — caller
// writes back); folder (feed-dir glob); validate_file_cmd/validate_cmd (row-grouping find pipe
// / exact memoized validate command, each NULL when this row never validates).
function pfb_ip_render_query(array $fields): array {
	global $pfb, $continents;

	// Inbound event
	if ($fields[11] == 'in') {
		$host		= $fields[7];
		$hostname	= array( 'src' => $fields[16], 'dst' => $fields[17] );
	}
	// Outbound event
	else {
		$host		= $fields[8];
		$hostname	= array( 'src' => $fields[17], 'dst' => $fields[16] );
	}

	// GeoIP event
	$pfb_geoip = FALSE;
	if (isset($continents[ substr($fields[13], 0, -3) ])) {
		$pfb_geoip = TRUE;
	}

	// Determine if Proofpoint IQRisk based Feed (Based on ':' in Feedname - Defines Feed Category)
	$et_header = FALSE;
	if (strpos($fields[15], ':') !== FALSE) {
		$data		= explode(':', $fields[15]);
		$fields[15]	= $data[1];
		$et_header	= TRUE;
	}

	// Determine folder type
	$folder		= '';
	$query_prefix	= "|";
	$query		= "{$pfb['grep']}";
	$query_host	= "{$fields[15]}.txt";

	if ($pfb_geoip) {
		$folder = "{$pfb['ccdir']}/*.txt";
	} elseif ($et_header) {
		$folder		= "{$pfb['etdir']}/*.txt";
		$query		= '';
		$query_host	= '';
		$query_prefix	= '';
	} elseif ($fields[3] == 'block') {
		$folder = "{$pfb['denydir']}/*.txt {$pfb['nativedir']}/*.txt";
	} elseif ($fields[3] == 'pass') {
		$folder = "{$pfb['permitdir']}/*.txt {$pfb['nativedir']}/*.txt";
	} elseif ($fields[3] == 'match') {
		$folder = pfb_ip_match_folders() . " {$pfb['nativedir']}/*.txt";
	}

	// Determine if event IP still exists in Feed Aliastable -- builds the exact validate
	// command pfb_ip_render_attribution() execs (via its page-scope memo); NULL reproduces today's
	// `$validate = '';` no-exec guard (an 'Unknown' evaluated IP or feed name never ran a
	// validate exec at all).
	$validate_file_cmd = NULL;
	$validate_cmd	    = NULL;
	$q_ip		    = NULL;
	if ($fields[14] != 'Unknown' && $fields[15] != 'Unknown') {
		$q_ip = pfb_ip_exact_entry_pattern($fields[14]);
	}

	if ($q_ip !== NULL) {
		$q_ip_esc = escapeshellarg($q_ip);
		// issue #832: the ET/Proofpoint branch above blanks $query/$query_host/
		// $query_prefix (no filename filter -- every file under etdir is a
		// candidate), so only append the filter tail when there IS one -- two
		// escaped empty-string operands (plus the blank, contentless $query_prefix)
		// made `find` error out ("unknown primary or operator"), which silently
		// killed the validate round for every ET row.
		$filter = '';
		if ($query !== '') {
			$query_esc	= escapeshellarg($query);
			$query_host_esc	= escapeshellarg($query_host);
			$filter = " {$query_prefix} {$query_esc} {$query_host_esc}";
		}

		$validate_file_cmd = "/usr/bin/find {$folder} -type f{$filter}";
		$validate_cmd	   = "{$validate_file_cmd} | xargs {$pfb['grep']} {$q_ip_esc} 2>&1";
	}

	return array(
		'host'			=> $host,
		'hostname'		=> $hostname,
		'pfb_geoip'		=> $pfb_geoip,
		'field15'		=> $fields[15],
		'folder'		=> $folder,
		'validate_file_cmd'	=> $validate_file_cmd,
		'validate_cmd'		=> $validate_cmd,
	);
}


// Render-time attribution for one POST-timestamp-reorder IP row. The page keeps
// filtering, counters, icons, and HTML; this seam owns the per-row lookup fallback.
function pfb_ip_render_attribution(array $fields): array {
	global $pfb;

	$rq = pfb_ip_render_query($fields);
	$geoip_lock = FALSE;
	if ($rq['pfb_geoip']) {
		$geoip_lock = pfb_geoip_generation_read_lock();
		if ($geoip_lock === FALSE) {
			return array(
			'host' => $rq['host'],
			'hostname' => $rq['hostname'],
			'pfb_geoip' => TRUE,
			'field15' => $rq['field15'],
			'mask' => '',
			'feed_new' => 'Not listed!',
			'eval_new' => 'Not listed!',
			'alias_new' => '',
			'pfb_matchtitle' => 'This IP is not currently listed!',
			);
		}
	}
	$memos = &pfb_ip_render_memos();
	$mask = '';
	if ($fields[4] == 4) {
		$mask = strstr($fields[14], '/', FALSE) ?: '/32';
	}

	$feed_new = $eval_new = $alias_new = $pfb_matchtitle = '';
	$validate = '';
	if ($rq['validate_cmd'] !== NULL) {
		$validate_cmd = $rq['validate_cmd'];
		$validate = pfb_render_memo($memos['validate'], $validate_cmd, function () use ($validate_cmd) {
			return exec($validate_cmd);
		});
	}

	if (empty($validate)) {
		$miss_key = "{$rq['host']}|{$rq['folder']}";
		list($pfb_query, $validate) = pfb_render_memo($memos['miss'], $miss_key, function () use ($rq, $pfb) {
			$pfb_query = find_reported_header($rq['host'], $rq['folder']);
			$eval_new = ($pfb_query[1] == 'Unknown') ? 'Not listed!' : $pfb_query[1];
			$raw_validate = '';
			$q_ip = pfb_ip_exact_entry_pattern($eval_new);
			if ($q_ip !== NULL) {
				$q_ip_esc = escapeshellarg($q_ip);
				$raw_validate = exec("/usr/bin/find {$pfb['aliasdir']}/*.txt -type f | xargs {$pfb['grep']} {$q_ip_esc} /dev/null 2>&1");
			}
			return array($pfb_query, $raw_validate);
		});

		if ($pfb_query[0] == 'Unknown') {
			$feed_new = 'Not listed!';
			$pfb_matchtitle = 'This IP is not currently listed!';
		} else {
			$feed_new = $pfb_query[0];
		}

		if ($pfb_query[1] == 'Unknown') {
			$mask = '';
			$eval_new = 'Not listed!';
		} else {
			if ($fields[4] == 4) {
				$mx = explode('/', $pfb_query[1]);
				$mask = empty($mx[1]) ? '/32' : "/{$mx[1]}";
			}
			$eval_new = $pfb_query[1];
		}

		$validate = ltrim(strrchr(strstr(strstr($validate, ':', TRUE), '.txt', TRUE), '/'), '/');
		if ($validate != $fields[13]) {
			$alias_new = $validate;
		}
	}

	$result = array(
		'host' => $rq['host'],
		'hostname' => $rq['hostname'],
		'pfb_geoip' => $rq['pfb_geoip'],
		'field15' => $rq['field15'],
		'mask' => $mask,
		'feed_new' => $feed_new,
		'eval_new' => $eval_new,
		'alias_new' => $alias_new,
		'pfb_matchtitle' => $pfb_matchtitle,
	);
	pfb_geoip_generation_read_unlock($geoip_lock);
	return $result;
}


// issue #809: exposes the render-attribution memo stores ($validate_memo / $ip_miss_memo)
// through a reference-returning accessor so the batched prefetch pass below
// (pfb_ip_prefetch()) can seed them before pfb_ip_render_attribution() consumes them. Same
// one-page-load lifetime as before (a static local, just declared here). No reset is needed
// between the three per-type IP tables rendered on one page load: every key is content-derived
// (the exact validate command string, or "$host|$folder") and therefore stable regardless of
// which table populated it first.
function &pfb_ip_render_memos(): array {
	static $memos = array('validate' => array(), 'miss' => array());
	return $memos;
}


// Test-only reset hook for pfb_ip_render_memos()'s function-static store (issue #809
// review, T1). Production never needs this (see the docblock above -- a page render is
// one PHP process, and every memo key is content-derived, so cross-table reuse within
// that one load is correct by design). PHPUnit, though, runs every test method in ONE
// process, so without an explicit per-test reset a later test can silently inherit an
// earlier test's seeded memo entries -- a sibling-order leak that made a "covered rows
// survive the backing dirs disappearing" test a no-op (it reused a prior test's seed
// instead of exercising its own pfb_ip_prefetch() call).
function pfb_ip_render_memos_reset(): void {
	$memos = &pfb_ip_render_memos();
	$memos = array('validate' => array(), 'miss' => array());
}


// Shared write-outcome check for a batched-prefetch pattern-file write (issue #809
// review, B3/R1). file_put_contents() returns FALSE on total failure, or the number of
// bytes actually written -- a partial write (e.g. a full disk) returns a SHORT byte
// count, not FALSE, so a bare `=== FALSE` check alone misses it. Comparing the return
// value against strlen($data) catches both failure shapes; only an exact full-length
// write counts as complete. Used by pfb_ip_prefetch_grep_lines()'s pattern-file write.
function pfb_prefetch_pattern_file_write_ok($written, string $data): bool {
	return $written !== FALSE && $written === strlen($data);
}


// Run ONE batched `grep -f <patternfile>` pass, sharing the pattern-file plumbing across every
// IP-table batched round (validate / miss-header / aliastables) below. Returns every matched
// line (not a first-match map) since callers attribute possibly-many lines per candidate
// themselves. The pattern-file path is inserted between
// $cmd_prefix and $cmd_suffix verbatim (no sprintf/format-string parsing). Returns NULL —
// distinct from a genuine empty-array no-match — when the pattern file could not be created or
// fully written; every caller must treat NULL as "did not run" and leave rows UNSEEDED.
function pfb_ip_prefetch_grep_lines(string $cmd_prefix, string $cmd_suffix, array $patterns): ?array {

	$lines = array();
	if (empty($patterns)) {
		return $lines;
	}

	$pattern_file = tempnam(sys_get_temp_dir(), 'pfb_ip_prefetch_');
	if ($pattern_file === FALSE) {
		return NULL;
	}

	try {
		$data = implode("\n", $patterns) . "\n";
		$written = file_put_contents($pattern_file, $data);
		if (!pfb_prefetch_pattern_file_write_ok($written, $data)) {
			return NULL;
		}

		$pattern_file_esc = escapeshellarg($pattern_file);
		exec("{$cmd_prefix} {$pattern_file_esc} {$cmd_suffix}", $lines);
	} finally {
		@unlink($pattern_file);
	}

	return $lines;
}


// Attribute the LAST line in $lines (grep's original order is preserved regardless of pattern
// order) that exactly equals $raw_entry — reproducing per-row exec()'s "last stdout line"
// semantics from a batched multi-pattern grep pass whose output interleaves every candidate's
// matches. A line belongs under either grep shape: unprefixed (single file matched, line IS
// the content) or file-prefixed ("path:content", path always contains '/', so the substring
// after the FIRST ':' is the content). The colon fallback requires the segment before ':' to
// contain '/', else an unprefixed IPv6 line could be mistaken for path-prefixed output.
function pfb_ip_prefetch_last_match(array $lines, string $raw_entry): ?string {
	if (pfb_ip_exact_entry_pattern($raw_entry) === NULL) {
		return NULL;
	}

	$match = NULL;
	foreach ($lines as $line) {
		if ($line === $raw_entry) {
			$match = $line;
			continue;
		}
		$colon_pos = strpos($line, ':');
		if ($colon_pos !== FALSE &&
		    strpos(substr($line, 0, $colon_pos), '/') !== FALSE &&
		    substr($line, $colon_pos + 1) === $raw_entry) {
			$match = $line;
		}
	}
	return $match;
}


// Batched sibling of find_reported_header(): resolves every host in $hosts against the SAME
// $pfbfolder/$geoip via one exact-match Round-A pass over ALL hosts, then Round B for any
// Round-A miss: one grep per DISTINCT first-octet (v4) / prefix (v6) group among the
// still-missing hosts (worst case one PER HOST under fully-diverse prefixes). At most two
// batched exec()s touch any ONE host, replacing one-to-two exec() calls run independently per
// host. Returns host => $pfb_query (['Unknown','Unknown'] on a total miss). Round A's batched
// grep can fail with a NULL sentinel (pattern file unwritable, distinct from a genuine
// zero-hit round); on that failure Round B does NOT run, and every host is reported via
// $grep_failed so the caller leaves them UNSEEDED rather than caching a false Unknown/Unknown.
function pfb_find_reported_headers(array $hosts, $pfbfolder, $geoip = FALSE, ?array &$grep_failed = NULL): array {
	global $pfb;

	$hosts = array_values(array_unique($hosts));
	$grep_failed = array();
	$out = array();
	foreach ($hosts as $host) {
		$out[$host] = array('Unknown', 'Unknown');
	}
	if (empty($hosts)) {
		return $out;
	}
	$geoip_lock = FALSE;
	if ($geoip) {
		$geoip_lock = pfb_geoip_generation_read_lock();
		if ($geoip_lock === FALSE) {
			$grep_failed = array_fill_keys($hosts, TRUE);
			return $out;
		}
	}

	// Round A (exact): same command shape as find_reported_header()'s exact-match exec,
	// batched into one `-f patternfile` pass. pfb_ip_prefetch_last_match() recovers each
	// host's own LAST matching line from the shared batched output, reproducing what a
	// per-row `exec()` (last-line-of-output) call would have returned for that host alone.
	$patterns = array();
	$valid_hosts = array();
	foreach ($hosts as $host) {
		$pattern = pfb_ip_exact_entry_pattern($host);
		if ($pattern !== NULL) {
			$patterns[] = $pattern;
			$valid_hosts[$host] = TRUE;
		}
	}
	// issue #833: /dev/null forces the same file-prefix output as find_reported_
	// header()'s own exact-match exec, even for a single-file $pfbfolder glob.
	$lines = pfb_ip_prefetch_grep_lines("{$pfb['grep']} -s -f", "{$pfbfolder} /dev/null 2>&1", $patterns);

	if ($lines === NULL) {
		$grep_failed = array_fill_keys($hosts, TRUE);
		pfb_geoip_generation_read_unlock($geoip_lock);
		return $out;
	}

	$missed = array();
	foreach ($hosts as $host) {
		if (!isset($valid_hosts[$host])) {
			continue;
		}
		$match = pfb_ip_prefetch_last_match($lines, $host);
		if ($match !== NULL) {
			$out[$host] = pfb_parse_query($match);
		} else {
			$missed[] = $host;
		}
	}

	if (empty($missed)) {
		pfb_geoip_generation_read_unlock($geoip_lock);
		return $out;
	}

	// Round B (prefix + CIDR): group the still-missing hosts by their IDENTICAL first-
	// octet (v4) / prefix (v6) query string -- find_reported_header()'s own query for that
	// host -- so hosts sharing one query run it exactly ONCE, then share pfb_match_
	// reported_cidr()'s CIDR walk over that one shared grep-output array.
	//
	// B4 (issue #809 review): the group key is qualified by address family ('4|'/'6|'
	// prefix) -- a bare $query alone (e.g. "10") collides between a v4 host ("10.0.0.5")
	// and an unrelated v6 host ("10::1"): both would fall into ONE shared group keyed
	// "10", and whichever host's entry created that group silently handed its
	// v4_type/grep pattern to the OTHER family's host too. 'query'/'v4_type' are stored IN
	// the group array and read back from there (never re-derived from the qualified key),
	// which also sidesteps strstr()'s FALSE-return being coerced to an int-0 array key for
	// a segmentless host.
	$groups = array();
	foreach ($missed as $host) {
		$v4_type = TRUE;
		if (substr_count($host, ':') > 1) {
			$query   = strstr($host, ':', TRUE);
			$v4_type = FALSE;
		} else {
			$query = strstr($host, '.', TRUE);
		}
		$gkey = ($v4_type ? '4|' : '6|') . $query;
		if (!isset($groups[$gkey])) {
			$groups[$gkey] = array('v4_type' => $v4_type, 'query' => $query, 'hosts' => array());
		}
		$groups[$gkey]['hosts'][] = $host;
	}

	foreach ($groups as $group) {
		if ($group['v4_type']) {
			$query_esc = escapeshellarg("^{$group['query']}\.");
		} else {
			$query_esc = escapeshellarg("^{$group['query']}:");
		}

		$result = array();
		if (!$geoip) {
			// issue #833: same /dev/null forced-prefix fix as Round A above.
			exec("{$pfb['grep']} -s {$query_esc} {$pfbfolder} /dev/null 2>&1", $result);
		} else {
			$geoip_list = "Africa\|Antarctica\|Asia\|Europe\|North_America\|South_America\|Oceania\|Proxy_and_Satellite\|Top_Spammers";
			exec("{$pfb['grep']} -s {$query_esc} {$pfb['ccdir']}/*.txt /dev/null | {$pfb['grep']} -v '{$geoip_list}' 2>&1", $result);
		}

		foreach ($group['hosts'] as $host) {
			$rx = pfb_match_reported_cidr($result, $host, $group['v4_type']);
			if ($rx !== NULL) {
				$out[$host] = $rx;
			}
		}
	}

	pfb_geoip_generation_read_unlock($geoip_lock);
	return $out;
}


// Batch every buffered, filter-ACCEPTED row's render-time IP lookups ahead of the per-type IP
// table's replay pass: the validate round (is the logged IP/CIDR still in its feed file), the
// miss round (find_reported_header()'s exact + prefix/CIDR search), and the aliastables round
// (which alias table now holds the resolved IP), each collapsed from one exec() per row to at
// most one grep pass per distinct group. Seeds pfb_ip_render_memos() —
// pfb_ip_render_attribution() consults the same stores, falling back to a per-row exec for
// anything unseeded.
// $rows: one entry per buffered, filter-accepted row — 'host', 'folder', 'pfb_geoip',
// 'eval_ip_raw', and 'validate_file_cmd'/'validate_cmd' from pfb_ip_render_query().
function pfb_ip_prefetch(array $rows): void {
	global $pfb;

	$geoip_lock = FALSE;
	$has_geoip = FALSE;
	foreach ($rows as $row) {
		if (!empty($row['pfb_geoip'])) {
			$has_geoip = TRUE;
			break;
		}
	}
	if ($has_geoip) {
		$geoip_lock = pfb_geoip_generation_read_lock();
	}
	$rows = array_values(array_filter($rows, static function (array $row) use ($has_geoip, $geoip_lock): bool {
		return empty($row['pfb_geoip']) || !$has_geoip || $geoip_lock !== FALSE;
	}));
	if (empty($rows)) {
		return;
	}

	$memos = &pfb_ip_render_memos();

	// --- Validate round: group by the shared file-listing pipeline -------------------
	$validate_groups = array();
	foreach ($rows as $row) {
		if ($row['validate_cmd'] === NULL) {
			continue;	// mirrors pfb_ip_render_attribution()'s no-exec guard -- never validated
		}
		if (array_key_exists($row['validate_cmd'], $memos['validate'])) {
			continue;	// already resolved (this row, or an identical earlier one)
		}
		$key = $row['validate_file_cmd'];
		if (!isset($validate_groups[$key])) {
			$validate_groups[$key] = array('file_cmd' => $row['validate_file_cmd'], 'entries' => array());
		}
		$validate_groups[$key]['entries'][$row['validate_cmd']] = $row['eval_ip_raw'];
	}

	foreach ($validate_groups as $group) {
		$patterns = array();
		foreach ($group['entries'] as $raw_ip) {
			$pattern = pfb_ip_exact_entry_pattern($raw_ip);
			if ($pattern !== NULL) {
				$patterns[] = $pattern;
			}
		}
		$patterns = array_values(array_unique($patterns));

		$lines = pfb_ip_prefetch_grep_lines("{$group['file_cmd']} | xargs {$pfb['grep']} -f", '2>&1', $patterns);
		if ($lines === NULL) {
			// B3 (issue #809 review): this group's pattern file could not be created/
			// written -- leave every row in it UNSEEDED (never cache a false ''/no-hit)
			// so pfb_ip_render_attribution()'s per-row exec fallback runs for them instead.
			continue;
		}

		foreach ($group['entries'] as $cmd => $raw_ip) {
			$memos['validate'][$cmd] = pfb_ip_prefetch_last_match($lines, $raw_ip) ?? '';
		}
	}

	// --- Miss round: every row whose (seeded or guard-absent) validate is empty -------
	$miss_rows = array();
	foreach ($rows as $row) {
		$seeded_validate = ($row['validate_cmd'] !== NULL) ? ($memos['validate'][$row['validate_cmd']] ?? '') : '';
		if (!empty($seeded_validate)) {
			continue;
		}
		$miss_key = "{$row['host']}|{$row['folder']}";
		if (isset($memos['miss'][$miss_key]) || isset($miss_rows[$miss_key])) {
			continue;	// already seeded (or a duplicate host+folder within this batch)
		}
		$miss_rows[$miss_key] = $row;
	}

	if (empty($miss_rows)) {
		pfb_geoip_generation_read_unlock($geoip_lock);
		return;
	}

	// Round A/B (batched find_reported_header()), grouped by folder. NOTE -- quirk
	// PRESERVED, not introduced by this phase: pfb_ip_render_attribution()'s miss-round call is
	// `find_reported_header($host, $folder)`, no third argument, so it ALWAYS runs with
	// $geoip=FALSE even for a GeoIP row (whose $folder already points at ccdir on its own,
	// so the exact-match round is unaffected either way -- only the prefix round's
	// continent-name exclusion differs). Reproduced verbatim: this call always passes
	// FALSE too, matching today's Alerts-page behaviour exactly.
	$hosts_by_folder = array();
	foreach ($miss_rows as $row) {
		$hosts_by_folder[$row['folder']][$row['host']] = TRUE;
	}

	// B3 (issue #809 review): a host whose Round-A batching failed for its folder-group
	// is reported via $grep_failed and excluded here entirely -- it never enters
	// $headers_by_host_folder, so it is skipped by BOTH rounds below and stays unseeded.
	$headers_by_host_folder = array();
	foreach ($hosts_by_folder as $folder => $hosts) {
		$headers = pfb_find_reported_headers(array_keys($hosts), $folder, FALSE, $grep_failed);
		foreach ($headers as $host => $pfb_query) {
			if (isset($grep_failed[$host])) {
				continue;
			}
			$headers_by_host_folder["{$host}|{$folder}"] = $pfb_query;
		}
	}

	// --- Aliastables round: ONE batched pass across every STILL-resolved miss row -----
	// A miss_key absent from $headers_by_host_folder (its find_reported_headers() call
	// failed above) is dropped from this round too -- left unseeded rather than seeded
	// with a wrong/placeholder value.
	$alias_patterns  = array();
	$eval_new_by_key = array();
	foreach ($miss_rows as $miss_key => $row) {
		if (!array_key_exists($miss_key, $headers_by_host_folder)) {
			continue;
		}
		// issue #833: find_reported_header()/pfb_find_reported_headers() now force
		// grep's file-prefix output at every exec() site (a trailing /dev/null), so
		// pfb_parse_query() always returns the 2-element [feed, value] shape -- the
		// issue #831 1-element skip-seed guard that used to live here is dead code,
		// removed.
		$pfb_query = $headers_by_host_folder[$miss_key];
		$eval_new = ($pfb_query[1] == 'Unknown') ? 'Not listed!' : $pfb_query[1];
		$eval_new_by_key[$miss_key] = $eval_new;
		$pattern = pfb_ip_exact_entry_pattern($eval_new);
		if ($pattern !== NULL) {
			$alias_patterns[] = $pattern;
		}
	}
	$alias_patterns = array_values(array_unique($alias_patterns));

	// issue #833: '/dev/null' rides ahead of xargs's own appended file list, so
	// grep always has >=2 files and always emits the "path:" prefix, matching
	// pfb_ip_render_attribution()'s per-row aliastables exec, which needs that same
	// forced-prefix fix for its downstream alias-name parse.
	$alias_lines = pfb_ip_prefetch_grep_lines(
		"/usr/bin/find {$pfb['aliasdir']}/*.txt -type f | xargs {$pfb['grep']} -f",
		'/dev/null 2>&1',
		$alias_patterns
	);
	if ($alias_lines === NULL) {
		// B3: the aliastables pattern file could not be created/written -- leave every
		// remaining row unseeded (per-row fallback fires for all of them).
		pfb_geoip_generation_read_unlock($geoip_lock);
		return;
	}

	foreach ($eval_new_by_key as $miss_key => $eval_new) {
		$pfb_query    = $headers_by_host_folder[$miss_key];
		$raw_validate = pfb_ip_prefetch_last_match($alias_lines, $eval_new) ?? '';
		$memos['miss'][$miss_key] = array($pfb_query, $raw_validate);
	}
	pfb_geoip_generation_read_unlock($geoip_lock);
}


// Test whether a single IP literal is contained within a CIDR range. Both the IP
// and the network of the CIDR are compared in their packed (inet_pton) binary form,
// byte-for-byte over the whole bytes of the prefix plus a masked compare of the
// remainder bit. Returns TRUE when $ip lies inside $cidr, FALSE otherwise (including
// a parse failure or a family mismatch between $ip and $cidr). Single source of the
// binary-containment math, shared by pfb_ip_is_internal() and the feed-host
// allowlist check.
function pfb_ip_in_cidr($ip, $cidr) {

	if (!is_string($ip) || $ip === '' || !is_string($cidr) || strpos($cidr, '/') === FALSE) {
		return FALSE;
	}

	$bin = @inet_pton($ip);
	if ($bin === FALSE) {
		return FALSE;
	}

	list($net, $bits) = explode('/', $cidr, 2);
	$net_bin = @inet_pton($net);
	if ($net_bin === FALSE || strlen($net_bin) !== strlen($bin)) {
		// A parse failure or a family mismatch (v4 ip vs v6 cidr or vice versa).
		return FALSE;
	}

	$bits = (int) $bits;
	$full = intdiv($bits, 8);		// whole bytes that must match exactly
	$rem  = $bits % 8;			// remaining bits in the next byte

	if ($full > 0 && substr($bin, 0, $full) !== substr($net_bin, 0, $full)) {
		return FALSE;
	}
	if ($rem !== 0) {
		$mask = (~0 << (8 - $rem)) & 0xFF;
		if ((ord($bin[$full]) & $mask) !== (ord($net_bin[$full]) & $mask)) {
			return FALSE;
		}
	}

	return TRUE;
}


// Test whether a single IP literal falls inside one of the non-public/reserved
// ranges feeds may not be fetched from. Returns the matched CIDR (string) when
// the address is non-permitted, or FALSE when it is a routable public address.
// IPv4-mapped IPv6 (::ffff:0:0/96) is unwrapped and re-checked as IPv4 so a
// mapped form can't slip a private v4 address past the v6 ranges.
function pfb_ip_is_internal($ip) {

	// Non-permitted v4 / v6 ranges (CIDR). The exact set is explicit (rather than
	// the pfSense range helpers) so it is identical across releases.
	static $ranges_v4 = array(
		'0.0.0.0/8',		// 'this' network (RFC 1122)
		'10.0.0.0/8',		// private (RFC 1918)
		'100.64.0.0/10',	// CGNAT shared address space (RFC 6598)
		'127.0.0.0/8',		// loopback
		'169.254.0.0/16',	// link-local (RFC 3927)
		'172.16.0.0/12',	// private (RFC 1918)
		'192.168.0.0/16',	// private (RFC 1918)
	);
	static $ranges_v6 = array(
		'::1/128',		// loopback
		'fc00::/7',		// unique-local (RFC 4193)
		'fe80::/10',		// link-local (RFC 4291)
	);

	if (!is_string($ip) || $ip === '') {
		return FALSE;
	}

	$bin = @inet_pton($ip);
	if ($bin === FALSE) {
		return FALSE;
	}

	// Unwrap an IPv4-mapped IPv6 address (::ffff:0:0/96) to its IPv4 form so it is
	// vetted against the IPv4 ranges, not skipped by the v6 set.
	if (strlen($bin) === 16 && str_starts_with($bin, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff")) {
		$ip = inet_ntop(substr($bin, 12));
		$bin = substr($bin, 12);
	}

	if (strlen($bin) === 4) {
		$ranges = $ranges_v4;
	} elseif (strlen($bin) === 16) {
		$ranges = $ranges_v6;
	} else {
		return FALSE;
	}

	foreach ($ranges as $cidr) {
		if (pfb_ip_in_cidr($ip, $cidr)) {
			return $cidr;
		}
	}

	return FALSE;
}


// Parse the General-settings 'internal-address exemption' allowlist into a list of
// valid IP/CIDR entries. The stored value is one entry per line (also accepting
// comma/space separators); blank and invalid entries are silently dropped (only a
// valid is_ipaddr() literal or an is_subnet() CIDR survives). $ignored receives the
// count of non-blank entries that were rejected as invalid (for a neutral log line).
function pfb_feed_internal_allowlist($ignored = NULL) {

	$ignored = 0;
	$raw = PfbConfig::read('gen/pfb_feed_internal_allowlist');
	if (!is_string($raw) || $raw === '') {
		return array();
	}

	// The allowlist is stored base64-encoded, like every other pfBlockerNG textarea
	// (suppression / whitelist / custom; see pfb_text_area_decode). Decode before
	// parsing; an undecodable value yields no entries, so the filter stays fail-closed.
	$raw = (string) base64_decode($raw);

	$entries = array();
	foreach (preg_split('/[\s,]+/', $raw) as $entry) {
		$entry = trim($entry);
		if ($entry === '') {
			continue;
		}
		if (is_ipaddr($entry) || is_subnet($entry)) {
			$entries[] = $entry;
		} else {
			$ignored++;
		}
	}

	return $entries;
}


// Test whether a single IP literal is exempted by the allowlist: covered when it
// equals an allowlisted IP literal (by value) or is contained within an allowlisted
// CIDR. Returns TRUE when exempt, FALSE otherwise.
function pfb_ip_in_allowlist($ip, array $allowlist) {

	if (!is_string($ip) || $ip === '') {
		return FALSE;
	}

	$bin = @inet_pton($ip);

	foreach ($allowlist as $entry) {
		if (strpos($entry, '/') !== FALSE) {
			if (pfb_ip_in_cidr($ip, $entry)) {
				return TRUE;
			}
		} elseif ($bin !== FALSE && @inet_pton($entry) === $bin) {
			// IP-literal equality by packed value (so '::1' == '::0:1' etc.).
			return TRUE;
		}
	}

	return FALSE;
}


// issue #1907: one-time upgrade migration disabling pfb_py_reply/pfb_hsts when a stored
// 'on' was inert under pre-upgrade Unbound mode. Both were python-gated in 3.2
// ($mode == 'enabled' && dnsbl_mode == 'dnsbl_python'), so a stored 'on' under Unbound
// mode never actually took effect -- the #1907 default-on flip would otherwise silently
// activate it on upgrade. MUST run before adr02-dnsbl-python-mode, which overwrites
// dnsbl_mode and destroys the evidence this migration reads.
//
// $dconfig is the existing DNSBL-settings 'config/0' node. Guard: 'dnsbl_mode' must be
// PRESENT and NOT 'dnsbl_python' -- key-present-and-non-python is the only reliable
// pre-upgrade-Unbound-mode evidence. A fresh-4.0 install's registry-seeded section never
// carries 'dnsbl_mode' at all (the registry pass seeds only registered keys, and
// dnsbl_mode is unregistered), so an absent key must never be treated as pre-upgrade
// evidence -- that would wrongly disable a fresh install's seeded default-on toggle.
// Returns the updated config array to persist, or NULL when nothing should change.
function pfb_python_gated_toggles_migrate($dconfig) {

	if (!is_array($dconfig) || empty($dconfig)) {
		return NULL;
	}
	if (!array_key_exists('dnsbl_mode', $dconfig) || $dconfig['dnsbl_mode'] === 'dnsbl_python') {
		return NULL;
	}

	$changed = FALSE;
	foreach (array('pfb_py_reply', 'pfb_hsts') as $key) {
		if (($dconfig[$key] ?? '') === 'on') {
			$dconfig[$key] = 'off';
			$changed = TRUE;
		}
	}

	return $changed ? $dconfig : NULL;
}


// ADR-02: one-time upgrade migration for the DNSBL python-only mode. $dconfig is the
// existing DNSBL-settings 'config/0' node. Forces 'dnsbl_mode' to 'dnsbl_python' and
// 'pfb_py_block' to 'on'. Idempotent: returns NULL when both keys already carry the target
// values (or when the section is empty/absent — no prior DNSBL config = nothing to migrate).
// Returns the updated config array to persist, or NULL when nothing should change.
function pfb_dnsbl_python_migrate($dconfig) {

	if (!is_array($dconfig) || empty($dconfig)) {
		return NULL;
	}
	if (($dconfig['dnsbl_mode'] ?? '') === 'dnsbl_python' && ($dconfig['pfb_py_block'] ?? '') === 'on') {
		return NULL;
	}
	$dconfig['dnsbl_mode']   = 'dnsbl_python';
	$dconfig['pfb_py_block'] = 'on';
	return $dconfig;
}


// PFBL-03: one-time upgrade seed for the deprecated legacy DNS-TXT control sub-toggle.
// $dconfig is the DNSBL-settings 'config/0' node; DNS-TXT transport is OFF by default, so to
// avoid breaking an operator already driving control over DNS TXT, the legacy sub-toggle is
// seeded ON IFF the pre-existing config already had 'pfb_control' == 'on'. A one-shot marker
// ('pfb_control_legacy_seeded') makes this run EXACTLY ONCE, so a later save never re-enables
// a toggle the operator turned back off. Returns the updated config, or NULL when nothing
// changes (empty config, or already seeded). Slated for removal with the legacy DNS-TXT path.
function pfb_control_legacy_seed($dconfig) {

	if (!is_array($dconfig) || empty($dconfig)) {
		return NULL;
	}
	if (($dconfig['pfb_control_legacy_seeded'] ?? '') === 'on') {
		return NULL;
	}
	if (($dconfig['pfb_control'] ?? '') == 'on') {
		$dconfig['pfb_control_legacy'] = 'on';
	}
	$dconfig['pfb_control_legacy_seeded'] = 'on';
	return $dconfig;
}


// issue #2371: fresh-install detector for the feed-at-suffix PSL policy fields
// (dnsbl/pfb_psl_feed_private_policy, dnsbl/pfb_psl_feed_icann_policy). Same
// empty($dconfig)-on-the-operator-view idiom as pfb_schedule_migrate's $is_fresh, but
// DELIBERATELY NOT an entry in pfb_migration_registry() and NOT called from
// pfb_run_migrations(): every pfb_migration_registry() entry's write lands BEFORE
// pfb_registry_pass() re-reads the section for its own per-section NEWCFG/OLDCFG mode
// decision (issue #1921) -- seeding new keys into an otherwise-EMPTY dnsbl section
// there would flip that section's mode to OLDCFG for every OTHER registered dnsbl/*
// field before the pass ever sees it, wrongly applying an ABSENT-grandfather map meant
// only for a genuine upgrade. Confirmed against dnsbl/pfb_dnsbl_lenient (grandfather
// ABSENT -> 'on') via an executed probe: the same latent interaction already reaches
// gen/pfb_alias_delta_mode through pfb_schedule_migrate (#2308) today, empirically
// observed to yield 'replace' instead of the intended fresh-install 'auto'. #2371 does
// not fix that pre-existing interaction; it avoids adding a second instance of it by
// keeping this seed OUTSIDE pfb_migration_registry() entirely.
//
// pfblockerng_install.inc calls this on the section read BEFORE pfb_run_migrations()/
// pfb_registry_pass() run, then -- only when it returns TRUE -- applies the seed via
// PfbConfig::writeSystem() AFTER pfb_install_registry_writeback() has already persisted
// the registry pass's own (unrelated) '' defaults for these two fields.
//
// $dconfig is the DNSBL-settings 'config/0' node, read pre-mutation. Returns TRUE iff
// the section is genuinely fresh (empty under the operator view -- issues
// #1770/#1771/#1775), else FALSE.
function pfb_psl_feed_policy_is_fresh_install($dconfig) {

	if (!is_array($dconfig)) {
		return FALSE;
	}
	return empty(pfb_gconfig_operator_view($dconfig));
}


// issue #1898: the compatibility-only stored-key rename this migration still owns -- the
// dynamic per-feed row key. The scalar-section renames (TOP1M, TLD Allow, TLD Wildcard)
// now live as registry 'old_name' slots consumed by pfb_registry_pass() (issue #1921);
// this array covers only what that pass cannot reach, a key inside a per-row list section
// rather than a flat scalar section.
const PFB_LEGACY_KEY_RENAMES = array(
	array(
		'section' => 'installedpackages/pfblockerngdnsbl/config',
		'rows'    => TRUE,
		'keys'    => array('filter_alexa' => 'filter_top1m'),
	),
);


// Rename the retired keys inside ONE flat key => value node (a scalar section, or one feed
// row). Preflight per key: old absent -> nothing to do (covers both "never had it" and
// "already migrated"); old present, new absent -> move; both present and identical -> keep
// the new key and drop the old; both present and different -> a conflict this function
// refuses to resolve. The comparison is strict on the RAW stored value, because picking a
// winner is exactly the guess issue #1898 forbids. $changed / $conflicts accumulate across
// every node so the caller's decision stays all-or-nothing.
function pfb_legacy_key_rename_node(array $node, array $keys, $where, &$changed, array &$conflicts) {

	foreach ($keys as $old => $new) {
		if (!array_key_exists($old, $node)) {
			continue;
		}
		if (array_key_exists($new, $node) && $node[$old] !== $node[$new]) {
			$conflicts[] = "{$where}: [{$old}] and [{$new}] are both present with different values";
			continue;
		}
		if (!array_key_exists($new, $node)) {
			$node[$new] = $node[$old];
		}
		unset($node[$old]);
		$changed = TRUE;
	}

	return $node;
}


// Issue #1898: the one-time forward migration off the retired PER-ROW key name(s). Pure --
// it takes the section blobs the driver read and returns the blobs to persist, or NULL for a
// no-op (fresh install, already migrated, or a conflict). Atomic across every row: one
// unresolvable pair abandons the entire migration rather than leaving a row half-renamed, and
// the notice names the two keys but never their values. issue #1921: the scalar-section half
// of #1898 (TOP1M, TLD Allow, TLD Wildcard) now lives as registry 'old_name' slots consumed
// by pfb_registry_pass(), which is per-KEY (a conflict on one key never blocks its siblings);
// this migration keeps the dynamic per-feed row key, which pfb_registry_pass() cannot reach,
// and stays all-or-nothing across its rows.
function pfb_legacy_key_rename_migrate($sections) {

	if (!is_array($sections)) {
		return NULL;
	}

	$updated   = array();
	$changed   = FALSE;
	$conflicts = array();

	foreach (PFB_LEGACY_KEY_RENAMES as $spec) {
		$blob = $sections[$spec['section']] ?? array();
		if (!is_array($blob)) {
			continue;
		}
		if ($spec['rows']) {
			foreach ($blob as $index => $row) {
				if (is_array($row)) {
					$blob[$index] = pfb_legacy_key_rename_node($row, $spec['keys'],
						"{$spec['section']}/{$index}", $changed, $conflicts);
				}
			}
		} else {
			$blob = pfb_legacy_key_rename_node($blob, $spec['keys'], $spec['section'], $changed, $conflicts);
		}
		$updated[$spec['section']] = $blob;
	}

	if (!empty($conflicts)) {
		file_notice('pfBlockerNG',
			gettext('pfBlockerNG left the legacy configuration key names in place: ')
			. implode('; ', $conflicts)
			. gettext('. Remove the stale duplicate, or set both keys to the same value, then reinstall the package.'),
			'pfBlockerNG', '/pfblockerng/pfblockerng_dnsbl.php', 2);
		return NULL;
	}

	return $changed ? $updated : NULL;
}


/** @return array<string, string> Section path => NEWCFG/OLDCFG map. */
function pfb_registry_section_modes(array $sections): array {

	$modes = array();
	foreach (PFB_SECTIONS as $section) {
		$blob = $sections[$section] ?? array();
		$modes[$section] = is_array($blob) && !empty(pfb_gconfig_operator_view($blob)) ? 'OLDCFG' : 'NEWCFG';
	}
	return $modes;
}


/**
 * pfb_registry_pass — the one registry-driven install/upgrade pass (issue #1921).
 *
 * Replaces the former seeding pass, the scalar rename migration, and the four
 * grandfather/preservation migrations (#1887 x2, ADR-22, issue #281). For every
 * registered key, in registry order: RENAME -> GRANDFATHER-MAP -> SEED, as branch
 * order within that one key -- never three separate passes over the registry.
 *
 * Mode is computed ONCE per section, before any key in that section is mutated:
 * OLDCFG iff the blob is an array and pfb_gconfig_operator_view() of it is non-empty
 * (real operator data beyond the installer's own settings_family marker); otherwise
 * NEWCFG (covers a genuinely fresh install AND a marker-only section -- #1770/#1771/
 * #1775). A non-array blob is treated as empty. gen/settings_family itself is SKIPPED
 * entirely -- it is the mode instrument pfb_settings_family_record() owns, never a
 * peer row this pass renames/maps/seeds.
 *
 * NEWCFG: the key takes its registered default -- passed once through the grandfather
 * map's own non-ABSENT entries (the ABSENT entry itself is never consulted; it
 * specifically signals an EXISTING install, which a NEWCFG section by definition is
	 * not). A registered default can collide with its own map's non-ABSENT input;
	 * materialising the raw default there would
 * mint a value only to have the very next OLDCFG pass (the section is no longer empty
 * once seeded) immediately re-map it, breaking idempotency across a fresh install's
 * first upgrade. Running the default through the SAME lookup once, up front, is a
 * no-op for every other key and a stable fixed point for these -- the registry gate's
 * fixpoint rule below then guarantees no later pass can move it again.
 *
 * OLDCFG, per key:
 *   1. RENAME (only when 'old_name' is set and the old key is present): new absent ->
 *      move the value verbatim (any type, '' and '0' included), old unset. Both present
 *      and identical (===) -> keep new, drop old. Both present and different -> keep the
 *      new key's value, LEAVE THE OLD KEY IN PLACE, and record a conflict -- per-key, not
 *      all-or-nothing; every other key in the section is still processed.
 *   2. GRANDFATHER MAP: absent -> 'grandfather'[PFB_GF_ABSENT] if declared, else fall to
 *      SEED below. Present and a string -> 'grandfather'[value] if declared, else the
 *      value unchanged (identity). Present and NOT a string -> the value untouched,
 *      never used as a map key.
 *   3. SEED: absent with no ABSENT grandfather entry -> the registered default.
 *
 * Idempotent by construction: a present key short-circuits every RENAME/GRANDFATHER
 * branch above into identity, and the registry gate (CfgRegistryGrandfatherGateTest's
 * fixpoint check) guarantees a grandfather map's OUTPUT is never also one of its own
 * non-ABSENT INPUTs, so a repeat pass can never oscillate a value. '' is a stored value,
 * not absence -- it moves and maps exactly like any other value; only genuine
 * array_key_exists() absence is treated as absence.
 *
 * After the loop, one file_notice() names every RENAME conflict's key pair (never the
 * values -- these fields hold base64 blobs) if any fired; it does not abort anything.
 *
 * Pure: takes the section blobs the driver read, returns ONLY the sections whose blob
 * differs (!==) from the input -- the caller persists exactly those.
 *
 * @param  array      $sections  Section path => blob map (same shape the former seeding
 *                                pass took).
 * @param  array|null $registry  Defaults to pfb_cfg_registry(); parameter exists only so
 *                                a fixture registry can drive the pass in tests.
 * @param  array|null $modes     Optional pre-migration section path => NEWCFG/OLDCFG map.
 * @return array                 Section path => blob map, changed sections only.
 */
function pfb_registry_pass(array $sections, ?array $registry = NULL, ?array $modes = NULL): array {

	$registry = $registry ?? pfb_cfg_registry();

	$original = array();
	foreach (PFB_SECTIONS as $section) {
		$blob = $sections[$section] ?? array();
		if (!is_array($blob)) {
			$blob = array();
		}
		$original[$section] = $blob;
	}
	$modes = $modes ?? pfb_registry_section_modes($original);

	$result    = $original;
	$conflicts = array();

	foreach ($registry as $path_key => $entry) {
		if ($path_key === 'gen/settings_family') {
			continue;
		}
		[$alias, $key] = explode('/', $path_key, 2);
		$section = PFB_SECTIONS[$alias];
		$blob    = $result[$section];
		$map     = $entry['grandfather'] ?? array();

		// issue #1921: the registered default, stabilised through the map's own
		// non-ABSENT entries once -- a no-op unless the default itself collides with a
		// map input (see the docblock). Shared by NEWCFG's seed and OLDCFG's
		// absent-with-no-ABSENT-entry seed below, so a value freshly materialised by
		// EITHER path can never be moved again by a later OLDCFG pass once the section
		// is no longer empty.
		$default        = $entry['default'];
		$stable_default = (is_string($default) && array_key_exists($default, $map)) ? $map[$default] : $default;

		if ($modes[$section] === 'NEWCFG') {
			// The ABSENT map entry never applies here -- it specifically signals an
			// EXISTING install, which a NEWCFG section by definition is not.
			$blob[$key]      = $stable_default;
			$result[$section] = $blob;
			continue;
		}

		// OLDCFG -- 1) RENAME.
		if (isset($entry['old_name']) && array_key_exists($entry['old_name'], $blob)) {
			$old = $entry['old_name'];
			if (!array_key_exists($key, $blob)) {
				$blob[$key] = $blob[$old];
				unset($blob[$old]);
			} elseif ($blob[$key] === $blob[$old]) {
				unset($blob[$old]);
			} else {
				$conflicts[] = "{$section}: [{$old}] and [{$key}] are both present with different values";
			}
		}

		// 2) GRANDFATHER MAP, then 3) SEED.
		if (!array_key_exists($key, $blob)) {
			$blob[$key] = array_key_exists(PFB_GF_ABSENT, $map) ? $map[PFB_GF_ABSENT] : $stable_default;
		} elseif (is_string($blob[$key]) && array_key_exists($blob[$key], $map)) {
			$blob[$key] = $map[$blob[$key]];
		}
		// else: present and (non-string, or a string with no map entry) -- identity, untouched.

		$result[$section] = $blob;
	}

	if (!empty($conflicts)) {
		// The notice links the DNSBL settings page because every current 'old_name'
		// lives in that section; a future gen/ip old_name needs a per-section link.
		file_notice('pfBlockerNG',
			gettext('pfBlockerNG left the legacy configuration key names in place: ')
			. implode('; ', $conflicts)
			. gettext('. Remove the stale duplicate, or set both keys to the same value, then reinstall the package.'),
			'pfBlockerNG', '/pfblockerng/pfblockerng_dnsbl.php', 2);
	}

	$changed = array();
	foreach ($result as $section => $blob) {
		if ($blob !== $original[$section]) {
			$changed[$section] = $blob;
		}
	}
	return $changed;
}


// Whether the feed-host internal-address filter is enabled. Reads the General-settings
// 'pfb_feed_internal_filter' on/off flag. Absence uses the registered On default; present
// empty and legacy 'off' are Off. issue #1887: reads the enum through the gateway — junk
// now falls back to Off like every other toggle (it was "anything but 'off' is ON"), and
// case variants are recognised.
function pfb_feed_filter_enabled(): bool {

	return PfbConfig::read('gen/pfb_feed_internal_filter') === PfbToggle::On;
}


// Whether a resolved candidate IP is the firewall itself — its own configured address,
// or the IPv4/IPv6 loopback. A self-hosted feed (served by the box) is a long-supported
// pfBlockerNG case (see PFB_FILTER_URL), so a self IP is treated as allowed even though
// it is non-public; it is never the internal-pivot case the filter guards against.
function pfb_ip_is_self($ip) {

	if (!is_string($ip) || $ip === '') {
		return FALSE;
	}

	return ($ip === '127.0.0.1' || $ip === '::1' || is_ipaddr_configured($ip));
}


// Verify a feed host does not resolve to a non-public/reserved address before any connection
// is made. Fail-closed: an unresolvable host, or any resolved address that is non-public AND
// not covered by the operator's internal-address allowlist, is rejected. On success $pinned
// receives the vetted IP the caller pins the connection to (so the fetch cannot rebind to
// another address); $reason carries a neutral skip reason on rejection. A resolved address is
// permitted when public, self-hosted (firewall's own address/loopback), or allowlisted (exact
// IP or CIDR containment, General settings 'internal-address exemptions'); an empty allowlist
// (default) blocks every other internal/private-resolving feed.
function pfb_feed_host_allowed($host, &$reason, &$pinned) {

	$reason = '';
	$pinned = '';

	if (!is_string($host) || $host === '') {
		$reason = 'feed host is empty';
		return FALSE;
	}

	// Build the candidate IP list. A host that is already an IP literal is checked
	// directly; otherwise it is resolved (A/AAAA, following CNAMEs as the URL
	// validator does) into its address set.
	$candidates = array();
	if (is_ipaddr($host)) {
		$candidates[] = $host;
	} else {
		$records = resolve_host_addresses("{$host}.");
		if (empty($records) || !is_array($records)) {
			$reason = 'feed host did not resolve';
			return FALSE;
		}
		foreach ($records as $record) {
			if (empty($record['data'])) {
				continue;
			}
			if ($record['type'] == 'CNAME') {
				$cname = is_ipaddr($record['data'])
				    ? array(array('type' => 'A', 'data' => $record['data']))
				    : resolve_host_addresses("{$record['data']}.");
				if (!empty($cname) && is_array($cname)) {
					foreach ($cname as $centry) {
						if (!empty($centry['data']) && is_ipaddr($centry['data'])) {
							$candidates[] = $centry['data'];
						}
					}
				}
				continue;
			}
			if (is_ipaddr($record['data'])) {
				$candidates[] = $record['data'];
			}
		}
	}

	if (empty($candidates)) {
		$reason = 'feed host did not resolve to a valid address';
		return FALSE;
	}

	$allowlist = pfb_feed_internal_allowlist();

	// Reject if ANY resolved address is internal and neither the firewall itself nor
	// allowlisted (fail-closed). The self-exemption is per-candidate: a host resolving
	// to [box-self, foreign-internal] still rejects on the foreign-internal address.
	// Pin the first vetted address for the connection — by the time the loop completes
	// every candidate is public, self, or allowlisted, so pinning the first is safe
	// (and lets a self / allowlisted internal mirror's IP become the pinned target).
	foreach ($candidates as $candidate) {
		if (pfb_ip_is_internal($candidate) !== FALSE &&
		    !pfb_ip_is_self($candidate) &&
		    !pfb_ip_in_allowlist($candidate, $allowlist)) {
			$reason = 'feed host resolves to a non-permitted address';
			return FALSE;
		}
		if ($pinned === '') {
			$pinned = $candidate;
		}
	}

	return TRUE;
}


// Issue #811: shared entry-reject logger. When a feed URL fails PFB_FILTER_URL vetting,
// pfb_filter() logs its reject to error.log only — so when the CAUSE is the feed-host
// guard (an internal-resolving host), the reason never reaches the main log. Every
// entry-reject site calls this to re-run the guard and, iff the guard is why vetting
// failed, land the same header-scoped "[ header ] <reason> — skipped" line the
// fetch-time gates in pfb_download() emit. Any other rejection reason logs nothing here.
function pfb_log_feed_host_reject($list_url, $header, $logtype) {

	if (!pfb_feed_filter_enabled()) {
		return;
	}
	// Only speak for the guard when the URL would have REACHED the guard: pfb_filter()
	// rejects a disallowed scheme before ever consulting pfb_feed_host_allowed(), so a
	// bad-scheme URL whose host happens to resolve internally must NOT be attributed to
	// the SSRF guard. Mirror pfb_filter()'s scheme allow-list (the host::module rsync
	// form has no scheme and is covered by pfb_download()'s own rsync gate instead).
	$entry_scheme = strtolower((string) (parse_url($list_url, PHP_URL_SCHEME) ?: ''));
	if (!in_array($entry_scheme, array('http', 'https', 'rsync', 'ftp'), TRUE)) {
		return;
	}
	$entry_host = parse_url($list_url, PHP_URL_HOST) ?: '';
	if ($entry_host === '') {
		return;
	}
	$entry_reason = '';
	$entry_pinned = '';
	if (!pfb_feed_host_allowed($entry_host, $entry_reason, $entry_pinned)) {
		$log = "\n[ {$header} ] {$entry_reason} \xe2\x80\x94 skipped\n";
		pfb_logger("{$log}", "{$logtype}");
	}
}


// Resolve a (possibly relative) HTTP redirect Location against the URL it was
// returned from, then re-run the feed-host guard on the redirect target so a
// redirect cannot send the fetch to a non-permitted address. Returns FALSE when
// the target host is not permitted (or the Location cannot be resolved to an
// absolute http(s) URL); $reason carries a neutral skip reason. On success it
// returns array('url' => <absolute target URL>, 'host' => <host>, 'scheme' =>
// <scheme>, 'port' => <int port>) and $pinned receives the vetted IP the caller
// re-pins the connection to. The curl mechanics stay in pfb_download(); this
// holds only the per-hop decision so it is unit-testable off-appliance.
function pfb_feed_redirect_target($location, $current_url, &$reason, &$pinned) {

	$reason = '';
	$pinned = '';

	if (!is_string($location) || pfb_is_blank($location)) {
		$reason = 'feed redirect has no target';
		return FALSE;
	}
	$location = trim($location);

	// Resolve a possibly-relative Location against the current absolute URL.
	$target = pfb_resolve_relative_url($location, (string) $current_url);
	if ($target === '') {
		$reason = 'feed redirect target could not be resolved';
		return FALSE;
	}

	$parts	= parse_url($target);
	$host	= $parts['host'] ?? '';
	$scheme	= strtolower($parts['scheme'] ?? '');
	if ($host === '' || ($scheme !== 'http' && $scheme !== 'https')) {
		$reason = 'feed redirect target is not an http(s) URL';
		return FALSE;
	}

	if (!pfb_feed_host_allowed($host, $reason, $pinned)) {
		// $reason already carries the neutral guard reason.
		return FALSE;
	}

	$scheme_ports	= array('http' => 80, 'https' => 443);
	$port		= (int) ($parts['port'] ?? ($scheme_ports[$scheme] ?? 0));

	return array(
		'url'    => $target,
		'host'   => $host,
		'scheme' => $scheme,
		'port'   => $port,
	);
}


// Resolve a possibly-relative URL reference ($ref) against an absolute base URL
// ($base), returning an absolute URL string (or '' on failure). Handles an
// already-absolute reference, a scheme-relative '//host/path', an absolute-path
// '/path', and a relative-path reference (resolved against the base directory).
// A minimal RFC 3986-style resolver, sufficient for following HTTP redirects.
function pfb_resolve_relative_url($ref, $base) {

	if (!is_string($ref) || $ref === '') {
		return '';
	}

	// Already absolute (has a scheme).
	if (preg_match('#^[a-zA-Z][a-zA-Z0-9+.-]*://#', $ref)) {
		return $ref;
	}

	$bparts = parse_url((string) $base);
	$bscheme = strtolower($bparts['scheme'] ?? '');
	$bhost   = $bparts['host'] ?? '';
	if ($bscheme === '' || $bhost === '') {
		return '';
	}
	$bauth = $bhost . (isset($bparts['port']) ? ':' . $bparts['port'] : '');

	// Scheme-relative reference: //host/path
	if (strncmp($ref, '//', 2) === 0) {
		return "{$bscheme}:{$ref}";
	}

	// Absolute-path reference: /path
	if ($ref[0] === '/') {
		return "{$bscheme}://{$bauth}{$ref}";
	}

	// Relative-path reference: resolve against the base path's directory.
	$bpath = $bparts['path'] ?? '/';
	$dir   = (strpos($bpath, '/') !== FALSE) ? substr($bpath, 0, strrpos($bpath, '/') + 1) : '/';
	if ($dir === '' || $dir[0] !== '/') {
		$dir = '/' . $dir;
	}
	return "{$bscheme}://{$bauth}{$dir}{$ref}";
}


// Rebuild an rsync feed source so it connects to the vetted IP instead of the
// hostname (the guard's pinned address), keeping the module/path intact. Accepts
// both rsync forms: 'host::module/path' -> 'IP::module/path', and
// 'rsync://host/path' -> 'rsync://IP/path' (preserving an explicit port and any
// user@ prefix). Returns '' when the form cannot be parsed to substitute the host
// (caller fails closed). $ip must be a vetted IP literal.
function pfb_rsync_pin_url($list_url, $ip) {

	if (!is_string($list_url) || $list_url === '' || !is_string($ip) || $ip === '') {
		return '';
	}

	// Bracket an IPv6 literal for the rsync:// (URL) form.
	$ip_url = (strpos($ip, ':') !== FALSE) ? "[{$ip}]" : $ip;

	// rsync://[user@]host[:port]/path
	if (stripos($list_url, 'rsync://') === 0) {
		$rest = substr($list_url, strlen('rsync://'));
		// Split off the path (everything from the first '/').
		$slash = strpos($rest, '/');
		$authority = ($slash === FALSE) ? $rest : substr($rest, 0, $slash);
		$path = ($slash === FALSE) ? '' : substr($rest, $slash);
		if ($authority === '') {
			return '';
		}
		// Preserve a 'user@' prefix; drop the host[:port], substitute the IP.
		$at = strrpos($authority, '@');
		$userpart = ($at === FALSE) ? '' : substr($authority, 0, $at + 1);
		$hostport = ($at === FALSE) ? $authority : substr($authority, $at + 1);
		// Carry over an explicit ':port' (last colon, but not inside an IPv6 [..]).
		$port = '';
		if ($hostport !== '' && $hostport[0] !== '[') {
			$colon = strrpos($hostport, ':');
			if ($colon !== FALSE) {
				$port = substr($hostport, $colon);
			}
		}
		return "rsync://{$userpart}{$ip_url}{$port}{$path}";
	}

	// [user@]host::module/path
	if (strpos($list_url, '::') !== FALSE) {
		list($hostpart, $module) = explode('::', $list_url, 2);
		if ($hostpart === '') {
			return '';
		}
		$at = strrpos($hostpart, '@');
		$userpart = ($at === FALSE) ? '' : substr($hostpart, 0, $at + 1);
		return "{$userpart}{$ip}::{$module}";
	}

	return '';
}

// Issue #2876: build the rsync feed-transfer spawn under a whole-transfer
// wall-clock deadline. rsync's own --timeout is a maximum I/O timeout — it
// fires only when NO data moves for that interval, so a peer that trickles one
// byte per interval resets it forever and the exec() below would wait
// unboundedly; the byte ceiling (#2667) bounds disk, not elapsed time. The
// wrapper is timeout(1) in its DEFAULT (reaper) mode on purpose: rsync may
// start remote-shell descendants, and a hung transfer must die as a whole tree
// on expiry (docs/misc/external-process-waits.md "Choosing the mode") —
// --foreground would kill only the direct child and orphan the rest, whose
// inherited stdio could even hold exec()'s capture pipe open. The budget is
// the SAME per-feed whole-transfer deadline the cURL path already applies to
// the same download (CURLOPT_TIMEOUT, PfbDownloadRequest::$timeout; every
// caller passes 300), so the two transports for one feed share one settled
// product value — no new operator setting, floored at one second so a
// degenerate value can never disable the bound. $pfb['timeout'] and
// $pfb['rsync_bin'] are the established off-appliance injection points,
// mirroring pfb_reentry_cmd()'s $pfb['timeout'] / $pfb['php']. $src/$dst
// arrive unescaped and are escaped here, exactly once.
function pfb_rsync_transfer_cmd(string $src, string $dst, int $blocks, int $budget): string {
	global $pfb;

	$timeout_esc = escapeshellarg($pfb['timeout'] ?? '/usr/bin/timeout');
	$rsync_esc   = escapeshellarg($pfb['rsync_bin'] ?? '/usr/local/bin/rsync');
	$src_esc     = escapeshellarg($src);
	$dst_esc     = escapeshellarg($dst);

	return pfb_extract_cmd("{$timeout_esc} -s TERM -k " . PFB_HOOK_KILL_GRACE . ' ' .
		max(1, $budget) . " {$rsync_esc} --timeout=5 {$src_esc} {$dst_esc}", $blocks);
}


// Issue #890: redact the query string and userinfo ('user:pass@') from a feed/download URL
// before it is written to any log — either can carry a credential, and log files ship inside
// pfSense support bundles. scheme/host/port/path are kept for diagnosability. A well-formed
// http(s)/ftp/rsync:// URL is rebuilt from parse_url() (userinfo dropped, query replaced with
// '[redacted]'); anything parse_url() can't parse (malformed input, or the '[user@]host::module'
// rsync shorthand) falls back to a regex strip — when in doubt this over-redacts.
function pfb_redact_url($url) {
	if (!is_string($url) || $url === '') {
		return (string) $url;
	}

	$parts = parse_url($url);
	if (is_array($parts) && !empty($parts['host'])) {
		$scheme		= $parts['scheme'] ?? '';
		$redacted	= ($scheme !== '' ? "{$scheme}://" : '//') . $parts['host'];
		if (isset($parts['port'])) {
			$redacted .= ":{$parts['port']}";
		}
		$redacted .= $parts['path'] ?? '';
		if (isset($parts['query'])) {
			$redacted .= '?[redacted]';
		}
		return $redacted;
	}

	// Fallback (parse_url found no host): a malformed URL, or pfBlockerNG's bare
	// rsync '[user@]host::module' shorthand. Strip a '[scheme://]user[:pass]@'
	// userinfo prefix using the RIGHTMOST '@' in the authority -- an rsync
	// password may itself contain a literal '@' (mirrors pfb_download's own
	// strrpos('@') host handling), so a first-'@' split would leak part of it --
	// then drop any query AND fragment, either of which can carry a credential.
	$prefix		= '';
	$body		= $url;
	if (preg_match('#^([a-z][a-z0-9+.-]*://|//)#i', $body, $m)) {
		$prefix	= $m[0];
		$body	= substr($body, strlen($prefix));
	}
	$auth_end	= strcspn($body, '/?#');		// authority = up to the first /?#
	$authority	= substr($body, 0, $auth_end);
	$tail		= substr($body, $auth_end);
	$at		= strrpos($authority, '@');
	if ($at !== FALSE) {
		$authority = substr($authority, $at + 1);
	}
	$redacted	= $prefix . $authority . $tail;
	$cut		= strcspn($redacted, '?#');		// truncate a query OR fragment
	if ($cut < strlen($redacted)) {
		$redacted = substr($redacted, 0, $cut) . '?[redacted]';
	}
	return $redacted;
}


// ADR-59: merge caller-supplied HTTP headers with the ADR-42 conditional-GET header into one
// CURLOPT_HTTPHEADER list — neither clobbers the other. Pure/no I/O (pfb_download() itself
// isn't: tests/php/README.md "Out of scope").
//
// $extra_headers: caller-supplied header strings; a non-string/empty entry is dropped.
// $conditional_header: the ADR-42 conditional-GET header, or '' when none applies.
// @return string[] merged list, conditional-GET header first; byte-identical to the prior
//   single-element list when $extra_headers is empty (today, always).
function pfb_download_http_headers(array $extra_headers, string $conditional_header = ''): array
{
	$headers = array();
	if ($conditional_header !== '') {
		$headers[] = $conditional_header;
	}
	foreach ($extra_headers as $extra_header) {
		if (is_string($extra_header) && $extra_header !== '') {
			$headers[] = $extra_header;
		}
	}
	return $headers;
}

function pfb_download_finalize_text(
	string $orig_download,
	string $hash_base,
	string $hash_path,
	?callable $hash_write = NULL,
	?callable $transcode = NULL,
	?callable $newline = NULL
): void {
	$hash_write ??= 'pfb_hash_write';
	$transcode ??= 'pfb_utf16_transcode_file';
	$newline ??= 'pfb_ensure_trailing_newline';
	$hash_write($hash_base, $hash_path);
	$transcode($orig_download);
	$newline($orig_download);
}


// Issue #1906: normalize an extras feed's download credentials for PfbDownloadRequest, whose
// $username/$password are non-nullable strings. Each extras feed type carries its credentials
// differently -- the MaxMind (geoip) feeds take them from the settings, a DNSBL Blacklist
// category may carry its own, and the IPinfo ASN/TOP1M feeds carry none at all (they
// authenticate by URL token / header, or not at all) -- so a per-type branch in the caller
// left the credential-free types passing an undefined array key (NULL) straight into the
// constructor, an uncaught TypeError that aborted the whole extras run. Normalizing every
// type here keeps that class of crash out of the call sites. Pure/no I/O.
//
// Only NULL/absent means "no credential" here: unlike the `?: ''` this replaces, a literal "0"
// credential is reported faithfully rather than blanked. That is this helper's contract only --
// $feed: one $pfb['extras'] entry. $maxmind_account/$maxmind_key: the settings' MaxMind
//   credentials, already coerced to strings by pfb_global().
// @return array{0: string, 1: string} the username and password to download this feed with.
function pfb_extras_credentials(array $feed, string $maxmind_account, string $maxmind_key): array
{
	if (($feed['type'] ?? '') === 'geoip') {
		return array($maxmind_account, $maxmind_key);
	}
	return array((string) ($feed['username'] ?? ''), (string) ($feed['password'] ?? ''));
}


final class PfbDownloadRequest
{
	public function __construct(
		public readonly string $listUrl,
		public readonly string $downloadPath,
		public readonly bool $flex,
		public readonly string $header,
		public readonly string $format,
		public readonly int $logType,
		public readonly string $versionType = '',
		public readonly int $timeout = 300,
		public readonly string $type = '',
		public readonly string $username = '',
		public readonly string $password = '',
		public readonly string|false $sourceInterface = FALSE,
		public readonly array $extraHeaders = array(),
	) {
	}
}

final class PfbDownloadResult
{
	private function __construct(
		public readonly bool $success,
		public readonly ?array $responseMeta,
	) {
	}

	public static function success(?array $responseMeta = NULL): self
	{
		return new self(TRUE, $responseMeta);
	}

	public static function failure(?array $responseMeta = NULL): self
	{
		return new self(FALSE, $responseMeta);
	}
}

// issue #2820: the detector promotes a response's ADR-42 validators before the ingest it
// schedules can accept the body, so a refused ingest drops them here -- at the single exit,
// so no reject stage can diverge -- or the rejected body 304s the next conditional GET.
// Untouched: the served '.orig' and its last-good '.orig.xxhash128' baseline (#2660/#2668).
// Standard list feeds only; the extras lanes promote only after a successful publication.
function pfb_download(PfbDownloadRequest $request): PfbDownloadResult {
	$result = pfb_download_fetch($request);
	if (!$result->success && $request->type === '') {
		unlink_if_exists("{$request->downloadPath}.orig.etag");
		unlink_if_exists("{$request->downloadPath}.orig.lastmod");
	}
	return $result;
}


// Function to download feeds.
function pfb_download_fetch(PfbDownloadRequest $request): PfbDownloadResult {
	$list_url = $request->listUrl;
	$file_dwn = $request->downloadPath;
	$pflex = $request->flex;
	$header = $request->header;
	$format = $request->format;
	$logtype = $request->logType;
	$vtype = $request->versionType;
	$timeout = $request->timeout;
	$type = $request->type;
	$username = $request->username;
	$password = $request->password;
	$srcint = $request->sourceInterface;
	$extra_headers = $request->extraHeaders;
	$top1m_provider = ($type === 'top1m') ? pfb_top1m_active_provider() : array();
	global $pfb;
	$http_status = '';
	$elog = ">> {$pfb['log']} 2>&1";

	// Remove any leading/trailing whitespace
	$list_url = trim($list_url);

	// Re-evaluate URL
	if ($format == 'whois') {
		if (empty(pfb_filter($list_url, PFB_FILTER_DOMAIN, 'pfb_download'))) {
			pfb_logger("\n Failed", 2);
			return PfbDownloadResult::failure();
		}
	}
	elseif ($format == 'asn') {
		if (empty(pfb_filter($list_url, PFB_FILTER_ALNUM, 'pfb_download'))) {
			pfb_logger("\n Failed", 2);
			return PfbDownloadResult::failure();
		}
	}
	elseif (!pfb_filter($list_url, PFB_FILTER_URL, 'pfb_download_failure')) {
		// Issue #811: land the header-scoped, reason-bearing skip line in the main log
		// when the feed-host guard is why entry vetting failed (pfb_filter's own reject
		// line goes to error.log only). See pfb_log_feed_host_reject().
		pfb_log_feed_host_reject($list_url, $header, $logtype);
		pfb_logger("\n Failed", 2);
		return PfbDownloadResult::failure();
	}

	// Cron change-detection probe (conditional GET + content hash; legacy name was 'md5')
	if ($type == 'change_detect') {
		pfb_logger("\t\t\t\t( change check )\t\t", 1);
	}

	$file_dwn_esc	= escapeshellarg("{$file_dwn}.raw");
	$file_org_esc	= escapeshellarg("{$file_dwn}.orig");
	$list_url_esc	= escapeshellarg("{$list_url}");
	$header_esc	= escapeshellarg("{$header}");

	$file_download	= trim("{$file_dwn_esc}", "'");
	$orig_download	= trim("{$file_org_esc}", "'");
	$list_download	= trim("{$list_url_esc}", "'");
	$head_download	= trim("{$header_esc}", "'");

	$md5_download	= trim(escapeshellarg("{$file_dwn}.md5.raw"), "'");

	// If the change-detection probe already downloaded the body, re-utilize instead of downloading twice
	if (file_exists("{$md5_download}")) {
		$list_download = "{$md5_download}";
		pfb_logger(' ( change check ) ', 1);
	}

	// Download RSYNC format
	if ($format == 'rsync') {

		// Apply the same resolve+reject guard before rsync (fail-closed; opt-out
		// in General settings via 'pfb_feed_internal_filter'), then connect to the
		// vetted IP rather than the hostname so the exec cannot re-resolve to a
		// different address between the check and the connect. When the filter is
		// disabled, skip the guard and pin entirely (pre-filter fetch behaviour).
		$rsync_src = $list_url;
		if (pfb_feed_filter_enabled()) {
			if (strpos($list_url, '::') !== FALSE) {
				$rsync_host = explode('::', $list_url, 2)[0];	// host::module form
				// Strip an optional 'user@' prefix from the host component.
				$at = strrpos($rsync_host, '@');
				if ($at !== FALSE) {
					$rsync_host = substr($rsync_host, $at + 1);
				}
			} else {
				$rsync_host = parse_url($list_url, PHP_URL_HOST) ?: '';	// rsync://host/path form
			}
			$rsync_reason	= '';
			$rsync_pinned	= '';
			if (!pfb_feed_host_allowed($rsync_host, $rsync_reason, $rsync_pinned)) {
				$log = "\n[ {$header} ] {$rsync_reason} \xe2\x80\x94 skipped\n";
				pfb_logger("{$log}", "{$logtype}");
				return PfbDownloadResult::failure();
			}

			// Pin the connection to the vetted IP (substitute it for the host in the
			// rsync source). Fail closed if the source form can't be parsed to do so.
			$rsync_src = pfb_rsync_pin_url($list_url, $rsync_pinned);
			if ($rsync_src === '') {
				$log = "\n[ {$header} ] feed host could not be pinned \xe2\x80\x94 skipped\n";
				pfb_logger("{$log}", "{$logtype}");
				return PfbDownloadResult::failure();
			}
		}

		// issue #2667: bound the rsync ingest path, which writes the fetched body
		// straight to {file}.raw and was bounded by neither #2658 ceiling. Two halves:
		//  - kernel backstop: run rsync under pfb_extract_cmd()'s ulimit -f at TWICE
		//    the ceiling. rsync writes through an atomic temp file and renames only on
		//    a clean exit, so a body just over the ceiling must still land whole for
		//    the named check below; the backstop bounds what can hit disk even beyond
		//    that. Its kill surfaces as rsync's own nonzero exit ("File too large" on
		//    openrsync, SIGXFSZ status on GNU) -- the existing nonzero-exit gate refuses.
		//  - named refusal: a body that lands whole but over the ceiling is refused,
		//    removed, and logged stage=size reason=rsync_too_large, so an operator can
		//    tell "too large" from any other rsync failure on every platform.
		// --max-size was rejected: probed, openrsync exits 0 silently when the SOURCE
		// exceeds it (it bounds per-file transfer, not refusal), so it cannot be the
		// bound alone. $pfb['rsync_max_bytes'] is the test seam, mirroring #2658's
		// $pfb['curl_defaults'] ceiling seam.
		$rsync_ceiling = isset($GLOBALS['pfb']['rsync_max_bytes']) ? (int) $GLOBALS['pfb']['rsync_max_bytes'] : PFB_DOWNLOAD_MAX_BYTES;
		// exec() returns the command's LAST output line, not its exit status; the
		// real return code rides in the third argument. Test that, so a normal
		// rsync transfer (which prints progress/stats) is not mistaken for a failure.
		// ulimit -f counts 512-byte blocks, so twice the ceiling is ceiling / 256;
		// integer division keeps the bound exact for every ceiling (a float cast is
		// undefined once 2 * ceiling leaves the integer range).
		$rsync_blocks = intdiv($rsync_ceiling, 256);
		// Issue #2876: the spawn runs under the bounded-wait seam (whole-transfer
		// wall deadline; see pfb_rsync_transfer_cmd()) — rsync's --timeout=5 stays,
		// bounding a silent peer, while the wrapper bounds a slow-progress one.
		exec(pfb_rsync_transfer_cmd($rsync_src, "{$file_dwn}.raw", $rsync_blocks, $timeout), $rsync_output, $rsync_rc);
		if ($rsync_rc === 0) {
			clearstatcache(TRUE, "{$file_dwn}.raw");
			$rsync_size = @filesize("{$file_dwn}.raw");
			if ($rsync_size === FALSE || $rsync_size > $rsync_ceiling) {
				pfb_validate_log($header, 'size', 'rsync_too_large', pfb_redact_url($list_url));
				unlink_if_exists("{$file_dwn}.raw");
				return PfbDownloadResult::failure();
			}
			$http_status = '200';
		} elseif ($rsync_rc === 124) {
			// Issue #2876: deadline expiry is its own named failure, in the same
			// language as every other bounded spawn (timeout(1)'s status, whole
			// transfer tree reaped): nothing the killed transfer wrote may
			// survive, and the prior good publication is untouched by the
			// failure return below.
			pfb_logger("\n  RSYNC transfer TIMED OUT (killed); discarding its output\n", "{$logtype}");
			unlink_if_exists("{$file_dwn}.raw");
			return PfbDownloadResult::failure();
		} else {
			$rsync_msg = trim(implode(' ', $rsync_output));
			$log = "\n  RSYNC Failed (exit {$rsync_rc})" . ($rsync_msg !== '' ? ": {$rsync_msg}" : '') . "...\n";
			pfb_logger("{$log}", "{$logtype}");
			return PfbDownloadResult::failure();
		}
	}
	elseif ($format == 'whois' || $format == 'asn') {
		// Convert a Domain name/AS into its respective IP addresses
		exec("{$pfb['script']} whoisconvert {$header_esc} {$vtype} {$list_url_esc} {$elog}");
		return PfbDownloadResult::success();
	}
	else {
		// Determine if URL is a pfSense localfile
		$localfile = FALSE;
		if (pfb_filter("{$list_download}", PFB_FILTER_URL, 'pfb_download', '', TRUE)) {
			$localfile = TRUE;
		}

		// Download localfile format
		if ($localfile) {
			$file_data = @file_get_contents("{$list_download}");
			if ($file_data === FALSE) {
				$error = error_get_last();
				$log = "\n[ {$header} ] {$error['message']}\n";
				pfb_logger("{$log}", "{$logtype}");
				return PfbDownloadResult::failure();
			} else {
				// Save original downloaded file
				@file_put_contents("{$file_download}", $file_data, LOCK_EX);
				$http_status = '200';
			}
		}

		// Download using cURL
		else {
			$remote_stamp = -1;

			// Verify the feed host does not resolve to a non-public/reserved
			// address before opening any connection (fail-closed; opt-out in
			// General settings via 'pfb_feed_internal_filter'). Pin the connection
			// to the vetted IP so it cannot rebind to a different address between
			// this check and the fetch. When the filter is disabled, skip the guard
			// and the IP pin entirely (pre-filter fetch behaviour); $feed_filter
			// also selects manual (re-vetted) vs cURL-native redirect following.
			$feed_filter	= pfb_feed_filter_enabled();
			$url_parts	= parse_url($list_download);
			$feed_host	= $url_parts['host'] ?? '';
			$feed_scheme	= strtolower($url_parts['scheme'] ?? '');
			$feed_reason	= '';
			$feed_pinned	= '';
			// Fetch-time rebind (DNS-rebind/TOCTOU) re-check: entry vetting already ran
			// this same guard (pfb_filter -> pfb_feed_host_allowed) before the download
			// was scheduled. Re-resolving here and pinning to THIS verdict's IP is what
			// catches a host whose resolution changed since -- statically unreachable
			// otherwise, since a host still resolving the same way was already rejected
			// at entry and never gets here.
			if ($feed_filter &&
			    !pfb_feed_host_allowed($feed_host, $feed_reason, $feed_pinned)) {
				$log = "\n[ {$header} ] {$feed_reason} \xe2\x80\x94 skipped\n";
				pfb_logger("{$log}", "{$logtype}");
				return PfbDownloadResult::failure();
			}

			if (($fhandle = @fopen("{$file_download}", 'w')) !== FALSE) {
				if (!($ch = curl_init("{$list_download}"))) {
					$log = "\nFailed to create cURL resource... Exiting...\n";
					pfb_logger("{$log}", "{$logtype}");
					return PfbDownloadResult::failure();
				}

				// Load curl default settings — incl. the CURLOPT_PROTOCOLS scheme allow-list
				// (an independent libcurl-layer backstop to PFB_FILTER_URL).
				curl_setopt_array($ch, $pfb['curl_defaults']);

				curl_setopt($ch, CURLOPT_FILE, $fhandle);	// Add $fhandle setting to cURL
				curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);	// Set cURL download timeout

				// With the filter ON, do NOT let cURL auto-follow redirects: a 3xx
				// is followed manually below so every hop's host is re-vetted by the
				// feed-host guard and re-pinned before it is dialled (an auto-followed
				// redirect would be re-resolved by cURL, bypassing the guard + the IP
				// pin). With the filter OFF, restore cURL-native following (the
				// pre-filter behaviour) so the manual revalidation loop is bypassed.
				curl_setopt($ch, CURLOPT_FOLLOWLOCATION, !$feed_filter);
				curl_setopt($ch, CURLOPT_MAXREDIRS, $feed_filter ? 0 : PFB_DOWNLOAD_MAXREDIRS);

				// Capture the response 'Location' header for the manual redirect
				// follow and the 'ETag' header for ADR-42 conditional-GET.
				// Reset per hop ($redirect_location is cleared before each curl_exec).
				// Bodies are written to $fhandle; a redirect hop's body is truncated
				// away before the next hop so only the final 2xx body survives.
				$redirect_location = '';
				$response_etag     = '';
				curl_setopt($ch, CURLOPT_HEADERFUNCTION,
					function ($curl_handle, $hdr_line) use (&$redirect_location, &$response_etag) {
						$trimmed = trim($hdr_line);
						if (stripos($trimmed, 'Location:') === 0) {
							$redirect_location = trim(substr($trimmed, strlen('Location:')));
						} elseif (stripos($trimmed, 'ETag:') === 0) {
							$response_etag = trim(substr($trimmed, strlen('ETag:')));
						}
						return strlen($hdr_line);
					}
				);

				// ADR-42: send a conditional GET when stored validators are
				// available for this feed's .orig baseline.  ETag → If-None-Match
				// (primary); Last-Modified epoch → CURLOPT_TIMECONDITION (fallback).
				// Only applied to the probe ('change_detect') mode: the sync ingest callers
				// pass $type == '' and must always receive the full body.
				$conditional_header = '';
				if ($type === 'change_detect') {
					// Read the validators the detector persisted at {header}.orig, NOT the
					// probe's infixed {file_dwn}.orig (= {header}.md5.orig) — see
					// pfb_conditional_get_validator_base().  Otherwise If-None-Match is never
					// sent and the server can never answer 304 (ADR-42 §3 fast-path).
					$validators = pfb_validator_read(pfb_conditional_get_validator_base($file_dwn));
					if (is_string($validators['etag']) && $validators['etag'] !== '') {
						$conditional_header = "If-None-Match: {$validators['etag']}";
					} elseif (is_int($validators['lastmod']) && $validators['lastmod'] > 0) {
						curl_setopt($ch, CURLOPT_TIMECONDITION, CURL_TIMECOND_IFMODSINCE);
						curl_setopt($ch, CURLOPT_TIMEVALUE, $validators['lastmod']);
					}
				}

				// ADR-59: merge caller-supplied headers (the TOP1M provider auth header is
				// the first caller) with the conditional-GET header above -- neither list
				// clobbers the other. Skips the curl_setopt entirely when both are empty
				// (every other feed, plus an in-flight change_detect probe with no stored
				// ETag), matching prior behaviour byte-for-byte.
				$http_headers = pfb_download_http_headers($extra_headers, $conditional_header);
				if (!empty($http_headers)) {
					curl_setopt($ch, CURLOPT_HTTPHEADER, $http_headers);
				}

				// Issue #1953: a caller-supplied Authorization header (the TOP1M
				// Radar Bearer token) is an origin credential like CURLOPT_USERPWD
				// and must not ride an off-origin redirect hop; the redirect loop
				// below swaps between the full list and this one. Non-credential
				// headers (e.g. If-None-Match) stay on every hop. The literal
				// prefix matches the only credential header any caller passes
				// today (pfb_top1m_auth_headers); a provider descriptor
				// introducing a different credential header name must extend
				// this filter.
				$offorigin_http_headers = array_values(array_filter($http_headers,
					fn (string $hdr): bool => stripos($hdr, 'Authorization:') !== 0));
				$headers_have_auth = count($offorigin_http_headers) !== count($http_headers);

				if ($srcint) {
					curl_setopt($ch, CURLOPT_INTERFACE, $srcint);	// Use a specific interface when downloading lists
					pfb_logger("\nList: {$header} will be downloaded via interface: {$srcint}\n", 1);
				}

				// Pin the resolved IP for this connection (DNS-rebind close). The
				// host header/SNI stay the original host; only the address cURL
				// dials is forced to the one vetted above. Coexists with
				// CURLOPT_INTERFACE (the source interface is independent of the
				// destination address). The destination port is derived from the URL
				// or its scheme when implicit.
				$scheme_ports	= array('http' => 80, 'https' => 443, 'ftp' => 21, 'rsync' => 873);
				$feed_port	= (int) ($url_parts['port'] ?? ($scheme_ports[$feed_scheme] ?? 0));
				if ($feed_pinned !== '' && $feed_host !== '' && !empty($feed_scheme) && $feed_port > 0) {
					curl_setopt($ch, CURLOPT_RESOLVE, array("{$feed_host}:{$feed_port}:{$feed_pinned}"));
				}

				$feed_has_creds = !pfb_is_empty($username) || !pfb_is_empty($password);
				if ($feed_has_creds) {
					curl_setopt($ch, CURLOPT_USERPWD, "{$username}:{$password}");
					curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
				}

				// Manually follow validated redirects. Each hop's body is written to
				// $fhandle, truncated before the next hop so only the final response
				// body survives. The hop cap (PFB_DOWNLOAD_MAXREDIRS, 10) matches the
				// previous CURLOPT_MAXREDIRS. The common (non-redirecting) feed exits
				// on the first iteration with the body intact, behaving exactly as
				// before.
				$current_url	= $list_download;
				$http_status	= '';
				for ($hop = 0; $hop <= PFB_DOWNLOAD_MAXREDIRS; $hop++) {
					$redirect_location = '';

					// Attempt 3 Downloads before failing.
					$hop_ok = FALSE;
					for ($retries = 1; $retries <= 3; $retries++) {
						// issue #1072: a failed attempt can leave a partial body in the
						// file with the write offset at its end; reset so a retry cannot
						// append and hand off a corrupted concatenation as the download.
						ftruncate($fhandle, 0);
						rewind($fhandle);
						if (curl_exec($ch)) {
							// Collect remote timestamp.
							$raw_filetime = curl_getinfo($ch, CURLINFO_FILETIME);
							if ($raw_filetime == -1) {
								$remote_stamp = -1;
							} elseif (!empty(pfb_filter($raw_filetime, PFB_FILTER_NUM, 'pfb_download - remote timestamp'))) {
								$remote_stamp = $raw_filetime;
							}
							$hop_ok = TRUE;
							break;	// Break on success
						}

						$curl_error = curl_errno($ch);
						if ($logtype != 3) {
							pfb_logger(" cURL Error: {$curl_error}\n", 1);
						} else {
							pfb_logger(" {$header}\t\tcURL Error: {$curl_error}\n\n", 3);
						}

						// issue #2658: an over-large body is a permanent refusal, not a
						// transient failure -- retrying re-fetches the same feed twice more,
						// and the response code libcurl already collected can be a 200, which
						// would hand the truncated body to MIME validation as if it were the
						// whole feed. Refuse here, naming the reason.
						if ($curl_error === CURLE_FILESIZE_EXCEEDED) {
							pfb_validate_log($header, 'size', 'download_too_large', pfb_redact_url($list_download));
							// No curl_close(): it is a no-op since PHP 8.0 and deprecated in 8.5
							// (Plus ships php85); the handle frees when this frame returns.
							@fclose($fhandle);
							unlink_if_exists($file_download);
							return PfbDownloadResult::failure();
						}

						/* 'Flex' Downgrade cURL errors -	[ 35 - GET_SERVER_HELLO:sslv3		]
											[ 51 - NO alternative certificate	]
											[ 60 - Local Issuer Certificate Subject	]	*/

						// Allow downgrade of cURL settings 'Flex' after 1st failure, if user configured.
						if ($retries == 1 && $pflex && in_array($curl_error, array( '35', '51', '60'))) {
							curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
							curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);
							curl_setopt($ch, CURLOPT_SSL_CIPHER_LIST, 'TLSv1.3, TLSv1.2, TLSv1.1, TLSv1, SSLv3');
							$log = "\n  Downgrading SSL settings (Flex)";
							pfb_logger("{$log}", "{$logtype}");
						}
						else {
							if ($retries == 3) {
								$log = curl_error($ch) . " |{$head_download}|" . pfb_redact_url($list_download) . "| Retry [{$retries}] in 5 seconds...\n";
							} else {
								$log = curl_error($ch) . " Retry [{$retries}] in 5 seconds...\n";
							}
							pfb_logger("{$log}", "{$logtype}");
							sleep(5);
							pfb_logger('.', "{$logtype}");
						}
					}

					// Collect RFC7231 http status code for this hop
					$http_status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);

					// Not a redirect (or the request failed) -> this is the final
					// response; stop and treat what was written as the download.
					if (!$hop_ok || $http_status < 300 || $http_status >= 400 || $redirect_location === '') {
						break;
					}

					// A redirect: validate the target host before following it.
					if ($hop >= PFB_DOWNLOAD_MAXREDIRS) {
						$log = "\n[ {$header} ] too many redirects \xe2\x80\x94 skipped\n";
						pfb_logger("{$log}", "{$logtype}");
						if ($ch) {
							curl_close($ch);
						}
						if ($fhandle) {
							@fclose($fhandle);
						}
						return PfbDownloadResult::failure();
					}

					$rdr_reason	= '';
					$rdr_pinned	= '';
					$next = pfb_feed_redirect_target($redirect_location, $current_url, $rdr_reason, $rdr_pinned);
					if ($next === FALSE) {
						$log = "\n[ {$header} ] {$rdr_reason} \xe2\x80\x94 skipped\n";
						pfb_logger("{$log}", "{$logtype}");
						if ($ch) {
							curl_close($ch);
						}
						if ($fhandle) {
							@fclose($fhandle);
						}
						return PfbDownloadResult::failure();
					}

					// Discard the redirect-page body so only the final hop's body
					// remains in the feed file.
					ftruncate($fhandle, 0);
					rewind($fhandle);

					// Scope the Basic credentials to the ORIGINAL feed origin —
					// host AND scheme AND port (issue #1919) — libcurl's own
					// FOLLOWLOCATION policy since 7.83.0 (CVE-2022-27774): a
					// hop to any other origin must not receive the feed's
					// Authorization (another port or a downgraded scheme on
					// the same host is a different trust domain), and a hop
					// back onto the origin regains it. CURLAUTH_NONE (with
					// the userpwd blanked) stops libcurl from sending any
					// Authorization header.
					$hop_on_origin = (strcasecmp($next['host'], $feed_host) === 0 &&
							  $next['scheme'] === $feed_scheme &&
							  $next['port'] === $feed_port);
					if ($feed_has_creds) {
						if ($hop_on_origin) {
							curl_setopt($ch, CURLOPT_USERPWD, "{$username}:{$password}");
							curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
						} else {
							curl_setopt($ch, CURLOPT_USERPWD, '');
							curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_NONE);
						}
					}
					// Issue #1953: the caller-supplied Authorization header gets
					// the same origin scope (an empty off-origin list resets
					// CURLOPT_HTTPHEADER to cURL defaults).
					if ($headers_have_auth) {
						curl_setopt($ch, CURLOPT_HTTPHEADER,
							$hop_on_origin ? $http_headers : $offorigin_http_headers);
					}

					// Re-point cURL at the vetted target and re-pin its address. The
					// '-host:port' entry removes any prior pin for the same host:port
					// (e.g. a same-host relative redirect) so the add is not a
					// duplicate.
					$current_url = $next['url'];
					curl_setopt($ch, CURLOPT_URL, $next['url']);
					if ($rdr_pinned !== '' && $next['port'] > 0) {
						curl_setopt($ch, CURLOPT_RESOLVE, array(
							"-{$next['host']}:{$next['port']}",
							"{$next['host']}:{$next['port']}:{$rdr_pinned}",
						));
					}
				}

				if (isset($pfb['rfc7231'][$http_status])) {
					if ($logtype < 3) {
						pfb_logger(". {$pfb['rfc7231'][$http_status]}", $logtype);
					} else {
						pfb_logger(" {$file_dwn}\t\t{$pfb['rfc7231'][$http_status]}\n", $logtype);
					}
				} else {
					pfb_logger(". Unknown Failure Code [{$http_status}]", $logtype);
				}
				if ($ch) {
					curl_close($ch);
				}
			}
			if ($fhandle) {
				@fclose($fhandle);
			}
		}
	}

	// Probe mode for the cron detector (type='change_detect'): return response metadata
	// (ADR-42 conditional-GET path), then return.
	// A 304 means "not modified" — the server confirmed the feed unchanged; the
	// caller (pfb_update_check detector) handles the 304 via pfb_conditional_get_decision.
	// Any 200 means the body was downloaded to {file_dwn}.raw; the caller hashes it.
	// Any other status means the probe failed; the caller fails-safe to re-ingest.
	//
	if ($type == 'change_detect') {
		$probe_meta = array(
			'status'  => (string) $http_status,
			'etag'    => isset($response_etag) ? $response_etag : '',
			'lastmod' => isset($remote_stamp) && $remote_stamp > 0 ? (int) $remote_stamp : 0,
		);
		if ($http_status == '304' || $http_status == '200') {
			return PfbDownloadResult::success($probe_meta);
		}
		return PfbDownloadResult::failure($probe_meta);
	}

	// Remove any downloaded files with md5 extension
	unlink_if_exists("{$md5_download}");

	// '304 not modified' - Utilize previously downloaded file if available
	if ($http_status == '304' && file_exists("{$orig_download}")) {
		return PfbDownloadResult::success();
	}

	if (file_exists($file_download) && ($http_status == '200' || $http_status == '221' || $http_status == '226')) {

		// issue #1158: fail-safe default -- with unset(), paths that assigned nothing fell
		// through $retval == 0 as success
		$retval = pfb_download_initial_retval();

		// Validate File Mime-type
		$reject_detail = array();
		$file_type = pfb_filter(array("{$file_dwn_esc}", "{$file_download}", "{$list_download}"), PFB_FILTER_FILE_MIME, 'pfb_download', '', FALSE, $reject_detail);
		if (!$file_type) {
			pfb_validate_log($header, 'mime', 'mime_not_allowed', pfb_reject_detail_summary($reject_detail));
			return PfbDownloadResult::failure();
		}

		// ADR-49: opt-in plain-text sanity scan on accepted text feeds. The flag is
		// checked FIRST -- when default-off it short-circuits before THIS scan's own
		// MIME-scope check (the in_array below) and the sample read, so an off install
		// adds no work here (ADR-28 conv 2). ($file_type was already produced by the
		// upstream FILE_MIME check above; this gate only narrows to the text types.)
		// 'application/csv' rides with 'text/csv' -- same CSV body, just a different
		// libmagic verdict (both are allow-listed synonyms; see pfb_filter FILE_MIME).
		if (PfbConfig::read('gen/pfb_feed_sanity') === PfbToggle::On &&
			in_array($file_type, array('text/plain', 'text/html', 'text/csv', 'application/csv'), TRUE)) {
			// Read UP TO 64 KiB -- a cap, not a minimum; a shorter feed is read whole.
			// 64 KiB (raised from 8 KiB) because HTML-wrapped real feeds bury their
			// first data token behind boilerplate (cybercrime-tracker's first IP sits
			// ~12 KiB in) and the html_error_page guard must be able to see it.
			$pfb_sanity_sample = @file_get_contents($file_download, FALSE, NULL, 0, 65536);
			// A read error (FALSE) is NOT an empty feed: skip the scan (fail-open) so a
			// transient I/O glitch is not mislogged as below_min_content and the feed --
			// already MIME-validated -- proceeds instead of being wrongly dropped. A truly
			// empty (0-byte) feed reads as '' (not FALSE), so below_min_content still fires.
			if ($pfb_sanity_sample !== FALSE) {
				$pfb_sanity = pfb_text_sanity($pfb_sanity_sample);
				if ($pfb_sanity !== NULL) {
					pfb_validate_log($header, 'plaintext', $pfb_sanity, basename($file_download));
					unlink_if_exists($file_download);
					return PfbDownloadResult::failure();
				}
			}
		}

		// Create update file markers on new downloads available
		switch($type) {
			case 'geoip':
				touch("{$pfb['dbdir']}/geoip.update");
				break;
			case 'asn':
				touch("{$pfb['dbdir']}/asn.update");
				break;
			default:
				break;
		}

		// Set downloaded file timestamp to remote timestamp
		if (isset($remote_stamp) && $remote_stamp != -1) {
			@touch("{$file_download}", $remote_stamp);
		}

		// issue #2658: refuse before writing anything when a staging filesystem cannot
		// hold even the archive itself. A part-way extraction onto a full disk costs
		// the operator the data already in service; a refused feed does not. Only the
		// archive types below extract, so pfb_archive_probe() -- which already answers
		// "is this an archive" -- keeps a plain text feed out of the guard entirely.
		// The requirement is the archive's own size and nothing more: /var is a 60 MiB
		// RAM disk on a default use_mfs_tmpvar install, so any fixed floor would refuse
		// every feed there forever.
		if (pfb_archive_probe($file_type) !== NULL) {
			$extract_dirs = array(dirname($file_download), $pfb['dbdir'], $head_download, dirname($head_download));
			if ($type == 'geoip') {
				$extract_dirs[] = $pfb['geoipshare'];
			}
			$extract_short = pfb_extract_space_shortfall($extract_dirs, (int) @filesize($file_download));
			if ($extract_short !== NULL) {
				pfb_validate_log($header, 'size', 'staging_space_low', $extract_short);
				unlink_if_exists($file_download);
				return PfbDownloadResult::failure();
			}
		}

		// Decompress file if required
		if ($file_type == 'application/x-gzip' || $file_type == 'application/gzip') {
			if (!pfb_validate_archive($file_download, $file_type)) {
				pfb_validate_log($header, 'structural', 'probe_failed', "{$file_type} " . basename($file_download));
				unlink_if_exists($file_download);
				return PfbDownloadResult::failure();
			}
			if ($type == 'geoip') {
				// Extras - MaxMind downloads
				return pfb_geoip_extract_tar_to_share($header, $file_download, $file_dwn_esc, $retval);
			}
			elseif ($type == 'asn') {
				$retval = pfb_download_initial_retval();
				if (!pfb_stage_publish($head_download,
				    static function (string $staged) use ($file_dwn_esc, &$output, &$retval): int {
					exec(pfb_extract_cmd("/usr/bin/gunzip -c {$file_dwn_esc} > " . escapeshellarg($staged)), $output, $retval);
					return $retval;
				})) {
					pfb_logger("\n[pfb_download] asn extraction failed (gunzip exit {$retval})" . pfb_extract_cap_note($retval), 2);
					unlink_if_exists($file_download);
					return PfbDownloadResult::failure();
				}

				// Update ASN Lookup table definitions
				exec("{$pfb['script']} asn_table {$elog}");

				unlink_if_exists($file_download);
				return PfbDownloadResult::success();
			}
			elseif ($type == 'top1m') {
				// Issue #1542: stage the derived CSV and commit active plus raw/hash
				// baseline together. Backups stay beside the feed for same-filesystem
				// rename rollback; GeoIP/ASN paths above remain unchanged.
				$top1m_stage = @tempnam(dirname($head_download), '.pfbtop1m_');
				if ($top1m_stage === FALSE) {
					unlink_if_exists($file_download);
					return PfbDownloadResult::failure();
				}
				$header_esc = escapeshellarg($top1m_stage);
				exec(pfb_extract_cmd("/usr/bin/gunzip -c {$file_dwn_esc} > {$header_esc}"), $output, $retval);
				if (!pfb_download_extraction_succeeded($retval)) {
					unlink_if_exists($file_download);
					unlink_if_exists($top1m_stage);
					pfb_logger("\n[pfb_download] top1m extraction failed (gunzip exit {$retval})" . pfb_extract_cap_note($retval), 2);
					return PfbDownloadResult::failure();
				}
				if (!pfb_top1m_candidate_valid($top1m_stage, $top1m_provider)) {
					pfb_validate_log($header, 'top1m', 'semantic_invalid', basename($top1m_stage));
					unlink_if_exists($file_download);
					unlink_if_exists($top1m_stage);
					return PfbDownloadResult::failure();
				}
				$top1m_base_backup = @tempnam(dirname($file_dwn), '.pfbtop1m_base_');
				if ($top1m_base_backup === FALSE || !@unlink($top1m_base_backup) || !@mkdir($top1m_base_backup, 0700)) {
					unlink_if_exists($file_download);
					unlink_if_exists($top1m_stage);
					return PfbDownloadResult::failure();
				}
				$top1m_base_backups = array();
				foreach (array("{$file_dwn}.orig", "{$file_dwn}.xxhash128", "{$file_dwn}.md5") as $top1m_base_path) {
					if (is_file($top1m_base_path)) {
						$top1m_base_copy = "{$top1m_base_backup}/" . basename($top1m_base_path);
						if (!@copy($top1m_base_path, $top1m_base_copy)) {
							rmdir_recursive($top1m_base_backup);
							unlink_if_exists($file_download);
							unlink_if_exists($top1m_stage);
							return PfbDownloadResult::failure();
						}
						$top1m_base_backups[$top1m_base_path] = $top1m_base_copy;
					}
				}
				$top1m_active_backup = @tempnam(dirname($head_download), '.pfbtop1m_active_');
				if ($top1m_active_backup === FALSE || !@unlink($top1m_active_backup)) {
					rmdir_recursive($top1m_base_backup);
					unlink_if_exists($file_download);
					unlink_if_exists($top1m_stage);
					return PfbDownloadResult::failure();
				}
				$top1m_had_active = file_exists($head_download) || is_link($head_download);
				if ($top1m_had_active && !@rename($head_download, $top1m_active_backup)) {
					rmdir_recursive($top1m_base_backup);
					unlink_if_exists($file_download);
					unlink_if_exists($top1m_stage);
					return PfbDownloadResult::failure();
				}
				if (!@rename($top1m_stage, $head_download)) {
					if ($top1m_had_active) {
						@rename($top1m_active_backup, $head_download);
					}
					rmdir_recursive($top1m_base_backup);
					unlink_if_exists($file_download);
					unlink_if_exists($top1m_stage);
					return PfbDownloadResult::failure();
				}
				if (!pfb_top1m_persist_baseline($file_dwn, $file_download)) {
					unlink_if_exists($head_download);
					if ($top1m_had_active) {
						@rename($top1m_active_backup, $head_download);
					}
					foreach (array("{$file_dwn}.orig", "{$file_dwn}.xxhash128", "{$file_dwn}.md5") as $top1m_base_path) {
						if (isset($top1m_base_backups[$top1m_base_path])) {
							@copy($top1m_base_backups[$top1m_base_path], $top1m_base_path);
						} elseif (is_file($top1m_base_path)) {
							@unlink($top1m_base_path);
						}
					}
					rmdir_recursive($top1m_base_backup);
					unlink_if_exists($file_download);
					return PfbDownloadResult::failure();
				}
				if ($top1m_had_active) {
					is_dir($top1m_active_backup) ? rmdir_recursive($top1m_active_backup) : unlink_if_exists($top1m_active_backup);
				}
				rmdir_recursive($top1m_base_backup);
				unlink_if_exists($file_download);
				touch("{$pfb['dbdir']}/top-1m.update");
				return PfbDownloadResult::success();
			}
			elseif ($type == 'blacklist') {
				// Extras - Blacklist downloads
				@rename("{$file_download}", strstr("{$file_download}", '.raw', TRUE));
				$file_esc = trim(escapeshellarg("{$file_dwn}"), "'");
				$filename = basename(basename("{$file_esc}", '.tar.gz'), '.tar');

				if (!empty(pfb_filter($filename, PFB_FILTER_WORD, 'pfb_download category'))) {
					// ADR-46: disk-writing extraction of a THIRD-PARTY archive (member
					// names feed on-disk filenames) -- reject hostile member names first
					// (a NULL member list = unlistable archive rejects too, fail-closed).
					$unsafe_member = pfb_archive_unsafe_member(pfb_archive_member_names($file_dwn, $file_type));
					if ($unsafe_member !== NULL) {
						pfb_validate_log($header, 'member', 'unsafe_member_name', $unsafe_member);
						unlink_if_exists($file_dwn);
						return PfbDownloadResult::failure();
					}

					// Extract Blacklist categories from sub-folders into a single folder structure
					$cmd = "--include='*domains' -s',.*/\\(.*\\)/\\(.*\\)/domains,{$filename}_\\1_\\2,' -s',.*/\\(.*\\)/domains,{$filename}_\\1,'";
					// issue #2172: the extraction runs in a staging directory and is swapped
					// into place only once tar reports success, so a failed extraction leaves
					// the category contents already in service untouched.
					$retval = pfb_download_initial_retval();
					if (!pfb_stage_publish_dir("{$pfb['dbdir']}/{$filename}",
					    static function (string $staged) use ($file_dwn, $filename, $cmd, &$output, &$retval): int {
						exec(pfb_extract_cmd("/usr/bin/tar -xf " . escapeshellarg("{$file_dwn}") . " " . PFB_TAR_EXTRACT_FLAGS . " {$cmd} -C " . escapeshellarg("{$staged}/") . " >/dev/null 2>&1"), $output, $retval);
						return pfb_blacklist_tar_finalize_staged($staged, $filename, $retval);
					})) {
						pfb_logger("\n[pfb_download] blacklist extraction failed (tar exit {$retval})" . pfb_extract_cap_note($retval), 2);
						return PfbDownloadResult::failure();
					}

					// issue #2738: unlink leftover orig/hash sidecars — Blacklist has no consumer.
					return pfb_blacklist_tar_mark_updated($file_dwn, $filename);
				}
				else {
					pfb_logger("\n Invalid filename [{$filename}]", 1);
					return PfbDownloadResult::failure();
				}
			}
			else {
				$reject_detail = array();
				$inner_type = pfb_filter(array("{$file_dwn_esc}", "{$file_download}", "{$list_download}"), PFB_FILTER_FILE_MIME_COMPRESSED, 'pfb_download', '', FALSE, $reject_detail);
				if (!$inner_type) {
					pfb_validate_log($header, 'inner', 'compressed_mime_not_allowed', pfb_reject_detail_summary($reject_detail));
					return PfbDownloadResult::failure();
				}
				pfb_logger('.', 1);
				$retval = pfb_download_initial_retval();
				$extract_tar = ($inner_type == 'application/x-tar');
				$pfb_sanity = NULL;
				if (!pfb_stage_publish($orig_download,
				    static function (string $staged) use ($file_dwn_esc, $extract_tar, &$output, &$retval, &$pfb_sanity): int {
					if ($extract_tar) {
						exec(pfb_extract_cmd("set -o pipefail; /usr/bin/gunzip -c {$file_dwn_esc} | /usr/bin/tar -xOf - > " . escapeshellarg($staged)), $output, $retval);
					} else {
						exec(pfb_extract_cmd("/usr/bin/gunzip -c {$file_dwn_esc} > " . escapeshellarg($staged)), $output, $retval);
					}
					$pfb_sanity = pfb_extracted_text_sanity($staged, $retval);
					return $pfb_sanity === NULL ? $retval : pfb_download_initial_retval();
				})) {
					if ($pfb_sanity !== NULL) {
						pfb_validate_log($header, 'plaintext', $pfb_sanity, basename($orig_download));
					} else {
						pfb_logger("\n[pfb_download] gzip extraction failed (gunzip exit {$retval})" . pfb_extract_cap_note($retval), 2);
					}
					unlink_if_exists($file_download);
					return PfbDownloadResult::failure();
				}
			}
		}
		elseif ($file_type == 'application/x-bzip2') {
			if (!pfb_validate_archive($file_download, $file_type)) {
				pfb_validate_log($header, 'structural', 'probe_failed', "{$file_type} " . basename($file_download));
				unlink_if_exists($file_download);
				return PfbDownloadResult::failure();
			}
			if ($type == 'blacklist') {
				// issue #2739: bzip2 is not extracted into the Blacklist category tree.
				pfb_validate_log($header, 'extract', 'blacklist_not_archive', $file_type);
				unlink_if_exists($file_download);
				return PfbDownloadResult::failure();
			}
			$reject_detail = array();
			$inner_type = pfb_filter(array("{$file_dwn_esc}", "{$file_download}", "{$list_download}"), PFB_FILTER_FILE_MIME_COMPRESSED, 'pfb_download', '', FALSE, $reject_detail);
			if (!$inner_type) {
				pfb_validate_log($header, 'inner', 'compressed_mime_not_allowed', pfb_reject_detail_summary($reject_detail));
				return PfbDownloadResult::failure();
			}
			pfb_logger('.', 1);
			$retval = pfb_download_initial_retval();
			$extract_tar = ($inner_type == 'application/x-tar');
			$pfb_sanity = NULL;
			if (!pfb_stage_publish($orig_download,
			    static function (string $staged) use ($file_dwn_esc, $extract_tar, &$output, &$retval, &$pfb_sanity): int {
				if ($extract_tar) {
					exec(pfb_extract_cmd("set -o pipefail; /usr/bin/bzip2 -dkc {$file_dwn_esc} | /usr/bin/tar -xOf - > " . escapeshellarg($staged)), $output, $retval);
				} else {
					exec(pfb_extract_cmd("/usr/bin/bzip2 -dkc {$file_dwn_esc} > " . escapeshellarg($staged)), $output, $retval);
				}
				$pfb_sanity = pfb_extracted_text_sanity($staged, $retval);
				return $pfb_sanity === NULL ? $retval : pfb_download_initial_retval();
			})) {
				if ($pfb_sanity !== NULL) {
					pfb_validate_log($header, 'plaintext', $pfb_sanity, basename($orig_download));
				} else {
					pfb_logger("\n[pfb_download] bzip2 extraction failed (bzip2 exit {$retval})" . pfb_extract_cap_note($retval), 2);
				}
				unlink_if_exists($file_download);
				return PfbDownloadResult::failure();
			}
		}
		elseif ($file_type == 'application/zip') {
			if (!pfb_validate_archive($file_download, $file_type)) {
				pfb_validate_log($header, 'structural', 'probe_failed', "{$file_type} " . basename($file_download));
				unlink_if_exists($file_download);
				return PfbDownloadResult::failure();
			}
			if ($type == 'blacklist') {
				// issue #2739: zip is not extracted into the Blacklist category tree.
				pfb_validate_log($header, 'extract', 'blacklist_not_archive', $file_type);
				unlink_if_exists($file_download);
				return PfbDownloadResult::failure();
			}

			// Extras - MaxMind downloads. GeoIP publishes to its caller target;
			// TOP1M's staged/atomic branch is kept separate below.
			if ($type == 'geoip') {
				// Determine if the Zip contains multiple files. A NULL list
				// (unlistable) falls through to stdout extraction exactly as before.
				$archive_members = pfb_archive_member_names($file_download, $file_type);
				if ($archive_members !== NULL && count($archive_members) > 1) {
					// ADR-46: disk-writing extraction -- reject hostile member names first.
					$unsafe_member = pfb_archive_unsafe_member($archive_members);
					if ($unsafe_member !== NULL) {
						pfb_validate_log($header, 'member', 'unsafe_member_name', $unsafe_member);
						unlink_if_exists($file_download);
						return PfbDownloadResult::failure();
					}
					// issue #2668: the extraction runs in a staging directory inside
					// the target and its members are published only once tar reports
					// success, so a failure part-way leaves the publication already
					// in service byte-identical.
					$retval = pfb_download_initial_retval();
					if (!pfb_stage_publish_dir_merge($head_download,
					    static function (string $staged) use ($file_dwn_esc, &$output, &$retval): int {
						exec(pfb_extract_cmd("/usr/bin/tar -xf {$file_dwn_esc} " . PFB_TAR_EXTRACT_FLAGS . " --strip=1 -C " . escapeshellarg($staged) . " >/dev/null 2>&1"), $output, $retval);
						return $retval;
					})) {
						pfb_logger("\n[pfb_download] {$type} zip " . pfb_stage_publish_failure_note($retval), 2);
						unlink_if_exists($file_download);
						return PfbDownloadResult::failure();
					}
					unlink_if_exists($file_download);
					return PfbDownloadResult::success();
				}
				// ADR-46: stdout extraction -- member names never reach the filesystem.
				$retval = pfb_download_initial_retval();
				if (!pfb_stage_publish($head_download,
				    static function (string $staged) use ($file_dwn_esc, &$output, &$retval): int {
					exec(pfb_extract_cmd("/usr/bin/tar -xOf {$file_dwn_esc} > " . escapeshellarg($staged)), $output, $retval);
					return $retval;
				})) {
					pfb_logger("\n[pfb_download] {$type} zip extraction failed (tar exit {$retval})" . pfb_extract_cap_note($retval), 2);
					unlink_if_exists($file_download);
					return PfbDownloadResult::failure();
				}
				if (!pfb_download_extraction_succeeded($retval)) {
					pfb_logger("\n[pfb_download] {$type} zip extraction failed (tar exit {$retval})" . pfb_extract_cap_note($retval), 2);
					unlink_if_exists($file_download);
					return PfbDownloadResult::failure();
				}
				unlink_if_exists($file_download);
				return PfbDownloadResult::success();
			}

			if ($type == 'top1m') {
				$archive_members = pfb_archive_member_names($file_download, $file_type);
				$unsafe_member = pfb_archive_unsafe_member($archive_members);
				if ($unsafe_member !== NULL || $archive_members === NULL || count($archive_members) === 0) {
					if ($unsafe_member !== NULL) {
						pfb_validate_log($header, 'member', 'unsafe_member_name', $unsafe_member);
					}
					unlink_if_exists($file_download);
					return PfbDownloadResult::failure();
				}
				$top1m_target_dir = is_dir($head_download);
				if (!$top1m_target_dir && count($archive_members) !== 1) {
					unlink_if_exists($file_download);
					return PfbDownloadResult::failure();
				}
				$top1m_stage = @tempnam(dirname($head_download), '.pfbtop1m_');
				if ($top1m_stage === FALSE || !@unlink($top1m_stage) || !@mkdir($top1m_stage, 0700)) {
					unlink_if_exists($file_download);
					return PfbDownloadResult::failure();
				}
				$header_esc = escapeshellarg($top1m_stage);
				$strip = $top1m_target_dir ? ' --strip=1' : '';
				exec(pfb_extract_cmd("/usr/bin/tar -xf {$file_dwn_esc}{$strip} " . PFB_TAR_EXTRACT_FLAGS . " -C {$header_esc} >/dev/null 2>&1"), $output, $retval);
				if (!pfb_download_extraction_succeeded($retval)) {
					pfb_logger("\n[pfb_download] {$type} zip extraction failed (tar exit {$retval})" . pfb_extract_cap_note($retval), 2);
					rmdir_recursive($top1m_stage);
					unlink_if_exists($file_download);
					return PfbDownloadResult::failure();
				}
				$top1m_staged_files = array();
				$top1m_staged_link = FALSE;
				$top1m_iterator = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator($top1m_stage, FilesystemIterator::SKIP_DOTS),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				foreach ($top1m_iterator as $top1m_entry) {
					if ($top1m_entry->isLink()) {
						$top1m_staged_link = TRUE;
					} elseif ($top1m_entry->isFile()) {
						$top1m_staged_files[] = $top1m_entry->getPathname();
					}
				}
				if ($top1m_staged_link || ($top1m_target_dir && count($top1m_staged_files) === 0) || (!$top1m_target_dir && count($top1m_staged_files) !== 1)) {
					rmdir_recursive($top1m_stage);
					unlink_if_exists($file_download);
					return PfbDownloadResult::failure();
				}
				if (!$top1m_target_dir) {
					$top1m_inner_type = pfb_filter(
						array(escapeshellarg($top1m_staged_files[0]), $top1m_staged_files[0], $list_download),
						PFB_FILTER_FILE_MIME,
						'pfb_download'
					);
					if ($top1m_inner_type === 'text/html') {
						rmdir_recursive($top1m_stage);
						unlink_if_exists($file_download);
						return PfbDownloadResult::failure();
					}
					if (!pfb_top1m_candidate_valid($top1m_staged_files[0], $top1m_provider)) {
						pfb_validate_log($header, 'top1m', 'semantic_invalid', basename($top1m_staged_files[0]));
						rmdir_recursive($top1m_stage);
						unlink_if_exists($file_download);
						return PfbDownloadResult::failure();
					}
				}
				$top1m_base_backup = @tempnam(dirname($file_dwn), '.pfbtop1m_base_');
				if ($top1m_base_backup === FALSE || !@unlink($top1m_base_backup) || !@mkdir($top1m_base_backup, 0700)) {
					rmdir_recursive($top1m_stage);
					unlink_if_exists($file_download);
					return PfbDownloadResult::failure();
				}
				$top1m_base_backups = array();
				foreach (array("{$file_dwn}.orig", "{$file_dwn}.xxhash128", "{$file_dwn}.md5") as $top1m_base_path) {
					if (is_file($top1m_base_path)) {
						$top1m_base_copy = "{$top1m_base_backup}/" . basename($top1m_base_path);
						if (!@copy($top1m_base_path, $top1m_base_copy)) {
							rmdir_recursive($top1m_base_backup);
							rmdir_recursive($top1m_stage);
							unlink_if_exists($file_download);
							return PfbDownloadResult::failure();
						}
						$top1m_base_backups[$top1m_base_path] = $top1m_base_copy;
					}
				}
				$top1m_active_backup = @tempnam(dirname($head_download), '.pfbtop1m_active_');
				if ($top1m_active_backup === FALSE || !@unlink($top1m_active_backup)) {
					rmdir_recursive($top1m_base_backup);
					rmdir_recursive($top1m_stage);
					unlink_if_exists($file_download);
					return PfbDownloadResult::failure();
				}
				$top1m_had_active = file_exists($head_download) || is_link($head_download);
				if ($top1m_had_active && !@rename($head_download, $top1m_active_backup)) {
					rmdir_recursive($top1m_base_backup);
					rmdir_recursive($top1m_stage);
					unlink_if_exists($file_download);
					return PfbDownloadResult::failure();
				}
				$top1m_published = $top1m_target_dir
					? @rename($top1m_stage, $head_download)
					: @rename($top1m_staged_files[0], $head_download);
				if (!$top1m_published) {
					if ($top1m_had_active) {
						@rename($top1m_active_backup, $head_download);
					}
					rmdir_recursive($top1m_stage);
					rmdir_recursive($top1m_base_backup);
					unlink_if_exists($file_download);
					return PfbDownloadResult::failure();
				}
				if (!$top1m_target_dir) {
					rmdir_recursive($top1m_stage);
				}
				if (!pfb_top1m_persist_baseline($file_dwn, $file_download)) {
					is_dir($head_download) ? rmdir_recursive($head_download) : unlink_if_exists($head_download);
					if ($top1m_had_active) {
						@rename($top1m_active_backup, $head_download);
					}
					foreach (array("{$file_dwn}.orig", "{$file_dwn}.xxhash128", "{$file_dwn}.md5") as $top1m_base_path) {
						if (isset($top1m_base_backups[$top1m_base_path])) {
							@copy($top1m_base_backups[$top1m_base_path], $top1m_base_path);
						} elseif (is_file($top1m_base_path)) {
							@unlink($top1m_base_path);
						}
					}
					rmdir_recursive($top1m_base_backup);
					unlink_if_exists($file_download);
					return PfbDownloadResult::failure();
				}
				if ($top1m_had_active) {
					is_dir($top1m_active_backup) ? rmdir_recursive($top1m_active_backup) : unlink_if_exists($top1m_active_backup);
				}
				rmdir_recursive($top1m_base_backup);
				unlink_if_exists($file_download);
				touch("{$pfb['dbdir']}/top-1m.update");
				return PfbDownloadResult::success();
			}

			pfb_logger('.', 1);

			/* pfb_mime_normalise() (ADR-44) canonicalises ZIP-bearing MIME variants before
			   the allow-list gate. On a stock pfSense box, /usr/bin/file already returns
			   application/zip for real ZIP bytes (no false rejections occur without it);
			   normalisation is defensive — it handles custom magic databases and live
			   epub+zip-style archive types. This branch stays disabled because file -bZ
			   cannot classify a multi-member container (-Z decompresses a single stream);
			   the post-extraction PFB_FILTER_FILE_MIME re-check below is the ZIP
			   inner-content gate (issue #808).
			if (!pfb_filter(array("{$file_dwn_esc}", "{$file_download}", "{$list_download}"), PFB_FILTER_FILE_MIME_COMPRESSED, 'pfb_download')) {
				return PfbDownloadResult::failure();
			}
			*/
	
			// Check if ZIP archive contains xlsx files
			$xlsxtest = exec("/usr/bin/tar -tf {$file_dwn_esc}");
			if (strpos($xlsxtest, '.xlsx') !== FALSE) {
				// issue #2684: the helper unpacks the workbook into its OWN per-run temp
				// directory (`mktemp -d "${TMPDIR:-/tmp}/pfb.XXXXXXXX"`), which the
				// precheck above cannot see -- it belongs to a child process, not to
				// this function -- and which is a RAM disk on a default use_mfs_tmpvar
				// install. Same requirement as every other extraction and no fixed
				// floor: room for the archive itself. pfb_extract_temp_root() resolves
				// that directory the way the child does; the reasons it is neither
				// sys_get_temp_dir() nor a `?:` shorthand live at the helper.
				// Scoped to this branch on purpose: the gzip, bzip2 and tar paths write
				// nowhere near /tmp, and refusing them over a filesystem they never
				// touch would repeat issue #2658's 64 MiB-floor mistake.
				$xlsx_short = pfb_extract_space_shortfall(array(pfb_extract_temp_root()), (int) @filesize($file_download));
				if ($xlsx_short !== NULL) {
					pfb_validate_log($header, 'size', 'staging_space_low', $xlsx_short);
					unlink_if_exists($file_download);
					return PfbDownloadResult::failure();
				}
				// issue #2666: the helper's exit status decides the ingest, which is what
				// lets issue #2658's ceiling ride along. No unlink up front -- the
				// '.orig' already in service must survive a refused refresh.
				exec(pfb_extract_cmd("{$pfb['script']} xlsx {$header_esc} {$elog}"), $output, $retval);
				if (!pfb_download_extraction_succeeded($retval)) {
					pfb_logger("\n[pfb_download] xlsx extraction failed (script exit {$retval})" . pfb_extract_cap_note($retval), 2);
					unlink_if_exists($file_download);
					return PfbDownloadResult::failure();
				}
			} else {
				pfb_logger('.', 1);
				// Process ZIP file (SFS and hpHosts workaround)
				// pipefail so a tar extraction failure is not masked by the trailing
				// tr (issue #819); this exec runs on the appliance only -- FreeBSD sh
				// supports `set -o pipefail`.
				// ADR-46: stdout extraction (-xOf) -- member names never reach the
				// filesystem, so no member-name guard is needed on this path.
				$retval = pfb_download_initial_retval();
				$reject_detail = array();
				$inner_rejected = FALSE;
				$pfb_sanity = NULL;
				if (!pfb_stage_publish($orig_download,
				    static function (string $staged) use ($file_dwn_esc, $list_download,
				        &$output, &$retval, &$reject_detail, &$inner_rejected, &$pfb_sanity): int {
					exec(pfb_extract_cmd("set -o pipefail; /usr/bin/tar -xOf {$file_dwn_esc} | /usr/bin/sed 's/,[[:space:]]/; /g' | /usr/bin/tr ',' '\n' > " . escapeshellarg($staged)), $output, $retval);
					if ($retval !== 0) {
						return $retval;
					}
					// issue #2169: the inner-content gate unlinks whatever it probes, so
					// probe the staged copy -- a rejection must not reach the publication.
					if (!pfb_filter(array(escapeshellarg($staged), $staged, $list_download),
					    PFB_FILTER_FILE_MIME, 'pfb_download', '', FALSE, $reject_detail)) {
						$inner_rejected = TRUE;
						return pfb_download_initial_retval();
					}
					$pfb_sanity = pfb_extracted_text_sanity($staged, $retval);
					return $pfb_sanity === NULL ? $retval : pfb_download_initial_retval();
				})) {
					if ($pfb_sanity !== NULL) {
						pfb_validate_log($header, 'plaintext', $pfb_sanity, basename($orig_download));
					} elseif ($inner_rejected) {
						pfb_validate_log($header, 'inner', 'inner_mime_not_allowed', pfb_reject_detail_summary($reject_detail));
					} else {
						pfb_logger("\n[pfb_download] zip publish failed (tar exit {$retval})" . pfb_extract_cap_note($retval), 2);
					}
					unlink_if_exists($file_download);
					return PfbDownloadResult::failure();
				}
			}

			// ZIP inner-content gate (issue #808): probe the EXTRACTED payload
			// (orig_download), not the outer archive -- the outer container is
			// already covered by ADR-44's pfb_mime_normalise().
			$reject_detail = array();
			if (!pfb_filter(array("{$file_org_esc}", "{$orig_download}", "{$list_download}"), PFB_FILTER_FILE_MIME, 'pfb_download', '', FALSE, $reject_detail)) {
				pfb_validate_log($header, 'inner', 'inner_mime_not_allowed', pfb_reject_detail_summary($reject_detail));
				unlink_if_exists($file_download);
				return PfbDownloadResult::failure();
			}
		}
		else {
			// Uncompressed file format.
			if ($type == 'geoip' || $type == 'asn') {
				if ($file_type == 'application/x-tar') {
					if (!pfb_validate_archive($file_download, $file_type)) {
						pfb_validate_log($header, 'structural', 'probe_failed', "{$file_type} " . basename($file_download));
						unlink_if_exists($file_download);
						return PfbDownloadResult::failure();
					}
					$retval = pfb_download_initial_retval();
					if ($type == 'geoip') {
						return pfb_geoip_extract_tar_to_share($header, $file_download, $file_dwn_esc, $retval);
					}
					if (!pfb_stage_publish($head_download,
					    static function (string $staged) use ($file_dwn_esc, &$output, &$retval): int {
						exec(pfb_extract_cmd("/usr/bin/tar -xOf {$file_dwn_esc} > " . escapeshellarg($staged)), $output, $retval);
						return $retval;
					})) {
						unlink_if_exists($file_download);
						return PfbDownloadResult::failure();
					}
					unlink_if_exists($file_download);
					return PfbDownloadResult::success();
				}
				// Existing MaxMind/ASN path: preserve the direct rename contract.
				$renamed = @rename("{$file_download}", "{$head_download}");
				if (!$renamed) {
					pfb_logger("\n[pfb_download] {$type} rename to destination failed", 2);
					return PfbDownloadResult::failure();
				}
				return PfbDownloadResult::success();
			}
			if ($type == 'top1m') {
				// Stage TOP1M's plain body before publishing; baseline persistence
				// commits after active publication and rolls both back on failure.
				if ($file_type == 'application/x-tar') {
					if (!pfb_validate_archive($file_download, $file_type)) {
						pfb_validate_log($header, 'structural', 'probe_failed', "{$file_type} " . basename($file_download));
						unlink_if_exists($file_download);
						return PfbDownloadResult::failure();
					}
					$archive_members = pfb_archive_member_names($file_download, $file_type);
					$unsafe_member = pfb_archive_unsafe_member($archive_members);
					if ($unsafe_member !== NULL || $archive_members === NULL || count($archive_members) !== 1) {
						if ($unsafe_member !== NULL) {
							pfb_validate_log($header, 'member', 'unsafe_member_name', $unsafe_member);
						}
						unlink_if_exists($file_download);
						return PfbDownloadResult::failure();
					}
					$top1m_stage = @tempnam(dirname($head_download), '.pfbtop1m_');
					if ($top1m_stage === FALSE) {
						unlink_if_exists($file_download);
						return PfbDownloadResult::failure();
					}
					$top1m_stage_esc = escapeshellarg($top1m_stage);
					$retval = pfb_download_initial_retval();
					exec(pfb_extract_cmd("/usr/bin/tar -xOf {$file_dwn_esc} > {$top1m_stage_esc}"), $output, $retval);
					if (!pfb_download_extraction_succeeded($retval)) {
						unlink_if_exists($file_download);
						unlink_if_exists($top1m_stage);
						pfb_logger("\n[pfb_download] top1m extraction failed (tar exit {$retval})" . pfb_extract_cap_note($retval), 2);
						return PfbDownloadResult::failure();
					}
				} else {
					$top1m_stage = @tempnam(dirname($head_download), '.pfbtop1m_');
					if ($top1m_stage === FALSE || !@copy($file_download, $top1m_stage)) {
						pfb_logger("\n[pfb_download] {$type} rename to destination failed", 2);
						if ($top1m_stage !== FALSE) {
							unlink_if_exists($top1m_stage);
						}
						unlink_if_exists($file_download);
						return PfbDownloadResult::failure();
					}
				}
				if (!pfb_top1m_candidate_valid($top1m_stage, $top1m_provider)) {
					pfb_validate_log($header, 'top1m', 'semantic_invalid', basename($top1m_stage));
					unlink_if_exists($file_download);
					unlink_if_exists($top1m_stage);
					return PfbDownloadResult::failure();
				}
				$top1m_base_backup = @tempnam(dirname($file_dwn), '.pfbtop1m_base_');
				if ($top1m_base_backup === FALSE || !@unlink($top1m_base_backup) || !@mkdir($top1m_base_backup, 0700)) {
					unlink_if_exists($file_download);
					unlink_if_exists($top1m_stage);
					return PfbDownloadResult::failure();
				}
				$top1m_base_backups = array();
				foreach (array("{$file_dwn}.orig", "{$file_dwn}.xxhash128", "{$file_dwn}.md5") as $top1m_base_path) {
					if (is_file($top1m_base_path)) {
						$top1m_base_copy = "{$top1m_base_backup}/" . basename($top1m_base_path);
						if (!@copy($top1m_base_path, $top1m_base_copy)) {
							rmdir_recursive($top1m_base_backup);
							unlink_if_exists($file_download);
							unlink_if_exists($top1m_stage);
							return PfbDownloadResult::failure();
						}
						$top1m_base_backups[$top1m_base_path] = $top1m_base_copy;
					}
				}
				$top1m_active_backup = @tempnam(dirname($head_download), '.pfbtop1m_active_');
				if ($top1m_active_backup === FALSE || !@unlink($top1m_active_backup)) {
					rmdir_recursive($top1m_base_backup);
					unlink_if_exists($file_download);
					unlink_if_exists($top1m_stage);
					return PfbDownloadResult::failure();
				}
				$top1m_had_active = file_exists($head_download) || is_link($head_download);
				if ($top1m_had_active && !@rename($head_download, $top1m_active_backup)) {
					rmdir_recursive($top1m_base_backup);
					unlink_if_exists($file_download);
					unlink_if_exists($top1m_stage);
					return PfbDownloadResult::failure();
				}
				if (!@rename($top1m_stage, $head_download)) {
					if ($top1m_had_active) {
						@rename($top1m_active_backup, $head_download);
					}
					rmdir_recursive($top1m_base_backup);
					unlink_if_exists($file_download);
					unlink_if_exists($top1m_stage);
					return PfbDownloadResult::failure();
				}
				if (!pfb_top1m_persist_baseline($file_dwn, $file_download)) {
					unlink_if_exists($head_download);
					if ($top1m_had_active) {
						@rename($top1m_active_backup, $head_download);
					}
					foreach (array("{$file_dwn}.orig", "{$file_dwn}.xxhash128", "{$file_dwn}.md5") as $top1m_base_path) {
						if (isset($top1m_base_backups[$top1m_base_path])) {
							@copy($top1m_base_backups[$top1m_base_path], $top1m_base_path);
						} elseif (is_file($top1m_base_path)) {
							@unlink($top1m_base_path);
						}
					}
					rmdir_recursive($top1m_base_backup);
					unlink_if_exists($file_download);
					return PfbDownloadResult::failure();
				}
				if ($top1m_had_active) {
					is_dir($top1m_active_backup) ? rmdir_recursive($top1m_active_backup) : unlink_if_exists($top1m_active_backup);
				}
				rmdir_recursive($top1m_base_backup);
				unlink_if_exists($file_download);
				touch("{$pfb['dbdir']}/top-1m.update");
				return PfbDownloadResult::success();
			}
			elseif ($type == 'blacklist') {
				if ($file_type == 'application/x-tar') {
					if (!pfb_validate_archive($file_download, $file_type)) {
						pfb_validate_log($header, 'structural', 'probe_failed', "{$file_type} " . basename($file_download));
						unlink_if_exists($file_download);
						return PfbDownloadResult::failure();
					}
					@rename("{$file_download}", strstr("{$file_download}", '.raw', TRUE));
					$file_esc = trim(escapeshellarg("{$file_dwn}"), "'");
					$filename = basename(basename("{$file_esc}", '.tar.gz'), '.tar');
					if (empty(pfb_filter($filename, PFB_FILTER_WORD, 'pfb_download category'))) {
						pfb_logger("\n Invalid filename [{$filename}]", 1);
						return PfbDownloadResult::failure();
					}
					$unsafe_member = pfb_archive_unsafe_member(pfb_archive_member_names($file_dwn, $file_type));
					if ($unsafe_member !== NULL) {
						pfb_validate_log($header, 'member', 'unsafe_member_name', $unsafe_member);
						unlink_if_exists($file_dwn);
						return PfbDownloadResult::failure();
					}
					$cmd = "--include='*domains' -s',.*/\\(.*\\)/\\(.*\\)/domains,{$filename}_\\1_\\2,' -s',.*/\\(.*\\)/domains,{$filename}_\\1,'";
					$retval = pfb_download_initial_retval();
					if (!pfb_stage_publish_dir("{$pfb['dbdir']}/{$filename}",
					    static function (string $staged) use ($file_dwn, $filename, $cmd, &$output, &$retval): int {
						exec(pfb_extract_cmd("/usr/bin/tar -xf " . escapeshellarg("{$file_dwn}") . " " . PFB_TAR_EXTRACT_FLAGS . " {$cmd} -C " . escapeshellarg("{$staged}/") . " >/dev/null 2>&1"), $output, $retval);
						return pfb_blacklist_tar_finalize_staged($staged, $filename, $retval);
					})) {
						pfb_logger("\n[pfb_download] blacklist extraction failed (tar exit {$retval})" . pfb_extract_cap_note($retval), 2);
						return PfbDownloadResult::failure();
					}
					return pfb_blacklist_tar_mark_updated($file_dwn, $filename);
				}
				// issue #2635: a MIME-allowlisted non-archive body is not a
				// successful Blacklist update — leave category files untouched.
				pfb_validate_log($header, 'extract', 'blacklist_not_archive', $file_type);
				unlink_if_exists($file_download);
				return PfbDownloadResult::failure();
			}
			else {
				if ($file_type == 'application/x-tar') {
					if (!pfb_validate_archive($file_download, $file_type)) {
						pfb_validate_log($header, 'structural', 'probe_failed', "{$file_type} " . basename($file_download));
						unlink_if_exists($file_download);
						return PfbDownloadResult::failure();
					}
					$retval = pfb_download_initial_retval();
					$pfb_sanity = NULL;
					if (!pfb_stage_publish($orig_download,
					    static function (string $staged) use ($file_dwn_esc, &$output, &$retval, &$pfb_sanity): int {
						exec(pfb_extract_cmd("/usr/bin/tar -xOf {$file_dwn_esc} > " . escapeshellarg($staged)), $output, $retval);
						$pfb_sanity = pfb_extracted_text_sanity($staged, $retval);
						return $pfb_sanity === NULL ? $retval : pfb_download_initial_retval();
					})) {
						if ($pfb_sanity !== NULL) {
							pfb_validate_log($header, 'plaintext', $pfb_sanity, basename($orig_download));
						} else {
							pfb_logger("\n[pfb_download] tar extraction failed (tar exit {$retval})" . pfb_extract_cap_note($retval), 2);
						}
						unlink_if_exists($file_download);
						return PfbDownloadResult::failure();
					}
				} else {
					// Rename file to 'orig' format
					$renamed = @rename("{$file_download}", "{$orig_download}");
					if (!$renamed) {
						pfb_logger("\n[pfb_download] {$header} rename to .orig failed", 2);
						return PfbDownloadResult::failure();
					}
					$retval = 0;
				}
			}
		}

		if (pfb_download_retval_success($retval)) {
			// Set downloaded file timestamp to remote timestamp
			if (isset($remote_stamp) && $remote_stamp != -1) {
				@touch("{$orig_download}", $remote_stamp);
			}

			// ADR-42 / issue #713 bug 5: refresh the content-hash sidecar at every
			// successful ingest so pfb_local_feed_changed() / the probe's conditional-GET
			// compare always land on the SAME domain of bytes the probe hashed.  The probe
			// (pfb_update_check -> pfb_download(PfbDownloadRequest(type: 'change_detect'))) hashes the RAW
			// fetched body (it returns before any decompression), so the persisted digest
			// here must cover those same raw bytes too -- not the decompressed '.orig' --
			// or a compressed feed (gz/bz2/zip) never matches and re-ingests every cron.
			// pfb_source_hash_target() resolves to $file_download (the raw '.raw' download,
			// still on disk for every compressed format) or falls back to $orig_download for
			// an uncompressed feed, where $file_download was already renamed away (above)
			// into $orig_download -- byte-identical to what was fetched, so the fallback is
			// exact, not an approximation.  This covers both local and remote standard feeds
			// (any path that finalises a plain .orig here).  The geoip/asn/top1m/blacklist
			// archive early-returns above do not reach this block, so they correctly never get a sidecar.
			pfb_download_finalize_text(
				"{$orig_download}",
				"{$orig_download}",
				pfb_source_hash_target($file_download, $orig_download)
			);

			// issue #1797: normalization deliberately does NOT run here. Only the
			// parse-loop consumers normalize: the helper's changed-verdict means
			// "changed since the last CONSUMER normalize", so a download-time call
			// would consume the change signal and make the loops' norm-skip gate
			// wrongly reuse stale staging (caught live by
			// test_cron_detects_changed_local_feed). The geoip/asn/top1m/blacklist
			// archive paths return above (issue #2735) and never reach the text pipeline.

			// Process Emerging Threats IQRisk if required
			if (strpos($list_url, 'iprepdata.txt') !== FALSE) {
				// issue #2683: gated on processet()'s exit status -- which is what lets
				// issue #2658's ceiling ride along here.
				exec(pfb_extract_cmd("{$pfb['script']} et {$header_esc} x x x x x {$pfb['etblock']} {$pfb['etmatch']} {$elog}"), $output, $retval);
				if (!pfb_download_extraction_succeeded($retval)) {
					pfb_logger("\n[pfb_download] et processing failed (script exit {$retval})" . pfb_extract_cap_note($retval), 2);
					// The '.orig' this pass published is the raw ET CSV (processet() rewrites it
					// in place), which the apply loop's fail-marker fallback would parse. Both sidecar
					// families go (pfb_force_clear_validators()' set) or a surviving ETag 304s the next pass.
					foreach (array('', '.xxhash128', '.md5', '.etag', '.lastmod') as $et_sfx) {
						unlink_if_exists("{$orig_download}{$et_sfx}");
					}
					unlink_if_exists($file_download);
					return PfbDownloadResult::failure();
				}
			}
				return PfbDownloadResult::success();
		}
		else {
			$log = "   Decompression Failed\n";
			pfb_logger("{$log}", 2);
				return PfbDownloadResult::failure();
		}
	}
	else {
		// Download failed
		unlink_if_exists("{$file_download}");
	}
	return PfbDownloadResult::failure();
}


// Determine reason for download failure
function pfb_download_failure($alias, $header, $pfbfolder, $list_url, $format, $vtype) {
	global $pfb;
	$pfbfound = FALSE;

	// Re-evaluate URL
	if ($format == 'whois') {
		if (empty(pfb_filter($list_url, PFB_FILTER_DOMAIN, 'pfb_download_failure'))) {
			pfb_logger("\n Invalid WHOIS. Terminating Download! [ " . pfb_redact_url($list_url) . " ]\n", 1);
		}
	}
	elseif ($format == 'asn') {
		if (empty(pfb_filter($list_url, PFB_FILTER_ALNUM, 'pfb_download_failure'))) {
			pfb_logger("\n Invalid ASN. Terminating Download! [ " . pfb_redact_url($list_url) . " ]\n", 1);
		}
	}
	elseif (!pfb_filter($list_url, PFB_FILTER_URL, 'pfb_download_failure')) {
		pfb_logger("\n Invalid URL. Terminating Download! [ " . pfb_redact_url($list_url) . " ]\n", 1);
	}
	else {
		// Determine if URL is a localfile
		$localfile = FALSE;
		if (pfb_filter($list_url, PFB_FILTER_URL, 'pfb_download_failure', '', TRUE)) {
			$localfile = TRUE;
		}

		// Log FAILED downloads and check if firewall or Snort/Suricata is blocking host
		$log = "\n\n [ {$alias} - {$header} ] Download FAIL\n";
		pfb_logger("{$log}", 2);

		// Only perform these checks if they are not 'localfiles'
		if ($localfile) {
			$log = "   Local File Failure\n";
			pfb_logger("{$log}", 2);
		}
		else {
			// Determine if Firewall/IPS/DNSBL is blocking download.
			$data = parse_url("{$list_url}");

			if (is_ipaddr($data['host'])) {
				$validate_list = array(array('type' => 'IP', 'data' => $data['host']));
			} else {
				$validate_list = resolve_host_addresses($data['host']);
			}

			$validate_list_final = array();
			if (!empty($validate_list) && is_array($validate_list)) {
				foreach ($validate_list as $validate) {
					if ($validate['type'] == 'CNAME') {
						$cname_list = resolve_host_addresses($validate['data']);
						if (!empty($cname_list) && is_array($cname_list)) {
							foreach ($cname_list as $cname) {
								if (!empty($cname['data'])) {
									$validate_list_final[$cname['data']] = "Host:{$data['host']} | CNAME:{$cname['host']}";
								}
							}
						}
					}
					elseif (!empty($validate['data'])) {
						$validate_list_final[$validate['data']] = $data['host'];
					}
				}
			}
			else {
				pfb_logger("\n Cannot Resolve Host:{$data['host']}", 1);
			}

			if (!empty($validate_list_final)) {
				foreach ($validate_list_final as $ip => $host) {
					if (is_ipaddr($ip)) {

						// Query Firewall aliastables
						$result = find_reported_header($ip, "{$pfbfolder}/*", FALSE);
						if (!empty($result) && $result[0] != 'Unknown') {
							$log = " [ {$ip} ] Firewall IP block found in: [ {$result[0]} | {$result[1]} ] for HOST:{$host}!\n";
							pfb_logger("{$log}", 2);
							$pfbfound = TRUE;
						}

						// Determine if Host is listed in DNSBL
						if ($ip == $pfb['dnsbl_vip4'] || text_to_compressed_ip6($ip) == text_to_compressed_ip6("{$pfb['dnsbl_vip6']}") || $ip == '0.0.0.0') {
							$log = " [ {$host} ] Domain blocked via DNSBL!\n";
							pfb_logger("{$log}", 2);
							$pfbfound = TRUE;
						}

						// Query Snort/Suricata snort2c IP block table
						$ip_esc = escapeshellarg($ip);
						// issue #713: parse the numeric match count instead of comparing the
						// raw output's first character -- see pfb_pfctl_test_match_count().
						$count = pfb_pfctl_test_match_count(exec("{$pfb['pfctl']} -t snort2c -T test {$ip_esc} 2>&1"));
						if ($count > 0) {
							$log = " [ {$ip} ] IDS IP block found for HOST:{$host}!\n";
							pfb_logger("{$log}", 2);
							$pfbfound = TRUE;
						}
					}
					else {
						pfb_logger("\nInvalid IP or NXDOMAIN found for HOST:{$host}", 2);
						$pfbfound = TRUE;
					}
				}
			}

			if (!$pfbfound) {
				$log = "  DNSBL, Firewall, and IDS (Legacy mode only) are not blocking download.\n";
				pfb_logger("{$log}", 2);
			}
		}
	}

	// Call function to get all previous download fails
	pfb_failures();

	// On download failure, create file marker for subsequent download attempts. ('0' no download failure threshold)
	if ($pfb['skipfeed'] == 0 || $pfb['failed'][$header] <= $pfb['skipfeed']) {
		touch("{$pfbfolder}/{$header}.fail");
		return;
	}

	unlink_if_exists("{$pfbfolder}/{$header}.fail");
	return;
}


// Collect all previously failed daily download notices
function pfb_failures() {
	global $pfb;
	$pfb['failed'] = array();

	if (file_exists("{$pfb['errlog']}")) {
		$today_date = date('Y-m-d', time());	// matches pfb_logger()'s ISO-8601 log timestamp
		exec("{$pfb['grep']} 'FAIL' {$pfb['errlog']} | {$pfb['grep']} {$today_date}", $results);
		if (!empty($results)) {
			foreach ($results as $result) {
				// ADR-60: every errlog line now carries pfb_logger()'s leading ISO-8601
				// stamp -- strip it first so header[4] still indexes into the original
				// (pre-stamp) message shape, unchanged from before this rework.
				$result = preg_replace('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} /', '', $result);
				$header = explode(' ', $result);
				$alias  = $header[4] ?? '';
				$pfb['failed'][$alias] = ($pfb['failed'][$alias] ?? 0) + 1;	// avoid PHP 8 undefined-key warning on first failure
			}
		}
	}
	return;
}


// Collect tracker IDs from non-pfBlockerNG filter/rule rows so both tracker generators
// can avoid minting an ID that collides with a GUI or third-party rule. Only filter/rule
// is consulted -- NAT rules carry no tracker. Rows owned by pfBlockerNG (pfb_is_managed_obj)
// are excluded so we never treat our own prior rules as foreign, preventing re-mint churn.
function pfb_collect_foreign_trackers(): array {
	$trackers = array();
	foreach (config_get_path('filter/rule', array()) as $row) {
		if (!isset($row['tracker']) || $row['tracker'] === '') {
			continue;
		}
		if (pfb_is_managed_obj($row['descr'] ?? '')) {
			continue;
		}
		$trackers[] = (int) $row['tracker'];
	}
	return $trackers;
}


// Convert unique Alias details (via ascii table number) and return a 10 digit tracker ID
function pfb_tracker($alias, $int, $text) {
	global $pfb;

	$pfbtracker	= 0;
	$real_int	= get_real_interface($int);
	$ipaddr		= get_interface_ip($int);

	if (is_ipaddrv4($ipaddr)) {
		$ipaddr = ip2long32($ipaddr);
		$subnet = find_interface_subnet($real_int);
	}
	else {
		$ipaddr = get_interface_ipv6($real_int);
		$subnet = find_interface_subnetv6($real_int);
	}

	$search		= array( '1', '2', '3', '4', '5', '6', '7', '8', '9', '0' );
	$replace	= array( 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'zero' );
	$line		= "{$alias}{$int}{$text}{$real_int}{$ipaddr}{$subnet}";
	$line		= str_replace($search, $replace, $line);

	for ($i = 0; $i < strlen($line); $i++) {
		$pfbtracker += @ord($line[$i]);
	}

	$pfbtracker = '177' . str_pad($pfbtracker, 7, '0', STR_PAD_LEFT);
	if (strlen($pfbtracker) > 10) {
        	$pfbtracker = substr($pfbtracker, 0, 10);
	}
	
	// If duplicate Tracker ID found, pre-define a Tracker ID (Starts at 1700000010).
	// Also skip IDs already in use by non-pfBlockerNG filter rules (foreign_trackerids).
	if (in_array($pfbtracker, $pfb['trackerids']) || in_array($pfbtracker, $pfb['foreign_trackerids'] ?? [])) {
		$pfbtracker = ($pfb['last_trackerid'] + 1);

		// Increment prefix (digits 1&2) and reset Last_tracker ID after 10 digits
		if (strlen($pfbtracker) > 10) {
			$tracker_prefix = substr($pfbtracker, 0, 2);
			$pfbtracker	= ($tracker_prefix + 1) . '00000010';
		}
		// Keep bumping until free in both sets (handles runs of foreign collisions).
		while (in_array($pfbtracker, $pfb['trackerids']) || in_array($pfbtracker, $pfb['foreign_trackerids'] ?? [])) {
			$pfbtracker++;
			if (strlen($pfbtracker) > 10) {
				$tracker_prefix = substr($pfbtracker, 0, 2);
				$pfbtracker	= ($tracker_prefix + 1) . '00000010';
			}
		}
		$pfb['last_trackerid'] = $pfbtracker;
	}
	
	$pfb['trackerids'][] = $pfbtracker;
	return (int)$pfbtracker;
}


// Deterministic, IP-independent firewall-rule tracker for pfBlockerNG MANAGED STATIC rules
// (ADR-37 DoT/DoQ block). Modelled on pfb_tracker() (feed rules) but keyed on the rule's
// stable 'descr' ALONE — no interface IP/subnet — so the id is identical across re-syncs and
// survives a DHCP renewal; a fresh-each-sync tracker would churn write_config()/
// filter_configure() every sync. (ADR-36 NAT redirect rules need no tracker.) Namespaced '176'
// (distinct from feed trackers '177'); 176xxxxxxx is a PAST Unix epoch (~Oct 2025) so it can
// never collide with a future GUI rule's microtime() tracker, staying under pf's uint32
// ridentifier ceiling. Duplicates step to a sequential id in the same namespace.
function pfb_managed_rule_tracker(string $descr): int {
	global $pfb;

	if (!isset($pfb['trackerids']) || !is_array($pfb['trackerids'])) {
		$pfb['trackerids'] = array();
	}

	// Char-sum the descr (digit->word first, matching pfb_tracker()'s reduction so
	// digits don't bias the sum), then '176' + 7-digit body = a 10-digit numeric id.
	$search  = array('1', '2', '3', '4', '5', '6', '7', '8', '9', '0');
	$replace = array('one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'zero');
	$line    = str_replace($search, $replace, $descr);
	$sum     = 0;
	for ($i = 0, $n = strlen($line); $i < $n; $i++) {
		$sum += ord($line[$i]);
	}
	$tracker = (int) ('176' . str_pad((string) ($sum % 10000000), 7, '0', STR_PAD_LEFT));

	// Collision -> probe DETERMINISTICALLY by re-deriving from the descr's char-sum
	// (NOT a global running counter): a colliding descr maps to the SAME id on every
	// re-sync given the same set of occupied ids — preserving the determinism this
	// tracker exists for. Stays inside the '176' + 7-digit namespace (<= uint32) via
	// the modulo, and loops past any further collision so it never returns a duplicate.
	$probe = 0;
	while (in_array($tracker, $pfb['trackerids'], TRUE) || in_array($tracker, $pfb['foreign_trackerids'] ?? [], TRUE)) {
		$probe++;
		$tracker = (int) ('176' . str_pad((string) (($sum + $probe) % 10000000), 7, '0', STR_PAD_LEFT));
	}

	$pfb['trackerids'][] = $tracker;
	return $tracker;
}


// Define firewall rule settings
function pfb_firewall_rule($action, $pfb_alias, $vtype, $pfb_log, $agateway_in='default', $agateway_out='default',
	    $aaddrnot_in='', $adest_in='', $aports_in='', $aproto_in='', $anot_in='',
	    $aaddrnot_out='', $asrc_out='', $aports_out='', $aproto_out='', $anot_out='') {

	global $pfb;
	$rule = array();

	switch ($action) {
		case 'Deny_Both':
		case 'Deny_Outbound':
			$rule = $pfb['base_rule'];
			$rule['type'] = "{$pfb['deny_action_outbound']}";
			if ($vtype == '_v6') {
				$rule['ipprotocol'] = 'inet6';
			}
			if ($pfb['float'] === PfbToggle::On) {
				$rule['direction'] = 'out';
			}
			$rule['descr'] = "{$pfb_alias}{$pfb['suffix']}";
			if (!empty($asrc_out)) {
				$rule['source'] = array('address' => "{$asrc_out}");
			} else {
				$rule['source'] = array('any' => '');
			}
			if (!empty($asrc_out) && $anot_out == 'on') {
				$rule['source']['not'] = '';
			}
			if (!empty($aports_out)) {
				$rule['destination'] = array('address' => "{$pfb_alias}", 'port' => "{$aports_out}");
			} else {
				$rule['destination'] = array('address' => "{$pfb_alias}");
			}
			if ($aaddrnot_out == 'on') {
				$rule['destination']['not'] = '';
			}
			if (!empty($aproto_out)) {
				$rule['protocol'] = "{$aproto_out}";
			}
			if ($pfb['global_log'] === PfbToggle::On || $pfb_log == 'enabled') {
				$rule['log'] = '';
			}
			if (!empty($agateway_out) && $agateway_out != 'default') {
				$rule['gateway'] = "{$agateway_out}";
			}
			$rule['created'] = array('time' => (int)microtime(TRUE), 'username' => 'Auto');
			$pfb['deny_outbound'][] = $rule;
			if ($action != 'Deny_Both') {
				break;
			}
		case 'Deny_Inbound':
			$rule = $pfb['base_rule'];
			$rule['type'] = "{$pfb['deny_action_inbound']}";
			if ($vtype == '_v6') {
				$rule['ipprotocol'] = 'inet6';
			}
			if ($pfb['float'] === PfbToggle::On) {
				$rule['direction'] = 'in';
			}
			$rule['descr'] = "{$pfb_alias}{$pfb['suffix']}";
			$rule['source'] = array('address' => "{$pfb_alias}");
			if ($aaddrnot_in == 'on') {
				$rule['source']['not'] = '';
			}
			if (!empty($adest_in) && !empty($aports_in)) {
				$rule['destination'] = array('address' => "{$adest_in}", 'port' => "{$aports_in}");
			} elseif (!empty($adest_in) && empty($aports_in)) {
				$rule['destination'] = array('address' => "{$adest_in}");
			} elseif (empty($adest_in) && !empty($aports_in)) {
				$rule['destination'] = array('any' => '', 'port' => "{$aports_in}");
			} else {
				$rule['destination'] = array('any' => '');
			}
			if (!empty($adest_in) && $anot_in == 'on') {
				$rule['destination']['not'] = '';
			}
			if (!empty($aproto_in)) {
				$rule['protocol'] = "{$aproto_in}";
			}
			if ($pfb['global_log'] === PfbToggle::On || $pfb_log == 'enabled') {
				$rule['log'] = '';
			}
			if (!empty($agateway_in) && $agateway_in != 'default') {
				$rule['gateway'] = "{$agateway_in}";
			}
			$rule['created'] = array('time' => (int)microtime(TRUE), 'username' => 'Auto');
			$pfb['deny_inbound'][] = $rule;
			break;
		case 'Permit_Both':
		case 'Permit_Outbound':
			$rule = $pfb['base_rule'];
			$rule['type'] = 'pass';
			if ($vtype == '_v6') {
				$rule['ipprotocol'] = 'inet6';
			}
			if ($pfb['float'] === PfbToggle::On) {
				$rule['direction'] = 'out';
			}
			$rule['descr'] = "{$pfb_alias}{$pfb['suffix']}";
			if (!empty($asrc_out)) {
				$rule['source'] = array('address' => "{$asrc_out}");
			} else {
				$rule['source'] = array('any' => '');
			}
			if (!empty($asrc_out) && $anot_out == 'on') {
				$rule['source']['not'] = '';
			}
			if (!empty($aports_out)) {
				$rule['destination'] = array('address' => "{$pfb_alias}", 'port' => "{$aports_out}");
			} else {
				$rule['destination'] = array('address' => "{$pfb_alias}");
			}
			if ($aaddrnot_out == 'on') {
				$rule['destination']['not'] = '';
			}
			if (!empty($aproto_out)) {
				$rule['protocol'] = "{$aproto_out}";
			}
			if ($pfb['global_log'] === PfbToggle::On || $pfb_log == 'enabled') {
				$rule['log'] = '';
			}
			if (!empty($agateway_out) && $agateway_out != 'default') {
				$rule['gateway'] = "{$agateway_out}";
			}
			$rule['created'] = array('time' => (int)microtime(TRUE), 'username' => 'Auto');
			$pfb['permit_outbound'][] = $rule;
			if ($action != 'Permit_Both') {
				break;
			}
		case 'Permit_Inbound':
			$rule = $pfb['base_rule'];
			$rule['type'] = 'pass';
			if ($vtype == '_v6') {
				$rule['ipprotocol'] = 'inet6';
			}
			if ($pfb['float'] === PfbToggle::On) {
				$rule['direction'] = 'in';
			}
			$rule['descr'] = "{$pfb_alias}{$pfb['suffix']}";
			$rule['source'] = array('address' => "{$pfb_alias}");
			if ($aaddrnot_in == 'on') {
				$rule['source']['not'] = '';
			}
			if (!empty($adest_in) && !empty($aports_in)) {
				$rule['destination'] = array('address' => "{$adest_in}", 'port' => "{$aports_in}");
			} elseif (!empty($adest_in) && empty($aports_in)) {
				$rule['destination'] = array('address' => "{$adest_in}");
			} elseif (empty($adest_in) && !empty($aports_in)) {
				$rule['destination'] = array('any' => '', 'port' => "{$aports_in}");
			} else {
				$rule['destination'] = array('any' => '');
			}
			if (!empty($adest_in) && $anot_in == 'on') {
				$rule['destination']['not'] = '';
			}
			if (!empty($aproto_in)) {
				$rule['protocol'] = "{$aproto_in}";
			}
			if ($pfb['global_log'] === PfbToggle::On || $pfb_log == 'enabled') {
				$rule['log'] = '';
			}
			if (!empty($agateway_in) && $agateway_in != 'default') {
				$rule['gateway'] = "{$agateway_in}";
			}
			$rule['created'] = array('time' => (int)microtime(TRUE), 'username' => 'Auto');
			$pfb['permit_inbound'][] = $rule;
			break;
		case 'Match_Both':
		case 'Match_Outbound':
			$rule = $pfb['base_rule_float'];
			$rule['type'] = 'match';
			unset($rule['quick']);
			if ($vtype == '_v6') {
				$rule['ipprotocol'] = 'inet6';
			}
			$rule['direction'] = 'out';
			$rule['descr'] = "{$pfb_alias}{$pfb['suffix']}";
			if (!empty($asrc_out)) {
				$rule['source'] = array('address' => "{$asrc_out}");
			} else {
				$rule['source'] = array('any' => '');
			}
			if (!empty($asrc_out) && $anot_out == 'on') {
				$rule['source']['not'] = '';
			}
			if (!empty($aports_out)) {
				$rule['destination'] = array('address' => "{$pfb_alias}", 'port' => "{$aports_out}");
			} else {
				$rule['destination'] = array('address' => "{$pfb_alias}");
			}
			if ($aaddrnot_out == 'on') {
				$rule['destination']['not'] = '';
			}
			if (!empty($aproto_out)) {
				$rule['protocol'] = "{$aproto_out}";
			}
			if ($pfb['global_log'] === PfbToggle::On || $pfb_log == 'enabled') {
				$rule['log'] = '';
			}
			if (!empty($agateway_out) && $agateway_out != 'default') {
				$rule['gateway'] = "{$agateway_out}";
			}
			$rule['created'] = array('time' => (int)microtime(TRUE), 'username' => 'Auto');
			$pfb['match_outbound'][] = $rule;
			if ($action != 'Match_Both') {
				break;
			}
		case 'Match_Inbound':
			$rule = $pfb['base_rule_float'];
			$rule['type'] = 'match';
			unset($rule['quick']);
			if ($vtype == '_v6') {
				$rule['ipprotocol'] = 'inet6';
			}
			$rule['direction'] = 'in';
			$rule['descr'] = "{$pfb_alias}{$pfb['suffix']}";
			$rule['source'] = array('address' => "{$pfb_alias}");
			if ($aaddrnot_in == 'on') {
				$rule['source']['not'] = '';
			}
			if (!empty($adest_in) && !empty($aports_in)) {
				$rule['destination'] = array('address' => "{$adest_in}", 'port' => "{$aports_in}");
			} elseif (!empty($adest_in) && empty($aports_in)) {
				$rule['destination'] = array('address' => "{$adest_in}");
			} elseif (empty($adest_in) && !empty($aports_in)) {
				$rule['destination'] = array('any' => '', 'port' => "{$aports_in}");
			} else {
				$rule['destination'] = array('any' => '');
			}
			if (!empty($adest_in) && $anot_in == 'on') {
				$rule['destination']['not'] = '';
			}
			if (!empty($aproto_in)) {
				$rule['protocol'] = "{$aproto_in}";
			}
			if ($pfb['global_log'] === PfbToggle::On || $pfb_log == 'enabled') {
				$rule['log'] = '';
			}
			if (!empty($agateway_in) && $agateway_in != 'default') {
				$rule['gateway'] = "{$agateway_in}";
			}
			$rule['created'] = array('time' => (int)microtime(TRUE), 'username' => 'Auto');
			$pfb['match_inbound'][] = $rule;
			break;
	}
	return;
}


// Archive IP aliastables and DNSBL database. ( Ramdisk installations only )
function pfb_aliastables($mode) {
	global $g, $pfb;

	$msg = '';
	$earlyshellcmd = '/usr/local/pkg/pfblockerng/pfblockerng.sh aliastables';

	// Reload config.xml to get any recent changes
	config_read_file(FALSE, TRUE);

	$a_earlyshellcmd = config_get_path('system/earlyshellcmd', []);
	$a_shellcmdsettings = config_get_path('installedpackages/shellcmdsettings/config', []);

	// Only execute function if Ramdisks are used.
	if (config_path_enabled('system', 'use_mfs_tmpvar')) {

		// Archive aliastable folder
		if ($mode == 'update') {
			pfb_logger("\nArchiving Aliastable folder", 1);

			$files_to_backup = '';
			// #468: IP-only. The DNSBL python integration is archived separately by
			// pfb_dnsbl_cache() (different lifecycle); ADR-08 had wrongly piggybacked
			// the /var/unbound/pfb_unbound* + pfb_py_* files onto this IP archive.
			$files = glob("{{$pfb['aliasdir']}/pfB_*.txt,{$pfb['dnsbl_file']}.conf}", GLOB_BRACE) ?: [];
			// ADR-43: include the due-ledger so cron schedules survive a RAM-disk reboot.
			$pfb_ledger = "{$pfb['dbdir']}/pfb_due_ledger.json";
			if (is_file($pfb_ledger)) {
				$files[] = $pfb_ledger;
			}
			if (!empty($files)) {
				$files_to_backup = implode(' ', array_map('escapeshellarg', array_filter($files)));
			}

			// Archive IP Aliastables as required. #468: route through the shell
			// pfb_compress helper so the codec choice (zstd, else bzip2) stays
			// single-sourced; it appends .zst/.bz2 to the base and retires a stale
			// .bz2 after a verified zstd write.
			if (!empty($files_to_backup)) {
				exec(escapeshellarg($pfb['script']) . ' pfb_compress ' .
					escapeshellarg($pfb['aliasarchive']) . " {$files_to_backup} >/dev/null 2>&1");
				pfb_logger("\nArchiving selected pfBlockerNG files.\n", 1);
			} else {
				pfb_logger("\nNo Files to archive.\n", 1);
			}
		}

		// Check conf file for earlyshellcmd/shellcmd package settings
		elseif ($mode == 'conf') {

			// Add earlyshellcmd settings
			if (!empty($a_earlyshellcmd)) {
				if (!preg_grep("/pfblockerng.sh aliastables/", $a_earlyshellcmd)) {
					$a_earlyshellcmd[] = "{$earlyshellcmd}";
					$msg = "\n** Adding earlyshellcmd settings **\n";
				}
			}
			else {
				$a_earlyshellcmd = "{$earlyshellcmd}";
				$msg = "\n** Adding earlyshellcmd settings **\n";
			}

			// Add shellcmd package settings
			$found = FALSE;
			if (!empty($a_shellcmdsettings)) {
				foreach ($a_shellcmdsettings as $key => $shellcmd) {
					if (strpos($shellcmd['cmd'], 'pfblockerng.sh aliastables') !== FALSE) {
						$found = TRUE;
						break;
					}
				}
			}

			if (!$found) {
				$add = array(	'cmd' 		=> $earlyshellcmd,
						'cmdtype'	=> 'earlyshellcmd',
						'description'	=> 'pfBlockerNG earlyshellcmd. DO NOT EDIT/DELETE!');

				$a_shellcmdsettings[] = $add;
				$msg .= "\n** Adding shellcmd package settings **\n";
			}
		}
	}
	else {
		// Remove aliastables archive (both .zst and .bz2) if found
		unlink_if_exists("{$pfb['aliasarchive']}.zst");
		unlink_if_exists("{$pfb['aliasarchive']}.bz2");

		// Remove earlyshellcmd settings
		if (!empty($a_earlyshellcmd)) {
			if (preg_grep("/pfblockerng.sh aliastables/", $a_earlyshellcmd)) {
				$a_earlyshellcmd = preg_grep("/pfblockerng.sh aliastables/", $a_earlyshellcmd, PREG_GREP_INVERT);
				$msg = "\n** Removing earlyshellcmd settings **\n";
			}
		}

		// Remove shellcmd package settings
		if (!empty($a_shellcmdsettings)) {
			foreach ($a_shellcmdsettings as $key => $shellcmd) {
				if (strpos($shellcmd['cmd'], 'pfblockerng.sh aliastables') !== FALSE) {
					unset($a_shellcmdsettings[$key]);
					$msg .= "\n** Removing shellcmd package settings**\n";
				}
			}
		}
	}

	if (!empty($msg)) {
		pfb_logger("{$msg}", 1);
		config_set_path('system/earlyshellcmd', $a_earlyshellcmd);
		config_set_path('installedpackages/shellcmdsettings/config', $a_shellcmdsettings);
		write_config('pfBlockerNG: saving earlyshellcmd');
	}
}


// #468: DNSBL python-integration cache for RAM-disk /var (use_mfs_tmpvar) installs. SEPARATE
// from pfb_aliastables() on purpose — the IP-alias archive and the DNSBL archive have different
// lifecycles. All file ops live in 'pfblockerng.sh dnsbl_cache' (one home, in shell). 'conf':
// register the boot 'dnsbl_cache restore' earlyshellcmd when DNSBL is enabled AND /var is a RAM
// disk; otherwise remove it and delete the archive. 'save': archive the current generated DNSBL
// state (called post-reload on a real DNSBL change; the caller gates on use_mfs_tmpvar + DNSBL
// enabled).
function pfb_dnsbl_cache($mode) {
	global $pfb;

	$earlyshellcmd = '/usr/local/pkg/pfblockerng/pfblockerng.sh dnsbl_cache restore';

	if ($mode == 'save') {
		exec('/usr/local/pkg/pfblockerng/pfblockerng.sh dnsbl_cache save >/dev/null 2>&1');
		return;
	}

	// $mode == 'conf'
	// Reload config.xml to get any recent changes (parity with pfb_aliastables()).
	config_read_file(FALSE, TRUE);

	$msg = '';
	$a_earlyshellcmd = config_get_path('system/earlyshellcmd', []);
	$a_shellcmdsettings = config_get_path('installedpackages/shellcmdsettings/config', []);

	// Register only when DNSBL is enabled AND /var is a RAM disk; else deregister.
	$want = ($pfb['dnsbl'] === PfbToggle::On && config_path_enabled('system', 'use_mfs_tmpvar'));

	if ($want) {
		// Add earlyshellcmd settings (distinct 'dnsbl_cache restore' string).
		if (!empty($a_earlyshellcmd)) {
			if (!preg_grep("/pfblockerng.sh dnsbl_cache restore/", $a_earlyshellcmd)) {
				$a_earlyshellcmd[] = "{$earlyshellcmd}";
				$msg = "\n** Adding DNSBL cache earlyshellcmd settings **\n";
			}
		} else {
			$a_earlyshellcmd = "{$earlyshellcmd}";
			$msg = "\n** Adding DNSBL cache earlyshellcmd settings **\n";
		}

		// Add shellcmd package settings
		$found = FALSE;
		if (!empty($a_shellcmdsettings)) {
			foreach ($a_shellcmdsettings as $shellcmd) {
				if (strpos($shellcmd['cmd'], 'pfblockerng.sh dnsbl_cache restore') !== FALSE) {
					$found = TRUE;
					break;
				}
			}
		}

		if (!$found) {
			$add = array(	'cmd'		=> $earlyshellcmd,
					'cmdtype'	=> 'earlyshellcmd',
					'description'	=> 'pfBlockerNG DNSBL cache earlyshellcmd. DO NOT EDIT/DELETE!');

			$a_shellcmdsettings[] = $add;
			$msg .= "\n** Adding DNSBL cache shellcmd package settings **\n";
		}
	}
	else {
		// Remove DNSBL cache archive (both .zst and .bz2) if found
		unlink_if_exists("{$pfb['dnsblarchive']}.zst");
		unlink_if_exists("{$pfb['dnsblarchive']}.bz2");

		// Remove earlyshellcmd settings
		if (!empty($a_earlyshellcmd)) {
			if (preg_grep("/pfblockerng.sh dnsbl_cache restore/", $a_earlyshellcmd)) {
				$a_earlyshellcmd = preg_grep("/pfblockerng.sh dnsbl_cache restore/", $a_earlyshellcmd, PREG_GREP_INVERT);
				$msg = "\n** Removing DNSBL cache earlyshellcmd settings **\n";
			}
		}

		// Remove shellcmd package settings
		if (!empty($a_shellcmdsettings)) {
			foreach ($a_shellcmdsettings as $key => $shellcmd) {
				if (strpos($shellcmd['cmd'], 'pfblockerng.sh dnsbl_cache restore') !== FALSE) {
					unset($a_shellcmdsettings[$key]);
					$msg .= "\n** Removing DNSBL cache shellcmd package settings **\n";
				}
			}
		}
	}

	if (!empty($msg)) {
		pfb_logger("{$msg}", 1);
		config_set_path('system/earlyshellcmd', $a_earlyshellcmd);
		config_set_path('installedpackages/shellcmdsettings/config', $a_shellcmdsettings);
		write_config('pfBlockerNG: saving DNSBL cache earlyshellcmd');
	}
}


// Collect pfBlockerNG rule names and Tracker IDs
function pfb_filterrules() {
	global $pfb;

	$rule_list		= array();
	$rule_list['id']	= array();
	$rule_list['other']	= array();
	$rule_list['int']	= array();

	exec("{$pfb['pfctl']} -vvsr 2>&1", $results);
	if (!empty($results)) {
		foreach ($results as $result) {
			if (str_starts_with($result, '@')) {

				$type = strstr(ltrim(strstr($result, ' ', FALSE), ' '), ' ', TRUE);
				if (in_array($type, array('block', 'pass', 'match'))) {

					// Since pfSense CE 2.6 and pfSense Plus 22.01, pf rules use an 'ridentifier' string
					if (strrpos($result, 'ridentifier') !== FALSE) {
						$id_begin_delim = 'ridentifier ';
						$id_end_delim = ' ';
					} elseif (strpos($result, '(') !== FALSE && strpos($result, ')') !== FALSE) {
						$id_begin_delim = '(';
						$id_end_delim = ')';
					} else {
						continue;
					}

					// Get the rule ID
					$id_begin_offset	= strpos($result, $id_begin_delim) + strlen($id_begin_delim);
					$id_end_offset		= strpos($result, $id_end_delim, $id_begin_offset);

					if ($id_end_offset !== FALSE) {
						$id_length = $id_end_offset - $id_begin_offset;
					} else {
						$id_length = strlen($result) - $id_begin_offset;
					}
					$id = substr($result, $id_begin_offset, $id_length);
					if (!is_numeric($id)) {
						continue;
					}

					// Add the rule to the list
					if (strpos($result, ' <pfB_') !== FALSE) {
						$descr = ltrim(stristr($result, '<pfb_', FALSE), '<');
						$descr = strstr($descr, ':', TRUE);
						$type  = strstr(ltrim(strstr($result, ' ', FALSE), ' '), ' ', TRUE);
						if ($type == 'match') {
							$type = 'unkn(%u)';
						}
	
						if (!is_array($rule_list[$id])) {
							$rule_list[$id] = array();
						}
	
						$rule_list['id'][]	= $id;
						$rule_list[$id]['name']	= $descr;
						$rule_list[$id]['type']	= $type;
	
						$int = strstr(ltrim(strstr($result, ' on ', FALSE), ' on '), ' ', TRUE);
						if (!empty($int)) {
							 $rule_list['int'][$int] = '';
						}
					}
					else {
						// All other non-pfBlockerNG Tracker IDs
						$rule_list['other'][$id] = '';
					}
				}
			}
		}
	}
	return $rule_list;
}


// Function to remove existing firewall states for IPs that are have been recently added to IP block/reject aliastables
function pfb_remove_states() {
	global $pfb;

	$log = "\n===[  Kill States  ]==================================================\n";
	pfb_logger("{$log}", 1);

	$pfb_tables = array();
	// Collect all 'pfB_' and 'pfb_' rules that are 'Block/Reject' and do not have bypass states enabled
	foreach (config_get_path('aliases/alias', []) as $alias) {
		if ($alias['type'] == 'urltable' && strpos($alias['name'], 'pfB_') !== FALSE && strpos($alias['descr'], '[s]') === FALSE) {
			foreach (config_get_path('filter/rule', []) as $rule) {
				if ($alias['name'] === $rule['source']['address'] || $alias['name'] === $rule['destination']['address']) {

					if ($rule['type'] == 'block' ||
						$rule['type'] == 'reject' ||
						strpos($rule['descr'], '[ks]') !== FALSE) {

						if (isset($rule['source']['address']) && !isset($rule['source']['not'])) {
							$pfb_tables[]	= $rule['source']['address'];
						}
						elseif (isset($rule['destination']['address']) && !isset($rule['destination']['not'])) {
							$pfb_tables[]	= $rule['destination']['address'];
						}
					}
				}
			}
		}
	}
	$pfb_tables = array_unique($pfb_tables);

	// List of IPs to suppress
	$pfb_local = $pfb_localsub = array();

	// Collect v4/v6 Suppression list entries (ADR-53): checked prefix-aware via
	// pfb_ip_suppressed() below, replacing the old exact-IP hashmap + subnetv4_expand()
	// '/24' materialisation -- which could only express a bare host or an exact '/24';
	// any other containing mask (v4 '/8'-'/23', any v6 mask) silently stayed
	// unsuppressed (ADR-53 §1.2/§2.2 -- a correctness strengthening).
	// ADR-53 review finding B: '?? ""' -- same absent-key guard as
	// pfb_create_suppression_file() (both keys are absent from config.xml
	// until their first save on an upgraded or fresh install).
	$v4suppression = pfb_text_area_decode($pfb['ipconfig']['v4suppression'] ?? '', TRUE, FALSE);
	$v6suppression = pfb_text_area_decode($pfb['ipconfig']['v6suppression'] ?? '', TRUE, FALSE);

	// Collect Interface list that have pfB Rules assigned
	$data		= pfb_filterrules();
	$pfb_int	= $data['int'] ?: array();

	// Collect local IPs. $pfb_local is an IP-keyed set (isset() lookups) END-TO-END:
	// pfb_collect_localip() already returns that shape, and plain lists are folded in
	// via array_fill_keys(). No trailing array_flip(array_unique()) dedup -- issue #769:
	// re-flipping the already-flipped map turned its keys back into integers, so the
	// isset($pfb_local[$s_ip]) exclusion below could never match those entries.
	$data = pfb_collect_localip();
	if (!empty($data[0])) {
		$pfb_local = array_merge($pfb_local, $data[0]);
	}
	$pfb_localsub = $data[1] ?: array();

	// Collect DNS servers to suppress
	$pfb_dnsservers = get_dns_servers();
	if (!empty($pfb_dnsservers)) {
		$pfb_local = array_merge($pfb_local, array_fill_keys($pfb_dnsservers, 0));
	}

	// Collect any 'Permit' Customlist IPs to suppress
	$custom_supp = array();
	foreach (array('pfblockernglistsv4', 'pfblockernglistsv6') as $ip_type) {
		foreach (config_get_path("installedpackages/{$ip_type}/config", []) as $list) {
			if (!pfb_group_action_valid($list['action'] ?? NULL, 'ipv4')) {
				continue;
			}
			if (!empty($list['custom']) && strpos($list['action'], 'Permit_') !== FALSE) {
				$custom		= pfb_text_area_decode($list['custom'], TRUE, FALSE);
				$custom_supp	= array_merge($custom_supp, $custom);
			}
		}
	}

	$custom_supp = array_unique(array_filter($custom_supp));
	// Append '/32' CIDR as required
	foreach ($custom_supp as &$custom) {
		if (strpos($custom, '/') === FALSE) {
			$custom = $custom . '/32';
		}
	}

	// Collect firewall states and save to temp file
	exec("{$pfb['pfctl']} -s state > {$pfb['states_tmp']} 2>&1");

	$state_count = $all_states = 0;
	$states		= array();
	$states[4]	= array();
	$states[6]	= array();

	if (($s_handle = @fopen("{$pfb['states_tmp']}", 'r')) !== FALSE) {
		while (($sline = @fgets($s_handle)) !== FALSE) {

			$all_states++;

			// SAMPLE : em0 udp 93.15.36.22:6881 -> 192.168.0.3:681		MULTIPLE:MULTIPLE
			// SAMPLE : pppoe0 udp 35.170.3.40:57197 (192.168.0.45:681) -> 22.41.123.206:1001	MULTIPLE:MULTIPLE
			// SAMPLE : em0 tcp 2001:65c:1398:101:124[443] <- 2001:170:2f:3e:a4c4:7b23:fe5f:b36e[52725]	FIN_WAIT_2:FIN_WAIT_2

			if (!empty($sline)) {

				$detail	= array_filter(explode(' ', $sline));

				// Validate states for pfB Interfaces only
				if (!isset($pfb_int[$detail[0]])) {
					continue;
				}

				$count	= count($detail);
				if ($count == 6) {
					$orig_s_ip = $detail[2];
				}
				elseif ($count == 7) {
					$orig_s_ip = $detail[5];
				}
				else {
					continue; // Unknown state line
				}
			}
			else {
				continue;
			}

			$ip_version = 4;

			// Strip IPv6 port
			if (strpos($orig_s_ip, '[') !== FALSE) {
				list($s_ip, $s_port)  = explode('[', $orig_s_ip);
				$ip_version = 6;
			}

			// Strip IPv4 port
			elseif (strpos($orig_s_ip, ':') !== FALSE && substr_count($orig_s_ip, ':') == 1) {
				list($s_ip, $s_port)  = explode(':', $orig_s_ip);
				$ip_version = 4;
			}

			// No port listed
			else {
				$s_ip	= $orig_s_ip;
				$s_port = '';

				if (is_ipaddrv6($s_ip)) {
					$ip_version = 6;
				}
			}

			// Exclude local and reserved IPs (Validate unique IPs only once)
			if (!isset($states[$ip_version][$s_ip])) {

				if ($ip_version == 4) {
					if (isset($pfb_local[$s_ip]) ||
					    pfb_local_ip($s_ip, $pfb_localsub) ||
					    pfb_ip_suppressed($s_ip, $v4suppression) ||
					    is_private_ip($s_ip) ||
					    substr($s_ip, 0, 2) == '0.' ||
					    substr($s_ip, 0, 4) == '127.' ||
					    substr($s_ip, 0, 3) >= 224) {
						continue;
					}
				}
				else {
					if (isset($pfb_local[$s_ip]) ||
					    pfb_local_ip($s_ip, $pfb_localsub) ||
					    pfb_ip_suppressed($s_ip, $v6suppression) ||
					    !filter_var($s_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
						continue;
					}
				}

				// Exclude any 'Permit' Customlist IPs
				foreach ($custom_supp as $custom) {
					if (ip_in_subnet($s_ip, $custom)) {
						continue 2;
					}
				}
			}

			$state = rtrim($sline, "\x00..\x1F");
			$state_count++;

			// Collect IP for state removal verification
			if (!is_array($states[$ip_version][$s_ip])) {
				$states[$ip_version][$s_ip] = array();
			}

			if (!in_array($state, $states[$ip_version][$s_ip])) {
				$states[$ip_version][$s_ip][] = $state;
			}
		}
	}
	else {
		pfb_logger("\n No Firewall States found", 1);
	}

	if ($s_handle) {
		@fclose($s_handle);
	}
	unlink_if_exists("{$pfb['states_tmp']}");
	unset($pfb_local, $pfb_localsub, $custom_supp);

	$pfbfound = FALSE;
	foreach ($states as $ip_version => $details) {

		if (!empty($details)) {
			$log = "\nFirewall state(s) validation for [ " . count($details) . " ] IPv{$ip_version} address(es)...";
			pfb_logger("{$log}", 1);
			ksort($details, SORT_NATURAL);
		}

		foreach ($details as $s_ip => $state) {
			foreach ($pfb_tables as $s_table) {

				// Compare IP version and aliastable type
				if ($ip_version == 4 && strpos($s_table, '_v4') !== FALSE ||
				    $ip_version == 6 && strpos($s_table, '_v6') !== FALSE) {

					$s_table_esc	= escapeshellarg($s_table);
					$s_ip_esc	= escapeshellarg($s_ip);
					// issue #713: parse the numeric match count instead of comparing the
					// raw output's first character -- see pfb_pfctl_test_match_count().
					$count = pfb_pfctl_test_match_count(exec("{$pfb['pfctl']} -t {$s_table_esc} -T test {$s_ip_esc} 2>&1"));
					if ($count > 0) {

						$pfbfound = TRUE;
						$log = "\n\n\t[ {$s_table} ] Removed " . count($state) . " state(s) for [ {$s_ip} ]\n\n";
						pfb_logger("{$log}", 1);

						foreach ($state as $line) {
							pfb_logger("\t\t{$line}\n", 1);
						}

						// Kill all state entries originating from $s_ip
						exec("{$pfb['pfctl']} -k {$s_ip_esc} 2>&1");

						// Kill all state entries to the target $s_ip
						exec("{$pfb['pfctl']} -k 0.0.0.0/0 -k {$s_ip_esc} 2>&1");

						break;
					}
				}
			}
		}
	}
	unset($states, $pfb_tables);

	if ($pfbfound) {
		pfb_logger("\n======================================================================\n", 1);
	} else {
		pfb_logger("\nNo matching states found\n\n======================================================================\n", 1);
	}
}


// For subnet addresses - Determine if alert host 'dest' is within a local IP range.
function pfb_local_ip($subnet, $pfb_localsub) {

	if (!empty($pfb_localsub)) {
		foreach ($pfb_localsub as $line) {
			if (ip_in_subnet($subnet, $line)) {
				return TRUE;
			}
		}
	}
	return FALSE;
}


// Collect local IP addresses
function pfb_collect_localip() {
	$pfb_local = $pfb_localsub = array();

	// Collect gateway IP addresses for inbound/outbound list matching.
	// Enumerate interfaces locally rather than calling core get_interfaces_with_gateway():
	// pfSense's XML parser stores an EMPTY interface element (e.g. <lan></lan>) as an empty
	// STRING, not an array, and core dereferences $ifcfg['ipaddr'] on every node -- a fatal
	// "Cannot access offset of type string on string" under PHP 8. Skip any non-array node so
	// a malformed/empty interface cannot abort the whole walk; behaviour is otherwise identical
	// to core for well-formed configs (dynamic-WAN ipaddr types, ovpn/ipsec, or an explicit gateway).
	foreach (config_get_path('interfaces', []) as $ifname => $ifcfg) {
		if (!is_array($ifcfg)) {
			continue;
		}
		$ipaddr = $ifcfg['ipaddr'] ?? '';
		$if     = $ifcfg['if'] ?? '';
		$has_gateway = in_array($ipaddr, array('dhcp', 'pppoe', 'pptp', 'l2tp', 'ppp'), TRUE)
			|| str_starts_with($if, 'ovpn')
			|| str_starts_with($if, 'ipsec')
			|| !empty($ifcfg['gateway']);
		if ($has_gateway) {
			$pfb_local[] = get_interface_ip($ifname) ?: 'Disabled';
		}
	}

	// Collect virtual IP aliases for inbound/outbound list matching
	foreach (config_get_path('virtualip/vip', []) as $list) {
		if (!empty($list['subnet']) && !empty($list['subnet_bits']) && is_subnet("{$list['subnet']}/{$list['subnet_bits']}")) {
			if (is_ipaddrv4($list['subnet'])) {
				if ($list['subnet_bits'] >= 24) {
					$pfb_local	= array_merge(subnetv4_expand("{$list['subnet']}/{$list['subnet_bits']}"), $pfb_local);
				} else {
					$pfb_localsub[]	= "{$list['subnet']}/{$list['subnet_bits']}";
				}
			}
			elseif (is_ipaddrv6($list['subnet'])) {
				$pfb_localsub[] = gen_subnetv6("{$list['subnet']}", "{$list['subnet_bits']}") . "/{$list['subnet_bits']}";
			}
		}
		elseif (is_ipaddr($list['subnet'])) {
			$pfb_local[] = "{$list['subnet']}";
		}
	}

	// Collect NAT IP addresses for inbound/outbound list matching
	foreach (config_get_path('nat/rule', []) as $natent) {
		$pfb_local[] = $natent['target'];
	}

	// Collect 1:1 NAT IP addresses for inbound/outbound list matching
	foreach (config_get_path('nat/onetoone', []) as $onetoone) {
		$pfb_local[] = $onetoone['source']['address'];
	}

	// Convert any 'Firewall Aliases' to IP address format.
	// A multi-entry alias's stored 'address' is a SPACE-SEPARATED string (e.g.
	// '10.0.0.1 10.0.0.2') -- replacing the matched $pfb_local entry with that
	// string verbatim leaves ONE unmatchable compound key once $pfb_local is
	// array_flip()ed below (#782). Split each matched alias's address and
	// classify every member individually: a plain IP becomes its own entry (so
	// it gets its own flipped key), a CIDR goes to $pfb_localsub (matched via
	// pfb_local_ip()), a member that is itself an alias NAME expands in place
	// (pfSense nested aliases, #784 -- visited-set walk: each distinct alias
	// expands at most once, so cycles/self-references terminate and a wide
	// alias-of-aliases tree costs work linear in config size), and anything
	// else (hostname, port) is dropped silently.
	$pfb_alias_addrs = array();
	foreach (config_get_path('aliases/alias', []) as $alias) {
		if (is_array($alias) && isset($alias['name'])) {
			$pfb_alias_addrs[$alias['name']] = (string) ($alias['address'] ?? '');
		}
	}
	if (!empty($pfb_alias_addrs)) {
		foreach ($pfb_local as $cnt => $entry) {
			// A malformed config value (e.g. an array-typed NAT target) must not
			// abort the walk: array_key_exists() throws a TypeError on a non-scalar
			// key under PHP 8. Leave it in place for the later array_flip() to
			// warn-and-drop, matching pre-#782 tolerance.
			if (!is_string($entry) || !array_key_exists($entry, $pfb_alias_addrs)) {
				continue;
			}
			unset($pfb_local[$cnt]);
			$pfb_alias_seen = array($entry => TRUE);
			$members = preg_split('/\s+/', trim($pfb_alias_addrs[$entry]));
			while (!empty($members)) {
				$member = array_shift($members);
				if ($member === '') {
					continue;
				}
				if (is_ipaddr($member)) {
					$pfb_local[] = $member;
				} elseif (is_subnet($member)) {
					$pfb_localsub[] = $member;
				} elseif (array_key_exists($member, $pfb_alias_addrs) && !isset($pfb_alias_seen[$member])) {
					$pfb_alias_seen[$member] = TRUE;
					foreach (preg_split('/\s+/', trim($pfb_alias_addrs[$member])) as $sub_member) {
						$members[] = $sub_member;
					}
				}
			}
		}
	}

	// Collect all interface addresses for inbound/outbound list matching
	foreach (config_get_path('interfaces', []) as $int) {
		if (!is_array($int)) {
			continue;
		}
		if ($int['ipaddr'] != 'dhcp') {
			if (!empty($int['ipaddr']) && !empty($int['subnet']) && is_subnet("{$int['ipaddr']}/{$int['subnet']}")) {
				if (is_ipaddrv4($int['ipaddr'])) {
					if ($int['subnet'] >= 24) {
						$pfb_local	= array_merge(subnetv4_expand("{$int['ipaddr']}/{$int['subnet']}"), $pfb_local);
					} else {
						$pfb_localsub[]	= "{$int['ipaddr']}/{$int['subnet']}";
					}
				}
			}
			elseif (is_ipaddr($int['ipaddr'])) {
				$pfb_local[] = "{$int['ipaddr']}";
			}
		}
	}

	// Collect runtime IPv6 addresses for inbound/outbound list matching.
	// pfSense stores an interface's IPv6 assignment under ['ipaddrv6']/['subnetv6'];
	// ['ipaddr'] (read by the interface loop above) only ever holds the IPv4 value or a
	// mode keyword (dhcp/pppoe/…) — never an IPv6 literal, static or dynamic. So this
	// runtime block is the SOLE source of interface-IPv6 locality, for every assignment
	// mode (static as well as track6/dhcp6/SLAAC): get_configured_ipv6_addresses()
	// returns the actual runtime addresses (keyed by friendly interface name).
	$pfb_v6 = get_configured_ipv6_addresses();
	if (!empty($pfb_v6)) {
		foreach ($pfb_v6 as $iface => $v6addr) {
			if (!is_ipaddrv6($v6addr)) {
				continue;
			}
			$pfb_local[] = $v6addr;
			$bits = get_interface_subnetv6($iface);
			if ($bits !== null && $bits !== '') {
				$subnet = gen_subnetv6($v6addr, (string) $bits);
				if (!empty($subnet)) {
					$pfb_localsub[] = $subnet . "/{$bits}";
				}
			}
		}
	}

	// Remove any duplicate IPs
	if (!empty($pfb_local)) {
		$pfb_local = array_flip(array_filter(array_unique($pfb_local)));
	}
	$pfb_localsub = array_unique($pfb_localsub);

	return array($pfb_local, $pfb_localsub);
}


// Collect local hostnames
function pfb_collect_localhosts() {
	global $g, $pfb;

	// Collect DHCP hostnames/IPs
	$local_hosts = array();

	// Collect configured pfSense interfaces
	$pf_int = get_configured_ip_addresses();
	if (isset($pf_int)) {
		$local_hosts = array_merge($local_hosts, array_flip(array_filter($pf_int)));
	}
	$pf_int = get_configured_ipv6_addresses();
	if (isset($pf_int)) {
		$local_hosts = array_merge($local_hosts, array_flip(array_filter($pf_int)));
	}

	// Collect dynamic DHCP hostnames/IPs
	if (dhcp_is_backend('isc')) {

		// DHCP ISC
		$leasesfile = "{$g['dhcpd_chroot_path']}/var/db/dhcpd.leases";

		$end = $hostname = '';
		if (file_exists("{$leasesfile}")) {
			if (($l_handle = @fopen("{$leasesfile}", 'r')) !== FALSE) {
				while (($line = @fgets($l_handle)) !== FALSE) {
					if (strpos($line, '{') !== FALSE) {
						$end = FALSE;
						$data = explode(' ', $line);
						$ip = $data[1];
					}
					if (strpos($line, 'client-hostname') !== FALSE) {
						$data = explode(' ', $line);
						$hostname = trim(str_replace(array('"', ';'), '', $data[3]));
					}
					if (strpos($line, '}') !== FALSE) {
						$end = TRUE;
					}
					if ($end) {
						if (!empty($ip)) {
							$ip = pfb_filter($ip, PFB_FILTER_IP, 'Collect dynamic DHCP hostnames');
						}

						if (!empty($hostname)) {
							$hostname = pfb_filter($hostname, PFB_FILTER_HOSTNAME, 'Collect dynamic DHCP hostnames');
						}

						if (!empty($ip) && !empty($hostname)) {
							$local_hosts[$ip] = $hostname;
						}
						$ip = $hostname = '';
					}
				}
			}
		}
	}
	else {

		// DHCP KEA
		$leases = system_get_kea4leases();
		if (isset($leases) && is_array($leases['lease'])) {
			foreach ($leases['lease'] as $lease) {
				if (!empty($lease)) {
					$ip		= pfb_filter($lease['ip'], PFB_FILTER_IP, 'Collect dynamic DHCP hostnames');
					$hostname	= pfb_filter($lease['hostname'], PFB_FILTER_HOSTNAME, 'Collect dynamic DHCP hostnames');

					if (!empty($ip) && !empty($hostname)) {
						$local_hosts[$ip] = $hostname;
					}
				}
			}
		}
	}

	// Collect static DHCP hostnames/IPs
	foreach (config_get_path('dhcpd', []) as $dhcp) {
		if (isset($dhcp['staticmap']) && is_array($dhcp['staticmap'])) {
			foreach ($dhcp['staticmap'] as $smap) {
				$local_hosts[$smap['ipaddr']] = strtolower("{$smap['hostname']}");
			}
		}
	}

	// Collect static DHCPv6 hostnames/IPs
	foreach (config_get_path('dhcpdv6', []) as $dhcpv6) {
		if (isset($dhcpv6['staticmap']) && is_array($dhcpv6['staticmap'])) {
			foreach ($dhcpv6['staticmap'] as $smap) {
				$local_hosts[$smap['ipaddrv6']] = strtolower("{$smap['hostname']}");
			}
		}
	}

	// Collect Unbound Host overrides
	$hosts = config_get_path('unbound/hosts', []);
	foreach ($hosts as $host) {
		$local_hosts[$host['ip']] = strtolower("{$host['descr']}");
	}

	// Collect NAT IP addresses by Target:Port
	foreach (config_get_path('nat/rule', []) as $natent) {
		$local_hosts["{$natent['target']}:{$natent['local-port']}"] = strtolower("{$natent['descr']}");
	}

	// Collect virtual IP aliases
	foreach (config_get_path('virtualip/vip', []) as $list) {
		if (!empty($list['subnet']) && !empty($list['subnet_bits'])) {
	
			// Use pfSense hostname for DNSBL vip
			if ($list['subnet'] == $pfb['dnsbl_vip4']) {
				$list['descr'] = config_get_path('system/hostname', 'pfSense') . '.' . (config_get_path('system/domain', 'localdomain'));
			}
			$local_hosts[$list['subnet']] = strtolower("{$list['descr']}");
		}
	}

	// Add localhost hostname
	if (!isset($local_hosts['127.0.0.1'])) {
		$local_hosts['127.0.0.1'] = strtolower((config_get_path('system/hostname', 'pfSense')) . '.' . (config_get_path('system/domain', 'localdomain')));
	}

	return $local_hosts;
}


// Resolve a filter.log Tracker ID to a pfBlockerNG rule. Returns TRUE when $tracker is a pfB
// rule whose type matches $type (caller processes the line); FALSE for a known non-pfB
// ('other') or an unresolvable tracker (caller skips).
//
// $rule_list: positive cache from pfb_filterrules(); rebuilt in place on a reparse.
// $miss_cache: PERSISTENT negative cache keyed by "tracker\0type"; survives reparses, so each
//   unresolvable tracker/type triggers at most ONE reparse for the daemon's life (keyed by
//   type + checking the positive cache first, so a transient type mismatch never suppresses a
//   later match). $reparse: callable() => array, fresh rule list. $on_reparse: callable() =>
//   void, refresh daemon-local IP/host collections after a reparse.
function pfb_resolve_tracker(
	array &$rule_list,
	array &$miss_cache,
	string $tracker,
	string $type,
	callable $reparse,
	?callable $on_reparse = NULL
): bool {
	// Known pfB tracker of the matching type. Checked before the miss cache so a tracker
	// that becomes valid (e.g. after a reparse for another tracker) always resolves.
	if (isset($rule_list[$tracker]) && $rule_list[$tracker]['type'] == $type) {
		return TRUE;
	}

	$miss_key = "{$tracker}\0{$type}";

	// Negative cache: a tracker/type the ruleset doesn't list (anchor/trackerless) — never reparse again.
	if (isset($miss_cache[$miss_key])) {
		return FALSE;
	}

	// Known non-pfB tracker.
	if (isset($rule_list['other'][$tracker])) {
		return FALSE;
	}

	// Unknown — reparse ONCE to pick up a freshly added/changed rule.
	$rule_list = ($reparse)();
	if ($on_reparse !== NULL) {
		($on_reparse)();
	}

	if (isset($rule_list[$tracker]) && $rule_list[$tracker]['type'] == $type) {
		return TRUE;
	}

	if (isset($rule_list['other'][$tracker])) {
		return FALSE;
	}

	// Still unresolved for this tracker/type after a fresh parse — record in the negative cache.
	$miss_cache[$miss_key] = TRUE;
	return FALSE;
}


// Reverse-DNS (PTR) lookup for block-log entries (issue #336). Defaults OFF for
// new installs; existing installs are seeded 'on' at upgrade (see
// pfb_rdns_seed_value() + pfblockerng_install.inc) to preserve prior behaviour.
function pfb_resolve_enabled(): bool {
	return PfbConfig::read('ip/enable_rdns') === PfbToggle::On;
}

// Decide the one-time upgrade seed for enable_rdns (issue #336). An EXISTING
// install (non-empty general config) that has no enable_rdns key yet predates
// the option and historically always resolved, so seed 'on' to preserve that.
// A fresh install (empty general config) is left unseeded -> defaults OFF.
// A box that already has the key (incl. an explicit '' opt-out) is never reseeded.
// $gconfig  = installedpackages/pfblockerng/config/0
// $ipconfig = installedpackages/pfblockerngipsettings/config/0
function pfb_rdns_seed_value(array $gconfig, array $ipconfig): ?string {
	if (!empty($gconfig) && !array_key_exists('enable_rdns', $ipconfig)) {
		return 'on';
	}
	return null;
}


// Read $path's modification time with the per-process stat cache CLEARED first, so a
// long-lived process (e.g. the filterlog daemon) — and any caller — always sees the true
// on-disk mtime rather than a value PHP cached on an earlier stat of the same path. Single
// choke point so no call site has to remember to clear the cache. Returns the mtime, or
// FALSE if $path is absent.
function pfb_file_mtime($path) {
	clearstatcache(TRUE, $path);
	return @filemtime($path);
}

// ADR-42: content-hash helpers — xxh128-based, tagged sidecar format, and file comparison.
//
// Hash convention: PHP uses hash('xxh128')/hash_file('xxh128'); shell uses xxh128sum + the
// .xxhash128 extension. Legacy .md5 sidecars are read but never written (they are replaced
// on the first write). An unknown tag → sentinel 'changed' so the current consumer
// re-ingests rather than falsely skipping.
//
// Sidecar naming: {base}.xxhash128  (new),  {base}.md5  (legacy read-only).

// Returns the xxh128 hex digest of a file or a string (caller picks via $is_file).
// Returns FALSE on any I/O error (file unreadable or non-existent).
// Pure — no I/O side effects beyond reading the input file when $is_file === TRUE.
function pfb_content_hash($path_or_data, $is_file = TRUE) {
	if ($is_file) {
		if (!is_string($path_or_data) || !file_exists($path_or_data)) {
			return FALSE;
		}
		return @hash_file('xxh128', $path_or_data);
	}
	return hash('xxh128', (string) $path_or_data);
}

// Read the tagged hash sidecar for a base path (e.g. {pfborig}/{header}.orig).
// Preference order: .xxhash128 (compare with xxh128) → .md5 (compare with md5) → bare
// untagged legacy content treated as md5.
//
// Returns an array: ['algo' => 'xxh128'|'md5', 'digest' => <hex string>].
// Returns ['algo' => 'changed', 'digest' => ''] as a sentinel when the sidecar is
// unreadable, has an unknown extension tag, or has no content — so any consumer that
// cannot read the sidecar treats the file as changed and re-ingests (fail-safe).
function pfb_hash_read($base) {
	$sentinel = array('algo' => 'changed', 'digest' => '');

	// Prefer the new xxhash128 sidecar.
	$xxh_path = "{$base}.xxhash128";
	if (file_exists($xxh_path)) {
		$raw = @file_get_contents($xxh_path);
		if ($raw === FALSE) {
			return $sentinel;
		}
		$digest = trim($raw);
		// A valid xxh128 digest is exactly 32 lowercase hex chars.
		if (!preg_match('/^[0-9a-f]{32}$/', $digest)) {
			return $sentinel;
		}
		return array('algo' => 'xxh128', 'digest' => $digest);
	}

	// Legacy .md5 sidecar (read-only; next write replaces it with .xxhash128).
	$md5_path = "{$base}.md5";
	if (file_exists($md5_path)) {
		$raw = @file_get_contents($md5_path);
		if ($raw === FALSE) {
			return $sentinel;
		}
		$digest = trim($raw);
		if (!preg_match('/^[0-9a-f]{32}$/', $digest)) {
			return $sentinel;
		}
		return array('algo' => 'md5', 'digest' => $digest);
	}

	// No sidecar found — treat as changed (fail-safe).
	return $sentinel;
}

// ADR-42 / issue #713 bug 5: resolve which on-disk file holds the RAW fetched body, so the
// source-hash sidecar pfb_download() persists at ingest hashes the SAME bytes as the probe
// (which hashes the raw body before any decompression). $file_download is the '.raw' download
// (pre-decompression); $orig_download is the finalised '.orig'. Compressed feed: the decompress
// tool doesn't delete its source, so $file_download still exists and IS the raw bytes — hash
// that. Uncompressed feed: $file_download was already renamed onto $orig_download, so it's gone
// but $orig_download holds byte-identical content — falling back to it is exact. Pure / no I/O
// beyond file_exists().
function pfb_source_hash_target($file_download, $orig_download) {
	return file_exists($file_download) ? $file_download : $orig_download;
}

// Write the xxhash128 sidecar for a file path and remove any superseded .md5 sidecar.
// $base is the base path (e.g. {pfborig}/{header}.orig); the hash is computed from $path.
// Returns TRUE on success, FALSE if the hash cannot be computed or the write fails.
function pfb_hash_write($base, $path) {
	$digest = pfb_content_hash($path, TRUE);
	if ($digest === FALSE) {
		return FALSE;
	}
	$xxh_path = "{$base}.xxhash128";
	$ok = (bool) @file_put_contents($xxh_path, $digest, LOCK_EX);
	if ($ok) {
		// Remove the superseded legacy sidecar if present — migration step.
		unlink_if_exists("{$base}.md5");
	}
	return $ok;
}

// issue #1098: a pre-#1072 corrupted probe body (.md5.raw) would be reused verbatim by
// the next sync ingest — purge at install/upgrade.
function pfb_purge_probe_bodies() {
	global $pfb;
	foreach (array($pfb['origdir'] ?? '', $pfb['dnsorigdir'] ?? '') as $dir) {
		if ($dir === '' || !is_dir($dir)) {	// never glob an empty dir value (would sweep '/')
			continue;
		}
		// Direct @unlink, NOT unlink_if_exists(): the latter re-globs its argument, so a
		// metachar-named leftover could survive; glob() already resolved a literal path.
		foreach (glob("{$dir}/*.md5.raw") ?: array() as $probe_body) {
			@unlink($probe_body);
		}
	}
}

// ADR-42: map a probe ('change_detect' mode) download path to the feed's persisted
// conditional-GET validator baseline.  The detector (pfb_update_check) persists the
// ETag/Last-Modified sidecars at {header}.orig (pfb_validator_write on its $local_file),
// but the probe is handed file_dwn = {header}.md5 so the probe body ({file_dwn}.raw =
// {header}.md5.raw) stays separate from the ingest body.  That `.md5` probe-infix must
// NOT leak into the validator base, or the read targets a non-existent {header}.md5.orig
// and the conditional GET never sends If-None-Match (the 304 fast-path stays dead).
// Strip a single trailing `.md5` before appending the `.orig` baseline suffix.
function pfb_conditional_get_validator_base($file_dwn) {
	$file_dwn = (string) $file_dwn;
	if (str_ends_with($file_dwn, '.md5')) {
		$file_dwn = substr($file_dwn, 0, -4);
	}
	return "{$file_dwn}.orig";
}

// ADR-42: read the per-feed HTTP validators (ETag + Last-Modified epoch)
// stored as sidecars next to the .orig baseline.
//
// Returns an array with keys:
//   'etag'     => string (the stored ETag header value) or FALSE if absent/unreadable.
//   'lastmod'  => int (Unix epoch from the Last-Modified response header) or FALSE if absent.
//
// Side-car paths: {base}.etag, {base}.lastmod
// Pure read — no I/O side effects beyond reading those two files.
function pfb_validator_read($base) {
	$etag = FALSE;
	$etag_path = "{$base}.etag";
	if (file_exists($etag_path)) {
		$raw = @file_get_contents($etag_path);
		if ($raw !== FALSE) {
			$v = trim($raw);
			if ($v !== '') {
				$etag = $v;
			}
		}
	}

	$lastmod = FALSE;
	$lm_path = "{$base}.lastmod";
	if (file_exists($lm_path)) {
		$raw = @file_get_contents($lm_path);
		if ($raw !== FALSE) {
			$v = trim($raw);
			// A valid lastmod sidecar holds a decimal integer (Unix epoch).
			if (preg_match('/^[0-9]+$/', $v)) {
				$lastmod = (int) $v;
			}
		}
	}

	return array('etag' => $etag, 'lastmod' => $lastmod);
}

// ADR-42: persist the HTTP validators for a feed's .orig base path.
// $etag is the ETag response header value (string) or FALSE/'' to skip.
// $lastmod is the Last-Modified epoch (int > 0) or FALSE to skip.
// Does nothing when neither value is meaningful — never writes an empty sidecar.
function pfb_validator_write($base, $etag, $lastmod) {
	// Strip CR/LF before storing: a malicious server ETag containing CRLF could inject
	// headers when the value is echoed back in If-None-Match on the next request.
	if (is_string($etag) && $etag !== '') {
		$etag = preg_replace('/[\r\n]/', '', $etag);
		if ($etag !== '') {
			@file_put_contents("{$base}.etag", $etag, LOCK_EX);
		}
	}
	if (is_int($lastmod) && $lastmod > 0) {
		@file_put_contents("{$base}.lastmod", (string) $lastmod, LOCK_EX);
	}
}

// ADR-43 Force modes: clear the per-feed conditional-GET sidecars so an on-demand detector
// run re-fetches every in-scope list file (no ETag/Last-Modified to send => the server returns
// 200 + body instead of 304).  Sweeps {dir}/*.orig.etag and *.orig.lastmod in each $dir; when
// $clear_hashes is TRUE also removes *.orig.xxhash128 and *.orig.md5 so a re-fetched body has no
// baseline to compare against and every list re-ingests regardless of content.  The .orig content
// files are left intact.  Returns the number of sidecars removed.
function pfb_force_clear_validators(array $dirs, bool $clear_hashes): int {
	$suffixes = array('etag', 'lastmod');
	if ($clear_hashes) {
		$suffixes[] = 'xxhash128';
		$suffixes[] = 'md5';
	}
	$removed = 0;
	foreach ($dirs as $dir) {
		foreach ($suffixes as $sfx) {
			foreach (glob("{$dir}/*.orig.{$sfx}") ?: array() as $sidecar) {
				if (unlink_if_exists($sidecar)) {
					$removed++;
				}
			}
		}
		// issue #1797: also clear the normalize-stage source-digest baselines so
		// pfb_feed_normalize() fail-safes to 'changed' and the downstream norm-skip
		// gate cannot defeat a forced reprocess.
		if ($clear_hashes) {
			foreach (glob("{$dir}/*.norm.src.xxhash128") ?: array() as $sidecar) {
				if (unlink_if_exists($sidecar)) {
					$removed++;
				}
			}
		}
	}
	return $removed;
}

// ADR-43 Force modes: map a Run Now scope to the feed orig dir(s) it covers — 'ip' => the IP
// orig dir, 'dnsbl' => the DNSBL orig dir, 'both' (and any unrecognized scope, fail-safe) =>
// both. Pure (the two dir paths are passed in) so it is unit-testable off-appliance; the
// Update page feeds it $pfb['origdir'] and $pfb['dnsorigdir'].
function pfb_force_scope_dirs(string $scope, string $ip_origdir, string $dnsbl_origdir): array {
	if ($scope === 'ip') {
		return array($ip_origdir);
	}
	if ($scope === 'dnsbl') {
		return array($dnsbl_origdir);
	}
	return array($ip_origdir, $dnsbl_origdir);
}

// ADR-42: pure decision helper for the remote conditional-GET result, called by the detector
// after pfb_download returns the probe response (contract: ADR-42 §2 #5/#6). 304 -> unchanged.
// 200 with body_hash == persisted_hash -> unchanged (spurious 200). 200 with body_hash !=
// persisted_hash -> changed. 200 with no persisted hash or body_hash FALSE -> changed
// (fail-safe: no baseline to compare). Any other status -> changed (fail-safe, never a false
// skip). Returns TRUE when re-ingest is needed, FALSE when confirmed unchanged.
function pfb_conditional_get_decision($http_status, $body_hash, $persisted_hash) {
	if ($http_status === '304') {
		return FALSE;	// Server confirmed: not modified.
	}
	if ($http_status !== '200') {
		return TRUE;	// Ambiguous/error — fail-safe: re-ingest.
	}
	// 200: compare body hash vs baseline.
	if ($body_hash === FALSE || $persisted_hash === '') {
		return TRUE;	// No usable comparison — fail-safe.
	}
	return ($body_hash !== $persisted_hash);	// TRUE = changed, FALSE = spurious 200 (same bytes).
}

// Issue #1542: TOP1M's dcc detector keeps the existing conditional-GET decision
// matrix but adds an explicit failed-probe state for its download ledger.
function pfb_top1m_probe_decision($probe_ok, $http_status, $body_hash, $persisted_hash) {
	if (!$probe_ok) {
		return 'failed';
	}
	return pfb_conditional_get_decision($http_status, $body_hash, $persisted_hash)
		? 'changed' : 'unchanged';
}

// Issue #1542: provider/URL/auth identity is stored beside the raw baseline.
// A changed identity clears the detector baseline and validators; the active
// derived whitelist remains available until a replacement download succeeds.
function pfb_top1m_source_identity($provider, $url, array $headers = array()) {
	$header_identity = array_map(static function ($header) {
		return hash('sha256', (string) $header);
	}, array_values($headers));
	$encoded = json_encode(array(
		'provider' => (string) $provider,
		'url'      => (string) $url,
		'headers'  => $header_identity,
	), JSON_UNESCAPED_SLASHES);
	return $encoded === FALSE ? '' : $encoded;
}

function pfb_top1m_invalidate_baseline($base) {
	$validator_base = "{$base}.orig";
	foreach (array(
		"{$base}.orig",
		"{$base}.xxhash128",
		"{$base}.md5",
		"{$base}.source",
		"{$validator_base}.etag",
		"{$validator_base}.lastmod",
	) as $path) {
		unlink_if_exists($path);
	}
}

// Settings that affect TOP1M filtering reuse the cached source and trigger
// a local rebuild; provider identity changes take the download detector path.
function pfb_top1m_settings_reprocess(array $before, array $after) {
	foreach (array('enable', 'count', 'tld') as $key) {
		if (($before[$key] ?? '') !== ($after[$key] ?? '')) {
			return TRUE;
		}
	}
	return FALSE;
}

function pfb_top1m_persist_baseline($base, $raw_path) {
	if (!is_file($raw_path)) {
		return FALSE;
	}
	$tmp = @tempnam(dirname($base), '.pfbtop1m_raw_');
	if ($tmp === FALSE || !@copy($raw_path, $tmp) || !@rename($tmp, "{$base}.orig")) {
		if ($tmp !== FALSE) {
			@unlink($tmp);
		}
		return FALSE;
	}
	return pfb_hash_write($base, "{$base}.orig");
}

function pfb_top1m_download_ledger_update($download_ok, $ledger_dir, $message = '') {
	pfb_dnsbl_download_ledger_update((bool) $download_ok, 'top1m', (string) $message, $ledger_dir);
}

// Extract the local-feed change decision from pfb_update_check() as a named, off-appliance-
// testable helper. Returns TRUE when the feed changed (re-ingest needed), FALSE when not;
// never concludes "unchanged" on a read failure — fail-safe. Algorithm (ADR-42 content-hash
// gate, mtime removed): either file absent -> changed (no baseline); else read the tagged
// .orig sidecar (sentinel -> live-hash the .orig as baseline; 'md5'/'xxh128' -> sidecar digest
// compared with the matching hash function); hash the source in the SAME algo; changed =
// source_hash !== baseline. The sidecar is refreshed at ingest inside pfb_download(), so the
// baseline is always the last-ingested .orig's hash — else it would go stale and falsely
// report "changed" every cron after a real re-ingest.
function pfb_local_feed_changed($source_path, $orig_path) {
	if (!file_exists($source_path) || !file_exists($orig_path)) {
		return TRUE;
	}

	$sidecar = pfb_hash_read($orig_path);

	if ($sidecar['algo'] === 'changed') {
		// No or corrupt sidecar — fall back to live-hashing the .orig as the baseline.
		$baseline = pfb_content_hash($orig_path, TRUE);
		if ($baseline === FALSE) {
			return TRUE;
		}
		$src_hash = pfb_content_hash($source_path, TRUE);
		if ($src_hash === FALSE) {
			return TRUE;
		}
		return ($src_hash !== $baseline);
	}

	if ($sidecar['algo'] === 'md5') {
		$src_hash = @md5_file($source_path);
		if ($src_hash === FALSE) {
			return TRUE;
		}
		return ($src_hash !== $sidecar['digest']);
	}

	// 'xxh128' — canonical path.
	$src_hash = pfb_content_hash($source_path, TRUE);
	if ($src_hash === FALSE) {
		return TRUE;
	}
	return ($src_hash !== $sidecar['digest']);
}

// ADR-38 Amendment 1: keep the long-running filterlog daemon's view of the
// log_syslog toggle fresh. The daemon loads $config once at start; a live toggle
// (GUI save / CLI) writes config.xml, but the daemon's in-memory $config is stale,
// so the syslog gate would not change until a restart (a bug: enabled+syslog-on
// must emit; enabled+syslog-off must not, with no restart). Reload $config from
// disk ONLY when config.xml actually changes (mtime-gated) — a cheap
// pfb_file_mtime() per block event, a full read only on an actual change.
// Called on the block-emit path (low volume), not per packet.
function pfb_filterlog_refresh_config() {
	// pfb_file_mtime() clears PHP's per-process stat cache before stat'ing,
	// so in this long-lived daemon a later config.xml write is always detected.
	$cur = pfb_file_mtime('/conf/config.xml');
	if ($cur === FALSE) {
		return;
	}
	// Defensive: if the baseline was never captured (non-daemon caller), record it.
	if (!isset($GLOBALS['pfb_daemon_config_mtime'])) {
		$GLOBALS['pfb_daemon_config_mtime'] = $cur;
		return;
	}
	if ($cur !== $GLOBALS['pfb_daemon_config_mtime']) {
		$GLOBALS['pfb_daemon_config_mtime'] = $cur;
		config_read_file(FALSE, TRUE);
	}
}

// Select the correct filterlog port field for an exploded filter.log CSV row ($d) by IP
// version ($d[8]) and flow direction. v4 carries ports at $d[20]/$d[21] (src/dst); v6 — fewer
// leading fields — carries them at $d[17]/$d[18]. Issue #713: the port-selection used to use
// v4 indices unconditionally, mis-attributing the local_hosts reverse-lookup key for v6 flows.
// PURE — no I/O, no globals, no side effects.
//
// @param array<int, string> $d           Exploded filter.log CSV row.
// @param bool                $is_inbound  TRUE for the 'in' branch (dst is local).
function pfb_filterlog_port(array $d, bool $is_inbound): string {
	$is_v6 = ((int) ($d[8] ?? 0)) === 6;
	if ($is_inbound) {
		return $is_v6 ? ($d[18] ?? '') : ($d[21] ?? '');
	}
	return $is_v6 ? ($d[17] ?? '') : ($d[20] ?? '');
}


// Map the ASN Reporting setting to the SQLite relative-time window used to expire
// cached ASN lookups (the pfb_daemon_filterlog() cache-eviction DELETE). Falls back
// to '-24 hours' for BOTH 'disabled' and any unrecognised token, so the window is
// ALWAYS defined -- including when reporting is 'disabled' but an ASN token is still
// configured (issue #713: the old call site only ran this mapping when reporting
// wasn't 'disabled', leaving $asn_cache undefined/NULL for the token-only case, so
// the DELETE bound NULL and the cache never expired).
//
// PURE -- no I/O, no globals, no side effects.
function pfb_asn_cache_window(string $asn_reporting): string {
	switch ($asn_reporting) {
		case '1hour':
			return '-1 hour';
		case '4hour':
			return '-4 hours';
		case '12hour':
			return '-12 hours';
		case '24hour':
			return '-24 hours';
		case 'week':
			return '-1 week';
		default:
			return '-24 hours';
	}
}


// Number of already-processed filter.log lines to skip on daemon (re)start.
// issue #713/#1261: $count is pfb_count_lines()'s ?int -- NULL (e.g. a TOCTOU
// race between the caller's file_exists() guard and the read) means "count
// unknown", so skip nothing: the daemon reprocesses the whole log rather than
// silently dropping lines it never actually parsed.
//
// PURE -- no I/O, no globals, no side effects.
function pfb_filterlog_skip_count(?int $count): int {
	return $count === NULL ? 0 : max($count - 1, 0);
}


// Firewall filter.log parser daemon
function pfb_daemon_filterlog() {
	global $pfb;

	// ADR-38 Amendment 1: baseline mtime for the live log_syslog refresh (see
	// pfb_filterlog_refresh_config). Captured at daemon start — when $config was
	// loaded — so any later config.xml change is detected on the block path.
	// pfb_file_mtime() clears the stat cache first (#536: without this the
	// baseline could read a PHP-cached mtime from before the daemon's config load,
	// defeating the change-detection on the very first reload check).
	$GLOBALS['pfb_daemon_config_mtime'] = pfb_file_mtime('/conf/config.xml');

	// ASN Reporting - cached setting. Unconditional (issue #713): the cache-eviction
	// use site below runs whenever reporting is enabled OR an ASN token is set, so
	// $asn_cache must always be defined -- see pfb_asn_cache_window().
	$asn_cache = pfb_asn_cache_window($pfb['asn_reporting']);

	// Application paths
	if (file_exists('/usr/local/bin/mmdblookup') && file_exists("{$pfb['geoipshare']}/GeoLite2-Country.mmdb")) {
		$pathgeoip = "/usr/local/bin/mmdblookup -f {$pfb['geoipshare']}/GeoLite2-Country.mmdb -i";
	} else {
		$pathgeoip = '';
	}

	// Proofpoint ET IQRisk header name reference
	$et_header	= config_get_path('installedpackages/pfblockerngreputation/config/0/et_header', '');
	$et_enabled = TRUE;
	if (empty($et_header)) {
		$et_enabled = FALSE;
	}

	$p_entry 	= '';
	$line_cnt	= 0;
	$rule_list	= $rule_list['other'] = array();

	// INIT-GAP (#1497): each of these is assigned per-line inside the
	// `if ($dup_entry == '+')` branch below, but read again OUTSIDE that
	// branch (unconditional write/syslog emit) -- init here so a duplicate
	// (or the very first) stdin line never reads an undefined variable.
	$details	= '';
	$iplog		= '';
	$log		= '';
	$dir		= '';
	$int		= '';
	$geoip		= '';
	$pfb_alias	= '';
	$pfb_query	= array();
	$resolved_host	= '';
	$asn		= '';

	if (file_exists('/usr/local/sbin/clog_pfb')) {

		// Parse full filter.log on first run, otherwise only parse new filter.log events
		if (!file_exists($pfb['ip_blocklog']) && !file_exists($pfb['ip_permitlog']) && !file_exists($pfb['ip_matchlog'])) {
			$filter_cnt = 0;
		} elseif (file_exists('/var/log/filter.log')) {
			// issue #713/#1261: pfb_count_lines() replaces the exec()+grep fork;
			// pfb_filterlog_skip_count() treats its NULL (read failure) as skip-nothing.
			$filter_cnt = pfb_filterlog_skip_count(pfb_count_lines('/var/log/filter.log'));
		} else {
			$filter_cnt = 0;
		}
		$skip_cnt = $filter_cnt;
	}
	else {
		$skip_cnt = $filter_cnt = 0;
	}

	/* filter.log reference: URL: https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html

		$line -> $f

		[ BSD format ]	[ syslog format ]
		[0][1][2]	[1]			= Date/timestamp
		[5]		[7]			= Event Details

		$f[5] -> $d

		[0]	= Rule number
		[1]	= Sub-rule number
		[2]	= Anchor
		[3]	= Tracker ID
		[4]	= Real Interface
		[5]	= Reason
		[6]	= Action
		[7]	= Direction
		[8]	= IP version
		[9]	= IP Specific data

		IPv4	IPv6
		[10]	[]	=
		[11]	[]	=
		[12]	[]	=
		[13]	[]	=
		[14]	[]	=
		[15]	[13]	= Protocol ID
		[16]	[12]	= Protocol
		[17]	[]	=
		[18]	[15]	= SRC IP
		[19]	[16]	= DST IP
		[20]	[17]	= SRC Port
		[21]	[18]	= DST Port
		[22]	[]	=
		[23]	[20]	= TCP Protocol Flags

	Final output reference:
		[0]	= Date/Timestamp
		[1]	= Rulenum
		[2]	= Real Interface
		[3]	= Friendly Interface name
		[4]	= Action
		[5]	= Version
		[6]	= Protocol ID
		[7]	= Protocol
		[8]	= SRC IP
		[9]	= DST IP
		[10]	= SRC Port
		[11]	= DST Port
		[12]	= Direction
		[13]	= GeoIP code
		[14]	= IP Alias Name
		[15]	= IP evaluated
		[16]	= Feed Name
		[17]	= gethostbyaddr resolved hostname
		[18]	= Client Hostname
		[19]	= Duplicate ID indicator		*/

	// Persistent negative cache: trackers absent from the ruleset are never reparsed again.
	$tracker_misses = array();

	if (($s_handle = @fopen('php://stdin', 'r')) !== FALSE) {
		logger(LOG_NOTICE, localize_text('filterlog daemon started'), LOG_PREFIX_PKG_PFBLOCKERNG);
		while (!feof($s_handle)) {
			$line = @fgets($s_handle);

				// ADR-38 Amendment 1: pfb_daemon_filterlog is the single writer of
				// unified.log and the host-side DNSBL syslog emitter. The same stdin
				// also carries the DNSBL feature logs (tail_pfb -F dnsbl.log dns_reply.log).
				// Discriminate by the leading CSV token BEFORE the pf-filter parsing /
				// htmlspecialchars below (those feature-log rows are written verbatim, so
				// their bytes must not be altered — unified.log fidelity).
				if (is_string($line)) {
					if (strncmp($line, 'DNSBL-python,', 13) === 0) {
						$dnsline = rtrim($line, "\r\n");
						if ($dnsline !== '') {
							$df = str_getcsv($dnsline, ',', '"', '');
							@file_put_contents("{$pfb['unilog']}", "{$dnsline}\n", FILE_APPEND | LOCK_EX);
							// Emit syslog only for a well-formed logical row; raw unified.log
							// preservation above covers malformed rows without corruption.
							if (count($df) === 11) {
								// Every DNSBL block line syslogs uniformly (incl. the PHP-path
								// block the old python-only emitter missed). pfb_syslog_event
								// no-ops when the toggle is off. Refresh the daemon's config
								// first so a LIVE log_syslog toggle takes effect (no restart).
								pfb_filterlog_refresh_config();
								if (PfbConfig::read('gen/log_syslog') === PfbToggle::On) {
									pfb_syslog_event(pfb_syslog_format_dnsbl(array(
										'q_name' => $df[2], 'q_ip' => $df[3], 'q_type' => $df[10],
										'group' => $df[6], 'feed' => $df[8], 'b_type' => $df[5],
										'b_eval' => $df[7],
									)));
								}
							}
						}
						continue;
					}
					if (strncmp($line, 'DNS-reply,', 10) === 0) {
						$rpline = rtrim($line, "\r\n");
						if ($rpline !== '') {
							$rf = explode(',', $rpline);
							// DNS-reply -> unified.log ONLY (blocks-only syslog: never here).
							if (count($rf) === 10) {
								$uni = pfb_unified_format_dnsreply(array(
									'l_type' => $rf[0], 'datetime' => $rf[1], 'm_type' => $rf[2],
									'o_type' => $rf[3], 'q_type' => $rf[4], 'ttl' => $rf[5],
									'q_name' => $rf[6], 'q_ip' => $rf[7], 'r_addr' => $rf[8],
									'iso_code' => $rf[9],
								));
								@file_put_contents("{$pfb['unilog']}", "{$uni}\n", FILE_APPEND | LOCK_EX);
							} else {
								@file_put_contents("{$pfb['unilog']}", "{$rpline}\n", FILE_APPEND | LOCK_EX);
							}
						}
						continue;
					}
				}

			// Only parse new filter events
			if ($filter_cnt > 0 && $skip_cnt > 0) {
				$skip_cnt--;
				continue;
			}

			$log_type = 'BSD';
			$f_pos = 5;
			if (str_starts_with($line, '<')) {
				$log_type = 'syslog';
				$f_pos = 7;
			}

			// Remove any '^M' characters
			$line = htmlspecialchars(rtrim($line, "\x00..\x1F"));

			$f = explode(' ', $line);

			// Remove double space for single date entry nuance
			if ($log_type == 'BSD' && empty($f[1])) {
				array_splice($f, 1, 1);
			}
			// issue #1768: a short/malformed filterlog line has no field at $f_pos --
			// guard so explode() doesn't get NULL.
			$d = explode(',', $f[$f_pos] ?? '');

			// Resolve the Tracker ID: reparse at most once per unknown tracker; persistent
			// negative cache prevents repeated reparses for anchor/trackerless rules.
			if (!empty($d[3])) {
				// On reparse: refresh the daemon-local IP/host collections from the box.
				$pfb_reparse_cb = function () use (&$pfb_local, &$pfb_localsub, &$local_hosts) {
					$data		= pfb_collect_localip();
					$pfb_local	= $data[0] ?: array();
					$pfb_localsub	= $data[1] ?: array();
					$local_hosts	= pfb_collect_localhosts();
				};

				// Resolve the Tracker ID — returns TRUE when a matching pfB rule is found.
				if (!pfb_resolve_tracker($rule_list, $tracker_misses, $d[3], $d[6], 'pfb_filterrules', $pfb_reparse_cb)) {
					continue;
				}

				// Duplicate entry comparison: "Tracker ID/Action/SRC IP/DST IP/DST Port"
				$dup_entry = '+';
				if ($d[8] == 4 && "{$d[3]}{$d[6]}{$d[18]}{$d[19]}{$d[21]}" == $p_entry) {
					$dup_entry = '-';
				} elseif ($d[8] == 6 && "{$d[3]}{$d[6]}{$d[15]}{$d[16]}{$d[18]}" == $p_entry) {
					$dup_entry = '-';
				}

				if ($dup_entry == '+') {

					$int		= convert_real_interface_to_friendly_descr($d[4]);
					$pfb_alias	= pfb_filter($rule_list[$d[3]]['name'], PFB_FILTER_WORD, 'pfb_daemon_filterlog', 'Unknown');

					// Action setting variables
					if ($d[6] == 'block') {
						$folder = "{$pfb['denydir']}/* {$pfb['nativedir']}/*";
						$iplog	= "{$pfb['ip_blocklog']}";
						$l_type = 'Block';
					}
					elseif ($d[6] == 'pass') {
						$folder = "{$pfb['permitdir']}/* {$pfb['nativedir']}/*";
						$iplog	= "{$pfb['ip_permitlog']}";
						$l_type = 'Permit';
					}
					elseif ($d[6] == 'unkn(%u)') {
						$d[6]	= 'match';
						$folder = pfb_ip_match_folders() . " {$pfb['nativedir']}/*";
						$iplog	= "{$pfb['ip_matchlog']}";
						$l_type = 'Match';
					}
					// INIT-GAP (#1497): defined defaults for an out-of-format action
					// (unreachable per the kernel filterlog format: $d[6] is always
					// block/pass/unkn(%u)).
					else {
						$folder = '';
						$iplog	= '';
						$l_type = 'Unknown';
					}

					if ($d[8] == 4) {
						$srcip		= $d[18] ?: 'Unknown';
						$dstip		= $d[19] ?: 'Unknown';
						$tcp_flags	= $d[16] == 'tcp' ? $d[23] : '';	// Keep protocol flags for TCP only
					} else {
						$srcip		= $d[15] ?: 'Unknown';
						$dstip		= $d[16] ?: 'Unknown';
						$tcp_flags	= $d[12] == 'tcp' ? $d[20] : '';
					}

					// Determine if DST IP or SRC IP is the external host
					// issue #713: port field is selected by IP version -- see pfb_filterlog_port().
					if (isset($pfb_local[$dstip]) || pfb_local_ip($dstip, $pfb_localsub)) {
						$dir	= 'in';
						$host	= $srcip;
						$client	= $dstip;
						$port	= pfb_filterlog_port($d, TRUE);
					} else {
						$dir	= 'out';
						$host	= $dstip;
						$client	= $srcip;
						$port	= pfb_filterlog_port($d, FALSE);
					}

					if (!is_ipaddr($host)) {
						continue;
					}
					if (!is_ipaddr($client)) {
						continue;
					}
					if (!is_port($port)) {
						$port = '';
					}

					switch (TRUE) {
						case isset($local_hosts["{$client}:{$port}"]) && !empty($local_hosts["{$client}:{$port}"]):
							$hostname = $local_hosts["{$client}:{$port}"];
							break;
						case isset($local_hosts[$client]) && !empty($local_hosts[$client]):
							$hostname = $local_hosts[$client];
							break;
						default:
							$hostname = 'Unknown';
					}

					$ip_cache = FALSE;
					$db_handle = pfb_open_sqlite(7, 'Query ip cache');
					if ($db_handle) {
						$db_update = "SELECT * FROM ipcache WHERE host = :host;";
						$stmt = $db_handle->prepare($db_update);
						if ($stmt) {
							$stmt->bindValue(':host', $host, SQLITE3_TEXT);
							$result = $stmt->execute();
							if ($result) {
								$ip_cache = $result->fetchArray(SQLITE3_ASSOC);
							}
						}
					}
					pfb_close_sqlite($db_handle);

					if (!$ip_cache) {

						// Find the header which alerted this host
						$geoip_folder = FALSE;
						$geoip_validate = substr($pfb_alias, 0, -3);
						if (isset($pfb['continent_list'][$geoip_validate])) {
							$geoip_folder = TRUE;
						}
						$geoip_lock = $geoip_folder ? pfb_geoip_generation_read_lock() : FALSE;
						$geoip_deferred = $geoip_folder && $geoip_lock === FALSE;
						$pfb_query = find_reported_header($host, $folder, $geoip_folder);

						// Report specific ET IQRisk details
						if ($et_enabled && strpos($pfb_query[0], "{$et_header}") !== FALSE) {
							$ET_orig = $pfb_query;
							$pfb_query = find_reported_header($host, "{$pfb['etdir']}/*", FALSE);

							// ET IQRisk category is unknown.
							if ($pfb_query[1] == 'Unknown') {
								$pfb_query = $ET_orig;
							}
							else {
								// Prepend ET Header name
								$pfb_query[0] = "{$et_header}:{$pfb_query[0]}";
							}
						}

						// Determine GeoIP isocode of host
						if (!empty($pathgeoip)) {
							$geoip = exec("{$pathgeoip} " . escapeshellarg($host) . " country iso_code | grep -v '^\$' | cut -d '\"' -f2 2>&1");
							$geoip = pfb_filter($geoip, PFB_FILTER_ALPHA, 'pfb_daemon_filterlog', 'Unk');
						}
						else {
							$geoip = 'Unk';
						}

						if ($pfb['rdns']) {
							$resolved_host = gethostbyaddr($host) ?: 'Unknown';
							if ($host == $resolved_host || $resolved_host == 'Unknown') {
								$resolved_host = 'Unknown';
							}
						} else {
							$resolved_host = 'Unknown';
						}

						// Save entry to IP cache only when attribution was not deferred by a GeoIP swap.
						if (!$geoip_deferred) {
							$db_update = "INSERT into ipcache ( host, q0, q1, geoip, resolved_host ) VALUES ( :host, :q0, :q1, :geoip, :resolved_host )";
							$db_handle = pfb_open_sqlite(7, 'Add to IP cache');
							if ($db_handle) {
								$pfb_host	= pfb_filter($host, PFB_FILTER_HTML, 'pfb_daemon_filterlog');
								$pfb_query[0]	= pfb_filter($pfb_query[0], PFB_FILTER_HTML, 'pfb_daemon_filterlog');
								$pfb_query[1]	= pfb_filter($pfb_query[1], PFB_FILTER_HTML, 'pfb_daemon_filterlog');
								$geoip		= pfb_filter($geoip, PFB_FILTER_HTML, 'pfb_daemon_filterlog');
								$resolved_host	= pfb_filter($resolved_host, PFB_FILTER_HOSTNAME, 'pfb_daemon_filterlog', 'Unknown');

								$stmt = $db_handle->prepare($db_update);
								if ($stmt) {
									$stmt->bindValue(':host', $host, SQLITE3_TEXT);
									$stmt->bindValue(':q0', $pfb_query[0], SQLITE3_TEXT);
									$stmt->bindValue(':q1', $pfb_query[1], SQLITE3_TEXT);
									$stmt->bindValue(':geoip', $geoip, SQLITE3_TEXT);
									$stmt->bindValue(':resolved_host', $resolved_host, SQLITE3_TEXT);
									$stmt->execute();
								}
							}
							pfb_close_sqlite($db_handle);
						}
						pfb_geoip_generation_read_unlock($geoip_lock);
					}

					// Use cached entries
					else {
						$host		= htmlspecialchars($ip_cache['host'])		?: 'Unknown';
						$pfb_query	= array();
						$pfb_query[0]	= htmlspecialchars($ip_cache['q0'])		?: 'Unknown';
						$pfb_query[1]	= htmlspecialchars($ip_cache['q1'])		?: 'Unknown';
						$geoip		= htmlspecialchars($ip_cache['geoip'])		?: 'Unknown';
						$resolved_host	= htmlspecialchars($ip_cache['resolved_host'])	?: 'Unknown';
					}

					// Modify host for ASN query
					if ($d[8] == 4) {
						// For ASN, query for IP Network address (x.x.x.0)
						$ix = ip_explode($host);
						$ip = "{$ix['6']}0";
					} else {
						// For ASN, query for IP Network address with /48 subnet
						$ip = gen_subnetv6($host, 48);
					}
					$ip = pfb_filter($ip, PFB_FILTER_IP, 'pfb_daemon_filterlog');

					// Determine ASN number of host
					$asn = 'null';
					if (($pfb['asn_reporting'] != 'disabled' || !empty($pfb['asn_token'])) && !empty($ip)) {

						$is_asn_cache = FALSE;
						$db_handle = pfb_open_sqlite(5, 'Query ASN cache');
						if ($db_handle) {

							// Clear cached entries older than defined cache setting
							$db_update = "DELETE FROM asncache WHERE timestamp <= datetime('now', 'localtime', :asn_cache)";
							$stmt = $db_handle->prepare($db_update);
							if ($stmt) {
								$stmt->bindValue(':asn_cache', $asn_cache, SQLITE3_TEXT);
								$stmt->execute();
							}

							// Query for cached Host IP
							$db_update = "SELECT * FROM asncache WHERE host = :host;";
							$stmt = $db_handle->prepare($db_update);
							if ($stmt) {
								$stmt->bindValue(':host', $ip, SQLITE3_TEXT);
								$result = $stmt->execute();
								if ($result) {
									$is_asn_cache = $result->fetchArray(SQLITE3_ASSOC);
								}
							}
						}
						pfb_close_sqlite($db_handle);

						// If Host IP is not in ASN cache, collect ASN from ASN database
						if (!$is_asn_cache) {
							$asn = exec("{$pfb['script']} iptoasn " . escapeshellarg($ip) . " 2>&1");

							// Convert any IDN to ASCII
							$asn_final = '';
							if (!empty($asn) && !ctype_print($asn)) {
								if (strpos($asn, '|') !== FALSE) {
									$asn_ex = explode('|', $asn);
									if (is_array($asn_ex) && !empty($asn_ex)) {
										foreach ($asn_ex as $asn_element) {
											if (strpos($asn_element, ':') !== FALSE) {
												$asn_element_ex = explode(':', $asn_element);
												if (is_array($asn_element_ex) && (is_string($asn_element_ex[1]) && (strlen($asn_element_ex[1]) > 0))) {
													if (!ctype_print($asn_element_ex[1])) {
														$asn_element_ex[1] = mb_convert_encoding($asn_element_ex[1], 'UTF-8',
															mb_detect_encoding($asn_element_ex[1], 'UTF-8, ASCII, ISO-8859-1'));
														$asn_element_ex[1] = idn_to_ascii($asn_element_ex[1]);
													}
													$asn_final .= "{$asn_element_ex[0]}:{$asn_element_ex[1]}|";
												}
											}
										}
									}
								}
							}
							else {
								$asn_final = $asn;
							}
							$asn = pfb_filter($asn_final, PFB_FILTER_HTML, 'pfb_daemon_filterlog - asn');

							if (empty($asn) || strpos($asn, 'ASN:') === FALSE) {
								$asn = 'Unknown';
							}

							// Save entry to ASN cache
							else {
								$db_update = "INSERT into asncache ( asn, host, timestamp ) VALUES ( :asn, :host, datetime('now', 'localtime'))";
								$db_handle = pfb_open_sqlite(5, 'Add to ASN cache');
								if ($db_handle) {
									$stmt	= $db_handle->prepare($db_update);
									if ($stmt) {
										$asn = "|{$asn}";
										$stmt->bindValue(':asn', $asn, SQLITE3_TEXT);
										$stmt->bindValue(':host', $ip, SQLITE3_TEXT);
										$stmt->execute();
									}
								}
								pfb_close_sqlite($db_handle);
							}
						}

						// Use cached ASN Entry
						else {
							$asn = htmlspecialchars($is_asn_cache['asn'])	?: 'Unknown';
						}
					}

					// Log: "Date timestamp/Tracker ID/Interface/Interface Name/Action/IP Version"
					$ts_formatted = pfb_filterlog_timestamp($f, $log_type, time());
					$log = "{$ts_formatted},{$d[3]},{$d[4]},{$int},{$d[6]},{$d[8]},";

					// Details:	"Direction/GeoIP/Aliasname/IP evaluated/Feed Name/Resolved Hostname/Client Hostname/ASN,ASN Domain,ASN Name/Duplicate status"
					// issue #1369: the single pipe-blob ASN field is replaced by 3 plain
					// CSV columns (asn, asn_domain, asn_name), CSV-escaped by
					// pfb_asn_csv_fields() (native fputcsv(), explicit empty escape arg,
					// CR/LF normalized to spaces first) -- see ADR-38 Amendment 3. The raw
					// $asn blob itself is untouched and still feeds the syslog asn= value
					// below + the asncache.asn row.
					// issue #1784: $resolved_host/$hostname carry admin-authored
					// descr/hostname text (NAT rules, host aliases, static maps) --
					// CSV-quote them at the join (pfb_csv_field, the #1369 contract
					// every reader parses under) so a comma never shifts the row.
					$details	= "{$dir},{$geoip},{$pfb_alias},{$pfb_query[1]},{$pfb_query[0]}," . pfb_csv_field($resolved_host) . ',' . pfb_csv_field($hostname) . ',' . pfb_asn_csv_fields($asn);

					// Reverse Match text
					if ($d[6] == 'match') {
						$d[6] = 'unkn(%u)';
					}

					if ($d[8] == 4) {
						// Previous:	"Tracker ID/Action/SRC IP/DST IP/DST Port"
						$p_entry	= "{$d[3]}{$d[6]}{$d[18]}{$d[19]}{$d[21]}";
						$d[16]		= str_replace('TCP', 'TCP-', strtoupper($d[16]), $d[16]) . $tcp_flags;

						// Log:		"Protocol ID/Protocol/SRC IP/DST IP/SRC Port/DST Port"
						$log		.= "{$d[15]},{$d[16]},{$d[18]},{$d[19]},{$d[20]},{$d[21]}";
					}
					else {
						$p_entry	= "{$d[3]}{$d[6]}{$d[15]}{$d[16]}{$d[18]}";
						$d[12]		= str_replace('TCP', 'TCP-', strtoupper($d[12]), $d[12]) . $tcp_flags;
						$log		.= "{$d[13]},{$d[12]},{$d[15]},{$d[16]},{$d[17]},{$d[18]}";
					}
				}
				@file_put_contents("{$iplog}", "{$log},{$details},{$dup_entry}\n", FILE_APPEND | LOCK_EX);

				// ADR-38: emit one syslog record per CSV line when the toggle is on.
				// Refresh the daemon's config first so a LIVE log_syslog toggle takes
				// effect without a restart; pfb_syslog_event() then reads it fresh too.
				// Build the field array only when log_syslog is enabled; skip otherwise.
				// Emitted EXACTLY ONCE here — not again for the unified-log copy below.
				pfb_filterlog_refresh_config();
				if (PfbConfig::read('gen/log_syslog') === PfbToggle::On) {
					// Map $d[6] back to the canonical act value.
					// At this point $d[6] is 'block'|'pass'|'unkn(%u)' (match was reversed).
					$pfb_syslog_act = ($d[6] === 'unkn(%u)') ? 'match' : $d[6];
					if ($d[8] == 4) {
						$pfb_syslog_fields = [
							'act'   => $pfb_syslog_act,
							'dir'   => $dir,
							'if'    => $int,
							'proto' => $d[16],
							'src'   => $d[18],
							'dst'   => $d[19],
							'sport' => $d[20],
							'dport' => $d[21],
							'ipver' => '4',
							'geoip' => $geoip,
							'alias' => $pfb_alias,
							'feed'  => $pfb_query[0],
							'host'  => $resolved_host,
							'asn'   => $asn,
						];
					} else {
						$pfb_syslog_fields = [
							'act'   => $pfb_syslog_act,
							'dir'   => $dir,
							'if'    => $int,
							'proto' => $d[12],
							'src'   => $d[15],
							'dst'   => $d[16],
							'sport' => $d[17],
							'dport' => $d[18],
							'ipver' => '6',
							'geoip' => $geoip,
							'alias' => $pfb_alias,
							'feed'  => $pfb_query[0],
							'host'  => $resolved_host,
							'asn'   => $asn,
						];
					}
					pfb_syslog_event(pfb_syslog_format_ip($pfb_syslog_fields));
				}

				// Write to Unified Log (schema owned by pfb_unified_format_ip — ADR-38 Amendment 1)
				if ($dup_entry == '+') {
					@file_put_contents("{$pfb['unilog']}", pfb_unified_format_ip(array('l_type' => $l_type, 'log' => $log, 'details' => $details, 'dup' => $dup_entry)) . "\n", FILE_APPEND | LOCK_EX);
				}
			}
		}
	}
	else {
		logger(LOG_ERR, localize_text('filterlog - Failed to read STDIN'), LOG_PREFIX_PKG_PFBLOCKERNG);
	}
	if ($s_handle) {
		@fclose($s_handle);
	}
}


// Function to parse grep output and return Aliasname and IP fields
function pfb_parse_query($line) {
	$rx = explode('.txt:', $line);
	$rx[0] = ltrim(strrchr($rx[0], '/'), '/');

	// issue #843: a non-".txt:"-shaped line can reach this parser -- e.g. a grep stderr
	// message captured via 2>&1 ("grep -s" only silences "no such file") or a "Binary
	// file X matches" notice -- and explode() then yields a single element. Return a
	// stable 2-element [feed, value] shape so no consumer ever reads past the array.
	return array($rx[0], $rx[1] ?? '');
}


// Page-scope memoisation helper (issue #809 -- Alerts page render-time performance).
// A render request is one PHP process, so a $store passed in as a function-static
// array lives for exactly one page load: the first call for a given $key runs
// $resolver() and keeps the result; every later call with the same $key returns it
// with zero extra work. array_key_exists() (never isset()) so a resolver returning
// NULL/FALSE/''/0 is still cached -- those are valid resolved values, not "not yet
// resolved".
function pfb_render_memo(array &$store, string $key, callable $resolver) {
	if (!array_key_exists($key, $store)) {
		$store[$key] = $resolver();
	}
	return $store[$key];
}


// Predicate for the Unified-log render loop (pfblockerng_alerts.php): TRUE once no converter
// (convert_dnsbl_log/convert_dns_reply_log/convert_ip_log) can render another row, so the
// caller can break out of fgetcsv() instead of parsing the rest of the log for nothing (issue
// #809). Non-filter mode: all three share one counter/limit, so done = `$unified_count >=
// $pfbentries`. Filter mode: each converter gates on its OWN counter/limit and sets its OWN
// flag; done = `$ipfilterlimit && $dnsblfilterlimit && $dnsfilterlimit` (mirrors the <tfoot>
// summary check) — an unlimited (0) knob never sets its flag, so the loop runs to EOF as
// before.
function pfb_alerts_unified_scan_done($filterlogentries, $unified_count, $pfbentries, $ipfilterlimit, $dnsblfilterlimit, $dnsfilterlimit): bool {
	if ($filterlogentries) {
		return $ipfilterlimit && $dnsblfilterlimit && $dnsfilterlimit;
	}
	return $unified_count >= $pfbentries;
}


// Pass-1 buffer-append rule for the IP two-pass render's two COMPRESSIBLE line kinds
// (pfblockerng_alerts.php). Extracted verbatim so the compression arithmetic is unit-pinned by
// AlertsBufferReplayTest instead of living only as inline page code. The third buffer shape —
// an ACCEPTED row, array($fields, TRUE) — is not compressible and stays appended inline.
// $kind is 'dup' (a duplicate-marker '-' line) or 'reject': 'dup' extends a trailing int run or
// a trailing gap marker's 'dup' counter, or opens a fresh int run. 'reject' zeroes a trailing
// gap marker's 'dup' counter, REPLACES a trailing pure int run with a fresh zero-dup gap, or
// opens a fresh zero-dup gap — a reject's fields are never kept since convert_ip_log()'s
// filter-reject path has a CONSTANT effect, so only the post-last-reject dup count survives.
// See pfb_alerts_ip_replay_step() for the Pass-2 counterpart.
function pfb_alerts_ip_buffer_push(array &$buf, string $kind): void {
	$last = count($buf) - 1;
	$last_is_int = $last >= 0 && is_int($buf[$last]);
	$last_is_gap = $last >= 0 && is_array($buf[$last]) && isset($buf[$last]['rej']);

	if ($kind === 'dup') {
		if ($last_is_int) {
			$buf[$last]++;
		} elseif ($last_is_gap) {
			$buf[$last]['dup']++;
		} else {
			$buf[] = 1;
		}
		return;
	}

	// 'reject'
	if ($last_is_gap) {
		$buf[$last]['dup'] = 0;
	} elseif ($last_is_int) {
		$buf[$last] = array('rej' => TRUE, 'dup' => 0);
	} else {
		$buf[] = array('rej' => TRUE, 'dup' => 0);
	}
}


// Pass-2 replay-decode counterpart to pfb_alerts_ip_buffer_push(): tells the IP render loop
// what a buffered entry MEANS, so it never has to inspect the buffer's storage shape itself.
//   int N -> array('dup_add' => N): a pure dup run, one accumulation into $dup[$rtype],
//     output-identical to N individual increments.
//   array('rej'=>...,'dup'=>N) -> array('gap' => N): a mixed dup/reject run — the caller must
//     SET $dup[$rtype] = N (never +=) and clear $p_query_port, exactly as a reject's
//     convert_ip_log() return does; N is the dup count AFTER the last reject in the run.
//   array($fields, TRUE) -> array('render' => $fields): an accepted row, replayed through the
//     unchanged convert_ip_log() call.
function pfb_alerts_ip_replay_step($entry): array {
	if (is_int($entry)) {
		return array('dup_add' => $entry);
	}
	if (isset($entry['rej'])) {
		return array('gap' => $entry['dup']);
	}

	list($fields, ) = $entry;
	return array('render' => $fields);
}


// DNSBL Lighttpd 'dnsbl_error.log' conditional log parser
function pfb_daemon_dnsbl() {
	global $pfb;

	if (($h_handle = @fopen('php://stdin', 'r')) !== FALSE) {
		logger(LOG_NOTICE, localize_text('DNSBL parser daemon started'), LOG_PREFIX_PKG_PFBLOCKERNG);

		$chk_ver	= FALSE;
		$lighty_47	= FALSE;
		$lighty_58	= FALSE;
		$lighty_59	= FALSE;
		$checkpos	= 3; 	// Pre Lighttpd v1.4.47
		// INIT-GAP (#1497): assigned per-line further down, read again (via
		// pfb_filter()) on a LATER line under a checkpos-gated branch.
		$domain		= '';
		$src_ip		= '';

		while (!feof($h_handle)) {
			$pfb_buffer = @fgets($h_handle);

			if (!$chk_ver) {

				// Lighttpd v1.4.58+ conditional error log with 'ssl.verifyclient.activate' to collect the domain name
				if (!$lighty_47 && strpos($pfb_buffer, 'lighttpd/1.4.58') !== FALSE) {
					$chk_ver	= TRUE;
					$lighty_58	= TRUE;
					continue;
				}

				// Lighttpd v1.4.59+ syntax changes to IP line
                                elseif (!$lighty_47 &&
				    (strpos($pfb_buffer, 'lighttpd/1.4.59') !== FALSE ||
				    strpos($pfb_buffer, 'lighttpd/1.4.6') !== FALSE ||
				    strpos($pfb_buffer, 'lighttpd/1.4.7') !== FALSE ||
				    strpos($pfb_buffer, 'lighttpd/1.5') !== FALSE)) {
					$chk_ver	= TRUE;
					$lighty_59	= TRUE;
					continue;
				}

				// Lighttpd v1.4.47 uses mod_openssl with a different conditional log formatting
				elseif (strpos($pfb_buffer, 'global/HTTPscheme') !== FALSE) {
					$lighty_47	= TRUE;
					$checkpos	= 1;
					continue;
				}
			}

			if ($lighty_58 || $lighty_59) {

				// Verify HTTP["remoteip"]
				if (empty($src_ip)) {
					if ($lighty_58) {
						if (strpos($pfb_buffer, '["re') !== FALSE) {
							$src_ip = strstr($pfb_buffer, ') compare', TRUE);
							$src_ip = ltrim(strstr($src_ip, '] (', FALSE), '] (');
							$src_ip = (filter_var($src_ip, FILTER_VALIDATE_IP) !== FALSE) ? $src_ip : '';
						}
					} else {
						if (strpos($pfb_buffer, '["re') !== FALSE && strpos($pfb_buffer, ' compare to ') !== FALSE) {
							$src_ip = strstr($pfb_buffer, ' compare to ', FALSE);
							$src_ip = trim(ltrim($src_ip, ' compare to '));
							$src_ip = (filter_var($src_ip, FILTER_VALIDATE_IP) !== FALSE) ? $src_ip : '';
						}
					}
					continue;
				}

				if (!empty($src_ip) && strpos($pfb_buffer, "SSL: ") === FALSE) {
					continue;
				}
				if (empty($domain) && strpos($pfb_buffer, "SSL: can't verify client without ssl.") !== FALSE) {
					$domain = str_replace(' server name ', '', strstr(trim($pfb_buffer), ' server name ', FALSE));
				}

				if (!empty($domain) && !empty($src_ip)) {

					$domain = pfb_filter($domain, PFB_FILTER_DOMAIN, 'pfb_daemon_dnsbl');
					$src_ip = pfb_filter($src_ip, PFB_FILTER_IP, 'pfb_daemon_dnsbl');
					if (!empty($domain) && !empty($src_ip)) {

						// URL/Referer/URI/Agent String not available for HTTPS events
						$req_agent	= 'Unknown';
						$type		= 'DNSBL-HTTPS';

						pfb_log_event($type, $domain, $src_ip, $req_agent);
						$domain = $src_ip = '';
					}
				}
			}
			else {
				// Parse only HTTP["xxx"] log lines
				if (strpos($pfb_buffer, 'HTTP[') === FALSE) {
					continue;
				}

				// Verify only HTTPS lines
				if (strpos($pfb_buffer, '( https') !== FALSE) {
					if ($lighty_47) {
						continue;
					}
					$checkpos = 0;
				}

				// Verify HTTP["remoteip"]
				if ($checkpos == 1 && strpos($pfb_buffer, '["re') !== FALSE) {
					$src_ip = strstr($pfb_buffer, ' ) compare', TRUE);
					$src_ip = ltrim(strstr($src_ip, '] ( ', FALSE), '] ( ');
					$src_ip = (filter_var($src_ip, FILTER_VALIDATE_IP) !== FALSE) ? $src_ip : '';
				}

				// Verify HTTP["host"]
				elseif ($checkpos == 2 && strpos($pfb_buffer, '["ho') !== FALSE) {
					$lighty_47	= FALSE;
					$domain		= strstr($pfb_buffer, ' ) compare', TRUE);
					$domain		= ltrim(strstr($domain, '] ( ', FALSE), '] ( ');

					// URL/Referer/URI/Agent String not available for HTTPS events
					$req_agent	= 'Unknown';
					$type		= 'DNSBL-HTTPS';

					// Log event and Increment SQLite DNSBL Group counter
					if (!empty($domain) && !empty($src_ip)) {

						$domain = pfb_filter($domain, PFB_FILTER_DOMAIN, 'pfb_daemon_dnsbl');
						$src_ip = pfb_filter($src_ip, PFB_FILTER_IP, 'pfb_daemon_dnsbl');
						if (!empty($domain) && !empty($src_ip)) {

							// URL/Referer/URI/Agent String not available for HTTPS events
							$req_agent	= 'Unknown';
							$type		= 'DNSBL-HTTPS';

						 	pfb_log_event($type, $domain, $src_ip, $req_agent);
							$domain = $src_ip = '';
						}
					}
				}
				$checkpos++;
			}
		}
	}
	else {
		logger(LOG_ERR, localize_text('DNSBL conditional log parser - Failed to open handle'), LOG_PREFIX_PKG_PFBLOCKERNG);
	}
	@fclose($h_handle);
}


// DNSBL Lighttpd 'index.php' event parser
function pfb_daemon_dnsbl_index() {
	global $pfb;

	// Replace any [',' or '|' ] in HTTP_REFERER, REQUEST_URI or HTTP_USER_AGENT fields
	// Replace placeholder characters [ '!' and '*' ] to [ ',' and '|' ]
	$p1 = array( ',', '!', '|', ' * ' );
	$p2 = array( '', ',', '--', '|' );

	if (($i_handle = @fopen('php://stdin', 'r')) !== FALSE) {
		while (!feof($i_handle)) {
			$pfb_buffer = @fgets($i_handle);
			$pfb_buffer = str_replace($p1, $p2, $pfb_buffer);

			if (str_starts_with($pfb_buffer, 'INDEX,') && substr_count($pfb_buffer, ',') == 4) {
				$csvline = str_getcsv($pfb_buffer, ',', '"', '"');

				// Determine blocked domain type (Full, 1x1 or JS)
				if (isset($csvline[1]) && !empty($csvline[1])) {
					$request = strstr($csvline[1], '/', FALSE);
					$request = strstr($request, ' ', TRUE);

					if (strlen($request) < 2) {
						$type = 'DNSBL-Full';
					}
					else {
						if (pathinfo($request, PATHINFO_EXTENSION) == 'js') {
							$type = 'DNSBL-JS';
						} else {
							$type = 'DNSBL-1x1';
						}
					}
				}
				else {
					$type = 'DNSBL-Unknown';
				}

				$csvline[2] = pfb_filter($csvline[2], PFB_FILTER_DOMAIN, 'pfb_daemon_dnsbl_index');
				$csvline[3] = pfb_filter($csvline[3], PFB_FILTER_IP, 'pfb_daemon_dnsbl_index');
				$csvline[4] = pfb_filter($csvline[4], PFB_FILTER_HTML, 'pfb_daemon_dnsbl_index');
			}
			else {
				continue;
			}

			// Log event and increment SQLite DNSBL Group counter
			if (!empty($csvline[2]) && !empty($csvline[3])) {
				pfb_log_event($type, $csvline[2], $csvline[3], $csvline[4]);
			}
		}
	}
	else {
		logger(LOG_ERR, localize_text('DNSBL index event parser - Failed to open handle'), LOG_PREFIX_PKG_PFBLOCKERNG);
	}
	@fclose($i_handle);
}


// Map a numeric SQLite3 handle index (1-7, see pfb_open_sqlite() callers) to its
// table name + CREATE statement. Extracted as a pure function so the index->table
// mapping is unit-testable without a live SQLite3 file (issue #713 bug 10: table 6
// used to map to db_table 'stats' while its CREATE TABLE built 'lastclear' -- the
// name every other query in this file actually uses -- so DB-corruption recovery
// dropped the wrong/nonexistent table and aborted before 'lastclear' was rebuilt).
// Unknown $table returns empty strings (behaviour-preserving default; callers only
// ever pass 1-7).
function pfb_sqlite_table_spec(int $table): array {
	switch ($table) {
		case 1:
			return [ 'db_table' => 'dnsbl', 'db_create' => "CREATE TABLE IF NOT EXISTS dnsbl ( groupname TEXT, timestamp TEXT, entries INTEGER, counter INTEGER );" ];
		case 2:
			return [ 'db_table' => 'lastevent', 'db_create' => "CREATE TABLE IF NOT EXISTS lastevent ( row INTEGER, groupname TEXT, entry TEXT, details TEXT );" ];
		case 3:
			return [ 'db_table' => 'resolver', 'db_create' => "CREATE TABLE IF NOT EXISTS resolver ( row INTEGER, totalqueries INTEGER, queries INTEGER );" ];
		case 4:
			// Issue #1349: reserved retired reports-cache slot; keep IDs 5-7 stable.
			return [ 'db_table' => '', 'db_create' => '' ];
		case 5:
			return [ 'db_table' => 'asncache', 'db_create' => "CREATE TABLE IF NOT EXISTS asncache ( asn TEXT, host TEXT, timestamp TEXT );" ];
		case 6:
			return [ 'db_table' => 'lastclear', 'db_create' => "CREATE TABLE IF NOT EXISTS lastclear ( row INTEGER, lastipclear TEXT, lastdnsblclear TEXT );" ];
		case 7:
			return [ 'db_table' => 'ipcache', 'db_create' => "CREATE TABLE IF NOT EXISTS ipcache ( host TEXT, q0 TEXT, q1 TEXT, geoip TEXT, resolved_host TEXT );" ];
		default:
			return [ 'db_table' => '', 'db_create' => '' ];
	}
}


// Function to create/open SQLite3 database(s)
function pfb_open_sqlite($table, $message) {
	global $pfb;

	// $table is always 1-7 from callers, but the if/elseif chain below has no else;
	// default these so they are defined for any value. Behaviour-preserving.
	$database	= '';

	if ($table == 1) {
		$database	= $pfb['dnsbl_info'];
	} elseif ($table == 2) {
		$database	= $pfb['dnsbl_resolver'];
	} elseif ($table == 3) {
		$database	= $pfb['dnsbl_resolver'];
	} elseif ($table == 5) {
		$database	= $pfb['asn_cache'];
	} elseif ($table == 6) {
		$database	= $pfb['dnsbl_resolver'];
	} elseif ($table == 7) {
		$database	= $pfb['ip_cache'];
	}

	$table_spec	= pfb_sqlite_table_spec((int) $table);
	$db_table	= $table_spec['db_table'];
	$db_create	= $table_spec['db_create'];
	if ($database === '' || $db_table === '' || $db_create === '') {
		return NULL;
	}

	// ADR-60: these writes bypass pfb_logger() entirely, so they stamp themselves.
	$now = pfb_log_iso_timestamp();

	// issue #1494: both connection attempts below can throw, leaving $db_handle
	// unset at the `if ($db_handle)` check -- init here so that path returns
	// FALSE cleanly instead of reading an undefined variable.
	$db_handle = NULL;

	try {
		$db_handle = new SQLite3($database);
		$db_handle->busyTimeout("{$pfb['sqlite_timeout']}");
	}
	catch (Exception $e) {
		@file_put_contents($pfb['errlog'], "\n{$now} DNSBL_SQL: Failed to open DB - {$message}", FILE_APPEND | LOCK_EX);

		try {
			$db_handle = new SQLite3($database);
			$db_handle->busyTimeout("{$pfb['sqlite_timeout']}");
		}
		catch (Exception $e) {
			@file_put_contents($pfb['errlog'], "\n{$now} DNSBL_SQL: Failed to open DB 2nd attempt - {$message}", FILE_APPEND | LOCK_EX);
		}
	}

	if ($db_handle) {

		// ADR-03: use WAL so the persistent pfb_unbound.py connection and the PHP
		// readers/writers (widget, alerts, pfBlockerNG_clearsqlite counter resets)
		// coexist without 'database is locked'. WAL is a sticky property of the
		// database file and must be set outside of a transaction.
		try {
			// querySingle both sets and returns the effective journal mode, so we
			// can confirm WAL stuck (exec() returns only success, not the mode).
			$journal_mode = strtolower((string) $db_handle->querySingle('PRAGMA journal_mode = WAL;'));
			if ($journal_mode !== 'wal') {
				@file_put_contents($pfb['errlog'], "\n{$now} DNSBL_SQL: Failed to enable WAL ({$journal_mode}) - {$message}", FILE_APPEND | LOCK_EX);
			}
		}
		catch (Exception $e) {
			@file_put_contents($pfb['errlog'], "\n{$now} DNSBL_SQL: Failed to enable WAL - {$message}", FILE_APPEND | LOCK_EX);
		}

		// Validate database integrity
		$validate = $pfb_validate = FALSE;
		try {
			$validate = $db_handle->query("PRAGMA integrity_check;");
		}
		catch (Exception $e) {
			@file_put_contents($pfb['errlog'], "\n{$now} DNSBL_SQL: Failed to validate database - {$message}", FILE_APPEND | LOCK_EX);
		}

		if ($validate) {
			while ($res = $validate->fetchArray(SQLITE3_ASSOC)) {
				if ($res['integrity_check'] == 'ok') {
					$pfb_validate = TRUE;
				}
			}
		}

		if (!$pfb_validate) {
			logger(LOG_WARNING, localize_text("DNSBL SQLite3 database [ %s ] corrupt. Table deletion/re-creation completed.", $db_table), LOG_PREFIX_PKG_PFBLOCKERNG);
			@copy("{$database}", "{$database}.invalid");
			// IF EXISTS: the table may already be absent (e.g. a fresh/never-created
			// DB, or exactly the table-6 'stats'/'lastclear' name mismatch this fix
			// resolves) -- a bare DROP TABLE on a missing table errors and aborts the
			// whole BEGIN/END TRANSACTION below, so 'lastclear' (etc.) never gets
			// rebuilt and recovery silently fails (issue #713 bug 10).
			$db_create = "DROP TABLE IF EXISTS {$db_table}; {$db_create}";
		}

		try {
			$db_handle->exec("BEGIN TRANSACTION;"
					. "{$db_create}"
					. "END TRANSACTION;");
		}
		catch (Exception $e) {
			@file_put_contents($pfb['errlog'], "\n{$now} DNSBL_SQL: Database failure - {$message}", FILE_APPEND | LOCK_EX);
			return;
		}

		if ($table <= 4 && file_exists($database)) {
			@chown($database, 'unbound');
			@chgrp($database, 'unbound');
		}
		return $db_handle;
	}
	return FALSE;
}


// Function to close SQLite3 database
function pfb_close_sqlite($db_handle) {
	if (!empty($db_handle)) {
		$db_handle->close();
		unset($db_handle);
	}
}


// Function to Log event, Increment SQLite 'dnsbl' database and save last event to SQLite 'lastevent' Database
function pfb_log_event($type, $domain, $src_ip, $req_agent) {
	global $pfb;

	$datereq	= pfb_log_iso_timestamp();
	$req_agent	= str_replace("'", '', $req_agent);

	// Collect lastevent without saving new event
	$result		= pfb_dnsbl_lastevent('', "{$domain}{$src_ip}", '');
	$p_entry	= $result['entry'];
	$details	= $result['details'];

	// Duplicate entry comparison: "Domain/SRC IP"
	if ("{$domain}{$src_ip}" == $p_entry) {
		$dup_entry	= '-';
		$pfb_group	= $result['groupname'];
	}

	// If not duplicate entry, determine TLD type, Group Name and Feed name
	else {
		$dup_entry	= '+';

		// ADR-65: attribute via the live query channel instead of grepping the
		// retired interchange files; NULL and blocked=false are both "no verdict".
		$verdict = pfb_dnsbl_query($domain);
		if ($verdict !== NULL && $verdict['blocked']) {
			$pfb_mode	= $verdict['b_type']	?: 'Unknown';
			$pfb_group	= $verdict['group']	?: 'Unknown';
			$pfb_final	= $verdict['b_eval']	?: 'Unknown';
			$pfb_feed	= $verdict['feed']	?: 'Unknown';
		} else {
			$pfb_mode = $pfb_group = $pfb_final = $pfb_feed = 'Unknown';
		}

		$log_domain	= pfb_filter($domain, PFB_FILTER_HTML, 'pfb_log_event');
		$pfb_group	= pfb_filter($pfb_group, PFB_FILTER_HTML, 'pfb_log_event');
		$pfb_final	= pfb_filter($pfb_final, PFB_FILTER_HTML, 'pfb_log_event');
		$pfb_feed	= pfb_filter($pfb_feed, PFB_FILTER_HTML, 'pfb_log_event');
		$details	= "{$log_domain},{$src_ip},{$req_agent},{$pfb_mode},{$pfb_group},{$pfb_final},{$pfb_feed}";

		// Save new lastevent
		pfb_dnsbl_lastevent($pfb_group, "{$domain}{$src_ip}", $details);
	}

	$log = "{$type},{$datereq},{$details},{$dup_entry}\n";
	@file_put_contents($pfb['dnslog'], "{$log}", FILE_APPEND | LOCK_EX);

	// Increment DNSBL Widget counter
	if (!empty($pfb_group)) {

		$db_handle = pfb_open_sqlite(1, 'Increment Counter');
		if ($db_handle) {

			$pfb_group	= pfb_filter($pfb_group, PFB_FILTER_HTML, 'pfb_log_event');
			$db_update	= "UPDATE dnsbl SET counter = counter + 1 WHERE groupname = :pfb_group";

			$stmt = $db_handle->prepare($db_update);
			if ($stmt) {
				$stmt->bindValue(':pfb_group', $pfb_group, SQLITE3_TEXT);
				$stmt->execute();
			}
		}
		pfb_close_sqlite($db_handle);
	}
	@file_put_contents("{$pfb['dnslog']}.applied", "{$type},{$domain}\n", LOCK_EX);
}


// Function to 1) Collect lastevent and 2) Save lastevent to SQLite 'lastevent' Database
function pfb_dnsbl_lastevent($p_group, $p_entry, $p_details) {
	global $pfb;

	$db_update	= '';
	$final		= array();

	$db_handle = pfb_open_sqlite(2, 'LastEvent');
	if ($db_handle) {
		$result	= $db_handle->query("SELECT * FROM lastevent WHERE row = 0;");
		if ($result) {
			$final = $result->fetchArray(SQLITE3_ASSOC);
		}
	}
	pfb_close_sqlite($db_handle);

	// Collect or update existing row
	if (!empty($final)) {

		// Update lastevent entry (no-op when $p_group is empty -- only collect lastevent entry)
		if (!empty($p_group)) {
			$db_update = "UPDATE lastevent SET groupname=:p_group, entry=:p_entry, details=:p_details WHERE row = 0";
		}
	}

	// Add new lastevent entry
	else {
		$db_update = "INSERT into lastevent (row, groupname, entry, details) VALUES (0, :p_group, :p_entry, :p_details )";
	}

	if (!empty($db_update)) {
		$db_handle = pfb_open_sqlite(2, 'LastEvent');
		if ($db_handle) {

			$p_group	= pfb_filter($p_group, PFB_FILTER_HTML, 'pfb_dnsbl_lastevent');
			$p_entry	= pfb_filter($p_entry, PFB_FILTER_HTML, 'pfb_dnsbl_lastevent');
			$p_details	= pfb_filter($p_details, PFB_FILTER_HTML, 'pfb_dnsbl_lastevent');

			$stmt = $db_handle->prepare($db_update);
			if ($stmt) {
				$stmt->bindValue(':p_group', $p_group, SQLITE3_TEXT);
				$stmt->bindValue(':p_entry', $p_entry, SQLITE3_TEXT);
				$stmt->bindValue(':p_details', $p_details, SQLITE3_TEXT);
				$stmt->execute();
			}
		}
		pfb_close_sqlite($db_handle);
	}
	return $final;
}


// TRUE when a pfBlockerNG feed task (cron/update/pfb_trigger/tick/forcecheck) is
// currently running. The GLOBAL active-process guard for the Update-page Run-Now
// dispatchers (pfb_active_task_running): it refuses a second run while ANY pfB feed task
// is running -- including a cron tick this page never launched, so it must scan ps rather
// than rely on a per-run pidfile. (The Run-Now livetail tracks its OWN dispatched process
// by pidfile via isvalidpid() -- a narrower check; this ps scan is the broad one the guard needs.)
function pfb_feed_task_running(?array $ps_lines = NULL): bool {
	if ($ps_lines === NULL) {
		$ps_lines = [];
		exec('/bin/ps -wax', $ps_lines);
	}
	return (bool) preg_grep('/pfblockerng[.]php\s+?(cron-tick|cron|update(ip|dnsbl)?|pfb_trigger|tick|forcecheck|dc|dcc|bu|uc|gc|ugc|al|asn|asn_shell|bl|bls)(?![-\w])/', $ps_lines);
}


// TRUE when a pfBlockerNG UPDATE pass (cron/update/pfb_trigger/forcecheck/dcc/bl) is
// currently running -- deliberately narrower than pfb_feed_task_running() above:
//   - EXCLUDES 'tick' AND 'cron-tick' (the scheduled tick's own verb): the only caller is
//     pfblockerng_tick() itself (the scheduled log maintenance gate at its tail), and a tick
//     always sees its OWN process in `ps` -- including it here would make the gate permanently
//     closed. Hence (?![-\w]) rather than \b: a hyphen SATISFIES \b, so a bare 'cron' arm would
//     match the 'cron-tick' process (issue #1204).
//   - INCLUDES 'dcc'/'bl': both append to $pfb['extraslog'] for potentially minutes,
//     the same log pfb_log_mgmt()'s tail-to-temp-then-cat-over trim can race and lose
//     lines from, so a due-ledger-dispatched dcc/bl pass must also hold this gate closed.
// $ps_lines is injectable (bypasses exec()) so this is unit-testable off-appliance.
function pfb_update_pass_running(?array $ps_lines = NULL): bool {
	if ($ps_lines === NULL) {
		exec('/bin/ps -wax', $ps_lines);
	}
	return (bool) preg_grep('/pfblockerng[.]php\s+?(cron|update(ip|dnsbl)?|pfb_trigger|forcecheck|dcc|bl)(?![-\w])/', $ps_lines);
}


// Decide whether a plain Update-page load should AUTO-TAIL an in-progress update (stream it
// live like the View button) instead of pre-filling the last-run log tail. TRUE iff a
// pfBlockerNG feed task is running AND this request is neither a Run-Now/wizard dispatch
// ($run_dispatch) nor a View/End-View button click ($logview_posted) — those paths drive their
// own livetail. Pure (no globals/IO) so it is unit-tested directly; the page passes isset()
// booleans for the two POST signals.
function pfb_update_autotail(bool $task_running, bool $run_dispatch, bool $logview_posted): bool {
	return $task_running && !$run_dispatch && !$logview_posted;
}


// CLI result for a pass deferred before work starts because a feed lock is held.
define('PFB_EXIT_LOCKED', 75);

function pfb_feed_pass_exit_code(bool $completed, ?string $deferred_by): int {
	return $deferred_by !== NULL ? PFB_EXIT_LOCKED : ($completed ? 0 : 1);
}

function pfb_feed_pass_deferral_message(string $deferred_by): string {
	$lock = $deferred_by === 'dispatcher-lock' ? 'dispatcher lock' : 'feed-pass lock';
	return "pfBlockerNG feed pass deferred: {$lock} is held\n";
}

// issue #1175: cross-process mutual exclusion for a feed pass --
// pfb_feed_task_running()/pfb_update_pass_running() above are ps-scan guards
// (advisory-by-process-list); this flock-based sibling actually serializes two
// overlapping passes so they cannot corrupt shared recompute staging. Reentrant
// within a process: a second acquire by the same process is a no-op success.
// $timeout_s defaults to 0.0 -- one non-blocking attempt, the only shape a feed-pass
// dispatcher may use (it defers instead of queueing). Package installation waits
// (issue #3062, pfb_install_feed_pass_hold()) because it cannot be deferred.
function pfb_feed_pass_acquire(?bool &$contended = NULL, float $timeout_s = 0.0): bool {
	global $pfb;
	$contended = FALSE;

	if (isset($GLOBALS['pfb_feed_pass_lock']) && is_resource($GLOBALS['pfb_feed_pass_lock'])) {
		return TRUE;
	}

	$lockpath = "{$pfb['dbdir']}/pfb_feed_pass.lock";
	$lock = @fopen($lockpath, 'c');	// 'c': create if absent, no truncate
	if ($lock === FALSE) {
		// issue #3000: fail CLOSED like the un-contended flock failure below --
		// continuing without the lock would run the pass unserialised over shared
		// recompute staging while still reporting success to the CLI.
		pfb_logger("\n Feed pass lock: open failed [ {$lockpath} ]; feed pass aborted.\n", 2);
		return FALSE;
	}
	if (!pfb_flock_bounded($lock, LOCK_EX, $timeout_s, $contended)) {
		@fclose($lock);
		if (!$contended) {
			pfb_logger("\n Feed pass lock: acquire failed [ {$lockpath} ]; feed pass aborted.\n", 2);
		}
		return FALSE;
	}

	$GLOBALS['pfb_feed_pass_lock'] = $lock;
	if (empty($GLOBALS['pfb_feed_pass_lock_shutdown_registered'])) {
		// flock also auto-releases on process death (kernel); this just keeps
		// the window tight in a long-lived web worker that acquired but never
		// explicitly released.
		register_shutdown_function('pfb_feed_pass_release');
		$GLOBALS['pfb_feed_pass_lock_shutdown_registered'] = TRUE;
	}
	return TRUE;
}

// Release the lock acquired by pfb_feed_pass_acquire(). No-op unless this
// process holds it -- safe to call from an unconditional cleanup path.
function pfb_feed_pass_release(): void {
	if (!isset($GLOBALS['pfb_feed_pass_lock']) || !is_resource($GLOBALS['pfb_feed_pass_lock'])) {
		return;
	}
	@flock($GLOBALS['pfb_feed_pass_lock'], LOCK_UN);
	@fclose($GLOBALS['pfb_feed_pass_lock']);
	unset($GLOBALS['pfb_feed_pass_lock']);
}

// TRUE iff ANOTHER process currently holds the feed-pass lock. This process's
// own hold (via pfb_feed_pass_acquire()) never reads as busy to itself. The
// probe takes a momentary LOCK_NB hold to test contention, then releases
// immediately -- never left locked.
function pfb_feed_pass_busy(): bool {
	global $pfb;

	if (isset($GLOBALS['pfb_feed_pass_lock']) && is_resource($GLOBALS['pfb_feed_pass_lock'])) {
		return FALSE;
	}

	$lockpath = "{$pfb['dbdir']}/pfb_feed_pass.lock";
	$probe = @fopen($lockpath, 'c');
	if ($probe === FALSE) {
		return FALSE;	// fail open: an unwritable dbdir never reports busy
	}
	if (!@flock($probe, LOCK_EX | LOCK_NB)) {
		@fclose($probe);
		return TRUE;
	}
	@flock($probe, LOCK_UN);
	@fclose($probe);
	return FALSE;
}

// issue #1175: acquire-or-log-skip choke point both sync funnels call, so a
// busy pass is skipped with the SAME logged message regardless of dispatcher.
function pfb_feed_pass_begin(string $label, ?bool &$contended = NULL): bool {
	if (pfb_feed_pass_acquire($contended)) {
		return TRUE;
	}
	if (!$contended) {
		return FALSE;
	}
	pfb_logger("\nFeed pass [ {$label} ] skipped -- another pfBlockerNG feed pass is running.\n", 1);
	logger(LOG_NOTICE, localize_text('Feed pass [ %s ] skipped - another pfBlockerNG feed pass is running.', $label),
		LOG_PREFIX_PKG_PFBLOCKERNG);
	return FALSE;
}


// Seconds a package install waits for an in-flight feed pass before it proceeds anyway.
define('PFB_INSTALL_FEED_PASS_WAIT', 300.0);

// issue #3062: the install's hold on the feed-pass lock -- waits, then keeps it until this
// process exits (pfb_feed_pass_release() at shutdown). FALSE never aborts the caller: an
// install may not be abandoned. architecture-notes.md "The package install holds it too".
function pfb_install_feed_pass_hold(float $timeout_s = PFB_INSTALL_FEED_PASS_WAIT): bool {
	if (pfb_feed_pass_busy()) {
		pfb_logger("\nPackage install: waiting up to {$timeout_s}s for the in-flight feed pass to finish.\n", 1);
		logger(LOG_NOTICE, localize_text('Package install waiting for the in-flight feed pass to finish.'),
			LOG_PREFIX_PKG_PFBLOCKERNG);
	}

	$contended = FALSE;
	if (pfb_feed_pass_acquire($contended, $timeout_s)) {
		return TRUE;
	}

	if ($contended) {
		pfb_logger("\nPackage install proceeding WITHOUT the feed-pass lock: a feed pass is still running.\n", 2);
		logger(LOG_WARNING, localize_text('Package install proceeding without the feed-pass lock - a feed pass is still running.'),
			LOG_PREFIX_PKG_PFBLOCKERNG);
	} else {
		pfb_logger("\nPackage install proceeding WITHOUT the feed-pass lock: it could not be acquired.\n", 2);
		logger(LOG_WARNING, localize_text('Package install proceeding without the feed-pass lock - it could not be acquired.'),
			LOG_PREFIX_PKG_PFBLOCKERNG);
	}
	return FALSE;
}


// Encode a string as a JavaScript string literal (including the surrounding double quotes) for
// assignment to a textarea's plain-text .value. json_encode gives correct JS-string escaping --
// unlike htmlspecialchars(), which HTML-entity-escapes (so a '>' would render as a literal
// '&gt;' in the .value) and leaves backslashes unescaped (a log line ending in '\' could break
// out of the literal). JSON_HEX_TAG/AMP/APOS/QUOT neutralise a '</script>' or quote breakout;
// JSON_INVALID_UTF8_SUBSTITUTE keeps invalid bytes in log data from making json_encode return
// FALSE (the fallback is an empty literal).
function pfb_js_string(string $text): string {
	$json = json_encode($text, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_INVALID_UTF8_SUBSTITUTE);
	return ($json === FALSE) ? '""' : $json;
}


// Read the next slice of a live log file for the AJAX tail endpoint, starting at byte $offset.
// Returns ['data' => <new text>, 'offset' => <next byte offset to request>]. Whole lines only
// by default — a trailing partial line is held back ($offset advances only past the last
// newline) so a multibyte UTF-8 char is never split across two polls; pass $flush = TRUE on the
// FINAL read to emit the trailing partial line too. $offset is a RAW byte position (the
// returned data has CR stripped for display only, so the count is computed BEFORE stripping).
// $offset past EOF (file truncated/rotated) resets to 0 so the tail re-reads from the new start.
function pfb_log_tail_chunk(string $file, int $offset, bool $flush = FALSE): array {
	clearstatcache(FALSE, $file);
	$len = @filesize($file);
	if ($len === FALSE) {
		return ['data' => '', 'offset' => 0];	// no file yet
	}
	if ($offset < 0 || $offset > $len) {
		$offset = 0;				// truncated/rotated -> restart
	}
	if ($offset === $len) {
		return ['data' => '', 'offset' => $len];	// nothing new
	}

	$f = @fopen($file, 'rb');
	if ($f === FALSE) {
		return ['data' => '', 'offset' => $offset];
	}
	@fseek($f, $offset);
	$raw = '';
	while (!feof($f)) {
		$buf = @fread($f, 8192);
		if ($buf === FALSE) {
			break;
		}
		$raw .= $buf;
	}
	@fclose($f);

	if (!$flush) {
		// Emit up to the last complete line; hold the trailing partial for the next poll.
		$nl = strrpos($raw, "\n");
		if ($nl === FALSE) {
			return ['data' => '', 'offset' => $offset];
		}
		$raw = substr($raw, 0, $nl + 1);
	}

	return ['data' => str_replace("\r", '', $raw), 'offset' => $offset + strlen($raw)];
}


// Build the JSON payload for the AJAX live-log tail (the ?ajax=tail branch on the Update page).
// Returns an array the caller json_encode()s; no print/exit here (library code).
//
// $which selects the source: 'update' tails the per-run pfblockerng_run.log, falling back to the
// last ~15KB of the cumulative log for a View when no run file exists yet. $offset is the client's
// last byte position; $has_offset is FALSE on the first poll (the function then picks the source +
// starting offset). 'done' (process gone, via isvalidpid on the pidfile) tells the client to stop
// polling; the final read is flushed so the trailing partial line is not lost.
function pfb_log_tail_payload(string $which, int $offset, bool $has_offset): array {
	global $pfb;

	switch ($which) {
		case 'update':
			$pidfile  = '/var/run/pfb_runnow.pid';
			$runfile  = $pfb['runlog'];
			$fallback = $pfb['log'];
			break;
		default:
			return ['error' => 'invalid source'];
	}

	$running = isvalidpid($pidfile);

	// First poll: choose the source + initial offset.
	if (!$has_offset) {
		clearstatcache(FALSE, $runfile);
		$runsize = @filesize($runfile);
		// Fall back to the cumulative log's tail ONLY when the run log is empty AND no run is in
		// flight (a View with nothing current). While a run IS alive, an empty run log just means
		// the dispatched daemon has not written its first line yet -- the client's first poll
		// commonly beats the fork/exec/bootstrap -- so fall through to the run-log follow and keep
		// polling (done = FALSE), never a one-shot fallback that would stop the tail prematurely.
		if (($runsize === FALSE || $runsize === 0) && !$running) {
			// No current/last run log and nothing running -> one-shot View of the cumulative tail.
			$fsize = '';
			if ($fallback !== '') {
				clearstatcache(FALSE, $fallback);
				$fsize = @filesize($fallback);
			}
			if ($fsize !== '' && $fsize !== FALSE && $fsize > 0) {
				$chunk = pfb_log_tail_chunk($fallback, ($fsize > 15000) ? ($fsize - 15000) : 0, TRUE);
				return ['data' => $chunk['data'], 'offset' => $chunk['offset'], 'running' => FALSE, 'done' => TRUE, 'source' => 'fallback'];
			}
			return ['data' => '', 'offset' => 0, 'running' => $running, 'done' => !$running, 'source' => 'none'];
		}
		$offset = 0;
	}

	// Follow the run log; flush the final partial line once the process is gone.
	$chunk = pfb_log_tail_chunk($runfile, $offset, !$running);
	return ['data' => $chunk['data'], 'offset' => $chunk['offset'], 'running' => $running, 'done' => !$running, 'source' => 'run'];
}


// Open the per-run log window for the live viewer: truncate the run log once and turn on the
// pfb_logger() mirror (runlog_active). Guarded so the OUTERMOST entry point wins -- when
// pfblockerng_sync_cron() (Force Check / cron tick) begins the window and later calls
// sync_package_pfblockerng(), the inner call is a no-op and does NOT re-truncate mid-run (which
// would wipe the feed-pass output the client is already tailing). Idempotent within a process.
function pfb_runlog_begin() {
	global $pfb;
	if (!empty($pfb['runlog']) && empty($pfb['runlog_active'])) {
		@file_put_contents($pfb['runlog'], '');
		$pfb['runlog_active'] = TRUE;
	}
}


// The regular file a run's raw output (dispatched-process stdout, hook-script output) should be
// appended to: the per-run log WHILE a run is active (so the live tail streams it, interleaved
// with pfb_logger()'s mirror), else the cumulative log. Never a pipe -- a hook's spawned daemon
// inheriting a pipe would hang exec() on missing EOF (see pfb_run_hooks).
function pfb_run_log_target(): string {
	global $pfb;
	return (!empty($pfb['runlog_active']) && !empty($pfb['runlog'])) ? $pfb['runlog'] : $pfb['log'];
}


// Load/convert Feeds (w/alternative aliasname(s), if user-configured) and return as array
function convert_feeds_json() {
	global $pfb;

	$aconfig		= config_get_path('installedpackages/pfblockerngglobal', []);
	$pfb['feeds_list']	= $merge_feeds = $feed_info = array();

	$feed_info_raw = json_decode(@file_get_contents("{$pfb['feeds']}"), TRUE);
	if (json_last_error() !== JSON_ERROR_NONE || !is_array($feed_info_raw)) {
		return array('blank' => '');
	}

	$feed_count = array();
	foreach ($feed_info_raw as $type => $info) {

		if (!is_array($info) || (isset($info[0]) && $info[0] == '*')) {
			continue;
		}

		$feed_count[$type] = 0;
		foreach ($info as $aliasname => $data) {
			$l_aliasname = strtolower($aliasname);

			$feed_count[$type] = $feed_count[$type] + count($data['feeds']);
			foreach ($data['feeds'] as $key => $feed) {

				// Remove discontinued Feeds
				if (isset($feed['status']) && $feed['status'] == 'discontinued') {
					unset($data['feeds'][$key]);
					$feed_count[$type]--;
					continue;
				}

				if (isset($feed['alternate'])) {
					foreach ($feed['alternate'] as $alternate) {
						$feed_count[$type]++;
					}
				}
			}

			if (!array_key_exists($type, $pfb['feeds_list'])) {
				$pfb['feeds_list'][$type] = array();
			}
			if (!array_key_exists($type, $feed_info)) {
				$feed_info[$type] = array();
			}

			// Use alternative Aliasname(s) and/or merge multiple aliasname Feeds together (if user configured)
			if (!empty($aconfig['feed_' . $l_aliasname])) {

				$alt_feed = $aconfig['feed_' . $l_aliasname];
				$pfb['feeds_list'][$type][$aliasname] = $alt_feed;	// Global list of all known Feed aliasnames

				if (!is_array($merge_feeds[$alt_feed])) {
					$merge_feeds[$alt_feed] = array();
				}
				$merge_feeds[$alt_feed] = array_merge( $merge_feeds[$alt_feed], (array)$data['feeds'] );

				if (!isset($feed_info[$type][$alt_feed])) {

					// Modify 'info' and 'description' fields to reference user-defined aliasname
					foreach (array('info', 'description') as $atype) {
						$match = strpos($data[$atype], $aliasname);
						if ($match !== FALSE) {
							$data[$atype] = substr_replace($data[$atype], $aconfig['feed_' . $l_aliasname], $match, strlen($aliasname));
						}
					}
					$feed_info[$type][$aconfig['feed_' . $l_aliasname]] = $data;
				}
				$feed_info[$type][$alt_feed]['feeds'] = $merge_feeds[$alt_feed];
			}
			else {
				$pfb['feeds_list'][$type][$aliasname] = $aliasname;
				$feed_info[$type][$aliasname] = $data;
			}
		}
	}
	$feed_info['count'] = $feed_count;
	return $feed_info;
}


// Define Alerts Tab 'default GET request' (Top row)
function pfb_alerts_default_page() {
	global $pfb;

	$valid_views = [
		'dnsbl_stat',
		'dnsbl_reply_stat',
		'ip_block_stat',
		'ip_permit_stat',
		'ip_match_stat',
		'reply',
		'unified'
	];

	if (isset($pfb['config_global']) &&
	    isset($pfb['config_global']['pfbpageload'])) {
		$view = $pfb['config_global']['pfbpageload'];
		if (in_array($view, $valid_views, TRUE)) {
			return "?view={$view}";
		}
	}
	return '';
}


// Clear IP Alias Packet Counts (widget)
function pfBlockerNG_clearip() {
	global $pfb;

	exec("{$pfb['pfctl']} -z 2>&1");
}


// Clear DNSBL SQLite database statistics/queries as required
function pfBlockerNG_clearsqlite($mode, $totalqueries = 0) {
	global $g, $pfb;

	// Format of todo array: database, error message, SQLite command
	$todo = array();

	// INIT-GAP (#1497): each is assigned only in its own $mode branch below,
	// but read again in the $todo processing loop's matching $mode branch.
	$lastipclear = '';
	$lastdnsblclear = '';

	// Clear SQLite database 'queries' entry and update totalqueries (+queries), if Unbound Resolver PID changed (Reload)
	if ($mode == 'update_totalqueries') {
		$todo[] = array(3, 'Clear Resolver queries', 'UPDATE resolver SET totalqueries = :totalqueries, queries = 0 WHERE row = 0;');
	}
	elseif ($mode == 'clearip') {
		$lastipclear = date('Y-m-d H:i:s', time());
		$todo[] = array(6, 'Reset IP last clear timestamp', 'UPDATE lastclear SET lastipclear = :lastipclear WHERE row = 0;');
	}
	elseif ($mode == 'cleardnsbl') {
		$lastdnsblclear = date('Y-m-d H:i:s', time());
		$todo[] = array(1, 'Clear Widget counters', 'UPDATE dnsbl SET counter = 0;');
		$todo[] = array(3, 'Clear Resolver queries', 'UPDATE resolver SET totalqueries = 0, queries = 0;');
		$todo[] = array(6, 'Reset DNSBL last clear timestamp', 'UPDATE lastclear SET lastdnsblclear = :lastdnsblclear WHERE row = 0;');
	}

	// Clear Unbound Resolver statistics
	if ($mode != 'clearip' && is_process_running('unbound')) {
		exec("{$pfb['chroot_cmd']} flush_stats 2>&1");
	}

	if (!empty($todo)) {
		foreach ($todo as $data) {
			$db_handle = pfb_open_sqlite($data[0], $data[1]);

			if ($db_handle) {
				if ($mode == 'update_totalqueries') {
					if (is_numeric($totalqueries)) {
						$stmt = $db_handle->prepare($data[2]);
						if ($stmt) {
							$stmt->bindValue(':totalqueries', $totalqueries, SQLITE3_INTEGER);
							$stmt->execute();
						}
					}
				}
				elseif ($mode == 'clearip') {
					$stmt = $db_handle->prepare($data[2]);
					if ($stmt) {
						$stmt->bindValue(':lastipclear', $lastipclear, SQLITE3_TEXT);
						$stmt->execute();
					}
				}
				elseif ($mode == 'cleardnsbl') {
					$stmt = $db_handle->prepare($data[2]);
					if ($stmt) {
						$stmt->bindValue(':lastdnsblclear', $lastdnsblclear, SQLITE3_TEXT);
						$stmt->execute();
					}
				}
				else {
					$db_handle->exec("BEGIN TRANSACTION;"
							. "{$data[2]}"
							. "END TRANSACTION;");
				}
			}
			pfb_close_sqlite($db_handle);
		}
	}
}


// Function to read/lock/unlock IP/Domains from Aliastables/DNSBL (Called via Alerts Page)
function pfb_unlock($mode, $type, $filename_unlock, $remove='', $r_type='') {
	global $pfb;

	if ($type == 'ip') {
		$filename = $pfb['ip_unlock'];
	} elseif ($type == 'dnsbl') {
		$filename = $pfb['dnsbl_unlock'];
	} else {
		return;
	}

	if ($mode == 'read') {
		$filename_unlock = array();
		if (($handle = @fopen("{$filename}", 'r')) !== FALSE) {
			while (($line = @fgetcsv($handle)) !== FALSE) {
				if (!empty($line)) {
					$filename_unlock[$line[0]] = $line[1];
				}
			}
		}
		if ($handle) {
			@fclose($handle);
		}

		if (empty($filename_unlock)) {
			unlink_if_exists("{$filename}");
		}
		return $filename_unlock;
	}
	elseif ($mode == 'unlock' && isset($filename_unlock[$remove])) {
		return;
	}
	elseif (empty($remove)) {
		return;
	}

	// Add/Remove IP/Domain in unlock file
	if (($pfb_output = @fopen("{$filename}", 'w')) !== FALSE) {
		foreach ($filename_unlock as $key => $line) {

			// 'Remove locked IP/Domains' or 'Add existing unlocked IP/Domain' in unlock file
			if ($mode == 'unlock' || ($mode == 'lock' && $key != $remove)) {
				@fwrite($pfb_output, "{$key},{$line}\n");
			}
		}

		// Add IP/Domain to unlock file
		if ($mode == 'unlock') {
			$filename_unlock[$remove] = $r_type;
			@fwrite($pfb_output, "{$remove},{$r_type}\n");
		}
	}
	if ($pfb_output) {
		@fclose($pfb_output);
	}

	if (empty($filename_unlock)) {
		unlink_if_exists("{$filename}");
	}
}


// Function to clear pfBlockerNG folder/files
function pfb_clear_contents() {
	global $pfb;

	unlink_if_exists("{$pfb['dbdir']}/masterfile");
	unlink_if_exists("{$pfb['dbdir']}/mastercat");
	unlink_if_exists("{$pfb['supptxt']}");
	unlink_if_exists("{$pfb['supptxt_v6']}");
	unlink_if_exists("{$pfb['dnsbl_supptxt']}");
	unlink_if_exists("{$pfb['dnsbl_info']}");
	unlink_if_exists("{$pfb['dnsbl_resolver']}");
	foreach (array($pfb['dnsbl_cache'], "{$pfb['dnsbl_cache']}-wal", "{$pfb['dnsbl_cache']}-shm") as $legacy_cache) {
		unlink_if_exists($legacy_cache);
	}
	unlink_if_exists("/var/tmp/unbound_cache_*");
	unlink_if_exists("{$pfb['asn_cache']}");
	unlink_if_exists("{$pfb['ip_cache']}");
	rmdir_recursive("{$pfb['origdir']}");
	rmdir_recursive("{$pfb['snapdir']}");
	rmdir_recursive("{$pfb['matchdir']}");
	rmdir_recursive("{$pfb['permitdir']}");
	rmdir_recursive("{$pfb['denydir']}");
	rmdir_recursive("{$pfb['nativedir']}");
	rmdir_recursive("{$pfb['etdir']}");
	rmdir_recursive("{$pfb['dnsdir']}");
	rmdir_recursive("{$pfb['dnsorigdir']}");
	rmdir_recursive("{$pfb['dbdir']}/dnsblalias");
}


// ADR-38: the canonical installedpackages/package <logging> block pfBlockerNG registers for its
// dedicated syslog. The `pkg add` install path does NOT copy the package XML's <logging> block,
// so sync_package_pfblockerng() asserts it here. 'logtab' pins the Status > System Logs > Packages
// subtab label to "pfBlockerNG" on both channels (core else falls back to the package short name,
// which reads "pfBlockerNG-devel" on the devel package).
function pfb_syslog_logging_want() {
	return array(
		'logtab' => 'pfBlockerNG',
		'facilityname' => 'pfblockerng',
		'logfilename' => 'pfblockerng_syslog.log',
	);
}

// TRUE when the stored <logging> block must be rewritten to the canonical one: any tracked field
// (logtab / facilityname / logfilename) mismatches, or a stale <logsocket> is present (the removed
// in-chroot socket, which core would otherwise regenerate). An already-canonical block with no
// logsocket is left untouched.
function pfb_syslog_logging_needs_update($current, $want) {
	if (!is_array($current)) {
		$current = array();
	}
	foreach (array('logtab', 'facilityname', 'logfilename') as $pfb_k) {
		if (($current[$pfb_k] ?? '') !== ($want[$pfb_k] ?? '')) {
			return TRUE;
		}
	}
	return !empty($current['logsocket']);
}

/**
 * Diff two filter-rule arrays, restricted to pfBlockerNG-owned rules (pfb_is_managed_obj()
 * on the rule 'descr'). Returns the descr lists of pfB rules created / modified / removed
 * between $old_rules and $new_rules, plus a 'reordered' flag = TRUE when no pfB rule was
 * added, modified, or removed (the caller only diffs when the full arrays already differ, so
 * an empty pfB diff means the change was a reorder and/or user-rule edit). User rules are
 * never reported — ADR-41 reorders them but pfB does not own them.
 *
 * @param array $old_rules Rules before the change (created-tag stripped).
 * @param array $new_rules Rules after the change (created-tag stripped).
 * @return array{created: list<string>, modified: list<string>, removed: list<string>, reordered: bool}
 */
function pfb_diff_managed_rules(array $old_rules, array $new_rules): array {
	// Build descr => rule maps for pfB-owned rules only (last wins on duplicate descr).
	$old_map = [];
	foreach ($old_rules as $r) {
		$descr = (string) ($r['descr'] ?? '');
		if (pfb_is_managed_obj($descr)) {
			$old_map[$descr] = $r;
		}
	}
	$new_map = [];
	foreach ($new_rules as $r) {
		$descr = (string) ($r['descr'] ?? '');
		if (pfb_is_managed_obj($descr)) {
			$new_map[$descr] = $r;
		}
	}

	$created  = array_values(array_diff(array_keys($new_map), array_keys($old_map)));
	$removed  = array_values(array_diff(array_keys($old_map), array_keys($new_map)));
	$modified = [];
	foreach (array_intersect(array_keys($old_map), array_keys($new_map)) as $descr) {
		if ($old_map[$descr] != $new_map[$descr]) {
			$modified[] = $descr;
		}
	}

	$reordered = empty($created) && empty($modified) && empty($removed);
	return ['created' => $created, 'modified' => $modified, 'removed' => $removed, 'reordered' => $reordered];
}

/**
 * pfb_build_autorule_list() — pure emission helper extracted from sync_package_pfblockerng().
 *
 * Reconciles the firewall auto-rules by a STABLE bucket reorder: every surviving rule is sorted
 * into one of four buckets — pfB pass/match, pfB block/reject, user pass/match, user block/reject
 * — and the buckets are concatenated in the sequence the `pass_order` setting dictates. Whole
 * buckets move; nothing INSIDE a bucket is reordered, and no user rule is ever duplicated,
 * dropped, or content-mutated (the one exception is the legacy `_v4` alias-suffix upgrade). pfB
 * rules are regenerated from $pfb_generated; user rules pass through verbatim.
 *
 * The reorder is applied INDEPENDENTLY to the two pf rule groups, because pf evaluates them
 * separately: the FLOATING group (always carries the DNSBL/match pass rules; also the pfB
 * permit/deny when float mode is on, since the call site then builds them from base_rule_float)
 * and the INTERFACE group (the per-interface pfB permit/deny when float mode is off). Each group
 * orders its own four buckets by the same ORDER table:
 *
 *   order_0 | pfB pass/match | pfB block/reject | user (not split) |
 *   order_1 | user pass/match | pfB pass/match | pfB block/reject | user block/reject |
 *   order_2 | pfB pass/match | user pass/match | pfB block/reject | user block/reject |
 *   order_3 | pfB pass/match | pfB block/reject | user pass/match | user block/reject |
 *   order_4 | pfB pass/match | pfB block/reject | user block/reject | user pass/match |
 *   absent / unknown → order_0
 *
 * Returns the new filter/rule array. No I/O, no config writes, no pfctl — pure array logic.
 *
 * @param array  $existing_rules  The current filter/rule array from config.xml.
 * @param array  $pfb_generated   Pre-built pfB rule templates and DNSBL float rules:
 *                                  'permit_inbound'   => array of pfB pass template rules (inbound)
 *                                  'permit_outbound'  => array of pfB pass template rules (outbound)
 *                                  'deny_inbound'     => array of pfB block/reject template rules (inbound)
 *                                  'deny_outbound'    => array of pfB block/reject template rules (outbound)
 *                                  'match_inbound'    => array of pfB match template rules (inbound)
 *                                  'match_outbound'   => array of pfB match template rules (outbound)
 *                                  'inbound_floating' => interface string for match_inbound floating
 *                                  'outbound_floating'=> interface string for match_outbound floating
 *                                  'dnsbl_float'      => array of 0-2 pre-built DNSBL ping/permit rules
 * @param ?string $order          The pass_order value ('order_0' .. 'order_4'). The production
 *                                call site already passes `$pfb['order'] ?: 'order_0'`, so this is
 *                                never null/empty there (#532); nullable + the order_0 normalisation
 *                                below are defensive so any empty/unknown value behaves as order_0.
 * @param PfbToggle $float        Float mode. Typed since issue #1887: $pfb['float'] is a
 *                                PfbToggle, so the historical unconfigured-null case (which
 *                                this used to coerce to '') can no longer reach here.
 * @param array  $in_ifaces       Inbound interface names.
 * @param array  $out_ifaces      Outbound interface names.
 * @return array The new filter/rule array to write back to config.xml.
 */
function pfb_build_autorule_list(
	array   $existing_rules,
	array   $pfb_generated,
	?string $order,
	PfbToggle $float,
	array   $in_ifaces,
	array   $out_ifaces
): array {
	// $float arrives as a PfbToggle (issue #1887); $order
	// arrives pre-defaulted to 'order_0' from the call site (#532) but is accepted nullable too.
	// The historical inline code used these raw values in loose comparisons ('== on' / '== order_N'),
	// where null simply matches nothing -- so a null is behaviour-equivalent to ''. Coerce here
	// (the params are nullable) rather than let a strict string typehint TypeError on the null the
	// call site legitimately passes (e.g. enable_float unset).
	$order = $order ?? '';

	// Any value that is not a known order_1..4 behaves as order_0 -- the IP-settings default.
	// An empty/unknown order must never drop a user rule (issue #532/#539): normalise up front so
	// the bucketing and the order switch below always have a defined sequence.
	if (!in_array($order, ['order_1', 'order_2', 'order_3', 'order_4'], TRUE)) {
		$order = 'order_0';
	}
	$managed = array_merge($in_ifaces, $out_ifaces);

	// --- Partition surviving user rules into stable buckets --------------------------------
	// A rule is pfB-owned (regenerated below) iff its descr starts 'pfB_' AND it is not a
	// DNS-redirect / DoT-block bypass rule (those keep the prefix but stay user-managed). Every
	// surviving user rule lands in EXACTLY ONE bucket -- never duplicated -- and its content is
	// left untouched bar the legacy _v4 alias-suffix upgrade. The split mirrors the historical
	// sync_package_pfblockerng() "Assign Rules" logic verbatim; the four floating sub-buckets
	// only fill when pfB float mode is on (so user floating rules order relative to the floating
	// pfB rules), and $user_pm only fills when float mode is off (interface-group ordering).
	$user_pm = [];   // user pass/match on a managed iface  (float off, order != order_0)
	$user_br = [];   // every other non-floating user rule  (block/reject, order_0 catch-all, unmanaged)
	$fpermit = [];   // user floating pass   (float on)
	$fmatch  = [];   // user floating match  (float on)
	$fother  = [];   // user floating other  (float-on block/reject; ALL floating user rules when float off)

	foreach ($existing_rules as $rule) {
		$descr     = $rule['descr'] ?? '';
		$is_bypass = str_starts_with($descr, PFB_DNS_REDIR_DESCR_V4_PFX) ||
		             str_starts_with($descr, PFB_DOT_BLOCK_DESCR_PFX);

		if (str_starts_with($descr, 'pfB_') && !$is_bypass) {
			continue;  // pfB-owned — regenerated below
		}

		// Upgrade previous IPv4 pfBlockerNG alias names to '_v4' suffix format — the ONLY
		// permitted content change to a user rule.
		foreach (array('source', 'destination') as $rtype) {
			if (pfb_rule_alias_needs_v4_suffix($rule[$rtype]['address'] ?? '', $rule['ipprotocol'] ?? '')) {
				$rule[$rtype]['address'] = "{$rule[$rtype]['address']}_v4";
			}
		}

		$is_floating = ($rule['floating'] ?? '') === 'yes';
		$type        = $rule['type'] ?? '';

		if ($float === PfbToggle::On) {
			if ($order === 'order_0' && $is_floating) {
				$fother[]  = $rule;
			} elseif ($is_floating && $type === 'pass') {
				$fpermit[] = $rule;
			} elseif ($is_floating && $type === 'match') {
				$fmatch[]  = $rule;
			} elseif ($is_floating) {
				$fother[]  = $rule;
			} else {
				$user_br[] = $rule;
			}
		} elseif ($is_floating) {
			$fother[] = $rule;
		} elseif (in_array($rule['interface'] ?? '', $managed, TRUE) &&
		          ($type === 'pass' || isset($rule['associated-rule-id'])) &&
		          $order !== 'order_0') {
			$user_pm[] = $rule;
		} else {
			$user_br[] = $rule;
		}
	}

	// --- Regenerate the pfB rule buckets ---------------------------------------------------
	// DNSBL floating pass pair and the floating match rules ALWAYS belong to the floating pf
	// group; the per-interface permit/deny join the floating group when float mode is on and the
	// interface group otherwise (handled in the assembly below). The match rule is floating-only
	// and emitted ONCE across all interfaces; it rides in the pass/match bucket. (Grouping it
	// after the per-interface permits rather than mid-loop is inert: a match rule does not
	// short-circuit, and interface-scoped permits on different interfaces never interact.)
	$dnsbl   = [];   // pfB floating DNSBL pass (ping/permit pair, or empty)
	$ppermit = [];   // pfB permit (per managed interface)
	$pmatch  = [];   // pfB floating match (emitted once)
	$pdeny   = [];   // pfB block/reject (per managed interface)

	foreach ($pfb_generated['dnsbl_float'] as $cb_rules) {
		$dnsbl[] = $cb_rules;
	}

	$pfbrunonce = TRUE;
	foreach ($in_ifaces as $inbound_interface) {
		foreach ($pfb_generated['permit_inbound'] as $cb_rules) {
			$cb_rules['interface'] = $inbound_interface;
			$cb_rules['tracker']   = pfb_tracker($cb_rules['descr'], $inbound_interface, 'permit_in');
			$ppermit[]             = $cb_rules;
		}
		if ($pfbrunonce && !empty($pfb_generated['match_inbound'])) {
			foreach ($pfb_generated['match_inbound'] as $cb_rules) {
				$cb_rules['interface'] = $pfb_generated['inbound_floating'];
				$cb_rules['tracker']   = pfb_tracker($cb_rules['descr'], $inbound_interface, 'match_in');
				$pmatch[]              = $cb_rules;
				$pfbrunonce            = FALSE;
			}
		}
		foreach ($pfb_generated['deny_inbound'] as $cb_rules) {
			$cb_rules['interface'] = $inbound_interface;
			$cb_rules['tracker']   = pfb_tracker($cb_rules['descr'], $inbound_interface, 'deny_in');
			$pdeny[]               = $cb_rules;
		}
	}

	$pfbrunonce = TRUE;
	foreach ($out_ifaces as $outbound_interface) {
		foreach ($pfb_generated['permit_outbound'] as $cb_rules) {
			$cb_rules['interface'] = $outbound_interface;
			$cb_rules['tracker']   = pfb_tracker($cb_rules['descr'], $outbound_interface, 'permit_out');
			$ppermit[]             = $cb_rules;
		}
		if ($pfbrunonce && !empty($pfb_generated['match_outbound'])) {
			foreach ($pfb_generated['match_outbound'] as $cb_rules) {
				$cb_rules['interface'] = $pfb_generated['outbound_floating'];
				$cb_rules['tracker']   = pfb_tracker($cb_rules['descr'], $outbound_interface, 'match_out');
				$pmatch[]              = $cb_rules;
				$pfbrunonce            = FALSE;
			}
		}
		foreach ($pfb_generated['deny_outbound'] as $cb_rules) {
			$cb_rules['interface'] = $outbound_interface;
			$cb_rules['tracker']   = pfb_tracker($cb_rules['descr'], $outbound_interface, 'deny_out');
			$pdeny[]               = $cb_rules;
		}
	}

	// --- Assemble each pf group's four buckets in pass_order sequence -----------------------
	// $apply moves whole buckets per the ORDER table; order_0 and order_3 share a sequence
	// (order_0 leaves $upm empty by construction, so user pass/match is never split out).
	$apply = static function (string $o, array $pm, array $br, array $upm, array $ubr): array {
		return match ($o) {
			'order_1' => array_merge($upm, $pm, $br, $ubr),
			'order_2' => array_merge($pm, $upm, $br, $ubr),
			'order_4' => array_merge($pm, $br, $ubr, $upm),
			default   => array_merge($pm, $br, $upm, $ubr),  // order_0 / order_3
		};
	};

	if ($float === PfbToggle::On) {
		// Float mode on: the pfB permit/deny are floating too, so the whole pass_order reorder
		// happens in the floating group; the interface group carries only non-floating user rules.
		$float_seq = $apply($order, array_merge($dnsbl, $ppermit, $pmatch), $pdeny,
		                    array_merge($fpermit, $fmatch), $fother);
		$iface_seq = $apply($order, [], [], [], $user_br);
	} else {
		// Float mode off: pfB permit/deny are interface rules; only DNSBL/match are floating.
		// In the floating group the user's floating rules ($fother) historically lead for
		// order_1 and trail otherwise — the $upm slot reproduces exactly that placement.
		$float_seq = $apply($order, array_merge($dnsbl, $pmatch), [], $fother, []);
		$iface_seq = $apply($order, $ppermit, $pdeny, $user_pm, $user_br);
	}

	return array_values(array_merge($float_seq, $iface_seq));
}

require_once __DIR__ . '/pfblockerng_apply.inc';
require_once __DIR__ . '/pfblockerng_cron.inc';
require_once __DIR__ . '/pfblockerng_geoip.inc';


// Function to De-Install pfBlockerNG
function pfblockerng_php_pre_deinstall_command() {
	require_once('config.inc');
	global $g, $pfb;

	// Keep Settings remains governed by the existing pfb_keep boundary.
	pfb_settings_family_pre_uninstall();

	// #697: tear down ONLY on a genuine removal; keep pfBlockerNG live across a package upgrade.
	// pfSense reaches the pre-deinstall for both, but with a different pkg operation (read from the
	// pkg ancestor's argv): a real uninstall -- and a MAJOR OS upgrade's mass-removal -- is
	// `pkg delete` (op 'delete'); the GUI Update / `pkg upgrade` / a forced reinstall is
	// `pkg install -f` / `pkg upgrade` (op install|reinstall|upgrade). On a non-delete op we SKIP
	// the teardown and let the package's post-install resync re-apply -- so a version bump keeps
	// pfBlockerNG running. On a delete we tear down (uninstall = OFF); a major OS upgrade takes that
	// path too and is reinstalled after reboot, settings kept by keep=on (the default). '' fails safe
	// to teardown (a real uninstall is always a detectable `pkg delete`).
	$pfb_pkg_op = pfb_pkg_operation();
	if (!pfb_pkg_op_tears_down($pfb_pkg_op)) {
		update_status("Keeping pfBlockerNG active across the package {$pfb_pkg_op} (not a removal).\n");
		return;
	}

	// Set these two variables to disable pfBlockerNG on de-install. pfb_global() turns the
	// install/reinstall flag into enable/dnsbl='' (2129), so this runs a full DISABLE pass --
	// uninstall == turning pfBlockerNG OFF (rules removed, DNSBL/Unbound disabled, its pre/post
	// hooks fired so external consumers reconfigure to the off state), a no-op if already off.
	$pfb['save'] = $pfb['install'] = TRUE;
	// #684: publish the pkg transition to the hooks fired by the disable pass below (they get
	// PFB_PRE_UNINSTALL=1). Context only -- pfBlockerNG does not branch on it.
	$pfb['hook_lifecycle'] = 'uninstall';

	update_status("Removing pfBlockerNG...");
	sync_package_pfblockerng();
	pfb_top1m_teardown_call();

	// Live-object teardown always runs regardless of $pfb['keep'], so that uninstalling
	// with the default keep=on still removes active pf tables, boot hooks, owned firewall
	// objects, generated DNSBL files, Unbound chroot module, and the dashboard widget.
	update_status(" Removing live firewall objects and generated files...");

	// Remove all pfB aliastables
	exec("{$pfb['pfctl']} -s Tables | {$pfb['grep']} '^pfB_'", $pfb_tables);
	if (isset($pfb_tables)) {
		foreach ($pfb_tables as $pfb_table) {
			pfb_pfctl_table_op($pfb_table, 'kill');
		}
	}

	// #738 F7: marker must not survive uninstall (see pfb_deinstall_clear_pending_changes()).
	pfb_deinstall_clear_pending_changes();

	// Remove aliastables archive (.zst + .bz2) and earlyshellcmd if found.
	@unlink_if_exists("{$pfb['aliasarchive']}.zst");
	@unlink_if_exists("{$pfb['aliasarchive']}.bz2");
	if (config_get_path('system/earlyshellcmd') !== null) {
		$a_earlyshellcmd = config_get_path('system/earlyshellcmd', '');
		if (preg_grep("/pfblockerng.sh aliastables/", $a_earlyshellcmd)) {
			config_set_path('system/earlyshellcmd',
							preg_grep("/pfblockerng.sh aliastables/", $a_earlyshellcmd, PREG_GREP_INVERT));
		}
	}
	foreach (config_get_path('installedpackages/shellcmdsettings/config', []) as $key => $shellcmd) {
		if (strpos($shellcmd['cmd'], 'pfblockerng.sh aliastables') !== FALSE) {
			config_del_path("installedpackages/shellcmdsettings/config/{$key}");
		}
	}

	// #468: Remove DNSBL cache archive (.zst + .bz2) + restore earlyshellcmd if found
	// (separate 'dnsbl_cache restore' string from the IP aliastables hook above).
	@unlink_if_exists("{$pfb['dnsblarchive']}.zst");
	@unlink_if_exists("{$pfb['dnsblarchive']}.bz2");
	if (config_get_path('system/earlyshellcmd') !== null) {
		$a_earlyshellcmd = config_get_path('system/earlyshellcmd', '');
		if (preg_grep("/pfblockerng.sh dnsbl_cache restore/", $a_earlyshellcmd)) {
			config_set_path('system/earlyshellcmd',
							preg_grep("/pfblockerng.sh dnsbl_cache restore/", $a_earlyshellcmd, PREG_GREP_INVERT));
		}
	}
	foreach (config_get_path('installedpackages/shellcmdsettings/config', []) as $key => $shellcmd) {
		if (strpos($shellcmd['cmd'], 'pfblockerng.sh dnsbl_cache restore') !== FALSE) {
			config_del_path("installedpackages/shellcmdsettings/config/{$key}");
		}
	}

	// Remove owned firewall objects (VIP, NAT, filter rules) BEFORE the config
	// reference data is wiped by pfb_remove_config_settings(). Catches orphans that
	// the normal disable teardown missed. Idempotent — no write when nothing found.
	$swept = FALSE;
	// Sweep all pfB_-owned VIPs, NAT rules, and filter rules.
	foreach (['virtualip/vip', 'nat/rule', 'filter/rule'] as $deinstall_section) {
		$deinstall_rows     = config_get_path($deinstall_section, []);
		$deinstall_filtered = [];
		$deinstall_removed  = FALSE;
		foreach ($deinstall_rows as $deinstall_row) {
			if (pfb_is_managed_obj($deinstall_row['descr'] ?? '')) {
				$deinstall_removed = TRUE;
			} else {
				$deinstall_filtered[] = $deinstall_row;
			}
		}
		if ($deinstall_removed) {
			config_set_path($deinstall_section, $deinstall_filtered);
			$swept = TRUE;
		}
	}
	// Also explicitly remove DNS-redirect NAT rules and DoT/DoQ block filter rules
	// by marker prefix (covers the inline-managed objects).
	if (pfb_remove_managed_obj('nat/rule', PFB_DNS_REDIR_DESCR_V4_PFX)) {
		$swept = TRUE;
	}
	if (pfb_remove_managed_obj('filter/rule', PFB_DOT_BLOCK_DESCR_PFX)) {
		$swept = TRUE;
	}

	if ($swept) {
		write_config('pfBlockerNG: sweep orphan firewall objects on deinstall');
	}

	unlink_if_exists("{$pfb['dnsbl_conf']}");
	unlink_if_exists("{$pfb['dnsbl_cert']}");
	// aliasarchive (zst + legacy bz2) already removed above (co-located with the aliastables boot-hook teardown).
	unlink_if_exists("{$pfb['dnsbl_info']}");
	unlink_if_exists("{$pfb['dnsbl_resolver']}");

	// The chrooted Unbound python integration nullfs-mounts host dirs into the chroot
	// (var/log/pfblockerng for the DNSBL logs, usr/local/share/GeoIP).  A disable goes
	// through pfb_unbound_include.inc, which unmounts them; an uninstall instead just
	// deletes that include (below) and only pfb_unbound_python_unmount()s bin/lib — so
	// these data mounts are left ORPHANED on every uninstall.  A keep=off uninstall then
	// rmdir's the host log source under the live mount, leaving it stale: chrooted
	// dnsbl.log writes fail "No such file or directory" for the rest of the session
	// (surfaced once #484 added the first live keep=off uninstall coverage).  Unmount
	// them here, before the include is removed, so every uninstall (keep on or off) tears
	// the chroot down as cleanly as a disable.  Bounded loop clears any stacked mounts.
	foreach (array('var/log/pfblockerng', 'usr/local/share/GeoIP') as $pfb_cmnt) {
		$pfb_cmnt_path = "{$g['unbound_chroot_path']}/{$pfb_cmnt}";
		for ($pfb_cmnt_i = 0; $pfb_cmnt_i < 8; $pfb_cmnt_i++) {
			if (empty(exec("/sbin/mount | {$pfb['grep']} " . escapeshellarg($pfb_cmnt_path) . " 2>&1"))) {
				break;
			}
			exec("/sbin/umount -t nullfs " . escapeshellarg($pfb_cmnt_path) . " 2>&1", $pfb_cmnt_out, $pfb_cmnt_rv);
			if ($pfb_cmnt_rv != 0) {
				break;
			}
		}
	}

	exec('/usr/local/pkg/pfblockerng/pfblockerng.sh dnsbl_cache teardown >/dev/null 2>&1');

	// Remove widget (code from Snort deinstall)
	$pfb['widgets'] = config_get_path('widgets/sequence', '');
	if (!empty($pfb['widgets'])) {
		$widgetlist = explode(',', $pfb['widgets']);
		foreach ($widgetlist as $key => $widget) {
			if (strpos($widget, 'pfblockerng') !== FALSE) {
				unset($widgetlist[$key]);
			}
		}
		config_set_path('widgets/sequence', implode(',', $widgetlist));
		write_config('pfBlockerNG: Remove widget', FALSE);
	}

	// Maintain pfBlockerNG settings and database files if $pfb['keep'] is ON.
	if ($pfb['keep'] !== PfbToggle::On) {
		update_status(" Removing all customizations/data...");
		// Remove pfBlockerNG log and DB folder
		rmdir_recursive("{$pfb['dbdir']}");
		rmdir_recursive("{$pfb['logdir']}");

		// ADR-38: remove the dedicated syslog-export log + its newsyslog rotations.
		// It lives at /var/log/pfblockerng_syslog.log (outside logdir), so it is not
		// covered by the rmdir above. Core removes the syslog.d routing drop-in on
		// uninstall; we own the log file itself.
		foreach (glob('/var/log/pfblockerng_syslog.log*') ?: array() as $pfb_syslogfile) {
			unlink_if_exists($pfb_syslogfile);
		}

		// Remove settings from config.xml
		pfb_remove_config_settings();
	}
	else {
		update_status(" All customizations/data will be retained...");
	}

	unlink_if_exists('/usr/local/sbin/lighttpd_pfb');
	unlink_if_exists('/usr/local/bin/php_pfb');
	unlink_if_exists('/usr/local/sbin/clog_pfb');
	unlink_if_exists('/usr/bin/tail_pfb');
	unlink_if_exists('/usr/local/etc/rc.d/pfb_filter.sh');
	unlink_if_exists('/usr/local/etc/rc.d/pfb_dnsbl.sh');

	foreach (array($pfb['dnsbl_cache'], "{$pfb['dnsbl_cache']}-wal", "{$pfb['dnsbl_cache']}-shm") as $legacy_cache) {
		unlink_if_exists($legacy_cache);
	}
	unlink_if_exists("/var/tmp/unbound_cache_*");
	unlink_if_exists("{$pfb['ip_cache']}");

	// Remove incorrect xml setting
	config_del_path('installedpackages/pfblockerngantartica');

	// Persist the config-section removals above. config_del_path()/pfb_remove_config_settings()
	// only mutate the in-memory config; without this final write the uninstall's section wipe
	// (keep=off) and the legacy-misspelled-section cleanup are lost on disk — the package
	// reads back as "still installed" in config.xml (#484 fan-out).
	write_config('pfBlockerNG: remove package config sections on deinstall');

	update_status(" done.\n");
}


// Remove settings from config.xml — deinstall wipe of whole pfBlockerNG sections.
function pfb_remove_config_settings() {
	global $pfb;

	// Sweep EVERY installedpackages/pfblockerng* section dynamically rather than a
	// hardcoded list. A fixed list silently leaves behind any section a later feature
	// adds — e.g. pfblockerngdnsbleasylist (ADR-07 ABP/EasyList), the wizard temp
	// section, or the misspelled legacy 'pfblockerngantartica' — so a keep=off
	// uninstall did not fully remove the package (#484 fan-out). Removing every
	// pfblockerng-prefixed section is exactly the keep=off "full removal" contract and
	// is future-proof.
	//
	// ADR-29 foreign-key exclusion: a deinstall wipes whole package sections
	// (dynamic per-row lists, blacklist, continent structures) — a section-level
	// operation, not a registered scalar-field access. Use config_del_path directly.
	foreach (array_keys(config_get_path('installedpackages', array())) as $type) {
		if (strpos((string) $type, 'pfblockerng') === 0) {
			config_del_path("installedpackages/{$type}");
		}
	}
}


/* Uses XMLRPC to synchronize the changes to a remote node */
function pfblockerng_sync_on_changes() {
	// Create array of sync settings and exit if sync is disabled.
	$pfb_sync = config_get_path('installedpackages/pfblockerngsync/config/0', []);
	if (!empty($pfb_sync)) {
		if ($pfb_sync['varsynconchanges'] == 'disabled' || empty($pfb_sync['varsynconchanges'])) {
			return;
		}
		$synctimeout = $pfb_sync['varsynctimeout'] ?: 150;
	} else {
		return;
	}

	pfb_logger("\n===[  XMLRPC Sync ]===================================================\n", 1);
	logger(LOG_NOTICE, localize_text('XMLRPC sync is starting.'), LOG_PREFIX_PKG_PFBLOCKERNG);

	if (config_get_path('installedpackages/pfblockerngsync/config') != null) {
		switch ($pfb_sync['varsynconchanges']) {
			case 'manual':
				if (isset($pfb_sync['row'])) {
					$rs = $pfb_sync['row'];
				} else {
					logger(LOG_WARNING, localize_text('Manual XMLRPC sync is enabled but there are no replication targets configured.'), LOG_PREFIX_PKG_PFBLOCKERNG);
					return;
				}
				break;
			default:
				return;
				break;
		}
		if (isset($rs)) {
			foreach ($rs as $sh) {
				// Only sync enabled replication targets
				if ($sh['varsyncdestinenable']) {
					$sync_to_ip	= $sh['varsyncipaddress'];
					$port		= $sh['varsyncport'];
					$password	= $sh['varsyncpassword'];
					$protocol	= $sh['varsyncprotocol'];
					$username	= $sh['varsyncusername'] ?: 'admin';

					// issue #1778: PFB_FILTER_HOSTNAME (pfblockerng_sync.php, #1731)
					// accepts and persists a Unicode (IDN) sync target, but the gate
					// below and the XMLRPC connection (pfblockerng_do_xmlrpc_sync())
					// are ASCII-only -- punycode-convert at the point of use so both
					// see a candidate they can validate/dial. Keep the original for
					// the human-facing log lines -- the operator sees the target as
					// configured, not its punycode form. A conversion failure leaves
					// $sync_to_ip unchanged, so the existing gate rejects it exactly
					// as before. An ASCII target (the common case) is untouched.
					$sync_to_ip_display = $sync_to_ip;
					if (preg_match('/[^\x00-\x7F]/', (string) $sync_to_ip)) {
						$sync_to_ip_ascii = idn_to_ascii((string) $sync_to_ip);
						if (!empty($sync_to_ip_ascii)) {
							$sync_to_ip = $sync_to_ip_ascii;
						}
					}

					$validate = TRUE;
					$error = '| ';

					if (empty($password)) {
						$error .= 'Password parameter missing. | ';
						$validate = FALSE;
					}
					if (!is_ipaddr($sync_to_ip) && !is_hostname($sync_to_ip) && !is_domain($sync_to_ip)) {
						$error .= 'Mis-configured Target IP/Host address. | ';
						$validate = FALSE;
					}
					if (!is_port($port)) {
						$error .= 'Mis-configured Target Port setting. |';
						$validate = FALSE;
					}

					if ($validate) {
						pfb_logger("\n Sync with [ {$protocol}://{$sync_to_ip_display}:{$port} ] ...", 1);
						$success = pfblockerng_do_xmlrpc_sync($sync_to_ip, $port, $protocol, $username, $password, $synctimeout);

						if ($success) {
							pfb_logger(" done.\n", 1);
							logger(LOG_NOTICE, localize_text("XMLRPC sync to [ %s ] completed successfully.", "{$sync_to_ip_display}:{$port}"), LOG_PREFIX_PKG_PFBLOCKERNG);
						} else {
							pfb_logger(" Failed!\n", 1);
						}
					} else {
						pfb_logger(" terminated due to the following error(s): {$error}", 1);
						logger(LOG_ERR, localize_text("XMLRPC sync to [ %s:%s ] terminated due to the following error(s): %s", $sync_to_ip_display, $port, $error), LOG_PREFIX_PKG_PFBLOCKERNG);
					}
				}
			}
		}
	}
	pfb_logger("\n======================================================================\n", 1);
}


/*
 * Bare 'installedpackages/*' section names synced between XMLRPC nodes.
 * $include_interfaces adds the General/IP/DNSBL "Tab Customizations"
 * sections ahead of the always-synced list.
 */
function pfblockerng_sync_sections($include_interfaces) {
	$sections = [];

	if ($include_interfaces) {
		$sections = array_merge($sections, [
			'pfblockerng',
			'pfblockerngipsettings',
			'pfblockerngdnsblsettings'
		]);
	}

	return array_merge($sections, [
		'pfblockernglistsv4',
		'pfblockernglistsv6',
		'pfblockerngreputation',
		'pfblockerngtopspammers',
		'pfblockerngafrica',
		'pfblockerngantarctica',
		'pfblockerngasia',
		'pfblockerngeurope',
		'pfblockerngnorthamerica',
		'pfblockerngoceania',
		'pfblockerngsouthamerica',
		'pfblockerngproxyandsatellite',
		'pfblockerngdnsbl',
		'pfblockerngblacklist',
		'pfblockerngglobal',
		'pfblockerngsafesearch'
	]);
}

/* Do the actual XMLRPC sync */
function pfblockerng_do_xmlrpc_sync($sync_to_ip, $port, $protocol, $username, $password, $synctimeout) {
	global $g;
	$success = TRUE;

	// Take care of IPv6 literal address
	if (is_ipaddrv6($sync_to_ip)) {
		$sync_to_ip = "[{$sync_to_ip}]";
	}

	// If User Disabled, remove 'General/IP/DNSBL Tab Customizations' from Sync.
	// issue #2123: read through the gateway, so the registered default and the
	// case-insensitive toggle vocabulary apply here as on the Sync page.
	$sections = pfblockerng_sync_sections(PfbConfig::read('sync/syncinterfaces') !== PfbToggle::On);

	/* xml will hold the sections to sync */
	$xml = array();

	foreach ($sections as $section) {
		$section_config = config_get_path("installedpackages/{$section}");
		if (!isset($section_config)) {
			continue;
		}
		$xml[$section] = $section_config;
	}

	require_once('xmlrpc_client.inc');

	// xmlrpc cannot encode NULL objects/arrays
	foreach ($xml as $xmlkey => $xmlvalue) {
		if (gettype($xmlvalue) == 'NULL') {
			$xml[$xmlkey] = array();
		}
	}

	$synctimeout = intval($synctimeout);
	$rpc_client = new pfsense_xmlrpc_client();
	$rpc_client->setConnectionData($sync_to_ip, $port, $username, $password, $protocol);
	$resp = $rpc_client->xmlrpc_method('merge_installedpackages_section', $xml, $synctimeout);

	if (!isset($resp)) {
		return FALSE;
	} else {
		return TRUE;
	}
}

function pfblockerng_plugin_xmlrpc_send() {
	if (config_get_path('installedpackages/pfblockerngsync/config/0/varsynconchanges') != 'auto') {
		return [];
	}

	$section_paths_temp = [
		'installedpackages/pfblockerngsync/config/0/varsynconchanges'
	];
	// If User Disabled, remove 'General/IP/DNSBL Tab Customizations' from Sync (#2123).
	$sections = pfblockerng_sync_sections(PfbConfig::read('sync/syncinterfaces') !== PfbToggle::On);
	foreach ($sections as $section) {
		$section_paths_temp[] = "installedpackages/{$section}";
	}

	$section_paths = [];
	foreach ($section_paths_temp as $path) {
		$section_config = config_get_path($path);
		if (!isset($section_config)) {
			continue;
		}
		$section_paths[] = $path;
	}

	return $section_paths;
}

function pfblockerng_plugin_xmlrpc_recv($new_sections) {
	if (array_get_path($new_sections, 'installedpackages/pfblockerngsync/config/0/varsynconchanges') != 'auto') {
		return [];
	}

	$section_paths = [];
	foreach (pfblockerng_sync_sections(TRUE) as $section) {
		$section_paths[] = "installedpackages/{$section}";
	}

	$ret = [
		'xmlrpc_recv_result' => FALSE
	];
	foreach ($section_paths as $path) {
		$old_section = config_get_path($path, []);
		$new_section = array_get_path($new_sections, $path, []);

		// Don't save empty configuration sections.
		if (empty($old_section) && empty($new_section)) {
			continue;
		}
		// Ignore unchanged configuration sections.
		if ($old_section === $new_section) {
			continue;
		}

		$ret[$path] = array_merge($old_section, $new_section);
		$ret['xmlrpc_recv_result'] = TRUE;
	}

	return $ret;
}

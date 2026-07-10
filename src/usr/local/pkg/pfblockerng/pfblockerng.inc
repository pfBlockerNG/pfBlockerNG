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

// Folders
$pfb['dbdir']		= "{$g['vardb_path']}/pfblockerng";
$pfb['aliasdir']	= "{$g['vardb_path']}/aliastables";
$pfb['logdir']		= "{$g['varlog_path']}/pfblockerng";
$pfb['etdir']		= "{$pfb['dbdir']}/ET";
$pfb['nativedir']	= "{$pfb['dbdir']}/native";
$pfb['denydir']		= "{$pfb['dbdir']}/deny";
$pfb['matchdir']	= "{$pfb['dbdir']}/match";
$pfb['permitdir']	= "{$pfb['dbdir']}/permit";
$pfb['origdir']		= "{$pfb['dbdir']}/original";
$pfb['snapdir']		= "{$pfb['dbdir']}/snapshot";	// issue #1084: pristine post-preprocessing feed snapshots (recompute memberlist inputs)
$pfb['dnsdir']		= "{$pfb['dbdir']}/dnsbl";
$pfb['dnsorigdir']	= "{$pfb['dbdir']}/dnsblorig";
$pfb['dnsalias']	= "{$pfb['dbdir']}/dnsblalias";
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
$pfb['pfctl']	= '/sbin/pfctl';
$pfb['wc']	= '/usr/bin/wc';

// Folder Array
$pfb['folder_array'] = array(	"{$pfb['dbdir']}", "{$pfb['logdir']}", "{$pfb['ccdir']}", "{$pfb['origdir']}", "{$pfb['nativedir']}",
				"{$pfb['denydir']}", "{$pfb['matchdir']}","{$pfb['permitdir']}", "{$pfb['aliasdir']}",
				"{$pfb['dnsdir']}", "{$pfb['dnsorigdir']}", "{$pfb['dnsalias']}", "{$pfb['snapdir']}");

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

$pfb['dnsbl_tld_txt']	= "{$pfb['dnsdir']}/DNSBL_TLD.txt";
$pfb['dnsbl_tld_data']	= '/usr/local/pkg/pfblockerng/dnsbl_tld';
$pfb['dnsbl_conf']	= '/var/unbound/pfb_dnsbl_lighty.conf';
$pfb['dnsbl_cert']	= '/var/unbound/dnsbl_cert.pem';
$pfb['unbound_py_conf']	= '/var/unbound/pfb_unbound.ini';
$pfb['unbound_py_wh']	= '/var/unbound/pfb_py_whitelist.txt';
$pfb['unbound_py_data']	= '/var/unbound/pfb_py_data.txt';
$pfb['unbound_py_zone'] = '/var/unbound/pfb_py_zone.txt';
$pfb['unbound_py_ss']	= '/var/unbound/pfb_py_ss.txt';
$pfb['unbound_py_hsts']	= '/var/unbound/pfb_py_hsts.txt';	// SHIPPED file re-staged by dnsbl_cache_stage() cp -f; fingerprinted so a package update ships a new list and triggers a zero-downtime reload
$pfb['unbound_py_count']= '/var/unbound/pfb_py_count';
$pfb['unbound_py_regex_count']= '/var/unbound/pfb_py_regex_count';	// ADR-07: Python-emitted ADMITTED (cap-filtered) feed+user regex total for the DNSBL_Regex alias
$pfb['unbound_py_reject_stats']= '/var/unbound/pfb_py_reject_stats.json';	// ADR-48: Python-emitted per-entry reject tally (issue #789), read by pfb_emit_entry_reject_stats()
$pfb['unbound_py_sources']= '/var/unbound/pfb_py_sources.json';	// ADR-06: per-feed manifest consumed by pfb_unbound.py init
$pfb['unbound_py_rawdir']= '/var/unbound/pfb_py_raw';		// ADR-06: per-feed IP-stripped raw feeds referenced by the manifest

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
				CURLOPT_ENCODING	=> 'gzip',	// Request 'gzip' response encoding when the server offers it
				// Constrain libcurl to the schemes pfBlockerNG fetches feeds over (http/https/ftp;
				// rsync uses exec separately) — an independent backstop to the PFB_FILTER_URL scheme
				// allowlist, since PHP parse_url and libcurl can disagree on crafted input.
				CURLOPT_PROTOCOLS	=> CURLPROTO_HTTP | CURLPROTO_HTTPS | CURLPROTO_FTP,
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
					'application/x-tar',
					'application/gzip',
					'application/x-gzip',
					'application/x-bzip2',
					'application/zip',
					// ADR-45: first-class 7-Zip feeds. The pfb_download() 7z branch
					// extracts via /usr/local/bin/7z; the ADR-45 structural probe
					// (pfb_validate_archive '7z t') guards it, so a box without the
					// 7-Zip binary cleanly rejects rather than failing mid-extract.
					'application/x-7z-compressed'));

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

// Normalise the user-supplied 'Force Reload' option to one of its only
// legitimate values — 'All', 'IP', 'DNSBL' — returning 'All' for any absent,
// non-string, or unexpected input. Used to validate $_POST['pfb_reload_option']
// at the pfblockerng_update.php input boundary before it reaches the status
// display, the reload-type switch, or the log line. Exact-match only.
function pfb_reload_option_value($value) {
	if (is_string($value) && in_array($value, array('All', 'IP', 'DNSBL'), TRUE)) {
		return $value;
	}
	return 'All';
}

// Entry count for a pfBlockerNG alias file, excluding the '1.1.1.1' placeholder
// (used for an empty alias). $grep_lines is the output array of
// `grep -cv '^1.1.1.1$' <file>` — a single line holding the count in element 0.
// Returns 0 when the output is missing or non-numeric.
function pfb_alias_entry_count(array $grep_lines): int {
	return is_numeric($grep_lines[0] ?? NULL) ? (int) $grep_lines[0] : 0;
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
function pfb_archive_probe(string $canonical_type): ?array {
	switch ($canonical_type) {
		case 'application/zip':
			return array('/usr/bin/tar', '-tf');
		case 'application/gzip':
		case 'application/x-gzip':
			return array('/usr/bin/gunzip', '-t');
		case 'application/x-bzip2':
			return array('/usr/bin/bzip2', '-t');
		case 'application/x-7z-compressed':
			return array('/usr/local/bin/7z', 't');
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

// ADR-45: which structural-probe extractor a feed type needs WHEN that extractor is
// missing — returns the binary path, else NULL (tool present, or non-archive type).
// Lets pfb_download() emit a clear "install <tool>" message instead of a misleading
// "corrupt archive" when an OPTIONAL extractor is absent. In practice only 7-Zip is
// optional (/usr/local/bin/7z is an add-on package); gunzip/bzip2/tar are FreeBSD base
// and always present. $checker is injectable (defaults to is_executable) for unit tests.
function pfb_archive_missing_tool(string $canonical_type, ?callable $checker = NULL): ?string {
	$argv = pfb_archive_probe($canonical_type);
	if ($argv === NULL) {
		return NULL;        // non-archive: no extractor needed
	}
	if ($checker === NULL) {
		$checker = 'is_executable';
	}
	return $checker($argv[0]) ? NULL : $argv[0];
}

// ADR-48: pure formatter for the canonical download-validation reject line — a single
// greppable line naming feed/stage/reason + raw detected detail. $stage is one of
// mime|structural|inner|member|plaintext|entries (caller-owned vocabulary, unvalidated here).
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

// ADR-46: list an archive's member names via bsdtar. stderr goes to /dev/null so a
// bsdtar diagnostic (e.g. "tar: Failed to set default locale") can NEVER be mistaken
// for a member name -- merging streams and prefix-filtering would let a member
// literally named "tar: ../x" be silently dropped, bypassing the guard. Returns NULL
// on a listing failure (rc != 0) so every DISK-writing caller fails CLOSED: the
// gzip/UT1 sites' ADR-45 probe is only `gunzip -t` (gzip-stream integrity, not the
// inner tar), so a valid-gzip / corrupt-inner-tar archive lists rc != 0 here and must
// be rejected, not fail-open extracted. A genuinely intact archive always lists rc 0,
// so this rejects nothing legitimate.
function pfb_archive_member_names(string $file): ?array {
	$output = array();
	$retval = 1;
	exec('/usr/bin/tar -tf ' . escapeshellarg($file) . ' 2>/dev/null', $output, $retval);
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
// and #753 wire-cap rejects, bucketed shape/wire_cap, per feed/group) and emits
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
		foreach (array('shape', 'wire_cap') as $bucket) {
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

	// issue #1070: every non-FILE_MIME type runs scalar string ops below (htmlspecialchars/
	// preg_match) that PHP 8 TypeErrors on an array -- reject an array up front, before any
	// such op runs, for those types. issue #1139: must run before the control-char loop
	// below, which itself TypeErrors on a nested (non-scalar) array element.
	if (is_array($input) && !in_array($type, array(PFB_FILTER_FILE_MIME_COMPARE, PFB_FILTER_FILE_MIME, PFB_FILTER_FILE_MIME_COMPRESSED))) {
		return $return_type;
	}

	// Check for control characters. The /u modifier is required: without it, \p{C}
	// classifies each raw BYTE as a Latin-1 codepoint, so a valid multibyte UTF-8
	// character (e.g. "€", "日") whose continuation byte falls in 0x80-0x9F is
	// falsely rejected while other non-ASCII bytes pass through unexamined -- and a
	// genuinely invalid-UTF-8 subject is silently accepted. With /u, preg_match()
	// returns FALSE (not 0) on invalid UTF-8, so the check must reject on `!== 0`
	// to fail closed (this is a PFBL-01 input-sanitisation gate) rather than open.
	// The reject above already returned for every non-FILE_MIME type, so this array
	// branch only ever sees FILE_MIME's flat literal-string arrays (ADR-48).
	if (is_array($input)) {
		foreach ($input as $vline) {
			if (preg_match("/[\p{C}]+/u", $vline) !== 0) {
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
		if (preg_match("/[\p{C}]+/u", $input) !== 0) {
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
			// Validate TLD
			if (preg_match("/^[a-zA-Z0-9_\.\-]+$/", $input)) {
				$result = htmlspecialchars($input);
			}
			break;
		case PFB_FILTER_DOMAIN:
			// Validate domain
			if ((strpos($input, '.') !== FALSE) &&			// Exclude no dots
			    (strpos($input, '..') === FALSE) &&			// Exclude double dot
			    (strlen($input) < 255) &&				// Validate length of domain (Max 255 chars)
			    (pfb_validate_domain_labels($input) !== FALSE) &&	// Validate length of labels (Max of 63 chars)
			    (preg_match("/^[a-zA-Z0-9_\.\-]+$/", $input))) {  	// Exclude any other characters
				$result = TRUE;
			}
			if ($result) {
				$result = htmlspecialchars($input);
			}
			break;
		case PFB_FILTER_HOSTNAME:
			// Validate hostname
			if (is_hostname($input)) {
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
							array('application/zip', 'application/gzip', 'application/x-bzip2', 'application/x-7z-compressed'),
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

		// Exceptions -- callers whose rejected input must never be logged, even at
		// debug level: 'DNSBL_Download' (parsed feed lines -- volume); 'top1m_token'
		// (ADR-59 -- the secret itself, not merely its download URL); 'maxmind_key'
		// (issue #924 -- same masked/write-only treatment for the MaxMind license key).
		if (in_array($reference, array('DNSBL_Download', 'top1m_token', 'maxmind_key'))) {
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
   including them makes every pass look changed) and unbound_py_ss (has its own
   md5 gate via $safesearch_update; double-gating would suppress SafeSearch restarts).
   Pure (no global access): caller passes $pfb explicitly so tests can inject any paths. */
function pfb_dnsbl_loaded_input_paths(array $pfb): array {
	$raw_files = glob("{$pfb['unbound_py_rawdir']}/*.raw") ?: array();
	sort($raw_files, SORT_STRING);
	return array_merge(
		array($pfb['unbound_py_data'], $pfb['unbound_py_zone'], $pfb['unbound_py_wh'], $pfb['unbound_py_sources'], $pfb['unbound_py_hsts']),
		$raw_files
	);
}

/* TRUE iff genuine FEED-derived DNSBL content is currently loaded — i.e. a non-empty
   pfb_py_data, an existing pfb_py_zone, or at least one per-feed *.raw file. Deliberately
   EXCLUDES the shipped pfb_py_hsts and the always-present manifest/whitelist, which are NOT
   feed-derived: counting them makes a no-feed setup look "loaded" and triggers a clear+reload
   every cron pass (#546). Pure (no global access). */
function pfb_dnsbl_has_loaded_feeds(array $pfb): bool {
	if (is_file($pfb['unbound_py_data']) && filesize($pfb['unbound_py_data']) > 0) {
		return TRUE;
	}
	if (is_file($pfb['unbound_py_zone'])) {
		return TRUE;
	}
	if (!empty(glob("{$pfb['unbound_py_rawdir']}/*.raw") ?: array())) {
		return TRUE;
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

	$auto      = ($pfb['dnsbl_vip_auto'] ?? '') == 'on';
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

	$pfb['enable']		= PfbConfig::read('enable_cb')->value;		// Enable/Disable of pfBlockerNG
	$pfb['keep']		= PfbConfig::read('pfb_keep')->value;		// Keep blocklists on pfBlockerNG Disable (default ON via registry; #281)
	$pfb['interval']	= PfbConfig::read('pfb_interval')	?: '1';	// Hour cycle for scheduler

	// ADR-11: opt-in per-type aggregate ("Uber") aliases. CSV scalar of the action types
	// to aggregate (subset of Deny/Permit/Match/Native), default NONE -> [] -> no-op pass.
	// CSV (a single string, like blacklist_selected) so it round-trips with no '<0>' list XML.
	$pfb['agg_types']	= array_values(array_intersect(
					array('Deny', 'Permit', 'Match', 'Native'),
					array_filter(explode(',', PfbConfig::read('pfb_agg_types')))));

	// Validate Cron settings
	if (!is_numeric($pfb['interval'])) {
		$pfb['interval'] = '1';
	}
        foreach (array( 'pfb_min'		=> 'min',			// User defined CRON start minute
			'pfb_hour'		=> 'hour',			// Start hour of the scheduler
			'pfb_dailystart'	=> '24hour'			// Start hour of the 'Once a day' schedule
		) as $conf_value => $pfb_value) {

		$pfb_variable = $pfb['config'][$conf_value] ?: '0';
		if (!is_numeric($pfb_variable)) {
			$pfb[$pfb_value] = '0';
		} else {
			$pfb[$pfb_value] = $pfb_variable;
		}
	}

	$pfb['supp']		= $pfb['ipconfig']['suppression'];			// Enable Suppression
	$pfb['cc']		= $pfb['ipconfig']['database_cc'];			// Disable Country database CRON updates
	$pfb['maxmind_locale']	= $pfb['ipconfig']['maxmind_locale']	?: 'en';	// MaxMind Localized Language setting
	$pfb['asn_reporting']	= $pfb['ipconfig']['asn_reporting']	?: 'disabled';	// ASN Reporting
	$pfb['asn_token']	= $pfb['ipconfig']['asn_token']		?: '';		// ASN Token (IPinfo)
	$pfb['rdns']		= pfb_resolve_enabled($pfb['ipconfig']);			// Reverse-DNS lookup for block-log entries (issue #336)

	$pfb['maxmind_account']	= pfb_filter($pfb['ipconfig']['maxmind_account'], PFB_FILTER_WORD, 'pfb_global')	?: '';		// Maxmind Account ID
	$pfb['maxmind_key']	= pfb_filter($pfb['ipconfig']['maxmind_key'], PFB_FILTER_WORD, 'maxmind_key')		?: '';		// Maxmind License Key (issue #924: log-safe reference -- a rejected key is never logged on this consumer path either)

	$pfb['dnsbl']		= PfbConfig::read('pfb_dnsbl')->value;							// Enabled state of DNSBL
	$pfb['dnsbl_vip_auto']	= PfbConfig::read('pfb_dnsvip_auto')->value;						// [ ADR-13 ] Auto-create/remove the DNSBL sinkhole VIP(s) (default off)
	$pfb['dnsbl_nonat']	= PfbConfig::read('pfb_dnsbl_nonat')->value;						// [ #381 ] Opt out of automatic DNSBL NAT rule generation (default off)
	$pfb['dnsbl_vip4'] = get_configured_vip_ipv4($pfb['dnsblconfig']['pfb_dnsvip4']) ?? '';
	$pfb['dnsbl_vip6'] = get_configured_vip_ipv6($pfb['dnsblconfig']['pfb_dnsvip6']) ?? '';
	$pfb['dnsbl_iface']	= PfbConfig::read('dnsbl_interface');							// VIP Local Interface setting (default 'lo0')
	if (!empty($pfb['dnsbl'])) {
		// VIP validation: force-disable DNSBL on a genuinely invalid/missing/overlapping
		// VIP — UNLESS auto-create mode is active, in which case pfb_manage_dnsbl_vip()
		// owns provisioning and will (re)create a valid VIP during this same update pass.
		// Disabling DNSBL here in auto mode would prevent the bootstrap from ever running.
		$vips_valid_result = pfb_validate_vips($pfb['dnsbl_iface'], $pfb['dnsblconfig']['pfb_dnsvip4'], $pfb['dnsblconfig']['pfb_dnsvip6']);
		if (!$vips_valid_result[0]) {
			if ($pfb['dnsbl_vip_auto'] === 'on') {
				// [ ADR-13 / issue #487 ] Auto-create OWNS the DNSBL sinkhole VIP:
				// pfb_manage_dnsbl_vip() (re)provisions a valid VIP on the configured
				// interface during this same update pass. A stale / missing / wrong-interface
				// manual reference must NOT force-disable DNSBL here, or the auto bootstrap
				// can never run (mode would compute to 'disabled' and creation would be skipped).
				pfb_logger("\nDNSBL auto-VIP: VIP validation deferred to auto-create ({$vips_valid_result[1]})", 1);
			} else {
				// Manual mode: a genuinely invalid/missing/mismatched VIP disables DNSBL.
				$pfb['dnsbl'] = '';
				$vip_notice = "DNSBL disabled: {$vips_valid_result[1]}";
				pfb_logger("\n{$vip_notice}", 1);
				// issue #331: this was log-only, invisible in the GUI. Surface it like
				// the MaxMind/ASN credential notices below.
				file_notice('pfBlockerNG DNSBL', $vip_notice, 'pfBlockerNG', '/pfblockerng/pfblockerng_dnsbl.php', 2);
			}
		} elseif (pfb_dnsbl_v6_vip_required(pfb_unbound_listens_v6(), ($pfb['dnsbl_vip_auto'] === 'on')) && empty($pfb['dnsblconfig']['pfb_dnsvip6'])) {
			// [ ADR-13 §7 pivot ] NON-BLOCKING: the resolver listens on IPv6 but no v6
			// sinkhole VIP is configured (manual mode). DNSBL stays enabled on IPv4;
			// AAAA blocks simply are not sinkholed. Recommend auto-create or a v6 VIP.
			// (In auto mode pfb_manage_dnsbl_vip provisions the v6 VIP, so this never fires.)
			pfb_logger("\nDNSBL: the DNS Resolver listens on IPv6 but no IPv6 sinkhole VIP is configured; AAAA blocks will not be sinkholed. Enable 'Create VIPs automatically' or add an IPv6 VIP.", 1);
		}
	}

	$pfb['dnsbl_port']	= $pfb['dnsblconfig']['pfb_dnsport'];									// Lighttpd web server http port setting
	$pfb['dnsbl_port_ssl']	= $pfb['dnsblconfig']['pfb_dnsport_ssl'];								// Lighttpd web server https port setting
	$pfb['dnsbl_top1m']	= $pfb['dnsblconfig']['alexa_enable'];							// TOP1M whitelist
	$pfb['dnsbl_top1m_type']	= PfbConfig::read('alexa_type');						// TOP1M type (PfbTop1mSource enum; legacy 'alexa' coalesces to Tranco, #877) (default Tranco)
	$pfb['dnsbl_res_cache']	= $pfb['dnsblconfig']['pfb_cache'];							// DNSBL Option to backup/restore Resolver cache
	$pfb['dnsbl_global_log']= PfbConfig::read('global_log');							// Global Logging/Blocking mode (default '')
	// ADR-22: lenient feed parsing. 'on' = permissive scheme strip (today); anything else =
	// strict RFC 3986 scheme validation + URL-path rejection. New installs default OFF
	// (strict); existing installs are migrated to 'on' on upgrade (pfb_dnsbl_lenient_migrate).
	$pfb['dnsbl_lenient']	= PfbConfig::read('pfb_dnsbl_lenient');							// DNSBL scheme-parsing leniency (PfbLenient enum)

	$pfb['dnsbl_py_reply']	= $pfb['dnsblconfig']['pfb_py_reply'];			// DNSBL Resolver python DNS Reply logging
	$pfb['dnsbl_hsts']	= PfbConfig::read('pfb_hsts')->value;			// DNSBL Resolver python block HSTS via Null Blocking mode
	// ADR-08: IDN mode selector. PfbConfig::read() returns a PfbIdnMode enum via the
	// registry adapter: 'on' -> All (preserves block-all-IDN on upgrade); 'confusable'
	// -> Confusable; '' / 'off' / absent / the dropped 4.0.0-alpha 'all' -> Off. Downstream
	// consumers compare against the enum; the ini build serialises the canonical token.
	$pfb['dnsbl_idn']	= PfbConfig::read('pfb_idn');				// DNSBL Resolver python IDN mode (PfbIdnMode enum)
	$pfb['dnsbl_idn_block_malicious']	= PfbConfig::read('pfb_idn_block_malicious');		// Confusable: block malicious homoglyphs (default 'on')
	$pfb['dnsbl_idn_escalate_suspicious']	= PfbConfig::read('pfb_idn_escalate_suspicious');	// Confusable: escalate suspicious mixed-script to block (opt-in)
	$pfb['dnsbl_regex']	= $pfb['dnsblconfig']['pfb_regex'];			// DNSBL Resolver python regex
	$pfb['dnsbl_regex_list']= $pfb['dnsblconfig']['pfb_regex_list'];		// DNSBL Resolver python regex list
	$pfb['dnsbl_regex_cap']	= PfbConfig::read('pfb_regex_cap');			// DNSBL Resolver python opt-in "Limit long/complex regex" static cap
	$pfb['dnsbl_cname']	= $pfb['dnsblconfig']['pfb_cname'];			// DNSBL Resolver python CNAME Validation
	$pfb['dnsbl_pytld']	= $pfb['dnsblconfig']['pfb_pytld'];			// DNSBL Resolver python TLD Allow option
	$pfb['dnsbl_py_nolog']	= $pfb['dnsblconfig']['pfb_py_nolog'];			// DNSBL Resolver python - Log events via DNSBL Webserver vs python
	$pfb['dnsbl_noaaaa']	= $pfb['dnsblconfig']['pfb_noaaaa'];			// DNSBL Resolver python no AAAA
	$pfb['dnsbl_noaaaa_list']=$pfb['dnsblconfig']['pfb_noaaaa_list'];		// DNSBL Resolver python no AAAA list

	$pfb['dnsbl_gp']		= $pfb['dnsblconfig']['pfb_gp'];		// DNSBL Resolver python - DNSBL Bypass
	$pfb['dnsbl_gp_bypass_list']	= $pfb['dnsblconfig']['pfb_gp_bypass_list'];	// DNSBL Resolver python - List of Local IPs to bypass DNSBL

	// SafeSearch — read via gateway (ADR-29).
	$pfb['safesearch_enable']	= PfbConfig::read('safesearch_enable');
	$pfb['safesearch_youtube']	= PfbConfig::read('safesearch_youtube');
	$pfb['safesearch_doh']		= PfbConfig::read('safesearch_doh');
	$pfb['safesearch_doh_list']	= array_values(array_filter(array_map('trim', explode(',', PfbConfig::read('safesearch_doh_list'))), 'strlen'));

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
		$pfb['unbound_state'] = 'on';
	} else {
		$pfb['unbound_state'] = '';
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
		$pfb['enable'] = $pfb['dnsbl'] = '';
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


// Function to decode alias custom entry box.
// Default (False, True): Return as string with comments
function pfbng_text_area_decode($text, $mode=FALSE, $type=TRUE, $idn=FALSE) {

	if ($mode) {
		$custom = array();
	} else {
		$custom = '';	// string accumulator; '' (not undef) when no lines match
	}

	$customlist = explode("\r\n", base64_decode($text));
	if (!empty($customlist)) {
		foreach ($customlist as $line) {
			if (!str_starts_with(trim($line), '#') && !empty($line)) {
				if ($idn && !ctype_print($line)) {
					$line_old = $line;
					// Convert encodings to UTF-8
					$line = mb_convert_encoding($line, 'UTF-8',
						mb_detect_encoding($line, 'UTF-8, ASCII, ISO-8859-1'));
					if (strpos($line, '#') !== FALSE) {
						$tmpline = preg_split('/(?=#)/', $line);
						if (str_starts_with($tmpline[0], '.')) {
							// idn_to_ascii() returns empty string if it starts with '.' 
							$tmpline[0] = idn_to_ascii(ltrim($tmpline[0], '.'));
							if (!empty($tmpline[0])) {
								$tmpline[0] = '.' . $tmpline[0];
							}
						} elseif (is_string($tmpline[0]) && (strlen($tmpline[0]) > 0)) {
							$tmpline[0] = idn_to_ascii($tmpline[0]);
						}
						if (empty($tmpline[0])) {
							$log = "\nError converting IDN line '{$line_old}'\n";
							pfb_logger($log, 2);
							continue;
						}
						$line = implode(' ', $tmpline);
					} else {
						if (str_starts_with($line, '.')) {
							$line = idn_to_ascii(ltrim($line, '.'));
							if (!empty($line)) {
								$line = '.' . $line;
							}
						} elseif (is_string($line) && (strlen($line) > 0)) {
							$line = idn_to_ascii($line);
						}
						if (empty($line)) {
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

// ADR-60 S2.1: where a log type's Y-m-d H:i:s timestamp lives in a line -- a
// leading line-prefix for the free-text logs, else a fixed CSV field (verified
// per writer: pfb_logger()/pfb_daemon_filterlog()/pfb_parsed_fail()/dnsbl.log's
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

// issue #1052: probe-before-copy for the 'nolimit'+age-cap path -- log lines are
// chronologically appended, so an unexpired FIRST line means nothing in $path can
// be expired; the caller skips its whole copy()+age-trim pass this tick. An
// unparseable/legacy first line falls through to TRUE (pass must run), matching
// pfb_log_age_cutoff()'s own "unparseable = expired" rule.
function pfb_log_age_nolimit_pass_needed(string $path, int $agedays, string $logtype): bool {
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

	return $ts < (time() - ($agedays * 86400));
}

// Manage log files line limit + age-based retention (ADR-60)
function pfb_log_mgmt() {
	global $g, $pfb;
	pfb_global();

	$chroot_folder = '/var/unbound';

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
					// issue #1052: 'nolimit'+age-cap -- skip the whole copy()+age-trim
					// pass this tick when the first (oldest) line hasn't expired yet.
					if ($logmax === 'nolimit' && !pfb_log_age_nolimit_pass_needed($final_log_file, $agedays, $logtype)) {
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
				// issue #1052: same nolimit+age-cap skip as the chroot branch above.
				if ($logmax === 'nolimit' && !pfb_log_age_nolimit_pass_needed($pfb[$logtype], $agedays, $logtype)) {
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
			if (!$g['pfblockerng_install'] && !$pfb['extras_update']) {
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
 * 'disable'); NULL for anything else. Drives the persist-on-'disable' write and the
 * auto-launch suppression.
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
 * Channel a build is on, from its installed package NAME:
 *   pfSense-pkg-pfBlockerNG         -> 'stable'
 *   pfSense-pkg-pfBlockerNG-devel   -> 'devel'
 *   pfSense-pkg-pfBlockerNG-NIGHTLY -> 'nightly' (ADR-18)
 * Anything unrecognised/empty -> NULL. The installed name is authoritative for "what
 * channel am I on" (ADR-19 §2 channel detection). Suffix match is case-insensitive so
 * the NIGHTLY/devel spellings are tolerant.
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
			return 'stable';
		case '-devel':
			return 'devel';
		case '-nightly':
			return 'nightly';
		default:
			return null;
	}
}

/*
 * The pkg repo "read latest" maps to, for a given channel (2026-06-14 + 2026-06-15
 * amendments): stable AND devel share ONE repo 'pfblockerng' (the channel selects the
 * package, not a per-channel repo); 'nightly' is the sole separately-channelled build,
 * repo 'pfblockerng-nightly'. An unrecognised channel -> NULL (no repo to read from).
 */
function pfb_pkg_repo_name_for_channel(?string $channel): ?string {
	switch ($channel) {
		case 'stable':
		case 'devel':
			return 'pfblockerng';
		case 'nightly':
			return 'pfblockerng-nightly';
		default:
			return null;
	}
}

/*
 * Provenance gate (2026-06-15 amendment): TRUE only when the build was installed FROM
 * one of OUR repos — 'pfblockerng' (stable+devel) or 'pfblockerng-nightly'. The repo is
 * read from `pkg query '%R' <pkgname>`. A Netgate-installed add-on (repo 'pfSense'),
 * an empty/'unknown' origin, or anything else -> FALSE: the Software tab, the page, the
 * priv match[] line, AND the cron notice all gate on this so a stock build shows none of
 * them.
 */
function pfb_software_is_our_build(?string $installed_repo): bool {
	return in_array($installed_repo, array('pfblockerng', 'pfblockerng-nightly'), TRUE);
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
 * ENABLED: an our-repo install checks for and notifies of new versions out of the box. Only
 * an explicit 'off' (the user un-ticking the box, persisted by the Software page) disables it;
 * an unset value (never saved) or 'on' reads as enabled.
 */
function pfb_software_check_enabled(?string $raw): bool {
	return $raw !== 'off';
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
 * target — this is the binary pfSense itself and our add-repo.sh/build-repo.sh shell to.
 * The base /usr/sbin/pkg bootstrap stub does NOT report the repository origin ('%R') the
 * same way, so the provenance gate read FALSE on a genuine our-repo install when it was
 * used; the port binary returns the recorded repo name ('pfblockerng').
 */
define('PFB_PKG_BIN', '/usr/local/sbin/pkg');

/*
 * The installed pfBlockerNG package NAME (e.g. 'pfSense-pkg-pfBlockerNG-devel'), read
 * from `pkg query '%n'` filtered to our prefix; '' when not installed via pkg or the
 * query fails. Feeds pfb_channel_from_pkgname().
 */
function pfb_pkg_installed_name(): string {
	$out = array();
	$ret = -1;
	// -g: match the trailing '*' as a glob. pkg query treats the pattern as an EXACT
	// pkg-name without it, so 'pfSense-pkg-pfBlockerNG*' would match nothing and the
	// provenance gate would wrongly read the package as not-our-build on every install.
	exec(escapeshellarg(PFB_PKG_BIN) . " query -g '%n' " . escapeshellarg('pfSense-pkg-pfBlockerNG*') . ' 2>/dev/null', $out, $ret);
	if ($ret !== 0) {
		return '';
	}
	foreach ($out as $line) {
		$line = trim($line);
		if (pfb_channel_from_pkgname($line) !== null) {
			return $line;
		}
	}
	return '';
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
	exec(escapeshellarg(PFB_PKG_BIN) . " query '%v' " . escapeshellarg($pkgname) . ' 2>/dev/null', $out, $ret);
	return ($ret === 0 && isset($out[0])) ? trim($out[0]) : '';
}

/*
 * The repo $pkgname was installed FROM via `pkg query '%R'` (the provenance signal the
 * 2026-06-15 gate keys on); '' when absent/failed. Fed to pfb_software_is_our_build().
 */
function pfb_pkg_installed_repo(string $pkgname): string {
	if ($pkgname === '') {
		return '';
	}
	$out = array();
	$ret = -1;
	exec(escapeshellarg(PFB_PKG_BIN) . " query '%R' " . escapeshellarg($pkgname) . ' 2>/dev/null', $out, $ret);
	return ($ret === 0 && isset($out[0])) ? trim($out[0]) : '';
}

/*
 * The pfBlockerNG repo's latest version of $pkgname: `pkg update -r <repo>` (best-effort refresh of
 * just that repo's catalog DB) then `pkg rquery -r <repo> '%v' <pkgname>`. Reads ONLY that repo
 * ($reponame) — never -r pfSense / get_pkg_info (ADR-19 §2 "Read latest"). Returns ''
 * (the caller then serves cache) when:
 *   - $pkgname/$reponame is empty;
 *   - the pkg subsystem is locked (is_subsystem_dirty('pkg')) — never fight a base update;
 *   - DNS is unavailable (get_dnsavailable()) — never stall on a network read;
 *   - the rquery yields nothing (repo/conf absent).
 */
function pfb_pkg_latest(string $pkgname, string $reponame): string {
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
	// Best-effort catalog refresh of the pfBlockerNG repo only; ignore failures (stale DB still reads).
	exec("{$tmo}{$bin} update -r {$repo} 2>/dev/null");
	$out = array();
	$ret = -1;
	exec("{$tmo}{$bin} rquery -r {$repo} '%v' " . escapeshellarg($pkgname) . ' 2>/dev/null', $out, $ret);
	return ($ret === 0 && isset($out[0])) ? trim($out[0]) : '';
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
 * last_notified); [] when absent/unreadable/corrupt.
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
	return is_array($data) ? $data : array();
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
 *      $io ['installed_name','installed','latest']; absent keys fall through to the
 *      live pfb_pkg_*() shellout.
 *   2. PROVENANCE GATE FIRST: gate on pfb_software_provenance_ok() — the SAME predicate
 *      that decides whether the Software PAGE is displayable (our-repo install, honouring
 *      the hidden CI/support override) — so a build that cannot show the page never runs
 *      the background check or raises an update notice, even if "Check for new versions"
 *      remains enabled from a prior our-repo install. Injectable via $io['provenance_ok']
 *      for off-box tests.
 *   3. Read our-repo latest for the channel's repo (guarded inside pfb_pkg_latest()).
 *      An empty latest (pkg locked / no DNS / repo absent) preserves the cached latest so
 *      the page keeps showing the last-known value rather than regressing to ''.
 *   4. Refresh the cache (channel/installed/latest/last_checked) and, when
 *      pfb_should_notify() says so, raise a DE-DUPED file_notice and persist
 *      last_notified = latest (so repeated ticks at the same latest do not renotify).
 *
 * Best-effort throughout: it returns the cache array and never throws, so wiring it into
 * the cron pass can never break a feed update. $force (the page's "Check now" button) bypasses
 * the "Check for new versions" enable-gate so a manual check always runs; it never bypasses the
 * provenance gate, and notifications still require the setting enabled.
 */
function pfb_software_update_check(bool $force = FALSE, ?array $io = null): array {
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
	$check_raw = PfbConfig::read('pfb_software_check');
	$enabled = pfb_software_check_enabled(is_string($check_raw) ? $check_raw : null);
	if (!$enabled && !$force) {
		return pfb_software_read_cache();
	}

	$channel = pfb_channel_from_pkgname($pkgname);
	$repo    = pfb_pkg_repo_name_for_channel($channel);

	$cache = pfb_software_read_cache();

	// 3. Read our-repo latest; keep the cached value when the live read is unavailable.
	if (array_key_exists('latest', $io)) {
		$latest = (string) $io['latest'];
	} else {
		$latest = pfb_pkg_latest($pkgname, (string) $repo);
	}
	// Only reuse cached latest/last_notified when the cache belongs to the SAME installed
	// package — after a channel switch (stable<->devel<->nightly) a stale value must not
	// drive a wrong notice or suppress the first valid one for the new package.
	$cache_matches_pkg = (($cache['pkgname'] ?? '') === $pkgname);
	if ($latest === '' && $cache_matches_pkg) {
		$latest = (string) ($cache['latest'] ?? '');
	}

	$last_notified = $cache_matches_pkg ? (string) ($cache['last_notified'] ?? '') : '';

	// 4. Refresh the cache. last_notified is written from the scoped value so a cache left
	// by a different package (channel switch) is reset rather than carried forward.
	$cache['pkgname']       = $pkgname;
	$cache['channel']       = $channel;
	$cache['installed']     = $installed;
	$cache['latest']        = $latest;
	$cache['last_notified'] = $last_notified;
	$cache['last_checked']  = time();

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
 * and returns true ONLY when pfBlockerNG was installed from one of OUR repos
 * (`pfblockerng` / `pfblockerng-nightly`). A Netgate-ports install (repo
 * 'pfSense'/unknown/'') returns false.
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
		if (trim((string) ($hook['script'] ?? '')) === '') {
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
		// file in the allowed dir is the authorization. A non-executable script
		// will fail at run time (timeout(1) non-zero exit, logged by pfb_run_hooks),
		// so the picker/validator authorize on containment + regular-file only.
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

		// The script basename is safe to log (a filename, not a command line that
		// could carry inline secrets); it aids correlating the log to the file.
		$header = "\n[ pfB Hook ] {$when} {$label} ({$script}, timeout {$timeout}s)\n";
		pfb_logger($header, 1);

		// Run the vetted script as root under timeout(1): SIGTERM at $timeout,
		// SIGKILL after the grace period. The PFB_* context rides the env prefix
		// (the script reads it from the environment). The script runs via its own
		// shebang + execute bit (the hook-script dir convention).
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
			" {$timeout} " . escapeshellarg($path) . " >> {$logf} 2>&1 < /dev/null";

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
				PFB_HOOK_KILL_GRACE . " {$timeout} " . escapeshellarg($path);
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


// issue #1004: dedicated IP-parse-error sink; CSV adds a line-number column vs pfb_parsed_fail()
function pfb_ip_parsed_fail($header, $line, $oline, $logfile, $lineno) {
	$line  = $line !== '' ? $line : 'null';
	// issue #1004: $oline is a raw fgets() line (keeps its trailing \n); strip it and
	// terminate the row ourselves so the trailing $lineno stays on the SAME physical
	// line -- else the record splits and field0 empties (ADR-60 age-cutoff wipe).
	$oline = rtrim((string) $oline, "\r\n");
	$now   = pfb_log_iso_timestamp();
	$log   = "{$now},{$header},{$line},{$oline},{$lineno}\n";
	@file_put_contents("{$logfile}", "{$log}", FILE_APPEND);
}


// issue #993: per-feed parse-error summary wrapper extracted for unit coverage.
function pfb_ip_parse_fail_warn($parse_fail, $header) {
	if ($parse_fail > 0) {
		pfb_logger("\n[!] Parse Errors [ {$header} ]: {$parse_fail}\n", 2);
	}
}


// Record failed IP/DNSBL Feed parse errors
// issue #1004: trailing optional $lineno keeps existing 4-arg callers call-safe.
function pfb_parsed_fail($header, $line='', $oline, $logfile, $lineno = '') {

	$line   = $line ?: 'null';
	// issue #1004: strip the raw fgets() line's trailing \n and terminate the row here,
	// so the appended $lineno column can't split the record and empty field0 (ADR-60).
	$oline  = rtrim((string) $oline, "\r\n");
	$now	= pfb_log_iso_timestamp();

	$log	= "{$now},{$header},{$line},{$oline},{$lineno}\n";
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

	// Determine length of header to format log output
	$tabtype = strlen($header);
	if ($tabtype > 27) {
		$pfbarr['logtab'] = '';
	} elseif ($tabtype > 19) {
		$pfbarr['logtab'] = "\t";
	} elseif ($tabtype > 11) {
		$pfbarr['logtab'] = "\t\t";
	} elseif ($tabtype < 4) {
		$pfbarr['logtab'] = "\t\t\t\t";
	} else {
		$pfbarr['logtab'] = "\t\t\t";
	}

	// Configure autoports/protocol and auto destination if required.
	if (!empty($confconfig) && is_array(config_get_path("installedpackages/{$confconfig}/config/{$key}"))) {

		$conf_config	= config_get_path("installedpackages/{$confconfig}/config/{$key}");
		$autotype	= array( 'autoports' => 'aliasports', 'autoaddr' => 'aliasaddr');

		foreach (array('_out', '_in') as $dir) {

			$pfbarr['aproto' . $dir]	= $conf_config['autoproto' . $dir];
			$pfbarr['anot' . $dir]		= $conf_config['autonot' . $dir];
			$pfbarr['aaddrnot' . $dir]	= $conf_config['autoaddrnot' . $dir];
			$pfbarr['agateway' . $dir]	= $conf_config['agateway' . $dir];

			foreach ($autotype as $akey => $atype) {
				if ($conf_config[$akey . $dir] == 'on') {
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
	if ($pfbarr['aaddrnot_in'] == 'on' || $pfbarr['aaddrnot_out'] == 'on') {
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
	$placeholder = ($ip_ph === '') ? '' : (($family === 'v6') ? "::{$ip_ph}" : $ip_ph);
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
	$lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
	if ($lines === FALSE || empty($lines)) {
		return FALSE;
	}
	foreach ($lines as $line) {
		$line = trim($line);
		if ($line === '' || $line[0] === '#') {
			continue;
		}
		if ($line !== $placeholder) {
			return FALSE;
		}
	}
	return TRUE;
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
 * @param bool $dedup_on    Dedup pass due: $pfb['dup'] == 'on' ANDed by the caller with the
 *                          feed-changed trigger (repcheck && !save && enable) -- a quiet pass
 *                          (no IP-Deny snapshot written, no removal) invokes nothing, so the
 *                          placeholder refill from the closing pass is never truncated away.
 * @param bool $rep_trigger dRep/pRep's shared "changes found" gate: $pfb['repcheck'] &&
 *                          !$pfb['save'] && $pfb['enable'] == 'on'.
 * @param bool $drep_on     $pfb['drep'] == 'on'.
 * @param bool $prep_on     $pfb['prep'] == 'on'.
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

/**
 * The recompute memberlist entry for one header -- the existing snapshot when present, else a
 * one-line seed from the live deny .txt (first run after upgrade, or a header whose snapshot
 * was never written on this box). Load-bearing for upgrade continuity: without it, a
 * pre-#1084 deny alias would vanish from the memberlist (and the masterfile) on the first
 * recompute pass instead of carrying its current content forward.
 */
function pfb_ip_recompute_seed_snapshot(string $header, string $snapdir, string $denydir): string {
	$snap = pfb_ip_recompute_snapshot_path($snapdir, $header);
	if (!file_exists($snap)) {
		$live = "{$denydir}/{$header}.txt";
		if (file_exists($live)) {
			@copy($live, $snap);
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
	$lines = @file($src, FILE_IGNORE_NEW_LINES);
	@file_put_contents("{$origdir}/{$header}.aggcount", (is_array($lines) ? count($lines) : 0) . "\n", LOCK_EX);
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
// Callers: pfb_pfctl_table_op() (below) — which is the only exec() wrapper for
// pfctl -T mutation ops.  The message names every field so "Table does not exist"
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
	if ($pfb['enable'] != 'on') {
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
			$agg_esc	= escapeshellarg(($pfb['agg'] ?? '') === 'on' ? 'on' : 'off');
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
 * @param bool $supp_on       $pfb['supp'] == 'on'.
 * @param bool $vtype_matches $vtype == '_v4' (or '_v6' for the sibling call site).
 * @param bool $supp_update   $pfb['supp_update'].
 * @param bool $adv           $pfbadv (Deny-folder alias).
 * @param bool $feed_changed  in_array($alias, $final_alias_old).
 * @param bool $recompute_ran $pfb_recompute_ran_v4 / _v6 for this family.
 */
function pfb_ip_suppress_body_active(bool $supp_on, bool $vtype_matches, bool $supp_update, bool $adv, bool $feed_changed, bool $recompute_ran): bool {
	return $supp_on && $vtype_matches && $supp_update && $adv && ($feed_changed || $recompute_ran);
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


// Calculate the cron task base hour setting
function pfb_cron_base_hour($freq) {
	global $pfb;

	switch($freq) {
		case 'Disabled':
		case 1:
		case '01hour':
			$j = 23; $k = 1;
			break;
		case 2:
		case '02hours':
			$j = 11; $k = 2;
			break;
		case 3:
		case '03hours':
			$j = 7; $k = 3;
			break;
		case 4:
		case '04hours':
			$j = 5; $k = 4;
			break;
		case 6:
		case '06hours':
			$j = 3; $k = 6;
			break;
		case 8:
		case '08hours':
			$j = 2; $k = 8;
			break;
		case 12:
		case '12hours':
			$j = 1; $k = 12;
			break;
		case 24:
			return array($pfb['24hour']);
			break;
		default:
			$pfb['interval'] = 1;
			return [];
	}

	$shour	= intval(substr($pfb['hour'], 0, 2));
	$sch	= strval($shour);

	for ($i=0; $i < $j; $i++) {
		$shour += $k;
		if ($shour >= 24) {
			$shour -= 24;
		}
		$sch .= ',' . strval($shour);
	}

	$sch = explode(',', $sch);
	sort($sch);
	return $sch;
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
	$v4suppression = pfbng_text_area_decode($pfb['ipconfig']['v4suppression'] ?? '', FALSE, TRUE);
	if (!empty($v4suppression)) {
		@file_put_contents("{$pfb['supptxt']}", $v4suppression, LOCK_EX);
	} else {
		unlink_if_exists("{$pfb['supptxt']}");
	}

	// ADR-53: v6 sibling -- same decode/write/unlink-when-empty shape as v4 above.
	$v6suppression = pfbng_text_area_decode($pfb['ipconfig']['v6suppression'] ?? '', FALSE, TRUE);
	if (!empty($v6suppression)) {
		@file_put_contents("{$pfb['supptxt_v6']}", $v6suppression, LOCK_EX);
	} else {
		unlink_if_exists("{$pfb['supptxt_v6']}");
	}
}


// Function to update DNSBL aliases and widget stats
function dnsbl_alias_update($mode, $alias, $pfbfolder, $lists_dnsbl_current, $alias_cnt) {
	global $pfb;

	if ($mode == 'update') {

		// Create master alias file
		if ($lists_dnsbl_current != '') {
			// issue #1073: fwrite(FALSE)/fclose(FALSE) throw TypeError on PHP 8 ('@'
			// only silences warnings), so a failed open must skip its write/close.
			if (($pfb_output = @fopen("{$pfb['dnsalias']}/{$alias}", 'w')) !== FALSE) {
				foreach ($lists_dnsbl_current as $clist) {
					if (($handle = @fopen("{$pfbfolder}/{$clist}.txt", 'r')) !== FALSE) {
						while (($line = @fgets($handle)) !== FALSE) {
							@fwrite($pfb_output, $line);
						}
						@fclose($handle);
					}
				}
				@fclose($pfb_output);
			} else {
				pfb_logger("\nDNSBL [ {$alias} ]: failed to open master alias file for writing", 2);
			}
		}

		// Update DNSBL alias statistics
		$dns_now = date('Y-m-d H:i:s', time());
		$pfbfound = FALSE;

		if (!empty($pfb['dnsbl_info_stats'])) {
			foreach ($pfb['dnsbl_info_stats'] as $key => $line) {

				// Update existing alias stats
				if ($line['groupname'] == "{$alias}") {
					$pfbfound = TRUE;
					$pfb['dnsbl_info_stats'][$key]['timestamp']	= "{$dns_now}";
					$pfb['dnsbl_info_stats'][$key]['entries']	= "{$alias_cnt}";
					break;
				}
			}
		}

		if (!$pfbfound) {
			$pfb['dnsbl_info_stats'][] = array ( 'groupname' => $alias, 'timestamp' => $dns_now, 'entries' => $alias_cnt, 'counter' => 0);
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

if ($pfb['dnsbl_py_nolog'] == 'on') {
	$pfb_conf .= <<<EOF
server.errorlog			= "|/usr/local/bin/php -f /usr/local/pkg/pfblockerng/pfblockerng.inc dnsbl"

EOF;
}

	if (file_exists('/usr/local/lib/lighttpd/mod_openssl.so')) {
		if ($pfb['dnsbl_py_nolog'] == 'on') {
			$pfb_conf .= 'server.modules			= ( "mod_access", "mod_accesslog", "mod_fastcgi", "mod_rewrite", "mod_openssl" )';
		} else {
			$pfb_conf .= 'server.modules			= ( "mod_fastcgi", "mod_rewrite", "mod_openssl" )';
		}
	} else {
		if ($pfb['dnsbl_py_nolog'] == 'on') {
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
	if ($pfb['dnsbl_py_nolog'] == 'on') {

	$pfb_conf .= <<<EOF
debug.log-condition-handling	= "enable"
accesslog.use-syslog		= "disable"
accesslog.format		= "INDEX!%r!%V!%h!%{Referer}i * %r * %{User-Agent}i"
accesslog.filename		= "|/usr/local/bin/php -f /usr/local/pkg/pfblockerng/pfblockerng.inc index"

EOF;
}
	// Lighttpd v1.4.58+ conditional error log with 'ssl.verifyclient.activate' to collect the domain name
	$lighty_ver = exec('/usr/local/sbin/lighttpd -v 2>&1');
	if (($pfb['dnsbl_py_nolog'] == 'on') &&
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
function pfb_dnsbl_nat_enabled(string $iface, string $nonat): bool {
	return $iface !== 'lo0' && empty($nonat);
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

	if ((!empty($pfb['dnsbl_port']) && !empty($pfb['dnsbl_port_ssl']) && ($pfb['dnsbl'] == 'on') && $mode == 'enabled') || $mode == 'disabled') {

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

	$out4 = array();
	exec("{$drill_esc} A {$target_esc} {$extdns_esc} | /usr/bin/awk '/[ \\t]IN[ \\t]+A[ \\t]/ {print \$5; exit}'", $out4);
	$v4 = filter_var(trim($out4[0] ?? ''), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ?: '';

	$out6 = array();
	exec("{$drill_esc} AAAA {$target_esc} {$extdns_esc} | /usr/bin/awk '/[ \\t]IN[ \\t]+AAAA[ \\t]/ {print \$5; exit}'", $out6);
	$v6 = filter_var(trim($out6[0] ?? ''), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ?: '';

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
		$unbound_custom = base64_encode(str_replace("\r\n", "\n", $unbound_custom));
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
			unlink_if_exists("{$g['unbound_chroot_path']}/pfb_unbound.py");
			unlink_if_exists("{$g['unbound_chroot_path']}/pfb_unbound_include.inc");
			unlink_if_exists("{$g['unbound_chroot_path']}/pfb_py_hsts.txt");
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
	$dnsbl_white = pfbng_text_area_decode($pfb['dnsblconfig']['suppression'], TRUE, FALSE, TRUE);
	if (!empty($dnsbl_white)) {
		foreach ($dnsbl_white as $key => $line) {
			if (!empty($line)) {
				if (str_starts_with($line, 'www.')) {
					$line = substr($line, 4);
				}

				if (str_starts_with($line, '.')) {
					$line = ltrim($line, '.');
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

	$lines = pfbng_text_area_decode($pfb['dnsblconfig']['suppression'], TRUE, FALSE, TRUE);
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
// branch) check '#' themselves first and do not route it through here. Blank detection is
// empty($line) -- callers MUST trim() first, or a whitespace-only line won't match.
function pfb_is_blank_or_comment_line(string $line): bool {
	return empty($line) ||
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
		pfb_parsed_fail($header, $line, $oline, $logfile, $lineno);
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


// ADR-62 §2 Decision 4: the universal plain-path control-line skip. Mirrors
// pfb_is_blank_or_comment_line's contract: blank detection is an exact '' match, so
// the CALLER must trim() first. Deliberately excludes '#' -- pfb_dnsbl_hash_line_
// classify() owns it (side effects). A bracketed IPv6 literal is an ADDRESS, never
// skipped as an ABP section marker.
function pfb_dnsbl_is_skippable_control_line(string $line): bool {
	if ($line === '' || str_starts_with($line, '!') || str_starts_with($line, '//')) {
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
function pfb_dnsbl_is_abp_rule_line(string $line): bool {
	// issue #1067: a leading comma is never valid ABP syntax (empty first cosmetic
	// domain-list entry) -- a comma-first verbatim capture would collide with the
	// plain CSV dialect downstream.
	if (str_starts_with($line, ',')) {
		return FALSE;
	}
	if (str_starts_with($line, '||') || str_starts_with($line, '@@')) {
		return TRUE;
	}
	if (str_contains($line, '#')) {
		$first = FALSE;
		foreach (array('##', '#@#', '#?#', '#%#', '#$#') as $eh_marker) {
			$pos = strpos($line, $eh_marker);
			if ($pos !== FALSE && ($first === FALSE || $pos < $first)) {
				$first = $pos;
			}
		}
		if ($first !== FALSE &&
		    ($first === 0 || strspn($line, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._,~*-') >= $first)) {
			return TRUE;
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


// ADR-10: atomically publish a file to the chroot (/var/unbound). Stage into a
// temp file ON THE SAME FILESYSTEM (same directory) -> flush + fsync the data ->
// fix ownership -> atomic rename() over the final path. The plugin only ever reads
// a fully-written, immutable file: a half-written manifest is never visible because
// the rename is the all-or-nothing commit (POSIX rename(2) is atomic within a dir).
// Returns TRUE on success. No die()/exit(): a failure is logged + returned FALSE so
// the caller can fall back to the restart path.
function pfb_unbound_py_atomic_write($path, $content) {
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

	$ok = (@fwrite($fh, $content) !== FALSE);
	if ($ok) {
		@fflush($fh);
		// Durably persist the staged bytes before the rename so a crash between
		// rename and the OS flush cannot expose a zero-length manifest.
		@fsync($fh);
	}
	@fclose($fh);

	if (!$ok) {
		@unlink($tmp);
		pfb_logger("\nADR-10: failed to write staging file [ {$tmp} ]", 2);
		return FALSE;
	}

	// Ownership must match the consuming (chrooted) unbound user; set it on the
	// staging file so the rename publishes a correctly-owned inode atomically.
	@chown($tmp, 'unbound');
	@chgrp($tmp, 'unbound');

	if (!@rename($tmp, $path)) {
		@unlink($tmp);
		pfb_logger("\nADR-10: failed to publish [ {$path} ]", 2);
		return FALSE;
	}

	return TRUE;
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
	if (!@flock($lock, LOCK_EX)) {
		@fclose($lock);
		pfb_logger("\nPFBL-03: control channel lock acquire failed [ {$lockpath} ]", 2);
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
// construction; callers have already validated $header and resolved $format/$provenance.
function pfb_feed_manifest_row(string $header, string $group, string $log_flag,
	string $format, string $provenance, string $mode = 'deny'): array
{
	$row = array(
		'header'     => $header,
		'group'      => $group,
		'log'        => $log_flag,
		'format'     => $format,
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
// consumes. Every feed is 'plain' (ADR-62): raw is the bare-domain extraction of the parsed
// '.txt' (IPs already routed elsewhere), with ABP-shaped lines (pfb_dnsbl_is_abp_rule_line)
// passed through verbatim so Python's parse_abp sees them intact. $feeds rows:
// header/group/log/format/provenance ('user' Custom_List -> band 5, 'feed' download -> band 1).
// PFBL-01: RE-validates each header via pfb_sanitise_feed_header() (PFB_FILTER_WORD, not
// DOMAIN); a failing row is SKIPPED + logged before any file touch; pinned by
// tests/php/PfbFilterContractTest.php.
function pfb_unbound_python_sources($feeds) {
	global $pfb;

	if (!is_array($feeds)) {
		$feeds = array();
	}

	// Per-feed raw directory (recreated each build)
	rmdir_recursive("{$pfb['unbound_py_rawdir']}");
	safe_mkdir("{$pfb['unbound_py_rawdir']}");

	$manifest_feeds = array();
	foreach ($feeds as $feed) {
		$header	= isset($feed['header']) ? $feed['header'] : '';
		$group	= isset($feed['group'])  ? $feed['group']  : '';
		$logf	= isset($feed['log'])    ? (string) $feed['log'] : '1';
		// ADR-62: every LIVE caller now tags 'plain'; 'format_hint' below is a pure
		// pass-through -- Python still tolerates a stale 'abp' hint from an old
		// manifest (Semantics #7), but this writer no longer branches on it.
		$format	= (isset($feed['format']) && $feed['format'] === 'abp') ? 'abp' : 'plain';

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

		$rawpath	= "{$pfb['unbound_py_rawdir']}/{$header}.raw";
		$raw_h		= @fopen($rawpath, 'w');
		if ($raw_h === FALSE) {
			pfb_logger("\nFailed to create DNSBL python raw feed [ {$rawpath} ]", 2);
			continue;
		}
		if (($in_h = @fopen($src, 'r')) !== FALSE) {
			while (($line = @fgets($in_h)) !== FALSE) {
				// ADR-62 Decision 2: self-identifying ABP-shape verbatim line
				// from a non-ABP feed (the download loop wrote it through
				// untouched, NOT as 6-col CSV) -- pass it straight to the
				// '.raw' without CSV extraction. Python's build() routes it
				// to parse_abp().
				$rawline = rtrim($line, "\r\n");
				if (pfb_dnsbl_is_abp_rule_line($rawline)) {
					@fwrite($raw_h, "{$rawline}\n");
					continue;
				}
				// 'plain': extract bare domains (col1) from the 6-col CSV; this is
				// already IP-free (IPs went to the firewall path) and already
				// cleaned/validated by the download loop.
				// issue #1067: a non-captured line still carrying '#' is stale verbatim
				// ABP residue from a pre-guard staging file, never a machine CSV row --
				// skip it rather than extract col1 into a blockable "domain".
				$cols = explode(',', $line, 3);
				if (strpos($line, '#') === FALSE && isset($cols[1]) && $cols[1] !== '') {
					@fwrite($raw_h, "{$cols[1]}\n");
				}
			}
			@fclose($in_h);
		}
		if ($raw_h) {
			@fclose($raw_h);
		}

		// Store the raw path RELATIVE to the manifest's directory. pfb_unbound.py
		// runs inside Unbound's chroot (/var/unbound), so an absolute HOST path
		// like /var/unbound/pfb_py_raw/<f>.raw resolves to
		// /var/unbound/var/unbound/pfb_py_raw/<f>.raw inside the chroot and is not
		// found (feeds silently fail to load -> nothing blocked). The Python build
		// joins a relative path against the manifest's dir (the chroot root), which
		// resolves correctly both chrooted and not.
		$manifest_feeds[] = array(
			'raw'		=> basename($pfb['unbound_py_rawdir']) . "/{$header}.raw",
			'feed'		=> $header,
			'group'		=> $group,
			'format_hint'	=> $format,
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

	// Synthetic whole-TLD blacklist feed (DNSBL_TLD): the Python build emits these
	// as whole-TLD ZONE entries from config.tld_blacklist, so no raw file is needed.

	// TOP1M (Tranco/Cisco) popularity whitelist -> query-time whiteDB only when on.
	// ponytail: pfbalexawhitelist.txt keeps its on-disk name -- renaming a generated
	// artifact needs old-file cleanup for zero user benefit (#877 triage decision).
	$top1m_enabled	= ($pfb['dnsbl_top1m'] == 'on' &&
			   file_exists("{$pfb['dbdir']}/pfbalexawhitelist.txt"));
	$top1m_list	= array();
	if ($top1m_enabled) {
		$top1m_lines = @file("{$pfb['dbdir']}/pfbalexawhitelist.txt", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
		if (is_array($top1m_lines)) {
			$top1m_list = $top1m_lines;
		}
	}

	$tld_blacklist	= pfbng_text_area_decode($pfb['dnsblconfig']['tldblacklist'], TRUE, FALSE, TRUE) ?: array();
	$tld_exclusion	= pfbng_text_area_decode($pfb['dnsblconfig']['tldexclusion'], TRUE, FALSE, TRUE) ?: array();

	// Embed the public-suffix master list as LINES, not a path: pfb_unbound.py runs
	// chrooted in /var/unbound and cannot read /usr/local/pkg/... (outside the
	// chroot). _dnsbl_config_from_manifest() accepts tld_master as a list. Empty
	// when the file is absent (the TLD feature then simply has no suffixes).
	$tld_master_lines = array();
	if (file_exists($pfb['dnsbl_tld_data'])) {
		$tld_master_file = @file($pfb['dnsbl_tld_data'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
		if (is_array($tld_master_file)) {
			$tld_master_lines = $tld_master_file;
		}
	}

	$manifest = array(
		'version'	=> 1,
		'config'	=> array(
			'tld_master'	=> array_values($tld_master_lines),
			'tld_blacklist'	=> array_values($tld_blacklist),
			'tld_exclusion'	=> array_values($tld_exclusion),
			'user_whitelist'=> pfb_dnsbl_whitelist_lines(),
			// ADR-06 (#51): a FULL build CLEARS the temporary unlock set. A Force/Cron
			// update deletes the pfb_unlock store (pfb_update_unbound) right after this
			// manifest is written, so reading the live store here would bake unlocks
			// into the rebuilt manifest and they would survive the Force/Cron reload
			// (the manifest is not rewritten post-delete) -- breaking the documented
			// "re-locked on Cron/Force" semantic. Only pfb_unbound_python_sources_unlock()
			// (the incremental alerts dnsbl_remove path) repopulates user_unlock.
			'user_unlock'	=> array(),
			'top1m_list'	=> array_values($top1m_list),
			'top1m_enabled'	=> $top1m_enabled
		),
		'feeds'		=> $manifest_feeds
	);

	$json = json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
	if ($json !== FALSE) {
		// ADR-10: atomic publish (stage -> fsync -> rename). The per-feed raw
		// files were already (re)written into unbound_py_rawdir above; the manifest
		// rename is the point at which the new immutable set becomes readable. The
		// sentinel flip that ACTS on it is driven by pfb_reload_unbound's data
		// fast path (so a full feed update advances the generation exactly once,
		// after every manifest+raw file is in place), not here.
		pfb_unbound_py_atomic_write($pfb['unbound_py_sources'], $json);
	}

	return $manifest;
}


// ADR-06: patch a single scalar key of the manifest's config section in place
// (shared by the whitelist/unlock in-place patchers below), without a full
// feed re-enumeration. The query-time whiteDB is rebuilt from this on reload.
function pfb_unbound_python_sources_patch($key, $values) {
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

	$json = json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
	if ($json !== FALSE) {
		// ADR-10: atomic publish (the sentinel flip is driven by the reload).
		return pfb_unbound_py_atomic_write($pfb['unbound_py_sources'], $json);
	}

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
	$python_enable = 'off';
	if ($mode == 'enabled') {
		$python_enable = 'on';

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

		$python_reply = 'off';
		if ($pfb['dnsbl_py_reply'] == 'on') {
			$python_reply = 'on';
		}

		$python_blocking = 'on';

		$python_hsts = 'off';
		if ($pfb['dnsbl_hsts'] == 'on') {
			$python_hsts = 'on';
		}

		// ADR-08: emit the IDN mode + the legacy python_idn flag + the Confusable sub-toggles.
		// python_idn = on ONLY for All-IDN, so the legacy flag (and its blacklist side-effect)
		// stays byte-identical to today; Confusable rides the explicit idn_mode key instead.
		// py_unbound.ini IDN mode: the SAME canonical token as config.xml (toStored):
		// 'on' (= All) | 'confusable' | 'off'. The Python IdnMode enum reads it directly.
		$idn_mode = $pfb['dnsbl_idn']->toStored();
		$python_idn = ($pfb['dnsbl_idn'] === PfbIdnMode::All) ? 'on' : 'off';

		$python_idn_block_malicious = (pfb_cfg_toggle_read($pfb['dnsbl_idn_block_malicious']) === PfbToggle::On) ? 'on' : 'off';
		$python_idn_escalate_suspicious = (pfb_cfg_toggle_read($pfb['dnsbl_idn_escalate_suspicious']) === PfbToggle::On) ? 'on' : 'off';

		$python_cname = 'off';
		if ($pfb['dnsbl_cname'] == 'on') {
			$python_cname = 'on';
		}

		$python_control = 'off';
		if ($pfb['dnsbl_control'] == 'on') {
			$python_control = 'on';
		}

		// PFBL-03: deprecated legacy DNS-TXT control transport. OFF unless the operator
		// explicitly opted back in (and the parent DNSBL Control toggle is enabled).
		// DNSBL control is CLI-driven; this path is slated for removal next release.
		$python_control_legacy = 'off';
		if ($pfb['dnsbl_control'] == 'on' && $pfb['dnsbl_control_legacy'] == 'on') {
			$python_control_legacy = 'on';
		}

		$python_noaaaa = 'off';
		if ($pfb['dnsbl_noaaaa'] == 'on') {
			$python_noaaaa = 'on';
		}

		$python_tld = 'off';
		$python_tlds = '';
		if ($pfb['dnsbl_pytld'] == 'on') {
			if (!empty($pfb['dnsblconfig']['pfb_pytlds_gtld'])) {
				$python_tld = 'on';
				$python_tlds = $pfb['dnsblconfig']['pfb_pytlds_gtld'];
			}
			if (!empty($pfb['dnsblconfig']['pfb_pytlds_cctld'])) {
				$python_tld = 'on';
				$python_tlds .= ',' . $pfb['dnsblconfig']['pfb_pytlds_cctld'];
			}
			if (!empty($pfb['dnsblconfig']['pfb_pytlds_itld'])) {
				$python_tld = 'on';
				$python_tlds .= ',' . $pfb['dnsblconfig']['pfb_pytlds_itld'];
			}
			if (!empty($pfb['dnsblconfig']['pfb_pytlds_bgtld'])) {
				$python_tld = 'on';
				$python_tlds .= ',' . $pfb['dnsblconfig']['pfb_pytlds_bgtld'];
			}
			$python_tlds = ltrim($python_tlds, ',');
		}

		$python_nolog = 'off';
		if ($pfb['dnsbl_py_nolog'] == 'on') {
			$python_nolog = 'on';
		}

		// ADR-07: opt-in "Limit long/complex regex" static cap (drops over-long /
		// nested-quantifier patterns at load -- feed AND user regex). The always-on
		// runtime warn/evict guard does not need a toggle; its ceilings default in
		// Python (warn 10 ms / evict 100 ms) and are advanced-only knobs here.
		$regex_cap = 'off';
		if ($pfb['dnsbl_regex_cap'] == 'on') {
			$regex_cap = 'on';
		}

		// DNSBL Python decision-cache cap (LRU); WebUI-configurable, 0 = unlimited.
		// Already validated + clamped (digits-only) in pfb_global().
		$decisiondb_max = $pfb['dnsbl_decisiondb_max'] ?? '10000';

		$forwarding = (config_get_path('unbound/forwarding') == 'on') ? 'on' : 'off';

		$now = date('Y-m-d H:i:s', time());	// ISO-8601 (py_unbound.ini "File created" comment)

		// issue #1155: fixed at 1 -- the min-segment optimization was computed-and-discarded
		// in pfb_unbound_python_whitelist() since extraction; 1 is behaviourally identical
		// (only wildcard entries can match the Python suffix walk it gates).
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
python_idn	= {$python_idn}
idn_mode	= {$idn_mode}
python_idn_block_malicious	= {$python_idn_block_malicious}
python_idn_escalate_suspicious	= {$python_idn_escalate_suspicious}
python_tld_seg	= 1
decisiondb_max	= {$decisiondb_max}
python_tld	= {$python_tld}
python_tlds	= {$python_tlds}
python_nolog	= {$python_nolog}
python_cname	= {$python_cname}
python_control	= {$python_control}
python_control_legacy	= {$python_control_legacy}
regex_cap	= {$regex_cap}
forwarding	= {$forwarding}

EOF;
		if ($pfb['dnsbl_regex'] == 'on' && isset($pfb['dnsbl_regex_list']) && !empty($pfb['dnsbl_regex_list'])) {
			$regex = '';
			$regex_list = pfbng_text_area_decode($pfb['dnsbl_regex_list'], TRUE, TRUE, FALSE);
			if (!empty($regex_list)) {
				$counter = 1;
				$key_index = array();
				foreach ($regex_list as $key => $list) {
					if (!isset($list[1])) {
						$list[1] = "Regex_{$counter}";
					} else {
						$list[1] = trim(ltrim($list[1], '#'));
						$list[1] = preg_replace("/\W/", '', str_replace(' ', '_', $list[1]));
					}

					// Check if key exists
					if (!isset($key_index[$list[1]])) {
						$regex .= "{$list[1]} = {$list[0]}\n";
						$key_index[$list[1]] = '';
					} else {
						$regex .= "{$list[1]}_{$counter} = {$list[0]}\n";
						$key_index["{$list[1]}_{$counter}"] = '';
					}
					$counter++;
				}
				$pfb_py_conf .= <<<EOF

[REGEX]
{$regex}
EOF;
			}
		}

		if ($pfb['dnsbl_noaaaa'] == 'on' && isset($pfb['dnsbl_noaaaa_list']) && !empty($pfb['dnsbl_noaaaa_list'])) {
			$noaaaa = '';
			$noaaaa_list = pfbng_text_area_decode($pfb['dnsbl_noaaaa_list'], TRUE, TRUE, TRUE);
			if (!empty($noaaaa_list)) {
				foreach ($noaaaa_list as $key => $list) {
					if (str_starts_with($list[0], '.')) {
						$list[0] = ltrim($list[0], '.');
						$noaaaa .= "{$key} = {$list[0]},1\n";
					} else {
						$noaaaa .= "{$key} = {$list[0]},0\n";
					}
				}
				$pfb_py_conf .= <<<EOF

[noAAAA]
{$noaaaa}
EOF;
			}
		}

		if ($pfb['dnsbl_gp'] == 'on' && isset($pfb['dnsbl_gp_bypass_list']) && !empty($pfb['dnsbl_gp_bypass_list'])) {
			$gp_bypass = '';
			$gp_bypass_list = pfbng_text_area_decode($pfb['dnsbl_gp_bypass_list'], TRUE, TRUE, FALSE);
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


// Search for TLD match
function tld_search($tld, $dparts, $j, $k) {
	global $tlds;

	$tld_query = implode('.', array_slice($dparts, -$j, $j, TRUE));
	if (isset($tlds[$tld][$tld_query])) {
		return implode('.', array_slice($dparts, -$k, $k, TRUE));
	}
	return NULL;
}


// Function to determine if each Domain is a Sub-Domain ('transparent' zone) or a whole Domain ('redirect' zone)
function tld_analysis() {
	global $pfb, $tlds;

	if (!file_exists("{$pfb['dnsbl_file']}.raw")) {
		pfb_logger("\n\nTLD Analysis not required.", 1);
		return;
	}

	pfb_logger("\nTLD:\n", 1);

	$domain_cnt = 0;
	$pfb_found = FALSE;				// Flag to determine if TLD 'redirect' zones found

	rmdir_recursive("{$pfb['dnsbl_tmpdir']}");

	unlink_if_exists("{$pfb['dnsbl_file']}.tsp");
	unlink_if_exists("{$pfb['dnsbl_tld_txt']}.*");
	unlink_if_exists("{$pfb['dnsbl_tmp']}.sup");
	unlink_if_exists("{$pfb['dnsbl_tmp']}.adup");

	// Master TLD Domain list
	if (($t_handle = @fopen("{$pfb['dnsbl_tld_data']}", 'r')) !== FALSE) {
		while (($line = @fgets($t_handle)) !== FALSE) {
			$line	= trim(rtrim($line, "\x00..\x1F"));
			// issue #1116: match the Python mirror's contract -- skip comment and
			// whitespace-only lines; '0' is a valid dot-less TLD key.
			if ($line === '' || str_starts_with($line, '#')) {
				continue;
			}
			$dot	= strrpos($line, '.');
			// issue #1068: a dot-less line keys under its own full value
			// (FALSE + 1 would substr off the first char)
			$tld	= ($dot === FALSE) ? $line : substr($line, $dot + 1);

			if ($tld !== '') {
				if (!isset($tlds[$tld]) || !is_array($tlds[$tld])) {
					$tlds[$tld] = array();
				}
				$tlds[$tld][$line] = '';
			}
		}
		@fclose($t_handle);
	} else {
		pfb_logger("\n ** TLD Master data file missing. Terminating TLD **\n", 1);
		return;
	}

	// DNSBL python - create file handles for data and zone files
	$p_data = @fopen("{$pfb['unbound_py_data']}.raw", 'w');
	$p_zone = @fopen("{$pfb['unbound_py_zone']}.raw", 'w');

	if ($p_data === FALSE || $p_zone === FALSE) {

		pfb_logger("\nFailed to create DNSBL python data|zone file handles! Exiting\n", 1);
		foreach (array($p_data, $p_zone) as $handlex) {
			if ($handlex) {
				@fclose($handlex);
			}
		}
		return;
	}

	// Collect TLD Blacklist(s). If configured the whole TLD will be blocked
	$tld_blacklist = pfbng_text_area_decode($pfb['dnsblconfig']['tldblacklist'], TRUE, FALSE, TRUE);
	if (!empty($tld_blacklist)) {
		$tld_blacklist = array_flip($tld_blacklist);
	}

	// ADR-06: The native-mode 'static local-zone' TLD-whitelist resolver block
	// (drill-resolve a whitelisted domain to a user/real IP) was a leftover from
	// the removed native Unbound mode -- '$whitelist' was always empty and it is
	// not required for python-mode blocking. It has been removed.

	// Process TLD Blacklist(s). If configured the whole TLD will be blocked
	if (!empty($tld_blacklist)) {

		$tld_list	= '';
		$tld_cnt	= 0;
		$tld_segments	= 0;
		pfb_logger(" Blocking full TLD/Sub-Domain(s)... |", 1);

		foreach ($tld_blacklist as $tld => $key) {

			unset($tld_blacklist[$tld]);			// Remove old entry
			$tld = trim($tld, '.');				// Remove any leading/trailing dots
			$tld_blacklist[$tld] = '';			// Add new TLD entry

			// DNSBL python - TLD Blacklist (Set logging type to enabled '1')
			$tld_cnt++;
			$pfb_found = TRUE;
			$tld_segments = @max((array((substr_count($tld, '.') +1), $tld_segments) ?: 1));

			pfb_logger("{$tld}|", 1);
			@fwrite($p_zone, ",{$tld},,1,DNSBL_TLD,DNSBL_TLD\n");

			// Collect List of TLDs and save to DNSBL folder
			$tld_list .= ",{$tld},,\n";

			// Remove any 'TLD Blacklists' from the 'TLD master list'
			if (isset($tlds[$tld])) {
				unset($tlds[$tld]);
			}
			continue;

		}

		// Save a list of TLDs in DNSBL folder (DNSBL total line count verification)
		if (!empty($tld_list)) {
			@file_put_contents("{$pfb['dnsbl_tld_txt']}", $tld_list, LOCK_EX);

			// Add 'TLD' to Alias/Feeds array
			if (!is_array($pfb['tld_update']['DNSBL_TLD'])) {
				$pfb['tld_update']['DNSBL_TLD'] = array();
			}

			$pfb['tld_update']['DNSBL_TLD']['feeds']	= array('DNSBL_TLD');
			$pfb['tld_update']['DNSBL_TLD']['count']	= $tld_cnt;
			$pfb['alias_dnsbl_all'][]			= 'DNSBL_TLD';
		}
		else {
			unlink_if_exists("{$pfb['dnsbl_tld_txt']}");
		}
		pfb_logger(" completed\n", 1);
	}
	else {
		unlink_if_exists("{$pfb['dnsbl_tld_txt']}");
	}

	// Collect TLD Exclusion list and remove any 'TLD Exclusions' from the 'TLD master list'
	$exclusion = pfbng_text_area_decode($pfb['dnsblconfig']['tldexclusion'], TRUE, FALSE, TRUE);
	$tld_exclusion = array();
	if (!empty($exclusion)) {
		foreach ($exclusion as $key => $exclude) {
			$exclude = trim($exclude, '.');		// Remove any leading/trailing dots

			// Collect exclusion
			if (strpos($exclude, '.') !== FALSE) {
				$tld_exclusion[$exclude] = '';
			}

			// Remove Exclusion from TLDS array
			if (isset($tlds[$exclude])) {
				unset($tlds[$exclude]);
			}
		}
	}

	pfb_logger("TLD analysis", 1);

	// This loop parses ONLY the plain ',domain,,log,feed,group' CSV dialect.
	// Skip any line that isn't comma-first (issue #1060; cheap, hot loop) or
	// whose feed column is empty/unset (a verbatim-captured ABP/regex line,
	// ADR-62) -- Python's own parse_abp/TLD pass classifies those independently.

	// DNSBL python: Analyse DNSBL into data (transparent/exact) and zone (wildcard) files

	if (($fhandle = @fopen("{$pfb['dnsbl_file']}.raw", 'r')) !== FALSE) {
		while (($line = @fgets($fhandle)) !== FALSE) {
			if (empty($line)) {
				continue;
			}

			// ADR-07/ADR-21: plain CSV rows (',domain,,log,feed,group') always start
			// with ','; the known ABP raw shapes (||x^, @@||x^, /re/, '0.0.0.0 h')
			// don't -- skip those by prefix (issue #1060; cheap, hot loop).
			if (strncmp($line, ',', 1) !== 0) {
				continue;
			}
			$fparts	= explode(',', $line, 6);
			$lfeed	= isset($fparts[4]) ? $fparts[4] : '';
			if ($lfeed === '') {
				continue;
			}

			// Display progress indicator
			if ($domain_cnt % 100000 == 0) {
				// Memory limitation exceeded for 'redirect' zones
				if ($domain_cnt >= $pfb['domain_max_cnt']) {
					pfb_logger('x', 1);
				} else {
					pfb_logger('.', 1);
				}
			}

			// DNSBL python blocking mode
			$eparts = explode(',', $line, 3);

			// A well-formed row has all three parts; a degenerate comma-first
			// line (e.g. bare ',') must not become a malformed output row.
			if (!isset($eparts[2]) || $eparts[1] === '') {
				continue;
			}
			$domain = $eparts[1];
			$dparts = explode('.', $domain);
			$dcnt   = count($dparts);
			$tld    = end($dparts);
			$d_info = $eparts[2]; // Logging Type/Header/Alias group details
			$dfound	= '';



			if ($domain_cnt <= $pfb['domain_max_cnt']) {

				// Search TLD master list (Levels 1-4)
				// If Domain is a Sub-Domain, create 'transparent' zone. Otherwise create 'redirect' zone
				switch($dcnt) {
					case ($dcnt > 5):
						break;
					case '5':
						$dfound = tld_search($tld, $dparts, 4, 5);
						break;
					case '4':
						$dfound = tld_search($tld, $dparts, 3, 4);
						break;
					case '3':
						$dfound = tld_search($tld, $dparts, 2, 3);
						break;
					case '2':
						$dfound = implode('.', array_slice($dparts, -2, 2, TRUE));
						break;
				}
			}

			// If Domain is in the TLD Exclusion(s), use 'transparent zone'
			if (!empty($domain) && isset($tld_exclusion[$domain])) {
				$dfound = '';
			}

			// Create 'redirect' zone for Domain
			if (!empty($dfound)) {
				$pfb_found = TRUE;

				// DNSBL python blocking mode
				@fwrite($p_zone, ",{$dfound},{$d_info}");
			}

			// Create 'transparent zone' for Sub-Domain
			else {
				// DNSBL python blocking mode
				@fwrite($p_data, ",{$domain},{$d_info}");
			}

			// Increment Domain counter
			$domain_cnt++;
		}
	}

	foreach (array($fhandle, $p_data, $p_zone) as $handlex) {
		if ($handlex) {
			@fclose($handlex);
		}
	}
	unset($tlds, $tld_blacklist, $tld_exclusion);

	// TLD 'redirect zones' found. Finalize TLD function
	if ($pfb_found) {
		$log = " completed\n";
		// Print TLD exceedance error message
		if ($domain_cnt >= $pfb['domain_max_cnt']) {
			$log .= "\n  ** TLD Domain count exceeded. [ {$pfb['domain_max_cnt']} ] All subsequent Domains listed as-is **\n\n";
		}
		$log .= "TLD finalize";
		pfb_logger("{$log}", 1);

		// ADR-06: The shell domaintldpy pass (sort -u dedup + subdomain COLLAPSE via
		// ggrep -vF dnsbl_tld_remove + pfb_py_count write) is DROPPED -- the Python
		// dict load dedups keys for free and a redundant sub-domain is matched by its
		// parent zone, so no collapse is needed. Promote the classified .raw files to
		// their final paths directly; Python emits pfb_py_count itself at load.
		foreach (array($pfb['unbound_py_data'], $pfb['unbound_py_zone']) as $py_final) {
			if (file_exists("{$py_final}.raw")) {
				@rename("{$py_final}.raw", $py_final);
			}
		}
		pfb_logger("\nTLD finalize... completed\n", 1);

		// Update DNSBL Alias and Widget Stats
		if (!empty($pfb['tld_update'])) {
			foreach ($pfb['tld_update'] as $alias => $data) {

				// Create Alias summary file for each DNSBL Alias
				$lists_dnsbl_current = array();
				foreach ($data['feeds'] as $feed) {
					$lists_dnsbl_current[] = "{$feed}";
				}
				dnsbl_alias_update('update', $alias, $pfb['dnsdir'], $lists_dnsbl_current, $data['count']);
			}
		}
	}
	else {
		pfb_logger(" no changes\n", 1);
	}

	// Save DNSBL Alias statistics
	dnsbl_save_stats();

	if (file_exists("{$pfb['dnsbl_file']}.raw")) {
		unlink_if_exists("{$pfb['dnsbl_file']}.raw");
	}
}

// Function to Start Unbound
function pfb_stop_start_unbound($type) {
	global $g, $pfb;

	$final = array();
	if (file_exists("{$g['varrun_path']}/unbound.pid")) {
		pfb_logger("\nStopping Unbound Resolver", 1);
		sigkillbypid("{$g['varrun_path']}/unbound.pid", 'TERM');
	}

	// If unbound is still running, wait up to 30 seconds for it to terminate.
	for ($i=1; $i <= 30; $i++) {
		if (is_process_running('unbound')) {
			pfb_logger('.', 1);
			sleep(1);
		} else {
			pfb_logger("\nUnbound stopped in {$i} sec.", 1);
			break;
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
	exec("/usr/local/sbin/unbound -c /var/unbound/unbound.conf 2>&1", $final['result'], $final['retval']);
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


// ADR-10: C-cache flip for a zero-downtime swap. Staleness is ONE-DIRECTIONAL: since #43
// DNSBL blocks set qstate.no_cache_store=1, a block reply is NEVER cached. block->allow needs
// NO flush (decisionDB.clear() suffices); allow->block leaves the previously-resolved answer
// cached until TTL, so ONLY that direction needs a flush, ONLY for newly-blocked names. $names:
// the allow->block delta (alerts Lock passes one domain; feed/cron pass none, accepting
// TTL-bounded staleness — no regression, a restart is equally stale). Each name is VALIDATED as
// a domain (issue #153) before interpolation, dropped otherwise — defence in depth atop
// escapeshellarg(). Pure; coalesced into ONE chroot session, de-duped per name + 'www.' sibling.
function pfb_unbound_py_ccache_flush_cmds($names, $chroot_cmd) {
	$cmds = array();
	if (!is_array($names) || empty($names)) {
		return $cmds;
	}

	// One control session: flush each name + its 'www.' sibling (the alerts unlock path
	// flushes the same pair) so the prior resolved A/AAAA cannot keep serving.
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

	// The '.sync' marker (touched at the start of the data fast path / pfb_update_unbound)
	// tells the DNSBL Queries daemon to stand off the control socket; run the flushes
	// while it is set, coalesced, then let the normal work-file cleanup clear it.
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
function pfb_dnsbl_apply_ledger_update(): void {
	global $pfb;

	if (pfb_dnsbl_converged()) {
		pfb_sync_status_close('dnsbl', 'dnsbl', 'apply', $pfb['dbdir']);
	} else {
		pfb_sync_status_open('dnsbl', 'dnsbl', 'apply',
			'DNSBL apply not converged -- Unbound not fully live with pfb_unbound.py; see error.log',
			$pfb['dbdir']);
	}
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

// Reload Resolver. ADR-10: $datapath signals a pure DNSBL-DATA update (feed/cron or a #51
// custom-list edit) already published atomically to the manifest. When python is live, unbound
// is running, no config change is pending, and the RAM gate fits, this takes the ZERO-DOWNTIME
// fast path (flip the reload sentinel, no restart). $newly_blocked carries the allow->block
// delta to flush from the C-cache after the swap. Any other case falls back to the restart
// (fail-safe; PHP is the PRIMARY gate — never "flip and hope").
function pfb_reload_unbound($mode, $cache=FALSE, $pfbpython=FALSE, $datapath=FALSE, $newly_blocked=array()) {
	global $g, $pfb;

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
					// allow->block C-cache flush (block->allow needs none, #43), now that
					// the block is LIVE. Coalesced, gated behind the '.sync' marker above.
					pfb_unbound_py_ccache_flush($newly_blocked);

					pfb_logger(" completed", 1);
					// Clear the daemon-suppression marker before this early return: the
					// alert/#51 path (pfb_reload_unbound called from pfblockerng_alerts.php)
					// has no later clear_work_files, so '.sync' would otherwise leak and keep
					// the DNSBL Queries daemon suppressed. The restart-fallback paths below
					// reach the normal clear, so this is the only fast-path exit that needs it.
					unlink_if_exists("{$pfb['dnsbl_file']}.sync");
					// ADR-61: this swap just confirmed applied == sentinel -- a second,
					// independent convergence point besides the restart path's completion.
					pfb_dnsbl_apply_ledger_update();
					return;
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

		if ($cache && $pfb['dnsbl_res_cache'] == 'on') {
			exec("{$pfb['chroot_cmd']} dump_cache > " . escapeshellarg($cache_dumpfile) . " 2>&1");
			pfb_logger('.', 1);
		}
	}

	$final = pfb_stop_start_unbound($type);
	pfb_logger('.', 1);

	if ($final['retval'] != 0) {

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

	// Confirm that Resolver is running
	if (is_process_running('unbound')) {
		pfb_logger('.', 1);

		// $final['result'] will be appended with previous result above
		exec("{$pfb['chroot_cmd']} status 2>&1", $final['result'], $final['retval']);
		pfb_logger('.', 1);
		if (preg_grep("/is running.../", $final['result'])) {
			pfb_logger(" completed", 1);

			// Restore Resolver cache
			if ($cache && $pfb['dnsbl_res_cache'] == 'on' && file_exists($cache_dumpfile) && filesize($cache_dumpfile) > 0) {
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
		pfb_dnsbl_apply_ledger_update();
	} else {
		pfb_sync_status_close('dnsbl', 'dnsbl', 'apply', $pfb['dbdir']);
	}

	unlink_if_exists($cache_dumpfile);
}


// Function to clear Unbound/DNSBL work files
function pfb_unbound_clear_work_files() {
	global $pfb;

	foreach (array( $pfb['dnsbl_cache'],
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
			"/var/tmp/unbound_cache_*") as $remove) {
		unlink_if_exists($remove);
	}
}


// Load new DNSBL updates to Unbound Resolver
function pfb_update_unbound($mode, $pfbupdate, $pfbpython) {
	global $g, $pfb;

	if ($mode == 'enabled') {
		$ext = '.bk';
	} else {
		$ext = '.*';	// Remove all DNSBL Unbound files
	}

	// Execute TLD analysis, if configured
	if ($pfb['enable'] == 'on' && $pfb['dnsbl'] == 'on' && !$pfb['save']) {
		if ($pfb['dnsbl_tld']) {
			tld_analysis();
		} else {
			unlink_if_exists("{$pfb['dnsbl_tld_txt']}");
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
	// pfb['keep'] is now 'on'/'off' (PfbLenient); != 'on' covers both 'off' and legacy ''.
	if ($pfb['enable'] == '' && $pfb['keep'] != 'on' && !$pfb['install']) {
		unlink_if_exists("{$pfb['dnsbl_file']}{$ext}");
	}

	// Disable DNSBL
	if (($pfb['enable'] != 'on' || $pfb['dnsbl'] != 'on') && !$pfb['install']) {

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
		// change ($pfbpython TRUE) -> $datapath FALSE -> the restart path. The feed delta
		// (allow->block names) is not cheaply computable here, so no targeted C-cache
		// flush is passed -> accepted TTL-bounded staleness (no worse than the restart,
		// which preserves the resolved cache too).
		$datapath = !$pfbpython;
		pfb_reload_unbound($mode, TRUE, $pfbpython, $datapath);
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

	$dnsbl_cnt = exec("/bin/cat {$pfb['dnsdir']}/*.txt 2>/dev/null | {$pfb['grep']} -c ^");

	// ADR-06: pfb_py_count is now Python-emitted and means the LOADED entry total
	// (len(dataDB)+len(zoneDB)), written by pfb_unbound.py dnsbl_emit_count(). The
	// lists are no longer dedup/collapse/whitelist/TOP1M-pruned at build time, so
	// this value legitimately differs from (and is typically >=) the raw '*.txt'
	// feed line count. The old subtract-and-compare sync-check (which assumed the
	// count meant 'entries removed by subdomain collapse') no longer applies; just
	// report both numbers for visibility.
	$loaded_cnt = trim((string) @file_get_contents($pfb['unbound_py_count']));
	$log = "\nDNSBL update [ feed lines: {$dnsbl_cnt} | loaded entries: {$loaded_cnt} ]... completed";
	pfb_logger("{$log}", 1);

	// ADR-48 (issue #789): emit stage=entries reject lines for any feed
	// with a nonzero per-entry tally, BEFORE clearing work files.
	pfb_emit_entry_reject_stats($pfb['unbound_py_reject_stats']);

	// Clear work files
	pfb_unbound_clear_work_files();
	pfb_logger("\n------------------------------------------------------------------------", 1);
}


// Process TOP1M database
// $provider_override (ADR-59 test seam): when given, its 'parse'/'header'/
// 'domain_col' knobs drive the builder directly instead of resolving through
// pfb_top1m_providers()[$pfb['dnsbl_top1m_type']->value] -- lets a unit test
// exercise a synthetic descriptor's knobs without a live provider. Production
// never passes it, so the resolved-provider path is exactly today's behaviour.
function pfblockerng_top1m(?array $provider_override = NULL) {
	global $pfb;

	if (empty($pfb['dnsbl_top1m_inc'])) {
		pfb_logger("\n  TOP1M: No TLD Inclusions found.\n", 1);
		return;
	}

	// ADR-59: the active provider descriptor drives the parse knobs below.
	// $pfb['dnsbl_top1m_type'] may be unset in an isolated unit-test context
	// (it is normally set by pfb_global() -- PfbConfig::read('alexa_type') --
	// which some tests never call); default to Tranco, the same absent-default
	// the registry itself uses, so the resolved shape stays rank_domain/zip.
	$top1m_type	= $pfb['dnsbl_top1m_type'] ?? PfbTop1mSource::Tranco;
	$top1m_provider	= $provider_override ?? (pfb_top1m_providers()[$top1m_type->value] ?? array());
	$top1m_parse	= $top1m_provider['parse'] ?? 'rank_domain';
	$top1m_header	= $top1m_provider['header'] ?? FALSE;
	$top1m_domcol	= $top1m_provider['domain_col'] ?? 1;

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

				// ADR-59: Cloudflare's dataset is a SINGLE 'domain' column (domain_col
				// 0) -- a real data line has no comma at all (no column to split), so the
				// comma requirement below would wrongly reject every line. Only demand a
				// comma when a real multi-column split is expected (domain_col > 0, every
				// other provider today); domain_col 0 still requires a '.' (every domain
				// has one).
				$top1m_needs_comma = $top1m_domcol > 0;
				if (strpos($line, '.') === FALSE || empty($line) ||
				    ($top1m_needs_comma && strpos($line, ',') === FALSE)) {
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
				$csvline = str_getcsv($line, ',', '"', "\\");
				// #920: fold once here -- the GUI's inclusion keys are always lowercase
				// (pfblockerng_dnsbl.php's $options_alexa_inclusion), so an uppercase/
				// mixed-case feed domain otherwise passes every guard below but silently
				// fails the isset($pfb_include[$tld]) compare; folding here also feeds
				// the 'www.' strip and the write, so every downstream use is canonical.
				$domain = strtolower($csvline[$top1m_domcol] ?? '');
				if ($top1m_parse === 'rank_domain' && !ctype_digit((string) ($csvline[0] ?? ''))) {
					continue;
				}
				// #920: the `D` modifier anchors '$' to the true string end -- without it, a
				// quoted-unterminated CSV field (str_getcsv() retains its trailing "\n", unlike
				// every other field shape) wrongly passes and can flip a garbage-only feed from
				// dead (preserve) to valid (wipe), the same class of bug the #886/#892 guards fix.
				if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9.-]*\.(?:[A-Za-z]{2,}|[Xx][Nn]--[A-Za-z0-9][A-Za-z0-9-]+)$/D', $domain)) {
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

					// Create three whitelist options per TOP1M whitelisted Domain
					@fwrite($pfb_output, ".{$domain},,\n,{$domain},,\n,www.{$domain},,\n");
				}

				if ($x >= $pfb['dnsbl_top1m_cnt']) {
					break;
				}
			}
			@fclose($pfb_output);
			@fclose($handle);

			if ($linecnt === 0) {
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

	$parts	= explode('/', $ipaddr);
	$subnet	= $parts[0];
	$mask	= $parts[1] ?? '';	// '' (not undef) when no CIDR

	// An IPv4 prefix length must be 0..32; drop the line outright. A substring
	// strip here (str_replace('32', '')) used to rewrite an invalid mask into a
	// valid, far broader one (/132 -> /1 = half of IPv4) (issue #719).
	if ($mask !== '' && (!ctype_digit($mask) || (int)$mask > 32)) {
		return;
	}

	// An explicit /0 covers the entire IPv4 space and is never honored from a
	// downloaded feed: clamp to a single host so the address itself stays
	// blocked (issue #744). Custom-list entries are user-authored, so /0 is
	// kept as written (e.g. 0.0.0.0/0 referenced by a manual rule).
	if ($mask !== '' && (int)$mask === 0 && !$custom) {
		// Unlike the v6 sibling, callers reach this before validate_ipv4(), so
		// $ipaddr is raw feed text — strip control chars to keep the log clean.
		pfb_logger("\n  Feed /0 CIDR clamped to single host: " . preg_replace('/[[:cntrl:]]/', '', $ipaddr), 1);
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

	// Exclude private/reserved IPs (bypass exclusion for custom lists)
	if ($pfb['supp'] == 'on' && !$custom) {

		// Remove 'loopback' and '0.0.0.0' IPs
		if ($ip[0] == 127 || $ip[0] == 0 || empty($ip[0])) {
			return;
		}

		// Advanced IPv4 Tunable (Set CIDR Block size limit)
		if ($pfbcidr != 'Disabled' && !empty($mask) && $mask < $pfbcidr) {
			pfb_logger("\n  Suppression CIDR Limit: {$ip_final}/{$mask}", 1);
			$mask = '32';
		}

		if (!filter_var($ip_final, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== FALSE) {
			return;
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
			return;
		}
	}

	// '!== '' (not !empty()): empty('0') is TRUE, which silently collapsed a
	// custom list's honored /0 to a bare host (issue #744).
	if ($mask !== '') {
		return "{$ip_final}/{$mask}";
	}
	return "{$ip_final}";
}


// IPv6 sibling of sanitize_ipaddr(): excludes private/reserved/loopback IPv6 from loaded block
// lists when Suppression is enabled; a feed's explicit /0 clamps to a single host (issue #744).
// Also drops documentation (RFC 3849), multicast, and the NAT64 prefix (RFC 6052), which PHP's
// filter flags leave routable (issue #760) — explicit prefix checks so behaviour is independent
// of PHP's patch level (RFC 6890 moved 2001:db8::/32 between filter sets in 8.3.16/8.4.3).
// $pfbcidr: per-category Advanced "Suppression CIDR Limit" floor (issue #760 §3).
// Returns the canonical inet_ntop() form (issue #1084): textual variants of one
// address (case, zero-run, leading zeros) collapse to one string, and an
// unparseable address is dropped rather than passed through.
function sanitize_ipaddr_v6($ipaddr, $custom, $pfbcidr = 'Disabled') {
	global $pfb;

	// Extract the address part (before '/' for a CIDR like 'fc00::/7')
	$parts	= explode('/', $ipaddr);
	$s_ip	= $parts[0];
	$mask	= $parts[1] ?? '';

	// issue #1084: single inet_pton() per address, reused by the suppression
	// reserved-prefix checks below; an unparseable address drops the row. A %zone
	// form is dropped explicitly first -- inet_pton()'s handling of it is
	// platform-dependent (FreeBSD/glibc reject it, macOS strips the zone).
	if (strpos($s_ip, '%') !== FALSE) {
		return;
	}
	$bin = inet_pton($s_ip);
	if ($bin === FALSE) {
		return;
	}

	// An explicit /0 covers the entire IPv6 space and is never honored from a
	// downloaded feed: clamp to a single host so the address itself stays
	// blocked (issue #744). Custom-list entries are user-authored, so /0 is
	// kept as written.
	$mask_clamped = FALSE;
	if ($mask !== '' && ctype_digit($mask) && (int)$mask === 0 && !$custom) {
		pfb_logger("\n  Feed /0 CIDR clamped to single host: {$ipaddr}", 1);
		$mask_clamped = TRUE;
	}

	// Exclude private/reserved IPs (bypass exclusion for custom lists)
	if ($pfb['supp'] == 'on' && !$custom) {

		// Advanced IPv6 Tunable (Set CIDR Block size limit) (issue #760 §3).
		// A /0 was already clamped above (mask stays '0', never > 0, so this
		// guard never double-clamps it). All three feed call sites gate on
		// validate_ipv6() BEFORE calling this function, so $mask is already
		// 0-128 here; the ctype_digit()/range checks are defensive redundancy
		// for any direct caller that skips that guard.
		if ($pfbcidr != 'Disabled' && $mask !== '' && ctype_digit($mask) && (int)$mask > 0 && (int)$mask < (int)$pfbcidr) {
			pfb_logger("\n  Suppression CIDR Limit: {$s_ip}/{$mask}", 1);
			$mask_clamped = TRUE;
		}

		// Drop ULA (fc00::/7), link-local (fe80::/10), loopback (::1),
		// IPv4-mapped and the reserved set (mirrors inc:7118-7119).
		if (!filter_var($s_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) ||
		    !filter_var($s_ip, FILTER_CALLBACK, array('options' => 'FILTER_FLAG_NO_LOOPBACK_RANGE'))) {
			return;
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
			return;
		}
	}

	// issue #1084: canonical inet_ntop() form; mask re-appended only when
	// neither clamp above dropped it.
	if ($mask !== '' && !$mask_clamped) {
		return inet_ntop($bin) . '/' . $mask;
	}
	return inet_ntop($bin);
}


// Validate IPv4 IP addresses
function validate_ipv4($ipaddr) {
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

	// Find exact IP match
	$q_ip	= escapeshellarg(str_replace('.', '\.', "^{$ip}"));
	// issue #833: /dev/null forces grep to always be given >=2 files, so it
	// always emits the "path:" prefix -- even when $pfbfolder's glob resolves to
	// exactly ONE .txt file. Without it, pfb_parse_query() gets an unprefixed
	// line and returns a 1-element array (no [1]), corrupting every downstream
	// consumer that reads it.
	$query	= exec("{$pfb['grep']} -s {$q_ip} {$pfbfolder} /dev/null 2>&1");
	if (!empty($query)) {
		$rx = pfb_parse_query($query);
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
			return $rx;
		}
	}

	unset($result);
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


// issue #809: the exact per-row query derivation convert_ip_log() (pfblockerng_alerts.php)
// needs before validating/re-locating a reported IP — extracted VERBATIM so the batched
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
		$folder = "{$pfb['matchdir']}/*.txt {$pfb['nativedir']}/*.txt";
	}

	// Determine if event IP still exists in Feed Aliastable -- builds the exact validate
	// command convert_ip_log() execs (via its page-scope memo); NULL reproduces today's
	// `$validate = '';` no-exec guard (an 'Unknown' evaluated IP or feed name never ran a
	// validate exec at all).
	$validate_file_cmd = NULL;
	$validate_cmd	    = NULL;
	if ($fields[14] != 'Unknown' && $fields[15] != 'Unknown') {
		$q_ip = str_replace('.', '\.', $fields[14]);

		$q_ip_esc = escapeshellarg("^{$q_ip}");

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


// issue #809: promotes convert_ip_log()'s two function-static memo stores ($validate_memo /
// $ip_miss_memo, pfblockerng_alerts.php) to a reference-returning accessor so the batched
// prefetch pass below (pfb_ip_prefetch()) can seed them from OUTSIDE convert_ip_log(). Same
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
// instead of exercising its own pfb_ip_prefetch() call). Mirrors
// pfb_dnsbl_prefetch_store(NULL)'s reset contract for the DNSBL-side store.
function pfb_ip_render_memos_reset(): void {
	$memos = &pfb_ip_render_memos();
	$memos = array('validate' => array(), 'miss' => array());
}


// Shared write-outcome check for a batched-prefetch pattern-file write (issue #809
// review, B3/R1). file_put_contents() returns FALSE on total failure, or the number of
// bytes actually written -- a partial write (e.g. a full disk) returns a SHORT byte
// count, not FALSE, so a bare `=== FALSE` check alone misses it. Comparing the return
// value against strlen($data) catches both failure shapes; only an exact full-length
// write counts as complete. Shared by pfb_ip_prefetch_grep_lines() and
// pfb_dnsbl_prefetch_grep() so both pattern-file writers apply the identical rule.
function pfb_prefetch_pattern_file_write_ok($written, string $data): bool {
	return $written !== FALSE && $written === strlen($data);
}


// Run ONE batched `grep -f <patternfile>` pass, sharing the pattern-file plumbing across every
// IP-table batched round (validate / miss-header / aliastables) below. Returns every matched
// line (not a first-match map, unlike pfb_dnsbl_prefetch_grep()) since callers attribute
// possibly-many lines per candidate themselves. The pattern-file path is inserted between
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
// order) that "belongs" to $raw_prefix — reproducing per-row exec()'s "last stdout line"
// semantics from a batched multi-pattern grep pass whose output interleaves every candidate's
// matches. A line belongs under either grep shape: unprefixed (single file matched, line IS
// the content) or file-prefixed ("path:content", path always contains '/', so the substring
// after the FIRST ':' is the content) — preserving grep's own prefix-match quirk (`^1.2.3.4`
// also matches `1.2.3.45`) for behaviour-identity with the exec it replaces. The colon-fallback
// requires the segment BEFORE ':' to contain '/', else an unprefixed IPv6 line could misattribute.
function pfb_ip_prefetch_last_match(array $lines, string $raw_prefix): ?string {

	$match = NULL;
	foreach ($lines as $line) {
		if (str_starts_with($line, $raw_prefix)) {
			$match = $line;
			continue;
		}
		$colon_pos = strpos($line, ':');
		if ($colon_pos !== FALSE &&
		    strpos(substr($line, 0, $colon_pos), '/') !== FALSE &&
		    str_starts_with(substr($line, $colon_pos + 1), $raw_prefix)) {
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

	// Round A (exact): same command shape as find_reported_header()'s exact-match exec,
	// batched into one `-f patternfile` pass. pfb_ip_prefetch_last_match() recovers each
	// host's own LAST matching line from the shared batched output, reproducing what a
	// per-row `exec()` (last-line-of-output) call would have returned for that host alone.
	$patterns = array();
	foreach ($hosts as $host) {
		$patterns[] = '^' . str_replace('.', '\.', $host);
	}
	// issue #833: /dev/null forces the same file-prefix output as find_reported_
	// header()'s own exact-match exec, even for a single-file $pfbfolder glob.
	$lines = pfb_ip_prefetch_grep_lines("{$pfb['grep']} -s -f", "{$pfbfolder} /dev/null 2>&1", $patterns);

	if ($lines === NULL) {
		$grep_failed = array_fill_keys($hosts, TRUE);
		return $out;
	}

	$missed = array();
	foreach ($hosts as $host) {
		$match = pfb_ip_prefetch_last_match($lines, $host);
		if ($match !== NULL) {
			$out[$host] = pfb_parse_query($match);
		} else {
			$missed[] = $host;
		}
	}

	if (empty($missed)) {
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

	return $out;
}


// Batch every buffered, filter-ACCEPTED row's render-time IP lookups ahead of the per-type IP
// table's replay pass: the validate round (is the logged IP/CIDR still in its feed file), the
// miss round (find_reported_header()'s exact + prefix/CIDR search), and the aliastables round
// (which alias table now holds the resolved IP), each collapsed from one exec() per row to at
// most one grep pass per distinct group. Seeds pfb_ip_render_memos() — convert_ip_log()
// consults the same memo stores, falling back to its own per-row exec for anything unseeded.
// $rows: one entry per buffered, filter-accepted row — 'host', 'folder', 'eval_ip_raw',
// 'validate_file_cmd'/'validate_cmd' from pfb_ip_render_query() (both NULL when unused).
function pfb_ip_prefetch(array $rows): void {
	global $pfb;

	if (empty($rows)) {
		return;
	}

	$memos = &pfb_ip_render_memos();

	// --- Validate round: group by the shared file-listing pipeline -------------------
	$validate_groups = array();
	foreach ($rows as $row) {
		if ($row['validate_cmd'] === NULL) {
			continue;	// mirrors convert_ip_log()'s own no-exec guard -- never validated
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
			$patterns[] = '^' . str_replace('.', '\.', $raw_ip);
		}
		$patterns = array_values(array_unique($patterns));

		$lines = pfb_ip_prefetch_grep_lines("{$group['file_cmd']} | xargs {$pfb['grep']} -f", '2>&1', $patterns);
		if ($lines === NULL) {
			// B3 (issue #809 review): this group's pattern file could not be created/
			// written -- leave every row in it UNSEEDED (never cache a false ''/no-hit)
			// so convert_ip_log()'s own per-row exec fallback runs for them instead.
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
		return;
	}

	// Round A/B (batched find_reported_header()), grouped by folder. NOTE -- quirk
	// PRESERVED, not introduced by this phase: convert_ip_log()'s own miss-round call is
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
		$alias_patterns[] = '^' . str_replace('.', '\.', $eval_new);
	}
	$alias_patterns = array_values(array_unique($alias_patterns));

	// issue #833: '/dev/null' rides ahead of xargs's own appended file list, so
	// grep always has >=2 files and always emits the "path:" prefix, matching
	// convert_ip_log()'s own per-row aliastables exec (pfblockerng_alerts.php)
	// which needs that same forced-prefix fix for its downstream alias-name parse.
	$alias_lines = pfb_ip_prefetch_grep_lines(
		"/usr/bin/find {$pfb['aliasdir']}/*.txt -type f | xargs {$pfb['grep']} -f",
		'/dev/null 2>&1',
		$alias_patterns
	);
	if ($alias_lines === NULL) {
		// B3: the aliastables pattern file could not be created/written -- leave every
		// remaining row unseeded (per-row fallback fires for all of them).
		return;
	}

	foreach ($eval_new_by_key as $miss_key => $eval_new) {
		$pfb_query    = $headers_by_host_folder[$miss_key];
		$raw_validate = pfb_ip_prefetch_last_match($alias_lines, $eval_new) ?? '';
		$memos['miss'][$miss_key] = array($pfb_query, $raw_validate);
	}
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
	$raw = PfbConfig::read('pfb_feed_internal_allowlist');
	if (!is_string($raw) || $raw === '') {
		return array();
	}

	// The allowlist is stored base64-encoded, like every other pfBlockerNG textarea
	// (suppression / whitelist / custom; see pfbng_text_area_decode). Decode before
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


// Grandfather decision for the feed-host filter at install/upgrade. $gconfig is the
// existing General-settings 'config/0' node (null on a fresh, never-configured install).
// Returns 'off' only for an already-configured install that has not yet seen the toggle
// (so its existing feeds are never silently dropped); otherwise NULL — meaning leave the
// key unset, which the runtime reader (pfb_feed_filter_enabled) interprets as the ON
// default. Run-once + idempotent: once the key is set (either value) it returns NULL,
// never re-disabling an operator who opted back in.
function pfb_feed_filter_install_default($gconfig) {

	if (is_array($gconfig) && !isset($gconfig['pfb_feed_internal_filter'])) {
		return 'off';
	}
	return NULL;
}


// ADR-40: alias-table apply-mode grandfather decision the install/upgrade hook applies.
// $gconfig is the existing General-settings 'config/0' node (null on a fresh, never-configured
// install). A new install takes the registry absent-default 'auto' (delta for small churn, full
// replace for large churn / boot); an
// already-configured install that has not yet seen the key is pinned to 'replace' (the pre-ADR-40
// full -T replace) so the upgrade preserves that operator's prior apply behaviour instead of
// silently switching to delta. Run-once + idempotent: once the key is set (any value) it returns
// NULL, so a later save never overrides an operator's explicit choice.
function pfb_alias_delta_mode_install_default($gconfig) {

	if (is_array($gconfig) && !isset($gconfig['pfb_alias_delta_mode'])) {
		return 'replace';
	}
	return NULL;
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


// ADR-22: one-time upgrade migration for the 'pfb_dnsbl_lenient' DNSBL scheme-parsing toggle.
// New installs default to OFF (strict RFC 3986 parsing); an EXISTING install (non-empty
// $dconfig, distinguishing upgrade from first-ever install) that predates this key is migrated
// to 'on' (lenient) to preserve the permissive behaviour it already relies on. Migration ONLY
// sets a missing key — an existing 'on'/'off' value is never overwritten. Returns the updated
// config, or NULL when nothing should change (fresh install, or the key already present).
function pfb_dnsbl_lenient_migrate($dconfig) {

	if (!is_array($dconfig) || empty($dconfig)) {
		return NULL;
	}
	if (isset($dconfig['pfb_dnsbl_lenient'])) {
		return NULL;
	}
	$dconfig['pfb_dnsbl_lenient'] = 'on';
	return $dconfig;
}


// Issue #281: one-time upgrade seed for the 'pfb_keep' General-settings flag. The
// pre-deinstall hook wipes ALL pfBlockerNG config sections unless pfb_keep == 'on';
// the GUI default is 'on' but it only persists to config.xml once General settings are
// saved. On an EXISTING install (a populated General config section) that predates the
// key, seed it to 'on' so a later pkg upgrade's pre-deinstall preserves user settings.
// A fresh install has no prior section -> NULL (no write); the runtime default in
// pfb_global() covers it. An existing value (including an explicit '' = off) is never
// overwritten. Returns the updated config array to persist, or NULL when nothing changes.
function pfb_keep_migrate($gconfig) {

	if (!is_array($gconfig) || empty($gconfig)) {
		return NULL;
	}
	if (isset($gconfig['pfb_keep'])) {
		return NULL;
	}
	$gconfig['pfb_keep'] = 'on';
	return $gconfig;
}


// Whether the feed-host internal-address filter is enabled. Reads the General-settings
// 'pfb_feed_internal_filter' on/off flag, defaulting to ON when the key is absent (a
// fresh install ships the filter active; the install-time migration pins it OFF on an
// already-configured box so existing feeds are never silently dropped). Any value other
// than the literal 'off' is treated as ON.
function pfb_feed_filter_enabled() {

	$value = PfbConfig::read('pfb_feed_internal_filter');
	return ($value !== 'off');
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

	if (!is_string($location) || trim($location) === '') {
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


// Function to download feeds. Optional $response_meta — when a non-NULL reference is passed
// (detector probe mode), filled with ['status' => <http_status_string>, 'etag' => <ETag or
// ''>, 'lastmod' => <epoch or 0>]; the two sync callers in this file do NOT pass it, so their
// behaviour is unchanged. Optional $extra_headers (ADR-59) — caller-supplied HTTP header
// strings (e.g. a Cloudflare Radar 'Authorization: Bearer <token>'), merged with the
// conditional-GET header via pfb_download_http_headers(). The TOP1M provider is the first
// caller; every other feed still passes none, so its CURLOPT_HTTPHEADER behaviour is unchanged.
function pfb_download($list_url, $file_dwn, $pflex=FALSE, $header, $format, $logtype, $vtype='', $timeout=300, $type='', $username='', $password='', $srcint=FALSE, &$response_meta=NULL, array $extra_headers=array()) {
	global $pfb;
	$http_status = '';
	$elog = ">> {$pfb['log']} 2>&1";

	// Remove any leading/trailing whitespace
	$list_url = trim($list_url);

	// Re-evaluate URL
	if ($format == 'whois') {
		if (empty(pfb_filter($list_url, PFB_FILTER_DOMAIN, 'pfb_download'))) {
			pfb_logger("\n Failed", 2);
			return FALSE;
		}
	}
	elseif ($format == 'asn') {
		if (empty(pfb_filter($list_url, PFB_FILTER_ALNUM, 'pfb_download'))) {
			pfb_logger("\n Failed", 2);
			return FALSE;
		}
	}
	elseif (!pfb_filter($list_url, PFB_FILTER_URL, 'pfb_download_failure')) {
		// Issue #811: land the header-scoped, reason-bearing skip line in the main log
		// when the feed-host guard is why entry vetting failed (pfb_filter's own reject
		// line goes to error.log only). See pfb_log_feed_host_reject().
		pfb_log_feed_host_reject($list_url, $header, $logtype);
		pfb_logger("\n Failed", 2);
		return FALSE;
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
				return FALSE;
			}

			// Pin the connection to the vetted IP (substitute it for the host in the
			// rsync source). Fail closed if the source form can't be parsed to do so.
			$rsync_src = pfb_rsync_pin_url($list_url, $rsync_pinned);
			if ($rsync_src === '') {
				$log = "\n[ {$header} ] feed host could not be pinned \xe2\x80\x94 skipped\n";
				pfb_logger("{$log}", "{$logtype}");
				return FALSE;
			}
		}
		$rsync_src_esc = escapeshellarg("{$rsync_src}");

		// exec() returns the command's LAST output line, not its exit status; the
		// real return code rides in the third argument. Test that, so a normal
		// rsync transfer (which prints progress/stats) is not mistaken for a failure.
		exec("/usr/local/bin/rsync --timeout=5 {$rsync_src_esc} {$file_dwn_esc}", $rsync_output, $rsync_rc);
		if ($rsync_rc === 0) {
			$http_status = '200';
		} else {
			$rsync_msg = trim(implode(' ', $rsync_output));
			$log = "\n  RSYNC Failed (exit {$rsync_rc})" . ($rsync_msg !== '' ? ": {$rsync_msg}" : '') . "...\n";
			pfb_logger("{$log}", "{$logtype}");
			return FALSE;
		}
	}
	elseif ($format == 'whois' || $format == 'asn') {
		// Convert a Domain name/AS into its respective IP addresses
		exec("{$pfb['script']} whoisconvert {$header_esc} {$vtype} {$list_url_esc} {$elog}");
		return TRUE;
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
				return FALSE;
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
				return FALSE;
			}

			if (($fhandle = @fopen("{$file_download}", 'w')) !== FALSE) {
				if (!($ch = curl_init("{$list_download}"))) {
					$log = "\nFailed to create cURL resource... Exiting...\n";
					pfb_logger("{$log}", "{$logtype}");
					return FALSE;
				}

				// Load curl default settings — incl. the CURLOPT_PROTOCOLS scheme allow-list
				// (an independent libcurl-layer backstop to PFB_FILTER_URL) and gzip encoding.
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
				if ($feed_pinned !== '' && $feed_host !== '' && !empty($feed_scheme)) {
					$feed_port	= $url_parts['port'] ?? ($scheme_ports[$feed_scheme] ?? 0);
					if ($feed_port > 0) {
						curl_setopt($ch, CURLOPT_RESOLVE, array("{$feed_host}:{$feed_port}:{$feed_pinned}"));
					}
				}

				if (!empty($username) && !empty($password)) {
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
						return FALSE;
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
						return FALSE;
					}

					// Discard the redirect-page body so only the final hop's body
					// remains in the feed file.
					ftruncate($fhandle, 0);
					rewind($fhandle);

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

	// Probe mode for the cron detector (type='change_detect'): fill $response_meta when
	// the caller requested it (ADR-42 conditional-GET path), then return.
	// A 304 means "not modified" — the server confirmed the feed unchanged; the
	// caller (pfb_update_check detector) handles the 304 via pfb_conditional_get_decision.
	// Any 200 means the body was downloaded to {file_dwn}.raw; the caller hashes it.
	// Any other status means the probe failed; the caller fails-safe to re-ingest.
	//
	// CONTRACT: the caller MUST pass $response_meta = array() (not NULL) to activate
	// the fill block.  NULL is the sentinel for the two sync callers that do NOT want
	// the block filled; NULL !== NULL is always FALSE, so NULL silently skips the fill.
	if ($type == 'change_detect') {
		if ($response_meta !== NULL) {
			$response_meta = array(
				'status'  => (string) $http_status,
				'etag'    => isset($response_etag) ? $response_etag : '',
				'lastmod' => isset($remote_stamp) && $remote_stamp > 0 ? (int) $remote_stamp : 0,
			);
		}
		if ($http_status == '304' || $http_status == '200') {
			return TRUE;
		}
		return FALSE;
	}

	// Remove any downloaded files with md5 extension
	unlink_if_exists("{$md5_download}");

	// '304 not modified' - Utilize previously downloaded file if available
	if ($http_status == '304' && file_exists("{$orig_download}")) {
		return TRUE;
	}

	if (file_exists($file_download) && ($http_status == '200' || $http_status == '221' || $http_status == '226')) {

		// issue #1158: fail-safe default -- with unset(), paths that assigned nothing fell
		// through $retval == 0 as success
		$retval = 1;

		// Validate File Mime-type
		$reject_detail = array();
		$file_type = pfb_filter(array("{$file_dwn_esc}", "{$file_download}", "{$list_download}"), PFB_FILTER_FILE_MIME, 'pfb_download', '', FALSE, $reject_detail);
		if (!$file_type) {
			pfb_validate_log($header, 'mime', 'mime_not_allowed', pfb_reject_detail_summary($reject_detail));
			return FALSE;
		}

		// ADR-49: opt-in plain-text sanity scan on accepted text feeds. The flag is
		// checked FIRST -- when default-off it short-circuits before THIS scan's own
		// MIME-scope check (the in_array below) and the sample read, so an off install
		// adds no work here (ADR-28 conv 2). ($file_type was already produced by the
		// upstream FILE_MIME check above; this gate only narrows to the text types.)
		// 'application/csv' rides with 'text/csv' -- same CSV body, just a different
		// libmagic verdict (both are allow-listed synonyms; see pfb_filter FILE_MIME).
		if (PfbConfig::read('pfb_feed_sanity') === PfbToggle::On &&
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
					return FALSE;
				}
			}
		}

		// Create update file markers on new downloads available
		switch($type) {
			case 'geoip':
				touch("{$pfb['dbdir']}/geoip.update");
				break;
			case 'top1m':
				touch("{$pfb['dbdir']}/top-1m.update");
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

		// Decompress file if required
		if ($file_type == 'application/x-gzip' || $file_type == 'application/gzip') {
			if (!pfb_validate_archive($file_download, $file_type)) {
				pfb_validate_log($header, 'structural', 'probe_failed', "{$file_type} " . basename($file_download));
				unlink_if_exists($file_download);
				return FALSE;
			}
			if ($type == 'geoip') {
				// Extras - MaxMind downloads
				// ADR-46: disk-writing extraction -- reject hostile member names first
				// (a NULL member list = unlistable archive rejects too, fail-closed).
				$unsafe_member = pfb_archive_unsafe_member(pfb_archive_member_names($file_download));
				if ($unsafe_member !== NULL) {
					pfb_validate_log($header, 'member', 'unsafe_member_name', $unsafe_member);
					unlink_if_exists($file_download);
					return FALSE;
				}
				exec("/usr/bin/tar -xzf {$file_dwn_esc} --strip=1 -C {$pfb['geoipshare']} >/dev/null 2>&1");
				unlink_if_exists($file_download);
				return TRUE;
			}
			elseif ($type == 'asn') {
				exec("/usr/bin/gunzip -c {$file_dwn_esc} > {$header_esc}", $output, $retval);

				// Update ASN Lookup table definitions
				exec("{$pfb['script']} asn_table {$elog}");

				unlink_if_exists($file_download);
				return TRUE;
			}
			elseif ($type == 'top1m') {
				// ADR-59: a gz-container TOP1M provider decompresses straight to
				// the destination CSV pfblockerng_top1m() reads (no rename/staging).
				exec("/usr/bin/gunzip -c {$file_dwn_esc} > {$header_esc}", $output, $retval);
				unlink_if_exists($file_download);
				return TRUE;
			}
			elseif ($type == 'blacklist') {
				// Extras - Blacklist downloads
				@rename("{$file_download}", strstr("{$file_download}", '.raw', TRUE));
				$file_esc = trim(escapeshellarg("{$file_dwn}"), "'");
				$filename = basename("{$file_esc}", '.tar.gz');

				if (!empty(pfb_filter($filename, PFB_FILTER_WORD, 'pfb_download category'))) {
					rmdir_recursive("{$pfb['dbdir']}/{$filename}/");
					safe_mkdir("{$pfb['dbdir']}/{$filename}/");

					// ADR-46: disk-writing extraction of a THIRD-PARTY archive (member
					// names feed on-disk filenames) -- reject hostile member names first
					// (a NULL member list = unlistable archive rejects too, fail-closed).
					$unsafe_member = pfb_archive_unsafe_member(pfb_archive_member_names($file_dwn));
					if ($unsafe_member !== NULL) {
						pfb_validate_log($header, 'member', 'unsafe_member_name', $unsafe_member);
						unlink_if_exists($file_dwn);
						return FALSE;
					}

					// Extract Blacklist categories from sub-folders into a single folder structure
					$cmd = "--include='*domains' -s',.*/\\(.*\\)/\\(.*\\)/domains,{$filename}_\\1_\\2,' -s',.*/\\(.*\\)/domains,{$filename}_\\1,'";
					$filename_esc = escapeshellarg("{$pfb['dbdir']}/{$filename}/");
					exec("/usr/bin/tar -xf " . escapeshellarg("{$file_dwn}") . " {$cmd} -C {$filename_esc} >/dev/null 2>&1");

					// Rename any Category files with dashes
					$verifydir = "{$pfb['dbdir']}/{$filename}";
					if (is_dir("{$verifydir}")) {
						$list = glob("{$verifydir}/{$filename}*");
						if (is_array($list) && !empty($list)) {
							foreach ($list as $verify) {
								if (strpos($verify, '-') !== FALSE) {
									rename($verify, str_replace('-', '_', $verify));
								}
							}
						}
					}

					// Create update file indicator for update process
					touch("{$pfb['dbdir']}/{$filename}/{$filename}.update");
					$retval = 0;
				}
				else {
					pfb_logger("\n Invalid filename [{$filename}]", 1);
					return FALSE;
				}
			}
			else {
				$reject_detail = array();
				if (!pfb_filter(array("{$file_dwn_esc}", "{$file_download}", "{$list_download}"), PFB_FILTER_FILE_MIME_COMPRESSED, 'pfb_download', '', FALSE, $reject_detail)) {
					pfb_validate_log($header, 'inner', 'compressed_mime_not_allowed', pfb_reject_detail_summary($reject_detail));
					return FALSE;
				}
				pfb_logger('.', 1);
				exec("/usr/bin/gunzip -c {$file_dwn_esc} > {$file_org_esc}", $output, $retval);
			}
		}
		elseif ($file_type == 'application/x-bzip2') {
			if (!pfb_validate_archive($file_download, $file_type)) {
				pfb_validate_log($header, 'structural', 'probe_failed', "{$file_type} " . basename($file_download));
				unlink_if_exists($file_download);
				return FALSE;
			}
			$reject_detail = array();
			if (!pfb_filter(array("{$file_dwn_esc}", "{$file_download}", "{$list_download}"), PFB_FILTER_FILE_MIME_COMPRESSED, 'pfb_download', '', FALSE, $reject_detail)) {
				pfb_validate_log($header, 'inner', 'compressed_mime_not_allowed', pfb_reject_detail_summary($reject_detail));
				return FALSE;
			}
			pfb_logger('.', 1);
			exec("/usr/bin/bzip2 -dkc {$file_dwn_esc} > {$file_org_esc}", $output, $retval);
		}
		elseif ($file_type == 'application/zip') {
			if (!pfb_validate_archive($file_download, $file_type)) {
				pfb_validate_log($header, 'structural', 'probe_failed', "{$file_type} " . basename($file_download));
				unlink_if_exists($file_download);
				return FALSE;
			}

			// Extras - MaxMind/TOP1M downloads
			if ($type == 'geoip' || $type == 'top1m') {
				// Determine if the Zip contains multiple files. A NULL list (unlistable)
				// falls through to the stdout branch below -- no disk write, no traversal
				// surface -- and the extraction fails on its own exactly as before.
				$archive_members = pfb_archive_member_names($file_download);
				if ($archive_members !== NULL && count($archive_members) > 1) {
					// ADR-46: disk-writing extraction -- reject hostile member names first.
					$unsafe_member = pfb_archive_unsafe_member($archive_members);
					if ($unsafe_member !== NULL) {
						pfb_validate_log($header, 'member', 'unsafe_member_name', $unsafe_member);
						unlink_if_exists($file_download);
						return FALSE;
					}
					exec("/usr/bin/tar -xf {$file_dwn_esc} --strip=1 -C {$header_esc} >/dev/null 2>&1");
				} else {
					// ADR-46: stdout extraction -- member names never reach the
					// filesystem, so no member-name guard is needed here.
					exec("/usr/bin/tar -xOf {$file_dwn_esc} > {$header_esc}");
				}
				return TRUE;
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
				return FALSE;
			}
			*/
	
			// Check if ZIP archive contains xlsx files
			$xlsxtest = exec("/usr/bin/tar -tf {$file_dwn_esc}");
			if (strpos($xlsxtest, '.xlsx') !== FALSE) {
				unlink_if_exists("{$orig_download}");
				exec("{$pfb['script']} xlsx {$header_esc} {$elog}");
				if (file_exists("{$orig_download}")) {
					$retval = 0;
				}
			} else {
				pfb_logger('.', 1);
				// Process ZIP file (SFS and hpHosts workaround)
				// pipefail so a tar extraction failure is not masked by the trailing
				// tr (issue #819); this exec runs on the appliance only -- FreeBSD sh
				// supports `set -o pipefail`.
				// ADR-46: stdout extraction (-xOf) -- member names never reach the
				// filesystem, so no member-name guard is needed on this path.
				exec("set -o pipefail; /usr/bin/tar -xOf {$file_dwn_esc} | /usr/bin/sed 's/,[[:space:]]/; /g' | /usr/bin/tr ',' '\n' > {$file_org_esc}", $output, $retval);
			}

			// ZIP inner-content gate (issue #808): probe the EXTRACTED payload
			// (orig_download), not the outer archive -- the outer container is
			// already covered by ADR-44's pfb_mime_normalise().
			$reject_detail = array();
			if (!pfb_filter(array("{$file_org_esc}", "{$orig_download}", "{$list_download}"), PFB_FILTER_FILE_MIME, 'pfb_download', '', FALSE, $reject_detail)) {
				pfb_validate_log($header, 'inner', 'inner_mime_not_allowed', pfb_reject_detail_summary($reject_detail));
				unlink_if_exists($file_download);
				return FALSE;
			}
		}
		elseif ($file_type == 'application/x-7z-compressed') {
			// 7-Zip is an OPTIONAL add-on (not in the FreeBSD base, unlike gunzip/bzip2/tar),
			// so a 7z feed on a box without it must say "install 7-zip" — not the misleading
			// "corrupt archive" the structural probe would otherwise report (ADR-45).
			$missing_7z = pfb_archive_missing_tool($file_type);
			if ($missing_7z !== NULL) {
				pfb_logger("\n[pfb_download] Cannot process {$file_type} feed: '{$missing_7z}' is not installed. Install the 7-Zip package (pkg install 7-zip) to use 7z-compressed feeds. Skipping [" . htmlspecialchars(pfb_redact_url($list_url)) . "]", 2);
				unlink_if_exists($file_download);
				return FALSE;
			}
			if (!pfb_validate_archive($file_download, $file_type)) {
				pfb_validate_log($header, 'structural', 'probe_failed', "{$file_type} " . basename($file_download));
				unlink_if_exists($file_download);
				return FALSE;
			}
			$reject_detail = array();
			if (!pfb_filter(array("{$file_dwn_esc}", "{$file_download}", "{$list_download}"), PFB_FILTER_FILE_MIME_COMPRESSED, 'pfb_download', '', FALSE, $reject_detail)) {
				pfb_validate_log($header, 'inner', 'compressed_mime_not_allowed', pfb_reject_detail_summary($reject_detail));
				return FALSE;
			}
			pfb_logger('.', 1);
			exec("/usr/local/bin/7z e -so {$file_dwn_esc} > {$file_org_esc}", $output, $retval);
		}
		else {
			// Uncompressed file format.
			if ($type == 'geoip' || $type == 'asn' || $type == 'top1m') {
				// Extras - MaxMind/TOP1M/ASN downloads. ADR-59: a 'plain' container
				// provider's body IS the destination CSV -- rename straight to it, same
				// as geoip/asn (no intermediate '.orig' staging needed).
				@rename("{$file_download}", "{$head_download}");
				return TRUE;
			}
			elseif ($type == 'blacklist') {
				$retval = 0;
			}
			else {
				// Rename file to 'orig' format
				@rename("{$file_download}", "{$orig_download}");
				$retval = 0;
			}
		}

		if ($retval == 0) {
			// Set downloaded file timestamp to remote timestamp
			if (isset($remote_stamp) && $remote_stamp != -1) {
				@touch("{$orig_download}", $remote_stamp);
			}

			// ADR-42 / issue #713 bug 5: refresh the content-hash sidecar at every
			// successful ingest so pfb_local_feed_changed() / the probe's conditional-GET
			// compare always land on the SAME domain of bytes the probe hashed.  The probe
			// (pfb_update_check -> pfb_download($type='change_detect')) hashes the RAW
			// fetched body (it returns before any decompression), so the persisted digest
			// here must cover those same raw bytes too -- not the decompressed '.orig' --
			// or a compressed feed (gz/bz2/zip/7z) never matches and re-ingests every cron.
			// pfb_source_hash_target() resolves to $file_download (the raw '.raw' download,
			// still on disk for every compressed format) or falls back to $orig_download for
			// an uncompressed feed, where $file_download was already renamed away (above)
			// into $orig_download -- byte-identical to what was fetched, so the fallback is
			// exact, not an approximation.  This covers both local and remote standard feeds
			// (any path that finalises a plain .orig here).  The geoip/asn early-returns
			// above do not reach this block, so they correctly never get a sidecar.
			pfb_hash_write("{$orig_download}", pfb_source_hash_target($file_download, $orig_download));

			// issue #946: transcode a UTF-16/UTF-32-BOM-marked feed to UTF-8 AFTER the
			// hash sidecar above -- the sidecar hashes the RAW wire bytes (ADR-42), so
			// transcoding first would make the persisted digest diverge from the
			// change-probe's wire hash and re-ingest the feed every cron. No-op (FALSE,
			// file untouched) for every feed that isn't UTF-16/32-BOM-marked.
			pfb_utf16_transcode_file("{$orig_download}");

			// Process Emerging Threats IQRisk if required
			if (strpos($list_url, 'iprepdata.txt') !== FALSE) {
				exec("{$pfb['script']} et {$header_esc} x x x x x {$pfb['etblock']} {$pfb['etmatch']} {$elog}");
			}
			return TRUE;
		}
		else {
			$log = "   Decompression Failed\n";
			pfb_logger("{$log}", 2);
			return FALSE;
		}
	}
	else {
		// Download failed
		unlink_if_exists("{$file_download}");
	}
	return FALSE;
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
			if ($pfb['float'] == 'on') {
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
			if ($pfb['global_log'] == 'on' || $pfb_log == 'enabled') {
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
			if ($pfb['float'] == 'on') {
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
			if ($pfb['global_log'] == 'on' || $pfb_log == 'enabled') {
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
			if ($pfb['float'] == 'on') {
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
			if ($pfb['global_log'] == 'on' || $pfb_log == 'enabled') {
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
			if ($pfb['float'] == 'on') {
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
			if ($pfb['global_log'] == 'on' || $pfb_log == 'enabled') {
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
			if ($pfb['global_log'] == 'on' || $pfb_log == 'enabled') {
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
			if ($pfb['global_log'] == 'on' || $pfb_log == 'enabled') {
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
	$want = ($pfb['dnsbl'] == 'on' && config_path_enabled('system', 'use_mfs_tmpvar'));

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
	$v4suppression = pfbng_text_area_decode($pfb['ipconfig']['v4suppression'] ?? '', TRUE, FALSE);
	$v6suppression = pfbng_text_area_decode($pfb['ipconfig']['v6suppression'] ?? '', TRUE, FALSE);

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
			if (!empty($list['custom']) && strpos($list['action'], 'Permit_') !== FALSE) {
				$custom		= pfbng_text_area_decode($list['custom'], TRUE, FALSE);
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
// Returns FALSE when the key is absent (new install) or explicitly unchecked.
function pfb_resolve_enabled(array $ipconfig): bool {
	if (!array_key_exists('enable_rdns', $ipconfig)) {
		return FALSE;
	}
	return pfb_cfg_toggle_read($ipconfig['enable_rdns']) === PfbToggle::On;
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
// on the first write). An unknown tag → sentinel 'changed' so an older release always
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
// cannot read the sidecar treats the file as changed and re-ingests (fail-safe / downgrade).
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


// Number of already-processed filter.log lines to skip on daemon (re)start, derived
// from `grep -c ^ /var/log/filter.log`'s raw output. (int) casts so a grep error
// string (e.g. filter.log momentarily absent between rotation and daemon restart)
// coerces to 0 instead of throwing PHP 8's "Unsupported operand types: string - int"
// TypeError out of the daemon (issue #713 -- a crash loop). Callers must also guard
// with file_exists('/var/log/filter.log') so the exec() is skipped entirely when the
// file is absent.
//
// PURE -- no I/O, no globals, no side effects.
function pfb_filterlog_skip_count(string $grep_output): int {
	return max((int) $grep_output - 1, 0);
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

	if (file_exists('/usr/local/sbin/clog_pfb')) {

		// Parse full filter.log on first run, otherwise only parse new filter.log events
		if (!file_exists($pfb['ip_blocklog']) && !file_exists($pfb['ip_permitlog']) && !file_exists($pfb['ip_matchlog'])) {
			$filter_cnt = 0;
		} elseif (file_exists('/var/log/filter.log')) {
			// issue #713: guarded by file_exists() -- an absent filter.log made exec()
			// return a grep error string, and pfb_filterlog_skip_count() (int)-casts it
			// so it can never throw the old bare-subtraction TypeError.
			$filter_cnt = pfb_filterlog_skip_count(exec("{$pfb['grep']} -c ^ /var/log/filter.log 2>&1"));
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
							$df = explode(',', $dnsline);
							// Reformat through the schema-owning formatter when well-formed;
							// fall back to the raw line otherwise so a malformed row is never
							// dropped or corrupted.
							if (count($df) === 11) {
								$uni = pfb_unified_format_dnsbl(array(
									'l_type' => $df[0], 'datetime' => $df[1], 'q_name' => $df[2],
									'q_ip' => $df[3], 'p_type' => $df[4], 'b_type' => $df[5],
									'group' => $df[6], 'b_eval' => $df[7], 'feed' => $df[8],
									'dup' => $df[9], 'q_type' => $df[10],
								));
								@file_put_contents("{$pfb['unilog']}", "{$uni}\n", FILE_APPEND | LOCK_EX);
								// Every DNSBL block line syslogs uniformly (incl. the PHP-path
								// block the old python-only emitter missed). pfb_syslog_event
								// no-ops when the toggle is off. Refresh the daemon's config
								// first so a LIVE log_syslog toggle takes effect (no restart).
								pfb_filterlog_refresh_config();
								if (PfbConfig::read('log_syslog') === PfbToggle::On) {
									pfb_syslog_event(pfb_syslog_format_dnsbl(array(
										'q_name' => $df[2], 'q_ip' => $df[3], 'q_type' => $df[10],
										'group' => $df[6], 'feed' => $df[8], 'b_type' => $df[5],
										'b_eval' => $df[7],
									)));
								}
							} else {
								@file_put_contents("{$pfb['unilog']}", "{$dnsline}\n", FILE_APPEND | LOCK_EX);
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
			$d = explode(',', $f[$f_pos]);

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
						$folder = "{$pfb['matchdir']}/* {$pfb['nativedir']}/*";
						$iplog	= "{$pfb['ip_matchlog']}";
						$l_type = 'Match';
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

						// Save entry to IP cache
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

					// Details:	"Direction/GeoIP/Aliasname/IP evaluated/Feed Name/Resolved Hostname/Client Hostname/ASN/Duplicate status"
					$details	= "{$dir},{$geoip},{$pfb_alias},{$pfb_query[1]},{$pfb_query[0]},{$resolved_host},{$hostname},{$asn}";

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
				if (PfbConfig::read('log_syslog') === PfbToggle::On) {
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


// Pass-1 buffer-append rule for the DNSBL non-filter two-pass render (pfblockerng_alerts.php).
// Extracted verbatim so the compression arithmetic is unit-pinned by AlertsBufferReplayTest
// instead of living only as inline page code with no committed coverage. A duplicate-marker
// line ('-') either extends the buffer's trailing int run (a run-length counter) or opens a
// fresh one; a non-dup line is appended verbatim as $row ($row is unused when $is_dup is
// TRUE). See pfb_alerts_dnsbl_replay_step() for the Pass-2 counterpart.
function pfb_alerts_dnsbl_buffer_push(array &$buf, bool $is_dup, $row): void {
	if ($is_dup) {
		$last = count($buf) - 1;
		if ($last >= 0 && is_int($buf[$last])) {
			$buf[$last]++;
		} else {
			$buf[] = 1;
		}
		return;
	}

	$buf[] = $row;
}


// Pass-2 replay-decode counterpart to pfb_alerts_dnsbl_buffer_push(): tells the
// DNSBL render loop what a buffered entry MEANS, so it never has to inspect the
// buffer's storage shape itself.
//
//   int N       -> array('dup' => N)     -- a compressed dup run: accumulate N
//                                            into $dup['DNSBL'] in one step,
//                                            output-identical to N individual
//                                            $dup['DNSBL']++ increments.
//   $fields row -> array('render' => $fields) -- replay through the unchanged
//                                            convert_dnsbl_log() call.
function pfb_alerts_dnsbl_replay_step($entry): array {
	if (is_int($entry)) {
		return array('dup' => $entry);
	}

	return array('render' => $entry);
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


// Page-scope prefetch store for pfb_dnsbl_parse_compute()'s data/zone grep sites (issue #809).
// NULL means "no prefetch ran" — every consult site falls straight through to its normal
// per-row exec, so daemon mode (which never seeds this) is unaffected. Read:
// pfb_dnsbl_prefetch_store(); seed/reset: pfb_dnsbl_prefetch_store($arrayOrNull) — an explicit
// NULL argument (func_num_args() > 0) resets to "no prefetch", which the DNSBL table render
// pass clears once it finishes (defensive hygiene: today's page renders at most one
// prefetch-consuming table per request, so no live bug depends on the reset yet).
function pfb_dnsbl_prefetch_store(?array $seed = NULL): ?array {
	static $store = NULL;

	if (func_num_args() > 0) {
		$store = $seed;
	}

	return $store;
}


// Batch the DNSBL/TLD render-time grep lookups for $qdomains ahead of a page render pass
// (issue #809): one grep pass per file instead of a per-row exec each. Data file: fixed-string
// ",{domain},," match via `grep -shF` (issue #837 fixed a prior escaped-BRE match that let
// non-dot metacharacters ride into the regex live). Zone file: batches every longest-first
// label-suffix of every domain into one fixed-string pass. Negative results are cached too
// ('covered'/'zone_covered' with no match) so the consult sites serve a genuine miss from
// cache, never re-exec. A domain enters 'covered' only when it VALIDATES as PFB_FILTER_DOMAIN
// — guards an embedded control char reaching the pattern file. Seeds
// pfb_dnsbl_prefetch_store(); the caller resets it once rendering finishes.
function pfb_dnsbl_prefetch(array $qdomains) {
	global $pfb;

	$qdomains = array_values(array_unique($qdomains));

	$covered = array();
	$data_patterns = array();
	$zone_covered = array();
	$zone_patterns = array();
	foreach ($qdomains as $domain) {
		if (empty(pfb_filter($domain, PFB_FILTER_DOMAIN, 'pfb_dnsbl_prefetch'))) {
			continue;
		}

		$covered[$domain] = TRUE;
		$data_patterns[] = ",{$domain},,";

		// Label-walk suffixes for this domain -- same longest-first walk as the per-row
		// zone-grep loop in pfb_dnsbl_parse_compute() (full domain, then each suffix
		// with the leftmost label stripped, down to the bare TLD). Suffixes shared by
		// multiple domains are deduplicated (a single pattern/store entry serves them
		// all).
		$dparts = explode('.', $domain);
		$dcnt = count($dparts);
		for ($i = 0; $i < $dcnt; $i++) {
			$suffix = implode('.', $dparts);
			if (!isset($zone_covered[$suffix])) {
				$zone_covered[$suffix] = TRUE;
				$zone_patterns[] = ",{$suffix},,";
			}
			unset($dparts[$i]);
		}
	}

	$data = pfb_dnsbl_prefetch_grep($data_patterns, $pfb['unbound_py_data']);
	$zone = pfb_dnsbl_prefetch_grep($zone_patterns, $pfb['unbound_py_zone']);

	// B3/R1 (issue #809 review): either grep pass can fail (its pattern file could not be
	// created/written -- a full/read-only temp dir), returning NULL rather than a genuine
	// empty-array no-match result. Seeding only the successful half would still
	// false-miss every domain the FAILED half was supposed to cover, so on ANY failure
	// the store is left NULL entirely -- every consult site then falls straight through
	// to its unchanged per-row exec, exactly as if this prefetch pass had never run.
	if ($data === NULL || $zone === NULL) {
		pfb_dnsbl_prefetch_store(NULL);
		return;
	}

	pfb_dnsbl_prefetch_store(array(
		'covered'      => $covered,
		'data'         => $data,
		'zone_covered' => $zone_covered,
		'zone'         => $zone,
	));
}


// One `grep -shF -f <patternfile>` pass over $file, returning a map of the matched
// domain/suffix (field [1], same position pfb_dnsbl_parse_compute() destructures per-row) to
// the FIRST line seen for it — grep preserves file order, so "first seen in this batched pass"
// matches the per-row `-m1` result. $patterns are raw literal ",{domain-or-suffix},," strings
// (no regex escaping); the per-row sites are also `-F` fixed-string (issue #837), so both sides
// match identically by construction. Keying by field [1] works because in the
// ",domain,,log_type,feed,group" line shape the only double comma is right after the domain
// slot, so a ",X,," pattern can only match with X there. Returns NULL — distinct from a genuine
// empty-array no-match — when the pattern file could not be created/written; the caller must
// leave its store unseeded, never seed a false negative.
function pfb_dnsbl_prefetch_grep(array $patterns, string $file): ?array {
	global $pfb;

	$result = array();
	if (empty($patterns) || !is_file($file)) {
		return $result;
	}

	$pattern_file = tempnam(sys_get_temp_dir(), 'pfb_dnsbl_prefetch_');
	if ($pattern_file === FALSE) {
		return NULL;
	}

	try {
		$data = implode("\n", $patterns) . "\n";
		$written = file_put_contents($pattern_file, $data);
		if (!pfb_prefetch_pattern_file_write_ok($written, $data)) {
			return NULL;
		}

		$pattern_file_esc	= escapeshellarg($pattern_file);
		$file_esc		= escapeshellarg($file);
		$lines = array();
		exec("{$pfb['grep']} -shF -f {$pattern_file_esc} {$file_esc} 2>&1", $lines);

		foreach ($lines as $line) {
			$fields = explode(',', $line);
			$key = $fields[1] ?? NULL;
			if ($key !== NULL && !isset($result[$key])) {
				$result[$key] = $line;
			}
		}
	} finally {
		@unlink($pattern_file);
	}

	return $result;
}


// Function to find which DNSBL Feed/Groupname blocked this event.
//
// issue #809 (Alerts page render-time performance): in 'alerts' mode ONLY, memoize the whole
// return value per $domain — a render request is one PHP process, so a repeated domain across
// rows on one page load costs zero further SQLite/grep/drill work (the real work lives in
// pfb_dnsbl_parse_compute() below). 'daemon' mode (the long-running filterlog/dnsbl daemons) is
// unchanged: never memoized (an unbounded static store has no place in a service-lifetime
// process) and always calls straight through.
function pfb_dnsbl_parse($mode='daemon', $domain, $src_ip, $req_agent) {
	static $alerts_memo = array();

	if ($mode == 'alerts') {
		return pfb_render_memo($alerts_memo, $domain, function () use ($mode, $domain, $src_ip, $req_agent) {
			return pfb_dnsbl_parse_compute($mode, $domain, $src_ip, $req_agent);
		});
	}

	return pfb_dnsbl_parse_compute($mode, $domain, $src_ip, $req_agent);
}


// The actual DNSBL-parse work for pfb_dnsbl_parse() above -- factored out so the
// alerts-mode memo there can wrap a plain function call instead of needing to
// re-indent this whole body into a closure (issue #809).
//
// In 'alerts' mode ONLY, $alerts_db_handle keeps ONE dnsblcache SQLite3 connection
// open for the rest of the page load, reused for both the SELECT and the INSERT
// below, instead of the daemon's open/close per call. It is intentionally never
// closed in alerts mode -- process exit does that, same as any other page-scoped
// resource. A failed open is cached too (as FALSE), so it is attempted at most once
// per page load and then degrades to the same "always a cache miss" slow path a
// persistently-down DB gives today -- never retried mid-page, never fatal. 'daemon'
// mode keeps its per-call open/close exactly as before.
function pfb_dnsbl_parse_compute($mode, $domain, $src_ip, $req_agent) {
	global $pfb;

	static $alerts_db_handle = NULL;	// NULL = not yet opened; FALSE = open failed; else the SQLite3 handle

	$dnsbl_cache = FALSE;
	if ($mode == 'alerts') {
		if ($alerts_db_handle === NULL) {
			$alerts_db_handle = pfb_open_sqlite(4, 'Query cache') ?: FALSE;
		}
		$db_handle = $alerts_db_handle;
	} else {
		$db_handle = pfb_open_sqlite(4, 'Query cache');
	}
	if ($db_handle) {
		$db_update = "SELECT * FROM dnsblcache WHERE domain = :domain;";
		$stmt = $db_handle->prepare($db_update);
		if ($stmt) {
			$stmt->bindValue(':domain', $domain, SQLITE3_TEXT);
			$result = $stmt->execute();
			if ($result) {
				$dnsbl_cache = $result->fetchArray(SQLITE3_ASSOC);
			}
		}
	}
	if ($mode != 'alerts') {
		pfb_close_sqlite($db_handle);
	}

	// If domain is not in DNSBL cache, query for blocked domain details
	if (!$dnsbl_cache) {
		$o_domain = $domain; // Store original domain for CNAME query
		$cname_cnt = 0; // issue #834: only ever set inside the CNAME-found branch below,
		// but read unconditionally at "if ($cname_cnt == 0)" -- init so a total miss (no
		// data/zone/CNAME match) doesn't read an undefined variable there.

		// issue #809: NULL unless the Alerts page's DNSBL table render pass
		// seeded it via pfb_dnsbl_prefetch() -- read once here and reused at both grep
		// sites below (data + zone) for every iteration of the CNAME while(TRUE) loop.
		$prefetch_store = pfb_dnsbl_prefetch_store();

		while (TRUE) {

			// A covered domain reuses the batched grep's answer (a covered miss is a
			// cached '', never re-exec'd here); an uncovered one -- no store seeded, or
			// a CNAME-chain domain the prefetch pass never saw -- falls straight through
			// to today's per-row exec, unchanged.
			if ($prefetch_store !== NULL && isset($prefetch_store['covered'][$domain])) {
				$pfb_feed = $prefetch_store['data'][$domain] ?? '';
			} else {
				// issue #837: fixed-string match on the raw domain -- no regex escaping,
				// so no BRE metacharacter (besides the dot this used to hand-escape) can
				// false-match a different literal line, nor make the domain's own entry
				// unfindable. Same shape as the batched prefetch grep.
				$dquery_esc	= escapeshellarg(",{$domain},,");
				$pfb_feed	= exec("{$pfb['grep']} -shm1 -F {$dquery_esc} {$pfb['unbound_py_data']} 2>&1");
			}
			$pfb_group = $pfb_mode = $pfb_final = 'Unknown';

			// Exact Domain match found
			if (!empty($pfb_feed)) {

				list($dummy, $pfb_final, $empty_placeholder, $log_type, $pfb_feed, $pfb_group) = explode(',', $pfb_feed);
				$pfb_mode = 'DNSBL';
			}

			else {
				$dparts = explode('.', $domain);

				$dcnt = count($dparts);

				for ($i=0; $i < $dcnt; $i++) {

					$suffix		= implode('.', $dparts);

					// Same prefetch consult as the data-grep site above, keyed by this
					// label-walk suffix rather than the whole domain.
					if ($prefetch_store !== NULL && isset($prefetch_store['zone_covered'][$suffix])) {
						$pfb_feed = $prefetch_store['zone'][$suffix] ?? '';
					} else {
						// issue #837: fixed-string match -- see the data-grep site above.
						$dquery_esc	= escapeshellarg(",{$suffix},,");
						$pfb_feed	= exec("{$pfb['grep']} -shm1 -F {$dquery_esc} {$pfb['unbound_py_zone']} 2>&1");
					}

					// Collect Alias Group name
					if (!empty($pfb_feed)) {
						list($dummy, $d_found, $empty_placeholder, $log_type, $pfb_feed, $pfb_group) = explode(',', $pfb_feed);

						$pfb_final = $suffix;
						$pfb_mode = 'TLD';
						if ($pfb_feed == 'DNSBL_TLD') {
							$pfb_mode = 'DNSBL_TLD';
						}
						break;
					}
					unset($dparts[$i]);
				}
			}

			// Query for CNAME(s)
			if (empty($pfb_feed)) {
				if (!isset($cnames)) {
					$domain_esc = escapeshellarg($domain);
					$extdns_esc = escapeshellarg("@{$pfb['extdns']}");
					exec("/usr/bin/drill {$domain_esc} {$extdns_esc} | /usr/bin/awk '/CNAME/ {sub(\"\.\$\", \"\", \$5); print \$5;}'", $cnames);
					if (is_array($cnames) && !empty($cnames)) {
						foreach ($cnames as $key => $cname) {
							// Remove invalid CNAMES
							if (empty(pfb_filter($cname, PFB_FILTER_DOMAIN, 'pfb_dnsbl_parse'))) {
								unset($cnames[$key]);
								continue;
							}
                                                }
						$cname_cnt = count($cnames);
					}
				}
				if (is_array($cnames) && !empty($cnames)) {
					$domain = array_shift($cnames);
				}

				if ($cname_cnt == 0) {
					$domain = $o_domain; // No CNAME match found, revert back to original domain
					break;
				}
				$cname_cnt--;
			}
			else {
				break;
			}
		}
		$pfb_feed = $pfb_feed ?: 'Unknown';

		if (isset($cnames)) {
			unset($cnames);
			if ($pfb_feed != 'Unknown') {
				$pfb_mode = "{$pfb_mode}-CNAME";
			}
		}

		// Save entry to DNSBL cache
		$db_update = "INSERT into dnsblcache ( type, domain, groupname, final, feed ) VALUES ( :type, :domain, :groupname, :final, :feed )";
		if ($mode == 'alerts') {
			$db_handle = $alerts_db_handle;
		} else {
			$db_handle = pfb_open_sqlite(4, 'Add to DNSBL cache');
		}
		if ($db_handle) {
			$domain		= pfb_filter($domain, PFB_FILTER_HTML, 'pfb_dnsbl_parse');
			$pfb_group	= pfb_filter($pfb_group, PFB_FILTER_HTML, 'pfb_dnsbl_parse');
			$pfb_final	= pfb_filter($pfb_final, PFB_FILTER_HTML, 'pfb_dnsbl_parse');
			$pfb_feed	= pfb_filter($pfb_feed, PFB_FILTER_HTML, 'pfb_dnsbl_parse');

			$stmt = $db_handle->prepare($db_update);
			if ($stmt) {
				$stmt->bindValue(':type', $pfb_mode, SQLITE3_TEXT);
				$stmt->bindValue(':domain', $domain, SQLITE3_TEXT);
				$stmt->bindValue(':groupname', $pfb_group, SQLITE3_TEXT);
				$stmt->bindValue(':final', $pfb_final, SQLITE3_TEXT);
				$stmt->bindValue(':feed', $pfb_feed, SQLITE3_TEXT);
				$stmt->execute();
			}
		}
		if ($mode != 'alerts') {
			pfb_close_sqlite($db_handle);
		}
	}

	// Use cached entries
	else {
		$pfb_mode	= htmlspecialchars($dnsbl_cache['type'])	?: 'Unknown';
		$pfb_group	= htmlspecialchars($dnsbl_cache['groupname'])	?: 'Unknown';
		$pfb_final	= htmlspecialchars($dnsbl_cache['final'])	?: 'Unknown';
		$pfb_feed	= htmlspecialchars($dnsbl_cache['feed'])	?: 'Unknown';
	}

	if ($mode == 'daemon') {
		$details = "{$domain},{$src_ip},{$req_agent},{$pfb_mode},{$pfb_group},{$pfb_final},{$pfb_feed}";
		return array ($pfb_group, $details);
	} else {
		return array ('pfb_mode' => $pfb_mode, 'pfb_group' => $pfb_group, 'pfb_final' => $pfb_final, 'pfb_feed' => $pfb_feed);
	}
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
			return [ 'db_table' => 'dnsblcache', 'db_create' => "CREATE TABLE IF NOT EXISTS dnsblcache ( type TEXT, domain TEXT, groupname TEXT, final TEXT, feed TEXT );" ];
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

	// ADR-60: these writes bypass pfb_logger() entirely, so they stamp themselves.
	$now = pfb_log_iso_timestamp();

	// $table is always 1-7 from callers, but the if/elseif chain below has no else;
	// default these so they are defined for any value. Behaviour-preserving.
	$database	= '';

	if ($table == 1) {
		$database	= $pfb['dnsbl_info'];
	} elseif ($table == 2) {
		$database	= $pfb['dnsbl_resolver'];
	} elseif ($table == 3) {
		$database	= $pfb['dnsbl_resolver'];
	} elseif ($table == 4) {
		$database	= $pfb['dnsbl_cache'];
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
		$data		= pfb_dnsbl_parse('daemon', $domain, $src_ip, $req_agent);
		$pfb_group	= $data[0];
		$details	= $data[1];
		$req_agent	= $data[2];

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
function pfb_feed_task_running(): bool {
	$result_ps = array();
	exec('/bin/ps -wax', $result_ps);
	return (bool) preg_grep('/pfblockerng[.]php\s+?(cron|update|pfb_trigger|tick|forcecheck)/', $result_ps);
}


// TRUE when a pfBlockerNG UPDATE pass (cron/update/pfb_trigger/forcecheck/dcc/bl) is
// currently running -- deliberately narrower than pfb_feed_task_running() above:
//   - EXCLUDES 'tick': the only caller is pfblockerng_tick() itself (the scheduled log
//     maintenance gate at its tail), and a tick always sees its OWN process in `ps` --
//     including it here would make the gate permanently closed.
//   - INCLUDES 'dcc'/'bl': both append to $pfb['extraslog'] for potentially minutes,
//     the same log pfb_log_mgmt()'s tail-to-temp-then-cat-over trim can race and lose
//     lines from, so a due-ledger-dispatched dcc/bl pass must also hold this gate closed.
// $ps_lines is injectable (bypasses exec()) so this is unit-testable off-appliance.
function pfb_update_pass_running(?array $ps_lines = NULL): bool {
	if ($ps_lines === NULL) {
		exec('/bin/ps -wax', $ps_lines);
	}
	return (bool) preg_grep('/pfblockerng[.]php\s+?(cron|update(ip|dnsbl)?|pfb_trigger|forcecheck|dcc|bl)\b/', $ps_lines);
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
function pfb_unlock($mode, $type, $remove='', $r_type='', $filename_unlock) {
	global $pfb;

	if ($type == 'ip') {
		$filename = $pfb['ip_unlock'];
	} elseif ($type == 'dnsbl') {
		$filename = $pfb['dnsbl_unlock'];
	} elseif ($type == 'dnsbl_data') {
		$filename = "{$pfb['dnsbl_unlock']}.data";
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
	elseif ($mode == 'dnsbl_data') {
		$filename_unlock = '';
		$data = array();
		if (($handle = @fopen("{$filename}", 'r')) !== FALSE) {
			while (($line = @fgets($handle)) !== FALSE) {
				if (strpos($line, $remove) !== FALSE) {
					$data = explode(',', $line);
				} else {
					$filename_unlock .= "{$line}"; 
				}
			}
		}
		if ($handle) {
			@fclose($handle);
		}

		if (empty($filename_unlock)) {
			unlink_if_exists("{$filename}");
		} else {
			@file_put_contents("{$filename}", "{$filename_unlock}", LOCK_EX);
		}
		return $data;
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
	unlink_if_exists("{$pfb['dnsbl_cache']}");
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
	rmdir_recursive("{$pfb['dnsalias']}");
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
 * @param ?string $float          Float mode: 'on' or '' (off); null (the unconfigured
 *                                $pfb['float']) is coerced to '' (off) — this one IS passed unset.
 * @param array  $in_ifaces       Inbound interface names.
 * @param array  $out_ifaces      Outbound interface names.
 * @return array The new filter/rule array to write back to config.xml.
 */
function pfb_build_autorule_list(
	array   $existing_rules,
	array   $pfb_generated,
	?string $order,
	?string $float,
	array   $in_ifaces,
	array   $out_ifaces
): array {
	// $float comes straight from $pfb['float'], which is unset (null) until configured; $order
	// arrives pre-defaulted to 'order_0' from the call site (#532) but is accepted nullable too.
	// The historical inline code used these raw values in loose comparisons ('== on' / '== order_N'),
	// where null simply matches nothing -- so a null is behaviour-equivalent to ''. Coerce here
	// (the params are nullable) rather than let a strict string typehint TypeError on the null the
	// call site legitimately passes (e.g. enable_float unset).
	$order = $order ?? '';
	$float = $float ?? '';

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

		if ($float === 'on') {
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

	if ($float === 'on') {
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

// Main pfBlockerNG function
function sync_package_pfblockerng($cron='') {
	global $g, $pfb, $pfbarr;
	pfb_global();

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
		if ($pfb['dnsbl'] == 'on') {
			pfb_create_dnsbl('enabled');
		}
		$log = 'Sync terminated during boot process.';
		pfb_logger("\n{$log}\nUPDATE PROCESS ENDED\n", 1);
		logger(LOG_INFO, localize_text($log), LOG_PREFIX_PKG_PFBLOCKERNG);
		return;
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

	// Reloads existing lists without downloading new lists when defined 'on'
	$pfb['reuse'] = $pfb['config']['pfb_reuse'];
	$pfb['reuse_dnsbl'] = '';

	// Define update process (update or reload)
	if ($pfb_is_noups) {
		// Cron pass with no feed changes: save the configuration; nothing to reload.
		$pfb['save'] = TRUE;
	} elseif ($pfb_req['scope'] === 'both' && $pfb_req['force']) {
		// Force Reload BOTH (Update page Run-now with force on, and the wizard reload):
		// apply IP tables AND DNSBL from cached lists, no re-download — the union of the
		// scope=ip and scope=dnsbl force branches. Without this, scope=both + force fell
		// through with no adjustment (identical to force=false), so the most prominent
		// "Force" control did nothing beyond a plain detector-respecting pass.
		$pfb['reuse']        = 'on';
		$pfb['reuse_dnsbl']  = 'on';
		$pfb['updatednsbl']  = TRUE;
		unlink_if_exists("{$pfb['dbdir']}/masterfile");
		unlink_if_exists("{$pfb['dbdir']}/mastercat");
	} elseif ($pfb_req['scope'] === 'ip' && $pfb_req['force']) {
		// updateip: Force Reload IP — apply IP tables from cached lists, no re-download.
		$pfb['reuse']       = 'on';
		$pfb['reuse_dnsbl'] = '';
		unlink_if_exists("{$pfb['dbdir']}/masterfile");
		unlink_if_exists("{$pfb['dbdir']}/mastercat");
	} elseif ($pfb_req['scope'] === 'dnsbl' && $pfb_req['force']) {
		// updatednsbl: Force Reload DNSBL — apply from cached data, always reload Unbound.
		$pfb['reuse']        = '';
		$pfb['reuse_dnsbl']  = 'on';
		$pfb['updatednsbl']  = TRUE;
	} elseif ($pfb_cron_tick && $pfb['reuse'] == 'on') {
		// Scheduled cron tick with global Reload toggle on: propagate reuse to DNSBL side.
		$pfb['reuse_dnsbl'] = 'on';
		unlink_if_exists("{$pfb['dbdir']}/masterfile");
		unlink_if_exists("{$pfb['dbdir']}/mastercat");
	}
	// manual / '' (settings save / de-install) and any other non-cron path: no scope adjustment.

	// Start of pfBlockerNG logging to 'pfblockerng.log'
	if ($pfb['enable'] == 'on' && !$pfb['save']) {
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

	$pfb['float']		= $pfb['ipconfig']['enable_float'];				// Enable/Disable floating autorules
	$pfb['dup']		= $pfb['ipconfig']['enable_dup'];				// Enable remove of duplicate IPs utilizing grepcidr
	$pfb['agg']		= $pfb['ipconfig']['enable_agg'];				// Enable aggregation of CIDRs
	$pfb['order']		= $pfb['ipconfig']['pass_order'] ?: 'order_0';			// Order of the autorules (default order_0, matching the IP-settings UI; an empty value drops user pass-rules on a managed interface — issue #532)
	$pfb['global_log']	= $pfb['ipconfig']['enable_log'];				// Enable Global IP logging
	$pfb['suffix']		= $pfb['ipconfig']['autorule_suffix'];				// Suffix used for autorules
	$pfb['kstates'] 	= $pfb['ipconfig']['killstates'];				// Firewall states removal

	$pfb['ip_ph']		= pfb_filter($pfb['ipconfig']['ip_placeholder'], PFB_FILTER_IPV4, 'Placeholder IP Address', '127.1.7.7');	// Placeholder IP Address

	// DNSBL settings
	$pfb['dnsbl_ip']	= $pfb['dnsblconfig']['action']		?:  'Disabled';		// Enable/Disable IP blocking from DNSBL lists
	$pfb['dnsbl_rule']	= $pfb['dnsblconfig']['pfb_dnsbl_rule'] ?: 'Disabled';		// Auto create a Floating Pass Rule for other Lan subnets
	$pfb['dnsbl_top1m_cnt']	= $pfb['dnsblconfig']['alexa_count']	?: '1000';		// TOP1M whitelist domain setting
	// DNSBL Python decision-cache cap (LRU); 0 = unlimited. 0 is meaningful so avoid the
	// ?: idiom (0 is falsy), and reject non-numeric input -- else the intval() at the ini
	// emit would coerce a malformed value to 0 = silently unlimited. Clamp to the WebUI range.
	$pfb_dcm_raw = (string) ($pfb['dnsblconfig']['pfb_py_cache_max'] ?? '');
	$pfb['dnsbl_decisiondb_max'] = ctype_digit($pfb_dcm_raw) ? (string) min(5000000, (int) $pfb_dcm_raw) : '10000';
	$pfb['dnsbl_top1m_inc']	= $pfb['dnsblconfig']['alexa_inclusion']?: '';			// TOP1M TLDs inclusions for whitelisting
	$pfb['dnsbl_tld']	= $pfb['dnsblconfig']['pfb_tld'];				// Enable TLD Function
	$pfb['dnsbl_control']	= $pfb['dnsblconfig']['pfb_control']	?: '';			// Python Control integration
	$pfb['dnsbl_control_legacy']	= $pfb['dnsblconfig']['pfb_control_legacy']	?? '';	// PFBL-03: deprecated legacy DNS-TXT control transport

	// Validate pfB Script variable
	$pfb['dnsbl_top1m_inc'] = pfb_filter($pfb['dnsbl_top1m_inc'], PFB_FILTER_CSV, 'Validate pfB Script variable');

	// Reputation config variables
	$pfb['config_rep'] = config_get_path('installedpackages/pfblockerngreputation/config/0', []);

	// Validate pfB Script variables
	foreach (array(
			'enable_rep'		=> 'rep',					// Enable/Disable 'Max' Reputation
			'enable_pdup'		=> 'prep',					// Enable/Disable 'pRep' Reputation
			'enable_dedup'		=> 'drep',					// Enable/Disable 'dRep' Reputation
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

	// Starting variable to skip Reputation functions, if no changes are required
	$pfb['repcheck'] = FALSE;
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
			if ($continent_config['action'] != 'Disabled' && in_array($continent_config['action'], $action)) {
				$pfb['autorules'] = TRUE;
				break;
			}
		}
	}

	if (!$pfb['autorules']) {
		foreach ($ip_types as $ip_type => $vtype) {
			foreach(config_get_path("installedpackages/{$ip_type}/config", []) as $list) {
				if ($list['action'] != 'Disabled' && in_array($list['action'], $action)) {
					$pfb['autorules'] = TRUE;
					break;
				}
			}
		}
	}

	// Check if DNSBL auto permit rule or DNSBL 'Auto Deny' rules for DNSBL IPs are defined
	if (!empty($pfb['dnsblconfig']['dnsbl_allow_int']) || strpos($pfb['dnsblconfig']['action'], 'Deny_') !== FALSE) {
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
			if ($pfb['float'] == 'on') {
				$pfb['base_rule']		= $pfb['base_rule_float'];
				$pfb["{$type}_interfaces"]	= explode(' ', $pfb["{$type}_floating"]);
			} else {
				$pfb['base_rule']		= $pfb['base_rule_reg'];
				$pfb["{$type}_interfaces"]	= $interfaces;
			}
		}
	}

	// Determine max Domain count available for DNSBL TLD analysis (Avoid Unbound memory exhaustion)
	$pfs_memory = (round(get_single_sysctl('hw.physmem') / (1024*1024)) ?: 1000);

	$pfb['pfs_mem'] = [
		'0' => '100000',
		'1500' => '150000',
		'2000' => '200000',
		'2500' => '250000',
		'3000' => '400000',
		'4000' => '600000',
		'5000' => '1000000',
		'6000' => '1500000',
		'7000' => '2000000',
		'8000' => '2500000',
		'12000' => '3000000',
		'16000' => '4000000',
		'32000' => '8000000'
	];

	array_walk($pfb['pfs_mem'], function (&$value) {
		$value = $value * 3;
	});

	foreach ($pfb['pfs_mem'] as $pfb_mem => $domain_max) {
		if ($pfs_memory >= $pfb_mem) {
			$pfb['domain_max_cnt'] = $domain_max;
		}
	}


	#################################################
	#	Clear Removed Lists from Masterfiles	#
	#################################################

	$pfb['sync_master']	= TRUE;		// Process to keep IP Masterfiles in sync with valid Lists from config.conf file
	$pfb['remove']		= FALSE;	// Flag to execute pfctl and rules ordering or reload of DNSBL domains
	$pfb['summary']		= FALSE;	// Execute final summary as a list was removed

	// Don't execute this function when pfBlockerNG is disabled and 'keep blocklists' is enabled.
	if ($pfb['enable'] == '' && $pfb['keep'] == 'on') {
		$pfb['sync_master'] = FALSE;
	}

	if ($pfb['sync_master']) {

		// Find all enabled Continents lists
		foreach ($pfb['continents'] as $continent => $pfb_alias) {
			$cont_key = 'pfblockerng' . strtolower(str_replace(' ', '', $continent));
			if (!empty(config_get_path("installedpackages/{$cont_key}/config")) && $pfb['enable'] == 'on') {
				$continent_config = config_get_path("installedpackages/{$cont_key}/config/0");
				if ($continent_config['action'] != 'Disabled') {
					foreach ($cont_types as $c_type => $vtype) {
						if (!empty($continent_config[$c_type])) {

							// Force 'Alias Native' setting to any Alias with 'Advanced Inbound/Outbound -Invert src/dst' settings.
							// This will bypass Deduplication and Reputation features.
							if ($continent_config['autoaddrnot_in'] == 'on' ||
							    $continent_config['autoaddrnot_out'] == 'on') {
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
		foreach ($list_types as $ltype => $vtype) {
			$lists = array();

			$type_config = config_get_path("installedpackages/{$ltype}/config");
			if (!empty($type_config) && $pfb['enable'] == 'on') {
				foreach ($type_config as $list) {

					// If only the 'customlist' is defined. Remove the 'List row' data.
					if (isset($list['row']) && empty($list['row'][0]['url'])) {
						unset($list['row']);
					}

					if (!empty($list['custom'])) {
						$list['row'][] = array( 'header'	=> "{$list['aliasname']}_custom",
									'custom'	=> $list['custom'],
									'state'		=> 'Enabled',
									'url'		=> 'custom'
									);
					}
					$lists[] = $list;
				}
			}

			// ADD DNSBL IP
			if (($ltype == 'pfblockernglistsv4' || $ltype == 'pfblockernglistsv6') && $pfb['enable'] == 'on' && $pfb['dnsbl'] == 'on' && $pfb['dnsbl_ip'] != 'Disabled') {
				$list = array();
				$list['action'] = "{$pfb['dnsbl_ip']}";
				$list['row'][]	= array('format'	=> 'auto',
							'state'		=> 'Enabled',
							'url'		=> "{$pfb['dbdir']}/DNSBLIP{$vtype}.txt",
							'header'	=> 'DNSBLIP');
				$lists[] = $list;
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
						if ($list['action'] != 'unbound' && ($list['autoaddrnot_in'] == 'on' ||
						    $list['autoaddrnot_out'] == 'on')) {
							$list['action'] = 'Alias_Native';
						}

						foreach ($list['row'] as $hkey => $row) {

							// Remove any spaces or special characters in existing Header names
							if (preg_match("/\W/", $row['header'])) {
								$pfb_invalid	= TRUE;
								$row['header']	= preg_replace("/\W/", '', $row['header']);
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

		// If 'TLD' enabled and TLD Blacklists are defined, add to enabled DNSBL lists
		if ($pfb['dnsbl_tld']) {
			$tld_blacklist = pfbng_text_area_decode($pfb['dnsblconfig']['tldblacklist'], TRUE, FALSE, TRUE);
			if (!empty($tld_blacklist)) {
				$pfb['existing']['dnsbl'][] = 'DNSBL_TLD';
			}
		}

		// Add 'Reputation - ccwhite Action' if found
		if ($pfb['ccwhite'] == 'match' && file_exists("{$pfb['matchdir']}/matchdedup_v4.txt")) {
			$pfb['existing']['match'][] = 'matchdedup_v4';
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
			if ($pfb['enable'] == 'on' && $pftype != 'dnsbl') {
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
	// pfb['keep'] is now 'on'/'off' (PfbLenient); != 'on' covers both 'off' and legacy ''.
	if ($pfb['enable'] == '' && $pfb['keep'] != 'on' && !$pfb['install']) {
		$log = "\n  Removing DB Files/Folders \n";
		pfb_logger("{$log}", 1);
		pfb_clear_contents();
	}

	#################################################
	#	Create IP Suppression Txt File		#
	#################################################

	if ($pfb['enable'] == 'on' && $pfb['supp'] == 'on') {
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
	$pfb['tld_update']		= array();	// Array of all DNSBL Aliases/Feeds used for TLD Function
	$pfb['domain_update']		= FALSE;	// Flag to signal update Unbound
	$pfb['updateip']		= FALSE;	// Flag to signal updates to DNSBL IP lists
	$pfb_py_feeds			= array();	// ADR-06: per-feed manifest rows [header,group,log] for pfb_unbound_python_sources()
	$safesearch_update		= FALSE;	// Flag: SafeSearch CSV changed -> force an Unbound restart (issue #149)
	$pfb_fp_old			= null;		// Fingerprint of loaded input files BEFORE this pass (null => TLD mode or DNSBL not active)

	$dnsbl_error = FALSE;
	if ($pfb['enable'] == 'on' && $pfb['dnsbl'] == 'on' && !$pfb['save']) {

		// Terminate if DNSBL VIP is empty
		if (empty($pfb['dnsbl_port']) || empty($pfb['dnsbl_port_ssl'])) {
			$log = "\n\n===[  DNSBL Ports are not defined. Exiting  ]======\n";
			pfb_logger("{$log}", 1);
			$dnsbl_error = TRUE;
		}
	}

	if ($pfb['enable'] == 'on' && $pfb['dnsbl'] == 'on' && !$pfb['save'] && !$dnsbl_error) {
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


			// When DNSBL python blocking mode is enabled, zone should not exist, and data should exist
			if (!$pfb['dnsbl_tld']) {
				if (file_exists($pfb['unbound_py_zone'])) {
					$dnsbl_missing = TRUE;
				}
				if (!file_exists($pfb['unbound_py_data'])) {
					$dnsbl_missing = TRUE;
				}
			}

			// When DNSBL python blocking mode is enabled, atleast one 'data or zone' file must exist
			else {
				$found = FALSE;
				if (file_exists($pfb['unbound_py_data'])) {
					$found = TRUE;
				}
				if (file_exists($pfb['unbound_py_zone'])) {
					$found = TRUE;
				} 
				if (!$found) {
					$dnsbl_missing = TRUE;
				}
			}

			// Check if DNSBL database is missing, when DNSBL python blocking mode is not enabled


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
			// TLD mode builds data/zone inside pfb_update_unbound (after the gate), so
			// the fingerprint can't see those writes yet — leave null and fall back to the
			// domain_update / domain_clear flags for the gate decision.
			$pfb_fp_old = $pfb['dnsbl_tld'] ? null : pfb_dnsbl_loaded_fingerprint(pfb_dnsbl_loaded_input_paths($pfb));

			// Collect Whitelist, create string, and save to file (for grep -vF -f cmd)
			pfb_logger("\n Loading DNSBL Whitelist...", 1);
			$pfb_white = pfbng_text_area_decode($pfb['dnsblconfig']['suppression'], TRUE, FALSE, TRUE);
			if (!empty($pfb_white)) {
				foreach ($pfb_white as $line) {
					if (!empty($line)) {
						$wildcard = FALSE;
						if (str_starts_with($line, '.')) {
							$line = ltrim($line, '.');
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
			if ($pfb['dnsbl_top1m'] == 'on') {
				pfb_logger("\n Loading TOP1M Whitelist...", 1);

				// Check if TOP1M database exists
				if (!file_exists("{$pfb['dbdir']}/top-1m.csv")) {
					// Check if TOP1M download already in progress
					exec('/bin/ps -wax', $result_cron);
					if (!preg_grep("/pfblockerng[.]php\s+al/", $result_cron)) {
						$log = "\n TOP1M Database downloading ( approx 21MB ) ... Please wait ...\n";
						pfb_logger("{$log}", 1);
						exec('/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php al');

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
				if (!file_exists("{$pfb['dbdir']}/pfbalexawhitelist.txt") ||
				    file_exists("{$pfb['dbdir']}/top-1m.update")) {
					pfblockerng_top1m();
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
						$list['filter_alexa']	= '';

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
							exec("/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php bls {$bl_string} 2>&1", $pfb_return);

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
				// If only the 'customlist' is defined. Remove the 'List row' data.
				if (isset($list['row']) && empty($list['row'][0]['url'])) {
					unset($list['row']);
				}

				if (!empty($list['custom'])) {
						$list['row'][] = array( 'header'	=> "{$list['aliasname']}_custom",
												'custom'	=> $list['custom'],
												'state'		=> 'Enabled',
												'url'		=> 'custom'
						);
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

			foreach ($lists as $list) {

				// Reset variables once per alias
				$lists_dnsbl_current	= array();		// Array of all active Lists in current alias
				$pfb['aliasupdate']	= FALSE;		// Flag to signal changes to alias
				$pfb['domain_clear']	= FALSE;		// Flag to signal no Aliases defined or all Aliases disabled.
				$alias_cnt		= 0;
				// issue #1048: per-alias-pass failure flag -- a sibling feed's success must
				// never close a DIFFERENT feed's still-open download-failure ledger entry.
				$pfb_dl_failed		= FALSE;

				if ($list['action'] != 'Disabled' && isset($list['row'])) {
					$alias				= "DNSBL_{$list['aliasname']}";
					if (empty(pfb_filter($alias, PFB_FILTER_WORD, 'DNSBL - Processes'))) {
						pfb_logger("\n Invalid Aliasname:{$list['aliasname']}, *skipping*", 1);
						continue;
					}
					$pfb['alias_dnsbl_all'][]	= "{$alias}";

					// cURL Source Interface (sets CURLOPT_INTERFACE) — per-DNSBL-group
					// field, mirrors the IP loop. Previously $srcint was undefined here
					// (only assigned later in the IP loop), so the configured interface was
					// silently ignored on DNSBL ingest (#712). '?? '' keeps a legacy DNSBL
					// config with no srcint field warning-free.
					$srcint = $list['srcint'] ?? '' ?: FALSE;

					foreach ($list['row'] as $key => $row) {
						if (!empty($row['url']) && $row['state'] != 'Disabled') {

							// Empty header field validation check
							$header		= pfb_filter($row['header'], PFB_FILTER_WORD, 'DNSBL - Processes');
							if (empty($header)) {
								$log = "\n[ {$row['url']} ]{$logtab} Header Field cannot be empty. *Skipping* \n";
								pfb_logger("{$log}", 2);
								continue;
							}
							$header_esc	= escapeshellarg($header);

							$liteparser	= FALSE;	// Minimal DNSBL Parser
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

							if (file_exists("{$pfbfolder}/{$header}.txt") &&
							    !file_exists("{$pfbfolder}/{$header}.update") &&
							    !file_exists("{$pfbfolder}/{$header}.fail") &&
							    $pfbreuse == '') {


								if ($row['state'] == 'Hold') {
									$log = "\n[ {$header} ]{$logtab} static hold.";
								} else {
									$log = "\n[ {$header} ]{$logtab} exists.";
								}
								pfb_logger("{$log}", 1);

								// Collect existing list stats
								$lists_dnsbl_all[]	= "{$row['header']}.txt";
								$lists_dnsbl_current[]	= "{$row['header']}";
								// ADR-62: a reused feed isn't re-parsed; format_hint is always
								// 'plain' now (Python still tolerates a stale 'abp' hint on
								// an untouched manifest, Semantics #7) -- sweep any leftover
								// marker opportunistically.
								unlink_if_exists("{$pfbfolder}/{$header}.abp");	// retired-token-ok: opportunistic stale-marker sweep
								// ADR-31: delegate to pfb_feed_manifest_row() (deny default).
								// ADR-31: pass $mode derived from per-row 'action' (above).
								$pfb_py_feeds[]		= pfb_feed_manifest_row(
									$header, $alias, $logging_type,
									'plain',
									$custom ? 'user' : 'feed',
									$mode);
								$file_esc		= escapeshellarg("{$pfbfolder}/{$header}.txt");
								$list_cnt		= exec("{$pfb['grep']} -c ^ {$file_esc}");
								$alias_cnt		= $alias_cnt + $list_cnt;
							}
							else {
								if ($pfbreuse == 'on' && file_exists("{$pfborig}/{$header}.orig")) {
									$log = "\n[ {$header} ]{$logtab} Reload";
								} else {
									$log = "\n[ {$header} ]{$logtab} Downloading update";
								}
								pfb_logger("{$log}", 1);
								$file_dwn = "{$pfborig}/{$header}";
								$orig_content_stale = FALSE;

								if (!$custom) {
									pfb_logger(' .', 1);

									// Allow cURL SSL downgrade 'Flex' if user configured.
									$pflex = FALSE;
									if ($row['state'] == 'Flex') {
										$pflex = TRUE;
									}

									// Determine if list needs to be downloaded or reuse previously downloaded file.
									if ($pfbreuse == 'on' && file_exists("{$file_dwn}.orig")) {
										// File exists/reuse
										pfb_logger(' completed .', 1);
									} else {
										// Download file
										if (!pfb_download($row['url'], $file_dwn, $pflex, $header,
											$row['format'], 1, '', 300, '', '', '', $srcint)) {

											// Determine reason for download failure
											pfb_download_failure($alias, $header, $pfbfolder, $row['url'], $row['format'], '');
											// ADR-61: keyed on $alias (pfB_/DNSBL_-prefixed), not $header --
											// the widget's deep-link match needs that prefix (issue #998).
											// issue #1048: close moves to once-per-alias-pass below, so a
											// sibling feed's success can never mask this failure.
											$pfb_dl_failed = TRUE;
											pfb_dnsbl_download_ledger_update(FALSE, $alias, "[ {$alias} - {$header} ] Download FAIL", $pfb['dbdir']);

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
										}
									}
								}
								else {
									// Collect custom list data.
									$custom_list = pfbng_text_area_decode($row['custom'], FALSE, TRUE, TRUE);
									@file_put_contents("{$file_dwn}.orig", $custom_list, LOCK_EX);
									unset($custom_list);
									$liteparser = TRUE;
								}

								$run_once = $csv_parser = FALSE;
								$csv_type = '';
								$ipcount = $ip_cnt = $ip_cnt6 = 0;
								$pfb_scheme_skipped = 0;	// ADR-22: per-feed strict scheme/path skips
								$dnsbl_lineno = 0;		// issue #1004: per-line counter for the parse-error detail sink

								// Parse downloaded file for Domain names
								if (($fhandle = @fopen("{$file_dwn}.orig", 'r')) !== FALSE) {
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

											// Remove any '^M' characters
											if (strpos($line, "\r") !== FALSE) {
												$line = rtrim($line, "\x00..\x1F");
											}

											// Remove invalid charaters
											$line = trim($line, " \t\n\r\0\x0B\xC2\xA0");

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
												$domain_data = "{$line}\n";
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

											// CSV parser
											if ($csv_parser) {

												$csv_found = FALSE;
												$csv_count = count($csvline);

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
																continue 2;
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
																continue 2;
															}
														}
														break;
													case 'pon':
														if ($csv_count == 9) {
															$line		= $csvline[2];
															$csv_found	= TRUE;

															// Collect additional IP csv entry (guard value is
															// csvline[0], the collected value is line).
															if ($pfb['dnsbl_ip'] != 'Disabled' &&
															    pfb_dnsbl_collect_feed_ip($csvline[0], $line, $custom, $domain_data_ip, $domain_data_ip6)) {
																$pfb['updateip'] = TRUE;
																$ipcount++;
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
															continue 2;
														}

														// Parse Bambenek Consulting Feed
														elseif (strpos($csvline[3], 'osint.'
															. 'bambenekconsulting.com') !== FALSE) {
															$csv_type	= 'bbc';
															$line		= $csvline[0];
															$csv_found	= TRUE;
															$liteparser	= TRUE;
														}

														// Parse Alienvault OTX pulse Feed
														elseif ($line == 'Indicator type,Indicator,'
																. 'Description') {
															$csv_type	= 'otx';
															$liteparser	= FALSE;
															continue 2;
														}

														// Parse Ponomocup Feed
														elseif (strpos($csvline[0], 'timestamp') !== FALSE) {
															$csv_type	= 'pon';
															$liteparser	= TRUE;
															continue 2;
														}

														// Parse Proofpoint/ET IQRisk IPRep Feed
														elseif ($line == 'domain, category, score') {
															$csv_type	= 'et';
															$liteparser	= TRUE;
															continue 2;
														}

														// Reset variables for CSV determination
														else {
															$csv_parser = $run_once = FALSE;
														}
														break;
												}

												// Record Failed CSV Parse event
												if (!$csv_found || empty($csv_type)) {
													pfb_parsed_fail($header, '', $oline, $pfb['dnsbl_parse_err'], $dnsbl_lineno);
													continue;
												}
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
											if (!$liteparser) {

												$lite = FALSE;
												if (strpos($line, '.') !== FALSE &&
												    ctype_alnum(str_replace('.', '', $line))) {
													$lite = TRUE;
												}
											}
											else {
												$lite = TRUE;
											}

											if (!$lite) {

												// ADR-22: strip the '<scheme>://' prefix. Lenient (toggle ON,
												// the migrated/legacy default) keeps today's permissive strip;
												// strict (toggle OFF, the new-install default) validates the
												// scheme against RFC 3986 and rejects URL paths -- a rejected
												// line is skipped, recorded per-line in the parse-error log, and
												// counted for the once-per-feed summary WARNING below.
												$strict = ($pfb['dnsbl_lenient'] !== PfbLenient::On);
												$line = pfb_dnsbl_scheme_line($line, $strict, $header, $oline,
													$dnsbl_lineno, $pfb['dnsbl_parse_err'], $pfb_scheme_skipped);
												if ($line === FALSE) {
													continue;
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

												// If special characters found, parse line for host
												if (strpos($line, ';') !== FALSE) {
													$host = parse_url($line);
													if (isset($host['host'])) {
														$line = $host['host'];
													} else {
														$line = strstr($line, ';', TRUE);
													}
												}

												// Remove any Port numbers at end of line (IPv6-safe:
												// never mangle a bare IPv6 literal's trailing hextet).
												$line = pfb_strip_trailing_port($line);

												// Issue #938: unwrap a bracketed IPv6 literal (e.g. a
												// URI-style '[2604:2dc0::]') so the is_ipaddrv6($line)
												// collection branch below recognises it.
												$line = pfb_dnsbl_unbracket_ip6($line);
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
												$line = idn_to_ascii($line);
												if (!empty($line)) {
													pfb_logger("{$log} [ {$line} ]", 1);
												}
												else {
													// Record failed parsed line
													pfb_parsed_fail($header, '', $oline, $pfb['dnsbl_parse_err'], $dnsbl_lineno);
													continue;
												}
											}

											// Remove leading/trailing dots
											$line = trim(trim($line), '.');

											// Domain Validation
											if (empty(pfb_filter($line, PFB_FILTER_DOMAIN, 'DNSBL_Download'))) {

												// Reset lite parser
												$liteparser = FALSE;

												// Skip yHost '@' prefixed lines
												if (str_starts_with($line, '@')) {
													continue;
												}

												// Log invalid Domains
												if (!isset($dnsbl_skip[$line])) {
													pfb_parsed_fail($header, $line, $oline, $pfb['dnsbl_parse_err'], $dnsbl_lineno);
												}
												continue;
											}

											// For DNSBL python, save domain and Logging type
											$domain_data = ',' . strtolower($line)
												. ",,{$logging_type},{$header},{$alias}\n";
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

								// Close the "Reload . completed ." progress line with its trailing dot
								// BEFORE the strict-parsing WARNING below, else the warning's own
								// leading/trailing newlines strand this dot on its own line.
								if (!empty($domain_data)) {
									pfb_logger(".\n", 1);
								}

								// ADR-22: one WARNING per feed summarising strict-mode skips (silent
								// when none -- lenient never increments the counter).
								pfb_dnsbl_scheme_skip_warn($pfb_scheme_skipped, $header);

								if (isset($csvline)) {
									unset($csvline);
								}

								// Remove duplicates and save any IPs found in domain feed
								if (!empty($domain_data_ip)) {
									$domain_data_ip = implode("\n", array_unique($domain_data_ip)) . "\n";
									@file_put_contents("{$pfbfolder}/{$header}_v4.ip", $domain_data_ip, LOCK_EX);
									$ip_cnt = exec("{$pfb['grep']} -c ^ " . escapeshellarg("{$pfbfolder}/{$header}_v4.ip"));
								}
								else {
									// Remove previous IP feed
									unlink_if_exists("{$pfbfolder}/{$header}_v4.ip");
								}

								// Remove duplicates and save any IPv6 IPs found in domain feed
								if (!empty($domain_data_ip6)) {
									$domain_data_ip6 = implode("\n", array_unique($domain_data_ip6)) . "\n";
									@file_put_contents("{$pfbfolder}/{$header}_v6.ip", $domain_data_ip6, LOCK_EX);
									$ip_cnt6 = exec("{$pfb['grep']} -c ^ " . escapeshellarg("{$pfbfolder}/{$header}_v6.ip"));
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

									if ($ip_cnt > 0) {
										pfb_logger("  IPv4 count={$ip_cnt}\n", 1);
									}
									if ($ip_cnt6 > 0) {
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
									$result = array('unbound-checkconf: no errors');
								}

								// If parse error found, use previously downloaded file if available


								// Save DNSBL feed info for next steps
								$pfb['domain_update']	= $pfb['aliasupdate'] = $pfb['summary'] = TRUE;
								$lists_dnsbl_all[]	= "{$row['header']}.txt";
								$lists_dnsbl_current[]	= "{$row['header']}";
								// ADR-31: delegate to pfb_feed_manifest_row() (deny default).
								// ADR-31: pass $mode derived from per-row 'action' (above).
								$pfb_py_feeds[]		= pfb_feed_manifest_row(
									$header, $alias, $logging_type,
									'plain',
									$custom ? 'user' : 'feed',
									$mode);

								// ADR-62: the '.abp' marker is retired -- sweep any leftover
								// from a pre-upgrade build (format_hint is always 'plain' now;
								// Python still tolerates a stale manifest naming 'abp').
								unlink_if_exists("{$pfbfolder}/{$header}.abp");	// retired-token-ok: opportunistic stale-marker sweep

								// Rename newly downloaded file to final location
								if (file_exists("{$pfbfolder}/{$header}.bk")) {
									@rename("{$pfbfolder}/{$header}.bk", "{$pfbfolder}/{$header}.txt");
								}

								// Create empty placeholder file
								if (!file_exists("{$pfbfolder}/{$header}.txt")) {
									touch("{$pfbfolder}/{$header}.txt");
								}

								$list_cnt	= exec("{$pfb['grep']} -c ^ " . escapeshellarg("{$pfbfolder}/{$header}.txt"));
								$alias_cnt	= $alias_cnt + $list_cnt;

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
					if (!$pfb_dl_failed) {
						pfb_dnsbl_download_ledger_update(TRUE, $alias, '', $pfb['dbdir']);
					}

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

					// If changes found update DNSBL alias and TLD disabled, call function to update DNSBL alias
					if ($pfb['aliasupdate'] && !$pfb['dnsbl_tld']) {
						dnsbl_alias_update('update', $alias, $pfbfolder, $lists_dnsbl_current, $alias_cnt);
					}

					// Collect Alias/Feeds for post TLD function
					if ($pfb['dnsbl_tld']) {
						if (!is_array($pfb['tld_update'][$alias])) {
							$pfb['tld_update'][$alias] = array();
						}
						$pfb['tld_update'][$alias]['feeds']	= $lists_dnsbl_current;
						$pfb['tld_update'][$alias]['count']	= $alias_cnt;
					}
				}
				else {
					dnsbl_alias_update('disabled', $alias, '', '', '');
				}
			}

		}

		// Remove any unused DNSBL aliases
		$daliases = glob("{$pfb['dnsalias']}/*");
		if (!empty($daliases)) {
			foreach ($daliases as $dlist) {
				if (!in_array(basename($dlist), $pfb['alias_dnsbl_all'])) {
					unlink_if_exists ("{$dlist}");
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
			dnsbl_alias_update('update', 'DNSBL_IDN', '', '', $idn_cnt);
		}
		elseif ($pfb['dnsbl_idn'] === PfbIdnMode::Confusable) {
			$pfb['alias_dnsbl_all'][] = 'DNSBL_Homoglyph';
			dnsbl_alias_update('update', 'DNSBL_Homoglyph', '', '', 1);
			$pfb['alias_dnsbl_all'][] = 'DNSBL_Homoglyph_Suspect';
			dnsbl_alias_update('update', 'DNSBL_Homoglyph_Suspect', '', '', 1);
		}
		if ($pfb['dnsbl_pytld'] == 'on') {
			$pytld_cnt = 0;
			foreach (array('gtld', 'cctld', 'itld', 'bgtld') as $pytld) {
				if (isset($pfb['dnsblconfig']['pfb_pytlds_' . $pytld]) && !empty($pfb['dnsblconfig']['pfb_pytlds_' . $pytld])) {
					$p_cnt = count(explode(',', $pfb['dnsblconfig']['pfb_pytlds_' . $pytld]));
					if (is_numeric($p_cnt) && $p_cnt > 0) {
						$pytld_cnt += $p_cnt;
					}
				}
			}

			$pfb['alias_dnsbl_all'][] = 'DNSBL_TLD_Allow';
			dnsbl_alias_update('update', 'DNSBL_TLD_Allow', '', '', $pytld_cnt);
		}
		// ADR-07: the DNSBL_Regex alias count now reflects the ADMITTED
		// (cap-filtered) feed + user regex total emitted by Python (regexDB +
		// allowRegexDB after the static cap drops over-cap patterns at load) --
		// value changes by design (ADR §2 "Emit + counts"). The Python count file
		// is written at resolver (re)load, so it may be stale/absent on the first
		// run or before a reload; fall back to the configured user-regex line count
		// (today's behaviour) when it is not yet present. Surface the alias when the
		// user regex feature is on OR Python reports admitted feed regex.
		$py_regex_cnt = NULL;
		if (file_exists($pfb['unbound_py_regex_count'])) {
			$raw_rc = trim((string) @file_get_contents($pfb['unbound_py_regex_count']));
			if ($raw_rc !== '' && ctype_digit($raw_rc)) {
				$py_regex_cnt = (int) $raw_rc;
			}
		}
		if ($pfb['dnsbl_regex'] == 'on' || ($py_regex_cnt !== NULL && $py_regex_cnt > 0)) {
			if ($py_regex_cnt !== NULL) {
				$regex_cnt = $py_regex_cnt;
			} else {
				$regex_cnt = 0;
				if (isset($pfb['dnsbl_regex_list'])) {
					$regex_cnt = count(pfbng_text_area_decode($pfb['dnsbl_regex_list'], TRUE, FALSE, FALSE)) ?: 0;
				}
			}
			$pfb['alias_dnsbl_all'][] = 'DNSBL_Regex';
			dnsbl_alias_update('update', 'DNSBL_Regex', '', '', $regex_cnt);
		}

		// Save DNSBL Alias statistics (Not for TLD mode)
		if ($pfb['domain_update'] && !$pfb['dnsbl_tld']) {
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
			// issue #1097: a failed rebuild must not advance the fingerprint -- a stamped
			// .fp marks the stale output current and suppresses every future retry.
			if ($pfb_dnsblip_built) {
				@file_put_contents("{$dnsblip_v4}.fp", $pfb_dnsblip_fp, LOCK_EX);
				unlink_if_exists($pfb['ip_cache']);
				pfb_dnsblip_mark_reprocess($pfb['dnsbl_ip'], '_v4');
			}
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
			// issue #1097: same retry-preserving gate as the v4 path above.
			if ($pfb_dnsblip_built) {
				@file_put_contents("{$dnsblip_v6}.fp", $pfb_dnsblip_fp, LOCK_EX);
				unlink_if_exists($pfb['ip_cache']);
				pfb_dnsblip_mark_reprocess($pfb['dnsbl_ip'], '_v6');
			}
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
			unlink_if_exists("{$pfb['dnsbl_file']}.raw");
			$pfb_dnsbl_sources = array_map(
				static fn(string $current_list): string => "{$pfb['dnsdir']}/{$current_list}",
				$lists_dnsbl_all
			);
			// issue #1097: a failed assembly must keep the live python data/zone files --
			// deleting them ahead of a rename() of a never-created .raw destroys blocking
			// data the next tick would otherwise keep serving until the rebuild succeeds.
			if (pfb_dnsbl_concat_files("{$pfb['dnsbl_file']}.raw", $pfb_dnsbl_sources)) {
				pfb_logger("... completed", 1);

				// DNSBL Python blocking mode, if TLD is not enabled
				if (!$pfb['dnsbl_tld']) {
					unlink_if_exists($pfb['unbound_py_data']);
					unlink_if_exists($pfb['unbound_py_zone']);
					// ADR-10: keep pfb_py_count across a feed/cron rebuild. The zero-downtime
					// fast path's RAM gate (pfb_unbound_py_swap_fits_ram) reads this LIVE count
					// to project the build's ~2x transient; removing it mid-update fail-closed the
					// gate to a RESTART on EVERY feed/cron update, so the swap could never engage
					// for the most common case. The Python build overwrites it with the new count
					// on swap, so the stale value lives only for the brief publish->swap window.
					// The clear-all-feeds path (DNSBL going empty -> restart) still clears it.
					rename("{$pfb['dnsbl_file']}.raw", $pfb['unbound_py_data']);
				}

				// ADR-06: Write the per-feed manifest + IP-stripped raw that the Python
				// plugin's init builds the DNSBL structures from. Python then owns
				// parse/normalise/classify (the dropped shell/PHP passes) and emits
				// pfb_py_count itself.
				pfb_unbound_python_sources($pfb_py_feeds);
			}
			else {
				pfb_logger("\nDNSBL not Updated!\n", 1);
			}
		}

		else {
			$log = "\nDNSBL not Updated!\n";
			pfb_logger("{$log}", 1);
		}
	}
	else {
		if ($pfb['enable'] == 'on' && $pfb['dnsbl'] == 'on') {

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

				// Materialize canonical files as present-but-EMPTY rather than deleting them
				// (#546). Empty-but-present files are byte-identical pass-to-pass, so the
				// fingerprint gate treats empty→empty as unchanged (no reload). A genuine
				// loaded→empty transition still diverges on the first pass (one reload), then
				// stabilises. DO NOT delete pfb_py_wh: pfb_unbound_python() reads it to detect
				// a whitelist change; missing=FALSE !== '' triggers $pfbpython=TRUE every pass.
				pfb_unbound_python_sources(array());		// valid feeds:[] manifest + empty rawdir
				@file_put_contents($pfb['unbound_py_data'], '', LOCK_EX);	// present-but-empty CSV
				unlink_if_exists($pfb['unbound_py_zone']);			// python mode: zone must be absent
				unlink_if_exists($pfb['unbound_py_count']);
				unlink_if_exists($pfb['unbound_py_regex_count']);		// ADR-07
			}
		}
		else {
			foreach (array("{$pfb['dnsbl_file']}.conf", $pfb['unbound_py_data'], $pfb['unbound_py_zone']) as $pfb_file) {
				if (file_exists($pfb_file)) {
					$pfb['domain_clear'] = TRUE;
					@unlink($pfb_file);
				}
			}
			unlink_if_exists($pfb['unbound_py_sources']);
			rmdir_recursive("{$pfb['unbound_py_rawdir']}");
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
	if ($pfb['enable'] == 'on' && $pfb['dnsbl'] == 'on' && $pfb['unbound_state'] == 'on') {
		$mode = 'enabled';
	}
	elseif (($pfb['enable'] == '' || $pfb['dnsbl'] == '') && !$pfb['install']) {
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
		$redir_toggle  = PfbConfig::read('dnsbl_redir');
		$redir_enabled = ($mode === 'enabled') && ($redir_toggle instanceof PfbToggle && $redir_toggle === PfbToggle::On);

		if (!$redir_enabled) {
			// DISABLED: remove all pfB_DNS_Redirect_* NAT rules.
			if (pfb_remove_managed_obj('nat/rule', PFB_DNS_REDIR_DESCR_V4_PFX)) {
				$redir_changed = TRUE;
			}
		} else {
			// ENABLED: read interfaces (comma-separated) and exception alias.
			$redir_iface_raw = (string) PfbConfig::read('dnsbl_redir_int');
			$redir_exception = trim((string) PfbConfig::read('dnsbl_redir_exclude'));

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
		$dot_toggle  = PfbConfig::read('dnsbl_dot_block');
		$dot_enabled = ($mode === 'enabled') && ($dot_toggle instanceof PfbToggle && $dot_toggle === PfbToggle::On);

		if (!$dot_enabled) {
			// DISABLED: remove all pfB_DoT_Block_* filter rules.
			if (pfb_remove_managed_obj('filter/rule', PFB_DOT_BLOCK_DESCR_PFX)) {
				$dot_changed = TRUE;
			}
		} else {
			// ENABLED: read interfaces (comma-separated), exception alias, rule action, floating mode.
			$dot_iface_raw    = (string) PfbConfig::read('dnsbl_dot_block_int');
			$dot_exclude_alias = trim((string) PfbConfig::read('dnsbl_dot_block_exclude'));
			$dot_action       = pfb_dot_block_action((string) PfbConfig::read('dnsbl_dot_block_action'));
			$dot_floating_cfg = PfbConfig::read('dnsbl_dot_block_floating');
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
	// TLD mode (fp_old === null): tld_analysis() writes data/zone INSIDE pfb_update_unbound
	// (after this gate), so the post fingerprint can't see those writes yet — fall back to
	// domain_update / domain_clear as before.
	// The all-missing stable sentinel means empty→empty always yields equal fingerprints,
	// so an unchanged no-feeds steady state no longer triggers a reload every pass.
	$pfb_fp_new = ($pfb_fp_old === null) ? null : pfb_dnsbl_loaded_fingerprint(pfb_dnsbl_loaded_input_paths($pfb));
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
	if ($pfb_data_changed || $pfbupdate || $pfbpython || $safesearch_update ||
	    $pfb_dnsbl_unlock_forced) {

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

		pfb_update_unbound($mode, $pfbupdate, $pfbpython);

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
		if ($pfb['enable'] == 'on' && $pfb['dnsbl'] == 'on' && $pfb['unbound_state'] == 'on' &&
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
				exec("/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php dc >> {$pfb['log']} 2>&1");
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
			$cc_name = 'pfblockerng' . strtolower(str_replace(' ', '', $continent));
			if (isset($continent_config['action']) && $continent_config['action'] != 'Disabled' && $pfb['enable'] == 'on') {

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
									@rename("{$pfb['geoip_tmp']}", "{$pfborig}/{$cc_alias}.orig");
									@copy("{$pfborig}/{$cc_alias}.orig", "{$pfbfolder}/{$cc_alias}.txt");

									// Call Aggregate process
									if ($pfb['agg'] == 'on' && $vtype == '_v4') {
										exec("{$pfb['script']} cidr_aggregate {$cc_alias} {$pfbfolder} {$elog}");
									}

									// issue #1084: snapshot for the batch recompute memberlist -- replaces the
									// 'continent' duplicate() exec. Both families: the v6 continent .txt above is
									// regenerated on every GeoIP change same as v4, so its memberlist entry needs
									// its own fresh snapshot too, not the one-time upgrade seed forever (#1084 review).
									if ($pfbadv) {
										pfb_ip_recompute_write_snapshot("{$pfbfolder}/{$cc_alias}.txt", $cc_alias, $pfb['snapdir'], $pfb['origdir']);
									}

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

	// IPv4 REGEX Definitions
	$pfb['range']	= '/((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))-((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))/';
	$pfb['ipv4']	= '/(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\/(?:\d|[12]\d|3[0-2])\b)?/';

	// IPv6 REGEX Definitions - Reference: http://labs.spritelink.net/regex
	$pfb['ipv6'] = '/(?:(?:(?:[[:xdigit:]]{1,4}:){7}(?:[[:xdigit:]]{1,4}|:))|(?:(?:[[:xdigit:]]{1,4}:){6}(?::[[:xdigit:]]{1,4}|(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(?:(?:[[:xdigit:]]{1,4}:){5}(?:(?:(?::[[:xdigit:]]{1,4}){1,2})|:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(?:(?:[[:xdigit:]]{1,4}:){4}(?:(?:(?::[[:xdigit:]]{1,4}){1,3})|(?:(?::[[:xdigit:]]{1,4})?:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?:(?:[[:xdigit:]]{1,4}:){3}(?:(?:(?::[[:xdigit:]]{1,4}){1,4})|(?:(?::[[:xdigit:]]{1,4}){0,2}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?:(?:[[:xdigit:]]{1,4}:){2}(?:(?:(?::[[:xdigit:]]{1,4}){1,5})|(?:(?::[[:xdigit:]]{1,4}){0,3}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?:(?:[[:xdigit:]]{1,4}:){1}(?:(?:(?::[[:xdigit:]]{1,4}){1,6})|(?:(?::[[:xdigit:]]{1,4}){0,4}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?::(?:(?:(?::[[:xdigit:]]{1,4}){1,7})|(?:(?::[[:xdigit:]]{1,4}){0,5}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(?:%.+)?(?:\/(?:1(?:2[0-8]|[01]\d)|[1-9]?\d)\b)?/';

	if ($pfb['enable'] == 'on' && !$pfb['save']) {

		$pfb['supp_update'] = FALSE;
		$runonce_v4 = $runonce_v6 = TRUE;
		$lists = array();

		// Collect lists and custom list configuration and format into one array ($lists).
		foreach	($ip_types as $ip_type	=> $vtype) {

			// Only the '_v4'/'_v6' suffix may build an alias/path
			if (!pfb_valid_vtype($vtype)) {
				continue;
			}

			foreach (config_get_path("installedpackages/{$ip_type}/config", []) as $key => $list) {
				if (!is_array($list)) {
					$list = array();
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
					$list['row'][] = array(	'header'	=> "{$list['aliasname']}_custom",
											'custom'	=> $list['custom'],
											'state'		=> 'Enabled',
											'url'		=> 'custom'
					);
				}
				$lists[] = $list;
			}

			// Add DNSBLIP, if configured (IPv4 + IPv6)
			if ($pfb['dnsbl'] == 'on' && $pfb['dnsbl_ip'] != 'Disabled' && ($vtype == '_v4' || $vtype == '_v6')) {

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

				foreach	($list['row'] as $row) {
					if (!empty($row['url']) && $row['state'] != 'Disabled') {
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
								pfb_logger($mmsg, $logtype);
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

						// Collect active alias list (Used for pfctl update when 'Reputation' is enabled.
						$pfb_alias_lists_all[] = "{$alias}";

						// Set update flags on new downloads available for GeoIP and ASN
						if ($row['format'] == 'geoip' && file_exists("{$pfb['dbdir']}/geoip.update")) {
							touch("{$pfbfolder}/{$header}.update");
						}
						if ($row['format'] == 'asn' && file_exists("{$pfb['dbdir']}/asn.update")) {
							touch("{$pfbfolder}/{$header}.update");
						}

						if (file_exists("{$pfbfolder}/{$header}.txt") &&
						    !file_exists("{$pfbfolder}/{$header}.update") &&
						    !file_exists("{$pfbfolder}/{$header}.fail") &&
						    $pfbreuse == '') {

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
							$pfbreuse_on = $pfbreuse == 'on';
							$orig_exists_if_reused = $pfbreuse_on && file_exists("{$pfborig}/{$header}.orig");
							if (pfb_ip_reuse_skip_active($pfbreuse_on, $orig_exists_if_reused, isset($list['dnsblip']))) {
								$log = "\n[ {$header} ]{$logtab} Reload";
							} else {
								$log = "\n[ {$header} ]{$logtab} Downloading update";
							}
							pfb_logger("{$log}", 1);
							$file_dwn = "{$pfborig}/{$header}";
							$orig_content_stale = FALSE;

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
										if (file_exists("{$file_dwn}.raw")) {
											$file_dwn_esc = escapeshellarg("{$file_dwn}.raw");
											$file_org_esc = escapeshellarg("{$file_dwn}.orig");
											exec("/usr/bin/gunzip -c {$file_dwn_esc} > {$file_org_esc}");
										}
										exec("{$pfb['script']} et {$header_esc} x x x x x {$pfb['etblock']} {$pfb['etmatch']} {$elog}");
									}
								}
								else {
									// Download list
									if (!pfb_download($row['url'], $file_dwn, $pflex, $header, $row['format'],
										1, $list['vtype'], 300, '', '', '', $srcint)) {

										// Determine reason for download failure
										pfb_download_failure($alias, $header, $pfbfolder, $row['url'], $row['format'], $list['vtype']);
										// ADR-61: sync-status ledger, mirrors the download-fail log above. Keyed on
										// $alias (the pfB_*-prefixed table name), not $header (the per-row label,
										// never prefixed) -- the widget's deep-link recognition matches on the
										// pfB_/DNSBL_ prefix, so keying on $header would leave every entry unlinked.
										// issue #1048: close moves to once-per-alias-pass below, so a
										// sibling feed's success can never mask this failure.
										$pfb_dl_failed = TRUE;
										pfb_ip_download_ledger_update(FALSE, $alias, "[ {$alias} - {$header} ] Download FAIL", $pfb['dbdir']);

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
										pfb_logger('.', 1);
									}
								}
								pfb_logger(' completed .', 1);
							}
							else {
								if ($list['whois_convert'] == 'on') {
									// Process Domain/AS based custom list
									$custom_list = str_replace("\n", ',', pfbng_text_area_decode($list['custom'], FALSE, TRUE, TRUE));
									if (!empty(pfb_filter($custom_list, PFB_FILTER_CSV_WHOIS, 'Process Domain/AS based custom list'))) {
										exec("{$pfb['script']} whoisconvert {$header_esc} {$list['vtype']} {$custom_list} {$elog}");
									} else {
										pfb_logger("\nFailed to process customlist [AS/Whois convert | " . htmlspecialchars($custom_list) . " ]", 1);
									}
								}
								else {
									// Process IP based custom list
									$custom_list = pfbng_text_area_decode($list['custom'], FALSE, TRUE, FALSE);
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

							// IPv4/6 Advanced Tunable - (Pre Script processing)
							if ($pfb_script_pre && is_file("{$pfb_script_pre}")) {
								pfb_logger("\nExecuting pre-script: {$list['script_pre']}\n", 1);
								$file_dwn_esc = escapeshellarg("{$file_dwn}.orig");
								@copy("{$file_dwn}.orig", "{$file_dwn}.orig.pre"); // Save original file for restoration
								$tmo = '/usr/bin/timeout -s TERM -k ' . PFB_HOOK_KILL_GRACE . ' ' . PFB_LIST_SCRIPT_TIMEOUT . ' ';
								exec("{$tmo}" . escapeshellarg($pfb_script_pre) . " {$file_dwn_esc} {$list['vtype']} {$elog}");
							}

							if (($fhandle = @fopen("{$file_dwn}.orig", 'r')) !== FALSE) {
								while (($line = @fgets($fhandle)) !== FALSE) {
									// issue #1004: incremented every iteration, regardless of outcome
									$ip_lineno++;

									// Record original line for regex matching, if required.
									$oline = $line;

									// Remove any leading/trailing whitespaces
									$line = trim($line);

									// Remove commentlines and blank lines (mirrors the DNSBL hosts-
									// format skip -- feeds mix '#'/'!'/'//' comment conventions
									// regardless of the list's own declared format).
									if (pfb_is_blank_or_comment_line($line)) {
										continue;
									}

									$parse_error = FALSE;
									if ($list['vtype'] == '_v4' && $pftype == 'auto') {

										// IBlock - parser sample ( JKS Media, LLC:4.53.2.12-4.53.2.15 )
										// Remove leading domain name details
										if (strpos($line, '-') !== FALSE && strpos($line, ':') !== FALSE) {
											$line = str_replace(':', '', strstr($line, ':', FALSE));
										}

										// If 'space' character found, remove characters after space
										if (strpos($line, ' ') !== FALSE) {
											$line = strstr($line, ' ', TRUE);
										}

										// If '#' character found, remove characters after '#'
										if (strpos($line, '#') !== FALSE) {
											$line = str_replace('#', '', strstr($line, '#', TRUE));
										}

										// Remove any leading/trailing whitespaces
										$line = trim($line);

										// Range parser
										if (strpos($line, '-') !== FALSE) {
											$matches = explode('-', $line);
											if (count($matches) == 2) {
												$a_cidr = ip_range_to_subnet_array($matches[0],$matches[1]);
												if (!empty($a_cidr)) {
													foreach ($a_cidr as $cidr) {
														$cidr = sanitize_ipaddr($cidr, $custom, $pfbcidr);
														if (!empty($cidr)) {
															if (validate_ipv4($cidr)) {
																$ip_data .= $cidr . "\n";
															}
															else {
																$parse_error = TRUE;
															}
														}
													}
													if (!$parse_error) {
														continue;
													}
												}
											}
											else {
												$parse_error = TRUE;
											}
										}

										if (!$parse_error) {
											// Single address parser
											$parsed = sanitize_ipaddr($line, $custom, $pfbcidr);
											if (validate_ipv4($parsed)) {
												$ip_data .= $parsed . "\n";
												continue;
											}
											else {
												$parse_error = TRUE;
											}
										}
									}

									if ($list['vtype'] == '_v4' && ($pftype == 'regex' || $parse_error)) {

										// Use regex as last alternative.

										if (strpos($oline, '-') !== FALSE && strpos($oline, '.') !== FALSE) {
											// Network range 192.168.0.0-192.168.0.254
											if (preg_match($pfb['range'], $oline, $matches)) {
												$a_cidr = ip_range_to_subnet_array($matches[1], $matches[2]);
												if (!empty($a_cidr)) {
													foreach ($a_cidr as $cidr) {
														$cidr = sanitize_ipaddr($cidr, $custom, $pfbcidr);
														if (validate_ipv4($cidr)) {
															$ip_data .= $cidr . "\n";
														}
														else {
															// issue #1004: detail sink deliberately Site-B-only (per-line);
															// this per-CIDR path can fire many times per source line.
															$parse_fail++;
														}
													}
												}
												continue;
											}
										}

										// IPv4/CIDR format 192.168.0.0 | 192.168.0.0/16
										// A match requires 3 literal dots; skip the regex engine on lines that cannot contain one.
										if (substr_count($oline, '.') >= 3 && preg_match_all($pfb['ipv4'], $oline, $matches)) {
											$matches = array_unique($matches[0]);
											foreach ($matches as $match) {

												// Workaround to skip cloudflare error pages
												if (strpos($oline, 'cf-footer-item') === FALSE) {
													$parsed = sanitize_ipaddr($match, $custom, $pfbcidr);
													if (validate_ipv4($parsed)) {
														$ip_data .= $parsed . "\n";
													}
												}
											}
											continue;
										}
									}

									if ($list['vtype'] == '_v6') {
										// Auto IPv6 parser
										if ($pftype == 'auto') {
											if (strpos($line, ':') !== FALSE) {

												// Remove any comments
												if (strpos($line, '#') !== FALSE) {
													$line = str_replace('#', '', strstr($line, '#', TRUE));
												}

												if (validate_ipv6($line)) {
													$parsed = sanitize_ipaddr_v6($line, $custom, $pfbcidr_v6);
													if (!empty($parsed)) {
														$ip_data .= $parsed . "\n";
													}
													else {
														$ip_suppressed = TRUE;
													}
													continue;
												}
											}
										}

										// Range parser
										if (strpos($line, '-') !== FALSE && strpos($line, ':') !== FALSE) {
											$matches = explode('-', $line);
											if (count($matches) == 2) {
												$a_cidr = ip_range_to_subnet_array($matches[0],$matches[1]);
												if (!empty($a_cidr)) {
													foreach ($a_cidr as $cidr) {
														if (!empty($cidr)) {
															if (validate_ipv6($cidr)) {
																$parsed = sanitize_ipaddr_v6($cidr, $custom, $pfbcidr_v6);
																if (!empty($parsed)) {
																	$ip_data .= $parsed . "\n";
																}
																else {
																	$ip_suppressed = TRUE;
																}
															}
															else {
																$parse_error = TRUE;
															}
														}
													}
												}
												if (!$parse_error) {
													continue;
												}
											}
											else {
												$parse_error = TRUE;
											}
										}

										// IPv6 Regex parser
										// A match requires a literal colon; skip the regex engine on colon-less lines.
										if (strpos($oline, ':') !== FALSE && preg_match_all($pfb['ipv6'], $oline, $matches)) {
											$matches = array_unique($matches[0]);
											foreach ($matches as $match) {

												// Remove any comments
												if (strpos($match, '#') !== FALSE) {
													$match = str_replace('#', '', strstr($match, '#', TRUE));
												}

												// Workaround to skip cloudflare error pages
												if (strpos($oline, 'cf-footer-item') === FALSE) {
													if (validate_ipv6($match)) {
														$parsed = sanitize_ipaddr_v6($match, $custom, $pfbcidr_v6);
														if (!empty($parsed)) {
															$ip_data .= $parsed . "\n";
														}
														else {
															$ip_suppressed = TRUE;
														}
													}
												}
											}
											// Mirrors the IPv4 regex-parser sibling block above: without this,
											// a line the regex already matched and collected still falls
											// through to the parse-fail heuristic below and is double-counted.
											continue;
										}
									}

									// Check for parse failures
									if (!empty($line) && !preg_match('/[a-zA-Z,;|\"\'?]/', $line)) {

										// A syntactically valid address of the list's OTHER family (a
										// hex-letter-free IPv6 line in a '_v4' list, or an IPv4 line in
										// a '_v6' list) is not a parse failure -- mixed-family feeds are
										// common, and the family this list doesn't collect is silently
										// skipped either way (same as any hex-lettered opposite-family
										// address already is, uncounted). Only flag genuine garbage.
										$other_family_addr = pfb_ip_is_opposite_family($line, $list['vtype']);

										if (!$other_family_addr) {
											$parse_fail++;
											pfb_ip_parsed_fail($header, $line, $oline, $pfb['ip_parse_err'], $ip_lineno);
										}
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
								$tmo = '/usr/bin/timeout -s TERM -k ' . PFB_HOOK_KILL_GRACE . ' ' . PFB_LIST_SCRIPT_TIMEOUT . ' ';
								exec("{$tmo}" . escapeshellarg($pfb_script_post) . " {$file_org_esc} {$list['vtype']} {$elog}");
							}

							if (!$custom) {
								// Check to see if list actually failed download or has no IPs listed.
								$file_chk = '';
								if (file_exists("{$file_dwn}.orig") && @filesize("{$file_dwn}.orig") > 0) {
									$file_org_esc = escapeshellarg("{$file_dwn}.orig");
									$file_chk = exec("{$pfb['grep']} -cv '^#\|^\$' {$file_org_esc}");
								}

								if ($file_chk == 0) {
									if ($list['vtype'] == '_v6') {
										$p_ip = "::{$pfb['ip_ph']}";
									} else {
										$p_ip = $pfb['ip_ph'];
									}

									$ip_data	= "{$p_ip}\n";
									$log		= "  Empty file, Adding '{$p_ip}' to avoid download failure.\n";
									pfb_logger("{$log}", 1);
								}
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
									$args = pfb_ip_preprocess_args($pfb['dup'] == 'on', $pfb['agg'] == 'on', $pfb['rep'] == 'on');
									if (!empty($args)) {
										exec("{$pfb['script']} {$args} {$header_esc} {$pfb['max']} {$pfb['drep']} {$pfb['ccexclude']} {$pfb['ccwhite']} {$pfb['ccblack']} {$elog}");
									}

									// issue #1084: snapshot the pristine post-preprocessing feed for the
									// batch recompute memberlist -- replaces duplicate()'s per-feed write.
									pfb_ip_recompute_write_snapshot("{$pfbfolder}/{$header}.txt", $header, $pfb['snapdir'], $pfb['origdir']);
								}

								if (!$pfbadv && $list['vtype'] == '_v4') {
									// Call Aggregate process
									if ($pfb['agg'] == 'on') {
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
								if (pfb_supp_update_active($pfbadv, $pfb['supp'] == 'on')) {
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
							// Restore Original Downloaded file after Pre Script function 
							if (file_exists("{$file_dwn}.orig.pre")) {
								@rename("{$file_dwn}.orig.pre", "{$file_dwn}.orig");
							}
						}
					}
				}

				// issue #1048: close the download ledger entry once for the WHOLE
				// alias-pass, iff no row in it failed -- a per-row close let a later
				// feed's success mask an earlier feed's still-live failure.
				if (!$pfb_dl_failed) {
					pfb_ip_download_ledger_update(TRUE, $alias, '', $pfb['dbdir']);
				}
			}
		}
	}

	// Remove database update file markers
	unlink_if_exists("{$pfb['dbdir']}/geoip.update");
	unlink_if_exists("{$pfb['dbdir']}/asn.update");

	#################################
	#	REPUTATION PROCESSES	#
	#################################

	// issue #1084: batch recompute replaces the incremental duplicate()/dmax/pmax pass.
	// enable_dup drives a full v4+v6 pass; dedup-off + reputation alone is v4-only; both
	// off skips recompute (parse output stands) -- see pfb_ip_recompute_matrix(). The
	// whole block rides the feed-changed trigger: a quiet pass (no snapshot written, no
	// removal -- repcheck FALSE) runs no recompute at all.
	$pfb_rec_trigger = $pfb['repcheck'] && !$pfb['save'] && $pfb['enable'] == 'on';
	$pfb_rec_matrix  = pfb_ip_recompute_matrix(
		$pfb['dup'] == 'on' && $pfb_rec_trigger,
		$pfb_rec_trigger,
		$pfb['drep'] == 'on',
		$pfb['prep'] == 'on'
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
		@file_put_contents($pfb_rec_memberlist, $pfb_rec_paths ? (implode("\n", $pfb_rec_paths) . "\n") : '', LOCK_EX);

		// Reputation is v4-only (§1.2); the v6 pass is always a dedup-only passthrough.
		$pfb_rec_repmode = ($pfb_rec_family === 'v4') ? $pfb_rec_matrix['repmode'] : 'off';
		$pfb_rec_max     = ($pfb_rec_repmode === 'dmax') ? $pfb['dmax'] : (($pfb_rec_repmode === 'pmax') ? $pfb['pmax'] : '0');

		exec("{$pfb['script']} recompute {$pfb_rec_family} " . escapeshellarg($pfb_rec_memberlist) . ' ' . escapeshellarg($pfb_rec_countsfile)
			. " {$pfb_rec_matrix['dedup']} {$pfb_rec_repmode} {$pfb_rec_max} {$pfb['ccexclude']} {$pfb['ccwhite']} {$pfb['ccblack']} {$elog}");

		if ($pfb_rec_family === 'v4') {
			$pfb_recompute_ran_v4 = TRUE;
		} else {
			$pfb_recompute_ran_v6 = TRUE;
		}
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
		$pfb['dup'] == 'on',
		$pfb['drep'] == 'on' || $pfb['prep'] == 'on'
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
		if ($pfb['dnsbl'] == 'on' && $pfb['dnsbl_ip'] != 'Disabled' && ($vtype == '_v4' || $vtype == '_v6')) {

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

		if (!empty($lists) && $pfb['enable'] == 'on') {
			$pfbrunonce = TRUE;
			foreach ($lists as $key => $list) {
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
									// Script to run suppression process (print header only)
									if ($pfbrunonce && $pfb['supp'] == 'on' && $vtype == '_v4' && $pfb['supp_update']) {
										exec("{$pfb['script']} suppress suppressheader {$elog}");
										$pfbrunonce = FALSE;
									}
									// Script to run suppression process (body) — feed-changed aliases, OR any
									// alias recompute rewrote this pass (issue #1084 review: recompute rewrites
									// every family alias on any trigger, not just feed-changed ones).
									if (pfb_ip_suppress_body_active($pfb['supp'] == 'on', $vtype == '_v4', $pfb['supp_update'], $pfbadv, in_array($alias, $final_alias_old), $pfb_recompute_ran_v4)) {
										if ($pfb['dup'] == 'on') {
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
									if ($pfbrunonce && $pfb['supp'] == 'on' && $vtype == '_v6' && $pfb['supp_update']) {
										$supp_v6_header = "\n===[ Suppression Stats (v6) ]===============================\n\n"
											. sprintf("%-20s %-10s %-10s\n", 'List', 'Pre', 'Suppress')
											. "-------------------------------------------------------------\n";
										@file_put_contents("{$pfb['log']}", $supp_v6_header, FILE_APPEND);
										$pfbrunonce = FALSE;
									}
									if (pfb_ip_suppress_body_active($pfb['supp'] == 'on', $vtype == '_v6', $pfb['supp_update'], $pfbadv, in_array($alias, $final_alias_old), $pfb_recompute_ran_v6)
									    && is_readable("{$pfb['supptxt_v6']}") && filesize("{$pfb['supptxt_v6']}") > 0) {
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
	    && !empty($pfb['dnsblconfig']['dnsbl_allow_int']) && ($pfb['dnsbl'] == 'on')) {

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
	pfb_build_aggregate_aliases($new_aliases, $new_aliases_list, $pfb_alias_lists);

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
	if ($pfb['autorules'] || $pfb['enable'] == '' || $pfb['remove']) {
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
			if ($pfb['enable'] == 'on' && $pfb['dnsbl'] == 'on' && $pfb['dnsbl_rule'] != 'Disabled'
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
	if ($pfb['autorules'] && $orig_rules_nocreated != $new_rules_nocreated || $pfb['enable'] == '' || $pfb['remove']) {

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
				$pfb_delta_mode  = (string) PfbConfig::read('pfb_alias_delta_mode')->toStored();
				$pfb_delta_batch = pfb_alias_delta_batch_clamp((string) PfbConfig::read('pfb_alias_delta_batch'));

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
	if (!$pfb['save'] && $pfb['enable'] == 'on' &&
	    pfb_cfg_toggle_read($pfb['config']['pfb_reuse']) === PfbToggle::On) {

		pfb_logger("\nSaving config changes", 1);

		// Reload config.xml FIRST to pick up edits made concurrently during this
		// (long-running) update, THEN clear the flag through the gateway so the write
		// lands on the freshly-reloaded config. Writing before the reload would be
		// discarded by it; a single registered-key write needs no whole-config
		// array_replace_recursive() merge. ADR-29: registered key -> PfbConfig.
		config_read_file(FALSE, TRUE);
		PfbConfig::write('pfb_reuse', PfbToggle::Off);
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
	if ($pfb['filter_configure']) {

		// Remove any IPs in Alerts unlock feature
		unlink_if_exists("{$pfb['ip_unlock']}");

		// Remove IP Cache file
		unlink_if_exists($pfb['ip_cache']);

		require_once('filter.inc');
		filter_configure();

		// Stop/Restart pfb_filter service for new rule changes
		if ($pfb['enable'] == '') {
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
		if ($pfb['enable'] == '' && is_service_running('pfb_filter')) {
			$log = 'Stopping firewall filter daemon';
			stop_service('pfb_filter');
		}
		elseif ($pfb['enable'] == 'on' && !is_service_running('pfb_filter')) {
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

	if (!$pfb['save'] && $pfb['kstates'] && !$pfb['filter_configure']) {
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

	// ADR-43: one trigger-tick replaces the cron/dcc/ss_refresh/bl fleet.
	// A single */pfb_tick_interval cron entry fires; the tick reads the due-ledger
	// and dispatches each job only when its entry says "due". clearip/cleardnsbl
	// are out of scope (ADR-30 territory) and remain as separate jobs below.
	$pfb_tick_min = '*/' . pfb_tick_interval_clamp(PfbConfig::read('pfb_tick_interval'));
	$pfb_tick_cmd = "/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php tick >> {$pfb['log']} 2>&1";

	if ($pfb['enable'] == 'on') {
		if (!pfblockerng_cron_exists($pfb_tick_cmd, $pfb_tick_min, '*', '*', '*')) {
			install_cron_job('pfblockerng.php tick', FALSE);	// remove stale tick (interval changed)
			install_cron_job($pfb_tick_cmd, TRUE, $pfb_tick_min, '*', '*', '*', '*', 'root');
		}
	}
	else {
		install_cron_job('pfblockerng.php tick', FALSE);
	}

	// Migration teardown: remove old fleet jobs from pre-ADR-43 installs.
	install_cron_job('pfblockerng.php cron', FALSE);
	install_cron_job('pfblockerng.php dcc', FALSE);
	install_cron_job('pfblockerng.php ss_refresh', FALSE);
	install_cron_job('pfblockerng.php bl', FALSE);

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
	if ((!$pfb['save'] && $pfb['repcheck'] && $pfb['enable'] == 'on') || $pfb['summary']) {
		// issue #1084 review: dedup off + recompute having run the v4 family (the
		// dup-off+rep-on passthrough) still invokes 'closing off' so emptyfiles() refills
		// any alias pMax/dMax collapsed to zero rows -- see pfb_ip_closing_pass_active().
		[$pfb_closing_invoke, $pfb_closing_alias_arg] = pfb_ip_closing_pass_active($pfb['dup'] == 'on', $pfb_recompute_ran_v4);
		if ($pfb_closing_invoke) {
			exec("{$pfb['script']} closing {$pfb_closing_alias_arg} {$elog}");
		}
		if ($pfb['dup'] == 'on') {
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
		'DNSBL_CHANGED'		=> (!empty($pfb_data_changed) || !empty($pfbupdate) || !empty($pfbpython) ||
						!empty($safesearch_update) || !empty($pfb_dnsbl_unlock_forced)) ? '1' : '0',
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
	// banner. A General-page save ($pfb['save']=TRUE) deliberately does not reach this, so its
	// changes stay flagged until a genuine cron/Run-Now Update applies them.
	if (!$pfb['save']) {
		pfb_clear_pending_changes();
	}

	if ($pfb['enable'] == 'on' && !$pfb['save'] || $pfb['summary']) {
		pfb_logger("\n UPDATE PROCESS ENDED\n", 1);
	}
}


// Function to De-Install pfBlockerNG
function pfblockerng_php_pre_deinstall_command() {
	require_once('config.inc');
	global $g, $pfb;

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

	unlink_if_exists("{$g['unbound_chroot_path']}/pfb_unbound.py");
	unlink_if_exists("{$g['unbound_chroot_path']}/pfb_unbound_include.inc");
	unlink_if_exists("{$g['unbound_chroot_path']}/pfb_py_hsts.txt");

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
	if ($pfb['keep'] != 'on') {
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

	unlink_if_exists("{$pfb['dnsbl_cache']}");
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
						pfb_logger("\n Sync with [ {$protocol}://{$sync_to_ip}:{$port} ] ...", 1);
						$success = pfblockerng_do_xmlrpc_sync($sync_to_ip, $port, $protocol, $username, $password, $synctimeout);

						if ($success) {
							pfb_logger(" done.\n", 1);
							logger(LOG_NOTICE, localize_text("XMLRPC sync to [ %s ] completed successfully.", "{$sync_to_ip}:{$port}"), LOG_PREFIX_PKG_PFBLOCKERNG);
						} else {
							pfb_logger(" Failed!\n", 1);
						}
					} else {
						pfb_logger(" terminated due to the following error(s): {$error}", 1);
						logger(LOG_ERR, localize_text("XMLRPC sync to [ %s:%s ] terminated due to the following error(s): %s", $sync_to_ip, $port, $error), LOG_PREFIX_PKG_PFBLOCKERNG);
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

	// If User Disabled, remove 'General/IP/DNSBL Tab Customizations' from Sync
	$sections = pfblockerng_sync_sections(config_get_path('installedpackages/pfblockerngsync/config/0/syncinterfaces') != 'on');

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
	// If User Disabled, remove 'General/IP/DNSBL Tab Customizations' from Sync
	$sections = pfblockerng_sync_sections(config_get_path('installedpackages/pfblockerngsync/config/0/syncinterfaces') != 'on');
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

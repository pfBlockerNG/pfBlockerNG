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
				"{$pfb['dnsdir']}", "{$pfb['dnsorigdir']}", "{$pfb['dnsalias']}");

// Files
$pfb['log']		= "{$pfb['logdir']}/pfblockerng.log";
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

$pfb['master']		= "{$pfb['dbdir']}/masterfile";
$pfb['supptxt']		= "{$pfb['dbdir']}/pfbsuppression.txt";
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
$pfb['unbound_py_regex_count']= '/var/unbound/pfb_py_regex_count';	// ADR-07 P8: Python-emitted ADMITTED (cap-filtered) feed+user regex total for the DNSBL_Regex alias
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
					'application/zip'));

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

// Validate the DNS-redirect fields submitted via the DNSBL settings POST form.
// Each interface name is checked against the allow-list; the exception alias is
// validated by is_validaliasname() when non-empty.
// Returns an array of validation error messages (empty = all inputs valid).
function pfb_validate_dns_redirect_post(
	array $posted_ifaces,
	array $valid_iface_list,
	string $posted_alias
): array {
	$errors = [];
	foreach ($posted_ifaces as $iface) {
		if (!in_array($iface, $valid_iface_list, TRUE)) {
			$errors[] = 'DNS Redirect: Invalid interface selection: ' .
				htmlspecialchars((string) $iface, ENT_QUOTES);
		}
	}
	if ($posted_alias !== '') {
		if (!is_validaliasname($posted_alias)) {
			$errors[] = 'DNS Redirect: Invalid exception alias name: ' .
				htmlspecialchars($posted_alias, ENT_QUOTES);
		}
	}
	return $errors;
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
	$errors = [];
	foreach ($posted_ifaces as $iface) {
		if (!in_array($iface, $valid_iface_list, TRUE)) {
			$errors[] = 'DoT/DoQ Block: Invalid interface selection: ' .
				htmlspecialchars((string) $iface, ENT_QUOTES);
		}
	}
	if ($posted_alias !== '') {
		if (!is_validaliasname($posted_alias)) {
			$errors[] = 'DoT/DoQ Block: Invalid exception alias name: ' .
				htmlspecialchars($posted_alias, ENT_QUOTES);
		}
	}
	if (!in_array($posted_action, ['block', 'reject'], TRUE)) {
		$errors[] = 'DoT/DoQ Block: Invalid rule action: ' .
			htmlspecialchars($posted_action, ENT_QUOTES);
	}
	return $errors;
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
	$source = ($exclude_alias !== '')
		? ['address' => $exclude_alias, 'not' => '']
		: ['any' => ''];

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

// Validate and normalise the Reports-tab whitelist composite 'atype' parameter,
// which arrives as 'Whitelist|<ip>|<description>'. The IP is validated via
// PFB_FILTER_IP (is_ipaddr); an invalid IP yields an empty IP slot
// ('Whitelist||<descr>') that the downstream invalid-IP branch in the addgroup
// block catches and surfaces as a user-visible error. The description is kept as
// normalised raw text — control characters and newlines are collapsed to a single
// space so it cannot inject extra lines into the (base64-stored) custom list — and
// is NOT HTML-encoded here: storage is base64 and each display sink escapes on
// output (json_encode for the JS variable, Form_Input/Form_Textarea for HTML).
// Splitting with a limit of 3 preserves any '|' characters inside the description.
// A non-'Whitelist' first token is rejected (returns '').
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

// Function to filter/sanitize user input
function pfb_filter($input, $type, $reference='Unknown', $default='', $escape=FALSE) {
	global $pfb;

	$header = "\n PFB_FILTER - {$type} | {$reference} [ NOW ]";

	$return_type = $default;
	if (in_array($type, array(PFB_FILTER_URL, PFB_FILTER_FILE_MIME_COMPARE, PFB_FILTER_FILE_MIME, PFB_FILTER_FILE_MIME_COMPRESSED))) {
		$return_type = FALSE;
	}

	if (!in_array($type, array(PFB_FILTER_ON_OFF, PFB_FILTER_NUM))) {
		if (empty($input) || is_null($input)) {
			return $return_type;
		}
	}

	// Check for control characters
	if (is_array($input)) {
		foreach ($input as $vline) {
			if (preg_match("/[\p{C}]+/", $vline)) {
				pfb_logger("{$header} Control characters found [ " . htmlspecialchars($vline) . " ]", 6); 
				return $return_type;
			}
		}
	}
	else {
		if (preg_match("/[\p{C}]+/", $input)) {
			pfb_logger("{$header} Control characters found [ " . htmlspecialchars($input) . " ]", 6);
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
						pfb_logger("{$header} Invalid URL Scheme [ " . htmlspecialchars($input) . " ]", 6);
						return FALSE;
					}
				}

				$validate_list = '';
				if (!$data || !is_array($data)) {
					pfb_logger("{$header} Invalid URL (missing data) [ " . htmlspecialchars($input) . " ]", 6);
					return FALSE;
				} elseif (!isset($data['host']) || empty($data['host'])) {
					pfb_logger("{$header} Invalid URL (missing hostname) [ " . htmlspecialchars($input) . " ]", 6);
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
					pfb_logger("{$header} Invalid URL (cannot resolve) [ " . htmlspecialchars($input) . " ]", 6);
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
						pfb_logger("{$header} Invalid URL (alerts tab) [ " . htmlspecialchars($input) . " ]", 6);
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
					pfb_logger("{$header} Invalid URL (not allowed) [ " . htmlspecialchars($input) . " ]", 6);
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
					pfb_logger("{$header} Invalid URL ({$reason}) [ " . htmlspecialchars($input) . " ]", 6);
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
					pfb_logger("\n[PFB_FILTER - {$type}] Invalid URL (cannot resolve path) [ " . htmlspecialchars($input) . " ]", 6);
					return FALSE;
				}

				// The basename must be a plain filename — no directory
				// separators or '..' surviving canonicalization.
				$base = basename($real);
				if ($base === '' || $base === '.' || $base === '..' ||
				    strpbrk($base, '/\\') !== FALSE) {
					pfb_logger("\n[PFB_FILTER - {$type}] Invalid URL (not allowed2) [ " . htmlspecialchars($input) . " ]", 6);
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
			pfb_logger("\n[PFB_FILTER - {$type}] Invalid URL (not allowed2) [ " . htmlspecialchars($input) . " ]", 6);
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
			if (isset($retval)) {
				unset($retval);
			}
			if (isset($output)) {
				unset($output);
			}
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

			if (isset($retval)) {
				unset($retval);
			}
			if (isset($output)) {
				unset($output);
			}
			if (!file_exists($input[1])) {
				pfb_logger("{$header} Downloaded file not found: [" .  htmlspecialchars($input[0]) . "|" . htmlspecialchars($input[1]) . "]", 2);
				return FALSE;
			}
			exec("/usr/bin/file -b --mime-type " . escapeshellarg($input[1]) . " 2>&1", $output, $retval);
			if ($retval != 0 || empty($output[0]) || !isset($pfb['mime_types'][$output[0]])) {

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
					pfb_logger("\n[PFB_FILTER - {$type}] Failed or invalid Mime Type: [" .  htmlspecialchars($output[0]) . "|" . htmlspecialchars($retval) . "]", 2);
					unlink_if_exists($input[1]);
					return FALSE;
				}
			}
			$result = htmlspecialchars($output[0]);
			break;
		case PFB_FILTER_FILE_MIME_COMPRESSED:
			// Validate File Mime-types in compressed files
			// $input [0] path/file (legacy, unused), [1] path/file [2] URL
			// The probed path ($input[1]) is escapeshellarg()'d at the sink below,
			// so callers need not pre-escape it.
			if (isset($retval)) {
				unset($retval);
			}
			if (isset($output)) {
				unset($output);
			}
			if (!file_exists($input[1])) {
				pfb_logger("{$header} Downloaded file not found: [" .  htmlspecialchars($input[0]) . "|" . htmlspecialchars($input[1]) . "]", 2);
				return FALSE;
			}
			exec("/usr/bin/file -bZ --mime-type " . escapeshellarg($input[1]) . " 2>&1", $output, $retval);
			if ($retval != 0 || empty($output[0]) || !isset($pfb['mime_types'][$output[0]])) {
				pfb_logger("{$header} Failed or invalid Mime Type Compressed: [" .  htmlspecialchars($output[0]) . "|" . htmlspecialchars($retval) . "]", 2);
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

		// Exceptions
		if (in_array($reference, array(	'DNSBL_Download'))) {
			//
		} else {
			pfb_logger("{$header} Failed validation [ " . htmlspecialchars($input) . " ]", 6);
		}
	}

	return $result == FALSE ? $default : $result;
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

// [ ADR-13 ] Pure decision: is a v6 sinkhole VIP WANTED for this DNSBL config?
// True iff the DNS Resolver listens on IPv6 AND the package is NOT auto-provisioning
// the VIP (manual mode). When auto-create is on, pfb_manage_dnsbl_vip() provisions the
// v6 VIP with no user friction. When auto is off, a v6-listening resolver SHOULD have a
// v6 sinkhole VIP so AAAA blocks are sinkholed too — but this is a NON-BLOCKING
// recommendation (ADR-13 §7 pivot): pfb_global logs a warning and DNSBL keeps running
// on IPv4. It is NOT a hard requirement — an earlier revision force-disabled DNSBL here,
// which broke every existing manual setup whose resolver listens on IPv6 without a v6
// VIP (the common case). Pure: takes the two booleans, decides; no global/config access,
// so the recommendation has a single, directly-testable source of truth.
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
			return "{$dir}/{$name}";	// ponytail: in-dir path; exec follows the (contained) link
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

// v6 stays OPTIONAL (ADR-13 §7 pivot): a missing v6 VIP never fails validation, even when
// the resolver listens on IPv6 — pfb_global surfaces that as a non-blocking warning, not a
// force-disable. The validator only checks the VIPs that ARE configured (existence,
// interface, overlap). Behaviour is identical to before the (reverted) Phase-3 hard rule.
function pfb_validate_vips(string $interface, string|null $vip4 = '', string|null $vip6 = ''): array {
	$enabled4 = !empty($vip4);
	$enabled6 = !empty($vip6);

	if (!$enabled4 && !$enabled6) {
		return [FALSE, gettext('no VIP configured')];
	}

	if ($enabled4 && ($interface != get_configured_vip_interface($vip4))) {
		return [FALSE, sprintf(gettext('IPv4 VIP not on interface %s'), convert_friendly_interface_to_friendly_descr($interface))];
	}
	if ($enabled6 && ($interface != get_configured_vip_interface($vip6))) {
		return [FALSE, sprintf(gettext('IPv6 VIP not on interface %s'), convert_friendly_interface_to_friendly_descr($interface))];
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

// [ ADR-13 / issue #473 / issue #487 ] Small fixed ordered list of DNS-themed
// candidate sinkhole VIP addresses for a family. Pure (no side effects).
//
// IPv4 — three candidates, Class B first (least-used RFC1918 on end-user LANs),
// then Class C, then Class A (most-used, so last). Each is a /32 .53 host
// (DNS-port homage):
//   172.16.53.53  (172.16/12)
//   192.168.53.53 (192.168/16)
//   10.53.53.53   (10/8)
//
// IPv6 — single ULA candidate: fd00:53:53:53:53:53:53:53 (/128). On conflict
// the picker returns null and the user resolves it manually (an IPv6 user on
// that exact ULA can address it themselves without a larger pool).
//
// The conflict-aware picker (pfb_pick_free_dnsbl_vip) returns the first free one.
// Returns [] for any other family.
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

// [ ADR-13 ] True iff the DNS Resolver (Unbound) is configured to listen on at least
// one IPv6 address. Mirrors how pfSense builds Unbound's listen set in
// unbound_generate_config_text() (src/etc/inc/unbound.inc) — verified verbatim
// against upstream at RELENG_2_7_2 (frozen public-mirror ref, signatures stable
// 2.7->2.8) and master; the active_interface key, the empty/'all' => automatic
// branch, and the per-interface get_interface_ip()/get_interface_ipv6() resolution
// are identical across both refs:
//
//   $active = array_filter(explode(',', $unboundcfg['active_interface']));
//   if (empty($active) || in_array('all', $active, true)) { interface-automatic: yes }
//   else foreach ($active as $ubif) { ... get_interface_ipv6($ubif) -> bind v6 ... }
//
// Predicate (conservative/correct over clever):
//   * Resolver disabled (config_path_enabled('unbound') false) -> listens on nothing
//     -> false.
//   * active_interface empty or contains 'all' -> Unbound emits 'interface-automatic:
//     yes' and binds EVERY address on its enabled interfaces, v6 included -> true iff
//     ANY configured interface currently resolves to an IPv6 address (get_interface_ipv6).
//   * otherwise -> the explicit per-interface list: true iff ANY listed token is a v6
//     literal (is_ipaddrv6) or an interface that resolves to a v6 address
//     (get_interface_ipv6), mirroring upstream's bind loop (incl. the up/enabled
//     status guard from redmine #11087).
//
// MUST still be confirmed on-box (no PHP/Unbound runtime in CI): that
// get_interface_ipv6() returns a routable v6 (not just link-local) for an automatic
// bind, and that 'interface-automatic: yes' does in fact accept v6 queries on the
// box's configuration. Used by Phase 3 (v6-mandatory rule) — UNWIRED in Phase 1.
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

// [ ADR-13 ] Locate the index of the auto-managed DNSBL VIP this package owns inside a
// virtualip/vip array. Pure (no side effects). Ownership is decided by TWO predicates,
// both required, mirroring the lifecycle contract:
//   (1) MARKER  : pfb_is_managed_obj($vip['descr']) AND marker match via the same
//                 prefix/contains logic as pfb_find_managed_obj. VIP markers
//                 (PFB_AUTO_VIP_DESCR_V4/V6) start with 'pfB_' → str_starts_with.
//   (2) IP MATCH: when $match_ip is a non-empty string, $vip['subnet'] must equal it.
//                 Used on delete to bind removal to the address currently resolved from
//                 the stored pfb_dnsvip4/6 config, so we never delete a marked VIP whose
//                 address no longer corresponds to our config. Pass null to match on the
//                 marker alone (idempotent reuse on create, before any id is stored).
// Returns the integer key of the first matching entry, or null if none matches.
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

// [ ADR-13 ] VIP lifecycle manager. Creates the marked DNSBL sinkhole VIP(s) on enable
// (when 'Create VIPs automatically' is on) and removes ONLY the marked + IP-matched
// VIP(s) on disable / when no longer managed. Wired into pfb_create_dnsbl($mode).
//
// ADDITIVE: with pfb_dnsvip_auto off (and never previously on) there is no marked VIP,
// so neither the enabled nor the disabled path finds a marker+IP-matched VIP to remove
// -> $changed stays FALSE -> no write_config -> the runtime is byte-identical to today.
//
// Marker/IP delete guard: a VIP is removed iff BOTH (a) its descr equals
// PFB_AUTO_VIP_DESCR_V4/_V6 AND (b) its subnet equals the IP currently resolved from the
// stored pfb_dnsvip4/6 config (pfb_find_marked_vip(..., $match_ip)). A manually-created
// VIP (no marker) is NEVER touched; a marked VIP whose address no longer matches stored
// config is NEVER deleted on the basis of the marker alone.
//
// Create apply sequence matches upstream firewall_virtual_ip.inc (config first, then
// apply): the vip entry is written into virtualip/vip and the dnsvip id into the DNSBL
// settings, write_config fires ONCE iff anything changed, then interface_ipalias_configure()
// brings the alias up live.
//
// Validation contract (PFBL-01): $interface (the stored dnsbl_interface setting; a
// pfSense friendly interface name -- 'lo0', 'lan', 'optN', 'enc0', 'openvpn', 'l2tp',
// per pfb_build_if_list()) must validate via pfb_filter(PFB_FILTER_WORD) before it is
// written into a VIP entry or handed to interface_vip_bring_down() /
// interface_ipalias_configure(). Every legal friendly name is \w-only, so the WORD
// filter passes all of them unchanged and rejects anything carrying separators,
// spaces, quotes or other non-word characters. As a singular required parameter, a
// value failing the filter ABORTS VIP management for the run (log + return, no
// config read or write, no VIP operation). The constant's accept/reject behaviour
// is pinned by tests/php/PfbFilterContractTest.php.
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
	// (Phase 3 makes v6 mandatory in that case; here we simply provision it).
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

	// General variables — registered sections read through the gateway (ADR-29 P4).
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
	$pfb['maxmind_key']	= pfb_filter($pfb['ipconfig']['maxmind_key'], PFB_FILTER_WORD, 'pfb_global')		?: '';		// Maxmind License Key

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
				pfb_logger("\nDNSBL disabled: {$vips_valid_result[1]}", 1);
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
	$pfb['dnsbl_alexa']	= $pfb['dnsblconfig']['alexa_enable'];							// TOP1M whitelist
	$pfb['dnsbl_alexatype']	= PfbConfig::read('alexa_type');							// TOP1M type (Tranco, Alexa or Cisco) (default 'tranco')
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

	// SafeSearch — read via gateway (ADR-29 P4).
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

		if [ "\${filter_type}" == 'clog_pfb' ]; then
			# clog_pfb is the pre-2.5 circular-log reader (below min CE 2.8); it reads
			# only the filter.log clog. The DNSBL feature-log tail is tail_pfb-only.
			/usr/local/sbin/clog_pfb -f /var/log/filter.log | /usr/local/bin/php_pfb -f /usr/local/pkg/pfblockerng/pfblockerng.inc filterlog &
		else
			# ADR-38 Amendment 1: one daemon also tails the DNSBL feature logs so it
			# can write unified.log + emit DNSBL syslog host-side. -q suppresses tail's
			# per-file "==> name <==" headers; -F retries files that don't exist yet.
			/usr/bin/tail_pfb -q -n0 -F /var/log/filter.log /var/log/pfblockerng/dnsbl.log /var/log/pfblockerng/dns_reply.log | /usr/local/bin/php_pfb -f /usr/local/pkg/pfblockerng/pfblockerng.inc filterlog &
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
		/usr/local/sbin/lighttpd_pfb -f /var/unbound/pfb_dnsbl_lighty.conf
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


// Manage log files line limit
function pfb_log_mgmt() {
	global $g, $pfb;
	pfb_global();

	$chroot_folder = '/var/unbound';

	foreach (array(	'log', 'errlog', 'extraslog', 'ip_blocklog', 'ip_permitlog', 'ip_matchlog',
			'dnslog', 'dnsbl_parse_err', 'dnsreplylog', 'unilog') as $logtype) {

		// Max lines in Log file
		$logmax = pfb_filter($pfb['config']['log_max_' . $logtype], PFB_FILTER_NUM, 'pfb_log_mgmt', 20000);

		if ($logmax != 'nolimit' && file_exists($pfb[$logtype])) {
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
					// Truncate in place to preserve the inode (#264): mv replaces the
					// inode, so a remote syslog shipper keyed on (inode, offset) treats
					// it as a rotation and re-sends the whole log. cat over '>' keeps the
					// same inode - the file just shrinks - and so keeps its ownership.
					// Gate on each exit code: unlike the atomic mv, '>' truncates first,
					// so a failed tail/cat must not be allowed to leave an empty/partial log.
					exec("/usr/bin/tail -n " . escapeshellarg($logmax) . " " . escapeshellarg($final_log_file) . " > " . escapeshellarg($temp), $out, $ret);
					if ($ret === 0) {
						exec("/bin/cat " . escapeshellarg($temp) . " > " . escapeshellarg($final_log_file), $out, $ret);
						if ($ret === 0) {
							@chown($final_log_file, 'unbound');
							@chgrp($final_log_file, 'unbound');
						} else {
							pfb_logger("\npfb_log_mgmt: failed to overwrite {$final_log_file} during truncation", 2);
						}
					} else {
						pfb_logger("\npfb_log_mgmt: failed to tail {$final_log_file} for truncation", 2);
					}
				}
			}
			else {
				$temp = tempnam("{$g['tmp_path']}/", 'pfb_log_');
				// Truncate in place to preserve the inode (#264) - see above. Gate on
				// each exit code so a failed tail/cat cannot truncate the live log.
				exec("/usr/bin/tail -n " . escapeshellarg($logmax) . " {$pfb[$logtype]} > " . escapeshellarg($temp), $out, $ret);
				if ($ret === 0) {
					exec("/bin/cat " . escapeshellarg($temp) . " > {$pfb[$logtype]}", $out, $ret);
					if ($ret !== 0) {
						pfb_logger("\npfb_log_mgmt: failed to overwrite {$pfb[$logtype]} during truncation", 2);
					}
				} else {
					pfb_logger("\npfb_log_mgmt: failed to tail {$pfb[$logtype]} for truncation", 2);
				}
			}
			unlink_if_exists($temp);
		}
	}
}


// ---------------------------------------------------------------------------
// ADR-30 — Scheduled (calendar-boundary) per-log reset helpers + action.
// ---------------------------------------------------------------------------

/**
 * Parse the contents of the log_rotate.last marker file into a map of
 * log type -> last-reset period key.
 *
 * Format: one entry per line, "<type>=<period-key>"; blank lines and lines
 * that do not match the expected format are silently ignored (garbled entry
 * => '' for that type, i.e. treated as "never reset").
 *
 * PURE — no I/O, no globals, no side effects.
 *
 * @param string $contents  Raw contents of the marker file ('' when absent).
 * @return array<string,string>  Map of type => period-key (may be empty).
 */
function pfb_log_rotate_marker_parse(string $contents): array
{
	$entries = [];
	foreach (explode("\n", $contents) as $line) {
		$line = trim($line);
		if ($line === '') {
			continue;
		}
		$eq = strpos($line, '=');
		if ($eq === FALSE || $eq === 0) {
			// Garbled line — skip; the caller treats missing => '' => reset.
			continue;
		}
		$type = substr($line, 0, $eq);
		$key  = substr($line, $eq + 1);
		// Only accept entries whose type looks like a valid log identifier:
		// alphanumeric + underscore, non-empty. Anything else is garbled.
		if (!preg_match('/^[a-z_][a-z0-9_]*$/', $type)) {
			continue;
		}
		$entries[$type] = $key;
	}
	return $entries;
}

/**
 * Serialize a log-type -> period-key map back into marker-file contents.
 *
 * Each entry is emitted as "<type>=<period-key>\n"; entries are sorted by
 * type name for stable, human-readable output. The result always ends with
 * a newline (or is '' when the map is empty).
 *
 * PURE — no I/O, no globals, no side effects.
 *
 * @param array<string,string> $entries  Map of type => period-key.
 * @return string                         Serialized contents for the marker file.
 */
function pfb_log_rotate_marker_serialize(array $entries): string
{
	if (empty($entries)) {
		return '';
	}
	ksort($entries);
	$lines = '';
	foreach ($entries as $type => $key) {
		$lines .= "{$type}={$key}\n";
	}
	return $lines;
}

/**
 * Reset each pfBlockerNG log that has a configured calendar schedule and
 * whose period has rolled over since it was last reset.
 *
 * Iterates the same 10 log types that pfb_log_mgmt() manages. For each:
 *   - Reads its log_rotate_<type> schedule via PfbConfig (RequireConfigGateway).
 *   - Looks up its last-reset period key from the per-log marker file.
 *   - Calls pfb_log_should_reset() to decide (pure, no I/O).
 *   - On a rolled boundary: truncates that log to empty IN PLACE (inode +
 *     ownership preserved — same chroot/chown handling as pfb_log_mgmt()),
 *     then updates that log's marker entry.
 * Persists the marker file once after the loop.
 *
 * Called once per cron tick, immediately after pfb_log_mgmt().
 * NOT called on the settings-save path.
 *
 * Contract (ADR-30 §2.2):
 *   - 'off'/'' schedule => that log is never touched.
 *   - Idempotent: a second tick in the same period is a no-op (marker unchanged).
 *   - Per-log independent: one log's reset never affects another.
 *   - Inode + unbound ownership preserved for chrooted python logs (#264/#280).
 */
function pfb_log_reset(): void
{
	global $g, $pfb;
	pfb_global();

	$chroot_folder = '/var/unbound';
	$marker_path   = "{$pfb['dbdir']}/log_rotate.last";

	// Load the marker file once. A missing or unreadable file is treated as
	// 'never reset' for every log (the read returns '' -> parse returns []).
	$marker_contents = @file_get_contents($marker_path) ?: '';
	$entries         = pfb_log_rotate_marker_parse($marker_contents);

	$changed = FALSE;

	foreach (array('log', 'errlog', 'extraslog', 'ip_blocklog', 'ip_permitlog', 'ip_matchlog',
			'dnslog', 'dnsbl_parse_err', 'dnsreplylog', 'unilog') as $logtype) {

		// Read this log's schedule from the config gateway (ADR-29).
		$schedule = PfbConfig::read('log_rotate_' . $logtype);

		// Missing entry => '' => pfb_log_should_reset treats as "never reset".
		$last_key = $entries[$logtype] ?? '';

		if (!pfb_log_should_reset($schedule, $last_key, time())) {
			continue;
		}

		// Period has rolled over (or this log has never been reset).
		// ADR-30 amendment (#416): keep the last $keep lines when $keep > 0 (inode-
		// preserving, mirroring pfb_log_mgmt()); clear fully when $keep <= 0 (default).
		$keep = (int) PfbConfig::read('log_reset_keep_' . $logtype);

		if ($logtype === 'dnslog' || $logtype === 'dnsreplylog' || $logtype === 'unilog') {

			// DNS python logs: resolve through the Unbound chroot.
			if (is_dir("{$chroot_folder}/var/log/pfblockerng")) {
				$final_log_file = "{$chroot_folder}{$pfb[$logtype]}";
				$temp           = tempnam("{$chroot_folder}/var/log/pfblockerng", 'pfb_log_');
			} else {
				$final_log_file = $pfb[$logtype];
				$temp           = tempnam("{$g['tmp_path']}/", 'pfb_log_');
			}

			if (file_exists($final_log_file)) {
				if ($keep > 0) {
					// Keep last $keep lines inode-preservingly (ADR-30 amendment / #416).
					// Gate on each exec exit code: a failed tail/cat must NOT blank the log.
					exec("/usr/bin/tail -n " . escapeshellarg((string) $keep) . " " . escapeshellarg($final_log_file) . " > " . escapeshellarg($temp), $out, $ret);
					if ($ret === 0) {
						exec("/bin/cat " . escapeshellarg($temp) . " > " . escapeshellarg($final_log_file), $out, $ret);
						if ($ret === 0) {
							// Re-apply unbound ownership after the in-place keep (same as pfb_log_mgmt).
							@chown($final_log_file, 'unbound');
							@chgrp($final_log_file, 'unbound');
						} else {
							pfb_logger("\npfb_log_reset: failed to overwrite {$final_log_file} during keep", 2);
							unlink_if_exists($temp);
							continue;
						}
					} else {
						pfb_logger("\npfb_log_reset: failed to tail {$final_log_file} for keep", 2);
						unlink_if_exists($temp);
						continue;
					}
					unlink_if_exists($temp);
				} else {
					// Clear fully (default: $keep == 0).
					exec("/bin/cp /dev/null " . escapeshellarg($final_log_file), $out, $ret);
					if ($ret === 0) {
						// Re-apply unbound ownership after truncation (same as pfb_log_mgmt).
						@chown($final_log_file, 'unbound');
						@chgrp($final_log_file, 'unbound');
					} else {
						pfb_logger("\npfb_log_reset: failed to truncate {$final_log_file}", 2);
						unlink_if_exists($temp);
						continue;
					}
					unlink_if_exists($temp);
				}
			} else {
				unlink_if_exists($temp);
			}
		} else {
			if (file_exists($pfb[$logtype])) {
				if ($keep > 0) {
					// Keep last $keep lines inode-preservingly (ADR-30 amendment / #416).
					// Gate on each exec exit code: a failed tail/cat must NOT blank the log.
					$temp = tempnam("{$g['tmp_path']}/", 'pfb_log_');
					exec("/usr/bin/tail -n " . escapeshellarg((string) $keep) . " " . escapeshellarg($pfb[$logtype]) . " > " . escapeshellarg($temp), $out, $ret);
					if ($ret === 0) {
						exec("/bin/cat " . escapeshellarg($temp) . " > " . escapeshellarg($pfb[$logtype]), $out, $ret);
						if ($ret !== 0) {
							pfb_logger("\npfb_log_reset: failed to overwrite {$pfb[$logtype]} during keep", 2);
							unlink_if_exists($temp);
							continue;
						}
					} else {
						pfb_logger("\npfb_log_reset: failed to tail {$pfb[$logtype]} for keep", 2);
						unlink_if_exists($temp);
						continue;
					}
					unlink_if_exists($temp);
				} else {
					// Clear fully (default: $keep == 0).
					exec("/bin/cp /dev/null " . escapeshellarg($pfb[$logtype]), $out, $ret);
					if ($ret !== 0) {
						pfb_logger("\npfb_log_reset: failed to truncate {$pfb[$logtype]}", 2);
						continue;
					}
				}
			}
		}

		// Record the new period key for this log (same for both keep and clear paths).
		$entries[$logtype] = pfb_log_rotate_period($schedule, time());
		$changed           = TRUE;
	}

	// Persist the marker file once, only when something was reset.
	if ($changed) {
		@file_put_contents($marker_path, pfb_log_rotate_marker_serialize($entries), LOCK_EX);
	}
}


// Record log messsages to pfBlockerNG log file and/or error log file.
function pfb_logger($log, $logtype) {
	global $g, $pfb;

	$now = date('m/j/y H:i:s', time());

	// Only log timestamp if new
	if (strpos($log, 'NOW') !== FALSE) {
		$elog = str_replace('NOW', $now, "{$log}");	// Always report timestamp to errorlog
		if ($now == ($pfb['pnow'] ?? '')) {
			$log = str_replace(' [ NOW ]', '', "{$log}");
		} else {
			$log = str_replace('NOW', $now, "{$log}");
		}
		$pfb['pnow'] = "{$now}";
	}
	else {
		$elog = "{$log} [ {$now} ]";
	} 

	switch ($logtype) {

		// Print to pfBlockerNG log
		case 1:
			@file_put_contents("{$pfb['log']}", "{$log}", FILE_APPEND);
			break;

		// Print to pfBlockerNG log and Error log
		case 2:
			@file_put_contents("{$pfb['log']}", "{$log}", FILE_APPEND);
			@file_put_contents("{$pfb['errlog']}", "{$elog}", FILE_APPEND);
			break;

		// Print to Extras log
		case 3:
			@file_put_contents("{$pfb['extraslog']}", "{$log}", FILE_APPEND);
			break;

		// Print to screen and Extras log
		case 4:
			if (!$g['pfblockerng_install'] && !$pfb['extras_update']) {
				print "{$log}";
			}
			@file_put_contents("{$pfb['extraslog']}", "{$log}", FILE_APPEND);
			break;

		// Print to debugger
		case 5:
			@file_put_contents("/tmp/pfb_debug", "{$now} | {$elog}", FILE_APPEND);
			break;

		// Print to Error log
		case 6:
			@file_put_contents("{$pfb['errlog']}", "{$elog}", FILE_APPEND);
			break;
		default:
			break;
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
// file, never a GUI-entered command). Shared with the per-feed list pre/post
// scripts; hook scripts are named hook_pre_*/hook_post_* (.sh/.py).
if (!defined('PFB_HOOK_SCRIPT_DIR')) {
	define('PFB_HOOK_SCRIPT_DIR', '/usr/local/pkg/pfblockerng/list_scripts');
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
 * ADR-19 Phase 3 — pkg IO wrapper + cron-driven update check (consumes the pure core).
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
 * OUR repo's latest version of $pkgname: `pkg update -r <repo>` (best-effort refresh of
 * just our catalog DB) then `pkg rquery -r <repo> '%v' <pkgname>`. Reads ONLY our repo
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
	// Best-effort catalog refresh of our repo only; ignore failures (stale DB still reads).
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
 * ADR-19 Phase 4 — provenance gate for the shipped GUI surfaces.
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
 * Append the "Software" tab to a page's $tab_array — ONLY on an our-repo build
 * (pfb_software_provenance_ok()). Shared by every pfBlockerNG page so the tab is
 * consistently present (our build) or absent (Netgate build) across the GUI.
 * Call immediately before display_top_tabs(); $active marks it the current tab.
 */
function pfb_software_add_tab(array &$tab_array, bool $active = FALSE): void {
	if (pfb_software_provenance_ok()) {
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
		// shebang + execute bit (the list_scripts convention); 2>&1 folds stderr
		// into the captured stdout for the log.
		$cmd = "{$envprefix} /usr/bin/timeout -s TERM -k " . PFB_HOOK_KILL_GRACE .
			" {$timeout} " . escapeshellarg($path) . " 2>&1";

		$output = array();
		$retval = 0;
		exec($cmd, $output, $retval);

		if (!empty($output)) {
			pfb_logger(implode("\n", $output) . "\n", 1);
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


// Record failed IP/DNSBL Feed parse errors
function pfb_parsed_fail($header, $line='', $oline, $logfile) {

	$line   = $line ?: 'null';
	$now	= date('m/j/y H:i:s', time());

	$log	= "{$now},{$header},{$line},{$oline}";
	@file_put_contents("{$logfile}", "{$log}", FILE_APPEND);
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


// ADR-11: Return the EFFECTIVE member-file list for one aggregate action type and
// family -- the input the Phase-3 caller hands to `pfblockerng.sh aggregate` to union
// into pfB_<Type>_Aggregated_<fam>. Pure: it reads the per-type dir off disk and
// returns the matching family member files; it has NO side effects and is NOT yet
// called from the update pass (Phase 2 is behaviour-preserving).
//
// Type -> dir map (mirrors pfb_determine_list_detail's action -> folder routing):
//   'Deny'   -> denydir    'Permit' -> permitdir
//   'Match'  -> matchdir   'Native' -> nativedir
//
// EFFECTIVE / post-suppression -- the key Phase-4 fact:
//   The denydir '<header>_<fam>.txt' member files are ALREADY the effective
//   (post-suppression / post-whitelist) block set on disk. During the update pass
//   the shell 'suppress' action (pfblockerng.sh suppress, grepcidr -vf
//   pfbsuppression.txt) rewrites each Deny member file IN PLACE (pfblockerng.inc
//   ~:10829-10834) BEFORE it is read into the alias (~:10836) -- and
//   pfb_create_suppression_file() folds the user whitelist, local/DNS IPs and
//   Permit-customlist IPs into pfbsuppression.txt. So reading denydir/*_<fam>.txt
//   yields the effective set directly; the helper applies NO further suppression.
//   (Phase 3 must therefore run the aggregate AFTER the per-member suppress step.)
//
// DNSBLIP + GeoIP fold in for FREE -- no special-casing here:
//   DNSBLIP_<fam>.txt is deposited into the dir of its configured action
//   ($pfb['dnsbl_ip'], e.g. Deny -> denydir) during the build loop, and each
//   Deny-action GeoIP continent likewise lands in denydir by its action
//   (pfblockerng.inc ~:9926, the §1.5 "GeoIP folds by action" fact). Both are plain
//   '<header>_<fam>.txt' members in the type's dir, so this glob already includes
//   them; a continent set to Permit/Match lands in that type's dir instead, never
//   double-listed.
//
// $type   : 'Deny' | 'Permit' | 'Match' | 'Native'   (the GUI action-group labels)
// $family : 'v4' | 'v6'
// Returns : array of absolute member-file paths (possibly empty); [] for an unknown
//           type/family so the caller can treat it as "nothing to aggregate".
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


// ADR-11 Phase 3: build + register the opt-in per-type aggregate ("Uber") Native aliases.
//
// ONE generic loop over the type->dir map {Deny,Permit,Match,Native} x family {v4,v6}.
// For each SELECTED type ($pfb['agg_types'], CSV scalar, default none):
//   pfb_aggregate_member_list($type,$family) -> write a memberlist file -> run
//   `pfblockerng.sh aggregate <family> <memberlist> <aggout> <consumerout>` (cat|sort -u|
//   iprange, mtime-gated inside the action) -> register pfB_<Type>_Aggregated_<fam> as a
//   standard pfB `urltable` alias (mirrors the member-alias registration shape) -> load the
//   table via `pfctl -T replace -f`. NEVER pfb_firewall_rule -- "Native" is the registration
//   mode (no rule), regardless of which action class is being aggregated. When an aggregate
//   is actually (re)built this pass (aggout mtime advanced), its name is merged into
//   $pfb['changed_ip_aliases'] (emitted to the ADR-12 post-hook as PFB_CHANGED_IP_ALIASES)
//   and into $pfb_alias_lists, so a recipe can gate its reload on the aggregate changing.
//
// A NON-selected type (or pfBlockerNG disabled) is torn down: its aggregate file, consumer
// file and pf table are removed cleanly, and -- by NOT appending its name to
// $new_aliases_list -- the caller's existing pfB orphan-prune also unlinks its alias .txt.
//
// Additive guarantee: nothing selected => the loop registers/builds nothing and tears down
// nothing that exists (the aliases were never created), so the pass is byte-identical.
//
// $new_aliases, $new_aliases_list, $pfb_alias_lists are taken by reference (the caller's
// alias-registration arrays); the aggregate alias entries are appended like any other pfB
// alias so the normal config write + reconcile path carries them.
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
			$aliasname_esc	= escapeshellarg($aliasname);

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
					exec("{$pfb['pfctl']} -t {$aliasname_esc} -T kill 2>&1");
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
			exec("{$pfb['script']} aggregate {$family_esc} {$memberlist_esc} {$aggout_esc} {$consumer_esc} 2>&1");

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
				exec("{$pfb['pfctl']} -t {$aliasname_esc} -T replace -f {$aggout_esc} 2>&1");
			} else {
				exec("{$pfb['pfctl']} -t {$aliasname_esc} -T kill 2>&1");
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
// ADR-40 Phase 1 — alias reload-scope helpers (extracted from sync_package_pfblockerng)
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
 * Phase 3 will replace callers with pfb_canonical_alias_set() once content-addressed
 * gating is wired in. Until then this is the oracle for the current behaviour.
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
 * Used as the content-addressed gate input (ADR-40 P3) and the delta last_set source (P4).
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
 * through pfb_canonical_alias_set() before comparing, so a pre-Phase-3
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

// ---------------------------------------------------------------------------
// ADR-40 Phase 4 — forward-delta alias-table apply
// ---------------------------------------------------------------------------

/** Churn-ratio threshold above which 'auto' mode falls back to -T replace (20%). */
const PFB_DELTA_CHURN_THRESHOLD = 0.20;

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
 *   (5) Empty-table: full replace handles initial population (mirrors Phase-3 gate).
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
	$table_esc      = escapeshellarg($table);
	$table_file_esc = escapeshellarg($table_file);
	$batch_size     = pfb_alias_delta_batch_clamp($batch_size);

	// Force replace: boot/enable-disable initial load path.
	if ($force_replace || $mode === 'replace') {
		exec("{$pfctl_bin} -t {$table_esc} -T replace -f {$table_file_esc} 2>&1");
		return FALSE;
	}

	// Compute add/del sets (LC_ALL=C byte-order; arrays are already canonical).
	$add_set = array_values(array_diff($desired_set, $last_set));
	$del_set = array_values(array_diff($last_set, $desired_set));

	$churn      = count($add_set) + count($del_set);
	$table_size = max(count($desired_set), count($last_set));

	// Churn-ratio fallback: auto mode with large churn → replace.
	if ($mode === 'auto' && $table_size > 0 && ($churn / $table_size) >= PFB_DELTA_CHURN_THRESHOLD) {
		exec("{$pfctl_bin} -t {$table_esc} -T replace -f {$table_file_esc} 2>&1");
		return FALSE;
	}

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
		exec("{$pfctl_bin} -t {$table_esc} -T add -f {$tmp_esc} 2>&1");
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
		exec("{$pfctl_bin} -t {$table_esc} -T delete -f {$tmp_esc} 2>&1");
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


// Create suppression file from suppression list
function pfb_create_suppression_file() {
	global $pfb;

	$v4suppression = pfbng_text_area_decode($pfb['ipconfig']['v4suppression'], FALSE, TRUE);
	if (!empty($v4suppression)) {
		@file_put_contents("{$pfb['supptxt']}", $v4suppression, LOCK_EX);
	} else {
		unlink_if_exists("{$pfb['supptxt']}");
	}
}


// Function to update DNSBL aliases and widget stats
function dnsbl_alias_update($mode, $alias, $pfbfolder, $lists_dnsbl_current, $alias_cnt) {
	global $pfb;

	if ($mode == 'update') {

		// Create master alias file
		if ($lists_dnsbl_current != '') {
			$pfb_output = @fopen("{$pfb['dnsalias']}/{$alias}", 'w');
			foreach ($lists_dnsbl_current as $clist) {
				if (($handle = @fopen("{$pfbfolder}/{$clist}.txt", 'r')) !== FALSE) {
					while (($line = @fgets($handle)) !== FALSE) {
						@fwrite($pfb_output, $line);
					}
				}
				@fclose($handle);
			}
			@fclose($pfb_output);
		}

		// Update DNSBL alias statistics
		$dns_now = date('M j H:i:s', time());
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
			$dns_now = date('M j H:i:s', time());
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
	pfb_logger(" completed [ NOW ]", 1);
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


// Resolve a SafeSearch CNAME target (e.g. safe.duckduckgo.com) to its current
// A/AAAA via the configured external DNS server. These are the #2 baked-fallback
// IPs written into the SafeSearch CSV (issue #149): pfb_unbound.py uses them only
// when the live CNAME chase yields no address, and the SafeSearch freshness cron
// re-runs this every 15 minutes to keep them current. Returns array($v4, $v6),
// each '' when unresolved.
//
// Validation contract (PFBL-01): $target is built into an exec() command line
// (escapeshellarg() supplies the quoting; $pfb['extdns'] is already
// PFB_FILTER_IPV4-validated in pfb_global). The contract for this boundary is
// that $target must ALSO validate as a domain via pfb_filter(PFB_FILTER_DOMAIN)
// before any command is composed -- semantic validation and shell quoting are
// two distinct layers (the pattern pfb_unbound_py_ccache_flush_cmds() already
// follows). A value failing the filter is rejected: logged and returned as
// array('', '') with no command run -- the same shape as the empty-target
// guard, so pfb_ss_refresh_lines() keeps the prior baked IPs for a rejected
// target exactly as it does for a failed resolution. The constant's
// accept/reject behaviour is pinned by tests/php/PfbFilterContractTest.php.
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

	$out4 = array();
	exec("/usr/bin/drill A {$target_esc} {$extdns_esc} | /usr/bin/awk '/[ \\t]IN[ \\t]+A[ \\t]/ {print \$5; exit}'", $out4);
	$v4 = filter_var(trim($out4[0] ?? ''), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ?: '';

	$out6 = array();
	exec("/usr/bin/drill AAAA {$target_esc} {$extdns_esc} | /usr/bin/awk '/[ \\t]IN[ \\t]+AAAA[ \\t]/ {print \$5; exit}'", $out6);
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

				// Minimize the python whitelist queries to the smallest tld segment count
				if (!isset($tld_segments)) {
					$tld_segments = (substr_count($line, '.') +1);
				}
				$tld_segments = @min((array((substr_count($line, '.') +1), $tld_segments) ?: 1));

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


// ADR-06: Collect the user DNSBL whitelist as a normalised list of source lines
// for the Python build manifest (config.user_whitelist). The Python build performs
// the www-strip / leading-dot->wildcard normalisation itself (pfb_unbound.py
// _dnsbl_normalise_whitelist), so this hands the RAW suppression lines through.
//
// Validation contract (PFBL-01): the suppression textarea is free-form user input
// and pfbng_text_area_decode() only normalises encoding (no domain validation), yet
// each line lands in the manifest (config.user_whitelist) and from there in the
// query-time whiteDB. Each line must validate via pfb_filter(PFB_FILTER_DOMAIN)
// before it is returned -- the filter accepts the leading-dot wildcard form
// ('.example.com') as well as plain domains. A line failing the filter is
// SKIPPED + logged (list iteration), never silently dropped.
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

// ADR-06 (#51): collect the TEMPORARY per-alert DNSBL unlock store
// ($pfb['dnsbl_unlock'], a CSV of "domain,type" rows toggled by the alerts
// Lock/Unlock icon) as a normalised list of domains for the Python build manifest
// (config.user_unlock). The Python build merges these into whiteDB as band-6 user
// allows (same shape as config.user_whitelist) so an unlocked domain resolves. This
// store is deliberately temporary: it lives in /tmp and a full update / Force / Cron
// deletes it (pfb_update_unbound), so a FULL build emits an EMPTY user_unlock and the
// rebuilt manifest re-locks every unlock (the "re-locked on Cron/Force" behaviour
// documented in the alerts icon tooltip). Only pfb_unbound_python_sources_unlock()
// (the incremental alerts path) feeds the live store into the manifest.
//
// Validation contract (PFBL-01): the alerts handler filters the POSTed domain with
// pfb_filter(PFB_FILTER_DOMAIN) before it enters the store, but the store itself is
// a plain file under /tmp re-read here later -- so this reader is a boundary of its
// own and must not trust the file contents (same posture as
// pfb_unbound_py_ccache_flush_cmds() towards its callers). Each domain read from
// the store re-validates via pfb_filter(PFB_FILTER_DOMAIN) before it is placed
// into the manifest (config.user_unlock); a row failing the filter is SKIPPED
// + logged.
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

// ADR-07 P8: extract an IP from an ABP-anchored / hosts line for the DNSBL-IP
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


// ADR-22: the non-lite scheme strip, gated on the 'pfb_dnsbl_lenient' toggle.
//
// No '://' present  -> return the line unchanged (no scheme to strip).
//
// $strict === FALSE (lenient -- today's behaviour, byte-identical): strip everything up to
// and including the FIRST '://' and return the remainder (paths/query/port handled
// downstream). strpos() finds the first '://' anywhere, so the permissive cases
// ('123://evil.com', '://evil.com', mid-token schemes) are accepted exactly as before. The
// $strict parameter DEFAULTS to FALSE so callers (and the Phase-1 oracle tests) that pass no
// second argument observe this unchanged behaviour.
//
// $strict === TRUE (lenient OFF): validate the text before '://' against the RFC 3986 scheme
// grammar (ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )); an invalid scheme returns FALSE.
// A single trailing '/' (root path) is normalised away; any remaining '/' is an actual path
// and returns FALSE. A FALSE return tells the caller to skip + log the line (ADR §2.3/§2.4).
function pfb_dnsbl_strip_scheme(string $line, bool $strict = FALSE): string|false {
	$pos = strpos($line, '://');
	if ($pos === FALSE) {
		return $line;
	}
	if ($strict) {
		$scheme = substr($line, 0, $pos);
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


// ADR-22: per-line scheme parse for the non-lite download path. Returns the parsed host
// string to keep, or FALSE when strict parsing rejected the line (invalid scheme or a URL
// path). On rejection it records the line in the DNSBL parse-error log (the established
// per-line sink) and increments the per-feed skip counter so the caller can emit one summary
// WARNING (pfb_dnsbl_scheme_skip_warn) after the feed. In lenient mode it never rejects, so
// the counter is untouched and no parse-error line is written -- byte-identical to today.
function pfb_dnsbl_scheme_line(string $line, bool $strict, $header, $oline, $logfile, &$skipped): string|false {
	$stripped = pfb_dnsbl_strip_scheme($line, $strict);
	if ($stripped === FALSE) {
		pfb_parsed_fail($header, $line, $oline, $logfile);
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


// ADR-21: whole-feed ABP header sniff. A line in a feed's leading '!'-comment block
// that starts (leading whitespace tolerated) with '[Adblock', '[uBlock', or '! Title:'
// flags the feed as whole-feed ABP ($easylist = TRUE). The three generic prefixes are a
// SUPERSET of the four legacy magic strings ('[Adblock Plus '/'[Adblock Plus]' -> '[Adblock';
// '[uBlock Origin' -> '[uBlock'; '! Title: AdGuard' -> '! Title:'), so every feed detected
// before is still detected. PREFIX match (str_starts_with), NOT the legacy mid-line strpos:
// a '! Title:' token inside a data line cannot flip the feed. Safe because parse_abp() is a
// superset parser that still blocks the feed's bare-domain entries (ADR §1.4 / §2.4).
function pfb_dnsbl_is_abp_header($line) {
	$hline = ltrim($line);
	// A UTF-8 BOM on the feed's first line sits before the prefix; ltrim()
	// does not strip it, so peel it off (the legacy mid-line strpos() matched
	// regardless of a BOM -- without this a BOM-led header would regress).
	if (str_starts_with($hline, "\xEF\xBB\xBF")) {
		$hline = ltrim(substr($hline, 3));
	}
	return (str_starts_with($hline, '[Adblock') ||
		str_starts_with($hline, '[uBlock') ||
		str_starts_with($hline, '! Title:'));
}


// ADR-10 P5: atomically publish a file to the chroot (/var/unbound). Stage into a
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


// ADR-10 P5: flip the zero-downtime RELOAD SENTINEL (the all-or-nothing commit that
// wakes the Python reload-watcher). The sentinel host path is /var/unbound/pfb_py_reload
// (Unbound is chrooted at /var/unbound; the module opens it as the chroot-relative
// "pfb_py_reload" -- RESULTS/04 SS1). Its content is a monotonically NON-DECREASING
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


// ADR-10: wait (bounded) for the reload-watcher to APPLY a published generation.
// After flipping the sentinel to $gen, PHP blocks here until the watcher writes a value
// >= $gen to the applied marker (/var/unbound/pfb_py_reload.applied), so the data fast
// path returns only once the new lists are LIVE -- restoring the "lists live on return"
// invariant the restart had (the ADR-12 post hook + the #51 alert page then observe the
// new state, not a pending swap). Queries NEVER stop: the old snapshot keeps serving
// during the wait, so this stays zero-downtime/zero-dropped. Returns TRUE once applied;
// FALSE on timeout -- the caller then falls back to the restart so the lists still load
// (fail-safe). The watcher's poll cadence (RELOAD_POLL_INTERVAL ~2s) + the rebuild time
// bound the latency; the default budget covers a large ABP rebuild.
function pfb_unbound_py_wait_applied($gen, $timeout_s = 30) {
	global $pfb;

	$gen = (int) $gen;
	$applied = "{$pfb['dnsbldir']}/pfb_py_reload.applied";
	$deadline = microtime(TRUE) + (float) $timeout_s;

	do {
		if (file_exists($applied)) {
			$raw = @file_get_contents($applied);
			if ($raw !== FALSE) {
				$first = strtok($raw, "\n");
				if ($first !== FALSE) {
					$first = trim($first);
					if ($first !== '' && ctype_digit($first) && (int) $first >= $gen) {
						return TRUE;
					}
				}
			}
		}
		usleep(200000);	// 200 ms between polls
	} while (microtime(TRUE) < $deadline);

	return FALSE;
}


// Poll until the control-channel watcher has applied sequence $seq (or beyond), confirming
// the published command was consumed. Mirrors pfb_unbound_py_wait_applied() in structure:
// reads the applied marker (/var/unbound/pfb_py_control.applied), parses the first line as
// an integer, and returns TRUE when the stored value >= $seq. Returns FALSE on timeout.
// A $timeout_s <= 0 is never passed here (the caller guards); 200 ms poll interval.
function pfb_unbound_py_wait_control_applied($seq, $timeout_s = 5) {
	global $pfb;

	$seq     = (int) $seq;
	$applied  = "{$pfb['dnsbldir']}/pfb_py_control.applied";
	$deadline = microtime(TRUE) + (float) $timeout_s;

	do {
		if (file_exists($applied)) {
			$raw = @file_get_contents($applied);
			if ($raw !== FALSE) {
				$first = strtok($raw, "\n");
				if ($first !== FALSE) {
					$first = trim($first);
					if ($first !== '' && ctype_digit($first) && (int) $first >= $seq) {
						return TRUE;
					}
				}
			}
		}
		usleep(200000);	// 200 ms between polls
	} while (microtime(TRUE) < $deadline);

	return FALSE;
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


// PFBL-03: root-only DNSBL-control writer. Validates the command + its argument (the
// SEMANTIC layer -- a bypass IP through pfb_filter(PFB_FILTER_IP), a duration through
// pfb_filter(PFB_FILTER_NUM) clamped to 1-3600), assembles a small JSON record carrying a
// monotonically-advancing SEQUENCE, and atomically publishes it to the local privileged
// command channel with the root:unbound 0640 permission model (pfb_unbound_py_atomic_write_root).
// The control-watcher in pfb_unbound.py consumes a record only when its seq advances
// (exactly-once + replay safety) and re-validates every argument again before any side
// effect, so this writer and the reader form a dual-validation boundary.
//
//   $cmd      one of disable|enable|addbypass|removebypass
//   $ip       required for addbypass/removebypass (a v4/v6 literal); ignored otherwise
//   $duration optional seconds (1-3600) for disable/addbypass; ignored otherwise
//
// Returns the published sequence (>= 1) on success, or FALSE on an invalid command /
// invalid argument / lock failure / write failure. No die()/exit().
// $wait_timeout: seconds to wait for the watcher to apply the command (default 5).
//   <= 0 = fire-and-forget (skip the wait entirely, return the seq immediately).
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


// ADR-10 P5: PRIMARY RAM gate for the zero-downtime swap (the Python watcher re-checks
// it as a safety net -- RESULTS/04 SS3). The background rebuild holds the OLD and NEW
// matcher structures resident at once (~2x transient); on a constrained box that bust
// would OOM mid-swap (RESULTS/01 SS2: 785.9 MiB both-resident at ABP scale busts a 1 GB
// box). Mirror the Python projection: 2 * loaded_entries * 276 B + a 64 MiB headroom,
// measured against hw.usermem (physical RAM the OS can hand out). Returns TRUE when the
// projected build FITS (zero-downtime allowed); FALSE -> the caller must take the restart
// fallback so the new lists actually load. Unknown RAM / unknown count -> FALSE
// (fail-closed: when in doubt, restart -- which never doubles, it frees the old set by
// dying before rebuilding).
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


// ADR-31 P3: Build a single per-feed manifest row for $pfb_py_feeds[]. Extracted
// from the DNSBL download loop so the DNSWL section (Phase 4) can reuse the same
// structure parameterised by $mode.
//
// $mode = 'deny'   → omit the 'mode' key (byte-identical with pre-ADR-31 deny entries;
//                    Python treats absent as deny — Phase 2 contract).
// $mode = 'permit' → add 'mode' => 'permit' to the row (Phase 4 DNSWL feeds).
//
// No file I/O, no exec, no validation side-effects — pure array construction; the
// producing loops have already validated $header (PFB_FILTER_WORD) and resolved
// $format/$provenance before calling here.
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


// ADR-06: Build the shell->Python contract. Writes the per-feed manifest
// ($pfb['unbound_py_sources']) plus a per-feed IP-stripped raw file (one bare,
// lower-cased domain per line) referenced by the manifest. The Python plugin's
// init (pfb_unbound.py dnsbl_build_from_manifest) consumes this to build the
// DNSBL structures from raw -- replacing the previous data/zone CSV load.
//
// For 'plain' feeds the per-feed raw is the bare-domain extraction of the already-
// parsed per-feed '.txt' (col1 of the 6-col CSV produced by the download loop). The
// download loop already routes embedded IPs to the firewall '*_v4.ip' path and
// excludes them from '.txt', so the raw handed to Python carries NO bare-IP lines
// (ADR-06 §3b; Python would ignore stray IPs anyway). PHP has already done all
// per-format extraction (hosts/CSV/IDN), so Python only revalidates + lower-cases
// the bare domains -- decision-equivalent.
//
// ADR-07 P8: ABP/EasyList feeds are tagged format_hint='abp' (via the row 'format'
// key, set from $easylist in the download loop). Their '.txt' holds RAW ABP lines
// (the PHP lite parser is deleted) which are copied to the per-feed raw VERBATIM, so
// the full DNS-only ABP parser in Python (parse_abp: @@/regex/$important/$badfilter)
// sees them intact. Non-ABP feeds stay 'plain' exactly as ADR-06 left them.
//
// $feeds: array of rows [ 'header' => <feed>, 'group' => <alias>, 'log' => <flag>,
//         'format' => 'abp'|'plain', 'provenance' => 'user'|'feed' ]. ADR-07: a
//         Custom_List ({alias}_custom) row is 'user' -> the Python build bands it as a
//         sovereign user block (5); a downloaded feed is 'feed' -> band 1.
//
// Validation contract (PFBL-01): each row's 'header' names the per-feed source
// '.txt' and staged '.raw' files and becomes the manifest 'feed'/'raw' keys. The
// producing loops already validate headers with pfb_filter(PFB_FILTER_WORD) (e.g.
// 'DNSBL - Processes'), but this writer is the choke point for every path derived
// from a header and RE-validates each one via pfb_sanitise_feed_header() before
// use -- it must not trust its callers (the posture
// pfb_unbound_py_ccache_flush_cmds() documents). Note PFB_FILTER_WORD is the
// correct constant here, NOT PFB_FILTER_DOMAIN: headers are \w-only list labels
// (no dots), so the DOMAIN filter would reject every legal header. A row whose
// header fails the filter is SKIPPED + logged, before any file is touched. The
// constant's accept/reject behaviour is pinned by
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
		// ADR-07 P8: 'abp' feeds carry RAW ABP lines verbatim to the Python parser;
		// every other feed stays 'plain' (PHP-extracted bare domains, ADR-06).
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
				if ($format === 'abp') {
					// ADR-07 P8: pass the RAW ABP line through unmodified -- the
					// '.txt' of an 'abp' feed already holds raw ABP lines (the
					// lite parser is gone). Python's parse_abp does all parsing.
					$line = rtrim($line, "\r\n");
					if ($line !== '') {
						@fwrite($raw_h, "{$line}\n");
					}
					continue;
				}
				// ADR-21: ABP-anchored verbatim line from a non-ABP feed (the
				// download loop wrote '||'/'@@||' lines through untouched, NOT as
				// 6-col CSV) -- pass it straight to the '.raw' without CSV
				// extraction. Python's build() routes it to parse_abp().
				$rawline = rtrim($line, "\r\n");
				if (str_starts_with($rawline, '||') || str_starts_with($rawline, '@@||')) {
					@fwrite($raw_h, "{$rawline}\n");
					continue;
				}
				// 'plain': extract bare domains (col1) from the 6-col CSV; this is
				// already IP-free (IPs went to the firewall path) and already
				// cleaned/validated by the download loop.
				$cols = explode(',', $line, 3);
				if (isset($cols[1]) && $cols[1] !== '') {
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

	// TOP1M (Alexa/Tranco) popularity whitelist -> query-time whiteDB only when on.
	$top1m_enabled	= ($pfb['dnsbl_alexa'] == 'on' &&
			   file_exists("{$pfb['dbdir']}/pfbalexawhitelist.txt"));
	$top1m_list	= array();
	if ($top1m_enabled) {
		$alexa = @file("{$pfb['dbdir']}/pfbalexawhitelist.txt", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
		if (is_array($alexa)) {
			$top1m_list = $alexa;
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
		// ADR-10 P5: atomic publish (stage -> fsync -> rename). The per-feed raw
		// files were already (re)written into unbound_py_rawdir above; the manifest
		// rename is the point at which the new immutable set becomes readable. The
		// sentinel flip that ACTS on it is driven by pfb_reload_unbound's data
		// fast path (so a full feed update advances the generation exactly once,
		// after every manifest+raw file is in place), not here.
		pfb_unbound_py_atomic_write($pfb['unbound_py_sources'], $json);
	}

	return $manifest;
}


// ADR-06: Update only the manifest's config.user_whitelist in place (used by the
// alerts "add to whitelist" button, which changes the suppression config without a
// full feed re-enumeration). The query-time whiteDB is rebuilt from this on reload.
function pfb_unbound_python_sources_whitelist() {
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
	$manifest['config']['user_whitelist'] = pfb_dnsbl_whitelist_lines();

	$json = json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
	if ($json !== FALSE) {
		// ADR-10 P5: atomic publish (the sentinel flip is driven by the reload).
		return pfb_unbound_py_atomic_write($pfb['unbound_py_sources'], $json);
	}

	return FALSE;
}


// ADR-06 (#51): update ONLY the manifest's config.user_unlock in place, recomputed
// from the live temporary-unlock store (pfb_dnsbl_unlock_lines). Mirrors
// pfb_unbound_python_sources_whitelist(): the alerts Lock/Unlock icon toggles the
// pfb_unlock state without a full feed re-enumeration, so patch the manifest and let
// the query-time whiteDB rebuild from it on the next reload. The alerts handler's
// reload (pfb_reload_unbound) does NOT delete the store, so store and manifest stay in
// step; a full update/Force/Cron is the only thing that clears both.
function pfb_unbound_python_sources_unlock() {
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
	$manifest['config']['user_unlock'] = pfb_dnsbl_unlock_lines();

	$json = json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
	if ($json !== FALSE) {
		// ADR-10 P5: atomic publish (the sentinel flip is driven by the reload).
		return pfb_unbound_py_atomic_write($pfb['unbound_py_sources'], $json);
	}

	return FALSE;
}


// ADR-06 (#51): map a per-alert DNSBL Lock/Unlock action (the dnsbl_remove POST
// value) to its temporary-unlock STORE operation + status message. Extracted from
// the pfblockerng_alerts.php handler so the four-way dispatch is unit-testable (every
// branch covered, not just the unlock/lock paths the smoke matrix observes). The four
// icon actions collapse onto two pfb_unlock modes: unlock/relock ADD the domain to
// the store ('unlock'), lock/reunlock REMOVE it ('lock'). An UNKNOWN action returns an
// empty mode so the handler does NOTHING -- a crafted POST cannot mutate the store
// (the old inline `else` treated any non-unlock/relock value as a REMOVE). 'msg'
// carries a single %s for the domain (sprintf in the handler); empty for an unknown
// action so the redirect shows no status.
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

		if (!isset($tld_segments)) {
			$tld_segments = '1';
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

		$now = date('m/j/y H:i:s', time());

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
python_tld_seg	= {$tld_segments}
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
			$line	= rtrim($line, "\x00..\x1F");
			$tld	= substr($line, strrpos($line, '.') + 1);

			if (!empty($tld)) {
				if (!is_array($tlds[$tld])) {
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

	// ADR-07 P8: ABP/EasyList feeds carry RAW ABP lines (||x^, @@||x^, /re/,
	// '0.0.0.0 host') -- NOT the legacy ',domain,,log,feed,group' CSV shape that
	// this loop parses. Parsing them as CSV yields garbage/empty domains. ABP feeds
	// are tagged with a persisted '{$header}.abp' marker and are built ENTIRELY by
	// the Python ABP parser (parse_abp) via the per-feed manifest -- which is written
	// unconditionally (inc, pfb_unbound_python_sources call) and does its own TLD
	// classification, independent of this PHP TLD pass. So SKIP any line whose feed
	// carries the '.abp' marker: it is never CSV-mangled here, and Python still
	// builds its domains/regex. Plain feeds keep the legacy TLD behaviour unchanged.
	// FOLLOW-UP: a later pass should review full ABP x DNSBL-TLD integration (e.g.
	// folding the PHP TLD pass into the Python build for all feeds).
	$abp_feeds = array();
	foreach (glob("{$pfb['dnsdir']}/*.abp") ?: array() as $abp_marker) {
		$abp_feeds[basename($abp_marker, '.abp')] = '';
	}

	// DNSBL python: Analyse DNSBL into data (transparent/exact) and zone (wildcard) files

	if (($fhandle = @fopen("{$pfb['dnsbl_file']}.raw", 'r')) !== FALSE) {
		while (($line = @fgets($fhandle)) !== FALSE) {
			if (empty($line)) {
				continue;
			}

			// ADR-07 P8: skip ABP-feed lines (see note above). A plain CSV row is
			// ',domain,,log,feed,group'; the feed name is column index 4. ABP raw
			// lines lack this shape, so an unset/empty feed column also means skip.
			if (!empty($abp_feeds)) {
				$fparts	= explode(',', $line, 6);
				$lfeed	= isset($fparts[4]) ? $fparts[4] : '';
				if ($lfeed === '' || isset($abp_feeds[$lfeed])) {
					continue;
				}
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
		$log = " completed [ NOW ]\n";
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
		pfb_logger("\nTLD finalize... completed [ NOW ]\n", 1);

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


// ADR-10 P5: is the DNSBL Unbound python integration the LIVE resolver mode? The
// zero-downtime swap only applies when the in-memory matcher (pfb_unbound.py) is the
// active blocklist source -- i.e. the resolver config has the python module wired in.
// Read from config.xml (the source of truth), not a generated file.
function pfb_unbound_py_mode_active() {
	return (config_path_enabled('unbound', 'python') &&
		config_get_path('unbound/python_script') == 'pfb_unbound');
}


// ADR-10 P5: C-cache flip for a zero-downtime swap. Staleness is ONE-DIRECTIONAL
// (RESULTS/01 SS4b, Context 7): since #43 DNSBL blocks set qstate.no_cache_store=1 so a
// block reply is NEVER in Unbound's message cache. So:
//   block->allow (unlock / name removed): IMMEDIATE -- nothing to flush (the swap's
//     decisionDB.clear() inside the module is all it needs).
//   allow->block (lock / name added): the previously-RESOLVED real answer is still cached
//     and serves until its TTL. ONLY this direction needs a flush, and ONLY for names
//     whose new verdict is "blocked".
// $names: the newly-blocked names (allow->block delta). For an alerts Lock this is the
// single known domain (exact, cheap); a feed/cron update's delta is not cheaply
// computable here, so the caller passes none and we accept TTL-bounded staleness -- NOT a
// regression (today's restart preserves the resolved cache, so today is stale too).
// Coalesced into ONE chroot unbound-control session and gated behind the DNSBL-queries
// daemon's '.sync' suppression marker (touched by pfb_update_unbound / the fast path) so
// the flush does not collide with the daemon on the control socket.
// Build the coalesced unbound-control C-cache flush command list for the newly-blocked
// names. Each name is VALIDATED as a domain via pfb_filter() (issue #153) before it can be
// interpolated into a command: a non-domain / shell-metachar entry is DROPPED, never
// reaching the exec() in pfb_unbound_py_ccache_flush() -- defence in depth atop the
// escapeshellarg() below (the names already arrive PFB_FILTER_DOMAIN-filtered from the
// alerts page, but this choke point must not trust its input). Returns the full command
// strings (chroot_cmd-prefixed, each variant escapeshellarg'd), de-duplicated across each
// name + its 'www.' sibling. Pure (no globals / side effects) so every branch is
// unit-testable off-appliance (the exec lives in the wrapper below).
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


// Reload Resolver
//
// ADR-10 P5: $datapath signals a pure DNSBL-DATA update (feed/cron, or a #51 user
// custom-list Lock/Unlock/whitelist edit) that has already been published atomically to
// the manifest. When the python integration is the live mode, unbound is running, no
// config change is pending, and the projected ~2x build fits RAM, such an update takes
// the ZERO-DOWNTIME fast path: flip the reload sentinel (the module rebuilds + swaps off
// the query threads) with NO unbound restart. $newly_blocked carries the allow->block
// delta to flush from the C-cache after the swap (a #51 Lock passes the one locked name;
// feed/cron pass none -> accepted TTL-bounded staleness). Any other case -- a config
// change, the feature unavailable, or the RAM gate declining -- falls back to the restart
// (the fail-safe; PHP is the PRIMARY gate so we never "flip and hope").
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

					pfb_logger(" completed [ NOW ]", 1);
					// Clear the daemon-suppression marker before this early return: the
					// alert/#51 path (pfb_reload_unbound called from pfblockerng_alerts.php)
					// has no later clear_work_files, so '.sync' would otherwise leak and keep
					// the DNSBL Queries daemon suppressed. The restart-fallback paths below
					// reach the normal clear, so this is the only fast-path exit that needs it.
					unlink_if_exists("{$pfb['dnsbl_file']}.sync");
					return;
				}

				// The swap did not confirm within the budget (watcher stuck / declined
				// its own RAM re-check / very slow box) -> fall back to the restart so
				// the new lists definitely load. NOT an error: fail-safe by design.
				pfb_logger(" not confirmed in time -- falling back to Unbound restart", 2);
			}
			else {
				// Sentinel flip failed (could not stage/rename) -> fall back to the restart
				// so the new lists still load (don't leave a flipped-but-no-op state).
				pfb_logger("\nADR-10: sentinel flip failed -- falling back to Unbound restart", 2);
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
			pfb_logger(" completed [ NOW ]", 1);

			// Restore Resolver cache
			if ($cache && $pfb['dnsbl_res_cache'] == 'on' && file_exists($cache_dumpfile) && filesize($cache_dumpfile) > 0) {
				exec("{$pfb['chroot_cmd']} load_cache < " . escapeshellarg($cache_dumpfile) . " 2>&1");
				$log = "\nResolver cache restored [ NOW ]";
				pfb_logger($log, 1);
			}
		}
		else {
			$log = htmlspecialchars(implode("\n", $final['result']));
			pfb_logger(" Not completed. [ NOW ]\n{$log}\n", 1);
		}
	}
	else {
		$log = htmlspecialchars(implode("\n", $final['result']));
		pfb_logger(" Not completed. [ NOW ]\n{$log}\n", 1);
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

		// ADR-10 P5: a feed/cron DNSBL-DATA update takes the zero-downtime swap when the
		// reload introduces NO config change ($pfbpython FALSE -> unbound.conf/ini/mounts
		// unchanged). The manifest + per-feed raw were already published atomically by
		// pfb_unbound_python_sources() above; flip the sentinel, no restart. A config
		// change ($pfbpython TRUE) -> $datapath FALSE -> the restart path. The feed delta
		// (allow->block names) is not cheaply computable here, so no targeted C-cache
		// flush is passed -> accepted TTL-bounded staleness (no worse than the restart,
		// which preserves the resolved cache too -- RESULTS/01 SS4b).
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
	$log = "\nDNSBL update [ feed lines: {$dnsbl_cnt} | loaded entries: {$loaded_cnt} ]... completed [ NOW ]";
	pfb_logger("{$log}", 1);

	// Clear work files
	pfb_unbound_clear_work_files();
	pfb_logger("\n------------------------------------------------------------------------", 1);
}


// Process TOP1M database
function pfblockerng_top1m() {
	global $pfb;

	if (empty($pfb['dnsbl_alexa_inc'])) {
		pfb_logger("\n  TOP1M: No TLD Inclusions found.\n", 1);
		return;
	}

	// Array of TLDs to include in Whitelist
	$pfb_include = explode(',', $pfb['dnsbl_alexa_inc']);
	if (!empty($pfb_include)) {
		$pfb_include = array_flip($pfb_include);
	}

	$linecnt = $x = 0;
	pfb_logger(" Building TOP1M Whitelist [", 1);

	if (($handle = @fopen("{$pfb['dbdir']}/top-1m.csv", 'r')) !== FALSE) {
		$pfb_output = @fopen("{$pfb['dbdir']}/pfbalexawhitelist.txt", 'w');
		while (($line = @fgets($handle)) !== FALSE) {

			if (strpos($line, '.') === FALSE || strpos($line, ',') === FALSE || empty($line)) {
				continue;
			}

			// Display progress indicator
			if ($linecnt % 100000 == 0) {
				pfb_logger('.', 1);
			}

			// Collect Domain TLD
			$csvline	= str_getcsv($line, ',', '"', "\\");
			$tld		= substr($csvline[1], strrpos($csvline[1], '.') + 1);

			if (isset($pfb_include[$tld])) {
				// Whitelist both 'www.example.com' and 'example.com'
				if (str_starts_with($csvline[1], 'www.')) {
					$csvline[1] = substr($csvline[1], 4);
				}
				$x++;

				// Create three whitelist options per TOP1M whitelisted Domain
				@fwrite($pfb_output, ".{$csvline[1]},,\n,{$csvline[1]},,\n,www.{$csvline[1]},,\n");
			}

			if ($x >= $pfb['dnsbl_alexa_cnt']) {
				break;
			}
			$linecnt++;
		}
		pfb_logger("] [ Parsed {$linecnt} lines | Found {$x} of {$pfb['dnsbl_alexa_cnt']} ]...", 1);
	}
	else {
		$log = "\nTOP1M conversion Failed. File: top-1m.csv, not found...";
		pfb_logger("{$log}", 2);
	}

	if ($handle) {
		@fclose($handle);
	}
	if ($pfb_output) {
		@fclose($pfb_output);
	}

	// Remove Top1M update file marker
	unlink_if_exists("{$pfb['dbdir']}/top-1m.update");
}


// Function to remove any leading zeros in octets and to exclude private/reserved addresses.
function sanitize_ipaddr($ipaddr, $custom, $pfbcidr) {
	global $pfb;

	$parts	= explode('/', $ipaddr);
	$subnet	= $parts[0];
	$mask	= $parts[1] ?? '';	// '' (not undef) when no CIDR -> avoids str_replace(null) below
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

	$mask = str_replace('32', '', $mask);	// Strip '/32' mask
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

		if ($mask > 32) {
			$mask = '';
		}

		if (!filter_var($ip_final, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== FALSE) {
			return;
		}
	}

	if (!empty($mask)) {
		return "{$ip_final}/{$mask}";
	}
	return "{$ip_final}";
}


// IPv6 sibling of sanitize_ipaddr(): exclude private/reserved/loopback IPv6
// addresses from loaded block lists when Suppression is enabled. Returns the
// entry unchanged when kept; returns nothing (drops it) when excluded.
function sanitize_ipaddr_v6($ipaddr, $custom) {
	global $pfb;

	// Exclude private/reserved IPs (bypass exclusion for custom lists)
	if ($pfb['supp'] == 'on' && !$custom) {

		// Extract the address part (before '/' for a CIDR like 'fc00::/7')
		$s_ip = explode('/', $ipaddr)[0];

		// Drop ULA (fc00::/7), link-local (fe80::/10), loopback (::1),
		// IPv4-mapped and the reserved set (mirrors inc:7118-7119).
		if (!filter_var($s_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) ||
		    !filter_var($s_ip, FILTER_CALLBACK, array('options' => 'FILTER_FLAG_NO_LOOPBACK_RANGE'))) {
			return;
		}
	}

	return $ipaddr;
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
	$query	= exec("{$pfb['grep']} -s {$q_ip} {$pfbfolder} 2>&1");
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
			exec("{$pfb['grep']} -s {$query_esc} {$pfbfolder} 2>&1", $result);
		} else {
			$geoip_list = "Africa\|Antarctica\|Asia\|Europe\|North_America\|South_America\|Oceania\|Proxy_and_Satellite\|Top_Spammers";
			exec("{$pfb['grep']} -s {$query_esc} {$pfb['ccdir']}/*.txt | {$pfb['grep']} -v '{$geoip_list}' 2>&1", $result);
		}

		$cidrs = array();
		if (!empty($result)) {
			foreach ($result as $line) {
				$rx = pfb_parse_query($line);

				// Collect all CIDRs for analysis if Alert is from a CIDR
				if (strpos($rx[1], '/') !== FALSE) {
					$cidrs[] = $rx;
				}
			}
		}

		if (isset($result)) {
			unset($result);
		}

		// Determine which CIDR alerted the IP address
		if (!empty($cidrs)) {
			foreach ($cidrs as $line) {
				$validate = FALSE;
				if ($v4_type) {
					list($addr, $mask) = explode('/', $line[1]);
					$mask = (0xffffffff << (32 - $mask)) & 0xffffffff;
					$validate = ((ip2long($ip) & $mask) == (ip2long($addr) & $mask));
				}
				else {
					/* Normalize IPv6 prefix to its start address to avoid PHP errors
					 * https://redmine.pfsense.org/issues/14256
					 */
					list($prefix, $length) = explode('/', $line[1]);
					$prefix = gen_subnetv6($prefix, $length);
					$subnet = "{$prefix}/{$length}";

					$validate = (Net_IPv6::isInNetmask($ip, $subnet));
				}

				// Return header on CIDR match
				if ($validate) {
					unset($cidrs);
					return $line;
				}
			}
			unset($cidrs);
		}
	}

	if (isset($result)) {
		unset($result);
	}
	return array('Unknown', 'Unknown');
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
// $dconfig is the existing DNSBL-settings 'config/0' node. DNSBL control is CLI-driven and
// the DNS-TXT transport is OFF by default; to avoid breaking an operator already driving
// control over DNS TXT, the legacy sub-toggle is seeded ON IFF the pre-existing config
// already had DNSBL Control enabled ('pfb_control' == 'on') at this upgrade. A one-shot
// marker ('pfb_control_legacy_seeded') makes this run EXACTLY ONCE: once set, the function
// returns NULL (no change), so a later save never re-seeds and never re-enables a toggle
// the operator deliberately turned back off. Returns the updated config array to persist,
// or NULL when nothing should change (empty config, or the seed already ran). Slated for
// removal next release with the rest of the legacy DNS-TXT path.
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


// ADR-22: one-time upgrade migration for the 'pfb_dnsbl_lenient' DNSBL scheme-parsing
// toggle. $dconfig is the existing DNSBL-settings 'config/0' node. New installs default to
// OFF (strict RFC 3986 parsing); an EXISTING install (a non-empty config section) that
// predates this key is migrated to 'on' (lenient) to preserve the permissive behaviour it
// already relies on -- malformed-scheme lines were silently accepted/blocked before. Keying
// on a non-empty $dconfig distinguishes an upgrade from a first-ever install (which has no
// prior config section, so the new-install strict default stands). Migration ONLY sets a
// missing key -- an existing 'on'/'off' value is never overwritten. Returns the updated
// config array to persist, or NULL when nothing should change (fresh install, or the key
// already present).
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


// Verify a feed host does not resolve to a non-public/reserved address before any
// connection is made. Fail-closed: an unresolvable host, or any resolved address
// that is non-public AND not covered by the operator's internal-address allowlist,
// is rejected. On success $pinned receives the vetted IP the caller pins the
// connection to (so the fetch cannot rebind to another address); $reason carries a
// neutral skip reason on rejection.
//
// A resolved address is permitted when it is public, when it is the firewall itself
// (its own configured address / loopback — a self-hosted feed), or when it is covered
// by an allowlist entry (exact IP, or containment in an allowlisted CIDR — General
// settings: 'internal-address exemptions'). An empty allowlist (the default) blocks
// every other feed that resolves to an internal/private address.
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


// Function to download feeds
//
// Optional $response_meta — when a non-NULL reference is passed (detector probe mode), it is
// filled with an array: ['status' => <http_status_string>, 'etag' => <ETag string or ''>,
// 'lastmod' => <epoch int or 0>]. The two sync callers in pfblockerng.inc (lines ~12436 and
// ~14096) do NOT pass this argument, so their behaviour is entirely unchanged.
function pfb_download($list_url, $file_dwn, $pflex=FALSE, $header, $format, $logtype, $vtype='', $timeout=300, $type='', $username='', $password='', $srcint=FALSE, &$response_meta=NULL) {
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
		pfb_logger("\n Failed", 2);
		return FALSE;
	}

	// Cron update function for md5 comparison
	if ($type == 'md5') {
		pfb_logger("\t\t\t\t( md5 feed )\t\t", 1);
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

	// If the Cron update function 'md5 comparison' generated an md5 file, re-utilize instead of downloading twice
	if (file_exists("{$md5_download}")) {
		$list_download = "{$md5_download}";
		pfb_logger(' ( md5 feed ) ', 1);
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
				// follow and the 'ETag' header for ADR-42 Phase 3 conditional-GET.
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

				// ADR-42 Phase 3: send a conditional GET when stored validators are
				// available for this feed's .orig baseline.  ETag → If-None-Match
				// (primary); Last-Modified epoch → CURLOPT_TIMECONDITION (fallback).
				// Only applied to the probe ('md5') mode: the sync ingest callers pass
				// $type == '' and must always receive the full body.
				if ($type === 'md5') {
					$validators = pfb_validator_read("{$orig_download}");
					if (is_string($validators['etag']) && $validators['etag'] !== '') {
						curl_setopt($ch, CURLOPT_HTTPHEADER, array("If-None-Match: {$validators['etag']}"));
					} elseif (is_int($validators['lastmod']) && $validators['lastmod'] > 0) {
						curl_setopt($ch, CURLOPT_TIMECONDITION, CURL_TIMECOND_IFMODSINCE);
						curl_setopt($ch, CURLOPT_TIMEVALUE, $validators['lastmod']);
					}
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
							pfb_logger(" cURL Error: {$curl_error} [ NOW ]\n", 1);
						} else {
							pfb_logger(" {$header}\t\tcURL Error: {$curl_error} [ NOW ]\n\n", 3);
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
								$log = curl_error($ch) . " |{$head_download}|{$list_download}| Retry [{$retries}] in 5 seconds...\n";
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

	// Probe mode for the cron detector (type='md5'): fill $response_meta when
	// the caller requested it (ADR-42 Phase 3 conditional-GET path), then return.
	// A 304 means "not modified" — the server confirmed the feed unchanged; the
	// caller (pfb_update_check detector) handles the 304 via pfb_conditional_get_decision.
	// Any 200 means the body was downloaded to {file_dwn}.raw; the caller hashes it.
	// Any other status means the probe failed; the caller fails-safe to re-ingest.
	//
	// CONTRACT: the caller MUST pass $response_meta = array() (not NULL) to activate
	// the fill block.  NULL is the sentinel for the two sync callers that do NOT want
	// the block filled; NULL !== NULL is always FALSE, so NULL silently skips the fill.
	if ($type == 'md5') {
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

		if (isset($retval)) {
			unset($retval);
		}

		// Validate File Mime-type
		$file_type = pfb_filter(array("{$file_dwn_esc}", "{$file_download}", "{$list_download}"), PFB_FILTER_FILE_MIME, 'pfb_download');
		if (!$file_type) {
			return FALSE;
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
			if ($type == 'geoip') {
				// Extras - MaxMind downloads
				exec("/usr/bin/tar -xzf {$file_dwn_esc} --strip=1 -C {$pfb['geoipshare']} >/dev/null 2>&1");
				unlink_if_exists($file_dwn_esc);
				return TRUE;
			}
			elseif ($type == 'asn') {
				exec("/usr/bin/gunzip -c {$file_dwn_esc} > {$header_esc}", $output, $retval);

				// Update ASN Lookup table definitions
				exec("{$pfb['script']} asn_table >> {$logtype} 2>&1");

				unlink_if_exists($file_dwn_esc);
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
				}
				else {
					pfb_logger("\n Invalid filename [{$filename}]", 1);
					return FALSE;
				}
			}
			else {
				if (!pfb_filter(array("{$file_dwn_esc}", "{$file_download}", "{$list_download}"), PFB_FILTER_FILE_MIME_COMPRESSED, 'pfb_download')) {
					return FALSE;
				}
				pfb_logger('.', 1);
				exec("/usr/bin/gunzip -c {$file_dwn_esc} > {$file_org_esc}", $output, $retval);
			}
		}
		elseif ($file_type == 'application/x-bzip2') {
			if (!pfb_filter(array("{$file_dwn_esc}", "{$file_download}", "{$list_download}"), PFB_FILTER_FILE_MIME_COMPRESSED, 'pfb_download')) {
				return FALSE;
			}
			pfb_logger('.', 1);
			exec("/usr/bin/bzip2 -dkc {$file_dwn_esc} > {$file_org_esc}", $output, $retval);
		}
		elseif ($file_type == 'application/zip') {

			// Extras - MaxMind/TOP1M downloads
			if ($type == 'geoip' || $type == 'top1m') {
				// Determine if Zip contains multiple files
				exec("/usr/bin/tar -tf {$file_dwn_esc} 2>&1", $archive_count, $retval);
				if ($archive_count[0] == 'tar: Failed to set default locale') {
					unset($archive_count[0]);
				}
				if (count($archive_count) > 1) {
					exec("/usr/bin/tar -xf {$file_dwn_esc} --strip=1 -C {$header_esc} >/dev/null 2>&1");
				} else {
					exec("/usr/bin/tar -xOf {$file_dwn_esc} > {$header_esc}");
				}
				return TRUE;
			}

			pfb_logger('.', 1);

			/* TODO: FIX - Bypass ZIP Compression file mime type validation due to incompatability with ZIP files
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
				exec("/usr/bin/tar -xOf {$file_dwn_esc} | /usr/bin/sed 's/,[[:space:]]/; /g' | /usr/bin/tr ',' '\n' > {$file_org_esc}", $output, $retval);
			}

			// TODO: Validate file contents after extraction (to be removed once ZIP compression file mime type is fixed above)
			if (!pfb_filter(array("{$file_org_esc}", "{$file_download}", "{$list_download}"), PFB_FILTER_FILE_MIME, 'pfb_download')) {
				unlink_if_exists("{$file_org_esc}");
				return FALSE;
			}
		}
		elseif ($file_type == 'application/x-7z-compressed') {
			if (!pfb_filter(array("{$file_dwn_esc}", "{$file_download}", "{$list_download}"), PFB_FILTER_FILE_MIME_COMPRESSED, 'pfb_download')) {
				return FALSE;
			}
			pfb_logger('.', 1);
			exec("/usr/local/bin/7z e -so {$file_dwn_esc} > {$file_org_esc}", $output, $retval);
		}
		else {
			// Uncompressed file format.
			if ($type == 'geoip' || $type == 'asn') {
				// Extras - MaxMind/TOP1M/ASN downloads
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

			// ADR-42 Phase 2: refresh the content-hash sidecar at every successful ingest
			// so pfb_local_feed_changed() always compares against the last-ingested bytes.
			// This covers both local and remote standard feeds (any path that finalises a
			// plain .orig here).  geoip/asn early-returns (~line 7872) do not reach this
			// block, so they correctly never get a sidecar.
			pfb_hash_write("{$orig_download}", "{$orig_download}");

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
			pfb_logger("\n Invalid WHOIS. Terminating Download! [ {$list_url} ]\n", 1);
		}
	}
	elseif ($format == 'asn') {
		if (empty(pfb_filter($list_url, PFB_FILTER_ALNUM, 'pfb_download_failure'))) {
			pfb_logger("\n Invalid ASN. Terminating Download! [ {$list_url} ]\n", 1);
		}
	}
	elseif (!pfb_filter($list_url, PFB_FILTER_URL, 'pfb_download_failure')) {
		pfb_logger("\n Invalid URL. Terminating Download! [ {$list_url} ]\n", 1);
	}
	else {
		// Determine if URL is a localfile
		$localfile = FALSE;
		if (pfb_filter($list_url, PFB_FILTER_URL, 'pfb_download_failure', '', TRUE)) {
			$localfile = TRUE;
		}

		// Log FAILED downloads and check if firewall or Snort/Suricata is blocking host
		$log = "\n\n [ {$alias} - {$header} ] Download FAIL [ NOW ]\n";
		pfb_logger("{$log}", 2);

		// Only perform these checks if they are not 'localfiles'
		if ($localfile) {
			$log = "   Local File Failure\n";
			pfb_logger("{$log}", 2);
		}
		else {
			// Determine if Firewall/IPS/DNSBL is blocking download.
			$data = parse_url("{$list_url}");

			$validate_list = array();
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
						$result = substr(exec("{$pfb['pfctl']} -t snort2c -T test {$ip_esc} 2>&1"), 0, 1);
						if ($result > 0) {
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
		$today_date = date('m/j/y', time());
		exec("{$pfb['grep']} 'FAIL' {$pfb['errlog']} | {$pfb['grep']} {$today_date}", $results);
		if (!empty($results)) {
			foreach ($results as $result) {
				$header = explode(' ', $result);
				$pfb['failed'][$header[4]] += 1;
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


// Deterministic, IP-independent firewall-rule tracker for pfBlockerNG MANAGED
// STATIC rules (ADR-37 DoT/DoQ block). Modelled on pfb_tracker() (feed rules) but
// keyed on the rule's stable 'descr' ALONE -- no interface IP/subnet -- so the id
// is identical across re-syncs and survives a DHCP renewal. That stability is the
// point: a fresh-each-sync tracker (e.g. the GUI's (int)microtime()) would make the
// rule's change-detection always fire, churning write_config()/filter_configure()
// every sync. (ADR-36 NAT redirect rules need NO tracker -- pfSense NAT rules don't
// carry one, and 'associated-rule-id=pass' has no companion filter rule to link.)
//
// Namespaced '176' to mark it as a pfBlockerNG MANAGED-rule tracker, distinct from
// feed trackers ('177'). 176xxxxxxx is a PAST Unix epoch (~Oct 2025), so it can
// never collide with a future GUI rule's (int)microtime() tracker, and it stays
// well under 2^32 so pf's uint32 'ridentifier' never overflows. Duplicates (same
// char-sum) step to a sequential id in the same namespace, registered like
// pfb_tracker() so a managed tracker never clashes with a feed tracker in one sync.
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
			$files = glob("{{$pfb['aliasdir']}/pfB_*.txt,{$pfb['dnsbl_file']}.conf}", GLOB_BRACE);
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


// #468: DNSBL python-integration cache for RAM-disk /var (use_mfs_tmpvar) installs.
// SEPARATE from pfb_aliastables() on purpose -- the IP-alias archive and the DNSBL
// archive have different lifecycles (DNSBL changes vs IP-rule changes). All file ops
// live in 'pfblockerng.sh dnsbl_cache' (the shipped-file list has one home, in shell).
//
//   'conf' -- register the boot 'dnsbl_cache restore' earlyshellcmd when DNSBL is
//             enabled AND /var is a RAM disk; otherwise remove it and delete the
//             archive (DNSBL off or MFS off -> nothing to restore).
//   'save' -- archive the current generated DNSBL state (called post-reload on a real
//             DNSBL change; the caller gates on use_mfs_tmpvar + DNSBL enabled).
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

	// Collect IPv4 Suppression list IPs
	$v4suppression = pfbng_text_area_decode($pfb['ipconfig']['v4suppression'], TRUE, FALSE);
	foreach ($v4suppression as $line) {
		if (strpos($line, '/32') != FALSE) {
			$pfb_local[] = str_replace('/32', '', $line);
		}

		// Convert '/24' CIDRs
		$pfb_suppcidr = array();
		if (strpos($line, '/24') !== FALSE && is_ipaddrv4($line)) {
			$pfb_suppcidr	= subnetv4_expand($line);
			$pfb_local	= array_merge($pfb_local, $pfb_suppcidr);
		}
	}

	if (!empty($pfb_local)) {
		$pfb_local = array_flip($pfb_local);
	}

	// Collect Interface list that have pfB Rules assigned
	$data		= pfb_filterrules();
	$pfb_int	= $data['int'] ?: array();

	// Collect local IPs
	$data = pfb_collect_localip();
	if (!empty($data[0])) {
		$pfb_local = array_merge($pfb_local, $data[0]);
	}
	$pfb_localsub = $data[1] ?: array();

	// Collect DNS servers to suppress
	$pfb_dnsservers = get_dns_servers();
	if (!empty($pfb_dnsservers)) {
		$pfb_local = array_merge($pfb_local, $pfb_dnsservers);
	}

	// Remove any duplicate IPs
	if (!empty($pfb_local)) {
		$pfb_local = array_flip(array_unique($pfb_local));
	}

	// Collect any 'Permit' Customlist IPs to suppress
	$custom_supp = array();
	foreach (array('pfblockernglistsv4', 'pfblockernglistsv6') as $ip_type) {
		foreach (config_get_path("installedpackages{$ip_type}/config", []) as $list) {
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
					    !filter_var($s_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) ||
					    !filter_var($s_ip, FILTER_CALLBACK, array('options' => 'FILTER_FLAG_NO_LOOPBACK_RANGE'))) {
						continue;
					}
				}

				// Exclude any 'Permit' Customlist IPs
				foreach ($custom_supp as $custom) {
					if (ip_in_subnet($s_ip, $custom)) {
						continue;
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
					$result = substr(exec("{$pfb['pfctl']} -t {$s_table_esc} -T test {$s_ip_esc} 2>&1"), 0, 1);
					if ($result > 0) {

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

	// Convert any 'Firewall Aliases' to IP address format
	$aliases = config_get_path('aliases/alias', []);
	if (is_array($aliases)) {
		for ($cnt = 0; $cnt <= count($pfb_local); $cnt++) {
			foreach ($aliases as $i=> $alias) {
				if (isset($alias['name']) && isset($pfb_local[$cnt])) {
					if ($alias['name'] == $pfb_local[$cnt]) {
						$pfb_local[$cnt] = $alias['address'];
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
				elseif (is_ipaddrv6($int['ipaddr'])) {
					$pfb_localsub[] = gen_subnetv6("{$int['ipaddr']}", "{$int['subnet']}") . "/{$int['subnet']}";
				}
			}
			elseif (is_ipaddr($int['ipaddr'])) {
				$pfb_local[] = "{$int['ipaddr']}";
			}
		}
	}

	// Collect runtime IPv6 addresses for inbound/outbound list matching.
	// Interfaces using a dynamic address mode (track6/dhcp6/SLAAC) store a keyword
	// in config.xml rather than a literal IPv6 address, so the interface loop above
	// produces nothing for them.  get_configured_ipv6_addresses() returns the actual
	// runtime addresses (keyed by friendly interface name) and covers all modes.
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


// Resolve a filter.log Tracker ID to a pfBlockerNG rule.
//
// Returns TRUE when $tracker is a pfB rule whose type matches $type (caller processes
// the line); FALSE for a known non-pfB ('other') or an unresolvable tracker (caller skips).
//
// $rule_list  : positive cache from pfb_filterrules(); rebuilt in place on a reparse.
// $miss_cache : PERSISTENT negative cache keyed by "tracker\0type"; survives reparses (a
//               reparse rebuilds $rule_list but not this), so each unresolvable tracker/type
//               triggers at most ONE reparse for the daemon's life. Keying by type (and
//               checking the positive pfB cache first) ensures a transient type mismatch
//               never suppresses a later log event whose type DOES match the pfB rule.
// $reparse    : callable() => array — fresh rule list (production: 'pfb_filterrules').
// $on_reparse : callable() => void  — refresh daemon-local IP/host collections after a reparse.
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
		$digest = @hash_file('xxh128', $path_or_data);
		return ($digest !== FALSE) ? $digest : FALSE;
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

// ADR-42 Phase 3: read the per-feed HTTP validators (ETag + Last-Modified epoch)
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

// ADR-42 Phase 3: persist the HTTP validators for a feed's .orig base path.
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

// ADR-42 Phase 3: pure decision helper for the remote conditional-GET result.
// Called by the detector after pfb_download returns the probe response.
//
// Contract (ADR-42 §2 #5 and #6):
//   304 → unchanged (server confirmed — body was not re-sent).
//   200 with body_hash == persisted_hash → unchanged (spurious 200; same bytes as baseline).
//   200 with body_hash != persisted_hash → changed (real update; re-ingest needed).
//   200 with no persisted hash ('') or body_hash FALSE → changed (no baseline to compare;
//     fail-safe: cannot confirm unchanged, so treat as changed).
//   Any other status or body_hash FALSE → changed (ambiguous/error; fail-safe, never false skip).
//
// $http_status  — the HTTP status code string from pfb_download's $response_meta['status'].
// $body_hash    — the xxh128 digest of the probe body (string) or FALSE if unreadable.
// $persisted_hash — the stored xxh128 digest of the last-ingested .orig (string) or '' if absent.
// Returns TRUE when re-ingest is needed, FALSE when the feed is confirmed unchanged.
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

// Extract the local-feed change decision from pfb_update_check() as a named,
// off-appliance-testable helper. Callers pass the source path and the .orig baseline;
// this function returns TRUE when the feed has changed (re-ingest needed), FALSE when it
// has not. It never concludes "unchanged" on a read failure — fail-safe.
//
// Algorithm (ADR-42 Phase 2 — content-hash gate, mtime removed):
//  1. If either file is absent → changed (no baseline = first run).
//  2. Read the tagged sidecar for the .orig via pfb_hash_read():
//     - sentinel (no/corrupt sidecar) → live-hash the .orig as the baseline (the
//       first-pass-after-upgrade case; also handles new installs before any sidecar exists).
//     - 'md5' → baseline = sidecar digest; compare source with md5_file().
//     - 'xxh128' → baseline = sidecar digest; compare source with pfb_content_hash().
//  3. Hash the source in the SAME algo as the baseline.
//  4. changed = (source_hash !== baseline). Any read failure → TRUE (fail-safe).
//
// NOTE: The sidecar is written (refreshed) at ingest time inside pfb_download(), so the
// baseline is always the hash of the last-ingested .orig.  This prevents the staleness
// trap: if the sidecar were only written here (before ingest) it would hold the OLD hash
// after re-ingest, causing every subsequent cron to falsely report "changed".
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

	// 'xxh128' — canonical post-Phase-2 path.
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

	// ASN Reporting - cached setting
	if ($pfb['asn_reporting'] != 'disabled') {
		switch ($pfb['asn_reporting']) {
			case '1hour':
				$asn_cache = '-1 hour';
				break;
			case '4hour':
				$asn_cache = '-4 hours';
				break;
			case '12hour':
				$asn_cache = '-12 hours';
				break;
			case '24hour':
				$asn_cache = '-24 hours';
				break;
			case 'week':
				$asn_cache = '-1 week';
				break;
			default:
				$asn_cache = '-24 hours';
		}
	}

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
		} else {
			$filter_cnt = max( exec("{$pfb['grep']} -c ^ /var/log/filter.log 2>&1") -1, 0) ?: 0;
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
					if (isset($pfb_local[$dstip]) || pfb_local_ip($dstip, $pfb_localsub)) {
						$dir	= 'in';
						$host	= $srcip;
						$client	= $dstip;
						$port	= $d[21];
					} else {
						$dir	= 'out';
						$host	= $dstip;
						$client	= $srcip;
						$port	= $d[20];
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
					if ($log_type == 'BSD') {
						$log = "{$f[0]} {$f[1]} {$f[2]},{$d[3]},{$d[4]},{$int},{$d[6]},{$d[8]},";
					} else {
						$ts = date('M j H:i:s', strtotime($f[1]));
						$log = "{$ts},{$d[3]},{$d[4]},{$int},{$d[6]},{$d[8]},";
					}

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
	return $rx;
}


// Functon to find which DNSBL Feed/Groupname blocked this event
function pfb_dnsbl_parse($mode='daemon', $domain, $src_ip, $req_agent) {
	global $pfb;

	$dnsbl_cache = FALSE;
	$db_handle = pfb_open_sqlite(4, 'Query cache');
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
	pfb_close_sqlite($db_handle);

	// If domain is not in DNSBL cache, query for blocked domain details
	if (!$dnsbl_cache) {
		$o_domain = $domain; // Store original domain for CNAME query

		while (TRUE) {

			$domainparse = str_replace('.', '\.', $domain);
			$dquery_esc	= escapeshellarg(",{$domainparse},,");
			$pfb_feed	= exec("{$pfb['grep']} -shm1 {$dquery_esc} {$pfb['unbound_py_data']} 2>&1");
			$pfb_group = $pfb_mode = $pfb_final = 'Unknown';

			// Exact Domain match found
			if (!empty($pfb_feed)) {

				list($dummy, $pfb_final, $empty_placeholder, $log_type, $pfb_feed, $pfb_group) = explode(',', $pfb_feed);
				$pfb_mode = 'DNSBL';
			}

			else {
				$dparts = explode('.', $domain);

				$dcnt = count($dparts);

				for ($i=0; $i <= $dcnt; $i++) {

					$domainparse		= str_replace('.', '\.', implode('.', $dparts));
					$domainparse_esc	= escapeshellarg("^{$domainparse}$");


					$dquery_esc	= escapeshellarg(",{$domainparse},,");
					$pfb_feed	= exec("{$pfb['grep']} -shm1 {$dquery_esc} {$pfb['unbound_py_zone']} 2>&1");

					// Collect Alias Group name
					if (!empty($pfb_feed)) {
						list($dummy, $d_found, $empty_placeholder, $log_type, $pfb_feed, $pfb_group) = explode(',', $pfb_feed);

						$pfb_final = str_replace('\.', '.', $domainparse);
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
		$db_handle = pfb_open_sqlite(4, 'Add to DNSBL cache');
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
		pfb_close_sqlite($db_handle);
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


// Function to create/open SQLite3 database(s)
function pfb_open_sqlite($table, $message) {
	global $pfb;

	// $table is always 1-7 from callers, but the if/elseif chain below has no else;
	// default these so they are defined for any value. Behaviour-preserving.
	$database	= '';
	$db_table	= '';
	$db_create	= '';

	if ($table == 1) {
		$database	= $pfb['dnsbl_info'];
		$db_table	= 'dnsbl';
		$db_create	= "CREATE TABLE IF NOT EXISTS dnsbl ( groupname TEXT, timestamp TEXT, entries INTEGER, counter INTEGER );";
	} elseif ($table == 2) {
		$database	= $pfb['dnsbl_resolver'];
		$db_table	= 'lastevent';
		$db_create	= "CREATE TABLE IF NOT EXISTS lastevent ( row INTEGER, groupname TEXT, entry TEXT, details TEXT );";
	} elseif ($table == 3) {
		$database	= $pfb['dnsbl_resolver'];
		$db_table	= 'resolver';
		$db_create	= "CREATE TABLE IF NOT EXISTS resolver ( row INTEGER, totalqueries INTEGER, queries INTEGER );";
	} elseif ($table == 4) {
		$database	= $pfb['dnsbl_cache'];
		$db_table	= 'dnsblcache';
		$db_create	= "CREATE TABLE IF NOT EXISTS dnsblcache ( type TEXT, domain TEXT, groupname TEXT, final TEXT, feed TEXT );";
	} elseif ($table == 5) {
		$database	= $pfb['asn_cache'];
		$db_table	= 'asncache';
		$db_create	= "CREATE TABLE IF NOT EXISTS asncache ( asn TEXT, host TEXT, timestamp TEXT );";
	} elseif ($table == 6) {
		$database	= $pfb['dnsbl_resolver'];
		$db_table	= 'stats';
		$db_create	= "CREATE TABLE IF NOT EXISTS lastclear ( row INTEGER, lastipclear TEXT, lastdnsblclear TEXT );";
	} elseif ($table == 7) {
		$database	= $pfb['ip_cache'];
		$db_table	= 'ipcache';
		$db_create      = "CREATE TABLE IF NOT EXISTS ipcache ( host TEXT, q0 TEXT, q1 TEXT, geoip TEXT, resolved_host TEXT );";
	}

	try {
		$db_handle = new SQLite3($database);
		$db_handle->busyTimeout("{$pfb['sqlite_timeout']}");
	}
	catch (Exception $e) {
		@file_put_contents($pfb['errlog'], "\nDNSBL_SQL: Failed to open DB - {$message}", FILE_APPEND | LOCK_EX);

		try {
			$db_handle = new SQLite3($database);
			$db_handle->busyTimeout("{$pfb['sqlite_timeout']}");
		}
		catch (Exception $e) {
			@file_put_contents($pfb['errlog'], "\nDNSBL_SQL: Failed to open DB 2nd attempt - {$message}", FILE_APPEND | LOCK_EX);
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
				@file_put_contents($pfb['errlog'], "\nDNSBL_SQL: Failed to enable WAL ({$journal_mode}) - {$message}", FILE_APPEND | LOCK_EX);
			}
		}
		catch (Exception $e) {
			@file_put_contents($pfb['errlog'], "\nDNSBL_SQL: Failed to enable WAL - {$message}", FILE_APPEND | LOCK_EX);
		}

		// Validate database integrity
		$validate = $pfb_validate = FALSE;
		try {
			$validate = $db_handle->query("PRAGMA integrity_check;");
		}
		catch (Exception $e) {
			@file_put_contents($pfb['errlog'], "\nDNSBL_SQL: Failed to validate database - {$message}", FILE_APPEND | LOCK_EX);
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
			$db_create = "DROP TABLE {$db_table}; {$db_create}";
		}

		try {
			$db_handle->exec("BEGIN TRANSACTION;"
					. "{$db_create}"
					. "END TRANSACTION;");
		}
		catch (Exception $e) {
			@file_put_contents($pfb['errlog'], "\nDNSBL_SQL: Database failure - {$message}", FILE_APPEND | LOCK_EX);
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

	$datereq	= date('M j H:i:s', time());
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

		// Only collect lastevent entry
		if (empty($p_group)) {
			;
		}

		// Update lastevent entry
		else {
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


// Function to collect and update the Unbound Resolver query/pid entries into SQLite3 database
// Read logfile in realtime (livetail)
// Reference: http://stackoverflow.com/questions/3218895/php-how-to-read-a-file-live-that-is-constantly-being-written-to
function pfb_livetail($logfile, $mode) {
	global $pfb;

	if (!file_exists("{$logfile}")) {
		touch("{$logfile}");
	}

	$len		= @filesize("{$logfile}");	// Start at EOF
	$lastpos_old	= $pfb_output = '';

	if ($mode == 'view') {
		// Start at EOF ( - 15000)
		if ($len > 15000) {
			$lastpos = ($len - 15000);
		} else {
			$lastpos = 0;
		}
	}
	else {
		$lastpos = $len;
	}

	while (TRUE) {
		usleep(300000); //0.3s
		clearstatcache(FALSE, "{$logfile}");
		$len = @filesize("{$logfile}");

		if ($len < $lastpos) {
			$lastpos = $len;	// File deleted or reset
		}
		else {
			$f = @fopen("{$logfile}", 'rb+');
			if ($f === FALSE) {
				break;
			}
			@fseek($f, $lastpos);

			while (!feof($f)) {
				$pfb_buffer = @fread($f, 2048);
				$pfb_output .= str_replace( array ("\r", "\")"), '', $pfb_buffer);
				// Refresh on new lines only. This allows Scrolling.
				if ($lastpos != $lastpos_old) {
					pfbupdate_output($pfb_output);
				}
				$lastpos_old = $lastpos;
				ob_flush();
				flush();
			}

			$lastpos = @ftell($f);
			if ($f) {
				@fclose($f);
			}

			// Capture remaining output
			if ($mode != 'view' && strpos($pfb_output, 'UPDATE PROCESS ENDED') !== FALSE) {
				$f = @fopen($pfb['log'], 'rb');
				@fseek($f, $lastpos);
				$pfb_buffer = @fread($f, 2048);
				$pfb_output .= str_replace( "\r", '', $pfb_buffer);
				pfbupdate_output($pfb_output);
				clearstatcache(FALSE, $pfb['log']);
				ob_flush();
				flush();
				if ($f) {
					@fclose($f);
				}

				// Call log mgmt function
				pfb_log_mgmt();
				break;
			}
		}
	}
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

	if (isset($pfb['config_global']) &&
	    isset($pfb['config_global']['pfbpageload'])) {
		switch($pfb['config_global']['pfbpageload']) {
			case 'dnsbl_stat':
				return '?view=dnsbl_stat';
			case 'dnsbl_reply_stat':
				return '?view=dnsbl_reply_stat';
			case 'ip_block_stat':
				return '?view=ip_block_stat';
			case 'ip_permit_stat':
				return '?view=ip_permit_stat';
			case 'ip_match_stat':
				return '?view=ip_match_stat';
			case 'reply':
				return '?view=reply';
			case 'unified':
				return '?view=unified';
		}
	}
	return '';
}


// Clear IP Alias Packet Counts (widget)
function pfBlockerNG_clearip() {
	global $pfb;

	exec("{$pfb['pfctl']} -z 2>&1");

	/* TODO: Clear only pfB counters
	$pfb_tables = array();
	exec("{$pfb['pfctl']} -sTables | {$pfb['grep']} 'pfB_' 2>&1", $pfb_tables);
	if (!empty($pfb_tables)) {
		foreach ($pfb_tables as $table) {
			exec("{$pfb['pfctl']} -t {$table} -T zero");
		}
	}
	*/
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
		$lastipclear = date('M j H:i:s', time()); 
		$todo[] = array(6, 'Reset IP last clear timestamp', 'UPDATE lastclear SET lastipclear = :lastipclear WHERE row = 0;');
	}
	elseif ($mode == 'cleardnsbl') {
		$lastdnsblclear = date('M j H:i:s', time()); 
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
	unlink_if_exists("{$pfb['dnsbl_supptxt']}");
	unlink_if_exists("{$pfb['dnsbl_info']}");
	unlink_if_exists("{$pfb['dnsbl_resolver']}");
	unlink_if_exists("{$pfb['dnsbl_cache']}");
	unlink_if_exists("/var/tmp/unbound_cache_*");
	unlink_if_exists("{$pfb['asn_cache']}");
	unlink_if_exists("{$pfb['ip_cache']}");
	rmdir_recursive("{$pfb['origdir']}");
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
 * pfb_build_autorule_list() — pure emission helper extracted from sync_package_pfblockerng().
 *
 * Keeps all non-pfB rules verbatim (same set, count, and original relative order) and splices
 * the regenerated pfB rules at a single anchor determined by pass_order. No user rule is ever
 * bucketed, filtered, duplicated, split, or reordered — the only operations are "keep in place"
 * for user rules and "regenerate at anchor" for pfB rules.
 *
 * Anchor mapping (per-interface first-match semantics — ADR-41 Phase 2):
 *   order_1 / order_2           → pfB block AFTER kept user rules  (user pass wins)
 *   order_0 / order_3 / order_4 → pfB block BEFORE kept user rules (pfB wins)
 *   absent / unknown            → order_0 anchor / BEFORE           [subsumes #539]
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
 * @param ?string $order          The pass_order value ('order_0' .. 'order_4', or ''); null (the
 *                                unconfigured $pfb['order']) is coerced to '' (matches no order).
 * @param ?string $float          Float mode: 'on' or '' (off); null (the unconfigured
 *                                $pfb['float']) is coerced to '' (off).
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
	// $order/$float come straight from $pfb['order']/$pfb['float'], which are unset (null)
	// until configured. The original inline code used those raw values in loose comparisons
	// ('== on' / '== order_N'), where null simply matches nothing -- so a null is behaviour-
	// equivalent to ''. Coerce here (the params are nullable) rather than let a strict string
	// typehint TypeError on the null the call site legitimately passes (e.g. enable_float unset).
	$order = $order ?? '';
	$float = $float ?? '';

	// Step 1: build $keep — all non-pfB-owned rules in original order, alias-upgraded.
	// A rule is pfB-owned iff its descr starts with 'pfB_' AND it is NOT a bypass rule
	// (DNS-redirect / DoT-block bypass rules keep their pfB_ prefix but stay user-managed).
	$keep = [];
	foreach ($existing_rules as $rule) {
		$descr      = $rule['descr'] ?? '';
		$is_bypass  = str_starts_with($descr, PFB_DNS_REDIR_DESCR_V4_PFX) ||
		              str_starts_with($descr, PFB_DOT_BLOCK_DESCR_PFX);

		if (str_starts_with($descr, 'pfB_') && !$is_bypass) {
			continue;  // pfB-owned — will be regenerated below
		}

		// Upgrade previous IPv4 pfBlockerNG alias names to '_v4' suffix format.
		foreach (array('source', 'destination') as $rtype) {
			if (pfb_rule_alias_needs_v4_suffix($rule[$rtype]['address'] ?? '', $rule['ipprotocol'] ?? '')) {
				$rule[$rtype]['address'] = "{$rule[$rtype]['address']}_v4";
			}
		}

		$keep[] = $rule;
	}

	// Step 2: build the pfB block — same generation order as before (dnsbl_float first,
	// then per-inbound permit/match/deny, then per-outbound permit/match/deny).
	$pfb_block = [];

	// DNSBL floating pass rules (ping + permit pair, or empty) — emitted before interface rules.
	foreach ($pfb_generated['dnsbl_float'] as $cb_rules) {
		$pfb_block[] = $cb_rules;
	}

	// Inbound interface rules.
	$pfbrunonce = TRUE;
	foreach ($in_ifaces as $inbound_interface) {
		foreach ($pfb_generated['permit_inbound'] as $cb_rules) {
			$cb_rules['interface'] = $inbound_interface;
			$cb_rules['tracker']   = pfb_tracker($cb_rules['descr'], $inbound_interface, 'permit_in');
			$pfb_block[]           = $cb_rules;
		}
		// Match inbound rules are floating-only (emit once across all inbound interfaces).
		if ($pfbrunonce && !empty($pfb_generated['match_inbound'])) {
			foreach ($pfb_generated['match_inbound'] as $cb_rules) {
				$cb_rules['interface'] = $pfb_generated['inbound_floating'];
				$cb_rules['tracker']   = pfb_tracker($cb_rules['descr'], $inbound_interface, 'match_in');
				$pfb_block[]           = $cb_rules;
				$pfbrunonce            = FALSE;
			}
		}
		foreach ($pfb_generated['deny_inbound'] as $cb_rules) {
			$cb_rules['interface'] = $inbound_interface;
			$cb_rules['tracker']   = pfb_tracker($cb_rules['descr'], $inbound_interface, 'deny_in');
			$pfb_block[]           = $cb_rules;
		}
	}

	// Outbound interface rules.
	$pfbrunonce = TRUE;
	foreach ($out_ifaces as $outbound_interface) {
		foreach ($pfb_generated['permit_outbound'] as $cb_rules) {
			$cb_rules['interface'] = $outbound_interface;
			$cb_rules['tracker']   = pfb_tracker($cb_rules['descr'], $outbound_interface, 'permit_out');
			$pfb_block[]           = $cb_rules;
		}
		// Match outbound rules are floating-only (emit once across all outbound interfaces).
		if ($pfbrunonce && !empty($pfb_generated['match_outbound'])) {
			foreach ($pfb_generated['match_outbound'] as $cb_rules) {
				$cb_rules['interface'] = $pfb_generated['outbound_floating'];
				$cb_rules['tracker']   = pfb_tracker($cb_rules['descr'], $outbound_interface, 'match_out');
				$pfb_block[]           = $cb_rules;
				$pfbrunonce            = FALSE;
			}
		}
		foreach ($pfb_generated['deny_outbound'] as $cb_rules) {
			$cb_rules['interface'] = $outbound_interface;
			$cb_rules['tracker']   = pfb_tracker($cb_rules['descr'], $outbound_interface, 'deny_out');
			$pfb_block[]           = $cb_rules;
		}
	}

	// Step 3: splice at anchor.
	// order_1/order_2 → AFTER the kept user rules (user pass wins under per-iface first-match).
	// Everything else (order_0/3/4, absent, unknown) → BEFORE (pfB wins). Subsumes #539.
	if ($order === 'order_1' || $order === 'order_2') {
		return array_values(array_merge($keep, $pfb_block));
	}
	return array_values(array_merge($pfb_block, $keep));
}

// Main pfBlockerNG function
function sync_package_pfblockerng($cron='') {
	global $g, $pfb, $pfbarr;
	pfb_global();

	$pfb['filter_configure']	= FALSE;	// Flag to call filter_configure once

	// ADR-12 Phase 6: TWO pass-scoped accumulators of the names UPDATED this pass,
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
		pfb_logger("\n{$log}\nUPDATE PROCESS ENDED [ NOW ]\n", 1);
		logger(LOG_INFO, localize_text($log), LOG_PREFIX_PKG_PFBLOCKERNG);
		return;
	}

	// ADR-12: pre-update hooks. Fire at the TOP of the pass (after the boot/install
	// early-return above, before any feed processing). 'pre' cannot know what changed
	// yet -- nothing is downloaded -- so its context is just the trigger. No enabled
	// 'pre' hook => pfb_run_hooks() returns immediately (byte-identical pass).
	pfb_run_hooks('pre', array('TRIGGER' => pfb_hook_trigger($cron)));

	// Reloads existing lists without downloading new lists when defined 'on'
	$pfb['reuse'] = $pfb['config']['pfb_reuse'];
	$pfb['reuse_dnsbl'] = '';

	// Define update process (update or reload)
	switch ($cron) {
		case 'noupdates':
			// Force update - Set 'save' variable when 'No updates' found.
			$pfb['save'] = TRUE;
			break;
		case 'cron':
			if ($pfb['reuse'] == 'on') {
				$pfb['reuse_dnsbl'] = 'on';
				unlink_if_exists("{$pfb['dbdir']}/masterfile");
				unlink_if_exists("{$pfb['dbdir']}/mastercat");
			}
			break;
		case 'updatednsbl':
			$pfb['reuse'] = '';
			$pfb['reuse_dnsbl'] = 'on';
			$pfb['updatednsbl'] = TRUE;
			break;
		case 'updateip':
			$pfb['reuse'] = 'on';
			$pfb['reuse_dnsbl'] = '';
			unlink_if_exists("{$pfb['dbdir']}/masterfile");
			unlink_if_exists("{$pfb['dbdir']}/mastercat");
			break;
	}

	// Start of pfBlockerNG logging to 'pfblockerng.log'
	if ($pfb['enable'] == 'on' && !$pfb['save']) {
		$log = " UPDATE PROCESS START [ " . pfb_pkg_ver() . " ] [ NOW ]\n";
		pfb_logger("{$log}", 1);
	} else {
		if ($cron != 'noupdates') {
			$log = "\n**Saving configuration [ NOW ]**\n";
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
	$pfb['dnsbl_alexa_cnt']	= $pfb['dnsblconfig']['alexa_count']	?: '1000';		// TOP1M whitelist domain setting
	// DNSBL Python decision-cache cap (LRU); 0 = unlimited. 0 is meaningful so avoid the
	// ?: idiom (0 is falsy), and reject non-numeric input -- else the intval() at the ini
	// emit would coerce a malformed value to 0 = silently unlimited. Clamp to the WebUI range.
	$pfb_dcm_raw = (string) ($pfb['dnsblconfig']['pfb_py_cache_max'] ?? '');
	$pfb['dnsbl_decisiondb_max'] = ctype_digit($pfb_dcm_raw) ? (string) min(5000000, (int) $pfb_dcm_raw) : '10000';
	$pfb['dnsbl_alexa_inc']	= $pfb['dnsblconfig']['alexa_inclusion']?: '';			// TOP1M TLDs inclusions for whitelisting
	$pfb['dnsbl_tld']	= $pfb['dnsblconfig']['pfb_tld'];				// Enable TLD Function
	$pfb['dnsbl_control']	= $pfb['dnsblconfig']['pfb_control']	?: '';			// Python Control integration
	$pfb['dnsbl_control_legacy']	= $pfb['dnsblconfig']['pfb_control_legacy']	?? '';	// PFBL-03: deprecated legacy DNS-TXT control transport

	// Validate pfB Script variable
	$pfb['dnsbl_alexa_inc'] = pfb_filter($pfb['dnsbl_alexa_inc'], PFB_FILTER_CSV, 'Validate pfB Script variable');

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
	$pfbfound = FALSE;
	$pfb_suffix_match = '';
	foreach (config_get_path('filter/rule', []) as $rule) {

		// Query for previous IPv4 pfBlockerNG 'alias type' aliasnames which are not in the new '_v4' suffix format
		foreach (array('source', 'destination') as $rtype) {
			if (pfb_rule_alias_needs_v4_suffix($rule[$rtype]['address'] ?? '', $rule['ipprotocol'] ?? '')) {
				$pfb['autorules'] = TRUE;	// Set flag to re-configure Firewall rules and add missing '_v4' suffix
			}
		}

		// Collect any pre-existing suffix
		if (!empty($pfb_suffix_match) && preg_match('/^pfB_\w+(\s.*)/', $rule['descr'], $pfb_suffix_real)) {
			$pfb_suffix_match = $pfb_suffix_real[1];
		}
	}

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
			if ($pfb['dnsbl_alexa'] == 'on') {
				pfb_logger("\n Loading TOP1M Whitelist...", 1);

				// Check if TOP1M database exists
				if (!file_exists("{$pfb['dbdir']}/top-1m.csv")) {
					// Check if TOP1M download already in progress
					exec('/bin/ps -wax', $result_cron);
					if (!preg_grep("/pfblockerng[.]php\s+al/", $result_cron)) {
						$log = "\n TOP1M Database downloading ( approx 21MB ) ... Please wait ...\n";
						pfb_logger("{$log}", 1);
						exec('/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php al');
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
								foreach ($pfb_return as $key => $return_output) {

									pfb_logger("{$return_output}\n", 1);

									// On download failure, remove associated Blacklist category configuration
									if (strpos($return_output, 'Failed') !== FALSE) {
										unset($lists[$key]);
									}
								}
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

				if ($list['action'] != 'Disabled' && isset($list['row'])) {
					$alias				= "DNSBL_{$list['aliasname']}";
					if (empty(pfb_filter($alias, PFB_FILTER_WORD, 'DNSBL - Processes'))) {
						pfb_logger("\n Invalid Aliasname:{$list['aliasname']}, *skipping*", 1);
						continue;
					}
					$pfb['alias_dnsbl_all'][]	= "{$alias}";

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

							// ADR-31 P4: per-row action → manifest mode.
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
								$sinkhole_type4 = '0.0.0.0';
								$sinkhole_type6 = '::0';
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
								$sinkhole_type4 = "{$pfb['dnsbl_vip4']}";
								$sinkhole_type6 = "{$pfb['dnsbl_vip6']}";
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
									$log = "\n[ {$header} ]{$logtab} static hold. [ NOW ]";
								} else {
									$log = "\n[ {$header} ]{$logtab} exists. [ NOW ]";
								}
								pfb_logger("{$log}", 1);

								// Collect existing list stats
								$lists_dnsbl_all[]	= "{$row['header']}.txt";
								$lists_dnsbl_current[]	= "{$row['header']}";
								// ADR-07 P8: a reused feed isn't re-parsed, so read the
								// persisted '.abp' marker to carry its format_hint forward.
								// ADR-31 P3: delegate to pfb_feed_manifest_row() (deny default).
								// ADR-31 P4: pass $mode derived from per-row 'action' (above).
								$pfb_py_feeds[]		= pfb_feed_manifest_row(
									$header, $alias, $logging_type,
									file_exists("{$pfbfolder}/{$header}.abp") ? 'abp' : 'plain',
									$custom ? 'user' : 'feed',
									$mode);
								$file_esc		= escapeshellarg("{$pfbfolder}/{$header}.txt");
								$list_cnt		= exec("{$pfb['grep']} -c ^ {$file_esc}");
								$alias_cnt		= $alias_cnt + $list_cnt;
							}
							else {
								if ($pfbreuse == 'on' && file_exists("{$pfborig}/{$header}.orig")) {
									$log = "\n[ {$header} ]{$logtab} Reload [ NOW ]";
								} else {
									$log = "\n[ {$header} ]{$logtab} Downloading update [ NOW ]";
								}
								pfb_logger("{$log}", 1);
								$file_dwn = "{$pfborig}/{$header}";

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
											$row['format'], 1, '', '', '', '', '', $srcint)) {

											// Determine reason for download failure
											pfb_download_failure($alias, $header, $pfbfolder, $row['url'], $row['format'], '');

											// Utilize previously download file (If 'fail' marker exists)
											if (file_exists("{$pfbfolder}/{$header}.fail") &&
											    file_exists("{$file_dwn}.orig")) {
												pfb_logger("\n  Restoring previously downloaded file\n ", 2);
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

								// ADR-07 P8: ABP/EasyList feeds are header-sniffed (below) and
								// tagged format_hint='abp'; their RAW lines pass through to the
								// Python parser. The old PHP lite parser ($e_replace token-strip)
								// is deleted -- $easylist now only flags the feed as ABP.
								$easylist = $validate_header = FALSE;

								$run_once = $csv_parser = FALSE;
								$csv_type = '';
								$ipcount = $ip_cnt = $ip_cnt6 = 0;
								$pfb_scheme_skipped = 0;	// ADR-22: per-feed strict scheme/path skips

								// Parse downloaded file for Domain names
								if (($fhandle = @fopen("{$file_dwn}.orig", 'r')) !== FALSE) {
									if (($dhandle = @fopen("{$pfbfolder}/{$header}.bk", 'w')) !== FALSE) {
										while (($line = @fgets($fhandle)) !== FALSE) {

											// Collect original line
											$oline = $line;

											// Validate EasyList/AdBlock/uBlock/ADGuard Feeds.
											// ADR-21: broadened to the generic ABP header
											// convention ('[Adblock'/'[uBlock'/'! Title:'),
											// a superset of the four legacy magic strings.
											if (!$validate_header) {
												if (pfb_dnsbl_is_abp_header($line)) {
													$easylist = $validate_header = TRUE;
													continue;
												}
												elseif (str_starts_with($line, '!')) {
													continue;
												}
												else {
													$validate_header = TRUE;
												}
											}

											// Remove any '^M' characters
											if (strpos($line, "\r") !== FALSE) {
												$line = rtrim($line, "\x00..\x1F");
											}

											// Remove invalid charaters
											$line = trim($line, " \t\n\r\0\x0B\xC2\xA0");

											// ADR-21: ABP-anchored line in a non-ABP feed.
											// Captured BEFORE CSV autodetection and the
											// URL/path/'?'-query stripping below, which would
											// otherwise truncate '||domain/path^' or misparse a
											// comma-bearing ABP option line as CSV. '||'/'@@||'
											// are invalid in every plain dialect (pfb_filter()
											// would drop them), so write them VERBATIM to the
											// '.bk'/'.txt' staging file; the manifest builder
											// copies them to the '.raw' and Python's build()
											// routes them to parse_abp() (which returns None for
											// IP / path / wildcard anchors -> silently skipped).
											// $easylist feeds already pass ABP lines through
											// verbatim below, so this is for plain feeds only.
											if (!$easylist &&
											    (str_starts_with($line, '||') || str_starts_with($line, '@@||'))) {
												$domain_data = "{$line}\n";
												@fwrite($dhandle, $domain_data);
												continue;
											}

											if ($easylist) {
												// ADR-07 P8: the PHP $easylist lite parser is
												// DELETED. ABP feeds are tagged format_hint='abp'
												// and their RAW lines are passed through verbatim
												// to the Python parser (parse_abp), which is now
												// the one DNS-only ABP parser (@@/regex/$important/
												// $badfilter, not just ||domain^). PHP no longer
												// extracts domains from ABP feeds.
												//
												// DNSBL-IP coexistence (ADR-06 fact 7): the firewall
												// IP pass still runs over ABP feeds -- pull any
												// ABP-anchored / hosts IP (||1.2.3.4^, <ip> <ip>)
												// to DNSBLIP_v4/_v6; Python skips IP-valued anchors.
												if ($pfb['dnsbl_ip'] != 'Disabled') {
													$abp_ip = pfb_dnsbl_abp_extract_ip($line);
													if ($abp_ip !== '') {
														if (is_ipaddrv4($abp_ip)) {
															$parsed = sanitize_ipaddr($abp_ip, $custom, 'Disabled');
															if (validate_ipv4($parsed)) {
																$domain_data_ip[] = $parsed;
																$pfb['updateip'] = TRUE;
																$ipcount++;
															}
														}
														elseif (is_ipaddrv6($abp_ip) && validate_ipv6($abp_ip)) {
															$domain_data_ip6[] = $abp_ip;
															$pfb['updateip'] = TRUE;
															$ipcount++;
														}
														// IP -> firewall only; do not pass IP anchors
														// to Python (no double-handling, no leak).
														continue;
													}
												}

												// Skip ABP comment / control lines so the raw feed
												// passed to Python is dense (Python skips them too).
												if ($line === '' || str_starts_with($line, '!') ||
												    str_starts_with($line, '[')) {
													continue;
												}

												// Pass the RAW ABP line through to Python verbatim
												// (NO domain extraction). The manifest writer copies
												// 'abp' feed .txt lines into the per-feed raw as-is.
												@fwrite($dhandle, "{$line}\n");
												$domain_data = "{$line}\n";
												continue;
											}
											else {
												// If 'tab' character found, replace with whitespace
												if (strpos($line, "\x09") !== FALSE) {
													$line = str_replace("\x09", ' ', $line);
												}

												// If '%20' found, remove.
												if (strpos($line, '%20') !== FALSE) {
													$line = str_replace('%20', '', $line);
												}

												// Remove comment lines and special format considerations
												if (str_starts_with($line, '#')) {
													// Exit (hpHosts) when end of domain names found.
													if (strpos($line, 'Append critical updates below') !== FALSE) {
														break;
													}

													// Spamhaus format validation
													if (strpos($line, 'The Spamhaus Project Ltd') !== FALSE) {
														$rev_format = TRUE;
													}

													if ($line == '#family,type,url,status,first_seen,'
															. 'first_active,last_active,last_update') {
														$csv_type	= 'h3x';
														$csv_parser	= TRUE;
													}
													continue;
												}

												// Remove slash comment lines
												if (str_starts_with($line, '//')) {
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

															// Collect additional IP csv entry
															if (is_ipaddrv4($csvline[0]) &&
															    $pfb['dnsbl_ip'] != 'Disabled') {
																$parsed = sanitize_ipaddr($line, $custom, 'Disabled');
																if (validate_ipv4($parsed)) {
																	$domain_data_ip[] = $parsed;
																	$pfb['updateip'] = TRUE;
																	$ipcount++;
																}
															}
															// Collect additional IPv6 csv entry
															if (is_ipaddrv6($csvline[0]) &&
															    $pfb['dnsbl_ip'] != 'Disabled') {
																if (validate_ipv6($line)) {
																	$domain_data_ip6[] = $line;
																	$pfb['updateip'] = TRUE;
																	$ipcount++;
																}
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
													pfb_parsed_fail($header, '', $oline, $pfb['dnsbl_parse_err']);
													continue;
												}
											}
											$line = trim($line);

											if (!$easylist) {

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
													$pfb['dnsbl_parse_err'], $pfb_scheme_skipped);
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
											}
											$line = trim($line);

											// Collect any IPs found in domain feed
											if (is_ipaddrv4($line)) {
												if ($pfb['dnsbl_ip'] != 'Disabled') {
													$parsed = sanitize_ipaddr($line, $custom, 'Disabled');
													if (validate_ipv4($parsed)) {
														$domain_data_ip[] = $parsed;
														$pfb['updateip'] = TRUE;
														$ipcount++;
													}
												}
												continue;
											}
											// Collect any IPv6 IPs found in domain feed
											if (is_ipaddrv6($line)) {
												if ($pfb['dnsbl_ip'] != 'Disabled') {
													if (validate_ipv6($line)) {
														$domain_data_ip6[] = $line;
														$pfb['updateip'] = TRUE;
														$ipcount++;
													}
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
													pfb_parsed_fail($header, '', $oline, $pfb['dnsbl_parse_err']);
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
													pfb_parsed_fail($header, $line, $oline, $pfb['dnsbl_parse_err']);
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

									pfb_logger(".\n", 1);

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
									$ts = date('M_j', time());
									@copy("{$file_dwn}.orig", "/tmp/Error_{$header}_{$ts}.orig");

									unlink_if_exists("{$pfbfolder}/{$header}.bk");
									$result = array('unbound-checkconf: no errors');
								}

								// If parse error found, use previously downloaded file if available


								// Save DNSBL feed info for next steps
								$pfb['domain_update']	= $pfb['aliasupdate'] = $pfb['summary'] = TRUE;
								$lists_dnsbl_all[]	= "{$row['header']}.txt";
								$lists_dnsbl_current[]	= "{$row['header']}";
								// ADR-07 P8: tag ABP feeds 'abp' so the manifest writer passes
								// their RAW lines through to the Python parser (parse_abp); all
								// other feeds stay 'plain' (PHP-extracted bare domains).
								// ADR-31 P3: delegate to pfb_feed_manifest_row() (deny default).
								// ADR-31 P4: pass $mode derived from per-row 'action' (above).
								$pfb_py_feeds[]		= pfb_feed_manifest_row(
									$header, $alias, $logging_type,
									$easylist ? 'abp' : 'plain',
									$custom ? 'user' : 'feed',
									$mode);

								// ADR-07 P8: persist the ABP marker so a future reuse build (which
								// does not re-parse the feed) carries the format_hint forward.
								if ($easylist) {
									@touch("{$pfbfolder}/{$header}.abp");
								} else {
									unlink_if_exists("{$pfbfolder}/{$header}.abp");
								}

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

								// Remove update file indicator
								unlink_if_exists("{$pfbfolder}/{$header}.update");
							}
						}
					}

					// ADR-12 Phase 6: record GENUINELY-changed DNSBL groups for
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
		// ADR-07 P8: the DNSBL_Regex alias count now reflects the ADMITTED
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

	// Collect all DNSBL IP feeds (IPv4 only) into DNSBLIP_v4.txt
	if ($pfb['dnsbl_ip'] != 'Disabled' && ($pfb['updateip'] || !file_exists("{$pfb['dbdir']}/DNSBLIP_v4.txt"))) {

		$dnsbl_ip = glob("{$pfb['dnsdir']}/*_v4.ip");
		if (!empty($dnsbl_ip)) {
			$pfb_ips = @fopen("{$pfb['dbdir']}/DNSBLIP_v4.txt", 'w');
			foreach ($dnsbl_ip as $d_ip) {
				if (($handle = @fopen("{$d_ip}", 'r')) !== FALSE) {
					while (($line = @fgets($handle)) !== FALSE) {
						@fwrite($pfb_ips, $line);
					}
				}
				if ($handle) {
					@fclose($handle);
				}
			}
			if ($pfb_ips) {
				@fclose($pfb_ips);
			}
		}

		// Add empty placeholder IP
		else {
			@file_put_contents("{$pfb['dbdir']}/DNSBLIP_v4.txt", "{$pfb['ip_ph']}\n", LOCK_EX);
		}
		unlink_if_exists($pfb['ip_cache']);
		touch("{$pfb['denydir']}/DNSBLIP_v4.update");
	}

	// Remove DNSBL IP feed, if disabled
	if ($pfb['dnsbl_ip'] == 'Disabled') {
		unlink_if_exists("{$pfb['dbdir']}/DNSBLIP_v4.txt");
		unlink_if_exists("{$pfb['denydir']}/DNSBLIP_v4.*");
	}

	// Collect all DNSBL IP feeds (IPv6 only) into DNSBLIP_v6.txt
	if ($pfb['dnsbl_ip'] != 'Disabled' && ($pfb['updateip'] || !file_exists("{$pfb['dbdir']}/DNSBLIP_v6.txt"))) {

		$dnsbl_ip = glob("{$pfb['dnsdir']}/*_v6.ip");
		if (!empty($dnsbl_ip)) {
			$pfb_ips = @fopen("{$pfb['dbdir']}/DNSBLIP_v6.txt", 'w');
			foreach ($dnsbl_ip as $d_ip) {
				if (($handle = @fopen("{$d_ip}", 'r')) !== FALSE) {
					while (($line = @fgets($handle)) !== FALSE) {
						@fwrite($pfb_ips, $line);
					}
				}
				if ($handle) {
					@fclose($handle);
				}
			}
			if ($pfb_ips) {
				@fclose($pfb_ips);
			}
		}

		// Add empty placeholder IP
		else {
			@file_put_contents("{$pfb['dbdir']}/DNSBLIP_v6.txt", "::{$pfb['ip_ph']}\n", LOCK_EX);
		}
		unlink_if_exists($pfb['ip_cache']);
		touch("{$pfb['denydir']}/DNSBLIP_v6.update");
	}

	// Remove DNSBL IP feed, if disabled
	if ($pfb['dnsbl_ip'] == 'Disabled') {
		unlink_if_exists("{$pfb['dbdir']}/DNSBLIP_v6.txt");
		unlink_if_exists("{$pfb['denydir']}/DNSBLIP_v6.*");
	}

	#########################################
	#	UPDATE Unbound DNS Database	#
	#########################################

	if ($pfb['domain_update']) {
		if (!empty($lists_dnsbl_all)) {
			pfb_logger("\n------------------------------------------------------------------------\n", 1);

			pfb_logger('Assembling DNSBL database...', 1);
			unlink_if_exists("{$pfb['dnsbl_file']}.raw");
			$pfb_output = @fopen("{$pfb['dnsbl_file']}.raw", 'w');
			foreach ($lists_dnsbl_all as $current_list) {
				if (($handle = @fopen("{$pfb['dnsdir']}/{$current_list}", 'r')) !== FALSE) {
					while (($line = @fgets($handle)) !== FALSE) {
						@fwrite($pfb_output, $line);
					}
				}
				if ($handle) {
					@fclose($handle);
				}
			}
			if ($pfb_output) {
				@fclose($pfb_output);
			}
			pfb_logger("... completed [ NOW ]", 1);

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
				unlink_if_exists($pfb['unbound_py_regex_count']);		// ADR-07 P8
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
		$redir_enabled = (($mode ?? '') === 'enabled') && ($redir_toggle instanceof PfbToggle && $redir_toggle === PfbToggle::On);

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

				// Build new NAT rdr rules for each interface × family.
				$redir_new_owned = [];
				foreach ($redir_ifaces as $redir_iface) {
					foreach (['inet', 'inet6'] as $redir_family) {
						$redir_sfx    = ($redir_family === 'inet') ? PFB_DNS_REDIR_DESCR_V4_SFX : PFB_DNS_REDIR_DESCR_V6_SFX;
						$redir_target = ($redir_family === 'inet') ? '127.0.0.1' : '::1';
						$redir_descr  = PFB_DNS_REDIR_DESCR_V4_PFX . $redir_iface . $redir_sfx;
						$redir_source = ($redir_exception !== '')
							? ['address' => $redir_exception, 'not' => '']
							: ['any' => ''];
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
		$dot_enabled = (($mode ?? '') === 'enabled') && ($dot_toggle instanceof PfbToggle && $dot_toggle === PfbToggle::On);

		if (!$dot_enabled) {
			// DISABLED: remove all pfB_DoT_Block_* filter rules.
			if (pfb_remove_managed_obj('filter/rule', PFB_DOT_BLOCK_DESCR_PFX)) {
				$dot_changed = TRUE;
			}
		} else {
			// ENABLED: read interfaces (comma-separated), exception alias, rule action.
			$dot_iface_raw    = (string) PfbConfig::read('dnsbl_dot_block_int');
			$dot_exclude_alias = trim((string) PfbConfig::read('dnsbl_dot_block_exclude'));
			$dot_action       = pfb_dot_block_action((string) PfbConfig::read('dnsbl_dot_block_action'));

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
				// Build the expected marker set for the current iface set.
				$dot_expected_descrs = [];
				foreach ($dot_ifaces as $dot_iface) {
					$dot_expected_descrs[] = PFB_DOT_BLOCK_DESCR_PFX . $dot_iface;
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

				// Build new DoT/DoQ block filter rules for each interface. The rule
				// shape (incl. the configurable block/reject disposition) is built by
				// pfb_dot_block_rule(); the deterministic tracker is appended here
				// (last key) so the change-detection compare below stays stable.
				$dot_new_owned = [];
				foreach ($dot_ifaces as $dot_iface) {
					$dot_descr = PFB_DOT_BLOCK_DESCR_PFX . $dot_iface;
					$dot_rule  = pfb_dot_block_rule($dot_iface, $dot_exclude_alias, $dot_action);
					$dot_rule['tracker'] = $dot_existing_trackers[$dot_descr] ?? (string) pfb_managed_rule_tracker($dot_descr);
					$dot_new_owned[] = $dot_rule;
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
	// by the Force-Reload-DNSBL path (see the $cron switch).
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
						$pfctlck = trim(exec_command(implode(' ', [
							$pfb['pfctl'], '-t',
							$cc_alias,
							'-Tshow', '|', $pfb['wc'], '-l'
						])));

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
								$log = "\n[ {$cc_alias} ]{$logtab} exists. [ NOW ]";
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

									// Call Duplication process
									if ($pfb['dup'] == 'on' && $vtype == '_v4' && $pfbadv) {
										exec("{$pfb['script']} continent {$cc_alias} {$elog}");
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

								if ($file_chk <= 1) {
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
							$list_type = "{$ip_type}";
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
								$log = "\n[ {$header} ]{$logtab} static hold. [ NOW ]";
							} else {
								$log = "\n[ {$header} ]{$logtab} exists. [ NOW ]";
							}
							pfb_logger("{$log}", 1);
						}
						else {
							if ($pfbreuse == 'on' && file_exists("{$pfborig}/{$header}.orig")) {
								$log = "\n[ {$header} ]{$logtab} Reload [ NOW ]";
							} else {
								$log = "\n[ {$header} ]{$logtab} Downloading update [ NOW ]";
							}
							pfb_logger("{$log}", 1);
							$file_dwn = "{$pfborig}/{$header}";

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
								if ($pfbreuse == 'on' && file_exists("{$file_dwn}.orig")) {
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
										1, $list['vtype'], '', '', '', '', $srcint)) {

										// Determine reason for download failure
										pfb_download_failure($alias, $header, $pfbfolder, $row['url'], $row['format'], $list['vtype']);

										// Utilize previously download file (If 'fail' marker exists)
										if (file_exists("{$pfbfolder}/{$header}.fail") &&
										    file_exists("{$file_dwn}.orig")) {
											pfb_logger("\n  Restoring previously downloaded file contents...", 2);
										}
										else {
											if ($pfbadv) {
												// Script to Remove failed lists from masterfile
												exec("{$pfb['script']} remove x x x {$header_esc} {$elog}");
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
									// Record original line for regex matching, if required.
									$oline = $line;

									// Remove any leading/trailing whitespaces
									$line = trim($line);

									// Remove commentlines and blank lines
									if (str_starts_with($line, '#') || empty($line)) {
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
													$parsed = sanitize_ipaddr_v6($line, $custom);
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
																$parsed = sanitize_ipaddr_v6($cidr, $custom);
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
														$parsed = sanitize_ipaddr_v6($match, $custom);
														if (!empty($parsed)) {
															$ip_data .= $parsed . "\n";
														}
														else {
															$ip_suppressed = TRUE;
														}
													}
												}
											}
										}
									}
								}

								// Check for parse failures
								if (!empty($line) && !preg_match('/[a-zA-Z,;|\"\'?]/', $line)) {
									$parse_fail++;
									$log = "[!] Parse Errors [ {$parse_fail} ]\n";
									pfb_logger("{$log}", 2);
								}
							}
							if ($fhandle) {
								@fclose($fhandle);
							}
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
									$args = '';
									// Call Process255
									if ($pfb['dup'] == 'on' || $pfb['agg'] == 'on') {
										$args  = '_255';
									}
									// Call Aggregate process
									if ($pfb['agg'] == 'on') {
										$args .= '_agg';
									}
									// Call Reputation Max process
									if ($pfb['rep'] == 'on') {
										$args .= '_rep';
									}
									// Call Duplication process
									if ($pfb['dup'] == 'on') {
										$args .= '_dup';
									}
									if (!empty($args)) {
										exec("{$pfb['script']} {$args} {$header_esc} {$pfb['max']} {$pfb['drep']} {$pfb['ccexclude']} {$pfb['ccwhite']} {$pfb['ccblack']} {$elog}");
									}
								}

								if (!$pfbadv && $list['vtype'] == '_v4') {
									// Call Aggregate process
									if ($pfb['agg'] == 'on') {
										exec("{$pfb['script']} cidr_aggregate {$header_esc} {$pfbfolder} {$elog}");
									}
								}

								// Collect updated alias lists ('Reputation' disabled)
								$pfb_alias_lists[] = "{$alias}";

								if ($pfbadv && $list['vtype'] == '_v4') {
									// Execute Reputation functions, when changes are found.
									$pfb['repcheck'] = TRUE;

									// Enable suppression process due to updates
									if ($pfb['supp'] == 'on') {
										$pfb['supp_update'] = TRUE;
									}
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

							// Remove update file indicator
							unlink_if_exists("{$pfbfolder}/{$header}.update");

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
			}
		}
	}

	// Remove database update file markers
	unlink_if_exists("{$pfb['dbdir']}/geoip.update");
	unlink_if_exists("{$pfb['dbdir']}/asn.update");

	#################################
	#	REPUTATION PROCESSES	#
	#################################

	// IP Reputation processes (pMax and dMax)
	if ($pfb['prep'] == 'on' && $pfb['repcheck'] && !$pfb['save'] && $pfb['enable'] == 'on') {
		// Script to run prep process
		exec("{$pfb['script']} pmax x {$pfb['pmax']} {$elog}");
	}
	if ($pfb['drep'] == 'on' && $pfb['repcheck'] && !$pfb['save'] && $pfb['enable'] == 'on') {
		// Script to run drep process
		exec("{$pfb['script']} dmax x {$pfb['dmax']} {$pfb['drep']} {$pfb['ccexclude']} {$pfb['ccwhite']} {$pfb['ccblack']} {$elog}");
	}

	#################################################
	#	CONFIGURE ALIASES AND FIREWALL RULES	#
	#################################################

	// ADR-40 P3: Snapshot the feed-changed set (populated by the download loop above)
	// before the file-write loop.  The file-write loop will rebuild $pfb_alias_lists
	// as the content-diff set (aliases whose canonical membership set actually changed),
	// which is what the pfctl regions and ADR-12 emit consume.
	// $pfb_feed_changed: input to the hybrid scope gate; keeps the suppression sub-process
	// and "read member files" decision anchored to feed-changed aliases.
	$pfb_feed_changed    = $pfb_alias_lists;
	$pfb_alias_lists     = array();   // reset: refilled below with content-validated aliases
	// ADR-40 P4: per-alias map from alias name -> previous canonical set (what was in the
	// mirror BEFORE this pass wrote the new one).  Captured in the write loop (below) so the
	// no-rule-change reload site can compute add/del deltas without a second file read.
	$pfb_alias_prev_sets = array();

	// ADR-40 P3: hoist cross-list scope and feed-changed alias selection here — both
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
				$alias_esc = escapeshellarg($alias);

				// Skip any Alias that are 'enabled' but Lists/customlists are not defined.
				if (empty($list['row'][0]['url']) && empty($list['custom'])) {
					exec("{$pfb['pfctl']} -t {$alias_esc} -T kill 2>&1", $result);
					continue;
				}

				if (isset($list['dnsblip'])) {
					$list_type = 'pfblockerngdnsblsettings';
				} else {
					$list_type = "{$ip_type}";
				}

				// Determine 'list' details (return array $pfbarr)
				pfb_determine_list_detail($list['action'], '', $list_type, $key);
				$pfbadv		= $pfbarr['adv'];
				$pfbdescr	= $pfbarr['descr'];
				$pfbfolder	= $pfbarr['folder'];

				// ADR-40 P3: Content-addressed reload gate (hybrid scope).
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

								$pfctlck = trim(exec_command(implode(' ', [
									$pfb['pfctl'], '-t',
									$alias_esc,
									'-Tshow', '|', $pfb['wc'], '-l'
								])));

								// ADR-40 P3: read member files when:
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
									// Script to run suppression process (body) — only for feed-changed aliases.
									if ($pfb['supp'] == 'on' && $vtype == '_v4' && $pfb['supp_update'] && $pfbadv
									    && in_array($alias, $final_alias_old)) {
										if ($pfb['dup'] == 'on') {
											exec("{$pfb['script']} suppress {$header_esc} {$pfbfolder} on {$elog}");
										} else {
											exec("{$pfb['script']} suppress {$header_esc} {$pfbfolder} off {$elog}");
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
					$alias_esc = escapeshellarg($alias);
					$pfctlck = trim(exec_command(implode(' ', [
						$pfb['pfctl'], '-t',
						$alias_esc,
						'-Tshow', '|', $pfb['wc'], '-l'
					])));
					if (!empty($list['custom'])) {
						$urlvalue .= "{$aliasname},";
						// ADR-40 P3: same scope logic for custom lists.
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
						// ADR-40 P3: Compute the canonical set from the raw concat, compare
						// against the last-applied mirror (the existing aliasdir file), and write
						// only when the set changed.  This replaces the old pfbupdate flag write
						// (which wrote on every feed-fetch) with a content-addressed gate.
						if ($pfbupdate) {
							$alias_mirror  = "{$pfb['aliasdir']}/{$alias}.txt";
							$canonical_set = pfb_canonical_alias_set($alias_ips);
							if (pfb_alias_set_different($canonical_set, $alias_mirror) || empty($pfctlck)) {
								// ADR-40 P4: capture the previous canonical set before overwriting
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
			# NOTE (ADR-41): the 4-column interleaving above is the ORIGINAL strip-and-rebuild
			# intent. pfb_build_autorule_list() now keeps user rules IMMUTABLE and reduces this to a
			# BINARY anchor for the contiguous pfB block:
			#   order_1 / order_2        -> pfB block AFTER  the kept user rules (user pass wins)
			#   order_0 / 3 / 4 / absent -> pfB block BEFORE the kept user rules (pfB wins)
			# The pfB-p/m-vs-pfSense-p/m distinction is moot under per-interface first-match pf
			# (interface rules are always `quick`; proven live in ADR-41 Phase 2 -> RESULTS/02), so
			# it is no longer reproduced. order_4 no longer reorders the user's own rules.

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
		}

		exec("{$pfb['pfctl']} -s Tables | {$pfb['grep']} '^pfB_'", $pfb_tables);
		if (isset($pfb_tables)) {
			// ADR-40 P3: $pfb_alias_lists is the content-diff set (aliases whose
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
				$pfb_table_esc      = escapeshellarg($pfb_table);
				$pfb_table_path_esc = escapeshellarg("{$pfb['aliasdir']}/{$pfb_table}.txt");
				if (in_array($pfb_table, $pfb_active_aliases)) {
					if (in_array($pfb_table, $final_alias)) {
						// Active + changed: full -T replace so the kernel table is in sync
						// before filter_configure() rebuilds the ruleset from the aliasdir file.
						exec("{$pfb['pfctl']} -t {$pfb_table_esc} -T replace -f {$pfb_table_path_esc} 2>&1", $result);
					}
				} else {
					// Remove inactive pfB aliastables
					exec("{$pfb['pfctl']} -t {$pfb_table_esc} -T kill 2>&1", $result);
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
				// ADR-40 P3: ip_unlock forces a re-block of all active aliases (the previously
				// unlocked IP must be re-added to every alias it belongs to).  With content
				// gating, $pfb_alias_lists may be empty (if no feed changed this pass), so
				// explicitly add all active aliases to the reload set here — same as the old
				// $pfb_alias_lists_all widening via repcheck, but explicit (#519 contract).
				$pfb_alias_lists = array_unique(array_merge($pfb_alias_lists, $pfb_alias_lists_all));
			}

			// ADR-40 P3/P4: $pfb_alias_lists is the content-diff set — aliases whose
			// canonical membership set changed this pass (or ip_unlock forced a re-block).
			// P4: apply each changed alias via forward delta (or replace per mode/churn).
			$final_alias = array_unique($pfb_alias_lists);

			if (!empty($final_alias)) {
				// ADR-40 P4: read mode/batch once for the loop (PfbConfig gateway).
				$pfb_delta_mode  = (string) PfbConfig::read('pfb_alias_delta_mode')->toStored();
				$pfb_delta_batch = pfb_alias_delta_batch_clamp((string) PfbConfig::read('pfb_alias_delta_batch'));

				foreach ($final_alias as $final) {
					$log = "\n Updating: {$final}\n";
					pfb_logger("{$log}", 1);
					if (file_exists("{$pfb['aliasdir']}/{$final}.txt")) {
						// ADR-40 P4: compute delta from the stashed previous canonical set.
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
						$log = '';
					} else {
						$log = "Aliastable file not found\n";
					}
					pfb_logger("{$log}", 1);
				}
				pfb_logger("\n", 1);
				unset($pfb_delta_mode, $pfb_delta_batch, $desired, $previous, $mirror_path, $force_rpl);

				// Call function for Ramdisk processes.
				pfb_aliastables('update');
			} else {
				$log = "No Changes to Aliases, Skipping pfctl Update\n";
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

	// Replace CRON job with any user changes to $pfb_min
	if ($pfb['enable'] == 'on' && $pfb['interval'] != 'Disabled') {
		// Define pfBlockerNG CRON job
		$pfb_cmd = "/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php cron >> {$pfb['log']} 2>&1";
		// $pfb['min'] ( User defined variable. Variable defined at start of script )

		// Define CRON hour (CRON interval & start hour)
		if ($pfb['interval'] == 1) {
			$pfb_hour = '*';
		} elseif ($pfb['interval'] == 24) {
			$pfb_hour = $pfb['24hour'];
		} else {
			$pfb_hour = implode(',', pfb_cron_base_hour($pfb['interval']));
		}

		if ($pfb_hour == 0 || !empty(pfb_filter($pfb_hour, PFB_FILTER_CSV_CRON, 'Define pfBlockerNG CRON job'))) {
			$pfb_mday	= '*';
			$pfb_month	= '*';
			$pfb_wday	= '*';
			$pfb_who	= 'root';

			// Determine if CRON job requires updating
			if (!pfblockerng_cron_exists($pfb_cmd, $pfb['min'], $pfb_hour, $pfb_mday, $pfb_wday)) {
				install_cron_job('pfblockerng.php cron', FALSE);
				install_cron_job($pfb_cmd, TRUE, $pfb['min'], $pfb_hour, $pfb_mday, $pfb_month, $pfb_wday, $pfb_who);
			}
		}
		else {
			pfb_logger("\n Failed to create pfBlockerNG cron task [{$pfb_hour}]", 1);
		}
	}
	else {
		// Clear any existing pfBlockerNG CRON jobs
		install_cron_job('pfblockerng.php cron', FALSE);
	}

	// Define pfBlockerNG MaxMind/TOP1M/ASN Cron job
	if ($pfb['enable'] == 'on') {
		$pfb_gcmd = "/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php dcc >> {$pfb['extraslog']} 2>&1";
		// CRON hour is randomized between 0-23 Hour to minimize effect on Servers
		$pfb_gmin	= '0';
		$pfb_ghour	= rand(0,23);
		$pfb_gmday	= '*';
		$pfb_gmonth	= '*';
		$pfb_gwday	= '*';
		$pfb_gwho	= 'root';

		// Determine if CRON job requires updating
		if (!pfblockerng_cron_exists($pfb_gcmd, $pfb_gmin, 'random', $pfb_gmday, $pfb_gwday)) {
			install_cron_job('pfblockerng.php dcc', FALSE);
			install_cron_job($pfb_gcmd, TRUE, $pfb_gmin, $pfb_ghour, $pfb_gmday, $pfb_gmonth, $pfb_gwday, $pfb_gwho);
		}
	}
	else {
		// Clear any existing pfBlockerNG CRON jobs
		install_cron_job('pfblockerng.php dcc', FALSE);
	}

	// Define pfBlockerNG SafeSearch CNAME fallback freshness cron (issue #149).
	// The SafeSearch CNAMEs (duckduckgo/pixabay) are redirected in Python; their
	// baked #2-fallback IPs can drift between full DNSBL rebuilds, so this light
	// job re-resolves them every 15 minutes and reloads only on change. Installed
	// only while SafeSearch is enabled (the only source of CNAME entries).
	if ($pfb['enable'] == 'on' && $pfb['safesearch_enable'] !== 'Disable') {
		$pfb_sscmd	= "/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php ss_refresh >> {$pfb['log']} 2>&1";
		$pfb_ssmin	= '*/15';
		$pfb_sshour	= '*';
		$pfb_ssmday	= '*';
		$pfb_ssmonth	= '*';
		$pfb_sswday	= '*';
		$pfb_sswho	= 'root';

		if (!pfblockerng_cron_exists($pfb_sscmd, $pfb_ssmin, $pfb_sshour, $pfb_ssmday, $pfb_sswday)) {
			install_cron_job('pfblockerng.php ss_refresh', FALSE);
			install_cron_job($pfb_sscmd, TRUE, $pfb_ssmin, $pfb_sshour, $pfb_ssmday, $pfb_ssmonth, $pfb_sswday, $pfb_sswho);
		}
	}
	else {
		// Clear the SafeSearch freshness CRON job when SafeSearch is disabled
		install_cron_job('pfblockerng.php ss_refresh', FALSE);
	}


	// Define pfBlockerNG Blacklist CRON job
	if ($pfb['enable'] == 'on' && $pfb['dnsbl'] == 'on' && $pfb['blconfig'] &&
	    $pfb['blconfig']['blacklist_enable'] != 'Disable' &&
	    $pfb['blconfig']['blacklist_freq'] != 'Never' &&
	    !empty($pfb['blconfig']['blacklist_selected']) &&
	    isset($pfb['blconfig']['item'])) {

		$bl_string = '';
		$selected = array_flip(explode(',', $pfb['blconfig']['blacklist_selected'])) ?: array();
		foreach ($pfb['blconfig']['item'] as $item) {
			if (isset($selected[$item['xml']]) && !empty($item['selected'])) {
				$bl_string .= ",{$item['xml']}";
			}
		}
		$bl_string = pfb_filter(ltrim($bl_string, ','), PFB_FILTER_CSV, 'Define pfBlockerNG Blacklist CRON job');

		if (!empty($bl_string)) {
			$pfb_bcmd = "/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php bl {$bl_string} >> {$pfb['extraslog']} 2>&1";

			$pfb_bmin	= '0';
			$pfb_bhour	= rand(0,23);
			$pfb_bmday	= '*';
			$pfb_bmonth	= '*';
			$pfb_bwday	= ($pfb['blconfig']['blacklist_freq'] == 'Weekly' ? '7' : '*');
			$pfb_bwho	= 'root';

			// Determine if CRON job requires updating
			if (!pfblockerng_cron_exists($pfb_bcmd, $pfb_bmin, 'random', $pfb_bmday, $pfb_bwday)) {
				install_cron_job('pfblockerng.php bl', FALSE);
				install_cron_job($pfb_bcmd, TRUE, $pfb_bmin, $pfb_bhour, $pfb_bmday, $pfb_bmonth, $pfb_bwday, $pfb_bwho);
			}
		}
		else {
			pfb_logger("\n Failed to create pfBlockerNG Blacklist cron task [{$bl_string}]", 1);
		}
	}
	else {
		// Clear any existing pfBlockerNG Blacklist CRON jobs
		install_cron_job('pfblockerng.php bl', FALSE);
	}

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
		// Script to run final script processes.
		if ($pfb['dup'] == 'on') {
			exec("{$pfb['script']} closing on {$elog}");
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
	//   PFB_TRIGGER       = pfb_hook_trigger($cron).
	//   PFB_CHANGED_IP_ALIASES = the space-separated list of IP firewall aliases UPDATED
	//       this pass (ADR-12 Phase 6) = $pfb_alias_lists (the content-diff set --
	//       pfB_*_v4/_v6 whose canonical membership set actually changed this pass,
	//       as determined by pfb_alias_set_different(); ADR-40 P3).  Reputation/dedup
	//       no longer inflate this to all active aliases -- only moved tables appear here.
	//       The IP locals are in scope only at this tail, so they are merged into
	//       $pfb['changed_ip_aliases'] here, then de-duped at emit.
	//   PFB_CHANGED_DNSBL_GROUPS = the space-separated list of DNSBL groups UPDATED this
	//       pass (ADR-12 Phase 6) = the DNSBL_<group> names appended in the per-group
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
		'TRIGGER'		=> pfb_hook_trigger($cron),
		'IP_CHANGED'		=> (!empty($pfb['filter_configure']) || !empty($pfb_ip_unlock_forced)) ? '1' : '0',
		'DNSBL_CHANGED'		=> (!empty($pfb_data_changed) || !empty($pfbupdate) || !empty($pfbpython) ||
						!empty($safesearch_update) || !empty($pfb_dnsbl_unlock_forced)) ? '1' : '0',
		'STATUS'		=> 'ok',
		'CHANGED_IP_ALIASES'	=> implode(' ', array_unique($pfb['changed_ip_aliases'])),
		'CHANGED_DNSBL_GROUPS'	=> implode(' ', array_unique($pfb['changed_dnsbl_groups'])),
	));

	// Terminal marker -- emitted AFTER the post-update hooks so it is genuinely the
	// last line of the update log. The Update-page live tail (pfb_livetail) stops on
	// this marker; emitting it before the hooks truncated their progressive output
	// from the live view (e.g. a HAProxy reload hook running up to its timeout) -- it
	// then only reappeared on a manual 'View'.
	if ($pfb['enable'] == 'on' && !$pfb['save'] || $pfb['summary']) {
		pfb_logger("\n UPDATE PROCESS ENDED [ NOW ]\n", 1);
	}
}


// Function to De-Install pfBlockerNG
function pfblockerng_php_pre_deinstall_command() {
	require_once('config.inc');
	global $g, $pfb;

	// Set these two variables to disable pfBlockerNG on de-install
	$pfb['save'] = $pfb['install'] = TRUE;

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
			$pfb_table_esc = escapeshellarg($pfb_table);
			exec("{$pfb['pfctl']} -t {$pfb_table_esc} -T kill 2>&1", $result);
		}
	}

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


/* Do the actual XMLRPC sync */
function pfblockerng_do_xmlrpc_sync($sync_to_ip, $port, $protocol, $username, $password, $synctimeout) {
	global $g;
	$success = TRUE;

	// Take care of IPv6 literal address
	if (is_ipaddrv6($sync_to_ip)) {
		$sync_to_ip = "[{$sync_to_ip}]";
	}

	$sections = [];

	// If User Disabled, remove 'General/IP/DNSBL Tab Customizations' from Sync
	if (config_get_path('installedpackages/pfblockerngsync/config/0/syncinterfaces') != 'on') {
		$sections = array_merge($sections, [
			'pfblockerng',
			'pfblockerngipsettings',
			'pfblockerngdnsblsettings'
		]);
	}
	$sections = array_merge($sections, [
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
	if (config_get_path('installedpackages/pfblockerngsync/config/0/syncinterfaces') != 'on') {
		$section_paths_temp = array_merge($section_paths_temp, [
			'installedpackages/pfblockerng',
			'installedpackages/pfblockerngipsettings',
			'installedpackages/pfblockerngdnsblsettings'
		]);
	}
	$section_paths_temp = array_merge($section_paths_temp, [
		'installedpackages/pfblockernglistsv4',
		'installedpackages/pfblockernglistsv6',
		'installedpackages/pfblockerngreputation',
		'installedpackages/pfblockerngtopspammers',
		'installedpackages/pfblockerngafrica',
		'installedpackages/pfblockerngantarctica',
		'installedpackages/pfblockerngasia',
		'installedpackages/pfblockerngeurope',
		'installedpackages/pfblockerngnorthamerica',
		'installedpackages/pfblockerngoceania',
		'installedpackages/pfblockerngsouthamerica',
		'installedpackages/pfblockerngproxyandsatellite',
		'installedpackages/pfblockerngdnsbl',
		'installedpackages/pfblockerngblacklist',
		'installedpackages/pfblockerngglobal',
		'installedpackages/pfblockerngsafesearch'
	]);

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

	$section_paths = [
		'installedpackages/pfblockerng',
		'installedpackages/pfblockerngipsettings',
		'installedpackages/pfblockerngdnsblsettings',
		'installedpackages/pfblockernglistsv4',
		'installedpackages/pfblockernglistsv6',
		'installedpackages/pfblockerngreputation',
		'installedpackages/pfblockerngtopspammers',
		'installedpackages/pfblockerngafrica',
		'installedpackages/pfblockerngantarctica',
		'installedpackages/pfblockerngasia',
		'installedpackages/pfblockerngeurope',
		'installedpackages/pfblockerngnorthamerica',
		'installedpackages/pfblockerngoceania',
		'installedpackages/pfblockerngsouthamerica',
		'installedpackages/pfblockerngproxyandsatellite',
		'installedpackages/pfblockerngdnsbl',
		'installedpackages/pfblockerngblacklist',
		'installedpackages/pfblockerngglobal',
		'installedpackages/pfblockerngsafesearch'
	];

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

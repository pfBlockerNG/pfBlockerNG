<?php
/*
 * pfblockerng_alerts.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2015-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2015-2024 BBcan177@gmail.com
 * All rights reserved.
 *
 * Parts based on works from Snort_alerts.php
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

require_once('util.inc');
require_once('guiconfig.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');

global $g, $pfb;
pfb_global();

// Alerts tab customizations
$aglobal_array = array(	'pfbunicnt' => 200, 'pfbdenycnt' => 25, 'pfbpermitcnt' => 25, 'pfbmatchcnt' => 25,
			'pfbdnscnt' => 25, 'pfbdnsreplycnt' => 200,
			'ipfilterlimitentries' => 100, 'dnsblfilterlimitentries' => 100, 'dnsfilterlimitentries' => 100); 

$pfb['aglobal'] = PfbConfig::readSection('installedpackages/pfblockerngglobal');

// issue #2123: the ON default and the stored vocabulary now live in the registry
// (ADR-29) instead of this page. PfbConfig::read() applies the default only for a
// genuinely absent key, so an operator's unchecked '' still reads Off.
$alertrefresh	= PfbConfig::read('global/alertrefresh');
$pfbpageload	= $pfb['aglobal']['pfbpageload']	!= ''	? $pfb['aglobal']['pfbpageload']	: 'unified';
$pfbmaxtable	= $pfb['aglobal']['pfbmaxtable']	!= ''	? $pfb['aglobal']['pfbmaxtable']	: '1000';
$pfbreplytypes	= pfb_csv_list($pfb['aglobal']['pfbreplytypes'] ?? NULL);
$pfbreplyrec	= pfb_csv_list($pfb['aglobal']['pfbreplyrec'] ?? NULL);

// Unified Log - Light/Dark Theme colour keys: one registry drives the read defaults, the
// save loops, and the render loops below. 'upstream' reads with null-coalescing because it
// was added after the rest -- an existing config predating it lacks the key, so a plain
// `?:` would warn on the missing offset; the other keys have always been present.
$uni_defaults = array(
	'block'    => array('light_default' => '#FFF9C4', 'dark_default' => '#7A701B', 'light_help' => 'IP Block Event color',       'dark_help' => 'IP Block Event color',       'gated' => FALSE, 'safe_read' => FALSE),
	'permit'   => array('light_default' => '#80CBC4', 'dark_default' => '#367A74', 'light_help' => 'IP Permit Event color',      'dark_help' => 'IP Permit Event color',      'gated' => FALSE, 'safe_read' => FALSE),
	'match'    => array('light_default' => '#B3E5FC', 'dark_default' => '#3D7691', 'light_help' => 'IP Match Event color',       'dark_help' => 'IP Match Event color',       'gated' => FALSE, 'safe_read' => FALSE),
	'dnsbl'    => array('light_default' => '#EF9A9A', 'dark_default' => '#DB1C1C', 'light_help' => 'DNSBL Block Event color',    'dark_help' => 'DNSBL Block Event color',    'gated' => TRUE,  'safe_read' => FALSE),
	'upstream' => array('light_default' => '#CE93D8', 'dark_default' => '#9C27B0', 'light_help' => 'Upstream Block Event color', 'dark_help' => 'Upstream Block Event color', 'gated' => TRUE,  'safe_read' => TRUE),
	'reply'    => array('light_default' => '#E8E8E8', 'dark_default' => '#54585E', 'light_help' => 'DNS Reply Event color (Resolver only)', 'dark_help' => 'DNS Reply Event color', 'gated' => TRUE, 'safe_read' => FALSE),
);

foreach ($uni_defaults as $u_type => $u_cfg) {
	$u_light = "uni{$u_type}";
	$u_dark  = "uni{$u_type}2";
	if ($u_cfg['safe_read']) {
		// issue #1792: pfb_is_empty, not ?: -- a stored colour of literally
		// '0' is the user's (odd) value, not an absence.
		$pfb[$u_light]	= pfb_is_empty($pfb['aglobal'][$u_light] ?? NULL) ? $u_cfg['light_default'] : $pfb['aglobal'][$u_light];
		$pfb[$u_dark]	= pfb_is_empty($pfb['aglobal'][$u_dark] ?? NULL) ? $u_cfg['dark_default'] : $pfb['aglobal'][$u_dark];
	} else {
		$pfb[$u_light]	= $pfb['aglobal'][$u_light]		?: $u_cfg['light_default'];
		$pfb[$u_dark]	= $pfb['aglobal'][$u_dark]		?: $u_cfg['dark_default'];
	}
}

// Same source and missing-file fallback as head.inc. strpos(..., 'dark') === 0
// is falsy, so !== FALSE is required.
$pfb_webgui_css = pfb_effective_webguicss($user_settings ?? null);
$pfb_webgui_dark = strpos($pfb_webgui_css, 'dark') !== FALSE;

$pfbchartcnt	= $pfb['aglobal']['pfbchartcnt']		?: '24';
$pfbchartstyle	= $pfb['aglobal']['pfbchartstyle']		?: 'twotone';
$pfbchart1	= $pfb['aglobal']['pfbchart1']			?: '#0C6197';
$pfbchart2	= $pfb['aglobal']['pfbchart2']			?: '#7A7A7A';
$pfbblockstat	= pfb_csv_list($pfb['aglobal']['pfbblockstat'] ?? NULL);
$pfbpermitstat	= pfb_csv_list($pfb['aglobal']['pfbpermitstat'] ?? NULL);
$pfbmatchstat	= pfb_csv_list($pfb['aglobal']['pfbmatchstat'] ?? NULL);
$pfbdnsblstat	= pfb_csv_list($pfb['aglobal']['pfbdnsblstat'] ?? NULL);
$pfbdnsblreplystat = pfb_csv_list($pfb['aglobal']['pfbdnsblreplystat'] ?? NULL);

// issue #1497: explicit assignments (was a ${"$type"} variable-variable loop
// over $aglobal_array) -- PHPStan can't trace a variable-variable target, so
// every read of these 9 names was flagged as undefined despite always being
// set here. $aglobal_array itself stays (the save-handler loop below at
// ~line 592 is a separate consumer that still iterates it).
$pfbunicnt               = $pfb['aglobal']['pfbunicnt']               != '' ? $pfb['aglobal']['pfbunicnt']               : $aglobal_array['pfbunicnt'];
$pfbdenycnt              = $pfb['aglobal']['pfbdenycnt']              != '' ? $pfb['aglobal']['pfbdenycnt']              : $aglobal_array['pfbdenycnt'];
$pfbpermitcnt            = $pfb['aglobal']['pfbpermitcnt']            != '' ? $pfb['aglobal']['pfbpermitcnt']            : $aglobal_array['pfbpermitcnt'];
$pfbmatchcnt             = $pfb['aglobal']['pfbmatchcnt']             != '' ? $pfb['aglobal']['pfbmatchcnt']             : $aglobal_array['pfbmatchcnt'];
$pfbdnscnt               = $pfb['aglobal']['pfbdnscnt']               != '' ? $pfb['aglobal']['pfbdnscnt']              : $aglobal_array['pfbdnscnt'];
$pfbdnsreplycnt          = $pfb['aglobal']['pfbdnsreplycnt']          != '' ? $pfb['aglobal']['pfbdnsreplycnt']          : $aglobal_array['pfbdnsreplycnt'];
$ipfilterlimitentries    = $pfb['aglobal']['ipfilterlimitentries']    != '' ? $pfb['aglobal']['ipfilterlimitentries']    : $aglobal_array['ipfilterlimitentries'];
$dnsblfilterlimitentries = $pfb['aglobal']['dnsblfilterlimitentries'] != '' ? $pfb['aglobal']['dnsblfilterlimitentries'] : $aglobal_array['dnsblfilterlimitentries'];
$dnsfilterlimitentries   = $pfb['aglobal']['dnsfilterlimitentries']   != '' ? $pfb['aglobal']['dnsfilterlimitentries']   : $aglobal_array['dnsfilterlimitentries'];

$alert_view	= 'alert';
$alert_title	= '';
$alert_summary	= FALSE;
// The 'Collect Alert Statistics' block below (reached only when $alert_summary
// is TRUE) always assigns this fresh; the stats-render section far below reads
// it only under the identical $alert_summary condition. PHPStan can't trace
// that two separate `if ($alert_summary)` blocks thousands of lines apart
// agree, so this default keeps both reads provably defined without changing
// which branch runs.
$alert_stats	= array();
$active		= array('alerts' => TRUE, 'unified' => FALSE, 'ip_block' => FALSE, 'ip_permit' => FALSE, 'ip_match' => FALSE,
			'dnsbl' => FALSE, 'reply' => FALSE, 'dnsbl_reply_stat' => FALSE);

// Initialize filterfieldsarray
$filterfieldsarray	= array();
$filterfieldsarray[0]	= array();
foreach (array(0,2,6,7,8,9,10,12,13,15,16,17,18,99) as $field_0) {
	$filterfieldsarray[0][$field_0] = '';
}

$filterfieldsarray[1]	= array();
foreach (array(2,7,8,13,15,17,19,20,99) as $field_1) {
	$filterfieldsarray[1][$field_1] = '';
}

$filterfieldsarray[2]	= array();
foreach (array(81,82,83,84,85,86,87,88,89) as $field_2) {
	$filterfieldsarray[2][$field_2] = '';
}

// $alert_log is set by the view handler below but read in the stats section much later;
// default it so it is defined when that section runs without a view request. file_exists('')
// is false, so the stats block is skipped exactly as it was when $alert_log was undefined.
$alert_log = '';

if (isset($_GET) && isset($_GET['view']) || isset($_REQUEST) && isset($_REQUEST['alert_view'])) {
	switch($_GET['view'] != '' ? $_GET['view'] : $_REQUEST['alert_view']) {
		case 'dnsbl_stat':
			$alert_view	= 'dnsbl_stat';
			$alert_log	= $pfb['dnslog'];
			$alert_title	= 'DNSBL Block';
			$active		= array('dnsbl' => TRUE);
			break;
		case 'dnsbl_reply_stat':
			$alert_view	= 'dnsbl_reply_stat';
			$alert_log	= $pfb['dnsreplylog'];
			$alert_title	= 'DNS Reply Stats';
			$active		= array('dnsbl_reply_stat' => TRUE);
			break;
		case 'ip_block_stat':
			$alert_view	= 'ip_block_stat';
			$alert_log	= $pfb['ip_blocklog'];
			$alert_title	= 'IP Block';
			$active		= array('ip_block' => TRUE);
			break;
		case 'ip_permit_stat':
			$alert_view	= 'ip_permit_stat';
			$alert_log	= $pfb['ip_permitlog'];
			$alert_title	= 'IP Permit';
			$active		= array('ip_permit' => TRUE);
			break;
		case 'ip_match_stat':
			$alert_view	= 'ip_match_stat';
			$alert_log	= $pfb['ip_matchlog'];
			$alert_title	= 'IP Match';
			$active		= array('ip_match' => TRUE);
			break;
		case 'reply':
			$alert_view	= 'reply';
			$alert_log	= $pfb['dnsreplylog'];
			$alert_title	= 'DNS Reply';
			$active		= array('reply' => TRUE);
			break;
		case 'unified':
			$alert_view	= 'unified';
			$alert_log	= $pfb['unilog'];
			$alert_title	= 'Unified Logs';
			$active		= array('unified' => TRUE);
			break;
		default:
			$alert_view	= 'alert';
			$alert_log	= '';
			$alert_title	= '';
			$active		= array('alerts' => TRUE, 'unified' => FALSE, 'ip_block' => FALSE, 'ip_permit' => FALSE, 'ip_match' => FALSE,
						'dnsbl' => FALSE, 'reply' => FALSE, 'dnsbl_reply_stat' => FALSE);
			break;
	}

	if (!in_array($alert_view, array('reply', 'unified', 'alert'))) {
		$alert_summary = TRUE;
	}
}

// $clists is read later in contexts PHPStan can't prove are guarded; default it so it is
// defined even when the (!$alert_summary) collection block below is skipped (empty = no lists).
$clists = array();

// Collect all Whitelist/Suppression/Permit/Exclusion customlists
if (!$alert_summary) {

	foreach (array('ipwhitelist4' => 4, 'ipwhitelist6' => 6, 'dnsbl' => 'dnsbl') as $type => $vtype) {
		$c_config = $clists[$type] = array();

		if ($vtype == 'dnsbl') {
			// foreign structure: pfblockerngdnsbl is a dynamic per-feed list section, not in registry
			$c_config = config_get_path('installedpackages/pfblockerngdnsbl');
		} else {
			// foreign structure: pfblockernglistsv4/v6 are dynamic per-feed list sections, not in registry
			$c_config = config_get_path("installedpackages/pfblockernglistsv{$vtype}");
		}

		if (isset($c_config) &&
		    !empty($c_config['config'])) {

			foreach ($c_config['config'] as $row => $data) {
				$group_action = $data['action'] ?? NULL;
				$group_type = $type == 'dnsbl' ? 'dnsbl' : 'ipv4';
				if (pfb_group_action_valid($group_action, $group_type) &&
				    (strpos($group_action, 'Permit') !== FALSE || $group_action == 'unbound')) {

					if ($type == 'dnsbl') {
						$lname = "DNSBL_{$data['aliasname']}";
						// foreign structure: pfblockerngdnsbl/config/{row}/custom is a dynamic per-row key, not in registry
						$clists[$type][$lname]['base64'] = config_get_path("installedpackages/pfblockerngdnsbl/config/{$row}/custom");
						$clists[$type][$lname]['base64_idx'] = $row;

						// Collect Global DNSBL Logging type, or Group logging setting
						$g_log = PfbConfig::read('dnsbl/global_log');
						if (empty($g_log)) {
							// foreign structure: pfblockerngdnsbl/config/{row}/logging is a dynamic per-row key, not in registry
							$d_log = config_get_path("installedpackages/pfblockerngdnsbl/config/{$row}/logging");
						} else {
							$d_log = $g_log;
						}

						// Mirror the pfblockerng.inc logging_type mapping (issue #31 adds
						// NXDOMAIN '3'/'4'); anything else falls through to null-no-log '2'.
						if ($d_log == 'disabled_log') {
							$d_type = '0';
						} elseif ($d_log == 'enabled') {
							$d_type = '1';
						} elseif ($d_log == 'nxdomain_log') {
							$d_type = '3';
						} elseif ($d_log == 'nxdomain') {
							$d_type = '4';
						} else {
							$d_type = '2';
						}
						$clists[$type][$lname]['log'] = $d_type;
					} else {
						$lname = "pfB_{$data['aliasname']}_v{$vtype}";
						// foreign structure: pfblockernglistsv4/v6/config/{row}/custom is a dynamic per-row key, not in registry
						$clists[$type][$lname]['base64'] = config_get_path("installedpackages/pfblockernglistsv{$vtype}/config/{$row}/custom");
						$clists[$type][$lname]['base64_idx'] = $row;
					}
					$clists[$type][$lname]['data']	= array();

					$clists[$type]['options'][] = $lname;	// List of all Permit Aliases/DNSBL Customlists

					// issue #1782: $idn=TRUE -- matches pfblockerng_apply.inc:1758's decode of
					// this SAME per-row 'custom' field; a Unicode key here would never match
					// a $domain derived from a punycode log field.
					$decoded = pfb_text_area_decode($data['custom'], TRUE, TRUE, TRUE);
					if (!empty($decoded)) {
						foreach ($decoded as $line) {

							// Create string (Domain and Comment if found)
							if (isset($line[1])) {
								$clists[$type][$lname]['data'][$line[0]] = "{$line[0]} {$line[1]}\r\n";
							} else {
								$line[0] = trim($line[0]);
								$clists[$type][$lname]['data'][$line[0]] = "{$line[0]}\r\n";
							}
						}
					}
				}
			}
		}

		// Add Default pfBlockerNG IP Whitelist
		if (empty($clists[$type]['options'])) {
			if ($type == 'dnsbl') {
				$clists[$type]['options'][] = "Create new DNSBL Group";
			} else {
				$clists[$type]['options'][] = "Create new pfB_Whitelist_v{$vtype}";
			}
		}
	}

	PfbConfig::write('ip/v4suppression', PfbConfig::read('ip/v4suppression') ?: '');

	// ADR-53: v6 sibling -- same absent-key normalisation as v4suppression above.
	PfbConfig::write('ip/v6suppression', PfbConfig::read('ip/v6suppression') ?: '');

	PfbConfig::write('dnsbl/whitelist', PfbConfig::read('dnsbl/whitelist') ?: '');

	PfbConfig::write('dnsbl/tld_wildcard_exclusion', PfbConfig::read('dnsbl/tld_wildcard_exclusion') ?: '');

	// ADR-53: 'ipsuppression_v6' is the new v6suppression sibling of
	// 'ipsuppression' (v4) -- same collection shape, keyed separately so the
	// addsuppress handler below can dedup/rewrite each family's customlist
	// independently.
	foreach (array('ipsuppression', 'ipsuppression_v6', 'dnsblwhitelist', 'tld_wildcard_exclusion') as $key => $type) {

		if (!isset($clists[$type]) || !is_array($clists[$type])) {
			$clists[$type] = array();
		}

		if ($key == 0) {
			$clists[$type]['base64'] = PfbConfig::read('ip/v4suppression');
		} elseif ($key == 1) {
			$clists[$type]['base64'] = PfbConfig::read('ip/v6suppression');
		} elseif ($key == 2) {
			$clists[$type]['base64'] = PfbConfig::read('dnsbl/whitelist');
		} elseif ($key == 3) {
			$clists[$type]['base64'] = PfbConfig::read('dnsbl/tld_wildcard_exclusion');
		}

		$clists[$type]['data']		= array();
		if (isset($clists[$type]['base64']) && !empty($clists[$type]['base64'])) {
			// issue #1782: $idn=TRUE -- 'whitelist'/'tld_wildcard_exclusion' are decoded with
			// $idn=TRUE by their runtime consumers (pfblockerng.inc); a Unicode key
			// here would never match a $domain derived from a punycode log field.
			$decoded = pfb_text_area_decode($clists[$type]['base64'], TRUE, TRUE, TRUE);
			if (!empty($decoded)) {
				foreach ($decoded as $line) {

					// Create string (Domain and Comment if found)
					if (isset($line[1])) {
						$clists[$type]['data'][$line[0]] = "{$line[0]} {$line[1]}\r\n";
					} else {
						$line[0] = trim($line[0]);
						$clists[$type]['data'][$line[0]] = "{$line[0]}\r\n";
					}
				}
			}
		}
	}
}

// Collect all existing unlocked Domains
$dnsbl_unlock	= pfb_unlock('read', 'dnsbl', '', '', '');

// Collect all existing unlocked IPs
$ip_unlock	= pfb_unlock('read', 'ip', '', '', '');

if (isset($_REQUEST)) {

	// Define alerts log filter rollup window variable and collect widget alert pivot details
	if (isset($_REQUEST['filterip']) || isset($_REQUEST['filterdnsbl'])) {

		if (isset($_REQUEST['filterip'])) {
			$filterfieldsarray[0][13]	= pfb_filter($_REQUEST['filterip'], PFB_FILTER_HTML, 'alerts filter');
			$pfbdnscnt			= 0;
		}
		else {
			$filterfieldsarray[1][13]	= pfb_filter($_REQUEST['filterdnsbl'], PFB_FILTER_HTML, 'alerts filter');
			$pfbdenycnt			= $pfbpermitcnt = $pfbmatchcnt = 0;
		}
		$pfb['filterlogentries']		= TRUE;
	}
	else {
		$pfb['filterlogentries']		= FALSE;
	}

	// Re-enable any Alert 'filter settings' on page refresh
	if (isset($_REQUEST['refresh'])) {
		$refresharr = json_decode(urldecode($_REQUEST['refresh']), TRUE);
		if (isset($refresharr)) {
			foreach ($refresharr as $id => $row) {
				foreach ($row as $key => $type) {
					if (is_int($key)) {
						$filterfieldsarray[$id][$key] = pfb_filter($type, PFB_FILTER_HTML, 'alerts filter');
					}
				}
			}
		}
		$pfb['filterlogentries']	= TRUE;
	}
}


// Select field options

$options_pfbpageload	= [	'unified'		=> 'Unified Log',
				'default'		=> 'Alerts Tab',
				'ip_block_stat'		=> 'IP Block Stats',
				'ip_permit_stat'	=> 'IP Permit Stats',
				'ip_match_stat'		=> 'IP Match Stats',
				'reply'			=> 'DNS Reply',
				'dnsbl_reply_stat'	=> 'DNS Reply Stats',
				'dnsbl_stat'		=> 'DNSBL Block Stats'
				];

$options_pfbmaxtable	= [	'100'	=> '100',
				'1000'	=> '1,000',
				'2000'	=> '2,000',
				'3000'	=> '3,000',
				'4000'	=> '4,000',
				'5000'	=> '5,000',
				'6000'	=> '6,000',
				'7000'	=> '7,000',
				'8000'	=> '8,000',
				'9000'	=> '9,000',
				'10000'	=> '10,000',
				'max'	=> 'No limit'
				];

$options_pfbextdns	= [	'8.8.4.4'		=> 'Google 8.8.4.4',
				'8.8.8.8'		=> 'Google 8.8.8.8',
				'208.67.220.220'	=> 'OpenDNS 208.67.220.220',
				'208.67.222.222'	=> 'OpenDNS 208.67.222.222',
				'84.200.69.80'		=> 'DNS Watch 84.200.69.80',
				'84.200.70.40'		=> 'DNS Watch 84.200.70.40',
				'37.235.1.174'		=> 'FreeDNS 37.235.1.174',
				'37.235.1.177'		=> 'FreeDNS 37.235.1.177',
				'91.239.100.100'	=> 'UncensoredDNS 91.239.100.100',
				'89.233.43.71'		=> 'UncensoredDNS 89.233.43.71',
				'9.9.9.9'		=> 'Quad9 9.9.9.9',
				'149.112.112.112'	=> 'Quad9 149.112.112.112',
				'1.1.1.1'		=> 'Cloudflare 1.1.1.1',
				'1.0.0.1'		=> 'Cloudflare 1.0.0.1',
				'77.88.8.8'		=> 'Yandex 77.88.8.8',
				'77.88.8.1'		=> 'Yandex 77.88.8.1'
				];

$options_pfbreplytypes	= [	'resolver'	=> 'resolver',
				'reply'		=> 'reply',
				'cache'		=> 'cache',
				'local'		=> 'local',
				'servfail'	=> 'servfail',
				'Unknown'	=> 'Unknown'
				];

$options_pfbreplyrec	= [	'A'		=> 'A',
				'AAAA'		=> 'AAAA',
				'CNAME'		=> 'CNAME',
				'DNSKEY'	=> 'DNSKEY',
				'DS'		=> 'DS',
				'KEY'		=> 'KEY',
				'MX'		=> 'MX',
				'NAPTR' 	=> 'NAPTR',
				'NS'		=> 'NS',
				'NSEC3'		=> 'NSEC3',
				'PTR'		=> 'PTR',
				'SOA'		=> 'SOA',
				'SRV'		=> 'SRV',
				'TXT'		=> 'TXT',
				'TYPE65'	=> 'TYPE65',
				'Unknown'	=> 'Unknown'
				];

$options_pfbchartcnt	= [	'24'	=> '24 Hrs (~1 Day)',
				'48'	=> '48 Hrs (~2 Days)',
				'72'	=> '72 Hrs (~3 Days)',
				'96'	=> '96 Hrs (~4 Days)',
				'120'	=> '120 Hrs (~5 Days)',
				'144'	=> '144 Hrs (~6 Days)',
				'168'	=> '168 Hrs (~1 week)',
				'336'	=> '336 Hrs (~2 weeks)',
				'672'	=> '672 Hrs (~1 Month)',
				'1344'	=> '1344 Hrs (~2 Months)',
				'2016'	=> '2016 Hrs (~3 Months)',
				'2688'	=> '2688 Hrs (~4 Months)',
				'4032'	=> '4032 Hrs (~6 Months)',
				'8064'	=> '8064 Hrs (~1 Year)',
				'max'	=> 'Unlimited'
				];

$options_pfbchartstyle	= [	'twotone'	=> 'Two-Tone',
				'greyscale'	=> 'Grey-Scale',
				'multi'		=> 'Multi-Color'
				];

$options_ip_stats	= [	'ipchart'	=> 'IP Event Timeline',
				'srcipin'	=> 'Top SRC IP Inbound',
				'srcipout'	=> 'Top SRC IP Outbound',
				'dstipin'	=> 'Top DST IP Inbound',
				'dstipout'	=> 'Top DST IP Outbound',
				'srcport'	=> 'Top SRC Port',
				'dstport'	=> 'Top DST Port',
				'geoip'		=> 'Top GeoIP',
				'asn'		=> 'Top ASN',
				'aliasname'	=> 'Top Aliasname',
				'feed'		=> 'Top Feed',
				'interface'	=> 'Top Interface',
				'protocol'	=> 'Top Protocol',
				'direction'	=> 'Top Direction',
				'date'		=> 'Historical Summary'
				];

$options_pfbdnsblstat	= [	'dnsblchart'	=> 'DNSBL Event Timeline',
				'dnsbldomain'	=> 'Top Blocked Domain',
				'dnsblevald'	=> 'Top Blocked Eval\'d',
				'dnsblgptotal'	=> 'Top Group Count',
				'dnsblgpblock'	=> 'Top Blocked Group',
				'dnsblfeed'	=> 'Top Blocked Feed',
				'dnsblip'	=> 'Top Source IP',
				'dnsblagent'	=> 'Top Blocking mode',
				'dnsbltld'	=> 'Top TLD',
				'dnsblwebtype'	=> 'Top Webpage Types',
				'dnsblmode'	=> 'Top DNSBL Modes',
				'dnsbldatehr'	=> 'Top Date/Hr',
				'dnsbldatehrmin'=> 'Top Date/Hr/Min',
				'dnsbldate'	=> 'Top Date'
				];

$options_pfbdnsblreplystat = [	'replychart'    => 'Reply Event Timeline',
				'replytype'	=> 'Top Reply Type',
				'replyorec'	=> 'Top Reply Orig Record',
				'replyrec'	=> 'Top Reply Record',
				'replyttl'	=> 'Top TTL',
				'replydomain'	=> 'Top Reply Domain',
				'replytld'	=> 'Top Reply TLD',
				'replytld2'	=> 'Top Reply TLD 2nd level',
				'replytld3'	=> 'Top Reply TLD 3rd level',
				'replysrcip'	=> 'Top Reply SRC IP',
				'replydstip'	=> 'Top Reply DST IP',
				'replysrcipd'	=> 'Top Reply SRC IP/Domain',
				'replydate'	=> 'Top Date'
				];

if (isset($_POST) && !empty($_POST)) {

	// Save Alerts tab customizations
	if (isset($_POST['save'])) {

		// Validate Select field options
		$select_options = array(	'pfbpageload'		=> 'unified',
						'pfbmaxtable'		=> '1000',
						'pfbextdns'		=> '8.8.8.8',
						'pfbchartcnt'		=> '24',
						'pfbchartstyle'		=> 'twotone'
						);

		foreach ($select_options as $s_option => $s_default) {
			if (is_array($_POST[$s_option])) {
				$_POST[$s_option] = $s_default;
			}
			elseif (!array_key_exists($_POST[$s_option], ${"options_$s_option"})) {
				$_POST[$s_option] = $s_default;
			}
		}

		// Validate Select field (array) options
		$select_options = array(	'pfbreplytypes'		=> '',
						'pfbreplyrec'		=> '',
						'pfbblockstat'		=> '',
						'pfbpermitstat'		=> '',
						'pfbmatchstat'		=> '',
						'pfbdnsblstat'		=> '',
						'pfbdnsblreplystat'	=> ''
						);

		$select_ip_options = array( 'pfbblockstat', 'pfbpermitstat', 'pfbmatchstat' );

		foreach ($select_options as $s_option => $s_default) {

			// Array to validate against
			if (in_array($s_option, $select_ip_options)) {
				$query = $options_ip_stats;
			} else {
				$query = ${"options_$s_option"};
			}

			if (is_array($_POST[$s_option])) {
				foreach ($_POST[$s_option] as $post_option) {
					if (!array_key_exists($post_option, $query)) {
						$_POST[$s_option] = $s_default;
						break;
					}
				}
			}
			elseif (!array_key_exists($_POST[$s_option], $query)) {
				$_POST[$s_option] = $s_default;
			}
		}

		// Unified Log - Light/Dark Theme Hex settings
		$uni_hex_fields = array();
		foreach ($uni_defaults as $u_type => $u_cfg) {
			$uni_hex_fields["uni{$u_type}"] = $u_cfg['light_default'];
		}
		foreach ($uni_defaults as $u_type => $u_cfg) {
			$uni_hex_fields["uni{$u_type}2"] = $u_cfg['dark_default'];
		}
		foreach ($uni_hex_fields as $h_type => $h_default) {
			if (isset($_POST[$h_type]) && !empty($_POST[$h_type])) {
				$pfb['aglobal'][$h_type] = pfb_filter($_POST[$h_type], PFB_FILTER_HEX_COLOR, 'alerts hex', $h_default);
			} else {
				$pfb['aglobal'][$h_type] = $h_default;
			}
		}

		$pfb['aglobal']['pfbchart1']		= '#0C6197';
		if (isset($_POST['pfbchart1']) && !empty($_POST['pfbchart1'])) {
			$pfb['aglobal']['pfbchart1'] = pfb_filter($_POST['pfbchart1'], PFB_FILTER_HEX_COLOR, 'alerts hex', '#0C6197');
		}

		$pfb['aglobal']['pfbchart2']		= '#7A7A7A';
		if (isset($_POST['pfbchart2']) && !empty($_POST['pfbchart2'])) {
			$pfb['aglobal']['pfbchart2'] = pfb_filter($_POST['pfbchart2'], PFB_FILTER_HEX_COLOR, 'alerts hex', '#7A7A7A');
		}

		// issue #2123: an unchecked checkbox is absent from $_POST; PFB_FILTER_ON_OFF
		// emits the owner-ruled empty Off token for it, and writeSection() below
		// normalises the value through the key's registered adapter.
		$pfb['aglobal']['alertrefresh']		= pfb_filter($_POST['alertrefresh'] ?? '', PFB_FILTER_ON_OFF, 'alerts alertrefresh');

		$pfb['aglobal']['pfbpageload']		= $_POST['pfbpageload']					?: 'unified';
		$pfb['aglobal']['pfbmaxtable']		= $_POST['pfbmaxtable']					?: '1000';
		$pfb['aglobal']['pfbextdns']		= $_POST['pfbextdns']					?: '8.8.8.8';
		$pfb['aglobal']['pfbreplytypes']	= implode(',', (array)$_POST['pfbreplytypes'])		?: '';
		$pfb['aglobal']['pfbreplyrec']		= implode(',', (array)$_POST['pfbreplyrec'])		?: '';
		$pfb['aglobal']['pfbchartcnt']		= $_POST['pfbchartcnt']					?: '24';
		$pfb['aglobal']['pfbchartstyle']	= $_POST['pfbchartstyle']				?: 'twotone';
		$pfb['aglobal']['pfbblockstat']		= implode(',', (array)$_POST['pfbblockstat'])		?: '';
		$pfb['aglobal']['pfbpermitstat']	= implode(',', (array)$_POST['pfbpermitstat'])		?: '';
		$pfb['aglobal']['pfbmatchstat']		= implode(',', (array)$_POST['pfbmatchstat'])		?: '';
		$pfb['aglobal']['pfbdnsblstat']		= implode(',', (array)$_POST['pfbdnsblstat'])		?: '';
		$pfb['aglobal']['pfbdnsblreplystat']	= implode(',', (array)$_POST['pfbdnsblreplystat'])	?: '';

		foreach ($aglobal_array as $type => $value) {
			if (ctype_digit($_POST[$type]) && $_POST[$type] <= 5000) {
				$pfb['aglobal'][$type] = $_POST[$type];
			} else {
				$pfb['aglobal'][$type] = $value;
			}
		}

		// Remove obsolete XML tag
		if (isset($pfb['aglobal']['hostlookup'])) {
			unset($pfb['aglobal']['hostlookup']);
		}

		$pageview = htmlspecialchars(trim(strstr($_POST['save'], ' ', FALSE)));
		if (!in_array($pageview, array('', 'dnsbl_stat', 'dnsbl_reply_stat', 'ip_block_stat', 'ip_permit_stat', 'ip_match_stat', 'reply', 'unified', 'alert'))) {
			$pageview = 'alert';
		}

		PfbConfig::writeSection('installedpackages/pfblockerngglobal', $pfb['aglobal']);
		write_config('pfBlockerNG: Update ALERT tab settings.', FALSE);
		header("Location: /pfblockerng/pfblockerng_alerts.php?view={$pageview}");
		exit;
	}

	$filter_type = array();
	foreach ($_POST as $key => $post) {
		if (!empty($post) && strpos($key, 'filterlogentries_') !== FALSE) {
			$f_type = substr(substr($key, strrpos($key, '_') + 1), 0, 2);
			if ($f_type != 'cl' && $f_type != 'su') {
				$filter_type[$f_type] = '';
			}
		}
	}

	// Collect 'Filter selection' from 'Alert Statistics' Filter action and convert to existing filter fields
	if (!isset($_POST['filterlogentries_submit'])) {

		$f_value = key($filter_type);
		if (!empty($f_value)) {
			$ftypes = array();
			switch ($f_value) {
				case 'ip':
					$ftypes = array('ipdate' => 'ipdate', 'ipinterface' => 'ipint', 'ipprotocol' => 'ipproto', 'ipsrcipin' => 'ipsrcip',
							'ipsrcipout' => 'ipsrcip', 'ipdstipin' => 'ipdstip', 'ipdstipout' => 'ipdstip',
							'ipsrcport' => 'ipsrcport', 'ipdstport' => 'ipdstport', 'ipdirection' => '', 'ipgeoip' => 'ipgeoip',
							'ipaliasname' => 'ipalias', 'ipfeed' => 'ipfeed', 'ipasn' => 'ipasn' );
					break;
				case 'dn':
				case 'py':
					$ftypes = array('dnsblwebtype' => 'dnsbltype', 'dnsbldate' => 'dnsbldate', 'dnsbldatehr' => 'dnsbldate',
							'dnsbldatehrmin' => 'dnsbldate', 'dnsbldomain' => 'dnsbldomain', 'dnsbltld' => 'dnsbldomain',
							'dnsblip' => 'dnsblsrcip', 'dnsblagent' => 'dnsbltype', 'dnsblmode' => 'dnsblmode',
							'dnsblevald' => 'dnsbldomain', 'dnsblfeed' => 'dnsblfeed', 'dnsblgpblock' => 'dnsblgroup',
							'dnsblgptotal' => 'dnsblgroup', 'dnsbltype' => 'dnsbltype' );
					break;
				case 're':
					$ftypes = array('replydate' => 'replydate', 'replytype' => 'replytype', 'replyorec' => 'replyorec',
							'replyrec' => 'replyrec', 'replyttl' => 'replyttl', 'replygeoip' => 'replygeoip',
							'replydomain' => 'replydomain', 'replytld' => 'replydomain', 'replytld2' => 'replydomain',
							'replytld3' => 'replydomain', 'replydstip' => 'replydstip', 'replysrcip' => 'replysrcip',
							'replysrcipd' => 'replydomain');
			}

			foreach ($ftypes as $submit_type => $final_type) {
				if (isset($_POST['filterlogentries_submit_' . $submit_type]) && !empty($_POST['filterlogentries_submit_' . $submit_type])) {
					$final_type = $ftypes[$submit_type];

					// Split SRC/DST In/Outbound field into two filter fields (IP/GeoIP)
					if ($submit_type == 'replysrcipd') {
						$data = explode(',', $_POST['filterlogentries_submit_' . $submit_type]);
						$_POST['filterlogentries_' . $final_type]	= pfb_filter($data[0], PFB_FILTER_HTML, 'alerts filter');
						$_POST['filterlogentries_replysrcip']		= pfb_filter($data[1], PFB_FILTER_HTML, 'alerts filter');
					}
					elseif ($submit_type == 'replydstipd') {
						$data = explode(',', $_POST['filterlogentries_submit_' . $submit_type]);
						$_POST['filterlogentries_' . $final_type]	= pfb_filter($data[0], PFB_FILTER_HTML, 'alerts filter');
						$_POST['filterlogentries_replydstip']		= pfb_filter($data[1], PFB_FILTER_HTML, 'alerts filter');
					}
					elseif (strpos($submit_type, 'ipsrcip') !== FALSE || strpos($submit_type, 'ipdstip') !== FALSE) {
						$data = explode(',', $_POST['filterlogentries_submit_' . $submit_type]);
						$_POST['filterlogentries_' . $final_type]	= pfb_filter($data[0], PFB_FILTER_HTML, 'alerts filter');
						$_POST['filterlogentries_ipgeoip']		= pfb_filter($data[1], PFB_FILTER_HTML, 'alerts filter');
					}
					else {
						$_POST['filterlogentries_' . $final_type] = pfb_filter($_POST['filterlogentries_submit_' . $submit_type], PFB_FILTER_HTML, 'alerts filter');
					}

					// Apply POST setting
					$_POST['filterlogentries_submit'] = 'Apply Filter';
				}
			}
		}
	}

	// Filter Alerts based on user defined 'filter settings'
	if (isset($_POST['filterlogentries_submit']) && $_POST['filterlogentries_submit'] == 'Apply Filter' && !empty($filter_type)) {

		$pfb['filterlogentries'] = TRUE;

		$f_arr = array();
		foreach ($filter_type as $ftype => $value) {
			switch ($ftype) {
				case 'ip':
					$f_arr = array( 0 => 'iprule',
							2 => 'ipint',
							6 => 'ipproto',
							7 => 'ipsrcip',
							8 => 'ipdstip',
							9 => 'ipsrcport',
							10 => 'ipdstport',
							12 => 'ipgeoip',
							13 => 'ipalias',
							15 => 'ipfeed',
							16 => 'ipdsthostname',
							17 => 'ipsrchostname',
							18 => 'ipasn',
							99 => 'ipdate');
					break;
				case 'dn':
				case 'py':
					$f_arr = array( 2 => 'dnsblint',
							7 => 'dnsblsrcip',
							8 => 'dnsbldomain',
							13 => 'dnsblgroup',
							15 => 'dnsblfeed',
							17 => 'dnsblsrchostname',
							19 => 'dnsbltype',
							20 => 'dnsblmode',
							99 => 'dnsbldate');
					break;
				case 're':
					$f_arr = array( 81 => 'replytype',
							82 => 'replyorec',
							83 => 'replyrec',
							84 => 'replyttl',
							85 => 'replydomain',
							86 => 'replysrcip',
							87 => 'replydstip',
							88 => 'replygeoip',
							89 => 'replydate');
					break;
			}

			foreach ($f_arr as $key => $atype) {
				$atype = pfb_filter($_POST['filterlogentries_' . "{$atype}"], PFB_FILTER_HTML, 'alerts filter');
				if ($key == 6) {
					$atype = strtolower("{$atype}");
				}

				switch ($ftype) {
					case 'ip':
						$filterfieldsarray[0][$key] = $atype ?: NULL;
						break;
					case 'dn':
					case 'py':
						$filterfieldsarray[1][$key] = $atype ?: NULL;
						break;
					case 're':
						$filterfieldsarray[2][$key] = $atype ?: NULL;
						break;
				}
			}
		}

		// Remove blank entries in Filter Fields Array
		$filterfieldsarray[0]	= array_filter($filterfieldsarray[0]);
		$filterfieldsarray[1]	= array_filter($filterfieldsarray[1]);
		$filterfieldsarray[2]	= array_filter($filterfieldsarray[2]);
		$filterfieldsarray	= array_filter($filterfieldsarray);
	}

	// Clear Filter Alerts
	if (isset($_POST['filterlogentries_clear']) && !empty($_POST['filterlogentries_clear'])) {
		$pfb['filterlogentries'] = FALSE;
		$filterfieldsarray = array();
	}

	// Add a host to the suppression customlist.
	elseif (isset($_POST['addsuppress']) && !empty($_POST['addsuppress'])) {
		$ip	= pfb_filter($_POST['ip'], PFB_FILTER_IP, 'alerts addsuppress');
		$table	= pfb_filter($_POST['table'], PFB_FILTER_WORD, 'alerts addsuppress');

		// If IP is not valid or Table not valid, exit.
		if (empty($ip) || empty($table)) {
			$savemsg = gettext('Cannot Suppress: IP address not valid or Table not valid');
			header("Location: /pfblockerng/pfblockerng_alerts.php?savemsg={$savemsg}");
			exit;
		}

		$descr = '';
		if (isset($_POST['descr']) && !empty($_POST['descr'])) {
			$descr = pfb_filter($_POST['descr'], PFB_FILTER_HTML, 'alerts addsuppress');
		}
		$result = pfb_alerts_ip_action('addsuppress', $ip, $table, $descr, $clists, $ip_unlock);
		header("Location: /pfblockerng/pfblockerng_alerts.php?savemsg={$result['savemsg']}");
		exit;
	}

	// Add Domain to DNSBL Customlist
	elseif (isset($_POST['dnsbl_add']) && !empty($_POST['dnsbl_add'])) {

		$domain	= pfb_filter($_POST['domain'], PFB_FILTER_DOMAIN, 'alerts dnsbl_add');
		$list	= pfb_filter($_POST['dnsbl_customlist'], PFB_FILTER_WORD, 'alerts dnsbl_add');

		// If Domain or customlist field is empty, exit.
		if (empty($domain) || empty($list)) {
			$savemsg = gettext('Cannot Add domain to DNSBL Group customlist - Domain name or customlist value missing');
			header("Location: /pfblockerng/pfblockerng_alerts.php?savemsg={$savemsg}");
			exit;
		}

		$descr = '';
		if (isset($_POST['descr']) && !empty($_POST['descr'])) {
			$descr = pfb_filter($_POST['descr'], PFB_FILTER_HTML, 'alerts dnsbl_add');
		}
		// Issue #37: adding a domain to a Custom_List is the user's "block this"
		// intent. If the same domain sits in the DNSBL Whitelist, the two user stores
		// would silently disagree -- the band-6 whitelist would keep it resolving
		// despite the new band-5 Custom_List block. Newest action wins: strip it from
		// the whitelist so the block takes effect. (The dead file_put_contents into
		// pfb_py_data/pfb_py_zone was removed: under ADR-06 the resolver builds the
		// DNSBL structures from the manifest raws, never those legacy CSVs -- see
		// pfb_unbound.py's 'if not dnsbl_built' guard.)
		$wl_base = $domain;
		if (str_starts_with($wl_base, 'www.')) {
			$wl_base = substr($wl_base, 4);
		}
		$wl_variants = array($wl_base, "www.{$wl_base}");
		if ($_POST['dnsbl_wildcard'] == 'true') {
			$wl_variants[] = ".{$wl_base}";
		}
		$wl_removed = FALSE;
		foreach ($wl_variants as $variant) {
			if (isset($clists['dnsblwhitelist']['data'][$variant])) {
				unset($clists['dnsblwhitelist']['data'][$variant]);
				$wl_removed = TRUE;
			}
		}
		if ($wl_removed) {
			$data = '';
			foreach ($clists['dnsblwhitelist']['data'] as $line) {
				// Drop CNAME entries that had been whitelisted for this domain
				if (strpos($line, "({$wl_base})") === FALSE) {
					$data .= "{$line}";
				}
			}
			$clists['dnsblwhitelist']['base64'] = pfb_text_area_encode($data);
			PfbConfig::write('dnsbl/whitelist', $clists['dnsblwhitelist']['base64']);
			// issue #1872: this description is user-facing (Diagnostics > Config History),
			// so it spells the field the way the UI does -- "Custom List", not the
			// code-level "Custom_List".
			write_config("pfBlockerNG: Removed [ {$wl_base} ] from DNSBL Whitelist (added to Custom List)", FALSE);

			// Refresh the query-time whiteDB so the domain is no longer allowed.
			pfb_unbound_python_whitelist('alerts');
			pfb_unbound_python_sources_whitelist();
		}
	
		$savemsg = gettext(" Added domain [ {$domain} ] to the DNSBL Group [ $list ] customlist. You may need to flush your OS/Browser DNS Cache!");

		// Save changes
		$cl_added = FALSE;
		if (!isset($clists['dnsbl'][$list]['data'][$domain])) {
			$data = '';
			if (isset($clists['dnsbl'][$list]) && is_array($clists['dnsbl'][$list]['data'])) {
				foreach ($clists['dnsbl'][$list]['data'] as $line) {
					$data .= "{$line}";
				}
			}

			if (!empty($descr)) {
				$data .= "{$domain} # {$descr}\r\n";
			} else {
				$data .= "{$domain}\r\n";
			}
			$clists['dnsbl'][$list]['base64'] = pfb_text_area_encode($data);
			// foreign structure: pfblockerngdnsbl/config/{row}/custom is a dynamic per-row key, not in registry
			config_set_path("installedpackages/pfblockerngdnsbl/config/{$clists['dnsbl'][$list]['base64_idx']}/custom", $clists['dnsbl'][$list]['base64']);
			write_config("pfBlockerNG: Added [ {$domain} ] to DNSBL Group [ {$list} ] customlist", FALSE);
			$cl_added = TRUE;
		}
		else {
			$savemsg = gettext("Domain [ {$domain} ] already exists in DNSBL Group [ $list ] customlist");
		}

		// Issue #37: note the reverse-direction reconciliation in the UI message.
		if ($wl_removed) {
			$savemsg .= gettext(' Removed [ ') . "{$wl_base}" . gettext(' ] from the DNSBL Whitelist.');
		}

		// Reload if the Custom_List grew or the domain was stripped from the whitelist.
		// ADR-10: this is a #51 user custom-list DATA edit -- take the zero-downtime
		// fast path (no restart), then flush this exact allow-to-block change.
		if ($cl_added || $wl_removed) {
			$swapped = pfb_reload_unbound('enabled', FALSE, TRUE, TRUE);
			if ($swapped) {
				pfb_unbound_py_ccache_flush(array($domain));
			}
		}

		$return_page = pfb_filter($_POST['alert_view'], PFB_FILTER_HTML, 'alerts dnsbl_add');
		if (!in_array($return_page, array('', 'dnsbl_stat', 'dnsbl_reply_stat', 'ip_block_stat', 'ip_permit_stat', 'ip_match_stat', 'reply', 'unified', 'alert'))) {
			$return_page = 'alert';
		}

		header("Location: /pfblockerng/pfblockerng_alerts.php?savemsg={$savemsg}&view={$return_page}");
		exit;
	}

	// Add Domain/CNAME(s) to the DNSBL Whitelist customlist or TLD Exclusion customlist
	elseif (isset($_POST['addwhitelistdom']) && !empty($_POST['addwhitelistdom'])) {

		$domain	= pfb_filter($_POST['domain'], PFB_FILTER_DOMAIN, 'alerts addwhitelistdom');
		$table	= pfb_filter($_POST['table'], PFB_FILTER_WORD, 'alerts addwhitelistdom');

		// If Domain or Table field is empty, exit.
		if (empty($domain) || empty($table)) {
			$savemsg = gettext('Cannot Whitelist - Domain name or DNSBL Table value missing');
			header("Location: /pfblockerng/pfblockerng_alerts.php?savemsg={$savemsg}");
			exit;
		}
		// issue #2670: unlock store is keyed by the posted token; www. is stripped below
		$domain_unlock = $domain;

		$descr = '';
		if (isset($_POST['descr']) && !empty($_POST['descr'])) {
			$descr = pfb_filter($_POST['descr'], PFB_FILTER_HTML, 'alerts addwhitelistdom');
		}

		$wildcard = FALSE;
		if ($_POST['dnsbl_wildcard'] == 'true') {
			$wildcard = TRUE;
		}

		$dnsbl_exclude = FALSE;
		if ($_POST['dnsbl_exclude'] == 'true') {
			$dnsbl_exclude = TRUE;
		}

		// Query for CNAME(s)
		$cname_list = array();
		if (!empty(pfb_filter($pfb['extdns'], PFB_FILTER_IP, 'alerts addwhitelistdom'))) {
			$domain_esc	= escapeshellarg($domain);
			$ext_dns 	= escapeshellarg("@{$pfb['extdns']}");
			$drill_esc	= escapeshellarg($pfb['drill'] ?? '/usr/bin/drill');
			$timeout_esc	= escapeshellarg($pfb['timeout'] ?? '/usr/bin/timeout');
			// 30s DNS ceiling matches the established SafeSearch and whoisconvert lookups (#2014/#2015).
			$cname_lookup_timeout = 30;
			$cname_lookup_kill_grace = 5;
			$cname_lookup_prefix = "{$g['tmp_path']}/pfb_alerts_cname_" . getmypid() . '_' . bin2hex(random_bytes(8));
			$cname_lookup_file = "{$cname_lookup_prefix}_result";
			$cname_lookup_raw_file = "{$cname_lookup_prefix}_raw";
			$cname_lookup_pipeline = "{$drill_esc} {$domain_esc} {$ext_dns} > " . escapeshellarg($cname_lookup_raw_file) .
				" 2>&1 && /usr/bin/awk '/CNAME/ {sub(\"[.]\$\", \"\", \$5); print \$5;}' " . escapeshellarg($cname_lookup_raw_file);
			$cname_lookup_cmd = "{$timeout_esc} -s TERM -k {$cname_lookup_kill_grace} {$cname_lookup_timeout} /bin/sh -c " .
				escapeshellarg($cname_lookup_pipeline) . ' > ' . escapeshellarg($cname_lookup_file) . " 2>&1 < /dev/null";
			$cname_lookup_output = array();
			$cname_lookup_status = 0;
			exec($cname_lookup_cmd, $cname_lookup_output, $cname_lookup_status);
			if ($cname_lookup_status === 124) {
				pfb_logger("\npfblockerng_alerts: CNAME lookup TIMED OUT (killed); discarding partial output\n", 2);
			} elseif ($cname_lookup_status !== 0) {
				pfb_logger("\npfblockerng_alerts: CNAME lookup FAILED (exit {$cname_lookup_status}); discarding output\n", 2);
			} elseif (!is_file($cname_lookup_file)) {
				pfb_logger("\npfblockerng_alerts: CNAME lookup FAILED (capture missing); discarding output\n", 2);
			} else {
				$cname_list = file($cname_lookup_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: array();
			}
			@unlink($cname_lookup_file);
			@unlink($cname_lookup_raw_file);
		}

		// Remove 'www.' prefix
		if (str_starts_with($domain, 'www.')) {
			$domain = substr($domain, 4);
		}

		// Whitelist Domain/CNAME(s)
		if (!$dnsbl_exclude) {

			// Issue #37: collect the canonical domains being whitelisted so the same
			// set can be stripped from any user DNSBL Group Custom_List below --
			// reconcile the two user stores instead of only out-ranking at query time.
			$wl_domains = array($domain);

			if (!empty($descr)) {
				if ($wildcard) {
					$whitelist = ".{$domain} # {$descr}";
				} else {
					$whitelist = "{$domain} # {$descr}\r\nwww.{$domain} # {$descr}";
				}
			} else {
				if ($wildcard) {
					$whitelist = ".{$domain}";
				} else {
					$whitelist = "{$domain}\r\nwww.{$domain}";
				}
			}

			// Remove 'Domain and CNAME(s)' from Unbound Resolver pfb_dnsbl.conf file
			if (!empty($cname_list)) {
				$whitelist	.= "\r\n";
				$removed	= "{$domain} | ";

				$cnt = (count($cname_list) -1);
				foreach ($cname_list as $key => $cname) {

					// Remove invalid CNAMES
					$cname = pfb_filter($cname, PFB_FILTER_DOMAIN, 'alerts addwhitelistdom');
					if (empty($cname)) {
						unset($cname_list[$key]);
						continue;
					}

					$removed .= "{$cname} | ";

					$wl_domains[] = $cname;

					if ($wildcard) {
						$whitelist .= '.';
					}
					$whitelist .= "{$cname} # CNAME for ({$domain})";

					if ($cnt != $key) {
						$whitelist .= "\r\n";
					}
				}
				$savemsg = gettext('Removed - Domain|CNAME(s) | ') . "{$removed}";
			}
			else {
				$savemsg = gettext('Removed Domain: [ ') . "{$domain}" . ' ]';
			}
			$savemsg .= gettext(" from DNSBL. You may need to flush your OS/Browser DNS Cache!");

			// Save changes
			if (!isset($clists['dnsblwhitelist']['data'][$domain])) {
				$data = '';
				if (isset($clists['dnsblwhitelist']) && is_array($clists['dnsblwhitelist']['data'])) {
					foreach ($clists['dnsblwhitelist']['data'] as $line) {
						$data .= "{$line}";
					}
				}
				$data .= "{$whitelist}\r\n";
				$clists['dnsblwhitelist']['base64'] = pfb_text_area_encode($data);
				PfbConfig::write('dnsbl/whitelist', $clists['dnsblwhitelist']['base64']);
				write_config("pfBlockerNG: Added [ {$domain} ] to DNSBL Whitelist", FALSE);
			}

			// Issue #37: reconcile the two user stores. Whitelisting a domain is the
			// user's "stop blocking this" intent, so also strip it (its www. and, when
			// wildcarded, leading-dot forms) from every user DNSBL Group Custom_List --
			// the stores then agree at rest, not merely via query-time band precedence
			// (whitelist band 6 > Custom_List band 5). The dead 'grep -vF' of
			// pfb_py_data/pfb_py_zone was removed: under ADR-06 the resolver builds the
			// DNSBL structures from the manifest raws, never those legacy CSVs.
			$cl_changed = array();
			if (isset($clists['dnsbl']) && is_array($clists['dnsbl'])) {
				foreach ($wl_domains as $wl_dom) {
					$variants = array($wl_dom, "www.{$wl_dom}");
					if ($wildcard) {
						$variants[] = ".{$wl_dom}";
					}
					foreach ($clists['dnsbl'] as $lname => $linfo) {
						if (!is_array($linfo) || !isset($linfo['data']) || !is_array($linfo['data'])) {
							continue;	// skip the 'options' helper key
						}
						foreach ($variants as $variant) {
							if (isset($clists['dnsbl'][$lname]['data'][$variant])) {
								unset($clists['dnsbl'][$lname]['data'][$variant]);
								$cl_changed[$lname] = TRUE;
							}
						}
					}
				}
			}
			foreach (array_keys($cl_changed) as $lname) {
				$data = '';
				foreach ($clists['dnsbl'][$lname]['data'] as $line) {
					$data .= "{$line}";
				}
				$clists['dnsbl'][$lname]['base64'] = pfb_text_area_encode($data);
				// foreign structure: pfblockerngdnsbl/config/{row}/custom is a dynamic per-row key, not in registry
				config_set_path("installedpackages/pfblockerngdnsbl/config/{$clists['dnsbl'][$lname]['base64_idx']}/custom", $clists['dnsbl'][$lname]['base64']);
				write_config("pfBlockerNG: Removed [ {$domain} ] from DNSBL Group [ {$lname} ] customlist (whitelisted)", FALSE);
			}
			if (!empty($cl_changed)) {
				$savemsg .= gettext(' Also removed from DNSBL Group customlist(s): ') . implode(', ', array_keys($cl_changed)) . '.';
			}

			// ADR-06: the user whitelist is applied at QUERY TIME via the Python
			// whiteDB. Refresh the whitelist input AND the manifest's
			// config.user_whitelist so the next build's whiteDB un-blocks this domain.
			pfb_unbound_python_whitelist('alerts');
			pfb_unbound_python_sources_whitelist();
			// ADR-10: #51 whitelist add is a block->allow DATA edit -> zero-downtime
			// fast path (no restart). block->allow is immediate (blocks were never
			// C-cached since #43).
			pfb_reload_unbound('enabled', FALSE, FALSE, TRUE);
		}

		// Save Domain/CNAME(s) to the TLD Exclusion customlist
		else {
			$excluded = "{$domain} | ";
			if (!empty($descr)) {
				$exclude_string = "{$domain} # {$descr}";
			} else {
				$exclude_string = "{$domain}";
			}

			// Process CNAME(s)
			if (!empty($cname_list)) {
				$exclude_string .= "\r\n";
				$cnt = (count($cname_list) -1);

				foreach ($cname_list as $key => $cname) {

					// Remove invalid CNAMES
					$cname = pfb_filter($cname, PFB_FILTER_DOMAIN, 'alerts addwhitelistdom');
					if (empty($cname)) {
						unset($cname_list[$key]);
						continue;
					}

					$excluded	.= "{$cname} | ";
					$exclude_string .= "{$cname} # CNAME for ({$domain})";

					if ($cnt != $key) {
						$exclude_string .= "\r\n";
					}
				}
				$savemsg = gettext('Added Domain|CNAME(s) | ') . "{$excluded} ]";
			}
			else {
				$savemsg = gettext('Added Domain [ ') . "{$domain} ]";
			}
			$savemsg .= gettext(" to the TLD Exclusion customlist.");

			if (!isset($clists['tld_wildcard_exclusion']['data'][$domain])) {
				$data = '';
				foreach ($clists['tld_wildcard_exclusion']['data'] as $line) {
					$data .= "{$line}";
				}
				$data .= "{$exclude_string}\r\n";
				$clists['tld_wildcard_exclusion']['base64'] = pfb_text_area_encode($data);
				PfbConfig::write('dnsbl/tld_wildcard_exclusion', $clists['tld_wildcard_exclusion']['base64']);
				write_config("pfBlockerNG: Added [ {$domain} ] to DNSBL TLD Exclusion customlist.", FALSE);
			}
		}
		// issue #2670: durable whitelist/TLD exclusion replaces the temporary unlock row.
		$unlock_drop = pfb_alerts_whitelist_unlock_tokens($domain_unlock, $domain, $dnsbl_exclude, $cname_list);
		$dnsbl_unlock = pfb_alerts_unlock_drop('dnsbl', $dnsbl_unlock, $unlock_drop);
		header("Location: /pfblockerng/pfblockerng_alerts.php?savemsg={$savemsg}");
		exit;
	}

	// Delete entry from customlists (IP Suppression, DNSBL Whitelist, TLD Exclusion and IPv4/6 Permit Customlists)
	elseif (isset($_POST['entry_delete']) && !empty($_POST['entry_delete'])) {

		$entry = '';
		$table = '';
		// issue #1497: every case that reaches the $pfb_found gate below sets $type
		// unconditionally before any read of it; this file-scope name used to be
		// masked by the top-of-file ${"$type"} counter loop's leftover PHP
		// foreach-variable-persists value, which the #1497 explicit-assignment
		// rewrite removed. Same hand-crafted-only class as $table above.
		$type = '';

		// IPv4/IPv6 validation
		if ($entry = pfb_filter($_POST['domain'], PFB_FILTER_IP, 'alerts entry_delete', '', TRUE)) {
			$table = pfb_filter($_POST['table'], PFB_FILTER_WORD, 'alerts entry_delete', '', TRUE);
			if (empty($entry) || empty($table)) {
				$savemsg = "IP: [ {$entry} ] Table name is not valid and IP cannot be removed !";
				header("Location: /pfblockerng/pfblockerng_alerts.php?savemsg={$savemsg}");
				exit;
			}
		}

		// Domain validation
		elseif ($entry = pfb_filter($_POST['domain'], PFB_FILTER_DOMAIN, 'alerts entry_delete')) {
			// Domain
		}
		else {
			$savemsg = gettext('Cannot Delete this entry, value missing or invalid.');
			header("Location: /pfblockerng/pfblockerng_alerts.php?savemsg={$savemsg}");
			exit;
		}

		$pfb_found = TRUE;
		$dnsbl_py_changes = FALSE;

		switch ($_POST['entry_delete']) {
			case 'delete_domain':
				$savemsg = "The Domain [ {$entry} ] has been deleted from the DNSBL Whitelist!";
				if (isset($clists['dnsblwhitelist']['data'][$entry]) ||
				    isset($clists['dnsblwhitelist']['data']['www' . $entry])) {

					if (isset($clists['dnsblwhitelist']['data'][$entry])) {
						unset($clists['dnsblwhitelist']['data'][$entry]);
					}

					if (isset($clists['dnsblwhitelist']['data']['www' . $entry])) {
						unset($clists['dnsblwhitelist']['data']['www' . $entry]);
					}

					// ADR-06: re-blocking is driven by the whiteDB refresh below
					// (gated on $dnsbl_py_changes); the legacy pfb_py_data write was
					// dead (the resolver builds from the manifest, not that CSV).
					$dnsbl_py_changes = TRUE;
				}
			case 'delete_domainwildcard':
				$type = 'DNSBL Whitelist';
				// $savemsg is always set below when this case is reached directly (the
				// condition is a tautology on that path) or already set by the
				// 'delete_domain' fallthrough above; PHPStan can't trace either
				// correlation, so this coalesce is a runtime no-op that keeps the
				// post-switch read provably defined.
				$savemsg = $savemsg ?? '';
				if ($_POST['entry_delete'] == 'delete_domainwildcard') {
					$savemsg = "The Wildcard Domain [ .{$entry} ] has been deleted from the {$type} customlist!";
					if (isset($clists['dnsblwhitelist']['data']['.' . $entry]) ||
					    isset($clists['dnsblwhitelist']['data'][$entry])) {

						if (isset($clists['dnsblwhitelist']['data']['.' . $entry])) {
							unset($clists['dnsblwhitelist']['data']['.' . $entry]);
						}

						if (isset($clists['dnsblwhitelist']['data'][$entry])) {
							unset($clists['dnsblwhitelist']['data'][$entry]);
						}

						// ADR-06: re-blocking is driven by the whiteDB refresh below
						// (gated on $dnsbl_py_changes); the legacy pfb_py_zone write
						// was dead (the resolver builds from the manifest, not that CSV).
						$dnsbl_py_changes = TRUE;
					}
				}

				// Remove Domain from unlock file
				pfb_unlock('lock', 'dnsbl', $dnsbl_unlock, $entry, '');

				$data = '';
				foreach ($clists['dnsblwhitelist']['data'] as $line) {
					// Delete any associated CNAME entries
					if (strpos($line, "({$entry})") === FALSE) {
						$data .= "{$line}";
					}
				}
				$clists['dnsblwhitelist']['base64'] = pfb_text_area_encode($data);
				PfbConfig::write('dnsbl/whitelist', $clists['dnsblwhitelist']['base64']);
				break;
			case 'delete_exclusion':
				$type = 'TLD Exclusion';
				$savemsg = "The Domain [ {$entry} ] has been deleted from the {$type} customlist!";
				if (isset($clists['tld_wildcard_exclusion']['data'][$entry])) {
					unset($clists['tld_wildcard_exclusion']['data'][$entry]);
				}
				$data = '';
				foreach ($clists['tld_wildcard_exclusion']['data'] as $line) {
					$data .= "{$line}";
				}
				$clists['tld_wildcard_exclusion']['base64'] = pfb_text_area_encode($data);
				PfbConfig::write('dnsbl/tld_wildcard_exclusion', $clists['tld_wildcard_exclusion']['base64']);
				break;
			case 'delete_ip':
				// ADR-53 un-suppress rework (#422): the old flow only understood an
				// exact '/32' or a containing '/24' customlist entry and "healed" a
				// legacy exploded /24 block by re-adding up to 254 sibling hosts.
				// ADR-53 tables hold covering CIDRs, not sibling explosions, so that
				// loop no longer applies -- re-adding the removed suppression entry
				// itself restores exactly the coverage it carved out, any mask,
				// either family; any pre-ADR-53 exploded state self-heals on the
				// next reload (the persisted engines rebuild the canonical set).
				$ip	= trim($entry, "'");
				$is_v6	= strpos($ip, ':') !== FALSE;
				$family	= $is_v6 ? 6 : 4;
				$type	= "IPv{$family} Suppression";

				$supp_key	= $is_v6 ? 'ipsuppression_v6' : 'ipsuppression';
				$cfg_key	= $is_v6 ? 'v6suppression' : 'v4suppression';	// bare -- blob index
				$cfg_key_path	= $is_v6 ? 'ip/v6suppression' : 'ip/v4suppression';	// issue #1931: gateway key

				// Longest-prefix pick: when both a '/32' and a broader entry cover
				// the host, remove the most specific one -- deterministic, mirrors
				// the old /32-before-/24 precedence.
				$match = pfb_ip_suppressed_match($ip, array_keys($clists[$supp_key]['data']));
				if ($match !== NULL) {
					// issue #1505: check the re-add before touching the customlist --
					// a failed re-add must leave the suppression entry in place.
					$apply = pfb_pfctl_checked_op($pfb['pfctl'], trim($table, "'"), 'add', $match);
					if ($apply['ok']) {
						unset($clists[$supp_key]['data'][$match]);

						$data = '';
						foreach ($clists[$supp_key]['data'] as $line) {
							$data .= "{$line}";
						}
						$clists[$supp_key]['base64'] = pfb_text_area_encode($data);
						PfbConfig::write($cfg_key_path, $clists[$supp_key]['base64']);

						// Keep pfbsuppression(_v6).txt in step with the config edit --
						// same in-memory refresh the addsuppress handler applies.
						$pfb['ipconfig'][$cfg_key] = $clists[$supp_key]['base64'];
						pfb_create_suppression_file();

						$savemsg = "Removed [ {$match} ] from {$type} customlist and re-added it back into the aliastable [ {$table} ]";
					} else {
						$pfb_found = FALSE;
						$savemsg = "The re-add of [ {$match} ] into aliastable [ {$table} ] failed [ {$apply['fail']} ] -- the {$type} customlist entry was kept; see the pfBlockerNG log.";
					}
				}
				else {
					$pfb_found = FALSE;
					$savemsg = "IP: [ {$entry} ] was not found in {$type} customlist!";
				}
				break;
			case 'delete_ipwhitelist':
				$vtype = 6;
				if (strpos($table, '_v4')) {
					$vtype = 4;
				}

				$table_2 = trim($table, "'");
				$type	= "IPv{$vtype} Permit {$table_2}";
				$ix	= ip_explode(trim($entry, "'"));	// Explode IP into evaluation strings

				if (isset($clists['ipwhitelist' . $vtype][$table_2]['data'][$ix[0]])) {
					// issue #1505: check the delete before touching the customlist --
					// a failed delete must leave the Permit entry in place.
					$apply = pfb_pfctl_checked_op($pfb['pfctl'], $table_2, 'delete', trim($entry, "'"));
					if ($apply['ok']) {
						unset($clists['ipwhitelist' . $vtype][$table_2]['data'][$ix[0]]);

						$data = '';
						foreach ($clists['ipwhitelist' . $vtype][$table_2]['data'] as $line) {
							$data .= "{$line}";
						}

						$clists['ipwhitelist' . $vtype][$table_2]['base64'] = pfb_text_area_encode($data);
						// foreign structure: pfblockernglistsv4/v6/config/{row}/custom is a dynamic per-row key, not in registry
						config_set_path("installedpackages/pfblockernglistsv{$vtype}/config/{$clists['ipwhitelist' . $vtype][$table_2]['base64_idx']}/custom", $clists['ipwhitelist' . $vtype][$table_2]['base64']);
						$aname = substr(substr($table_2, 4),0, -3);					// Remove 'pfB_' and '_v4'
						touch("{$pfb['permitdir']}/{$aname}_custom_v{$vtype}.update");			// Set Flag for Cron/Update process
						$savemsg = "The IP [ {$entry} ] has been deleted from the [ {$table} ] Permit Alias customlist.";
					} else {
						$pfb_found = FALSE;
						$savemsg = "The delete of [ {$entry} ] from aliastable [ {$table} ] failed [ {$apply['fail']} ] -- the {$type} customlist entry was kept; see the pfBlockerNG log.";
					}
				}
				else {
					$pfb_found = FALSE;
					$savemsg = "IP: [ {$entry} ] was not found in {$type} customlist!";
				}
				break;
			default:
				$pfb_found = FALSE;
				$savemsg = gettext('Cannot Delete this entry, invalid delete action.');
				break;
		}

		if ($pfb_found) {
			write_config("pfBlockerNG: Deleted [ {$entry} ] from {$type} customlist", FALSE);
			if ($dnsbl_py_changes) {
				pfb_unbound_python_whitelist('alerts');
				pfb_unbound_python_sources_whitelist();
				// ADR-10: whitelist removal is allow->block. Exact entries get one
				// targeted flush; wildcard removal can affect an unknown set of cached
				// subdomains, so flush the full cache after the applied-generation wait.
				$swapped = pfb_reload_unbound('enabled', FALSE, FALSE, TRUE);
				if ($swapped) {
					if ($_POST['entry_delete'] == 'delete_domainwildcard') {
						exec("{$pfb['chroot_cmd']} flush_zone +c . 2>&1");
					} else {
						pfb_unbound_py_ccache_flush(array($entry));
					}
				}
			}
		}
		header("Location: /pfblockerng/pfblockerng_alerts.php?savemsg={$savemsg}");
		exit;
	}

	// Unlock/Lock DNSBL events
	elseif (isset($_POST['dnsbl_remove']) && !empty($_POST['dnsbl_remove'])) {

		$domain		= pfb_filter($_POST['domain'], PFB_FILTER_DOMAIN, 'alerts dnsbl_remove');
		$dnsbl_type	= pfb_filter($_POST['dnsbl_type'], PFB_FILTER_WORD, 'alerts dnsbl_remove');

		$action		= pfb_filter($_POST['dnsbl_remove'], PFB_FILTER_WORD, 'alerts dnsbl_remove');

		// If Domain or DNSBL type field is empty, exit.
		if (empty($domain) || empty($dnsbl_type)) {
			$savemsg = gettext('Cannot Lock/Unlock - Domain name or DNSBL Type value missing');
			header("Location: /pfblockerng/pfblockerng_alerts.php?savemsg={$savemsg}");
			exit;
		}

		// ADR-06 (#51): DNSBL is built by Unbound's python plugin from the per-feed
		// manifest; the legacy pfb_py_whitelist.txt/pfb_py_data/pfb_py_zone files this
		// handler once wrote are not read on the manifest path (only pfb_unbound.py's
		// legacy CSV fallback still loads them), so writing them was a no-op. Lock/Unlock
		// now only toggles $pfb['dnsbl_unlock']; the resolver effect comes from
		// regenerating the manifest's config.user_unlock from that store and reloading
		// Unbound. Dispatch: pfb_dnsbl_unlock_action() (unit-tested); unknown action = no-op.
		$ua = pfb_dnsbl_unlock_action($action);
		if ($ua['mode'] !== '') {
			pfb_unlock($ua['mode'], 'dnsbl', $dnsbl_unlock, $domain, $dnsbl_type);

			// Patch the manifest's config.user_unlock from the updated store, then
			// reload Unbound so the query-time whiteDB picks up the change.
			pfb_unbound_python_sources_unlock();

			// ADR-10: #51 Lock/Unlock is a user custom-list DATA edit -> zero-downtime
			// fast path (no restart). pfb_dnsbl_unlock_action() collapses the four icons
			// onto two store modes: 'lock' (lock/reunlock) REMOVES the domain from the
			// unlock store -> it returns to feed-blocked = allow->block; 'unlock'
			// (unlock/relock) ADDS it -> allowed = block->allow -> immediate, no flush
			// (blocks were never C-cached since #43).
			// The store toggle (re-lock on Force/Cron) is unchanged -- only the apply
			// mechanism (swap, not restart) changed.
			$swapped = pfb_reload_unbound('enabled', FALSE, FALSE, TRUE);

			if ($swapped) {
				if ($ua['mode'] === 'lock') {
					pfb_unbound_py_ccache_flush(array($domain));
				}
			}
		}

		// sprintf with the (domain-filtered, so '%'-free) name; an unknown action's
		// empty 'msg' yields an empty savemsg.
		$savemsg = sprintf($ua['msg'], $domain);
		header("Location: /pfblockerng/pfblockerng_alerts.php?savemsg={$savemsg}");
		exit;
	}

	// Unlock/Lock IP events -- ADR-53 parity (#1412): the icon now posts the
	// EXACT alerted host (never a feed CIDR), same shape the Suppression "+"
	// already posts, so a single PFB_FILTER_IP call replaces the old v4-only,
	// /24-/32-only split-capture regex; any CIDR-shaped or otherwise invalid
	// $_POST['ip'] (either family) is rejected by is_ipaddr() outright.
	elseif (isset($_POST['ip_remove']) && !empty($_POST['ip_remove'])) {

		$ip	= pfb_filter($_POST['ip'], PFB_FILTER_IP, 'alerts ip_remove');
		$table	= pfb_filter($_POST['table'], PFB_FILTER_WORD, 'alerts ip_remove');

		// If IP or table field is empty, exit.
		if (empty($ip) || empty($table)) {
			$savemsg = gettext('Cannot Lock/Unlock - IP Invalid or table missing');
			header("Location: /pfblockerng/pfblockerng_alerts.php?savemsg={$savemsg}");
			exit;
		}

		$ip_remove_action = NULL;
		if (is_string($_POST['ip_remove']) &&
		    ($_POST['ip_remove'] === 'unlock' || $_POST['ip_remove'] === 'lock')) {
			$ip_remove_action = $_POST['ip_remove'];
		}
		$result = pfb_alerts_ip_action($ip_remove_action, $ip, $table, '', $clists, $ip_unlock);
		if ($result['redirect']) {
			header("Location: /pfblockerng/pfblockerng_alerts.php?savemsg={$result['savemsg']}");
			exit;
		}
	}

	// Whitelist IP events
	elseif (isset($_POST['ip_white']) && $_POST['ip_white'] == 'true') {

		$ip	= pfb_filter($_POST['ip'], PFB_FILTER_IP, 'alerts ip_white');
		$table	= pfb_filter($_POST['table'], PFB_FILTER_WORD, 'alerts ip_white');

		$vtype = '6';
		if (strpos($table, '_v4') !== FALSE) {
			$vtype = '4';
		}

		// If IP or table field is empty, exit.
		if (empty($ip) || empty($table)) {
			$savemsg = gettext('Cannot Whitelist - IP address or Whitelist missing');
			header("Location: /pfblockerng/pfblockerng_alerts.php?savemsg={$savemsg}");
			exit;
		}

		$descr = '';
		if (isset($_POST['descr']) && !empty($_POST['descr'])) {
			$descr = pfb_filter($_POST['descr'], PFB_FILTER_HTML, 'alerts ip_white');
		}

		// Create new IP Whitelist Alias
		if (str_starts_with($table, 'NEW_')) {
			$table = substr($table, 4);
			header("Location: /pfblockerng/pfblockerng_category_edit.php?type=ipv{$vtype}&act=addgroup&atype=Whitelist|{$ip}|{$descr}#Customlist");
			exit;
		}

		$result = pfb_alerts_ip_action('ip_white', $ip, $table, $descr, $clists, $ip_unlock);
		if ($result['redirect']) {
			header("Location: /pfblockerng/pfblockerng_alerts.php?savemsg={$result['savemsg']}");
			exit;
		}
	}
}


// Array of Log Types for Alerts Filter
if ($pfb['filterlogentries']) {
	$filter_unified = array('Block', 'Permit', 'Match', 'DNSBL', 'DNSBL-python', 'DNS-reply');

	// IP/DNSBL/DNS Reply filter events
	if (isset($filterfieldsarray[0]) && isset($filterfieldsarray[1]) && isset($filterfieldsarray[2])) {

		// Filter for all Unified Log types
		$alert_view	= 'unified';
		$active		= array('unified' => TRUE);
	}

	// IP/DNSBL filter events
	elseif (isset($filterfieldsarray[0]) && isset($filterfieldsarray[1])) {
		if ($alert_view == 'reply') {
			$pfbdnscnt = 0;
		} else {
			$pfbdnsreplycnt = 0;
		}
		unset($filter_unified[5]);

		$alert_view	= 'alert';
		$active		= array('alerts' => TRUE);
	}

	// IP/DNS Reply filter events
	elseif (isset($filterfieldsarray[0]) && isset($filterfieldsarray[2])) {
		$pfbdnscnt = 0;
		unset($filter_unified[3], $filter_unified[4]);

		$alert_view	= 'unified';
		$alert_title	= 'Unified Logs';
		$active		= array('unified' => TRUE);
	}

	// DNSBL/DNS Reply filter events
	elseif (isset($filterfieldsarray[1]) && isset($filterfieldsarray[2])) {
		$pfbdenycnt = $pfbpermitcnt = $pfbmatchcnt = 0;
		unset($filter_unified[0], $filter_unified[1], $filter_unified[2]);

		$alert_view	= 'unified';
		$alert_title	= 'Unified Logs';
		$active		= array('unified' => TRUE);
	}

	// IP filter events
	elseif (isset($filterfieldsarray[0])) {
		$pfbdnscnt = $pfbdnsreplycnt = 0;
		unset($filter_unified[3], $filter_unified[4], $filter_unified[5]);

		$alert_view	= 'alert';
		$active		= array('alerts' => TRUE);
	}

	// DNSBL filter events
	elseif (isset($filterfieldsarray[1])) {
		$pfbdenycnt = $pfbpermitcnt = $pfbmatchcnt = 0;
		if ($alert_view == 'reply') {
			$pfbdnscnt = 0;
		} else {
			$pfbdnsreplycnt = 0;
		}
		unset($filter_unified[0], $filter_unified[1], $filter_unified[2], $filter_unified[5]);

		$alert_view	= 'alert';
		$active		= array('alerts' => TRUE);
	}

	// DNS Reply filter events
	elseif (isset($filterfieldsarray[2])) {
		$pfbdenycnt = $pfbpermitcnt = $pfbmatchcnt = $pfbdnscnt = 0;
		unset($filter_unified[0], $filter_unified[1], $filter_unified[2], $filter_unified[3], $filter_unified[4]);

		$alert_view	= 'reply';
		$alert_title	= 'DNS Reply';
		$active		= array('reply' => TRUE);
	}

	if (!empty($filter_unified)) {
		$filter_unified = array_flip($filter_unified);
	}

	// Add Unbound Mode - DNSBL Modes to Unified Filter
	if (isset($filter_unified['DNSBL'])) {
		$filter_unified['DNSBL-1x1'] = '';
		$filter_unified['DNSBL-Full'] = '';
		$filter_unified['DNSBL-HTTPS'] = '';
	}
}

// Define common variables and arrays for report tables
$continents	= array_flip(array('pfB_Africa', 'pfB_Antarctica', 'pfB_Asia', 'pfB_Europe', 'pfB_NAmerica', 'pfB_Oceania', 'pfB_SAmerica', 'pfB_Top'));

// Collect Interfaces
$dnsbl_int = array();
// foreign section: interfaces is a pfSense core section, not in registry
foreach (config_get_path('interfaces', []) as $int) {
	if ($int['ipaddr'] != 'dhcp' && !empty($int['ipaddr']) && !empty($int['subnet'])) {
		$dnsbl_int[] = array("{$int['ipaddr']}/{$int['subnet']}", "{$int['descr']}");
	}
}

// Collect DHCP hostnames/IPs
$local_hosts = pfb_collect_localhosts();

// Collect Alert Statistics
if ($alert_summary) {

	if ($alert_view == 'dnsbl_stat') {
		$stat_info = array(	'dnsblwebtype'  => 1,
					'dnsbldate'	=> 2,
					'dnsblchart'	=> 2,
					'dnsbldatehr'	=> 2,
					'dnsbldatehrmin'=> 2,
					'dnsbldomain'	=> 3,
					'dnsbltld'	=> 3,
					'dnsblip'	=> 4,
					'dnsblagent'	=> 5,
					'dnsblmode'	=> 6,
					'dnsblevald'	=> 8,
					'dnsblfeed'	=> 9);
	}
	elseif ($alert_view == 'dnsbl_reply_stat') {
		$stat_info = array(	'replydate'	=> 2,
					'replychart'	=> 2,
					'replytype'	=> 3,
					'replyorec'	=> 4,
					'replyrec'	=> 5,
					'replyttl'	=> 6,
					'replydomain'	=> 7,
					'replytld'	=> 7,
					'replytld2'	=> 7,
					'replytld3'	=> 7,
					'replysrcipd'	=> 7,
					'replysrcip'	=> 8,
					'replydstip'	=> 9,
					'replygeoip'	=> 10);
	}
	else {
		$stat_info = array(	'ipdate'	=> 1,
					'ipchart'	=> 1,
					'ipinterface'	=> 4,
					'ipprotocol'	=> 8,
					'ipsrcipin'	=> 9,
					'ipsrcipout'	=> 9,
					'ipdstipin'	=> 10,
					'ipdstipout'	=> 10,
					'ipsrcport'	=> 11,
					'ipdstport'	=> 12,
					'ipdirection'	=> 13,
					'ipgeoip'	=> 14,
					'ipaliasname'	=> 15,
					'ipfeed'	=> 17,
					'ipasn'		=> 20);
	}

	// issue #1814 follow-up: BSD cut/sort/uniq (the pfSense/FreeBSD guest's
	// userland) ABORT with "Illegal byte sequence" on an invalid-UTF-8 byte
	// when the process locale is UTF-8 (pfSense's default) -- silently losing
	// EVERY row in the whole stat/chart panel, not just the one bad row.
	// LC_ALL=C forces byte-safe processing; the `export` form (not a leading
	// `VAR=x cmd`, which only binds the first pipeline member) is required so
	// every stage of the exec() pipeline sees it.
	$lc_bytes	= 'LC_ALL=C; export LC_ALL; ';
	$su_cmd		= "sort | uniq -c";
	$grep_cmd	= "{$pfb['grep']} -v";
	$sss_cmd	= "sort | uniq -c | {$pfb['sed']} 's/^ *//' | sort -nr";

	// dnsbl.log/ip logs' date field is now ISO ('Y-m-d H:i:s', one space token
	// before the hour), so the label is date+"("+hour+")" -- one fewer field
	// than the old 3-token 'M j H:i:s' shape this pipeline used to assume.
	// issue #1009: keep the parens UNescaped -- awk string literals need no
	// paren escaping, and mawk prints a literal `\(` where gawk/onetrueawk strip it.
	$chart_cmd = "awk '{\$1=\$1} 1' | awk -F ' ' '{print \$2 \" (\" \$3 \"),\" \$1}' >> /usr/local/www/pfblockerng/chart_stats.csv";

	$alert_stats = array();
	$alert_stats[$alert_view] = array();

	// Skip processing hidden Stats
	$stat_hidden = array();
	if ($alert_view == 'dnsbl_stat') {
		$stat_hidden = $pfbdnsblstat;
	} elseif ($alert_view == 'dnsbl_reply_stat') {
		$stat_hidden = $pfbdnsblreplystat;
	} elseif ($alert_view == 'ip_block_stat') {
		$stat_hidden = $pfbblockstat;
	} elseif ($alert_view == 'ip_permit_stat') {
		$stat_hidden = $pfbpermitstat;
	} elseif ($alert_view == 'ip_match_stat') {
		$stat_hidden = $pfbmatchstat;
	}
	if (!empty($stat_hidden)) {
		$stat_hidden = array_flip($stat_hidden);
	}

	// Total entry count for this view is constant across every $stat_info
	// iteration (the log doesn't change mid-loop), so compute it once here
	// instead of once per iteration (issue #809). The per-iteration assignment
	// below stays IN the loop body -- if every stat type is hidden the loop body
	// never runs, so $alert_stats['count'] must stay unset for this view exactly
	// as it does today.
	// issue #1261: display-only total -- NULL (read failure) -> 0, same as the
	// exec()-era `?: 0` fallback (a legitimately-empty file also yields 0).
	$alert_log_total_count = file_exists($alert_log) ? (pfb_count_lines($alert_log) ?? 0) : 0;

	foreach ($stat_info as $stat_type => $column) {
		if (isset($stat_hidden[$stat_type])) {
			continue;
		}

		if (file_exists($alert_log)) {

			$cut_cmd = "{$pfb['cut']} -d ',' -f{$column}";

			if ($alert_view != 'dnsbl_stat') {
				$unknown_msg = 'Unknown';
			} else {
				$unknown_msg = 'DNSBL Webserver/VIP';
			}

			$agent_cmd = '';
			if ($stat_type == 'dnsblagent') {
				$agent_cmd = "cut -d '|' -f3 | ";
			}

			$stats = array();
			switch ($stat_type) {
				case 'ipdate':
				case 'dnsbldate':
				case 'replydate':
					// ISO date/time has 1 space token (not the old 3-token
					// 'M j H:i:s'); the day bucket is the date field alone.
					// issue #1057: grep skips pre-ISO legacy lines (no digit-year prefix).
					exec("{$lc_bytes}{$cut_cmd} {$alert_log} | {$pfb['grep']} -E '^[0-9]{4}-' | cut -d ' ' -f1 | uniq -c 2>&1", $stats);
					$stats = array_reverse($stats);
					break;
				case 'dnsbldatehr':
					// issue #1057: grep skips pre-ISO legacy lines (no digit-year prefix).
					exec("{$lc_bytes}{$cut_cmd} {$alert_log} | {$pfb['grep']} -E '^[0-9]{4}-' | cut -d ':' -f1 | sort | uniq -c | sort -nr 2>&1", $stats);
					break;
				case 'dnsbldatehrmin':
					// issue #1057: grep skips pre-ISO legacy lines (no digit-year prefix).
					exec("{$lc_bytes}{$cut_cmd} {$alert_log} | {$pfb['grep']} -E '^[0-9]{4}-' | cut -d ':' -f1,2 | sort | uniq -c | sort -nr 2>&1", $stats);
					break;
				case 'dnsblchart':
				case 'replychart':
				case 'ipchart':
					exec("{$lc_bytes}echo 'edate,ecount' > /usr/local/www/pfblockerng/chart_stats.csv");
					exec("{$lc_bytes}{$cut_cmd} {$alert_log} | cut -d ':' -f1 | uniq -c | {$chart_cmd} 2>&1");
					break;
				case 'ipsrcipin':
					exec("{$lc_bytes}{$cut_cmd},13,14,18 {$alert_log} | {$grep_cmd} ',out,' | {$sss_cmd} | {$pfb['sed']} 's/,in,/,/' 2>&1", $stats);
					break;
				case 'ipsrcipout':
					exec("{$lc_bytes}{$cut_cmd},13,14 {$alert_log} | {$grep_cmd} ',in,' | {$sss_cmd} | {$pfb['sed']} 's/,out,/,/' 2>&1", $stats);
 					break;
				case 'ipdstipin':
					exec("{$lc_bytes}{$cut_cmd},13,14 {$alert_log} | {$grep_cmd} ',out,' | {$sss_cmd} | {$pfb['sed']} 's/,in,/,/' 2>&1", $stats);
					break;
				case 'ipdstipout':
					exec("{$lc_bytes}{$cut_cmd},13,14,18 {$alert_log} | {$grep_cmd} ',in,' | {$sss_cmd} | {$pfb['sed']} 's/,out,/,/' 2>&1", $stats);
					break;
				case 'dnsbltld':
				case 'replytld':
					exec("{$lc_bytes}{$cut_cmd} {$alert_log} | awk -F. 'NF>1' | rev | cut -d '.' -f1 | rev | sort | uniq -c | sort -nr 2>&1", $stats);
					break;
				case 'replytld2':
					exec("{$lc_bytes}{$cut_cmd} {$alert_log} | rev | cut -d '.' -f1,2 | awk -F. 'NF>1' | rev | sort | uniq -c | sort -nr 2>&1", $stats);
					break;
				case 'replytld3':
					exec("{$lc_bytes}{$cut_cmd} {$alert_log} | rev | cut -d '.' -f1,2,3 | awk -F. 'NF>2' | rev | sort | uniq -c | sort -nr 2>&1", $stats);
					break;
				case 'ipsrcport':
					exec("{$lc_bytes}{$cut_cmd} {$alert_log} | {$su_cmd} | {$pfb['awk']} -F ' ' '\$2 <= 1024 || \$2 ~ /[a-zA-Z]/' | sort -nr 2>&1", $stats);
					break;
				case 'replyttl':
					exec("{$lc_bytes}{$cut_cmd} {$alert_log} | {$pfb['grep']} -v ',cache,' | {$su_cmd} | sort -nr 2>&1", $stats);
					break;
				case 'dnsbldomain':
					exec("{$lc_bytes}{$cut_cmd},6 {$alert_log} | {$su_cmd} | sort -nr 2>&1", $stats);
					break;
				case 'dnsblevald':
					exec("{$lc_bytes}{$cut_cmd},6 {$alert_log} | {$pfb['grep']} 'TLD' | {$su_cmd} | sort -nr 2>&1", $stats);
					break;
				case 'replysrcipd':
					exec("{$lc_bytes}{$cut_cmd},8 {$alert_log} | {$su_cmd} | sort -nr 2>&1", $stats);
					break;
				case 'ipasn':
					// issue #1369 (ADR-38 Amendment 3): no back-compat for log entries --
					// only the new 23-field schema carries a plain ASN token at column 20
					// (unchanged position: the 2 new columns were appended AFTER it). A
					// pre-upgrade 21-field legacy row's column 20 is still the old
					// pipe-blob text, and any other field count is malformed either way --
					// gate on the exact new field count before extracting, so a legacy/
					// malformed row is skipped silently instead of polluting the Top ASN
					// count with blob noise.
					exec("{$lc_bytes}{$pfb['awk']} -F',' 'NF == 23' {$alert_log} | {$cut_cmd} | {$agent_cmd} {$su_cmd} | sort -nr 2>&1", $stats);
					break;
				default:
					exec("{$lc_bytes}{$cut_cmd} {$alert_log} | {$agent_cmd} {$su_cmd} | sort -nr 2>&1", $stats);
					break;
			}

			if (!empty($stats)) {
				foreach($stats as $key => $line) {

					// Remove last column for '-' and '+' indicator
					$eol = substr($line, -2);
					if ($eol == ' -' || $eol == ' +') {
						continue;
					}

					$data = array_map('trim', explode(' ', trim($line), 2));
					// issue #1792: a stat label of literally '0' is a real
					// label -- only a MISSING/empty field reads "Unknown".
					$alert_stats[$alert_view][$stat_type][pfb_is_empty($data[1] ?? NULL) ? $unknown_msg : $data[1]] = (int) $data[0];
				}
			}
			else {
				$alert_stats[$alert_view][$stat_type] = array();
				if ($alert_view == 'dnsbl_stat') {
					$alert_stats[$alert_view]['dnsblgptotal'] = array();
					$alert_stats[$alert_view]['dnsblgpblock'] = array();
				}
			}
			// The exec is hoisted above the loop (issue #809); this assignment
			// stays here so an all-hidden $stat_info leaves $alert_stats['count']
			// unset for this view, exactly as before.
			$alert_stats['count'][$alert_view] = $alert_log_total_count;
		}
		else {
			$alert_stats[$alert_view][$stat_type]	= array();
			$alert_stats['count'][$alert_view]	= 0;
			if ($alert_view == 'dnsbl_stat') {
				$alert_stats[$alert_view]['dnsblgptotal'] = array();
				$alert_stats[$alert_view]['dnsblgpblock'] = array();
			}

			if ($stat_type == 'dnsblchart' || $stat_type == 'replychart' || $stat_type == 'ipchart') {
				exec("{$lc_bytes}echo 'edate,ecount' > /usr/local/www/pfblockerng/chart_stats.csv");
			}
		}
	}

	// Collect DNSBL widget statistics
	if ($alert_view == 'dnsbl_stat') {
		$alert_stats[$alert_view]['dnsblgptotal'] = array();
		$alert_stats[$alert_view]['dnsblgpblock'] = array();

		if (file_exists($pfb['dnsbl_info'])) {
			$db_handle = pfb_open_sqlite(1, 'Report Stats');
			if ($db_handle) {
				$result = $db_handle->query("SELECT * FROM dnsbl;");
				if ($result) {
					while ($res = $result->fetchArray(SQLITE3_ASSOC)) {

						$res['groupname'] = pfb_filter($res['groupname'], PFB_FILTER_HTML, 'alerts widget stat');
						if (!empty($res['groupname'])) {
							if ($res['entries'] == 'disabled') {
								$res['entries']		= 0;
								$res['groupname']	= "{$res['groupname']}&emsp;(Disabled)";
							}

							$alert_stats[$alert_view]['dnsblgptotal'][$res['groupname']] = pfb_filter($res['entries'], PFB_FILTER_NUM, 'alerts widget stat', '0');
							$alert_stats[$alert_view]['dnsblgpblock'][$res['groupname']] = pfb_filter($res['counter'], PFB_FILTER_NUM, 'alerts widget stat', '0');
						}
					}

					array_multisort($alert_stats[$alert_view]['dnsblgptotal'], SORT_DESC, 1);
					array_multisort($alert_stats[$alert_view]['dnsblgpblock'], SORT_DESC, 1);
				}
			}
			$db_handle->close();
			unset($db_handle);
		}
	}
}


// HTML-encode a log/host-derived data token before it is folded into the
// Alerts/Reports table markup. Every value that originates from a parsed log
// line, a resolved/DHCP hostname, or an IDN conversion must pass through this
// at the point it enters cell markup, so HTML metacharacters render as text
// (the intentional static markup around it stays unencoded).
function pfb_hsc($value) {
	// ENT_SUBSTITUTE: without it, ANY invalid-UTF-8 byte anywhere in $value makes
	// htmlspecialchars() return '' -- blanking the WHOLE string, not just the offending
	// byte (issue #1814). With it, the invalid byte alone is replaced with U+FFFD and the
	// rest of the value still renders.
	$encoded = htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

	// Unicode bidirectional controls survive HTML encoding -- they are not metacharacters --
	// and reverse the display order of everything after them, so a log-derived domain, feed
	// name or hostname can render as something other than the bytes actually logged
	// (issue #2041). Config text never reaches here carrying one: pfb_sanitize_text() strips
	// \p{C} at the persist boundary (issue #1723). Log-derived values have no such gate.
	//
	// Stripped AFTER encoding, not before: ENT_SUBSTITUTE guarantees its output is valid
	// UTF-8, and preg_replace()'s /u modifier returns NULL on invalid input -- stripping
	// first would hand that NULL straight into the cell for exactly the malformed values
	// #1814 exists to keep rendering. No entity htmlspecialchars() emits is in this set, so
	// running after it cannot corrupt one.
	//
	// Only the bidi set, not all of \p{C}: this is the encode chokepoint for every Alerts
	// and Reports cell, and \p{C} would also take newlines and tabs out of values that may
	// legitimately carry them.
	// The marks (U+061C, U+200E, U+200F), the embedding/override set (U+202A-U+202E) and
	// the isolates (U+2066-U+2069). None carry textual content.
	$stripped = preg_replace('/[\x{061C}\x{200E}\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}]/u', '', $encoded);

	return $stripped === NULL ? $encoded : $stripped;
}

// Truncate a RAW log/host-derived token to $length CHARACTERS (never bytes), so a
// multibyte character straddling the cut survives whole instead of leaving a
// dangling lead byte for pfb_hsc()'s ENT_SUBSTITUTE to replace (issue #1815). An
// invalid byte within the kept prefix is still replaced with U+FFFD -- the same
// symbol pfb_hsc()'s ENT_SUBSTITUTE produces (issue #1814) -- by pinning
// mb_substitute_character() for the duration of the call; mb_substr()'s own
// default substitute ('?') would otherwise fabricate a character the input never
// carried. mb_substitute_character() is request-global state, so the prior value
// is restored on every exit path -- the finally is what makes that true for a
// throwing $value cast as well as the normal return.
function pfb_truncate($value, $length) {
	$prev = mb_substitute_character();
	mb_substitute_character(0xFFFD);
	try {
		return mb_substr((string) $value, 0, $length, 'UTF-8');
	} finally {
		mb_substitute_character($prev);
	}
}

// Compose the resolved-hostname stats cell for the IP src/dst-in stats. The raw
// hostname is attacker-influenceable, so HTML-encode it; a >45-char value is
// truncated for display with the full value kept in the title attribute.
// issue #1069: truncate the RAW value THEN encode -- encoding first then substr()
// can split a named entity (&quot; -> &qu) or a multibyte char.
function pfb_stat_hostname_cell($resolved) {
	$resolved = (string) $resolved;
	$full = pfb_hsc($resolved);
	if (mb_strlen($resolved, 'UTF-8') > 45) {
		$title = "title=\"{$full}\"";
		$cell  = pfb_hsc(pfb_truncate($resolved, 45)) . "<small>...</small>";
	} else {
		$title = '';
		$cell  = $full;
	}
	return "<br /><span {$title}><small>{$cell}</small></span>";
}

// Function to Filter Alerts report on user defined input
function pfb_match_filter_field($flent, $fields) {

	if (isset($fields)) {
		foreach ($fields as $key => $field) {

			$not_filter = FALSE;
			if (str_starts_with($field, '!')) {
				$not_filter = TRUE;
				$field = substr($field, 1);
			}

			$field_regex = str_replace('/', '\/', str_replace('\/', '/', $field));
			if (strpos($field_regex, '(') !== FALSE) {
				$field_regex = str_replace('(', '\(', str_replace('\(', '(', $field_regex));
				$field_regex = str_replace(')', '\)', str_replace('\)', ')', $field_regex));
			}
			if (strpos($field_regex, '[') !== FALSE) {
				$field_regex = str_replace(']', '\]', str_replace('\]', ']', $field_regex));
				$field_regex = str_replace('[', '\[', str_replace('\[', '[', $field_regex));
			}

			// Remove 'AS' characters from ASN queries
			if ($key == 18) {
				$field_regex = str_replace('AS', '', $field_regex);
			}

			if ($not_filter) {
				if (@preg_match("/{$field_regex}/i", $flent[$key])) {
					return FALSE;
				}
			} else {
				if (!@preg_match("/{$field_regex}/i", $flent[$key])) {
					return FALSE;
				}
			}
		}
	}
	return TRUE;
}

/* Render-time attribution model (docs/misc/alerts-reports-pipeline.md; perf: issue #809)

   The logs already carry full event-time attribution: pfb_unbound.py writes the DNSBL/
   DNS-reply verdicts, and the filterlog daemon (pfb_daemon_filterlog) resolves the bare
   pf event into rule/feed/GeoIP/rDNS/ASN once, at event time, caching in its ipcache.
   DNSBL rows therefore render their logged fields directly — no render-time lookup.
   Issue #1349 removed the retired per-row re-check and drill machinery. Only
   the IP converter still re-checks the logged attribution against the CURRENT feed state
   (drift strikethrough + icon decisions): the issue #809 batched pfb_ip_prefetch() pass seeds
   in-process memos to cut per-row execs, but has no PERSISTENT cache (ipcache is daemon-write-
   only, never read here). See the doc before changing lookup ordering or caching here. */

// Function to collect DNSBL Log event details based on Blocking mode field
function dnsbl_log_details($fields) {
	global $clists;

	$isTLD = $isCNAME = $isPython = $isExclusion = FALSE;
	$pfb_python = $wt_line = '';

	if (strpos($fields[5], 'TLD') !== FALSE) {
		$isTLD		= TRUE;
	}
	if (strpos($fields[5], '_CNAME') !== FALSE) {
		$isCNAME	= TRUE;
		$pfb_python	= "&nbsp;<i class=\"fa-solid fa-bolt\" title=\"CNAME Validation\"></i>";
	}
	if (strpos($fields[5], 'Python') !== FALSE) {
		$isPython	= TRUE;
		$pfb_python	= "&nbsp;<i class=\"fa-solid fa-bolt\" title=\"" . pfb_hsc($fields[5]) . "\"></i>";
	}

	// Select blocked Domain or Evaluated Domain
	$qdomain = $fields[2];
	if ($isTLD || $isCNAME) {
		$qdomain = $fields[7];
	}

	// Determine if blocked Domain is a TLD Exclusion
	if ($isTLD && isset($clists['tld_wildcard_exclusion']['data'][$fields[7]])) {
		$wt_line = rtrim($clists['tld_wildcard_exclusion']['data'][$fields[7]], "\x00..\x1F");
		$isExclusion = TRUE;
	}

	return array($isTLD, $isCNAME, $isPython, $isExclusion, $pfb_python, $qdomain, $wt_line);
}


// Function to determine Whitelist type for DNSBL and DNS Reply
function dnsbl_whitelist_type($fields, $clists, $isExclusion, $isTLD, $qdomain) {
	global $pfb;

	$isWhitelist_found = FALSE;

	// HTML-encoded copies of the log-derived tokens that get folded into the
	// title/id/href markup below (the raw values are still used for lookups).
	$h_f2		= pfb_hsc($fields[2]);
	$h_f6		= pfb_hsc($fields[6]);
	$h_f7		= pfb_hsc($fields[7]);
	$h_f8		= pfb_hsc($fields[8]);
	$h_qdomain	= pfb_hsc($qdomain);

	$ex_dom = $s_txt = '';
	if ($isExclusion) {
		$wt_line = rtrim(array_get_path($clists, "tld_wildcard_exclusion/data/{$fields[7]}", ''), "\x00..\x1F");
		$h_wt_line = pfb_hsc($wt_line);
		$s_txt  = "Note:&emsp;The following Domain is in the TLD Exclusion customlist:\n\n"
			. "TLD Exclusion:&emsp;[ {$h_wt_line} ]\n\n"
			. "&#8226; TLD Exclusions require a Force Reload when a Domain is initially added.\n"
			. "&#8226; To remove this Domain from the TLD Exclusion customlist, Click 'OK'";

		$ex_dom = '&nbsp;<i class="fa-regular fa-trash-can no-confirm icon-pointer" id="DNSBLWT|'
			. 'delete_exclusion|' . $h_f7 . '" title="' . $s_txt . '"></i>';
	}

	$supp_dom = $s_txt = '';
	// Default Whitelist text for DNSBL/TLD domains
	if ($isTLD) {
		$s_txt  = "Note:&emsp;The following Domain was Wildcard blocked via TLD.\n\n"
			. "Blocked Domain:&emsp;&emsp;[ {$h_f2} ]\n"
			. "Evaluated Domain:&emsp;&nbsp;[ {$h_f7} ]\n\n"
			. "DNSBL Groupname:&emsp;[ {$h_f6} ]\n"
			. "DNSBL Feedname:&emsp;&nbsp;&nbsp;[ {$h_f8} ]\n\n";

		$s_txt .= "Whitelist [ {$h_f2} ]\n\n"
			. "Note:&emsp;This will immediately remove the blocked Domain\n"
			. "&emsp;&emsp;&emsp;&nbsp;and associated CNAMES from DNSBL.\n"
			. "&emsp;&emsp;&emsp;&nbsp;(CNAMES: Define the external DNS server in Alert settings\n"
			. "&emsp;&emsp;&emsp;&nbsp;&nbsp;and ensure that the Resolver has access to the External DNS server.)\n\n"
			. "Whitelisting Options:\n\n"
			. "1) Wildcard whitelist [ .{$h_f2} ]\n"
			. "2) Whitelist only [ {$h_f2} ]\n";
	}
	else {
		$s_txt = "Whitelist [ {$h_f2} ]\n\n"
			. "Note:&emsp;This will immediately remove the blocked Domain\n"
			. "&emsp;&emsp;&emsp;&nbsp;and associated CNAMES from DNSBL.\n"
			. "&emsp;&emsp;&emsp;&nbsp;(CNAMES: Define the external DNS server in Alert settings\n"
			. "&emsp;&emsp;&emsp;&nbsp;&nbsp;and ensure that the Resolver has access to the External DNS server.)\n\n"
			. "Whitelisting Options:\n\n"
			. "1) Wildcard whitelist [ .{$h_f2} ]\n"
			. "2) Whitelist only [ {$h_f2} ]\n";
	}

	// Determine if Domain is blocked via TLD Blacklist
	if ($fields[5] != 'DNSBL_TLD') {

		// Remove Whitelist Icon for 'Unknown'
		if ($fields[6] != 'Unknown') {
		
			// Default - Domain not in Whitelist
			$supp_dom = '<i class="fa-solid fa-plus icon-pointer" id="DNSBLWT|' . 'add|'
					. $h_f7 . '|' . $h_f8 . '" title="' . $s_txt . '"></i>';
		}

		// Determine if Blocked Domain is in DNSBL Whitelist
		if (isset($clists['dnsblwhitelist']['data'][$fields[2]])) {
			$w_line = rtrim($clists['dnsblwhitelist']['data'][$fields[2]], "\x00..\x1F");
			$h_w_line = pfb_hsc($w_line);
			$isWhitelist_found = TRUE;

			// Verify if the Whitelisted Domain matches the Evaluated Domain
			if ($fields[2] == $qdomain || $fields[6] == 'Unknown') {
				$s_txt = "Note:&emsp;The following Domain exists in the DNSBL Whitelist:\n\n"
					. "Whitelisted:&emsp;[ {$h_w_line} ]\n\n"
					. "To remove this Domain from the DNSBL Whitelist, press 'OK'";
			} else {
				$s_txt = "Note:&emsp;The following Domain exists in the DNSBL Whitelist:\n\n"
					. "Whitelisted:&emsp;[ {$h_w_line} ]\n\n"
					. "However it is still being Wildcard blocked by the following Domain:\n"
					. "Whitelisted:&emsp;[ {$h_qdomain} ]\n\n"
					. "To remove this Domain [ {$h_f2} ] from the DNSBL Whitelist"
					. ", Click 'OK'";
			}
			$supp_dom = '<i class="fa-solid fa-trash-can no-confirm icon-pointer" id="DNSBLWT|'
					. 'delete_domain|' . $h_f2 . '" title="' . $s_txt . '"></i>';
		}

		// Determine if Blocked Domain is in DNSBL Whitelist (prefixed by a "dot" )
		elseif (!empty($clists['dnsblwhitelist']['data'])) {

			$q_wdomain = ltrim($fields[7], '.');	// Is this needed?
			$dparts	= explode('.', $q_wdomain);
			$dcnt	= count($dparts);
			for ($i=$dcnt; $i > 0; $i--) {

				$d_query = implode('.', array_slice($dparts, -$i, $i, TRUE));
				if (isset($clists['dnsblwhitelist']['data']['.' . $d_query])) {
					$w_line = rtrim($clists['dnsblwhitelist']['data']['.' . $d_query], "\x00..\x1F");
					$h_w_line = pfb_hsc($w_line);
					$h_d_query = pfb_hsc($d_query);
					$isWhitelist_found = TRUE;

					if ($d_query == $qdomain || $fields[6] == 'Unknown') {
						$s_txt = "Note:&emsp;The following Domain exists"
							. " in the DNSBL Whitelist:\n\n"
							. "Whitelisted:&emsp;[ {$h_w_line} ]\n\n"
							. "To remove this Domain from the DNSBL Whitelist,"
							. " press 'OK'";
					} else {
						$s_txt = "Note:&emsp;The following Domain exists in the"
							. " DNSBL Whitelist:\n\n"
							. "Whitelisted:&emsp;[ {$h_w_line} ]\n\n"
							. "However it is still being Wildcard blocked"
							. " by the following Domain:\n"
							. "Whitelisted:&emsp;[ {$h_qdomain} ]\n\n"
							. "To remove this Domain [ {$h_d_query} ]"
							. "from the DNSBL Whitelist, Click 'OK'";
					}
					$supp_dom = '<i class="fa-solid fa-trash-can no-confirm icon-pointer"'
							. ' id="DNSBLWT|' . "delete_domainwildcard|" . $h_d_query
							. '" title="' . $s_txt . '"></i>';
					break;
				}
			}
		}

		// Root Domain blocking all Sub-Domains and is not in whitelist and not in TLD Exclusion
		if ($isTLD && !$isWhitelist_found && !$isExclusion) {
			$supp_dom = '<i class="fa-solid fa-plus-circle icon-pointer" id="DNSBLWT|' . 'add|'
				. $h_f7 . '|' . $h_f8 . '|' . pfb_hsc($fields[5]) . '" title="' . $s_txt . '"></i>';
		}
	}

	// Whole TLD is blocked
	else {
		$s_txt  = "Note:&emsp;The following Domain was blocked via 'DNSBL TLD' (TLD Blacklist):\n\n"
			. "Blocked Domain:&emsp;&emsp;[ {$h_f2} ]\n"
			. "Evaluated Domain:&emsp;&nbsp;[ {$h_f7} ]\n\n"
			. "Add [ {$h_f2} ] to the TLD Whitelist?";

		$supp_dom = '<i class="fa-regular fa-hand icon-pointer" id="DNSBLWT|' . 'tld|'
			. $h_f2 . '|' . $h_f7 . '" title="' . $s_txt . '"></i>';
	}

	return array ($supp_dom, $ex_dom, $isWhitelist_found);
}


/**
 * `|alias…` suffix for PFBIPSUP / PFBIPWHITE ids from one family's `$clists` entry.
 * Shared by the event-table suppression icon and the Unlocked panel.
 */
function pfb_alerts_permit_option_suffix($family): string
{
	if (!is_array($family) || empty($family['options']) || !is_array($family['options'])) {
		return '';
	}
	return '|' . implode('|', $family['options']);
}


/**
 * Action icons for one Unlocked IPs/Domains panel row (Alerts tab).
 * Temporary unlock and permanent whitelist/suppression stay independent (issue #1526).
 *
 * Confirm-dialog titles shadow the event-table copies in convert_ip_log()
 * `$supp_ip_txt` and dnsbl_whitelist_type() `$s_txt`, shortened for the panel
 * (no feed/eval-IP, no Force-Update / CNAME parenthetical).
 *
 * @return array{alert: string, unlock: string, supp: string}
 */
function pfb_alerts_unlocked_entry_actions(string $kind, string $entry, string $type, array $clists): array
{
	$h_entry = pfb_hsc($entry);
	$h_type  = pfb_hsc($type);

	if ($kind === 'ip') {
		$unlock = '<i class="fa-solid fa-unlock text-primary" id="IPLCK|' . $h_entry . '|' . $h_type
			. '" title="Re-Lock IP: [ ' . $h_entry . ' ] back into Aliastable [ '
			. $h_type . ' ]? "></i>';
		$alert = '<a class="fa-solid fa-info icon-pointer" target="_blank" rel="noopener noreferrer"'
			. ' href="/pfblockerng/pfblockerng_threats.php?host='
			. $h_entry . '" title="Click for Threat source IP Lookup for [ ' . $h_entry . ' ]"></a>';
		$vtype = (strpos($entry, ':') !== FALSE) ? '6' : '4';
		$permit_option = pfb_alerts_permit_option_suffix($clists['ipwhitelist' . $vtype] ?? NULL);
		$supp_txt = "Note:&emsp;The following IPv{$vtype} is temporarily unlocked:\n\n"
			. "IP:&emsp;[ {$h_entry} ]\n"
			. "IP Aliasname:&emsp;[ {$h_type} ]\n\n"
			. "Whitelisting Options:\n\n"
			. "1) Suppress the IP.\n"
			. "2) Whitelist the IP to an existing 'Permit' Alias customlist.\n\n"
			. "Click 'OK' to continue";
		$supp = '<i class="fa-solid fa-plus icon-pointer" id="PFBIPSUP|' . 'add|' . $h_entry
			. '|' . $h_type . $permit_option
			. '" title="' . $supp_txt . '"></i>';
	} else {
		$unlock = '<i class="fa-solid fa-unlock text-primary" id="DNSBL_LCK|' . $h_entry . '|' . $h_type
			. '" title="Re-Lock Domain: [ ' . $h_entry . ' ] back into DNSBL? "></i>';
		$alert = '<a class="fa-solid fa-info icon-pointer" target="_blank" rel="noopener noreferrer"'
			. ' href="/pfblockerng/pfblockerng_threats.php?domain='
			. $h_entry . '" title="Click for Threat source Domain Lookup for [ ' . $h_entry . ' ]"></a>';
		$supp_txt = "Whitelist [ {$h_entry} ]\n\n"
			. "Note:&emsp;This will immediately remove the blocked Domain\n"
			. "&emsp;&emsp;&emsp;&nbsp;and associated CNAMES from DNSBL.\n\n"
			. "Whitelisting Options:\n\n"
			. "1) Wildcard whitelist [ .{$h_entry} ]\n"
			. "2) Whitelist only [ {$h_entry} ]\n";
		$tld_field = (strpos($type, 'TLD') !== FALSE) ? '|TLD' : '';
		$supp = '<i class="fa-solid fa-plus icon-pointer" id="DNSBLWT|' . 'add|'
			. $h_entry . '|' . $h_type . $tld_field . '" title="' . $supp_txt . '"></i>';
	}

	return array('alert' => $alert, 'unlock' => $unlock, 'supp' => $supp);
}


// Function to convert dnsbl.log -> Reports Tab
function convert_dnsbl_log($mode, $fields) {
	global $pfb, $pfb_webgui_dark, $local_hosts, $dnsbl_int, $filterfieldsarray, $clists, $dnsbl_unlock, $dup, $counter,
		$pfbentries, $skipcount, $dnsblfilterlimit, $dnsblfilterlimitentries;

	if ($dnsblfilterlimit) {
		return TRUE;
	}

	// Counter/limit gate (issue #809): the non-filter limit check runs first,
	// unconditionally. The filter-mode limit gate stays after the filter-MATCH gate
	// below -- it only trips on rows that pass the match, so hoisting it would
	// mis-flag a post-limit tail of non-matching rows.
	if (!$pfb['filterlogentries'] &&
		$counter[$mode == 'Unified' && !$pfb['filterlogentries'] ? 'Unified' : 'DNSBL'] >= $pfbentries) {
		$dnsblfilterlimit = TRUE;
		return TRUE;
	}

	/* dnsbl.log Fields Reference

		[0]	= DNSBL prefix - Python mode: 'DNSBL-python' | Unbound Mode: 'DNSBL-Full', 'DNSBL-1x1' or 'DNSBL-HTTPS'
		[1]	= Date/Timestamp
		[2]	= Domain name
		[3]	= Source IP
		[4]	= DNSBL Type - Python mode: 'Python', 'HSTS' Suffix A/AAAA | Unbound Mode: URL/Referer/URI/Agent String
		[5]	= DNSBL Mode - 'DNSBL', 'TLD', 'DNSBL TLD' Suffix A/AAAA/CNAME
		[6]	= Group Name
		[7]	= Evaluated Domain/TLD
		[8]	= Feed Name
		[9]	= Duplicate ID indicator / Count
		[10]	= Query Type - Python mode only: 'A', 'AAAA', 'ANY', ... (absent on older/Unbound-mode lines, where A/AAAA is carried in the b_type suffix [5])

	pfbalertdnsbl fields array reference (Used for filter functionality)

		[2]	= Interface
		[7]	= SRC IP address
		[8]	= Domain name
		[13]	= Group Name
		[15]	= Feed Name
		[19]	= DNSBL Type 
		[20]	= DNSBL Mode
		[99]	= Date/Timestamp		*/

	// Remove 'Unknown' for Agent field
	if ($fields[4] == 'Unknown') {
		$fields[4] = '';
	}

	// Upstream DNS block (logged by _log_upstream_block; not a local feed entry).
	$isUpstream = ($fields[5] === 'Upstream_Block');

	// Determine event parameters
	list ( $isTLD, $isCNAME, $isPython, $isExclusion, $pfb_python, $qdomain, $wt_line ) = dnsbl_log_details($fields);

	// Determine Whitelist type
	list ( $supp_dom, $ex_dom, $isWhitelist_found ) = dnsbl_whitelist_type($fields, $clists, $isExclusion, $isTLD, $qdomain);

	// ADR-65: rows render their OWN logged fields -- the render-time re-check
	// against the (retired) interchange files is gone; no group/feed/mode/domain
	// drift refinement runs here anymore.

	// Upstream block: override icon to cloud (uses raw fields[7]/[8] before truncation below).
	if ($isUpstream) {
		$pfb_python = "&nbsp;<i class=\"fa-solid fa-cloud\" title=\"Upstream Block: " . pfb_hsc($fields[7]) . " [ " . pfb_hsc($fields[8]) . " ]\"></i>";
	}

	// Filter Field array
	$pfbalertdnsbl = array();

	// Determine interface name based on Source IP address
	$pfbalertdnsbl[2] = 'LAN';		// Define LAN Interface as 'default'
	if (!empty($dnsbl_int)) {
		foreach ($dnsbl_int as $subnet) {
			if (strpos($fields[3], 'Unknown') !== FALSE) {
				$pfbalertdnsbl[2] = 'Unknown';
				break;
			} elseif (ip_in_subnet($fields[3], $subnet[0])) {
				$pfbalertdnsbl[2] = pfb_hsc($subnet[1]);
				break;
			}
		}
	}

	// SRC IP Address and Hostname
	$hostname = array_key_exists($fields[3], $local_hosts) ? $local_hosts[$fields[3]] : '';
	if (!empty($hostname)) {
		$h_title		= '';
		if (mb_strlen($hostname, 'UTF-8') >= 25) {
			$h_title	= pfb_hsc($hostname);
			$hostname	= pfb_hsc(pfb_truncate($hostname, 24)) . "<small>...</small>";
		} else {
			$hostname	= pfb_hsc($hostname);
		}

		$pfbalertdnsbl[7]	= pfb_hsc($fields[3]);
		$pfbalertdnsbl[17]	= "<span title=\"{$h_title}\">{$hostname}</span>";
	} else {
		$pfbalertdnsbl[7]	= pfb_hsc($fields[3]);
		$pfbalertdnsbl[17]	= '';
	}

	$f2 = $fields[2];
	if (strpos($f2, 'xn--') !== FALSE) {
		$f2 = "{$f2} [" . idn_to_utf8($f2) . "]";
	}
	if (mb_strlen($f2, 'UTF-8') >= ($mode != 'Unified' ? 60 : 40)) {
		$f2 = pfb_hsc(pfb_truncate($f2, ($mode != 'Unified' ? 59 : 39))) . "<small>...</small>";
	} else {
		$f2 = pfb_hsc($f2);
	}

	if ($isCNAME) {
		$f7 = $fields[7];
		if (strpos($f7, 'xn--') !== FALSE) {
			$f7		= "{$f7} [" . idn_to_utf8($f7) . "]";
		}
		if (mb_strlen($f7, 'UTF-8') >= ($mode != 'Unified' ? 52 : 32)) {
			$f7		= pfb_hsc(pfb_truncate($f7, ($mode != 'Unified' ? 51 : 31))) . "<small>...</small>";
		} else {
			$f7		= pfb_hsc($f7);
		}
		$pfbalertdnsbl[8]	= "Domain: {$f2}<br />CNAME: {$f7}";
	} else {
		$pfbalertdnsbl[8]	= "{$f2}";
	}

	$f_g_title = '';

	// Add Title - Header line to Feed/Group
	if ($fields[6] == 'Unknown') {
		if ($isTLD) {
			$f_g_title = "The domain: [ " . pfb_hsc($fields[7]) . " ] is not currently listed in DNSBL as a TLD wildcard blocked domain.";
		} else {
			$f_g_title = 'The domain is not currently listed in DNSBL!';
		}
	}
	else {
		$f_g_title = "The Feed and Group that blocked the indicated Domain:";
	}

	if (!empty($fields[8])) {
		$f_g_title .= "&#013;Feed: " . pfb_hsc($fields[8]);
	}
	if (!empty($fields[6])) {
		$f_g_title .= "&#013;Group: " . pfb_hsc($fields[6]);
	}

	$pfbalertdnsbl[13]	= pfb_hsc($fields[6]);
	$pfbalertdnsbl[15]	= pfb_hsc($fields[8]);

	// Group the Feed/Group cell by record; no previous value to strike anymore (ADR-65).
	$feed_group_cell = pfb_dnsbl_feed_group_cell('', pfb_hsc($fields[8]), '', pfb_hsc($fields[6]));

	// Query type suffix (Python mode logs the record type as field [10]; older
	// Unbound-mode lines carry it in the b_type suffix [5] and lack field [10]).
	$qtype_sfx = '';
	if (isset($fields[10])) {
		$qtype = trim($fields[10]);
		if ($qtype != '' && $qtype != 'Unknown') {
			$qtype_sfx = " | " . pfb_hsc($qtype);
		}
	}

	if (!empty($fields[4])) {
		if (mb_strlen($fields[4], 'UTF-8') >= 25) {
			$f4 = pfb_hsc(pfb_truncate($fields[4], 24)) . "<small>...</small>";
			$fields[4] = "<span title=\"" . pfb_hsc($fields[4]) . "\">{$f4}</span>";
		} else {
			$fields[4] = pfb_hsc($fields[4]);
		}
		$pfbalertdnsbl[19] = pfb_hsc($fields[0]) . " | {$fields[4]}{$qtype_sfx}";
	} else {
		$pfbalertdnsbl[19] = pfb_hsc($fields[0]) . "{$qtype_sfx}";
	}

	$pfbalertdnsbl[20]	= pfb_hsc($fields[5]);

	$pfbalertdnsbl[99]	= pfb_hsc($fields[1]);	// Timestamp

	// If alerts filtering is selected, process filters as required. ADR-65: a
	// feed/group-name filter now matches the LOGGED value ($pfbalertdnsbl is built
	// straight from $fields), not a re-derived current one.
	if ($pfb['filterlogentries']) {
		if (empty($filterfieldsarray[1])) {
			return TRUE;
		}
		if (!pfb_match_filter_field($pfbalertdnsbl, $filterfieldsarray[1])) {
			return FALSE;
		}
		if ($dnsblfilterlimitentries != 0 && $counter[$mode == 'Unified' && !$pfb['filterlogentries'] ? 'Unified' : 'DNSBL'] >= $dnsblfilterlimitentries) {
			$dnsblfilterlimit = TRUE;
			return TRUE;
		}
	}
	$counter[$mode == 'Unified' && !$pfb['filterlogentries'] ? 'Unified' : 'DNSBL']++;

	// Determine Whitelist type
	list($supp_dom, $ex_dom, $isWhitelist_found) = dnsbl_whitelist_type($fields, $clists, $isExclusion, $isTLD, $qdomain);

	// Lock/Unlock Domain Icon
	$s_txt = '';
	$unlock_dom = '&nbsp;&nbsp;&nbsp;';


	$tnote = "\n\nNote:&emsp;&#8226; Unlocking Domain(s) is temporary and may be automatically\n"
		. "&emsp;&emsp;&emsp;&emsp;re-locked on a Cron or Force command with an Unbound Reload!\n"
		. "&emsp;&emsp;&emsp;&nbsp;&#8226; Review Threat Source ( i ) Icon for Domain details.\n"
		. "&emsp;&emsp;&emsp;&nbsp;&#8226; Clear your Browser and OS cache after each Lock/Unlock!";

	if ($isPython) {
		$unlock_type = 'python';
	} else {
		$unlock_type = $fields[5];
	}

	$h_qdomain	= pfb_hsc($qdomain);
	$h_unlock_type	= pfb_hsc($unlock_type);

	if (!isset($dnsbl_unlock[$qdomain])) {
		if ($isWhitelist_found) {
			$s_txt = "\n\nNote:&emsp;The following Domain exists in the DNSBL Whitelist:\n\n"
				. "Whitelisted:&emsp;[ {$h_qdomain} ]\n\n"
				. "This Domain can be temporarily Relocked into DNSBL\n"
				. "by selecting the Unlock Icon!";

			$unlock_dom = '<i class="fa-solid fa-unlock text-warning" id="DNSBL_RELCK|'
					. $h_qdomain . '|' . $h_unlock_type . '" title="' . $s_txt . '"></i>';
		}
		else {
			$unlock_dom = '<i class="fa-solid fa-lock text-danger" id="DNSBL_ULCK|'
					. $h_qdomain . '|' . $h_unlock_type
					. '" title="Unlock Domain: [ ' . $h_qdomain . '] from DNSBL?' . $tnote . '" ></i>';
		}
	} else {
		if ($isWhitelist_found) {
			$s_txt = "\n\nNote:&emsp;The following Domain exists in the DNSBL Whitelist:\n\n"
				. "Whitelisted:&emsp;[ " . pfb_hsc($wt_line) . " ]\n\n"
				. "Unlock this Domain by selecting the Unlock Icon!";

			$unlock_dom = '<i class="fa-solid fa-lock text-warning" id="DNSBL_REULCK|'
				. $h_qdomain . '|' . $h_unlock_type . '" title="' . $s_txt . '"></i>';
		}
		else {
			$unlock_dom = '<i class="fa-solid fa-unlock text-primary" id="DNSBL_LCK|'
				. $h_qdomain . '|' . $h_unlock_type . '" title="Re-Lock Domain: ['
				. $h_qdomain . ' ] back into DNSBL?' . $tnote . '" ></i>';
		}
	}

	// Add 'https' icon to Domains as required.
	$pfb_https = '';
	if ($fields[0] == 'DNSBL-HTTPS') {
		$pfb_https = "&nbsp;<i class=\"fa-solid fa-key icon-pointer\" title=\"Note: HTTPS - URL/URI/UA are not collected at this time!\"></i>";
	}

	// Threat Lookup Icon
	$alert_dom = '';
	if ($fields[6] != 'Unknown') {
		$alert_dom = '<a class="fa-solid fa-info icon-pointer" title="Click for Threat Domain Lookup." target="_blank" rel="noopener noreferrer" ' .
				'href="/pfblockerng/pfblockerng_threats.php?domain=' . pfb_hsc($qdomain) . '"></a>';
	}

	$dup_cnt = '';
	if ($dup['DNSBL'] != 0) {
		$dup_cnt = "<span title=\"Total additional duplicate event count(s) [ {$dup['DNSBL']} ]\"> [{$dup['DNSBL']}]</span>";
		$dup['DNSBL'] = 0;
	}

	// Upstream blocks have no local feed entry: suppress the lock/whitelist/exclusion
	// action icons (they all target a local-feed domain; they are no-op or confusing
	// for an upstream block). The threat-lookup $alert_dom icon is kept as-is.
	if ($isUpstream) {
		$unlock_dom = '&nbsp;&nbsp;&nbsp;';
		$supp_dom   = '';
		$ex_dom     = '';
	}

	if ($mode != 'Unified') {
		print ("<tr>
			<td>{$pfbalertdnsbl[99]}{$dup_cnt}</td>
			<td>{$pfbalertdnsbl[2]}</td>
			<td>{$pfbalertdnsbl[7]}<br /><small>{$pfbalertdnsbl[17]}</small></td>
			<td style=\"white-space: nowrap;\">{$unlock_dom}&nbsp;{$alert_dom}&nbsp;{$supp_dom}{$ex_dom}</td>
			<td>{$pfbalertdnsbl[8]}<small>&emsp;[ {$pfbalertdnsbl[20]} ]</small> {$pfb_https}{$pfb_python}
				<br /><small>{$pfbalertdnsbl[19]}</small></td>
			<td title=\"{$f_g_title}\">{$feed_group_cell}</td>
			</tr>");
	}
	else {
		// foreign key: system/webgui/webguicss is a pfSense core key, not in registry
		if ($isUpstream) {
			$bg = $pfb_webgui_dark ? $pfb['uniupstream2'] : $pfb['uniupstream'];
		} else {
			$bg = $pfb_webgui_dark ? $pfb['unidnsbl2'] : $pfb['unidnsbl'];
		}
		if ($bg == 'none') {
			$bg = '';
		}
		$tr_title = $isUpstream ? 'Upstream Block Event' : 'DNSBL Event';

		print ("<tr title=\"{$tr_title}\" style=\"background-color:{$bg}\">
			<td style=\"white-space: nowrap;\">{$pfbalertdnsbl[99]}{$dup_cnt}</td>
			<td></td>
			<td>{$pfbalertdnsbl[7]}<br /><small>{$pfbalertdnsbl[17]}</small></td>
			<td style=\"white-space: nowrap;\"><small>{$pfbalertdnsbl[20]}</small> {$pfb_https}{$pfb_python}
				<br /><small>{$pfbalertdnsbl[19]}</small></td>
			<td>{$pfbalertdnsbl[2]}</td>
			<td style=\"white-space: nowrap;\">{$unlock_dom}&nbsp;{$alert_dom}&nbsp;{$supp_dom}{$ex_dom}</td>
			<td>{$pfbalertdnsbl[8]}</td>
			<td title=\"{$f_g_title}\">{$feed_group_cell}</td>
			<td></td>
			</tr>");
	}
	return FALSE;
}


// Function to convert dns_reply.log -> Reports Tab
function convert_dns_reply_log($mode, $fields) {
	global $pfb, $pfb_webgui_dark, $local_hosts, $filterfieldsarray, $clists, $counter, $pfbentries, $skipcount, $dnsfilterlimit, $dnsfilterlimitentries;

	if ($dnsfilterlimit) {
		return TRUE;
	}

	$pfbalertreply		= array();
	$pfbalertreply[81]	= $fields[2];	// DNS Reply Type
	$pfbalertreply[82]	= $fields[3];	// DNS Reply Orig Type 
	$pfbalertreply[83]	= $fields[4];	// DNS Reply Final Type 
	$pfbalertreply[84]	= $fields[5];	// DNS Reply TTL 
	$pfbalertreply[85]	= $fields[6];	// DNS Reply Domain
	$pfbalertreply[86]	= $fields[7];	// DNS Reply SRC IP
	$pfbalertreply[87]	= $fields[8];	// DNS Reply DST IP
	$pfbalertreply[88]	= $fields[9];	// DNS Reply GeoIP
	$pfbalertreply[89]	= $fields[1];   // DNS Reply Timestamp

	// If alerts filtering is selected, process filters as required.
	if ($pfb['filterlogentries']) {
		if (empty($filterfieldsarray[2])) {
			return TRUE;
		}
		if (!pfb_match_filter_field($pfbalertreply, $filterfieldsarray[2])) {
			return FALSE;
		}
		if ($dnsfilterlimitentries != 0 && $counter[$mode == 'Unified' && !$pfb['filterlogentries'] ? 'Unified' : 'DNS'] >= $dnsfilterlimitentries) {
			$dnsfilterlimit = TRUE;
			return TRUE;
		}
	} else {
		if ($counter[$mode == 'Unified' && !$pfb['filterlogentries'] ? 'Unified' : 'DNS'] >= $pfbentries) {
			$dnsfilterlimit = TRUE;
			return TRUE;
		}
	}
	$counter[$mode == 'Unified' && !$pfb['filterlogentries'] ? 'Unified' : 'DNS']++;

	$hostname = $local_hosts[$fields[7]] ?: '';
	$title_hostname = '';
	if (!empty($hostname) && mb_strlen($hostname, 'UTF-8') >= 25) {
		$title_hostname = pfb_hsc($hostname);
		$hostname	= pfb_hsc(pfb_truncate($hostname, 24)) . "<small>...</small>";
	} else {
		$hostname	= pfb_hsc($hostname);
	}

	// Determine if Domain is a TLD Exclusion
	$isExclusion = FALSE;
	if (isset($clists['tld_wildcard_exclusion']['data'][$fields[7]])) {
		$isExclusion = TRUE;
	}

	// Python_control command
	if (strpos($fields[6], 'python_control') !== FALSE) {
		$cc_color = 'blue';
		if (strpos($fields[8], 'not authorized') !== FALSE) {
			$cc_color = 'red';
		}
		$icons = "<i class=\"fa-solid fa-cog\" title=\"Python_control command\" style=\"color: {$cc_color}\"></i>";
	}

	// Determine Whitelist type
	else {

		// issue #1777: dnsbl_whitelist_type() unconditionally reads keys 5/7/8 too
		// (DNSBL Mode / Evaluated Domain / Feed Name) -- a DNS reply row has no
		// Mode, Evaluated Domain or Feed, so each key preserves the pre-fix
		// implicit-NULL read at its own call site:
		//   - key 5 (DNSBL Mode, gates the != 'DNSBL_TLD' branch split): '' keeps
		//     the pre-fix branch selection byte-for-byte, since NULL != 'DNSBL_TLD'
		//     is also TRUE.
		//   - key 7 (Evaluated Domain): '' -- NOT $fields[6]. A prior fix set this
		//     to $fields[6] (the replied domain) reasoning only about the
		//     exclusion-icon id; it missed that dnsbl_whitelist_type() ALSO feeds
		//     key 7 into the dot-prefixed wildcard-whitelist walk
		//     (dnsbl_whitelist_type() ~:2056, `ltrim($fields[7], '.')`). A real
		//     domain there enters that walk and can flip $isWhitelist_found to
		//     TRUE for any dot-prefixed whitelist entry that is an ancestor
		//     domain -- silently reclassifying an unrelated reply row as
		//     already-whitelisted. '' is chosen because
		//     ltrim(NULL, '.') === ltrim('', '.') === '', so it reproduces the
		//     pre-fix NULL read exactly and never enters the walk.
		//   - key 8 (Feed Name) is read only inside the `$fields[6] != 'Unknown'`
		//     branch (dnsbl_whitelist_type() ~:2023), which the caller's own
		//     hardcoded '6' => 'Unknown' provably never enters -- no reply-log
		//     analogue exists and none is needed; '' is inert by construction.
		// The replied domain doubles as key 2 and the $qdomain argument below.
		$dns_fields = array ('2' => $fields[6], '5' => '', '6' => 'Unknown', '7' => '', '8' => '');
		list($supp_dom, $ex_dom, $isWhitelist_found) = dnsbl_whitelist_type($dns_fields, $clists, $isExclusion, FALSE, $fields[6]);

		// Threat Lookup Icon
		$icons = '<a class="fa-solid fa-info icon-pointer" title="Click for Threat Domain Lookup." target="_blank" rel="noopener noreferrer" ' .
				'href="/pfblockerng/pfblockerng_threats.php?domain=' . pfb_hsc($fields[6]) . '"></a>';

		if (!empty($supp_dom)) {
			$icons .= "&nbsp;{$supp_dom}";
		}

		// Default - Add to Blacklist
		else {
			$h_f6 = pfb_hsc($fields[6]);
			$icons .= '&nbsp;<i class="fa-solid fa-plus icon-pointer" id="DNSBLWT|' . 'dnsbl_add|'
				. $h_f6 . '|' . implode('|', $clists['dnsbl']['options']) . '" title="'
				. "Add Domain [ {$h_f6} ] to DNSBL" . '"></i>';
		}

		if (!empty($ex_dom)) {
			$icons .= "&nbsp;{$ex_dom}";
		}
	}

	// Timestamp / Type / Orig Type / Final Type / SRC IP / GeoIP printed verbatim
	$fields[1]	= pfb_hsc($fields[1]);
	$fields[2]	= pfb_hsc($fields[2]);
	$fields[3]	= pfb_hsc($fields[3]);
	$fields[4]	= pfb_hsc($fields[4]);
	$fields[7]	= pfb_hsc($fields[7]);
	$fields[9]	= pfb_hsc($fields[9]);

	// Truncate long TTLs
	$pfb_title5 = '';
	if (mb_strlen($fields[5], 'UTF-8') >= 6) {
		$pfb_title5	= pfb_hsc($fields[5]);
		$fields[5]	= pfb_hsc(pfb_truncate($fields[5], 5)) . "<small>...</small>";
	} else {
		$fields[5]	= pfb_hsc($fields[5]);
	}

	// Truncate long Domain names
	$pfb_title6 = '';
	if (mb_strlen($fields[6], 'UTF-8') >= ($mode != 'Unified' ? 45 : 30)) {
		$pfb_title6	= pfb_hsc($fields[6]);
		$fields[6]	= pfb_hsc(pfb_truncate($fields[6], ($mode != 'Unified' ? 44 : 29))) . "<small>...</small>";
	} else {
		$fields[6]	= pfb_hsc($fields[6]);
	}

	// Truncate long Resolved names
	$pfb_title8 = '';
	if (mb_strlen($fields[8], 'UTF-8') >= 17) {
		$pfb_title8	= pfb_hsc($fields[8]);
		$fields[8]	= pfb_hsc(pfb_truncate($fields[8], 16)) . "<small>...</small>";
	} else {
		$fields[8]	= pfb_hsc($fields[8]);
	}

	if ($mode != 'Unified') {
		print ("<tr>
			<td>{$fields[1]}</td>
			<td title=\"{$title_hostname}\">{$fields[7]}<br /><small>{$hostname}</small></td>
			<td style=\"text-align: center\">{$fields[2]}</td>
			<td style=\"text-align: center\">{$fields[3]}</td>
			<td style=\"text-align: center\">{$fields[4]}</td>
			<td style=\"white-space: nowrap;\">{$icons}</td>
			<td title=\"{$pfb_title6}\">{$fields[6]}</td>
			<td title=\"{$pfb_title5}\">{$fields[5]}</td>
			<td title=\"{$pfb_title8}\">{$fields[8]}</td>
			<td>{$fields[9]}</td>
			</tr>");
	}
	else {
		$style_bg = '';
		$title = 'DNS Reply Event';
		if ($fields[7] == '127.0.0.1') {
			// foreign key: system/webgui/webguicss is a pfSense core key, not in registry
			$bg = $pfb_webgui_dark ? $pfb['unireply2'] : $pfb['unireply'];
			if ($bg != 'none') {
				$style_bg = "style=\"background-color:{$bg}\"";
			}
			$title = 'DNS Reply (Resolver) Event';
		}

		print ("<tr title=\"{$title}\" {$style_bg}>
			<td style=\"white-space: nowrap;\">{$fields[1]}</td>
			<td></td>
			<td title=\"{$title_hostname}\">{$fields[7]}<br /><small>{$hostname}</small></td>
			<td>{$fields[2]}<br /><small>{$fields[3]} | {$fields[4]}</small></td>
			<td title=\"{$pfb_title5}\"><small>{$fields[5]}</small></td>
			<td style=\"text-align: center; white-space: nowrap;\">{$icons}</td>
			<td title=\"{$pfb_title6}\">{$fields[6]}</td>
			<td title=\"{$pfb_title8}\">{$fields[8]}</td>
			<td>{$fields[9]}</td>
			</tr>");
	}
	return FALSE;
}


/**
 * Build the inner HTML for the IP alert Feed/Match cell.
 *
 * When both the feed name and matched IP/CIDR were re-evaluated (both $feed_new
 * and $match_new are non-empty), groups the output by record: the struck
 * previous pair first, then the current pair. When only one field changed the
 * per-field layout is preserved, matching today's existing behaviour.
 *
 * All four parameters must already be HTML-escaped by the caller; $feed_new and
 * $match_new must be empty strings when the corresponding field did not change.
 */
function pfb_ip_feed_match_cell(string $feed, string $feed_new, string $match, string $match_new): string {
	if ($feed_new !== '' && $match_new !== '') {
		// Both changed — group by record: struck previous pair, then current pair.
		return "<s>{$feed}</s><br /><small><s>{$match}</s></small><br />{$feed_new}<br /><small>{$match_new}</small>";
	}
	elseif ($feed_new !== '') {
		// Only feed changed — per-field layout.
		return "<s>{$feed}</s><br />{$feed_new}<br /><small>{$match}</small>";
	}
	elseif ($match_new !== '') {
		// Only match changed — per-field layout.
		return "{$feed}<br /><small><s>{$match}</s><br />{$match_new}</small>";
	}
	// Neither changed.
	return "{$feed}<br /><small>{$match}</small>";
}


/**
 * Build the inner HTML for the DNSBL alert Feed/Group cell.
 *
 * Sibling of pfb_ip_feed_match_cell() for the DNSBL views. When a domain was
 * previously blocked by a different feed AND a different group (both $prev_feed
 * and $prev_group are non-empty), groups the output by record: the struck
 * previous pair first, then the current pair. When only one of the two has a
 * previous value the per-field layout is preserved, matching today's behaviour.
 *
 * All four parameters must already be HTML-escaped by the caller; $prev_feed and
 * $prev_group are empty strings when there is no previous value for that field.
 */
function pfb_dnsbl_feed_group_cell(string $prev_feed, string $cur_feed, string $prev_group, string $cur_group): string {
	if ($prev_feed !== '' && $prev_group !== '') {
		// Both changed — group by record: struck previous pair, then current pair.
		return "<s>{$prev_feed}</s><br /><small><s>{$prev_group}</s></small><br />{$cur_feed}<br /><small>{$cur_group}</small>";
	}
	elseif ($prev_feed !== '') {
		// Only the feed changed — per-field layout.
		return "<s>{$prev_feed}</s><br />{$cur_feed}<br /><small>{$cur_group}</small>";
	}
	elseif ($prev_group !== '') {
		// Only the group changed — per-field layout.
		return "{$cur_feed}<br /><small><s>{$prev_group}</s><br />{$cur_group}</small>";
	}
	// No previous value.
	return "{$cur_feed}<br /><small>{$cur_group}</small>";
}

/**
 * Render the Permit-Whitelist trash-can icon markup when $host is covered by
 * one of the given ipwhitelist alias lists, else return NULL.
 *
 * Shared by both Alerts icon call sites that need this lookup (issue #798):
 * the Suppression-icon gate's whitelist sub-path, and the standalone IP
 * Whitelist Icon fallback. The NULL return also replaces the old $pfb_found
 * flag as the caller's "not found" signal -- $pfb_found was left undefined
 * (PHP 8 E_WARNING on read) whenever $wlists was empty.
 */
function pfb_whitelist_trash_icon(array $wlists, string $host, int $vtype, string $h_host, string $h_eval_ip): ?string {
	if (empty($wlists)) {
		return NULL;
	}

	foreach ($wlists as $atype => $permit_list) {
		if (!isset($permit_list['data'][$host])) {
			continue;
		}

		$w_line = rtrim($permit_list['data'][$host], "\x00..\x1F");
		$supp_ip_txt = "Note:&emsp;The following IPv{$vtype} address is in a Permit Alias:\n\n"
				. "Permitted IP:&emsp;[ " . pfb_hsc($w_line) . " ]\n"
				. "Evaluated IP:&emsp;[ {$h_eval_ip} ]\n"
				. "IP Aliasname:&emsp;[ " . pfb_hsc($atype) . " ]\n\n"

				. "To remove this IP from the Whitelist, press 'OK'";

		return '<i class="fa-solid fa-trash-can no-confirm icon-pointer" id="DNSBLWT|' . 'delete_ipwhitelist|' . $h_host
				. '|' . pfb_hsc($atype) . '" title="' . $supp_ip_txt . '"></i>';
	}

	return NULL;
}


// Function to convert IP Logs (ip_block, ip_permit and ip_match).log -> Reports Tab
function convert_ip_log($mode, $fields, $p_query_port, $rtype) {
	global $pfb, $pfb_webgui_dark, $continents, $filterfieldsarray, $clists, $ip_unlock, $counter, $pfbentries, $skipcount, $dup, $ipfilterlimit, $ipfilterlimitentries;

	if ($ipfilterlimit) {
		return array(TRUE, '');
	}

	// issue #1369 (ADR-38 Amendment 3): only the current 23-field feature-row /
	// 24-field Unified-row schema is supported on the read path -- no back-compat
	// for log entries (owner decision). ANY other field count, including every
	// pre-upgrade legacy row still on disk, is skipped here silently (no PHP
	// warnings/notices) BEFORE the timestamp shift below or any indexed field
	// access -- see pfb_ip_log_row_schema_ok() (pfblockerng_extra.inc).
	if (!pfb_ip_log_row_schema_ok($fields, $mode)) {
		return array(FALSE, '');
	}

	$alert_ip = '';
	$src_icons = $dst_icons = $feed_new = $eval_new = $alias_new = '';

	// Reorder timestamp field for Filter fields functionality
	$fields[99] = array_shift($fields);

	/* Fields Reference

		(Removed and re-ordered)
		[0]	=> [99] = Date/TimestamP
		[18]	 	= Duplicate ID indicator / Count

		(Final $fields array reference)
		[0]	= Rulenum
		[1]	= Real Interface
		[2]	= Friendly Interface name
		[3]	= Action
		[4]	= Version
		[5]	= Protocol ID
		[6]	= Protocol
		[7]	= SRC IP
		[8]	= DST IP
		[9]	= SRC Port
		[10]	= DST Port
		[11]	= Direction
		[12]	= GeoIP code
		[13]	= IP Alias Name
		[14]	= IP evaluated
		[15]	= Feed Name
		[16]	= gethostbyaddr resolved hostname
		[17]	= Client Hostname
		[18]	= ASN
		[19]	= ASN Domain	(issue #1369)
		[20]	= ASN Name	(issue #1369)		*/

	// If alerts filtering is selected, process filters as required.
	if ($pfb['filterlogentries']) {
		if (empty($filterfieldsarray[0])) {
			return array(TRUE, '');
		}
		if (!pfb_match_filter_field($fields, $filterfieldsarray[0])) {
			$dup[$mode == 'Unified' ? 'Unified' && !$pfb['filterlogentries'] : $rtype] = 0;
			return array(FALSE, '');
		}
		if ($ipfilterlimitentries != 0 && $counter[$mode == 'Unified' && !$pfb['filterlogentries'] ? 'Unified' : $rtype] >= $ipfilterlimitentries) {
			$ipfilterlimit = TRUE;
			return array(TRUE, '');
		}
	}
	else {
		if ($counter[$mode == 'Unified' && !$pfb['filterlogentries'] ? 'Unified' : $rtype] >= $pfbentries) {
			$ipfilterlimit = TRUE;
			return array(TRUE, '');
		}
	}
	$counter[$mode == 'Unified' && !$pfb['filterlogentries'] ? 'Unified' : $rtype]++;

	// Cleanup port output
	if ($fields[6] == 'ICMP' || $fields[6] == 'ICMPV6') {
		$srcport = '';
		$dstport = '';
	} else {
		$srcport = ":" . pfb_hsc($fields[9]);
		$dstport = ":" . pfb_hsc($fields[10]);
	}

	// IPv4 or IPv6 event
	$pfb_ipv4 = FALSE;
	$vtype = 6;
	if ($fields[4] == 4) {
		$pfb_ipv4 = TRUE;
		$vtype = 4;
	}

	$attribution = pfb_ip_render_attribution($fields);
	$host = $attribution['host'];
	$hostname = $attribution['hostname'];
	$pfb_geoip = $attribution['pfb_geoip'];
	$fields[15] = $attribution['field15'];
	$mask = $attribution['mask'];
	$feed_new = $attribution['feed_new'];
	$eval_new = $attribution['eval_new'];
	$alias_new = $attribution['alias_new'];
	$pfb_matchtitle = $attribution['pfb_matchtitle'];

	// HTML-encode the resolved/DHCP hostnames before they are printed as cell text.
	$hostname['src'] = pfb_hsc($hostname['src']);
	$hostname['dst'] = pfb_hsc($hostname['dst']);

	// ASN - Add to GeoIP column. issue #1369 (ADR-38 Amendment 3): the ASN
	// number renders directly from its own plain CSV column ([18]); the
	// tooltip is built from the separate ASN Domain/Name columns ([19]/[20])
	// -- no more pipe-blob explode()/label-stripping.
	if ($pfb['asn_reporting'] != 'disabled' && !empty($fields[18]) && $fields[18] != 'Unknown' && $fields[18] != 'null') {
		$asn_domain = $fields[19] ?? '';
		$asn_name   = $fields[20] ?? '';
		$asn_title  = "domain:  {$asn_domain} | name:  {$asn_name}";
		$fields[18] = "<span title=\"" . pfb_hsc($asn_title) . "\">" . pfb_hsc($fields[18]) . "</span>";
	}
	else {
		$fields[18] = '';
	}

	// v4-only, /32|/24 -- ADR-53 (issue #422) narrowed this to feed ONLY the
	// legacy whitelist-fallback quirk gate below (issue #1412 moved the
	// Unlock/Lock icon gate onto the family/mask-agnostic condition the
	// Suppression icon already uses, so $mask_unlock -- its only other
	// reader -- is retired).
	$mask_suppression = FALSE;

	if ($pfb_ipv4 && ($mask == '/32' || $mask == '/24')) {
		$mask_suppression = TRUE;
	}

	$table = $fields[13];
	if (!empty($alias_new)) {
		$table = $alias_new;
	}

	$eval_ip = $fields[14];
	if (!empty($eval_new)) {
		$eval_ip = $eval_new;
	}

	// HTML-encoded copies of the IP/alias tokens that get folded into the icon
	// id/title/href markup below (the raw values stay for lookup paths).
	$h_host		= pfb_hsc($host);
	$h_eval_ip	= pfb_hsc($eval_ip);
	$h_table	= pfb_hsc($table);

	$alert_ip = '<a class="fa-solid fa-info icon-pointer" target="_blank" rel="noopener noreferrer" href="/pfblockerng/pfblockerng_threats.php?host=' .
			$h_host . '" title="Click for Threat source IP Lookup for [ ' . $h_host . ' ]"></a>';

	// Suppression Icon -- any family, any mask (ADR-53 follow-up, issue #422).
	// GeoIP rows stay excluded (maintainer constraint).
	$supp_ip = $unlock_ip = '&nbsp;&nbsp;&nbsp;';
	if ($rtype == 'Block' && !$pfb_geoip) {

		$supp_key = ($vtype == 6) ? 'ipsuppression_v6' : 'ipsuppression';
		$supp_match = NULL;
		if (pfb_cfg_toggle_read($pfb['supp']) === PfbToggle::On) {
			$supp_match = pfb_ip_suppressed_match($host, array_keys($clists[$supp_key]['data']));
			if ($supp_match !== NULL) {
				$w_line = rtrim($clists[$supp_key]['data'][$supp_match], "\x00..\x1F");
			}
		}

		// Host is not covered by any Suppression entry
		if ($supp_match === NULL) {

			// Check if host is in a Permit Whitelist Alias
			$supp_ip_wl = pfb_whitelist_trash_icon($clists['ipwhitelist' . $vtype], $host, $vtype, $h_host, $h_eval_ip);

			// Host found in a Permit Whitelist Alias
			if ($supp_ip_wl !== NULL) {
				$supp_ip = $supp_ip_wl;
			}

			// Add Suppression/Whitelist Icon
			if ($supp_ip_wl === NULL) {
				$permit_option = pfb_alerts_permit_option_suffix($clists['ipwhitelist' . $vtype] ?? NULL);

				$supp_ip_txt  = "Note:&emsp;The following IPv{$vtype} was blocked:\n\n"
						. "Blocked IP:&emsp;&emsp;[ {$h_host} ]\n"
						. "Evaluated IP:&emsp;&nbsp;[ {$h_eval_ip} ]\n\n"
						. "IP Aliasname:&emsp;[ {$h_table} ]\n"
						. "IP Feedname:&emsp;&nbsp;[ "
						. pfb_hsc(!empty($feed_new) ? $feed_new : $fields[15]) . " ]\n\n"

						. "Whitelisting Options:\n\n"
						. "1) Suppress the IP. This will immediately remove the IP\n"
						. "&emsp;and keep the IP suppressed until its removed from the customlist\n\n"
						. "2) Whitelist the IP to an existing 'Permit' Alias customlist. Ensure that this\n"
						. "&emsp;Permit Alias/Rule is above the Block/Reject rules (Rule Order option)\n\n"
						. "&emsp;If no 'Whitelist' is found, a default 'Whitelist' will be created.\n"
						. "&emsp;A Force Update is required to add the associated Firewall Permit Rule!\n\n"
						. "Click 'OK' to continue";

				$supp_ip = '<i class="fa-solid fa-plus icon-pointer" id="PFBIPSUP|' . 'add|' . $h_host
						. '|' . $h_table . $permit_option
						. '" title="' . $supp_ip_txt . '"></i>';
			}
		}
		else {
			$supp_ip_txt = "Note:&emsp;The following IPv{$vtype} address is in a IP Suppression list:\n\n"
					. "Suppressed IP:&emsp;[ " . pfb_hsc($w_line) . " ]\n"
					. "Evaluated IP:&emsp;[ {$h_eval_ip} ]\n\n"

					. "To remove this IP from the Suppression list, press 'OK'";

			$supp_ip = '<i class="fa-solid fa-trash-can no-confirm icon-pointer" id="DNSBLWT|' . 'delete_ip|' . $h_host
					. '|' . $h_table . '" title="' . $supp_ip_txt . '"></i>&emsp;';
		}
	}

	// Unlock/Lock Icon -- ADR-53 parity (#1412): same eligibility as the
	// Suppression icon above (any family, any mask -- $mask_suppression /
	// the retired $mask_unlock were v4-only /24|/32 restrictions), and the
	// SAME exact-host token the Suppression "+" posts ($host), never the
	// possibly-CIDR $eval_ip a feed match can report; $ip_unlock is keyed by
	// that same exact host (the package seam calls pfb_unlock() with $ip = the
	// posted host). The stored table must match THIS
	// row's table -- a host unlocked in another alias still shows the Unlock
	// icon here.
	if ($rtype == 'Block' && !$pfb_geoip) {
		$tnote = "\n\nNote:\n&emsp;&emsp;&#8226; Unlocking IP(s) is temporary and may be automatically\n"
			. "&emsp;&emsp;&emsp;re-locked on a Cron or Force command!\n"
			. "&emsp;&emsp;&#8226; Review Threat Source ( i ) Icons for further IP details.";

		if (($ip_unlock[$host] ?? NULL) !== $table) {
			$unlock_ip = '<i class="fa-solid fa-lock text-danger" id="IPULCK|' . $h_host . '|'  . $h_table
					. '" title="Unlock IP: [ ' . $h_host . ' ] from Aliastable [ ' . $h_table . ' ]?'
					. $tnote . '" ></i>';
		} else {
			$unlock_ip = '<i class="fa-solid fa-unlock text-primary" id="IPLCK|' . $h_host . '|' . $h_table
					. '" title="Re-Lock IP: [ ' . $h_host . ' ] back into Aliastable [ ' . $h_table . ' ]?'
					. $tnote . '" ></i>';
		}
	}

	// IP Whitelist Icon -- rows handled by the Suppression-icon gate above
	// (Block, non-GeoIP) never reach this branch any more; the
	// !$mask_suppression leg preserves today's behaviour unchanged for the
	// rest (Match rows, GeoIP rows, Permit-alias rows).
	if (!($rtype == 'Block' && !$pfb_geoip) && !$mask_suppression) {
		if ($clists['ipwhitelist' . $vtype]) {

			$supp_ip_wl = pfb_whitelist_trash_icon($clists['ipwhitelist' . $vtype], $host, $vtype, $h_host, $h_eval_ip);

			if ($supp_ip_wl !== NULL) {
				$supp_ip = $supp_ip_wl;
			}
			else {
				$supp_ip_txt  = "Note:&emsp;The following IPv{$vtype} was blocked:\n\n"
						. "Blocked IP:&emsp;&emsp;[ {$h_host} ]\n"
						. "Evaluated IP:&emsp;&nbsp;[ {$h_eval_ip} ]\n\n"
						. "IP Aliasname:&emsp;[ {$h_table} ]\n"
						. "IP Feedname:&emsp;&nbsp;[ "
						. pfb_hsc(!empty($feed_new) ? $feed_new : $fields[15]) . " ]\n\n"

						. "Whitelisting details:\n\n"
						. "&#8226; To permit access to this Blocked IP, you can add it to any\n"
						. "&emsp;existing 'Permit' Alias.\n\n"
						. "&emsp;If no 'Whitelist' is found, a default 'Whitelist' will be created.\n"
						. "&emsp;A Force Update is required to add the associated Firewall Permit Rule!\n\n"
						. "&#8226; Ensure that this Permit Alias/Rule is above the "
						. "Block/Reject rules\n&emsp;(Rule Order option)\n\n"
						. "Click 'OK' to continue";

				$supp_ip = '<i class="fa-solid fa-plus-circle icon-pointer" id="PFBIPWHITE|' . $h_host
						. pfb_alerts_permit_option_suffix($clists['ipwhitelist' . $vtype] ?? NULL)
						. '" title="' . $supp_ip_txt . '"></i>';
			}
		}
	}

	// Remove Suppression Icon for 'Not Listed' events
	if ($eval_new == 'Not listed!') {
		$supp_ip = '';
	}

	// Threat port lookup
	$query_port = '';
	if ($p_query_port != $fields[10]) {
		$h_dstport_q = pfb_hsc($fields[10]);
		$query_port = '<a class="fa-solid fa-search icon-pointer" target="_blank" rel="noopener noreferrer" '
				. 'href="/pfblockerng/pfblockerng_threats.php?port=' . $h_dstport_q
				. '" title="Click for Threat Port Lookup [ ' . $h_dstport_q . ' ]"></a>';
	}

	// Inbound event
	$src_icons = $dst_icons = '&emsp;&emsp;&emsp;';
	if ($fields[11] == 'in') {
		if ($rtype == 'Block') {
			$src_icons	= "{$unlock_ip}&nbsp;{$alert_ip}&nbsp;{$supp_ip}";
		} elseif ($rtype == 'Match') {
			$src_icons	= "{$alert_ip}&nbsp;";
		}
	}

	// Outbound event
	else {
		if ($rtype == 'Block') {
			$dst_icons	= "{$unlock_ip}&nbsp;{$alert_ip}&nbsp;{$supp_ip}";
		} elseif ($rtype == 'Match') {
			$dst_icons	= "{$alert_ip}";
		}
	}

	// Add []'s to IPv6 addresses and add a zero-width space as soft-break opportunity after each colon if we have an IPv6 address (from Snort)
	if ($fields[4] == 6) {
		$fields[97] = '[' . str_replace(':', ':&#8203;', pfb_hsc($fields[7])) . ']';
		$fields[98] = '[' . str_replace(':', ':&#8203;', pfb_hsc($fields[8])) . ']';
	}
	else {
		$fields[97] = pfb_hsc($fields[7]);
		$fields[98] = pfb_hsc($fields[8]);
	}

	if (mb_strlen($fields[15], 'UTF-8') >= 17) {
		if (!empty($pfb_matchtitle)) {
			$pfb_matchtitle .= '&#013;';
		}
		$pfb_matchtitle .= "Feed: " . pfb_hsc($fields[15]);
		$fields[15]	= pfb_hsc(pfb_truncate($fields[15], 16)) . "<small>...</small>";
	} else {
		$fields[15]	= pfb_hsc($fields[15]);
	}
	if (mb_strlen($feed_new, 'UTF-8') >= 17) {
		if (!empty($pfb_matchtitle)) {
			$pfb_matchtitle .= '&#013;';
		}
		$pfb_matchtitle .= "Feed new: " . pfb_hsc($feed_new);
		$feed_new	= pfb_hsc(pfb_truncate($feed_new, 16)) . "<small>...</small>";
	} else {
		$feed_new	= pfb_hsc($feed_new);
	}

	$fields[14]		= pfb_hsc($fields[14]);
	$feed_match_cell	= pfb_ip_feed_match_cell($fields[15], $feed_new, $fields[14], pfb_hsc($eval_new));

	// Interface / Protocol / GeoIP code / Timestamp printed verbatim
	$fields[2]	= pfb_hsc($fields[2]);
	$fields[6]	= pfb_hsc($fields[6]);
	$fields[12]	= pfb_hsc($fields[12]);
	$fields[99]	= pfb_hsc($fields[99]);

	$h_rule_alias	= pfb_hsc($fields[13]);
	$h_rule_num	= pfb_hsc($fields[0]);
	if (!empty($alias_new)) {
		$rule = "<s>{$h_rule_alias}</s><br />" . pfb_hsc($alias_new) . "<br /><small>({$h_rule_num})</small>";
	} else {
		$rule = "{$h_rule_alias}<br /><small>({$h_rule_num})</small>";
	}

	$dup_cnt = '';
	if ($dup[$rtype] != 0) {
		$dup_cnt = "<span title=\"Total additional duplicate event count(s) [ {$dup[$rtype]} ]\"> [{$dup[$rtype]}]</span>";
		$dup[$rtype] = 0;
	}

	if ($mode != 'Unified') {
		print ("<tr>
			<td>{$fields[99]}{$dup_cnt}</td>
			<td>{$fields[2]}</td>
			<td>{$rule}</td>
			<td>{$fields[6]}</td>
			<td>{$src_icons}</td>
			<td>{$fields[97]}{$srcport}<br /><small>{$hostname['src']}</small></td>
			<td>{$dst_icons}</td>
			<td>{$fields[98]}{$dstport}&emsp;{$query_port}<br /><small>{$hostname['dst']}</small></td>
			<td>{$fields[12]}<br />{$fields[18]}</td>
			<td title=\"{$pfb_matchtitle}\">{$feed_match_cell}</td>
			</tr>");
	}
	else {
		// foreign key: system/webgui/webguicss is a pfSense core key, not in registry
		switch($rtype) {
			case 'Block':
				$bg = $pfb_webgui_dark ? $pfb['uniblock2'] : $pfb['uniblock'];
				break;
			case 'Permit':
				$bg = $pfb_webgui_dark ? $pfb['unipermit2'] : $pfb['unipermit'];
				break;
			case 'Match':
				$bg = $pfb_webgui_dark ? $pfb['unimatch2'] : $pfb['unimatch'];
				break;
			default:
				$bg = '';
				break;
		}

		if ($bg == 'none') {
			$bg = '';
		}

		print ("<tr title=\"IP {$rtype} Event\" style=\"background-color:{$bg}\">
			<td style=\"white-space: nowrap;\">{$fields[99]}{$dup_cnt}</td>
			<td style=\"white-space: nowrap; text-align: center;\"\>{$src_icons}</td>
			<td>{$fields[97]}{$srcport}<br /><small>{$hostname['src']}</small></td>
			<td>{$rule}&emsp;<small>{$fields[6]}</small></td>
			<td><small>{$fields[2]}</small></td>
			<td style=\"white-space: nowrap; text-align: center;\">{$dst_icons}</td>
			<td>{$fields[98]}{$dstport}&emsp;{$query_port}<br /><small>{$hostname['dst']}</small></td>
			<td title=\"{$pfb_matchtitle}\">{$feed_match_cell}</td>
			<td>{$fields[12]}<br />{$fields[18]}</td>
			</tr>");
	}

	// Collect Previous SRC port
	$p_query_port = $fields[10];

	return array(FALSE, $p_query_port);
}


$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('Alerts'));
$pglinks = array('', '/pfblockerng/pfblockerng_general.php', '@self');
$shortcut_section = 'pfblockerng';
include_once('head.inc');
$pfb_unified_tint = $pfb_webgui_dark ? 'rgba(255,255,255,.06)' : 'rgba(0,0,0,.05)';
?>

<style>
/* Stats panel: flex columns that shrink and wrap on narrow viewports */
.pfb-stats-row {
	display: flex;
	flex-wrap: wrap;
	gap: 10px;
}
.pfb-stats-col {
	flex: 1 1 480px;
	min-width: 0;
}
/* Let the d3pie SVG scale fluidly within its column */
.pfb-stats-col svg {
	max-width: 100%;
	height: auto;
}

@media print {
	.pfb-stats-row { display: block; }
	.pfb-stats-col {
		width: 100% !important;
		float: none !important;
		height: auto !important;
		overflow: visible !important;
		page-break-inside: avoid;
	}
	.panel-body { overflow: visible !important; }
	* { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
}
.pfb-unified tbody tr:nth-of-type(odd) {
	background-image: linear-gradient(<?=$pfb_unified_tint?>, <?=$pfb_unified_tint?>);
}
</style>

<script type="text/javascript">
//<![CDATA[
/* Set a viewBox on the fixed-size d3pie SVG so CSS max-width scales it
   without distorting the annotated labels. */
function pfbPieFluid(id) {
	var el = document.getElementById(id);
	if (!el) { return; }
	var svg = el.querySelector('svg');
	if (!svg) { return; }
	var w = svg.getAttribute('width');
	var h = svg.getAttribute('height');
	if (w && h && !svg.getAttribute('viewBox')) {
		svg.setAttribute('viewBox', '0 0 ' + w + ' ' + h);
	}
	svg.removeAttribute('width');
	svg.removeAttribute('height');
	svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
}
//]]>
</script>

<?php
// Define default Alerts Tab href link (Top row)
$get_req = pfb_alerts_default_page();

if (isset($savemsg)) {
	print_info_box($savemsg);
}

if (isset($_REQUEST['savemsg'])) {
	$savemsg = htmlspecialchars($_REQUEST['savemsg']);
	print_info_box($savemsg);
}


$tab_array   = array();
$tab_array[] = array(gettext('General'),	FALSE,	'/pfblockerng/pfblockerng_general.php');
$tab_array[] = array(gettext('IP'),		FALSE,	'/pfblockerng/pfblockerng_ip.php');
$tab_array[] = array(gettext('DNSBL'),		FALSE,	'/pfblockerng/pfblockerng_dnsbl.php');
$tab_array[] = array(gettext('Update'),		FALSE,	'/pfblockerng/pfblockerng_update.php');
$tab_array[] = array(gettext('Reports'),	TRUE,	"/pfblockerng/pfblockerng_alerts.php{$get_req}");
$tab_array[] = array(gettext('Feeds'),		FALSE,	'/pfblockerng/pfblockerng_feeds.php');
$tab_array[] = array(gettext('Logs'),		FALSE,	'/pfblockerng/pfblockerng_log.php');
$tab_array[] = array(gettext('Sync'),		FALSE,	'/pfblockerng/pfblockerng_sync.php');
pfb_software_add_tab($tab_array);
display_top_tabs($tab_array, TRUE);

$tab_array   = array();
$tab_array[] = array(gettext('Unified'),		$active['unified'],	'/pfblockerng/pfblockerng_alerts.php?view=unified');
$tab_array[] = array(gettext('Alerts'),			$active['alerts'],	'/pfblockerng/pfblockerng_alerts.php');
$tab_array[] = array(gettext('IP Block Stats'),		$active['ip_block'],	'/pfblockerng/pfblockerng_alerts.php?view=ip_block_stat');
$tab_array[] = array(gettext('IP Permit Stats'),	$active['ip_permit'],	'/pfblockerng/pfblockerng_alerts.php?view=ip_permit_stat');
$tab_array[] = array(gettext('IP Match Stats'),		$active['ip_match'],	'/pfblockerng/pfblockerng_alerts.php?view=ip_match_stat');

$tab_array[] = array(gettext('DNS Reply'),		$active['reply'],		'/pfblockerng/pfblockerng_alerts.php?view=reply');
$tab_array[] = array(gettext('DNS Reply Stats'),	$active['dnsbl_reply_stat'],	'/pfblockerng/pfblockerng_alerts.php?view=dnsbl_reply_stat');
$tab_array[] = array(gettext('DNSBL Block Stats'),	$active['dnsbl'],	'/pfblockerng/pfblockerng_alerts.php?view=dnsbl_stat');
display_top_tabs($tab_array, TRUE);
pfb_print_pending_changes_box();

// Create Form
$form = new Form(FALSE);
$form->setAction('/pfblockerng/pfblockerng_alerts.php');

if ($alert_summary && strpos($alert_view, 'ip_') !== FALSE) {
	// Build 'Shortcut Links' section
	$section = new Form_Section(NULL);
	$section->addInput(new Form_StaticText(
		'Links',
		'<small>'
		. '<a href="/firewall_aliases.php" target="_blank" rel="noopener noreferrer">Firewall Alias</a>&emsp;'
		. '<a href="/firewall_rules.php" target="_blank" rel="noopener noreferrer">Firewall Rules</a>&emsp;'
		. '<a href="/status_logs_filter.php" target="_blank" rel="noopener noreferrer">Firewall Logs</a></small>'
	));
	$form->add($section);
}

$section = new Form_Section('Alert Settings', 'alertsettings', COLLAPSIBLE|SEC_CLOSED);
$form->add($section);

// Build 'Alert Settings' group section
$group = new Form_Group('Settings');
$group->add(new Form_Input(
	'pfbunicnt',
	'Unified',
	'number',
	$pfbunicnt,
	['min' => 0, 'max' => 5000]
))->setHelp('Unified')->setAttribute('title', 'Enter number of \'Unified\' log entries to view. Set to \'0\' to disable');

$group->add(new Form_Input(
	'pfbdenycnt',
	'Deny',
	'number',
	$pfbdenycnt,
	['min' => 0, 'max' => 5000]
))->setHelp('IP Deny')->setAttribute('title', 'Enter number of \'Deny\' log entries to view. Set to \'0\' to disable');

$group->add(new Form_Input(
	'pfbdnscnt',
	'DNSBL',
	'number',
	$pfbdnscnt,
	['min' => 0, 'max' => 5000]
))->setHelp('DNSBL')->setAttribute('title', 'Enter number of \'DNSBL\' log entries to view. Set to \'0\' to disable');

$group->add(new Form_Input(
	'pfbdnsreplycnt',
	'DNS Reply',
	'number',
	$pfbdnsreplycnt,
	['min' => 0, 'max' => 5000]
))->setHelp('DNS Reply')->setAttribute('title', 'Enter number of \'DNS Reply\' log entries to view. Set to \'0\' to disable');

$group->add(new Form_Input(
	'pfbpermitcnt',
	'Permit',
	'number',
	$pfbpermitcnt,
	['min' => 0, 'max' => 5000]
))->setHelp('IP Permit')->setAttribute('title', 'Enter number of \'Permit\' log entries to view. Set to \'0\' to disable');

$group->add(new Form_Input(
	'pfbmatchcnt',
	'Match',
	'number',
	$pfbmatchcnt,
	['min' => 0, 'max' => 5000]
))->setHelp('IP Match')->setAttribute('title', 'Enter number of \'Match\' log entries to view. Set to \'0\' to disable');

$group->add(new Form_Checkbox(
	'alertrefresh',
	'Auto-Refresh',
	NULL,
	$alertrefresh === PfbToggle::On,
	'on'
))->setHelp('Auto&nbsp;Refresh')->setAttribute('title', 'Select to \'Auto-Refresh\' Alerts page every 60 seconds.');

// Remove 'Save' button when Alert Filtering is enabled to avoid saving incorrect filter entries
if (!$pfb['filterlogentries']) {
	$btn_save = new Form_Button(
		'save',
		'Save ' . $alert_view,
		null,
		'fa-solid fa-save'
	);
	$btn_save->removeClass('btn-primary')->addClass('btn-primary btn-xs');
	$group->add(new Form_StaticText(
		NULL,
		$btn_save
	));
}
$section->add($group);

$group = new Form_Group(NULL);
$group->add(new Form_Select(
	'pfbpageload',
	'Default page',
	$pfbpageload,
	$options_pfbpageload
))->setHelp('Select the initial page to load')->setAttribute('style', 'width: auto');

$group->add(new Form_Select(
	'pfbmaxtable',
	'',
	$pfbmaxtable,
	$options_pfbmaxtable
))->setHelp('Select the maximum Stat Table entries to display');

if ($pfb['dnsbl'] === PfbToggle::On) {
	$group->add(new Form_Select(
		'pfbextdns',
		'DNS lookup',
		$pfb['extdns'],
		$options_pfbextdns
	))->setHelp('Select the DNS server for the DNSBL Whitelist CNAME lookup')
	  ->setAttribute('style', 'width: auto');
}
$section->add($group);

$group = new Form_Group(NULL);
$group->add(new Form_Input(
	'ipfilterlimitentries',
	'IP Filter Limit',
	'number',
	$ipfilterlimitentries,
	['min' => 0, 'max' => 2000]
))->setHelp('IP Filter Limit Entries')
  ->setAttribute('title', 'Enter number of \'Filter Limit Entries\' to view. Set to \'0\' to disable');

if ($pfb['dnsbl'] === PfbToggle::On) {
	$group->add(new Form_Input(
		'dnsblfilterlimitentries',
		'DNSBL Filter Limit',
		'number',
		$dnsblfilterlimitentries,
		['min' => 0, 'max' => 2000]
	))->setHelp('DNSBL Filter Limit Entries')
	  ->setAttribute('title', 'Enter number of \'DNSBL Filter Limit Entries\' to view. Set to \'0\' to disable');

	$group->add(new Form_Input(
		'dnsfilterlimitentries',
		'DNS Reply Filter Limit',
		'number',
		$dnsfilterlimitentries,
		['min' => 0, 'max' => 2000]
	))->setHelp('DNS Reply Filter Limit Entries')
	  ->setAttribute('title', 'Enter number of \'DNS Reply Filter Limit Entries\' to view. Set to \'0\' to disable');
}
$section->add($group);

$uni_dnsbl_on = $pfb['dnsbl'] === PfbToggle::On;

$group = new Form_Group('Unified Log: Light Background Theme. Enter \'none\' to disable.');
foreach ($uni_defaults as $u_type => $u_cfg) {
	if ($u_cfg['gated'] && !$uni_dnsbl_on) {
		continue;
	}
	$u_key = "uni{$u_type}";
	$group->add(new Form_Input(
		$u_key,
		'',
		'text',
		$pfb[$u_key],
		['placeholder' => $u_cfg['light_default']]
	))->setHelp($u_cfg['light_help'])
	  ->setAttribute('style', "background: {$pfb[$u_key]}")
	  ->setWidth(2);
}
$section->add($group);

$group = new Form_Group('Unified Log: Dark Background Theme. Enter \'none\' to disable.');
foreach ($uni_defaults as $u_type => $u_cfg) {
	if ($u_cfg['gated'] && !$uni_dnsbl_on) {
		continue;
	}
	$u_key = "uni{$u_type}2";
	$group->add(new Form_Input(
		$u_key,
		'',
		'text',
		$pfb[$u_key],
		['placeholder' => $u_cfg['dark_default']]
	))->setHelp($u_cfg['dark_help'])
	  ->setAttribute('style', "background: {$pfb[$u_key]}; color: white;")
	  ->setWidth(2);
}
$section->add($group);

if ($pfb['dnsbl'] === PfbToggle::On) {
	$group = new Form_Group('DNS Reply Log Options');
	$group->add(new Form_Select(
		'pfbreplytypes',
		'',
		$pfbreplytypes,
		$options_pfbreplytypes,
		TRUE
	))->setHelp('DNS Reply Type Suppress')
	  ->setAttribute('title', 'Select the DNS Types to suppress from the DNS Reply Log')
	  ->setWidth(2)
	  ->setAttribute('size', 6);

	$group->add(new Form_Select(
		'pfbreplyrec',
		'',
		$pfbreplyrec,
		$options_pfbreplyrec,
		TRUE
	))->setHelp('DNS Reply Record Suppress')
	  ->setWidth(2)
	  ->setAttribute('title', 'Select the DNS Record Types to suppress from the DNS Reply Log')
	  ->setAttribute('size', 16);

	$section->add($group);
}

$group = new Form_Group('Event Timeline Options');
$group->add(new Form_Select(
	'pfbchartcnt',
	'',
	$pfbchartcnt,
	$options_pfbchartcnt
))->setHelp('Chart Statistics - Number of logged hours to chart')
  ->setWidth(4)
  ->setAttribute('title', 'Select the Number of logged hours to chart')
  ->setAttribute('size', 15);

$group->add(new Form_Select(
	'pfbchartstyle',
	'',
	$pfbchartstyle,
	$options_pfbchartstyle
))->setHelp('Chart Color Style')
  ->setAttribute('title', 'Select the Event Timeline Chart color style')
  ->setWidth(2)
  ->setAttribute('size', 3);

$group->add(new Form_Input(
	'pfbchart1',
	'',
	'text',
	$pfbchart1,
	['placeholder' => '#0C6197']
))->setHelp('Two-Tone<br />Zero Hour bar color')
  ->setAttribute('style', "background: {$pfbchart1}; color: white;")
  ->setWidth(2);

$group->add(new Form_Input(
	'pfbchart2',
	'',
	'text',
	$pfbchart2,
	['placeholder' => '#7A7A7A']
))->setHelp('Two-Tone<br />Other Hour bar color')
  ->setAttribute('style', "background: {$pfbchart2}; color: white;")
  ->setWidth(2);
$section->add($group);

$group = new Form_Group('Statistics Options');
$group->add(new Form_Select(
	'pfbblockstat',
	'Disabled IP Block Stats',
	$pfbblockstat,
	$options_ip_stats,
	TRUE
))->setHelp("Select the <strong>IP Block</strong> Stat table(s) to hide")
  ->setAttribute('style', 'width: auto; overflow: hidden;')
  ->setAttribute('size', 15);

$group->add(new Form_Select(
	'pfbpermitstat',
	'Disabled IP Permit Stats',
	$pfbpermitstat,
	$options_ip_stats,
	TRUE
))->setHelp("Select the <strong>IP Permit</strong> Stat table(s) to hide")
  ->setAttribute('style', 'width: auto; overflow: hidden;')
  ->setAttribute('size', 15);

$group->add(new Form_Select(
	'pfbmatchstat',
	'Disabled IP Match Stats',
	$pfbmatchstat,
	$options_ip_stats,
	TRUE
))->setHelp("Select the <strong>Match Stat</strong> table(s) to hide")
  ->setAttribute('style', 'width: auto; overflow: hidden;')
  ->setAttribute('size', 15);

if ($pfb['dnsbl'] === PfbToggle::On) {
	$group->add(new Form_Select(
		'pfbdnsblstat',
		'Disabled DNSBL Stats',
		$pfbdnsblstat,
		$options_pfbdnsblstat,
		TRUE
	))->setHelp("Select the <strong>DNSBL Stat</strong> table(s) to hide")
	  ->setAttribute('style', 'width: auto; overflow: hidden;')
	  ->setAttribute('size', 14);

	$group->add(new Form_Select(
		'pfbdnsblreplystat',
		'Disabled DNS Reply Stats',
		$pfbdnsblreplystat,
		$options_pfbdnsblreplystat,
		TRUE
	))->setHelp("Select the <strong>DNS Reply Stat</strong> table(s) to hide")
	  ->setAttribute('style', 'width: auto; overflow: hidden;')
	  ->setAttribute('size', 13);
}
$section->add($group);

if (!$alert_summary) {

	// Build 'Alert Filter' group section
	$filterstatus = SEC_CLOSED;
	if ($pfb['filterlogentries']) {
		$filterstatus = SEC_OPEN;
	}
	$section = new Form_Section('Alert Filter', 'alertfilter', COLLAPSIBLE|$filterstatus);
	$form->add($section);
}

if (!$alert_summary && ($alert_title != 'DNS Reply')) {

	$group = new Form_Group('IP');
	$group->add(new Form_Input(
		'filterlogentries_ipdate',
		'IP - Date',
		'text',
		$filterfieldsarray[0][99]
	))->setAttribute('title', 'Enter filter \'Date\'.');

	$group->add(new Form_Input(
		'filterlogentries_ipint',
		'IP - Interface',
		'text',
		$filterfieldsarray[0][2]
	))->setAttribute('title', 'Enter filter \'Interface\'.');

	$group->add(new Form_Input(
		'filterlogentries_iprule',
		'IP - Rule Number Only',
		'text',
		$filterfieldsarray[0][0]
	))->setAttribute('title', 'Enter filter \'Rule Number\' only.');

	$group->add(new Form_Input(
		'filterlogentries_ipproto',
		'IP - Protocol',
		'text',
		$filterfieldsarray[0][6]
	))->setAttribute('title', 'Enter filter \'Protocol\'.');
	$section->add($group);

	$group = new Form_Group(NULL);
	$group->add(new Form_Input(
		'filterlogentries_ipsrcip',
		'IP - Source Address',
		'text',
		$filterfieldsarray[0][7]
	))->setAttribute('title', 'Enter filter \'Source IP Address\'.');

	$group->add(new Form_Input(
		'filterlogentries_ipsrchostname',
		'IP - Source Hostname',
		'text',
		$filterfieldsarray[0][17]
	))->setAttribute('title', 'Enter filter \'Source Hostname\'.');

	$group->add(new Form_Input(
		'filterlogentries_ipsrcport',
		'IP - Source:Port',
		'text',
		$filterfieldsarray[0][9]
	))->setAttribute('title', 'Enter filter \'Source:Port\'.');
	$section->add($group);

	$group = new Form_Group(NULL);
	$group->add(new Form_Input(
		'filterlogentries_ipdstip',
		'IP - Destination Address',
		'text',
		$filterfieldsarray[0][8]
	))->setAttribute('title', 'Enter filter \'Destination IP Address\'.');

	$group->add(new Form_Input(
		'filterlogentries_ipdsthostname',
		'IP - Destination Hostname',
		'text',
		$filterfieldsarray[0][16]
	))->setAttribute('title', 'Enter filter \'Destination Hostname\'.');

	$group->add(new Form_Input(
		'filterlogentries_ipdstport',
		'IP - Destination:Port',
		'text',
		$filterfieldsarray[0][10]
	))->setAttribute('title', 'Enter filter \'Destination:Port\'.');
	$section->add($group);

	$group = new Form_Group(NULL);
	$group->add(new Form_Input(
		'filterlogentries_ipfeed',
		'IP - Feed',
		'text',
		$filterfieldsarray[0][15]
	))->setAttribute('title', 'Enter filter \'Feed name\'.');

	$group->add(new Form_Input(
		'filterlogentries_ipalias',
		'IP - Alias',
		'text',
		$filterfieldsarray[0][13]
	))->setAttribute('title', 'Enter filter \'Aliasname\'.');

	$group->add(new Form_Input(
		'filterlogentries_ipgeoip',
		'IP - GeoIP',
		'text',
		$filterfieldsarray[0][12]
	))->setAttribute('title', 'Enter filter \'GeoIP\'.')
	  ->setwidth(2);

	$group->add(new Form_Input(
		'filterlogentries_ipasn',
		'IP - ASN',
		'text',
		$filterfieldsarray[0][18]
	))->setAttribute('title', 'Enter filter \'ASN\'.')
	  ->setwidth(2);
	$section->add($group);

	if ($pfb['dnsbl'] === PfbToggle::On) {
		$group = new Form_Group('DNSBL');
		$group->add(new Form_Input(
			'filterlogentries_dnsbldate',
			'DNSBL - Date',
			'text',
			$filterfieldsarray[1][99]
		))->setAttribute('title', 'Enter filter \'Date\'.');

		$group->add(new Form_Input(
			'filterlogentries_dnsblint',
			'DNSBL - Interface',
			'text',
			$filterfieldsarray[1][2]
		))->setAttribute('title', 'Enter filter \'Interface\'.');
		$section->add($group);

		$group = new Form_Group(NULL);
		$group->add(new Form_Input(
			'filterlogentries_dnsbldomain',
			'DNSBL - Domain',
			'text',
			$filterfieldsarray[1][8]
		))->setAttribute('title', 'Enter filter \'Enter filter \'Domain\'.');

		$group->add(new Form_Input(
			'filterlogentries_dnsblsrcip',
			'DNSBL - Source Address',
			'text',
			$filterfieldsarray[1][7]
		))->setAttribute('title', 'Enter filter \'Source IP Address\'.');

		$group->add(new Form_Input(
			'filterlogentries_dnsblsrchostname',
			'DNSBL - Source Hostname',
			'text',
			$filterfieldsarray[1][17]
		))->setAttribute('title', 'Enter filter \'Source Hostname\'.');
		$section->add($group);

		$group = new Form_Group(NULL);
		$group->add(new Form_Input(
			'filterlogentries_dnsblfeed',
			'DNSBL - Feed',
			'text',
			$filterfieldsarray[1][15]
		))->setAttribute('title', 'Enter filter \'Feed name\'.');

		$group->add(new Form_Input(
			'filterlogentries_dnsblgroup',
			'DNSBL - Group',
			'text',
			$filterfieldsarray[1][13]
		))->setAttribute('title', 'Enter filter \'Group name\'.');
		$section->add($group);

		$f19_title = (gettext("DNSBL: Blocking Type"));
		$group = new Form_Group(NULL);
		$group->add(new Form_Input(
			'filterlogentries_dnsbltype',
			$f19_title,
			'text',
			$filterfieldsarray[1][19]
		))->setAttribute('title', "Enter filter '{$f19_title}'.");

		$group->add(new Form_Input(
			'filterlogentries_dnsblmode',
			'DNSBL - Blocking Mode',
			'text',
			$filterfieldsarray[1][20]
		))->setAttribute('title', 'Enter filter \'DNSBL Blocking Mode (ie: DNSBL/TLD)\'.');
		$section->add($group);
	}
}

if (!$alert_summary && ($alert_title == 'DNS Reply' || $alert_title == 'Unified Logs')) {

	$group = new Form_Group('DNS Reply');
	$group->add(new Form_Input(
		'filterlogentries_replydate',
		'Reply - Date',
		'text',
		$filterfieldsarray[2][89]
	))->setAttribute('title', 'Enter filter \'DNS Reply Date\'.');

	$group->add(new Form_Input(
		'filterlogentries_replydomain',
		'Reply - Domain',
		'text',
		$filterfieldsarray[2][85]
	))->setAttribute('title', 'Enter filter \'DNS Reply Domain\'.');
	$section->add($group);

	$group = new Form_Group(NULL);
	$group->add(new Form_Input(
		'filterlogentries_replysrcip',
		'Reply - Source IP',
		'text',
		$filterfieldsarray[2][86]
	))->setAttribute('title', 'Enter filter \'DNS Reply SRC IP\'.');

	$group->add(new Form_Input(
		'filterlogentries_replydstip',
		'Reply - Resolved IP',
		'text',
		$filterfieldsarray[2][87]
	))->setAttribute('title', 'Enter filter \'DNS Resolved IP\'.');

	$group->add(new Form_Input(
		'filterlogentries_replygeoip',
		'Reply - GeoIP',
		'text',
		$filterfieldsarray[2][88]
	))->setAttribute('title', 'Enter filter \'DNS Reply GeoIP\'.')
	  ->setwidth(2);
	$section->add($group);

	$group = new Form_Group(NULL);
	$group->add(new Form_Input(
		'filterlogentries_replytype',
		'Reply - Type',
		'text',
		$filterfieldsarray[2][81]
	))->setAttribute('title', 'Enter filter \'DNS Reply Type\'.');

	$group->add(new Form_Input(
		'filterlogentries_replyorec',
		'Reply - Original Record',
		'text',
		$filterfieldsarray[2][82]
	))->setAttribute('title', 'Enter filter \'DNS Reply Orig Record\'.');

	$group->add(new Form_Input(
		'filterlogentries_replyrec',
		'Reply - DNS Record',
		'text',
		$filterfieldsarray[2][83]
	))->setAttribute('title', 'Enter filter \'DNS Reply Record\'.');

	$group->add(new Form_Input(
		'filterlogentries_replyttl',
		'Reply - TTL',
		'text',
		$filterfieldsarray[2][84]
	))->setAttribute('title', 'Enter filter \'DNS Reply TTL\'.');
	$section->add($group);
}

if (!$alert_summary) {
	$group = new Form_Group(NULL);
	$btnsubmit = new Form_Button(
		'filterlogentries_submit',
		'Apply Filter',
		NULL,
		'fa-solid fa-filter'
	);
	$btnsubmit->removeClass('btn-primary')->addClass('btn-primary btn-xs');

	$btnclear = new Form_Button(
		'filterlogentries_clear',
		gettext('Clear Filter'),
		NULL,
		'fa-filter fa-solid fa-rotate-180'
	);
	$btnclear->removeClass('btn-primary')->addClass('btn-danger btn-xs');

	$group->add(new Form_StaticText(
		'',
		$btnsubmit
	))->setwidth(1);

	$group->add(new Form_StaticText(
		'',
		$btnclear
	))->setwidth(1);
	$section->add($group);

	$group = new Form_Group(NULL);
	$group->add(new Form_StaticText(
		'',
		'( Save disabled during <strong>Apply Filter</strong>)'
		. '&emsp;<div class="infoblock">'
		. '<h6>Regex Style Matching Only! Do not prefix/suffix field with a backslash! <a href="https://regexr.com/" target="_blank" rel="noopener noreferrer">Regular Expression Help link</a>. '
		. 'Precede with exclamation (!) as first character to exclude match.)</h6>'
		. '<h6>Example: ( ^80$ - Match Port 80, ^80$|^8080$ - Match both port 80 & 8080 )</h6>'
		. '</div>'
	));
	$section->add($group);

	$form->addGlobal(new Form_Input('domain', 'domain', 'hidden', ''));
	$form->addGlobal(new Form_Input('dnsbl_customlist', 'dnsbl_customlist', 'hidden', ''));
	$form->addGlobal(new Form_Input('table', 'table', 'hidden', ''));
	$form->addGlobal(new Form_Input('descr', 'descr', 'hidden', ''));
	$form->addGlobal(new Form_Input('ip', 'ip', 'hidden', ''));
	$form->addGlobal(new Form_Input('addsuppress', 'addsuppress', 'hidden', ''));
	$form->addGlobal(new Form_Input('addwhitelistdom', 'addwhitelistdom', 'hidden', ''));
	$form->addGlobal(new Form_Input('entry_delete', 'entry_delete', 'hidden', ''));
	$form->addGlobal(new Form_Input('dnsbl_wildcard', 'dnsbl_wildcard', 'hidden', ''));
	$form->addGlobal(new Form_Input('dnsbl_exclude', 'dnsbl_exclude', 'hidden', ''));
	$form->addGlobal(new Form_Input('dnsbl_remove', 'dnsbl_remove', 'hidden', ''));
	$form->addGlobal(new Form_Input('dnsbl_type', 'dnsbl_type', 'hidden', ''));
	$form->addGlobal(new Form_Input('dnsbl_add', 'dnsbl_add', 'hidden', ''));
	$form->addGlobal(new Form_Input('ip_remove', 'ip_remove', 'hidden', ''));
	$form->addGlobal(new Form_Input('ip_white', 'ip_white', 'hidden', ''));
	$form->addGlobal(new Form_Input('alert_view', 'alert_view', 'hidden', $alert_view));
}
print($form);

if (!$alert_summary):

	// Print Unlocked IPs and Domain table
	if (!empty($ip_unlock) || !empty($dnsbl_unlock)): ?>

<div class="panel panel-default" style="display: inline-block; width: 100%;">
	<div class="panel-heading">
		<h2 class="panel-title">&nbsp;<?=gettext('Unlocked IP(s) & Domain(s)')?></h2>
	</div>

	<?php
		$height = min( max( array( max(count($ip_unlock), 1), max(count($dnsbl_unlock), 1))) * 63, 200);
		foreach (array( array($ip_unlock, 'IP', 'Table'),
				array($dnsbl_unlock, 'Domain', 'Type')) as $key => $data):

			$float = $key %2 ? 'right' : 'left';
	?>

	<div style="float: <?=$float;?>; width: 50%; height: <?=$height;?>px; overflow-y: scroll;">
		<div class="panel-body">
			<table class="table table-striped table-hover table-compact sortable-theme-bootstrap" data-sortable>
			<thead>
				<tr>
					<th><?=gettext("Unlocked " . htmlspecialchars($data[1]) . "(s)")?></th>
					<th><?=gettext(htmlspecialchars($data[2]))?></th>
				</tr>
			</thead>
			<tbody>
	<?php
			foreach ($data[0] as $entry => $type) {
				$kind = ($key == 0) ? 'ip' : 'dnsbl';
				$actions = pfb_alerts_unlocked_entry_actions($kind, (string) $entry, (string) $type, $clists);
				$alert = $actions['alert'];
				$unlock = $actions['unlock'];
				$supp = $actions['supp'];

				print ("<tr><td>&nbsp;{$alert}&emsp;{$unlock}&emsp;{$supp}&emsp;" . htmlspecialchars($entry) . "</td><td>" . htmlspecialchars($type) . "</td></tr>");
			}
	?>
			</tbody>
			</table>
		</div>
	</div>
		<?php endforeach; ?>
</div>
	<?php
	endif; // End Print Unlocked IPs and Domain table

	// Create four output windows 'Block', 'DNSBL', 'Permit' and 'Match' -> 'Alerts Tab'
	// or Create DNS Reply Tab
	// or Create Unified Log Tab

	$skipcount 	= 0;
	$counter 	= array('Block' => 0, 'Permit' => 0, 'Match' => 0, 'Unified' => 0, 'DNSBL' => 0, 'DNS' => 0);
	$dup		= array('Block' => 0, 'Permit' => 0, 'Match' => 0, 'DNSBL' => 0, 'Unified' => 0);

	// Suppress user-defined reply types
	if (isset($pfbreplytypes) && !empty($pfbreplytypes[0])) {
		$pfbreplytypes = array_flip($pfbreplytypes);
	} else {
		unset($pfbreplytypes);
	}

	if (isset($pfbreplyrec) && !empty($pfbreplyrec[0])) {
		$pfbreplyrec = array_flip($pfbreplyrec);
	} else {
		unset($pfbreplyrec);
	}

	foreach (array (	'Block'		=> "{$pfb['ip_blocklog']}",
				'DNSBL Block'	=> "{$pfb['dnslog']}",
				'DNSBL Python'	=> "{$pfb['dnslog']}",
				'DNS Reply'	=> "{$pfb['dnsreplylog']}",
				'Permit'	=> "{$pfb['ip_permitlog']}",
				'Match'		=> "{$pfb['ip_matchlog']}",
				'Unified'	=> "{$pfb['unilog']}") as $logtype => $pfb_log ):

		// $pfbentries gets a definite default here (issue #809, same approach as
		// $folder above): every reachable path below overwrites it before the
		// post-switch reads (the "Skip table output" gate, the Unified early-exit
		// call, the <tfoot> message) -- the `continue 2` paths skip those reads too.
		// The default makes that provable to PHPStan instead of relying on it to
		// trace the switch/if/continue control flow.
		$pfbentries = 0;

		// Validate Alert view and Log type
		switch ($alert_view) {
			case 'alert':
				if ($pfb['dnsbl'] === PfbToggle::On) {
					$pfbentries = "{$pfbdnscnt}";
					if ($pfb['filterlogentries'] && $dnsblfilterlimitentries != 0) {
						$pfbentries = $dnsblfilterlimitentries;
					}

					if ($logtype == 'DNSBL Block') {
						continue 2;
					}
					elseif ($logtype == 'DNSBL Python') {
						break;
					}
				}

				if ($logtype == 'Block') {
					$rtype = 'Block';
					$pfbentries = "{$pfbdenycnt}";
					if ($pfb['filterlogentries'] && $ipfilterlimitentries != 0) {
						$pfbentries = $ipfilterlimitentries;
					}
					break;
				}
				elseif ($logtype == 'Permit') {
					$rtype = 'Permit';
					$pfbentries = "{$pfbpermitcnt}";
					if ($pfb['filterlogentries'] && $ipfilterlimitentries != 0) {
						$pfbentries = $ipfilterlimitentries;
					}
					break;
				}
				elseif ($logtype == 'Match') {
					$rtype = 'Match';
					$pfbentries = "{$pfbmatchcnt}";
					if ($pfb['filterlogentries'] && $ipfilterlimitentries != 0) {
						$pfbentries = $ipfilterlimitentries;
					}
					break;
				}
				continue 2;
			case 'reply':
				if ($logtype == 'DNS Reply') {
					$pfbentries = "{$pfbdnsreplycnt}";
					if ($pfb['filterlogentries'] && $dnsfilterlimitentries != 0) {
						$pfbentries = $dnsfilterlimitentries;
					}
					break;
				}
				continue 2;
			case 'unified':
				if ($logtype == 'Unified') {
					$pfbentries = "{$pfbunicnt}";
					break;
				}
				continue 2;
			default:
				continue 2;
		}

		// Skip table output if $pfbentries is zero.
		if ($pfbentries == 0 && $skipcount != 5) {
			$skipcount++;
			continue;
		}

		$ipfilterlimit = $dnsblfilterlimit = $dnsfilterlimit = FALSE;
		?>

<div class="panel panel-default" style="width: 100%;">
	<div class="panel-heading">
		<h2 class="panel-title">
			<? if ($alertrefresh === PfbToggle::On): ?>
			<i class="fa-solid fa-pause-circle" id="PauseRefresh" " title="Pause Alerts Refresh"></i>&nbsp;
			<? endif; ?>
			<?=gettext($logtype)?><small>-&nbsp;<?=gettext('Last')?>&nbsp;<?=$pfbentries?>&nbsp;<?=gettext('Alert Entries')?></small>
		</h2>
	</div>
	<div class="panel-body">
		<div class="table-responsive">
		<table style="width: 100%;" class="table table-striped table-hover table-compact sortable-theme-bootstrap<?= $logtype == 'Unified' ? ' pfb-unified' : '' ?>" data-sortable>

	<?php
		// Create Unified Report
		$handle = FALSE;
		$p_query_port = '';
		if ($logtype == 'Unified' && file_exists("{$pfb_log}")) {
	?>
			<thead>
				<tr>
					<th style="max-width:5%;"><?=gettext("Date")?></th>
					<th style="max-width:1%;"><!----- Buttons -----></th>
					<th style="max-width:10%;"><?=gettext("SRC")?></th>
					<th style="max-width:3%;"><?=gettext("Rule|Mode/Type")?></th>
					<th style="max-width:20%;"><?=gettext("IF/TTL")?></th>
					<th style="max-width:1%;"><!----- Buttons -----></th>
					<th style="max-width:20%;"><?=gettext("Destination")?></th>
					<th style="max-width:20%;"><?=gettext("Resolved/Feed")?></th>
					<th style="max-width:20%;"><?=gettext("GeoIP")?></th>
				</tr>
			</thead>
			<tbody>
	<?php
			// This loop reads the reversed log via a popen() stream (no on-disk .rev
			// copy, issue #809) and breaks as soon as pfb_alerts_unified_scan_done()
			// determines no converter (convert_dnsbl_log() / convert_dns_reply_log() /
			// convert_ip_log()) can render another row -- see that helper for the exact
			// non-filter/filter mode conditions. If any per-type filter-limit knob is 0
			// (unlimited) its flag never sets and this still scans to EOF, exactly as before.
			// issue #1369: every fgetcsv() call reading these logs (all 5 sites in this
			// file) passes an explicit empty escape argument, matching the writer's
			// pfb_asn_csv_fields()/fputcsv() -- a bare fgetcsv() defaults to a backslash
			// escape char, which would mis-parse a literal backslash inside a quoted ASN
			// domain/name field (RFC4180 has no escape char at all; PHP's default is a
			// non-standard extension the two sides must agree on to round-trip).
			if (($handle = @popen('/usr/bin/tail -r ' . escapeshellarg($pfb_log), 'r')) !== FALSE) {
				while (($fields = @fgetcsv($handle, 0, ',', '"', '')) !== FALSE) {

					if (pfb_alerts_unified_scan_done($pfb['filterlogentries'], $counter['Unified'], $pfbentries, $ipfilterlimit, $dnsblfilterlimit, $dnsfilterlimit)) {
						break;
					}

					// Filter Unified Log for specific Log Types
					if ($pfb['filterlogentries'] && !isset($filter_unified[$fields[0]])) {
						continue;
					}

					switch ($fields[0]) {
						case 'DNSBL-Full':
						case 'DNSBL-1x1':
						case 'DNSBL-HTTPS':
						case 'DNSBL-python':
							convert_dnsbl_log('Unified', $fields);
							break;
						case 'DNS-reply':

							// Suppress user-defined reply types
							if (isset($pfbreplytypes) && isset($pfbreplytypes[$fields[2]])) {
								continue 2;
							}

							// Suppress user-defined DNS Records
							if (isset($pfbreplyrec) && (isset($pfbreplyrec[$fields[3]]) || isset($pfbreplyrec[$fields[4]]))) {
								continue 2;
							}

							convert_dns_reply_log('Unified', $fields);
							break;
						case 'Block':
							$rtype = 'Block';
						case 'Permit':
							$rtype = empty($rtype) ? 'Permit' : $rtype;
						case 'Match':
							$rtype = empty($rtype) ? 'Match' : $rtype;
							array_shift($fields); // Remove Unified log prefix field
							convert_ip_log('Unified', $fields, $p_query_port, $rtype);
							break;
						default:
							break;
					}
				}
			}
			if ($handle) {
				@pclose($handle);
			}
		}

		// Process dns array for DNSBL and generate output
		if (($logtype == 'DNSBL Block' || $logtype == 'DNSBL Python') && file_exists("{$pfb_log}")) {
	?>
			<thead>
				<tr>
					<th><?=gettext("Date")?></th>
					<th><?=gettext("IF")?></th>
					<th><?=gettext("Source")?></th>
					<th style="width: 5.3%;"><!----- Buttons -----></th>
					<th><?=$logtype == 'DNSBL Python' ? gettext("Domain/Block mode") : gettext("Domain/Referer|URI|Agent")?></th>
					<th><?=gettext("Feed/Group")?></th>
				</tr>
			</thead>
			<tbody>
	<?php
			// ADR-65: a single streaming pass -- rows render straight from their own
			// logged fields now, so there is nothing left to batch-prefetch between passes.
			if (($handle = @popen('/usr/bin/tail -r ' . escapeshellarg($pfb_log), 'r')) !== FALSE) {
				while (($fields = @fgetcsv($handle, 0, ',', '"', '')) !== FALSE) {

					// Remove and record duplicate entries
					if ($fields[9] == '-') {
						$dup['DNSBL']++;
						continue;
					}
					if (convert_dnsbl_log('non_unified', $fields)) {
						break;
					}
					$dup['DNSBL'] = 0;
				}
			}
			if ($handle) {
				@pclose($handle);
			}
		}

		// Process DNS Reply log and generate output
		if ($logtype == 'DNS Reply' && file_exists("{$pfb_log}")) {
	?>
			<thead>
				<tr>
					<th style="width:10%"><?=gettext("Date")?></th>
					<th style="width:10%"><?=gettext("Source")?></th>
					<th style="width:3%"><?=gettext("Reply Type")?></th>
					<th style="width:3%"><?=gettext("Orig Record")?></th>
					<th style="width:3%"><?=gettext("DNS Record")?></th>
					<th style="width:1%"><!----- Buttons -----></th>
					<th style="width:15%"><?=gettext("Domain")?></th>
					<th style="width:4%" title="TTL remaining"><?=gettext("TTL")?></th>
					<th style="width:15%"><?=gettext("Resolved")?></th>
					<th style="width:3%"><?=gettext("GeoIP")?></th>
				</tr>
			</thead>
			<tbody>
	<?php
			if (($handle = @popen('/usr/bin/tail -r ' . escapeshellarg($pfb_log), 'r')) !== FALSE) {
				while (($fields = @fgetcsv($handle, 0, ',', '"', '')) !== FALSE) {

					// Suppress user-defined reply types
					if (isset($pfbreplytypes) && isset($pfbreplytypes[$fields[2]])) {
						continue;
					}

					// Suppress user-defined DNS Records
					if (isset($pfbreplyrec) && (isset($pfbreplyrec[$fields[3]]) || isset($pfbreplyrec[$fields[4]]))) {
						continue;
					}

					if (convert_dns_reply_log('non_unified', $fields)) {
						break;
					}
				}
			}
			if ($handle) {
				@pclose($handle);
			}
		}

		// Process Deny/Permit/Match and generate output
		if (($logtype == 'Block' || $logtype == 'Permit' || $logtype == 'Match') && file_exists("{$pfb_log}")) {

	?>
		<thead>
			<tr>
				<th><?=gettext("Date")?></th>
				<th><?=gettext("IF")?></th>
				<th><?=gettext("Rule")?></th>
				<th><?=gettext("Proto")?></th>
				<th><!----- Buttons -----></th>
				<th><?=gettext("Source")?></th>
				<th><!----- Buttons -----></th>
				<th><?=gettext("Destination")?></th>
				<th><?=$pfb['asn_reporting'] != 'disabled' ? gettext("GeoIP/ASN") : gettext("GeoIP")?></th>
				<th><?=gettext("Feed")?></th>
			</tr>
		</thead>
		<tbody>
	<?php

			$p_query_port = '';
			// $rtype is set above (case 'alert' of the switch($alert_view) block, same
			// $logtype iteration) whenever this Block/Permit/Match section is reached;
			// PHPStan can't trace that correlation, so this coalesce is a runtime no-op
			// that keeps every read below provably defined -- same idiom the two-pass
			// branch below already uses.
			$rtype = $rtype ?? '';

			// issue #809 scope guard: batching below only runs when a finite row bound
			// exists -- non-filter mode (bound $pfbentries), or filter mode with a real
			// per-row limit ($ipfilterlimitentries != 0) AND real filter fields set.
			// Otherwise the log genuinely scans to EOF (unbounded buffer unsafe), so both
			// cases keep the single-pass streaming loop. See docs/misc/alerts-reports-pipeline.md.
			// issue #1497: $ipfilterlimitentries is now an explicit top-of-page
			// assignment (was a ${"$type"} variable-variable loop PHPStan couldn't
			// trace), so it is provably defined here -- no coalesce needed.
			$ip_two_pass = !$pfb['filterlogentries'] || ($ipfilterlimitentries != 0 && !empty($filterfieldsarray[0]));

			if (!$ip_two_pass) {
				if (($handle = @popen('/usr/bin/tail -r ' . escapeshellarg($pfb_log), 'r')) !== FALSE) {
					while (($fields = @fgetcsv($handle, 0, ',', '"', '')) !== FALSE) {
						$last_fld = array_pop($fields);

						// Remove and record duplicate entries
						if ($last_fld == '-') {
							$dup[$rtype]++;
							continue;
						}

						$convert_ip = convert_ip_log('non_unified', $fields, $p_query_port, $rtype);
						if ($convert_ip[0]) {
							break;
						} else {
							$p_query_port	= $convert_ip[1];
						}
					}
				}
				if ($handle) {
					@pclose($handle);
				}
			} else {
				// Two passes over the reversed log instead of one: render-time IP lookups for
				// every buffered row are batched via pfb_ip_prefetch() instead of one-to-three
				// exec()s per row. Buffer entries: array($fields, TRUE) (accepted row), int N
				// (N dup-marker lines), or array('rej'=>TRUE,'dup'=>N) (a mixed dup/reject run
				// collapsed to one gap marker). Bound + correctness proof:
				// docs/misc/alerts-reports-pipeline.md; compression logic is
				// pfb_alerts_ip_buffer_push() (pfblockerng.inc), pinned by AlertsBufferReplayTest.
				$ip_buffered	  = array();
				$ip_accepted_seen = 0;
				if (($handle = @popen('/usr/bin/tail -r ' . escapeshellarg($pfb_log), 'r')) !== FALSE) {
					while (($fields = @fgetcsv($handle, 0, ',', '"', '')) !== FALSE) {
						$last_fld = array_pop($fields);

						// Duplicate-marker line: extend the current run.
						if ($last_fld == '-') {
							pfb_alerts_ip_buffer_push($ip_buffered, 'dup');
							continue;
						}

						// issue #1369: a legacy/malformed row's field count never matches
						// the current schema -- fold it into the SAME gap-marker path as a
						// filtered row, so it is never buffered and never reaches Pass 1.5's
						// pfb_ip_render_query() (which assumes the current schema's fixed
						// indices) or pfb_match_filter_field() below. convert_ip_log()'s own
						// guard is a backstop for the OTHER two callers, not the only one here.
						if (!pfb_ip_log_row_schema_ok($fields, 'non_unified')) {
							pfb_alerts_ip_buffer_push($ip_buffered, 'reject');
							continue;
						}

						// Filter-mode acceptance, replicated with the SAME function
						// convert_ip_log() itself calls -- on a COPY, since Pass 2 must
						// replay the buffered $fields UNMODIFIED (convert_ip_log() does this
						// exact reorder itself, as its own first line).
						$accepted = TRUE;
						if ($pfb['filterlogentries']) {
							$ip_copy = $fields;
							$ip_copy[99] = array_shift($ip_copy);
							$accepted = pfb_match_filter_field($ip_copy, $filterfieldsarray[0]);
						}

						// Rejected line: fold into a gap marker. The row's fields are
						// deliberately NOT kept -- see the constant-effect argument above.
						if (!$accepted) {
							pfb_alerts_ip_buffer_push($ip_buffered, 'reject');
							continue;
						}

						// Accepted row: buffered POST-dup-pop, PRE-reorder -- exactly the
						// shape convert_ip_log() itself expects as input.
						$ip_buffered[] = array($fields, TRUE);
						$ip_accepted_seen++;

						if ($ip_accepted_seen >= ($pfbentries + 1)) {
							break;
						}
					}
				}
				if ($handle) {
					@pclose($handle);
				}

				// Pass 1.5 (derive + batch): every ACCEPTED buffered row's lookups, via the
				// SAME helper (pfb_ip_render_query()) the Pass 2 attribution seam calls
				// -- so the two passes can never derive a different answer for the same row.
				// int runs and gap markers carry no fields and are never looked up.
				$ip_prefetch_rows = array();
				foreach ($ip_buffered as $ip_entry) {
					if (is_int($ip_entry) || isset($ip_entry['rej'])) {
						continue;
					}
					list($ip_fields, ) = $ip_entry;

					$ip_copy = $ip_fields;
					$ip_copy[99] = array_shift($ip_copy);
					$ip_rq = pfb_ip_render_query($ip_copy);

					$ip_prefetch_rows[] = array(
						'host'			=> $ip_rq['host'],
						'folder'		=> $ip_rq['folder'],
						'pfb_geoip'		=> $ip_rq['pfb_geoip'],
						'validate_file_cmd'	=> $ip_rq['validate_file_cmd'],
						'validate_cmd'		=> $ip_rq['validate_cmd'],
						'eval_ip_raw'		=> $ip_copy[14],
					);
				}
				pfb_ip_prefetch($ip_prefetch_rows);

				// Pass 2 (render): replay the buffer in the same (reversed) order via
				// pfb_alerts_ip_replay_step() (pfblockerng.inc; decode contract documented
				// there), unit-pinned by AlertsBufferReplayTest -- 'render' rows replay through
				// the unchanged convert_ip_log() loop body, whose attribution seam consults the
				// batched pfb_ip_render_memos() first. $rtype was already coalesced above (the
				// $ipfilterlimitentries coalesce note), so it is provably defined here.
				foreach ($ip_buffered as $ip_entry) {
					$ip_step = pfb_alerts_ip_replay_step($ip_entry);
					if (isset($ip_step['dup_add'])) {
						$dup[$rtype] += $ip_step['dup_add'];
						continue;
					}
					if (isset($ip_step['gap'])) {
						$dup[$rtype] = $ip_step['gap'];
						$p_query_port = '';
						continue;
					}
					$fields = $ip_step['render'];

					$convert_ip = convert_ip_log('non_unified', $fields, $p_query_port, $rtype);
					if ($convert_ip[0]) {
						break;
					} else {
						$p_query_port	= $convert_ip[1];
					}
				}
			}
		}
	?>
		</tbody>
		<tfoot>
	<?php
		// $logtype only ever takes the seven literal keys of the foreach array above
		// (issue #809's same reasoning as $pfbentries's default), so every case below
		// is exhaustive in practice -- but PHPStan can't narrow the switch subject to
		// that literal union, so it treats the (unreachable) default as leaving these
		// unset. Behaviour-neutral defaults keep the post-switch reads provably defined.
		$colspan = '';
		$fcounter = 0;
		$pfbfilterlimit = FALSE;
		// $rtype is set above (case 'alert' of the switch($alert_view) block) whenever
		// $logtype is 'Block'/'Permit'/'Match' -- the only way the case below is
		// reached -- but the tbody's own coalesce above only runs when file_exists()
		// gates it TRUE (a fresh-install log-not-yet-created iteration skips it), so
		// this file-scope read needs its own no-op coalesce.
		$rtype = $rtype ?? '';
		switch ($logtype) {
			case 'Block':
			case 'Permit':
			case 'Match':
				$colspan = "colspan='10'";
				$fcounter = $counter[$rtype];
				$pfbfilterlimit = $ipfilterlimit;
				break;
			case 'DNSBL Block':
			case 'DNSBL Python':
				$colspan = "colspan='7'";
				$fcounter = $counter['DNSBL'];
				$pfbfilterlimit = $dnsblfilterlimit;
				break;
			case 'DNS Reply':
				$colspan = "colspan='7'";
				$fcounter = $counter['DNS'];
				$pfbfilterlimit = $dnsfilterlimit;
				break;
			case 'Unified':
				$colspan = "colspan='9'";

				if ($pfb['filterlogentries']) {
					$pfbfilterlimit = FALSE;
					if ($ipfilterlimit && $dnsblfilterlimit && $dnsfilterlimit) {
						$pfbfilterlimit = TRUE;
					}
					$fcounter = 0;
					foreach ($counter as $c) {
						$fcounter += $c;
					}
				}
				else {
					$pfbfilterlimit = FALSE;
					$fcounter = $counter['Unified'];
				}
				break;
			default:
				break;
		}

		// Print final table info
		$msg = '';
		if ($pfbfilterlimit) {
			$msg = " - Filter Limit setting reached.";
		} elseif (!$pfb['filterlogentries'] && $pfbentries != $fcounter) {
			$msg = ' - Insufficient Alerts found.';
		}

		if ($logtype == 'Unified') {
			$fcounter = "{$fcounter} (IP/DNSBL/DNS Reply)";
		}

		print ("			<td {$colspan} style='font-size:10px; color: red; background-color: rgba(128, 128, 128, 0.2);' >Found {$fcounter} Alert Entries{$msg}</td>");
		$fcounter = 0; $msg = '';
	?>

		</tfoot>
	</table>
	</div>
</div>
</div>
	<?php
		endforeach;	// End - Create four output windows ('Deny', 'DNSBL', 'Permit' and 'Match') or DNS Reply or Unified Log
	?>

<!-- Show Icon Legend -->
<div class="infoblock">
<div class="alert alert-info clearfix" role="alert">
	<dl class="dl-horizontal responsive">
		<dt><?=gettext('Icon')?></dt>
			<dd><?=gettext('Legend')?></dd>
		<dt><i class="fa-solid fa-info">&nbsp;</i></dt>
			<dd><?=gettext('Links to Threat Source lookups');?></dd>
		<dt><i class="fa-solid fa-plus"></i></dt>
			<dd><?=gettext('Whitelist a IP/Domain');?></dd>
		<dt><i class="fa-solid fa-plus-circle"></i></dt>
			<dd><?=gettext('Whitelist 1) A GeoIP or large CIDR IP or 2) A TLD Domain');?></dd>
		<dt><i class="fa-regular fa-hand"></i></dt>
			<dd><?=gettext('Domain is blocked by a whole TLD');?></dd>
		<dt><i class="fa-solid fa-trash-can"></i></dt>
			<dd><?=gettext('IP/Domain is already Whitelisted');?></dd>
		<dt><i class="fa-regular fa-trash-can"></i></dt>
			<dd><?=gettext('Domain is in the TLD Exclusion customlist');?></dd>
		<dt><i class="fa-solid fa-lock text-danger"></i></dt>
			<dd><?=gettext('IP/Domain is locked');?></dd>
		<dt><i class="fa-solid fa-unlock"></i></dt>
			<dd><?=gettext('IP/Domain is unlocked');?></dd>
	</dl>
</div>
</div>

<?php

elseif ($alert_summary):

// Print Statistics table/graphs
if (!$pfb['filterlogentries']):?>

<form action="/pfblockerng/pfblockerng_alerts.php" method="post" name="iform_stats" id="iform_stats" class="form-horizontal">
<script src="../vendor/d3/d3.min.js?v=<?=pfb_file_mtime('/usr/local/www/vendor/d3/d3.min.js')?>"></script>
<script src="../vendor/d3pie/d3pie.min.js"></script>
<script src="../vendor/nvd3/nv.d3.min.js?v=<?=pfb_file_mtime('/usr/local/www/vendor/nvd3/nv.d3.min.js')?>"></script>
<link href="../vendor/nvd3/nv.d3.min.css" media="screen, projection" rel="stylesheet" type="text/css">

<div class="panel panel-default">
<div class="panel-heading">
	<h2 class="panel-title">
		<?=$alert_title;?> Statistics&emsp;<small>Total event(s):
		&emsp;[ <?=$alert_stats['count'][$alert_view];?> ]</small>
	</h2>
</div>
</div>

<div class="panel-body">
<?php
$segcolors = array(	"#2484c1", "#65a620", "#7b6888", "#a05d56", "#961a1a", "#d8d23a", "#e98125", "#d0743c", "#635222", "#6ada6a",
			"#0c6197", "#7d9058", "#207f33", "#44b9b0", "#bca44a", "#e4a14b", "#a3acb2", "#8cc3e9", "#69a6f9", "#5b388f" );

if ($alert_summary && $alert_view == 'dnsbl_stat') {
$stats = array( 'dnsblchart'	=> array("DNSBL Event Timeline&emsp;<small>(Last <span id=\"range\">{$pfbchartcnt}</span> hours)</small>",'','', FALSE, ''),
		'dnsbldomain'	=> array('Top Blocked Domain',			'Found', 'Blocked Domain(s)',	TRUE, 'domain'),
		'dnsblevald'	=> array('Top Blocked Evaluated Domain (TLD)',	'Found', 'Blocked Domain(s)',	TRUE, 'domain'),
		'dnsblgptotal'	=> array('Top Group Count',			'Found', 'DNSBL Group(s)',	FALSE, ''),
		'dnsblgpblock'	=> array('Top Blocked Group',			'Found', 'DNSBL Group(s)',	FALSE, ''),
		'dnsblfeed'	=> array('Top Feed',				'Found', 'Feed(s)',		FALSE, ''),
		'dnsblip'	=> array('Top Source IP',			'Found', 'Source IP(s)',	FALSE, ''),
		'dnsblagent'	=> array('Blocking Type', 'Found',
					'Type(s)',		FALSE, ''),
		'dnsbltld'	=> array('Top TLD',				'Found', 'TLD(s)',		FALSE, ''),
		'dnsblwebtype'	=> array('Top Blocked Webpage Types',		'Found', 'Blocked Webpage Type(s)',	FALSE, ''),
		'dnsblmode'	=> array('Top DNSBL Modes',			'Found', 'Blocked DNSBL Mode(s)',	FALSE, ''),
		'dnsbldatehr'	=> array('Top Date/Hr',				'Found', 'Date/Hr segment(s)',		FALSE, ''),
		'dnsbldatehrmin'=> array('Top Date/Hr/Min',			'Found', 'Date/Hr/Min segment(s)',	FALSE, ''),
		'dnsbldate'	=> array('Top Date',				'Found', 'day(s) of logs',		FALSE, '') );
}
elseif ($alert_summary && $alert_view == 'dnsbl_reply_stat') {
$stats = array( 'replychart'	=> array("Reply Event Timeline&emsp;<small>(Last <span id=\"range\">{$pfbchartcnt}</span> hours)</small>",'','', FALSE, ''),
			'replydomain'	=> array('Top Reply Domain',			'Found', 'Reply Domain(s)',	FALSE, 'domain'),
			'replytld'	=> array('Top Reply TLD',			'Found', 'Reply TLD(s)',	FALSE, ''),
			'replytld2'	=> array('Top Reply TLD 2nd level',		'Found', 'Reply TLD(s)',	FALSE, ''),
			'replytld3'	=> array('Top Reply TLD 3rd level',		'Found', 'Reply TLD(s)',	FALSE, ''),
			'replysrcip'	=> array('Top Reply SRC IP',			'Found', 'SRC IP(s)',		FALSE, ''),
			'replydstip'	=> array('Top Reply DST IP',			'Found', 'IP(s)',		FALSE, 'host'),
			'replysrcipd'	=> array('Top Reply SRC IP/Domain',		'Found', 'Domain/IP(s)',	FALSE, 'domain'),
			'replytype'	=> array('Top Reply Type',			'Found', 'Reply Type(s)',	FALSE, ''),
			'replyorec'	=> array('Top Reply Orig Record',		'Found', 'Reply Record(s)',	FALSE, ''),
			'replyrec'	=> array('Top Reply Record',			'Found', 'Reply Record(s)',	FALSE, ''),
			'replyttl'	=> array('Top Reply TTL',			'Found', 'Reply TTL(s)',	FALSE, ''),
			'replygeoip'	=> array('Top Reply GeoIP',			'Found', 'Reply GeoIP(s)',	FALSE, ''),
			'replydate'	=> array('Top Date',				'Found', 'day(s) of logs',	FALSE, ''));
}
else {
	$stats = array(	'ipchart'	=> array("IP Event Timeline&emsp;<small>(Last <span id=\"range\">{$pfbchartcnt}</span> hours)</small>",'','', FALSE, ''),
			'ipsrcipin'	=> array("Top SRC IP Inbound (by GeoIP)",	'Found', 'SRC IP(s)',		TRUE, 'host'),
			'ipsrcipout'	=> array("Top SRC IP Outbound (by GeoIP)",	'Found', 'SRC IP(s)',		TRUE, 'host'),
			'ipdstipin'	=> array("Top DST IP Inbound (by GeoIP)",	'Found', 'DST IP(s)',		TRUE, 'host'),
			'ipdstipout'	=> array("Top DST IP Outbound (by GeoIP)",	'Found', 'DST IP(s)',		TRUE, 'host'),
			'ipsrcport'	=> array("Top SRC Port (1-1024 only)",		'Found', 'SRC Port(s)',		FALSE, ''),
			'ipdstport'	=> array("Top DST Port",			'Found', 'DST Port(s)',		FALSE, ''),
			'ipgeoip'	=> array("Top GeoIP",				'Found', 'GeoIP(s)',		FALSE, ''),
			'ipasn'		=> array("Top ASN",				'Found', 'ASN(s)',		FALSE, ''),
			'ipaliasname'	=> array("Top Aliasname",			'Found', 'Aliasname(s)',	FALSE, ''),
			'ipfeed'	=> array("Top Feed",				'Found', 'Feed{s)',		FALSE, ''),
			'ipinterface'	=> array("Top Interface",			'Found', 'Interface(s)',	FALSE, ''),
			'ipprotocol'	=> array("Top Protocol",			'Found', 'Protocol(s)',		FALSE, ''),
			'ipdirection'	=> array("Top Direction",			'Found', 'Direction(s)',	FALSE, ''),
			'ipdate'	=> array("Top Date",				'Found', 'day(s) of logs',	FALSE, ''));
}

foreach ($stats as $stat_type => $stype):

	if ($stat_type == 'ipasn' && $pfb['asn_reporting'] == 'disabled') {
		continue;
	}


	$topcount = $sumlines = 0;
	if (!empty($alert_stats[$alert_view][$stat_type])) {
		$topcount = count($alert_stats[$alert_view][$stat_type]);
		$sumlines = array_sum($alert_stats[$alert_view][$stat_type]);
	}

	if (!is_numeric($topcount)) {
		$topcount = 0;
	}
	if (!is_numeric($sumlines)) {
		$sumlines = 0;
	}

	$height = 30;
	if ($topcount > 0) {
		$height = 390;
	}

	$collapse_status = 'in';
	if (isset($stat_hidden[$stat_type])) {
		$collapse_status = 'out';
		continue;
	}
?>

<div class="panel panel-default" id="Alert_Stats_<?=$stat_type?>" style="display: inline-block; width: 100%;">
	<div class="panel-heading">
		<h2 class="panel-title">
			<? if ($alertrefresh === PfbToggle::On): ?>
			<i class="fa-solid fa-pause-circle" id="PauseRefresh" " title="Pause Alerts Refresh"></i>&nbsp;
			<? endif; ?>

			<?=$stype[0]?>
			<span class="widget-heading-icon pull-right">
				<a data-toggle="collapse" href="#Alert_Stats_<?=$stat_type?>_panel-body" id="Alert_Stats_A_<?=$stat_type?>">
					<i class="fa-solid fa-plus-circle"></i>
				</a>
			</span>
		</h2>
		</div>

		<div class="panel-body collapse <?=$collapse_status?>" id="Alert_Stats_<?=$stat_type?>_panel-body" style="overflow-x: auto;">

			<?php if ($stat_type == 'dnsblchart' || $stat_type == 'replychart' || $stat_type == 'ipchart'): ?>

			<div id="chart" class="d3-chart" style="overflow: hidden;">

				<!-- Date range dropdown menu -->
				<div class="btn-group navbar-right" style="margin-right: 10px;">
					<ul class="navbar-nav">
						<a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button" aria-expanded="true">
							Date Range <span class="caret"></span>
						</a>
						<ul class="dropdown-menu" role="menu" style="padding: 1px 1px 1px 1px; font-size: smaller;">
							<?php foreach ($options_pfbchartcnt as $event => $type):?>
							<li id="chartEvent" value="<?=$event?>">
								<a href="#" class="navlnk"><?=$type?></a>
							</li>
							<?php endforeach;?>
						</ul>
					</ul>
				</div>

				<!-- Chart SVG -->
				<svg></svg>
			</div>
			<?php d3_chart($pfbchartcnt, $pfbchartstyle, $pfbchart1, $pfbchart2); ?>

			<?php else: ?>

			<div class="pfb-stats-row">
			<div class="pfb-stats-col" style="height: <?=$height;?>px; overflow-y: scroll;">
			<table class="table table-responsive table-bordered table-striped table-hover table-compact sortable-theme-bootstrap" data-sortable>

				<thead>
					<tr>
						<th style="width: 10%;"><!--  Action buttons --></th>
						<th style="width: 10%; text-align: center;"><?=gettext("Count")?></th>

						<?php if ($stype[3]): ?>
						<th style="width: 2%; text-align: center;">
							<?php
							$column_title = 'GeoIP';
							if ($stat_type == 'dnsbldomain' || $stat_type == 'dnsblevald') {
								$column_title = 'Type';
							} elseif ($stat_type == 'replysrcipd') {
								$column_title = 'SRC IP';
							}
							?>
							<?=gettext($column_title);?></th>
						<?php endif; ?>

						<th><small><?=$stype[1] . "&emsp;[ {$topcount} ]&emsp;" . $stype[2]?></th>
					</tr>
				</thead>
				<tbody>
					<?php
					// issue #1495: default FALSE -- when the first non-chart stat category
					// has no data (routine on a fresh install), the block below never runs,
					// and $max_table_entries must still be defined for the tfoot check.
					$max_table_entries = FALSE;
					if (!empty($alert_stats[$alert_view][$stat_type])) {

						$table_entries = 0;
						foreach ($alert_stats[$alert_view][$stat_type] as $data => $data_count) {

							if ($pfbmaxtable != 'max') {
								if ($table_entries > $pfbmaxtable) {
									$max_table_entries = TRUE;
									break;
								}
								$table_entries++;
							}

							$alert_event = $btnsubmit = $query_port = $hostname = '';
							$subdata = array();
							// issue #1069: NULL until a trusted-literal branch below opts the
							// final <td> out of escaping; otherwise it defaults to pfb_hsc($data).
							$data_disp = NULL;

							$filter_value = $data;
							if ($stat_type == 'dnsbltld' || $stat_type == 'replytld' ||
							    $stat_type == 'replytld2'|| $stat_type == 'replytld3' ) {
								$filter_value = "\.{$data}$";
							}
							elseif ($stat_type == 'ipsrcport' || $stat_type == 'ipdstport' ||
								$stat_type == 'replyorec' || $stat_type == 'replyrec') {
								$filter_value = "^{$data}$";
							}
							elseif ($stat_type == 'replyttl') {
								if (strlen($data) > 8) {
									$filter_value = "^15\d{6,10}";
								} else {
									$filter_value = "^{$data}$";
								}
							}
							elseif ($stat_type == 'ipasn') {
								if ($data == 'null') {
									continue;
								} elseif ($data != 'Unknown' && !ctype_digit($data)) { 
									if (strpos($data, '| ') !== FALSE) {
										$ex		= explode('| ', $data, 3);
										$filter_value	= $ex[1];
										$data		= "{$ex[1]} | {$ex[2]}";
									} else {
										$ex		= explode(' ', $data, 2);
										$filter_value	= $ex[0];
										$data		= "{$ex[0]} | {$ex[1]}";
									}
								}
							}
							elseif ($stat_type == 'dnsbldomain') {
								$ex = explode(',', $data, 2);
								$filter_value = $ex[0];
							}
							elseif ($stat_type == 'dnsblevald') {
								$ex = explode(',', $data, 2);
								$filter_value = $ex[1];
							}

							if ($stat_type != 'ipdirection') {
								// issue #1069: filter_value/data are log-derived -- HTML-encode
								// both attribute values.
								$btnsubmit = '<button type="submit" class="fa-solid fa-filter button-icon"'
										. " name=\"filterlogentries_submit_{$stat_type}\""
										. " id=\"filterlogentries_submit_{$stat_type}\""
										. " value=\"" . pfb_hsc($filter_value) . "\" title=\"Filter Alerts for [ "
										. pfb_hsc($data) . " ]\"></button>";
							}

							// Collect GeoIP or DNSBL Type classification
							if ($stype[3]) {
								$subdata = explode(',', $data);
								if ($stat_type == 'dnsblevald') {
									$data		= $subdata[1];
									$subdata[1]	= $subdata[0];
								}
								else {
									$data = $subdata[0];
								}

								// issue #1069: $data rides a URL query segment -- rawurlencode,
								// not HTML-encode.
								$alert_event = '<a class="fa-solid fa-info icon-pointer"'
										. ' title="Click for Threat Lookup." target="_blank" rel="noopener noreferrer"'
										. ' href="/pfblockerng/pfblockerng_threats.php?' . $stype[4] . '=' . rawurlencode($data) . '"></a>';
							}

							if ($stat_type == 'dnsbldatehr' || $stat_type == 'dnsbldatehrmin') {
								// ISO bucket key is 2 space-tokens (date, hour[:min]), not the
								// old 3-token "Mon D HH" shape -- label as "date (hour[:min])".
								// issue #1057: a truncated/corrupt key has no 2nd token.
								$d = explode (' ', $data);
								$data = isset($d[1]) ? "{$d[0]}&emsp;({$d[1]})" : $d[0];
								$data_disp = $data;	// program-generated date/hour token, trusted
							}

							if (!empty($data) && $data != 'Not available for HTTPS alerts') {

								// Report Local hostname if found
								if ($stat_type == 'ipsrcipout' || $stat_type == 'ipdstipin') {
									if (isset($local_hosts[$data])) {
										$hostname = "&emsp;<small>( " . pfb_hsc($local_hosts[$data]) . " )</small>";
									}
								}

								// Get external IP hostname and Resolved hostname
								elseif ($stat_type == 'ipsrcipin' || $stat_type == 'ipdstipout') {
									$hostname = pfb_stat_hostname_cell($subdata[2]);
								}
							}

							if ($stat_type == 'dnsblagent' && $data == 'Unknown') {
								$data = 'DNSBL Webserver/VIP';
								$data_disp = $data;	// literal, trusted
							}

							if ($stat_type == 'ipdstport') {
								// issue #1069: href segment rawurlencode'd; title HTML-encoded.
								$query_port = '&nbsp;<a class="fa-solid fa-search icon-pointer" target="_blank" rel="noopener noreferrer"'
										. ' href="/pfblockerng/pfblockerng_threats.php?port=' . rawurlencode($data)
										. '" title="Click for Threat Port Lookup [ ' . pfb_hsc($data) . ' ]"></a>';
							}

							elseif ($stat_type == 'ipdirection') {
								if ($data == 'in') {
									$data = 'Inbound packets';
								} else {
									$data = 'Outbound packets';
								}
								$data_disp = $data;	// literal, trusted
							}

							if (empty($data)) {
								$data = 'Unknown';
								$data_disp = $data;	// literal, trusted
							}

							$td_type = '';
							if ($stype[3]) {
								$td_type = "<td style=\"text-align: center;\">" . pfb_hsc($subdata[1]) . "</td>";
							}

							// issue #1069: everything NOT opted into a trusted literal above is
							// attacker-influenceable log/feed data -- HTML-encode it here.
							if ($data_disp === NULL) {
								$data_disp = pfb_hsc($data);
							}

							print ("<tr>
								<td style=\"text-align: center; white-space: nowrap;\">{$alert_event}{$query_port}{$btnsubmit}</td>
								<td style=\"text-align: right; padding-right: 15px;\">{$data_count}</td>
								{$td_type}
								<td style=\"white-space: nowrap;\">{$data_disp}{$hostname}</td></tr>");
						}
					}
					?>
				</tbody>
			</table>
			</div>

			<div class="pfb-stats-col" style="height: <?=$height;?>px;">
				<div id="pieChart_<?=$stat_type?>">
				<?php
					if ($topcount > 9) {
						$alert_stats[$alert_view][$stat_type] = array_slice($alert_stats[$alert_view][$stat_type], 0, 10, TRUE);
					}

					if (!empty($alert_stats[$alert_view][$stat_type])) {
						pie_block($alert_stats[$alert_view][$stat_type], $stat_type, $topcount, 10, $segcolors);
					}
				?>
				</div>
			</div>
			</div><!-- /.pfb-stats-row -->

			<!-- Display max table extry limit, if found -->
			<?php if ($max_table_entries): ?>
			<div>
				&emsp;
				<span class="text-warning" style="font-size:12px; background-color: #424242;"
					title="Table limit reached! Setting can be modified in widget Alert Settings, but may slow page refresh time.">
					<small>Displaying [ <?= $pfbmaxtable; ?> ] entries.</small>
				</span>
			</div>
			<?php endif; ?>

			<?php endif; ?>

		</div>
	</div>
	<?php endforeach; ?>
	</div>
</div>
</form>
	<?php endif;
endif;

// Refresh page every 60 secs
if ($alertrefresh === PfbToggle::On) {

	$pageview = '?';
	if ($pfb['filterlogentries']) {
		$pageview = '&';
	}

	if (!empty($alert_view) && $alert_view != 'alert') {
		$pageview .= "view={$alert_view}";
	} else {
		$pageview = '';
	}

        // Validate pfSense URL
	$pfSense_url = '';
	if ($_SERVER['REQUEST_SCHEME'] == 'http' || $_SERVER['REQUEST_SCHEME'] == 'https') {
		$HTTP_HOST = '';
		if (strpos($_SERVER['HTTP_HOST'], ':') !== FALSE) {
			$parts = explode(':', $_SERVER['HTTP_HOST']);
			if (count($parts) == 2 && !empty(pfb_filter($parts[0], PFB_FILTER_DOMAIN, 'alerts refresh')) && is_port($parts[1])) {
				$HTTP_HOST = pfb_filter($_SERVER['HTTP_HOST'], PFB_FILTER_HTML, 'alerts refresh'); 
			}
		}
		else {
			$HTTP_HOST = pfb_filter($_SERVER['HTTP_HOST'], PFB_FILTER_DOMAIN, 'alerts refresh');
		}
		if (!empty($HTTP_HOST)) {
			$pfSense_url = "{$_SERVER['REQUEST_SCHEME']}://{$HTTP_HOST}";

			if (!pfb_filter("{$pfSense_url}/", PFB_FILTER_URL, 'alerts refresh', '', TRUE)) {
				$pfSense_url = '';
			}
		}
	}

	// Refresh page with 'Filter options', if defined
	if (!empty($pfSense_url)) {
		if ($pfb['filterlogentries']) {
			$refreshentries = urlencode(json_encode($filterfieldsarray));
			print ("<meta id=\"AlertRefresh\" http-equiv=\"refresh\" content=\"60;url={$pfSense_url}/pfblockerng/pfblockerng_alerts.php?refresh={$refreshentries}{$pageview}\" />\n");
		}

		// Refresh page
		else {
			print ("<meta id=\"AlertRefresh\" http-equiv=\"refresh\" content=\"60;url={$pfSense_url}/pfblockerng/pfblockerng_alerts.php{$pageview}\" />\n");
		}
	}
}

function pie_block($summary, $stat_type, $sumlines, $numsegments, $segcolors) {

?>
<script type="text/javascript">
//<![CDATA[

var pieChart_<?=$stat_type?> = new d3pie("pieChart_<?=$stat_type?>", {
	"size": {
		"canvasHeight": 390,
		"canvasWidth": 560,
		"pieInnerRadius": 60,
		"pieOuterRadius": "78%"
	},
	"data": {
		"sortOrder": "value-asc",
		"content": [
<?php
	uasort($summary, fn($a, $b) => $b <=> $a);
	$k = array_keys($summary);
	$numentries = 0;
	for ($i = 0; $i < ($numsegments-1); $i++) {
		if ($k[$i] ?? NULL) {
			$numentries++;
			if ($i > 0) {
				print(",\r\n");
			}

			// Don't add 0 values
			if ($summary[$k[$i]] == 0) {
				$summary[$k[$i]] = 0.1;
			}

			print("{");
			// issue #1069: log/feed-derived label into an inline <script>. pfb_js_string()
			// JSON-encodes with JSON_HEX_* (quote/tag breakout) + JSON_INVALID_UTF8_SUBSTITUTE
			// and a FALSE fallback, so a non-UTF8 byte can't emit invalid JS.
			print('"label": ' . pfb_js_string((string) $k[$i]) . ', "value": ');
			print((float) $summary[$k[$i]]);
			print(', "color": "' . $segcolors[$i % $numsegments] . '"');
			print("}");
		}
	}

	$balance = $sumlines - $numentries;
	if ($balance > 0) {
		print(",\r\n");
		print("{");
		print('"label": "Other", "value": ');
		print($balance);
		print(', "color": "' . $segcolors[$i % $numsegments] . '"');
		print("}");
	}
?>
		]
	},
	"labels": {
		"outer": {
			"pieDistance": 25
		},
		"inner": {
			"format": "percentage",
			"hideWhenLessThanPercentage": 3
		},
		"mainLabel": {
			"font": "verdana",
			"fontSize": 14
		},
		"percentage": {
			"color": "#ffffff",
			"font": "verdana",
			"fontSize": 10,
			"decimalPlaces": 0
		},
		"value": {
			"color": "#adadad",
			"font": "verdana",
			"fontSize": 15
		},
		"lines": {
			"enabled": true,
			"style": "curved",
			"color": "segment"
		},
		"truncation": {
			"enabled": true,
			truncateLength: 15
		}
	},
	"effects": {
		"load": {
			"speed": 300
		},
		"pullOutSegmentOnClick": {
			"effect": "linear",
			"speed": 400,
			"size": 20
		},
		highlightSegmentOnMouseover: true,
		highlightLuminosity: -0.7
	},
	tooltips: {
		enabled: true,
		type: "placeholder",
		string: "{label}: {percentage}% ({value})",
		placeholderParser: null,
		styles: {
			fadeInSpeed: 250,
			backgroundColor: "#000000",
			backgroundOpacity: 0.5,
			color: "#f7f7f7",
			borderRadius: 2,
			font: "verdana",
			fontSize: 14,
			padding: 4
		}
	},
	"misc": {
		"gradient": {
			"enabled": true,
			"percentage": 50
		},
		"pieCenterOffset": {
			"x": 0,
			"y": 0
		},
		colors: {
			background: null,
			segmentStroke: "#ffffff"
		}
	}
});
pfbPieFluid("pieChart_<?=$stat_type?>");
//]]>
</script>
<?php
}

function d3_chart($pfbchartcnt, $pfbchartstyle, $pfbchart1, $pfbchart2) {

?>
<script type="text/javascript">
//<![CDATA[

var max_entries = "<?=$pfbchartcnt;?>"
var chart_style = "<?=$pfbchartstyle;?>"
var chart_c1	= "<?=$pfbchart1;?>"
var chart_c2	= "<?=$pfbchart2;?>"

build_chart(max_entries);

function build_chart(max_entries) {

	d3.select('#range').text(max_entries);
	d3.select("#svg").remove();
	d3.select('#chart').append('svg').attr('id', 'svg');

	var chart = new d3.csv('chart_stats.csv', function(error, data) {
		series1 = []
		data = data.slice(-max_entries);

		// Add filler bars if under 24 bars 
		var cnt = data.length
		if (cnt != 0 && cnt < 24) {
			for (i = (24 - cnt); i > 0; i--) {
				var filler = { edate: "Placeholder " +i, ecount: "0", series: "0" }
				data.push(filler)
			}
		}

		data.forEach(function (d){
			d.ecount = +d.ecount
			series1.push(d)
		})

		var finalData = [{
				key: "Series 1",
				values: series1,
				color: "#0000ff"
				}];

		nv.addGraph(function() {
			var chart = nv.models.discreteBarChart()
				.margin({top: 5, left: 65, right: 25, bottom: 60})
				.x(function (d) { return d.edate })
				.y(function (d) { return d.ecount })
				.showYAxis(true)
				.showXAxis(true);

			chart.xAxis
				.tickPadding(10)
				.axisLabel('Date (Hr) [ Found: ' + cnt + ' hours ]');

			chart.yAxis
				.tickFormat(d3.format('.0f'))
				.tickPadding(10)
				.axisLabel('Event(s)');

			//  Pantone Color Institute "Color of the Year"
			if (chart_style == 'multi') {
				var colors = [	"#9BB7D4", "#C74375", "#BF1932", "#7BC4C4", "#E2583E", "#53B0AE",
						"#DECDBE", "#9B1B30", "#5A5B9F", "#F0C05A", "#45B5AA", "#D94F70",
						"#DD4124", "#009473", "#B163A3", "#955251", "#F7CAC9", "#92A8D1",
						"#88B04B", "#5F4B8B", "#FF6F61", "#2484C1", "#65A620", "#7B6888" ];
			}

			// Greyscale
			else {
				var colors = [	"#E0E0E0", "#DCDCDC", "#D8D8D8", "#D3D3D3", "#D0D0D0", "#C8C8C8",
						"#C0C0C0", "#BEBEBE", "#B8B8B8", "#B0B0B0", "#A9A9A9", "#A8A8A8",
						"#A0A0A0", "#989898", "#909090", "#888888", "#808080", "#787878",
						"#707070", "#696969", "#686868", "#606060", "#585858", "#505050" ];
			}

			chart.color(function(d) {
				if (chart_style == 'greyscale' || chart_style == 'multi') {
					return colors[Number(d.edate.slice(-3,-1)).toString()];
				}
				else {
					if (d.edate.slice(-3,-1) == '00') {
						return chart_c1;
					} else {
						return chart_c2;
					}
				}
			});

			d3.select('#chart svg')
				.datum(finalData)
				.transition().duration(300)
				.call(chart);

			// Hide xAxis Labels
			xCnt = Math.max(3, Math.round((series1.length * 0.17) / 10) * 10)
			d3.selectAll(".tick text").attr("class", function(d,i) {
				if (isNaN(d) && i % xCnt != 0) {
					d3.select(this).style("opacity", 0);
				} else {
					d3.select(this).style("opacity", 1);
				}
			});

			nv.utils.windowResize(function() { chart.update() });
			return chart;
		});
	})
}
//]]>
</script>
<?php } ?>

<?php include('foot.inc');?>
<script type="text/javascript">
//<![CDATA[

function dnsbl_whitelist() {

	if (domain && table) {
		$('#addwhitelistdom').val('true');
		$('form').submit();
	}
}

function ip_whitelist() {

	if (ip && table) {
		$('#ip_white').val('true');
		$('form').submit();
	}
}

function dnsbl_customlist() {

	if (domain && dnsbl_customlist) {
		$('#dnsbl_add').val('true');
		$('form').submit();
	}
}

function ip_suppression() {

	var description = prompt('Please enter Suppression description');
	$('#descr').val(description);

	if (ip && table) {
		$('#addsuppress').val('true');
		$('form').submit();
	}
}

// ADR-53: the "+" now carves the reported host out of WHICHEVER table
// entry currently contains it, at any mask -- the /32-vs-/24 mask-choice
// dialog this function used to show is no longer meaningful (the backend
// never reads a chosen mask, see pfblockerng_alerts.php's addsuppress
// handler), so it goes straight to ip_suppression() once suppression is
// confirmed enabled.
function ip_suppression_type() {

	// Confirm if the Suppression option is enabled
	// issue #1887: the mirror is a PfbToggle — render its token explicitly (echoing
	// the enum raw is a page-killing fatal: not convertible to string).
	var is_supp = "<?=($pfb['supp'] === PfbToggle::On ? 'on' : 'off')?>";
	if (is_supp != 'on') {
		alert('The IP Suppression option has not been enabled. Please enable this option in the IP Tab to suppress this IP.');
		return;
	}

	ip_suppression();
}

function add_description(mode) {

	if (mode == 'dnsbl') {
		title_text = 'Whitelist';
	} else {
		title_text = 'Block';
	}

	$('<div></Div>').appendTo('body')
	.html('<div><h6>Do you want to add a description?</h6></div>')
	.dialog({
		modal: true,
		autoOpen: true,
		resizable: false,
		closeOnEscape: true,
		width: 'auto',
		title: title_text + ' description:',
		position: { my: 'top', at: 'top' },
		buttons: {
			Yes: function () {
				var description = prompt('Please enter ' + title_text + ' description');
				$('#descr').val(description);
				$(this).dialog('close');
				if (mode == 'dnsbl') {
					dnsbl_whitelist();
				} else if (mode == 'ip') {
					ip_whitelist();
				} else {
					dnsbl_customlist();
				}
			},
			No: function () {
				$(this).dialog('close');
				if (mode == 'dnsbl') {
					dnsbl_whitelist();
				} else if (mode == 'ip') {
					ip_whitelist();
				} else {
					dnsbl_customlist();
				}
			},
			'Cancel': function (event, ui) {
				$(this).dialog('close');
			}
		}
	}).css('background-color','#ffd700');
	$("div[role=dialog]").find('button').addClass('btn-info btn-xs');
}


function select_whitelist(mode, permit_list) {

	var buttons = {};
	$.each(permit_list, function(index, val) {
		buttons[index + ') ' + val] = function() {
								// Rename 'Create new IP Whitelist'
								if (val.indexOf("Create new") >= 0) {
									val = val.replace('Create new ', 'NEW_');
								}
								if (mode == 'ip') {
									$('#table').val(val);
								} else {
									$('#dnsbl_customlist').val(val);
								}
								$(this).dialog('close');
								add_description(mode);
							};
	});
	buttons['Cancel'] = function() { $(this).dialog('close'); };

	if (mode == 'ip') {
		s_title = 'Whitelist';
		d_title = 'Select a Permit Whitelist Alias:';
	} else {
		s_title = 'DNSBL Customlist';
		d_title = 'Select a DNSBL Customlist Group:';
	}

	$('<div></div>').appendTo('body')
	.html('<div><h6>Select ' + s_title + ':</h6></div>')
	.dialog({
		modal: true,
		autoOpen: true,
		resizable: false,
		closeOnEscape: true,
		width: 'auto',
		title: d_title,
		position: { my: 'top', at: 'top' },
		width: 750,
		buttons: buttons
	}).css('background-color','#ffd700');
	$("div[role=dialog]").find('button').addClass('btn-info btn-xs');
}

// Change filterfield input fields to lightgrey
function pfb_chg_filerfields_bkgd() {
	$("[id^='filterlogentries_']").each(function() {

		if ($(this).attr("id").indexOf("submit") == -1 && $(this).val() != 'Apply Filter' && $(this).val() != 'Clear Filter') {
			if ($(this).val() != '') {
				$(this).css({"background-color": "#1976D2", "color": "white"});
			} else {
				$(this).css({"background-color": "", "color": "black"});
			}
		}
	});
}

events.push(function() {

	pfb_chg_filerfields_bkgd();
	$("[id^='filterlogentries_']").autocomplete({
		change: function(event,ui) {
			pfb_chg_filerfields_bkgd();
		}
	});

	// Rebuild D3 Chart on date range change
	$('[id=chartEvent]').click(function() {
		if (($.isNumeric($(this).attr('value'))) && $(this).attr('value') > 0 && $(this).attr('value') < 8065) {
			build_chart($(this).attr('value'));
		}
	})

	// Pause Alert tab auto-refresh 
	$('[id=PauseRefresh]').click(function() {
		var metaId = $('meta[id=AlertRefresh]');
		var pr = $('[id=PauseRefresh]');

		if (metaId.attr('http-equiv') == 'refresh') {
			metaId.removeAttr('http-equiv');
			pr.removeClass('fa-solid fa-pause-circle').addClass('fa-solid fa-undo').attr('title', 'Resume Alerts Refresh');
			window.stop();
		} else {
			metaId.attr('http-equiv', 'refresh');
			pr.removeClass('fa-solid fa-undo').addClass('fa-solid fa-pause-circle').attr('title', 'Pause Alerts Refresh');
		}
	})

	// Redraw d3pie chart when table window was previously collapsed
	$('[id^=Alert_Stats_A_]').click(function() {

		// collect name of piechart to redraw
		var pieChart = this.id.replace('Alert_Stats_A_', '');

		if (pieChart == 'ipsrcipin') {
			pieChart_ipsrcipin.redraw();
		} else if (pieChart == 'ipsrcipout') {
			pieChart_ipsrcipout.redraw();
		} else if (pieChart == 'ipdstipin') {
			pieChart_ipdstipin.redraw();
		} else if (pieChart == 'ipdstipout') {
			pieChart_ipdstipout.redraw();
		} else if (pieChart == 'ipsrcport') {
			pieChart_ipsrcport.redraw();
		} else if (pieChart == 'ipdstport') {
			pieChart_ipdstport.redraw();
		} else if (pieChart == 'ipgeoip') {
			pieChart_ipgeoip.redraw();
		} else if (pieChart == 'ipasn') {
			pieChart_ipasn.redraw();
		} else if (pieChart == 'ipaliasname') {
			pieChart_ipaliasname.redraw();
		} else if (pieChart == 'ipfeed') {
			pieChart_ipfeed.redraw();
		} else if (pieChart == 'ipinterface') {
			pieChart_ipinterface.redraw();
		} else if (pieChart == 'ipprotocol') {
			pieChart_ipprotocol.redraw();
		} else if (pieChart == 'ipdirection') {
			pieChart_ipdirection.redraw();
		} else if (pieChart == 'ipdate') {
			pieChart_ipdate.redraw();

		} else if (pieChart == 'dnsbldomain') {
			pieChart_dnsbldomain.redraw();
		} else if (pieChart == 'dnsblevald') {
			pieChart_dnsblevald.redraw();
		} else if (pieChart == 'dnsblgptotal') {
			pieChart_dnsblgptotal.redraw();
		} else if (pieChart == 'dnsblgpblock') {
			pieChart_dnsblgblock.redraw();
		} else if (pieChart == 'dnsblfeed') {
			pieChart_dnsblfeed.redraw();
		} else if (pieChart == 'dnsblip') {
			pieChart_dnsblip.redraw();
		} else if (pieChart == 'dnsblagent') {
			pieChart_dnsblagent.redraw();
		} else if (pieChart == 'dnsbltld') {
			pieChart_dnsbltld.redraw();
		} else if (pieChart == 'dnsblwebtype') {
			pieChart_dnsblwebtype.redraw();
		} else if (pieChart == 'dnsblmode') {
			pieChart_dnsblmode.redraw();
		} else if (pieChart == 'dnsbldatehr') {
			pieChart_dnsbldatehr.redraw();
		} else if (pieChart == 'dnsbldatehrmin') {
			pieChart_dnsbldatehrmin.redraw();

		} else if (pieChart == 'replyorec') {
			pieChart_replyorec.redraw();
		} else if (pieChart == 'replyrec') {
			pieChart_replyrec.redraw();
		} else if (pieChart == 'replyttl') {
			pieChart_replyttl.redraw();
		} else if (pieChart == 'replydomain') {
			pieChart_replydomain.redraw();
		} else if (pieChart == 'replytld') {
			pieChart_replytld.redraw();
		} else if (pieChart == 'replytld2') {
			pieChart_replytld2.redraw();
		} else if (pieChart == 'replytld3') {
			pieChart_replytld3.redraw();
		} else if (pieChart == 'replysrcip') {
			pieChart_replysrcip.redraw();
		} else if (pieChart == 'replysrcipd') {
			pieChart_replysrcipd.redraw();
		} else if (pieChart == 'replydstip') {
			pieChart_replydstip.redraw();
		} else if (pieChart == 'replygeoip') {
			pieChart_replygeoip.redraw();
		} else if (pieChart == 'replydate') {
			pieChart_replydate.redraw();
		}
		pfbPieFluid('pieChart_' + pieChart);
	})

	$('[id^=DNSBLWT]').click(function(event) {
		if (confirm(event.target.title)) {
			$('meta[http-equiv=refresh]').remove();
			var arr = this.id.split('|');

			var DNSBLWT_Type = arr[1];	// add/delete/exclude/TLD
			$('#domain').val(arr[2]);	// Domain or IP
			if (typeof arr[2] === 'undefined') {
				return;
			}
			var blocktype = '';		// Types (DNSBL/TLD/DNSBL TLD)

			switch (DNSBLWT_Type) {
				case 'add':
					$('#table').val(arr[3]);	// Feed Name
					var blocktype = arr[4];
					button_text = 'Whitelist';
					descr_type = 'dnsbl';
					break;
				case 'delete_domain':
				case 'delete_domainwildcard':
				case 'delete_exclusion':
				case 'delete_ip':
				case 'delete_ipwhitelist':
					if (DNSBLWT_Type == 'delete_ipwhitelist' || DNSBLWT_Type == 'delete_ip') {
						$('#table').val(arr[3]);
					}
					$('#entry_delete').val(DNSBLWT_Type);
					$('form').submit();
					return;
				case 'tld':
					$('#table').val(arr[3]);
					var blocktype = arr[4];
					descr_type = 'dnsbl';
					break;
				case 'dnsbl_add':
					button_text = 'Block';
					blocktype = 'dnsbl';
					descr_type = 'dns_reply';
					var dnsbl_customlist = arr.splice(3)
					break;
				default:
					return;
			}

			var buttons = {};
			buttons['1. Wildcard ' + button_text] = function() {
					$('#dnsbl_wildcard').val('true');
					$(this).dialog('close');

					if (DNSBLWT_Type == 'dnsbl_add') {
						select_whitelist('dns_reply', dnsbl_customlist);
					} else {
						add_description(descr_type);
					}
				};

			if (blocktype != 'TLD') {
				msg = 'Do you wish to Wildcard ' + button_text + ' [ .' + arr[2] + ' ] or only ' + button_text + ' [ ' + arr[2] + ' ]?';
				buttons['2. ' + button_text] = function() {
							$(this).dialog('close');
							if (DNSBLWT_Type == 'dnsbl_add') {
								select_whitelist('dns_reply', dnsbl_customlist);
							} else {
								add_description(descr_type);
							}
						};
			}
			else {
				msg = 'Do you wish to Wildcard Whitelist [ .' + arr[2] + ' ] or add it to the TLD Exclusion customlist?';
				buttons['2. Exclude'] = function() {
							$('#dnsbl_exclude').val('true');
							$(this).dialog('close');
							add_description(descr_type);
						};
			}
			buttons['Cancel'] = function() { $(this).dialog('close'); };

			$('<div></div>').appendTo('body')
			.html('<div><h6>' + msg + '</h6></div>')
			.dialog({
				modal: true,
				autoOpen: true,
				resizable: false,
				closeOnEscape: true,
				width: 'auto',
				title: 'Domain ' + button_text + 'ing:',
				position: { my: 'top', at: 'top' },
				buttons: buttons
			}).css('background-color','#ffd700');
			$("div[role=dialog]").find('button').addClass('btn-info btn-xs');
		}
	});

	$('[id^=PFBIPSUP]').click(function(event) {
		if (confirm(event.target.title)) {
			$('meta[http-equiv=refresh]').remove();
			var arr = this.id.split('|');
			$('#ip').val(arr[2]);
			$('#table').val(arr[3]);

			var permit_list = arr.splice(4);
			if (permit_list) {

				$('<div></Div>').appendTo('body')
				.html('<div><h6>Do you want to Suppress or Add to a Permit Whitelist Alias?</h6></div>')
				.dialog({
					modal: true,
					autoOpen: true,
					resizable: false,
					closeOnEscape: true,
					width: 'auto',
					title: 'Whitelist Description:',
					position: { my: 'top', at: 'top' },
					buttons: {
						'1) Suppress': function () {
								$(this).dialog('close');
								ip_suppression_type();
						},
						'2) Whitelist': function () {
								$(this).dialog('close');
								select_whitelist('ip', permit_list);
						},
						'Cancel': function (event, ui) {
							$(this).dialog('close');
						}
					}
				}).css('background-color','#ffd700');
				$("div[role=dialog]").find('button').addClass('btn-info btn-xs');
			}
			else {
				ip_suppression_type();
			}
		}
	});

	$('[id^=PFBIPWHITE]').click(function(event) {
		if (confirm(event.target.title)) {
			$('meta[http-equiv=refresh]').remove();
			var arr = this.id.split('|');
			$('#ip').val(arr[1]);

			var permit_list = arr.splice(2);
			select_whitelist('ip', permit_list);
		}
	});

	$('[id^=DNSBL_ULCK]').click(function(event) {
		if (confirm(event.target.title)) {
			var arr = this.id.split('|');
			$('#domain').val(arr[1]);
			$('#dnsbl_type').val(arr[2]);

			$('#dnsbl_remove').val('unlock');
			$('form').submit();
		}
	});

	$('[id^=DNSBL_LCK]').click(function(event) {
		if (confirm(event.target.title)) {
			var arr = this.id.split('|');
			$('#domain').val(arr[1]);
			$('#dnsbl_type').val(arr[2]);

			$('#dnsbl_remove').val('lock');
			$('form').submit();
		}
	});

	$('[id^=DNSBL_RELCK]').click(function(event) {
		if (confirm(event.target.title)) {
			var arr = this.id.split('|');
			$('#domain').val(arr[1]);
			$('#dnsbl_type').val(arr[2]);

			$('#dnsbl_remove').val('relock');
			$('form').submit();
		}
	});

	$('[id^=DNSBL_REULCK]').click(function(event) {
		if (confirm(event.target.title)) {
			var arr = this.id.split('|');
			$('#domain').val(arr[1]);
			$('#dnsbl_type').val(arr[2]);

			$('#dnsbl_remove').val('reunlock');
			$('form').submit();
		}
	});

	$('[id^=IPULCK]').click(function(event) {
		if (confirm(event.target.title)) {
			var arr = this.id.split('|');
			$('#ip').val(arr[1]);
			$('#table').val(arr[2]);

			$('#ip_remove').val('unlock');
			$('form').submit();
		}
	});

	$('[id^=IPLCK]').click(function(event) {
		if (confirm(event.target.title)) {
			var arr = this.id.split('|');
			$('#ip').val(arr[1]);
			$('#table').val(arr[2]);

			$('#ip_remove').val('lock');
			$('form').submit();
		}
	});
});

//]]>
</script>

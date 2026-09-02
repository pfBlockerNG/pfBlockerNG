<?php
/*
 * pfblockerng_dnsbl.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2016-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2015-2024 BBcan177@gmail.com
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the \"License\");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an \"AS IS\" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

require_once('guiconfig.inc');
require_once('globals.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');

global $pfb;
pfb_global();

$pfb['dconfig'] = PfbConfig::readSection('installedpackages/pfblockerngdnsblsettings/config/0');

// issue #1669 slice C: General-settings toggle gating the CodeMirror 6 live-highlight
// overlay for the pfb_regex_list field below (registered in the general section,
// default on, LENIENT adapter -- mirrors pfb_keep; owned/rendered by
// pfblockerng_general.php). Read via the PfbConfig gateway -- matches this page's
// pfb_cache_flush precedent (PfbConfig::read() returns the enum directly here,
// compared with ===, not ->value).
$pfb_syntaxhl_on = pfb_editor_enabled();

$pfb_dnsbl_editor = pfb_dnsbl_editor_render($pfb_syntaxhl_on);

// Collect local domain TLD for Python TLD Allow array
// foreign key — out of ADR-29 gateway scope (system/domain is not a pfblockerng* path)
if (strpos(config_get_path('system/domain'), '.') !== FALSE) {
	$local_tld = ltrim(strstr(config_get_path('system/domain'), '.', FALSE), '.');
} else {
	$local_tld = config_get_path('system/domain');
}
$default_tlds = array('arpa',$local_tld,'com','net','org','edu','ca','co','io');

$pconfig = array();
$pconfig['pfb_dnsbl']		= PfbConfig::read('dnsbl/pfb_dnsbl');
$pconfig['tld_wildcard']		= PfbConfig::read('dnsbl/tld_wildcard');
$pconfig['pfb_control']		= PfbConfig::read('dnsbl/pfb_control');
$pconfig['pfb_control_legacy']	= PfbConfig::read('dnsbl/pfb_control_legacy');
// Widget empty-option sentinel 'none'; stored default is '' (save maps none to '').
$pconfig['pfb_dnsvip4'] = PfbConfig::read('dnsbl/pfb_dnsvip4') ?: 'none';
$pconfig['pfb_dnsvip6'] = PfbConfig::read('dnsbl/pfb_dnsvip6') ?: 'none';
$pconfig['pfb_dnsvip_auto']	= PfbConfig::read('dnsbl/pfb_dnsvip_auto');
$pconfig['pfb_dnsbl_nonat']	= PfbConfig::read('dnsbl/pfb_dnsbl_nonat');
$pconfig['pfb_dnsport']		= PfbConfig::read('dnsbl/pfb_dnsport');
$pconfig['pfb_dnsport_ssl']	= PfbConfig::read('dnsbl/pfb_dnsport_ssl');
$pconfig['dnsbl_interface']	= PfbConfig::read('dnsbl/dnsbl_interface');
$pconfig['pfb_dnsbl_rule']	= PfbConfig::read('dnsbl/pfb_dnsbl_rule');
$pconfig['dnsbl_allow_int']	= pfb_csv_list($pfb['dconfig']['dnsbl_allow_int'] ?? NULL);
$pconfig['global_log']		= PfbConfig::read('dnsbl/global_log');
$pconfig['dnsbl_webpage']	= $pfb['dconfig']['dnsbl_webpage']			?: 'dnsbl_default.php';
// Default 'on' owned by the registry (ADR-29, issue #1907); PfbConfig::read applies it
// when absent.
$pconfig['pfb_cache']		= PfbConfig::read('dnsbl/pfb_cache');
$pconfig['pfb_cache_flush']	= PfbConfig::read('dnsbl/pfb_cache_flush');

$pconfig['pfb_py_reply']	= PfbConfig::read('dnsbl/pfb_py_reply');
$pconfig['pfb_hsts']		= PfbConfig::read('dnsbl/pfb_hsts');
$pconfig['pfb_psl_include_private'] = PfbConfig::read('dnsbl/pfb_psl_include_private');
$pconfig['pfb_psl_allow_private'] = PfbConfig::read('dnsbl/pfb_psl_allow_private');
// issue #2371: feed-at-suffix policy selects (PfbFeedSuffixPolicy enum; absent -> Honor).
// ->value gives the runtime option key the <select> options below carry (same idiom as
// pfb_idn above).
$pconfig['pfb_psl_feed_private_policy'] = PfbConfig::read('dnsbl/pfb_psl_feed_private_policy')->value;
$pconfig['pfb_psl_feed_icann_policy'] = PfbConfig::read('dnsbl/pfb_psl_feed_icann_policy')->value;
// ADR-08: IDN mode selector (Off | All-IDN | Confusable). PfbConfig::read() returns a
// PfbIdnMode enum (legacy 'on' -> All; alpha-only 'all', legacy 'off', and '' -> Off);
// enum value gives the runtime option key that the <select> options below carry.
$pconfig['pfb_idn']		= PfbConfig::read('dnsbl/pfb_idn')->value;
// Confusable-mode sub-toggles: block clearly-malicious homoglyphs is default-on;
// escalate suspicious mixed-script (else alert only) is opt-in (default off).
// Default 'on' owned by the registry (ADR-29); PfbConfig::read applies it when absent.
$pconfig['pfb_idn_block_malicious']	= PfbConfig::read('dnsbl/pfb_idn_block_malicious');
$pconfig['pfb_idn_escalate_suspicious']	= PfbConfig::read('dnsbl/pfb_idn_escalate_suspicious');
$pconfig['pfb_regex']		= PfbConfig::read('dnsbl/pfb_regex');
$pconfig['pfb_regex_cap']	= PfbConfig::read('dnsbl/pfb_regex_cap');
$pconfig['pfb_cname']		= PfbConfig::read('dnsbl/pfb_cname');
// ADR-22: lenient scheme parsing. Absent = unchecked (strict) for new installs; existing
// installs are grandfathered to 'on' by the registry pass at install/upgrade (issue #1921).
$pconfig['pfb_dnsbl_lenient']	= PfbConfig::read('dnsbl/pfb_dnsbl_lenient');
$pconfig['pfb_noaaaa']		= PfbConfig::read('dnsbl/pfb_noaaaa');
$pconfig['pfb_gp']		= PfbConfig::read('dnsbl/pfb_gp');
$pconfig['tld_allow']		= PfbConfig::read('dnsbl/tld_allow');
$pconfig['tld_allow_sort']	= PfbConfig::read('dnsbl/tld_allow_sort');
$pconfig['tld_allow_gtld']	= pfb_csv_list($pfb['dconfig']['tld_allow_gtld'] ?? NULL, $default_tlds);
$pconfig['tld_allow_cctld']	= pfb_csv_list($pfb['dconfig']['tld_allow_cctld'] ?? NULL);
$pconfig['tld_allow_itld']	= pfb_csv_list($pfb['dconfig']['tld_allow_itld'] ?? NULL);
$pconfig['tld_allow_bgtld']	= pfb_csv_list($pfb['dconfig']['tld_allow_bgtld'] ?? NULL);
$pconfig['pfb_py_nolog']	= PfbConfig::read('dnsbl/pfb_py_nolog');
$pconfig['pfb_regex_list']	= pfb_b64_text($pfb['dconfig']['pfb_regex_list'] ?? NULL);
$pconfig['pfb_noaaaa_list']	= pfb_b64_text($pfb['dconfig']['pfb_noaaaa_list'] ?? NULL);
$pconfig['pfb_gp_bypass_list']	= pfb_b64_text($pfb['dconfig']['pfb_gp_bypass_list'] ?? NULL);
$pconfig['action']		= PfbConfig::read('dnsbl/action');
$pconfig['aliaslog']		= PfbConfig::read('dnsbl/aliaslog');

// issue #2123: the eight Advanced In/Outbound rule checkbox defaults are owned by the
// registry (ADR-29), not restated here. A validation-error redisplay replaces $pconfig
// with raw $_POST (:1019), so the renders still run the value through the toggle read
// adapter -- that call is the POST-redisplay adapter, not a second default.
$pconfig['autoaddrnot_in']	= PfbConfig::read('dnsbl/autoaddrnot_in');
$pconfig['autoports_in']	= PfbConfig::read('dnsbl/autoports_in');
$pconfig['aliasports_in']	= $pfb['dconfig']['aliasports_in']			?: '';
$pconfig['autoaddr_in']		= PfbConfig::read('dnsbl/autoaddr_in');
$pconfig['autonot_in']		= PfbConfig::read('dnsbl/autonot_in');
$pconfig['aliasaddr_in']	= $pfb['dconfig']['aliasaddr_in']			?: '';
$pconfig['autoproto_in']	= $pfb['dconfig']['autoproto_in']			?: 'any';
$pconfig['agateway_in']		= $pfb['dconfig']['agateway_in']			?: 'default';

$pconfig['autoaddrnot_out']	= PfbConfig::read('dnsbl/autoaddrnot_out');
$pconfig['autoports_out']	= PfbConfig::read('dnsbl/autoports_out');
$pconfig['aliasports_out']	= $pfb['dconfig']['aliasports_out']			?: '';
$pconfig['autoaddr_out']	= PfbConfig::read('dnsbl/autoaddr_out');
$pconfig['autonot_out']		= PfbConfig::read('dnsbl/autonot_out');
$pconfig['aliasaddr_out']	= $pfb['dconfig']['aliasaddr_out']			?: '';
$pconfig['autoproto_out']	= $pfb['dconfig']['autoproto_out']			?: 'any';
$pconfig['agateway_out']	= $pfb['dconfig']['agateway_out']			?: 'default';

$pconfig['whitelist']		= pfb_b64_text($pfb['dconfig']['whitelist'] ?? NULL);

$pconfig['top1m_enable']	= PfbConfig::read('dnsbl/top1m_enable');
// Routed via the gateway (not the section array) so a stored legacy 'alexa'
// (dead TOP1M source, #872/#877) coalesces to 'tranco' for the form select.
// ->toStored() unwraps the PfbTop1mSource enum to its scalar option key (a
// Form_Select selected-value must be the scalar, not the enum instance).
$pconfig['top1m_source']		= PfbConfig::read('dnsbl/top1m_source')->toStored();
$pconfig['top1m_count']		= PfbConfig::read('dnsbl/top1m_count');
// 0 (unlimited) is meaningful, so don't use the ?: idiom (0 is falsy -> would reset to default).
$pconfig['pfb_py_cache_max']	= (isset($pfb['dconfig']['pfb_py_cache_max']) && $pfb['dconfig']['pfb_py_cache_max'] !== '') ? $pfb['dconfig']['pfb_py_cache_max'] : '10000';
$pconfig['top1m_inclusion']	= pfb_csv_list($pfb['dconfig']['top1m_inclusion'] ?? NULL, array('com','net','org','ca','co','io'));

$pconfig['tld_wildcard_exclusion']	= pfb_b64_text($pfb['dconfig']['tld_wildcard_exclusion'] ?? NULL);
$pconfig['tld_wildcard_blacklist']	= pfb_b64_text($pfb['dconfig']['tld_wildcard_blacklist'] ?? NULL);

// DoH/DoT/DoQ blocking — stored in pfblockerngsafesearch; read via gateway (registered keys)
$pconfig['safesearch_doh']		= PfbConfig::read('ss/safesearch_doh');
$pconfig['safesearch_doh_list']		= explode(',', PfbConfig::read('ss/safesearch_doh_list'));

// [ ADR-36 ] DNS Redirect — stored in pfblockerngdnsblsettings; read via gateway.
$pconfig['dnsbl_redir']			= PfbConfig::read('dnsbl/dnsbl_redir');
$pfb_redir_int_raw			= (string) PfbConfig::read('dnsbl/dnsbl_redir_int');
$pconfig['dnsbl_redir_int']		= ($pfb_redir_int_raw !== '') ? explode(',', $pfb_redir_int_raw) : [];
$pconfig['dnsbl_redir_exclude']		= (string) PfbConfig::read('dnsbl/dnsbl_redir_exclude');

// [ ADR-37 ] DoT/DoQ Block — stored in pfblockerngdnsblsettings; read via gateway.
$pconfig['dnsbl_dot_block']		= PfbConfig::read('dnsbl/dnsbl_dot_block');
$pfb_dot_block_int_raw			= (string) PfbConfig::read('dnsbl/dnsbl_dot_block_int');
$pconfig['dnsbl_dot_block_int']		= ($pfb_dot_block_int_raw !== '') ? explode(',', $pfb_dot_block_int_raw) : [];
$pconfig['dnsbl_dot_block_exclude']	= (string) PfbConfig::read('dnsbl/dnsbl_dot_block_exclude');
$pconfig['dnsbl_dot_block_action']	= (string) PfbConfig::read('dnsbl/dnsbl_dot_block_action');
$pconfig['dnsbl_dot_block_floating']	= PfbConfig::read('dnsbl/dnsbl_dot_block_floating');

// Select field options

$options_dnsbl_interface	= pfb_build_if_list(FALSE, FALSE);
$options_dnsbl_interface_all	= array_merge(array('lo0' => 'Localhost'), $options_dnsbl_interface);
$options_dnsbl_interface_cnt	= count($options_dnsbl_interface) ?: '1';

$options_dnsbl_allow_int	= $options_dnsbl_interface;

// [ ADR-36 ] DNS Redirect: WAN-excluded interface list (same filter as Permit Firewall Rules).
$options_dnsbl_redir_int	= $options_dnsbl_interface;

// [ ADR-37 ] DoT/DoQ Block: WAN-excluded interface list (same filter as Permit Firewall Rules).
$options_dnsbl_dot_block_int	= $options_dnsbl_interface;

// [ ADR-37 ] DoT/DoQ Block: rule action selector (mirrors the IP-settings Rule Action).
$options_dnsbl_dot_block_action	= [ 'block' => 'Block', 'reject' => 'Reject' ];

$options_global_log_txt = 'Overrides each DNSBL Group\'s Logging/Blocking setting. Default is no global override.'
			. '<div class="infoblock">'
			. 'Default: <strong>No Global mode</strong><br />'
			. 'Enabling this option will override the individual DNSBL Group "Logging/Blocking" settings!<br /><br />'
			. '&#8226 <strong>DNSBL WebServer/VIP</strong>, Domains are sinkholed to the DNSBL VIP and logged via the DNSBL WebServer.<br />'
			. '&#8226 <strong>Null Blocking (logging)</strong>, Utilize \'0.0.0.0\' with logging.<br />'
			. '&#8226 <strong>Null Blocking (no logging)</strong>, Utilize \'0.0.0.0\' with no logging.<br />'
			. '&#8226 <strong>NXDOMAIN (logging)</strong>, Reply NXDOMAIN with logging. The DNSBL block page is bypassed.<br />'
			. '&#8226 <strong>NXDOMAIN (no logging)</strong>, Reply NXDOMAIN with no logging. The DNSBL block page is bypassed.<br />'
			. 'Blocked domains will be reported to the Alert/Block Table.<br /><br />'
			. 'A \'Force Reload - DNSBL\' is required for changes to take effect'
			. '</div>';

$options_global_log	= [	''		=> 'No Global mode',
				'enabled'	=> 'DNSBL WebServer/VIP',
				'disabled_log'	=> 'Null Blocking (logging)',
				'disabled'	=> 'Null Blocking (no logging)',
				'nxdomain_log'	=> 'NXDOMAIN (logging)',
				'nxdomain'	=> 'NXDOMAIN (no logging)'];

$options_dnsbl_webpage = array();
$indexdir = '/usr/local/www/pfblockerng/www';
if (is_dir("{$indexdir}")) {
	$list = glob("{$indexdir}/*.{php,html}", GLOB_BRACE);
	if (!empty($list)) {
		foreach ($list as $line) {
			if (strpos($line, 'index.php') !== FALSE || strpos($line, 'dnsbl_active.php') !== FALSE) {
				continue;
			} else {
				$file = basename($line);
				if (@filesize("/usr/local/www/pfblockerng/www/{$file}") > 0) {
					$options_dnsbl_webpage = array_merge($options_dnsbl_webpage, array($file => $file));
				}
			}
		}
	}
}
$options_dnsbl_webpage_cnt = count($options_dnsbl_webpage) ?: '1';

$options_top1m_source		= [ 'tranco' => 'Tranco TOP1M', 'cisco' => 'Cisco Umbrella TOP1M',
					    'openpagerank' => 'OpenPageRank TOP1M', 'majestic' => 'Majestic Million TOP1M',
					    'cloudflare' => 'Cloudflare Radar' ];

// ADR-59: providers whose 'auth' needs the top1m_token field, derived from the
// descriptor table so a future token provider needs no JS edit -- the JS toggle
// below shows/hides the masked token field based on the selected provider.
$pfb_top1m_token_providers = [];
foreach (pfb_top1m_providers() as $pfb_top1m_id => $pfb_top1m_provider_row) {
	if (is_array($pfb_top1m_provider_row['auth']) && !empty($pfb_top1m_provider_row['auth']['header'])) {
		$pfb_top1m_token_providers[] = $pfb_top1m_id;
	}
}
$pfb_top1m_token_providers_json = json_encode($pfb_top1m_token_providers);

$options_top1m_count		= [	'500' => 'Top 500', '1000' => 'Top 1k', '2000' => 'Top 2k', '5000' => 'Top 5k', '10000' => 'Top 10k',
					'25000' => 'Top 25k', '50000' => 'Top 50k', '75000' => 'Top 75k', '100000' => 'Top 100k', '250000' => 'Top 250k',
					'500000' => 'Top 500k', '750000' => 'Top 750k', '1000000' => 'Top 1M' ];

$options_top1m_inclusion	= [	'ae' => 'AE',
					'aero' => 'AERO',
					'ag' => 'AG',
					'al' => 'AL',
					'am' => 'AM',
					'ar' => 'AR',
					'asia' => 'ASIA',
					'at' => 'AT',
					'au' => 'AU (16)',
					'az' => 'AZ',
					'ba' => 'BA',
					'bd' => 'BD',
					'be' => 'BE',
					'bg' => 'BG',
					'biz' => 'BIZ',
					'bo' => 'BO',
					'br' => 'BR (7)',
					'by' => 'BY',
					'bz' => 'BZ',
					'ca' => 'CA (21)',
					'cat' => 'CAT',
					'cc' => 'CC',
					'cf' => 'CF',
					'ch' => 'CH',
					'cl' => 'CL',
					'club' => 'CLUB',
					'cn' => 'CN (14)',
					'co' => 'CO (22)',
					'com' => 'COM (1)',
					'coop' => 'COOP',
					'cr' => 'CR',
					'cu' => 'CU',
					'cy' => 'CY',
					'cz' => 'CZ (23)',
					'de' => 'DE (5)',
					'dev' => 'DEV',
					'dk' => 'DK',
					'do' => 'DO',
					'dz' => 'DZ',
					'ec' => 'EC',
					'edu' => 'EDU',
					'ee' => 'EE',
					'eg' => 'EG',
					'es' => 'ES (18)',
					'eu' => 'EU (25)',
					'fi' => 'FI',
					'fm' => 'FM',
					'fr' => 'FR (12)',
					'ga' => 'GA',
					'ge' => 'GE',
					'gov' => 'GOV',
					'gr' => 'GR (20)',
					'gt' => 'GT',
					'guru' => 'GURU',
					'hk' => 'HK',
					'hr' => 'HR',
					'hu' => 'HU',
					'id' => 'ID',
					'ie' => 'IE',
					'il' => 'IL',
					'im' => 'IM',
					'in' => 'IN (9)',
					'info' => 'INFO (15)',
					'int' => 'INT',
					'io' => 'IO',
					'ir' => 'IR (13)',
					'is' => 'IS',
					'it' => 'IT (11)',
					'jo' => 'JO',
					'jobs' => 'JOBS',
					'jp' => 'JP (6)',
					'ke' => 'KE',
					'kg' => 'KG',
					'kr' => 'KR (19)',
					'kw' => 'KW',
					'kz' => 'KZ',
					'la' => 'LA',
					'li' => 'LI',
					'link' => 'LINK',
					'lk' => 'LK',
					'lt' => 'LT',
					'lu' => 'LU',
					'lv' => 'LV',
					'ly' => 'LY',
					'ma' => 'MA',
					'md' => 'MD',
					'me' => 'ME',
					'mk' => 'MK',
					'ml' => 'ML',
					'mn' => 'MN',
					'mobi' => 'MOBI',
					'mx' => 'MX',
					'my' => 'MY',
					'name' => 'NAME',
					'net' => 'NET (2)',
					'ng' => 'NG',
					'ninja' => 'NINJA',
					'nl' => 'NL (17)',
					'no' => 'NO',
					'np' => 'NP',
					'nu' => 'NU',
					'nz' => 'NZ',
					'om' => 'OM',
					'org' => 'ORG (4)',
					'pa' => 'PA',
					'pe' => 'PE',
					'ph' => 'PH',
					'pk' => 'PK',
					'pl' => 'PL (10)',
					'pro' => 'PRO',
					'pt' => 'PT',
					'pw' => 'PW',
					'py' => 'PY',
					'qa' => 'QA',
					'ro' => 'RO',
					'rs' => 'RS',
					'ru' => 'RU (3)',
					'sa' => 'SA',
					'se' => 'SE',
					'sg' => 'SG',
					'si' => 'SI',
					'sk' => 'SK',
					'so' => 'SO',
					'space' => 'SPACE',
					'su' => 'SU',
					'th' => 'TH',
					'tk' => 'TK',
					'tn' => 'TN',
					'to' => 'TO',
					'today' => 'TODAY',
					'top' => 'TOP',
					'tr' => 'TR',
					'travel' => 'TRAVEL',
					'tv' => 'TV',
					'tw' => 'TW (24)',
					'tz' => 'TZ',
					'ua' => 'UA',
					'uk' => 'UK (8)',
					'us' => 'US',
					'uy' => 'UY',
					'uz' => 'UZ',
					'vc' => 'VC',
					've' => 'VE',
					'vn' => 'VN',
					'website' => 'WEBSITE',
					'ws' => 'WS',
					'xn--p1ai' => 'XN--P1AI',
					'xxx' => 'XXX',
					'xyz' => 'XYZ',
					'za' => 'ZA'
				];

$options_action			= [ 'Disabled' => 'Disabled', 'Deny_Inbound' => 'Deny Inbound', 'Deny_Outbound' => 'Deny Outbound', 'Deny_Both' => 'Deny Both', 'Alias_Deny' => 'Alias Deny', 'Alias_Native' => 'Alias Native' ];

$options_aliaslog		= [ 'enabled' => 'Enable', 'disabled' => 'Disable' ];

// DoH/DoT/DoQ blocking options — stored in pfblockerngsafesearch (foreign section; see ADR-29 foreign-key exclusion list)
$options_safesearch_doh		= ['Disable' => 'Disable', 'Enable' => 'Enable'];
$options_safesearch_doh_list	= [
					'use-application-dns.net' => 'Firefox [use-application-dns.net]',
					'cloudflare-dns.com' => 'CloudFlare DoH/DoT [cloudflare-dns.com]',
					'security.cloudflare-dns.com' => 'CloudFlare Security DoH/DoT [security.cloudflare-dns.com]',
					'family.cloudflare-dns.com' => 'CloudFlare Family DoH/DoT [family.cloudflare-dns.com]',
					'one.one.one.one' => 'CloudFlare One [one.one.one.one]',
					'1dot1dot1dot1.cloudflare-dns.com' => 'CloudFlare 1dot DoT [1dot1dot1dot1.cloudflare-dns.com]',
					'dns.google' => 'Google DoH/DoT [dns.google]',
					'doh.dns.apple.com' => 'Apple [doh.dns.apple.com]',
					'mask.icloud.com' => 'Apple iCloud Private Relay [mask.icloud.com]',
					'mask-h2.icloud.com' => 'Apple iCloud Private Relay [mask-h2.icloud.com]',
					'mask-api.icloud.com' => 'Apple iCloud Private Relay [mask-api.icloud.com]',
					'mask-t.apple-dns.net' => 'Apple iCloud Private Relay [mask-t.apple-dns.net]',
					'mask.apple-dns.net' => 'Apple iCloud Private Relay [mask.apple-dns.net]',
					'mask-api.fe.apple-dns.net' => 'Apple iCloud Private Relay [mask-api.fe.apple-dns.net]',
					'doh.opendns.com' => 'OpenDNS DoH [doh.opendns.com]',
					'doh.familyshield.opendns.com' => 'OpenDNS Family DoH [doh.familyshield.opendns.com]',
					'dns.quad9.net' => 'Quad9 DoH/DoT [dns.quad9.net]',
					'dns10.quad9.net' => 'Quad9 Unsecured DoH/DoT [dns10.quad9.net]',
					'dns11.quad9.net' => 'Quad9 ECS DoH/DoT [dns11.quad9.net]',
					'dns.adguard-dns.com' => 'AdGuard DoH/DoT/DoQ [dns.adguard-dns.com]',
					'unfiltered.adguard-dns.com' => 'AdGuard Unfiltered DoH/DoT/DoQ [unfiltered.adguard-dns.com]',
					'family.adguard-dns.com' => 'AdGuard Family DoH/DoT/DoQ [family.adguard-dns.com]',
					'doh.cleanbrowsing.org' => 'CleanBrowsing [doh.cleanbrowsing.org]',
					'security-filter-dns.cleanbrowsing.org' => 'CleanBrowsing Security [security-filter-dns.cleanbrowsing.org]',
					'family-filter-dns.cleanbrowsing.org' => 'CleanBrowsing Family [family-filter-dns.cleanbrowsing.org]',
					'adult-filter-dns.cleanbrowsing.org' => 'CleanBrowsing Adult [adult-filter-dns.cleanbrowsing.org]',
					'dns.nextdns.io' => 'NextDNS DoH/DoT/DoQ [dns.nextdns.io]',
					'dns.switch.ch' => 'SWITCH DoH/DoT [dns.switch.ch]',
					'dns.futuredns.me' => 'FutureDNS DoH/DoT/DoQ [dns.futuredns.me]',
					'dns.comss.one' => 'Comss.ru West DoH/DoT [dns.comss.one]',
					'dns.east.comss.one' => 'Comss.ru East [dns.east.comss.one]',
					'private.canadianshield.cira.ca' => 'CIRA Private [private.canadianshield.cira.ca]',
					'protected.canadianshield.cira.ca' => 'CIRA Protected [protected.canadianshield.cira.ca]',
					'family.canadianshield.cira.ca' => 'CIRA Family [family.canadianshield.cira.ca]',
					'doh-fi.blahdns.com' => 'BlahDNS DoH Finland [doh-fi.blahdns.com]',
					'doh-jp.blahdns.com' => 'BlahDNS DoH Japan [doh-jp.blahdns.com]',
					'doh-de.blahdns.com' => 'BlahDNS DoH Germany [doh-de.blahdns.com]',
					'dot-fi.blahdns.com' => 'BlahDNS DoT Finland [dot-fi.blahdns.com]',
					'dot-jp.blahdns.com' => 'BlahDNS DoT Japan [dot-fi.blahdns.com]',
					'dot-de.blahdns.com' => 'BlahDNS DoT Germany [dot-de.blahdns.com]',
					'fi.doh.dns.snopyta.org' => 'Snopyta [fi.doh.dns.snopyta.org]',
					'dns-doh.dnsforfamily.com' => 'DNS for Family DoH [dns-doh.dnsforfamily.com]',
					'dns-dot.dnsforfamily.com' => 'DNS for Family DoT [dns-dot.dnsforfamily.com]',
					'odvr.nic.cz' => 'CZ.NIC ODVR [odvr.nic.cz]',
					'dns.alidns.com' => 'Ali [dns.alidns.com]',
					'dns.cfiec.net' => 'CFIEC [dns.cfiec.net]',
					'asia.dnscepat.id' => 'DNSCEPAT Asia [asia.dnscepat.id]',
					'eropa.dnscepat.id' => 'DNSCEPAT Eropa [eropa.dnscepat.id]',
					'doh.360.cn' => '360 Secure [doh.360.cn]',
					'public.dns.iij.jp' => 'IIJ.JP [public.dns.iij.jp]',
					'dns.pub' => 'DNSPod [dns.pub]',
					'doh.pub' => 'DNSPod DoH [doh.pub]',
					'dot.pub' => 'DNSPod DoT [dot.pub]',
					'dns.twnic.tw' => 'Quad101 [dns.twnic.tw]',
					'doh.tiarap.org' => 'Privacy-First Singapore [doh.tiarap.org]',
					'doh.tiar.app' => 'Privacy-First Singapore DoH/DoQ [doh.tiar.app]',
					'dot.tiar.app' => 'Privacy-First Singapore DoT [dot.tiar.app]',
					'jp.tiarap.org' => 'Privacy-First Japan DoH [jp.tiarap.org]',
					'jp.tiar.app' => 'Privacy-First Japan DoT [jp.tiar.app]',
					'dns.oszx.co' => 'OSZX [dns.oszx.co]',
					'dns.pumplex.com' => 'Pumplex [dns.pumplex.com]',
					'doh.applied-privacy.net' => 'Applied Privacy DoH [doh.applied-privacy.net]',
					'dot1.applied-privacy.net' => 'Applied Privacy DoT [dot1.applied-privacy.net]',
					'dns.decloudus.com' => 'DeCloudUs [dns.decloudus.com]',
					'resolver-eu.lelux.fi' => 'Lelux [resolver-eu.lelux.fi]',
					'doh.dns.sb' => 'DNS.SB [doh.dns.sb]',
					'dnsforge.de' => 'DNS Forge [dnsforge.de]',
					'kaitain.restena.lu' => 'Fondation Restena [kaitain.restena.lu]',
					'doh.ffmuc.net' => 'FFMUC DoH [doh.ffmuc.net]',
					'dot.ffmuc.net' => 'FFMUC DoT [dot.ffmuc.net]',
					'dns.digitale-gesellschaft.ch' => 'Digitale Gesellschaft [dns.digitale-gesellschaft.ch]',
					'doh.libredns.gr' => 'LibreDNS DoH [doh.libredns.gr]',
					'dot.libredns.gr' => 'LibreDNS DoT [dot.libredns.gr]',
					'ibksturm.synology.me' => 'ibksturm [ibksturm.synology.me]',
					'getdnsapi.net' => 'DNS Privacy [getdnsapi.net]',
					'dnsovertls.sinodun.com' => 'DNS Privacy TLS [dnsovertls.sinodun.com]',
					'dnsovertls1.sinodun.com' => 'DNS Privacy TLS2 [dnsovertls1.sinodun.com]',
					'unicast.censurfridns.dk' => 'DNS Privacy Unicast [unicast.censurfridns.dk]',
					'anycast.censurfridns.dk' => 'DNS Privacy Anycast [anycast.censurfridns.dk]',
					'dns.cmrg.net' => 'DNS Privacy dkg [dns.cmrg.net]',
					'dns.larsdebruin.net' => 'DNS Privacy larsdebruin [dns.larsdebruin.net]',
					'dns-tls.bitwiseshift.net' => 'DNS Privacy bitwiseshift [dns-tls.bitwiseshift.net]',
					'ns1.dnsprivacy.at' => 'DNS Privacy dnsprivacy [ns1.dnsprivacy.at]',
					'ns2.dnsprivacy.at' => 'DNS Privacy dnsprivacy2 [ns2.dnsprivacy.at]',
					'dns.bitgeek.in' => 'DNS Privacy bitgeek [dns.bitgeek.in]',
					'dns.neutopia.org' => 'DNS Privacy neutopia [dns.neutopia.org]',
					'privacydns.go6lab.si' => 'DNS Privacy Go6Lab [privacydns.go6lab.si]',
					'dot.securedns.eu' => 'DNS Privacy securedns [dot.securedns.eu]',
					'dnsotls.lab.nic.cl' => 'DNS Privacy NIC Chile [dnsotls.lab.nic.cl]',
					'tls-dns-u.odvr.dns-oarc.net' => 'DNS Privacy OARC [tls-dns-u.odvr.dns-oarc.net]',
					'doh.centraleu.pi-dns.com' => 'PI-DNS Central EU DoH [doh.centraleu.pi-dns.com]',
					'dot.centraleu.pi-dns.com' => 'PI-DNS Central EU DoT [dot.centraleu.pi-dns.com]',
					'doh.northeu.pi-dns.com' => 'PI-DNS North EU DoH [doh.northeu.pi-dns.com]',
					'dot.northeu.pi-dns.com' => 'PI-DNS North EU DoT [dot.northeu.pi-dns.com]',
					'doh.westus.pi-dns.com' => 'PI-DNS West USA DoH [doh.westus.pi-dns.com]',
					'dot.westus.pi-dns.com' => 'PI-DNS West USA DoT [dot.westus.pi-dns.com]',
					'doh.eastus.pi-dns.com' => 'PI-DNS East USA DoH [doh.eastus.pi-dns.com]',
					'dot.eastus.pi-dns.com' => 'PI-DNS East USA DoT [dot.eastus.pi-dns.com]',
					'doh.eastau.pi-dns.com' => 'PI-DNS East AU DoH [doh.eastau.pi-dns.com]',
					'dot.eastau.pi-dns.com' => 'PI-DNS East AU DoT [dot.eastau.pi-dns.com]',
					'doh.eastas.pi-dns.com' => 'PI-DNS East AS DoH [doh.eastas.pi-dns.com]',
					'dot.eastas.pi-dns.com' => 'PI-DNS East AS DoT [dot.eastas.pi-dns.com]',
					'doh.pi-dns.com' => 'PI-DNS [doh.pi-dns.com]',
					'dot.seby.io' => 'Seby [dot.seby.io]',
					'doh-2.seby.io' => 'Seby 2 [doh-2.seby.io]',
					'doh.dnslify.com' => 'DNSlify [doh.dnslify.com]',
					'dns.yandex' => 'Yandex DoH/DoT [dns.yandex]',
					'blitz.ahadns.com' => 'AhaDNS Blitz DoH [blitz.ahadns.com]',
					'doh.nl.ahadns.net' => 'AhaDNS Blitz Netherlands DoH [doh.nl.ahadns.net]',
					'dot.nl.ahadns.net' => 'AhaDNS Blitz Netherlands DoT [dot.nl.ahadns.net]',
					'doh.in.ahadns.net' => 'AhaDNS Blitz India DoH [doh.in.ahadns.net]',
					'dot.in.ahadns.net' => 'AhaDNS Blitz India DoT [dot.in.ahadns.net]',
					'doh.la.ahadns.net' => 'AhaDNS Blitz Las Angeles DoH [doh.la.ahadns.net]',
					'dot.la.ahadns.net' => 'AhaDNS Blitz Las Angeles DoT [dot.la.ahadns.net]',
					'doh.ny.ahadns.net' => 'AhaDNS Blitz New York DoH [doh.ny.ahadns.net]',
					'dot.ny.ahadns.net' => 'AhaDNS Blitz New York DoT [dot.ny.ahadns.net]',
					'doh.pl.ahadns.net' => 'AhaDNS Blitz Poland DoH [doh.pl.ahadns.net]',
					'dot.pl.ahadns.net' => 'AhaDNS Blitz Poland DoT [dot.pl.ahadns.net]',
					'doh.it.ahadns.net' => 'AhaDNS Blitz Italy DoH [doh.it.ahadns.net]',
					'dot.it.ahadns.net' => 'AhaDNS Blitz Italy DoT [dot.it.ahadns.net]',
					'doh.es.ahadns.net' => 'AhaDNS Blitz Spain DoH [doh.es.ahadns.net]',
					'dot.es.ahadns.net' => 'AhaDNS Blitz Spain DoT [dot.es.ahadns.net]',
					'doh.no.ahadns.net' => 'AhaDNS Blitz Norway DoH [doh.no.ahadns.net]',
					'dot.no.ahadns.net' => 'AhaDNS Blitz Norway DoT [dot.no.ahadns.net]',
					'doh.chi.ahadns.net' => 'AhaDNS Blitz Chicago DoH [doh.chi.ahadns.net]',
					'dot.chi.ahadns.net' => 'AhaDNS Blitz Chicago DoT [dot.chi.ahadns.net]',
					'doh.au.ahadns.net' => 'AhaDNS Blitz Australia DoH [doh.au.ahadns.net]',
					'dot.au.ahadns.net' => 'AhaDNS Blitz Australia DoT [dot.au.ahadns.net]',
					'basic.rethinkdns.com' => 'RethinkDNS DoH [basic.rethinkdns.com]',
					'max.rethinkdns.com' => 'RethinkDNS DoT [max.rethinkdns.com]',
					'freedns.controld.com' => 'ControlD DoH [freedns.controld.com]',
					'p0.freedns.controld.com' => 'ControlD DoT [p0.freedns.controld.com]',
					'p1.freedns.controld.com' => 'ControlD DoT [p1.freedns.controld.com]',
					'p2.freedns.controld.com' => 'ControlD DoT [p2.freedns.controld.com]',
					'p3.freedns.controld.com' => 'ControlD DoT [p3.freedns.controld.com]',
					'doh.mullvad.net' => 'Mullvad [doh.mullvad.net]',
					'adblock.doh.mullvad.net' => 'Mullvad [adblock.doh.mullvad.net]',
					'dns.arapurayil.com' => 'Arapurayil [dns.arapurayil.com]',
					'dandelionsprout.asuscomm.com' => 'Dandelion Sprout DoH/DoT/DoQ [dandelionsprout.asuscomm.com]',
					'zero.dns0.eu' => 'European public DNS DoH/DoT/DoQ [zero.dns0.eu]'
					];

// Collect all pfSense 'Port' + address-bearing Aliases
// foreign key — out of ADR-29 gateway scope (aliases/alias is not a pfblockerng* path)
$pfb_ac_lists			= pfb_alias_autocomplete_lists(config_get_path('aliases/alias', []));
$options_aliasports_in		= $options_aliasports_out	= $pfb_ac_lists['ports'];
$options_aliasaddr_in		= $options_aliasaddr_out	= $pfb_ac_lists['networks'];
$ports_list			= implode(',', array_keys($pfb_ac_lists['ports']));
$networks_list			= implode(',', array_keys($pfb_ac_lists['networks']));

$options_autoproto_in		= $options_autoproto_out	= get_ipprotocols();
$options_agateway_in		= $options_agateway_out		= pfb_get_gateways();

// $input_errors and $savemsg are read unconditionally in the render section below,
// so they must be defined on every request path. Initialise them once.
$input_errors = array();
$savemsg = '';

// Validate input fields and save
if ($_POST) {
	if (isset($_POST['save'])) {

		// issue #1723: sanitize at ingestion -- first step, before any evaluation.
		foreach (array('pfb_dnsvip4', 'pfb_dnsvip6', 'dnsbl_webpage', 'dnsbl_redir_exclude', 'dnsbl_dot_block_exclude',
				'top1m_token', 'aliasaddr_in', 'aliasaddr_out', 'aliasports_in', 'aliasports_out') as $pfb_text_field) {
			$_POST[$pfb_text_field] = pfb_sanitize_text((string) ($_POST[$pfb_text_field] ?? ''));
		}
		foreach (array('pfb_regex_list', 'pfb_noaaaa_list', 'pfb_gp_bypass_list', 'whitelist', 'tld_wildcard_exclusion', 'tld_wildcard_blacklist') as $pfb_text_area_field) {
			$_POST[$pfb_text_area_field] = pfb_sanitize_text_area((string) ($_POST[$pfb_text_area_field] ?? ''));
		}

		// Validate Select field options
		$select_options = array(						'dnsbl_interface'	=> 'lo0',
						'global_log'		=> '',
						'dnsbl_webpage'		=> 'dnsbl_default.php',
						'top1m_source'		=> 'tranco',
						'top1m_count'		=> '1000',
						'action'		=> 'Disabled',
						'aliaslog'		=> 'enabled',
						'aliasports_in'		=> '',
						'aliasports_out'	=> '',
						'aliasaddr_in'		=> '',
						'aliasaddr_out'		=> '',
						'autoproto_in'		=> 'any',
						'autoproto_out'		=> 'any',
						'agateway_in'		=> 'default',
						'agateway_out'		=> 'default',
						'dnsbl_dot_block_action'=> 'reject'
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
		$select_options = array(	'dnsbl_allow_int'	=> '',
						'top1m_inclusion'	=> $default_tlds
						);

		foreach ($select_options as $s_option => $s_default) {
			if (is_array($_POST[$s_option])) {
				foreach ($_POST[$s_option] as $post_option) {
					if (!array_key_exists($post_option, ${"options_$s_option"})) {
						$_POST[$s_option] = $s_default;
						break;
					}
				}
			}
			elseif (!array_key_exists($_POST[$s_option], ${"options_$s_option"})) {
				$_POST[$s_option] = $s_default;
			}
		}

		// Validate DNSBL webserver block page
		$dnsbl_webpage		= FALSE;
		// issue #1723: already sanitized by the ingestion prologue above -- plain read.
		$dnsbl_webpage_file	= pfb_filter(basename($_POST['dnsbl_webpage'] ?? ''), PFB_FILTER_WORD_DOT, 'dnsbl', 'dnsbl_default.php');
		if (file_exists("/usr/local/www/pfblockerng/www/{$dnsbl_webpage_file}") &&
		    @filesize("/usr/local/www/pfblockerng/www/{$dnsbl_webpage_file}") > 0 &&
		    pfb_filter(array("/usr/local/www/pfblockerng/www/{$dnsbl_webpage_file}", 'text/html'), PFB_FILTER_FILE_MIME_COMPARE, 'dnsbl')) {

			// Check if DNSBL Webpage has been changed.
			if ($dnsbl_webpage_file != $pfb['dconfig']['dnsbl_webpage']) {
				$dnsbl_webpage = TRUE;
			}
			$pfb['dconfig']['dnsbl_webpage'] = $dnsbl_webpage_file;
			// foreign key — out of ADR-29 gateway scope (dnsbl_webpage is out-of-scope; see CfgGatewayTest $out_of_scope)
			config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_webpage', $pfb['dconfig']['dnsbl_webpage']);
		}
		else {
			$input_errors[] = 'DNSBL Web Server page is invalid!';
		}

		foreach (array('aliasports_in', 'aliasaddr_in', 'aliasports_out', 'aliasaddr_out') as $value) {
			if (!empty($_POST[$value]) && !is_validaliasname($_POST[$value])) {
				$input_errors[] = 'Settings: Advanced In/Outbound Aliasname error - ' . invalidaliasnamemsg($_POST[$value]);
			}
		}

		if (!is_port($_POST['pfb_dnsport'])) {
			$input_errors[] = 'DNSBL Port is invalid!';
		}
		if (!is_port($_POST['pfb_dnsport_ssl'])) {
			$input_errors[] = 'DNSBL SSL Port is invalid!';
		}
		if (isset($_POST['pfb_py_cache_max']) && $_POST['pfb_py_cache_max'] !== '' &&
			(!ctype_digit((string) $_POST['pfb_py_cache_max']) || (int) $_POST['pfb_py_cache_max'] > 5000000)) {
			$input_errors[] = 'DNSBL Decision cache max entries must be a whole number between 0 and 5000000.';
		}

		// Non-ascii characters are not allowed for DNSBL Regex
		if (!mb_detect_encoding($_POST['pfb_regex_list'], 'ASCII', TRUE)) {
			$input_errors[] = 'DNSBL Regex list contains non-ascii characters';
		}

		// ADR-08: IDN Blocking mode must be one of the <select> options. PFB_FILTER_WORD
		// only checks shape, so without this an out-of-vocabulary value (e.g. a tampered
		// POST) would canonicalise to Off and silently disable IDN blocking.
		if (!in_array(pfb_filter($_POST['pfb_idn'] ?? '', PFB_FILTER_WORD, 'dnsbl'),
			array('off', 'confusable', 'on'), TRUE)) {
			$input_errors[] = 'DNSBL IDN Blocking mode is invalid!';
		}

		// ADR-59: top1m_token is a masked, write-only field -- a blank POST means
		// "leave the stored token unchanged" (never overwrite/clear it), so only a
		// NON-EMPTY submission is validated. PFB_FILTER_WORD (used by asn_token) would
		// reject a real base64url/JWT token -- PFB_FILTER_TOKEN accepts that charset.
		// Reference 'top1m_token' suppresses pfb_filter()'s failed-validation log line
		// -- the token itself must never reach a log, even a rejected one.
		// issue #1723: already sanitized by the ingestion prologue above -- plain read.
		$pfb_top1m_token_post = (string) ($_POST['top1m_token'] ?? '');
		if ($pfb_top1m_token_post !== '' && empty(pfb_filter($pfb_top1m_token_post, PFB_FILTER_TOKEN, 'top1m_token'))) {
			$input_errors[] = 'DNSBL TOP1M Token is invalid!';
		}

		// Validate customlists
		foreach (array(
				'pfb_noaaaa_list'	=> 'domain',
				'pfb_gp_bypass_list'	=> 'ip',
				'whitelist'		=> 'domain',
				'tld_wildcard_exclusion'		=> 'hostname',
				'tld_wildcard_blacklist'		=> 'tld' ) as $custom_type => $custom_format) {

				if (!empty($_POST[$custom_type])) {
					// issue #1723: the ingestion prologue already normalized CRLF/CR to LF,
					// so per-line validation now splits on "\n" (the pre-#1723 "\r\n" split
					// matched a browser's raw CRLF submission; that separator no longer
					// survives ingestion).
					$customlist = explode("\n", $_POST[$custom_type]);
					if (!empty($customlist)) {
						foreach ($customlist as $line) {

							if (str_starts_with($line, '#') || empty($line)) {
								continue;
							}
							$value = array_map('trim', preg_split('/(?=#)/', $line));

							switch ($custom_format) {
								case 'hostname':
									$value[0] = trim($value[0], '.');
									if (empty(pfb_filter($value[0], PFB_FILTER_HOSTNAME, 'dnsbl'))) {
										$input_errors[] = "Customlist {$custom_type}: Invalid  Hostname entry: [ " . htmlspecialchars($line) . " ]";
									}
									break;
								case 'domain':
									// issue #1741: only the trailing dot(s) come off -- pfb_filter()
									// takes the leading-dot wildcard form itself, and stripping that
									// here would validate an invalid '..host' row as a legal one.
									$value[0] = rtrim($value[0], '.');
									if (empty(pfb_filter($value[0], PFB_FILTER_DOMAIN, 'dnsbl'))) {
										$input_errors[] = "Customlist {$custom_type}: Invalid Domain name entry: [ " . htmlspecialchars($line) . " ]";
									}
									break;
								case 'ip':
									if (empty(pfb_filter($value[0], PFB_FILTER_IP, 'dnsbl'))) {
										$input_errors[] = "Customlist {$custom_type}: Invalid IP entry: [ " . htmlspecialchars($line) . " ]";
									}
									break;
								case 'tld':
									if (empty(pfb_filter($value[0], PFB_FILTER_TLD, 'dnsbl'))) {
										$input_errors[] = "Customlist {$custom_type}: Invalid TLD entry: [ " . htmlspecialchars($line) . " ]";
									}
									break;
								default:
									break;
							}
						}
					}
				}
		}
		// A usable validator always runs, so an entry the resolver would drop is reported
		// whether or not the feature is on yet. Only the fail-closed branch is gated: with
		// no usable interpreter, pfb_unbound.py loads Regex List patterns solely when this
		// toggle is on, so an unloaded list must not make the whole page unsavable.
		$pfb_regex_python = pfb_python_interpreter();
		$pfb_regex_ready = $pfb_regex_python !== '';
		if (pfb_dnsbl_regex_validation_required_page(
			$pfb_regex_ready,
			$_POST['pfb_regex'] ?? ''
		)) {
			foreach (pfb_dnsbl_regex_validation_errors((string) ($_POST['pfb_regex_list'] ?? ''), PFB_PYTHON_WRAPPER, ($_POST['pfb_regex_cap'] ?? '') === 'on') as $regex_error) {
				$input_errors[] = 'Customlist pfb_regex_list: ' . htmlspecialchars($regex_error, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
			}
		}

		// Validate DNSBL VIP address
		// [ ADR-13 ] Auto-create mode: pfBlockerNG owns the DNSBL sinkhole VIP(s) and
		// provisions them server side on the next pfb_create_dnsbl('enabled') pass
		// (pfb_manage_dnsbl_vip). The manual dropdowns are disabled in the UI (a disabled
		// control is not submitted), so the manual VIP validation (existence / interface /
		// overlap) does NOT apply — the package picks a conflict-free address and
		// provisions the v6 VIP itself when the resolver listens on IPv6. In manual mode
		// (box off) the validator runs exactly as before; a missing IPv6 VIP is NOT a save
		// error (ADR-13 §7 pivot — it is a non-blocking runtime warning from pfb_global).
		$pfb_auto = (isset($_POST['pfb_dnsvip_auto']) && $_POST['pfb_dnsvip_auto'] == 'on');
		if (!$pfb_auto) {
			// issue #1723: already sanitized by the ingestion prologue above.
			if (($_POST['pfb_dnsvip4'] ?? '') == 'none') {
				$_POST['pfb_dnsvip4'] = '';
			}
			if (($_POST['pfb_dnsvip6'] ?? '') == 'none') {
				$_POST['pfb_dnsvip6'] = '';
			}
			list($vips_valid, $error) = pfb_validate_vips($_POST['dnsbl_interface'], $_POST['pfb_dnsvip4'] ?? '', $_POST['pfb_dnsvip6'] ?? '');
			if (!$vips_valid) {
				$input_errors[] = "DNSBL: {$error}";
			}
		}

		// Validate Adv. firewall rule 'Protocol' setting
		if (!empty($_POST['autoports_in']) || !empty($_POST['autoaddr_in'])) {
			if (empty($_POST['autoproto_in']) || $_POST['autoproto_in'] == 'any') {
				$input_errors[] = "Settings: Protocol setting cannot be set to 'Any' with Advanced Inbound firewall rule settings.";
			}
		}
		if (!empty($_POST['autoports_out']) || !empty($_POST['autoaddr_out'])) {
			if (empty($_POST['autoproto_out']) || $_POST['autoproto_out'] == 'any') {
				$input_errors[] = "Settings: Protocol setting cannot be set to 'Any' with Advanced Outbound firewall rule settings.";
			}
		}

		// Validate DoH/DoT/DoQ blocking fields (stored in pfblockerngsafesearch — foreign section)
		if (($_POST['safesearch_doh'] ?? '') == 'Enable' && empty($_POST['safesearch_doh_list'])) {
			$input_errors[] = 'Warning: With DoH/DoT/DoQ Blocking enabled, you must select at least one List';
		}

		if (!array_key_exists($_POST['safesearch_doh'] ?? '', $options_safesearch_doh)) {
			$_POST['safesearch_doh'] = 'Disable';
		}

		if (is_array($_POST['safesearch_doh_list'] ?? '')) {
			foreach ($_POST['safesearch_doh_list'] as $validate) {
				if (!array_key_exists($validate, $options_safesearch_doh_list)) {
					$_POST['safesearch_doh_list'] = '';
					break;
				}
			}
		}
		elseif (!array_key_exists($_POST['safesearch_doh_list'] ?? '', $options_safesearch_doh_list)) {
			$_POST['safesearch_doh_list'] = '';
		}

		// Validate DNS Redirect fields.
		$redir_ifaces_raw = (array)($_POST['dnsbl_redir_int'] ?? []);
		// issue #1723: already sanitized by the ingestion prologue above -- plain read.
		$redir_alias_raw  = (string)($_POST['dnsbl_redir_exclude'] ?? '');
		$redir_errors     = pfb_validate_dns_redirect_post(
			$redir_ifaces_raw,
			array_keys($options_dnsbl_redir_int),
			$redir_alias_raw
		);
		$input_errors = array_merge($input_errors, $redir_errors);

		// Validate DoT/DoQ Block fields.
		$dot_block_ifaces_raw = (array)($_POST['dnsbl_dot_block_int'] ?? []);
		// issue #1723: already sanitized by the ingestion prologue above -- plain read.
		$dot_block_alias_raw  = (string)($_POST['dnsbl_dot_block_exclude'] ?? '');
		$dot_block_action_raw = (string)($_POST['dnsbl_dot_block_action'] ?? 'reject');
		$dot_block_errors     = pfb_validate_dot_block_post(
			$dot_block_ifaces_raw,
			array_keys($options_dnsbl_dot_block_int),
			$dot_block_alias_raw,
			$dot_block_action_raw
		);
		$input_errors = array_merge($input_errors, $dot_block_errors);

		if (!$input_errors) {
			$pfb_top1m_settings_before = array(
				'enable'   => $pfb['dconfig']['top1m_enable'] ?? '',
				'count'    => $pfb['dconfig']['top1m_count'] ?? '',
				'tld'      => $pfb['dconfig']['top1m_inclusion'] ?? '',
				'provider' => $pfb['dconfig']['top1m_source'] ?? '',
			);

			$pfb['dconfig']['pfb_dnsbl']		= pfb_filter($_POST['pfb_dnsbl'], PFB_FILTER_ON_OFF, 'dnsbl')		?: '';
			$pfb['dconfig']['tld_wildcard']		= pfb_filter($_POST['tld_wildcard'], PFB_FILTER_ON_OFF, 'dnsbl')		?: '';
			$psl_include_private = pfb_filter($_POST['pfb_psl_include_private'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl') ?: '';
			$psl_allow_private = pfb_filter($_POST['pfb_psl_allow_private'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl') ?: '';
			// issue #2371: feed-at-suffix policy selects. PFB_FILTER_WORD only checks shape
			// (word chars) -- the canonicalisation to the three-token vocabulary (anything
			// else -> Honor) happens in PfbConfig::write()'s write_adapter
			// (pfb_cfg_feed_suffix_policy_write -> PfbFeedSuffixPolicy::fromStored), same
			// fail-safe principle as PfbToggle/PfbIdnMode's unknown-token fallback.
			$psl_feed_private_policy = pfb_filter($_POST['pfb_psl_feed_private_policy'] ?? '', PFB_FILTER_WORD, 'dnsbl') ?: '';
			$psl_feed_icann_policy = pfb_filter($_POST['pfb_psl_feed_icann_policy'] ?? '', PFB_FILTER_WORD, 'dnsbl') ?: '';
			$pfb['dconfig']['pfb_control']		= pfb_filter($_POST['pfb_control'], PFB_FILTER_ON_OFF, 'dnsbl')		?: '';
			$pfb['dconfig']['pfb_control_legacy']	= pfb_filter($_POST['pfb_control_legacy'], PFB_FILTER_ON_OFF, 'dnsbl')	?: '';
			$pfb['dconfig']['pfb_dnsbl_nonat']	= pfb_filter($_POST['pfb_dnsbl_nonat'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl')	?: '';

			// [ ADR-13 ] Persist the auto-create decision. When ON, leave the stored
			// pfb_dnsvip4/6 ids untouched here (the manual dropdowns are disabled): the
			// next pfb_create_dnsbl('enabled') pass (pfb_manage_dnsbl_vip) provisions the
			// marked VIP(s) and repoints pfb_dnsvip4/6 to the new _vip{uniqid} ids. When
			// OFF, the manual dropdown selections are saved below exactly as before.
			$pfb['dconfig']['pfb_dnsvip_auto']	= $pfb_auto ? 'on' : '';
			if (!$pfb_auto) {
				$pfb['dconfig']['pfb_dnsvip6'] = $_POST['pfb_dnsvip6'] ?: '';
			}

			$pfb['dconfig']['pfb_dnsport']		= $_POST['pfb_dnsport']							?: '8081';
			$pfb['dconfig']['pfb_dnsport_ssl']	= $_POST['pfb_dnsport_ssl']						?: '8443';
			$pfb['dconfig']['pfb_dnsbl_rule']	= pfb_filter($_POST['pfb_dnsbl_rule'], PFB_FILTER_ON_OFF, 'dnsbl')	?: '';
			$pfb['dconfig']['dnsbl_allow_int']	= implode(',', (array)$_POST['dnsbl_allow_int'])			?: '';
			$pfb['dconfig']['global_log']		= $_POST['global_log']							?: '';
			// issue #1907: checkbox-absent is the owner-ruled empty Off token.
			$pfb['dconfig']['pfb_cache']		= pfb_filter($_POST['pfb_cache'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl') ?: '';
			$pfb['dconfig']['pfb_cache_flush']	= pfb_filter($_POST['pfb_cache_flush'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl')	?: '';

			// issue #1907: checkbox-absent is the owner-ruled empty Off token.
			$pfb['dconfig']['pfb_py_reply']		= pfb_filter($_POST['pfb_py_reply'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl') ?: '';
			$pfb['dconfig']['pfb_hsts']		= pfb_filter($_POST['pfb_hsts'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl') ?: '';
			// ADR-08: IDN mode selector. Validate the raw word, then canonicalise via the
			// PfbIdnMode adapter to ('on' = All | 'confusable' | '' = Off).
			$pfb_idn_mode = pfb_filter($_POST['pfb_idn'], PFB_FILTER_WORD, 'dnsbl');
			$pfb['dconfig']['pfb_idn']		= pfb_cfg_idn_mode_write($pfb_idn_mode);
			// issue #1887: checkbox-absent is the owner-ruled empty Off token.
			$pfb['dconfig']['pfb_idn_block_malicious']	= pfb_filter($_POST['pfb_idn_block_malicious'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl') ?: '';
			$pfb['dconfig']['pfb_idn_escalate_suspicious']	= pfb_filter($_POST['pfb_idn_escalate_suspicious'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl') ?: '';
			$pfb['dconfig']['pfb_regex']		= pfb_filter($_POST['pfb_regex'], PFB_FILTER_ON_OFF, 'dnsbl')		?: '';
			$pfb['dconfig']['pfb_regex_cap']	= pfb_filter($_POST['pfb_regex_cap'], PFB_FILTER_ON_OFF, 'dnsbl')	?: '';
			$pfb['dconfig']['pfb_cname']		= pfb_filter($_POST['pfb_cname'], PFB_FILTER_ON_OFF, 'dnsbl')		?: '';
			$pfb['dconfig']['pfb_dnsbl_lenient']	= pfb_filter($_POST['pfb_dnsbl_lenient'], PFB_FILTER_ON_OFF, 'dnsbl')	?: '';
			$pfb['dconfig']['pfb_noaaaa']		= pfb_filter($_POST['pfb_noaaaa'], PFB_FILTER_ON_OFF, 'dnsbl')		?: '';
			$pfb['dconfig']['pfb_gp']		= pfb_filter($_POST['pfb_gp'], PFB_FILTER_ON_OFF, 'dnsbl')		?: '';

			$pfb['dconfig']['tld_allow']		= pfb_filter($_POST['tld_allow'], PFB_FILTER_ON_OFF, 'dnsbl')		?: '';
			$pfb['dconfig']['tld_allow_sort']	= pfb_filter($_POST['tld_allow_sort'], PFB_FILTER_ON_OFF, 'dnsbl')	?: '';
			$pfb['dconfig']['pfb_py_nolog']		= pfb_filter($_POST['pfb_py_nolog'], PFB_FILTER_ON_OFF, 'dnsbl')	?: '';

			// Python TLD Allow (Add default TLD Allows + ARPA + pfSense TLD
			if (!empty($_POST['tld_allow_gtld'])) {
				$pfb['dconfig']['tld_allow_gtld']	= "arpa,{$local_tld}," . implode(',', (array)$_POST['tld_allow_gtld']); 
			} else {
				$pfb['dconfig']['tld_allow_gtld']	= implode(',', $default_tlds);
			}

			// Python TLD Allow
			$pfb['dconfig']['tld_allow_cctld']	= implode(',', (array)$_POST['tld_allow_cctld']);
			$pfb['dconfig']['tld_allow_itld']	= implode(',', (array)$_POST['tld_allow_itld']);
			$pfb['dconfig']['tld_allow_bgtld']	= implode(',', (array)$_POST['tld_allow_bgtld']);

			$pfb['dconfig']['action']		= $_POST['action']							?: 'Disabled';
			$pfb['dconfig']['aliaslog']		= $_POST['aliaslog']							?: 'enabled';

			$pfb['dconfig']['autoaddrnot_in']	= pfb_filter($_POST['autoaddrnot_in'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl')	?: '';
			$pfb['dconfig']['autoports_in']		= pfb_filter($_POST['autoports_in'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl')	?: '';
			// issue #1723: aliasaddr_in/out, aliasports_in/out already sanitized by the
			// ingestion prologue above -- plain read.
			$pfb['dconfig']['aliasports_in']	= $_POST['aliasports_in']						?: '';
			$pfb['dconfig']['autoaddr_in']		= pfb_filter($_POST['autoaddr_in'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl')		?: '';
			$pfb['dconfig']['autonot_in']		= pfb_filter($_POST['autonot_in'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl')		?: '';
			$pfb['dconfig']['aliasaddr_in']		= $_POST['aliasaddr_in']						?: '';
			$pfb['dconfig']['autoproto_in']		= $_POST['autoproto_in']						?: 'any';
			$pfb['dconfig']['agateway_in']		= $_POST['agateway_in']							?: 'default';

			$pfb['dconfig']['autoaddrnot_out']	= pfb_filter($_POST['autoaddrnot_out'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl')	?: '';
			$pfb['dconfig']['autoports_out']	= pfb_filter($_POST['autoports_out'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl')	?: '';
			$pfb['dconfig']['aliasports_out']	= $_POST['aliasports_out']						?: '';
			$pfb['dconfig']['autoaddr_out']		= pfb_filter($_POST['autoaddr_out'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl')	?: '';
			$pfb['dconfig']['autonot_out']		= pfb_filter($_POST['autonot_out'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl')		?: '';
			$pfb['dconfig']['aliasaddr_out']	= $_POST['aliasaddr_out']						?: '';
			$pfb['dconfig']['autoproto_out']	= $_POST['autoproto_out']						?: 'any';
			$pfb['dconfig']['agateway_out']		= $_POST['agateway_out']						?: 'default';

			$pfb['dconfig']['top1m_enable']		= pfb_filter($_POST['top1m_enable'], PFB_FILTER_ON_OFF, 'dnsbl')	?: '';

			// issue #1723: already sanitized by the ingestion prologue above -- plain encode.
			$pfb['dconfig']['pfb_regex_list']	= base64_encode($_POST['pfb_regex_list'] ?? '');
			$pfb['dconfig']['pfb_noaaaa_list']	= base64_encode($_POST['pfb_noaaaa_list'] ?? '');
			$pfb['dconfig']['pfb_gp_bypass_list']	= base64_encode($_POST['pfb_gp_bypass_list'] ?? '');
			$pfb['dconfig']['whitelist']		= base64_encode($_POST['whitelist'] ?? '');
			$pfb['dconfig']['tld_wildcard_exclusion']		= base64_encode($_POST['tld_wildcard_exclusion'] ?? '');
			$pfb['dconfig']['tld_wildcard_blacklist']		= base64_encode($_POST['tld_wildcard_blacklist'] ?? '');

			// A provider/auth identity change invalidates only the download detector
			// baseline. Keep the active source and derived whitelist available until
			// the replacement download has been validated and published.
			$pfb_top1m_provider = $_POST['top1m_source'] ?: 'tranco';
			$pfb_top1m_identity_changed =
				(($pfb['dconfig']['top1m_source'] ?? '') !== $pfb_top1m_provider) ||
				($pfb_top1m_token_post !== '' &&
					($pfb['dconfig']['top1m_token'] ?? '') !== $pfb_top1m_token_post);
			$pfb['dconfig']['top1m_source'] = $pfb_top1m_provider;

			// top1m_token: masked/write-only -- blank means "keep the existing stored
			// token" (never clear it via a blank submit, e.g. an unrelated settings
			// save re-posting this always-blank-rendered field). $pfb['dconfig']
			// ['top1m_token'] already holds the current stored value from the
			// readSection() at the top of this page, so skip the assignment entirely
			// when the field was left blank.
			if ($pfb_top1m_token_post !== '') {
				$pfb['dconfig']['top1m_token'] = $pfb_top1m_token_post;
			}
			if ($pfb_top1m_identity_changed) {
				pfb_top1m_invalidate_baseline("{$pfb['dbdir']}/top-1m.csv.zip");
			}

			$pfb['dconfig']['top1m_count']		= $_POST['top1m_count']							?: '1000';
			$pfb['dconfig']['top1m_inclusion']	= implode(',', (array) $_POST['top1m_inclusion']);
			$pfb_top1m_settings_after = array(
				'enable'   => $pfb['dconfig']['top1m_enable'],
				'count'    => $pfb['dconfig']['top1m_count'],
				'tld'      => $pfb['dconfig']['top1m_inclusion'],
				'provider' => $pfb['dconfig']['top1m_source'],
			);
			if (pfb_top1m_settings_reprocess($pfb_top1m_settings_before, $pfb_top1m_settings_after)) {
				touch("{$pfb['dbdir']}/top-1m.update");
			}
			// 0 (unlimited) is meaningful; ctype_digit keeps "0", else fall back to the default.
			$pfb['dconfig']['pfb_py_cache_max']	= ctype_digit((string) $_POST['pfb_py_cache_max']) ? (string) ((int) $_POST['pfb_py_cache_max']) : '10000';


			if (!$pfb_auto) {
				$pfb['dconfig']['pfb_dnsvip4']	= $_POST['pfb_dnsvip4']							?: '';
			}
			$pfb['dconfig']['dnsbl_interface']	= $_POST['dnsbl_interface']						?: 'lo0';

			// Replace DNSBL active blocked webpage with user selection
			if ($dnsbl_webpage || !file_exists('/usr/local/www/pfblockerng/www/dnsbl_active.php')) {
				@copy("/usr/local/www/pfblockerng/www/{$pfb['dconfig']['dnsbl_webpage']}", '/usr/local/www/pfblockerng/www/dnsbl_active.php');
			}

			// Flush the bulk DNSBL settings snapshot FIRST. writeSection() replaces the whole
			// pfblockerngdnsblsettings/config/0 section with $pfb['dconfig'], which does NOT carry
			// the per-field registered keys written via PfbConfig::write() below (dnsbl_redir*,
			// dnsbl_dot_block*). Those leaf writes MUST therefore follow the section write — done
			// before it they are silently clobbered before write_config() flushes, so enabling DNS
			// Redirect or DoT/DoQ Block never persists. (safesearch_doh* target a different section.)
			PfbConfig::writeSection('installedpackages/pfblockerngdnsblsettings/config/0', $pfb['dconfig']);
			PfbConfig::write('dnsbl/pfb_psl_include_private', $psl_include_private);
			PfbConfig::write('dnsbl/pfb_psl_allow_private', $psl_allow_private);
			PfbConfig::write('dnsbl/pfb_psl_feed_private_policy', $psl_feed_private_policy);
			PfbConfig::write('dnsbl/pfb_psl_feed_icann_policy', $psl_feed_icann_policy);

			// Save DoH/DoT/DoQ blocking fields via gateway (registered keys in pfblockerngsafesearch)
			PfbConfig::write('ss/safesearch_doh', $_POST['safesearch_doh'] ?: 'Disable');
			PfbConfig::write('ss/safesearch_doh_list', implode(',', (array)$_POST['safesearch_doh_list']) ?: '');

			// [ ADR-36 ] Save DNS Redirect fields via gateway (registered keys in pfblockerngdnsblsettings)
			PfbConfig::write('dnsbl/dnsbl_redir', pfb_filter($_POST['dnsbl_redir'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl') ?: '');
			PfbConfig::write('dnsbl/dnsbl_redir_int', implode(',', $redir_ifaces_raw));
			PfbConfig::write('dnsbl/dnsbl_redir_exclude', $redir_alias_raw);

			// [ ADR-37 ] Save DoT/DoQ Block fields via gateway (registered keys in pfblockerngdnsblsettings)
			PfbConfig::write('dnsbl/dnsbl_dot_block', pfb_filter($_POST['dnsbl_dot_block'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl') ?: '');
			PfbConfig::write('dnsbl/dnsbl_dot_block_int', implode(',', $dot_block_ifaces_raw));
			PfbConfig::write('dnsbl/dnsbl_dot_block_exclude', $dot_block_alias_raw);
			PfbConfig::write('dnsbl/dnsbl_dot_block_action', pfb_dot_block_action($dot_block_action_raw));
			PfbConfig::write('dnsbl/dnsbl_dot_block_floating', pfb_filter($_POST['dnsbl_dot_block_floating'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl') ?: '');

			write_config('[pfBlockerNG] save DNSBL settings');
			pfb_mark_pending_changes();	// applies on the next Update, not on save
			if ($savemsg) {
				header("Location: /pfblockerng/pfblockerng_dnsbl.php?savemsg={$savemsg}");
			} else {
				header('Location: /pfblockerng/pfblockerng_dnsbl.php');
			}
			exit;
		}
		else {
			$pconfig = $_POST;	// Restore $_POST data on input errors
		}
	}
}

// TLD data. Defined before the GUI block so $tld_total is in scope for the
// TLD Allow help text below -- the reorganisation moved that control above
// where these arrays used to sit, which made the count unrenderable there.

$tld_list = array();

$tld_list['gTLD'] = array(
'abogado' => '(es) ABOGADO',
'abudhabi' => '(asia) SABUDHABI',
'academy' => 'ACADEMY',
'accountant' => 'ACCOUNTANT',
'accountants' => 'ACCOUNTANTS',
'actor' => 'ACTOR',
'ads' => 'ADS',
'adult' => 'ADULT',
'aero' => '(s) AERO',
'africa' => '(af) AFRICA',
'agency' => 'AGENCY',
'airforce' => 'AIRFORCE',
'alsace' => '(eu) ALSACE',
'amazon' => 'AMAZON',
'amsterdam' => '(eu) AMSTERDAM',
'analytics' => 'ANALYTICS',
'anquan' => 'ANQUAN (QIHOO-Security)',
'apartments' => 'APARTMENTS',
'app' => '(s) APP',
'arab' => '(asia) ARAB',
'archi' => 'ARCHI',
'army' => 'ARMY',
'arpa' => 'ARPA',
'art' => 'ART',
'arte' => '(fr) ARTE',
'asia' => '(s) ASIA',
'associates' => 'ASSOCIATES',
'attorney' => 'ATTORNEY',
'auction' => 'AUCTION',
'audible' => 'AUDIBLE',
'audio' => 'AUDIO',
'author' => 'AUTHOR',
'auto' => 'AUTO',
'autos' => 'AUTOS',
'aws' => 'AWS',
'baby' => 'BABY',
'band' => 'BAND',
'bank' => 'BANK',
'bar' => 'BAR',
'barcelona' => '(eu) BARCELONA',
'barefoot' => 'BAREFOOT',
'bargains' => 'BARGAINS',
'baseball' => 'BASEBALL',
'bayern' => '(eu) BAYERN',
'bcn' => '(eu) BCN',
'beauty' => 'BEAUTY',
'beer' => 'BEER',
'berlin' => '(eu) BERLIN',
'best' => 'BEST',
'bestbuy' => 'BESTBUY',
'bet' => 'BET',
'bible' => 'BIBLE',
'bid' => '( ! ) BID',
'bike' => 'BIKE',
'bingo' => 'BINGO',
'bio' => 'BIO',
'biz' => 'BIZ',
'black' => 'BLACK',
'blackfriday' => 'BLACKFRIDAY',
'blockbuster' => 'BLOCKBUSTER',
'blog' => 'BLOG',
'blue' => 'BLUE',
'boats' => 'BOATS',
'bom' => 'BOM',
'boo' => 'BOO',
'book' => 'BOOK',
'boston' => '(na) BOSTON',
'bot' => 'BOT',
'boutique' => 'BOUTIQUE',
'box' => 'BOX',
'broadway' => 'BROADWAY',
'brussels' => '(eu) BRUSSELS',
'build' => 'BUILD',
'builders' => 'BUILDERS',
'business' => 'BUSINESS',
'buy' => 'BUY',
'buzz' => 'BUZZ',
'bzh' => '(af) BZH',
'cab' => 'CAB',
'cafe' => 'CAFE',
'call' => 'CALL',
'cam' => 'CAM',
'camera' => 'CAMERA',
'camp' => 'CAMP',
'capetown' => '(af) CAPETOWN',
'capital' => 'CAPITAL',
'car' => 'CAR',
'cards' => 'CARDS',
'care' => 'CARE',
'career' => 'CAREER',
'careers' => 'CAREERS',
'cars' => 'CARS',
'casa' => '(it) CASA',
'case' => 'CASE',
'cash' => 'CASH',
'casino' => 'CASINO',
'cat' => '(s) CAT',
'catering' => 'CATERING',
'catholic' => 'CATHOLIC',
'center' => 'CENTER',
'ceo' => 'CEO',
'cfd' => 'CFD',
'channel' => 'CHANNEL',
'charity' => 'CHARITY',
'chat' => 'CHAT',
'cheap' => 'CHEAP',
'christmas' => 'CHRISTMAS',
'church' => 'CHURCH',
'cipriani' => 'CIPRIANI',
'circle' => 'CIRCLE',
'city' => 'CITY',
'claims' => 'CLAIMS',
'cleaning' => 'CLEANING',
'click' => 'CLICK',
'clinic' => 'CLINIC',
'clinique' => '(fr) CLINIQUE',
'clothing' => 'CLOTHING',
'cloud' => 'CLOUD',
'club' => 'CLUB',
'coach' => 'COACH',
'codes' => 'CODES',
'coffee' => 'COFFEE',
'college' => 'COLLEGE',
'cologne' => '(eu) COLOGNE',
'com' => 'COM*',
'community' => 'COMMUNITY',
'company' => 'COMPANY',
'compare' => 'COMPARE',
'computer' => 'COMPUTER',
'condos' => 'CONDOS',
'construction' => 'CONSTRUCTION',
'consulting' => 'CONSULTING',
'contact' => 'CONTACT',
'contractors' => 'CONTRACTORS',
'cooking' => 'COOKING',
'cool' => 'COOL',
'coop' => '(s) COOP',
'corsica' => '(eu) CORSICA',
'country' => 'COUNTRY',
'coupon' => 'COUPON',
'coupons' => 'COUPONS',
'courses' => 'COURSES',
'cpa' => 'CPA',
'credit' => 'CREDIT',
'creditcard' => 'CREDITCARD',
'cricket' => 'CRICKET',
'cruise' => 'CRUISE',
'cruises' => 'CRUISES',
'cymru' => '(eu) CYMRU',
'dad' => 'DAD',
'dance' => 'DANCE',
'data' => 'DATA',
'date' => '( ! ) DATE',
'dating' => 'DATING',
'day' => 'DAY',
'dds' => 'DDS (Dr. Dental Surgery)',
'deal' => 'DEAL',
'deals' => 'DEALS',
'degree' => 'DEGREE',
'delivery' => 'DELIVERY',
'democrat' => 'DEMOCRAT',
'dental' => 'DENTAL',
'dentist' => 'DENTIST',
'desi' => 'DESI',
'design' => 'DESIGN',
'dev' => 'DEV',
'diamonds' => 'DIAMONDS',
'diet' => 'DIET',
'digital' => 'DIGITAL',
'direct' => 'DIRECT',
'directory' => 'DIRECTORY',
'discount' => 'DISCOUNT',
'diy' => 'DIY',
'docs' => 'DOCS',
'doctor' => 'DOCTOR',
'dog' => 'DOG',
'domains' => 'DOMAINS',
'dot' => 'DOT',
'download' => 'DOWNLOAD',
'drive' => 'DRIVE',
'dubai' => '(asia) DUBAI',
'durban' => '(af) DURBAN',
'earth' => 'EARTH',
'eat' => 'EAT',
'eco' => 'ECO',
'edu' => 'EDU*',
'education' => 'EDUCATION',
'email' => 'EMAIL',
'energy' => 'ENERGY',
'engineer' => 'ENGINEER',
'engineering' => 'ENGINEERING',
'enterprises' => 'ENTERPRISES',
'equipment' => 'EQUIPMENT',
'esq' => 'ESQ',
'estate' => 'ESTATE',
'eus' => '(eu) EUS',
'events' => 'EVENTS',
'exchange' => 'EXCHANGE',
'expert' => 'EXPERT',
'exposed' => 'EXPOSED',
'express' => 'EXPRESS',
'fail' => 'FAIL',
'faith' => 'FAITH',
'family' => 'FAMILY',
'fan' => 'FAN',
'fans' => 'FANS',
'farm' => 'FARM',
'fashion' => 'FASHION',
'fast' => 'FAST',
'feedback' => 'FEEDBACK',
'film' => 'FILM',
'final' => 'FINAL',
'finance' => 'FINANCE',
'financial' => 'FINANCIAL',
'fire' => 'FIRE',
'fish' => 'FISH',
'fishing' => 'FISHING',
'fit' => 'FIT',
'fitness' => 'FITNESS',
'flights' => 'FLIGHTS',
'florist' => 'FLORIST',
'flowers' => 'FLOWERS',
'fly' => 'FLY',
'foo' => 'FOO',
'food' => 'FOOD',
'football' => 'FOOTBALL',
'forum' => 'FORUM',
'foundation' => 'FOUNDATION',
'free' => 'FREE',
'frl' => '(eu) FRL',
'fun' => 'FUN',
'fund' => 'FUND',
'furniture' => 'FURNITURE',
'futbol' => '(es) FUTBOL',
'fyi' => 'FYI',
'gal' => '(eu) GAL',
'gallery' => 'GALLERY',
'game' => 'GAME',
'games' => 'GAMES',
'garden' => 'GARDEN',
'gay' => 'GAY',
'gdn' => '( ! ) GDN',
'gent' => '(eu) GENT',
'gift' => 'GIFT',
'gifts' => 'GIFTS',
'gives' => 'GIVES',
'glass' => 'GLASS',
'global' => 'GLOBAL',
'gmbh' => '(de) GMBH',
'gold' => 'GOLD',
'golf' => 'GOLF',
'gop' => 'GOP',
'got' => 'GOT (Amazon)',
'gov' => 'GOV',
'graphics' => 'GRAPHICS',
'gratis' => '(es) GRATIS',
'green' => 'GREEN',
'gripe' => 'GRIPE',
'grocery' => 'GROCERY',
'group' => 'GROUP',
'guide' => 'GUIDE',
'guitars' => 'GUITARS',
'guru' => 'GURU',
'hair' => 'HAIR',
'hamburg' => '(eu) HAMBURG',
'hangout' => 'HANGOUT',
'haus' => '(de) HAUS',
'health' => 'HEALTH',
'healthcare' => 'HEALTHCARE',
'help' => 'HELP',
'helsinki' => '(eu) HELSINKI',
'here' => 'HERE',
'hiphop' => 'HIPHOP',
'hiv' => 'HIV',
'hockey' => 'HOCKEY',
'holdings' => 'HOLDINGS',
'holiday' => 'HOLIDAY',
'homegoods' => 'HOMEGOODS',
'homes' => 'HOMES',
'homesense' => 'HOMESENSE',
'horse' => 'HORSE',
'hospital' => 'HOSPITAL',
'host' => 'HOST',
'hosting' => 'HOSTING',
'hot' => 'HOT',
'hotels' => 'HOTELS',
'house' => 'HOUSE',
'how' => 'HOW',
'ice' => 'ICE',
'icu' => 'ICU',
'imamat' => 'IMAMAT (Fondation Aga Khan)',
'immo' => '(it) IMMO',
'immobilien' => '(de) IMMOBILIEN',
'inc' => 'INC (Uniregistry)',
'industries' => 'INDUSTRIES',
'info' => 'INFO',
'ing' => 'ING',
'ink' => 'INK',
'institute' => 'INSTITUTE',
'insurance' => 'INSURANCE',
'insure' => 'INSURE',
'int' => '(s) INT',
'international' => 'INTERNATIONAL',
'investments' => 'INVESTMENTS',
'irish' => '(eu) IRISH',
'ismaili' => 'ISMAILI (Fondation Aga Khan)',
'ist' => '(eu) IST',
'istanbul' => '(eu) ISTANBUL',
'jetzt' => '(de) JETZT',
'jewelry' => 'JEWELRY',
'jobs' => '(s) JOBS',
'joburg' => '(af) JOBURG',
'jot' => 'JOT (Amazon)',
'joy' => 'JOY',
'juegos' => '(es) JUEGOS',
'kaufen' => '(de) KAUFEN',
'kids' => 'KIDS',
'kim' => 'KIM',
'kitchen' => 'KITCHEN',
'kiwi' => '(oc) KIWI',
'koeln' => '(eu) KOELN',
'kosher' => 'KOSHER (Kosher Marketing)',
'kpn' => 'KPN (KPN)',
'krd' => '(asia) KRD',
'kyoto' => '(asia) KYOTO',
'land' => 'LAND',
'lat' => '(s) LAT',
'latino' => 'LATINO',
'law' => 'LAW',
'lawyer' => 'LAWYER',
'lease' => 'LEASE',
'legal' => 'LEGAL',
'lgbt' => 'LGBT',
'life' => 'LIFE',
'lifeinsurance' => 'LIFEINSURANCE',
'lighting' => 'LIGHTING',
'like' => 'LIKE',
'limited' => 'LIMITED',
'limo' => 'LIMO',
'link' => 'LINK',
'live' => 'LIVE',
'living' => 'LIVING',
'llc' => 'LLC',
'llp' => 'LLP',
'loan' => 'LOAN',
'loans' => '( ! ) LOANS',
'locker' => 'LOCKER',
'lol' => 'LOL',
'london' => '(eu) LONDON',
'lotto' => 'LOTTO',
'love' => 'LOVE (Merchant Law Group)',
'ltd' => 'LTD',
'ltda' => '(es) LTDA',
'luxe' => '(fr) LUXE',
'luxury' => 'LUXURY',
'madrid' => '(eu) MADRID',
'maison' => '(fr) MAISON',
'makeup' => 'MAKEUP',
'management' => 'MANAGEMENT',
'map' => 'MAP',
'market' => 'MARKET',
'marketing' => 'MARKETING',
'markets' => 'MARKETS',
'mba' => 'MBA',
'med' => 'MED',
'media' => 'MEDIA',
'meet' => 'MEET',
'melbourne' => '(oc) MELBOURNE',
'meme' => 'MEME',
'memorial' => 'MEMORIAL',
'men' => 'MEN',
'menu' => 'MENU',
'merck' => 'MERCK',
'miami' => '(na) MIAMI',
'mil' => 'MIL',
'mint' => 'MINT',
'mls' => 'MLS (Canada Real Estate Assoc.)',
'mobi' => '(s) MOBI',
'mobile' => 'MOBILE',
'moda' => '(it) MODA',
'moe' => 'MOE',
'moi' => '(fr) MOI',
'mom' => 'MOM',
'money' => 'MONEY',
'mortgage' => 'MORTGAGE',
'moscow' => '(eu) MOSCOW',
'motorcycles' => 'MOTORCYCLES',
'mov' => 'MOV',
'movie' => 'MOVIE',
'museum' => '(s) MUSEUM',
'music' => 'MUSIC',
'nagoya' => '(asia) NAGOYA',
'name' => 'NAME',
'navy' => 'NAVY',
'net' => 'NET*',
'network' => 'NETWORK',
'new' => 'NEW',
'news' => 'NEWS',
'ngo' => 'NGO',
'ninja' => 'NINJA',
'now' => 'NOW',
'nowruz' => 'NOWRUZ (Asia Green IT)',
'nrw' => '(eu) NRW',
'nyc' => '(na) NYC',
'observer' => 'OBSERVER',
'okinawa' => '(asia) OKINAWA',
'one' => 'ONE',
'ong' => 'ONG',
'onl' => 'ONL',
'online' => 'ONLINE',
'ooo' => 'OOO',
'open' => 'OPEN',
'org' => 'ORG*',
'organic' => 'ORGANIC',
'origins' => 'ORIGINS',
'osaka' => '(asia) OSAKA',
'page' => 'PAGE',
'paris' => '(eu) PARIS',
'pars' => 'PARS (Asia Green)',
'partners' => 'PARTNERS',
'parts' => 'PARTS',
'party' => 'PARTY',
'pay' => 'PAY',
'pet' => 'PET',
'pharmacy' => 'PHARMACY',
'phd' => 'PHD (Charleston Road Registry)',
'phone' => 'PHONE',
'photo' => 'PHOTO',
'photography' => 'PHOTOGRAPHY',
'photos' => 'PHOTOS',
'physio' => 'PHYSIO',
'pics' => 'PICS',
'pictures' => 'PICTURES',
'pid' => 'PID',
'pin' => 'PIN',
'pink' => 'PINK',
'pizza' => 'PIZZA',
'place' => 'PLACE',
'plumbing' => 'PLUMBING',
'plus' => 'PLUS',
'poker' => 'POKER',
'porn' => 'PORN',
'post' => '(s) POST',
'press' => 'PRESS',
'prime' => 'PRIME',
'pro' => 'PRO',
'productions' => 'PRODUCTIONS',
'prof' => 'PROF',
'promo' => 'PROMO',
'properties' => 'PROPERTIES',
'property' => 'PROPERTY',
'protection' => 'PROTECTION',
'pub' => 'PUB',
'qpon' => 'QPON',
'quebec' => '(na) QUEBEC',
'racing' => 'RACING',
'radio' => 'RADIO',
'read' => 'READ',
'realestate' => 'REALESTATE',
'realtor' => 'REALTOR',
'realty' => 'REALTY',
'recipes' => 'RECIPES',
'red' => 'RED',
'rehab' => 'REHAB',
'reise' => '(de) REISE',
'reisen' => '(de) REISEN',
'reit' => 'REIT',
'ren' => 'REN',
'rent' => 'RENT',
'rentals' => 'RENTALS',
'repair' => 'REPAIR',
'report' => 'REPORT',
'republican' => 'REPUBLICAN',
'rest' => 'REST',
'restaurant' => 'RESTAURANT',
'review' => 'REVIEW',
'reviews' => 'REVIEWS',
'rich' => 'RICH',
'ril' => 'RIL (Reliance Industries)',
'rio' => '(s) RIO',
'rip' => 'RIP',
'rocks' => 'ROCKS',
'rodeo' => 'RODEO',
'room' => 'ROOM',
'rsvp' => '(fr) RSVP',
'rugby' => 'RUGBY',
'ruhr' => '(eu) RUHR',
'run' => 'RUN',
'ryukyu' => '(asia) RYUKYU',
'saarland' => '(eu) SAARLAND',
'safe' => 'SAFE',
'sale' => 'SALE',
'salon' => 'SALON (Outer Orchard LLC)',
'samsclub' => 'SAMSCLUB (Walmart)',
'sarl' => 'SARL',
'save' => 'SAVE',
'scholarships' => 'SCHOLARSHIPS',
'school' => 'SCHOOL',
'schule' => '(de) SCHULE',
'science' => 'SCIENCE',
'scot' => '(eu) SCOT',
'search' => 'SEARCH',
'secure' => 'SECURE',
'security' => 'SECURITY',
'select' => 'SELECT',
'services' => 'SERVICES',
'sex' => 'SEX',
'sexy' => 'SEXY',
'shia' => 'SHIA (Asia Green)',
'shiksha' => 'SHIKSHA',
'shoes' => 'SHOES',
'shop' => 'SHOP',
'shopping' => 'SHOPPING',
'shouji' => '(cn) SHOUJI',
'show' => 'SHOW',
'silk' => 'SILK',
'singles' => 'SINGLES',
'site' => 'SITE',
'ski' => 'SKI',
'skin' => 'SKIN',
'sling' => 'SLING',
'smile' => 'SMILE',
'soccer' => 'SOCCER',
'social' => 'SOCIAL',
'software' => 'SOFTWARE',
'solar' => 'SOLAR',
'solutions' => 'SOLUTIONS',
'song' => 'SONG',
'soy' => '(es) SOY',
'spa' => 'SPA',
'space' => 'SPACE',
'sport' => 'SPORT (Global Assoc. of Sports Fed.)',
'spot' => 'SPOT',
'srl' => 'SRL (InterNetx)',
'stockholm' => '(eu) STOCKHOLM',
'storage' => 'STORAGE',
'store' => 'STORE',
'stream' => 'STREAM',
'studio' => 'STUDIO',
'study' => 'STUDY',
'style' => 'STYLE',
'sucks' => 'SUCKS',
'supplies' => 'SUPPLIES',
'supply' => 'SUPPLY',
'support' => 'SUPPORT',
'surf' => 'SURF',
'surgery' => 'SURGERY',
'swiss' => '(eu) SWISS',
'sydney' => '(oc) SYDNEY',
'systems' => 'SYSTEMS',
'taipei' => '(asia) TAIPEI',
'talk' => 'TALK',
'tatar' => '(asia) TATAR',
'tattoo' => 'TATTOO',
'tax' => 'TAX',
'taxi' => 'TAXI',
'team' => 'TEAM',
'tech' => 'TECH',
'technology' => 'TECHNOLOGY',
'tel' => '(s) TEL',
'tennis' => 'TENNIS',
'theater' => 'THEATER',
'theatre' => 'THEATRE',
'tiaa' => 'TIAA (Teachers Insurance & Assoc)',
'tickets' => 'TICKETS',
'tienda' => '(es) TIENDA',
'tips' => 'TIPS',
'tires' => 'TIRES',
'tirol' => '(eu) TIROL',
'tjmaxx' => 'TJMAXX (TJX Companies)',
'tkmaxx' => 'TKMAXX (TJX Companies)',
'today' => 'TODAY',
'tokyo' => '( ! ) (asia) TOKYO',
'tools' => 'TOOLS',
'top' => 'TOP',
'tours' => 'TOURS',
'town' => 'TOWN',
'toys' => 'TOYS',
'trade' => 'TRADE',
'trading' => 'TRADING',
'training' => 'TRAINING',
'travel' => '(s) TRAVEL',
'travelersinsurance' => 'TRAVELERSINSURANCE',
'trust' => 'TRUST',
'tube' => 'TUBE',
'tunes' => 'TUNES',
'tushu' => '(cn) TUSHU',
'ubank' => 'UBANK (Bank Of Australia)',
'university' => 'UNIVERSITY',
'uno' => '(es) UNO',
'vacations' => 'VACATIONS',
'vana' => 'VANA (Lifetyle Domain Holdings)',
'vegas' => '(na) VEGAS',
'ventures' => 'VENTURES',
'versicherung' => '(de) VERSICHERUNG',
'vet' => 'VET',
'viajes' => '(es) VIAJES',
'video' => 'VIDEO',
'villas' => 'VILLAS',
'vin' => 'VIN',
'vip' => 'VIP',
'vision' => 'VISION',
'viva' => 'VIVA (Saudi Tele - CentralNic)',
'vlaanderen' => '(eu) VLAANDEREN',
'vodka' => 'VODKA',
'vote' => 'VOTE',
'voting' => 'VOTING',
'voto' => '(it) VOTO',
'voyage' => 'VOYAGE',
'wales' => '(eu) WALES',
'wang' => 'WANG',
'wanggou' => '(cn) WANGGOU',
'watch' => 'WATCH',
'watches' => 'WATCHES',
'weather' => 'WEATHER',
'web' => 'WEB',
'webcam' => 'WEBCAM',
'website' => 'WEBSITE',
'wed' => 'WED',
'wedding' => 'WEDDING',
'weibo' => '(cn) WEIBO',
'whoswho' => 'WHOSWHO',
'wien' => '(eu) WIEN',
'wiki' => 'WIKI',
'win' => 'WIN',
'wine' => 'WINE',
'winners' => 'WINNERS',
'work' => '( ! ) WORK',
'works' => 'WORKS',
'world' => 'WORLD',
'wow' => 'WOW',
'wtf' => 'WTF',
'xihuan' => '(de) XIHUAN',
'xin' => 'XIN (HiChina)',
'xxx' => '(s) XXX',
'xyz' => 'XYZ',
'yachts' => 'YACHTS',
'yoga' => 'YOGA',
'yokohama' => '(asia) YOKOHAMA',
'you' => 'YOU',
'yun' => 'YUN (QIHOO-Security)',
'zero' => 'ZERO',
'zone' => 'ZONE',
'zuerich' => '(eu) ZUERICH'
);

$tld_list['ccTLD'] = array(
'ac' => 'AC (Ascention Island)',
'ad' => 'AD (Andorra)',
'ae' => 'AE (United Arab Emirates)',
'af' => 'AF (Afghanistan)',
'ag' => 'AG (Antigua and Barbuda)',
'ai' => 'AI (Anguilla)',
'al' => 'AL (Albania)',
'am' => 'AM (Armenia)',
'ao' => 'AO (Angola)',
'aq' => 'AQ (Antarctica)',
'ar' => 'AR (Argentina)',
'as' => 'AS (American Samoa)',
'at' => 'AT (Austria)',
'au' => 'AU (Australia)',
'aw' => 'AW (Aruba)',
'ax' => 'AX (Aland Islands)',
'az' => 'AZ (Azerbaijan)',
'ba' => 'BA (Bosnia and Herzegovina)',
'bb' => 'BB (Barbados)',
'bd' => 'BD (Bangladesh)',
'be' => 'BE (Belgium)',
'bf' => 'BF (Burkina Faso)',
'bg' => 'BG (Bulgaria)',
'bh' => 'BH (Bahrain)',
'bi' => 'BI (Burundi)',
'bj' => 'BJ (Benin)',
'bm' => 'BM (Bermuda)',
'bn' => 'BN (Brunei)',
'bo' => 'BO (Bolivia)',
'br' => 'BR (Brazil)',
'bs' => 'BS (Bahamas)',
'bt' => 'BT (Bhutan)',
'bv' => 'BV (Bouvet Island)',
'bw' => 'BW (Botswana)',
'by' => 'BY (Belarus)',
'bz' => 'BZ (Belize)',
'ca' => 'CA (Canada)',
'cc' => 'CC (Cocos Islands)',
'cd' => 'CD (Democratic Republic of the Congo)',
'cf' => '( ! ) CF (Central African Republic)',
'cg' => 'CG (Republic of the Congo)',
'ch' => 'CH* (Switzerland)',
'ci' => 'CI (Ivory Coast)',
'ck' => 'CK (Cook Islands)',
'cl' => 'CL (Chile)',
'cm' => 'CM (Cameroon)',
'cn' => 'CN (China)',
'co' => 'CO* (Colombia)',
'cr' => 'CR (Costa Rica)',
'cu' => 'CU (Cuba)',
'cv' => 'CV (Cape Verde)',
'cw' => 'CW (Curacao)',
'cx' => 'CX (Christmas Island)',
'cy' => 'CY (Cyprus)',
'cz' => 'CZ (Czechia)',
'de' => 'DE* (Germany)',
'dj' => 'DJ (Djibouti)',
'dk' => 'DK (Denmark)',
'dm' => 'DM (Dominica)',
'do' => 'DO (Dominican Republic)',
'dz' => 'DZ (Algeria)',
'ec' => 'EC (Ecuador)',
'ee' => 'EE (Estonia)',
'eg' => 'EG (Egypt)',
'er' => 'ER (Eritrea)',
'es' => 'ES (Spain)',
'et' => 'ET (Ethiopia)',
'eu' => 'EU (European Union)',
'fi' => 'FI (Finland)',
'fj' => 'FJ (Fiji)',
'fk' => 'FK (Falkland Islands)',
'fm' => 'FM (Micronesia)',
'fo' => 'FO (Faroe Islands)',
'fr' => 'FR (France)',
'ga' => '( ! ) GA (Gabon)',
'gb' => 'GB (United Kingdom)',
'gd' => 'GD (Grenada)',
'ge' => 'GE (Georgia)',
'gf' => 'GF (French Guiana)',
'gg' => 'GG (Guernsey)',
'gh' => 'GH (Ghana)',
'gi' => 'GI (Gibraltar)',
'gl' => 'GL (Greenland)',
'gm' => 'GM (Gambia)',
'gn' => 'GN (Guinea)',
'gp' => 'GP (Guadeloupe)',
'gq' => '( ! ) GQ (Equatorial Guinea)',
'gr' => 'GR (Greece)',
'gs' => 'GS (South Georgia and the South Sandwich Islands)',
'gt' => 'GT (Guatemala)',
'gu' => 'GU (Guam)',
'gw' => 'GW (Guinea-Bissau)',
'gy' => 'GY (Guyana)',
'hk' => 'HK (Hong Kong)',
'hm' => 'HM (Heard Island and McDonald Islands)',
'hn' => 'HN (Honduras)',
'hr' => 'HR (Croatia)',
'ht' => 'HT (Haiti)',
'hu' => 'HU (Hungary)',
'id' => 'ID (Indonesia)',
'ie' => 'IE (Ireland)',
'il' => 'IL (Israel)',
'im' => 'IM (Isle of Man)',
'in' => 'IN (India)',
'io' => 'IO* (British Indian Ocean Territory)',
'iq' => 'IQ (Iraq)',
'ir' => 'IR (Iran)',
'is' => 'IS (Iceland)',
'it' => 'IT (Italy)',
'je' => 'JE (Jersey)',
'jm' => 'JM (Jamaica)',
'jo' => 'JO (Jordan)',
'jp' => 'JP (Japan)',
'ke' => 'KE (Kenya)',
'kg' => 'KG (Kyrgyzstan)',
'kh' => 'KH (Cambodia)',
'ki' => 'KI (Kiribati)',
'km' => 'KM (Comoros)',
'kn' => 'KN (Saint Kitts and Nevis)',
'kp' => 'KP (North Korea)',
'kr' => 'KR (South Korea)',
'kw' => 'KW (Kuwait)',
'ky' => 'KY (Cayman Islands)',
'kz' => 'KZ (Kazakhstan)',
'la' => 'LA (Laos)',
'lb' => 'LB (Lebanon)',
'lc' => 'LC (Saint Lucia)',
'li' => 'LI (Liechtenstein)',
'lk' => 'LK (Sri Lanka)',
'lr' => 'LR (Liberia)',
'ls' => 'LS (Lesotho)',
'lt' => 'LT* (Lithuania)',
'lu' => 'LU (Luxembourg)',
'lv' => 'LV (Latvia)',
'ly' => 'LY (Libya)',
'ma' => 'MA (Morocco)',
'mc' => 'MC (Monaco)',
'md' => 'MD (Moldova)',
'me' => 'ME (Montenegro)',
'mg' => 'MG (Madagascar)',
'mh' => 'MH (Marshall Islands)',
'mk' => 'MK (Macedonia)',
'ml' => '( ! ) ML (Mali)',
'mm' => 'MM (Myanmar)',
'mn' => 'MN (Mongolia)',
'mo' => 'MO (Macao)',
'mp' => 'MP (Northern Mariana Islands)',
'mq' => 'MQ (Martinique)',
'mr' => 'MR (Mauritania)',
'ms' => 'MS* (Montserrat)',
'mt' => 'MT (Malta)',
'mu' => 'MU (Mauritius)',
'mv' => 'MV (Maldives)',
'mw' => 'MW (Malawi)',
'mx' => 'MX (Mexico)',
'my' => 'MY (Malaysia)',
'mz' => 'MZ (Mozambique)',
'na' => 'NA (Namibia)',
'nc' => 'NC (New Caledonia)',
'ne' => 'NE (Niger)',
'nf' => 'NF (Norfolk Island)',
'ng' => 'NG (Nigeria)',
'ni' => 'NI (Nicaragua)',
'nl' => 'NL (Netherlands)',
'no' => 'NO (Norway)',
'np' => 'NP (Nepal)',
'nr' => 'NR (Nauru)',
'nu' => 'NU (Niue)',
'nz' => 'NZ (New Zealand)',
'om' => 'OM (Oman)',
'pa' => 'PA (Panama)',
'pe' => 'PE (Peru)',
'pf' => 'PF (French Polynesia)',
'pg' => 'PG (Papua New Guinea)',
'ph' => 'PH (Philippines)',
'pk' => 'PK (Pakistan)',
'pl' => 'PL (Poland)',
'pm' => 'PM (Saint Pierre and Miquelon)',
'pn' => 'PN (Pitcairn)',
'pr' => 'PR (Puerto Rico)',
'ps' => 'PS (Palestinian Territory)',
'pt' => 'PT (Portugal)',
'pw' => 'PW (Palau)',
'py' => 'PY (Paraguay)',
'qa' => 'QA (Qatar)',
're' => 'RE (Reunion)',
'ro' => 'RO (Romania)',
'rs' => 'RS (Serbia)',
'ru' => 'RU (Russia)',
'rw' => 'RW (Rwanda)',
'sa' => 'SA (Saudi Arabia)',
'sb' => 'SB (Solomon Islands)',
'sc' => 'SC (Seychelles)',
'sd' => 'SD (Sudan)',
'se' => 'SE (Sweden)',
'sg' => 'SG (Singapore)',
'sh' => 'SH (Saint Helena)',
'si' => 'SI (Slovenia)',
'sj' => 'SJ (Svalbard and Jan Mayen)',
'sk' => 'SK* (Slovakia)',
'sl' => 'SL (Sierra Leone)',
'sm' => 'SM (San Marino)',
'sn' => 'SN (Senegal)',
'so' => 'SO (Somalia)',
'sr' => 'SR (Suriname)',
'ss' => 'SS (South Sudan)',
'st' => 'ST (Sao Tome and Principe)',
'su' => 'SU',
'sv' => 'SV (El Salvador)',
'sx' => 'SX (Sint Maarten)',
'sy' => 'SY (Syria)',
'sz' => 'SZ (Swaziland)',
'tc' => 'TC (Turks and Caicos Islands)',
'td' => 'TD (Chad)',
'tf' => 'TF (French Southern Territories)',
'tg' => 'TG (Togo)',
'th' => 'TH (Thailand)',
'tj' => 'TJ (Tajikistan)',
'tk' => 'TK (Tokelau)',
'tl' => 'TL (East Timor)',
'tm' => 'TM (Turkmenistan)',
'tn' => 'TN (Tunisia)',
'to' => 'TO* (Tonga)',
'tr' => 'TR (Turkey)',
'tt' => 'TT (Trinidad and Tobago)',
'tv' => 'TV (Tuvalu)',
'tw' => 'TW (Taiwan)',
'tz' => 'TZ (Tanzania)',
'ua' => 'UA (Ukraine)',
'ug' => 'UG (Uganda)',
'uk' => 'UK* (United Kingdom)',
'us' => 'US (United States)',
'uy' => 'UY (Uruguay)',
'uz' => 'UZ (Uzbekistan)',
'va' => 'VA (Vatican)',
'vc' => 'VC (Saint Vincent and the Grenadines)',
've' => 'VE (Venezuela)',
'vg' => 'VG (British Virgin Islands)',
'vi' => 'VI (U.S. Virgin Islands)',
'vn' => 'VN (Vietnam)',
'vu' => 'VU (Vanuatu)',
'wf' => 'WF (Wallis and Futuna)',
'ws' => 'WS (Samoa)',
'ye' => 'YE (Yemen)',
'yt' => 'YT (Mayotte)',
'za' => 'ZA (South Africa)',
'zm' => 'ZM (Zambia)',
'zw' => 'ZW (Zimbabwe)'
);

$tld_list['iTLD'] = array(
'xn--11b4c3d' => 'XN--11B4C3D - कॉम',
'xn--1ck2e1b' => 'XN--1CK2E1B - セール',
'xn--1qqw23a' => '(cc) XN--1QQW23A - 佛山',
'xn--2scrj9c' => '(cc) XN--2SCRJ9C - ಭಾರತ',
'xn--30rr7y' => '(cn) XN--30RR7Y - 慈善',
'xn--3bst00m' => '(cn) XN--3BST00M - 集团',
'xn--3ds443g' => '(cn) XN--3DS443G - 在线',
'xn--3e0b707e' => '(cc) XN--3E0B707E - 한국',
'xn--3hcrj9c' => '(cc) XN--3HCRJ9C - ଭାରତ',
'xn--3pxu8k' => '(cc) XN--3PXU8K - 点看',
'xn--42c2d9a' => 'XN--42C2D9A - คอม',
'xn--45br5cyl' => '(cc) XN--45BR5CYL - ভাৰত',
'xn--45brj9c' => '(cc) XN--45BRJ9C - ভারত',
'xn--45q11c' => '(cn) XN--45Q11C - 八卦',
'xn--4dbrk0ce' => 'XN--4DBRK0CE',
'xn--4gbrim' => '(ar) XN--4GBRIM - موقع',
'xn--54b7fta0cc' => '(cc) XN--54B7FTA0CC - বাংলা',
'xn--55qw42g' => '(cn) XN--55QW42G - 公益',
'xn--55qx5d' => '(cn) XN--55QX5D - 公司',
'xn--5su34j936bgsg' => '(Brand) XN--5SU34J936BGSG - 香格里拉',
'xn--5tzm5g' => '(cn) XN--5TZM5G - 网站',
'xn--6frz82g' => '(Brand) XN--6FRZ82G - 移动',
'xn--6qq986b3xl' => '(cn) XN--6QQ986B3XL - 我爱你',
'xn--80adxhks' => '(cc) XN--80ADXHKS - москва',
'xn--80ao21a' => '(cc) XN--80AO21A - қаз',
'xn--80aqecdr1a' => '(cr) XN--80AQECDR1A - католик',
'xn--80asehdb' => '(cr) XN--80ASEHDB - онлайн',
'xn--80aswg' => '(cr) XN--80ASWG - сайт',
'xn--8y0a063a' => '(Brand) XN--8Y0A063A - 联通',
'xn--90a3ac' => '(cc) XN--90A3AC - срб',
'xn--90ae' => '(cc) XN--90AE - бг',
'xn--90ais' => '(cc) XN--90AIS - бел',
'xn--9dbq2a' => 'XN--9DBQ2A - קום',
'xn--9et52u' => '(cc) XN--9ET52U - 时尚',
'xn--9krt00a' => '(cn) XN--9KRT00A - 微博',
'xn--b4w605ferd' => '(Brand) XN--B4W605FERD - 淡马锡',
'xn--bck1b9a5dre4c' => 'XN--BCK1B9A5DRE4C - ファッション',
'xn--c1avg' => '(cr) XN--C1AVG - орг',
'xn--c2br7g' => 'XN--C2BR7G - नेट',
'xn--cck2b3b' => 'XN--CCK2B3B - ストア',
'xn--cckwcxetd' => 'XN--CCKWCXETD',
'xn--cg4bki' => '(Brand) XN--CG4BKI - 삼성',
'xn--clchc0ea0b2g2a9gcd' => '(cc) XN--CLCHC0EA0B2G2A9GCD - சிங்கப்பூர்',
'xn--czr694b' => '(cn) XN--CZR694B - 商标',
'xn--czrs0t' => '(cc) XN--CZRS0T - 商店',
'xn--czru2d' => '(cn) XN--CZRU2D - 商城',
'xn--d1acj3b' => '(cr) XN--D1ACJ3B - дети',
'xn--d1alf' => '(cc) XN--D1ALF - мкд',
'xn--e1a4c' => '(cc) XN--E1A4C - ею',
'xn--eckvdtc9d' => 'XN--ECKVDTC9D - ポイント',
'xn--efvy88h' => '(cc) XN--EFVY88H - 新闻',
'xn--fct429k' => '(cc) XN--FCT429K - 家電',
'xn--fhbei' => '(ar) XN--FHBEI - كوم',
'xn--fiq228c5hs' => '(cn) XN--FIQ228C5HS - 中文网',
'xn--fiq64b' => '(Brand) XN--FIQ64B - 中信',
'xn--fiqs8s' => '(cc) XN--FIQS8S - 中国',
'xn--fiqz9s' => '(cc) XN--FIQZ9S - 中國',
'xn--fjq720a' => '(cc) XN--FJQ720A - 娱乐',
'xn--flw351e' => '(Brand) XN--FLW351E - 谷歌',
'xn--fpcrj9c3d' => '(cc) XN--FPCRJ9C3D - భారత్',
'xn--fzc2c9e2c' => '(cc) XN--FZC2C9E2C - ලංකා',
'xn--fzys8d69uvgm' => '(Brand) XN--FZYS8D69UVGM - 電訊盈科',
'xn--g2xx48c' => '(cc) XN--G2XX48C - 购物',
'xn--gckr3f0f' => 'XN--GCKR3F0F - クラウド',
'xn--gecrj9c' => '(cc) XN--GECRJ9C - ભારત',
'xn--gk3at1e' => '(cc) XN--GK3AT1E - 通販',
'xn--h2breg3eve' => '(cc) XN--H2BREG3EVE - भारतम्',
'xn--h2brj9c' => '(cc) XN--H2BRJ9C - भारत',
'xn--h2brj9c8c' => '(cc) XN--H2BRJ9C8C - भारोत',
'xn--hxt814e' => '(cc) XN--HXT814E - 网店',
'xn--i1b6b1a6a2e' => 'XN--I1B6B1A6A2E - संगठन',
'xn--imr513n' => '(cc) XN--IMR513N - 餐厅',
'xn--io0a7i' => '(cn) XN--IO0A7I - 网络',
'xn--j1aef' => '(cr) XN--J1AEF - ком',
'xn--j1amh' => '(cc) XN--J1AMH - укр',
'xn--j6w193g' => '(cc) XN--J6W193G - 香港',
'xn--jlq480n2rg' => 'XN--JLQ480N2RG',
'xn--jvr189m' => '(cc) XN--JVR189M - 食品',
'xn--kcrx77d1x4a' => '(Brand) XN--KCRX77D1X4A - 飞利浦',
'xn--kprw13d' => '(cc) XN--KPRW13D - 台湾',
'xn--kpry57d' => '(cc) XN--KPRY57D - 台灣',
'xn--kput3i' => '(cc) XN--KPUT3I - 手机',
'xn--l1acc' => '(cc) XN--L1ACC - мон',
'xn--lgbbat1ad8j' => '(cc) XN--LGBBAT1AD8J - الجزائر',
'xn--mgb9awbf' => '(cc) XN--MGB9AWBF - عمان',
'xn--mgba3a3ejt' => '(Brand) XN--MGBA3A3EJT - ارامكو',
'xn--mgba3a4f16a' => '(cc) XN--MGBA3A4F16A - ایران',
'xn--mgba7c0bbn0a' => '(cc) XN--MGBA7C0BBN0A - العليان',
'xn--mgbaam7a8h' => '(cc) XN--MGBAAM7A8H - امارات',
'xn--mgbab2bd' => '(ar) XN--MGBAB2BD - بازار',
'xn--mgbah1a3hjkrd' => 'XN--MGBAH1A3HJKRD',
'xn--mgbai9azgqp6j' => '(cc) XN--MGBAI9AZGQP6J - پاکستان',
'xn--mgbayh7gpa' => '(cc) XN--MGBAYH7GPA - الاردن',
'xn--mgbbh1a' => '(cc) XN--MGBBH1A - بارت',
'xn--mgbbh1a71e' => '(cc) XN--MGBBH1A71E - بھارت',
'xn--mgbc0a9azcg' => '(cc) XN--MGBC0A9AZCG - المغرب',
'xn--mgbca7dzdo' => '(cc) XN--MGBCA7DZDO - ابوظبي',
'xn--mgbcpq6gpa1a' => 'XN--MGBCPQ6GPA1A',
'xn--mgberp4a5d4ar' => '(cc) XN--MGBERP4A5D4AR - السعودية',
'xn--mgbgu82a' => '(cc) XN--MGBGU82A - ڀارت',
'xn--mgbi4ecexp' => '(ar) XN--MGBI4ECEXP - كاثوليك',
'xn--mgbpl2fh' => '(cc) XN--MGBPL2FH - سودان',
'xn--mgbt3dhd' => '(cc) XN--MGBT3DHD - همراه',
'xn--mgbtx2b' => '(cc) XN--MGBTX2B - عراق',
'xn--mgbx4cd0ab' => '(cc) XN--MGBX4CD0AB - مليسيا',
'xn--mix891f' => '(cc) XN--MIX891F - 澳門',
'xn--mk1bu44c' => 'XN--MK1BU44C - 닷컴',
'xn--mxtq1m' => '(cc) XN--MXTQ1M - 政府',
'xn--ngbc5azd' => '(ar) XN--NGBC5AZD - شبكة',
'xn--ngbe9e0a' => '(ar) XN--NGBE9E0A - بيتك',
'xn--ngbrx' => '(cc) XN--NGBRX - عرب',
'xn--node' => '(cc) XN--NODE - გე',
'xn--nqv7f' => '(cn) XN--NQV7F - 机构',
'xn--nqv7fs00ema' => '(cc) XN--NQV7FS00EMA - 组织机构',
'xn--nyqy26a' => '(cc) XN--NYQY26A - 健康',
'xn--o3cw4h' => '(cc) XN--O3CW4H - ไทย',
'xn--ogbpf8fl' => '(cc) XN--OGBPF8FL - سورية',
'xn--otu796d' => '(cc) XN--OTU796D - 招聘',
'xn--p1acf' => '(cc) XN--P1ACF - рус',
'xn--p1ai' => '(cc) XN--P1AI - рф',
'xn--pgbs0dh' => '(cc) XN--PGBS0DH - تونس',
'xn--pssy2u' => '(cc) XN--PSSY2U - 大拿',
'xn--q7ce6a' => 'XN--Q7CE6A',
'xn--q9jyb4c' => 'XN--Q9JYB4C - みんな',
'xn--qcka1pmc' => '(Brand) XN--QCKA1PMC - グーグル',
'xn--qxa6a' => 'XN--QXA6A',
'xn--qxam' => '(cc) XN--QXAM - ελ',
'xn--rhqv96g' => '(cn) XN--RHQV96G - 世界',
'xn--rovu88b' => '(cc) XN--ROVU88B - 書籍',
'xn--rvc1e0am3e' => '(cc) XN--RVC1E0AM3E - ഭാരതം',
'xn--s9brj9c' => '(cc) XN--S9BRJ9C - ਭਾਰਤ',
'xn--ses554g' => '(cn) XN--SES554G - 网址',
'xn--t60b56a' => 'XN--T60B56A - 닷넷',
'xn--tckwe' => 'XN--TCKWE - コム',
'xn--tiq49xqyj' => '(cc) XN--TIQ49XQYJ - 天主教',
'xn--unup4y' => '(cc) XN--UNUP4Y - 游戏',
'xn--vermgensberater-ctb' => '(Brand) XN--VERMGENSBERATUNGCTB - vermögensberater',
'xn--vermgensberatung-pwb' => '(Brand) XN--VERMGENSBERATUNGPWB - vermögensberatung',
'xn--vhquv' => '(cc) XN--VHQUV - 企业',
'xn--vuq861b' => '(cc) XN--VUQ861B - 信息',
'xn--w4r85el8fhu5dnra' => '(Brand) XN--W4R85EL8FHU5DNRA - 嘉里大酒店',
'xn--w4rs40l' => '(Brand) XN--W4RS40L - 嘉里',
'xn--wgbh1c' => '(cc) XN--WGBH1C - مصر',
'xn--wgbl6a' => '(cc) XN--WGBL6A - قطر',
'xn--xhq521b' => '(cc) XN--XHQ521B - 广东',
'xn--xkc2al3hye2a' => '(cc) XN--XKC2AL3HYE2A - இலங்கை',
'xn--xkc2dl3a5ee0h' => '(cc) XN--XKC2DL3A5EE0H - இந்தியா',
'xn--y9a3aq' => '(cc) XN--Y9A3AQ - հայ',
'xn--yfro4i67o' => '(cc) XN--YFRO4I67O - 新加坡',
'xn--ygbi2ammx' => '(cc) XN--YGBI2AMMX - فلسطين',
'xn--zfr164b' => '(cc) XN--ZFR164B - 政务'
);

$tld_list['bgTLD'] = array(
'ovh' => 'OVH [66,591]',
'forsale' => 'FORSALE [7,807]',
'kred' => 'KRED [6,749]',
'dvag' => 'DVAG [2,519]',
'mma' => 'MMA [1,684]',
'audi' => 'AUDI [1,409]',
'allfinanz' => 'ALLFINANZ [702]',
'broker' => 'BROKER [664]',
'seat' => 'SEAT [659]',
'mini' => 'MINI [653]',
'neustar' => 'NEUSTAR [633]',
'creditunion' => 'CREDITUNION [619]',
'gmx' => 'GMX [473]',
'crs' => 'CRS [397]',
'aco' => 'ACO [293]',
'bnpparibas' => 'BNPPARIBAS [253]',
'basketball' => 'BASKETBALL [230]',
'lamborghini' => 'LAMBORGHINI [203]',
'forex' => 'FOREX (IG Holdings) [198]',
'leclerc' => 'LECLERC (A.C.D. Assoc.) [166]',
'abbott' => 'ABBOTT [162]',
'citic' => 'CITIC [159]',
'bradesco' => 'BRADESCO [147]',
'esurance' => 'ESURANCE [147]',
'nra' => 'NRA [144]',
'weber' => 'WEBER [142]',
'man' => 'MAN [130]',
'bmw' => 'BMW [122]',
'weir' => 'WEIR [120]',
'barclays' => 'BARCLAYS [118]',
'jnj' => 'JNJ (Johnson & Johnson) [107]',
'discover' => 'DISCOVER [101]',
'stada' => 'STADA [86]',
'iselect' => 'ISELECT [86]',
'linde' => 'LINDE [85]',
'goog' => 'GOOG [81]',
'pru' => 'PRU [78]',
'erni' => 'ERNI [76]',
'bloomberg' => 'BLOOMBERG [75]',
'fox' => 'FOX [72]',
'prudential' => 'PRUDENTIAL [71]',
'schwarz' => 'SCHWARZ [67]',
'globo' => 'GLOBO [65]',
'afl' => 'AFL [65]',
'fage' => 'FAGE [61]',
'total' => 'TOTAL [57]',
'edeka' => 'EDEKA [54]',
'monash' => 'MONASH [53]',
'saxo' => 'SAXO [51]',
'cba' => 'CBA [50]',
'microsoft' => 'MICROSOFT [49]',
'pictet' => 'PICTET [48]',
'firmdale' => 'FIRMDALE [48]',
'uol' => 'UOL [45]',
'mango' => 'MANGO [43]',
'auspost' => 'AUSPOST [43]',
'aig' => 'AIG [42]',
'fresenius' => 'FRESENIUS [40]',
'canon' => 'CANON [38]',
'toray' => 'TORAY [38]',
'sener' => 'SENER [36]',
'google' => 'GOOGLE [35]',
'vivo' => 'VIVO [35]',
'yandex' => 'YANDEX [34]',
'sky' => 'SKY [33]',
'xbox' => 'XBOX [33]',
'aquarelle' => 'AQUARELLE [33]',
'mlb' => 'MLB [33]',
'scb' => 'SCB [33]',
'deloitte' => 'DELOITTE [31]',
'cern' => 'CERN [30]',
'liaison' => 'LIAISON [30]',
'shriram' => 'SHRIRAM [28]',
'axa' => 'AXA [28]',
'lidl' => 'LIDL [26]',
'abb' => 'ABB [25]',
'bentley' => 'BENTLEY [25]',
'ikano' => 'IKANO [25]',
'smart' => 'SMART [24]',
'ipiranga' => 'IPIRANGA [24]',
'barclaycard' => 'BARCLAYCARD [24]',
'windows' => 'WINDOWS [24]',
'komatsu' => 'KOMATSU [24]',
'ifm' => 'IFM [23]',
'hyatt' => 'HYATT [23]',
'cisco' => 'CISCO [23]',
'bing' => 'BING [22]',
'latrobe' => 'LATROBE [21]',
'allstate' => 'ALLSTATE [21]',
'philips' => 'PHILIPS [21]',
'hsbc' => 'HSBC [20]',
'sbi' => 'SBI [20]',
'sap' => 'SAP [20]',
'sandvik' => 'SANDVIK [19]',
'hotmail' => 'HOTMAIL [19]',
'csc' => 'CSC [18]',
'williamhill' => 'WILLIAMHILL [18]',
'otsuka' => 'OTSUKA [18]',
'shell' => 'SHELL [18]',
'sncf' => 'SNCF [18]',
'hisamitsu' => 'HISAMITSU [17]',
'amex' => 'AMEX [17]',
'woodside' => 'WOODSIDE [17]',
'praxi' => 'PRAXI [17]',
'sharp' => 'SHARP [16]',
'kfh' => 'KFH [15]',
'marriott' => 'MARRIOTT [15]',
'jprs' => 'JPRS (Japan Registry) [15]',
'teva' => 'TEVA [14]',
'statefarm' => 'STATEFARM [14]',
'schmidt' => 'SCHMIDT [14]',
'walter' => 'WALTER [14]',
'azure' => 'AZURE [13]',
'bbva' => 'BBVA [13]',
'dell' => 'DELL [13]',
'locus' => 'LOCUS [12]',
'hitachi' => 'HITACHI [12]',
'nico' => 'NICO [12]',
'ricoh' => 'RICOH [12]',
'suzuki' => 'SUZUKI [12]',
'jcb' => 'JCB [12]',
'chase' => 'CHASE [11]',
'dhl' => 'DHL [11]',
'sew' => 'SEW [11]',
'emerck' => 'EMERCK [10]',
'abc' => 'ABC [10]',
'lundbeck' => 'LUNDBECK [10]',
'orange' => 'ORANGE [9]',
'bostik' => 'BOSTIK [9]',
'amfam' => 'AMFAM [9]',
'seven' => 'SEVEN [9]',
'gmo' => 'GMO [9]',
'jll' => 'JLL (Jones Lang LaSalle Inc.) [9]',
'ntt' => 'NTT [9]',
'stc' => 'STC [9]',
'dabur' => 'DABUR [9]',
'nec' => 'NEC [9]',
'americanexpress' => 'AMERICANEXPRESS [8]',
'pioneer' => 'PIONEER [8]',
'gle' => 'GLE [8]',
'swatch' => 'SWATCH [8]',
'fujitsu' => 'FUJITSU [8]',
'lancaster' => 'LANCASTER [8]',
'gea' => 'GEA [8]',
'extraspace' => 'EXTRASPACE [8]',
'redstone' => 'REDSTONE [8]',
'maif' => 'MAIF [8]',
'vistaprint' => 'VISTAPRINT [8]',
'toyota' => 'TOYOTA [8]',
'bridgestone' => 'BRIDGESTONE [8]',
'brother' => 'BROTHER [8]',
'jpmorgan' => 'JPMORGAN [8]',
'rexroth' => 'REXROTH [8]',
'vanguard' => 'VANGUARD [8]',
'chintai' => 'CHINTAI [8]',
'dnp' => 'DNP [7]',
'clubmed' => 'CLUBMED [7]',
'sanofi' => 'SANOFI [7]',
'sandvikcoromant' => 'SANDVIKCOROMANT [7]',
'itv' => 'ITV [7]',
'aetna' => 'AETNA [7]',
'sony' => 'SONY [7]',
'intel' => 'INTEL [7]',
'sfr' => 'SFR [7]',
'kpmg' => 'KPMG [7]',
'monster' => 'MONSTER (Monster Worldwide Inc.) [6]',
'sohu' => 'SOHU [6]',
'gucci' => 'GUCCI [6]',
'sca' => 'SCA [6]',
'lipsy' => 'LIPSY [6]',
'skype' => 'SKYPE [6]',
'temasek' => 'TEMASEK [6]',
'wme' => 'WME [6]',
'bugatti' => 'BUGATTI [6]',
'anz' => 'ANZ [6]',
'cfa' => 'CFA [6]',
'honda' => 'HONDA [5]',
'schaeffler' => 'SCHAEFFLER [5]',
'netbank' => 'NETBANK (Bank Of Australia) [5]',
'cuisinella' => 'CUISINELLA [5]',
'softbank' => 'SOFTBANK [5]',
'landrover' => 'LANDROVER [5]',
'mattel' => 'MATTEL [5]',
'next' => 'NEXT (Next PLC) [5]',
'kia' => 'KIA [5]',
'apple' => 'APPLE [5]',
'mtn' => 'MTN [5]',
'onyourside' => 'ONYOURSIDE (Nationwide Mutual Insurance) [5]',
'frogans' => 'FROGANS [5]',
'tatamotors' => 'TATAMOTORS [5]',
'nissan' => 'NISSAN [4]',
'jaguar' => 'JAGUAR [4]',
'commbank' => 'COMMBANK [4]',
'rmit' => 'RMIT [4]',
'citi' => 'CITI [4]',
'northwesternmutual' => 'NORTHWESTERNMUTUAL [4]',
'chanel' => 'CHANEL [4]',
'genting' => 'GENTING [4]',
'java' => 'JAVA [4]',
'bauhaus' => 'BAUHAUS [4]',
'jio' => 'JIO (Affinity Names) [4]',
'volkswagen' => 'VOLKSWAGEN [4]',
'nokia' => 'NOKIA [4]',
'blanco' => 'BLANCO [4]',
'grainger' => 'GRAINGER [4]',
'hermes' => 'HERMES [4]',
'lexus' => 'LEXUS [4]',
'airbus' => 'AIRBUS [4]',
'ferrero' => 'FERRERO [4]',
'zara' => 'ZARA [4]',
'fairwinds' => 'FAIRWINDS [4]',
'gmail' => 'GMAIL [4]',
'everbank' => 'EVERBANK [4]',
'eurovision' => 'EUROVISION [4]',
'ford' => 'FORD [4]',
'lanxess' => 'LANXESS [4]',
'bbc' => 'BBC [3]',
'able' => 'ABLE [3]',
'kinder' => 'KINDER [3]',
'accenture' => 'ACCENTURE [3]',
'panasonic' => 'PANASONIC [3]',
'amica' => 'AMICA [3]',
'lilly' => 'LILLY [3]',
'youtube' => 'YOUTUBE [3]',
'kerrylogistics' => 'KERRYLOGISTICS [3]',
'playstation' => 'PLAYSTATION [3]',
'lupin' => 'LUPIN [3]',
'xerox' => 'XEROX [3]',
'pfizer' => 'PFIZER [3]',
'aarp' => 'AARP [3]',
'ses' => 'SES [3]',
'lixil' => 'LIXIL [3]',
'mit' => 'MIT [3]',
'goo' => 'GOO (NTT Resonant) [3]',
'target' => 'TARGET [3]',
'dupont' => 'DUPONT [3]',
'natura' => 'NATURA [3]',
'bond' => 'BOND [3]',
'nadex' => 'NADEX [3]',
'sbs' => 'SBS [3]',
'guardian' => 'GUARDIAN [3]',
'ieee' => 'IEEE [3]',
'travelers' => 'TRAVELERS [3]',
'obi' => 'OBI [3]',
'nab' => 'NAB (National Australia Bank) [3]',
'mutual' => 'MUTUAL [3]',
'mtr' => 'MTR [3]',
'jmp' => 'JMP (Matrix IP LLC) [3]',
'omega' => 'OMEGA [3]',
'oracle' => 'ORACLE [3]',
'mitsubishi' => 'MITSUBISHI [2]',
'pwc' => 'PWC [2]',
'pohl' => 'POHL [2]',
'quest' => 'QUEST [2]',
'redumbrella' => 'REDUMBRELLA (Affilias) [2]',
'nextdirect' => 'NEXTDIRECT (Next PLC) [2]',
'ping' => 'PING [2]',
'rwe' => 'RWE [2]',
'nfl' => 'NFL [2]',
'nhk' => 'NHK [2]',
'rocher' => 'ROCHER [2]',
'raid' => 'RAID (Johnson & Johnson) [2]',
'nikon' => 'NIKON [2]',
'office' => 'OFFICE [2]',
'olayan' => 'OLAYAN (Crescent Holding GmbH) [2]',
'olayangroup' => 'OLAYANGROUP (Crescent Holding GmbH) [2]',
'sas' => 'SAS (Research IP LLC) [2]',
'aaa' => 'AAA [2]',
'lotte' => 'LOTTE [2]',
'ubs' => 'UBS [2]',
'firestone' => 'FIRESTONE [2]',
'fidelity' => 'FIDELITY [2]',
'lincoln' => 'LINCOLN [2]',
'tmall' => 'TMALL (Alibaba) [2]',
'toshiba' => 'TOSHIBA [2]',
'datsun' => 'DATSUN [2]',
'travelchannel' => 'TRAVELCHANNEL [2]',
'crown' => 'CROWN [2]',
'cookingchannel' => 'COOKINGCHANNEL [2]',
'trv' => 'TRV (Travelers TLD) [2]',
'chrome' => 'CHROME [2]',
'ceb' => 'CEB (Corp. Exec. Board Co) [2]',
'flir' => 'FLIR [2]',
'cbs' => 'CBS [2]',
'unicom' => 'UNICOM [2]',
'cbn' => 'CBN [2]',
'bosch' => 'BOSCH [2]',
'booking' => 'BOOKING [2]',
'bananarepublic' => 'BANANAREPUBLIC [2]',
'warman' => 'WARMAN (Weir Group IP) [2]',
'aramco' => 'ARAMCO [2]',
'yahoo' => 'YAHOO [2]',
'yodobashi' => 'YODOBASHI [2]',
'zappos' => 'ZAPPOS [2]',
'zip' => 'ZIP [2]',
'symantec' => 'SYMANTEC [2]',
'prod' => 'PROD [2]',
'ibm' => 'IBM [2]',
'kddi' => 'KDDI [2]',
'itau' => 'ITAU [2]',
'infiniti' => 'INFINITI [2]',
'gallo' => 'GALLO [2]',
'hyundai' => 'HYUNDAI [2]',
'honeywell' => 'HONEYWELL [2]',
'jcp' => 'JCP [2]',
'hdfcbank' => 'HDFCBANK [2]',
'spiegel' => 'SPIEGEL [2]',
'goldpoint' => 'GOLDPOINT [2]',
'godaddy' => 'GODADDY [2]',
'juniper' => 'JUNIPER [2]',
'glade' => 'GLADE (Johnson & Johnson) [2]',
'gbiz' => 'GBIZ [2]',
'weatherchannel' => 'WEATHERCHANNEL [1]',
'xfinity' => 'XFINITY [1]',
'sina' => 'SINA [1]',
'scjohnson' => 'SCJOHNSON [1]',
'scor' => 'SCOR [1]',
'seek' => 'SEEK [1]',
'yamaxun' => 'YAMAXUN [1]',
'shangrila' => 'SHANGRILA [1]',
'virgin' => 'VIRGIN [1]',
'shaw' => 'SHAW [1]',
'visa' => 'VISA [1]',
'qvc' => 'QVC [1]',
'vista' => 'VISTA [1]',
'volvo' => 'VOLVO [1]',
'wtc' => 'WTC [1]',
'wolterskluwer' => 'WOLTERSKLUWER [1]',
'vig' => 'VIG [1]',
'walmart' => 'WALMART [1]',
'viking' => 'VIKING [1]',
'swiftcover' => 'SWIFTCOVER [1]',
'reliance' => 'RELIANCE [1]',
'thd' => 'THD (Homer TLC Inc.) [1]',
'stcgroup' => 'STCGROUP [1]',
'tab' => 'TAB (Tabcorp Holdings) [1]',
'samsung' => 'SAMSUNG [1]',
'taobao' => 'TAOBAO [1]',
'sakura' => 'SAKURA [1]',
'tci' => 'TCI (Asia Green) [1]',
'tdk' => 'TDK [1]',
'safety' => 'SAFETY [1]',
'telefonica' => 'TELEFONICA [1]',
'tiffany' => 'TIFFANY [1]',
'verisign' => 'VERISIGN [1]',
'statebank' => 'STATEBANK [1]',
'rogers' => 'ROGERS [1]',
'starhub' => 'STARHUB [1]',
'star' => 'STAR [1]',
'staples' => 'STAPLES [1]',
'tui' => 'TUI [1]',
'tvs' => 'TVS [1]',
'richardli' => 'RICHARDLI (Pacific Century Asset Mgmt) [1]',
'ups' => 'UPS [1]',
'tjx' => 'TJX [1]',
'lacaixa' => 'LACAIXA [1]',
'progressive' => 'PROGRESSIVE [1]',
'dish' => 'DISH [1]',
'capitalone' => 'CAPITALONE [1]',
'caravan' => 'CARAVAN [1]',
'cartier' => 'CARTIER [1]',
'caseih' => 'CASEIH (Fiat)  [1]',
'cbre' => 'CBRE [1]',
'chrysler' => 'CHRYSLER [1]',
'citadel' => 'CITADEL [1]',
'comcast' => 'COMCAST [1]',
'comsec' => 'COMSEC (Verisign) [1]',
'cyou' => 'CYOU (Afilias) [1]',
'dclk' => 'DCLK (Google) [1]',
'dealer' => 'DEALER [1]',
'delta' => 'DELTA [1]',
'dodge' => 'DODGE [1]',
'cal' => 'CAL [1]',
'dtv' => 'DTV (Dish TV) [1]',
'dunlop' => 'DUNLOP [1]',
'duns' => 'DUNS (Dun and Bradstreet) [1]',
'dvr' => 'DVR (Hughes Satellite Co.) [1]',
'ericsson' => 'ERICSSON [1]',
'etisalat' => 'ETISALAT [1]',
'farmers' => 'FARMERS [1]',
'fedex' => 'FEDEX [1]',
'ferrari' => 'FERRARI [1]',
'fiat' => 'FIAT [1]',
'fido' => 'FIDO (Rogers) [1]',
'flickr' => 'FLICKR [1]',
'frontier' => 'FRONTIER [1]',
'calvinklein' => 'CALVINKLEIN [1]',
'bofa' => 'BOFA (NMS Services) [1]',
'fujixerox' => 'FUJIXEROX [1]',
'alstom' => 'ALSTOM [1]',
'abarth' => 'ABARTH [1]',
'abbvie' => 'ABBVIE [1]',
'adac' => 'ADAC (Allgemeiner De. Auto-Club) [1]',
'aeg' => 'AEG [1]',
'afamilycompany' => 'AFAMILYCOMPANY (Johnson & Johnson) [1]',
'agakhan' => 'AGAKHAN [1]',
'aigo' => 'AIGO [1]',
'airtel' => 'AIRTEL [1]',
'akdn' => 'AKDN [1]',
'alfaromeo' => 'ALFAROMEO [1]',
'alibaba' => 'ALIBABA [1]',
'alipay' => 'ALIPAY [1]',
'ally' => 'ALLY [1]',
'americanfamily' => 'AMERICANFAMILY (AMFam) [1]',
'boehringer' => 'BOEHRINGER [1]',
'android' => 'ANDROID [1]',
'aol' => 'AOL [1]',
'asda' => 'ASDA (Walmart) [1]',
'athleta' => 'ATHLETA (The Gap) [1]',
'avianca' => 'AVIANCA (Aerovias del Continente Americano) [1]',
'baidu' => 'BAIDU [1]',
'banamex' => 'BANAMEX (Citigroup) [1]',
'bbt' => 'BBT [1]',
'bcg' => 'BCG [1]',
'beats' => 'BEATS (Beats Elecronics) [1]',
'bharti' => 'BHARTI [1]',
'bms' => 'BMS [1]',
'bnl' => 'BNL [1]',
'pramerica' => 'PRAMERICA (Prudential Financial) [1]',
'ftr' => 'FTR (Frontier Communications Co.) [1]',
'gallup' => 'GALLUP [1]',
'nba' => 'NBA [1]',
'lplfinancial' => 'LPLFINANCIAL [1]',
'macys' => 'MACYS [1]',
'marshalls' => 'MARSHALLS (TJX Co. Inc.) [1]',
'maserati' => 'MASERATI [1]',
'mckinsey' => 'MCKINSEY [1]',
'merckmsd' => 'MERCKMSD (MSD Registry) [1]',
'metlife' => 'METLIFE [1]',
'mopar' => 'MOPAR (Chrysler Group) [1]',
'mormon' => 'MORMON [1]',
'moto' => 'MOTO [1]',
'movistar' => 'MOVISTAR [1]',
'msd' => 'MSD [1]',
'nationwide' => 'NATIONWIDE [1]',
'netflix' => 'NETFLIX [1]',
'lifestyle' => 'LIFESTYLE [1]',
'newholland' => 'NEWHOLLAND [1]',
'nexus' => 'NEXUS [1]',
'nike' => 'NIKE [1]',
'nissay' => 'NISSAY (Nippon Life Ins. Co.) [1]',
'norton' => 'NORTON [1]',
'nowtv' => 'NOWTV (Starbucks) [1]',
'oldnavy' => 'OLDNAVY (The GAP) [1]',
'ollo' => 'OLLO (Dish DBS Co.) [1]',
'ott' => 'OTT (Dish Network) [1]',
'pccw' => 'PCCW [1]',
'piaget' => 'PIAGET [1]',
'play' => 'PLAY [1]',
'pnc' => 'PNC (PNC Domain Co.) [1]',
'politie' => 'POLITIE [1]',
'lpl' => 'LPL [1]',
'lego' => 'LEGO [1]',
'gap' => 'GAP [1]',
'lefrak' => 'LEFRAK (LeFrak Org.) [1]',
'george' => 'GEORGE (Walmart) [1]',
'ggee' => 'GGEE (GMO Registry) [1]',
'giving' => 'GIVING [1]',
'goodyear' => 'GOODYEAR [1]',
'guge' => 'GUGE (Google) [1]',
'hbo' => 'HBO [1]',
'hdfc' => 'HDFC [1]',
'hgtv' => 'HGTV (Lifestyle Brands) [1]',
'hkt' => 'HKT [1]',
'homedepot' => 'HOMEDEPOT (Homer TLC) [1]',
'hughes' => 'HUGHES [1]',
'icbc' => 'ICBC (Bank of China) [1]',
'imdb' => 'IMDB [1]',
'intuit' => 'INTUIT [1]',
'iveco' => 'IVECO [1]',
'lds' => 'LDS [1]',
'lasalle' => 'LASALLE [1]',
'lancome' => 'LANCOME [1]',
'lancia' => 'LANCIA [1]',
'lamer' => 'LAMER (Estee Lauder) [1]',
'ladbrokes' => 'LADBROKES [1]',
'kuokgroup' => 'KUOKGROUP [1]',
'kindle' => 'KINDLE [1]',
'kerryproperties' => 'KERRYPROPERTIES [1]',
'kerryhotels' => 'KERRYHOTELS [1]',
'jeep' => 'JEEP [1]',
'zippo' => 'ZIPPO [1]',
'telecity' => 'TELECITY [Unknown]',
'epson' => 'EPSON [Unknown]',
'chloe' => 'CHLOE [Unknown]',
'statoil' => 'STATOIL [Unknown]'
);

$tld_info = array();
$tld_info['gTLD']	= 'List of Generic Top-Level-Domains (gTLD)';
$tld_info['ccTLD']	= 'List of Country code Top-Level-Domains (ccTLD)';
$tld_info['iTLD']	= 'List of Internationalized (IDN) Top-Level-Domains (iTLD)';
$tld_info['bgTLD']	= 'List of Branded Generic Top-Level-Domains (bgTLD)';

$tld_total = array_sum(array_map('count', $tld_list));

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('DNSBL'));
$pglinks = array('', '/pfblockerng/pfblockerng_dnsbl.php', '@self');
$shortcut_section = 'pfblockerng';
include_once('head.inc');

if ($input_errors) {
	print_input_errors($input_errors);
}

// Define default Alerts Tab href link (Top row)
$get_req = pfb_alerts_default_page();

$tab_array	= array();
$tab_array[]	= array(gettext('General'),	FALSE,	'/pfblockerng/pfblockerng_general.php');
$tab_array[]	= array(gettext('IP'),		FALSE,	'/pfblockerng/pfblockerng_ip.php');
$tab_array[]	= array(gettext('DNSBL'),	TRUE,	'/pfblockerng/pfblockerng_dnsbl.php');
$tab_array[]	= array(gettext('Update'),	FALSE,	'/pfblockerng/pfblockerng_update.php');
$tab_array[]	= array(gettext('Reports'),	FALSE,	"/pfblockerng/pfblockerng_alerts.php{$get_req}");
$tab_array[]	= array(gettext('Feeds'),	FALSE,	'/pfblockerng/pfblockerng_feeds.php');
$tab_array[]	= array(gettext('Logs'),	FALSE,	'/pfblockerng/pfblockerng_log.php');
$tab_array[]	= array(gettext('Sync'),	FALSE,	'/pfblockerng/pfblockerng_sync.php');
pfb_software_add_tab($tab_array);
display_top_tabs($tab_array, TRUE);

$tab_array	= array();
$tab_array[]	= array(gettext('DNSBL Groups'),	FALSE,		'/pfblockerng/pfblockerng_category.php?type=dnsbl');
$tab_array[]	= array(gettext('DNSBL Category'),	FALSE,		'/pfblockerng/pfblockerng_blacklist.php');
$tab_array[]	= array(gettext('DNSBL SafeSearch'),	FALSE,		'/pfblockerng/pfblockerng_safesearch.php');
display_top_tabs($tab_array, TRUE);
pfb_print_pending_changes_box();

if (isset($_REQUEST['savemsg'])) {
	$savemsg = htmlspecialchars($_REQUEST['savemsg']);
	print_info_box($savemsg);
}

$form = new Form('Save DNSBL settings');

$section = new Form_Section('DNSBL');
$section->addInput(new Form_StaticText(
	'Links',
	'<small>'
	. '<a href="/firewall_aliases.php" target="_blank" rel="noopener noreferrer">Firewall Aliases</a>&emsp;'
	. '<a href="/firewall_rules.php" target="_blank" rel="noopener noreferrer">Firewall Rules</a>&emsp;'
	. '<a href="/status_logs_filter.php" target="_blank" rel="noopener noreferrer">Firewall Logs</a></small>'
));

$dnsbl_text = '<div class="infoblock">'
		. '<div id="dnsbl_eval_order">'
		. '<strong>DNSBL evaluation order</strong> (first match wins):'
		. '<ol>'
		. '<li><strong>Feed lists, exact name</strong> — a listed domain is blocked (logged as DNSBL).</li>'
		. '<li><strong>Feed lists, wildcard/zone</strong> — Wildcard Blocking classifies registrable domains (logged as TLD).</li>'
		. '<li><strong>TLD Allow</strong> — when enabled, a name whose suffix is not selected is blocked here (logged as TLD_Allow).</li>'
		. '<li><strong>IDN Blocking</strong> — Off / Confusable / Always. Confusable can raise a non-blocking alert instead of a block.</li>'
		. '<li><strong>Regex Blocking</strong> — user regex and ABP feed block-regex.</li>'
		. '</ol>'
		. 'Feed exact and wildcard matching (1–2) run only while DNSBL blocking is enabled; TLD Allow, IDN, and Regex (3–5) still run.<br /><br />'
		. 'If a block is found, a whitelist entry, an ABP allow rule (@@) or an allow-regex can override it. Once an ABP feed loads $important rules, block and allow are resolved by priority rather than allow-always-wins.<br /><br />'
		. 'If the name is still blocked, the reply is shaped last: HSTS may use null-blocking to avoid browser certificate errors; NXDOMAIN replies (logged or silent) replace a VIP or null answer; a hit via a CNAME chain is tagged _CNAME. Null-blocking is not a property of which stage matched.<br /><br />'
		. 'CNAME Validation and no-AAAA are separate features, not steps in this order. Feed-at-suffix (PSL) policies, the regex cap, and Download Schemes shape what is loaded, not the per-query order.'
		. '</div><br /><br />'
		. '<span class="text-danger">Note: </span>'
		. 'DNSBL requires the DNS Resolver (Unbound) to be used as the DNS service.<br />'
		. 'How a blocked name is answered depends on the <strong>Global Logging/Blocking Mode</strong> and on each DNSBL Group\'s own Logging/Blocking setting:<br />'
		. '&#8226 <strong>DNSBL WebServer/VIP</strong> - the request is redirected to the DNSBL Virtual IP, where a Lighttpd instance records the hit and returns a \'1x1\' GIF. For a root domain the customizable Blocked Webpage is shown instead.<br />'
		. '&#8226 <strong>Null Blocking</strong> - the name is answered with \'0.0.0.0\'. No Virtual IP, no web server and no block page are involved.<br />'
		. '&#8226 <strong>NXDOMAIN</strong> - the name is answered NXDOMAIN and the block page is bypassed.<br /><br />'
		. 'If browsing is slow <strong>in VIP mode</strong>, check for Firewall LAN Rules/Limiters that might be blocking access to the DNSBL VIP.<br /><br />'
		. '<span class="text-danger">Note: </span>'
		. 'DNSBL will block and <u>partially</u> log Alerts for HTTPS requests. '
		. 'To debug issues with \'False Positives\', the following tools below can be used:<br />'
		. '<ol>'
		. '<li>Browser Developer tools, Console tab, for error messages.</li>'
		. '<li>Execute the following from the pfSense Shell, substituting your LAN interface for \'re1\' and the DNSBL Virtual IP listed under <strong>DNSBL Webserver Configuration</strong> above:<br />'
		. '&emsp;<strong>tcpdump -nnvli re1 port 53 | grep -B1 \'A &lt;VIP&gt;\'</strong></li>'
		. '<li>Packet capture software such as Wireshark.</li>'
		. '</ol>'
		. '</div>';

$section->addInput(new Form_Checkbox(
	'pfb_dnsbl',
	gettext('DNSBL'),
	'Enable DNSBL',
	pfb_cfg_toggle_read($pconfig['pfb_dnsbl']) === PfbToggle::On,
	'on'
))->setHelp('This will enable DNS Block List for Malicious and/or unwanted Adverts Domains<br />'
		. 'To Utilize, <strong>Unbound DNS Resolver</strong> must be enabled. Also ensure that pfBlockerNG is enabled.'
		. "{$dnsbl_text}"
);

$tld_wildcard_text = 'Block listed domains and their subdomains. '
		. pfb_list_section_help_note(['TLD Exclusion List', 'TLD Blacklist'], TRUE)
		. '<div id="dnsbl_tld_info" class="infoblock">

		<strong>Definition: Public suffix</strong> -
		&emsp;a domain suffix under which the public may register names, per the
		<a href="https://publicsuffix.org/" target="_blank" rel="noopener noreferrer">Public Suffix List</a>. IE: <strong>com</strong>,
		<strong>co.uk</strong>, <strong>github.io</strong><br /><br />

		<strong>Definition: Registrable domain</strong> -
		&emsp;a public suffix plus exactly one additional label. IE: example.com (suffix = com), example.co.uk (suffix = co.uk)<br /><br />

		When enabled and after all downloads for DNSBL Feeds have completed; this process will classify the listed Domains.<br />
		A Domain listed at its <strong>registrable domain</strong> is wildcard blocked (Block all sub-Domains).<br />
		A Domain that is itself a <strong>public suffix</strong> is <strong>never</strong> wildcard blocked (blocking it would block every registrant under it).<br />
		A Domain listed <strong>deeper</strong> than its registrable domain stays an exact block (only that specific name).<br />
		The Public Suffix List authority can be found in &emsp;<u>/usr/local/pkg/pfblockerng/dnsbl_psl</u><br /><br />

		To exclude a suffix/Domain from this process, add it to the <strong>TLD Exclusion</strong> custom list:<br />
		&#8226&emsp;This only excludes the domain from the process, it doesn\'t whitelist the domain.<br />
		&#8226&emsp;Only the specific Sub-Domains/Domains listed in the DNSBL Feeds will be blocked.<br />
		&#8226&emsp;Changes to the TLD Exclusion take effect on the next DNSBL update.<br /><br />
		<strong>Note:</strong>
		&emsp;A specific sub-Domain added to the <strong>Custom Domain Whitelist</strong> is exempted from a
		Wildcard Blocked domain (that exact name resolves).<br />
		&emsp;&emsp;&emsp;&emsp;To exempt the whole domain (all sub-Domains), add it to the TLD Exclusion, or add a wildcard Whitelist entry for the domain.<br /><br />

		<strong>TLD Blacklist</strong>, can be used to block whole TLDs. &emsp;IE: <strong>xyz</strong><br />

		Enabling or disabling this option takes effect on the next DNSBL update.<br /><br />

	</div>';

$section->addInput(new Form_Checkbox(
	'tld_wildcard',
	gettext('Wildcard Blocking'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['tld_wildcard']) === PfbToggle::On,
	'on'
))->setHelp($tld_wildcard_text);

$section->addInput(new Form_Checkbox(
	'pfb_py_reply',
	gettext('DNS Reply Logging'),
	'Enable',
	pfb_dnsbl_toggle_enabled($pconfig['pfb_py_reply'] ?? NULL),
	'on'
))->setHelp('Enable the logging of all DNS Replies that were not blocked via DNSBL.');

$section->addInput(new Form_Checkbox(
	'pfb_hsts',
	gettext('HSTS mode'),
	'Enable',
	pfb_dnsbl_toggle_enabled($pconfig['pfb_hsts'] ?? NULL),
	'on'
))->setHelp('Answer HSTS-preload domains with 0.0.0.0 instead of the DNSBL VIP, which may avoid browser certificate errors.'
	. '<div class="infoblock">'
	. 'Enable the DNSBL <strong title="Utilizes 0.0.0.0 instead of the DNSBL VIP">Null Blocking mode</strong> for HSTS domains.<br />'
	. 'Blocked domains that are in the <a target=_"blank" href="https://hstspreload.org/">HSTS preload</a> browser'
	. ' <a target=_"blank" href="https://raw.githubusercontent.com/chromium/chromium/master/net/http/transport_security_state_static.json">list</a>'
	. ' will use the Null Blocking Mode which *may* prevent Browser Certificate Errors.<br />'
	. '<span class="text-danger">Note:</span> This option will not block HSTS domains, unless those Domains are added via the Feeds/Customlists.'
	. '</div>'
);

$section->addInput(new Form_Select(
	'pfb_idn',
	gettext('IDN Blocking'),
	$pconfig['pfb_idn'],
	array(
		'off'		=> 'Off',
		'confusable'	=> 'Confusable',
		'on'		=> 'Always',
	)
))->setHelp('How IDN / xn-- names are handled (Off, Confusable, or Always). Not regex-based.'
		. '<div class="infoblock">'
		. 'IDN handling (not Regex based).<ul>'
		. '<li><strong>Off</strong> - no IDN action.</li>'
		. '<li><strong>Confusable</strong> - block only cross-script homoglyphs (Latin/Cyrillic/Greek mixes, '
		. 'including Cyrillic+Greek).<br />Does not catch whole-script confusables or pure-ASCII typosquats.</li>'
		. '<li><strong>Always</strong> - block every IDN/\'xn--\' domain (blunt).</li></ul>'
		. '</div>');

$section->addInput(new Form_Checkbox(
	'pfb_idn_block_malicious',
	gettext('Block clearly-malicious homoglyphs'),
	'Enable',
	pfb_dnsbl_toggle_enabled($pconfig['pfb_idn_block_malicious'] ?? NULL),
	'on'
))->setHelp('Confusable mode: block names that mix confusable scripts in one label (clearly malicious). Disable to alert only. '
		. 'Applies in Confusable mode.');

$section->addInput(new Form_Checkbox(
	'pfb_idn_escalate_suspicious',
	gettext('Block suspicious mixed-script'),
	'Enable',
	pfb_dnsbl_toggle_enabled($pconfig['pfb_idn_escalate_suspicious'] ?? NULL),
	'on'
))->setHelp('Confusable mode: escalate suspicious mixed-script names to a block. Default alerts only (no block). '
		. 'Applies in Confusable mode.');

$section->addInput(new Form_Checkbox(
	'pfb_regex',
	gettext('Regex Blocking'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['pfb_regex']) === PfbToggle::On,
	'on'
))->setHelp('Enable the Regex blocking feature. '
		. pfb_list_section_help_note(['Regex List'], TRUE));

$section->addInput(new Form_Checkbox(
	'pfb_regex_cap',
	gettext('Limit long/complex regex'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['pfb_regex_cap']) === PfbToggle::On,
	'on'
))->setHelp('Best-effort ReDoS safeguard (opt-in): over-long or catastrophic-backtracking regex patterns are dropped at load, before they run. '
		. 'Applies when Regex Blocking is enabled.'
		. '<div class="infoblock">From both feeds (ABP) and the Regex List below (each drop is logged). '
		. 'An always-on runtime guard additionally warns on, then evicts, any pattern whose match runs too slow.</div>');

$section->addInput(new Form_Checkbox(
	'pfb_cname',
	gettext('CNAME Validation'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['pfb_cname']) === PfbToggle::On,
	'on'
))->setHelp('Also check CNAME targets against DNSBL.'
		. '<div class="infoblock">'
		. 'Enable the CNAME Validation feature. All CNAMES will be evaluated against DNSBL database and blocked.<br />'
		. 'Events are logged with a "_CNAME" suffix in the DNSBL Log.'
		. '</div>');

$section->addInput(new Form_Checkbox(
	'pfb_noaaaa',
	gettext('no-AAAA'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['pfb_noaaaa']) === PfbToggle::On,
	'on'
))->setHelp('Enable the no-AAAA feature. This will block all (IPv6) AAAA DNS requests for the defined domains. '
		. pfb_list_section_help_note(['no-AAAA List'], TRUE));

$section->addInput(new Form_Checkbox(
	'pfb_gp',
	gettext('DNSBL Group Policy'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['pfb_gp']) === PfbToggle::On,
	'on'
))->setHelp('Enable the Group Policy functionality to allow certain Local LAN IPs to bypass DNSBL. '
		. pfb_list_section_help_note(['DNSBL Group Policy'], TRUE));

$section->addInput(new Form_Checkbox(
	'pfb_dnsbl_lenient',
	gettext('Download Schemes'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['pfb_dnsbl_lenient']) === PfbToggle::On,
	'on'
))->setHelp('How feed lines are parsed: strip scheme:// and URL paths, or skip those lines.'
		. '<div class="infoblock">'
		. 'Parse DNSBL feed lines permissively: any <strong>scheme://</strong> is stripped and URL paths are removed.<br />'
		. 'When disabled (strict), lines with an invalid scheme (e.g. <strong>123://</strong>) or a URL path are skipped and logged.<br />'
		. 'New installs default to disabled (strict); upgraded installs keep the permissive behaviour.'
		. '</div>');

$section->addInput(new Form_Select(
	'global_log',
	'Global Logging/Blocking Mode',
	$pconfig['global_log'],
	$options_global_log
))->setHelp($options_global_log_txt)
  ->setAttribute('style', 'width: auto');

$section->addInput(new Form_Checkbox(
	'tld_allow',
	gettext('Allow Only Selected Domain Suffixes'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['tld_allow']) === PfbToggle::On,
	'on'
))->setHelp('Enable the TLD Allow feature (' . number_format($tld_total) . ' TLDs available). '
		. 'This will block all TLDs that are not specifically selected. '
		. pfb_list_section_help_note(['TLD Allow list'], TRUE));

$form->add($section);

$section = new Form_Section('DNSBL Webserver Configuration');
$section->addInput(new Form_Select(
	'dnsbl_interface',
	gettext('Web Server Interface'),
	$pconfig['dnsbl_interface'],
	$options_dnsbl_interface_all
))->setHelp('Select the interface which DNSBL Web Server will Listen on.<br />'
	. 'Default: <strong>Localhost (ports 80/443)</strong> - Selected Interface should be a Local Interface only.');

$section->addInput(new Form_Checkbox(
	'pfb_dnsbl_nonat',
	gettext('Auto NAT'),
	gettext('Disable automatic NAT rule creation'),
	(pfb_cfg_toggle_read($pconfig['pfb_dnsbl_nonat']) === PfbToggle::On),
	'on'
))->setHelp('When set, pfBlockerNG will not auto-create the DNSBL NAT port-forward rules (non-Localhost interface only); manage them manually.');

// [ ADR-13 ] Compute the address(es) the package WOULD auto-create, for the currently
// selected DNSBL Web Server interface, so the UI can pre-fill them and detect conflict
// exhaustion. pfb_pick_free_dnsbl_vip() returns the first free candidate from
// pfb_dnsbl_vip_candidates() (null when every candidate conflicts). A v6 VIP is only relevant when the
// DNS Resolver listens on IPv6 (pfb_unbound_listens_v6()); otherwise v6 is not required.
$pfb_auto_iface		= $pconfig['dnsbl_interface'] ?: 'lo0';
$pfb_auto_v6_needed	= pfb_unbound_listens_v6();
$pfb_auto_vip4		= pfb_pick_free_dnsbl_vip(AF_INET, $pfb_auto_iface);
$pfb_auto_vip6		= $pfb_auto_v6_needed ? pfb_pick_free_dnsbl_vip(AF_INET6, $pfb_auto_iface) : null;

// Conflict exhaustion: v4 is always required; v6 only when the resolver listens on it.
// When no free candidate exists for a required family the checkbox is rendered disabled
// with a warning, so auto-create can never be enabled into a known-conflicting state.
$pfb_auto_exhausted	= ($pfb_auto_vip4 === null) || ($pfb_auto_v6_needed && $pfb_auto_vip6 === null);

$vips = pfb_get_vips();

// [ ADR-13 ] The "Create VIPs automatically" toggle on its OWN row, above the
// manual VIP selects. Its explanation lives in the group help UNDER the fields,
// not on the checkbox: a long inline checkbox help renders as a very tall, narrow
// column that towers over the rest of the section.
$pfb_auto_chk = new Form_Checkbox(
	'pfb_dnsvip_auto',
	gettext('Auto VIP'),
	gettext('Create VIPs automatically'),
	(!$pfb_auto_exhausted && pfb_cfg_toggle_read($pconfig['pfb_dnsvip_auto']) === PfbToggle::On),
	'on'
);
if ($pfb_auto_exhausted) {
	$pfb_auto_chk->setAttribute('disabled', 'disabled');
}
$section->addInput($pfb_auto_chk);

$group = new Form_Group('DNSBL Virtual IP');
$group->add(new Form_Select(
	'pfb_dnsvip4',
	gettext('IPv4 VIP'),
	$pconfig['pfb_dnsvip4'],
	pfb_get_vip_options(AF_INET)
))->setWidth(4)->setHelp('IPv4 Virtual IP');
$group->add(new Form_Select(
	'pfb_dnsvip6',
	gettext('IPv6 VIP'),
	$pconfig['pfb_dnsvip6'],
	pfb_get_vip_options(AF_INET6)
))->setWidth(4)->setHelp('IPv6 Virtual IP (optional)');

// Help under the side-by-side VIP fields: the original intro, a line break at the
// SENTENCE boundary (never mid-sentence), then one concise line covering both
// modes. "VIP"/"Virtual IP" used consistently (no "IP-Alias VIP" jargon); the
// address/lifecycle detail belongs in the docs.
$pfb_vip_help = 'Select the DNSBL VIP address — rejected DNS requests are forwarded here. '
	. 'It should be in an isolated range not already used on the network.<br />'
	. 'Enable <strong>Create VIPs automatically</strong> to have pfBlockerNG manage it, or select one '
	. 'manually — create it first at '
	. '<a target="_blank" rel="noopener noreferrer" href="/firewall_virtual_ip.php">Firewall &gt; Virtual IPs</a>.';
if ($pfb_auto_exhausted) {
	$pfb_vip_help .= '<br /><i class="fa fa-exclamation-triangle text-warning"></i> '
		. '<span class="text-warning">No free auto-create address is available — free one of the '
		. 'auto-create candidates, or select a VIP manually.</span>';
}
$group->setHelp($pfb_vip_help);
$section->add($group);

$section->addInput(new Form_Input(
	'pfb_dnsport',
	gettext('Port'),
	'number',
	$pconfig['pfb_dnsport'],
	[ 'min' => 1, 'max' => 65535, 'placeholder' => 'Enter DNSBL Listening Port' ]
))->setHelp('Example ( 8081 ) &mdash; a single PORT in the range 1 - 65535. '
		. 'Applies when Web Server Interface is not Localhost.'
		. '<div class="infoblock">This Port must not be in use by any other process.</div>'
);

$section->addInput(new Form_Input(
	'pfb_dnsport_ssl',
	gettext('SSL Port'),
	'number',
	$pconfig['pfb_dnsport_ssl'],
	[ 'min' => 1, 'max' => 65535, 'placeholder' => 'Enter DNSBL SSL Listening Port' ]
))->setHelp('Example ( 8443 ) &mdash; a single PORT in the range 1 - 65535. '
		. 'Applies when Web Server Interface is not Localhost.'
		. '<div class="infoblock">This Port must not be in use by any other process.</div>'
);

// Add option to disable DNSBL logging and utilize the DNSBL Webserver (excluding nullblocking events)
$section->addInput(new Form_Checkbox(
	'pfb_py_nolog',
	gettext('DNSBL Event Logging'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['pfb_py_nolog']) === PfbToggle::On,
	'on'
))->setHelp('Disable event logging in the DNS Resolver and utilize the DNSBL Webserver. Typically used when an upstream LAN DNS server is utilized.<br />'
	. 'Null blocked events will still be logged.');


$section->addInput(new Form_Checkbox(
	'pfb_dnsbl_rule',
	gettext('Permit Firewall Rules'),
	gettext('Enable'),
	pfb_cfg_toggle_read($pconfig['pfb_dnsbl_rule']) === PfbToggle::On,
	'on'
))->setHelp('Creates \'Floating\' Firewall permit rules allowing the selected interface(s) to reach the DNSBL Webserver (ICMP and Webserver ports only).'
		. '<div class="infoblock">This option is not designed to bypass DNSBL for the non-selected LAN segments. '
		. 'Only required for networks with multiple LAN Segments.</div>');

$section->addInput(new Form_Select(
	'dnsbl_allow_int',
	gettext('Interface(s)'),
	$pconfig['dnsbl_allow_int'],
	$options_dnsbl_interface,
	TRUE
))->setAttribute('style', 'width: auto')
  ->setAttribute('size', $options_dnsbl_interface_cnt)
  ->setHelp('Interface(s) permitted to reach the DNSBL Webserver by the Permit Firewall Rules above.');

$section->addInput(new Form_Select(
	'dnsbl_webpage',
	'Blocked Webpage',
	$pconfig['dnsbl_webpage'],
	$options_dnsbl_webpage
))->sethelp('Default: <strong>dnsbl_default.php</strong><br />Select the DNSBL Blocked Webpage.<br /><br />'
	. 'Custom block web pages can be added to: <strong>/usr/local/www/pfblockerng/www/</strong> folder.')
  ->setAttribute('style', 'width: auto')
  ->setAttribute('size', $options_dnsbl_webpage_cnt);
$form->add($section);

$section = new Form_Section('AdBlock suffix handling', 'dnsbl_suffix', COLLAPSIBLE|SEC_CLOSED);

// issue #2371: feed-at-suffix policy selects. Feed-wide and independent of Wildcard
// Blocking (and of each other) -- deliberately NOT behind a hideCheckbox() show/hide,
// so placement here (near Wildcard Blocking, for topical proximity) never implies a
// dependency on it. Applies only to Feed-provenance rows; a Custom List or a sovereign
// ABP list entry is never affected by either select.
$psl_feed_policy_options = array(
	'ignore'	=> 'Ignore entirely',
	'apex'		=> 'Block the suffix apex only',
	'honor'		=> 'Honor list rules',
);
$psl_feed_policy_help = '<div class="infoblock"><ul>'
	. '<li><strong>Ignore entirely</strong> - the feed entry is dropped (counted in the reject stats).</li>'
	. '<li><strong>Block the suffix apex only</strong> - only the exact suffix name is blocked; this entry no longer affects names under the suffix (other list entries still apply).</li>'
	. '<li><strong>Honor list rules</strong> - the list is honored as written, including an explicit ABP wildcard rule that may still blanket the suffix.</li>'
	. '</ul>'
	. 'A Custom List or a sovereign ABP list entry is never affected by this policy. Intentional whole-suffix blocking belongs in '
	. '<strong>TLD Blacklist</strong> below (dotted entries supported).</div>';

$section->addInput(new Form_Select(
	'pfb_psl_feed_private_policy',
	gettext('Feed entries at shared-hosting suffixes (PSL PRIVATE)'),
	$pconfig['pfb_psl_feed_private_policy'],
	$psl_feed_policy_options
))->setHelp('Applies only to a Feed entry named exactly at a PSL PRIVATE suffix (shared domains such as github.io -- not private DNS).'
	. $psl_feed_policy_help);

$section->addInput(new Form_Select(
	'pfb_psl_feed_icann_policy',
	gettext('Feed entries at public suffixes (ICANN)'),
	$pconfig['pfb_psl_feed_icann_policy'],
	$psl_feed_policy_options
))->setHelp('Applies only to a Feed entry named exactly at an ICANN (public) suffix.'
	. $psl_feed_policy_help);

$section->addInput(new Form_Checkbox(
	'pfb_psl_include_private',
	gettext('Recognize Shared-Hosting Suffixes (PSL PRIVATE)'),
	'Enable',
	$pconfig['pfb_psl_include_private'] === PfbToggle::On,
	'on'
))->setHelp('Recognize the PSL PRIVATE section when determining the registrable boundary. '
		. 'Applies when Wildcard Blocking is enabled.'
		. '<div class="infoblock">A suffix apex is never wildcarded. PSL PRIVATE describes shared domains such as github.io; it does not mean private DNS.</div>');

$section->addInput(new Form_Checkbox(
	'pfb_psl_allow_private',
	gettext('Allow Shared-Hosting Suffixes (PSL PRIVATE)'),
	'Enable',
	$pconfig['pfb_psl_allow_private'] === PfbToggle::On,
	'on'
))->setHelp('Permit only the winning PSL PRIVATE boundary when no selected IANA root TLD matches. '
		. 'Applies when Allow Only Selected Domain Suffixes is enabled.'
		. '<div class="infoblock">This precision applies to shared domains such as github.io; the suffix apex itself is never wildcarded.</div>');

$form->add($section);

$section = new Form_Section('TLD Allow list', 'tld_allow_pickers', COLLAPSIBLE|SEC_CLOSED);
$section->addInput(new Form_StaticText(
	NULL,
	'<div id="dnsbl_python_tld_allow_text">'
	. '<strong>By default</strong> \'ARPA\' and the pfSense TLD \'' . strtoupper($local_tld) . '\' are allowed.<br />'
	. 'If no TLDs are selected, the following are added by default [ COM, NET, ORG, EDU, CA, CO, IO ]<br /><br />'
	. 'Picker: <strong>IANA root TLDs</strong>. Detailed TLD listings : <a target=_blank rel="noopener noreferrer" href="http://www.iana.org/domains/root/db">Root Zone Top-Level Domains.</a><br />'
	. 'Changes to this option will require a Force Update to take effect.<br /><br />'
	. '<strong>Legend</strong>:<br />'
	. '(*) TLD is used by atleast one DNSBL Feed in the Feeds Tab. Confirm the TLDs used by the selected Feeds.<br />'
	. '(!) TLD is listed by <a target=_blank rel="noopener noreferrer" href="https://www.spamhaus.org/statistics/tlds/">Spamhaus (Most Abused TLDs)</a><br /></div>'
));

$section->addInput(new Form_Checkbox(
	'tld_allow_sort',
	'',
	'Enable',
	pfb_cfg_toggle_read($pconfig['tld_allow_sort']) === PfbToggle::On,
	'on'
))->setHelp('Enable to sort TLDs alphabetically');

$group = new Form_Group('TLD Group 1');
foreach (array('gTLD', 'ccTLD', 'iTLD', 'bgTLD') as $key => $tld_type) {
	if ($key == 2) {
		$group = new Form_Group('TLD Group 2');
	}
	$count = count($tld_list[$tld_type]);

	if (pfb_cfg_toggle_read($pconfig['tld_allow_sort']) === PfbToggle::On) {
		ksort($tld_list[$tld_type]);
	}

	$group->add(new Form_Select(
		'tld_allow_' . strtolower($tld_type),
		'',
		$pconfig['tld_allow_' . strtolower($tld_type)],
		$tld_list[$tld_type],
		TRUE
	))->setHelp("{$tld_info[$tld_type]}<br />Total TLD Count: [{$count}]")
	  ->setAttribute('size', '20')
	  ->setWidth(4);

	if ($key == 1 || $key == 3) { 
		$section->add($group);
	}
}

$form->add($section);

$section = new Form_Section('DNSBL Control', 'dnsbl_control', COLLAPSIBLE|SEC_CLOSED);
$section->addInput(new Form_Checkbox(
	'pfb_control',
	gettext('DNSBL Control'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['pfb_control']) === PfbToggle::On,
	'on'
))->setHelp('Enabling this option will allow sending DNSBL control commands via the local CLI.'
	. '<div class="infoblock" style="width: 90%;">'
	. 'Commands are run on pfSense as root via the <strong>pfblockerng dnsbl-control</strong> CLI<br />'
	. 'A disable is a temporary intervention, and will be reset on a restart of the Resolver<br />'
	. 'These commands can be incorporated in CRON/Scheduler tasks or run manually as required<br />'
	. 'All events are logged to the Reports Tab (Gear icon)<br /><br />'
	. '<strong>Command Syntax:</strong><br />'
	. '<table class="table table-bordered table-striped table-hover table-compact">'
	. '	<thead>'
	. '		<tr>'
	. '			<th style="max-width: 10%">Description</th>'
	. '			<th style="max-width: 85%">Command</th>'
	. '			<th style="max-width: 5%">Notes</th>'
	. '		</tr>'
	. '	</thead>'
	. '	<tbody>'
	. '		<tr><td>Enable DNSBL</td><td>pfblockerng dnsbl-control enable</td><td></td></tr>'
	. '		<tr><td>Disable DNSBL</td><td>pfblockerng dnsbl-control disable</td><td></td></tr>'
	. '		<tr><td>Disable DNSBL for duration</td><td>pfblockerng dnsbl-control disable seconds</td><td>Seconds: 1-3600</td></tr>'
	. '		<tr><td>Add a Global bypass IP</td><td>pfblockerng dnsbl-control addbypass 1.2.3.4</td><td></td></tr>'
	. '		<tr><td>Add a Global bypass IP for duration</td><td>pfblockerng dnsbl-control addbypass 1.2.3.4 seconds</td><td>Seconds: 1-3600</td></tr>'
	. '		<tr><td>Remove a Global bypass IP</td><td>pfblockerng dnsbl-control removebypass 1.2.3.4</td><td></td></tr>'
	. '	</tbody>'
	. '</table>'
	. '</div>');

$section->addInput(new Form_Checkbox(
	'pfb_control_legacy',
	gettext('DNSBL Control (legacy DNS TXT)'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['pfb_control_legacy']) === PfbToggle::On,
	'on'
))->setHelp('<span class="text-danger">Deprecated</span> - re-enable the legacy DNS TXT control transport (drill TXT python_control.*).'
	. '<div class="infoblock" style="width: 90%;">'
	. 'This option is <strong>deprecated</strong>, <strong>less secure</strong>, and will be <strong>removed in a future release</strong>.<br />'
	. 'It only takes effect when <strong>DNSBL Control</strong> above is enabled. Leave it off and use the CLI instead.<br />'
	. 'Migrate any CRON/Scheduler tasks from drill TXT python_control.* to the pfblockerng dnsbl-control CLI shown above.'
	. '</div>');
$form->add($section);


// DNSBL Group Policy section — placed directly below the main 'DNSBL' section (which
// holds its pfb_gp enable checkbox) and above the encrypted-DNS sections. The pfb_gp
// checkbox JS toggles this section's visibility by its 'Python_Group_Policy' id.
$section = new Form_Section('DNSBL Group Policy', 'Python_Group_Policy', COLLAPSIBLE|SEC_CLOSED);
$section->addInput(new Form_StaticText(
	NULL,
	'This is a preliminary DNSBL Group Policy configuration that will bypass DNSBL for the defined LAN IPs. (No Subnets allowed)'));

$section->addInput(new Form_Textarea(
	'pfb_gp_bypass_list',
	'Bypass IPs',
	$pconfig['pfb_gp_bypass_list']
))->removeClass('form-control')
  ->addClass('row-fluid col-sm-12')
  ->setAttribute('columns', '90')
  ->setAttribute('rows', '15')
  ->setAttribute('wrap', 'off')
  ->setAttribute('style', 'width: 100%')
  ->setHelp('Enter the Local LAN IPs (one per line) that will bypass DNSBL Blocking.<br />'
		. 'Changes to this option will require a Force Update to take effect.');

$form->add($section);

// DNS Bypass Prevention: DNS Redirect + DoT/DoQ Block + DoH/DoT/DoQ Blocking.
// [ ADR-36 ] DNS Redirect section — placed above the DoH/DoT/DoQ Blocking section.
// Redirects outbound port-53 DNS traffic on the selected interfaces to the
// firewall's own resolver. DoH/DoT bypass is NOT covered.
$section = new Form_Section('DNS Bypass Prevention', 'dnsbl_bypass', COLLAPSIBLE|SEC_CLOSED);
$section->addInput(new Form_StaticText(
	'',
	'<style>' . pfb_form_subhdr_css_rules() . '</style>'
));
$section->add(pfb_form_subhdr('DNS Redirect'));

$group = new Form_Group('DNS Redirect');
$group->add(new Form_Checkbox(
	'dnsbl_redir',
	NULL,
	gettext('Enable'),
	pfb_cfg_toggle_read($pconfig['dnsbl_redir']) === PfbToggle::On,
	'on'
))->setWidth(7)
  ->setHelp('Redirects outbound port-53 DNS traffic on the selected interface(s) to the firewall\'s own resolver.'
		. '<div class="infoblock">Keeps clients on the local DNS resolver so DNSBL stays effective.<br />'
		. 'The firewall itself is always exempt. Does not cover DoH/DoT/DoQ traffic (use the DoH/DoT/DoQ Blocking section below for that).</div>');

// [ ADR-36/37 ] Build the quick-fill interface union (inbound + outbound from IP settings).
// These are the pfBlockerNG firewall-rule interfaces; the quick-fill populates the DNS
// Redirect AND DoT/DoQ Block selects to match that set with one click. $options_dnsbl_redir_int
// and $options_dnsbl_dot_block_int are both aliases of $options_dnsbl_interface (identical
// interface list), so this one computed set/JSON serves both sections -- see the DoT/DoQ
// Block section below, which reuses it via a JS alias instead of recomputing it.
$pfb_ipconfig_raw = config_get_path('installedpackages/pfblockerngipsettings/config/0', []);
$pfb_redir_fill_ifaces = array_unique(array_filter(array_merge(
	array_filter(array_map('trim', explode(',', $pfb_ipconfig_raw['inbound_interface'] ?? ''))),
	array_filter(array_map('trim', explode(',', $pfb_ipconfig_raw['outbound_interface'] ?? '')))
)));
// Restrict to only interfaces present in the DNS Redirect option list.
$pfb_redir_fill_ifaces = array_values(array_intersect($pfb_redir_fill_ifaces, array_keys($options_dnsbl_redir_int)));
$pfb_redir_fill_json   = json_encode($pfb_redir_fill_ifaces);

// [ ADR-36/37 ] Address-type firewall alias names for the Exception Alias autocomplete on the
// DNS Redirect + DoT/DoQ Block fields. Restrict to host/network/urltable (address) aliases —
// a port alias cannot be a rule source. The field still accepts free text; existence is
// enforced server-side (pfb_validate_dns_redirect_post / pfb_validate_dot_block_post).
$pfb_alias_names = array();
foreach (config_get_path('aliases/alias', []) as $pfb_alias_entry) {
	$pfb_alias_entry_name = (string)($pfb_alias_entry['name'] ?? '');
	// Skip pfBlockerNG-managed aliases (pfB_*): they are not valid exception aliases
	// (rejected server-side in pfb_validate_dns_redirect_post / pfb_validate_dot_block_post).
	if (str_starts_with($pfb_alias_entry_name, PFB_MANAGED_FILTER_PFX)) {
		continue;
	}
	if (in_array($pfb_alias_entry['type'] ?? '', pfb_exclude_alias_types(), TRUE)) {
		$pfb_alias_names[] = $pfb_alias_entry_name;
	}
}
$pfb_alias_names_json = json_encode(array_values(array_filter(array_unique($pfb_alias_names), 'strlen')));

$group->add(new Form_Select(
	'dnsbl_redir_int',
	NULL,
	$pconfig['dnsbl_redir_int'],
	$options_dnsbl_redir_int,
	TRUE
))->setAttribute('style', 'width: auto')
  ->setAttribute('size', $options_dnsbl_interface_cnt);
$group->setHelp('<a href="#" id="pfb_redir_fill" onclick="pfb_fill_interfaces(\'dnsbl_redir_int\', pfb_redir_fill_ifaces); return false;">'
	. 'Fill from IP Interfaces</a> — select the union of pfBlockerNG Inbound + Outbound interfaces.');
$section->add($group);

$section->addInput(new Form_Input(
	'dnsbl_redir_exclude',
	gettext('DNS Redirect Exception Alias'),
	'text',
	$pconfig['dnsbl_redir_exclude'],
	['placeholder' => 'Firewall alias name (optional)']
))->setHelp('Optional. Name of an existing Firewall Alias. Hosts/subnets in this alias bypass the DNS redirect.<br />'
		. 'The alias must be created separately at <a href="/firewall_aliases.php" target="_blank" rel="noopener noreferrer">Firewall &gt; Aliases</a>.');


// [ ADR-37 ] DoT/DoQ Block section — placed adjacent to DNS Redirect.
// Blocks port-853 DoT (TCP) and DoQ (UDP) traffic on the selected interfaces.
// DoH (port 443) is not covered here; it is addressed by the DoH-IP feed and DNSBL domain blocking.
$section->add(pfb_form_subhdr('DoT/DoQ Block'));

$group = new Form_Group('DoT/DoQ Block');
$group->add(new Form_Checkbox(
	'dnsbl_dot_block',
	NULL,
	gettext('Enable'),
	pfb_cfg_toggle_read($pconfig['dnsbl_dot_block']) === PfbToggle::On,
	'on'
))->setWidth(7)
  ->setHelp('Blocks DNS-over-TLS (TCP 853) and DNS-over-QUIC (UDP 853) on the selected interface(s).'
		. '<div class="infoblock">DoH (port 443) is <strong>not</strong> blocked here — blocking 443 would break all HTTPS. '
		. 'DoH is addressed by the DoH-IP feed and DNSBL domain blocking.<br />'
		. 'The firewall itself is always exempt. Hosts in the exception alias are also exempt. '
		. 'The exception alias must exist at '
		. '<a href="/firewall_aliases.php" target="_blank" rel="noopener noreferrer">Firewall &gt; Aliases</a> before use.</div>');

// [ ADR-37 ] Quick-fill interface union -- identical to the ADR-36 DNS Redirect fill above
// ($options_dnsbl_dot_block_int is the same interface list as $options_dnsbl_redir_int), so
// this section's "Fill" button reuses that already-computed set via a JS alias (see below).
$group->add(new Form_Select(
	'dnsbl_dot_block_int',
	NULL,
	$pconfig['dnsbl_dot_block_int'],
	$options_dnsbl_dot_block_int,
	TRUE
))->setAttribute('style', 'width: auto')
  ->setAttribute('size', $options_dnsbl_interface_cnt);
$group->setHelp('<a href="#" id="pfb_dot_block_fill" onclick="pfb_fill_interfaces(\'dnsbl_dot_block_int\', pfb_dot_block_fill_ifaces); return false;">'
	. 'Fill from IP Interfaces</a> — select the union of pfBlockerNG Inbound + Outbound interfaces.');
$section->add($group);

$section->addInput(new Form_Input(
	'dnsbl_dot_block_exclude',
	gettext('DoT/DoQ Exception Alias'),
	'text',
	$pconfig['dnsbl_dot_block_exclude'],
	['placeholder' => 'Firewall alias name (optional)']
))->setHelp('Optional. Name of an existing Firewall Alias. Hosts/subnets in this alias bypass the DoT/DoQ block.<br />'
		. 'The alias must be created separately at <a href="/firewall_aliases.php" target="_blank" rel="noopener noreferrer">Firewall &gt; Aliases</a>.');

$section->addInput(new Form_Select(
	'dnsbl_dot_block_action',
	gettext('Rule Action'),
	pfb_dot_block_action($pconfig['dnsbl_dot_block_action']),
	$options_dnsbl_dot_block_action
))->setHelp('Default: <strong>Reject</strong><br />'
		. 'Select the action for the DoT/DoQ block rules. <strong>Reject</strong> fast-fails the client '
		. '(so it falls back to plain DNS) while <strong>Block</strong> silently drops the connection.')
  ->setAttribute('style', 'width: auto');

$section->addInput(new Form_Checkbox(
	'dnsbl_dot_block_floating',
	gettext('Floating Rule'),
	gettext('Use a single floating rule instead of one rule per interface'),
	pfb_cfg_toggle_read($pconfig['dnsbl_dot_block_floating']) === PfbToggle::On,
	'on'
))->setHelp('Default: <strong>off</strong> (one rule per selected interface). When enabled, one floating rule covers all selected interfaces instead of one rule each.'
		. '<div class="infoblock">A single floating rule (direction <strong>in</strong>, quick) is created over all selected interfaces. '
		. 'The action, interface selection, and exception alias all apply unchanged.</div>');


$section->add(pfb_form_subhdr('DNS over HTTPS/TLS/QUIC'));

$section->addInput(new Form_Select(
	'safesearch_doh',
	gettext('DoH/DoT/DoQ Blocking'),
	$pconfig['safesearch_doh'],
	$options_safesearch_doh
))->setHelp('Block well-known DNS over HTTPS/TLS/QUIC (DoH/DoT/DoQ) providers.'
		. '<div class="infoblock">Modern browsers and devices often use encrypted DNS that bypasses DNSBL; blocking these providers keeps clients on the local resolver so DNSBL stays effective. '
		. 'DNS requests to these domains will return NXDOMAIN. '
		. 'A DoH/DoT/DoQ <a href="/pfblockerng/pfblockerng_feeds.php" target="_blank" rel="noopener noreferrer">Feed</a> may cover more providers and update more often than this built-in list.</div>')
  ->setAttribute('style', 'width: auto');

$section->addInput(new Form_Select(
	'safesearch_doh_list',
	gettext('DoH/DoT/DoQ Blocking List'),
	$pconfig['safesearch_doh_list'],
	$options_safesearch_doh_list,
	TRUE
))->setHelp('Select the DoH/DoT/DoQ providers to block.')
  ->setAttribute('style', 'width: auto')
  ->setAttribute('size', '20');

$form->add($section);

$regex_text = pfb_dnsbl_regex_help_render();

$section = new Form_Section('Regex List', 'Python_regex_list', COLLAPSIBLE|SEC_CLOSED);
$section->addInput(new Form_Textarea(
	'pfb_regex_list',
	'Regex List',
	$pconfig['pfb_regex_list']
))->removeClass('form-control')
  ->addClass('row-fluid col-sm-12')
  ->setAttribute('columns', '90')
  ->setAttribute('rows', '15')
  ->setAttribute('wrap', 'off')
  ->setAttribute('style', 'width: 100%')
  ->setHelp($regex_text);

$form->add($section);

$noaaaa_text = 'List of no-AAAA domains to block the (IPv6) AAAA DNS Resolution.<br /><br />
		Enter a single domain per line.<br />
		Prefix domain with a "." to apply wildcard no-AAAA to all Sub-Domains. &emsp;IE: (.example.com)<br /><br />
		Any domain added to the no-AAAA list, will never be filtered by any DNSBL blocking.<br /><br />
		This List is stored as \'Base64\' format in the config.xml file.<br /><br />
		Changes to this option will require a Force Update to take effect.';

$section = new Form_Section('no-AAAA List', 'Python_noaaaa_list', COLLAPSIBLE|SEC_CLOSED);
$section->addInput(new Form_Textarea(
	'pfb_noaaaa_list',
	'no-AAAA List',
	$pconfig['pfb_noaaaa_list']
))->removeClass('form-control')
  ->addClass('row-fluid col-sm-12')
  ->setAttribute('columns', '90')
  ->setAttribute('rows', '15')
  ->setAttribute('wrap', 'off')
  ->setAttribute('style', 'width: 100%')
  ->setHelp($noaaaa_text);

$form->add($section);


$section = new Form_Section('DNS Caching', 'dnsbl_caches', COLLAPSIBLE|SEC_CLOSED);
$section->addInput(new Form_Checkbox(
	'pfb_cache',
	gettext('Resolver cache'),
	'Enable',
	pfb_dnsbl_toggle_enabled($pconfig['pfb_cache'] ?? NULL),
	'on'
))->setHelp('Default: <strong>Enabled</strong><br />Enable the backup and restore of the DNS Resolver Cache on DNSBL Update|Reload|Cron events');

$section->addInput(new Form_Checkbox(
	'pfb_cache_flush',
	gettext('Clear Resolver Cache'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['pfb_cache_flush']) === PfbToggle::On,
	'on'
))->setHelp('Default: <strong>Disabled</strong><br />Clear Unbound\'s resolver cache after a DNSBL update without restarting Unbound.'
	. '<div class="infoblock">When enabled, newly blocked domains take effect immediately when an allowed answer was already cached, but also discards unrelated answers and can temporarily increase DNS latency and upstream queries. '
	. 'When disabled, cached allowed answers remain until their DNS TTL expires. Resolver restarts already clear the cache; exact Alerts actions use targeted flushing.</div>');

$section->addInput(new Form_Input(
	'pfb_py_cache_max',
	gettext('Decision cache max entries'),
	'number',
	$pconfig['pfb_py_cache_max'],
	['min' => 0, 'max' => 5000000, 'placeholder' => '10000']
))->setHelp('Default: <strong>10000</strong><br />Maximum number of domains kept in the DNSBL per-domain decision cache.'
	. '<div class="infoblock">It is an <strong>LRU</strong> cache: frequently-queried domains stay resident and the least-recently-used entries are evicted at the cap. '
	. 'Roughly under 1 KB of RAM per entry. Set to <strong>0</strong> for unlimited (no eviction). '
	. 'Takes effect on the next DNSBL Reload.</div>');

// issue #1881: the "#Whitelist" page anchor that used to live here was its own empty
// Form_StaticText row -- every .form-group carries a theme border-bottom, so it drew a
// separator with nothing above it. Its only consumer, the dashboard widget, now links
// the DNSBL Whitelist section's own id (#DNSBL_Whitelist_customlist) instead.
$form->add($section);

$whitelist_text = 'No Regex Entries Allowed!&emsp;
			<div class="infoblock">
				Enter one &emsp; <strong>Domain Name</strong>&emsp; per line<br />
				Prefix Domain with a "." to Whitelist all Sub-Domains. &emsp;IE: (.example.com)<br />
				You may use "<strong>#</strong>" after any Domain name to add comments. &emsp;IE: (example.com # Whitelist example.com)<br />
				This List is stored as \'Base64\' format in the config.xml file.<br /><br />

				<span class="text-danger">Note: </span>These entries are only Whitelisted when Feeds are downloaded or on a
				<span class="text-danger">\'Force Reload\'.</span><br />

				Use the Alerts Tab \'+\' Whitelist Icon to immediately remove a Domain (and any associated CNAMES) from Unbound DNSBL.<br />
				Note: When manually adding a Domain to the Whitelist, check for any associated CNAMES<br />
				&emsp; ie: \'drill @8.8.8.8 example.com\'
			</div>';

$pfb_dnsbl_anchor_layout = pfb_dnsbl_anchor_layout_render();
$section = new Form_Section('DNSBL Whitelist', $pfb_dnsbl_anchor_layout['whitelist'], COLLAPSIBLE|SEC_CLOSED);
$section->addInput(new Form_Textarea(
	'whitelist',
	NULL,
	$pconfig['whitelist']
))->removeClass('form-control')
  ->addClass('row-fluid col-sm-12')
  ->setAttribute('columns', '90')
  ->setAttribute('rows', '15')
  ->setAttribute('wrap', 'off')
  ->setAttribute('style', 'width: 100%')
  ->setHelp($whitelist_text);

$form->add($section);

$section = new Form_Section('TOP1M Whitelist', 'TOP1M_Whitelist', COLLAPSIBLE|SEC_CLOSED);
$top1m_text = 'The TOP1M feed can be used to whitelist the most popular Domain names to avoid false positives.<br />
		Note: The domains listed in the TOP1M *may* be malicious in nature, consider limiting this feature.<br /><br />
		Whitelist(s) available:<br />

		<ul>
			<li><a target="_blank" rel="noopener noreferrer" href="https://tranco-list.eu/">Tranco TOP1M</a></li>
			<li><a target="_blank" rel="noopener noreferrer" href="https://s3-us-west-1.amazonaws.com/umbrella-static/index.html">Cisco Umbrella TOP1M</a></li>
			<li><a target="_blank" rel="noopener noreferrer" href="https://openpagerank.keywordseverywhere.com/top-10-million-domains">OpenPageRank TOP1M</a></li>
			<li><a target="_blank" rel="noopener noreferrer" href="https://majestic.com/reports/majestic-million">Majestic Million TOP1M</a> --
				distributed under the <strong>Creative Commons Attribution (CC BY) 3.0</strong> License by:
				<a target="_blank" rel="noopener noreferrer" href="https://majestic.com">Majestic</a>, attribution required.</li>
			<li><a target="_blank" rel="noopener noreferrer" href="https://radar.cloudflare.com/domains">Cloudflare Radar</a> --
				distributed under the <strong>Creative Commons Attribution-NonCommercial (CC BY-NC) 4.0</strong> License by:
				<a target="_blank" rel="noopener noreferrer" href="https://www.cloudflare.com">Cloudflare</a>, non-commercial use, attribution required.
				Requires a free <a target="_blank" rel="noopener noreferrer" href="https://developers.cloudflare.com/fundamentals/api/get-started/create-token/">Cloudflare API Token</a>
				entered below.</li>
		</ul>
		To use this feature, select the number of \'Top Domains\' to whitelist. You can also \'include\' which TLDs to whitelist.

		<div class="infoblock">
			<span class="text-danger">Recommendation: </span>
			<ul>TOP1M also contains the \'Top\' AD Servers, so its recommended to configure the first DNSBL Alias with AD Server<br />
				(ie. yoyo, Adaway...) based feeds. TOP1M whitelisting can be disabled for this first defined Alias.<br /><br />
				Generally, TOP1M should be used for feeds that post full URLs like PhishTank, OpenPhish or MalwarePatrol.<br /><br />
				To bypass a TOP1M Domain, add the Domain to the first defined Alias \'Custom Block list\' with TOP1M disabled in this alias.<br />
				When enabled, this list will be automatically updated once per month along with the MaxMind Database.
			</ul>
		</div>';

$section->addInput(new Form_Checkbox(
	'top1m_enable',
	gettext('TOP1M'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['top1m_enable']) === PfbToggle::On,
	'on'
))->setHelp($top1m_text);

$section->addInput(new Form_Select(
	'top1m_source',
	gettext('Type'),
	$pconfig['top1m_source'],
	$options_top1m_source
))->setHelp('Default: Tranco TOP1M. To change the TOP1M type, select the type and Save, then run an Update -- this marks the source for reprocessing.');

// ADR-59: masked, write-only token for a token-authenticated provider (currently only
// Cloudflare Radar). Never populated from the stored value -- $pconfig['top1m_token'] is
// only ever set here from a redisplayed $_POST on a validation error (like every other
// field), never from PfbConfig::read(), so a plain GET always renders this field blank.
// The JS toggle below (enable_top1m_token) shows it only for a provider whose 'auth' needs it.
$section->addInput(new Form_Input(
	'top1m_token',
	gettext('API Token'),
	'password',
	$pconfig['top1m_token'] ?? '',
	['placeholder' => 'Enter your Cloudflare Radar API Token -- leave blank to keep the current token']
))->setHelp('Required for Cloudflare Radar. Leave blank on Save to keep the existing token. '
		. 'Applies when the selected Type requires an API token.'
		. '<div class="infoblock">The stored token is never displayed here.</div>')
  ->setAttribute('autocomplete', 'off');

$section->addInput(new Form_Select(
	'top1m_count',
	gettext('Domain count'),
	$pconfig['top1m_count'],
	$options_top1m_count
))->sethelp('<strong>Default: Top 1k</strong><br />Select the <strong>number</strong> of TOP1M \'Top Domain global ranking\' to whitelist.');

$section->addInput(new Form_Select(
	'top1m_inclusion',
	gettext('TLD Inclusion'),
	$pconfig['top1m_inclusion'],
	$options_top1m_inclusion,
	TRUE
))->setHelp('Select the TLDs for Whitelist. (Only showing the Top 150 TLDs)<br />'
		. '<strong>Default: COM, NET, ORG, CA, CO, IO</strong><br /><br />'
		. 'Detailed listing : <a target=_blank rel="noopener noreferrer" href="http://www.iana.org/domains/root/db">Root Zone Top-Level Domains.</a>'
)->setAttribute('size', '20')
 ->setWidth(3);

$form->add($section);

$section = new Form_Section('TLD Exclusion List', 'TLD_Exclusion', COLLAPSIBLE|SEC_CLOSED);
$tld_exclusion_text = 'Enter TLD(s) and/or Domain(s) to be excluded from the TLD function. These excluded TLDs/domains/sub-domains will be listed as-is.&emsp;
			<div class="infoblock">
				Enter one &emsp; <strong>Domain Name or TLD</strong>&emsp; per line<br />
				No Regex Entries and no leading/trailing \'dot\' allowed!<br />
				You may use "<strong>#</strong>" after any Domain/TLD to add comments. &emsp;<br />
				IE: (example.com # Exclude example.com)<br />
				IE: (co.uk # Exclude CO.UK)<br />
				This List is stored as \'Base64\' format in the config.xml file.<br /><br />
			</div>';

$section->addInput(new Form_Textarea(
	'tld_wildcard_exclusion',
	'TLD Exclusion List',
	$pconfig['tld_wildcard_exclusion']
))->removeClass('form-control')
  ->addClass('row-fluid col-sm-12')
  ->setAttribute('columns', '90')
  ->setAttribute('rows', '15')
  ->setAttribute('wrap', 'off')
  ->setAttribute('style', 'width: 100%')
  ->setHelp($tld_exclusion_text);

$form->add($section);

$section = new Form_Section('TLD Blacklist', 'TLD_BW_list', COLLAPSIBLE|SEC_CLOSED);

$section->addInput(new Form_StaticText(
	'Note:',
	'The TLD Blacklist is used to block a whole TLD (IE: pw).<br /><br />'
	. '<span class="text-danger">Note:</span><br />'
	. 'TLD Blacklist: A <strong>static</strong> zone entry is used in the DNS Resolver for this feature, therefore no Alerts will be generated.<br />'
));

$tld_blacklist_text = 'Enter TLD(s) to be blacklisted.&emsp;
			<div class="infoblock">
				Enter one &emsp; <strong>TLD</strong>&emsp; per line. ie: xyz<br />
				No Regex Entries and no leading/trailing \'dot\' allowed!<br />
				You may use "<strong>#</strong>" after any TLD to add comments. example (xyz # Blacklist XYZ TLD)<br />
				This List is stored as \'Base64\' format in the config.xml file.<br /><br />
			</div>';

$section->addInput(new Form_Textarea(
	'tld_wildcard_blacklist',
	'TLD Blacklist',
	$pconfig['tld_wildcard_blacklist']
))->removeClass('form-control')
  ->addClass('row-fluid col-sm-12')
  ->setAttribute('columns', '90')
  ->setAttribute('rows', '15')
  ->setAttribute('wrap', 'off')
  ->setAttribute('style', 'width: 100%')
  ->setHelp($tld_blacklist_text);

$form->add($section);

$section = new Form_Section('DNSBL IPs', 'dnsbl_ips', COLLAPSIBLE|SEC_CLOSED);
$section->addInput(new Form_StaticText(
	NULL,
	'When literal IP addresses are found in any Domain based Feed, those IPs are added to the <strong>pfB_DNSBLIP_v4</strong> / <strong>pfB_DNSBLIP_v6</strong> IP Aliastables and<br />'
	. ' a firewall rule will be added to block those IPs.<br /><br />'
	. 'IPv6 entries appear only when a Feed lists literal IPv6 addresses (uncommon); an empty <strong>pfB_DNSBLIP_v6</strong> does not mean the blocked Domains have no IPv6 &#8212; the Domain itself is sinkholed at the DNS layer for both A and AAAA queries.<br /><br />'
	. '<span class="text-danger">Note: </span>To utilize this feature, select the appropriate List Action and define the Inbound/Outbound Interfaces in the <strong>IP Tab</strong>.'
));

$list_action_text = 'Default: <strong>Disabled</strong>
			<div class="infoblock">
				Select the <strong>Action</strong> for Firewall Rules when any DNSBL Feed contain IP addresses.<br /><br />
				<strong><u>\'Disabled\' Rule:</u></strong> Disables selection and does nothing to selected Alias.<br /><br />

				<strong><u>\'Deny\' Rules:</u></strong><br />
				\'Deny\' rules create high priority \'block\' or \'reject\' rules on the stated interfaces.
				 They don\'t change the \'pass\' rules on other interfaces. Typical uses of \'Deny\' rules are:<br />

				<ul>
				<li><strong>Deny Both</strong> - blocks all traffic in both directions, if the source or destination IP is in the block list</li>
				<li><strong>Deny Inbound/Deny Outbound</strong> - blocks all traffic in one direction <u>unless</u> it is part of a session started by
				traffic sent in the other direction. Does not affect traffic in the other direction.</li>
				<li>One way \'Deny\' rules can be used to selectively block <u>unsolicited</u> incoming (new session) packets in one direction, while
				still allowing <u>deliberate</u> outgoing sessions to be created in the other direction.</li>
				</ul>

				<strong><u>\'Alias\' Rules:</u></strong><br />
				\'Alias\' rules create an <a href="/firewall_aliases.php">alias</a> for the list without adding any firewall rules.
				 This enables a pfBlockerNG list to be used by name, in any firewall rule or pfSense function, as desired.<br />

				<ul>
				<li><strong>Alias Deny</strong> - the IPs are added to the alias and can use the De-Duplication and Reputation
				processes (if configured).</li>
				<li><strong>Alias Native</strong> - the IPs are kept in their Native format without any modifications
				(De-Duplication and Reputation are bypassed).</li>
				</ul>
			</div>';

$section->addInput(new Form_Select(
	'action',
	gettext('List Action'),
	$pconfig['action'],
	$options_action
))->setHelp($list_action_text);

$section->addInput(new Form_Select(
	'aliaslog',
	gettext('Enable Logging'),
	$pconfig['aliaslog'],
	$options_aliaslog
))->sethelp('Default: <strong>Enable</strong><br />Select - Logging to Status: System Logs: FIREWALL ( Log )<br />'
		. 'This can be overriden by the \'Force Global IP Logging\' option on the IP Tab. '
		. 'Applies when List Action is not Disabled.'
);
$form->add($section);

// Print Advanced Firewall Rule Settings (Inbound and Outbound) section
foreach (array( 'In' => 'Source', 'Out' => 'Destination') as $adv_mode => $adv_type) {
	$advmode = strtolower($adv_mode);

	$section = new Form_Section("DNSBL IPs - Advanced {$adv_mode}bound Firewall Rule Settings", "adv{$advmode}boundsettings", COLLAPSIBLE|SEC_CLOSED);
	$section->addInput(new Form_StaticText(
		null,
		"<span class=\"text-danger\">Note:</span>&nbsp; In general, Auto-Rules are created as follows:<br />
			<dl class=\"dl-horizontal\">
				<dt>{$adv_mode}bound</dt><dd>'any' port, 'any' protocol, 'any' destination and 'any' gateway</dd>
			</dl>
			Configuring the Adv. {$adv_mode}bound Rule settings, will allow for more customization of the {$adv_mode}bound Auto-Rules.")
		)->addClass('dnsbl_ip');

	$section->addInput(new Form_Checkbox(
		'autoaddrnot_' . $advmode,
		"Invert {$adv_type}",
		NULL,
		pfb_cfg_toggle_read($pconfig['autoaddrnot_' . $advmode] ?? NULL) === PfbToggle::On,
		'on'
	))->setHelp("Option to invert the sense of the match. ie - Not (!) {$adv_type} Address(es)")
	  ->addClass('dnsbl_ip');

	$group = new Form_Group("Custom DST Port");
	$group->add(new Form_Checkbox(
		'autoports_' . $advmode,
		'Custom DST Port',
		NULL,
		pfb_cfg_toggle_read($pconfig['autoports_' . $advmode] ?? NULL) === PfbToggle::On,
		'on'
	))->setHelp('Enable')
	  ->setWidth(2)
	  ->addClass('dnsbl_ip');

	$group->add(new Form_Input(
		'aliasports_' . $advmode,
		'Custom Port',
		'text',
		$pconfig["aliasports_{$advmode}"]
	))->setHelp("<a target=\"_blank\" href=\"/firewall_aliases.php?tab=port\">Click Here to add/edit Aliases</a>
			Do not manually enter port numbers.<br />Do not use 'pfB_' in the Port Alias name."
	)->setWidth(8)
	 ->addClass('dnsbl_ip');
	$section->add($group);

	if ($adv_type == 'Source') {
		$custom_location = 'Destination';
	} else {
		$custom_location = 'Source';
	}

	$group = new Form_Group("Custom {$custom_location}");
	$group->add(new Form_Checkbox(
		'autoaddr_' . $advmode,
		"Custom {$custom_location}",
		NULL,
		pfb_cfg_toggle_read($pconfig["autoaddr_{$advmode}"] ?? NULL) === PfbToggle::On,
		'on'
	))->setHelp('Enable')->setWidth(1)
	  ->addClass('dnsbl_ip');

	$group->add(new Form_Checkbox(
		'autonot_' . $advmode,
		NULL,
		NULL,
		pfb_cfg_toggle_read($pconfig["autonot_{$advmode}"] ?? NULL) === PfbToggle::On,
		'on'
	))->setHelp('Invert')->setWidth(1)
	  ->addClass('dnsbl_ip');

	$group->add(new Form_Input(
		'aliasaddr_' . $advmode,
		"Custom {$custom_location}",
		'text',
		$pconfig['aliasaddr_' . $advmode]
	))->sethelp('<a target="_blank" rel="noopener noreferrer" href="/firewall_aliases.php?tab=ip">Click Here to add/edit Aliases</a>'
		. 'Do not manually enter Addresses(es).<br />Do not use \'pfB_\' in the address-type (Host/Network/URL/URL Table) Alias name.<br />'
		. "Select 'invert' to invert the sense of the match. ie - Not (!) {$custom_location} Address(es)"
	)->setWidth(8)
	 ->addClass('dnsbl_ip');
	$section->add($group);

	$group = new Form_Group('Custom Protocol');
	$group->add(new Form_Select(
		'autoproto_' . $advmode,
		NULL,
		$pconfig['autoproto_' . $advmode],
		$options_autoproto_in
	))->setHelp("<strong>Default: any</strong><br />Select the Protocol used for {$adv_mode}bound Firewall Rule(s).<br />
		<span class=\"text-danger\">Note:</span>&nbsp;Do not use 'Any' with Adv. {$adv_mode}bound Rules as it will bypass these settings!")
	  ->addClass('dnsbl_ip');
	$section->add($group);

	$group = new Form_Group('Custom Gateway');
	$group->add(new Form_Select(
		'agateway_' . $advmode,
		NULL,
		$pconfig['agateway_' . $advmode],
		$options_agateway_in
	))->setHelp("Select alternate Gateway or keep 'default' setting.")
	  ->addClass('dnsbl_ip');

	$section->add($group);
	$form->add($section);
}

print ($form);
print_callout('<strong>Setting changes are applied via CRON or \'Force Update|Reload\' only!</strong>');

?>
<?=$pfb_dnsbl_editor['asset']?>
<script type="text/javascript">
//<![CDATA[

var pagetype = 'advanced';

// Auto-Complete for Adv. In/Out Address Select boxes
var plist = "<?=$ports_list?>";
var portsarray = plist.split(',');
var nlist = "<?=$networks_list?>";
var networksarray = nlist.split(',');

// Disable GeoIP/ASN Autocomplete as not required for the DNSBL page
var geoiparray = 'disabled';

// [ ADR-36/37 ] Address-type firewall alias names for the Exception Alias autocomplete.
var pfb_alias_names = <?=$pfb_alias_names_json?>;

// Wire jQuery-UI autocomplete onto the DNS Redirect + DoT/DoQ Block exception fields so a
// valid alias name can be picked rather than typed (a typo there used to save and then emit
// an unresolvable "from !" rule that broke the whole ruleset). minLength 0 + the focus search
// shows the full alias list on focus.
function pfb_redir_exclude_autocomplete() {
	$('#dnsbl_redir_exclude, #dnsbl_dot_block_exclude')
		.autocomplete({ minLength: 0, source: pfb_alias_names })
		.on('focus', function() { $(this).autocomplete('search', $(this).val()); });
}

// [ ADR-36/37 ] Quick-fill: union of pfBlockerNG Inbound + Outbound interfaces, shared by the
// DNS Redirect and DoT/DoQ Block sections (same underlying interface list -- ADR-37 aliases
// the ADR-36 set here rather than recomputing it server-side).
var pfb_redir_fill_ifaces = <?=$pfb_redir_fill_json?>;
var pfb_dot_block_fill_ifaces = pfb_redir_fill_ifaces;

function pfb_fill_interfaces(selectName, fillSet) {
	// Set the multi-select to exactly the fill set (deselects the rest). .val([...]) is the
	// reliable jQuery idiom for a <select multiple>; trigger('change') notifies any listeners.
	// NOTE: a pfSense multi-select renders id (and name) as "<field>[]", so the bracket-free
	// id selector "#<field>" matches nothing — target it by name instead (this is why the
	// button previously appeared to do nothing).
	$('select[name="' + selectName + '[]"]').val(fillSet).trigger('change');
}

// [ ADR-13 ] Address(es) the package would auto-create for the selected interface, so
// the "Create VIPs automatically" checkbox can pre-fill the (display-only) VIP fields.
// Empty string => no candidate / family not required.
var pfb_auto_vip4 = "<?=htmlspecialchars($pfb_auto_vip4 ?? '', ENT_QUOTES)?>";
var pfb_auto_vip6 = "<?=htmlspecialchars($pfb_auto_vip6 ?? '', ENT_QUOTES)?>";

// [ ADR-13 ] On check: pre-fill the VIP dropdown(s) with the address pfBlockerNG would
// create (a synthetic, selected option for display) and disable the manual dropdowns; on
// uncheck: remove the synthetic option, restore the prior manual selection, and re-enable.
function enable_dnsvip_auto() {
	var on = $('#pfb_dnsvip_auto').prop('checked');
	var fields = [['pfb_dnsvip4', pfb_auto_vip4], ['pfb_dnsvip6', pfb_auto_vip6]];
	$.each(fields, function(i, f) {
		var id = f[0], addr = f[1];
		var $sel = $('#' + id);
		if (on) {
			// Remember the manual selection once, then show the auto address.
			if (typeof $sel.data('pfbManualVal') === 'undefined') {
				$sel.data('pfbManualVal', $sel.val());
			}
			$sel.find('option.pfb-auto-opt').remove();
			if (addr !== '') {
				$sel.append($('<option>', { 'class': 'pfb-auto-opt', value: '_pfb_auto', text: addr }));
				$sel.val('_pfb_auto');
			}
			disableInput(id, true);
		} else {
			disableInput(id, false);
			$sel.find('option.pfb-auto-opt').remove();
			if (typeof $sel.data('pfbManualVal') !== 'undefined') {
				$sel.val($sel.data('pfbManualVal'));
				$sel.removeData('pfbManualVal');
			}
		}
	});
}

function enable_tld() {
	if ($('#tld_wildcard').prop('checked')) {
		$('#TLD_Exclusion').show();
		$('#TLD_BW_list').show();
		disableInput('pfb_psl_include_private', false);
	} else {
		$('#TLD_Exclusion').hide();
		$('#TLD_BW_list').hide();
		disableInput('pfb_psl_include_private', true);
	}
}

function enable_ports() {
	if ($('#dnsbl_interface').val() == 'lo0') {
		disableInput('pfb_dnsport', true);
		disableInput('pfb_dnsport_ssl', true);
	} else {
		disableInput('pfb_dnsport', false);
		disableInput('pfb_dnsport_ssl', false);
	}
}

function enable_tld_allow() {
	if ($('#tld_allow').prop('checked')) {
		$('#tld_allow_pickers').show();
		disableInput('pfb_psl_allow_private', false);
	} else {
		$('#tld_allow_pickers').hide();
		disableInput('pfb_psl_allow_private', true);
	}
}

function enable_idn_mode() {
	// ADR-08: the two Confusable sub-toggles apply only in Confusable mode.
	if ($('#pfb_idn').val() == 'confusable') {
		hideCheckbox('pfb_idn_block_malicious', false);
		hideCheckbox('pfb_idn_escalate_suspicious', false);
	} else {
		hideCheckbox('pfb_idn_block_malicious', true);
		hideCheckbox('pfb_idn_escalate_suspicious', true);
	}
}

// ADR-59: providers whose 'auth' needs a token, derived server-side from the
// descriptor table (pfb_top1m_providers()) -- a future token provider needs no JS edit.
var pfb_top1m_token_providers = <?=$pfb_top1m_token_providers_json?>;

function enable_top1m_token() {
	disableInput('top1m_token', pfb_top1m_token_providers.indexOf($('#top1m_source').val()) === -1);
}

function enable_python_regex() {
	if ($('#pfb_regex').prop('checked')) {
		$('#Python_regex_list').show();
		hideCheckbox('pfb_regex_cap', false);
	} else {
		$('#Python_regex_list').hide();
		hideCheckbox('pfb_regex_cap', true);
	}
}

function enable_python_noaaaa() {
	if ($('#pfb_noaaaa').prop('checked')) {
		$('#Python_noaaaa_list').show();
	} else {
		$('#Python_noaaaa_list').hide();
	}
}

function enable_python_gp() {
	if ($('#pfb_gp').prop('checked')) {
		$('#Python_Group_Policy').show();
	} else {
		$('#Python_Group_Policy').hide();
	}
}

function enable_dnsblip() {
	if ($('#action').val() != 'Disabled') {
		disableInput('aliaslog', false);
		$('#advinboundsettings').show();
		$('#advoutboundsettings').show();
	} else {
		disableInput('aliaslog', true);
		$('#advinboundsettings').hide();
		$('#advoutboundsettings').hide();
	}
}

events.push(function(){
<?=$pfb_dnsbl_editor['regex']?>
<?=$pfb_dnsbl_editor['lists']?>

	$('#tld_wildcard').click(function() {
		enable_tld();
	});
	enable_tld();

	$('#dnsbl_interface').click(function() {
		enable_ports();
	});
	enable_ports();

	$('#tld_allow').click(function() {
		enable_tld_allow();
	});
	enable_tld_allow();

	$('#pfb_idn').change(function() {
		enable_idn_mode();
	});
	enable_idn_mode();

	$('#top1m_source').change(function() {
		enable_top1m_token();
	});
	enable_top1m_token();

	$('#pfb_regex').on('click change', function() {
		enable_python_regex();
	});
	enable_python_regex();

	$('#pfb_noaaaa').click(function() {
		enable_python_noaaaa();
	});
	enable_python_noaaaa();

	$('#pfb_gp').click(function() {
		enable_python_gp();
	});
	enable_python_gp();

	$('#action').click(function() {
		enable_dnsblip();
	});
	enable_dnsblip();

	var pfb_gated_ids = [
		'pfb_psl_include_private', 'pfb_dnsport', 'pfb_dnsport_ssl',
		'pfb_psl_allow_private', 'top1m_token', 'aliaslog'
	];
	$('form').submit(function() {
		$.each(pfb_gated_ids, function(_, id) {
			disableInput(id, false);
		});
	});

	$('#pfb_dnsvip_auto').click(function() {
		enable_dnsvip_auto();
	});
	enable_dnsvip_auto();

	(function() {
		var $title = $('#pfb_dnsbl').closest('.panel').children('.panel-heading').find('.panel-title').first();
		if (!$title.length) {
			return;
		}
		var $btn = $('<button type="button" id="pfb_expand_all" class="btn btn-xs btn-default pull-right">Expand all</button>');
		$title.append($btn);
		function collapses() {
			return $('form .panel-body.collapse');
		}
		function anyClosed() {
			return collapses().filter(':not(.in)').length > 0;
		}
		function syncLabel() {
			$btn.text(anyClosed() ? 'Expand all' : 'Collapse all');
		}
		$btn.on('click', function(e) {
			e.preventDefault();
			collapses().collapse(anyClosed() ? 'show' : 'hide');
			syncLabel();
		});
		$('form').on('shown.bs.collapse hidden.bs.collapse', syncLabel);
		syncLabel();
	})();

	pfb_redir_exclude_autocomplete();
});

//]]>
</script>
<?=pfb_dnsbl_js_asset_render()?>
<?php include('foot.inc');?>

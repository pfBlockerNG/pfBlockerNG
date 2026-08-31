<?php
/*
 * pfblockerng_ip.php
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

$pfb['iconfig'] = PfbConfig::readSection('installedpackages/pfblockerngipsettings/config/0');

// issue #1875 step 2b: gate the CM6 live-highlight overlay for v4suppression/v6suppression,
// same $pfb_syntaxhl_on idiom pfblockerng_dnsbl.php establishes at its line 38.
$pfb_syntaxhl_on = pfb_editor_enabled();

$pfb_ip_editor = pfb_ip_editor_render($pfb_syntaxhl_on);

$pconfig = array();
// issue #2123: the seven checkbox defaults below are owned by the registry (ADR-29),
// not restated here; PfbConfig::read() applies each one when the key is absent and
// returns the PfbToggle the render compares. A validation-error redisplay replaces
// $pconfig with raw $_POST (see below), so the renders still run the value through
// the toggle read adapter -- that call is the POST-redisplay adapter, not a second
// declaration of the default.
$pconfig['enable_dup']		= PfbConfig::read('ip/enable_dup');
$pconfig['enable_agg']		= PfbConfig::read('ip/enable_agg');

// ADR-11: opt-in per-type aggregate ("Uber") aliases. CSV scalar, gateway-registered
// (general section); presented here beside CIDR Aggregation. Default none -> [''] selects
// nothing in the multi-select. Options defined here (before the POST handler) so the
// save-time sanitiser and the rendered select share one source of allowed values.
// Stored VALUES are Deny/Permit/Match/Native; Native's label keeps "Alias Native".
$options_pfb_agg_types		= [ 'Deny' => 'Deny', 'Permit' => 'Permit', 'Match' => 'Match', 'Native' => 'Alias Native' ];
$pconfig['pfb_agg_types']	= explode(',', (string) PfbConfig::read('gen/pfb_agg_types'));

// ADR-40: alias-table apply mode (gateway-registered, general section).
$options_pfb_alias_delta_mode	= [ 'auto' => 'Auto (delta for small churn, replace for large)', 'delta' => 'Delta (-T add/-T delete)', 'replace' => 'Replace (-T replace, pre-4.0 behaviour)' ];
$pconfig['pfb_alias_delta_mode']	= (string) PfbConfig::read('gen/pfb_alias_delta_mode')->toStored();
$pconfig['pfb_alias_delta_batch']	= pfb_alias_delta_batch_clamp((string) PfbConfig::read('gen/pfb_alias_delta_batch'));

// Default 'on' owned by the registry (ADR-29, issue #1907); PfbConfig::read applies it
// when absent.
$pconfig['suppression']		= PfbConfig::read('ip/suppression');

$pconfig['enable_log']		= PfbConfig::read('ip/enable_log');
$pconfig['enable_rdns']		= PfbConfig::read('ip/enable_rdns');
$pconfig['ip_placeholder']	= $pfb['iconfig']['ip_placeholder']			?: '127.1.7.7';
$pconfig['maxmind_locale']	= $pfb['iconfig']['maxmind_locale']			?: 'en';
$pconfig['asn_reporting']	= $pfb['iconfig']['asn_reporting']			?: 'disabled';
// issue #2922: asn_token is masked/write-only; never load the stored token into the form.
$pconfig['asn_token']		= $_POST['asn_token'] ?? '';
$pconfig['database_cc']		= PfbConfig::read('ip/database_cc');
$pconfig['maxmind_account']	= $pfb['iconfig']['maxmind_account']			?: '';
// issue #924: maxmind_key is masked/write-only -- never populate it from the stored value.
// A GET renders blank; a validation-error redisplay preserves the just-typed $_POST value
// (like every other field), never PfbConfig/iconfig.
$pconfig['maxmind_key']		= $_POST['maxmind_key'] ?? '';
$pconfig['inbound_interface']	= pfb_csv_list($pfb['iconfig']['inbound_interface'] ?? NULL);
$pconfig['inbound_deny_action']	= $pfb['iconfig']['inbound_deny_action']		?: 'block';
$pconfig['outbound_interface']	= pfb_csv_list($pfb['iconfig']['outbound_interface'] ?? NULL);
$pconfig['outbound_deny_action']= $pfb['iconfig']['outbound_deny_action']		?: 'reject';
$pconfig['enable_float']	= PfbConfig::read('ip/enable_float');
$pconfig['pass_order']		= $pfb['iconfig']['pass_order']				?: 'order_0';
$pconfig['autorule_suffix']	= $pfb['iconfig']['autorule_suffix']			?: 'autorule';
$pconfig['killstates']		= PfbConfig::read('ip/killstates');
$pconfig['v4suppression']	= pfb_b64_text($pfb['iconfig']['v4suppression'] ?? NULL);
// ADR-53 review finding B: '?? ""' on the array read -- v6suppression (unlike
// v4suppression) is NEVER install-migrated, so it is absent from config.xml
// on every install until this page's first post-upgrade save.
$pconfig['v6suppression']	= pfb_b64_text($pfb['iconfig']['v6suppression'] ?? NULL);

// Select array options
$options_asn_reporting 		= [	'disabled'	=> 'Disabled',
					'week'		=> 'Enabled - ASN entries cached for 1 week',
					'24hour'	=> 'Enabled - ASN entries cached for 24 hours',
					'12hour'	=> 'Enabled - ASN entries cached for 12 hours',
					'4hour'		=> 'Enabled - ASN entries cached for 4 hours',
					'1hour'		=> 'Enabled - ASN entries cached for 1 hour' ];

$options_maxmind_locale		= [	'en' => 'English', 'fr' => 'French', 'pt-BR' => 'Brazilian Portuguese', 'de' => 'German',
					'ja' => 'Japanese', 'zh-CN' => 'Simplified Chinese', 'es' => 'Spanish' ];

$options_inbound_interface	= $options_outbound_interface		= pfb_build_if_list(TRUE, FALSE);
$options_inbound_deny_action	= $options_outbound_deny_action		= [ 'block' => 'Block', 'reject' => 'Reject' ];
$options_interface_cnt		= count($options_inbound_interface) ?: '1';

$options_pass_order		= [	'order_0' => '| pfB_Pass/Match/Block/Reject | All other Rules | (Default format)',
					'order_1' => '| pfSense Pass/Match | pfB_Pass/Match | pfB_Block/Reject | pfSense Block/Reject |',
					'order_2' => '| pfB_Pass/Match | pfSense Pass/Match | pfB_Block/Reject | pfSense Block/Reject |',
					'order_3' => '| pfB_Pass/Match | pfB_Block/Reject | pfSense Pass/Match | pfSense Block/Reject |',
					'order_4' => '| pfB_Pass/Match | pfB_Block/Reject | pfSense Block/Reject | pfSense Pass/Match |' ];

$options_autorule_suffix = [ 'autorule' => 'auto rule', 'standard' => 'Null (no suffix)', 'ar' => 'AR' ];

// $input_errors is read unconditionally in the render section below, so it must be
// defined on every request path (incl. a POST without 'save'). Initialise it once.
$input_errors = array();

// Validate input fields and save
if ($_POST) {
	if (isset($_POST['save'])) {

		unset($savemsg);

		// issue #1777: reject an array-valued field ('asn_token[]=x') before any
		// string sink below Array-to-string-converts on it -- same idea as
		// pfblockerng_category_edit.php (issue #1106), but NOT the same guard
		// shape: unlike category_edit, this page has genuine multi-select fields
		// -- pfSense's Form_Select(..., TRUE) appends '[]' to the POST name, so a
		// real browser legitimately posts those as arrays and a guard over every
		// $_POST key would reject and blank them on every save. Excluding the
		// multi-selects (a small, stable set this page owns) rather than listing
		// the scalar fields keeps every present and future scalar field covered:
		// beyond the #1723 sanitize loops below, pfb_alias_delta_mode reaches
		// array_key_exists(), which is a fatal TypeError on an array, and
		// pfb_alias_delta_batch reaches a (string) cast.
		$pfb_multiselect_fields = array('inbound_interface', 'outbound_interface', 'pfb_agg_types');
		foreach (array_keys($_POST) as $pfb_post_field) {
			if (!is_scalar($_POST[$pfb_post_field]) && !in_array($pfb_post_field, $pfb_multiselect_fields, TRUE)) {
				$input_errors[] = gettext('Invalid value submitted for field:') . ' ' . htmlspecialchars($pfb_post_field);
				$_POST[$pfb_post_field] = '';
			}
		}

		// issue #1723: sanitize at ingestion -- first step, before any evaluation.
		foreach (array('ip_placeholder', 'asn_token', 'autorule_suffix', 'maxmind_account', 'maxmind_key') as $pfb_text_field) {
			$_POST[$pfb_text_field] = pfb_sanitize_text((string) ($_POST[$pfb_text_field] ?? ''));
		}
		foreach (array('v4suppression', 'v6suppression') as $pfb_text_area_field) {
			$_POST[$pfb_text_area_field] = pfb_sanitize_text_area((string) ($_POST[$pfb_text_area_field] ?? ''));
		}

		// Validate Select field options
		$select_options = array(	'asn_reporting'		=> 'disabled',
						'maxmind_locale'	=> 'en',
						'inbound_deny_action'	=> 'block',
						'outbound_deny_action'	=> 'reject',
						'pass_order'		=> 'order_0', 
						'autorule_suffix'	=> 'autorule'
						);

		foreach ($select_options as $s_option => $s_default) {
			if (is_array($_POST[$s_option])) {
				$_POST[$s_option] = $s_default;
			}
			elseif (!array_key_exists($_POST[$s_option], ${"options_$s_option"})) {
				$_POST[$s_option] = $s_default;
			}
		}

		// Validate Placeholder IP address
		if (!is_ipaddrv4($_POST['ip_placeholder'])) {
			$input_errors[] = 'Placeholder IP: A valid IPv4 address must be specified.';
		}
		else {
			$ip_validate = where_is_ipaddr_configured($_POST['ip_placeholder'], '' , TRUE, TRUE, '');
			if (count($ip_validate)) {
				$input_errors[] = 'Placeholder IP: Address must be in an isolated Range that is not used in your Network.';
			}
		}

		if (!empty($_POST['maxmind_account']) && empty(pfb_filter($_POST['maxmind_account'], PFB_FILTER_WORD, 'ip'))) {
			$input_errors[] = 'MaxMind Account Invalid';
		}

		// issue #924: maxmind_key is masked/write-only -- a blank POST keeps the stored key, so
		// validate only a non-empty submission. Reference 'maxmind_key' suppresses pfb_filter()'s
		// failed-validation log line so the secret never reaches a log, even when rejected.
		// issue #1723: already sanitized by the ingestion prologue above -- plain read.
		$pfb_maxmind_key_post = (string) ($_POST['maxmind_key'] ?? '');
		if ($pfb_maxmind_key_post !== '' && empty(pfb_filter($pfb_maxmind_key_post, PFB_FILTER_WORD, 'maxmind_key'))) {
			$input_errors[] = 'MaxMind License key Invalid';
		}

		$pfb_asn_token_post = (string) ($_POST['asn_token'] ?? '');
		if ($pfb_asn_token_post !== '' && empty(pfb_filter($pfb_asn_token_post, PFB_FILTER_WORD, 'asn_token'))) {
			$input_errors[] = 'IPinfo Token Invalid';
		}

		// issue #1723: the ingestion prologue already normalized CRLF/CR to LF, so
		// per-line validation now splits on "\n" (the pre-#1723 "\r\n" split matched
		// a browser's raw CRLF submission; that separator no longer survives ingestion).
		$v4suppression = explode("\n", $_POST['v4suppression']);
		if (!empty($v4suppression)) {
			foreach ($v4suppression as $line) {
				$suppression_error = pfb_validate_suppression_line($line, 'ipv4');
				if ($suppression_error !== NULL) {
					$input_errors[] = $suppression_error;
				}
			}
		}

		// ADR-53: v6 sibling of the v4 validation above. explode() always returns a
		// non-empty array, so (unlike the v4 block above) this skips the vestigial
		// !empty() wrapper -- avoids replicating the pre-existing PHPStan
		// empty.variable finding baselined for v4suppression at the same call shape.
		foreach (explode("\n", $_POST['v6suppression']) as $line) {
			$suppression_error = pfb_validate_suppression_line($line, 'ipv6');
			if ($suppression_error !== NULL) {
				$input_errors[] = $suppression_error;
			}
		}

		// Apply MaxMind locale changes if required
		if (in_array($_POST['maxmind_locale'], array('en', 'fr', 'de', 'pt-BR', 'ja', 'zh-CN', 'es')) &&
		    in_array($pconfig['maxmind_locale'], array('en', 'fr', 'de', 'pt-BR', 'ja', 'zh-CN', 'es'))) {

			$maxmind	= $pconfig['maxmind_locale'];
			$p_maxmind	= $_POST['maxmind_locale'];

			if ($maxmind != $p_maxmind) {
				exec('/bin/ps -wx', $result_cron);
				if (!preg_grep("/pfblockerng[.]php\s+?(uc|gc|ugc)/", $result_cron)) {
					if (!$input_errors) {
						// Execute MaxMind update and generate pfSense Notice message on completion
						$maxmind_esc    = escapeshellarg($maxmind);
						$p_maxmind_esc  = escapeshellarg($p_maxmind);
						mwexec_bg("/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php ugc {$maxmind_esc} {$p_maxmind_esc} >> {$pfb['extraslog']} 2>&1");

						$savemsg = "The MaxMind language locale is being changed from [ {$maxmind_esc} to {$p_maxmind_esc} ]. "
							. "A pfSense Notice message will be submitted on completion.";
					}
				} else {
					$input_errors[] = 'MaxMind GeoIP conversion already in process!';
					$input_errors[] = 'Cannot change Language Locale at this time!';
				}
			}
		}
		else {
			$input_errors[] = 'MaxMind Locale is not valid!';
		}

		if (!$input_errors) {

			// issue #1907/#2123: an unchecked checkbox is absent from $_POST, and the
			// owner-ruled empty token is what PFB_FILTER_ON_OFF already emits for it;
			// writeSection() then normalises every registered key below through its
			// registered adapter.
			$pfb['iconfig']['enable_dup']		= pfb_filter($_POST['enable_dup'] ?? '', PFB_FILTER_ON_OFF, 'ip') ?: '';
			$pfb['iconfig']['enable_agg']		= pfb_filter($_POST['enable_agg'] ?? '', PFB_FILTER_ON_OFF, 'ip') ?: '';
			$pfb['iconfig']['suppression']		= pfb_filter($_POST['suppression'] ?? '', PFB_FILTER_ON_OFF, 'ip') ?: '';
			$pfb['iconfig']['enable_log']		= pfb_filter($_POST['enable_log'] ?? '', PFB_FILTER_ON_OFF, 'ip') ?: '';
			$pfb['iconfig']['enable_rdns']		= pfb_filter($_POST['enable_rdns'] ?? '', PFB_FILTER_ON_OFF, 'ip') ?: '';
			$pfb['iconfig']['ip_placeholder']	= $_POST['ip_placeholder']					?: '127.1.7.7';
			$pfb['iconfig']['maxmind_locale']	= $_POST['maxmind_locale']					?: 'en';
			$pfb['iconfig']['database_cc']		= pfb_filter($_POST['database_cc'] ?? '', PFB_FILTER_ON_OFF, 'ip') ?: '';
			$pfb['iconfig']['maxmind_account']	= pfb_filter($_POST['maxmind_account'], PFB_FILTER_WORD, 'ip')	?: '';
			// issue #924: blank keeps the existing stored key -- only overwrite on a non-empty
			// submission, never clear it via a blank re-post ($pfb['iconfig']['maxmind_key']
			// already holds the current stored value from the readSection() above).
			if ($pfb_maxmind_key_post !== '') {
				$pfb['iconfig']['maxmind_key'] = pfb_filter($pfb_maxmind_key_post, PFB_FILTER_WORD, 'maxmind_key') ?: '';
			}
			$pfb['iconfig']['asn_reporting']	= $_POST['asn_reporting']					?: 'disabled';
			if ($pfb_asn_token_post !== '') {
				$pfb['iconfig']['asn_token'] = $pfb_asn_token_post;
			}
			$pfb['iconfig']['inbound_interface']	= implode(',', (array)$_POST['inbound_interface'])		?: '';
			$pfb['iconfig']['inbound_deny_action']	= $_POST['inbound_deny_action']					?: '';
			$pfb['iconfig']['outbound_interface']	= implode(',', (array)$_POST['outbound_interface'])		?: '';
			$pfb['iconfig']['outbound_deny_action']	= $_POST['outbound_deny_action']				?: '';
			$pfb['iconfig']['enable_float']		= pfb_filter($_POST['enable_float'] ?? '', PFB_FILTER_ON_OFF, 'ip') ?: '';
			$pfb['iconfig']['pass_order']		= $_POST['pass_order']						?: 'order_0';
			$pfb['iconfig']['autorule_suffix']	= $_POST['autorule_suffix']					?: 'autorule';
			$pfb['iconfig']['killstates']		= pfb_filter($_POST['killstates'] ?? '', PFB_FILTER_ON_OFF, 'ip') ?: '';
			// issue #1723: already sanitized by the ingestion prologue -- plain encode.
			$pfb['iconfig']['v4suppression']	= base64_encode($_POST['v4suppression'] ?? '');
			$pfb['iconfig']['v6suppression']	= base64_encode($_POST['v6suppression'] ?? '');

			// ADR-11: per-type aggregate aliases multi-select -> CSV scalar (sanitised to the
			// known option keys; default none). Gateway-registered in the general section, so
			// written via PfbConfig::write (not the IP section blob). array_keys() keeps the
			// allowed set in lockstep with $options_pfb_agg_types (defined above).
			$agg_types_post	= array_values(array_intersect(
						array_keys($options_pfb_agg_types),
						(array) ($_POST['pfb_agg_types'] ?? array())));
			PfbConfig::write('gen/pfb_agg_types', implode(',', $agg_types_post));

			// ADR-40: alias-table apply mode (gateway-registered scalar).
			$delta_mode_post = array_key_exists($_POST['pfb_alias_delta_mode'] ?? '', $options_pfb_alias_delta_mode)
				? $_POST['pfb_alias_delta_mode']
				: 'auto';
			PfbConfig::write('gen/pfb_alias_delta_mode', $delta_mode_post);

			// ADR-40: batch size — clamp to [64, 4096].  An empty field (user
			// cleared the value) must default to 512, not cast to 0 and clamp to 64.
			$_pfb_batch_raw = trim((string) ($_POST['pfb_alias_delta_batch'] ?? ''));
			PfbConfig::write('gen/pfb_alias_delta_batch', (string) pfb_alias_delta_batch_resolve($_pfb_batch_raw));

			PfbConfig::writeSection('installedpackages/pfblockerngipsettings/config/0', $pfb['iconfig']);
			write_config('[pfBlockerNG] save IP settings');
			pfb_mark_pending_changes();	// applies on the next Update, not on save
			if (!empty($savemsg)) {
				header("Location: /pfblockerng/pfblockerng_ip.php?savemsg={$savemsg}");
			} else {
				header('Location: /pfblockerng/pfblockerng_ip.php');
			}
			exit;
		}
		else {
			$pconfig = $_POST;
		}
	}
}

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('IP'));
$pglinks = array('', '/pfblockerng/pfblockerng_ip.php', '@self');
$shortcut_section = 'pfblockerng';
include_once('head.inc');

if ($input_errors) {
	print_input_errors($input_errors);
}

// Define default Alerts Tab href link (Top row)
$get_req = pfb_alerts_default_page();

$tab_array	= array();
$tab_array[]	= array(gettext('General'),	FALSE,	'/pfblockerng/pfblockerng_general.php');
$tab_array[]	= array(gettext('IP'),		TRUE,	'/pfblockerng/pfblockerng_ip.php');
$tab_array[]	= array(gettext('DNSBL'),	FALSE,	'/pfblockerng/pfblockerng_dnsbl.php');
$tab_array[]	= array(gettext('Update'),	FALSE,	'/pfblockerng/pfblockerng_update.php');
$tab_array[]	= array(gettext('Reports'),	FALSE,	"/pfblockerng/pfblockerng_alerts.php{$get_req}");
$tab_array[]	= array(gettext('Feeds'),	FALSE,	'/pfblockerng/pfblockerng_feeds.php');
$tab_array[]	= array(gettext('Logs'),	FALSE,	'/pfblockerng/pfblockerng_log.php');
$tab_array[]	= array(gettext('Sync'),	FALSE,	'/pfblockerng/pfblockerng_sync.php');
pfb_software_add_tab($tab_array);
display_top_tabs($tab_array, TRUE);

$tab_array	= array();
$tab_array[]	= array(gettext('IPv4'),	FALSE,	'/pfblockerng/pfblockerng_category.php?type=ipv4');
$tab_array[]	= array(gettext('IPv6'),	FALSE,	'/pfblockerng/pfblockerng_category.php?type=ipv6');
$tab_array[]	= array(gettext('GeoIP'),	FALSE,	'/pfblockerng/pfblockerng_category.php?type=geoip');
$tab_array[]	= array(gettext('Reputation'),	FALSE,	'/pfblockerng/pfblockerng_reputation.php');
display_top_tabs($tab_array, TRUE);
pfb_print_pending_changes_box();

if (!$input_errors && isset($_REQUEST['savemsg'])) {
	$savemsg = htmlspecialchars($_REQUEST['savemsg']);
	print_info_box($savemsg);
}

$form = new Form('Save IP settings');

$section = new Form_Section('IP Configuration');
$section->addInput(new Form_StaticText(
	'Links',
	'<small>'
	. '<a href="/firewall_aliases.php" target="_blank" rel="noopener noreferrer">Firewall Aliases</a>&emsp;'
	. '<a href="/firewall_rules.php" target="_blank" rel="noopener noreferrer">Firewall Rules</a>&emsp;'
	. '<a href="/status_logs_filter.php" target="_blank" rel="noopener noreferrer">Firewall Logs</a></small>'
));

$section->addInput(new Form_Checkbox(
	'enable_dup',
	'De-Duplication',
	'Enable',
	pfb_cfg_toggle_read($pconfig['enable_dup'] ?? NULL) === PfbToggle::On,
	'on'
))->setHelp('Default: <strong>Off</strong><br />'
		. 'Remove duplicate IPv4 addresses across Deny lists so the same host is not listed more than once. '
		. 'Only used for IPv4 Deny Lists.');

$section->addInput(new Form_Checkbox(
	'enable_agg',
	'CIDR Aggregation',
	'Enable',
	pfb_cfg_toggle_read($pconfig['enable_agg'] ?? NULL) === PfbToggle::On,
	'on'
))->setHelp('Default: <strong>Off</strong><br />'
		. 'Optimise CIDRs - merge contiguous CIDRs into larger CIDR blocks.');

$section->addInput(new Form_Checkbox(
	'suppression',
	'Suppression',
	'Enable',
	pfb_ip_suppression_enabled($pconfig['suppression'] ?? NULL),
	'on'
))->setHelp('Default: <strong>Enabled</strong><br />This will prevent Selected IPs (and private/reserved addresses) from being blocked. For IPv4 lists (/8 through /32) and IPv6 lists (/32 through /128). '
	. pfb_list_section_help_note(['IPv4 Suppression', 'IPv6 Suppression'], FALSE)
	. '<div class="infoblock">'
	. 'GeoIP blocklist cannot be suppressed.<br /><br />'
	. 'Alerts can be suppressed using the \'+\' icon in the Alerts tab; the IP is added to the matching family\'s (IPv4/IPv6) Suppression custom list.<br />'
	. 'For GeoIP, or Blocked IPs in a CIDR broader than the supported range (/8 IPv4, /32 IPv6), use a \'Whitelist alias\' w/ a List Action: \'Permit Outbound\' Firewall rule.<br />'
	. 'Only \'Deny\' type Aliases can be suppressed!'
	. '</div>'
);

$section->addInput(new Form_Checkbox(
	'enable_log',
	'Force Global IP Logging',
	'Enable',
	pfb_cfg_toggle_read($pconfig['enable_log'] ?? NULL) === PfbToggle::On,
	'on'
))->setHelp('Default: <strong>Off</strong><br />'
		. 'Forces logging on for every IP Alias, overriding the per-alias settings in the GeoIP/IPv4/IPv6 tabs. '
		. 'It cannot turn logging off.'
);

$section->addInput(new Form_Checkbox(
	'enable_rdns',
	'Reverse DNS Lookups',
	'Enable',
	pfb_cfg_toggle_read($pconfig['enable_rdns'] ?? NULL) === PfbToggle::On,
	'on'
))->setHelp('Default: <strong>Off</strong><br />'
		. 'Perform a reverse DNS (PTR) lookup to resolve the hostname of each blocked IP address shown in the Alerts and logs.<br />'
		. 'Enabling this increases the number of DNS queries performed, though the impact is usually negligible.');

$section->addInput(new Form_Checkbox(
	'killstates',
	'Kill States',
	'Enable',
	pfb_cfg_toggle_read($pconfig['killstates'] ?? NULL) === PfbToggle::On,
	'on'
))->setHelp('Default: <strong>Off</strong><br />'
		. 'When enabled, after a cron event or any Force command, any blocked IPs found in the Firewall states will be cleared.');

$form->add($section);

$section = new Form_Section('IP Interface/Rules Configuration');

$group = new Form_Group('Inbound Firewall Rules');
$group->add(new Form_Select(
	'inbound_interface',
	'Interface(s)',
	$pconfig['inbound_interface'],
	$options_inbound_interface,
	TRUE
))->setHelp('Select the Inbound interface(s) you want to apply auto rules to:')
  ->setAttribute('size', $options_interface_cnt);

$group->add(new Form_Select(
	'inbound_deny_action',
	'Rule Action',
	$pconfig['inbound_deny_action'],
	$options_inbound_deny_action
))->setHelp('Default: <strong>Block</strong><br />Select \'Rule action\' for Inbound rules:')
  ->setAttribute('style', 'width: auto');
$section->add($group);

$group = new Form_Group('Outbound Firewall Rules');
$group->add(new Form_Select(
	'outbound_interface',
	'Interface(s)',
	$pconfig['outbound_interface'],
	$options_outbound_interface,
	TRUE
))->setHelp('Select the Outbound interface(s) you want to apply auto rules to:')
  ->setAttribute('size', $options_interface_cnt);

$group->add(new Form_Select(
	'outbound_deny_action',
	'Rule Action',
	$pconfig['outbound_deny_action'],
	$options_outbound_deny_action
))->setHelp('Default: <strong>Reject</strong><br />Select \'Rule action\' for Outbound rules:')
  ->setAttribute('style', 'width: auto');
$section->add($group);

$section->addInput(new Form_Checkbox(
	'enable_float',
	'Floating Rules',
	'Enable',
	pfb_cfg_toggle_read($pconfig['enable_float'] ?? NULL) === PfbToggle::On,
	'on'
))->setHelp('Default: <strong>Off</strong><br />'
		. '<strong>Enabled:</strong> Auto-rules will be generated in the \'Floating Rules\' tab.<br />'
		. '<strong>Disabled:</strong> Auto-rules will be generated in the selected Inbound/Outbound interfaces.'
);

$section->addInput(new Form_Select(
	'pass_order',
	'Firewall \'Auto\' Rule Order',
	$pconfig['pass_order'],
	$options_pass_order
))->setHelp('Default Order:<strong>| pfB_Pass/Match/Block/Reject | All other Rules | (Default format)</strong><br />'
		. '<span class="text-danger"><strong>Note: \'Auto type\' Firewall Rules will be \'ordered\' by this selection.</strong></span>'
		. '<div class="infoblock">'
		. 'Refer to the blue infoblock \'List Action\' icon in the IPv4 tab for details on how to use \'Alias type\'<br />'
		. '(ie: \'Alias Deny\') instead of \'Auto generated rules\', if required for your network design.<br /><br />'
		. 'Select the \'<strong>Order</strong>\' of the Rules<br /><br />'
		. '&emsp;Selecting \'Default format\', sets pfBlockerNG rules at the top of the Firewall TAB.<br />'
		. '&emsp;Selecting any other \'Order\' will re-order <strong>all the rules to the format indicated!</strong></div>')
  ->setAttribute('style', 'width: auto; max-width: 100%');

$section->addInput(new Form_Select(
	'autorule_suffix',
	'Firewall \'Auto\' Rule Suffix',
	$pconfig['autorule_suffix'],
	$options_autorule_suffix
))->setHelp('Default: <strong>auto rule</strong><br />Select \'Auto Rule\' description suffix for auto defined rules. pfBlockerNG must be disabled to modify suffix.')
  ->setAttribute('style', 'width: auto');

$form->add($section);

$section = new Form_Section('ASN configuration');
$section->addInput(new Form_StaticText(
	'Attribution',
	'<small>'
	. 'ASN database distributed under the Creative Commons Attribution-ShareAlike 4.0 International License by: '
	. '<a target="_blank" rel="noopener noreferrer" href="https://ipinfo.io">IPinfo</a><br />'
	. 'The ASN database is automatically updated each day at a random hour.</small>'
));


$section->addInput(new Form_Select(
	'asn_reporting',
	'ASN Reporting',
	$pconfig['asn_reporting'],
	$options_asn_reporting
))->setHelp('Default: <strong>Disabled</strong><br />Query for the ASN (IPinfo downloaded ASN database) for each block/reject/permit/match IP entry. ASN values are cached as per the defined selection.')
  ->setAttribute('style', 'width: auto');

$section->addInput(new Form_Input(
	'asn_token',
	gettext('ASN IPinfo Token'),
	'password',
	$pconfig['asn_token'] ?? '',
	['placeholder' => 'Enter your IPinfo Token -- leave blank to keep the current token']
))->setHelp('To utilize the free IPinfo ASN functionality, you must first register for a free IPinfo user account. Visit the following '
	. '<a href="https://ipinfo.io/signup" target="_blank" rel="noopener noreferrer">Link to Register</a> for a free IPinfo user account. '
	. '<strong>NOTE: If you use Snort/Suricata, check for IPinfo blocked events!</strong>'
	. ' The stored token is never displayed here; leaving this field blank on Save keeps the existing token unchanged.')
  ->setAttribute('autocomplete', 'off');

$form->add($section);
$section = new Form_Section('MaxMind GeoIP configuration');

$section->addInput(new Form_StaticText(
        'Attribution',
        '<small>'
        . 'GeoIP database GeoLite2 distributed under the Creative Commons Attribution-ShareAlike 4.0 International License by: '
	. '<a target="_blank" rel="noopener noreferrer" href="https://www.maxmind.com">MaxMind Inc.</a><br />'
	. 'The GeoIP database is automatically updated each day at a random hour.</small>'
));

$section->addInput(new Form_Input(
	'maxmind_account',
	gettext('MaxMind Account ID'),
	'text',
	$pconfig['maxmind_account'],
	['placeholder' => 'Enter your MaxMind GeoLite2 Account ID']
))->setHelp('To utilize the free MaxMind GeoLite2 GeoIP functionality, you must first register for a free MaxMind user account. Visit the following '
	. '<a href="https://www.maxmind.com/en/geolite2/signup" target="_blank" rel="noopener noreferrer">Link to Register</a> for a free MaxMind user account. '
	. '<strong>Use the GeoIP Update version 3.1.1 or newer registration option.</strong>')
  ->setAttribute('autocomplete', 'off');

$section->addInput(new Form_Input(
	'maxmind_key',
	gettext('MaxMind License Key'),
	'password',
	$pconfig['maxmind_key'] ?? '',
	['placeholder' => 'Enter your MaxMind GeoLite2 License Key -- leave blank to keep the current key']
))->setHelp('To utilize the free MaxMind GeoLite2 GeoIP functionality, you must first register for a free MaxMind user account. Visit the following '
	. '<a href="https://www.maxmind.com/en/geolite2/signup" target="_blank" rel="noopener noreferrer">Link to Register</a> for a free MaxMind user account. '
	. '<strong>Utilize the GeoIP Update version 3.1.1 or newer registration option.</strong>'
	. ' The stored key is never displayed here; leaving this field blank on Save keeps the existing key unchanged.')
  ->setAttribute('autocomplete', 'off');

$section->addInput(new Form_Select(
	'maxmind_locale',
	'MaxMind Localized Language',
	$pconfig['maxmind_locale'],
	$options_maxmind_locale
))->setHelp('Default: <strong>English</strong><br />Select the localized name data from the Language options available.<br />'
		. 'Changes to the Locale will be executed in the background, and will take a few minutes to complete.<br />'
		. 'Upon completion, a pfSense Notice will be generated.')
  ->setAttribute('style', 'width: auto');

$section->addInput(new Form_Checkbox(
	'database_cc',
	'MaxMind CSV Updates',
	'Check to disable MaxMind CSV updates',
	pfb_cfg_toggle_read($pconfig['database_cc'] ?? NULL) === PfbToggle::On,
	'on'
))->setHelp('Default: <strong>Off</strong> (CSV updates run).<br />This will disable the MaxMind monthly CSV GeoIP database cron update. This does not affect the MaxMind binary cron update that is used for other GeoIP funcionality in the package.');

$form->add($section);

$pfb_ip_anchor_layout = pfb_ip_anchor_layout_render();
$section = new Form_Section('IPv4 Suppression', $pfb_ip_anchor_layout['suppression'], COLLAPSIBLE|SEC_CLOSED);
$suppression_text = '<strong><u>This suppression list is for [ /8 through /32 ] IPv4 addresses only!</u></strong><br /><br />

			When \'Suppression\' is enabled, all RFC1918, loopback and reserved (documentation, multicast, CGN, benchmarking, 6to4)
			addresses are also filtered on feed download|Update|Reload.<br /><br />

			Enter one &emsp; <strong>IPv4 address</strong>&emsp; per line<br />
			You may use "<strong>#</strong>" after any address to add comments. &emsp;IE: (x.x.x.x/32 # example.com)<br /><br />

			To utilize this <strong>Suppression List</strong>, enable <strong>Suppression</strong> and click on the "+"
			icon(s) in the Alerts tab to add the IPv4 addresses automatically to this Suppression list and immediately
			remove the IPv4 address from the Deny aliastable.<br /><br />

			Note: When manually adding an IPv4 address <strong>[ /8 through /32 only! ]</strong> to this Suppression List,
			you must run a <strong>"Force Reload - IP"</strong> for the changes to take effect.';

$section->addInput(new Form_Textarea(
	'v4suppression',
	'',
	$pconfig['v4suppression']
))->removeClass('form-control')
  ->addClass('row-fluid col-sm-12')
  ->setAttribute('columns', '90')
  ->setAttribute('rows', '15')
  ->setAttribute('wrap', 'off')
  ->setAttribute('style', 'width: 100%')
  ->setHelp($suppression_text);

$form->add($section);

$section = new Form_Section('IPv6 Suppression', 'IPv6_Suppression_customlist', COLLAPSIBLE|SEC_CLOSED);
$suppression_text_v6 = '<strong><u>This suppression list is for [ /32 through /128 ] IPv6 addresses only!</u></strong><br /><br />

			When \'Suppression\' is enabled, all ULA (fc00::/7), link-local, loopback and reserved (documentation, multicast, NAT64)
			addresses are also filtered on feed download|Update|Reload.<br /><br />

			Enter one &emsp; <strong>IPv6 address</strong>&emsp; per line<br />
			You may use "<strong>#</strong>" after any address to add comments. &emsp;IE: (2001:db8::1/128 # example.com)<br /><br />

			To utilize this <strong>Suppression List</strong>, enable <strong>Suppression</strong> and click on the "+"
			icon(s) in the Alerts tab to add the IPv6 addresses automatically to this Suppression list and immediately
			remove the IPv6 address from the Deny aliastable.<br /><br />

			Note: When manually adding an IPv6 address <strong>[ /32 through /128 only! ]</strong> to this Suppression List,
			you must run a <strong>"Force Reload - IP"</strong> for the changes to take effect.';

$section->addInput(new Form_Textarea(
	'v6suppression',
	'',
	$pconfig['v6suppression']
))->removeClass('form-control')
  ->addClass('row-fluid col-sm-12')
  ->setAttribute('columns', '90')
  ->setAttribute('rows', '15')
  ->setAttribute('wrap', 'off')
  ->setAttribute('style', 'width: 100%')
  ->setHelp($suppression_text_v6);

$form->add($section);

$section = new Form_Section('Advanced Settings', 'ip_advanced', COLLAPSIBLE|SEC_CLOSED);

$section->addInput(new Form_Select(
	'pfb_agg_types',
	'Aggregated Aliases',
	$pconfig['pfb_agg_types'],
	$options_pfb_agg_types,
	TRUE
))->setHelp('Default: <strong>none</strong><br />'
		. 'For each type selected, build a <strong>pfB_&lt;Type&gt;_Aggregated_v4/_v6</strong> '
		. 'alias holding the CIDR-aggregated union of <strong>every feed of that type</strong>, '
		. 'whichever List Action produced it &mdash; <em>Deny</em> covers Deny Inbound, Outbound '
		. 'and Both as well as Alias Deny.<br />'
		. 'Each aggregate is <strong>reference only &mdash; no firewall rule is added</strong>. '
		. 'Use it by name where you need it (your own rule, an HAProxy ACL). Each one loads as a '
		. 'pf table, so enable only the types you use.')
  ->setAttribute('size', count($options_pfb_agg_types))
  ->setAttribute('style', 'width: auto');

$section->addInput(new Form_Select(
	'pfb_alias_delta_mode',
	'Alias Table Apply Mode',
	$pconfig['pfb_alias_delta_mode'],
	$options_pfb_alias_delta_mode
))->setHelp('Default: <strong>Auto</strong><br />'
		. '<strong>Auto:</strong> delta apply (-T add/-T delete) for small churn (&lt;~5%); '
		. 'full replace for initial load, boot, or large churn. Safe default.<br />'
		. '<strong>Delta:</strong> always delta apply — no large-churn replace fallback. Power-user override; '
		. 'can be slow on a full-table rebuild.<br />'
		. '<strong>Replace:</strong> always full -T replace (pre-4.0 behaviour).')
  ->setAttribute('id', 'pfb_alias_delta_mode')
  ->setAttribute('style', 'width: auto');

$section->addInput(new Form_Input(
	'pfb_alias_delta_batch',
	'Alias Table Delta Batch Size',
	'number',
	$pconfig['pfb_alias_delta_batch'],
	[ 'min' => '64', 'max' => '4096', 'placeholder' => '512' ]
))->setHelp('Default: <strong>512</strong> (range 64–4096). '
		. 'Entries applied per pfctl call in delta mode. '
		. 'Use 512 for typical tables; 1024+ for tables with 1M+ entries. '
		. 'Applies in Auto and Delta modes.');

$section->addInput(new Form_Input(
	'ip_placeholder',
	gettext('Placeholder IP Address'),
	'text',
	$pconfig['ip_placeholder'],
	[ 'placeholder' => '127.1.7.7' ]
))->setHelp('Default: <strong>127.1.7.7</strong><br />Enter a single IPv4 placeholder address<br />'
	. 'For IPv6 \'::\' will be prefixed to the placeholder IP.<br />'
	. 'This address should be in an Isolated Range that is not used in your Network.<br />'
	. 'This IP address will be used as a placeholder IP to avoid empty Feeds/Aliases.'
);

$form->add($section);

print_callout('<strong>Setting changes are applied via CRON or \'Force Update|Reload\' only!</strong>');
print ($form);

?>
<?=$pfb_ip_editor['asset']?>
<script type="text/javascript">
//<![CDATA[

var pagetype = null;

function enable_delta_batch() {
	hideInput('pfb_alias_delta_batch', $('#pfb_alias_delta_mode').val() == 'replace');
}

events.push(function(){
<?=$pfb_ip_editor['lists']?>

	$('#pfb_alias_delta_mode').change(function() {
		enable_delta_batch();
	});
	enable_delta_batch();
});

//]]>
</script>
<?=pfb_ip_js_asset_render()?>
<?php include('foot.inc');?>

<?php
/*
 * pfblockerng_general.php
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

// Add Wizard tab on new installations only
$pfb_wizard = TRUE;

$wizard_action = pfb_wizard_get_action($_GET ?: array());

// "Do not show this again": persist the choice so the setup wizard never auto-launches
// again. Stored outside config/0 so a fresh, unconfigured install still reads as
// unconfigured (config/0 == null) for the upgrade-migration paths in pfblockerng_install.inc.
if ($wizard_action === 'disable') {
	// foreign key — out of ADR-29 gateway scope (pfb_wizard_skip is not a /config/0 scalar)
	config_set_path('installedpackages/pfblockerng/pfb_wizard_skip', 'on');
	write_config('[pfBlockerNG] Disable setup wizard auto-launch');
}

// Skip the auto-launch for this request ('skip'), permanently ('disable' persisted),
// or once the package has been configured.
if (pfb_wizard_suppress_autolaunch($wizard_action,
    config_get_path('installedpackages/pfblockerng/pfb_wizard_skip'),	// foreign key — out of ADR-29 gateway scope
    config_get_path('installedpackages/pfblockerng/config/0'))) {	// section existence check — not a scalar read
	$pfb_wizard = FALSE;
}

$pfb['gconfig'] = PfbConfig::readSection('installedpackages/pfblockerng/config/0');

$pconfig = array();
$pconfig['enable_cb']			= $pfb['gconfig']['enable_cb']				?: '';

// Default 'on' — owned by the registry (ADR-29); PfbConfig::read applies it when absent.
$pconfig['pfb_keep']			= PfbConfig::read('pfb_keep')->value;

// Default 'on' — owned by the registry (ADR-29); PfbConfig::read applies it when absent.
// Pinned 'off' on existing installs by the upgrade migration in pfblockerng_install.inc.
$pconfig['pfb_feed_internal_filter']	= PfbConfig::read('pfb_feed_internal_filter');

// Exemptions from the internal-address feed-host check: IP addresses / CIDR ranges
// (one per line) whose feeds are allowed even when they resolve internally.
$pconfig['pfb_feed_internal_allowlist']	= (string) base64_decode($pfb['gconfig']['pfb_feed_internal_allowlist'] ?? '');

$pconfig['pfb_interval']		= $pfb['gconfig']['pfb_interval']			?: 1;

$pconfig['pfb_min']			= $pfb['gconfig']['pfb_min']				?: 0;
$pconfig['pfb_hour']			= $pfb['gconfig']['pfb_hour']				?: 0;
$pconfig['pfb_dailystart']		= $pfb['gconfig']['pfb_dailystart']			?: 0;
$pconfig['skipfeed']			= $pfb['gconfig']['skipfeed']				?: 0;

$pconfig['log_max_log']			= $pfb['gconfig']['log_max_log']			?: 20000;
$pconfig['log_max_errlog']		= $pfb['gconfig']['log_max_errlog']			?: 20000;
$pconfig['log_max_extraslog']		= $pfb['gconfig']['log_max_extraslog']			?: 20000;
$pconfig['log_max_ip_blocklog']		= $pfb['gconfig']['log_max_ip_blocklog']		?: 20000;
$pconfig['log_max_ip_permitlog']	= $pfb['gconfig']['log_max_ip_permitlog']		?: 20000;
$pconfig['log_max_ip_matchlog']		= $pfb['gconfig']['log_max_ip_matchlog']		?: 20000;
$pconfig['log_max_dnslog']		= $pfb['gconfig']['log_max_dnslog']			?: 20000;
$pconfig['log_max_dnsbl_parse_err']	= $pfb['gconfig']['log_max_dnsbl_parse_err']		?: 20000;
$pconfig['log_max_dnsreplylog']		= $pfb['gconfig']['log_max_dnsreplylog']		?: 20000;
$pconfig['log_max_unilog']		= $pfb['gconfig']['log_max_unilog']			?: 20000;

// ADR-30: per-log rotation schedule. Read via PfbConfig::read so the registered
// default ('off') is applied when the key is absent (new install / upgrade).
$pconfig['log_rotate_log']		= PfbConfig::read('log_rotate_log');
$pconfig['log_rotate_errlog']		= PfbConfig::read('log_rotate_errlog');
$pconfig['log_rotate_extraslog']	= PfbConfig::read('log_rotate_extraslog');
$pconfig['log_rotate_ip_blocklog']	= PfbConfig::read('log_rotate_ip_blocklog');
$pconfig['log_rotate_ip_permitlog']	= PfbConfig::read('log_rotate_ip_permitlog');
$pconfig['log_rotate_ip_matchlog']	= PfbConfig::read('log_rotate_ip_matchlog');
$pconfig['log_rotate_dnslog']		= PfbConfig::read('log_rotate_dnslog');
$pconfig['log_rotate_dnsbl_parse_err']	= PfbConfig::read('log_rotate_dnsbl_parse_err');
$pconfig['log_rotate_dnsreplylog']	= PfbConfig::read('log_rotate_dnsreplylog');
$pconfig['log_rotate_unilog']		= PfbConfig::read('log_rotate_unilog');

// ADR-30 amendment: lines to keep on scheduled reset. Default '0' (clear fully).
$pconfig['log_reset_keep_log']			= PfbConfig::read('log_reset_keep_log');
$pconfig['log_reset_keep_errlog']		= PfbConfig::read('log_reset_keep_errlog');
$pconfig['log_reset_keep_extraslog']		= PfbConfig::read('log_reset_keep_extraslog');
$pconfig['log_reset_keep_ip_blocklog']		= PfbConfig::read('log_reset_keep_ip_blocklog');
$pconfig['log_reset_keep_ip_permitlog']		= PfbConfig::read('log_reset_keep_ip_permitlog');
$pconfig['log_reset_keep_ip_matchlog']		= PfbConfig::read('log_reset_keep_ip_matchlog');
$pconfig['log_reset_keep_dnslog']		= PfbConfig::read('log_reset_keep_dnslog');
$pconfig['log_reset_keep_dnsbl_parse_err']	= PfbConfig::read('log_reset_keep_dnsbl_parse_err');
$pconfig['log_reset_keep_dnsreplylog']		= PfbConfig::read('log_reset_keep_dnsreplylog');
$pconfig['log_reset_keep_unilog']		= PfbConfig::read('log_reset_keep_unilog');

// ADR-38: syslog export controls. Read via PfbConfig::read so registered defaults apply.
// log_syslog uses the PfbToggle adapter — extract the scalar .value for pfb_cfg_toggle_read().
$pconfig['log_syslog']			= PfbConfig::read('log_syslog')->value;
$pconfig['log_syslog_facility']		= PfbConfig::read('log_syslog_facility');
$pconfig['log_syslog_priority']		= PfbConfig::read('log_syslog_priority');

// Select field options
$options_pfb_interval	= [	'1' => 'Every hour',
				'2' => 'Every 2 hours',
				'3' => 'Every 3 hours',
				'4' => 'Every 4 hours',
				'6' => 'Every 6 hours',
				'8' => 'Every 8 hours',
				'12' => 'Every 12 hours',
				'24' => 'Once a day',
				'Disabled' => 'Disabled' ];
$options_pfb_min	= [ '0' => '00', '15' => '15', '30' => '30', '45' => '45' ];
$options_pfb_hour	= range(0, 23, 1);
$options_pfb_dailystart	= range(0, 23, 1);
$options_skipfeed	= [ '0' => 'No Limit', '1' => '1', '2' => '2', '3' => '3', '4' => '4', '5' => '5', '6' => '6' ];
$options_log_types	= [	'100' => '100', '1000' => '1,000', '2000' => '2,000', '4000' => '4,000', '6000' => '6,000',
				'8000' => '8,000', '10000' => '10,000', '20000' => '20,000', '40000' => '40,000', '60000' => '60,000',
				'80000' => '80,000', '100000' => '100,000', '200000' => '200,000 - Memory intensive...', '400000' => '400,000',
				'600000' => '600,000', '800000' => '800,000', '1000000' => '1,000,000', '1500000' => '1,500,000',
				'2000000' => '2,000,000', '2500000' => '2,500,000', '3000000' => '3,000,000',
				'nolimit' => 'No Limit - Not recommended' ];
// ADR-30: rotation schedule options for each per-log schedule select.
$options_log_rotate	= [ 'off' => 'Off', 'daily' => 'Daily', 'weekly' => 'Weekly', 'monthly' => 'Monthly' ];

// ADR-38: syslog facility and priority option lists (Snort-style token → display label).
$options_log_syslog_facility = [
	'log_local0' => 'local0', 'log_local1' => 'local1', 'log_local2' => 'local2', 'log_local3' => 'local3',
	'log_local4' => 'local4', 'log_local5' => 'local5', 'log_local6' => 'local6 (default)', 'log_local7' => 'local7',
	'log_daemon' => 'daemon', 'log_user'   => 'user',   'log_auth'   => 'auth',
	'log_kern'   => 'kern',   'log_mail'   => 'mail',   'log_lpr'    => 'lpr',
	'log_news'   => 'news',   'log_uucp'   => 'uucp',   'log_cron'   => 'cron',
	'log_syslog' => 'syslog',
];
$options_log_syslog_priority = [
	'log_emerg'   => 'emerg',   'log_alert'   => 'alert',   'log_crit'    => 'crit',
	'log_err'     => 'err',     'log_warning' => 'warning',
	'log_notice'  => 'notice (default)', 'log_info' => 'info', 'log_debug' => 'debug',
];


// $input_errors is read unconditionally in the render section below, so it must be
// defined on every request path (incl. a POST without 'save'). Initialise it once.
$input_errors = array();

// Validate input fields and save
if ($_POST) {
	if (isset($_POST['save'])) {

		// Validate Select field options
		$select_options = array(	'pfb_interval'			=> 1,
						'pfb_min'			=> 0,
						'pfb_hour'			=> 0,
						'pfb_dailystart'		=> 0,
						'skipfeed'			=> 0,
						'log_max_log'			=> 20000,
						'log_max_errlog'		=> 20000,
						'log_max_extraslog'		=> 20000,
						'log_max_ip_blocklog'		=> 20000,
						'log_max_ip_permitlog'		=> 20000,
						'log_max_ip_matchlog'		=> 20000,
						'log_max_dnslog'		=> 20000,
						'log_max_dnsbl_parse_err'	=> 20000,
						'log_max_dnsreplylog'		=> 20000,
						'log_max_unilog'		=> 20000
						);

		foreach ($select_options as $s_option => $s_default) {

			// Array to validate against
			if (strpos($s_option, 'log_max_') !== FALSE) {
				$query = $options_log_types;
			} else {
				$query = ${"options_$s_option"};
			}

			if (is_array($_POST[$s_option])) {
				$_POST[$s_option] = $s_default;
			}
			elseif (!array_key_exists($_POST[$s_option], $query)) {
				$_POST[$s_option] = $s_default;
			}
		}

		// ADR-30: validate per-log rotation schedule selects. Handled separately to
		// avoid extending the ${"options_$s_option"} lookup with unknown variable names.
		$log_rotate_keys = array(
			'log_rotate_log', 'log_rotate_errlog', 'log_rotate_extraslog',
			'log_rotate_ip_blocklog', 'log_rotate_ip_permitlog', 'log_rotate_ip_matchlog',
			'log_rotate_dnslog', 'log_rotate_dnsbl_parse_err',
			'log_rotate_dnsreplylog', 'log_rotate_unilog',
		);
		foreach ($log_rotate_keys as $rkey) {
			if (is_array($_POST[$rkey])) {
				$_POST[$rkey] = 'off';
			} elseif (!array_key_exists($_POST[$rkey], $options_log_rotate)) {
				$_POST[$rkey] = 'off';
			}
		}

		// ADR-30 amendment: validate per-log keep-lines fields (non-negative integer string).
		$log_reset_keep_keys = array(
			'log_reset_keep_log', 'log_reset_keep_errlog', 'log_reset_keep_extraslog',
			'log_reset_keep_ip_blocklog', 'log_reset_keep_ip_permitlog', 'log_reset_keep_ip_matchlog',
			'log_reset_keep_dnslog', 'log_reset_keep_dnsbl_parse_err',
			'log_reset_keep_dnsreplylog', 'log_reset_keep_unilog',
		);
		foreach ($log_reset_keep_keys as $kkey) {
			$v = $_POST[$kkey] ?? '0';
			if (is_array($v) || !ctype_digit((string) $v)) {
				$_POST[$kkey] = '0';
			}
		}

		// ADR-38: validate syslog facility and priority selects.
		$_v = $_POST['log_syslog_facility'] ?? '';
		if (is_array($_v) || !array_key_exists($_v, $options_log_syslog_facility)) {
			$_POST['log_syslog_facility'] = 'log_local6';
		}
		$_v = $_POST['log_syslog_priority'] ?? '';
		if (is_array($_v) || !array_key_exists($_v, $options_log_syslog_priority)) {
			$_POST['log_syslog_priority'] = 'log_notice';
		}
		unset($_v);

		if (!$input_errors) {

			$pfb['gconfig']['enable_cb']			= pfb_filter($_POST['enable_cb'], PFB_FILTER_ON_OFF, 'general', '');
			$pfb['gconfig']['pfb_keep']			= pfb_filter($_POST['pfb_keep'], PFB_FILTER_ON_OFF, 'general', '');

			// Store the master feed-host filter toggle as an explicit 'on'/'off' (a
			// checkbox submits 'on' when checked, nothing when unchecked) so the
			// runtime reader can tell an unchecked save (off) from a never-configured
			// install (key absent => default on).
			$pfb['gconfig']['pfb_feed_internal_filter']	= (($_POST['pfb_feed_internal_filter'] ?? '') === 'on') ? 'on' : 'off';

			// The allowlist textarea is greyed (disabled) when the filter is off, so the
			// browser does not submit it. Preserve the previously stored value in that
			// case rather than overwriting it with the absent POST field.
			if ($pfb['gconfig']['pfb_feed_internal_filter'] === 'on') {
				$pfb['gconfig']['pfb_feed_internal_allowlist']	= base64_encode(str_replace("\r\n", "\n", trim($_POST['pfb_feed_internal_allowlist'] ?? '')));
			}
			$pfb['gconfig']['pfb_interval']			= $_POST['pfb_interval']			?: 1;
			$pfb['gconfig']['pfb_min']			= $_POST['pfb_min']				?: 0;
			$pfb['gconfig']['pfb_hour']			= $_POST['pfb_hour']				?: 0;
			$pfb['gconfig']['pfb_dailystart']		= $_POST['pfb_dailystart']			?: 0;
			$pfb['gconfig']['skipfeed']			= $_POST['skipfeed']				?: 0;

			// Remove old Line Limit setting
			if (isset($pfb['gconfig']['log_maxlines'])) {
				unset($pfb['gconfig']['log_maxlines']);
			}

			$pfb['gconfig']['log_max_log']			= $_POST['log_max_log']				?: 20000;
			$pfb['gconfig']['log_max_errlog']		= $_POST['log_max_errlog']			?: 20000;
			$pfb['gconfig']['log_max_extraslog']		= $_POST['log_max_extraslog']			?: 20000;
			$pfb['gconfig']['log_max_ip_blocklog']		= $_POST['log_max_ip_blocklog']			?: 20000;
			$pfb['gconfig']['log_max_ip_permitlog']		= $_POST['log_max_ip_permitlog']		?: 20000;
			$pfb['gconfig']['log_max_ip_matchlog']		= $_POST['log_max_ip_matchlog']			?: 20000;
			$pfb['gconfig']['log_max_dnslog']		= $_POST['log_max_dnslog']			?: 20000;
			$pfb['gconfig']['log_max_dnsbl_parse_err']	= $_POST['log_max_dnsbl_parse_err']		?: 20000;
			$pfb['gconfig']['log_max_dnsreplylog']		= $_POST['log_max_dnsreplylog']			?: 20000;
			$pfb['gconfig']['log_max_unilog']		= $_POST['log_max_unilog']			?: 20000;

			// ADR-30: persist per-log rotation schedules. Values have already been validated
			// above. Written into $pfb['gconfig'] so the writeSection() call below includes
			// them in the section; PfbConfig::write would be overwritten by writeSection.
			$pfb['gconfig']['log_rotate_log']		= $_POST['log_rotate_log']		?: 'off';
			$pfb['gconfig']['log_rotate_errlog']		= $_POST['log_rotate_errlog']		?: 'off';
			$pfb['gconfig']['log_rotate_extraslog']		= $_POST['log_rotate_extraslog']	?: 'off';
			$pfb['gconfig']['log_rotate_ip_blocklog']	= $_POST['log_rotate_ip_blocklog']	?: 'off';
			$pfb['gconfig']['log_rotate_ip_permitlog']	= $_POST['log_rotate_ip_permitlog']	?: 'off';
			$pfb['gconfig']['log_rotate_ip_matchlog']	= $_POST['log_rotate_ip_matchlog']	?: 'off';
			$pfb['gconfig']['log_rotate_dnslog']		= $_POST['log_rotate_dnslog']		?: 'off';
			$pfb['gconfig']['log_rotate_dnsbl_parse_err']	= $_POST['log_rotate_dnsbl_parse_err']	?: 'off';
			$pfb['gconfig']['log_rotate_dnsreplylog']	= $_POST['log_rotate_dnsreplylog']	?: 'off';
			$pfb['gconfig']['log_rotate_unilog']		= $_POST['log_rotate_unilog']		?: 'off';

			// ADR-30 amendment: persist per-log keep-lines (validated above; default '0').
			$pfb['gconfig']['log_reset_keep_log']			= $_POST['log_reset_keep_log']			?: '0';
			$pfb['gconfig']['log_reset_keep_errlog']		= $_POST['log_reset_keep_errlog']		?: '0';
			$pfb['gconfig']['log_reset_keep_extraslog']		= $_POST['log_reset_keep_extraslog']		?: '0';
			$pfb['gconfig']['log_reset_keep_ip_blocklog']		= $_POST['log_reset_keep_ip_blocklog']		?: '0';
			$pfb['gconfig']['log_reset_keep_ip_permitlog']		= $_POST['log_reset_keep_ip_permitlog']		?: '0';
			$pfb['gconfig']['log_reset_keep_ip_matchlog']		= $_POST['log_reset_keep_ip_matchlog']		?: '0';
			$pfb['gconfig']['log_reset_keep_dnslog']		= $_POST['log_reset_keep_dnslog']		?: '0';
			$pfb['gconfig']['log_reset_keep_dnsbl_parse_err']	= $_POST['log_reset_keep_dnsbl_parse_err']	?: '0';
			$pfb['gconfig']['log_reset_keep_dnsreplylog']		= $_POST['log_reset_keep_dnsreplylog']		?: '0';
			$pfb['gconfig']['log_reset_keep_unilog']		= $_POST['log_reset_keep_unilog']		?: '0';

			// ADR-38: persist syslog export settings. Written into $pfb['gconfig'] so the
			// writeSection() call below includes them; a bare PfbConfig::write() before
			// writeSection() would be clobbered by the section-level write.
			//
			// Capture the pre-save values so we can detect a syslog change after the
			// write and restart pfb_filter (its static cache would otherwise hold stale
			// settings for the lifetime of the process).
			$pfb_old_log_syslog		= $pfb['gconfig']['log_syslog']			?? '';
			$pfb_old_log_facility		= $pfb['gconfig']['log_syslog_facility']	?? '';
			$pfb_old_log_priority		= $pfb['gconfig']['log_syslog_priority']	?? '';

			$pfb['gconfig']['log_syslog']	= pfb_filter($_POST['log_syslog'], PFB_FILTER_ON_OFF, 'general', '');

			// The facility and priority selects are disabled (greyed-out) when the
			// toggle is off, so the browser does not submit them. Preserve the
			// previously stored values in that case rather than overwriting with the
			// absent POST fields (mirrors the allowlist-textarea pattern above).
			if ($pfb['gconfig']['log_syslog'] === 'on') {
				$pfb['gconfig']['log_syslog_facility']	= $_POST['log_syslog_facility']	?: 'log_local6';
				$pfb['gconfig']['log_syslog_priority']	= $_POST['log_syslog_priority']	?: 'log_notice';
			}

			PfbConfig::writeSection('installedpackages/pfblockerng/config/0', $pfb['gconfig']);
			write_config('[pfBlockerNG] save General settings');

			$pfb['save'] = TRUE;
			sync_package_pfblockerng();

			// If any syslog key changed, restart pfb_filter so its per-process static
			// cache (in pfb_syslog_event()) picks up the new settings immediately.
			if (($pfb['gconfig']['log_syslog']		!== $pfb_old_log_syslog)	||
			    ($pfb['gconfig']['log_syslog_facility']	!== $pfb_old_log_facility)	||
			    ($pfb['gconfig']['log_syslog_priority']	!== $pfb_old_log_priority)) {
				if (is_service_running('pfb_filter')) {
					restart_service('pfb_filter');
				}
			}

			header('Location: /pfblockerng/pfblockerng_general.php');
			exit;
		}
	}
}

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'));
$pglinks = array('', '@self');
include_once('head.inc');

if ($input_errors) {
	print_input_errors($input_errors);
}

// Load Wizard on new installations only
if ($pfb_wizard) {
	header('Location: /wizard.php?xml=pfblockerng_wizard.xml');
	exit;
}
else {
	// Define default Alerts Tab href link (Top row)
	$get_req = pfb_alerts_default_page();

	$tab_array	= array();
	$tab_array[]	= array(gettext('General'),	TRUE,	'/pfblockerng/pfblockerng_general.php');
	$tab_array[]	= array(gettext('IP'),		FALSE,	'/pfblockerng/pfblockerng_ip.php');
	$tab_array[]	= array(gettext('DNSBL'),	FALSE,	'/pfblockerng/pfblockerng_dnsbl.php');
	$tab_array[]	= array(gettext('Update'),	FALSE,	'/pfblockerng/pfblockerng_update.php');
	$tab_array[]	= array(gettext('Reports'),	FALSE,	"/pfblockerng/pfblockerng_alerts.php{$get_req}");
	$tab_array[]	= array(gettext('Feeds'),	FALSE,	'/pfblockerng/pfblockerng_feeds.php');
	$tab_array[]	= array(gettext('Logs'),	FALSE,	'/pfblockerng/pfblockerng_log.php');
	$tab_array[]	= array(gettext('Sync'),	FALSE,	'/pfblockerng/pfblockerng_sync.php');
	pfb_software_add_tab($tab_array);
	$tab_array[]	= array(gettext('Wizard'),	FALSE,	'/wizard.php?xml=pfblockerng_wizard.xml');
	display_top_tabs($tab_array, TRUE);
}

$form = new Form('Save');

$section = new Form_Section('General Settings');
$section->addInput(new Form_StaticText(
	'Links',
	'<small>'
	. '<a href="/firewall_aliases.php" target="_blank">Firewall Aliases</a>&emsp;'
	. '<a href="/firewall_rules.php" target="_blank">Firewall Rules</a>&emsp;'
	. '<a href="/status_logs_filter.php" target="_blank">Firewall Logs</a></small>'
));

$section->addInput(new Form_Checkbox(
	'enable_cb',
	'pfBlockerNG',
	gettext('Enable'),
	pfb_cfg_toggle_read($pconfig['enable_cb']) === PfbToggle::On,
	'on'
))->setHelp('<span class="text-danger">Note: </span>'
		. 'Context help is available on various pages by clicking the \'blue infoblock\' icons &emsp;---->'
		. '<div class="infoblock">Sample help information.</div>'
);

$section->addInput(new Form_Checkbox(
	'pfb_keep',
	'Keep Settings',
	gettext('Enable'),
	pfb_cfg_toggle_read($pconfig['pfb_keep']) === PfbToggle::On,
	'on'
))->setHelp('<span class="text-danger">Note: </span>'
		. 'With \'Keep settings\' enabled, pfBlockerNG will maintain run state on Installation/Upgrade.<br />'
		. ' If \'Keep Settings\' is not \'enabled\' on pkg Install/De-Install, all settings will be Wiped!<br /><br />'
		. '<span class="text-danger">Note: </span>'
		. ' To clear all downloaded lists, uncheck these two checkboxes and \'Save\'. Re-check both boxes and run a \'Force Update|Reload\''
);

$section->addInput(new Form_Checkbox(
	'pfb_feed_internal_filter',
	'Internal Feed Host Filter',
	gettext('Enable'),
	pfb_cfg_toggle_read($pconfig['pfb_feed_internal_filter']) === PfbToggle::On,
	'on'
))->setHelp('Restrict feeds from being fetched from non-public/internal addresses. '
		. 'The exemptions list below allows specific IP/CIDRs through.'
);

$section->addInput(new Form_Textarea(
	'pfb_feed_internal_allowlist',
	'Internal Feed Host Exemptions',
	$pconfig['pfb_feed_internal_allowlist']
))->setHelp('IP addresses or CIDR ranges (one per line) that are exempt from the '
		. 'internal-address check &mdash; e.g. an internal mirror. '
		. 'Leave empty to block all feeds that resolve to an internal/private address.'
);

$group = new Form_Group('CRON Settings');
$group->add(new Form_Select(
	'pfb_interval',
	'Hour Interval',
	$pconfig['pfb_interval'],
	$options_pfb_interval
))->setHelp('Default: <strong>Every hour</strong><br />Select the Cron hour interval.');

$group->add(new Form_Select(
	'pfb_min',
	'Start Min',
	$pconfig['pfb_min'],
	$options_pfb_min
))->setHelp('Default: <strong>:00</strong><br />Select the Cron update minute.');

$group->add(new Form_Select(
	'pfb_hour',
	'Start Hour',
	$pconfig['pfb_hour'],
	$options_pfb_hour
))->setHelp('Default: <strong>0</strong><br />Select the Cron start hour.');

$group->add(new Form_Select(
	'pfb_dailystart',
	'Daily/Weekly Start Hour',
	$pconfig['pfb_dailystart'],
	$options_pfb_dailystart
))->setHelp('Default: <strong>0</strong><br />Select the \'Daily/Weekly\' start hour.');
$section->add($group);

$section->addInput(new Form_Select(
	'skipfeed',
	'Download Failure Threshold',
	$pconfig['skipfeed'],
	$options_skipfeed
))->setHelp('Default: <strong>No limit</strong><br />'
		. 'Select max daily download failure threshold via CRON. Clear widget \'failed downloads\' to reset.<br />'
		. 'On a download failure, the previously downloaded list is reloaded.')
  ->setAttribute('style', 'width: auto');

$form->add($section);

// ADR-30: section title includes "(max lines)" for backward-compat label; schedule
// and reset-keep controls are added inline per log, with a single help note shown per group.
$section = new Form_Section('Log Settings (max lines / rotation schedule)');
$log_types = array (	'General'	=> array('pfBlockerNG' => 'log', 'Unified Log' => 'unilog', 'Error' => 'errlog', 'Extras' => 'extraslog'),
			'IP'		=> array('IP Block' => 'ip_blocklog', 'IP Permit' => 'ip_permitlog', 'IP Match' => 'ip_matchlog'),
			'DNSBL'		=> array('DNSBL' => 'dnslog', 'DNSBL Parse Error' => 'dnsbl_parse_err'),
			'DNS Reply'	=> array('DNS Reply' => 'dnsreplylog')
			);

// Help text for the schedule column — shown once per group (first log in each group).
$rotate_help = 'Resets this log at the start of each calendar period (day/week/month) so '
	. 'statistics reflect the current period only. Independent of the max-lines limit. '
	. '<strong>A reset discards that period\'s data</strong> &mdash; export first if you need history.';
// Help text for the keep-lines column — shown once per group (first log in each group).
$reset_keep_help = 'Lines to retain at the tail of this log when the scheduled reset fires. '
	. 'Default: <strong>0</strong> (clear fully). '
	. 'Set &gt; 0 as an opt-in cushion for remote log shippers that need a few moments to drain the file.';

foreach ($log_types as $logdescr => $logtype) {
	$group    = new Form_Group($logdescr);
	$first    = TRUE;
	foreach ($logtype as $descr => $type) {
		$group->add(new Form_Select(
			'log_max_' . $type,
			$descr,
			$pconfig['log_max_' . $type],
			$options_log_types
		))->setHelp("Default: <strong>20000<br />{$descr}</strong> Log")
		  ->setWidth(2);
		$rotate_sel = $group->add(new Form_Select(
			'log_rotate_' . $type,
			'Schedule',
			$pconfig['log_rotate_' . $type],
			$options_log_rotate
		))->setWidth(2);
		if ($first) {
			$rotate_sel->setHelp($rotate_help);
		}
		$keep_inp = $group->add(new Form_Input(
			'log_reset_keep_' . $type,
			'Keep lines',
			'number',
			$pconfig['log_reset_keep_' . $type]
		))->setAttribute('min', '0')
		  ->setWidth(2);
		if ($first) {
			$keep_inp->setHelp($reset_keep_help);
			$first = FALSE;
		}
	}
	$section->add($group);
}

// ADR-38: syslog export controls — appended at the end of the Log Settings section.
$section->addInput(new Form_Checkbox(
	'log_syslog',
	'Send Security Events to System Log',
	gettext('Enable'),
	pfb_cfg_toggle_read($pconfig['log_syslog']) === PfbToggle::On,
	'on'
))->setHelp('When enabled, every IP Block/Permit/Match and DNSBL block event is also '
		. 'emitted to syslog (tagged <code>pfblockerng</code>, in <code>key=value</code> form) '
		. 'at the selected facility and severity. Remote delivery: pfSense '
		. '<strong>Status &gt; System Logs &gt; Settings &gt; Remote Logging &rarr; Everything</strong>. '
		. 'Default facility: <strong>local6</strong>.'
);

$section->addInput(new Form_Select(
	'log_syslog_facility',
	'Syslog Facility',
	$pconfig['log_syslog_facility'],
	$options_log_syslog_facility
))->setHelp('Default: <strong>local6</strong><br />Syslog facility for pfBlockerNG security events. '
		. 'Choose a facility not already used by another pfSense service.'
)->setAttribute('id', 'log_syslog_facility');

$section->addInput(new Form_Select(
	'log_syslog_priority',
	'Syslog Severity',
	$pconfig['log_syslog_priority'],
	$options_log_syslog_priority
))->setHelp('Default: <strong>notice</strong><br />Severity level applied to all exported security events.'
)->setAttribute('id', 'log_syslog_priority');

$form->add($section);

$section = new Form_Section('Support');
$section->addInput(new Form_StaticText(
	null,
	'
<div>
<div style="width: 75%; height: 180px; float: left;">
	<strong>pfBlockerNG</strong> is created, designed, developed, supported and maintained by:
	<a target="_blank" href="https://forum.netgate.com/user/bbcan177">BBcan177</a><br />

	<ul class="list-inline" style="margin-top: 4px; margin-bottom: -2px; border-style: outset; border-bottom-color: #8B181B; border-right-color: #8B181B; border-width: 2px;">
		<li class="list-inline-item"><a target="_blank" href="http://pfblockerng.com">
			<span style="color: #8B181B;" class="fa-solid fa-globe"></span> HomePage</a></li>
		<li class="list-inline-item"><a target="_blank" href="https://twitter.com/intent/follow?screen_name=BBcan177">
			<span style="color: #8B181B;" class="fa-brands fa-twitter"></span> Follow on X formerly Twitter</a></li>
		<li class="list-inline-item"><a target="_blank" href="https://www.reddit.com/r/pfBlockerNG/new/">
			<span style="color: #8B181B;" class="fa-brands fa-reddit"></span> Reddit</a></li>
		<li class="list-inline-item"><a target="_blank" href="https://infosec.exchange/@BBcan177#">
			<span style="color: #8B181B;" class="fa-solid fa-globe"></span> Mastodon</a></li>
		<li class="list-inline-item"><a target="_blank" href="https://github.com/BBcan177">
			<span style="color: #8B181B;" class="fa-brands fa-github"></span> GitHub</a></li>
		<li class="list-inline-item"><a target="_blank" href="mailto:bbcan177@gmail.com?Subject=pfBlockerNG%20Support">
			<span style="color: #8B181B;" class="fa-regular fa-envelope"></span> Contact Us</a></li>
	</ul>
	<span class="pull-right"><small>Based upon pfBlocker by Marcello Coutinho and Tom Schaefer.</small></span>
</div>

<div style="width: 25%; height: 170px; float: right;">
	<a target="_blank" href="http://pfblockerng.com">

<svg width="180.0pt" height="180.0pt" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px"
	 viewBox="30 225 560 470" style="enable-background:new 30 225 560 470;" xml:space="preserve">
<style type="text/css">
	.st0{fill:#8B181B;}
	.st1{fill:#660818;}
	.st2{fill:#58595B;}
	.st3{fill:#FFFFFF;}
	.st4{fill:none;stroke:#FFFFFF;stroke-width:2;stroke-miterlimit:10;}
</style>
<g id="Layer_1">
	<circle id="XMLID_3_" class="st0" cx="320.2" cy="363.8" r="184.1"/>
	<path id="XMLID_2_" class="st1" d="M213.7,403.2l90.2,144.6c0,0,91.7,9.9,149.6-58.9c0,0,34.5-27.9,47-87.7l-46.8-135"/>
</g>
<g id="Layer_3">
</g>
<g id="Layer_2">
	<g id="XMLID_1_">
		<path id="XMLID_4_" class="st2" d="M320.2,234.2c0,0,113,32.1,133.5,32.1c0,0,0.7,197.4-133.5,256.1h0
			C186,463.6,186.7,266.2,186.7,266.2C207.2,266.2,320.2,234.2,320.2,234.2"/>
		<path id="XMLID_175_" class="st3" d="M257.1,399.6h-0.4l0.1,75.9l-9.5-11.6l-7.9-11.2V307.3h17.3v19h0.4
			c8.5-14.3,20.9-21.5,37.3-21.5c13.9,0,24.8,4.8,32.6,14.5c7.8,9.7,11.7,22.6,11.7,38.8c0,18.1-4.4,32.5-13.2,43.4
			c-8.8,10.9-20.8,16.3-36.1,16.3C275.4,417.7,264.7,411.7,257.1,399.6z M256.6,356.1v15.1c0,8.9,2.9,16.5,8.7,22.7
			c5.8,6.2,13.2,9.3,22.1,9.3c10.5,0,18.7-4,24.6-12c5.9-8,8.9-19.2,8.9-33.4c0-12-2.8-21.4-8.3-28.3c-5.6-6.8-13.1-10.2-22.6-10.2
			c-10.1,0-18.1,3.5-24.2,10.5C259.7,336.8,256.6,345.5,256.6,356.1z"/>
		<path id="XMLID_173_" class="st3" d="M403.1,272.1c-3.4-1.9-7.2-2.8-11.5-2.8c-12.1,0-18.1,7.6-18.1,22.9v16.7h25.3v14.8h-25.3
			v93.2h-17.2v-93.2h-18.4v-14.8h18.4v-17.5c0-11.3,3.3-20.3,9.8-26.8c6.5-6.6,14.7-9.9,24.5-9.9c5.3,0,9.5,0.6,12.5,1.9V272.1z"/>
		<g id="XMLID_5_">
			<path id="XMLID_6_" class="st3" d="M260.6,455v-24.2h7.4c1.5,0,2.7,0.2,3.6,0.7c0.9,0.5,1.6,1.2,2.2,2.2c0.6,1,0.8,2.1,0.8,3.3
				c0,1.1-0.2,2.1-0.7,3c-0.5,0.9-1.2,1.6-2,2.1c1.1,0.4,2.1,1.1,2.7,2.1c0.7,1,1,2.2,1,3.7c0,1.5-0.3,2.7-0.9,3.9
				c-0.6,1.1-1.4,1.9-2.4,2.4c-1,0.5-2.4,0.8-4.1,0.8H260.6z M263.2,441h4.3c1.1,0,1.9-0.1,2.4-0.2c0.7-0.2,1.2-0.6,1.6-1.2
				c0.4-0.5,0.6-1.3,0.6-2.2c0-0.9-0.2-1.6-0.5-2.2c-0.3-0.6-0.8-1-1.3-1.2c-0.6-0.2-1.6-0.3-3-0.3h-4V441z M263.2,452.1h4.9
				c1.1,0,1.9-0.1,2.4-0.3c0.7-0.3,1.3-0.8,1.7-1.4c0.4-0.7,0.6-1.5,0.6-2.5c0-0.9-0.2-1.7-0.6-2.3c-0.4-0.6-0.9-1.1-1.5-1.4
				s-1.6-0.4-3-0.4h-4.6V452.1z"/>
			<path id="XMLID_13_" class="st3" d="M278.7,455v-24.2h2.4V455H278.7z"/>
			<path id="XMLID_15_" class="st3" d="M284,446.2c0-3,0.6-5.3,1.9-6.8c1.3-1.5,2.9-2.3,4.8-2.3c1.9,0,3.5,0.8,4.8,2.3
				c1.3,1.5,1.9,3.8,1.9,6.7c0,3.1-0.6,5.5-1.9,7c-1.3,1.5-2.9,2.3-4.8,2.3c-1.9,0-3.5-0.8-4.8-2.3C284.7,451.5,284,449.2,284,446.2
				z M286.5,446.2c0,2.3,0.4,4,1.2,5.1c0.8,1.1,1.8,1.7,3.1,1.7c1.1,0,2.1-0.6,2.9-1.7c0.8-1.1,1.2-2.8,1.2-5c0-2.3-0.4-3.9-1.2-5
				c-0.8-1.1-1.8-1.7-3.1-1.7c-1.2,0-2.1,0.6-3,1.7C286.9,442.3,286.5,444,286.5,446.2z"/>
			<path id="XMLID_18_" class="st3" d="M309.8,448.6l2.4,0.4c-0.3,2.1-1,3.7-2.1,4.8c-1.1,1.1-2.4,1.6-4,1.6c-1.9,0-3.4-0.8-4.6-2.3
				c-1.2-1.5-1.8-3.8-1.8-6.9c0-3,0.6-5.3,1.8-6.9c1.2-1.5,2.8-2.3,4.7-2.3c1.5,0,2.7,0.5,3.8,1.4s1.7,2.3,2,4.2l-2.4,0.4
				c-0.2-1.2-0.6-2.1-1.2-2.7s-1.3-0.9-2.1-0.9c-1.2,0-2.2,0.5-3,1.6c-0.8,1.1-1.2,2.7-1.2,5.1c0,2.4,0.4,4.1,1.1,5.2
				c0.8,1.1,1.7,1.6,2.9,1.6c0.9,0,1.7-0.4,2.4-1.1C309.2,451.2,309.6,450.1,309.8,448.6z"/>
			<path id="XMLID_20_" class="st3" d="M314.3,455v-24.2h2.4v13.8l5.8-7.1h3.2l-5.5,6.5l6,11h-3l-4.8-9l-1.7,2v6.9H314.3z"/>
			<path id="XMLID_22_" class="st3" d="M337.9,449.3l2.5,0.4c-0.4,1.9-1.2,3.3-2.3,4.2c-1.1,1-2.4,1.4-4.1,1.4c-2,0-3.7-0.8-4.9-2.3
				c-1.3-1.5-1.9-3.8-1.9-6.7c0-3,0.6-5.3,1.9-6.9c1.3-1.6,2.9-2.4,4.8-2.4c1.9,0,3.4,0.8,4.7,2.3c1.2,1.6,1.9,3.8,1.9,6.8l0,0.8
				h-10.7c0.1,2,0.6,3.5,1.4,4.5c0.8,1,1.8,1.5,3,1.5C335.9,452.9,337.2,451.7,337.9,449.3z M329.9,444.5h8c-0.1-1.5-0.4-2.7-1-3.4
				c-0.8-1.1-1.8-1.6-3-1.6c-1.1,0-2,0.5-2.8,1.4C330.4,441.8,330,443,329.9,444.5z"/>
			<path id="XMLID_25_" class="st3" d="M343.5,455v-17.5h2.2v2.7c0.6-1.2,1.1-2,1.5-2.4s1-0.6,1.6-0.6c0.8,0,1.6,0.3,2.5,1l-0.8,2.8
				c-0.6-0.4-1.2-0.6-1.8-0.6c-0.5,0-1,0.2-1.4,0.5c-0.4,0.4-0.7,0.9-0.9,1.5c-0.3,1.1-0.5,2.3-0.5,3.6v9.2H343.5z"/>
			<path id="XMLID_27_" class="st3" d="M353,455v-24.2h2.7l10.4,19v-19h2.5V455h-2.7l-10.4-19v19H353z"/>
			<path id="XMLID_29_" class="st3" d="M382.4,445.5v-2.9l8.4,0v9c-1.3,1.3-2.6,2.2-4,2.8c-1.4,0.6-2.8,0.9-4.2,0.9
				c-1.9,0-3.7-0.5-5.2-1.5c-1.5-1-2.7-2.4-3.6-4.2s-1.3-4.1-1.3-6.7c0-2.6,0.4-4.9,1.3-6.9c0.9-2,2.1-3.4,3.5-4.3
				c1.4-0.9,3.1-1.4,5.1-1.4c1.5,0,2.7,0.3,3.8,0.8c1.1,0.5,2,1.3,2.7,2.3c0.7,1,1.2,2.3,1.6,4.1l-2.4,0.8c-0.3-1.4-0.7-2.4-1.2-3.1
				c-0.5-0.7-1.1-1.2-1.9-1.6c-0.8-0.4-1.7-0.6-2.7-0.6c-1.4,0-2.7,0.3-3.7,1c-1,0.7-1.9,1.8-2.5,3.3c-0.6,1.5-0.9,3.3-0.9,5.4
				c0,3.2,0.7,5.7,2,7.3c1.4,1.6,3.1,2.4,5.3,2.4c1,0,2.1-0.2,3.2-0.7c1.1-0.5,1.9-1.1,2.6-1.8v-4.5H382.4z"/>
		</g>
		<line id="XMLID_7_" class="st4" x1="260.4" y1="425.6" x2="390.9" y2="425.6"/>
	</g></g></svg></a>
	</div></div>'
));

$form->add($section);
print($form);
print_callout('<p><strong>Setting changes are applied via CRON or \'Force Update|Reload\' only!</strong></p>');
?>

<script type="text/javascript">
//<![CDATA[
events.push(function() {

	// Grey out the internal-feed-host exemption list when the master filter is off.
	// The value is left intact (disabled, not cleared); the POST handler preserves the
	// stored exemptions across an off-toggle save, since a disabled field is not sent.
	function pfb_sync_internal_filter() {
		disableInput('pfb_feed_internal_allowlist', !$('#pfb_feed_internal_filter').prop('checked'));
	}

	$('#pfb_feed_internal_filter').click(pfb_sync_internal_filter);
	pfb_sync_internal_filter();

	// ADR-38: grey out facility/severity selects when the syslog toggle is off.
	// Disabled selects are not submitted by the browser; the POST handler preserves
	// the stored values across an off-save so the user's choice is intact on re-enable.
	function pfb_sync_syslog() {
		var enabled = $('#log_syslog').prop('checked');
		disableInput('log_syslog_facility', !enabled);
		disableInput('log_syslog_priority', !enabled);
	}

	$('#log_syslog').click(pfb_sync_syslog);
	pfb_sync_syslog();
});
//]]>
</script>

<?php include('foot.inc');?>

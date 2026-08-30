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

// The ?wizard= GET is STATE-FREE: the "Do not show this again" persist happens in
// the wizard's csrf-magic-validated POST (pfb_wizard_persist_disable, called from
// pfb_wizard_skip_check) BEFORE the redirect here — a state-changing GET would be
// CSRF-forgeable, csrf-magic validates POSTs only (issue #1651).

// Skip the auto-launch for this request ('skip'), permanently ('disable' persisted),
// or once the package has been configured.
if (pfb_wizard_suppress_autolaunch($wizard_action,
    config_get_path('installedpackages/pfblockerng/pfb_wizard_skip'),	// foreign key — out of ADR-29 gateway scope
    config_get_path('installedpackages/pfblockerng/config/0'))) {	// section existence check — not a scalar read
	$pfb_wizard = FALSE;
}

$pfb['gconfig'] = PfbConfig::readSection('installedpackages/pfblockerng/config/0');

$pconfig = array();
$pconfig['enable_cb']			= PfbConfig::read('gen/enable_cb');

// Default 'on' — owned by the registry (ADR-29); PfbConfig::read applies it when absent.
$pconfig['pfb_keep']			= PfbConfig::read('gen/pfb_keep')->value;

// Default 'on' — owned by the registry (ADR-29); PfbConfig::read applies it when absent.
// Pinned 'off' on existing installs by the upgrade migration in pfblockerng_install.inc.
$pconfig['pfb_feed_internal_filter']	= PfbConfig::read('gen/pfb_feed_internal_filter')->value;

// Exemptions from the internal-address feed-host check: IP addresses / CIDR ranges
// (one per line) whose feeds are allowed even when they resolve internally.
$pconfig['pfb_feed_internal_allowlist']	= (string) base64_decode($pfb['gconfig']['pfb_feed_internal_allowlist'] ?? '');

$pconfig['pfb_scheduled_feed_updates'] = PfbConfig::read('gen/pfb_scheduled_feed_updates')->value;
$pconfig['pfb_schedule_weekday'] = PfbConfig::read('gen/pfb_schedule_weekday');
$pconfig['pfb_schedule_hour'] = PfbConfig::read('gen/pfb_schedule_hour');
$pconfig['pfb_schedule_minute'] = PfbConfig::read('gen/pfb_schedule_minute');
$pconfig['skipfeed'] = PfbConfig::read('gen/skipfeed');

$pconfig['pfb_quiet_hours_enabled'] = '';
$pconfig['pfb_quiet_hours_start'] = '00:00';
$pconfig['pfb_quiet_hours_end'] = '06:00';
$pfb_quiet_hours = (string) PfbConfig::read('gen/pfb_quiet_hours');
if (preg_match('/^((?:[01][0-9]|2[0-3]):(?:00|15|30|45))-((?:[01][0-9]|2[0-3]):(?:00|15|30|45))$/D', $pfb_quiet_hours, $matches) === 1
	&& $matches[1] !== $matches[2]) {
	$pconfig['pfb_quiet_hours_enabled'] = 'on';
	$pconfig['pfb_quiet_hours_start'] = $matches[1];
	$pconfig['pfb_quiet_hours_end'] = $matches[2];
}

// Flat list of per-log suffixes shared by the log_max_*/log_max_days_* key families below
// (read here, saved further down) and their validation loops -- one source of truth for
// the per-log key set, in the same order as $log_types further down the file.
$log_suffixes = array('log', 'errlog', 'extraslog', 'ip_blocklog', 'ip_permitlog', 'ip_matchlog', 'ip_parse_err', 'dnslog', 'dnsbl_parse_err', 'dnsreplylog', 'unilog');

foreach ($log_suffixes as $log_suffix) {
	$pconfig['log_max_' . $log_suffix]	= $pfb['gconfig']['log_max_' . $log_suffix]	?: 20000;
}

// ADR-60: per-log age-based retention (days; '0' = disabled). Read via PfbConfig::read
// so the registered default applies when the key is absent (new install / upgrade).
foreach ($log_suffixes as $log_suffix) {
	$pconfig['log_max_days_' . $log_suffix]	= PfbConfig::read('gen/log_max_days_' . $log_suffix);
}

// ADR-38: syslog export toggle. Read via PfbConfig::read so registered default applies.
// log_syslog uses the PfbToggle adapter — extract the scalar .value for pfb_cfg_toggle_read().
$pconfig['log_syslog']			= PfbConfig::read('gen/log_syslog')->value;

// issue #1109: log-trim hysteresis margin (percent, global). Read via PfbConfig::read so
// the registered default ('0') applies when the key is absent (new install / upgrade).
$pconfig['pfb_log_trim_margin_pct']	= PfbConfig::read('gen/pfb_log_trim_margin_pct');

// issue #2851: the one global nested-pass timeout (seconds). Render the EFFECTIVE
// budget from PfbConfig::readSection()'s raw gen-section mirror, then through the same
// mixed-safe resolver both language seams use. A field-level read has no adapter and
// would cast hostile arrays/floats before validation.
$pconfig['pfb_reentry_timeout']		= (string) pfb_reentry_timeout($pfb['gconfig']['pfb_reentry_timeout'] ?? NULL);

// issue #1669 slice C / #1888: client-side editor toggle (default on). Read via
// PfbConfig::read so the registered default applies; pfb_syntax_highlight is a
// default-on toggle field (merged PfbToggle, issue #1887; mirrors pfb_keep) --
// extract the scalar .value for pfb_cfg_toggle_read() at render.
$pconfig['pfb_syntax_highlight']	= PfbConfig::read('gen/pfb_syntax_highlight')->value;

// issue #1875 step 2b: gate the CM6 live-highlight overlay for pfb_feed_internal_allowlist,
// same $pfb_syntaxhl_on idiom pfblockerng_dnsbl.php establishes at its line 38.
$pfb_syntaxhl_on = pfb_editor_enabled();

$pfb_general_editor = pfb_general_editor_render($pfb_syntaxhl_on);

// Select field options
$options_schedule_weekday = [
	'7' => 'Sunday', '1' => 'Monday', '2' => 'Tuesday', '3' => 'Wednesday',
	'4' => 'Thursday', '5' => 'Friday', '6' => 'Saturday',
];
$options_schedule_hour = array_combine(array_map('strval', range(0, 23)), range(0, 23));
$options_schedule_minute = [ '0' => '00', '15' => '15', '30' => '30', '45' => '45' ];
$options_skipfeed	= [ '0' => 'No Limit', '1' => '1', '2' => '2', '3' => '3', '4' => '4', '5' => '5', '6' => '6' ];
$options_log_types	= [	'100' => '100', '1000' => '1,000', '2000' => '2,000', '4000' => '4,000', '6000' => '6,000',
				'8000' => '8,000', '10000' => '10,000', '20000' => '20,000', '40000' => '40,000', '60000' => '60,000',
				'80000' => '80,000', '100000' => '100,000', '200000' => '200,000 - Memory intensive...', '400000' => '400,000',
				'600000' => '600,000', '800000' => '800,000', '1000000' => '1,000,000', '1500000' => '1,500,000',
				'2000000' => '2,000,000', '2500000' => '2,500,000', '3000000' => '3,000,000',
				'nolimit' => 'No Limit - Not recommended' ];

// $input_errors is read unconditionally in the render section below, so it must be
// defined on every request path (incl. a POST without 'save'). Initialise it once.
$input_errors = array();
$schedule_cache_failed = ($_GET['schcache'] ?? '') === 'failed';

// Validate input fields and save
if ($_POST) {
	if (isset($_POST['save'])) {
		$schedule_result = pfb_general_schedule_validate($_POST);
		$input_errors = array_merge($input_errors, $schedule_result['errors']);
		$schedule_values = $schedule_result['values'];

		// issue #1723: sanitize at ingestion -- first step, before any evaluation.
		// The whole-blob trim() folds in here too (persist-site base64_encode() is
		// now plain -- sanitize once, never re-sanitize downstream).
		$_POST['pfb_feed_internal_allowlist'] = trim(pfb_sanitize_text_area((string) ($_POST['pfb_feed_internal_allowlist'] ?? '')));

		// Validate Select field options
		$select_options = array(	'skipfeed'			=> 0,
						'log_max_log'			=> 20000,
						'log_max_errlog'		=> 20000,
						'log_max_extraslog'		=> 20000,
						'log_max_ip_blocklog'		=> 20000,
						'log_max_ip_permitlog'		=> 20000,
						'log_max_ip_matchlog'		=> 20000,
						'log_max_ip_parse_err'		=> 20000,
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
				// @phpstan-ignore variable.undefined, variable.undefined, variable.undefined, variable.undefined, variable.undefined, variable.undefined, variable.undefined, variable.undefined, variable.undefined, variable.undefined, variable.undefined (11x: the strpos guard above consumes all log_max_* keys before this line runs; PHPStan doesn't narrow the literal union, so it still considers all 11 log_max_* completions reachable here)
				$query = ${"options_$s_option"};
			}

			if (is_array($_POST[$s_option])) {
				$_POST[$s_option] = $s_default;
			}
			elseif (!array_key_exists($_POST[$s_option], $query)) {
				$_POST[$s_option] = $s_default;
			}
		}

		// ADR-60: validate per-log age-based retention fields (non-negative integer string).
		foreach ($log_suffixes as $log_suffix) {
			$dkey = 'log_max_days_' . $log_suffix;
			$v = $_POST[$dkey] ?? '0';
			if (is_array($v) || !ctype_digit((string) $v)) {
				$_POST[$dkey] = '0';
			}
		}

		// issue #1109: canonicalize the log-trim hysteresis margin through the same parser
		// the backend reads it with, so the STORED value is the effective one -- storing an
		// out-of-range '999999999' would render a number the runtime clamp never uses.
		$_POST['pfb_log_trim_margin_pct'] = (string) pfb_log_trim_margin_pct($_POST['pfb_log_trim_margin_pct'] ?? '0');

		// issue #2851: canonicalize the nested-pass timeout through the same resolver the
		// PHP and shell seams read it with, so the STORED value IS the effective one --
		// storing an out-of-range '9999' would claim a budget neither seam ever uses. An
		// array (crafted POST) reaches the untyped resolver and lands on the default.
		$_POST['pfb_reentry_timeout'] = (string) pfb_reentry_timeout($_POST['pfb_reentry_timeout'] ?? NULL);

		if (!$input_errors) {

			$pfb['gconfig']['enable_cb']			= pfb_filter($_POST['enable_cb'], PFB_FILTER_ON_OFF, 'general', '');
			$pfb['gconfig']['pfb_keep']			= pfb_filter($_POST['pfb_keep'] ?? '', PFB_FILTER_ON_OFF, 'general') ?: '';

			$pfb['gconfig']['pfb_feed_internal_filter']	= pfb_filter($_POST['pfb_feed_internal_filter'] ?? '', PFB_FILTER_ON_OFF, 'general') ?: '';

			// The allowlist textarea is greyed (disabled) when the filter is off, so the
			// browser does not submit it. Preserve the previously stored value in that
			// case rather than overwriting it with the absent POST field.
			if ($pfb['gconfig']['pfb_feed_internal_filter'] === 'on') {
				$pfb['gconfig']['pfb_feed_internal_allowlist']	= base64_encode($_POST['pfb_feed_internal_allowlist'] ?? '');
			}
			$pfb['gconfig']['pfb_scheduled_feed_updates'] = $schedule_values['pfb_scheduled_feed_updates'];
			$pfb['gconfig']['pfb_schedule_weekday'] = $schedule_values['pfb_schedule_weekday'];
			$pfb['gconfig']['pfb_schedule_hour'] = $schedule_values['pfb_schedule_hour'];
			$pfb['gconfig']['pfb_schedule_minute'] = $schedule_values['pfb_schedule_minute'];
			$pfb['gconfig']['pfb_quiet_hours'] = $schedule_values['pfb_quiet_hours'];
			$pfb['gconfig']['skipfeed']			= $_POST['skipfeed']				?: 0;

			// Remove old Line Limit setting
			unset($pfb['gconfig']['log_maxlines']);

			foreach ($log_suffixes as $log_suffix) {
				$pfb['gconfig']['log_max_' . $log_suffix]	= $_POST['log_max_' . $log_suffix]	?: 20000;
			}

			// ADR-60: persist per-log age-based retention (validated above; default '0').
			// Written into $pfb['gconfig'] so the writeSection() call below includes it in
			// the section; a bare PfbConfig::write() would be overwritten by writeSection.
			foreach ($log_suffixes as $log_suffix) {
				$pfb['gconfig']['log_max_days_' . $log_suffix]	= $_POST['log_max_days_' . $log_suffix]	?: '0';
			}

			// issue #1109: persist the log-trim hysteresis margin (validated above; default
			// '0'). Written into $pfb['gconfig'] so writeSection() below includes it -- a bare
			// PfbConfig::write() would be overwritten by writeSection.
			$pfb['gconfig']['pfb_log_trim_margin_pct']	= $_POST['pfb_log_trim_margin_pct']	?: '0';

			// issue #2851: persist the nested-pass timeout (canonicalized above). Written
			// into $pfb['gconfig'] so writeSection() below includes it -- a bare
			// PfbConfig::write() would be overwritten by the section-level write.
			$pfb['gconfig']['pfb_reentry_timeout']		= $_POST['pfb_reentry_timeout'];

			// ADR-38: persist syslog export toggle. Written into $pfb['gconfig'] so the
			// writeSection() call below includes it; a bare PfbConfig::write() before
			// writeSection() would be clobbered by the section-level write.
			// Facility and priority are fixed constants in pfb_syslog_event() and no
			// longer stored; the daemon reads the toggle fresh on each event so no
			// service restart is needed when the toggle changes.
			$pfb['gconfig']['log_syslog']	= pfb_filter($_POST['log_syslog'], PFB_FILTER_ON_OFF, 'general', '');

			$pfb['gconfig']['pfb_syntax_highlight']	= pfb_filter($_POST['pfb_syntax_highlight'] ?? '', PFB_FILTER_ON_OFF, 'general') ?: '';

			PfbConfig::writeSection('installedpackages/pfblockerng/config/0', $pfb['gconfig']);
			write_config('[pfBlockerNG] save General settings');
			$runtime_model = pfb_schedule_runtime_config();
			$runtime_state = pfb_schedule_state_read($pfb['schedule_state_dir'] ?? '/usr/local/etc');
			$runtime_timezone = $pfb['schedule_timezone'] ?? date_default_timezone_get();
			try {
				$runtime_timezone = $runtime_timezone instanceof DateTimeZone
					? $runtime_timezone : new DateTimeZone((string) $runtime_timezone);
			} catch (Throwable) {
				$runtime_timezone = NULL;
			}
			$candidate_file = @tempnam(sys_get_temp_dir(), 'pfb_sched_');
			$candidate_dir = $candidate_file === FALSE ? '' : $candidate_file . '.d';
			if ($candidate_file !== FALSE) {
				@unlink($candidate_file);
				if (!@mkdir($candidate_dir, 0700)) {
					$candidate_dir = '';
				}
			}
			// issue #2855: name the stage that failed instead of collapsing six checks into
			// one boolean. pfb_schedule_runtime_config() logs the 'config' detail itself.
			$cache_stage = pfb_schedule_cache_stage(
				$runtime_model, $runtime_state, $runtime_timezone, $candidate_dir
			);
			$cache_ok = $cache_stage === '';
			if ($candidate_dir !== '') {
				foreach (scandir($candidate_dir) ?: [] as $candidate_artifact) {
					if ($candidate_artifact !== '.' && $candidate_artifact !== '..') {
						@unlink("{$candidate_dir}/{$candidate_artifact}");
					}
				}
				@rmdir($candidate_dir);
			}
			$pfb['save'] = TRUE;
			sync_package_pfblockerng();
			if (!$cache_ok) {
				logger(LOG_NOTICE, localize_text('General save: schedule-cache generation failed - %s',
					pfb_schedule_cache_stage_label($cache_stage)), LOG_PREFIX_PKG_PFBLOCKERNG);
			}
			header('Location: ' . pfb_general_schedule_save_redirect(
				$cache_ok, '/pfblockerng/pfblockerng_general.php?schcache=failed&schstage=' . $cache_stage
			));
			exit;
		}
	}
}

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'));
$pglinks = array('', '@self');
$shortcut_section = 'pfblockerng';
include_once('head.inc');

if ($input_errors) {
	print_input_errors($input_errors);
}
if ($schedule_cache_failed) {
	print_info_box(sprintf(gettext('Settings were saved, but schedule-cache generation failed: %s. '
		. 'The system log records the detail under pfBlockerNG; quote that line if you report this.'),
		pfb_schedule_cache_stage_label(is_string($_GET['schstage'] ?? NULL) ? $_GET['schstage'] : '')),
		'warning');
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
	pfb_print_pending_changes_box();
}

$form = new Form('Save');

$section = new Form_Section('General Settings');
$section->addInput(new Form_StaticText(
	'Links',
	'<small>'
	. '<a href="/firewall_aliases.php" target="_blank" rel="noopener noreferrer">Firewall Aliases</a>&emsp;'
	. '<a href="/firewall_rules.php" target="_blank" rel="noopener noreferrer">Firewall Rules</a>&emsp;'
	. '<a href="/status_logs_filter.php" target="_blank" rel="noopener noreferrer">Firewall Logs</a></small>'
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
		. ' If \'Keep Settings\' is not \'enabled\' on pkg Install/De-Install, all settings will be Wiped!<br />'
		. ' This also applies to a major pfSense version upgrade, which fully removes and reinstalls '
		. 'packages &mdash; with \'Keep Settings\' disabled it wipes pfBlockerNG\'s settings too. A normal '
		. 'package update keeps them.<br /><br />'
		. '<span class="text-danger">Note: </span>'
		. ' To clear all downloaded lists, uncheck this checkbox and \'Save\'. Re-check it and run a \'Force Update|Reload\''
);

$section->addInput(new Form_Checkbox(
	'pfb_feed_internal_filter',
	'Block Private-Address',
	gettext('Enable'),
	pfb_cfg_toggle_read($pconfig['pfb_feed_internal_filter']) === PfbToggle::On,
	'on'
))->setHelp('Restrict feeds from being fetched from non-public/internal addresses. '
		. 'The exemptions list below allows specific IP/CIDRs through.'
);

$section->addInput(new Form_Textarea(
	'pfb_feed_internal_allowlist',
	'Block Private-Address Exceptions',
	$pconfig['pfb_feed_internal_allowlist']
))->setAttribute('rows', '1')
  ->setAttribute('data-pfb-autogrow-max', '5')
  ->setWidth(8)
  ->setHelp('IP addresses or CIDR ranges (one per line) that are exempt from the '
		. 'internal-address check &mdash; e.g. an internal mirror. '
		. 'Leave empty to block all feeds that resolve to an internal/private address.'
);

// issue #1669 slice C: the client-side editor for the list and script fields. Label and
// help cover the whole editor (issue #1888) -- the config key stays pfb_syntax_highlight.
$section->addInput(new Form_Checkbox(
	'pfb_syntax_highlight',
	pfb_general_toggle_label(),
	gettext('Enable'),
	pfb_cfg_toggle_read($pconfig['pfb_syntax_highlight']) === PfbToggle::On,
	'on'
))->setHelp(pfb_general_toggle_help());

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

$section = new Form_Section('Scheduling');
$section->addInput(new Form_Checkbox(
	'pfb_scheduled_feed_updates',
	'Scheduled Feed Updates',
	gettext('Enable'),
	$pconfig['pfb_scheduled_feed_updates'] === 'on',
	'on'
))->setHelp('Run enabled feed groups on their configured schedules. This does not affect manual updates, Extras refreshes, or pending applies.<br />'
	);

$group = new Form_Group('Default Schedule');
$group->setHelp('Default local-time schedule for feed groups and calendar-scheduled Extras. Hourly schedules use the minute; daily schedules use the time; weekly schedules use all three.');
$group->add(new Form_Select(
	'pfb_schedule_weekday',
	'Weekday',
	$pconfig['pfb_schedule_weekday'],
	$options_schedule_weekday
))->setHelp('Sunday first.');
$group->add(new Form_Select(
	'pfb_schedule_hour',
	'Hour',
	$pconfig['pfb_schedule_hour'],
	$options_schedule_hour
))->setHelp('Local hour (00–23).');
$group->add(new Form_Select(
	'pfb_schedule_minute',
	'Minute',
	$pconfig['pfb_schedule_minute'],
	$options_schedule_minute
))->setHelp('Quarter-hour minute.');
$section->add($group);

$section->addInput(new Form_Checkbox('pfb_quiet_hours_enabled',
	'Automatic Apply Window',
	gettext('Restrict automatic applies to a time window'),
	$pconfig['pfb_quiet_hours_enabled'] === 'on',
	'on'
))->setHelp('Changes detected outside this window remain pending and apply on the first eligible tick inside it.');

$group = new Form_Group('Apply Window');
$group->add((new Form_Input(
	'pfb_quiet_hours_start',
	'Start',
	'time',
	$pconfig['pfb_quiet_hours_start']
))->setAttribute('step', '900'))->setWidth(4);
$group->add((new Form_Input(
	'pfb_quiet_hours_end',
	'End',
	'time',
	$pconfig['pfb_quiet_hours_end']
))->setAttribute('step', '900'))->setWidth(4);
$section->add($group);
$form->add($section);

// issue #489: Log Settings — grouped by category, one row per log. Column titles
// (Max lines / Max days) are labelled once at the top on desktop; each category is a
// full-width centred divider. On xs the column-title row is hidden and per-control
// label-start labels name the stacked fields.
$section = new Form_Section('Log Settings');
$log_types = array(
	'General'	=> array('pfBlockerNG' => 'log', 'Unified' => 'unilog', 'Error' => 'errlog', 'Extras' => 'extraslog'),
	'IP'		=> array('Block' => 'ip_blocklog', 'Permit' => 'ip_permitlog', 'Match' => 'ip_matchlog', 'Parse Error' => 'ip_parse_err'),
	'DNS'		=> array('Block' => 'dnslog', 'Reply' => 'dnsreplylog', 'Parse Error' => 'dnsbl_parse_err'),
);

// Intro explains the two columns. Trim Margin help stays on that field (not repeated here).
// Desktop hide of label-start is scoped to .pfb-logrow so other form-label uses on this
// page are not suppressed.
$section->addInput(new Form_StaticText(
	'',
	'<style>'
	. '@media (min-width: 768px) { .pfb-logrow label.form-label { display: none; } }'
	. '@media (max-width: 767px) { .pfb-logcolhdr { display: none; } }'
	. pfb_form_subhdr_css_rules()
	. '.pfb-logtrim { margin-top: 14px; padding-top: 10px; }'
	. '</style>'
	. '<ul style="margin-bottom:0">'
	. '<li><strong>Max lines</strong> &mdash; rolling cap; the log keeps only its most recent N lines.</li>'
	. '<li><strong>Max days</strong> &mdash; trims lines older than this many days (0 = disabled); '
	. 'independent of Max lines &mdash; whichever cap is more restrictive wins.</li>'
	. '</ul>'
));

$colhdr = new Form_Group('');
$colhdr->addClass('pfb-logcolhdr');
$colhdr->add(new Form_StaticText('', '<p class="form-control-static hidden-xs"><strong>Max lines</strong></p>'))->setWidth(4);
$colhdr->add(new Form_StaticText('', '<p class="form-control-static hidden-xs"><strong>Max days</strong></p>'))->setWidth(4);
$section->add($colhdr);

foreach ($log_types as $logdescr => $logtype) {
	$section->add(pfb_form_subhdr($logdescr, 'pfb-loghdr'));

	// One row per log in this category. Each control carries a label-start so the column is
	// named on mobile (hidden on desktop via the scoped media query above).
	foreach ($logtype as $descr => $type) {
		$group = new Form_Group($descr);
		$group->addClass('pfb-logrow');
		$group->add(new Form_Select(
			'log_max_' . $type,
			'',
			$pconfig['log_max_' . $type],
			$options_log_types
		))->setWidth(4)->setAttribute('label-start', 'Max lines');
		$group->add((new Form_Input(
			'log_max_days_' . $type,
			'',
			'number',
			$pconfig['log_max_days_' . $type]
		))->setAttribute('min', '0'))->setWidth(4)->setAttribute('label-start', 'Max days');
		$section->add($group);
	}
}

// issue #1109: log-trim hysteresis margin -- a single global percentage applying to both
// the line and age caps. Sits with syslog, after the table it describes.
$trim = new Form_Group('Trim Margin');
$trim->addClass('pfb-logtrim');
$trim->add((new Form_Input(
	'pfb_log_trim_margin_pct',
	null,
	'number',
	$pconfig['pfb_log_trim_margin_pct']
))->setAttribute('min', '0')->setAttribute('max', '1000'));
$trim->setHelp(
	'Percent tolerance above whichever cap (Max lines or Max days) is active. The log is '
	. 'rewritten only once it drifts past cap + margin%, then trimmed back to the exact cap. '
	. '<strong>0</strong> (default) trims as soon as the cap is exceeded. A larger margin means '
	. 'fewer, larger rewrites &mdash; less flash/SSD wear.'
);
$section->add($trim);

// ADR-38: syslog export controls — appended at the end of the Log Settings section.
$section->addInput(new Form_Checkbox(
	'log_syslog',
	'Send Security Events to System Log',
	gettext('Enable'),
	pfb_cfg_toggle_read($pconfig['log_syslog']) === PfbToggle::On,
	'on'
))->setHelp('When enabled, every IP Block/Permit/Match and DNSBL block event is also '
		. 'emitted to syslog (tagged <code>pfblockerng</code>, in <code>key=value</code> form) '
		. 'at facility <strong>local6</strong> and severity <strong>info</strong>. '
		. 'Remote delivery: pfSense '
		. '<strong>Status &gt; System Logs &gt; Settings &gt; Remote Logging &rarr; Everything</strong>.'
);

$form->add($section);

// issue #2851: the operator surface for issue #2016's nested-pass budget. Advanced and
// collapsed by default, the same shape the IP tab's 'ip_advanced' panel uses.
$section = new Form_Section('Advanced Settings', 'general_advanced', COLLAPSIBLE|SEC_CLOSED);
$section->addInput(new Form_Input(
	'pfb_reentry_timeout',
	'Nested pass timeout',
	'number',
	$pconfig['pfb_reentry_timeout'],
	[ 'min' => (string) PFB_REENTRY_TIMEOUT_MIN, 'max' => (string) PFB_REENTRY_TIMEOUT_MAX,
	  'placeholder' => (string) PFB_REENTRY_TIMEOUT ]
))->setHelp('Default: <strong>' . PFB_REENTRY_TIMEOUT . '</strong> seconds (range '
		. PFB_REENTRY_TIMEOUT_MIN . '&ndash;' . PFB_REENTRY_TIMEOUT_MAX . ', whole seconds).<br />'
		. 'Time budget for ONE nested update pass &mdash; the MaxMind/GeoIP, blacklist, '
		. 'TOP1M and ASN downloads an update pass runs as child processes.<br />'
		. 'On expiry the <strong>whole process tree</strong> is terminated, not just the '
		. 'interpreter, so a stalled download cannot outlive it; the expiry is named in the '
		. 'pfBlockerNG and Error logs and the pass continues to a defined state. The download '
		. 'is retried by the next scheduled update, or immediately via '
		. '<strong>Force Update</strong>.<br />'
		. 'Raise it for low-powered hardware or slow links where a full download pass needs '
		. 'longer. A blank, non-numeric or out-of-range value falls back to '
		. PFB_REENTRY_TIMEOUT . ' seconds.');

$form->add($section);

$section = new Form_Section('Support');
$section->addInput(new Form_StaticText(
	null,
	'
<div class="row">
<div class="col-sm-9">
	<strong>pfBlockerNG</strong> is created by
	<a target="_blank" rel="noopener noreferrer" href="https://github.com/BBcan177">BBcan177</a>,
	who designs, supports and maintains it with
	<a target="_blank" rel="noopener noreferrer" href="https://github.com/andrebrait">André Brait</a>.<br />

	<ul class="list-inline" style="margin-top: 4px; margin-bottom: -2px; border-style: outset; border-bottom-color: #8B181B; border-right-color: #8B181B; border-width: 2px;">
		<li class="list-inline-item"><a target="_blank" rel="noopener noreferrer" href="https://pfblockerng.com">
			<span style="color: #8B181B;" class="fa-solid fa-globe"></span> HomePage</a></li>
		<li class="list-inline-item"><a target="_blank" rel="noopener noreferrer" href="https://twitter.com/intent/follow?screen_name=BBcan177">
			<span style="color: #8B181B;" class="fa-brands fa-twitter"></span> Follow on X formerly Twitter</a></li>
		<li class="list-inline-item"><a target="_blank" rel="noopener noreferrer" href="https://www.reddit.com/r/pfBlockerNG/new/">
			<span style="color: #8B181B;" class="fa-brands fa-reddit"></span> Reddit</a></li>
		<li class="list-inline-item"><a target="_blank" rel="noopener noreferrer" href="https://infosec.exchange/@BBcan177#">
			<span style="color: #8B181B;" class="fa-solid fa-globe"></span> Mastodon</a></li>
		<li class="list-inline-item"><a target="_blank" rel="noopener noreferrer" href="https://github.com/pfBlockerNG/pfBlockerNG">
			<span style="color: #8B181B;" class="fa-brands fa-github"></span> GitHub</a></li>
		<li class="list-inline-item"><a target="_blank" rel="noopener noreferrer" href="mailto:bbcan177@gmail.com?Subject=pfBlockerNG%20Support">
			<span style="color: #8B181B;" class="fa-regular fa-envelope"></span> Contact Us</a></li>
	</ul>
	<span class="pull-right"><small>Based upon pfBlocker by Marcello Coutinho and Tom Schaefer.</small></span>
</div>

<div class="col-sm-3" style="color-scheme: only light; text-align: center">
	<a target="_blank" rel="noopener noreferrer" href="https://pfblockerng.com">

<svg version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px"
	 viewBox="128 172 384 384" style="display:block;margin-left:auto;margin-right:auto;width:100%;height:auto;max-width:140pt;" xml:space="preserve">
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
<?=$pfb_general_editor['asset']?>

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

	function pfb_sync_quiet_hours() {
		var enabled = $('#pfb_quiet_hours_enabled').prop('checked');
		disableInput('pfb_quiet_hours_start', !enabled);
		disableInput('pfb_quiet_hours_end', !enabled);
	}

	$('#pfb_quiet_hours_enabled').click(pfb_sync_quiet_hours);
	pfb_sync_quiet_hours();

<?=$pfb_general_editor['lists']?>
<?=pfb_autogrow_textarea_js('pfb_feed_internal_allowlist', 5)?>

});
//]]>
</script>

<?php include('foot.inc');?>

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
require_once('pkg-utils.inc');
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
$pconfig['pfb_feed_internal_allowlist']	= (string) base64_decode(PfbConfig::read('gen/pfb_feed_internal_allowlist'));

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

// The gateway normalizes before scalar coercion, using the shared timeout resolver.
$pconfig['pfb_reentry_timeout']		= PfbConfig::read('gen/pfb_reentry_timeout');

// issue #1669 slice C / #1888: client-side editor toggle (default on). Read via
// PfbConfig::read so the registered default applies; pfb_syntax_highlight is a
// default-on toggle field (merged PfbToggle, issue #1887; mirrors pfb_keep) --
// extract the scalar .value for pfb_cfg_toggle_read() at render.
$pconfig['pfb_syntax_highlight']	= PfbConfig::read('gen/pfb_syntax_highlight')->value;

// #3522: metrics export toggle (default off). Read here for the render; the save gate reads the POST.
$pconfig['pfb_metrics_export']	= PfbConfig::read('gen/pfb_metrics_export')->value;

// Read once per request: the save gate and the render both depend on them.
$metrics_export_pkg = is_pkg_installed('pfSense-pkg-node_exporter');
$metrics_export_stored_on = PfbConfig::read('gen/pfb_metrics_export') === PfbToggle::On;

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

		// Server-side gate: a crafted POST cannot turn the option on without the package.
		$metrics_export_posted = pfb_filter($_POST['pfb_metrics_export'] ?? '', PFB_FILTER_ON_OFF, 'general');
		$metrics_export_error = pfb_metrics_export_allowed($metrics_export_posted, $metrics_export_pkg, $metrics_export_stored_on);
		if ($metrics_export_error !== NULL) {
			$input_errors[] = $metrics_export_error;
		}

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

			// The gate above refuses a new 'on' without node_exporter, so only a valid value reaches here.
			$pfb['gconfig']['pfb_metrics_export']	= $metrics_export_posted ?: '';

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
	$tab_array[]	= array(gettext('DNS'),		FALSE,	'/pfblockerng/pfblockerng_dns_general.php');
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
))->setHelp('Turn pfBlockerNG on. Blue (i) icons open more help.');

$section->addInput(new Form_Checkbox(
	'pfb_keep',
	'Keep Settings',
	gettext('Enable'),
	pfb_cfg_toggle_read($pconfig['pfb_keep']) === PfbToggle::On,
	'on'
))->setHelp('<p><strong>Keep Settings</strong> preserves settings and downloaded lists during package removal and while pfBlockerNG is disabled. A normal package update keeps them regardless.</p>'
		. '<p><span class="text-danger"><strong>Warning:</strong></span> With <strong>Keep Settings</strong> off, removing the package, including removal during a major pfSense upgrade, deletes its settings, logs and lists.</p>'
		. '<p>To clear downloaded lists:</p>'
		. '<ol>'
		. '<li>Turn off <strong>pfBlockerNG</strong> and <strong>Keep Settings</strong>, then save.</li>'
		. '<li>Turn both settings back on and save again.</li>'
		. '<li>Open <strong>Update</strong> and use <strong>Run Now</strong>.</li>'
		. '</ol>'
);

$section->addInput(new Form_Checkbox(
	'pfb_feed_internal_filter',
	'Block Private-Address',
	gettext('Enable'),
	pfb_cfg_toggle_read($pconfig['pfb_feed_internal_filter']) === PfbToggle::On,
	'on'
))->setHelp('Restrict feeds from being fetched from non-public/internal addresses. '
		. 'Use <strong>Block Private-Address Exceptions</strong> to allow additional internal feed hosts.'
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
		. 'Leave empty to block every internal/private feed host except this firewall itself.'
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

// Disabled without node_exporter unless the option is stored on: then it stays enabled so it can be turned off.
$metrics_export_box = new Form_Checkbox(
	'pfb_metrics_export',
	'Metrics export',
	gettext('Enable'),
	pfb_cfg_toggle_read($pconfig['pfb_metrics_export']) === PfbToggle::On,
	'on'
);
if (pfb_metrics_export_box_disabled($metrics_export_pkg, $metrics_export_stored_on)) {
	$metrics_export_box->setAttribute('disabled', 'disabled');
}
$section->addInput($metrics_export_box)->setHelp(
	'Publish Prometheus metrics through the node_exporter package\'s textfile collector (<code>/var/tmp/node_exporter/pfblockerng.prom</code>).'
	. ($metrics_export_pkg ? '' : '<br /><span class="text-danger">Requires the <a href="/pkg_mgr_install.php?pkg=pfSense-pkg-node_exporter">node_exporter package</a>.</span>')
);

$section->addInput(new Form_Select(
	'skipfeed',
	'Download Failure Threshold',
	$pconfig['skipfeed'],
	$options_skipfeed
))->setHelp('<p>Default: <strong>3</strong> on a new install; an upgrade without a saved value uses <strong>No Limit</strong>.</p>'
		. '<p>Failed downloads per feed per day after which retries stop until the next day. <strong>No Limit</strong>: always retry. The last good copy stays in use. Use <strong>Clear Failed Downloads</strong> in the widget to reset the count.</p>')
  ->setAttribute('style', 'width: auto');

$form->add($section);

$section = new Form_Section('Scheduling');
$section->addInput(new Form_Checkbox(
	'pfb_scheduled_feed_updates',
	'Scheduled Feed Updates',
	gettext('Enable'),
	$pconfig['pfb_scheduled_feed_updates'] === 'on',
	'on'
))->setHelp('Run enabled feed groups on their configured schedules. This does not affect manual updates, Extras refreshes, or pending applies.'
	);

$group = new Form_Group('Default Schedule');
$group->setHelp('Default local-time schedule for feed groups and calendar-scheduled Extras. Hourly schedules use <strong>Minute</strong>; daily schedules use <strong>Hour</strong> and <strong>Minute</strong>; weekly schedules also use <strong>Weekday</strong>.');
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
))->setHelp('Pending changes are applied only inside this window.');

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
	'Percent tolerance above whichever cap (<strong>Max lines</strong> or <strong>Max days</strong>) is active. The log is '
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
		. '<strong>Status &gt; System Logs &gt; Settings &gt; Remote Logging &rarr; Everything</strong>. '
		. 'View events locally under <strong>Status &gt; System Logs &gt; Packages &gt; pfBlockerNG</strong>.'
);

$form->add($section);

// issue #2851: the operator surface for issue #2016's nested-pass budget. Advanced and
// collapsed by default, the same shape the IP tab's 'ip_advanced' panel uses.
$section = new Form_Section('Advanced Settings', 'general_advanced', COLLAPSIBLE|SEC_CLOSED);
$section->addInput(new Form_Input(
	'pfb_reentry_timeout',
	'Database download timeout',
	'number',
	$pconfig['pfb_reentry_timeout'],
	[ 'min' => (string) PFB_REENTRY_TIMEOUT_MIN, 'max' => (string) PFB_REENTRY_TIMEOUT_MAX,
	  'placeholder' => (string) PFB_REENTRY_TIMEOUT ]
))->setHelp('Default: <strong>' . PFB_REENTRY_TIMEOUT . '</strong> seconds (range '
		. PFB_REENTRY_TIMEOUT_MIN . '&ndash;' . PFB_REENTRY_TIMEOUT_MAX . ').<br />'
		. 'Maximum time for each nested download pass (MaxMind, ASN, TOP1M and DNSBL Category) during an update, not for each download. '
		. 'A pass that runs longer is stopped with all its downloads, logged, and retried at the next update. '
		. 'Raise it on slow links or hardware. A blank, non-numeric or out-of-range value falls back to '
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

	<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" style="display:block;margin-left:auto;margin-right:auto;width:100%;height:auto;max-width:140pt;" role="img" aria-label="pfBlockerNG">
		<rect width="256" height="256" rx="46" fill="#2b2b2b"/>
		<g transform="translate(128 128) scale(1.11) translate(-144.5 -115.5)">
			<path fill="#58585a" d="M66 43 C85 32 105 24 125 19 C158 20 195 29 223 40 L222 47 C183 29 122 31 66 50 Z"/>
			<path fill="#8b181a" d="M66 64 L109 107 L110 199 L83 168 C73 157 71 149 70 132 Z"/>
			<path fill="#8b181a" d="M184 42 C200 43 214 46 222 51 L212 127 C207 166 172 190 126 212 L117 207 L117 171.5 L143 140 L143 89 Z"/>
			<path fill="#ffffff" d="M67 55 C101 44 138 39 175 41 L135 87 L135 100 L116 122 L116 103 Z"/>
			<path fill="#58585a" d="M116.8 133.24 L135 112.39 L135 137.53 L116.8 159.51 Z"/>
		</g>
	</svg></a>
	</div></div>'
));

$form->add($section);
print($form);
print_callout('<p><strong>General</strong> settings take effect when saved. Apply pending list and rule changes from other pages using <strong>Run Now</strong> on <strong>Update</strong>.</p>');
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

<?php
/*
 * pfblockerng_update.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2016-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2015-2024 BBcan177@gmail.com
 * All rights reserved.
 *
 * Portions of this code are based on original work done for
 * pfSense from the following contributors:
 *
 * pkg_mgr_install.php
 * Part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2005 Colin Smith
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

// Disable NGINX output buffering
header("X-Accel-Buffering: no");

require_once('guiconfig.inc');
require_once('globals.inc');
require_once('pfsense-utils.inc');
require_once('functions.inc');
require_once('util.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');

global $pfb;
pfb_global();

// Collect pfBlockerNG log file and post live output to terminal window.
function pfbupdate_output($text) {
	$text = htmlspecialchars(str_replace("\n", "\\n", $text), ENT_COMPAT);
	print("\n<script type=\"text/javascript\">");
	print("\n//<![CDATA[");
	print("\nthis.document.forms[0].pfb_output.value = \"" . $text . "\";");
	print("\nthis.document.forms[0].pfb_output.scrollTop = this.document.forms[0].pfb_output.scrollHeight;");
	print("\n//]]>");
	print("\n</script>");
	/* ensure that contents are written out */
	ob_flush();
}


// Post status message to terminal window.
function pfbupdate_status($status) {
	$status = htmlspecialchars(str_replace("\n", "\\n", $status), ENT_COMPAT);
	print("\n<script type=\"text/javascript\">");
	print("\n//<![CDATA[");
	print("\nthis.document.forms[0].pfb_status.value=\"" . $status . "\";");
	print("\n//]]>");
	print("\n</script>");
	/* ensure that contents are written out */
	ob_flush();
}


// Dispatch pfb_trigger via the Phase-3 explicit API, stream log output,
// then update the due ledger so the Schedule view reflects the manual run.
function pfb_runnow(string $scope, bool $force): void {
	global $pfb;

	// Check for any active pfBlockerNG process before dispatching.
	exec('/bin/ps -wax', $result_ps);
	if (preg_grep('/pfblockerng[.]php\s+?(cron|update|pfb_trigger|tick)/', $result_ps)) {
		pfbupdate_status(gettext('Run Now skipped — an active pfBlockerNG task is running.'));
		return;
	}

	if (!file_exists("{$pfb['log']}")) {
		touch("{$pfb['log']}");
	}

	$trigger     = $force ? 'force' : 'manual';
	$force_val   = $force ? 'true'  : 'false';
	$scope_esc   = escapeshellarg($scope);
	$trigger_esc = escapeshellarg($trigger);

	pfbupdate_status(gettext("Running: scope={$scope} force={$force_val}"));

	// Remove the tick cron to prevent overlap; sync_package_pfblockerng() restores it.
	install_cron_job('pfblockerng.php tick', FALSE);

	pfb_logger("\n [ Run Now - scope={$scope} force={$force_val} trigger={$trigger} ]\n", 1);

	// Record $now before dispatching so last_run reflects when the run was requested.
	$now = time();
	mwexec_bg("/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php pfb_trigger scope={$scope_esc} force={$force_val} trigger={$trigger_esc} >> {$pfb['log']} 2>&1");

	// Block until the bg process writes "UPDATE PROCESS ENDED".
	pfb_livetail($pfb['log'], 'force');

	// Update the 'cron' ledger entry so the Schedule view reflects this manual run.
	// jitter_max=0 mirrors the tick's cron dispatch (no spread for manual runs).
	$interval = ((int)($pfb['interval'] ?: 1)) * 3600;
	pfb_due_ledger_mark_ran('cron', $interval, $now, pfb_tick_seed(), 0, $pfb['dbdir']);
}

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('Update'));
$pglinks = array('', '/pfblockerng/pfblockerng_general.php', '@self');
$shortcut_section = 'pfblockerng';
include_once('head.inc');

$pconfig = array();
if ($_POST) {
	$pconfig = $_POST;
}

// Wizard handler (updated to Phase-3 API: scope=both force-reparse).
$pfb_wizard = FALSE;
if (isset($_GET) && isset($_GET['wizard']) && $_GET['wizard'] == 'reload') {
	$pconfig['run']           = '';
	$pconfig['pfb_scope']     = 'both';
	$pconfig['pfb_run_force'] = 'on';	// reparse = Force Reload equivalent
	$pfb_wizard               = TRUE;
}

// Validate user-supplied scope; default to 'both' for unexpected input.
$pfb_allowed_scopes = array('ip', 'dnsbl', 'both');
if (isset($pconfig['pfb_scope']) && !in_array($pconfig['pfb_scope'], $pfb_allowed_scopes, TRUE)) {
	$pconfig['pfb_scope'] = 'both';
}

// Define default Alerts Tab href link (Top row)
$get_req = pfb_alerts_default_page();

$tab_array	= array();
$tab_array[]	= array(gettext('General'),	FALSE,	'/pfblockerng/pfblockerng_general.php');
$tab_array[]	= array(gettext('IP'),		FALSE,	'/pfblockerng/pfblockerng_ip.php');
$tab_array[]	= array(gettext('DNSBL'),	FALSE,	'/pfblockerng/pfblockerng_dnsbl.php');
$tab_array[]	= array(gettext('Update'),	TRUE,	'/pfblockerng/pfblockerng_update.php');
$tab_array[]	= array(gettext('Reports'),	FALSE,	"/pfblockerng/pfblockerng_alerts.php{$get_req}");
$tab_array[]	= array(gettext('Feeds'),	FALSE,	'/pfblockerng/pfblockerng_feeds.php');
$tab_array[]	= array(gettext('Logs'),	FALSE,	'/pfblockerng/pfblockerng_log.php');
$tab_array[]	= array(gettext('Sync'),	FALSE,	'/pfblockerng/pfblockerng_sync.php');
pfb_software_add_tab($tab_array);
display_top_tabs($tab_array, TRUE);

// Update sub-tabs: Run (this page) and Hooks (pre/post update scripts).
// Second display_top_tabs row, matching the Feeds page IPv4/IPv6/DNSBL sub-tab idiom.
$tab_array_sub	= array();
$tab_array_sub[]	= array(gettext('Run'),		TRUE,	'/pfblockerng/pfblockerng_update.php');
$tab_array_sub[]	= array(gettext('Hooks'),	FALSE,	'/pfblockerng/pfblockerng_hooks.php');
display_top_tabs($tab_array_sub, TRUE);

if (pfb_cfg_toggle_read($pfb['enable']) === PfbToggle::On) {
	/* Legend - Time variables

	$pfb['interval']	Hour interval setting	(1,2,3,4,6,8,12,24)
	$pfb['min']		Cron minute start time	(0-23)
	$pfb['hour']		Cron start hour		(0-23)
	$pfb['24hour']		Cron daily/wk start hr	(0-23)

	$currenthour		Current hour
	$currentmin		Current minute
	$currentsec		Current second
	$currentdaysec		Total number of seconds elapsed so far in the day
	$cron_hour_begin	First cron hour setting (interval 2-24)
	$cron_hour_next		Next cron hour setting  (interval 2-24)

	$nextcron		Next cron event in hour:mins
	$cronreal		Time remaining to next cron in hours:mins:secs		*/

	$currenthour	= date('G');
	$currentmin	= date('i');
	$currentsec	= date('s');
	$currentdaysec	= ($currenthour * 3600) + ($currentmin * 60) + $currentsec;

	if (!is_numeric($pfb['min'])) {
		$pfb['min'] = 0;
	}

	if ($pfb['interval'] == 1) {
		if ($currentmin < $pfb['min']) {
			$cron_hour_next = $currenthour;
		} else {
			$cron_hour_next = ($currenthour + 1) % 24;
		}
	}
	elseif ($pfb['interval'] == 24) {
		$cron_hour_next = $cron_hour_begin = $pfb['24hour'] ?: '00';
	}
	else {
		// Find next cron hour schedule
		$crondata = pfb_cron_base_hour($pfb['interval']);
		$cron_hour_begin = 0;
		$cron_hour_next  = '';
		if (!empty($crondata)) {
			foreach ($crondata as $key => $line) {
				if ($key == 0) {
					$cron_hour_begin = $line;
				}
				if (($line * 3600) + ($pfb['min'] * 60) > $currentdaysec) {
					$cron_hour_next = $line;
					break;
				}
			}
		}
		// Roll over to the first cron hour setting
		if (empty($cron_hour_next)) {
			$cron_hour_next = $cron_hour_begin;
		}
	}

	$cron_seconds_next = ($cron_hour_next * 3600) + ($pfb['min'] * 60);
	if ($currentdaysec < $cron_seconds_next) {
		// The next cron job is ahead of us in the day
		$sec_remain = $cron_seconds_next - $currentdaysec;
	} else {
		// The next cron job is tomorrow
		$sec_remain = (24*60*60) + $cron_seconds_next - $currentdaysec;
	}

	// Ensure hour:min:sec variables are two digit
	$pfb['min']	= str_pad($pfb['min'], 2, '0', STR_PAD_LEFT);
	$sec_final	= str_pad(($sec_remain % 60),  2, '0', STR_PAD_LEFT);
	$min_remain	= str_pad(floor($sec_remain / 60), 2, '0', STR_PAD_LEFT);
	$min_final	= str_pad(($min_remain % 60), 2, '0', STR_PAD_LEFT);
	$hour_final	= str_pad(floor($min_remain / 60), 2, '0', STR_PAD_LEFT);
	$cron_hour_next = str_pad($cron_hour_next, 2, '0', STR_PAD_LEFT);

	$cronreal = "{$cron_hour_next}:{$pfb['min']}";
	$nextcron = "{$hour_final}:{$min_final}:{$sec_final}";
}

$pfb_cmd = "/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php tick >> {$pfb['log']} 2>&1";
if ($pfb['interval'] == 1) {
	$pfb_hour = '*';
} elseif ($pfb['interval'] == 24) {
	$pfb_hour = $pfb['24hour'];
} else {
	$pfb_hour = implode(',', pfb_cron_base_hour($pfb['interval']));
}

// Determine if the tick CRON job is missing
if (pfb_cfg_toggle_read($pfb['enable']) === PfbToggle::On && $pfb['interval'] != 'Disabled' &&
    !pfblockerng_cron_exists($pfb_cmd, $pfb['min'], $pfb_hour, '*', '*')) {
	$cronreal = ' [ Missing cron task ]';
	$nextcron = '--';
}

// Determine if CRON job is disabled
elseif (empty($pfb['enable']) || empty($cron_hour_next) || $pfb['interval'] == 'Disabled') {
	$cronreal = ' [ Disabled ]';
	$nextcron = '--';
}

$status = 'NEXT Scheduled CRON Event will run at'
	. "&emsp;<strong>{$cronreal}</strong>&emsp;with<strong><span style=\"color: red;\">&emsp;{$nextcron}"
	. '&emsp;</span></strong> time remaining.';

// Query for any active pfBlockerNG task
exec('/bin/ps -wax', $result_ps);
if (preg_grep('/pfblockerng[.]php\s+?(cron|update|pfb_trigger|tick)/', $result_ps)) {
	$status = '<span style="color: red;">&emsp;&emsp;'
		. 'Active pfBlockerNG CRON JOB'
		. '</span>&emsp;<i class="fa-solid fa-spinner fa-pulse fa-lg"></i>';
}
$status .= '<br />&emsp;<small><span style="color: red;">Refresh to update current status and time remaining.</span></small>';

// Read the due-ledger entries for the Schedule view (read-only at page load).
$ledger_cron = pfb_due_ledger_read_entry('cron', $pfb['dbdir']);
$ledger_dcc  = pfb_due_ledger_read_entry('dcc',  $pfb['dbdir']);
$ledger_bl   = pfb_due_ledger_read_entry('bl',   $pfb['dbdir']);

/**
 * Format a ledger entry as "Last: YYYY-MM-DD HH:MM  Next: YYYY-MM-DD HH:MM"
 * or "Not yet run" when the entry is absent.
 */
function pfb_ledger_entry_html(?array $entry): string {
	if ($entry === NULL) {
		return '<em>Not yet run</em>';
	}
	$last = isset($entry['last_run']) ? date('Y-m-d H:i', (int)$entry['last_run']) : '—';
	$next = isset($entry['next_due']) ? date('Y-m-d H:i', (int)$entry['next_due']) : '—';
	return "Last: <strong>{$last}</strong>&emsp;Next: <strong>{$next}</strong>";
}

// Create Form
$form = new Form(FALSE);

// ---- Update Settings section ----
$section = new Form_Section('Update Settings');
$section->addInput(new Form_StaticText(
	'Links',
	'<small>'
	. '<a href="/firewall_aliases.php" target="_blank">Firewall Aliases</a>&emsp;'
	. '<a href="/firewall_rules.php" target="_blank">Firewall Rules</a>&emsp;'
	. '<a href="/status_logs_filter.php" target="_blank">Firewall Logs</a></small>'
));

// Run Scope selector (ip / dnsbl / both)
$pfb_scope_val = $pconfig['pfb_scope'] ?? 'both';
$group = new Form_Group('Run Scope');
$group->add(new Form_Checkbox(
	'pfb_scope',
	NULL,
	'Both',
	$pfb_scope_val === 'both',
	'both'
))->displayAsRadio('pfb_scope_both')->setAttribute('title', 'Sync IP and DNSBL feeds.')->setWidth(1);

$group->add(new Form_Checkbox(
	'pfb_scope',
	NULL,
	'IP',
	$pfb_scope_val === 'ip',
	'ip'
))->displayAsRadio('pfb_scope_ip')->setAttribute('title', 'Sync IP feeds only.')->setWidth(1);

$group->add(new Form_Checkbox(
	'pfb_scope',
	NULL,
	'DNSBL',
	$pfb_scope_val === 'dnsbl',
	'dnsbl'
))->displayAsRadio('pfb_scope_dnsbl')->setAttribute('title', 'Sync DNSBL feeds only.')->setWidth(1);

$group->setHelp('Which lists to sync on Run Now: Both, IP-only, or DNSBL-only.');
$section->add($group);

// Force Reparse toggle
$group = new Form_Group('Force Reparse');
$group->add(new Form_Checkbox(
	'pfb_run_force',
	NULL,
	'Reparse',
	isset($pconfig['pfb_run_force']) && $pconfig['pfb_run_force'] === 'on'
))->setAttribute('title', 'Reparse cached downloads even if no changes are detected.');
$group->setHelp('When checked, reprocesses existing downloaded files without re-checking for changes.');
$section->add($group);

$group = new Form_Group(NULL);
$btn_run = new Form_Button(
	'run',
	'Run Now',
	NULL,
	'fa-solid fa-play-circle'
);
$btn_run->removeClass('btn-primary')->addClass('btn-primary btn-xs')->setWidth(1);

// Alternate view/end view button text
if (!isset($pconfig['log_view'])) {
	$pconfig['log_view'] = 'View';
} elseif($pconfig['log_view'] == 'View') {
	$pconfig['log_view'] = 'End View' ;
} else {
	$pconfig['log_view'] = 'View';
}

// Alternate view/end view title text
$btn_logview_title = 'Click to End Log View';
if ($pconfig['log_view'] == 'View') {
	$btn_logview_title = 'Click to View a running Cron Update.';
}

$btn_logview = new Form_Button(
	'log_view',
	$pconfig['log_view'],
	NULL,
	'fa-regular fa-circle-play'
);
$btn_logview->removeClass('btn-primary')->addClass('btn-primary btn-xs')->setWidth(1)
	    ->setAttribute('title', $btn_logview_title);
$group->add(new Form_StaticText(
		NULL,
		$btn_run . $btn_logview
));

$section->add($group);
$form->add($section);

// ---- Schedule section ----
$section = new Form_Section('Schedule');
$section->addInput(new Form_StaticText(
	'Cron Status',
	$status
));
$section->addInput(new Form_StaticText(
	'Feed cron',
	pfb_ledger_entry_html($ledger_cron)
));
$section->addInput(new Form_StaticText(
	'MaxMind/Extras',
	pfb_ledger_entry_html($ledger_dcc)
));
$section->addInput(new Form_StaticText(
	'DNSBL category',
	pfb_ledger_entry_html($ledger_bl)
));
$form->add($section);

// ---- Log section ----
$section = new Form_Section('Log');
$section->addInput(new Form_Textarea(
	'pfb_status',
	NULL,
	'Log Viewer Standby'
))->removeClass('form-control')->addClass('row-fluid col-sm-12')->setAttribute('rows', '1')->setAttribute('wrap', 'off')
  ->setAttribute('readonly', 'readonly')->setAttribute('style', 'background:#fafafa; width: 100%');

$section->addInput(new Form_Textarea(
	'pfb_output',
	NULL,
	NULL
))->removeClass('form-control')->addClass('row-fluid col-sm-12')->setAttribute('rows', '30')->setAttribute('wrap', 'off')
  ->setAttribute('readonly', 'readonly')->setAttribute('style', 'background:#fafafa; width: 100%');

$form->add($section);
print($form);

// Execute the viewer output window
if (isset($pconfig['log_view'])) {
	if ($pconfig['log_view'] !== 'View') {
		pfbupdate_status(gettext("Log Viewing in progress.    ** Press 'END VIEW' to Exit ** "));
		pfb_livetail($pfb['log'], 'view');
	} else {
		// End the viewer output Window
		clearstatcache(FALSE, $pfb['log']);
		ob_flush();
		flush();
	}
}

// Run Now handler — dispatches pfb_trigger via the Phase-3 explicit API.
if (pfb_cfg_toggle_read($pfb['enable']) === PfbToggle::On && isset($pconfig['run']) &&
    isset($pconfig['pfb_scope']) && !empty($pconfig['pfb_scope'])) {
	$scope = in_array($pconfig['pfb_scope'], $pfb_allowed_scopes, TRUE) ? $pconfig['pfb_scope'] : 'both';
	$force = isset($pconfig['pfb_run_force']) && $pconfig['pfb_run_force'] === 'on';
	pfb_runnow($scope, $force);

	if ($pfb_wizard) {

		$wizard_log =
'<div class="pull-left alert alert-info clearfix" style="width: 100%;" role="alert">
	<p>pfBlockerNG has been successfully configured and updated. This installation will now block IPs based on some recommended
		Feed source providers. It will also block most ADverts based on Feed sources including EasyList/EasyPrivacy. Some additional
		Feed source providers include some malicious domain blocking.</p>
	<p>Please note that this is an entry level configuration for pfBlockerNG IP and DNSBL components. It is designed to allow new
		users to get running quickly to learn how effective pfBlockerNG can be for their networks.</p>
	<p>The Feeds tab includes many different types of IP and DNSBL feed sources. Careful review should be completed to select which feeds are
		appropriate for your needs.</p><br />
	<p><u>NOTE</u>:</p><br />
	<ul>
		<li>Please review the update log above for any errors.</li>
		<li>For DNSBL, ensure that all of your LAN devices are pointed at pfSense ONLY for DNS resolution.</li>
		<li>For users who have VLANS, please enable the DNSBL permit firewall rule option to allow all subnets to access the
			DNSBL Webserver, or there may be some browser timeouts.</li>
		<li>All IP/DNSBL events will be reported to the Reports/Alerts Tab. You can whitelist from the Alerts tab directly.</li>
		<li>Review the Reports/Statistics tabs for an in-depth summary of all IP and DNSBL events</li>
	</ul><br />
	<p>The Wizard is now finalized!</p>
	<p><small>A copy of this message has been saved to the wizard.log file</small></p>
</div>';
		print ("{$wizard_log}");

		$wizard_log = str_replace(array("\x09", '</p><br />'), array('', '<br />'), $wizard_log);
		$wizard_log = str_replace(array('</p>', '<br />'), "\n", $wizard_log);
		$wizard_log = str_replace('<li>', ' - ', $wizard_log);
		$wizard_log = strip_tags($wizard_log);
		@file_put_contents('/var/log/pfblockerng/wizard.log', "{$wizard_log}", LOCK_EX);
	}
}
?>

<script type="text/javascript">
//<![CDATA[

events.push(function(){

	// Expand log textareas to full width
	$('textarea[name="pfb_status"], textarea[name="pfb_output"]').each(function() {
		var $row = $(this).closest('.row.form-group, .form-group');
		$row.find('label.col-sm-2').remove();
		$row.find('div.col-sm-10').removeClass('col-sm-10').addClass('col-sm-12');
	});

	// Scroll to the bottom of the page after wizard
	var pfb_wizard = "<?=$pfb_wizard;?>";
	if (pfb_wizard) {
		$("html, body").animate({ scrollTop: $(document).height() }, 2000);
	}

	// Scroll to the bottom on Run Now click
	$('#run').click(function() {
		$("html, body").animate({ scrollTop: $(document).height() }, 2000);
	});
});
//]]>
</script>
<?php include('foot.inc'); ?>

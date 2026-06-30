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


// TRUE when a pfBlockerNG feed task (cron/update/trigger/tick/forcecheck) is already running.
// The active-process guard used by the Run Now dispatchers and the status line; delegates to
// pfb_feed_task_running() (pfblockerng.inc) so the guard and pfb_livetail's terminator share
// one process-liveness check.
function pfb_active_task_running(): bool {
	return pfb_feed_task_running();
}

// Dispatch pfb_trigger via the Phase-3 explicit API, stream log output,
// then update the due ledger so the Schedule view reflects the manual run.
function pfb_runnow(string $scope, bool $force): void {
	global $pfb;

	// Check for any active pfBlockerNG process before dispatching.
	if (pfb_active_task_running()) {
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
	// Launch detached under daemon(8) with a pidfile so the livetail can track THIS
	// dispatched process by pid (isvalidpid) rather than a ps-pattern guess. daemon writes
	// the child pid to $pidfile and removes it on exit; mwexec_bg keeps the robust detach.
	$pidfile = '/var/run/pfb_runnow.pid';
	@unlink($pidfile);
	mwexec_bg("/usr/sbin/daemon -p " . escapeshellarg($pidfile) .
		" /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php pfb_trigger scope={$scope_esc} force={$force_val} trigger={$trigger_esc} >> {$pfb['log']} 2>&1");

	// Block until the dispatched process exits (the tail keys on its pidfile).
	pfb_livetail($pfb['log'], 'force', $pidfile);

	// Update the 'cron' ledger entry so the Schedule view reflects this manual run.
	// Only advance the full-pass ledger when scope=both — a partial scope=ip/dnsbl run
	// does not complete a full cron pass, and advancing next_due here would suppress the
	// next DNSBL-inclusive tick for up to pfb_interval hours.
	// jitter_max=0 mirrors the tick's cron dispatch (no spread for manual runs).
	if ($scope === 'both') {
		$interval = ((int)($pfb['interval'] ?: 1)) * 3600;
		pfb_due_ledger_mark_ran('cron', $interval, $now, pfb_tick_seed(), 0, $pfb['dbdir']);
	}
}

// Dispatch the on-demand detector (forcecheck verb) via mwexec_bg, stream log output,
// and update the due ledger — same active-process guard and livetail as pfb_runnow().
// Callers must clear the appropriate sidecars (pfb_force_clear_validators) BEFORE calling
// this so pfblockerng_sync_cron($force_all=TRUE) re-fetches every in-scope feed.
function pfb_runnow_forcecheck(string $scope): void {
	global $pfb;

	// Active-process guard — TOCTOU backstop; the POST handler also pre-checks before
	// clearing any sidecars (so a skipped run never leaves the box primed for a re-fetch).
	if (pfb_active_task_running()) {
		pfbupdate_status(gettext('Run Now skipped — an active pfBlockerNG task is running.'));
		return;
	}

	if (!file_exists("{$pfb['log']}")) {
		touch("{$pfb['log']}");
	}

	$scope_esc = escapeshellarg($scope);

	pfbupdate_status(gettext("Running: scope={$scope} force=download/both (on-demand detector)"));

	install_cron_job('pfblockerng.php tick', FALSE);

	pfb_logger("\n [ Force check - scope={$scope} ]\n", 1);

	$now = time();
	// Launch detached under daemon(8) with a pidfile — see pfb_runnow(); the livetail
	// tracks this dispatched process by pid (isvalidpid), not a ps-pattern.
	$pidfile = '/var/run/pfb_runnow.pid';
	@unlink($pidfile);
	mwexec_bg("/usr/sbin/daemon -p " . escapeshellarg($pidfile) .
		" /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php forcecheck scope={$scope_esc} >> {$pfb['log']} 2>&1");

	pfb_livetail($pfb['log'], 'force', $pidfile);

	if ($scope === 'both') {
		$interval = ((int)($pfb['interval'] ?: 1)) * 3600;
		pfb_due_ledger_mark_ran('cron', $interval, $now, pfb_tick_seed(), 0, $pfb['dbdir']);
	}
}

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('Update'));
$pglinks = array('', '/pfblockerng/pfblockerng_general.php', '@self');
$shortcut_section = 'pfblockerng';
include_once('head.inc');

$pconfig = array();
if ($_POST) {
	$pconfig = $_POST;
}

// Wizard handler (updated to Phase-3 API: scope=both, force=parse).
$pfb_wizard = FALSE;
if (isset($_GET) && isset($_GET['wizard']) && $_GET['wizard'] == 'reload') {
	$pconfig['run']            = '';
	$pconfig['pfb_scope']      = 'both';
	$pconfig['pfb_force_mode'] = 'parse';	// reparse cached lists, no re-download
	$pfb_wizard                = TRUE;
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

// ADR-43: the scheduler is a single */pfb_tick_interval cron tick that fires every hour ('*'),
// installed iff pfBlockerNG is enabled (the feed `interval` only gates the feed job *inside* the
// tick, not the tick itself). So the "NEXT Scheduled CRON Event" tracks the tick boundary; the
// per-feed cadence lives in the Schedule view below.
$pfb_tick_min = pfb_tick_interval_clamp(PfbConfig::read('pfb_tick_interval'));

if (pfb_cfg_toggle_read($pfb['enable']) === PfbToggle::On) {
	list($next_hour, $next_min, $sec_remain) =
	    pfb_next_tick_boundary($pfb_tick_min, (int) date('G'), (int) date('i'), (int) date('s'));

	$sec_final	= str_pad(($sec_remain % 60),          2, '0', STR_PAD_LEFT);
	$min_remain	= (int) floor($sec_remain / 60);
	$min_final	= str_pad(($min_remain % 60),          2, '0', STR_PAD_LEFT);
	$hour_final	= str_pad((int) floor($min_remain / 60), 2, '0', STR_PAD_LEFT);

	$cronreal	= str_pad($next_hour, 2, '0', STR_PAD_LEFT) . ':' . str_pad($next_min, 2, '0', STR_PAD_LEFT);
	$nextcron	= "{$hour_final}:{$min_final}:{$sec_final}";
}

// Probe for the exact tick signature install_cron_job() registers in pfblockerng.inc, so an
// installed tick is not misreported as "[ Missing cron task ]".
$pfb_cmd = "/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php tick >> {$pfb['log']} 2>&1";

if (pfb_cfg_toggle_read($pfb['enable']) === PfbToggle::On) {
	if (!pfblockerng_cron_exists($pfb_cmd, '*/' . $pfb_tick_min, '*', '*', '*')) {
		$cronreal = ' [ Missing cron task ]';
		$nextcron = '--';
	}
} else {
	$cronreal = ' [ Disabled ]';
	$nextcron = '--';
}

$status = 'NEXT Scheduled CRON Event will run at'
	. "&emsp;<strong>{$cronreal}</strong>&emsp;with<strong><span style=\"color: red;\">&emsp;{$nextcron}"
	. '&emsp;</span></strong> time remaining.';

// Query for any active pfBlockerNG task (captured once: reused by the status line AND the
// auto-tail decision below).
$pfb_task_running = pfb_active_task_running();
if ($pfb_task_running) {
	$status = '<span style="color: red;">&emsp;&emsp;'
		. 'Active pfBlockerNG CRON JOB'
		. '</span>&emsp;<i class="fa-solid fa-spinner fa-pulse fa-lg"></i>';
}

// Auto-tail an IN-PROGRESS update on a plain page load (no Run Now / wizard dispatch, no View
// button click) — stream it live like the View button instead of showing a stale last-run tail.
$pfb_auto_tail = pfb_update_autotail($pfb_task_running, isset($pconfig['run']), isset($_POST['log_view']));
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

/**
 * Format the DNSBL Category ('bl') schedule row.
 *
 * Unlike the feed/extras jobs, the category job only runs (and so only ever records a
 * ledger entry) when the DNSBL Category feature is enabled with at least one category
 * selected — the exact gate the tick dispatcher applies before dispatching 'bl'. When the
 * feature is off, a bare "Not yet run" reads as if a scheduled job is stuck, so report WHY
 * it is not scheduled instead.
 */
function pfb_dnsbl_category_schedule_html(array $pfb, ?array $entry): string {
	$bl = $pfb['blconfig'] ?? array();
	if (($pfb['enable'] ?? '') !== 'on' ||
	    empty($bl['blacklist_enable']) || $bl['blacklist_enable'] === 'Disable') {
		return '<em>Disabled</em>';
	}
	// Enabled — but is any category actually selected? (Mirrors the tick's bl_str build:
	// an item counts only when it is in blacklist_selected AND flagged selected.)
	$selected = !empty($bl['blacklist_selected']) ? array_flip(explode(',', $bl['blacklist_selected'])) : array();
	foreach (($bl['item'] ?? array()) as $item) {
		if (isset($selected[$item['xml']]) && !empty($item['selected'])) {
			return pfb_ledger_entry_html($entry);	// active — show the real schedule
		}
	}
	return '<em>None selected</em>';
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
))->displayAsRadio('pfb_scope_both')->setAttribute('title', 'Sync IP and DNSBL feeds.')->setWidth(2);

$group->add(new Form_Checkbox(
	'pfb_scope',
	NULL,
	'IP',
	$pfb_scope_val === 'ip',
	'ip'
))->displayAsRadio('pfb_scope_ip')->setAttribute('title', 'Sync IP feeds only.')->setWidth(2);

$group->add(new Form_Checkbox(
	'pfb_scope',
	NULL,
	'DNSBL',
	$pfb_scope_val === 'dnsbl',
	'dnsbl'
))->displayAsRadio('pfb_scope_dnsbl')->setAttribute('title', 'Sync DNSBL feeds only.')->setWidth(2);

$group->setHelp('Which lists to sync: Both, IP-only, or DNSBL-only.');
$section->add($group);

// Force mode — mutually-exclusive radios. None = a plain detector-respecting run.
$pfb_force_mode = $pconfig['pfb_force_mode'] ?? 'none';
$group = new Form_Group('Force');
$group->add(new Form_Checkbox('pfb_force_mode', NULL, 'None',     $pfb_force_mode === 'none',     'none'))
	->displayAsRadio('pfb_force_none')->setAttribute('title', 'Normal run — reload only what changed.')->setWidth(2);
$group->add(new Form_Checkbox('pfb_force_mode', NULL, 'Parse',    $pfb_force_mode === 'parse',    'parse'))
	->displayAsRadio('pfb_force_parse')->setAttribute('title', 'Reload all lists regardless of changes (no re-download).')->setWidth(2);
$group->add(new Form_Checkbox('pfb_force_mode', NULL, 'Download', $pfb_force_mode === 'download', 'download'))
	->displayAsRadio('pfb_force_download')->setAttribute('title', 'Re-fetch all list files (reload only if changes are detected).')->setWidth(2);
$group->add(new Form_Checkbox('pfb_force_mode', NULL, 'Both',     $pfb_force_mode === 'both',     'both'))
	->displayAsRadio('pfb_force_both')->setAttribute('title', 'Re-fetch all list files and reload all lists regardless of changes.')->setWidth(2);
$group->setHelp('<strong>None:</strong> reload only what changed (normal run).<br />'
	. '<strong>Parse:</strong> reload all lists regardless of changes (no re-download).<br />'
	. '<strong>Download:</strong> re-fetch all list files (reload only if changes are detected).<br />'
	. '<strong>Both:</strong> re-fetch all list files and reload all lists regardless of changes.');
$section->add($group);

$group = new Form_Group(NULL);
$btn_run = new Form_Button(
	'run',
	'Run Now',
	NULL,
	'fa-solid fa-play-circle'
);
// No setWidth(): a per-button column wrapper floats the two buttons flush together on
// desktop (the gap only showed on mobile, where the columns stack). Keep them inline and
// space them with a margin on Run instead.
$btn_run->removeClass('btn-primary')->addClass('btn-primary btn-xs')->setAttribute('style', 'margin-right: 0.5em;');

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
$btn_logview->removeClass('btn-primary')->addClass('btn-primary btn-xs')
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
	pfb_dnsbl_category_schedule_html($pfb, $ledger_bl)
));
$form->add($section);

// ---- Log section ----
// Plain GET (no active run and no live-view) → prefill pfb_output with the last log tail.
// $pconfig['run'] is the SAME signal the Run Now dispatch gate keys on (set by a button POST
// and by the wizard-reload GET), so this suppresses the stale prefill on every run-start path.
// $pfb_auto_tail also suppresses the stale prefill: an in-progress update is streamed live
// (below) instead, so pfb_output must start empty for the livetail to fill it.
$pfb_log_active = isset($pconfig['run']) ||
                  (isset($pconfig['log_view']) && $pconfig['log_view'] !== 'View') ||
                  $pfb_auto_tail;
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
	$pfb_log_active ? NULL : pfb_log_tail($pfb['log'])
))->removeClass('form-control')->addClass('row-fluid col-sm-12')->setAttribute('rows', '30')->setAttribute('wrap', 'off')
  ->setAttribute('readonly', 'readonly')->setAttribute('style', 'background:#fafafa; width: 100%');

$form->add($section);
print($form);

// Execute the viewer output window
if (isset($pconfig['log_view'])) {
	if ($pconfig['log_view'] !== 'View') {
		pfbupdate_status(gettext("Log Viewing in progress.    ** Press 'END VIEW' to Exit ** "));
		pfb_livetail($pfb['log'], 'view');
	} elseif ($pfb_auto_tail) {
		// Plain page load while an update is in progress: tail it live (passive 'view' viewer,
		// same as the View button) rather than leaving the prefilled last-run tail.
		pfbupdate_status(gettext("Update in progress — tailing the live log..."));
		pfb_livetail($pfb['log'], 'view');
	} else {
		// End the viewer output Window
		clearstatcache(FALSE, $pfb['log']);
		ob_flush();
		flush();
	}
}

// Run Now handler — dispatches pfb_trigger or forcecheck depending on force mode.
if (pfb_cfg_toggle_read($pfb['enable']) === PfbToggle::On && isset($pconfig['run']) &&
    isset($pconfig['pfb_scope']) && !empty($pconfig['pfb_scope'])) {
	$scope      = in_array($pconfig['pfb_scope'], $pfb_allowed_scopes, TRUE) ? $pconfig['pfb_scope'] : 'both';
	$force_mode = $pconfig['pfb_force_mode'] ?? 'none';
	if (!in_array($force_mode, array('none', 'parse', 'download', 'both'), TRUE)) {
		$force_mode = 'none';
	}
	if ($force_mode === 'download' || $force_mode === 'both') {
		// Pre-check the active-task guard BEFORE clearing any sidecars: if a run is already
		// in progress, clearing them here (then skipping the dispatch) would leave the box
		// primed for an unrequested re-fetch on the next scheduled tick.
		if (pfb_active_task_running()) {
			pfbupdate_status(gettext('Run Now skipped — an active pfBlockerNG task is running.'));
		} else {
			// Clear the scoped conditional-GET sidecars, then run the detector on-demand so it
			// re-fetches (200) and re-ingests changed feeds (Both also clears the hash => all).
			$dirs = pfb_force_scope_dirs($scope, $pfb['origdir'], $pfb['dnsorigdir']);
			pfb_force_clear_validators($dirs, $force_mode === 'both');
			pfb_runnow_forcecheck($scope);
		}
	} else {
		// none -> plain pass; parse -> reuse=on (reparse cached, no download).
		pfb_runnow($scope, $force_mode === 'parse');
	}

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

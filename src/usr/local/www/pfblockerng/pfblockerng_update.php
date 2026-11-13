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

require_once('guiconfig.inc');
require_once('globals.inc');
require_once('pfsense-utils.inc');
require_once('functions.inc');
require_once('util.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');

global $pfb;
pfb_global();

// AJAX view of the one Update: the poller fetches ?ajax=update[&after=<cursor>] and appends the returned log. The reply is
// Core's GetUpdate (issue #3941); `after` is the `next` of the previous reply, passed back as the string it is. Must run
// before any head/HTML output.
if (($_GET['ajax'] ?? '') === 'update') {
	// Release the PHP session write-lock immediately: this poll only READS from Core, it never writes the session.
	// guiconfig.inc holds an EXCLUSIVE per-session lock for the whole request, so without this every 1s poll serialises
	// behind any other same-session request (other tabs, nav background requests, the dispatching POST). During a long
	// no-output gap -- e.g. an HAProxy graceful-restart drain in an update hook -- one such blocked poll leaves the
	// client's in-flight guard stuck and freezes the live view until a manual reload.
	session_write_close();
	$pfb_view_response = pfb_update_view_response($_GET, 'pfb_core_call');
	foreach ($pfb_view_response['headers'] as $pfb_view_header) {
		header($pfb_view_header);
	}
	print($pfb_view_response['body']);
	exit;
}

// Post status message to terminal window.
function pfbupdate_status($status) {
	print("\n<script type=\"text/javascript\">");
	print("\n//<![CDATA[");
	print("\nthis.document.forms[0].pfb_status.value = " . pfb_js_string($status) . ";");
	print("\n//]]>");
	print("\n</script>");
	/* ensure that contents are written out */
	ob_flush();
}

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('Update'));
$pglinks = array('', '/pfblockerng/pfblockerng_general.php', '@self');
$shortcut_section = 'pfblockerng';
include_once('head.inc');

$pconfig = array();
if ($_POST) {
	$pconfig = $_POST;
}

// Wizard handler (updated to the explicit API: scope=both, force=parse).
$pfb_wizard = FALSE;
if (isset($_GET) && isset($_GET['wizard']) && $_GET['wizard'] == 'reload') {
	$pconfig['run']            = '';
	$pconfig['pfb_scope']      = 'both';
	$pconfig['pfb_force_mode'] = 'parse';	// reparse cached lists, no re-download
	$pfb_wizard                = TRUE;
}

// Validate user-supplied scope and force mode; default to 'both' / 'none' for unexpected input.
$pfb_allowed_scopes = array('ip', 'dnsbl', 'both');
if (isset($pconfig['pfb_scope']) && !in_array($pconfig['pfb_scope'], $pfb_allowed_scopes, TRUE)) {
	$pconfig['pfb_scope'] = 'both';
}
if (isset($pconfig['pfb_force_mode']) && !in_array($pconfig['pfb_force_mode'], array('none', 'parse', 'download', 'both'), TRUE)) {
	$pconfig['pfb_force_mode'] = 'none';
}

// Define default Alerts Tab href link (Top row)
$get_req = pfb_alerts_default_page();

$tab_array	= array();
$tab_array[]	= array(gettext('General'),	FALSE,	'/pfblockerng/pfblockerng_general.php');
$tab_array[]	= array(gettext('IP'),		FALSE,	'/pfblockerng/pfblockerng_ip.php');
$tab_array[]	= array(gettext('DNS'),		FALSE,	'/pfblockerng/pfblockerng_dns_general.php');
$tab_array[]	= array(gettext('Update'),	TRUE,	'/pfblockerng/pfblockerng_update.php');
$tab_array[]	= array(gettext('Reports'),	FALSE,	"/pfblockerng/pfblockerng_alerts.php{$get_req}");
$tab_array[]	= array(gettext('Feeds'),	FALSE,	'/pfblockerng/pfblockerng_feeds.php');
$tab_array[]	= array(gettext('Logs'),	FALSE,	'/pfblockerng/pfblockerng_log.php');
$tab_array[]	= array(gettext('Sync'),	FALSE,	'/pfblockerng/pfblockerng_sync.php');
pfb_software_add_tab($tab_array);
display_top_tabs($tab_array, TRUE);

// Update sub-tabs: Run (this page), Hooks (pre/post update scripts), and Edit Hooks
// (issue #1669 Part B: the gated hook-script authoring editor, directly after Hooks).
// Second display_top_tabs row, matching the Feeds page IPv4/IPv6/DNSBL sub-tab idiom.
$tab_array_sub = pfb_edit_hooks_tabs('run');
display_top_tabs($tab_array_sub, TRUE);
pfb_print_pending_changes_box(TRUE);

// ADR-43: the scheduler is a single fixed */15 cron tick,
// installed iff pfBlockerNG is enabled (the feed `interval` only gates the feed job *inside* the
// tick, not the tick itself). So the "Next schedule check" tracks the tick boundary; the
// per-feed cadence lives in the Schedule view below.
$pfb_tick_min = 15;

if ($pfb['enable'] === PfbToggle::On) {
	list($next_hour, $next_min, $sec_remain) =
	    pfb_next_tick_boundary($pfb_tick_min, (int) date('G'), (int) date('i'), (int) date('s'));

	$sec_final	= str_pad(($sec_remain % 60),          2, '0', STR_PAD_LEFT);
	$min_remain	= (int) floor($sec_remain / 60);
	$min_final	= str_pad(($min_remain % 60),          2, '0', STR_PAD_LEFT);
	$hour_final	= str_pad((int) floor($min_remain / 60), 2, '0', STR_PAD_LEFT);

	$cronreal	= str_pad($next_hour, 2, '0', STR_PAD_LEFT) . ':' . str_pad($next_min, 2, '0', STR_PAD_LEFT);
	$nextcron	= "{$hour_final}:{$min_final}:{$sec_final}";
}

// Probe for the exact cron-tick signature install_cron_job() registers in pfblockerng.inc, so
// an installed cron-tick is not misreported as "[ Missing cron task ]".
$pfb_cmd = "/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php cron-tick >> {$pfb['log']} 2>&1";

// issue #1204: the suppression sentinel outranks the enabled/missing-cron checks below, so a
// stray .pfb_cron_disable file is always visible even on an otherwise-healthy schedule.
if (pfb_cron_disabled()) {
	$cronreal = ' [ Disabled by ' . pfb_cron_disable_path() . ' ]';
	$nextcron = '--';
} elseif ($pfb['enable'] === PfbToggle::On) {
	if (!pfblockerng_cron_exists($pfb_cmd, '*/' . $pfb_tick_min, '*', '*', '*')) {
		$cronreal = ' [ Missing cron task ]';
		$nextcron = '--';
	}
} else {
	$cronreal = ' [ Disabled ]';
	$nextcron = '--';
}

$status = 'Next schedule check:'
	. "&emsp;<strong>{$cronreal}</strong>&emsp;(in <strong><span style=\"color: red;\">{$nextcron}</span></strong>). "
	. 'Feed groups update at their own <strong>Update Frequency</strong>.';

// Ask Core whether an Update runs (captured once: reused by the status line AND the auto-tail decision below).
$pfb_update_answer = pfb_core_call('GetUpdate', []);
$pfb_task_running = pfb_update_core_failure($pfb_update_answer) === NULL
	&& ($pfb_update_answer['body']['running'] ?? FALSE) === TRUE;
if ($pfb_task_running) {
	$status = '<span style="color: red;">&emsp;&emsp;'
		. 'An update is running.'
		. '</span>&emsp;<i class="fa-solid fa-spinner fa-pulse fa-lg"></i>';
}

// Auto-tail an IN-PROGRESS update on a plain page load (no Run Now / wizard dispatch, no View
// button click) — stream it live like the View button instead of showing a stale last-run tail.
$pfb_auto_tail = pfb_update_autotail($pfb_task_running, isset($pconfig['run']), isset($_POST['log_view']));
$status .= '<br />&emsp;<small><span style="color: red;">Refresh to update current status and time remaining.</span></small>';

// Whether the client should poll the Update view (?ajax=update) once the page has rendered. TRUE
// when an update is already in progress (auto-tail); also set TRUE by the View button and the Run
// Now dispatch below. A plain visit with no active run leaves it FALSE (empty box, per #666).
$pfb_poll        = $pfb_auto_tail;
$pfb_poll_status = $pfb_auto_tail ? gettext('Update in progress — tailing the live log...') : '';

// The Schedule view is Core's (issue #3941): the scheduler and its state live there.
$pfb_schedule = pfb_update_schedule_view('pfb_core_call');

/**
 * Format a schedule entry as "Last: YYYY-MM-DD HH:MM:SS  Next: YYYY-MM-DD HH:MM:SS"; "—" stands for a time the entry lacks.
 *
 * @param array{last_run?: int, next_due?: int} $entry
 */
function pfb_ledger_entry_html(array $entry): string {
	$last = isset($entry['last_run']) ? date('Y-m-d H:i:s', (int)$entry['last_run']) : '—';
	$next = isset($entry['next_due']) ? date('Y-m-d H:i:s', (int)$entry['next_due']) : '—';
	return "Last: <strong>{$last}</strong>&emsp;Next: <strong>{$next}</strong>";
}

/**
 * Format one Schedule row from Core's answer: its entry, "Not scheduled" when Core has none, or "Core is not answering" (the
 * reason on hover) when Core gave no schedule.
 */
function pfb_schedule_entry_html(?string $error, ?array $entry): string {
	if ($error !== NULL) {
		return '<em title="' . htmlspecialchars($error, ENT_QUOTES) . '">Core is not answering</em>';
	}
	return $entry === NULL ? '<em>Not scheduled</em>' : pfb_ledger_entry_html($entry);
}

/**
 * Format the DNSBL Category ('bl') schedule row.
 *
 * Unlike the feed/extras jobs, the category job is only scheduled when the DNSBL Category feature is enabled with at least one
 * category selected. When the feature is off, "Not scheduled" reads as if a scheduled job is missing, so report WHY it is not
 * scheduled instead.
 */
function pfb_dnsbl_category_schedule_html(array $pfb, ?array $entry, ?string $error = NULL): string {
	$bl = $pfb['blconfig'] ?? array();
	if (($pfb['enable'] ?? PfbToggle::Off) !== PfbToggle::On ||
	    empty($bl['blacklist_enable']) || $bl['blacklist_enable'] === 'Disable') {
		return '<em>Disabled</em>';
	}
	// Enabled — but is any category actually selected? An item counts only when it is in
	// blacklist_selected AND flagged selected.
	$selected = !empty($bl['blacklist_selected']) ? array_flip(explode(',', $bl['blacklist_selected'])) : array();
	foreach (($bl['item'] ?? array()) as $item) {
		if (isset($selected[$item['xml']]) && !empty($item['selected'])) {
			return pfb_schedule_entry_html($error, $entry);	// active — show Core's schedule
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
	. '<a href="/firewall_aliases.php" target="_blank" rel="noopener noreferrer">Firewall Aliases</a>&emsp;'
	. '<a href="/firewall_rules.php" target="_blank" rel="noopener noreferrer">Firewall Rules</a>&emsp;'
	. '<a href="/status_logs_filter.php" target="_blank" rel="noopener noreferrer">Firewall Logs</a></small>'
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
))->displayAsRadio('pfb_scope_both')->setAttribute('title', 'Update IP and DNSBL lists.')->setWidth(2);

$group->add(new Form_Checkbox(
	'pfb_scope',
	NULL,
	'IP',
	$pfb_scope_val === 'ip',
	'ip'
))->displayAsRadio('pfb_scope_ip')->setAttribute('title', 'Update IP lists only.')->setWidth(2);

$group->add(new Form_Checkbox(
	'pfb_scope',
	NULL,
	'DNSBL',
	$pfb_scope_val === 'dnsbl',
	'dnsbl'
))->displayAsRadio('pfb_scope_dnsbl')->setAttribute('title', 'Update DNSBL lists only.')->setWidth(2);

$group->setHelp('Which lists to update.');
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
	$btn_logview_title = 'View the log of the running update.';
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
	'Status',
	$status
));
$section->addInput(new Form_StaticText(
	'Feed groups',
	pfb_schedule_entry_html($pfb_schedule['error'], $pfb_schedule['feeds'])
));
$section->addInput(new Form_StaticText(
	'Extras (MaxMind, ASN, TOP1M)',
	pfb_schedule_entry_html($pfb_schedule['error'], $pfb_schedule['dcc'])
));
$section->addInput(new Form_StaticText(
	'DNSBL Category',
	pfb_dnsbl_category_schedule_html($pfb, $pfb_schedule['bl'], $pfb_schedule['error'])
));
$form->add($section);

// ---- Log section ----
// The output textarea always starts EMPTY on load — no prefill of the last log tail. The
// live paths fill it dynamically: Run Now / View / an in-progress update stream into it (and
// scroll as they write); use the View button to inspect the last log.
$section = new Form_Section('Log');
$section->addInput(new Form_Textarea(
	'pfb_status',
	NULL,
	'Log Viewer Standby'
))->removeClass('form-control')->addClass('row-fluid col-sm-12')->setAttribute('rows', '1')->setAttribute('wrap', 'off')
  ->setAttribute('readonly', 'readonly')->setAttribute('style', 'width: 100%; background-color: #fafafa; color: #212121;');

$section->addInput(new Form_Textarea(
	'pfb_output',
	NULL,
	NULL
))->removeClass('form-control')->addClass('row-fluid col-sm-12')->setAttribute('rows', '30')->setAttribute('wrap', 'off')
  ->setAttribute('readonly', 'readonly')->setAttribute('style', 'width: 100%; background-color: #fafafa; color: #212121;');

$form->add($section);
print($form);

// View / End-View button: start (or stop) the client-side live-log poll. 'End View' text means
// the viewer is now active (the toggle flipped it above); 'View' means it was just ended, and an
// in-progress update still auto-tails.
if (isset($pconfig['log_view']) && $pconfig['log_view'] !== 'View') {
	$pfb_poll        = TRUE;
	$pfb_poll_status = gettext("Log Viewing in progress.    ** Press 'END VIEW' to Exit ** ");
}

// Run Now handler (and the Wizard reload): ask Core for a manual Update of the scope with the force mode.
// An Update that already runs is reported, and the poller views it.
if ($pfb['enable'] === PfbToggle::On && isset($pconfig['run']) &&
    isset($pconfig['pfb_scope']) && !empty($pconfig['pfb_scope'])) {
	$pfb_poll = TRUE;
	pfbupdate_status(pfb_update_start($pconfig['pfb_scope'], $pconfig['pfb_force_mode'] ?? 'none', 'pfb_core_call'));

	if ($pfb_wizard) {

		$wizard_log =
'<div class="pull-left alert alert-info clearfix" style="width: 100%;" role="alert">
	<p>Wizard settings have been saved. Check the update log above to confirm that the lists loaded successfully.</p>
	<ul>
		<li>IP: the PRI1 feeds block listed addresses on the selected outbound interfaces.</li>
		<li>DNSBL: the ADs Basic group uses the Steven Black hosts feed.</li>
	</ul>
	<p>Add other feeds from <strong>Feeds</strong> as needed.</p>
	<ul>
		<li>Point LAN devices at this firewall for DNS.</li>
		<li>Open <strong>Reports</strong> > <strong>Alerts</strong> to review logged blocks and add exceptions.</li>
		<li>Open <strong>Reports</strong> > <strong>IP Block Stats</strong> or <strong>DNSBL Block Stats</strong> for totals.</li>
	</ul>
	<p><small>A copy of this message has been saved to the wizard.log file.</small></p>
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

	// Run Now no longer yanks the whole page to the bottom on click: it reloads into the
	// AJAX poll tail, which sticky-follows the live log WITHIN the output box on its own.
	// The old whole-page animate scrolled the pre-reload page (matching neither View nor the
	// post-reload state) and left the reloaded page scrolled down. Match View: no page scroll.

<?php if ($pfb_poll): ?>
	// Live view of the Update. The page has fully rendered (foot.inc ran, so the nav menu works); the log
	// streams in by polling ?ajax=update, which relays Core's GetUpdate, and appending the returned log.
	// Sticky auto-follow: re-pin to the bottom only when the user is already at the bottom, so scrolling
	// up to read is not yanked back.
	(function() {
		var out     = document.forms[0].pfb_output;
		var stat    = document.forms[0].pfb_status;
		var after     = null;   // Core's cursor: the `next` of the last reply, sent back as the string it is
		var startedAt = null;   // update.startedAt of the Update being followed
		var timer   = null;
		var pending = false;    // at most one poll in flight -- guards against overlapping requests
		var done    = false;    // (mobile resume / catch-up ticks) both reading the same cursor
		var initStatus = <?=pfb_js_string($pfb_poll_status);?>;
		var doneStatus = <?=pfb_js_string(gettext('Log viewer idle.'));?>;
		var errorStatus = <?=pfb_js_string(gettext('The Update view stopped: '));?>;
		if (initStatus) { stat.value = initStatus; }
		function stop(text) {
			done = true;
			if (timer) { clearInterval(timer); timer = null; }
			stat.value = text;
		}
		function poll() {
			if (pending || done) { return; }   // skip the tick while a request is outstanding
			pending = true;
			var url = '/pfblockerng/pfblockerng_update.php?ajax=update' + (after !== null ? '&after=' + encodeURIComponent(after) : '');
			// timeout: a poll normally returns in ms; if one ever blocks, abort at 5s so .always()
			// clears the in-flight guard and the next tick retries (the cursor only advances on a
			// successful .done, so a retry re-reads the same range -- no data lost). Without it, a
			// single blocked poll would freeze the view until a manual reload.
			$.ajax({ url: url, type: 'GET', dataType: 'json', cache: false, timeout: 5000 }).done(function(r) {
				if (!r) { return; }
				if (r.error) { stop(errorStatus + r.error); return; }
				var at = r.update ? r.update.startedAt : null;
				if (startedAt !== null && at !== startedAt) {
					// Another Update, or a restarted Core whose cursor may match this one's: start a clean log and
					// read the Update again from its start (a cursor is not valid across either).
					out.value = '';
					after = null;
					startedAt = at;
					setTimeout(poll, 0);
					return;
				}
				startedAt = at;
				if (r.log) {
					var atBottom = (out.scrollHeight - out.scrollTop - out.clientHeight) <= 16;
					out.value += r.log;
					if (atBottom) { out.scrollTop = out.scrollHeight; }
				}
				after = r.next;
				if (r.done && r.log === '') { stop(doneStatus); }
			}).always(function() { pending = false; });
		}
		poll();
		timer = setInterval(poll, 1000);
		// Mobile browsers suspend timers when the tab is backgrounded; re-poll once on return so
		// the view catches up from its stored cursor (the in-flight guard prevents a double read).
		document.addEventListener('visibilitychange', function() {
			if (!document.hidden && !done) { poll(); }
		});
	})();
<?php endif; ?>
});
//]]>
</script>
<?php include('foot.inc'); ?>

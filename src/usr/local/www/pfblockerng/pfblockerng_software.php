<?php
/*
 * pfblockerng_software.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2016-2026 Rubicon Communications, LLC (Netgate)
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

// ADR-19: the "Software" page — show the installed pfBlockerNG channel/version vs our-repo
// latest (from the cron-maintained cache), toggle the "Check for new versions" setting, and
// run same-channel Check / Update actions.

require_once('guiconfig.inc');
require_once('globals.inc');
require_once('pfsense-utils.inc');
require_once('util.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');

global $pfb;
pfb_global();

// PROVENANCE GUARD — FIRST executable thing. The Software page exists ONLY on a
// build installed from one of OUR repos (ADR-19 2026-06-15 amendment). A
// Netgate-ports / sideloaded install (repo 'pfSense'/unknown/'') must never see
// this page; redirect it away before any rendering or action handler runs.
if (!pfb_software_provenance_ok()) {
	header('Location: /index.php');
	exit;
}

// SECONDARY PRIVILEGE GATE (issue #485). The framework page-guard already requires
// page-firewall-pfblockerng to reach here; this page can now UNINSTALL the package, so
// additionally require the Package Manager "Installed" privilege — the priv pfSense uses for
// its own package-Remove page (page-system-packagemanager-installed, match 'pkg_mgr_installed.php*').
// pfSense match-based privilege is OR across groups, so this AND can only be enforced by an
// explicit in-page check. Use isAllowedPage() against that page, NOT userHasPrivilege() with the
// raw priv id: isAllowedPage honours the admin (uid 0) short-circuit AND the 'page-all' wildcard
// match, whereas userHasPrivilege does an exact priv-id membership test that wrongly excludes a
// page-all admin (who lacks the literal '…-installed' priv) — that would lock admins out.
if (!isAllowedPage('pkg_mgr_installed.php')) {
	header('Location: /index.php');
	exit;
}

// Resolve the installed package + channel ONCE (used by display + the actions).
$pfb_sw_pkgname	= pfb_pkg_installed_name();
$pfb_sw_channel	= pfb_channel_from_pkgname($pfb_sw_pkgname);

// AJAX live-log tail for the Software terminal (polled by the client; gated by the same provenance
// + privilege checks above). Returns the next log slice; on completion the done-payload also
// carries the action result + refreshed version/status so the client patches the page in place
// (no post-upgrade reload). Must run before any head/HTML output.
if (($_GET['ajax'] ?? '') === 'tail') {
	header('Content-Type: application/json');
	header('Cache-Control: no-cache, no-store, must-revalidate');
	$pfb_has_off = isset($_GET['offset']) && ctype_digit((string) $_GET['offset']);
	$pfb_tail = pfb_log_tail_payload('software', $pfb_has_off ? (int) $_GET['offset'] : -1, $pfb_has_off);
	if (!empty($pfb_tail['done'])) {
		$pfb_tail += pfb_software_done_extras();
	}
	print(json_encode($pfb_tail));
	exit;
}

// The "Check for new versions" setting (default ENABLED). Persisted as 'on'/'off'; an unset
// value (never saved) reads as enabled via pfb_software_check_enabled().
$pfb_sw_check_raw = PfbConfig::read('pfb_software_check');
$pfb_sw_check	= pfb_software_check_enabled(is_string($pfb_sw_check_raw) ? $pfb_sw_check_raw : null);


// Post a one-line status to the terminal status window (a one-shot refusal/notice message). The
// live log itself is streamed by the client poller via ?ajax=tail, not from here.
function pfb_software_status($status) {
	print("\n<script type=\"text/javascript\">");
	print("\n//<![CDATA[");
	print("\nthis.document.forms[0].pfb_status.value = " . pfb_js_string($status) . ";");
	print("\n//]]>");
	print("\n</script>");
	ob_flush();
	flush();
}


// Dispatch a pkg action (update/uninstall) as a DETACHED daemon writing the per-run software log,
// so the page returns immediately (head.inc + foot.inc load and the nav menu works) and the client
// polls ?ajax=tail for the live output. $pkgsubcmd is a FIXED pkg invocation whose only variable
// parts are pkg-derived names already escapeshellarg'd by the caller — no request input is
// interpolated. The daemon redirects all output to the run log ('>' truncate-on-open) and records
// the exit code in the result sidecar on completion; $action is recorded so the tail's done-payload
// can tell the client what to do (patch the version fields / redirect).
function pfb_software_dispatch(string $action, string $pkgsubcmd): void {
	global $pfb;
	$pidfile = '/var/run/pfb_software.pid';
	@unlink($pidfile);
	@unlink('/var/run/pfb_software.result');
	@file_put_contents('/var/run/pfb_software.action', $action);
	@file_put_contents($pfb['sw_runlog'], '');
	$logq = escapeshellarg($pfb['sw_runlog']);
	$resq = escapeshellarg('/var/run/pfb_software.result');
	// Nested shell: the inner sh -c string is passed as ONE escapeshellarg'd argument, so the
	// outer mwexec_bg shell does not evaluate $? or re-split the already-quoted paths.
	$inner = "{$pkgsubcmd} > {$logq} 2>&1; echo \$? > {$resq}";
	mwexec_bg('/usr/sbin/daemon -p ' . escapeshellarg($pidfile) . ' /bin/sh -c ' . escapeshellarg($inner));
}


// Software-specific tail done-payload: the action + exit code from the sidecars, plus the freshly
// re-read installed version + status after a successful update, so the client patches the page in
// place (no post-upgrade reload). Read in the ?ajax=tail branch once the run is done.
function pfb_software_done_extras(): array {
	global $pfb_sw_pkgname;
	$action = @file_get_contents('/var/run/pfb_software.action');
	$rcraw  = @file_get_contents('/var/run/pfb_software.result');
	$out = array(
		'sw_action' => ($action !== FALSE) ? trim($action) : '',
		'sw_rc'     => ($rcraw !== FALSE && trim((string) $rcraw) !== '') ? (int) trim((string) $rcraw) : -1,
	);
	if ($out['sw_action'] === 'update') {
		$installed = pfb_pkg_installed_version((string) $pfb_sw_pkgname);
		$cache     = pfb_software_read_cache();
		$avail     = pfb_update_available($installed, (string) ($cache['latest'] ?? ''));
		$out['sw_installed']        = ($installed !== '') ? $installed : gettext('unknown');
		$out['sw_update_available'] = $avail;
		$out['sw_status']           = $avail ? gettext('Update available') : gettext('Up to date');
	}
	return $out;
}


$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('Software'));
$pglinks = array('', '/pfblockerng/pfblockerng_general.php', '@self');

// Determine which (POST-guarded) action was requested. The destructive Update and the
// cache-refreshing Check run on POST only — never on a GET (so the ui_render gate's GET
// cannot trigger pkg).
$pfb_sw_action = '';
if ($_POST && !empty($_POST['pfb_sw_action'])) {
	$pfb_sw_action = (string) $_POST['pfb_sw_action'];
}


// "Save" the settings (standard pfSense CSRF POST). A checkbox is absent from the POST when
// unticked, so persist an explicit 'on'/'off' — an unset value defaults to enabled, an
// explicit 'off' is the user opting out.
if ($_POST && isset($_POST['save'])) {
	PfbConfig::write('pfb_software_check', isset($_POST['pfb_software_check']) ? 'on' : 'off');
	write_config('[pfBlockerNG] save Software settings');
	header('Location: /pfblockerng/pfblockerng_software.php');
	exit;
}

// "Check now" — a manual, explicit cache refresh from our repo, then redisplay. $force=true
// bypasses the "Check for new versions" enable-gate so a one-off check always works.
if ($pfb_sw_action === 'check') {
	pfb_software_update_check(TRUE);
	header('Location: /pfblockerng/pfblockerng_software.php');
	exit;
}

$shortcut_section = 'pfblockerng';
include_once('head.inc');

// Tab bar (the Software tab is the active one here; gated like every page).
$get_req = pfb_alerts_default_page();

$tab_array	= array();
$tab_array[]	= array(gettext('General'),	FALSE,	'/pfblockerng/pfblockerng_general.php');
$tab_array[]	= array(gettext('IP'),		FALSE,	'/pfblockerng/pfblockerng_ip.php');
$tab_array[]	= array(gettext('DNSBL'),	FALSE,	'/pfblockerng/pfblockerng_dnsbl.php');
$tab_array[]	= array(gettext('Update'),	FALSE,	'/pfblockerng/pfblockerng_update.php');
$tab_array[]	= array(gettext('Reports'),	FALSE,	"/pfblockerng/pfblockerng_alerts.php{$get_req}");
$tab_array[]	= array(gettext('Feeds'),	FALSE,	'/pfblockerng/pfblockerng_feeds.php');
$tab_array[]	= array(gettext('Logs'),	FALSE,	'/pfblockerng/pfblockerng_log.php');
$tab_array[]	= array(gettext('Sync'),	FALSE,	'/pfblockerng/pfblockerng_sync.php');
pfb_software_add_tab($tab_array, TRUE);
display_top_tabs($tab_array, TRUE);
pfb_print_pending_changes_box();

// Channel + installed version are read LIVE (local `pkg query`, no network) so they are
// always known on an installed box. Only the our-repo "latest" + status + last-checked come
// from the cron-maintained cache (empty/unknown renders a clean "Not checked yet" — never a
// warning — so the page passes ui_render on the first GET, before any check has run).
$cache		= pfb_software_read_cache();
$installed_ver	= pfb_pkg_installed_version($pfb_sw_pkgname);
$disp_channel	= $pfb_sw_channel ?: gettext('unknown');
$disp_installed	= ($installed_ver !== '') ? $installed_ver : gettext('unknown');
$disp_latest	= !empty($cache['latest']) ? (string) $cache['latest'] : gettext('Not checked yet');
$disp_checked	= !empty($cache['last_checked'])
			? date('Y-m-d H:i:s', (int) $cache['last_checked'])
			: gettext('never');

$update_available = pfb_update_available($installed_ver, (string) ($cache['latest'] ?? ''));
if ($update_available) {
	$disp_status = '<span class="text-warning">' . gettext('Update available') . '</span>';
} elseif (!empty($cache['latest'])) {
	$disp_status = '<span class="text-success">' . gettext('Up to date') . '</span>';
} else {
	$disp_status = gettext('Not checked yet');
}

// pfb-software-panel — the page-specific render marker (ADR-14 ui_render oracle).
$form = new Form('Save');

$section = new Form_Section('Software Status');
$section->addInput(new Form_StaticText(
	'Channel',
	'<span id="pfb-software-panel">' . htmlspecialchars((string) $disp_channel) . '</span>'
));
$section->addInput(new Form_StaticText(
	'Installed version',
	'<span id="pfb-sw-installed">' . htmlspecialchars((string) $disp_installed) . '</span>'
));
$section->addInput(new Form_StaticText(
	'Latest version',
	htmlspecialchars((string) $disp_latest)
));
$section->addInput(new Form_StaticText(
	'Status',
	'<span id="pfb-sw-status">' . $disp_status . '</span>'
));
$section->addInput(new Form_StaticText(
	'Last checked',
	htmlspecialchars((string) $disp_checked)
));
$form->add($section);

$section = new Form_Section('Updates');
$section->addInput(new Form_Checkbox(
	'pfb_software_check',
	'New version check',
	'Enabled',
	$pfb_sw_check
))->setHelp('Periodically check for a new version and notify when one is available.');
$form->add($section);

$section = new Form_Section('Actions');

$btn_check = new Form_Button(
	'pfb_sw_check',
	'Check now',
	null,
	'fa-solid fa-arrows-rotate'
);
$btn_check->removeClass('btn-primary')->addClass('btn-primary btn-xs')->setWidth(2);
// A button is a Form_Element, not a Form_Input — wrap each in a Form_StaticText (the
// established pattern) so it gets its own labelled row + per-line help.
$section->addInput(new Form_StaticText(null, $btn_check))
	->setHelp('Check for a new version now.');

$btn_update = new Form_Button(
	'pfb_sw_update',
	'Update now',
	null,
	'fa-solid fa-download'
);
$btn_update->removeClass('btn-primary')->addClass('btn-warning btn-xs')->setWidth(2);
// Enabled ONLY when an update is available (there is something to install).
if (!$update_available) {
	$btn_update->setAttribute('disabled', 'disabled');
}
$section->addInput(new Form_StaticText(null, $btn_update))
	->setHelp('Install the latest version. Available only when an update is found.');

$section->addInput(new Form_Checkbox(
	'pfb_sw_uninstall_confirm',
	'Confirm uninstall',
	'Confirm I want to uninstall pfBlockerNG',
	FALSE
))->setHelp('Required before the Uninstall button is enabled. Uninstalling removes pfBlockerNG entirely.');

$btn_uninstall = new Form_Button(
	'pfb_sw_uninstall',
	'Uninstall',
	null,
	'fa-solid fa-trash-can'
);
$btn_uninstall->removeClass('btn-primary')->addClass('btn-danger btn-xs')->setWidth(2);
$btn_uninstall->setAttribute('disabled', 'disabled');
$section->addInput(new Form_StaticText(null, $btn_uninstall))
	->setHelp('Remove pfBlockerNG from this firewall. Enabled only after the confirmation box is checked.');
$form->add($section);

// Live terminal window. The output textarea always starts EMPTY; the client poller fills it via
// ?ajax=tail when a software action is dispatched (or one is already running). $pfb_sw_poll gates
// the poller — TRUE on an update/uninstall POST (set in the handlers below) or when a software
// task is already running (a reload mid-run). $pfb_sw_poll_status seeds the status line.
$pfb_sw_poll        = isvalidpid('/var/run/pfb_software.pid');
$pfb_sw_poll_status = $pfb_sw_poll ? gettext('A pfBlockerNG software task is running...') : '';
// The in-flight action drives the poller's completion handling (esp. the uninstall .fail redirect,
// since pkg delete removes this endpoint). On a fresh POST it is $pfb_sw_action; on a plain reload
// mid-run there is no POST, so recover it from the dispatcher's action sidecar.
$pfb_sw_poll_action = $pfb_sw_action;
if ($pfb_sw_poll_action === '' && $pfb_sw_poll) {
	$pfb_sw_action_raw  = @file_get_contents('/var/run/pfb_software.action');
	$pfb_sw_poll_action = ($pfb_sw_action_raw !== FALSE) ? trim($pfb_sw_action_raw) : '';
}
$section = new Form_Section('Output');
$section->addInput(new Form_Textarea(
	'pfb_status',
	null,
	'Standby'
))->removeClass('form-control')->addClass('row-fluid col-sm-12')->setAttribute('rows', '1')->setAttribute('wrap', 'off')
  ->setAttribute('readonly', 'readonly')->setAttribute('style', 'background:#fafafa; width: 100%');
$section->addInput(new Form_Textarea(
	'pfb_output',
	null,
	null
))->removeClass('form-control')->addClass('row-fluid col-sm-12')->setAttribute('rows', '20')->setAttribute('wrap', 'off')
  ->setAttribute('readonly', 'readonly')->setAttribute('style', 'background:#fafafa; width: 100%');
$form->add($section);

print($form);

// The destructive Update is DISPATCHED (detached daemon) after the form has rendered; the page
// then returns and the client poller tails the live log via ?ajax=tail. POST-guarded only.
if ($pfb_sw_action === 'update') {
	// Defense-in-depth: the "Update now" button is only disabled client-side, so also
	// refuse the action server-side when there is nothing to install — never run pkg on a
	// stale/no-op POST. (Request authenticity is enforced by pfSense's CSRF token.)
	if (!$update_available) {
		pfb_software_status(gettext('No update is currently available.'));
	} elseif ($pfb_sw_pkgname === '') {
		pfb_software_status(gettext('No pfBlockerNG package detected — cannot update.'));
	} elseif (isvalidpid('/var/run/pfb_software.pid')) {
		// A software task is already running — refuse a second concurrent pkg dispatch (which would
		// clobber the in-flight run's sidecars). Mirrors the Update page's active-task guard.
		pfb_software_status(gettext('A pfBlockerNG software task is already running.'));
		$pfb_sw_poll = TRUE;
	} else {
		$bin = escapeshellarg(PFB_PKG_BIN);
		$pkg = escapeshellarg($pfb_sw_pkgname);
		pfb_software_dispatch('update', "{$bin} upgrade -y {$pkg}");
		// The poller tails the log; on a clean finish it patches the installed-version + status
		// fields in place (no reload) from the done-payload.
		$pfb_sw_poll        = TRUE;
		$pfb_sw_poll_status = gettext('Updating pfBlockerNG...');
	}
}

// Uninstall is dispatched the same way. POST-guarded.
if ($pfb_sw_action === 'uninstall') {
	// Defense-in-depth: the Uninstall button is only disabled client-side, so re-check the
	// confirmation server-side and refuse without it. (CSRF token enforces request authenticity.)
	if (!isset($_POST['pfb_sw_uninstall_confirm'])) {
		pfb_software_status(gettext('Uninstall not confirmed — tick the confirmation box first.'));
	} elseif ($pfb_sw_pkgname === '') {
		pfb_software_status(gettext('No pfBlockerNG package detected — cannot uninstall.'));
	} elseif (isvalidpid('/var/run/pfb_software.pid')) {
		pfb_software_status(gettext('A pfBlockerNG software task is already running.'));
		$pfb_sw_poll = TRUE;
	} else {
		$bin = escapeshellarg(PFB_PKG_BIN);
		$pkg = escapeshellarg($pfb_sw_pkgname);
		pfb_software_dispatch('uninstall', "{$bin} delete -y {$pkg}");
		// Uninstall removes the very package serving this page, so the poller's endpoint will
		// vanish near the end: the client treats a poll failure (or a clean 'done') as success
		// and redirects to the Package Manager.
		$pfb_sw_poll        = TRUE;
		$pfb_sw_poll_status = gettext('Uninstalling pfBlockerNG...');
	}
}
?>

<script type="text/javascript">
//<![CDATA[
events.push(function() {

	// Wire each action button to a POST. Update is destructive (it runs pkg) so it
	// confirms first; Check is a cache refresh and posts straight through.
	function pfb_sw_submit(action) {
		var f = document.forms[0];
		var i = document.createElement('input');
		i.type = 'hidden';
		i.name = 'pfb_sw_action';
		i.value = action;
		f.appendChild(i);
		f.submit();
	}

	$('#pfb_sw_check').click(function(e) {
		e.preventDefault();
		pfb_sw_submit('check');
	});
	$('#pfb_sw_update').click(function(e) {
		e.preventDefault();
		if (confirm('Update pfBlockerNG to the latest version now?')) {
			pfb_sw_submit('update');
		}
	});

	function pfb_sw_uninstall_sync() {
		document.getElementById('pfb_sw_uninstall').disabled = !document.getElementById('pfb_sw_uninstall_confirm').checked;
	}
	$('#pfb_sw_uninstall_confirm').on('change', pfb_sw_uninstall_sync);
	pfb_sw_uninstall_sync();

	$('#pfb_sw_uninstall').click(function(e) {
		e.preventDefault();
		if (confirm('Uninstall pfBlockerNG from this firewall? This cannot be undone.')) {
			pfb_sw_submit('uninstall');
		}
	});

<?php if ($pfb_sw_poll): ?>
	// Live-log tail for the software action. The page has fully rendered (foot.inc ran, the nav
	// menu works); the log streams in by polling ?ajax=tail. On completion the done-payload carries
	// the result: a successful update patches the installed-version + status fields in place (no
	// reload), and an uninstall — which removes this very page — redirects to the Package Manager.
	(function() {
		var out    = document.forms[0].pfb_output;
		var stat   = document.forms[0].pfb_status;
		var offset = null;
		var timer  = null;
		var action = <?=pfb_js_string($pfb_sw_poll_action);?>;
		var initStatus = <?=pfb_js_string($pfb_sw_poll_status);?>;
		if (initStatus) { stat.value = initStatus; }
		function gotoInstalled() { window.location.assign('/pkg_mgr_installed.php'); }
		function poll() {
			var url = '/pfblockerng/pfblockerng_software.php?ajax=tail' + (offset !== null ? '&offset=' + offset : '');
			$.ajax({ url: url, type: 'GET', dataType: 'json', cache: false }).done(function(r) {
				if (!r) { return; }
				if (r.data) {
					var atBottom = (out.scrollHeight - out.scrollTop - out.clientHeight) <= 16;
					out.value += r.data;
					if (atBottom) { out.scrollTop = out.scrollHeight; }
				}
				if (typeof r.offset !== 'undefined') { offset = r.offset; }
				if (!r.done) { return; }
				if (timer) { clearInterval(timer); timer = null; }
				if (r.sw_action === 'uninstall') {
					stat.value = (r.sw_rc === 0)
						? 'Uninstall complete — redirecting...'
						: 'Uninstall finished with errors — see the log above.';
					if (r.sw_rc === 0) { setTimeout(gotoInstalled, 1200); }
				} else if (r.sw_action === 'update') {
					if (r.sw_rc === 0) {
						if (r.sw_installed) { $('#pfb-sw-installed').text(r.sw_installed); }
						if (typeof r.sw_status !== 'undefined') {
							$('#pfb-sw-status').html((r.sw_update_available ? '<span class="text-warning">' : '<span class="text-success">') + r.sw_status + '</span>');
						}
						if (r.sw_update_available === false) { $('#pfb_sw_update').prop('disabled', true); }
						// Clean the URL so a manual refresh is a GET, never a re-POST of the action.
						if (window.history && window.history.replaceState) {
							window.history.replaceState({}, '', '/pfblockerng/pfblockerng_software.php');
						}
						stat.value = 'Update complete.';
					} else {
						stat.value = 'Update finished with errors — see the log above.';
					}
				} else {
					stat.value = 'Done.';
				}
			}).fail(function() {
				// During an uninstall the package (and this endpoint) disappears: a poll failure
				// means the uninstall succeeded — stop and redirect. Otherwise ignore + retry.
				if (action === 'uninstall') {
					if (timer) { clearInterval(timer); timer = null; }
					gotoInstalled();
				}
			});
		}
		poll();
		timer = setInterval(poll, 1000);
	})();
<?php endif; ?>
});
//]]>
</script>

<?php include('foot.inc'); ?>

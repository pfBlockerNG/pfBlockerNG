<?php
/*
 * pfblockerng_crowdsec_status.php
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

// The CrowdSec tab's Status subtab (docs/specs/crowdsec-integration.md, D7): read-only. Everything but the tables, the lookup and the
// log comes from the bouncer's status file; only the lookup talks to the LAPI. The bouncer key is never rendered.

require_once('guiconfig.inc');
require_once('globals.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');

global $pfb;
pfb_global();

const PFB_CROWDSEC_PAGE_SIZE = 100;
$families = array('ipv4' => gettext('IPv4'), 'ipv6' => gettext('IPv6'));

$settings = pfb_crowdsec_settings();
$reason = pfb_crowdsec_off_reason();
$running = isvalidpid(PFB_CROWDSEC_PIDFILE);
$status = pfb_crowdsec_status_read();

$lookup_ip = is_string($_GET['lookup'] ?? NULL) ? trim($_GET['lookup']) : '';
$lookup = $lookup_ip === '' ? NULL : pfb_crowdsec_lookup($lookup_ip, (string) $settings['lapi_url'], (string) $settings['api_key']);

$h = static fn (mixed $text): string => htmlspecialchars((string) $text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$when = static fn (int $ts): string => $ts === 0 ? gettext('Never')
    : '<time datetime="' . gmdate('Y-m-d\TH:i:s\Z', $ts) . '">' . htmlspecialchars(date('Y-m-d H:i:s T', $ts)) . '</time>';
$row = static fn (string $label, string $id, string $html): string => "<tr><th>{$label}</th><td id=\"{$id}\">{$html}</td></tr>\n";
$panel = static function (string $title, string $body): void {
	print("<div class=\"panel panel-default\"><div class=\"panel-heading\"><h2 class=\"panel-title\">{$title}</h2></div>\n"
	    . "<div class=\"panel-body\">{$body}</div></div>\n");
};

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('CrowdSec'), gettext('Status'));
$pglinks = array('', '/pfblockerng/pfblockerng_general.php', PFB_CROWDSEC_PAGE, '@self');
$shortcut_section = 'pfblockerng';
include_once('head.inc');

pfb_crowdsec_display_tabs(PFB_CROWDSEC_STATUS_PAGE);

// Service
$state = $reason !== NULL ? sprintf(gettext('Not running: %s'), $reason) : ($running ? gettext('Running') : gettext('Stopped'));
$panel(gettext('Bouncer Service'), '<table class="table table-condensed">'
    . $row(gettext('State'), 'cs-service', $h($state))
    . ($status === NULL ? ''
    : $row(gettext('Version'), 'cs-version', $h($status['version'])) . $row(gettext('Started'), 'cs-started', $when($status['start_time']))
    . $row(gettext('Status written'), 'cs-updated', $when($status['updated_at'])
    . (pfb_crowdsec_status_fresh($status, time()) ? '' : ' <span class="text-danger">' . gettext('(stale)') . '</span>')))
    . '</table>'
    . ($status === NULL ? '<p id="cs-status-missing">' . gettext('No status yet: the bouncer writes its status file after each pull.') . '</p>' : ''));

// LAPI
$lapi = $row(gettext('URL'), 'cs-lapi-url', $h($settings['lapi_url']));
if ($status !== NULL) {
	$error = $status['last_error_time'] === 0 ? gettext('None') : $when($status['last_error_time']) . ' ' . $h($status['last_error']);
	$lapi .= $row(gettext('Last successful pull'), 'cs-last-pull', $when($status['last_pull']))
	    . $row(gettext('Last error'), 'cs-last-error', $error)
	    . $row(gettext('Requests'), 'cs-requests', (string) $status['lapi_requests'])
	    . $row(gettext('Errors'), 'cs-errors', (string) $status['lapi_errors']);
}
$panel(gettext('LAPI'), "<table class=\"table table-condensed\">{$lapi}</table>");

// Decisions and counters
if ($status !== NULL) {
	$banned = $dropped = '';
	foreach ($families as $family => $label) {
		foreach ($status['banned'][$family]['origins'] as $origin => $count) {
			$banned .= "<tr class=\"cs-banned\"><td>{$label}</td><td>{$h($origin)}</td><td>{$count}</td></tr>\n";
		}
		$banned .= "<tr class=\"cs-banned\"><td>{$label}</td><td><strong>" . gettext('Total') . "</strong></td>"
		    . "<td><strong>{$status['banned'][$family]['total']}</strong></td></tr>\n";
		$dropped .= "<tr class=\"cs-dropped\"><td>{$label}</td><td>{$status['dropped'][$family]['packets']}</td>"
		    . "<td>{$status['dropped'][$family]['bytes']}</td></tr>\n";
	}
	$panel(gettext('Decisions'), '<table class="table table-condensed table-striped"><thead><tr><th>' . gettext('Family') . '</th><th>'
	    . gettext('Origin') . '</th><th>' . gettext('Banned values') . "</th></tr></thead><tbody>{$banned}</tbody></table>");
	$panel(gettext('Dropped'), '<table class="table table-condensed table-striped"><thead><tr><th>' . gettext('Family') . '</th><th>'
	    . gettext('Packets') . '</th><th>' . gettext('Bytes') . "</th></tr></thead><tbody>{$dropped}</tbody></table>");
}

// The tables' contents, PFB_CROWDSEC_PAGE_SIZE entries per page; each table keeps its own page number in the query
foreach (PFB_CROWDSEC_TABLES as $family => $table) {
	$entries = pfb_crowdsec_table_entries($table);
	if ($entries === NULL) {
		$panel(sprintf(gettext('Table %s'), $table), '<p>' . gettext('The table does not exist: the bouncer is not running, or has not created it yet.') . '</p>');
		continue;
	}
	$pages = max(1, (int) ceil(count($entries) / PFB_CROWDSEC_PAGE_SIZE));
	$param = "page_{$family}";
	$current = filter_var(is_string($_GET[$param] ?? NULL) ? $_GET[$param] : 1, FILTER_VALIDATE_INT,
	    array('options' => array('min_range' => 1, 'max_range' => $pages, 'default' => 1)));
	$shown = array_slice($entries, ($current - 1) * PFB_CROWDSEC_PAGE_SIZE, PFB_CROWDSEC_PAGE_SIZE);
	$links = '';
	for ($n = 1; $n <= $pages && $pages > 1; $n++) {
		$query = $h('?' . http_build_query(array_merge(array_intersect_key($_GET, array_flip(array('page_ipv4', 'page_ipv6'))), array($param => $n))));
		$links .= $n === $current ? "<li class=\"active\"><span>{$n}</span></li>" : "<li><a href=\"{$query}\">{$n}</a></li>";
	}
	$panel(sprintf(gettext('Table %s'), $table), '<p id="cs-table-' . $family . '-count">'
	    . sprintf(gettext('%1$d entries; page %2$d of %3$d.'), count($entries), $current, $pages) . '</p>'
	    . "<pre id=\"cs-table-{$family}\">" . $h(implode("\n", $shown)) . '</pre>'
	    . ($links === '' ? '' : "<ul class=\"pagination\">{$links}</ul>"));
}

// Lookup
$result = '';
if ($lookup !== NULL && $lookup['error'] !== NULL) {
	$result = '<div class="alert alert-danger" id="cs-lookup-error">' . $h($lookup['error']) . '</div>';
} elseif ($lookup !== NULL) {
	$rows = '';
	foreach ($lookup['decisions'] as $d) {
		$rows .= "<tr class=\"cs-decision\"><td>{$h($d['value'])}</td><td>{$h($d['scope'])}</td><td>{$h($d['origin'])}</td>"
		    . "<td>{$h($d['scenario'])}</td><td>{$h($d['type'])}</td><td>{$h($d['duration'])}</td></tr>\n";
	}
	$result = '<div id="cs-lookup-result">' . ($rows === '' ? '<p>' . sprintf(gettext('No decision for %s.'), $h($lookup_ip)) . '</p>'
	    : '<table class="table table-condensed table-striped"><thead><tr><th>' . gettext('Value') . '</th><th>' . gettext('Scope')
	    . '</th><th>' . gettext('Origin') . '</th><th>' . gettext('Scenario') . '</th><th>' . gettext('Type') . '</th><th>'
	    . gettext('Expires in') . "</th></tr></thead><tbody>{$rows}</tbody></table>") . '</div>';
}
$panel(gettext('Decision Lookup'), '<form method="get" class="form-inline" action="' . PFB_CROWDSEC_STATUS_PAGE . '">'
    . '<input type="text" class="form-control" name="lookup" placeholder="192.0.2.1" value="' . $h($lookup_ip) . '"> '
    . '<button type="submit" class="btn btn-primary btn-sm"><i class="fa-solid fa-search icon-embed-btn"></i>' . gettext('Look up')
    . '</button><span class="help-block">' . gettext('Asks the LAPI for the decisions it holds on one IP address.') . '</span></form>'
    . $result);

// Log
$log = pfb_crowdsec_log_tail();
$panel(gettext('Log'), '<pre id="cs-log">' . ($log === array() ? gettext('No log lines tagged pfb_crowdsec.') : $h(implode("\n", $log))) . '</pre>');

include('foot.inc');
?>

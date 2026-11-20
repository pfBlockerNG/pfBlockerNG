<?php
/*
 * pfblockerng_crowdsec.inc
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2015-2026 Rubicon Communications, LLC (Netgate)
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

// The CrowdSec bouncer pfb_crowdsec (go/pfb_crowdsec): its Settings, config file, service, rules and status. docs/specs/crowdsec-integration.md, D2-D7.

const PFB_CROWDSEC_DIR = '/usr/local/pkg/pfblockerng/crowdsec';
const PFB_CROWDSEC_PAGE = '/pfblockerng/pfblockerng_crowdsec.php';
const PFB_CROWDSEC_STATUS_PAGE = '/pfblockerng/pfblockerng_crowdsec_status.php';
const PFB_CROWDSEC_RCFILE = '/usr/local/etc/rc.d/pfb_crowdsec.sh';
const PFB_CROWDSEC_CONFIG = '/usr/local/etc/pfb_crowdsec.json';
const PFB_CROWDSEC_STATUS = '/var/run/pfb_crowdsec.json';
// The status file's address families (go/pfb_crowdsec ipTypes) and their tables (D3); a larger status file is not the bouncer's
const PFB_CROWDSEC_TABLES = ['ipv4' => 'crowdsec_v4', 'ipv6' => 'crowdsec_v6'];
const PFB_CROWDSEC_STATUS_MAX = 1048576;
// The Status subtab's lookup (D7): the whole request's time limit, and the largest answer read
const PFB_CROWDSEC_LOOKUP_TIMEOUT = 5;
const PFB_CROWDSEC_LOOKUP_MAX = 1048576;
// The Status subtab's log: how much of the system log's end it reads
const PFB_CROWDSEC_LOG_WINDOW = 1048576;
// The bouncer's own pid (daemon -p), which the rule hook signals; SIGUSR1 to daemon(8)'s supervisor (-P) would kill it (#4069)
const PFB_CROWDSEC_PIDFILE = '/var/run/pfb_crowdsec.pid';
const PFB_CROWDSEC_DAEMON_PIDFILE = '/var/run/pfb_crowdsec_daemon.pid';
// The lock the rc script's starts and stops share, and the start's record of the binary it runs (`sha256 -r`: hash, space, path)
const PFB_CROWDSEC_LOCKFILE = '/var/run/pfb_crowdsec.lock';
const PFB_CROWDSEC_BINARY_RECORD = '/var/run/pfb_crowdsec.sha256';
const PFB_CROWDSEC_LOG_LEVELS = ['debug', 'info', 'warning', 'error'];
const PFB_CROWDSEC_TAG_PATTERN = '/^[A-Za-z0-9_-]{1,63}$/D';
// The bouncer key (D2): it travels in a request header, so no whitespace or control character
const PFB_CROWDSEC_KEY_PATTERN = '/^[\x21-\x7e]{1,256}$/D';
// The section's fields in the spec's order, and those the generated rules depend on (the enable and the rule settings)
const PFB_CROWDSEC_FIELDS = ['enable', 'lapi_url', 'api_key', 'log_level', 'rules_all_interfaces', 'rules_interfaces', 'rules_log',
	'rules_tag', 'rule_v4', 'rule_v6'];
const PFB_CROWDSEC_RULE_FIELDS = ['enable', 'rules_all_interfaces', 'rules_interfaces', 'rules_log', 'rules_tag', 'rule_v4', 'rule_v6'];

/**
 * The stored settings, each read through the gateway: toggles as PfbToggle, the rest as strings (an empty stored element reads '').
 *
 * @return array<string, PfbToggle|string> field => value, in PFB_CROWDSEC_FIELDS order
 */
function pfb_crowdsec_settings(): array {
	$settings = [];
	foreach (PFB_CROWDSEC_FIELDS as $field) {
		$value = PfbConfig::read("crowdsec/{$field}");
		$settings[$field] = ($value instanceof PfbToggle || is_string($value)) ? $value : '';
	}
	return $settings;
}

/**
 * Why the bouncer does not run (D4, shown by D7), or NULL when it should: pfBlockerNG's master enable, the CrowdSec enable, and a key
 * stored on this node. The master enable is $pfb['enable'] once pfb_global() loaded it (a removal turns it off in its own process), else
 * the stored one: pfSense's filter reload calls the rule hook without loading pfBlockerNG's globals.
 */
function pfb_crowdsec_off_reason(): ?string {
	global $pfb;

	if (($pfb['enable'] ?? PfbConfig::read('gen/enable_cb')) !== PfbToggle::On) {
		return gettext('pfBlockerNG is disabled');
	}
	if (PfbConfig::read('crowdsec/enable') !== PfbToggle::On) {
		return gettext('CrowdSec is disabled');
	}
	$key = PfbConfig::read('crowdsec/api_key');
	return (is_string($key) && $key !== '') ? NULL : gettext('no bouncer API key is stored on this node');
}

/** Should the bouncer run (D4): pfb_crowdsec_off_reason() finds no reason against it. */
function pfb_crowdsec_should_run(): bool {
	return pfb_crowdsec_off_reason() === NULL;
}

/**
 * An http:// or https:// URL with a host, and no credentials, query or fragment: what the bouncer accepts as its api_url (its
 * config check, go/pfb_crowdsec config.go, parses it with net/url). A character a URL never holds unencoded (ASCII space, quotes, <, >,
 * \, ^, `, {, |, }) is refused, as is a % that starts no escape and an authority net/url refuses: the host is a name without
 * brackets, colons or escapes, or a bracketed IPv6 address with an optional %25 zone, and the port, when there is a colon, is
 * digits only. The URL reaches a JSON file and curl, never a shell, so $ ' ; & ( * ! pass.
 */
function pfb_crowdsec_url_valid(string $url): bool {
	if (strlen($url) > 2048 || preg_match('/[\x00-\x20"<>\\\\^`{|}\x7f]|%(?![0-9A-Fa-f]{2})/', $url) || str_contains($url, '?')
	    || str_contains($url, '#') || !preg_match('~^https?://([^/]*)~i', $url, $m)
	    || !preg_match('~^(?:\[([0-9A-Fa-f:.]+)(?:%25[^%\]/]+)?\]|([^\[\]:%@]+))(?::[0-9]*)?$~D', $m[1], $a)) {
		return FALSE;
	}
	return ($a[2] ?? '') !== '' || filter_var($a[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== FALSE;
}

/**
 * Validate a Settings save (D2). The URL is sanitized once, here (pfb_sanitize_text(), issue #1723); the key and the tag are
 * checked as posted, so a control or format character or outer whitespace in either is refused, not stripped. A checkbox is on
 * only when posted as 'on'. An empty key field keeps $storedKey. No message names the key.
 *
 * @param array<string, mixed> $post the posted form
 * @param list<string> $interfaces this node's configured interfaces (get_configured_interface_with_descr() keys)
 * @return array{values: array<string, string>, errors: list<string>} the section's values to store (toggles 'on' or ''), and the
 *   input errors; values is to be stored only when errors is empty
 */
function pfb_crowdsec_validate(array $post, string $storedKey, array $interfaces): array {
	$errors = [];
	// Narrower than the sanitize-at-ingestion rule: a stripped key or tag is a different value than the one typed, which D2 refuses
	$raw = static fn (string $field): ?string => is_string($value = $post[$field] ?? '') ? $value : NULL;
	$toggle = static fn (string $field): string => (($post[$field] ?? '') === 'on') ? 'on' : '';
	$values = ['enable' => $toggle('enable')];
	$enabled = $values['enable'] === 'on';

	$url = is_string($post['lapi_url'] ?? '') ? pfb_sanitize_text($post['lapi_url'] ?? '') : NULL;
	if ($url === NULL || ($url !== '' && !pfb_crowdsec_url_valid($url))) {
		$errors[] = gettext('The Remote LAPI URL must be an http:// or https:// URL with a host, without credentials, query or fragment.');
	} elseif ($url === '' && $enabled) {
		$errors[] = gettext('Enter the Remote LAPI URL to enable the bouncer.');
	}
	$values['lapi_url'] = $url ?? '';

	$key = $raw('api_key');
	$values['api_key'] = $storedKey;
	if ($key === NULL || ($key !== '' && !preg_match(PFB_CROWDSEC_KEY_PATTERN, $key))) {
		$errors[] = gettext('The Bouncer API key must be 1 to 256 printable ASCII characters, without spaces.');
	} elseif ($key !== '') {
		$values['api_key'] = $key;
	} elseif ($storedKey === '' && $enabled) {
		$errors[] = gettext('Enter the Bouncer API key to enable the bouncer.');
	}

	$level = $post['log_level'] ?? NULL;
	if (!is_string($level) || !in_array($level, PFB_CROWDSEC_LOG_LEVELS, TRUE)) {
		$errors[] = gettext('The log level must be one of debug, info, warning or error.');
		$level = 'info';
	}
	$values['log_level'] = $level;

	$values['rules_all_interfaces'] = $toggle('rules_all_interfaces');
	$chosen = $post['rules_interfaces'] ?? [];
	if (!is_array($chosen) || array_filter($chosen, static fn (mixed $i): bool => !is_string($i) || !in_array($i, $interfaces, TRUE)) !== []) {
		$errors[] = gettext('Each selected interface must be one of the configured interfaces.');
		$chosen = [];
	} elseif ($chosen === [] && $values['rules_all_interfaces'] === '') {
		$errors[] = gettext('Select at least one interface, or apply the rules to all interfaces.');
	}
	$values['rules_interfaces'] = implode(',', array_unique($chosen));

	$values['rules_log'] = $toggle('rules_log');
	$tag = $raw('rules_tag');
	if ($tag === NULL || ($tag !== '' && !preg_match(PFB_CROWDSEC_TAG_PATTERN, $tag))) {
		$errors[] = gettext('The Tag must be empty, or 1 to 63 letters, digits, _ or -.');
		$tag = '';
	}
	$values['rules_tag'] = $tag;
	$values['rule_v4'] = $toggle('rule_v4');
	$values['rule_v6'] = $toggle('rule_v6');

	return ['values' => $values, 'errors' => $errors];
}

/**
 * The bouncer's config file (D3): the LAPI URL, the key and the log level from the settings, the rest fixed. The key is printable
 * ASCII by validation; JSON escaping covers a key stored by other means.
 *
 * @param array<string, PfbToggle|string> $settings pfb_crowdsec_settings()
 */
function pfb_crowdsec_config_json(array $settings): string {
	return json_encode([
		'api_url'          => (string) $settings['lapi_url'],
		'api_key'          => (string) $settings['api_key'],
		'update_frequency' => '10s',
		'table_v4'         => PFB_CROWDSEC_TABLES['ipv4'],
		'table_v6'         => PFB_CROWDSEC_TABLES['ipv6'],
		'log_level'        => (string) $settings['log_level'],
		'status_file'      => PFB_CROWDSEC_STATUS,
	], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
}

/**
 * Write $content to $path atomically (D3): a temporary file in the same folder, mode 0600 before the content (it holds the key),
 * renamed over $path. A failure removes the temporary file and leaves $path as it was.
 */
function pfb_crowdsec_config_write(string $content, string $path): bool {
	$tmp = @tempnam(dirname($path), '.pfb_crowdsec.');
	if ($tmp === FALSE) {
		return FALSE;
	}
	// tempnam() falls back to the system temp folder when it cannot create in dirname($path): a rename from there is no atomic replace
	if (dirname($tmp) !== realpath(dirname($path)) || !@chmod($tmp, 0600) || @file_put_contents($tmp, $content) !== strlen($content)
	    || !@rename($tmp, $path)) {
		@unlink($tmp);
		return FALSE;
	}
	return TRUE;
}

/**
 * Apply the "should run" decision (D4). Called by the Settings save and by pfb_crowdsec_resync(), never by the update pass. While the
 * bouncer should run: write the config file and start the service, or restart it when the file or the installed binary changed
 * (pfb_crowdsec_binary_changed()). Otherwise: stop it and remove the file, which also keeps the rc script's
 * own start (at boot) from starting it. The rc script is (re)generated on every call.
 *
 * @return bool TRUE when the bouncer was turned on or off (the config file appeared or went): its rules change, so the caller
 *   reloads the filter
 */
function pfb_crowdsec_apply(): bool {
	global $pfb;

	$config = $pfb['crowdsec_config'] ?? PFB_CROWDSEC_CONFIG;
	pfb_crowdsec_service();
	$was = is_file($config);

	if (!pfb_crowdsec_should_run()) {
		// A supervisor outlives its bouncer between restarts (-R 5), when the bouncer pidfile names no live process
		if ($was || is_service_running('pfb_crowdsec')) {
			stop_service('pfb_crowdsec');
		}
		unlink_if_exists($config);
		return $was;
	}

	$json = pfb_crowdsec_config_json(pfb_crowdsec_settings());
	$old = $was ? @file_get_contents($config) : FALSE;
	if ($old !== $json && !pfb_crowdsec_config_write($json, $config)) {
		logger(LOG_ERR, sprintf(gettext('CrowdSec bouncer: cannot write %s - not started'), $config), LOG_PREFIX_PKG_PFBLOCKERNG);
		return FALSE;
	}
	if (!is_service_running('pfb_crowdsec')) {
		start_service('pfb_crowdsec');
	} elseif ($old !== $json || pfb_crowdsec_binary_changed()) {
		restart_service('pfb_crowdsec');
	}
	return !$was;
}

/**
 * Does the running bouncer run another binary than the one installed now (an upgrade replaced it)? The rc start records the sha256 and
 * the path of what it runs; no record, or one that cannot be read, counts as changed (a start by an earlier version's rc script).
 */
function pfb_crowdsec_binary_changed(): bool {
	global $pfb;

	$record = @file_get_contents($pfb['crowdsec_binary_record'] ?? PFB_CROWDSEC_BINARY_RECORD);
	if (!is_string($record) || !preg_match('/^([0-9a-f]{64}) (\/\S+)$/D', trim($record), $m)) {
		return TRUE;
	}
	return @hash_file('sha256', $m[2]) !== $m[1];
}

/** The settings the generated rules depend on, as read now: a save that changes one reloads the filter. */
function pfb_crowdsec_rule_state(): array {
	return array_intersect_key(pfb_crowdsec_settings(), array_flip(PFB_CROWDSEC_RULE_FIELDS));
}

/**
 * The Settings subtab's save (D4): store $values (pfb_crowdsec_validate()'s, over the section's other keys), write the rule hook's
 * registration when it is missing, apply the decision at once, and reload the filter when the enable or a rule setting changed, the
 * bouncer was turned on or off, or the hook was registered while it should run. The page then runs the save-mode pass, which sends the
 * change to the peers as the General save does.
 *
 * @param array<string, string> $values
 */
function pfb_crowdsec_save(array $values): void {
	$section = PfbConfig::readSection(PFB_SECTIONS['crowdsec']);
	$before = pfb_crowdsec_rule_state();
	PfbConfig::writeSection(PFB_SECTIONS['crowdsec'], array_replace(is_array($section) ? $section : [], $values));
	write_config('pfBlockerNG: save the CrowdSec settings');
	$registered = pfb_crowdsec_register_rule_hook();
	$turned = pfb_crowdsec_apply();
	if ($turned || $before !== pfb_crowdsec_rule_state() || ($registered && pfb_crowdsec_should_run())) {
		filter_configure();
	}
}

/**
 * Apply the bouncer for a trigger outside its Settings (D4): the master enable's save, the wizard, an XMLRPC receive that changed
 * the master enable or the CrowdSec section, and the installer. Writes the rule hook's registration when it is missing, applies the
 * decision, and reloads the filter when the rules changed: the bouncer was turned on or off, or the hook was registered while it
 * should run.
 */
function pfb_crowdsec_resync(): void {
	$registered = pfb_crowdsec_register_rule_hook();
	$turned = pfb_crowdsec_apply();
	if ($turned || ($registered && pfb_crowdsec_should_run())) {
		filter_configure();
	}
}

/**
 * Print the CrowdSec pages' tab rows: pfBlockerNG's top row with the CrowdSec tab selected, the pending-changes box, and the
 * subtab row with $page (PFB_CROWDSEC_PAGE or PFB_CROWDSEC_STATUS_PAGE) selected.
 */
function pfb_crowdsec_display_tabs(string $page): void {
	$get_req = pfb_alerts_default_page();

	$tab_array	= array();
	$tab_array[]	= array(gettext('General'),	FALSE,	'/pfblockerng/pfblockerng_general.php');
	$tab_array[]	= array(gettext('IP'),		FALSE,	'/pfblockerng/pfblockerng_ip.php');
	$tab_array[]	= array(gettext('DNS'),		FALSE,	'/pfblockerng/pfblockerng_dns_general.php');
	$tab_array[]	= array(gettext('Update'),	FALSE,	'/pfblockerng/pfblockerng_update.php');
	$tab_array[]	= array(gettext('Reports'),	FALSE,	"/pfblockerng/pfblockerng_alerts.php{$get_req}");
	$tab_array[]	= array(gettext('Feeds'),	FALSE,	'/pfblockerng/pfblockerng_feeds.php');
	$tab_array[]	= array(gettext('Logs'),	FALSE,	'/pfblockerng/pfblockerng_log.php');
	$tab_array[]	= array(gettext('Sync'),	FALSE,	'/pfblockerng/pfblockerng_sync.php');
	pfb_software_add_tab($tab_array);
	foreach ($tab_array as &$tab) {
		$tab[1] = ($tab[2] === PFB_CROWDSEC_PAGE);
	}
	unset($tab);
	display_top_tabs($tab_array, TRUE);
	pfb_print_pending_changes_box();

	$tab_array = array(
		array(gettext('Settings'), $page === PFB_CROWDSEC_PAGE, PFB_CROWDSEC_PAGE),
		array(gettext('Status'), $page === PFB_CROWDSEC_STATUS_PAGE, PFB_CROWDSEC_STATUS_PAGE),
	);
	display_top_tabs($tab_array, TRUE);
}

/**
 * The bouncer's status file (D1, go/pfb_crowdsec status.go), checked field by field: NULL when it is missing, unreadable, larger than
 * PFB_CROWDSEC_STATUS_MAX, not JSON, or not the daemon's shape (each count an integer from 0 up to PHP_INT_MAX, a positive update
 * frequency, both families in `banned` and `dropped`).
 *
 * @return array{version: string, start_time: int, update_frequency_seconds: int, updated_at: int, last_pull: int, last_error_time: int,
 *   last_error: string, lapi_requests: int, lapi_errors: int, banned: array<string, array{total: int, origins: array<array-key, int>}>,
 *   dropped: array<string, array{packets: int, bytes: int}>}|null families keyed as PFB_CROWDSEC_TABLES; an origin may read back as an
 *   int key (PHP array keys)
 */
function pfb_crowdsec_status_read(string $path = PFB_CROWDSEC_STATUS): ?array {
	$raw = is_file($path) ? @file_get_contents($path, FALSE, NULL, 0, PFB_CROWDSEC_STATUS_MAX + 1) : FALSE;
	if (!is_string($raw) || strlen($raw) > PFB_CROWDSEC_STATUS_MAX) {
		return NULL;
	}
	// Objects stay objects, so a JSON list is never taken for a map; an integer beyond PHP_INT_MAX decodes as a float and is refused
	$doc = json_decode($raw, FALSE, 8);
	$get = static fn (mixed $object, string $key): mixed => ($object instanceof stdClass && property_exists($object, $key)) ? $object->$key : NULL;
	$count = static fn (mixed $value): ?int => (is_int($value) && $value >= 0) ? $value : NULL;

	$status = array('version' => $get($doc, 'version'), 'last_error' => $get($doc, 'last_error'));
	foreach (array('start_time', 'update_frequency_seconds', 'updated_at', 'last_pull', 'last_error_time', 'lapi_requests', 'lapi_errors') as $field) {
		$status[$field] = $count($get($doc, $field));
	}
	if (!is_string($status['version']) || !is_string($status['last_error']) || in_array(NULL, $status, TRUE)
	    || $status['update_frequency_seconds'] === 0) {
		return NULL;
	}
	foreach (array_keys(PFB_CROWDSEC_TABLES) as $family) {
		$bans = $get($get($doc, 'banned'), $family);
		$origins = $get($bans, 'origins');
		// An empty JSON list is as empty as the {} Go writes for no origins
		$origins = $origins instanceof stdClass ? array_map($count, get_object_vars($origins)) : ($origins === array() ? array() : NULL);
		$dropped = $get($get($doc, 'dropped'), $family);
		$status['banned'][$family] = array('total' => $count($get($bans, 'total')), 'origins' => $origins);
		$status['dropped'][$family] = array('packets' => $count($get($dropped, 'packets')), 'bytes' => $count($get($dropped, 'bytes')));
		if ($origins === NULL || in_array(NULL, $origins, TRUE) || in_array(NULL, $status['banned'][$family], TRUE)
		    || in_array(NULL, $status['dropped'][$family], TRUE)) {
			return NULL;
		}
	}
	return $status;
}

/**
 * A status file is fresh while it is at most three update intervals old (D6); older, the bouncer has stopped writing it. One written
 * more than an interval in the future is not fresh either: after the clock steps back it would otherwise stay fresh however old it gets.
 */
function pfb_crowdsec_status_fresh(array $status, int $now): bool {
	$age = $now - $status['updated_at'];
	return $age <= 3 * $status['update_frequency_seconds'] && $age >= -$status['update_frequency_seconds'];
}

/**
 * One table's entries as `pfctl -t <table> -T show` lists them (D7), or NULL when pfctl fails, as it does for a table that does not exist.
 *
 * @return list<string>|null
 */
function pfb_crowdsec_table_entries(string $table): ?array {
	global $pfb;

	$out = array();
	exec(escapeshellarg($pfb['pfctl'] ?? '/sbin/pfctl') . ' -t ' . escapeshellarg($table) . ' -T show 2>/dev/null', $out, $rc);
	return $rc === 0 ? array_values(array_filter(array_map('trim', $out), static fn (string $entry): bool => $entry !== '')) : NULL;
}

/**
 * The last $lines lines of the system log tagged pfb_crowdsec (D7, D4's `daemon -T pfb_crowdsec`), oldest first, in either of pfSense's
 * log formats (BSD `<time> <host> pfb_crowdsec[<pid>]:`, or RFC 5424 `<pri>1 <time> <host> pfb_crowdsec`). Only the log's last
 * PFB_CROWDSEC_LOG_WINDOW bytes are read, without the partial line they start inside.
 *
 * @return list<string>
 */
function pfb_crowdsec_log_tail(string $log = '/var/log/system.log', int $lines = 50): array {
	$fh = @fopen($log, 'rb');
	if ($fh === FALSE) {
		return array();
	}
	// One byte before the window as well: up to the first newline is the line the window starts inside (or nothing, when it starts
	// a line), a fragment that could pass for a line of its own
	$start = max(0, (int) @filesize($log) - PFB_CROWDSEC_LOG_WINDOW - 1);
	@fseek($fh, $start);
	$rows = explode("\n", mb_scrub((string) @stream_get_contents($fh), 'UTF-8'));
	fclose($fh);
	if ($start > 0) {
		array_shift($rows);
	}
	$tagged = preg_grep('/^(?:\S+\s+\d+\s+\d\d:\d\d:\d\d\s+\S+\s+pfb_crowdsec(?:\[\d+\])?:|<\d+>1\s+\S+\s+\S+\s+pfb_crowdsec\s)/', $rows);
	return array_slice(array_values($tagged), -$lines);
}

/**
 * The Status subtab's lookup (D7): the decisions the LAPI at $url holds for $ip, from `GET /v1/decisions?ip=<ip>` with the bouncer key.
 * $ip must be an IP address, else nothing is sent. The key is never part of the result.
 *
 * @param callable(string, string): array{status: int, body: string, error: string}|null $get the request (NULL: pfb_crowdsec_lapi_get())
 * @return array{error: ?string, decisions: list<array{value: string, scope: string, origin: string, scenario: string, type: string,
 *   duration: string}>}
 */
function pfb_crowdsec_lookup(string $ip, string $url, string $key, ?callable $get = NULL): array {
	$fail = static fn (string $error): array => array('error' => $error, 'decisions' => array());
	if (filter_var($ip, FILTER_VALIDATE_IP) === FALSE) {
		return $fail(gettext('The lookup address is not an IP address.'));
	}
	// Both as the Settings accept them: the URL http(s) only, the key fit for a request header. A stored value may come from elsewhere.
	if (!pfb_crowdsec_url_valid($url) || !preg_match(PFB_CROWDSEC_KEY_PATTERN, $key)) {
		return $fail(gettext('Store the Remote LAPI URL and the Bouncer API key on the Settings subtab first.'));
	}
	$answer = ($get ?? 'pfb_crowdsec_lapi_get')(rtrim($url, '/') . '/v1/decisions?ip=' . rawurlencode($ip), $key);
	if ($answer['error'] !== '') {
		return $fail(sprintf(gettext('The LAPI request failed: %s'), $answer['error']));
	}
	if ($answer['status'] !== 200) {
		return $fail(sprintf(gettext('The LAPI answered HTTP %d.'), $answer['status']));
	}
	// The LAPI answers `null` when no decision matches
	$list = json_decode($answer['body'], TRUE, 8);
	if ($list === NULL && trim($answer['body']) === 'null') {
		return array('error' => NULL, 'decisions' => array());
	}
	if (!is_array($list) || !array_is_list($list) || array_filter($list, 'is_array') !== $list) {
		return $fail(gettext('The LAPI answer is not a list of decisions.'));
	}
	$decisions = array();
	foreach ($list as $decision) {
		$row = array();
		foreach (array('value', 'scope', 'origin', 'scenario', 'type', 'duration') as $field) {
			$row[$field] = is_scalar($decision[$field] ?? NULL) ? (string) $decision[$field] : '';
		}
		$decisions[] = $row;
	}
	return array('error' => NULL, 'decisions' => $decisions);
}

/**
 * GET $url with the bouncer key, PFB_CROWDSEC_LOOKUP_TIMEOUT seconds for the whole request and no redirect (it would carry the key
 * elsewhere). An answer larger than PFB_CROWDSEC_LOOKUP_MAX is a failed request.
 *
 * @return array{status: int, body: string, error: string} error is '' on success; it never carries the key
 */
function pfb_crowdsec_lapi_get(string $url, string $key): array {
	$body = '';
	$ch = curl_init($url);
	curl_setopt_array($ch, array(
		CURLOPT_HTTPGET        => TRUE,
		CURLOPT_HTTPHEADER     => array("X-Api-Key: {$key}", 'Accept: application/json', 'User-Agent: pfBlockerNG'),
		CURLOPT_TIMEOUT        => PFB_CROWDSEC_LOOKUP_TIMEOUT,
		CURLOPT_CONNECTTIMEOUT => PFB_CROWDSEC_LOOKUP_TIMEOUT,
		CURLOPT_FOLLOWLOCATION => FALSE,
		CURLOPT_NOSIGNAL       => TRUE,
		CURLOPT_WRITEFUNCTION  => static function ($ch, string $chunk) use (&$body): int {
			if (strlen($body) + strlen($chunk) > PFB_CROWDSEC_LOOKUP_MAX) {
				return 0;
			}
			$body .= $chunk;
			return strlen($chunk);
		},
	));
	// No curl_close(): a no-op since PHP 8.0, deprecated in 8.5
	$ok = curl_exec($ch);
	return array(
		'status' => (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE),
		'body'   => $body,
		'error'  => $ok === FALSE ? (curl_error($ch) ?: gettext('no answer')) : '',
	);
}

/**
 * (Re)generate /usr/local/etc/rc.d/pfb_crowdsec.sh, the bouncer's service (D4), in the shape of Core's (pfb_core_service()).
 *
 * Start and stop run under one lock (PFB_CROWDSEC_LOCKFILE, waited for at most 20 s; a start or stop that cannot get it does nothing
 * and exits 75), so two starts run one after the other and the second keeps the first one's bouncer. Start: only while the config file
 * exists (pfb_crowdsec_apply() keeps it exactly while the bouncer should run, so the boot start follows the settings too); a
 * supervisor its pidfile names keeps running. Otherwise it stops what is left (a survivor fails the start) and runs this machine's
 * pfb_crowdsec ($dir/bin/freebsd-amd64 or freebsd-arm64, by `uname -p`) once `pfb_crowdsec -t` accepts the file, under daemon(8):
 * restarted 5 s after it exits, std fds detached, output to syslog (daemon facility, tag pfb_crowdsec), the supervisor's pid in
 * PFB_CROWDSEC_DAEMON_PIDFILE and the bouncer's in PFB_CROWDSEC_PIDFILE, and the sha256 of the binary it runs in
 * PFB_CROWDSEC_BINARY_RECORD; the start returns once the supervisor's pidfile names it (5 s). No binary for this machine starts nothing
 * and is not a failure; an unknown machine, a refused file, a failed daemon(8) or no supervisor are.
 * Stop: TERM to the supervisor and the bouncer (which empties its tables), KILL to both at 5 s; still running at 7 s fails the stop
 * and keeps the pidfiles. A pid is signalled only while a pidfile names
 * it and its command line is the bouncer's or the supervisor's. pfSense's own stop under a package upgrade or reinstall leaves the
 * bouncer running (pfb_rc_package_upgrade_keep(), as pfB-DNS's); the installer then restarts it only when its binary or its file
 * changed. Nothing here touches PF.
 *
 * @param string $dir the package's crowdsec directory (a test points it at a temp directory)
 */
function pfb_crowdsec_service(string $dir = PFB_CROWDSEC_DIR): void {
	global $pfb;

	$prefix = LOG_PREFIX_PKG_PFBLOCKERNG;
	$config = escapeshellarg($pfb['crowdsec_config'] ?? PFB_CROWDSEC_CONFIG);
	$daemonpid = escapeshellarg($pfb['crowdsec_daemon_pidfile'] ?? PFB_CROWDSEC_DAEMON_PIDFILE);
	$childpid = escapeshellarg($pfb['crowdsec_pidfile'] ?? PFB_CROWDSEC_PIDFILE);
	$lockfile = escapeshellarg($pfb['crowdsec_lockfile'] ?? PFB_CROWDSEC_LOCKFILE);
	$record = escapeshellarg($pfb['crowdsec_binary_record'] ?? PFB_CROWDSEC_BINARY_RECORD);
	$bin = escapeshellarg("{$dir}/bin");
	$keep = pfb_rc_package_upgrade_keep();
	// pgrep/pkill -f patterns (extended regular expressions): the supervisor, by daemon(8)'s title or, until it is set, by its own
	// command line; and the bouncer
	$supervisor = escapeshellarg('^(daemon: pfb_crowdsec\[|/usr/sbin/daemon .*-t pfb_crowdsec )');
	$child = escapeshellarg(pfb_crowdsec_child_pattern($dir));

	$rc		= array();
	$rc['file']	= 'pfb_crowdsec.sh';
	$rc['start']	= <<<EOF

	# Starts and stops are serialized (Core's lock): lockf holds it (file kept, at most 20 s) while this script runs itself once more
	if [ -z "\${PFB_CROWDSEC_LOCKED:-}" ]; then
		PFB_CROWDSEC_LOCKED=1 /usr/bin/lockf -k -t 20 {$lockfile} /bin/sh "\$0" start
		lockstatus="\$?"
		if [ "\${lockstatus}" -eq 75 ]; then
			/usr/bin/logger -p daemon.err -t pfb_crowdsec "ERROR [{$prefix}] CrowdSec bouncer: another start or stop held the lock for 20 s - not started"
		fi
		exit "\${lockstatus}"
	fi

	# Only while the bouncer should run: pfBlockerNG writes the config file then, and removes it otherwise
	if [ ! -f {$config} ]; then
		/usr/bin/logger -p daemon.info -t pfb_crowdsec "INFO [{$prefix}] CrowdSec bouncer: off, or no key on this node - not started"
		exit 0
	fi
	# Already running: keep it
	if /bin/pgrep -F {$daemonpid} -f {$supervisor} >/dev/null 2>&1; then
		exit 0
	fi

	machine="\$(/usr/bin/uname -p)"
	case "\${machine}" in
		amd64) target=freebsd-amd64 ;;
		aarch64|arm64) target=freebsd-arm64 ;;
		*)
			/usr/bin/logger -p daemon.err -t pfb_crowdsec "ERROR [{$prefix}] CrowdSec bouncer: no pfb_crowdsec for machine '\${machine}' - not started"
			exit 1
			;;
	esac
	binary={$bin}"/\${target}/pfb_crowdsec"
	if [ ! -f "\${binary}" ] || [ ! -x "\${binary}" ]; then
		/usr/bin/logger -p daemon.info -t pfb_crowdsec "INFO [{$prefix}] CrowdSec bouncer: pfb_crowdsec is not installed for \${target} - not started"
		exit 0
	fi
	# The bouncer's check names the field it refuses, never the key's value
	if ! check="\$("\${binary}" -t -c {$config} 2>&1)"; then
		/usr/bin/logger -p daemon.err -t pfb_crowdsec "ERROR [{$prefix}] CrowdSec bouncer: \${check} - not started"
		exit 1
	fi

	rc_stop || exit 1
	unset PFB_CROWDSEC_LOCKED
	# What it runs, for the installer to compare with the binary it installs
	/sbin/sha256 -r "\${binary}" > {$record}
	# Detach std fds (#662): the caller's pipe must not stay open in the daemon
	/usr/sbin/daemon -r -R 5 -S -l daemon -T pfb_crowdsec -t pfb_crowdsec -P {$daemonpid} -p {$childpid} "\${binary}" -c {$config} </dev/null >/dev/null 2>&1
	daemonstatus="\$?"
	if [ "\${daemonstatus}" -ne 0 ]; then
		/usr/bin/logger -p daemon.err -t pfb_crowdsec "ERROR [{$prefix}] CrowdSec bouncer: daemon(8) failed with status \${daemonstatus} - not started"
		exit 1
	fi
	# daemon(8) returns before its supervisor has written its pidfile: wait (5 s) until the pidfile names it
	tick=0
	while ! /bin/pgrep -F {$daemonpid} -f {$supervisor} >/dev/null 2>&1; do
		if [ "\${tick}" -ge 5 ]; then
			/usr/bin/logger -p daemon.err -t pfb_crowdsec "ERROR [{$prefix}] CrowdSec bouncer: daemon(8) started no supervisor"
			exit 1
		fi
		/bin/sleep 1
		tick="\$((tick + 1))"
	done
	/usr/bin/logger -p daemon.info -t pfb_crowdsec "INFO [{$prefix}] CrowdSec bouncer started"

EOF;
	$rc['stop']	= <<<EOF

	# pfSense stops package services while pkg upgrades or reinstalls this package: the bouncer keeps running, and the installer
	# restarts it only when its binary or its file changed. Only pfSense's own call has no argument; restart passes one
	if [ "\$#" -eq 0 ] && [ -z "\${PFB_CROWDSEC_LOCKED:-}" ]; then
{$keep}
		if [ "\${keep}" = keep ]; then
			/usr/bin/logger -p daemon.info -t pfb_crowdsec "INFO [{$prefix}] CrowdSec bouncer left running across the package upgrade"
			return 0
		fi
	fi
	if [ -z "\${PFB_CROWDSEC_LOCKED:-}" ]; then
		PFB_CROWDSEC_LOCKED=1 /usr/bin/lockf -k -t 20 {$lockfile} /bin/sh "\$0" stop
		lockstatus="\$?"
		if [ "\${lockstatus}" -eq 75 ]; then
			/usr/bin/logger -p daemon.err -t pfb_crowdsec "ERROR [{$prefix}] CrowdSec bouncer: another start or stop held the lock for 20 s - not stopped"
		fi
		return "\${lockstatus}"
	fi

	# TERM at 0 s, KILL at 5 s, give up at 7 s keeping the pidfiles (they still name the survivor)
	/bin/pkill -TERM -F {$daemonpid} -f {$supervisor} 2>/dev/null
	/bin/pkill -TERM -F {$childpid} -f {$child} 2>/dev/null
	waited=0
	killed=0
	while /bin/pgrep -F {$daemonpid} -f {$supervisor} >/dev/null 2>&1 || /bin/pgrep -F {$childpid} -f {$child} >/dev/null 2>&1; do
		if [ "\${waited}" -ge 5 ] && [ "\${killed}" -eq 0 ]; then
			/usr/bin/logger -p daemon.warning -t pfb_crowdsec "WARNING [{$prefix}] CrowdSec bouncer ignored TERM for 5 s, sending KILL"
			/bin/pkill -KILL -F {$daemonpid} -f {$supervisor} 2>/dev/null
			/bin/pkill -KILL -F {$childpid} -f {$child} 2>/dev/null
			killed=1
			continue
		fi
		if [ "\${waited}" -ge 7 ]; then
			/usr/bin/logger -p daemon.err -t pfb_crowdsec "ERROR [{$prefix}] CrowdSec bouncer still running after KILL"
			return 1
		fi
		/bin/sleep 1
		waited="\$((waited + 1))"
	done
	/bin/rm -f {$daemonpid} {$childpid} {$record}

EOF;
	// A survivor must fail the restart: the start would otherwise report success over it. The argument keeps the upgrade check out
	$rc['restart']	= <<<EOF
	if [ -z "\${PFB_CROWDSEC_LOCKED:-}" ]; then
		PFB_CROWDSEC_LOCKED=1 /usr/bin/lockf -k -t 20 {$lockfile} /bin/sh "\$0" restart
		return "\$?"
	fi
	rc_stop restart || return 1
	rc_start

EOF;
	write_rcfile($rc);
}

/**
 * Name the rule hook in pfBlockerNG's installedpackages/package/<n>/filter_rule_function, which pfSense reads on every filter
 * reload (D5). pfSense's install_package_xml() sets it from <filter_rules_needed> in memory only, then runs the install command,
 * whose pfb_global() re-reads config.xml and drops it; so each trigger that applies the bouncer registers it here (D4, #4139).
 *
 * @return bool TRUE when it wrote the registration (the filter has not reloaded with the hook yet)
 */
function pfb_crowdsec_register_rule_hook(): bool {
	foreach (config_get_path('installedpackages/package', []) as $idx => $pkg) {
		if (($pkg['configurationfile'] ?? '') === 'pfblockerng.xml') {
			if (($pkg['filter_rule_function'] ?? '') === 'pfb_crowdsec_rules') {
				break;
			}
			config_set_path("installedpackages/package/{$idx}/filter_rule_function", 'pfb_crowdsec_rules');
			write_config('[pfBlockerNG] register the CrowdSec rule hook');
			return TRUE;
		}
	}
	return FALSE;
}

/** The pgrep/pkill -f pattern (an extended regular expression) of the bouncer's command line as daemon(8) runs it from $dir. */
function pfb_crowdsec_child_pattern(string $dir = PFB_CROWDSEC_DIR): string {
	return '^' . str_replace('.', '\.', $dir) . '/bin/freebsd-[a-z0-9]+/pfb_crowdsec -c ';
}

/**
 * pfSense's filter_rule_function (pfblockerng.xml filter_rules_needed), called for each rule type on every filter reload (D5).
 * Only `pfearly`, and only while the bouncer should run: per enabled family an inbound rule (the bouncer's counter parser reads its
 * shape) and an outbound one, `on` the selected interfaces' real names for that family unless "all interfaces" is on (a family with
 * none left gets no rules), `log` and `tag` when set. A stored tag the Settings would refuse is left out: it reaches the ruleset verbatim.
 * The tables are never declared: the bouncer creates them. The reload kills them (#4070), so the first call that returns rules
 * registers pfb_crowdsec_signal() to run when this process ends, after the kill.
 */
function pfb_crowdsec_rules(string $type): string {
	static $registered = FALSE;

	if ($type !== 'pfearly' || !pfb_crowdsec_should_run()) {
		return '';
	}
	$s = pfb_crowdsec_settings();
	$selected = $s['rules_all_interfaces'] === PfbToggle::On ? NULL : explode(',', (string) $s['rules_interfaces']);
	$log = $s['rules_log'] === PfbToggle::On ? ' log' : '';
	// Quoted: unquoted, pf reads a tag such as `123` or `quick` as a number or a keyword, and pfSense then drops every rule here
	$tag = is_string($s['rules_tag']) && preg_match(PFB_CROWDSEC_TAG_PATTERN, $s['rules_tag']) ? " tag \"{$s['rules_tag']}\"" : '';

	$rules = '';
	foreach (['4' => ['rule_v4', 'inet'], '6' => ['rule_v6', 'inet6']] as $n => [$field, $af]) {
		if ($s[$field] !== PfbToggle::On) {
			continue;
		}
		$on = '';
		if ($selected !== NULL) {
			// Per family: a 6rd or 6to4 WAN carries its IPv6 on <name>_stf
			$real = array_filter(array_map(static fn (string $i): ?string => get_real_interface($i, $af), $selected));
			if ($real === []) {
				continue;
			}
			$on = ' on { ' . implode(' ', $real) . ' }';
		}
		$table = PFB_CROWDSEC_TABLES["ipv{$n}"];
		$rules .= "block drop in{$log} quick{$on} {$af} from <{$table}> to any label \"CrowdSec IPv{$n}\"{$tag}\n"
		    . "block drop out{$log} quick{$on} {$af} from any to <{$table}> label \"CrowdSec IPv{$n} out\"{$tag}\n";
	}
	if ($rules !== '' && !$registered) {
		register_shutdown_function('pfb_crowdsec_signal');
		$registered = TRUE;
	}
	return $rules;
}

/**
 * After a filter reload (D5): SIGUSR1 makes the bouncer re-create and refill its tables from memory at once. Only to the pid in
 * PFB_CROWDSEC_PIDFILE that isvalidpid() confirms, and only while its command line is the bouncer's (a stale pidfile may name a reused
 * pid); never to daemon(8)'s supervisor, which SIGUSR1 kills (#4069). A missed signal costs at most one pull: the next one reconciles.
 */
function pfb_crowdsec_signal(): void {
	global $pfb;

	$pidfile = $pfb['crowdsec_pidfile'] ?? PFB_CROWDSEC_PIDFILE;
	if (isvalidpid($pidfile)) {
		mwexec('/bin/pkill -USR1 -F ' . escapeshellarg($pidfile) . ' -f ' . escapeshellarg(pfb_crowdsec_child_pattern()), TRUE);
	}
}

/**
 * Package removal (D4): stop the bouncer and remove its rc script, config file, status file, lock and binary record. The pidfiles are the
 * stop's, as Core's: it removes them once nothing runs and keeps them while a survivor does. The binaries are package files.
 */
function pfb_crowdsec_teardown(): void {
	global $pfb;

	stop_service('pfb_crowdsec');
	foreach (['crowdsec_rcfile' => PFB_CROWDSEC_RCFILE, 'crowdsec_config' => PFB_CROWDSEC_CONFIG, 'crowdsec_status' => PFB_CROWDSEC_STATUS,
	    'crowdsec_lockfile' => PFB_CROWDSEC_LOCKFILE, 'crowdsec_binary_record' => PFB_CROWDSEC_BINARY_RECORD] as $key => $path) {
		unlink_if_exists($pfb[$key] ?? $path);
	}
}

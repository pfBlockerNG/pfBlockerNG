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

// The CrowdSec bouncer pfb_crowdsec (go/pfb_crowdsec): its Settings, config file, service and rules. docs/specs/crowdsec-integration.md, D2-D5.

const PFB_CROWDSEC_DIR = '/usr/local/pkg/pfblockerng/crowdsec';
const PFB_CROWDSEC_PAGE = '/pfblockerng/pfblockerng_crowdsec.php';
const PFB_CROWDSEC_RCFILE = '/usr/local/etc/rc.d/pfb_crowdsec.sh';
const PFB_CROWDSEC_CONFIG = '/usr/local/etc/pfb_crowdsec.json';
const PFB_CROWDSEC_STATUS = '/var/run/pfb_crowdsec.json';
// The bouncer's own pid (daemon -p), which the rule hook signals; SIGUSR1 to daemon(8)'s supervisor (-P) would kill it (#4069)
const PFB_CROWDSEC_PIDFILE = '/var/run/pfb_crowdsec.pid';
const PFB_CROWDSEC_DAEMON_PIDFILE = '/var/run/pfb_crowdsec_daemon.pid';
const PFB_CROWDSEC_LOG_LEVELS = ['debug', 'info', 'warning', 'error'];
const PFB_CROWDSEC_TAG_PATTERN = '/^[A-Za-z0-9_-]{1,63}$/D';
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
 * Should the bouncer run (D4): pfBlockerNG's master enable, the CrowdSec enable, and a key stored on this node. The master enable is
 * $pfb['enable'] once pfb_global() loaded it (a removal turns it off in its own process), else the stored one: pfSense's filter
 * reload calls the rule hook without loading pfBlockerNG's globals.
 */
function pfb_crowdsec_should_run(): bool {
	global $pfb;

	$key = PfbConfig::read('crowdsec/api_key');
	return ($pfb['enable'] ?? PfbConfig::read('gen/enable_cb')) === PfbToggle::On && PfbConfig::read('crowdsec/enable') === PfbToggle::On
	    && is_string($key) && $key !== '';
}

/**
 * An http:// or https:// URL with a host, and no credentials, query or fragment: what the bouncer accepts as its api_url (its
 * config check, go/pfb_crowdsec config.go, parses it with net/url). A character a URL never holds unencoded (space, quotes, <, >,
 * \, ^, `, {, |, }) is refused, which also keeps every shell metacharacter that needs quoting out of the file; so are a % that
 * starts no escape and an authority net/url refuses: the host is a name without brackets, colons or escapes, or a bracketed
 * IPv6 address with an optional %25 zone, and the port, when there is a colon, is digits only.
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
 * Validate a Settings save (D2). Text fields are sanitized once, here (pfb_sanitize_text(), issue #1723); a checkbox is on only
 * when posted as 'on'. An empty key field keeps $storedKey. No message names the key.
 *
 * @param array<string, mixed> $post the posted form
 * @param list<string> $interfaces this node's configured interfaces (get_configured_interface_with_descr() keys)
 * @return array{values: array<string, string>, errors: list<string>} the section's values to store (toggles 'on' or ''), and the
 *   input errors; values is to be stored only when errors is empty
 */
function pfb_crowdsec_validate(array $post, string $storedKey, array $interfaces): array {
	$errors = [];
	$text = static fn (string $field): ?string => is_string($post[$field] ?? '') ? pfb_sanitize_text($post[$field] ?? '') : NULL;
	$toggle = static fn (string $field): string => (($post[$field] ?? '') === 'on') ? 'on' : '';
	$values = ['enable' => $toggle('enable')];
	$enabled = $values['enable'] === 'on';

	$url = $text('lapi_url');
	if ($url === NULL || ($url !== '' && !pfb_crowdsec_url_valid($url))) {
		$errors[] = gettext('The Remote LAPI URL must be an http:// or https:// URL with a host, without credentials, query or fragment.');
	} elseif ($url === '' && $enabled) {
		$errors[] = gettext('Enter the Remote LAPI URL to enable the bouncer.');
	}
	$values['lapi_url'] = $url ?? '';

	$key = $text('api_key');
	$values['api_key'] = $storedKey;
	if ($key === NULL || ($key !== '' && !preg_match('/^[\x21-\x7e]{1,256}$/D', $key))) {
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
	$tag = $text('rules_tag');
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
		'table_v4'         => 'crowdsec_v4',
		'table_v6'         => 'crowdsec_v6',
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
 * Apply the "should run" decision (D4). Called by the Settings save, by pfBlockerNG's update pass (after a master enable change or
 * an XMLRPC receive) and by the installer (the pass ends early during an install). While the bouncer should run: write the config file and
 * start the service, or restart it when the file changed. Otherwise: stop it and remove the file, which also keeps the rc script's
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
	} elseif ($old !== $json) {
		restart_service('pfb_crowdsec');
	}
	return !$was;
}

/** The settings the generated rules depend on, as read now: a save that changes one reloads the filter. */
function pfb_crowdsec_rule_state(): array {
	return array_intersect_key(pfb_crowdsec_settings(), array_flip(PFB_CROWDSEC_RULE_FIELDS));
}

/**
 * The Settings subtab's save (D4): store $values (pfb_crowdsec_validate()'s, over the section's other keys), apply the decision at
 * once, and reload the filter when the enable or a rule setting changed, or the bouncer was turned on or off.
 *
 * @param array<string, string> $values
 */
function pfb_crowdsec_save(array $values): void {
	$section = PfbConfig::readSection(PFB_SECTIONS['crowdsec']);
	$before = pfb_crowdsec_rule_state();
	PfbConfig::writeSection(PFB_SECTIONS['crowdsec'], array_replace(is_array($section) ? $section : [], $values));
	write_config('pfBlockerNG: save the CrowdSec settings');
	$turned = pfb_crowdsec_apply();
	if ($turned || $before !== pfb_crowdsec_rule_state()) {
		filter_configure();
	}
}

/** Append the CrowdSec tab to a pfBlockerNG top row; its own pages mark it selected. */
function pfb_crowdsec_add_tab(array &$tab_array): void {
	$tab_array[] = array(gettext('CrowdSec'), FALSE, PFB_CROWDSEC_PAGE);
}

/**
 * (Re)generate /usr/local/etc/rc.d/pfb_crowdsec.sh, the bouncer's service (D4).
 *
 * Start: only while the config file exists (pfb_crowdsec_apply() keeps it exactly while the bouncer should run, so the boot start
 * follows the settings too); a bouncer whose supervisor its pidfile names keeps running. Otherwise it runs this machine's
 * pfb_crowdsec ($dir/bin/freebsd-amd64 or freebsd-arm64, by `uname -p`) once `pfb_crowdsec -t` accepts the file, under daemon(8):
 * restarted 5 s after it exits, std fds detached, output to syslog (daemon facility, tag pfb_crowdsec), the supervisor's pid in
 * PFB_CROWDSEC_DAEMON_PIDFILE and the bouncer's in PFB_CROWDSEC_PIDFILE; the start returns once the supervisor's pidfile names it
 * (5 s). No binary for this machine starts nothing and is not a failure; an unknown machine, a refused file, a failed daemon(8) or
 * no supervisor are. Two starts at once cannot both launch: daemon(8) locks its pidfiles.
 * Stop: TERM to the supervisor (daemon(8) passes it on, and the bouncer empties its tables), to the bouncer only when no supervisor
 * is left, KILL to both at 5 s; still running at 7 s fails the stop and keeps the pidfiles. A pid is signalled only while its
 * command line is the supervisor's or the bouncer's: a stale pidfile may name a reused pid. Nothing here touches PF.
 *
 * @param string $dir the package's crowdsec directory (a test points it at a temp directory)
 */
function pfb_crowdsec_service(string $dir = PFB_CROWDSEC_DIR): void {
	global $pfb;

	$prefix = LOG_PREFIX_PKG_PFBLOCKERNG;
	$config = escapeshellarg($pfb['crowdsec_config'] ?? PFB_CROWDSEC_CONFIG);
	$daemonpid = escapeshellarg($pfb['crowdsec_daemon_pidfile'] ?? PFB_CROWDSEC_DAEMON_PIDFILE);
	$childpid = escapeshellarg($pfb['crowdsec_pidfile'] ?? PFB_CROWDSEC_PIDFILE);
	$bin = escapeshellarg("{$dir}/bin");
	// pgrep/pkill -f patterns (extended regular expressions): the supervisor, by daemon(8)'s title or, until it is set, by its own
	// command line; and the bouncer
	$supervisor = escapeshellarg('^(daemon: pfb_crowdsec\[|/usr/sbin/daemon .*-t pfb_crowdsec )');
	$child = escapeshellarg(pfb_crowdsec_child_pattern($dir));

	$rc		= array();
	$rc['file']	= 'pfb_crowdsec.sh';
	$rc['start']	= <<<EOF

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

	# TERM to the supervisor, which passes it on (a TERM to the bouncer as well would be a second one); to the bouncer itself only
	# when no supervisor is left. KILL to both at 5 s, give up at 7 s keeping the pidfiles (they still name the survivor)
	/bin/pkill -TERM -F {$daemonpid} -f {$supervisor} 2>/dev/null || /bin/pkill -TERM -F {$childpid} -f {$child} 2>/dev/null
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
	/bin/rm -f {$daemonpid} {$childpid}

EOF;
	// A survivor must fail the restart: the start would otherwise report success over it
	$rc['restart']	= "\trc_stop || return 1\n\trc_start\n";
	write_rcfile($rc);
}

/**
 * Name the rule hook in pfBlockerNG's installedpackages/package/<n>/filter_rule_function, which pfSense reads on every filter
 * reload (D5). pfSense's install_package_xml() sets it from <filter_rules_needed> in memory only, then runs the install command,
 * whose pfb_global() re-reads config.xml and drops it; so the update pass, the install's resync included, registers it here.
 *
 * @return bool TRUE when it wrote the registration (the filter has not reloaded with the hook yet)
 */
function pfb_crowdsec_register_rule_hook(): bool {
	foreach (config_get_path('installedpackages/package', []) as $idx => $pkg) {
		if (($pkg['configurationfile'] ?? '') !== 'pfblockerng.xml') {
			continue;
		}
		if (($pkg['filter_rule_function'] ?? '') !== 'pfb_crowdsec_rules') {
			config_set_path("installedpackages/package/{$idx}/filter_rule_function", 'pfb_crowdsec_rules');
			write_config('[pfBlockerNG] register the CrowdSec rule hook');
			return TRUE;
		}
		return FALSE;
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
 * shape) and an outbound one, `on` the selected interfaces' real names unless "all interfaces" is on (a selection with none left
 * gives no rules), `log` and `tag` when set. A stored tag the Settings would refuse is left out: it reaches the ruleset verbatim.
 * The tables are never declared: the bouncer creates them. The reload kills them (#4070), so the first call that returns rules
 * registers pfb_crowdsec_signal() to run when this process ends, after the kill.
 */
function pfb_crowdsec_rules(string $type): string {
	static $registered = FALSE;

	if ($type !== 'pfearly' || !pfb_crowdsec_should_run()) {
		return '';
	}
	$s = pfb_crowdsec_settings();
	$on = '';
	if ($s['rules_all_interfaces'] !== PfbToggle::On) {
		$real = array_filter(array_map('get_real_interface', explode(',', (string) $s['rules_interfaces'])));
		if ($real === []) {
			return '';
		}
		$on = ' on { ' . implode(' ', $real) . ' }';
	}
	$opt = ($s['rules_log'] === PfbToggle::On ? ' log' : '') . " quick{$on}";
	// Quoted: unquoted, pf reads a tag such as `123` or `quick` as a number or a keyword, and pfSense then drops every rule here
	$tag = is_string($s['rules_tag']) && preg_match(PFB_CROWDSEC_TAG_PATTERN, $s['rules_tag']) ? " tag \"{$s['rules_tag']}\"" : '';

	$rules = '';
	foreach (['4' => ['rule_v4', 'inet'], '6' => ['rule_v6', 'inet6']] as $n => [$field, $af]) {
		if ($s[$field] === PfbToggle::On) {
			$rules .= "block drop in{$opt} {$af} from <crowdsec_v{$n}> to any label \"CrowdSec IPv{$n}\"{$tag}\n"
			    . "block drop out{$opt} {$af} from any to <crowdsec_v{$n}> label \"CrowdSec IPv{$n} out\"{$tag}\n";
		}
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

/** Package removal (D4): stop the bouncer and remove its rc script, config file, status file and pidfiles. The binaries are package files. */
function pfb_crowdsec_teardown(): void {
	global $pfb;

	stop_service('pfb_crowdsec');
	foreach (['crowdsec_rcfile' => PFB_CROWDSEC_RCFILE, 'crowdsec_config' => PFB_CROWDSEC_CONFIG, 'crowdsec_status' => PFB_CROWDSEC_STATUS,
	    'crowdsec_pidfile' => PFB_CROWDSEC_PIDFILE, 'crowdsec_daemon_pidfile' => PFB_CROWDSEC_DAEMON_PIDFILE] as $key => $path) {
		unlink_if_exists($pfb[$key] ?? $path);
	}
}

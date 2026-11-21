<?php

declare(strict_types=1);

/**
 * Child process for OutpostApplyCorpusTest (#4037, corpus A): runs the real sync_package_pfblockerng() over the PHPUnit
 * doubles for one scenario of tests/outpost/fixtures/apply/ and writes what each pass did as JSON. argv: scenario file,
 * work directory, result file.
 *
 * A child per scenario because the `post` hook directory is a constant fixed when pfblockerng.inc loads; the hook is a
 * shell script that appends its PFB_* environment to a file, so the context it records is the one a real hook receives.
 *
 * Everything the pass writes stays under the work directory, so concurrent runs share nothing: TMPDIR (and with it the
 * bootstrap sandbox and every temporary file) is {work}/tmp, and every $pfb path under /usr/local/etc, /var/unbound or
 * /tmp moves under {work}/host. The three host paths the pass names literally (/usr/local/sbin/lighttpd_pfb,
 * /usr/local/etc/rc.d/pfb_dnsbl.sh, /var/tmp/node_exporter/pfblockerng.prom) reach only unlink_if_exists(), which here
 * removes nothing outside the work directory.
 *
 * Seams, all existing: `pfctl` is $pfb['pfctl'], here a shell double that keeps each kernel table as a sorted file and
 * logs every call with the lines of its -f file; a file `pfctl-fail/<table>.<verb>` makes that call fail as pfctl does.
 * The filter reload is $pfb['filter_configure_sync'], an executable that exits 0 (or no file, when the scenario says
 * so). write_config(), the service calls, try_lock()/unlock(), the XMLRPC client and file_notice() are the recording
 * doubles of tests/php/pfsense_doubles.php.
 *
 * Scenario: `steps`, each a pass. Before a pass, `config` (config path => value; `custom` values of an IP list are
 * written as lines and base64-encoded here), `files` (path under the work directory, or under {aliasdir} => lines, NULL
 * removes), `kernel` (table => lines, NULL removes), `pfctlFail` (list of "<table>.<verb>"), `pending` (TRUE: a GUI
 * change is marked pending before the pass), `openRecord` (TRUE: a received policy's apply record is open),
 * `received` (TRUE: the node accepted the legacy payload it now holds, so the pass starts suppressed), `reload` ("ok"
 * or "missing"), `dnsConfigLockHeld` (TRUE: another process holds the DNS configuration lock), `dispatchHeld` (TRUE:
 * the caller already holds the scheduler dispatcher lock, as a scheduled tick does), `writeConfigFail` (write_config()
 * descriptions that fail), `save` (TRUE: a settings-save pass). The record of a pass, compacted by corpus_compact(), is
 * what the test compares with the step's `expect`.
 */

[, $scenarioFile, $work, $resultFile] = $argv;
$sc   = json_decode((string) file_get_contents($scenarioFile), TRUE, 64, JSON_THROW_ON_ERROR);
$repo = dirname(__DIR__, 3);
$host = "{$work}/host";

foreach (["{$work}/tmp", "{$work}/kernel", "{$work}/pfctl-fail", "{$host}/usr/local/etc", "{$host}/var/unbound", "{$host}/tmp"] as $dir) {
	@mkdir($dir, 0755, TRUE);
}
putenv("TMPDIR={$work}/tmp");	// before anything asks: sys_get_temp_dir() keeps its first answer
$GLOBALS['corpus_work'] = $work;

// pfSense util.inc, as the shared double, except that nothing outside the work directory is removed.
function unlink_if_exists($fn) {
	if (!str_starts_with((string) $fn, $GLOBALS['corpus_work'] . '/')) {
		return FALSE;
	}
	$to_do = glob($fn);
	if (is_array($to_do) && count($to_do) > 0) {
		$results = @array_map('unlink', $to_do);
		return !in_array(FALSE, $results, TRUE);
	}
	return @unlink($fn);
}

$marker = "{$host}/usr/local/etc/pfb_pending_changes";
define('PFB_HOOK_SCRIPT_DIR', "{$work}/hooks");
@mkdir(PFB_HOOK_SCRIPT_DIR, 0755, TRUE);
// The hook also records whether the GUI change was still pending when it ran (pfb_pending_changes()): the settle follows the hooks.
file_put_contents(PFB_HOOK_SCRIPT_DIR . '/hook_post_ctx.sh', <<<SH
#!/bin/sh
p=0
if [ -e '{$marker}' ] && { [ ! -s '{$marker}' ] || ! cmp -s '{$marker}' '{$marker}.applied'; }; then p=1; fi
{ echo '--'; env | grep '^PFB_' | sort; echo "PENDING_AT_HOOK=\$p"; } >> '{$work}/hook_ctx.log'

SH);
chmod(PFB_HOOK_SCRIPT_DIR . '/hook_post_ctx.sh', 0755);
file_put_contents("{$work}/pfctl", <<<'SH'
#!/bin/sh
d=$(dirname "$0")
k="$d/kernel"
printf '%s\n' "$*" >> "$d/pfctl.log"
t=''; op=''; f=''; s=''
while [ $# -gt 0 ]; do
	case "$1" in
		-t) t="$2"; shift 2 ;;
		-T) op="$2"; shift 2 ;;
		-f) f="$2"; shift 2 ;;
		-s) s="$2"; shift 2 ;;
		*) shift ;;
	esac
done
if [ -n "$f" ]; then
	sed 's/^/  /' "$f" >> "$d/pfctl.log"
fi
if [ "$s" = 'Tables' ]; then
	ls "$k"
	exit 0
fi
if [ -n "$t" ] && [ -e "$d/pfctl-fail/$t.$op" ]; then
	echo 'pfctl: Operation not permitted.'
	exit 1
fi
case "$op" in
	show) if [ -f "$k/$t" ]; then cat "$k/$t"; fi ;;
	replace) sort -u "$f" > "$k/$t.new" && mv "$k/$t.new" "$k/$t" ;;
	add) cat "$f" "$k/$t" 2>/dev/null | sort -u > "$k/$t.new" && mv "$k/$t.new" "$k/$t" ;;
	delete) if [ -f "$k/$t" ]; then grep -vxF -f "$f" "$k/$t" > "$k/$t.new"; mv "$k/$t.new" "$k/$t"; fi ;;
	kill) rm -f "$k/$t" ;;
esac
exit 0
SH);
chmod("{$work}/pfctl", 0755);

/** The filter reload double: an executable that exits 0. */
function corpus_reload_script(string $work): void
{
	file_put_contents("{$work}/rc.filter_configure_sync", "#!/bin/sh\nexit 0\n");
	chmod("{$work}/rc.filter_configure_sync", 0755);
}
corpus_reload_script($work);

foreach (array_keys(getenv()) as $name) {
	if (str_starts_with($name, 'PFB_')) {
		putenv($name);	// the hook inherits this process's environment: only the pass's PFB_* may reach it
	}
}

require "{$repo}/tests/php/bootstrap.php";
require_once "{$repo}/tests/php/SyncPrereqSeedTrait.php";

$pfb =& $GLOBALS['pfb'];
foreach ($pfb as $key => $value) {
	if (is_string($value) && !str_starts_with($value, "{$work}/") && preg_match('#^(/usr/local/etc|/var/unbound|/tmp)(/|$)#', $value)) {
		$pfb[$key] = $host . $value;
	}
}
$pfb['schedule_state_dir']    = "{$host}/usr/local/etc";
$pfb['pfctl']                 = "{$work}/pfctl";
$pfb['ip_unlock']             = "{$work}/ip_unlock";
$pfb['filter_configure_sync'] = "{$work}/rc.filter_configure_sync";
$pfb['php']                   = "{$work}/php-recorder";
$pfb['install']               = FALSE;
$pfb['domain_clear']          = FALSE;
@mkdir($pfb['dbdir'], 0755, TRUE);
$GLOBALS['g']['pfblockerng_install'] = FALSE;
$GLOBALS['g']['unbound_chroot_path'] = "{$host}/var/unbound";
$GLOBALS['config'] = [];

/** The minimum every test that runs the pass seeds (SyncPrereqSeedTrait), and what this corpus adds to it. */
final class CorpusSeed
{
	use SyncPrereqSeedTrait;

	public function seed(): void
	{
		$this->seedSyncPrereqs();
		$gen   = 'installedpackages/pfblockerng/config/0';
		$ip    = 'installedpackages/pfblockerngipsettings/config/0';
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';
		config_set_path("{$gen}/pfb_reuse", '');
		config_set_path("{$gen}/enable_cb", 'on');
		foreach (['enable_dup', 'enable_agg', 'enable_float', 'enable_log', 'killstates', 'ip_placeholder', 'inbound_deny_action',
			'outbound_deny_action', 'pass_order', 'autorule_suffix'] as $key) {
			config_set_path("{$ip}/{$key}", '');
		}
		config_set_path("{$ip}/inbound_interface", 'wan');
		config_set_path("{$ip}/outbound_interface", 'lan');
		config_set_path('interfaces', ['wan' => ['enable' => '', 'if' => 'vtnet0', 'descr' => 'WAN'],
			'lan' => ['enable' => '', 'if' => 'vtnet1', 'descr' => 'LAN']]);
		config_set_path('installedpackages/pfblockerngblacklist/blacklist_enable', 'Disable');
		foreach (['enable_dedup', 'enable_pdup', 'enable_rep', 'et_update', 'ccwhite', 'ccblack', 'etblock', 'etmatch', 'p24_max_var',
			'p24_dmax_var', 'p24_pmax_var', 'ccexclude'] as $key) {
			config_set_path("installedpackages/pfblockerngreputation/config/0/{$key}", '');
		}
		foreach (['top1m_count', 'top1m_inclusion', 'pfb_dnsbl_rule', 'tld_wildcard', 'pfb_control'] as $key) {
			config_set_path("{$dnsbl}/{$key}", '');
		}
		config_set_path('installedpackages/pfblockernglistsv4/config', []);
		config_set_path('installedpackages/pfblockernglistsv6/config', []);
		config_set_path('installedpackages/pfblockerngdnsbl/config', []);
		config_set_path("{$gen}/hooks", ['row' => [['enabled' => 'on', 'when' => 'post', 'script' => 'hook_post_ctx.sh',
			'description' => 'corpus', 'timeout' => '30']]]);
	}
}

/**
 * Lines of a scenario list: a string is one line, {"seq": "10.0.0.%d", "from": 1, "to": 130} is a run of them.
 *
 * @return list<string>
 */
function corpus_expand(array $items): array
{
	$lines = [];
	foreach ($items as $item) {
		if (is_array($item)) {
			for ($i = $item['from']; $i <= $item['to']; $i++) {
				$lines[] = sprintf($item['seq'], $i);
			}
		} else {
			$lines[] = $item;
		}
	}
	return $lines;
}

/** @return list<string> */
function corpus_lines(string $path): array
{
	return is_file($path) ? array_values(array_filter(explode("\n", (string) file_get_contents($path)), static fn ($l) => $l !== '')) : [];
}

/** Writes $lines sorted, one per line, as the pfctl double keeps a kernel table. */
function corpus_write_sorted(string $file, array $lines): void
{
	sort($lines, SORT_STRING);
	file_put_contents($file, implode('', array_map(static fn ($l) => "{$l}\n", $lines)));
}

function corpus_path(string $path, string $work): string
{
	global $pfb;
	return str_replace(['{aliasdir}', '{dbdir}', '{denydir}', '{permitdir}', '{matchdir}', '{nativedir}'],
		[$pfb['aliasdir'], $pfb['dbdir'], $pfb['denydir'], $pfb['permitdir'], $pfb['matchdir'], $pfb['nativedir']],
		str_starts_with($path, '{') ? $path : "{$work}/{$path}");
}

/** Variable parts of a recorded text: the moved host paths, the sandbox, the work directory, temporary file names, dates and times. */
function corpus_normal(string $text, string $work): string
{
	$text = str_replace(["{$work}/host", dirname($GLOBALS['g']['vardb_path']), "{$work}/tmp", $work], ['', '<sandbox>', '<tmp>', '<work>'], $text);
	$text = (string) preg_replace('/(pfb_(?:add|del)_)[A-Za-z0-9]+/', '$1*', $text);
	$text = (string) preg_replace('/\b\d{4}-\d{2}-\d{2}\b/', '<d>', $text);
	$text = (string) preg_replace('/\b\d{1,2}\/\d{1,2}\/\d{2,4}\b|\b\d{1,2}:\d{2}(?::\d{2})?\b|\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\b|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b \d{1,2}/', '<t>', $text);
	return $text;
}

/** @return list<array{call:string,lines:list<string>}> */
function corpus_pfctl_calls(string $work): array
{
	$calls = [];
	foreach (corpus_lines("{$work}/pfctl.log") as $line) {
		if (str_starts_with($line, '  ') && $calls !== []) {
			$calls[count($calls) - 1]['lines'][] = substr($line, 2);
		} else {
			$calls[] = ['call' => corpus_normal($line, $work), 'lines' => []];
		}
	}
	foreach ($calls as &$call) {
		sort($call['lines'], SORT_STRING);
	}
	return $calls;
}

/**
 * A member list longer than 8 lines as its count, digest and ends.
 *
 * @return list<string>|array{count:int,sha1:string,first:string,last:string}
 */
function corpus_list(array $lines): array
{
	return count($lines) <= 8 ? $lines
		: ['count' => count($lines), 'sha1' => sha1(implode("\n", $lines)), 'first' => $lines[0], 'last' => $lines[count($lines) - 1]];
}

/**
 * The record as a fixture holds it: long member lists folded (corpus_list()), a kernel table only where it differs from
 * its sorted mirror, and an array or text section equal to the previous pass's (compacted) as "same".
 */
function corpus_compact(array $record, ?array $previous): array
{
	$kernel = [];
	foreach ($record['kernel'] as $table => $members) {
		$mirror = $record['mirrors']["{$table}.txt"] ?? NULL;
		if ($mirror !== NULL) {
			sort($mirror, SORT_STRING);
		}
		if ($mirror !== $members) {
			$kernel[$table] = corpus_list($members);
		}
	}
	$record['kernel']  = $kernel;
	$record['mirrors'] = array_map('corpus_list', $record['mirrors']);
	$record['pfctl']   = array_map(static fn (array $call): array => ['call' => $call['call'], 'lines' => corpus_list($call['lines'])], $record['pfctl']);
	foreach ($previous === NULL ? [] : $record as $field => $value) {
		if ((is_array($value) || is_string($value)) && $value === $previous[$field]) {
			$record[$field] = 'same';
		}
	}
	return $record;
}

/**
 * The DNS listener's VIPs and what it advertises, each VIP's random uniqid named by its position (<vip1>, ...).
 *
 * @return array{virtualip:array,dnsListen:array}
 */
function corpus_listener(): array
{
	$vips = config_get_path('virtualip/vip', []);
	$ids  = array_values(array_filter(array_column($vips, 'uniqid'), 'strlen'));
	$json = json_encode(['virtualip' => $vips, 'dnsListen' => ['dhcpd' => config_get_path('dhcpd', []),
		'dhcpdv6' => config_get_path('dhcpdv6', []), 'activeInterface' => config_get_path('unbound/active_interface'),
		'added' => PfbConfig::read('gen/pfb_dns_listen_added')]], JSON_THROW_ON_ERROR);
	return json_decode(str_replace($ids, array_map(static fn (int $i): string => '<vip' . ($i + 1) . '>', array_keys($ids)), $json),
		TRUE, 64, JSON_THROW_ON_ERROR);
}

(new CorpusSeed())->seed();
$records  = [];
$previous = NULL;
foreach ($sc['steps'] as $step) {
	foreach ($step['config'] ?? [] as $path => $value) {
		if (str_starts_with($path, 'installedpackages/pfblockernglistsv') && is_array($value)) {
			foreach ($value as &$list) {
				if (isset($list['custom']) && is_array($list['custom'])) {
					$list['custom'] = base64_encode(implode("\n", corpus_expand($list['custom'])));
				}
			}
			unset($list);
		}
		config_set_path($path, $value);
	}
	foreach ($step['files'] ?? [] as $path => $lines) {
		$file = corpus_path($path, $work);
		if ($lines === NULL) {
			@unlink($file);
		} else {
			@mkdir(dirname($file), 0755, TRUE);
			file_put_contents($file, implode('', array_map(static fn ($l) => "{$l}\n", corpus_expand($lines))));
		}
	}
	foreach ($step['kernel'] ?? [] as $table => $lines) {
		if ($lines === NULL) {
			@unlink("{$work}/kernel/{$table}");
		} else {	// 'mirror': what pfSense's filter reload loads from the alias file
			corpus_write_sorted("{$work}/kernel/{$table}", $lines === 'mirror' ? corpus_lines("{$pfb['aliasdir']}/{$table}.txt") : corpus_expand($lines));
		}
	}
	array_map('unlink', glob("{$work}/pfctl-fail/*") ?: []);
	foreach ($step['pfctlFail'] ?? [] as $name) {
		touch("{$work}/pfctl-fail/{$name}");
	}
	if (($step['reload'] ?? 'ok') === 'missing') {
		@unlink("{$work}/rc.filter_configure_sync");
	} elseif (!is_file("{$work}/rc.filter_configure_sync")) {
		corpus_reload_script($work);
	}
	if (!empty($step['pending'])) {
		pfb_mark_pending_changes();
		pfb_due_ledger_set_pending('cron', $pfb['dbdir']);
	}
	$GLOBALS['pfb_test_try_lock_fail'] = !empty($step['dnsConfigLockHeld']);	// the DNS configuration lock is held elsewhere
	$failing = $step['writeConfigFail'] ?? [];
	$GLOBALS['pfb_test_write_config_hook'] = static function (string $desc) use ($failing): void {
		$GLOBALS['pfb_test_write_config_result'] = !in_array($desc, $failing, TRUE);
	};
	if (!empty($step['openRecord'])) {
		$time = time() - 100;
		file_put_contents("{$pfb['dbdir']}/pfb_sync_receive.json", json_encode(['accepted_digest' => NULL,
			'last' => ['time' => $time, 'outcome' => 'changed'], 'apply' => ['time' => $time, 'outcome' => 'waiting']]));
	}
	if (!empty($step['received'])) {
		file_put_contents("{$pfb['dbdir']}/pfb_sync_receive.json", json_encode(['accepted_digest' => 'received',
			'legacy_digests' => pfb_sync_legacy_digests(['all', 'lists'])]));
	}
	if (!empty($step['dispatchHeld'])) {
		pfb_schedule_dispatch_begin();
	}

	@unlink("{$work}/pfctl.log");
	@unlink("{$work}/hook_ctx.log");
	@file_put_contents($pfb['log'], '');
	$GLOBALS['pfb_test_write_config_calls']      = [];
	$GLOBALS['pfb_test_service_calls']           = [];
	$GLOBALS['pfb_test_file_notices']            = [];
	$GLOBALS['pfb_test_lock_events']             = [];
	$GLOBALS['pfb_test_unbound_configure_calls'] = [];
	$GLOBALS['pfb_test_xmlrpc_calls']            = [];
	$GLOBALS['pfb_test_xmlrpc_connections']      = [];
	$GLOBALS['pfb']['save']                      = !empty($step['save']);

	$returned = sync_package_pfblockerng();

	$mirrors = [];
	foreach (glob("{$pfb['aliasdir']}/*") ?: [] as $file) {
		$mirrors[basename($file)] = corpus_lines($file);
	}
	ksort($mirrors);
	$kernel = [];
	foreach (glob("{$work}/kernel/*") ?: [] as $file) {
		$kernel[basename($file)] = corpus_lines($file);
	}
	ksort($kernel);
	$ctx = [];
	$pendingAtHook = NULL;
	foreach (corpus_lines("{$work}/hook_ctx.log") as $line) {
		if ($line !== '--') {
			[$name, $value] = explode('=', $line, 2) + [1 => ''];
			if ($name === 'PENDING_AT_HOOK') {
				$pendingAtHook = $value === '1';
			} else {
				$ctx[$name] = $value;
			}
		}
	}
	$ledger = [];
	foreach (glob("{$pfb['dbdir']}/pfb_sync_status*") ?: [] as $file) {
		$ledger[basename($file)] = (string) preg_replace('/"(first_seen|last_seen)": \d+/', '"$1": "<t>"',
			corpus_normal((string) file_get_contents($file), $work));
	}
	$receive = is_file("{$pfb['dbdir']}/pfb_sync_receive.json")
		? json_decode((string) file_get_contents("{$pfb['dbdir']}/pfb_sync_receive.json"), TRUE) : NULL;
	$full = [
		'returned'     => $returned,
		'pfctl'        => corpus_pfctl_calls($work),
		'kernel'       => $kernel,
		'mirrors'      => $mirrors,
		'aliases'      => config_get_path('aliases/alias', []),
		'rules'        => array_map(static function (array $rule): array {
			unset($rule['created'], $rule['updated']);
			return $rule;
		}, config_get_path('filter/rule', [])),
		'nat'          => config_get_path('nat/rule', []),
		'reuse'        => config_get_path('installedpackages/pfblockerng/config/0/pfb_reuse'),
		'writeConfig'  => $GLOBALS['pfb_test_write_config_calls'],
		'services'     => $GLOBALS['pfb_test_service_calls'],
		'hook'         => $ctx,
		'pending'      => pfb_pending_changes(),
		'ledgerPending' => pfb_due_ledger_is_pending('cron', $pfb['dbdir']),
		'applyRecord'  => isset($receive['apply']) ? array_diff_key($receive['apply'], ['time' => 1, 'opened' => 1]) : NULL,
		'syncStatus'   => $ledger,
		'ipUnlock'     => is_file($pfb['ip_unlock']),
		'ipCache'      => is_file($pfb['ip_cache']),
		'log'          => corpus_normal((string) file_get_contents($pfb['log']), $work),
		// Whether the GUI change was still pending when the `post` hook ran; NULL: no hook ran.
		'pendingAtHook' => $pendingAtHook,
		// The DNS listener's objects: its VIPs, the DHCP and Resolver lists it advertises on, and what it recorded adding.
		...corpus_listener(),
		'unboundConfigure' => $GLOBALS['pfb_test_unbound_configure_calls'],
		// The locks the pass left held, and the named locks it took and released, in order.
		'locks'        => ['feedPass' => isset($GLOBALS['pfb_feed_pass_lock']),
			'dispatch'  => is_resource($GLOBALS['pfb_schedule_dispatch_lock'] ?? NULL),
			'dnsConfig' => !empty($GLOBALS['pfb_test_lock_held']),
			'holders'   => array_keys($GLOBALS['pfb_test_lock_holders'] ?? []),
			'events'    => $GLOBALS['pfb_test_lock_events']],
		'xmlrpc'       => array_map(static fn (array $call, array $to): array => [$call[0], $to['ip']],
			$GLOBALS['pfb_test_xmlrpc_calls'], $GLOBALS['pfb_test_xmlrpc_connections']),
		// Whether the received legacy payload on record is what the node holds now; NULL: no policy accepted.
		'receivedCurrent' => ($receive['accepted_digest'] ?? NULL) === NULL ? NULL
			: ($receive['legacy_digests'] ?? NULL) === pfb_sync_legacy_digests(['all', 'lists']),
		'metricsSentinel' => is_file($pfb['metrics_enabled']),
	];
	if (!empty($step['dispatchHeld'])) {
		pfb_schedule_dispatch_release();
	}
	$records[] = corpus_compact($full, $previous);
	$previous  = corpus_compact($full, NULL);
}
file_put_contents($resultFile, json_encode($records, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));

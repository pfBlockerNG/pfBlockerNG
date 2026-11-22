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
 * bootstrap sandbox and every temporary file) is {work}/tmp, checked after the bootstrap, and every absolute path in
 * $pfb, at any depth, that lies outside the work directory and the source tree moves under {work}/host, except the
 * tools of CORPUS_HOST_TOOLS. $pfb is walked again after each pass, and a host path found there fails the run.
 *
 * Some host paths the pass names literally rather than through $pfb. Those that reach unlink_if_exists()
 * (/usr/local/sbin/lighttpd_pfb, /usr/local/etc/rc.d/pfb_dnsbl.sh, /var/tmp/node_exporter/pfblockerng.prom,
 * /var/unbound/pfb_py_ss.*) are removed under {work}/host instead, as production removes them on the host. Two have no
 * seam: /var/unbound/pfb_py_ss.raw, written when SafeSearch is on, and /tmp/Error_<feed>_<date>.orig, written when a
 * DNSBL feed yields no domains; the worker refuses a scenario that enables SafeSearch or configures a feed to download.
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
 * descriptions that fail), `writeConfigThrow` (write_config() descriptions that throw), `save` (TRUE: a settings-save pass), `pendingToken` (the pending mark holds exactly this token). The
 * record of a pass, compacted by corpus_compact(), is what the test compares with the step's `expect`.
 *
 * A step with `apply` runs the version 2 apply of #4037 in place of the pass (OutpostApplyTest): its `request` goes to
 * pfb_core_update_serve() on stdin, the Core API's socket is served by support/CoreApiStandIn.php from its `core` script
 * (no `core`: nothing listens), `lockHeld` (TRUE) holds the apply lock and `dispatchLockHeld` (TRUE) the scheduler
 * dispatcher lock while it runs. Its `seams` replace the host-reaching steps of the apply: `dns` ({mode, update, python, active}:
 * what pfb_apply_dns() reports, `active` turns DNSBL, pfB-DNS and the Resolver on in $pfb for the steps after it), `unbound`
 * ({effect}: what the Resolver reload does besides recording its call: `flag` sets
 * $pfb['dnsbl_accounting_failed'], `marker` writes the `accounting` retry marker), `cache` (TRUE: the DNSBL archive records
 * its call) and `fetchThrowAt` (the n-th fetch, from 1, throws). The record adds `seamCalls`. Its record is not compacted and adds the exit status, the result lines, the cursor file, the
 * requests Core received, the notices filed, the DNSBL statistics rows and the GeoIP pages.
 */

[, $scenarioFile, $work, $resultFile] = $argv;
$sc   = json_decode((string) file_get_contents($scenarioFile), TRUE, 64, JSON_THROW_ON_ERROR);
$repo = dirname(__DIR__, 3);
$host = "{$work}/host";

foreach (["{$work}/tmp", "{$work}/kernel", "{$work}/pfctl-fail", "{$host}/usr/local/etc", "{$host}/var/unbound", "{$host}/tmp"] as $dir) {
	@mkdir($dir, 0755, TRUE);
}
$GLOBALS['corpus_host'] = $host;
putenv("TMPDIR={$work}/tmp");	// before anything asks: sys_get_temp_dir() keeps its first answer
$GLOBALS['corpus_work'] = $work;

// pfSense util.inc, as the shared double, except that a path outside the work directory is removed under {work}/host.
function unlink_if_exists($fn) {
	$fn = (string) $fn;
	if (!str_starts_with($fn, $GLOBALS['corpus_work'] . '/')) {
		if (!str_starts_with($fn, '/')) {
			throw new RuntimeException("unlink_if_exists() got a relative path: {$fn}");
		}
		$fn = $GLOBALS['corpus_host'] . $fn;
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
	replace) LC_ALL=C sort -u "$f" > "$k/$t.new" && mv "$k/$t.new" "$k/$t" ;;
	add) cat "$f" "$k/$t" 2>/dev/null | LC_ALL=C sort -u > "$k/$t.new" && mv "$k/$t.new" "$k/$t" ;;
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
require_once "{$repo}/tests/php/support/ProcessRunner.php";
require_once "{$repo}/tests/php/SyncPrereqSeedTrait.php";

// PHP's sys_temp_dir setting overrides TMPDIR: the bootstrap's sandbox must have landed under the work directory.
if (!str_starts_with($GLOBALS['g']['vardb_path'], "{$work}/tmp/")) {
	throw new RuntimeException("the bootstrap sandbox {$GLOBALS['g']['vardb_path']} lies outside {$work}/tmp");
}

// $pfb keys whose host path the pass may keep: executables it runs and never writes.
const CORPUS_HOST_TOOLS = ['awk', 'cat', 'cut', 'ggrep', 'grep', 'ls', 'sed', 'tar', 'timeout', 'wc'];

/** Whether $value is an absolute path outside the work directory and the source tree (a regex such as $pfb['ipv4'] is not a path). */
function corpus_is_host_path(mixed $value, string $work, string $repo): bool
{
	return is_string($value) && preg_match('#^(/[A-Za-z0-9._@+-]+)+/?$#', $value) === 1
		&& !str_starts_with("{$value}/", "{$work}/") && !str_starts_with("{$value}/", "{$repo}/");
}

/** Moves every host path in $values, at any depth, under {work}/host; at the top level the tools keep theirs. */
function corpus_sandbox_paths(array &$values, string $work, string $repo, bool $top = TRUE): void
{
	foreach ($values as $key => &$value) {
		if (is_array($value)) {
			corpus_sandbox_paths($value, $work, $repo, FALSE);
		} elseif (corpus_is_host_path($value, $work, $repo) && !($top && in_array($key, CORPUS_HOST_TOOLS, TRUE))) {
			$value = "{$work}/host{$value}";
		}
	}
}

/** Throws if any host path is left in $values, at any depth, other than a tool's. */
function corpus_assert_sandboxed(array $values, string $work, string $repo, string $at = 'pfb'): void
{
	foreach ($values as $key => $value) {
		if (is_array($value)) {
			corpus_assert_sandboxed($value, $work, $repo, "{$at}[{$key}]");
		} elseif (corpus_is_host_path($value, $work, $repo) && !($at === 'pfb' && in_array($key, CORPUS_HOST_TOOLS, TRUE))) {
			throw new RuntimeException("{$at}[{$key}] points at the host: {$value}");
		}
	}
}

$pfb =& $GLOBALS['pfb'];
corpus_sandbox_paths($pfb, $work, $repo);
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
corpus_assert_sandboxed($pfb, $work, $repo);

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
	return str_replace(['{aliasdir}', '{dbdir}', '{denydir}', '{permitdir}', '{matchdir}', '{nativedir}', '{ccdir}'],
		[$pfb['aliasdir'], $pfb['dbdir'], $pfb['denydir'], $pfb['permitdir'], $pfb['matchdir'], $pfb['nativedir'], $pfb['ccdir']],
		str_starts_with($path, '{') ? $path : "{$work}/{$path}");
}

/** Variable parts of a recorded text: the moved host paths, the sandbox, the work directory, temporary file names, dates and times. */
function corpus_normal(string $text, string $work): string
{
	$text = str_replace(["{$work}/host", dirname($GLOBALS['g']['vardb_path']), "{$work}/tmp", $work], ['<host>', '<sandbox>', '<tmp>', '<work>'], $text);
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
 * its sorted mirror (NULL: a mirror whose kernel table is absent), and an array or text section equal to the previous
 * pass's (compacted) as "same".
 */
function corpus_compact(array $record, ?array $previous): array
{
	$kernel = [];
	$tables = array_keys($record['kernel']);
	foreach (array_keys($record['mirrors']) as $name) {
		if (str_ends_with($name, '.txt')) {
			$tables[] = substr($name, 0, -4);
		}
	}
	$tables = array_unique($tables);
	sort($tables, SORT_STRING);
	foreach ($tables as $table) {
		$members = $record['kernel'][$table] ?? NULL;
		$mirror  = $record['mirrors']["{$table}.txt"] ?? NULL;
		if ($mirror !== NULL) {
			sort($mirror, SORT_STRING);
		}
		if ($members === NULL) {
			$kernel[$table] = NULL;
		} elseif ($mirror !== $members) {
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

/** Refuses a configuration that makes the pass write a literal host path no seam moves (see the header). */
function corpus_refuse_unsandboxed(): void
{
	foreach (['ss/safesearch_enable', 'ss/safesearch_youtube', 'ss/safesearch_doh'] as $key) {
		if (PfbConfig::read($key) !== 'Disable') {	// the test of pfb_global() that turns SafeSearch on
			throw new RuntimeException("the scenario enables SafeSearch ({$key}): the pass would write /var/unbound/pfb_py_ss.raw on the host");
		}
	}
	foreach (['installedpackages/pfblockernglistsv4/config', 'installedpackages/pfblockernglistsv6/config',
		'installedpackages/pfblockerngdnsbl/config'] as $path) {
		foreach (config_get_path($path, []) as $list) {
			if (!empty($list['row'])) {
				throw new RuntimeException("the scenario configures a feed to download ({$path}): the pass may write /tmp/Error_*.orig on the host");
			}
		}
	}
	if (config_get_path('installedpackages/pfblockerngblacklist/blacklist_enable') !== 'Disable') {
		throw new RuntimeException('the scenario enables the DNSBL blacklist categories, which the pass downloads');
	}
}

/**
 * Run the version 2 apply for one step: [what pfb_core_update_serve() returned, what the record adds].
 *
 * @param array{request: array, core?: list<array>, lockHeld?: bool} $apply
 * @return array{0: int, 1: array<string, mixed>}
 */
function corpus_v2_apply(array $apply, string $work, string $repo): array
{
	global $pfb;
	$socket = "{$work}/api.sock";
	$pfb['core_socket'] = $socket;
	foreach ([$socket, "{$work}/core-requests", "{$work}/result"] as $path) {
		@unlink($path);
	}
	$standin = NULL;
	if (isset($apply['core'])) {
		file_put_contents("{$work}/core-script.json", json_encode($apply['core'], JSON_THROW_ON_ERROR));
		$standin = pfb_test_start_process([PHP_BINARY, "{$repo}/tests/php/support/CoreApiStandIn.php", $socket, "{$work}/core-requests",
			'script', "{$work}/core-script.json"]);
		pfb_test_await_ready($standin);
	}
	$held = [];
	foreach (['lockHeld' => "{$pfb['dbdir']}/pfb_feed_pass.lock", 'dispatchLockHeld' => "{$pfb['schedule_state_dir']}/pfb_schedule_dispatch.lock"]
		as $key => $lock) {
		if (!empty($apply[$key])) {	// another open file description: flock() refuses this process too
			$held[] = $fh = fopen($lock, 'c');
			flock($fh, LOCK_EX);
		}
	}
	$calls = ['unbound' => [], 'cache' => 0];
	$want = $apply['seams'] ?? [];
	$seams = [];
	if (isset($want['dns'])) {
		$seams['dns'] = static function () use ($want): array {
			global $pfb;
			if (!empty($want['dns']['active'])) {
				$pfb['enable'] = $pfb['pfb_dns'] = $pfb['dnsbl'] = $pfb['unbound_state'] = PfbToggle::On;
			}
			return [$want['dns']['mode'] ?? 'enabled', !empty($want['dns']['update']), !empty($want['dns']['python'])];
		};
	}
	if (isset($want['unbound'])) {
		$seams['unbound'] = static function (string $mode, bool $update, bool $python) use ($want, &$calls): ?bool {
			global $pfb;
			$calls['unbound'][] = [$mode, $update, $python];
			$effect = $want['unbound']['effect'] ?? '';
			if ($effect === 'flag') {
				$pfb['dnsbl_accounting_failed'] = TRUE;
			} elseif ($effect === 'marker') {
				file_put_contents("{$pfb['dnsbl_file']}.reload", 'accounting');
			}
			return NULL;
		};
	}
	if (!empty($want['cache'])) {
		$seams['cache'] = static function (string $mode) use (&$calls): void {
			$calls['cache']++;
			$calls['cacheMode'] = $mode;
		};
	}
	if (isset($want['fetchThrowAt'])) {
		$fetches = 0;
		$seams['fetch'] = static function (mixed ...$args) use ($want, &$fetches): array {
			if (++$fetches === $want['fetchThrowAt']) {
				throw new RuntimeException('the fetch throws, as the scenario asks');
			}
			return pfb_outpost_fetch(...$args);
		};
	}
	$status = pfb_core_update_serve(json_encode($apply['request'], JSON_THROW_ON_ERROR), "{$work}/result", $seams);
	foreach ($held as $fh) {
		flock($fh, LOCK_UN);
		fclose($fh);
	}
	$served = NULL;
	if ($standin !== NULL) {
		$served = pfb_test_finish_process($standin, 30.0)['exit'];
	}
	$cursors = "{$pfb['dbdir']}/pfb_apply_cursors.json";
	$stats = NULL;
	if (is_file($pfb['dnsbl_info'])) {
		$db = new SQLite3($pfb['dnsbl_info'], SQLITE3_OPEN_READONLY);
		$rows = @$db->query('SELECT groupname, entries FROM dnsbl ORDER BY groupname');
		while ($rows !== FALSE && ($row = $rows->fetchArray(SQLITE3_ASSOC)) !== FALSE) {
			$stats[$row['groupname']] = (string) $row['entries'];
		}
		$db->close();
	}
	$pages = array_map('basename', glob(dirname($pfb['feeds']) . '/pfblockerng_*.php') ?: []);
	sort($pages, SORT_STRING);
	return [$status, [
		'exit'         => $status,
		'seamCalls'    => $calls,
		'resultLines'  => is_file("{$work}/result") ? array_map(static fn (string $line): mixed => json_decode($line, TRUE),
			corpus_lines("{$work}/result")) : NULL,
		'cursors'      => is_file($cursors) ? json_decode((string) file_get_contents($cursors), TRUE) : NULL,
		'coreRequests' => array_map(static fn (string $line): mixed => json_decode($line, TRUE), corpus_lines("{$work}/core-requests")),
		// 0: the stand-in served its whole script; NULL: nothing listened
		'coreServed'   => $served,
		'notices'      => $GLOBALS['pfb_test_file_notices'],
		// the DNSBL statistics rows, groupname => entries (NULL: no database), and the GeoIP pages in the web folder
		'dnsblStats'   => $stats,
		'geoPages'     => $pages,
	]];
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
	if (isset($step['pendingToken'])) {
		file_put_contents($marker, $step['pendingToken']);
	}
	if (!empty($step['pending'])) {
		pfb_mark_pending_changes();
		pfb_due_ledger_set_pending('cron', $pfb['dbdir']);
	}
	$GLOBALS['pfb_test_try_lock_fail'] = !empty($step['dnsConfigLockHeld']);	// the DNS configuration lock is held elsewhere
	$failing = $step['writeConfigFail'] ?? [];
	$throwing = $step['writeConfigThrow'] ?? [];
	$GLOBALS['pfb_test_write_config_hook'] = static function (string $desc) use ($failing, $throwing): void {
		if (in_array($desc, $throwing, TRUE)) {
			throw new RuntimeException("write_config({$desc}) throws, as the scenario asks");
		}
		$GLOBALS['pfb_test_write_config_result'] = !in_array($desc, $failing, TRUE);
	};
	if (!empty($step['openRecord'])) {
		$time = time() - 100;
		file_put_contents("{$pfb['dbdir']}/pfb_sync_receive.json", json_encode(['accepted_digest' => NULL,
			'last' => ['time' => $time, 'outcome' => 'changed'], 'apply' => ['time' => $time, 'outcome' => 'waiting']]));
	}
	if (!empty($step['received'])) {
		$file = "{$pfb['dbdir']}/pfb_sync_receive.json";	// merged, so an `openRecord` step keeps its apply record beside the policy
		$open = is_file($file) ? json_decode((string) file_get_contents($file), TRUE, 8, JSON_THROW_ON_ERROR) : [];
		file_put_contents($file, json_encode(['accepted_digest' => 'received',
			'legacy_digests' => pfb_sync_legacy_digests(['all', 'lists'])] + $open));
	}
	if (!empty($step['dispatchHeld'])) {
		pfb_schedule_dispatch_begin();
	}
	corpus_refuse_unsandboxed();

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

	$v2 = [];
	if (isset($step['apply'])) {
		[$returned, $v2] = corpus_v2_apply($step['apply'], $work, $repo);
	} else {
		$returned = sync_package_pfblockerng();
	}
	corpus_assert_sandboxed($pfb, $work, $repo);

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
	foreach (array_filter(glob("{$pfb['dbdir']}/pfb_sync_status*") ?: [], 'is_file') as $file) {
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
		// Each XMLRPC call with the connection of the same index; a missing partner is NULL.
		'xmlrpc'       => array_map(static fn (?array $call, ?array $to): array => [$call[0] ?? NULL, $to['ip'] ?? NULL],
			$GLOBALS['pfb_test_xmlrpc_calls'], $GLOBALS['pfb_test_xmlrpc_connections']),
		// Whether the received legacy payload on record is what the node holds now; NULL: no policy accepted.
		'receivedCurrent' => ($receive['accepted_digest'] ?? NULL) === NULL ? NULL
			: ($receive['legacy_digests'] ?? NULL) === pfb_sync_legacy_digests(['all', 'lists']),
		'metricsSentinel' => is_file($pfb['metrics_enabled']),
	];
	if (!empty($step['dispatchHeld'])) {
		pfb_schedule_dispatch_release();
	}
	$records[] = $v2 === [] ? corpus_compact($full, $previous) : $full + $v2;
	$previous  = corpus_compact($full, NULL);
}
file_put_contents($resultFile, json_encode($records, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));

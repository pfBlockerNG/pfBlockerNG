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
 * Seams, all existing: `pfctl` is $pfb['pfctl'], here a shell double that keeps each kernel table as a sorted file and
 * logs every call with the lines of its -f file; a file `pfctl-fail/<table>.<verb>` makes that call fail as pfctl does.
 * The filter reload is $pfb['filter_configure_sync'], an executable that exits 0 (or no file, when the scenario says
 * so). write_config(), the service calls and file_notice() are the recording doubles of tests/php/pfsense_doubles.php.
 *
 * Scenario: `steps`, each a pass. Before a pass, `config` (config path => value; `custom` values of an IP list are
 * written as lines and base64-encoded here), `files` (path under the work directory, or under {aliasdir} => lines, NULL
 * removes), `kernel` (table => lines, NULL removes), `pfctlFail` (list of "<table>.<verb>"), `pending` (TRUE: a GUI
 * change is marked pending before the pass), `openRecord` (TRUE: a received policy's apply record is open), `reload`
 * ("ok" or "missing"). The record of a pass is what the test compares with the step's `expect`.
 */

[, $scenarioFile, $work, $resultFile] = $argv;
$sc   = json_decode((string) file_get_contents($scenarioFile), TRUE, 64, JSON_THROW_ON_ERROR);
$repo = dirname(__DIR__, 3);

define('PFB_HOOK_SCRIPT_DIR', "{$work}/hooks");
@mkdir(PFB_HOOK_SCRIPT_DIR, 0755, TRUE);
@mkdir("{$work}/kernel", 0755, TRUE);
@mkdir("{$work}/pfctl-fail", 0755, TRUE);
file_put_contents(PFB_HOOK_SCRIPT_DIR . '/hook_post_ctx.sh', "#!/bin/sh\n{ echo '--'; env | grep '^PFB_' | sort; } >> '{$work}/hook_ctx.log'\n");
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
file_put_contents("{$work}/rc.filter_configure_sync", "#!/bin/sh\nexit 0\n");
chmod("{$work}/rc.filter_configure_sync", 0755);

foreach (array_keys(getenv()) as $name) {
	if (str_starts_with($name, 'PFB_')) {
		putenv($name);	// the hook inherits this process's environment: only the pass's PFB_* may reach it
	}
}

// pfSense util.inc (master): the custom-list branch of the IP download loop calls it and the shared doubles lack it.
function array_init_path(mixed &$arr, ?string $path): void
{
	if (!is_array($arr)) {
		$arr = [];
	}
	if ($path === NULL) {
		return;
	}
	$tmp = &$arr;
	foreach (explode('/', $path) as $key) {
		if (!is_array($tmp[$key] ?? NULL)) {
			$tmp[$key] = [];
		}
		$tmp = &$tmp[$key];
	}
}

require "{$repo}/tests/php/bootstrap.php";

$pfb =& $GLOBALS['pfb'];
$pfb['pfctl']                 = "{$work}/pfctl";
$pfb['ip_unlock']             = "{$work}/ip_unlock";
$pfb['filter_configure_sync'] = "{$work}/rc.filter_configure_sync";
$pfb['php']                   = "{$work}/php-recorder";
$pfb['install']               = FALSE;
$pfb['domain_clear']          = FALSE;
@mkdir($pfb['dbdir'], 0755, TRUE);
$GLOBALS['g']['pfblockerng_install'] = FALSE;
$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
$GLOBALS['config'] = [];

/** The same minimum every test that runs the pass seeds (SyncPrereqSeedTrait, SyncPolicyApplyRecordTest). */
function corpus_seed_config(): void
{
	$gen   = 'installedpackages/pfblockerng/config/0';
	$ip    = 'installedpackages/pfblockerngipsettings/config/0';
	$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';
	foreach (['pfb_min' => '0', 'pfb_hour' => '0', 'pfb_dailystart' => '0', 'skipfeed' => '0', 'pfb_interval' => '24',
		'pfb_quiet_hours' => '', 'pfb_reuse' => '', 'enable_cb' => 'on'] as $key => $value) {
		config_set_path("{$gen}/{$key}", $value);
	}
	foreach (['suppression' => '', 'database_cc' => '', 'maxmind_locale' => 'en', 'asn_reporting' => 'disabled', 'asn_token' => '',
		'maxmind_account' => '', 'maxmind_key' => '', 'enable_dup' => '', 'enable_agg' => '', 'enable_float' => '', 'enable_log' => '',
		'killstates' => '', 'ip_placeholder' => '', 'inbound_deny_action' => '', 'outbound_deny_action' => '', 'pass_order' => '',
		'autorule_suffix' => ''] as $key => $value) {
		config_set_path("{$ip}/{$key}", $value);
	}
	config_set_path("{$ip}/inbound_interface", 'wan');
	config_set_path("{$ip}/outbound_interface", 'lan');
	config_set_path('interfaces', ['wan' => ['enable' => '', 'if' => 'vtnet0', 'descr' => 'WAN'],
		'lan' => ['enable' => '', 'if' => 'vtnet1', 'descr' => 'LAN']]);
	config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
	config_set_path('installedpackages/pfblockerngblacklist/blacklist_enable', 'Disable');
	foreach (['enable_dedup', 'enable_pdup', 'enable_rep', 'et_update', 'ccwhite', 'ccblack', 'etblock', 'etmatch', 'p24_max_var',
		'p24_dmax_var', 'p24_pmax_var', 'ccexclude'] as $key) {
		config_set_path("installedpackages/pfblockerngreputation/config/0/{$key}", '');
	}
	foreach (['pfb_dnsvip4' => '', 'pfb_dnsvip6' => '', 'pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443', 'top1m_enable' => '',
		'top1m_count' => '', 'top1m_inclusion' => '', 'pfb_py_reply' => '', 'pfb_regex' => '', 'pfb_regex_list' => '', 'pfb_cname' => '',
		'tld_allow' => '', 'pfb_py_nolog' => '', 'pfb_noaaaa' => '', 'pfb_noaaaa_list' => '', 'pfb_gp' => '', 'pfb_gp_bypass_list' => '',
		'pfb_dnsbl_rule' => '', 'tld_wildcard' => '', 'pfb_control' => ''] as $key => $value) {
		config_set_path("{$dnsbl}/{$key}", $value);
	}
	config_set_path('installedpackages/pfblockernglistsv4/config', []);
	config_set_path('installedpackages/pfblockernglistsv6/config', []);
	config_set_path('installedpackages/pfblockerngdnsbl/config', []);
	config_set_path("{$gen}/hooks", ['row' => [['enabled' => 'on', 'when' => 'post', 'script' => 'hook_post_ctx.sh',
		'description' => 'corpus', 'timeout' => '30']]]);
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

function corpus_path(string $path, string $work): string
{
	global $pfb;
	return str_replace(['{aliasdir}', '{dbdir}', '{denydir}', '{permitdir}', '{matchdir}', '{nativedir}'],
		[$pfb['aliasdir'], $pfb['dbdir'], $pfb['denydir'], $pfb['permitdir'], $pfb['matchdir'], $pfb['nativedir']],
		str_starts_with($path, '{') ? $path : "{$work}/{$path}");
}

/** Variable parts of a recorded text: the sandbox, the work directory, temporary file names, dates and times. */
function corpus_normal(string $text, string $work): string
{
	$text = str_replace([$work, dirname($GLOBALS['g']['vardb_path']), rtrim(sys_get_temp_dir(), '/')], ['<work>', '<sandbox>', '<tmp>'], $text);
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

corpus_seed_config();
$records = [];
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
		} elseif ($lines === 'mirror') {	// what pfSense's filter reload loads from the alias file
			$lines = corpus_lines("{$pfb['aliasdir']}/{$table}.txt");
			sort($lines, SORT_STRING);
			file_put_contents("{$work}/kernel/{$table}", implode('', array_map(static fn ($l) => "{$l}\n", $lines)));
		} else {
			$lines = corpus_expand($lines);
			sort($lines, SORT_STRING);
			file_put_contents("{$work}/kernel/{$table}", implode('', array_map(static fn ($l) => "{$l}\n", $lines)));
		}
	}
	array_map('unlink', glob("{$work}/pfctl-fail/*") ?: []);
	foreach ($step['pfctlFail'] ?? [] as $name) {
		touch("{$work}/pfctl-fail/{$name}");
	}
	if (($step['reload'] ?? 'ok') === 'missing') {
		@unlink("{$work}/rc.filter_configure_sync");
	} elseif (!is_file("{$work}/rc.filter_configure_sync")) {
		file_put_contents("{$work}/rc.filter_configure_sync", "#!/bin/sh\nexit 0\n");
		chmod("{$work}/rc.filter_configure_sync", 0755);
	}
	if (!empty($step['pending'])) {
		pfb_mark_pending_changes();
		pfb_due_ledger_set_pending('cron', $pfb['dbdir']);
	}
	if (!empty($step['openRecord'])) {
		$time = time() - 100;
		file_put_contents("{$pfb['dbdir']}/pfb_sync_receive.json", json_encode(['accepted_digest' => NULL,
			'last' => ['time' => $time, 'outcome' => 'changed'], 'apply' => ['time' => $time, 'outcome' => 'waiting']]));
	}

	@unlink("{$work}/pfctl.log");
	@unlink("{$work}/hook_ctx.log");
	@file_put_contents($pfb['log'], '');
	$GLOBALS['pfb_test_write_config_calls'] = [];
	$GLOBALS['pfb_test_service_calls']      = [];
	$GLOBALS['pfb_test_file_notices']       = [];
	$GLOBALS['pfb']['save']                 = FALSE;

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
	foreach (corpus_lines("{$work}/hook_ctx.log") as $line) {
		if ($line !== '--') {
			[$name, $value] = explode('=', $line, 2) + [1 => ''];
			$ctx[$name] = $value;
		}
	}
	$ledger = [];
	foreach (glob("{$pfb['dbdir']}/pfb_sync_status*") ?: [] as $file) {
		$ledger[basename($file)] = (string) preg_replace('/"(first_seen|last_seen)": \d+/', '"$1": "<t>"',
			corpus_normal((string) file_get_contents($file), $work));
	}
	$receive = is_file("{$pfb['dbdir']}/pfb_sync_receive.json")
		? json_decode((string) file_get_contents("{$pfb['dbdir']}/pfb_sync_receive.json"), TRUE) : NULL;
	$records[] = [
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
	];
}
file_put_contents($resultFile, json_encode($records, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));

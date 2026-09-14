<?php

declare(strict_types=1);

/*
 * issue #3292: bounded Unbound restart/recovery regression assertions for release/3.3.
 *
 * Backports devel's recovery contract (issues #3055, #3094, #3100, #2879) onto the
 * legacy pfb_stop_start_unbound()/pfb_reload_unbound() pair: bounded TERM/KILL stop
 * escalation with no double-start while the old daemon survives, PID-first stop with a
 * name-based fallback for a missing/stale pidfile, a supervised start that lets a real
 * daemon detach while a stuck launcher/helper is reaped, a start-outcome vocabulary
 * (start_completed + a distinguished PFB_UNBOUND_STOP_FAILED/124) that keeps a genuine
 * config-error rollback/retry from firing on infrastructure failure, and bounded
 * unbound-control IPC for dump_cache/status/load_cache with truthful, non-clobbering
 * results.
 *
 * This line ships no PHPUnit/composer (tests/php/README has none for release/3.3), so
 * this follows the established row()/check() assertion-script pattern
 * (tests/php/assert_pkg_upgrade_guard_3_3.php): eval() the extracted PRODUCTION function
 * bodies straight from the shipped .inc, with behavioural doubles for the pfSense
 * platform functions (is_process_running/isvalidpid/sigkillbypid/sigkillbyname).
 * Real process-group/signal semantics (TERM/KILL escalation, a daemon detaching via
 * posix_setsid(), a supervised launcher and its helper being reaped) are proven with a
 * REAL child process tree per row, run in an ISOLATED PHP subprocess so each row can set
 * its own PFB_UNBOUND_* budgets (constants are process-global and define-once). Every
 * isolated run carries an outer `timeout` SALVAGE watchdog -- it reaps a stuck run, it is
 * never the pass criterion; the row's own assertions are.
 */

function function_source(string $source, string $name): string
{
	$start = strpos($source, "function {$name}");
	if ($start === false) {
		throw new RuntimeException("missing {$name}");
	}
	$open = strpos($source, '{', $start);
	if ($open === false) {
		throw new RuntimeException("missing {$name} body");
	}
	$depth = 0;
	$length = strlen($source);
	for ($i = $open; $i < $length; $i++) {
		if ($source[$i] === '{') {
			$depth++;
		} elseif ($source[$i] === '}' && --$depth === 0) {
			return substr($source, $start, $i - $start + 1);
		}
	}
	throw new RuntimeException("unterminated {$name}");
}

/** Balanced-brace slice starting at the first '{' at/after $needle, through its match. */
function block_source(string $source, string $needle): string
{
	$start = strpos($source, $needle);
	if ($start === false) {
		throw new RuntimeException("missing block: {$needle}");
	}
	$open = strpos($source, '{', $start);
	if ($open === false) {
		throw new RuntimeException("missing block body: {$needle}");
	}
	$depth = 0;
	$length = strlen($source);
	for ($i = $open; $i < $length; $i++) {
		if ($source[$i] === '{') {
			$depth++;
		} elseif ($source[$i] === '}' && --$depth === 0) {
			return substr($source, $start, $i - $start + 1);
		}
	}
	throw new RuntimeException("unterminated block: {$needle}");
}

function rmdir_recursive_local(string $dir): void
{
	if (!is_dir($dir)) {
		return;
	}
	$items = scandir($dir);
	if ($items === false) {
		return;
	}
	foreach ($items as $item) {
		if ($item === '.' || $item === '..') {
			continue;
		}
		$path = "{$dir}/{$item}";
		if (is_dir($path) && !is_link($path)) {
			rmdir_recursive_local($path);
		} else {
			@unlink($path);
		}
	}
	@rmdir($dir);
}

$failures = 0;
$test_dirs = [];
function row(string $name, callable $test): void
{
	global $failures, $test_dirs;
	try {
		$test();
		echo "PASS {$name}\n";
	} catch (Throwable $error) {
		$failures++;
		echo "FAIL {$name}: {$error->getMessage()}\n";
	} finally {
		foreach ($test_dirs as $dir) {
			foreach (['daemon.pid', 'stuck.pid', 'launcher.pid', 'helper.pid'] as $marker) {
				$pid = (int) @file_get_contents("{$dir}/{$marker}");
				if ($pid > 0) {
					reapPid($pid);
				}
			}
			rmdir_recursive_local($dir);
		}
		$test_dirs = [];
	}
}

function check(bool $condition, string $message): void
{
	if (!$condition) {
		throw new RuntimeException($message);
	}
}

function same(mixed $expected, mixed $actual, string $message): void
{
	if ($expected !== $actual) {
		throw new RuntimeException($message . ' expected=' . var_export($expected, true) . ' actual=' . var_export($actual, true));
	}
}

function pidAlive(int $pid): bool
{
	return $pid > 0 && posix_kill($pid, 0);
}

function reapPid(int $pid): void
{
	if (!pidAlive($pid)) {
		return;
	}
	posix_kill($pid, 9);
	$deadline = microtime(true) + 2.0;
	while (pidAlive($pid) && microtime(true) < $deadline) {
		usleep(10000);
	}
}

$root = dirname(__DIR__, 2);
$inc_path = "{$root}/src/usr/local/pkg/pfblockerng/pfblockerng.inc";
$install_path = "{$root}/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc";
foreach ([$inc_path, $install_path] as $path) {
	if (!is_file($path)) {
		echo "FAIL missing source: {$path}\n";
		exit(1);
	}
}
$src = (string) file_get_contents($inc_path);
$install_src = (string) file_get_contents($install_path);

$timeout_bin = trim((string) shell_exec('command -v timeout 2>/dev/null'));
if ($timeout_bin === '') {
	echo "FAIL missing prerequisite: no 'timeout' binary on PATH\n";
	exit(1);
}

/** Standard behavioural-double block, shared by every isolated stop/start runner. */
const DOUBLES = <<<'PHP'
$GLOBALS['pfb_sigkillbypid_calls'] = [];
$GLOBALS['pfb_sigkillbyname_calls'] = [];
$GLOBALS['pfb_logger_calls'] = [];
function sigkillbypid($pidfile, $sig) {
	$GLOBALS['pfb_sigkillbypid_calls'][] = [$pidfile, $sig];
	$effect = $GLOBALS['pfb_sigkillbypid_effect'] ?? null;
	if (is_callable($effect)) { $effect($pidfile, $sig); }
}
function sigkillbyname($proc, $sig) {
	$GLOBALS['pfb_sigkillbyname_calls'][] = [$proc, $sig];
	$effect = $GLOBALS['pfb_sigkillbyname_effect'] ?? null;
	if (is_callable($effect)) { $effect($proc, $sig); }
}
function is_process_running($proc) {
	$v = $GLOBALS['pfb_process_running'][$proc] ?? false;
	return is_callable($v) ? (bool) $v() : (bool) $v;
}
function isvalidpid($pidfile) {
	return !empty($GLOBALS['pfb_valid_pids'][$pidfile]);
}
function pfb_logger($log, $type) {
	$GLOBALS['pfb_logger_calls'][] = $log;
	if (isset($GLOBALS['pfb']['log'])) { @file_put_contents($GLOBALS['pfb']['log'], $log, FILE_APPEND); }
	if ($type >= 2 && isset($GLOBALS['pfb']['errlog'])) { @file_put_contents($GLOBALS['pfb']['errlog'], $log, FILE_APPEND); }
}
function pfb_unbound_python_unmount() { $GLOBALS['pfb_unmount_calls'] = ($GLOBALS['pfb_unmount_calls'] ?? 0) + 1; }
function unlink_if_exists($p) { if (is_string($p) && $p !== '' && file_exists($p)) { @unlink($p); } }
PHP;

/**
 * Run $body (already-complete PHP statements) in an isolated subprocess that first
 * defines $constants, installs the shared DOUBLES, then eval-includes the extracted
 * production bodies named in $fns. The child always ends with one JSON line on stdout.
 * A salvage watchdog bounds the whole run; it only reaps a stuck child -- rows assert on
 * the decoded payload, never on wall-clock elapsed time.
 *
 * @param array<string,int|string> $constants
 * @param list<string> $fns
 * @return array{status:int, output:list<string>, payload:array<string,mixed>|null, dir:string}
 */
function run_isolated(string $src, array $constants, array $fns, string $body, int $salvage = 15, array $ini = []): array
{
	global $timeout_bin, $test_dirs;
	$dir = sys_get_temp_dir() . '/pfb3292_' . getmypid() . '_' . bin2hex(random_bytes(5));
	mkdir($dir, 0777, true);
	$test_dirs[] = $dir;
	$runner = "{$dir}/runner.php";

	$code = "<?php\n\$__dir = " . var_export($dir, true) . ";\n";
	foreach ($constants as $k => $v) {
		// {{DIR}} lets a constant (e.g. PFB_UNBOUND_START_CMD) reference this run's own
		// isolated directory even though it is only created here, after the caller built
		// the constants array -- e.g. a start-command marker file unique to this run.
		if (is_string($v)) {
			$v = str_replace('{{DIR}}', $dir, $v);
		}
		$code .= "if (!defined(" . var_export($k, true) . ")) { define(" . var_export($k, true) . ", " . var_export($v, true) . "); }\n";
	}
	$code .= DOUBLES . "\n";
	foreach ($fns as $fn) {
		// Historical releases call exec directly and do not define these new helpers.
		if (in_array($fn, ['pfb_unbound_control_cmd', 'pfb_unbound_control_exec'], true)
			&& !str_contains($src, "function {$fn}(")) {
			continue;
		}
		$code .= function_source($src, $fn) . "\n";
	}
	$code .= $body;
	file_put_contents($runner, $code);

	$flags = '';
	foreach ($ini as $setting) {
		$flags .= ' -d ' . escapeshellarg(str_replace('{{DIR}}', $dir, $setting));
	}
	$cmd = escapeshellarg($timeout_bin) . ' -k 2 ' . $salvage . ' '
		. escapeshellarg(PHP_BINARY) . $flags . ' ' . escapeshellarg($runner) . ' 2>&1';
	$output = [];
	$status = 0;
	exec($cmd, $output, $status);

	$payload = null;
	if ($output !== []) {
		$decoded = json_decode((string) end($output), true);
		$payload = is_array($decoded) ? $decoded : null;
	}
	if ($payload === null && in_array($status, [124, 137], true)) {
		$output[] = "STUCK/ENVIRONMENT: isolated runner exceeded its {$salvage}s salvage watchdog (exit {$status})";
	}
	return ['status' => $status, 'output' => $output, 'payload' => $payload, 'dir' => $dir];
}

function makeScript(string $dir, string $name, string $body): string
{
	$path = "{$dir}/{$name}";
	file_put_contents($path, "#!/bin/sh\n{$body}\n");
	chmod($path, 0755);
	return $path;
}

/** Standard fast budgets shared by every row that does not need a distinct value. */
function fastConstants(array $overrides = []): array
{
	return array_replace([
		'PFB_UNBOUND_STOP_FAILED'      => -2,
		'PFB_UNBOUND_STOP_WAIT'        => 1,
		'PFB_UNBOUND_KILL_WAIT'        => 1,
		'PFB_UNBOUND_START_WAIT'       => 2,
		'PFB_UNBOUND_START_SETUP_WAIT' => 2,
		'PFB_HOOK_KILL_GRACE'          => 1,
		'PFB_UNBOUND_CONTROL_WAIT'     => 2,
		'PFB_UNBOUND_START_CMD'        => 'true',
	], $overrides);
}

/** Runner-side prelude common to every pfb_stop_start_unbound() row. */
function stopStartPrelude(): string
{
	return <<<'PHP'
$dir = $__dir;
$GLOBALS['g'] = ['varrun_path' => $dir];
$GLOBALS['pfb'] = [
	'dnsbl_python_unmount' => false,
	'log' => "$dir/pfb.log",
	'errlog' => "$dir/pfb.err",
];
PHP;
}

echo "== issue #3292: bounded Unbound restart/recovery ==\n";

row('Row 1: healthy graceful stop/start retains existing behavior', function () use ($src) {
	$run = run_isolated($src, fastConstants(), ['pfb_stop_start_unbound'],
		stopStartPrelude() . <<<'PHP'
$pidfile = "$dir/unbound.pid";
file_put_contents($pidfile, "4242\n");
$GLOBALS['pfb_valid_pids'] = [$pidfile => true];
$GLOBALS['pfb_process_running']['unbound'] = true;
$GLOBALS['pfb_sigkillbypid_effect'] = function ($file, $sig) {
	if ($sig === 'TERM') { $GLOBALS['pfb_process_running']['unbound'] = false; }
};
$final = pfb_stop_start_unbound('');
echo json_encode([
	'final' => $final,
	'sigkillbypid_calls' => $GLOBALS['pfb_sigkillbypid_calls'],
	'sigkillbyname_calls' => $GLOBALS['pfb_sigkillbyname_calls'],
]) . "\n";
PHP
	);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	check(is_array($run['payload']), 'runner must emit JSON payload');
	$p = $run['payload'];
	same([[$run['dir'] . '/unbound.pid', 'TERM']], $p['sigkillbypid_calls'], 'a graceful stop must TERM the valid pidfile once');
	same([], $p['sigkillbyname_calls'], 'a graceful PID-targeted stop must never escalate to a name-based signal');
	same(true, $p['final']['start_completed'] ?? null, 'a healthy restart must complete');
	same(0, $p['final']['retval'] ?? null, 'a healthy restart must report success');
	rmdir_recursive_local($run['dir']);
});

row('Row 2: TERM-ignoring daemon exits after KILL -- exactly one fresh start', function () use ($src) {
	$run = run_isolated($src, fastConstants(), ['pfb_stop_start_unbound'],
		stopStartPrelude() . <<<'PHP'
$pidfile = "$dir/unbound.pid";
file_put_contents($pidfile, "4242\n");
$GLOBALS['pfb_valid_pids'] = [$pidfile => true];
$GLOBALS['pfb_process_running']['unbound'] = true;
$GLOBALS['pfb_sigkillbyname_effect'] = function ($name, $sig) {
	if ($name === 'unbound' && $sig === 'KILL') { $GLOBALS['pfb_process_running']['unbound'] = false; }
};
$final = pfb_stop_start_unbound('');
echo json_encode([
	'final' => $final,
	'sigkillbypid_calls' => $GLOBALS['pfb_sigkillbypid_calls'],
	'sigkillbyname_calls' => $GLOBALS['pfb_sigkillbyname_calls'],
]) . "\n";
PHP
	);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	same([[$run['dir'] . '/unbound.pid', 'TERM']], $p['sigkillbypid_calls'], 'the PID must still get TERM first, even though it is ignored');
	same([['unbound', 'KILL']], $p['sigkillbyname_calls'], 'a TERM-ignoring daemon must escalate to exactly one name-based KILL');
	same(true, $p['final']['start_completed'] ?? null, 'the daemon dying on KILL must still allow exactly one completed start');
	same(0, $p['final']['retval'] ?? null, 'the post-KILL start must run through the true double');
	rmdir_recursive_local($run['dir']);
});

row('Row 3a: daemon survives TERM and KILL -- refuses a second start, never runs it', function () use ($src) {
	$run = run_isolated($src, fastConstants(['PFB_UNBOUND_START_CMD' => 'touch {{DIR}}/start-ran']),
		['pfb_stop_start_unbound'],
		stopStartPrelude() . <<<'PHP'
$GLOBALS['pfb_process_running']['unbound'] = true; // never dies, TERM or KILL
$final = pfb_stop_start_unbound('');
echo json_encode([
	'final' => $final,
	'sigkillbyname_calls' => $GLOBALS['pfb_sigkillbyname_calls'],
	'start_ran' => file_exists("$dir/start-ran"),
]) . "\n";
PHP
	);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	same([['unbound', 'TERM'], ['unbound', 'KILL']], $p['sigkillbyname_calls'], 'a live-forever daemon must get TERM then KILL exactly once each');
	same(-2, $p['final']['retval'] ?? null, 'a refusal must report PFB_UNBOUND_STOP_FAILED, not a generic -1 shared with config failure');
	same(false, $p['final']['start_completed'] ?? null, 'a refused stop must never reach a completed start');
	same(false, $p['start_ran'] ?? null, 'the configured start command must never execute while the old daemon survives');
	rmdir_recursive_local($run['dir']);
});

row('Row 3b: a stop refusal reaching pfb_reload_unbound preserves config -- no quarantine, no rollback, no retry', function () use ($src, $timeout_bin) {
	$run = run_isolated($src, fastConstants(['PFB_UNBOUND_START_CMD' => 'touch {{DIR}}/start-ran']),
		['pfb_stop_start_unbound', 'pfb_reload_unbound', 'pfb_unbound_control_cmd', 'pfb_unbound_control_exec'],
		stopStartPrelude() . "\$GLOBALS['pfb']['timeout'] = " . var_export($timeout_bin, true) . ";\n" . <<<'PHP'
$GLOBALS['pfb']['dnsbldir'] = $dir;
$GLOBALS['pfb']['dnsbl_file'] = "$dir/dnsbl";
$GLOBALS['pfb']['dnsbl_py_blacklist'] = false;
$GLOBALS['pfb']['dnsbl_res_cache'] = 'off';
$GLOBALS['pfb']['chroot_cmd'] = '/bin/true';
file_put_contents("$dir/unbound.conf", "NEW-UNBOUND\n");
file_put_contents("$dir/unbound.bk", "OLD-UNBOUND\n");
$GLOBALS['pfb_process_running']['unbound'] = true; // never dies
pfb_reload_unbound('enabled', false, false);
echo json_encode([
	'conf' => trim((string) @file_get_contents("$dir/unbound.conf")),
	'error_exists' => file_exists("$dir/unbound.conf.error"),
	'bk_exists' => file_exists("$dir/unbound.bk"),
	'sigkillbyname_calls' => $GLOBALS['pfb_sigkillbyname_calls'],
	'start_ran' => file_exists("$dir/start-ran"),
	'log' => (string) @file_get_contents($GLOBALS['pfb']['log']),
]) . "\n";
PHP
	);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	same('NEW-UNBOUND', $p['conf'] ?? null, 'a stop refusal must leave the valid config untouched');
	same(false, $p['error_exists'] ?? null, 'a stop refusal must never quarantine the config as broken');
	same(true, $p['bk_exists'] ?? null, 'a stop refusal must never consume the backup');
	same([['unbound', 'TERM'], ['unbound', 'KILL']], $p['sigkillbyname_calls'], 'the refusal must not be retried -- exactly one TERM/KILL pair total');
	same(false, $p['start_ran'] ?? null, 'a stop refusal must never let the configured start command run, even if the refusal handling regresses');
	check(str_contains((string) $p['log'], 'could not be stopped'), 'the refusal must be named in the log');
	check(!str_contains((string) $p['log'], 'Fix error(s)'), 'a stop refusal must never be reported as a fixable config error');
	rmdir_recursive_local($run['dir']);
});

/** Exercise reload recovery through real startup/supervisor failures. */
function reloadIncompleteStartRun(string $src, string $mode, bool $pyBlacklist, array $constantOverrides,
	?string $phpCli = null, array $ini = []): array
{
	global $timeout_bin;
	$py_bool = $pyBlacklist ? 'true' : 'false';
	$prelude = stopStartPrelude()
		. "\$GLOBALS['pfb']['timeout'] = " . var_export($timeout_bin, true) . ";\n";
	if ($phpCli !== null) {
		$prelude .= "\$GLOBALS['pfb']['php'] = str_replace('{{DIR}}', \$dir, "
			. var_export($phpCli, true) . ");\n";
	}
	return run_isolated($src, fastConstants($constantOverrides),
		['pfb_stop_start_unbound', 'pfb_reload_unbound', 'pfb_unbound_control_cmd', 'pfb_unbound_control_exec'],
		$prelude . <<<PHP
\$GLOBALS['pfb']['dnsbldir'] = \$dir;
\$GLOBALS['pfb']['dnsbl_file'] = "\$dir/dnsbl";
\$GLOBALS['pfb']['dnsbl_py_blacklist'] = {$py_bool};
\$GLOBALS['pfb']['dnsbl_res_cache'] = 'off';
\$GLOBALS['pfb']['chroot_cmd'] = "\$dir/should-not-run.sh";
file_put_contents("\$dir/should-not-run.sh", "#!/bin/sh\\ntouch '\$dir/status-ran'\\nprintf 'is running...'\\n");
chmod("\$dir/should-not-run.sh", 0755);
file_put_contents("\$dir/unbound.conf", "NEW-UNBOUND\\n");
file_put_contents("\$dir/unbound.bk", "OLD-UNBOUND\\n");
file_put_contents("\$dir/dnsbl.conf", "NEW-DNSBL\\n");
file_put_contents("\$dir/dnsbl.bk", "OLD-DNSBL\\n");
\$GLOBALS['pfb_process_running']['unbound'] = false;
pfb_reload_unbound('{$mode}', false, false);
\$attempts = file_exists("\$dir/start-attempts.log") ? (file("\$dir/start-attempts.log", FILE_IGNORE_NEW_LINES) ?: []) : [];
echo json_encode([
	'unbound_conf' => trim((string) @file_get_contents("\$dir/unbound.conf")),
	'unbound_bk_exists' => file_exists("\$dir/unbound.bk"),
	'unbound_error_exists' => file_exists("\$dir/unbound.conf.error"),
	'dnsbl_conf' => trim((string) @file_get_contents("\$dir/dnsbl.conf")),
	'dnsbl_bk_exists' => file_exists("\$dir/dnsbl.bk"),
	'status_ran' => file_exists("\$dir/status-ran"),
	'start_attempts' => \$attempts,
	'stuck_pid' => (int) trim((string) @file_get_contents("\$dir/stuck.pid")),
	'log' => (string) @file_get_contents(\$GLOBALS['pfb']['log']),
]) . "\\n";
PHP
		, 20, $ini);
}

row('Row 3c: a real startup expiry reaching pfb_reload_unbound preserves config -- enabled, Python mode', function () use ($src) {
	$run = reloadIncompleteStartRun($src, 'enabled', true, [
		'PFB_UNBOUND_START_CMD' => "sh -c 'printf %s \$\$ > {{DIR}}/stuck.pid; echo x >> {{DIR}}/start-attempts.log; trap '\"'\"''\"'\"' TERM; exec sleep 30'",
		'PFB_UNBOUND_START_WAIT' => 1,
	]);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	same('NEW-UNBOUND', $p['unbound_conf'] ?? null, 'a real startup expiry must never trigger the python-mode unbound.conf restore');
	same(true, $p['unbound_bk_exists'] ?? null, 'the backup must never be consumed by an infrastructure failure');
	same(false, $p['unbound_error_exists'] ?? null, 'an expired start must never be quarantined as a config error');
	same(1, count($p['start_attempts'] ?? []), 'an expired start must never be retried');
	same(false, $p['status_ran'] ?? null, 'an expired start must never reach the status confirm step');
	check(!str_contains((string) $p['log'], 'Fix error(s)'), 'an expired start must never be reported as a fixable config error');
	$pid = (int) ($p['stuck_pid'] ?? 0);
	if ($pid > 0 && pidAlive($pid)) {
		reapPid($pid);
		throw new RuntimeException('the SIGKILL grace must leave no TERM-ignoring start process behind');
	}
	rmdir_recursive_local($run['dir']);
});

row('Row 3d: a real startup expiry reaching pfb_reload_unbound preserves config -- enabled, non-Python mode', function () use ($src) {
	$run = reloadIncompleteStartRun($src, 'enabled', false, [
		'PFB_UNBOUND_START_CMD' => "sh -c 'printf %s \$\$ > {{DIR}}/stuck.pid; echo x >> {{DIR}}/start-attempts.log; trap '\"'\"''\"'\"' TERM; exec sleep 30'",
		'PFB_UNBOUND_START_WAIT' => 1,
	]);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	same('NEW-DNSBL', $p['dnsbl_conf'] ?? null, 'a real startup expiry must never trigger the non-python-mode dnsbl_file restore');
	same(true, $p['dnsbl_bk_exists'] ?? null, 'the DNSBL backup must never be consumed by an infrastructure failure');
	same('NEW-UNBOUND', $p['unbound_conf'] ?? null, 'unbound.conf must stay untouched in non-python mode too');
	same(false, $p['unbound_error_exists'] ?? null, 'an expired start must never be quarantined as a config error');
	same(1, count($p['start_attempts'] ?? []), 'an expired start must never be retried');
	$pid = (int) ($p['stuck_pid'] ?? 0);
	if ($pid > 0 && pidAlive($pid)) {
		reapPid($pid);
		throw new RuntimeException('the SIGKILL grace must leave no TERM-ignoring start process behind');
	}
	rmdir_recursive_local($run['dir']);
});

row('Row 3e: a real startup expiry reaching pfb_reload_unbound preserves config -- disabled mode', function () use ($src) {
	$run = reloadIncompleteStartRun($src, 'disabled', false, [
		'PFB_UNBOUND_START_CMD' => "sh -c 'printf %s \$\$ > {{DIR}}/stuck.pid; echo x >> {{DIR}}/start-attempts.log; trap '\"'\"''\"'\"' TERM; exec sleep 30'",
		'PFB_UNBOUND_START_WAIT' => 1,
	]);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	same('NEW-UNBOUND', $p['unbound_conf'] ?? null, 'disabled mode must never restore unbound.conf on an infrastructure failure');
	same(true, $p['unbound_bk_exists'] ?? null, 'disabled mode must never consume the backup on an infrastructure failure');
	same(false, $p['unbound_error_exists'] ?? null,
		'unlike a genuine completed config failure (Row 7c), an expired start must never be quarantined as .error, even in disabled mode');
	same(1, count($p['start_attempts'] ?? []), 'an expired start must never be retried');
	$pid = (int) ($p['stuck_pid'] ?? 0);
	if ($pid > 0 && pidAlive($pid)) {
		reapPid($pid);
		throw new RuntimeException('the SIGKILL grace must leave no TERM-ignoring start process behind');
	}
	rmdir_recursive_local($run['dir']);
});

row('Row 3f: a completed exit-124 start reaching pfb_reload_unbound is conservatively preserved without retry', function () use ($src) {
	$run = reloadIncompleteStartRun($src, 'enabled', true, [
		'PFB_UNBOUND_START_CMD' => 'sh -c "echo x >> {{DIR}}/start-attempts.log; exit 124"',
	]);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	same('NEW-UNBOUND', $p['unbound_conf'] ?? null,
		'a start that itself completes with exit 124 (not killed) must be conservatively treated like an expiry, never a genuine config error');
	same(true, $p['unbound_bk_exists'] ?? null, 'the backup must never be consumed by a completed-124 outcome');
	same(false, $p['unbound_error_exists'] ?? null, 'a completed-124 outcome must never be quarantined as .error');
	same(1, count($p['start_attempts'] ?? []), 'a completed-124 outcome must never be retried');
	rmdir_recursive_local($run['dir']);
});

foreach (['missing-launcher' => '{{DIR}}/missing-php', 'setup-failure' => '/bin/false',
	'incomplete-success' => '/bin/true', 'staging-failure' => null] as $failure => $phpCli) {
	row("Row 3g: {$failure} preserves configuration without retry or confirmation", function () use ($src, $failure, $phpCli) {
		$run = reloadIncompleteStartRun($src, 'enabled', true, [
			'PFB_UNBOUND_START_CMD' => 'echo x >> {{DIR}}/start-attempts.log',
		], $phpCli, $failure === 'staging-failure' ? ['sys_temp_dir={{DIR}}/missing-temp'] : []);
		check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
		$p = $run['payload'];
		same('NEW-UNBOUND', $p['unbound_conf'] ?? null, 'incomplete startup must not roll back valid configuration');
		same(true, $p['unbound_bk_exists'] ?? null, 'incomplete startup must preserve the backup');
		same(false, $p['unbound_error_exists'] ?? null, 'incomplete startup must not quarantine configuration');
		same([], $p['start_attempts'] ?? null, 'failed supervisor setup must not execute the start command');
		same(false, $p['status_ran'] ?? null, 'incomplete startup must not attempt confirmation');
		check(!str_contains((string) $p['log'], 'Fix error(s)'), 'infrastructure failure must not be blamed on configuration');
		check(str_contains((string) $p['log'], 'Not completed'), 'incomplete startup must not report success');
	});
}

row('Row 4a: a missing pidfile falls back to name-based TERM before any escalation', function () use ($src) {
	$run = run_isolated($src, fastConstants(), ['pfb_stop_start_unbound'],
		stopStartPrelude() . <<<'PHP'
// No pidfile written at all.
$GLOBALS['pfb_process_running']['unbound'] = true;
$GLOBALS['pfb_sigkillbyname_effect'] = function ($name, $sig) {
	if ($name === 'unbound' && $sig === 'TERM') { $GLOBALS['pfb_process_running']['unbound'] = false; }
};
$final = pfb_stop_start_unbound('');
echo json_encode([
	'final' => $final,
	'sigkillbypid_calls' => $GLOBALS['pfb_sigkillbypid_calls'],
	'sigkillbyname_calls' => $GLOBALS['pfb_sigkillbyname_calls'],
]) . "\n";
PHP
	);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	same([], $p['sigkillbypid_calls'], 'a missing pidfile must never be trusted as a PID signal target');
	same([['unbound', 'TERM']], $p['sigkillbyname_calls'], 'a live daemon with no pidfile must receive name-based TERM before any KILL');
	same(true, $p['final']['start_completed'] ?? null, 'the daemon exiting on name-based TERM must proceed to a completed start');
	rmdir_recursive_local($run['dir']);
});

row('Row 4b: a stale (invalid) pidfile also falls back to name-based TERM, never PID-targeted', function () use ($src) {
	$run = run_isolated($src, fastConstants(), ['pfb_stop_start_unbound'],
		stopStartPrelude() . <<<'PHP'
$pidfile = "$dir/unbound.pid";
file_put_contents($pidfile, "stale-not-a-pid\n");
$GLOBALS['pfb_valid_pids'] = [$pidfile => false]; // isvalidpid() says NO
$GLOBALS['pfb_process_running']['unbound'] = true;
$GLOBALS['pfb_sigkillbyname_effect'] = function ($name, $sig) {
	if ($name === 'unbound' && $sig === 'TERM') { $GLOBALS['pfb_process_running']['unbound'] = false; }
};
$final = pfb_stop_start_unbound('');
echo json_encode([
	'final' => $final,
	'sigkillbypid_calls' => $GLOBALS['pfb_sigkillbypid_calls'],
	'sigkillbyname_calls' => $GLOBALS['pfb_sigkillbyname_calls'],
]) . "\n";
PHP
	);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	same([], $p['sigkillbypid_calls'], 'an invalid/stale pidfile must never be trusted as a PID signal target');
	same([['unbound', 'TERM']], $p['sigkillbyname_calls'], 'a stale pidfile with a live daemon must fall back to name-based TERM');
	same(true, $p['final']['start_completed'] ?? null, 'the daemon exiting on name-based TERM must proceed to a completed start');
	rmdir_recursive_local($run['dir']);
});

row('Row 5a: output-staging failure is a finite, incomplete failure -- start command never runs', function () use ($src) {
	$run = run_isolated($src,
		fastConstants(['PFB_UNBOUND_START_CMD' => 'touch {{DIR}}/start-ran']),
		['pfb_stop_start_unbound'],
		stopStartPrelude() . <<<'PHP'
$GLOBALS['pfb_process_running']['unbound'] = false;
$final = pfb_stop_start_unbound('');
echo json_encode(['final' => $final, 'start_ran' => file_exists("$dir/start-ran")]) . "\n";
PHP
		, 15, ['sys_temp_dir=' . '{{DIR}}/no-such-temp-dir']
	);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	same(-1, $p['final']['retval'] ?? null, 'an output-staging failure must report a distinct failure code');
	same(false, $p['final']['start_completed'] ?? null, 'an output-staging failure must never look like a completed start');
	same(false, $p['start_ran'] ?? null, 'staging must fail BEFORE the configured start command ever runs');
	rmdir_recursive_local($run['dir']);
});

row('Row 5b: a TERM-ignoring start command expires finitely and leaves no process behind', function () use ($src) {
	$run = run_isolated($src, fastConstants([
			'PFB_UNBOUND_START_CMD' => "sh -c 'printf %s \$\$ > {{DIR}}/stuck.pid; trap '\"'\"''\"'\"' TERM; exec sleep 30'",
			'PFB_UNBOUND_START_WAIT' => 1,
		]),
		['pfb_stop_start_unbound'],
		stopStartPrelude() . <<<'PHP'
$GLOBALS['pfb_process_running']['unbound'] = false;
$final = pfb_stop_start_unbound('');
$pid = (int) trim((string) @file_get_contents("$dir/stuck.pid"));
echo json_encode(['final' => $final, 'pid' => $pid, 'log' => (string) @file_get_contents($GLOBALS['pfb']['log'])]) . "\n";
PHP
	, 15
	);
	check($run['status'] === 0, 'isolated runner must exit cleanly (RED issue #3292: the wait must not be unbounded): ' . implode("\n", $run['output']));
	$p = $run['payload'];
	same(124, $p['final']['retval'] ?? null, 'an expired start must retain status 124');
	same(false, $p['final']['start_completed'] ?? null, 'a command killed at its deadline must never produce a valid completion record');
	check(str_contains((string) $p['log'], 'TIMED OUT'), 'expiry must be explicit in the log');
	$pid = (int) ($p['pid'] ?? 0);
	if ($pid > 0 && pidAlive($pid)) {
		reapPid($pid);
		throw new RuntimeException('the SIGKILL grace must leave no TERM-ignoring start process behind');
	}
	rmdir_recursive_local($run['dir']);
});

row('Row 6a: a successfully daemonized start detaches and survives the bounded wrapper', function () use ($src) {
	$daemon_code = '$sid = posix_setsid(); if ($sid === -1) { exit(126); } '
		. 'file_put_contents($argv[1], (string) getmypid()); sleep(30);';
	// A shell wrapper backgrounds the daemonizing php -r process and exits as soon as
	// its pidfile appears -- the ONLY way to prove the daemon truly detaches (survives
	// past the configured command's own exit), matching docs/misc/external-process-waits.md
	// "Mixed survivor + transient tree". Built with escapeshellarg() at each layer so the
	// {{DIR}} token (substituted on the whole constant value later) survives intact.
	$inner = PHP_BINARY . ' -r ' . escapeshellarg($daemon_code) . ' {{DIR}}/daemon.pid';
	$wrapper = $inner . ' </dev/null >/dev/null 2>&1 &' . "\n"
		. 'i=0; while [ ! -s {{DIR}}/daemon.pid ] && [ "$i" -lt 300 ]; do i=$((i + 1)); sleep 0.01; done' . "\n"
		. '[ -s {{DIR}}/daemon.pid ] || exit 126' . "\n"
		. 'exit 0';
	$start_cmd = 'sh -c ' . escapeshellarg($wrapper);

	$run = run_isolated($src, fastConstants(['PFB_UNBOUND_START_CMD' => $start_cmd]),
		['pfb_stop_start_unbound'],
		stopStartPrelude() . <<<'PHP'
$GLOBALS['pfb_process_running']['unbound'] = false;
$final = pfb_stop_start_unbound('');
$pid = (int) trim((string) @file_get_contents("$dir/daemon.pid"));
echo json_encode(['final' => $final, 'pid' => $pid]) . "\n";
PHP
	);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	$pid = (int) ($p['pid'] ?? 0);
	try {
		same(0, $p['final']['retval'] ?? null, 'a successfully daemonized start must remain a successful start');
		same(true, $p['final']['start_completed'] ?? null, 'the successful daemon start must carry a validated completion record');
		check($pid > 0, 'the row must observe the daemon pid before evaluating survival');
		check(pidAlive($pid), 'a successfully daemonized resolver must escape the supervised launcher group and survive');
	} finally {
		if ($pid > 0) {
			reapPid($pid);
		}
	}
	rmdir_recursive_local($run['dir']);
});

row('Row 6b: a TERM-ignoring launcher and its helper are both reaped on expiry', function () use ($src) {
	$run = run_isolated($src, fastConstants([
			'PFB_UNBOUND_START_CMD' => "sh -c 'trap '\"'\"''\"'\"' TERM; printf %s \$\$ > {{DIR}}/launcher.pid; "
				. "(trap '\"'\"''\"'\"' TERM; exec sleep 30) & echo \$! > {{DIR}}/helper.pid; wait'",
			'PFB_UNBOUND_START_WAIT' => 1,
		]),
		['pfb_stop_start_unbound'],
		stopStartPrelude() . <<<'PHP'
$GLOBALS['pfb_process_running']['unbound'] = false;
$final = pfb_stop_start_unbound('');
$launcher = (int) trim((string) @file_get_contents("$dir/launcher.pid"));
$helper = (int) trim((string) @file_get_contents("$dir/helper.pid"));
echo json_encode(['final' => $final, 'launcher' => $launcher, 'helper' => $helper]) . "\n";
PHP
	);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	same(124, $p['final']['retval'] ?? null, 'the process-tree expiry must preserve the distinguished timeout status');
	$launcher = (int) ($p['launcher'] ?? 0);
	$helper = (int) ($p['helper'] ?? 0);
	check($launcher > 0 && $helper > 0, 'the row must observe both the launcher and its helper before evaluating cleanup');
	$launcherAlive = pidAlive($launcher);
	$helperAlive = pidAlive($helper);
	if ($launcherAlive) { reapPid($launcher); }
	if ($helperAlive) { reapPid($helper); }
	check(!$launcherAlive, 'the TERM-ignoring launcher must be gone after the kill grace');
	check(!$helperAlive, 'expiry must kill the launcher process GROUP, not orphan its TERM-ignoring helper');
	rmdir_recursive_local($run['dir']);
});

function reloadCauseAwareRun(string $src, string $mode, bool $pyBlacklist): array
{
	$py_bool = $pyBlacklist ? 'true' : 'false';
	return run_isolated($src, fastConstants(['PFB_UNBOUND_START_CMD' => 'sh -c "echo bad-config-line; exit 7"']),
		['pfb_stop_start_unbound', 'pfb_reload_unbound'],
		stopStartPrelude() . <<<PHP
\$GLOBALS['pfb']['dnsbldir'] = \$dir;
\$GLOBALS['pfb']['dnsbl_file'] = "\$dir/dnsbl";
\$GLOBALS['pfb']['dnsbl_py_blacklist'] = {$py_bool};
\$GLOBALS['pfb']['dnsbl_res_cache'] = 'off';
\$GLOBALS['pfb']['chroot_cmd'] = '/bin/true';
file_put_contents("\$dir/unbound.conf", "NEW-UNBOUND\\n");
file_put_contents("\$dir/unbound.bk", "OLD-UNBOUND\\n");
file_put_contents("\$dir/dnsbl.conf", "NEW-DNSBL\\n");
file_put_contents("\$dir/dnsbl.bk", "OLD-DNSBL\\n");
\$GLOBALS['pfb_process_running']['unbound'] = false;
pfb_reload_unbound('{$mode}', false, false);
echo json_encode([
	'unbound_conf' => trim((string) @file_get_contents("\$dir/unbound.conf")),
	'unbound_bk_exists' => file_exists("\$dir/unbound.bk"),
	'unbound_error_exists' => file_exists("\$dir/unbound.conf.error"),
	'dnsbl_conf' => trim((string) @file_get_contents("\$dir/dnsbl.conf")),
	'dnsbl_bk_exists' => file_exists("\$dir/dnsbl.bk"),
	'log' => (string) @file_get_contents(\$GLOBALS['pfb']['log']),
]) . "\\n";
PHP
	);
}

row('Row 7a: a completed genuine config-error start retries legacy rollback -- enabled, Python mode', function () use ($src) {
	$run = reloadCauseAwareRun($src, 'enabled', true);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	same('OLD-UNBOUND', $p['unbound_conf'] ?? null, 'a genuine completed config failure in python mode must restore unbound.bk over unbound.conf');
	same(false, $p['unbound_bk_exists'] ?? null, 'the backup must be consumed by the restore');
	same(true, $p['unbound_error_exists'] ?? null, 'the bad config must be quarantined as .error');
	check(str_contains((string) $p['log'], 'Fix error(s)'), 'a genuine config failure must still tell the operator to fix it');
});

row('Row 7b: a completed genuine config-error start retries legacy rollback -- enabled, non-Python mode', function () use ($src) {
	$run = reloadCauseAwareRun($src, 'enabled', false);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	same('OLD-DNSBL', $p['dnsbl_conf'] ?? null, 'non-python mode restores dnsbl_file.bk over dnsbl_file.conf, not unbound.conf');
	same(false, $p['dnsbl_bk_exists'] ?? null, 'the DNSBL backup must be consumed by the restore');
	same('NEW-UNBOUND', $p['unbound_conf'] ?? null, 'non-python mode restores the DNSBL list, not unbound.conf itself, when dnsbl_file.bk exists');
	same(true, $p['unbound_bk_exists'] ?? null, 'unbound.bk must stay untouched when the dnsbl_file.bk fallback already ran');
	same(true, $p['unbound_error_exists'] ?? null, 'the bad config is still quarantined as .error');
	check(str_contains((string) $p['log'], 'Fix error(s)'), 'a genuine config failure must still tell the operator to fix it');
});

row('Row 7c: a completed genuine config-error start quarantines but does not restore -- disabled mode', function () use ($src) {
	$run = reloadCauseAwareRun($src, 'disabled', false);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	same('NEW-UNBOUND', $p['unbound_conf'] ?? null, 'a disabled-mode failure must not restore unbound.bk -- legacy behavior preserved verbatim');
	same(true, $p['unbound_bk_exists'] ?? null, 'a disabled-mode failure must not consume the backup');
	same(true, $p['unbound_error_exists'] ?? null, 'the failed config is still quarantined as .error, matching legacy behavior');
	check(str_contains((string) $p['log'], 'Fix error(s)'), 'the operator must still be told to fix and re-run');
});

row('Row 8a: a failed/incomplete start can never produce completion -- status is never attempted', function () use ($src, $timeout_bin) {
	$run = run_isolated($src, fastConstants(),
		['pfb_stop_start_unbound', 'pfb_reload_unbound', 'pfb_unbound_control_cmd', 'pfb_unbound_control_exec'],
		stopStartPrelude() . "\$GLOBALS['pfb']['timeout'] = " . var_export($timeout_bin, true) . ";\n" . <<<'PHP'
$GLOBALS['pfb']['dnsbldir'] = $dir;
$GLOBALS['pfb']['dnsbl_file'] = "$dir/dnsbl";
$GLOBALS['pfb']['dnsbl_py_blacklist'] = false;
$GLOBALS['pfb']['dnsbl_res_cache'] = 'off';
$GLOBALS['pfb']['chroot_cmd'] = "$dir/should-not-run.sh";
file_put_contents("$dir/should-not-run.sh", "#!/bin/sh\ntouch \"$dir/status-ran\"\nprintf 'is running...'\n");
chmod("$dir/should-not-run.sh", 0755);
file_put_contents("$dir/unbound.conf", "NEW\n");
$GLOBALS['pfb_process_running']['unbound'] = true; // never stops -> stop refusal, start never runs
pfb_reload_unbound('enabled', false, false);
echo json_encode(['status_ran' => file_exists("$dir/status-ran"), 'log' => (string) @file_get_contents($GLOBALS['pfb']['log'])]) . "\n";
PHP
	);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	same(false, $p['status_ran'] ?? null, 'a failed/refused start must never reach the status confirm step');
	check(str_contains((string) $p['log'], 'Not completed'), 'a failed start must report not completed');
	rmdir_recursive_local($run['dir']);
});

row('Row 8b: a healthy start whose status check times out is reported not-completed', function () use ($src, $timeout_bin) {
	$run = run_isolated($src, fastConstants(),
		['pfb_stop_start_unbound', 'pfb_unbound_control_cmd', 'pfb_unbound_control_exec', 'pfb_reload_unbound'],
		stopStartPrelude() . "\$GLOBALS['pfb']['timeout'] = " . var_export($timeout_bin, true) . ";\n" . <<<'PHP'
$pidfile = "$dir/unbound.pid";
file_put_contents($pidfile, "4242\n");
$GLOBALS['pfb_valid_pids'] = [$pidfile => true];
$GLOBALS['pfb']['dnsbldir'] = $dir;
$GLOBALS['pfb']['dnsbl_file'] = "$dir/dnsbl";
$GLOBALS['pfb']['dnsbl_py_blacklist'] = false;
$GLOBALS['pfb']['dnsbl_res_cache'] = 'off';
$GLOBALS['pfb']['chroot_cmd'] = 'sh -c \'trap "" TERM; exec sleep 30\'';
file_put_contents("$dir/unbound.conf", "NEW\n");
$GLOBALS['pfb_pr_calls'] = 0;
// Verified call sequence (probed against production): #1 pre-stop gate, #2/#3 stop-wait
// loop + post-loop escalation check, #4 the post-start confirm gate.
$GLOBALS['pfb_process_running']['unbound'] = function () {
	$c = ++$GLOBALS['pfb_pr_calls'];
	return ($c === 1 || $c >= 4);
};
pfb_reload_unbound('enabled', false, false);
echo json_encode(['log' => (string) @file_get_contents($GLOBALS['pfb']['log']), 'status_result' => $GLOBALS['pfb_logger_calls']]) . "\n";
PHP
	);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	check(!str_contains((string) $p['log'], 'completed [ NOW ]'), 'a timed-out status must never report completion');
	check(str_contains((string) $p['log'], 'Not completed'), 'a timed-out status must be reported not completed');
	// GNU timeout reports 137 for KILL escalation where FreeBSD reports 124.
	// Either outcome must leave the resolver unconfirmed.
	check(!str_contains(implode('', $p['status_result'] ?? []), 'is running...'),
		'a killed status command must never leave a false "is running..." marker for the caller to read as success');
	rmdir_recursive_local($run['dir']);
});

/** Shared body for every Row 9 (cache dump/status/load) sub-case. */
function row9Body(string $dumpBody, string $statusBody, string $loadBody, bool $cacheOn = true): string
{
	$cacheOnPhp = $cacheOn ? "'on'" : "'off'";
	// Built with var_export(), not runtime PHP string interpolation: $dumpBody/etc. are
	// arbitrary shell snippets that may contain double quotes (e.g. `trap "" TERM`), and
	// var_export() is the only construction here immune to breaking out of the
	// surrounding PHP string literal.
	$scriptTemplate = "#!/bin/sh\n"
		. "echo \"\$1\" >> \"{{RUNDIR}}/calls.log\"\n"
		. "case \"\$1\" in\n"
		. "  dump_cache) {$dumpBody};;\n"
		. "  status) {$statusBody};;\n"
		. "  load_cache) {$loadBody};;\n"
		. "esac\n";
	$scriptExport = var_export($scriptTemplate, true);
	return <<<PHP
\$pidfile = "\$dir/unbound.pid";
file_put_contents(\$pidfile, "4242\\n");
\$GLOBALS['pfb_valid_pids'] = [\$pidfile => true];
\$GLOBALS['pfb']['dnsbldir'] = \$dir;
\$GLOBALS['pfb']['dnsbl_file'] = "\$dir/dnsbl";
\$GLOBALS['pfb']['dnsbl_py_blacklist'] = false;
\$GLOBALS['pfb']['dnsbl_res_cache'] = {$cacheOnPhp};
\$script = str_replace('{{RUNDIR}}', \$dir, {$scriptExport});
file_put_contents("\$dir/control.sh", \$script);
chmod("\$dir/control.sh", 0755);
\$GLOBALS['pfb']['chroot_cmd'] = "\$dir/control.sh";
file_put_contents("\$dir/unbound.conf", "NEW\\n");
\$GLOBALS['pfb_pr_calls'] = 0;
\$GLOBALS['pfb_process_running']['unbound'] = function () {
	\$c = ++\$GLOBALS['pfb_pr_calls'];
	return (\$c === 1 || \$c >= 4);
};
pfb_reload_unbound('enabled', true, false);
\$calls = file_exists("\$dir/calls.log") ? (file("\$dir/calls.log", FILE_IGNORE_NEW_LINES) ?: []) : [];
echo json_encode(['calls' => \$calls, 'log' => (string) @file_get_contents(\$GLOBALS['pfb']['log'])]) . "\\n";
PHP;
}

row('Row 9a: cache disabled -- dump_cache and load_cache are never invoked', function () use ($src, $timeout_bin) {
	$run = run_isolated($src, fastConstants(),
		['pfb_stop_start_unbound', 'pfb_unbound_control_cmd', 'pfb_unbound_control_exec', 'pfb_reload_unbound'],
		stopStartPrelude() . "\$GLOBALS['pfb']['timeout'] = " . var_export($timeout_bin, true) . ";\n"
			. row9Body('exit 0', "printf 'is running...'; exit 0", 'cat >/dev/null; exit 0', false)
	);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	$calls = $p['calls'] ?? [];
	check(!in_array('dump_cache', $calls, true), 'cache disabled must never invoke dump_cache');
	check(in_array('status', $calls, true), 'the resolver must still confirm status regardless of cache setting');
	check(!in_array('load_cache', $calls, true), 'cache disabled must never invoke load_cache');
	check(!str_contains((string) $p['log'], 'Resolver cache restored'), 'no restore message can appear without a dump');
	rmdir_recursive_local($run['dir']);
});

row('Row 9b: a failed dump_cache is discarded -- load_cache is never invoked on a truncated dump', function () use ($src, $timeout_bin) {
	$run = run_isolated($src, fastConstants(),
		['pfb_stop_start_unbound', 'pfb_unbound_control_cmd', 'pfb_unbound_control_exec', 'pfb_reload_unbound'],
		stopStartPrelude() . "\$GLOBALS['pfb']['timeout'] = " . var_export($timeout_bin, true) . ";\n"
			. row9Body('echo dump-broke; exit 1', "printf 'is running...'; exit 0", 'cat >/dev/null; exit 0')
	);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	$calls = $p['calls'] ?? [];
	same(['dump_cache', 'status'], $calls, 'a failed dump must still let status run, but must never reach load_cache');
	check(str_contains((string) $p['log'], '[ dump_cache ] FAILED'), 'a failed dump must be named truthfully');
	check(!str_contains((string) $p['log'], 'Resolver cache restored'), 'a discarded/truncated dump must never be reported restored');
	rmdir_recursive_local($run['dir']);
});

row('Row 9c: a successful dump whose load_cache fails is never reported restored', function () use ($src, $timeout_bin) {
	$run = run_isolated($src, fastConstants(),
		['pfb_stop_start_unbound', 'pfb_unbound_control_cmd', 'pfb_unbound_control_exec', 'pfb_reload_unbound'],
		stopStartPrelude() . "\$GLOBALS['pfb']['timeout'] = " . var_export($timeout_bin, true) . ";\n"
			. row9Body("printf 'DUMP-CONTENT'; exit 0", "printf 'is running...'; exit 0", 'cat >/dev/null; exit 1')
	);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	$calls = $p['calls'] ?? [];
	same(['dump_cache', 'status', 'load_cache'], $calls, 'a real dump must be attempted for restore');
	check(str_contains((string) $p['log'], 'completed [ NOW ]'), 'the resolver status itself is unaffected by a cache restore failure');
	check(!str_contains((string) $p['log'], 'Resolver cache restored'), 'a failed load_cache must never be reported restored');
	rmdir_recursive_local($run['dir']);
});

row('Row 9d: healthy dump/start/status/load ordering and a truthful restored message', function () use ($src, $timeout_bin) {
	$run = run_isolated($src, fastConstants(),
		['pfb_stop_start_unbound', 'pfb_unbound_control_cmd', 'pfb_unbound_control_exec', 'pfb_reload_unbound'],
		stopStartPrelude() . "\$GLOBALS['pfb']['timeout'] = " . var_export($timeout_bin, true) . ";\n"
			. row9Body("printf 'DUMP-CONTENT'; exit 0", "printf 'is running...'; exit 0", 'cat >/dev/null; exit 0')
	);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	same(['dump_cache', 'status', 'load_cache'], $p['calls'] ?? [],
		'a healthy pass must dump BEFORE the restart and confirm status BEFORE restoring the cache, in that exact order');
	check(str_contains((string) $p['log'], 'Resolver cache restored'), 'a healthy dump+load must be reported restored');
	rmdir_recursive_local($run['dir']);
});

row('Row 9e: a TERM-ignoring dump_cache expires finitely, is discarded, and does not abort the reload', function () use ($src, $timeout_bin) {
	$run = run_isolated($src, fastConstants(),
		['pfb_stop_start_unbound', 'pfb_unbound_control_cmd', 'pfb_unbound_control_exec', 'pfb_reload_unbound'],
		stopStartPrelude() . "\$GLOBALS['pfb']['timeout'] = " . var_export($timeout_bin, true) . ";\n"
			. row9Body('trap "" TERM; exec sleep 30', "printf 'is running...'; exit 0", 'cat >/dev/null; exit 0'),
		20
	);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	$calls = $p['calls'] ?? [];
	same(['dump_cache', 'status'], $calls, 'an expired dump must be discarded -- load_cache must never run on it');
	// Platform note (see row9Body/Row 8b and tests/php/UnboundControlIpcBoundTest.php on
	// devel): GNU/uutils timeout reports 137, not FreeBSD's 124, for a KILL-escalated
	// dump_cache on this Linux dev box -- assert the outcome (discarded, non-fatal), not
	// the specific label this platform's timeout(1) happens to log.
	check(str_contains((string) $p['log'], '[ dump_cache ] TIMED OUT') || str_contains((string) $p['log'], '[ dump_cache ] FAILED'),
		'the dump expiry must be named as unsuccessful, whichever label this platform\'s timeout(1) produces');
	check(str_contains((string) $p['log'], 'completed [ NOW ]'), 'a dump-cache expiry must not abort the rest of the reload (issue #2879 "Continue after expiry")');
	check(!str_contains((string) $p['log'], 'Resolver cache restored'), 'a discarded dump must never be reported restored');
	rmdir_recursive_local($run['dir']);
});

row('Row 9f: a TERM-ignoring load_cache expires finitely, is discarded, and is never reported restored', function () use ($src, $timeout_bin) {
	$run = run_isolated($src, fastConstants(),
		['pfb_stop_start_unbound', 'pfb_unbound_control_cmd', 'pfb_unbound_control_exec', 'pfb_reload_unbound'],
		stopStartPrelude() . "\$GLOBALS['pfb']['timeout'] = " . var_export($timeout_bin, true) . ";\n"
			. row9Body("printf 'DUMP-CONTENT'; exit 0", "printf 'is running...'; exit 0", 'trap "" TERM; exec sleep 30'),
		20
	);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	$calls = $p['calls'] ?? [];
	same(['dump_cache', 'status', 'load_cache'], $calls, 'a real dump/status must still precede the load attempt even though the load itself expires');
	check(str_contains((string) $p['log'], '[ load_cache ] TIMED OUT') || str_contains((string) $p['log'], '[ load_cache ] FAILED'),
		'the load expiry must be named as unsuccessful, whichever label this platform\'s timeout(1) produces');
	check(str_contains((string) $p['log'], 'completed [ NOW ]'), 'a load-cache expiry must not abort the rest of the reload (issue #2879 "Continue after expiry")');
	check(!str_contains((string) $p['log'], 'Resolver cache restored'), 'an expired load must never be reported restored');
	rmdir_recursive_local($run['dir']);
});

row('Row 9g: a status exiting zero without the running-reply text must never be credited as a fresh success', function () use ($src, $timeout_bin) {
	$run = run_isolated($src, fastConstants(['PFB_UNBOUND_START_CMD' => "printf 'is running...'"]),
		['pfb_stop_start_unbound', 'pfb_unbound_control_cmd', 'pfb_unbound_control_exec', 'pfb_reload_unbound'],
		stopStartPrelude() . "\$GLOBALS['pfb']['timeout'] = " . var_export($timeout_bin, true) . ";\n"
			. row9Body("printf 'DUMP-CONTENT'; exit 0", ':', 'cat >/dev/null; exit 0')
	);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	$calls = $p['calls'] ?? [];
	check(in_array('status', $calls, true), 'the resolver must still be asked for status');
	check(!str_contains((string) $p['log'], 'completed [ NOW ]'), 'an exit-zero status without its own running-reply text must never be credited as a fresh success');
	check(str_contains((string) $p['log'], 'Not completed'), 'a stale/empty-success status must be reported not completed');
	rmdir_recursive_local($run['dir']);
});

row('Row 9h: failed status with running text cannot confirm success', function () use ($src, $timeout_bin) {
	$run = run_isolated($src, fastConstants(),
		['pfb_stop_start_unbound', 'pfb_unbound_control_cmd', 'pfb_unbound_control_exec', 'pfb_reload_unbound'],
		stopStartPrelude() . "\$GLOBALS['pfb']['timeout'] = " . var_export($timeout_bin, true) . ";\n"
			. row9Body("printf 'DUMP-CONTENT'; exit 0", "printf 'is running...'; exit 1", 'cat >/dev/null; exit 0')
	);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	same(['dump_cache', 'status'], $p['calls'] ?? [], 'a failed status must not reach cache restoration');
	check(!str_contains((string) $p['log'], 'completed [ NOW ]'), 'running text cannot override failed status');
	check(str_contains((string) $p['log'], 'Not completed'), 'failed status must report incomplete recovery');
});

row('Row 9i: an empty nonzero status response names the IPC failure', function () use ($src, $timeout_bin) {
	$run = run_isolated($src, fastConstants(),
		['pfb_stop_start_unbound', 'pfb_unbound_control_cmd', 'pfb_unbound_control_exec', 'pfb_reload_unbound'],
		stopStartPrelude() . "\$GLOBALS['pfb']['timeout'] = " . var_export($timeout_bin, true) . ";\n"
			. row9Body('exit 0', 'exit 1', 'exit 0', false)
	);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	check(str_contains((string) $run['payload']['log'], '[ status ] FAILED (exit 1)'),
		'a silent nonzero status command must report its operation and exit code');
});

row('Row 9j: a failed dump is never loaded even when its truncation is denied', function () use ($src) {
	$fixture = <<<'PHP'
namespace ReadonlyCache;
function tempnam($dir, $prefix) {
	$path = \tempnam($GLOBALS['cache_dir'], $prefix);
	$GLOBALS['cache_path'] = $path;
	return $path;
}
function pfb_stop_start_unbound($type) {
	return ['retval' => 0, 'start_completed' => true, 'result' => []];
}
function pfb_unbound_control_exec($cmd, $label, &$lines = null, $log_nonzero = true) {
	$GLOBALS['cache_calls'][] = $label;
	if ($label === 'dump_cache') {
		$path = $GLOBALS['cache_path'];
		\file_put_contents($path, 'PARTIAL');
		if (!\chmod($path, 0400)) { throw new \RuntimeException('cannot create read-only dump fixture'); }
		\clearstatcache(true, $path);
		$GLOBALS['cache_readonly'] = !\is_writable($path);
		return 1;
	}
	if ($label === 'status') { $lines = ['is running...']; }
	return 0;
}
function unlink_if_exists($path) {
	if ($path === $GLOBALS['cache_path']) {
		$GLOBALS['cache_before_cleanup'] = \file_get_contents($path);
	}
	\unlink_if_exists($path);
}
PHP;
	$fixture .= "\n" . function_source($src, 'pfb_reload_unbound');
	$run = run_isolated($src, fastConstants(), [], stopStartPrelude() . <<<'PHP'
if (!chmod($dir, 0777)) { throw new RuntimeException('cannot prepare private fixture directory'); }
if (posix_geteuid() === 0) {
	$account = posix_getpwnam('nobody');
	if (!$account || !posix_setgid($account['gid']) || !posix_setuid($account['uid'])) {
		throw new RuntimeException('cannot drop fixture child privileges to exercise real permission denial');
	}
}
$GLOBALS['cache_dir'] = $dir;
$GLOBALS['cache_calls'] = [];
$GLOBALS['pfb']['dnsbldir'] = $dir;
$GLOBALS['pfb']['dnsbl_file'] = "$dir/dnsbl";
$GLOBALS['pfb']['dnsbl_py_blacklist'] = false;
$GLOBALS['pfb']['dnsbl_res_cache'] = 'on';
$GLOBALS['pfb']['chroot_cmd'] = '/bin/true';
$GLOBALS['pfb_process_running']['unbound'] = true;
PHP
		. "\neval(" . var_export($fixture, true) . ");\n" . <<<'PHP'
\ReadonlyCache\pfb_reload_unbound('enabled', true, false);
echo json_encode([
	'calls' => $GLOBALS['cache_calls'],
	'readonly' => $GLOBALS['cache_readonly'],
	'remaining' => $GLOBALS['cache_before_cleanup'],
]) . "\n";
PHP
	);
	check($run['status'] === 0, 'isolated runner must exit cleanly: ' . implode("\n", $run['output']));
	$p = $run['payload'];
	same(true, $p['readonly'] ?? null, 'fixture must genuinely deny writes, even when the suite runs as root');
	same('PARTIAL', $p['remaining'] ?? null, 'failed truncation must leave the real partial dump intact');
	same(['dump_cache', 'status'], $p['calls'] ?? null, 'an invalid dump must not reach load_cache');
});

row('Row 10: conditional install migration reports restart failure without changing its trigger', function () use ($install_src) {
	$block = block_source($install_src, "if (\$ufound) {\n\t\$final = pfb_stop_start_unbound(");
	check(str_contains($block, "pfb_stop_start_unbound('')"), 'sanity: the extracted block must be the migration caller');

	if (!function_exists('pfb_stop_start_unbound')) {
		function pfb_stop_start_unbound($type)
		{
			$GLOBALS['pfb_test_stop_start_calls']++;
			return $GLOBALS['pfb_test_stop_start_return'];
		}
	}
	if (!function_exists('update_status')) {
		function update_status($msg)
		{
			$GLOBALS['pfb_test_update_status_calls'][] = $msg;
		}
	}
	$GLOBALS['pfb_test_stop_start_calls'] = 0;

	// (a) the migration never ran ($ufound = false): the trigger must stay gated.
	$ufound = false;
	$GLOBALS['pfb_test_update_status_calls'] = [];
	eval($block);
	same(0, $GLOBALS['pfb_test_stop_start_calls'], 'an untouched migration ($ufound=false) must never call pfb_stop_start_unbound');
	same([], $GLOBALS['pfb_test_update_status_calls'], 'no failure message when the migration never ran');

	// (b) the migration ran and the restart succeeded: no failure message.
	$ufound = true;
	$GLOBALS['pfb_test_stop_start_return'] = ['retval' => 0];
	$GLOBALS['pfb_test_update_status_calls'] = [];
	eval($block);
	same(1, $GLOBALS['pfb_test_stop_start_calls'], 'a triggered migration must call pfb_stop_start_unbound exactly once');
	same([], $GLOBALS['pfb_test_update_status_calls'], 'a healthy restart must report no failure');

	// (c) the migration ran and the restart failed: the caller must now branch and report it,
	// while the trigger condition ($ufound) itself is completely unaffected by the outcome.
	$ufound = true;
	$GLOBALS['pfb_test_stop_start_return'] = ['retval' => -2];
	$GLOBALS['pfb_test_update_status_calls'] = [];
	eval($block);
	same(2, $GLOBALS['pfb_test_stop_start_calls'], 'the trigger itself is unchanged by the outcome -- still exactly one more call');
	check(count($GLOBALS['pfb_test_update_status_calls']) === 1
		&& str_contains($GLOBALS['pfb_test_update_status_calls'][0], 'did not restart'),
		'a failed restart must now be reported to update_status(), not silently discarded');
});

echo $failures === 0 ? "ALL PASS\n" : "{$failures} FAILURE(S)\n";
exit($failures === 0 ? 0 : 1);

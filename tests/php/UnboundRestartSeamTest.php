<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #2613 -- pfb_stop_start_unbound() execs the Unbound daemon and polls for the
 * outgoing process to exit. Both boundaries are named constants (PFB_UNBOUND_START_CMD,
 * PFB_UNBOUND_STOP_WAIT) that tests/php/bootstrap.php overrides before the package loads,
 * so a unit run starts no resolver on a developer box that HAS Unbound installed at the
 * shipped path, and no individual test has to defuse the appliance's 30-poll stop-wait.
 */
#[CoversFunction('pfb_stop_start_unbound')]
final class UnboundRestartSeamTest extends TestCase
{
	private const SALVAGE_SECONDS = 8;

	private string $dir;
	/** @var array<string, array{0: bool, 1: mixed}> key => [existed, value] */
	private array $savedPfb = [];
	/** @var array{0: bool, 1: mixed} */
	private array $savedVarrun = [FALSE, NULL];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_unbound_seam_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);

		// Track key EXISTENCE separately from value: 'dnsbl_python_unmount' is legitimately
		// boolean FALSE, so a FALSE sentinel would unset a sibling suite's value instead of
		// restoring it.
		foreach (['log', 'errlog', 'dnsbl_python_unmount', 'php'] as $key) {
			$this->savedPfb[$key] = [
				array_key_exists($key, $GLOBALS['pfb'] ?? []),
				$GLOBALS['pfb'][$key] ?? NULL,
			];
		}
		$this->savedVarrun = [
			array_key_exists('varrun_path', $GLOBALS['g'] ?? []),
			$GLOBALS['g']['varrun_path'] ?? NULL,
		];

		// Each row owns its pidfile and process state; no signal reaches a host daemon.
		$GLOBALS['pfb'] = array_replace($GLOBALS['pfb'], [
			'log'                  => "{$this->dir}/pfblockerng.log",
			'errlog'               => "{$this->dir}/error.log",
			'dnsbl_python_unmount' => FALSE,
			'php'                  => PHP_BINARY,
		]);
		$GLOBALS['g']['varrun_path'] = $this->dir;
	}

	protected function tearDown(): void
	{
		foreach ($this->savedPfb as $key => [$existed, $value]) {
			if ($existed) {
				$GLOBALS['pfb'][$key] = $value;
			} else {
				unset($GLOBALS['pfb'][$key]);
			}
		}
		[$existed, $value] = $this->savedVarrun;
		if ($existed) {
			$GLOBALS['g']['varrun_path'] = $value;
		} else {
			unset($GLOBALS['g']['varrun_path']);
		}
		unset($GLOBALS['pfb_test_process_running'], $GLOBALS['pfb_test_valid_pids'],
			$GLOBALS['pfb_test_sigkillbypid_calls'], $GLOBALS['pfb_test_sigkillbypid_effect'],
			$GLOBALS['pfb_test_sigkillbyname_calls'], $GLOBALS['pfb_test_sigkillbyname_effect']);
		rmdir_recursive($this->dir);
	}

	/**
	 * Invocations the harness daemon-start double has recorded so far. Counted
	 * relatively, never absolutely: the log accumulates over the whole process, and
	 * sibling suites that reach the restart fallback append to it too.
	 *
	 * @return list<string>
	 */
	private function doubleInvocations(): array
	{
		$log = (string) ($GLOBALS['pfb_test_unbound_start_log'] ?? '');
		$this->assertNotSame('', $log,
			'the harness must publish the path of its daemon-start double log');
		return file_exists($log) ? (file($log, FILE_IGNORE_NEW_LINES) ?: []) : [];
	}
	private function makeStartScript(string $name, string $body): string
	{
		$path = "{$this->dir}/{$name}";
		file_put_contents($path, "#!/bin/sh\n{$body}\n");
		chmod($path, 0755);
		return $path;
	}

	/**
	 * Run the production function in a fresh PHP process so each row can set the
	 * existing PFB_UNBOUND_START_CMD seam. The outer timeout is salvage only:
	 * default mode reaps the whole runner tree if production regresses to an
	 * unbounded wait. A $prelude may name another entry point in
	 * $GLOBALS['pfb_test_start_entry'] and set a closure in
	 * $GLOBALS['pfb_test_after_start'], called the instant the start returns; its
	 * result is the payload's 'after'.
	 *
	 * @param list<string> $ini PHP INI settings applied only to the isolated runner
	 * @return array{status: int, output: list<string>, payload: array<string, mixed>|null}
	 */
	private function runIsolatedStart(
		string $startCommand,
		int $budget = 5,
		?string $phpCli = NULL,
		array $ini = [],
		string $prelude = ''
	): array
	{
		$phpCli ??= PHP_BINARY;
		$id = bin2hex(random_bytes(4));
		$runner = "{$this->dir}/runner_{$id}.php";
		$log = "{$this->dir}/isolated_{$id}.log";
		$errlog = "{$this->dir}/isolated_{$id}.err";
		$timeout = (string) $GLOBALS['pfb']['timeout'];
		$bootstrap = __DIR__ . '/bootstrap.php';
		file_put_contents($runner, "<?php\n"
			. "define('PFB_UNBOUND_START_CMD', " . var_export($startCommand, TRUE) . ");\n"
			. "define('PFB_UNBOUND_STOP_WAIT', 1);\n"
			. "define('PFB_UNBOUND_START_WAIT', " . var_export($budget, TRUE) . ");\n"
			. "define('PFB_HOOK_KILL_GRACE', 1);\n"
			. 'require ' . var_export($bootstrap, TRUE) . ";\n"
			. '$GLOBALS[\'pfb\'][\'timeout\'] = ' . var_export($timeout, TRUE) . ";\n"
			. '$GLOBALS[\'pfb\'][\'php\'] = ' . var_export($phpCli, TRUE) . ";\n"
			. '$GLOBALS[\'pfb\'][\'log\'] = ' . var_export($log, TRUE) . ";\n"
			. '$GLOBALS[\'pfb\'][\'errlog\'] = ' . var_export($errlog, TRUE) . ";\n"
			. "\$GLOBALS['pfb']['dnsbl_python_unmount'] = FALSE;\n"
			. '$GLOBALS[\'g\'][\'varrun_path\'] = ' . var_export($this->dir, TRUE) . ";\n"
			. "\$GLOBALS['pfb_test_process_running']['unbound'] = FALSE;\n"
			. $prelude
			. "\$final = (\$GLOBALS['pfb_test_start_entry'] ?? 'pfb_stop_start_unbound')('');\n"
			. "\$after = isset(\$GLOBALS['pfb_test_after_start']) ? (\$GLOBALS['pfb_test_after_start'])() : NULL;\n"
			. 'echo json_encode([\'final\' => $final, \'log\' => (string) @file_get_contents('
			. var_export($log, TRUE) . '), \'errlog\' => (string) @file_get_contents('
			. var_export($errlog, TRUE) . '), \'mount_include_log\' => (string) @file_get_contents('
			. '$GLOBALS[\'pfb_test_unbound_include_log\'] ?? \'\'), \'after\' => $after]), "\\n";' . "\n");

		$output = [];
		$status = 0;
		$flags = '';
		foreach ($ini as $flag) {
			$flags .= ' -d ' . escapeshellarg($flag);
		}
		$cmd = 'TMPDIR=' . escapeshellarg($this->dir) . ' ' .
			escapeshellarg($timeout) . ' -s TERM -k 2 ' . self::SALVAGE_SECONDS .
			' ' . escapeshellarg(PHP_BINARY) . $flags . ' ' . escapeshellarg($runner) . ' 2>&1';
		exec($cmd, $output, $status);

		$payload = NULL;
		if ($status === 0 && $output !== []) {
			$decoded = json_decode((string) end($output), TRUE);
			$payload = is_array($decoded) ? $decoded : NULL;
		}
		return ['status' => $status, 'output' => $output, 'payload' => $payload];
	}

	private function pidIsAlive(int $pid): bool
	{
		return $pid > 0 && posix_kill($pid, 0);
	}

	private function terminatePid(int $pid): void
	{
		if (!$this->pidIsAlive($pid)) {
			return;
		}
		posix_kill($pid, 9);
		$deadline = microtime(TRUE) + 2.0;
		while ($this->pidIsAlive($pid) && microtime(TRUE) < $deadline) {
			usleep(10000);
		}
	}


	/**
	 * Scenario: a restart under the unit harness must not reach the real daemon.
	 *   Given the harness has overridden the daemon-start boundary,
	 *   When pfb_stop_start_unbound() runs its start step,
	 *   Then the harness double records the attempt and the shipped binary is never named.
	 */
	public function testDaemonStartRunsTheHarnessDoubleNotTheShippedBinary(): void
	{
		$before = $this->doubleInvocations();
		$this->assertTrue(defined('PFB_UNBOUND_START_CMD'),
			'the daemon-start boundary must be an overridable constant, not a hardcoded exec()');
		$this->assertStringNotContainsString('/usr/local/sbin/unbound', PFB_UNBOUND_START_CMD,
			'a unit run must never be pointed at the real Unbound binary');
		$GLOBALS['pfb_test_process_running']['unbound'] = FALSE;

		$final = pfb_stop_start_unbound(' (DNSBL python)');

		$this->assertCount(count($before) + 1, $this->doubleInvocations(),
			'the start step must run the harness double exactly once per call');
		$this->assertSame(127, $final['retval'],
			'the double must keep reporting command-not-found, the status an absent binary '
			. "already produces off-appliance, so the caller's retry branch stays exercised");
		$this->assertArrayHasKey('start_completed', $final);
		$this->assertTrue($final['start_completed'],
			'a completed command-not-found result must be distinguishable from a pre-start failure');
		$this->assertNotEmpty($final['result'],
			'the caller logs the start output on failure, so the double must produce one');
	}

	/**
	 * Scenario (issue #3850): a Resolver restart no longer prepares Unbound's chroot for the retired DNSBL python module.
	 *   Given a mount include staged where the restart used to look for one,
	 *   When pfb_stop_start_unbound() restarts Unbound,
	 *   Then the restart runs no mount include and its log names no mounts, only the start.
	 */
	public function testAResolverRestartRunsNoMountIncludeAndLogsNoMounts(): void
	{
		$run = $this->runIsolatedStart('true');

		$this->assertSame(0, $run['status'], 'the isolated runner must exit cleanly: ' . implode("\n", $run['output']));
		$this->assertIsArray($run['payload'], 'the isolated start runner must return its JSON result');
		$log = (string) $run['payload']['log'];
		$this->assertStringContainsString('Starting Unbound Resolver', $log, 'before: the restart ran its start step');
		$this->assertStringNotContainsStringIgnoringCase('mounts', $log, 'the restart logged a mount step: ' . $log);
		$this->assertSame('', $run['payload']['mount_include_log'], 'the restart ran a mount include');
	}

	/**
	 * Scenario: the stop-wait must not cost a test the appliance's full budget.
	 *   Given a process-running double that never reports the daemon gone,
	 *   When pfb_stop_start_unbound() waits for it to terminate,
	 *   Then the stop-wait loop polls only the harness budget -- 30 one-second polls
	 *   per call otherwise -- and the KILL escalation adds only its own budget.
	 */
	public function testStopWaitIsBoundedWhenTheDaemonNeverExits(): void
	{
		$polls = 0;
		$GLOBALS['pfb_test_process_running']['unbound'] = static function () use (&$polls): bool {
			$polls++;
			return TRUE;
		};

		pfb_stop_start_unbound('');

		$this->assertLessThan(30, $polls,
			"a test that never reports the daemon gone must not pay the appliance's 30 one-second polls");
		// The stop loop polls its budget; the timeout branch then re-checks once, polls
		// the KILL budget, and re-checks once more before refusing to start.
		$this->assertSame(PFB_UNBOUND_STOP_WAIT + PFB_UNBOUND_KILL_WAIT + 2, $polls,
			'both waits must poll exactly their configured budgets when the daemon never exits');
	}

	/**
	 * Scenario (#3055): a stop that times out must not be followed by a start.
	 *   Given Unbound is still running after both the TERM wait and the KILL wait,
	 *   When pfb_stop_start_unbound() runs,
	 *   Then no start is attempted, and the refusal is reported and logged.
	 *
	 * Starting on top of a live daemon is 'bind: address already in use' -- the owner's
	 * production failure, recoverable only with kill -9 and a PEM rebuild.
	 */
	public function testStopTimeoutRefusesToStartASecondInstance(): void
	{
		$before = $this->doubleInvocations();
		$GLOBALS['pfb_test_process_running']['unbound'] = TRUE;
		$GLOBALS['pfb_test_sigkillbyname_calls'] = array();

		$final = pfb_stop_start_unbound('');

		$this->assertCount(count($before), $this->doubleInvocations(),
			'a stop that never completed must not reach the daemon start at all');
		$this->assertSame(PFB_UNBOUND_STOP_FAILED, $final['retval'],
			'the refusal must be reported to the caller as a failure, not a silent success');
		$this->assertArrayHasKey('start_completed', $final);
		$this->assertFalse($final['start_completed'],
			'a refused stop must report that no start command completed');
		// issue #3094: the whole point of the code is that a caller can tell "the daemon
		// would not stop" from "the generated config is bad". Sharing -1 with the generic
		// failure would put it straight back into the unbound.bk rollback path.
		$this->assertNotSame(-1, PFB_UNBOUND_STOP_FAILED,
			'the stop-failure code must be distinguishable from a generic failure');
		$this->assertNotEmpty($final['result'],
			'the caller logs the result, so the refusal must carry a reason');
		$this->assertSame(array(array('unbound', 'TERM'), array('unbound', 'KILL')),
			$GLOBALS['pfb_test_sigkillbyname_calls'],
			'the timeout must attempt TERM before escalating to KILL exactly once');
		$this->assertStringContainsString('not starting a second instance',
			(string) @file_get_contents($GLOBALS['pfb']['log']),
			'the refusal must be loud in the log, not inferable only from a return value');
	}

	/**
	 * Scenario (#3055): the KILL escalation is the recovery, not just a louder failure.
	 *   Given Unbound ignores TERM but dies on KILL,
	 *   When pfb_stop_start_unbound() runs,
	 *   Then the start proceeds normally.
	 */
	public function testDaemonThatOnlyDiesOnKillStillGetsRestarted(): void
	{
		$before = $this->doubleInvocations();
		$GLOBALS['pfb_test_process_running']['unbound'] = TRUE;
		$GLOBALS['pfb_test_sigkillbyname_calls'] = array();
		$GLOBALS['pfb_test_sigkillbyname_effect'] = static function (string $name, string $sig): void {
			if ($name === 'unbound' && $sig === 'KILL') {
				$GLOBALS['pfb_test_process_running']['unbound'] = FALSE;
			}
		};

		try {
			$final = pfb_stop_start_unbound('');
		} finally {
			unset($GLOBALS['pfb_test_sigkillbyname_effect']);
		}

		$this->assertCount(count($before) + 1, $this->doubleInvocations(),
			'a daemon that KILL did clear must be restarted, not abandoned');
		$this->assertSame(127, $final['retval'],
			'the start must run through the harness double exactly as on the clean-stop path');
		$this->assertArrayHasKey('start_completed', $final);
		$this->assertTrue($final['start_completed'],
			'the post-KILL start command must report its completed non-zero status');
		$this->assertSame(array(array('unbound', 'TERM'), array('unbound', 'KILL')),
			$GLOBALS['pfb_test_sigkillbyname_calls'],
			'a missing pidfile must attempt name-based TERM before KILL');
	}

	public function testValidLivePidfileUsesPidTermOnly(): void
	{
		$pidfile = "{$this->dir}/unbound.pid";
		file_put_contents($pidfile, "123\n");
		$GLOBALS['pfb_test_valid_pids'] = [$pidfile => TRUE];
		$GLOBALS['pfb_test_process_running']['unbound'] = TRUE;
		$GLOBALS['pfb_test_sigkillbypid_calls'] = array();
		$GLOBALS['pfb_test_sigkillbyname_calls'] = array();
		$GLOBALS['pfb_test_sigkillbypid_effect'] = static function (string $file, string $sig): void {
			if ($sig === 'TERM') {
				$GLOBALS['pfb_test_process_running']['unbound'] = FALSE;
			}
		};

		$final = pfb_stop_start_unbound('');

		$this->assertSame(array(array($pidfile, 'TERM')), $GLOBALS['pfb_test_sigkillbypid_calls'],
			'a valid live pidfile must target only that PID with TERM');
		$this->assertSame(array(), $GLOBALS['pfb_test_sigkillbyname_calls'],
			'a valid live pidfile must not fan TERM out by process name');
		$this->assertArrayHasKey('start_completed', $final);
		$this->assertTrue($final['start_completed']);
	}

	public function testMissingPidfileUsesNameTermAndStartsWhenDaemonStops(): void
	{
		$GLOBALS['pfb_test_process_running']['unbound'] = TRUE;
		$GLOBALS['pfb_test_sigkillbyname_calls'] = array();
		$GLOBALS['pfb_test_sigkillbyname_effect'] = static function (string $name, string $sig): void {
			if ($name === 'unbound' && $sig === 'TERM') {
				$GLOBALS['pfb_test_process_running']['unbound'] = FALSE;
			}
		};

		$final = pfb_stop_start_unbound('');

		$this->assertSame(array(array('unbound', 'TERM')), $GLOBALS['pfb_test_sigkillbyname_calls'],
			'a live daemon without a pidfile must receive name-based TERM before any KILL');
		$this->assertArrayHasKey('start_completed', $final);
		$this->assertTrue($final['start_completed'],
			'a daemon that exits on name-based TERM must proceed to one completed start');
	}

	public function testInvalidPidfileFallsBackToNameTerm(): void
	{
		$pidfile = "{$this->dir}/unbound.pid";
		file_put_contents($pidfile, "not-a-pid\n");
		$GLOBALS['pfb_test_valid_pids'] = [$pidfile => FALSE];
		$GLOBALS['pfb_test_process_running']['unbound'] = TRUE;
		$GLOBALS['pfb_test_sigkillbypid_calls'] = array();
		$GLOBALS['pfb_test_sigkillbyname_calls'] = array();
		$GLOBALS['pfb_test_sigkillbyname_effect'] = static function (string $name, string $sig): void {
			if ($name === 'unbound' && $sig === 'TERM') {
				$GLOBALS['pfb_test_process_running']['unbound'] = FALSE;
			}
		};

		pfb_stop_start_unbound('');

		$this->assertSame(array(), $GLOBALS['pfb_test_sigkillbypid_calls'],
			'an invalid pidfile must never be trusted as a PID signal target');
		$this->assertSame(array(array('unbound', 'TERM')), $GLOBALS['pfb_test_sigkillbyname_calls'],
			'an invalid pidfile with a live daemon must fall back to name-based TERM');
	}

	public function testNoLiveDaemonSendsNoTermSignal(): void
	{
		$GLOBALS['pfb_test_process_running']['unbound'] = FALSE;
		$GLOBALS['pfb_test_sigkillbypid_calls'] = array();
		$GLOBALS['pfb_test_sigkillbyname_calls'] = array();

		pfb_stop_start_unbound('');

		$this->assertSame(array(), $GLOBALS['pfb_test_sigkillbypid_calls']);
		$this->assertSame(array(), $GLOBALS['pfb_test_sigkillbyname_calls'],
			'an absent daemon must not receive a name-based signal');
	}
	public function testDaemonizedStartSurvivesTheBoundedWrapper(): void
	{
		$pidfile = "{$this->dir}/daemon.pid";
		$daemonCode = '$sid = posix_setsid(); if ($sid === -1) { exit(126); } '
			. 'file_put_contents($argv[1], (string) getmypid()); sleep(30);';
		$script = $this->makeStartScript('daemonize.sh',
			'"$2" -r ' . escapeshellarg($daemonCode) . ' "$1" </dev/null >/dev/null 2>&1 &' . "\n"
			. 'i=0; while [ ! -s "$1" ] && [ "$i" -lt 100 ]; do i=$((i + 1)); sleep 0.01; done' . "\n"
			. '[ -s "$1" ] || exit 126' . "\n"
			. 'exit 0');

		$run = $this->runIsolatedStart(escapeshellarg($script) . ' ' .
			escapeshellarg($pidfile) . ' ' . escapeshellarg(PHP_BINARY));
		$pid = (int) trim((string) @file_get_contents($pidfile));
		try {
			$this->assertSame(0, $run['status'],
				'stuck/environment: the daemonized start runner exceeded its salvage cap: '
				. implode("\n", $run['output']));
			$this->assertIsArray($run['payload'], 'the isolated start runner must return its JSON result');
			$this->assertSame(0, $run['payload']['final']['retval'],
				'a successfully daemonized start must remain a successful start');
			$this->assertArrayHasKey('start_completed', $run['payload']['final']);
			$this->assertTrue($run['payload']['final']['start_completed'],
				'the successful daemon start must carry a validated completion record');
			$this->assertTrue($this->pidIsAlive($pid),
				'a successfully daemonized resolver must escape the supervised launcher group and survive');
		} finally {
			$this->terminatePid($pid);
		}
		$this->assertFalse($this->pidIsAlive($pid),
			'the daemon-survival row must reap its controlled survivor before returning');
	}

	public function testStartCommandRunsOnlyAfterItsProcessGroupExists(): void
	{
		$expectedFile = "{$this->dir}/expected.pgid";
		$actualFile = "{$this->dir}/actual.pgid";
		$script = $this->makeStartScript('record-pgid.sh',
			'printf \'%s\\n\' "$PFB_UNBOUND_START_PGID" > "$1"' . "\n"
			. 'ps -o pgid= -p "$$" | tr -d \' \' > "$2"' . "\n"
			. 'exit 0');

		$run = $this->runIsolatedStart(escapeshellarg($script) . ' '
			. escapeshellarg($expectedFile) . ' ' . escapeshellarg($actualFile));
		$expected = trim((string) @file_get_contents($expectedFile));
		$actual = trim((string) @file_get_contents($actualFile));

		$this->assertSame(0, $run['status'],
			'the process-group runner must complete inside its salvage cap: ' . implode("\n", $run['output']));
		$this->assertIsArray($run['payload']);
		$this->assertSame(0, $run['payload']['final']['retval']);
		$this->assertArrayHasKey('start_completed', $run['payload']['final']);
		$this->assertTrue($run['payload']['final']['start_completed']);
		$this->assertMatchesRegularExpression('/^[1-9][0-9]*$/', $expected,
			'RED issue #2882: the launcher must publish its group only after setpgid succeeds');
		$this->assertSame($expected, $actual,
			'the start command must not execute until it is inside the launcher process group');
	}

	public function testSupervisorUsesConfiguredCliPhpInsteadOfCurrentSapiBinary(): void
	{
		$argvLog = "{$this->dir}/php-cli.argv";
		$phpCli = $this->makeStartScript('php-cli',
			'printf \'%s\\n\' "$@" > ' . escapeshellarg($argvLog) . "\n"
			. 'exec ' . escapeshellarg(PHP_BINARY) . ' "$@"');
		$start = $this->makeStartScript('cli-start.sh', 'exit 0');

		$run = $this->runIsolatedStart(escapeshellarg($start), 5, $phpCli);
		$argv = file_exists($argvLog) ? (file($argvLog, FILE_IGNORE_NEW_LINES) ?: []) : [];

		$this->assertSame(0, $run['status'],
			'the configured-CLI runner must complete inside its salvage cap: ' . implode("\n", $run['output']));
		$this->assertIsArray($run['payload']);
		$this->assertSame(0, $run['payload']['final']['retval'],
			'the configured CLI executable must run the supervisor and preserve child success');
		$this->assertArrayHasKey('start_completed', $run['payload']['final']);
		$this->assertTrue($run['payload']['final']['start_completed']);
		$this->assertSame('-r', $argv[0] ?? NULL,
			'RED issue #2882: the supervisor must invoke the configured CLI PHP, not PHP_BINARY/php-cgi');
		$this->assertContains('--', $argv,
			'the CLI supervisor arguments must retain the option terminator before runtime values');
	}

	public function testTermIgnoringStartExpiresObservablyAndLeavesNoProcess(): void
	{
		$pidfile = "{$this->dir}/stuck.pid";
		$script = $this->makeStartScript('term-ignoring.sh',
			'printf \'%s\\n\' "$$" > "$1"' . "\n"
			. 'trap \'\' TERM' . "\n"
			. 'exec sleep 30');

		$run = $this->runIsolatedStart(
			escapeshellarg($script) . ' ' . escapeshellarg($pidfile),
			2
		);
		$pid = (int) trim((string) @file_get_contents($pidfile));
		$alive = $this->pidIsAlive($pid);
		if ($alive) {
			$this->terminatePid($pid);
		}
		$this->assertGreaterThan(0, $pid,
			'the timeout row must observe the command-start event before evaluating cleanup');

		$this->assertSame(0, $run['status'],
			'RED issue #2882: the production start wait exceeded the 8s salvage cap; '
			. 'the direct PFB_UNBOUND_START_CMD child is still unbounded. Output: '
			. implode("\n", $run['output']));
		$this->assertIsArray($run['payload'], 'the bounded start must return its JSON result');
		$this->assertSame(124, $run['payload']['final']['retval'],
			'an expired start must retain status 124 so callers preserve the valid configuration');
		$this->assertArrayHasKey('start_completed', $run['payload']['final']);
		$this->assertFalse($run['payload']['final']['start_completed'],
			'a command killed at its deadline did not produce a valid completion record');
		$this->assertStringContainsString('Unbound Resolver start TIMED OUT after 2s and was killed',
			$run['payload']['log'], 'expiry must be explicit in the main log');
		$this->assertStringContainsString('Unbound Resolver start TIMED OUT after 2s and was killed',
			$run['payload']['errlog'], 'expiry must be explicit in the error log');
		$this->assertFalse($alive,
			'the SIGKILL grace must leave no TERM-ignoring transient start process behind');
	}

	public function testExpiryReapsTermIgnoringLauncherAndDescendant(): void
	{
		$launcherFile = "{$this->dir}/launcher.pid";
		$helperFile = "{$this->dir}/helper.pid";
		$script = $this->makeStartScript('term-ignoring-tree.sh',
			'trap \'\' TERM' . "\n"
			. 'printf \'%s\\n\' "$$" > "$1"' . "\n"
			. '(' . "\n"
			. "\ttrap '' TERM\n"
			. "\texec sleep 30\n"
			. ') &' . "\n"
			. 'helper=$!' . "\n"
			. 'printf \'%s\\n\' "$helper" > "$2"' . "\n"
			. 'wait "$helper"');

		$run = $this->runIsolatedStart(
			escapeshellarg($script) . ' ' . escapeshellarg($launcherFile) . ' ' . escapeshellarg($helperFile),
			2
		);
		$launcher = (int) trim((string) @file_get_contents($launcherFile));
		$helper = (int) trim((string) @file_get_contents($helperFile));
		$launcherAlive = $this->pidIsAlive($launcher);
		$helperAlive = $this->pidIsAlive($helper);
		if ($launcherAlive) {
			$this->terminatePid($launcher);
		}
		if ($helperAlive) {
			$this->terminatePid($helper);
		}
		$this->assertGreaterThan(0, $launcher,
			'the process-tree row must observe its direct launcher before evaluating cleanup');
		$this->assertGreaterThan(0, $helper,
			'the process-tree row must observe its helper before evaluating cleanup');

		$this->assertSame(0, $run['status'],
			'the process-tree expiry runner must complete inside its salvage cap: ' . implode("\n", $run['output']));
		$this->assertIsArray($run['payload']);
		$this->assertSame(124, $run['payload']['final']['retval'],
			'the process-tree expiry must preserve the distinguished timeout status');
		$this->assertArrayHasKey('start_completed', $run['payload']['final']);
		$this->assertFalse($run['payload']['final']['start_completed'],
			'an expired process tree did not produce a valid completion record');
		$this->assertFalse($launcherAlive,
			'the direct TERM-ignoring launcher must be absent after kill grace');
		$this->assertFalse($helperAlive,
			'RED issue #2882: expiry must kill the launcher process group, not orphan its TERM-ignoring helper');
	}

	/**
	 * issue #3663: runner prelude that loads pfb_stop_start_unbound() on the house clock fixture
	 * with a recording posix_kill(): every call is sent for real and logged with the clock's time.
	 * Sleeps stay real, so the clock follows the real start and supervisor; with $virtualAfterKill
	 * they turn virtual once a group SIGKILL is sent, so the wait after it is measured on the clock
	 * alone. When the start returns, the runner reports the calls, the group named in $pgidFile and
	 * whether that group still exists, then kills what is left of it. $extra runs last.
	 */
	private function groupKillPrelude(string $pgidFile, bool $virtualAfterKill, string $extra = ''): string
	{
		return 'require_once ' . var_export(__DIR__ . '/support/PfbFlockClockFixture.php', TRUE) . ";\n"
			. '$pgid_file = ' . var_export($pgidFile, TRUE) . ";\n"
			. '$virtual_after_kill = ' . var_export($virtualAfterKill, TRUE) . ";\n"
			. <<<'PHP'
$GLOBALS['pfb_test_clock'] = $clock = new PfbFlockClockFixture();
$ns = $clock->loadChain(['pfb_stop_start_unbound']);
eval(str_replace('@NS@', $ns, <<<'NS'
namespace @NS@;
function posix_kill(int $pid, int $sig): bool
{
	$sent = \posix_kill($pid, $sig);
	$GLOBALS['pfb_test_kill_calls'][] = [$pid, $sig, $sent, hrtime(TRUE)];
	return $sent;
}
NS));
$GLOBALS['pfb_test_start_entry'] = "{$ns}\\pfb_stop_start_unbound";
$clock->setOnSleep(static function () use ($clock, $virtual_after_kill): void {
	foreach ($GLOBALS['pfb_test_kill_calls'] ?? [] as [$pid, $sig]) {
		if ($virtual_after_kill && $pid < 0 && $sig === 9) {
			return;
		}
	}
	$us = (int) end($clock->sleeps);
	time_nanosleep(intdiv($us, 1000000), ($us % 1000000) * 1000);
});
$GLOBALS['pfb_test_after_start'] = static function () use ($pgid_file): array {
	$pgid = (int) trim((string) @file_get_contents($pgid_file));
	$alive = $pgid > 0 && posix_kill(-$pgid, 0);
	if ($alive) {
		posix_kill(-$pgid, 9);
	}
	return ['pgid' => $pgid, 'group_alive' => $alive, 'grace' => PFB_HOOK_KILL_GRACE,
		'kill_calls' => $GLOBALS['pfb_test_kill_calls'] ?? []];
};

PHP
			. $extra;
	}

	/**
	 * The recorded kill() calls that follow the last SIGKILL sent to $pgid's group, plus that SIGKILL.
	 *
	 * @param list<array{0: int, 1: int, 2: bool, 3: int}> $calls
	 * @return array{0: array{0: int, 1: int, 2: bool, 3: int}, 1: list<array{0: int, 1: int, 2: bool, 3: int}>}
	 */
	private function callsAfterGroupKill(array $calls, int $pgid): array
	{
		$kills = array_keys(array_filter($calls,
			static fn (array $call): bool => $call[0] === -$pgid && $call[1] === 9));
		$this->assertNotSame([], $kills,
			'the expiry must reach the group SIGKILL; kill calls: ' . json_encode($calls));
		$kill = (int) end($kills);
		return [$calls[$kill], array_slice($calls, $kill + 1)];
	}

	/** @return array<string, array{bool}> */
	public static function killedGroupProvider(): array
	{
		return [
			'TERM-ignoring member outlives its reaped supervisor' => [FALSE],
			'unresponsive supervisor is killed with its group'     => [TRUE],
		];
	}

	/**
	 * Scenario (issue #3663): SIGKILL only queues the signal, so a killed member stays in its
	 * group until it has exited and been reaped.
	 *   Given an expired start whose TERM-ignoring member is SIGKILLed with its group,
	 *     with the supervisor either reaped after TERM or stopped and killed too,
	 *   When pfb_stop_start_unbound() returns,
	 *   Then its last kill() after the group SIGKILL found the group gone,
	 *   And no member of that group exists.
	 */
	#[DataProvider('killedGroupProvider')]
	public function testExpiredStartReturnsOnlyOnceItsKilledGroupIsGone(bool $stopSupervisor): void
	{
		$pgidFile = "{$this->dir}/pgid";
		$script = $this->makeStartScript('group-member.sh',
			"trap '' TERM\n"
			. 'printf %s "$PFB_UNBOUND_START_PGID" > "$1"' . "\n"
			. ($stopSupervisor ? 'kill -STOP "$PFB_UNBOUND_START_PGID"' : ':') . "\n"
			. 'exec sleep 30');

		$run = $this->runIsolatedStart(escapeshellarg($script) . ' ' . escapeshellarg($pgidFile), 1,
			prelude: $this->groupKillPrelude($pgidFile, FALSE));
		$pgid = (int) trim((string) @file_get_contents($pgidFile));
		if ($pgid > 0 && @posix_kill(-$pgid, 0)) {
			posix_kill(-$pgid, 9);
		}

		$this->assertSame(0, $run['status'],
			'the runner must complete inside its salvage cap: ' . implode("\n", $run['output']));
		$this->assertIsArray($run['payload']);
		$this->assertSame(124, $run['payload']['final']['retval'], 'the row must exercise a real start expiry');
		$after = $run['payload']['after'];
		$this->assertSame($pgid, $after['pgid'], 'the runner must report the group the start command ran in');
		$this->assertGreaterThan(0, $pgid, 'the row must observe the supervised group before evaluating cleanup');
		[, $afterKill] = $this->callsAfterGroupKill($after['kill_calls'], $pgid);
		$last = end($afterKill);
		$this->assertSame([-$pgid, 0, FALSE], $last === FALSE ? NULL : array_slice($last, 0, 3),
			'pfb_stop_start_unbound() must not return until a kill() after its group SIGKILL has found '
			. 'the group gone; calls after the KILL: ' . json_encode($afterKill));
		$this->assertFalse($after['group_alive'], 'no member of the SIGKILLed group may exist when the start returns');
	}

	/**
	 * Scenario (issue #3663): the wait after the group SIGKILL is bounded and visible.
	 *   Given an expired start whose group keeps a member the wait never sees go -- the runner's
	 *     own child, which it cannot reap while it is inside the call,
	 *   When pfb_stop_start_unbound() gives up on that member,
	 *   Then it has waited one full PFB_HOOK_KILL_GRACE on the controlled clock, and no longer,
	 *   And it names the group in the error log and still returns the expiry.
	 */
	public function testGroupOutlastingThePostKillWaitIsLoggedAfterOneFullGrace(): void
	{
		$fifo = "{$this->dir}/pgid.fifo";
		$joined = "{$this->dir}/joined";
		$this->assertTrue(posix_mkfifo($fifo, 0600), 'the row needs a FIFO to hand the group id to its joiner');
		$joiner = 'if (!posix_setpgid(0, $pgid = (int) file_get_contents($argv[1]))) { exit(3); } '
			. 'file_put_contents($argv[2], (string) $pgid); sleep(30);';
		$extra = '$joiner = proc_open([PHP_BINARY, \'-r\', ' . var_export($joiner, TRUE) . ', \'--\', '
			. var_export($fifo, TRUE) . ', ' . var_export($joined, TRUE) . "],\n"
			. "\t[0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], \$pipes);\n"
			. <<<'PHP'
$report = $GLOBALS['pfb_test_after_start'];
$GLOBALS['pfb_test_after_start'] = static function () use ($report, $joiner): array {
	$after = $report();
	proc_terminate($joiner, 9);
	proc_close($joiner);
	return $after;
};

PHP;

		$run = $this->runIsolatedStart(
			'printf %s "$PFB_UNBOUND_START_PGID" > ' . escapeshellarg($fifo) . '; exec sleep 30', 1,
			prelude: $this->groupKillPrelude($joined, TRUE, $extra));

		$this->assertSame(0, $run['status'],
			'the runner must complete inside its salvage cap: ' . implode("\n", $run['output']));
		$this->assertIsArray($run['payload']);
		$this->assertSame(124, $run['payload']['final']['retval'], 'the row must exercise a real start expiry');
		$after = $run['payload']['after'];
		$pgid = (int) $after['pgid'];
		$this->assertGreaterThan(0, $pgid, 'the runner child must have joined the supervised group before the expiry');
		[$kill, $afterKill] = $this->callsAfterGroupKill($after['kill_calls'], $pgid);
		$last = end($afterKill);
		$this->assertSame([-$pgid, 0, TRUE], $last === FALSE ? NULL : array_slice($last, 0, 3),
			'the wait must give up on a group it still finds present; calls after the KILL: ' . json_encode($afterKill));
		$graceNs = $after['grace'] * 1_000_000_000;
		$waitedNs = $last[3] - $kill[3];
		$this->assertGreaterThanOrEqual($graceNs, $waitedNs,
			'the wait after the group SIGKILL must last one full PFB_HOOK_KILL_GRACE on the clock before it gives up');
		$this->assertLessThan(2 * $graceNs, $waitedNs,
			'the wait after the group SIGKILL must be bounded by one grace, not run on into another');
		$this->assertStringContainsString("Unbound start process group {$pgid} still present",
			$run['payload']['errlog'], 'a group the wait gives up on must be named in the error log');
	}

	public function testImmediateNonZeroStartPreservesStatusAndOutput(): void
	{
		$script = $this->makeStartScript('nonzero.sh', "echo 'start failed'\nexit 7");

		$run = $this->runIsolatedStart(escapeshellarg($script));

		$this->assertSame(0, $run['status'],
			'the immediate-failure runner must complete inside its salvage cap: ' . implode("\n", $run['output']));
		$this->assertIsArray($run['payload']);
		$this->assertSame(7, $run['payload']['final']['retval'],
			'a quick non-zero start must retain its status for the existing retry branch');
		$this->assertArrayHasKey('start_completed', $run['payload']['final']);
		$this->assertTrue($run['payload']['final']['start_completed'],
			'a quick non-zero command produced a valid completion record');
		$this->assertSame(['start failed'], $run['payload']['final']['result'],
			'a quick non-zero start must retain diagnostics for the existing recovery log');
		$this->assertStringNotContainsString('TIMED OUT', $run['payload']['log'],
			'a quick non-zero exit is a launch failure, not an expiry');
	}

	public function testMissingStartCommandRemainsAnExplicitLaunchFailure(): void
	{
		$run = $this->runIsolatedStart(escapeshellarg("{$this->dir}/missing-unbound") . ' 2>&1');

		$this->assertSame(0, $run['status'],
			'the missing-command runner must complete inside its salvage cap: ' . implode("\n", $run['output']));
		$this->assertIsArray($run['payload']);
		$this->assertSame(127, $run['payload']['final']['retval'],
			'a start command that cannot launch must remain non-zero for retry/recovery');
		$this->assertArrayHasKey('start_completed', $run['payload']['final']);
		$this->assertTrue($run['payload']['final']['start_completed'],
			'a shell-level command-not-found is still a completed start command');
		$this->assertNotEmpty($run['payload']['final']['result'],
			'the launch failure must retain timeout/shell diagnostics');
	}

	public function testCompletedExit124IsNotMisclassifiedAsWrapperExpiry(): void
	{
		$script = $this->makeStartScript('exit-124.sh', 'exit 124');

		$run = $this->runIsolatedStart(escapeshellarg($script));

		$this->assertSame(0, $run['status'],
			'the exit-124 runner must complete inside its salvage cap: ' . implode("\n", $run['output']));
		$this->assertIsArray($run['payload']);
		$this->assertSame(124, $run['payload']['final']['retval']);
		$this->assertArrayHasKey('start_completed', $run['payload']['final']);
		$this->assertTrue($run['payload']['final']['start_completed'],
			'a command that itself exits 124 still produced a valid completion record');
		$this->assertStringNotContainsString('TIMED OUT', $run['payload']['log'],
			'a completed command status 124 must not be mislabeled as wrapper expiry');
	}

	public function testSupervisorExitZeroWithoutDoneIsAnIncompleteFailure(): void
	{
		$startProbe = "{$this->dir}/start-ran";
		$start = $this->makeStartScript('should-not-run.sh',
			'touch ' . escapeshellarg($startProbe) . "\nexit 0");
		$phpCli = $this->makeStartScript('zero-supervisor.sh', 'exit 0');

		$run = $this->runIsolatedStart(escapeshellarg($start), phpCli: $phpCli);

		$this->assertSame(0, $run['status'],
			'the incomplete-supervisor runner must return inside its salvage cap: '
			. implode("\n", $run['output']));
		$this->assertIsArray($run['payload']);
		$this->assertSame(-1, $run['payload']['final']['retval'],
			'a supervisor exit without a valid done record must never look like start success');
		$this->assertArrayHasKey('start_completed', $run['payload']['final']);
		$this->assertFalse($run['payload']['final']['start_completed']);
		$this->assertFileDoesNotExist($startProbe,
			'the configured start command must not be credited when the supervisor never ran it');
	}

	public function testUnstageableOutputIsIncompleteAndNeverRunsStart(): void
	{
		$startProbe = "{$this->dir}/start-ran";
		$start = $this->makeStartScript('unstageable-should-not-run.sh',
			'touch ' . escapeshellarg($startProbe) . "\nexit 0");
		$root = dirname(__DIR__, 2);
		$prelude = "ini_set('open_basedir', implode(PATH_SEPARATOR, array("
			. var_export($root, TRUE) . ', ' . var_export($this->dir, TRUE)
			. ", \$pfb_test_tmp, '/usr', '/bin', '/etc', '/dev', '/proc')));\n";

		$run = $this->runIsolatedStart(
			escapeshellarg($start),
			ini: ['sys_temp_dir=/tmp'],
			prelude: $prelude
		);

		$this->assertSame(0, $run['status'],
			'the staging-failure runner must return inside its salvage cap: ' . implode("\n", $run['output']));
		$this->assertIsArray($run['payload']);
		$this->assertSame(-1, $run['payload']['final']['retval']);
		$this->assertArrayHasKey('start_completed', $run['payload']['final']);
		$this->assertFalse($run['payload']['final']['start_completed']);
		$this->assertFileDoesNotExist($startProbe,
			'an output-staging failure must occur before the configured start command');
	}


}

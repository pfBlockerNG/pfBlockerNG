<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #2613 -- pfb_stop_start_unbound() execs the Unbound daemon and polls for the
 * outgoing process to exit. Both boundaries are named constants (PFB_UNBOUND_START_CMD,
 * PFB_UNBOUND_STOP_WAIT) that tests/php/bootstrap.php overrides before the package loads,
 * so a unit run starts no resolver on a developer box that HAS Unbound installed at the
 * shipped path, and no individual test has to defuse the appliance's 30-poll stop-wait.
 *
 * The shipped appliance values are pinned from source: the harness necessarily replaces
 * both constants for the whole process, so the only place their real values can be
 * asserted is the file that ships them.
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

		// varrun_path holds no unbound.pid, so the TERM half is skipped; the stop-wait
		// loop and the daemon start are what this file exercises.
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
		unset($GLOBALS['pfb_test_process_running'], $GLOBALS['pfb_test_sigkillbyname_calls'],
			$GLOBALS['pfb_test_sigkillbyname_effect']);
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
	 * unbounded wait.
	 *
	 * @return array{status: int, output: list<string>, payload: array<string, mixed>|null}
	 */
	private function runIsolatedStart(
		string $startCommand,
		int $budget = 5,
		?string $phpCli = NULL
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
			. "\$final = pfb_stop_start_unbound('');\n"
			. 'echo json_encode([\'final\' => $final, \'log\' => (string) @file_get_contents('
			. var_export($log, TRUE) . '), \'errlog\' => (string) @file_get_contents('
			. var_export($errlog, TRUE) . ")]), \"\\n\";\n");

		$output = [];
		$status = 0;
		$cmd = 'TMPDIR=' . escapeshellarg($this->dir) . ' ' .
			escapeshellarg($timeout) . ' -s TERM -k 2 ' . self::SALVAGE_SECONDS .
			' ' . escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($runner) . ' 2>&1';
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
		$this->assertNotEmpty($final['result'],
			'the caller logs the start output on failure, so the double must produce one');
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
		$this->assertSame(-1, $final['retval'],
			'the refusal must be reported to the caller as a failure, not a silent success');
		$this->assertNotEmpty($final['result'],
			'the caller logs the result, so the refusal must carry a reason');
		$this->assertSame(array(array('unbound', 'KILL')), $GLOBALS['pfb_test_sigkillbyname_calls'],
			'the timeout must escalate TERM to KILL exactly once before giving up');
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
			'an expired start must surface timeout(1) status 124 so retry/recovery still runs');
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
			'the process-tree expiry must preserve the retry-triggering timeout status');
		$this->assertFalse($launcherAlive,
			'the direct TERM-ignoring launcher must be absent after kill grace');
		$this->assertFalse($helperAlive,
			'RED issue #2882: expiry must kill the launcher process group, not orphan its TERM-ignoring helper');
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
		$this->assertNotEmpty($run['payload']['final']['result'],
			'the launch failure must retain timeout/shell diagnostics');
	}


	/**
	 * The appliance keeps starting the shipped daemon against the shipped config, and
	 * keeps both stop and start waits at 30 seconds -- asserted against the source
	 * because the harness replaces those constants at load time in this process.
	 */
	public function testShippedDefaultsStillStartTheApplianceDaemon(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc';
		$src = (string) @file_get_contents($path);
		$this->assertNotSame('', $src, "could not read {$path}");

		// strpos() rather than assertStringContainsString(): the haystack is the whole
		// 800 KB package file, and a failed containment assertion would dump all of it.
		$this->assertNotFalse(strpos($src,
			"define('PFB_UNBOUND_START_CMD', '/usr/local/sbin/unbound -c /var/unbound/unbound.conf 2>&1');"),
			'the appliance must still start the shipped daemon against the shipped config');
		$this->assertNotFalse(strpos($src, "define('PFB_UNBOUND_STOP_WAIT', 30);"),
			'the appliance must still wait up to 30 seconds for the outgoing daemon');
		$this->assertNotFalse(strpos($src, "define('PFB_UNBOUND_KILL_WAIT', 5);"),
			'the KILL escalation must have its own finite five-second budget');
		$this->assertNotFalse(strpos($src, "define('PFB_UNBOUND_START_WAIT', 30);"),
			'the appliance start child must have an explicit finite 30-second budget');
		$this->assertNotFalse(strpos($src, "define('PFB_UNBOUND_START_SETUP_WAIT', 5);"),
			'the process-group setup barrier must have its own finite five-second budget');

		$start = strpos($src, 'function pfb_stop_start_unbound(');
		$this->assertNotFalse($start, 'pfb_stop_start_unbound() must still exist');
		$end = strpos($src, "\n}\n", $start);
		$this->assertNotFalse($end, 'could not find the end of pfb_stop_start_unbound()');
		$body = substr($src, $start, $end - $start);
		$this->assertStringContainsString('$start_ack_deadline = NULL;', $body,
			'the start-ack deadline must have an explicit unarmed sentinel');
		$this->assertStringContainsString('$deadline = NULL;', $body,
			'the command deadline must have an explicit unarmed sentinel');
		$this->assertStringContainsString('if ($start_ack_deadline === NULL) {', $body,
			'the start-ack loop must fail closed before reading an unarmed deadline');
		$this->assertStringContainsString('if ($deadline === NULL) {', $body,
			'the command loop must fail closed before reading an unarmed deadline');
		$release = strpos($body, '@touch($release)');
		$acknowledged = strpos($body, 'file_exists($command_started)');
		$deadline = strpos($body, '$deadline = hrtime(TRUE) + (PFB_UNBOUND_START_WAIT');
		$this->assertNotFalse($release, 'the parent must explicitly release the verified process group');
		$this->assertNotFalse($acknowledged, 'the child must acknowledge command start after release');
		$this->assertNotFalse($deadline, 'the configured command deadline must be explicit');
		$this->assertGreaterThan($acknowledged, $deadline,
			'the start-command deadline must begin after the child start event, not during supervisor setup');

		$this->assertStringContainsString(
			"\$php_cli = (string) (\$pfb['php'] ?? (PHP_BINDIR . '/php'));",
			$body,
			'the appliance must select the canonical CLI executable without a version hardcode'
		);
		$this->assertStringNotContainsString('PHP_BINARY', $body,
			'the web php-cgi SAPI binary must never launch the CLI-only -r supervisor');
		$this->assertStringContainsString('PFB_UNBOUND_START_CMD', $body,
			'the daemon start must run through the constant so a harness can neuter it');
		$this->assertStringNotContainsString('/usr/local/sbin/unbound', $body,
			'no branch may reach the daemon binary except through PFB_UNBOUND_START_CMD');
		$this->assertStringContainsString('$i <= PFB_UNBOUND_STOP_WAIT;', $body,
			'the stop-wait budget must come from the constant, not a literal');
		$this->assertStringContainsString('$i <= PFB_UNBOUND_KILL_WAIT;', $body,
			'the KILL-escalation budget must come from the constant, not a literal');
		$stopLoop = strpos($body, '$i <= PFB_UNBOUND_STOP_WAIT;');
		$refusal = strpos($body, 'not starting a ');
		$start = strpos($body, 'PFB_UNBOUND_START_CMD,');
		$this->assertNotFalse($refusal, 'the stop timeout must have an explicit refusal branch (#3055)');
		$this->assertNotFalse($start, 'the daemon start must still be reachable');
		$this->assertGreaterThan($stopLoop, $refusal,
			'the refusal must be checked after the stop-wait loop, not inside it');
		$this->assertLessThan($start, $refusal,
			'the refusal must precede the daemon start, or the second instance is already launched');
		$this->assertStringContainsString('posix_setpgid(0, 0)', $body,
			'the start command must enter its own process group before the release barrier opens');
		$this->assertStringContainsString('posix_kill(-$pid', $body,
			'expiry must signal the whole launcher group, not only its direct process');
		$this->assertStringContainsString('PFB_UNBOUND_START_WAIT', $body,
			'the start wait must consume its configured finite budget');
		$this->assertStringContainsString("0 => array('file', '/dev/null', 'r')", $body,
			'the supervised launcher must read from /dev/null');
		$this->assertStringContainsString("1 => array('file', \$outfile, 'a')", $body,
			'a daemon must inherit a regular output file, never proc_open() pipes');
	}
}

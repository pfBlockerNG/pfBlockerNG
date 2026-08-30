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
		foreach (['log', 'errlog', 'dnsbl_python_unmount'] as $key) {
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
		unset($GLOBALS['pfb_test_process_running']);
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
	private function runIsolatedStart(string $startCommand): array
	{
		$id = bin2hex(random_bytes(4));
		$runner = "{$this->dir}/runner_{$id}.php";
		$log = "{$this->dir}/isolated_{$id}.log";
		$errlog = "{$this->dir}/isolated_{$id}.err";
		$timeout = (string) $GLOBALS['pfb']['timeout'];
		$bootstrap = __DIR__ . '/bootstrap.php';
		file_put_contents($runner, "<?php\n"
			. "define('PFB_UNBOUND_START_CMD', " . var_export($startCommand, TRUE) . ");\n"
			. "define('PFB_UNBOUND_STOP_WAIT', 1);\n"
			. "define('PFB_UNBOUND_START_WAIT', 1);\n"
			. "define('PFB_HOOK_KILL_GRACE', 1);\n"
			. 'require ' . var_export($bootstrap, TRUE) . ";\n"
			. '$GLOBALS[\'pfb\'][\'timeout\'] = ' . var_export($timeout, TRUE) . ";\n"
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
		$cmd = escapeshellarg($timeout) . ' -s TERM -k 2 ' . self::SALVAGE_SECONDS
			. ' ' . escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($runner) . ' 2>&1';
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
	 *   Then it polls only the harness budget -- 30 one-second polls per call otherwise.
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
		$this->assertSame(PFB_UNBOUND_STOP_WAIT, $polls,
			'the wait loop must poll exactly its configured budget when the daemon never exits');
	}
	public function testDaemonizedStartSurvivesTheBoundedWrapper(): void
	{
		$pidfile = "{$this->dir}/daemon.pid";
		$script = $this->makeStartScript('daemonize.sh',
			'sleep 30 </dev/null >/dev/null 2>&1 &' . "\n"
			. 'printf \'%s\\n\' "$!" > "$1"' . "\n"
			. 'exit 0');

		$run = $this->runIsolatedStart(escapeshellarg($script) . ' ' . escapeshellarg($pidfile));
		$pid = (int) trim((string) @file_get_contents($pidfile));
		try {
			$this->assertSame(0, $run['status'],
				'stuck/environment: the daemonized start runner exceeded its salvage cap: '
				. implode("\n", $run['output']));
			$this->assertIsArray($run['payload'], 'the isolated start runner must return its JSON result');
			$this->assertSame(0, $run['payload']['final']['retval'],
				'a successfully daemonized start must remain a successful start');
			$this->assertTrue($this->pidIsAlive($pid),
				'--foreground must let the successfully daemonized resolver survive its launcher');
		} finally {
			$this->terminatePid($pid);
		}
		$this->assertFalse($this->pidIsAlive($pid),
			'the daemon-survival row must reap its controlled survivor before returning');
	}

	public function testTermIgnoringStartExpiresObservablyAndLeavesNoProcess(): void
	{
		$pidfile = "{$this->dir}/stuck.pid";
		$script = $this->makeStartScript('term-ignoring.sh',
			'printf \'%s\\n\' "$$" > "$1"' . "\n"
			. 'trap \'\' TERM' . "\n"
			. 'exec sleep 30');

		$run = $this->runIsolatedStart(escapeshellarg($script) . ' ' . escapeshellarg($pidfile));
		$pid = (int) trim((string) @file_get_contents($pidfile));
		$alive = $this->pidIsAlive($pid);
		if ($alive) {
			$this->terminatePid($pid);
		}

		$this->assertSame(0, $run['status'],
			'RED issue #2882: the production start wait exceeded the 8s salvage cap; '
			. 'the direct PFB_UNBOUND_START_CMD child is still unbounded. Output: '
			. implode("\n", $run['output']));
		$this->assertIsArray($run['payload'], 'the bounded start must return its JSON result');
		$this->assertSame(124, $run['payload']['final']['retval'],
			'an expired start must surface timeout(1) status 124 so retry/recovery still runs');
		$this->assertStringContainsString('Unbound Resolver start TIMED OUT after 1s and was killed',
			$run['payload']['log'], 'expiry must be explicit in the main log');
		$this->assertStringContainsString('Unbound Resolver start TIMED OUT after 1s and was killed',
			$run['payload']['errlog'], 'expiry must be explicit in the error log');
		$this->assertFalse($alive,
			'the SIGKILL grace must leave no TERM-ignoring transient start process behind');
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
		$this->assertNotFalse(strpos($src, "define('PFB_UNBOUND_START_WAIT', 30);"),
			'the appliance start child must have an explicit finite 30-second budget');

		$start = strpos($src, 'function pfb_stop_start_unbound(');
		$this->assertNotFalse($start, 'pfb_stop_start_unbound() must still exist');
		$end = strpos($src, "\n}\n", $start);
		$this->assertNotFalse($end, 'could not find the end of pfb_stop_start_unbound()');
		$body = substr($src, $start, $end - $start);

		$this->assertStringContainsString('PFB_UNBOUND_START_CMD', $body,
			'the daemon start must run through the constant so a harness can neuter it');
		$this->assertStringNotContainsString('/usr/local/sbin/unbound', $body,
			'no branch may reach the daemon binary except through PFB_UNBOUND_START_CMD');
		$this->assertStringContainsString('$i <= PFB_UNBOUND_STOP_WAIT;', $body,
			'the stop-wait budget must come from the constant, not a literal');
		$this->assertStringContainsString('--foreground -s TERM -k ', $body,
			'the start wait must let a daemonized resolver survive and still kill a stuck launcher');
		$this->assertStringContainsString('PFB_UNBOUND_START_WAIT', $body,
			'the start wait must consume its configured finite budget');
		$this->assertStringContainsString(' 2>&1 < /dev/null', $body,
			'a daemon must inherit a regular output file, never exec() capture pipes');
	}
}

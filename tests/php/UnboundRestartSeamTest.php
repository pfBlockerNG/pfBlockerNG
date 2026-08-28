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

	/**
	 * The appliance keeps starting the shipped daemon against the shipped config, and
	 * keeps waiting the full 30 seconds for the old one -- asserted against the source
	 * because the harness replaces both constants at load time in this process.
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

		$start = strpos($src, 'function pfb_stop_start_unbound(');
		$this->assertNotFalse($start, 'pfb_stop_start_unbound() must still exist');
		$end = strpos($src, "\n}\n", $start);
		$this->assertNotFalse($end, 'could not find the end of pfb_stop_start_unbound()');
		$body = substr($src, $start, $end - $start);

		$this->assertStringContainsString('exec(PFB_UNBOUND_START_CMD,', $body,
			'the daemon start must run through the constant so a harness can neuter it');
		$this->assertStringNotContainsString('/usr/local/sbin/unbound', $body,
			'no branch may reach the daemon binary except through PFB_UNBOUND_START_CMD');
		$this->assertStringContainsString('$i <= PFB_UNBOUND_STOP_WAIT;', $body,
			'the stop-wait budget must come from the constant, not a literal');
	}
}

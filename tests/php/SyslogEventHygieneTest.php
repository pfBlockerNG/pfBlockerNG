<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/SyslogEventTest.php';

/**
 * Issue #2046: SyslogEventTest must isolate and restore every global in its
 * config/syslog test seam, including globals that were absent before a test.
 */
final class SyslogEventHygieneTest extends TestCase
{
	/** @var array<string, array{had: bool, value: mixed}> */
	private array $outerState = [];

	protected function setUp(): void
	{
		$this->outerState = $this->snapshotOwnedGlobals();
	}

	protected function tearDown(): void
	{
		$this->restoreOwnedGlobals($this->outerState);
	}

	public function testLifecycleRestoresAbsentOwnedGlobals(): void
	{
		$this->clearOwnedGlobals();

		try {
			$this->runLifecycle();

			foreach ($this->ownedGlobalNames() as $name) {
				$this->assertArrayNotHasKey(
					$name,
					$GLOBALS,
					"absent outer state: {$name} must remain absent after SyslogEvent lifecycle"
				);
			}
		} finally {
			$this->restoreOwnedGlobals($this->outerState);
		}
	}

	public function testLifecycleRestoresForeignOwnedGlobalSentinels(): void
	{
		$sentinels = [
			'config'                => ['foreign_config_2046' => ['state' => 'untouched']],
			'pfb_test_syslog_spy'   => 'foreign-spy-2046',
			'pfb_test_syslog_calls' => ['foreign-call-2046'],
			'pfb_test_syslog_reset' => 'foreign-reset-2046',
		];
		foreach ($sentinels as $name => $value) {
			$GLOBALS[$name] = $value;
		}

		try {
			$this->runLifecycle();

			foreach ($sentinels as $name => $sentinel) {
				$this->assertArrayHasKey(
					$name,
					$GLOBALS,
					"foreign outer state: {$name} must be present after SyslogEvent lifecycle"
				);
				$this->assertSame(
					$sentinel,
					$GLOBALS[$name],
					"foreign outer state: {$name} value must be restored exactly"
				);
			}
		} finally {
			$this->restoreOwnedGlobals($this->outerState);
		}
	}

	/** Drive one real SyslogEventTest setUp()+test()+tearDown() cycle. */
	private function runLifecycle(): void
	{
		$suite = new SyslogEventTest('testToggleOnEmitsExactlyOneCallWithCorrectBody');
		$ref   = new ReflectionClass($suite);
		$setUp = $ref->getMethod('setUp');
		$test  = $ref->getMethod('testToggleOnEmitsExactlyOneCallWithCorrectBody');
		$tear  = $ref->getMethod('tearDown');
		$setUpComplete = false;

		try {
			$setUp->invoke($suite);
			$setUpComplete = true;

			$this->assertSame([], $GLOBALS['config'] ?? null, 'lifecycle: config root must be exactly []');
			$this->assertSame(TRUE, $GLOBALS['pfb_test_syslog_spy'] ?? null, 'lifecycle: syslog spy must be TRUE');
			$this->assertSame([], $GLOBALS['pfb_test_syslog_calls'] ?? null, 'lifecycle: syslog calls must be []');
			$this->assertArrayNotHasKey('pfb_test_syslog_reset', $GLOBALS, 'lifecycle: reset flag must be absent');

			$test->invoke($suite);
		} finally {
			if ($setUpComplete) {
				$tear->invoke($suite);
			}
		}
	}

	/** @return list<string> */
	private function ownedGlobalNames(): array
	{
		return ['config', 'pfb_test_syslog_spy', 'pfb_test_syslog_calls', 'pfb_test_syslog_reset'];
	}

	/** @return array<string, array{had: bool, value: mixed}> */
	private function snapshotOwnedGlobals(): array
	{
		$snapshot = [];
		foreach ($this->ownedGlobalNames() as $name) {
			$snapshot[$name] = [
				'had'   => array_key_exists($name, $GLOBALS),
				'value' => $GLOBALS[$name] ?? null,
			];
		}
		return $snapshot;
	}

	private function clearOwnedGlobals(): void
	{
		foreach ($this->ownedGlobalNames() as $name) {
			unset($GLOBALS[$name]);
		}
	}

	/** @param array<string, array{had: bool, value: mixed}> $snapshot */
	private function restoreOwnedGlobals(array $snapshot): void
	{
		foreach ($snapshot as $name => $state) {
			if ($state['had']) {
				$GLOBALS[$name] = $state['value'];
			} else {
				unset($GLOBALS[$name]);
			}
		}
	}
}

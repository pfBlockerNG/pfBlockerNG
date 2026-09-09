<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/ProcessRunner.php';

final class UnboundControlFixturePortabilityTest extends TestCase
{
	public function testRestartFixturesReachTheirAssertionsOnTheHostToolchain(): void
	{
		$root = dirname(__DIR__, 2);
		$result = pfb_test_run_process([
			(string) $GLOBALS['pfb']['timeout'], '-s', 'TERM', '-k', '5', '90',
			PHP_BINARY,
			"{$root}/vendor/bin/phpunit",
			'--configuration', "{$root}/phpunit.xml",
			'--do-not-cache-result',
			'--fail-on-empty-test-suite',
			'--fail-on-skipped',
			'--filter', 'testStatusMustSucceedEvenWhenItsOutputSaysRunning|testUnstageableCacheDumpStillRestartsTheResolver',
			__DIR__ . '/UnboundControlIpcBoundTest.php',
		], 100.0);

		$this->assertSame(0, $result['exit'],
			"restart fixtures must reach their control assertions rather than fail host setup:\n"
			. $result['stdout'] . $result['stderr']);
	}
}

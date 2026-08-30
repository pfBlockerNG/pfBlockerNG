<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/TickExtrasOrderingTest.php';
require_once __DIR__ . '/Issue1840SuppUpdateNullPostinstallTest.php';

final class Issue1840SuppUpdateNullPostinstallAbsentGlobalIsolationTest extends TestCase
{
	public function testTickExtrasRestoresAbsentGlobalG(): void
	{
		$this->assertRestoresAbsentGlobalG(
			new TickExtrasOrderingTest('testDueExtrasRunDccThenBlThenFeedAndIgnoreApplyWindow'),
			"TickExtrasOrderingTest::tearDown() must leave absent \$GLOBALS['g'] absent"
		);
	}

	public function testIssue1840RestoresAbsentGlobalG(): void
	{
		$this->assertRestoresAbsentGlobalG(
			new Issue1840SuppUpdateNullPostinstallTest('testPostInstallResyncDoesNotCrashOnNullSuppUpdateV4'),
			"Issue1840SuppUpdateNullPostinstallTest::tearDown() must leave absent \$GLOBALS['g'] absent"
		);
	}

	private function assertRestoresAbsentGlobalG(TestCase $fixture, string $message): void
	{
		$hadPfb = array_key_exists('pfb', $GLOBALS);
		$originalPfb = $GLOBALS['pfb'] ?? NULL;
		$hadConfig = array_key_exists('config', $GLOBALS);
		$originalConfig = $GLOBALS['config'] ?? NULL;
		$hadG = array_key_exists('g', $GLOBALS);
		$originalG = $GLOBALS['g'] ?? NULL;

		try {
			unset($GLOBALS['g']);
			$setUp = new ReflectionMethod($fixture, 'setUp');
			$tearDown = new ReflectionMethod($fixture, 'tearDown');

			try {
				$setUp->invoke($fixture);
				$GLOBALS['g'] = ['hostile_sentinel' => 'must be removed'];
			} finally {
				$tearDown->invoke($fixture);
			}

			$this->assertArrayNotHasKey('g', $GLOBALS, $message);
		} finally {
			if ($hadPfb) {
				$GLOBALS['pfb'] = $originalPfb;
			} else {
				unset($GLOBALS['pfb']);
			}
			if ($hadConfig) {
				$GLOBALS['config'] = $originalConfig;
			} else {
				unset($GLOBALS['config']);
			}
			if ($hadG) {
				$GLOBALS['g'] = $originalG;
			} else {
				unset($GLOBALS['g']);
			}
		}
	}
}

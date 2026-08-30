<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/TickExtrasOrderingTest.php';
require_once __DIR__ . '/Issue1840SuppUpdateNullPostinstallTest.php';

final class Issue1840SuppUpdateNullPostinstallFixtureIsolationTest extends TestCase
{
	public function testTickExtrasRestoresWholeGlobalG(): void
	{
		$hadPfb = array_key_exists('pfb', $GLOBALS);
		$originalPfb = $GLOBALS['pfb'] ?? NULL;
		$hadConfig = array_key_exists('config', $GLOBALS);
		$originalConfig = $GLOBALS['config'] ?? NULL;
		$hadG = array_key_exists('g', $GLOBALS);
		$originalG = $GLOBALS['g'] ?? NULL;
		$incomingG = [
			'pfblockerng_install' => FALSE,
			'unbound_chroot_path' => '/sentinel/tick-extras',
			'unrelated_sentinel' => ['keep' => 'exactly'],
		];

		try {
			$GLOBALS['g'] = $incomingG;
			$fixture = new TickExtrasOrderingTest('testDueExtrasRunDccThenBlThenFeedAndIgnoreApplyWindow');
			$setUp = new ReflectionMethod($fixture, 'setUp');
			$tearDown = new ReflectionMethod($fixture, 'tearDown');

			try {
				$setUp->invoke($fixture);
			} finally {
				$tearDown->invoke($fixture);
			}

			$this->assertSame(
				$incomingG,
				$GLOBALS['g'] ?? NULL,
				"TickExtrasOrderingTest::tearDown() must restore the exact incoming \$GLOBALS['g'] array"
			);
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

	public function testIssue1840SeedsClearedPostinstallerGlobalsAndRestoresWholeGlobalG(): void
	{
		$hadPfb = array_key_exists('pfb', $GLOBALS);
		$originalPfb = $GLOBALS['pfb'] ?? NULL;
		$hadConfig = array_key_exists('config', $GLOBALS);
		$originalConfig = $GLOBALS['config'] ?? NULL;
		$hadG = array_key_exists('g', $GLOBALS);
		$originalG = $GLOBALS['g'] ?? NULL;
		$incomingG = [
			'unbound_chroot_path' => '/sentinel/issue1840',
			'unrelated_sentinel' => ['keep' => 'exactly'],
		];

		try {
			$GLOBALS['g'] = $incomingG;
			$fixture = new Issue1840SuppUpdateNullPostinstallTest('testPostInstallResyncDoesNotCrashOnNullSuppUpdateV4');
			$setUp = new ReflectionMethod($fixture, 'setUp');
			$tearDown = new ReflectionMethod($fixture, 'tearDown');

			try {
				$setUp->invoke($fixture);
				$this->assertSame(
					FALSE,
					$GLOBALS['g']['pfblockerng_install'] ?? NULL,
					'Issue1840SuppUpdateNullPostinstallTest::setUp() must seed cleared pfblockerng_install FALSE'
				);
				$this->assertSame(
					'/var/unbound',
					$GLOBALS['g']['unbound_chroot_path'] ?? NULL,
					'Issue1840SuppUpdateNullPostinstallTest::setUp() must force unbound_chroot_path to /var/unbound'
				);
			} finally {
				$tearDown->invoke($fixture);
			}

			$this->assertSame(
				$incomingG,
				$GLOBALS['g'] ?? NULL,
				"Issue1840SuppUpdateNullPostinstallTest::tearDown() must restore the exact incoming \$GLOBALS['g'] array"
			);
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

<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class Top1mTeardownWiringTest extends TestCase
{
	public function testTeardownCallRunsInjectedEffect(): void
	{
		$calls = 0;
		$this->assertTrue(pfb_top1m_teardown_call(static function () use (&$calls): bool {
			$calls++;
			return TRUE;
		}));
		$this->assertSame(1, $calls, 'the teardown seam must invoke its effect exactly once');
	}

	/**
	 * The sync and pre-deinstall entrypoints are appliance-only procedural flows. Keep this
	 * wiring pin code-only so comments/docblocks cannot satisfy it; the seam above proves the
	 * observable teardown effect.
	 */
	public function testDisableAndUninstallWireTheSharedTeardown(): void
	{
		$apply = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$inc = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$this->assertStringContainsString('pfb_top1m_teardown_call();', $apply,
			'DNSBL disable must invoke the shared TOP1M teardown seam');
		$this->assertMatchesRegularExpression(
			'/sync_package_pfblockerng\(\);\s*pfb_top1m_teardown_call\(\);/',
			$inc,
			'package removal must tear down retained TOP1M runtime state after the disable pass'
		);
	}
}

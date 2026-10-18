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
		// The teardown removes the manifest and raw lists a restarted DNS proxy loads its blocklists from: the removal reaches it
		// only past the abort check ahead of the disable pass, so a removal that stops (DnsProxyUninstallAbortTest) never runs it.
		$this->assertMatchesRegularExpression(
			'/if \(!pfb_dns_proxy_deinstall\(\)\) \{\s*return pfb_package_removal_stopped\(\);\s*\}.*?sync_package_pfblockerng\(\);\s*if \(!pfb_dns_proxy_deinstall\(\)\) \{\s*return pfb_package_removal_stopped\(\);\s*\}\s*pfb_top1m_teardown_call\(\);/s',
			$inc,
			'package removal must put the Resolver back before the disable pass and tear down retained TOP1M runtime state after it, once the removal is going ahead'
		);
	}
}

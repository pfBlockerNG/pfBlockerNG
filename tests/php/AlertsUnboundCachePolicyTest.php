<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #1615 -- Alerts generation changes flush only allow-to-block deltas:
 * exact names target one cache entry; wildcard removals flush the full cache.
 */
final class AlertsUnboundCachePolicyTest extends TestCase
{
	private static string $source;

	public static function setUpBeforeClass(): void
	{
		self::$source = (string) file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_alerts.php'
		);
	}

	private function region(string $startMarker, string $endMarker): string
	{
		$start = strpos(self::$source, $startMarker);
		$end = strpos(self::$source, $endMarker, $start === FALSE ? 0 : $start);

		$this->assertNotFalse($start, "missing Alerts source marker: {$startMarker}");
		$this->assertNotFalse($end, "missing Alerts source marker: {$endMarker}");

		return substr(self::$source, $start, $end - $start);
	}

	private function assertOrdered(string $region, string $reload, string $flush): void
	{
		$reloadAt = strpos($region, $reload);
		$flushAt = strpos($region, $flush);
		$this->assertNotFalse($reloadAt, "missing reload: {$reload}");
		$this->assertNotFalse($flushAt, "missing targeted flush: {$flush}");
		$this->assertTrue($reloadAt < $flushAt, 'targeted cache flush must run after reload returns');
	}

	public function testKnownAllowToBlockChangesFlushTheirFiniteNameSetAfterReload(): void
	{
		$this->assertOrdered(
			$this->region('// Add Domain to DNSBL Customlist', '// Add Domain/CNAME(s) to the DNSBL Whitelist'),
			"pfb_reload_unbound('enabled', FALSE, TRUE, TRUE);",
			'pfb_unbound_py_ccache_flush(array($domain));'
		);
		$this->assertOrdered(
			$this->region("if (\$_POST['entry_delete'] == 'delete_domainwildcard')", '// Unlock/Lock DNSBL events'),
			"pfb_reload_unbound('enabled', FALSE, FALSE, TRUE);",
			'pfb_unbound_py_ccache_flush(array($entry));'
		);
		$this->assertOrdered(
			$this->region('// Unlock/Lock DNSBL events', '// sprintf with the (domain-filtered'),
			"pfb_reload_unbound('enabled', FALSE, FALSE, TRUE);",
			'pfb_unbound_py_ccache_flush(array($domain));'
		);
	}

	public function testWildcardWhitelistRemovalFlushesFullCacheAfterSuccessfulSwap(): void
	{
		$delete = $this->region('// Delete entry from customlists', '// Unlock/Lock DNSBL events');

		$this->assertOrdered(
			$delete,
			'$swapped = pfb_reload_unbound(\'enabled\', FALSE, FALSE, TRUE);',
			'exec("{$pfb[\'chroot_cmd\']} flush_zone +c . 2>&1");'
		);
		$this->assertStringContainsString('if ($swapped)', $delete,
			'cache work must be skipped when reload falls back to a full restart');
		$this->assertSame(1, substr_count(self::$source, 'flush_zone +c .'));
	}

	public function testBlockToAllowAlertsChangesDoNotFlushUnboundCache(): void
	{
		$whitelist = $this->region(
			'// Add Domain/CNAME(s) to the DNSBL Whitelist',
			'// Save Domain/CNAME(s) to the TLD Exclusion customlist'
		);
		$unlock = $this->region('// Unlock/Lock DNSBL events', '// sprintf with the (domain-filtered');

		$this->assertStringNotContainsString('flush {$domain_esc}', $whitelist);
		$this->assertStringNotContainsString('if ($action == \'unlock\')', $unlock);
		$this->assertSame(
			4,
			preg_match_all('/pfb_reload_unbound\([^;]+,\s*TRUE\);/', self::$source),
			'new Alerts datapath callers need an explicit exact-name cache policy'
		);
	}
}

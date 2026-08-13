<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class GeoipSwapConsumerGuardTest extends TestCase
{
	private string $dir;
	private array $savedPfb;

	protected function setUp(): void
	{
		$this->savedPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_geoip_swap_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
		file_put_contents($this->dir . '/.pfb_generation_swapping', 'pending');
		$GLOBALS['pfb']['ccdir'] = $this->dir;
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->savedPfb;
		rmdir_recursive($this->dir);
	}

	public function testBatchedGeoipDeferralIsNotCacheableAsUnknown(): void
	{
		$failed = [];
		$this->assertSame(
			['192.0.2.1' => ['Unknown', 'Unknown']],
			pfb_find_reported_headers(['192.0.2.1'], $this->dir . '/*.txt', TRUE, $failed)
		);
		$this->assertSame(['192.0.2.1' => TRUE], $failed);
	}

	public function testProductionAlertsAndDaemonCarryTheSwapGuard(): void
	{
		$root = dirname(__DIR__, 2);
		$alerts = php_strip_whitespace($root . '/src/usr/local/www/pfblockerng/pfblockerng_alerts.php');
		$inc = php_strip_whitespace($root . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$this->assertStringContainsString("'pfb_geoip' => \$ip_rq['pfb_geoip']", $alerts);
		$this->assertStringContainsString('$geoip_deferred = $geoip_folder && !pfb_geoip_generation_ready();', $inc);
		$this->assertStringContainsString('if (!$geoip_deferred) { $db_update = "INSERT into ipcache', $inc);
	}
}

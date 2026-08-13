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
		$this->assertStringContainsString('$geoip_lock = $geoip_folder ? pfb_geoip_generation_read_lock() : FALSE;', $inc);
		$this->assertStringContainsString('$geoip_deferred = $geoip_folder && $geoip_lock === FALSE;', $inc);
		$this->assertStringContainsString('if (!$geoip_deferred) { $db_update = "INSERT into ipcache', $inc);
		$this->assertStringContainsString('pfb_geoip_generation_read_unlock($geoip_lock);', $inc);
	}

	public function testCountryPublicationHoldsExclusiveLockUntilSentinelRemoval(): void
	{
		$source = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php'
		);
		$lock = strpos($source, '$publication_lock = pfb_geoip_generation_publication_lock($live_ccdir);');
		$sentinel = strpos($source, 'file_put_contents($swap_sentinel, $generation, LOCK_EX)');
		$remove = strrpos($source, 'unlink_if_exists($swap_sentinel);');
		$unlock = strrpos($source, 'pfb_geoip_generation_publication_unlock($publication_lock);');
		$this->assertIsInt($lock);
		$this->assertIsInt($sentinel);
		$this->assertIsInt($remove);
		$this->assertIsInt($unlock);
		$this->assertLessThan($sentinel, $lock);
		$this->assertLessThan($remove, $sentinel);
		$this->assertLessThan($unlock, $remove);
	}

	public function testDirectReaderBlocksAnExclusiveSwapForTheWholeLookup(): void
	{
		unlink($this->dir . '/.pfb_generation_swapping');
		$probe = $this->dir . '/exclusive-probe';
		$feed = $this->dir . '/Europe_v4.txt';
		file_put_contents($feed, "192.0.2.1\n");
		$GLOBALS['pfb']['grep'] = $this->lockingGrep($probe, "{$feed}:192.0.2.1");

		$this->assertSame(['Europe_v4', '192.0.2.1'], find_reported_header('192.0.2.1', "{$this->dir}/*.txt", TRUE));
		$this->assertSame('blocked', trim((string) file_get_contents($probe)));
	}

	public function testPrefetchDoesNotMemoizeWhilePublisherOwnsLock(): void
	{
		unlink($this->dir . '/.pfb_generation_swapping');
		$invoked = $this->dir . '/prefetch-invoked';
		$GLOBALS['pfb']['grep'] = $this->markerGrep($invoked);
		$GLOBALS['pfb']['aliasdir'] = $this->dir;
		$row = [
			'host' => '192.0.2.1',
			'folder' => "{$this->dir}/*.txt",
			'pfb_geoip' => TRUE,
			'eval_ip_raw' => '192.0.2.1',
			'validate_file_cmd' => "/usr/bin/find {$this->dir} -type f",
			'validate_cmd' => NULL,
		];
		$lock = fopen($this->dir . '/.pfb_generation.lock', 'c');
		$this->assertIsResource($lock);
		$this->assertTrue(flock($lock, LOCK_EX));
		pfb_ip_render_memos_reset();

		try {
			pfb_ip_prefetch([$row]);
			$this->assertSame(['validate' => [], 'miss' => []], pfb_ip_render_memos());
			$this->assertFileDoesNotExist($invoked);
		} finally {
			flock($lock, LOCK_UN);
			fclose($lock);
			pfb_ip_render_memos_reset();
		}
	}

	private function lockingGrep(string $probe, string $match): string
	{
		$path = $this->dir . '/grep-locking';
		$code = '$f=fopen($argv[1],"c"); $ok=$f !== false && @flock($f,LOCK_EX|LOCK_NB); file_put_contents($argv[2],$ok ? "acquired" : "blocked"); if ($ok) { flock($f,LOCK_UN); } echo $argv[3],"\n";';
		$script = "#!/bin/sh\n" . escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code) . ' '
			. escapeshellarg($this->dir . '/.pfb_generation.lock') . ' ' . escapeshellarg($probe) . ' '
			. escapeshellarg($match) . "\n";
		file_put_contents($path, $script);
		chmod($path, 0700);
		return $path;
	}

	private function markerGrep(string $marker): string
	{
		$path = $this->dir . '/grep-marker';
		file_put_contents($path, "#!/bin/sh\ntouch " . escapeshellarg($marker) . "\nexit 1\n");
		chmod($path, 0700);
		return $path;
	}
}

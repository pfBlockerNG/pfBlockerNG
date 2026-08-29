<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class GeoipPublicationLockTest extends TestCase
{
	private string $dir;
	private mixed $savedPfb;
	private mixed $savedContinents;

	protected function setUp(): void
	{
		$this->savedPfb = $GLOBALS['pfb'];
		$this->savedContinents = $GLOBALS['continents'] ?? NULL;
		$this->dir = sys_get_temp_dir() . '/pfb_geoip_lock_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
		$GLOBALS['pfb']['ccdir'] = $this->dir;
		$GLOBALS['continents'] = ['pfB_Europe' => 0];
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->savedPfb;
		if ($this->savedContinents === NULL) {
			unset($GLOBALS['continents']);
		} else {
			$GLOBALS['continents'] = $this->savedContinents;
		}
		rmdir_recursive($this->dir);
	}

	public function testDirectAndBatchedReadersFailClosedWhilePublisherOwnsLock(): void
	{
		$invoked = $this->dir . '/reader-invoked';
		$GLOBALS['pfb']['grep'] = $this->probeGrep($invoked);
		$lock = fopen($this->dir . '/.pfb_generation.lock', 'c');
		$this->assertIsResource($lock);
		$this->assertTrue(flock($lock, LOCK_EX));

		try {
			$this->assertSame(['Unknown', 'Unknown'], find_reported_header('192.0.2.1', '/dev/null', TRUE));
			$failed = [];
			$this->assertSame(
				['192.0.2.1' => ['Unknown', 'Unknown']],
				pfb_find_reported_headers(['192.0.2.1'], '/dev/null', TRUE, $failed)
			);
			$this->assertSame(['192.0.2.1' => TRUE], $failed);
			$this->assertFileDoesNotExist($invoked);
		} finally {
			flock($lock, LOCK_UN);
			fclose($lock);
		}
	}

	public function testAlertsReaderDoesNotMemoizeDuringPublicationLock(): void
	{
		$invoked = $this->dir . '/alerts-reader-invoked';
		$GLOBALS['pfb']['grep'] = $this->probeGrep($invoked);
		$fields = array_fill(0, 18, '');
		$fields[3] = 'block';
		$fields[4] = 4;
		$fields[7] = '192.0.2.1';
		$fields[11] = 'in';
		$fields[13] = 'pfB_Europe_v4';
		$fields[14] = '192.0.2.1';
		$fields[15] = 'Europe_v4';
		pfb_ip_render_memos_reset();
		$lock = fopen($this->dir . '/.pfb_generation.lock', 'c');
		$this->assertIsResource($lock);
		$this->assertTrue(flock($lock, LOCK_EX));

		try {
			$result = pfb_ip_render_attribution($fields);
			$this->assertSame('Not listed!', $result['feed_new']);
			$this->assertSame(['validate' => [], 'miss' => []], pfb_ip_render_memos());
			$this->assertFileDoesNotExist($invoked);
		} finally {
			flock($lock, LOCK_UN);
			fclose($lock);
			pfb_ip_render_memos_reset();
		}
	}

	public function testReaderKeepsSharedLockAcrossLookupInsteadOfAllowingSwapABA(): void
	{
		$probe = $this->dir . '/exclusive-probe';
		$GLOBALS['pfb']['grep'] = $this->lockProbeGrep($probe);
		$this->assertSame(['Unknown', 'Unknown'], find_reported_header('192.0.2.1', '/dev/null', TRUE));
		$this->assertSame('blocked', trim((string) file_get_contents($probe)));
	}

	private function probeGrep(string $marker): string
	{
		$path = $this->dir . '/grep-probe';
		$script = "#!/bin/sh\ntouch " . escapeshellarg($marker) . "\nexit 1\n";
		file_put_contents($path, $script);
		chmod($path, 0700);
		return $path;
	}

	private function lockProbeGrep(string $marker): string
	{
		$path = $this->dir . '/grep-lock-probe';
		$lock = $this->dir . '/.pfb_generation.lock';
		$php = escapeshellarg(PHP_BINARY);
		$lockArg = escapeshellarg($lock);
		$markerArg = escapeshellarg($marker);
		$code = '$f=fopen($argv[1],"c"); $ok=$f !== false && @flock($f,LOCK_EX|LOCK_NB); file_put_contents($argv[2], $ok ? "acquired" : "blocked"); if ($ok) { flock($f, LOCK_UN); }';
		$script = "#!/bin/sh\n{$php} -r " . escapeshellarg($code) . " {$lockArg} {$markerArg}\nexit 1\n";
		file_put_contents($path, $script);
		chmod($path, 0700);
		return $path;
	}
}

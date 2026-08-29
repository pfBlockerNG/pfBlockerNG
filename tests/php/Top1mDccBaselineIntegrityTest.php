<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #1542 — TOP1M detector must not trust an incomplete or stale baseline.
 */
final class Top1mDccBaselineIntegrityTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		self::loadWwwDccHelpers();
		$this->dir = sys_get_temp_dir() . '/pfb_top1m_baseline_' . getmypid() . '_' . uniqid();
		$this->assertTrue(mkdir($this->dir, 0777, TRUE));
	}

	protected function tearDown(): void
	{
		if (is_dir($this->dir)) {
			$it = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator($this->dir, FilesystemIterator::SKIP_DOTS),
				RecursiveIteratorIterator::CHILD_FIRST
			);
			foreach ($it as $file) {
				$file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
			}
			rmdir($this->dir);
		}
	}

	public function testDetectorRejectsRawHashMismatch(): void
	{
		$base = $this->dir . '/top-1m.csv.zip';
		$raw = "{$base}.orig";
		$body = "1,example.test\n";
		$this->assertNotFalse(file_put_contents($raw, $body));
		$this->assertTrue(pfb_hash_write($base, $raw));

		$this->assertNotFalse(file_put_contents($raw, "1,changed.test\n"));
		$this->assertSame(
			'changed',
			pfb_top1m_detector_decision(TRUE, '304', FALSE, '', $base, TRUE, TRUE),
			'304 must not skip when raw baseline no longer matches its sidecar'
		);

	}

	public function testDetectorRequires304ValidatorButAllowsSame200Body(): void
	{
		$base = $this->dir . '/top-1m.csv.zip';
		$raw = "{$base}.orig";
		$body = "1,example.test\n";
		$body_hash = pfb_content_hash($body, FALSE);
		$this->assertNotFalse(file_put_contents($raw, $body));
		$this->assertTrue(pfb_hash_write($base, $raw));

		$this->assertSame(
			'unchanged',
			pfb_top1m_detector_decision(TRUE, '200', $body_hash, '', $base, TRUE, FALSE),
			'200 same body may remain unchanged without HTTP validators'
		);
		$this->assertSame(
			'changed',
			pfb_top1m_detector_decision(TRUE, '200', pfb_content_hash("1,changed.example\n", FALSE), '', $base, TRUE, FALSE),
			'200 changed body must trigger re-ingest even without HTTP validators'
		);
		$this->assertSame(
			'changed',
			pfb_top1m_detector_decision(TRUE, '304', FALSE, '', $base, TRUE, TRUE),
			'304 must not skip without a usable persisted validator'
		);

		$this->assertNotFalse(file_put_contents("{$base}.orig.etag", '"etag-v1"'));
		$this->assertSame(
			'unchanged',
			pfb_top1m_detector_decision(TRUE, '304', FALSE, '', $base, TRUE, TRUE),
			'304 with a persisted ETag may remain unchanged'
		);
	}

	private static function loadWwwDccHelpers(): void
	{
		if (function_exists('pfb_top1m_detector_decision')) {
			return;
		}
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php');
		if ($source === FALSE) {
			self::fail('failed to read pfblockerng.php');
		}
		$start = strpos($source, "\nfunction pfb_top1m_detector_decision");
		$end = strpos($source, "\nfunction pfblockerng_download_extras", $start === FALSE ? 0 : $start);
		if ($start === FALSE || $end === FALSE || $end <= $start) {
			self::fail('could not locate extracted TOP1M helper block');
		}
		eval("\n" . substr($source, $start + 1, $end - $start - 1));
	}
}

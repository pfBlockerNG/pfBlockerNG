<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** ET-IQRisk publication orders gunzip, newline normalization, then ET consumer. */
final class GunzipTrailingNewlineWiringTest extends TestCase
{
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	private string $dir;

	public static function setUpBeforeClass(): void
	{
		require_once dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	}

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb gunzip; ' . getmypid() . " 'fixture'";
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->dir}/*") ?: [] as $path) {
			@unlink($path);
		}
		@rmdir($this->dir);
	}

	public function testGunzipPipelineTerminatesBeforeEtConsumer(): void
	{
		$raw = "{$this->dir}/feed; 'raw'";
		$orig = "{$this->dir}/feed.orig";
		$events = [];
		$this->assertNotFalse(file_put_contents($raw, (string) gzencode('iprep-data')));

		$this->assertTrue(pfb_apply_gunzip_orig_pipeline($raw, $orig,
			static function (string $published) use (&$events): void {
				$events[] = is_file($published) ? (string) file_get_contents($published) : 'missing';
			}
		));

		$this->assertSame(["iprep-data\n"], $events);
		$this->assertSame("iprep-data\n", file_get_contents($orig));
	}

	public function testGunzipFailurePreservesLegacyEtConsumerAttempt(): void
	{
		$raw = "{$this->dir}/bad.raw";
		$orig = "{$this->dir}/bad.orig";
		$events = [];
		$this->assertNotFalse(file_put_contents($raw, 'not-gzip'));

		$this->assertFalse(pfb_apply_gunzip_orig_pipeline($raw, $orig,
			static function () use (&$events): void { $events[] = 'consume'; }
		));

		$this->assertSame(['consume'], $events);
		$this->assertFileExists($raw);
		$this->assertFileExists($orig);
	}

	public function testMissingRawStillRunsLegacyEtConsumer(): void
	{
		$events = [];
		$this->assertFalse(pfb_apply_gunzip_orig_pipeline("{$this->dir}/missing.raw", "{$this->dir}/missing.orig",
			static function () use (&$events): void { $events[] = 'consume'; }
		));
		$this->assertSame(['consume'], $events);
	}

	/** The ET reuse path lives in the #993 sync monolith; behavior runs above. */
	public function testSyncPassDispatchesTheGunzipPublicationPipeline(): void
	{
		$source = php_strip_whitespace(self::APPLY);
		$start = strpos($source, 'function sync_package_pfblockerng(');
		$this->assertNotFalse($start);
		$this->assertSame(1, substr_count(substr($source, $start), 'pfb_apply_gunzip_orig_pipeline('));
	}
}

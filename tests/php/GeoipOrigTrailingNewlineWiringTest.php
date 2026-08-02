<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** GeoIP publication orders rename, newline normalization, mirror, then consumer. */
final class GeoipOrigTrailingNewlineWiringTest extends TestCase
{
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	private string $dir;

	public static function setUpBeforeClass(): void
	{
		require_once dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	}

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb geoip; ' . getmypid() . " 'fixture'";
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->dir}/*") ?: [] as $path) {
			@unlink($path);
		}
		@rmdir($this->dir);
	}

	public function testPublicationPipelineOrdersMirrorBeforeConsumer(): void
	{
		$source = "{$this->dir}/continent; 'tmp'";
		$orig = "{$this->dir}/continent.orig";
		$mirror = "{$this->dir}/continent.txt";
		$events = [];
		$this->assertNotFalse(file_put_contents($source, '192.0.2.0/24'));

		$this->assertTrue(pfb_apply_geoip_orig_pipeline($source, $orig, $mirror,
			static function (string $published, string $mirrored) use (&$events): void {
				$events[] = 'consume';
				$events[] = is_file($published) && is_file($mirrored)
					? (string) file_get_contents($mirrored) : 'missing';
			}
		));

		$this->assertSame(['consume', "192.0.2.0/24\n"], $events);
		$this->assertFileDoesNotExist($source);
		$this->assertSame("192.0.2.0/24\n", file_get_contents($orig));
		$this->assertSame(file_get_contents($orig), file_get_contents($mirror));
	}

	public function testRenameFailurePreservesLegacyConsumerAttempt(): void
	{
		$orig = "{$this->dir}/continent.orig";
		$mirror = "{$this->dir}/continent.txt";
		$events = [];

		$this->assertFalse(pfb_apply_geoip_orig_pipeline("{$this->dir}/missing", $orig, $mirror,
			static function () use (&$events): void { $events[] = 'consume'; }
		));

		$this->assertSame(['consume'], $events);
		$this->assertFileDoesNotExist($mirror);
	}

	public function testEmptyPublicationPreservesLegacyMirrorAndConsumerAttempt(): void
	{
		$source = "{$this->dir}/empty.tmp";
		$orig = "{$this->dir}/empty.orig";
		$mirror = "{$this->dir}/empty.txt";
		$events = [];
		$this->assertNotFalse(file_put_contents($source, ''));

		$this->assertFalse(pfb_apply_geoip_orig_pipeline($source, $orig, $mirror,
			static function () use (&$events): void { $events[] = 'consume'; }
		));

		$this->assertSame(['consume'], $events);
		$this->assertFileExists($mirror);
		$this->assertSame('', file_get_contents($mirror));
	}

	/** The live GeoIP branch is part of the #993 sync monolith; behavior runs above. */
	public function testSyncPassDispatchesTheGeoipPublicationPipeline(): void
	{
		$source = php_strip_whitespace(self::APPLY);
		$start = strpos($source, 'function sync_package_pfblockerng(');
		$this->assertNotFalse($start);
		$this->assertSame(1, substr_count(substr($source, $start), 'pfb_apply_geoip_orig_pipeline('));
	}
}

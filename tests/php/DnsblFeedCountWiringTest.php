<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class DnsblFeedCountWiringTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_dnsbl_count_wiring_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
	}

	protected function tearDown(): void
	{
		foreach (glob($this->dir . '/*') ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);
	}

	public function testUpdateCountDelegatesToTheConfiguredCounter(): void
	{
		$calls = [];
		$count = pfb_update_unbound_feed_count(
			$this->dir,
			static function (string $dir) use (&$calls): int {
				$calls[] = $dir;
				return 17;
			}
		);

		$this->assertSame(17, $count);
		$this->assertSame([$this->dir], $calls);
	}

	public function testDefaultCounterCountsEachFeedWithoutWeldingFiles(): void
	{
		file_put_contents($this->dir . '/first.txt', "one\ntwo");
		file_put_contents($this->dir . '/second.txt', "three\n");

		$this->assertSame(3, pfb_update_unbound_feed_count($this->dir));
	}

	/**
	 * pfb_update_unbound() restarts live DNSBL/Unbound services, so PHPUnit
	 * cannot execute its caller. This comment-free pin is only the outer
	 * dispatch; the injected counter above proves the observable call effect.
	 */
	public function testLiveUpdateDispatchesThroughTheCountSeam(): void
	{
		$code = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc'
		);
		$this->assertIsString($code);
		$this->assertStringContainsString(
			'$dnsbl_cnt = pfb_update_unbound_feed_count($pfb[\'dnsdir\']);',
			$code
		);
	}
}

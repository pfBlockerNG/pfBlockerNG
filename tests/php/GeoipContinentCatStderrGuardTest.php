<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class GeoipContinentCatStderrGuardTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_geoip_cat_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
	}

	public function testInterruptedSwapSentinelBlocksConsumersUntilDccRecovery(): void
	{
		$oldPfb = $GLOBALS['pfb'];
		$GLOBALS['pfb']['ccdir'] = $this->dir . '/live';
		mkdir($GLOBALS['pfb']['ccdir'], 0700);
		file_put_contents($GLOBALS['pfb']['ccdir'] . '/.pfb_generation_swapping', 'pending');
		try {
			$this->assertFalse(pfb_geoip_generation_ready());
			unlink($GLOBALS['pfb']['ccdir'] . '/.pfb_generation_swapping');
			$this->assertTrue(pfb_geoip_generation_ready());
		} finally {
			$GLOBALS['pfb'] = $oldPfb;
		}
	}

	public function testInterruptedSwapBlocksGeoipLookupReaders(): void
	{
		$oldPfb = $GLOBALS['pfb'];
		$GLOBALS['pfb']['ccdir'] = $this->dir . '/live';
		mkdir($GLOBALS['pfb']['ccdir'], 0700);
		file_put_contents($GLOBALS['pfb']['ccdir'] . '/.pfb_generation_swapping', 'pending');
		$invoked = $this->dir . '/geoip-reader-invoked';
		$grep = $this->dir . '/geoip-reader-grep';
		file_put_contents($grep, "#!/bin/sh\ntouch " . escapeshellarg($invoked) . "\nexit 1\n");
		chmod($grep, 0700);
		$GLOBALS['pfb']['grep'] = $grep;

		try {
			$this->assertSame(['Unknown', 'Unknown'], find_reported_header('192.0.2.1', '/dev/null', TRUE));
			$this->assertSame(
				['192.0.2.1' => ['Unknown', 'Unknown']],
				pfb_find_reported_headers(['192.0.2.1'], '/dev/null', TRUE)
			);
			$this->assertFileDoesNotExist($invoked, 'GeoIP readers must not execute during publication.');
		} finally {
			$GLOBALS['pfb'] = $oldPfb;
		}
		$category = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_category_edit.php'
		);
		$this->assertIsString($category);
		$this->assertStringContainsString(
			'if (pfb_geoip_generation_ready() && file_exists("{$pfb[\'geoip_isos\']}"))',
			$category
		);
	}

	public function testInterruptedSwapBlocksAlertsAttributionAndPrefetch(): void
	{
		$oldPfb = $GLOBALS['pfb'];
		$oldContinents = $GLOBALS['continents'] ?? NULL;
		$live = $this->dir . '/live';
		$alias = $this->dir . '/alias';
		mkdir($live, 0700);
		mkdir($alias, 0700);
		file_put_contents($live . '/.pfb_generation_swapping', 'pending');
		$invoked = $this->dir . '/alerts-reader-invoked';
		$grep = $this->dir . '/alerts-reader-grep';
		file_put_contents($grep, "#!/bin/sh\ntouch " . escapeshellarg($invoked) . "\nexit 1\n");
		chmod($grep, 0700);
		$GLOBALS['pfb'] = array_merge($oldPfb, [
			'grep' => $grep,
			'ccdir' => $live,
			'aliasdir' => $alias,
		]);
		$GLOBALS['continents'] = ['pfB_Europe' => 0];
		$fields = array_fill(0, 18, '');
		$fields[3] = 'block';
		$fields[4] = 4;
		$fields[7] = '192.0.2.1';
		$fields[11] = 'in';
		$fields[13] = 'pfB_Europe_v4';
		$fields[14] = '192.0.2.1';
		$fields[15] = 'Europe_v4';
		pfb_ip_render_memos_reset();

		try {
			$query = pfb_ip_render_query($fields);
			$this->assertTrue($query['pfb_geoip']);
			$attribution = pfb_ip_render_attribution($fields);
			$this->assertSame('Not listed!', $attribution['feed_new']);
			pfb_ip_prefetch([[
				'host' => $query['host'],
				'folder' => $query['folder'],
				'pfb_geoip' => $query['pfb_geoip'],
				'validate_file_cmd' => $query['validate_file_cmd'],
				'validate_cmd' => $query['validate_cmd'],
				'eval_ip_raw' => $fields[14],
			]]);
			$this->assertSame(['validate' => [], 'miss' => []], pfb_ip_render_memos());
			$this->assertFileDoesNotExist($invoked, 'Alerts lookup paths must not read GeoIP files during publication.');
		} finally {
			pfb_ip_render_memos_reset();
			$GLOBALS['pfb'] = $oldPfb;
			if ($oldContinents === NULL) {
				unset($GLOBALS['continents']);
			} else {
				$GLOBALS['continents'] = $oldContinents;
			}
		}
	}
}

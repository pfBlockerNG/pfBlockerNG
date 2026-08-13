<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class GeoipContinentCatStderrGuardTest extends TestCase
{
	private string $dir;

	public static function setUpBeforeClass(): void
	{
		if (!function_exists('pfblockerng_uc_countries')) {
			$source = file_get_contents(__DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng.php');
			$start = strpos($source, 'function pfblockerng_uc_countries');
			self::assertNotFalse($start);
			eval(substr($source, $start));
		}
	}

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_geoip_cat_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
	}

	public function testCatFailureDiscardsPartialOutputAndTemporaryState(): void
	{
		$cat = $this->catFixture("printf 'partial-network\\n'\nexit 7\n");
		$iso = $this->dir . '/US_v4.txt';
		$continent = $this->dir . '/continent_v4.txt';
		$tmp = $this->dir . '/build_tmp';
		mkdir($tmp, 0700);
		file_put_contents($tmp . '/working', 'temporary');
		file_put_contents($iso, "ignored\n");
		file_put_contents($continent, "# header\n");

		$this->assertFalse(pfb_geoip_append_iso_data(
			$cat, $iso, $continent, $tmp, 'US', '4', static function (): void {}
		));
		$this->assertFileDoesNotExist($continent);
		$this->assertDirectoryDoesNotExist($tmp);
	}

	public function testCatSuccessAppendsOnlyStdout(): void
	{
		$cat = $this->catFixture("printf 'network-v4\\n'\n");
		$iso = $this->dir . '/US_v4.txt';
		$continent = $this->dir . '/continent_v4.txt';
		$tmp = $this->dir . '/build_tmp';
		mkdir($tmp, 0700);
		file_put_contents($iso, "ignored\n");
		file_put_contents($continent, "# header\n");

		$this->assertTrue(pfb_geoip_append_iso_data($cat, $iso, $continent, $tmp, 'US', '4'));
		$this->assertSame("# header\nnetwork-v4\n", file_get_contents($continent));
	}

	public function testDirectoryInputFailsWithoutWritingCatStderr(): void
	{
		$iso = $this->dir . '/unreadable_iso';
		mkdir($iso, 0700);
		$continent = $this->dir . '/continent_v4.txt';
		$tmp = $this->dir . '/build_tmp';
		mkdir($tmp, 0700);
		file_put_contents($continent, "# header\n");

		$this->assertFalse(pfb_geoip_append_iso_data(
			'/bin/cat', $iso, $continent, $tmp, 'US', '4', static function (): void {}
		));
		$this->assertFileDoesNotExist($continent);
	}

	public function testCountryGenerationFailurePreservesLiveGeneration(): void
	{
		$live = $this->dir . '/live';
		$share = $this->dir . '/share';
		$log = $this->dir . '/log';
		mkdir($live, 0700);
		mkdir($share, 0700);
		mkdir($log, 0700);
		file_put_contents($live . '/Europe_v4.txt', "healthy-continent\n");
		file_put_contents($this->dir . '/geoip_isos', 'healthy-isos');
		file_put_contents(
			$share . '/GeoLite2-Country-Locations-en.csv',
			"geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name\n"
			. "49518,en,EU,Europe,RW,Rwanda\n"
		);
		foreach (['4' => '1.2.3.0/24', '6' => '2001:db8::/32'] as $type => $network) {
			file_put_contents(
				$share . "/GeoLite2-Country-Blocks-IPv{$type}.csv",
				"network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider\n"
				. "{$network},49518,49518,,0,0\n"
			);
		}

		$oldPfb = $GLOBALS['pfb'];
		$GLOBALS['pfb'] = array_merge($oldPfb, [
			'dbdir' => $this->dir . '/db',
			'logdir' => $log,
			'ccdir' => $live,
			'ccdir_tmp' => $this->dir . '/working',
			'geoipshare' => $share,
			'geoip_isos' => $this->dir . '/geoip_isos',
			'maxmind_locale' => 'en',
			'grep' => '/usr/bin/grep',
			'cut' => '/usr/bin/cut',
			'cat' => $this->catFixture("printf 'partial-network\\n'\nexit 7\n"),
		]);

		try {
			$this->assertFalse(pfblockerng_uc_countries());
			$this->assertSame("healthy-continent\n", file_get_contents($live . '/Europe_v4.txt'));
			$this->assertSame('healthy-isos', file_get_contents($this->dir . '/geoip_isos'));
		} finally {
			$GLOBALS['pfb'] = $oldPfb;
		}
	}

	public function testUiGenerationFailurePreservesLiveGeneration(): void
	{
		$live = $this->dir . '/live';
		$share = $this->dir . '/share';
		$log = $this->dir . '/log';
		mkdir($live, 0700);
		mkdir($share, 0700);
		mkdir($log, 0700);
		file_put_contents($live . '/Europe_v4.txt', "healthy-continent\n");
		file_put_contents($this->dir . '/geoip_isos', 'healthy-isos');
		file_put_contents(
			$share . '/GeoLite2-Country-Locations-en.csv',
			"geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name\n"
			. "49518,en,EU,Europe,RW,Rwanda\n"
		);
		foreach (['4' => '1.2.3.0/24', '6' => '2001:db8::/32'] as $type => $network) {
			file_put_contents(
				$share . "/GeoLite2-Country-Blocks-IPv{$type}.csv",
				"network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider\n"
				. "{$network},49518,49518,,0,0\n"
			);
		}
		$outputRoot = $this->dir . '/not-a-directory';
		file_put_contents($outputRoot, 'occupied');
		$oldPfb = $GLOBALS['pfb'];
		$GLOBALS['pfb'] = array_merge($oldPfb, [
			'dbdir' => $this->dir . '/db', 'logdir' => $log, 'ccdir' => $live,
			'ccdir_tmp' => $this->dir . '/working', 'geoipshare' => $share,
			'geoip_isos' => $this->dir . '/geoip_isos', 'maxmind_locale' => 'en',
			'grep' => '/usr/bin/grep', 'cut' => '/usr/bin/cut', 'cat' => '/bin/cat',
		]);

		try {
			$this->assertFalse(pfblockerng_uc_countries($outputRoot));
			$this->assertSame("healthy-continent\n", file_get_contents($live . '/Europe_v4.txt'));
			$this->assertSame('healthy-isos', file_get_contents($this->dir . '/geoip_isos'));
		} finally {
			$GLOBALS['pfb'] = $oldPfb;
		}
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

	public function testUiBackupFailureCannotMarkLivePageAsPublished(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php');
		$this->assertIsString($source);
		$loop = strstr($source, 'if ($publish_ok && $stage_output_root !== NULL) {');
		$this->assertIsString($loop);
		$backup = strpos($loop, 'if (is_file("{$output_root}/{$name}") && !@copy(');
		$published = strpos($loop, '$published_output_files[$name] = TRUE;');
		$rename = strpos($loop, 'if (!@rename($stage_file, "{$output_root}/{$name}"))');
		$this->assertIsInt($backup);
		$this->assertIsInt($published);
		$this->assertIsInt($rename);
		$this->assertLessThan($published, $backup, 'Backup must succeed before rollback owns the live page.');
		$this->assertLessThan($rename, $published, 'Rollback must own the page before live publication starts.');
	}

	public function testUiRollbackBackupLivesBesideUiPublication(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php');
		$this->assertIsString($source);
		$this->assertStringContainsString(
			'$backup_output_root = $stage_output_root === NULL ? NULL : "{$output_root}.old.{$generation}";',
			$source
		);
		$this->assertStringNotContainsString('$backup_output_root = "{$backup_root}/ui";', $source);
	}

	private function catFixture(string $body): string
	{
		$path = $this->dir . '/cat-' . bin2hex(random_bytes(4));
		file_put_contents($path, "#!/bin/sh\n{$body}");
		chmod($path, 0755);
		return $path;
	}
}

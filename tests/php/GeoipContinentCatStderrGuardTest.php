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
		foreach (glob($this->dir . '/*') ?: [] as $file) {
			is_dir($file) ? @rmdir($file) : @unlink($file);
		}
		@rmdir($this->dir);
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

	private function catFixture(string $body): string
	{
		$path = $this->dir . '/cat-' . bin2hex(random_bytes(4));
		file_put_contents($path, "#!/bin/sh\n{$body}");
		chmod($path, 0755);
		return $path;
	}
}

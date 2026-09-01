<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class CountryNetworksCountGuardTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_country_networks_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
	}

	public function testCountReadFailureUsesNonPlaceholderHeader(): void
	{
		$directory = $this->dir . '/not-a-file';
		$this->assertTrue(mkdir($directory, 0700));

		$this->assertNull(pfb_count_lines($directory));
		$this->assertSame(
			"# Country: Testland\n# ISO Code: TL\n# Total Networks: ERROR\n",
			pfb_geoip_networks_header($directory, 'Testland', '', 'TL')
		);
	}

	public function testEmptyFileStillUsesZeroPlaceholder(): void
	{
		$empty = $this->dir . '/empty.txt';
		$this->assertSame(0, file_put_contents($empty, ''));

		$this->assertSame(
			"# Country: Testland\n# ISO Code: TL\n# Total Networks: 0\n",
			pfb_geoip_networks_header($empty, 'Testland', '', 'TL')
		);
	}

	public function testHeaderIncludesGeonameIdWhenPresent(): void
	{
		$file = $this->dir . '/country.txt';
		file_put_contents($file, "10.0.0.0/8\n");

		$this->assertSame(
			"# Country: Testland [42]\n# ISO Code: TL\n# Total Networks: 1\n",
			pfb_geoip_networks_header($file, 'Testland', '42', 'TL')
		);
	}
}

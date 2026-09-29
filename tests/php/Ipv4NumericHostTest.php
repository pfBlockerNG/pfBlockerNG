<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_ipv4_numeric_host(): decode a host the way the WHATWG URL parser and libcurl do.
 *
 * Hex/octal/DWORD and short spellings of an IPv4 address ('0xC0A80164', '192.168.356') reach a
 * real address in every client, so ingest and the feed-host guard must see that address, not a
 * name. The table in tests/fixtures/ipv4_numeric_host.json is shared with the Python shape twin
 * (tests/test_ipv4_numeric_host.py) so both halves classify the same inputs the same way.
 */
#[CoversFunction('pfb_ipv4_numeric_host')]
final class Ipv4NumericHostTest extends TestCase
{
	/** @return array<string, array{string, string|false|null}> */
	public static function sharedTable(): array
	{
		$json = file_get_contents(dirname(__DIR__) . '/fixtures/ipv4_numeric_host.json');
		$data = json_decode((string) $json, TRUE, 512, JSON_THROW_ON_ERROR);
		$cases = array();
		foreach ($data['cases'] as [$host, $expected]) {
			$cases[var_export($host, TRUE)] = array($host, $expected);
		}
		return $cases;
	}

	#[DataProvider('sharedTable')]
	public function testSharedTable(string $host, string|false|null $expected): void
	{
		$want = match (TRUE) {
			$expected === NULL	=> NULL,
			$expected === FALSE	=> array('ip' => NULL),
			default			=> array('ip' => $expected),
		};
		$this->assertSame($want, pfb_ipv4_numeric_host($host), "host {$host}");
	}

	public function testTableCoversEveryResultShape(): void
	{
		$expected = array_column(self::sharedTable(), 1);
		$this->assertContains(NULL, $expected);
		$this->assertContains(FALSE, $expected);
		$this->assertNotEmpty(array_filter($expected, 'is_string'));
	}
}

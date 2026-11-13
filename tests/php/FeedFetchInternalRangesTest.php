<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_ip_is_internal() against the range table shared with Core (tests/feedfetch/fixtures/internal_ranges.json,
 * which go/pfb_core/feedfetch/internal_test.go runs against internal()): the inside and the first address outside
 * every non-permitted range, IPv4-mapped forms and public addresses. A row that passes here and fails there, or the
 * reverse, is a divergence of the feed-host guard.
 */
#[CoversFunction('pfb_ip_is_internal')]
final class FeedFetchInternalRangesTest extends TestCase
{
	public static function ranges(): array
	{
		$rows = json_decode((string) file_get_contents(__DIR__ . '/../feedfetch/fixtures/internal_ranges.json'), TRUE,
			512, JSON_THROW_ON_ERROR);
		$cases = [];
		foreach ($rows as $row) {
			$cases[$row['ip'] . ($row['internal'] ? ' is internal' : ' is public')] = [$row['ip'], $row['internal']];
		}
		return $cases;
	}

	#[DataProvider('ranges')]
	public function testAddressIsClassifiedAsTheSharedTableSays(string $ip, bool $internal): void
	{
		$this->assertSame($internal, pfb_ip_is_internal($ip) !== FALSE, "pfb_ip_is_internal({$ip})");
	}
}

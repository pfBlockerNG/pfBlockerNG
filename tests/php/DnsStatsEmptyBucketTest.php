<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/DnsStatsAggregationTest.php';

final class DnsStatsEmptyBucketTest extends TestCase
{
	public function testEmptyAndLiteralUnknownCombineWithoutLosingDescendingCountOrder(): void
	{
		$rows = [];
		foreach (['named', '', '', '', 'Unknown', '0'] as $value) {
			$rows[] = ['DNS-reply', '2030-01-15 09:00:00', $value, 'A', 'A', '0', 'a.test', '', '', ''];
		}
		[$result] = DnsStatsAggregationTest::aggregate('dnsbl_reply_stat', DnsStatsAggregationTest::csv($rows));
		$this->assertSame(['Unknown' => 4, 'named' => 1, 0 => 1], $result['dnsbl_reply_stat']['replytype']);
	}
}

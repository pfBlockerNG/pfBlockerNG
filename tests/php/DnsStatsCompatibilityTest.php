<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/DnsStatsAggregationTest.php';

final class DnsStatsCompatibilityTest extends TestCase
{
	public function testIpBlockPermitAndMatchKeepTheirExistingBuckets(): void
	{
		$row = ['2030-01-15 09:00:00', 'tracker', 'rule', 'wan', '4', 'block', '0', 'TCP',
			'192.0.2.1', '192.0.2.2', '443', '53', 'in', 'US', 'Alias', 'unused', 'Feed',
			'host.test', 'unused', '64500', 'unused', 'unused', 'unused'];
		foreach (['ip_block_stat', 'ip_permit_stat', 'ip_match_stat'] as $view) {
			[$result, $chart] = DnsStatsAggregationTest::aggregate($view, implode(',', $row) . "\n");
			$this->assertSame(1, $result['count'][$view], $view);
			foreach ([
				'ipdate' => ['2030-01-15' => 1], 'ipchart' => [], 'ipinterface' => ['wan' => 1],
				'ipprotocol' => ['TCP' => 1], 'ipsrcipin' => ['192.0.2.1,US,host.test' => 1],
				'ipsrcipout' => [], 'ipdstipin' => ['192.0.2.2,US' => 1], 'ipdstipout' => [],
				'ipsrcport' => [443 => 1], 'ipdstport' => [53 => 1], 'ipdirection' => ['in' => 1],
				'ipgeoip' => ['US' => 1], 'ipaliasname' => ['Alias' => 1], 'ipfeed' => ['Feed' => 1],
				'ipasn' => [64500 => 1],
			] as $type => $expected) {
				$this->assertSame($expected, $result[$view][$type], $view . '/' . $type);
			}
			$this->assertSame("edate,ecount\n2030-01-15 (09),1\n", $chart);
		}
	}

	public function testDnsblEmptyZeroIndicatorsAndAgentWithoutPipeKeepTheirMeaning(): void
	{
		$rows = [];
		foreach (['', '0', '-', '+'] as $value) {
			$rows[] = ['DNSBL', '2030-01-15 09:00:00', 'localhost', '192.0.2.1', 'Python', 'DNSBL', 'group', 'not.eval', $value];
		}
		[$result] = DnsStatsAggregationTest::aggregate('dnsbl_stat', DnsStatsAggregationTest::csv($rows));
		$this->assertSame([0 => 1, pfb_dnsbl_mechanism_labels()['enabled'] => 1], $result['dnsbl_stat']['dnsblfeed']);
		$this->assertSame(['Python' => 4], $result['dnsbl_stat']['dnsblagent']);
		$this->assertSame([], $result['dnsbl_stat']['dnsblevald']);
		$this->assertSame([], $result['dnsbl_stat']['dnsbltld']);
	}

	public function testBlankPhysicalLinesAreIncludedInDisplayTotal(): void
	{
		[$result] = DnsStatsAggregationTest::aggregate('dnsbl_reply_stat', "\n\n");
		$this->assertSame(2, $result['count']['dnsbl_reply_stat']);
		$this->assertSame(['Unknown' => 2], $result['dnsbl_reply_stat']['replytype']);
	}
}

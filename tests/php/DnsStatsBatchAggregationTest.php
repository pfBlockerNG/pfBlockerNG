<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class DnsStatsBatchAggregationTest extends TestCase
{
	public function testInterleavedHoursRepeatedValuesTiesAndFinalRecordKeepEveryReplyCategory(): void
	{
		$rows = [];
		for ($i = 0; $i < 2052; $i++) {
			$rows[] = ['DNS-reply', $i % 2 ? '2030-01-15 09:02:03' : '2030-01-16 11:04:05',
				'UDP', 'A', 'AAAA', '0', $i % 2 ? 'b.a.test' : 'a.z.test', 'src', 'dst', 'US'];
		}
		$rows[] = ['DNS-reply', '2030-01-17 08:06:07', 'UDP', 'A', 'AAAA', '0', 'a.z.test', 'src', 'dst', 'US'];
		$csv = rtrim($this->csv($rows), "\n");
		$map = ['replydate' => 2, 'replychart' => 2, 'replytype' => 3, 'replyorec' => 4, 'replyrec' => 5,
			'replyttl' => 6, 'replydomain' => 7, 'replytld' => 7, 'replytld2' => 7, 'replytld3' => 7,
			'replysrcipd' => 7, 'replysrcip' => 8, 'replydstip' => 9, 'replygeoip' => 10];
		$expected = ['replydate' => ['2030-01-17' => 1, '2030-01-16' => 1026, '2030-01-15' => 1026],
			'replychart' => [], 'replytype' => ['UDP' => 2053], 'replyorec' => ['A' => 2053],
			'replyrec' => ['AAAA' => 2053], 'replyttl' => [0 => 2053],
			'replydomain' => ['a.z.test' => 1027, 'b.a.test' => 1026], 'replytld' => ['test' => 2053],
			'replytld2' => ['z.test' => 1027, 'a.test' => 1026],
			'replytld3' => ['a.z.test' => 1027, 'b.a.test' => 1026],
			'replysrcipd' => ['a.z.test,src' => 1027, 'b.a.test,src' => 1026],
			'replysrcip' => ['src' => 2053], 'replydstip' => ['dst' => 2053], 'replygeoip' => ['US' => 2053]];
		$chart = ['2030-01-15 09' => 1026, '2030-01-16 11' => 1026, '2030-01-17 08' => 1];
		$this->assertSame(['stats' => $expected, 'count' => 2053, 'chart' => $chart], $this->aggregate($csv, $map));
		foreach (range(0, 7) as $mask) {
			$selected = [];
			$want = [];
			foreach (['replytld', 'replytld2', 'replytld3'] as $bit => $type) {
				if ($mask & (1 << $bit)) {
					$selected[$type] = 7;
					$want[$type] = $expected[$type];
				}
			}
			$this->assertSame(['stats' => $want, 'count' => $mask ? 2053 : 0, 'chart' => []],
				$this->aggregate($csv, $selected), "suffix subset {$mask}");
		}
		foreach (['replytype', 'replydate', 'replychart', 'replysrcipd', 'replytld3'] as $type) {
			$this->assertSame(['stats' => [$type => $expected[$type]], 'count' => 2053,
				'chart' => $type === 'replychart' ? $chart : []], $this->aggregate($csv, [$type => $map[$type]]), $type);
		}
		$this->assertSame(['stats' => array_fill_keys(array_keys($map), []), 'count' => 0, 'chart' => []],
			$this->aggregate('', $map));
	}

	public function testMissingBlankQuotedEmptyAndZeroRecordsAreNotDropped(): void
	{
		$date = '2030-01-15 09:00:00';
		$csv = str_repeat("\nDNS-reply\nDNS-reply,{$date},\"\"\nDNS-reply,{$date},0\n", 513)
			. "DNS-reply,{$date},0";
		$this->assertSame(['stats' => ['replytype' => ['Unknown' => 1539, 0 => 514],
			'replydstip' => ['Unknown' => 2053], 'replysrcipd' => [',' => 2053], 'replytld' => [],
			'replydate' => ['2030-01-15' => 1027], 'replychart' => []],
			'count' => 2053, 'chart' => ['2030-01-15 09' => 1027]],
			$this->aggregate($csv, ['replytype' => 3, 'replydstip' => 99, 'replysrcipd' => 7,
				'replytld' => 7, 'replydate' => 2, 'replychart' => 2]));
	}

	public function testRowOneFieldShortOfLastColumnIsUnknown(): void
	{
		$csv = "DNS-reply,2030-01-15 09:00:00,UDP\nDNS-reply,2030-01-15 09:00:00,UDP,A\n";
		$this->assertSame(['stats' => ['replytype' => ['UDP' => 2], 'replyorec' => ['A' => 1, 'Unknown' => 1]],
			'count' => 2, 'chart' => []], $this->aggregate($csv, ['replytype' => 3, 'replyorec' => 4]));
	}

	public function testHourBucketAndCompositeAreTrimmed(): void
	{
		$this->assertSame(['stats' => ['dnsbldatehr' => ['2030-01-15' => 1]], 'count' => 1, 'chart' => []],
			$this->aggregate("DNS-reply,2030-01-15 :,x\n", ['dnsbldatehr' => 2]));
		$this->assertSame(['stats' => ['dnsbldomain' => ['a.test,TLD' => 1]], 'count' => 1, 'chart' => []],
			$this->aggregate("DNSBL,2030-01-15 09:00:00, a.test,x,y,TLD\n", ['dnsbldomain' => 3]));
	}

	public function testTwoPartAgentIsUnknown(): void
	{
		$this->assertSame(['stats' => ['dnsblagent' => ['Unknown' => 1]], 'count' => 1, 'chart' => []],
			$this->aggregate("DNSBL,2030-01-15 09:00:00,a.test,src,a|b\n", ['dnsblagent' => 5]));
	}

	public function testAbsentUnsharedCompositeColumnFallsBackToEmpty(): void
	{
		$this->assertSame(['stats' => ['replysrcipd' => [',' => 1]], 'count' => 1, 'chart' => []],
			$this->aggregate("DNSBL,2030-01-15 09:00:00,a.test\n", ['replysrcipd' => 99]));
	}

	public function testUnknownMergeKeepsOriginalTieOrderAcrossTheFinalRemainder(): void
	{
		$prefix = 'DNS-reply,2030-01-15 09:00:00,';
		$csv = str_repeat($prefix . "zz\n", 1020) . str_repeat($prefix . "\n", 3)
			. str_repeat($prefix . "Unknown\n", 2) . str_repeat($prefix . "AAA\n", 4)
			. str_repeat($prefix . "zz\n", 1017) . str_repeat($prefix . "\n", 2)
			. $prefix . "Unknown\n" . str_repeat($prefix . "AAA\n", 4);
		$this->assertSame(['stats' => ['replytype' => ['zz' => 2037, 'AAA' => 8, 'Unknown' => 8]],
			'count' => 2053, 'chart' => []], $this->aggregate($csv, ['replytype' => 3]));
	}

	public function testCorrelatedCommaValuesKeepWholeCompositeCollisionsAndTldGate(): void
	{
		$rows = [
			['DNSBL', '2030-01-15 09:00:00', 'a,b.test', 'src', 'agent', 'TLD,x', 'group', 'v,w', 'feed'],
			['DNSBL', '2030-01-15 09:00:00', 'a', 'src', 'agent', 'b.test,TLD,x', 'group', 'v,w', 'feed'],
			['DNSBL', '2030-01-15 09:00:00', 'c,d.test', 'src', 'agent', 'plain,mode', 'group', 'TLD,v', 'feed'],
			['DNSBL', '2030-01-15 09:00:00', 'c,d.test', 'src', 'agent', 'plain,mode', 'group', 'v,w', 'feed'],
		];
		$csv = str_repeat($this->csv($rows), 513);
		$this->assertSame(['stats' => ['dnsbldomain' => ['c,d.test,plain,mode' => 1026, 'a,b.test,TLD,x' => 1026],
			'dnsblevald' => ['plain,mode,TLD,v' => 513, 'b.test,TLD,x,v,w' => 513, 'TLD,x,v,w' => 513],
			'dnsblmode' => ['plain,mode' => 1026, 'b.test,TLD,x' => 513, 'TLD,x' => 513]],
			'count' => 2052, 'chart' => []],
			$this->aggregate($csv, ['dnsbldomain' => 3, 'dnsblevald' => 8, 'dnsblmode' => 6]));
		$reply = [
			['DNS-reply', '', '', '', '', '', 'a,b', 'c,d'],
			['DNS-reply', '', '', '', '', '', 'a', 'b,c,d'],
			['DNS-reply', '', '', '', '', '', 'a,b', 'x,y'],
		];
		$this->assertSame(['stats' => ['replysrcipd' => ['a,b,c,d' => 1368, 'a,b,x,y' => 684],
			'replydomain' => ['a,b' => 1368, 'a' => 684],
			'replysrcip' => ['x,y' => 684, 'c,d' => 684, 'b,c,d' => 684]], 'count' => 2052, 'chart' => []],
			$this->aggregate(str_repeat($this->csv($reply), 684), ['replysrcipd' => 7, 'replydomain' => 7, 'replysrcip' => 8]));
	}

	public function testDnsblMarkersWhitespaceAgentsAndSuffixVisibilityAcrossRepeatedRecords(): void
	{
		$rows = [];
		foreach ([' - ', ' + ', 'name - ', "name +\t", ' 0 ', ' ', ' Unknown ', ' keep '] as $i => $value) {
			$rows[] = ['DNSBL', $i % 2 ? 'legacy date' : '2030-01-15 09:02:03', 'a.test', 'src',
				$i % 2 ? 'raw-agent' : 'one|two|parsed|four', 'TLD', 'group', 'eval', $value];
		}
		$csv = str_repeat($this->csv($rows), 257);
		$map = ['dnsblwebtype' => 1, 'dnsbldate' => 2, 'dnsblchart' => 2, 'dnsbldatehr' => 2,
			'dnsbldatehrmin' => 2, 'dnsbldomain' => 3, 'dnsbltld' => 3, 'dnsblip' => 4,
			'dnsblagent' => 5, 'dnsblmode' => 6, 'dnsblevald' => 8, 'dnsblfeed' => 9];
		$expected = ['dnsblwebtype' => ['DNSBL' => 2056], 'dnsbldate' => ['2030-01-15' => 1028],
			'dnsblchart' => [], 'dnsbldatehr' => ['2030-01-15 09' => 1028],
			'dnsbldatehrmin' => ['2030-01-15 09:02' => 1028], 'dnsbldomain' => ['a.test,TLD' => 2056],
			'dnsbltld' => ['test' => 2056], 'dnsblip' => ['src' => 2056],
			'dnsblagent' => ['raw-agent' => 1028, 'parsed' => 1028], 'dnsblmode' => ['TLD' => 2056],
			'dnsblevald' => ['TLD,eval' => 2056], 'dnsblfeed' => ['Unknown' => 514, 'keep' => 257, 0 => 257]];
		$this->assertSame(['stats' => $expected, 'count' => 2056, 'chart' => ['2030-01-15 09' => 1028]],
			$this->aggregate($csv, $map));
		foreach ([FALSE, TRUE] as $enabled) {
			$this->assertSame(['stats' => $enabled ? ['dnsbltld' => ['test' => 2056]] : [],
				'count' => $enabled ? 2056 : 0, 'chart' => []], $this->aggregate($csv, $enabled ? ['dnsbltld' => 3] : []));
		}
	}

	public function testQuotedMultilineRecordsAndMalformedFinalEofKeepPhysicalTotals(): void
	{
		foreach (["\n", "\r\n"] as $ending) {
			$prefix = str_repeat('DNS-reply,2030-01-15 09:00:00,UDP,A,A,0,normal.test,src' . $ending, 2051);
			$multiline = 'DNS-reply,2030-01-16 11:00:00,UDP,A,A,0,"a.b' . $ending . 'c.test",src' . $ending;
			foreach (['tail.test' => 'tail.test', '"open' . $ending . 'tail.test' => 'open' . $ending . 'tail.test'] as $raw => $label) {
				$csv = $prefix . $multiline . 'DNS-reply,2030-01-17 08:00:00,UDP,A,A,0,' . $raw;
				$this->assertSame(['stats' => ['replydomain' => ['normal.test' => 2051, $label => 1, 'a.b' . $ending . 'c.test' => 1],
					'replychart' => []], 'count' => 2054 + ($label !== 'tail.test' ? 1 : 0),
					'chart' => ['2030-01-15 09' => 2051, '2030-01-16 11' => 1, '2030-01-17 08' => 1]],
					$this->aggregate($csv, ['replydomain' => 7, 'replychart' => 2]), bin2hex($ending) . '/' . bin2hex($raw));
			}
		}
	}

	public function testOversizedQuotedFieldDoesNotLoseTheFollowingNormalRecord(): void
	{
		$domain = str_repeat('x', 524300) . ',large.test';
		$csv = $this->csv([['DNS-reply', '2030-01-15 09:00:00', 'UDP', 'A', 'A', '0', $domain, 'src']])
			. 'DNS-reply,2030-01-16 10:00:00,UDP,A,A,0,normal.test,src';
		$result = $this->aggregate($csv, ['replydomain' => 7, 'replytld' => 7, 'replysrcipd' => 7, 'replychart' => 2]);
		$hashed = [];
		foreach (['replydomain', 'replysrcipd'] as $type) {
			$hashed[$type] = [];
			foreach ($result['stats'][$type] as $key => $count) {
				$hashed[$type][hash('sha256', $key)] = $count;
			}
		}
		$this->assertSame(['replydomain' => [hash('sha256', $domain) => 1, hash('sha256', 'normal.test') => 1],
			'replysrcipd' => [hash('sha256', $domain . ',src') => 1, hash('sha256', 'normal.test,src') => 1]], $hashed);
		$this->assertSame(['test' => 2], $result['stats']['replytld']);
		$this->assertSame([], $result['stats']['replychart']);
		$this->assertSame(2, $result['count']);
		$this->assertSame(['2030-01-15 09' => 1, '2030-01-16 10' => 1], $result['chart']);
	}

	private function aggregate(string $csv, array $map): array
	{
		$path = tempnam(sys_get_temp_dir(), 'batch-');
		try {
			file_put_contents($path, $csv);
			return pfb_dns_stats($path, $map, 'Unknown');
		} finally {
			unlink($path);
		}
	}

	private function csv(array $rows): string
	{
		$stream = fopen('php://temp', 'w+');
		foreach ($rows as $row) {
			fputcsv($stream, $row, ',', '"', '');
		}
		rewind($stream);
		$result = stream_get_contents($stream);
		fclose($stream);
		return $result;
	}
}

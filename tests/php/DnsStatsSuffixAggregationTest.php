<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DnsStatsSuffixAggregationTest extends TestCase
{
	/** The literals describe each level independently: trimming a deeper bucket must not change a shallower one. */
	public static function domains(): iterable
	{
		foreach ([
			['', NULL, NULL, NULL], ['0', NULL, NULL, NULL], ['single', NULL, NULL, NULL],
			['a.test', 'test', 'a.test', NULL], ['a.b.test', 'test', 'b.test', 'a.b.test'],
			['a.b.c.test', 'test', 'c.test', 'b.c.test'], ['a.', 'Unknown', 'a.', NULL],
			['.', 'Unknown', '.', NULL], ['..', 'Unknown', '.', '..'],
			['a..test', 'test', '.test', 'a..test'], ['a.b.', 'Unknown', 'b.', 'a.b.'],
			[' a. b. test ', 'test', 'b. test', 'a. b. test'],
			['a.0', 0, 'a.0', NULL], ['a.Unknown', 'Unknown', 'a.Unknown', NULL],
			['a.+', NULL, 'a.+', NULL], ['a.-', NULL, 'a.-', NULL],
			['a.x +', NULL, NULL, NULL], ['a.x -', NULL, NULL, NULL],
			['a.x±', 'x±', 'a.x±', NULL], ['a. - .test', 'test', '- .test', 'a. - .test'],
			['a.é.测试', '测试', 'é.测试', 'a.é.测试'],
			["a.\xff.test", 'test', "\xff.test", "a.\xff.test"],
			['a."b,c".test', 'test', '"b,c".test', 'a."b,c".test'],
			['a.b\\c.test', 'test', 'b\\c.test', 'a.b\\c.test'],
			["a.b\nc.test", 'test', "b\nc.test", "a.b\nc.test"],
			["a.b\r\nc.test", 'test', "b\r\nc.test", "a.b\r\nc.test"],
		] as $index => [$domain, $one, $two, $three]) {
			foreach (range(0, 7) as $mask) {
				yield "domain-{$index}/subset-{$mask}" => [$domain, [$one, $two, $three], $mask];
			}
		}
	}

	#[DataProvider('domains')]
	public function testEverySelectedSuffixAndFollowingRecord(string $domain, array $suffixes, int $mask): void
	{
		$map = [];
		$expected = [];
		foreach (['replytld', 'replytld2', 'replytld3'] as $index => $type) {
			if ($mask & (1 << $index)) {
				$map[$type] = 7;
				$expected[$type] = $suffixes[$index] === NULL ? [] : [$suffixes[$index] => 1];
			}
		}
		foreach ([FALSE, TRUE] as $visible_domain) {
			$selected = $map;
			$want = $expected;
			if ($visible_domain) {
				$selected['replydomain'] = 7;
				$want['replydomain'] = in_array($domain, ['a.x +', 'a.x -'], TRUE) ? []
					: [trim($domain) === '' ? 'Unknown' : trim($domain) => 1];
			}
			$reply = ['DNS-reply', '2030-01-15 09:00:00', 'UDP', 'A', 'A', '0', $domain, 'src', 'dst', 'US'];
			$this->assertSame(['stats' => $want, 'count' => $selected ? 1 + substr_count($domain, "\n") : 0, 'chart' => []],
				$this->aggregate($this->csv([$reply]), $selected));
		}
		// An unterminated final physical line after a quoted/multiline record must not be skipped.
		$reply[6] = 'cursor.example';
		$following = rtrim($this->csv([$reply]), "\n");
		$result = $this->aggregate($this->csv([array_replace($reply, [6 => $domain])]) . $following,
			['replydomain' => 7]);
		$this->assertSame(1, $result['stats']['replydomain']['cursor.example']);
		$this->assertSame(2 + substr_count($domain, "\n"), $result['count']);

		foreach ([FALSE, TRUE] as $enabled) {
			$map = $enabled ? ['dnsbltld' => 3] : [];
			$this->assertSame(['stats' => $enabled ? ['dnsbltld' => $suffixes[0] === NULL ? [] : [$suffixes[0] => 1]] : [],
				'count' => $enabled ? 1 + substr_count($domain, "\n") : 0, 'chart' => []],
				$this->aggregate($this->csv([['DNSBL', '2030-01-15 09:00:00', $domain]]), $map));
		}
	}

	public function testCountsOrderingUnknownMergingAndAllOtherDnsCategories(): void
	{
		$map = ['dnsblwebtype' => 1, 'dnsbldate' => 2, 'dnsblchart' => 2, 'dnsbldatehr' => 2,
			'dnsbldatehrmin' => 2, 'dnsbldomain' => 3, 'dnsbltld' => 3, 'dnsblip' => 4,
			'dnsblagent' => 5, 'dnsblmode' => 6, 'dnsblevald' => 8, 'dnsblfeed' => 9];
		$row = ['DNSBL', '2030-01-15 09:02:03', 'a.test', 'src', 'one|two|agent|four', 'TLD', 'group', 'eval', 'feed'];
		$this->assertSame(['stats' => [
			'dnsblwebtype' => ['DNSBL' => 1], 'dnsbldate' => ['2030-01-15' => 1], 'dnsblchart' => [],
			'dnsbldatehr' => ['2030-01-15 09' => 1], 'dnsbldatehrmin' => ['2030-01-15 09:02' => 1],
			'dnsbldomain' => ['a.test,TLD' => 1], 'dnsbltld' => ['test' => 1], 'dnsblip' => ['src' => 1],
			'dnsblagent' => ['agent' => 1], 'dnsblmode' => ['TLD' => 1], 'dnsblevald' => ['TLD,eval' => 1],
			'dnsblfeed' => ['feed' => 1]], 'count' => 1, 'chart' => ['2030-01-15 09' => 1]],
			$this->aggregate($this->csv([$row]), $map));
		$map = ['replydate' => 2, 'replychart' => 2, 'replytype' => 3, 'replyorec' => 4, 'replyrec' => 5,
			'replyttl' => 6, 'replydomain' => 7, 'replytld' => 7, 'replytld2' => 7, 'replytld3' => 7,
			'replysrcipd' => 7, 'replysrcip' => 8, 'replydstip' => 9, 'replygeoip' => 10];
		$rows = [];
		foreach (['a.z.test', 'a.a.test', 'a.z.test', 'a..', 'a.Unknown', 'a.0'] as $i => $domain) {
			$rows[] = ['DNS-reply', '2030-01-15 ' . ($i % 2 ? '10' : '09') . ':02:03', 'UDP', 'A', 'AAAA', '0', $domain, 'src', 'dst', 'US'];
		}
		$result = $this->aggregate($this->csv($rows), $map);
		$this->assertSame(['test' => 3, 'Unknown' => 2, 0 => 1], $result['stats']['replytld']);
		$this->assertSame(['z.test' => 2, 'a.test' => 1, 'a.Unknown' => 1, 'a.0' => 1, '.' => 1], $result['stats']['replytld2']);
		$this->assertSame(['a.z.test' => 2, 'a.a.test' => 1, 'a..' => 1], $result['stats']['replytld3']);
		foreach (['replydate' => ['2030-01-15' => 6], 'replychart' => [], 'replytype' => ['UDP' => 6],
			'replyorec' => ['A' => 6], 'replyrec' => ['AAAA' => 6], 'replyttl' => [0 => 6],
			'replysrcipd' => ['a.z.test,src' => 2, 'a.a.test,src' => 1, 'a.Unknown,src' => 1, 'a.0,src' => 1, 'a..,src' => 1],
			'replysrcip' => ['src' => 6], 'replydstip' => ['dst' => 6],
			'replygeoip' => ['US' => 6]] as $type => $want) {
			$this->assertSame($want, $result['stats'][$type], $type);
		}
		$this->assertSame(['2030-01-15 09' => 3, '2030-01-15 10' => 3], $result['chart']);
		$this->assertSame(6, $result['count']);
	}

	public function testMalformedQuotedEofKeepsPhysicalCount(): void
	{
		foreach (["\"a.b.test", "\"a.b.test\nsecond"] as $domain) {
			$log = 'DNS-reply,2030-01-15 09:00:00,UDP,A,A,0,' . $domain;
			$result = $this->aggregate($log, ['replytld' => 7, 'replytld2' => 7, 'replytld3' => 7]);
			$this->assertSame(1 + substr_count($log, "\n"), $result['count']);
			$this->assertSame(['test' . (str_contains($domain, "\n") ? "\nsecond" : '') => 1], $result['stats']['replytld']);
		}
	}

	private function aggregate(string $csv, array $map): array
	{
		$path = tempnam(sys_get_temp_dir(), 'suffix-');
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

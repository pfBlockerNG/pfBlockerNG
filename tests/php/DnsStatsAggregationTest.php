<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class DnsStatsAggregationTest extends TestCase
{
	public static function aggregate(string $view, ?string $contents, array $hidden = []): array
	{
		$dir = sys_get_temp_dir() . '/dnsstats_' . bin2hex(random_bytes(8));
		mkdir($dir);
		$alert_log = $dir . '/events.csv';
		$chart = $dir . '/chart.csv';
		if ($contents !== NULL) {
			file_put_contents($alert_log, $contents);
		}
		$source = file_get_contents(__DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_alerts.php');
		$start = strpos($source, '// Collect Alert Statistics');
		$end = strpos($source, '// Collect DNSBL widget statistics', $start);
		$code = substr($source, $start, $end - $start) . "\n}";
		$code = str_replace('/usr/local/www/pfblockerng/chart_stats.csv', $chart, $code);
		$alert_summary = TRUE;
		$alert_view = $view;
		$pfbdnsblstat = $pfbdnsblreplystat = $pfbblockstat = $pfbpermitstat = $pfbmatchstat = $hidden;
		$pfb = ['cut' => 'cut', 'grep' => 'grep', 'sed' => 'sed', 'awk' => 'awk'];
		try {
			eval($code);
			return [$alert_stats, file_exists($chart) ? file_get_contents($chart) : NULL];
		} finally {
			foreach (glob($dir . '/*') as $file) {
				unlink($file);
			}
			rmdir($dir);
		}
	}

	public static function csv(array $rows): string
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

	public function testDnsblBucketsDecodeCsvAndAggregateNonconsecutiveHours(): void
	{
		$domain = 'a,"quoted"\\.例子.test';
		$rows = [
			['DNSBL', '2030-01-15 09:01:02', $domain, '192.0.2.1', 'x|y|agent', 'TLD', 'group', 'eval.test', 'feed,one', '+', 'A'],
			['DNSBL', '2030-01-16 10:02:03', 'other.test', '192.0.2.2', 'x|y|agent', 'DNSBL', 'group', 'ignored', 'feed,one', '-', 'A', 'TCP'],
			['DNSBL', '2030-01-15 09:03:04', $domain, '192.0.2.1', 'x|y|agent', 'TLD', 'group', 'eval.test', 'feed,one', '+', 'A', 'UDP'],
		];
		[$result, $chart] = self::aggregate('dnsbl_stat', rtrim(self::csv($rows), "\n"));
		$s = $result['dnsbl_stat'];
		$this->assertSame(3, $result['count']['dnsbl_stat']);
		foreach ([
			'dnsblwebtype' => ['DNSBL' => 3], 'dnsbldate' => ['2030-01-16' => 1, '2030-01-15' => 2],
			'dnsblchart' => [], 'dnsbldatehr' => ['2030-01-15 09' => 2, '2030-01-16 10' => 1],
			'dnsbldatehrmin' => ['2030-01-16 10:02' => 1, '2030-01-15 09:03' => 1, '2030-01-15 09:01' => 1],
			'dnsbldomain' => [$domain . ',TLD' => 2, 'other.test,DNSBL' => 1], 'dnsbltld' => ['test' => 3],
			'dnsblip' => ['192.0.2.1' => 2, '192.0.2.2' => 1], 'dnsblagent' => ['agent' => 3],
			'dnsblmode' => ['TLD' => 2, 'DNSBL' => 1], 'dnsblevald' => ['TLD,eval.test' => 2], 'dnsblfeed' => ['feed,one' => 3],
		] as $type => $expected) {
			$this->assertSame($expected, $s[$type], $type);
		}
		$this->assertSame("edate,ecount\n2030-01-15 (09),2\n2030-01-16 (10),1\n", $chart);
	}

	public function testReplyAllCategoriesPreserveCacheTtlAndSuffixDepth(): void
	{
		$rows = [
			['DNS-reply','2030-01-15 09:01:02','cache','A','A','0','a.b.c.test','192.0.2.1','192.0.2.53','US'],
			['DNS-reply','2030-01-16 10:01:02','reply','AAAA','AAAA','60','c.test','192.0.2.2','192.0.2.53','US','TCP'],
			['DNS-reply','2030-01-15 09:02:02','cache','A','A','0','localhost','192.0.2.1','192.0.2.53','US','UDP'],
		];
		[$result, $chart] = self::aggregate('dnsbl_reply_stat', self::csv($rows));
		$s = $result['dnsbl_reply_stat'];
		foreach ([
			'replydate' => ['2030-01-16' => 1, '2030-01-15' => 2], 'replychart' => [],
			'replytype' => ['cache' => 2, 'reply' => 1], 'replyorec' => ['A' => 2, 'AAAA' => 1],
			'replyrec' => ['A' => 2, 'AAAA' => 1], 'replyttl' => [0 => 2, 60 => 1],
			'replydomain' => ['localhost' => 1, 'c.test' => 1, 'a.b.c.test' => 1], 'replytld' => ['test' => 2],
			'replytld2' => ['c.test' => 2], 'replytld3' => ['b.c.test' => 1],
			'replysrcipd' => ['localhost,192.0.2.1' => 1, 'c.test,192.0.2.2' => 1, 'a.b.c.test,192.0.2.1' => 1],
			'replysrcip' => ['192.0.2.1' => 2, '192.0.2.2' => 1], 'replydstip' => ['192.0.2.53' => 3], 'replygeoip' => ['US' => 3],
		] as $type => $expected) {
			$this->assertSame($expected, $s[$type], $type);
		}
		$this->assertSame(3, $result['count']['dnsbl_reply_stat']);
		$this->assertSame("edate,ecount\n2030-01-15 (09),2\n2030-01-16 (10),1\n", $chart);
	}

	public function testEmptyZeroMarkersBytesLegacyDatesAndPhysicalLines(): void
	{
		$rows = [];
		foreach (['', '0', '-', '+', "bad\xff,\"\\例子", "two\nlines"] as $value) {
			$rows[] = ['DNS-reply', 'Jan 15 09:00:00', $value, 'A', 'A', '0', 'one.two.three', '', '', ''];
		}
		[$result, $chart] = self::aggregate('dnsbl_reply_stat', rtrim(self::csv($rows), "\n"));
		$this->assertSame(7, $result['count']['dnsbl_reply_stat']);
		$this->assertSame(["two\nlines" => 1, "bad\xff,\"\\例子" => 1, 0 => 1, 'Unknown' => 1], $result['dnsbl_reply_stat']['replytype']);
		$this->assertSame([], $result['dnsbl_reply_stat']['replydate']);
		$this->assertSame(['two.three' => 6], $result['dnsbl_reply_stat']['replytld2']);
		$this->assertSame(['one.two.three' => 6], $result['dnsbl_reply_stat']['replytld3']);
	}

	public function testMissingEmptyAndHiddenCategories(): void
	{
		foreach (['dnsbl_stat', 'dnsbl_reply_stat'] as $view) {
			foreach ([NULL, ''] as $contents) {
				[$result, $chart] = self::aggregate($view, $contents);
				$this->assertSame(0, $result['count'][$view]);
				$this->assertSame("edate,ecount\n", $chart);
			}
			[$baseline] = self::aggregate($view, '');
			$hidden = array_keys($baseline[$view]);
			[$result, $chart] = self::aggregate($view, '', $hidden);
			$this->assertArrayNotHasKey('count', $result);
			$this->assertNull($chart);
			[$result] = self::aggregate($view, '', [$hidden[0]]);
			$this->assertArrayNotHasKey($hidden[0], $result[$view]);
		}
	}
}

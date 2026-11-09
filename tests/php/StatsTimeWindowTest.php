<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_stats.inc';

/**
 * #3773: one shared time range for every Stats panel. Direct helper calls; every fixture is a private
 * tempnam() file that the test which made it removes and checks.
 */
final class StatsTimeWindowTest extends TestCase
{
	private const SINCE = '2030-01-15 12:00:00';
	private const DNS_MAP = ['replychart' => 2, 'replydomain' => 7, 'replydate' => 2];
	// 2030-01-10 00:00:00 UTC, one line every STEP seconds.
	private const BASE = 1894233600;
	private const STEP = 5;

	private string $timezone = 'UTC';

	protected function setUp(): void
	{
		// The window is local wall-clock; pin it so a DST shift never moves a fixture.
		$this->timezone = date_default_timezone_get();
		date_default_timezone_set('UTC');
	}

	protected function tearDown(): void
	{
		date_default_timezone_set($this->timezone);
	}

	public function testRangeAcceptsOnlyOptionKeysAndFallsBackRequestedThenSavedThenDefault(): void
	{
		$options = ['24' => '24 Hrs', '48' => '48 Hrs', '168' => '1 week', 'max' => 'All time'];
		foreach (['24', '48', '168', 'max'] as $valid) {
			$this->assertSame($valid, pfb_stats_range($valid, $valid === '48' ? '24' : '48', $options));
		}
		$this->assertSame('168', pfb_stats_range(NULL, '168', $options));
		$this->assertSame('max', pfb_stats_range('', 'max', $options));
		$this->assertSame('24', pfb_stats_range(NULL, 'nope', $options));
		$this->assertSame('24', pfb_stats_range('nope', '', $options));
		// Loose comparison would accept several of these (" 24", "24.0", "1e2") as the number they spell.
		$injected = ['1;id', '-1', '', ' 24', '24 ', "24\n", '024', '24.0', '1e2', '0', 'MAX', 'max ', '../48', '48&range=24'];
		foreach ($injected as $value) {
			$this->assertSame('168', pfb_stats_range($value, '168', $options), 'requested ' . json_encode($value));
			$this->assertSame('24', pfb_stats_range($value, $value, $options), 'saved ' . json_encode($value));
		}
	}

	public function testSinceIsLocalWallClockMinusWholeElapsedHoursAndMaxIsNull(): void
	{
		$now = 1800000000; // 2027-01-15 08:00:00 UTC
		$this->assertSame('2027-01-14 08:00:00', pfb_stats_since('24', $now));
		$this->assertSame('2027-01-15 07:00:00', pfb_stats_since('1', $now));
		$this->assertSame('2027-01-08 08:00:00', pfb_stats_since('168', $now));
		$this->assertNull(pfb_stats_since('max', $now));
		$this->assertNull(pfb_stats_since('max'));

		date_default_timezone_set('America/New_York');
		$this->assertSame('2027-01-14 03:00:00', pfb_stats_since('24', $now), 'local time, not UTC');
		// 2027-03-14 12:00 EDT is 23 calendar-hours after 2027-03-13 12:00 EST: 24 elapsed hours is 11:00 the day before.
		$this->assertSame('2027-03-13 11:00:00', pfb_stats_since('24', mktime(12, 0, 0, 3, 14, 2027)));

		date_default_timezone_set('UTC');
		$before = time();
		$since = pfb_stats_since('24');
		$after = time();
		$this->assertGreaterThanOrEqual(date('Y-m-d H:i:s', $before - 86400), $since);
		$this->assertLessThanOrEqual(date('Y-m-d H:i:s', $after - 86400), $since);
	}

	public function testWindowedDnsStatsKeepOnlyRecordsAtOrAfterSinceThroughSkewAndLegacyRows(): void
	{
		[$all, $inWindow] = $this->skewedDnsLog();
		$expected = $this->aggregate($inWindow, self::DNS_MAP); // same records, read with no window at all
		$this->assertSame(29, $expected['count']);

		$windowed = $this->aggregate($all, self::DNS_MAP, [self::SINCE]);
		$this->assertSame($expected, $windowed);
		$this->assertSame(29, $windowed['count'], 'excluded records and their physical lines must not count');
		$this->assertSame(
			['2030-01-15 12' => 6, '2030-01-15 13' => 20, '2030-01-16 09' => 1, '2030-01-16 10' => 1],
			$windowed['chart']
		);
		$this->assertSame(['2030-01-16' => 2, '2030-01-15' => 26], $windowed['stats']['replydate']);
		$domains = $windowed['stats']['replydomain'];
		ksort($domains);
		$this->assertSame(
			['bulk.test' => 20, 'early.test' => 5, 'edge.test' => 1, "m1\nx,2030-01-16 11:00:00" => 1, 'next.test' => 1],
			$domains
		);
	}

	public function testNullSinceIsIdenticalToTheCallWithoutTheArgumentAndStillReadsEverything(): void
	{
		[$all] = $this->skewedDnsLog();
		$legacy = $this->aggregate($all, self::DNS_MAP);
		$this->assertSame($legacy, $this->aggregate($all, self::DNS_MAP, [NULL]));
		$this->assertSame(substr_count($all, "\n"), $legacy['count']);
		$this->assertArrayHasKey('filler.test', $legacy['stats']['replydomain']);
		$this->assertArrayHasKey('legacy.test', $legacy['stats']['replydomain']);
	}

	public function testEmptyWindowCountsNothingAndLeavesEveryBucketEmpty(): void
	{
		[$all] = $this->skewedDnsLog();
		$empty = ['stats' => ['replychart' => [], 'replydomain' => [], 'replydate' => []], 'count' => 0, 'chart' => []];
		$this->assertSame($empty, $this->aggregate($all, self::DNS_MAP, ['2031-01-01 00:00:00']));
		$this->assertSame($empty, $this->aggregate('', self::DNS_MAP, [self::SINCE]));
	}

	public function testBoundaryIsInclusiveByTheSecondAndNonIsoRowsNeverCount(): void
	{
		// 'Jan' sorts above '2', so a bare string comparison would keep this legacy row.
		$csv = "DNS-reply,Jan 15 13:00:00,UDP,A,A,0,legacy.test,src\n"
			. $this->dnsLine('2030-01-15 11:59:59', 'before.test')
			. $this->dnsLine(self::SINCE, 'at.test');
		$this->assertSame(
			['stats' => ['replychart' => [], 'replydomain' => ['at.test' => 1], 'replydate' => ['2030-01-15' => 1]],
				'count' => 1, 'chart' => ['2030-01-15 12' => 1]],
			$this->aggregate($csv, self::DNS_MAP, [self::SINCE])
		);
	}

	public function testQuotedMultilineRecordCountsItsPhysicalLinesOnlyInsideTheWindow(): void
	{
		// The continuation line of the kept record starts with a date so the whole tail stays time-ordered.
		$csv = "DNS-reply,2030-01-15 11:40:00,UDP,A,A,0,\"old\nlines.test\",src\n"
			. $this->dnsLine(self::SINCE, 'at.test')
			. "DNS-reply,2030-01-15 12:10:00,UDP,A,A,0,\"two\nlines,2030-01-15 12:11:00\",src\n";
		$result = $this->aggregate($csv, self::DNS_MAP, [self::SINCE]);
		$this->assertSame(3, $result['count']);
		$domains = $result['stats']['replydomain'];
		ksort($domains);
		$this->assertSame(['at.test' => 1, "two\nlines,2030-01-15 12:11:00" => 1], $domains);
		$this->assertSame(['2030-01-15 12' => 2], $result['chart']);
	}

	public function testOffsetLandsOnALineStartThatSkipsOldLinesAndNeverPassesAnInWindowLine(): void
	{
		foreach ([[1, FALSE], [0, FALSE], [1, TRUE], [0, TRUE]] as [$index, $skewed]) {
			$log = $this->logFixture(60000, $index, $skewed);
			$size = strlen($log['contents']);
			$this->assertGreaterThanOrEqual(50000, count($log['lines']));
			$this->withFile($log['contents'], function (string $path) use ($log, $index, $skewed, $size): void {
				foreach ([[20000, 0], [40000, 0], [40000, 2], [55000, 0], [55000, 2]] as [$at, $extra]) {
					// $extra 0: the since-1h cut falls exactly on a line; 2: between two lines
					$stamp = self::BASE + $at * self::STEP + $extra;
					$since = gmdate('Y-m-d H:i:s', $stamp);
					$context = "index {$index} skewed " . json_encode($skewed) . " since {$since}";
					$offset = pfb_log_window_offset($path, $index, $since);
					$this->assertGreaterThan(0, $offset, "{$context}: nothing was skipped");
					$this->assertLessThan($size, $offset, $context);
					$this->assertArrayHasKey($offset, $log['line_at'], "{$context}: not a line start");
					$line = $log['line_at'][$offset];
					$this->assertLessThanOrEqual(
						$this->firstAtOrAfter($log['dates'], $since),
						$line,
						"{$context}: an in-window line lies before the offset"
					);
					$this->assertGreaterThanOrEqual(
						$this->firstAtOrAfter($log['dates'], gmdate('Y-m-d H:i:s', $stamp - 3600)),
						$line,
						"{$context}: lines older than the skew margin were not skipped"
					);
				}
			});
		}
	}

	public function testOffsetSearchDoesNotLoadTheWholeFile(): void
	{
		$log = $this->logFixture(150000, 1, FALSE);
		$size = strlen($log['contents']);
		$this->assertGreaterThan(8000000, $size);
		$this->withFile($log['contents'], function (string $path) use ($size): void {
			$since = gmdate('Y-m-d H:i:s', self::BASE + 100000 * self::STEP);
			$before = memory_get_usage();
			memory_reset_peak_usage();
			$offset = pfb_log_window_offset($path, 1, $since);
			$peak = memory_get_peak_usage() - $before;
			$this->assertGreaterThan(0, $offset);
			$this->assertLessThan(intdiv($size, 3), $peak, 'the log must be read in bounded pieces');
		});
	}

	public function testOffsetEdgeInputs(): void
	{
		$old = "2030-01-01 00:00:00,a\n2030-01-02 00:00:00,b\n";
		$new = "2030-01-16 00:00:00,a\n2030-01-17 00:00:00,b\n";
		$legacy = "Jan 15 13:00:00,a\nJan 15 13:00:01,b\n";

		$this->assertSame(0, pfb_log_window_offset('/nonexistent/' . bin2hex(random_bytes(4)), 1, self::SINCE));
		$cases = [
			'empty' => ['', 0, 0],
			'all old' => [$old, 0, strlen($old)],
			'all old, unterminated' => [rtrim($old), 0, strlen(rtrim($old))],
			'all new' => [$new, 0, 0],
			'only legacy' => [$legacy, 0, strlen($legacy)],
			'legacy then new' => [$legacy . $new, 0, strlen($legacy)],
			'date field missing' => [$old, 9, strlen($old)],
		];
		foreach ($cases as $name => [$contents, $index, $expected]) {
			$actual = $this->withFile($contents, fn (string $path): int => pfb_log_window_offset($path, $index, self::SINCE));
			$this->assertSame($expected, $actual, $name);
		}
	}

	public function testWindowLogCopiesExactlyTheInWindowIsoLinesToAPrivateTempFile(): void
	{
		$log = "Jan 15 13:00:00,legacy\n"
			. "2030-01-15 10:00:00,old\n"
			. "2030-01-15 11:59:59,just-old\n"
			. "2030-01-15 12:00:00,boundary\n"
			. "2030-01-15 11:30:00,late-old\n"
			. "2030-01-15 12:30:00,new\n"
			. "2030-01-16 08:00:00,tail\n";
		$want = "2030-01-15 12:00:00,boundary\n2030-01-15 12:30:00,new\n2030-01-16 08:00:00,tail\n";
		$this->withFile($log, function (string $path) use ($log, $want): void {
			$first = pfb_stats_window_log($path, self::SINCE);
			$second = pfb_stats_window_log($path, self::SINCE);
			try {
				$this->assertIsString($first);
				$this->assertIsString($second);
				$this->assertNotSame($first, $second);
				$this->assertNotSame($path, $first);
				$this->assertSame($want, file_get_contents($first));
				$this->assertSame($want, file_get_contents($second));
				$this->assertStringStartsWith('pfb-stats-', basename($first));
				$this->assertSame(realpath(sys_get_temp_dir()), realpath(dirname($first)));
				$this->assertSame(0600, fileperms($first) & 0777);
				$this->assertSame($log, file_get_contents($path), 'the source log must not be touched');
			} finally {
				foreach ([$first, $second] as $out) {
					if (is_string($out)) {
						unlink($out);
						$this->assertFileDoesNotExist($out);
					}
				}
			}
		});
	}

	public function testWindowLogKeepsTheFinalUnterminatedLineAndStaysEmptyOutsideTheWindow(): void
	{
		$log = "2030-01-15 11:59:59,old\n2030-01-15 12:00:00,boundary\n2030-01-16 08:00:00,tail";
		$this->withFile($log, function (string $path): void {
			$this->assertSame(
				"2030-01-15 12:00:00,boundary\n2030-01-16 08:00:00,tail",
				rtrim($this->windowLog($path, self::SINCE), "\n") // a terminator on the last line is fine
			);
			$this->assertSame('', $this->windowLog($path, '2031-01-01 00:00:00'));
		});
		$this->withFile("Jan 15 13:00:00,legacy\nnot a date\n", function (string $path): void {
			$this->assertSame('', $this->windowLog($path, self::SINCE));
		});
	}

	public function testWindowLogOfAVeryLargeLogEqualsTheInWindowLinesInFileOrder(): void
	{
		foreach ([FALSE, TRUE] as $skewed) {
			$log = $this->logFixture(60000, 0, $skewed);
			$since = gmdate('Y-m-d H:i:s', self::BASE + 45000 * self::STEP);
			$want = implode('', array_filter(
				$log['lines'],
				static fn (int $i): bool => $log['dates'][$i] >= $since,
				ARRAY_FILTER_USE_KEY
			));
			$this->assertNotSame('', $want);
			$this->assertLessThan(strlen($log['contents']), strlen($want));
			$this->withFile($log['contents'], function (string $path) use ($since, $want): void {
				$this->assertTrue($this->windowLog($path, $since) === $want);
			});
		}
	}

	public function testWindowLogOfAnUnreadableSourceIsNullAndLeavesNoTempFile(): void
	{
		$before = glob(sys_get_temp_dir() . '/pfb-stats-*') ?: [];
		$this->assertNull(pfb_stats_window_log('/nonexistent/' . bin2hex(random_bytes(4)), self::SINCE));
		$this->assertSame($before, glob(sys_get_temp_dir() . '/pfb-stats-*') ?: []);
	}

	/** Run `pfb_dns_stats()`; $extra is the optional 4th argument, empty for the legacy 3-argument call. */
	private function aggregate(string $csv, array $map, array $extra = []): array
	{
		return $this->withFile($csv, static fn (string $path): array => pfb_dns_stats($path, $map, 'Unknown', ...$extra));
	}

	/** Content of the temp file `pfb_stats_window_log()` writes, removed again before returning. */
	private function windowLog(string $path, string $since): string
	{
		$out = pfb_stats_window_log($path, $since);
		$this->assertIsString($out);
		try {
			return (string) file_get_contents($out);
		} finally {
			unlink($out);
			$this->assertFileDoesNotExist($out);
		}
	}

	private function withFile(string $contents, callable $use): mixed
	{
		$path = tempnam(sys_get_temp_dir(), 'pfb-win-');
		$this->assertIsString($path);
		try {
			file_put_contents($path, $contents);
			return $use($path);
		} finally {
			unlink($path);
			$this->assertFileDoesNotExist($path);
		}
	}

	private function dnsLine(string $date, string $domain): string
	{
		return implode(',', ['DNS-reply', $date, 'UDP', 'A', 'A', '0', $domain, 'src']) . "\n";
	}

	/**
	 * A DNS-reply log shaped like a real one around SINCE: old days, a one-hour margin full of rows that must
	 * never count, then in-window rows with older rows arriving after newer ones.
	 *
	 * @return array{0: string, 1: string} the whole log, and only the records at or after SINCE
	 */
	private function skewedDnsLog(): array
	{
		$all = '';
		$inWindow = '';
		$add = function (string $line, bool $kept) use (&$all, &$inWindow): void {
			$all .= $line;
			$inWindow .= $kept ? $line : '';
		};
		for ($i = 0; $i < 2000; $i++) { // 14 old days: something real for the offset search to skip
			$stamp = sprintf('2030-01-%02d %02d:%02d:00', 1 + intdiv($i, 144), intdiv($i % 144, 6), $i % 6 * 10);
			$add($this->dnsLine($stamp, 'filler.test'), FALSE);
		}
		$noise = [
			"DNS-reply,Jan 15 13:00:00,UDP,A,A,0,legacy.test,src\n", // 'Jan' sorts above '2'
			"DNS-reply\n",
			"DNS-reply,,UDP,A,A,0,undated.test,src\n",
			"DNS-reply,2030-01-15 11:20:00,UDP,A,A,0,\"quoted\nzone.test\",src\n",
		];
		for ($i = 0; $i < 120; $i++) { // 11:00-11:59 is inside the one-hour margin but before SINCE
			$add($this->dnsLine(sprintf('2030-01-15 11:%02d:%02d', intdiv($i, 2), $i % 2 * 30), 'zone.test'), FALSE);
			$add($noise[$i % 4], FALSE);
		}
		$add($this->dnsLine('2030-01-15 11:59:59', 'before.test'), FALSE);
		for ($i = 0; $i < 6; $i++) {
			$add($this->dnsLine(sprintf('2030-01-15 12:%02d:00', $i * 5), $i === 0 ? 'edge.test' : 'early.test'), TRUE);
			$add($this->dnsLine(sprintf('2030-01-15 11:%02d:00', 35 + $i), 'late.test'), FALSE); // arrives after newer rows
		}
		for ($i = 0; $i < 20; $i++) {
			$add($this->dnsLine(sprintf('2030-01-15 13:%02d:00', $i), 'bulk.test'), TRUE);
		}
		$add($this->dnsLine('2030-01-16 09:30:00', 'next.test'), TRUE);
		// Last record, two physical lines; its second line starts with a date so every line from the first
		// in-window row on is at or after the offset threshold.
		$add("DNS-reply,2030-01-16 10:00:00,UDP,A,A,0,\"m1\nx,2030-01-16 11:00:00\",src\n", TRUE);
		return [$all, $inWindow];
	}

	/**
	 * Time-ordered log of $count lines, one per STEP seconds from BASE; with $skewed every other line is stamped
	 * 50 minutes early (heavy out-of-order arrival, still under the one-hour skew).
	 *
	 * @return array{contents: string, lines: list<string>, dates: list<string>, line_at: array<int, int>}
	 */
	private function logFixture(int $count, int $dateIndex, bool $skewed): array
	{
		$lines = [];
		$dates = [];
		$lineAt = [];
		$offset = 0;
		for ($i = 0; $i < $count; $i++) {
			$date = gmdate('Y-m-d H:i:s', self::BASE + $i * self::STEP - ($skewed && $i % 2 === 1 ? 3000 : 0));
			$lines[] = $dateIndex === 1
				? "DNS-reply,{$date},UDP,A,A,0,host{$i}.test,src\n"
				: "{$date},100,em0,WAN,block,4,6,TCP,192.0.2.1,198.51.100.1,54321,80,in,US,pfB_v4,192.0.2.1,Feed,Unknown,Unknown,64500,asn.test,ASN,+\n";
			$dates[] = $date;
			$lineAt[$offset] = $i;
			$offset += strlen($lines[$i]);
		}
		return ['contents' => implode('', $lines), 'lines' => $lines, 'dates' => $dates, 'line_at' => $lineAt];
	}

	/** Index of the first line, in file order, whose date is at or after $threshold. */
	private function firstAtOrAfter(array $dates, string $threshold): int
	{
		foreach ($dates as $i => $date) {
			if ($date >= $threshold) {
				return $i;
			}
		}
		return count($dates);
	}
}

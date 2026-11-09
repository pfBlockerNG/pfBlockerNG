<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_stats.inc';

/**
 * #3773 hardening of the shared Stats time window, beyond StatsTimeWindowTest: non-ISO lines in the middle of a window
 * log, lines longer than a read piece, a log with a newline-free run read under a small memory limit, a DST fall-back
 * in the log, and the two page statements around `range` (the `?range[]=` guard, the auto-refresh URL). Every fixture is
 * a private temp file the test removes and checks.
 */
final class StatsTimeWindowRobustnessTest extends TestCase
{
	private const PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_alerts.php';
	private const SINCE = '2030-01-15 12:00:00';

	private string $timezone = 'UTC';

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/PageStatementLoader.php';
	}

	protected function setUp(): void
	{
		$this->timezone = date_default_timezone_get();
		date_default_timezone_set('UTC');
		$_GET = [];
	}

	protected function tearDown(): void
	{
		date_default_timezone_set($this->timezone);
		$_GET = [];
	}

	public function testNonIsoLinesBetweenInWindowLinesNeverReachTheWindowLog(): void
	{
		// 'Jan ...' and 'zzz' sort above '2030-...': only the per-line ISO check keeps them out of every IP panel.
		$old = '';
		for ($i = 0; $i < 40; $i++) {
			$old .= sprintf("2030-01-10 %02d:00:%02d,old{$i}\n", intdiv($i, 2), $i);
		}
		$legacyBlock = str_repeat("Jan 15 13:00:00,legacy\n", 300);
		$first = "2030-01-15 12:10:00,in1\n";
		$noise = "Jan 15 13:00:00,legacy-mid\n"
			. " 2030-01-15 13:00:00,leading-space\n"
			. "\"2030-01-15 13:00:00\",quoted\n"
			. "zzz,not,a,date\n"
			. "\n";
		$last = "2030-01-15 12:20:00,in2\n2030-01-16 08:00:00,in3\n";
		$log = $old . $legacyBlock . $first . $noise . $last;

		$this->withFile($log, function (string $path) use ($old, $legacyBlock, $first, $last): void {
			$out = pfb_stats_window_log($path, self::SINCE);
			$this->assertIsString($out);
			try {
				$this->assertSame($first . $last, file_get_contents($out));
			} finally {
				unlink($out);
			}
			$offset = pfb_log_window_offset($path, 0, self::SINCE);
			$this->assertGreaterThan(0, $offset, 'the old lines were not skipped');
			$this->assertLessThanOrEqual(strlen($old . $legacyBlock), $offset, 'an in-window line was skipped');
		});
	}

	public function testLinesLongerThanAReadPieceAreCopiedWholeOrSkippedWhole(): void
	{
		$lengths = [4090, 4093, 4094, 4095, 4096, 4097, 8191, 8192, 12000, 5];
		$log = '';
		$want = '';
		foreach ($lengths as $index => $length) {
			$log .= sprintf('2030-01-10 10:00:%02d,', $index) . str_repeat('o', $length) . "\n";
		}
		foreach ($lengths as $index => $length) {
			$new = sprintf('2030-01-15 13:00:%02d,', $index) . str_repeat('n', $length) . "\n";
			$log .= $new . 'Jan 15 13:00:00,' . str_repeat('l', $length) . "\n";
			$want .= $new;
		}
		$log .= '2030-01-17 00:00:00,' . str_repeat('t', 9000); // no terminator
		$want .= '2030-01-17 00:00:00,' . str_repeat('t', 9000);

		$this->withFile($log, function (string $path) use ($want): void {
			$out = pfb_stats_window_log($path, self::SINCE);
			$this->assertIsString($out);
			try {
				$this->assertTrue(file_get_contents($out) === $want, 'a long line was cut, merged or dropped');
			} finally {
				unlink($out);
			}
		});
	}

	public function testNewlineFreeRunsAreReadWithinAMemoryLimitThatCannotHoldThem(): void
	{
		// 40 MiB with no newline in the middle and 40 MiB at the end, read by a child limited to 32 MiB.
		$old = '';
		for ($i = 0; $i < 1500; $i++) {
			$old .= gmdate('Y-m-d H:i:s', 1894233600 + $i * 5) . ",old\n"; // 2030-01-10, days before SINCE
		}
		$new = '';
		for ($i = 0; $i < 1500; $i++) {
			$new .= gmdate('Y-m-d H:i:s', 1895587200 + $i * 5) . ",new\n"; // 2030-01-25, after SINCE
		}
		$dir = sys_get_temp_dir() . '/pfb-win-' . bin2hex(random_bytes(8));
		mkdir($dir, 0700);
		$fixture = $dir . '/events.log';
		$worker = $dir . '/worker.php';
		try {
			$stream = fopen($fixture, 'xb');
			$this->assertIsResource($stream);
			try {
				fwrite($stream, $old);
				for ($i = 0; $i < 40; $i++) {
					fwrite($stream, str_repeat('x', 1048576));
				}
				fwrite($stream, "\n" . $new);
				for ($i = 0; $i < 40; $i++) {
					fwrite($stream, str_repeat("\0", 1048576));
				}
			} finally {
				fclose($stream);
			}
			file_put_contents($worker, "<?php\nrequire " . var_export(__DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_stats.inc', TRUE)
				. ";\ndate_default_timezone_set('UTC');\n"
				. "\$out = pfb_stats_window_log(\$argv[1], \$argv[2]);\n"
				. "echo json_encode(['offset' => pfb_log_window_offset(\$argv[1], 0, \$argv[2]), 'size' => is_string(\$out) ? filesize(\$out) : NULL, "
				. "'head' => is_string(\$out) ? file_get_contents(\$out, FALSE, NULL, 0, 40) : NULL]);\n"
				. "if (is_string(\$out)) { unlink(\$out); }\n");
			$process = proc_open([PHP_BINARY, '-d', 'memory_limit=32M', '-d', 'display_errors=stderr', $worker, $fixture, self::SINCE],
				[0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
			$this->assertIsResource($process, 'could not start the memory-limited worker');
			fclose($pipes[0]);
			$stdout = stream_get_contents($pipes[1]);
			$stderr = stream_get_contents($pipes[2]);
			fclose($pipes[1]);
			fclose($pipes[2]);
			$status = proc_close($process);
			$this->assertSame(0, $status, "worker stdout: {$stdout}\nworker stderr: {$stderr}");
			$this->assertSame('', $stderr);
			$result = json_decode($stdout, TRUE, 512, JSON_THROW_ON_ERROR);
			$this->assertSame(strlen($old) + 40 * 1048576 + 1, $result['offset'], 'not the first in-window line');
			$this->assertSame(strlen($new), $result['size'], 'the in-window lines are the window log, the garbage is not');
			$this->assertSame(substr($new, 0, 40), $result['head']);
		} finally {
			foreach ([$worker, $fixture] as $file) {
				if (is_file($file)) {
					unlink($file);
				}
			}
			rmdir($dir);
		}
		$this->assertDirectoryDoesNotExist($dir);
	}

	/** @return array<string, array{string, string}> */
	public static function dstFallbacks(): array
	{
		return [
			'London (BST to GMT)' => ['Europe/London', '2030-10-27'],
			'Berlin (CEST to CET)' => ['Europe/Berlin', '2030-10-27'],
			'Sydney (AEDT to AEST)' => ['Australia/Sydney', '2030-04-07'],
			'New York (EDT to EST)' => ['America/New_York', '2030-11-03'],
		];
	}

	/**
	 * The stamps are local wall-clock, so a fall-back repeats an hour and the log is out of wall-clock order by up to
	 * an hour: the margin must be wall-clock arithmetic. Every window start across the repeated hour keeps every row
	 * dated at or after it.
	 */
	#[DataProvider('dstFallbacks')]
	public function testNoInWindowRowIsLostAcrossADstFallBack(string $zone, string $day): void
	{
		date_default_timezone_set($zone);
		$midnight = strtotime("{$day} 00:00:00 UTC");
		$transitions = (new DateTimeZone($zone))->getTransitions($midnight - 86400, $midnight + 2 * 86400);
		$this->assertArrayHasKey(1, $transitions, "no DST transition found for {$zone}");
		$fallback = $transitions[1]['ts'];
		$stamps = [];
		$log = '';
		for ($t = $fallback - 3 * 3600; $t <= $fallback + 3 * 3600; $t += 60) {
			$stamp = date('Y-m-d H:i:s', $t);
			$stamps[] = $stamp;
			$log .= "{$stamp},row\n";
		}
		$this->assertLessThan(count($stamps), count(array_unique($stamps)), 'the fixture must repeat a wall-clock hour');

		$this->withFile($log, function (string $path) use ($stamps): void {
			foreach ($stamps as $index => $since) {
				if ($index % 5 !== 0) {
					continue;
				}
				$want = '';
				foreach ($stamps as $stamp) {
					if ($stamp >= $since) {
						$want .= "{$stamp},row\n";
					}
				}
				$out = pfb_stats_window_log($path, $since);
				$this->assertIsString($out);
				try {
					$this->assertTrue(file_get_contents($out) === $want, "rows lost for the window starting {$since}");
				} finally {
					unlink($out);
				}
			}
		});
	}

	public function testAnArrayRangeFallsBackToTheSavedDefaultInsteadOfFailing(): void
	{
		$statements = pfb_test_page_statement(self::PAGE, '/\$stats_range\s*=/') . "\n"
			. pfb_test_page_statement(self::PAGE, '/\$stats_since\s*=/');
		$vars = ['pfbchartcnt' => '168', 'options_pfbchartcnt' => ['24' => '24', '48' => '48', '168' => '168', 'max' => 'max']];
		foreach ([
			'a valid key' => ['48', '48'],
			'the key max' => ['max', 'max'],
			'an unknown key' => ['evil', '168'],
			'an injection' => ['1;id', '168'],
			'an array' => [['x'], '168'],
			'a nested array' => [[['24']], '168'],
		] as $name => [$requested, $expected]) {
			$_GET = ['range' => $requested];
			$scope = pfb_test_page_eval($statements, $vars);
			$this->assertSame($expected, $scope['stats_range'], $name);
			$this->assertSame($expected === 'max', $scope['stats_since'] === NULL, $name);
		}
		$_GET = [];
		$this->assertSame('168', pfb_test_page_eval($statements, $vars)['stats_range'], 'no range at all is the saved default');
	}

	public function testTheAutoRefreshUrlKeepsTheRangeOnStatsViewsOnly(): void
	{
		$code = pfb_test_page_region(self::PAGE, "\$pageview = '?';", '// Validate pfSense URL');
		$refresh = static fn (string $view, bool $summary, string $range, bool $filtered): string => pfb_test_page_eval($code, [
			'pfb' => ['filterlogentries' => $filtered],
			'alert_view' => $view,
			'alert_summary' => $summary,
			'stats_range' => $range,
		])['pageview'];

		$this->assertSame('?view=ip_block_stat&range=48', $refresh('ip_block_stat', TRUE, '48', FALSE));
		$this->assertSame('?view=dnsbl_reply_stat&range=max', $refresh('dnsbl_reply_stat', TRUE, 'max', FALSE));
		$this->assertSame('?view=unified', $refresh('unified', FALSE, '48', FALSE), 'only Stats views carry a range');
		$this->assertSame('?view=reply', $refresh('reply', FALSE, '48', FALSE));
		$this->assertSame('', $refresh('alert', FALSE, '48', FALSE));
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
}

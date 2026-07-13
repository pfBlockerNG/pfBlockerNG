<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * $ip_cnt / $ip_cnt6 -- the IPv4/IPv6 line counts extracted from a DNSBL
 * domain feed's `_v4.ip`/`_v6.ip` sidecar files inside
 * sync_package_pfblockerng() (issue #1261). Both gate only a log line
 * (`if ($ip_cnt > 0) pfb_logger(...)`), never arithmetic -- display-only, so
 * a pfb_count_lines() NULL (read failure) must fall back to 0, exactly as
 * exec()'s falsy "" fell through the pre-#1261 `> 0` comparison. Not
 * unit-reachable directly (deep inside sync_package_pfblockerng()) -- pinned
 * via source-inspection, house precedent: tests/php/AliasCntGrepCountGuardTest.php.
 */
final class DnsblIpCountGuardTest extends TestCase
{
	private static string $src;

	public static function setUpBeforeClass(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc';
		$src = file_get_contents($path);
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng.inc');
		}
		self::$src = $src;
	}

	public function testIpCntAssignedFromPfbCountLinesWithNullFallback(): void
	{
		$this->assertMatchesRegularExpression(
			'/\$ip_cnt\s*=\s*pfb_count_lines\([^;]*_v4\.ip[^;]*\)\s*\?\?\s*0\s*;/',
			self::$src,
			'$ip_cnt must be assigned from pfb_count_lines(..._v4.ip) ?? 0 (issue #1261)'
		);
	}

	public function testIpCnt6AssignedFromPfbCountLinesWithNullFallback(): void
	{
		$this->assertMatchesRegularExpression(
			'/\$ip_cnt6\s*=\s*pfb_count_lines\([^;]*_v6\.ip[^;]*\)\s*\?\?\s*0\s*;/',
			self::$src,
			'$ip_cnt6 must be assigned from pfb_count_lines(..._v6.ip) ?? 0 (issue #1261)'
		);
	}

	public function testNoExecGrepForkSurvivesForIpCnt(): void
	{
		$this->assertDoesNotMatchRegularExpression(
			'/\$ip_cnt6?\s*=\s*exec\(/',
			self::$src,
			'an $ip_cnt/$ip_cnt6 = exec(...) fork survives -- issue #1261 must replace it with pfb_count_lines()'
		);
	}

	// -----------------------------------------------------------------------
	// Mirrored-expression hostile-input rows: the `> 0` log-gate must never
	// throw and must treat a NULL (read failure) as "nothing to log".
	// -----------------------------------------------------------------------

	public static function gateRows(): array
	{
		return [
			'NULL count (pfb_count_lines() read failure)' => [NULL, FALSE],
			'zero count (empty file)'                      => [0, FALSE],
			'happy path count'                              => [7, TRUE],
		];
	}

	#[DataProvider('gateRows')]
	public function testLogGateNeverThrowsAndSkipsOnNullOrZero(?int $pfbCountLinesResult, bool $expectGateOpen): void
	{
		$ip_cnt = $pfbCountLinesResult ?? 0;
		$this->assertSame($expectGateOpen, $ip_cnt > 0);
	}
}

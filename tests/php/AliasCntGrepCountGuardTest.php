<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * $alias_cnt accumulation from a per-file line count (issue #1162; issue
 * #1261: the exec("grep -c ^ <file>") fork is replaced by pfb_count_lines()).
 *
 * sync_package_pfblockerng() has two sites that feed a file's line count into
 * `+` arithmetic: `$alias_cnt = $alias_cnt + $list_cnt;`. Before #1261,
 * $list_cnt came from exec()'s raw output (a non-numeric string on a failed
 * grep, needing an inline (int) cast). Now pfb_count_lines() returns ?int
 * directly, and NULL (read failure) is coerced to 0 at the assignment
 * (`?? 0`) -- so $list_cnt is always a plain int by the time it reaches the
 * accumulation, and the accumulation itself needs no cast. Both sites are
 * inside sync_package_pfblockerng(), not unit-reachable directly -- pinned
 * here via source-inspection (house precedent:
 * tests/php/DownloadRetvalFailsafeTest.php) plus a mirrored-expression data
 * provider (house precedent: tests/php/IpRegexPrefilterGuardTest.php).
 */
final class AliasCntGrepCountGuardTest extends TestCase
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

	// -----------------------------------------------------------------------
	// Source-inspection pin -- both $alias_cnt accumulation sites exist, both
	// feed from pfb_count_lines() with a `?? 0` NULL fallback, and no exec()
	// grep fork survives at either site.
	// -----------------------------------------------------------------------

	private const ACCUMULATION_RE = '/\$alias_cnt\s*=\s*\$alias_cnt\s*\+\s*\$list_cnt\s*;/';
	private const COUNT_ASSIGN_RE = '/\$list_cnt\s*=\s*pfb_count_lines\([^;]*\)\s*\?\?\s*0\s*;/';

	public function testVacuityExactlyTwoAccumulationSitesExist(): void
	{
		$count = preg_match_all(self::ACCUMULATION_RE, self::$src);
		$this->assertSame(2, $count,
			'expected exactly 2 $alias_cnt = $alias_cnt + $list_cnt; accumulation sites '
			. "(list-reuse branch and downloaded/rebuilt branch); found {$count}");
	}

	public function testBothSitesAssignListCntFromPfbCountLinesWithNullFallback(): void
	{
		$count = preg_match_all(self::COUNT_ASSIGN_RE, self::$src);
		$this->assertSame(2, $count,
			'expected exactly 2 `$list_cnt = pfb_count_lines(...) ?? 0;` assignments feeding '
			. "the accumulation sites (issue #1261); found {$count}");
	}

	public function testNoExecGrepForkSurvivesForListCnt(): void
	{
		$this->assertDoesNotMatchRegularExpression(
			'/\$list_cnt\s*=\s*exec\(/',
			self::$src,
			'a $list_cnt = exec(...) fork survives -- issue #1261 must replace it with pfb_count_lines()'
		);
	}

	// -----------------------------------------------------------------------
	// Mirrored-expression hostile-input rows (issue #1162's failure mode +
	// the happy path). Mirrors the production expressions exactly.
	// -----------------------------------------------------------------------

	public static function accumulationRows(): array
	{
		return [
			'NULL count (pfb_count_lines() read failure)' => [NULL, 0],
			'happy path count'                             => [42, 42],
			'zero count (empty file)'                      => [0, 0],
		];
	}

	/** Mirror of the post-#1261 `$list_cnt = pfb_count_lines(...) ?? 0; $alias_cnt = $alias_cnt + $list_cnt;`. */
	#[DataProvider('accumulationRows')]
	public function testAccumulationNeverThrowsAndCoercesNullToZero(?int $pfbCountLinesResult, int $expect): void
	{
		$alias_cnt = 0;
		$list_cnt  = $pfbCountLinesResult ?? 0;
		$alias_cnt = $alias_cnt + $list_cnt;
		$this->assertSame($expect, $alias_cnt);
	}
}

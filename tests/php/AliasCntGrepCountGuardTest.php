<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * $alias_cnt accumulation from `grep -c ^ <file>` output (issue #1162).
 *
 * sync_package_pfblockerng() has two sites that feed a raw exec("grep -c ^
 * <file>") result straight into `+` arithmetic: `$alias_cnt = $alias_cnt +
 * $list_cnt;`. exec() on a failed grep (no 2>&1 capture) returns "" (or a
 * non-numeric error string), and PHP 8's `+` operator throws TypeError:
 * "Unsupported operand types: string + int" on a non-numeric string operand
 * -- fatalling the whole sync pass. Both sites are inside
 * sync_package_pfblockerng(), not unit-reachable directly -- pinned here via
 * source-inspection (house precedent: tests/php/DownloadRetvalFailsafeTest.php)
 * plus a mirrored-expression data provider (house precedent:
 * tests/php/IpRegexPrefilterGuardTest.php).
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
	// Source-inspection pin -- both $alias_cnt accumulation sites exist,
	// both cast $list_cnt to int, and no uncast form survives.
	// -----------------------------------------------------------------------

	/**
	 * `$alias_cnt = $alias_cnt + $list_cnt;` (uncast) or
	 * `$alias_cnt = $alias_cnt + (int) $list_cnt;` (cast) -- matches either
	 * form so the count assertion holds both before and after the fix.
	 */
	private const ACCUMULATION_RE = '/\$alias_cnt\s*=\s*\$alias_cnt\s*\+\s*(\(int\)\s*)?\$list_cnt\s*;/';

	public function testVacuityExactlyTwoAccumulationSitesExist(): void
	{
		$count = preg_match_all(self::ACCUMULATION_RE, self::$src);
		$this->assertSame(2, $count,
			'expected exactly 2 $alias_cnt = $alias_cnt + $list_cnt; accumulation sites '
			. "(Site A ~16702-16703, Site B ~17274-17275); found {$count}");
	}

	public function testBothAccumulationSitesCastListCntToInt(): void
	{
		preg_match_all(self::ACCUMULATION_RE, self::$src, $m);
		$this->assertCount(2, $m[0], 'vacuity re-check: exactly 2 accumulation sites must be found');
		foreach ($m[0] as $i => $statement) {
			$this->assertNotSame('', $m[1][$i],
				"accumulation site #{$i} does not cast \$list_cnt with (int) -- "
				. 'PHP 8 TypeError hazard on a failed grep (issue #1162); statement: ' . $statement);
		}
	}

	public function testNoUncastAccumulationSurvives(): void
	{
		$this->assertDoesNotMatchRegularExpression(
			'/\$alias_cnt\s*=\s*\$alias_cnt\s*\+\s*\$list_cnt\s*;/',
			self::$src,
			'an uncast $alias_cnt = $alias_cnt + $list_cnt; accumulation remains -- '
			. 'PHP 8 TypeError hazard on a failed grep (issue #1162)'
		);
	}

	// -----------------------------------------------------------------------
	// Mirrored-expression hostile-input rows (issue #1162's failure mode +
	// the happy path). Mirrors the production expressions exactly.
	// -----------------------------------------------------------------------

	public static function unguardedRows(): array
	{
		return [
			'empty exec result (grep failure)' => ['', TRUE],
			'grep error string (no such file)' => ['grep: /x: No such file or directory', TRUE],
			'happy path count'                 => ['42', FALSE],
			'zero count'                       => ['0', FALSE],
			'exec() total failure (FALSE)'     => [FALSE, FALSE],
		];
	}

	/** Unguarded mirror of the pre-fix `$alias_cnt = $alias_cnt + $list_cnt;`. */
	#[DataProvider('unguardedRows')]
	public function testUnguardedMirrorThrowsOnlyForNonNumericGrepOutput(string|bool $listCnt, bool $expectThrow): void
	{
		if ($expectThrow) {
			$this->expectException(TypeError::class);
			$this->expectExceptionMessage('Unsupported operand types');
		}
		$alias_cnt = 0;
		$alias_cnt = $alias_cnt + $listCnt;
		if (!$expectThrow) {
			$this->assertIsInt($alias_cnt);
		}
	}

	public static function guardedRows(): array
	{
		return [
			'empty exec result (grep failure)' => ['', 0],
			'grep error string (no such file)' => ['grep: /x: No such file or directory', 0],
			'happy path count'                 => ['42', 42],
			'zero count'                       => ['0', 0],
			'exec() total failure (FALSE)'     => [FALSE, 0],
		];
	}

	/** Guarded mirror of the post-fix `$alias_cnt = $alias_cnt + (int) $list_cnt;` -- never throws. */
	#[DataProvider('guardedRows')]
	public function testGuardedMirrorCoercesNonNumericGrepOutputToZero(string|bool $listCnt, int $expect): void
	{
		$alias_cnt = 0;
		$alias_cnt = $alias_cnt + (int) $listCnt;
		$this->assertSame($expect, $alias_cnt);
	}

	// -----------------------------------------------------------------------
	// Motivating-semantics assertion -- the exact PHP 8 hazard the (int)
	// casts defend against.
	// -----------------------------------------------------------------------

	public function testEmptyStringPlusIntThrowsTypeErrorBackingTheGuard(): void
	{
		$this->expectException(TypeError::class);
		$this->expectExceptionMessage('Unsupported operand types');
		// phpcs:ignore -- deliberately unguarded: this IS the hazard the (int) cast defends against.
		$unused = 0 + '';
	}
}

<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1777: two narrow diagnostic-only guards in pfblockerng_alerts.php,
 * each eval-extracted VERBATIM (pure array-index logic, no page state) and
 * run standalone -- guard-state-agnostic, so this file is red pre-fix and
 * green post-fix unchanged.
 *
 * (a) pie_block() (:4917-5052, mixed HTML/PHP template) segments the pie
 *     chart over `for ($i = 0; $i < ($numsegments-1); $i++) { if ($k[$i]) ...`
 *     -- $numsegments-1 can exceed count($k) (fewer real entries than pie
 *     segments), so $k[$i] undefined-key warns on every trailing iteration.
 *     The read is already effectively optional (falsy skips the segment) --
 *     `?? NULL` silences the warning without changing which iterations build
 *     a segment. The loop bound must NOT be shortened: $i survives the loop
 *     and is read again (`$segcolors[$i % $numsegments]`) to colour the
 *     trailing "Other" segment -- bounding the loop to count($k) would shift
 *     $i and silently change that colour.
 *
 * (b) The alert-summary day/hour stat loop (:1774-1785) splits a shell stat
 *     line on the first space (`explode(' ', trim($line), 2)`); a line with
 *     no space at all (a stray/short summary row) yields a single-element
 *     $data, so $data[1] is undefined -- `?? ''` keeps the existing `?:
 *     $unknown_msg` fallback semantics (both '' and NULL are falsy) while
 *     dropping the warning.
 */
final class AlertsPieBlockAndStatsGuardTest extends TestCase
{
	private const ALERTS_PHP = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_alerts.php';

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(self::ALERTS_PHP);
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_alerts.php');
		}

		if (!function_exists('pfb_alerts_oracle_pie_segment_loop')) {
			// Anchored on the for-loop header through the "Other" segment block's
			// closing brace -- captures BOTH the guarded $k[$i] read and the
			// post-loop $i re-use verbatim, in one extraction.
			if (!preg_match(
				'/(for \(\$i = 0; \$i < \(\$numsegments-1\); \$i\+\+\) \{\n.*?\n\t\}\n\n'
				. '\t\$balance = \$sumlines - \$numentries;\n'
				. '\tif \(\$balance > 0\) \{\n.*?\n\t\})\n\?>/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: pie_block segment loop not found');
			}
			eval(
				'function pfb_alerts_oracle_pie_segment_loop(array $summary, int $numsegments, array $segcolors, int $sumlines): array {'
				. ' $k = array_keys($summary); $numentries = 0; ob_start();'
				. $m[1]
				. ' $out = (string) ob_get_clean();'
				. ' return [$out, $numentries, $i]; }'
			);
		}

		if (!function_exists('pfb_alerts_oracle_stat_bucket_key')) {
			if (!preg_match(
				'/\$data = array_map\(\'trim\', explode\(\' \', trim\(\$line\), 2\)\);\n(?:\t*\/\/[^\n]*\n)*\t*'
				. '(\$alert_stats\[\$alert_view\]\[\$stat_type\]\[[^\n]*\n)/',
				$src,
				$m2
			)) {
				throw new RuntimeException('test bootstrap: stat-bucket line not found');
			}
			eval(
				'function pfb_alerts_oracle_stat_bucket_key(string $line, string $unknown_msg): array {'
				. ' $alert_view = \'v\'; $stat_type = \'t\'; $alert_stats = [];'
				. ' $data = array_map(\'trim\', explode(\' \', trim($line), 2));'
				. $m2[1]
				. ' return [array_key_first($alert_stats[\'v\'][\'t\']), reset($alert_stats[\'v\'][\'t\'])]; }'
			);
		}
	}

	private function runCapturing(callable $fn): array
	{
		$diagnostics = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$diagnostics): bool {
			$diagnostics[] = $errstr;
			return TRUE;
		});
		try {
			$result = $fn();
		} finally {
			restore_error_handler();
		}
		return [$result, $diagnostics];
	}

	/** @return string[] */
	private static function undefinedKeyDiagnostics(array $diagnostics): array
	{
		return array_values(array_filter($diagnostics, static fn (string $d): bool => str_contains($d, 'Undefined array key')));
	}

	// -----------------------------------------------------------------------
	// (a) pie_block() segment loop.
	// -----------------------------------------------------------------------

	public function testPieSegmentLoopEmitsNoUndefinedArrayKeyWhenFewerEntriesThanSegments(): void
	{
		// 2 real entries, 5 pie segments -> the loop runs $i=0..3, and $k[2]/$k[3]
		// are undefined (only $k[0]/$k[1] exist).
		[$result, $diagnostics] = $this->runCapturing(static fn () => pfb_alerts_oracle_pie_segment_loop(
			['a.example' => 10, 'b.example' => 5],
			5,
			['#111', '#222', '#333', '#444', '#555'],
			15
		));

		$undefined = self::undefinedKeyDiagnostics($diagnostics);
		$this->assertSame([], $undefined, "pie_block()'s segment loop must emit zero 'Undefined array key' diagnostics, got:\n" . implode("\n", $undefined));

		[$out, $numentries, ] = $result;
		$this->assertSame(2, $numentries, 'only the 2 real entries must build a segment (behaviour-preserving)');
		$this->assertStringContainsString('a.example', $out);
		$this->assertStringContainsString('b.example', $out);
	}

	public function testPieSegmentLoopPostLoopIndexIsUnchangedByTheGuard(): void
	{
		// Pins the "Other" segment colour derivation: $i must equal the loop's
		// natural post-condition value ($numsegments-1), NOT be shortened by a
		// count($k)-based bound -- the exact regression this fix must avoid.
		$numsegments = 5;
		[$result, ] = $this->runCapturing(static fn () => pfb_alerts_oracle_pie_segment_loop(
			['a.example' => 10, 'b.example' => 5],
			$numsegments,
			['#111', '#222', '#333', '#444', '#555'],
			15
		));

		[$out, , $finalI] = $result;
		$this->assertSame($numsegments - 1, $finalI, '$i must survive the loop unshortened -- bounding to count($k) would change this');
		// $segcolors[$i % $numsegments] with the unshortened $i=4 -> index 4 -> '#555'.
		$this->assertStringContainsString('"color": "#555"', $out, 'the "Other" segment colour must use the UNSHORTENED post-loop $i');
	}

	// -----------------------------------------------------------------------
	// (b) alert-summary stat bucket key.
	// -----------------------------------------------------------------------

	public function testStatBucketKeyEmitsNoUndefinedArrayKeyOnASpacelessLine(): void
	{
		[$result, $diagnostics] = $this->runCapturing(static fn () => pfb_alerts_oracle_stat_bucket_key('14', 'Unknown'));

		$undefined = self::undefinedKeyDiagnostics($diagnostics);
		$this->assertSame([], $undefined, "the stat-bucket key build must emit zero 'Undefined array key' diagnostics on a spaceless line, got:\n" . implode("\n", $undefined));
		[$bucketKey, ] = $result;
		$this->assertSame('Unknown', $bucketKey, 'a spaceless line must still fall back to $unknown_msg (behaviour-preserving)');
	}

	public function testStatBucketKeyPassesThroughAWellFormedLineUnchanged(): void
	{
		[$result, $diagnostics] = $this->runCapturing(static fn () => pfb_alerts_oracle_stat_bucket_key('  12 example.com', 'Unknown'));

		$this->assertSame([], self::undefinedKeyDiagnostics($diagnostics));
		[$bucketKey, $bucketCount] = $result;
		$this->assertSame('example.com', $bucketKey, 'a well-formed line must still bucket by its own key (behaviour-preserving)');
		// issue #1792: the bucket count is a genuine int now ((int) cast at the site).
		$this->assertSame(12, $bucketCount);
	}
}

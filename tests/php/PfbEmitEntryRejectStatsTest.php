<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_emit_entry_reject_stats() -- reads the Python-emitted per-entry reject tally
 * artifact (ADR-48 Phase 4, issue #789) and emits ONE canonical stage=entries
 * line per (feed, nonzero bucket) via pfb_validate_log(). Python only WRITES the
 * artifact; this is the sole place the line is EMITTED (sinks stay PHP-only).
 * Uses the sink-capture technique from PfbValidateLogTest: $GLOBALS['pfb']
 * 'log'/'errlog' point at temp files so the real on-disk write is asserted.
 *
 * ADR-60 P2: pfb_logger() inserts its ISO-8601 stamp AFTER
 * pfb_validate_log_line()'s leading "\n" -- assertions below match on that
 * shape via stampedLinePattern(), not the pre-stamp literal.
 */
#[CoversFunction('pfb_emit_entry_reject_stats')]
final class PfbEmitEntryRejectStatsTest extends TestCase
{
	/** @var string[] temp files to remove in tearDown */
	private array $tmpfiles = [];

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $saved = [];

	protected function setUp(): void
	{
		foreach (['log', 'errlog', 'runlog', 'runlog_active'] as $k) {
			$this->saved[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : false;
		}
		// A stray 'runlog_active' from an earlier test must not mirror our writes
		// into a third file this test never provisions.
		unset($GLOBALS['pfb']['runlog'], $GLOBALS['pfb']['runlog_active']);
	}

	/** Regex matching $expectedLine (pfb_validate_log_line()'s output) as pfb_logger() now stamps it. */
	private function stampedLinePattern(string $expectedLine): string
	{
		return '/\n\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} ' . preg_quote(substr($expectedLine, 1), '/') . '/';
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $k => $prev) {
			if ($prev === false) {
				unset($GLOBALS['pfb'][$k]);
			} else {
				$GLOBALS['pfb'][$k] = $prev;
			}
		}
		foreach ($this->tmpfiles as $f) {
			if (is_file($f)) {
				$this->assertTrue(unlink($f), "failed to remove temp file {$f}");
			}
		}
		$this->tmpfiles = [];
	}

	private function tempFile(string $prefix): string
	{
		$path = tempnam(sys_get_temp_dir(), $prefix);
		$this->assertNotFalse($path, "could not create temp file for {$prefix}");
		$this->tmpfiles[] = $path;
		return $path;
	}

	private function statsFile(string $contents): string
	{
		$path = $this->tempFile('pfb_py_reject_stats_');
		file_put_contents($path, $contents);
		return $path;
	}

	/** Seed BOTH sinks the sink-capture technique reads and return the pfB log path. */
	private function seedLogSinks(): string
	{
		$log = $this->tempFile('pfb_emit_reject_log_');
		$GLOBALS['pfb']['log'] = $log;
		$GLOBALS['pfb']['errlog'] = $this->tempFile('pfb_emit_reject_errlog_');
		return $log;
	}

	public function testNonzeroBucketsEmitOneCanonicalLineEach(): void
	{
		// Given: an artifact row with BOTH buckets nonzero.
		$log = $this->seedLogSinks();
		$stats = $this->statsFile(json_encode([
			['feed' => 'FeedA', 'group' => 'GroupA', 'shape' => 3, 'wire_cap' => 5],
		]));

		// When: the artifact is read.
		pfb_emit_entry_reject_stats($stats);

		// Then: one canonical line per bucket, exact shape.
		$logContents = (string) file_get_contents($log);
		$expectedShape = pfb_validate_log_line('FeedA', 'entries', 'shape', '3');
		$expectedWireCap = pfb_validate_log_line('FeedA', 'entries', 'wire_cap', '5');
		$this->assertMatchesRegularExpression(
			$this->stampedLinePattern($expectedShape),
			$logContents,
			"expected <{$expectedShape}> in <{$logContents}>"
		);
		$this->assertMatchesRegularExpression(
			$this->stampedLinePattern($expectedWireCap),
			$logContents,
			"expected <{$expectedWireCap}> in <{$logContents}>"
		);
	}

	public function testZeroCountBucketEmitsNoLineButNonzeroSiblingStillDoes(): void
	{
		// Given: one bucket is zero, the other nonzero -- proves the per-bucket
		// gate, not an all-or-nothing row decision.
		$log = $this->seedLogSinks();
		$stats = $this->statsFile(json_encode([
			['feed' => 'FeedB', 'group' => 'GroupB', 'shape' => 0, 'wire_cap' => 2],
		]));

		pfb_emit_entry_reject_stats($stats);

		$logContents = (string) file_get_contents($log);
		$shapeLine = pfb_validate_log_line('FeedB', 'entries', 'shape', '0');
		$this->assertDoesNotMatchRegularExpression(
			$this->stampedLinePattern($shapeLine),
			$logContents,
			"a zero-count bucket must not log a line, got <{$logContents}>"
		);
		$wireCapLine = pfb_validate_log_line('FeedB', 'entries', 'wire_cap', '2');
		$this->assertMatchesRegularExpression($this->stampedLinePattern($wireCapLine), $logContents);
	}

	public function testEmptyArrayEmitsNoLines(): void
	{
		// Given: the artifact Python writes when a run had zero rejects ("[]").
		$log = $this->seedLogSinks();
		$stats = $this->statsFile('[]');

		pfb_emit_entry_reject_stats($stats);

		$this->assertSame('', file_get_contents($log), 'an empty tally artifact must emit nothing');
	}

	public function testAbsentFileEmitsNoLinesAndDoesNotError(): void
	{
		// Given: no artifact at all (fresh boot / an old python module).
		$log = $this->seedLogSinks();

		pfb_emit_entry_reject_stats(sys_get_temp_dir() . '/pfb_py_reject_stats_does_not_exist.json');

		$this->assertSame('', file_get_contents($log), 'a missing artifact must emit nothing, never error');
	}

	public function testCorruptJsonEmitsNoLinesAndDoesNotError(): void
	{
		// Given: a truncated/corrupt artifact (e.g. a write raced a read).
		$log = $this->seedLogSinks();
		$stats = $this->statsFile('{not valid json');

		pfb_emit_entry_reject_stats($stats);

		$this->assertSame('', file_get_contents($log), 'corrupt JSON must emit nothing, never throw');
	}

	public function testIssue2371SuffixBucketsEmitTheirOwnCanonicalLines(): void
	{
		// Given: an artifact row shaped the way the Python writer actually
		// emits it -- shape/wire_cap ALWAYS present (zero included), the #2371
		// suffix buckets present only because they fired.
		$log = $this->seedLogSinks();
		$stats = $this->statsFile(json_encode([
			[
				'feed' => 'FeedC',
				'group' => 'GroupC',
				'shape' => 0,
				'wire_cap' => 0,
				'suffix_drop' => 2,
				'suffix_demote' => 1,
			],
		]));

		// When: the artifact is read.
		pfb_emit_entry_reject_stats($stats);

		// Then: one canonical line per #2371 bucket, exact shape.
		$logContents = (string) file_get_contents($log);
		$expectedDrop = pfb_validate_log_line('FeedC', 'entries', 'suffix_drop', '2');
		$expectedDemote = pfb_validate_log_line('FeedC', 'entries', 'suffix_demote', '1');
		$this->assertMatchesRegularExpression(
			$this->stampedLinePattern($expectedDrop),
			$logContents,
			"expected <{$expectedDrop}> in <{$logContents}>"
		);
		$this->assertMatchesRegularExpression(
			$this->stampedLinePattern($expectedDemote),
			$logContents,
			"expected <{$expectedDemote}> in <{$logContents}>"
		);
	}

	public function testIssue2371AbsentSuffixBucketsEmitNoLines(): void
	{
		// Given: a legacy-shaped row that never carries the #2371 keys at all
		// (the pre-#2371 artifact shape: shape/wire_cap always written).
		$log = $this->seedLogSinks();
		$stats = $this->statsFile(json_encode([
			['feed' => 'FeedD', 'group' => 'GroupD', 'shape' => 1, 'wire_cap' => 0],
		]));

		pfb_emit_entry_reject_stats($stats);

		$logContents = (string) file_get_contents($log);
		$this->assertDoesNotMatchRegularExpression(
			$this->stampedLinePattern(pfb_validate_log_line('FeedD', 'entries', 'suffix_drop', '0')),
			$logContents,
			"an absent bucket must not log a line, got <{$logContents}>"
		);
		$this->assertStringNotContainsString(
			'suffix_demote',
			$logContents,
			"an absent suffix_demote bucket must not log a line, got <{$logContents}>"
		);
		$this->assertMatchesRegularExpression(
			$this->stampedLinePattern(pfb_validate_log_line('FeedD', 'entries', 'shape', '1')),
			$logContents
		);
	}

	public function testNonScalarFieldsAreSkippedSilently(): void
	{
		// Given: syntactically valid JSON whose values have hostile SHAPES -- an
		// array where a scalar belongs. (string)/(int) casts on an array raise
		// PHP warnings and stringify to "Array", so such entries must be skipped
		// outright, and a non-scalar COUNT must read as 0, not emit
		// (adversarial-review fix, PR #807). The doc contract is "corrupt
		// artifact = silent no-op" -- warnings are not silent.
		$log = $this->seedLogSinks();
		$stats = $this->statsFile(json_encode([
			['feed' => [1, 2], 'shape' => 5],                    // array feed -> whole entry skipped
			['feed' => 'FeedOk', 'shape' => ['nested' => 1]],    // array count -> bucket reads 0
			['feed' => 'FeedReal', 'wire_cap' => 3],             // sane sibling still emits
		]));

		pfb_emit_entry_reject_stats($stats);

		$logContents = (string) file_get_contents($log);
		$this->assertStringNotContainsString('feed=Array', $logContents, 'an array feed must never stringify into a line');
		$this->assertStringNotContainsString('FeedOk', $logContents, 'a non-scalar count must read as 0 (no line)');
		$this->assertMatchesRegularExpression(
			$this->stampedLinePattern(pfb_validate_log_line('FeedReal', 'entries', 'wire_cap', '3')),
			$logContents,
			'a sane sibling entry must still emit despite hostile neighbours'
		);
	}
}

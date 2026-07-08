<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-60 S2.2 age-cutoff pure helpers:
 *
 *   pfb_log_age_field_mode(string $logtype): string
 *   pfb_log_line_timestamp(string $line, string $field_mode): ?int
 *   pfb_log_age_cutoff(array $lines, int $cutoff_ts, string $field_mode): array
 *
 * All three are pure (no I/O) -- pfb_log_mgmt()'s integration with real files
 * (LogMgmtAgeCutoffTest.php) exercises the wiring; this suite pins the parsing
 * and scan logic in isolation, including every S2.6 hostile-input row.
 */
#[CoversFunction('pfb_log_age_field_mode')]
#[CoversFunction('pfb_log_line_timestamp')]
#[CoversFunction('pfb_log_age_cutoff')]
final class LogAgeCutoffTest extends TestCase
{
	// -----------------------------------------------------------------------
	// pfb_log_age_field_mode() -- per-type field-position mapping (S2.1).
	// -----------------------------------------------------------------------

	/**
	 * Every one of the 10 log types maps to its verified field position:
	 * 'log'/'errlog'/'extraslog' are a leading line-prefix; 'dnslog'/
	 * 'dnsreplylog'/'unilog' carry the timestamp at CSV field 1 (field 0 is a
	 * type label prepended by both writers); the rest are CSV field 0.
	 */
	public function testFieldModeMapsEveryLogTypeToItsVerifiedPosition(): void
	{
		$expected = [
			'log'             => 'prefix',
			'errlog'          => 'prefix',
			'extraslog'       => 'prefix',
			'ip_blocklog'     => 'field0',
			'ip_permitlog'    => 'field0',
			'ip_matchlog'     => 'field0',
			'dnsbl_parse_err' => 'field0',
			'dnslog'          => 'field1',
			'dnsreplylog'     => 'field1',
			'unilog'          => 'field1',
		];

		foreach ($expected as $logtype => $mode) {
			$this->assertSame($mode, pfb_log_age_field_mode($logtype),
				"{$logtype} must map to field mode '{$mode}'"
			);
		}
	}

	// -----------------------------------------------------------------------
	// pfb_log_line_timestamp() -- extraction + strict validation.
	// -----------------------------------------------------------------------

	/**
	 * 'prefix' mode reads the leading 19 chars ('log'/'errlog'/'extraslog' shape).
	 */
	public function testPrefixModeParsesLeadingTimestamp(): void
	{
		$ts = pfb_log_line_timestamp('2026-07-08 14:30:00 some log message', 'prefix');
		$this->assertSame(mktime(14, 30, 0, 7, 8, 2026), $ts, 'prefix timestamp must parse to the exact second');
	}

	/**
	 * 'field0' mode reads CSV column 0 ('ip_blocklog'/'dnsbl_parse_err' shape).
	 */
	public function testField0ModeParsesFirstCsvColumn(): void
	{
		$ts = pfb_log_line_timestamp('2026-07-08 14:30:00,3,eth0,WAN,block,4', 'field0');
		$this->assertSame(mktime(14, 30, 0, 7, 8, 2026), $ts, 'field0 timestamp must parse to the exact second');
	}

	/**
	 * 'field1' mode reads CSV column 1 -- the label at column 0 (e.g.
	 * 'DNSBL-python'/'block') is skipped ('dnslog'/'dnsreplylog'/'unilog' shape).
	 */
	public function testField1ModeParsesSecondCsvColumnSkippingTheLabel(): void
	{
		$ts = pfb_log_line_timestamp('DNSBL-python,2026-07-08 14:30:00,example.com,127.0.0.1', 'field1');
		$this->assertSame(mktime(14, 30, 0, 7, 8, 2026), $ts, 'field1 timestamp must parse to the exact second');
	}

	/**
	 * 'field1' mode with a line missing the second column (only 1 field, no
	 * comma at all) has no candidate to parse -- NULL, not a crash.
	 */
	public function testField1ModeWithMissingSecondColumnReturnsNull(): void
	{
		$this->assertNull(pfb_log_line_timestamp('onlyonefield', 'field1'),
			'field1 mode with no second CSV column must return NULL'
		);
	}

	/**
	 * S2.6 hostile row -- a corrupted/truncated timestamp prefix (a partial
	 * write mid-line from a crash) is shorter than 19 chars -- unparseable.
	 */
	public function testCorruptedTruncatedPrefixIsUnparseable(): void
	{
		$this->assertNull(pfb_log_line_timestamp('2026-07-08 14:3', 'prefix'),
			'a truncated 15-char prefix must not parse as a valid timestamp'
		);
	}

	/**
	 * S2.6 hostile row -- a completely garbage line (legacy pre-rework
	 * free-text with no timestamp at all) is unparseable.
	 */
	public function testGarbageLineIsUnparseable(): void
	{
		$this->assertNull(pfb_log_line_timestamp('garbage line here', 'prefix'),
			'a line with no timestamp shape at all must return NULL'
		);
	}

	/**
	 * S2.6 hostile row -- empty input is unparseable.
	 */
	public function testEmptyLineIsUnparseable(): void
	{
		$this->assertNull(pfb_log_line_timestamp('', 'prefix'), 'an empty line must return NULL');
	}

	/**
	 * An invalid-but-19-char-shaped timestamp ('2026-13-45 99:99:99' -- month
	 * 13, day 45, hour/min/sec 99) is rejected: DateTime::createFromFormat()
	 * alone silently OVERFLOWS this into a different, valid-looking date (verified
	 * this session: it rolls forward to 2027-02-18 04:40:39) -- the round-trip
	 * string-equality check catches what createFromFormat()'s leniency misses.
	 */
	public function testInvalidButShapedTimestampIsRejectedByRoundTripCheck(): void
	{
		$this->assertNull(pfb_log_line_timestamp('2026-13-45 99:99:99', 'prefix'),
			'an out-of-range but 19-char-shaped timestamp must be rejected, not silently overflowed'
		);
	}

	// -----------------------------------------------------------------------
	// pfb_log_age_cutoff() -- the leading-run scan.
	// -----------------------------------------------------------------------

	/**
	 * S2.6 hostile row -- an empty candidate (empty file) yields an empty result.
	 */
	public function testEmptyLinesArrayReturnsEmptyArray(): void
	{
		$this->assertSame([], pfb_log_age_cutoff([], time(), 'prefix'), 'empty input must yield empty output');
	}

	/**
	 * S2.6 hostile row -- a file with ONLY unparseable (legacy-format) lines:
	 * every line counts as expired -- the whole file is dropped.
	 */
	public function testAllLegacyFormatLinesAreAllDropped(): void
	{
		$lines = ['legacy line one', 'legacy line two', 'legacy line three'];
		$this->assertSame([], pfb_log_age_cutoff($lines, time(), 'prefix'),
			'a file with only unparseable lines must be entirely dropped (unparseable = expired)'
		);
	}

	/**
	 * All lines fresh (well within the window): nothing is dropped.
	 */
	public function testAllFreshLinesAreAllKept(): void
	{
		$now   = time();
		$lines = [
			date('Y-m-d H:i:s', $now - 60) . ' one',
			date('Y-m-d H:i:s', $now - 30) . ' two',
			date('Y-m-d H:i:s', $now)      . ' three',
		];
		$this->assertSame($lines, pfb_log_age_cutoff($lines, $now - 3600, 'prefix'),
			'all lines within the window must be kept, in order'
		);
	}

	/**
	 * S2.6 hostile row -- a realistic upgrade scenario: a mix of legacy
	 * (unparseable) lines followed by new-format fresh lines. Only the legacy
	 * lines are dropped.
	 *
	 * Scenario:
	 *   Given 2 legacy lines (no timestamp) followed by 2 fresh ISO lines.
	 *   When  pfb_log_age_cutoff() scans with a cutoff well in the past.
	 *   Then  only the 2 fresh lines survive.
	 */
	public function testMixedLegacyAndNewFormatDropsOnlyTheLegacyLines(): void
	{
		$now   = time();
		$fresh1 = date('Y-m-d H:i:s', $now - 60) . ' fresh one';
		$fresh2 = date('Y-m-d H:i:s', $now)      . ' fresh two';
		$lines  = ['legacy one', 'legacy two', $fresh1, $fresh2];

		$this->assertSame([$fresh1, $fresh2], pfb_log_age_cutoff($lines, $now - 3600, 'prefix'),
			'the leading legacy run must be dropped; both fresh lines must survive'
		);
	}

	/**
	 * Leading expired run followed by fresh lines: only the fresh tail survives,
	 * dropped in the same chronological order (no reordering).
	 */
	public function testLeadingExpiredRunIsDroppedFreshTailSurvives(): void
	{
		$now      = time();
		$expired1 = date('Y-m-d H:i:s', $now - (40 * 86400)) . ' old one';
		$expired2 = date('Y-m-d H:i:s', $now - (35 * 86400)) . ' old two';
		$fresh1   = date('Y-m-d H:i:s', $now - 60) . ' new one';
		$fresh2   = date('Y-m-d H:i:s', $now)      . ' new two';

		$lines = [$expired1, $expired2, $fresh1, $fresh2];
		$cutoff = $now - (10 * 86400); // 10-day window

		$this->assertSame([$fresh1, $fresh2], pfb_log_age_cutoff($lines, $cutoff, 'prefix'),
			'the leading 40/35-day-old lines must be dropped; the fresh tail must survive in order'
		);
	}

	/**
	 * S2.6 hostile row -- boundary, "kept" side: a line whose timestamp is
	 * EXACTLY at the cutoff (== now - N days) is NOT older than the cutoff --
	 * it must be kept (S2.2: "drop lines older than now - N days").
	 */
	public function testLineExactlyAtCutoffBoundaryIsKept(): void
	{
		$cutoff = time() - (10 * 86400);
		$line   = date('Y-m-d H:i:s', $cutoff) . ' boundary';

		$this->assertSame([$line], pfb_log_age_cutoff([$line], $cutoff, 'prefix'),
			'a line timestamped exactly at the cutoff must be kept (not "older than")'
		);
	}

	/**
	 * S2.6 hostile row -- boundary, "dropped" side: a line one second OLDER
	 * than the cutoff must be dropped.
	 */
	public function testLineOneSecondOlderThanCutoffBoundaryIsDropped(): void
	{
		$cutoff = time() - (10 * 86400);
		$line   = date('Y-m-d H:i:s', $cutoff - 1) . ' just too old';

		$this->assertSame([], pfb_log_age_cutoff([$line], $cutoff, 'prefix'),
			'a line one second older than the cutoff must be dropped'
		);
	}

	/**
	 * S2.6 hostile row -- a corrupted/truncated timestamp among the LEADING
	 * (still-scanning) run is treated as expired and dropped, same as any
	 * other unparseable line.
	 */
	public function testCorruptedPrefixInLeadingRunIsDroppedAsExpired(): void
	{
		$now    = time();
		$fresh  = date('Y-m-d H:i:s', $now) . ' fresh';
		$lines  = ['2026-07-08 14:3', $fresh]; // truncated, then a fresh line

		$this->assertSame([$fresh], pfb_log_age_cutoff($lines, $now - 3600, 'prefix'),
			'a corrupted/truncated leading timestamp must be treated as expired and dropped'
		);
	}

	/**
	 * Once the first non-expired line is found, the scan stops -- everything
	 * after it is kept verbatim WITHOUT re-validation (S2.2: "single linear
	 * scan with an early stop... no need to touch the rest"). A corrupted line
	 * AFTER a confirmed keeper is kept as-is, not re-checked/dropped.
	 */
	public function testLinesAfterFirstKeeperAreKeptWithoutReValidation(): void
	{
		$now      = time();
		$keeper   = date('Y-m-d H:i:s', $now) . ' keeper';
		$garbled  = 'this line is garbled and would be unparseable on its own';

		$lines = [$keeper, $garbled];

		$this->assertSame([$keeper, $garbled], pfb_log_age_cutoff($lines, $now - 3600, 'prefix'),
			'a garbled line AFTER the first keeper must be kept unconditionally, not re-validated'
		);
	}
}

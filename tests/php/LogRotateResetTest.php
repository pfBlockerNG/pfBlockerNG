<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-30 Phase 3 — Marker parse/serialize seams + per-log selection logic.
 *
 * Tests the pure, off-box-testable helpers introduced in pfb_log_reset():
 *   pfb_log_rotate_marker_parse(string $contents): array
 *   pfb_log_rotate_marker_serialize(array $entries): string
 *
 * Also tests the per-log selection decision using pfb_log_should_reset()
 * with realistic marker data — asserts that one eligible log triggers reset
 * while another in the same period does not (per-log independence).
 *
 * The actual truncate/exec is the live-VM smoke's job (Phase 5); these tests
 * assert the decision + marker logic only, with no real file I/O.
 *
 * Coverage mandate (CLAUDE.md):
 *   - Every branch of parse (normal, blank, garbled = no '=', garbled = bad type,
 *     multiple entries, overwrite last occurrence of a duplicate key).
 *   - Every branch of serialize (empty map, single entry, multiple entries sorted).
 *   - Round-trip: parse(serialize(m)) == m for several maps.
 *   - Per-log independence: eligible log => should reset; same-period log => no-op.
 *   - Before-and-after in transition tests.
 */
final class LogRotateResetTest extends TestCase
{
	// -----------------------------------------------------------------------
	// pfb_log_rotate_marker_parse() — parse marker file contents
	// -----------------------------------------------------------------------

	/**
	 * Empty string contents (absent marker file) returns an empty map.
	 *
	 * Scenario:
	 *   Given $contents = '' (marker file absent or empty).
	 *   When  pfb_log_rotate_marker_parse('').
	 *   Then  returns [] (no entries; every log treated as "never reset").
	 */
	public function testParseEmptyContentsReturnsEmptyMap(): void
	{
		$result = pfb_log_rotate_marker_parse('');
		$this->assertSame([], $result, 'empty string yields empty map');
	}

	/**
	 * A single well-formed entry is parsed correctly.
	 *
	 * Scenario:
	 *   Given $contents = "log=2025-07-15\n".
	 *   When  pfb_log_rotate_marker_parse($contents).
	 *   Then  returns ['log' => '2025-07-15'].
	 */
	public function testParseSingleWellFormedEntry(): void
	{
		$contents = "log=2025-07-15\n";
		$result   = pfb_log_rotate_marker_parse($contents);
		$this->assertSame(['log' => '2025-07-15'], $result, 'single entry parsed');
	}

	/**
	 * Multiple well-formed entries are all parsed.
	 *
	 * Scenario:
	 *   Given contents with log, dnslog, and ip_blocklog entries.
	 *   When  pfb_log_rotate_marker_parse($contents).
	 *   Then  all three are present in the returned map.
	 */
	public function testParseMultipleWellFormedEntries(): void
	{
		$contents = "log=2025-07-15\ndnslog=2025-W29\nip_blocklog=2025-07\n";
		$result   = pfb_log_rotate_marker_parse($contents);

		$this->assertSame('2025-07-15', $result['log'],          'log entry');
		$this->assertSame('2025-W29',   $result['dnslog'],       'dnslog entry');
		$this->assertSame('2025-07',    $result['ip_blocklog'],  'ip_blocklog entry');
		$this->assertCount(3, $result, 'exactly 3 entries');
	}

	/**
	 * Blank lines are silently skipped.
	 *
	 * Scenario:
	 *   Given $contents with interleaved blank lines.
	 *   When  pfb_log_rotate_marker_parse($contents).
	 *   Then  blank lines do not produce entries.
	 */
	public function testParseBlankLinesAreSkipped(): void
	{
		$contents = "\nlog=2025-07-15\n\n\ndnslog=2025-W29\n\n";
		$result   = pfb_log_rotate_marker_parse($contents);
		$this->assertCount(2, $result, 'blank lines produce no entries');
		$this->assertArrayHasKey('log',    $result);
		$this->assertArrayHasKey('dnslog', $result);
	}

	/**
	 * A line with no '=' is garbled and is silently skipped.
	 *
	 * Scenario:
	 *   Given $contents contains a line with no '=' separator.
	 *   When  pfb_log_rotate_marker_parse($contents).
	 *   Then  that line produces no entry (absent => '' => "never reset").
	 */
	public function testParseGarbledLineNoEqualsIsSkipped(): void
	{
		$contents = "log=2025-07-15\nTHIS-IS-GARBLED\ndnslog=2025-W29\n";
		$result   = pfb_log_rotate_marker_parse($contents);
		$this->assertCount(2, $result, 'garbled no-equals line is skipped');
		$this->assertArrayHasKey('log',    $result);
		$this->assertArrayHasKey('dnslog', $result);
		$this->assertArrayNotHasKey('THIS-IS-GARBLED', $result);
	}

	/**
	 * A line with '=' at position 0 (no key) is garbled and silently skipped.
	 *
	 * Scenario:
	 *   Given $contents = "=2025-07-15\n" (key is empty string).
	 *   When  pfb_log_rotate_marker_parse($contents).
	 *   Then  no entry is added (a zero-position '=' means no type name).
	 */
	public function testParseGarbledLineEqualsAtPositionZeroIsSkipped(): void
	{
		$contents = "=2025-07-15\nlog=2025-07-15\n";
		$result   = pfb_log_rotate_marker_parse($contents);
		$this->assertCount(1, $result, 'leading-equals line produces no entry');
		$this->assertArrayHasKey('log', $result);
	}

	/**
	 * A line whose type contains invalid characters is garbled and silently skipped.
	 *
	 * Scenario:
	 *   Given $contents contains "BAD TYPE=2025-07-15\n" (space in type).
	 *   When  pfb_log_rotate_marker_parse($contents).
	 *   Then  that entry is not added.
	 */
	public function testParseGarbledLineInvalidTypeCharactersIsSkipped(): void
	{
		$contents = "BAD TYPE=2025-07-15\nlog=2025-07-15\n";
		$result   = pfb_log_rotate_marker_parse($contents);
		$this->assertCount(1, $result, 'type with space is garbled and skipped');
		$this->assertArrayHasKey('log', $result);
	}

	/**
	 * A period-key value containing '=' is preserved (only the first '=' is the
	 * separator; the rest is part of the value).
	 *
	 * Scenario:
	 *   Given $contents = "log=val=with=equals\n".
	 *   When  pfb_log_rotate_marker_parse($contents).
	 *   Then  $result['log'] === 'val=with=equals'.
	 */
	public function testParseValueWithEqualsSignIsPreserved(): void
	{
		$contents = "log=val=with=equals\n";
		$result   = pfb_log_rotate_marker_parse($contents);
		$this->assertSame('val=with=equals', $result['log'], 'first = is separator; rest is value');
	}

	/**
	 * A duplicate type key: last occurrence wins (map overwrite).
	 *
	 * Scenario:
	 *   Given $contents has two entries for the same type.
	 *   When  pfb_log_rotate_marker_parse($contents).
	 *   Then  the second (last) value is stored.
	 */
	public function testParseDuplicateTypeLastValueWins(): void
	{
		$contents = "log=2025-07-14\nlog=2025-07-15\n";
		$result   = pfb_log_rotate_marker_parse($contents);
		$this->assertCount(1, $result, 'duplicate type collapses to one entry');
		$this->assertSame('2025-07-15', $result['log'], 'last value wins for duplicate type');
	}

	// -----------------------------------------------------------------------
	// pfb_log_rotate_marker_serialize() — serialize map to marker file contents
	// -----------------------------------------------------------------------

	/**
	 * Serializing an empty map returns ''.
	 *
	 * Scenario:
	 *   Given $entries = [].
	 *   When  pfb_log_rotate_marker_serialize([]).
	 *   Then  returns '' (no content to write).
	 */
	public function testSerializeEmptyMapReturnsEmptyString(): void
	{
		$result = pfb_log_rotate_marker_serialize([]);
		$this->assertSame('', $result, 'empty map serializes to empty string');
	}

	/**
	 * A single entry is serialized as "<type>=<key>\n".
	 *
	 * Scenario:
	 *   Given $entries = ['log' => '2025-07-15'].
	 *   When  pfb_log_rotate_marker_serialize($entries).
	 *   Then  returns "log=2025-07-15\n".
	 */
	public function testSerializeSingleEntry(): void
	{
		$result = pfb_log_rotate_marker_serialize(['log' => '2025-07-15']);
		$this->assertSame("log=2025-07-15\n", $result, 'single entry serialized');
	}

	/**
	 * Multiple entries are serialized sorted by type name (stable output).
	 *
	 * Scenario:
	 *   Given $entries = ['dnslog' => 'X', 'log' => 'Y', 'errlog' => 'Z'].
	 *   When  pfb_log_rotate_marker_serialize($entries).
	 *   Then  lines appear in alphabetical type order.
	 */
	public function testSerializeMultipleEntriesSortedByType(): void
	{
		$entries = ['dnslog' => '2025-W29', 'log' => '2025-07-15', 'errlog' => '2025-07'];
		$result  = pfb_log_rotate_marker_serialize($entries);

		$expected = "dnslog=2025-W29\nerrlog=2025-07\nlog=2025-07-15\n";
		$this->assertSame($expected, $result, 'entries sorted alphabetically by type');
	}

	// -----------------------------------------------------------------------
	// Round-trip: parse(serialize(m)) == m
	// -----------------------------------------------------------------------

	/**
	 * Round-trip for an empty map.
	 *
	 * Scenario:
	 *   Given $entries = [].
	 *   When  parse(serialize([])).
	 *   Then  returns [].
	 */
	public function testRoundTripEmptyMap(): void
	{
		$entries    = [];
		$serialized = pfb_log_rotate_marker_serialize($entries);
		$reparsed   = pfb_log_rotate_marker_parse($serialized);
		$this->assertSame($entries, $reparsed, 'empty map round-trips');
	}

	/**
	 * Round-trip for a single entry.
	 *
	 * Scenario:
	 *   Given $entries = ['ip_blocklog' => '2025-W30'].
	 *   When  parse(serialize($entries)).
	 *   Then  returns the original map.
	 */
	public function testRoundTripSingleEntry(): void
	{
		$entries    = ['ip_blocklog' => '2025-W30'];
		$serialized = pfb_log_rotate_marker_serialize($entries);
		$reparsed   = pfb_log_rotate_marker_parse($serialized);
		$this->assertSame($entries, $reparsed, 'single-entry map round-trips');
	}

	/**
	 * Round-trip for all 10 log types with realistic period keys.
	 *
	 * Scenario:
	 *   Given $entries containing all 10 log types with mixed schedule keys.
	 *   When  parse(serialize($entries)).
	 *   Then  the reparsed map equals the original.
	 */
	public function testRoundTripAllTenLogTypes(): void
	{
		$entries = [
			'log'             => '2025-07-15',
			'errlog'          => '2025-07-15',
			'extraslog'       => '2025-W29',
			'ip_blocklog'     => '2025-07',
			'ip_permitlog'    => '2025-07',
			'ip_matchlog'     => '2025-07-15',
			'dnslog'          => '2025-W29',
			'dnsbl_parse_err' => '2025-07-15',
			'dnsreplylog'     => '2025-07',
			'unilog'          => '2025-W29',
		];

		$serialized = pfb_log_rotate_marker_serialize($entries);
		$reparsed   = pfb_log_rotate_marker_parse($serialized);

		// serialize() sorts by type; parse() preserves that order. Sort the
		// expected map to match so assertSame works on both keys and values.
		ksort($entries);
		$this->assertSame($entries, $reparsed, 'all 10 log types round-trip through serialize/parse');
	}

	// -----------------------------------------------------------------------
	// Per-log selection using pfb_log_should_reset() with marker data.
	// Demonstrates the decision logic pfb_log_reset() applies per log.
	// -----------------------------------------------------------------------

	/**
	 * A log with a stale marker entry should reset; one still in its period should not.
	 *
	 * Scenario (per-log independence):
	 *   Given marker entries: log='2025-07-14' (stale), dnslog='2025-W29' (same week).
	 *   And   $now_ts = 2025-07-15 (Tuesday, ISO week W29).
	 *   Before: both entries are present in the marker.
	 *   When   pfb_log_should_reset() is called for each log with its own entry.
	 *   Then   log => TRUE (daily period rolled from 07-14 to 07-15).
	 *          dnslog => FALSE (still in W29; period has not changed).
	 */
	public function testPerLogIndependenceOneEligibleOneNot(): void
	{
		$ts_tue = mktime(12, 0, 0, 7, 15, 2025);   // 2025-07-15 = Tuesday W29.

		$marker_contents = "log=2025-07-14\ndnslog=2025-W29\n";
		$entries         = pfb_log_rotate_marker_parse($marker_contents);

		// Before: confirm both entries are present (marker is valid).
		$this->assertSame('2025-07-14', $entries['log'],    'log marker entry present before');
		$this->assertSame('2025-W29',   $entries['dnslog'], 'dnslog marker entry present before');

		// When: apply the should-reset decision for each log.
		$log_should    = pfb_log_should_reset('daily',  $entries['log'],    $ts_tue);
		$dns_should    = pfb_log_should_reset('weekly', $entries['dnslog'], $ts_tue);

		// Then: log => reset (day rolled); dnslog => no-op (same week).
		$this->assertTrue($log_should,    'log: daily period rolled from 07-14 to 07-15 => reset');
		$this->assertFalse($dns_should,   'dnslog: still in W29 => no reset');
	}

	/**
	 * A log absent from the marker (never reset) triggers reset; one with a
	 * current-period marker does not.
	 *
	 * Scenario:
	 *   Given marker: ip_blocklog='2025-07' (monthly, same month).
	 *   And   errlog is absent from the marker (never reset; daily schedule).
	 *   And   $now_ts = 2025-07-15 (July 2025).
	 *   Before: ip_blocklog is in the map; errlog is not.
	 *   When   pfb_log_should_reset() applied with each log's own entry.
	 *   Then   ip_blocklog => FALSE (still July).
	 *          errlog => TRUE (absent entry => "never reset" => first reset now).
	 */
	public function testAbsentMarkerEntryTriggersReset(): void
	{
		$ts_jul = mktime(12, 0, 0, 7, 15, 2025);

		$marker_contents = "ip_blocklog=2025-07\n";
		$entries         = pfb_log_rotate_marker_parse($marker_contents);

		// Before: ip_blocklog is present; errlog is absent.
		$this->assertArrayHasKey('ip_blocklog', $entries, 'ip_blocklog entry present before');
		$this->assertArrayNotHasKey('errlog', $entries,   'errlog absent from marker before');

		// Retrieve each log's marker entry (absent => '').
		$ip_block_key = $entries['ip_blocklog'] ?? '';
		$errlog_key   = $entries['errlog'] ?? '';

		// When.
		$ip_block_should = pfb_log_should_reset('monthly', $ip_block_key, $ts_jul);
		$errlog_should   = pfb_log_should_reset('daily',   $errlog_key,   $ts_jul);

		// Then.
		$this->assertFalse($ip_block_should, 'ip_blocklog: same monthly period => no reset');
		$this->assertTrue($errlog_should,    'errlog: absent marker => never reset => first reset');
	}

	/**
	 * Idempotency: after a reset the marker is updated; a second tick in the
	 * same period is a no-op.
	 *
	 * Scenario:
	 *   Given a log was just reset on 2025-07-15; its new marker entry = '2025-07-15'.
	 *   Before: pfb_log_should_reset returned TRUE (stale marker) — that was the first tick.
	 *   When   a second cron tick runs at the same time (same day, $ts_same).
	 *   Then   pfb_log_should_reset returns FALSE (same period, no reset).
	 */
	public function testIdempotencySecondTickSamePeriodIsNoop(): void
	{
		$ts_same = mktime(14, 0, 0, 7, 15, 2025);  // Later same day.

		// First tick: stale marker triggers reset.
		$stale_key = '2025-07-14';
		$this->assertTrue(
			pfb_log_should_reset('daily', $stale_key, $ts_same),
			'Before: stale marker => first tick triggers reset'
		);

		// After reset, marker is updated to the new period key.
		$new_key = pfb_log_rotate_period('daily', $ts_same);
		$this->assertSame('2025-07-15', $new_key, 'new period key after reset');

		// Second tick in the same period: no-op.
		$this->assertFalse(
			pfb_log_should_reset('daily', $new_key, $ts_same),
			'After: same-period marker => second tick is a no-op'
		);
	}

	/**
	 * A garbled marker entry is treated as '' (never reset) for that log.
	 *
	 * Scenario:
	 *   Given contents with one valid and one garbled line.
	 *   When  pfb_log_rotate_marker_parse($contents).
	 *   Then  the garbled type is absent from the map; its absent-key is ''
	 *         => pfb_log_should_reset treats it as "never reset" => TRUE.
	 */
	public function testGarbledMarkerEntryTreatedAsNeverReset(): void
	{
		$ts = mktime(12, 0, 0, 7, 15, 2025);

		// "GARBLED" has no '=' so it is skipped.
		$contents = "log=2025-07-15\nGARBLED\n";
		$entries  = pfb_log_rotate_marker_parse($contents);

		// Before: confirm log is present and garbled type is absent.
		$this->assertArrayHasKey('log', $entries,           'log present after parse');
		$this->assertArrayNotHasKey('GARBLED', $entries,    'GARBLED absent after parse');

		// Absent entry => '' => should_reset treats as "never reset".
		$absent_key    = $entries['errlog'] ?? '';
		$this->assertSame('', $absent_key, 'absent entry yields empty string');

		$should_reset = pfb_log_should_reset('daily', $absent_key, $ts);
		$this->assertTrue($should_reset, 'absent marker entry => never reset => triggers reset');
	}

	/**
	 * Off schedule: a log with schedule='off' is never eligible regardless of the marker.
	 *
	 * Scenario:
	 *   Given a log has schedule='off' and an absent marker ('' — never reset).
	 *   When  pfb_log_should_reset('off', '', $ts).
	 *   Then  returns FALSE (off => no reset ever).
	 */
	public function testOffScheduleNeverEligibleEvenWithAbsentMarker(): void
	{
		$ts = mktime(12, 0, 0, 7, 15, 2025);

		// Before: confirm that empty last_key with an active schedule WOULD trigger.
		$this->assertTrue(
			pfb_log_should_reset('daily', '', $ts),
			'Before: daily + absent marker would trigger reset'
		);

		// After (schedule='off'): no reset regardless of marker state.
		$this->assertFalse(
			pfb_log_should_reset('off', '', $ts),
			'After: off schedule => never resets even with absent marker'
		);
	}
}

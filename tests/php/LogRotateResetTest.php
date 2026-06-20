<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-30 Phase 3 + amendment #416 — Log-reset helpers and pfb_log_reset() file I/O.
 *
 * Part A (pure helpers, no I/O):
 *   pfb_log_rotate_marker_parse(string $contents): array
 *   pfb_log_rotate_marker_serialize(array $entries): string
 *   pfb_log_should_reset(string $schedule, string $last_key, int $now_ts): bool
 *
 * Part B (ADR-30 amendment #416 — pfb_log_reset() file I/O):
 *   pfb_log_reset() with log_reset_keep_<type> = 0 (full clear) and > 0 (keep N lines).
 *   Exercises the real exec path off-box using the bootstrap temp sandbox under $g.
 *
 * Coverage mandate (CLAUDE.md):
 *   Part A:
 *   - Every branch of parse (normal, blank, garbled = no '=', garbled = bad type,
 *     multiple entries, overwrite last occurrence of a duplicate key).
 *   - Every branch of serialize (empty map, single entry, multiple entries sorted).
 *   - Round-trip: parse(serialize(m)) == m for several maps.
 *   - Per-log independence: eligible log => should reset; same-period log => no-op.
 *   - Before-and-after in transition tests.
 *
 *   Part B (ADR-30 amendment / #416 — K=0 vs K>0 branch coverage):
 *   - K=0 (default) empties the log; assert NON-empty before, EMPTY after, marker advanced.
 *   - K>0 keeps the last K lines inode-preservingly; assert before=N lines,
 *     after=last K lines (content), inode unchanged, marker advanced.
 *   - K>0 but fewer than K lines present → whole file retained, marker advanced.
 *   - DNS log (chroot path) with K>0 → last K lines kept; the chroot-dir absence
 *     on the test runner falls back to the host path (same assertions as plain log);
 *     live-VM smoke owns the true chroot + ownership assertions.
 *   - K=0 on a DNS log → full clear, marker advanced (proves real exec path, not just K branch).
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

	// -----------------------------------------------------------------------
	// Part B — pfb_log_reset() file I/O (ADR-30 amendment / #416).
	//
	// These tests call pfb_log_reset() with real files under the bootstrap
	// temp sandbox ($g set in tests/php/bootstrap.php). Each test:
	//   1. Seeds a log file with content at the $pfb[] path.
	//   2. Writes a stale marker so the log is "due" for reset.
	//   3. Seeds log_reset_keep_<type> (and log_rotate_<type>='daily') into config.
	//   4. Calls pfb_log_reset().
	//   5. Asserts content (empty or kept) + inode (unchanged) + marker (advanced).
	//
	// The chroot dir (/var/unbound/var/log/pfblockerng) is absent on the test
	// runner, so DNS logs fall back to the host path — same assertions apply.
	// Live-VM smoke owns the true chroot + unbound-ownership assertions.
	// -----------------------------------------------------------------------

	/**
	 * Helper: return the absolute path to the sandbox log file for $logtype.
	 * Uses $GLOBALS['pfb'] which is populated at load time from $g.
	 */
	private function logPath(string $logtype): string
	{
		return $GLOBALS['pfb'][$logtype];
	}

	/**
	 * Helper: return the absolute path to the marker file.
	 */
	private function markerPath(): string
	{
		return $GLOBALS['pfb']['dbdir'] . '/log_rotate.last';
	}

	/**
	 * Helper: seed the minimum config keys pfb_global() accesses when called with a
	 * near-empty config, plus the log schedule + keep values for one log type.
	 *
	 * pfb_global() reads many section keys that are normally present on a real pfSense
	 * box but absent in tests. Seeding their minimums here prevents undefined-array-key
	 * PHP warnings and keeps the test output clean, without changing any tested behaviour.
	 * All other log types are set to schedule='off' so only $logtype resets.
	 *
	 * @param string $logtype   The single log type to make due for reset.
	 * @param string $keepVal   Value for log_reset_keep_<logtype> (default '0' = full clear).
	 */
	private function seedConfigForReset(string $logtype, string $keepVal = '0'): void
	{
		$GLOBALS['config'] = [];
		$gen               = 'installedpackages/pfblockerng/config/0';
		$ip                = 'installedpackages/pfblockerngipsettings/config/0';
		$dnsbl             = 'installedpackages/pfblockerngdnsblsettings/config/0';

		// Minimum general-section keys pfb_global() reads to avoid undefined-key warnings.
		config_set_path("{$gen}/pfb_min",       '0');
		config_set_path("{$gen}/pfb_hour",      '0');
		config_set_path("{$gen}/pfb_dailystart",'0');
		config_set_path("{$gen}/skipfeed",      '0');

		// Minimum ipsettings keys.
		config_set_path("{$ip}/suppression",    '');
		config_set_path("{$ip}/database_cc",    '');
		config_set_path("{$ip}/maxmind_locale", 'en');
		config_set_path("{$ip}/asn_reporting",  'disabled');
		config_set_path("{$ip}/asn_token",      '');
		config_set_path("{$ip}/maxmind_account",'');
		config_set_path("{$ip}/maxmind_key",    '');

		// Minimum global section keys.
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');

		// Minimum dnsblsettings keys.
		config_set_path("{$dnsbl}/pfb_dnsvip4",   '');
		config_set_path("{$dnsbl}/pfb_dnsvip6",   '');
		config_set_path("{$dnsbl}/pfb_dnsport",   '8081');
		config_set_path("{$dnsbl}/pfb_dnsport_ssl",'8443');
		config_set_path("{$dnsbl}/alexa_enable",  '');
		config_set_path("{$dnsbl}/pfb_cache",     '');
		config_set_path("{$dnsbl}/pfb_py_reply",  '');
		config_set_path("{$dnsbl}/pfb_regex",     '');
		config_set_path("{$dnsbl}/pfb_regex_list",'');
		config_set_path("{$dnsbl}/pfb_cname",     '');
		config_set_path("{$dnsbl}/pfb_pytld",     '');
		config_set_path("{$dnsbl}/pfb_py_nolog",  '');
		config_set_path("{$dnsbl}/pfb_noaaaa",    '');
		config_set_path("{$dnsbl}/pfb_noaaaa_list",'');
		config_set_path("{$dnsbl}/pfb_gp",        '');
		config_set_path("{$dnsbl}/pfb_gp_bypass_list",'');

		// $g['unbound_chroot_path'] is used to build pfb_global()'s chroot_cmd string.
		// Provide a dummy value so the string interpolation resolves without a warning.
		if (!isset($GLOBALS['g']['unbound_chroot_path'])) {
			$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
		}

		// All 10 log types: schedule='off' + keep='0' (only $logtype will fire).
		$allTypes = ['log', 'errlog', 'extraslog', 'ip_blocklog', 'ip_permitlog',
		             'ip_matchlog', 'dnslog', 'dnsbl_parse_err', 'dnsreplylog', 'unilog'];
		foreach ($allTypes as $t) {
			config_set_path("{$gen}/log_rotate_{$t}",    'off');
			config_set_path("{$gen}/log_reset_keep_{$t}", '0');
		}

		// The log type under test: daily schedule + the requested keep value.
		config_set_path("{$gen}/log_rotate_{$logtype}",    'daily');
		config_set_path("{$gen}/log_reset_keep_{$logtype}", $keepVal);
	}

	/**
	 * Helper: call pfb_log_reset() — thin wrapper kept for documentation clarity.
	 */
	private function callPfbLogReset(): void
	{
		pfb_log_reset();
	}

	/**
	 * Helper: write a stale marker (yesterday's date for $logtype) and return the marker path.
	 *
	 * @param string $logtype   The log type whose marker entry is stale.
	 */
	private function writeStaleMarker(string $logtype): string
	{
		$yesterday  = date('Y-m-d', strtotime('-1 day'));
		$contents   = "{$logtype}={$yesterday}\n";
		$markerPath = $this->markerPath();
		$markerDir  = dirname($markerPath);
		if (!is_dir($markerDir)) {
			@mkdir($markerDir, 0755, TRUE);
		}
		file_put_contents($markerPath, $contents);
		return $markerPath;
	}

	/**
	 * Helper: ensure the sandbox log directory exists.
	 */
	private function ensureLogDir(): void
	{
		$logdir = $GLOBALS['pfb']['logdir'];
		if (!is_dir($logdir)) {
			@mkdir($logdir, 0755, TRUE);
		}
	}

	/**
	 * K=0 (default) clears the log fully on a scheduled reset.
	 *
	 * Proves the K=0 branch is real: the same log seeded with K>0 in the sibling
	 * test keeps lines instead of emptying. Both tests must pass for K to be a
	 * genuine branch.
	 *
	 * Scenario:
	 *   Background: log_reset_keep_log = '0' (default — full clear).
	 *     Given a non-empty 'log' file (5 lines seeded).
	 *     And   a stale daily marker for 'log' (yesterday).
	 *     Before: file is NON-EMPTY.
	 *     When  pfb_log_reset() is called.
	 *     Then  the 'log' file is EMPTY (fully cleared).
	 *     And   the marker for 'log' is advanced to today.
	 */
	public function testK0ClearsLogFully(): void
	{
		$this->ensureLogDir();
		$logPath = $this->logPath('log');

		// Seed 5 lines.
		$content = implode("\n", ['line1', 'line2', 'line3', 'line4', 'line5']) . "\n";
		file_put_contents($logPath, $content);

		// Seed config: daily schedule + keep=0.
		$this->seedConfigForReset('log', '0');

		// Write a stale marker.
		$markerPath = $this->writeStaleMarker('log');

		// Before: file is non-empty.
		$this->assertGreaterThan(0, filesize($logPath), 'Before: log must be non-empty');

		// Act.
		$this->callPfbLogReset();

		// After: file is EMPTY (K=0 branch cleared it).
		clearstatcache(TRUE, $logPath);
		$this->assertSame(0, filesize($logPath), 'After K=0: log must be fully cleared');

		// Marker is advanced to today.
		$markerContents = (string) file_get_contents($markerPath);
		$entries        = pfb_log_rotate_marker_parse($markerContents);
		$this->assertSame(date('Y-m-d'), $entries['log'], 'After K=0: marker advanced to today');
	}

	/**
	 * K>0 keeps the last K lines inode-preservingly on a scheduled reset.
	 *
	 * Scenario:
	 *   Background: log_reset_keep_log = '3' (keep last 3 of 5 lines).
	 *     Given a 'log' file with 5 distinct lines.
	 *     And   a stale daily marker for 'log' (yesterday).
	 *     Before: file has 5 lines; inode = I.
	 *     When  pfb_log_reset() is called.
	 *     Then  file has exactly the LAST 3 lines (content matches tail).
	 *     And   inode is UNCHANGED (in-place truncation).
	 *     And   marker for 'log' is advanced to today.
	 */
	public function testKGreaterThanZeroKeepsLastKLines(): void
	{
		$this->ensureLogDir();
		$logPath = $this->logPath('log');

		// Seed 5 distinct lines.
		$lines   = ['alpha', 'bravo', 'charlie', 'delta', 'echo'];
		$content = implode("\n", $lines) . "\n";
		file_put_contents($logPath, $content);

		// Capture inode BEFORE the reset.
		$inodeBefore = fileinode($logPath);

		// Seed config: daily schedule + keep=3.
		$this->seedConfigForReset('log', '3');

		// Write a stale marker.
		$markerPath = $this->writeStaleMarker('log');

		// Before: 5 lines present.
		$linesBefore = count(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(5, $linesBefore, 'Before: log must have 5 lines');

		// Act.
		$this->callPfbLogReset();

		// After: exactly the last 3 lines retained.
		clearstatcache(TRUE, $logPath);
		$afterContent = (string) file_get_contents($logPath);
		$afterLines   = array_values(array_filter(explode("\n", $afterContent), 'strlen'));
		$this->assertCount(3, $afterLines, 'After K=3: log must have exactly 3 lines');
		$this->assertSame(['charlie', 'delta', 'echo'], $afterLines, 'After K=3: content must be last 3 lines');

		// Inode is unchanged (in-place truncation preserved the inode).
		$inodeAfter = fileinode($logPath);
		$this->assertSame($inodeBefore, $inodeAfter, 'After K=3: inode must be unchanged (in-place)');

		// Marker advanced to today.
		$markerContents = (string) file_get_contents($markerPath);
		$entries        = pfb_log_rotate_marker_parse($markerContents);
		$this->assertSame(date('Y-m-d'), $entries['log'], 'After K=3: marker advanced to today');
	}

	/**
	 * K>0 but fewer than K lines present retains the entire file unchanged.
	 *
	 * Scenario:
	 *   Background: log_reset_keep_log = '10' (keep last 10) but only 3 lines present.
	 *     Given a 'log' file with 3 lines.
	 *     And   a stale daily marker for 'log' (yesterday).
	 *     Before: file has 3 lines; inode = I.
	 *     When  pfb_log_reset() is called.
	 *     Then  file has all 3 lines (tail -n 10 of a 3-line file returns all 3).
	 *     And   inode is UNCHANGED.
	 *     And   marker for 'log' is advanced to today.
	 */
	public function testKGreaterThanZeroFewerLinesThanKRetainsAll(): void
	{
		$this->ensureLogDir();
		$logPath = $this->logPath('errlog');

		// Seed 3 lines.
		$lines   = ['one', 'two', 'three'];
		$content = implode("\n", $lines) . "\n";
		file_put_contents($logPath, $content);

		// Capture inode BEFORE.
		$inodeBefore = fileinode($logPath);

		// Seed config: daily schedule + keep=10 (larger than file).
		$this->seedConfigForReset('errlog', '10');

		// Write stale marker.
		$markerPath = $this->writeStaleMarker('errlog');

		// Before: 3 lines.
		$linesBefore = count(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(3, $linesBefore, 'Before: log must have 3 lines');

		// Act.
		$this->callPfbLogReset();

		// After: all 3 lines still present (K=10 > 3 → tail returns all).
		clearstatcache(TRUE, $logPath);
		$afterLines = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertCount(3, $afterLines, 'After K=10 on 3-line file: all 3 lines retained');
		$this->assertSame(['one', 'two', 'three'], $afterLines, 'After: content is the full original file');

		// Inode unchanged.
		$this->assertSame($inodeBefore, fileinode($logPath), 'After K=10: inode must be unchanged');

		// Marker advanced.
		$entries = pfb_log_rotate_marker_parse((string) file_get_contents($markerPath));
		$this->assertSame(date('Y-m-d'), $entries['errlog'], 'After K=10: marker advanced to today');
	}

	/**
	 * DNS log (chroot path) with K>0 keeps the last K lines.
	 *
	 * On the test runner /var/unbound/var/log/pfblockerng is absent, so the chroot
	 * branch falls back to the host path — the assertions are identical to the plain
	 * log case. The exec+ownership assertions for the true chroot path belong in the
	 * live-VM smoke suite (ADR-04).
	 *
	 * Proves the chroot log type is exercised through the K>0 code path (not dead code).
	 *
	 * Scenario:
	 *   Background: log_reset_keep_dnslog = '2', schedule = 'daily'.
	 *     Given a 'dnslog' file with 4 distinct lines.
	 *     And   a stale daily marker for 'dnslog' (yesterday).
	 *     Before: file has 4 lines; inode = I.
	 *     When  pfb_log_reset() is called.
	 *     Then  file has exactly the LAST 2 lines.
	 *     And   inode is UNCHANGED.
	 *     And   marker for 'dnslog' is advanced to today.
	 */
	public function testDnsLogKGreaterThanZeroKeepsLastKLines(): void
	{
		$this->ensureLogDir();
		$logPath = $this->logPath('dnslog');

		// Seed 4 distinct lines.
		$lines   = ['dns-line1', 'dns-line2', 'dns-line3', 'dns-line4'];
		$content = implode("\n", $lines) . "\n";
		file_put_contents($logPath, $content);

		// Capture inode BEFORE.
		$inodeBefore = fileinode($logPath);

		// Seed config: daily schedule + keep=2.
		$this->seedConfigForReset('dnslog', '2');

		// Write stale marker.
		$markerPath = $this->writeStaleMarker('dnslog');

		// Before: 4 lines.
		$linesBefore = count(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(4, $linesBefore, 'Before: dnslog must have 4 lines');

		// Act.
		$this->callPfbLogReset();

		// After: exactly the last 2 lines.
		clearstatcache(TRUE, $logPath);
		$afterLines = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertCount(2, $afterLines, 'After K=2: dnslog must have exactly 2 lines');
		$this->assertSame(['dns-line3', 'dns-line4'], $afterLines, 'After K=2: content must be last 2 lines');

		// Inode unchanged.
		$this->assertSame($inodeBefore, fileinode($logPath), 'After K=2: inode must be unchanged (in-place)');

		// Marker advanced.
		$entries = pfb_log_rotate_marker_parse((string) file_get_contents($markerPath));
		$this->assertSame(date('Y-m-d'), $entries['dnslog'], 'After K=2: marker advanced to today');
	}

	/**
	 * K=0 on a DNS log type clears the log fully (proves K=0 path for the chroot branch).
	 *
	 * Scenario:
	 *   Background: log_reset_keep_dnslog = '0' (default — full clear), schedule = 'daily'.
	 *     Given a non-empty 'dnslog' file.
	 *     And   a stale daily marker for 'dnslog'.
	 *     Before: file is NON-EMPTY.
	 *     When  pfb_log_reset() is called.
	 *     Then  the 'dnslog' file is EMPTY.
	 *     And   marker for 'dnslog' is advanced to today.
	 */
	public function testK0OnDnsLogClearsLogFully(): void
	{
		$this->ensureLogDir();
		$logPath = $this->logPath('dnslog');

		// Seed content.
		file_put_contents($logPath, "dns-entry-1\ndns-entry-2\ndns-entry-3\n");

		// Seed config: daily + keep=0.
		$this->seedConfigForReset('dnslog', '0');

		// Write stale marker.
		$markerPath = $this->writeStaleMarker('dnslog');

		// Before: non-empty.
		$this->assertGreaterThan(0, filesize($logPath), 'Before: dnslog must be non-empty');

		// Act.
		$this->callPfbLogReset();

		// After: empty.
		clearstatcache(TRUE, $logPath);
		$this->assertSame(0, filesize($logPath), 'After K=0 on dnslog: must be fully cleared');

		// Marker advanced.
		$entries = pfb_log_rotate_marker_parse((string) file_get_contents($markerPath));
		$this->assertSame(date('Y-m-d'), $entries['dnslog'], 'After K=0 on dnslog: marker advanced to today');
	}
}

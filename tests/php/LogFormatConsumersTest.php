<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-60 Phase 5 -- the two in-repo consumers byte-coupled to the OLD
 * 3-space-token log shape (ADR.md S1.8), now rebuilt for the ISO-8601 shape
 * Phases 2-4 landed.
 *
 * Neither `www/index.php`'s DNSBL block page nor `pfblockerng_alerts.php`'s
 * day-bucket/chart builder is a callable function -- both are top-level
 * script code (`www/index.php` runs at include time; the alerts stat loop
 * is guarded by a live `$alert_summary`/`$alert_log`, not wrapped in a
 * function AlertsPageLoader.php's eval window covers). Each fixed formula
 * below is pinned by a comment-free code tripwire (php_strip_whitespace(), so
 * production prose can never satisfy the oracle) and then reproduced -- not included -- and executed for REAL via
 * `exec()`/`shell_exec()` against synthetic fixture files, mirroring Phase
 * 1/3's convention for daemon code that cannot be called directly.
 */
final class LogFormatConsumersTest extends TestCase
{
	private const INDEX_PHP  = __DIR__ . '/../../src/usr/local/www/pfblockerng/www/index.php';
	private const ALERTS_PHP = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_alerts.php';

	/** @var string[] temp files to remove in tearDown */
	private array $tmpfiles = [];

	private string $savedTz;

	protected function setUp(): void
	{
		$this->savedTz = date_default_timezone_get();
		date_default_timezone_set('UTC');
	}

	protected function tearDown(): void
	{
		date_default_timezone_set($this->savedTz);
		foreach ($this->tmpfiles as $f) {
			if (is_file($f)) {
				$this->assertTrue(unlink($f), "failed to remove temp file {$f}");
			}
		}
		$this->tmpfiles = [];
	}

	private function tempFile(string $prefix): string
	{
		$f = tempnam(sys_get_temp_dir(), $prefix);
		$this->assertNotFalse($f, "could not create temp file ({$prefix})");
		$this->tmpfiles[] = $f;
		return $f;
	}

	private function codeSource(string $path): string
	{
		$source = php_strip_whitespace($path);
		$this->assertNotSame('', $source, "could not read comment-free source: {$path}");
		return $source;
	}

	// -----------------------------------------------------------------------
	// www/index.php -- the DNSBL block page's dnsbl.log correlation grep key
	// -----------------------------------------------------------------------

	/**
	 * The critical finding: the guard regex's charset must include '-' or an
	 * ISO timestamp (which always contains one) fails preg_match and the
	 * page render aborts via `exit`. Confirms the CURRENT source has the
	 * widened charset, then proves it accepts an ISO string.
	 */
	public function testBlockPageGuardCharsetAcceptsIsoTimestamp(): void
	{
		$source = $this->codeSource(self::INDEX_PHP);
		$needle = 'preg_match("/^[a-zA-Z0-9:\- ]+$/"';
		$this->assertStringContainsString(
			$needle,
			$source,
			"www/index.php's timestamp guard regex changed -- update this oracle (expected: {$needle})"
		);
		$this->assertSame(
			2,
			substr_count($source, $needle),
			'expected exactly 2 guard-regex call sites (the outer $timestamp guard and the foreach $ts guard)'
		);

		$this->assertSame(1, preg_match('/^[a-zA-Z0-9:\- ]+$/', '2026-07-08 14:30'), 'ISO date+time must pass the guard');
		$this->assertSame(1, preg_match('/^[a-zA-Z0-9:\- ]+$/', '2026-07-08'), 'ISO date-only must pass the guard');
	}

	/**
	 * Red proof (the critical finding): the PRE-Phase-5 guard charset (no '-',
	 * confirmed via `git show` of the prior commit) rejects an ISO timestamp,
	 * which is exactly what would have driven the page's `exit` on every real
	 * request once Phase 4's writer went ISO -- worse than a placeholder
	 * fallback, a hard abort.
	 */
	public function testBlockPageOldGuardCharsetWouldHaveAbortedOnIsoTimestamp(): void
	{
		// Pre-Phase-5 charset, verified via `git show HEAD~1:.../www/index.php`
		// before this phase's fix landed -- reproduced literally, not re-derived.
		$oldGuardRegex = '/^[a-zA-Z0-9: ]+$/';

		$this->assertSame(0, preg_match($oldGuardRegex, '2026-07-08 14:30'), 'the OLD charset must reject an ISO timestamp (the abort bug)');
		$this->assertSame(1, preg_match($oldGuardRegex, 'Jul 8 14:30'), 'sanity: the OLD charset accepted the OLD no-hyphen format');
	}

	/**
	 * Green, end-to-end: a synthetic ISO-format dnsbl.log line is found by the
	 * rebuilt grep key and its Type/Group/Evaluated/Feed fields render.
	 */
	public function testBlockPageCorrelationMatchesNewIsoFormatLogLine(): void
	{
		$source = $this->codeSource(self::INDEX_PHP);
		$this->assertStringContainsString(
			"date('Y-m-d H:i', htmlspecialchars(\$_SERVER['REQUEST_TIME']))",
			$source,
			"www/index.php's outer timestamp build changed -- update this oracle"
		);
		$this->assertStringContainsString(
			'/usr/bin/tail -n50 /var/log/pfblockerng/dnsbl.log | /usr/bin/grep -F -- {$domain} | /usr/bin/grep {$now} | /usr/bin/tail -1',
			$source,
			"www/index.php's correlation exec() pipeline changed -- update this oracle"
		);

		$log = $this->tempFile('pfb_dnsbl_iso_');
		$host = 'rv60p5-block.example';
		// b_type=DNSBL-Full, group=RV60P5Group, evald=Match, feed=RV60P5Feed (fields 5-8, 0-indexed).
		file_put_contents(
			$log,
			"DNSBL-python,2026-07-08 14:30:15,{$host},203.0.113.9,Python,DNSBL-Full,RV60P5Group,Match,RV60P5Feed,+,A\n"
		);

		$requestTime = strtotime('2026-07-08 14:30:45 UTC');
		$this->assertNotFalse($requestTime, 'fixture sanity: the fixed instant must parse');

		// Reproduces www/index.php's exact variable construction (tripwired above),
		// against the synthetic log path instead of the hardcoded production one.
		$timestamp = date('Y-m-d H:i', $requestTime);
		$this->assertSame('2026-07-08 14:30', $timestamp, 'fixture sanity: the built timestamp must match the log line\'s minute');
		$ts = $timestamp; // first foreach iteration -- matches immediately, same as production's loop order.
		$now = escapeshellarg($ts);
		$domain = escapeshellarg(',' . $host . ',');

		$data = [];
		$logArg = escapeshellarg($log);
		exec("/usr/bin/tail -n50 {$logArg} | /usr/bin/grep -F -- {$domain} | /usr/bin/grep {$now} | /usr/bin/tail -1", $data, $retval);
		$this->assertSame(0, $retval, 'the reproduced pipeline must exit 0');
		$this->assertNotEmpty($data, 'the ISO-format log line must be found by the rebuilt grep key (green)');

		$fields = explode(',', $data[0]);
		$this->assertSame('DNSBL-Full', $fields[5] ?? null, 'type field (index 5) must render, not a "-" placeholder');
		$this->assertSame('RV60P5Group', $fields[6] ?? null, 'group field (index 6) must render');
		$this->assertSame('Match', $fields[7] ?? null, 'evald field (index 7) must render');
		$this->assertSame('RV60P5Feed', $fields[8] ?? null, 'feed field (index 8) must render');
	}

	/**
	 * Red proof (the real live breakage this phase fixes): the SAME synthetic
	 * ISO-format log line, correlated with the PRE-Phase-5 key format (`M j
	 * H:i`, confirmed via `git show` of the prior commit) -- must NOT match.
	 * This is exactly the state the branch tip was in before this phase's fix.
	 */
	public function testBlockPageCorrelationFailsWithPreP5KeyAgainstNewIsoLogLine(): void
	{
		$log = $this->tempFile('pfb_dnsbl_iso_preP5_');
		$host = 'rv60p5-block.example';
		file_put_contents(
			$log,
			"DNSBL-python,2026-07-08 14:30:15,{$host},203.0.113.9,Python,DNSBL-Full,RV60P5Group,Match,RV60P5Feed,+,A\n"
		);

		$requestTime = strtotime('2026-07-08 14:30:45 UTC');
		// Pre-Phase-5 key build (verified via `git show HEAD~1:.../www/index.php`
		// before this phase's fix landed).
		$oldTs = date('M j H:i', $requestTime);
		$this->assertSame('Jul 8 14:30', $oldTs, 'fixture sanity: the OLD-format key for this instant');
		$oldNow = escapeshellarg($oldTs);
		$domain = escapeshellarg(',' . $host . ',');

		$data = [];
		exec("/usr/bin/tail -n50 {$log} | /usr/bin/grep {$domain} | /usr/bin/grep {$oldNow} | /usr/bin/tail -1", $data, $retval);
		$this->assertEmpty(
			$data,
			'the OLD 3-space-token key must NOT match a NEW ISO-format log line -- this is the live breakage Phase 5 fixes'
		);
	}

	/**
	 * issue #1652: the correlation grep embedded the host as an unanchored
	 * Basic Regular Expression, so '.' wildcard-matched any character and a
	 * blocked host could correlate to a DIFFERENT entry's row --
	 * `ads.example.com` matching `ads-example.com`'s line -- rendering the
	 * wrong Group/Feed/Evaluated-Domain on the block page. A log containing
	 * only the lookalike host's row must not correlate to the blocked host.
	 */
	public function testBlockPageCorrelationNeverMatchesLookalikeHostRow(): void
	{
		$source = $this->codeSource(self::INDEX_PHP);
		$matched = preg_match(
			'#exec\("(/usr/bin/tail -n50 /var/log/pfblockerng/dnsbl\.log[^"]+)",\s*\$data,\s*\$retval\);#',
			$source,
			$m
		);
		$this->assertSame(1, $matched, 'could not extract the correlation exec() pipeline from www/index.php');

		$log = $this->tempFile('pfb_dnsbl_lookalike_');
		// ONLY the lookalike's row: '-' exactly where the victim host has '.'.
		file_put_contents(
			$log,
			"DNSBL-python,2026-07-08 14:30:15,ads-example.com,203.0.113.9,Python,DNSBL-Full,LookalikeGroup,ads-example.com,LookalikeFeed,+,A\n"
		);

		$ts = '2026-07-08 14:30';
		$now = escapeshellarg($ts);
		// index.php's exact key construction, per host queried.
		$pipelineFor = static fn (string $host): string => str_replace(
			['/var/log/pfblockerng/dnsbl.log', '{$domain}', '{$now}'],
			[escapeshellarg($log), escapeshellarg(',' . $host . ','), $now],
			$m[1]
		);

		// Control (before-state discipline): the lookalike host itself DOES
		// correlate to its own row, proving the fixture, key construction, and
		// extracted pipeline find a genuine match.
		$ownData = [];
		exec($pipelineFor('ads-example.com'), $ownData);
		$this->assertNotEmpty($ownData, "control: the lookalike host must correlate to its OWN row");

		$data = [];
		exec($pipelineFor('ads.example.com'), $data);
		$this->assertSame(
			[],
			$data,
			"a blocked host must never correlate to a DIFFERENT entry's row ('.' must not wildcard-match '-'); matched: "
			. implode(' | ', $data)
		);
	}

	// -----------------------------------------------------------------------
	// pfblockerng_alerts.php -- day-bucket stats + hourly chart label
	// -----------------------------------------------------------------------

	/**
	 * Green: the rebuilt day-bucket field selection (`cut -d ' ' -f1`) groups
	 * ISO-format rows sharing a date into one bucket, regardless of their time.
	 * issue #1057 added the `grep -E '^[0-9]{4}-'` gate right before it -- pinned
	 * as part of the SAME tripwire so the two can never drift apart unnoticed.
	 */
	public function testDayBucketCutFieldSelectionGroupsIsoLinesByDate(): void
	{
		$source = $this->codeSource(self::ALERTS_PHP);
		$needle = "{\$pfb['grep']} -E '^[0-9]{4}-' | cut -d ' ' -f1 | uniq -c";
		$this->assertStringContainsString($needle, $source, "pfblockerng_alerts.php's day-bucket cut changed -- update this oracle");
		$this->assertStringNotContainsString("cut -d ' ' -f1-2", $source, 'the OLD 3-token field selection must be gone');

		$fixture = $this->tempFile('pfb_alerts_daybucket_');
		file_put_contents(
			$fixture,
			"DNSBL-python,2026-07-08 09:00:00,a.example,1,,,,,,,\n"
			. "DNSBL-python,2026-07-08 10:15:30,b.example,1,,,,,,,\n"
			. "DNSBL-python,2026-07-09 08:00:00,c.example,1,,,,,,,\n"
		);

		$cutField2 = "/usr/bin/cut -d ',' -f2 {$fixture}";
		exec("{$cutField2} | /usr/bin/grep -E '^[0-9]{4}-' | cut -d ' ' -f1 | uniq -c", $stats);

		$this->assertCount(2, $stats, 'two distinct days must produce exactly two buckets');
		$buckets = array_map(static fn (string $l): array => array_map('trim', explode(' ', trim($l), 2)), $stats);
		$byDate = array_combine(array_column($buckets, 1), array_column($buckets, 0));
		$this->assertSame('2', $byDate['2026-07-08'] ?? null, '2026-07-08 must bucket both its rows together');
		$this->assertSame('1', $byDate['2026-07-09'] ?? null, '2026-07-09 must bucket its single row');
	}

	/**
	 * Red proof: the SAME fixture through the PRE-Phase-5 field selection
	 * (`-f1-2`, confirmed via `git show` of the prior commit) -- every line
	 * becomes its own bucket down to the second, none grouped by day.
	 */
	public function testDayBucketOldFieldSelectionFailsToGroupIsoLines(): void
	{
		$fixture = $this->tempFile('pfb_alerts_daybucket_oldkey_');
		file_put_contents(
			$fixture,
			"DNSBL-python,2026-07-08 09:00:00,a.example,1,,,,,,,\n"
			. "DNSBL-python,2026-07-08 10:15:30,b.example,1,,,,,,,\n"
			. "DNSBL-python,2026-07-09 08:00:00,c.example,1,,,,,,,\n"
		);

		$cutField2 = "/usr/bin/cut -d ',' -f2 {$fixture}";
		exec("{$cutField2} | cut -d ' ' -f1-2 | uniq -c", $stats);

		$this->assertCount(
			3,
			$stats,
			'the OLD -f1-2 selection must fail to group even the two SAME-day rows -- every line its own bucket (the live breakage)'
		);
	}

	/**
	 * Green: the rebuilt 3-field chart-label awk shows the real hour for an
	 * ISO-shaped "count date hour" line (the `uniq -c` output shape).
	 */
	public function testHourlyChartLabelAwkShowsCorrectHourForIsoLines(): void
	{
		$source = $this->codeSource(self::ALERTS_PHP);
		// Nowdoc: zero escape processing, so this holds the exact RAW source bytes
		// (literal backslashes and all) for a byte-for-byte tripwire against the file.
		$rawSourceNeedle = <<<'EOT'
awk '{\$1=\$1} 1' | awk -F ' ' '{print \$2 \" (\" \$3 \"),\" \$1}'
EOT;
		$this->assertStringContainsString(
			$rawSourceNeedle,
			$source,
			'pfblockerng_alerts.php\'s $chart_cmd awk formula changed -- update this oracle'
		);
		// Same formula, hand-copied as a double-quoted PHP string so ITS escapes
		// resolve (matching what production's $chart_cmd evaluates to at runtime) --
		// reproduced for real execution below, not re-derived.
		$chartCmdFormula = "awk '{\$1=\$1} 1' | awk -F ' ' '{print \$2 \" (\" \$3 \"),\" \$1}'";

		$out = $this->tempFile('pfb_alerts_chart_new_');
		// Shape of `cut -d ':' -f1 | uniq -c` over ISO dnsbl.log lines: "  N date hour".
		$input = "  2 2026-07-08 09\n  1 2026-07-08 14\n";
		exec("printf '%s' " . escapeshellarg($input) . " | {$chartCmdFormula} >> {$out}");

		$written = (string) file_get_contents($out);
		$this->assertStringContainsString('2026-07-08 (09),2', $written, "expected the 09:00 bucket's label+count; got: {$written}");
		$this->assertStringContainsString('2026-07-08 (14),1', $written, "expected the 14:00 bucket's label+count; got: {$written}");
		$this->assertStringNotContainsString('(),', $written, "chart label must never show an empty hour field; got: {$written}");
	}

	/**
	 * Red proof: the SAME synthetic input through the PRE-Phase-5 4-field awk
	 * (confirmed via `git show` of the prior commit) -- the hour field is
	 * empty because ISO's date has no internal space to fill it from.
	 */
	public function testHourlyChartLabelOldAwkProducesEmptyHourForIsoLines(): void
	{
		// Pre-Phase-5 $chart_cmd's 4-field selection, awk-paren escaping normalized
		// (issue #1009: bare parens print identically on every awk; mawk keeps `\(`).
		$oldChartCmdFormula = "awk '{\$1=\$1} 1' | awk -F ' ' '{print \$2 \" \" \$3 \" (\" \$4 \"),\" \$1}'";

		$out = $this->tempFile('pfb_alerts_chart_old_');
		$input = "  2 2026-07-08 09\n";
		exec("printf '%s' " . escapeshellarg($input) . " | {$oldChartCmdFormula} >> {$out}");

		$written = (string) file_get_contents($out);
		$this->assertStringContainsString(
			'(),',
			$written,
			"the OLD 4-field awk must show an empty hour field against ISO input (the live breakage); got: {$written}"
		);
	}

	/**
	 * Regression: `dnsbldatehr`/`dnsbldatehrmin` (`:'-split hour buckets) formula
	 * ITSELF is genuinely unaffected by the ISO format change -- neither line was
	 * rewritten this phase, and BOTH an old-format and a new-format sample bucket
	 * to the same "<date> <hour[:min]>" shape at this cut stage alone. issue #1057
	 * later gated this formula's INPUT (a `grep -E '^[0-9]{4}-'`, pinned below) so
	 * an old-format sample no longer REACHES it in production -- LogFormatConsumersTest's
	 * mixed-fixture tests below cover that full-pipeline behaviour.
	 */
	public function testDnsblDateHrAndHrMinBucketsUnaffectedByFormatChange(): void
	{
		$source = $this->codeSource(self::ALERTS_PHP);
		$this->assertStringContainsString(
			"{\$pfb['grep']} -E '^[0-9]{4}-' | cut -d ':' -f1 | sort | uniq -c | sort -nr",
			$source,
			'dnsbldatehr\'s cut formula changed -- update this oracle'
		);
		$this->assertStringContainsString(
			"{\$pfb['grep']} -E '^[0-9]{4}-' | cut -d ':' -f1,2 | sort | uniq -c | sort -nr",
			$source,
			'dnsbldatehrmin\'s cut formula changed -- update this oracle'
		);

		foreach (
			[
				'old-format' => 'Jan 5 14:30:45',
				'new-format' => '2026-07-08 14:30:45',
			] as $label => $sample
		) {
			exec('echo ' . escapeshellarg($sample) . " | cut -d ':' -f1", $hrOut);
			exec('echo ' . escapeshellarg($sample) . " | cut -d ':' -f1,2", $hrMinOut);

			$this->assertMatchesRegularExpression('/ 14$/', $hrOut[0] ?? '', "{$label}: dnsbldatehr must end in the correct hour");
			$this->assertMatchesRegularExpression(
				'/ 14:30$/',
				$hrMinOut[0] ?? '',
				"{$label}: dnsbldatehrmin must end in the correct hour:minute"
			);
			$hrOut = $hrMinOut = [];
		}
	}

	// -----------------------------------------------------------------------
	// issue #1057 -- legacy pre-ISO lines surviving an upgrade must not
	// pollute the day/hour buckets (mixed-format fixture, all 3 pipelines).
	// -----------------------------------------------------------------------

	/**
	 * A dnsbl.log with 2 ISO rows (same day, different hours) plus 1 legacy
	 * `M j H:i:s`-prefixed row (`Nov 31 14:30:15`, the exact shape the issue
	 * reports rendering as "Nov (31)"), CSV field 2 (column for the dnsbl_stat
	 * view's $stat_info), mirroring a real dnsbl.log's field layout.
	 */
	private function mixedFormatFixture(): string
	{
		$fixture = $this->tempFile('pfb_alerts_mixed_');
		file_put_contents(
			$fixture,
			"DNSBL-python,2026-07-08 09:15:00,a.example,203.0.113.1,Python,VIP,G1,a.example,F1,+,A\n"
			. "DNSBL-python,2026-07-08 10:20:00,b.example,203.0.113.2,Python,VIP,G1,b.example,F1,+,A\n"
			. "DNSBL-python,Nov 31 14:30:15,legacy.example,203.0.113.9,Python,VIP,G1,legacy.example,F1,+,A\n"
		);
		return $fixture;
	}

	/**
	 * Red proof: the PRE-#1057 day-bucket pipeline (no grep gate) buckets the
	 * legacy row's bare month token "Nov" as if it were a day -- exactly the
	 * issue's reported symptom.
	 */
	public function testMixedFormatDayBucketOldPipelinePollutesWithLegacyMonthToken(): void
	{
		$fixture = $this->mixedFormatFixture();
		$cutField2 = "/usr/bin/cut -d ',' -f2 {$fixture}";
		exec("{$cutField2} | cut -d ' ' -f1 | uniq -c", $stats);

		$this->assertNotEmpty(
			array_filter($stats, static fn (string $l): bool => str_contains($l, 'Nov')),
			'the OLD (ungated) day-bucket pipeline must bucket the legacy row\'s bare "Nov" token (the live breakage)'
		);
	}

	/**
	 * Green: the NEW (`grep -E '^[0-9]{4}-'`-gated) day-bucket pipeline skips
	 * the legacy row entirely -- only the 2 ISO rows bucket, by date.
	 */
	public function testMixedFormatDayBucketNewPipelineSkipsLegacyLines(): void
	{
		$fixture = $this->mixedFormatFixture();
		$cutField2 = "/usr/bin/cut -d ',' -f2 {$fixture}";
		exec("{$cutField2} | /usr/bin/grep -E '^[0-9]{4}-' | cut -d ' ' -f1 | uniq -c", $stats);

		$this->assertEmpty(
			array_filter($stats, static fn (string $l): bool => str_contains($l, 'Nov')),
			'the NEW gated pipeline must never bucket the legacy row\'s "Nov" token; got: ' . implode(', ', $stats)
		);
		$this->assertCount(1, $stats, 'the 2 same-day ISO rows must collapse into exactly one bucket');
		$this->assertStringContainsString('2026-07-08', $stats[0], "expected the ISO date bucket; got: {$stats[0]}");
		$this->assertMatchesRegularExpression('/^\s*2\s/', $stats[0], "expected a count of 2; got: {$stats[0]}");
	}

	/**
	 * Red proof: the PRE-#1057 dnsbldatehr pipeline buckets the legacy row as
	 * "Nov 31 14" (month/day/hour all shifted one slot left of where an ISO
	 * row's "date hour" bucket key would put them) -- the exact shape the
	 * render loop later mangles into "Nov (31)".
	 */
	public function testMixedFormatDnsblDateHrOldPipelinePollutesWithLegacyBucket(): void
	{
		$fixture = $this->mixedFormatFixture();
		$cutField2 = "/usr/bin/cut -d ',' -f2 {$fixture}";
		exec("{$cutField2} | cut -d ':' -f1 | sort | uniq -c | sort -nr", $stats);

		$this->assertNotEmpty(
			array_filter($stats, static fn (string $l): bool => str_contains($l, 'Nov 31 14')),
			'the OLD (ungated) dnsbldatehr pipeline must bucket the legacy row as "Nov 31 14" (the live breakage)'
		);
	}

	/**
	 * Green: the NEW gated dnsbldatehr pipeline skips the legacy row -- only
	 * the 2 ISO "date hour" buckets survive.
	 */
	public function testMixedFormatDnsblDateHrNewPipelineSkipsLegacyLines(): void
	{
		$fixture = $this->mixedFormatFixture();
		$cutField2 = "/usr/bin/cut -d ',' -f2 {$fixture}";
		exec("{$cutField2} | /usr/bin/grep -E '^[0-9]{4}-' | cut -d ':' -f1 | sort | uniq -c | sort -nr", $stats);

		$joined = implode(', ', $stats);
		$this->assertStringNotContainsString('Nov', $joined, "legacy row must never survive the gate; got: {$joined}");
		$this->assertStringContainsString('2026-07-08 09', $joined, "expected the 09:00 ISO bucket; got: {$joined}");
		$this->assertStringContainsString('2026-07-08 10', $joined, "expected the 10:00 ISO bucket; got: {$joined}");
		$this->assertCount(2, $stats, 'exactly the 2 distinct ISO hour buckets, no legacy pollution');
	}

	/**
	 * Red proof: the PRE-#1057 dnsbldatehrmin pipeline buckets the legacy row
	 * as "Nov 31 14:30".
	 */
	public function testMixedFormatDnsblDateHrMinOldPipelinePollutesWithLegacyBucket(): void
	{
		$fixture = $this->mixedFormatFixture();
		$cutField2 = "/usr/bin/cut -d ',' -f2 {$fixture}";
		exec("{$cutField2} | cut -d ':' -f1,2 | sort | uniq -c | sort -nr", $stats);

		$this->assertNotEmpty(
			array_filter($stats, static fn (string $l): bool => str_contains($l, 'Nov 31 14:30')),
			'the OLD (ungated) dnsbldatehrmin pipeline must bucket the legacy row as "Nov 31 14:30" (the live breakage)'
		);
	}

	/**
	 * Green: the NEW gated dnsbldatehrmin pipeline skips the legacy row.
	 */
	public function testMixedFormatDnsblDateHrMinNewPipelineSkipsLegacyLines(): void
	{
		$fixture = $this->mixedFormatFixture();
		$cutField2 = "/usr/bin/cut -d ',' -f2 {$fixture}";
		exec("{$cutField2} | /usr/bin/grep -E '^[0-9]{4}-' | cut -d ':' -f1,2 | sort | uniq -c | sort -nr", $stats);

		$joined = implode(', ', $stats);
		$this->assertStringNotContainsString('Nov', $joined, "legacy row must never survive the gate; got: {$joined}");
		$this->assertStringContainsString('2026-07-08 09:15', $joined, "expected the 09:15 ISO bucket; got: {$joined}");
		$this->assertStringContainsString('2026-07-08 10:20', $joined, "expected the 10:20 ISO bucket; got: {$joined}");
		$this->assertCount(2, $stats, 'exactly the 2 distinct ISO hour:min buckets, no legacy pollution');
	}

	// -----------------------------------------------------------------------
	// issue #1057 -- the $d[1] undefined-array-key exposure on a truncated/
	// corrupt bucket key (no space at all in $data).
	// -----------------------------------------------------------------------

	/**
	 * Red proof: the PRE-#1057 render line (no `isset()` guard), reproduced
	 * verbatim, raises "Undefined array key 1" when $data has no space --
	 * exactly the truncated/corrupt-key exposure the issue reports.
	 */
	public function testBucketLabelOldCodeWarnsOnKeyWithoutSpace(): void
	{
		$warnings = [];
		set_error_handler(function (int $errno, string $errstr) use (&$warnings): bool {
			$warnings[] = $errstr;
			return true;
		});
		try {
			$data = '14'; // corrupt/truncated key: no space, so explode() yields only index 0.
			$d = explode(' ', $data);
			$data = "{$d[0]}&emsp;({$d[1]})"; // the OLD (unguarded) shape reproduced verbatim.
		} finally {
			restore_error_handler();
		}

		$this->assertNotEmpty($warnings, 'the OLD unguarded access must raise a PHP warning on a spaceless key');
		$this->assertStringContainsString('Undefined array key', $warnings[0] ?? '', "got: " . implode(', ', $warnings));
	}

	/**
	 * Green: the NEW `isset($d[1])`-guarded render line, pinned by source
	 * tripwire then reproduced verbatim, raises NO warning on a spaceless key
	 * (falls back to the bare $d[0]) and keeps the normal "date (hour)" shape
	 * for a well-formed key.
	 */
	public function testBucketLabelIssetGuardPreventsWarningOnKeyWithoutSpace(): void
	{
		$source = $this->codeSource(self::ALERTS_PHP);
		$needle = '$data = isset($d[1]) ? "{$d[0]}&emsp;({$d[1]})" : $d[0];';
		$this->assertStringContainsString($needle, $source, 'the $d[1] render guard changed -- update this oracle');

		foreach (
			[
				'well-formed key'   => ['2026-07-08 09', '2026-07-08&emsp;(09)'],
				'spaceless (corrupt) key' => ['14', '14'],
			] as $label => [$data, $expected]
		) {
			$warnings = [];
			set_error_handler(function (int $errno, string $errstr) use (&$warnings): bool {
				$warnings[] = $errstr;
				return true;
			});
			try {
				$d = explode(' ', $data);
				$data = isset($d[1]) ? "{$d[0]}&emsp;({$d[1]})" : $d[0]; // the NEW (guarded) shape, reproduced verbatim.
			} finally {
				restore_error_handler();
			}

			$this->assertSame([], $warnings, "{$label}: the guarded access must never warn; got: " . implode(', ', $warnings));
			$this->assertSame($expected, $data, "{$label}: unexpected rendered bucket label");
		}
	}

	// -----------------------------------------------------------------------
	// issue #1369 (ADR-38 Amendment 3) -- Top ASN stats: the shell (cut/awk)
	// pipeline behind pfblockerng_alerts.php's 'ipasn' stat is inline
	// top-level page code (the $stat_info/switch block), not a callable
	// function -- same reproduce-and-exec convention this file already uses
	// for the day-bucket/chart pipelines above.
	// -----------------------------------------------------------------------

	/**
	 * Source tripwire: the 'ipasn' case must gate on the exact new-schema
	 * field count (NF == 23) BEFORE cutting column 20, so this oracle goes
	 * red the moment the gate or the column position drifts.
	 */
	public function testTopAsnStatPipelineSourceHasSchemaGate(): void
	{
		$source = $this->codeSource(self::ALERTS_PHP);
		$needle = "{\$pfb['awk']} -F',' 'NF == 23' {\$alert_log} | {\$cut_cmd} | {\$agent_cmd} {\$su_cmd} | sort -nr 2>&1";
		$this->assertStringContainsString($needle, $source, "pfblockerng_alerts.php's Top ASN ('ipasn') pipeline changed -- update this oracle");
		$this->assertSame(
			1,
			preg_match("/'ipasn'\s*=>\s*20/", $source),
			"the 'ipasn' cut-column position changed -- update this oracle (must stay 20: the 2 new columns were appended AFTER it)"
		);
	}

	/**
	 * A synthetic ip_block.log with 2 new-schema (23-field) rows sharing one
	 * ASN plus 1 pre-upgrade legacy (21-field, single pipe-blob ASN column)
	 * row. Green: the NEW (NF==23-gated) pipeline counts only the 2 new-
	 * schema rows under their plain ASN token; the legacy row's blob-shaped
	 * column 20 never appears at all.
	 */
	private function mixedAsnFixture(): string
	{
		$fixture = $this->tempFile('pfb_alerts_asn_mixed_');
		$new1 = '2026-07-18 09:00:00,rule1,em0,WAN,block,4,tcp,TCP,192.0.2.1,198.51.100.1,1,2,in,US,Alias,192.0.2.1,Feed,,,AS50360,4vendeta.com,Tamatiya EOOD,+';
		$new2 = '2026-07-18 09:05:00,rule1,em0,WAN,block,4,tcp,TCP,192.0.2.2,198.51.100.1,1,2,in,US,Alias,192.0.2.2,Feed,,,AS50360,4vendeta.com,Tamatiya EOOD,+';
		$legacy = '2026-07-18 09:10:00,rule1,em0,WAN,block,4,tcp,TCP,192.0.2.9,198.51.100.1,1,2,in,US,Alias,192.0.2.9,Feed,,,|ASN:  AS99999 | domain:  legacy.example | name:  Legacy Org |,+';
		$this->assertCount(23, explode(',', $new1), 'fixture sanity: new1 must be the 23-field schema');
		$this->assertCount(23, explode(',', $new2), 'fixture sanity: new2 must be the 23-field schema');
		$this->assertCount(21, explode(',', $legacy), 'fixture sanity: legacy must be the OLD 21-field schema');
		file_put_contents($fixture, "{$new1}\n{$new2}\n{$legacy}\n");
		return $fixture;
	}

	public function testTopAsnNewPipelineSkipsLegacyRowAndCountsNewSchemaRows(): void
	{
		$fixture = $this->mixedAsnFixture();

		// Reproduces the 'ipasn' case body verbatim (tripwired above) against
		// the synthetic fixture instead of a real alert_log.
		exec("/usr/bin/awk -F',' 'NF == 23' {$fixture} | /usr/bin/cut -d ',' -f20 | sort | uniq -c | sort -nr 2>&1", $stats);

		$joined = implode(', ', $stats);
		$this->assertStringNotContainsString('ASN:', $joined, "the legacy row's pipe-blob text must never appear in the Top ASN stat; got: {$joined}");
		$this->assertStringNotContainsString('AS99999', $joined, "the legacy row's ASN must never be counted; got: {$joined}");
		$this->assertCount(1, $stats, 'the 2 new-schema rows sharing one ASN must collapse into exactly one bucket');
		$this->assertStringContainsString('AS50360', $stats[0], "expected the new-schema ASN bucket; got: {$stats[0]}");
		$this->assertMatchesRegularExpression('/^\s*2\s+AS50360$/', $stats[0], "expected a count of 2 for AS50360; got: {$stats[0]}");
	}

	/**
	 * Red proof: the PRE-#1369 (ungated) pipeline -- a bare `cut -d ',' -f20`
	 * with no NF filter -- pollutes the Top ASN count with the legacy row's
	 * raw pipe-blob text as if it were a real ASN bucket (the live breakage
	 * the owner's no-back-compat amendment requires this gate to prevent).
	 */
	public function testTopAsnOldUngatedPipelinePollutesWithLegacyBlobText(): void
	{
		$fixture = $this->mixedAsnFixture();

		exec("/usr/bin/cut -d ',' -f20 {$fixture} | sort | uniq -c | sort -nr 2>&1", $stats);

		$joined = implode(', ', $stats);
		$this->assertStringContainsString(
			'ASN:',
			$joined,
			"the OLD ungated pipeline must surface the legacy row's raw blob text as a bucket (the live breakage); got: {$joined}"
		);
	}
}

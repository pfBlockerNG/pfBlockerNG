<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-60 Phase 5 -- the two in-repo consumers byte-coupled to the OLD
 * 3-space-token log shape (ADR.md S1.8), now rebuilt for the ISO-8601 shape
 * Phases 2-4 landed.
 *
 * `pfblockerng_alerts.php`'s day-bucket/chart builder is not a callable function: the alerts stat loop is
 * guarded by a live `$alert_summary`/`$alert_log`, not wrapped in a function AlertsPageLoader.php's eval window
 * covers. (Issue #4053 removed the other consumer, the `www/index.php` block page.) Each fixed formula
 * below is pinned by a comment-free code tripwire (php_strip_whitespace(), so
 * production prose can never satisfy the oracle) and then reproduced -- not included -- and executed for REAL via
 * `exec()`/`shell_exec()` against synthetic fixture files, mirroring Phase
 * 1/3's convention for daemon code that cannot be called directly.
 */
final class LogFormatConsumersTest extends TestCase
{
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

	/** Historical colon-split compatibility; live DNS aggregation is covered by DnsStatsAggregationTest. */
	public function testDnsblDateHrAndHrMinBucketsUnaffectedByFormatChange(): void
	{
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

	/** Corrupt keys keep their bare label; valid keys retain the full date and hour. */
	public function testBucketLabelIssetGuardPreventsWarningOnKeyWithoutSpace(): void
	{
		require_once __DIR__ . '/AlertsPageLoader.php';
		require_once __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_stats.inc';
		pfb_test_load_alerts_page_functions();

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
				$panel = pfb_stats_panel('dnsbldatehr', ['', 'Found', 'hours', FALSE, ''], [$data => 1], 'max', []);
			} finally {
				restore_error_handler();
			}

			$this->assertSame([], $warnings, "{$label}: the guarded access must never warn; got: " . implode(', ', $warnings));
			$this->assertStringContainsString('>' . $expected . '</td>', $panel['html'], $label);
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
		$needle = "{\$pfb['awk']} -F',' 'NF == 23' {\$stats_log} | {\$cut_cmd} | {\$agent_cmd} {\$su_cmd} | sort -nr 2>&1";
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

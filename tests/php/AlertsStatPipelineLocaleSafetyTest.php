<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * Pin the byte-safety of the Alerts/Reports stat + chart pipelines in
 * pfblockerng_alerts.php (~L1691-1848: the per-$stat_type exec() switch that
 * builds $cut_cmd/$grep_cmd/$sss_cmd/$agent_cmd/$su_cmd pipelines against the
 * raw log file, both chart_stats.csv writers, and the ASN awk 'NF == 23' one).
 *
 * issue #1814 follow-up: this block is top-level page code (before the file's
 * first `function` keyword), needing the full pfSense render-time state
 * ($alert_view, $stat_info, $stat_hidden, config_get_path(), ...) -- not
 * reachable through the AlertsPageLoader eval-from-first-function convention.
 * Same reachability gap AlertsPieBlockAndStatsGuardTest already documents and
 * works around for two OTHER snippets in this exact block (the pie-segment
 * loop and the stat-bucket key build): this class follows that established
 * technique -- read the live production source and eval-extract just the one
 * case body under test into a standalone, parameterised function, verbatim.
 *
 * Two angles, per the brief:
 *   - testDefaultStatPipelineSurvivesAnInvalidUtf8ByteUnderAUtf8Locale drives
 *     the REAL exec() line (the `default:` case) against a real temp log
 *     file, with the process locale forced to a UTF-8 locale via putenv()
 *     (restored in tearDown). Red pre-fix only on BSD userland (macOS dev
 *     boxes, the FreeBSD appliance -- BSD cut aborts on an invalid byte
 *     under a UTF-8 locale); GNU cut tolerates invalid bytes, so on glibc
 *     hosts (GitHub CI) this test is green either way and the source-text
 *     pin below carries the regression coverage there.
 *   - testEveryStatChartExecCarriesTheByteSafeLocalePrefix is a source-text
 *     pin (same convention as UpdateAjaxTailJsonEncodingTest's call-site flag
 *     pin) covering EVERY exec( in the block -- the coverage axis the brief
 *     asks for, cheaper than eval-extracting and driving all ~20 pipelines.
 *     This top-level block has no off-appliance callable seam, so the retained
 *     pin scans php_strip_whitespace() output and cannot depend on comments.
 */
#[CoversNothing]
final class AlertsStatPipelineLocaleSafetyTest extends TestCase
{
	private const ALERTS_PHP = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_alerts.php';

	/** Bounds the whole per-$stat_type stats/chart section (both anchors are unique in the file). */
	private const BLOCK_END_ANCHOR = 'function pfb_hsc(';

	private string|false $prevLcAll = FALSE;
	private string $tmpLog = '';

	public static function setUpBeforeClass(): void
	{
		if (function_exists('pfb_alerts_oracle_default_stat_pipeline')) {
			return;
		}
		// Anchored on the literal `default:` case of the $stat_type switch -- the
		// simplest pipeline in the block (fewest interpolated command vars), verbatim.
		$block = self::boundedCodeBlock();
		$defPos = strpos($block, 'default:');
		if ($defPos === FALSE) {
			throw new RuntimeException('test bootstrap: default: case not found in the stats/chart switch');
		}
		$lineStart = strpos($block, 'exec("', $defPos);
		$lineEnd = strpos($block, ');', $lineStart === FALSE ? 0 : $lineStart);
		if ($lineStart === FALSE || $lineEnd === FALSE) {
			throw new RuntimeException('test bootstrap: could not find the end of the default: case exec() line');
		}
		$execLine = substr($block, $lineStart, $lineEnd + 2 - $lineStart);
		if (strpos($execLine, 'exec(') !== 0) {
			throw new RuntimeException("test bootstrap: default: case body was not the expected single exec() line, got: {$execLine}");
		}

		eval(
			'function pfb_alerts_oracle_default_stat_pipeline(string $cut_cmd, string $alert_log, string $agent_cmd, string $su_cmd, string $lc_bytes = \'\'): array {'
			. ' $stats = [];'
			. $execLine
			. ' return $stats; }'
		);
	}

	protected function setUp(): void
	{
		$this->prevLcAll = getenv('LC_ALL');
		$tmp = tempnam(sys_get_temp_dir(), 'pfb_stat_locale_');
		if ($tmp === FALSE) {
			throw new RuntimeException('test oracle: tempnam() failed');
		}
		$this->tmpLog = $tmp;
	}

	protected function tearDown(): void
	{
		if ($this->prevLcAll === FALSE) {
			putenv('LC_ALL');
		} else {
			putenv("LC_ALL={$this->prevLcAll}");
		}
		if ($this->tmpLog !== '') {
			@unlink($this->tmpLog);
		}
	}

	private static function boundedCodeBlock(): string
	{
		$code = php_strip_whitespace(self::ALERTS_PHP);
		if ($code === '') {
			throw new RuntimeException('test oracle: failed to read comment-free Alerts source');
		}
		$start = strpos($code, '$cut_cmd =');
		$end = strpos($code, self::BLOCK_END_ANCHOR, $start === FALSE ? 0 : $start);
		if ($start === FALSE || $end === FALSE || $end <= $start) {
			throw new RuntimeException('test oracle: comment-free stats/chart block bounds not found');
		}
		return substr($code, $start, $end - $start);
	}

	public function testDefaultStatPipelineSurvivesAnInvalidUtf8ByteUnderAUtf8Locale(): void
	{
		// 25 identical rows (mirrors the live smoke fixture's row count) whose
		// domain field (column 3) carries a raw 0xFF byte -- never valid in any
		// UTF-8 sequence. Forcing LC_ALL=en_US.UTF-8 reproduces the FreeBSD guest's
		// default UTF-8 locale regardless of this host's own default: BSD
		// cut/sort/uniq (this macOS box's userland is BSD, same family as the
		// FreeBSD guest's) ABORT on the invalid byte under a UTF-8 locale and the
		// WHOLE pipeline yields ZERO rows -- not just one blanked row.
		$line = "DNSBL-python,2030-02-21 10:00:00,badutf8\xFFdomain.invalidutf8.example,203.0.113.51,Python,DNSBL,InvalidUtf8Group,Match,InvalidUtf8Feed,+,A\n";
		file_put_contents($this->tmpLog, str_repeat($line, 25));

		putenv('LC_ALL=en_US.UTF-8');

		global $pfb;
		$cutCmd = "{$pfb['cut']} -d ',' -f3";
		$suCmd = 'sort | uniq -c';
		$lcBytes = 'LC_ALL=C; export LC_ALL; ';

		$stats = pfb_alerts_oracle_default_stat_pipeline($cutCmd, $this->tmpLog, '', $suCmd, $lcBytes);

		$this->assertNotSame(
			[],
			$stats,
			'the stat pipeline must not silently lose every row when an invalid UTF-8 byte is present under a UTF-8 locale'
		);
		$found = FALSE;
		foreach ($stats as $line) {
			if (str_contains($line, 'invalidutf8.example')) {
				$found = TRUE;
				break;
			}
		}
		$this->assertTrue($found, 'the invalid-UTF-8 domain row must survive the stat pipeline, not vanish along with every other row');
	}

	public function testEveryStatChartExecCarriesTheByteSafeLocalePrefix(): void
	{
		$block = self::boundedCodeBlock();

		// Every site in this block calls exec("...") -- a double-quoted string
		// literal as the first argument -- never exec($var) or a single-quoted one.
		$count = preg_match_all('/exec\("/', $block, $m, PREG_OFFSET_CAPTURE);
		$this->assertGreaterThanOrEqual(
			20,
			$count,
			'test oracle: expected at least 20 exec("...") sites in the stats/chart block -- did the block change shape?'
		);

		$missing = [];
		foreach ($m[0] as [$match, $offset]) {
			$afterQuote = $offset + strlen($match);
			if (substr($block, $afterQuote, strlen('{$lc_bytes}')) !== '{$lc_bytes}') {
				$lineEnd = strpos($block, "\n", $offset);
				$missing[] = trim(substr($block, $offset, ($lineEnd !== FALSE ? $lineEnd : $offset + 80) - $offset));
			}
		}

		$this->assertSame(
			[],
			$missing,
			'every exec("...") in the stats/chart block must be prefixed with {$lc_bytes} (LC_ALL=C) -- else BSD ' .
				'cut/sort/uniq/awk abort on an invalid-UTF-8 byte under a UTF-8 locale and silently drop every row ' .
				"in the panel (issue #1814 follow-up). Missing on:\n" . implode("\n", $missing)
		);
	}
}

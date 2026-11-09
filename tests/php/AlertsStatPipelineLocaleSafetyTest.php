<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/** Exercise the remaining IP stat pipeline with invalid UTF-8 under a UTF-8 locale. */
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
			'function pfb_alerts_oracle_default_stat_pipeline(string $cut_cmd, string $stats_log, string $agent_cmd, string $su_cmd, string $lc_bytes = \'\'): array {'
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

}

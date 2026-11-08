<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_stats.inc';

final class AlertsPieBlockAndStatsGuardTest extends TestCase
{
	private const ALERTS_PHP = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_alerts.php';

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(self::ALERTS_PHP);
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_alerts.php');
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

	public function testPieSegmentLoopEmitsNoUndefinedArrayKeyWhenFewerEntriesThanSegments(): void
	{
		[$result, $diagnostics] = $this->runCapturing(static fn () => pfb_stats_pie(
			['a.example' => 10, 'b.example' => 5], 2, 'test'
		));
		$this->assertSame([], self::undefinedKeyDiagnostics($diagnostics));
		$this->assertSame([
			['label' => 'a.example', 'value' => 10.0, 'color' => '#2484c1'],
			['label' => 'b.example', 'value' => 5.0, 'color' => '#65a620'],
		], $result['content']);
	}

	public function testPieSegmentLoopPostLoopIndexIsUnchangedByTheGuard(): void
	{
		[$result, $diagnostics] = $this->runCapturing(static fn () => pfb_stats_pie(
			array_combine(range('a', 'l'), range(12, 1)), 12, 'test'
		));
		$this->assertSame([], self::undefinedKeyDiagnostics($diagnostics));
		$this->assertCount(10, $result['content']);
		$this->assertSame(['label' => 'Other', 'value' => 3, 'color' => '#6ada6a'], $result['content'][9]);
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

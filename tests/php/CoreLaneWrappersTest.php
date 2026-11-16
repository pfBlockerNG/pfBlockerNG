<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** The metrics and counters wrappers Core execs (issue #3996): their shipped bytes, and the one value they share with the package. */
final class CoreLaneWrappersTest extends TestCase
{
	private const PKG = __DIR__ . '/../../src/usr/local/pkg/pfblockerng';

	/** @return list<string> */
	private function lines(string $wrapper): array
	{
		$path = self::PKG . "/{$wrapper}";
		$this->assertFileExists($path);
		$this->assertTrue(is_executable($path), 'Core must be able to exec the installed wrapper');
		return file($path, FILE_IGNORE_NEW_LINES) ?: [];
	}

	public function testMetricsWrapperTestsTheSentinelThePackageCreates(): void
	{
		$lines = $this->lines('pfb_core_metrics.sh');
		$this->assertSame('#!/bin/sh', $lines[0]);
		$this->assertStringStartsWith('# ', $lines[1]);
		$this->assertSame("[ -e {$GLOBALS['pfb']['metrics_enabled']} ] || exit 0", $lines[2], 'the wrapper and pfb_metrics_configure_export() must name the same sentinel');
		$this->assertSame('exec /usr/bin/timeout -s TERM -k 5 50 /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php metrics', $lines[3]);
		$this->assertCount(4, $lines);
	}

	public function testCountersWrapperExecsOnlyTheCountersVerbWithItsArguments(): void
	{
		$lines = $this->lines('pfb_core_counters.sh');
		$this->assertSame('#!/bin/sh', $lines[0]);
		$this->assertSame('exec /usr/local/bin/php -d display_errors=stderr -f /usr/local/pkg/pfblockerng/pfblockerng.inc core_counters "$@"', $lines[count($lines) - 1]);
		$this->assertCount(3, $lines, 'one comment, no second implementation');
	}
}

<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #1657 — url_compare() in pfblockerng_feeds.php declared its four
 * optional parameters ($alternate, $alt_header, $alt_info, $alt_register)
 * BEFORE the required $a_key, which PHP 8 deprecates (one Deprecated notice
 * per optional parameter ahead of the required one). Loading the Feeds page
 * emitted four deprecations while `php -l` and PHPUnit stayed green -- this
 * pins the E_ALL lint of the file itself so that class of regression cannot
 * come back silently.
 *
 * Scope: this file only, NOT tree-wide. A tree-wide `php -d error_reporting=
 * E_ALL -l` sweep of every tracked src/ PHP file (issue #1657 brief, section
 * 5) found a SECOND, pre-existing offender outside this file's blast radius:
 * pfBlockerNG_get_table() in src/usr/local/www/widgets/widgets/
 * pfblockerng.widget.php ("Optional parameter $mode declared before required
 * parameter $pfb_table"). That one is out of scope for #1657 and is left for
 * a follow-up issue -- fixing it here would be an undisclosed scope creep.
 */
final class FeedsUrlCompareDeprecationTest extends TestCase
{
	private const TARGET = 'src/usr/local/www/pfblockerng/pfblockerng_feeds.php';

	public function testFeedsFileLintsCleanUnderErrorReportingEAll(): void
	{
		$root = dirname(__DIR__, 2);
		$path = $root . '/' . self::TARGET;
		$this->assertFileExists($path);

		$cmd = escapeshellarg(PHP_BINARY)
			. ' -d error_reporting=E_ALL -l '
			. escapeshellarg($path)
			. ' 2>&1';

		$output = shell_exec($cmd);
		$this->assertIsString($output, 'php -l must produce output');

		$this->assertStringContainsString(
			'No syntax errors detected',
			(string) $output,
			'php -l must confirm the file still parses'
		);
		$this->assertDoesNotMatchRegularExpression(
			'/\b(Deprecated|Warning|Notice)\b/',
			(string) $output,
			"php -l -d error_reporting=E_ALL must emit no Deprecated/Warning/Notice diagnostics; got:\n{$output}"
		);
	}
}

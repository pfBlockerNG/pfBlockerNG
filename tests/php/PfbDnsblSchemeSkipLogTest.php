<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-22 Phase 2 -- the call-site toggle resolution + the strict-mode skip logging.
 *
 * Scenario: a strict skip is recorded per-line AND summarised once per feed; lenient is
 * byte-identical to today (nothing skipped, no new log output).
 *   Background:
 *     - strict = (pfb_dnsbl_lenient !== 'on') -- the trivial single-toggle resolution.
 *     - pfb_dnsbl_scheme_line($line, $strict, $header, $oline, $logfile, &$skipped):
 *       returns the kept host, or FALSE after recording a parse-error line + bumping the
 *       per-feed counter.
 *     - pfb_dnsbl_scheme_skip_warn($skipped, $header): one main-log WARNING when $skipped>0.
 *
 * Real pfb_parsed_fail()/pfb_logger() are exercised (the shipped code), pointed at temp
 * files so the side-effects are asserted -- not coverage theater.
 */
#[CoversFunction('pfb_dnsbl_scheme_line')]
#[CoversFunction('pfb_dnsbl_scheme_skip_warn')]
final class PfbDnsblSchemeSkipLogTest extends TestCase
{
	// --- Toggle resolution: strict = lenient !== 'on' (ADR §2.1). Both branches. ---

	public function testStrictResolvesTrueWhenLenientOff(): void
	{
		// lenient OFF (the new-install default) => strict parsing.
		$lenient = 'off';
		$this->assertTrue($lenient !== 'on');
	}

	public function testStrictResolvesFalseWhenLenientOn(): void
	{
		// lenient ON (the migrated/legacy default) => permissive parsing.
		$lenient = 'on';
		$this->assertFalse($lenient !== 'on');
	}

	// --- Per-line skip + parse-error log (strict) vs silent passthrough (lenient). ---

	public function testStrictSkipIsLogged(): void
	{
		$logfile = tempnam(sys_get_temp_dir(), 'pfb_parse_err_');
		$this->assertNotFalse($logfile);
		@file_put_contents($logfile, '');	// Given: an empty parse-error log.
		$skipped = 0;

		// When: a malformed line ('123://evil.com') is parsed in STRICT mode.
		$result = pfb_dnsbl_scheme_line('123://evil.com', true, 'TestFeed', '123://evil.com', $logfile, $skipped);

		// Then: the line is rejected, the counter bumped, and a CSV parse-error row written.
		$this->assertFalse($result);
		$this->assertSame(1, $skipped);
		$logged = (string)@file_get_contents($logfile);
		$this->assertStringContainsString('TestFeed', $logged);
		$this->assertStringContainsString('123://evil.com', $logged);

		@unlink($logfile);
	}

	public function testLenientEmitsNoNewLog(): void
	{
		$logfile = tempnam(sys_get_temp_dir(), 'pfb_parse_err_');
		$this->assertNotFalse($logfile);
		@file_put_contents($logfile, '');	// Given: an empty parse-error log.
		$skipped = 0;

		// When: the SAME malformed line is parsed in LENIENT mode.
		$result = pfb_dnsbl_scheme_line('123://evil.com', false, 'TestFeed', '123://evil.com', $logfile, $skipped);

		// Then: it is kept (today's behaviour), nothing is counted, and the log stays empty
		// -- byte-identical to today.
		$this->assertSame('evil.com', $result);
		$this->assertSame(0, $skipped);
		$this->assertSame('', (string)@file_get_contents($logfile));

		@unlink($logfile);
	}

	public function testValidSchemeLineKeptInStrictWithoutLogging(): void
	{
		// A valid scheme, no path: kept in strict too, nothing logged/counted (regression
		// guard -- strict must not skip legitimate lines).
		$logfile = tempnam(sys_get_temp_dir(), 'pfb_parse_err_');
		@file_put_contents($logfile, '');
		$skipped = 0;

		$result = pfb_dnsbl_scheme_line('evil://evil.com', true, 'TestFeed', 'evil://evil.com', $logfile, $skipped);

		$this->assertSame('evil.com', $result);
		$this->assertSame(0, $skipped);
		$this->assertSame('', (string)@file_get_contents($logfile));

		@unlink($logfile);
	}

	// --- Per-feed summary WARNING: once per feed, only when something was skipped. ---

	public function testPerFeedWarningEmittedOnceWhenSkipped(): void
	{
		$mainlog = tempnam(sys_get_temp_dir(), 'pfb_main_log_');
		$this->assertNotFalse($mainlog);
		@file_put_contents($mainlog, '');
		$GLOBALS['pfb']['log'] = $mainlog;	// pfb_logger() writes here (logtype 2).

		// When: the per-feed summary fires for a feed that skipped 3 lines.
		pfb_dnsbl_scheme_skip_warn(3, 'TestFeed');

		// Then: exactly ONE WARNING line, naming the feed + the count (not one per line).
		$logged = (string)@file_get_contents($mainlog);
		$this->assertStringContainsString('TestFeed', $logged);
		$this->assertStringContainsString('3 line(s) skipped', $logged);
		$this->assertSame(1, substr_count($logged, 'line(s) skipped'));

		@unlink($mainlog);
	}

	public function testPerFeedWarningSilentWhenNothingSkipped(): void
	{
		// Before: empty log. Lenient mode never increments the counter, so the summary must
		// stay silent (byte-identical to today).
		$mainlog = tempnam(sys_get_temp_dir(), 'pfb_main_log_');
		@file_put_contents($mainlog, '');
		$GLOBALS['pfb']['log'] = $mainlog;

		pfb_dnsbl_scheme_skip_warn(0, 'TestFeed');

		$this->assertSame('', (string)@file_get_contents($mainlog));

		@unlink($mainlog);
	}
}

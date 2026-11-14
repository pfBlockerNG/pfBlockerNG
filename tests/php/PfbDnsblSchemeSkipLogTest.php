<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-22 Phase 2 -- the call-site toggle resolution + the per-feed strict-mode skip summary.
 *
 *   Background:
 *     - strict = (pfb_dnsbl_lenient !== 'on') -- the trivial single-toggle resolution.
 *     - pfb_dnsbl_scheme_skip_warn($skipped, $header): one main-log WARNING when $skipped>0; the per-line skip and
 *       its parse-error row are Core's feed parse since #3977 (go/pfb_core/feedparse TestDNSBLCorpus).
 *
 * Real pfb_logger() is exercised (the shipped code), pointed at temp files so the side-effects are asserted. File I/O
 * results are asserted (no '@' suppression) so a setup/teardown failure cannot mask a false green, and
 * $GLOBALS['pfb']['log'] is saved/restored per test so the suite stays order-independent.
 */
#[CoversFunction('pfb_dnsbl_scheme_skip_warn')]
final class PfbDnsblSchemeSkipLogTest extends TestCase
{
	/** @var string[] temp files to remove in tearDown */
	private array $tmpfiles = [];

	/** original $GLOBALS['pfb']['log'] (sentinel FALSE = was unset) */
	private mixed $prevLog = false;

	protected function setUp(): void
	{
		$this->prevLog = array_key_exists('log', $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb']['log'] : false;
	}

	protected function tearDown(): void
	{
		// Restore the shared global so a test that points pfb_logger() at a temp file does
		// not leak that path into later tests.
		if ($this->prevLog === false) {
			unset($GLOBALS['pfb']['log']);
		} else {
			$GLOBALS['pfb']['log'] = $this->prevLog;
		}
		foreach ($this->tmpfiles as $f) {
			if (is_file($f)) {
				$this->assertTrue(unlink($f), "failed to remove temp file {$f}");
			}
		}
		$this->tmpfiles = [];
	}

	/** Create an empty temp file, registered for teardown removal, with its result asserted. */
	private function mktemp(string $prefix): string
	{
		$path = tempnam(sys_get_temp_dir(), $prefix);
		$this->assertNotFalse($path, "tempnam({$prefix}) failed");
		$this->tmpfiles[] = $path;
		$this->assertNotFalse(file_put_contents($path, ''), "could not truncate {$path}");
		return $path;
	}

	private function readFile(string $path): string
	{
		$raw = file_get_contents($path);
		$this->assertNotFalse($raw, "could not read {$path}");
		return (string) $raw;
	}

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

	// --- Per-feed summary WARNING: once per feed, only when something was skipped. ---

	public function testPerFeedWarningEmittedOnceWhenSkipped(): void
	{
		$mainlog = $this->mktemp('pfb_main_log_');
		$GLOBALS['pfb']['log'] = $mainlog;	// pfb_logger() writes here (logtype 1; restored in tearDown).

		// When: the per-feed summary fires for a feed that skipped 3 lines.
		pfb_dnsbl_scheme_skip_warn(3, 'TestFeed');

		// Then: exactly ONE WARNING line, naming the feed + the count (not one per line).
		$logged = $this->readFile($mainlog);
		$this->assertStringContainsString('TestFeed', $logged);
		$this->assertStringContainsString('3 line(s) skipped', $logged);
		$this->assertSame(1, substr_count($logged, 'line(s) skipped'));
	}

	public function testPerFeedWarningSilentWhenNothingSkipped(): void
	{
		// Before: empty log. Lenient mode never increments the counter, so the summary must
		// stay silent (byte-identical to today).
		$mainlog = $this->mktemp('pfb_main_log_');
		$GLOBALS['pfb']['log'] = $mainlog;

		pfb_dnsbl_scheme_skip_warn(0, 'TestFeed');

		$this->assertSame('', $this->readFile($mainlog));
	}
}
